import Foundation
import CryptoKit
import FernletDomainModel
import FernletFoundation

/// Offline "away" hearts over the CloudKit public-DB dead-drop (bitchat adoptions Increment 3,
/// Docs/Plan-Bitchat-Adoptions-2026-07-25.md; architecture decided 2026-06 as the
/// "CloudKit public-DB E2EE dead-drop + proximity hybrid").
///
/// All crypto happens here on the sealed side of the S3 wall; the injected
/// `HeartDropTransporting` (CloudKitSync) only ever sees rotating day tags + ciphertext.
/// Flow:
///   send  — consent → ledger 5-min gate (consume-on-queue) → signed inner envelope →
///           prekey (FS) or static-fallback outer seal → persisted outbox → upload.
///   fetch — consent → expected tags (kept friends × last 7 UTC days) → open → durable dedup →
///           sender-must-be-active-friend gate → envelope verify (nil replay cache: drops are
///           legitimately days old; the durable dedup replaces it) → per-sender per-day budget →
///           ledger (existing bubble/glow surfaces it).
///   cleanup — sender deletes its own server records past the 14-day outbox lifetime
///           (recipients cannot delete a sender's public-DB records; they dedup instead).
@MainActor
@Observable
public final class HeartDropService {

    public enum QueueOutcome: Equatable, Sendable {
        case queued
        case rateLimited
        case backlogFull
        case disabled
        case failed
    }

    /// Fetch looks back this many UTC days (sender records live 14 d; 7 d of tags keeps the
    /// query small — a heart older than a week reads stale anyway).
    public static let pickupWindowDays: UInt64 = 6 // today + 6 back = 7 tags per friend

    @ObservationIgnored private let identity: IdentityService
    @ObservationIgnored private let prekeys: HeartPrekeyStore
    @ObservationIgnored private let peerBundles: HeartDropPeerBundleCache
    @ObservationIgnored private let outbox: HeartDropOutbox
    @ObservationIgnored private let dedup: HeartDropDedupStore
    @ObservationIgnored private let ledger: ProximityHeartLedger
    @ObservationIgnored private let isEnabled: () -> Bool
    @ObservationIgnored private let activeFriends: () -> [ProximityTrustedPeerRecord]
    @ObservationIgnored private let localDayKey: (Date) -> String
    @ObservationIgnored private let displayName: () -> String
    @ObservationIgnored private let now: () -> Date
    /// Set by the app layer (CloudKitSync's `HeartDropCloudTransport`); nil in tests without one.
    @ObservationIgnored public var transport: (any HeartDropTransporting)?

    public private(set) var isSyncing = false
    /// Bumped whenever outbox contents change, so friend rows can re-derive queued counts.
    public private(set) var outboxRevision = 0

    public init(
        ledger: ProximityHeartLedger,
        isEnabled: @escaping () -> Bool,
        activeFriends: @escaping () -> [ProximityTrustedPeerRecord],
        localDayKey: @escaping (Date) -> String,
        displayName: @escaping () -> String,
        identity: IdentityService = IdentityService(),
        prekeys: HeartPrekeyStore? = nil,
        peerBundles: HeartDropPeerBundleCache? = nil,
        outbox: HeartDropOutbox? = nil,
        dedup: HeartDropDedupStore? = nil,
        now: @escaping () -> Date = { Date() }
    ) {
        self.ledger = ledger
        self.isEnabled = isEnabled
        self.activeFriends = activeFriends
        self.localDayKey = localDayKey
        self.displayName = displayName
        self.identity = identity
        try? identity.ensureProvisioned()
        self.prekeys = prekeys ?? HeartPrekeyStore()
        self.peerBundles = peerBundles ?? HeartDropPeerBundleCache()
        self.outbox = outbox ?? HeartDropOutbox(now: now)
        self.dedup = dedup ?? HeartDropDedupStore(now: now)
        self.now = now
    }

    // MARK: - Gossip seams (wired to ProximityCoordinator closures by the managers)

    /// Our current bundle for intro gossip — nil while consent is off, so an opted-out device
    /// never advertises drop reachability.
    public func currentLocalBundle() -> HeartPrekeyStore.Bundle? {
        guard isEnabled() else { return nil }
        return prekeys.currentBundle()
    }

    /// A friend's verified intro carried a bundle (provenance = the intro envelope signature).
    public func storePeerBundle(_ bundle: HeartPrekeyStore.Bundle, friendSigningKey: Data) {
        peerBundles.store(bundle: bundle, forFriendSigningKey: friendSigningKey)
    }

    // MARK: - Send

    public func queueHeart(to friend: ProximityTrustedPeerRecord) -> QueueOutcome {
        guard isEnabled(), friend.blockedAt == nil, friend.revokedAt == nil,
              !friend.keyAgreementPublicKey.isEmpty else { return .disabled }
        guard ledger.canSendHeart(to: friend.fingerprint) else { return .rateLimited }

        let sentAt = now()
        let payload = HeartPayload(sentAtDayKey: localDayKey(sentAt))
        guard let payloadData = try? JSONEncoder().encode(payload),
              let envelope = try? FernletIdentityEnvelope.signed(
                  identityService: identity,
                  senderDisplayName: displayName(),
                  recipientFingerprint: friend.fingerprint,
                  payloadType: .friendHeartDrop,
                  payloadEncryption: .none, // the outer HeartDropSealer seal IS the confidentiality
                  payloadSummary: PayloadSummary(title: PayloadType.friendHeartDrop.rawValue),
                  payload: payloadData,
                  createdAt: sentAt,
                  expiresAt: sentAt.addingTimeInterval(HeartDropOutbox.entryLifetime)
              ),
              let envelopeJSON = try? JSONEncoder().encode(envelope) else { return .failed }

        // Forward secrecy when a gossiped prekey is available; static fallback otherwise
        // (availability over FS — the friend may never have gossiped a bundle to us yet).
        let prekey = peerBundles.consumePrekey(forFriendSigningKey: friend.signingPublicKey)
        guard let pairSecret = try? identity.heartDropPairSecret(with: friend.keyAgreementPublicKey),
              let wire = try? HeartDropSealer.seal(
                  innerEnvelopeJSON: envelopeJSON,
                  toPrekey: prekey,
                  orStaticKey: friend.keyAgreementPublicKey
              ) else { return .failed }

        let tag = IdentityService.heartDropTag(
            pairSecret: pairSecret,
            dayEpoch: IdentityService.heartDropDayEpoch(at: sentAt),
            senderKeyAgreementPublicKey: identity.localKeyAgreementPublicKey
        )
        let entry = HeartDropOutbox.Entry(
            id: UUID(),
            friendSigningKey: friend.signingPublicKey,
            tag: tag,
            wire: wire,
            createdAt: sentAt
        )
        guard outbox.enqueue(entry) else { return .backlogFull }
        outboxRevision += 1
        ledger.recordHeartSent(to: friend.fingerprint) // consume-on-queue keeps the 5-min gate honest
        FernletAuditLog.log("heartdrop.queued", context: ["prekey": prekey == nil ? "static" : "one-time"])
        scheduleSync()
        return .queued
    }

    /// Hearts waiting for this friend (drives the "will be delivered" row state).
    public func pendingCount(for friend: ProximityTrustedPeerRecord) -> Int {
        _ = outboxRevision
        return outbox.pendingCount(friendSigningKey: friend.signingPublicKey)
    }

    // MARK: - Sync

    /// Foreground entry point: flush queued uploads, fetch incoming, clean up expired records.
    public func syncNow() {
        scheduleSync()
    }

    /// Awaitable one-shot sync — the deterministic seam tests drive instead of the
    /// fire-and-forget `syncNow()`. Waits out any in-flight sync (e.g. the one `queueHeart`
    /// auto-kicked) and then runs a full pass of its own, so callers return to a settled state.
    public func syncOnce() async {
        while isSyncing { await Task.yield() }
        guard isEnabled(), transport != nil else { return }
        isSyncing = true
        defer { isSyncing = false }
        await runSync()
    }

    private func scheduleSync() {
        guard !isSyncing, isEnabled(), transport != nil else { return }
        isSyncing = true
        Task { [weak self] in
            await self?.runSync()
            self?.isSyncing = false
        }
    }

    private func runSync() async {
        guard let transport, isEnabled() else { return }
        guard await transport.accountAvailable() else { return }
        await flush(transport)
        await fetchIncoming(transport)
        await cleanup(transport)
    }

    private func flush(_ transport: any HeartDropTransporting) async {
        for entry in outbox.pendingUploads() {
            do {
                let recordName = try await transport.upload(tag: entry.tag, payload: entry.wire)
                outbox.markUploaded(id: entry.id, recordName: recordName)
            } catch {
                outbox.recordAttempt(id: entry.id) // retried next sync until the 14 d expiry
            }
            outboxRevision += 1
        }
    }

    private func fetchIncoming(_ transport: any HeartDropTransporting) async {
        let friends = activeFriends().filter { !$0.keyAgreementPublicKey.isEmpty }
        guard !friends.isEmpty else { return }

        var tagOwner: [String: ProximityTrustedPeerRecord] = [:]
        let today = IdentityService.heartDropDayEpoch(at: now())
        for friend in friends {
            guard let pairSecret = try? identity.heartDropPairSecret(with: friend.keyAgreementPublicKey) else { continue }
            for offset in 0...Self.pickupWindowDays where today >= offset {
                // Expected INCOMING tags use the FRIEND as the sender term.
                let tag = IdentityService.heartDropTag(
                    pairSecret: pairSecret,
                    dayEpoch: today - offset,
                    senderKeyAgreementPublicKey: friend.keyAgreementPublicKey
                )
                tagOwner[tag] = friend
            }
        }
        guard let records = try? await transport.fetch(tags: Array(tagOwner.keys)) else { return }
        for record in records {
            openIncoming(record, expectedSender: tagOwner[record.tag])
        }
    }

    private func openIncoming(_ record: HeartDropRecord, expectedSender: ProximityTrustedPeerRecord?) {
        guard let inner = try? HeartDropSealer.open(
            record.payload,
            prekeyPrivateKey: { [prekeys] id in prekeys.privateKey(forPrekeyID: id) },
            staticAgreement: { [identity] eph in try identity.heartDropStaticAgreement(withEphemeralPublicKey: eph) },
            staticPublicKey: identity.localKeyAgreementPublicKey
        ), let envelope = try? JSONDecoder().decode(FernletIdentityEnvelope.self, from: inner) else { return }

        guard envelope.payloadType == .friendHeartDrop else { return }
        // Durable dedup FIRST — the ledger's 48 h retention can't stop a week-later re-fetch.
        guard dedup.recordIfNew(envelopeID: envelope.envelopeID) else { return }
        // The tag binds the pair; the signature must match the SAME friend (an attacker knowing a
        // tag still can't impersonate — the inner envelope is signed by the sender's identity key).
        guard let sender = expectedSender,
              envelope.senderSigningPublicKey == sender.signingPublicKey,
              sender.blockedAt == nil, sender.revokedAt == nil else { return }
        // nil replay cache: drops are legitimately older than the 24 h cache window; the durable
        // dedup above replaces it. Signature/schema/expiry/recipient checks all still run.
        guard let plaintext = try? envelope.verify(identityService: identity, replayCache: nil),
              let heart = try? JSONDecoder().decode(HeartPayload.self, from: plaintext),
              HeartPayload.isValidDayKey(heart.sentAtDayKey) else { return }
        // Receive-side flood bound: a malicious client could ignore its 5-min consume-on-send.
        guard dedup.acceptIfWithinDailyBudget(senderFingerprint: sender.fingerprint, dayKey: heart.sentAtDayKey) else { return }

        if ledger.recordReceivedDropHeart(
            id: heart.id,
            senderDisplayName: sender.displayName,
            senderFingerprint: sender.fingerprint
        ) {
            FernletAuditLog.log("heartdrop.received")
        }
    }

    private func cleanup(_ transport: any HeartDropTransporting) async {
        let expired = outbox.expiredEntries()
        guard !expired.isEmpty else { return }
        let uploadedNames = expired.compactMap(\.recordName)
        if !uploadedNames.isEmpty {
            guard (try? await transport.deleteOwnRecords(recordNames: uploadedNames)) != nil else { return }
        }
        outbox.remove(ids: expired.map(\.id))
        outboxRevision += 1
    }

    // MARK: - Delete-all seam (Docs/PrivacyWipeCoverage.md)

    public func wipeForDeleteAll() {
        prekeys.wipeForDeleteAll()
        peerBundles.wipeForDeleteAll()
        outbox.wipeForDeleteAll()
        dedup.wipeForDeleteAll()
        try? identity.wipe() // the service's own live IdentityService cache (4th instance)
        outboxRevision += 1
    }
}
