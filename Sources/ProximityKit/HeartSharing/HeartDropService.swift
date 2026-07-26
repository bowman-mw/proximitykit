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
///   fetch — consent → expected tags (kept friends × the full outbox lifetime in UTC days) →
///           open → durable dedup →
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
        /// Too many hearts already WAITING for this friend (`HeartDropOutbox.maxPendingPerFriend`).
        case backlogFull
        /// This friend's share of today is spent (`HeartDropOutbox.maxPerFriendPerDay`). Distinct
        /// from `.rateLimited` because it is honest: the wait is until tomorrow, not five minutes.
        case dailyLimitReached
        case disabled
        /// A sidecar the queue depends on is unavailable (Track A): the heart is refused rather
        /// than accepted into a state that could not be durably recorded.
        case storageUnavailable
        case failed
    }

    /// Why queued hearts are not flowing. Nothing-silent: `queueHeart` returns `.queued` and the
    /// UI promises delivery, so every state in which that promise is not being kept has to be
    /// observable by the app layer. Declared here (not in FernletDomainModel) deliberately.
    public enum DeliveryProblem: Equatable, Sendable {
        /// No iCloud account — the dead-drop can neither be written nor read at all.
        case noAccount
        /// Uploads keep failing (network, or the public schema not yet promoted).
        /// `since` is when the oldest still-waiting heart was queued.
        case uploadFailing(since: Date)
        /// Hearts given up on: they hit the outbox lifetime without ever reaching the drop.
        case undeliverable(count: Int)
        /// A heart sidecar cannot be read or written right now (locked-device read, failing
        /// write, or an unrecoverable store that had to be quarantined). Track A's
        /// nothing-silent surface: queued hearts are not flowing and new ones are refused.
        case storageUnavailable
    }

    /// Fetch looks back exactly as far as the sender keeps retrying, DERIVED from the outbox
    /// lifetime so the two can never drift apart: a heart that is still "waiting" on the sender
    /// must still be findable by the recipient (a two-week trip should not lose hearts).
    ///
    /// The window is the lifetime's whole days, NOT one less. Entries expire in CONTINUOUS time
    /// (`createdAt + entryLifetime`) while tags rotate on UTC midnights, so a drop created just
    /// before a midnight is still live after the 14th midnight has passed — by which point its
    /// creation day sits at offset 14, not 13. Querying `0...13` made that final sliver of a live,
    /// still-uploaded record unfindable while the sender's UI still counted it as deliverable.
    /// Cost of the alignment: 15 tags per friend instead of 7, which is why
    /// `HeartDropCloudTransport.fetch` MUST paginate its query cursor.
    public static let pickupWindowDays: UInt64 = UInt64(HeartDropOutbox.entryLifetime / 86_400)

    /// How far outside the pickup window a drop's signed `createdAt` may sit before the drop is
    /// refused — clock skew tolerance, and the clamp that keeps the receive-side flood budget
    /// bounded to a handful of day buckets per sender. Public: a term in the signed-prekey
    /// retention invariant test.
    public static let createdAtSkewTolerance: TimeInterval = 24 * 3600
    /// Upload retries on one heart before delivery is reported as failing.
    public static let failingAttemptThreshold = 3
    /// Floor between unforced `syncNow()` passes. Drops are days-scale by nature, so a minute of
    /// staleness costs the user nothing, while the scene/tab listener that calls it can fire many
    /// times a minute.
    public static let minimumSyncInterval: TimeInterval = 60
    /// Bound on coalesced re-runs of a single scheduled sync (see `scheduleSync`).
    static let maxCoalescedPasses = 4

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
    /// Non-nil when queued hearts are not reaching the dead-drop. Observed by the app layer.
    public private(set) var deliveryProblem: DeliveryProblem?

    /// Hearts that expired un-uploaded since the user last acknowledged the problem. Process-local
    /// by design: it is a nudge, not a record, and it must not become another persisted trace of
    /// who the user sends hearts to.
    @ObservationIgnored private var undeliveredCount = 0
    @ObservationIgnored private var syncTask: Task<Void, Never>?
    /// A heart queued while a sync was already running: the wakeup is coalesced into one re-run
    /// rather than dropped (it used to wait for the next foreground event).
    @ObservationIgnored private var syncRequestedAgain = false
    /// Invalidation token so a sync cancelled mid-flight (delete-all, purge) can't clear
    /// `isSyncing` out from under the pass that replaced it.
    @ObservationIgnored private var syncGeneration = 0
    /// The purge's equivalent: a purge suspended in its remote delete must not apply its
    /// non-record-scoped after-effects once a newer purge has taken over.
    @ObservationIgnored private var purgeGeneration = 0
    /// When the last pass actually started — the throttle floor for `syncNow()`.
    @ObservationIgnored private var lastSyncStartedAt: Date?

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
        self.prekeys = prekeys ?? HeartPrekeyStore(now: now)
        // Production stores are sealed at rest (Increment 4); tests that inject their own
        // stores choose their own seal (usually none, or a UUID-scoped keychain service).
        self.peerBundles = peerBundles
            ?? HeartDropPeerBundleCache(seal: HeartDropSidecarSeal.production(), now: now)
        self.outbox = outbox ?? HeartDropOutbox(seal: HeartDropSidecarSeal.production(), now: now)
        self.dedup = dedup ?? HeartDropDedupStore(seal: HeartDropSidecarSeal.production(), now: now)
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
    /// Consent-gated to mirror `currentLocalBundle()`: an opted-out device neither advertises nor
    /// accumulates drop reachability. (The cache is capped and LRU-evicted regardless — bundles
    /// arrive from every verified intro, not only from friends.)
    public func storePeerBundle(_ bundle: HeartPrekeyStore.Bundle, friendSigningKey: Data) {
        guard isEnabled() else { return }
        peerBundles.store(bundle: bundle, forFriendSigningKey: friendSigningKey)
    }

    // MARK: - Send

    public func queueHeart(to friend: ProximityTrustedPeerRecord) -> QueueOutcome {
        guard isEnabled(), friend.blockedAt == nil, friend.revokedAt == nil,
              !friend.keyAgreementPublicKey.isEmpty else { return .disabled }
        // Storage health BEFORE anything irreversible (Track A): an outbox that cannot durably
        // record the heart, or a ledger whose 5-minute gate cannot be checked or armed, refuses
        // the heart honestly instead of promising a delivery nothing can keep. Retried on access
        // and by every sync pass; the peer-bundle cache is deliberately NOT gated — its failure
        // mode is the static-key fallback, availability over FS.
        guard outbox.retryLoad(), ledger.isLoaded || ledger.retryLoad() else {
            refreshStorageProblemNow()
            return .storageUnavailable
        }
        let sentAt = now()
        // The daily cap is checked BEFORE the 5-minute gate on purpose: when both apply, "your
        // hearts for today are sent" is the state that actually persists, and telling the user to
        // wait five minutes for a heart that will still be refused afterwards is the lie.
        guard outbox.hasDailyCapacity(forFriendSigningKey: friend.signingPublicKey, at: sentAt) else {
            return .dailyLimitReached
        }
        guard ledger.canSendHeart(to: friend.fingerprint) else { return .rateLimited }
        // Capacity FIRST, before anything irreversible is spent: a one-time prekey consumed for a
        // heart that is then refused never returns to the pool, and repeated refusals would drain
        // the friend's 16-key bundle into permanent static-key fallback — losing forward secrecy
        // for no delivered heart at all. Same for the ledger's 5-minute cooldown.
        guard outbox.hasCapacity(forFriendSigningKey: friend.signingPublicKey) else { return .backlogFull }

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

        guard let pairSecret = try? identity.heartDropPairSecret(with: friend.keyAgreementPublicKey) else {
            return .failed
        }

        // Forward secrecy when a gossiped prekey is available — a one-time key first, else the
        // medium-term signed prekey (Track B); static fallback otherwise (availability over FS —
        // the friend may never have gossiped a bundle to us yet). Consumed as late as possible,
        // and handed back on every path that fails after it. Only a ONE-TIME key is returnable:
        // the signed prekey is reusable, so there is nothing to un-burn (and the cache's
        // returnPrekey guard would no-op on it only by accident of its consumption check).
        let prekey = peerBundles.consumePrekey(forFriendSigningKey: friend.signingPublicKey)
        func returnPrekey() {
            guard let prekey, prekey.isOneTime else { return }
            peerBundles.returnPrekey(id: prekey.id, forFriendSigningKey: friend.signingPublicKey)
        }

        guard let wire = try? HeartDropSealer.seal(
            innerEnvelopeJSON: envelopeJSON,
            toPrekey: prekey.map { (id: $0.id, publicKey: $0.publicKey) },
            orStaticKey: friend.keyAgreementPublicKey
        ) else {
            returnPrekey()
            return .failed
        }

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
        switch outbox.enqueue(entry) {
        case .queued:
            break
        case .backlogFull:
            returnPrekey()
            return .backlogFull
        case .storageUnavailable:
            returnPrekey()
            refreshStorageProblemNow()
            return .storageUnavailable
        }
        outboxRevision += 1
        ledger.recordHeartSent(to: friend.fingerprint) // consume-on-queue keeps the 5-min gate honest
        // The fallback mix ("signed" vs "static" especially) is the field telemetry that would
        // ever justify reopening per-friend prekey sets — keep the three cases distinguishable.
        let prekeyKind: String
        switch prekey {
        case nil: prekeyKind = "static"
        case .some(let used): prekeyKind = used.isOneTime ? "one-time" : "signed"
        }
        FernletAuditLog.log("heartdrop.queued", context: ["prekey": prekeyKind])
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
    ///
    /// Rate-limited by `minimumSyncInterval`, because the production caller is a scene/tab/lock
    /// listener that fires on every tab switch and each pass is a real public-database round trip.
    /// The invariant lives here rather than at the call site so a future caller inherits it. The
    /// paths that must be immediate do not go through it: `queueHeart` and `syncOnce()` reach
    /// `scheduleSync()`/`runSync()` directly, so a heart the user just sent still leaves now and
    /// tests stay deterministic. `force: true` is for a caller that IS user-initiated (a manual
    /// refresh) but has no heart to enqueue.
    public func syncNow(force: Bool = false) {
        if !force, let last = lastSyncStartedAt, now().timeIntervalSince(last) < Self.minimumSyncInterval {
            return
        }
        scheduleSync()
    }

    /// Awaitable one-shot sync — the deterministic seam tests drive instead of the
    /// fire-and-forget `syncNow()`. Waits out any in-flight sync (e.g. the one `queueHeart`
    /// auto-kicked) and then runs a full pass of its own, so callers return to a settled state.
    public func syncOnce() async {
        while isSyncing { await Task.yield() }
        guard isEnabled(), transport != nil else { return }
        syncGeneration += 1
        let generation = syncGeneration
        isSyncing = true
        defer { if generation == syncGeneration { isSyncing = false } }
        await runSync()
    }

    private func scheduleSync() {
        guard isEnabled(), transport != nil else { return }
        guard !isSyncing else {
            // Coalesce rather than drop: a heart queued mid-sync used to wait for the next
            // foreground event, because the pass that was already running had passed its flush.
            syncRequestedAgain = true
            return
        }
        syncGeneration += 1
        let generation = syncGeneration
        isSyncing = true
        lastSyncStartedAt = now()
        syncTask = Task { [weak self] in
            await self?.runCoalescedSyncPasses(generation: generation)
        }
    }

    private func runCoalescedSyncPasses(generation: Int) async {
        defer { if generation == syncGeneration { isSyncing = false } }
        var passes = 0
        repeat {
            syncRequestedAgain = false
            await runSync()
            passes += 1
        } while syncRequestedAgain && !Task.isCancelled && generation == syncGeneration
            && passes < Self.maxCoalescedPasses
    }

    /// Every await boundary re-checks cancellation AND consent: a pass that started before a
    /// delete-all or a consent withdrawal must not upload, and must not write into the
    /// just-cleared ledger/dedup/outbox (the "writers that resurrect data after a wipe" class).
    private func runSync() async {
        guard let transport, isEnabled() else { return }
        // The sync pass is the natural storage-recovery tick (Track A): re-attempt any failed
        // load (never overwriting a file that couldn't be read) and re-persist any value whose
        // last write failed — for the outbox that write can carry a record name that exists
        // nowhere else.
        outbox.retryLoad()
        dedup.retryLoad()
        peerBundles.retryLoad()
        ledger.retryLoad()
        let accountAvailable = await transport.accountAvailable()
        guard !Task.isCancelled, isEnabled() else { return }
        guard accountAvailable else {
            refreshDeliveryProblem(accountAvailable: false)
            return
        }
        await flush(transport)
        guard !Task.isCancelled, isEnabled() else { return }
        await fetchIncoming(transport)
        guard !Task.isCancelled, isEnabled() else { return }
        await cleanup(transport)
        guard !Task.isCancelled, isEnabled() else { return }
        refreshDeliveryProblem(accountAvailable: true)
    }

    private func flush(_ transport: any HeartDropTransporting) async {
        for entry in outbox.pendingUploads() {
            guard !Task.isCancelled, isEnabled() else { return }
            do {
                let recordName = try await transport.upload(tag: entry.tag, payload: entry.wire)
                guard !Task.isCancelled, isEnabled() else {
                    // The record is on the server but the outbox may be gone; the record name is
                    // lost with it, so log the orphan rather than write it back into a wiped store.
                    FernletAuditLog.log("heartdrop.upload.orphaned")
                    return
                }
                if !outbox.markUploaded(id: entry.id, recordName: recordName) {
                    // The write-failure sibling of the cancellation orphan above (the live bug
                    // Track A closes): the device locked across the await and the
                    // `.completeFileProtection` write failed. The name survives in the outbox's
                    // memory as the truth and a later persist commits it — but until then it is
                    // not durable, so say so and stop uploading more.
                    FernletAuditLog.log("heartdrop.upload.orphaned", context: ["reason": "persistFailed"])
                    outboxRevision += 1
                    refreshStorageProblemNow()
                    break
                }
            } catch {
                outbox.recordAttempt(id: entry.id) // retried next sync until the outbox expiry
            }
            outboxRevision += 1
        }
    }

    // MARK: - Delivery health (nothing-silent)

    /// True when any sidecar is `.unavailable` (unloaded or write-owed) or the outbox had to
    /// discard/quarantine data. Every one of these states breaks the "queued means delivered"
    /// promise, so all of them surface (Increment 3, nothing-silent).
    private var storageUnavailable: Bool {
        !outbox.isAvailable || !dedup.isAvailable || !peerBundles.isAvailable
            || !ledger.isLoaded || outbox.dataLossOccurred
    }

    /// Synchronous raise for paths that discover a storage problem outside a sync pass
    /// (a refused queue, a failed `markUploaded`) — the next pass re-derives it either way.
    private func refreshStorageProblemNow() {
        if storageUnavailable { deliveryProblem = .storageUnavailable }
    }

    private func refreshDeliveryProblem(accountAvailable: Bool) {
        if storageUnavailable {
            // Outranks everything: while a sidecar can't be read or written, the other signals
            // are either unknowable or stale.
            deliveryProblem = .storageUnavailable
        } else if undeliveredCount > 0 {
            deliveryProblem = .undeliverable(count: undeliveredCount)
        } else if !accountAvailable {
            // Surfaced even with an empty outbox: with no account, away hearts can be neither
            // delivered nor received, and the toggle being on is an explicit opt-in to the
            // feature — silently doing nothing is the failure mode this exists to prevent.
            deliveryProblem = .noAccount
        } else if let failure = outbox.uploadFailureState(),
                  failure.maxAttempts >= Self.failingAttemptThreshold {
            deliveryProblem = .uploadFailing(since: failure.oldestCreatedAt)
        } else {
            deliveryProblem = nil
        }
    }

    /// Clears a surfaced delivery problem once the user has seen it. The underlying condition
    /// re-raises it on the next sync if it is still true (a sticky data-loss marker is cleared
    /// here — it is a nudge, not a record).
    public func acknowledgeDeliveryProblem() {
        undeliveredCount = 0
        outbox.acknowledgeDataLoss()
        deliveryProblem = nil
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
        guard !Task.isCancelled, isEnabled() else { return }
        for record in records {
            openIncoming(record, expectedSender: tagOwner[record.tag])
        }
    }

    private func openIncoming(_ record: HeartDropRecord, expectedSender: ProximityTrustedPeerRecord?) {
        // Storage pre-check (Track A): accepting a drop spends durable state at three seams —
        // the dedup mark, the daily-budget mark, and the ledger record. If any of them can't
        // persist, leave the record on the server untouched; the next sync re-fetches it.
        // Consuming the dedup/budget marks and then failing the ledger write would burn the
        // envelope id and lose the heart.
        guard dedup.isAvailable, ledger.isLoaded else { return }
        // Size gate before any decryption or inflation — the public database accepts writes from
        // any authenticated iCloud user, so a fat record under a known tag is a denial-of-service
        // attempt, not a heart.
        guard record.payload.count <= HeartDropSealer.maxWireByteCount else {
            FernletAuditLog.log("heartdrop.rejected", context: [
                "reason": "oversized", "bytes": "\(record.payload.count)"
            ])
            return
        }
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
        // The bucket is a RECEIVER-side day. `heart.sentAtDayKey` stays display-only — it is
        // sender-controlled and only shape-checked, so keying the budget on it made the bound
        // vacuous (~10^8 reachable buckets). `envelope.createdAt` is signature-covered but still
        // sender-CHOSEN, so it is clamped to the window the pickup query can legitimately have
        // returned; that leaves ~16 buckets per sender, which is what makes the cap bind.
        let currentTime = now()
        let createdAt = envelope.createdAt
        guard createdAt <= currentTime.addingTimeInterval(Self.createdAtSkewTolerance),
              createdAt >= currentTime.addingTimeInterval(
                  -(HeartDropOutbox.entryLifetime + Self.createdAtSkewTolerance)) else {
            FernletAuditLog.log("heartdrop.rejected", context: ["reason": "createdAt-outside-window"])
            return
        }
        guard dedup.acceptIfWithinDailyBudget(
            senderFingerprint: sender.fingerprint,
            dayEpoch: IdentityService.heartDropDayEpoch(at: createdAt)
        ) else { return }

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
        // Hearts that aged out without ever being uploaded were never delivered — count them so
        // the user can be told, instead of them disappearing quietly.
        let neverUploaded = expired.filter { $0.recordName == nil }.count
        let uploadedNames = expired.compactMap(\.recordName)
        if !uploadedNames.isEmpty {
            guard (try? await transport.deleteOwnRecords(recordNames: uploadedNames)) != nil else { return }
        }
        guard !Task.isCancelled, isEnabled() else { return }
        outbox.remove(ids: expired.map(\.id))
        if neverUploaded > 0 {
            undeliveredCount += neverUploaded
            FernletAuditLog.log("heartdrop.undeliverable", context: ["count": "\(neverUploaded)"])
        }
        outboxRevision += 1
    }

    // MARK: - Purge (consent withdrawn / delete-all)

    /// Deletes THIS device's uploaded drop records from the dead-drop and drops the outbox entries
    /// that named them.
    ///
    /// Deliberately NOT gated on `isEnabled()`: both callers run when consent is already gone —
    /// the user turning the away-hearts toggle off, and delete-all. Delete-all must call this
    /// BEFORE `wipeForDeleteAll()`, because the wipe destroys the very record names needed to
    /// delete our own public-database records (recipients cannot delete a sender's records).
    ///
    /// Returns false when the remote delete did not succeed; the outbox is then KEPT so a later
    /// attempt can retry, since a public-DB record nobody can name is a record nobody can remove.
    @discardableResult
    public func purgeDeadDrop() async -> Bool {
        cancelInFlightSync()
        purgeGeneration += 1
        let generation = purgeGeneration
        // Captured BEFORE the await and removed BY ID after it — never `removeAll()`. A purge is a
        // suspension point long enough for the user to turn away-hearts back on and send: wiping
        // the outbox on resume would silently destroy that heart, and with it the record name of an
        // already-uploaded one, stranding that record on the public database forever.
        //
        // Nil snapshot = the outbox never loaded, so what is on the public database is UNKNOWN.
        // Report failure so the derived retry seam tries again — an unknown answer must never
        // read as "nothing to purge" (Track A).
        guard outbox.retryLoad(), let doomed = outbox.snapshot() else { return false }
        let recordNames = doomed.compactMap(\.recordName)
        guard !recordNames.isEmpty else {
            // No await between the capture and here, so nothing can have raced in.
            outbox.removeUnchanged(doomed)
            outboxRevision += 1
            acknowledgeDeliveryProblem()
            return true
        }
        guard let transport else { return false }
        guard (try? await transport.deleteOwnRecords(recordNames: recordNames)) != nil else {
            FernletAuditLog.log("heartdrop.purge.failed", context: ["records": "\(recordNames.count)"])
            return false
        }
        // Exactly what we captured, and only where it is unchanged. Hearts enqueued during the
        // delete arrived under renewed consent (or belong to a newer purge, which captured them
        // itself) and survive untouched; so does a captured entry that got UPLOADED during the
        // delete, whose new record name we did not pass to `deleteOwnRecords`.
        let removed = outbox.removeUnchanged(doomed)
        outboxRevision += 1
        // The only after-effect that is not about the records we deleted, so it is the only one that
        // has to re-validate: a superseded purge must not clear a delivery problem raised since it
        // started, or the nothing-silent promise breaks on exactly the re-enable path.
        if generation == purgeGeneration, !isEnabled() {
            acknowledgeDeliveryProblem()
        }
        FernletAuditLog.log("heartdrop.purged", context: [
            "records": "\(recordNames.count)", "entries": "\(removed)"
        ])
        return true
    }

    /// Sealed hearts THIS DEVICE has sitting on the CloudKit public database right now — derived
    /// from the outbox's uploaded record names, never from a process-local flag. NIL while the
    /// outbox is unloaded: the answer is unknown, and an unknown reported as zero is exactly the
    /// "the UI says it's gone when it isn't" lie the derived form exists to kill (Track A).
    ///
    /// Two things need the derived form: a purge owed from a previous launch (a process flag dies
    /// with the process, the record names do not), and consent withdrawn on ANOTHER device, which
    /// arrives by settings sync and so never runs the local setter that would have set a flag.
    /// Reads `outboxRevision` so an observing view re-derives when the outbox changes.
    public func uploadedDeadDropRecordCount() -> Int? {
        _ = outboxRevision
        return outbox.uploadedRecordNames()?.count
    }

    /// True when a dead-drop purge is still owed: this device has records out there that only this
    /// device can name (recipients cannot delete a sender's public-DB records). While the outbox
    /// is unloaded the answer is unknown and this fails CLOSED (true): the retry seam keeps
    /// trying, and `purgeDeadDrop()` itself reports failure until the outbox can be read.
    public func hasStrandedDeadDropRecords() -> Bool {
        uploadedDeadDropRecordCount().map { $0 > 0 } ?? true
    }

    // MARK: - Delete-all seam (Docs/PrivacyWipeCoverage.md)

    /// Callers should `await purgeDeadDrop()` first when the network allows it — this wipe drops
    /// the record names our own uploaded records are addressed by.
    public func wipeForDeleteAll() {
        cancelInFlightSync()
        prekeys.wipeForDeleteAll()
        peerBundles.wipeForDeleteAll()
        outbox.wipeForDeleteAll()
        dedup.wipeForDeleteAll()
        try? identity.wipe() // the service's own live IdentityService cache (4th instance)
        undeliveredCount = 0
        deliveryProblem = nil
        outboxRevision += 1
    }

    /// Cancels the scheduled sync and invalidates its generation, so a pass suspended at an await
    /// cannot resume into the cleared stores. Cancellation is cooperative — the guards in
    /// `runSync`/`flush`/`fetchIncoming`/`cleanup` are what actually stop the writes.
    private func cancelInFlightSync() {
        syncTask?.cancel()
        syncTask = nil
        syncGeneration += 1
        isSyncing = false
        syncRequestedAgain = false
    }
}
