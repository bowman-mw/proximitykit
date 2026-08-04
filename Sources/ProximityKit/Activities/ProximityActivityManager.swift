// ProximityActivityManager.swift
// ProximityKit/Activities
//
// The state + logic brain for Group Activities (Phase 6). Owned by `MeshNetworkManager` (a sub-manager
// like `MeshClothingShop`); activities RIDE THE FRIEND MESH — no new radio, no new Bonjour service. The
// UWB dwell-commit that forms a friend session IS the join ritual; every activity payload is exchanged
// only between committed, transport-verified peers.
//
// This type owns:
//  * the roster state (activities I host / joined / have been offered / pending join requests),
//  * host-authoritative minting + verification (via the `ActivityJoinToken`/`ActivityRosterSnapshot`
//    crypto in `ActivityPayloads.swift`), and
//  * a device-local sidecar (App Support JSON, `.completeFileProtection`, NEVER synced — the
//    HeartLedger/ClosenessLedger stance) so a hosted/joined activity survives launches until `expiresAt`.
//
// It does NOT touch `MCSession` directly. `MeshNetworkManager` wires two closures in:
//  * `send` — seal + sign + transmit a payload to one verified fingerprint's committed slot;
//  * `committedActivityPeerFingerprints` — the fingerprints of currently-committed peers that advertise
//    the `.activities` capability.
// and forwards every received activity payload here. Authorization is INDEPENDENT of the shared
// handshake: the friend-session trust policy hard-codes `isTrustedProximityPeer == true`, so the grant
// carries its own host-signed, invitee-key-bound token (exactly as hearts carry their own eligibility).

import Foundation
import Observation
import FernletDomainModel

/// The state + logic brain for Group Activities (Phase 6): hosting, joining, offers, pending
/// join requests, and host-authoritative roster convergence — riding the friend mesh with no
/// radio of its own.
///
/// Owned by ``MeshNetworkManager`` (a sub-manager like ``MeshClothingShop``), which wires in the
/// two seams this type uses instead of touching MCSession: `send` (seal + sign + transmit to one
/// verified fingerprint's committed slot) and `committedActivityPeerFingerprints`. Authorization
/// is independent of the shared handshake: membership is carried by the host-signed,
/// invitee-key-bound `ActivityJoinToken`, snapshots verify only under the host key PINNED at
/// join, and roster convergence is max-version-wins. Receive paths reject oversized/hand-crafted
/// descriptors (the 7-day lifetime ceiling is re-enforced here, by rejection rather than
/// clamping, because the signed params hash must not be rewritten) and never serve a roster to a
/// non-member. Hosted/joined activities persist in a device-local sidecar
/// (`ActivityLedger.json`, `.completeFileProtection`, NEVER synced) until `expiresAt`; offers
/// and pending joins are memory-only. `@MainActor @Observable`.
@MainActor
@Observable
public final class ProximityActivityManager {

    // MARK: - Stored activity shapes

    /// An activity this device hosts. `participants` includes the host; `currentSnapshot` is the latest
    /// host-signed roster (kept in sync with `participants`/`version`). Persisted.
    public struct HostedActivity: Codable, Equatable, Identifiable {
        public var id: UUID { descriptor.activityID }
        public var descriptor: ActivityDescriptor
        public var participants: [ActivityParticipant]
        public var version: Int
        public var currentSnapshot: ActivityRosterSnapshot
    }

    /// An activity this device has joined. `descriptor` is PINNED at join (its `hostSigningPublicKey` is
    /// the trust root for every later snapshot); `token` is our membership credential; `lastSnapshot` is
    /// the highest verified roster we hold. Persisted.
    public struct JoinedActivity: Codable, Equatable, Identifiable {
        public var id: UUID { descriptor.activityID }
        public var descriptor: ActivityDescriptor
        public var token: ActivityJoinToken
        public var lastSnapshot: ActivityRosterSnapshot
    }

    /// An activity a committed host offered us this session. Memory-only (never persisted — an offer is a
    /// live invitation, not a commitment).
    public struct OfferedActivity: Identifiable, Equatable {
        public var id: UUID { descriptor.activityID }
        public var descriptor: ActivityDescriptor
        public var offeringFingerprint: String
        public var rosterVersion: Int
        public var receivedAt: Date
    }

    /// A join request awaiting the host's confirm. Carries the TRANSPORT-VERIFIED joiner identity (never
    /// the wire-claimed values) so the minted token binds the real key. Memory-only.
    public struct PendingActivityJoin: Identifiable, Equatable {
        public var id: String { verifiedFingerprint }
        public var activityID: UUID
        public var verifiedFingerprint: String
        public var displayName: String
        public var verifiedSigningPublicKey: Data
        public var verifiedKeyAgreementPublicKey: Data
        public var receivedAt: Date
    }

    // MARK: - Observable state

    public private(set) var hostedActivities: [HostedActivity] = []
    public private(set) var joinedActivities: [JoinedActivity] = []
    public private(set) var offeredActivities: [OfferedActivity] = []
    public private(set) var pendingJoinRequests: [PendingActivityJoin] = []
    /// A user-facing error string surfaced by the Activities screen; cleared by the view.
    public var activityError: String?

    // MARK: - Injected dependencies

    @ObservationIgnored private unowned let store: any ProximityHost
    @ObservationIgnored private let identity: IdentityService?
    @ObservationIgnored private let fileURL: URL
    @ObservationIgnored private let now: () -> Date

    /// Set by `MeshNetworkManager`: seal+sign+transmit a payload to a verified fingerprint's committed
    /// slot. `sealed: false` only for the bodyless-ish `.activityJoinRequest`.
    public typealias ActivitySend = @MainActor (_ type: PayloadType, _ payload: any Encodable, _ toFingerprint: String, _ sealed: Bool) async -> Void
    @ObservationIgnored public var send: ActivitySend?
    /// Set by `MeshNetworkManager`: fingerprints of currently-committed peers advertising `.activities`.
    @ObservationIgnored public var committedActivityPeerFingerprints: (() -> [String])?

    /// Per-peer rate limit on `activitySync` snapshot replies (anti-amplification).
    @ObservationIgnored private var lastSyncReplyAt: [String: Date] = [:]
    static let syncReplyRateLimitSeconds: TimeInterval = 2

    public init(
        store: any ProximityHost,
        identity: IdentityService? = nil,
        fileURL: URL? = nil,
        now: @escaping () -> Date = Date.init
    ) {
        self.store = store
        self.identity = identity
        self.fileURL = fileURL ?? Self.defaultFileURL()
        self.now = now
        load()
        gcExpired()
    }

    // MARK: - Host actions (called by the Activities screen)

    /// Creates an activity this device hosts (host is the sole initial participant), signs the initial
    /// roster, persists, and offers it to every currently-committed `.activities` peer. Returns the
    /// descriptor, or nil (no identity / host cap reached / signing failed) with `activityError` set.
    @discardableResult
    public func host(
        title: String,
        activityTypeToken: String,
        coarseLocation: String?,
        expiresAt: Date
    ) -> ActivityDescriptor? {
        gcExpired()
        guard let identity else { activityError = "Identity unavailable."; return nil }
        guard hostedActivities.count < ActivityLimits.maxHosted else {
            activityError = "You can host up to \(ActivityLimits.maxHosted) activities."
            return nil
        }
        let created = now()
        let cleanTitle = ItemNameModeration.sanitizedName(title)
        let cleanLocation = coarseLocation.map { ItemNameModeration.sanitizedName($0) }.flatMap { $0.isEmpty ? nil : $0 }
        let descriptor = ActivityDescriptor(
            activityID: UUID(),
            hostFingerprint: identity.localFingerprint,
            hostSigningPublicKey: identity.localSigningPublicKey,
            title: cleanTitle,
            activityTypeToken: activityTypeToken,
            coarseLocation: cleanLocation,
            createdAt: created,
            expiresAt: ActivityDescriptor.clampedExpiry(createdAt: created, requested: expiresAt)
        )
        let hostParticipant = ActivityParticipant(
            fingerprint: identity.localFingerprint,
            displayName: ItemNameModeration.sanitizedName(store.proximityDisplayName),
            signingPublicKey: identity.localSigningPublicKey,
            keyAgreementPublicKey: identity.localKeyAgreementPublicKey,
            joinedAt: created
        )
        let version = 1
        guard let snapshot = try? ActivityRosterSnapshot.signed(
            activityID: descriptor.activityID,
            version: version,
            participants: [hostParticipant],
            issuedAt: created,
            hostIdentity: identity
        ) else {
            activityError = "Couldn't create the activity."
            return nil
        }
        hostedActivities.append(HostedActivity(
            descriptor: descriptor, participants: [hostParticipant], version: version, currentSnapshot: snapshot
        ))
        save()
        // Offer the new activity to peers already in this session.
        for fingerprint in committedActivityPeerFingerprints?() ?? [] {
            sendOffers(to: fingerprint)
        }
        return descriptor
    }

    /// The host stops hosting locally. v1 sends no revocation tombstone (deferred) — members' copies
    /// simply expire at `expiresAt`.
    public func endHosting(activityID: UUID) {
        hostedActivities.removeAll { $0.descriptor.activityID == activityID }
        save()
    }

    /// The host removes a member: bump the version, re-sign the roster, and gossip the new snapshot to
    /// remaining committed members (max-version-wins convergence). The removed peer keeps its stale copy
    /// + still-valid token until expiry (no tombstones in v1).
    public func removeParticipant(activityID: UUID, fingerprint: String) {
        guard let identity, let index = hostedActivities.firstIndex(where: { $0.descriptor.activityID == activityID }) else { return }
        var hosted = hostedActivities[index]
        // Never remove the host from its own roster.
        guard fingerprint != hosted.descriptor.hostFingerprint else { return }
        guard hosted.participants.contains(where: { $0.fingerprint == fingerprint }) else { return }
        hosted.participants.removeAll { $0.fingerprint == fingerprint }
        hosted.version += 1
        guard let snapshot = try? ActivityRosterSnapshot.signed(
            activityID: activityID,
            version: hosted.version,
            participants: hosted.participants,
            issuedAt: now(),
            hostIdentity: identity
        ) else { return }
        hosted.currentSnapshot = snapshot
        hostedActivities[index] = hosted
        save()
        gossipSnapshot(snapshot)
    }

    /// The host confirms a pending join: mint a token bound to the TRANSPORT-VERIFIED joiner key (never
    /// the wire claim), append the participant, bump + re-sign the roster, send the sealed grant, and
    /// gossip the new snapshot to other members. Idempotent by signing key (a duplicate never double-adds).
    public func admitJoin(_ pending: PendingActivityJoin) {
        pendingJoinRequests.removeAll { $0.verifiedFingerprint == pending.verifiedFingerprint && $0.activityID == pending.activityID }
        guard let identity, let index = hostedActivities.firstIndex(where: { $0.descriptor.activityID == pending.activityID }) else { return }
        var hosted = hostedActivities[index]
        // Already a member (a host double-fire / stale pending)? Do nothing — re-admitting must not
        // inflate the version or re-gossip (they already hold a valid grant + roster).
        guard !hosted.participants.contains(where: { $0.signingPublicKey == pending.verifiedSigningPublicKey }) else { return }
        // Cap the roster (host included).
        guard hosted.participants.count < ActivityLimits.maxParticipants else {
            activityError = "This activity is full."
            return
        }
        let paramsHash = ActivityParamsHash.of(hosted.descriptor)
        hosted.version += 1
        hosted.participants.append(ActivityParticipant(
            fingerprint: pending.verifiedFingerprint,
            displayName: ItemNameModeration.sanitizedName(pending.displayName),
            signingPublicKey: pending.verifiedSigningPublicKey,
            keyAgreementPublicKey: pending.verifiedKeyAgreementPublicKey,
            joinedAt: now()
        ))
        guard
            let token = try? ActivityJoinToken.signed(
                activityID: hosted.descriptor.activityID,
                activityParamsHash: paramsHash,
                joinerFingerprint: pending.verifiedFingerprint,
                joinerSigningPublicKey: pending.verifiedSigningPublicKey,
                hostIdentity: identity,
                grantedAt: now(),
                expiresAt: hosted.descriptor.expiresAt,
                rosterVersionAtGrant: hosted.version
            ),
            let snapshot = try? ActivityRosterSnapshot.signed(
                activityID: hosted.descriptor.activityID,
                version: hosted.version,
                participants: hosted.participants,
                issuedAt: now(),
                hostIdentity: identity
            )
        else {
            activityError = "Couldn't grant the join."
            return
        }
        hosted.currentSnapshot = snapshot
        hostedActivities[index] = hosted
        save()
        let grant = ActivityJoinGrantPayload(token: token, snapshot: snapshot)
        let recipient = pending.verifiedFingerprint
        Task { [weak self] in await self?.send?(.activityJoinGrant, grant, recipient, true) }
        gossipSnapshot(snapshot)
    }

    /// Re-mints and re-sends a grant to an EXISTING roster member (their key is already in the verified
    /// roster, so no new participant is admitted and the roster is not mutated). Used to recover an
    /// orphaned or re-joining member — see `receiveJoinRequest`. The token is freshly signed at the
    /// current roster version; the current signed snapshot is re-delivered unchanged.
    private func regrantExistingMember(_ member: ActivityParticipant, hostedIndex: Int) {
        guard let identity else { return }
        let hosted = hostedActivities[hostedIndex]
        guard let token = try? ActivityJoinToken.signed(
            activityID: hosted.descriptor.activityID,
            activityParamsHash: ActivityParamsHash.of(hosted.descriptor),
            joinerFingerprint: member.fingerprint,
            joinerSigningPublicKey: member.signingPublicKey,
            hostIdentity: identity,
            grantedAt: now(),
            expiresAt: hosted.descriptor.expiresAt,
            rosterVersionAtGrant: hosted.version
        ) else { return }
        let grant = ActivityJoinGrantPayload(token: token, snapshot: hosted.currentSnapshot)
        let recipient = member.fingerprint
        Task { [weak self] in await self?.send?(.activityJoinGrant, grant, recipient, true) }
    }

    public func declineJoin(_ pending: PendingActivityJoin) {
        pendingJoinRequests.removeAll { $0.verifiedFingerprint == pending.verifiedFingerprint && $0.activityID == pending.activityID }
    }

    // MARK: - Joiner actions (called by the Activities screen)

    /// Ask an offered activity's host to join. Sends the UNSEALED `.activityJoinRequest` to the host's
    /// committed slot; the host re-validates our claimed identity against the transport-verified slot.
    public func requestJoin(_ offered: OfferedActivity) {
        guard let identity else { activityError = "Identity unavailable."; return }
        gcExpired()
        guard !offered.descriptor.isExpired(at: now()) else {
            activityError = "That activity has expired."
            offeredActivities.removeAll { $0.descriptor.activityID == offered.descriptor.activityID }
            return
        }
        guard joinedActivities.count < ActivityLimits.maxJoined else {
            activityError = "You've joined the maximum number of activities."
            return
        }
        let request = ActivityJoinRequestPayload(
            activityID: offered.descriptor.activityID,
            joinerFingerprint: identity.localFingerprint,
            joinerDisplayName: ItemNameModeration.sanitizedName(store.proximityDisplayName),
            joinerSigningPublicKey: identity.localSigningPublicKey,
            joinerKeyAgreementPublicKey: identity.localKeyAgreementPublicKey
        )
        let hostFingerprint = offered.offeringFingerprint
        Task { [weak self] in await self?.send?(.activityJoinRequest, request, hostFingerprint, false) }
    }

    public func dismissOffer(activityID: UUID) {
        offeredActivities.removeAll { $0.descriptor.activityID == activityID }
    }

    public func leaveJoined(activityID: UUID) {
        joinedActivities.removeAll { $0.descriptor.activityID == activityID }
        save()
    }

    // MARK: - Inbound (called by MeshNetworkManager's registered handlers)

    /// A committed host offered an activity. The handler has already gated on committed-slot + block +
    /// vault trust. `verifiedHostSigningPublicKey` is the sender's transport-verified key — we require it
    /// to equal the descriptor's `hostSigningPublicKey`, pinning the trust root to the real sender.
    public func receiveOffer(_ payload: ActivityOfferPayload, fromFingerprint: String, verifiedHostSigningPublicKey: Data) {
        guard payload.isWellFormed else { return }
        let descriptor = payload.descriptor
        guard !descriptor.isExpired(at: now()) else { return }
        // Enforce the HARD 7-day ephemerality ceiling on the receive path too (`host()` clamps, but a
        // patched host could hand-craft a far-future descriptor that would then NEVER be GC'd, keeping
        // every member's identity keys on disk forever). We must REJECT rather than clamp — clamping
        // rewrites bytes and would diverge the signed `activityParamsHash`. Bound `createdAt` as well, so a
        // future-dated `createdAt` can't defeat the delta.
        guard descriptor.createdAt <= now().addingTimeInterval(60 * 60),
              descriptor.expiresAt <= descriptor.createdAt.addingTimeInterval(ActivityLimits.maxLifetime)
        else { return }
        // The offering peer MUST be the host: transport-verified key == descriptor host key, and the
        // descriptor's host fingerprint is consistent with its host key.
        guard descriptor.hostSigningPublicKey == verifiedHostSigningPublicKey,
              descriptor.hostFingerprint == fromFingerprint,
              IdentityService.fingerprintsMatch(
                IdentityService.fingerprint(of: descriptor.hostSigningPublicKey), descriptor.hostFingerprint
              ) else { return }
        // Already hosting or joined? Nothing to offer.
        guard !hostedActivities.contains(where: { $0.descriptor.activityID == descriptor.activityID }),
              !joinedActivities.contains(where: { $0.descriptor.activityID == descriptor.activityID }) else { return }
        // Anti-abuse bound: a legit host sanitizes at creation (title/location <= maxNameLength), so this
        // only drops a hostile oversized descriptor — never a well-formed one. We must NOT rewrite the
        // descriptor's bytes: the signed join token binds `activityParamsHash = SHA-256(descriptor)`, so
        // the joiner has to pin the descriptor EXACTLY as received or its paramsHash would diverge and
        // every grant would be rejected. Rendering sanitizes via `descriptor.sanitizedTitle` instead.
        guard descriptor.title.count <= ItemNameModeration.maxNameLength,
              (descriptor.coarseLocation?.count ?? 0) <= ItemNameModeration.maxNameLength else { return }
        offeredActivities.removeAll { $0.descriptor.activityID == descriptor.activityID }
        offeredActivities.insert(OfferedActivity(
            descriptor: descriptor, offeringFingerprint: fromFingerprint, rosterVersion: payload.rosterVersion, receivedAt: now()
        ), at: 0)
        if offeredActivities.count > 24 { offeredActivities = Array(offeredActivities.prefix(24)) }
    }

    /// A committed peer asked to join one of my activities. The handler passes the TRANSPORT-VERIFIED
    /// joiner identity; we accept only if the claimed fingerprint/key match the verified values (mirror
    /// `handleAdmissionRequest`), then queue the request for the host's confirm.
    public func receiveJoinRequest(
        _ payload: ActivityJoinRequestPayload,
        verifiedFingerprint: String,
        verifiedSigningPublicKey: Data,
        verifiedKeyAgreementPublicKey: Data
    ) {
        guard payload.isWellFormed else { return }
        // Claimed identity must equal the transport-verified identity.
        guard payload.joinerFingerprint == verifiedFingerprint,
              payload.joinerSigningPublicKey == verifiedSigningPublicKey else { return }
        guard let index = hostedActivities.firstIndex(where: { $0.descriptor.activityID == payload.activityID }) else { return }
        let hosted = hostedActivities[index]
        guard !hosted.descriptor.isExpired(at: now()) else { return }
        // Already a member? RE-ISSUE their grant rather than dropping the request. This recovers two
        // dead-ends: a member whose original grant send failed (stranded in the roster with no token), and
        // a member who left and is re-joining (their local join was deleted but the host still lists them).
        // The roster is unchanged, so no version bump / re-gossip — we only re-deliver their token + the
        // current snapshot to the transport-verified requester (whose key already equals a roster member's).
        if let member = hosted.participants.first(where: { $0.signingPublicKey == verifiedSigningPublicKey }) {
            regrantExistingMember(member, hostedIndex: index)
            return
        }
        // Dedup pending by fingerprint+activity.
        pendingJoinRequests.removeAll { $0.verifiedFingerprint == verifiedFingerprint && $0.activityID == payload.activityID }
        pendingJoinRequests.append(PendingActivityJoin(
            activityID: payload.activityID,
            verifiedFingerprint: verifiedFingerprint,
            displayName: ItemNameModeration.sanitizedName(payload.joinerDisplayName),
            verifiedSigningPublicKey: verifiedSigningPublicKey,
            verifiedKeyAgreementPublicKey: verifiedKeyAgreementPublicKey,
            receivedAt: now()
        ))
        if pendingJoinRequests.count > ActivityLimits.maxParticipants {
            pendingJoinRequests = Array(pendingJoinRequests.suffix(ActivityLimits.maxParticipants))
        }
    }

    /// The host granted our join. Verify the token (bound to OUR key + expected activity + params hash)
    /// and the snapshot (under the PINNED host key from the offer we're joining), then persist membership.
    public func receiveGrant(_ payload: ActivityJoinGrantPayload, fromFingerprint: String) {
        guard payload.isWellFormed, let identity else { return }
        let activityID = payload.token.activityID
        // We must have an offer we pinned (the descriptor + host key). Grants for unknown activities are
        // dropped — we never join something we weren't offered in person.
        guard let offered = offeredActivities.first(where: { $0.descriptor.activityID == activityID }) else { return }
        let descriptor = offered.descriptor
        guard fromFingerprint == descriptor.hostFingerprint else { return }
        // Defense-in-depth: a grant can't extend the pinned lifetime beyond the descriptor we accepted.
        guard payload.token.expiresAt <= descriptor.expiresAt else { return }
        let paramsHash = ActivityParamsHash.of(descriptor)
        do {
            try payload.token.verify(
                joinerSigningPublicKey: identity.localSigningPublicKey,
                expectedActivityID: activityID,
                expectedParamsHash: paramsHash,
                expectedHostSigningPublicKey: descriptor.hostSigningPublicKey,
                now: now()
            )
            try payload.snapshot.verify(
                expectedActivityID: activityID,
                expectedHostSigningPublicKey: descriptor.hostSigningPublicKey
            )
        } catch {
            activityError = "That invitation couldn't be verified."
            return
        }
        offeredActivities.removeAll { $0.descriptor.activityID == activityID }
        // Idempotent by activity id.
        if let existing = joinedActivities.firstIndex(where: { $0.descriptor.activityID == activityID }) {
            // Keep the higher-version snapshot.
            if payload.snapshot.version > joinedActivities[existing].lastSnapshot.version {
                joinedActivities[existing].lastSnapshot = payload.snapshot
                joinedActivities[existing].token = payload.token
            }
        } else {
            // Cap persisted memberships on the INBOUND path too — a patched host could otherwise mint 24
            // valid grants/session and grow the sidecar past the cap without the user ever tapping "join".
            guard joinedActivities.count < ActivityLimits.maxJoined else { return }
            joinedActivities.append(JoinedActivity(
                descriptor: descriptor, token: payload.token, lastSnapshot: payload.snapshot
            ))
        }
        save()
    }

    /// A host-signed roster snapshot arrived (gossip). Apply it to a hosted or joined activity iff it
    /// verifies under the PINNED host key and is a higher version (max-wins). Anyone may relay it — it
    /// self-authenticates — so the sender need not be the host.
    public func receiveSnapshot(_ snapshot: ActivityRosterSnapshot) {
        let activityID = snapshot.activityID
        if let index = joinedActivities.firstIndex(where: { $0.descriptor.activityID == activityID }) {
            let pinnedHostKey = joinedActivities[index].descriptor.hostSigningPublicKey
            guard (try? snapshot.verify(expectedActivityID: activityID, expectedHostSigningPublicKey: pinnedHostKey)) != nil else { return }
            guard snapshot.version > joinedActivities[index].lastSnapshot.version else { return }
            joinedActivities[index].lastSnapshot = snapshot
            save()
        }
        // A host never accepts a foreign snapshot for its own activity — it is the sole authority.
    }

    /// A committed peer's version digest. For each activity where WE hold a strictly higher verified
    /// version, push our snapshot (rate-limited). Convergence: both sides digest on commit; each pushes
    /// what it holds higher.
    public func receiveSync(_ sync: ActivitySyncPayload, fromFingerprint: String) {
        guard sync.isWellFormed else { return }
        if let last = lastSyncReplyAt[fromFingerprint], now().timeIntervalSince(last) < Self.syncReplyRateLimitSeconds { return }
        var replied = false
        for entry in sync.held.prefix(ActivityLimits.maxJoined + ActivityLimits.maxHosted) {
            // Only serve a roster to a peer who is IN it — otherwise a committed non-member could name a
            // random activity id and pull the members' identities. `gossipSnapshot` enforces the same rule.
            if let snapshot = bestSnapshot(for: entry.activityID),
               snapshot.version > entry.versionHeld,
               snapshot.participants.contains(where: { $0.fingerprint == fromFingerprint }) {
                let target = fromFingerprint
                Task { [weak self] in await self?.send?(.activityRosterSnapshot, ActivityRosterSnapshotPayload(snapshot: snapshot), target, true) }
                replied = true
            }
        }
        if replied { lastSyncReplyAt[fromFingerprint] = now() }
    }

    // MARK: - Commit hook (called by MeshNetworkManager on each slot commit)

    /// A peer committed: offer them everything we host, and exchange a version digest so any newer roster
    /// converges.
    public func onPeerCommitted(fingerprint: String) {
        gcExpired()
        sendOffers(to: fingerprint)
        sendSyncDigest(to: fingerprint)
    }

    // MARK: - Outbound helpers

    /// Offer up to `maxOffersPerCommit` non-expired hosted activities to one committed peer.
    private func sendOffers(to fingerprint: String) {
        let offers = hostedActivities
            .filter { !$0.descriptor.isExpired(at: now()) }
            .prefix(ActivityLimits.maxOffersPerCommit)
            .map { ActivityOfferPayload(descriptor: $0.descriptor, rosterVersion: $0.version) }
        for offer in offers {
            Task { [weak self] in await self?.send?(.activityOffer, offer, fingerprint, true) }
        }
    }

    /// Send our version digest to one committed peer — but ONLY for activities that peer is a MEMBER of.
    /// A committed friend who isn't in an activity must never learn its id/version (it would let them
    /// pull the full roster), so this mirrors `gossipSnapshot`'s membership filter. An activity's roster
    /// (identities of everyone in it) is a private social graph, not session-wide knowledge.
    private func sendSyncDigest(to fingerprint: String) {
        var entries: [ActivitySyncPayload.Entry] = []
        for hosted in hostedActivities
        where !hosted.descriptor.isExpired(at: now()) && hosted.participants.contains(where: { $0.fingerprint == fingerprint }) {
            entries.append(.init(activityID: hosted.descriptor.activityID, versionHeld: hosted.version))
        }
        for joined in joinedActivities
        where !joined.descriptor.isExpired(at: now()) && joined.lastSnapshot.participants.contains(where: { $0.fingerprint == fingerprint }) {
            entries.append(.init(activityID: joined.descriptor.activityID, versionHeld: joined.lastSnapshot.version))
        }
        guard !entries.isEmpty else { return }
        let payload = ActivitySyncPayload(held: entries)
        Task { [weak self] in await self?.send?(.activitySync, payload, fingerprint, true) }
    }

    /// Gossip a fresh host-signed snapshot to every currently-committed member of that activity.
    private func gossipSnapshot(_ snapshot: ActivityRosterSnapshot) {
        let members = Set(snapshot.participants.map(\.fingerprint))
        for fingerprint in committedActivityPeerFingerprints?() ?? [] where members.contains(fingerprint) {
            Task { [weak self] in await self?.send?(.activityRosterSnapshot, ActivityRosterSnapshotPayload(snapshot: snapshot), fingerprint, true) }
        }
    }

    /// The highest-version snapshot we can vouch for an activity (hosted authority > joined copy).
    private func bestSnapshot(for activityID: UUID) -> ActivityRosterSnapshot? {
        if let hosted = hostedActivities.first(where: { $0.descriptor.activityID == activityID }) {
            return hosted.currentSnapshot
        }
        return joinedActivities.first(where: { $0.descriptor.activityID == activityID })?.lastSnapshot
    }

    // MARK: - GC + reset

    /// Drop expired hosted/joined/offered activities. Called on launch, on foreground, and lazily before
    /// each state read.
    public func gcExpired() {
        let t = now()
        let hostedBefore = hostedActivities.count
        let joinedBefore = joinedActivities.count
        hostedActivities.removeAll { $0.descriptor.isExpired(at: t) }
        joinedActivities.removeAll { $0.descriptor.isExpired(at: t) }
        offeredActivities.removeAll { $0.descriptor.isExpired(at: t) }
        pendingJoinRequests.removeAll { pending in
            !hostedActivities.contains { $0.descriptor.activityID == pending.activityID }
        }
        // Prune the per-peer sync rate-limit map so it can't grow one entry per lifetime-distinct peer.
        let syncCutoff = t.addingTimeInterval(-Self.syncReplyRateLimitSeconds * 10)
        lastSyncReplyAt = lastSyncReplyAt.filter { $0.value >= syncCutoff }
        if hostedActivities.count != hostedBefore || joinedActivities.count != joinedBefore { save() }
    }

    /// "Reset everything": wipe all in-memory state + the sidecar file.
    public func clearAll() {
        hostedActivities = []
        joinedActivities = []
        offeredActivities = []
        pendingJoinRequests = []
        lastSyncReplyAt = [:]
        activityError = nil
        try? FileManager.default.removeItem(at: fileURL)
    }

    // MARK: - Persistence (device-local sidecar, NEVER synced)

    /// Versioned sidecar shape: hosted + joined activities only (offers and pending joins are
    /// deliberately memory-only). Missing keys decode to empty.
    private struct PersistedState: Codable {
        var version = 1
        var hosted: [HostedActivity] = []
        var joined: [JoinedActivity] = []
        init() {}
        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            version = try c.decodeIfPresent(Int.self, forKey: .version) ?? 1
            hosted = try c.decodeIfPresent([HostedActivity].self, forKey: .hosted) ?? []
            joined = try c.decodeIfPresent([JoinedActivity].self, forKey: .joined) ?? []
        }
    }

    private func load() {
        guard let data = try? Data(contentsOf: fileURL),
              let state = try? JSONDecoder().decode(PersistedState.self, from: data) else { return }
        hostedActivities = state.hosted
        joinedActivities = state.joined
    }

    private func save() {
        var state = PersistedState()
        state.hosted = hostedActivities
        state.joined = joinedActivities
        guard let data = try? JSONEncoder().encode(state) else { return }
        try? FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: fileURL, options: [.atomic, .completeFileProtection])
    }

    private nonisolated static func defaultFileURL() -> URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("Fernlet/ActivityLedger.json")
    }
}
