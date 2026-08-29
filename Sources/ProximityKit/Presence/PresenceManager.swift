// PresenceManager.swift
// ProximityKit/Presence
//
// The standing presence radio (mesh redesign Phase 4a/4b, Docs/Proximity-Mesh-Redesign-2026-07-10.md):
// a continuous advertise+browse on `fernlet-near` that lets KEPT friends recognize each other
// nearby without connecting. It broadcasts ONLY rotating pairwise-DH tags — no display name, no
// stable session id.
//
// Phase 4b — hearts ride the presence layer. The standalone `fernlet-heart` radio is deleted; a
// heart is delivered over an ON-DEMAND, short-lived pairwise connection formed on THIS presence
// session:
//   send:    invite the currently-discovered peer whose pairwise tag matched the intended friend →
//            1-RTT friend-mode handshake → programmatic auto-commit → verify the connected identity
//            IS that friend (verified fingerprint + heart-eligible vault record) → sealed
//            `friendHeart` → ledger record → teardown (coordinator cancel + best-effort
//            disconnectPeer so zombies never accumulate toward the 8-peer MCSession cap).
//   receive: accept invitations ONLY from peers whose discovered tag matched a friend; the inbound
//            `friendHeart` runs the same coordinator machinery and the ported receive gates
//            (verified sender, active-friend vault check, blocked/revoked drop, display-name
//            sanitization) plus the 5-minute receive-rate mirror.
// The send-side `allowNearbyHearts` gate, the inbound drop when it is off, and the FriendListView
// row render are the three homes of the hearts opt-out; presence VISIBILITY is governed by the
// separate `allowNearbyPresence` setting — hearts-off + presence-on means a friend still sees you
// nearby but an inbound heart to you is silently dropped.
//
// Privacy posture:
//  - The advertised discoveryInfo is `{v: "1", t: <own tags>}`. Each tag is a truncated HMAC of
//    the current 15-minute epoch under a per-friend-pair static-static X25519 secret
//    (`IdentityService.presenceTag`), so a passive observer sees an unlinkable value that rotates
//    every epoch, and only the two members of a pair can derive it. Blocking/removing a friend
//    drops their tag at the next roster rebuild.
//  - The radio's MCPeerID is per-start RANDOM and never persisted (`usesEphemeralPeerID`), so
//    presence is cross-launch unlinkable — it deliberately does NOT share the stable archived
//    peer ID the other radios use.
//  - Everything here is memory-only: the nearby set is never persisted, never synced, and the
//    diagnostics ring never carries an identity.
//  - Accepted residual (spec): an active adversary replaying a tag within its epoch can spoof
//    "friend nearby"; connection-forming flows add invitation gating in 4b.
//
// Lifecycle is owned by ContentView (opt-in setting + scene phase + tab + lock), exactly like the
// recipe/heart listeners; the opt-out setter (`FernletStore.setAllowNearbyPresence`) stops the
// manager immediately.
//
// Manager-Task lifetime rule (Phase-3 crash): every escaping Task below captures `[weak self]`,
// and the epoch-rotation loop re-acquires `self` in a SCOPED binding each iteration so no strong
// reference is ever held across a suspension — a strong capture would extend the manager past its
// owning store and abort on the store's `unowned` reference.

import Foundation
import Observation
import UIKit
import FernletDomainModel
import FernletFoundation

/// One in-flight heart connection on the presence session. Retains its `FriendSessionTrustPolicy`
/// for the connection's lifetime so the coordinator's `weak` trustPolicy stays alive (the
/// revoked/blocked-key envelope rejection + audit calls silently no-op otherwise) — mirrors the
/// recipe manager's `RecipeShareConnection`.
private struct PresenceHeartConnection: Identifiable {
    let id: UUID
    let peer: PeerHandle
    let channel: PeerChannelTransport
    let coordinator: ProximityCoordinator
    let trustPolicy: FriendSessionTrustPolicy
    /// The friend this connection is delivering a heart to (outbound). `nil` = an inbound-only
    /// connection we accepted so a friend could send US a heart.
    var intendedFriend: ProximityTrustedPeerRecord?
    var fingerprint: String?
    /// Set once the outbound heart has been written, so teardown/observation never re-sends.
    var didSend = false
}

/// The standing presence radio (`fernlet-near`): lets KEPT friends recognize each other nearby
/// without connecting, and delivers in-person hearts over on-demand pairwise connections formed
/// on that recognition.
///
/// Privacy posture is the design center: the advertisement carries ONLY rotating pairwise-DH
/// tags (truncated HMACs of the 15-minute epoch under per-friend-pair static-static X25519
/// secrets — see `IdentityService.presenceTag`), the MCPeerID is per-start random and never
/// persisted, and all state (nearby set, connections, diagnostics) is memory-only with no
/// identities in any log line. Matching spans ±1 epoch; three self-exclusion layers drop our own
/// ghost advertisements; a 45 s lost-grace debounce smooths the epoch advertiser-restart flap.
///
/// Hearts (Phase 4b): sends invite the tag-matched peer, run a 1-RTT friend handshake with the
/// SEALED-INTRODUCTION rule (intro/ack sealed to the intended friend's vault KA key so a
/// tag-replay forger learns nothing), auto-commit, verify the connected identity IS that friend
/// and heart-eligible, deliver one sealed `.friendHeart`, then tear down — zombie connections
/// must never accumulate toward the 8-peer MCSession cap. Receives accept invitations only from
/// tag-matched peers and enforce the `allowNearbyHearts` opt-out, the trusted-friend gate, and
/// the shared ``ProximityHeartLedger`` 5-minute receive window. The away-delivery seams
/// (`queueAwayHeart`, prekey-bundle gossip) hand race-window sends to the dead-drop. Every
/// escaping Task captures `[weak self]` (manager-Task lifetime rule — the owning store holds
/// this `unowned`). Lifecycle is owned by the app (opt-in setting + scene/tab/lock).
/// `@MainActor @Observable`.
@MainActor
@Observable
public final class PresenceManager: ProximityPayloadHandling {

    /// The multi-second send pipeline, observed by FriendListView (spinner while connecting, then
    /// distinct copy for each terminal state). `verifying` is the window between the transport
    /// connecting and the identity being confirmed as the intended friend.
    public enum HeartSendState: Equatable {
        case idle
        case connecting(recipientName: String)
        case verifying(recipientName: String)
        case sent(recipientName: String)
        case failed(message: String)
    }

    public private(set) var heartSendState: HeartSendState = .idle

    /// 12 chars — MCNearbyServiceAdvertiser crashes at init beyond 15.
    public static let serviceType = "fernlet-near"
    /// Max own tags advertised (most-recently-seen friends first). 24 tags × 12 base64 chars
    /// + separators ≈ 312 B, safely inside the ~400 B Bonjour TXT budget.
    static let maxAdvertisedTags = 24
    /// A matched peer counts as GONE only after this much continuous absence — spans the
    /// epoch advertiser-restart flap (lost+found) without flickering the nearby set.
    static let lostGraceInterval: TimeInterval = 45

    /// Vault fingerprints of kept friends currently recognized nearby. Memory-only, observable.
    public private(set) var nearbyFriendFingerprints: Set<String> = []
    public private(set) var diagnosticEvents: [ProximityRecipeShareDiagnosticEvent] = []

    /// Max concurrent heart connections on the presence session — a small cap well under the
    /// 8-peer MCSession limit (hearts are short-lived: invite → send → teardown in seconds).
    static let maxHeartConnections = 4
    /// Per-attempt pre-connect budget: if the invited peer hasn't produced an MC channel in this
    /// long, retry the invite (the pre-discovery race — the peer hasn't discovered us yet).
    /// Internal so tests can shorten it.
    @ObservationIgnored var heartConnectTimeoutSeconds: TimeInterval = 8
    /// Total invite attempts before giving up (initial + 2 retries), mirroring the mesh re-invite
    /// pattern the recipe cap uses.
    static let maxHeartInviteAttempts = 3
    /// R3 cap on the self-exclusion name ring: `start()` runs once per scene/tab/lock toggle, so
    /// the set is fed by repeated user actions. Only the last few starts can still have a Bonjour
    /// ghost on the air, so remembering 32 is generous.
    static let maxRememberedEphemeralNames = 32
    static let heartReinviteDelaySeconds: TimeInterval = 2

    @ObservationIgnored private unowned let store: any ProximityHost
    @ObservationIgnored private let identity: IdentityService
    @ObservationIgnored private let ledger: ProximityHeartLedger
    @ObservationIgnored private let replayCache = ReplayCache()
    /// Fired (with the friend's fingerprint) when a heart is successfully sent / received, so the app can
    /// feed the closeness signal. Set by the app; nil in tests / when closeness isn't wired.
    @ObservationIgnored public var onHeartSent: ((String) -> Void)?
    @ObservationIgnored public var onHeartReceived: ((String) -> Void)?
    @ObservationIgnored private var session: MeshMultipeerSession?
    @ObservationIgnored private(set) var isRunning = false

    /// Live heart connections (outbound sends in flight + inbound accepts). Keyed by peer UUID.
    @ObservationIgnored private var heartConnections: [PresenceHeartConnection] = []
    /// Peers currently discovered nearby (the PeerHandle objects), so a send can invite the
    /// exact peer whose tag matched the intended friend.
    @ObservationIgnored private var discoveredPeers: [UUID: PeerHandle] = [:]
    /// Outbound sends awaiting their MC channel: peer UUID → (friend, attempt count).
    @ObservationIgnored private var pendingHeartSends: [UUID: (friend: ProximityTrustedPeerRecord, attempt: Int)] = [:]
    @ObservationIgnored private var heartObservationTask: Task<Void, Never>?
    @ObservationIgnored private var heartConnectTimeoutTasks: [UUID: Task<Void, Never>] = [:]
    @ObservationIgnored private var clearHeartStatusTask: Task<Void, Never>?
    private var heartConnectionObservationRevision = 0

    /// Advertised tag tokens (base64 of the 8-byte pair tag) for the CURRENT epoch, one per
    /// capped roster friend. Internal for tests.
    @ObservationIgnored private(set) var ownTagTokens: Set<String> = []
    /// Candidate token → friend fingerprint, spanning epoch −1…+1 for EVERY eligible friend
    /// (matching is uncapped; only the advertised set is capped). Internal for tests.
    @ObservationIgnored private(set) var candidateTokens: [String: String] = [:]
    /// Display names of the most recent ephemeral peer IDs this manager generated — exact
    /// recognition of our own previous-start ghost advertisements (self-exclusion layer 1).
    /// Bounded: see ``rememberOwnEphemeralPeerName(_:)``.
    @ObservationIgnored private var ownEphemeralPeerNames: Set<String> = []
    /// Insertion order for `ownEphemeralPeerNames`, so the cap evicts the OLDEST name.
    @ObservationIgnored private var ownEphemeralPeerNameOrder: [String] = []

    /// Matched friend fingerprints per discovered peer (peers currently contributing to the
    /// nearby set — including peers within the lost-grace window).
    @ObservationIgnored private var matchedFingerprintsByPeer: [UUID: Set<String>] = [:]
    /// The raw tag tokens each matched peer advertised, kept so an epoch rotation can re-match
    /// cached advertisements against the fresh candidate window.
    @ObservationIgnored private var tokensByPeer: [UUID: Set<String>] = [:]
    /// Peers reported lost, awaiting the debounce grace before removal (re-found cancels).
    @ObservationIgnored private var peerLostAt: [UUID: Date] = [:]

    @ObservationIgnored private var currentEpoch: UInt64 = 0
    @ObservationIgnored private var epochRotationTask: Task<Void, Never>?
    /// The single in-flight lost-peer sweep (see ``scheduleLostSweep()``) — nil when none is armed.
    @ObservationIgnored private var lostSweepTask: Task<Void, Never>?

    /// Test seam: injectable clock (epoch derivation, lost-grace expiry). Production default.
    @ObservationIgnored var nowProvider: () -> Date = { Date() }

    public init(store: any ProximityHost, ledger: ProximityHeartLedger, identity: IdentityService? = nil) {
        self.store = store
        self.ledger = ledger
        if let identity {
            self.identity = identity
        } else {
            let id = IdentityService()
            // Fail-soft: the manager still constructs, but a failed provisioning is NAMED (R7) —
            // otherwise every later presence tag and heart send fails with no visible cause.
            do {
                try id.ensureProvisioned()
            } catch {
                FernletAuditLog.log(
                    "presence.identity.provisionFailed",
                    context: ["error": String(describing: error)]
                )
            }
            self.identity = id
        }
    }

    // MARK: - Lifecycle

    /// Ends every long-running task the manager owns if it is released without `stop()` (the
    /// production instance never is — process-lifetime on the store — but tasks must not outlive
    /// their owner: the observation loop would stay parked, the timers spin one more tick).
    /// `isolated`: the handles are main-actor state.
    isolated deinit {
        heartObservationTask?.cancel()
        clearHeartStatusTask?.cancel()
        epochRotationTask?.cancel()
        lostSweepTask?.cancel()
        for task in heartConnectTimeoutTasks.values { task.cancel() }
    }

    public func start() {
        guard !isRunning else { return }
        isRunning = true
        currentEpoch = IdentityService.presenceEpoch(at: nowProvider())
        rebuildTags(epoch: currentEpoch)

        // Fresh ephemeral MCPeerID per start (never persisted, never the shared archived ID).
        let session = MeshMultipeerSession(usesEphemeralPeerID: true)
        rememberOwnEphemeralPeerName(session.localPeerID.displayName)
        session.onPeerDiscovered = { [weak self] peer in
            self?.handleDiscoveredPeer(peer)
        }
        session.onPeerLost = { [weak self] peer in
            self?.handleLostPeer(peer)
        }
        // Phase 4b — hearts: accept an invitation ONLY from a peer whose discovered tag matched a
        // friend (the nearby-match map). A pre-discovery-race inviter is rejected; the sender
        // retries (see armHeartConnectTimeout).
        session.shouldAcceptInvitation = { [weak self] peer in
            self?.shouldAcceptHeartInvitation(peer) ?? false
        }
        session.onPeerChannelReady = { [weak self] channel in
            self?.handleHeartChannelReady(channel)
        }
        session.onPeerDisconnected = { [weak self] peer, _ in
            self?.removeHeartConnection(matching: peer)
        }
        session.onTransportError = { [weak self] message in
            self?.recordDiagnostic(message)
        }
        self.session = session
        session.start(serviceType: Self.serviceType, discoveryInfo: discoveryInfo())
        startEpochRotation()
        startHeartObserving()
        recordDiagnostic("Presence started.")
    }

    public func stop() {
        if isRunning {
            recordDiagnostic("Presence stopped.")
        }
        isRunning = false
        epochRotationTask?.cancel()
        epochRotationTask = nil
        lostSweepTask?.cancel()
        lostSweepTask = nil
        teardownAllHeartConnections()
        heartObservationTask?.cancel()
        heartObservationTask = nil
        clearHeartStatusTask?.cancel()
        clearHeartStatusTask = nil
        session?.stop()
        session = nil
        matchedFingerprintsByPeer.removeAll()
        tokensByPeer.removeAll()
        peerLostAt.removeAll()
        discoveredPeers.removeAll()
        ownTagTokens.removeAll()
        candidateTokens.removeAll()
        nearbyFriendFingerprints = []
        heartSendState = .idle
    }

    /// The vault roster changed (friend kept / blocked / revoked / unblocked): re-derive tags
    /// and restart the advertiser with the fresh set. No-op while not running — `start()`
    /// derives from the live vault anyway.
    public func refreshRoster() {
        guard isRunning else { return }
        rebuildTags(epoch: IdentityService.presenceEpoch(at: nowProvider()))
        session?.updateDiscoveryInfo(discoveryInfo())
        reevaluateDiscoveredPeers()
    }

    // MARK: - Roster → tags

    /// Vault friends eligible for presence: not blocked, not revoked, with real key material
    /// (block-only stubs carry an empty KA key). Most-recently-seen first, which is also the
    /// advertise-cap preference order.
    static func eligibleFriends(in peers: [ProximityTrustedPeerRecord]) -> [ProximityTrustedPeerRecord] {
        peers
            .filter {
                $0.blockedAt == nil && $0.revokedAt == nil
                    && !$0.keyAgreementPublicKey.isEmpty && !$0.signingPublicKey.isEmpty
            }
            .sorted { $0.lastSeenAt > $1.lastSeenAt }
    }

    private func rebuildTags(epoch: UInt64) {
        currentEpoch = epoch
        let eligible = Self.eligibleFriends(in: store.proximityTrustVault.trustedPeers)

        // A tag that fails to derive silently drops that friend from presence entirely, so the
        // failures are counted and surfaced once per rebuild (R7) — count only, never an identity.
        var derivationFailures = 0
        var own: Set<String> = []
        for friend in eligible.prefix(Self.maxAdvertisedTags) {
            do {
                let tag = try identity.presenceTag(for: friend.keyAgreementPublicKey, epoch: epoch)
                own.insert(tag.base64EncodedString())
            } catch {
                derivationFailures += 1
            }
        }
        ownTagTokens = own

        // Matching window ±1 epoch: a peer's advertisement is static until they restart their
        // advertiser, so their tags may lag ours by one rotation (and clocks skew both ways).
        var candidates: [String: String] = [:]
        for friend in eligible {
            for candidateEpoch in [epoch &- 1, epoch, epoch &+ 1] {
                do {
                    let tag = try identity.presenceTag(for: friend.keyAgreementPublicKey, epoch: candidateEpoch)
                    candidates[tag.base64EncodedString()] = friend.fingerprint
                } catch {
                    derivationFailures += 1
                }
            }
        }
        candidateTokens = candidates
        if derivationFailures > 0 {
            recordDiagnostic("Skipped \(derivationFailures) presence tag(s) — derivation failed.")
        }
    }

    /// The advertised TXT payload: version + own tags ONLY. No display name, no session id —
    /// nothing stable or user-identifying (identifier hygiene is the whole point of this radio).
    private func discoveryInfo() -> [String: String] {
        ["v": "1", "t": ownTagTokens.sorted().joined(separator: ",")]
    }

    // MARK: - Discovery → nearby set

    private func handleDiscoveredPeer(_ peer: PeerHandle) {
        guard let info = peer.discoveryInfo, info["v"] == "1", let joined = info["t"] else { return }
        // Self-exclusion layer 1: our own previous-start ghost (stale Bonjour cache during a
        // stop/start) advertises under an ephemeral display name we generated this launch.
        guard !ownEphemeralPeerNames.contains(peer.displayHint) else { return }

        let tokens = Set(joined.split(separator: ",").map(String.init)).filter { !$0.isEmpty }
        var matched: Set<String> = []
        for token in tokens {
            if let fingerprint = candidateTokens[token] { matched.insert(fingerprint) }
        }
        guard !matched.isEmpty else {
            // Not (or no longer) a friend advertisement — forget any prior match for this peer.
            removePeer(peer.id)
            return
        }
        // Self-exclusion layer 3 (single-friend ghost): a genuine friend who has ANY friend
        // besides us advertises at least one pair tag we cannot derive (we hold neither private
        // key of that pair), so their FULL advertised set is never a subset of our own advertised
        // tags. Our own previous-start ghost (a stale Bonjour cache under a random name this
        // process never generated, so self-exclusion layer 1 misses it) advertises nothing beyond
        // our own tags. Treat a fully-own token set as self. RESIDUAL (bounded, accepted, spec):
        // a mutual friend whose ONLY friend is us, at the same 15-min epoch, is indistinguishable
        // from our ghost by tags alone and is likewise excluded; an adjacent-epoch advertisement
        // carries a tag outside `ownTagTokens`, so the flap case still recognizes them.
        if tokens.isSubset(of: ownTagTokens) {
            recordDiagnostic("Ignored a presence advertisement matching only our own tags (self/ghost).")
            removePeer(peer.id)
            return
        }
        // Self-exclusion layer 2 (impossible-for-genuine invariant): every pair tag is unique to
        // its pair, so a REAL peer's advertisement can match at most ONE of our friends. An ad
        // matching 2+ distinct friends is our own reflected tag set (a ghost we failed to name-
        // match) or a spliced replay — never a friend. Drop it.
        guard matched.count == 1 else {
            recordDiagnostic("Ignored a presence advertisement matching multiple friends (self/replay).")
            removePeer(peer.id)
            return
        }
        matchedFingerprintsByPeer[peer.id] = matched
        tokensByPeer[peer.id] = tokens
        discoveredPeers[peer.id] = peer
        peerLostAt.removeValue(forKey: peer.id)
        recomputeNearby()
    }

    private func handleLostPeer(_ peer: PeerHandle) {
        guard matchedFingerprintsByPeer[peer.id] != nil else { return }
        peerLostAt[peer.id] = nowProvider()
        // Debounce: the peer stays "nearby" through the grace window (epoch restart flap); the
        // sweep only removes peers still absent when it fires. Re-discovery clears the mark.
        scheduleLostSweep()
    }

    /// Arms the single lost-peer sweep, re-arming itself while any mark remains.
    ///
    /// R3 (bounded task fan-out): ONE in-flight sweep task per manager, not one 46-second sleeping
    /// task per lost-peer event — a flapping advertiser used to accumulate tasks in proportion to
    /// its event rate.
    private func scheduleLostSweep() {
        guard lostSweepTask == nil else { return }
        lostSweepTask = Task { @MainActor [weak self] in
            do {
                try await Task.sleep(for: .seconds(Self.lostGraceInterval + 1))
            } catch {
                // Cancelled (stop/teardown): the marks are cleared by `stop()`; nothing to sweep.
                self?.lostSweepTask = nil
                return
            }
            guard let self else { return }
            self.lostSweepTask = nil
            self.sweepExpiredPeers()
            // Peers marked after this task armed are still inside their grace window — re-arm so
            // they expire too, and stop re-arming once no marks remain.
            if !self.peerLostAt.isEmpty { self.scheduleLostSweep() }
        }
    }

    /// Records one of our own ephemeral peer-ID display names, evicting the oldest past
    /// ``maxRememberedEphemeralNames`` so repeated `start()` calls cannot grow the set unboundedly (R3).
    private func rememberOwnEphemeralPeerName(_ name: String) {
        guard ownEphemeralPeerNames.insert(name).inserted else { return }
        ownEphemeralPeerNameOrder.append(name)
        while ownEphemeralPeerNameOrder.count > Self.maxRememberedEphemeralNames {
            let oldest = ownEphemeralPeerNameOrder.removeFirst()
            ownEphemeralPeerNames.remove(oldest)
        }
    }

    /// Drops peers that have been continuously absent for `lostGraceInterval`. Uses the
    /// injectable clock so the debounce is unit-testable without waiting.
    private func sweepExpiredPeers() {
        let now = nowProvider()
        let expired = peerLostAt.filter { now.timeIntervalSince($0.value) >= Self.lostGraceInterval }
        guard !expired.isEmpty else { return }
        for id in expired.keys { removePeer(id) }
    }

    private func removePeer(_ id: UUID) {
        matchedFingerprintsByPeer.removeValue(forKey: id)
        tokensByPeer.removeValue(forKey: id)
        // Keep the peer object if a heart connection is still using it — the connection teardown
        // prunes it once it also stops matching. Otherwise drop it.
        if !heartConnections.contains(where: { $0.id == id }) {
            discoveredPeers.removeValue(forKey: id)
        }
        peerLostAt.removeValue(forKey: id)
        recomputeNearby()
    }

    /// After a heart connection ends, drop the peer object ONLY if it is no longer part of the
    /// nearby set — i.e. a real departure that `removePeer` deferred while the connection was live.
    /// A still-advertising (still-matched) peer is KEPT so `isReachable` and the sendable set agree
    /// (Group 4: a teardown must not strand a present peer as reachable-but-unsendable).
    private func pruneDiscoveredPeerIfDeparted(_ id: UUID) {
        if matchedFingerprintsByPeer[id] == nil {
            discoveredPeers.removeValue(forKey: id)
        }
    }

    private func recomputeNearby() {
        let current = matchedFingerprintsByPeer.values.reduce(into: Set<String>()) { $0.formUnion($1) }
        if current != nearbyFriendFingerprints {
            nearbyFriendFingerprints = current
        }
    }

    // MARK: - Epoch rotation

    private func startEpochRotation() {
        epochRotationTask?.cancel()
        epochRotationTask = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                // SCOPED strong bindings only — never hold `self` across the sleep (manager-Task
                // lifetime rule; a strong capture would outlive the owning store and abort).
                guard let delay = self?.delayToNextEpochBoundary() else { return }
                // Cancellation ends the rotation loop — that IS the recovery (R7).
                do {
                    try await Task.sleep(for: .seconds(delay))
                } catch {
                    return
                }
                if let self {
                    self.rotateEpochIfNeeded()
                } else {
                    return
                }
            }
        }
    }

    private func delayToNextEpochBoundary() -> TimeInterval {
        let now = nowProvider().timeIntervalSince1970
        let intoEpoch = now.truncatingRemainder(dividingBy: IdentityService.presenceEpochSeconds)
        // +0.5 s slack so the wake lands cleanly inside the next epoch; minimum 1 s so a
        // boundary-adjacent wake can never busy-loop.
        return max(1, IdentityService.presenceEpochSeconds - intoEpoch + 0.5)
    }

    /// Epoch boundary: re-derive candidates, restart the advertiser with fresh tags
    /// (`updateDiscoveryInfo` uses the stop-and-recreate pattern), and re-match cached peer
    /// advertisements — a peer whose (static) ad is now 2+ epochs stale falls out of the
    /// candidate window and drops.
    func rotateEpochIfNeeded() {
        let epoch = IdentityService.presenceEpoch(at: nowProvider())
        guard epoch != currentEpoch else { return }
        rebuildTags(epoch: epoch)
        session?.updateDiscoveryInfo(discoveryInfo())
        reevaluateDiscoveredPeers()
    }

    /// Re-match every cached advertisement against the current candidate window (roster or epoch
    /// changed). Peers that no longer match anything are removed immediately — their tags are
    /// provably not a current friend's (blocked/removed friends must disappear promptly).
    private func reevaluateDiscoveredPeers() {
        var dropped: [UUID] = []
        for (id, tokens) in tokensByPeer {
            var matched: Set<String> = []
            for token in tokens {
                if let fingerprint = candidateTokens[token] { matched.insert(fingerprint) }
            }
            if matched.count == 1 {
                matchedFingerprintsByPeer[id] = matched
            } else {
                dropped.append(id)
            }
        }
        // Same release path as a lost/self-excluded peer (R3): `removePeer` also drops the
        // `discoveredPeers` entry — unless a live heart connection still holds the peer, whose
        // teardown prunes it. Removing only the match bookkeeping here orphaned the peer object
        // (a later `lostPeer` found no `tokensByPeer` entry, so the entry lived until `stop()`).
        for id in dropped { removePeer(id) }
        recomputeNearby()
    }

    // MARK: - Hearts: reachability + send

    /// First word of a display name for warm copy ("Aisha" from "Aisha Bloom"). Pure, so
    /// `nonisolated`. Moved here from the deleted ProximityHeartManager.
    public nonisolated static func firstName(of displayName: String) -> String {
        let trimmed = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let first = trimmed.split(separator: " ").first, !first.isEmpty else { return "your friend" }
        return String(first)
    }

    /// A friend is heart-reachable when their pairwise tag is in the presence nearby set right now.
    public func isReachable(fingerprint: String) -> Bool {
        nearbyFriendFingerprints.contains { IdentityService.fingerprintsMatch($0, fingerprint) }
    }

    /// The heart-send affordance for a friend (Group 2 — "hearts require presence"). Pure and
    /// unit-testable: reachability is the presence nearby set, so hearts-ON + presence-OFF would
    /// otherwise render every friend perpetually "Not nearby" with a misleading hint. That case is
    /// a DISTINCT `needsPresence` state — an actionable prompt to turn on Nearby Friends — never a
    /// dead "not nearby". `reachable` is meaningful only when presence is enabled.
    public enum HeartAffordance: Equatable, Sendable {
        case heartsOff       // the hearts opt-out is off — the send affordance is hidden entirely
        case needsPresence   // hearts on, presence off, away delivery off — prompt to enable presence
        case notNearby       // not recognized nearby, but a heart can still be sent (away delivery)
        case reachable       // ready to send in person
    }

    /// Pure decision for `HeartAffordance`. IN-PERSON hearts function only when presence is also on
    /// — but away delivery (bitchat adoptions Increment 3) needs no radio at all, so once the user
    /// has opted into it the presence prompt is wrong: the friend is simply `.notNearby`, which is
    /// exactly the state the send affordance renders its dead-drop path from. Without the
    /// `awayDeliveryEnabled` term, opting into away hearts while leaving Nearby Friends off left
    /// every friend row on a dead-end "Turn on Nearby Friends to send hearts" nag with no Send
    /// button at all (review finding, 2026-07-27).
    public nonisolated static func heartAffordance(
        heartsEnabled: Bool, presenceEnabled: Bool, reachable: Bool, awayDeliveryEnabled: Bool = false
    ) -> HeartAffordance {
        guard heartsEnabled else { return .heartsOff }
        guard presenceEnabled else { return awayDeliveryEnabled ? .notNearby : .needsPresence }
        return reachable ? .reachable : .notNearby
    }

    /// The advertised local display name (shared coercion; see `PeerDisplayNames.swift`).
    private var displayName: String { store.resolvedProximityDisplayName }

    /// Deliver a heart to a nearby friend over an on-demand pairwise connection. Multi-second
    /// pipeline; drives `heartSendState`. The FriendListView button is enabled only while the
    /// friend is reachable and the 5-minute cooldown is clear — the guards here are the belt.
    public func sendHeart(to friend: ProximityTrustedPeerRecord) {
        let firstName = Self.firstName(of: friend.displayName)

        // Send-side opt-out gate (one of the three homes of allowNearbyHearts).
        guard store.allowNearbyHearts else {
            failHeart("Turn on nearby hearts to send \(firstName) some warmth.")
            return
        }
        // Active record only: never send to a blocked or revoked (unfriended) peer.
        guard friend.blockedAt == nil, friend.revokedAt == nil else { return }
        guard ledger.canSendHeart(to: friend.fingerprint) else {
            failHeart("You just sent \(firstName) some warmth — hearts settle for a few minutes.")
            return
        }
        guard isRunning else {
            // Race window: the row rendered reachable but the radio has since stopped. With away
            // delivery on, hand the heart to the dead-drop (which consumed the cooldown) instead
            // of failing — the button's own away path normally catches this before we do.
            if queueAwayHeart?(friend) == true {
                heartSendState = .sent(recipientName: friend.displayName)
                scheduleHeartStatusClear()
                return
            }
            failHeart(notNearbyHeartMessage(firstName: firstName))
            return
        }
        // Reuse an already-verified live connection to this friend if one exists.
        if let connection = verifiedHeartConnection(fingerprint: friend.fingerprint) {
            heartSendState = .verifying(recipientName: friend.displayName)
            Task { [weak self] in await self?.deliverHeart(via: connection, to: friend) }
            return
        }
        guard let peer = discoveredPeer(matchingFriendFingerprint: friend.fingerprint) else {
            if queueAwayHeart?(friend) == true {
                heartSendState = .sent(recipientName: friend.displayName)
                scheduleHeartStatusClear()
                return
            }
            failHeart(notNearbyHeartMessage(firstName: firstName))
            return
        }
        guard !heartConnections.contains(where: { $0.id == peer.id }),
              heartConnections.count < Self.maxHeartConnections else {
            failHeart("Already sending \(firstName) some warmth — one moment.")
            return
        }
        heartSendState = .connecting(recipientName: friend.displayName)
        recordDiagnostic("Connecting to send a heart.")
        pendingHeartSends[peer.id] = (friend, 0)
        session?.invite(peer)
        armHeartConnectTimeout(peerID: peer.id, peer: peer, friend: friend)
    }

    private func verifiedHeartConnection(fingerprint: String) -> PresenceHeartConnection? {
        heartConnections.first { conn in
            guard let verified = conn.fingerprint else { return false }
            return IdentityService.fingerprintsMatch(verified, fingerprint)
        }
    }

    private func discoveredPeer(matchingFriendFingerprint fingerprint: String) -> PeerHandle? {
        for (peerID, matched) in matchedFingerprintsByPeer
        where matched.contains(where: { IdentityService.fingerprintsMatch($0, fingerprint) }) {
            if let peer = discoveredPeers[peerID] { return peer }
        }
        return nil
    }

    /// The intended friend's vault KA public key for a heart connection (the SEALED-INTRODUCTION
    /// recipient). Outbound: the pending-send friend record. Inbound: the ACTIVE, non-blocked,
    /// non-revoked vault record whose fingerprint this peer's tag matched. `nil` when no such record
    /// with real key material exists — the caller then refuses the connection (never sends unsealed).
    private func expectedFriendKeyAgreementKey(forPeer peerID: UUID, intended: ProximityTrustedPeerRecord?) -> Data? {
        if let intended, !intended.keyAgreementPublicKey.isEmpty { return intended.keyAgreementPublicKey }
        guard let matched = matchedFingerprintsByPeer[peerID] else { return nil }
        let record = store.proximityTrustVault.trustedPeers.first { peer in
            peer.blockedAt == nil && peer.revokedAt == nil && !peer.keyAgreementPublicKey.isEmpty
                && matched.contains { IdentityService.fingerprintsMatch(peer.fingerprint, $0) }
        }
        return record?.keyAgreementPublicKey
    }

    // MARK: - Hearts: inbound invitation gate

    /// Accept an inbound presence invitation ONLY from a peer whose discovered tag matched a
    /// friend, hearts are enabled, and we're under the connection cap. A pre-discovery-race
    /// inviter (not yet in the match map) is REJECTED — the sender retries.
    func shouldAcceptHeartInvitation(_ peer: PeerHandle) -> Bool {
        // A peer we already hold a connection with re-inviting (retry of a dropped attempt) is
        // always let through.
        if heartConnections.contains(where: { $0.peer.isSameEndpoint(as: peer) }) {
            return true
        }
        guard store.allowNearbyHearts else { return false }
        guard heartConnections.count < Self.maxHeartConnections else { return false }
        guard let matched = matchedFingerprintsByPeer[peer.id], !matched.isEmpty else { return false }
        return true
    }

    // MARK: - Hearts: connection lifecycle

    private func handleHeartChannelReady(_ channel: PeerChannelTransport) {
        guard !heartConnections.contains(where: { $0.id == channel.peer.id }) else { return }
        guard heartConnections.count < Self.maxHeartConnections else {
            session?.disconnectPeer(channel.peer)
            return
        }
        // The MC channel is up — cancel the pre-connect retry timer (the coordinator's own 25 s
        // handshake budget governs from here).
        cancelHeartConnectTimeout(peerID: channel.peer.id)
        let intended = pendingHeartSends[channel.peer.id]?.friend

        // SEALED-INTRODUCTION rule (Phase 4b): the heart handshake must never emit our identity in
        // the clear. Both sides seal the intro/ack to the intended friend's vault KA key. Presence
        // recognition is mutual-by-construction, so an accepted peer always maps to a friend whose
        // KA key we hold. If no active vault record with a non-empty KA key is available for this
        // peer (can't happen for a real mutual friend; a replay-forger that matched by tag simply
        // gets refused BEFORE any intro), refuse the connection rather than fall back to unsealed.
        guard let expectedFriendKA = expectedFriendKeyAgreementKey(forPeer: channel.peer.id, intended: intended),
              !expectedFriendKA.isEmpty else {
            recordDiagnostic("Refused a heart connection with no friend key.")
            session?.disconnectPeer(channel.peer)
            pendingHeartSends.removeValue(forKey: channel.peer.id)
            if intended != nil, isHeartSendInProgress {
                failHeart("Couldn't verify this friend — no heart was sent.")
            }
            return
        }

        let trustPolicy = FriendSessionTrustPolicy(vault: store.proximityTrustVault)
        let coordinator = ProximityCoordinator(
            identity: identity,
            transport: channel,
            ranging: NIRangingSession(),
            payloadHandler: self,
            trustPolicy: trustPolicy,
            replayCache: replayCache,
            displayName: displayName,
            capabilities: [ProximityCapability.hearts.rawValue, ProximityCapability.wire2.rawValue],
            sealedIntroductionPeerKeyAgreementKey: expectedFriendKA,
            timeoutSeconds: 25
        )
        // Away-hearts prekey gossip (Increment 3): the sealed presence intro carries our bundle;
        // the friend's verified intro hands theirs over.
        coordinator.heartDropPrekeyBundleProvider = { [weak self] in self?.heartDropBundleProvider?() }
        coordinator.onHeartDropPrekeyBundle = { [weak self] key, bundle in self?.onPeerPrekeyBundle?(key, bundle) }
        heartConnections.append(PresenceHeartConnection(
            id: channel.peer.id,
            peer: channel.peer,
            channel: channel,
            coordinator: coordinator,
            trustPolicy: trustPolicy,
            intendedFriend: intended,
            fingerprint: nil
        ))
        heartConnectionObservationRevision += 1

        Task { [weak self] in
            await coordinator.begin(role: .browser, mode: .friend)
            channel.notifyConnected()
            self?.checkHeartCoordinatorStates()
        }
    }

    private func startHeartObserving() {
        heartObservationTask?.cancel()
        heartObservationTask = ObservationLoop.start(
            on: self,
            tracking: { owner in
                _ = owner.heartConnectionObservationRevision
                _ = owner.heartConnections.count
                for connection in owner.heartConnections {
                    _ = connection.coordinator.state
                }
            },
            onChange: { owner in
                owner.checkHeartCoordinatorStates()
            }
        )
    }

    private func checkHeartCoordinatorStates() {
        var teardownIDs: [UUID] = []

        for index in heartConnections.indices {
            switch heartConnections[index].coordinator.state {
            case .awaitingManualCommit, .awaitingProximityCommit:
                // Programmatic auto-commit — a heart handshake has no user-facing dwell ritual.
                let coordinator = heartConnections[index].coordinator
                Task { await coordinator.commitManualProximity() }
            default:
                break
            }

            guard case .connected(let peerIdentity) = heartConnections[index].coordinator.state,
                  heartConnections[index].fingerprint == nil else { continue }

            heartConnections[index].fingerprint = peerIdentity.fingerprint
            let eligible = Self.isHeartEligibleFriend(peerIdentity, in: store)

            if let intended = heartConnections[index].intendedFriend {
                // Outbound: the connected identity MUST be the intended friend (verified
                // fingerprint) AND a heart-eligible active-friend vault record.
                if eligible, IdentityService.fingerprintsMatch(peerIdentity.fingerprint, intended.fingerprint) {
                    let connection = heartConnections[index]
                    heartSendState = .verifying(recipientName: intended.displayName)
                    Task { [weak self] in await self?.deliverHeart(via: connection, to: intended) }
                } else {
                    failHeart("Couldn't verify \(Self.firstName(of: intended.displayName)) — no heart was sent.")
                    teardownIDs.append(heartConnections[index].id)
                }
            } else if !eligible {
                // Inbound-only stranger (or blocked/revoked prior friend): tear down at once so no
                // slot is held. An eligible friend stays connected long enough to deliver a heart.
                recordDiagnostic("Disconnected a verified non-friend heart peer.")
                teardownIDs.append(heartConnections[index].id)
            }
        }

        for id in teardownIDs { teardownHeartConnection(id: id) }

        let stale = heartConnections.filter { connection in
            switch connection.coordinator.state {
            case .ended, .failed: return true
            default: return false
            }
        }
        for connection in stale {
            if connection.intendedFriend != nil, isHeartSendInProgress {
                failHeart("No heart was sent — the connection dropped.")
            }
            // Every record drop runs the coordinator's own teardown. Idempotent for `.ended`
            // (its `end()` already stopped everything); for `.failed` it is what guarantees the
            // ranging + Live Activity anchor stop even if `fail()`'s own teardown task has not run.
            let coordinator = connection.coordinator
            Task { await coordinator.cancel() }
            // A failed handshake never fires an MC disconnect — best-effort kick the zombie.
            session?.disconnectPeer(connection.peer)
            heartConnections.removeAll { $0.id == connection.id }
            pendingHeartSends.removeValue(forKey: connection.id)
            // A failed heart handshake doesn't mean the peer left presence — keep it if still
            // advertising; prune only if it has already departed (Group 4).
            pruneDiscoveredPeerIfDeparted(connection.id)
        }
        if !stale.isEmpty || !teardownIDs.isEmpty {
            heartConnectionObservationRevision += 1
        }
    }

    private func deliverHeart(via connection: PresenceHeartConnection, to friend: ProximityTrustedPeerRecord) async {
        defer { teardownHeartConnection(id: connection.id) }
        // Re-check the cooldown right before the wire write (a racing send may have consumed it).
        guard ledger.canSendHeart(to: friend.fingerprint) else {
            failHeart("You just sent \(Self.firstName(of: friend.displayName)) some warmth — hearts settle for a few minutes.")
            return
        }
        do {
            let payload = HeartPayload(sentAtDayKey: FernletDate.dayKey(for: Date()))
            let payloadData = try JSONEncoder().encode(payload)
            // Sealed to the coordinator's verified peer — the same identity the fingerprint match
            // pinned to `friend`, so a heart can never land on a different device.
            try await connection.coordinator.sendPayload(
                type: .friendHeart,
                // DO NOT LOCALIZE "Good vibes". It reads like the friendliest possible display
                // string, and it is — on the RECIPIENT's Connection Inspector, not the sender's.
                // It is also folded into the Ed25519 canonical bytes. The user-facing copy for this
                // feature is the `heartSendState` text a few lines below, which IS display and may
                // localize freely. See `FernletIdentityEnvelope.payloadSummary`.
                summary: PayloadSummary(title: "Good vibes"),
                payload: payloadData,
                sealed: true
            )
            ledger.recordHeartSent(to: friend.fingerprint)
            onHeartSent?(friend.fingerprint)
            heartSendState = .sent(recipientName: friend.displayName)
            recordDiagnostic("Sent good vibes to a friend.")
        } catch {
            heartSendState = .failed(message: "Could not send that heart just now.")
            recordDiagnostic("Heart send failed.")
        }
        scheduleHeartStatusClear()
    }

    /// Cancel the coordinator (which disconnects the transport), best-effort MC kick, and drop the
    /// record — so a completed/failed heart never leaves a zombie connection toward the 8-peer cap.
    private func teardownHeartConnection(id: UUID) {
        guard let connection = heartConnections.first(where: { $0.id == id }) else { return }
        pendingHeartSends.removeValue(forKey: id)
        cancelHeartConnectTimeout(peerID: id)
        let coordinator = connection.coordinator
        Task { await coordinator.cancel() }
        session?.disconnectPeer(connection.peer)
        heartConnections.removeAll { $0.id == id }
        // Only the heart CONNECTION ended — a still-advertising peer stays reachable and sendable
        // (an immediate re-send after the cooldown must not see isReachable==true yet fail
        // "not nearby"). Prune only if it has already departed presence.
        pruneDiscoveredPeerIfDeparted(id)
        heartConnectionObservationRevision += 1
    }

    private func teardownAllHeartConnections() {
        for connection in heartConnections {
            let coordinator = connection.coordinator
            Task { await coordinator.cancel() }
        }
        heartConnections.removeAll()
        pendingHeartSends.removeAll()
        for task in heartConnectTimeoutTasks.values { task.cancel() }
        heartConnectTimeoutTasks.removeAll()
    }

    private func removeHeartConnection(matching peer: PeerHandle) {
        let dropped = heartConnections.filter { conn in
            conn.peer.isSameEndpoint(as: peer)
        }
        guard !dropped.isEmpty else { return }
        let droppedIDs = Set(dropped.map(\.id))
        heartConnections.removeAll { droppedIDs.contains($0.id) }
        // The MC channel is already gone, but the coordinator's OWN teardown has not run: its
        // `.disconnected` hop is a weak-self Task that finds nothing once the record (the only
        // strong owner) is dropped. `cancel()` → `end()` still stops ranging and the foreground
        // anchor (the Live Activity) — without it every heart ended by a transport drop leaves an
        // orphaned Live Activity until the system's time cap. Mirrors `teardownHeartConnection`.
        for connection in dropped {
            let coordinator = connection.coordinator
            Task { await coordinator.cancel() }
        }
        let droppedOutbound = dropped.contains { $0.intendedFriend != nil }
        pendingHeartSends.removeValue(forKey: peer.id)
        // The heart channel's MC disconnect does not mean the peer left presence — it may still be
        // advertising. Keep it in discoveredPeers so reachable and sendable agree; prune only if it
        // has already departed presence (Group 4).
        pruneDiscoveredPeerIfDeparted(peer.id)
        heartConnectionObservationRevision += 1
        if droppedOutbound, isHeartSendInProgress {
            failHeart("The connection dropped — no heart was sent.")
        }
    }

    // MARK: - Hearts: pre-connect timeout + retry (pre-discovery race)

    private func armHeartConnectTimeout(peerID: UUID, peer: PeerHandle, friend: ProximityTrustedPeerRecord) {
        cancelHeartConnectTimeout(peerID: peerID)
        let timeout = heartConnectTimeoutSeconds
        heartConnectTimeoutTasks[peerID] = Task { @MainActor [weak self] in
            // A cancelled timeout means the channel came up — it must not fire the retry (R7).
            do {
                try await Task.sleep(for: .seconds(timeout))
            } catch {
                return
            }
            guard !Task.isCancelled, let self else { return }
            self.heartConnectTimeoutTasks.removeValue(forKey: peerID)
            self.handleHeartConnectTimeout(peerID: peerID, peer: peer, friend: friend)
        }
    }

    private func handleHeartConnectTimeout(peerID: UUID, peer: PeerHandle, friend: ProximityTrustedPeerRecord) {
        // A channel already came up — the handshake budget governs; nothing to do.
        guard !heartConnections.contains(where: { $0.id == peerID }) else { return }
        guard let pending = pendingHeartSends[peerID], pending.friend.fingerprint == friend.fingerprint else { return }
        let nextAttempt = pending.attempt + 1
        guard nextAttempt < Self.maxHeartInviteAttempts else {
            pendingHeartSends.removeValue(forKey: peerID)
            session?.disconnectPeer(peer)
            failHeart("\(Self.firstName(of: friend.displayName)) didn't answer — try again in a moment.")
            return
        }
        // Pre-discovery race: clear the stale invite, then re-invite after a short delay (mirrors
        // the mesh re-invite pattern the recipe cap uses).
        pendingHeartSends[peerID] = (friend, nextAttempt)
        session?.disconnectPeer(peer)
        recordDiagnostic("Retrying heart invite.")
        Task { @MainActor [weak self] in
            // Cancelled re-invite delay: the send was abandoned, so do not invite (R7).
            do {
                try await Task.sleep(for: .seconds(Self.heartReinviteDelaySeconds))
            } catch {
                return
            }
            guard !Task.isCancelled, let self else { return }
            guard self.pendingHeartSends[peerID]?.friend.fingerprint == friend.fingerprint,
                  !self.heartConnections.contains(where: { $0.id == peerID }) else { return }
            self.session?.invite(peer)
            self.armHeartConnectTimeout(peerID: peerID, peer: peer, friend: friend)
        }
    }

    private func cancelHeartConnectTimeout(peerID: UUID) {
        heartConnectTimeoutTasks[peerID]?.cancel()
        heartConnectTimeoutTasks.removeValue(forKey: peerID)
    }

    // MARK: - Hearts: receive

    public func proximityCoordinator(
        _ coordinator: ProximityCoordinator,
        didReceive envelope: FernletIdentityEnvelope,
        plaintext: Data,
        from peer: ProximityCoordinator.PeerIdentity?
    ) {
        guard envelope.payloadType == .friendHeart,
              let payload = try? JSONDecoder().decode(HeartPayload.self, from: plaintext),
              payload.format == "fernlet.proximity.heart",
              payload.version == 1,
              HeartPayload.isValidDayKey(payload.sentAtDayKey) else { return }

        // Receive-side opt-out (one of the three homes of allowNearbyHearts): a heart to a
        // hearts-off device is silently dropped even though presence kept us visible.
        guard store.allowNearbyHearts else {
            recordDiagnostic("Dropped a heart — nearby hearts are off.")
            return
        }
        // Hearts are friends-only: require a verified sender who is a still-trusted, unblocked,
        // non-revoked friend. The coordinator already rejects blocked/revoked senders at
        // introduction time; these checks close the gap for a record changed mid-session.
        guard let peer else {
            recordDiagnostic("Dropped a heart from an unverified sender.")
            return
        }
        guard Self.isHeartEligibleFriend(peer, in: store) else {
            recordDiagnostic("Dropped a heart from a non-friend.")
            return
        }
        // Wire boundary: the display name is peer-supplied — sanitize (control/zero-width/bidi
        // scalars out, length-capped) before it is persisted.
        let senderName = ItemNameModeration.moderatedPeerDisplayName(peer.displayName)
        // The ledger drops duplicates (same id) and enforces the 5-minute per-sender receive rate.
        if ledger.recordReceivedHeart(id: payload.id, senderDisplayName: senderName, senderFingerprint: peer.fingerprint) {
            onHeartReceived?(peer.fingerprint)
            recordDiagnostic("Received good vibes from a friend.")
        }
    }

    /// A verified peer is heart-eligible only when the vault knows their signing key as an ACTIVE
    /// (still-trusted → not revoked), unblocked friend. `isTrustedProximityPeer` already excludes
    /// revoked records, so a revoked-only "Removed" peer (unfriended, Phase-2 lifecycle) fails here.
    static func isHeartEligibleFriend(_ peerIdentity: ProximityCoordinator.PeerIdentity, in host: any ProximityHost) -> Bool {
        let vault = host.proximityTrustVault
        return vault.isTrustedProximityPeer(signingPublicKey: peerIdentity.signingPublicKey)
            && !vault.isBlockedProximitySigningKey(peerIdentity.signingPublicKey)
            && !host.isBlockedFingerprint(peerIdentity.fingerprint)
    }

    // MARK: - Hearts: status helpers

    private var isHeartSendInProgress: Bool {
        switch heartSendState {
        case .connecting, .verifying: return true
        default: return false
        }
    }

    private func failHeart(_ message: String) {
        heartSendState = .failed(message: message)
        scheduleHeartStatusClear()
    }

    /// Copy for "they aren't nearby and the drop-off couldn't take it either". The `heartsAwayDelivery`
    /// consent is the ONE thing this manager reads that setting for (`ProximityHost
    /// .heartsAwayDeliveryEnabled`): with it off, "hearts travel in person" is the honest and
    /// complete explanation; with it on, the away path was tried (`queueAwayHeart` returned false)
    /// and failed, so saying hearts only travel in person would contradict the feature the user
    /// just turned on.
    private func notNearbyHeartMessage(firstName: String) -> String {
        store.heartsAwayDeliveryEnabled
            ? "\(firstName) isn't nearby, and the heart couldn't be tucked away just now — try again in a moment."
            : "\(firstName) isn't nearby right now — hearts travel in person for now."
    }

    private func scheduleHeartStatusClear() {
        clearHeartStatusTask?.cancel()
        clearHeartStatusTask = Task { @MainActor [weak self] in
            // Cancelled: a newer status replaced this one, so leave `heartSendState` alone (R7).
            do {
                try await Task.sleep(for: .seconds(3))
            } catch {
                return
            }
            self?.heartSendState = .idle
        }
    }

    // MARK: - Diagnostics

    /// Diagnostics NEVER carry identities (no fingerprints, no names) — the nearby set is
    /// memory-only and must not leak into any log surface.
    private func recordDiagnostic(_ message: String) {
        diagnosticEvents = ProximityRecipeShareDiagnostics.appending(
            ProximityRecipeShareDiagnosticEvent(message: message),
            to: diagnosticEvents
        )
    }

    // MARK: - Test seams (no real radios: unit tests must never start Bonjour)

    /// Puts the manager in the running state WITHOUT starting radios (`session` stays nil; every
    /// session touch is optional-chained), deriving tags from the live vault.
    func activateForTesting() {
        guard !isRunning else { return }
        isRunning = true
        currentEpoch = IdentityService.presenceEpoch(at: nowProvider())
        rebuildTags(epoch: currentEpoch)
    }

    func handleDiscoveredPeerForTesting(_ peer: PeerHandle) {
        handleDiscoveredPeer(peer)
    }

    /// Marks the peer lost WITHOUT scheduling the real-time sweep task — tests drive expiry
    /// through `sweepExpiredPeersForTesting()` against the injected clock.
    func markPeerLostForTesting(_ peer: PeerHandle) {
        guard matchedFingerprintsByPeer[peer.id] != nil else { return }
        peerLostAt[peer.id] = nowProvider()
    }

    func sweepExpiredPeersForTesting() {
        sweepExpiredPeers()
    }

    func discoveryInfoForTesting() -> [String: String] {
        discoveryInfo()
    }

    func registerOwnEphemeralPeerNameForTesting(_ name: String) {
        rememberOwnEphemeralPeerName(name)
    }

    /// `discoveredPeers.count` — so a test can prove the peer-object map shrinks with the match map
    /// (a re-evaluation that drops a match must release the peer, not orphan it until `stop()`).
    var discoveredPeerCountForTesting: Int { discoveredPeers.count }

    /// Drives the production MC-disconnect removal path (`removeHeartConnection(matching:)`)
    /// exactly as the transport's `onPeerDisconnected` would — the writer needs a live radio a
    /// unit test must never start.
    func simulateHeartPeerDisconnectForTesting(_ peer: PeerHandle) {
        removeHeartConnection(matching: peer)
    }

    // MARK: - Heart test seams (no real radios)

    /// Pure friend gate keyed by a host — the exact accept/reject decision, unit-testable without
    /// driving a live handshake to `.connected`.
    static func isHeartEligibleFriendForTesting(_ peerIdentity: ProximityCoordinator.PeerIdentity, in host: any ProximityHost) -> Bool {
        isHeartEligibleFriend(peerIdentity, in: host)
    }

    /// Drives the production inbound-invitation gate exactly as the transport would.
    func shouldAcceptHeartInvitationForTesting(_ peer: PeerHandle) -> Bool {
        shouldAcceptHeartInvitation(peer)
    }

    var heartConnectionCountForTesting: Int { heartConnections.count }

    /// Group-4 seam: whether a send to `fingerprint` would find a peer to invite (the sendable
    /// set). It MUST agree with `isReachable(fingerprint:)` — a peer that is reachable but not
    /// sendable is the exact teardown bug this guards.
    func hasSendablePeerForTesting(fingerprint: String) -> Bool {
        discoveredPeer(matchingFriendFingerprint: fingerprint) != nil
    }

    /// Delete-all seam (Docs/PrivacyWipeCoverage.md): clears THIS instance's in-memory identity
    /// key cache. The keychain rows are shared with the mesh/recipe-share instances, so the
    /// underlying `deleteAll` is idempotent across the three calls — what matters here is that
    /// no live instance keeps the wiped identity usable in RAM until relaunch.
    public func wipeIdentityForDeleteAll() throws {
        try identity.wipe()
    }

    /// Away-hearts seams (bitchat adoptions Increment 3), wired by FernletStore: prekey-bundle
    /// gossip mirrors MeshNetworkManager's, and `queueAwayHeart` is the race-window fallback —
    /// a live send that discovers the friend just left can hand the heart to the dead-drop
    /// instead of failing (returns true when queued; the ledger cooldown was consumed there).
    public var heartDropBundleProvider: (() -> HeartPrekeyStore.Bundle?)?
    public var onPeerPrekeyBundle: ((Data, HeartPrekeyStore.Bundle) -> Void)?
    public var queueAwayHeart: ((ProximityTrustedPeerRecord) -> Bool)?

    /// Group-4 seam: registers a heart connection for an already-discovered peer (with an injected
    /// ranging provider so no real radio starts), then tears it down — exercising the exact
    /// teardown path a completed/failed send runs. Afterward the peer, if still advertising, must
    /// remain both reachable and sendable.
    func simulateHeartConnectionTeardownForTesting(peer: PeerHandle, ranging: any RangingProvider) {
        let channelSession = session ?? MeshMultipeerSession(usesEphemeralPeerID: true)
        let channel = PeerChannelTransport(peer: peer, session: channelSession)
        let coordinator = ProximityCoordinator(
            identity: identity,
            transport: channel,
            ranging: ranging,
            replayCache: replayCache,
            timeoutSeconds: 0)
        heartConnections.append(PresenceHeartConnection(
            id: peer.id,
            peer: peer,
            channel: channel,
            coordinator: coordinator,
            trustPolicy: FriendSessionTrustPolicy(vault: store.proximityTrustVault),
            intendedFriend: nil,
            fingerprint: nil))
        teardownHeartConnection(id: peer.id)
    }

    /// Registers a live coordinator (already driven to `.connected` by the caller) as an inbound
    /// heart connection and runs the real trust gate (`checkHeartCoordinatorStates`). Returns
    /// `true` iff the peer was accepted as an eligible friend (a stranger is torn down → the
    /// connection is dropped → `false`). Mirrors the deleted heart manager's
    /// `evaluateConnectedCoordinatorForTesting`. The production path is driven by a live
    /// `MeshMultipeerSession` a unit test cannot fake.
    ///
    /// Deliberately NOT `@discardableResult` (R7): the `Bool` is the accept/reject signal, so a
    /// caller that ignores it is ignoring the trust decision.
    func evaluateConnectedCoordinatorForTesting(
        _ coordinator: ProximityCoordinator,
        peer: PeerHandle,
        trustPolicy: FriendSessionTrustPolicy,
        intendedFriend: ProximityTrustedPeerRecord? = nil
    ) -> Bool {
        let channelSession = session ?? MeshMultipeerSession(usesEphemeralPeerID: true)
        heartConnections.append(PresenceHeartConnection(
            id: peer.id,
            peer: peer,
            channel: PeerChannelTransport(peer: peer, session: channelSession),
            coordinator: coordinator,
            trustPolicy: trustPolicy,
            intendedFriend: intendedFriend,
            fingerprint: nil
        ))
        heartConnectionObservationRevision += 1
        checkHeartCoordinatorStates()
        return heartConnections.contains { $0.id == peer.id && $0.fingerprint != nil }
    }
}
