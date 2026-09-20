// PresenceManager.swift
// ProximityKit/Presence
//
// The standing presence radio (mesh redesign Phase 4a/4b, Docs/Proximity-Mesh-Redesign-2026-07-10.md):
// a continuous advertise+browse on `_fernlet-near2._udp` that lets KEPT friends recognize each other
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
//            disconnectPeer so zombies never accumulate toward the transport's tunnel cap).
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
//  - The radio's advertised identity is a `PresenceEpochPosture` (P9 item 2, plan §17.1): for any
//    instant it answers the epoch, the service instance name to advertise and the TLS identity to
//    present, and all three are replaced WHOLE at every 900 s boundary. `presencePosture` below is
//    the one source of all three, and `NetworkPresenceSession` advertises exactly what it says —
//    so two sightings 901 seconds apart share no byte, and nothing about the device is derivable
//    across a boundary. Nothing is persisted: a stood-down radio keeps no name and no certificate
//    to come back up under.
//  - What a boundary does NOT break, stated plainly: a link-local observer sees one IP address
//    throughout, and a live heart tunnel opened before the boundary stays open across it. Neither
//    is a regression and neither is reachable by rotating a name — the tunnel's far end is a
//    verified friend who already knows us, and same-link IP correlation is below this layer. What
//    the rotation removes is exactly what it claims: correlation by Bonjour name or certificate,
//    which is what survives a change of network and a change of day.
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
    let channel: NetworkPeerChannel
    let coordinator: ProximityCoordinator
    let trustPolicy: FriendSessionTrustPolicy
    /// The friend this connection is delivering a heart to (outbound). `nil` = an inbound-only
    /// connection we accepted so a friend could send US a heart.
    var intendedFriend: ProximityTrustedPeerRecord?
    var fingerprint: String?
    /// Set once the outbound heart has been written, so teardown/observation never re-sends.
    var didSend = false
}

/// The standing presence radio (`_fernlet-near2._udp`): lets KEPT friends recognize each other nearby
/// without connecting, and delivers in-person hearts over on-demand pairwise connections formed
/// on that recognition.
///
/// Privacy posture is the design center: the advertisement carries ONLY rotating pairwise-DH
/// tags (truncated HMACs of the 15-minute epoch under per-friend-pair static-static X25519
/// secrets — see `IdentityService.presenceTag`), the epoch's advertised instance name and TLS
/// identity are a fresh ``PresenceEpochPosture`` that survives no boundary and is what
/// ``NetworkPresenceSession`` actually advertises, and all state (nearby set, connections,
/// diagnostics) is memory-only with no identities in any log line. Matching spans ±1 epoch; three self-exclusion
/// layers drop our own ghost advertisements; a 45 s lost-grace debounce smooths the epoch
/// advertiser restart.
///
/// Hearts (Phase 4b): sends invite the tag-matched peer, run a 1-RTT friend handshake with the
/// SEALED-INTRODUCTION rule (intro/ack sealed to the intended friend's vault KA key so a
/// tag-replay forger learns nothing), auto-commit, verify the connected identity IS that friend
/// and heart-eligible, deliver one sealed `.friendHeart`, then tear down — zombie connections
/// must never accumulate toward the transport's tunnel cap. Receives admit an inbound dialer only
/// when the pairwise tag it claims resolves to an already-browsed, tag-matched peer and enforce the `allowNearbyHearts` opt-out, the trusted-friend gate, and
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

    /// Max own tags advertised (most-recently-seen friends first).
    ///
    /// 24 tags × 12 base64 characters plus separators is 311 bytes, which does **not** fit one
    /// DNS-SD TXT entry (RFC 6763 §6.1 caps one `key=value` string at 255 bytes). It does not have
    /// to: ``PresenceAdvertisement/publishedFields(tags:)`` chunks the list across `t` and `t1`,
    /// whose combined capacity is 36 tags, so this roster cap is the one that bites and the wire
    /// ceiling is never the thing that silently drops a friend. `PresenceAdvertisementTests`
    /// reddens if this is ever raised past that capacity.
    ///
    /// `nonisolated`: an immutable bound the pure TXT vocabulary and its tests read without a hop.
    nonisolated static let maxAdvertisedTags = 24
    /// A matched peer counts as GONE only after this much continuous absence — spans the
    /// epoch advertiser-restart flap (lost+found) without flickering the nearby set.
    static let lostGraceInterval: TimeInterval = 45

    /// Vault fingerprints of kept friends currently recognized nearby. Memory-only, observable.
    public private(set) var nearbyFriendFingerprints: Set<String> = []
    public private(set) var diagnosticEvents: [ProximityRecipeShareDiagnosticEvent] = []

    /// Max concurrent heart connections on the presence session — a small cap well under the
    /// transport's own tunnel cap (hearts are short-lived: dial → send → teardown in seconds).
    static let maxHeartConnections = 4
    /// Per-attempt pre-connect budget: if the dialed peer hasn't produced a channel in this
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
    @ObservationIgnored private var session: (any PresenceRadioSession)?
    /// Test seam: the radio this manager brings up. The production default is the one QUIC
    /// presence radio and nothing in shipping code writes this — the counterpart of
    /// `MeshTransportFactory` for a manager that only ever has one answer. A test substitutes an
    /// in-memory fake so the advertise, republish, dial and stand-down decisions are reachable
    /// without starting Bonjour.
    @ObservationIgnored var makeSession: () -> any PresenceRadioSession = { NetworkPresenceSession() }
    @ObservationIgnored private(set) var isRunning = false

    /// Live heart connections (outbound sends in flight + inbound accepts). Keyed by peer UUID.
    @ObservationIgnored private var heartConnections: [PresenceHeartConnection] = []
    /// Peers currently discovered nearby (the PeerHandle objects), so a send can invite the
    /// exact peer whose tag matched the intended friend.
    @ObservationIgnored private var discoveredPeers: [UUID: PeerHandle] = [:]
    /// Outbound sends awaiting their channel: peer UUID → (the dialed handle, friend, attempt
    /// count).
    ///
    /// The handle rides in the VALUE because the key cannot answer the only question this map is
    /// ever asked — "is the device now connecting the one my send is for?". A key is a
    /// ``PeerHandle/id``, and a device that re-appears after a bounded identity-map eviction or a
    /// transport `stop()`/restart arrives under a fresh one; every read goes through
    /// ``pendingHeartSend(for:)``, which matches the stored handle by endpoint.
    @ObservationIgnored private var pendingHeartSends:
        [UUID: (peer: PeerHandle, friend: ProximityTrustedPeerRecord, attempt: Int)] = [:]
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
    /// The ephemeral posture for ``currentEpoch`` — the ONE source of this radio's epoch index,
    /// advertised instance name and TLS identity (plan §17.1, P9 item 2). Minted when the radio
    /// comes up, re-minted whole at every 900 s boundary by ``rotateEpochIfNeeded()``, and dropped
    /// by `stop()`: no name and no identity survives a boundary, a stand-down or a launch, and
    /// none of it is ever written anywhere.
    ///
    /// It is read for ``currentEpoch``, and it is what the radio ADVERTISES: every
    /// ``NetworkPresenceSession`` listener is registered under
    /// ``PresenceEpochPosture/instanceName`` and presents ``PresenceEpochPosture/tlsIdentity``,
    /// re-registered whole at each boundary by ``republishAdvertisement()``. That is the rotation
    /// the retired MultipeerConnectivity advertiser could not do — it minted one random peer ID per
    /// `start()`, so a radio left up for hours advertised freshly rotating tags under one
    /// unchanging name, which is the linkability the tag rotation exists to remove.
    @ObservationIgnored private(set) var presencePosture: PresenceEpochPosture?
    /// The epoch a posture mint last FAILED in — the mint's retry budget, and nothing more.
    ///
    /// A mint is a synchronous P-256 keygen plus a certificate mint on the main actor, and
    /// ``refreshRoster()`` is called from six places in the app. Without a budget one failed mint
    /// turns every later refresh in that epoch into another keygen and another audit row; with it
    /// the radio tries once per epoch and then waits for the boundary, which is when the inputs
    /// could plausibly have changed anyway.
    ///
    /// Memory-only, and — unlike the posture — it SURVIVES `stop()`. A failed mint stands the
    /// radio down, the run policy re-applies on the next scene/tab/lock event, and `start()` runs
    /// again; a budget cleared by the teardown would therefore be no budget at all on the one path
    /// that exercises it most. It needs no clearing of its own: it is honoured only for the epoch
    /// it names, and a successful mint clears it.
    @ObservationIgnored private var postureMintFailedEpoch: UInt64?
    @ObservationIgnored private var epochRotationTask: Task<Void, Never>?
    /// The single in-flight lost-peer sweep (see ``scheduleLostSweep()``) — nil when none is armed.
    @ObservationIgnored private var lostSweepTask: Task<Void, Never>?

    /// Test seam: injectable clock (epoch derivation, lost-grace expiry). Production default.
    @ObservationIgnored var nowProvider: () -> Date = { Date() }

    /// Test seam: the posture mint, as `(posture held now, instant) -> the posture to wear`. The
    /// production default is ``PresenceEpochPosture``'s own production path — the system CSPRNG
    /// and the module's one certificate path — and nothing in shipping code writes this. A test
    /// substitutes a failing mint to exercise the once-per-epoch budget above.
    @ObservationIgnored var postureMint: (PresenceEpochPosture?, Date) throws -> PresenceEpochPosture = { held, now in
        try held?.rotated(at: now) ?? PresenceEpochPosture.minted(at: now)
    }

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

    /// Whether the presence radio is up right now — the radio's own account, on the same terms as
    /// `ProximityRecipeShareManager.isListening`, read by the run policy's seam.
    public var isListening: Bool { isRunning }

    public func start() {
        guard !isRunning else { return }
        currentEpoch = rotatePosture(at: nowProvider())
        // The posture IS the radio's identity now: no posture, no name and no certificate to
        // advertise under, so there is simply nothing to start, and the manager never transiently
        // reads as running.
        //
        // Deliberately NOT a stand-down: `stop()` would be tearing down a radio that was never
        // built, and — because the mint's once-per-epoch budget survives `stop()` — the run policy
        // re-applies on every scene, tab and lock event, so a deterministically failing mint would
        // otherwise re-run a P-256 keygen and write another audit row on each of them. The mint
        // itself has already booked the one audit row this epoch gets (``rotatePosture(at:)``);
        // `isListening` stays false, which is exactly what the run policy's seam reads.
        guard let posture = presencePosture else { return }
        isRunning = true
        rebuildTags(epoch: currentEpoch)

        let session = makeSession()
        session.onPeerDiscovered = { [weak self] peer in
            self?.handleDiscoveredPeer(peer)
        }
        session.onPeerLost = { [weak self] peer in
            self?.handleLostPeer(peer)
        }
        // Phase 4b — hearts: admit an inbound dialer ONLY when the pairwise tag it claims resolves
        // to a peer whose advertisement we have already matched to a friend. A pre-discovery-race
        // dialer is refused; the sender retries (see armHeartConnectTimeout).
        session.resolveDialer = { [weak self] tag in
            self?.resolveHeartDialer(tag: tag)
        }
        session.onPeerChannelReady = { [weak self] channel in
            self?.handleHeartChannelReady(channel)
        }
        session.onPeerDisconnected = { [weak self] peer, _ in
            self?.removeHeartConnection(matching: peer)
        }
        session.onTransportError = { [weak self] message in
            self?.handleTransportError(message)
        }
        self.session = session
        do {
            try session.start(posture: posture, discoveryInfo: discoveryInfo())
        } catch {
            handleTransportError("The presence radio could not start: \(error)")
            return
        }
        startEpochRotation()
        startHeartObserving()
        recordDiagnostic("Presence started.")
    }

    /// The transport reported a failure — today an advertiser or browser `didNotStart*`, which the
    /// Local Network permission prompt guarantees on a fresh install's very first start.
    ///
    /// Stands the radio down (P8 item 0, device finding (b)), mirroring
    /// `ProximityRecipeShareManager`'s handler: with `isRunning` left true the idempotent
    /// `start()` no-ops forever over a dead radio, and the app's run-policy seam — which
    /// re-applies a running verdict to a listener whose ``isListening`` says it is down — would
    /// have nothing to see. `didNotStart*` only fires from start attempts, but guard on no heart
    /// connection held anyway, so an unexpected error can never tear down a live pairing.
    private func handleTransportError(_ message: String) {
        recordDiagnostic(message)
        guard heartConnections.isEmpty, isRunning else { return }
        stop()
        recordDiagnostic("Presence radio failed to start — the run policy re-applies it at its next run.")
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
        // The posture is ephemeral in the strong sense: a stood-down radio keeps no name and no
        // TLS identity to come back up under, so a restart is never linkable to what preceded it.
        //
        // The mint's retry budget deliberately does NOT go with it. It is not state about the
        // radio, it is a per-epoch note that a keygen failed, and `start()` is called again on
        // every scene, tab and lock event: clearing it here turned "one attempt and one audit row
        // per epoch" into one of each per policy run for the rest of the epoch. It expires by
        // itself — ``rotatePosture(at:)`` only honours it for the epoch it names, and clears it
        // outright when a mint succeeds.
        presencePosture = nil
        nearbyFriendFingerprints = []
        heartSendState = .idle
    }

    /// The vault roster changed (friend kept / blocked / revoked / unblocked): re-derive tags
    /// and restart the advertiser with the fresh set. No-op while not running — `start()`
    /// derives from the live vault anyway.
    public func refreshRoster() {
        guard isRunning else { return }
        // Through the posture, not around it: a roster refresh that happens to land after a
        // boundary must rotate the name and the identity with the tags, never the tags alone.
        rebuildTags(epoch: rotatePosture(at: nowProvider()))
        republishAdvertisement()
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
    /// ``PresenceAdvertisement`` owns the encoding, including the chunking that keeps the tag list
    /// inside DNS-SD's 255-byte-per-entry ceiling.
    private func discoveryInfo() -> [String: String] {
        PresenceAdvertisement.publishedFields(tags: ownTagTokens.sorted())
    }

    /// Re-advertises the current tags under the current posture.
    ///
    /// The one door from this manager to the radio's advertisement, so a republish can never carry
    /// fresh tags under a stale name: the posture and the tags are read in the same breath, from
    /// the same rotation. A radio with no posture has nothing to advertise under and is left alone
    /// — the next boundary re-mints one.
    private func republishAdvertisement() {
        guard let posture = presencePosture else { return }
        session?.republish(posture: posture, discoveryInfo: discoveryInfo())
    }

    /// The pairwise tag we advertise for `friend` this epoch — the token a dial hello claims, and
    /// the same value the friend derives on their side to match it. Nil when it cannot be derived,
    /// which is the same condition that would have dropped the friend from the advertisement.
    private func ownTagToken(for friend: ProximityTrustedPeerRecord) -> String? {
        guard !friend.keyAgreementPublicKey.isEmpty else { return nil }
        do {
            return try identity.presenceTag(for: friend.keyAgreementPublicKey, epoch: currentEpoch)
                .base64EncodedString()
        } catch {
            return nil
        }
    }

    // MARK: - Discovery → nearby set

    private func handleDiscoveredPeer(_ peer: PeerHandle) {
        guard PresenceAdvertisement.isPresenceAdvertisement(peer.discoveryInfo) else { return }
        // Self-exclusion layer 1: our own ghost from a previous epoch or a previous start (a stale
        // Bonjour cache) advertises under one of the posture instance names we minted this launch.
        guard !ownEphemeralPeerNames.contains(peer.displayHint) else { return }

        let tokens = PresenceAdvertisement.tags(from: peer.discoveryInfo)
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
        // host-pin: timer — stored handle, synchronous main-actor body (`sweepExpiredPeers()`) (HP2)
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

    /// Records one of our own posture instance names, evicting the oldest past
    /// ``maxRememberedEphemeralNames`` so repeated starts and rotations cannot grow the set
    /// unboundedly (R3).
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
        // host-pin: timer — stored handle, synchronous main-actor body (`rotateEpochIfNeeded()`) (HP2)
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
    /// (the listener is re-registered under the new posture), and re-match cached peer
    /// advertisements — a peer whose (static) ad is now 2+ epochs stale falls out of the
    /// candidate window and drops.
    func rotateEpochIfNeeded() {
        let now = nowProvider()
        guard IdentityService.presenceEpoch(at: now) != currentEpoch else { return }
        rebuildTags(epoch: rotatePosture(at: now))
        republishAdvertisement()
        reevaluateDiscoveredPeers()
    }

    /// Rotates ``presencePosture`` to the epoch containing `now` and answers that epoch.
    ///
    /// Inside the held posture's epoch this is a no-op returning its epoch; across a boundary it
    /// mints an entirely fresh one — new instance name, new key pair, new certificate. It has no
    /// clock of its own: every caller hands it `nowProvider()`, and the epoch is always
    /// `IdentityService.presenceEpoch(at:)`, the same counter the tags are derived at. It arms
    /// nothing — the rotation tick above and the roster/start paths are the only callers, so
    /// presence still owns exactly one timer.
    ///
    /// Fail-soft, NAMED (R7) and BUDGETED: a mint that fails leaves NO posture rather than a stale
    /// one, and the epoch still comes from the same clock, so tag derivation and matching are
    /// untouched. The failure is remembered for that epoch (``postureMintFailedEpoch``) so the
    /// next refresh does not re-run a keygen and write another audit row — one attempt and one row
    /// per epoch, then the boundary retries. It is deliberately not a diagnostic event — the
    /// connection log is a user-facing surface and this is a developer fault, not a radio
    /// condition.
    private func rotatePosture(at now: Date) -> UInt64 {
        let epoch = IdentityService.presenceEpoch(at: now)
        if let posture = presencePosture, posture.epoch == epoch { return epoch }
        guard postureMintFailedEpoch != epoch else { return epoch }
        do {
            let rotated = try postureMint(presencePosture, now)
            presencePosture = rotated
            postureMintFailedEpoch = nil
            // Self-exclusion layer 1's feed. Under the retired radio this was a per-start random
            // peer-ID name; it is now every posture name this launch has worn, because a stale
            // Bonjour cache can still be carrying the PREVIOUS epoch's registration after a
            // boundary — a case a filter that only knows the current name cannot see.
            rememberOwnEphemeralPeerName(rotated.instanceName)
            return rotated.epoch
        } catch {
            presencePosture = nil
            postureMintFailedEpoch = epoch
            FernletAuditLog.log(
                "presence.posture.mintFailed",
                context: ["error": String(describing: error)]
            )
            return epoch
        }
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

    /// Spawns a detached task that PINS this manager's host for the task's own lifetime.
    ///
    /// ``store`` is `unowned` because the host owns this manager (`FernletStore.swift`'s `lazy var`
    /// managers), and the unowned back-reference is that ownership's cycle-breaker. A detached task,
    /// however, holds `self` STRONGLY for the duration of every `self?.method()` it awaits, so it can
    /// outlive the host and then read a destroyed object — `swift_abortRetainUnowned` aborts the whole
    /// process, which is what P5 item 1a's crash reports are. Capturing the host here, read
    /// synchronously on the main actor at a point where it is provably alive, makes the read the task
    /// will later perform valid by construction (invariant HP1).
    ///
    /// The pin is safe ONLY because this task's handle is not stored on the manager: nothing the host
    /// owns can reach this closure context, so no `store → manager → task → store` cycle forms. NEVER
    /// build the same pin into a task whose handle the manager keeps (invariant HP2) — see the `// host-pin: timer`
    /// markers on the sites in this file that must not use this helper.
    ///
    /// The closure is deliberately neither `@Sendable` nor `sending`, so it inherits this manager's
    /// isolation exactly as the `Task { … }` literal it replaces did — same executor, same enqueue,
    /// same ordering. It carries no `@_implicitSelfCapture` either, so a strong `self` capture has to
    /// be spelled `self.` at the call site.
    private func spawnHostPinned(_ operation: @escaping () async -> Void) {
        let host = store
        Task {   // host-pin: helper
            await operation()
            withExtendedLifetime(host) {}
        }
    }

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
            spawnHostPinned { [weak self] in await self?.deliverHeart(via: connection, to: friend) }
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
        // Recognize the device by endpoint, exactly as the two gates on the inbound side do: the
        // id-only test this replaced (plan §6.4) read a device whose handle had churned — a
        // bounded identity-map eviction, a transport `stop()`/restart — as a stranger, so it
        // re-invited a device we already hold a connection to and stranded `pendingHeartSends`
        // until the connect timeout failed the send.
        guard !hasHeartConnection(with: peer),
              heartConnections.count < Self.maxHeartConnections else {
            failHeart("Already sending \(firstName) some warmth — one moment.")
            return
        }
        // The dial hello claims the pairwise tag we advertise for this friend, which is how the
        // far side resolves an inbound QUIC connection back to the browsed peer it matched (see
        // ``PresenceDialHello``). A tag we cannot derive is a friend we are not advertising, so
        // there is no connection to open.
        guard let tag = ownTagToken(for: friend) else {
            failHeart(notNearbyHeartMessage(firstName: firstName))
            return
        }
        heartSendState = .connecting(recipientName: friend.displayName)
        recordDiagnostic("Connecting to send a heart.")
        // Exactly one pending send per DEVICE: a leftover entry filed under an earlier handle for
        // this same device would make `pendingHeartSend(for:)`'s `first` a coin flip.
        removePendingHeartSend(for: peer)
        pendingHeartSends[peer.id] = (peer, friend, 0)
        session?.dial(peer, helloTag: tag)
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
    /// Resolves an inbound dialer's claimed pairwise tag to the browsed peer it names, for the
    /// radio's ``NetworkPresenceSession/resolveDialer`` hook.
    ///
    /// The QUIC replacement for the MC advertiser's `shouldAcceptInvitation`, and deliberately the
    /// SAME decision with one step in front of it: the tag is looked up in our own
    /// ``candidateTokens`` — tokens we derived ourselves from pairwise secrets only the two members
    /// of a pair hold — and then the friend it names must already be discovered nearby. Both halves
    /// fail closed, and neither believes the dialer about anything except which of our own
    /// advertisements it is answering.
    ///
    /// Answering with the BROWSED peer's handle is what gives this radio the collapse MC had for
    /// free: the inbound tunnel lands under the same ``PeerEndpointKey`` an outbound dial to that
    /// device would, so ``hasHeartConnection(with:)`` and ``expectedFriendKeyAgreementKey(forPeer:intended:)``
    /// keep working unchanged.
    func resolveHeartDialer(tag: String) -> PeerHandle? {
        guard let fingerprint = candidateTokens[tag],
              let peer = discoveredPeer(matchingFriendFingerprint: fingerprint),
              shouldAcceptHeartInvitation(peer) else { return nil }
        return peer
    }

    func shouldAcceptHeartInvitation(_ peer: PeerHandle) -> Bool {
        // A peer we already hold a connection with re-inviting (retry of a dropped attempt) is
        // always let through.
        if hasHeartConnection(with: peer) {
            return true
        }
        guard store.allowNearbyHearts else { return false }
        guard heartConnections.count < Self.maxHeartConnections else { return false }
        guard let matched = matchedFingerprintsByPeer[peer.id], !matched.isEmpty else { return false }
        return true
    }

    // MARK: - Hearts: connection lifecycle

    /// True when `peer`'s DEVICE already holds a heart connection.
    ///
    /// The one spelling of "are we already connected to this device?", matched the way every stored
    /// record must be matched against a transport event — by ``PeerHandle/isSameEndpoint(as:)``,
    /// never `==` — so the inbound-invitation gate, the channel-ready gate, the outbound
    /// ``sendHeart(to:)`` gate and the pre-connect retry cannot drift apart again.
    /// `removeHeartConnection(matching:)` filters on the same test.
    private func hasHeartConnection(with peer: PeerHandle) -> Bool {
        heartConnections.contains { $0.peer.isSameEndpoint(as: peer) }
    }

    /// The outbound send in flight to `peer`'s DEVICE, if any.
    ///
    /// The companion to ``hasHeartConnection(with:)`` for ``pendingHeartSends``: every read of that
    /// map asks a device question, so every read matches the stored handle by endpoint rather than
    /// subscripting with an `id` the device may no longer be carrying. Subscripting was what let a
    /// churned handle strand a send — the channel came up, `pendingHeartSends[channel.peer.id]`
    /// missed, and the connection was seated with no `intendedFriend`, so the verified handshake
    /// never delivered the heart it was opened for.
    private func pendingHeartSend(
        for peer: PeerHandle
    ) -> (peer: PeerHandle, friend: ProximityTrustedPeerRecord, attempt: Int)? {
        pendingHeartSends.values.first { $0.peer.isSameEndpoint(as: peer) }
    }

    /// Drops the outbound send filed for `peer`'s DEVICE, whatever handle it was filed under.
    /// The removal half of ``pendingHeartSend(for:)`` — an id-keyed `removeValue` after a churn
    /// left the entry behind for the manager's lifetime.
    private func removePendingHeartSend(for peer: PeerHandle) {
        let staleKeys = pendingHeartSends.filter { $0.value.peer.isSameEndpoint(as: peer) }.map(\.key)
        for key in staleKeys { pendingHeartSends.removeValue(forKey: key) }
    }

    /// What ``handleHeartChannelReady`` does with a freshly connected heart channel.
    ///
    /// Extracted from the guard chain so the decision is reachable from a unit test: what follows
    /// it in production is a live `ProximityCoordinator` over a real `NIRangingSession`, which a
    /// unit test must not build, and the decision is the half that was wrong. Mirrors
    /// `MeshNetworkManager.ChannelAdmission`.
    enum HeartChannelAdmission: Equatable {
        /// Build the coordinator and hold the heart connection.
        case admit
        /// Refuse and free the tunnel. A connected peer with no heart-connection record holds a
        /// zombie link — one of the transport's tunnel slots — until presence stops.
        case turnAway
        /// This device already holds a heart connection. Leave it entirely alone: disconnecting
        /// here would drop the live handshake, and admitting would hold one device twice.
        case alreadyConnected
    }

    /// The admission decision for a freshly connected heart channel — see
    /// ``HeartChannelAdmission``.
    ///
    /// Recognizes the peer by endpoint, exactly as ``shouldAcceptHeartInvitation(_:)`` above does,
    /// and in the same order: a device we already hold is answered before the cap, because the cap
    /// is not what it is asking. The duplicate check used to compare `peer.id` alone (plan §6.4),
    /// so a connected device whose handle churned — a bounded identity-map eviction, a transport
    /// `stop()`/restart — was read as a stranger by the ready path the invitation gate had just
    /// waved through: below the cap it opened a SECOND coordinator, ranging session and Live
    /// Activity anchor for one peer; at the cap it disconnected the device, killing the live
    /// connection it already held.
    func heartChannelAdmission(for peer: PeerHandle) -> HeartChannelAdmission {
        guard !hasHeartConnection(with: peer) else { return .alreadyConnected }
        guard heartConnections.count < Self.maxHeartConnections else { return .turnAway }
        return .admit
    }

    private func handleHeartChannelReady(_ channel: NetworkPeerChannel) {
        switch heartChannelAdmission(for: channel.peer) {
        case .alreadyConnected:
            return
        case .turnAway:
            session?.disconnectPeer(channel.peer)
            return
        case .admit:
            break
        }
        // The channel is up — cancel the pre-connect retry timer (the coordinator's own 25 s
        // handshake budget governs from here).
        cancelHeartConnectTimeout(for: channel.peer)
        let intended = pendingHeartSend(for: channel.peer)?.friend

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
            removePendingHeartSend(for: channel.peer)
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

        spawnHostPinned { [weak self] in
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
                // host-pin: exempt — coordinator/channel only, no `self`, no host read
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
                    spawnHostPinned { [weak self] in await self?.deliverHeart(via: connection, to: intended) }
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
            // host-pin: exempt — coordinator/channel only, no `self`, no host read
            Task { await coordinator.cancel() }
            // A failed handshake never fires a transport disconnect — best-effort kick the zombie.
            session?.disconnectPeer(connection.peer)
            heartConnections.removeAll { $0.id == connection.id }
            removePendingHeartSend(for: connection.peer)
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

    /// Cancel the coordinator (which disconnects the transport), ask the presence radio to drop the
    /// tunnel as well, and drop the record — so a completed or failed heart never leaves a zombie
    /// connection counting toward the radio's tunnel cap (`NetworkPresenceSession.maxTunnels`).
    private func teardownHeartConnection(id: UUID) {
        guard let connection = heartConnections.first(where: { $0.id == id }) else { return }
        // Cancel BEFORE the removal: `cancelHeartConnectTimeout(for:)` finds the arming handle
        // through the pending send, so dropping that first would strand a churned-handle timer.
        cancelHeartConnectTimeout(for: connection.peer)
        removePendingHeartSend(for: connection.peer)
        let coordinator = connection.coordinator
        // host-pin: exempt — coordinator/channel only, no `self`, no host read
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
            // host-pin: exempt — coordinator/channel only, no `self`, no host read
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
        // The channel is already gone, but the coordinator's OWN teardown has not run: its
        // `.disconnected` hop is a weak-self Task that finds nothing once the record (the only
        // strong owner) is dropped. `cancel()` → `end()` still stops ranging and the foreground
        // anchor (the Live Activity) — without it every heart ended by a transport drop leaves an
        // orphaned Live Activity until the system's time cap. Mirrors `teardownHeartConnection`.
        for connection in dropped {
            let coordinator = connection.coordinator
            // host-pin: exempt — coordinator/channel only, no `self`, no host read
            Task { await coordinator.cancel() }
        }
        let droppedOutbound = dropped.contains { $0.intendedFriend != nil }
        removePendingHeartSend(for: peer)
        // The heart channel's disconnect does not mean the peer left presence — it may still be
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
        // host-pin: timer — stored handle; its host read is synchronous main-actor code, so HP0 covers it (HP2)
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

    /// Whether the pre-connect retry has been overtaken by events and must stand down: the DEVICE
    /// is already connected, or the send the retry belongs to is gone or superseded.
    ///
    /// The timeout body and its delayed re-invite ask exactly this, which is why it is one
    /// function: they used to ask it twice, and both spellings compared `heartConnections`
    /// `id`s against the invited handle's `id` (plan §6.4). A device that connected under a
    /// churned handle — a bounded identity-map eviction, a transport `stop()`/restart — therefore
    /// read as a stranger to a manager whose every other same-device question is
    /// ``PeerHandle/isSameEndpoint(as:)``: the timeout `disconnectPeer`'d the live connection it
    /// already held and re-invited it, and the delayed task invited a device already connected.
    ///
    /// Internal so a unit test can pin the decision: the production path only reaches it after a
    /// real `Task.sleep` behind a live radio.
    func heartConnectRetryIsMoot(for peer: PeerHandle, friend: ProximityTrustedPeerRecord) -> Bool {
        if hasHeartConnection(with: peer) { return true }
        return pendingHeartSend(for: peer)?.friend.fingerprint != friend.fingerprint
    }

    private func handleHeartConnectTimeout(peerID: UUID, peer: PeerHandle, friend: ProximityTrustedPeerRecord) {
        // A channel already came up (the handshake budget governs from there), or the send is
        // gone — nothing to do either way.
        guard !heartConnectRetryIsMoot(for: peer, friend: friend),
              let pending = pendingHeartSend(for: peer) else { return }
        let nextAttempt = pending.attempt + 1
        guard nextAttempt < Self.maxHeartInviteAttempts else {
            removePendingHeartSend(for: peer)
            session?.disconnectPeer(peer)
            failHeart("\(Self.firstName(of: friend.displayName)) didn't answer — try again in a moment.")
            return
        }
        // Pre-discovery race: clear the stale invite, then re-invite after a short delay (mirrors
        // the mesh re-invite pattern the recipe cap uses).
        removePendingHeartSend(for: peer)
        pendingHeartSends[peerID] = (peer, friend, nextAttempt)
        session?.disconnectPeer(peer)
        recordDiagnostic("Retrying heart invite.")
        spawnHostPinned { [weak self] in
            // Cancelled re-invite delay: the send was abandoned, so do not invite (R7).
            do {
                try await Task.sleep(for: .seconds(Self.heartReinviteDelaySeconds))
            } catch {
                return
            }
            guard !Task.isCancelled, let self else { return }
            guard !self.heartConnectRetryIsMoot(for: peer, friend: friend) else { return }
            // Re-derived, never carried: the retry may land in a later epoch than the first
            // attempt, and a stale tag resolves to nobody on the far side.
            guard let tag = self.ownTagToken(for: friend) else { return }
            self.session?.dial(peer, helloTag: tag)
            self.armHeartConnectTimeout(peerID: peerID, peer: peer, friend: friend)
        }
    }

    /// Cancels the pre-connect timer armed for `peer`'s DEVICE. The timer is filed under the handle
    /// the send was issued to, so a channel that comes up under a churned handle must look the
    /// arming handle up through ``pendingHeartSend(for:)`` rather than cancel by its own `id` and
    /// leave the real timer running.
    private func cancelHeartConnectTimeout(for peer: PeerHandle) {
        cancelHeartConnectTimeout(peerID: pendingHeartSend(for: peer)?.peer.id ?? peer.id)
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
    ///
    /// A thin delegation to ``isHeartEligible(signingPublicKey:fingerprint:in:)`` since P6 item 6,
    /// so the routed heart path — which has no `PeerIdentity` — reaches the same three legs rather
    /// than re-implementing them.
    static func isHeartEligibleFriend(_ peerIdentity: ProximityCoordinator.PeerIdentity, in host: any ProximityHost) -> Bool {
        isHeartEligible(
            signingPublicKey: peerIdentity.signingPublicKey,
            fingerprint: peerIdentity.fingerprint,
            in: host
        )
    }

    /// The heart-eligibility gate over its two inputs rather than over a live handshake (P6 item 6).
    ///
    /// One definition, two callers. The presence path passes a handshake-verified
    /// `ProximityCoordinator.PeerIdentity`; the routed path has no handshake at all and passes the
    /// **admission ledger's** own values (`MeshRosterMember.signingPublicKey` plus the origin's
    /// signed fingerprint). That is the real improvement over the legacy transport, and it is not
    /// that the input is "less of a claim" — the legacy input was handshake-verified too — but that
    /// the ledger's key is durable, quorum-admitted, available with no live link, and not
    /// substitutable by a re-provisioned identity.
    ///
    /// All three legs are preserved, and the block list is consulted with **both** inputs, so an
    /// admitted-then-blocked member is refused here as well as at the projection's own hoisted
    /// block check (blocking is local and does not remove a member from the derived roster, so this
    /// is a live case rather than a hypothetical).
    ///
    /// - Parameters:
    ///   - signingPublicKey: The peer's Ed25519 signing key.
    ///   - fingerprint: The peer's fingerprint.
    ///   - host: The host holding the trust vault and the block list.
    /// - Returns: whether a heart from or to this peer may be recorded.
    static func isHeartEligible(
        signingPublicKey: Data, fingerprint: String, in host: any ProximityHost
    ) -> Bool {
        let vault = host.proximityTrustVault
        return vault.isTrustedProximityPeer(signingPublicKey: signingPublicKey)
            && !vault.isBlockedProximitySigningKey(signingPublicKey)
            && !host.isBlockedFingerprint(fingerprint)
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
        // host-pin: timer — stored handle, synchronous main-actor body (`heartSendState = .idle`) (HP2)
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
    /// Drives the transport-error handler exactly as the session would, without a radio: the
    /// closure `start()` installs is on a session a unit test never creates.
    func handleTransportErrorForTesting(_ message: String) {
        handleTransportError(message)
    }

    func activateForTesting() {
        guard !isRunning else { return }
        isRunning = true
        currentEpoch = rotatePosture(at: nowProvider())
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

    /// Fires the pre-connect retry exactly as the armed timer would, without waiting out
    /// `heartConnectTimeoutSeconds` — the arming path needs a live radio a unit test must not
    /// start, and the retry's own effects (a `disconnectPeer` of a live pairing, a re-invite) are
    /// what the churned-handle regression turns on.
    func fireHeartConnectTimeoutForTesting(peer: PeerHandle, friend: ProximityTrustedPeerRecord) {
        handleHeartConnectTimeout(peerID: peer.id, peer: peer, friend: friend)
    }

    /// Drives the production disconnect-removal path (`removeHeartConnection(matching:)`) exactly
    /// as the presence radio's `onPeerDisconnected` would — the writer needs a live radio a unit
    /// test must never start.
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
        let channelSession = session ?? NetworkPresenceSession()
        let channel = channelSession.channel(for: peer)
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
    /// `NetworkPresenceSession` a unit test cannot fake.
    ///
    /// Deliberately NOT `@discardableResult` (R7): the `Bool` is the accept/reject signal, so a
    /// caller that ignores it is ignoring the trust decision.
    func evaluateConnectedCoordinatorForTesting(
        _ coordinator: ProximityCoordinator,
        peer: PeerHandle,
        trustPolicy: FriendSessionTrustPolicy,
        intendedFriend: ProximityTrustedPeerRecord? = nil
    ) -> Bool {
        let channelSession = session ?? NetworkPresenceSession()
        heartConnections.append(PresenceHeartConnection(
            id: peer.id,
            peer: peer,
            channel: channelSession.channel(for: peer),
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
