import Foundation
import Observation
import UIKit
import FernletDomainModel
import FernletFoundation

/// One live recipe-share pairing: the peer, its channel + coordinator, and (once the handshake
/// completes) the verified fingerprint and KA key.
///
/// Under the hard 2-device cap the manager holds at most one of these at a time.
private struct RecipeShareConnection: Identifiable {
    let id: UUID
    let peer: MultipeerPeer
    let channel: PeerChannelTransport
    let coordinator: ProximityCoordinator
    /// Retained for the connection's lifetime so the coordinator's `weak` trustPolicy stays alive —
    /// otherwise the revoked/blocked-key envelope rejection + audit calls silently no-op (they would
    /// evaluate `nil?.isRevokedProximitySigningKey(...) == true` → false, and every recordTrainerAudit
    /// becomes a no-op). Mirrors MeshNetworkManager's `slotTrustPolicies` and the heart manager's
    /// HeartShareConnection.
    let trustPolicy: FriendSessionTrustPolicy
    var fingerprint: String?
    var verifiedKeyAgreementPublicKey: Data?
}

// Pure diagnostics value type + a stateless ring-buffer helper — explicitly
// `nonisolated` so they are NOT swept into the target's `defaultIsolation(MainActor.self)`.
// They hold no main-actor state, so keeping them nonisolated preserves their off-main
// usability under Swift 6 mode (behaviour-identical to the prior Swift 5 language mode).
// Mirrors WI-9's nonisolated wire types; the @MainActor manager below still uses them freely.
/// One timestamped, identity-free line in a proximity manager's diagnostics ring.
///
/// Shared display shape across the recipe-share and presence managers' diagnostic surfaces;
/// messages never carry fingerprints or keys.
public struct ProximityRecipeShareDiagnosticEvent: Identifiable, Equatable {
    public nonisolated let id: UUID
    public nonisolated let timestamp: Date
    public nonisolated let message: String

    public nonisolated init(id: UUID = UUID(), timestamp: Date = Date(), message: String) {
        self.id = id
        self.timestamp = timestamp
        self.message = message
    }
}

/// Stateless ring-buffer helper for the diagnostics event list: append and trim to the newest
/// `maxEvents`.
///
/// Pure and `nonisolated` so any isolation domain can use it; both the recipe-share and
/// presence managers funnel their `recordDiagnostic` through it.
public enum ProximityRecipeShareDiagnostics {
    public nonisolated static let maxEvents = 40

    public nonisolated static func appending(
        _ event: ProximityRecipeShareDiagnosticEvent,
        to events: [ProximityRecipeShareDiagnosticEvent],
        maxCount: Int = maxEvents
    ) -> [ProximityRecipeShareDiagnosticEvent] {
        guard maxCount > 0 else { return [] }
        return Array((events + [event]).suffix(maxCount))
    }
}

/// The recipe-share radio (`fernlet-recipe`): discovers nearby Fernlets, forms a hard-capped
/// 2-device verified pairing, and exchanges sealed `.recipeShare` payloads.
///
/// Owns its own `MeshMultipeerSession`, ``IdentityService`` cache, and ``ReplayCache``; each
/// pairing gets a ``ProximityCoordinator`` with a retained ``FriendSessionTrustPolicy`` (the
/// coordinator's trust ref is `weak` — dropping the retention silently disables the
/// revoked/blocked drops). The hard 2-device cap is enforced at four layers: the inbound
/// invitation gate, the outbound send guard, the connecting-window check, and the belt-and-braces
/// channel admission — with the radio PAUSED while paired (`pauseDiscovery`) and reopened only on
/// manager-level record eviction, never on MC disconnect events (a failed handshake fires none).
/// Timeouts: a 12 s pre-connect timer (the peer-is-busy case), the coordinator's 25 s handshake
/// budget, and a parked-connection sweep for coordinators stalled pre-verification. Inbound
/// shares are rate-limited per sender and capped at 8 pending. Lifecycle is owned by the app
/// (ContentView gates on tab/scene/lock). `@MainActor @Observable`.
@MainActor
@Observable
public final class ProximityRecipeShareManager: ProximityPayloadHandling {
    /// The observable send pipeline the share sheet renders: connecting → sending → sent, or a
    /// failure message; `idle` between sends (auto-cleared after 2.5 s).
    public enum SendState: Equatable {
        case idle
        case connecting(recipientName: String)
        case sending(recipientName: String)
        case sent(recipientName: String)
        case failed(message: String)
    }

    public private(set) var nearbyRecipients: [ProximityRecipeShareRecipient] = []
    public private(set) var sendState: SendState = .idle
    public private(set) var diagnosticEvents: [ProximityRecipeShareDiagnosticEvent] = []
    /// R6: read-only outside this file — the cap (`maxPendingShares`) and the dedup live in this
    /// file's writers, and the two `dismissRecipeShare` methods cover the external mutation need.
    public private(set) var pendingRecipeShares: [PendingProximityRecipeShare] = []
    /// The recipient this manager is currently engaged with — connecting to, sending to, or
    /// holding the (hard-capped, one-at-a-time) verified connection with. The share sheet
    /// disables every other recipient row while this is set; nil when idle.
    public private(set) var engagedRecipientID: UUID?

    @ObservationIgnored private unowned let store: any ProximityHost
    @ObservationIgnored private let session = MeshMultipeerSession()
    @ObservationIgnored private let identity: IdentityService
    @ObservationIgnored private let replayCache = ReplayCache()
    @ObservationIgnored private var connections: [RecipeShareConnection] = []
    @ObservationIgnored private var discoveredPeers: [UUID: MultipeerPeer] = [:]
    @ObservationIgnored private var observationTask: Task<Void, Never>?
    @ObservationIgnored private var clearStatusTask: Task<Void, Never>?
    @ObservationIgnored private var connectTimeoutTask: Task<Void, Never>?
    @ObservationIgnored private var parkedSweepTask: Task<Void, Never>?
    @ObservationIgnored private var parkedSince: [UUID: Date] = [:]
    @ObservationIgnored private var pendingOutgoing: (payload: ProximityRecipeSharePayload, recipient: ProximityRecipeShareRecipient)?
    @ObservationIgnored private var isRunning = false
    private var connectionObservationRevision = 0
    @ObservationIgnored private var sessionID = UUID().uuidString

    private static let serviceType = "fernlet-recipe"
    private static let maxPendingShares = 8
    private static let perSenderRateLimitSeconds: TimeInterval = 3
    /// How long a coordinator may sit in a pre-verification state (.idle/.starting/
    /// .discovering/.peerInRange) before its connection record is force-evicted. The
    /// coordinator's own handshake timeout is 25 s; this is that plus slack, so the parked
    /// sweep only ever catches records the coordinator's timeout can no longer convert to
    /// .ended (the friend-mode auto-reconnect path re-parks in .discovering).
    private static let parkedConnectionTimeoutSeconds: TimeInterval = 30
    private static let parkedSweepIntervalSeconds: TimeInterval = 5
    /// Sender-side connect timeout (mesh redesign Phase 3b): under a hard 2-device cap,
    /// "the other Fernlet is already paired and ignoring invites" is the COMMON failure, and
    /// without this it looked like an eternal "Connecting…". Scoped to the PRE-CONNECT stage
    /// only — it is cancelled the moment the connection record exists (`registerConnection`,
    /// fired by handleChannelReady): from there the coordinator's own 25 s handshake budget
    /// governs, and letting this shorter timer keep running would best-effort kick a pairing
    /// that is still progressing. Internal (not private) so tests can shorten it.
    @ObservationIgnored var connectTimeoutSeconds: TimeInterval = 12
    @ObservationIgnored private var lastAcceptedBySender: [String: Date] = [:]

    public init(store: any ProximityHost) {
        self.store = store
        let id = IdentityService()
        do {
            try id.ensureProvisioned()
        } catch {
            // Benign: every session start re-attempts provisioning and fails visibly
            // (`fail(error.localizedDescription)`) — but the FIRST failure must not vanish.
            FernletAuditLog.log("recipeShare.identity.provisionFailed",
                                context: ["error": String(describing: error)])
        }
        self.identity = id
        setupSession()
    }

    /// Delete-all seam (Docs/PrivacyWipeCoverage.md): clears THIS instance's in-memory identity
    /// key cache; keychain rows are shared with the mesh/presence instances (idempotent).
    public func wipeIdentityForDeleteAll() throws {
        try identity.wipe()
    }

    /// Ends every long-running task the manager owns if it is released without `stop()` (the
    /// production instance never is — process-lifetime on the store — but tasks must not outlive
    /// their owner: the observation loop would stay parked, the timers spin one more tick).
    /// `isolated`: the handles are main-actor state.
    isolated deinit {
        observationTask?.cancel()
        clearStatusTask?.cancel()
        connectTimeoutTask?.cancel()
        parkedSweepTask?.cancel()
    }

    public func start() {
        guard !isRunning else { return }
        isRunning = true
        recordDiagnostic("Recipe share discovery started.")
        session.start(serviceType: Self.serviceType, discoveryInfo: discoveryInfo())
        startObserving()
    }

    public func stop() {
        if isRunning {
            recordDiagnostic("Recipe share discovery stopped.")
        }
        isRunning = false
        observationTask?.cancel()
        observationTask = nil
        clearStatusTask?.cancel()
        clearStatusTask = nil
        connectTimeoutTask?.cancel()
        connectTimeoutTask = nil
        parkedSweepTask?.cancel()
        parkedSweepTask = nil
        parkedSince.removeAll()
        cancelCoordinators(of: connections)
        session.stop()
        nearbyRecipients.removeAll()
        pendingOutgoing = nil
        discoveredPeers.removeAll()
        connections.removeAll()
        engagedRecipientID = nil
        sendState = .idle
    }

    public func refreshDiscovery() {
        // Hard 2-device cap: refreshing must NEVER tear down a live pairing — the old
        // stop-and-restart body would have dropped the verified connection mid-share. Refuse
        // visibly instead; discovery reopens on its own when the connection record is evicted.
        if let connection = connections.first {
            let name = displayName(for: connection)
            recordDiagnostic("Search skipped — already paired with \(name).")
            sendState = .failed(message: "Connected to \(name) — recipe sharing links two Fernlets at a time.")
            scheduleStatusClear()
            return
        }
        let shouldRestart = isRunning
        recordDiagnostic("Recipe share discovery refreshed.")
        observationTask?.cancel()
        observationTask = nil
        connectTimeoutTask?.cancel()
        connectTimeoutTask = nil
        parkedSweepTask?.cancel()
        parkedSweepTask = nil
        parkedSince.removeAll()
        cancelCoordinators(of: connections)
        session.stop()
        nearbyRecipients.removeAll()
        pendingOutgoing = nil
        discoveredPeers.removeAll()
        connections.removeAll()
        engagedRecipientID = nil
        sendState = .idle
        isRunning = false
        if shouldRestart {
            start()
        }
    }

    public func sendRecipeShare(_ payload: ProximityRecipeSharePayload, to recipient: ProximityRecipeShareRecipient) {
        connectTimeoutTask?.cancel()

        // Hard 2-device cap (outbound): refuse — visibly, never silently — while a connection
        // to a DIFFERENT peer exists. The radio is paused while paired, so an invite could not
        // go out anyway (see MeshMultipeerSession.pauseDiscovery contract).
        if let connection = connections.first, connection.id != recipient.id {
            let name = displayName(for: connection)
            sendState = .failed(message: "Still sharing with \(name) — recipe sharing links two Fernlets at a time.")
            recordDiagnostic("Refused share to \(recipient.displayName): already paired with \(name).")
            scheduleStatusClear()
            return
        }

        start()
        pendingOutgoing = (payload, recipient)
        sendState = .connecting(recipientName: recipient.displayName)
        engagedRecipientID = recipient.id
        recordDiagnostic("Connecting to \(recipient.displayName).")

        if let connection = connections.first(where: { $0.id == recipient.id }),
           connection.verifiedKeyAgreementPublicKey != nil {
            Task { [weak self] in await self?.sendPendingPayload(via: connection) }
            return
        }

        guard let peer = peer(for: recipient) else {
            pendingOutgoing = nil
            sendState = .failed(message: "That nearby Fernlet is no longer available.")
            recordDiagnostic("Recipe share failed: \(recipient.displayName) is no longer available.")
            updateEngagedRecipient()
            scheduleStatusClear()
            return
        }
        // Hard 2-device cap (connecting window): an attempt to a different peer is already in
        // flight — inviting a second one could race two connections past the cap.
        if session.hasPendingConnections(besides: peer) {
            pendingOutgoing = nil
            sendState = .failed(message: "Still connecting to another Fernlet — recipe sharing links two Fernlets at a time.")
            recordDiagnostic("Refused share to \(recipient.displayName): another connection attempt is in flight.")
            updateEngagedRecipient()
            scheduleStatusClear()
            return
        }
        session.invite(peer)
        armConnectTimeout(for: recipient)
    }

    public func dismissRecipeShare(_ share: PendingProximityRecipeShare) {
        pendingRecipeShares.removeAll { $0.id == share.id }
    }

    public func dismissRecipeShare(id: UUID) {
        pendingRecipeShares.removeAll { $0.id == id }
    }

    public func proximityCoordinator(
        _ coordinator: ProximityCoordinator,
        didReceive envelope: FernletIdentityEnvelope,
        plaintext: Data,
        from peer: ProximityCoordinator.PeerIdentity?
    ) {
        guard envelope.payloadType == .recipeShare else { return }
        // Size gate BEFORE the decoder: the transport floor is 16 MiB, and JSONDecoder on a
        // multi-megabyte body is itself the denial-of-service. An honest share is far under 1 MiB
        // (see ProximityRecipeSharePayload.maxWireBytes for the derivation).
        // Peer-supplied name, rendered in the review sheet and every diagnostic below: coerce ONCE
        // here (control/zero-width/bidi out, 24-char cap). Never coerce it before `verify` — the
        // raw field is signature-covered.
        let senderName = ItemNameModeration.moderatedPeerDisplayName(envelope.senderDisplayName)
        guard plaintext.count <= ProximityRecipeSharePayload.maxWireBytes else {
            recordDiagnostic("Dropped an oversized recipe share from \(senderName).")
            return
        }
        guard let decoded = try? JSONDecoder().decode(ProximityRecipeSharePayload.self, from: plaintext),
              decoded.format == "fernlet.proximity.recipe",
              decoded.version == 1 else { return }
        // Enforce the wire image cap AT THE DOOR, not just at import time: the pending queue holds
        // payloads until the user reviews them, and the sealed-frame layer alone would let a
        // hostile peer park multi-MB images (bytes an honest sender never produces) in memory.
        // clampedForReview() bounds the strings the review sheet renders for the same reason.
        let payload = decoded.droppingOversizeImage().clampedForReview()

        // DELIBERATELY RAW: this is the per-sender RATE-LIMIT key, never rendered. Sanitizing it
        // would collapse distinct unfingerprinted senders — names differing only by a zero-width
        // character — into one bucket, which is the opposite of what the limiter is for.
        let senderFP = peer?.fingerprint ?? envelope.senderDisplayName
        let now = Date()
        if let lastAccepted = lastAcceptedBySender[senderFP],
           now.timeIntervalSince(lastAccepted) < Self.perSenderRateLimitSeconds {
            recordDiagnostic("Rate-limited recipe share from \(senderName).")
            return
        }
        guard pendingRecipeShares.count < Self.maxPendingShares else {
            recordDiagnostic("Dropped recipe share from \(senderName): queue full.")
            return
        }
        // R3: prune before inserting — entries older than the rate-limit window gate nothing, so
        // without this the map grows one entry per distinct sender for the manager's lifetime.
        lastAcceptedBySender = lastAcceptedBySender.filter {
            now.timeIntervalSince($0.value) < Self.perSenderRateLimitSeconds
        }
        lastAcceptedBySender[senderFP] = now

        let pending = PendingProximityRecipeShare(
            senderDisplayName: senderName,
            senderFingerprint: peer?.fingerprint,
            receivedAt: now,
            payload: payload
        )
        pendingRecipeShares.removeAll { $0.id == pending.id }
        pendingRecipeShares.insert(pending, at: 0)
        if pendingRecipeShares.count > Self.maxPendingShares {
            pendingRecipeShares = Array(pendingRecipeShares.prefix(Self.maxPendingShares))
        }
        recordDiagnostic("Received recipe share from \(senderName).")
    }

    private func setupSession() {
        session.onPeerDiscovered = { [weak self] peer in
            self?.handlePeerDiscovered(peer)
        }
        session.onPeerLost = { [weak self] peer in
            self?.handlePeerLost(peer)
        }
        session.onPeerChannelReady = { [weak self] channel in
            self?.handleChannelReady(channel)
        }
        session.onPeerDisconnected = { [weak self] peer, _ in
            guard let self else { return }
            self.handlePeerLost(peer)
            self.removeConnections(matching: peer)
            self.recordDiagnostic("\(peer.displayName) disconnected.")
        }
        session.shouldAcceptInvitation = { [weak self] peer in
            guard let self else { return false }
            // Blocklist is enforced at identity-introduction time by the coordinator.
            // Hard 2-device cap (inbound): accept only when we hold no connection AND no
            // connecting-window pending peer — checking `connections` alone leaves a race
            // where a second inviter slips in while the first is still MC-connecting. The
            // SAME peer re-inviting (retry of a dropped attempt) is always let through.
            if self.connections.contains(where: { $0.peer.id == peer.id || $0.peer.underlying == peer.underlying }) {
                return true
            }
            guard self.connections.isEmpty else { return false }
            return !self.session.hasPendingConnections(besides: peer)
        }
        session.onTransportError = { [weak self] message in
            guard let self else { return }
            self.recordDiagnostic(message)
            // Discovery failed to (re)start (advertiser/browser didNotStart — e.g. the Bonjour
            // restart after a record eviction's resumeDiscovery): with `isRunning` left true,
            // ContentView's idempotent start() no-ops forever and passive listening stays dark.
            // Stop fully so the next gate event (tab/scene/lock change) or sheet restart genuinely
            // restarts the radio. didNotStart* only fires from start attempts — and resume runs
            // only with no connection held — but guard on an empty connection list anyway so an
            // unexpected error can never tear down a live pairing.
            guard self.connections.isEmpty, self.isRunning else { return }
            self.stop()
            self.recordDiagnostic("Recipe share radio failed to start — listening will retry on the next app event.")
        }
    }

    private func discoveryInfo() -> [String: String] {
        [
            "v": "1",
            "sid": sessionID,
            "name": String(displayName.prefix(32)),
            "mode": "recipe"
        ]
    }

    /// The advertised local display name (shared coercion; see `PeerDisplayNames.swift`).
    private var displayName: String { store.resolvedProximityDisplayName }

    private func handlePeerDiscovered(_ peer: MultipeerPeer) {
        // Exclude self using session ID comparison; blocklist is enforced post-introduction.
        if let remoteSID = peer.discoveryInfo?["sid"], remoteSID == sessionID { return }
        discoveredPeers[peer.id] = peer
        let recipient = ProximityRecipeShareRecipient(
            id: peer.id,
            // Pre-handshake label straight off the wire — the picker, the browse list and the
            // diagnostics all read it back from here, so this is the one ingest to coerce.
            displayName: ItemNameModeration.moderatedPeerDisplayName(peer.discoveryInfo?["name"] ?? peer.displayName),
            fingerprint: nil
        )
        nearbyRecipients.removeAll { $0.id == recipient.id }
        nearbyRecipients.append(recipient)
        nearbyRecipients.sort { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending }
        recordDiagnostic("Discovered \(recipient.displayName).")
    }

    private func handlePeerLost(_ peer: MultipeerPeer) {
        let displayName = nearbyRecipients.first { $0.id == peer.id }?.displayName ?? peer.displayName
        discoveredPeers.removeValue(forKey: peer.id)
        nearbyRecipients.removeAll { $0.id == peer.id }
        recordDiagnostic("\(displayName) is no longer nearby.")
    }

    /// Belt-and-braces admission check for a just-connected MC channel (hard 2-device cap):
    /// true only when no connection exists or the peer already holds it. A third peer can
    /// still slip past both invitation gates in the connecting window; this is the last line.
    func shouldAdmitChannel(for peer: MultipeerPeer) -> Bool {
        connections.isEmpty || connections.contains { $0.peer.id == peer.id || $0.peer.underlying == peer.underlying }
    }

    private func handleChannelReady(_ channel: PeerChannelTransport) {
        guard !connections.contains(where: { $0.peer.id == channel.peer.id }) else { return }
        // Hard 2-device cap, belt-and-braces: a third peer that won the connecting-window race
        // anyway is never admitted — best-effort kick it (see disconnectPeer's caveats) and
        // leave the existing pairing untouched.
        guard shouldAdmitChannel(for: channel.peer) else {
            recordDiagnostic("Turned away \(channel.peer.displayName) — recipe sharing links two Fernlets at a time.")
            session.disconnectPeer(channel.peer)
            return
        }
        recordDiagnostic("Secure recipe-share channel opened with \(channel.peer.displayName).")
        let trustPolicy = FriendSessionTrustPolicy(vault: store.proximityTrustVault)
        let coordinator = ProximityCoordinator(
            identity: identity,
            transport: channel,
            ranging: NIRangingSession(),
            payloadHandler: self,
            trustPolicy: trustPolicy,
            replayCache: replayCache,
            displayName: displayName,
            timeoutSeconds: 25
        )
        let connection = RecipeShareConnection(
            id: channel.peer.id,
            peer: channel.peer,
            channel: channel,
            coordinator: coordinator,
            trustPolicy: trustPolicy,
            fingerprint: nil,
            verifiedKeyAgreementPublicKey: nil
        )
        registerConnection(connection)

        Task { [weak self] in
            await coordinator.begin(role: .browser, mode: .friend)
            channel.notifyConnected()
            self?.checkCoordinatorStates()
        }
    }

    /// Single add-path for connection records. Pauses discovery the moment a connection is
    /// established — this runs for BOTH roles (handleChannelReady fires on inviter and invitee
    /// alike), which is the owner's "the mesh closes once two devices connect": the recipient's
    /// radio goes quiet while paired too. `resumeDiscovery` is keyed on record eviction in
    /// `finalizeConnectionRemovals`.
    private func registerConnection(_ connection: RecipeShareConnection) {
        connections.append(connection)
        connectionObservationRevision += 1
        // The connect stage for the engaged recipient is over: from here the coordinator's own
        // 25 s handshake budget (plus the parked sweep) governs — the shorter pre-connect timer
        // must not fire and best-effort kick a pairing that is progressing.
        if pendingOutgoing?.recipient.id == connection.id {
            connectTimeoutTask?.cancel()
            connectTimeoutTask = nil
        }
        session.pauseDiscovery()
        recordDiagnostic("Recipe sharing closed to others while paired with \(connection.peer.displayName).")
        updateEngagedRecipient()
        startParkedSweepIfNeeded()
    }

    private func startObserving() {
        observationTask?.cancel()
        observationTask = ObservationLoop.start(
            on: self,
            tracking: { owner in
                _ = owner.connectionObservationRevision
                _ = owner.connections.count
                for connection in owner.connections {
                    _ = connection.coordinator.state
                }
            },
            onChange: { owner in
                owner.checkCoordinatorStates()
            }
        )
    }

    private func checkCoordinatorStates() {
        for index in connections.indices {
            switch connections[index].coordinator.state {
            case .awaitingManualCommit, .awaitingProximityCommit:
                let coordinator = connections[index].coordinator
                recordDiagnostic("Recipe share recipient verified; confirming selected recipient.")
                Task { await coordinator.commitManualProximity() }
            default:
                break
            }

            if case .connected(let peerIdentity) = connections[index].coordinator.state {
                let fingerprint = peerIdentity.fingerprint
                if connections[index].fingerprint != fingerprint {
                    connections[index].fingerprint = fingerprint
                    connections[index].verifiedKeyAgreementPublicKey = peerIdentity.keyAgreementPublicKey
                    ensureRecipient(for: connections[index], identity: peerIdentity)
                    recordDiagnostic("Verified \(peerIdentity.displayName).")
                }
                if pendingOutgoing?.recipient.id == connections[index].id {
                    let connection = connections[index]
                    Task { [weak self] in await self?.sendPendingPayload(via: connection) }
                }
            }
        }

        let stale = connections.filter { connection in
            switch connection.coordinator.state {
            case .ended, .failed: return true
            default: return false
            }
        }
        let before = connections.count
        cancelCoordinators(of: stale)
        for connection in stale {
            // A coordinator can fail/end without MC ever reporting a disconnect (a failed
            // handshake never fires one) — best-effort kick so the MC link doesn't linger as
            // a zombie while the record eviction below reopens discovery.
            session.disconnectPeer(connection.peer)
            parkedSince.removeValue(forKey: connection.id)
            connections.removeAll { $0.id == connection.id }
        }
        finalizeConnectionRemovals(previousCount: before)
    }

    private func removeConnections(matching peer: MultipeerPeer) {
        let before = connections.count
        let evicted = connections.filter { connection in
            connection.peer.id == peer.id || connection.peer.underlying == peer.underlying
        }
        cancelCoordinators(of: evicted)
        for connection in evicted { parkedSince.removeValue(forKey: connection.id) }
        let evictedIDs = Set(evicted.map(\.id))
        connections.removeAll { evictedIDs.contains($0.id) }
        finalizeConnectionRemovals(previousCount: before)
    }

    /// Runs the coordinators' OWN teardown for records being evicted. A `RecipeShareConnection`
    /// is the only strong owner of its ``ProximityCoordinator``; dropping the record without
    /// `cancel()` frees the Swift graph but skips `end()` — the NISession invalidate, the
    /// foreground anchor's Live Activity end, and the `.sessionEnded` audit — because the
    /// coordinator's own `.disconnected` hop is a weak-self Task that finds nothing. Every drop
    /// path (stop, refresh, MC disconnect, parked sweep, stale sweep) funnels here. For an
    /// `.ended` record `cancel()` is idempotent; for a `.failed` one it is what guarantees the
    /// teardown runs (`fail()` only enqueues it, and this sweep can drop the last reference
    /// first). Capturing the whole record keeps the coordinator's weak trust policy alive for the
    /// audit; the Task releases it afterwards.
    private func cancelCoordinators(of evicted: [RecipeShareConnection]) {
        for connection in evicted {
            Task { [connection] in await connection.coordinator.cancel() }
        }
    }

    /// Every connection-record removal funnels through here. Reopening the radio is keyed on
    /// MANAGER-LEVEL record eviction, deliberately NOT on MC disconnect events: a failed
    /// handshake never fires an MC disconnect, so waiting for one would leave the radio paused
    /// forever with no connection — the deadlock class the redesign closes. Covered removal
    /// paths: `onPeerDisconnected` (via removeConnections), the stale-coordinator sweep
    /// (.ended/.failed) in checkCoordinatorStates, and the parked-.discovering sweep.
    private func finalizeConnectionRemovals(previousCount: Int) {
        guard connections.count != previousCount else { return }
        connectionObservationRevision += 1
        updateEngagedRecipient()
        guard connections.isEmpty else { return }
        parkedSweepTask?.cancel()
        parkedSweepTask = nil
        parkedSince.removeAll()
        if isRunning, session.isDiscoveryPaused {
            session.resumeDiscovery()
            recordDiagnostic("Recipe sharing reopened to nearby Fernlets.")
        }
    }

    /// Derived observable: connection first (it outlives the send), pending outgoing second.
    private func updateEngagedRecipient() {
        engagedRecipientID = connections.first?.id ?? pendingOutgoing?.recipient.id
    }

    private func displayName(for connection: RecipeShareConnection) -> String {
        nearbyRecipients.first { $0.id == connection.id }?.displayName
            ?? ItemNameModeration.moderatedPeerDisplayName(connection.peer.displayName)
    }

    /// Arms the sender-side connect timeout for the PRE-CONNECT stage only. Under the hard
    /// 2-device cap the peer being busy (paired with someone else, silently rejecting invites)
    /// is the common case — surface it as a distinct visible failure instead of an eternal
    /// "Connecting…". `registerConnection` cancels this the moment the MC channel comes up;
    /// past that point the coordinator's 25 s handshake budget owns failure.
    private func armConnectTimeout(for recipient: ProximityRecipeShareRecipient) {
        connectTimeoutTask?.cancel()
        let timeout = connectTimeoutSeconds
        connectTimeoutTask = Task { @MainActor [weak self] in
            // Cancelled by `registerConnection`/`stop` ⇒ the connect stage succeeded or the
            // session went away; not firing IS the recovery.
            do { try await Task.sleep(for: .seconds(timeout)) } catch { return }
            guard let self else { return }
            guard let outgoing = self.pendingOutgoing, outgoing.recipient.id == recipient.id else { return }
            // Belt-and-braces stage check (registerConnection already cancels this task): a
            // connection record means the connect stage succeeded — never fail or kick a
            // handshake in progress from here.
            guard !self.connections.contains(where: { $0.id == recipient.id }) else { return }
            self.pendingOutgoing = nil
            self.sendState = .failed(message: "No answer from \(recipient.displayName) — that Fernlet may be busy sharing with someone else.")
            self.recordDiagnostic("Connect timeout: \(recipient.displayName) did not answer.")
            // Best-effort cancel of the half-open attempt so it doesn't linger in the
            // connecting window and block the next accept/invite.
            if let peer = self.peer(for: recipient) {
                self.session.disconnectPeer(peer)
            }
            self.updateEngagedRecipient()
            self.scheduleStatusClear()
        }
    }

    // MARK: - Parked-connection sweep

    private func startParkedSweepIfNeeded() {
        guard parkedSweepTask == nil else { return }
        parkedSweepTask = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                // Cancellation ends the sweep loop here rather than spinning one more iteration.
                do { try await Task.sleep(for: .seconds(Self.parkedSweepIntervalSeconds)) } catch { return }
                guard let self else { return }
                self.sweepParkedConnections(now: Date())
                if self.connections.isEmpty {
                    self.parkedSweepTask = nil
                    return
                }
            }
        }
    }

    /// Evicts connection records whose coordinator has parked in a pre-verification state
    /// (.idle/.starting/.discovering/.peerInRange) past `parkedConnectionTimeoutSeconds`. The
    /// .ended/.failed sweep in checkCoordinatorStates can never catch these: a transport that
    /// dies pre-verification fires no MC disconnect, and the friend-mode auto-reconnect path
    /// parks a once-connected coordinator back in .discovering — with the radio paused, such a
    /// record would hold the 2-device cap closed forever. Internal so tests can drive it with
    /// synthetic dates; production calls it from the periodic sweep task.
    func sweepParkedConnections(now: Date) {
        var evicted: [RecipeShareConnection] = []
        for connection in connections {
            switch connection.coordinator.state {
            case .idle, .starting, .discovering, .peerInRange:
                if let since = parkedSince[connection.id] {
                    if now.timeIntervalSince(since) >= Self.parkedConnectionTimeoutSeconds {
                        evicted.append(connection)
                    }
                } else {
                    parkedSince[connection.id] = now
                }
            default:
                parkedSince.removeValue(forKey: connection.id)
            }
        }
        guard !evicted.isEmpty else { return }
        let before = connections.count
        cancelCoordinators(of: evicted)
        for connection in evicted {
            // Same zombie caveat as the stale sweep: the MC link may still be up even though
            // the coordinator stalled — kick it best-effort.
            session.disconnectPeer(connection.peer)
            parkedSince.removeValue(forKey: connection.id)
            recordDiagnostic("Dropped stalled connection to \(connection.peer.displayName).")
            connections.removeAll { $0.id == connection.id }
        }
        finalizeConnectionRemovals(previousCount: before)
    }

    private func ensureRecipient(for connection: RecipeShareConnection, identity peerIdentity: ProximityCoordinator.PeerIdentity) {
        let recipient = ProximityRecipeShareRecipient(
            id: connection.id,
            displayName: peerIdentity.displayName,
            fingerprint: peerIdentity.fingerprint
        )
        nearbyRecipients.removeAll { $0.id == recipient.id || $0.fingerprint == recipient.fingerprint }
        nearbyRecipients.append(recipient)
        nearbyRecipients.sort { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending }
    }

    private func sendPendingPayload(via connection: RecipeShareConnection) async {
        guard let outgoing = pendingOutgoing,
              outgoing.recipient.id == connection.id else { return }
        connectTimeoutTask?.cancel()  // connected + verified — the connect phase is over
        pendingOutgoing = nil
        updateEngagedRecipient()
        sendState = .sending(recipientName: outgoing.recipient.displayName)
        recordDiagnostic("Sending \(outgoing.payload.recipe.title) to \(outgoing.recipient.displayName).")
        do {
            // DO NOT LOCALIZE "Recipe share" — it is signed into the envelope's canonical bytes and
            // rendered in the RECEIVING device's Connection Inspector, so translating it here would
            // put the sender's language in a stranger's audit log. The recipient-facing consent copy
            // is built on the receiving side and is free to localize; this is not it. See
            // `FernletIdentityEnvelope.payloadSummary`.
            let summary = PayloadSummary(
                title: "Recipe share",
                subtitle: nil,
                itemCount: outgoing.payload.recipe.ingredientCount
            )
            let payloadData = try JSONEncoder().encode(outgoing.payload)
            try await connection.coordinator.sendPayload(
                type: .recipeShare,
                summary: summary,
                payload: payloadData,
                sealed: true
            )
            sendState = .sent(recipientName: outgoing.recipient.displayName)
            recordDiagnostic("Sent \(outgoing.payload.recipe.title) to \(outgoing.recipient.displayName).")
        } catch {
            sendState = .failed(message: "Could not send that recipe.")
            recordDiagnostic("Recipe share failed while sending to \(outgoing.recipient.displayName).")
        }
        scheduleStatusClear()
    }

    private func peer(for recipient: ProximityRecipeShareRecipient) -> MultipeerPeer? {
        if let connection = connections.first(where: { $0.id == recipient.id }) {
            return connection.peer
        }
        return discoveredPeers[recipient.id]
            ?? session.channels.values.map(\.peer).first { $0.id == recipient.id }
    }

    private func scheduleStatusClear() {
        clearStatusTask?.cancel()
        clearStatusTask = Task { @MainActor [weak self] in
            // A superseding `scheduleStatusClear` cancels this one — NOT clearing the status is
            // the correct recovery, because the newer timer owns it.
            do { try await Task.sleep(for: .seconds(2.5)) } catch { return }
            self?.sendState = .idle
        }
    }

    private func recordDiagnostic(_ message: String) {
        diagnosticEvents = ProximityRecipeShareDiagnostics.appending(
            ProximityRecipeShareDiagnosticEvent(message: message),
            to: diagnosticEvents
        )
    }

    // MARK: - Test seam

    /// Builds AND retains a connection exactly as `handleChannelReady` does — creating the
    /// FriendSessionTrustPolicy from the store's vault and holding it on the connection struct so the
    /// coordinator's `weak` trustPolicy survives past this method's scope — but over an injected transport
    /// so a unit test can drive a revoked/blocked-key envelope through the coordinator. Returns the
    /// connection's coordinator. `internal` for `@testable` unit tests only: the production connection path
    /// is driven by a live `MeshMultipeerSession` a unit test cannot fake (mirrors the clothing manager's
    /// `clearCatalogs(...)` and the heart manager's `evaluateConnectedCoordinatorForTesting(...)`). If the
    /// retention regresses (policy no longer stored on the connection), the coordinator's weak ref goes nil
    /// once this returns and the revoked-key drop this drives silently stops firing.
    func makeRetainedConnectionCoordinatorForTesting(
        peer: MultipeerPeer,
        transport: any MultipeerTransport,
        ranging: any RangingProvider
    ) -> ProximityCoordinator {
        let trustPolicy = FriendSessionTrustPolicy(vault: store.proximityTrustVault)
        let coordinator = ProximityCoordinator(
            identity: identity,
            transport: transport,
            ranging: ranging,
            payloadHandler: self,
            trustPolicy: trustPolicy,
            replayCache: replayCache,
            foregroundAnchor: NoopProximityForegroundAnchor(),
            displayName: displayName,
            timeoutSeconds: 0
        )
        let connection = RecipeShareConnection(
            id: peer.id,
            peer: peer,
            channel: PeerChannelTransport(peer: peer, session: session),
            coordinator: coordinator,
            trustPolicy: trustPolicy,
            fingerprint: nil,
            verifiedKeyAgreementPublicKey: nil
        )
        // Routed through the production add-path so cap tests exercise the real
        // pause-on-connect behavior (and the retention noted above still holds).
        registerConnection(connection)
        return coordinator
    }

    /// The private MeshMultipeerSession, exposed for cap tests only: they assert the
    /// pause/resume flag and drive the manager's own session callbacks (onPeerDisconnected,
    /// shouldAcceptInvitation) — the production writers need live radios a unit test must
    /// never start.
    var multipeerSessionForTesting: MeshMultipeerSession { session }

    var connectionCountForTesting: Int { connections.count }

    /// The run flag, exposed so the transport-error recovery tests can pin that a failed
    /// discovery (re)start flips it false — the property `start()`'s idempotence gate reads.
    var isRunningForTesting: Bool { isRunning }

    /// Marks the manager running WITHOUT starting the radio — `start()` would bring up a real
    /// advertiser/browser, which unit tests must never do. The resume-on-eviction gate checks
    /// `isRunning`, so cap tests need this to observe reopen behavior.
    func markRunningForTesting() {
        isRunning = true
    }

    /// Drives the production inbound-invitation gate closure exactly as the transport would.
    func shouldAcceptInvitationForTesting(_ peer: MultipeerPeer) -> Bool {
        session.shouldAcceptInvitation?(peer) ?? false
    }

    /// Runs the stale-coordinator sweep deterministically (production runs it from the
    /// observation loop, which only spins after a real `start()`).
    func checkCoordinatorStatesForTesting() {
        checkCoordinatorStates()
    }
}
