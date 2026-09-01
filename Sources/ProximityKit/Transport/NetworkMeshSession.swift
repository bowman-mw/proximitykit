import Combine
import CryptoKit
import Dispatch
import Foundation
import Network
import os
import Security
import FernletCrypto
import FernletDomainModel
import FernletFoundation

// MARK: - NetworkMeshWire

/// The QUIC control stream's length framing.
///
/// One long-lived bidirectional stream per connection carries every app frame (plan §7.1), and a
/// stream is a byte pipe, so the frame boundaries `MCSession.send` gave for free have to be written
/// back in. Four big-endian bytes of length, then that many bytes of payload.
///
/// The ceiling is ``NetworkMeshSession/maxInboundWireBytes`` — the same value the MC transport
/// enforces, deliberately, so the two transports refuse the same frame. Splitting them would mean a
/// payload that rides one radio and is dropped by the other.
nonisolated enum NetworkMeshWire {

    /// Bytes of big-endian length prefix before every payload.
    static let headerByteCount = 4

    /// The length header for a payload of `byteCount` bytes.
    static func header(for byteCount: Int) -> Data {
        let value = UInt32(truncatingIfNeeded: byteCount)
        return Data([
            UInt8((value >> 24) & 0xFF), UInt8((value >> 16) & 0xFF),
            UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)
        ])
    }

    /// The payload length a header names, refusing zero, a short header, and anything past the
    /// transport ceiling **before** a single payload byte is read.
    ///
    /// That ordering is the point: an attacker-supplied length is the one field that decides how
    /// much memory the next read allocates, so it is validated against the cap first and the read
    /// never happens for an implausible value.
    static func payloadLength(from header: Data, ceiling: Int) throws -> Int {
        let bytes = [UInt8](header)
        guard bytes.count == headerByteCount else { throw MeshTransportError.invalidFrameLength }
        let value = (UInt32(bytes[0]) << 24) | (UInt32(bytes[1]) << 16)
            | (UInt32(bytes[2]) << 8) | UInt32(bytes[3])
        guard value > 0, value <= UInt32(clamping: ceiling) else {
            throw MeshTransportError.invalidFrameLength
        }
        return Int(value)
    }
}

// MARK: - MeshSessionIdentityMap

/// One session-stable ``PeerHandle`` identity per remote endpoint.
///
/// The exact rule `MeshMultipeerSession` established in P2 item 3, restated for the QUIC transport:
/// `id` and ``PeerEndpointKey`` are minted **together, at one point, once per endpoint**, so they
/// can never disagree, and they live outside the caches discovery prunes — a peer lost and
/// re-browsed comes back as the same peer to every owner holding a record for it (a slot, a QR
/// binding, a re-dial budget). Under a transport that reconnects routinely rather than
/// exceptionally, that property matters more than it did under MC, not less.
///
/// Bounded oldest-first (Power of 10 rule 3). Eviction can only re-expose the pre-existing false
/// negative — a returning device read as new — never a false positive, because an identity is
/// minted once per distinct key.
///
/// **Session-scoped and memory-only**: never persisted, never advertised, never on the wire, and
/// cleared whole at teardown. Keeping it past a stop/start would link two runs of the radio to one
/// device, which is exactly what the per-session random Bonjour name exists to prevent.
nonisolated struct MeshSessionIdentityMap {

    /// Cap on retained identities. Four times the roster cap: an order of magnitude of headroom
    /// over any real session while a crowded room still cannot grow the map without end.
    static let maxTrackedEndpoints = 32

    /// One endpoint's identity: the `id` every handle minted for it carries, and its endpoint key.
    struct Identity: Equatable, Sendable {
        /// The stable ``PeerHandle/id`` for this endpoint, for as long as the session holds it.
        let id: UUID
        /// The transport's opaque endpoint key, handed to every handle minted for this endpoint.
        let endpoint: PeerEndpointKey
    }

    private var identities: [MeshLinkKey: Identity] = [:]
    private var keysByEndpoint: [PeerEndpointKey: MeshLinkKey] = [:]
    private var order: [MeshLinkKey] = []

    /// An empty map. A session owns exactly one.
    init() {}

    /// The identity for `key`, minting one on first sight. The single mint point.
    mutating func identity(for key: MeshLinkKey) -> Identity {
        if let existing = identities[key] { return existing }
        evictOldestIfFull()
        let minted = Identity(id: UUID(), endpoint: PeerEndpointKey())
        identities[key] = minted
        keysByEndpoint[minted.endpoint] = key
        order.append(key)
        return minted
    }

    /// The endpoint behind a handle, or nil once it has aged out. Every route from an owner's
    /// ``PeerHandle`` back to a live connection goes through here.
    func key(for peer: PeerHandle) -> MeshLinkKey? {
        keysByEndpoint[peer.endpoint]
    }

    /// How many endpoints this map holds an identity for — the read that lets a test assert
    /// teardown left nothing behind instead of inferring it from a re-mint.
    var trackedCount: Int {
        identities.count
    }

    /// Drops every identity. Called from teardown, with everything else the radio was holding.
    mutating func removeAll() {
        identities.removeAll()
        keysByEndpoint.removeAll()
        order.removeAll()
    }

    /// Makes room for one more identity, dropping the oldest — and both directions of its mapping,
    /// so the two can never point at different identities.
    private mutating func evictOldestIfFull() {
        guard order.count >= Self.maxTrackedEndpoints, let oldest = order.first else { return }
        order.removeFirst()
        guard let stale = identities.removeValue(forKey: oldest) else { return }
        keysByEndpoint.removeValue(forKey: stale.endpoint)
    }
}

// MARK: - NetworkPeerChannel

/// Per-peer ``PeerTransport`` adapter over one QUIC tunnel.
///
/// The QUIC counterpart of `PeerChannelTransport`, and deliberately the same shape: ``NetworkMeshSession``
/// owns the listener, the browser and the connections, and this type only routes one peer's state
/// and data. The advertise/browse/invite/accept requirements are no-ops for the same reason they
/// are there — the shared session owns discovery — and `disconnect` signals idle locally without
/// tearing down the shared radio.
///
/// **This channel never publishes ``PeerTransportState/discovered``**, matching the MC conformer
/// exactly. That is a constraint, not an omission: `ProximityCoordinator.shouldInviteDiscoveredPeer`
/// is a *second*, dormant inviter policy that compares `sessionID < remoteSID` — the opposite
/// direction to the live one in `MeshNetworkManager.shouldInitiateInvite` (`>`) — and it wakes the
/// moment a conformer emits a discovered state. Two policies pointing opposite ways means neither
/// side dials. Discovery reaches the owner through ``NetworkMeshSession/onPeerDiscovered`` instead,
/// which is where the live policy already reads it.
@MainActor
final class NetworkPeerChannel: PeerTransport {

    /// The peer this channel carries.
    let peer: PeerHandle

    private weak var session: NetworkMeshSession?
    private let stateSubject = CurrentValueSubject<PeerTransportState, Never>(.idle)
    private let inboundSubject = PassthroughSubject<InboundPeerFrame, Never>()

    var state: AnyPublisher<PeerTransportState, Never> { stateSubject.eraseToAnyPublisher() }
    var inbound: AnyPublisher<InboundPeerFrame, Never> { inboundSubject.eraseToAnyPublisher() }
    var connectedPeers: [PeerHandle] { [] }

    init(peer: PeerHandle, session: NetworkMeshSession) {
        self.peer = peer
        self.session = session
    }

    // Discovery and admission belong to the shared session, exactly as they do under MC.
    func startAdvertising(serviceType: String, discoveryInfo: [String: String]) async throws {}
    func startBrowsing(serviceType: String) async throws {}
    func invite(_ peer: PeerHandle) async throws {}
    func accept(_ invite: PeerPendingInvite) async throws {}

    func send(_ data: Data, to peer: PeerHandle, mode: PeerDeliveryMode) async throws {
        guard let session else { throw PeerTransportError.unexpectedState }
        try await session.send(data, to: peer, mode: mode)
    }

    func disconnect() async {
        // Signals idle locally only — the shared radio and its other tunnels keep running.
        stateSubject.send(.idle)
    }

    // MARK: - Called by NetworkMeshSession

    /// Publishes `.connected`. Called after the owner's `begin()` has completed, matching the MC
    /// ordering contract that keeps the coordinator out of the wrong handshake branch.
    func notifyConnected() {
        stateSubject.send(.connected(peer))
    }

    /// Publishes `.disconnected` with a diagnostic reason.
    func notifyDisconnected(reason: String = "Peer disconnected") {
        stateSubject.send(.disconnected(reason: reason))
    }

    /// Publishes one inbound frame. The bytes are untrusted: the coordinator decodes, size-gates
    /// and signature-verifies before anything downstream sees them.
    func receive(_ data: Data, at receivedAt: Date) {
        inboundSubject.send(InboundPeerFrame(
            peer: peer,
            data: data,
            receivedAt: receivedAt,
            bytesReceived: data.count
        ))
    }
}

// MARK: - NetworkMeshSession

/// The shared Network.framework/QUIC radio: one listener, one browser, and up to
/// ``MeshLinkTable/maxConcurrentLinks`` authenticated tunnels, multiplexed into per-peer
/// ``NetworkPeerChannel`` channels.
///
/// The TN3213 counterpart of `MeshMultipeerSession`, and the second `PeerTransport` conformer plan
/// §7 calls for. The mapping it implements: `MCNearbyServiceAdvertiser` → a `NetworkListener` over
/// `.bonjour`; `MCNearbyServiceBrowser` → a `NetworkBrowser`; one `MCSession` with N peers → one
/// QUIC `NetworkConnection` per peer; `.reliable` sends → a long-lived control stream;
/// `.bestEffort` sends and heartbeats → QUIC datagrams.
///
/// **Every decision lives somewhere testable.** The peer cap, the per-connection state machine, the
/// three-attempt dial budget, duplicate-tunnel suppression and the endpoint cache are
/// ``MeshLinkTable``; the 30 s heartbeat is ``MeshHeartbeatSchedule``; the TXT vocabulary is
/// ``MeshLinkAdvertisement``; peer identity is ``MeshSessionIdentityMap``. What is left here is the
/// framework plumbing that asks them and acts on the answer — which is the part no unit test can
/// reach, so it is kept as thin as it can be made.
///
/// **Security posture** (plan §7.2). TLS presents an ``EphemeralMeshTLSIdentity`` minted per session
/// and thrown away with it, paired with an accept-any certificate validator — because certificate
/// validation is *not* the authentication decision here. Authentication is the **signed channel
/// introduction**: before a single app frame crosses in either direction, both ends exchange
/// ``MeshChannelHello``s and then Ed25519 signatures over one ``MeshChannelIntroductionTranscript``
/// bound to this tunnel's TLS exporter secret, and each verifies the other against the current
/// roster. Failure tears the tunnel down; there is no degraded accept.
/// `prohibitedInterfaceTypes` is `[.cellular]` on every listener, browser and connection, always: it
/// is what turns the serverless/no-internet claim from an aspiration into something the OS enforces.
///
/// **Fail closed without an authority.** ``introductionAuthority`` is the seam that supplies the
/// mesh id, the epoch reference, the roster and the signing key. It is nil until P2 item 8 wires
/// `MeshNetworkManager`, and a session with no authority cannot authenticate anyone, so it refuses
/// every tunnel rather than admitting one unverified.
///
/// `@MainActor`; framework callbacks arrive `@Sendable` and hop in. Owners wire behaviour through
/// the closure hooks, the same way they do for the MC session.
@MainActor
final class NetworkMeshSession {

    /// The friend mesh's QUIC service type. Frozen wire token: it must also appear in the app's
    /// Info.plist `NSBonjourServices` or discovery is silently dead on device.
    nonisolated static let friendServiceType = "_fernlet-mesh2._udp"

    /// ALPN for the mesh protocol. Frozen wire token, never localized, distinct from the DEBUG
    /// probe's `fernlet-mesh-probe-v1` so a spike build and a shipping build cannot negotiate.
    nonisolated static let alpn = "fernlet-mesh-v1"

    /// Hard ceiling on one inbound frame, enforced before the bytes reach any channel or decoder.
    /// Pinned to the same value `MeshMultipeerSession` uses so both transports refuse identically.
    nonisolated static let maxInboundWireBytes = SealedPayloadFraming.maxInflatedByteCount

    /// QUIC datagram frame size requested in the parameters, and the UDP payload size beneath it.
    /// The probe's measured values on the feasibility lane.
    nonisolated static let datagramFrameSize = 1_024
    /// Maximum UDP payload requested, the floor QUIC datagrams negotiate against.
    nonisolated static let udpPayloadSize = 1_280

    /// Seconds between ticks of the single poll that drives retries and heartbeats.
    nonisolated static let pollIntervalSeconds: TimeInterval = 1

    /// Ticks the poll runs before it stops on its own — six hours at 1 Hz, the session ceiling
    /// plan §3 sets. Bounded rather than `while true` (Power of 10 rule 2).
    nonisolated static let maxPollTicks = 6 * 60 * 60

    /// Frames one connection may deliver before its receive loop retires. Bounded for the same
    /// reason; two orders of magnitude above the 500-message and 200-photo session caps.
    nonisolated static let maxInboundFramesPerConnection = 20_000

    /// Inbound tunnels that may be mid-introduction at once.
    ///
    /// A separate, smaller budget from the link table's slots on purpose: a peer that has not yet
    /// proved who it is must never occupy a **roster** seat, because the seat would then be taken by
    /// whoever dialed first rather than by a member. An unauthenticated connection holds one of
    /// these instead, and takes a real slot only once ``MeshChannelIntroductionExchange`` accepts it.
    nonisolated static let maxPendingInboundTunnels = MeshLinkTable.maxConcurrentLinks

    /// Seconds an inbound connection may take to finish its signed channel introduction.
    ///
    /// Without it, a peer that connects and then says nothing holds one of the pending seats for as
    /// long as the session lives, and eight silent connections keep every real member out. Two
    /// round trips over a link-local radio is milliseconds; ten seconds is generous for a phone that
    /// just woke, and it is swept by the same one poll that drives retries and heartbeats rather
    /// than by a timer per connection.
    nonisolated static let introductionDeadlineSeconds: TimeInterval = 10

    /// Whether Apple peer-to-peer Wi-Fi is requested. Simulators have no AWDL radio and reach each
    /// other over infrastructure only, which is the lane the feasibility probe validated.
    #if targetEnvironment(simulator)
    nonisolated static let includesPeerToPeer = false
    #else
    nonisolated static let includesPeerToPeer = true
    #endif

    private static let logger = Logger(subsystem: "com.fernlet", category: "proximity.transport.quic")

    // MARK: Hooks

    /// A peer appeared in the browse results. The owner's dial policy reads it — this radio never
    /// dials on its own, exactly as the MC session never invites on its own.
    var onPeerDiscovered: ((PeerHandle) -> Void)?
    /// A peer left the browse results.
    var onPeerLost: ((PeerHandle) -> Void)?
    /// A peer completed the signed channel introduction. Fires exactly once per tunnel, immediately
    /// before ``onPeerChannelReady`` — so an owner always learns *who* a channel belongs to before
    /// it is handed the channel, and never learns it for a tunnel that failed to authenticate.
    var onPeerVerified: ((PeerHandle, MeshVerifiedPeer) -> Void)?
    /// A tunnel reached ready and its channel is live.
    var onPeerChannelReady: ((NetworkPeerChannel) -> Void)?
    /// A tunnel went down, with a diagnostic reason.
    var onPeerDisconnected: ((PeerHandle, String) -> Void)?
    /// Invoked with frozen diagnostic English when the listener or browser fails to start.
    /// Without it a missing `NSBonjourServices` entry or a declined Local Network prompt is silent.
    var onTransportError: ((String) -> Void)?

    // MARK: State

    /// One live or in-flight tunnel: the peer it carries, its channel, the QUIC objects once the
    /// connection is up, and the two tasks that own its lifetime.
    ///
    /// `controlStream != nil` is the readiness test the whole class turns on — a connection that
    /// never got a control stream failed to dial, one that had a stream and lost it disconnected,
    /// and those two are charged to different budgets.
    private struct Tunnel {
        let peer: PeerHandle
        let channel: NetworkPeerChannel
        var controlStream: Network.QUIC.Stream<QUICStream>?
        var datagrams: Network.QUIC.Datagrams<QUICDatagram>?
        /// The identity this tunnel's peer proved in the signed channel introduction. Set once, at
        /// activation; a tunnel with no verified peer never reaches this map.
        var verified: MeshVerifiedPeer?
        /// Owns the connection: cancelling it is how the connection is torn down.
        var task: Task<Void, Never>?
        /// Owns the inbound datagram reader.
        var datagramTask: Task<Void, Never>?
    }

    /// The mesh id, epoch reference, roster and signing key the introduction needs. Nil refuses
    /// every tunnel — see the type's discussion.
    weak var introductionAuthority: (any MeshIntroductionAuthority)?

    private var links = MeshLinkTable()
    private var heartbeats = MeshHeartbeatSchedule()
    private var identities = MeshSessionIdentityMap()
    private var introductionNonces = MeshIntroductionNonceCache()
    private var tunnels: [MeshLinkKey: Tunnel] = [:]
    /// One inbound connection that has not yet proved who it is: the task that owns it, and when it
    /// arrived, so the shared poll can drop one that never finishes its introduction.
    private struct PendingInbound {
        let startedAt: Date
        let task: Task<Void, Never>
    }

    /// Inbound connections whose introduction has not finished. They hold no link-table slot and no
    /// channel; a tunnel is built only once a peer is verified.
    private var pendingInbound: [MeshLinkKey: PendingInbound] = [:]
    private var browsedEndpoints: [MeshLinkKey: Bonjour.Endpoint] = [:]
    private var tlsIdentity: EphemeralMeshTLSIdentity.Minted?
    private var listener: NetworkListener<QUIC>?
    private var browser: NetworkBrowser<Bonjour>?
    private var listenerTask: Task<Void, Never>?
    private var browserTask: Task<Void, Never>?
    private var pollTask: Task<Void, Never>?
    private var instanceName = MeshLinkAdvertisement.randomInstanceName()
    private var advertisedFields: [String: String] = [:]
    private var listenerIsReady = false
    private var listenerIsAdvertised = false
    private(set) var isRunning = false

    /// Channels for every live tunnel, in no particular order.
    var channels: [NetworkPeerChannel] { tunnels.values.map(\.channel) }

    /// Peers this radio currently holds a tunnel to.
    var connectedPeers: [PeerHandle] { tunnels.values.map(\.peer) }

    init() {}

    /// Cancels every task this radio owns.
    ///
    /// ``stop()`` already does this, and an owner that tears down cleanly never reaches here. The
    /// deinit exists for the owner that does not: a listener, browser, poll or per-tunnel task
    /// outlives its session otherwise, keeping a QUIC connection and a `MeshLinkKey` closure alive
    /// with nothing left to deliver to (memory-lifecycle rule ML1, the pattern `MeshNetworkManager`,
    /// `PresenceManager` and `ProximityRecipeShareManager` all use).
    isolated deinit {
        listenerTask?.cancel()
        browserTask?.cancel()
        pollTask?.cancel()
        for tunnel in tunnels.values {
            tunnel.task?.cancel()
            tunnel.datagramTask?.cancel()
        }
        for pending in pendingInbound.values {
            pending.task.cancel()
        }
    }

    // MARK: - Lifecycle

    /// Brings the radio up: mints this session's TLS identity and Bonjour name, starts the QUIC
    /// listener, and starts browsing once the listener is both ready and advertised.
    func start(discoveryInfo: [String: String]) throws {
        guard !isRunning else { return }
        instanceName = MeshLinkAdvertisement.randomInstanceName()
        advertisedFields = MeshLinkAdvertisement.publishedFields(from: discoveryInfo)
        tlsIdentity = try EphemeralMeshTLSIdentity.mint()
        isRunning = true
        try startListener()
        startPoll()
    }

    /// Republishes the TXT record. The listener is recreated rather than mutated, matching the
    /// stop-and-recreate pattern the MC advertiser needs; a no-op while stopped.
    func updateDiscoveryInfo(_ discoveryInfo: [String: String]) {
        advertisedFields = MeshLinkAdvertisement.publishedFields(from: discoveryInfo)
        guard isRunning else { return }
        listenerTask?.cancel()
        listenerTask = nil
        listener = nil
        listenerIsReady = false
        listenerIsAdvertised = false
        do {
            try startListener()
        } catch {
            report("The QUIC listener could not be republished: \(error)")
        }
    }

    /// Tears the radio down and drops everything it was holding.
    ///
    /// Every session-scoped map is cleared here — links, heartbeats, identities, the endpoint
    /// cache, the browsed endpoints, and the TLS identity. That is the privacy constraint: nothing
    /// this radio learns survives its own stop, so nothing owes a row on the wipe ledger.
    func stop() {
        for tunnel in tunnels.values {
            tunnel.task?.cancel()
            tunnel.datagramTask?.cancel()
        }
        for pending in pendingInbound.values {
            pending.task.cancel()
        }
        listenerTask?.cancel()
        browserTask?.cancel()
        pollTask?.cancel()
        listenerTask = nil
        browserTask = nil
        pollTask = nil
        listener = nil
        browser = nil
        tunnels.removeAll()
        pendingInbound.removeAll()
        browsedEndpoints.removeAll()
        links.removeAll()
        heartbeats.removeAll()
        identities.removeAll()
        introductionNonces.removeAll()
        tlsIdentity = nil
        listenerIsReady = false
        listenerIsAdvertised = false
        isRunning = false
    }

    // MARK: - Dialing

    /// Opens a tunnel to a discovered peer, if ``MeshLinkTable`` admits it.
    ///
    /// The owner's call, not this radio's: the live inviter decision is
    /// `MeshNetworkManager.shouldInitiateInvite`, which ranks the `sid` this transport publishes
    /// and parses. A refused dial is dropped and logged; the reason is on the admission value.
    func dial(_ peer: PeerHandle) {
        guard isRunning, let key = identities.key(for: peer) else { return }
        let admission = links.admitDial(to: key, now: Date())
        guard admission == .admit else {
            Self.logger.debug("dial refused for \(key.rawValue, privacy: .public)")
            return
        }
        startOutboundTunnel(to: key)
    }

    /// Sends one frame to a peer. `.reliable` rides the control stream; `.bestEffort` rides a QUIC
    /// datagram when the payload fits one, and falls back to the control stream when it does not —
    /// delivering a best-effort frame reliably is always allowed, dropping it silently is not.
    func send(_ data: Data, to peer: PeerHandle, mode: PeerDeliveryMode) async throws {
        guard let key = identities.key(for: peer), let tunnel = tunnels[key] else {
            throw PeerTransportError.unexpectedState
        }
        guard data.count <= Self.maxInboundWireBytes else {
            throw PeerTransportError.sendFailed(
                reason: MeshTransportError.oversizedFrame(byteCount: data.count).diagnosticDescription
            )
        }
        if mode == .bestEffort, let datagrams = tunnel.datagrams,
           data.count <= datagrams.parent.usableDatagramFrameSize {
            try await sendDatagram(data, over: datagrams)
            return
        }
        guard let stream = tunnel.controlStream else {
            throw PeerTransportError.sendFailed(reason: MeshTransportError.noControlStream.diagnosticDescription)
        }
        try await sendFramed(data, over: stream)
    }

    // MARK: - Test seam

    /// How many endpoints the session is holding an identity for. The read that lets a test assert
    /// ``stop()`` left nothing behind rather than inferring it from a re-mint.
    var trackedEndpointCountForTesting: Int { identities.trackedCount }

    /// The link table, so a test can assert what the radio decided without driving real radios.
    var linkTableForTesting: MeshLinkTable { links }

    /// How many introduction nonces the session is holding — the read that lets a test assert
    /// ``stop()`` dropped the replay cache with everything else.
    var trackedIntroductionNonceCountForTesting: Int { introductionNonces.trackedCount }

    /// How many inbound connections are mid-introduction, holding no roster slot.
    var pendingInboundCountForTesting: Int { pendingInbound.count }

    /// Books a pending inbound connection behind a stub task, so the introduction deadline can be
    /// driven at tier 1. The sweep cancels the stub exactly as it would a real connection's task.
    func bookPendingInboundForTesting(_ key: MeshLinkKey, startedAt: Date) {
        pendingInbound[key] = PendingInbound(startedAt: startedAt, task: Task {})
    }

    /// Runs the pending-introduction sweep the shared poll runs, at a caller-chosen `now`.
    func expirePendingInboundForTesting(now: Date) {
        expirePendingInbound(now: now)
    }
}

// MARK: - Listener and browser

private extension NetworkMeshSession {

    /// Brings up the QUIC listener over Bonjour and starts serving inbound tunnels.
    func startListener() throws {
        guard let tlsIdentity else { throw MeshTransportError.tlsIdentityUnavailable }
        let listener = try NetworkListener(
            for: .bonjour(
                name: instanceName,
                type: Self.friendServiceType,
                txtRecord: NWTXTRecord(advertisedFields)
            ),
            using: Self.listenerParameters(identity: tlsIdentity.identity)
        ).newConnectionLimit(MeshLinkTable.maxConcurrentLinks)
        self.listener = listener
        listener.onStateUpdate { [weak self] _, state in
            Task { @MainActor in self?.listenerStateChanged(state) }
        }
        listener.onServiceRegistrationUpdate { [weak self] _, change in
            Task { @MainActor in self?.listenerRegistrationChanged(change) }
        }
        listenerTask = Task { @MainActor [weak self, listener] in
            do {
                try await listener.run { connection in
                    self?.acceptInbound(connection)
                }
            } catch {
                self?.report("The QUIC listener stopped: \(error)")
            }
        }
    }

    /// Starts browsing once the listener is both ready and advertised — browsing earlier finds
    /// peers this device cannot yet be found by, which is how one side of a pair ends up dialing
    /// into a service that is not registered.
    func startBrowser() {
        guard isRunning, browser == nil else { return }
        let browser = NetworkBrowser(
            for: .bonjour(Self.friendServiceType, includeTxtRecord: true),
            using: Self.connectionParameters().parameters
        )
        self.browser = browser
        browser.onStateUpdate { [weak self] _, state in
            Task { @MainActor in self?.browserStateChanged(state) }
        }
        browserTask = Task { @MainActor [weak self, browser] in
            do {
                try await browser.run { endpoints in
                    self?.observe(endpoints)
                }
            } catch {
                self?.report("The Bonjour browser stopped: \(error)")
            }
        }
    }

    func listenerStateChanged(_ state: NetworkListener<QUIC>.State) {
        guard isRunning else { return }
        switch state {
        case .ready:
            listenerIsReady = true
            startBrowserWhenReady()
        case .waiting(let error):
            Self.logger.debug("QUIC listener waiting: \(error.localizedDescription, privacy: .public)")
        case .failed(let error):
            report("The QUIC listener failed: \(error.localizedDescription)")
        case .setup, .cancelled:
            break
        @unknown default:
            break
        }
    }

    func listenerRegistrationChanged(_ change: NetworkListener<QUIC>.ServiceRegistrationChange) {
        guard isRunning else { return }
        switch change {
        case .add:
            listenerIsAdvertised = true
            startBrowserWhenReady()
        case .remove:
            listenerIsAdvertised = false
        @unknown default:
            break
        }
    }

    func startBrowserWhenReady() {
        guard listenerIsReady, listenerIsAdvertised else { return }
        startBrowser()
    }

    func browserStateChanged(_ state: NetworkBrowser<Bonjour>.State) {
        guard isRunning else { return }
        switch state {
        case .failed(let error):
            report("The Bonjour browser failed: \(error.localizedDescription)")
        case .waiting(let error):
            Self.logger.debug("Bonjour browser waiting: \(error.localizedDescription, privacy: .public)")
        case .ready, .setup, .cancelled:
            break
        @unknown default:
            break
        }
    }

    /// QUIC parameters for an outbound connection. No local identity: only the listener side
    /// presents a certificate, and neither side validates one — see ``EphemeralMeshTLSIdentity``.
    static func connectionParameters() -> NWParametersBuilder<QUIC> {
        let parameters = NWParametersBuilder<QUIC>.parameters {
            QUIC(alpn: [alpn])
                .tls.certificateValidator { _, _ in true }
                .tls.peerAuthentication(.none)
                .maxUDPPayloadSize(udpPayloadSize)
                .maxDatagramFrameSize(datagramFrameSize)
        }.prohibitedInterfaceTypes([.cellular])
        guard includesPeerToPeer else { return parameters }
        return parameters.peerToPeerIncluded(true)
    }

    /// QUIC parameters for the listener, presenting this session's ephemeral identity.
    static func listenerParameters(identity: sec_identity_t) -> NWParametersBuilder<QUIC> {
        let parameters = NWParametersBuilder<QUIC>.parameters {
            QUIC(alpn: [alpn])
                .tls.localIdentity(identity)
                .tls.certificateValidator { _, _ in true }
                .tls.peerAuthentication(.none)
                .maxUDPPayloadSize(udpPayloadSize)
                .maxDatagramFrameSize(datagramFrameSize)
        }.prohibitedInterfaceTypes([.cellular])
        guard includesPeerToPeer else { return parameters }
        return parameters.peerToPeerIncluded(true)
    }
}

// MARK: - Discovery

private extension NetworkMeshSession {

    /// One browse result set: refresh what is known, announce arrivals, announce departures.
    ///
    /// The local advertisement is filtered out by instance name — the same self-exclusion the
    /// presence radio does, and necessary because a device browses its own Bonjour registration.
    func observe(_ endpoints: [Bonjour.Endpoint]) {
        guard isRunning else { return }
        let now = Date()
        let bounded = endpoints.prefix(MeshSessionIdentityMap.maxTrackedEndpoints)
        var seen: Set<MeshLinkKey> = []
        for endpoint in bounded where endpoint.name != instanceName {
            let key = MeshLinkKey(endpoint.id)
            seen.insert(key)
            noteBrowsed(endpoint, key: key, at: now)
        }
        for key in Array(browsedEndpoints.keys) where !seen.contains(key) {
            noteLost(key)
        }
    }

    /// Records a browsed endpoint and announces it when it is new or its advertisement changed.
    ///
    /// Re-announcing on change is load-bearing: a Bonjour peer is routinely seen before its TXT
    /// record arrives, so the first sighting can carry no `sid` at all and the owner's tie-break
    /// would be stuck with "unrankable" forever if the late record never reached it.
    func noteBrowsed(_ endpoint: Bonjour.Endpoint, key: MeshLinkKey, at now: Date) {
        let previous = links.cachedEndpoint(key)?.advertisement
        let advertisement = MeshLinkAdvertisement.advertisement(from: endpoint.txtRecord.dictionary)
        browsedEndpoints[key] = endpoint
        links.remember(MeshEndpointRecord(
            key: key,
            instanceName: endpoint.name,
            advertisement: advertisement,
            lastSeenAt: now
        ))
        guard previous != advertisement else { return }
        onPeerDiscovered?(handle(for: key))
    }

    /// Drops an endpoint that left the browse results. Its cache entry survives only while a tunnel
    /// to it does — that is the endpoint cache doing its job, keeping a re-dial possible without
    /// waiting for Bonjour to find the peer again.
    func noteLost(_ key: MeshLinkKey) {
        let peer = handle(for: key)
        browsedEndpoints.removeValue(forKey: key)
        if tunnels[key] == nil { links.forget(key) }
        onPeerLost?(peer)
    }

    /// The session-stable handle for an endpoint.
    ///
    /// `advertisedFingerprint` is always nil, matching ``MeshLinkAdvertisement/withheldKeys``: this
    /// radio publishes no `fp` and believes no inbound one, so a handle from it never carries a
    /// fingerprint claim. `displayHint` is the peer's random Bonjour instance name — a hint, never
    /// a name shown to anyone; mesh display names arrive inside the signed identity introduction.
    func handle(for key: MeshLinkKey) -> PeerHandle {
        let identity = identities.identity(for: key)
        let record = links.cachedEndpoint(key)
        return PeerHandle(
            id: identity.id,
            displayHint: record?.instanceName ?? key.rawValue,
            discoveryInfo: record?.advertisement,
            advertisedFingerprint: nil,
            endpoint: identity.endpoint
        )
    }
}

// MARK: - Tunnels

private extension NetworkMeshSession {

    /// The heartbeat datagram's fixed payload. A frozen wire token, never localized, and filtered
    /// out of the inbound path so it never reaches a decoder as an app frame.
    static var heartbeatDatagram: Data { Data("fernlet-mesh-heartbeat".utf8) }

    /// Opens an outbound QUIC tunnel to a cached endpoint.
    ///
    /// The dial admission has already been booked by the caller; this only builds the connection
    /// and the task that owns it. Cancelling that task is how the connection is torn down — the
    /// TN3213 connection has no `cancel()` of its own, its lifetime is its running task's.
    func startOutboundTunnel(to key: MeshLinkKey) {
        guard let endpoint = browsedEndpoints[key] else {
            handleDialFailure(key, reason: "no cached endpoint for a due re-dial")
            return
        }
        let connection = NetworkConnection(to: endpoint, using: Self.connectionParameters()).start()
        let channel = prepareChannel(for: key)
        replaceTunnel(at: key, with: Tunnel(peer: channel.peer, channel: channel))
        tunnels[key]?.task = Task { @MainActor [weak self] in
            await self?.runInitiator(connection, key: key)
        }
    }

    /// Takes an inbound QUIC connection as *pending*: nothing is admitted, no channel exists, and
    /// no roster slot is held until the peer has proved who it is.
    ///
    /// The admission decision moved into ``admitVerifiedInbound(_:pendingKey:)``, behind the signed
    /// channel introduction, which is what closes item 5's named residual. Two things were wrong
    /// with deciding here: the peer had said nothing yet, so the tie-break had no `sid` to rank and
    /// fell through to ``MeshDialPreference/unranked`` on every inbound tunnel; and an
    /// unauthenticated connection took a roster seat, so eight strangers could fill an eight-member
    /// mesh. Both are answered by waiting: a pending connection holds one of
    /// ``maxPendingInboundTunnels`` instead, and takes a real slot only once it is verified.
    func acceptInbound(_ connection: NetworkConnection<QUIC>) {
        guard isRunning else { return }
        let key = MeshLinkKey(connection.id)
        guard pendingInbound[key] == nil, pendingInbound.count < Self.maxPendingInboundTunnels else {
            Self.logger.debug("inbound QUIC tunnel refused pre-introduction for \(key.rawValue, privacy: .public)")
            return
        }
        pendingInbound[key] = PendingInbound(
            startedAt: Date(),
            task: Task { @MainActor [weak self] in
                await self?.runResponder(connection, pendingKey: key)
            }
        )
    }

    /// Resolves a verified inbound peer to the link key its tunnel should live under, and books the
    /// admission — the accept path, now unreachable without a ``MeshVerifiedPeer``.
    ///
    /// The verified `sid` does two jobs. It resolves the connection to the browsed advertisement it
    /// came from (see ``MeshLinkTable/key(advertisingSessionID:)``), so an inbound tunnel and an
    /// outbound dial to the same peer collide under one key instead of coexisting; and it ranks the
    /// pair, so duplicate-tunnel suppression makes the real ``MeshDialPreference`` decision rather
    /// than admitting both sides.
    ///
    /// - Returns: the key to build the tunnel under, or nil when the table refused it.
    func admitVerifiedInbound(_ verified: MeshVerifiedPeer, pendingKey: MeshLinkKey) -> MeshLinkKey? {
        let key = links.key(advertisingSessionID: verified.sessionID) ?? pendingKey
        let admission = links.admitInbound(
            from: key,
            localSessionID: advertisedFields[MeshLinkAdvertisement.sessionIDKey] ?? "",
            peerSessionID: verified.sessionID,
            now: Date()
        )
        guard admission == .admit else {
            Self.logger.debug("inbound QUIC tunnel refused for \(key.rawValue, privacy: .public)")
            return nil
        }
        return key
    }

    /// Drops a pending inbound connection, cancelling the task that owns it. Idempotent, and safe
    /// to call from inside that task — cancelling itself is how the connection is closed.
    func dropPendingInbound(_ key: MeshLinkKey) {
        pendingInbound.removeValue(forKey: key)?.task.cancel()
    }

    /// Drops every inbound connection that has outstayed
    /// ``NetworkMeshSession/introductionDeadlineSeconds`` without finishing its introduction.
    /// Bounded by ``maxPendingInboundTunnels``, and driven by the shared poll (Power of 10 rule 2).
    func expirePendingInbound(now: Date) {
        let expired = pendingInbound
            .filter { now.timeIntervalSince($0.value.startedAt) > Self.introductionDeadlineSeconds }
            .keys
        for key in expired {
            Self.logger.debug("inbound QUIC tunnel timed out mid-introduction for \(key.rawValue, privacy: .public)")
            dropPendingInbound(key)
        }
    }

    /// The channel for an endpoint, reusing the live one so a reconnect does not orphan the
    /// publishers an owner is already subscribed to.
    func prepareChannel(for key: MeshLinkKey) -> NetworkPeerChannel {
        if let existing = tunnels[key]?.channel { return existing }
        return NetworkPeerChannel(peer: handle(for: key), session: self)
    }

    /// Dialing side: open the control stream, run the signed channel introduction, and only then
    /// read app frames.
    ///
    /// An introduction failure ends the tunnel through the dial budget, not as a live disconnect: no
    /// control stream was ever recorded, so ``endTunnel(_:reason:)`` charges it as a failed dial and
    /// the three-attempt budget bounds how often this side re-offers itself to a peer that refuses
    /// it. A cancelled task returns silently — cancellation is a deliberate teardown (``stop()``, or
    /// this dial losing the duplicate-tunnel tie-break), never a failure to book.
    func runInitiator(_ connection: NetworkConnection<QUIC>, key: MeshLinkKey) async {
        do {
            let stream = try await connection.openStream()
            let datagrams = try await connection.datagrams
            guard let verified = await introduce(role: .initiator, over: connection, stream: stream) else {
                guard !Task.isCancelled else { return }
                endTunnel(key, reason: "The outbound QUIC tunnel failed its signed channel introduction.")
                return
            }
            activate(key, stream: stream, datagrams: datagrams, verified: verified)
            try await receiveFrames(for: key, from: stream)
        } catch {
            guard !Task.isCancelled else { return }
            endTunnel(key, reason: "The outbound QUIC tunnel ended: \(error.localizedDescription)")
        }
    }

    /// Listening side: serve the peer's control stream. Only the first inbound stream is served;
    /// later ones (per-transfer photo streams, plan §7.1) have no handler yet and are declined
    /// rather than silently treated as control.
    func runResponder(_ connection: NetworkConnection<QUIC>, pendingKey: MeshLinkKey) async {
        do {
            try await connection.inboundStreams { stream in
                guard self.pendingInbound[pendingKey] != nil else { return }
                let datagrams = try await connection.datagrams
                await self.serveInbound(connection, stream: stream, datagrams: datagrams, pendingKey: pendingKey)
            }
        } catch {
            guard !Task.isCancelled else { return }
            dropPendingInbound(pendingKey)
        }
    }

    /// Runs the introduction on an inbound connection and, only if it succeeds and the table admits
    /// the verified peer, promotes it from pending to a real tunnel.
    ///
    /// Every early return drops the pending connection whole: no channel is built, no handle is
    /// minted for an owner, and `links` is never told a `sid`. That is the "no leakage" property —
    /// it holds by construction, because everything downstream needs a ``MeshVerifiedPeer`` this
    /// path does not have.
    func serveInbound(
        _ connection: NetworkConnection<QUIC>,
        stream: Network.QUIC.Stream<QUICStream>,
        datagrams: Network.QUIC.Datagrams<QUICDatagram>,
        pendingKey: MeshLinkKey
    ) async {
        guard let verified = await introduce(role: .responder, over: connection, stream: stream),
              pendingInbound[pendingKey] != nil,
              let key = admitVerifiedInbound(verified, pendingKey: pendingKey),
              let owning = pendingInbound.removeValue(forKey: pendingKey) else {
            dropPendingInbound(pendingKey)
            return
        }
        let channel = prepareChannel(for: key)
        replaceTunnel(at: key, with: Tunnel(peer: channel.peer, channel: channel, task: owning.task))
        activate(key, stream: stream, datagrams: datagrams, verified: verified)
        do {
            try await receiveFrames(for: key, from: stream)
        } catch {
            guard !Task.isCancelled else { return }
            endTunnel(key, reason: "The inbound QUIC tunnel ended: \(error.localizedDescription)")
        }
    }

    /// Installs a tunnel, cancelling whatever held that key before it.
    ///
    /// The other half of duplicate-tunnel suppression: when the table admits an inbound tunnel for a
    /// key this side was dialing, ``MeshLinkTable/admitInbound(from:preference:now:)`` says the peer
    /// won the tie-break, and this is where the losing outbound attempt is actually abandoned. The
    /// cancelled task returns without booking anything, because both its failure paths check
    /// `Task.isCancelled` first.
    private func replaceTunnel(at key: MeshLinkKey, with tunnel: Tunnel) {
        if let previous = tunnels.removeValue(forKey: key) {
            previous.task?.cancel()
            previous.datagramTask?.cancel()
        }
        tunnels[key] = tunnel
    }

    /// Marks a tunnel live: record its stream, datagram flow and verified peer, start its heartbeat
    /// and its datagram reader, and hand the channel to the owner.
    ///
    /// Only ever called with a ``MeshVerifiedPeer``, which is what makes "no app frame crosses
    /// before the introduction" structural rather than a matter of call order: the control stream is
    /// recorded here, ``send(_:to:mode:)`` refuses without one, and both receive loops start here.
    ///
    /// `notifyConnected()` is deliberately NOT called here. The owner's `onPeerChannelReady` hook
    /// creates the coordinator and awaits its `begin()`, and publishing `.connected` before that
    /// completes is what put the MC handshake into the wrong branch — the channel's owner makes the
    /// call once `begin()` returns. Same contract, same reason.
    func activate(
        _ key: MeshLinkKey,
        stream: Network.QUIC.Stream<QUICStream>,
        datagrams: Network.QUIC.Datagrams<QUICDatagram>,
        verified: MeshVerifiedPeer
    ) {
        guard var tunnel = tunnels[key] else { return }
        let now = Date()
        tunnel.controlStream = stream
        tunnel.datagrams = datagrams
        tunnel.verified = verified
        tunnel.datagramTask = Task { @MainActor [weak self] in
            await self?.receiveDatagrams(for: key, from: datagrams)
        }
        tunnels[key] = tunnel
        links.noteReady(key, now: now)
        heartbeats.start(key, now: now)
        onPeerVerified?(tunnel.peer, verified)
        onPeerChannelReady?(tunnel.channel)
    }

    /// Reads length-framed app frames off the control stream until the connection ends or the
    /// bounded frame budget is spent.
    ///
    /// Falling out of the loop **throws** rather than returning: a receive loop that simply stopped
    /// would leave a tunnel that still reads as connected and delivers nothing, which is the silent
    /// failure the bound exists to avoid rather than to cause.
    func receiveFrames(for key: MeshLinkKey, from stream: Network.QUIC.Stream<QUICStream>) async throws {
        for _ in 0..<Self.maxInboundFramesPerConnection {
            guard !Task.isCancelled, tunnels[key] != nil else { return }
            let header = try await stream.receive(exactly: NetworkMeshWire.headerByteCount).content
            let length = try NetworkMeshWire.payloadLength(from: header, ceiling: Self.maxInboundWireBytes)
            let payload = try await stream.receive(exactly: length).content
            tunnels[key]?.channel.receive(payload, at: Date())
        }
        throw MeshTransportError.frameBudgetSpent
    }

    /// Reads datagrams: heartbeats are consumed here, everything else is a best-effort app frame.
    ///
    /// An oversized datagram is dropped rather than fatal — never disconnect at this layer, or any
    /// peer could end any session with one malformed frame. Same rule the MC transport floor uses.
    func receiveDatagrams(
        for key: MeshLinkKey,
        from datagrams: Network.QUIC.Datagrams<QUICDatagram>
    ) async {
        for _ in 0..<Self.maxInboundFramesPerConnection {
            guard !Task.isCancelled, tunnels[key] != nil else { return }
            do {
                let payload = try await datagrams.receive().content
                guard payload != Self.heartbeatDatagram else { continue }
                guard payload.count <= Self.maxInboundWireBytes else {
                    FernletAuditLog.log(
                        "mesh.quic.droppedOversizedDatagram",
                        context: ["bytes": "\(payload.count)"]
                    )
                    continue
                }
                tunnels[key]?.channel.receive(payload, at: Date())
            } catch {
                return
            }
        }
        endTunnel(key, reason: MeshTransportError.frameBudgetSpent.diagnosticDescription)
    }

    /// Ends a tunnel, choosing between "the dial failed" and "a live link dropped" by whether the
    /// control stream ever came up. Charging a disconnect to the dial budget is how a peer that
    /// reconnects a few times would become permanently undialable.
    func endTunnel(_ key: MeshLinkKey, reason: String) {
        heartbeats.stop(key)
        guard let tunnel = tunnels.removeValue(forKey: key) else { return }
        tunnel.task?.cancel()
        tunnel.datagramTask?.cancel()
        guard tunnel.controlStream != nil else {
            handleDialFailure(key, reason: reason)
            return
        }
        links.noteClosed(key)
        tunnel.channel.notifyDisconnected(reason: reason)
        onPeerDisconnected?(tunnel.peer, reason)
    }

    /// Books a failed dial attempt and reports the give-up. The retry itself is not scheduled here:
    /// the shared poll picks it up from ``MeshLinkTable/dueRetries(now:)``, so a retry can never
    /// outlive the table that authorised it.
    func handleDialFailure(_ key: MeshLinkKey, reason: String) {
        switch links.noteDialFailed(key, now: Date()) {
        case .retry(let attempt, _):
            Self.logger.debug("QUIC dial attempt \(attempt, privacy: .public) queued after: \(reason, privacy: .public)")
        case .giveUp(let attempts):
            report("The QUIC tunnel gave up after \(attempts) attempts: \(reason)")
        }
    }
}

// MARK: - Signed channel introduction

private extension NetworkMeshSession {

    /// Runs plan §7.2's mutually-signed, exporter-bound channel introduction over a fresh control
    /// stream, and returns the peer it authenticated.
    ///
    /// **Who sends when.** The initiator sends its hello, then the responder sends its. Both then
    /// derive the same transcript and sign it. The responder *receives and verifies* the initiator's
    /// signature before sending its own, so it never signs for a peer it has already refused; the
    /// initiator necessarily sends first, and what it sends is worthless anywhere else because the
    /// transcript is bound to this tunnel's TLS exporter secret.
    ///
    /// - Returns: the verified peer, or nil — which the caller must treat as a teardown. Every
    ///   failure is reported with its own frozen-English reason: silence here would be
    ///   indistinguishable from a network fault, and this is the surface that says "that peer is not
    ///   on your roster" rather than "it didn't connect".
    func introduce(
        role: MeshChannelRole,
        over connection: NetworkConnection<QUIC>,
        stream: Network.QUIC.Stream<QUICStream>
    ) async -> MeshVerifiedPeer? {
        guard let authority = introductionAuthority else {
            report("The QUIC transport has no introduction authority, so no peer can be authenticated.")
            return nil
        }
        guard let binding = Self.channelBindingHash(for: connection) else {
            report("The QUIC transport could not derive a TLS exporter binding for this tunnel.")
            return nil
        }
        var exchange = MeshChannelIntroductionExchange(
            role: role,
            localHello: localHello(from: authority)
        )
        do {
            let peerHello = try await exchangeHellos(role: role, local: exchange.localHello, over: stream)
            if let rejection = exchange.receive(
                peerHello, roster: authority.roster, nonces: &introductionNonces
            ) {
                report("A QUIC tunnel was refused: \(rejection.diagnosticDescription)")
                return nil
            }
            guard let transcript = exchange.bind(channelBindingHash: binding) else {
                report("The QUIC transport could not derive a channel-introduction transcript.")
                return nil
            }
            let signed = MeshChannelIntroduction(
                channelBindingHash: binding,
                signature: try authority.signChannelIntroduction(transcript)
            )
            return try await settle(exchange, role: role, signed: signed, over: stream)
        } catch {
            report("A QUIC channel introduction did not complete: \(error.localizedDescription)")
            return nil
        }
    }

    /// This device's half of the hello. The `sid` is the one it advertises, so a peer can match this
    /// tunnel to the advertisement it browsed.
    func localHello(from authority: any MeshIntroductionAuthority) -> MeshChannelHello {
        MeshChannelHello(
            protocolVersion: MeshChannelIntroductionFormat.protocolVersion,
            meshID: authority.meshID,
            epochRef: authority.epochRef,
            signingPublicKey: authority.localSigningPublicKey,
            nonce: MeshChannelIntroductionFormat.randomNonce(),
            sessionID: advertisedFields[MeshLinkAdvertisement.sessionIDKey] ?? ""
        )
    }

    /// Exchanges hellos in the order the role fixes: the dialer speaks first.
    func exchangeHellos(
        role: MeshChannelRole,
        local: MeshChannelHello,
        over stream: Network.QUIC.Stream<QUICStream>
    ) async throws -> MeshChannelHello {
        guard role == .initiator else {
            let peer = try await receiveIntroductionFrame(MeshChannelHello.self, from: stream)
            try await sendIntroductionFrame(local, over: stream)
            return peer
        }
        try await sendIntroductionFrame(local, over: stream)
        return try await receiveIntroductionFrame(MeshChannelHello.self, from: stream)
    }

    /// Exchanges signed introductions and reports the verdict. The responder verifies before it
    /// signs its half onto the wire.
    func settle(
        _ exchange: MeshChannelIntroductionExchange,
        role: MeshChannelRole,
        signed: MeshChannelIntroduction,
        over stream: Network.QUIC.Stream<QUICStream>
    ) async throws -> MeshVerifiedPeer? {
        let outcome: MeshChannelIntroductionOutcome
        if role == .initiator {
            try await sendIntroductionFrame(signed, over: stream)
            outcome = exchange.review(
                try await receiveIntroductionFrame(MeshChannelIntroduction.self, from: stream)
            )
        } else {
            outcome = exchange.review(
                try await receiveIntroductionFrame(MeshChannelIntroduction.self, from: stream)
            )
            if outcome.verifiedPeer != nil {
                try await sendIntroductionFrame(signed, over: stream)
            }
        }
        guard let peer = outcome.verifiedPeer else {
            if case .rejected(let rejection) = outcome {
                report("A QUIC tunnel was refused: \(rejection.diagnosticDescription)")
            }
            return nil
        }
        return peer
    }

    /// SHA-256 of this connection's TLS exporter secret — the value that is equal at the two ends of
    /// one live tunnel and nowhere else.
    ///
    /// The label is the reviewed registry constant `KeyDerivation.meshTLSExporterV1`, never a
    /// literal, and deliberately **not** the DEBUG probe's `meshProbeTLSExporterV1`: two builds
    /// deriving the same secret from the same connection would make the spike a signing oracle for
    /// the shipping introduction. `CryptographicDomainSeparationTests` pins the two apart.
    static func channelBindingHash(for connection: NetworkConnection<QUIC>) -> Data? {
        let label = FernletCryptoPurpose.KeyDerivation.meshTLSExporterV1.rawValue
        let secret = label.withCString { pointer in
            sec_protocol_metadata_create_secret(
                connection.securityProtocolMetadata,
                label.utf8.count,
                pointer,
                MeshChannelIntroductionFormat.channelBindingByteCount
            )
        }
        guard let secret else { return nil }
        return Data(SHA256.hash(data: Data(secret as DispatchData)))
    }

    /// Writes one length-framed JSON handshake frame.
    func sendIntroductionFrame(
        _ value: some Encodable,
        over stream: Network.QUIC.Stream<QUICStream>
    ) async throws {
        let payload = try JSONEncoder().encode(value)
        guard payload.count <= MeshChannelIntroductionFormat.maxFrameByteCount else {
            throw MeshTransportError.oversizedFrame(byteCount: payload.count)
        }
        try await stream.send(NetworkMeshWire.header(for: payload.count))
        try await stream.send(payload)
    }

    /// Reads one length-framed JSON handshake frame, under the handshake's own small ceiling.
    ///
    /// The ceiling is ``MeshChannelIntroductionFormat/maxFrameByteCount``, not the transport's
    /// ``maxInboundWireBytes``: these bytes come from a peer that has proved nothing yet, so the
    /// only sizes it may name are handshake-sized ones.
    func receiveIntroductionFrame<T: Decodable>(
        _ type: T.Type,
        from stream: Network.QUIC.Stream<QUICStream>
    ) async throws -> T {
        let header = try await stream.receive(exactly: NetworkMeshWire.headerByteCount).content
        let length = try NetworkMeshWire.payloadLength(
            from: header,
            ceiling: MeshChannelIntroductionFormat.maxFrameByteCount
        )
        let payload = try await stream.receive(exactly: length).content
        return try JSONDecoder().decode(type, from: payload)
    }
}

// MARK: - Sending and the shared poll

private extension NetworkMeshSession {

    /// Writes one length-framed payload to a control stream.
    func sendFramed(_ payload: Data, over stream: Network.QUIC.Stream<QUICStream>) async throws {
        do {
            try await stream.send(NetworkMeshWire.header(for: payload.count))
            try await stream.send(payload)
        } catch {
            throw PeerTransportError.sendFailed(reason: error.localizedDescription)
        }
    }

    /// Writes one QUIC datagram.
    func sendDatagram(
        _ payload: Data,
        over datagrams: Network.QUIC.Datagrams<QUICDatagram>
    ) async throws {
        do {
            try await datagrams.send(payload)
        } catch {
            throw PeerTransportError.sendFailed(reason: error.localizedDescription)
        }
    }

    /// Starts the one timer this radio owns.
    ///
    /// One poll for every link, rather than a timer per link per duty: N self-rescheduling timers is
    /// N ways for a closure to outlive what it was scheduled for, and this codebase has been bitten
    /// by exactly that. Bounded at ``maxPollTicks`` (Power of 10 rule 2) — six hours at 1 Hz, the
    /// session ceiling plan §3 sets.
    func startPoll() {
        guard pollTask == nil else { return }
        pollTask = Task { @MainActor [weak self] in
            for _ in 0..<NetworkMeshSession.maxPollTicks {
                do {
                    try await Task.sleep(for: .seconds(NetworkMeshSession.pollIntervalSeconds))
                } catch {
                    return
                }
                guard let self, self.isRunning else { return }
                self.tick(now: Date())
            }
        }
    }

    /// One tick: re-dial what is due, beat what is due. Both lists are capped by the roster cap, so
    /// both loops are bounded by construction.
    func tick(now: Date) {
        expirePendingInbound(now: now)
        for key in links.dueRetries(now: now) {
            guard browsedEndpoints[key] != nil else {
                links.forget(key)
                continue
            }
            guard links.admitDial(to: key, now: now) == .admit else { continue }
            startOutboundTunnel(to: key)
        }
        for key in heartbeats.due(now: now) {
            heartbeats.noteSent(key, now: now)
            sendHeartbeat(to: key)
        }
    }

    /// Sends one heartbeat datagram, ending the tunnel if the write fails — a link that cannot
    /// carry 22 bytes is not a link.
    func sendHeartbeat(to key: MeshLinkKey) {
        guard let datagrams = tunnels[key]?.datagrams else { return }
        Task { @MainActor [weak self] in
            do {
                try await datagrams.send(NetworkMeshSession.heartbeatDatagram)
            } catch {
                self?.endTunnel(key, reason: "A heartbeat could not be sent: \(error.localizedDescription)")
            }
        }
    }

    /// Logs a diagnostic and hands it to the owner. Frozen English: this is the surface that makes
    /// a missing `NSBonjourServices` entry or a declined Local Network prompt visible instead of
    /// silently dead, and it is read by a developer, not a user.
    func report(_ message: String) {
        Self.logger.error("\(message, privacy: .public)")
        onTransportError?(message)
    }
}
