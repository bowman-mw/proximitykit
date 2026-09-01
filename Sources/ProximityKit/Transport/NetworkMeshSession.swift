import Combine
import Foundation
import Network
import os
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
/// validation is *not* the authentication decision here. Authentication is the signed identity
/// introduction the coordinator already exchanges over the connection, and, once P2 item 7 lands,
/// the TLS-exporter-bound signed channel introduction on top of it. `prohibitedInterfaceTypes` is
/// `[.cellular]` on every listener, browser and connection, always: it is what turns the
/// serverless/no-internet claim from an aspiration into something the OS enforces.
///
/// **Not yet wired to `MeshNetworkManager`.** An inbound tunnel cannot be matched to a browsed
/// advertisement until the peer says who it is, which is what item 7's introduction carries — see
/// ``acceptInbound(_:)``. Until then this radio runs standalone.
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
        /// Owns the connection: cancelling it is how the connection is torn down.
        var task: Task<Void, Never>?
        /// Owns the inbound datagram reader.
        var datagramTask: Task<Void, Never>?
    }

    private var links = MeshLinkTable()
    private var heartbeats = MeshHeartbeatSchedule()
    private var identities = MeshSessionIdentityMap()
    private var tunnels: [MeshLinkKey: Tunnel] = [:]
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
        listenerTask?.cancel()
        browserTask?.cancel()
        pollTask?.cancel()
        listenerTask = nil
        browserTask = nil
        pollTask = nil
        listener = nil
        browser = nil
        tunnels.removeAll()
        browsedEndpoints.removeAll()
        links.removeAll()
        heartbeats.removeAll()
        identities.removeAll()
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
        tunnels[key] = Tunnel(peer: channel.peer, channel: channel)
        tunnels[key]?.task = Task { @MainActor [weak self] in
            await self?.runInitiator(connection, key: key)
        }
    }

    /// Accepts (or refuses) an inbound QUIC tunnel.
    ///
    /// **The preference is ``MeshDialPreference/unranked`` today, and that is a seam, not a
    /// shortcut.** An inbound connection's remote endpoint is a host and port; a browsed peer is a
    /// Bonjour service instance. Nothing available at accept time matches the two, so this side
    /// cannot know whether the peer it is being dialed by is one it is dialing — which is exactly
    /// the question the signed channel introduction (P2 item 7) answers, and why this radio is not
    /// yet wired to `MeshNetworkManager`. `unranked` is the safe answer in the meantime: it admits,
    /// so a mutually-dialing pair ends with a duplicate tunnel rather than none. See
    /// ``MeshDialPreference`` for why refusing on both sides is the unrecoverable direction.
    func acceptInbound(_ connection: NetworkConnection<QUIC>) {
        guard isRunning else { return }
        let key = MeshLinkKey(connection.id)
        let admission = links.admitInbound(
            from: key,
            localSessionID: advertisedFields[MeshLinkAdvertisement.sessionIDKey] ?? "",
            // Item 7's signed channel introduction is what will name the peer here.
            peerSessionID: nil,
            now: Date()
        )
        guard admission == .admit else {
            Self.logger.debug("inbound QUIC tunnel refused for \(key.rawValue, privacy: .public)")
            return
        }
        let channel = prepareChannel(for: key)
        tunnels[key] = Tunnel(peer: channel.peer, channel: channel)
        tunnels[key]?.task = Task { @MainActor [weak self] in
            await self?.runResponder(connection, key: key)
        }
    }

    /// The channel for an endpoint, reusing the live one so a reconnect does not orphan the
    /// publishers an owner is already subscribed to.
    func prepareChannel(for key: MeshLinkKey) -> NetworkPeerChannel {
        if let existing = tunnels[key]?.channel { return existing }
        return NetworkPeerChannel(peer: handle(for: key), session: self)
    }

    /// Dialing side: open the control stream, take the datagram flow, then read frames until the
    /// connection ends.
    func runInitiator(_ connection: NetworkConnection<QUIC>, key: MeshLinkKey) async {
        do {
            let stream = try await connection.openStream()
            let datagrams = try await connection.datagrams
            activate(key, stream: stream, datagrams: datagrams)
            try await receiveFrames(for: key, from: stream)
        } catch {
            endTunnel(key, reason: "The outbound QUIC tunnel ended: \(error.localizedDescription)")
        }
    }

    /// Listening side: serve the peer's control stream. Only the first inbound stream becomes the
    /// control stream; later ones (per-transfer photo streams, plan §7.1) have no handler yet and
    /// are declined rather than silently treated as control.
    func runResponder(_ connection: NetworkConnection<QUIC>, key: MeshLinkKey) async {
        do {
            try await connection.inboundStreams { stream in
                guard self.tunnels[key]?.controlStream == nil else { return }
                let datagrams = try await connection.datagrams
                self.activate(key, stream: stream, datagrams: datagrams)
                try await self.receiveFrames(for: key, from: stream)
            }
        } catch {
            endTunnel(key, reason: "The inbound QUIC tunnel ended: \(error.localizedDescription)")
        }
    }

    /// Marks a tunnel live: record its stream and datagram flow, start its heartbeat and its
    /// datagram reader, and hand the channel to the owner.
    ///
    /// `notifyConnected()` is deliberately NOT called here. The owner's `onPeerChannelReady` hook
    /// creates the coordinator and awaits its `begin()`, and publishing `.connected` before that
    /// completes is what put the MC handshake into the wrong branch — the channel's owner makes the
    /// call once `begin()` returns. Same contract, same reason.
    func activate(
        _ key: MeshLinkKey,
        stream: Network.QUIC.Stream<QUICStream>,
        datagrams: Network.QUIC.Datagrams<QUICDatagram>
    ) {
        guard var tunnel = tunnels[key] else { return }
        let now = Date()
        tunnel.controlStream = stream
        tunnel.datagrams = datagrams
        tunnel.datagramTask = Task { @MainActor [weak self] in
            await self?.receiveDatagrams(for: key, from: datagrams)
        }
        tunnels[key] = tunnel
        links.noteReady(key, now: now)
        heartbeats.start(key, now: now)
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
