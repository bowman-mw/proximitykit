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

    /// Sends one frame. A reliable payload at or above ``MeshTransferStreamTable/bulkFloorBytes``
    /// takes a per-transfer stream of its own (plan §7.1); everything else rides the tunnel's
    /// control stream or a datagram, exactly as it did before those streams existed. **No caller
    /// above this line can tell the difference**, which is the point: `MeshNetworkManager` sends a
    /// friend photo the same way over MultipeerConnectivity and over QUIC.
    func send(_ data: Data, to peer: PeerHandle, mode: PeerDeliveryMode) async throws {
        guard let session else { throw PeerTransportError.unexpectedState }
        try await session.send(data, to: peer, mode: mode)
    }

    /// Per-transfer streams open on this peer's tunnel right now, in both directions.
    ///
    /// Zero on a settled tunnel. The read exists so a test can assert that a finished transfer gave
    /// its budget slot back, rather than inferring it from a later send happening to succeed.
    var openTransferCount: Int {
        session?.openTransferCount(for: peer) ?? 0
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
/// mesh id, the epoch reference, the roster and the signing key; `MeshNetworkManager` attaches
/// itself as one through ``MeshTransportSession/attachIntroductionAuthority(_:)`` when this radio is
/// selected (P2 item 8). A session with no authority cannot authenticate anyone, so it refuses every
/// tunnel rather than admitting one unverified — as does one whose owner wired no ``invitationGate``.
///
/// **Selected, never defaulted.** `MeshTransportFactory` hands the manager a `MeshMultipeerSession`
/// on every shipping path; this radio is reachable only from an internal injection or the DEBUG-only
/// `FERNLET_MESH_TRANSPORT=quic` launch variable, and nothing about that choice is persisted.
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

    /// The QUIC stream id the control stream always has.
    ///
    /// Not a choice: RFC 9000 §2.1 assigns client-initiated bidirectional streams the ids 0, 4, 8 …
    /// in the order they are opened, and the dialing side opens exactly one stream — the control
    /// stream — before the signed introduction. So the listening side can name the control stream by
    /// its id alone, and every other inbound stream is a per-transfer stream.
    nonisolated static let controlStreamID: UInt64 = 0

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
    /// The owner's admission gate, consulted once a peer has proved who it is and before its tunnel
    /// takes a roster slot (``admitVerifiedInbound(_:pendingKey:)``).
    ///
    /// **Fail closed**, exactly like the MC advertiser's `shouldAcceptInvitation` (`?? false`): a
    /// radio nobody has wired admits nobody. It runs *after* the signed channel introduction rather
    /// than before, because there is no invitation moment here to gate — a peer dials and
    /// authenticates — so the earliest honest question is "this verified member: do you want it?".
    var invitationGate: ((PeerHandle) -> Bool)?

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
        /// Which end opened this connection. The only fact about a tunnel both devices name
        /// identically, and therefore the only one ``MeshTunnelConvergence`` can rule on.
        let role: MeshChannelRole
        var controlStream: Network.QUIC.Stream<QUICStream>?
        var datagrams: Network.QUIC.Datagrams<QUICDatagram>?
        /// The connection every per-transfer stream is opened on. Recorded at activation beside the
        /// control stream, because a bulk frame needs the *connection* and the control stream is
        /// the one object on a tunnel that cannot produce one.
        var connection: NetworkConnection<QUIC>?
        /// The identity this tunnel's peer proved in the signed channel introduction. Set once, at
        /// activation; a tunnel with no verified peer never reaches this map.
        var verified: MeshVerifiedPeer?
        /// Owns the connection: cancelling it is how the connection is torn down.
        var task: Task<Void, Never>?
        /// Owns the inbound datagram reader.
        var datagramTask: Task<Void, Never>?
        /// Owns the inbound *transfer stream* acceptor on the dialing side. The listening side has
        /// no such task: its `inboundStreams` acceptor is already running, and every stream past the
        /// control one is routed there (see ``NetworkMeshSession/runResponder(_:pendingKey:)``).
        var transferAcceptorTask: Task<Void, Never>?
        /// Which frames earn a stream of their own, and how many may be open at once. Held **in**
        /// the tunnel so a budget can never outlive the link it bounded.
        var transfers = MeshTransferStreamTable()
        /// Set once a heartbeat write to this tunnel's datagram flow has thrown. The one-shot latch
        /// ``MeshHeartbeatChannel`` reads: the designed channel is tried once per tunnel, and a
        /// tunnel that has answered "no" is never asked again. Never a reason to end the tunnel.
        var datagramWriteFailed = false

        /// Cancels every task this tunnel owns.
        ///
        /// One funnel rather than a list repeated at each teardown site: a tunnel gained a third
        /// task when per-transfer streams landed, and the five call sites that had to learn about it
        /// are exactly the shape a leak hides in.
        func cancelTasks() {
            task?.cancel()
            datagramTask?.cancel()
            transferAcceptorTask?.cancel()
        }
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
            tunnel.cancelTasks()
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
            tunnel.cancelTasks()
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

    /// Frees one peer's tunnel — the QUIC counterpart of the MC session's targeted disconnect, and
    /// best-effort in the same way: the owner's record eviction is what actually drives teardown.
    ///
    /// `notifyOwner: false` is the load-bearing half. This is an eviction the owner *asked* for, and
    /// ``endTunnel(_:cause:reason:notifyOwner:)`` fires ``onPeerDisconnected`` synchronously — so
    /// reporting it back would re-enter the owner's disconnect path from inside its own removal
    /// funnel. MC has the same shape and does not have the problem only because its `.notConnected`
    /// arrives later, on a delegate callback the owner already knows to swallow. The peer's channel
    /// still publishes `.disconnected`: the coordinator on the other end of it must see the link die.
    func disconnectPeer(_ peer: PeerHandle) {
        guard let key = identities.key(for: peer) else { return }
        endTunnel(
            key,
            cause: .localEviction,
            reason: "This peer's slot was evicted locally.",
            notifyOwner: false
        )
    }

    /// Hands a start failure to the owner's transport-error hook, with the same logging every other
    /// radio failure gets. Internal so the ``MeshTransportSession`` conformance — whose
    /// `startRadios(discoveryInfo:)` cannot throw, because the MC radio's cannot — can report one.
    func reportTransportError(_ message: String) {
        report(message)
    }

    /// Sends one frame to a peer.
    ///
    /// `.bestEffort` rides a QUIC datagram when the payload fits one. A `.reliable` frame at or above
    /// ``MeshTransferStreamTable/bulkFloorBytes`` — a friend photo, in practice — rides a stream
    /// opened for it alone, so it cannot park the rest of the tunnel behind itself. Everything else
    /// rides the control stream, in order, as it does under MultipeerConnectivity.
    ///
    /// Every fallback runs the same direction: a payload too large for a datagram, and a bulk frame
    /// with no transfer slot free, both end up on the control stream. Delivering a frame more
    /// reliably or more slowly than designed is always allowed; dropping it silently is not.
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
        if mode == .reliable, let claim = claimTransferStream(key, byteCount: data.count) {
            try await sendOverTransferStream(data, key: key, claim: claim)
            return
        }
        guard let stream = tunnel.controlStream else {
            throw PeerTransportError.sendFailed(reason: MeshTransportError.noControlStream.diagnosticDescription)
        }
        try await sendFramed(data, over: stream)
    }

    /// How many per-transfer streams are open on one peer's tunnel, outbound plus inbound.
    ///
    /// The read `NetworkPeerChannel.openTransferCount` exposes: it lets a test — and a Lane C
    /// transcript — assert that a transfer released its slot rather than infer it from a later send
    /// happening to succeed.
    func openTransferCount(for peer: PeerHandle) -> Int {
        guard let key = identities.key(for: peer), let tunnel = tunnels[key] else { return 0 }
        return tunnel.transfers.outbound.openCount + tunnel.transfers.inbound.openCount
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

    /// Which endpoints hold a tunnel right now, in sorted key order — the read that lets a test say
    /// *which* tunnel of a collapsed pair survived, not merely how many did.
    var tunnelKeysForTesting: [MeshLinkKey] {
        tunnels.keys.sorted { $0.rawValue < $1.rawValue }
    }

    /// Books a tunnel exactly as `replaceTunnel` and `activate` record one, minus the two framework
    /// objects a unit test cannot build.
    ///
    /// `verified: nil` is a tunnel mid-introduction — precisely what sits in the map at the instant
    /// the duplicate-collapse gate is asked about it. A non-nil one is an activated tunnel, holding
    /// a roster slot and a running heartbeat.
    func bookTunnelForTesting(_ key: MeshLinkKey, role: MeshChannelRole, verified: MeshVerifiedPeer?) {
        let channel = prepareChannel(for: key)
        var tunnel = Tunnel(peer: channel.peer, channel: channel, role: role)
        tunnel.verified = verified
        tunnels[key] = tunnel
        guard verified != nil else { return }
        let now = Date()
        links.noteReady(key, now: now)
        heartbeats.start(key, now: now)
    }

    /// Claims one outbound transfer slot on a booked tunnel — the **budget** half of what
    /// ``send(_:to:mode:)`` does, minus the framework connection a unit test cannot build.
    ///
    /// Same fork, same cap, same answer shape: nil means "send it on the control stream", whether
    /// because the frame is under the floor or because the direction is full.
    func claimOutboundTransferForTesting(_ key: MeshLinkKey, byteCount: Int) -> MeshTransferID? {
        guard var tunnel = tunnels[key],
              let id = tunnel.transfers.openOutbound(reliableByteCount: byteCount) else { return nil }
        tunnels[key] = tunnel
        return id
    }

    /// Releases one outbound transfer slot, exactly as ``sendOverTransferStream(_:key:claim:)``'s
    /// `defer` releases it on both the success and the failure path.
    func releaseOutboundTransferForTesting(_ key: MeshLinkKey, id: MeshTransferID) {
        tunnels[key]?.transfers.closeOutbound(id)
    }

    /// Runs the duplicate-collapse gate `activate` runs, and answers exactly what it answers: may
    /// this tunnel go live?
    func admitActivationForTesting(
        at key: MeshLinkKey,
        role: MeshChannelRole,
        verified: MeshVerifiedPeer
    ) -> Bool {
        admitActivation(at: key, role: role, verified: verified)
    }

    /// Runs the verified inbound admission, so the same-key half of the convergence can be driven
    /// through the production function rather than through its parts.
    func admitVerifiedInboundForTesting(
        _ verified: MeshVerifiedPeer,
        pendingKey: MeshLinkKey
    ) -> MeshLinkKey? {
        admitVerifiedInbound(verified, pendingKey: pendingKey)
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
    ///
    /// ``MeshHeartbeatSchedule/idleTimeoutMilliseconds`` is declared rather than defaulted, and that
    /// is the P2 item 15 fix: the framework's default idle timeout sat at roughly the heartbeat
    /// interval, so QUIC reaped every tunnel a moment before its first beat was due.
    static func connectionParameters() -> NWParametersBuilder<QUIC> {
        let parameters = NWParametersBuilder<QUIC>.parameters {
            QUIC(alpn: [alpn])
                .tls.certificateValidator { _, _ in true }
                .tls.peerAuthentication(.none)
                .idleTimeout(MeshHeartbeatSchedule.idleTimeoutMilliseconds)
                .maxUDPPayloadSize(udpPayloadSize)
                .maxDatagramFrameSize(datagramFrameSize)
        }.prohibitedInterfaceTypes([.cellular])
        guard includesPeerToPeer else { return parameters }
        return parameters.peerToPeerIncluded(true)
    }

    /// QUIC parameters for the listener, presenting this session's ephemeral identity.
    ///
    /// The idle timeout is declared on both sides deliberately: QUIC uses the **minimum** of the two
    /// endpoints' advertised `max_idle_timeout` values, so a listener left on the default would pull
    /// the negotiated timeout straight back under the heartbeat interval.
    static func listenerParameters(identity: sec_identity_t) -> NWParametersBuilder<QUIC> {
        let parameters = NWParametersBuilder<QUIC>.parameters {
            QUIC(alpn: [alpn])
                .tls.localIdentity(identity)
                .tls.certificateValidator { _, _ in true }
                .tls.peerAuthentication(.none)
                .idleTimeout(MeshHeartbeatSchedule.idleTimeoutMilliseconds)
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
        replaceTunnel(at: key, with: Tunnel(peer: channel.peer, channel: channel, role: .initiator))
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
    /// The owner's ``invitationGate`` is consulted here too, and fails closed: this is the moment
    /// the MC advertiser's `shouldAcceptInvitation` answers, moved to the earliest point on this
    /// radio where the question can honestly be asked (the peer has proved who it is; nothing has
    /// been admitted yet).
    ///
    /// A duplicate against a tunnel *already verified as the same peer* is not a refusal but a
    /// convergence question, and it is answered by the same ``MeshTunnelConvergence`` rule the
    /// cross-key case uses. It has to be: whether a peer's two connections collide under one key or
    /// land under two depends on whether that side happened to have cached the peer's TXT `sid`, and
    /// the two ends can differ on that. One rule at both sites is what stops the pair from closing
    /// one connection each and ending with none.
    ///
    /// - Returns: the key to build the tunnel under, or nil when the table or the owner refused it.
    func admitVerifiedInbound(_ verified: MeshVerifiedPeer, pendingKey: MeshLinkKey) -> MeshLinkKey? {
        let key = links.key(advertisingSessionID: verified.sessionID) ?? pendingKey
        guard invitationGate?(handle(for: key)) ?? false else {
            noteInboundRefusal("owner", key: key)
            return nil
        }
        var admission = inboundAdmission(for: verified, at: key)
        if case .refusedDuplicateTunnel = admission, yieldSameKeyDuplicate(at: key, to: verified) {
            admission = inboundAdmission(for: verified, at: key)
        }
        guard admission == .admit else {
            noteInboundRefusal("\(admission)", key: key)
            return nil
        }
        return key
    }

    /// The single place the link table is asked about an inbound tunnel, so the `sid` that drives
    /// duplicate suppression can only ever come off a ``MeshVerifiedPeer``.
    func inboundAdmission(for verified: MeshVerifiedPeer, at key: MeshLinkKey) -> MeshLinkAdmission {
        links.admitInbound(
            from: key,
            localSessionID: localSessionID,
            peerSessionID: verified.sessionID,
            now: Date()
        )
    }

    /// The `sid` this session advertises, which is also the one its hello carries — one spelling, so
    /// the value the peer ranks us by and the value we rank ourselves by cannot drift apart.
    var localSessionID: String {
        advertisedFields[MeshLinkAdvertisement.sessionIDKey] ?? ""
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
    /// control stream was ever recorded, so ``endTunnel(_:cause:reason:notifyOwner:)`` charges it as a failed dial and
    /// the three-attempt budget bounds how often this side re-offers itself to a peer that refuses
    /// it. A cancelled task returns silently — cancellation is a deliberate teardown (``stop()``, or
    /// this dial losing the duplicate-tunnel tie-break), never a failure to book.
    func runInitiator(_ connection: NetworkConnection<QUIC>, key: MeshLinkKey) async {
        do {
            let stream = try await connection.openStream()
            let datagrams = try await connection.datagrams
            guard let verified = await introduce(role: .initiator, over: connection, stream: stream) else {
                guard !Task.isCancelled else { return }
                endTunnel(
                    key,
                    cause: .introductionFailed,
                    reason: "The outbound QUIC tunnel failed its signed channel introduction."
                )
                return
            }
            activate(key, connection: connection, stream: stream, datagrams: datagrams, verified: verified)
            try await receiveFrames(for: key, from: stream)
        } catch {
            guard !Task.isCancelled else { return }
            endTunnel(
                key,
                cause: .controlStreamEnded,
                reason: "The outbound QUIC tunnel ended: \(error.localizedDescription)"
            )
        }
    }

    /// Listening side: serve the peer's control stream, and every later stream as a transfer.
    ///
    /// **The control stream is the peer's stream 0, and only ever that.** RFC 9000 §2.1 numbers
    /// client-initiated bidirectional streams 0, 4, 8 …, and the dialing side opens exactly one
    /// stream before the signed introduction — so `streamID == 0` names the control stream without a
    /// latch, and cannot be confused by a transfer that arrives while the introduction is still
    /// running. Anything else is a per-transfer stream (plan §7.1), which closes item 5's named
    /// residual: those streams used to be dropped for want of a handler.
    ///
    /// The handler for stream 0 blocks for the tunnel's whole life, and that is fine: this framework
    /// runs `inboundStreams` handlers concurrently, one task per stream. Measured, not assumed — a
    /// loopback QUIC pair delivered stream 4 to a handler while stream 0's handler was still parked
    /// in its receive loop.
    func runResponder(_ connection: NetworkConnection<QUIC>, pendingKey: MeshLinkKey) async {
        do {
            try await connection.inboundStreams { stream in
                guard stream.streamID == Self.controlStreamID else {
                    await self.serveTransferStream(stream, on: connection)
                    return
                }
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
        replaceTunnel(
            at: key,
            with: Tunnel(peer: channel.peer, channel: channel, role: .responder, task: owning.task)
        )
        activate(key, connection: connection, stream: stream, datagrams: datagrams, verified: verified)
        do {
            try await receiveFrames(for: key, from: stream)
        } catch {
            guard !Task.isCancelled else { return }
            endTunnel(
                key,
                cause: .controlStreamEnded,
                reason: "The inbound QUIC tunnel ended: \(error.localizedDescription)"
            )
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
        tunnels.removeValue(forKey: key)?.cancelTasks()
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
    ///
    /// ``admitActivation(at:role:verified:)`` runs **first**, before a single hook fires: a tunnel
    /// that loses the duplicate collapse must never be announced to an owner, or the owner is handed
    /// a second peer for one device and then told one of them died.
    ///
    /// The connection is recorded here for the same reason the control stream is: it is what a
    /// per-transfer stream is opened on, and recording it only at activation is what makes "a
    /// transfer stream can never carry a frame from an unverified peer" structural rather than a
    /// matter of call order (``serveTransferStream(_:on:)`` resolves its tunnel *through* it). The
    /// dialing side also starts its transfer acceptor here — the listening side already has one.
    func activate(
        _ key: MeshLinkKey,
        connection: NetworkConnection<QUIC>,
        stream: Network.QUIC.Stream<QUICStream>,
        datagrams: Network.QUIC.Datagrams<QUICDatagram>,
        verified: MeshVerifiedPeer
    ) {
        guard let role = tunnels[key]?.role,
              admitActivation(at: key, role: role, verified: verified),
              var tunnel = tunnels[key] else { return }
        let now = Date()
        tunnel.controlStream = stream
        tunnel.datagrams = datagrams
        tunnel.connection = connection
        tunnel.verified = verified
        tunnel.datagramTask = Task { @MainActor [weak self] in
            await self?.receiveDatagrams(for: key, from: datagrams)
        }
        if role == .initiator {
            tunnel.transferAcceptorTask = Task { @MainActor [weak self] in
                await self?.acceptTransferStreams(on: connection, key: key)
            }
        }
        tunnels[key] = tunnel
        links.noteReady(key, now: now)
        heartbeats.start(key, now: now)
        // `tunnels=` is what makes "at most one connection per peer pair" READABLE in a Lane C
        // transcript. Without it the line says a tunnel came up and nothing about whether the last
        // one is still there, so two activations are indistinguishable from one tunnel replacing
        // another — which is exactly the ambiguity item 13 was opened on.
        MeshTransportConsoleLog.echo(
            "accepted \(verified.fingerprint) sid=\(verified.sessionID): tunnel activated, tunnels=\(tunnels.count)"
        )
        noteDatagramCapacity(key, datagrams: datagrams)
        onPeerVerified?(tunnel.peer, verified)
        onPeerChannelReady?(tunnel.channel)
    }

    /// Records this tunnel's declared and reported liveness parameters, once, at activation.
    ///
    /// The measurement the P2 loop went a fortnight without. It carries the requested datagram frame
    /// size, the size the framework *reports* as usable, the beat a heartbeat needs, and the two
    /// numbers whose relationship the churn turned on — the heartbeat interval and the QUIC idle
    /// timeout. Until they were logged together, "the keepalive fires after the timeout it defends
    /// against" was not a thing anyone could read off a transcript.
    ///
    /// The reported usable size is evidence, not a verdict: see ``MeshHeartbeatChannel`` for why it
    /// is read off the parent connection and therefore cannot distinguish "datagrams did not
    /// negotiate" from "this is the wrong object to ask".
    ///
    /// A separate line rather than a longer `accepted` one: the runbook's Lane C rows grep the
    /// activation line, and a diagnostic that rewrites the evidence it is being read against is a
    /// diagnostic that invalidates its own record.
    func noteDatagramCapacity(
        _ key: MeshLinkKey,
        datagrams: Network.QUIC.Datagrams<QUICDatagram>
    ) {
        let line = "datagramCapacity usable=\(datagrams.parent.usableDatagramFrameSize) "
            + "requested=\(Self.datagramFrameSize) required=\(Self.heartbeatDatagram.count) "
            + "idleTimeoutMs=\(MeshHeartbeatSchedule.idleTimeoutMilliseconds) "
            + "beatSeconds=\(Int(MeshHeartbeatSchedule.intervalSeconds)) for \(key.rawValue)"
        Self.logger.notice("\(line, privacy: .public)")
        MeshTransportConsoleLog.echo(line)
    }

    // MARK: Duplicate collapse

    /// Collapses a verified pair that ended up holding two tunnels, and says whether the tunnel now
    /// activating is the one that survives.
    ///
    /// The defect this closes, observed on the radio in P2 item 9: during the pre-TXT window neither
    /// side can rank the other, so *both* dial (the documented, deadlock-avoiding fallback); an
    /// inbound tunnel whose `sid` still resolves to no browsed advertisement lands under its own
    /// connection key; and two keys never collide, so the link table's duplicate suppression never
    /// sees a duplicate. Both tunnels activated, and "at most one connection per peer pair" failed
    /// on the wire while selectivity was untouched.
    ///
    /// Keying on the **durable verified identity** — the Ed25519 signing key, not the per-launch
    /// `sid` and not the link key — is what makes the two tunnels recognisable as one peer's. The
    /// verdict itself is ``MeshTunnelConvergence``, a pure function of facts both devices share.
    func admitActivation(at key: MeshLinkKey, role: MeshChannelRole, verified: MeshVerifiedPeer) -> Bool {
        guard let established = liveTunnel(verifiedAs: verified.signingPublicKey, excluding: key) else {
            return true
        }
        switch MeshTunnelConvergence.resolve(
            incomingRole: role,
            establishedRole: established.tunnel.role,
            localSessionID: localSessionID,
            peerSessionID: verified.sessionID
        ) {
        case .keepBoth:
            return true
        case .keepIncoming:
            closeRedundantTunnel(established.key, peer: verified)
            return true
        case .keepEstablished:
            closeRedundantTunnel(key, peer: verified)
            return false
        }
    }

    /// The live tunnel already carrying `signingPublicKey` under some key other than `key`.
    ///
    /// Only *verified* tunnels are candidates: a tunnel still dialing has proved nothing, so it has
    /// no identity to match and is left to ``MeshDialPreference`` where it already belongs. Scanned
    /// in sorted key order so the answer is deterministic, and bounded by the roster cap.
    private func liveTunnel(
        verifiedAs signingPublicKey: Data,
        excluding key: MeshLinkKey
    ) -> (key: MeshLinkKey, tunnel: Tunnel)? {
        for candidate in tunnels.keys.sorted(by: { $0.rawValue < $1.rawValue }) where candidate != key {
            guard let tunnel = tunnels[candidate],
                  tunnel.verified?.signingPublicKey == signingPublicKey else { continue }
            return (candidate, tunnel)
        }
        return nil
    }

    /// Closes the losing half of a collapsed duplicate pair — a **benign** close, and every clause
    /// of that word is load-bearing.
    ///
    /// It is not a dial failure, so it never reaches ``handleDialFailure(_:reason:)`` and spends
    /// nothing from the three-attempt budget; the link returns to ``MeshLinkPhase/idle`` with a full
    /// one, exactly as an honest disconnect does. It is not a rejection, so it does not go through
    /// ``report(_:)`` — an owner's `onTransportError` must not light up because a radio tidied
    /// itself. And it is not a peer disconnect, so ``onPeerDisconnected`` is not fired: the peer is
    /// still connected, on the surviving tunnel, and re-entering the owner's removal funnel would
    /// arm its re-invite retry against a device that never left (P2 item 8's `notifyOwner:` lesson).
    /// The channel is still told, because a coordinator built on the losing tunnel must not sit
    /// waiting on a connection that is gone; the owner's stale-coordinator sweep reclaims its slot
    /// through the same `removeSlot` funnel a disconnect would have used.
    ///
    /// Idempotent, and everything it touches is keyed by `key` alone, so the surviving tunnel's
    /// stream, heartbeat, budget and channel are untouched.
    func closeRedundantTunnel(_ key: MeshLinkKey, peer verified: MeshVerifiedPeer) {
        heartbeats.stop(key)
        guard let tunnel = tunnels.removeValue(forKey: key) else { return }
        tunnel.cancelTasks()
        links.noteClosed(key)
        tunnel.channel.notifyDisconnected(reason: MeshTunnelConvergence.closeReason)
        noteTunnelEnded(key, cause: .redundantDuplicate, tunnel: tunnel, detail: "closed")
        MeshTransportConsoleLog.echo(
            "redundantTunnelClosed \(verified.fingerprint) sid=\(verified.sessionID): closed"
        )
    }

    /// Hands one key's tunnel over to the connection now arriving on it, when the convergence rule
    /// says the peer's dial is the one that survives.
    ///
    /// The same-key twin of ``closeRedundantTunnel(_:peer:)``, and it differs in exactly one way:
    /// the channel is **kept**. Both connections resolved to one ``MeshLinkKey``, so they are one
    /// peer to every owner above — the same ``PeerHandle``, the same channel, the same slot — and
    /// tearing the channel down only to hand back an identical one would evict a live coordinator to
    /// replace it with itself. What is released is the losing *connection*: its tasks are cancelled,
    /// its stream and datagrams are dropped, its heartbeat stops, and its identity is cleared so the
    /// cross-key scan cannot mistake the husk for a second live tunnel. The link returns to
    /// ``MeshLinkPhase/idle`` with a full budget, so the caller's re-ask admits.
    func yieldSameKeyDuplicate(at key: MeshLinkKey, to verified: MeshVerifiedPeer) -> Bool {
        guard var tunnel = tunnels[key],
              tunnel.verified?.signingPublicKey == verified.signingPublicKey,
              MeshTunnelConvergence.resolve(
                incomingRole: .responder,
                establishedRole: tunnel.role,
                localSessionID: localSessionID,
                peerSessionID: verified.sessionID
              ) == .keepIncoming else { return false }
        heartbeats.stop(key)
        noteTunnelEnded(key, cause: .redundantDuplicate, tunnel: tunnel, detail: "yielded")
        tunnel.task?.cancel()
        tunnel.datagramTask?.cancel()
        tunnel.task = nil
        tunnel.datagramTask = nil
        tunnel.controlStream = nil
        tunnel.datagrams = nil
        tunnel.verified = nil
        tunnels[key] = tunnel
        links.noteClosed(key)
        MeshTransportConsoleLog.echo(
            "redundantTunnelClosed \(verified.fingerprint) sid=\(verified.sessionID): yielded"
        )
        return true
    }

    /// Reads length-framed app frames off the control stream until the connection ends or the
    /// bounded frame budget is spent.
    ///
    /// Falling out of the loop **throws** rather than returning: a receive loop that simply stopped
    /// would leave a tunnel that still reads as connected and delivers nothing, which is the silent
    /// failure the bound exists to avoid rather than to cause.
    ///
    /// Heartbeats are filtered here for the same reason ``receiveDatagrams(for:from:)`` filters
    /// them: since P2 item 15 a beat rides this stream whenever the datagram flow did not negotiate,
    /// and a liveness token handed to a decoder as an app frame is a frame the coordinator has to
    /// reject on every beat. One byte-equal comparison against a frozen token keeps it off that
    /// path entirely.
    func receiveFrames(for key: MeshLinkKey, from stream: Network.QUIC.Stream<QUICStream>) async throws {
        for _ in 0..<Self.maxInboundFramesPerConnection {
            guard !Task.isCancelled, tunnels[key] != nil else { return }
            let header = try await stream.receive(exactly: NetworkMeshWire.headerByteCount).content
            let length = try NetworkMeshWire.payloadLength(from: header, ceiling: Self.maxInboundWireBytes)
            let payload = try await stream.receive(exactly: length).content
            guard payload != Self.heartbeatDatagram else {
                noteHeartbeat("received", key: key, over: .controlStream)
                continue
            }
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
                guard payload != Self.heartbeatDatagram else {
                    noteHeartbeat("received", key: key, over: .datagram)
                    continue
                }
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
        endTunnel(
            key,
            cause: .frameBudgetSpent,
            reason: MeshTransportError.frameBudgetSpent.diagnosticDescription
        )
    }

    /// Ends a tunnel, choosing between "the dial failed" and "a live link dropped" by whether the
    /// control stream ever came up. Charging a disconnect to the dial budget is how a peer that
    /// reconnects a few times would become permanently undialable.
    ///
    /// `notifyOwner` is false for exactly one caller — ``disconnectPeer(_:)``, an eviction the owner
    /// asked for, which must not be reported back to the owner from inside its own removal funnel.
    /// The channel is told either way.
    ///
    /// `cause` is not decoration. Every end passes through ``noteTunnelEnded(_:cause:tunnel:detail:)``
    /// before anything else happens, so a tunnel can no longer stop carrying traffic without saying
    /// so — the silence that made P2 item 13 misread three sequential tunnels as three coexisting
    /// ones, and then hid the churn behind that misreading for another fortnight.
    func endTunnel(
        _ key: MeshLinkKey,
        cause: MeshTunnelEndReason,
        reason: String,
        notifyOwner: Bool = true
    ) {
        heartbeats.stop(key)
        guard let tunnel = tunnels.removeValue(forKey: key) else { return }
        tunnel.cancelTasks()
        noteTunnelEnded(key, cause: cause, tunnel: tunnel, detail: reason)
        guard tunnel.controlStream != nil else {
            handleDialFailure(key, reason: reason)
            return
        }
        links.noteClosed(key)
        tunnel.channel.notifyDisconnected(reason: reason)
        guard notifyOwner else { return }
        onPeerDisconnected?(tunnel.peer, reason)
    }

    /// The one line every tunnel end emits, in production and not only under a debug flag.
    ///
    /// **Permanent os.log, not a diagnostic hack.** A disconnect that leaves no trace is unreadable
    /// on a device, where there is no console mirror at all — and the console mirror exists to make
    /// a headless simulator run legible, not to be the only place the fact is recorded.
    ///
    /// What it carries is reasons and hashes: the frozen ``MeshTunnelEndReason`` token, the peer's
    /// 16-character key fingerprint (or ``MeshTunnelEndReason/unverifiedFingerprint`` when the
    /// tunnel died before anyone proved who they were), whether the tunnel had ever gone live, the
    /// surviving tunnel count, and the framework's own error text. No payload, no endpoint address,
    /// no display name — `key.rawValue` is the same session-scoped opaque endpoint id every other
    /// line in this class already logs.
    ///
    /// A benign end logs at `notice` and a fault at `error`, so an owner tidying a slot does not
    /// read as a radio failure — see ``MeshTunnelEndReason/isBenign``.
    private func noteTunnelEnded(
        _ key: MeshLinkKey,
        cause: MeshTunnelEndReason,
        tunnel: Tunnel,
        detail: String
    ) {
        let fingerprint = tunnel.verified?.fingerprint ?? MeshTunnelEndReason.unverifiedFingerprint
        let line = "tunnelEnded \(cause.rawValue) \(fingerprint) live=\(tunnel.controlStream != nil) "
            + "tunnels=\(tunnels.count) for \(key.rawValue): \(detail)"
        guard cause.isBenign else {
            Self.logger.error("\(line, privacy: .public)")
            MeshTransportConsoleLog.echo(line)
            return
        }
        Self.logger.notice("\(line, privacy: .public)")
        MeshTransportConsoleLog.echo(line)
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

// MARK: - Per-transfer streams

/// One claimed outbound transfer: the budget slot it holds and the connection its stream is opened
/// on.
///
/// The two are claimed together and released together, so a slot cannot be taken for a tunnel whose
/// connection has already gone.
private struct MeshTransferClaim {

    /// The budget slot this transfer holds, released when it finishes however it finishes.
    let id: MeshTransferID

    /// The connection to open this transfer's stream on.
    let connection: NetworkConnection<QUIC>
}

private extension NetworkMeshSession {

    /// Claims a transfer stream for one outbound frame, or answers nil to send it on the control
    /// stream — see ``MeshTransferStreamTable/openOutbound(reliableByteCount:)`` for why those two
    /// answers are deliberately one value.
    func claimTransferStream(_ key: MeshLinkKey, byteCount: Int) -> MeshTransferClaim? {
        guard var tunnel = tunnels[key], let connection = tunnel.connection,
              let id = tunnel.transfers.openOutbound(reliableByteCount: byteCount) else { return nil }
        tunnels[key] = tunnel
        return MeshTransferClaim(id: id, connection: connection)
    }

    /// Writes one length-framed payload on a stream of its own and waits for the peer's ack.
    ///
    /// **The ack is not a protocol feature, it is what keeps the stream open.** A
    /// `Network.QUIC.Stream`'s lifetime is its Swift object's: returning the moment the last write
    /// returns releases the stream, and a peer that had not finished reading sees it reset. Reading
    /// one byte back is the shortest thing that holds the object until the payload has landed — and
    /// it turns a peer that vanished mid-transfer into a thrown send the caller already handles,
    /// rather than a silent truncation the receiver would have to detect.
    ///
    /// The `defer` releases the budget on every path, including the throw and including a tunnel
    /// that was torn down while this was in flight (where the optional chain is a no-op because the
    /// whole record, budget included, is already gone).
    func sendOverTransferStream(_ payload: Data, key: MeshLinkKey, claim: MeshTransferClaim) async throws {
        defer { tunnels[key]?.transfers.closeOutbound(claim.id) }
        do {
            let stream = try await claim.connection.openStream()
            noteTransfer("opened", bytes: payload.count, streamID: stream.streamID, key: key)
            try await stream.send(NetworkMeshWire.header(for: payload.count))
            try await stream.send(payload, endOfStream: true)
            _ = try await stream.receive(exactly: MeshTransferStreamTable.ack.count)
            noteTransfer("sent", bytes: payload.count, streamID: stream.streamID, key: key)
        } catch {
            noteTransfer("failed", bytes: payload.count, streamID: 0, key: key)
            throw PeerTransportError.sendFailed(reason: error.localizedDescription)
        }
    }

    /// The dialing side's inbound-stream acceptor.
    ///
    /// It exists because that side has none: it opens its own control stream, so every stream
    /// arriving *at* it is a per-transfer stream and there is nothing to disambiguate. The listening
    /// side needs no equivalent — its `inboundStreams` acceptor is already running and routes past
    /// the control stream itself.
    func acceptTransferStreams(on connection: NetworkConnection<QUIC>, key: MeshLinkKey) async {
        do {
            try await connection.inboundStreams { stream in
                await self.serveTransferStream(stream, on: connection)
            }
        } catch {
            guard !Task.isCancelled else { return }
            Self.logger.debug("QUIC transfer acceptor ended for \(key.rawValue, privacy: .public)")
        }
    }

    /// Reads one whole transfer, hands it to the peer's channel as a single frame, and acks it.
    ///
    /// **Nothing crosses before the introduction, structurally.** A tunnel records its connection
    /// only at ``activate(_:connection:stream:datagrams:verified:)``, which is only ever reached
    /// with a ``MeshVerifiedPeer`` — so a stream opened by an unauthenticated connection resolves to
    /// no tunnel here, is refused, and never reaches a channel or a decoder.
    ///
    /// A refused or failed transfer is dropped rather than fatal, and the stream goes back un-acked
    /// so the sender's write fails loudly. That is the MC photo path's own failure semantics, and it
    /// is why neither branch touches the tunnel: never disconnect at this layer, or one malformed
    /// transfer could end any session.
    func serveTransferStream(
        _ stream: Network.QUIC.Stream<QUICStream>,
        on connection: NetworkConnection<QUIC>
    ) async {
        guard let key = tunnelKey(for: connection), let id = claimInboundTransfer(key) else {
            FernletAuditLog.log("mesh.quic.refusedTransferStream")
            return
        }
        defer { tunnels[key]?.transfers.closeInbound(id) }
        do {
            let header = try await stream.receive(exactly: NetworkMeshWire.headerByteCount).content
            let length = try NetworkMeshWire.payloadLength(from: header, ceiling: Self.maxInboundWireBytes)
            let payload = try await stream.receive(exactly: length).content
            tunnels[key]?.channel.receive(payload, at: Date())
            noteTransfer("received", bytes: length, streamID: stream.streamID, key: key)
            try await stream.send(MeshTransferStreamTable.ack, endOfStream: true)
        } catch {
            FernletAuditLog.log("mesh.quic.transferStreamFailed")
            noteTransfer("dropped", bytes: 0, streamID: stream.streamID, key: key)
        }
    }

    /// Takes one inbound transfer slot on a live tunnel, or answers nil when the peer already holds
    /// ``MeshTransferStreamTable/maxConcurrentInbound``.
    func claimInboundTransfer(_ key: MeshLinkKey) -> MeshTransferID? {
        guard var tunnel = tunnels[key], let id = tunnel.transfers.openInbound() else { return nil }
        tunnels[key] = tunnel
        return id
    }

    /// The tunnel a connection belongs to, by object identity.
    ///
    /// Identity rather than a second pendingKey→tunnelKey map: a listening tunnel is promoted from
    /// its pending key to the key its verified `sid` resolves to, so a map would have two spellings
    /// of one link to keep in step. The connection object has exactly one. Scanned in sorted key
    /// order and bounded by the roster cap, like ``liveTunnel(verifiedAs:excluding:)``.
    func tunnelKey(for connection: NetworkConnection<QUIC>) -> MeshLinkKey? {
        for candidate in tunnels.keys.sorted(by: { $0.rawValue < $1.rawValue })
        where tunnels[candidate]?.connection === connection {
            return candidate
        }
        return nil
    }

    /// Records one transfer crossing: the verb, the payload size, and the stream it rode.
    ///
    /// Byte counts and stream ids only — no payload, no peer name, and the same session-scoped
    /// opaque endpoint id every other line in this class logs. `notice`, not `debug`: a transfer is
    /// a rare, significant event, and this is the line a Lane C transcript reads the photo flow off.
    func noteTransfer(_ verb: String, bytes: Int, streamID: UInt64, key: MeshLinkKey) {
        let line = "transfer \(verb) bytes=\(bytes) stream=\(streamID) for \(key.rawValue)"
        Self.logger.notice("\(line, privacy: .public)")
        MeshTransportConsoleLog.echo(line)
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
                MeshTransportConsoleLog.echo(Self.refusalDetail(rejection, role: role, authority: authority))
                report("A QUIC tunnel was refused: \(rejection.diagnosticDescription)")
                return nil
            }
            guard let transcript = exchange.bind(channelBindingHash: binding) else {
                report("The QUIC transport could not derive a channel-introduction transcript.")
                return nil
            }
            let signed = MeshChannelIntroduction(
                channelBindingHash: binding,
                signature: MeshIntroductionChaos.signature(
                    try authority.signChannelIntroduction(transcript)
                )
            )
            return try await settle(exchange, role: role, signed: signed, over: stream)
        } catch {
            report("A QUIC channel introduction did not complete: \(error.localizedDescription)")
            return nil
        }
    }

    /// This device's half of the hello. The `sid` is the one it advertises, so a peer can match this
    /// tunnel to the advertisement it browsed.
    ///
    /// The nonce comes through ``MeshIntroductionChaos/introductionNonce()`` rather than directly
    /// from ``MeshChannelIntroductionFormat/randomNonce()``: in Release the two are the same call,
    /// and in DEBUG the seam lets a run deliberately replay a nonce so the peer's refusal is
    /// observable over a real radio.
    func localHello(from authority: any MeshIntroductionAuthority) -> MeshChannelHello {
        MeshChannelHello(
            protocolVersion: MeshChannelIntroductionFormat.protocolVersion,
            meshID: authority.meshID,
            epochRef: authority.epochRef,
            signingPublicKey: authority.localSigningPublicKey,
            nonce: MeshIntroductionChaos.introductionNonce(),
            sessionID: localSessionID
        )
    }

    /// One console line describing a refused hello *and what it was judged against*.
    ///
    /// The reason alone cannot tell "nobody is on my roster" from "somebody is, but not you", and
    /// those are two different rows of the rejection matrix. DEBUG mirror only — the `report(_:)`
    /// text and the `Logger` line are unchanged.
    static func refusalDetail(
        _ rejection: MeshIntroductionRejection,
        role: MeshChannelRole,
        authority: any MeshIntroductionAuthority
    ) -> String {
        let roster = authority.roster
        return "refused \(rejection) as \(role): mesh=\(authority.meshID) epoch=\"\(authority.epochRef)\" "
            + "rosterMembers=\(roster.memberCount) rosterBarred=\(roster.barredCount)"
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
                MeshTransportConsoleLog.echo("refused \(rejection) as \(role) at the signed introduction")
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
        // One write, for the reason ``sendFramed(_:over:)`` gives at length: a length prefix and its
        // payload written as two awaited sends can be split by another writer on the same stream.
        // The handshake has only one writer per stream today, so this is uniformity rather than a
        // fix — but a framing rule that holds in one place and not the other is the kind that gets
        // broken by the next caller.
        var frame = NetworkMeshWire.header(for: payload.count)
        frame.append(payload)
        try await stream.send(frame)
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

    /// Writes one length-framed payload to a control stream, in **one** write.
    ///
    /// The single write is the whole point, and it is not a micro-optimisation. Every frame on a
    /// tunnel shares one control stream, and `MeshNetworkManager` fires its envelopes as independent
    /// tasks — a photo manifest, a vouch list, a shop catalogue and a shop request all leave within
    /// the same instant of a slot committing. Writing the header and the payload as two awaited
    /// sends let two of those tasks interleave at the suspension between them, so the peer read one
    /// frame's header followed by another frame's first four bytes as a length. The reader then
    /// refused an implausible length (``MeshTransportError/invalidFrameLength``) and the tunnel died
    /// — observed on the Lane C app-flow run, every time, within a second of the first slot commit.
    ///
    /// One contiguous buffer per frame closes it: concurrent sends can be ordered either way, but
    /// neither can land inside the other. The bytes on the wire are identical.
    ///
    /// The per-transfer streams do not need this and deliberately do not copy: a transfer stream is
    /// opened by one task, written by that task alone, and closed with it, so it has no second
    /// writer to interleave with — and a bulk payload is exactly the one it would be wasteful to
    /// concatenate.
    func sendFramed(_ payload: Data, over stream: Network.QUIC.Stream<QUICStream>) async throws {
        var frame = NetworkMeshWire.header(for: payload.count)
        frame.append(payload)
        do {
            try await stream.send(frame)
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

    /// Sends one heartbeat on whichever pipe this tunnel actually has.
    ///
    /// **The channel is asked, not assumed** (P2 item 15). Plan §7.1 puts heartbeats on QUIC
    /// datagrams, so a fresh tunnel tries that first; if the write throws, the tunnel latches
    /// ``Tunnel/datagramWriteFailed`` and every later beat rides the control stream. See
    /// ``MeshHeartbeatChannel`` for why the *reported* usable frame size is recorded as evidence but
    /// never used as the gate.
    ///
    /// A failed datagram write is **not** a dead peer and no longer ends the tunnel. Only a beat
    /// that the reliable control stream also refuses does that — a link that cannot carry 22 framed
    /// bytes really is not a link.
    func sendHeartbeat(to key: MeshLinkKey) {
        guard let tunnel = tunnels[key] else { return }
        let channel = MeshHeartbeatChannel.choice(
            hasDatagramFlow: tunnel.datagrams != nil,
            datagramWriteFailed: tunnel.datagramWriteFailed
        )
        guard channel == .datagram, let datagrams = tunnel.datagrams else {
            guard let stream = tunnel.controlStream else { return }
            noteHeartbeat("sending", key: key, over: .controlStream)
            beat(key) { try await self.sendFramed(Self.heartbeatDatagram, over: stream) }
            return
        }
        noteHeartbeat("sending", key: key, over: .datagram)
        beat(key, isDatagram: true) {
            try await datagrams.send(NetworkMeshSession.heartbeatDatagram)
        }
    }

    /// Runs one heartbeat write off the main actor's queue and applies the failure policy.
    ///
    /// The two channels differ only in the write, so the policy lives here once rather than twice.
    /// A failed *datagram* beat latches the tunnel onto the control stream and is otherwise
    /// harmless; a failed *control stream* beat ends the tunnel, naming
    /// ``MeshTunnelEndReason/heartbeatSendFailed`` instead of ending it without a word.
    func beat(
        _ key: MeshLinkKey,
        isDatagram: Bool = false,
        write: @escaping @MainActor () async throws -> Void
    ) {
        Task { @MainActor [weak self] in
            do {
                try await write()
            } catch {
                self?.heartbeatFailed(key, isDatagram: isDatagram, error: error)
            }
        }
    }

    /// One failed heartbeat write: latch and carry on, or end the tunnel.
    func heartbeatFailed(_ key: MeshLinkKey, isDatagram: Bool, error: Error) {
        guard isDatagram else {
            endTunnel(
                key,
                cause: .heartbeatSendFailed,
                reason: "A heartbeat could not be sent: \(error.localizedDescription)"
            )
            return
        }
        tunnels[key]?.datagramWriteFailed = true
        let line = "heartbeat datagram refused, falling back to the control stream "
            + "for \(key.rawValue): \(error.localizedDescription)"
        Self.logger.notice("\(line, privacy: .public)")
        MeshTransportConsoleLog.echo(line)
    }

    /// Records one heartbeat crossing, at `debug` level plus the console mirror.
    ///
    /// Debug rather than notice on purpose: two lines a minute per link is the right volume for a
    /// Lane C transcript and the wrong volume for a device's persisted log. What it makes directly
    /// observable is the thing that was only ever inferred before — that beats are *flowing*, and on
    /// which pipe.
    func noteHeartbeat(_ verb: String, key: MeshLinkKey, over channel: MeshHeartbeatChannel) {
        let line = "heartbeat \(verb) over \(channel) for \(key.rawValue)"
        Self.logger.debug("\(line, privacy: .public)")
        MeshTransportConsoleLog.echo(line)
    }

    /// Records one inbound tunnel this session verified and then declined to keep.
    ///
    /// Mirrored to the console log rather than left at `debug`, because a declined inbound is
    /// *silent on both ends otherwise*: the dialer sees only its own control stream die with an
    /// `ENOTCONN`, and this side logs nothing a `--console-pty` transcript can read. That silence
    /// is what made the runbook's three-node bring-up unreadable — an edge that never formed looked
    /// identical to an edge nobody attempted. `notice`, not `error`: a duplicate collapsing or an
    /// owner tidying a slot is ordinary, and only the *absence* of a reason was ever the fault.
    ///
    /// - Parameters:
    ///   - reason: Frozen English naming who refused — `owner`, or the ``MeshLinkAdmission`` case.
    ///   - key: The link the refused tunnel would have lived under.
    func noteInboundRefusal(_ reason: String, key: MeshLinkKey) {
        let line = "inbound tunnel refused \(reason) for \(key.rawValue)"
        Self.logger.notice("\(line, privacy: .public)")
        MeshTransportConsoleLog.echo(line)
    }

    /// Logs a diagnostic and hands it to the owner. Frozen English: this is the surface that makes
    /// a missing `NSBonjourServices` entry or a declined Local Network prompt visible instead of
    /// silently dead, and it is read by a developer, not a user.
    func report(_ message: String) {
        Self.logger.error("\(message, privacy: .public)")
        MeshTransportConsoleLog.echo(message)
        onTransportError?(message)
    }
}
