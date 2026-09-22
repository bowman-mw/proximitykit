import CryptoKit
import Dispatch
import Foundation
import Network
import os
import Security
import FernletFoundation

// MARK: - PresenceRadioSession

/// The presence radio, as the surface ``PresenceManager`` actually drives.
///
/// The seam `PresenceManager` did not have. `MeshNetworkManager` has held its radio behind
/// `MeshTransportSession` since P2 item 8, so the whole manager can be exercised at tier 1 over an
/// in-memory fake; presence constructed its session inline, which is why not one of its advertise,
/// republish, dial or stand-down decisions was reachable without starting a real radio. Everything
/// the manager asks of a radio is here and nothing else is: no browse internals, no tunnels, no
/// framework type.
///
/// The hooks are settable rather than delegate methods because that is the shape both existing
/// radios already publish, and because the manager wires them once in `start()` and never again.
@MainActor
protocol PresenceRadioSession: AnyObject {

    /// A peer appeared in the browse results, with its advertisement.
    var onPeerDiscovered: ((PeerHandle) -> Void)? { get set }
    /// A peer left the browse results.
    var onPeerLost: ((PeerHandle) -> Void)? { get set }
    /// A tunnel came up and its channel is live.
    var onPeerChannelReady: ((NetworkPeerChannel) -> Void)? { get set }
    /// A tunnel went down, with a diagnostic reason.
    var onPeerDisconnected: ((PeerHandle, String) -> Void)? { get set }
    /// The listener or browser failed to start.
    var onTransportError: ((String) -> Void)? { get set }
    /// Resolves an inbound dialer's claimed pairwise tag to the browsed peer it names, or nil to
    /// refuse. Fails closed when unwired.
    var resolveDialer: ((String) -> PeerHandle?)? { get set }

    /// Brings the radio up under `posture`, advertising `discoveryInfo`.
    func start(posture: PresenceEpochPosture, discoveryInfo: [String: String]) throws
    /// Re-advertises under `posture`, withdrawing whatever registration preceded it.
    func republish(posture: PresenceEpochPosture, discoveryInfo: [String: String])
    /// Tears the radio down and drops everything it held, including the posture.
    func stop()
    /// Opens a tunnel to a browsed peer, claiming `helloTag`.
    func dial(_ peer: PeerHandle, helloTag: String)
    /// Ends a peer's tunnel at the owner's request.
    func disconnectPeer(_ peer: PeerHandle)
    /// The channel this radio would hand the owner for `peer`, built exactly as the live path
    /// builds one — the seam a heart rig uses to stand a connection up with no radio.
    func channel(for peer: PeerHandle) -> NetworkPeerChannel
}

// MARK: - NetworkPresenceSession

/// The presence radio's Network.framework/QUIC surface: one listener, one browser, and up to
/// ``maxTunnels`` short-lived pairwise tunnels multiplexed into ``NetworkPeerChannel``s.
///
/// The presence half of plan §17.1, and deliberately a **separate, much smaller** session than
/// ``NetworkMeshSession`` rather than a parameterization of it. What the two radios share is
/// extracted and reused by symbol — ``ProximityQUICParameters`` (the TLS/QUIC parameter factory),
/// ``NetworkMeshWire`` (control-stream framing), ``MeshSessionIdentityMap`` (one session-stable
/// ``PeerHandle`` identity per endpoint), ``MeshLinkKey`` and ``NetworkPeerChannel`` itself. What
/// they do not share is why they are two types:
///
/// * **The posture rotates here and must never rotate there.** This session advertises under a
///   ``PresenceEpochPosture``'s instance name and TLS identity, replaced whole at every 900 s
///   boundary. A mesh session's name and identity are stable for its whole life, and a mesh tunnel
///   that re-registered under a new name mid-session would drop every peer. Making rotation a
///   parameter would put a switch on `NetworkMeshSession` whose wrong setting is silent.
/// * **There is no signed channel introduction.** The mesh authenticates a tunnel with
///   ``MeshChannelIntroduction`` against its roster before a single app frame crosses. Presence
///   must not: `ProximityCoordinator`'s SEALED introduction is the presence handshake, and its
///   whole point is that identity never travels in the clear — a mesh-style signed hello would
///   emit exactly what the seal exists to hide.
/// * **There is no roster, no dial budget, no heartbeat and no transfer stream.** A presence tunnel
///   is opened to deliver one heart and torn down seconds later, so ``MeshLinkTable``,
///   ``MeshHeartbeatSchedule`` and ``MeshTransferStreamTable`` have nothing to decide here — and
///   this session owns **no timer at all**, which is what keeps `PresenceManager`'s one-timer rule
///   (the epoch rotation tick) true after the migration.
///
/// ## Inbound peer resolution
///
/// MultipeerConnectivity resolved an inbound peer for free: an invitation arrives bearing the
/// `MCPeerID` the browser already found. QUIC does not — an inbound connection carries a connection
/// id that belongs to no browse result — so the dialer opens with one ``PresenceDialHello`` naming
/// the pairwise tag it advertises, and the owner resolves that tag to a peer it has already browsed
/// and tag-matched through ``resolveDialer``. A hello that names no such peer is refused before any
/// channel exists. See ``PresenceDialHello`` for why that frame discloses nothing the air did not.
///
/// The resolved key is the **browsed** peer's key, not the connection's, which is what gives this
/// radio the same collapse MC had: an inbound tunnel and an outbound dial to one device land under
/// one ``MeshLinkKey``, so the owner's "already connected to this device?" test keeps working.
///
/// ## Glare
///
/// Two friends who sight each other at the same moment both dial — two phones approaching, which is
/// the common case rather than a corner. MultipeerConnectivity collapsed that for free: one
/// session, one invitation, one peer. Here each side holds an outbound tunnel under the peer's
/// browsed key *and* receives an inbound connection resolving to that same key, and refusing the
/// inbound on both sides ends with **zero** tunnels — the refusal closes the peer's connection, so
/// each side's own dial dies at the other end and neither heart is delivered.
///
/// So a second connection under a held key is **collapsed rather than refused**, by the mesh's own
/// rule (``MeshTunnelConvergence``) applied to the only pair of values both devices hold and agree
/// on before any presence handshake has run: the two advertised instance names. Both sides compute
/// the same verdict from the same two strings, so the connection that survives is the same one on
/// both devices however the two arrivals interleave; the loser is closed with the
/// `presence.quic.redundantTunnelClosed` audit token. See ``admitInbound(at:)``.
///
/// ## Accepted residuals
///
/// Both are availability-only, both are bounded, and the SEALED introduction refuses everything
/// either of them can reach — a forger cannot open the intro, cannot answer it and learns nothing.
///
/// * **Tag-replay slot squatting.** A non-friend that sights a pairwise tag on the air and replays
///   it inside its 900 s epoch is resolved by the owner to the friend that tag names, so its
///   connection occupies that friend's ``MeshLinkKey`` slot — one of ``maxTunnels`` — until its own
///   connection dies, which is at most ``maxInboundFramesPerConnection`` frames or
///   ``MeshHeartbeatSchedule/idleTimeoutMilliseconds`` of silence. MultipeerConnectivity had no
///   equivalent, because an invitation carried the `MCPeerID` the browser had already found. The
///   fix that would remove it — filing an inbound tunnel under its *connection* id until the sealed
///   introduction SUCCEEDS, and only then moving it under the browsed key — is deliberately not
///   taken: this session never sees the coordinator's verdict, so it would need a new radio seam
///   for "the introduction completed" plus an alias holding two keys for one peer, and that alias
///   multiplies every glare case above.
/// * **Glare eviction.** Because the tie-break ranks instance names rather than verified
///   identities, a replayed tag can evict a live tunnel to the real friend when the rank happens to
///   favour the incoming connection. The cost is one failed heart send, which the owner's own
///   pre-connect retry re-attempts; same attacker, same epoch bound, same sealed refusal.
///
/// ## Security posture
///
/// TLS presents the epoch posture's identity with an accept-any validator, exactly as the mesh
/// does and for the same reason: certificate validation is not the authentication decision, the
/// sealed introduction is. `prohibitedInterfaceTypes` is `[.cellular]` on every listener, browser
/// and connection — the local-link claim, enforced by the OS. The ALPN is presence's own, so a
/// presence connection and a mesh connection can never negotiate.
///
/// **Fail closed without an owner.** A session whose owner wired no ``resolveDialer`` resolves
/// nobody and therefore accepts nobody, mirroring the retired MC advertiser's
/// `shouldAcceptInvitation` (`?? false`).
///
/// `@MainActor`; framework callbacks arrive `@Sendable` and hop in. Owners wire behaviour through
/// the closure hooks, the same way they do for the other two radios.
@MainActor
final class NetworkPresenceSession: PresenceRadioSession, NetworkChannelHost {

    /// The presence radio's QUIC service type. A frozen wire token: it must also appear in the
    /// app's Info.plist `NSBonjourServices` or discovery is silently dead on device.
    ///
    /// Deliberately **not** a reuse of the retired MC radio's `_fernlet-near._udp`. That entry
    /// survived in the app's plist for the length of the migration window, and reusing the name
    /// then would have put this listener and the MC advertiser on one service type, where each
    /// would have browsed the other's registrations as a peer. The old entry is gone; this token
    /// is the one that stayed.
    nonisolated static let serviceType = "_fernlet-near2._udp"

    /// ALPN for the presence protocol. A frozen wire token, distinct from the mesh's
    /// `fernlet-mesh-v1` so the two radios cannot negotiate a connection with each other.
    nonisolated static let alpn = "fernlet-near-v1"

    /// Hard ceiling on one inbound frame, enforced before the bytes reach any channel or decoder.
    /// The same value both other transports enforce, so all three refuse identically.
    nonisolated static let maxInboundWireBytes = NetworkMeshSession.maxInboundWireBytes

    /// The QUIC stream id the control stream always has — RFC 9000 §2.1 numbers client-initiated
    /// bidirectional streams 0, 4, 8 … and a presence dialer opens exactly one.
    nonisolated static let controlStreamID: UInt64 = 0

    /// Live tunnels this radio may hold. Presence hearts are short-lived, and the owner caps its
    /// own heart connections at the same number (`PresenceManager.maxHeartConnections`); this copy
    /// is the floor that still holds when the owner's does not — a radio whose owner is wired
    /// wrong, or not wired at all, must not accumulate tunnels.
    nonisolated static let maxTunnels = 4

    /// Inbound connections that may be mid-hello at once.
    ///
    /// A silent dialer is reaped by QUIC's own idle timeout — the same
    /// ``MeshHeartbeatSchedule/idleTimeoutMilliseconds`` the mesh declares, which ends the
    /// connection and throws its owning task out of `inboundStreams`. That is deliberately the only
    /// reaper: a sweep would need a clock, and presence owns exactly one timer, which belongs to the
    /// epoch rotation.
    nonisolated static let maxPendingInbound = 4

    /// Frames one tunnel may deliver before its receive loop retires (Power of 10 rule 2). Two
    /// orders of magnitude above a heart exchange, which is a handful of frames.
    nonisolated static let maxInboundFramesPerConnection = 2_000

    /// Browse results considered in one callback. Bounded for the same reason the mesh bounds its
    /// own: a crowded room is untrusted input.
    nonisolated static let maxBrowsedEndpoints = MeshSessionIdentityMap.maxTrackedEndpoints

    /// Characters of the certificate digest carried in the diagnostic context. Enough that two
    /// epochs' identities are never confused by eye, short enough to read off a log line.
    nonisolated static let certificateDigestLength = 16

    /// Bytes of per-session salt behind ``peerLabel(for:)`` — 256 bits, drawn once per session
    /// from the same CSPRNG the posture's instance name draws from.
    nonisolated static let peerLabelSaltByteCount = 32

    /// Characters of the salted digest one peer label carries. Long enough that two peers in one
    /// room are never confused by eye, short enough to read off a log line.
    nonisolated static let peerLabelLength = 12

    /// The label a peer gets when this session has no salt to hide it behind — the fail-closed
    /// direction, and the only branch of ``peerLabel(for:)`` that is not a digest. A constant
    /// carries no peer value at all, which is strictly better than an unsalted one.
    nonisolated static let unlabelledPeer = "unlabelled"

    /// Frozen diagnostic English for the benign close that collapses a double dial.
    ///
    /// Deliberately not a ``MeshTransportError``: nothing failed and nothing was refused. It leads
    /// with its own token so a log reader — and the tier-2 runner's grep — can tell a collapsed
    /// duplicate from a rejected peer at a glance. Never localized, never user copy.
    nonisolated static let redundantTunnelCloseReason =
        "redundantTunnelClosed: a duplicate presence connection to one peer was collapsed."

    private static let logger = Logger(subsystem: "com.fernlet", category: "proximity.presence.quic")

    // MARK: Hooks

    /// A peer appeared in the browse results, with its advertisement.
    var onPeerDiscovered: ((PeerHandle) -> Void)?
    /// A peer left the browse results.
    var onPeerLost: ((PeerHandle) -> Void)?
    /// A tunnel came up and its channel is live.
    var onPeerChannelReady: ((NetworkPeerChannel) -> Void)?
    /// A tunnel went down, with a diagnostic reason.
    var onPeerDisconnected: ((PeerHandle, String) -> Void)?
    /// Invoked with frozen diagnostic English when the listener or browser fails to start. Without
    /// it a missing `NSBonjourServices` entry or a declined Local Network prompt is silent.
    var onTransportError: ((String) -> Void)?

    /// Resolves an inbound dialer's claimed pairwise tag to the browsed peer it names, or nil to
    /// refuse the connection. **Fails closed**: a radio nobody has wired resolves nobody.
    var resolveDialer: ((String) -> PeerHandle?)?

    // MARK: State

    /// One live or in-flight tunnel. `controlStream != nil` is the readiness test: a connection
    /// that never got one failed to dial, and one that had a stream and lost it disconnected.
    private struct Tunnel {
        let peer: PeerHandle
        let channel: NetworkPeerChannel
        /// Which end opened this connection, named from **this** device: `.initiator` is a tunnel
        /// ``dial(_:helloTag:)`` opened, `.responder` one ``serveInbound(stream:pendingKey:)``
        /// accepted. The discriminator the glare tie-break ranks against an arriving connection.
        let role: MeshChannelRole
        var controlStream: Network.QUIC.Stream<QUICStream>?
        var task: Task<Void, Never>?
    }

    private var tunnels: [MeshLinkKey: Tunnel] = [:]
    private var pendingInbound: [MeshLinkKey: Task<Void, Never>] = [:]
    private var identities = MeshSessionIdentityMap()
    private var browsedEndpoints: [MeshLinkKey: Bonjour.Endpoint] = [:]
    private var browsedRecords: [MeshLinkKey: MeshEndpointRecord] = [:]
    private var listener: NetworkListener<QUIC>?
    private var browser: NetworkBrowser<Bonjour>?
    private var listenerTask: Task<Void, Never>?
    private var browserTask: Task<Void, Never>?
    private var listenerIsReady = false
    private var listenerIsAdvertised = false

    /// The posture this radio is currently wearing — the ONLY source of the advertised instance
    /// name and the TLS identity. Never minted here: `PresenceManager` owns the epoch tick and
    /// hands a posture in at ``start(posture:discoveryInfo:)`` and every
    /// ``republish(posture:discoveryInfo:)``.
    private var posture: PresenceEpochPosture?
    private var advertisedFields: [String: String] = [:]
    private(set) var isRunning = false

    /// The random salt every peer label in this session's diagnostics is taken under.
    ///
    /// Drawn once at construction and never again: not persisted, not advertised, not on the wire,
    /// not derived from anything, and gone with the session. It is what makes ``peerLabel(for:)``
    /// opaque *to a reader who holds the peer's name* — an unsalted digest of the name would be
    /// recomputable by anyone who can hash, so two log excerpts from two sessions (or a log and a
    /// packet capture) would re-link a peer exactly as the raw name did.
    private let peerLabelSalt: [UInt8] =
        PresenceEpochPosture.systemEntropy(NetworkPresenceSession.peerLabelSaltByteCount)

    /// Peers this radio currently holds a tunnel to, in no particular order.
    var connectedPeers: [PeerHandle] { tunnels.values.map(\.peer) }

    init() {}

    /// Cancels every task this radio owns (memory-lifecycle rule ML1). ``stop()`` already does it;
    /// this is for the owner that is released without calling it.
    isolated deinit {
        listenerTask?.cancel()
        browserTask?.cancel()
        for tunnel in tunnels.values { tunnel.task?.cancel() }
        for task in pendingInbound.values { task.cancel() }
    }

    // MARK: - Lifecycle

    /// Brings the radio up under `posture`: advertises `discoveryInfo` as the TXT record on a QUIC
    /// listener named ``PresenceEpochPosture/instanceName`` and presenting
    /// ``PresenceEpochPosture/tlsIdentity``, then browses once the listener is both ready and
    /// advertised.
    ///
    /// Throws rather than reporting, because the owner's `start()` is the one caller and it stands
    /// the radio down on a failure — the `didNotStart*` shape P8 item 0's device finding (b) fixed.
    func start(posture: PresenceEpochPosture, discoveryInfo: [String: String]) throws {
        guard !isRunning else { return }
        self.posture = posture
        advertisedFields = discoveryInfo
        isRunning = true
        try startListener()
    }

    /// Re-advertises under `posture`, carrying `discoveryInfo`.
    ///
    /// The listener is torn down and re-minted rather than mutated — the same stop-and-recreate the
    /// mesh radio needs and the retired MC advertiser needed, and the **only** way to withdraw a
    /// Bonjour registration. That is what makes an epoch boundary total: the old instance name stops being
    /// advertised before the new one starts, so there is no instant at which both are on the air.
    ///
    /// Every live tunnel survives, deliberately and necessarily: an inbound tunnel is owned by its
    /// own task and an outbound one is its own connection, neither by the listener. A tunnel that
    /// survives a boundary carries no link from the old posture to the new one that its peer did
    /// not already hold — it is a verified friend, which is the only party that ever learns either
    /// name (see the type's discussion of what a boundary does and does not break).
    func republish(posture: PresenceEpochPosture, discoveryInfo: [String: String]) {
        let rotated = self.posture?.epoch != posture.epoch
        self.posture = posture
        advertisedFields = discoveryInfo
        guard isRunning else { return }
        cancelListener()
        do {
            try startListener()
        } catch {
            report("The presence listener could not be republished: \(error)")
            return
        }
        guard rotated else { return }
        FernletAuditLog.log("presence.quic.rotated", context: auditContext(for: posture))
    }

    /// Tears the radio down and drops everything it was holding — including the posture, so a
    /// stood-down radio keeps no name and no identity to come back up under.
    func stop() {
        let stopped = isRunning
        for tunnel in tunnels.values { tunnel.task?.cancel() }
        for task in pendingInbound.values { task.cancel() }
        cancelListener()
        cancelBrowser()
        tunnels.removeAll()
        pendingInbound.removeAll()
        browsedEndpoints.removeAll()
        browsedRecords.removeAll()
        identities.removeAll()
        advertisedFields.removeAll()
        posture = nil
        isRunning = false
        guard stopped else { return }
        FernletAuditLog.log("presence.quic.stopped", context: [:])
    }

    // MARK: - Dialing

    /// Opens a tunnel to a browsed peer and writes the dial hello claiming `helloTag`.
    ///
    /// The owner's call, not this radio's — presence dials only to deliver a heart, and the
    /// decision of when belongs with the gates that own it.
    ///
    /// A dial this radio cannot make is a **dial refusal and nothing more**: it is logged and the
    /// call returns. It is emphatically not a ``report(_:)``, because that hook is the owner's
    /// START-failure door (P8 item 0, device finding (b)) and it stands the whole radio down. The
    /// reachable miss is routine: a friend's own epoch boundary withdraws their Bonjour
    /// registration for the instant between the old listener going down and the new one coming up,
    /// so ``noteLost(_:)`` drops the endpoint while the owner's 45 s lost-grace still offers that
    /// friend as nearby. A heart tapped in that window used to take presence off the air — nearby
    /// list emptied, posture dropped — until the next scene event re-applied the run policy.
    func dial(_ peer: PeerHandle, helloTag: String) {
        guard isRunning, let key = identities.key(for: peer) else { return }
        guard let endpoint = browsedEndpoints[key] else {
            Self.logger.notice(
                "presence dial refused for \(self.peerLabel(for: key), privacy: .public): no browsed endpoint"
            )
            return
        }
        guard tunnels[key] == nil, tunnels.count < Self.maxTunnels else { return }
        let connection = NetworkConnection(
            to: endpoint,
            using: ProximityQUICParameters.connection(alpn: Self.alpn)
        ).start()
        let channel = prepareChannel(for: key)
        tunnels[key] = Tunnel(peer: channel.peer, channel: channel, role: .initiator)
        tunnels[key]?.task = Task { @MainActor [weak self] in
            await self?.runInitiator(connection, key: key, helloTag: helloTag)
        }
    }

    /// Ends a peer's tunnel at the owner's request, without reporting it back to the owner.
    func disconnectPeer(_ peer: PeerHandle) {
        guard let key = identities.key(for: peer) else { return }
        endTunnel(key, reason: "This peer's presence connection was closed locally.", notifyOwner: false)
    }

    /// Hands a START failure to the owner's transport-error hook, which stands the radio down.
    /// Never a per-dial or per-connection refusal — see ``dial(_:helloTag:)``.
    func reportTransportError(_ message: String) {
        report(message)
    }

    // MARK: - NetworkChannelHost

    /// Sends one frame over a peer's control stream.
    ///
    /// `mode` is accepted and ignored: this radio negotiates no datagram flow and opens no
    /// per-transfer streams, so every presence frame is reliable and in order. Delivering a frame
    /// more reliably than asked is always allowed; dropping it silently is not.
    func send(_ data: Data, to peer: PeerHandle, mode: PeerDeliveryMode) async throws {
        guard let key = identities.key(for: peer), let stream = tunnels[key]?.controlStream else {
            throw PeerTransportError.unexpectedState
        }
        guard data.count <= Self.maxInboundWireBytes else {
            throw PeerTransportError.sendFailed(
                reason: MeshTransportError.oversizedFrame(byteCount: data.count).diagnosticDescription
            )
        }
        var frame = NetworkMeshWire.header(for: data.count)
        frame.append(data)
        do {
            try await stream.send(frame)
        } catch {
            throw PeerTransportError.sendFailed(reason: error.localizedDescription)
        }
    }

    /// Always zero: presence opens no per-transfer streams. Required by ``NetworkChannelHost`` so
    /// one channel type serves both radios.
    func openTransferCount(for peer: PeerHandle) -> Int { 0 }

    // MARK: - Peer labels

    /// The opaque, session-scoped label this radio names `key` by in **every** diagnostic line it
    /// writes — the audit rows and the `os.Logger` lines alike.
    ///
    /// The first ``peerLabelLength`` hexadecimal characters of SHA-256 over this session's random
    /// ``peerLabelSalt`` followed by the key's bytes. Three properties, and each is load-bearing:
    ///
    /// * **Not the peer's name.** ``MeshLinkKey`` looks opaque and is not: under this radio its
    ///   `rawValue` is the browsed Bonjour endpoint's id, which *contains the instance name the
    ///   peer advertises* (`fn-<16 hex>._fernlet-near2._udp.local.`). Logging it verbatim put the
    ///   peer's rotating identifier on every sighting line — the exact value the posture rotation
    ///   exists to keep uncorrelatable — which is what the tier-2 run of P9 item 2 observed.
    /// * **Not recomputable.** The salt is private to this session, so a reader who holds the
    ///   peer's name (it is public on the air) still cannot turn two log excerpts, or a log and a
    ///   packet capture, into one peer. A plain unsalted hash would be no protection at all.
    /// * **Stable within the session.** The same key labels identically for the session's whole
    ///   life, so a sighting, a collapse and a teardown are still readable as one peer's story —
    ///   which is the entire reason a per-peer token appears in these lines at all.
    ///
    /// Not a cryptographic decision: nothing compares two of these and nothing depends on their
    /// unforgeability. A session whose entropy draw came back empty labels every peer
    /// ``unlabelledPeer`` rather than falling back to anything derived from the key.
    func peerLabel(for key: MeshLinkKey) -> String {
        guard !peerLabelSalt.isEmpty else { return Self.unlabelledPeer }
        var hasher = SHA256()
        hasher.update(data: Data(peerLabelSalt))
        hasher.update(data: Data(key.rawValue.utf8))
        let hexadecimal = PresenceEpochPosture.hexadecimal(Array(hasher.finalize()))
        return String(hexadecimal.prefix(Self.peerLabelLength))
    }

    // MARK: - Test seam

    /// The instance name this radio is advertising right now, or nil while it is down.
    ///
    /// The read the mesh radio never had: `NetworkMeshSession` keeps its name and identity private
    /// and its suite proves the listener's behaviour by grepping statement order. Presence's whole
    /// claim is that these two values rotate together and leave nothing behind, so they are
    /// observable — a rotation that did not reach the listener is exactly the defect a source scan
    /// cannot see.
    var advertisedInstanceNameForTesting: String? { posture?.instanceName }

    /// The digest of the certificate this radio is presenting right now, or nil while it is down.
    var advertisedCertificateDigestForTesting: String? {
        posture.map { Self.certificateDigest(of: $0) }
    }

    /// The epoch this radio is advertising for, or nil while it is down.
    var advertisedEpochForTesting: UInt64? { posture?.epoch }

    /// The TXT fields this radio is advertising.
    var advertisedFieldsForTesting: [String: String] { advertisedFields }

    /// How many endpoints the session holds an identity for — the read that lets a test assert
    /// ``stop()`` left nothing behind rather than inferring it from a re-mint.
    var trackedEndpointCountForTesting: Int { identities.trackedCount }

    /// How many tunnels are live.
    var tunnelCountForTesting: Int { tunnels.count }

    /// Which end of a peer's surviving connection this radio is holding, or nil for no tunnel —
    /// the read that lets a glare test say the two devices kept the SAME connection (one
    /// `.initiator`, one `.responder`) rather than one each.
    func tunnelRoleForTesting(at key: MeshLinkKey) -> MeshChannelRole? { tunnels[key]?.role }

    /// Brings this radio up WITHOUT a listener or a browser: it wears `posture` and reads as
    /// running, which is every precondition ``dial(_:helloTag:)`` and ``admitInbound(at:)`` test,
    /// and nothing at all that touches Bonjour.
    ///
    /// ``start(posture:discoveryInfo:)`` creates a real `NetworkListener`, which a unit test must
    /// never do — and the two decisions this unblocks (a dial for a peer whose registration has
    /// gone; a second connection under a held key) are precisely the ones that were unreachable
    /// below a live radio.
    func runWithoutRadiosForTesting(posture: PresenceEpochPosture) {
        self.posture = posture
        isRunning = true
    }

    /// The session-stable handle for an endpoint key, minting the identity exactly as a browse
    /// result does — so a test can hold the handle for a peer this radio has seen and then lost,
    /// which is the state a friend's own epoch boundary leaves behind.
    func handleForTesting(_ key: MeshLinkKey) -> PeerHandle { handle(for: key) }

    /// Records a browsed endpoint's instance name exactly as ``noteBrowsed(_:key:at:)`` records it,
    /// minus the framework endpoint a unit test cannot build. That name is the peer's half of the
    /// tie-break.
    func noteBrowsedNameForTesting(_ key: MeshLinkKey, instanceName: String) {
        browsedRecords[key] = MeshEndpointRecord(
            key: key,
            instanceName: instanceName,
            advertisement: [:],
            lastSeenAt: Date()
        )
    }

    /// Drives one whole SIGHTING exactly as a browse result drives it — the record, the
    /// `presence.quic.sighted` audit line and the owner's discovery callback — minus the framework
    /// endpoint a unit test cannot build.
    ///
    /// Distinct from ``noteBrowsedNameForTesting(_:instanceName:)``, which plants only the name the
    /// glare tie-break reads and deliberately emits nothing.
    func noteBrowsedForTesting(
        _ key: MeshLinkKey,
        instanceName: String,
        advertisement: [String: String]
    ) {
        recordBrowsed(key: key, instanceName: instanceName, advertisement: advertisement, at: Date())
    }

    /// Books a tunnel exactly as ``dial(_:helloTag:)`` and ``serveInbound(stream:pendingKey:)``
    /// record one, minus the framework connection and stream a unit test cannot build. Mirrors
    /// `NetworkMeshSession.bookTunnelForTesting(_:role:verified:)`.
    func bookTunnelForTesting(_ key: MeshLinkKey, role: MeshChannelRole) {
        let channel = prepareChannel(for: key)
        tunnels[key] = Tunnel(peer: channel.peer, channel: channel, role: role)
    }

    /// Runs the glare gate ``serveInbound(stream:pendingKey:)`` runs, and answers exactly what it
    /// answers: may an inbound connection that resolved to `key` take that key's tunnel slot?
    func admitInboundForTesting(at key: MeshLinkKey) -> Bool {
        admitInbound(at: key)
    }

    /// How many inbound connections are mid-hello.
    var pendingInboundCountForTesting: Int { pendingInbound.count }

    /// The channel this radio would hand the owner for `peer`, built exactly as the live path
    /// builds one. ``PresenceRadioSession`` requirement.
    func channel(for peer: PeerHandle) -> NetworkPeerChannel {
        NetworkPeerChannel(peer: peer, host: self)
    }
}

// MARK: - Listener and browser

private extension NetworkPresenceSession {

    /// Brings up the QUIC listener over Bonjour under the posture's name and identity.
    func startListener() throws {
        guard let posture else { throw MeshTransportError.tlsIdentityUnavailable }
        let listener = try NetworkListener(
            for: .bonjour(
                name: posture.instanceName,
                type: Self.serviceType,
                txtRecord: NWTXTRecord(advertisedFields)
            ),
            using: ProximityQUICParameters.listener(
                alpn: Self.alpn,
                identity: posture.tlsIdentity.identity
            )
        ).newConnectionLimit(Self.maxTunnels)
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
                // A cancel is this radio tidying itself, never a failure: ``republish(posture:
                // discoveryInfo:)`` cancels this task at EVERY epoch boundary and every roster
                // refresh, because re-creating the listener is the only way to withdraw a Bonjour
                // registration. Reporting a `CancellationError` would hand the owner a start
                // failure and stand presence down every 900 s.
                guard !Task.isCancelled else { return }
                self?.report("The presence listener stopped: \(error)")
            }
        }
        FernletAuditLog.log("presence.quic.advertised", context: auditContext(for: posture))
    }

    /// Stands the listener down and forgets it, keeping every tunnel.
    func cancelListener() {
        listenerTask?.cancel()
        listenerTask = nil
        listener = nil
        listenerIsReady = false
        listenerIsAdvertised = false
    }

    /// Stands the browser down and forgets it, keeping every tunnel.
    func cancelBrowser() {
        browserTask?.cancel()
        browserTask = nil
        browser = nil
    }

    /// Starts browsing once the listener is both ready and advertised — browsing earlier finds
    /// peers this device cannot yet be found by.
    func startBrowser() {
        guard isRunning, browser == nil else { return }
        let browser = NetworkBrowser(
            for: .bonjour(Self.serviceType, includeTxtRecord: true),
            using: ProximityQUICParameters.connection(alpn: Self.alpn).parameters
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
                // Same rule as the listener task above: ``stop()`` cancels this one, and a
                // cancellation reported as a start failure stands the radio down on the way down.
                guard !Task.isCancelled else { return }
                self?.report("The presence browser stopped: \(error)")
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
            Self.logger.debug("presence listener waiting: \(error.localizedDescription, privacy: .public)")
        case .failed(let error):
            report("The presence listener failed: \(error.localizedDescription)")
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
            report("The presence browser failed: \(error.localizedDescription)")
        case .waiting(let error):
            Self.logger.debug("presence browser waiting: \(error.localizedDescription, privacy: .public)")
        case .ready, .setup, .cancelled:
            break
        @unknown default:
            break
        }
    }

    /// The diagnostic context for one posture: the epoch in the clear, the instance name and the
    /// certificate digest under `FernletAuditLog`'s `.private` redaction.
    ///
    /// Every value here is **this device's own**, and that is the whole of the exception: the two
    /// lines that carry it (`presence.quic.advertised` and `.rotated`) are what a tier-2 runner
    /// reads across a boundary — our name A and digest A before it, our name B and digest B after,
    /// on each device, with no byte in common. No PEER's name or tag is logged anywhere in this
    /// file; a browsed peer is named by ``peerLabel(for:)``, which is opaque in the sense the
    /// endpoint key only looked — the key carries the peer's advertised instance name verbatim.
    /// `.private` shows on a Simulator and redacts on a device, which is the correct asymmetry —
    /// the values are public on the air, but a device log is not a place to accumulate them.
    func auditContext(for posture: PresenceEpochPosture) -> [String: String] {
        [
            "epoch": String(posture.epoch),
            "name": posture.instanceName,
            "certificate": Self.certificateDigest(of: posture)
        ]
    }

    func report(_ message: String) {
        Self.logger.error("\(message, privacy: .public)")
        onTransportError?(message)
    }
}

// MARK: - Discovery

private extension NetworkPresenceSession {

    /// One browse result set: refresh what is known, announce arrivals, announce departures.
    ///
    /// The local advertisement is filtered out by instance name, which is the posture's — never a
    /// session-minted one. `PresenceManager` keeps a bounded ring of our own PREVIOUS epochs' names
    /// for the same job, because a stale Bonjour cache can still be carrying one of those and this
    /// filter only knows the name currently worn.
    func observe(_ endpoints: [Bonjour.Endpoint]) {
        guard isRunning else { return }
        let now = Date()
        let ownName = posture?.instanceName
        var seen: Set<MeshLinkKey> = []
        for endpoint in endpoints.prefix(Self.maxBrowsedEndpoints) where endpoint.name != ownName {
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
    /// Re-announcing on change is load-bearing here for the same reason it is on the mesh: a
    /// Bonjour peer is routinely seen before its TXT record arrives, so a first sighting can carry
    /// no tags at all and the owner would never re-evaluate it if the late record went unannounced.
    func noteBrowsed(_ endpoint: Bonjour.Endpoint, key: MeshLinkKey, at now: Date) {
        browsedEndpoints[key] = endpoint
        recordBrowsed(
            key: key,
            instanceName: endpoint.name,
            advertisement: endpoint.txtRecord.dictionary,
            at: now
        )
    }

    /// The framework-free half of ``noteBrowsed(_:key:at:)``: everything a browse result does to
    /// this session's own state, the audit line included, with no `Bonjour.Endpoint` in sight.
    ///
    /// Split out so the sighting path — and in particular what its audit line carries — is
    /// reachable at tier 1. A unit test cannot build a `Bonjour.Endpoint`, so before the split the
    /// one line that named a peer was observable only by starting a real radio.
    func recordBrowsed(
        key: MeshLinkKey,
        instanceName: String,
        advertisement: [String: String],
        at now: Date
    ) {
        let previous = browsedRecords[key]?.advertisement
        browsedRecords[key] = MeshEndpointRecord(
            key: key,
            instanceName: instanceName,
            advertisement: advertisement,
            lastSeenAt: now
        )
        guard previous != advertisement else { return }
        // The line names the peer by ``peerLabel(for:)`` — the same opaque, salted, session-scoped
        // token every other per-peer line in this file uses — and never by the endpoint key, which
        // CONTAINS the instance name the peer advertises; and it counts the tags rather than
        // carrying them. A peer's name and a peer's tag are both values a log reader could
        // correlate two sightings with, which is the exact linkage the whole posture rotation
        // exists to break; "no identities in any log line" has to hold for the peer's identifiers
        // as strictly as it does for ours. Logging `key.rawValue` here is what P9 item 2's tier-2
        // run caught: every observed line read `peer=fn-<the peer's own name>…`.
        FernletAuditLog.log(
            "presence.quic.sighted",
            context: [
                "peer": peerLabel(for: key),
                "tags": String(PresenceAdvertisement.tags(from: advertisement).count)
            ]
        )
        onPeerDiscovered?(handle(for: key))
    }

    /// Drops an endpoint that left the browse results. Its cache entry survives only while a tunnel
    /// to it does, so a live heart connection is never stranded without an endpoint to answer on.
    func noteLost(_ key: MeshLinkKey) {
        let peer = handle(for: key)
        browsedEndpoints.removeValue(forKey: key)
        if tunnels[key] == nil { browsedRecords.removeValue(forKey: key) }
        onPeerLost?(peer)
    }

    /// The session-stable handle for an endpoint.
    ///
    /// `advertisedFingerprint` is always nil: this radio publishes no `fp` and believes no inbound
    /// one. `displayHint` is the peer's per-epoch random instance name — a hint, never a name shown
    /// to anyone, and the value `PresenceManager`'s own-ghost filter compares against.
    func handle(for key: MeshLinkKey) -> PeerHandle {
        let identity = identities.identity(for: key)
        let record = browsedRecords[key]
        return PeerHandle(
            id: identity.id,
            displayHint: record?.instanceName ?? key.rawValue,
            discoveryInfo: record?.advertisement,
            advertisedFingerprint: nil,
            endpoint: identity.endpoint
        )
    }

    /// The channel for an endpoint, reusing the live one so a reconnect does not orphan the
    /// publishers an owner is already subscribed to.
    func prepareChannel(for key: MeshLinkKey) -> NetworkPeerChannel {
        if let existing = tunnels[key]?.channel { return existing }
        return NetworkPeerChannel(peer: handle(for: key), host: self)
    }

    /// The first ``certificateDigestLength`` hexadecimal characters of the SHA-256 of a posture's
    /// certificate — a per-epoch label for a diagnostic line, never an identity and never on the
    /// wire. Not a cryptographic decision: nothing compares two of these.
    static func certificateDigest(of posture: PresenceEpochPosture) -> String {
        let digest = SHA256.hash(data: posture.tlsIdentity.certificateDER)
        return String(digest.map { String(format: "%02x", $0) }.joined().prefix(certificateDigestLength))
    }
}

// MARK: - Tunnels

private extension NetworkPresenceSession {

    /// Dialing side: open the control stream, write the dial hello, then read app frames.
    ///
    /// The channel is handed to the owner as soon as the hello is written rather than after any
    /// acknowledgement, because there is none to wait for: a responder that refuses the hello
    /// cancels its connection, which surfaces here as an ended tunnel and, above, as the owner's
    /// pre-connect retry. That is the same shape MC had — an invitation that is declined produces a
    /// disconnect, not a rejection message.
    func runInitiator(_ connection: NetworkConnection<QUIC>, key: MeshLinkKey, helloTag: String) async {
        do {
            let stream = try await connection.openStream()
            let hello = try PresenceDialHello.encoded(tag: helloTag)
            var frame = NetworkMeshWire.header(for: hello.count)
            frame.append(hello)
            try await stream.send(frame)
            activate(key, stream: stream)
            try await receiveFrames(for: key, from: stream)
        } catch {
            guard !Task.isCancelled else { return }
            endTunnel(key, reason: "The outbound presence connection ended: \(error.localizedDescription)")
        }
    }

    /// Takes an inbound QUIC connection as *pending*: nothing is admitted, no channel exists and no
    /// handle is minted for an owner until the dial hello has resolved to a browsed peer.
    func acceptInbound(_ connection: NetworkConnection<QUIC>) {
        guard isRunning else { return }
        let pendingKey = MeshLinkKey(connection.id)
        guard pendingInbound[pendingKey] == nil, pendingInbound.count < Self.maxPendingInbound else {
            Self.logger.debug("presence connection refused pre-hello for \(self.peerLabel(for: pendingKey), privacy: .public)")
            return
        }
        pendingInbound[pendingKey] = Task { @MainActor [weak self] in
            await self?.runResponder(connection, pendingKey: pendingKey)
        }
    }

    /// Listening side: serve the peer's control stream and ignore every other stream.
    ///
    /// The control stream is the peer's stream 0 and only ever that. Presence opens no per-transfer
    /// streams, so a second stream is something this protocol does not produce; it is dropped
    /// rather than served.
    func runResponder(_ connection: NetworkConnection<QUIC>, pendingKey: MeshLinkKey) async {
        do {
            try await connection.inboundStreams { stream in
                guard stream.streamID == Self.controlStreamID else { return }
                guard self.pendingInbound[pendingKey] != nil else { return }
                await self.serveInbound(stream: stream, pendingKey: pendingKey)
            }
        } catch {
            guard !Task.isCancelled else { return }
            dropPendingInbound(pendingKey)
        }
    }

    /// Reads the dial hello and, only if it resolves to a browsed peer the owner accepts and
    /// ``admitInbound(at:)`` gives it the slot, promotes the pending connection to a real tunnel.
    ///
    /// Every early return drops the pending connection whole: no channel is built and no handle is
    /// minted for an owner. That is the "no leakage" property, and it holds by construction —
    /// everything downstream needs a resolved ``PeerHandle`` this path does not have.
    ///
    /// The pending entry is checked BEFORE ``admitInbound(at:)`` and removed after, so the one
    /// guard in the chain with an effect (it may close a tunnel) can never run for a connection
    /// that has already been dropped.
    func serveInbound(stream: Network.QUIC.Stream<QUICStream>, pendingKey: MeshLinkKey) async {
        guard let hello = await readDialHello(from: stream),
              let peer = resolveDialer?(hello.tag),
              let key = identities.key(for: peer),
              pendingInbound[pendingKey] != nil,
              admitInbound(at: key),
              let owning = pendingInbound.removeValue(forKey: pendingKey) else {
            dropPendingInbound(pendingKey)
            return
        }
        let channel = prepareChannel(for: key)
        tunnels[key] = Tunnel(peer: channel.peer, channel: channel, role: .responder, task: owning)
        activate(key, stream: stream)
        do {
            try await receiveFrames(for: key, from: stream)
        } catch {
            guard !Task.isCancelled else { return }
            endTunnel(key, reason: "The inbound presence connection ended: \(error.localizedDescription)")
        }
    }

    /// Whether an inbound connection that resolved to `key` may take that key's one tunnel slot,
    /// closing whatever it displaces — the glare resolution the type's ## Glare section describes.
    ///
    /// The verdict is the mesh's ``MeshTunnelConvergence``, computed over the two advertised
    /// **instance names** in place of the mesh's two session ids. They are the same shape of value
    /// — a random per-epoch token each side publishes and the other browses — and they are the only
    /// pair of facts both devices hold and agree on here, because presence runs no signed channel
    /// introduction and so has no verified identity to rank at this point.
    ///
    /// Three outcomes, and each is deliberate:
    ///
    /// * **No tunnel yet** — the ordinary case, admitted under ``maxTunnels``.
    /// * **`.keepEstablished`** — the connection we already hold is the survivor, so this one is
    ///   dropped. That is not a refusal of the peer: the peer is connected to us, on the tunnel
    ///   that won. The far side computes the same verdict and yields, so nothing is left dangling.
    /// * **`.keepIncoming`** (and `.keepBoth`) — we yield. The established tunnel is ended through
    ///   ``endTunnel(_:reason:notifyOwner:)`` with the owner TOLD, which is load-bearing rather
    ///   than incidental: the owner's channel-ready gate answers "already connected" for a device
    ///   it still holds a record for, so a yield that stayed quiet would hand the fresh channel to
    ///   an owner that dropped it on the floor and left a coordinator waiting on a dead connection.
    ///   `.keepBoth` cannot be represented — one browsed key holds one tunnel — and is read as a
    ///   yield because that is the branch which can never end with zero tunnels; it is in any case
    ///   unreachable between two real postures, whose names are 64 bits of fresh entropy each.
    ///
    /// Answers `false` when either name is missing (a radio with no posture is on its way down),
    /// which is the fail-closed direction.
    func admitInbound(at key: MeshLinkKey) -> Bool {
        guard let established = tunnels[key] else { return tunnels.count < Self.maxTunnels }
        guard let localName = posture?.instanceName,
              let peerName = browsedRecords[key]?.instanceName else { return false }
        let verdict = MeshTunnelConvergence.resolve(
            incomingRole: .responder,
            establishedRole: established.role,
            localSessionID: localName,
            peerSessionID: peerName
        )
        guard verdict != .keepEstablished else {
            auditRedundantTunnelClosed(key, kept: "established")
            return false
        }
        endTunnel(key, reason: Self.redundantTunnelCloseReason)
        auditRedundantTunnelClosed(key, kept: "incoming")
        return true
    }

    /// The one audit line for a collapsed duplicate, naming the peer by ``peerLabel(for:)`` and
    /// which half survived. Never the endpoint key, which carries the peer's advertised instance
    /// name verbatim — see ``noteBrowsed(_:key:at:)``.
    func auditRedundantTunnelClosed(_ key: MeshLinkKey, kept: String) {
        FernletAuditLog.log(
            "presence.quic.redundantTunnelClosed",
            context: ["peer": peerLabel(for: key), "kept": kept]
        )
    }

    /// Reads exactly one length-framed ``PresenceDialHello``, or nil for anything else.
    func readDialHello(from stream: Network.QUIC.Stream<QUICStream>) async -> PresenceDialHello? {
        do {
            let header = try await stream.receive(exactly: NetworkMeshWire.headerByteCount).content
            let length = try NetworkMeshWire.payloadLength(
                from: header,
                ceiling: PresenceDialHello.maxEncodedBytes
            )
            let payload = try await stream.receive(exactly: length).content
            return PresenceDialHello.decoded(payload)
        } catch {
            return nil
        }
    }

    /// Drops a pending inbound connection, cancelling the task that owns it. Idempotent, and safe
    /// to call from inside that task — cancelling itself is how the connection is closed.
    func dropPendingInbound(_ key: MeshLinkKey) {
        pendingInbound.removeValue(forKey: key)?.cancel()
    }

    /// Records the control stream and hands the channel to the owner.
    func activate(_ key: MeshLinkKey, stream: Network.QUIC.Stream<QUICStream>) {
        guard var tunnel = tunnels[key] else { return }
        tunnel.controlStream = stream
        tunnels[key] = tunnel
        FernletAuditLog.log("presence.quic.connected", context: ["tunnels": String(tunnels.count)])
        onPeerChannelReady?(tunnel.channel)
    }

    /// Reads length-framed app frames off a control stream and routes them to the channel.
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

    /// Ends a tunnel, telling the channel either way and the owner unless it asked for the end.
    func endTunnel(_ key: MeshLinkKey, reason: String, notifyOwner: Bool = true) {
        guard let tunnel = tunnels.removeValue(forKey: key) else { return }
        tunnel.task?.cancel()
        Self.logger.notice("presence tunnel ended for \(self.peerLabel(for: key), privacy: .public): \(reason, privacy: .public)")
        tunnel.channel.notifyDisconnected(reason: reason)
        guard notifyOwner else { return }
        onPeerDisconnected?(tunnel.peer, reason)
    }
}
