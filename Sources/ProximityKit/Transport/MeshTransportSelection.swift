import Combine
import Foundation

// MARK: - MeshPeerChannel

/// A per-peer channel a shared mesh radio hands to its owner.
///
/// A ``PeerTransport`` that also knows which peer it carries and can be told to publish
/// `.connected` / `.disconnected`. `PeerChannelTransport` (MultipeerConnectivity) and
/// `NetworkPeerChannel` (QUIC) already had exactly this shape; the protocol only names it, so
/// `MeshNetworkManager` can hold a slot's channel without knowing which radio minted it.
///
/// `notifyConnected()` is the owner's call, never the radio's: the owner creates the slot's
/// coordinator and awaits its `begin()` first, because publishing `.connected` before that returns
/// is what put the handshake into the wrong branch. Both conformers document the same contract.
@MainActor
protocol MeshPeerChannel: PeerTransport {

    /// The peer this channel carries.
    var peer: PeerHandle { get }

    /// Publishes `.connected` for ``peer``.
    func notifyConnected()

    /// Publishes `.disconnected` with a diagnostic reason.
    func notifyDisconnected(reason: String)
}

extension PeerChannelTransport: MeshPeerChannel {}

extension NetworkPeerChannel: MeshPeerChannel {}

// MARK: - DetachedPeerChannel

/// A channel with no radio behind it: it publishes state locally and refuses every send.
///
/// The manager's `internal` test seams (`addSlotForTesting`, `makeRetainedSlotCoordinatorForTesting`)
/// need a slot channel, and a unit test has no live radio to put behind one. They used to build a
/// `PeerChannelTransport` over the manager's never-started `MeshMultipeerSession`, whose `send`
/// throws ``PeerTransportError/unexpectedState`` for want of an MCSession — this is that same
/// behaviour, said out loud, and it costs the manager one fewer reason to name a specific radio.
@MainActor
final class DetachedPeerChannel: MeshPeerChannel {

    let peer: PeerHandle

    private let stateSubject = CurrentValueSubject<PeerTransportState, Never>(.idle)
    private let inboundSubject = PassthroughSubject<InboundPeerFrame, Never>()

    var state: AnyPublisher<PeerTransportState, Never> { stateSubject.eraseToAnyPublisher() }
    var inbound: AnyPublisher<InboundPeerFrame, Never> { inboundSubject.eraseToAnyPublisher() }
    var connectedPeers: [PeerHandle] { [] }

    init(peer: PeerHandle) {
        self.peer = peer
    }

    // Discovery belongs to a shared session this channel does not have.
    func startAdvertising(serviceType: String, discoveryInfo: [String: String]) async throws {}
    func startBrowsing(serviceType: String) async throws {}
    func invite(_ peer: PeerHandle) async throws {}
    func accept(_ invite: PeerPendingInvite) async throws {}

    /// Always throws: there is no radio to carry the bytes, and a channel that silently swallowed
    /// them would let a test pass over a send that never happened.
    func send(_ data: Data, to peer: PeerHandle, mode: PeerDeliveryMode) async throws {
        throw PeerTransportError.unexpectedState
    }

    func disconnect() async {
        stateSubject.send(.idle)
    }

    func notifyConnected() {
        stateSubject.send(.connected(peer))
    }

    func notifyDisconnected(reason: String = "Peer disconnected") {
        stateSubject.send(.disconnected(reason: reason))
    }
}

// MARK: - MeshTransportHandlers

/// Everything a mesh radio calls back into its owner for, in one value.
///
/// One struct rather than five settable properties on ``MeshTransportSession``: the two radios store
/// their hooks under their own names and types (the MC session's channel hook is typed to
/// `PeerChannelTransport`, the QUIC session's to `NetworkPeerChannel`), so a settable protocol
/// property would need a getter that could not honestly answer. ``MeshTransportSession/wire(_:)``
/// takes the whole set instead, and each conformer forwards it to whatever it actually keeps.
///
/// Every closure here is expected to capture its owner weakly; a radio holds this struct for its
/// lifetime.
struct MeshTransportHandlers {

    /// A peer appeared in discovery. The owner decides whether to dial it.
    var onPeerDiscovered: ((PeerHandle) -> Void)?

    /// A peer's channel is live and ready to be given a coordinator.
    var onChannelReady: ((any MeshPeerChannel) -> Void)?

    /// A peer's link dropped, with a diagnostic reason.
    var onPeerDisconnected: ((PeerHandle, String) -> Void)?

    /// Whether to admit an inbound connection attempt. **Fail closed**: a radio with no gate wired
    /// refuses, exactly as `MeshMultipeerSession`'s advertiser does (`?? false`).
    var shouldAcceptInvitation: ((PeerHandle) -> Bool)?

    /// Discovery failed to start — a declined Local Network prompt, or a service type missing from
    /// `NSBonjourServices`. Surfaced to the user rather than searched-forever in silence.
    var onTransportError: ((String) -> Void)?
}

// MARK: - MeshTransportSession

/// The shared radio `MeshNetworkManager` drives, with neither radio's name on it.
///
/// `MeshMultipeerSession` and `NetworkMeshSession` are the two conformers. The manager owns one of
/// them through this protocol, so the suite can run the manager over an in-memory fake and the QUIC
/// conformer can be selected without a second copy of the manager.
///
/// `startRadios(discoveryInfo:)` rather than `start(discoveryInfo:)`: the MC session's own
/// `start(serviceType:discoveryInfo:)` defaults its service type, so a same-named forwarder would
/// read as direct recursion (Power of 10 rule 1) for no gain. The service type is each radio's own
/// affair now — the owner never picks one.
@MainActor
protocol MeshTransportSession: AnyObject {

    /// Installs the owner's callbacks. Called once, at wiring time.
    func wire(_ handlers: MeshTransportHandlers)

    /// Hands the radio the mesh id, epoch reference, roster and signing key its peer authentication
    /// needs. A no-op on the MC radio, which authenticates inside the coordinator's identity
    /// introduction instead; on the QUIC radio it is the difference between admitting a verified
    /// roster member and refusing every tunnel.
    func attachIntroductionAuthority(_ authority: any MeshIntroductionAuthority)

    /// Brings advertising and browsing up with the owner's discovery payload.
    func startRadios(discoveryInfo: [String: String])

    /// Tears the radio down and drops every peer-keyed record it held.
    func stop()

    /// Republishes the discovery payload.
    func updateDiscoveryInfo(_ info: [String: String])

    /// Opens a connection to a discovered peer. The inviter decision is the owner's
    /// (`MeshNetworkManager.shouldInitiateInvite`), never the radio's.
    func invite(_ peer: PeerHandle)

    /// Frees one peer's link. Best-effort on both radios — the owner's record eviction is what
    /// actually drives teardown.
    func disconnectPeer(_ peer: PeerHandle)
}

// MARK: - Conformances

extension MeshMultipeerSession: MeshTransportSession {

    func wire(_ handlers: MeshTransportHandlers) {
        onPeerDiscovered = handlers.onPeerDiscovered
        onPeerChannelReady = { channel in handlers.onChannelReady?(channel) }
        onPeerDisconnected = handlers.onPeerDisconnected
        shouldAcceptInvitation = handlers.shouldAcceptInvitation
        onTransportError = handlers.onTransportError
    }

    /// Deliberately empty. This radio's peers authenticate inside `ProximityCoordinator`'s signed
    /// identity introduction, over an already-established MC link; it has no transport-level
    /// admission decision to make and therefore no authority to consult. Holding a reference it
    /// never reads would be the misleading half.
    func attachIntroductionAuthority(_ authority: any MeshIntroductionAuthority) {}

    func startRadios(discoveryInfo: [String: String]) {
        start(serviceType: MeshMultipeerSession.friendServiceType, discoveryInfo: discoveryInfo)
    }
}

extension NetworkMeshSession: MeshTransportSession {

    func wire(_ handlers: MeshTransportHandlers) {
        onPeerDiscovered = handlers.onPeerDiscovered
        onPeerChannelReady = { channel in handlers.onChannelReady?(channel) }
        onPeerDisconnected = handlers.onPeerDisconnected
        onTransportError = handlers.onTransportError
        invitationGate = handlers.shouldAcceptInvitation
    }

    func attachIntroductionAuthority(_ authority: any MeshIntroductionAuthority) {
        introductionAuthority = authority
    }

    /// "Invite" is the MC word for it; on this radio it is a dial. Same decision, same owner, and
    /// the same refusal rules — ``MeshLinkTable`` still gets the last word on whether it happens.
    func invite(_ peer: PeerHandle) {
        dial(peer)
    }

    /// A failed listener is reported through the owner's transport-error hook rather than thrown:
    /// the owner's start path is the same on both radios, and the MC one cannot throw. The symptom
    /// a user sees — the discovery-failure banner — is identical either way.
    func startRadios(discoveryInfo: [String: String]) {
        do {
            try start(discoveryInfo: discoveryInfo)
        } catch {
            reportTransportError("The QUIC mesh radio could not start: \(error.localizedDescription)")
        }
    }
}

// MARK: - MeshTransportKind

/// Which radio the friend mesh runs on.
///
/// Frozen internal tokens: the raw values are parsed from a DEBUG-only environment variable and
/// never localized, persisted, or put on a wire.
enum MeshTransportKind: String, Sendable, CaseIterable {

    /// MultipeerConnectivity — the shipping default on every path.
    case multipeer

    /// Network.framework QUIC — opt-in, DEBUG-only, for the migration's tier-2 lanes.
    case quic
}

/// Builds the friend mesh's radio, and decides which one a build gets.
///
/// **MultipeerConnectivity is the default in every shipping path.** ``shippingDefault`` is the only
/// answer a Release build can produce — the environment read is compiled out — and nothing about the
/// choice is persisted: there is no setting, no UI, and no `UserDefaults` key, so the selection owes
/// no row on the persisted-surface wipe ledger. A DEBUG build can opt into QUIC for one launch with
/// ``quicSelectionEnvironmentKey``, which is how the migration's Simulator lanes drive it.
@MainActor
enum MeshTransportFactory {

    /// What every shipping build uses, unconditionally.
    static var shippingDefault: MeshTransportKind { .multipeer }

    #if DEBUG
    /// Launch environment key selecting the radio, e.g. `FERNLET_MESH_TRANSPORT=quic`. DEBUG only,
    /// per-launch, never written anywhere. An unrecognized value falls back to ``shippingDefault``
    /// rather than failing to start a radio at all.
    static let quicSelectionEnvironmentKey = "FERNLET_MESH_TRANSPORT"
    #endif

    /// The radio this build should use, given a launch environment.
    ///
    /// Takes the environment rather than reading `ProcessInfo` so the decision is a pure function a
    /// test can enumerate, including the Release answer.
    static func resolvedKind(environment: [String: String]) -> MeshTransportKind {
        #if DEBUG
        guard let raw = environment[quicSelectionEnvironmentKey] else { return shippingDefault }
        return MeshTransportKind(rawValue: raw) ?? shippingDefault
        #else
        return shippingDefault
        #endif
    }

    /// The radio this process should use.
    static func resolvedKind() -> MeshTransportKind {
        resolvedKind(environment: ProcessInfo.processInfo.environment)
    }

    /// Builds one radio of the given kind.
    static func makeSession(_ kind: MeshTransportKind) -> any MeshTransportSession {
        switch kind {
        case .multipeer: return MeshMultipeerSession()
        case .quic:      return NetworkMeshSession()
        }
    }
}
