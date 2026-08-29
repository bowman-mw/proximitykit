import Foundation
import Combine
import FernletDomainModel

/// Namespace for shared Bonjour service-type constants.
///
/// Only the coach channel's `fernlet-coach` lives here; the friend and presence radios declare
/// their service types on their owning session/manager types. Every service type must also
/// appear in the app's Info.plist `NSBonjourServices` or discovery silently fails on device.
///
/// The values are frozen wire tokens. Nothing in the test suite pins the literal — a changed
/// spelling compiles, passes CI, and shows up only as dead discovery on a physical device.
nonisolated public enum MultipeerServiceType {
    public static let trainer = "fernlet-coach"
}

/// How reliably a frame must be delivered.
///
/// The transport-neutral replacement for `MCSessionSendDataMode`, mapped to the framework's own
/// mode inside the conformer that owns the framework. `reliable` is ordered and retransmitted;
/// `bestEffort` may be dropped or reordered and is used only where loss is acceptable.
public enum PeerDeliveryMode: Sendable {
    case reliable
    case bestEffort
}

/// Observable lifecycle of a ``PeerTransport``, from idle discovery through connection to
/// failure/disconnect.
///
/// ``ProximityCoordinator`` subscribes to this stream and drives its own handshake state machine
/// off the transitions (e.g. `.connected` triggers the identity introduction in friend mode).
///
/// Note that the production conformer, `PeerChannelTransport`, only ever emits `.idle`,
/// `.connected` and `.disconnected` — the shared session owns discovery, so the discovery-shaped
/// cases are reachable only from a test fake. Coordinator branches keyed on them are therefore
/// exercised by tests alone; the live inviter decision is `MeshNetworkManager.shouldInitiateInvite`.
public enum PeerTransportState: Equatable {
    case idle
    case advertising
    case browsing
    case discovered([PeerHandle])
    case awaitingPeerAcceptance(PeerHandle)
    case awaitingLocalAcceptance(PeerPendingInvite)
    case connecting(PeerHandle)
    case connected(PeerHandle)
    case disconnected(reason: String)
    case failed(PeerTransportError)

    public static func == (lhs: PeerTransportState, rhs: PeerTransportState) -> Bool {
        switch (lhs, rhs) {
        case (.idle, .idle), (.advertising, .advertising), (.browsing, .browsing):
            return true
        case (.discovered(let a), .discovered(let b)):                       return a == b
        case (.awaitingPeerAcceptance(let a), .awaitingPeerAcceptance(let b)): return a == b
        case (.awaitingLocalAcceptance(let a), .awaitingLocalAcceptance(let b)): return a == b
        case (.connecting(let a), .connecting(let b)):                       return a == b
        case (.connected(let a), .connected(let b)):                         return a == b
        case (.disconnected(let a), .disconnected(let b)):                   return a == b
        case (.failed(let a), .failed(let b)):                               return a == b
        default: return false
        }
    }
}

/// An inbound invitation awaiting a local accept/reject decision.
///
/// Carries the single-shot `respond` callback from the transport's advertiser side; equality
/// ignores it (peer + info + context only). Surfaced as `.awaitingLocalAcceptance` — friend mode
/// auto-accepts, trainer mode presents it to the user.
public struct PeerPendingInvite: Equatable {
    public let peer: PeerHandle
    public let advertisedInfo: [String: String]
    public let context: Data?
    public let respond: (Bool) -> Void

    public init(
        peer: PeerHandle,
        advertisedInfo: [String: String],
        context: Data?,
        respond: @escaping (Bool) -> Void
    ) {
        self.peer = peer
        self.advertisedInfo = advertisedInfo
        self.context = context
        self.respond = respond
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.peer == rhs.peer && lhs.advertisedInfo == rhs.advertisedInfo && lhs.context == rhs.context
    }
}

/// Failures a ``PeerTransport`` can surface — radio availability, session lifecycle, and
/// per-send errors.
///
/// `sendFailed` wraps the underlying transport error description; the others describe states
/// callers can retry or surface to the user.
public enum PeerTransportError: Equatable, Error {
    case wifiUnavailable, bluetoothUnavailable, peerIDLoadFailed
    case sessionRejected, sessionTimeout, unexpectedState
    case sendFailed(reason: String)
}

/// One raw inbound data frame from a peer, as delivered on ``PeerTransport/inbound``.
///
/// The bytes are untrusted wire input — ``ProximityCoordinator`` decodes, size-gates, and
/// signature-verifies them before anything downstream sees the payload.
public struct InboundPeerFrame {
    public let peer: PeerHandle
    public let data: Data
    public let receivedAt: Date
    public let bytesReceived: Int

    public init(peer: PeerHandle, data: Data, receivedAt: Date, bytesReceived: Int) {
        self.peer = peer
        self.data = data
        self.receivedAt = receivedAt
        self.bytesReceived = bytesReceived
    }
}

/// The transport abstraction ``ProximityCoordinator`` drives: advertise/browse, invite/accept,
/// reliable/best-effort send, and Combine streams of state + inbound data.
///
/// No framework type appears anywhere on this surface — that is the whole point of it. The
/// production conformer is `PeerChannelTransport`, a per-peer routing adapter over the shared
/// `MeshMultipeerSession`, so a coordinator never manages MultipeerConnectivity lifecycle itself;
/// tests inject scripted fakes. A second conformer over Network.framework QUIC slots in beside it
/// in P2 without any change here. `@MainActor`: the coordinator and every conformer live on the
/// main actor, with delegate callbacks hopped in.
@MainActor
public protocol PeerTransport: AnyObject {
    var state: AnyPublisher<PeerTransportState, Never> { get }
    var inbound: AnyPublisher<InboundPeerFrame, Never> { get }
    var connectedPeers: [PeerHandle] { get }

    func startAdvertising(serviceType: String, discoveryInfo: [String: String]) async throws
    func startBrowsing(serviceType: String) async throws
    func invite(_ peer: PeerHandle) async throws
    func accept(_ invite: PeerPendingInvite) async throws
    func send(_ data: Data, to peer: PeerHandle, mode: PeerDeliveryMode) async throws
    func disconnect() async
}
