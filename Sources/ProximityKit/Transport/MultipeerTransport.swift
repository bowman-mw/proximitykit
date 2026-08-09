import Foundation
import MultipeerConnectivity
import Combine
import FernletDomainModel

/// Namespace for shared Bonjour service-type constants.
///
/// Only the coach channel's `fernlet-coach` lives here; the friend and presence radios declare
/// their service types on their owning session/manager types. Every service type must also
/// appear in the app's Info.plist `NSBonjourServices` or discovery silently fails on device.
nonisolated public enum MultipeerServiceType {
    public static let trainer = "fernlet-coach"
}

/// Observable lifecycle of a ``MultipeerTransport``, from idle discovery through connection to
/// failure/disconnect.
///
/// ``ProximityCoordinator`` subscribes to this stream and drives its own handshake state machine
/// off the transitions (e.g. `.connected` triggers the identity introduction in friend mode).
public enum MultipeerTransportState: Equatable {
    case idle
    case advertising
    case browsing
    case discovered([MultipeerPeer])
    case awaitingPeerAcceptance(MultipeerPeer)
    case awaitingLocalAcceptance(MultipeerPendingInvite)
    case connecting(MultipeerPeer)
    case connected(MultipeerPeer)
    case disconnected(reason: String)
    case failed(MultipeerTransportError)

    public static func == (lhs: MultipeerTransportState, rhs: MultipeerTransportState) -> Bool {
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

/// An inbound MC invitation awaiting a local accept/reject decision.
///
/// Carries the single-shot `respond` callback from the MC advertiser delegate; equality ignores
/// it (peer + info + context only). Surfaced as `.awaitingLocalAcceptance` — friend mode
/// auto-accepts, trainer mode presents it to the user.
public struct MultipeerPendingInvite: Equatable {
    public let peer: MultipeerPeer
    public let advertisedInfo: [String: String]
    public let context: Data?
    public let respond: (Bool) -> Void

    public init(
        peer: MultipeerPeer,
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

/// Failures a ``MultipeerTransport`` can surface — radio availability, session lifecycle, and
/// per-send errors.
///
/// `sendFailed` wraps the underlying MC error description; the others describe states callers
/// can retry or surface to the user.
public enum MultipeerTransportError: Equatable, Error {
    case wifiUnavailable, bluetoothUnavailable, peerIDLoadFailed
    case sessionRejected, sessionTimeout, unexpectedState
    case sendFailed(reason: String)
}

/// One raw inbound data frame from a peer, as delivered on ``MultipeerTransport/inbound``.
///
/// The bytes are untrusted wire input — ``ProximityCoordinator`` decodes, size-gates, and
/// signature-verifies them before anything downstream sees the payload.
public struct MultipeerInboundMessage {
    public let peer: MultipeerPeer
    public let data: Data
    public let receivedAt: Date
    public let bytesReceived: Int

    public init(peer: MultipeerPeer, data: Data, receivedAt: Date, bytesReceived: Int) {
        self.peer = peer
        self.data = data
        self.receivedAt = receivedAt
        self.bytesReceived = bytesReceived
    }
}

/// The transport abstraction ``ProximityCoordinator`` drives: advertise/browse, invite/accept,
/// reliable/unreliable send, and Combine streams of state + inbound data.
///
/// The production conformer is `PeerChannelTransport` — a per-peer routing adapter over the
/// shared `MeshMultipeerSession` MCSession — so a coordinator never manages MC lifecycle
/// itself; tests inject scripted fakes. `@MainActor`: the coordinator and every conformer live
/// on the main actor, with delegate callbacks hopped in.
@MainActor
public protocol MultipeerTransport: AnyObject {
    var state: AnyPublisher<MultipeerTransportState, Never> { get }
    var inbound: AnyPublisher<MultipeerInboundMessage, Never> { get }
    var connectedPeers: [MultipeerPeer] { get }

    func startAdvertising(serviceType: String, discoveryInfo: [String: String]) async throws
    func startBrowsing(serviceType: String) async throws
    func invite(_ peer: MultipeerPeer) async throws
    func accept(_ invite: MultipeerPendingInvite) async throws
    func send(_ data: Data, to peer: MultipeerPeer, mode: MCSessionSendDataMode) async throws
    func disconnect() async
}
