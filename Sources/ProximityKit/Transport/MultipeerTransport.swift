import Foundation
import MultipeerConnectivity
import Combine
import FernletDomainModel

nonisolated public enum MultipeerServiceType {
    public static let trainer = "fernlet-coach"
}

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

public enum MultipeerTransportError: Equatable, Error {
    case wifiUnavailable, bluetoothUnavailable, peerIDLoadFailed
    case sessionRejected, sessionTimeout, unexpectedState
    case sendFailed(reason: String)
}

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
