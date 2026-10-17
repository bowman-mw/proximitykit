import ProximityKit
import Foundation
import Combine

@MainActor
final class MockMultipeerTransport: PeerTransport {

    private let stateSubject = CurrentValueSubject<PeerTransportState, Never>(.idle)
    private let inboundSubject = PassthroughSubject<InboundPeerFrame, Never>()

    var state: AnyPublisher<PeerTransportState, Never> { stateSubject.eraseToAnyPublisher() }
    var inbound: AnyPublisher<InboundPeerFrame, Never> { inboundSubject.eraseToAnyPublisher() }
    var connectedPeers: [PeerHandle] = []

    // Recorded calls
    var advertisingStarted = false
    var browsingStarted = false
    var lastDiscoveryInfo: [String: String]?
    var disconnectCalled = false
    var sendDelayNanoseconds: UInt64 = 0
    var sentData: [(Data, PeerHandle, PeerDeliveryMode)] = []
    var acceptedInvites: [PeerPendingInvite] = []

    // MARK: PeerTransport

    func startAdvertising(discoveryInfo: [String: String]) async throws {
        advertisingStarted = true
        lastDiscoveryInfo = discoveryInfo
        stateSubject.send(.advertising)
    }

    func startBrowsing() async throws {
        browsingStarted = true
        stateSubject.send(.browsing)
    }

    func invite(_ peer: PeerHandle) async throws {
        stateSubject.send(.awaitingPeerAcceptance(peer))
    }

    func accept(_ invite: PeerPendingInvite) async throws {
        acceptedInvites.append(invite)
        invite.respond(true)
    }

    func send(_ data: Data, to peer: PeerHandle, mode: PeerDeliveryMode) async throws {
        if sendDelayNanoseconds > 0 {
            try? await Task.sleep(nanoseconds: sendDelayNanoseconds)
        }
        sentData.append((data, peer, mode))
    }

    func disconnect() async {
        disconnectCalled = true
        connectedPeers = []
        stateSubject.send(.idle)
    }

    // MARK: Simulation helpers

    func simulateDiscovery(peer: PeerHandle) {
        if case .discovered(let existing) = stateSubject.value {
            stateSubject.send(.discovered(existing + [peer]))
        } else {
            stateSubject.send(.discovered([peer]))
        }
    }

    func simulatePeerLost(peer: PeerHandle) {
        if case .discovered(let existing) = stateSubject.value {
            stateSubject.send(.discovered(existing.filter { $0.id != peer.id }))
        }
    }

    func simulateInvite(from peer: PeerHandle, info: [String: String] = [:]) {
        let invite = PeerPendingInvite(
            peer: peer,
            advertisedInfo: info,
            context: nil,
            respond: { [weak self] accepted in
                guard let self, accepted else { return }
                self.stateSubject.send(.connecting(peer))
            }
        )
        stateSubject.send(.awaitingLocalAcceptance(invite))
    }

    /// The MC-realistic two-step: a `.connecting` event lands before `.connected` (the real
    /// session delegate always reports both), which is what puts a trainer coordinator into
    /// `.awaitingTapConfirmation` BEFORE the connected event — the second of the tap-gate
    /// auto-advance's two entry points.
    func simulateConnecting(peer: PeerHandle) {
        stateSubject.send(.connecting(peer))
    }

    func simulateConnected(peer: PeerHandle) {
        connectedPeers = [peer]
        stateSubject.send(.connected(peer))
    }

    func simulateInboundData(_ data: Data, from peer: PeerHandle) {
        let msg = InboundPeerFrame(peer: peer, data: data, receivedAt: Date(), bytesReceived: data.count)
        inboundSubject.send(msg)
    }

    func simulateDisconnection() {
        connectedPeers = []
        stateSubject.send(.disconnected(reason: "Simulated disconnection"))
    }
}
