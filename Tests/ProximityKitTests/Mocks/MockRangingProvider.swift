import ProximityKit
import Foundation
import Combine
import simd
import FernletDomainModel

@MainActor
final class MockRangingProvider: RangingProvider {

    let isHardwareSupported: Bool

    private let distanceSubject = PassthroughSubject<RangingDistance, Never>()
    private let stateSubject: CurrentValueSubject<RangingState, Never>

    var distance: AnyPublisher<RangingDistance, Never> { distanceSubject.eraseToAnyPublisher() }
    var state: AnyPublisher<RangingState, Never> { stateSubject.eraseToAnyPublisher() }

    // Recorded calls
    var startCalled = false
    var stopCalled = false
    var lastPeerTokenData: Data?

    init(isHardwareSupported: Bool = true) {
        self.isHardwareSupported = isHardwareSupported
        self.stateSubject = CurrentValueSubject(isHardwareSupported ? .idle : .fallback(rssiOnly: true))
    }

    func start(with peerToken: Data) async throws {
        startCalled = true
        lastPeerTokenData = peerToken
        stateSubject.send(isHardwareSupported ? .running : .fallback(rssiOnly: true))
    }

    func stop() async {
        stopCalled = true
        stateSubject.send(.idle)
    }

    func myDiscoveryToken() async throws -> Data {
        guard isHardwareSupported else { throw RangingError.hardwareUnsupported }
        return Data(repeating: 0xAB, count: 32)
    }

    // MARK: Simulation helpers

    func simulateDistance(_ meters: Double, direction: simd_float3? = nil) {
        distanceSubject.send(.meters(meters, direction: direction))
    }

    func simulateUnknownDistance() {
        distanceSubject.send(.unknown)
    }

    func simulateInvalidated(reason: String) {
        stateSubject.send(.invalidated(reason: reason))
    }
}
