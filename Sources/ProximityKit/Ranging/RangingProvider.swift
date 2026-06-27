import Foundation
import Combine
import simd
import FernletDomainModel

public enum RangingDistance: Equatable {
    case unknown
    case meters(Double, direction: simd_float3?)

    public static func == (lhs: RangingDistance, rhs: RangingDistance) -> Bool {
        switch (lhs, rhs) {
        case (.unknown, .unknown): return true
        case (.meters(let d1, let dir1), .meters(let d2, let dir2)):
            return d1 == d2 && dir1 == dir2
        default: return false
        }
    }
}

public enum RangingState: Equatable {
    case idle
    case running
    case invalidated(reason: String)
    case fallback(rssiOnly: Bool)
}

@MainActor
public protocol RangingProvider: AnyObject {
    var distance: AnyPublisher<RangingDistance, Never> { get }
    var state: AnyPublisher<RangingState, Never> { get }
    var isHardwareSupported: Bool { get }

    func start(with peerToken: Data) async throws
    func stop() async
    func myDiscoveryToken() async throws -> Data
}
