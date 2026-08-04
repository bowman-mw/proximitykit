import Foundation
import Combine
import simd
import FernletDomainModel

/// A single distance reading from a ranging provider: either a measured distance in meters
/// (with an optional UWB direction vector) or no reading at all.
///
/// Published by ``RangingProvider/distance`` and consumed by ``ProximityCoordinator`` and
/// ``ProximityCommitDetector`` to drive the dwell-commit gates.
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

/// Lifecycle of a ranging session, published by ``RangingProvider/state``.
///
/// `fallback(rssiOnly:)` signals that precise UWB measurement is unavailable and the coordinator
/// should degrade to the manual-commit path; `invalidated` carries the framework's reason string.
public enum RangingState: Equatable {
    case idle
    case running
    case invalidated(reason: String)
    case fallback(rssiOnly: Bool)
}

/// Abstraction over peer-to-peer distance measurement for the proximity handshake.
///
/// The production conformer is ``NIRangingSession`` (NearbyInteraction / UWB); tests inject fakes.
/// ``ProximityCoordinator`` exchanges discovery tokens through `myDiscoveryToken()` inside the
/// signed identity intro, starts ranging with the peer's token, and feeds the `distance` stream
/// into its commit detectors. `isHardwareSupported == false` means the provider only ever reports
/// the RSSI fallback and the coordinator uses manual commit instead of the UWB dwell. `@MainActor`:
/// implementations bridge framework delegate callbacks onto the main actor.
@MainActor
public protocol RangingProvider: AnyObject {
    var distance: AnyPublisher<RangingDistance, Never> { get }
    var state: AnyPublisher<RangingState, Never> { get }
    var isHardwareSupported: Bool { get }

    func start(with peerToken: Data) async throws
    func stop() async
    func myDiscoveryToken() async throws -> Data
}
