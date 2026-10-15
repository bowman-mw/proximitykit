import Foundation
import Combine
import simd

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

/// What a ``RangingProvider`` throws, the same three cases for every provider (plan step A0.6.3 moved
/// the type here from `NIRangingSession`, so no host or test names an iOS-only type to catch one).
///
/// A provider without ranging hardware never throws from `start(with:)`: it reports
/// `.fallback(rssiOnly: true)` instead, and the coordinator takes the manual commit. Its text reaches
/// only a coordinator's inspector, never a wire, keychain or on-disk byte. `nonisolated`, as this
/// module's other value-type errors are, so it can be thrown and compared from any context.
public nonisolated enum RangingError: Error, Equatable, Sendable {
    /// `myDiscoveryToken()` was asked on a device or host with no ranging hardware.
    case hardwareUnsupported
    /// The local discovery token never populated, so there is none to offer the peer.
    case tokenUnavailable
    /// The peer's discovery token bytes did not decode, so ranging cannot start against it.
    case invalidPeerToken
}

/// Abstraction over peer-to-peer distance measurement for the proximity handshake.
///
/// Each connection's provider comes from its host's ``ProximityHost/makeProximityRangingProvider()``,
/// which the mesh's, the recipe radio's and a host's presence channel-ready doors call once per
/// connection; the coordinator built over it owns it and stops it. This module's conformers are
/// `NIRangingSession` (NearbyInteraction / UWB, iOS only) and ``NoopRangingProvider`` (no ranging, on
/// any platform); tests inject fakes. ``ProximityCoordinator`` exchanges discovery tokens through
/// `myDiscoveryToken()` inside the signed identity intro, starts ranging with the peer's token, and
/// feeds the `distance` stream into its commit detectors. `isHardwareSupported == false` means the
/// provider only ever reports the RSSI fallback and the coordinator uses manual commit instead of the
/// UWB dwell; such a provider is never started. A provider throws ``RangingError``. `@MainActor`:
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
