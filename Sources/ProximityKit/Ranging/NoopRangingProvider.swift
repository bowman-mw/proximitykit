import Foundation
import Combine

/// The ``RangingProvider`` for a device or a host without ranging: it measures nothing, so every
/// session over it commits by hand or by the QR verification ceremony (plan step A0.6.3).
///
/// A host on macOS, where NearbyInteraction's types are unavailable, or one that wants no ranging,
/// answers it from ``ProximityHost/makeProximityRangingProvider()``. It is identical, observable for
/// observable, to `NIRangingSession` on hardware without UWB, which is what every iPad runs:
/// - ``isHardwareSupported`` is `false`;
/// - ``state`` holds `.fallback(rssiOnly: true)` from construction, so a subscriber reads it first;
/// - ``start(with:)`` sends `.fallback(rssiOnly: true)` again and does not throw;
/// - ``stop()`` sends `.idle`;
/// - ``distance`` never sends a value and never completes (a subject the provider keeps, never an
///   `Empty`, which would complete at once);
/// - ``myDiscoveryToken()`` throws ``RangingError/hardwareUnsupported``.
///
/// So a ``ProximityCoordinator`` over it introduces itself as `rssi` with no discovery token, never
/// starts it, and waits at the manual-commit gate. It touches no framework and no radio and reads no
/// device capability. One per connection, like every provider: the coordinator owns and stops it.
/// `@MainActor`, as the protocol is.
@MainActor
public final class NoopRangingProvider: RangingProvider {

    /// Always `false`: this provider measures nothing.
    public let isHardwareSupported = false

    /// The distance stream's subject: kept and never sent to, so the stream neither sends nor
    /// completes.
    private let distanceSubject = PassthroughSubject<RangingDistance, Never>()

    /// The lifecycle's subject, holding the manual-commit fallback from construction.
    private let stateSubject = CurrentValueSubject<RangingState, Never>(.fallback(rssiOnly: true))

    /// Distances: never a value, never a completion.
    public var distance: AnyPublisher<RangingDistance, Never> { distanceSubject.eraseToAnyPublisher() }

    /// The lifecycle: `.fallback(rssiOnly: true)` from construction and after a start, `.idle` after a
    /// stop.
    public var state: AnyPublisher<RangingState, Never> { stateSubject.eraseToAnyPublisher() }

    /// A provider for one connection. Reads nothing and starts nothing.
    public init() {}

    /// Refuses, as a provider without hardware does: there is no discovery token to offer.
    ///
    /// - Throws: ``RangingError/hardwareUnsupported``, always.
    public func myDiscoveryToken() async throws -> Data {
        throw RangingError.hardwareUnsupported
    }

    /// Reports the manual-commit fallback again and returns without throwing; `peerToken` is not read.
    public func start(with peerToken: Data) async throws {
        stateSubject.send(.fallback(rssiOnly: true))
    }

    /// Reports `.idle`.
    public func stop() async {
        stateSubject.send(.idle)
    }
}
