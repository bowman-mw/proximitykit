import Foundation
import NearbyInteraction
import Combine
import FernletDomainModel

// MARK: - NIRangingSession

/// The production ``RangingProvider``: NearbyInteraction UWB distance measurement between two
/// devices that have exchanged discovery tokens.
///
/// Owns one `NISession` at a time, archiving/unarchiving discovery tokens as `Data` so they can
/// ride the signed identity intro. Publishes distances on `distance` and lifecycle on `state`;
/// unsupported hardware immediately reports `.fallback(rssiOnly: true)` so
/// ``ProximityCoordinator`` degrades to manual commit. Delegate callbacks arrive nonisolated and
/// extract Sendable values (or transfer the session via `nonisolated(unsafe)`, kept alive to
/// close the address-reuse window) before hopping to the main actor; suspension re-runs the last
/// configuration when it ends. `@MainActor`: all session state lives on the main actor.
@MainActor
public final class NIRangingSession: NSObject, RangingProvider {

    /// Reasons a ranging session cannot start or produce a token: no UWB hardware, the local
    /// discovery token never populated, or the peer's token bytes failed to unarchive.
    public enum RangingError: Error {
        case hardwareUnsupported
        case tokenUnavailable
        case invalidPeerToken
    }

    public let isHardwareSupported: Bool

    private var niSession: NISession?
    private var lastConfig: NINearbyPeerConfiguration?
    private let distanceSubject = PassthroughSubject<RangingDistance, Never>()
    private let stateSubject = CurrentValueSubject<RangingState, Never>(.idle)

    public var distance: AnyPublisher<RangingDistance, Never> { distanceSubject.eraseToAnyPublisher() }
    public var state: AnyPublisher<RangingState, Never> { stateSubject.eraseToAnyPublisher() }

    public init(isHardwareSupported: Bool? = nil) {
        if let override = isHardwareSupported {
            self.isHardwareSupported = override
        } else if #available(iOS 16.0, *) {
            self.isHardwareSupported = NISession.deviceCapabilities.supportsPreciseDistanceMeasurement
        } else {
            self.isHardwareSupported = NISession.isSupported
        }
        super.init()
        if !self.isHardwareSupported {
            stateSubject.send(.fallback(rssiOnly: true))
        }
    }

    public func myDiscoveryToken() async throws -> Data {
        guard isHardwareSupported else { throw RangingError.hardwareUnsupported }
        let session = getOrCreateSession()
        // NISession.discoveryToken can be nil briefly after init; wait one tick for it to populate.
        if session.discoveryToken == nil {
            // This function throws, so cancellation propagates instead of being swallowed (R7):
            // a cancelled handshake must not go on to archive a token for a session nobody awaits.
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        guard let token = session.discoveryToken else { throw RangingError.tokenUnavailable }
        return try NSKeyedArchiver.archivedData(withRootObject: token, requiringSecureCoding: true)
    }

    public func start(with peerTokenData: Data) async throws {
        guard isHardwareSupported else {
            stateSubject.send(.fallback(rssiOnly: true))
            return
        }
        guard let peerToken = try? NSKeyedUnarchiver.unarchivedObject(ofClass: NIDiscoveryToken.self, from: peerTokenData) else {
            throw RangingError.invalidPeerToken
        }
        let session = getOrCreateSession()
        let config = NINearbyPeerConfiguration(peerToken: peerToken)
        lastConfig = config
        session.run(config)
        stateSubject.send(.running)
    }

    public func stop() async {
        niSession?.invalidate()
        niSession = nil
        stateSubject.send(.idle)
    }

    private func getOrCreateSession() -> NISession {
        if let existing = niSession { return existing }
        let session = NISession()
        session.delegate = self
        niSession = session
        return session
    }
}

// MARK: - NISessionDelegate

extension NIRangingSession: NISessionDelegate {
    nonisolated public func session(_ session: NISession, didUpdate nearbyObjects: [NINearbyObject]) {
        // Extract the Sendable values BEFORE the @MainActor hop: [NINearbyObject] is
        // non-Sendable, so capturing it into the Task is a Swift 6 `sending` error.
        // distance (Float?) and direction (simd_float3?) are both Sendable.
        guard let first = nearbyObjects.first else { return }
        let distance = first.distance
        let direction = first.direction
        Task { @MainActor [weak self] in
            guard let self else { return }
            if let distance {
                self.distanceSubject.send(.meters(max(0, Double(distance)), direction: direction))
            } else {
                self.distanceSubject.send(.unknown)
            }
        }
    }

    nonisolated public func session(_ session: NISession, didInvalidateWith error: Error) {
        // Transfer the NISession itself across the @MainActor hop via nonisolated(unsafe) and compare
        // by identity (===) after the hop — the established ProximityKit pattern for non-Sendable
        // framework objects (see MeshMultipeerSession). Capturing the OBJECT (not just an
        // ObjectIdentifier) keeps it ALIVE until the comparison runs, closing the address-reuse window:
        // with only the identifier captured, the invalidated session could deallocate and a freshly
        // created session be allocated at the same address before the Task runs, aliasing the
        // identifiers and nulling the LIVE `niSession`.
        nonisolated(unsafe) let invalidatedSession = session
        let reason = error.localizedDescription
        Task { @MainActor [weak self] in
            guard let self else { return }
            if self.niSession === invalidatedSession {
                self.niSession = nil
            }
            self.stateSubject.send(.invalidated(reason: reason))
        }
    }

    nonisolated public func sessionWasSuspended(_ session: NISession) {
        Task { @MainActor [weak self] in
            self?.stateSubject.send(.fallback(rssiOnly: false))
        }
    }

    nonisolated public func sessionSuspensionEnded(_ session: NISession) {
        Task { @MainActor [weak self] in
            guard let self, let config = self.lastConfig, let niSession = self.niSession else { return }
            niSession.run(config)
            self.stateSubject.send(.running)
        }
    }
}
