import Foundation
import NearbyInteraction
import Combine
import FernletDomainModel

// MARK: - NIRangingSession

@MainActor
public final class NIRangingSession: NSObject, RangingProvider {

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
            try? await Task.sleep(nanoseconds: 100_000_000)
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
        Task { @MainActor [weak self] in
            guard let self, let first = nearbyObjects.first else { return }
            if let dist = first.distance {
                self.distanceSubject.send(.meters(max(0, Double(dist)), direction: first.direction))
            } else {
                self.distanceSubject.send(.unknown)
            }
        }
    }

    nonisolated public func session(_ session: NISession, didInvalidateWith error: Error) {
        Task { @MainActor [weak self] in
            if self?.niSession === session {
                self?.niSession = nil
            }
            self?.stateSubject.send(.invalidated(reason: error.localizedDescription))
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
