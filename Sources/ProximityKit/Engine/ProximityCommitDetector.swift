import Foundation
import FernletDomainModel

/// Dwell gate over a stream of distance samples: fires once the peer has stayed inside a
/// distance threshold for a minimum dwell time and sample count.
///
/// ``ProximityCoordinator`` runs two instances — a tight "tap" gate for trainer mode
/// (0.05 m / 1.0 s) and the friend-mode commit gate (0.15 m / 0.8 s) that turns physical
/// closeness into session consent. Stateful and single-peer: any sample outside the threshold
/// resets the dwell clock, and callers `reset()` between sessions. `ingest` returns `true`
/// exactly when the commit condition is currently satisfied.
public final class ProximityCommitDetector {
    private var thresholdEntryTime: Date?
    private var closeSampleCount = 0
    private let proximityThreshold: Double
    private let dwellSeconds: Double
    private let minimumSamples: Int

    public init(proximityThreshold: Double = 0.15, dwellSeconds: Double = 0.8, minimumSamples: Int = 3) {
        self.proximityThreshold = proximityThreshold
        self.dwellSeconds = dwellSeconds
        self.minimumSamples = minimumSamples
    }

    public func ingest(distanceMeters: Double, at timestamp: Date) -> Bool {
        guard distanceMeters < proximityThreshold else {
            reset()
            return false
        }

        if thresholdEntryTime == nil {
            thresholdEntryTime = timestamp
        }
        closeSampleCount += 1

        guard closeSampleCount >= minimumSamples,
              let thresholdEntryTime,
              timestamp.timeIntervalSince(thresholdEntryTime) >= dwellSeconds else {
            return false
        }

        return true
    }

    public func reset() {
        thresholdEntryTime = nil
        closeSampleCount = 0
    }
}
