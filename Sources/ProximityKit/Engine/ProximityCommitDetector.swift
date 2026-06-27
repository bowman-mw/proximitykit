import Foundation
import FernletDomainModel

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
