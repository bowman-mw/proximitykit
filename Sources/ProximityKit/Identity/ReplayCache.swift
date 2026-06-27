// ReplayCache.swift
// Fernlet/Proximity
//
// Rolling 24-hour cache of seen envelope IDs for replay-attack prevention.
// The dateProvider is injectable so tests can simulate clock advancement.

import Foundation
import FernletDomainModel

@MainActor
public final class ReplayCache {
    private var seen: [UUID: Date] = [:]
    private let retentionInterval: TimeInterval = 24 * 60 * 60
    private let maxEntries: Int
    public let dateProvider: @Sendable () -> Date

    public init(maxEntries: Int = 10_000, dateProvider: @escaping @Sendable () -> Date = { Date() }) {
        self.maxEntries = maxEntries
        self.dateProvider = dateProvider
    }

    /// Records `envelopeID` as seen at the current time.
    /// Throws `.replayDetected` if the same ID was already seen within the retention window,
    /// or if `createdAt` is older than the retention window (stale envelope, flush-and-replay defence).
    public func recordIfNew(envelopeID: UUID, createdAt: Date) throws {
        let now = dateProvider()
        let cutoff = now.addingTimeInterval(-retentionInterval)
        guard createdAt >= cutoff else {
            throw FernletIdentityEnvelope.VerifyError.replayDetected
        }
        purgeIfNeeded()
        if seen[envelopeID] != nil {
            throw FernletIdentityEnvelope.VerifyError.replayDetected
        }
        seen[envelopeID] = now
    }

    private func purgeIfNeeded() {
        let cutoff = dateProvider().addingTimeInterval(-retentionInterval)
        seen = seen.filter { $0.value >= cutoff }
        if seen.count > maxEntries {
            // Keep the NEWEST entries. The stale-`createdAt` guard above already bounds the
            // replay window, so dropping old IDs is safe; dropping new ones is not — under a
            // >maxEntries flood it would evict the fingerprints of recent legitimate envelopes,
            // letting those recent envelopes be replayed undetected.
            seen = Dictionary(
                seen.sorted(by: { $0.value > $1.value }).prefix(maxEntries).map { ($0.key, $0.value) },
                uniquingKeysWith: { a, _ in a }
            )
        }
    }
}
