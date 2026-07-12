// ClosenessLedger.swift
// ProximityKit/Presence
//
// Device-local record of in-person interaction counts per friend (Phase 5), the input to the
// deterministic closeness score + close-slot assignment. Day-granularity capped counters only — no
// timestamps, names, or durations — so it's a warmth signal, never a who-met-whom surveillance log.
// A JSON sidecar in Application Support, the HeartLedger stance: NEVER in the snapshot, never synced;
// closeness is a private, per-device view of who feels near.

import Foundation
import Observation
import FernletDomainModel

@MainActor
@Observable
public final class ClosenessLedger {
    /// fingerprint → dayKey → counts.
    @ObservationIgnored private var byFriend: [String: [String: FriendInteractionDayCounts]] = [:]
    /// The current close-slot assignment (persisted so hysteresis dwell survives relaunch).
    public private(set) var slotState = CloseSlotState()

    @ObservationIgnored private let fileURL: URL
    @ObservationIgnored private let now: () -> Date

    static let retentionDays = 31
    static let maxTrackedFriends = 64

    public init(fileURL: URL? = nil, now: @escaping () -> Date = Date.init) {
        self.fileURL = fileURL ?? Self.defaultFileURL()
        self.now = now
        load()
    }

    // MARK: - Record interaction events (each bumps today's bucket for the friend)

    public func recordSession(fingerprint: String) { mutate(fingerprint) { $0.sessions += 1 } }
    public func recordPhotoSession(fingerprint: String) { mutate(fingerprint) { $0.photoSessions += 1 } }
    public func recordShareAccepted(fingerprint: String) { mutate(fingerprint) { $0.sharesAccepted += 1 } }
    public func recordHeartSent(fingerprint: String) { mutate(fingerprint) { $0.heartSent += 1 } }
    public func recordHeartReceived(fingerprint: String) { mutate(fingerprint) { $0.heartReceived += 1 } }

    private func mutate(_ fingerprint: String, _ block: (inout FriendInteractionDayCounts) -> Void) {
        let day = Self.dayKey(for: now())
        var days = byFriend[fingerprint] ?? [:]
        var counts = days[day] ?? FriendInteractionDayCounts()
        block(&counts)
        days[day] = counts
        byFriend[fingerprint] = days
        pruneAndSave()
    }

    // MARK: - Closeness + slots

    public func closeness(fingerprint: String) -> Double {
        guard let days = byFriend[fingerprint] else { return 0 }
        let today = Self.dayKey(for: now())
        let daily = days.compactMap { entry -> (ageDays: Int, counts: FriendInteractionDayCounts)? in
            guard let age = Self.daysBetween(entry.key, and: today) else { return nil }
            return (age, entry.value)
        }
        return ClosenessMath.closeness(daily: daily)
    }

    public func closenessMap(for fingerprints: [String]) -> [String: Double] {
        Dictionary(uniqueKeysWithValues: fingerprints.map { ($0, closeness(fingerprint: $0)) })
    }

    /// True when the close slots haven't been evaluated yet today (drives once-per-day evaluation).
    public var needsDailyEvaluation: Bool { slotState.lastEvalDayKey != Self.dayKey(for: now()) }

    /// Re-assigns the close slots (with hysteresis) over the eligible friends. Call at most once/day.
    public func evaluateSlots(eligibleFingerprints: [String], firstAcceptedAt: [String: Date]) {
        let eligible = closenessMap(for: eligibleFingerprints)
        slotState = CloseSlotAssignment.evaluate(
            eligible: eligible, firstAcceptedAt: firstAcceptedAt, state: slotState,
            now: now(), todayKey: Self.dayKey(for: now()))
        save()
    }

    public func isClose(fingerprint: String) -> Bool { slotState.closeFingerprints.contains(fingerprint) }

    public func remove(fingerprint: String) {
        guard byFriend[fingerprint] != nil || slotState.enteredAt[fingerprint] != nil else { return }
        byFriend[fingerprint] = nil
        slotState.closeFingerprints.removeAll { $0 == fingerprint }
        slotState.enteredAt[fingerprint] = nil
        pruneAndSave()
    }

    public func clearAll() {
        byFriend = [:]
        slotState = CloseSlotState()
        try? FileManager.default.removeItem(at: fileURL)
    }

    // MARK: - Date helpers (local day keys, matching the app's day semantics)

    private nonisolated static let dayFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd"
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = .current
        return f
    }()

    static func dayKey(for date: Date) -> String { dayFormatter.string(from: date) }

    static func daysBetween(_ earlierKey: String, and laterKey: String) -> Int? {
        guard let e = dayFormatter.date(from: earlierKey), let l = dayFormatter.date(from: laterKey) else { return nil }
        return Calendar.current.dateComponents([.day], from: e, to: l).day
    }

    // MARK: - Persistence

    private func pruneAndSave() {
        let today = Self.dayKey(for: now())
        // Drop day buckets outside the retention window; drop friends with no remaining buckets.
        for (fingerprint, days) in byFriend {
            let kept = days.filter { entry in
                guard let age = Self.daysBetween(entry.key, and: today) else { return false }
                return (0..<Self.retentionDays).contains(age)
            }
            byFriend[fingerprint] = kept.isEmpty ? nil : kept
        }
        // Bound the number of tracked friends (drop the least-close).
        if byFriend.count > Self.maxTrackedFriends {
            let keep = byFriend.keys
                .sorted { closeness(fingerprint: $0) > closeness(fingerprint: $1) }
                .prefix(Self.maxTrackedFriends)
            byFriend = byFriend.filter { keep.contains($0.key) }
        }
        save()
    }

    private struct PersistedState: Codable {
        var version = 1
        var byFriend: [String: [String: FriendInteractionDayCounts]] = [:]
        var slotState = CloseSlotState()
        init() {}
        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            version = try c.decodeIfPresent(Int.self, forKey: .version) ?? 1
            byFriend = try c.decodeIfPresent([String: [String: FriendInteractionDayCounts]].self, forKey: .byFriend) ?? [:]
            slotState = try c.decodeIfPresent(CloseSlotState.self, forKey: .slotState) ?? CloseSlotState()
        }
    }

    private func load() {
        guard let data = try? Data(contentsOf: fileURL),
              let state = try? JSONDecoder().decode(PersistedState.self, from: data) else { return }
        byFriend = state.byFriend
        slotState = state.slotState
    }

    private func save() {
        var state = PersistedState()
        state.byFriend = byFriend
        state.slotState = slotState
        guard let data = try? JSONEncoder().encode(state) else { return }
        try? FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: fileURL, options: [.atomic, .completeFileProtection])
    }

    private nonisolated static func defaultFileURL() -> URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("Fernlet/ClosenessLedger.json")
    }
}
