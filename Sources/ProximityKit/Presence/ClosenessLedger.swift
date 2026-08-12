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

/// Device-local record of per-friend in-person interaction counts (Phase 5) — the input to the
/// deterministic closeness score and the close-slot assignment with hysteresis.
///
/// The app feeds it interaction events (sessions, photo sessions, accepted shares, hearts each
/// direction); each bumps a day-granularity capped counter — no timestamps, names, or durations,
/// so it is a warmth signal, never a who-met-whom surveillance log. Closeness derives via
/// `ClosenessMath` over age-bucketed daily counts; `evaluateSlots` runs at most once per day and
/// persists `slotState` so hysteresis dwell survives relaunch. Persistence is a JSON sidecar in
/// Application Support (`.completeFileProtection`), NEVER in the synced snapshot; retention is 31
/// days and at most 64 tracked friends (least-close dropped). Day keys pin one timezone-stable
/// formatter/calendar pair so bucketing and diffing always agree. `remove` is wired from
/// block/revoke; `clearAll` from reset-everything. `@MainActor @Observable`.
@MainActor
@Observable
public final class ClosenessLedger {
    /// fingerprint → dayKey → counts.
    @ObservationIgnored private var byFriend: [String: [String: FriendInteractionDayCounts]] = [:]
    /// The current close-slot assignment (persisted so hysteresis dwell survives relaunch).
    public private(set) var slotState = CloseSlotState()

    @ObservationIgnored private let file: JSONSidecarFile<PersistedState>
    @ObservationIgnored private let now: () -> Date

    static let retentionDays = 31
    static let maxTrackedFriends = 64

    public init(fileURL: URL? = nil, now: @escaping () -> Date = Date.init) {
        self.file = JSONSidecarFile(fileURL: fileURL ?? Self.fileURL(in: ProximitySupportLayout.defaultDirectory))
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
        // `uniquingKeysWith` (not the trapping `uniqueKeysWithValues`): a duplicate fingerprint in the
        // caller's list must not crash the Friends tab. Matches the sibling `firstAcceptedAt` dict built
        // at the call site.
        Dictionary(fingerprints.map { ($0, closeness(fingerprint: $0)) }, uniquingKeysWith: { first, _ in first })
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
        file.removeFile()
    }

    // MARK: - Date helpers (local day keys, matching the app's day semantics)

    private nonisolated static let dayFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd"
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = .current
        return f
    }()

    /// A calendar pinned to the SAME timezone the formatter captured, so day-bucketing (`dayKey`) and
    /// day-diffing (`daysBetween`) always agree. Using the live `Calendar.current` here would let the two
    /// disagree by a day after a timezone change / DST boundary, skewing the decay window.
    private nonisolated static let dayCalendar: Calendar = {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = dayFormatter.timeZone
        cal.locale = Locale(identifier: "en_US_POSIX")
        return cal
    }()

    static func dayKey(for date: Date) -> String { dayFormatter.string(from: date) }

    static func daysBetween(_ earlierKey: String, and laterKey: String) -> Int? {
        guard let e = dayFormatter.date(from: earlierKey), let l = dayFormatter.date(from: laterKey) else { return nil }
        return dayCalendar.dateComponents([.day], from: e, to: l).day
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

    /// Versioned on-disk shape; missing keys decode to empty so older files keep loading.
    ///
    /// `nonisolated` so its hand-written `Decodable` conformance stays usable from the
    /// nonisolated ``JSONSidecarFile`` generic (pure data).
    private nonisolated struct PersistedState: Codable {
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
        guard let state = file.load() else { return }
        byFriend = state.byFriend
        slotState = state.slotState
    }

    private func save() {
        var state = PersistedState()
        state.byFriend = byFriend
        state.slotState = slotState
        file.save(state)
    }

    /// This store's file inside a given proximity-sidecar root — the ONE definition of its name, so
    /// the production default and a scoped (per-store) root can never name different files.
    ///
    /// Given a root rather than fixed because it is shared mutable on-disk state that a wipe reaches:
    /// `clearAll()` removes this file, and `FernletStore.resetAll` calls it (the closeness signal (in-person interaction counts + close-slot assignment)
    /// must not outlive "Reset everything"). Under the test runner, where XCTest and Swift Testing
    /// suites run in parallel in ONE process, a constant path means any wiping test deletes this for
    /// every concurrently-live store. Unsealed, so — unlike the heart-drop sidecars — the root is the
    /// whole fix and no keychain scoping is needed. See ``ProximityHost/proximitySupportDirectory``.
    public nonisolated static func fileURL(in directory: URL) -> URL {
        JSONSidecarFile<PersistedState>.fileURL(in: directory, name: "ClosenessLedger.json")
    }
}
