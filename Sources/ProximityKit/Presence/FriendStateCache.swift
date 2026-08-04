// FriendStateCache.swift
// ProximityKit/Presence
//
// Device-local cache of the fuzzy wellbeing state + avatar appearance a friend shared the last time
// you met in person (Phase 4). Same home + stance as HeartLedger.json — a JSON sidecar in Application
// Support, deliberately NEVER in the snapshot: a friend's struggling state is theirs, not something to
// carry into the user's iCloud. Entries older than 30 days stop being shown (a month-old vibe is
// misinformation, per the fuzzy-state memo).

import Foundation
import Observation
import FernletDomainModel

/// One friend's shared fuzzy wellbeing state + companion appearance, stamped with the in-person
/// meeting it was captured at.
///
/// The persisted row of ``FriendStateCache``; keyed by the friend's fingerprint and shown with
/// "as of last time you met" staleness treatment.
public nonisolated struct CachedFriendState: Codable, Equatable, Identifiable {
    public let fingerprint: String
    public var fuzzyState: FriendFuzzyState
    public var appearance: CompanionAppearance
    /// When this was captured — i.e. the in-person meeting it came from. Drives the "as of last time
    /// you met" staleness treatment.
    public var capturedAt: Date

    public var id: String { fingerprint }

    public init(fingerprint: String, fuzzyState: FriendFuzzyState, appearance: CompanionAppearance, capturedAt: Date) {
        self.fingerprint = fingerprint
        self.fuzzyState = fuzzyState
        self.appearance = appearance
        self.capturedAt = capturedAt
    }
}

/// Device-local cache of the fuzzy wellbeing state + avatar appearance each friend shared at the
/// last in-person meeting (Phase 4 of the mesh redesign).
///
/// Fed by the app when a verified `.friendState` payload arrives from a committed, vault-trusted
/// friend; read by the Friends UI. Persistence is a JSON sidecar in Application Support with
/// `.completeFileProtection` — deliberately NEVER in the synced snapshot, since a friend's
/// struggling state is theirs and must not follow the user into iCloud. Entries expire from the
/// UI after 30 days (`staleAfter`), the map is bounded at `maxStates` (newest kept), and decode
/// is per-row tolerant so one unknown future value can never wipe the cache. `remove` is wired
/// from block/revoke so a removed friend leaves nothing behind; `clearAll` from reset-everything.
/// `@MainActor @Observable`: UI-facing state.
@MainActor
@Observable
public final class FriendStateCache {
    public private(set) var states: [String: CachedFriendState] = [:]

    @ObservationIgnored private let fileURL: URL
    @ObservationIgnored private let now: () -> Date

    static let maxStates = 64
    /// State older than this is not shown at all — expired from the UI.
    public static let staleAfter: TimeInterval = 30 * 24 * 3600

    public init(fileURL: URL? = nil, now: @escaping () -> Date = Date.init) {
        self.fileURL = fileURL ?? Self.defaultFileURL()
        self.now = now
        load()
    }

    /// Stores/refreshes a friend's shared state, stamped now (the meeting).
    public func record(fingerprint: String, fuzzyState: FriendFuzzyState, appearance: CompanionAppearance) {
        states[fingerprint] = CachedFriendState(
            fingerprint: fingerprint, fuzzyState: fuzzyState, appearance: appearance, capturedAt: now())
        pruneAndSave()
    }

    /// The friend's cached state IF still fresh enough to show (≤ 30 days). Older → nil (expired).
    public func state(for fingerprint: String) -> CachedFriendState? {
        guard let cached = states[fingerprint],
              now().timeIntervalSince(cached.capturedAt) <= Self.staleAfter else { return nil }
        return cached
    }

    /// Drops one friend's cached state (wire from block/revoke so a removed friend leaves nothing behind).
    public func remove(fingerprint: String) {
        guard states[fingerprint] != nil else { return }
        states[fingerprint] = nil
        pruneAndSave()
    }

    public func clearAll() {
        states = [:]
        try? FileManager.default.removeItem(at: fileURL)
    }

    // MARK: - Persistence

    private func pruneAndSave() {
        // Drop expired rows; then bound the map.
        let at = now()
        states = states.filter { at.timeIntervalSince($0.value.capturedAt) <= Self.staleAfter }
        if states.count > Self.maxStates {
            let keep = states.values.sorted { $0.capturedAt > $1.capturedAt }.prefix(Self.maxStates)
            states = Dictionary(uniqueKeysWithValues: keep.map { ($0.fingerprint, $0) })
        }
        save()
    }

    /// Wraps a `Decodable` so a single element that fails to decode becomes `nil` instead of throwing and
    /// taking the whole array down with it (freeze/park convention — one unknown row must not wipe the
    /// cache; e.g. a future `FriendFuzzyState` case written by a newer build then read after a downgrade).
    private struct Lenient<T: Decodable>: Decodable {
        let value: T?
        init(from decoder: Decoder) throws { value = try? T(from: decoder) }
    }

    /// Versioned on-disk shape; decodes rows leniently so one bad element never drops the file.
    private struct PersistedState: Codable {
        var version = 1
        var states: [CachedFriendState] = []
        init() {}
        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            version = try c.decodeIfPresent(Int.self, forKey: .version) ?? 1
            // Per-row tolerant: skip any undecodable row, keep the rest.
            states = (try c.decodeIfPresent([Lenient<CachedFriendState>].self, forKey: .states) ?? [])
                .compactMap(\.value)
        }
    }

    private func load() {
        guard let data = try? Data(contentsOf: fileURL),
              let state = try? JSONDecoder().decode(PersistedState.self, from: data) else { return }
        states = Dictionary(state.states.map { ($0.fingerprint, $0) }, uniquingKeysWith: { first, _ in first })
    }

    private func save() {
        var state = PersistedState()
        state.states = Array(states.values)
        guard let data = try? JSONEncoder().encode(state) else { return }
        try? FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: fileURL, options: [.atomic, .completeFileProtection])
    }

    private nonisolated static func defaultFileURL() -> URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("Fernlet/FriendStateCache.json")
    }
}
