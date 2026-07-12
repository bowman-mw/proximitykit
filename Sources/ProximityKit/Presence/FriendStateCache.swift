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

    private struct PersistedState: Codable {
        var version = 1
        var states: [CachedFriendState] = []
        init() {}
        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            version = try c.decodeIfPresent(Int.self, forKey: .version) ?? 1
            states = try c.decodeIfPresent([CachedFriendState].self, forKey: .states) ?? []
        }
    }

    private func load() {
        guard let data = try? Data(contentsOf: fileURL),
              let state = try? JSONDecoder().decode(PersistedState.self, from: data) else { return }
        states = Dictionary(uniqueKeysWithValues: state.states.map { ($0.fingerprint, $0) })
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
