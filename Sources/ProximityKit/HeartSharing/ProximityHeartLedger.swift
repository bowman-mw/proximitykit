// ProximityHeartLedger.swift
// ProximityKit/HeartSharing
//
// Device-local persistence for the hearts feature: received hearts (for the Home bubble and
// the 24h health-bar glow) plus the one-heart-per-friend-per-day rate limit, enforced in BOTH
// directions. Stored as a small JSON sidecar in Application Support (the same home as
// MeshPhotoCache.json / MeshPhotoWallPreferences.json) — deliberately NEVER in the snapshot,
// so heart activity (who, when) stays off every synced store. Ephemeral social warmth should
// not follow the user into iCloud.

import Foundation
import Observation
import FernletDomainModel
import FernletFoundation

/// One received heart. `senderDisplayName` is sanitized at the wire boundary before it is
/// handed to the ledger (see `ProximityHeartManager`), so nothing peer-controlled lands here raw.
public nonisolated struct ReceivedHeartRecord: Codable, Equatable, Identifiable, Sendable {
    /// The wire payload's id — stable across a duplicate delivery, so exact re-sends dedupe.
    public let id: UUID
    public let senderDisplayName: String
    public let senderFingerprint: String
    public let receivedAt: Date
    /// When the Home bubble for this heart was dismissed. The health-bar glow keeps decaying
    /// on its own 24h clock regardless — dismissal only hides the bubble.
    public var bubbleDismissedAt: Date?

    public init(
        id: UUID,
        senderDisplayName: String,
        senderFingerprint: String,
        receivedAt: Date,
        bubbleDismissedAt: Date? = nil
    ) {
        self.id = id
        self.senderDisplayName = senderDisplayName
        self.senderFingerprint = senderFingerprint
        self.receivedAt = receivedAt
        self.bubbleDismissedAt = bubbleDismissedAt
    }
}

@MainActor
@Observable
public final class ProximityHeartLedger {
    /// Hearts received in the retention window, oldest first. Bounded (`maxStoredHearts`).
    public private(set) var receivedHearts: [ReceivedHeartRecord] = []

    @ObservationIgnored private var rateLimitKeys: Set<String> = []
    @ObservationIgnored private let fileURL: URL
    @ObservationIgnored private let now: () -> Date

    /// Received hearts kept beyond their 24h glow (small buffer so a same-day duplicate after
    /// the glow fades is still recognized), then pruned.
    static let heartRetention: TimeInterval = 48 * 60 * 60
    /// Rate-limit keys are day-scoped; keep a few days so a timezone hop can't re-open today.
    static let rateLimitKeyRetentionDays = 3
    static let maxStoredHearts = 32

    private struct PersistedState: Codable {
        var version: Int = 1
        var rateLimitKeys: [String] = []
        var receivedHearts: [ReceivedHeartRecord] = []
    }

    /// - Parameters:
    ///   - fileURL: injectable for tests (relaunch = a new ledger on the same URL); defaults to
    ///     `Application Support/Fernlet/HeartLedger.json`.
    ///   - now: injectable clock for the day-key rate limit and glow decay.
    public init(fileURL: URL? = nil, now: @escaping () -> Date = Date.init) {
        self.fileURL = fileURL ?? Self.defaultFileURL()
        self.now = now
        load()
    }

    // MARK: - Rate limit (one heart per friend per day, each direction)

    /// Deterministic day-scoped key, e.g. `heart:sent:a1b2c3d4e5f60718:2026-07-05`.
    /// The direction segment keeps the send and receive limits independent — sending a friend
    /// warmth must never consume their heart to you.
    static func rateLimitKey(direction: String, fingerprint: String, dayKey: String) -> String {
        "heart:\(direction):\(fingerprint):\(dayKey)"
    }

    public func canSendHeart(to fingerprint: String) -> Bool {
        !rateLimitKeys.contains(Self.rateLimitKey(direction: "sent", fingerprint: fingerprint, dayKey: todayKey()))
    }

    /// Marks today's heart to `fingerprint` as sent. Called only after the wire send succeeds,
    /// so a failed send never consumes the day's heart.
    public func recordHeartSent(to fingerprint: String) {
        rateLimitKeys.insert(Self.rateLimitKey(direction: "sent", fingerprint: fingerprint, dayKey: todayKey()))
        pruneAndSave()
    }

    /// Records a received heart. Returns `false` (and stores nothing) when this is a duplicate:
    /// either the exact payload re-delivered (same id — true replays are already rejected by the
    /// envelope ReplayCache; this covers a re-send after relaunch) or a second heart from the
    /// same friend on the same local day. Duplicates are dropped silently by design.
    @discardableResult
    public func recordReceivedHeart(id: UUID, senderDisplayName: String, senderFingerprint: String) -> Bool {
        guard !receivedHearts.contains(where: { $0.id == id }) else { return false }
        let key = Self.rateLimitKey(direction: "received", fingerprint: senderFingerprint, dayKey: todayKey())
        guard !rateLimitKeys.contains(key) else { return false }
        rateLimitKeys.insert(key)
        receivedHearts.append(ReceivedHeartRecord(
            id: id,
            senderDisplayName: senderDisplayName,
            senderFingerprint: senderFingerprint,
            receivedAt: now()
        ))
        pruneAndSave()
        return true
    }

    // MARK: - Surfacing

    /// The heart whose Home bubble should show: the oldest undismissed heart still glowing.
    /// One at a time keeps the surface quiet even if several friends sent warmth.
    public var pendingBubbleHeart: ReceivedHeartRecord? {
        let at = now()
        return receivedHearts.first {
            $0.bubbleDismissedAt == nil && HeartGlowMath.glow(receivedAt: $0.receivedAt, at: at) > 0
        }
    }

    public func dismissBubble(id: UUID) {
        guard let index = receivedHearts.firstIndex(where: { $0.id == id }),
              receivedHearts[index].bubbleDismissedAt == nil else { return }
        receivedHearts[index].bubbleDismissedAt = now()
        pruneAndSave()
    }

    /// Presentation-only golden glow in [0, 1] for the health bar: the strongest (most recent)
    /// heart wins — intensity is capped, never summed, so the glow stays subtle and carries no
    /// count information.
    public func activeGlow(at date: Date? = nil) -> Double {
        let at = date ?? now()
        return receivedHearts
            .map { HeartGlowMath.glow(receivedAt: $0.receivedAt, at: at) }
            .max() ?? 0
    }

    /// Wipes all received-heart records and rate-limit keys and removes the on-disk sidecar. Wired
    /// from `FernletStore.resetAll` so "Reset everything" doesn't leave a friend's name, fingerprint,
    /// or glow behind after the relationships they refer to (the trust vault) are cleared.
    public func clearAll() {
        receivedHearts = []
        rateLimitKeys = []
        try? FileManager.default.removeItem(at: fileURL)
    }

    // MARK: - Persistence

    private func todayKey() -> String {
        FernletDate.dayKey(for: now())
    }

    private func prune() {
        let at = now()
        receivedHearts.removeAll { at.timeIntervalSince($0.receivedAt) > Self.heartRetention }
        if receivedHearts.count > Self.maxStoredHearts {
            receivedHearts = Array(receivedHearts.suffix(Self.maxStoredHearts))
        }
        // Day keys sort lexicographically, so a plain string compare is a date compare.
        let cutoffDate = at.addingTimeInterval(-TimeInterval(Self.rateLimitKeyRetentionDays) * 24 * 60 * 60)
        let cutoffKey = FernletDate.dayKey(for: cutoffDate)
        rateLimitKeys = rateLimitKeys.filter { key in
            guard let dayKey = key.split(separator: ":").last else { return false }
            return String(dayKey) >= cutoffKey
        }
    }

    private func pruneAndSave() {
        prune()
        save()
    }

    private func load() {
        guard let data = try? Data(contentsOf: fileURL),
              let state = try? JSONDecoder().decode(PersistedState.self, from: data) else { return }
        rateLimitKeys = Set(state.rateLimitKeys)
        receivedHearts = state.receivedHearts.sorted { $0.receivedAt < $1.receivedAt }
        prune()
    }

    private func save() {
        let state = PersistedState(
            rateLimitKeys: rateLimitKeys.sorted(),
            receivedHearts: receivedHearts
        )
        guard let data = try? JSONEncoder().encode(state) else { return }
        try? FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        // completeFileProtection: low-stakes data, but "who sent me warmth and when" is still
        // social metadata — keep it encrypted at rest like the rest of the app's sidecars.
        try? data.write(to: fileURL, options: [.atomic, .completeFileProtection])
    }

    private nonisolated static func defaultFileURL() -> URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("Fernlet/HeartLedger.json")
    }
}
