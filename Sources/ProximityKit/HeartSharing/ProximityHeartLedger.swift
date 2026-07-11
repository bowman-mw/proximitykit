// ProximityHeartLedger.swift
// ProximityKit/HeartSharing
//
// Device-local persistence for the hearts feature: received hearts (for the Home bubble and
// the 24h health-bar glow) plus the per-friend rate limit, enforced in BOTH directions.
// Stored as a small JSON sidecar in Application Support (the same home as MeshPhotoCache.json /
// MeshPhotoWallPreferences.json) — deliberately NEVER in the snapshot, so heart activity
// (who, when) stays off every synced store. Ephemeral social warmth should not follow the user
// into iCloud.
//
// Rate model (mesh redesign Phase 4b, owner decision): NO daily limit for in-person hearts —
// instead a rolling 1-heart-per-friend-per-5-minutes rate limit, mirrored on receive (accept at
// most one heart per sender per 5 minutes). The wire `HeartPayload.sentAtDayKey` is now a
// shape-check only (a hostile peer can't land an oversized string) and no longer a limit key;
// the ledger keys the limit on the last-send/last-receive timestamp per friend fingerprint.
// Consume-on-send is retained: `recordHeartSent` runs only after the wire write succeeds.

import Foundation
import Observation
import FernletDomainModel
import FernletFoundation

/// One received heart. `senderDisplayName` is sanitized at the wire boundary before it is
/// handed to the ledger (see `PresenceManager`), so nothing peer-controlled lands here raw.
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

    /// Last-send timestamp per friend fingerprint (the send-side rate key).
    @ObservationIgnored private var lastSentAt: [String: Date] = [:]
    /// Last-accepted timestamp per sender fingerprint (the receive-side rate mirror).
    @ObservationIgnored private var lastReceivedAt: [String: Date] = [:]
    @ObservationIgnored private let fileURL: URL
    @ObservationIgnored private let now: () -> Date

    /// Received hearts kept beyond their 24h glow (small buffer so a duplicate after the glow
    /// fades is still recognized), then pruned.
    static let heartRetention: TimeInterval = 48 * 60 * 60
    /// The per-friend rate window, each direction: at most one heart per friend per 5 minutes.
    static let rateLimitInterval: TimeInterval = 5 * 60
    static let maxStoredHearts = 32

    private struct PersistedState: Codable {
        var version = 2
        var lastSentAt: [String: Date] = [:]
        var lastReceivedAt: [String: Date] = [:]
        var receivedHearts: [ReceivedHeartRecord] = []

        init() {}

        /// Tolerant decode: a v1 blob carried `rateLimitKeys` (day-scoped Set) and no
        /// timestamp maps. Those day keys no longer gate anything under the 5-minute model, so
        /// they are simply dropped — the only user-visible effect of the upgrade is that a
        /// heart may be sendable immediately after the update, which is harmless.
        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            version = try c.decodeIfPresent(Int.self, forKey: .version) ?? 1
            lastSentAt = try c.decodeIfPresent([String: Date].self, forKey: .lastSentAt) ?? [:]
            lastReceivedAt = try c.decodeIfPresent([String: Date].self, forKey: .lastReceivedAt) ?? [:]
            receivedHearts = try c.decodeIfPresent([ReceivedHeartRecord].self, forKey: .receivedHearts) ?? []
        }
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

    // MARK: - Rate limit (one heart per friend per 5 minutes, each direction)

    /// True when the last heart sent to `fingerprint` was ≥ 5 minutes ago (or never). A receipt
    /// timestamp in the future (device clock moved back) reads as "just sent" and gates, so a
    /// clock hop can never re-open the window early.
    public func canSendHeart(to fingerprint: String) -> Bool {
        guard let last = lastSentAt[fingerprint] else { return true }
        return now().timeIntervalSince(last) >= Self.rateLimitInterval
    }

    /// Marks a heart to `fingerprint` as just sent. Called only after the wire send succeeds,
    /// so a failed send never consumes the window (consume-on-send).
    public func recordHeartSent(to fingerprint: String) {
        lastSentAt[fingerprint] = now()
        pruneAndSave()
    }

    /// Records a received heart. Returns `false` (and stores nothing) when this is a duplicate:
    /// either the exact payload re-delivered (same id — true replays are already rejected by the
    /// envelope ReplayCache; this covers a re-send after relaunch) or a second heart from the
    /// same friend inside the 5-minute receive window. Duplicates are dropped silently by design.
    @discardableResult
    public func recordReceivedHeart(id: UUID, senderDisplayName: String, senderFingerprint: String) -> Bool {
        guard !receivedHearts.contains(where: { $0.id == id }) else { return false }
        if let last = lastReceivedAt[senderFingerprint],
           now().timeIntervalSince(last) < Self.rateLimitInterval {
            return false
        }
        lastReceivedAt[senderFingerprint] = now()
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
        lastSentAt = [:]
        lastReceivedAt = [:]
        try? FileManager.default.removeItem(at: fileURL)
    }

    // MARK: - Persistence

    private func prune() {
        let at = now()
        receivedHearts.removeAll { at.timeIntervalSince($0.receivedAt) > Self.heartRetention }
        if receivedHearts.count > Self.maxStoredHearts {
            receivedHearts = Array(receivedHearts.suffix(Self.maxStoredHearts))
        }
        // Rate-limit timestamps only gate for `rateLimitInterval`; once elapsed they no longer
        // affect any decision, so drop them to keep the maps tiny. A future-dated entry (clock
        // moved back) is kept — it still gates as "just sent".
        let expired: (Date) -> Bool = { at.timeIntervalSince($0) > Self.rateLimitInterval }
        lastSentAt = lastSentAt.filter { !expired($0.value) }
        lastReceivedAt = lastReceivedAt.filter { !expired($0.value) }
    }

    private func pruneAndSave() {
        prune()
        save()
    }

    private func load() {
        guard let data = try? Data(contentsOf: fileURL),
              let state = try? JSONDecoder().decode(PersistedState.self, from: data) else { return }
        lastSentAt = state.lastSentAt
        lastReceivedAt = state.lastReceivedAt
        receivedHearts = state.receivedHearts.sorted { $0.receivedAt < $1.receivedAt }
        prune()
    }

    private func save() {
        var state = PersistedState()
        state.lastSentAt = lastSentAt
        state.lastReceivedAt = lastReceivedAt
        state.receivedHearts = receivedHearts
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
