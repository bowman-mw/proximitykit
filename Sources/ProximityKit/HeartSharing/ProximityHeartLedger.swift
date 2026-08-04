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
//
// Track A (2026-07-26, O5): loads through `ProtectedSidecar` like the other heart sidecars, so
// a transient read failure can no longer read as "empty ledger" and be persisted back — a wiped
// ledger re-opens the 5-minute receive gate and drops the received-hearts record. While
// unloaded the ledger fails closed: sends are refused (the gate can't be checked or armed) and
// received hearts are not recorded (the drop path pre-checks availability and leaves the record
// on the server for a later pass).

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

/// Device-local persistence for hearts: received-heart records (the Home bubble + 24h health-bar
/// glow) and the per-friend 5-minute rate limit, enforced in BOTH directions and shared by every
/// heart transport (presence, in-session mesh, dead-drop).
///
/// Rate model (owner decision): no daily limit — one heart per friend per 5 minutes each way,
/// keyed on last-send/last-receive timestamps per fingerprint; consume-on-send means
/// `recordHeartSent` runs only after the wire write succeeds. Dead-drop hearts use
/// `recordReceivedDropHeart`, which keeps id-dedup + retention but deliberately skips (and does
/// not arm) the 5-minute receive window — a multi-day pickup batch must not collapse to one
/// heart. Persistence rides a ``ProtectedSidecar`` (Application Support/`HeartLedger.json`,
/// `.completeFileProtection`, NEVER in the synced snapshot) and fails closed while unloaded:
/// sends are refused and receives unrecorded, with the drop record left on the server for a later
/// pass. `receivedHearts` is a published mirror refreshed after every mutation and sidecar
/// recovery. Retention: 48 h / 32 hearts; `clearAll` is wired from reset-everything.
/// `@MainActor @Observable`.
@MainActor
@Observable
public final class ProximityHeartLedger {
    /// Hearts received in the retention window, oldest first. Bounded (`maxStoredHearts`).
    /// A published mirror of the sidecar value, refreshed after every mutation/recovery.
    public private(set) var receivedHearts: [ReceivedHeartRecord] = []

    @ObservationIgnored private let sidecar: ProtectedSidecar<PersistedState>
    @ObservationIgnored private let now: () -> Date

    /// Received hearts kept beyond their 24h glow (small buffer so a duplicate after the glow
    /// fades is still recognized), then pruned.
    static let heartRetention: TimeInterval = 48 * 60 * 60
    /// The per-friend rate window, each direction: at most one heart per friend per 5 minutes.
    static let rateLimitInterval: TimeInterval = 5 * 60
    static let maxStoredHearts = 32

    /// Versioned sidecar shape: the two per-fingerprint rate-limit timestamp maps plus the
    /// received-heart records. Decodes v1 blobs tolerantly (see `init(from:)`).
    private struct PersistedState: Codable {
        var version = 2
        /// Last-send timestamp per friend fingerprint (the send-side rate key).
        var lastSentAt: [String: Date] = [:]
        /// Last-accepted timestamp per sender fingerprint (the receive-side rate mirror).
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
    ///   - now: injectable clock for the 5-minute rate windows and glow decay.
    ///   - readData: injectable file reader for tests; defaults to `Data(contentsOf:)`.
    ///   - writeData: injectable file writer for tests; defaults to atomic protected sidecar writes.
    public init(
        fileURL: URL? = nil,
        now: @escaping () -> Date = Date.init,
        readData: ((URL) throws -> Data)? = nil,
        writeData: ((Data, URL) throws -> Void)? = nil
    ) {
        self.now = now
        // completeFileProtection (the sidecar's default write): low-stakes data, but "who sent
        // me warmth and when" is still social metadata — encrypted at rest like the rest of the
        // app's sidecars. Deliberately NOT sealed with the heart-drop sidecar key: the ledger's
        // lifecycle is `clearAll` (resetAll), not `HeartDropService.wipeForDeleteAll`, so tying
        // it to a key that delete-all removes independently would strand it.
        self.sidecar = ProtectedSidecar(
            fileURL: fileURL ?? Self.defaultFileURL(),
            empty: PersistedState(),
            auditPrefix: "heartledger",
            now: now,
            readData: readData,
            writeData: writeData
        )
        // The sidecar can recover through its OWN paths (the unlock notification, an on-access
        // read from a view body) — the published mirror must follow, or hearts loaded on unlock
        // stay invisible for the session whenever away-hearts is off and no sync pass runs.
        // Hopped: on-access recovery fires inside view-body reads (`canSendHeart`), and the
        // published mirror must not mutate mid-render.
        sidecar.onRecovery = { [weak self] in
            Task { @MainActor [weak self] in self?.refreshMirror() }
        }
        refreshMirror()
    }

    /// True when the sidecar holds real state (loaded, possibly with a write owed). While false,
    /// sends and receives are refused fail-closed; `HeartDropService` surfaces the outage and
    /// leaves drop records on the server for a later pass.
    public var isLoaded: Bool { sidecar.isLoaded }
    @discardableResult
    public func retryLoad() -> Bool {
        let recovered = sidecar.retryLoad()
        refreshMirror()
        return recovered
    }

    // MARK: - Rate limit (one heart per friend per 5 minutes, each direction)

    /// True when the last heart sent to `fingerprint` was ≥ 5 minutes ago (or never). A receipt
    /// timestamp in the future (device clock moved back) reads as "just sent" and gates, so a
    /// clock hop can never re-open the window early. False while the ledger is unloaded — the
    /// gate can't be checked, so the send is refused rather than allowed ungated.
    public func canSendHeart(to fingerprint: String) -> Bool {
        guard let state = sidecar.read() else { return false }
        guard let last = state.lastSentAt[fingerprint] else { return true }
        return now().timeIntervalSince(last) >= Self.rateLimitInterval
    }

    /// Marks a heart to `fingerprint` as just sent. Called only after the wire send succeeds,
    /// so a failed send never consumes the window (consume-on-send). Commit-even-on-write-failure:
    /// the send already happened, so the gate must stay armed in memory regardless.
    public func recordHeartSent(to fingerprint: String) {
        let at = now()
        sidecar.mutate { state in
            state.lastSentAt[fingerprint] = at
            Self.prune(&state, at: at)
        }
        refreshMirror()
    }

    /// Records a received heart. Returns `false` (and stores nothing) when this is a duplicate:
    /// either the exact payload re-delivered (same id — true replays are already rejected by the
    /// envelope ReplayCache; this covers a re-send after relaunch) or a second heart from the
    /// same friend inside the 5-minute receive window. Duplicates are dropped silently by design.
    /// Also false while the ledger is unloaded (fail-closed — nothing to check the window against).
    @discardableResult
    public func recordReceivedHeart(id: UUID, senderDisplayName: String, senderFingerprint: String) -> Bool {
        guard let state = sidecar.read() else { return false }
        guard !state.receivedHearts.contains(where: { $0.id == id }) else { return false }
        let at = now()
        if let last = state.lastReceivedAt[senderFingerprint],
           at.timeIntervalSince(last) < Self.rateLimitInterval {
            return false
        }
        sidecar.mutate { state in
            state.lastReceivedAt[senderFingerprint] = at
            state.receivedHearts.append(ReceivedHeartRecord(
                id: id,
                senderDisplayName: senderDisplayName,
                senderFingerprint: senderFingerprint,
                receivedAt: at
            ))
            Self.prune(&state, at: at)
        }
        refreshMirror()
        return true
    }

    /// Records a dead-drop heart (bitchat adoptions Increment 3). Same id-dedup and retention as
    /// the live path, but deliberately NOT the 5-minute receive window: a multi-day pickup batch
    /// legitimately lands seconds apart and must not collapse to one heart. The receive-side
    /// flood bound lives in `HeartDropDedupStore`'s per-sender per-day budget instead.
    ///
    /// It also does not ARM that window (`lastReceivedAt`), which is the live path's key: picking
    /// up a days-old drop must not swallow the next in-person heart from the same friend.
    @discardableResult
    public func recordReceivedDropHeart(id: UUID, senderDisplayName: String, senderFingerprint: String) -> Bool {
        guard let state = sidecar.read() else { return false }
        guard !state.receivedHearts.contains(where: { $0.id == id }) else { return false }
        let at = now()
        sidecar.mutate { state in
            state.receivedHearts.append(ReceivedHeartRecord(
                id: id,
                senderDisplayName: senderDisplayName,
                senderFingerprint: senderFingerprint,
                receivedAt: at
            ))
            Self.prune(&state, at: at)
        }
        refreshMirror()
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
        guard let state = sidecar.read(),
              let index = state.receivedHearts.firstIndex(where: { $0.id == id }),
              state.receivedHearts[index].bubbleDismissedAt == nil else { return }
        let at = now()
        sidecar.mutate { state in
            guard let index = state.receivedHearts.firstIndex(where: { $0.id == id }) else { return }
            state.receivedHearts[index].bubbleDismissedAt = at
            Self.prune(&state, at: at)
        }
        refreshMirror()
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
        sidecar.wipe()
        refreshMirror()
    }

    // MARK: - Persistence

    private func refreshMirror() {
        let mirrored = (sidecar.read()?.receivedHearts ?? []).sorted { $0.receivedAt < $1.receivedAt }
        if mirrored != receivedHearts {
            receivedHearts = mirrored
        }
    }

    private static func prune(_ state: inout PersistedState, at: Date) {
        state.receivedHearts.removeAll { at.timeIntervalSince($0.receivedAt) > Self.heartRetention }
        if state.receivedHearts.count > Self.maxStoredHearts {
            state.receivedHearts = Array(state.receivedHearts.suffix(Self.maxStoredHearts))
        }
        // Rate-limit timestamps only gate for `rateLimitInterval`; once elapsed they no longer
        // affect any decision, so drop them to keep the maps tiny. A future-dated entry (clock
        // moved back) is kept — it still gates as "just sent".
        let expired: (Date) -> Bool = { at.timeIntervalSince($0) > Self.rateLimitInterval }
        state.lastSentAt = state.lastSentAt.filter { !expired($0.value) }
        state.lastReceivedAt = state.lastReceivedAt.filter { !expired($0.value) }
    }

    private nonisolated static func defaultFileURL() -> URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("Fernlet/HeartLedger.json")
    }
}
