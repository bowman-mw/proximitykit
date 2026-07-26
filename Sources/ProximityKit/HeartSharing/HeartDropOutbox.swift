import Foundation

/// Persisted sender-side queue for offline heart drops + the durable receive dedup
/// (bitchat adoptions Increment 3). Two small JSON sidecars beside `HeartLedger.json` —
/// deliberately NOT in the synced snapshot: drops are pairwise device-scoped, like the ledger.
///
/// Outbox pattern from bitchat's courier outbox (persisted, resend-until-expiry, bounded); the
/// dedup store is load-bearing on its own: `ProximityHeartLedger` retains only 48 h / 32 hearts,
/// so a still-on-server record would re-deliver after ledger pruning without this 30-day record.

@MainActor
public final class HeartDropOutbox {

    public struct Entry: Codable, Equatable, Sendable {
        public let id: UUID
        public let friendSigningKey: Data
        public let tag: String
        public let wire: Data
        public let createdAt: Date
        public var attempts: Int
        /// Server record name once uploaded — kept until expiry so cleanup can delete our own
        /// public-DB records without any server-side query.
        public var recordName: String?

        public init(id: UUID, friendSigningKey: Data, tag: String, wire: Data,
                    createdAt: Date, attempts: Int = 0, recordName: String? = nil) {
            self.id = id
            self.friendSigningKey = friendSigningKey
            self.tag = tag
            self.wire = wire
            self.createdAt = createdAt
            self.attempts = attempts
            self.recordName = recordName
        }
    }

    /// Drops older than this are given up on and their server records deleted. Also drives
    /// `HeartDropService.pickupWindowDays` — the recipient's tag window is derived from this so a
    /// heart can never age out of the pickup window while the sender is still retrying it.
    public static let entryLifetime: TimeInterval = 14 * 24 * 3600
    /// Not-yet-uploaded entries per friend — the ledger's 5-minute send gate bounds the rate; this
    /// bounds the backlog when a friend stays away for weeks. Delivered (uploaded) entries are
    /// deliberately NOT counted: they are on the server already, so counting them would refuse new
    /// hearts for up to `entryLifetime` after eight successful sends.
    public static let maxPendingPerFriend = 8
    /// Drops QUEUED for one friend per UTC day, derived from the receiver's acceptance budget so the
    /// two can never drift. Without it the backlog cap bounds nothing useful — uploaded entries free
    /// capacity immediately, so the 5-minute send gate alone would allow ~288 hearts/day to one
    /// friend, of which the recipient accepts 3 and silently discards the rest AFTER they were
    /// sealed, uploaded, stored on the public database and reported to the sender as delivered.
    public static let maxPerFriendPerDay = HeartDropDedupStore.maxAcceptedPerSenderPerDay

    private let fileURL: URL
    private let now: () -> Date
    private(set) var entries: [Entry]

    public init(fileURL: URL? = nil, now: @escaping () -> Date = { Date() }) {
        self.fileURL = fileURL ?? Self.defaultFileURL()
        self.now = now
        self.entries = Self.load(from: self.fileURL)
    }

    /// Whether another heart for this friend would fit under the backlog cap. Callers check this
    /// BEFORE spending anything irreversible on the send (a one-time prekey, the 5-minute
    /// cooldown) — see `HeartDropService.queueHeart`.
    public func hasCapacity(forFriendSigningKey key: Data) -> Bool {
        pendingCount(friendSigningKey: key) < Self.maxPendingPerFriend
    }

    /// Whether another heart for this friend would fit under the per-UTC-day cap. Unlike the backlog
    /// cap this counts UPLOADED entries too: those are exactly the ones already spending the
    /// recipient's daily acceptance budget, so forgiving them would defeat the point.
    ///
    /// Derived from the outbox rather than a separate counter so it can never disagree with what was
    /// actually queued. The known slack: a purge (consent withdrawn) drops the day's entries, so
    /// toggling away-hearts off and on again resets the sender-side count. The receiver's identical
    /// budget is the authoritative bound; this one exists so we never upload a heart destined to be
    /// discarded.
    public func hasDailyCapacity(forFriendSigningKey key: Data, at date: Date) -> Bool {
        queuedCount(
            friendSigningKey: key,
            dayEpoch: IdentityService.heartDropDayEpoch(at: date)
        ) < Self.maxPerFriendPerDay
    }

    /// Drops queued for this friend whose `createdAt` falls in the given UTC day epoch — the same
    /// bucket the receiver derives from the signed `createdAt` when it applies its own budget.
    public func queuedCount(friendSigningKey: Data, dayEpoch: UInt64) -> Int {
        entries.filter {
            $0.friendSigningKey == friendSigningKey
                && IdentityService.heartDropDayEpoch(at: $0.createdAt) == dayEpoch
        }.count
    }

    /// False when the friend's pending backlog is full — the caller should surface "hearts are
    /// waiting" rather than queue more.
    @discardableResult
    public func enqueue(_ entry: Entry) -> Bool {
        guard hasCapacity(forFriendSigningKey: entry.friendSigningKey) else { return false }
        entries.append(entry)
        persist()
        return true
    }

    public func pendingUploads() -> [Entry] {
        entries.filter { $0.recordName == nil && !isExpired($0) }
    }

    public func markUploaded(id: UUID, recordName: String) {
        guard let index = entries.firstIndex(where: { $0.id == id }) else { return }
        entries[index].recordName = recordName
        persist()
    }

    public func recordAttempt(id: UUID) {
        guard let index = entries.firstIndex(where: { $0.id == id }) else { return }
        entries[index].attempts += 1
        persist()
    }

    /// Entries past their lifetime — cleanup deletes their server records (when uploaded) and
    /// then removes them.
    public func expiredEntries() -> [Entry] {
        entries.filter { isExpired($0) }
    }

    public func remove(ids: [UUID]) {
        guard !ids.isEmpty else { return }
        let removal = Set(ids)
        entries.removeAll { removal.contains($0.id) }
        persist()
    }

    /// Removes exactly the captured entries that are STILL in the state they were captured in, and
    /// reports how many went. Used by the purge across its remote-delete await.
    ///
    /// The `recordName` comparison is the load-bearing part: an entry captured as pending but
    /// uploaded during the caller's suspension no longer matches, and is kept. Dropping it would
    /// discard a record name minted after the capture — a record left on the public database with
    /// nothing left in the app able to name it, and only the sender may delete it.
    @discardableResult
    public func removeUnchanged(_ captured: [Entry]) -> Int {
        guard !captured.isEmpty else { return 0 }
        // Two collections rather than one `[UUID: String?]`: assigning a nil value through a
        // dictionary subscript ERASES the key, which would quietly exempt every pending entry.
        var capturedNames: [UUID: String] = [:]
        var capturedPending: Set<UUID> = []
        for entry in captured {
            if let name = entry.recordName {
                capturedNames[entry.id] = name
            } else {
                capturedPending.insert(entry.id)
            }
        }
        let before = entries.count
        entries.removeAll { entry in
            guard let name = entry.recordName else { return capturedPending.contains(entry.id) }
            return capturedNames[entry.id] == name
        }
        let removed = before - entries.count
        if removed > 0 { persist() }
        return removed
    }

    /// Hearts still WAITING for this friend: not yet uploaded and not yet expired. An uploaded
    /// entry is retained (cleanup needs its record name) but it has already been delivered to the
    /// dead-drop, so it neither counts against the backlog cap nor reads as "waiting" in the UI.
    public func pendingCount(friendSigningKey: Data) -> Int {
        entries.filter {
            $0.friendSigningKey == friendSigningKey && $0.recordName == nil && !isExpired($0)
        }.count
    }

    /// Entries the sender gave up on: past their lifetime and never uploaded. Drives the
    /// user-facing "these hearts never made it" signal — undelivered hearts must not vanish
    /// silently.
    public func expiredUndeliveredCount() -> Int {
        entries.filter { isExpired($0) && $0.recordName == nil }.count
    }

    /// Highest retry count among entries still waiting to upload, and the oldest such entry's
    /// creation date — the delivery-health inputs (`HeartDropService.DeliveryProblem`).
    public func uploadFailureState() -> (maxAttempts: Int, oldestCreatedAt: Date)? {
        let waiting = entries.filter { $0.recordName == nil && !isExpired($0) }
        guard let maxAttempts = waiting.map(\.attempts).max(),
              let oldest = waiting.map(\.createdAt).min() else { return nil }
        return (maxAttempts, oldest)
    }

    /// Every uploaded entry's server record name — the purge path deletes these from the public
    /// database when the user turns the feature off or wipes.
    public func uploadedRecordNames() -> [String] {
        entries.compactMap(\.recordName)
    }

    /// Every entry as of right now. The purge path captures this BEFORE its remote delete and then
    /// removes exactly these ids afterwards. There is deliberately no `removeAll()`: a purge that
    /// wiped the outbox after its await would destroy hearts queued during it — including their
    /// record names, stranding those records on the public database with nothing left to name them.
    public func snapshot() -> [Entry] {
        entries
    }

    /// Delete-all seam (Docs/PrivacyWipeCoverage.md).
    public func wipeForDeleteAll() {
        entries = []
        try? FileManager.default.removeItem(at: fileURL)
    }

    // MARK: - Persistence

    private func isExpired(_ entry: Entry) -> Bool {
        entry.createdAt.addingTimeInterval(Self.entryLifetime) < now()
    }

    private static func defaultFileURL() -> URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Fernlet/HeartDropOutbox.json")
    }

    private static func load(from url: URL) -> [Entry] {
        guard let data = try? Data(contentsOf: url),
              let entries = try? JSONDecoder().decode([Entry].self, from: data) else { return [] }
        return entries
    }

    private func persist() {
        try? FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        guard let data = try? JSONEncoder().encode(entries) else { return }
        try? data.write(to: fileURL, options: [.atomic, .completeFileProtection])
    }
}

/// Durable dedup + per-sender-per-day acceptance counters for RECEIVED drops. Retains 30 days —
/// past the pickup window and the sender's 14-day record lifetime with margin.
///
/// Budget keying (review 2026-07-25): the day bucket is a UTC day EPOCH the receiver derives and
/// clamps, never the sender-supplied `sentAtDayKey`. A shape-valid day string admits ~10^8 distinct
/// buckets, so keying on it made the flood bound vacuous against exactly the adversary it exists
/// for — a client that ignores its own 5-minute consume-on-send.
@MainActor
public final class HeartDropDedupStore {

    public static let retention: TimeInterval = 30 * 24 * 3600
    static let retentionDays: UInt64 = 30
    /// Max accepted drop-hearts per sender per receiver-clamped UTC day — the receive-side flood
    /// bound (a malicious client could ignore the sender-side 5-minute consume-on-send).
    public static let maxAcceptedPerSenderPerDay = 3
    /// Hard caps so a hostile flood can't grow the sidecar without bound. Both evict OLDEST-first
    /// rather than clearing: a wholesale reset is itself an attack (it would hand every sender a
    /// fresh budget, and re-open every deduped envelope id for redelivery).
    static let maxSeenEnvelopeIDs = 8192
    static let maxSenderDayCounters = 4096

    private struct State: Codable {
        var seenEnvelopeIDs: [UUID: Date] = [:]
        /// "senderFingerprint|utcDayEpoch" → accepted count.
        var acceptedBySenderDay: [String: Int] = [:]
    }

    private let fileURL: URL
    private let now: () -> Date
    private var state: State

    public init(fileURL: URL? = nil, now: @escaping () -> Date = { Date() }) {
        self.fileURL = fileURL ?? FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Fernlet/HeartDropDedup.json")
        self.now = now
        if let data = try? Data(contentsOf: self.fileURL),
           let state = try? JSONDecoder().decode(State.self, from: data) {
            self.state = state
        } else {
            self.state = State()
        }
        prune()
    }

    /// Records the envelope id; false when it was already seen (drop the record silently).
    public func recordIfNew(envelopeID: UUID) -> Bool {
        prune()
        guard state.seenEnvelopeIDs[envelopeID] == nil else { return false }
        state.seenEnvelopeIDs[envelopeID] = now()
        persist()
        return true
    }

    /// Whether the sender still has acceptance budget for this UTC day epoch; increments on accept.
    /// `dayEpoch` MUST be receiver-derived (the caller clamps the signed `createdAt` into the
    /// pickup window) — passing a sender-controlled value re-opens the flood hole.
    public func acceptIfWithinDailyBudget(senderFingerprint: String, dayEpoch: UInt64) -> Bool {
        prune()
        let key = "\(senderFingerprint)|\(dayEpoch)"
        let count = state.acceptedBySenderDay[key, default: 0]
        guard count < Self.maxAcceptedPerSenderPerDay else { return false }
        state.acceptedBySenderDay[key] = count + 1
        persist()
        return true
    }

    /// Delete-all seam (Docs/PrivacyWipeCoverage.md).
    public func wipeForDeleteAll() {
        state = State()
        try? FileManager.default.removeItem(at: fileURL)
    }

    private func prune() {
        let currentTime = now()
        let cutoff = currentTime.addingTimeInterval(-Self.retention)
        state.seenEnvelopeIDs = state.seenEnvelopeIDs.filter { $0.value >= cutoff }
        if state.seenEnvelopeIDs.count > Self.maxSeenEnvelopeIDs {
            let kept = state.seenEnvelopeIDs
                .sorted { $0.value > $1.value }
                .prefix(Self.maxSeenEnvelopeIDs)
            state.seenEnvelopeIDs = Dictionary(uniqueKeysWithValues: kept.map { ($0.key, $0.value) })
        }
        // Day counters carry their own day epoch in the key, so they prune BY DAY. The previous
        // "over 4096 → removeAll" was itself an attack surface: a flood could trip it deliberately
        // and hand every sender a fresh acceptance budget.
        let today = IdentityService.heartDropDayEpoch(at: currentTime)
        let oldestKeptDay = today >= Self.retentionDays ? today - Self.retentionDays : 0
        state.acceptedBySenderDay = state.acceptedBySenderDay.filter { key, _ in
            guard let day = Self.dayEpoch(fromCounterKey: key) else { return false }
            return day >= oldestKeptDay && day <= today + 1 // +1 day of tolerated clock skew
        }
        if state.acceptedBySenderDay.count > Self.maxSenderDayCounters {
            let kept = state.acceptedBySenderDay
                .sorted { (Self.dayEpoch(fromCounterKey: $0.key) ?? 0) > (Self.dayEpoch(fromCounterKey: $1.key) ?? 0) }
                .prefix(Self.maxSenderDayCounters)
            state.acceptedBySenderDay = Dictionary(uniqueKeysWithValues: kept.map { ($0.key, $0.value) })
        }
    }

    /// The day epoch embedded in a `"fingerprint|dayEpoch"` counter key. Nil for a key written by
    /// the pre-review build (which embedded a `yyyy-MM-dd` string) — those are dropped on load.
    private static func dayEpoch(fromCounterKey key: String) -> UInt64? {
        guard let separator = key.lastIndex(of: "|") else { return nil }
        return UInt64(key[key.index(after: separator)...])
    }

    private func persist() {
        try? FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        guard let data = try? JSONEncoder().encode(state) else { return }
        try? data.write(to: fileURL, options: [.atomic, .completeFileProtection])
    }
}
