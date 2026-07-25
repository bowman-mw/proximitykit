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

    /// Drops older than this are given up on and their server records deleted.
    public static let entryLifetime: TimeInterval = 14 * 24 * 3600
    /// Pending (not-yet-expired) entries per friend — the ledger's 5-minute send gate bounds the
    /// rate; this bounds the backlog when a friend stays away for weeks.
    public static let maxPendingPerFriend = 8

    private let fileURL: URL
    private let now: () -> Date
    private(set) var entries: [Entry]

    public init(fileURL: URL? = nil, now: @escaping () -> Date = { Date() }) {
        self.fileURL = fileURL ?? Self.defaultFileURL()
        self.now = now
        self.entries = Self.load(from: self.fileURL)
    }

    /// False when the friend's pending backlog is full — the caller should surface "hearts are
    /// waiting" rather than queue more.
    @discardableResult
    public func enqueue(_ entry: Entry) -> Bool {
        let pendingForFriend = entries.filter {
            $0.friendSigningKey == entry.friendSigningKey && !isExpired($0)
        }
        guard pendingForFriend.count < Self.maxPendingPerFriend else { return false }
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

    public func pendingCount(friendSigningKey: Data) -> Int {
        entries.filter { $0.friendSigningKey == friendSigningKey && !isExpired($0) }.count
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
/// past the 7-day pickup window and the sender's 14-day record lifetime with margin.
@MainActor
public final class HeartDropDedupStore {

    public static let retention: TimeInterval = 30 * 24 * 3600
    /// Max accepted drop-hearts per sender per `sentAtDayKey` — the receive-side flood bound
    /// (a malicious client could ignore the sender-side 5-minute consume-on-send).
    public static let maxAcceptedPerSenderPerDay = 3

    private struct State: Codable {
        var seenEnvelopeIDs: [UUID: Date] = [:]
        /// "senderFingerprint|dayKey" → accepted count.
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

    /// Whether the sender still has acceptance budget for this day key; increments on accept.
    public func acceptIfWithinDailyBudget(senderFingerprint: String, dayKey: String) -> Bool {
        let key = "\(senderFingerprint)|\(dayKey)"
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
        let cutoff = now().addingTimeInterval(-Self.retention)
        state.seenEnvelopeIDs = state.seenEnvelopeIDs.filter { $0.value >= cutoff }
        // Day-count keys older than retention can't recur (their records expired server-side);
        // bound the map by keeping only days within the window.
        if state.acceptedBySenderDay.count > 4096 {
            state.acceptedBySenderDay.removeAll()
        }
    }

    private func persist() {
        try? FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        guard let data = try? JSONEncoder().encode(state) else { return }
        try? data.write(to: fileURL, options: [.atomic, .completeFileProtection])
    }
}
