import Foundation

/// Persisted sender-side queue for offline heart drops + the durable receive dedup
/// (bitchat adoptions Increment 3). Two small JSON sidecars beside `HeartLedger.json` —
/// deliberately NOT in the synced snapshot: drops are pairwise device-scoped, like the ledger.
///
/// Outbox pattern from bitchat's courier outbox (persisted, resend-until-expiry, bounded); the
/// dedup store is load-bearing on its own: `ProximityHeartLedger` retains only 48 h / 32 hearts,
/// so a still-on-server record would re-deliver after ledger pruning without this 30-day record.
///
/// Both stores load through `ProtectedSidecar` (Track A, 2026-07-26): a transient read failure
/// is `.unavailable` — never "empty" — so a locked-device read can no longer let the next
/// persist overwrite the real file. The outbox fails OPEN on remembered state (its in-memory
/// value stays the truth across a failed write, because `recordName` is unreconstructable) and
/// CLOSED on new state; the dedup store fails closed in both directions.
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

    public enum EnqueueOutcome: Equatable, Sendable {
        case queued
        case backlogFull
        /// The sidecar is unavailable (unloaded, or a write is failing) — refused so a heart the
        /// UI reports as "tucked away" can never exist only in memory.
        case storageUnavailable
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

    private let sidecar: ProtectedSidecar<[Entry]>
    private let now: () -> Date

    public init(
        fileURL: URL? = nil,
        seal: SidecarSeal? = nil,
        now: @escaping () -> Date = { Date() },
        readData: ((URL) throws -> Data)? = nil,
        writeData: ((Data, URL) throws -> Void)? = nil
    ) {
        self.now = now
        self.sidecar = ProtectedSidecar(
            fileURL: fileURL ?? Self.defaultFileURL(),
            empty: [],
            seal: seal,
            auditPrefix: "heartdrop.outbox",
            salvage: Self.salvageEntries(_:),
            // A sealed outbox blob nobody can open still names public-DB records; parking it is
            // the durable marker of that loss, and the wipe owns the quarantine path.
            quarantinesUnreadableSealedData: true,
            now: now,
            readData: readData,
            writeData: writeData
        )
    }

    // MARK: - Availability (Increment 2/3 surfacing seams)

    /// Fully healthy: loaded AND the last write landed. New hearts are only accepted here.
    public var isAvailable: Bool { sidecar.state == .ready }
    /// Memory holds the truth (possibly with a write still owed). Derived answers are real.
    public var isLoaded: Bool { sidecar.isLoaded }
    /// Sticky: corrupt rows were discarded or an unopenable sealed file was quarantined.
    public var dataLossOccurred: Bool { sidecar.dataLossOccurred }
    public func acknowledgeDataLoss() { sidecar.acknowledgeDataLoss() }
    @discardableResult
    public func retryLoad() -> Bool { sidecar.retryLoad() }

    private var entries: [Entry]? { sidecar.read() }

    /// Whether another heart for this friend would fit under the backlog cap. Callers check this
    /// BEFORE spending anything irreversible on the send (a one-time prekey, the 5-minute
    /// cooldown) — see `HeartDropService.queueHeart`. False while unavailable (fail-closed; the
    /// delivery-problem surface says why).
    public func hasCapacity(forFriendSigningKey key: Data) -> Bool {
        guard entries != nil else { return false }
        return pendingCount(friendSigningKey: key) < Self.maxPendingPerFriend
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
        guard entries != nil else { return false }
        return queuedCount(
            friendSigningKey: key,
            dayEpoch: IdentityService.heartDropDayEpoch(at: date)
        ) < Self.maxPerFriendPerDay
    }

    /// Drops queued for this friend whose `createdAt` falls in the given UTC day epoch — the same
    /// bucket the receiver derives from the signed `createdAt` when it applies its own budget.
    public func queuedCount(friendSigningKey: Data, dayEpoch: UInt64) -> Int {
        (entries ?? []).filter {
            $0.friendSigningKey == friendSigningKey
                && IdentityService.heartDropDayEpoch(at: $0.createdAt) == dayEpoch
        }.count
    }

    /// New hearts are accepted only when the sidecar is fully healthy AND the write lands —
    /// all-or-nothing, so `.queued` is never reported for a heart that exists only in memory.
    @discardableResult
    public func enqueue(_ entry: Entry) -> EnqueueOutcome {
        guard sidecar.read() != nil, isAvailable else { return .storageUnavailable }
        guard hasCapacity(forFriendSigningKey: entry.friendSigningKey) else { return .backlogFull }
        guard sidecar.mutateIfPersisted({ $0.append(entry) }) else { return .storageUnavailable }
        return .queued
    }

    public func pendingUploads() -> [Entry] {
        // Only a fully healthy outbox uploads: uploading while the record name could not be
        // durably recorded is exactly the orphaned-record bug Increment 3 closes.
        guard isAvailable else { return [] }
        return (entries ?? []).filter { $0.recordName == nil && !isExpired($0) }
    }

    /// Records the server name for an uploaded entry. False when the name did NOT land durably —
    /// either the write failed (the name is kept in memory as the truth and re-persisted by a
    /// later pass) or the entry is gone (wiped mid-flight). The record is on the public database
    /// either way, so the caller must treat false as a possible orphan, not continue silently.
    @discardableResult
    public func markUploaded(id: UUID, recordName: String) -> Bool {
        guard let current = entries, current.contains(where: { $0.id == id }) else { return false }
        let outcome = sidecar.mutate { entries in
            guard let index = entries.firstIndex(where: { $0.id == id }) else { return }
            entries[index].recordName = recordName
        }
        return outcome == .persisted
    }

    public func recordAttempt(id: UUID) {
        sidecar.mutate { entries in
            guard let index = entries.firstIndex(where: { $0.id == id }) else { return }
            entries[index].attempts += 1
        }
    }

    /// Entries past their lifetime — cleanup deletes their server records (when uploaded) and
    /// then removes them. Empty unless fully healthy: cleanup's remote deletes must not run
    /// against a state whose removals might not persist.
    public func expiredEntries() -> [Entry] {
        guard isAvailable else { return [] }
        return (entries ?? []).filter { isExpired($0) }
    }

    public func remove(ids: [UUID]) {
        guard !ids.isEmpty else { return }
        let removal = Set(ids)
        // Commit-on-failure: the caller already deleted these entries' server records, so the
        // removal must hold in memory even if the write is owed.
        sidecar.mutate { $0.removeAll { removal.contains($0.id) } }
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
        guard !captured.isEmpty, let current = entries else { return 0 }
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
        let before = current.count
        var after = before
        sidecar.mutate { entries in
            entries.removeAll { entry in
                guard let name = entry.recordName else { return capturedPending.contains(entry.id) }
                return capturedNames[entry.id] == name
            }
            after = entries.count
        }
        return before - after
    }

    /// Hearts still WAITING for this friend: not yet uploaded and not yet expired. An uploaded
    /// entry is retained (cleanup needs its record name) but it has already been delivered to the
    /// dead-drop, so it neither counts against the backlog cap nor reads as "waiting" in the UI.
    /// Zero while unloaded — safe only because the delivery-problem surface reports the outage.
    public func pendingCount(friendSigningKey: Data) -> Int {
        (entries ?? []).filter {
            $0.friendSigningKey == friendSigningKey && $0.recordName == nil && !isExpired($0)
        }.count
    }

    /// Entries the sender gave up on: past their lifetime and never uploaded. Drives the
    /// user-facing "these hearts never made it" signal — undelivered hearts must not vanish
    /// silently.
    public func expiredUndeliveredCount() -> Int {
        (entries ?? []).filter { isExpired($0) && $0.recordName == nil }.count
    }

    /// Highest retry count among entries still waiting to upload, and the oldest such entry's
    /// creation date — the delivery-health inputs (`HeartDropService.DeliveryProblem`).
    public func uploadFailureState() -> (maxAttempts: Int, oldestCreatedAt: Date)? {
        let waiting = (entries ?? []).filter { $0.recordName == nil && !isExpired($0) }
        guard let maxAttempts = waiting.map(\.attempts).max(),
              let oldest = waiting.map(\.createdAt).min() else { return nil }
        return (maxAttempts, oldest)
    }

    /// Every uploaded entry's server record name — the purge path deletes these from the public
    /// database when the user turns the feature off or wipes. NIL while unloaded: an unloaded
    /// outbox reporting "no uploaded records" is exactly the "the UI says it's gone when it
    /// isn't" lie the derived stranded-records state exists to kill. Callers must propagate the
    /// unknown, not treat it as empty.
    public func uploadedRecordNames() -> [String]? {
        guard let entries else { return nil }
        return entries.compactMap(\.recordName)
    }

    /// Every entry as of right now, or NIL while unloaded (see `uploadedRecordNames()`). The
    /// purge path captures this BEFORE its remote delete and then removes exactly these ids
    /// afterwards. There is deliberately no `removeAll()`: a purge that wiped the outbox after
    /// its await would destroy hearts queued during it — including their record names, stranding
    /// those records on the public database with nothing left to name them.
    public func snapshot() -> [Entry]? {
        entries
    }

    /// Delete-all seam (Docs/PrivacyWipeCoverage.md). Removes the primary file AND the
    /// quarantine file; the seal key is deleted by `HeartPrekeyStore.wipeForDeleteAll()`
    /// (same keychain service).
    public func wipeForDeleteAll() {
        sidecar.wipe()
    }

    // MARK: - Persistence

    private func isExpired(_ entry: Entry) -> Bool {
        entry.createdAt.addingTimeInterval(Self.entryLifetime) < now()
    }

    private static func defaultFileURL() -> URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Fernlet/HeartDropOutbox.json")
    }

    /// Element-wise lossy decode for a corrupt outbox (locked decision O4): keep what parses,
    /// discard the remainder. This preserves `recordName`s across an additive `Entry` field —
    /// the single highest-consequence loss in the subsystem (a lost record name = a permanently
    /// undeletable public-DB record; creator-delete-only). Nil when nothing is even array-shaped.
    private struct FailableEntry: Decodable {
        let entry: Entry?
        init(from decoder: Decoder) {
            entry = try? Entry(from: decoder)
        }
    }

    private static func salvageEntries(_ data: Data) -> (value: [Entry], lostCount: Int)? {
        guard let rows = try? JSONDecoder().decode([FailableEntry].self, from: data) else {
            return nil
        }
        let kept = rows.compactMap(\.entry)
        return (kept, rows.count - kept.count)
    }
}

/// Durable dedup + per-sender-per-day acceptance counters for RECEIVED drops. Retains 30 days —
/// past the pickup window and the sender's 14-day record lifetime with margin.
///
/// Budget keying (review 2026-07-25): the day bucket is a UTC day EPOCH the receiver derives and
/// clamps, never the sender-supplied `sentAtDayKey`. A shape-valid day string admits ~10^8 distinct
/// buckets, so keying on it made the flood bound vacuous against exactly the adversary it exists
/// for — a client that ignores its own 5-minute consume-on-send.
///
/// Fail-closed in BOTH directions while the sidecar is unavailable (Track A): an accept mark that
/// exists only in memory would re-deliver after a crash, and a wiped-by-overwrite store would
/// hand every sender a fresh budget — so nothing is accepted unless the mark landed on disk.
/// The record stays on the server and the next sync re-fetches it; no double-delivery, no reset.
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

    private let sidecar: ProtectedSidecar<State>
    private let now: () -> Date

    public init(
        fileURL: URL? = nil,
        seal: SidecarSeal? = nil,
        now: @escaping () -> Date = { Date() },
        readData: ((URL) throws -> Data)? = nil,
        writeData: ((Data, URL) throws -> Void)? = nil
    ) {
        self.now = now
        self.sidecar = ProtectedSidecar(
            fileURL: fileURL ?? FileManager.default
                .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("Fernlet/HeartDropDedup.json"),
            empty: State(),
            seal: seal,
            auditPrefix: "heartdrop.dedup",
            // Corrupt → empty, overwritable: neither loss is irrecoverable (a re-delivered heart
            // is a duplicate bubble the ledger's id-dedup mostly absorbs).
            now: now,
            readData: readData,
            writeData: writeData
        )
    }

    public var isAvailable: Bool { sidecar.state == .ready }
    @discardableResult
    public func retryLoad() -> Bool { sidecar.retryLoad() }

    /// Records the envelope id; false when it was already seen (drop the record silently) OR the
    /// mark could not be durably persisted (drop stays on the server for a later pass).
    public func recordIfNew(envelopeID: UUID) -> Bool {
        guard var state = sidecar.read(), isAvailable else { return false }
        prune(&state)
        guard state.seenEnvelopeIDs[envelopeID] == nil else { return false }
        state.seenEnvelopeIDs[envelopeID] = now()
        return sidecar.mutateIfPersisted { $0 = state }
    }

    /// Whether the sender still has acceptance budget for this UTC day epoch; increments on accept.
    /// `dayEpoch` MUST be receiver-derived (the caller clamps the signed `createdAt` into the
    /// pickup window) — passing a sender-controlled value re-opens the flood hole.
    public func acceptIfWithinDailyBudget(senderFingerprint: String, dayEpoch: UInt64) -> Bool {
        guard var state = sidecar.read(), isAvailable else { return false }
        prune(&state)
        let key = "\(senderFingerprint)|\(dayEpoch)"
        let count = state.acceptedBySenderDay[key, default: 0]
        guard count < Self.maxAcceptedPerSenderPerDay else { return false }
        state.acceptedBySenderDay[key] = count + 1
        return sidecar.mutateIfPersisted { $0 = state }
    }

    /// Delete-all seam (Docs/PrivacyWipeCoverage.md).
    public func wipeForDeleteAll() {
        sidecar.wipe()
    }

    private func prune(_ state: inout State) {
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
}
