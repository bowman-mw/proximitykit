import Foundation
#if canImport(UIKit)
import UIKit
#endif
import FernletFoundation

/// Sealing hooks for a sidecar file at rest (Increment 4 of
/// Docs/Plan-Prekeys-ProtectedLoad-CoachMesh-2026-07-26.md). The keychain-backed production
/// implementation lives in `HeartDropSidecarSeal`; tests inject their own closures.
public struct SidecarSeal {
    /// Seal/open failures, classified by recoverability — the transient case defers like a
    /// locked-file read; the others invoke per-store data-loss policy.
    public enum SealError: Error, Equatable {
        /// The seal key could not be read right now (locked keychain, interaction required).
        /// Treated like a deferred file read: the store goes `.unavailable` and retries.
        case keyTransientlyUnavailable
        /// The file is in sealed format but the key is definitively gone (`errSecItemNotFound`).
        /// Unrecoverable: nobody can ever open these bytes again — per-store policy applies.
        case keyMissingForSealedFile
        /// The key could not be minted/verified — refuse to seal rather than write ciphertext
        /// that a silently-dropped key would make unrecoverable.
        case sealFailed
        /// Decryption/authentication failed on bytes that claimed to be sealed. Unrecoverable.
        case openFailed
    }

    /// Whether `bytes` are in this seal's on-disk format (vs a legacy plaintext v0 file).
    public let isSealed: (Data) -> Bool
    /// Sealed file bytes → plaintext. Throws `SealError` only.
    public let open: (Data) throws -> Data
    /// Plaintext → sealed file bytes. Throws `SealError` only.
    public let seal: (Data) throws -> Data

    public init(
        isSealed: @escaping (Data) -> Bool,
        open: @escaping (Data) throws -> Data,
        seal: @escaping (Data) throws -> Data
    ) {
        self.isSealed = isSealed
        self.open = open
        self.seal = seal
    }
}

/// Load/persist state machine for the heart-sharing JSON sidecars (Track A of
/// Docs/Plan-Prekeys-ProtectedLoad-CoachMesh-2026-07-26.md).
///
/// The bug this exists to kill: every sidecar used to `try? Data(contentsOf:)` and treat ANY
/// read failure as "no data" — so a `.completeFileProtection` file touched while the device was
/// locked (or any transient I/O error) read as empty, and the next `persist()` wrote that empty
/// state back over the real file. This class classifies the read instead:
///
///  1. file absent            → empty value, `.ready` (genuinely no data)
///  2. read threw             → **`.unavailable`** — deliberately coarse: any read error is
///                              treated as transient, never as license to overwrite
///  3. read ok, decode threw  → corrupt, per-store policy (salvage / discard / quarantine)
///  4. decoded                → `.ready`
///
/// A failed WRITE is a different failure and must never cause a later reload from disk: the
/// on-disk copy is older, and re-reading it would discard the unpersisted mutation — for the
/// outbox's `markUploaded` that mutation IS the server record name, the one field nothing can
/// reconstruct once the record is on the public database. So "unavailable" is modeled as two
/// internal states: `.unloaded` (never read — retry the LOAD) and `.dirty(value)` (memory is
/// the truth — retry the PERSIST).
///
/// Retry is driven both on access (with a floor, because `hasCapacity`-style accessors are read
/// from view bodies every render) and proactively from
/// `UIApplication.protectedDataDidBecomeAvailableNotification`.
@MainActor
public final class ProtectedSidecar<Value: Codable> {

    /// The caller-visible availability. `.unavailable` covers BOTH failure flavors (never
    /// loaded, and loaded-but-the-last-write-failed) so the nothing-silent surfacing in
    /// `HeartDropService.refreshDeliveryProblem` sees them without caring which it is.
    public enum State: Equatable {
        case ready
        case unavailable
    }

    /// What became of a `mutate` call — persisted, applied only in memory, or refused outright.
    public enum MutateOutcome: Equatable {
        /// Applied and durably on disk.
        case persisted
        /// Applied to the in-memory value — which is now the truth — but the write failed.
        /// The store is `.unavailable` until a later persist lands it.
        case appliedNotPersisted
        /// Nothing was ever loaded; the mutation was refused so an empty state can never be
        /// written over the real file.
        case refused
    }

    /// The three-state internal model behind the two-state public `State` — dirty and unloaded
    /// recover differently (re-persist vs re-read), which is the whole point of the split.
    private enum Storage {
        /// Memory and disk agree.
        case ready(Value)
        /// Memory is the truth; the last write failed. Recovery re-PERSISTS, never re-reads.
        case dirty(Value)
        /// Never loaded: the read failed. Recovery re-attempts the LOAD.
        case unloaded
    }

    /// Floor between on-access load retries, so a failing file read is not re-attempted on
    /// every SwiftUI render (`FriendListView` reads capacity accessors from view bodies).
    /// `retryLoad()` — the sync-pass / unlock-notification path — bypasses it.
    static var retryFloor: TimeInterval { 5 }

    /// Sticky "data was actually lost" marker (corrupt rows discarded, or an unopenable sealed
    /// file quarantined/deleted). Process-local by design — a nudge, not a record — cleared by
    /// `acknowledgeDataLoss()` or `wipe()`.
    public private(set) var dataLossOccurred = false

    /// Called after a DEFERRED load recovers — whichever path recovered it (the unlock
    /// notification, an on-access read, or an explicit `retryLoad()`). Owners that publish a
    /// derived mirror of the value (`ProximityHeartLedger.receivedHearts`) hook this so the
    /// mirror can never go stale-empty when the sidecar heals through one of its own internal
    /// paths — without it, received hearts loaded on unlock stayed invisible for the whole
    /// session whenever nothing else touched the owner (review finding, 2026-07-26).
    public var onRecovery: (() -> Void)?

    private var storage: Storage = .unloaded
    private let fileURL: URL
    private let quarantineURL: URL
    private let empty: () -> Value
    private let seal: SidecarSeal?
    private let auditPrefix: String
    /// Corrupt-decode recovery: plaintext → (salvaged value, rows lost). Nil result means
    /// nothing was salvageable. Stores without one treat corrupt as empty-overwritable.
    private let salvage: ((Data) -> (value: Value, lostCount: Int)?)?
    /// What to do with SEALED bytes that can never be opened again (key gone / auth failure):
    /// `true` moves them aside to `<file>.corrupt` — ciphertext without a key is privacy-inert,
    /// and the moved file is a durable marker of the loss — `false` deletes them. Plaintext that
    /// fails to decode is always DISCARDED, never quarantined (locked decision O4: a corrupt
    /// plaintext outbox is a friend-graph privacy surface nobody can act on).
    private let quarantinesUnreadableSealedData: Bool
    private let now: () -> Date
    private let readData: (URL) throws -> Data
    private let writeData: (Data, URL) throws -> Void
    private var lastFailedLoadAt: Date?
    /// R9: a plain isolated `var` — the `isolated deinit` below runs on the main actor, so the
    /// token no longer needs `nonisolated(unsafe)` to be readable while tearing down.
    private var protectedDataObserver: (any NSObjectProtocol)?

    public init(
        fileURL: URL,
        empty: @autoclosure @escaping () -> Value,
        seal: SidecarSeal? = nil,
        auditPrefix: String,
        salvage: ((Data) -> (value: Value, lostCount: Int)?)? = nil,
        quarantinesUnreadableSealedData: Bool = false,
        now: @escaping () -> Date = { Date() },
        readData: ((URL) throws -> Data)? = nil,
        writeData: ((Data, URL) throws -> Void)? = nil,
        observeProtectedData: Bool = true
    ) {
        self.fileURL = fileURL
        self.quarantineURL = fileURL.appendingPathExtension("corrupt")
        self.empty = empty
        self.seal = seal
        self.auditPrefix = auditPrefix
        self.salvage = salvage
        self.quarantinesUnreadableSealedData = quarantinesUnreadableSealedData
        self.now = now
        self.readData = readData ?? { try Data(contentsOf: $0) }
        // Captured by value (not through `self`, which is still initializing) so the default
        // writer can name the store in its audit line.
        let auditPrefixForWrites = auditPrefix
        self.writeData = writeData ?? { data, url in
            try data.write(to: url, options: [.atomic, .completeFileProtection])
            // O1: the sidecars are device-scoped (their seal key is ThisDeviceOnly), so file and
            // key share one fate — and the cleartext friend graph stays out of iCloud backups.
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            var mutableURL = url
            do {
                try mutableURL.setResourceValues(values)
            } catch {
                // Benign — the bytes themselves are sealed (Increment 4), so the exclusion is
                // defense in depth — but a sidecar that can ride into a backup must not do so
                // silently.
                FernletAuditLog.log("\(auditPrefixForWrites).backupExclusionFailed",
                                    context: ["error": String(describing: error)])
            }
        }
        performLoad()
        #if canImport(UIKit)
        if observeProtectedData {
            // The block runs nonisolated under Swift 6 — never touch state directly; hop first.
            // The hop goes through the non-generic `ProtectedDataRetrying` erasure of `self`: a
            // `Task { @MainActor … }` closure that called `self?.retryLoad()` directly would
            // capture `Value.Type`, which is not Sendable for a generic parameter (SE-0470).
            let retrying: any ProtectedDataRetrying = self
            protectedDataObserver = NotificationCenter.default.addObserver(
                forName: UIApplication.protectedDataDidBecomeAvailableNotification,
                object: nil,
                queue: nil
            ) { [weak retrying] _ in
                Task { @MainActor [weak retrying] in retrying?.retryLoad() }
            }
        }
        #endif
    }

    isolated deinit {
        if let protectedDataObserver {
            NotificationCenter.default.removeObserver(protectedDataObserver)
        }
    }

    // MARK: - Reads

    public var state: State {
        if case .ready = storage { return .ready }
        return .unavailable
    }

    /// True when memory holds the truth (`.ready` OR `.dirty`) — i.e. answers derived from the
    /// value are real, even if the last write hasn't landed yet. False only while `.unloaded`,
    /// which is the one state whose answers would be lies.
    public var isLoaded: Bool {
        if case .unloaded = storage { return false }
        return true
    }

    /// The current value, or nil while nothing was ever loaded. A `.dirty` store still serves
    /// its in-memory value — that value IS the truth; only the disk is stale.
    public func read() -> Value? {
        retryLoadIfFloorAllows()
        switch storage {
        case .ready(let value), .dirty(let value): return value
        case .unloaded: return nil
        }
    }

    // MARK: - Mutations

    /// Commit-even-if-the-write-fails. For mutations that carry state which must survive a
    /// failed write (the outbox's `markUploaded` record name is already on the server — losing
    /// it strands the record). On write failure the value stays in memory as the truth and the
    /// store goes `.unavailable` until a later persist lands it.
    /// No `@discardableResult` (R7): the outcome is a success/failure signal. Callers that
    /// deliberately proceed regardless use ``mutateCommitting(_:)``, which names the ignore once.
    public func mutate(_ body: (inout Value) -> Void) -> MutateOutcome {
        retryLoadIfFloorAllows()
        switch storage {
        case .unloaded:
            // Logged here so a dropped mutation is never silent, whichever caller hit it.
            FernletAuditLog.log("\(auditPrefix).mutateRefused")
            return .refused
        case .ready(let value), .dirty(let value):
            var updated = value
            body(&updated)
            if attemptWrite(updated) {
                storage = .ready(updated)
                return .persisted
            }
            storage = .dirty(updated)
            return .appliedNotPersisted
        }
    }

    /// ``mutate(_:)`` for the commit-on-failure call sites that have no further recovery: the
    /// caller's own guards already proved the store is loaded, and BOTH non-`.persisted` outcomes
    /// are audit-logged inside (`writeFailed` / `mutateRefused`). Exists so the "ignore the
    /// outcome" decision lives in one named place instead of at every mutation site.
    public func mutateCommitting(_ body: (inout Value) -> Void) {
        switch mutate(body) {
        case .persisted, .appliedNotPersisted, .refused:
            break
        }
    }

    /// All-or-nothing: the mutation commits only if the write lands. For fail-closed
    /// bookkeeping (the dedup store's accept marks, prekey consumption) where refusing is safe
    /// — the record stays on the server / the prekey stays unburned — but a mark that exists in
    /// memory and not on disk would lie. A `.dirty` store first tries to flush its pending
    /// value; if that write still fails, the mutation is refused.
    /// No `@discardableResult` (R7): false means the mutation did NOT commit, which every caller
    /// has to act on (or name why it does not).
    public func mutateIfPersisted(_ body: (inout Value) -> Void) -> Bool {
        retryLoadIfFloorAllows()
        if case .dirty = storage { retryLoad() }
        guard case .ready(let current) = storage else { return false }
        var updated = current
        body(&updated)
        guard attemptWrite(updated) else { return false }
        storage = .ready(updated)
        return true
    }

    /// Re-attempts whichever recovery the current state needs: a failed LOAD is re-read; a
    /// failed WRITE re-persists the in-memory truth (never re-reads — the disk copy is older).
    ///
    /// Returns nothing (R7): the old `Bool` was exactly `state == .ready` afterwards, so callers
    /// read ``state``/``isLoaded`` directly instead of discarding a success value. Every failure
    /// path audit-logs inside (`writeFailed` from `attemptWrite`, `readDeferred` from the load).
    public func retryLoad() {
        switch storage {
        case .ready:
            return
        case .dirty(let value):
            if attemptWrite(value) { storage = .ready(value) }
        case .unloaded:
            performLoad()
            if isLoaded { onRecovery?() }
        }
    }

    public func acknowledgeDataLoss() {
        dataLossOccurred = false
    }

    /// Delete-all seam: removes the primary file AND the quarantine file, and resets to a
    /// ready-empty state (after a wipe, empty IS the truth — even if the store was unavailable).
    public func wipe() {
        removeItemLoggingFailure(at: fileURL, what: "primary")
        removeItemLoggingFailure(at: quarantineURL, what: "quarantine")
        storage = .ready(empty())
        dataLossOccurred = false
        lastFailedLoadAt = nil
    }

    // MARK: - Load classification

    private func retryLoadIfFloorAllows() {
        guard case .unloaded = storage else { return }
        if let lastFailedLoadAt, now().timeIntervalSince(lastFailedLoadAt) < Self.retryFloor {
            return
        }
        performLoad()
        if isLoaded { onRecovery?() }
    }

    private func performLoad() {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            storage = .ready(empty())
            return
        }
        let raw: Data
        do {
            raw = try readData(fileURL)
        } catch {
            // Deliberately coarse: ANY read error is transient. That is the safe direction —
            // the file survives untouched until a read succeeds.
            deferLoad(reason: "read")
            return
        }

        let plaintext: Data
        var needsSealedRewrite = false
        if let seal {
            if seal.isSealed(raw) {
                do {
                    plaintext = try seal.open(raw)
                } catch SidecarSeal.SealError.keyTransientlyUnavailable {
                    deferLoad(reason: "key")
                    return
                } catch {
                    // Key definitively gone or authentication failed: these bytes can never be
                    // opened again. Per-store policy (quarantine vs delete), never deferred.
                    handleUnopenableSealedFile(raw)
                    return
                }
            } else {
                // Legacy plaintext v0 file: read once, rewrite sealed below (one-way migration
                // — no dual-format read path to maintain afterwards).
                plaintext = raw
                needsSealedRewrite = true
            }
        } else {
            plaintext = raw
        }

        if let value = try? JSONDecoder().decode(Value.self, from: plaintext) {
            if needsSealedRewrite, attemptWrite(value) == false {
                // Migration write failed (e.g. sealing key transiently unreadable). The decoded
                // value is still the truth; `.dirty` retries the sealed rewrite, and the
                // plaintext file stays readable in the meantime.
                storage = .dirty(value)
                FernletAuditLog.log("\(auditPrefix).sealMigrationDeferred")
                return
            }
            storage = .ready(value)
            return
        }

        // Read succeeded, decode failed: corrupt. Salvage what parses; DISCARD the remainder
        // and audit-log the count (locked decision O4 — a corrupt blob is not quarantined,
        // because nobody can act on it and keeping plaintext is a second friend-key surface).
        if let salvage, let (value, lostCount) = salvage(plaintext) {
            FernletAuditLog.log("\(auditPrefix).corrupt", context: [
                "salvaged": "\(salvagedCount(of: value))", "lost": "\(lostCount)"
            ])
            if lostCount > 0 { dataLossOccurred = true }
            if attemptWrite(value) {
                storage = .ready(value)
            } else {
                storage = .dirty(value)
            }
            return
        }
        FernletAuditLog.log("\(auditPrefix).corrupt", context: ["salvaged": "0", "lost": "all"])
        dataLossOccurred = true
        removeItemLoggingFailure(at: fileURL, what: "corruptDiscard")
        storage = .ready(empty())
    }

    /// Best-effort file removal that still names its failure (R7): "already absent" IS the goal,
    /// anything else is logged, because a file that survives a wipe/discard must not do so
    /// silently. Removal failure never changes the caller's state transition — the next persist
    /// overwrites the file either way.
    private func removeItemLoggingFailure(at url: URL, what: String) {
        do {
            try FileManager.default.removeItem(at: url)
        } catch CocoaError.fileNoSuchFile {
            return
        } catch {
            FernletAuditLog.log("\(auditPrefix).removeFailed", context: [
                "what": what, "error": String(describing: error)
            ])
        }
    }

    private func deferLoad(reason: String) {
        lastFailedLoadAt = now()
        if case .unloaded = storage {} else { storage = .unloaded }
        FernletAuditLog.log("\(auditPrefix).readDeferred", context: ["reason": reason])
    }

    private func handleUnopenableSealedFile(_ raw: Data) {
        dataLossOccurred = true
        if quarantinesUnreadableSealedData {
            // Ciphertext without its key is privacy-inert; parking it preserves a durable
            // marker that data was lost (and the wipe owns the quarantine path).
            removeItemLoggingFailure(at: quarantineURL, what: "staleQuarantine")
            do {
                try FileManager.default.moveItem(at: fileURL, to: quarantineURL)
                FernletAuditLog.log("\(auditPrefix).quarantined")
            } catch {
                // The durable marker could not be parked: the unopenable bytes stay at fileURL
                // and the next persist overwrites them (the delete policy's outcome). Say so
                // rather than logging "quarantined" for something that never moved.
                FernletAuditLog.log("\(auditPrefix).quarantineFailed",
                                    context: ["error": String(describing: error)])
            }
        } else {
            removeItemLoggingFailure(at: fileURL, what: "unopenableDiscard")
            FernletAuditLog.log("\(auditPrefix).unopenableDiscarded")
        }
        storage = .ready(empty())
    }

    private func salvagedCount(of value: Value) -> Int {
        (value as? any Collection)?.count ?? 1
    }

    // MARK: - Writes

    /// Pure write attempt — no state transition, so callers can implement both commit-on-failure
    /// (`mutate`) and rollback-on-failure (`mutateIfPersisted`) semantics on top of it.
    private func attemptWrite(_ value: Value) -> Bool {
        do {
            let plaintext = try JSONEncoder().encode(value)
            let fileBytes: Data
            if let seal {
                fileBytes = try seal.seal(plaintext)
            } else {
                fileBytes = plaintext
            }
            try FileManager.default.createDirectory(
                at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try writeData(fileBytes, fileURL)
            return true
        } catch {
            // Logged at the seam, so every write failure is named once regardless of which
            // mutation path hit it (`mutate`, `mutateIfPersisted`, or a `.dirty` re-persist).
            FernletAuditLog.log("\(auditPrefix).writeFailed",
                                context: ["error": String(describing: error)])
            return false
        }
    }
}

// MARK: - Unlock-notification hop seam

/// The non-generic face of ``ProtectedSidecar`` that the protected-data-available notification
/// hop calls through.
///
/// `Task { @MainActor … }` takes a `@Sendable` closure, and a closure that calls a method on the
/// generic sidecar directly captures `Value.Type` — not Sendable for a generic parameter (SE-0470),
/// and constraining `Value: SendableMetatype` would in turn reject every payload whose `Codable`
/// conformance is main-actor isolated (all of them are: they are nested in `@MainActor` stores).
/// Erasing `self` to this existential once, in the generic initializer, keeps the hop free of the
/// metatype. `Sendable` so the erased reference can be weakly captured by the notification block;
/// the conformer is `@MainActor` and therefore Sendable already.
@MainActor
private protocol ProtectedDataRetrying: AnyObject, Sendable {
    /// Re-attempts a deferred load; see ``ProtectedSidecar/retryLoad()``.
    func retryLoad()
}

extension ProtectedSidecar: ProtectedDataRetrying {}
