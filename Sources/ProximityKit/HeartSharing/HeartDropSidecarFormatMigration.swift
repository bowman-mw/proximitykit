// HeartDropSidecarFormatMigration.swift
// ProximityKit/HeartSharing
//
// Phase 2.2 of Docs/Plan-Crypto-Standardization-2026-08-27.md for the `HeartDropSidecarKey`
// surface (Class A, row 6 of the plan's §2 table): the scan → convert → latch format migrator
// that drives the census's `legacySealedCount` to zero so Phase 3 can delete the read-only
// `FSC1` branch at `HeartDropSidecarKey.swift:61`.
//
// The scan IS the census (`HeartDropSidecarFormatCensus.survey`) — same code, so the buckets can
// never disagree with the number Phase 3 is gated on. The convert step goes through
// `HeartDropSidecarSeal.make`'s existing `open`/`seal` closures, so the migrator binds the
// existing registered `heartDropSidecarV2` purpose without ever naming a purpose, touching key
// bytes, or adding a crypto call shape of its own. Writes go through `SidecarFileWriter` — the
// same atomic + `.completeFileProtection` + backup-exclusion path every sidecar persist uses.

import Foundation
import FernletCrypto
import FernletFoundation

/// The persisted "no heart-drop sidecar on this device is in the `FSC1` legacy format" latch
/// (crypto-standardization Phase 2.2).
///
/// ATTESTS: a full pass over the census's three MAIN rows (outbox, peer bundles, dedup) found
/// every one `absent`, `empty`, or `v2Sealed`, converted nothing, and failed nothing. The
/// quarantine row never participates: `HeartDropOutbox.json.corrupt` is a durable data-loss
/// tombstone no reader ever opens again, so its marker bytes prove nothing about live data.
///
/// DOES NOT ATTEST the Phase-3 gate — that gate reads the census on real upgraded devices at
/// gate time, per-row, never this bit. The latch's job is to stop re-funding passes and keep the
/// steady-state launch cost at four `stat`s — and even a set latch is REVALIDATED against the
/// disk every launch (``HeartDropSidecarFormatMigrator/runAtLaunch()``), so observation always
/// beats memory.
///
/// Device-local (`UserDefaults`, never synced): the claim is about THIS device's bytes. Cleared
/// by `deleteAllData` via ``resetForDeleteAll(defaults:)`` — the wipe destroys the latch's
/// entire subject, the sidecar files (`heartDropService.wipeForDeleteAll()`) AND the seal key
/// (`HeartPrekeyStore.wipeForDeleteAll()`'s service-wide delete), the deliberate mirror-image of
/// `ownPhotoKeyMigrationComplete`'s kept row, whose subject survives its wipe. Wipe wall:
/// `Docs/PrivacyWipeCoverage.md` + `PersistedSurfaceWipeBoundaryTests`, same commit as this key.
///
/// Concurrency: `nonisolated` value type over `UserDefaults` (itself thread-safe), as the
/// `FormatMigrationLatching` family expects.
public nonisolated struct HeartDropSidecarMigrationLatch: FormatMigrationLatching {
    /// The `UserDefaults` key holding the latch. A `static let` literal so the wipe wall's
    /// discovery scan finds it (the `OwnPhotoMigrationLatch` shape, byte for byte).
    public static let defaultsKey = "com.fernlet.heartdrop.sidecarFormatMigrationComplete"

    private let defaults: UserDefaults

    /// Creates a latch over `defaults`; tests inject an isolated suite so they never touch the
    /// device's real completion state.
    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    /// Whether a full clean pass has proven every main-row sidecar is out of the legacy format.
    /// Absent (never set) reads as false — the fail-closed direction.
    public var isComplete: Bool {
        defaults.bool(forKey: Self.defaultsKey)
    }

    /// Records completion. Called ONLY from `FormatMigrator.run(maxPasses:)` after a clean pass;
    /// never from a UI path, and never speculatively.
    public func markComplete() {
        defaults.set(true, forKey: Self.defaultsKey)
    }

    /// Clears the latch, forcing a re-scan on the next run. For tests, for the delete-all funnel
    /// (via ``resetForDeleteAll(defaults:)``), and for
    /// ``HeartDropSidecarFormatMigrator/runAtLaunch()``'s revalidation when the disk contradicts
    /// the recorded proof.
    public func reset() {
        defaults.removeObject(forKey: Self.defaultsKey)
    }

    /// The delete-all funnel's named clear — the wipe-wall token, spelled as its own static so
    /// the funnel call site is distinctive for both walls' matchers.
    public static func resetForDeleteAll(defaults: UserDefaults = .standard) {
        HeartDropSidecarMigrationLatch(defaults: defaults).reset()
    }
}

/// One migration pass's tally — and, through ``isClean``, the sole authority on whether the
/// completion latch may be set.
///
/// Buckets follow the census `FileState`s on the three MAIN rows; the quarantine row is carried
/// as a reading (``quarantineState``), never as a verdict input. Every examined row lands in
/// exactly ONE bucket, so the counts always sum to ``examined`` and a diagnostic read of the
/// tally is never off by a phantom row.
///
/// Conforms to `FormatMigrationPassResult`: ``isClean`` and ``madeForwardProgress`` are the two
/// verdicts the shared `FormatMigrator.run(maxPasses:)` loop reads; the buckets below are this
/// migration's own diagnostic breakdown.
public nonisolated struct HeartDropSidecarMigrationResult: Sendable, Equatable,
                                                           FormatMigrationPassResult {
    /// Main rows surveyed (three — the quarantine row is deliberately not one of them).
    public let examined: Int
    /// Already in the current `FSC2` format — nothing to do.
    public let alreadyV2: Int
    /// No file, or a zero-byte file. Both non-blocking, matching the census's `isClean`: neither
    /// carries a blob the Phase-3 reader delete could cost.
    public let absentOrEmpty: Int
    /// `FSC1` rows opened, re-sealed under `FSC2`, verified round-trip BEFORE the atomic write,
    /// and read back afterwards — by THIS pass. Non-zero means the corpus was not clean when the
    /// pass started, so the latch waits for a following pass to confirm zero.
    public let converted: Int
    /// A conversion step failed after a successful open: the seal, the pre-write verification,
    /// the atomic write, or the post-write read-back. Blocks the latch; the source bytes are
    /// untouched (verify-before-replace), so the next pass re-examines.
    public let convertFailures: Int
    /// `open` threw either key error (`keyTransientlyUnavailable` or `keyMissingForSealedFile`).
    /// INDETERMINATE, never unopenable — "the key is gone" is a fact about the key, not proof
    /// about the bytes — and it blocks the latch. ALSO counts every legacy main row left
    /// unattempted after the key-error stop: one key serves all files, so those rows are
    /// indeterminate for the identical reason, and tallying them here keeps every examined row
    /// in exactly one bucket (a two-legacy-file keyless corpus reads 2, never 1).
    public let keyUnavailable: Int
    /// Key present, authentication failed. Blocks the latch — a named deviation from
    /// `OwnPhotoKeyMigrationResult.unopenable`'s non-blocking rule: the store read path resolves
    /// such a file only destructively and only on its lazily-triggered next load, so "already
    /// resolves" cannot be asserted at pass time. Disposal stays delegated to the store's
    /// shipped policy (outbox → quarantine, dedup/peer-bundles → delete); the following
    /// launch's pass then reads clean.
    public let unopenableLegacy: Int
    /// A main row matching neither marker — v0 plaintext or garbage, indistinguishable without
    /// decoding the friend graph, which this migrator refuses for the census's reason. Blocks
    /// the latch, fail-closed, and is NEVER touched: `ProtectedSidecar.performLoad` is the
    /// runtime authority that resolves it (seal-on-load or salvage/discard) when the store
    /// next loads.
    public let unmarkedPending: Int
    /// The census read `.unreadable`, or the full read of a legacy row failed. Blocks the latch —
    /// "I could not look" must never latch.
    public let unreadable: Int
    /// The quarantine row's census reading, reported for diagnostics only. Whatever it says —
    /// including `.legacySealed` — it never blocks: the tombstone's bytes were already
    /// unreadable when they were parked, and no reader ever opens the quarantine path again.
    public let quarantineState: HeartDropSidecarFormatCensus.FileState

    /// Whether this pass PROVES the corpus is fully migrated: every main row was `absent`,
    /// `empty`, or `v2Sealed`, and nothing was converted or failed this pass. The only state
    /// that may set the latch.
    public var isClean: Bool {
        converted == 0 && convertFailures == 0 && keyUnavailable == 0
            && unopenableLegacy == 0 && unmarkedPending == 0 && unreadable == 0
    }

    /// Whether this pass converted at least one row — the forward-progress verdict the shared
    /// run loop uses to decide between "confirm with another pass" and "stop, retry next launch".
    public var madeForwardProgress: Bool { converted > 0 }

    /// Creates a result. Public (with zero defaults) so tests can build expectations; production
    /// values come from ``HeartDropSidecarFormatMigrator/performPass()``.
    public init(
        examined: Int = 0,
        alreadyV2: Int = 0,
        absentOrEmpty: Int = 0,
        converted: Int = 0,
        convertFailures: Int = 0,
        keyUnavailable: Int = 0,
        unopenableLegacy: Int = 0,
        unmarkedPending: Int = 0,
        unreadable: Int = 0,
        quarantineState: HeartDropSidecarFormatCensus.FileState = .absent
    ) {
        self.examined = examined
        self.alreadyV2 = alreadyV2
        self.absentOrEmpty = absentOrEmpty
        self.converted = converted
        self.convertFailures = convertFailures
        self.keyUnavailable = keyUnavailable
        self.unopenableLegacy = unopenableLegacy
        self.unmarkedPending = unmarkedPending
        self.unreadable = unreadable
        self.quarantineState = quarantineState
    }
}

/// The Phase 2.2 `FormatMigrator` conformer: converts `FSC1` heart-drop sidecars to `FSC2`
/// in bounded, resumable, idempotent passes.
///
/// **Scan = the census.** `performPass()` opens with `HeartDropSidecarFormatCensus.survey`, so
/// classification cannot drift from the number Phase 3 is gated on. **Convert = the shipping
/// seal.** A legacy main row is opened through the existing legacy-read branch — this migrator
/// is that branch's last legitimate caller — and re-sealed through the existing v2 path, which
/// binds the registered `heartDropSidecarV2` purpose inside the closure; the migrator never
/// names a purpose and never reads a key byte. Open comes strictly BEFORE seal, and seal only
/// for a file open just succeeded on, so `loadOrMintKey`'s minting arm is unreachable: a
/// keyless pass leaves the keychain rowless, and a clean corpus latches without touching the
/// keychain at all (the survey is marker-only).
///
/// **Never deletes.** The pass contains no file removal of any kind; the only mutation is the
/// single atomic in-place rewrite of a verified-openable legacy main row, after the candidate
/// bytes were proven to round-trip. Unopenable, unmarked, unreadable, empty and quarantine
/// files are left byte-identical.
///
/// Concurrency: `@MainActor` (the module default) with an isolated conformance to the
/// nonisolated sync `FormatMigrator` — the entire seal path and every sidecar writer live on
/// the main actor, and the ≤4-file corpus makes the synchronous pass a few milliseconds with
/// no suspension points, so a store persist can never interleave mid-file. `run()` is called
/// synchronously from a MainActor context, exactly the use SE-0470 isolated conformances
/// permit (compile-spiked at hour zero; plan A of the Phase 2.2 design).
@MainActor
public struct HeartDropSidecarFormatMigrator: FormatMigrator {
    /// The completion latch the shared `FormatMigrator.run(maxPasses:)` loop sets after a clean
    /// pass (a protocol requirement, which is why it is not `private`). The latch TYPE is a
    /// nonisolated value type as the protocol family expects, but this stored property is
    /// main-actor isolated (an isolated witness, legal under the isolated conformance): Swift 6
    /// allows `nonisolated` on a stored property only for `Sendable` types, and `UserDefaults`
    /// — the latch's one member — is not `Sendable` in this SDK.
    public let latch: HeartDropSidecarMigrationLatch

    /// R2: the named maximum number of sweep passes the shared `run(maxPasses:)` funds — one to
    /// convert every legacy main row (there are at most three), one to confirm by marker scan.
    nonisolated public static let maxMigrationPasses = 2

    /// The audit-event family every log line here uses, and the prefix the shared writer's
    /// backup-exclusion failure line is filed under.
    nonisolated static let auditPrefix = "heartdrop.sidecarFormat"

    private let scope: HeartDropStorageScope
    private let seal: SidecarSeal
    private let readData: (URL) throws -> Data
    private let writeData: (Data, URL) throws -> Void

    /// Creates a migrator over one storage scope. The `readData`/`writeData` test seam mirrors
    /// `ProtectedSidecar`: nil means the shipping paths (a plain `Data(contentsOf:)` read, and
    /// `SidecarFileWriter` — the same atomic, fully-protected, backup-excluded write every
    /// sidecar persist uses).
    public init(
        scope: HeartDropStorageScope,
        latch: HeartDropSidecarMigrationLatch,
        readData: ((URL) throws -> Data)? = nil,
        writeData: ((Data, URL) throws -> Void)? = nil
    ) {
        self.scope = scope
        self.latch = latch
        // Building the seal is key-free: the closures load the keychain row per USE (no cache),
        // so a clean pass — which never calls them — inherits the census's key-free property.
        self.seal = HeartDropSidecarSeal.make(keychainService: scope.keychainService)
        self.readData = readData ?? { try Data(contentsOf: $0) }
        self.writeData = writeData ?? { data, url in
            try SidecarFileWriter.write(data, to: url, auditPrefix: Self.auditPrefix)
        }
    }

    /// The production migrator for one scope: shipping read/write paths, latch on `defaults`.
    public static func standard(
        scope: HeartDropStorageScope,
        defaults: UserDefaults = .standard
    ) -> HeartDropSidecarFormatMigrator {
        HeartDropSidecarFormatMigrator(scope: scope, latch: latch(defaults: defaults))
    }

    /// The completion latch over `defaults` — the same one ``standard(scope:defaults:)`` uses,
    /// exposed so a caller can read the gate without building a migrator.
    public static func latch(defaults: UserDefaults = .standard) -> HeartDropSidecarMigrationLatch {
        HeartDropSidecarMigrationLatch(defaults: defaults)
    }

    // MARK: - The pass

    /// Census survey → convert legacy main rows → tally. Never sets the latch — `run(maxPasses:)`
    /// owns that decision — so tests can drive passes directly and assert idempotence.
    ///
    /// - Returns: the pass tally, which carries the pass's failure information. R7: not
    ///   `@discardableResult`.
    public func performPass() -> HeartDropSidecarMigrationResult {
        let report = HeartDropSidecarFormatCensus.survey(in: scope.directory)
        var outcomes: [RowOutcome] = []
        var keyErrorStopped = false
        // R2: bounded by the census's fixed four-name corpus; the three main rows land here.
        for reading in report.files where reading.sidecar != .outboxQuarantine {
            let outcome: RowOutcome
            if reading.state == .legacySealed && keyErrorStopped {
                // Left unattempted after the key-error stop: the one key that just failed is
                // the key that serves this row too, so it is indeterminate for the same reason
                // — tallied per-file so every examined row has exactly one bucket.
                outcome = .keyUnavailable
            } else {
                outcome = examine(reading)
            }
            if outcome == .keyUnavailable { keyErrorStopped = true }
            outcomes.append(outcome)
        }
        let result = HeartDropSidecarMigrationResult(
            examined: outcomes.count,
            alreadyV2: outcomes.filter { $0 == .alreadyV2 }.count,
            absentOrEmpty: outcomes.filter { $0 == .absentOrEmpty }.count,
            converted: outcomes.filter { $0 == .converted }.count,
            convertFailures: outcomes.filter { $0 == .convertFailure }.count,
            keyUnavailable: outcomes.filter { $0 == .keyUnavailable }.count,
            unopenableLegacy: outcomes.filter { $0 == .unopenableLegacy }.count,
            unmarkedPending: outcomes.filter { $0 == .unmarkedPending }.count,
            unreadable: outcomes.filter { $0 == .unreadable }.count,
            // `survey(in:)` always covers all four rows; the coalesce is for the type system,
            // and `.absent` is the honest stand-in for a reading that does not exist.
            quarantineState: report.state(of: .outboxQuarantine) ?? .absent
        )
        logPassOutcome(result)
        return result
    }

    /// The launch entry point: a set latch is REVALIDATED with one marker-only survey (four
    /// `stat`s, at most 16 bytes, key-free); any observed BLOCKING-CLASS main row —
    /// `legacySealed`, `unsealedOrUnrecognized`, or `unreadable`, i.e. exactly the set the latch
    /// predicate refuses to latch over — resets the latch and falls through to `run()`. One
    /// predicate serves both directions: the latch never stands over a corpus its own `isClean`
    /// would refuse, so a restore-reintroduced file (or a `.standard`-latch contaminated by a
    /// scoped store) is observed on the next launch, not silently outlived. The reset changes no
    /// file's fate — unmarked bytes are never converted under any latch state; only the audit
    /// truthfulness and pass-funding change.
    ///
    /// - Returns: whether completion is proven now. R7: deliberately not `@discardableResult` —
    ///   a false must be surfaced (the caller logs `heartdrop.sidecarFormat.incomplete`).
    public func runAtLaunch() -> Bool {
        if latch.isComplete {
            let report = HeartDropSidecarFormatCensus.survey(in: scope.directory)
            guard Self.anyMainRowBlocks(in: report) else { return true }
            FernletAuditLog.log("\(Self.auditPrefix).latchInvalidated")
            latch.reset()
        }
        return run()
    }

    // MARK: - Per-row conversion

    /// The bucket one examined main row landed in — private plumbing between the per-row
    /// conversion and the pass tally, mirroring the result's fields one-to-one.
    private enum RowOutcome: Equatable {
        case alreadyV2
        case absentOrEmpty
        case converted
        case convertFailure
        case keyUnavailable
        case unopenableLegacy
        case unmarkedPending
        case unreadable
    }

    /// Maps one census reading to its bucket, converting the `legacySealed` case.
    private func examine(_ reading: HeartDropSidecarFormatCensus.FileReading) -> RowOutcome {
        switch reading.state {
        case .absent, .empty: return .absentOrEmpty
        case .v2Sealed: return .alreadyV2
        case .unsealedOrUnrecognized: return .unmarkedPending
        case .unreadable: return .unreadable
        case .legacySealed: return convertLegacyRow(at: reading.sidecar.url(in: scope.directory))
        }
    }

    /// Converts ONE legacy main row in place: full read, defensive marker re-check, open through
    /// the existing legacy branch, re-seal through the existing v2 path, round-trip verify
    /// BEFORE the atomic write, read back after. The source bytes are replaced only by that one
    /// atomic write — nothing is ever deleted, so every failure leaves the file wholly old and
    /// re-examined next pass.
    private func convertLegacyRow(at url: URL) -> RowOutcome {
        let raw: Data
        do {
            raw = try readData(url)
        } catch {
            return .unreadable
        }
        // Defensive re-check: a synchronous MainActor pass makes drift from the survey
        // impossible, but the guard re-buckets rather than assumes.
        if raw.starts(with: HeartDropSidecarSeal.magic) { return .alreadyV2 }
        guard !raw.isEmpty else { return .absentOrEmpty }
        guard raw.starts(with: HeartDropSidecarSeal.legacyMagic) else { return .unmarkedPending }
        let plaintext: Data
        do {
            plaintext = try seal.open(raw)
        } catch SidecarSeal.SealError.keyTransientlyUnavailable,
                SidecarSeal.SealError.keyMissingForSealedFile {
            // Indeterminate, never unopenable: a fact about the KEY, not proof about the bytes.
            // Both self-resolve without the migrator (recovery by next launch, or the store's
            // own load policy), after which a later pass reads clean.
            return .keyUnavailable
        } catch {
            // Key present, authentication failed (`.openFailed` — including a malformed key
            // row, which `loadKeyForOpen` reports the same way). Blocking; disposal stays
            // delegated to the store's shipped policy.
            return .unopenableLegacy
        }
        let candidate: Data
        do {
            candidate = try seal.seal(plaintext)
        } catch {
            return .convertFailure
        }
        // Pre-write verification: the candidate bytes round-trip under the keychain row that
        // will open them, proven BEFORE the old bytes are replaced.
        guard candidate.starts(with: HeartDropSidecarSeal.magic),
              opensBack(candidate, to: plaintext) else {
            return .convertFailure
        }
        do {
            try writeData(candidate, url)
        } catch {
            // Atomicity means the file is wholly old; re-examined next pass.
            return .convertFailure
        }
        return readBackConfirms(at: url, plaintext: plaintext) ? .converted : .convertFailure
    }

    /// Whether `sealed` opens back to exactly `plaintext` through the shipping seal.
    private func opensBack(_ sealed: Data, to plaintext: Data) -> Bool {
        do {
            return try seal.open(sealed) == plaintext
        } catch {
            return false
        }
    }

    /// Post-write read-back: the file now on disk carries the `FSC2` marker and opens back to
    /// the original plaintext. A false blocks the latch, but loses nothing — the bytes were
    /// verified in memory before the write, and the atomic write excludes torn state.
    private func readBackConfirms(at url: URL, plaintext: Data) -> Bool {
        let echoed: Data
        do {
            echoed = try readData(url)
        } catch {
            return false
        }
        return echoed.starts(with: HeartDropSidecarSeal.magic) && opensBack(echoed, to: plaintext)
    }

    /// Whether any MAIN row of `report` is in a blocking class — `legacySealed`,
    /// `unsealedOrUnrecognized`, or `unreadable`. Deliberately THE SAME set the latch predicate
    /// refuses, so ``runAtLaunch()``'s reset predicate equals the latch predicate.
    private nonisolated static func anyMainRowBlocks(
        in report: HeartDropSidecarFormatCensus.Report
    ) -> Bool {
        // R2: bounded by the census's fixed four-name corpus.
        report.files.contains { reading in
            guard reading.sidecar != .outboxQuarantine else { return false }
            switch reading.state {
            case .legacySealed, .unsealedOrUnrecognized, .unreadable: return true
            case .absent, .empty, .v2Sealed: return false
            }
        }
    }

    /// Names every non-no-op pass outcome in the audit log (nothing-silent): conversions with
    /// the full bucket tally, and conversion failures. Indeterminate/blocked passes surface
    /// through the caller's `heartdrop.sidecarFormat.incomplete` line when `runAtLaunch()`
    /// returns false.
    private func logPassOutcome(_ result: HeartDropSidecarMigrationResult) {
        if result.converted > 0 {
            FernletAuditLog.log("\(Self.auditPrefix).converted", context: [
                "converted": "\(result.converted)",
                "alreadyV2": "\(result.alreadyV2)",
                "absentOrEmpty": "\(result.absentOrEmpty)",
                "keyUnavailable": "\(result.keyUnavailable)",
                "unopenableLegacy": "\(result.unopenableLegacy)",
                "unmarkedPending": "\(result.unmarkedPending)",
                "unreadable": "\(result.unreadable)"
            ])
        }
        if result.convertFailures > 0 {
            FernletAuditLog.log("\(Self.auditPrefix).convertFailed", context: [
                "failures": "\(result.convertFailures)"
            ])
        }
    }
}
