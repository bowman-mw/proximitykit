// HeartDropSidecarFormatCensus.swift
// ProximityKit/HeartSharing
//
// Phase 0 of Docs/Plan-Crypto-Standardization-2026-08-27.md for the `HeartDropSidecarKey` surface
// (Class A, row 6 of the plan's §2 table).
//
// The plan's §3 names the missing precondition plainly: nothing can be deleted until the number of
// legacy blobs is known and observed to reach zero. This file produces that number for the
// heart-drop sidecars — and produces it the way the §6 risk row demands, from the MARKER BYTES
// ALONE. It never opens a blob, never reads a keychain row, and never writes anything.

import Foundation

/// Read-only census of the heart-drop sidecar corpus, classified by the four marker bytes at
/// offset 0 of each file.
///
/// **What it answers.** How many of this device's heart-drop sidecars are still in the read-only
/// `FSC1` legacy format (`HeartDropSidecarSeal.legacyMagic`), how many are in the current `FSC2`
/// format (`HeartDropSidecarSeal.magic`), and how many are in neither. Phase 3 of the plan — the
/// deletion of the legacy reader at `HeartDropSidecarKey.swift:61` — is gated on this reporting
/// zero legacy files on real upgraded devices, so the count must be produced honestly or not at all.
///
/// **Why it needs no key.** Classification is a pure prefix comparison: the seal's own
/// `isSealed` closure (`HeartDropSidecarKey.swift:48`) is exactly
/// `starts(with: magic) || starts(with: legacyMagic)`, evaluated before any keychain access. The
/// census therefore reads no keychain row AT ALL, which is not merely an optimization — it is what
/// keeps the count correct on the device that most needs counting: one whose seal key was wiped or
/// is momentarily unreadable still reports its ciphertext accurately, rather than reporting an
/// encouraging zero.
///
/// **`FSC1` provenance (read this before believing a zero).** The legacy prefix was WRITABLE only
/// between `beaff0d` (2026-07-26, the at-rest seal) and `91c3956` (2026-08-26, domain separation);
/// no writer emits it today. A device therefore holds `FSC1` bytes only if it wrote a sidecar
/// inside that ~one-month window and has not re-written that file since — and every persist
/// re-seals under `FSC2`, so an active outbox self-heals while a quiet dedup or peer-bundle file
/// does not. Real legacy corpora may well not exist outside dev devices; this census is how we find
/// out instead of assuming.
///
/// **What the census deliberately cannot tell you.** Bytes that match NEITHER marker are ambiguous
/// *by bytes alone*: a legitimate v0 plaintext JSON sidecar (which `ProtectedSidecar.performLoad`
/// silently migrates to sealed on the next load) and outright garbage are indistinguishable without
/// decoding the JSON — and decoding it would read the user's friend graph, which a census has no
/// business doing. They are conflated into the single honest ``FileState/unsealedOrUnrecognized``
/// bucket. `ProtectedSidecar.performLoad` (`ProtectedSidecar.swift:335-406`) is the runtime
/// authority that separates them, by decoding; this type is not.
///
/// **Locked devices.** Every sidecar is written `.completeFileProtection`
/// (`ProtectedSidecar.swift:170`), so a read attempted while the device is locked FAILS. That is
/// reported as ``FileState/unreadable`` — indeterminate, never zero — and ``Report/isConclusive``
/// goes false, because "I could not look" must never be mistaken for "there is nothing there".
/// The app lock is irrelevant here: these files are sealed by a keychain key, not by the lock.
public nonisolated enum HeartDropSidecarFormatCensus {

    // MARK: - The corpus

    /// The complete file-name table the census reads — three sealed sidecars plus at most one
    /// quarantine file, per storage scope.
    ///
    /// **This table must agree with the stores' own definitions**, which are the single source of
    /// each name, and it stays in agreement by CONSTRUCTION: ``url(in:)`` calls those definitions
    /// rather than repeating their literals.
    ///
    ///  - ``outbox`` — `HeartDropOutbox.fileURL(in:)`, `HeartDropOutbox.swift:296-298`
    ///  - ``peerBundles`` — `HeartDropPeerBundleCache.fileURL(in:)`,
    ///    `HeartDropPeerBundleCache.swift:84-86`
    ///  - ``dedup`` — `HeartDropDedupStore.fileURL(in:)`, `HeartDropOutbox.swift:381-383`
    ///  - ``outboxQuarantine`` — the outbox file plus ``quarantinePathExtension``, the suffix
    ///    `ProtectedSidecar` appends (`ProtectedSidecar.swift:158`). ONLY the outbox can produce
    ///    one: it is the single store constructed with `quarantinesUnreadableSealedData: true`
    ///    (`HeartDropOutbox.swift:93`); the other two delete unopenable sealed bytes instead of
    ///    parking them (`ProtectedSidecar.swift:447-450`).
    ///
    /// **Why the census enumerates known names instead of sweeping the directory.** The scope
    /// directory is shared: `HeartLedger.json`, the presence/closeness ledgers, the friend photo
    /// wall's cache and its preferences all live beside these files (see
    /// `ProximitySupportLayout.defaultDirectory`, `ProximityHost.swift:75`). A sweep would classify
    /// unrelated files as "unsealed" and inflate the very number Phase 3 is gated on. Four names,
    /// ever — if a fourth sidecar is added, it is added here in the same commit as its store.
    public nonisolated enum Sidecar: String, Sendable, Equatable, CaseIterable {
        /// The sender-side queue of pending heart drops, `HeartDropOutbox.json`.
        case outbox
        /// The gossiped peer prekey-bundle cache, `HeartDropPeerBundles.json`.
        case peerBundles
        /// The durable receive dedup + daily budget counters, `HeartDropDedup.json`.
        case dedup
        /// Outbox ciphertext parked because it could no longer be opened,
        /// `HeartDropOutbox.json.corrupt`. Absent on a healthy device — and absent is the normal,
        /// expected state, not a gap in the census.
        case outboxQuarantine

        /// This sidecar's file inside a heart-drop root, delegated to the store that owns the name
        /// so the census can never survey a file the store does not write.
        public func url(in directory: URL) -> URL {
            switch self {
            case .outbox: return HeartDropOutbox.fileURL(in: directory)
            case .peerBundles: return HeartDropPeerBundleCache.fileURL(in: directory)
            case .dedup: return HeartDropDedupStore.fileURL(in: directory)
            case .outboxQuarantine:
                return HeartDropOutbox.fileURL(in: directory)
                    .appendingPathExtension(HeartDropSidecarFormatCensus.quarantinePathExtension)
            }
        }
    }

    // MARK: - Bounds

    /// Bytes read per file — the length of the longest marker, so the census reads the marker and
    /// NOTHING beyond it. Derived from the seal's own constants rather than the literal `4`: if a
    /// future marker changes length, this bound follows it instead of silently truncating.
    public static let markerByteCount = max(
        HeartDropSidecarSeal.magic.count,
        HeartDropSidecarSeal.legacyMagic.count
    )

    /// The extension `ProtectedSidecar` appends for the quarantine copy
    /// (`ProtectedSidecar.swift:158`). Named here so the census's fourth file name has the same
    /// single-definition discipline as the three store-owned ones.
    public static let quarantinePathExtension = "corrupt"

    // MARK: - Buckets

    /// What one file's first ``markerByteCount`` bytes say about its format.
    ///
    /// Six buckets, and the split between them is the whole design: a file is counted as
    /// migrated (``v2Sealed``) only on positive evidence, while everything that could hide a
    /// legacy or unconverted blob falls into a bucket that keeps ``Report/isClean`` false.
    public nonisolated enum FileState: String, Sendable, Equatable, CaseIterable {
        /// No file at that name. A legitimate, common state — a device that never queued a heart
        /// has no outbox, and a healthy device never has a quarantine file.
        case absent
        /// Current format: the bytes begin with `HeartDropSidecarSeal.magic` (`FSC2`).
        case v2Sealed
        /// Read-only legacy format: the bytes begin with `HeartDropSidecarSeal.legacyMagic`
        /// (`FSC1`). THIS is the number Phase 3 is gated on reaching zero.
        case legacySealed
        /// Neither marker. Deliberately conflates two cases a marker cannot separate: a legitimate
        /// v0 plaintext JSON sidecar awaiting its silent seal-on-load migration, and corrupt or
        /// truncated garbage. Distinguishing them requires decoding the JSON — reading user
        /// content — which the census does not do. Both must block a "clean" verdict anyway: the
        /// first is unmigrated, and the second is unproven.
        case unsealedOrUnrecognized
        /// The file exists and is zero bytes. Carries no marker and no data; separated from
        /// ``unsealedOrUnrecognized`` because an empty file is a distinct on-disk accident (an
        /// interrupted write) rather than a candidate for migration.
        case empty
        /// The file exists but could not be opened or read — a locked device
        /// (`.completeFileProtection`), a permissions failure, or a file that vanished between the
        /// existence check and the open. INDETERMINATE, never zero: it makes
        /// ``Report/isConclusive`` false rather than being folded into any count that could be
        /// mistaken for evidence of absence.
        case unreadable
    }

    // MARK: - Result

    /// One surveyed file: which sidecar it is, the name that was looked for, and what its marker
    /// bytes said.
    public nonisolated struct FileReading: Sendable, Equatable {
        /// Which of the four known files this reading is for.
        public let sidecar: Sidecar
        /// The last path component actually surveyed — carried so a diagnostic row can name the
        /// file without re-deriving it, and so a report reads correctly on its own.
        public let fileName: String
        /// The bucket the marker bytes put it in.
        public let state: FileState

        public init(sidecar: Sidecar, fileName: String, state: FileState) {
            self.sidecar = sidecar
            self.fileName = fileName
            self.state = state
        }
    }

    /// One scope's census: a reading per known file, plus the aggregate counts Phase 0's exit
    /// criterion is stated in.
    ///
    /// The aggregates are COMPUTED from ``files`` rather than stored alongside it, so a report can
    /// never carry a total that disagrees with its own rows.
    public nonisolated struct Report: Sendable, Equatable {
        /// The heart-drop root that was surveyed.
        public let directory: URL
        /// One reading per ``Sidecar`` case, in ``Sidecar/allCases`` order.
        public let files: [FileReading]

        public init(directory: URL, files: [FileReading]) {
            self.directory = directory
            self.files = files
        }

        /// How many surveyed files landed in `state`.
        public func count(of state: FileState) -> Int {
            files.filter { $0.state == state }.count
        }

        /// The reading for one sidecar, or nil if this report did not survey it (only possible for
        /// a hand-built report; `survey(in:)` always covers all four).
        public func state(of sidecar: Sidecar) -> FileState? {
            files.first { $0.sidecar == sidecar }?.state
        }

        /// Files in the current `FSC2` format.
        public var v2SealedCount: Int { count(of: .v2Sealed) }
        /// Files still in the read-only `FSC1` legacy format — the Phase 3 gate.
        public var legacySealedCount: Int { count(of: .legacySealed) }
        /// Files matching neither marker (v0 plaintext or garbage — see
        /// ``FileState/unsealedOrUnrecognized``).
        public var unsealedOrUnrecognizedCount: Int { count(of: .unsealedOrUnrecognized) }
        /// Zero-byte files.
        public var emptyCount: Int { count(of: .empty) }
        /// Files that are not there — the normal state for most of the corpus on most devices.
        public var absentCount: Int { count(of: .absent) }
        /// Files that could not be read. Any non-zero value makes the report inconclusive.
        public var unreadableCount: Int { count(of: .unreadable) }

        /// Whether every known file was actually classified. False while anything was
        /// ``FileState/unreadable`` — the census looked and could not see, which is a different
        /// answer from "nothing is there" and must never be reported as one. Re-survey after
        /// unlock (`UIApplication.protectedDataDidBecomeAvailableNotification` is the same signal
        /// `ProtectedSidecar` retries on).
        public var isConclusive: Bool { unreadableCount == 0 }

        /// Whether this scope is PROVEN free of blobs a migration would have to convert: nothing
        /// legacy, nothing unrecognized, and nothing unread. Deliberately conservative in the same
        /// direction as `OwnPhotoKeyMigration`'s `isClean` — a pass that could not look at a file,
        /// or that found bytes it cannot vouch for, is not proof of completion.
        public var isClean: Bool {
            isConclusive && legacySealedCount == 0 && unsealedOrUnrecognizedCount == 0
        }
    }

    // MARK: - Survey

    /// Censuses one heart-drop root: every known file name, classified by its marker bytes.
    ///
    /// Read-only and bounded — four `stat`s and at most four opens of
    /// ``markerByteCount`` bytes each. Nothing is created, moved, rewritten or deleted, so this is
    /// safe to call from a DEBUG diagnostic row on a device carrying real tester data.
    public static func survey(in directory: URL) -> Report {
        let readings = Sidecar.allCases.map { sidecar -> FileReading in
            let url = sidecar.url(in: directory)
            return FileReading(
                sidecar: sidecar,
                fileName: url.lastPathComponent,
                state: classify(fileAt: url)
            )
        }
        return Report(directory: directory, files: readings)
    }

    /// Censuses the sidecars of one ``HeartDropStorageScope``.
    ///
    /// Only the scope's `directory` is used: the census needs no key, so the scope's
    /// `keychainService` half is deliberately untouched (see the type's "Why it needs no key").
    /// The scope overload exists because the module's rule is that every caller states its scope
    /// rather than reaching for a hidden production default — see ``HeartDropStorageScope``.
    public static func survey(in scope: HeartDropStorageScope) -> Report {
        survey(in: scope.directory)
    }

    /// Classifies ONE file by its first ``markerByteCount`` bytes.
    ///
    /// Order of evidence, and why: a missing file is ``FileState/absent`` (checked first, because
    /// it is the common case and is not a failure); an existing file that cannot be opened or read
    /// is ``FileState/unreadable`` (indeterminate — the locked-device answer); zero bytes is
    /// ``FileState/empty``; a short-but-non-empty head cannot match either 4-byte marker and joins
    /// ``FileState/unsealedOrUnrecognized``, as does anything else that matches neither.
    ///
    /// The existence check and the open are two syscalls, so a file deleted between them reports
    /// ``FileState/unreadable`` rather than ``FileState/absent``. That race resolves toward
    /// "inconclusive", which is the safe direction: it can only withhold a clean verdict, never
    /// manufacture one.
    public static func classify(fileAt url: URL) -> FileState {
        guard FileManager.default.fileExists(atPath: url.path) else { return .absent }
        guard let handle = try? FileHandle(forReadingFrom: url) else { return .unreadable }
        defer { try? handle.close() }
        let head: Data?
        do {
            head = try handle.read(upToCount: markerByteCount)
        } catch {
            // Any read failure is indeterminate, exactly as `ProtectedSidecar` treats one: the
            // census reports that it could not look, and never that there was nothing to see.
            return .unreadable
        }
        guard let head, !head.isEmpty else { return .empty }
        if head.starts(with: HeartDropSidecarSeal.magic) { return .v2Sealed }
        if head.starts(with: HeartDropSidecarSeal.legacyMagic) { return .legacySealed }
        return .unsealedOrUnrecognized
    }
}
