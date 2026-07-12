// ModerationLedger.swift
// ProximityKit/Moderation
//
// Device-local, append-only store of moderation reports (this device's own reports in Phase 2; peers'
// verified reports arrive in Phase 3). A small JSON sidecar in Application Support, the same home and
// stance as HeartLedger.json — deliberately NEVER in the snapshot: who reported whom is sensitive
// social data and must not follow the user into iCloud. Rows are keyed by a deterministic id so a
// repeat report de-dupes and a retract supersedes its report by a higher `reporterSeq`.

import Foundation
import Observation
import FernletDomainModel

@MainActor
@Observable
public final class ModerationLedger {
    /// All stored rows (reports + retracts), most recent last. Bounded by `maxRows`.
    public private(set) var rows: [ModerationLedgerEntry] = []

    @ObservationIgnored private let fileURL: URL
    @ObservationIgnored private let now: () -> Date

    static let maxRows = 512

    public init(fileURL: URL? = nil, now: @escaping () -> Date = Date.init) {
        self.fileURL = fileURL ?? Self.defaultFileURL()
        self.now = now
        load()
    }

    // MARK: - Local report / retract

    /// Records a LOCAL report by this device (reporter == own key). Idempotent by artwork.
    @discardableResult
    public func recordLocalReport(
        reporterSigningPublicKey: Data, reporterFingerprint: String,
        subjectSigningPublicKey: Data, itemID: UUID, contentHash: Data, reason: String
    ) -> ModerationLedgerEntry {
        let entry = ModerationLedgerEntry(
            id: ModerationLedgerEntry.rowID(kind: .report, reporterFingerprint: reporterFingerprint, contentHash: contentHash),
            kind: .report,
            reporterSigningPublicKey: reporterSigningPublicKey,
            subjectSigningPublicKey: subjectSigningPublicKey,
            itemID: itemID, contentHash: contentHash, reasonToken: reason,
            reporterSeq: nextSeq(reporterFingerprint: reporterFingerprint, contentHash: contentHash),
            createdAt: now())
        upsert(entry)
        return entry
    }

    /// Records a LOCAL retract (undo) that supersedes the matching report.
    @discardableResult
    public func recordLocalRetract(
        reporterSigningPublicKey: Data, reporterFingerprint: String,
        subjectSigningPublicKey: Data, itemID: UUID, contentHash: Data
    ) -> ModerationLedgerEntry {
        let entry = ModerationLedgerEntry(
            id: ModerationLedgerEntry.rowID(kind: .retract, reporterFingerprint: reporterFingerprint, contentHash: contentHash),
            kind: .retract,
            reporterSigningPublicKey: reporterSigningPublicKey,
            subjectSigningPublicKey: subjectSigningPublicKey,
            itemID: itemID, contentHash: contentHash, reasonToken: ReportReason.other.rawValue,
            reporterSeq: nextSeq(reporterFingerprint: reporterFingerprint, contentHash: contentHash),
            createdAt: now())
        upsert(entry)
        return entry
    }

    /// Stores peers' already-verified report rows (from the one-hop relay). Upsert de-dupes by the
    /// deterministic id and keeps the higher `reporterSeq`, so re-delivery is idempotent.
    public func ingestForeign(_ entries: [ModerationLedgerEntry]) {
        for entry in entries { upsert(entry) }
    }

    // MARK: - Reads

    /// True when this device holds a live (non-retracted) local report for the artwork — used to hide
    /// a reported item from the shop grid and the buy path.
    public func isLocallyReported(contentHash: Data, reporterFingerprint: String) -> Bool {
        let reportID = ModerationLedgerEntry.rowID(kind: .report, reporterFingerprint: reporterFingerprint, contentHash: contentHash)
        guard let report = rows.first(where: { $0.id == reportID }) else { return false }
        let retractID = ModerationLedgerEntry.rowID(kind: .retract, reporterFingerprint: reporterFingerprint, contentHash: contentHash)
        if let retract = rows.first(where: { $0.id == retractID }), retract.reporterSeq > report.reporterSeq {
            return false
        }
        return true
    }

    /// Wipes every row and the on-disk sidecar (wired from `FernletStore.resetAll`).
    public func clearAll() {
        rows = []
        try? FileManager.default.removeItem(at: fileURL)
    }

    // MARK: - Internals

    private func nextSeq(reporterFingerprint: String, contentHash: Data) -> UInt64 {
        let reportID = ModerationLedgerEntry.rowID(kind: .report, reporterFingerprint: reporterFingerprint, contentHash: contentHash)
        let retractID = ModerationLedgerEntry.rowID(kind: .retract, reporterFingerprint: reporterFingerprint, contentHash: contentHash)
        let existing = rows.filter { $0.id == reportID || $0.id == retractID }.map(\.reporterSeq).max()
        return (existing ?? 0) + 1
    }

    private func upsert(_ entry: ModerationLedgerEntry) {
        if let index = rows.firstIndex(where: { $0.id == entry.id }) {
            // Same deterministic id: keep the higher-seq row (idempotent re-record).
            if entry.reporterSeq >= rows[index].reporterSeq { rows[index] = entry }
        } else {
            rows.append(entry)
        }
        if rows.count > Self.maxRows {
            rows = Array(rows.sorted { $0.createdAt < $1.createdAt }.suffix(Self.maxRows))
        }
        save()
    }

    private struct PersistedState: Codable {
        var version = 1
        var rows: [ModerationLedgerEntry] = []
        init() {}
        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            version = try c.decodeIfPresent(Int.self, forKey: .version) ?? 1
            rows = try c.decodeIfPresent([ModerationLedgerEntry].self, forKey: .rows) ?? []
        }
    }

    private func load() {
        guard let data = try? Data(contentsOf: fileURL),
              let state = try? JSONDecoder().decode(PersistedState.self, from: data) else { return }
        rows = state.rows.sorted { $0.createdAt < $1.createdAt }
    }

    private func save() {
        var state = PersistedState()
        state.rows = rows
        guard let data = try? JSONEncoder().encode(state) else { return }
        try? FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: fileURL, options: [.atomic, .completeFileProtection])
    }

    private nonisolated static func defaultFileURL() -> URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("Fernlet/ModerationLedger.json")
    }
}
