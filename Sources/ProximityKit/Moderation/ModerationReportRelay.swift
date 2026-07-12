// ModerationReportRelay.swift
// ProximityKit/Moderation
//
// The one-hop report wire (Phase 3b). A reporter hands their OWN Ed25519-signed report rows to a
// vault-trusted friend in person; the friend's device verifies each signature against the
// transport-verified sender key and stores only rows that sender personally signed. There is NO
// transitive relay and no merged global count — each device tallies over reports it verified itself,
// which is the Sybil defense (2026-07-11 ban memo).

import Foundation
import FernletDomainModel

/// One report row plus the reporter's signature over its canonical bytes.
public nonisolated struct SignedModerationReport: Codable, Equatable, Sendable {
    public var entry: ModerationLedgerEntry
    public var signature: Data
    public init(entry: ModerationLedgerEntry, signature: Data) {
        self.entry = entry
        self.signature = signature
    }
}

/// A sealed bundle of the sender's own signed reports (capped).
public nonisolated struct ModerationReportPayload: Codable, Equatable, Sendable {
    public var format = "fernlet.proximity.moderation.report"
    public var version = 1
    public var reports: [SignedModerationReport]
    public static let maxReports = 32

    public init(reports: [SignedModerationReport]) {
        self.reports = Array(reports.prefix(Self.maxReports))
    }
}

public enum ModerationReportRelay {
    /// Builds a payload of the local user's OWN report rows (reporter == local key), each signed.
    public static func buildPayload(ownReports: [ModerationLedgerEntry], identity: IdentityService) -> ModerationReportPayload {
        let localKey = identity.localSigningPublicKey
        let signed: [SignedModerationReport] = ownReports
            .filter { $0.reporterSigningPublicKey == localKey && $0.kind == .report }
            .prefix(ModerationReportPayload.maxReports)
            .compactMap { entry in
                guard let signature = try? identity.sign(ModerationLedgerEntry.canonicalSignedBytes(entry)) else { return nil }
                return SignedModerationReport(entry: entry, signature: signature)
            }
        return ModerationReportPayload(reports: signed)
    }

    /// Verifies + filters a received payload to the rows this device may store. Each row must be signed
    /// by the transport-verified SENDER key AND name that same sender as its reporter (one-hop: you may
    /// deliver only reports you yourself signed). The stored `id` and `reporterSeq` are re-derived from
    /// the verified sender so a hostile sender can't spoof another reporter's dedup key; a future-dated
    /// `createdAt` is clamped to `now` (decay uses the stored value, verification used the signed one).
    public static func verifiedRows(from payload: ModerationReportPayload, senderSigningKey: Data, now: Date) -> [ModerationLedgerEntry] {
        let senderFingerprint = IdentityService.fingerprint(of: senderSigningKey)
        return payload.reports.compactMap { signed in
            let entry = signed.entry
            guard entry.reporterSigningPublicKey == senderSigningKey else { return nil }       // one-hop
            guard entry.kind == .report else { return nil }
            guard IdentityService.verify(signed.signature,
                                         of: ModerationLedgerEntry.canonicalSignedBytes(entry),
                                         by: senderSigningKey) else { return nil }
            var row = entry
            row.id = ModerationLedgerEntry.rowID(kind: .report, reporterFingerprint: senderFingerprint, contentHash: row.contentHash)
            if row.createdAt > now { row.createdAt = now }
            return row
        }
    }
}
