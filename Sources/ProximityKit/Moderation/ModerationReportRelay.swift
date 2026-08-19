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
import FernletFoundation

/// One report row plus the reporter's Ed25519 signature over its canonical bytes.
///
/// The unit of the one-hop relay: the receiver re-verifies the signature against the
/// transport-verified sender key before the row is ever stored.
public nonisolated struct SignedModerationReport: Codable, Equatable, Sendable {
    public var entry: ModerationLedgerEntry
    public var signature: Data
    public init(entry: ModerationLedgerEntry, signature: Data) {
        self.entry = entry
        self.signature = signature
    }
}

/// A sealed wire bundle of the sender's OWN signed reports (capped at `maxReports`).
///
/// Rides the friend mesh as the `.itemReport` payload; carries retractions alongside reports so
/// an undo propagates to peers who already stored the original row.
public nonisolated struct ModerationReportPayload: Codable, Equatable, Sendable {
    public var format = "fernlet.proximity.moderation.report"
    public var version = 1
    public var reports: [SignedModerationReport]
    public static let maxReports = 32

    // Anti-bloat upper bounds on the per-row variable-length fields, in the same spirit as
    // `ActivityRosterSnapshot.maxParticipantKeyBytes`: a reporter controls its own signature, so it
    // could sign a perfectly valid but multi-MB row that we would then verify, persist verbatim and
    // re-read forever. These are generous — they only reject an abusive sender, never a well-formed
    // row — and they are checked BEFORE the Ed25519 verification so an oversized row costs no CPU.

    /// Largest accepted `contentHash`. SHA-256 is 32 bytes; 64 leaves room for SHA-512 without a wire break.
    public static let maxContentHashBytes = 64
    /// Largest accepted `subjectSigningPublicKey`. Matches `ActivityRosterSnapshot.maxParticipantKeyBytes`
    /// (a raw Ed25519 key is 32 bytes).
    public static let maxSubjectKeyBytes = 128
    /// Largest accepted `reasonToken`. Every `ReportReason` raw value is under 10 ASCII bytes.
    public static let maxReasonTokenBytes = 64

    public init(reports: [SignedModerationReport]) {
        self.reports = Array(reports.prefix(Self.maxReports))
    }

    /// Hand-written so the cap holds on the RECEIVE path too (R3): the synthesized `Decodable`
    /// bypassed `init(reports:)`, so a peer could ship thousands of self-signed rows and have
    /// every one signature-verified and upserted.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        format = try container.decodeIfPresent(String.self, forKey: .format)
            ?? "fernlet.proximity.moderation.report"
        version = try container.decodeIfPresent(Int.self, forKey: .version) ?? 1
        let decoded = try container.decodeIfPresent([SignedModerationReport].self, forKey: .reports) ?? []
        reports = Array(decoded.prefix(Self.maxReports))
    }
}

/// Builds and verifies the one-hop moderation-report wire (Phase 3b): a reporter hands only rows
/// they personally signed to a vault-trusted friend, and the receiver stores only rows the
/// transport-verified sender signed.
///
/// The no-transitive-relay rule is the Sybil defense — each device tallies over reports it
/// verified itself. Stateless namespace enum; ``MeshNetworkManager`` calls `buildPayload` on slot
/// commit and `verifiedRows` in its `.itemReport` handler, with storage owned by the app-side
/// ``ModerationLedger``.
public enum ModerationReportRelay {
    /// Builds a payload of the local user's OWN rows (reporter == local key), each signed. Carries both
    /// reports AND their retractions, so undoing a report propagates to peers who already stored it (a
    /// retract supersedes its report by a higher `reporterSeq` in `ModerationEconomy.liveReports`).
    ///
    /// DELIBERATELY unfiltered by recipient: rows whose `subjectSigningPublicKey` is the RECIPIENT's own
    /// key are sent too, and dropping them is not the harmless privacy win it looks like. Because the
    /// relay is strictly one-hop (`verifiedRows` requires `reporterSigningPublicKey == senderSigningKey`,
    /// so no third party ever forwards a row), the reporter is the ONLY party that can ever deliver a row
    /// naming a device as its subject — those rows are the sole evidence source for
    /// ``ModerationBanStore/reconcile(rows:localSigningKey:)``'s self-ban branch. Filtering them here
    /// would make `isSelfBanned` unreachable and silently delete the shipped "a maker whose items are
    /// repeatedly reported loses their shop for a while" behaviour, with nothing in the build to say so.
    /// `ModerationBanTests.testForeignRowsNamingLocalKeySelfBanTheShop` pins this. That the report is
    /// therefore visible to the person reported is disclosed in the report copy and the privacy policy.
    public static func buildPayload(ownReports: [ModerationLedgerEntry], identity: IdentityService) -> ModerationReportPayload {
        let localKey = identity.localSigningPublicKey
        let signed: [SignedModerationReport] = ownReports
            .filter { $0.reporterSigningPublicKey == localKey && ($0.kind == .report || $0.kind == .retract) }
            .prefix(ModerationReportPayload.maxReports)
            .compactMap { entry in
                guard let signature = try? identity.sign(canonicalBytes(for: entry)) else { return nil }
                return SignedModerationReport(entry: entry, signature: signature)
            }
        return ModerationReportPayload(reports: signed)
    }

    /// Verifies + filters a received payload to the rows this device may store. Each row must be signed
    /// by the transport-verified SENDER key AND name that same sender as its reporter (one-hop: you may
    /// deliver only rows you yourself signed). Both reports and retractions are carried; the stored `id`
    /// is re-derived from the verified sender AND the row's own kind so a hostile sender can't spoof
    /// another reporter's dedup key (and a retract can't masquerade as a report or vice versa). A
    /// future-dated `createdAt` is clamped to `now` (decay uses the stored value; verification used the
    /// signed one). `reporterSeq` is preserved so a retract still supersedes its report. Rows whose
    /// variable-length fields exceed the anti-bloat bounds are rejected outright, before the signature
    /// check — see ``ModerationReportPayload/maxContentHashBytes``.
    public static func verifiedRows(from payload: ModerationReportPayload, senderSigningKey: Data, now: Date) -> [ModerationLedgerEntry] {
        let senderFingerprint = IdentityService.fingerprint(of: senderSigningKey)
        // R3: the cap is applied where the input ENTERS, not only in the memberwise init.
        let rows: [ModerationLedgerEntry] = payload.reports.prefix(ModerationReportPayload.maxReports).compactMap { signed in
            let entry = signed.entry
            guard entry.reporterSigningPublicKey == senderSigningKey else { return nil }       // one-hop
            guard entry.kind == .report || entry.kind == .retract else { return nil }
            // R3 size bound, BEFORE the signature check: a well-signed multi-MB row would otherwise be
            // verified (expensive) and then stored verbatim forever. REJECT rather than clamp —
            // clamping mutates the signed bytes, so the row would be stored under content its own
            // signature no longer covers. `reporterSigningPublicKey` needs no bound: the guard above
            // already forces it equal to the transport-verified sender key.
            guard entry.contentHash.count <= ModerationReportPayload.maxContentHashBytes,
                  entry.subjectSigningPublicKey.count <= ModerationReportPayload.maxSubjectKeyBytes,
                  entry.reasonToken.utf8.count <= ModerationReportPayload.maxReasonTokenBytes else { return nil }
            guard IdentityService.verify(signed.signature,
                                         of: canonicalBytes(for: entry),
                                         by: senderSigningKey) else { return nil }
            var row = entry
            row.id = ModerationLedgerEntry.rowID(kind: entry.kind, reporterFingerprint: senderFingerprint, contentHash: row.contentHash)
            if row.createdAt > now { row.createdAt = now }
            return row
        }
        // NOTHING SILENT: a row dropped here is a peer's report we refused to count, so the shortfall
        // is named once per payload rather than vanishing inside the `compactMap`. Counts only — the
        // reporter fingerprint is sensitive social data and does not belong in the audit log.
        if rows.count < payload.reports.count {
            FernletAuditLog.log("moderation.relay.rowsRejected", context: [
                "received": String(payload.reports.count),
                "kept": String(rows.count)
            ])
        }
        return rows
    }
}
