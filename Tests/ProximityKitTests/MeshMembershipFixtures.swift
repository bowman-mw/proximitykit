// MeshMembershipFixtures.swift
//
// Deterministic membership records for test fixtures. A twin (ProximityKit plan step A0.8): the
// same file at Tests/FernletTests and FernletKit/Tests/ProximityKitTests, held identical but for
// its imports by CIGateSelectorBoundaryTests.everyTwinMatchesItsOriginal(), because the package's
// three membership suites (MeshMembershipRecordsTests.swift) and six FernletTests files (the
// membership event wire, P7 acceptance, rotation trigger, session resume presentation, session
// state machine and session store suites) build fixtures with it, and a test target cannot import
// another.

import Foundation
@testable import ProximityKit

/// Fixtures the membership suites share: fingerprints, keys and records built from small integers so
/// every value in a test is reproducible and nothing reads a wall clock.
enum MeshMembershipFixtures {

    /// A fixed epoch so no fixture rots against the calendar.
    static let base = Date(timeIntervalSince1970: 1_700_000_000)

    /// A deterministic fingerprint. Zero-padded so lexical order matches numeric order.
    static func fingerprint(_ index: Int) -> String {
        String(format: "fp%03d", index)
    }

    /// A deterministic 32-byte signing key for member `index`.
    static func signingKey(_ index: Int) -> Data {
        Data((0..<32).map { UInt8((index &+ $0) % 251) })
    }

    /// A deterministic 64-byte signature blob. Opaque bytes; nothing here verifies it.
    static func signature(_ index: Int) -> Data {
        Data((0..<64).map { UInt8((index &* 7 &+ $0) % 251) })
    }

    static let meshID = UUID(uuidString: "1F1F1F1F-2E2E-4D4D-8C8C-0B0B0B0B0B0B") ?? UUID()

    /// An admission record for member `index`, `secondsIn` seconds after the base date.
    static func admission(_ index: Int, secondsIn: Int = 0) -> SignedAdmissionRecord {
        SignedAdmissionRecord(token: MeshAdmissionToken(
            meshID: meshID,
            joinerFingerprint: fingerprint(index),
            joinerSigningPublicKey: signingKey(index),
            admitterFingerprint: fingerprint(0),
            grantedAt: base.addingTimeInterval(TimeInterval(secondsIn)),
            expiresAt: base.addingTimeInterval(TimeInterval(secondsIn) + 7_200),
            admitterSigningPublicKey: signingKey(0),
            admitterSignature: signature(index)
        ))
    }

    /// A departure record signed by member `index`.
    static func departure(_ index: Int, secondsIn: Int = 100) -> SignedDepartureRecord {
        SignedDepartureRecord(
            meshID: meshID,
            memberFingerprint: fingerprint(index),
            occurredAt: base.addingTimeInterval(TimeInterval(secondsIn)),
            custodyHandoff: MeshCustodyHandoffSummary(
                custodianFingerprints: [fingerprint(0)],
                handedOffItemCount: 2
            ),
            signature: signature(index)
        )
    }

    /// A completed-removal record for member `index`, tallied by member 0.
    static func removal(_ index: Int, secondsIn: Int = 200) -> SignedRemovalRecord {
        SignedRemovalRecord(
            meshID: meshID,
            memberFingerprint: fingerprint(index),
            proposalID: UUID(uuidString: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE") ?? UUID(),
            voterFingerprints: [fingerprint(0), fingerprint(1)],
            occurredAt: base.addingTimeInterval(TimeInterval(secondsIn)),
            authorFingerprint: fingerprint(0),
            signature: signature(index)
        )
    }

    /// A termination record signed by member `index`.
    static func termination(_ index: Int, roster: [Int] = [], secondsIn: Int = 300) -> SignedTerminationRecord {
        SignedTerminationRecord(
            meshID: meshID,
            memberFingerprint: fingerprint(index),
            rosterAtSigning: roster.map(fingerprint),
            occurredAt: base.addingTimeInterval(TimeInterval(secondsIn)),
            signature: signature(index)
        )
    }

    /// A ledger admitting members `indices`, one second apart, in the order given.
    static func ledger(admitting indices: [Int]) -> MeshMembershipLedger {
        MeshMembershipLedger(
            admissions: MeshMembershipRecordSet(
                indices.enumerated().map { admission($0.element, secondsIn: $0.offset) }
            )
        )
    }
}
