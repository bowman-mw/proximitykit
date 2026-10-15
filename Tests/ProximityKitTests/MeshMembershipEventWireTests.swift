// MeshMembershipEventWireTests.swift
// ProximityKitTests
//
// P3 item 3 (plan §8.3, §9, §10.5): the membership events that move signed bytes.
//
// Four claims are walled here, each one a thing a later item cannot cheaply re-derive:
//
// 1. **The signed bytes are pinned.** Golden vectors written from the FORMAT — a length-prefixed
//    domain, fixed-width integers and dates, length-prefixed strings — not copied out of the
//    serializer's own output. A golden that only records what the code did proves nothing about
//    what the code should do; these were computed independently and then met.
// 2. **The registry's declared framing matches the bytes.** Every new purpose is `.lengthPrefixed`
//    and every new serializer must satisfy it. That pairing is what broke silently in `91c3956`,
//    so it is asserted in `CryptographicPurposeBoundaryTests` beside the introduction's — and the
//    cross-domain half is asserted here: a departure signature must not verify as a termination.
// 3. **Verification happens BEFORE insertion.** Item 1's sets are capped at sixteen and keep the
//    EARLIEST records, so unverified junk with a low timestamp does not merely add noise — it
//    crowds a real removal out of the set on every device it reaches.
// 4. **A legacy goodbye cannot end a membership.** It is unsigned; the strongest thing it can mean
//    is "this link is going away". Letting it mint a permanent, grow-only departure record would
//    make eviction forgeable by anyone who can reach the link, with no way to undo it.
//
// A partial copy (ProximityKit plan step A1, the split's first batch of copied suites): of the
// Fernlet repository's FernletTests file of the same name, this holds only the fixtures the
// package's copied suites read (`MeshMembershipEventFixtures` and `extension
// MeshInventoryDigestPayload`), unchanged; its suites stay there, so what this header says of them
// is not held here.

import Foundation
import Testing
@testable import ProximityKit

// MARK: - Fixtures

/// Fixed values shared by the golden vectors, so every byte in a pinned hex string is traceable to
/// a line here and nothing reads a wall clock.
enum MeshMembershipEventFixtures {

    static let meshID = UUID(uuidString: "1F1F1F1F-2E2E-4D4D-8C8C-0B0B0B0B0B0B") ?? UUID()
    static let proposalID = UUID(uuidString: "2A2A2A2A-3B3B-4C4C-8D8D-0E0E0E0E0E0E") ?? UUID()
    /// A second proposal, so the voter-cap vector is a different record rather than a variant of
    /// the one item 3 already pinned.
    static let cappedProposalID = UUID(uuidString: "3C3C3C3C-4D4D-4E4E-8F8F-1A1A1A1A1A1A") ?? UUID()
    static let base = Date(timeIntervalSince1970: 1_700_000_000)

    /// A 64-byte blob standing in for a signature in the golden vectors. Signatures are EXCLUDED
    /// from canonical bytes, so its value must not be able to change a single pinned byte — which
    /// is itself one of the things the goldens prove.
    static let opaqueSignature = Data(repeating: 0xAB, count: 64)

    static func departure() -> SignedDepartureRecord {
        SignedDepartureRecord(
            meshID: meshID,
            memberFingerprint: "fp001",
            occurredAt: base.addingTimeInterval(60),
            custodyHandoff: MeshCustodyHandoffSummary(
                custodianFingerprints: ["fp002", "fp003"],
                handedOffItemCount: 4
            ),
            signature: opaqueSignature
        )
    }

    static func removal() -> SignedRemovalRecord {
        SignedRemovalRecord(
            meshID: meshID,
            memberFingerprint: "fp004",
            proposalID: proposalID,
            voterFingerprints: ["fp001", "fp002"],
            occurredAt: base.addingTimeInterval(120),
            authorFingerprint: "fp001",
            signature: opaqueSignature
        )
    }

    /// A completed removal citing the §9 maximum number of voters — the widest voter list the
    /// format ever has to carry, and the one a frame's clamp is judged against.
    static func removalAtVoterCap() -> SignedRemovalRecord {
        SignedRemovalRecord(
            meshID: meshID,
            memberFingerprint: "fp009",
            proposalID: cappedProposalID,
            voterFingerprints: (1...MeshMembershipBounds.maxVoters).map { String(format: "fp%03d", $0) },
            occurredAt: base.addingTimeInterval(300),
            authorFingerprint: "fp002",
            signature: opaqueSignature
        )
    }

    static func termination() -> SignedTerminationRecord {
        SignedTerminationRecord(
            meshID: meshID,
            memberFingerprint: "fp001",
            rosterAtSigning: ["fp001", "fp002"],
            occurredAt: base.addingTimeInterval(180),
            signature: opaqueSignature
        )
    }

    /// A ledger holding exactly one admission, built from item 1's own fixtures so the digest's
    /// pinned hash is reproducible.
    static func singleAdmissionLedger() -> MeshMembershipLedger {
        MeshMembershipLedger(admissions: MeshMembershipRecordSet([MeshMembershipFixtures.admission(1)]))
    }

    static func inventoryPayload() -> MeshInventoryDigestPayload {
        MeshInventoryDigestPayload(
            digest: MeshInventoryDigest(meshID: meshID, ledger: singleAdmissionLedger()),
            senderFingerprint: "fp001",
            sentAt: base.addingTimeInterval(240),
            signature: opaqueSignature
        )
    }

    /// The two divergent branch heads the epoch-head vector carries: one counter, two minting
    /// coordinators — the only shape a merge actually has to reconcile (plan §10.3).
    ///
    /// Built through ``MeshEpochRef/minted(counter:coordinatorFingerprint:meshID:)`` so the ids in
    /// the pinned hex are the *derived* ones a real branch would compute, not literals a test made
    /// up: a change to the epoch-id derivation must move this golden.
    static func divergentHeads() -> [MeshEpochRef] {
        [
            MeshEpochRef.minted(counter: 7, coordinatorFingerprint: "00000000000000aa", meshID: meshID),
            MeshEpochRef.minted(counter: 7, coordinatorFingerprint: "00000000000000bb", meshID: meshID)
        ].compactMap { $0 }
    }

    /// The `fernlet.mesh.epoch-heads.v1` frame's payload (P4 item 3).
    static func epochHeadsPayload() -> MeshEpochHeadsPayload {
        MeshEpochHeadsPayload(
            meshID: meshID,
            heads: divergentHeads(),
            senderFingerprint: "fp001",
            sentAt: base.addingTimeInterval(300),
            signature: opaqueSignature
        )
    }

    /// P4 item 5's proposal id — a third one, so the quorum vectors are their own records rather
    /// than variants of the two the removal goldens already pinned.
    static let quorumProposalID = UUID(uuidString: "4E4E4E4E-5F5F-4A4A-9B9B-2C2C2C2C2C2C") ?? UUID()

    /// The `fernlet.mesh.removal-proposal.v1` frame (plan §10.4). Its target is the same `fp004`
    /// the removal record names, so the three vectors read as one story: propose, vote, complete.
    static func removalProposal() -> SignedRemovalProposal {
        SignedRemovalProposal(
            meshID: meshID,
            proposalID: quorumProposalID,
            targetFingerprint: "fp004",
            proposerFingerprint: "fp001",
            issuedAt: base.addingTimeInterval(360),
            signature: opaqueSignature
        )
    }

    /// The `fernlet.mesh.removal-vote.v1` frame: `fp002` agreeing with the proposal above.
    static func removalVote() -> SignedRemovalVote {
        SignedRemovalVote(
            meshID: meshID,
            proposalID: quorumProposalID,
            targetFingerprint: "fp004",
            voterFingerprint: "fp002",
            castAt: base.addingTimeInterval(420),
            signature: opaqueSignature
        )
    }

    /// The 32-byte key-agreement public key the P6 item 1 vector advertises. A fixed pattern, and
    /// deliberately not the signature blob's `0xAB`, so a transposed field would move the golden.
    static let keyAgreementKey = Data(
        repeating: 0x5A, count: MeshMembershipEventFormat.keyAgreementByteCount
    )

    /// The `fernlet.mesh.key-agreement.v1` statement (P6 item 1): `fp001` naming its own durable
    /// key-agreement public key. `advertisedAt` continues the same one-minute story the records
    /// above tell, so every byte in the pinned hex is traceable to a line here.
    static func keyAdvertisement() -> SignedKeyAgreementAdvertisement {
        SignedKeyAgreementAdvertisement(
            meshID: meshID,
            memberFingerprint: "fp001",
            keyAgreementPublicKey: keyAgreementKey,
            advertisedAt: base.addingTimeInterval(480),
            signature: opaqueSignature
        )
    }

    static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Test-only helper

extension MeshInventoryDigestPayload {
    /// The same signed payload with a DIFFERENT digest spliced in — the shape a relay would take
    /// if it tried to rewrite a peer's inventory claim while re-gossiping it.
    static func signedForTestingWithTamperedDigest(
        _ payload: MeshInventoryDigestPayload
    ) -> MeshInventoryDigestPayload {
        MeshInventoryDigestPayload(
            digest: MeshInventoryDigest(
                meshID: payload.digest.meshID,
                admissionCount: payload.digest.admissionCount + 1,
                departureCount: payload.digest.departureCount,
                removalCount: payload.digest.removalCount,
                terminationCount: payload.digest.terminationCount,
                recordsHash: payload.digest.recordsHash
            ),
            senderFingerprint: payload.senderFingerprint,
            sentAt: payload.sentAt,
            signature: payload.signature
        )
    }
}
