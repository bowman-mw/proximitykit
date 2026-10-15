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
// Fernlet repository's FernletTests file of the same name, this holds only
// `MeshInventoryDigestTests`, with its name and tests unchanged, and the fixtures the package's
// copied suites read (`MeshMembershipEventFixtures` and `extension MeshInventoryDigestPayload`);
// and, since ProximityKit plan step A1.3 (batch D: the cells of that repository's tests that read this
// module's sources, copied before it deletes its in-tree copy of the module), the half of
// `MeshLegacyGoodbyeInteropTests.noShippingSourceEmitsAGoodbye` that reads ProximityKit's code, under
// its suite's and its test's names; its other suites, and that cell's other half (Fernlet's own roots),
// stay there, so what this header says of them is not held here.

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

// MARK: - Inventory digest

/// The digest is a pure function of the record SET (plan §10.5): equal ledgers agree no matter how
/// they were assembled, and one differing record is visible.
@Suite(.serialized)
struct MeshInventoryDigestTests {

    private func ledger(_ indices: [Int]) -> MeshMembershipLedger {
        MeshMembershipLedger(
            admissions: MeshMembershipRecordSet(indices.map { MeshMembershipFixtures.admission($0) })
        )
    }

    @Test func equalLedgersProduceEqualDigests() {
        let meshID = MeshMembershipEventFixtures.meshID
        let forward = MeshInventoryDigest(meshID: meshID, ledger: ledger([1, 2, 3]))
        let reversed = MeshInventoryDigest(meshID: meshID, ledger: ledger([3, 2, 1]))
        #expect(forward == reversed)
        #expect(forward.recordsHash == reversed.recordsHash)
        #expect(forward.isWellFormed)
        #expect(forward.recordCount == 3)
    }

    @Test func oneExtraRecordChangesTheDigest() {
        let meshID = MeshMembershipEventFixtures.meshID
        let smaller = MeshInventoryDigest(meshID: meshID, ledger: ledger([1, 2]))
        let larger = MeshInventoryDigest(meshID: meshID, ledger: ledger([1, 2, 3]))
        #expect(smaller != larger)
        #expect(smaller.recordsHash != larger.recordsHash)
    }

    /// The counts alone are not the digest. Two ledgers with the same SHAPE but different records
    /// must differ, or a peer could hide a substitution behind a matching count.
    @Test func sameCountsWithDifferentRecordsDiffer() {
        let meshID = MeshMembershipEventFixtures.meshID
        let first = MeshInventoryDigest(meshID: meshID, ledger: ledger([1, 2]))
        let second = MeshInventoryDigest(meshID: meshID, ledger: ledger([1, 5]))
        #expect(first.admissionCount == second.admissionCount)
        #expect(first.recordsHash != second.recordsHash)
    }

    /// Every kind contributes, and it contributes UNDER ITS KIND: a departure and a removal of the
    /// same member at the same instant are different records, and a digest that conflated them
    /// would report convergence between two ledgers that disagree about why somebody is out.
    @Test func theDigestCoversEveryRecordKind() {
        let meshID = MeshMembershipEventFixtures.meshID
        let base = ledger([1, 2])
        var withDeparture = base
        withDeparture.departures = MeshMembershipRecordSet([MeshMembershipEventFixtures.departure()])
        var withTermination = base
        withTermination.terminations = MeshMembershipRecordSet([MeshMembershipEventFixtures.termination()])
        let digests = [base, withDeparture, withTermination]
            .map { MeshInventoryDigest(meshID: meshID, ledger: $0) }
        #expect(Set(digests.map(\.recordsHash)).count == 3)
        #expect(MeshInventoryDigest(meshID: meshID, ledger: withDeparture).departureCount == 1)
    }

    /// Counts arrive from a peer, so they are clamped on decode exactly as on init — a digest is
    /// bounded input like every other record (plan §9).
    @Test func decodedCountsAreClamped() throws {
        let json = """
        {"meshID":"1F1F1F1F-2E2E-4D4D-8C8C-0B0B0B0B0B0B","admissionCount":9999,\
        "departureCount":-4,"removalCount":0,"terminationCount":77,"recordsHash":""}
        """
        let decoded = try JSONDecoder().decode(MeshInventoryDigest.self, from: Data(json.utf8))
        #expect(decoded.admissionCount == MeshMembershipBounds.maxRecordsPerKind)
        #expect(decoded.departureCount == 0)
        #expect(decoded.terminationCount == MeshMembershipBounds.maxTerminationRecords)
        #expect(!decoded.isWellFormed)   // a zero-length hash is malformed, not a cheap collision
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

// MARK: - Legacy goodbye interop

/// The legacy goodbye: parsed, never emitted, and never a departure (plan §8.2, §8.3). Of the
/// original's four cells this holds the grep-wall's half that reads ProximityKit's code; the three
/// behaviour cells, which read Fernlet's namespace and payload types, stay in Fernlet's copy.
@Suite(.serialized)
struct MeshLegacyGoodbyeInteropTests {

    /// No shipping code path emits it any more. A grep-wall rather than a behavioural test,
    /// because "did not send" is otherwise only visible with two radios in a room.
    ///
    /// **Not vacuous.** The original walks every shipping root of Fernlet's and throws on an empty one;
    /// this half walks every Swift file of the module through ``PackageSwiftFiles/sources()``, at the
    /// walk's floor, and also holds the needle's stem, `sendEnvelope(`, to some line of it, so a sender
    /// renamed out from under the needle reddens rather than leaving it matching nothing, and the token
    /// the wall is about to a case of the module's roles (`case sessionGoodbye`).
    @Test func noShippingSourceEmitsAGoodbye() throws {
        let files = try PackageSwiftFiles.sources()
        #expect(files.count >= PackageSwiftFiles.sourceFloor, """
            the goodbye grep-wall read \(files.count) Swift files under \(PackageSwiftFiles.sourceFolder), \
            below its floor \(PackageSwiftFiles.sourceFloor): the walk is broken, not the module clean
            """)
        var offenders: [String] = []
        var senders = 0
        // R2: bounded by the module's file list × each file's lines.
        for file in files {
            for line in file.text.components(separatedBy: .newlines) where line.contains("sendEnvelope(") {
                senders += 1
                if line.contains("sendEnvelope(.sessionGoodbye") { offenders.append(file.path) }
            }
        }
        #expect(
            offenders.isEmpty,
            """
            \(offenders.count) shipping source file(s) still EMIT `.sessionGoodbye`. It is parsed,
            never emitted (plan §8.3): membership ends via a signed departure or removal record,
            and an unsigned goodbye can only mean the link went away:
            \(offenders.sorted().joined(separator: "\n"))
            """
        )
        #expect(senders >= 1, """
            no line of the module calls `sendEnvelope(`, the stem of the wall's needle: the sender was \
            renamed or moved, and the wall now matches nothing
            """)
        #expect(files.contains { $0.text.contains("case sessionGoodbye") },
                "the goodbye is no longer a case of the module's roles, so the wall speaks of no frame")
    }
}
