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
// `MeshInventoryDigestTests` and, since ProximityKit plan step A1's second batch of copied suites (those
// that reach the keychain and open no store), `MeshMembershipRecordVerifierTests`, with their names
// and tests unchanged, and the fixtures the package's
// copied suites read (`MeshMembershipEventFixtures` and `extension MeshInventoryDigestPayload`);
// and, since ProximityKit plan step A1.3 (batch D: the cells of that repository's tests that read this
// module's sources, copied before it deletes its in-tree copy of the module), the half of
// `MeshLegacyGoodbyeInteropTests.noShippingSourceEmitsAGoodbye` that reads ProximityKit's code, under
// its suite's and its test's names; and, since ProximityKit plan step A1's third batch of copied suites
// (those that reach the keychain and open a store), `MeshMemberRemovalFrameTests`, with its name and
// tests unchanged, over a package host whose install binding its cells switch; its other suites, and
// that cell's other half (Fernlet's own roots), stay there, so what this header says of them is not
// held here.

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

// MARK: - Verify-then-insert

/// The seam item 1 deliberately left open: a record enters a ledger only after its signature
/// verifies against the signer's ADMITTED key.
@MainActor
@Suite(.serialized)
struct MeshMembershipRecordVerifierTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer
    /// has run before a cell's identities reach the keychain.
    let keychain = PackageTestEnvironment.keychain

    private func makeIdentity() throws -> (IdentityService, String) {
        let id = "com.fernlet.mesh-membership.test.\(UUID().uuidString)"
        let service = IdentityService(keychainService: id)
        try service.ensureProvisioned()
        return (service, id)
    }

    /// A verifier holding `founder` plus every identity in `others`, all admitted by the founder.
    private func seeded(
        founder: IdentityService,
        others: [IdentityService],
        meshID: UUID
    ) throws -> MeshMembershipRecordVerifier {
        var verifier = MeshMembershipRecordVerifier(
            meshID: meshID,
            founderSigningPublicKey: founder.localSigningPublicKey
        )
        #expect(verifier.insert(try admission(of: founder, by: founder, meshID: meshID)) == nil)
        for member in others {
            #expect(verifier.insert(try admission(of: member, by: founder, meshID: meshID)) == nil)
        }
        return verifier
    }

    private func admission(
        of joiner: IdentityService,
        by admitter: IdentityService,
        meshID: UUID
    ) throws -> SignedAdmissionRecord {
        SignedAdmissionRecord(token: try MeshAdmissionToken.signed(
            meshID: meshID,
            joinerFingerprint: joiner.localFingerprint,
            joinerSigningPublicKey: joiner.localSigningPublicKey,
            admitterIdentity: admitter,
            grantedAt: MeshMembershipEventFixtures.base
        ))
    }

    @Test func aFoundersOwnAdmissionBootstrapsTheRoster() throws {
        let (founder, id) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: id) }
        let meshID = UUID()
        let verifier = try seeded(founder: founder, others: [], meshID: meshID)
        #expect(verifier.roster.memberFingerprints == [founder.localFingerprint])
    }

    /// Without the founder key there is nothing to root the first admission in, so the ledger stays
    /// empty. Fail closed: an empty roster admits nobody, which is the right answer for a device
    /// that cannot tell who started the mesh.
    @Test func anUnrootedAdmissionIsRefused() throws {
        let (founder, id) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: id) }
        let meshID = UUID()
        var verifier = MeshMembershipRecordVerifier(meshID: meshID, founderSigningPublicKey: nil)
        let rejection = verifier.insert(try admission(of: founder, by: founder, meshID: meshID))
        #expect(rejection == .unauthorizedAdmitter)
        #expect(verifier.ledger.admissions.isEmpty)
    }

    @Test func aSignedDepartureIsAcceptedAndSubtracts() throws {
        let (founder, fid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: fid) }
        let (leaver, lid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: lid) }
        let meshID = UUID()
        var verifier = try seeded(founder: founder, others: [leaver], meshID: meshID)
        #expect(verifier.roster.memberCount == 2)

        let record = try SignedDepartureRecord.signed(
            meshID: meshID, identity: leaver, occurredAt: MeshMembershipEventFixtures.base)
        #expect(verifier.insert(record) == nil)
        #expect(verifier.roster.memberFingerprints == [founder.localFingerprint])
    }

    /// The whole reason this seam exists: junk must be refused BEFORE it competes for one of the
    /// sixteen slots. A forged departure with a very low timestamp would otherwise win the
    /// earliest-wins truncation on every device it reached.
    @Test func aForgedDepartureNeverReachesTheCappedSet() throws {
        let (founder, fid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: fid) }
        let (member, mid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: mid) }
        let (stranger, sid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: sid) }
        let meshID = UUID()
        var verifier = try seeded(founder: founder, others: [member], meshID: meshID)

        // Signed by a stranger, claiming to be the member.
        let honest = try SignedDepartureRecord.signed(
            meshID: meshID, identity: stranger, occurredAt: Date(timeIntervalSince1970: 1))
        let forged = SignedDepartureRecord(
            meshID: meshID,
            memberFingerprint: member.localFingerprint,
            occurredAt: honest.occurredAt,
            signature: honest.signature
        )
        #expect(verifier.insert(forged) == .signatureInvalid)
        #expect(verifier.ledger.departures.isEmpty)
        #expect(verifier.roster.memberCount == 2)

        // And a departure about somebody the mesh never admitted has no key to check at all.
        let outsider = try SignedDepartureRecord.signed(meshID: meshID, identity: stranger)
        #expect(verifier.insert(outsider) == .signerNotAdmitted)
        #expect(verifier.ledger.departures.isEmpty)
    }

    @Test func aRecordFromAnotherMeshIsRefused() throws {
        let (founder, fid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: fid) }
        let (member, mid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: mid) }
        let meshID = UUID()
        var verifier = try seeded(founder: founder, others: [member], meshID: meshID)
        let record = try SignedDepartureRecord.signed(meshID: UUID(), identity: member)
        #expect(verifier.insert(record) == .foreignMesh)
    }

    /// Plan §10.4's arithmetic, re-checked against the RECEIVER's merged roster. Roster 3 needs 2
    /// votes; one vote is short, and the target's own vote never counts.
    @Test func aRemovalNeedsQuorumFromTheReceiversRoster() throws {
        let (founder, fid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: fid) }
        let (second, sid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: sid) }
        let (target, tid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: tid) }
        let meshID = UUID()
        var verifier = try seeded(founder: founder, others: [second, target], meshID: meshID)
        #expect(verifier.roster.quorumThreshold == 2)

        let short = try SignedRemovalRecord.signed(
            meshID: meshID,
            identity: founder,
            memberFingerprint: target.localFingerprint,
            proposalID: MeshMembershipEventFixtures.proposalID,
            voterFingerprints: [founder.localFingerprint]
        )
        #expect(verifier.insert(short) == .quorumNotMet(required: 2, presented: 1))

        let selfVote = try SignedRemovalRecord.signed(
            meshID: meshID,
            identity: founder,
            memberFingerprint: target.localFingerprint,
            proposalID: MeshMembershipEventFixtures.proposalID,
            voterFingerprints: [founder.localFingerprint, target.localFingerprint]
        )
        #expect(verifier.insert(selfVote) == .voterNotEligible)

        let complete = try SignedRemovalRecord.signed(
            meshID: meshID,
            identity: founder,
            memberFingerprint: target.localFingerprint,
            proposalID: MeshMembershipEventFixtures.proposalID,
            voterFingerprints: [founder.localFingerprint, second.localFingerprint]
        )
        #expect(verifier.insert(complete) == nil)
        #expect(!verifier.roster.contains(fingerprint: target.localFingerprint))
    }

    /// A cited voter who is not on the receiver's roster is not evidence. The record is refused
    /// whether the voter is a stranger the mesh never admitted or a member who has since left —
    /// quorum is arithmetic over the roster the RECEIVER derives, at the moment it derives it.
    @Test func aRemovalCitingANonMemberVoterIsRefused() throws {
        let (founder, fid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: fid) }
        let (second, sid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: sid) }
        let (target, tid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: tid) }
        let meshID = UUID()
        var verifier = try seeded(founder: founder, others: [second, target], meshID: meshID)

        let stranger = try SignedRemovalRecord.signed(
            meshID: meshID,
            identity: founder,
            memberFingerprint: target.localFingerprint,
            proposalID: MeshMembershipEventFixtures.proposalID,
            voterFingerprints: [founder.localFingerprint, "fp-never-admitted"]
        )
        #expect(verifier.insert(stranger) == .voterNotEligible)

        // The same is true of a voter who WAS a member: the departure subtracted them, so their
        // vote no longer counts towards a quorum evaluated after it.
        #expect(verifier.insert(try SignedDepartureRecord.signed(meshID: meshID, identity: second)) == nil)
        let departedVoter = try SignedRemovalRecord.signed(
            meshID: meshID,
            identity: founder,
            memberFingerprint: target.localFingerprint,
            proposalID: MeshMembershipEventFixtures.proposalID,
            voterFingerprints: [founder.localFingerprint, second.localFingerprint]
        )
        #expect(verifier.insert(departedVoter) == .voterNotEligible)
        #expect(verifier.ledger.removals.isEmpty)
    }

    /// A re-gossiped removal is the NORMAL case (plan §10.5), so replaying one must be free: the
    /// set dedups by removed member, and the roster it derives does not move a second time. If it
    /// did, every re-gossip on every later connect would spend a rotation.
    @Test func aReplayedRemovalIsDedupedRatherThanCountedTwice() throws {
        let (founder, fid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: fid) }
        let (second, sid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: sid) }
        let (target, tid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: tid) }
        let meshID = UUID()
        var verifier = try seeded(founder: founder, others: [second, target], meshID: meshID)

        let record = try SignedRemovalRecord.signed(
            meshID: meshID,
            identity: founder,
            memberFingerprint: target.localFingerprint,
            proposalID: MeshMembershipEventFixtures.proposalID,
            voterFingerprints: [founder.localFingerprint, second.localFingerprint]
        )
        #expect(verifier.insert(record) == nil)
        let rosterAfterFirst = verifier.roster
        #expect(verifier.insert(record) == nil, "a re-gossiped record is not an error")
        #expect(verifier.ledger.removals.count == 1, "and it does not spend a second of sixteen slots")
        #expect(verifier.roster == rosterAfterFirst, "so the roster does not move twice")
    }

    /// A termination from somebody who is not a member must not be able to end the mesh.
    @Test func aTerminationMustComeFromAMember() throws {
        let (founder, fid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: fid) }
        let (member, mid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: mid) }
        let (stranger, sid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: sid) }
        let meshID = UUID()
        var verifier = try seeded(founder: founder, others: [member], meshID: meshID)

        let outsider = try SignedTerminationRecord.signed(
            meshID: meshID, identity: stranger, rosterAtSigning: [])
        #expect(verifier.insert(outsider) == .signerNotAdmitted)
        #expect(verifier.roster.status == .active)

        let real = try SignedTerminationRecord.signed(
            meshID: meshID,
            identity: member,
            rosterAtSigning: [founder.localFingerprint, member.localFingerprint]
        )
        #expect(verifier.insert(real) == nil)
        #expect(verifier.roster.status == .terminated)
    }

    /// A signed digest verifies, and the same records on both sides compare equal (plan §10.5).
    @Test func anInventoryDigestVerifiesAndCompares() throws {
        let (founder, fid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: fid) }
        let (member, mid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: mid) }
        let meshID = UUID()
        let verifier = try seeded(founder: founder, others: [member], meshID: meshID)

        let payload = try MeshInventoryDigestPayload.signed(
            meshID: meshID,
            ledger: verifier.ledger,
            identity: member,
            sentAt: MeshMembershipEventFixtures.base
        )
        #expect(verifier.verify(payload) == nil)
        #expect(verifier.matchesLocalInventory(payload.digest))

        let stale = MeshInventoryDigestPayload.signedForTestingWithTamperedDigest(payload)
        #expect(verifier.verify(stale) == .signatureInvalid)
    }

    /// A merge imports records ONE AT A TIME through the same door — a peer that forged one record
    /// must not be able to import all of them by handing over a whole ledger.
    @Test func mergingAPeersLedgerVerifiesEveryRecord() throws {
        let (founder, fid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: fid) }
        let (member, mid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: mid) }
        let meshID = UUID()
        var verifier = try seeded(founder: founder, others: [member], meshID: meshID)

        var hostile = MeshMembershipLedger.empty
        hostile.departures = MeshMembershipRecordSet([SignedDepartureRecord(
            meshID: meshID,
            memberFingerprint: founder.localFingerprint,
            occurredAt: Date(timeIntervalSince1970: 1),
            signature: Data(repeating: 0x11, count: 64)
        )])
        let rejections = verifier.merge(hostile)
        #expect(rejections == [.signatureInvalid])
        #expect(verifier.roster.memberCount == 2)
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
    /// walk's floor, and holds the needle's stem, `sendEnvelope(`, to ``goodbyeSenderCallFloor`` calls
    /// on the module's code lines, so a sender renamed out from under the needle reddens rather than
    /// leaving it matching nothing, and the token the wall is about to a case of the module's roles
    /// (`case sessionGoodbye`), read in code.
    ///
    /// **Beyond the original** (ProximityKit plan step A1.3's review). The needle sees a goodbye only
    /// when it is spelled `sendEnvelope(.sessionGoodbye`, never one written through
    /// `writeMembershipFrame(_:_:to:)`, whose role reaches
    /// `sendEnvelopeReportingResult(_:encodable:via:sealed:)` as `meshToken(type)`, nor one held in a
    /// variable; the Fernlet repository's original has the same blind spot. So every code spelling of
    /// `.sessionGoodbye` is also held to its four homes
    /// (``goodbyeRoleCodeLines``): the receive switch's one `case .sessionGoodbye:` in the manager, and
    /// three lines that declare the role and its token rather than send it.
    @Test func noShippingSourceEmitsAGoodbye() throws {
        let files = try PackageSwiftFiles.sources()
        #expect(files.count >= PackageSwiftFiles.sourceFloor, """
            the goodbye grep-wall read \(files.count) Swift files under \(PackageSwiftFiles.sourceFolder), \
            below its floor \(PackageSwiftFiles.sourceFloor): the walk is broken, not the module clean
            """)
        var offenders: [String] = []
        // R2: bounded by the module's file list × each file's lines.
        for file in files {
            for line in file.text.components(separatedBy: .newlines) where line.contains("sendEnvelope(.sessionGoodbye") {
                offenders.append(file.path)
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
        let problems = Self.goodbyeShapeProblems(in: files)
        #expect(problems.isEmpty, "\(problems.joined(separator: "\n"))")
    }

    /// The fewest calls of the module's role sender, `sendEnvelope(`, the goodbye walls hold its code
    /// lines to (whole-line comments dropped, the sender's own declaration not counted): four fifths of
    /// the 11 the module made at ProximityKit plan step A1.3's review, so a sender renamed, or most of
    /// its calls moved behind another door, reddens the walls rather than leaving their needle
    /// matching little or nothing.
    static let goodbyeSenderCallFloor = 9

    /// Every code line of the module that spells `.sessionGoodbye`, by its path under
    /// ``PackageSwiftFiles/sourceFolder`` and its trimmed text, as measured at ProximityKit plan step
    /// A1.3's review: the receive switch's one case in the manager, the role's token row, the interop
    /// rule's role and the vocabulary's initializer. None of them sends; a line that sends the role by
    /// any door or through any variable spells it a fifth time, and fails.
    static let goodbyeRoleCodeLines: [(file: String, line: String)] = [
        (file: "Mesh/MeshMembershipEvents.swift", line: "static let payloadType = MeshPayloadRole.sessionGoodbye"),
        (file: "Mesh/MeshNetworkManager.swift", line: "case .sessionGoodbye:"),
        (file: "Mesh/MeshPayloadRole.swift", line: "case .sessionGoodbye: return mesh.sessionGoodbye"),
        (file: "Namespace/ProximityNamespace+Vocabulary.swift", line: "self.sessionGoodbye = sessionGoodbye")
    ]

    /// What the goodbye walls hold beyond the original's needle, over the module's Swift files, each
    /// read code-only (``MeshRoutedSourceScan/codeOnly(_:)``): the sender's calls at their floor, the
    /// role still a case, and `.sessionGoodbye` spelled only on ``goodbyeRoleCodeLines``. This suite's
    /// cell and `MeshP3InteropAcceptanceTests.theGoodbyeGrepWallStillHolds` both read through it.
    ///
    /// - Parameter files: The module's Swift files, as ``PackageSwiftFiles/sources()`` returns them.
    /// - Returns: One sentence per problem; empty when the walls hold.
    static func goodbyeShapeProblems(in files: [PackageSwiftFiles.File]) -> [String] {
        var senders = 0
        var roleCase = false
        var spelled: [String] = []
        // R2: bounded by the module's file list × each file's lines.
        for file in files {
            for raw in MeshRoutedSourceScan.codeOnly(file.text).components(separatedBy: .newlines) {
                let line = raw.trimmingCharacters(in: .whitespaces)
                if line.contains("sendEnvelope("), !line.contains("func sendEnvelope(") { senders += 1 }
                if line.contains("case sessionGoodbye") { roleCase = true }
                if line.contains(".sessionGoodbye") { spelled.append("\(file.path): \(line)") }
            }
        }
        var problems: [String] = []
        if senders < goodbyeSenderCallFloor {
            problems.append("""
                the module's code calls `sendEnvelope(`, the stem of the goodbye walls' needle, \(senders) \
                times, below the floor of \(goodbyeSenderCallFloor): the sender was renamed or moved, and \
                the needle now matches little or nothing
                """)
        }
        if !roleCase {
            problems.append("the goodbye is no longer a case of the module's roles, so the wall speaks of no frame")
        }
        let homes = goodbyeRoleCodeLines.map { "\($0.file): \($0.line)" }.sorted()
        if spelled.sorted() != homes {
            problems.append("""
                the module's code spells `.sessionGoodbye` on \(spelled.sorted()), not only on its homes \
                \(homes): a goodbye written through another door or held in a variable is still EMITTED, \
                and a home that moved is re-pointed here with its reason
                """)
        }
        return problems
    }
}

// MARK: - The removal frame on the manager

/// P3 item 3b (plan §8.3, §10.4): `fernlet.mesh.member-removal.v1` end to end.
///
/// Item 5 mints a removal record where the vote completes and files it locally; item 3 framed the
/// other three record kinds. This suite walls the fourth frame's two directions and the one edge
/// item 6 could not wire:
///
/// 1. **The removed member is not sent the record.** Exclusion is computed by item 5's own
///    key-distribution rule, so "who gets the new key" and "who is told why" cannot drift apart.
/// 2. **A received record is verified, made durable, and only then counted** — and if it names this
///    device, it ends this device's session (plan §8.2's `removed` edge).
/// 3. **The legacy `.meshRemovalSecond` path still agrees.** It is the interim exclusion authority
///    until item 7, so the two must never disagree about who is out.
@MainActor
@Suite(.serialized)
struct MeshMemberRemovalFrameTests {

    let store = PackageTestHost(installBinding: PackageSwitchableInstallBinding())

    /// A pinned install identity, so every seal in this suite is deterministic.
    private static let install = Data(repeating: 0x3B, count: 16)

    // MARK: Fixtures

    private func makeIdentity() throws -> (IdentityService, String) {
        let id = "com.fernlet.mesh-removal-frame.test.\(UUID().uuidString)"
        let service = IdentityService(keychainService: id)
        try service.ensureProvisioned()
        return (service, id)
    }

    private func makeMesh(_ manager: MeshNetworkManager) -> MeshDescriptor {
        let now = Date()
        let local = MeshMember(
            fingerprint: manager.identityForTesting.localFingerprint,
            displayName: "Local",
            signingPublicKey: manager.identityForTesting.localSigningPublicKey,
            keyAgreementPublicKey: manager.identityForTesting.localKeyAgreementPublicKey,
            joinedAt: now
        )
        return MeshDescriptor(
            meshID: UUID(),
            name: "Removal Meadow",
            mode: .open,
            members: [local],
            nameSetAt: now,
            nameSetBy: local.fingerprint,
            modeSetAt: now,
            modeSetBy: local.fingerprint,
            createdAt: now
        )
    }

    /// A ledger admitting `founder` (by itself) and every identity in `others` (by the founder) —
    /// the roster a removal's quorum is re-derived against.
    private func ledger(
        founder: IdentityService,
        others: [IdentityService],
        meshID: UUID
    ) throws -> MeshMembershipLedger {
        var built = MeshMembershipLedger.empty
        for member in [founder] + others {
            built.admissions = built.admissions.inserting(
                SignedAdmissionRecord(token: try MeshAdmissionToken.signed(
                    meshID: meshID,
                    joinerFingerprint: member.localFingerprint,
                    joinerSigningPublicKey: member.localSigningPublicKey,
                    admitterIdentity: founder
                ))
            )
        }
        return built
    }

    /// A coordinator with no live dependencies, for slots this suite only needs to exist.
    private static func throwawayCoordinator() -> ProximityCoordinator {
        ProximityCoordinator(
            identity: IdentityService(keychainService: "test.mesh.removal-frame.\(UUID().uuidString)"),
            transport: MockMultipeerTransport(),
            ranging: MockRangingProvider(),
            inspector: nil,
            replayCache: ReplayCache(),
            foregroundAnchor: nil,
            displayName: "Local",
            timeoutSeconds: 0
        )
    }

    /// Attaches a COMMITTED slot for `fingerprint` and returns the coordinator that owns it, which
    /// is how the real dispatch entry point finds the slot a frame arrived on.
    @discardableResult
    private func attachSlot(to manager: MeshNetworkManager, fingerprint: String) -> ProximityCoordinator {
        let coordinator = Self.throwawayCoordinator()
        manager.addSlotForTesting(
            coordinator: coordinator,
            peer: PeerHandle(
                id: UUID(),
                displayHint: "iPhone",
                discoveryInfo: ["v": "1"],
                advertisedFingerprint: fingerprint,
                endpoint: PeerEndpointKey()
            ),
            fingerprint: fingerprint
        )
        return coordinator
    }

    /// Delivers a removal frame through the REAL receive entry point, under a pinned install so the
    /// seal the receive path owes can actually be written.
    ///
    /// - Parameter binding: The device-binding behaviour to deliver under; nil is the pinned,
    ///   sealable install. (A default argument cannot name ``install`` — a `@MainActor` type's
    ///   static member is not available as a default-argument value.)
    private func deliver(
        _ record: SignedRemovalRecord,
        to manager: MeshNetworkManager,
        from sender: IdentityService,
        over coordinator: ProximityCoordinator,
        binding: PackageSwitchableInstallBinding.TestOverride? = nil
    ) throws {
        let plaintext = try JSONEncoder().encode(MeshMemberRemovalPayload(record: record))
        let envelope = try ProximityIdentityEnvelope.signed(
            identityService: sender,
            senderDisplayName: "Peer",
            payloadType: .meshMemberRemoval,
            payloadSummary: PayloadSummary(title: "Removal"),
            payload: plaintext
        )
        PackageSwitchableInstallBinding.testOverride.withValue(binding ?? .identifier(Self.install)) {
            manager.proximityCoordinator(
                coordinator, didReceive: envelope, plaintext: plaintext, from: nil
            )
        }
    }

    /// Reads the sealed context back, under the same pinned install everything here writes with.
    private func loadContext() -> MeshSessionContext? {
        let sessionStore = MeshSessionStore(scope: store.meshSessionStorage)
        let load = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Self.install)) {
            sessionStore.load()
        }
        guard case .loaded(let context, _) = load else { return nil }
        return context
    }

    // MARK: Bounds (plan §9)

    /// A frame carrying more voters than the mesh can hold is CLAMPED on decode, not trimmed after
    /// it is trusted and never a trap — and because the clamp changes the bytes the tallier signed,
    /// the padded record is then refused outright rather than crediting an inflated quorum.
    @Test func aPaddedVoterListIsClampedOnDecodeAndThenRefused() throws {
        let (founder, fid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: fid) }
        let (second, sid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: sid) }
        let (target, tid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: tid) }
        let meshID = UUID()

        let honest = try SignedRemovalRecord.signed(
            meshID: meshID,
            identity: founder,
            memberFingerprint: target.localFingerprint,
            proposalID: MeshMembershipEventFixtures.proposalID,
            voterFingerprints: [founder.localFingerprint, second.localFingerprint]
        )
        let padded = SignedRemovalRecord(
            meshID: meshID,
            memberFingerprint: honest.memberFingerprint,
            proposalID: honest.proposalID,
            voterFingerprints: (0..<99).map { "fp-pad-\($0)" },
            occurredAt: honest.occurredAt,
            authorFingerprint: honest.authorFingerprint,
            signature: honest.signature
        )
        // The initializer already clamped; the DECODE of a hostile frame must clamp too, which a
        // synthesized `Codable` would not have done.
        let wire = try JSONEncoder().encode(MeshMemberRemovalPayload(record: padded))
        let decoded = try JSONDecoder().decode(MeshMemberRemovalPayload.self, from: wire)
        #expect(decoded.record.voterFingerprints.count == MeshMembershipBounds.maxVoters)

        var verifier = MeshMembershipRecordVerifier(
            meshID: meshID, founderSigningPublicKey: founder.localSigningPublicKey,
            ledger: try ledger(founder: founder, others: [second, target], meshID: meshID)
        )
        #expect(verifier.insert(decoded.record) == .voterNotEligible)
        #expect(verifier.ledger.removals.isEmpty)
    }

    // MARK: Emission

    /// The removed member is not sent the record that removes them (plan §8.3): they learn of it as
    /// a key that no longer opens anything. Every other committed member is.
    @Test func theRemovalFrameExcludesTheRemovedMember() {
        let manager = MeshNetworkManager(store: store)
        manager.currentMesh = makeMesh(manager)
        attachSlot(to: manager, fingerprint: "fp-target")
        attachSlot(to: manager, fingerprint: "fp-witness")

        let recipients = manager.membershipEventRecipients(excluding: "fp-target")

        #expect(!recipients.contains("fp-target"), "the removed member must not receive the record")
        #expect(recipients.contains("fp-witness"), "every other member must")
        #expect(recipients.contains(manager.identityForTesting.localFingerprint),
                "and this device is always in the set the key distribution uses")
        manager.leaveMesh()
    }

    /// The vote completing puts the signed record on the wire — the gap item 5 named and left open,
    /// where peers learned of a removal only from the legacy broadcast and the descriptor.
    @Test func aCompletedVoteBroadcastsTheSignedRecord() async {
        let manager = MeshNetworkManager(store: store)
        manager.currentMesh = makeMesh(manager)
        attachSlot(to: manager, fingerprint: "fp-witness")
        var emitted: [MeshPayloadRole] = []
        manager.onMembershipEventSentForTesting = { emitted.append($0) }

        PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Self.install)) {
            manager.secondRemoval(MeshRemovalProposalPayload(
                id: UUID(),
                targetFingerprint: "fp-target",
                targetDisplayName: "Target",
                proposerFingerprint: "fp-proposer",
                proposerDisplayName: "Proposer",
                createdAt: Date(),
                expiresAt: Date().addingTimeInterval(60)
            ))
        }
        // The emit is fire-and-forget on a task, so let the main actor drain it. Bounded, and it
        // completes in a hop or two — the yields are a settle, never a timeout.
        var yields = 0
        while emitted.isEmpty, yields < 100 {
            await Task.yield()
            yields += 1
        }

        #expect(emitted == [.meshMemberRemoval],
                "a completed removal now ships its record, not only the legacy second")
        manager.leaveMesh()
    }

    /// Both removal paths agree on who is out. The legacy `.meshRemovalSecond` vote is the interim
    /// exclusion authority until item 7 and the signed record is the durable one; a mesh in which
    /// they disagreed would exclude a member from the key and keep them on the roster, or worse.
    @Test func theLegacyPathAndTheRecordAgreeOnExclusion() {
        let manager = MeshNetworkManager(store: store)
        manager.currentMesh = makeMesh(manager)
        attachSlot(to: manager, fingerprint: "fp-target")

        PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Self.install)) {
            manager.secondRemoval(MeshRemovalProposalPayload(
                id: UUID(),
                targetFingerprint: "fp-target",
                targetDisplayName: "Target",
                proposerFingerprint: "fp-proposer",
                proposerDisplayName: "Proposer",
                createdAt: Date(),
                expiresAt: Date().addingTimeInterval(60)
            ))
        }

        #expect(manager.removedMemberFingerprints.contains("fp-target"),
                "the legacy path still records the exclusion")
        #expect(!manager.membershipEventRecipients(excluding: "fp-other").contains("fp-target"),
                "and the record path excludes exactly the same member")
        #expect(manager.rotationTriggers.pendingCause == .membership,
                "a completed removal still rotates the key at once")
        manager.leaveMesh()
    }

    // MARK: Reception

    /// A verified removal from a peer inserts, reaches the disk, moves the roster and rotates —
    /// the whole receive contract for a member who is not the one being removed.
    @Test func aReceivedRemovalInsertsPersistsAndRotates() throws {
        let manager = MeshNetworkManager(store: store)
        let mesh = makeMesh(manager)
        manager.currentMesh = mesh
        let (founder, fid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: fid) }
        let (target, tid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: tid) }
        manager.seedMembershipLedgerForTesting(
            meshID: mesh.meshID,
            founderSigningPublicKey: founder.localSigningPublicKey,
            ledger: try ledger(
                founder: founder, others: [manager.identityForTesting, target], meshID: mesh.meshID
            )
        )
        #expect(manager.membershipVerifier?.roster.memberCount == 3)
        let coordinator = attachSlot(to: manager, fingerprint: founder.localFingerprint)

        let record = try SignedRemovalRecord.signed(
            meshID: mesh.meshID,
            identity: founder,
            memberFingerprint: target.localFingerprint,
            proposalID: MeshMembershipEventFixtures.proposalID,
            voterFingerprints: [founder.localFingerprint, manager.identityForTesting.localFingerprint]
        )
        try deliver(record, to: manager, from: founder, over: coordinator)

        #expect(manager.membershipVerifier?.ledger.removals.count == 1)
        #expect(manager.membershipVerifier?.roster.contains(fingerprint: target.localFingerprint) == false)
        #expect(loadContext()?.ledger.removals.count == 1, "the record is on the disk, not only in RAM")
        #expect(manager.rotationTriggers.pendingCause == .membership,
                "a roster move rotates as `membership` (plan §8.3)")
        #expect(manager.sessionState != .departed, "somebody else's removal is not this device's")
        manager.leaveMesh()
    }

    /// Durable before acknowledged (plan §3.6): a seal the store refuses rolls the record back out
    /// of the ledger, and the rotation it would have caused never fires.
    @Test func aRemovalTheStoreCannotSealIsNotAcknowledged() throws {
        let manager = MeshNetworkManager(store: store)
        let mesh = makeMesh(manager)
        manager.currentMesh = mesh
        let (founder, fid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: fid) }
        let (target, tid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: tid) }
        manager.seedMembershipLedgerForTesting(
            meshID: mesh.meshID,
            founderSigningPublicKey: founder.localSigningPublicKey,
            ledger: try ledger(
                founder: founder, others: [manager.identityForTesting, target], meshID: mesh.meshID
            )
        )
        let coordinator = attachSlot(to: manager, fingerprint: founder.localFingerprint)

        let record = try SignedRemovalRecord.signed(
            meshID: mesh.meshID,
            identity: founder,
            memberFingerprint: target.localFingerprint,
            proposalID: MeshMembershipEventFixtures.proposalID,
            voterFingerprints: [founder.localFingerprint, manager.identityForTesting.localFingerprint]
        )
        try deliver(record, to: manager, from: founder, over: coordinator, binding: .unavailable)

        #expect(manager.membershipVerifier?.ledger.removals.isEmpty == true,
                "a record that could not be written down is not inserted for roster purposes")
        #expect(manager.membershipVerifier?.roster.contains(fingerprint: target.localFingerprint) == true)
        #expect(manager.rotationTriggers.pendingCause == nil,
                "and the rotation it would have caused must not fire")
        manager.leaveMesh()
    }

    /// The edge item 6 built and could not wire: a verified record naming THIS device ends its
    /// membership. State `departed`, the durable mark written, the rejoin bar up, participation
    /// stopped — and the mesh carries on without it, which is why it is not `terminated`.
    @Test func aReceivedRemovalNamingThisDeviceEndsItsSession() throws {
        let manager = MeshNetworkManager(store: store)
        let mesh = makeMesh(manager)
        manager.currentMesh = mesh
        let (founder, fid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: fid) }
        let (second, sid) = try makeIdentity()
        defer { ProximityKeychainItem.deleteAll(service: sid) }
        manager.seedMembershipLedgerForTesting(
            meshID: mesh.meshID,
            founderSigningPublicKey: founder.localSigningPublicKey,
            ledger: try ledger(
                founder: founder, others: [second, manager.identityForTesting], meshID: mesh.meshID
            )
        )
        let coordinator = attachSlot(to: manager, fingerprint: founder.localFingerprint)
        PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Self.install)) {
            manager.applySessionEvent(.founded)
            manager.applySessionEvent(.peerCommitted)
        }

        let record = try SignedRemovalRecord.signed(
            meshID: mesh.meshID,
            identity: founder,
            memberFingerprint: manager.identityForTesting.localFingerprint,
            proposalID: MeshMembershipEventFixtures.proposalID,
            voterFingerprints: [founder.localFingerprint, second.localFingerprint]
        )
        try deliver(record, to: manager, from: founder, over: coordinator)

        #expect(manager.sessionState == .departed,
                "a verified removal of this device is terminal for this device only")
        #expect(manager.rejoinBar?.reason == .removedFromRoster, "and the rejoin bar names why")
        #expect(loadContext()?.localTermination?.reason == .removedFromRoster,
                "the ending mark is on the disk before the teardown")
        #expect(manager.currentMesh == nil, "participation is torn down, as the legacy path does")
        #expect(manager.slots.isEmpty, "and the links with it")
    }
}
