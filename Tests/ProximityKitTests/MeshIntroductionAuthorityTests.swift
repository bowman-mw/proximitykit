// MeshIntroductionAuthorityTests.swift
// ProximityKitTests
//
// P3 item 7 (plan §8.1, §8.3, §10.5, §20.4.4): the introduction authority answers from the DERIVED
// roster, and a joiner holds a ledger to derive it from.
//
// Four claims are walled here, each one a thing the items before this could not reach:
//
// 1. **A joiner adopts a ledger.** Item 3 recorded the gap verbatim — "joiners never adopt a
//    ledger, so every received event on a joiner is refused `signerNotAdmitted`". Bootstrap from
//    the admission this device verified, then rebase onto the mesh's real founder once the offered
//    ledger's chain to this device's admitter is proven.
// 2. **`barred` has real contents.** Plan §20.1's gap: the live manager kept removals by
//    fingerprint and held no signing key for a member it had dropped, so a removed peer refused as
//    an anonymous `unknownIdentity` and matrix row 3 was produced by a chaos hook. The admission
//    record carries the key, so the shipping authority now answers `.barredMember` itself.
// 3. **The legacy fallback is reachable only with an empty ledger, and says so.** A roster derived
//    from gossip rather than from signed records is a fact the log has to carry.
// 4. **Three nodes converge on one roster.** A(founder) → B → C, with C never having met A: all
//    three derive the same members, and the rotation's key distribution includes C. Without the
//    admission on the wire an unpropagated joiner is silently excluded from the group key.
//
// A partial copy (ProximityKit plan step A1, the split's second batch of copied suites: those that reach
// the keychain and open no store): of the Fernlet repository's FernletTests file of the same name, this
// holds only `MeshLedgerAdoptionTests`, with its name and tests unchanged, and the fixture it reads
// (`MeshLedgerChainFixture`); its other suites stay there, so what this header says of them is not held
// here. The fixture's initializer gains one first statement that reads `PackageTestEnvironment.keychain`
// (the package's hygiene rule I9).

import Foundation
import Testing
@testable import ProximityKit

// MARK: - Shared fixtures

/// The three-identity mesh every suite in this file builds: a founder, the member it admitted, and
/// the joiner that member admitted in turn.
///
/// Held as a type rather than as loose helpers because the *chain* is the fixture — C's admission
/// is signed by B, and B's by A — and a test that rebuilt it inline would keep re-deriving the one
/// property adoption turns on.
@MainActor
struct MeshLedgerChainFixture {

    /// The mesh every record names.
    let meshID = UUID()
    /// The founder, who self-admits.
    let founder: IdentityService
    /// The member the founder admitted, and the one that admits the joiner.
    let admitter: IdentityService
    /// The joiner, which has never met the founder.
    let joiner: IdentityService

    /// Keychain services to delete on teardown.
    let services: [String]

    /// Builds three provisioned identities in isolated keychain services.
    init() throws {
        _ = PackageTestEnvironment.keychain
        var built: [(IdentityService, String)] = []
        for index in 0..<3 {
            let name = "com.fernlet.mesh-authority.test.\(index).\(UUID().uuidString)"
            let service = IdentityService(keychainService: name)
            try service.ensureProvisioned()
            built.append((service, name))
        }
        founder = built[0].0
        admitter = built[1].0
        joiner = built[2].0
        services = built.map(\.1)
    }

    /// Deletes every keychain item the fixture provisioned.
    func tearDown() {
        for service in services { ProximityKeychainItem.deleteAll(service: service) }
    }

    /// One admission record: `admitter` signing `member` in.
    func admission(
        of member: IdentityService,
        by admittingIdentity: IdentityService
    ) throws -> SignedAdmissionRecord {
        SignedAdmissionRecord(token: try MeshAdmissionToken.signed(
            meshID: meshID,
            joinerFingerprint: member.localFingerprint,
            joinerSigningPublicKey: member.localSigningPublicKey,
            admitterIdentity: admittingIdentity
        ))
    }

    /// The founder's own self-admission — the root of every chain.
    func founderAdmission() throws -> SignedAdmissionRecord {
        try admission(of: founder, by: founder)
    }

    /// The full three-member ledger the admitter holds: A self-admitted, B by A, C by B.
    func fullLedger() throws -> MeshMembershipLedger {
        var ledger = MeshMembershipLedger.empty
        ledger.admissions = ledger.admissions
            .inserting(try founderAdmission())
            .inserting(try admission(of: admitter, by: founder))
            .inserting(try admission(of: joiner, by: admitter))
        return ledger
    }

    /// The grant payload the joiner verified: the token that admitted it, wrapped for the manager
    /// path that arms the ledger.
    func joinerGrant() throws -> MeshAdmissionGrantPayload {
        MeshAdmissionGrantPayload(
            meshID: meshID,
            requesterFingerprint: joiner.localFingerprint,
            token: try admission(of: joiner, by: admitter).token
        )
    }
}

// MARK: - Adoption, pure (plan §8.3, §20.4.4)

/// P3 item 7: how a joiner comes to hold a ledger, with no store and no transport in sight.
@MainActor
@Suite struct MeshLedgerAdoptionTests {

    /// A joiner arms itself from the one thing it authenticated: the admission its transport-
    /// verified peer signed. The root is provisional — the admitter's key, not the founder's — and
    /// the roster it derives is exactly one member, this device.
    @Test func aJoinerBootstrapsFromTheAdmissionItVerified() throws {
        let fixture = try MeshLedgerChainFixture()
        defer { fixture.tearDown() }
        let own = try fixture.admission(of: fixture.joiner, by: fixture.admitter)

        guard case .adopted(let verifier) = MeshLedgerAdoption.bootstrapVerifier(
            meshID: fixture.meshID, ownAdmission: own
        ) else {
            Issue.record("a verified admission must arm a ledger")
            return
        }

        #expect(verifier.roster.memberFingerprints == [fixture.joiner.localFingerprint])
        #expect(verifier.founderSigningPublicKey == fixture.admitter.localSigningPublicKey)
        #expect(MeshLedgerAdoption.isBootstrap(
            verifier.ledger, selfFingerprint: fixture.joiner.localFingerprint
        ))
    }

    /// A founder's ledger is also one admission long, and must never be rebased: the difference is
    /// in the record, not in a flag — its author is the founder itself.
    @Test func aFounderLedgerIsNotABootstrapToRebase() throws {
        let fixture = try MeshLedgerChainFixture()
        defer { fixture.tearDown() }
        var founderLedger = MeshMembershipLedger.empty
        founderLedger.admissions = founderLedger.admissions.inserting(try fixture.founderAdmission())

        #expect(!MeshLedgerAdoption.isBootstrap(
            founderLedger, selfFingerprint: fixture.founder.localFingerprint
        ))
    }

    /// The rebase: a peer's ledger is re-verified from its OWN root, and that root is accepted as
    /// the founder because the resulting roster admits this device's admitter under exactly the key
    /// its token names. Merging record-by-record could never have got here — the founder's
    /// self-admission is `unauthorizedAdmitter` to a ledger rooted at the admitter.
    @Test func adoptingAPeerLedgerRebasesOntoTheRealFounder() throws {
        let fixture = try MeshLedgerChainFixture()
        defer { fixture.tearDown() }
        let own = try fixture.admission(of: fixture.joiner, by: fixture.admitter)

        guard case .adopted(let adopted) = MeshLedgerAdoption.adopt(
            offered: try fixture.fullLedger(), ownAdmission: own, meshID: fixture.meshID
        ) else {
            Issue.record("a chained ledger must be adopted")
            return
        }

        #expect(adopted.founderSigningPublicKey == fixture.founder.localSigningPublicKey)
        #expect(adopted.roster.memberFingerprints == [
            fixture.founder.localFingerprint,
            fixture.admitter.localFingerprint,
            fixture.joiner.localFingerprint
        ].sorted())
    }

    /// The chain check is the whole of the rebase's safety: a ledger that does not admit the peer
    /// that admitted this device proves nothing about this mesh's history, however well-formed.
    @Test func aLedgerThatDoesNotAdmitMyAdmitterIsRefused() throws {
        let fixture = try MeshLedgerChainFixture()
        defer { fixture.tearDown() }
        // The founder's own ledger, before it ever admitted the admitter.
        var lonely = MeshMembershipLedger.empty
        lonely.admissions = lonely.admissions.inserting(try fixture.founderAdmission())
        let own = try fixture.admission(of: fixture.joiner, by: fixture.admitter)

        let outcome = MeshLedgerAdoption.adopt(
            offered: lonely, ownAdmission: own, meshID: fixture.meshID
        )

        guard case .refused(let refusal) = outcome else {
            Issue.record("an unchained ledger must be refused")
            return
        }
        #expect(refusal == .admitterNotChained)
    }

    /// A root that is not self-admitted is nobody's founder: every other record needs an
    /// already-admitted admitter, so a ledger rooted in one would derive an empty roster anyway —
    /// and refusing it by name is what stops a forged "root" being adopted silently.
    @Test func aLedgerWhoseRootIsNotSelfAdmittedIsRefused() throws {
        let fixture = try MeshLedgerChainFixture()
        defer { fixture.tearDown() }
        var rootless = MeshMembershipLedger.empty
        rootless.admissions = rootless.admissions
            .inserting(try fixture.admission(of: fixture.admitter, by: fixture.founder))
        let own = try fixture.admission(of: fixture.joiner, by: fixture.admitter)

        let outcome = MeshLedgerAdoption.adopt(
            offered: rootless, ownAdmission: own, meshID: fixture.meshID
        )

        guard case .refused(let refusal) = outcome else {
            Issue.record("a ledger with no self-admitted root must be refused")
            return
        }
        #expect(refusal == .rootNotSelfAdmitted)
    }

    /// A ledger for another mesh is a refusal, not a difference — records never cross meshes.
    @Test func aForeignLedgerIsRefused() throws {
        let fixture = try MeshLedgerChainFixture()
        defer { fixture.tearDown() }
        let own = try fixture.admission(of: fixture.joiner, by: fixture.admitter)

        let outcome = MeshLedgerAdoption.adopt(
            offered: try fixture.fullLedger(), ownAdmission: own, meshID: UUID()
        )

        guard case .refused(let refusal) = outcome else {
            Issue.record("a foreign ledger must be refused")
            return
        }
        #expect(refusal == .foreignMesh)
    }

    /// Plan §10.5's convergence, and the reason the admission needed a frame at all: all three
    /// devices derive the SAME roster, and the joiner is in the set the next rotation wraps the
    /// group key for. An admission that stopped at its admitter would leave C on nobody else's
    /// roster and therefore out of the key distribution — silently.
    @Test func threeNodesConvergeAndTheJoinerIsInTheKeyDistribution() throws {
        let fixture = try MeshLedgerChainFixture()
        defer { fixture.tearDown() }
        let full = try fixture.fullLedger()
        let own = try fixture.admission(of: fixture.joiner, by: fixture.admitter)

        var founderView = MeshMembershipRecordVerifier(
            meshID: fixture.meshID, founderSigningPublicKey: fixture.founder.localSigningPublicKey
        )
        founderView.merge(full)
        var admitterView = MeshMembershipRecordVerifier(
            meshID: fixture.meshID, founderSigningPublicKey: fixture.founder.localSigningPublicKey
        )
        admitterView.merge(full)
        guard case .adopted(let joinerView) = MeshLedgerAdoption.adopt(
            offered: full, ownAdmission: own, meshID: fixture.meshID
        ) else {
            Issue.record("the joiner must adopt")
            return
        }

        let expected = [
            fixture.founder.localFingerprint,
            fixture.admitter.localFingerprint,
            fixture.joiner.localFingerprint
        ].sorted()
        #expect(founderView.roster.memberFingerprints == expected)
        #expect(admitterView.roster.memberFingerprints == expected)
        #expect(joinerView.roster.memberFingerprints == expected)
        let recipients = MeshRotationPolicy.recipients(
            acked: Set(expected),
            selfFingerprint: fixture.founder.localFingerprint,
            derivedRoster: founderView.roster,
            locallyRemoved: []
        )
        #expect(recipients.contains(fixture.joiner.localFingerprint),
                "a member the founder learned of by record must receive the next epoch's key")
    }
}
