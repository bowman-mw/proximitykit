import Foundation
import Testing
@testable import ProximityKit

// MARK: - MeshMembershipRecordsTests

// P3 item 1: the pure membership model — signed records, their union-merge, and the derived roster
// `admitted − departed − removed` (plan §8.1, bounds §9).
//
// Everything in this file is a value computation: no store, no transport, no clock, no signature
// verification. That is the point. The three claims worth a wall here are the three that later
// items build on and cannot re-check cheaply:
//
// 1. **The roster is subtraction, and subtraction is permanent.** A departed member is out for the
//    life of the mesh; a later admission record for the same fingerprint does not bring them back.
// 2. **The merge is a semilattice** — commutative, associative, idempotent — *including its caps*,
//    which is the half that is easy to break: a cap applied per-merge instead of over the union
//    would make convergence depend on who connected first, and that failure only shows up as two
//    devices quietly disagreeing about who is in the room.
// 3. **Every bound in §9 is enforced without a trap.** Records past the cap are dropped by a rule
//    that is the same on every device (earliest wins), never by a crash and never by luck.

// MARK: - Roster algebra

/// `admitted − departed − removed`, the termination rule, and the arithmetic every later phase
/// reads off the roster.
@MainActor
@Suite(.serialized)
struct MeshDerivedRosterTests {

    typealias Fixture = MeshMembershipFixtures

    /// The headline subtraction: three admitted, one departs, one is removed, one remains.
    @Test func rosterIsAdmittedMinusDepartedMinusRemoved() {
        var ledger = Fixture.ledger(admitting: [1, 2, 3])
        #expect(ledger.derivedRoster.memberFingerprints == [
            Fixture.fingerprint(1), Fixture.fingerprint(2), Fixture.fingerprint(3)
        ])

        ledger.departures = ledger.departures.inserting(Fixture.departure(2))
        ledger.removals = ledger.removals.inserting(Fixture.removal(3))

        let roster = ledger.derivedRoster
        #expect(roster.memberFingerprints == [Fixture.fingerprint(1)])
        #expect(roster.barred.map(\.fingerprint) == [Fixture.fingerprint(2), Fixture.fingerprint(3)])
        #expect(roster.status == .active)
        #expect(roster.contains(fingerprint: Fixture.fingerprint(1)))
        #expect(!roster.contains(fingerprint: Fixture.fingerprint(2)))
    }

    /// Departure is permanent: a second admission record for a departed fingerprint changes nothing,
    /// because the records are grow-only and subtraction runs after the union. Rejoining is a new
    /// mesh, not a re-admission (plan §8.1/§8.2).
    @Test func aDepartedMemberCannotBeReAdmitted() {
        var ledger = Fixture.ledger(admitting: [1, 2])
        ledger.departures = ledger.departures.inserting(Fixture.departure(2, secondsIn: 100))
        #expect(ledger.derivedRoster.memberFingerprints == [Fixture.fingerprint(1)])

        ledger.admissions = ledger.admissions.inserting(Fixture.admission(2, secondsIn: 500))
        #expect(ledger.derivedRoster.memberFingerprints == [Fixture.fingerprint(1)])
        #expect(ledger.derivedRoster.barred.map(\.fingerprint) == [Fixture.fingerprint(2)])
    }

    /// A removal gives the transport a barred **key**, not just a fingerprint — the gap plan §20.1
    /// records, where the live manager had to leave `barred` empty.
    @Test func removalFillsTheTransportsBarredListWithKeys() {
        var ledger = Fixture.ledger(admitting: [1, 2])
        ledger.removals = ledger.removals.inserting(Fixture.removal(2))

        let introduction = ledger.derivedRoster.introductionRoster()
        #expect(introduction.verdict(for: Fixture.signingKey(1)) == .member)
        #expect(introduction.verdict(for: Fixture.signingKey(2)) == .barred)
        #expect(introduction.verdict(for: Fixture.signingKey(9)) == .stranger)
        #expect(introduction.memberCount == 1)
        #expect(introduction.barredCount == 1)
    }

    /// An empty ledger derives an empty roster: every introduction is a stranger, which is the
    /// fail-closed answer for a device that has joined nothing.
    @Test func anEmptyLedgerAdmitsNobody() {
        let roster = MeshDerivedRoster.empty
        #expect(roster.members.isEmpty)
        #expect(roster.status == .active)
        #expect(roster.coordinatorFingerprint == nil)
        #expect(!roster.isFinalPair)
        #expect(roster.introductionRoster().verdict(for: Fixture.signingKey(1)) == .stranger)
    }

    /// A termination signed by a final-pair member ends the mesh for everyone.
    @Test func terminationFromAFinalPairEndsTheMesh() {
        var ledger = Fixture.ledger(admitting: [1, 2])
        #expect(ledger.derivedRoster.isFinalPair)

        ledger.terminations = ledger.terminations.inserting(Fixture.termination(1, roster: [1, 2]))
        let roster = ledger.derivedRoster
        #expect(roster.status == .terminated)
        #expect(roster.members.isEmpty)
        #expect(roster.barred.count == 2)
        #expect(!roster.isFinalPair)
    }

    /// The same record read against a larger merged roster downgrades to the signer's departure
    /// (plan §8.3): a partitioned member who thought they were a pair only removes themself.
    @Test func terminationDowngradesToADepartureOnALargerRoster() {
        var ledger = Fixture.ledger(admitting: [1, 2, 3])
        ledger.terminations = ledger.terminations.inserting(Fixture.termination(1, roster: [1, 2]))

        let roster = ledger.derivedRoster
        #expect(roster.status == .active)
        #expect(roster.memberFingerprints == [Fixture.fingerprint(2), Fixture.fingerprint(3)])
        #expect(roster.barred.map(\.fingerprint) == [Fixture.fingerprint(1)])
    }

    /// A termination signed by somebody who is not a member is ignored outright — a departed member
    /// or a stranger must not be able to end a mesh they are not in.
    @Test func terminationFromANonMemberIsIgnored() {
        var ledger = Fixture.ledger(admitting: [1, 2])
        ledger.terminations = ledger.terminations.inserting(Fixture.termination(7))
        #expect(ledger.derivedRoster.status == .active)
        #expect(ledger.derivedRoster.memberCount == 2)

        ledger.departures = ledger.departures.inserting(Fixture.departure(2))
        ledger.terminations = MeshMembershipRecordSet([Fixture.termination(2)])
        #expect(ledger.derivedRoster.status == .active)
        #expect(ledger.derivedRoster.memberFingerprints == [Fixture.fingerprint(1)])
    }

    /// Quorum is ⌊|roster|/2⌋ + 1 for every roster size the mesh can reach (plan §10.4), and never
    /// zero — a caller must not be able to read "no votes needed" off an empty roster.
    @Test func quorumThresholdMatchesThePlansTable() {
        let expected = [1: 1, 2: 2, 3: 2, 4: 3, 5: 3, 6: 4, 7: 4, 8: 5]
        for size in 1...MeshMembershipBounds.maxRosterMembers {
            let roster = Fixture.ledger(admitting: Array(1...size)).derivedRoster
            #expect(roster.memberCount == size)
            #expect(roster.quorumThreshold == expected[size], "roster of \(size)")
        }
        #expect(MeshDerivedRoster.empty.quorumThreshold == 1)
    }

    /// The coordinator is the lowest fingerprint present, and it moves when that member leaves —
    /// the deterministic election plan §8.4 assumes each partition can run on its own.
    @Test func coordinatorIsTheLowestFingerprintPresent() {
        var ledger = Fixture.ledger(admitting: [3, 1, 2])
        #expect(ledger.derivedRoster.coordinatorFingerprint == Fixture.fingerprint(1))

        ledger.departures = ledger.departures.inserting(Fixture.departure(1))
        #expect(ledger.derivedRoster.coordinatorFingerprint == Fixture.fingerprint(2))
    }
}

// MARK: - Union-merge laws

/// The merge is a join-semilattice: commutative, associative, idempotent — and stays one once the
/// caps are involved. Plan §10.3's "any reconnect is a merge" rests entirely on this.
@MainActor
@Suite(.serialized)
struct MeshMembershipMergeTests {

    typealias Fixture = MeshMembershipFixtures

    /// Six ledgers covering the shapes a partition actually produces: disjoint views, overlapping
    /// views, a departure only one side saw, a removal only one side saw, a termination, and a view
    /// that has seen everything.
    static func fixtures() -> [MeshMembershipLedger] {
        let admitted = Fixture.ledger(admitting: [1, 2, 3, 4])
        var withDeparture = admitted
        withDeparture.departures = MeshMembershipRecordSet([Fixture.departure(2)])
        var withRemoval = admitted
        withRemoval.removals = MeshMembershipRecordSet([Fixture.removal(3)])
        var everything = withDeparture
        everything.removals = withRemoval.removals
        return [
            .empty,
            Fixture.ledger(admitting: [1, 2]),
            Fixture.ledger(admitting: [3, 4]),
            admitted,
            withDeparture,
            withRemoval,
            everything
        ]
    }

    /// `a ∪ b == b ∪ a`, over every pair of fixtures, in both the ledger and the roster it derives.
    @Test func mergeIsCommutative() {
        let all = Self.fixtures()
        for left in all {
            for right in all {
                #expect(left.merging(right) == right.merging(left))
                #expect(left.merging(right).derivedRoster == right.merging(left).derivedRoster)
            }
        }
    }

    /// `(a ∪ b) ∪ c == a ∪ (b ∪ c)`, over every triple.
    @Test func mergeIsAssociative() {
        let all = Self.fixtures()
        for left in all {
            for middle in all {
                for right in all {
                    #expect(
                        left.merging(middle).merging(right) == left.merging(middle.merging(right))
                    )
                }
            }
        }
    }

    /// `a ∪ a == a`, and re-merging a peer's view a second time changes nothing — the re-gossip
    /// plan §8.3 does on every connect must be free.
    @Test func mergeIsIdempotent() {
        let all = Self.fixtures()
        for ledger in all {
            #expect(ledger.merging(ledger) == ledger)
            for other in all {
                let merged = ledger.merging(other)
                #expect(merged.merging(other) == merged)
                #expect(merged.merging(merged) == merged)
            }
        }
    }

    /// Two devices that independently recorded the same member's departure spend one slot, and the
    /// earlier record is the one that survives on both.
    @Test func duplicateRecordsForOneMemberCollapseToTheEarliest() {
        let early = Fixture.departure(2, secondsIn: 100)
        let late = Fixture.departure(2, secondsIn: 400)
        let forward = MeshMembershipRecordSet([early, late])
        let backward = MeshMembershipRecordSet([late, early])
        #expect(forward.count == 1)
        #expect(forward == backward)
        #expect(forward.all.first?.occurredAt == early.occurredAt)
    }

    /// Determinism: the same records in any of several orders give byte-identical rosters — same
    /// contents, same order, same coordinator.
    @Test func rosterIsIdenticalUnderEveryMergeOrder() {
        let parts = Self.fixtures()
        let reference = parts.reduce(MeshMembershipLedger.empty) { $0.merging($1) }
        let reversed = parts.reversed().reduce(MeshMembershipLedger.empty) { $0.merging($1) }
        let interleaved = parts.enumerated()
            .sorted { ($0.offset % 3, $0.offset) < ($1.offset % 3, $1.offset) }
            .map(\.element)
            .reduce(MeshMembershipLedger.empty) { $0.merging($1) }

        #expect(reference == reversed)
        #expect(reference == interleaved)
        #expect(reference.derivedRoster.memberFingerprints == reversed.derivedRoster.memberFingerprints)
        #expect(reference.derivedRoster.memberFingerprints == interleaved.derivedRoster.memberFingerprints)
        #expect(reference.derivedRoster.barred == reversed.derivedRoster.barred)
    }

    /// The worked example from plan §10.5: {A,B,C,D} splits, B departs where only A can see it, A
    /// later meets C, C gossips to D. All three converge on the same roster without B ever meeting
    /// C or D.
    @Test func departureGossipConvergesTransitively() {
        let full = Fixture.ledger(admitting: [1, 2, 3, 4])
        var deviceA = full
        deviceA.departures = MeshMembershipRecordSet([Fixture.departure(2)])
        let deviceC = full
        let deviceD = full

        let cAfterMeetingA = deviceC.merging(deviceA)
        let dAfterMeetingC = deviceD.merging(cAfterMeetingA)

        let expected = [Fixture.fingerprint(1), Fixture.fingerprint(3), Fixture.fingerprint(4)]
        #expect(deviceA.derivedRoster.memberFingerprints == expected)
        #expect(cAfterMeetingA.derivedRoster.memberFingerprints == expected)
        #expect(dAfterMeetingC.derivedRoster.memberFingerprints == expected)
        #expect(dAfterMeetingC.derivedRoster.quorumThreshold == 2)
    }
}

// MARK: - Bounds

/// Every cap plan §9 puts on membership state, each reached deliberately and each documented
/// behaviour observed — dropped by rule, never by a trap.
@MainActor
@Suite(.serialized)
struct MeshMembershipBoundsTests {

    typealias Fixture = MeshMembershipFixtures

    /// The caps are the transport's caps, not a second opinion about them.
    @Test func boundsMatchThePlansTable() {
        #expect(MeshMembershipBounds.maxRosterMembers == 8)
        #expect(MeshMembershipBounds.maxRecordsPerKind == 16)
        #expect(MeshMembershipBounds.maxTerminationRecords == 1)
        #expect(MeshMembershipBounds.maxRosterMembers == MeshIntroductionRoster.maxMembers)
        #expect(MeshMembershipBounds.maxRecordsPerKind == MeshIntroductionRoster.maxBarred)
    }

    /// Forty admissions offered, sixteen kept — the earliest sixteen, on any device.
    @Test func aRecordSetStopsAtItsCapAndKeepsTheEarliest() {
        let offered = (1...40).map { Fixture.admission($0, secondsIn: $0) }
        let set = MeshMembershipRecordSet(offered)
        #expect(set.count == MeshMembershipBounds.maxRecordsPerKind)
        #expect(set.isAtCapacity)
        #expect(set.all.map(\.memberFingerprint) == (1...16).map(Fixture.fingerprint))
        #expect(MeshMembershipRecordSet(offered.reversed()) == set)
    }

    /// Inserting into a full set is not an error and not a silent overwrite: a later record is
    /// simply not kept, and the set is unchanged.
    @Test func insertingIntoAFullSetDropsTheLaterRecord() {
        let set = MeshMembershipRecordSet((1...16).map { Fixture.admission($0, secondsIn: $0) })
        let after = set.inserting(Fixture.admission(99, secondsIn: 900))
        #expect(after == set)
        #expect(!after.contains(fingerprint: Fixture.fingerprint(99)))

        let earlier = set.inserting(Fixture.admission(99, secondsIn: -10))
        #expect(earlier.count == MeshMembershipBounds.maxRecordsPerKind)
        #expect(earlier.contains(fingerprint: Fixture.fingerprint(99)))
        #expect(!earlier.contains(fingerprint: Fixture.fingerprint(16)))
    }

    /// The cap survives merging: capping each side then merging gives the same set as merging then
    /// capping. Without this the roster would depend on who connected first.
    @Test func theCapIsStillAssociativeAndCommutative() {
        let left = (1...20).map { Fixture.admission($0, secondsIn: $0) }
        let right = (10...30).map { Fixture.admission($0, secondsIn: $0) }
        let third = (5...25).map { Fixture.admission($0, secondsIn: $0) }

        let a = MeshMembershipRecordSet(left)
        let b = MeshMembershipRecordSet(right)
        let c = MeshMembershipRecordSet(third)
        #expect(a.merging(b) == b.merging(a))
        #expect(a.merging(b).merging(c) == a.merging(b.merging(c)))
        #expect(a.merging(b) == MeshMembershipRecordSet(left + right))
    }

    /// The roster cap (8) is tighter than the record cap (16): sixteen admissions, eight members.
    @Test func theRosterCapIsEightEvenWithSixteenAdmissions() {
        let ledger = MeshMembershipLedger(
            admissions: MeshMembershipRecordSet((1...16).map { Fixture.admission($0, secondsIn: $0) })
        )
        let roster = ledger.derivedRoster
        #expect(roster.memberCount == MeshMembershipBounds.maxRosterMembers)
        #expect(roster.memberFingerprints == (1...8).map(Fixture.fingerprint))
        #expect(roster.quorumThreshold == 5)
        #expect(roster.introductionRoster().memberCount == MeshMembershipBounds.maxRosterMembers)
    }

    /// A mesh ends once: a second termination record does not displace the first, and the earliest
    /// wins whichever order the two views merged in.
    @Test func onlyOneTerminationRecordIsKept() {
        let first = Fixture.termination(1, secondsIn: 300)
        let second = Fixture.termination(2, secondsIn: 400)
        let forward = MeshMembershipRecordSet([first, second])
        let backward = MeshMembershipRecordSet([second, first])
        #expect(forward.count == MeshMembershipBounds.maxTerminationRecords)
        #expect(forward == backward)
        #expect(forward.earliest?.memberFingerprint == Fixture.fingerprint(1))
    }

    /// The list fields inside a record clamp on construction: custodians, voters and the signer's
    /// roster view all stop at the roster cap, and a negative item count clamps to zero.
    @Test func recordListFieldsClampOnConstruction() {
        let many = (1...30).map(Fixture.fingerprint)
        let summary = MeshCustodyHandoffSummary(custodianFingerprints: many, handedOffItemCount: -5)
        #expect(summary.custodianFingerprints.count == MeshMembershipBounds.maxCustodians)
        #expect(summary.handedOffItemCount == 0)

        let removal = SignedRemovalRecord(
            meshID: Fixture.meshID,
            memberFingerprint: Fixture.fingerprint(2),
            proposalID: UUID(),
            voterFingerprints: many,
            occurredAt: Fixture.base,
            authorFingerprint: Fixture.fingerprint(0),
            signature: Fixture.signature(2)
        )
        #expect(removal.voterFingerprints.count == MeshMembershipBounds.maxVoters)

        let termination = SignedTerminationRecord(
            meshID: Fixture.meshID,
            memberFingerprint: Fixture.fingerprint(1),
            rosterAtSigning: many,
            occurredAt: Fixture.base,
            signature: Fixture.signature(1)
        )
        #expect(termination.rosterAtSigning.count == MeshMembershipBounds.maxRosterMembers)
    }

    /// Decoding applies the same caps as construction. A sidecar or a peer that offers forty
    /// records and thirty voters is untrusted input, and `Codable` synthesis would have clamped
    /// neither.
    @Test func decodingAppliesTheSameCaps() throws {
        let oversized = OversizedLedgerFixture(
            admissions: (1...40).map { Fixture.admission($0, secondsIn: $0) },
            removals: [SignedRemovalRecord(
                meshID: Fixture.meshID,
                memberFingerprint: Fixture.fingerprint(2),
                proposalID: UUID(),
                voterFingerprints: (1...30).map(Fixture.fingerprint),
                occurredAt: Fixture.base,
                authorFingerprint: Fixture.fingerprint(0),
                signature: Fixture.signature(2)
            )]
        )
        let data = try JSONEncoder().encode(oversized)
        let decoded = try JSONDecoder().decode(MeshMembershipLedger.self, from: data)

        #expect(decoded.admissions.count == MeshMembershipBounds.maxRecordsPerKind)
        #expect(decoded.removals.earliest?.voterFingerprints.count == MeshMembershipBounds.maxVoters)
        // Eight admitted (the roster cap, out of sixteen kept records), minus the decoded removal.
        #expect(decoded.derivedRoster.memberCount == MeshMembershipBounds.maxRosterMembers - 1)
        #expect(!decoded.derivedRoster.contains(fingerprint: Fixture.fingerprint(2)))
    }

    /// A round trip through JSON preserves the ledger and therefore the roster — what item 2's
    /// sealed store will rely on.
    @Test func aLedgerSurvivesARoundTrip() throws {
        var ledger = Fixture.ledger(admitting: [1, 2, 3])
        ledger.departures = MeshMembershipRecordSet([Fixture.departure(2)])
        ledger.removals = MeshMembershipRecordSet([Fixture.removal(3)])

        let data = try JSONEncoder().encode(ledger)
        let decoded = try JSONDecoder().decode(MeshMembershipLedger.self, from: data)
        #expect(decoded == ledger)
        #expect(decoded.derivedRoster == ledger.derivedRoster)
    }
}

// MARK: - Oversized fixture

/// An encoder-side stand-in for a peer or a sidecar that offers more records than the caps allow.
///
/// It exists because the real types clamp on the way in: to prove the *decode* path clamps too, the
/// bytes have to be written by something that does not.
private struct OversizedLedgerFixture: Encodable {
    let admissions: [SignedAdmissionRecord]
    let removals: [OversizedRemoval]
    let departures: [SignedDepartureRecord] = []
    let terminations: [SignedTerminationRecord] = []

    init(admissions: [SignedAdmissionRecord], removals: [SignedRemovalRecord]) {
        self.admissions = admissions
        self.removals = removals.map(OversizedRemoval.init)
    }
}

/// A removal encoded with an unclamped voter list, so the decoder's clamp has something to clamp.
private struct OversizedRemoval: Encodable {
    let meshID: UUID
    let memberFingerprint: String
    let proposalID: UUID
    let voterFingerprints: [String]
    let occurredAt: Date
    let authorFingerprint: String
    let signature: Data

    init(_ record: SignedRemovalRecord) {
        meshID = record.meshID
        memberFingerprint = record.memberFingerprint
        proposalID = record.proposalID
        voterFingerprints = (1...30).map(MeshMembershipFixtures.fingerprint)
        occurredAt = record.occurredAt
        authorFingerprint = record.authorFingerprint
        signature = record.signature
    }
}
