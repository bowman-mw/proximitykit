// MeshPartitionDetectionTests.swift
// ProximityKitTests
//
// P4 item 1 (plan §10.2): partition detection and branch-local operation.
//
// The claims walled here, in the order the plan makes them:
//
//  1. **A partition is presence, never a record.** Losing a roster member marks them
//     `temporarilyDisconnected` and mints nothing: the derived roster, the quorum threshold and the
//     final-pair test are byte-identical before and after, and the sealed file does not move.
//  2. **Reachability returning is a heal, not a re-admission.** `linksRestored` puts the member's
//     presence back and still writes no record.
//  3. **The branch coordinator is the lowest fingerprint PRESENT**, and it flips when the global
//     lowest goes out of reach and back when it returns — including in the roster the manager would
//     actually present with a rotation, which is what scopes the branch's epochs to the branch.
//  4. **Branch-local rotation still fires**, scoped to the branch: fifteen minutes into a split the
//     branch coordinator plans a strictly greater successor over the branch's roster, and the two
//     branches' refs at the same counter are distinct — the `coexist` shape P4 item 3 reconciles.
//  5. **A partition of one idles out at thirty minutes**; one authenticated external heartbeat
//     inside the window is enough to keep a live branch alive.
//  6. **Presence survives a save/load round trip by not being there.** The schema stays at 2 and a
//     restored manager has looked at nothing.
//  7. **Final pair is judged on the merged roster, not the branch** — the minimal guard; §10.6's
//     full treatment is item 6.
//
// **Nothing here sleeps and nothing reads a wall clock for a decision.** Every instant is an
// argument, exactly as `MeshP3AcceptanceTests` and `MeshEpochKeyring` do it, and reachability is a
// `Set<String>` a test hands to `evaluatePartition(reachable:now:)` rather than a radio it has to
// script. The only real time that passes is whatever a seal takes.
//
// A partial copy (ProximityKit plan step A1, the split's second batch of copied suites: those that reach
// the keychain and open no store): of the Fernlet repository's FernletTests file of the same name, this
// holds only `MeshPartitionBranchViewTests`, with its name and tests unchanged, and the fixtures the
// package's copied suites read (`MeshPartitionFixtures`); its other suites stay there, so what this
// header says of them is not held here. Each fixture member here that reaches the keychain gains one
// first statement that reads `PackageTestEnvironment.keychain` (the package's hygiene rule I9).

import Foundation
import Testing
@testable import ProximityKit

// MARK: - Shared fixtures

/// The roster fixtures both suites below build on.
///
/// Fingerprints come out of real signing keys, so their *order* is not knowable in advance — every
/// scenario therefore sorts and addresses members by rank ("the lowest", "the second lowest")
/// rather than by name, which is also how the shipping coordinator election reads them.
@MainActor
enum MeshPartitionFixtures {

    /// The most members any scenario here builds — plan §9's roster cap is 8, and four is the
    /// shape §10.4's worked example uses (roster 4 → quorum 3 → a 2/2 split moderates nobody).
    static let maxFixtureMembers = 8

    /// A fresh, **provisioned** identity, keyed per call so no two fixtures share a keychain row.
    ///
    /// The provisioning is load-bearing rather than hygiene: an unprovisioned `IdentityService`
    /// cannot sign (`IdentityError.notProvisioned`) and every one of them reports the same
    /// placeholder fingerprint — so a roster built from them would silently dedupe to one member
    /// and every "roster of four" assertion below would be testing a roster of two.
    static func identity(_ label: String) throws -> IdentityService {
        _ = PackageTestEnvironment.keychain
        let service = IdentityService(keychainService: "test.mesh.p4partition.\(label).\(UUID().uuidString)")
        try service.ensureProvisioned()
        return service
    }

    /// A ledger in which `founder` self-admits and then admits everybody else.
    ///
    /// Every record is honestly signed — the derived roster does not verify, but a fixture that
    /// forged one would be a fixture no later phase could reuse.
    static func ledger(
        founder: IdentityService, others: [IdentityService], meshID: UUID
    ) throws -> MeshMembershipLedger {
        var ledger = MeshMembershipLedger.empty
        let joiners = ([founder] + others).prefix(maxFixtureMembers)
        for joiner in joiners {
            ledger.admissions = ledger.admissions.inserting(
                SignedAdmissionRecord(token: try MeshAdmissionToken.signed(
                    meshID: meshID,
                    joinerFingerprint: joiner.localFingerprint,
                    joinerSigningPublicKey: joiner.localSigningPublicKey,
                    admitterIdentity: founder
                ))
            )
        }
        return ledger
    }

    /// How many membership records a ledger holds, so "no record was written" is one comparison
    /// over all four kinds rather than four assertions that could each be forgotten.
    static func recordCounts(_ ledger: MeshMembershipLedger?) -> [Int] {
        guard let ledger else { return [] }
        return [
            ledger.admissions.count, ledger.departures.count,
            ledger.removals.count, ledger.terminations.count
        ]
    }
}

// MARK: - MeshPartitionBranchViewTests

/// The pure half: ``MeshBranchView`` and ``MeshPartitionDetector``, with no manager, no store and
/// no transport.
@MainActor
@Suite(.serialized)
struct MeshPartitionBranchViewTests {

    /// Four members, their fingerprints in ascending order, and the roster they derive.
    private func fourMemberRoster() throws -> (fingerprints: [String], roster: MeshDerivedRoster) {
        let founder = try MeshPartitionFixtures.identity("founder")
        let others = try (0..<3).map { try MeshPartitionFixtures.identity("member\($0)") }
        let ledger = try MeshPartitionFixtures.ledger(
            founder: founder, others: others, meshID: UUID()
        )
        let roster = ledger.derivedRoster
        return (roster.memberFingerprints, roster)
    }

    /// **Claim 1, at the value level.** An unreachable member is `temporarilyDisconnected` and the
    /// three roster answers a partition must not move are copied through unchanged.
    @Test func anUnreachableMemberIsPresenceAndTheRosterArithmeticDoesNotMove() throws {
        let (names, roster) = try fourMemberRoster()
        let whole = MeshBranchView(
            roster: roster, reachable: Set(names), selfFingerprint: names[0]
        )
        let split = MeshBranchView(
            roster: roster, reachable: [names[0], names[1]], selfFingerprint: names[0]
        )
        #expect(whole.isPartitioned == false)
        #expect(split.isPartitioned)
        #expect(split.presentFingerprints == [names[0], names[1]])
        #expect(split.temporarilyDisconnectedFingerprints == [names[2], names[3]])
        #expect(split.presence(of: names[1]) == .present)
        #expect(split.presence(of: names[3]) == .temporarilyDisconnected)
        #expect(split.presence(of: "not-a-member") == nil, "presence is only defined over the roster")
        // The three answers §10.2/§10.4/§10.6 say a split must not touch.
        #expect(split.rosterMemberCount == 4 && whole.rosterMemberCount == 4)
        #expect(split.rosterQuorumThreshold == 3 && whole.rosterQuorumThreshold == 3)
        #expect(split.rosterIsFinalPair == false)
    }

    /// **Claim 3.** The branch coordinator is the lowest fingerprint present, and it flips when the
    /// global lowest becomes unreachable and back when reachability returns.
    @Test func theBranchCoordinatorIsTheLowestFingerprintPresentAndFlipsBothWays() throws {
        let (names, roster) = try fourMemberRoster()
        let observer = names[3]
        let whole = MeshBranchView(roster: roster, reachable: Set(names), selfFingerprint: observer)
        #expect(whole.branchCoordinatorFingerprint == names[0], "unsplit, the branch is the roster")
        let withoutLowest = MeshBranchView(
            roster: roster, reachable: [names[1], names[2], observer], selfFingerprint: observer
        )
        #expect(withoutLowest.branchCoordinatorFingerprint == names[1],
                "the lowest PRESENT coordinates the branch, not the lowest admitted")
        let healed = MeshBranchView(roster: roster, reachable: Set(names), selfFingerprint: observer)
        #expect(healed.branchCoordinatorFingerprint == names[0], "the flip is reversible")
        // A branch of one coordinates itself, and knows it is alone.
        let alone = MeshBranchView(roster: roster, reachable: [observer], selfFingerprint: observer)
        #expect(alone.branchCoordinatorFingerprint == observer)
        #expect(alone.isLocalBranchCoordinator)
        #expect(alone.isAlone)
        #expect(withoutLowest.isAlone == false, "a branch of three is not a partition of one")
    }

    /// **The detector is an edge-detector.** Only entering a partition raises `linksLost`, and only
    /// a full heal raises `linksRestored`; deepening a split and partially healing one raise
    /// nothing, so the session neither re-arms a window nor prematurely re-activates.
    @Test func onlyTheBoundaryOfAPartitionRaisesAnEvent() throws {
        let (names, roster) = try fourMemberRoster()
        func view(_ reachable: [String]) -> MeshBranchView {
            MeshBranchView(roster: roster, reachable: Set(reachable), selfFingerprint: names[0])
        }
        let whole = view(names)
        let half = view([names[0], names[1]])
        let alone = view([names[0]])
        #expect(MeshPartitionDetector.verdict(previous: nil, current: whole) == .unchanged)
        #expect(MeshPartitionDetector.verdict(previous: nil, current: half) == .linksLost,
                "a device that has never looked and finds itself split has lost links")
        #expect(MeshPartitionDetector.verdict(previous: whole, current: half) == .linksLost)
        #expect(MeshPartitionDetector.verdict(previous: half, current: alone) == .unchanged,
                "a deepening split is already partitioned")
        #expect(MeshPartitionDetector.verdict(previous: alone, current: half) == .unchanged,
                "a partial heal leaves a member the roster still names out of reach")
        #expect(MeshPartitionDetector.verdict(previous: half, current: whole) == .linksRestored)
        #expect(MeshPartitionDetector.verdict(previous: whole, current: whole) == .unchanged)
        #expect(MeshPartitionVerdict.linksLost.sessionEvent == .linksLost)
        #expect(MeshPartitionVerdict.linksRestored.sessionEvent == .linksRestored)
        #expect(MeshPartitionVerdict.unchanged.sessionEvent == nil)
    }

    /// **Claim 7, at the value level.** A 2/2 split of a roster of four is not two final pairs, and
    /// neither branch can moderate anybody — the quorum is still 3 (§10.4's worked example).
    @Test func aBranchOfTwoInARosterOfFourIsNeitherAFinalPairNorAQuorum() throws {
        let (names, roster) = try fourMemberRoster()
        let left = MeshBranchView(
            roster: roster, reachable: [names[0], names[1]], selfFingerprint: names[0]
        )
        let right = MeshBranchView(
            roster: roster, reachable: [names[2], names[3]], selfFingerprint: names[2]
        )
        for branch in [left, right] {
            #expect(branch.branchMemberCount == 2)
            #expect(branch.rosterIsFinalPair == false, "final pair is judged on the MERGED roster")
            #expect(branch.rosterQuorumThreshold > branch.branchMemberCount,
                    "a 2/2 split of a four-roster moderates nobody")
        }
        #expect(roster.isFinalPair == false)
        #expect(roster.memberCount == 4)
    }

    /// **Claim 4, at the value level.** Fifteen minutes into a split, each branch's coordinator
    /// plans a strictly greater successor over **its own** roster — and the two branches' refs at
    /// the same counter are distinct, which is the `coexist` state item 3 reconciles.
    @Test func branchLocalRotationPlansAStrictlyGreaterSuccessorScopedToTheBranch() throws {
        let meshID = UUID()
        let founder = try MeshPartitionFixtures.identity("rot-founder")
        let others = try (0..<3).map { try MeshPartitionFixtures.identity("rot-member\($0)") }
        let roster = try MeshPartitionFixtures.ledger(
            founder: founder, others: others, meshID: meshID
        ).derivedRoster
        let names = roster.memberFingerprints
        let start = Date(timeIntervalSince1970: 1_800_000_000)
        // The 15-minute timer, injected: the trigger is requested a quarter of an hour into the
        // split and coalesces into one rotation two seconds later.
        var queue = MeshRotationTriggerQueue()
        let firesAt = start.addingTimeInterval(15 * 60)
        let debounce = MeshRotationTriggerBounds.debounceWindowSeconds
        #expect(queue.request(.timer, at: firesAt)
                == .scheduled(at: firesAt.addingTimeInterval(debounce), cause: .timer))
        #expect(queue.claim(at: firesAt.addingTimeInterval(debounce)) == .timer)
        guard let head = MeshEpochRef.minted(
            counter: 7, coordinatorFingerprint: names[0], meshID: meshID
        ) else {
            Issue.record("could not mint the shared pre-split epoch")
            return
        }
        var minted: [MeshEpochRef] = []
        for branch in [[names[0], names[1]], [names[2], names[3]]] {
            let view = MeshBranchView(
                roster: roster, reachable: Set(branch), selfFingerprint: branch[0]
            )
            guard let coordinator = view.branchCoordinatorFingerprint else {
                Issue.record("a branch of two must elect a coordinator")
                return
            }
            #expect(coordinator == branch[0])
            let plan = MeshRotationPolicy.plan(
                head: head, coordinatorFingerprint: coordinator, meshID: meshID,
                presentedRoster: view.presentFingerprints
            )
            guard case .rotate(let next) = plan else {
                Issue.record("a branch coordinator must be able to rotate its own branch: \(plan)")
                return
            }
            #expect(next.counter == 8, "each branch increments its own head")
            minted.append(next)
        }
        #expect(minted.count == 2)
        #expect(minted[0] != minted[1],
                "same counter, different branch coordinators — two refs that coexist until a merge")
    }
}
