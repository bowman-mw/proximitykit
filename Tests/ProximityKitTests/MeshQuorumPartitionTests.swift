// MeshQuorumPartitionTests.swift
// ProximityKitTests
//
// P4 item 5 (plan §10.4): moderation under partition — the roster quorum.
//
// §10.4, verbatim, is what this file encodes:
//
//   Removal requires ⌊|roster|/2⌋ + 1 distinct signed votes (the proposal counts as the proposer's
//   vote; the target cannot vote), where roster is the *current merged derived roster* at
//   evaluation time. Votes are signed records referencing a proposal ID; a proposal expires 5
//   minutes after issuance. A completed removal becomes a permanent `SignedRemovalRecord` and
//   union-merges like any record; an incomplete proposal simply expires and leaves no trace in the
//   roster. Consequences: roster 4 → quorum 3 → a 2/2 split can moderate nobody; a 3/1 split can
//   remove the isolated member. Roster 2 → quorum 2 with the target abstaining → removal is
//   structurally impossible. After a departure shrinks roster 4 → 3, quorum drops to 2 and a
//   connected pair regains moderation power.
//
// Four claims are walled here, each one something a later item cannot cheaply re-derive:
//
// 1. **Quorum is the RECEIVER's arithmetic, on the MERGED roster.** A partition does not shrink the
//    derived roster (item 1), so a branch of two out of four is short of quorum however connected
//    it feels. The table below runs rosters 2–8 × partition shapes and checks both questions in
//    every cell: can this branch remove somebody inside it, and somebody outside it.
// 2. **No wall clock in the bytes decides anything.** Expiry is measured from the RECEIVER's own
//    first-seen instant on an injected clock. The signed `issuedAt` is only ever a *bound* (§10.3's
//    ±10 minutes), so a forged far-future stamp cannot extend a window and a forged far-past one
//    cannot kill a live proposal.
// 3. **An incomplete proposal leaves no trace.** Not a tombstone, not a sealed row, not a record —
//    the ledger's four record counts are identical before the proposal and after it expires, and
//    `MeshSessionContext` stays at schema 2 because nothing here is ever persisted.
// 4. **Two independent completions converge on ONE removal.** Three members of a branch each reach
//    quorum and each mint a record; the union deduplicates by member keeping the earliest, so the
//    merge needs no special case and no second ledger commit happens at the manager seam.
//
// Everything except the last suite is a **value test**: `MeshRemovalQuorum` takes its clock and its
// roster as parameters and verifies no signatures, so §10.4's whole arithmetic runs with no fabric,
// no store and no transport. The signature half is `MeshMembershipRecordVerifier`'s and is asserted
// separately, with really-signed proposals and votes.
//
// A partial copy (ProximityKit plan step A1, the split's second batch of copied suites: those that reach
// the keychain and open no store): of the Fernlet repository's FernletTests file of the same name, this
// holds only `MeshRemovalQuorumArithmeticTests`, `MeshRemovalQuorumExpiryTests`,
// `MeshQuorumPartitionTableTests` and `MeshQuorumSignatureTests`, with their names and tests unchanged,
// and the fixtures they read (`MeshQuorumRoster`, `MeshQuorumCell`, `MeshQuorumFixtures` and
// `MeshQuorumTestFailure`); its last suite, `MeshQuorumManagerSeamTests`, stays there, so what this
// header says of it is not held here.

import Foundation
import Testing
@testable import ProximityKit

// MARK: - MeshQuorumRoster

/// A roster of `n` real, provisioned members and the ledger it derives from.
///
/// The identities are kept because §10.4's departure case needs one of them to sign its own
/// departure — a fixture that only kept fingerprints could not shrink a roster honestly.
@MainActor
struct MeshQuorumRoster {

    /// The members, in creation order (NOT roster order — the roster sorts by fingerprint).
    let identities: [IdentityService]

    /// The mesh everything is keyed on.
    let meshID: UUID

    /// The records the roster is derived from.
    var ledger: MeshMembershipLedger

    /// The derived roster, re-derived on every read exactly as the shipping code does.
    var roster: MeshDerivedRoster { ledger.derivedRoster }

    /// The member fingerprints, in the roster's own deterministic order.
    var fingerprints: [String] { roster.memberFingerprints }
}

// MARK: - MeshQuorumCell

/// One cell of plan §10.4's consequences table: a merged roster size and the branches a partition
/// splits it into.
///
/// A value type rather than a tuple so the failure messages name the shape — "4 → 2/2" is the
/// difference between reading a failure and bisecting one.
struct MeshQuorumCell: Sendable {

    /// The merged derived roster's size. A partition never changes it (item 1).
    let rosterSize: Int

    /// The branches, largest first. They sum to ``rosterSize``.
    let branchSizes: [Int]

    /// The frozen diagnostic label, e.g. `"8 → 4/2/2"`. Never display copy.
    var label: String {
        "\(rosterSize) → " + branchSizes.map(String.init).joined(separator: "/")
    }

    /// Plan §10.4's threshold, written from the plan rather than read off the code under test.
    var quorum: Int { rosterSize / 2 + 1 }
}

// MARK: - MeshQuorumFixtures

/// Everything the quorum scenarios build, in one place.
@MainActor
enum MeshQuorumFixtures {

    /// The pinned instant every scenario measures from. Nothing here reads a wall clock.
    ///
    /// `nonisolated` because it is a default argument below, and a `@MainActor` value cannot be one.
    nonisolated static let base = Date(timeIntervalSince1970: 1_700_000_000)

    /// A 64-byte blob standing in for a signature. ``MeshRemovalQuorum`` verifies nothing — that is
    /// ``MeshMembershipRecordVerifier``'s job and has its own suite — so a well-formed placeholder
    /// is the honest input here, and using a real one would only make the arithmetic slower.
    nonisolated static let placeholderSignature = Data(repeating: 0xAB, count: 64)

    /// A roster of `size` real, provisioned members.
    ///
    /// - Parameters:
    ///   - size: How many members. Plan §9 caps a roster at 8.
    ///   - label: Keychain-row prefix, so no two fixtures share a row.
    static func roster(size: Int, label: String) throws -> MeshQuorumRoster {
        let meshID = UUID()
        let identities = try (0..<size).map { try MeshPartitionFixtures.identity("\(label)\($0)") }
        guard let founder = identities.first else { throw MeshQuorumTestFailure.rosterTooSmall }
        #expect(Set(identities.map(\.localFingerprint)).count == size,
                "\(size) DISTINCT provisioned identities, or every claim below is vacuous")
        let ledger = try MeshPartitionFixtures.ledger(
            founder: founder, others: Array(identities.dropFirst()), meshID: meshID
        )
        let built = MeshQuorumRoster(identities: identities, meshID: meshID, ledger: ledger)
        #expect(built.roster.memberCount == size, "roster \(size) is this cell's hard precondition")
        return built
    }

    /// An unsigned-but-well-formed proposal, for the arithmetic suites.
    static func proposal(
        meshID: UUID,
        proposalID: UUID = UUID(),
        target: String,
        proposer: String,
        issuedAt: Date = base
    ) -> SignedRemovalProposal {
        SignedRemovalProposal(
            meshID: meshID, proposalID: proposalID, targetFingerprint: target,
            proposerFingerprint: proposer, issuedAt: issuedAt, signature: placeholderSignature
        )
    }

    /// A well-formed vote agreeing with `proposal`.
    static func vote(
        on proposal: SignedRemovalProposal, voter: String, castAt: Date = base
    ) -> SignedRemovalVote {
        SignedRemovalVote(
            meshID: proposal.meshID, proposalID: proposal.proposalID,
            targetFingerprint: proposal.targetFingerprint, voterFingerprint: voter,
            castAt: castAt, signature: placeholderSignature
        )
    }

    /// Opens a proposal by `voters.first` and casts the rest, then answers §10.4 for that branch.
    ///
    /// - Parameters:
    ///   - voters: The branch members that may vote, proposer first. Never contains the target.
    ///   - target: The member proposed for removal, in the branch or outside it.
    ///   - roster: The **merged** derived roster the arithmetic is judged on.
    ///   - meshID: The mesh.
    /// - Returns: The verdict, or `.unknown` when the branch could not even open a proposal.
    static func verdict(
        voters: [String], target: String, roster: MeshDerivedRoster, meshID: UUID
    ) -> MeshRemovalQuorumVerdict {
        guard let proposer = voters.first else { return .unknown }
        var quorum = MeshRemovalQuorum()
        let opened = Self.proposal(meshID: meshID, target: target, proposer: proposer)
        guard quorum.open(opened, meshID: meshID, roster: roster, now: base) == nil else {
            return .unknown
        }
        for voter in voters.dropFirst() {
            let rejection = quorum.cast(
                Self.vote(on: opened, voter: voter), meshID: meshID, roster: roster, now: base
            )
            #expect(rejection == nil, "a branch member's vote must count: \(voter)")
        }
        return quorum.verdict(for: opened.proposalID, roster: roster, at: base)
    }
}

// MARK: - MeshQuorumTestFailure

/// A precondition a quorum fixture could not meet. Thrown rather than force-unwrapped so a broken
/// fixture fails as a named error instead of trapping (Power of 10 rule 5).
enum MeshQuorumTestFailure: Error {
    /// Fewer identities than the scenario needs.
    case rosterTooSmall
    /// A record the fixture had to sign could not be signed.
    case couldNotSign
}

// MARK: - MeshRemovalQuorumArithmeticTests

/// The rules §10.4 states about *who* counts, on a fixed roster of four.
@MainActor
@Suite(.serialized)
struct MeshRemovalQuorumArithmeticTests {

    /// The proposal IS the proposer's vote — so a roster of four needs two more, not three.
    @Test func theProposalCountsAsTheProposersVote() throws {
        let fixture = try MeshQuorumFixtures.roster(size: 4, label: "q-proposer")
        let names = fixture.fingerprints
        var quorum = MeshRemovalQuorum()
        let proposal = MeshQuorumFixtures.proposal(
            meshID: fixture.meshID, target: names[3], proposer: names[0]
        )
        #expect(quorum.open(
            proposal, meshID: fixture.meshID, roster: fixture.roster, now: MeshQuorumFixtures.base
        ) == nil)
        #expect(quorum.proposal(proposal.proposalID)?.voterFingerprints == [names[0]])
        #expect(quorum.verdict(
            for: proposal.proposalID, roster: fixture.roster, at: MeshQuorumFixtures.base
        ) == .pending(required: 3, counted: 1))
    }

    /// The target's vote is **discarded, not counted** — and it is refused at the door as well, so
    /// the rule survives a refactor of either half.
    @Test func theTargetMayNotVote() throws {
        let fixture = try MeshQuorumFixtures.roster(size: 4, label: "q-target")
        let names = fixture.fingerprints
        var quorum = MeshRemovalQuorum()
        let proposal = MeshQuorumFixtures.proposal(
            meshID: fixture.meshID, target: names[3], proposer: names[0]
        )
        #expect(quorum.open(
            proposal, meshID: fixture.meshID, roster: fixture.roster, now: MeshQuorumFixtures.base
        ) == nil)
        // The target's own vote is not even well-formed: target == voter.
        let selfVote = MeshQuorumFixtures.vote(on: proposal, voter: names[3])
        #expect(selfVote.isWellFormed == false)
        #expect(quorum.cast(
            selfVote, meshID: fixture.meshID, roster: fixture.roster, now: MeshQuorumFixtures.base
        ) == .malformed)
        // A proposal whose proposer IS the target is refused too.
        var second = MeshRemovalQuorum()
        let selfProposal = MeshQuorumFixtures.proposal(
            meshID: fixture.meshID, target: names[1], proposer: names[1]
        )
        #expect(second.open(
            selfProposal, meshID: fixture.meshID, roster: fixture.roster,
            now: MeshQuorumFixtures.base
        ) == .malformed)
    }

    /// A duplicate signer counts once, and a stranger counts never.
    @Test func duplicatesCountOnceAndNonMembersNotAtAll() throws {
        let fixture = try MeshQuorumFixtures.roster(size: 4, label: "q-dupe")
        let names = fixture.fingerprints
        var quorum = MeshRemovalQuorum()
        let proposal = MeshQuorumFixtures.proposal(
            meshID: fixture.meshID, target: names[3], proposer: names[0]
        )
        #expect(quorum.open(
            proposal, meshID: fixture.meshID, roster: fixture.roster, now: MeshQuorumFixtures.base
        ) == nil)
        #expect(quorum.cast(
            MeshQuorumFixtures.vote(on: proposal, voter: names[1]),
            meshID: fixture.meshID, roster: fixture.roster, now: MeshQuorumFixtures.base
        ) == nil)
        #expect(quorum.cast(
            MeshQuorumFixtures.vote(on: proposal, voter: names[1]),
            meshID: fixture.meshID, roster: fixture.roster, now: MeshQuorumFixtures.base
        ) == .duplicateVote)
        #expect(quorum.cast(
            MeshQuorumFixtures.vote(on: proposal, voter: "stranger-fingerprint"),
            meshID: fixture.meshID, roster: fixture.roster, now: MeshQuorumFixtures.base
        ) == .notAMember)
        #expect(quorum.verdict(
            for: proposal.proposalID, roster: fixture.roster, at: MeshQuorumFixtures.base
        ) == .pending(required: 3, counted: 2))
    }

    /// A voter who has DEPARTED by evaluation time stops counting — without any stored vote
    /// changing. That is what "re-derived on the merged roster at evaluation time" buys.
    @Test func aVoterWhoLeavesBeforeEvaluationStopsCounting() throws {
        var fixture = try MeshQuorumFixtures.roster(size: 4, label: "q-leaver")
        let names = fixture.fingerprints
        var quorum = MeshRemovalQuorum()
        let proposal = MeshQuorumFixtures.proposal(
            meshID: fixture.meshID, target: names[3], proposer: names[0]
        )
        #expect(quorum.open(
            proposal, meshID: fixture.meshID, roster: fixture.roster, now: MeshQuorumFixtures.base
        ) == nil)
        for voter in [names[1], names[2]] {
            #expect(quorum.cast(
                MeshQuorumFixtures.vote(on: proposal, voter: voter),
                meshID: fixture.meshID, roster: fixture.roster, now: MeshQuorumFixtures.base
            ) == nil)
        }
        #expect(quorum.verdict(
            for: proposal.proposalID, roster: fixture.roster, at: MeshQuorumFixtures.base
        ).isComplete, "three of four is quorum")
        // names[2] departs. Roster 3 ⇒ quorum 2, and only two of the three cited voters remain.
        guard let leaver = fixture.identities.first(where: { $0.localFingerprint == names[2] })
        else { throw MeshQuorumTestFailure.rosterTooSmall }
        fixture.ledger.departures = fixture.ledger.departures.inserting(
            try SignedDepartureRecord.signed(
                meshID: fixture.meshID, identity: leaver, occurredAt: MeshQuorumFixtures.base
            )
        )
        #expect(fixture.roster.memberCount == 3)
        #expect(fixture.roster.quorumThreshold == 2)
        #expect(quorum.verdict(
            for: proposal.proposalID, roster: fixture.roster, at: MeshQuorumFixtures.base
        ).isComplete, "the two surviving voters still make the smaller quorum")
        #expect(quorum.proposal(proposal.proposalID)?.voterFingerprints.count == 3,
                "nothing STORED changed — only the roster the verdict is derived against")
    }

    /// The bounded tables: four open proposals, eight votes on one.
    @Test func theQuorumTablesAreBounded() throws {
        let fixture = try MeshQuorumFixtures.roster(size: 4, label: "q-bounds")
        let names = fixture.fingerprints
        var quorum = MeshRemovalQuorum()
        for index in 0...MeshRemovalQuorumBounds.maxOpenProposals {
            let proposal = MeshQuorumFixtures.proposal(
                meshID: fixture.meshID, target: names[3], proposer: names[0]
            )
            let rejection = quorum.open(
                proposal, meshID: fixture.meshID, roster: fixture.roster,
                now: MeshQuorumFixtures.base
            )
            let expected: MeshRemovalQuorumRejection? =
                index < MeshRemovalQuorumBounds.maxOpenProposals ? nil : .tableFull
            #expect(rejection == expected, "open proposal \(index)")
        }
        #expect(quorum.count == MeshRemovalQuorumBounds.maxOpenProposals)
        #expect(MeshRemovalQuorumBounds.maxVotesPerProposal == MeshMembershipBounds.maxVoters)
    }
}

// MARK: - MeshRemovalQuorumExpiryTests

/// §10.4's five-minute window, and the two clock claims underneath it.
@MainActor
@Suite(.serialized)
struct MeshRemovalQuorumExpiryTests {

    /// The window is measured from the RECEIVER's first-seen instant, not from the signed stamp —
    /// so a proposal is live for five minutes *here* however the proposer stamped it.
    @Test func expiryIsMeasuredFromTheReceiversFirstSeenInstant() throws {
        let fixture = try MeshQuorumFixtures.roster(size: 4, label: "q-expiry")
        let names = fixture.fingerprints
        let seenAt = MeshQuorumFixtures.base.addingTimeInterval(120)
        var quorum = MeshRemovalQuorum()
        // Stamped five minutes in the PAST (inside the ±10-minute bound) — and still live for a
        // full five minutes from the moment this device first saw it.
        let proposal = MeshQuorumFixtures.proposal(
            meshID: fixture.meshID, target: names[3], proposer: names[0],
            issuedAt: seenAt.addingTimeInterval(-300)
        )
        #expect(quorum.open(
            proposal, meshID: fixture.meshID, roster: fixture.roster, now: seenAt
        ) == nil)
        #expect(quorum.proposal(proposal.proposalID)?.firstSeenAt == seenAt)
        let almost = seenAt.addingTimeInterval(MeshRemovalQuorumBounds.proposalLifetime - 1)
        #expect(quorum.verdict(for: proposal.proposalID, roster: fixture.roster, at: almost)
                == .pending(required: 3, counted: 1))
        let after = seenAt.addingTimeInterval(MeshRemovalQuorumBounds.proposalLifetime)
        #expect(quorum.verdict(for: proposal.proposalID, roster: fixture.roster, at: after) == .expired)
        #expect(MeshRemovalQuorumBounds.proposalLifetime == 300, "plan §10.4's five minutes")
    }

    /// A forged far-future stamp cannot extend a window: the ±10-minute bound refuses it outright,
    /// and even inside the bound it is not what expiry reads.
    @Test func aForgedIssuanceStampIsBoundedAndDecidesNothing() throws {
        let fixture = try MeshQuorumFixtures.roster(size: 4, label: "q-skew")
        let names = fixture.fingerprints
        var quorum = MeshRemovalQuorum()
        let allowance = MeshRemovalQuorumBounds.issuanceSkewAllowance
        for offset in [allowance + 1, -(allowance + 1)] {
            let forged = MeshQuorumFixtures.proposal(
                meshID: fixture.meshID, target: names[3], proposer: names[0],
                issuedAt: MeshQuorumFixtures.base.addingTimeInterval(offset)
            )
            #expect(quorum.open(
                forged, meshID: fixture.meshID, roster: fixture.roster,
                now: MeshQuorumFixtures.base
            ) == .issuanceOutOfRange, "offset \(offset)")
        }
        #expect(quorum.count == 0)
        #expect(allowance == 600, "plan §10.3's ±10 minutes, reused rather than restated")
    }

    /// **An incomplete proposal leaves no trace.** The ledger's four record counts are identical
    /// before it, while it is open, and after it expires — and the tally itself is empty again.
    @Test func anIncompleteProposalLeavesNoTrace() throws {
        let fixture = try MeshQuorumFixtures.roster(size: 4, label: "q-trace")
        let names = fixture.fingerprints
        let before = MeshPartitionFixtures.recordCounts(fixture.ledger)
        var quorum = MeshRemovalQuorum()
        let proposal = MeshQuorumFixtures.proposal(
            meshID: fixture.meshID, target: names[3], proposer: names[0]
        )
        #expect(quorum.open(
            proposal, meshID: fixture.meshID, roster: fixture.roster, now: MeshQuorumFixtures.base
        ) == nil)
        #expect(quorum.cast(
            MeshQuorumFixtures.vote(on: proposal, voter: names[1]),
            meshID: fixture.meshID, roster: fixture.roster, now: MeshQuorumFixtures.base
        ) == nil, "one vote short of quorum 3")
        #expect(MeshPartitionFixtures.recordCounts(fixture.ledger) == before,
                "an OPEN proposal writes no record")
        let after = MeshQuorumFixtures.base
            .addingTimeInterval(MeshRemovalQuorumBounds.proposalLifetime + 1)
        #expect(quorum.prune(at: after) == 1)
        #expect(quorum.count == 0)
        #expect(quorum.verdict(for: proposal.proposalID, roster: fixture.roster, at: after) == .unknown,
                "expiry is a deletion, not a tombstone")
        #expect(MeshPartitionFixtures.recordCounts(fixture.ledger) == before,
                "and an EXPIRED proposal writes no record either")
    }

    /// A vote that arrives after the window has closed is refused by name, and a vote for a
    /// proposal this device never saw is refused by a different name — the two are not the same
    /// situation and a bare `false` would make them one.
    @Test func lateAndOrphanVotesAreRefusedByName() throws {
        let fixture = try MeshQuorumFixtures.roster(size: 4, label: "q-late")
        let names = fixture.fingerprints
        var quorum = MeshRemovalQuorum()
        let proposal = MeshQuorumFixtures.proposal(
            meshID: fixture.meshID, target: names[3], proposer: names[0]
        )
        #expect(quorum.open(
            proposal, meshID: fixture.meshID, roster: fixture.roster, now: MeshQuorumFixtures.base
        ) == nil)
        let orphan = MeshQuorumFixtures.proposal(
            meshID: fixture.meshID, target: names[2], proposer: names[0]
        )
        #expect(quorum.cast(
            MeshQuorumFixtures.vote(on: orphan, voter: names[1]),
            meshID: fixture.meshID, roster: fixture.roster, now: MeshQuorumFixtures.base
        ) == .unknownProposal)
        // A vote citing the right proposal but naming a different target cannot be counted either.
        let mismatched = SignedRemovalVote(
            meshID: fixture.meshID, proposalID: proposal.proposalID,
            targetFingerprint: names[2], voterFingerprint: names[1],
            castAt: MeshQuorumFixtures.base, signature: MeshQuorumFixtures.placeholderSignature
        )
        #expect(quorum.cast(
            mismatched, meshID: fixture.meshID, roster: fixture.roster, now: MeshQuorumFixtures.base
        ) == .proposalMismatch)
        // And a late one: the prune inside `cast` drops the window, so the answer is "unknown".
        let late = MeshQuorumFixtures.base
            .addingTimeInterval(MeshRemovalQuorumBounds.proposalLifetime + 1)
        #expect(quorum.cast(
            MeshQuorumFixtures.vote(on: proposal, voter: names[1], castAt: late),
            meshID: fixture.meshID, roster: fixture.roster, now: late
        ) == .unknownProposal)
    }
}

// MARK: - MeshQuorumPartitionTableTests

/// Plan §10.4's consequences, table-driven over rosters 2–8 × partition shapes.
@MainActor
@Suite(.serialized)
struct MeshQuorumPartitionTableTests {

    /// Every shape the plan names, plus the ones that fill the 2–8 range around them.
    static let cells: [MeshQuorumCell] = [
        MeshQuorumCell(rosterSize: 2, branchSizes: [2]),
        MeshQuorumCell(rosterSize: 3, branchSizes: [2, 1]),
        MeshQuorumCell(rosterSize: 4, branchSizes: [2, 2]),
        MeshQuorumCell(rosterSize: 4, branchSizes: [3, 1]),
        MeshQuorumCell(rosterSize: 5, branchSizes: [3, 2]),
        MeshQuorumCell(rosterSize: 6, branchSizes: [3, 3]),
        MeshQuorumCell(rosterSize: 6, branchSizes: [4, 2]),
        MeshQuorumCell(rosterSize: 8, branchSizes: [4, 4]),
        MeshQuorumCell(rosterSize: 8, branchSizes: [5, 3]),
        MeshQuorumCell(rosterSize: 8, branchSizes: [4, 2, 2])
    ]

    /// The whole table. One roster is built per distinct size and reused across that size's shapes:
    /// provisioning is the expensive part and the shapes differ only in how the fingerprints are
    /// grouped, which is a partition — not a different mesh.
    @Test func everyPartitionShapeAnswersPlanSection104() throws {
        var rosters: [Int: MeshQuorumRoster] = [:]
        for size in Set(Self.cells.map(\.rosterSize)).sorted() {
            rosters[size] = try MeshQuorumFixtures.roster(size: size, label: "q-table\(size)-")
        }
        for cell in Self.cells {
            guard let fixture = rosters[cell.rosterSize] else { throw MeshQuorumTestFailure.rosterTooSmall }
            #expect(cell.branchSizes.reduce(0, +) == cell.rosterSize, "\(cell.label) must partition")
            #expect(fixture.roster.quorumThreshold == cell.quorum,
                    "\(cell.label): quorum comes from the MERGED roster, which a split never shrinks")
            try Self.assertBranches(of: cell, on: fixture)
        }
    }

    /// Both §10.4 questions, in every branch of one cell.
    private static func assertBranches(of cell: MeshQuorumCell, on fixture: MeshQuorumRoster) throws {
        let names = fixture.fingerprints
        var start = 0
        for size in cell.branchSizes {
            let branch = Array(names[start..<(start + size)])
            let outsiders = names.filter { !branch.contains($0) }
            start += size
            // (a) an in-branch member: the branch's OTHER members are the only voters.
            guard let inTarget = branch.last else { continue }
            let inVoters = branch.filter { $0 != inTarget }
            let inVerdict = MeshQuorumFixtures.verdict(
                voters: inVoters, target: inTarget, roster: fixture.roster, meshID: fixture.meshID
            )
            #expect(inVerdict.isComplete == (size - 1 >= cell.quorum),
                    "\(cell.label), branch of \(size), in-branch target")
            // (b) an out-of-branch (absent) member: every branch member may vote.
            guard let outTarget = outsiders.first else { continue }
            let outVerdict = MeshQuorumFixtures.verdict(
                voters: branch, target: outTarget, roster: fixture.roster, meshID: fixture.meshID
            )
            #expect(outVerdict.isComplete == (size >= cell.quorum),
                    "\(cell.label), branch of \(size), absent target")
        }
    }

    /// The plan's own three sentences, pinned literally rather than via the formula — so a change
    /// to `quorumThreshold` that happened to keep the formula self-consistent still fails here.
    @Test func thePlansNamedConsequencesHoldLiterally() throws {
        let four = try MeshQuorumFixtures.roster(size: 4, label: "q-named4-")
        let names = four.fingerprints
        #expect(four.roster.quorumThreshold == 3, "roster 4 → quorum 3")
        // 2/2 moderates NOBODY: neither the member beside you nor the two across the split.
        #expect(MeshQuorumFixtures.verdict(
            voters: [names[0]], target: names[1], roster: four.roster, meshID: four.meshID
        ).isComplete == false, "a 2/2 branch cannot remove its own partner")
        #expect(MeshQuorumFixtures.verdict(
            voters: [names[0], names[1]], target: names[2], roster: four.roster, meshID: four.meshID
        ).isComplete == false, "…nor anyone on the other side")
        // 3/1 removes the isolated member — votes are valid for an absent target.
        #expect(MeshQuorumFixtures.verdict(
            voters: [names[0], names[1], names[2]], target: names[3],
            roster: four.roster, meshID: four.meshID
        ).isComplete, "a 3/1 branch removes the isolated member")
    }

    /// Roster 2 is structurally impossible, and a departure that shrinks 4 → 3 gives a connected
    /// pair its moderation power back. (What the final pair does *instead* is item 6's business;
    /// all that is claimed here is that quorum cannot be met.)
    @Test func rosterTwoCannotModerateAndADepartureRestoresAPairsPower() throws {
        let pair = try MeshQuorumFixtures.roster(size: 2, label: "q-pair-")
        #expect(pair.roster.quorumThreshold == 2)
        #expect(MeshQuorumFixtures.verdict(
            voters: [pair.fingerprints[0]], target: pair.fingerprints[1],
            roster: pair.roster, meshID: pair.meshID
        ) == .pending(required: 2, counted: 1),
                "quorum 2 with the target abstaining leaves exactly one vote, forever")

        var four = try MeshQuorumFixtures.roster(size: 4, label: "q-shrink-")
        let names = four.fingerprints
        #expect(MeshQuorumFixtures.verdict(
            voters: [names[0], names[1]], target: names[2], roster: four.roster, meshID: four.meshID
        ).isComplete == false, "before the departure, a pair is one vote short")
        guard let leaver = four.identities.first(where: { $0.localFingerprint == names[3] })
        else { throw MeshQuorumTestFailure.rosterTooSmall }
        four.ledger.departures = four.ledger.departures.inserting(
            try SignedDepartureRecord.signed(
                meshID: four.meshID, identity: leaver, occurredAt: MeshQuorumFixtures.base
            )
        )
        #expect(four.roster.memberCount == 3)
        #expect(four.roster.quorumThreshold == 2, "roster 4 → 3 drops quorum to 2")
        #expect(MeshQuorumFixtures.verdict(
            voters: [names[0], names[1]], target: names[2], roster: four.roster, meshID: four.meshID
        ).isComplete, "and the connected pair regains moderation power")
    }

    /// A partition does not move the roster arithmetic — item 1's invariant, re-asserted here
    /// because §10.4's whole table depends on it. `MeshBranchView` reports the MERGED roster's
    /// threshold whatever it can reach.
    @Test func aBranchViewReportsTheMergedRostersQuorum() throws {
        let fixture = try MeshQuorumFixtures.roster(size: 4, label: "q-branchview-")
        let names = fixture.fingerprints
        let whole = MeshBranchView(
            roster: fixture.roster, reachable: Set(names), selfFingerprint: names[0]
        )
        let split = MeshBranchView(
            roster: fixture.roster, reachable: [names[0], names[1]], selfFingerprint: names[0]
        )
        #expect(whole.rosterQuorumThreshold == 3)
        #expect(split.rosterQuorumThreshold == 3, "a 2/2 split does not lower the bar to 2")
        #expect(split.isPartitioned)
    }
}

// MARK: - MeshQuorumSignatureTests

/// The half ``MeshRemovalQuorum`` deliberately does not do: signatures and signer eligibility, with
/// really-signed proposals and votes.
@MainActor
@Suite(.serialized)
struct MeshQuorumSignatureTests {

    /// A verifier over a roster of four, and the four members' identities.
    private func fixture(_ label: String) throws -> (MeshQuorumRoster, MeshMembershipRecordVerifier) {
        let built = try MeshQuorumFixtures.roster(size: 4, label: label)
        guard let founder = built.identities.first else { throw MeshQuorumTestFailure.rosterTooSmall }
        let verifier = MeshMembershipRecordVerifier(
            meshID: built.meshID,
            founderSigningPublicKey: founder.localSigningPublicKey,
            ledger: built.ledger
        )
        return (built, verifier)
    }

    /// An honestly signed proposal and vote verify; a tampered one does not.
    @Test func honestQuorumFramesVerifyAndTamperedOnesDoNot() throws {
        let (built, verifier) = try fixture("q-sig-")
        let members = built.identities
        guard members.count == 4 else { throw MeshQuorumTestFailure.rosterTooSmall }
        let target = members[3].localFingerprint
        let proposal = try SignedRemovalProposal.signed(
            meshID: built.meshID, identity: members[0], targetFingerprint: target,
            issuedAt: MeshQuorumFixtures.base
        )
        let vote = try SignedRemovalVote.signed(
            on: proposal, identity: members[1], castAt: MeshQuorumFixtures.base
        )
        #expect(verifier.verify(proposal) == nil)
        #expect(verifier.verify(vote) == nil)
        let tampered = SignedRemovalProposal(
            meshID: proposal.meshID, proposalID: proposal.proposalID,
            targetFingerprint: members[2].localFingerprint,
            proposerFingerprint: proposal.proposerFingerprint,
            issuedAt: proposal.issuedAt, signature: proposal.signature
        )
        #expect(verifier.verify(tampered) == .signatureInvalid,
                "re-pointing a proposal at another member breaks the proposer's signature")
    }

    /// A proposal or vote signed by a **stranger** — someone this ledger never admitted — has no
    /// key to check against and is refused by name.
    @Test func aStrangersQuorumFrameIsRefused() throws {
        let (built, verifier) = try fixture("q-sig-stranger-")
        guard let member = built.identities.first else { throw MeshQuorumTestFailure.rosterTooSmall }
        let stranger = try MeshPartitionFixtures.identity("q-sig-outsider")
        let proposal = try SignedRemovalProposal.signed(
            meshID: built.meshID, identity: stranger,
            targetFingerprint: member.localFingerprint, issuedAt: MeshQuorumFixtures.base
        )
        #expect(verifier.verify(proposal) == .signerNotAdmitted)
        let honest = try SignedRemovalProposal.signed(
            meshID: built.meshID, identity: member,
            targetFingerprint: built.fingerprints[3], issuedAt: MeshQuorumFixtures.base
        )
        let strangerVote = try SignedRemovalVote.signed(
            on: honest, identity: stranger, castAt: MeshQuorumFixtures.base
        )
        #expect(verifier.verify(strangerVote) == .signerNotAdmitted)
    }

    /// A vote's bytes cannot be replayed as a proposal, or as a completed removal — the domains are
    /// what keep three signed objects of similar shape apart.
    @Test func aVoteCannotBeReplayedAsAProposalOrARemoval() throws {
        let (built, _) = try fixture("q-sig-domain-")
        let members = built.identities
        guard members.count == 4 else { throw MeshQuorumTestFailure.rosterTooSmall }
        let proposal = try SignedRemovalProposal.signed(
            meshID: built.meshID, identity: members[0],
            targetFingerprint: members[3].localFingerprint, issuedAt: MeshQuorumFixtures.base
        )
        let vote = try SignedRemovalVote.signed(
            on: proposal, identity: members[1], castAt: MeshQuorumFixtures.base
        )
        // Same fields, other domain: the vote's signature must not verify over the proposal's
        // transcript, nor the proposal's over the vote's.
        #expect(IdentityService.verify(
            vote.signature, of: canonicalBytes(for: proposal),
            by: members[1].localSigningPublicKey,
            purpose: ProximityNamespace.packageTest.family.purposes.signature.meshRemovalProposalV1
        ) == false)
        #expect(IdentityService.verify(
            proposal.signature, of: canonicalBytes(for: vote),
            by: members[0].localSigningPublicKey,
            purpose: ProximityNamespace.packageTest.family.purposes.signature.meshRemovalVoteV1
        ) == false)
    }
}
