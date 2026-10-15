// MeshMergeWindowTests.swift
// ProximityKitTests
//
// Network migration P5 item 7: the merge-window redesign, which retires P4's deferred defect 2d.
//
// Two suites, and the split is the design:
//
// - `MeshMergeWindowStateTests` drives `MeshMergeWindow` as the pure value it is — no manager, no
//   store, no clock. The closing law is `pending = (asked ∪ answered) ∩ reachable ∖ matched`, and
//   every claim about it is one line here rather than a settle away.
// - `MeshMergeWindowWireTests` drives the same rule through real signed frames on `FakePeerNetwork`.
//   Cells with three managers run on `MeshDepartureRig`, never on `MeshMergeWire`: a
//   `MeshMergeWireNode` holds exactly ONE coordinator, and `MeshNetworkManager` resolves an inbound
//   frame's slot by coordinator identity — so on a node with two peers every frame would be
//   attributed to one of them and an `asked` set of two could not be observed at all.
//
// Window state is sampled **right after a synchronous pump**, never after an `await`: a yield
// releases the main actor and the 2 s rotation debounce can fire in the gap. The rigs' `settle`
// helpers run their `until:` / `sampling:` closures at exactly that point.
//
// A partial copy (ProximityKit plan step A1, the split's first batch of copied suites): of the
// Fernlet repository's FernletTests file of the same name, this holds only
// `MeshMergeWindowStateTests`, with its name and tests unchanged; its other suites stay there, so
// what this header says of them is not held here.

import Foundation
import Testing
@testable import ProximityKit

// MARK: - MeshMergeWindowStateTests

/// The closing law, as pure values.
@MainActor
@Suite
struct MeshMergeWindowStateTests {

    /// The mesh every fixture digest names.
    private static let meshID = UUID()

    /// The instant every window records. Recorded, never compared.
    private static let instant = Date(timeIntervalSince1970: 1_800_000_000)

    private static let peerB = "fingerprint-b"
    private static let peerC = "fingerprint-c"
    private static let peerD = "fingerprint-d"
    private static let peerZ = "fingerprint-z"

    /// A digest that differs from every other `byte`, and only in its record hash.
    private static func digest(_ byte: UInt8) -> MeshInventoryDigest {
        MeshInventoryDigest(
            meshID: meshID,
            admissionCount: 2, departureCount: 0, removalCount: 0, terminationCount: 0,
            recordsHash: Data(repeating: byte, count: MeshMembershipEventFormat.digestByteCount)
        )
    }

    /// A freshly armed window.
    private static func opened() -> MeshMergeWindow { .opened(at: instant) }

    /// **1.** A window waits on every peer it asked — and a window that asked nobody (the pre-guard
    /// arming) closes at its first evaluation.
    @Test func anOpenedWindowWaitsOnEveryPeerItAsked() {
        let window = Self.opened().asking([Self.peerB, Self.peerC])
        #expect(window.verdict(reachable: [Self.peerB, Self.peerC]) == .open(outstanding: 2))
        #expect(Self.opened().verdict(reachable: [Self.peerB]) == .closed(.nothingOutstanding),
                "an idle window has nothing to wait for")
    }

    /// **2. 2d, in one line.** One match of two does not close the window.
    @Test func oneMatchOfTwoDoesNotClose() {
        let window = Self.opened().asking([Self.peerB, Self.peerC]).matching(Self.peerB)
        #expect(window.verdict(reachable: [Self.peerB, Self.peerC]) == .open(outstanding: 1))
    }

    /// **3.** Every asked peer matched closes it, and says why.
    @Test func everyAskedPeerMatchedCloses() {
        let window = Self.opened()
            .asking([Self.peerB, Self.peerC]).matching(Self.peerB).matching(Self.peerC)
        #expect(window.verdict(reachable: [Self.peerB, Self.peerC]) == .closed(.converged))
    }

    /// **4. The 2c deadlock, unrepresentable.** Answering alone never closes anything.
    @Test func answeringAloneNeverCloses() {
        let window = Self.opened().answering(Self.peerB)
        #expect(window.verdict(reachable: [Self.peerB]) == .open(outstanding: 1))
        #expect(window.role == .responder)
    }

    /// **5.** An answered peer closes only when it matches back.
    @Test func anAnsweredPeerClosesOnlyWhenItMatchesBack() {
        let window = Self.opened().answering(Self.peerB).matching(Self.peerB)
        #expect(window.verdict(reachable: [Self.peerB]) == .closed(.converged))
    }

    /// **6.** A late ask joins the same window and re-opens nothing *another* peer already proved.
    @Test func aLateAskJoinsTheSameWindowAndReopensNothing() {
        let window = Self.opened().asking([Self.peerB]).matching(Self.peerB).reAsking(Self.peerD)
        #expect(window.verdict(reachable: [Self.peerB, Self.peerD]) == .open(outstanding: 1))
        #expect(window.matched.contains(Self.peerB),
                "re-asking D did not un-prove B — the un-match is per peer, not per window")
    }

    /// **6a.** But a late ask **does** un-prove the peer it re-asks (D-7.32): a late ask exists
    /// because that peer's link dropped and re-formed, and while it was gone it may have linked to
    /// the other branch of a split — so a match recorded before it left proves nothing now.
    @Test func aLateAskToAMatchedPeerReopensThatPeersObligation() {
        let reAsked = Self.opened()
            .asking([Self.peerB, Self.peerC]).matching(Self.peerC).reAsking(Self.peerC)
        #expect(reAsked.asked == [Self.peerB, Self.peerC], "still one window, one peer wider")
        #expect(!reAsked.matched.contains(Self.peerC))
        #expect(reAsked.verdict(reachable: [Self.peerB, Self.peerC]) == .open(outstanding: 2))
        let bMatched = reAsked.matching(Self.peerB)
        #expect(bMatched.verdict(reachable: [Self.peerB, Self.peerC]) == .open(outstanding: 1),
                "the other peer's match cannot close a window on the re-asked peer's behalf")
        #expect(bMatched.matching(Self.peerC)
            .verdict(reachable: [Self.peerB, Self.peerC]) == .closed(.converged),
                "and its own fresh digest still closes it")
    }

    /// **7.** A mismatching digest un-matches its sender: the obligation an answer creates cannot be
    /// discharged by the match it just contradicted.
    @Test func aMismatchingDigestUnMatchesItsSender() {
        let window = Self.opened().asking([Self.peerB]).matching(Self.peerB).answering(Self.peerB)
        #expect(window.verdict(reachable: [Self.peerB]) == .open(outstanding: 1))
        #expect(!window.matched.contains(Self.peerB))
    }

    /// **7a.** The monotonicity that IS kept, and the one way back into `matched`: the peer's own
    /// evidence, re-evaluated against a ledger that has since grown.
    @Test func onlyThePeersOwnEvidenceMovesItBackToMatched() {
        let reAsked = Self.opened().asking([Self.peerB]).matching(Self.peerB).asking([Self.peerB])
        #expect(reAsked.verdict(reachable: [Self.peerB]) == .closed(.converged),
                "the OPENING ask cannot un-match; the LATE ask has its own transition (test 6a)")
        let local = Self.digest(0x11)
        let recovered = Self.opened()
            .asking([Self.peerB]).matching(Self.peerB).answering(Self.peerB)
            .recording(local, from: Self.peerB)
            .reEvaluated(against: local, reachable: [Self.peerB])
        #expect(recovered.verdict(reachable: [Self.peerB]) == .closed(.converged))
    }

    /// **8.** A matching digest from a peer the window never asked is recorded and asks nothing.
    @Test func anUnaskedPeersMatchIsRecordedAndAsksNothing() {
        let window = Self.opened().asking([Self.peerB]).matching(Self.peerZ)
        #expect(window.verdict(reachable: [Self.peerB, Self.peerZ]) == .open(outstanding: 1))
        #expect(window.matched.contains(Self.peerZ))
        #expect(!window.asked.contains(Self.peerZ), "recorded, never promoted into the ask")
    }

    /// **9.** An unreachable peer is not waited for — the departure rule, with no fourth state.
    @Test func anUnreachablePeerIsNotWaitedFor() {
        let matched = Self.opened().asking([Self.peerB, Self.peerC]).matching(Self.peerB)
        #expect(matched.verdict(reachable: [Self.peerB]) == .closed(.converged))
        let unmatched = Self.opened().asking([Self.peerB, Self.peerC])
        #expect(unmatched.verdict(reachable: []) == .closed(.nothingOutstanding),
                "a window whose peers all left closes honestly, and says which closure it was")
    }

    /// **10.** Every set is bounded by the roster cap.
    @Test func everySetIsBoundedByTheRosterCap() {
        let cap = MeshMembershipBounds.maxRosterMembers
        let peers = (0..<(cap + 3)).map { "over-\($0)" }
        var window = Self.opened().asking(Set(peers))
        for peer in peers {
            window = window.answering(peer).matching(peer)
                .recording(Self.digest(0x22), from: peer)
        }
        #expect(window.asked.count <= cap)
        #expect(window.answered.count <= cap)
        #expect(window.matched.count <= cap)
        #expect(window.evidence.count <= cap)
    }

    /// **11.** A proof is sent once per distinct digest.
    @Test func aProofIsSentOncePerDistinctDigest() {
        let first = Self.digest(0x31)
        let second = Self.digest(0x32)
        let window = Self.opened()
        #expect(window.needsProof(of: first))
        let advertised = window.advertised(first)
        #expect(!advertised.needsProof(of: first), "the state already on the wire needs no frame")
        #expect(advertised.needsProof(of: second))
    }

    /// **12.** The proof cap is derived from the ledger's own bounds, equals the re-gossip budget,
    /// and cannot bite before the ledger is full.
    @Test func theProofCapIsDerivedAndCannotBiteBeforeTheLedgerIsFull() {
        #expect(MeshMergeWindow.maxProofs
                == MeshMembershipBounds.maxRecordsPerKind * 3
                + MeshMembershipBounds.maxTerminationRecords)
        #expect(MeshMergeWindow.maxProofs == MeshNetworkManager.maxReGossipFrames,
                "re-deriving the re-gossip budget must not silently leave the proof cap behind")
        var window = Self.opened()
        for index in 0..<MeshMergeWindow.maxProofs {
            window = window.advertised(Self.digest(UInt8(index % 251)))
        }
        #expect(!window.needsProof(of: Self.digest(0xFE)), "the budget is spent")
    }

    /// **13.** The role is derived from the sets, never stored.
    @Test func roleIsDerivedFromTheSets() {
        #expect(Self.opened().asking([Self.peerB]).role == .initiator)
        #expect(Self.opened().answering(Self.peerB).role == .responder)
        #expect(Self.opened().asking([Self.peerB]).answering(Self.peerB).role == .both)
        #expect(Self.opened().role == .idle)
    }

    /// **14.** `openedAt` is recorded and never branched on: two windows differing only in it give
    /// identical verdicts everywhere. The value-level proof that no timer exists.
    @Test func openedAtIsRecordedAndNeverBranchedOn() {
        let early = MeshMergeWindow.opened(at: Self.instant)
            .asking([Self.peerB, Self.peerC]).matching(Self.peerB)
        let late = MeshMergeWindow.opened(at: Self.instant.addingTimeInterval(86_400))
            .asking([Self.peerB, Self.peerC]).matching(Self.peerB)
        let sets: [Set<String>] = [[], [Self.peerB], [Self.peerC], [Self.peerB, Self.peerC]]
        for reachable in sets {
            #expect(early.verdict(reachable: reachable) == late.verdict(reachable: reachable))
        }
        #expect(early.openedAt != late.openedAt, "the instant is still recorded")
    }

    /// **15.** The closure and role vocabularies are frozen English tokens.
    @Test func theClosureVocabularyIsFrozenEnglish() {
        #expect(MeshMergeWindowClosure.allCases.map(\.rawValue)
                == ["converged", "nothingOutstanding"])
        #expect(MeshMergeWindowRole.initiator.rawValue == "initiator")
        #expect(MeshMergeWindowRole.responder.rawValue == "responder")
        #expect(MeshMergeWindowRole.both.rawValue == "both")
        #expect(MeshMergeWindowRole.idle.rawValue == "idle")
    }

    /// **15a.** The evidence is the window's own, bounded, and cannot pre-date it.
    @Test func evidenceIsWindowScopedAndBounded() {
        let local = Self.digest(0x41)
        let cap = MeshMembershipBounds.maxRosterMembers
        var recorded = Self.opened()
        for index in 0..<(cap + 3) { recorded = recorded.recording(local, from: "ev-\(index)") }
        #expect(recorded.evidence.count <= cap)
        let fresh = MeshMergeWindow.opened(at: Self.instant).asking([Self.peerB])
        #expect(fresh.reEvaluated(against: local, reachable: [Self.peerB])
                .verdict(reachable: [Self.peerB]) == .open(outstanding: 1),
                "a window with no evidence of its own matches nobody, whatever another window saw")
    }

    /// **39. The mechanical half of "recorded, never compared".** The value type holds no clock.
    @Test func theWindowTypeHasNoClock() throws {
        let source = try PackageRoot.source("Sources/ProximityKit/Mesh/MeshMergeWindow.swift")
        let code = MeshRoutedSourceScan.codeOnly(source)
        #expect(!code.contains("Date()"), "the manager supplies `now`; the window never reads a clock")
        #expect(!code.contains("timeIntervalSince"), "and never compares one")
    }
}
