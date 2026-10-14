import Foundation
import Testing
@testable import ProximityKit

// MARK: - MeshEpochModelTests
//
// P3 item 4 (plan §8.4): the epoch model, tier 1 and nothing else. No radio, no store, no wall
// clock — every instant here is a value the test states, matching the injected-now idiom the rest
// of the mesh's deterministic suites use.

// MARK: - MeshEpochRefTests

/// The value type: its canonical string, its bounds, and the one property the whole phase rests
/// on — that two divergent epochs at one counter are different values.
@Suite(.serialized)
struct MeshEpochRefTests {

    /// The string form round-trips exactly, and it is the form the introduction field carries.
    @Test func theCanonicalStringRoundTripsAndIsCanonical() throws {
        let ref = MeshEpochFixtures.ref(7)
        let text = ref.canonicalString
        let parsed = try MeshEpochRef(canonical: text)

        #expect(parsed == ref)
        #expect(parsed.canonicalString == text, "parsing then re-rendering must be the identity")
        #expect(text.hasPrefix("7."))
        #expect(text.hasSuffix(MeshEpochFixtures.coordinatorA))
        #expect(MeshEpochRef.isCanonical(text))
    }

    /// The whole reason the field cap was left at 96 in P2: a real ref fits it with room.
    @Test func everyRefFitsTheIntroductionField() {
        let widest = MeshEpochFixtures.ref(MeshEpochBounds.counterCap)
        #expect(widest.canonicalString.utf8.count <= MeshEpochBounds.canonicalStringMaxLength)
        #expect(MeshEpochBounds.canonicalStringMaxLength
                <= MeshChannelIntroductionFormat.maxEpochRefLength,
                "the canonical form outgrew the wire field — that is a wire decision, not a re-pin")
        #expect(MeshChannelIntroductionFormat.isAcceptableEpochRef(widest.canonicalString))
        #expect(MeshChannelIntroductionFormat.isAcceptableEpochRef(""), "empty means no epoch")
    }

    /// Two members of ONE branch derive the same id; two branches at one counter do not.
    /// This is the divergent-same-counter representability plan §8.4 asks for.
    @Test func divergentBranchesAtOneCounterAreDifferentValues() {
        let ours = MeshEpochFixtures.ref(7, coordinator: MeshEpochFixtures.coordinatorA)
        let alsoOurs = MeshEpochFixtures.ref(7, coordinator: MeshEpochFixtures.coordinatorA)
        let theirs = MeshEpochFixtures.ref(7, coordinator: MeshEpochFixtures.coordinatorB)

        #expect(ours == alsoOurs, "one branch must derive one id on every member")
        #expect(ours != theirs)
        #expect(ours.counter == theirs.counter, "and they genuinely share a counter")
        #expect(ours.epochID != theirs.epochID)

        // Same counter and coordinator, different mesh: still different.
        let elsewhere = MeshEpochFixtures.ref(7, meshID: MeshEpochFixtures.otherMeshID)
        #expect(ours != elsewhere)
    }

    /// Both divergent heads survive in the persisted head set, bounded and deterministically
    /// ordered. Coexistence is a state, not an error.
    @Test func bothDivergentHeadsAreRepresentableAndBounded() {
        let ours = MeshEpochFixtures.ref(7, coordinator: MeshEpochFixtures.coordinatorA)
        let theirs = MeshEpochFixtures.ref(7, coordinator: MeshEpochFixtures.coordinatorB)
        var heads = MeshEpochAcceptance.mergedHeads([], adding: ours)
        heads = MeshEpochAcceptance.mergedHeads(heads, adding: theirs)
        heads = MeshEpochAcceptance.mergedHeads(heads, adding: ours)

        #expect(heads.count == 2, "a divergent pair must both be heads, and neither duplicated")
        #expect(heads.contains(ours) && heads.contains(theirs))

        let cap = MeshSessionContextSchema.maxEpochHeads
        var many: [MeshEpochRef] = []
        for counter in 0..<UInt32(cap + 5) {
            many = MeshEpochAcceptance.mergedHeads(many, adding: MeshEpochFixtures.ref(counter))
        }
        #expect(many.count == cap)
        #expect(many.first?.counter == UInt32(cap + 4), "the newest heads are the ones kept")
    }

    /// The counter cap does not trap: it refuses, and the refusal is the documented "rotation
    /// refused / this session must terminate" answer.
    @Test func theCounterCapRefusesRatherThanTraps() {
        let atCap = MeshEpochFixtures.ref(MeshEpochBounds.counterCap)
        #expect(atCap.counter == MeshEpochBounds.counterCap)
        #expect(atCap.successor(
            coordinatorFingerprint: MeshEpochFixtures.coordinatorA, meshID: MeshEpochFixtures.meshID
        ) == nil, "a ref at the cap must refuse to mint a successor")
        #expect(MeshEpochRef.minted(
            counter: MeshEpochBounds.counterCap + 1,
            coordinatorFingerprint: MeshEpochFixtures.coordinatorA,
            meshID: MeshEpochFixtures.meshID
        ) == nil)
        let below = MeshEpochFixtures.ref(MeshEpochBounds.counterCap - 1)
        #expect(below.successor(
            coordinatorFingerprint: MeshEpochFixtures.coordinatorA, meshID: MeshEpochFixtures.meshID
        )?.counter == MeshEpochBounds.counterCap)
    }

    /// A non-canonical fingerprint cannot mint. Fingerprints are 16 lowercase hex, everywhere.
    @Test func aNonCanonicalCoordinatorCannotMint() {
        for bad in ["", "AA00000000000000", "0000000000000", "00000000000000zz", "0000000000000000a"] {
            #expect(MeshEpochRef.minted(
                counter: 3, coordinatorFingerprint: bad, meshID: MeshEpochFixtures.meshID
            ) == nil, "\(bad) minted an epoch")
        }
    }

    /// Every parse refusal names itself, and the parser is strict about canonical spelling.
    @Test func everyParseRefusalNamesItself() {
        let id = String(repeating: "0", count: MeshEpochBounds.epochIDHexLength)
        let fingerprint = MeshEpochFixtures.coordinatorA
        let table: [(String, MeshEpochRefParseError)] = [
            ("", .wrongFieldCount),
            ("7", .wrongFieldCount),
            ("7.\(id)", .wrongFieldCount),
            ("7.\(id).\(fingerprint).extra", .wrongFieldCount),
            ("07.\(id).\(fingerprint)", .malformedCounter),
            ("-1.\(id).\(fingerprint)", .malformedCounter),
            ("99999.\(id).\(fingerprint)", .malformedCounter),
            (" 7.\(id).\(fingerprint)", .malformedCounter),
            ("7.\(id.dropLast())Z.\(fingerprint)", .malformedEpochID),
            ("7.\(id.dropLast()).\(fingerprint)", .malformedEpochID),
            ("7.\(id).\(fingerprint.uppercased())", .malformedCoordinatorFingerprint),
            ("7.\(id).zz", .malformedCoordinatorFingerprint)
        ]
        for (text, expected) in table {
            #expect(throws: expected) { _ = try MeshEpochRef(canonical: text) }
            #expect(!MeshEpochRef.isCanonical(text))
        }
    }

    /// A counter over the cap is refused by NAME, so a diagnostic can say what it saw.
    @Test func anOverCapCounterIsRefusedByName() {
        let over = MeshEpochBounds.counterCap + 1
        #expect(throws: MeshEpochRefParseError.counterOverCap(over)) {
            _ = try MeshEpochRef(canonical: "\(over).00000000000000000000000000000000.00000000000000aa")
        }
    }

    /// The persisted form is the canonical string, so a head that is not one fails the decode.
    @Test func codableIsTheCanonicalStringAndValidatesOnDecode() throws {
        let ref = MeshEpochFixtures.ref(12)
        let encoded = try JSONEncoder().encode([ref])
        #expect(String(data: encoded, encoding: .utf8) == "[\"\(ref.canonicalString)\"]")
        #expect(try JSONDecoder().decode([MeshEpochRef].self, from: encoded) == [ref])

        let junk = Data("[\"epoch-1\"]".utf8)
        #expect(throws: (any Error).self) { _ = try JSONDecoder().decode([MeshEpochRef].self, from: junk) }
    }

    /// The head order is total, so two devices truncating the same set keep the same heads.
    @Test func theHeadOrderIsTotal() {
        let low = MeshEpochFixtures.ref(3)
        let high = MeshEpochFixtures.ref(4)
        let sibling = MeshEpochFixtures.ref(3, coordinator: MeshEpochFixtures.coordinatorB)

        #expect(MeshEpochRefOrder.precedes(low, high))
        #expect(!MeshEpochRefOrder.precedes(high, low))
        #expect(MeshEpochRefOrder.precedes(low, sibling), "coordinator breaks a counter tie")
        #expect(!MeshEpochRefOrder.precedes(sibling, low))
        #expect(!MeshEpochRefOrder.precedes(low, low), "irreflexive")
    }
}

// MARK: - MeshEpochKeyringTests

/// The bounded keyring: current + ≤ 3 predecessors, each ≤ 5 minutes of grace, injected clock.
@MainActor
@Suite(.serialized)
struct MeshEpochKeyringTests {

    /// A fresh keyring opens its own epoch and nothing else.
    @Test func aFreshKeyringOpensOnlyItsHead() {
        let head = MeshEpochFixtures.ref(1)
        let ring = MeshEpochKeyring(head: head, key: MeshEpochFixtures.key(1))

        #expect(ring.head == head)
        #expect(ring.key(for: head, at: MeshEpochFixtures.base)?.epoch == 1)
        #expect(!ring.canOpen(MeshEpochFixtures.ref(2), at: MeshEpochFixtures.base))
        #expect(ring.openableEpochs(at: MeshEpochFixtures.base) == [head])
    }

    /// A superseded key keeps working for exactly the grace window, then stops. Both edges pinned.
    @Test func aPredecessorWorksInsideGraceAndIsRejectedAfterIt() throws {
        var ring = MeshEpochKeyring(head: MeshEpochFixtures.ref(1), key: MeshEpochFixtures.key(1))
        let old = ring.head
        let now = MeshEpochFixtures.base
        try ring.rotate(to: MeshEpochFixtures.ref(2), key: MeshEpochFixtures.key(2), at: now)

        #expect(ring.canOpen(old, at: now), "the instant of supersession is inside grace")
        let lastGood = now.addingTimeInterval(MeshEpochBounds.predecessorGraceSeconds)
        #expect(ring.canOpen(old, at: lastGood), "the last instant of grace still opens")
        let justAfter = lastGood.addingTimeInterval(1)
        #expect(!ring.canOpen(old, at: justAfter), "one second past grace, the old key is rejected")
        #expect(ring.key(for: old, at: justAfter) == nil)
        #expect(ring.canOpen(ring.head, at: justAfter), "the head is unaffected by any grace")
        #expect(ring.openableEpochs(at: justAfter) == [ring.head])
    }

    /// The keyring holds current + 3 predecessors and no more, even when every one is in grace.
    @Test func theKeyringKeepsAtMostThreePredecessors() throws {
        var ring = MeshEpochKeyring(head: MeshEpochFixtures.ref(1), key: MeshEpochFixtures.key(1))
        for counter: UInt32 in 2...6 {
            try ring.rotate(
                to: MeshEpochFixtures.ref(counter),
                key: MeshEpochFixtures.key(counter),
                at: MeshEpochFixtures.base
            )
        }
        let openable = ring.openableEpochs(at: MeshEpochFixtures.base)

        #expect(ring.head == MeshEpochFixtures.ref(6))
        #expect(openable.count == MeshEpochBounds.keyringPredecessors + 1)
        let expected: [UInt32] = [6, 5, 4, 3]
        #expect(openable == expected.map { MeshEpochFixtures.ref($0) })
        #expect(!ring.canOpen(MeshEpochFixtures.ref(1), at: MeshEpochFixtures.base),
                "the oldest key must be gone on the cap, not merely on the clock")
    }

    /// Rotation refuses stale, identical and divergent epochs — each by name, leaving the ring
    /// untouched. A divergent branch never supersedes; it coexists (plan §8.4).
    @Test func rotationRefusalsAreNamedAndLeaveTheRingUntouched() throws {
        var ring = MeshEpochKeyring(head: MeshEpochFixtures.ref(5), key: MeshEpochFixtures.key(5))
        let table: [(MeshEpochRef, MeshEpochKeyringRotationRefusal)] = [
            (MeshEpochFixtures.ref(4), .staleCounter),
            (MeshEpochFixtures.ref(5), .alreadyCurrent),
            (MeshEpochFixtures.ref(5, coordinator: MeshEpochFixtures.coordinatorB), .divergentBranch)
        ]
        for (ref, expected) in table {
            #expect(throws: expected) {
                try ring.rotate(to: ref, key: MeshEpochFixtures.key(ref.counter), at: MeshEpochFixtures.base)
            }
            #expect(ring.head == MeshEpochFixtures.ref(5), "\(expected) moved the head")
            #expect(ring.openableEpochs(at: MeshEpochFixtures.base).count == 1)
        }
        try ring.rotate(to: MeshEpochFixtures.ref(9), key: MeshEpochFixtures.key(9), at: MeshEpochFixtures.base)
        #expect(ring.head.counter == 9, "continuity is not required: 5 → 9 with no 6, 7, 8")
    }

    /// Pruning drops expired predecessors; it never drops the head, and it is idempotent.
    @Test func pruningIsMemoryHygieneAndNeverTouchesTheHead() throws {
        var ring = MeshEpochKeyring(head: MeshEpochFixtures.ref(1), key: MeshEpochFixtures.key(1))
        try ring.rotate(to: MeshEpochFixtures.ref(2), key: MeshEpochFixtures.key(2), at: MeshEpochFixtures.base)
        let after = MeshEpochFixtures.base
            .addingTimeInterval(MeshEpochBounds.predecessorGraceSeconds + 1)

        ring.prune(at: after)
        ring.prune(at: after)

        #expect(ring.head == MeshEpochFixtures.ref(2))
        #expect(ring.openableEpochs(at: after) == [MeshEpochFixtures.ref(2)])
    }
}

// MARK: - MeshEpochAcceptanceTests

/// Plan §8.4's acceptance rule: who may rotate the head, what coexists, and the strict gate.
@Suite(.serialized)
struct MeshEpochAcceptanceTests {

    private static let roster = [
        MeshEpochFixtures.coordinatorA, MeshEpochFixtures.coordinatorB, "00000000000000cc"
    ]

    /// The plan's rule verbatim: the deterministic coordinator of the presented roster, with a
    /// strictly greater counter.
    @Test func aCoordinatorWithAGreaterCounterIsAccepted() {
        let verdict = MeshEpochAcceptance.rotationVerdict(
            local: MeshEpochFixtures.ref(4),
            presented: MeshEpochFixtures.ref(5),
            presentedRoster: Self.roster,
            presenterFingerprint: MeshEpochFixtures.coordinatorA
        )
        #expect(verdict == .accept)

        // Continuity is not required: 4 → 9 with nothing in between.
        #expect(MeshEpochAcceptance.rotationVerdict(
            local: MeshEpochFixtures.ref(4),
            presented: MeshEpochFixtures.ref(9),
            presentedRoster: Self.roster,
            presenterFingerprint: MeshEpochFixtures.coordinatorA
        ) == .accept)

        // A device with no epoch accepts the first one it is offered.
        #expect(MeshEpochAcceptance.rotationVerdict(
            local: nil,
            presented: MeshEpochFixtures.ref(5),
            presentedRoster: Self.roster,
            presenterFingerprint: MeshEpochFixtures.coordinatorA
        ) == .accept)
    }

    /// Same counter, different minting: neither supersedes. This is the answer a boolean cannot
    /// give, and the state P4's merge resolves.
    @Test func divergentSameCounterEpochsCoexist() {
        let ours = MeshEpochFixtures.ref(5, coordinator: MeshEpochFixtures.coordinatorA)
        let theirs = MeshEpochFixtures.ref(5, coordinator: MeshEpochFixtures.coordinatorB)
        let verdict = MeshEpochAcceptance.rotationVerdict(
            local: ours,
            presented: theirs,
            presentedRoster: [MeshEpochFixtures.coordinatorB, "00000000000000cc"],
            presenterFingerprint: MeshEpochFixtures.coordinatorB
        )
        #expect(verdict == .coexist)

        let heads = MeshEpochAcceptance.mergedHeads([ours], adding: theirs)
        #expect(heads.count == 2, "coexistence has to be representable, not just named")
    }

    /// Every refusal, by name: a non-member, a member that is not the lowest fingerprint, a
    /// coordinator that does not match the epoch it presents, an out-of-bounds roster, a stale
    /// counter, and an idempotent re-delivery.
    @Test func everyRotationRefusalNamesItself() {
        let local = MeshEpochFixtures.ref(5)
        let table: [(MeshEpochRef, [String], String, MeshEpochRotationRefusal)] = [
            (MeshEpochFixtures.ref(6), Self.roster, "00000000000000dd", .presenterNotInPresentedRoster),
            (MeshEpochFixtures.ref(6, coordinator: MeshEpochFixtures.coordinatorB),
             Self.roster, MeshEpochFixtures.coordinatorB, .presenterIsNotTheCoordinator),
            (MeshEpochFixtures.ref(6, coordinator: MeshEpochFixtures.coordinatorB),
             Self.roster, MeshEpochFixtures.coordinatorA, .presenterIsNotTheCoordinator),
            (MeshEpochFixtures.ref(6), [], MeshEpochFixtures.coordinatorA, .presentedRosterOutOfBounds),
            (MeshEpochFixtures.ref(4), Self.roster, MeshEpochFixtures.coordinatorA, .staleCounter),
            (MeshEpochFixtures.ref(5), Self.roster, MeshEpochFixtures.coordinatorA, .alreadyCurrent)
        ]
        for (presented, roster, presenter, expected) in table {
            let verdict = MeshEpochAcceptance.rotationVerdict(
                local: local, presented: presented,
                presentedRoster: roster, presenterFingerprint: presenter
            )
            #expect(verdict == .reject(expected))
            #expect(!expected.diagnosticDescription.isEmpty)
        }

        let oversized = (0..<(MeshMembershipBounds.maxRosterMembers + 1)).map { "0000000000000\(String(format: "%03x", $0))" }
        #expect(MeshEpochAcceptance.rotationVerdict(
            local: local, presented: MeshEpochFixtures.ref(6),
            presentedRoster: oversized, presenterFingerprint: oversized[0]
        ) == .reject(.presentedRosterOutOfBounds))
    }

    /// The strict introduction gate, on every axis it got stricter (plan §20.1).
    @Test func theIntroductionGateIsStrict() {
        let ours = MeshEpochFixtures.ref(7).canonicalString
        let theirs = MeshEpochFixtures.ref(7, coordinator: MeshEpochFixtures.coordinatorB).canonicalString
        let later = MeshEpochFixtures.ref(9).canonicalString

        #expect(MeshEpochAcceptance.introductionVerdict(local: "", peer: "") == .converge(nil))
        #expect(MeshEpochAcceptance.introductionVerdict(local: ours, peer: ours)
                == .converge(MeshEpochFixtures.ref(7)))
        #expect(MeshEpochAcceptance.introductionVerdict(local: "", peer: ours)
                == .converge(MeshEpochFixtures.ref(7)), "a joiner adopts a well-formed peer epoch")
        #expect(MeshEpochAcceptance.introductionVerdict(local: ours, peer: "")
                == .converge(MeshEpochFixtures.ref(7)))

        // 1. Junk is malformed, even opposite an empty side — the old rule waved it through.
        for junk in ["7", "9", "epoch-1", "7.x.y"] {
            #expect(MeshEpochAcceptance.introductionVerdict(local: "", peer: junk) == .malformed)
            #expect(MeshEpochAcceptance.introductionVerdict(local: junk, peer: "") == .malformed)
        }
        // 2. Two branches wearing one counter are now seen — and, since P4 item 3, NAMED rather
        //    than refused: the merge that reconciles them runs over the tunnel this used to tear
        //    down. Both heads come back, so nothing about the divergence is lost in the answer.
        #expect(MeshEpochAcceptance.introductionVerdict(local: ours, peer: theirs)
                == .reconcile(local: MeshEpochFixtures.ref(7),
                              peer: MeshEpochFixtures.ref(7, coordinator: MeshEpochFixtures.coordinatorB)))
        // 3. Different counters reconcile too — plan §10.3 mints `max + 1` over both.
        #expect(MeshEpochAcceptance.introductionVerdict(local: ours, peer: later)
                == .reconcile(local: MeshEpochFixtures.ref(7), peer: MeshEpochFixtures.ref(9)))
    }
}

// MARK: - MeshFrameReplayWindowTests

/// Replay protection, moved OFF epochs (plan §8.4): dedup by frame id, per authenticated sender.
@Suite(.serialized)
struct MeshFrameReplayWindowTests {

    private static let meshID = MeshEpochFixtures.meshID
    private static let expiry = MeshEpochFixtures.base.addingTimeInterval(600)

    /// The core claim of the move: a replayed frame is refused because its ID was seen, and that
    /// answer does not change when the epoch does — in either direction.
    @Test func aReplayedFrameIsRejectedIndependentlyOfTheEpoch() {
        var window = MeshFrameReplayWindow(meshID: Self.meshID)
        let frame = UUID()
        let sender = MeshEpochFixtures.coordinatorA

        // Epoch 3 is current when the frame first arrives.
        var ring = MeshEpochKeyringHolder(counter: 3)
        #expect(window.admit(frameID: frame, from: sender, meshID: Self.meshID,
                             expiresAt: Self.expiry, now: MeshEpochFixtures.base) == .admitted)
        #expect(window.admit(frameID: frame, from: sender, meshID: Self.meshID,
                             expiresAt: Self.expiry, now: MeshEpochFixtures.base) == .replayed)

        // Rotate the epoch. The frame is still a replay, and a fresh id is still admitted —
        // neither answer came from the epoch.
        ring.rotate(to: 4)
        #expect(window.admit(frameID: frame, from: sender, meshID: Self.meshID,
                             expiresAt: Self.expiry, now: MeshEpochFixtures.base) == .replayed)
        #expect(window.admit(frameID: UUID(), from: sender, meshID: Self.meshID,
                             expiresAt: Self.expiry, now: MeshEpochFixtures.base) == .admitted)
        #expect(ring.counter == 4)
    }

    /// One sender's history is its own: two members may legitimately present the same id.
    @Test func windowsArePerAuthenticatedSender() {
        var window = MeshFrameReplayWindow(meshID: Self.meshID)
        let frame = UUID()

        #expect(window.admit(frameID: frame, from: MeshEpochFixtures.coordinatorA, meshID: Self.meshID,
                             expiresAt: Self.expiry, now: MeshEpochFixtures.base) == .admitted)
        #expect(window.admit(frameID: frame, from: MeshEpochFixtures.coordinatorB, meshID: Self.meshID,
                             expiresAt: Self.expiry, now: MeshEpochFixtures.base) == .admitted)
        #expect(window.trackedSenderCount == 2)

        window.forget(senderFingerprint: MeshEpochFixtures.coordinatorA)
        #expect(window.recordedCount(for: MeshEpochFixtures.coordinatorA) == 0)
        #expect(window.recordedCount(for: MeshEpochFixtures.coordinatorB) == 1)
    }

    /// Expiry, foreign mesh and the per-sender cap each name themselves, and none of them records
    /// anything — an expired or foreign frame must not consume a slot an honest one could use.
    @Test func everyReplayRefusalNamesItselfAndRecordsNothing() {
        var window = MeshFrameReplayWindow(meshID: Self.meshID)
        let sender = MeshEpochFixtures.coordinatorA
        let late = Self.expiry.addingTimeInterval(1)

        #expect(window.admit(frameID: UUID(), from: sender, meshID: Self.meshID,
                             expiresAt: Self.expiry, now: late) == .expired)
        #expect(window.admit(frameID: UUID(), from: sender, meshID: MeshEpochFixtures.otherMeshID,
                             expiresAt: Self.expiry, now: MeshEpochFixtures.base) == .foreignMesh)
        #expect(window.recordedCount(for: sender) == 0)

        for _ in 0..<MeshFrameReplayWindow.maxFramesPerSender {
            _ = window.admit(frameID: UUID(), from: sender, meshID: Self.meshID,
                             expiresAt: Self.expiry, now: MeshEpochFixtures.base)
        }
        #expect(window.recordedCount(for: sender) == MeshFrameReplayWindow.maxFramesPerSender)
        #expect(window.admit(frameID: UUID(), from: sender, meshID: Self.meshID,
                             expiresAt: Self.expiry, now: MeshEpochFixtures.base) == .senderWindowFull,
                "the cap refuses rather than evicting — an LRU would let a flood erase history")
    }

    /// The sender cap is the roster cap; a ninth sender is refused rather than admitted.
    @Test func theSenderCapIsTheRosterCap() {
        var window = MeshFrameReplayWindow(meshID: Self.meshID)
        for index in 0..<MeshFrameReplayWindow.maxSenders {
            let sender = String(format: "00000000000000%02x", index)
            #expect(window.admit(frameID: UUID(), from: sender, meshID: Self.meshID,
                                 expiresAt: Self.expiry, now: MeshEpochFixtures.base) == .admitted)
        }
        #expect(window.trackedSenderCount == MeshFrameReplayWindow.maxSenders)
        #expect(window.admit(frameID: UUID(), from: "0000000000000fff", meshID: Self.meshID,
                             expiresAt: Self.expiry, now: MeshEpochFixtures.base) == .senderWindowFull)
    }

    // MARK: - P5 item 12: the routed instance's two axes

    /// **The arithmetic the routed wiring rests on.** One maximal item's whole frame family — 1024
    /// chunk ids plus its manifest — fits on ONE author's axis at the routed frame cap, so the 65th
    /// chunk of a 16 MiB item is ordinary traffic rather than the `senderWindowFull` the pre-item-12
    /// static would have answered.
    @Test func aMaximalItemsFramesAllFitOneAuthorsAxis() {
        var window = MeshFrameReplayWindow(
            meshID: Self.meshID, framesPerSender: MeshRoutedDrainBounds.sessionFramesPerPeer
        )
        let author = MeshEpochFixtures.coordinatorA
        var refusals = 0
        // R2: bounded by the chunk format's own maximal item, plus its manifest.
        for _ in 0...MeshChunkFormat.maxChunkCount {
            let verdict = window.admit(frameID: UUID(), from: author, meshID: Self.meshID,
                                       expiresAt: Self.expiry, now: MeshEpochFixtures.base)
            if verdict != .admitted { refusals += 1 }
        }
        #expect(refusals == 0, "a maximal item's frame family did not fit one author's axis")
        #expect(window.recordedCount(for: author) == MeshChunkFormat.maxChunkCount + 1)
        #expect(MeshRoutedDrainBounds.sessionFramesPerPeer >= MeshChunkFormat.maxChunkCount + 1,
                "the frame cap must carry a maximal item plus its manifest")
    }

    /// **The keying, from the other direction.** `MeshChunk.chunkID` deliberately omits the origin,
    /// so two origins can present the identical id for the same `(itemID, index)` — and both are
    /// admitted, because the window's own axis is the author.
    @Test func twoOriginsMayPresentTheSameChunkID() {
        var window = MeshFrameReplayWindow(meshID: Self.meshID)
        let shared = MeshRoutedContentDigest.chunkID(itemID: Self.meshID, chunkIndex: 7)

        #expect(window.admit(frameID: shared, from: MeshEpochFixtures.coordinatorA,
                             meshID: Self.meshID, expiresAt: Self.expiry,
                             now: MeshEpochFixtures.base) == .admitted)
        #expect(window.admit(frameID: shared, from: MeshEpochFixtures.coordinatorB,
                             meshID: Self.meshID, expiresAt: Self.expiry,
                             now: MeshEpochFixtures.base) == .admitted)
        #expect(window.admit(frameID: shared, from: MeshEpochFixtures.coordinatorA,
                             meshID: Self.meshID, expiresAt: Self.expiry,
                             now: MeshEpochFixtures.base) == .replayed)
    }

    /// A per-instance frame cap still refuses rather than growing — the bound holds under a hostile
    /// author however the instance is sized.
    @Test func aFullAuthorAxisRefusesRatherThanGrowing() {
        var window = MeshFrameReplayWindow(meshID: Self.meshID, framesPerSender: 4)
        let author = MeshEpochFixtures.coordinatorA
        // R2: the instance's own cap.
        for _ in 0..<4 {
            #expect(window.admit(frameID: UUID(), from: author, meshID: Self.meshID,
                                 expiresAt: Self.expiry, now: MeshEpochFixtures.base) == .admitted)
        }
        #expect(window.admit(frameID: UUID(), from: author, meshID: Self.meshID,
                             expiresAt: Self.expiry, now: MeshEpochFixtures.base) == .senderWindowFull)
        #expect(window.recordedCount(for: author) == 4, "a refusal must not grow the axis")
    }

    /// And one full author leaves every other author's axis untouched — the whole point of keying
    /// per author rather than per session.
    @Test func aFullAuthorAxisLeavesOtherAuthorsUnaffected() {
        var window = MeshFrameReplayWindow(meshID: Self.meshID, framesPerSender: 4)
        // R2: the instance's own cap, plus the one that overflows it.
        for _ in 0..<5 {
            _ = window.admit(frameID: UUID(), from: MeshEpochFixtures.coordinatorA,
                             meshID: Self.meshID, expiresAt: Self.expiry, now: MeshEpochFixtures.base)
        }
        #expect(window.admit(frameID: UUID(), from: MeshEpochFixtures.coordinatorB,
                             meshID: Self.meshID, expiresAt: Self.expiry,
                             now: MeshEpochFixtures.base) == .admitted)
    }

    /// **The routed author population is the ADMISSION set, not the derived roster.** Every routed
    /// verifier resolves its author's key from `ledger.admissions.all`, whose capacity is
    /// `maxRecordsPerKind`; the roster cap of 8 is tighter, and a departed origin — whose content
    /// stays valid and keeps moving under custody transfer — is not a roster member at all. At the
    /// roster cap the 9th author's every frame would answer `senderWindowFull` and never be caught
    /// on repeat, which is the defence silently off for exactly that traffic.
    @Test func theAuthorAxisIsTheAdmissionCapNotTheRosterCap() {
        var window = MeshFrameReplayWindow(
            meshID: Self.meshID, maxSenders: MeshMembershipBounds.maxRecordsPerKind
        )
        let frame = UUID()
        // R2: bounded by the admission-set capacity.
        for index in 0..<MeshMembershipBounds.maxRecordsPerKind {
            let author = String(format: "00000000000000%02x", index)
            #expect(window.admit(frameID: frame, from: author, meshID: Self.meshID,
                                 expiresAt: Self.expiry, now: MeshEpochFixtures.base) == .admitted)
        }
        let ninth = String(format: "00000000000000%02x", MeshMembershipBounds.maxRosterMembers)
        #expect(window.admit(frameID: frame, from: ninth, meshID: Self.meshID,
                             expiresAt: Self.expiry, now: MeshEpochFixtures.base) == .replayed,
                "an author one past the ROSTER cap must still be tracked, and its repeat caught")
        #expect(window.admit(frameID: UUID(), from: "0000000000000fff", meshID: Self.meshID,
                             expiresAt: Self.expiry, now: MeshEpochFixtures.base) == .senderWindowFull,
                "and the axis past the ADMISSION cap is where the refusal lands")
        #expect(MeshMembershipBounds.maxRecordsPerKind >= MeshMembershipBounds.maxRosterMembers)
    }

    /// **The one thing the store can give back.** A chunk repair drops a slot and a peer re-offers
    /// that exact chunk under the identical derived id, so the id must be un-recordable — and the
    /// author's axis must survive it, because releasing an axis is the eviction primitive this type
    /// refuses to offer.
    @Test func aForgottenFrameIsReAdmittableAndKeepsItsAuthorsAxis() {
        var window = MeshFrameReplayWindow(meshID: Self.meshID)
        let author = MeshEpochFixtures.coordinatorA
        let slot = MeshRoutedContentDigest.chunkID(itemID: Self.meshID, chunkIndex: 3)
        let other = UUID()
        _ = window.admit(frameID: slot, from: author, meshID: Self.meshID,
                         expiresAt: Self.expiry, now: MeshEpochFixtures.base)
        _ = window.admit(frameID: other, from: author, meshID: Self.meshID,
                         expiresAt: Self.expiry, now: MeshEpochFixtures.base)

        window.forget(frameID: slot, from: author)

        #expect(window.admit(frameID: slot, from: author, meshID: Self.meshID,
                             expiresAt: Self.expiry, now: MeshEpochFixtures.base) == .admitted)
        #expect(window.admit(frameID: other, from: author, meshID: Self.meshID,
                             expiresAt: Self.expiry, now: MeshEpochFixtures.base) == .replayed,
                "forgetting one id must not clear the author's whole history")
    }
}

// MARK: - MeshEpochKeyringHolder

/// A one-field stand-in for "the epoch moved", so the replay suite can rotate an epoch without
/// pulling the MainActor-isolated keyring into a nonisolated suite. The point of the test is that
/// the replay window never consults it.
private struct MeshEpochKeyringHolder {

    /// The counter this holder is on.
    private(set) var counter: UInt32

    /// Starts on one counter.
    init(counter: UInt32) { self.counter = counter }

    /// Moves to another counter.
    mutating func rotate(to next: UInt32) { counter = next }
}
