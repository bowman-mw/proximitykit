// MeshRotationTriggerTests.swift
// ProximityKitTests
//
// P3 item 5 (plan §8.3, §8.4): membership-driven rotation.
//
// The claims worth walling here are the ones the phase rests on:
//
// 1. **Every trigger fires exactly one rotation, with the right cause token.** Timer, roster change
//    and merge each rotate; a burst of records rotates once; nothing rotates while a rotation is in
//    flight.
// 2. **A voted-out member does not get the next key.** This is the confirmed gap the item exists to
//    close — before it, a removed member kept the group key until the next 15-minute tick.
// 3. **An old key stops working at a stated moment**, five minutes after it was superseded, not
//    whenever the last reference goes away.
// 4. **Durable before acknowledged (plan §3.6).** A save the sealed store refuses abandons the
//    rotation and names why; it does not distribute a key nobody could write down.
// 5. **The counter cap ends the session rather than trapping** (plan §8.4).
//
// The pure suites state every instant as a value (the injected-now idiom `MeshEpochKeyring` and
// `MeshRotationTriggerQueue` share). The manager suite drives the real rotation entry point with
// the debounce window bypassed, because a two-second wall-clock sleep in a test is a flake waiting
// for a loaded runner.
//
// A copy (ProximityKit plan step A1, the split's first and third batches of copied suites): of the
// Fernlet repository's FernletTests file of the same name, this holds every suite, with its name and
// tests unchanged: `MeshRotationTriggerQueueTests`, `MeshRotationPolicyTests`,
// `MeshKeyRotationCauseWireTests` and `MeshEpochGraceTests`, and, since the third batch (the suites
// that reach the keychain and open a store), `MeshRotationManagerTests`, over a package host whose
// install binding its cells switch.

import Foundation
import Testing
@testable import ProximityKit

// MARK: - MeshRotationTriggerQueueTests

/// Plan §8.3's trigger set: 15-minute timer ∪ any roster change ∪ any merge, coalesced and
/// non-reentrant.
///
/// `@MainActor` because the queue is: it is owned by `MeshNetworkManager` and inherits the module's
/// default isolation. Its clock is still injected, so nothing here waits.
@MainActor
@Suite(.serialized)
struct MeshRotationTriggerQueueTests {

    /// The instant every case measures from. Nothing here reads a wall clock.
    private let base = Date(timeIntervalSince1970: 1_800_000_000)

    /// One trigger, one rotation, and the window is honoured on both sides of its edge.
    @Test func oneTriggerSchedulesExactlyOneRotation() {
        var queue = MeshRotationTriggerQueue()
        let outcome = queue.request(.timer, at: base)

        let window = MeshRotationTriggerBounds.debounceWindowSeconds
        #expect(outcome == .scheduled(at: base.addingTimeInterval(window), cause: .timer))
        #expect(queue.claim(at: base.addingTimeInterval(window - 0.001)) == nil,
                "the window must not be claimable before it elapses")
        #expect(queue.claim(at: base.addingTimeInterval(window)) == .timer)
        #expect(queue.isRotating)

        _ = queue.finish(at: base.addingTimeInterval(window))
        #expect(queue.claim(at: base.addingTimeInterval(window + 60)) == nil,
                "one trigger must not be claimable twice")
    }

    /// Each of the three causes fires, and each carries its own token.
    @Test func everyCauseFiresWithItsOwnToken() {
        let window = MeshRotationTriggerBounds.debounceWindowSeconds
        for cause in MeshKeyRotationCause.allCases {
            var queue = MeshRotationTriggerQueue()
            #expect(queue.request(cause, at: base) == .scheduled(at: base.addingTimeInterval(window), cause: cause))
            #expect(queue.claim(at: base.addingTimeInterval(window)) == cause)
        }
    }

    /// A burst of records inside one window rotates ONCE — the debounce this item promises.
    @Test func aBurstOfRecordsRotatesOnce() {
        var queue = MeshRotationTriggerQueue()
        let window = MeshRotationTriggerBounds.debounceWindowSeconds
        let target = base.addingTimeInterval(window)

        #expect(queue.request(.membership, at: base) == .scheduled(at: target, cause: .membership))
        for offset in [0.1, 0.5, 1.9] {
            #expect(queue.request(.membership, at: base.addingTimeInterval(offset))
                    == .coalesced(at: target, cause: .membership),
                    "a second record inside the window must fold in, never open a second window")
        }
        #expect(queue.claim(at: target) == .membership)
        _ = queue.finish(at: target)
        #expect(queue.claim(at: target.addingTimeInterval(window)) == nil, "the burst rotated once")
    }

    /// When causes coalesce the most specific one is what reaches the wire.
    @Test func theHighestRankedCauseWinsACoalescedBurst() {
        var ascending = MeshRotationTriggerQueue()
        _ = ascending.request(.timer, at: base)
        _ = ascending.request(.membership, at: base)
        _ = ascending.request(.merge, at: base)
        #expect(ascending.claim(at: base.addingTimeInterval(9)) == .merge)

        var descending = MeshRotationTriggerQueue()
        _ = descending.request(.merge, at: base)
        _ = descending.request(.timer, at: base)
        #expect(descending.claim(at: base.addingTimeInterval(9)) == .merge,
                "a later timer must not demote a merge that is already pending")
    }

    /// A rotation never runs while one is in flight — the trigger is deferred, never dropped.
    @Test func nothingRotatesWhileARotationIsInFlight() {
        var queue = MeshRotationTriggerQueue()
        _ = queue.request(.timer, at: base)
        #expect(queue.claim(at: base.addingTimeInterval(9)) == .timer)

        let during = base.addingTimeInterval(10)
        #expect(queue.request(.membership, at: during) == .queuedBehindInFlight(cause: .membership))
        #expect(queue.claim(at: during) == nil, "a second rotation must not start mid-rotation")

        let outcome = queue.finish(at: during)
        let window = MeshRotationTriggerBounds.debounceWindowSeconds
        #expect(outcome == .scheduled(at: during.addingTimeInterval(window), cause: .membership),
                "a trigger raised mid-rotation must be re-armed, not lost")
        #expect(queue.claim(at: during.addingTimeInterval(window)) == .membership)
    }

    /// Finishing with nothing deferred arms nothing, and a reset forgets everything.
    @Test func finishingCleanArmsNothingAndResetForgets() {
        var queue = MeshRotationTriggerQueue()
        _ = queue.request(.timer, at: base)
        _ = queue.claim(at: base.addingTimeInterval(9))
        #expect(queue.finish(at: base.addingTimeInterval(9)) == nil)

        _ = queue.request(.merge, at: base)
        queue.reset()
        #expect(queue.pendingCause == nil)
        #expect(queue.firesAt == nil)
        #expect(!queue.isRotating)
        #expect(queue.claim(at: base.addingTimeInterval(600)) == nil)
    }
}

// MARK: - MeshRotationPolicyTests

/// The two pure decisions: which epoch comes next, and who gets its key.
@Suite(.serialized)
struct MeshRotationPolicyTests {

    private typealias Fixture = MeshMembershipFixtures

    private let meshID = MeshEpochFixtures.meshID
    private let coordinator = MeshEpochFixtures.coordinatorA
    private let other = MeshEpochFixtures.coordinatorB

    /// The coordinator of the roster it presents plans the strict successor of its own head.
    @Test func theCoordinatorPlansTheStrictSuccessor() {
        let head = MeshEpochFixtures.ref(4)
        let plan = MeshRotationPolicy.plan(
            head: head,
            coordinatorFingerprint: coordinator,
            meshID: meshID,
            presentedRoster: [coordinator, other]
        )
        #expect(plan == .rotate(MeshEpochFixtures.ref(5)))
    }

    /// A device with no epoch yet mints counter 1 rather than refusing.
    @Test func aDeviceWithNoEpochMintsTheFirstOne() {
        let plan = MeshRotationPolicy.plan(
            head: nil,
            coordinatorFingerprint: coordinator,
            meshID: meshID,
            presentedRoster: [coordinator]
        )
        #expect(plan == .rotate(MeshEpochFixtures.ref(1)))
    }

    /// Plan §8.4's counter cap: the session ENDS, and nothing traps on the way there.
    @Test func theCounterCapTerminatesRatherThanTraps() {
        let plan = MeshRotationPolicy.plan(
            head: MeshEpochFixtures.ref(MeshEpochBounds.counterCap),
            coordinatorFingerprint: coordinator,
            meshID: meshID,
            presentedRoster: [coordinator]
        )
        #expect(plan == .terminate)
    }

    /// A device that is not the lowest fingerprint of the roster it presents refuses BY NAME —
    /// the same test every receiver applies to an arriving rotation.
    @Test func aNonCoordinatorRefusesItsOwnRotationByName() {
        let plan = MeshRotationPolicy.plan(
            head: MeshEpochFixtures.ref(2, coordinator: other),
            coordinatorFingerprint: other,
            meshID: meshID,
            presentedRoster: [coordinator, other]
        )
        #expect(plan == .refuse(.epochAcceptance(.presenterIsNotTheCoordinator)))

        let outOfRoster = MeshRotationPolicy.plan(
            head: nil, coordinatorFingerprint: coordinator, meshID: meshID, presentedRoster: [other]
        )
        #expect(outOfRoster == .refuse(.epochAcceptance(.presenterNotInPresentedRoster)))

        let empty = MeshRotationPolicy.plan(
            head: nil, coordinatorFingerprint: coordinator, meshID: meshID, presentedRoster: []
        )
        #expect(empty == .refuse(.epochAcceptance(.presentedRosterOutOfBounds)))
    }

    /// A non-canonical fingerprint cannot mint, and the refusal says so rather than terminating.
    @Test func aNonCanonicalCoordinatorRefusesRatherThanTerminates() {
        let plan = MeshRotationPolicy.plan(
            head: nil, coordinatorFingerprint: "NOT-HEX", meshID: meshID, presentedRoster: ["NOT-HEX"]
        )
        #expect(plan == .refuse(.coordinatorFingerprintNotCanonical))
    }

    /// **The gap this item closes.** A voted-out member — one with a verified removal record — is
    /// not in the next epoch's key distribution, even though it acked the drain.
    @Test func aRemovedMemberIsExcludedFromTheNextKey() {
        var ledger = Fixture.ledger(admitting: [1, 2, 3])
        ledger.removals = ledger.removals.inserting(Fixture.removal(3))
        let roster = ledger.derivedRoster

        let recipients = MeshRotationPolicy.recipients(
            acked: [Fixture.fingerprint(2), Fixture.fingerprint(3)],
            selfFingerprint: Fixture.fingerprint(1),
            derivedRoster: roster,
            locallyRemoved: []
        )
        #expect(!recipients.contains(Fixture.fingerprint(3)), "a removed member must get no key")
        #expect(recipients == [Fixture.fingerprint(1), Fixture.fingerprint(2)])
    }

    /// A departed member is excluded on the same rule.
    @Test func aDepartedMemberIsExcludedFromTheNextKey() {
        var ledger = Fixture.ledger(admitting: [1, 2])
        ledger.departures = ledger.departures.inserting(Fixture.departure(2))

        let recipients = MeshRotationPolicy.recipients(
            acked: [Fixture.fingerprint(2)],
            selfFingerprint: Fixture.fingerprint(1),
            derivedRoster: ledger.derivedRoster,
            locallyRemoved: []
        )
        #expect(recipients == [Fixture.fingerprint(1)])
    }

    /// The live vote-out set excludes a member before its signed record has reached any ledger —
    /// which is the state the shipping build is in until item 7 fills the ledger.
    @Test func aLocallyVotedOutMemberIsExcludedWithNoLedgerAtAll() {
        let recipients = MeshRotationPolicy.recipients(
            acked: ["fp-a", "fp-b"],
            selfFingerprint: "fp-self",
            derivedRoster: nil,
            locallyRemoved: ["fp-b"]
        )
        #expect(recipients == ["fp-self", "fp-a"])
    }

    /// With no ledger and nobody voted out the rule is a pass-through plus self: the exclusion is
    /// subtractive, so an empty ledger can never mean "distribute to nobody".
    @Test func anEmptyLedgerNeverStarvesTheDistribution() {
        let recipients = MeshRotationPolicy.recipients(
            acked: ["fp-a", "fp-b"], selfFingerprint: "fp-self", derivedRoster: nil, locallyRemoved: []
        )
        #expect(recipients == ["fp-self", "fp-a", "fp-b"])

        let alone = MeshRotationPolicy.recipients(
            acked: [], selfFingerprint: "fp-self", derivedRoster: nil, locallyRemoved: []
        )
        #expect(alone == ["fp-self"], "the coordinator always wraps the key for itself")
    }

    /// Once the ledger knows a roster the rule TIGHTENS: an acking fingerprint that is on no
    /// roster at all gets nothing.
    @Test func aKnownRosterNarrowsTheRecipientsToItsMembers() {
        let ledger = Fixture.ledger(admitting: [1, 2])
        let recipients = MeshRotationPolicy.recipients(
            acked: [Fixture.fingerprint(2), "fp-stranger"],
            selfFingerprint: Fixture.fingerprint(1),
            derivedRoster: ledger.derivedRoster,
            locallyRemoved: []
        )
        #expect(recipients == [Fixture.fingerprint(1), Fixture.fingerprint(2)])
    }
}

// MARK: - MeshKeyRotationCauseWireTests

/// The `cause` token on the wire: frozen English, pinned bytes, and a legacy frame that still
/// decodes.
@Suite(.serialized)
struct MeshKeyRotationCauseWireTests {

    /// The pinned encoding of an extended rotation frame.
    ///
    /// **A new vector, not a moved one.** `meshKeyRotation` is unsigned — it rides the signed
    /// `ProximityIdentityEnvelope` — so it had no canonical serializer and no golden before this
    /// item, and adding `cause` moved no signature transcript. Nothing in
    /// `PeerHandleWireGoldenTests` or `MeshMembershipEventWireTests` changes.
    private static let goldenJSON = """
        {"cause":"membership","coordinatorFingerprint":"00000000000000aa","newEpoch":7,\
        "perMember":{"fp0001":"AQID"},"rotationInitiatedAt":800000000}
        """

    private func payload(cause: MeshKeyRotationCause) -> MeshKeyRotationPayload {
        MeshKeyRotationPayload(
            newEpoch: 7,
            perMember: ["fp0001": Data([0x01, 0x02, 0x03])],
            rotationInitiatedAt: Date(timeIntervalSinceReferenceDate: 800_000_000),
            coordinatorFingerprint: MeshEpochFixtures.coordinatorA,
            cause: cause
        )
    }

    private func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }

    /// The three tokens are frozen English and there are exactly three of them.
    @Test func theCauseTokensAreFrozenEnglish() {
        #expect(MeshKeyRotationCause.timer.rawValue == "timer")
        #expect(MeshKeyRotationCause.membership.rawValue == "membership")
        #expect(MeshKeyRotationCause.merge.rawValue == "merge")
        #expect(MeshKeyRotationCause.allCases.count == 3)
    }

    /// The extended frame's bytes are pinned.
    @Test func theExtendedFramePinsItsBytes() throws {
        let actual = String(decoding: try encoder().encode(payload(cause: .membership)), as: UTF8.self)
        #expect(actual == Self.goldenJSON, "actual rotation JSON = \(actual)")
    }

    /// Every cause round-trips, and the field is genuinely on the wire.
    @Test func everyCauseRoundTrips() throws {
        for cause in MeshKeyRotationCause.allCases {
            let bytes = try encoder().encode(payload(cause: cause))
            let decoded = try JSONDecoder().decode(MeshKeyRotationPayload.self, from: bytes)
            #expect(decoded.cause == cause)
            #expect(decoded == payload(cause: cause))
            #expect(String(decoding: bytes, as: UTF8.self).contains("\"\(cause.rawValue)\""))
        }
    }

    /// A frame from a build with no `cause` field decodes as `timer` — the only rotation those
    /// builds ever performed — rather than failing the decode and stranding the member.
    @Test func aFrameWithoutACauseDecodesAsTimer() throws {
        let legacy = """
            {"coordinatorFingerprint":"00000000000000aa","newEpoch":7,\
            "perMember":{"fp0001":"AQID"},"rotationInitiatedAt":800000000}
            """
        let decoded = try JSONDecoder().decode(
            MeshKeyRotationPayload.self, from: Data(legacy.utf8)
        )
        #expect(decoded.cause == .timer)
        #expect(decoded.newEpoch == 7)
    }

    /// An unrecognised cause from a future build is read as `timer` too: a member must still be
    /// able to adopt a key it can otherwise read.
    @Test func anUnknownCauseDoesNotBreakTheDecode() throws {
        let future = """
            {"cause":"ceiling","coordinatorFingerprint":"00000000000000aa","newEpoch":7,\
            "perMember":{},"rotationInitiatedAt":800000000}
            """
        let decoded = try JSONDecoder().decode(MeshKeyRotationPayload.self, from: Data(future.utf8))
        #expect(decoded.cause == .timer)
    }
}

// MARK: - MeshEpochGraceTests

/// The other half of the exclusion: a member cut out of the new epoch keeps reading old-key frames
/// for the grace window, and not one second longer.
@MainActor
@Suite(.serialized)
struct MeshEpochGraceTests {

    /// After the ≤ 5-minute grace, the superseded epoch's key is gone — there is no fallback path
    /// and no "try it anyway".
    @Test func anOldKeyIsRejectedAfterTheGrace() throws {
        let old = MeshEpochFixtures.ref(1)
        let new = MeshEpochFixtures.ref(2)
        let rotatedAt = MeshEpochFixtures.base
        var keyring = MeshEpochKeyring(head: old, key: MeshEpochFixtures.key(1))
        try keyring.rotate(to: new, key: MeshEpochFixtures.key(2), at: rotatedAt)

        let grace = MeshEpochBounds.predecessorGraceSeconds
        #expect(keyring.canOpen(new, at: rotatedAt.addingTimeInterval(grace + 60)),
                "the head never expires")
        #expect(keyring.canOpen(old, at: rotatedAt.addingTimeInterval(grace - 1)),
                "in-flight frames under the closing epoch must still open")
        #expect(!keyring.canOpen(old, at: rotatedAt.addingTimeInterval(grace + 1)),
                "past the grace the old key must be rejected")
        #expect(keyring.openableEpochs(at: rotatedAt.addingTimeInterval(grace + 1)) == [new])
    }
}

// MARK: - MeshRotationManagerTests

/// The manager side: the triggers that fire, the departure that ships, the save that blocks, and
/// the cap that ends the session.
@MainActor
@Suite(.serialized)
struct MeshRotationManagerTests {

    let store = PackageTestHost(installBinding: PackageSwitchableInstallBinding())

    /// A fixed install identity, so the sealed save is deterministic rather than whatever the
    /// simulator's real device-binding row happens to be.
    private static let install = Data(repeating: 0x5C, count: 16)

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
            name: "Rotation Meadow",
            mode: .open,
            members: [local],
            nameSetAt: now,
            nameSetBy: local.fingerprint,
            modeSetAt: now,
            modeSetBy: local.fingerprint,
            createdAt: now
        )
    }

    /// A group key bound to `counter`, and the epoch ref that names it for this manager's mesh.
    private func seedEpoch(_ manager: MeshNetworkManager, counter: UInt32) -> MeshEpochRef? {
        guard let coordinator = MeshEpochRef.minted(
            counter: counter,
            coordinatorFingerprint: manager.identityForTesting.localFingerprint,
            meshID: manager.currentMesh?.meshID ?? UUID()
        ) else {
            Issue.record("could not mint the seed epoch — is the local fingerprint canonical?")
            return nil
        }
        manager.seedEpochKeyringForTesting(
            head: coordinator,
            key: MeshGroupKey(
                epoch: Int(counter),
                keyBytes: Data(repeating: 0x11, count: 32),
                activeSince: Date()
            )
        )
        return coordinator
    }

    /// The 15-minute timer's trigger still arms a rotation, and it arms it as `timer`.
    @Test func theTimerTriggerStillArmsARotation() {
        let manager = MeshNetworkManager(store: store)
        manager.currentMesh = makeMesh(manager)

        manager.requestRotation(cause: .timer)

        #expect(manager.rotationTriggers.pendingCause == .timer)
        #expect(manager.rotationTriggers.firesAt != nil, "the timer trigger must arm a window")
        manager.leaveMesh()
    }

    /// A completed removal vote rotates immediately (plan §8.3) and bars the member locally, so the
    /// next distribution cannot include them.
    @Test func aCompletedRemovalTriggersAMembershipRotation() {
        let manager = MeshNetworkManager(store: store)
        manager.currentMesh = makeMesh(manager)
        let proposal = MeshRemovalProposalPayload(
            id: UUID(),
            targetFingerprint: "fp-target",
            targetDisplayName: "Target",
            proposerFingerprint: "fp-proposer",
            proposerDisplayName: "Proposer",
            createdAt: Date(),
            expiresAt: Date().addingTimeInterval(60)
        )

        manager.secondRemoval(proposal)

        #expect(manager.rotationTriggers.pendingCause == .membership,
                "a voted-out member must trigger a rotation, not wait for the 15-minute tick")
        #expect(manager.removedMemberFingerprints.contains("fp-target"))
        manager.leaveMesh()
    }

    /// A merge that MOVES the derived roster rotates; one that changes nothing does not.
    @Test func onlyAMergeThatChangesTheRosterRotates() throws {
        let manager = MeshNetworkManager(store: store)
        let mesh = makeMesh(manager)
        manager.currentMesh = mesh
        let identity = manager.identityForTesting
        manager.prepareMembershipLedger(
            meshID: mesh.meshID, founderSigningPublicKey: identity.localSigningPublicKey
        )

        var donor = MeshMembershipLedger.empty
        donor.admissions = donor.admissions.inserting(
            SignedAdmissionRecord(token: try MeshAdmissionToken.signed(
                meshID: mesh.meshID,
                joinerFingerprint: identity.localFingerprint,
                joinerSigningPublicKey: identity.localSigningPublicKey,
                admitterIdentity: identity
            ))
        )
        #expect(manager.mergeMembershipLedger(donor).isEmpty, "the founder's own admission verifies")
        #expect(manager.rotationTriggers.pendingCause == .merge,
                "a merge that admits a member is a roster change")

        manager.leaveMesh()
        manager.currentMesh = mesh
        manager.prepareMembershipLedger(
            meshID: mesh.meshID, founderSigningPublicKey: identity.localSigningPublicKey
        )
        var forged = MeshMembershipLedger.empty
        forged.departures = forged.departures.inserting(MeshMembershipFixtures.departure(9))
        #expect(!manager.mergeMembershipLedger(forged).isEmpty, "a record from a stranger is refused")
        #expect(manager.rotationTriggers.pendingCause == nil,
                "a refused record must not spend a rotation")
        manager.leaveMesh()
    }

    /// Item 3's interim regression, closed: leaving now emits a SIGNED departure before the
    /// transport goes away.
    @Test func leavingEmitsASignedDeparture() async {
        let manager = MeshNetworkManager(store: store)
        manager.currentMesh = makeMesh(manager)
        var emitted: [MeshPayloadRole] = []
        manager.onMembershipEventSentForTesting = { emitted.append($0) }

        await manager.leaveSessionAfterNotifyingPeers()

        #expect(emitted == [.meshMemberDeparture],
                "leaveSessionAfterNotifyingPeers must notify peers — item 3 left it sending nothing")
        #expect(manager.currentMesh == nil, "and it must still end the session")
    }

    /// Durable before acknowledged (plan §3.6): a refused seal abandons the rotation, keeps the old
    /// epoch, and names the reason instead of swallowing it.
    @Test func aRefusedSaveBlocksTheRotation() async {
        let manager = MeshNetworkManager(store: store)
        manager.currentMesh = makeMesh(manager)
        guard let seeded = seedEpoch(manager, counter: 3) else { return }

        await PackageSwitchableInstallBinding.testOverride.withValue(.unavailable) {
            await manager.rotateNowForTesting(cause: .membership)
        }

        #expect(manager.epochKeyring?.head == seeded, "a rotation that cannot be sealed must not happen")
        #expect(manager.currentGroupKey?.epoch == 3)
        #expect(manager.lastRotationBlockReason != nil, "a blocked rotation is never silent")
        manager.leaveMesh()
    }

    /// The same rotation succeeds once the seal can be written, and it records its cause.
    @Test func aSealableRotationAdvancesTheHeldKeyring() async {
        let manager = MeshNetworkManager(store: store)
        manager.currentMesh = makeMesh(manager)
        guard let seeded = seedEpoch(manager, counter: 3) else { return }

        await PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Self.install)) {
            await manager.rotateNowForTesting(cause: .membership)
        }

        #expect(manager.epochKeyring?.head.counter == 4)
        #expect(manager.currentGroupKey?.epoch == 4)
        #expect(manager.lastRotationCause == .membership)
        #expect(manager.lastRotationBlockReason == nil)
        #expect(manager.epochRef == manager.epochKeyring?.head.canonicalString,
                "the introduction's epochRef is read off the held keyring, not re-derived")
        #expect(manager.epochKeyring?.canOpen(seeded, at: Date()) == true,
                "the closing epoch stays openable for its grace window")
        manager.leaveMesh()
    }

    /// Plan §8.4's counter cap: the session ends with a signed termination rather than trapping or
    /// serving a key it can never retire.
    @Test func theCounterCapEndsTheSession() async {
        let manager = MeshNetworkManager(store: store)
        manager.currentMesh = makeMesh(manager)
        guard seedEpoch(manager, counter: MeshEpochBounds.counterCap) != nil else { return }
        var emitted: [MeshPayloadRole] = []
        manager.onMembershipEventSentForTesting = { emitted.append($0) }

        await PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Self.install)) {
            await manager.rotateNowForTesting(cause: .membership)
        }

        #expect(emitted == [.meshTerminated])
        #expect(manager.currentMesh == nil, "a mesh that cannot rotate must end")
        // Ending the session drops the keyring — and with it the block reason, which is
        // per-session diagnostic state rather than a durable one.
        #expect(manager.epochKeyring == nil)
        #expect(manager.currentGroupKey == nil)
    }
}
