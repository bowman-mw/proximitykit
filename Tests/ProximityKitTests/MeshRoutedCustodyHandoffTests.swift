// MeshRoutedCustodyHandoffTests.swift
// ProximityKitTests
//
// Network migration P5 item 8 (plan §10.6, §11): custody-transfer-on-departure — the load-bearing
// case, and increment 1's ONLY relay hop.
//
// Tier 1 only — `FakePeerNetwork` + `FakeMeshTransportSession` + an injected clock, no radio and no
// wall-clock sleeps. The rig is item 6's `MeshRoutedDrainRig` with the three verbs the drain never
// needed, not a second rig; the nodes, links, pumps, settles and rotation samples are item 4's.
//
// The invariant every cell here is about: custody is at the ORIGIN, or — after exactly one
// transfer, at exactly one moment, a development — at the custodians the leaver's own signed
// departure record names AND served the manifest to. Never between two live connected members, and
// never a second hop.
//
// **One anchor, and it is the rig's** (item 6a). Every `let base` below is
// `MeshRoutedDrainRig.createdAt`, not a second pinned literal: the items these cells develop are
// minted at `MeshRoutedDrainRig.now` (= that anchor + 600), and a development instant anchored
// somewhere else drifts away from the mint the moment the rig's anchor rolls. Measured: with the
// two anchors split, seven cells in this family fail on the hand-off count.
//
// A partial copy (ProximityKit plan step A1, the split's first batch of copied suites): of the
// Fernlet repository's FernletTests file of the same name, this holds only
// `MeshRoutedCustodyHandoffWallTests` and, since ProximityKit plan step A1's third batch of copied
// suites (those that reach the keychain and open a store), `MeshRoutedCustodyHandoffDoorTests`, the
// store's two batch doors with no manager at all, with their names and tests unchanged; its other
// suite and the fixtures only that suite reads stay there, so what this header says of them is not
// held here.

import Foundation
import Testing
@testable import ProximityKit

// MARK: - The walls

/// The mechanical halves of "exactly one transfer, at exactly one moment", "no second hop" and "no
/// merge-window dependence" — grep-walls over the shipping source, brace-matched per function so a
/// claim is about a FUNCTION rather than about a file's line count.
@MainActor
@Suite(.serialized)
struct MeshRoutedCustodyHandoffWallTests {

    private func managerSource() throws -> String {
        MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift")
        )
    }

    private func storeSource() throws -> String {
        MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Mesh/MeshRoutedCustodyHandoff.swift")
        )
    }

    /// **The rung moves on the development path and nowhere else.** Both batch doors have exactly
    /// one call site each, in the one function that owns them; the single-item transfer door still
    /// has **zero** shipping callers, so nothing else in the manager can write a `custodied(by:)`
    /// rung; and the claim's custodian is this device's own fingerprint, supplied at the call site
    /// rather than read inside an identity-free store.
    @Test func theRungMovesOnlyOnTheDevelopmentPath() throws {
        let source = try managerSource()
        #expect(source.components(separatedBy: "recordingCustodyHandoff(").count - 1 == 1)
        #expect(source.components(separatedBy: "claimingHandedOffLegs(").count - 1 == 1)
        #expect(source.components(separatedBy: "recordingCustodyTransfer(").count - 1 == 0,
                "the single-item transfer door still has no shipping caller")
        let apply = try #require(Self.body(startingWith: "private func applyCustodyHandoff(", in: source))
        #expect(apply.contains("recordingCustodyHandoff("))
        let transfer = try #require(
            Self.body(startingWith: "private func transferCustodyOnDevelopment(", in: source)
        )
        #expect(transfer.contains("applyCustodyHandoff("), "one owner, one call")
        #expect(source.components(separatedBy: "applyCustodyHandoff(").count - 1 == 2,
                "one declaration plus exactly one call site")
        let claims = try #require(
            Self.body(startingWith: "private func applyHandedOffClaims(", in: source)
        )
        #expect(claims.contains("claimingHandedOffLegs("))
        let claim = try #require(
            Self.body(startingWith: "private func claimHandedOffCustody(", in: source)
        )
        #expect(claim.contains("let me = identity.localFingerprint"))
        #expect(claim.contains("selfFingerprint: me"), "the custodian is this device, at the caller")
    }

    /// Each batch door is one load, N updates and **one** save — the shape that keeps a fifteen-second
    /// window from becoming two thousand crypto passes, and that makes the whole batch
    /// durable-before-acknowledged at once.
    @Test func eachBatchDoorLoadsOnceAndSavesOnce() throws {
        let source = try storeSource()
        for door in [
            "func recordingCustodyHandoff(", "func claimingHandedOffLegs("
        ] {
            let body = try #require(Self.body(startingWith: door, in: source),
                                    "\(door) is gone from MeshRoutedCustodyHandoff.swift")
            #expect(body.components(separatedBy: "indexForWriting()").count - 1 == 1,
                    "\(door) loads exactly once")
            #expect(body.components(separatedBy: "try save(").count - 1 == 1,
                    "\(door) saves exactly once")
        }
        #expect(source.components(separatedBy: "try save(").count - 1 == 2,
                "and nothing else in the file writes at all")
    }

    /// **R8.** The custody path names no merge-window symbol: custody depends on no window closing,
    /// which is what keeps item 7's "a window is not guaranteed to close" from becoming a custody
    /// liveness problem.
    @Test func theDevelopmentPathNamesNoMergeWindowSymbol() throws {
        let source = try managerSource()
        for door in [
            "private func transferCustodyOnDevelopment(",
            "private func pushCustodyToCustodians(",
            "private func claimHandedOffCustody(",
            "private func handoffEntitlement("
        ] {
            let body = try #require(Self.body(startingWith: door, in: source),
                                    "\(door) is gone from MeshNetworkManager.swift")
            for symbol in [
                "mergeWindow", "concludeMergeIfConverged", "readvertiseMergeProof(",
                "sendInventoryDigest(", "sendRoutedInventory("
            ] {
                #expect(!body.contains(symbol), "\(door) reads \(symbol)")
            }
        }
    }

    /// The entitlement a development opens is armed at exactly one site and cleared at exactly one,
    /// so it cannot outlive the session it belongs to. Arming plus clearing is two assignment sites:
    /// "exactly one assignment" would be a wall that could never go green.
    @Test func theHandoffEntitlementDiesWithTheSession() throws {
        let source = try managerSource()
        #expect(source.components(separatedBy: "developmentHandoff = ").count - 1 == 2,
                "one arming site and one clear")
        let armed = try #require(
            Self.body(startingWith: "private func transferCustodyOnDevelopment(", in: source)
        )
        #expect(armed.contains("developmentHandoff = MeshCustodyHandoffScope("))
        let reset = try #require(
            Self.body(startingWith: "private func resetSessionStateMachine(", in: source)
        )
        #expect(reset.contains("developmentHandoff = nil"))
        #expect(!source.contains("lastDevelopmentPlan?.handoffTargets"),
                "the entitlement is never read off the plan that outlives the session")
    }

    /// **D-6.16 declined, by name.** The two receive clauses still admit only a destination's own
    /// item or the origin's own forward, and neither names a hand-off target: widening either is
    /// increment 2.
    @Test func theReceiveClauseIsStillOneHopFromTheOrigin() throws {
        let source = try managerSource()
        let manifestDoor = try #require(
            Self.body(startingWith: "private func ingestRoutedManifest(", in: source)
        )
        #expect(manifestDoor.contains("context.sender == manifest.originFingerprint"))
        #expect(!manifestDoor.contains("handoffTargets"))
        let chunkDoor = try #require(
            Self.body(startingWith: "private func ingestRoutedChunk(", in: source)
        )
        #expect(chunkDoor.contains("context.sender == chunk.originFingerprint"))
        #expect(!chunkDoor.contains("handoffTargets"))
    }

    /// **The hop bound.** The origin-served set has one writer, one reader and one clear. A second
    /// writer is increment 2 arriving without a decision.
    ///
    /// **Amended by P5 item 12, and strengthened in the same commit.** The wall used to count one
    /// call site; the replay window's probe is sender-BLIND (author = the origin, id = the item), so
    /// a courier's copy and the origin's own are indistinguishable to it, and leaving the write
    /// inside the probe's early return would drop the origin's own hand-off copy as `replayed` and
    /// strand that leg at the origin's next departure. The write therefore runs on the replayed path
    /// too — so the count moved to two and the wall became **per door**: both call sites must sit
    /// inside `ingestRoutedManifest`, which a bare count could never say.
    @Test func theOriginServedSetIsWrittenAtOneDoorAndDiesWithTheSession() throws {
        let source = try managerSource()
        #expect(source.components(separatedBy: "originServedItems.insert(").count - 1 == 1)
        #expect(source.components(separatedBy: "noteOriginServed(").count - 1 == 3,
                "one declaration plus exactly two call sites")
        let writer = try #require(Self.body(startingWith: "private func noteOriginServed(", in: source))
        #expect(writer.contains("originServedItems.insert("))
        let manifestDoor = try #require(
            Self.body(startingWith: "private func ingestRoutedManifest(", in: source)
        )
        #expect(manifestDoor.contains("noteOriginServed(key)"))
        #expect(manifestDoor.components(separatedBy: "noteOriginServed(").count - 1 == 2,
                "BOTH writes live in the one door — the admitted path and the replayed one")
        let reader = try #require(
            Self.body(startingWith: "private func claimHandedOffCustody(", in: source)
        )
        #expect(reader.components(separatedBy: "originServed: originServedItems").count - 1 == 2,
                "the claim planner and its residual counter are the only readers")
        let reset = try #require(
            Self.body(startingWith: "private func resetSessionStateMachine(", in: source)
        )
        #expect(reset.contains("originServedItems.removeAll()"))
    }

    /// **The deferred commit queue is drained by the claim itself, and dies with the session.**
    ///
    /// Routing the retry through the claim *planner* is what would make the deferral permanent —
    /// after a claim no named leg is `pending`, so a re-plan is empty by construction. The queue is
    /// therefore drained even when an evaluation plans nothing, and it is cleared with the session
    /// because it names items of one mesh.
    @Test func theDeferredCommitQueueIsDrainedByTheClaimAndDiesWithTheSession() throws {
        let source = try managerSource()
        let claim = try #require(
            Self.body(startingWith: "private func claimHandedOffCustody(", in: source)
        )
        #expect(claim.contains("mintClaimedCustody([], at: now)"),
                "an evaluation that plans nothing still drains the queue")
        let mint = try #require(
            Self.body(startingWith: "private func mintClaimedCustody(", in: source)
        )
        #expect(mint.contains("deferredCustodyCommits + keys"), "the queue runs AHEAD of new work")
        #expect(mint.components(separatedBy: "deferredCustodyCommits = ").count - 1 == 2,
                "one carry-the-whole-queue site and one overflow site, and nothing else assigns it")
        let reset = try #require(
            Self.body(startingWith: "private func resetSessionStateMachine(", in: source)
        )
        #expect(reset.contains("deferredCustodyCommits.removeAll()"))
    }

    /// **The merge door runs the verdict FIRST.** A merge that ejects this device, or ends the mesh,
    /// must not first write custody rungs — the same order the live-record twin uses.
    @Test func theMergeDoorClaimsOnlyWhenTheVerdictDeclinedToEndTheSession() throws {
        let source = try managerSource()
        let merge = try #require(
            Self.body(startingWith: "func mergeMembershipLedger(", in: source)
        )
        #expect(merge.contains("if moved, !applyMergedRosterVerdict(from: before) {"),
                "the claim and the rotation both hang off the verdict declining")
        #expect(merge.components(separatedBy: "claimHandedOffCustody(").count - 1 == 1)
        let verdictFirst = try #require(merge.range(of: "applyMergedRosterVerdict(from: before)"))
        let claimAfter = try #require(merge.range(of: "claimHandedOffCustody("))
        #expect(verdictFirst.lowerBound < claimAfter.lowerBound,
                "the claim is inside the verdict's own guard, never before it")
        let move = try #require(
            Self.body(startingWith: "private func applyRosterMove(", in: source)
        )
        let selfRemoval = try #require(move.range(of: "applyVerifiedSelfRemoval()"))
        let termination = try #require(move.range(of: "applyVerifiedTermination()"))
        let liveClaim = try #require(move.range(of: "claimHandedOffCustody("))
        #expect(selfRemoval.lowerBound < liveClaim.lowerBound
                && termination.lowerBound < liveClaim.lowerBound,
                "the live-record twin still ends the session before it claims")
    }

    /// **D-8.21, mechanically.** A departure record that was never emitted is folded into the result
    /// rather than reported as a transfer, and the byte push runs only when it WAS emitted.
    @Test func aRecordThatWasNeverEmittedSkipsThePush() throws {
        let source = try managerSource()
        let body = try #require(
            Self.body(startingWith: "func leaveSessionAfterNotifyingPeers(clock:", in: source)
        )
        #expect(body.contains("let emitted = await sendMembershipEvent("))
        #expect(body.contains("if emitted {"))
        #expect(body.contains("handoff = handoff.notAnnounced()"))
        #expect(body.components(separatedBy: "pushCustodyToCustodians(").count - 1 == 1,
                "the push has exactly one call site, inside the emitted branch")
        let emit = try #require(Self.body(startingWith: "func sendMembershipEvent(", in: source))
        #expect(emit.components(separatedBy: "return false").count - 1 == 4,
                "every exit that broadcast nothing answers false")
    }

    /// One function's body found from a declaration **prefix**, brace-matched from the first `{`
    /// after it — so a declaration whose parameters wrap onto several lines can still be named.
    private static func body(startingWith prefix: String, in source: String) -> String? {
        guard let start = source.range(of: prefix),
              let open = source.range(of: "{", range: start.upperBound..<source.endIndex)
        else { return nil }
        var depth = 1
        var index = open.upperBound
        var scanned = 0
        // R2: bounded by the file's own length.
        while index < source.endIndex, scanned < source.count {
            scanned += 1
            if source[index] == "{" { depth += 1 }
            if source[index] == "}" {
                depth -= 1
                if depth == 0 { return String(source[open.upperBound..<index]) }
            }
            index = source.index(after: index)
        }
        return nil
    }
}

// MARK: - The store doors, with no manager at all

/// The two batch doors' own rules: one load, N updates, one save, and three lists that never
/// collapse into each other.
@MainActor
@Suite(.serialized)
struct MeshRoutedCustodyHandoffDoorTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer
    /// has run before a cell's identities or stores reach the keychain.
    let keychain = PackageTestEnvironment.keychain

    private typealias Fixture = MeshRoutedStoreFixtures

    /// One call advances every item's rung, and every one survives the single save.
    @Test func aBatchTransferWritesEveryRungInOneSave() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let first = try MeshRoutedCustodyFixtures.rig(scope: scope)
        let second = try MeshRoutedCustodyFixtures.rig(scope: scope)
        let transfers = [
            MeshRoutedCustodyHandoff(
                item: first.key, destinations: first.otherDestinations,
                receipt: try MeshRoutedCustodyFixtures.receipt(first)
            ),
            MeshRoutedCustodyHandoff(
                item: second.key, destinations: second.otherDestinations,
                receipt: try MeshRoutedCustodyFixtures.receipt(second)
            )
        ]
        let outcome = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            first.store.recordingCustodyHandoff(transfers, now: Fixture.now)
        }

        #expect(outcome.value?.advanced.count == 2, "\(outcome)")
        let index = try #require(MeshRoutedCustodyFixtures.loadedIndex(first.store))
        for transfer in transfers {
            let target = try #require(index.record(for: transfer.item)?.deliveryTarget)
            let custodian = transfer.receipt.custodianFingerprint
            let moved = transfer.destinations.allSatisfy {
                target.state(of: $0) == .custodied(by: custodian)
            }
            #expect(moved, "one save carried every rung the batch planned")
        }
    }

    /// A per-item refusal skips **that** item: nothing about one item's receipt says anything about
    /// another's, so the batch continues and the refusal is named.
    @Test func aRefusedItemDoesNotAbortTheBatch() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        let receipt = try MeshRoutedCustodyFixtures.receipt(rig)
        let stranger = MeshRoutedItemKey(originFingerprint: "fpNobody", itemID: UUID())
        let outcome = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            rig.store.recordingCustodyHandoff(
                [
                    MeshRoutedCustodyHandoff(
                        item: stranger, destinations: rig.otherDestinations, receipt: receipt
                    ),
                    MeshRoutedCustodyHandoff(
                        item: rig.key, destinations: rig.otherDestinations, receipt: receipt
                    )
                ],
                now: Fixture.now
            )
        }

        #expect(outcome.value?.advanced == [rig.key])
        #expect(outcome.value?.refused.map(\.refusal) == [.store(.unknownItem)])
        #expect(outcome.value?.refused.map(\.item) == [stranger])
    }

    /// **A delivery-level refusal keeps its own name.** `advancingAll` refuses the whole item at the
    /// first ladder refusal and applies nothing, so reporting it as `unchanged` would make a caller
    /// bug indistinguishable from "every leg was already where the door would have put it" — and it
    /// would reach no report and no audit line at all.
    @Test func aDeliveryLevelRefusalIsNamedRatherThanCalledUnchanged() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(
            scope: scope, typeToken: MeshRoutedTypeToken.photo
        )
        MeshRoutedCustodyFixtures.stageAll(rig)
        _ = MeshRoutedCustodyFixtures.commit(rig)
        let commit = MeshRoutedCustodyFixtures.commitDelivery(rig)
        let witness = try #require(MeshRoutedCustodyFixtures.deliveryWitness(commit), "\(commit)")
        let receipt = try MeshRecipientReceipt.signed(
            witness: witness, manifest: rig.manifest, identity: rig.custodian
        )
        let closed = rig.custodian.localFingerprint
        let filed = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            rig.store.recordingRecipientReceipt(item: rig.key, receipt: receipt, now: Fixture.now)
        }
        #expect(filed.value?.target != nil, "the leg must actually reach `delivered`: \(filed)")
        #expect(MeshRoutedCustodyFixtures.loadedIndex(rig.store)?
            .record(for: rig.key)?.deliveryTarget?.state(of: closed) == .delivered)
        // A caller bug by construction: naming another member the courier for a leg that is already
        // terminal. The ladder refuses it, and the batch must say which refusal that was.
        let courier = try #require(rig.otherDestinations.first)
        let outcome = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            rig.store.claimingHandedOffLegs(
                [MeshRoutedHandoffClaim(
                    item: rig.key, destinations: [closed], custodian: courier
                )],
                now: Fixture.now
            )
        }

        #expect(outcome.value?.refused.map(\.refusal) == [.delivery(.alreadyDelivered)], "\(outcome)")
        #expect(outcome.value?.advanced.isEmpty == true, "and nothing was written")
        #expect(outcome.value?.incomplete.isEmpty == true, "a refusal is not a 'not yet'")
    }

    /// A store that cannot be read writes nothing at all — not even the items it could have taken.
    @Test func anUnavailableStoreWritesNothing() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        let receipt = try MeshRoutedCustodyFixtures.receipt(rig)
        try Fixture.writeRaw(Data("not a sealed index".utf8), into: rig.store)
        let before = Fixture.snapshot(scope)
        let outcome = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            rig.store.recordingCustodyHandoff(
                [MeshRoutedCustodyHandoff(
                    item: rig.key, destinations: rig.otherDestinations, receipt: receipt
                )],
                now: Fixture.now
            )
        }

        #expect(outcome.unavailability != nil, "\(outcome)")
        #expect(Fixture.snapshot(scope) == before, "an unreadable store was written to anyway")
    }

    /// "Not yet" is not a refusal: an incomplete item has no ``MeshRoutedStoreRefusal`` spelling, so
    /// it rides its own list and is retried when the item completes.
    @Test func aClaimNamesAnIncompleteItemInItsOwnList() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            #expect(rig.store.admittingManifest(rig.manifest, now: Fixture.now).value != nil)
        }
        let outcome = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            rig.store.claimingHandedOffLegs(
                [MeshRoutedHandoffClaim(
                    item: rig.key, destinations: rig.otherDestinations,
                    custodian: rig.custodian.localFingerprint
                )],
                now: Fixture.now
            )
        }

        #expect(outcome.value?.incomplete == [rig.key])
        #expect(outcome.value?.refused.isEmpty == true, "not yet is not a refusal")
        #expect(outcome.value?.advanced.isEmpty == true)
    }

    /// The claim is receipt-free: a record's evidence set holds OTHER members' receipts, and this
    /// device's own custody is `custodiedAt` plus a re-mint on demand.
    @Test func aClaimStoresNoReceiptOfItsOwn() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        MeshRoutedCustodyFixtures.stageAll(rig)
        let outcome = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            rig.store.claimingHandedOffLegs(
                [MeshRoutedHandoffClaim(
                    item: rig.key, destinations: rig.otherDestinations,
                    custodian: rig.custodian.localFingerprint
                )],
                now: Fixture.now
            )
        }

        #expect(outcome.value?.advanced == [rig.key], "\(outcome)")
        let record = try #require(MeshRoutedCustodyFixtures.loadedIndex(rig.store)?.record(for: rig.key))
        #expect(record.receipts.isEmpty, "the claim burned no evidence slot on a self-receipt")
        #expect(record.custodiedAt == nil, "and it committed nothing: the rung is not the commit")
    }

    /// A parked item — chunks with no manifest — answers `manifestMismatch` by name, the same answer
    /// the single-item transfer door gives.
    @Test func aParkedItemAnswersManifestMismatch() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        let receipt = try MeshRoutedCustodyFixtures.receipt(rig)
        let parkedScope = Fixture.scope()
        defer { Fixture.tearDown(parkedScope) }
        let parked = MeshRoutedStore(scope: parkedScope)
        PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            for chunk in rig.chunks {
                #expect(parked.stagingChunk(chunk, now: Fixture.now).value != nil)
            }
        }
        let outcome = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            parked.recordingCustodyHandoff(
                [MeshRoutedCustodyHandoff(
                    item: rig.key, destinations: rig.otherDestinations, receipt: receipt
                )],
                now: Fixture.now
            )
        }

        #expect(outcome.value?.refused.map(\.refusal) == [.store(.manifestMismatch)], "\(outcome)")
        #expect(outcome.value?.advanced.isEmpty == true)
    }

    /// **The cell that would have caught the memberwise-initializer bypass.** The push batch goes
    /// through the drain's narrowing initializer, so a maximal local index still fits inside the
    /// per-answer bounds instead of charging a thousand frames to send sixty-four.
    @Test func aPushBatchNeverExceedsTheDrainFrameBound() throws {
        let index = Self.bulkyIndex(items: 40, chunks: 100)
        let meshID = MeshRoutedManifestFixtures.meshID
        let local = try #require(MeshRoutedInventory(
            meshID: meshID, index: index, selfFingerprint: "fpSelf", at: Fixture.now
        ))
        let bounds = MeshRoutedDrainBounds.increment1
        let batch = try #require(MeshCustodyHandoffPlan.pushBatch(
            local: local,
            remote: MeshRoutedInventory(meshID: meshID, members: [], entries: []),
            offerable: Set(index.items.map(\.key)),
            refused: [],
            frameAllowance: bounds.maxFrames
        ))

        #expect(batch.frameCount <= bounds.maxFrames, "\(batch.frameCount) frames planned")
        #expect(batch.manifests.count <= bounds.maxItems)
        #expect(batch.chunks.reduce(0) { $0 + $1.indices.count } <= bounds.maxChunksPerAnswer)
        #expect(batch.truncated, "the remainder is owed, not lost")
    }

    /// A synthetic index of `items` complete, manifest-bound records with `chunks` slots each —
    /// bigger than any single answer may carry, which is the whole point.
    private static func bulkyIndex(items: Int, chunks: Int) -> MeshRoutedIndex {
        var records: [MeshRoutedItemRecord] = []
        // R2: bounded by the caller's own item count.
        for _ in 0..<items {
            let manifest = MeshRoutedManifestFixtures.manifest().replacing(itemID: UUID())
            let descriptors = (0..<chunks).map {
                Fixture.descriptor(index: UInt32($0), count: UInt32(chunks), bytes: 16)
            }
            records.append(MeshRoutedItemRecord(
                key: MeshRoutedItemKey(manifest),
                contentHash: manifest.contentHash,
                chunkCount: UInt32(chunks),
                expiresAt: manifest.expiresAt,
                manifest: manifest,
                firstSeenAt: MeshRoutedManifestFixtures.base,
                custodiedAt: nil,
                deliveredAt: nil,
                chunks: descriptors,
                delivery: nil,
                receipts: [],
                recipientReceipts: []
            ))
        }
        return MeshRoutedIndex(items: records)
    }
}
