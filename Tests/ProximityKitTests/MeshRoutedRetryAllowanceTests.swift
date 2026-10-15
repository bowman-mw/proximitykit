// MeshRoutedRetryAllowanceTests.swift
// ProximityKitTests
//
// Network migration P6 item 5 (plan §23.3, D-13.32): the re-entry pass's allowance discipline —
// the pure planner's whole table, and the starvation it exists to stop, on a rig.
//
// Two halves, deliberately. `MeshRoutedRetryPlanTests` drives `MeshRoutedRetryPlan` and
// `MeshRoutedRetryRotation` as the value types they are: no mesh, no store, no item and no clock,
// which is what lets the split be stated exhaustively rather than sampled. `MeshRoutedRetryAllowance`
// `Tests` then drives the two real lists through `MeshRoutedDrainRig` and the manager's own
// `applyRoutedAccessGate` edge, because a plan nobody spends is not a fix.
//
// Two fixture facts the rig cells rest on, both paid for by earlier suites:
//
// - **One pinned install binding** (`MeshP3Acceptance.install`) around every store-touching call,
//   and one clock anchor (`MeshRoutedFixtureClock` through `MeshRoutedDrainRig.createdAt`).
// - **`MeshRoutedDrainItem.stage(into:at:)` writes the store without the manager seeing a chunk**,
//   so an item staged that way is still waiting for job 4 and job 5 — which is the only way to
//   observe either retry list at all (a chunk that arrives on a link has its receipt filed and its
//   plaintext projected at the live door, before any re-entry pass exists to pace).
//
// Where a population is PLANTED rather than minted, the cell says why in its own doc: the routes
// that are convenient to construct are either unreachable from a registered mint (an over-resident
// blob — the photo row's cap IS the resident bound, D-13.19) or self-healing (a missing chunk file
// is repaired out of completeness on the first read).
//
// **The projection list's retryable population IS reachable in production, and three documents said
// otherwise** (item 5 review, P2-3; the commit message, the ledger row and this header's earlier
// wording all claimed it was structural). Two real routes pass `isProjectableAtThisPass` and reach
// the arm: the text arm (`routedCanonicalDispatch(_: MeshRoutedTextBody, …)`, FernletSocial's chat's
// since ProximityKit plan step A0.5.9) answers `.refusedForNow` whenever
// `transcriptLiveness` is `.notLiveRightNow` — a session ended by the five-minute give-up door that
// `startSearching()` can un-end, in the right mesh and the right generation — and
// `routedProjectionBlob` answers nil for a store read that is `.unavailable` or `.refused`, which
// repeats at every pass and does not self-heal. The filter only excludes `.endedForGood`. So item 5's
// projection half is load-bearing in production, not merely structural; what the plants buy is a
// population that is easy to place at the HEAD of an index ordered by origin fingerprint.
//
// A partial copy (ProximityKit plan step A1, the split's first batch of copied suites): of the
// Fernlet repository's FernletTests file of the same name, this holds only
// `MeshRoutedRetryPlanTests`, with its name and tests unchanged; its other suites stay there, so
// what this header says of them is not held here.

@testable import ProximityKit
import Foundation
import Testing

// MARK: - The planner

/// ``MeshRoutedRetryPlan`` and ``MeshRoutedRetryRotation`` as values: the whole split, the
/// round-robin, the two marks and the bound.
@Suite(.serialized)
struct MeshRoutedRetryPlanTests {

    /// A deterministic low-sorting key: the index orders by `(originFingerprint, itemID.uuidString)`,
    /// so a decimal-digit id really does sort by `n`.
    private static func key(_ n: Int) throws -> MeshRoutedItemKey {
        let id = try #require(UUID(uuidString: String(format: "00000000-0000-0000-0000-%012d", n)))
        return MeshRoutedItemKey(originFingerprint: "fp001", itemID: id)
    }

    /// `range`'s keys, in ascending order.
    private static func keys(_ range: Range<Int>) throws -> [MeshRoutedItemKey] {
        try range.map { try Self.key($0) }
    }

    /// An instant with no clock read in it — the rotation only ever compares, never measures.
    private static let anchor = Date(timeIntervalSince1970: 1_800_000_000)

    /// The per-pass allowance the manager spends, restated here so the table reads as arithmetic.
    private static let allowance = 16

    /// **The split, exhaustively.** Never-attempted work gets its reserved half, a retrying
    /// population is capped at the other half, and an unused slot on either side spills to the
    /// other rather than being wasted.
    ///
    /// The last three rows are the ones a naive implementation gets wrong: `(1, 16)` is the whole
    /// point of the item (one new item behind sixteen retryables must still be tried NOW), `(20, 0)`
    /// and `(0, 20)` are the spill in both directions, and `(12, 20)` is the only row where both
    /// caps bind at once.
    @Test func theAllowanceReservesHalfForNeverAttemptedWorkAndSpillsTheRest() throws {
        let pool = try Self.keys(0..<40)
        let table: [(retryable: Int, fresh: Int, expectedNew: Int, expectedRetried: Int)] = [
            (retryable: 16, fresh: 1, expectedNew: 1, expectedRetried: 15),
            (retryable: 20, fresh: 20, expectedNew: 8, expectedRetried: 8),
            (retryable: 12, fresh: 20, expectedNew: 8, expectedRetried: 8),
            (retryable: 20, fresh: 0, expectedNew: 0, expectedRetried: 16),
            (retryable: 0, fresh: 20, expectedNew: 16, expectedRetried: 0),
            (retryable: 20, fresh: 4, expectedNew: 4, expectedRetried: 12),
            (retryable: 0, fresh: 0, expectedNew: 0, expectedRetried: 0)
        ]
        #expect(table.count == 7, "a table this cell sampled to nothing would be green over nothing")
        // R2: bounded by the table.
        for row in table {
            let retryable = Array(pool.prefix(row.retryable))
            let fresh = Array(pool.dropFirst(row.retryable).prefix(row.fresh))
            let plan = MeshRoutedRetryPlan(
                enumerated: retryable + fresh, attempted: Set(retryable),
                rotation: retryable, allowance: Self.allowance
            )
            #expect(plan.neverTriedCount == row.expectedNew)
            #expect(plan.retriedCount == row.expectedRetried)
            #expect(plan.keysToTry.count == row.expectedNew + row.expectedRetried)
            #expect(plan.deferredRetryCount == row.retryable - row.expectedRetried)
            let headIsFresh = plan.keysToTry.prefix(row.expectedNew)
                .allSatisfy { fresh.contains($0) }
            #expect(headIsFresh, "never-attempted work must be at the HEAD, not merely included")
            let boundedByAllowance = plan.keysToTry.count <= Self.allowance
            #expect(boundedByAllowance, "the plan is the allowance's only spender")
        }
    }

    /// **The round-robin, and why the sub-allowance alone is not enough.** A retrying population
    /// larger than its share is rotated, so the tail is reached — with a plain head-of-list retry a
    /// 24-item population would re-try the same sixteen for ever.
    @Test func everyRetryableGetsATurnBecauseTheRotationMovesOn() throws {
        let held = try Self.keys(0..<24)
        var rotation = MeshRoutedRetryRotation()
        _ = rotation.armed(at: Self.anchor)
        // R2: bounded by the population.
        for key in held {
            // A mutating member cannot be called inside `#expect` — the macro captures its
            // subexpressions immutably — so every one of these binds the answer first.
            let remembered = rotation.noteCarriedOver(key)
            #expect(remembered, "the bound must not refuse twenty-four keys")
        }

        var passes: [[MeshRoutedItemKey]] = []
        // R2: two passes, fixed.
        for _ in 0..<2 {
            let plan = rotation.plan(for: held, allowance: Self.allowance)
            passes.append(plan.keysToTry)
            // R2: bounded by the allowance.
            for key in plan.keysToTry {
                let requeued = rotation.noteRetryable(key)
                #expect(requeued, "a re-queue at no bound must not refuse")
            }
        }

        #expect(passes.first == Array(held.prefix(16)), "the first pass takes the head")
        #expect(passes.last?.first == held[16], """
            the second pass must START where the first stopped — a rotation that restarted at the \
            head is the original defect, one level down
            """)
        let seen = Set(passes.flatMap { $0 })
        #expect(seen.count == held.count, "every retryable gets a turn inside two passes")
    }

    /// **A final leaves BOTH sets**, and says so twice: the tried set stops naming it, and the
    /// rotation stops holding a queue slot for it.
    ///
    /// The last assertion is the one worth stating: a finalised key reads as never-attempted again.
    /// That is correct rather than a leak — job 5's `routedProjectedItems` mark and job 4's durable
    /// stamp are what stop it being enumerated at all, and this set's job is only to pace what IS
    /// enumerated.
    @Test func aFinalKeyLeavesTheTriedSetAndTheRotationTogether() throws {
        var rotation = MeshRoutedRetryRotation()
        let first = try Self.key(1)
        let second = try Self.key(2)
        let firstRemembered = rotation.noteRetryable(first)
        let secondRemembered = rotation.noteRetryable(second)
        #expect(firstRemembered && secondRemembered)
        #expect(rotation.attempted == Set([first, second]))
        #expect(rotation.order == [first, second], "the queue is attempt order")

        rotation.noteFinal(first)
        #expect(rotation.attempted == Set([second]), "a final leaves the tried set")
        #expect(rotation.order == [second], "and the rotation, or it holds a queue slot for ever")
        rotation.noteFinal(first)
        #expect(rotation.order == [second], "and a second final is not an error")

        let plan = rotation.plan(for: [first, second], allowance: Self.allowance)
        #expect(plan.neverTriedCount == 1, "the finalised key is never-attempted work again")
        #expect(plan.keysToTry.first == first, "so it is tried first if it is still enumerated")
    }

    /// **The tried set stops at the store's item cap** — it refuses to remember rather than growing,
    /// and a key it already holds is still re-queueable at the bound.
    ///
    /// Degrading toward "never-attempted" is the safe direction: an unremembered key competes for
    /// the reserved half, which wastes a slot on work that may refuse again. The other direction
    /// would be an unbounded set on the main actor.
    @Test func theTriedSetStopsAtTheStoreItemCapAndRefusesRatherThanGrowing() throws {
        var rotation = MeshRoutedRetryRotation()
        var refusedInsideTheCap = false
        // R2: bounded by the store's item cap.
        for position in 0..<MeshRoutedStoreFormat.maxItems where !refusedInsideTheCap {
            refusedInsideTheCap = !rotation.noteRetryable(try Self.key(position))
        }
        #expect(refusedInsideTheCap == false, "nothing inside the cap may be refused")
        #expect(rotation.attempted.count == MeshRoutedStoreFormat.maxItems)

        let overCap = try Self.key(MeshRoutedStoreFormat.maxItems)
        let refusedOverCap = rotation.noteRetryable(overCap)
        #expect(refusedOverCap == false, "the bound refuses by name")
        #expect(rotation.attempted.count == MeshRoutedStoreFormat.maxItems, "and does not grow")
        #expect(rotation.order.count == MeshRoutedStoreFormat.maxItems)
        let requeuedAtTheBound = rotation.noteRetryable(try Self.key(0))
        #expect(requeuedAtTheBound,
                "a key already remembered is still re-queueable at the bound")
    }

    /// **The restart bound.** The session's cut is the FIRST pass's instant and never moves, and an
    /// item this device already held at that instant competes for the retry share rather than for
    /// the reserved never-attempted half.
    ///
    /// That is what makes the memory-only marks honest: after a restart every held item looks
    /// never-attempted, so without the cut a re-derived backlog of refusals would spend the half a
    /// genuinely new item is entitled to.
    @Test func anItemHeldBeforeTheFirstPassCompetesForTheRetryShare() throws {
        var rotation = MeshRoutedRetryRotation()
        #expect(rotation.armedAt == nil, "unarmed until the first pass")
        let armed = rotation.armed(at: Self.anchor)
        #expect(armed == Self.anchor)
        let rearmed = rotation.armed(at: Self.anchor.addingTimeInterval(600))
        #expect(rearmed == Self.anchor,
                "the cut is the FIRST pass's instant; a later pass must not move it")

        let held = try Self.key(1)
        let arrived = try Self.key(2)
        let carried = rotation.noteCarriedOver(held)
        #expect(carried)
        let plan = rotation.plan(for: [held, arrived], allowance: 2)
        #expect(plan.neverTriedCount == 1)
        #expect(plan.keysToTry == [arrived, held], "the newcomer is tried first, the backlog second")

        var attempted = MeshRoutedRetryRotation()
        let heldAttempt = attempted.noteRetryable(held)
        let arrivedAttempt = attempted.noteRetryable(arrived)
        #expect(heldAttempt && arrivedAttempt)
        let carriedAgain = attempted.noteCarriedOver(held)
        #expect(carriedAgain, "idempotent")
        #expect(attempted.order == [held, arrived], """
            a carried-over note must not re-queue a key the pass genuinely attempted, or an item \
            enumerated at every pass is shuffled to the back on each one and the rotation it feeds \
            never advances
            """)
    }

    /// **The planner is type-agnostic, and that is a wall rather than a claim** (item 5.2).
    ///
    /// Item 6 supplies its heart predicate to `MeshNetworkManager.ackableNow(_:in:judgement:)`, the
    /// filter-before-plan seam, and never here: a planner that could see a type token would be a
    /// second per-type source beside the registry, which `noShippingCodeBranchesOnARoutedTypeToken`
    /// exists to forbid. The needles are matched against CODE only, so the file's own doc comments
    /// may name what the code may not.
    @Test func thePlannerNamesNoRoutedTypeNoRegistryAndNoStore() throws {
        let path = "Sources/ProximityKit/Mesh/MeshRoutedRetryPlan.swift"
        let source = try PackageRoot.source(path)
        #expect(source.count > 2_000, "the source scan must not be reading an empty file")
        let code = MeshRoutedSourceScan.codeOnly(source)
        #expect(code.contains("MeshRoutedRetryPlan"), "the scan must be reading the right file")
        // R2: bounded by the needle list.
        for needle in ["MeshRoutedTypeToken", "typeToken", "routedTypes", "contentScope",
                       "entry(for:", "requiresForeground", "MeshRoutedManifest",
                       "MeshRoutedStore(", "MeshRoutedIndex(", "ProximityAudit"] {
            #expect(code.contains(needle) == false, "the planner acquired something it must not see")
        }
    }
}
