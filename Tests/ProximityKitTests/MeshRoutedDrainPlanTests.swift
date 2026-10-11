// MeshRoutedDrainPlanTests.swift
// ProximityKitTests
//
// Network migration P5 item 6 (plan §11, §10.3): the pure half of the drain — no manager, no store,
// no clock. Every cell is a value in and a value out.

import Foundation
import Testing
@testable import ProximityKit

// MARK: - Fixtures

/// Keys, gaps and deltas for the plan's own tests. Nothing here touches disk or a clock.
enum MeshRoutedDrainPlanFixtures {

    static let origin = "fp001"

    /// A deterministic key whose UUID ordering is the ordering of `slot`.
    static func key(_ slot: Int) -> MeshRoutedItemKey {
        let text = String(format: "%08X-0000-4000-8000-000000000000", slot)
        return MeshRoutedItemKey(originFingerprint: origin, itemID: UUID(uuidString: text) ?? UUID())
    }

    /// A gap naming the first `count` slots of a `count`-chunk item.
    static func gap(_ slot: Int, count: Int) -> MeshRoutedChunkGap {
        let bytes = MeshRoutedInventoryEntry.bitmapByteCount(forChunkCount: UInt32(count))
        var map = Data(repeating: 0, count: bytes)
        // R2: bounded by the caller's own chunk count.
        for index in 0..<count {
            map[map.startIndex + index / 8] |= UInt8(1) << UInt8(index % 8)
        }
        return MeshRoutedChunkGap(key: key(slot), chunkCount: UInt32(count), missing: map)
    }

    static func receipt(_ slot: Int, signer: String) -> MeshRoutedInventoryReceiptRef {
        MeshRoutedInventoryReceiptRef(key: key(slot), signer: signer, kind: .recipient)
    }

    /// A delta with three offers, three chunk gaps of one slot each, two receipts and two asks.
    static func delta() -> MeshRoutedInventoryDelta {
        MeshRoutedInventoryDelta(
            manifestsToRequest: [key(20)],
            chunksToRequest: [gap(21, count: 1)],
            manifestsToOffer: [key(1), key(2), key(3)],
            chunksToOffer: [gap(1, count: 1), gap(2, count: 1), gap(3, count: 1)],
            receiptsToForward: [receipt(1, signer: "fp002"), receipt(2, signer: "fp003")],
            receiptsToRequest: []
        )
    }
}

// MARK: - The plan

/// The narrowing rules: refused keys, the bounds, the session allowance, order and determinism.
@Suite(.serialized)
struct MeshRoutedDrainPlanTests {

    private func plan(
        _ delta: MeshRoutedInventoryDelta,
        refused: Set<MeshRoutedItemKey> = [],
        bounds: MeshRoutedDrainBounds = .increment1,
        allowance: Int = MeshRoutedDrainBounds.increment1.maxFrames
    ) -> MeshRoutedDrainPlan {
        MeshRoutedDrainPlan(delta: delta, refused: refused, bounds: bounds, frameAllowance: allowance)
    }

    @Test func theRefusedSetRemovesExactlyItsKeysFromBothDirections() {
        let refused: Set<MeshRoutedItemKey> = [MeshRoutedDrainPlanFixtures.key(2)]
        let narrowed = plan(MeshRoutedDrainPlanFixtures.delta(), refused: refused)
        #expect(narrowed.manifests == [
            MeshRoutedDrainPlanFixtures.key(1), MeshRoutedDrainPlanFixtures.key(3)
        ])
        #expect(narrowed.chunks.map(\.key) == [
            MeshRoutedDrainPlanFixtures.key(1), MeshRoutedDrainPlanFixtures.key(3)
        ])
        #expect(narrowed.receipts.map(\.key) == [MeshRoutedDrainPlanFixtures.key(1)])
        let untouched = plan(MeshRoutedDrainPlanFixtures.delta())
        #expect(untouched.manifests.count == 3)
        #expect(untouched.receipts.count == 2)
    }

    /// A refused key is subtracted from the diagnostic ask too, so a refusal does not re-fire in
    /// either direction.
    @Test func theRefusedSetAlsoNarrowsTheAsk() {
        let refused: Set<MeshRoutedItemKey> = [MeshRoutedDrainPlanFixtures.key(20)]
        let narrowed = plan(MeshRoutedDrainPlanFixtures.delta(), refused: refused)
        #expect(narrowed.requests.contains(MeshRoutedDrainPlanFixtures.key(20)) == false)
        #expect(narrowed.requests.contains(MeshRoutedDrainPlanFixtures.key(21)))
    }

    @Test func theBoundsTruncateRatherThanGrow() {
        let tiny = MeshRoutedDrainBounds(maxItems: 1, maxChunksPerAnswer: 1, maxReceipts: 1)
        let narrowed = plan(MeshRoutedDrainPlanFixtures.delta(), bounds: tiny, allowance: tiny.maxFrames)
        #expect(narrowed.frameCount <= tiny.maxFrames)
        #expect(narrowed.manifests.count == 1)
        #expect(narrowed.receipts.count == 1)
        #expect(narrowed.truncated)
    }

    @Test func theOrderIsTheDeltasCanonicalOrder() {
        let delta = MeshRoutedDrainPlanFixtures.delta()
        let narrowed = plan(delta)
        #expect(narrowed.manifests == delta.manifestsToOffer)
        #expect(narrowed.chunks.map(\.key) == delta.chunksToOffer.map(\.key))
        #expect(narrowed.receipts == delta.receiptsToForward)
    }

    @Test func twoRunsOnTheSameInputsAreEqual() {
        let delta = MeshRoutedDrainPlanFixtures.delta()
        #expect(plan(delta) == plan(delta))
    }

    @Test func anEmptyDeltaPlansNothing() {
        let empty = MeshRoutedInventoryDelta(
            manifestsToRequest: [], chunksToRequest: [], manifestsToOffer: [],
            chunksToOffer: [], receiptsToForward: [], receiptsToRequest: []
        )
        let narrowed = plan(empty)
        #expect(narrowed.isEmpty)
        #expect(narrowed.frameCount == 0)
        #expect(narrowed.truncated == false)
    }

    /// The session budget narrows an answer rather than refusing it, and what survives is the
    /// delta's canonical PREFIX — so the remainder is what the next exchange starts from.
    @Test func aFrameAllowanceBelowTheBoundsTruncatesToIt() {
        let narrowed = plan(MeshRoutedDrainPlanFixtures.delta(), allowance: 5)
        #expect(narrowed.frameCount <= 5)
        #expect(narrowed.truncated)
        #expect(narrowed.manifests == [
            MeshRoutedDrainPlanFixtures.key(1), MeshRoutedDrainPlanFixtures.key(2),
            MeshRoutedDrainPlanFixtures.key(3)
        ])
        #expect(narrowed.chunks.map(\.key) == [
            MeshRoutedDrainPlanFixtures.key(1), MeshRoutedDrainPlanFixtures.key(2)
        ])
    }

    /// A zero allowance plans nothing at all — the refusal is the caller's, not a half-served batch.
    @Test func aZeroAllowancePlansNothing() {
        let narrowed = plan(MeshRoutedDrainPlanFixtures.delta(), allowance: 0)
        #expect(narrowed.isEmpty)
        #expect(narrowed.truncated)
    }

    /// **The pacing regression.** One item may spend the whole per-answer chunk allowance: reusing
    /// `MeshChunkFormat.maxChunksInFlightPerPeer` (3) as a per-answer total is what would make every
    /// item over 768 KiB permanently undeliverable.
    @Test func oneItemMaySpendTheWholeChunkAllowance() {
        let big = MeshRoutedInventoryDelta(
            manifestsToRequest: [], chunksToRequest: [],
            manifestsToOffer: [],
            chunksToOffer: [MeshRoutedDrainPlanFixtures.gap(1, count: 64)],
            receiptsToForward: [], receiptsToRequest: []
        )
        let narrowed = plan(big)
        #expect(narrowed.chunks.count == 1)
        #expect(narrowed.chunks.first?.indices.count == 64)
        #expect(narrowed.truncated == false)
        #expect(MeshRoutedDrainBounds.increment1.maxChunksPerAnswer == 64)
        #expect(MeshRoutedDrainBounds.increment1.maxChunksPerAnswer > MeshChunkFormat.maxChunksInFlightPerPeer)
    }

    /// The session bound is derived from the chunk format's own maximal item, never picked: a budget
    /// that cannot complete one maximal item is a starvation bug wearing a bound's name.
    @Test func theSessionBudgetCoversOneMaximalItem() {
        #expect(MeshRoutedDrainBounds.sessionFramesPerPeer
                == MeshChunkFormat.maxChunkCount + 2 * MeshMembershipBounds.maxRecordsPerKind)
        #expect(MeshRoutedDrainBounds.sessionFramesPerPeer > MeshChunkFormat.maxChunkCount)
    }
}
