// MeshRoutedInventoryDeltaTests.swift
// ProximityKitTests
//
// P5 item 5 (plan §11, §10.3): the pure comparison of two routed inventories — six lists, six rules,
// and the four deadlocks each rule is shaped to avoid.
//
// The three claims that would be expensive to rediscover later:
//
// 1. **Chunks are compared as SETS.** Equal counts over different held sets are NOT quiescent. This
//    test fails against any count-ordered rule, and there is no later stage that would catch it.
// 2. **Quiescence is one-sided.** A device holding nothing computes an empty delta against every
//    peer, including one holding an item addressed to it — so `isQuiescent` alone is true on the
//    primary delivery path, and only `converged(local:peerReportsQuiescent:)` is item 7's predicate.
// 3. **Signer sets are compared as FINGERPRINTS.** Member tables are minimal per digest, so two
//    honest peers carry different tables; an index-wise comparison produces both false forwards and
//    false gaps with no compile error.
//
// Pure: no store, no identity, no clock.

import Foundation
import Testing
@testable import ProximityKit

/// The comparison, rule by rule.
@Suite(.serialized)
struct MeshRoutedInventoryDeltaTests {

    private static let mesh = MeshRoutedInventoryFixtures.meshID
    private static let itemA = MeshRoutedInventoryFixtures.itemID
    private static let itemB = MeshRoutedInventoryFixtures.parkedItemID
    private static let table = ["fp001", "fp004"]

    /// A canonical bitmap over `count` slots for the held indices.
    private static func bitmap(_ held: [UInt32], count: UInt32) -> Data {
        var bytes = Data(
            repeating: 0, count: MeshRoutedInventoryEntry.bitmapByteCount(forChunkCount: count)
        )
        for index in held where index < count {
            bytes[Int(index) / 8] |= UInt8(1) << UInt8(Int(index) % 8)
        }
        return bytes
    }

    private static func entry(
        origin: UInt8 = 0,
        item: UUID,
        manifest: Bool = true,
        count: UInt32 = 3,
        held: [UInt32] = [0, 1, 2],
        custody: [UInt8] = [],
        recipient: [UInt8] = []
    ) -> MeshRoutedInventoryEntry {
        MeshRoutedInventoryEntry(
            originIndex: origin, itemID: item, holdsManifest: manifest, chunkCount: count,
            heldChunks: bitmap(held, count: count), custodySigners: custody, recipientSigners: recipient
        )
    }

    private static func inventory(
        _ entries: [MeshRoutedInventoryEntry], members: [String] = table, mesh: UUID = mesh
    ) -> MeshRoutedInventory {
        MeshRoutedInventory(meshID: mesh, members: members, entries: entries)
    }

    private static func key(_ origin: String, _ item: UUID) -> MeshRoutedItemKey {
        MeshRoutedItemKey(originFingerprint: origin, itemID: item)
    }

    /// The delta, required rather than optional — every case but the foreign-mesh one has a value.
    private static func delta(
        _ local: MeshRoutedInventory,
        _ remote: MeshRoutedInventory,
        entitled: Set<MeshRoutedItemKey> = []
    ) throws -> MeshRoutedInventoryDelta {
        try #require(MeshRoutedInventoryDelta.between(
            local: local, remote: remote, offerableToPeer: entitled
        ))
    }

    // MARK: Quiescence

    @Test func identicalInventoriesAreQuiescent() throws {
        let both = Self.inventory([Self.entry(item: Self.itemA, custody: [1], recipient: [1])])
        let delta = try Self.delta(both, both, entitled: [Self.key("fp001", Self.itemA)])
        #expect(delta.isQuiescent)
        #expect(delta.ask.isEmpty)
        #expect(delta.offer.isEmpty)
    }

    @Test func twoEmptyInventoriesAreQuiescent() throws {
        let empty = Self.inventory([], members: [])
        #expect(try Self.delta(empty, empty).isQuiescent)
    }

    // MARK: One test per list

    @Test func aParkedItemAsksForTheManifestThePeerHolds() throws {
        let mine = Self.inventory([Self.entry(item: Self.itemA, manifest: false)])
        let theirs = Self.inventory([Self.entry(item: Self.itemA, manifest: true)])
        let delta = try Self.delta(mine, theirs)

        #expect(delta.manifestsToRequest == [Self.key("fp001", Self.itemA)])
        #expect(delta.manifestsToOffer.isEmpty)
        #expect(delta.isQuiescent == false)
    }

    @Test func aChunkThePeerHoldsAndILackIsRequested() throws {
        let mine = Self.inventory([Self.entry(item: Self.itemA, count: 4, held: [0, 1])])
        let theirs = Self.inventory([Self.entry(item: Self.itemA, count: 4, held: [0, 1, 3])])
        let delta = try Self.delta(mine, theirs)

        let gap = try #require(delta.chunksToRequest.first)
        #expect(delta.chunksToRequest.count == 1)
        #expect(gap.key == Self.key("fp001", Self.itemA))
        #expect(gap.chunkCount == 4)
        #expect(gap.missingIndices() == [3])
        #expect(delta.chunksToOffer.isEmpty)
    }

    @Test func anEntitledManifestThePeerLacksIsOffered() throws {
        let mine = Self.inventory([Self.entry(item: Self.itemA)])
        let theirs = Self.inventory([Self.entry(item: Self.itemA, manifest: false, held: [])])
        let entitled: Set = [Self.key("fp001", Self.itemA)]
        let delta = try Self.delta(mine, theirs, entitled: entitled)

        #expect(delta.manifestsToOffer == [Self.key("fp001", Self.itemA)])
        #expect(delta.manifestsToRequest.isEmpty)
    }

    @Test func anEntitledChunkThePeerLacksIsOffered() throws {
        let mine = Self.inventory([Self.entry(item: Self.itemA, count: 4, held: [0, 1, 2])])
        let theirs = Self.inventory([Self.entry(item: Self.itemA, count: 4, held: [0])])
        let entitled: Set = [Self.key("fp001", Self.itemA)]
        let delta = try Self.delta(mine, theirs, entitled: entitled)

        let gap = try #require(delta.chunksToOffer.first)
        #expect(gap.missingIndices() == [1, 2])
        #expect(gap.chunkCount == 4)
        #expect(delta.chunksToRequest.isEmpty)
    }

    @Test func aReceiptIHoldAndThePeerLacksIsForwarded() throws {
        let mine = Self.inventory([Self.entry(item: Self.itemA, custody: [1], recipient: [1])])
        let theirs = Self.inventory([Self.entry(item: Self.itemA)])
        let delta = try Self.delta(mine, theirs)

        #expect(delta.receiptsToForward == [
            MeshRoutedInventoryReceiptRef(key: Self.key("fp001", Self.itemA), signer: "fp004", kind: .custody),
            MeshRoutedInventoryReceiptRef(key: Self.key("fp001", Self.itemA), signer: "fp004", kind: .recipient)
        ])
        #expect(delta.receiptsToRequest.isEmpty)
    }

    @Test func aReceiptThePeerHoldsAndILackIsRequested() throws {
        let mine = Self.inventory([Self.entry(item: Self.itemA)])
        let theirs = Self.inventory([Self.entry(item: Self.itemA, custody: [1])])
        let delta = try Self.delta(mine, theirs)

        #expect(delta.receiptsToRequest == [
            MeshRoutedInventoryReceiptRef(key: Self.key("fp001", Self.itemA), signer: "fp004", kind: .custody)
        ])
        #expect(delta.receiptsToForward.isEmpty)
    }

    // MARK: The chunk-set claims (D-5.14)

    /// **The D-5.14 regression.** Local {0,1,4}, remote {0,1,2} of 5: the counts tie, the sets do
    /// not, and both directions are named. It fails against any count-ordered rule.
    @Test func equalCountsWithDifferentHeldSetsAreNotQuiescent() throws {
        let mine = Self.inventory([Self.entry(item: Self.itemA, count: 5, held: [0, 1, 4])])
        let theirs = Self.inventory([Self.entry(item: Self.itemA, count: 5, held: [0, 1, 2])])
        let entitled: Set = [Self.key("fp001", Self.itemA)]
        let delta = try Self.delta(mine, theirs, entitled: entitled)

        #expect(try #require(delta.chunksToRequest.first).missingIndices() == [2])
        #expect(try #require(delta.chunksToOffer.first).missingIndices() == [4])
        #expect(delta.isQuiescent == false)
    }

    @Test func aChunkGapCarriesExactlyTheMissingIndicesAndIsNeverEmpty() throws {
        let mine = Self.inventory([Self.entry(item: Self.itemA, count: 9, held: [0])])
        let theirs = Self.inventory([Self.entry(item: Self.itemA, count: 9, held: [0, 3, 8])])
        let delta = try Self.delta(mine, theirs)

        let gap = try #require(delta.chunksToRequest.first)
        #expect(gap.missingIndices() == [3, 8])
        #expect(gap.missingCount == 2)
        #expect(gap.missing.count == 2, "ceil(9 / 8) bytes")
        for gap in delta.chunksToRequest + delta.chunksToOffer {
            #expect(gap.missingCount > 0, "an all-zero bitmap is not a gap and is never emitted")
        }
    }

    /// A `chunkCount` disagreement is compared over the OVERLAP and never adopted: the count is the
    /// origin's signed fact, and the manifest ask is what resolves it.
    @Test func aDisagreeingChunkCountIsComparedOverTheOverlapOnly() throws {
        let mine = Self.inventory([Self.entry(item: Self.itemA, count: 4, held: [0])])
        let theirs = Self.inventory([Self.entry(item: Self.itemA, count: 8, held: [0, 2, 6])])
        let delta = try Self.delta(mine, theirs)

        let gap = try #require(delta.chunksToRequest.first)
        #expect(gap.chunkCount == 4, "a gap carries THIS device's count")
        #expect(gap.missing.count == 1)
        #expect(gap.missingIndices() == [2], "index 6 is above the overlap and is never asked for")
        #expect(MeshRoutedInventoryEntry.bitmapIsCanonical(gap.missing, for: gap.chunkCount))
    }

    // MARK: Disjoint and superset peers

    @Test func disjointInventoriesProduceNoAskAndNoReceiptWork() throws {
        let mine = Self.inventory([Self.entry(item: Self.itemA, custody: [1])])
        let theirs = Self.inventory([Self.entry(origin: 1, item: Self.itemB, custody: [0])])
        let entitled: Set = [Self.key("fp001", Self.itemA)]
        let delta = try Self.delta(mine, theirs, entitled: entitled)

        #expect(delta.ask.isEmpty)
        #expect(delta.receiptsToForward.isEmpty)
        #expect(delta.receiptsToRequest.isEmpty)
        #expect(delta.manifestsToOffer == [Self.key("fp001", Self.itemA)])
        #expect(try #require(delta.chunksToOffer.first).missingIndices() == [0, 1, 2],
                "an absent peer entry is the empty held set")
    }

    /// The honest name for what a "superset peer" proves: keys I have never seen produce **no** ask
    /// work, because a destination set lives in the origin's signed manifest and I cannot know I am
    /// a destination of an item I do not hold. The peer's OFFER is what serves that, not my ask.
    @Test func aPeerAheadOnKeysIAlreadyHoldProducesAskWorkAndNoOfferWork() throws {
        let mine = Self.inventory([Self.entry(item: Self.itemA, count: 4, held: [0])])
        let theirs = Self.inventory([
            Self.entry(item: Self.itemA, count: 4, held: [0, 1]),
            Self.entry(origin: 1, item: Self.itemB)
        ])
        let delta = try Self.delta(mine, theirs)

        #expect(try #require(delta.chunksToRequest.first).missingIndices() == [1])
        let unseen = Self.key("fp004", Self.itemB)
        #expect(delta.ask.contains(unseen) == false)
        #expect(delta.offer.contains(unseen) == false)
        #expect(delta.manifestsToRequest.isEmpty)
    }

    // MARK: The receipt deadlocks

    /// A receipt forwarded for an item the peer does not hold is refused `unknownItem` at its ingest
    /// door — so it could never land, and the rule would re-fire every exchange.
    @Test func aReceiptForAnItemThePeerDoesNotListIsNotForwarded() throws {
        let mine = Self.inventory([Self.entry(item: Self.itemA, custody: [1], recipient: [1])])
        let theirs = Self.inventory([], members: [])
        let delta = try Self.delta(mine, theirs)

        #expect(delta.receiptsToForward.isEmpty)
        #expect(delta.receiptsToRequest.isEmpty)
    }

    /// Both ingest doors refuse a receipt for a record held PARKED, so a parked peer is un-parked by
    /// the manifest ask first and only then carries receipt work.
    @Test func aReceiptForAnItemThePeerHoldsParkedIsNotForwarded() throws {
        let mine = Self.inventory([Self.entry(item: Self.itemA, custody: [1])])
        let theirs = Self.inventory([Self.entry(item: Self.itemA, manifest: false)])
        let delta = try Self.delta(mine, theirs)

        #expect(delta.receiptsToForward.isEmpty)
        #expect(delta.manifestsToRequest.isEmpty, "my own entry is not parked, so I ask for nothing")
    }

    @Test func aReceiptIsNotRequestedWhileMyOwnEntryIsParked() throws {
        let mine = Self.inventory([Self.entry(item: Self.itemA, manifest: false)])
        let theirs = Self.inventory([Self.entry(item: Self.itemA, custody: [1])])
        let delta = try Self.delta(mine, theirs)

        #expect(delta.receiptsToRequest.isEmpty)
        #expect(delta.manifestsToRequest == [Self.key("fp001", Self.itemA)],
                "the manifest ask is what un-parks me; the receipt follows on a later exchange")
    }

    /// **D-5.17.** Two digests carrying deliberately different (but individually minimal) member
    /// tables must produce the same receipt work as two identical tables would. It fails against any
    /// `Set<UInt8>` subtraction.
    @Test func signerSetsAreComparedAsFingerprintsNotIndices() throws {
        // Mine: fp001 is the origin at 0, fp004 the custody signer at 1.
        let mine = Self.inventory([Self.entry(item: Self.itemA, custody: [1])])
        // Theirs: the SAME item, whose origin fp001 sits at index 1 behind an unrelated fp000.
        let theirs = MeshRoutedInventory(
            meshID: Self.mesh, members: ["fp000", "fp001"],
            entries: [Self.entry(origin: 1, item: Self.itemA, custody: [0])]
        )
        #expect(mine.isWellFormed)
        #expect(theirs.isWellFormed)
        let delta = try Self.delta(mine, theirs)

        #expect(delta.receiptsToForward == [
            MeshRoutedInventoryReceiptRef(key: Self.key("fp001", Self.itemA), signer: "fp004", kind: .custody)
        ])
        #expect(delta.receiptsToRequest == [
            MeshRoutedInventoryReceiptRef(key: Self.key("fp001", Self.itemA), signer: "fp000", kind: .custody)
        ])
    }

    // MARK: Entitlement

    @Test func anUnentitledItemIsNeverOffered() throws {
        let mine = Self.inventory([Self.entry(item: Self.itemA)])
        let theirs = Self.inventory([], members: [])
        let delta = try Self.delta(mine, theirs, entitled: [])

        #expect(delta.manifestsToOffer.isEmpty)
        #expect(delta.chunksToOffer.isEmpty)
        #expect(delta.ask.isEmpty)
        #expect(delta.isQuiescent)
    }

    @Test func entitlementDoesNotGateTheAsk() throws {
        let mine = Self.inventory([Self.entry(item: Self.itemA, manifest: false, count: 4, held: [0])])
        let theirs = Self.inventory([Self.entry(item: Self.itemA, count: 4, held: [0, 1])])
        let withEntitlement = try Self.delta(mine, theirs, entitled: [Self.key("fp001", Self.itemA)])
        let without = try Self.delta(mine, theirs, entitled: [])

        #expect(withEntitlement.manifestsToRequest == without.manifestsToRequest)
        #expect(withEntitlement.chunksToRequest == without.chunksToRequest)
        #expect(without.manifestsToRequest.isEmpty == false)
    }

    /// **Entitlement source 2**, without which the delta could move no bytes at all to a fresh
    /// custodian and item 8 would have to build a transfer path outside the comparison.
    @Test func anItemOfferableOnlyAsACustodyHandoffIsOffered() throws {
        let mine = Self.inventory([Self.entry(item: Self.itemA)])
        let custodian = Self.inventory([], members: [])
        let handoff: Set = [Self.key("fp001", Self.itemA)]

        let offered = try Self.delta(mine, custodian, entitled: handoff)
        #expect(offered.manifestsToOffer == [Self.key("fp001", Self.itemA)])
        #expect(offered.chunksToOffer.count == 1)

        let unentitled = try Self.delta(mine, custodian, entitled: [])
        #expect(unentitled.manifestsToOffer.isEmpty)
        #expect(unentitled.chunksToOffer.isEmpty)
    }

    // MARK: Symmetry, order and bounds

    /// The mirror holds **over the shared keys** — the unscoped version is false by construction,
    /// because a key the peer has never seen is my offer and neither side's ask.
    @Test func theOfferAndAskMirrorOverTheSharedKeys() throws {
        let mine = Self.inventory([
            Self.entry(item: Self.itemA, count: 4, held: [0, 1, 2]),
            Self.entry(origin: 1, item: Self.itemB, count: 2, held: [0, 1])
        ])
        let theirs = Self.inventory([Self.entry(item: Self.itemA, manifest: false, count: 4, held: [0])])
        let shared = Set(theirs.entries.compactMap { theirs.key(of: $0) })
        let everything = Set(mine.entries.compactMap { mine.key(of: $0) }).union(shared)

        let forward = try Self.delta(mine, theirs, entitled: everything)
        let backward = try Self.delta(theirs, mine, entitled: everything)

        #expect(forward.manifestsToOffer.filter { shared.contains($0) } == backward.manifestsToRequest)
        #expect(forward.chunksToOffer.filter { shared.contains($0.key) }.map(\.key)
                == backward.chunksToRequest.map(\.key))
        let unseen = Self.key("fp004", Self.itemB)
        #expect(forward.manifestsToOffer.contains(unseen))
        #expect(forward.manifestsToRequest.contains(unseen) == false)
        #expect(backward.manifestsToRequest.contains(unseen) == false)
        // The receipt mirror is NOT asserted here: the shared key is parked on the peer's side, so
        // both receipt rules are scoped out and `[] == []` would hold against any implementation.
        // `theReceiptMirrorHoldsWhereBothSidesHoldTheManifest` is where that claim is made.
        #expect(forward.receiptsToForward.isEmpty)
        #expect(backward.receiptsToRequest.isEmpty)
    }

    /// The receipt half of the mirror, over a pair where **both** rules can fire: what I forward is
    /// exactly what the peer requests, non-empty in both families.
    ///
    /// Its own case rather than a clause on the test above, because the shared key there is parked on
    /// one side — which scopes both receipt rules out, making the mirror `[] == []` and true of a
    /// `return []` stub. Un-parking that fixture would invalidate its manifest clauses instead.
    @Test func theReceiptMirrorHoldsWhereBothSidesHoldTheManifest() throws {
        let mine = Self.inventory([Self.entry(item: Self.itemA, custody: [1], recipient: [1])])
        let theirs = Self.inventory([Self.entry(item: Self.itemA)])

        let forward = try Self.delta(mine, theirs)
        let backward = try Self.delta(theirs, mine)

        #expect(forward.receiptsToForward.isEmpty == false)
        #expect(forward.receiptsToForward.map(\.kind) == [.custody, .recipient])
        #expect(forward.receiptsToForward == backward.receiptsToRequest)
        #expect(backward.receiptsToForward.isEmpty)
        #expect(forward.receiptsToRequest.isEmpty)
    }

    /// ``MeshRoutedInventoryDelta/ask`` and ``offer`` are **sets in canonical order**, not the two
    /// lists glued together.
    ///
    /// One key satisfies both an ask rule and a chunk rule whenever I hold it parked and the peer is
    /// both un-parked and ahead — the ordinary catch-up shape — so a concatenation would name it
    /// twice and order it manifests-then-chunks. Item 6 paces sends off these lists.
    @Test func theAskAndOfferAreDistinctKeysInCanonicalOrder() throws {
        let mine = Self.inventory([
            Self.entry(item: Self.itemA, manifest: false, count: 4, held: [0]),
            Self.entry(origin: 1, item: Self.itemB, manifest: false, count: 4, held: [0])
        ])
        let theirs = Self.inventory([
            Self.entry(item: Self.itemA, count: 4, held: [0, 1]),
            Self.entry(origin: 1, item: Self.itemB, count: 4, held: [0, 1])
        ])
        let delta = try Self.delta(mine, theirs)

        let both = [Self.key("fp001", Self.itemA), Self.key("fp004", Self.itemB)]
        #expect(delta.manifestsToRequest == both)
        #expect(delta.chunksToRequest.map(\.key) == both)
        #expect(delta.ask == delta.ask.sorted(by: MeshRoutedItemKey.isOrderedBefore))
        #expect(delta.ask == both, "each key appears once, in the digests' own order")
        #expect(Set(delta.ask).count == delta.ask.count)

        let offerable = Set(both)
        let offered = try Self.delta(theirs, mine, entitled: offerable)
        #expect(offered.manifestsToOffer.count == 2)
        #expect(offered.chunksToOffer.count == 2)
        #expect(offered.offer == both)
        #expect(Set(offered.offer).count == offered.offer.count)
    }

    @Test func everyListIsInCanonicalOrder() throws {
        let entries = [
            Self.entry(item: Self.itemA, count: 2, held: [0], custody: [1], recipient: [1]),
            Self.entry(origin: 1, item: Self.itemB, count: 2, held: [0], custody: [0], recipient: [0])
        ]
        let mine = Self.inventory(entries)
        let theirs = Self.inventory(entries.map { $0.replacing(
            heldChunks: Data([0x02]), custodySigners: [], recipientSigners: []
        ) })
        let entitled = Set(mine.entries.compactMap { mine.key(of: $0) })
        let delta = try Self.delta(mine, theirs, entitled: entitled)

        #expect(delta.chunksToOffer.map(\.key) == mine.entries.compactMap { mine.key(of: $0) })
        #expect(delta.chunksToRequest.map(\.key) == mine.entries.compactMap { mine.key(of: $0) })
        let refs = delta.receiptsToForward
        #expect(refs.count == 4)
        #expect(refs.map(\.kind) == [.custody, .recipient, .custody, .recipient])
        #expect(refs.map(\.key) == [
            Self.key("fp001", Self.itemA), Self.key("fp001", Self.itemA),
            Self.key("fp004", Self.itemB), Self.key("fp004", Self.itemB)
        ])
    }

    @Test func everyListIsBounded() throws {
        let custody = (0..<MeshRoutedInventoryFormat.maxCustodySignersPerEntry).map { UInt8($0) }
        let recipient = (0..<MeshRoutedInventoryFormat.maxRecipientSignersPerEntry).map { UInt8($0) }
        let table = (0..<MeshRoutedInventoryFormat.maxReferencedMembers)
            .map { "fp\(String(format: "%03d", $0))" }
        let mine = Self.inventory(
            [Self.entry(item: Self.itemA, custody: custody, recipient: recipient)], members: table
        )
        let theirs = Self.inventory([Self.entry(item: Self.itemA)], members: table)
        let delta = try Self.delta(mine, theirs, entitled: [Self.key("fp000", Self.itemA)])

        let refBound = MeshRoutedInventoryFormat.maxEntries
            * (MeshRoutedInventoryFormat.maxCustodySignersPerEntry
               + MeshRoutedInventoryFormat.maxRecipientSignersPerEntry)
        #expect(refBound == 1024 * 17)
        #expect(delta.receiptsToForward.count == custody.count + recipient.count)
        #expect(delta.receiptsToForward.count <= refBound)
        #expect(delta.manifestsToRequest.count <= MeshRoutedInventoryFormat.maxEntries)
        #expect(delta.chunksToRequest.count <= MeshRoutedInventoryFormat.maxEntries)
    }

    // MARK: The predicates item 7 inherits

    /// **D-5.15.** B holds nothing while A holds an item destined for B: B's delta is empty and
    /// `isQuiescent` is true, yet the pair is NOT converged. This is the test that stops item 7 from
    /// spending the one-sided predicate on the primary delivery path.
    @Test func anEmptyLocalInventoryIsQuiescentButNotConverged() throws {
        let holdsNothing = Self.inventory([], members: [])
        let holdsTheItem = Self.inventory([Self.entry(item: Self.itemA)])
        let delta = try Self.delta(holdsNothing, holdsTheItem)

        #expect(delta.isQuiescent, "one-sided by construction: I know of no work")
        #expect(MeshRoutedInventoryDelta.converged(local: delta, peerReportsQuiescent: false) == false)
        #expect(MeshRoutedInventoryDelta.converged(local: delta, peerReportsQuiescent: true))
    }

    /// **D-5.16.** A foreign-mesh pair is a refusal, never an empty delta — an empty delta would read
    /// as quiescent, i.e. as matched, which is the fail-open direction.
    @Test func aForeignMeshPairIsRefusedNotEmptied() {
        let mine = Self.inventory([Self.entry(item: Self.itemA)])
        let elsewhere = Self.inventory([Self.entry(item: Self.itemA)], members: Self.table, mesh: UUID())
        #expect(MeshRoutedInventoryDelta.between(local: mine, remote: elsewhere, offerableToPeer: []) == nil)
        #expect(MeshRoutedInventoryDelta.between(local: elsewhere, remote: mine, offerableToPeer: []) == nil)
    }

    // MARK: The four deadlock regressions item 7 inherits

    /// (a) An origin and a non-destination are never EQUAL, yet the origin is quiescent — which is
    /// why `matched` is quiescence and not equality.
    @Test func anOriginAndANonDestinationAreNeverEqualYetAreQuiescent() throws {
        let origin = Self.inventory([Self.entry(item: Self.itemA)])
        let stranger = Self.inventory([], members: [])
        let delta = try Self.delta(origin, stranger, entitled: [])

        #expect(origin != stranger)
        #expect(delta.isQuiescent)
    }

    /// (b) The origin advertises no custody of its own item, so nobody asks for a receipt it could
    /// never mint.
    @Test func theOriginDoesNotAdvertiseCustodyOfItsOwnItemSoNoOneAsksForIt() throws {
        let origin = Self.inventory([Self.entry(item: Self.itemA, custody: [])])
        let peer = Self.inventory([Self.entry(item: Self.itemA, custody: [])])
        let delta = try Self.delta(peer, origin)

        #expect(delta.receiptsToRequest.isEmpty)
        #expect(delta.isQuiescent)
    }

    /// (c) Once the recipient receipt has propagated, the pair converges and stays converged.
    @Test func afterDeliveryTheReceiptsConvergeAndThePairIsQuiescent() throws {
        let before = Self.inventory([Self.entry(item: Self.itemA, recipient: [1])])
        let behind = Self.inventory([Self.entry(item: Self.itemA)])
        #expect(try Self.delta(before, behind).receiptsToForward.count == 1)

        let after = Self.inventory([Self.entry(item: Self.itemA, recipient: [1])])
        let delta = try Self.delta(before, after)
        #expect(delta.isQuiescent)
        #expect(MeshRoutedInventoryDelta.converged(local: delta, peerReportsQuiescent: true))
    }

    /// (d) A custody transfer is visible in the digest and is asked for exactly once — the next
    /// digest, carrying the signer, produces no work.
    @Test func aCustodyTransferIsVisibleAndIsAskedForExactlyOnce() throws {
        let custodian = Self.inventory([Self.entry(item: Self.itemA, custody: [1])])
        let originBefore = Self.inventory([Self.entry(item: Self.itemA)])
        let first = try Self.delta(originBefore, custodian)
        #expect(first.receiptsToRequest == [
            MeshRoutedInventoryReceiptRef(key: Self.key("fp001", Self.itemA), signer: "fp004", kind: .custody)
        ])

        let originAfter = Self.inventory([Self.entry(item: Self.itemA, custody: [1])])
        #expect(try Self.delta(originAfter, custodian).isQuiescent)
    }

    /// Item 14's pre-assertion: one deterministic call, identical value, and no clock on either path.
    @Test func aDeltaIsOneDeterministicCallWithNoClock() throws {
        let mine = Self.inventory([Self.entry(item: Self.itemA, count: 4, held: [0, 2], custody: [1])])
        let theirs = Self.inventory([Self.entry(item: Self.itemA, count: 4, held: [1], recipient: [1])])
        let entitled: Set = [Self.key("fp001", Self.itemA)]

        let first = try Self.delta(mine, theirs, entitled: entitled)
        let second = try Self.delta(mine, theirs, entitled: entitled)
        #expect(first == second)
        #expect(first.isQuiescent == false)
    }
}
