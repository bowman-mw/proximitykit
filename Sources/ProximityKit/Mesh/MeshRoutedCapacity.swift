// MeshRoutedCapacity.swift
// ProximityKit/Mesh
//
// Network migration P5 item 9 (plan §11's backpressure clause, §3.4's "bounded everything"): the
// routed store's caps as **one** value, what an index is actually spending against them, and the
// single terminal-refusal rule that drops a parked chunk set.
//
// Three pure values, no clock, no store, no transport — which is what keeps item 9's additions to
// `MeshNetworkManager` in the one-to-three-line band while the *decisions* live here and are unit
// testable on their own.
//
// The load-bearing facts, stated once:
//
// 1. **No number is written in this file.** ``MeshRoutedCapacity/production`` is defined *as*
//    ``MeshRoutedStoreFormat``, itself derived from ``MeshRoutedManifestFormat/maxContentByteCount``
//    (the only 256 MiB in the tree), ``MeshChunkFormat/maxChunkCount`` and
//    ``MeshMembershipBounds/maxRosterMembers``.
// 2. **One cap model per process.** The capacity is injected on the store and read back off it by
//    everything that accounts, so the writer doors and the sweep can never measure against two
//    different bounds.
// 3. **The release predicate measures what the door measures.** The chunk door refuses the file cap
//    against `max(index, directory)`, so ``MeshRoutedCapacityUsage/hasRoomToAdmit`` does too — a
//    predicate that cleared a hold while the door still refused would be a surface asserting a
//    condition the store has not escaped, which is the same defect as an invisible refusal.
// 4. **A parked set is dropped for exactly one reason, and only when its own origin refused it.**
//    Every other manifest rejection keeps the bytes: see ``MeshRoutedParkedDrop/reason(rejection:senderIsClaimedOrigin:)``.

import Foundation

// MARK: - MeshRoutedCapacity

/// Every cap the routed store enforces at a writer door, as ONE injectable value.
///
/// ``production`` is the shipping model and is defined **as** the existing constants — nothing here
/// restates a number, because restating 256 MiB is precisely what
/// ``MeshRoutedManifestFormat/maxContentByteCount`` forbids and restating the roster cap would let
/// two numbers drift.
///
/// Injected through ``MeshRoutedStore/init(scope:capacity:)`` so a test can drive a door to its cap
/// in milliseconds instead of planting 1024 records — and read back off the store by
/// ``MeshRoutedCapacityUsage``, so the doors and the accounting are one model. There is no
/// `@TaskLocal`, no `static var` and no shipping knob (Power of 10 rule 6).
///
/// - Important: the two 1024s are **two different caps that happen to be equal** (items vs
///   chunks-per-item) and stay two fields; ``maxContentBytes`` is a **wire** bound and is reused,
///   never redefined.
nonisolated struct MeshRoutedCapacity: Equatable, Sendable {

    /// Most logical items the store holds at once, parked ones included.
    let maxItems: Int

    /// The store's whole CONTENT byte budget.
    let maxContentBytes: UInt64

    /// Most chunks one item holds.
    let maxChunksPerItem: Int

    /// Most sealed payload FILES the store holds, across every item.
    let maxHeldChunkFiles: Int

    /// Most receipts one item's evidence set holds, per signer role.
    let maxReceiptsPerItem: Int

    /// Builds a cap model. Tests pass deliberately small bounds; shipping code takes ``production``.
    ///
    /// - Parameters:
    ///   - maxItems: Logical items, parked ones included.
    ///   - maxContentBytes: The whole-store content budget.
    ///   - maxChunksPerItem: Chunks in one item.
    ///   - maxHeldChunkFiles: Sealed payload files across every item.
    ///   - maxReceiptsPerItem: Receipts in one item's evidence set, per signer role.
    init(
        maxItems: Int,
        maxContentBytes: UInt64,
        maxChunksPerItem: Int,
        maxHeldChunkFiles: Int,
        maxReceiptsPerItem: Int
    ) {
        self.maxItems = maxItems
        self.maxContentBytes = maxContentBytes
        self.maxChunksPerItem = maxChunksPerItem
        self.maxHeldChunkFiles = maxHeldChunkFiles
        self.maxReceiptsPerItem = maxReceiptsPerItem
    }

    /// The shipping cap model: ``MeshRoutedStoreFormat``, field for field, and nothing else.
    static let production = MeshRoutedCapacity(
        maxItems: MeshRoutedStoreFormat.maxItems,
        maxContentBytes: MeshRoutedStoreFormat.maxContentBytes,
        maxChunksPerItem: MeshRoutedStoreFormat.maxChunksPerItem,
        maxHeldChunkFiles: MeshRoutedStoreFormat.maxHeldChunkFiles,
        maxReceiptsPerItem: MeshRoutedStoreFormat.maxReceiptsPerItem
    )
}

// MARK: - MeshRoutedCapacityUsage

/// What one index is actually spending, parked sets included, against the capacity the store that
/// vended the index was built with. Derived at a read, never stored.
///
/// ## The accounting rule, written down once
///
/// 1. **Items** = every record, *parked included*. A manifest-less chunk set is a real item with a
///    real key; C10's bytes are not free.
/// 2. **Bytes** = the sum of ``MeshRoutedChunkDescriptor/payloadByteCount`` over every record, i.e.
///    exactly the sealed payload files on disk. It does **not** count the sealed index file itself
///    (manifests plus up to 16 receipts per item) — a **named** gap, bounded separately by
///    `maxItems × (1 manifest + 8 custody + 8 recipient receipts)` and measured, not guessed at.
/// 3. **Files** = `max(`the descriptors the index names, the payload files the directory actually
///    holds`)` — **exactly what the chunk door refuses against**. Orphans (a force-quit between an
///    index save and its unlinks, or an unlink the store counted as failed) are named by the
///    directory and by nothing else, so a predicate reading the index alone would clear a hold the
///    door is still refusing. An **unreadable** directory reads as "no room", never as room.
/// 4. **Receipts** = per item, per signer role; re-recording an existing signer is not growth.
/// 5. ``uncompletableItemCount`` names the over-commit the manifest door cannot refuse: the door
///    reserves `manifest.size` against **staged** bytes, so two 200 MiB manifests both admit and
///    neither can finish. It **warns only** — it never refuses, drops or reserves.
/// 6. ``unrestorableItemCount`` is counted and audited, never repaired: those items are invisible to
///    every enumerator, hold their caps until expiry, and are deliberately not a hold of their own.
///
/// ## Concurrency
///
/// A `nonisolated`, `Sendable` value derived from an index and an injected instant. No clock is read
/// and no file is touched.
nonisolated struct MeshRoutedCapacityUsage: Equatable, Sendable {

    /// The capacity this usage is measured against — the store's own, never ``MeshRoutedCapacity/production``
    /// by assumption.
    let capacity: MeshRoutedCapacity

    /// Logical items held, parked ones included.
    let itemCount: Int

    /// Content bytes actually staged, across every item.
    let contentBytesHeld: Int

    /// Sealed payload files the index names.
    let chunkFileCount: Int

    /// Sealed payload files the chunk DIRECTORY actually holds, or nil when it could not be listed.
    ///
    /// Nil is deliberately not zero: a directory this device cannot enumerate is a store whose file
    /// cap cannot be measured, and ``hasRoomToAdmit`` answers `false` for it.
    let directoryFileCount: Int?

    /// Live items held with no manifest — chunk sets that arrived ahead of their manifest (C10).
    let parkedItemCount: Int

    /// The parked slice of ``contentBytesHeld``.
    let parkedContentBytes: Int

    /// Live items with bytes still outstanding that the byte budget can no longer satisfy for
    /// everything admitted — the silent over-commit, made visible.
    let uncompletableItemCount: Int

    /// Live items whose own stored delivery map refuses to restore. Counted and audited; never
    /// repaired and never a hold of their own.
    let unrestorableItemCount: Int

    /// Measures one index against one capacity.
    ///
    /// - Parameters:
    ///   - index: The loaded index.
    ///   - now: The injected instant; expiry-sensitive counts are taken against it.
    ///   - capacity: The **store's own** capacity, never a second model.
    ///   - directoryFileCount: What the chunk directory actually holds, or nil when it could not be
    ///     listed. ``MeshRoutedStore/capacityUsage(of:at:)`` is the seam that supplies it, so a
    ///     caller cannot accidentally measure the index against one store and the disk against
    ///     another.
    init(
        index: MeshRoutedIndex, at now: Date, capacity: MeshRoutedCapacity, directoryFileCount: Int?
    ) {
        self.capacity = capacity
        self.directoryFileCount = directoryFileCount
        itemCount = index.itemCount
        contentBytesHeld = index.totalContentBytesHeld
        chunkFileCount = index.heldChunkFileCount
        let parked = index.parkedItems(at: now)
        parkedItemCount = parked.count
        parkedContentBytes = parked.reduce(0) { $0 + $1.contentBytesHeld }
        uncompletableItemCount = Self.uncompletableCount(in: index, at: now, capacity: capacity)
        unrestorableItemCount = index.itemsWithUnrestorableDelivery(at: now).count
    }

    /// Whether the store has room to admit anything at all — the **release predicate** for a
    /// `.storeFull` hold.
    ///
    /// A hold that outlives its condition is the same defect as an invisible refusal: the surface has
    /// to be true, not merely present. Which is why every clause here measures **exactly what a door
    /// refuses against**: the three STORE-level admission caps (`.capacityItems`, `.capacityBytes`,
    /// `.capacityChunkFiles`), the file one taken against `max(index, directory)` as
    /// `MeshRoutedCustody`'s chunk door takes it, plus the over-commit that no door can refuse.
    ///
    /// - Important: it is **not** a release for the three per-item caps
    ///   (`.capacityChunksPerItem` / `.capacityReceipts` / `.capacityRecipientReceipts`): those are
    ///   claims about ONE item's shape, not about this device being full, and
    ///   `MeshNetworkManager.routedStoreFullRefusals` is the narrower set that may raise the hold
    ///   this predicate releases.
    var hasRoomToAdmit: Bool {
        guard let directoryFileCount else { return false }
        return itemCount < capacity.maxItems
            && UInt64(contentBytesHeld) < capacity.maxContentBytes
            && max(chunkFileCount, directoryFileCount) < capacity.maxHeldChunkFiles
            && uncompletableItemCount == 0
    }

    /// How many live items still need bytes the whole budget can no longer supply.
    ///
    /// The test is per item and is asked of an item's OWN remaining need against the budget its
    /// siblings have not already spoken for — equivalently, every item with work left is named once
    /// the store's total commitment passes the cap, and an item that needs nothing is never named.
    /// It is a **warning**, never a refusal, precisely because a parked item's need is an upper
    /// bound: no manifest has bound its size yet.
    private static func uncompletableCount(
        in index: MeshRoutedIndex, at now: Date, capacity: MeshRoutedCapacity
    ) -> Int {
        var needs: [UInt64] = []
        // R2: bounded by `maxItems`; each need is clamped to the byte cap so the sum cannot overflow.
        for item in index.items where item.isLive(at: now) {
            needs.append(min(remainingNeed(of: item), capacity.maxContentBytes))
        }
        let committed = UInt64(index.totalContentBytesHeld) + needs.reduce(0, +)
        guard committed > capacity.maxContentBytes else { return 0 }
        return needs.filter { $0 > 0 }.count
    }

    /// One item's outstanding byte need: exact where a manifest has bound the size, an upper bound
    /// from the unheld slot count while the set is still parked.
    private static func remainingNeed(of item: MeshRoutedItemRecord) -> UInt64 {
        let held = UInt64(item.contentBytesHeld)
        if let manifest = item.manifest {
            return manifest.size > held ? manifest.size - held : 0
        }
        let outstanding = Int(item.chunkCount) - item.chunks.count
        guard outstanding > 0 else { return 0 }
        return UInt64(outstanding) * UInt64(MeshChunkFormat.maxChunkPayloadBytes)
    }
}

// MARK: - MeshRoutedParkedDrop

/// The ONE rule that turns a refused manifest into a dropped parked chunk set (plan §11's "unknown
/// type tokens are rejected, not forwarded", carried through to the bytes that rode ahead of it).
///
/// The rule has exactly one clause, and its narrowness is the design: a drop is a **destructor of
/// custody this device already holds**, so every widening is a remote delete lever until proven
/// otherwise. `unknownTypeToken` is terminal for the item under this build's registry, and it is
/// bound to `sender == manifest.originFingerprint` because the origin is the only party that could
/// have parked the set (the chunk door's own retention clause) — so binding costs nothing and closes
/// the lever.
///
/// Deliberately **not** a drop: `signatureInvalid` / `originNotAdmitted` / `originKeyMismatch` /
/// `foreignMesh` / `malformed` (unauthenticated, or a ledger view that can still converge);
/// `destinationSetInvalid` / `wrapsDoNotMatchDestinations` / `expiryMismatch` (signature-valid shape
/// refusals a corrected manifest for the same item id may follow); `originRemoved` (the mesh's
/// moderation act, not the origin's retraction — expiry collects those bytes). And never on a
/// capacity refusal, which would turn backpressure into data loss.
nonisolated enum MeshRoutedParkedDrop {

    /// Why a parked set was dropped. A frozen English audit token, logged verbatim, never localized
    /// and never user copy.
    nonisolated enum Reason: String, CaseIterable, Equatable, Sendable {
        /// The set's own origin sent a manifest whose routed type token this build does not accept.
        case unknownTypeToken
    }

    /// The drop reason for one manifest rejection, or nil when the parked bytes stay.
    ///
    /// - Parameters:
    ///   - rejection: The verifier's answer.
    ///   - senderIsClaimedOrigin: Whether the frame's sender is the manifest's own claimed origin.
    ///     Checked before the signature, exactly as the rejection itself is — which is why the clause
    ///     is bound to the only party that could have parked the set rather than to any admitted
    ///     member.
    /// - Returns: the frozen reason, or nil.
    static func reason(
        rejection: MeshRoutedManifestRejection,
        senderIsClaimedOrigin: Bool
    ) -> Reason? {
        guard senderIsClaimedOrigin else { return nil }
        switch rejection {
        case .unknownTypeToken:
            return .unknownTypeToken
        case .foreignMesh, .malformed, .originNotAdmitted, .originRemoved, .originKeyMismatch,
             .signatureInvalid, .wrapsDoNotMatchDestinations, .destinationSetInvalid, .expiryMismatch:
            return nil
        }
    }
}
