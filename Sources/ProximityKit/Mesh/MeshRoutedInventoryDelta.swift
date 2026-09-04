// MeshRoutedInventoryDelta.swift
// ProximityKit/Mesh
//
// Network migration P5 item 5 (plan §11, §10.3): the pure comparison of two routed inventories —
// what I lack that you hold, what you lack that I hold, and which receipts each of us is missing.
//
// **All the drain's policy lives here, so item 6 implements none of its own.** Six lists, six rules,
// one deterministic call with no clock and no I/O. Four of the six are pure functions of the two
// digests alone; only the two *offer* lists take an entitlement set, because offering an item to a
// peer that is neither one of its ORIGIN-SIGNED destinations nor a custodian this device chose for
// it at departure would be third-party relay — increment 2 wearing increment 1's name.
//
// Two shapes here exist because the obvious version of each is wrong in a way nothing downstream
// catches:
//
// - **The chunk halves compare SETS, never counts.** Two peers holding equally many *different*
//   chunks tie on any count-ordered rule, so all six lists come back empty and a pair that has
//   permanently lost a chunk each way reports itself converged.
// - **Quiescence is ONE-SIDED.** Every ask rule requires "my entry exists" and every offer rule
//   requires me to hold the item, so a device holding **nothing** computes an empty delta against
//   every peer — including a peer holding an item addressed to it that it has never seen. That false
//   positive is *stable*, not transient, so ``MeshRoutedInventoryDelta/isQuiescent`` is never the
//   merge window's predicate on its own: ``MeshRoutedInventoryDelta/converged(local:peerReportsQuiescent:)``
//   is.

import Foundation

// MARK: - MeshRoutedInventoryReceiptKind

/// Which receipt family a missing signature belongs to. Frozen English; the spellings are compared,
/// never displayed.
nonisolated enum MeshRoutedInventoryReceiptKind: String, CaseIterable, Equatable, Sendable {
    /// A `MeshCustodyReceipt` — a custodian durably holds the item's complete ciphertext.
    case custody
    /// A `MeshRecipientReceipt` — a destination received the item, finally.
    case recipient
}

// MARK: - MeshRoutedInventoryReceiptRef

/// One receipt the comparison names: which item, whose signature, and which family.
///
/// The signer is a **resolved fingerprint, never an index**. Each digest's member table is minimal
/// *per digest*, so index 1 on one side and index 1 on the other are unrelated fingerprints by
/// construction; a `Set<UInt8>` subtraction across two tables silently yields both false forwards and
/// false gaps, with no compile error and no test failure.
nonisolated struct MeshRoutedInventoryReceiptRef: Hashable, Sendable {
    /// The item the receipt is about — the signed pair.
    let key: MeshRoutedItemKey
    /// The receipt's signer: a custodian or a destination, as a fingerprint.
    let signer: String
    /// Which receipt family.
    let kind: MeshRoutedInventoryReceiptKind

    /// Builds a reference to one missing receipt.
    init(key: MeshRoutedItemKey, signer: String, kind: MeshRoutedInventoryReceiptKind) {
        self.key = key
        self.signer = signer
        self.kind = kind
    }
}

// MARK: - MeshRoutedChunkGap

/// One item's chunk difference: which slots the other side holds that this side does not (or the
/// mirror, for an offer).
///
/// ``missing`` is a canonical bitmap in ``MeshRoutedInventoryEntry``'s frozen bit order, over **this
/// device's** ``chunkCount``, and it is never all-zero — an empty difference is not a gap and is not
/// emitted. No bit above the two sides' overlap is ever set: a peer's larger chunk-count claim is
/// neither believed nor asked for, because the count is the origin's signed fact and the manifest
/// ask is what resolves a disagreement.
nonisolated struct MeshRoutedChunkGap: Equatable, Sendable {
    /// The item — the signed pair.
    let key: MeshRoutedItemKey
    /// This device's chunk count for the item, which is the bitmap's index space.
    let chunkCount: UInt32
    /// The difference, as a canonical bitmap.
    let missing: Data

    /// Builds a gap from an already-computed difference.
    init(key: MeshRoutedItemKey, chunkCount: UInt32, missing: Data) {
        self.key = key
        self.chunkCount = chunkCount
        self.missing = missing
    }

    /// How many slots differ — the bitmap's popcount.
    var missingCount: Int {
        var total = 0
        // R2: bounded by `maxHeldChunkBitmapBytes`.
        for byte in missing { total += byte.nonzeroBitCount }
        return total
    }

    /// The differing indices, ascending. Expanded **on demand, one item at a time**, never over a
    /// whole delta at once.
    func missingIndices() -> [UInt32] {
        var indices: [UInt32] = []
        // R2: bounded by `maxHeldChunkBitmapBytes`.
        for byte in 0..<missing.count {
            let value = missing[missing.startIndex + byte]
            guard value != 0 else { continue }
            // R2: eight bits.
            for bit in 0..<8 where value & (UInt8(1) << UInt8(bit)) != 0 {
                indices.append(UInt32(byte * 8 + bit))
            }
        }
        return indices
    }
}

// MARK: - MeshRoutedInventoryDelta

/// The six work lists two routed inventories imply, in the digests' own canonical order.
///
/// Pure, deterministic, no clock, no I/O: two calls on the same inputs produce identical values.
/// Every list is bounded — the two key lists and the two gap lists by
/// ``MeshRoutedInventoryFormat/maxEntries``, the two receipt lists by `maxEntries ×
/// (maxCustodySignersPerEntry + maxRecipientSignersPerEntry)`. The receipt lists are a **work list,
/// not a frame**: the caller paces them and must not put one on the wire whole.
///
/// The offer lists take their entitlement from the caller, and there are exactly **two** honest
/// sources for it, both rooted in the origin's signed manifest:
///
/// 1. **The peer is a destination with work outstanding** —
///    `index.outstandingItems(at:in:)[peer]`, which is plan §11's "destinations lacking a
///    `MeshRecipientReceipt`", partition-agnostic by construction and with `delivered` and `departed`
///    already excluded (this is what kills the re-delivery loop).
/// 2. **The peer is a custodian this device chose at departure** —
///    `index.itemsAwaitingHandoff(at:in:)` restricted to a peer in
///    `MeshDevelopmentPlan.handoffTargets`. This is increment 1's own load-bearing case: without it
///    the delta could move **no bytes at all** to a fresh custodian.
///
/// Two classes of held item can be *advertised* but generate no offer under source 1, and both are
/// named rather than silently dropped: an item whose delivery map will not restore (its destinations
/// cannot be named) and a **parked** item (no manifest ⇒ no destination set). A parked device
/// completes by **asking** instead — it has an entry, so both ask rules fire.
///
/// What the delta deliberately does **not** carry: any custody-candidate list (a hand-off is
/// departure-driven and directed, not digest-driven, and a candidate is not work this exchange must
/// finish — putting it here would make quiescence dishonest), and any representation of a peer's
/// capacity refusal (the caller narrows the entitlement set with its own per-peer, per-session
/// refused set, which keeps the delta a pure function of its inputs).
nonisolated struct MeshRoutedInventoryDelta: Equatable, Sendable {
    /// Items I hold parked that the peer holds a manifest for.
    let manifestsToRequest: [MeshRoutedItemKey]
    /// Items I hold where the peer holds chunks I lack, with the exact indices.
    let chunksToRequest: [MeshRoutedChunkGap]
    /// Entitled items I hold a manifest for that the peer lacks or holds parked.
    let manifestsToOffer: [MeshRoutedItemKey]
    /// Entitled items where I hold chunks the peer lacks, with the exact indices.
    let chunksToOffer: [MeshRoutedChunkGap]
    /// Receipts I hold that the peer's entry does not list.
    let receiptsToForward: [MeshRoutedInventoryReceiptRef]
    /// Receipts the peer lists that my entry does not.
    let receiptsToRequest: [MeshRoutedInventoryReceiptRef]

    /// Builds a delta from already-computed lists. The comparison below is the only production
    /// caller.
    init(
        manifestsToRequest: [MeshRoutedItemKey],
        chunksToRequest: [MeshRoutedChunkGap],
        manifestsToOffer: [MeshRoutedItemKey],
        chunksToOffer: [MeshRoutedChunkGap],
        receiptsToForward: [MeshRoutedInventoryReceiptRef],
        receiptsToRequest: [MeshRoutedInventoryReceiptRef]
    ) {
        self.manifestsToRequest = manifestsToRequest
        self.chunksToRequest = chunksToRequest
        self.manifestsToOffer = manifestsToOffer
        self.chunksToOffer = chunksToOffer
        self.receiptsToForward = receiptsToForward
        self.receiptsToRequest = receiptsToRequest
    }

    /// Every item this device needs something for: **distinct keys, in canonical order**.
    ///
    /// Not a concatenation of the two ask lists. One key satisfies both rules whenever I hold it
    /// parked and the peer both holds the manifest and is ahead on chunks — the ordinary shape of a
    /// device catching up — so a concatenation names it twice, and it is ordered
    /// manifests-then-chunks rather than in the digests' own order. Item 6 paces its sends off this
    /// list, so a repeat is a double send and a per-key budget spent twice.
    var ask: [MeshRoutedItemKey] {
        Self.canonicalUnion(manifestsToRequest, chunksToRequest.map(\.key))
    }

    /// Every item this device can move to the peer: **distinct keys, in canonical order**, with the
    /// same reasoning as ``ask``.
    var offer: [MeshRoutedItemKey] {
        Self.canonicalUnion(manifestsToOffer, chunksToOffer.map(\.key))
    }

    /// The two lists as one distinct set in ``MeshRoutedItemKey``'s own order.
    ///
    /// Each input is already distinct and ascending (both are emitted over one pass of the local
    /// keys), so the only duplicate possible is a key present in both, and re-sorting the union is
    /// what makes the pair's order the digests' order rather than "manifests, then chunks".
    private static func canonicalUnion(
        _ first: [MeshRoutedItemKey], _ second: [MeshRoutedItemKey]
    ) -> [MeshRoutedItemKey] {
        let named = Set(first)
        let merged = first + second.filter { !named.contains($0) }
        return merged.sorted(by: MeshRoutedItemKey.isOrderedBefore)
    }

    /// All six lists empty.
    ///
    /// **Strictly local**: "nothing *I* know I owe or need". It is **not** convergence, and it is
    /// never the merge window's predicate on its own — a device holding nothing is quiescent against
    /// every peer, including one holding an item addressed to it. Use
    /// ``converged(local:peerReportsQuiescent:)``.
    var isQuiescent: Bool {
        manifestsToRequest.isEmpty && chunksToRequest.isEmpty
            && manifestsToOffer.isEmpty && chunksToOffer.isEmpty
            && receiptsToForward.isEmpty && receiptsToRequest.isEmpty
    }

    /// The routed half of "this peer has nothing left to give me and I have nothing left to give
    /// it": **both** sides report no local work.
    ///
    /// The peer's bit is its own ``isQuiescent`` against the digest it just verified, carried back on
    /// the drain's answer — one Bool, not a field on the digest, because the digest describes a disk
    /// while this describes a comparison. It terminates: once the last transfer lands, the next
    /// exchange has both sides reporting true.
    ///
    /// - Parameters:
    ///   - local: This device's delta against the peer's digest.
    ///   - peerReportsQuiescent: What the peer said about its own delta against ours.
    static func converged(local: MeshRoutedInventoryDelta, peerReportsQuiescent: Bool) -> Bool {
        local.isQuiescent && peerReportsQuiescent
    }

    /// The six lists two inventories imply.
    ///
    /// - Parameters:
    ///   - local: This device's holdings.
    ///   - remote: The peer's **verified** holdings.
    ///   - offerableToPeer: The keys this device may move to this peer — the union of the two
    ///     entitlement sources named on the type. Empty is a legal, meaningful answer: it removes
    ///     both offer lists and leaves the ask untouched.
    /// - Returns: the delta, or **nil** when the two digests name different meshes. Never an empty
    ///   delta for that case: an empty delta reads as quiescent, i.e. as *matched*, which is the
    ///   fail-open direction for the one predicate a merge window closes on. A foreign-mesh pair is a
    ///   precondition failure the caller logs — the verifier has already refused it.
    static func between(
        local: MeshRoutedInventory,
        remote: MeshRoutedInventory,
        offerableToPeer: Set<MeshRoutedItemKey>
    ) -> MeshRoutedInventoryDelta? {
        guard local.meshID == remote.meshID else { return nil }
        let sides = MeshRoutedInventorySides(local: local, remote: remote)
        return MeshRoutedInventoryDelta(
            manifestsToRequest: sides.manifestsToRequest(),
            chunksToRequest: sides.chunksToRequest(),
            manifestsToOffer: sides.manifestsToOffer(entitled: offerableToPeer),
            chunksToOffer: sides.chunksToOffer(entitled: offerableToPeer),
            receiptsToForward: sides.receiptsToForward(),
            receiptsToRequest: sides.receiptsToRequest()
        )
    }
}

// MARK: - MeshRoutedInventorySides

/// The two inventories with their signer indices **resolved to fingerprints once**, keyed by the
/// signed pair — the shape every rule below reads.
///
/// Resolution happens here rather than inside each rule for correctness, not tidiness: a member
/// table is minimal per digest, so comparing raw `UInt8` indices across two tables is a silent
/// mis-comparison. An entry whose origin index does not index its own table is **skipped**; the
/// verifier refuses such a digest long before this, so the case is unreachable from the wire.
private nonisolated struct MeshRoutedInventorySides {

    /// One side's entry with its two signer sets already resolved.
    struct Resolved {
        /// The advertised entry.
        let entry: MeshRoutedInventoryEntry
        /// Custody-receipt signers, as fingerprints.
        let custodySigners: Set<String>
        /// Recipient-receipt signers, as fingerprints.
        let recipientSigners: Set<String>

        /// The signer set for one receipt family.
        func signers(for kind: MeshRoutedInventoryReceiptKind) -> Set<String> {
            switch kind {
            case .custody: return custodySigners
            case .recipient: return recipientSigners
            }
        }
    }

    /// This device's keys, in the digest's canonical order — every list is emitted in it.
    let localKeys: [MeshRoutedItemKey]
    /// This device's resolved entries.
    let mine: [MeshRoutedItemKey: Resolved]
    /// The peer's resolved entries.
    let theirs: [MeshRoutedItemKey: Resolved]

    /// Resolves both sides once.
    init(local: MeshRoutedInventory, remote: MeshRoutedInventory) {
        let resolvedLocal = Self.resolve(local)
        localKeys = resolvedLocal.order
        mine = resolvedLocal.entries
        theirs = Self.resolve(remote).entries
    }

    /// Items I hold parked whose manifest the peer holds.
    func manifestsToRequest() -> [MeshRoutedItemKey] {
        var keys: [MeshRoutedItemKey] = []
        // R2: bounded by `maxEntries`.
        for key in localKeys {
            guard let mine = mine[key], !mine.entry.holdsManifest else { continue }
            guard let theirs = theirs[key], theirs.entry.holdsManifest else { continue }
            keys.append(key)
        }
        return keys
    }

    /// Items I hold where the peer holds chunks I lack.
    func chunksToRequest() -> [MeshRoutedChunkGap] {
        var gaps: [MeshRoutedChunkGap] = []
        // R2: bounded by `maxEntries`.
        for key in localKeys {
            guard let mine = mine[key], let theirs = theirs[key] else { continue }
            let missing = mine.entry.missingChunks(against: theirs.entry)
            guard let gap = Self.gap(key: key, entry: mine.entry, missing: missing) else { continue }
            gaps.append(gap)
        }
        return gaps
    }

    /// Entitled items whose manifest I hold and the peer lacks or holds parked.
    func manifestsToOffer(entitled: Set<MeshRoutedItemKey>) -> [MeshRoutedItemKey] {
        var keys: [MeshRoutedItemKey] = []
        // R2: bounded by `maxEntries`.
        for key in localKeys where entitled.contains(key) {
            guard let mine = mine[key], mine.entry.holdsManifest else { continue }
            guard theirs[key]?.entry.holdsManifest != true else { continue }
            keys.append(key)
        }
        return keys
    }

    /// Entitled items where I hold chunks the peer lacks. An absent peer entry is the empty held
    /// set, so the whole of mine is the gap.
    func chunksToOffer(entitled: Set<MeshRoutedItemKey>) -> [MeshRoutedChunkGap] {
        var gaps: [MeshRoutedChunkGap] = []
        // R2: bounded by `maxEntries`.
        for key in localKeys where entitled.contains(key) {
            guard let mine = mine[key] else { continue }
            let missing = theirs[key].map { mine.entry.chunksHeldBeyond($0.entry) }
                ?? mine.entry.heldChunks
            guard let gap = Self.gap(key: key, entry: mine.entry, missing: missing) else { continue }
            gaps.append(gap)
        }
        return gaps
    }

    /// Receipts I list that the peer's entry does not.
    ///
    /// Scoped by the peer's entry **existing and being un-parked**, because both ingest doors refuse
    /// a receipt for an item the peer does not hold or holds parked — a receipt forwarded into either
    /// state can never land, so the rule would re-fire every exchange and the pair would never reach
    /// quiescence.
    func receiptsToForward() -> [MeshRoutedInventoryReceiptRef] {
        var refs: [MeshRoutedInventoryReceiptRef] = []
        // R2: bounded by `maxEntries`.
        for key in localKeys {
            guard let mine = mine[key], let theirs = theirs[key], theirs.entry.holdsManifest else {
                continue
            }
            refs.append(contentsOf: Self.refs(key: key, listing: mine, lacking: theirs))
        }
        return refs
    }

    /// Receipts the peer lists that my entry does not. The mirror of the forward rule, scoped by
    /// **my own** entry being un-parked: a receipt I request while parked is refused by my own store.
    func receiptsToRequest() -> [MeshRoutedInventoryReceiptRef] {
        var refs: [MeshRoutedInventoryReceiptRef] = []
        // R2: bounded by `maxEntries`.
        for key in localKeys {
            guard let mine = mine[key], mine.entry.holdsManifest, let theirs = theirs[key] else {
                continue
            }
            refs.append(contentsOf: Self.refs(key: key, listing: theirs, lacking: mine))
        }
        return refs
    }

    /// The refs `listing` names that `lacking` does not, custody family first, then signer ascending.
    private static func refs(
        key: MeshRoutedItemKey, listing: Resolved, lacking: Resolved
    ) -> [MeshRoutedInventoryReceiptRef] {
        var refs: [MeshRoutedInventoryReceiptRef] = []
        // R2: two cases.
        for kind in MeshRoutedInventoryReceiptKind.allCases {
            let missing = listing.signers(for: kind).subtracting(lacking.signers(for: kind))
            // R2: bounded by the per-entry signer caps.
            for signer in missing.sorted() {
                refs.append(MeshRoutedInventoryReceiptRef(key: key, signer: signer, kind: kind))
            }
        }
        return refs
    }

    /// A gap for `missing`, or nil when nothing differs — an all-zero bitmap is not a gap.
    private static func gap(
        key: MeshRoutedItemKey, entry: MeshRoutedInventoryEntry, missing: Data
    ) -> MeshRoutedChunkGap? {
        let gap = MeshRoutedChunkGap(key: key, chunkCount: entry.chunkCount, missing: missing)
        guard gap.missingCount > 0 else { return nil }
        return gap
    }

    /// One inventory's entries, keyed and resolved, plus its canonical key order.
    private static func resolve(
        _ inventory: MeshRoutedInventory
    ) -> (order: [MeshRoutedItemKey], entries: [MeshRoutedItemKey: Resolved]) {
        var order: [MeshRoutedItemKey] = []
        var resolved: [MeshRoutedItemKey: Resolved] = [:]
        // R2: bounded by `maxEntries`.
        for entry in inventory.entries {
            guard let key = inventory.key(of: entry) else { continue }
            order.append(key)
            resolved[key] = Resolved(
                entry: entry,
                custodySigners: fingerprints(entry.custodySigners, in: inventory),
                recipientSigners: fingerprints(entry.recipientSigners, in: inventory)
            )
        }
        return (order, resolved)
    }

    /// `indices` resolved through `inventory`'s own member table. An out-of-range index is skipped —
    /// the verifier refuses such a digest before this.
    private static func fingerprints(_ indices: [UInt8], in inventory: MeshRoutedInventory) -> Set<String> {
        var names: Set<String> = []
        // R2: bounded by the per-entry signer caps.
        for index in indices where Int(index) < inventory.members.count {
            names.insert(inventory.members[Int(index)])
        }
        return names
    }
}
