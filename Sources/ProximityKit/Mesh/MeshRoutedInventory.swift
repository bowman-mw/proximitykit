// MeshRoutedInventory.swift
// ProximityKit/Mesh
//
// Network migration P5 item 5 (plan §11): the ROUTED CONTENT digest — the bounded ID lists one
// device advertises so a peer can decide what to ask for and what to offer.
//
// **This is not the membership digest, and the two must never be confused.** P4's
// `MeshInventoryDigest` / `fernlet.mesh.inventory-digest.v1` summarises a MEMBERSHIP LEDGER with
// four counts and a rollup hash. This summarises a ROUTED STORE with a per-item list, under its own
// frozen token `fernlet.mesh.routed-inventory-digest.v1` and its own signature domain. The wire
// vocabulary deliberately shares the `inventory-digest` spelling — a `grep` for it returns BOTH
// families — so the separation that actually holds is over Swift value types: no routed value type
// here carries the stem `InventoryDigest`, and no membership value type carries `Routed`.
// `MeshRoutedInventoryGoldenTests.theDigestNamesDoNotCollide` is the mechanical half.
//
// What an entry says, and why each half is exactly the shape it is:
//
// - The **signed pair** `(origin, itemID)`, never a bare item id (D11): routed frames are signed but
//   unsealed, so one id can be squatted under two origins and an offer computed from a bare id would
//   hand content to the wrong destination set.
// - An **exact held-chunk bitmap**, never a count. Held sets are not nested prefixes — a free slot,
//   an out-of-order arrival and a chunk-file repair all punch holes — so two peers holding equally
//   many DIFFERENT chunks would compare as converged under a count-ordered rule, with no later stage
//   to catch it. The bitmap is the set itself: exact, fixed-width, nothing probabilistic (plan §11
//   declines Bloom filters and sketches by name).
// - Two **signer index lists** rather than an evidence hash, so a difference names WHICH
//   `(key, signer, kind)` is missing instead of only "we differ".
//
// What is deliberately NOT here: destination sets, `typeToken`, `size`, `contentHash` (all the
// ORIGIN-signed manifest's — a second advertiser-signed copy could disagree with it); `firstSeenAt`
// (receiver-local, never on the wire); `custodiedAt` / `deliveredAt` (the receipts carry the signed
// instants); any delivery-state token or map; a STORED held-chunk count (the popcount is derived, so
// it cannot disagree); per-chunk hashes or payloads; chunk file names (opaque local UUIDs); any
// `keyEpoch`, branch id, partition id, hop count or TTL; any rollup hash; and any schema integer —
// the `.v1` in the token IS the version.
//
// Built and unwired, exactly as items 1–4 left the manifest, chunk and receipts: no send, no
// receive, no dispatch case, no manager edit, no persistence, no wipe row.

import FernletCrypto
import Foundation

// MARK: - MeshRoutedInventoryFormat

/// Fixed bounds of the routed-inventory wire family (network migration P5 item 5, plan §11).
///
/// Every constant is **reused, never invented**: restating 1024 or 64 here is how two bounds drift
/// apart. The two signer caps are deliberately different numbers derived from different constants —
/// see each one's note.
nonisolated enum MeshRoutedInventoryFormat {
    /// Most entries one digest carries — plan §11's 1024-item cap, restated from the store's own.
    static let maxEntries = MeshRoutedStoreFormat.maxItems

    /// Most distinct fingerprints the member table may name.
    ///
    /// The **admission** cap (16), not the roster's (8), on purpose: over a mesh's life more members
    /// can have been admitted than are ever seated at once, and a departed origin's items are still
    /// held — a digest that cannot name a departed custodian is a digest that strands its receipt.
    static let maxReferencedMembers = MeshMembershipBounds.maxRecordsPerKind

    /// Most custody signers one entry may list: the 8 receipts a record stores, plus **one** for
    /// this device's own custody, which is never stored (it is re-minted from the witness).
    static let maxCustodySignersPerEntry = MeshRoutedStoreFormat.maxReceiptsPerItem + 1

    /// Most recipient signers one entry may list — the 8 a record stores, this device's own already
    /// among them, so there is no `+ 1` here.
    static let maxRecipientSignersPerEntry = MeshRoutedStoreFormat.maxReceiptsPerItem

    /// Most chunks one item declares — ``MeshChunkFormat/maxChunkCount``, reused.
    static let maxChunkCount = MeshChunkFormat.maxChunkCount

    /// Widest held-chunk bitmap: `ceil(maxChunkCount / 8)` = 128 bytes.
    static let maxHeldChunkBitmapBytes = (maxChunkCount + 7) / 8

    /// Cap on a fingerprint's UTF-8 length, shared with the routed family.
    static let maxFingerprintLength = MeshRoutedManifestFormat.maxFingerprintLength

    /// Ed25519 signature length, shared with the routed family.
    static let signatureByteCount = MeshRoutedManifestFormat.signatureByteCount
}

// MARK: - MeshRoutedInventoryEntry

/// One held item, as the advertiser summarises it: the signed pair, whether the manifest is held,
/// the item's chunk count, the **exact** held-chunk set, and the receipt signers this device can
/// hand over or is holding.
///
/// **The bitmap's bit order is frozen with the rest of the wire vocabulary.** Bit `i` lives in byte
/// `i / 8` at the position `i % 8` counted from that byte's LEAST-significant bit; the map is
/// exactly `ceil(chunkCount / 8)` bytes; and every bit at an index ≥ ``chunkCount`` is **zero**. The
/// trailing-zero rule is not tidiness — without it two encodings of one held set differ, and set
/// equality over the digest (the whole comparison surface) breaks.
///
/// **``recipientSigners`` *is* "delivered"** — a recipient receipt from destination D is the signed
/// evidence that D got it, so delivery state needs no field of its own, and an unsigned copy of it
/// would be a second source of truth. **``custodySigners`` *is* "custody held"**, and it includes
/// this device when it holds custody of somebody else's item, which is what makes a custody transfer
/// visible to the origin.
///
/// **A parked entry carries empty signer lists, always.** Both ingest doors refuse a receipt for a
/// record held parked, and a custody commit refuses a parked item outright — so `holdsManifest`
/// false and a non-empty signer list is a state no store produces, and the delta's receipt rules are
/// scoped by it.
nonisolated struct MeshRoutedInventoryEntry: Codable, Equatable, Sendable {
    /// Index into ``MeshRoutedInventory/members`` of the item's ORIGIN. With ``itemID`` this is the
    /// store's union key (D11).
    let originIndex: UInt8
    /// The routed item — `MeshRoutedManifest.itemID`.
    let itemID: UUID
    /// Whether the origin's signed manifest is held. `false` ⇒ **parked**: chunks without a
    /// manifest. Advertised, never hidden — a parked device asks its way to the manifest.
    let holdsManifest: Bool
    /// The item's total chunk count, 1 … ``MeshRoutedInventoryFormat/maxChunkCount``. The ORIGIN's
    /// signed fact, carried here as this device knows it and never adopted from a peer.
    let chunkCount: UInt32
    /// The exact held set as a bitmap, `ceil(chunkCount / 8)` bytes.
    let heldChunks: Data
    /// Ascending, distinct member indices whose custody receipts this device can hand over.
    let custodySigners: [UInt8]
    /// Ascending, distinct member indices whose recipient receipts this device holds.
    let recipientSigners: [UInt8]

    /// Builds an entry verbatim. Nothing is clamped, sorted or repaired — a malformed entry is
    /// **refused** at the verifier, never quietly fixed here.
    init(
        originIndex: UInt8,
        itemID: UUID,
        holdsManifest: Bool,
        chunkCount: UInt32,
        heldChunks: Data,
        custodySigners: [UInt8],
        recipientSigners: [UInt8]
    ) {
        self.originIndex = originIndex
        self.itemID = itemID
        self.holdsManifest = holdsManifest
        self.chunkCount = chunkCount
        self.heldChunks = heldChunks
        self.custodySigners = custodySigners
        self.recipientSigners = recipientSigners
    }

    /// Decodes through the memberwise initializer, so the two doors cannot drift.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            originIndex: try container.decode(UInt8.self, forKey: .originIndex),
            itemID: try container.decode(UUID.self, forKey: .itemID),
            holdsManifest: try container.decode(Bool.self, forKey: .holdsManifest),
            chunkCount: try container.decode(UInt32.self, forKey: .chunkCount),
            heldChunks: try container.decode(Data.self, forKey: .heldChunks),
            custodySigners: try container.decode([UInt8].self, forKey: .custodySigners),
            recipientSigners: try container.decode([UInt8].self, forKey: .recipientSigners)
        )
    }

    /// How many chunks are held — the bitmap's **popcount**, derived on every read.
    ///
    /// Never a stored field: a stored copy is a second representation of one fact that can disagree
    /// with the first.
    var heldChunkCount: Int {
        var total = 0
        // R2: bounded by `maxHeldChunkBitmapBytes`.
        for byte in heldChunks { total += byte.nonzeroBitCount }
        return total
    }

    /// Whether every declared chunk is held. Derived, never a `Bool` field.
    var isComplete: Bool { heldChunkCount == Int(chunkCount) }

    /// The canonical byte width of this entry's bitmap.
    var bitmapByteCount: Int { Self.bitmapByteCount(forChunkCount: chunkCount) }

    /// Whether chunk `index` is held. One index computation, no loop.
    func holdsChunk(_ index: UInt32) -> Bool {
        let byte = Int(index) / 8
        guard byte >= 0, byte < heldChunks.count else { return false }
        let mask = UInt8(1) << UInt8(Int(index) % 8)
        return heldChunks[heldChunks.startIndex + byte] & mask != 0
    }

    /// The chunks `other` holds that this entry lacks — the **ask** direction.
    ///
    /// The result is a canonical bitmap over **this** entry's index space, and no bit above the two
    /// entries' overlap is ever set: the two sides may legitimately declare different chunk counts
    /// (one learned it from the manifest, the other from a chunk header), and the count is the
    /// ORIGIN's signed fact — never something to adopt on a peer's word. The manifest ask is what
    /// resolves a disagreement; this never believes the peer's excess claim.
    func missingChunks(against other: MeshRoutedInventoryEntry) -> Data {
        Self.difference(
            other.heldChunks, minus: heldChunks,
            width: bitmapByteCount, overlap: Swift.min(chunkCount, other.chunkCount)
        )
    }

    /// The chunks this entry holds that `other` lacks — the **offer** direction, in this entry's
    /// index space and over the same overlap, so an offer never claims a slot the peer's own count
    /// does not have.
    func chunksHeldBeyond(_ other: MeshRoutedInventoryEntry) -> Data {
        Self.difference(
            heldChunks, minus: other.heldChunks,
            width: bitmapByteCount, overlap: Swift.min(chunkCount, other.chunkCount)
        )
    }

    /// `ceil(chunkCount / 8)` — the one place the bitmap's width is computed.
    static func bitmapByteCount(forChunkCount count: UInt32) -> Int {
        (Int(count) + 7) / 8
    }

    /// Whether `map` is the canonical bitmap of an item declaring `chunkCount` chunks: exactly
    /// `ceil(chunkCount / 8)` bytes, with no bit set at an index ≥ `chunkCount`.
    static func bitmapIsCanonical(_ map: Data, for chunkCount: UInt32) -> Bool {
        guard map.count == bitmapByteCount(forChunkCount: chunkCount) else { return false }
        // R2: bounded by `maxHeldChunkBitmapBytes`.
        for byte in 0..<map.count {
            let live = overlapMask(byte: byte, overlap: chunkCount)
            guard map[map.startIndex + byte] & ~live == 0 else { return false }
        }
        return true
    }

    /// `holder` minus `absentee`, as a canonical bitmap `width` bytes wide with every bit at an
    /// index ≥ `overlap` cleared. The one bit-twiddling site, so the frozen bit order lives once.
    private static func difference(
        _ holder: Data, minus absentee: Data, width: Int, overlap: UInt32
    ) -> Data {
        guard width > 0 else { return Data() }
        var bytes = Data(repeating: 0, count: width)
        // R2: bounded by `maxHeldChunkBitmapBytes`.
        for byte in 0..<width {
            let held = byte < holder.count ? holder[holder.startIndex + byte] : 0
            let have = byte < absentee.count ? absentee[absentee.startIndex + byte] : 0
            bytes[byte] = held & ~have & overlapMask(byte: byte, overlap: overlap)
        }
        return bytes
    }

    /// The bits of byte `byte` that lie below `overlap`: `0xFF` for a whole byte, a partial mask for
    /// the byte the overlap ends in, `0` above it.
    private static func overlapMask(byte: Int, overlap: UInt32) -> UInt8 {
        let low = byte * 8
        guard UInt64(low) < UInt64(overlap) else { return 0 }
        guard UInt64(low) + 8 > UInt64(overlap) else { return 0xFF }
        let bits = Int(overlap) - low
        return UInt8((1 << bits) - 1)
    }
}

// MARK: - MeshRoutedInventory

/// This device's advertisable routed holdings: the mesh it is about, a minimal fingerprint table,
/// and one entry per live held item in the store's own canonical order.
///
/// **Equality IS the comparison surface.** With entries canonically ordered and ``members`` minimal,
/// `==` over the value is set equality of the advertised holdings — which is why a mis-ordered or
/// non-minimal value is **refused** at the verifier rather than repaired at the decode: a repairing
/// decode would make the refusal unreachable, and two encodings of one holdings set would compare
/// unequal.
///
/// There is **no rollup hash**: the list *is* the digest. A hash is a second representation of one
/// fact that can disagree with the first, and it buys nothing, because the consumer needs the
/// elements to compute a difference and the list therefore travels anyway.
///
/// A digest for another mesh is a **refusal, not a difference** — the verifier refuses it, and
/// ``MeshRoutedInventoryDelta/between(local:remote:offerableToPeer:)`` answers `nil` rather than an
/// empty delta.
///
/// Pure value; nothing here reads a clock, opens a file or touches a key.
nonisolated struct MeshRoutedInventory: Codable, Equatable, Sendable {
    /// The mesh these holdings belong to.
    let meshID: UUID
    /// Every fingerprint any entry references — origins **and** receipt signers — sorted ascending,
    /// distinct, and **minimal** (nothing listed that no entry references). `UInt8` positions in
    /// this table are what the entries carry, which is what keeps a maximal digest ~196 KiB instead
    /// of ~2.4 MB of inlined fingerprints.
    let members: [String]
    /// The held items, in ``MeshRoutedItemKey/isOrderedBefore(_:_:)`` order, at most
    /// ``MeshRoutedInventoryFormat/maxEntries``.
    let entries: [MeshRoutedInventoryEntry]

    /// Builds an inventory **verbatim**: no sort, no clamp, no repair. The builder in
    /// `MeshRoutedInventoryBuilder.swift` is the only production caller.
    init(meshID: UUID, members: [String], entries: [MeshRoutedInventoryEntry]) {
        self.meshID = meshID
        self.members = members
        self.entries = entries
    }

    /// Decodes through the memberwise initializer, so the two doors cannot drift — and, exactly as
    /// there, stores what arrived: an over-cap list is refused by name at the verifier, never
    /// clamped, and a mis-ordered list is refused, never sorted.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            meshID: try container.decode(UUID.self, forKey: .meshID),
            members: try container.decode([String].self, forKey: .members),
            entries: try container.decode([MeshRoutedInventoryEntry].self, forKey: .entries)
        )
    }

    /// The signed pair `entry` names, or nil when its origin index is out of the member table.
    func key(of entry: MeshRoutedInventoryEntry) -> MeshRoutedItemKey? {
        let position = Int(entry.originIndex)
        guard position >= 0, position < members.count else { return nil }
        return MeshRoutedItemKey(originFingerprint: members[position], itemID: entry.itemID)
    }

    /// Whether every bounded collection is inside its cap. Checked on **untrusted bytes** before any
    /// signature verify, and its own rejection — an over-cap digest is refused **by name**
    /// (``MeshRoutedInventoryRejection/overCapacity``), never clamped: clamping a *list* silently
    /// claims not to hold something.
    var isWithinCaps: Bool {
        members.count <= MeshRoutedInventoryFormat.maxReferencedMembers
            && entries.count <= MeshRoutedInventoryFormat.maxEntries
            && membersAreWithinTheFingerprintCap
            && entriesAreWithinTheirSignerCaps
    }

    /// The fingerprint-width half of ``isWithinCaps``.
    private var membersAreWithinTheFingerprintCap: Bool {
        // R2: bounded by `maxReferencedMembers` — the count clause above short-circuits first.
        for member in members
        where member.utf8.count > MeshRoutedInventoryFormat.maxFingerprintLength {
            return false
        }
        return true
    }

    /// The per-entry half of ``isWithinCaps``: the two signer caps, which are different numbers, and
    /// the bitmap's own width ceiling.
    private var entriesAreWithinTheirSignerCaps: Bool {
        // R2: bounded by `maxEntries` — the count clause above short-circuits first.
        for entry in entries {
            guard entry.custodySigners.count
                <= MeshRoutedInventoryFormat.maxCustodySignersPerEntry else { return false }
            guard entry.recipientSigners.count
                <= MeshRoutedInventoryFormat.maxRecipientSignersPerEntry else { return false }
            guard entry.heldChunks.count
                <= MeshRoutedInventoryFormat.maxHeldChunkBitmapBytes else { return false }
        }
        return true
    }

    /// Whether the value is a *canonical* encoding of a holdings set: five clauses, none of which
    /// repairs anything. Reaches ``MeshRoutedInventoryRejection/malformed`` at the verifier.
    var isWellFormed: Bool {
        hasWellFormedMembers
            && membersAreMinimal
            && hasWellFormedEntries
            && hasWellFormedHeldChunkMaps
            && entriesAreCanonicallyOrdered
    }

    /// Clause 1: member fingerprints are non-empty and **strictly** ascending (hence distinct).
    private var hasWellFormedMembers: Bool {
        var previous: String?
        // R2: bounded by `maxReferencedMembers` (the caps check runs first at the verifier).
        for member in members {
            guard !member.isEmpty else { return false }
            if let previous { guard previous < member else { return false } }
            previous = member
        }
        return true
    }

    /// Clause 2: every listed member is referenced by at least one entry, as an origin or a signer.
    ///
    /// **Load-bearing.** Without minimality two encodings of one holdings set differ, and set
    /// equality over the value — the whole comparison surface — breaks.
    private var membersAreMinimal: Bool {
        guard members.count <= Int(UInt8.max) else { return false }
        let referenced = referencedMemberIndices
        // R2: bounded by `maxReferencedMembers`.
        for position in members.indices
        where !referenced.contains(UInt8(truncatingIfNeeded: position)) {
            return false
        }
        return true
    }

    /// Every member index any entry names, as an origin or a signer.
    private var referencedMemberIndices: Set<UInt8> {
        var referenced: Set<UInt8> = []
        // R2: bounded by `maxEntries` × the two per-entry signer caps.
        for entry in entries {
            referenced.insert(entry.originIndex)
            for index in entry.custodySigners { referenced.insert(index) }
            for index in entry.recipientSigners { referenced.insert(index) }
        }
        return referenced
    }

    /// Clause 3: every origin and signer index is in range, every signer list is strictly ascending,
    /// and every chunk count is inside `1 … maxChunkCount`.
    private var hasWellFormedEntries: Bool {
        let memberCount = members.count
        // R2: bounded by `maxEntries`.
        for entry in entries {
            guard Int(entry.originIndex) < memberCount else { return false }
            guard entry.chunkCount >= 1,
                  Int(entry.chunkCount) <= MeshRoutedInventoryFormat.maxChunkCount else { return false }
            guard Self.indicesAreAscendingAndInRange(entry.custodySigners, memberCount: memberCount),
                  Self.indicesAreAscendingAndInRange(entry.recipientSigners, memberCount: memberCount)
            else { return false }
        }
        return true
    }

    /// Clause 4: every bitmap is the canonical width for its own `chunkCount`, with no bit set at an
    /// index at or above it.
    private var hasWellFormedHeldChunkMaps: Bool {
        // R2: bounded by `maxEntries`.
        for entry in entries
        where !MeshRoutedInventoryEntry.bitmapIsCanonical(entry.heldChunks, for: entry.chunkCount) {
            return false
        }
        return true
    }

    /// Clause 5: entries are **strictly** increasing under `(originIndex, itemID.uuidString)`, which
    /// also rules out a duplicate `(origin, item)` pair.
    ///
    /// Because ``members`` is sorted by fingerprint, this coincides with
    /// ``MeshRoutedItemKey/isOrderedBefore(_:_:)`` — origin fingerprint ascending, then the
    /// **uppercase dashed `uuidString`**, a string compare and not raw UUID bytes.
    private var entriesAreCanonicallyOrdered: Bool {
        var previous: (origin: UInt8, item: String)?
        // R2: bounded by `maxEntries`.
        for entry in entries {
            let current = (origin: entry.originIndex, item: entry.itemID.uuidString)
            if let previous {
                let ordered = previous.origin < current.origin
                    || (previous.origin == current.origin && previous.item < current.item)
                guard ordered else { return false }
            }
            previous = current
        }
        return true
    }

    /// Whether `indices` is strictly ascending and every value indexes the member table.
    private static func indicesAreAscendingAndInRange(_ indices: [UInt8], memberCount: Int) -> Bool {
        var previous = -1
        // R2: bounded by the two per-entry signer caps.
        for index in indices {
            guard Int(index) > previous, Int(index) < memberCount else { return false }
            previous = Int(index)
        }
        return true
    }
}

// MARK: - MeshRoutedInventoryPayload

/// The `fernlet.mesh.routed-inventory-digest.v1` frame: what one device holds, signed by the
/// **advertiser** (plan §11, §10.3).
///
/// Signed for the reason the membership digest is — the digest is the input to a bounded exchange,
/// and an unsigned one could be forged to spend a peer's budget — plus two the membership digest
/// does not have: an ID list is a statement about *who this device is carrying content for*, so an
/// unsigned one would be a free probe of another member's delivery map; and it decides what a peer
/// spends up to the 256 MiB cap on. The cost is one Ed25519 verification per exchange.
///
/// **Not in `FernletIdentityEnvelope.sealingRequiredTypes`, on purpose:** signed-and-unsealed is
/// what lets a frame cross a **divergent** pair, the same property that carries the membership
/// digest and the epoch heads over a reconciling tunnel. A sealed routed digest would be dropped in
/// exactly the partition the drain exists to heal. Additive: older builds park the token and still
/// verify the envelope.
nonisolated struct MeshRoutedInventoryPayload: Codable, Equatable, Sendable {
    /// The advertiser's holdings.
    let inventory: MeshRoutedInventory
    /// The **advertiser** — the device whose disk this describes. Resolved against the admission
    /// ledger by this fingerprint, never by the envelope's sender.
    let senderFingerprint: String
    /// When it was signed, floored to whole seconds — **bound into the signature**, so a stale
    /// digest cannot be replayed as fresh.
    let sentAt: Date
    /// The advertiser's Ed25519 signature over `canonicalBytes(for:)` under
    /// `FernletCryptoPurpose.Signature.meshRoutedInventoryDigestV1`. Excluded from those bytes.
    let signature: Data

    /// Builds a payload from already-signed parts, flooring `sentAt` so the stored value is
    /// byte-identical to what the canonical writer emits.
    init(inventory: MeshRoutedInventory, senderFingerprint: String, sentAt: Date, signature: Data) {
        self.inventory = inventory
        self.senderFingerprint = senderFingerprint
        self.sentAt = MeshRoutedManifest.floored(sentAt)
        self.signature = signature
    }

    /// Decodes through the memberwise initializer, applying the same floor.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            inventory: try container.decode(MeshRoutedInventory.self, forKey: .inventory),
            senderFingerprint: try container.decode(String.self, forKey: .senderFingerprint),
            sentAt: try container.decode(Date.self, forKey: .sentAt),
            signature: try container.decode(Data.self, forKey: .signature)
        )
    }

    /// The inventory's own cap check, forwarded.
    var isWithinCaps: Bool { inventory.isWithinCaps }

    /// The inventory's shape **and the payload's own two untrusted scalars**.
    ///
    /// ``senderFingerprint`` and ``signature`` are the two fields no door clamps: the member table's
    /// bound does not reach the advertiser, which need not appear in a minimal table at all. Without
    /// this the verifier would reach the ledger lookup with an unbounded or empty fingerprint and
    /// hand Ed25519 an arbitrary-width signature.
    var isWellFormed: Bool {
        inventory.isWellFormed
            && signature.count == MeshRoutedInventoryFormat.signatureByteCount
            && !senderFingerprint.isEmpty
            && senderFingerprint.utf8.count <= MeshRoutedInventoryFormat.maxFingerprintLength
    }
}

// MARK: - MeshRoutedInventoryMintError

/// Why ``MeshRoutedInventoryPayload/signed(meshID:index:sentAt:identity:)`` refused
/// to mint.
///
/// Thrown, never returned as nil, and never silent — every other mint in the P5 family answers that
/// way, precisely so a caller's "logs it and sends nothing" has something to log.
///
/// Not `LocalizedError` — ``diagnosticDescription`` is frozen English for the audit log and is never
/// shown as user copy.
nonisolated enum MeshRoutedInventoryMintError: Error, Equatable, Sendable {
    /// The live records reference more distinct fingerprints than a member table may name. The
    /// honest answer is "I cannot advertise my holdings", not an over-cap digest the peer refuses.
    case tooManyReferencedMembers

    /// Frozen English for the diagnostic surface. Never shown as user copy.
    var diagnosticDescription: String {
        switch self {
        case .tooManyReferencedMembers:
            return "The held items name more members than one inventory digest can carry."
        }
    }
}

// MARK: - Signing factory

extension MeshRoutedInventoryPayload {

    /// Derives this device's routed inventory from a **loaded** index and signs it.
    ///
    /// There is deliberately **no `sentAt: Date = Date()` default**: every P5 instant is injected, so
    /// the property battery can drive a digest on a schedule clock. Nothing in item 5 reads a clock.
    ///
    /// There is also deliberately **no `selfFingerprint` parameter**, and it is not a convenience:
    /// this device has exactly one spelling here, `identity.localFingerprint`, and it is the same
    /// value that signs the frame. A caller-supplied second spelling would be a legal member
    /// fingerprint the verifier cannot refuse — the shape check, the admitted-key lookup and the
    /// signature all pass — while the builder's custody self-rule would attribute custody to a device
    /// that never held the item. A peer would then ask that device for a custody receipt it can never
    /// mint (``MeshCustodyReceipt`` refuses `originIsSelf`), the ask would re-fire every exchange, and
    /// the merge window item 7 closes on "every asked peer matched" would never close. The family's
    /// idiom is the same fact stated as a guard (`MeshCustodyReceipt.signed`'s `notTheCustodian`,
    /// `MeshRecipientReceipt.signed`'s); here the honest form is to have no second spelling at all,
    /// exactly as `MeshRoutedManifest.signed` derives its origin. The pure builder keeps its
    /// parameter — it is a value door with no identity to check against.
    ///
    /// - Parameters:
    ///   - meshID: The session these holdings belong to.
    ///   - index: The routed store's loaded index. A non-`.loaded` load must send **no digest at
    ///     all**, never an empty one — an empty digest is a positive claim ("I hold nothing") that
    ///     makes every peer re-offer everything.
    ///   - sentAt: The injected instant, floored into the signed bytes.
    ///   - identity: The advertiser, and the sole source of "this device".
    /// - Returns: The signed frame.
    /// - Throws: ``MeshRoutedInventoryMintError`` or the identity's signing error. Never a trap.
    @MainActor
    static func signed(
        meshID: UUID,
        index: MeshRoutedIndex,
        sentAt: Date,
        identity: IdentityService
    ) throws -> MeshRoutedInventoryPayload {
        let advertiser = identity.localFingerprint
        guard let inventory = MeshRoutedInventory(
            meshID: meshID, index: index, selfFingerprint: advertiser, at: sentAt
        ) else {
            throw MeshRoutedInventoryMintError.tooManyReferencedMembers
        }
        let unsigned = MeshRoutedInventoryPayload(
            inventory: inventory,
            senderFingerprint: advertiser,
            sentAt: sentAt,
            signature: Data()
        )
        let signature = try identity.sign(
            canonicalBytes(for: unsigned),
            purpose: FernletCryptoPurpose.Signature.meshRoutedInventoryDigestV1
        )
        return MeshRoutedInventoryPayload(
            inventory: inventory,
            senderFingerprint: unsigned.senderFingerprint,
            sentAt: unsigned.sentAt,
            signature: signature
        )
    }
}
