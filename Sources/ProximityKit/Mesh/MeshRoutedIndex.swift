// MeshRoutedIndex.swift
// ProximityKit/Mesh
//
// Network migration P5 item 3 (plan §11, §19.5): the routed store's sealed CATALOGUE — what this
// device is holding for other people, how far each destination's copy has got, and which sealed
// payload file backs each chunk.
//
// The index is authoritative over what we have. A `MeshRoutedChunks/<uuid>.chunk` file it does not
// name is an orphan; a descriptor whose file is gone is bytes we do not have. Both statements are
// one-directional on purpose — the store repairs the index against the files it can authenticate
// and never the other way round.
//
// Two bound decisions live here rather than in the store, because they are properties of the
// RECORDS and not of the file system:
//
//   • Caps are enforced at rest by REFUSAL, never by clamping. An over-cap index throws
//     `MeshRoutedIndexDecodingError.capacityExceeded`, which the store classifies `corrupt` and
//     recovers from through `quarantineCorruptIndex`. Clamping a durable record away would silently
//     drop an item whose chunk files stay on disk as orphans — possibly one a `MeshCustodyReceipt`
//     was already emitted for, i.e. a restart quietly losing acknowledged state, which is plan §3.6
//     inverted. (The WIRE records clamp their bounded collections at both doors; that is untrusted
//     input, and a different rule for a different surface. Both are stated out loud because they
//     look alike.)
//   • The union key is the SIGNED PAIR `(originFingerprint, itemID)` (D11). An `itemID` alone lets
//     an admitted member squat another origin's id under its own key and have it verify.
//
// What is deliberately NOT here: any file I/O, any crypto, any clock. Every query takes its instant
// as a parameter and every mutation is a value transformation the store then seals.

import Foundation
import FernletFoundation

// MARK: - MeshRoutedIndexSchema

/// The routed store's at-rest schema — **its own from day one**, never a field on
/// `MeshSessionContext` (whose schema stays 2).
///
/// A file this build does not own is refused **as a whole**, never partially reinterpreted, and
/// lands in `corrupt`, never `absent`. Older is corrupt, not migrated, and the justification is
/// temporal and true today: no build that wrote an older version ever ran on a device.
///
/// P5 item 4 moved it 1 → **2** for the two durable fields a final acknowledgement needs
/// (``MeshRoutedItemRecord/deliveredAt`` and ``MeshRoutedItemRecord/recipientReceipts``). Adding
/// them under schema 1 would have created an undeclared schema-1 variant: an item-3 build loading an
/// item-4 index would silently drop both on its next save, quietly losing acknowledged state, which
/// is plan §3.6 inverted and exactly what "refused as a whole" exists to prevent.
nonisolated enum MeshRoutedIndexSchema {
    /// The version this build writes and the only version it reads.
    static let current = 2
    /// Frozen English at-rest token — the same spelling as the sealing purpose
    /// (`KeyDerivation.meshRoutedStoreV1`), so the file's format and its key derivation are one
    /// vocabulary. Never localized, never displayed.
    static let token = "fernlet.mesh.routed-store.v1"
}

// MARK: - MeshRoutedStoreFormat

/// The routed store's caps (plan §11's backpressure bounds, §3.4's "bounded everything").
///
/// Three of the five are **reused constants, never restated**: restating 256 MiB here would be the
/// duplication `MeshRoutedManifestFormat.maxContentByteCount` explicitly forbids ("nothing else
/// defines 256 MiB"), and restating the roster cap would let two numbers drift.
nonisolated enum MeshRoutedStoreFormat {
    /// Most logical items the store holds at once (plan §9). Parked, manifest-less items count.
    static let maxItems = 1024

    /// The store's whole content budget. **Deliberately the same constant** as one item's ceiling:
    /// ``MeshRoutedManifestFormat/maxContentByteCount``'s own documentation says "Item 9 reuses this
    /// constant as its cache-total cap; nothing else defines 256 MiB".
    ///
    /// - Important: **Moving this constant moves a WIRE bound.** ``MeshChunkFormat/maxChunkCount``
    ///   is derived from it and gates `MeshChunk.isWellFormed`'s `chunkCount`, and it is also the
    ///   manifest's `size` ceiling. A cache-size change is therefore a wire decision needing a
    ///   golden review, not a config tweak. If the two caps ever genuinely need to differ, that is a
    ///   deliberate fork with its own doc comment naming both facts, not a silent edit.
    static let maxContentBytes = MeshRoutedManifestFormat.maxContentByteCount

    /// Chunks in one item — ``MeshChunkFormat/maxChunkCount``, reused.
    ///
    /// - Important: 1024 items and 1024 chunks-per-item are **two different caps that happen to be
    ///   equal** (item 2's flag F2). Item 9 must not collapse them: a single 256 MiB item exhausts
    ///   the whole byte budget while consuming 1 of the 1024 item slots.
    static let maxChunksPerItem = MeshChunkFormat.maxChunkCount

    /// Most sealed chunk FILES the store holds, across every item — the third, structural cap.
    ///
    /// Bytes do not bound file count: 1024 parked items × 1024 one-byte chunks is a legal,
    /// cheap-to-produce ~1 M-file store at ~1 MB of content. 4096 is chosen because 256 MiB of
    /// *full* chunks is 1024 files, so the ceiling leaves a 4× margin for small-chunk items while
    /// keeping the index itself bounded.
    static let maxHeldChunkFiles = 4096

    /// Most OTHER members' custody receipts one item's evidence set holds — one per roster member,
    /// ``MeshMembershipBounds/maxRosterMembers`` reused rather than an invented number.
    static let maxReceiptsPerItem = MeshMembershipBounds.maxRosterMembers
}

// MARK: - MeshRoutedIndexDecodingError

/// Why a sealed index this build decrypted still is not an index this build can use.
///
/// Both cases are classified `corrupt` by the store, which is the only state with a deliberate
/// recovery route (`quarantineCorruptIndex`). Neither is ever repaired in place.
nonisolated enum MeshRoutedIndexDecodingError: Error, Equatable, Sendable {
    /// The blob decoded, but its `schemaVersion` is not ``MeshRoutedIndexSchema/current``.
    case unsupportedSchemaVersion(Int)
    /// A cap this build owns was exceeded by bytes already on disk. Carries the cap's frozen
    /// English name: `items`, `chunksPerItem`, `chunkCount`, `receiptsPerItem`,
    /// `recipientReceiptsPerItem`, `contentBytes` or `chunkFiles`.
    ///
    /// A refusal rather than a clamp, on purpose: these are OUR durable records, and clamping one
    /// away silently drops an item whose chunk files stay on disk as orphans.
    case capacityExceeded(String)
}

// MARK: - MeshRoutedItemKey

/// The routed store's union key — the **signed pair** `(originFingerprint, itemID)` (D11).
///
/// An `itemID` alone is not an identity: routed frames are signed but unsealed, so any admitted
/// member can mint a manifest or a chunk reusing another origin's id under its own key and have it
/// verify. Both halves are inside every signed transcript, so keying on the pair needs no wire
/// change.
nonisolated struct MeshRoutedItemKey: Hashable, Codable, Sendable {
    /// The author of the item — the only signer of its manifest and chunks.
    let originFingerprint: String
    /// The item id: `MeshRoutedManifest.itemID` and `MeshDeliveryTarget.contentID`.
    let itemID: UUID

    /// Builds a key from its two halves.
    init(originFingerprint: String, itemID: UUID) {
        self.originFingerprint = originFingerprint
        self.itemID = itemID
    }

    /// The key of the item this manifest describes.
    init(_ manifest: MeshRoutedManifest) {
        self.init(originFingerprint: manifest.originFingerprint, itemID: manifest.itemID)
    }

    /// The key of the item this chunk is part of.
    init(_ chunk: MeshChunk) {
        self.init(originFingerprint: chunk.originFingerprint, itemID: chunk.itemID)
    }

    /// The deterministic order the index is kept in: origin, then item id.
    static func isOrderedBefore(_ lhs: MeshRoutedItemKey, _ rhs: MeshRoutedItemKey) -> Bool {
        if lhs.originFingerprint != rhs.originFingerprint {
            return lhs.originFingerprint < rhs.originFingerprint
        }
        return lhs.itemID.uuidString < rhs.itemID.uuidString
    }
}

// MARK: - MeshRoutedChunkDescriptor

/// One held chunk: its signed transcript's fields, the payload length, and the opaque file name.
///
/// **The file name carries no meaning.** It is a fresh random UUID recorded here, so no fingerprint,
/// item id, index or hash appears in any path component. The index is what binds a file to a slot.
///
/// The descriptor is a **mirror, not a binding**: `ColumnCrypto` authenticates with
/// `aad = purpose ‖ install binding`, with no file name in it, so under one key and one install
/// *every* chunk blob authenticates in *any* slot. That is why every read compares the opened
/// chunk's ``MeshChunkDescriptor`` and payload length against the stored ones — do not remove that
/// comparison as redundant.
nonisolated struct MeshRoutedChunkDescriptor: Codable, Equatable, Sendable {
    /// Every canonical-transcript field of the chunk the file holds.
    let descriptor: MeshChunkDescriptor
    /// The payload's byte count, 1 … ``MeshChunkFormat/maxChunkPayloadBytes``.
    let payloadByteCount: Int
    /// `"<uuid>.chunk"`, opaque, relative to the store's chunk directory.
    let fileName: String

    /// Builds a descriptor for a chunk that has been sealed to `fileName`.
    init(descriptor: MeshChunkDescriptor, payloadByteCount: Int, fileName: String) {
        self.descriptor = descriptor
        self.payloadByteCount = payloadByteCount
        self.fileName = fileName
    }
}

// MARK: - MeshRoutedDeliveryProgress

/// One destination's stored delivery state, in `MeshDeliveryStateToken`'s frozen English spellings.
///
/// `departed` is **never** written: it is not a `MeshDeliveryState` case at all, it is derived at
/// read against the current roster, and a fourth stored state would let a max-merge overwrite a
/// `delivered`. The decoder refuses the spelling by name.
nonisolated struct MeshRoutedDeliveryProgress: Codable, Equatable, Sendable {
    /// A `MeshDeliveryStateToken` rawValue — `pending`, `custodied` or `delivered`, never `departed`.
    let token: String
    /// The custodian's fingerprint. Present **iff** `token == "custodied"`.
    let custodian: String?

    /// Builds a progress entry from an already-validated token and custodian.
    init(token: String, custodian: String?) {
        self.token = token
        self.custodian = custodian
    }

    /// Encodes one live state. `pending` is representable but never stored — the record normalizes
    /// it to an absence, exactly as `MeshDeliveryTarget` does.
    init(_ state: MeshDeliveryState) {
        token = state.token.rawValue
        custodian = state.custodianFingerprint
    }
}

// MARK: - MeshRoutedDeliveryRecord

/// The persisted half of one item's ``MeshDeliveryTarget`` — the **progress map only**.
///
/// The destination set is deliberately NOT stored: it is restored from the ORIGIN'S SIGNED MANIFEST,
/// so it comes back from bytes the origin signed rather than from a file an attacker with disk
/// access could edit, and it can never be silently re-derived from the *current* roster (the §10.1
/// bug `MeshDeliveryTarget` exists to prevent). A parked item has no manifest and therefore no
/// delivery record — which is correct: a custodian that has not seen the manifest does not know the
/// destinations.
nonisolated struct MeshRoutedDeliveryRecord: Codable, Equatable, Sendable {
    /// The item this record is about — `MeshDeliveryTarget.contentID`.
    let contentID: UUID
    /// Sparse per-destination progress: `pending` is an ABSENCE, exactly as `MeshDeliveryTarget`
    /// normalizes it, so two records that mean the same thing are `==`.
    var progress: [String: MeshRoutedDeliveryProgress]

    /// Builds a record from an id and an already-normalized progress map.
    init(contentID: UUID, progress: [String: MeshRoutedDeliveryProgress]) {
        self.contentID = contentID
        self.progress = progress
    }

    /// The explicit encoder. Reads the target through its **public surface only**
    /// (`destinations`, `state(of:)`), so the target's storage stays private and non-`Codable` —
    /// P5 owns this encoding deliberately rather than inheriting one nobody chose.
    init(encoding target: MeshDeliveryTarget) {
        contentID = target.contentID
        var stored: [String: MeshRoutedDeliveryProgress] = [:]
        // R2: bounded by the destination cap (the roster minus self, ≤ 7).
        for destination in target.destinations {
            guard let state = target.state(of: destination), state != .pending else { continue }
            stored[destination] = MeshRoutedDeliveryProgress(state)
        }
        progress = stored
    }

    /// The explicit decoder, against the destination set from the **signed manifest**.
    ///
    /// - Parameter destinations: `MeshRoutedManifest.destinations`, verbatim. Never a reachable set,
    ///   a branch view or a current roster.
    /// - Returns: the restored target, or the named refusal.
    func restored(destinations: [String]) -> MeshDeliveryRestoreOutcome {
        var states: [String: MeshDeliveryState] = [:]
        // R2: bounded by the stored map, itself bounded by the destination cap on write.
        for (destination, entry) in progress {
            switch Self.state(from: entry) {
            case .refused(let refusal): return .refused(refusal)
            case .state(let state): states[destination] = state
            }
        }
        return MeshDeliveryTarget.restoring(
            contentID: contentID, destinations: destinations, progress: states
        )
    }

    /// One stored entry as a live state, or the refusal that says why it is not one.
    ///
    /// Every refusal here is about the ENTRY rather than the destination set: an unknown or derived
    /// spelling, or a custodian that disagrees with the rung it is attached to.
    private static func state(from entry: MeshRoutedDeliveryProgress) -> MeshRoutedProgressDecode {
        guard entry.token != MeshDeliveryStateToken.departed.rawValue else {
            return .refused(.departedIsDerived)
        }
        guard let token = MeshDeliveryStateToken(rawValue: entry.token) else {
            return .refused(.unknownStateToken)
        }
        guard token == .custodied else {
            guard entry.custodian == nil else { return .refused(.custodianOnANonCustodiedState) }
            return .state(token == .delivered ? .delivered : .pending)
        }
        guard let custodian = entry.custodian else { return .refused(.custodianMissing) }
        guard !custodian.isEmpty else { return .refused(.emptyCustodian) }
        return .state(.custodied(by: custodian))
    }
}

/// The two answers ``MeshRoutedDeliveryRecord``'s per-entry decode can give. A private result type
/// rather than `Result`, so `MeshDeliveryRestoreRefusal` need not become an `Error` it is not.
private nonisolated enum MeshRoutedProgressDecode {
    /// The entry decoded to a live delivery state.
    case state(MeshDeliveryState)
    /// The entry is not a state this build can restore, and this is why.
    case refused(MeshDeliveryRestoreRefusal)
}

// MARK: - MeshRoutedItemRecord

/// Everything the routed store durably knows about one item.
///
/// The manifest is stored **whole** because a custodian must re-emit the origin's exact signed
/// object (relays never re-sign), and rebuilding a subset would need a signature this device cannot
/// make. The same rule is why each chunk FILE holds the entire `MeshChunk` and not a bare payload.
nonisolated struct MeshRoutedItemRecord: Codable, Equatable, Sendable {
    /// The signed pair this record is keyed on.
    let key: MeshRoutedItemKey
    /// The whole item's content hash, from the manifest or the first chunk.
    let contentHash: Data
    /// How many chunks the item has.
    let chunkCount: UInt32
    /// The item's expiry, floored — from the manifest or the first chunk.
    let expiresAt: Date
    /// The origin's signed manifest, stored verbatim. **Nil ⇒ PARKED**: chunks arrived first, and
    /// parked items count against every cap so a peer cannot park bytes for free.
    var manifest: MeshRoutedManifest?
    /// When this device first saw the item. Receiver-local, monotone, floored, **never on the
    /// wire** and never adopted from a peer at merge — the clamp authority for `orderingInstant`.
    let firstSeenAt: Date
    /// The instant the index write that FIRST recorded durable custody returned, floored.
    ///
    /// Written **once** and re-used by every later witness, so a re-mint's canonical bytes are
    /// byte-identical; nil ⇒ no witness may exist. **Cleared** by any repair that drops a
    /// descriptor: the item is no longer complete, so the durable claim behind a witness is gone.
    var custodiedAt: Date?
    /// The instant the index write that FIRST recorded THIS DEVICE's final ack returned, floored
    /// (P5 item 4).
    ///
    /// Written **once** and re-used by every later ``MeshRecipientDeliveryWitness``, so a re-mint's
    /// canonical bytes are byte-identical; nil ⇒ no delivery witness may exist. Unlike
    /// ``custodiedAt`` it is **not cleared by a repair**: custody asserts bytes we still hold, while
    /// this records an acknowledgement already given — plan §11's final ack is a fact, and
    /// `MeshDeliveryState.delivered` is terminal.
    var deliveredAt: Date?
    /// The held chunks, ordered by `chunkIndex`, at most ``MeshRoutedStoreFormat/maxChunksPerItem``.
    var chunks: [MeshRoutedChunkDescriptor]
    /// The persisted delivery map. Present **iff** ``manifest`` is.
    var delivery: MeshRoutedDeliveryRecord?
    /// OTHER members' custody receipts for this item, ordered by custodian fingerprint, at most
    /// ``MeshRoutedStoreFormat/maxReceiptsPerItem``.
    ///
    /// The EVIDENCE behind ``delivery``'s `custodied(by:)` entries — stored verbatim so a peer can
    /// be handed the origin-of-the-claim's own signed bytes rather than this device's unsigned word
    /// (plan §3.2: receipts are union records). This device's OWN receipt is never stored: it is
    /// re-minted from the witness.
    var receipts: [MeshCustodyReceipt]
    /// Recipient receipts for this item — peers' AND this device's own — ordered by
    /// `recipientFingerprint`, at most ``MeshRoutedStoreFormat/maxReceiptsPerItem`` (P5 item 4).
    ///
    /// The EVIDENCE behind ``delivery``'s `delivered` entries, stored verbatim so a peer is handed
    /// the signer's own bytes (plan §3.2's union records). This device's own receipt **is** stored,
    /// which is the deliberate difference from ``receipts``: a custody claim is re-measurable from
    /// the bytes on disk forever, while a heart's final-ack condition is a one-shot ledger judgement
    /// the ledger will refuse to repeat, so a design that re-derived would either strand hearts or
    /// need a second, weaker mint.
    var recipientReceipts: [MeshRecipientReceipt]

    /// Builds a record field by field. The store's verbs are the only production callers.
    init(
        key: MeshRoutedItemKey,
        contentHash: Data,
        chunkCount: UInt32,
        expiresAt: Date,
        manifest: MeshRoutedManifest?,
        firstSeenAt: Date,
        custodiedAt: Date?,
        deliveredAt: Date?,
        chunks: [MeshRoutedChunkDescriptor],
        delivery: MeshRoutedDeliveryRecord?,
        receipts: [MeshCustodyReceipt],
        recipientReceipts: [MeshRecipientReceipt]
    ) {
        self.key = key
        self.contentHash = contentHash
        self.chunkCount = chunkCount
        self.expiresAt = MeshRoutedManifest.floored(expiresAt)
        self.manifest = manifest
        self.firstSeenAt = MeshRoutedManifest.floored(firstSeenAt)
        self.custodiedAt = custodiedAt.map(MeshRoutedManifest.floored)
        self.deliveredAt = deliveredAt.map(MeshRoutedManifest.floored)
        self.chunks = chunks
        self.delivery = delivery
        self.receipts = receipts
        self.recipientReceipts = recipientReceipts
    }

    /// Decodes a record, **refusing** — never clamping — an at-rest collection over its cap.
    ///
    /// The two P5 item 4 fields decode differently, on purpose. ``recipientReceipts`` is
    /// **hard-decoded**, beside its two sibling arrays: a `decodeIfPresent` array would admit a
    /// schema-2 record with the key missing as "no receipts held", which re-opens *inside* schema 2
    /// the partial reinterpretation the 1 → 2 bump was spent to close. ``deliveredAt`` keeps
    /// `decodeIfPresent`, mirroring ``custodiedAt`` — it is a genuine `Date?`, and "absent" and "nil"
    /// are the same fact for it.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let storedChunks = try container.decode([MeshRoutedChunkDescriptor].self, forKey: .chunks)
        let storedReceipts = try container.decode([MeshCustodyReceipt].self, forKey: .receipts)
        let storedAcks = try container.decode([MeshRecipientReceipt].self, forKey: .recipientReceipts)
        let storedCount = try container.decode(UInt32.self, forKey: .chunkCount)
        guard storedChunks.count <= MeshRoutedStoreFormat.maxChunksPerItem else {
            throw MeshRoutedIndexDecodingError.capacityExceeded("chunksPerItem")
        }
        // The fourth sibling (P5 item 9): the DECLARED count is a bare scalar, so without this an
        // at-rest record could claim 2^32 − 1 chunks beside three guarded collections. `Int(UInt32)`
        // cannot trap; `UInt32(Int)` could, so the comparison is spelled this way round.
        guard Int(storedCount) <= MeshRoutedStoreFormat.maxChunksPerItem else {
            throw MeshRoutedIndexDecodingError.capacityExceeded("chunkCount")
        }
        guard storedReceipts.count <= MeshRoutedStoreFormat.maxReceiptsPerItem else {
            throw MeshRoutedIndexDecodingError.capacityExceeded("receiptsPerItem")
        }
        guard storedAcks.count <= MeshRoutedStoreFormat.maxReceiptsPerItem else {
            throw MeshRoutedIndexDecodingError.capacityExceeded("recipientReceiptsPerItem")
        }
        self.init(
            key: try container.decode(MeshRoutedItemKey.self, forKey: .key),
            contentHash: try container.decode(Data.self, forKey: .contentHash),
            chunkCount: storedCount,
            expiresAt: try container.decode(Date.self, forKey: .expiresAt),
            manifest: try container.decodeIfPresent(MeshRoutedManifest.self, forKey: .manifest),
            firstSeenAt: try container.decode(Date.self, forKey: .firstSeenAt),
            custodiedAt: try container.decodeIfPresent(Date.self, forKey: .custodiedAt),
            deliveredAt: try container.decodeIfPresent(Date.self, forKey: .deliveredAt),
            chunks: storedChunks,
            delivery: try container.decodeIfPresent(MeshRoutedDeliveryRecord.self, forKey: .delivery),
            receipts: storedReceipts,
            recipientReceipts: storedAcks
        )
    }

    /// How many distinct chunk indices are held.
    var receivedCount: Int { chunks.count }

    /// How many CONTENT bytes are held for this item (never disk bytes — the seal inflates by
    /// roughly 1.37×, and the cap counts content).
    var contentBytesHeld: Int {
        chunks.reduce(0) { $0 + $1.payloadByteCount }
    }

    /// Whether every index is held. Necessary for a custody commit, never sufficient — the whole
    /// item's `contentHash` still decides.
    var isComplete: Bool { chunks.count == Int(chunkCount) }

    /// Whether a durable custody commit has succeeded and not been undone by a repair.
    var isCustodied: Bool { custodiedAt != nil }

    /// Whether this device has written its own durable final-ack record for the item.
    ///
    /// It means exactly that, and the natural misreadings are the dangerous ones. It is **not**
    /// "this device's receipt is stored" — the window between the ack write and the receipt landing
    /// is `true` here with no receipt, and ``MeshRoutedIndex/itemsAwaitingLocalAck(at:for:)`` is what
    /// names it. And it is emphatically **not** "the content has been consumed and the item is safe
    /// to drop": anything reclaiming content reads
    /// ``MeshRoutedIndex/itemsReclaimableAsCustodian(at:in:for:)``.
    var isDeliveredLocally: Bool { deliveredAt != nil }

    /// The stored recipient receipt signed by `fingerprint`, or nil.
    func recipientReceipt(from fingerprint: String) -> MeshRecipientReceipt? {
        recipientReceipts.first { $0.recipientFingerprint == fingerprint }
    }

    /// Whether this item is chunks without a manifest.
    var isParked: Bool { manifest == nil }

    /// Liveness under an injected clock, the same predicate the wire records use.
    func isLive(at now: Date) -> Bool { now <= expiresAt }

    /// The descriptor holding `index`, or nil when that slot is free.
    func chunk(at index: UInt32) -> MeshRoutedChunkDescriptor? {
        chunks.first { $0.descriptor.chunkIndex == index }
    }

    /// The small read-only view a caller iterates.
    var reference: MeshRoutedItemRef {
        MeshRoutedItemRef(
            key: key, contentHash: contentHash, chunkCount: chunkCount, receivedCount: receivedCount,
            contentBytesHeld: contentBytesHeld, expiresAt: expiresAt, firstSeenAt: firstSeenAt,
            isCustodied: isCustodied, isParked: isParked,
            deliveryRestoreRefused: deliveryRestoreRefused,
            isAcknowledgedLocally: isDeliveredLocally
        )
    }

    /// Whether our OWN stored delivery map refuses to restore — a held item whose outstanding
    /// destinations this device cannot account for.
    ///
    /// Structurally different from "no destinations are known", which is what a parked item (no
    /// manifest, so no signed destination set) honestly reports. ``deliveryTarget`` collapses both
    /// to nil, and every enumerator skips a nil target, so without this flag a held item with
    /// outstanding work would leave items 6 and 8 with no value-level signal at all — plan §11's
    /// "nothing grows silently" and §3.6's "no silent drop" read on the same item.
    ///
    /// A pure predicate over ≤ ``MeshRoutedManifestFormat/maxDestinations`` entries, and
    /// deliberately silent: ``deliveryTarget`` audits the refusal once at the read that needed the
    /// target, and a flag consulted on every enumerated item must not add a log line each time.
    var deliveryRestoreRefused: Bool {
        guard let manifest, let delivery else { return false }
        if case .refused = delivery.restored(destinations: manifest.destinations) { return true }
        return false
    }

    /// This record's restored delivery target, or nil when the item is parked or the stored map does
    /// not restore. A refusal is audited rather than swallowed — it is a fault in our own bytes —
    /// and named at the value level by ``deliveryRestoreRefused``.
    var deliveryTarget: MeshDeliveryTarget? {
        guard let manifest, let delivery else { return nil }
        switch delivery.restored(destinations: manifest.destinations) {
        case .restored(let target):
            return target
        case .refused(let refusal):
            FernletAuditLog.log(
                "mesh.routedStore.deliveryRestoreRefused",
                context: ["refusal": refusal.rawValue]
            )
            return nil
        }
    }
}

// MARK: - MeshRoutedItemRef

/// The small read-only view of one held item that callers iterate — enumeration without handing out
/// the manifest, the receipts or the file names.
///
/// The opaque chunk file names are deliberately absent from every public accessor, so the property
/// battery (item 14) can decide later whether to inject a name factory without item 3 having fixed
/// the answer.
nonisolated struct MeshRoutedItemRef: Equatable, Sendable {
    /// The signed pair.
    let key: MeshRoutedItemKey
    /// The whole item's content hash.
    let contentHash: Data
    /// How many chunks the item has.
    let chunkCount: UInt32
    /// How many are held.
    let receivedCount: Int
    /// How many content bytes are held.
    let contentBytesHeld: Int
    /// The item's expiry.
    let expiresAt: Date
    /// When this device first saw it.
    let firstSeenAt: Date
    /// Whether a durable custody commit stands.
    let isCustodied: Bool
    /// Whether the manifest is still missing.
    let isParked: Bool
    /// Whether this device's own stored delivery map refuses to restore.
    ///
    /// `true` means the item is HELD with destinations this device cannot account for — it is
    /// therefore absent from ``MeshRoutedIndex/outstandingItems(at:in:)`` and
    /// ``MeshRoutedIndex/itemsAwaitingHandoff(at:in:originatedBy:)``, and named by
    /// ``MeshRoutedIndex/itemsWithUnrestorableDelivery(at:)``. Never `true` for a parked item, which
    /// has no signed destination set to fail to restore.
    let deliveryRestoreRefused: Bool
    /// Whether this device wrote its own durable final-ack record for the item (P5 item 4).
    ///
    /// ``MeshRoutedItemRecord/isDeliveredLocally``, carried onto the ref — the ref is not persisted,
    /// so this is not a schema change. Its two misreadings are named there and are worth repeating:
    /// it is not "this device's receipt is stored", and it is **never** "safe to drop". Reading it
    /// as the latter deletes the only copy of a received photo.
    let isAcknowledgedLocally: Bool
}

// MARK: - MeshRoutedIndex

/// The routed store's sealed catalogue: every item this device holds, in a deterministic order.
///
/// Ordered by `(originFingerprint, itemID)` so two indexes with the same records are `==` and the
/// sealed bytes are stable. Every mutation is a value transformation the store then seals under a
/// write token — nothing here writes a file, and nothing here reads a clock.
nonisolated struct MeshRoutedIndex: Codable, Equatable, Sendable {

    /// Stamped ``MeshRoutedIndexSchema/current`` on every write; any other value on read is refused
    /// (``MeshRoutedIndexDecodingError/unsupportedSchemaVersion(_:)``).
    let schemaVersion: Int

    /// The held items, ordered by ``MeshRoutedItemKey/isOrderedBefore(_:_:)``, at most
    /// ``MeshRoutedStoreFormat/maxItems``.
    private(set) var items: [MeshRoutedItemRecord]

    /// Builds an index, sorting the records into the canonical order.
    ///
    /// - Parameter items: The records to hold. Callers stay inside the caps; an over-cap value is
    ///   refused at the writer doors and, at rest, at ``init(from:)``.
    init(items: [MeshRoutedItemRecord] = []) {
        schemaVersion = MeshRoutedIndexSchema.current
        self.items = items.sorted { MeshRoutedItemKey.isOrderedBefore($0.key, $1.key) }
    }

    /// Decodes an index, refusing a schema this build does not own and any at-rest cap violation.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let version = try container.decode(Int.self, forKey: .schemaVersion)
        guard version == MeshRoutedIndexSchema.current else {
            throw MeshRoutedIndexDecodingError.unsupportedSchemaVersion(version)
        }
        let stored = try container.decode([MeshRoutedItemRecord].self, forKey: .items)
        guard stored.count <= MeshRoutedStoreFormat.maxItems else {
            throw MeshRoutedIndexDecodingError.capacityExceeded("items")
        }
        let bytes = stored.reduce(0) { $0 + $1.contentBytesHeld }
        guard UInt64(bytes) <= MeshRoutedStoreFormat.maxContentBytes else {
            throw MeshRoutedIndexDecodingError.capacityExceeded("contentBytes")
        }
        let files = stored.reduce(0) { $0 + $1.chunks.count }
        guard files <= MeshRoutedStoreFormat.maxHeldChunkFiles else {
            throw MeshRoutedIndexDecodingError.capacityExceeded("chunkFiles")
        }
        schemaVersion = version
        items = stored.sorted { MeshRoutedItemKey.isOrderedBefore($0.key, $1.key) }
    }

    // MARK: Records

    /// The record for `key`, or nil.
    func record(for key: MeshRoutedItemKey) -> MeshRoutedItemRecord? {
        items.first { $0.key == key }
    }

    /// Whether any held item carries `itemID` under a DIFFERENT origin — the `duplicateItemID` door
    /// (D11), asked before a new item is admitted.
    func holdsItemID(_ itemID: UUID, underAnotherOriginThan origin: String) -> Bool {
        items.contains { $0.key.itemID == itemID && $0.key.originFingerprint != origin }
    }

    /// Inserts or replaces `record`, keeping the canonical order.
    mutating func upsert(_ record: MeshRoutedItemRecord) {
        if let position = items.firstIndex(where: { $0.key == record.key }) {
            items[position] = record
            return
        }
        items.append(record)
        items.sort { MeshRoutedItemKey.isOrderedBefore($0.key, $1.key) }
    }

    /// Removes the record for `key`, if present, and answers the file names it was holding — so the
    /// caller can take the payload files away with the record rather than leaving orphans.
    mutating func remove(_ key: MeshRoutedItemKey) -> [String] {
        guard let position = items.firstIndex(where: { $0.key == key }) else { return [] }
        let removed = items.remove(at: position)
        return removed.chunks.map(\.fileName)
    }

    // MARK: Counters (item 9's backpressure inputs)

    /// How many logical items are held, parked ones included.
    var itemCount: Int { items.count }

    /// How many CONTENT bytes are held across every item, parked ones included.
    var totalContentBytesHeld: Int {
        items.reduce(0) { $0 + $1.contentBytesHeld }
    }

    /// How many sealed chunk files the index names. The store additionally checks the DIRECTORY at
    /// its writer door, because an orphan is on disk and not in the index.
    var heldChunkFileCount: Int {
        items.reduce(0) { $0 + $1.chunks.count }
    }

    /// Every file name the index names, for the orphan sweep to subtract from the directory.
    var heldChunkFileNames: Set<String> {
        var names: Set<String> = []
        // R2: bounded by `maxHeldChunkFiles`.
        for item in items {
            for chunk in item.chunks { names.insert(chunk.fileName) }
        }
        return names
    }

    /// When this device first saw `key`, or nil. Receiver-local and never on the wire.
    func firstSeenAt(of key: MeshRoutedItemKey) -> Date? {
        record(for: key)?.firstSeenAt
    }

    /// The held chunk indices of `key`, ascending — what a transfer iterates.
    func heldChunkIndices(of key: MeshRoutedItemKey) -> [UInt32] {
        (record(for: key)?.chunks ?? []).map(\.descriptor.chunkIndex).sorted()
    }

    // MARK: Enumeration (item 6's drain, item 8's handoff)

    /// Live items held with **no manifest** — chunk sets that arrived ahead of their manifest (C10).
    ///
    /// They already count against every cap; what was missing until P5 item 9 was any way to *say
    /// so*. In index order, bounded by ``MeshRoutedStoreFormat/maxItems`` like every enumerator here.
    ///
    /// - Parameter now: The injected instant; expired items are excluded, as everywhere else.
    /// - Returns: the refs, each with ``MeshRoutedItemRef/isParked`` set.
    func parkedItems(at now: Date) -> [MeshRoutedItemRef] {
        items.filter { $0.isLive(at: now) && $0.isParked }.map(\.reference)
    }

    /// The destinations of `key` that still have work outstanding — pending plus custodied,
    /// departed and delivered excluded — against the CURRENT roster.
    ///
    /// Drives off the **restored** target, so the destination set is the origin's signed one and
    /// "outstanding" is plan §11's "destinations lacking a `MeshRecipientReceipt`", partition-
    /// agnostic by construction.
    ///
    /// - Important: empty for a parked item AND for one whose stored map will not restore. The two
    ///   are told apart by ``MeshRoutedItemRef/deliveryRestoreRefused`` and
    ///   ``itemsWithUnrestorableDelivery(at:)`` — never by this list.
    func outstandingDestinations(
        for key: MeshRoutedItemKey,
        in roster: MeshDerivedRoster
    ) -> [String] {
        guard let target = record(for: key)?.deliveryTarget else { return [] }
        return target.outstanding(in: roster)
    }

    /// Whether **every** destination of `key` is positively `delivered` against `roster` — the
    /// POSITIVE predicate a reclaim needs, as opposed to "nothing is outstanding".
    ///
    /// The difference is a deletion. ``MeshDeliveryTarget/disposition(of:in:)`` answers `.departed`
    /// for any fingerprint the **local** roster does not contain, and `isFullyDelivered` is only
    /// "outstanding is empty" — so a destination this device has simply not heard of yet reads as
    /// closed. A reclaim on that answer deletes content still owed to a member admitted after the
    /// manifest was created, and audits it as `delivered`. This asks for the delivered state itself,
    /// and a roster-absent destination therefore frees no byte.
    ///
    /// - Parameters:
    ///   - key: The signed pair.
    ///   - roster: The current merged roster.
    /// - Returns: `false` for a missing record, a parked item, an unrestorable delivery map, an empty
    ///   destination set, and any destination that is not `.delivered`.
    func everyDestinationDelivered(_ key: MeshRoutedItemKey, in roster: MeshDerivedRoster) -> Bool {
        guard let record = record(for: key), let manifest = record.manifest,
              let target = record.deliveryTarget else {
            return false
        }
        let answers = target.dispositions(in: roster)
        guard !manifest.destinations.isEmpty,
              answers.count == manifest.destinations.count else {
            return false
        }
        // R2: bounded by `MeshRoutedManifestFormat.maxDestinations`.
        return answers.values.allSatisfy { $0 == .delivered }
    }

    /// The outstanding destinations of `key` this branch can reach right now.
    func outstandingReachable(
        for key: MeshRoutedItemKey,
        from branch: MeshBranchView,
        in roster: MeshDerivedRoster
    ) -> [String] {
        guard let target = record(for: key)?.deliveryTarget else { return [] }
        return target.outstandingReachable(from: branch, in: roster)
    }

    /// The outstanding destinations of `key` this branch cannot reach — the pending deliveries a
    /// partition is holding up. They stay destinations throughout.
    func outstandingUnreachable(
        for key: MeshRoutedItemKey,
        from branch: MeshBranchView,
        in roster: MeshDerivedRoster
    ) -> [String] {
        guard let target = record(for: key)?.deliveryTarget else { return [] }
        return target.outstandingUnreachable(from: branch, in: roster)
    }

    /// Every live item with work outstanding, bucketed by destination fingerprint.
    ///
    /// An item whose stored delivery map will not restore has no destinations to bucket it under
    /// and is therefore absent here — ``itemsWithUnrestorableDelivery(at:)`` is where it appears,
    /// so item 6 can surface it rather than lose it.
    ///
    /// - Parameters:
    ///   - now: The injected instant; expired items are excluded.
    ///   - roster: The current merged roster — departed destinations are derived out here.
    /// - Returns: destination → the items still owed to it, in index order.
    func outstandingItems(at now: Date, in roster: MeshDerivedRoster) -> [String: [MeshRoutedItemRef]] {
        var buckets: [String: [MeshRoutedItemRef]] = [:]
        // R2: bounded by `maxItems` × the destination cap.
        for item in items where item.isLive(at: now) {
            guard let target = item.deliveryTarget else { continue }
            for destination in target.outstanding(in: roster) {
                buckets[destination, default: []].append(item.reference)
            }
        }
        return buckets
    }

    /// Whole held items still live at `now` with at least one outstanding destination, **originated
    /// by one named device** — what a departure hands over.
    ///
    /// An item whose stored delivery map will not restore is not here either (its destinations are
    /// unknown to this device, so a handoff could not name them); item 8 reads
    /// ``itemsWithUnrestorableDelivery(at:)`` for those.
    ///
    /// - Important: `originatedBy` is **required, and has no default**, because it is P5 item 8's
    ///   no-second-hop wall rather than a convenience. Increment 1's custody moves at exactly one
    ///   moment — a development — and only for content the departing device itself minted; a
    ///   departing *custodian* enumerates nothing. Defaulting the parameter would turn that
    ///   structural bound into something a future call site has to remember.
    ///
    /// - Parameters:
    ///   - now: The injected instant; expired items are excluded.
    ///   - roster: The current merged roster — departed destinations are derived out here.
    ///   - originatedBy: The origin whose items are being handed over — this device, always.
    func itemsAwaitingHandoff(
        at now: Date, in roster: MeshDerivedRoster, originatedBy origin: String
    ) -> [MeshRoutedItemRef] {
        items.filter { item in
            guard item.key.originFingerprint == origin else { return false }
            guard item.isLive(at: now), item.isComplete, let target = item.deliveryTarget else {
                return false
            }
            return !target.outstanding(in: roster).isEmpty
        }.map(\.reference)
    }

    /// Every live item whose own stored delivery map refuses to restore — held ciphertext with
    /// outstanding destinations this device cannot account for.
    ///
    /// Exactly the items the four outstanding/handoff enumerators cannot answer for, named rather
    /// than dropped: a delivery record that will not restore is a fault in our own durable bytes,
    /// not evidence that nothing is owed. Items 6 and 8 surface these; nothing here repairs
    /// anything, because a repair at a read door would be a write with no token.
    ///
    /// - Important: item 4 deliberately does **not** re-derive a fresh map for these from the
    ///   manifest. Re-deriving would overwrite a stored map this device cannot read, which is a
    ///   silent loss of somebody's `delivered` — so the items stay named and untouched, and both
    ///   delivery doors take the corruption route for them rather than a refusal.
    ///
    /// - Parameter now: The injected instant; expired items are excluded, as everywhere else.
    /// - Returns: the refs, in index order, each with ``MeshRoutedItemRef/deliveryRestoreRefused``
    ///   set.
    func itemsWithUnrestorableDelivery(at now: Date) -> [MeshRoutedItemRef] {
        items.filter { $0.isLive(at: now) && $0.deliveryRestoreRefused }.map(\.reference)
    }

    // MARK: Delivery enumeration (P5 item 4)

    /// Live items every destination has delivered or departed from.
    ///
    /// A PARKED item is never here: it has no manifest, so no signed destination set, exactly as it
    /// is never named by ``itemsWithUnrestorableDelivery(at:)``.
    ///
    /// - Important: **this is not a reclaim list.** A destination's own entry reaches `delivered` on
    ///   durable ciphertext alone for photos and text, so at a RECIPIENT this answers `true` while
    ///   the store's copy is still the only copy of content nothing has moved into the canonical
    ///   store yet. Item 9 reads ``itemsReclaimableAsCustodian(at:in:for:)``, and
    ///   ``MeshRoutedItemRef/isAcknowledgedLocally`` says nothing about consumption.
    ///
    /// - Parameters:
    ///   - now: The injected instant; expired items are excluded.
    ///   - roster: The current merged roster — departed destinations are derived out here.
    /// - Returns: the refs, in index order.
    func itemsFullyDelivered(at now: Date, in roster: MeshDerivedRoster) -> [MeshRoutedItemRef] {
        items.filter { item in
            guard item.isLive(at: now), let target = item.deliveryTarget else { return false }
            return target.isFullyDelivered(in: roster)
        }.map(\.reference)
    }

    /// Live items that are fully delivered **and do not name this device as a destination** — the
    /// courier's own copies, whose content this device holds for other people and nothing local
    /// still needs. Item 9's reclaim input.
    ///
    /// The exclusion is deliberate and one-directional: an item this device is a destination for
    /// stays until its content has actually been consumed, and P5 item 4 ships **no**
    /// consumed-locally signal to relax that with. `dropping(item:reason:)` has no destination guard
    /// of its own — it removes the record and its chunk files on the caller's word — so this list is
    /// the guard.
    ///
    /// - Parameters:
    ///   - now: The injected instant; expired items are excluded.
    ///   - roster: The current merged roster.
    ///   - selfFingerprint: This device.
    /// - Returns: the refs, in index order.
    func itemsReclaimableAsCustodian(
        at now: Date,
        in roster: MeshDerivedRoster,
        for selfFingerprint: String
    ) -> [MeshRoutedItemRef] {
        items.filter { item in
            guard item.isLive(at: now), let manifest = item.manifest else { return false }
            guard !manifest.destinations.contains(selfFingerprint) else { return false }
            guard let target = item.deliveryTarget else { return false }
            return target.isFullyDelivered(in: roster)
        }.map(\.reference)
    }

    /// Live items where THIS DEVICE is a destination and **this device's own recipient receipt is
    /// not stored** — the retry list. Item 10's enumerator, and item 6's self-drain input.
    ///
    /// Deliberately NOT conditioned on the ack instant, on completeness or on custody: the predicate
    /// has to reach every state a retry must fix, and each of those three would hide one — the window
    /// between a stamped ack and a stored receipt, a heart whose ledger commit landed and whose
    /// custody a later repair then cleared, and an incomplete item this device is a destination for.
    /// A retry list that misses an item strands it forever; one carrying an extra item costs exactly
    /// one named shortfall. Callers that want to prioritise read ``MeshRoutedItemRef/isCustodied``,
    /// ``MeshRoutedItemRef/receivedCount`` and ``MeshRoutedItemRef/chunkCount``, which are already
    /// there.
    ///
    /// - Parameters:
    ///   - now: The injected instant; expired items are excluded.
    ///   - selfFingerprint: This device.
    /// - Returns: the refs, in index order.
    func itemsAwaitingLocalAck(at now: Date, for selfFingerprint: String) -> [MeshRoutedItemRef] {
        items.filter { item in
            guard item.isLive(at: now), let manifest = item.manifest else { return false }
            guard manifest.destinations.contains(selfFingerprint) else { return false }
            return item.recipientReceipt(from: selfFingerprint) == nil
        }.map(\.reference)
    }

    /// How many items ``itemsAwaitingHandoff(at:in:originatedBy:)`` would name.
    ///
    /// - Important: this is a **candidate** count, never `MeshCustodyHandoffSummary.handedOffItemCount`.
    ///   That field is signed into a departure record nobody can retract, so P5 item 8 fills it from
    ///   what actually transferred, after the transfers — `MeshCustodyHandoffResult.transferredItemCount`.
    func handoffCandidateCount(
        at now: Date, in roster: MeshDerivedRoster, originatedBy origin: String
    ) -> Int {
        itemsAwaitingHandoff(at: now, in: roster, originatedBy: origin).count
    }
}
