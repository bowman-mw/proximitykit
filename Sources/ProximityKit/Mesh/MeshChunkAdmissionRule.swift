// MeshChunkAdmissionRule.swift
// ProximityKit/Mesh
//
// Network migration P5 item 3 (plan §11, C13): the two chunk-set decisions, extracted so the
// IN-MEMORY reassembler and the DURABLE routed store reach them through one function each.
//
// Item 2 shipped both decisions inside `MeshChunkAssembly`, over held `MeshChunk` values. A durable
// store cannot hold 256 MiB of payload, so it holds descriptors and files instead — and the moment
// the same decision is written twice, the ten refusal tokens drift. C13 names that as a binding
// constraint on item 3, so the verdicts moved here and BOTH doors call them:
//
//   • `MeshChunkAssembly.admit(_:)`  and  `MeshRoutedStore.stagingChunk(_:now:)`      → `verdict`
//   • `MeshChunkAssembly.bind(to:)`  and  `MeshRoutedStore.admittingManifest(_:now:)` → `bindingVerdict`
//
// The extraction is behaviour-preserving by construction: item 2's `MeshChunkAssemblyTests` pass
// unmodified, which is the regression proof.
//
// The one substitution worth stating. The assembly decided a duplicate on
// `canonicalBytes(held) == canonicalBytes(chunk) && held.payload == chunk.payload`; the rule decides
// it on `descriptor(held) == descriptor(chunk) && payloadHash == held.chunkHash`. Both halves are
// equalities of the same facts: the canonical transcript is a fixed encoding of exactly the eight
// descriptor fields, so descriptor equality ⇔ transcript equality; and every held chunk passed the
// `chunkHash(of: payload) == chunkHash` guard at its own admission, so `payloadHash == held.chunkHash`
// ⇔ `chunkHash(chunk.payload) == chunkHash(held.payload)` ⇔ (SHA-256 collision resistance) the
// payloads are equal. A chunk whose payload does NOT hash to its own declared `chunkHash` therefore
// still answers `conflictingChunk` at an occupied index, in both forms.

import Foundation

// MARK: - MeshChunkDescriptor

/// Every field of a ``MeshChunk``'s **signed transcript**, and nothing else — the metadata mirror a
/// verdict reads so no decision has to open a payload.
///
/// Exactly the eight values `canonicalBytes(for: MeshChunk)` writes, in that order, so descriptor
/// equality and transcript equality are the same statement (pinned by test). The payload and the
/// 64-byte signature are deliberately absent: the payload is bound *through* ``chunkHash`` and the
/// signature is excluded from the transcript, so neither participates in any verdict.
///
/// `Codable` because the routed store persists one per held chunk file beside the file's opaque
/// name; the chunk file itself carries the whole origin-signed ``MeshChunk``, so the descriptor is a
/// mirror rather than a replacement. Pure value; nothing here reads a clock.
nonisolated struct MeshChunkDescriptor: Codable, Equatable, Sendable {
    /// The mesh the chunk belongs to.
    let meshID: UUID
    /// The routed item the chunk is part of.
    let itemID: UUID
    /// The author, and the only signer.
    let originFingerprint: String
    /// The whole item's content hash, as the chunk carries it.
    let contentHash: Data
    /// Zero-based position.
    let chunkIndex: UInt32
    /// How many chunks the whole item has.
    let chunkCount: UInt32
    /// This slice's own payload hash — the field the payload is bound through.
    let chunkHash: Data
    /// The item's expiry, floored.
    let expiresAt: Date

    /// Mirrors a chunk's signed transcript.
    init(_ chunk: MeshChunk) {
        meshID = chunk.meshID
        itemID = chunk.itemID
        originFingerprint = chunk.originFingerprint
        contentHash = chunk.contentHash
        chunkIndex = chunk.chunkIndex
        chunkCount = chunk.chunkCount
        chunkHash = chunk.chunkHash
        expiresAt = chunk.expiresAt
    }

    /// Builds a descriptor field by field. Used by the decoder and by tests; production always
    /// mirrors a real chunk through ``init(_:)``.
    init(
        meshID: UUID,
        itemID: UUID,
        originFingerprint: String,
        contentHash: Data,
        chunkIndex: UInt32,
        chunkCount: UInt32,
        chunkHash: Data,
        expiresAt: Date
    ) {
        self.meshID = meshID
        self.itemID = itemID
        self.originFingerprint = originFingerprint
        self.contentHash = contentHash
        self.chunkIndex = chunkIndex
        self.chunkCount = chunkCount
        self.chunkHash = chunkHash
        self.expiresAt = MeshRoutedManifest.floored(expiresAt)
    }
}

// MARK: - MeshChunkSetShape

/// The state one chunk-set decision reads: everything about a held set **except the payloads**.
///
/// The in-memory assembly builds it from its chunk map; the routed store builds it from its index
/// records. Identical inputs on both sides is what makes ``MeshChunkAdmissionRule``'s verdicts
/// identical, and it is why no verdict can ever need a payload — the durable form has none resident.
nonisolated struct MeshChunkSetShape: Equatable, Sendable {
    /// The item every admitted chunk must name.
    let itemID: UUID
    /// The origin every admitted chunk must name. Half of the anti-squatting triple.
    let originFingerprint: String
    /// The whole item's claimed content hash.
    let contentHash: Data
    /// How many chunks the item has.
    let chunkCount: UInt32
    /// The item's byte count once a manifest has bound the set; nil while **parked**.
    let boundSize: UInt64?
    /// How many payload bytes are held. Bounded by 1024 × 256 KiB.
    let bytesHeld: Int
    /// The descriptor at the incoming chunk's index, if that slot is occupied.
    let held: MeshChunkDescriptor?
    /// Every held slot's payload length, at most ``MeshChunkFormat/maxChunkCount`` entries. Read
    /// ONLY by ``MeshChunkAdmissionRule/bindingVerdict(for:in:)``, which is the one decision that
    /// has to re-check chunks other than the incoming one.
    let heldPayloadLengths: [UInt32: Int]

    /// Builds a shape. Every field is a plain value read off whichever form holds the set.
    init(
        itemID: UUID,
        originFingerprint: String,
        contentHash: Data,
        chunkCount: UInt32,
        boundSize: UInt64?,
        bytesHeld: Int,
        held: MeshChunkDescriptor?,
        heldPayloadLengths: [UInt32: Int]
    ) {
        self.itemID = itemID
        self.originFingerprint = originFingerprint
        self.contentHash = contentHash
        self.chunkCount = chunkCount
        self.boundSize = boundSize
        self.bytesHeld = bytesHeld
        self.held = held
        self.heldPayloadLengths = heldPayloadLengths
    }
}

// MARK: - MeshChunkAdmissionRule

/// The two chunk-set decisions, as pure functions over a ``MeshChunkSetShape`` (C13).
///
/// Neither mutates anything and neither reads a clock, a file or a payload. `MeshChunkAssembly` and
/// `MeshRoutedStore` are the only callers; a third form of either decision is the drift this type
/// exists to prevent.
nonisolated enum MeshChunkAdmissionRule {

    /// The one PER-CHUNK decision, in the order item 2 shipped it: `foreignItem` → `countMismatch`
    /// → `indexOutOfRange` → duplicate/`conflictingChunk` → `chunkHashMismatch` → `sizeOverflow` →
    /// `payloadLengthMismatch`.
    ///
    /// - Parameters:
    ///   - chunk: The chunk being offered. Must be one `MeshChunkVerifier` already accepted.
    ///   - payloadHash: `MeshRoutedContentDigest.chunkHash(of: chunk.payload)`, computed **once**
    ///     by the caller and used for both the duplicate check and the hash guard.
    ///   - shape: The held set's state at `chunk.chunkIndex`.
    ///   - receivedCount: How many indices are held right now, before this chunk.
    /// - Returns: `admitted` with the post-insertion count, `duplicate` with the unchanged count,
    ///   or a named refusal.
    static func verdict(
        for chunk: MeshChunk,
        payloadHash: Data,
        in shape: MeshChunkSetShape,
        receivedCount: Int
    ) -> MeshChunkAdmission {
        guard chunk.itemID == shape.itemID,
              chunk.originFingerprint == shape.originFingerprint,
              chunk.contentHash == shape.contentHash else {
            return .refused(.foreignItem)
        }
        guard chunk.chunkCount == shape.chunkCount else { return .refused(.countMismatch) }
        guard chunk.chunkIndex < shape.chunkCount else { return .refused(.indexOutOfRange) }
        if let existing = duplicateVerdict(
            for: chunk, payloadHash: payloadHash, held: shape.held, receivedCount: receivedCount
        ) {
            return existing
        }
        guard payloadHash == chunk.chunkHash else { return .refused(.chunkHashMismatch) }
        if let size = shape.boundSize, UInt64(shape.bytesHeld) + UInt64(chunk.payload.count) > size {
            return .refused(.sizeOverflow)
        }
        if let refusal = lengthRefusal(
            for: chunk, boundSize: shape.boundSize, chunkCount: shape.chunkCount
        ) {
            return .refused(refusal)
        }
        return .admitted(received: receivedCount + 1, expected: Int(shape.chunkCount))
    }

    /// The one BINDING decision, in the order `MeshChunkAssembly.bind(to:)` shipped it: identity
    /// triple ⇒ `foreignItem`; a derived chunk count that is not the set's ⇒ `countMismatch`; any
    /// already-held slot whose length is not
    /// ``MeshChunk/expectedPayloadByteCount(index:count:size:)`` ⇒ `payloadLengthMismatch`.
    ///
    /// Pure, and it mutates nothing — a refusal leaves the parked set exactly as it was, on both
    /// sides. That is the property item 2 documented and the store must not lose.
    ///
    /// - Parameters:
    ///   - manifest: The item's manifest. Must be one `MeshRoutedManifestVerifier` already accepted.
    ///   - shape: The held set's state. ``MeshChunkSetShape/heldPayloadLengths`` is read here and
    ///     nowhere else.
    /// - Returns: `bound`, or the named refusal.
    static func bindingVerdict(
        for manifest: MeshRoutedManifest,
        in shape: MeshChunkSetShape
    ) -> MeshChunkBinding {
        guard manifest.itemID == shape.itemID,
              manifest.originFingerprint == shape.originFingerprint,
              manifest.contentHash == shape.contentHash else {
            return .refused(.foreignItem)
        }
        guard let derived = MeshChunkFormat.chunkCount(forSize: manifest.size),
              derived == Int(shape.chunkCount) else {
            return .refused(.countMismatch)
        }
        if let refusal = heldLengthRefusal(in: shape, size: manifest.size) {
            return .refused(refusal)
        }
        return .bound
    }

    /// The verdict for an index that is already occupied: a retransmission of the same chunk is a
    /// duplicate no-op, anything else is a conflict. Nil when the index is free.
    ///
    /// Decided on the **content-bearing identity** — the signed transcript plus the payload's hash
    /// — never on `==`, which would fold in the 64-byte `signature`. CryptoKit's Ed25519 signing is
    /// *hedged*, so two mints of one logical chunk differ in exactly that field and honest re-mints
    /// are the normal case: item 6 streams without retaining what it minted, one item sent to two
    /// destinations is two mints, and item 8's custody transfer at departure can hand a holder a
    /// copy of what it already has.
    private static func duplicateVerdict(
        for chunk: MeshChunk,
        payloadHash: Data,
        held: MeshChunkDescriptor?,
        receivedCount: Int
    ) -> MeshChunkAdmission? {
        guard let held else { return nil }
        guard held == MeshChunkDescriptor(chunk), payloadHash == held.chunkHash else {
            return .refused(.conflictingChunk)
        }
        return .duplicate(received: receivedCount)
    }

    /// The length rule, bound and unbound. Bound: exactly what
    /// ``MeshChunk/expectedPayloadByteCount(index:count:size:)`` fixes. Unbound: interior chunks are
    /// exactly 256 KiB — derivable from `chunkCount` alone — and the last is 1 … 256 KiB, checked
    /// here rather than left to ``MeshChunk/isWellFormed``, because the bounded-growth statement has
    /// to be true at this door whoever called it.
    private static func lengthRefusal(
        for chunk: MeshChunk,
        boundSize: UInt64?,
        chunkCount: UInt32
    ) -> MeshChunkRefusal? {
        if let size = boundSize {
            guard let expected = MeshChunk.expectedPayloadByteCount(
                index: chunk.chunkIndex, count: chunkCount, size: size
            ), chunk.payload.count == expected else {
                return .payloadLengthMismatch
            }
            return nil
        }
        guard chunk.payload.count >= 1,
              chunk.payload.count <= MeshChunkFormat.maxChunkPayloadBytes else {
            return .payloadLengthMismatch
        }
        guard chunk.chunkIndex == chunkCount - 1
                || chunk.payload.count == MeshChunkFormat.maxChunkPayloadBytes else {
            return .payloadLengthMismatch
        }
        return nil
    }

    /// Whether any already-held slot has the wrong length for `size`. One bounded loop over the
    /// chunk count; nothing is mutated, so a refusal leaves the parked set untouched.
    private static func heldLengthRefusal(
        in shape: MeshChunkSetShape,
        size: UInt64
    ) -> MeshChunkRefusal? {
        // R2: bounded by the set's chunk count, itself bounded by `MeshChunkFormat.maxChunkCount`.
        for index in 0..<Int(shape.chunkCount) {
            guard let heldLength = shape.heldPayloadLengths[UInt32(index)] else { continue }
            guard let expected = MeshChunk.expectedPayloadByteCount(
                index: UInt32(index), count: shape.chunkCount, size: size
            ), heldLength == expected else {
                return .payloadLengthMismatch
            }
        }
        return nil
    }
}
