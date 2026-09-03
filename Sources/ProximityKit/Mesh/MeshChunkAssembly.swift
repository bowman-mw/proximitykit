// MeshChunkAssembly.swift
// ProximityKit/Mesh
//
// Network migration P5 item 2 (plan §11): the receive-side reassembler — the bounded value that
// collects one item's ``MeshChunk``s in any order and decides, once, whether the ciphertext is
// whole.
//
// Order-independence is not a nicety here: chunks ride per-transfer streams that are explicitly
// not ordered against each other or against the control stream carrying the manifest, so "the
// chunks arrived before the manifest" and "chunk 7 arrived before chunk 2" are both normal. Every
// input returns a verdict and nothing is silently dropped — the transport's own rule for a
// malformed inbound transfer (log and drop, never disconnect) reaches the application as a named
// refusal rather than a throw.
//
// Chunk bytes live in MEMORY here (item 3 re-backs the byte custody with its sealed sidecar — the
// four-state load plus the fifth "seal refused" distinction — and REUSES this verdict logic
// unchanged: the durable form must produce the same `MeshChunkAdmission` and `MeshChunkCompletion`
// values for the same inputs). Inventing a byte-storage protocol here would be item 3's design
// made without item 3's constraints.
//
// What is deliberately NOT here: any capacity verdict. The assembly's own bound IS
// 1024 × 256 KiB = `MeshRoutedManifestFormat.maxContentByteCount`, structurally, so there is no
// per-item `capacityRefused` to fake. Plan §11's aggregate 256 MiB / 1024-ITEM backpressure — "refuse
// new custody with a bounded, user-visible delivery failure" — is a seam item 9 adds in FRONT of
// `admit` / `forChunk`, and its accounting must include parked, manifest-less chunks or a peer can
// park bytes for free.

import Foundation

// MARK: - MeshChunkRefusal

/// Why ``MeshChunkAssembly`` refused a chunk, a binding or a completion. Frozen English tokens,
/// logged verbatim, never localized and never user copy — item 9 owns the user-visible
/// backpressure failure. Not `Error`, not `LocalizedError`.
nonisolated enum MeshChunkRefusal: String, CaseIterable, Equatable, Sendable {
    /// The chunk or manifest belongs to a different item: its `itemID`, `originFingerprint` or
    /// `contentHash` differs. All three, because the identity of routed content is the triple.
    case foreignItem
    /// The chunk's or manifest's chunk count is not this assembly's.
    case countMismatch
    /// `chunkIndex` is at or past `chunkCount`.
    case indexOutOfRange
    /// A DIFFERENT chunk is already held at that index — a differing signed transcript or a
    /// differing payload. A retransmission is a duplicate (a no-op), not this, and so is a second
    /// MINT of the same chunk: CryptoKit's Ed25519 signing is hedged, so two mints of one logical
    /// chunk agree on every field except the 64-byte signature, and item 6 streams with
    /// ``MeshChunker/chunk(of:at:for:identity:)`` precisely so it need not retain what it minted.
    /// This token is an integrity claim about CONTENT; see ``MeshChunkAssembly/admit(_:)``.
    case conflictingChunk
    /// ``MeshChunk/chunkHash`` does not cover the payload. Re-checked here even though
    /// ``MeshChunkVerifier`` checks it, because this is the boundary item 3 gates durable custody
    /// on and it must hold at the storage door regardless of who called what.
    case chunkHashMismatch
    /// Admitting this chunk would take the held bytes past the bound item size. The bounded-growth
    /// statement, said where the growth happens.
    case sizeOverflow
    /// The payload is not the length its index requires — exactly 256 KiB for an interior chunk,
    /// the remainder for the last.
    case payloadLengthMismatch
    /// No manifest has bound this assembly, so completion is impossible: nothing has said what the
    /// whole item's bytes should hash to.
    case notBound
    /// The reassembled blob is not `manifest.size` bytes.
    case sizeMismatch
    /// The reassembled blob does not hash to `manifest.contentHash`. Every chunk can be
    /// individually consistent and the whole still be wrong — this is the check that says so.
    case contentHashMismatch

    /// Frozen English for the diagnostic surface. Never shown as user copy.
    var diagnosticDescription: String {
        switch self {
        case .foreignItem: return "The chunk or manifest belongs to a different routed item."
        case .countMismatch: return "The chunk count disagrees with this assembly's."
        case .indexOutOfRange: return "The chunk index is outside this item's chunk count."
        case .conflictingChunk: return "A different chunk is already held at that index."
        case .chunkHashMismatch: return "The chunk hash does not cover the chunk's payload."
        case .sizeOverflow: return "Admitting the chunk would exceed the item's size."
        case .payloadLengthMismatch: return "The chunk's payload is not the length its index requires."
        case .notBound: return "No manifest has bound this assembly."
        case .sizeMismatch: return "The reassembled item is not the manifest's size."
        case .contentHashMismatch: return "The reassembled item does not hash to the manifest's content hash."
        }
    }
}

// MARK: - Verdicts

/// What ``MeshChunkAssembly/admit(_:)`` did with one chunk. Every input gets one of these; nothing
/// is silently dropped.
nonisolated enum MeshChunkAdmission: Equatable, Sendable {
    /// The chunk was stored. `received` of `expected` indices are now held.
    case admitted(received: Int, expected: Int)
    /// The identical chunk was already held — a retransmission, which is **normal**, not an error.
    /// "Identical" is the **signed transcript plus the payload**, not `==`: a re-mint of the same
    /// chunk carries a fresh hedged Ed25519 signature over identical canonical bytes and lands
    /// here too. Nothing changed.
    case duplicate(received: Int)
    /// The chunk was refused, by name.
    case refused(MeshChunkRefusal)
}

/// What ``MeshChunkAssembly/bind(to:)`` did with one manifest.
nonisolated enum MeshChunkBinding: Equatable, Sendable {
    /// The manifest is this item's; the assembly now knows the item's size. Idempotent — binding
    /// the same manifest twice is `bound` again.
    case bound
    /// The manifest was refused, by name. Nothing was mutated.
    case refused(MeshChunkRefusal)
}

/// What ``MeshChunkAssembly/completion(against:)`` found.
nonisolated enum MeshChunkCompletion: Equatable, Sendable {
    /// Every index is held and the reassembled ciphertext matches the bound manifest's size and
    /// content hash.
    ///
    /// **A NECESSARY, NEVER SUFFICIENT precondition for item 3's custody receipt.** This is a
    /// verdict over **in-memory** bytes: a value type's chunk map does not survive a force-quit,
    /// and plan §3.6 ("durable before acknowledged") is a *second, separate* gate. The order is
    /// **durable, then complete, then receipt** — item 3 emits its receipt only once the
    /// ciphertext is in its sealed sidecar, with the four-state load and the "seal refused"
    /// distinction honoured. Reading this as "the only precondition" ships a receipt for bytes
    /// that exist only in memory.
    case complete(blob: Data)
    /// Some index is missing. No partial blob is ever produced.
    case incomplete(received: Int, expected: Int)
    /// The completion was refused, by name.
    case refused(MeshChunkRefusal)
}

// MARK: - MeshChunkAssembly

/// One routed item's chunks, collected in any order and reassembled once.
///
/// A bounded value: at most ``MeshChunkFormat/maxChunkCount`` (1024) chunks of at most
/// ``MeshChunkFormat/maxChunkPayloadBytes`` (256 KiB) each, which is
/// `MeshRoutedManifestFormat.maxContentByteCount` rather than a second cap of its own. **Both
/// halves are checked at the ``admit(_:)`` door itself**, not left to the verifier precondition
/// below: the count against this assembly's, and the per-chunk 256 KiB in the bound branch (exact
/// length) *and* the unbound one (1 … 256 KiB). The bound is held to the same standard as the
/// chunk hash for the same reason — this is the boundary item 3 gates durable custody on.
///
/// **Two preconditions, neither re-checked here.**
///
/// 1. ``admit(_:)`` takes a chunk ``MeshChunkVerifier`` has already accepted. It re-checks only
///    what is about *this assembly* — plus the chunk hash, because that is the check item 3 gates
///    durable custody on.
/// 2. ``bind(to:)`` and ``completion(against:)`` take a manifest
///    ``MeshRoutedManifestVerifier/verify(_:)`` has already accepted: *it is the only authority on
///    `contentHash`, `size` and the derived chunk count, and none of them is re-derived here.*
///    Without it, ``MeshChunkCompletion/complete(blob:)`` degrades from "whole and authentic" to
///    "self-consistent with whatever manifest the caller handed in".
///
/// **Item 3's seam:** chunk bytes live in memory here. Item 3 re-backs the byte custody with its
/// sealed sidecar and **reuses this verdict logic unchanged** — the durable form must produce the
/// same ``MeshChunkAdmission`` and ``MeshChunkCompletion`` values for the same inputs.
nonisolated struct MeshChunkAssembly: Equatable, Sendable {
    /// The item every admitted chunk must name.
    let itemID: UUID
    /// The origin every admitted chunk must name. Half of the anti-squatting triple.
    let originFingerprint: String
    /// The whole item's claimed content hash, as the manifest or the first chunk stated it. What
    /// the reassembled blob is finally measured against.
    let contentHash: Data
    /// How many chunks the item has.
    let chunkCount: UInt32
    /// The item's byte count once a manifest has bound this assembly; nil while parked. Completion
    /// is impossible while nil.
    private(set) var boundSize: UInt64?
    /// The held chunks by index. At most ``chunkCount`` (≤ 1024) entries.
    private var chunks: [UInt32: MeshChunk] = [:]

    /// The one initializer, private so every assembly starts from a manifest or a chunk that was
    /// checked first.
    private init(itemID: UUID, originFingerprint: String, contentHash: Data, chunkCount: UInt32, boundSize: UInt64?) {
        self.itemID = itemID
        self.originFingerprint = originFingerprint
        self.contentHash = contentHash
        self.chunkCount = chunkCount
        self.boundSize = boundSize
    }

    /// An assembly for a manifest, already bound to its size. Nil when `manifest.size` cannot be
    /// chunked (zero or above the 256 MiB content cap).
    ///
    /// - Important: `manifest` must be one ``MeshRoutedManifestVerifier/verify(_:)`` has already
    ///   accepted — it is the only authority on `contentHash`, `size` and the chunk count, and
    ///   none of them is re-derived here.
    static func forManifest(_ manifest: MeshRoutedManifest) -> MeshChunkAssembly? {
        guard let count = MeshChunkFormat.chunkCount(forSize: manifest.size) else { return nil }
        return MeshChunkAssembly(
            itemID: manifest.itemID, originFingerprint: manifest.originFingerprint,
            contentHash: manifest.contentHash, chunkCount: UInt32(count), boundSize: manifest.size
        )
    }

    /// An UNBOUND assembly for a chunk that arrived before its manifest — the parked case. Nil
    /// when the chunk is malformed.
    ///
    /// - Important: `chunk` must be one ``MeshChunkVerifier/verify(_:)`` has already accepted.
    static func forChunk(_ chunk: MeshChunk) -> MeshChunkAssembly? {
        guard chunk.isWellFormed else { return nil }
        return MeshChunkAssembly(
            itemID: chunk.itemID, originFingerprint: chunk.originFingerprint,
            contentHash: chunk.contentHash, chunkCount: chunk.chunkCount, boundSize: nil
        )
    }

    /// How many distinct indices are held.
    var receivedCount: Int { chunks.count }

    /// How many payload bytes are held. Bounded by 1024 × 256 KiB.
    var bytesHeld: Int { chunks.values.reduce(0) { $0 + $1.payload.count } }

    /// Whether every index is present. Necessary for completion, never sufficient: the manifest's
    /// hash and size still decide.
    var isComplete: Bool { chunks.count == Int(chunkCount) }

    /// Binds this assembly to the item's manifest, learning the exact item size.
    ///
    /// Cross-checks the identity triple and the derived chunk count, then re-validates every
    /// ALREADY-HELD chunk's length against the now-known size in one bounded loop and refuses
    /// **without mutating** if any fails. Idempotent: the same manifest twice is
    /// ``MeshChunkBinding/bound``; a different one is ``MeshChunkRefusal/foreignItem``.
    ///
    /// - Important: `manifest` must be one ``MeshRoutedManifestVerifier/verify(_:)`` has already
    ///   accepted — see the type's precondition 2.
    mutating func bind(to manifest: MeshRoutedManifest) -> MeshChunkBinding {
        guard manifest.itemID == itemID,
              manifest.originFingerprint == originFingerprint,
              manifest.contentHash == contentHash else {
            return .refused(.foreignItem)
        }
        guard let derived = MeshChunkFormat.chunkCount(forSize: manifest.size),
              derived == Int(chunkCount) else {
            return .refused(.countMismatch)
        }
        if let refusal = heldChunkRefusal(forSize: manifest.size) { return .refused(refusal) }
        boundSize = manifest.size
        return .bound
    }

    /// Offers one chunk to the assembly. Every branch returns a verdict; no input is ever silently
    /// dropped.
    ///
    /// A chunk offered at an index already held is ``MeshChunkAdmission/duplicate(received:)``
    /// when its **signed transcript and payload** match what is held — a re-mint's fresh hedged
    /// signature is a retransmission, not a conflict — and ``MeshChunkRefusal/conflictingChunk``
    /// otherwise.
    ///
    /// - Important: `chunk` must be one ``MeshChunkVerifier/verify(_:)`` has already accepted —
    ///   see the type's precondition 1.
    mutating func admit(_ chunk: MeshChunk) -> MeshChunkAdmission {
        guard chunk.itemID == itemID,
              chunk.originFingerprint == originFingerprint,
              chunk.contentHash == contentHash else {
            return .refused(.foreignItem)
        }
        guard chunk.chunkCount == chunkCount else { return .refused(.countMismatch) }
        guard chunk.chunkIndex < chunkCount else { return .refused(.indexOutOfRange) }
        if let verdict = existingVerdict(for: chunk) { return verdict }
        guard MeshRoutedContentDigest.chunkHash(of: chunk.payload) == chunk.chunkHash else {
            return .refused(.chunkHashMismatch)
        }
        if let size = boundSize, UInt64(bytesHeld) + UInt64(chunk.payload.count) > size {
            return .refused(.sizeOverflow)
        }
        if let refusal = lengthRefusal(for: chunk) { return .refused(refusal) }
        chunks[chunk.chunkIndex] = chunk
        return .admitted(received: chunks.count, expected: Int(chunkCount))
    }

    /// Whether the item is whole, and if so its ciphertext.
    ///
    /// The only way to a blob is this function returning ``MeshChunkCompletion/complete(blob:)``,
    /// and it returns the assembly's bytes unchanged when they do not match — the
    /// `MeshPhotoReassembly.admitting(_:reassembled:into:)` rule. A gap is
    /// ``MeshChunkCompletion/incomplete(received:expected:)``, never a partial blob.
    ///
    /// - Important: `manifest` must be one ``MeshRoutedManifestVerifier/verify(_:)`` has already
    ///   accepted, and `.complete` is **necessary, never sufficient** for a custody receipt: it is
    ///   a verdict over in-memory bytes, so durability (plan §3.6) is a second gate item 3 owns.
    func completion(against manifest: MeshRoutedManifest) -> MeshChunkCompletion {
        guard let size = boundSize else { return .refused(.notBound) }
        guard manifest.itemID == itemID,
              manifest.originFingerprint == originFingerprint,
              manifest.contentHash == contentHash,
              manifest.size == size else {
            return .refused(.foreignItem)
        }
        guard let blob = assembledBlob() else {
            return .incomplete(received: chunks.count, expected: Int(chunkCount))
        }
        guard UInt64(blob.count) == manifest.size else { return .refused(.sizeMismatch) }
        guard MeshRoutedContentDigest.contentHash(of: blob) == manifest.contentHash else {
            return .refused(.contentHashMismatch)
        }
        return .complete(blob: blob)
    }

    /// The verdict for an index that is already occupied: a retransmission of the same chunk is a
    /// duplicate no-op, anything else is a conflict. Nil when the index is free.
    ///
    /// Decided on the **content-bearing identity** — the signed transcript plus the payload —
    /// never on `==`, which would fold in the 64-byte `signature`. CryptoKit's Ed25519 signing is
    /// *hedged*, so two mints of one logical chunk differ in exactly that field, and honest
    /// re-mints are the normal case: ``MeshChunker/chunk(of:at:for:identity:)`` exists so item 6
    /// can stream without retaining what it minted, one item sent to two destinations is two
    /// mints, and item 8's custody transfer at departure can hand a holder a copy of what it
    /// already has. Comparing whole values would answer ``MeshChunkRefusal/conflictingChunk`` — an
    /// integrity claim — for honest bytes on exactly the path plan §11 calls load-bearing. Both
    /// copies passed ``MeshChunkVerifier`` (the type's precondition 1), so both signatures are
    /// authentic and the held one is kept.
    private func existingVerdict(for chunk: MeshChunk) -> MeshChunkAdmission? {
        guard let held = chunks[chunk.chunkIndex] else { return nil }
        guard canonicalBytes(for: held) == canonicalBytes(for: chunk),
              held.payload == chunk.payload else {
            return .refused(.conflictingChunk)
        }
        return .duplicate(received: chunks.count)
    }

    /// The length rule, bound and unbound. Bound: exactly what
    /// ``MeshChunk/expectedPayloadByteCount(index:count:size:)`` fixes. Unbound: interior chunks
    /// are exactly 256 KiB — derivable from `chunkCount` alone — and the last is 1 … 256 KiB,
    /// checked **here** rather than left to ``MeshChunk/isWellFormed``: that is the verifier's
    /// precondition, and the assembly's own bounded-growth statement has to be true at this door
    /// whoever called it.
    private func lengthRefusal(for chunk: MeshChunk) -> MeshChunkRefusal? {
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

    /// Whether any already-held chunk has the wrong length for `size`. One bounded loop over the
    /// chunk count; nothing is mutated.
    private func heldChunkRefusal(forSize size: UInt64) -> MeshChunkRefusal? {
        for index in 0..<Int(chunkCount) {
            guard let held = chunks[UInt32(index)] else { continue }
            guard let expected = MeshChunk.expectedPayloadByteCount(
                index: held.chunkIndex, count: chunkCount, size: size
            ), held.payload.count == expected else {
                return .payloadLengthMismatch
            }
        }
        return nil
    }

    /// The concatenated payloads in index order, or nil at the first gap. One bounded loop; never
    /// a partial result.
    private func assembledBlob() -> Data? {
        var blob = Data()
        for index in 0..<Int(chunkCount) {
            guard let held = chunks[UInt32(index)] else { return nil }
            blob.append(held.payload)
        }
        return blob
    }
}
