// MeshChunker.swift
// ProximityKit/Mesh
//
// Network migration P5 item 2 (plan §11): the mint — the ORIGIN's side of the routed-chunk family,
// and the only place a `MeshChunk` signature is ever produced.
//
// The primitive is ONE chunk. `chunks(of:for:identity:)` is the bounded loop over it, so item 6 can
// stream a large item with peak memory of `blob + one chunk` rather than `2 × blob`. The guard
// chain — whose content-hash clause is a pass over the WHOLE blob — runs once per item, not once
// per chunk: the loop mints through the private `mint(of:at:count:for:identity:)`, which takes the
// count the chain already derived.
//
// Two properties are load-bearing and easy to lose. Every SIGNED byte a chunk carries is a pure
// function of the manifest and the blob — no randomness, no clock — which is what item 14's
// property battery and every golden need. (The Ed25519 signature itself is excluded from those
// bytes and CryptoKit's signing is hedged, so two mints of one chunk agree on everything except
// that field.) It is also the decisive reason item 2 does NOT seal the item: an AEAD seal mints a
// random nonce, and that nonce would land INSIDE the blob the content hash and every chunk hash
// measure, so a sealing chunker could not be goldened at all. The seal is item 6 / P6's. And the
// mint **refuses to mint for a manifest the local identity did not originate** (`notTheOrigin`): a
// custodian is a courier, not a co-signer.
//
// The blob is OPAQUE here. Its contract, frozen by item 2: it is self-contained — the seal's nonce
// and tag live inside it, because the manifest carries no nonce field — and `manifest.contentHash`
// and `manifest.size` measure the COMPLETE blob, the exact bytes a custodian stores, a chunker
// splits and a recipient hashes before decrypting. Whatever item 6 / P6 puts inside the blob
// changes nothing in this file.
//
// What is deliberately NOT here: any send path, envelope, queue or pacer (item 6 dispatches; the
// only pacing statement in item 2 is the named constant
// `MeshChunkFormat.maxChunksInFlightPerPeer`), any forwarding or custody transfer (item 8), and
// any content-key handling at all.

import FernletCrypto
import Foundation

// MARK: - MeshChunkMintError

/// Why ``MeshChunker`` refused to mint. Thrown, never returned as nil, and never silent. Not
/// `LocalizedError` — ``diagnosticDescription`` is frozen English for the audit log and is never
/// shown as user copy (the ``MeshRoutedManifestMintError`` idiom).
nonisolated enum MeshChunkMintError: Error, Equatable, Sendable {
    /// There is nothing to chunk.
    case emptyBlob
    /// The blob is not `manifest.size` bytes. The manifest is the authority; a chunker that
    /// re-derived the size from the blob would let the two disagree under one signature.
    case sizeMismatch(blobByteCount: Int, manifestSize: UInt64)
    /// The blob does not hash to `manifest.contentHash` under `Hash.meshRoutedContentV1`.
    case contentHashMismatch
    /// The signing identity is not the manifest's origin. A custodian forwards the origin's exact
    /// signed objects; it never mints new ones for somebody else's item.
    case notTheOrigin(origin: String)
    /// `manifest.size` cannot be chunked inside ``MeshChunkFormat/maxChunkCount``. Unreachable
    /// while `MeshRoutedManifest.isWellFormed` bounds `size` to 256 MiB *and* the blob really is
    /// that size — kept because the bound belongs where the growth happens.
    case tooManyChunks(size: UInt64)
    /// The single-chunk mint was asked for an index outside `0 ..< chunkCount`.
    case indexOutOfRange(index: Int, count: Int)

    /// Frozen English for the diagnostic surface. Never shown as user copy.
    var diagnosticDescription: String {
        switch self {
        case .emptyBlob: return "The routed item's ciphertext is empty."
        case .sizeMismatch(let blobByteCount, let manifestSize):
            return "The blob is \(blobByteCount) bytes; the manifest claims \(manifestSize)."
        case .contentHashMismatch: return "The blob does not hash to the manifest's content hash."
        case .notTheOrigin(let origin):
            return "This device is not the manifest's origin \(origin)."
        case .tooManyChunks(let size):
            return "A size of \(size) bytes exceeds the routed chunk cap."
        case .indexOutOfRange(let index, let count):
            return "Chunk index \(index) is outside 0..<\(count)."
        }
    }
}

// MARK: - MeshChunker

/// The origin's mint for ``MeshChunk`` — one chunk at a time, or the whole bounded run.
///
/// The **type** is `nonisolated`; only the two mint functions are `@MainActor`, because
/// `IdentityService` is (and `@MainActor` plus `nonisolated` on one declaration does not compile).
/// The guard chain stays nonisolated and pure, so the verifier, the assembler and
/// ``MeshChunkFormat/chunkCount(forSize:)`` reach the same arithmetic without an actor hop.
///
/// **Emission contract, built by item 6, stated here so it is not re-invented:** one
/// ``MeshChunkPayload`` per chunk inside one
/// `FernletIdentityEnvelope.signed(payloadType: .meshRoutedChunk, payloadEncryption: .none, …)`,
/// sent `.reliable`, at most ``MeshChunkFormat/maxChunksInFlightPerPeer`` outstanding per peer. A
/// 256 KiB payload in a signed envelope is above `MeshTransferStreamTable.bulkFloorBytes` and below
/// `SealedPayloadFraming.maxInflatedByteCount`, so it takes a transfer stream by size alone — "ride
/// the lane" IS "emit one ordinary reliable frame". **No send code ships in item 2.**
nonisolated enum MeshChunker {

    /// Mints exactly one signed chunk — the primitive, so a large item can be streamed at
    /// `blob + one chunk` of peak memory.
    ///
    /// - Parameters:
    ///   - blob: The item's complete sealed ciphertext. Opaque; nothing here parses it.
    ///   - index: Which chunk, `0 ..< ceil(size / 256 KiB)`.
    ///   - manifest: The item's manifest. The only authority on item, origin, content hash and size.
    ///   - identity: The origin. Its fingerprint must equal `manifest.originFingerprint`.
    /// - Returns: the signed chunk, whose canonical bytes are exactly what was signed.
    /// - Throws: ``MeshChunkMintError`` or the identity's signing error. Never a trap.
    @MainActor
    static func chunk(
        of blob: Data,
        at index: Int,
        for manifest: MeshRoutedManifest,
        identity: IdentityService
    ) throws -> MeshChunk {
        let count = try validated(blob: blob, manifest: manifest, origin: identity.localFingerprint)
        return try mint(of: blob, at: index, count: count, for: manifest, identity: identity)
    }

    /// Mints every chunk of `blob`, in index order. Bounded by ``MeshChunkFormat/maxChunkCount``
    /// (1024) — never a `while`.
    ///
    /// - Parameters:
    ///   - blob: The item's complete sealed ciphertext.
    ///   - manifest: The item's manifest.
    ///   - identity: The origin.
    /// - Returns: `ceil(manifest.size / 256 KiB)` signed chunks.
    /// - Throws: ``MeshChunkMintError`` or the identity's signing error.
    ///
    /// The guard chain runs **once per item, never once per chunk**: ``validated(blob:manifest:origin:)``
    /// hashes the WHOLE blob, so re-running it inside the loop would cost `chunkCount + 1` passes
    /// over the item — 1025 SHA-256 passes over 256 MiB for a maximal one, on the main actor — for
    /// a chain whose every clause but the index is loop-invariant. The loop mints through the
    /// private ``mint(of:at:count:for:identity:)`` instead.
    @MainActor
    static func chunks(
        of blob: Data,
        for manifest: MeshRoutedManifest,
        identity: IdentityService
    ) throws -> [MeshChunk] {
        let count = try validated(blob: blob, manifest: manifest, origin: identity.localFingerprint)
        var minted: [MeshChunk] = []
        minted.reserveCapacity(count)
        for index in 0..<count {
            minted.append(try mint(of: blob, at: index, count: count, for: manifest, identity: identity))
        }
        return minted
    }

    /// Mints one chunk over an ALREADY-validated `(blob, manifest, origin)` and the count
    /// ``validated(blob:manifest:origin:)`` derived — the loop body, and the whole mint apart from
    /// that chain.
    ///
    /// Private on purpose: every caller reaches it through a function that has just validated, so
    /// there is no door into the mint that skips the guard chain. The `index` bound is re-checked
    /// here because it is the one clause that is NOT loop-invariant.
    @MainActor
    private static func mint(
        of blob: Data,
        at index: Int,
        count: Int,
        for manifest: MeshRoutedManifest,
        identity: IdentityService
    ) throws -> MeshChunk {
        guard index >= 0, index < count else {
            throw MeshChunkMintError.indexOutOfRange(index: index, count: count)
        }
        let payload = slice(of: blob, at: index)
        let unsigned = MeshChunk(
            meshID: manifest.meshID, itemID: manifest.itemID,
            originFingerprint: manifest.originFingerprint, contentHash: manifest.contentHash,
            chunkIndex: UInt32(index), chunkCount: UInt32(count),
            chunkHash: MeshRoutedContentDigest.chunkHash(of: payload),
            expiresAt: manifest.expiresAt, payload: payload, signature: Data()
        )
        let signature = try identity.sign(
            canonicalBytes(for: unsigned),
            purpose: FernletCryptoPurpose.Signature.meshRoutedChunkV1
        )
        return signed(unsigned, with: signature)
    }

    /// The mint's guard chain, in ``MeshChunkMintError``'s case order, and the derived chunk count.
    /// Pure and `nonisolated`: every refusal is named before a byte is sliced or a signature taken.
    ///
    /// Runs **once per item**. Its content-hash clause is a pass over the whole blob, which is why
    /// ``chunks(of:for:identity:)`` derives the count here and then mints through
    /// ``mint(of:at:count:for:identity:)`` rather than re-entering the public primitive per index.
    private static func validated(blob: Data, manifest: MeshRoutedManifest, origin: String) throws -> Int {
        guard !blob.isEmpty else { throw MeshChunkMintError.emptyBlob }
        guard UInt64(blob.count) == manifest.size else {
            throw MeshChunkMintError.sizeMismatch(blobByteCount: blob.count, manifestSize: manifest.size)
        }
        guard MeshRoutedContentDigest.contentHash(of: blob) == manifest.contentHash else {
            throw MeshChunkMintError.contentHashMismatch
        }
        guard origin == manifest.originFingerprint else {
            throw MeshChunkMintError.notTheOrigin(origin: manifest.originFingerprint)
        }
        guard let count = MeshChunkFormat.chunkCount(forSize: manifest.size) else {
            throw MeshChunkMintError.tooManyChunks(size: manifest.size)
        }
        return count
    }

    /// The bytes of chunk `index`, as a FRESH `Data` — never a `Data.SubSequence` sharing the
    /// blob's indices, whose non-zero `startIndex` is a classic off-by-one once it round-trips
    /// through `Codable`.
    private static func slice(of blob: Data, at index: Int) -> Data {
        let start = index * MeshChunkFormat.maxChunkPayloadBytes
        let end = min(start + MeshChunkFormat.maxChunkPayloadBytes, blob.count)
        guard start < end else { return Data() }
        return Data(blob[blob.startIndex + start ..< blob.startIndex + end])
    }

    /// The unsigned chunk rebuilt with its signature, from the unsigned value's OWN (already
    /// floored) fields — so the bytes that were signed and the bytes that go on the wire agree.
    private static func signed(_ unsigned: MeshChunk, with signature: Data) -> MeshChunk {
        MeshChunk(
            meshID: unsigned.meshID, itemID: unsigned.itemID,
            originFingerprint: unsigned.originFingerprint, contentHash: unsigned.contentHash,
            chunkIndex: unsigned.chunkIndex, chunkCount: unsigned.chunkCount,
            chunkHash: unsigned.chunkHash, expiresAt: unsigned.expiresAt,
            payload: unsigned.payload, signature: signature
        )
    }
}
