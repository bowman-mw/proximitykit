// MeshChunk.swift
// ProximityKit/Mesh
//
// Network migration P5 item 2 (plan §11): one origin-signed slice of a routed item's ciphertext,
// and the two domain-tagged digests the routed family hashes under.
//
// A chunk is the second routed-content record. It says which mesh and item, who authored it, what
// the WHOLE item's ciphertext hashes to, where this slice sits (`chunkIndex` of `chunkCount`),
// what THIS slice hashes to, when the item stops mattering, and it carries the slice — signed by
// the ORIGIN only. A custodian forwards the exact object inside its own envelope and never
// re-signs: there is no factory here that signs somebody else's chunk, which is what keeps origin
// authenticity a property of the bytes rather than of the path they took.
//
// Two structural facts are worth stating once. The payload is EXCLUDED from the signed transcript
// and bound through ``MeshChunk/chunkHash`` — 32 bytes of transcript instead of 256 KiB of copy,
// with the same authenticity. And the chunk's identity is the triple
// `(originFingerprint, itemID, chunkIndex)`: the frame is unsealed, so any admitted member can
// mint a chunk reusing another origin's `itemID` under its own key.
//
// Chunks ride P2's existing per-transfer stream lane with NO transport change: a 256 KiB payload
// inside a signed envelope is far above `MeshTransferStreamTable.bulkFloorBytes` and far below
// `SealedPayloadFraming.maxInflatedByteCount`, so `NetworkMeshSession` gives it a QUIC stream of
// its own by size alone. Frames on separate streams are not ordered against each other, which is
// why ``MeshChunkAssembly`` is order-independent by construction.
//
// What is deliberately NOT here: persistence (item 3, with its wipe row), dispatch and emission
// (item 6), any relay hop or custody transfer (item 8; increment 2's hop count and TTL are not on
// the wire), the item seal (item 6 / P6 — this file chunks an OPAQUE blob), the type-token
// registry (item 11), backpressure (item 9). `MeshChunkVerifier` is the receive-side door,
// `MeshChunker` the mint, `MeshChunkAssembly` the reassembler; this file is the record, its
// bounds and its digests.

import CryptoKit
import FernletCrypto
import Foundation

// MARK: - MeshChunkFormat

/// Fixed widths and caps of the routed-chunk wire family (network migration P5 item 2, plan §11).
///
/// Every constant is a **bound on untrusted input** as much as a description of honest output: a
/// chunk arrives from a peer, may be forwarded verbatim by a custodian that never saw it minted,
/// and is checked field by field BEFORE its origin signature is verified
/// (``MeshChunk/isWellFormed``). Nothing here is a tuning knob — a change to a width is a wire
/// decision, and a change to a cap is a bound decision recorded in the plan.
nonisolated enum MeshChunkFormat {
    /// Ed25519 signature length. Shared with the routed-manifest family.
    static let signatureByteCount = MeshRoutedManifestFormat.signatureByteCount
    /// SHA-256 width of ``MeshChunk/chunkHash``.
    static let chunkHashByteCount = MeshRoutedManifestFormat.contentHashByteCount
    /// SHA-256 width of ``MeshChunk/contentHash`` — the manifest's, copied.
    static let contentHashByteCount = MeshRoutedManifestFormat.contentHashByteCount
    /// Cap on a fingerprint's UTF-8 length, shared with the routed-manifest family.
    static let maxFingerprintLength = MeshRoutedManifestFormat.maxFingerprintLength

    /// Plan §11's chunk size: 256 KiB, and the **only new magic number in the item**.
    ///
    /// A named constant precisely so tier 2 can re-measure chunk pacing at another size **without
    /// touching the wire shape** — the chunk carries no size field, and boundaries are a pure
    /// function of this number plus ``MeshChunk/chunkCount``. It is not a knob, not an env hook,
    /// and never negotiated per peer: two peers that disagreed on it would disagree on every
    /// interior chunk's length.
    static let maxChunkPayloadBytes = 256 * 1024

    /// Chunks in one maximal item: `256 MiB / 256 KiB`, **derived** from
    /// ``MeshRoutedManifestFormat/maxContentByteCount`` — the single definition of 256 MiB in the
    /// tree — never restated.
    ///
    /// **1024 is two different caps that happen to be equal, and item 9 must not collapse them.**
    /// Plan §9 caps the routed store at 1024 *logical items*; this is 1024 *chunks in one maximal
    /// item*. A single 256 MiB item exhausts the whole byte budget while consuming 1 of the 1024
    /// item slots.
    static let maxChunkCount = Int(MeshRoutedManifestFormat.maxContentByteCount) / maxChunkPayloadBytes

    /// How many routed chunks one sender should keep in flight to one peer: **three, one slot of
    /// headroom**, not a throughput target and not a guarantee.
    ///
    /// ``MeshTransferStreamTable/maxConcurrentOutbound`` is **one tunnel's whole outbound bulk
    /// budget in one direction**, booked by *every* reliable frame at or above the 64 KiB floor —
    /// friend photos above all, which is what the shipped 4 was sized against. Setting the routed
    /// bound equal to it would let one transfer at full pace fill the budget alone and push a
    /// concurrent photo onto the control stream, which is the head-of-line blocking the transfer
    /// lane exists to prevent. Nothing reserves a slot for the photo path, and
    /// ``MeshTransferStreamTable/openOutbound(reliableByteCount:)`` returning nil is
    /// indistinguishable from "sub-floor", so an over-eager sender never learns it was throttled —
    /// hence a *courtesy* bound. **The safe in-flight number is a tier-2 measurement** ("whether a
    /// large transfer starves the control stream", plan §11), run with a concurrent photo transfer
    /// on the same tunnel. This constant is the v1 placeholder item 6 must not silently re-derive.
    static let maxChunksInFlightPerPeer = MeshTransferStreamTable.maxConcurrentOutbound - 1

    /// `ceil(size / maxChunkPayloadBytes)`, or nil when `size` is zero or above the content cap.
    ///
    /// Pure arithmetic on this enum's own constant — the single definition the mint, the verifier,
    /// the assembler and ``MeshChunk/expectedPayloadByteCount(index:count:size:)`` all share, so
    /// none of them can derive a different count. The cap guard runs FIRST, so the ceil addition
    /// below can never overflow on a hostile `size`.
    static func chunkCount(forSize size: UInt64) -> Int? {
        guard size >= 1, size <= MeshRoutedManifestFormat.maxContentByteCount else { return nil }
        let payloadBytes = UInt64(maxChunkPayloadBytes)
        return Int((size + payloadBytes - 1) / payloadBytes)
    }
}

// MARK: - MeshRoutedContentDigest

/// The two domain-tagged digests of the routed-content family, plus the derived chunk id.
///
/// **Why two digests and not one.** Untagged, a one-chunk item's *item* hash and its *chunk* hash
/// would be the same 32 bytes, so a chunk hash could be replayed as a content hash. Each digest
/// therefore carries its own `Hash` purpose as a length-prefixed prefix, exactly as
/// `canonicalInventoryDigestBytes` does — the post-standardization house rule
/// (`MeshPhotoReassembly`'s bare SHA-256 is the pre-standardization form and is not the model).
///
/// The prefix is **writer-produced** (a ``CanonicalByteWriter`` with one
/// `appendLengthPrefixed`), then the body is *streamed* into the hasher rather than appended to a
/// buffer: a 256 KiB `appendLengthPrefixed(payload)` would copy the payload once per hash, and a
/// streaming `SHA256()` does not. No length bytes are hand-rolled.
///
/// **The blob contract, frozen by item 2 (C12).** ``contentHash(of:)`` and
/// `MeshRoutedManifest.size` measure the **complete sealed blob** — the exact bytes a custodian
/// stores, a chunker splits and a recipient hashes before decrypting. The blob is therefore
/// **self-contained**: its seal's nonce and tag live *inside* it, because the manifest carries no
/// nonce field. Whatever item 6 / P6 ships inside the blob changes nothing here, which is the
/// property this freeze buys.
nonisolated enum MeshRoutedContentDigest {

    /// The zero id ``chunkID(itemID:chunkIndex:)`` falls back to if it is ever handed a short
    /// digest. Unreachable: SHA-256 is 32 bytes. Present so no `!` is needed (Power of 10 R5).
    private static let zeroID = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    /// `SHA-256(lp(Hash.meshRoutedContentV1) ‖ blob)` — the digest a
    /// ``MeshRoutedManifest/contentHash`` carries, over the **complete sealed blob** (C12).
    static func contentHash(of blob: Data) -> Data {
        digest(FernletCryptoPurpose.Hash.meshRoutedContentV1, over: blob)
    }

    /// `SHA-256(lp(Hash.meshRoutedChunkV1) ‖ payload)` — the digest one ``MeshChunk`` carries over
    /// its own slice. A different domain from ``contentHash(of:)`` so a one-chunk item's two
    /// digests can never be interchanged.
    static func chunkHash(of payload: Data) -> Data {
        digest(FernletCryptoPurpose.Hash.meshRoutedChunkV1, over: payload)
    }

    /// One chunk's replay-window id: `SHA-256(lp(Hash.meshRoutedChunkIDV1) ‖ uuid(itemID) ‖
    /// u64(chunkIndex))`, first 16 bytes read as a `UUID`.
    ///
    /// **Derived, never a wire field**: 16 bytes × 1024 chunks of nothing on the wire, and a
    /// sender-chosen id is an attacker-chosen id. Deterministic; equal for a retransmission of the
    /// same chunk (it is *not* a hash of the payload); different for a different index or item;
    /// recomputable by item 3 from the `(itemID, index)` it stores. `originFingerprint` is
    /// deliberately **not** an input — `MeshFrameReplayWindow.admit(frameID:from:…)` already
    /// separates by sender, so the real key is the pair `(origin, chunkID)` and folding the origin
    /// in twice would make the id underivable from what item 3 holds. P5 item 12 wired exactly that
    /// pair: the window's author axis is `chunk.originFingerprint`, never the forwarding envelope's
    /// sender, so one origin's chunk arriving via two custodians is one row and two origins' chunks
    /// at the same `(itemID, index)` are two.
    ///
    /// The result is **not** an RFC-4122 versioned UUID: it is a 128-bit dedup key that happens to
    /// have `UUID`'s shape, which is what `MeshFrameReplayWindow` takes.
    static func chunkID(itemID: UUID, chunkIndex: UInt32) -> UUID {
        var writer = CanonicalByteWriter()
        writer.appendLengthPrefixed(FernletCryptoPurpose.Hash.meshRoutedChunkIDV1.data)
        writer.appendUUID(itemID)
        writer.appendUInt64(UInt64(chunkIndex))
        return uuid(fromFirst16: Data(SHA256.hash(data: writer.bytes)))
    }

    /// `SHA-256` over the purpose's length-prefixed spelling followed by `body`, streamed so the
    /// body is never copied into an intermediate buffer.
    private static func digest(_ purpose: CryptographicPurpose, over body: Data) -> Data {
        var writer = CanonicalByteWriter()
        writer.appendLengthPrefixed(purpose.data)
        var hasher = SHA256()
        hasher.update(data: writer.bytes)
        hasher.update(data: body)
        return Data(hasher.finalize())
    }

    /// The first 16 bytes of `data` as a `UUID`, via the tuple form — never `withUnsafeBytes`
    /// (Power of 10 R9). A parallel 16-byte reader to `HeartDropSealer.uuid(from:)`, which is
    /// heart-drop vocabulary with no other caller, rather than a duplicated policy.
    private static func uuid(fromFirst16 data: Data) -> UUID {
        guard data.count >= 16 else { return zeroID }
        let bytes = [UInt8](data.prefix(16))
        return UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                           bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
    }
}

// MARK: - MeshChunk

/// One origin-signed slice of a routed item's ciphertext (network migration P5 item 2, plan §11):
/// which mesh and item, who authored it, the whole item's content hash, this slice's position and
/// its own hash, when the item expires, and the slice itself.
///
/// **Signed by the origin only.** A custodian forwards this exact object — the same decoded
/// fields, the same `signature` — inside its OWN `FernletIdentityEnvelope`; there is no factory
/// that re-signs someone else's chunk, and ``MeshChunkVerifier`` resolves the signing key from
/// ``originFingerprint`` via the admission ledger, never from the envelope's sender. A
/// since-departed origin's chunk still verifies (leaving is not a retraction); a quorum-REMOVED
/// origin's does not.
///
/// **The payload is excluded from the signed transcript and bound through ``chunkHash``.** The
/// receiver checks `chunkHash == MeshRoutedContentDigest.chunkHash(of: payload)`, so the
/// signature is a statement about the bytes *through* that hash — 96 bytes of signature and hash
/// per 256 KiB slice (0.04 %), and no 256 KiB copy into a signing buffer. The reassembled blob is
/// checked against the manifest's `contentHash` before any completion is reported.
///
/// **A chunk without its manifest is admissible.** Mesh, shape, signature, chunk hash and expiry
/// are all checkable from the chunk alone, so it is verified and *parked*; the manifest-dependent
/// checks run when one binds. Chunks ride per-transfer streams that are explicitly not ordered
/// against the control stream carrying the manifest, so manifest-last is a normal case, not an
/// attack.
///
/// Carries **no** `createdAt` (ordering is the manifest's job), no `size` (``chunkCount`` plus the
/// fixed 256 KiB boundary is the same information without a second source of truth under one
/// signature), no type token (the type gate happened at the manifest — one registry, not two), no
/// key epoch, branch or partition (invariants §3.2/§3.3), no custodian, hop count or TTL
/// (increment 2's vocabulary, deliberately off the wire), and no explicit chunk id (``chunkID`` is
/// derived). Records carry **no schema integer**: the `.v1` in the domain IS the version, so a
/// later field means a whole `routed-chunk.v2` family beside v1 — never an optional `Codable`
/// field, which outside the canonical bytes would be unsigned and forgeable.
///
/// Pure value; every instant is a parameter and nothing reads a clock. `Codable` **for the wire
/// only** — nothing persists this type in item 2 (item 3 owns persistence).
nonisolated struct MeshChunk: Codable, Equatable, Sendable {
    /// The mesh this chunk belongs to. A chunk for another mesh is a **refusal**, not a difference
    /// — and `MeshFrameReplayWindow.admit` needs it on the chunk itself, since a chunk may arrive
    /// before its manifest.
    let meshID: UUID
    /// The routed item this chunk is part of — equal to ``MeshRoutedManifest/itemID`` and to
    /// `MeshDeliveryTarget.contentID`. **Never the store's key on its own:** the frame is
    /// unsealed, so any admitted member can mint a chunk reusing another origin's `itemID` under
    /// its own key. The identity of a chunk is the triple
    /// `(originFingerprint, itemID, chunkIndex)`.
    let itemID: UUID
    /// The author, and the only signer. The verifying key is resolved from the **admission
    /// ledger** by this field — never from the envelope sender, which is whoever is forwarding
    /// this hop.
    let originFingerprint: String
    /// The manifest's ``MeshRoutedManifest/contentHash``, copied: `SHA-256` over the **complete
    /// sealed blob** under `Hash.meshRoutedContentV1`. Carried so a chunk arriving before its
    /// manifest is self-describing, and so item 3 can bind custody to content rather than to an id
    /// alone. 32 bytes per 256 KiB.
    let contentHash: Data
    /// Zero-based position. Chunk boundaries are a pure function of the blob, so this plus
    /// ``chunkCount`` fixes the payload's expected length exactly.
    let chunkIndex: UInt32
    /// How many chunks the whole item has: `ceil(size / 256 KiB)`. Cross-checked against the
    /// manifest's `size` at bind time; a disagreement is a named refusal, never a reconciliation.
    let chunkCount: UInt32
    /// `SHA-256` over **this chunk's payload** under `Hash.meshRoutedChunkV1` — a different domain
    /// from the item hash so a one-chunk item's two digests can never be interchanged. The payload
    /// is excluded from the signed transcript and bound **through** this field.
    let chunkHash: Data
    /// ``MeshRoutedManifest/expiry(afterHardDeadline:)`` — the mesh `hardDeadline` floored plus the
    /// 20-minute development grace, the **same formula**, never restated. Checked for **exact**
    /// equality against the receiver's own value. Present so a chunk is admissible to the replay
    /// window and retirable **without** its manifest. Compared only as a `Date`.
    let expiresAt: Date
    /// The ciphertext slice, 1 … ``MeshChunkFormat/maxChunkPayloadBytes``. Opaque to this type:
    /// the seal's own nonce and tag live **inside** the blob these slices reassemble (the manifest
    /// carries no nonce), so nothing here parses it. Excluded from ``canonicalBytes(for:)-(MeshChunk)``
    /// and bound through ``chunkHash``; still part of `==`, because transcript exclusion is a
    /// serializer fact, not a value fact.
    let payload: Data
    /// The origin's Ed25519 signature over ``canonicalBytes(for:)-(MeshChunk)`` under
    /// `FernletCryptoPurpose.Signature.meshRoutedChunkV1`. Excluded from those bytes. A custodian
    /// carries it verbatim; there is no API in this module that re-signs somebody else's chunk.
    let signature: Data

    /// Builds a chunk from already-signed parts, flooring ``expiresAt`` to whole seconds through
    /// ``MeshRoutedManifest/floored(_:)`` — so a decoded chunk's `Date` is always the value the
    /// signature covers. Nothing else is clamped: an over-long `payload` must **fail**
    /// ``isWellFormed``, never be silently trimmed into a valid-looking chunk.
    init(
        meshID: UUID,
        itemID: UUID,
        originFingerprint: String,
        contentHash: Data,
        chunkIndex: UInt32,
        chunkCount: UInt32,
        chunkHash: Data,
        expiresAt: Date,
        payload: Data,
        signature: Data
    ) {
        self.meshID = meshID
        self.itemID = itemID
        self.originFingerprint = originFingerprint
        self.contentHash = contentHash
        self.chunkIndex = chunkIndex
        self.chunkCount = chunkCount
        self.chunkHash = chunkHash
        self.expiresAt = MeshRoutedManifest.floored(expiresAt)
        self.payload = payload
        self.signature = signature
    }

    /// Decodes with the same floor the memberwise initializer applies (the `MeshEpochHeadsPayload`
    /// idiom): it routes through that initializer, so the two doors cannot drift. A relay that
    /// re-encoded the wire with a sub-second fraction decodes back to the origin's exact bytes.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            meshID: try container.decode(UUID.self, forKey: .meshID),
            itemID: try container.decode(UUID.self, forKey: .itemID),
            originFingerprint: try container.decode(String.self, forKey: .originFingerprint),
            contentHash: try container.decode(Data.self, forKey: .contentHash),
            chunkIndex: try container.decode(UInt32.self, forKey: .chunkIndex),
            chunkCount: try container.decode(UInt32.self, forKey: .chunkCount),
            chunkHash: try container.decode(Data.self, forKey: .chunkHash),
            expiresAt: try container.decode(Date.self, forKey: .expiresAt),
            payload: try container.decode(Data.self, forKey: .payload),
            signature: try container.decode(Data.self, forKey: .signature)
        )
    }

    /// Whether every field has the width or bound the format fixes. Checked on **untrusted bytes,
    /// BEFORE any signature verify**. Cross-checks against a manifest are ``MeshChunkVerifier``'s,
    /// after the signature.
    var isWellFormed: Bool {
        hasWellFormedWidths && hasWellFormedCounts
    }

    /// The fixed-width half of ``isWellFormed``.
    private var hasWellFormedWidths: Bool {
        signature.count == MeshChunkFormat.signatureByteCount
            && chunkHash.count == MeshChunkFormat.chunkHashByteCount
            && contentHash.count == MeshChunkFormat.contentHashByteCount
            && !originFingerprint.isEmpty
            && originFingerprint.utf8.count <= MeshChunkFormat.maxFingerprintLength
    }

    /// The counted half of ``isWellFormed``: the chunk cap, the index inside it, and the payload
    /// bound. An over-long payload fails here rather than being trimmed.
    private var hasWellFormedCounts: Bool {
        chunkCount >= 1
            && Int(chunkCount) <= MeshChunkFormat.maxChunkCount
            && chunkIndex < chunkCount
            && payload.count >= 1
            && payload.count <= MeshChunkFormat.maxChunkPayloadBytes
    }

    /// Liveness under an injected clock: `now <= expiresAt`, the same predicate as
    /// `MeshFrameReplayWindow.admit` and ``MeshRoutedManifest/isLive(at:)``. Never reads `Date()`.
    func isLive(at now: Date) -> Bool {
        now <= expiresAt
    }

    /// This chunk's replay-window id — see ``MeshRoutedContentDigest/chunkID(itemID:chunkIndex:)``.
    /// Derived, never a wire field. P5 item 12 wires it as
    /// `window.admit(frameID: chunk.chunkID, from: chunk.originFingerprint, meshID: context.meshID,
    /// expiresAt: chunk.expiresAt, now: now)` — the id, the author and the expiry come off the
    /// chunk, and the author is the **origin**, never the forwarding envelope's sender; the mesh id
    /// is the **ingest session's own** (`currentMesh.meshID`), not the frame's claimed one.
    ///
    /// That last parameter makes the window's own mesh guard inert on this path by construction:
    /// the routed window is built with `context.meshID` and probed with it, so
    /// ``MeshFrameReplayVerdict/foreignMesh`` is unreachable at the four routed doors. It is not a
    /// gap — a chunk naming another mesh is refused by ``MeshChunkVerifier`` one step later
    /// (`chunk.meshID == meshID`, its own `.foreignMesh`), and the same holds for the manifest and
    /// both receipt kinds. The foreign-mesh refusal is the verifiers' and stays there; the window's
    /// job here is the id.
    ///
    /// **The 64-vs-1024 caveat this doc used to carry is answered, twice over.** The routed window
    /// is a per-instance one: `framesPerSender` is `MeshRoutedDrainBounds.sessionFramesPerPeer`
    /// (1024 + 32 = 1056 ≥ one maximal item's 1024 chunks + its manifest + both receipt kinds), so
    /// the 65th chunk of a 16 MiB item is ordinary traffic. And structurally, `senderWindowFull` is
    /// a **named degradation, never a refusal**: the manager's probe acts on `.replayed` alone and
    /// every other verdict falls through to the unchanged verify-and-store path, so no legitimate
    /// chunk can be dropped by this defence at any window size.
    var chunkID: UUID {
        MeshRoutedContentDigest.chunkID(itemID: itemID, chunkIndex: chunkIndex)
    }

    /// The one place the chunk-boundary rule lives: how many bytes the chunk at `index` of `count`
    /// must carry for an item of `size` bytes.
    ///
    /// Every index but the last is exactly ``MeshChunkFormat/maxChunkPayloadBytes``; the last is
    /// the remainder. Returns nil when `index` is out of range or when `count` disagrees with
    /// `MeshChunkFormat.chunkCount(forSize: size)` — the mint, the verifier, the assembler and the
    /// tests all read this one function, so the four cannot disagree.
    static func expectedPayloadByteCount(index: UInt32, count: UInt32, size: UInt64) -> Int? {
        guard index < count else { return nil }
        guard let derived = MeshChunkFormat.chunkCount(forSize: size), derived == Int(count) else { return nil }
        guard Int(index) == derived - 1 else { return MeshChunkFormat.maxChunkPayloadBytes }
        let priorBytes = UInt64(derived - 1) * UInt64(MeshChunkFormat.maxChunkPayloadBytes)
        return Int(size - priorBytes)
    }
}

// MARK: - MeshChunkPayload

/// The wire frame for a ``MeshChunk`` — `PayloadType.meshRoutedChunk`, signed and UNSEALED like
/// the routed manifest beside it so a custodian can re-broadcast it verbatim; the payload is
/// already ciphertext under the item's own content key, and pairwise sealing would make a chunk
/// readable only by its first hop. Carries no second claim about the origin: the record already
/// says, under the origin's own signature. Registered in item 2, dispatched from item 6 (P4's
/// "built, unwired" shape).
nonisolated struct MeshChunkPayload: Codable, Equatable, Sendable {
    /// The origin's signed slice.
    let chunk: MeshChunk

    /// Wraps a chunk for the wire.
    init(chunk: MeshChunk) {
        self.chunk = chunk
    }
}
