// MeshChunkTests.swift
// ProximityKitTests
//
// P5 item 2 (plan §11): the routed CHUNK — the second routed wire family.
//
// Four claims are walled here, each one a thing a later item cannot cheaply re-derive:
//
// 1. **The signed bytes are pinned, and so are the three digests.** `goldenRoutedChunkHex` and the
//    chunk-hash / content-hash / chunk-id vectors were derived from the FORMAT by an independent
//    Python re-implementation that first reproduced the shipped `goldenInventoryHex`,
//    `goldenEpochHeadsHex` AND item 1's `goldenRoutedManifestHex` byte-for-byte. A golden that only
//    records what the code did proves nothing; these were computed independently and then met. The
//    frame is additive: nothing above it moves, and the manifest golden is re-asserted here untouched.
// 2. **The payload is bound through the hash, not carried in the transcript.** Replacing the
//    payload moves no signed byte; replacing the signature moves none either. That is what makes
//    a 256 KiB slice cost 32 transcript bytes and still be authentic.
// 3. **The two digest domains disagree on identical bytes**, which is the whole reason a
//    one-chunk item's item hash and chunk hash are not the same 32 bytes.
// 4. **Every shape fault is a refusal, never a repair** — an over-long payload fails
//    `isWellFormed` rather than being trimmed into a valid-looking chunk — and every derived
//    constant is checked against the constant it is derived from.
//
// Nothing here sleeps, touches disk, or reads a wall clock for a decision.
//
// A partial copy (ProximityKit plan step A1, the split's first batch of copied suites): of the
// Fernlet repository's FernletTests file of the same name, this holds only the fixtures the
// package's copied suites read (`MeshChunkFixtures`, `extension MeshChunk` and
// `MeshChunkShapeFault`), unchanged; its suites stay there, so what this header says of them is not
// held here.

import Foundation
import Testing
@testable import ProximityKit

// MARK: - Fixtures

/// Fixed values for the chunk golden vectors — every pinned byte traces to a line here; nothing
/// reads a clock. `meshID`, `itemID`, `contentHash`, `expiresAt` and `opaqueSignature` are item 1's
/// own, so the chunk vector reads beside the manifest vector as one story.
enum MeshChunkFixtures {

    static let meshID = MeshRoutedManifestFixtures.meshID
    static let itemID = MeshRoutedManifestFixtures.itemID
    static let base = MeshRoutedManifestFixtures.base
    static let originFingerprint = MeshRoutedManifestFixtures.originFingerprint
    /// `00 01 … 1f` — the manifest's, copied onto the chunk exactly as the wire does.
    static let contentHash = MeshRoutedManifestFixtures.contentHash
    /// `hardDeadline + 20 min`, the manifest's own expiry: the chunk never restates the formula.
    static let expiresAt = MeshRoutedManifestFixtures.expiresAt
    static let hardDeadline = MeshRoutedManifestFixtures.hardDeadline
    static let opaqueSignature = MeshMembershipEventFixtures.opaqueSignature

    /// Four bytes. The payload is NOT in the transcript, so a tiny fixture pins exactly the same
    /// bytes a 256 KiB one would — and keeps the golden readable.
    static let payload = Data([0xC0, 0xC1, 0xC2, 0xC3])
    /// Index 1 of 3: a nonzero index catches an omitted or transposed field, which index 0 would not.
    static let chunkIndex: UInt32 = 1
    static let chunkCount: UInt32 = 3
    /// A fixed 48-byte "blob" for the ITEM digest vector. Traceable, and deliberately not the
    /// chunk payload, so the two digest goldens cannot be confused for each other.
    static let digestBlob = Data((0..<48).map { UInt8(truncatingIfNeeded: $0 &* 3 &+ 7) })

    /// The golden chunk, built from already-"signed" parts through the memberwise init.
    ///
    /// **A SHAPE vector, deliberately not size-consistent with any manifest**: index 1 of 3 with a
    /// four-byte payload could not come from a real item. That is fine and intended — the
    /// transcript carries neither `size` nor `payload`, so consistency is a *verifier* property and
    /// is exercised in `MeshChunkerTests` against real manifests. Do not "fix" it.
    static func chunk() -> MeshChunk {
        MeshChunk(
            meshID: meshID,
            itemID: itemID,
            originFingerprint: originFingerprint,
            contentHash: contentHash,
            chunkIndex: chunkIndex,
            chunkCount: chunkCount,
            chunkHash: MeshRoutedContentDigest.chunkHash(of: payload),
            expiresAt: expiresAt,
            payload: payload,
            signature: opaqueSignature
        )
    }

    /// A deterministic pseudo-random blob of `byteCount` bytes. Non-repeating over 64 KiB, so a
    /// mis-sliced chunk boundary changes the reassembled bytes.
    static func blob(byteCount: Int) -> Data {
        Data((0..<byteCount).map { UInt8(truncatingIfNeeded: ($0 &* 31 &+ 7) ^ ($0 >> 8)) })
    }

    /// A well-formed chunk of `byteCount` bytes at `index` of `count`, with a real chunk hash and
    /// the fixture's opaque signature. The assembler verifies no signature, so this drives its
    /// whole battery with no keychain.
    static func chunk(
        index: UInt32,
        count: UInt32,
        payload: Data,
        itemID: UUID = MeshChunkFixtures.itemID,
        origin: String = MeshChunkFixtures.originFingerprint,
        contentHash: Data = MeshChunkFixtures.contentHash
    ) -> MeshChunk {
        MeshChunk(
            meshID: meshID, itemID: itemID, originFingerprint: origin, contentHash: contentHash,
            chunkIndex: index, chunkCount: count,
            chunkHash: MeshRoutedContentDigest.chunkHash(of: payload),
            expiresAt: expiresAt, payload: payload, signature: opaqueSignature
        )
    }

    static func hex(_ data: Data) -> String {
        MeshMembershipEventFixtures.hex(data)
    }

    /// A `UUID`'s 16 network-order bytes, through the same writer the derivation uses — so the
    /// chunk-id golden compares the id itself, not a formatted string.
    static func bytes(of uuid: UUID) -> Data {
        var writer = CanonicalByteWriter()
        writer.appendUUID(uuid)
        return writer.bytes
    }
}

// MARK: - Test-only rebuilders

extension MeshChunk {
    /// Test-only: a copy with the named fields replaced, through the flooring memberwise init.
    func replacing(
        meshID: UUID? = nil,
        itemID: UUID? = nil,
        originFingerprint: String? = nil,
        contentHash: Data? = nil,
        chunkIndex: UInt32? = nil,
        chunkCount: UInt32? = nil,
        chunkHash: Data? = nil,
        expiresAt: Date? = nil,
        payload: Data? = nil,
        signature: Data? = nil
    ) -> MeshChunk {
        MeshChunk(
            meshID: meshID ?? self.meshID,
            itemID: itemID ?? self.itemID,
            originFingerprint: originFingerprint ?? self.originFingerprint,
            contentHash: contentHash ?? self.contentHash,
            chunkIndex: chunkIndex ?? self.chunkIndex,
            chunkCount: chunkCount ?? self.chunkCount,
            chunkHash: chunkHash ?? self.chunkHash,
            expiresAt: expiresAt ?? self.expiresAt,
            payload: payload ?? self.payload,
            signature: signature ?? self.signature
        )
    }
}

/// One wrong width or count per case — each a refusal, never a repair.
enum MeshChunkShapeFault: String, CaseIterable, Sendable {
    case signature63, signature65, chunkHash31, chunkHash33, contentHash31, contentHash33
    case emptyPayload, payloadOverCap, emptyOrigin, origin65, countZero, countOverCap, indexAtCount

    /// The golden fixture with this one fault applied through the memberwise init.
    func applied(to base: MeshChunk) -> MeshChunk {
        switch self {
        case .signature63: return base.replacing(signature: Data(repeating: 0xAB, count: 63))
        case .signature65: return base.replacing(signature: Data(repeating: 0xAB, count: 65))
        case .chunkHash31: return base.replacing(chunkHash: Data(repeating: 0x01, count: 31))
        case .chunkHash33: return base.replacing(chunkHash: Data(repeating: 0x01, count: 33))
        case .contentHash31: return base.replacing(contentHash: Data(repeating: 0x02, count: 31))
        case .contentHash33: return base.replacing(contentHash: Data(repeating: 0x02, count: 33))
        case .emptyPayload: return base.replacing(payload: Data())
        case .payloadOverCap:
            return base.replacing(payload: Data(repeating: 0x7F, count: MeshChunkFormat.maxChunkPayloadBytes + 1))
        case .emptyOrigin: return base.replacing(originFingerprint: "")
        case .origin65: return base.replacing(originFingerprint: String(repeating: "f", count: 65))
        case .countZero: return base.replacing(chunkIndex: 0, chunkCount: 0)
        case .countOverCap:
            return base.replacing(chunkCount: UInt32(MeshChunkFormat.maxChunkCount + 1))
        case .indexAtCount: return base.replacing(chunkIndex: base.chunkCount)
        }
    }
}
