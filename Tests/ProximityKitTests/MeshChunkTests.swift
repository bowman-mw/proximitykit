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
// Fernlet repository's FernletTests file of the same name, this holds only `MeshChunkShapeTests`,
// with its name and tests unchanged, and the fixtures the package's copied suites read
// (`MeshChunkFixtures`, `extension MeshChunk` and `MeshChunkShapeFault`, and, since ProximityKit plan
// step A1's second batch of copied suites, `MeshChunkTamper`, which `MeshChunkerTests` reads); its
// other suites stay there, so what this header says of them is not held here.

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

/// A chunk's JSON with NO floor on the instant and no bound on the payload — what a re-encoded or
/// hostile frame from a peer looks like on the wire. Same coding keys and encoder strategy as the
/// real type, so decoding it as a ``MeshChunk`` exercises `init(from:)` exactly.
private struct UnclampedChunkWire: Encodable {
    let meshID: UUID
    let itemID: UUID
    let originFingerprint: String
    let contentHash: Data
    let chunkIndex: UInt32
    let chunkCount: UInt32
    let chunkHash: Data
    let expiresAt: Date
    let payload: Data
    let signature: Data

    /// `chunk`, optionally with a different (unfloored) instant and a different payload — the two
    /// things the real type can no longer put on the wire itself.
    init(_ chunk: MeshChunk, expiresAt: Date? = nil, payload: Data? = nil) {
        meshID = chunk.meshID
        itemID = chunk.itemID
        originFingerprint = chunk.originFingerprint
        contentHash = chunk.contentHash
        chunkIndex = chunk.chunkIndex
        chunkCount = chunk.chunkCount
        chunkHash = chunk.chunkHash
        self.expiresAt = expiresAt ?? chunk.expiresAt
        self.payload = payload ?? chunk.payload
        signature = chunk.signature
    }

    /// Encodes this wire form and decodes it through the real type's door.
    func decodedChunk() throws -> MeshChunk {
        try JSONDecoder().decode(MeshChunk.self, from: JSONEncoder().encode(self))
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

/// One SIGNED field per case; every case must land on `.signatureInvalid` and nothing else, which
/// is the point of signing all of them. `meshID` and `payload` are deliberately absent — each has
/// an earlier, differently named refusal of its own (`foreignMesh`, `chunkHashMismatch`).
enum MeshChunkTamper: String, CaseIterable, Sendable {
    case itemID, originFingerprint, contentHash, chunkIndex, chunkCount, chunkHash, expiresAt
    case signatureByte

    /// A minted chunk with this one field changed, through the memberwise init. The origin
    /// substitute is another ADMITTED member, so every case reaches the signature check.
    func applied(to chunk: MeshChunk, otherAdmittedOrigin: String) -> MeshChunk {
        switch self {
        case .itemID: return chunk.replacing(itemID: MeshMembershipEventFixtures.proposalID)
        case .originFingerprint: return chunk.replacing(originFingerprint: otherAdmittedOrigin)
        case .contentHash:
            var hash = chunk.contentHash
            hash[hash.startIndex] ^= 0x01
            return chunk.replacing(contentHash: hash)
        case .chunkIndex:
            let moved = chunk.chunkIndex == 0 ? chunk.chunkIndex + 1 : chunk.chunkIndex - 1
            return chunk.replacing(chunkIndex: moved)
        case .chunkCount: return chunk.replacing(chunkCount: chunk.chunkCount + 1)
        case .chunkHash:
            var hash = chunk.chunkHash
            hash[hash.startIndex] ^= 0x01
            return chunk.replacing(chunkHash: hash)
        case .expiresAt: return chunk.replacing(expiresAt: chunk.expiresAt.addingTimeInterval(1))
        case .signatureByte:
            var signature = chunk.signature
            signature[signature.startIndex] ^= 0x01
            return chunk.replacing(signature: signature)
        }
    }
}

// MARK: - Shape, bounds and derivations

/// The chunk's own bounds: what a wrong width does, what the derived caps must equal, and what the
/// boundary rule computes. Pure — no keychain, no clock, no disk.
@Suite(.serialized)
struct MeshChunkShapeTests {

    @Test func aWellFormedChunkPassesTheShapeCheck() {
        #expect(MeshChunkFixtures.chunk().isWellFormed)
    }

    @Test(arguments: MeshChunkShapeFault.allCases)
    func everyShapeFaultIsRefused(fault: MeshChunkShapeFault) {
        #expect(MeshChunkFixtures.chunk().isWellFormed)
        #expect(fault.applied(to: MeshChunkFixtures.chunk()).isWellFormed == false, "\(fault)")
    }

    /// An over-long payload on the wire is NOT trimmed into a valid-looking chunk: it decodes whole
    /// and fails the shape check, which is the difference between a refusal and a repair.
    @Test func anUnclampedWireChunkIsRefusedOnDecode() throws {
        let oversize = Data(repeating: 0x5A, count: MeshChunkFormat.maxChunkPayloadBytes + 1)
        let decoded = try UnclampedChunkWire(MeshChunkFixtures.chunk(), payload: oversize).decodedChunk()
        #expect(decoded.payload.count == MeshChunkFormat.maxChunkPayloadBytes + 1)
        #expect(decoded.isWellFormed == false)
    }

    /// Both doors floor the instant, so a relay re-encoding the wire with `expiresAt + 0.999`
    /// decodes to a chunk `==` the origin's whose canonical bytes are unchanged.
    @Test func aDecodedChunkFloorsItsExpiryLikeTheMemberwiseDoor() throws {
        let signed = MeshChunkFixtures.chunk()
        let fractional = try UnclampedChunkWire(
            signed, expiresAt: signed.expiresAt.addingTimeInterval(0.999)
        ).decodedChunk()
        #expect(fractional == signed)
        #expect(fractional.expiresAt == MeshChunkFixtures.expiresAt)
        #expect(canonicalBytes(for: fractional) == canonicalBytes(for: signed))
        #expect(fractional.isLive(at: MeshChunkFixtures.expiresAt))
        #expect(fractional.isLive(at: MeshChunkFixtures.expiresAt.addingTimeInterval(1)) == false)
    }

    /// The id is a function of `(itemID, index)` only: a retransmission with different payload
    /// bytes is the SAME id (dedup works), a different index or item is a different id.
    @Test func theChunkIDIsStableAcrossARetransmission() {
        let chunk = MeshChunkFixtures.chunk()
        let repayloaded = chunk.replacing(payload: Data([0x01, 0x02, 0x03, 0x04]))
        #expect(repayloaded.chunkID == chunk.chunkID)
        #expect(chunk.replacing(chunkIndex: 2).chunkID != chunk.chunkID)
        #expect(chunk.replacing(itemID: MeshMembershipEventFixtures.proposalID).chunkID != chunk.chunkID)
        // Origin-free by design: two origins squatting one itemID produce equal ids, and the replay
        // window separates them on its own sender axis (item 12's F3-ii).
        #expect(chunk.replacing(originFingerprint: "fp002").chunkID == chunk.chunkID)
    }

    /// Not vacuous: it fires the day 256 KiB stops dividing 256 MiB evenly.
    @Test func theDerivedChunkCapMatchesTheContentCap() {
        let contentCap = MeshRoutedManifestFormat.maxContentByteCount
        let expected = (Int(contentCap) + MeshChunkFormat.maxChunkPayloadBytes - 1)
            / MeshChunkFormat.maxChunkPayloadBytes
        #expect(MeshChunkFormat.maxChunkCount == expected)
        #expect(MeshChunkFormat.maxChunkCount == 1024)
        #expect(MeshChunkFormat.maxChunkPayloadBytes == 256 * 1024)
        #expect(MeshChunkFormat.chunkCount(forSize: contentCap) == MeshChunkFormat.maxChunkCount)
    }

    /// C15: pin the NUMBER and the strict INEQUALITY, never the equality with the constant it is
    /// defined from — that would be true by construction and could never fail. The inequality is
    /// the decision: one slot of headroom in a budget the photo path shares.
    @Test func theInFlightBoundLeavesHeadroomInTheSharedBudget() {
        #expect(MeshChunkFormat.maxChunksInFlightPerPeer == 3)
        #expect(MeshChunkFormat.maxChunksInFlightPerPeer < MeshTransferStreamTable.maxConcurrentOutbound)
        #expect(MeshChunkFormat.maxChunksInFlightPerPeer >= 1)
    }

    @Test func theExpectedPayloadLengthRuleIsExact() {
        let full = MeshChunkFormat.maxChunkPayloadBytes
        let size = UInt64(2 * full + 1_000)
        #expect(MeshChunk.expectedPayloadByteCount(index: 0, count: 3, size: size) == full)
        #expect(MeshChunk.expectedPayloadByteCount(index: 1, count: 3, size: size) == full)
        #expect(MeshChunk.expectedPayloadByteCount(index: 2, count: 3, size: size) == 1_000)
        // Out of range, and a count that disagrees with the size, are both nil.
        #expect(MeshChunk.expectedPayloadByteCount(index: 3, count: 3, size: size) == nil)
        #expect(MeshChunk.expectedPayloadByteCount(index: 0, count: 4, size: size) == nil)
        // An exact multiple: the last chunk is full, not zero.
        #expect(MeshChunk.expectedPayloadByteCount(index: 1, count: 2, size: UInt64(2 * full)) == full)
        // A single chunk shorter than the cap.
        #expect(MeshChunk.expectedPayloadByteCount(index: 0, count: 1, size: 1) == 1)
    }

    @Test func theChunkCountRuleIsExactAtEveryBoundary() {
        let full = UInt64(MeshChunkFormat.maxChunkPayloadBytes)
        #expect(MeshChunkFormat.chunkCount(forSize: 0) == nil)
        #expect(MeshChunkFormat.chunkCount(forSize: 1) == 1)
        #expect(MeshChunkFormat.chunkCount(forSize: full - 1) == 1)
        #expect(MeshChunkFormat.chunkCount(forSize: full) == 1)
        #expect(MeshChunkFormat.chunkCount(forSize: full + 1) == 2)
        #expect(MeshChunkFormat.chunkCount(forSize: MeshRoutedManifestFormat.maxContentByteCount + 1) == nil)
        // A hostile size never traps: the cap guard runs before the ceil addition.
        #expect(MeshChunkFormat.chunkCount(forSize: UInt64.max) == nil)
    }

    @Test func everyRejectionHasAFrozenDiagnostic() {
        #expect(MeshChunkRejection.allCases.count == 11)
        #expect(MeshChunkRefusal.allCases.count == 10)
        let rejectionsNamed = MeshChunkRejection.allCases.allSatisfy { !$0.diagnosticDescription.isEmpty }
        #expect(rejectionsNamed)
        let refusalsNamed = MeshChunkRefusal.allCases.allSatisfy { !$0.diagnosticDescription.isEmpty }
        #expect(refusalsNamed)
        #expect(Set(MeshChunkRejection.allCases.map(\.rawValue)).count == MeshChunkRejection.allCases.count)
        #expect(Set(MeshChunkRefusal.allCases.map(\.rawValue)).count == MeshChunkRefusal.allCases.count)
        let mintErrors: [MeshChunkMintError] = [
            .emptyBlob, .sizeMismatch(blobByteCount: 1, manifestSize: 2), .contentHashMismatch,
            .notTheOrigin(origin: "fp001"), .tooManyChunks(size: 1), .indexOutOfRange(index: 9, count: 3)
        ]
        let mintErrorsNamed = mintErrors.allSatisfy { !$0.diagnosticDescription.isEmpty }
        #expect(mintErrorsNamed)
    }

    /// The ten fields, and nothing receiver-local, custodial or increment-2 shaped.
    @Test func aChunkCarriesNoCustodyNoHopAndNoEpoch() {
        let labels = Mirror(reflecting: MeshChunkFixtures.chunk()).children.compactMap(\.label)
        #expect(labels == [
            "meshID", "itemID", "originFingerprint", "contentHash", "chunkIndex", "chunkCount",
            "chunkHash", "expiresAt", "payload", "signature"
        ])
        for label in labels.map({ $0.lowercased() }) {
            #expect(label.contains("epoch") == false)
            #expect(label.contains("branch") == false)
            #expect(label.contains("partition") == false)
            #expect(label.contains("custod") == false)
            #expect(label.contains("hop") == false)
            #expect(label.contains("ttl") == false)
            #expect(label.contains("seen") == false)
            #expect(label.contains("size") == false)
        }
    }
}
