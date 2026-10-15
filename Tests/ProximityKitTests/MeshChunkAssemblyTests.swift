// MeshChunkAssemblyTests.swift
// ProximityKitTests
//
// P5 item 2 (plan §11): the receive-side reassembler.
//
// The claims walled here:
//
// 1. **Order independence is structural.** Forward, reverse and a fixed permutation all reassemble
//    to identical bytes, because chunks ride streams that are not ordered against each other or
//    against the control stream carrying the manifest.
// 2. **Every input gets a verdict, and a retransmission is a no-op rather than an error.** A
//    duplicate is `.duplicate` — including a copy that differs only in its 64-byte signature, which
//    is what an honest RE-MINT looks like under CryptoKit's hedged Ed25519 — a chunk with a
//    different signed transcript or payload at a taken index is `.conflictingChunk`; nothing is
//    silently dropped.
// 3. **Completion is impossible while unbound, and `.complete` is the whole-item hash check.**
//    Every index can be present and the answer still be `.notBound`; every chunk can be
//    individually consistent and the assembled blob still fail the manifest's content hash.
// 4. **Growth is bounded where it happens.** A chunk that would take the held bytes past the bound
//    size is `.sizeOverflow`; a wrong-length interior chunk is `.payloadLengthMismatch` bound AND
//    unbound; the per-chunk 256 KiB half of the assembly's structural bound is checked at the door
//    in the unbound branch too, not left to the verifier's precondition; and binding re-validates
//    what is already held without mutating anything.
//
// Pure: the assembler verifies no signature, so fixture chunks carrying the opaque signature drive
// the whole battery with no keychain, no clock and no disk.

import Foundation
import Testing
@testable import ProximityKit

/// The reassembler's verdicts, one claim each.
@Suite(.serialized)
struct MeshChunkAssemblyTests {

    /// Three small chunks of one fixture item, with a real content hash over their concatenation —
    /// so `completion` measures something honest rather than a fixture constant.
    private struct Item {
        let blob: Data
        let contentHash: Data
        let size: UInt64
        let chunks: [MeshChunk]
        let manifest: MeshRoutedManifest
    }

    /// A synthetic item of `count` chunks. Sizes are honest — interior chunks are exactly
    /// 256 KiB — so the bound-length rule is exercised for real; `lastByteCount` shortens the tail.
    private func item(count: UInt32, lastByteCount: Int, itemID: UUID? = nil, contentHashOverride: Data? = nil) -> Item {
        let full = MeshChunkFormat.maxChunkPayloadBytes
        let size = (Int(count) - 1) * full + lastByteCount
        let blob = MeshChunkFixtures.blob(byteCount: size)
        let hash = contentHashOverride ?? MeshRoutedContentDigest.contentHash(of: blob)
        let id = itemID ?? MeshChunkFixtures.itemID
        var chunks: [MeshChunk] = []
        for index in 0..<Int(count) {
            let start = index * full
            let end = min(start + full, blob.count)
            chunks.append(MeshChunkFixtures.chunk(
                index: UInt32(index), count: count,
                payload: Data(blob[blob.startIndex + start ..< blob.startIndex + end]),
                itemID: id, contentHash: hash
            ))
        }
        return Item(
            blob: blob, contentHash: hash, size: UInt64(size), chunks: chunks,
            manifest: manifest(itemID: id, contentHash: hash, size: UInt64(size))
        )
    }

    /// A manifest with the fields the assembler cross-checks. Never verified here: the assembler's
    /// documented precondition is that `MeshRoutedManifestVerifier` already accepted it, and this
    /// suite is about what the assembler does with one, not about how it was authenticated.
    private func manifest(itemID: UUID, contentHash: Data, size: UInt64) -> MeshRoutedManifest {
        MeshRoutedManifest(
            meshID: MeshChunkFixtures.meshID,
            itemID: itemID,
            originFingerprint: MeshChunkFixtures.originFingerprint,
            typeToken: MeshRoutedManifestFixtures.typeToken,
            contentHash: contentHash,
            size: size,
            createdAt: MeshChunkFixtures.base,
            expiresAt: MeshChunkFixtures.expiresAt,
            destinations: MeshRoutedManifestFixtures.destinations,
            keyWraps: MeshRoutedManifestFixtures.keyWraps(),
            signature: MeshChunkFixtures.opaqueSignature
        )
    }

    /// A two-chunk item: one full interior chunk plus a short tail. The cheapest shape that still
    /// has an interior chunk to get wrong.
    private func twoChunkItem() -> Item {
        item(count: 2, lastByteCount: 500)
    }

    // MARK: Order independence

    @Test func chunksAdmitInAnyOrder() throws {
        let source = item(count: 3, lastByteCount: 1_000)
        let orders: [[Int]] = [[0, 1, 2], [2, 1, 0], [1, 2, 0]]
        for order in orders {
            var assembly = try #require(MeshChunkAssembly.forManifest(source.manifest))
            for index in order {
                #expect(assembly.admit(source.chunks[index]) != .refused(.foreignItem), "\(order)")
            }
            #expect(assembly.isComplete, "\(order)")
            #expect(assembly.completion(against: source.manifest) == .complete(blob: source.blob), "\(order)")
        }
    }

    // MARK: Every input gets a verdict

    @Test func aDuplicateChunkIsANoOpNotAnError() throws {
        let source = twoChunkItem()
        var assembly = try #require(MeshChunkAssembly.forManifest(source.manifest))
        #expect(assembly.admit(source.chunks[0]) == .admitted(received: 1, expected: 2))
        let heldBytes = assembly.bytesHeld
        #expect(assembly.admit(source.chunks[0]) == .duplicate(received: 1))
        #expect(assembly.receivedCount == 1)
        #expect(assembly.bytesHeld == heldBytes)
    }

    @Test func aDifferentPayloadAtATakenIndexIsRefused() throws {
        let source = twoChunkItem()
        var assembly = try #require(MeshChunkAssembly.forManifest(source.manifest))
        #expect(assembly.admit(source.chunks[1]) == .admitted(received: 1, expected: 2))
        let other = Data(repeating: 0x5A, count: 500)
        let conflicting = source.chunks[1].replacing(
            chunkHash: MeshRoutedContentDigest.chunkHash(of: other), payload: other
        )
        #expect(assembly.admit(conflicting) == .refused(.conflictingChunk))
        #expect(assembly.receivedCount == 1)
    }

    /// The duplicate rule is decided on the **signed transcript plus the payload**, never on `==`:
    /// CryptoKit's Ed25519 signing is hedged, so two mints of one logical chunk differ in the
    /// 64-byte signature alone, and answering `.conflictingChunk` — an integrity claim — for those
    /// bytes would make an honest origin look like an attacker. The real re-mint is exercised in
    /// `MeshChunkerTests`; this pins the rule with no keychain.
    @Test func aChunkDifferingOnlyInItsSignatureIsADuplicate() throws {
        let source = twoChunkItem()
        var assembly = try #require(MeshChunkAssembly.forManifest(source.manifest))
        #expect(assembly.admit(source.chunks[0]) == .admitted(received: 1, expected: 2))
        let reSigned = source.chunks[0].replacing(signature: Data(repeating: 0x7E, count: 64))
        #expect(reSigned != source.chunks[0])
        #expect(assembly.admit(reSigned) == .duplicate(received: 1))
        #expect(assembly.receivedCount == 1)
        // A differing SIGNED field at the same index is still a conflict.
        let restamped = source.chunks[0].replacing(
            expiresAt: MeshChunkFixtures.expiresAt.addingTimeInterval(60)
        )
        #expect(assembly.admit(restamped) == .refused(.conflictingChunk))
        #expect(assembly.receivedCount == 1)
    }

    @Test func anOutOfRangeIndexIsRefused() throws {
        let source = twoChunkItem()
        var assembly = try #require(MeshChunkAssembly.forManifest(source.manifest))
        // `chunkCount` still matches, so this reaches the index guard rather than the count guard.
        #expect(assembly.admit(source.chunks[1].replacing(chunkIndex: 2)) == .refused(.indexOutOfRange))
    }

    @Test func aCountThatDisagreesWithTheAssemblyIsRefused() throws {
        let source = twoChunkItem()
        var assembly = try #require(MeshChunkAssembly.forManifest(source.manifest))
        #expect(assembly.admit(source.chunks[0].replacing(chunkCount: 3)) == .refused(.countMismatch))
    }

    /// The identity triple: any one leg differing is the same named refusal.
    @Test func aChunkForAnotherItemOrOriginIsRefused() throws {
        let source = twoChunkItem()
        var assembly = try #require(MeshChunkAssembly.forManifest(source.manifest))
        let chunk = source.chunks[0]
        #expect(assembly.admit(chunk.replacing(itemID: MeshMembershipEventFixtures.proposalID))
                == .refused(.foreignItem))
        #expect(assembly.admit(chunk.replacing(originFingerprint: "fp002")) == .refused(.foreignItem))
        #expect(assembly.admit(chunk.replacing(contentHash: Data(repeating: 0x09, count: 32)))
                == .refused(.foreignItem))
        #expect(assembly.receivedCount == 0)
    }

    /// Re-checked here even though the verifier checks it: this is the boundary item 3 gates
    /// durable custody on, and it must hold at the storage door regardless of who called what.
    @Test func aChunkWhoseHashDoesNotCoverItsPayloadIsRefused() throws {
        let source = twoChunkItem()
        var assembly = try #require(MeshChunkAssembly.forManifest(source.manifest))
        var hash = source.chunks[0].chunkHash
        hash[hash.startIndex] ^= 0x01
        #expect(assembly.admit(source.chunks[0].replacing(chunkHash: hash)) == .refused(.chunkHashMismatch))
    }

    // MARK: Bounded growth

    @Test func anOverLongLastChunkIsRefusedAsSizeOverflow() throws {
        let source = twoChunkItem()
        var assembly = try #require(MeshChunkAssembly.forManifest(source.manifest))
        #expect(assembly.admit(source.chunks[0]) == .admitted(received: 1, expected: 2))
        let oversize = MeshChunkFixtures.blob(byteCount: MeshChunkFormat.maxChunkPayloadBytes)
        let greedy = source.chunks[1].replacing(
            chunkHash: MeshRoutedContentDigest.chunkHash(of: oversize), payload: oversize
        )
        #expect(assembly.admit(greedy) == .refused(.sizeOverflow))
        #expect(assembly.bytesHeld == MeshChunkFormat.maxChunkPayloadBytes)
    }

    /// Bound AND unbound: the unbound rule ("interior chunks are exactly 256 KiB") is derivable
    /// from `chunkCount` alone, which is what makes a parked set safe to hold.
    @Test func aShortInteriorChunkIsRefusedAsPayloadLengthMismatch() throws {
        let source = twoChunkItem()
        let short = Data(source.chunks[0].payload.prefix(1_024))
        let trimmed = source.chunks[0].replacing(
            chunkHash: MeshRoutedContentDigest.chunkHash(of: short), payload: short
        )
        var bound = try #require(MeshChunkAssembly.forManifest(source.manifest))
        #expect(bound.admit(trimmed) == .refused(.payloadLengthMismatch))

        var parked = try #require(MeshChunkAssembly.forChunk(source.chunks[1]))
        #expect(parked.boundSize == nil)
        #expect(parked.admit(trimmed) == .refused(.payloadLengthMismatch))
        // The short LAST chunk is fine while unbound — only the manifest can say how short.
        #expect(parked.admit(source.chunks[1]) == .admitted(received: 1, expected: 2))
    }

    /// The per-chunk 256 KiB bound holds at the door in the UNBOUND branch too — where only the
    /// LAST index's length is otherwise unconstrained. `MeshChunk.isWellFormed` would carry it, but
    /// that is the verifier's precondition: this is the door item 3 gates durable custody on, and
    /// the bound is held to the same standard as the chunk hash beside it.
    @Test func anOverLongOrEmptyLastChunkIsRefusedWhileUnbound() throws {
        let source = twoChunkItem()
        var parked = try #require(MeshChunkAssembly.forChunk(source.chunks[0]))
        #expect(parked.boundSize == nil)
        let overLong = MeshChunkFixtures.blob(byteCount: MeshChunkFormat.maxChunkPayloadBytes + 1)
        let greedy = source.chunks[1].replacing(
            chunkHash: MeshRoutedContentDigest.chunkHash(of: overLong), payload: overLong
        )
        #expect(greedy.isWellFormed == false)
        #expect(parked.admit(greedy) == .refused(.payloadLengthMismatch))
        let empty = source.chunks[1].replacing(
            chunkHash: MeshRoutedContentDigest.chunkHash(of: Data()), payload: Data()
        )
        #expect(parked.admit(empty) == .refused(.payloadLengthMismatch))
        #expect(parked.receivedCount == 0)
        #expect(parked.bytesHeld == 0)
    }

    // MARK: Binding

    @Test func anUnboundAssemblyNeverCompletes() throws {
        let source = twoChunkItem()
        var assembly = try #require(MeshChunkAssembly.forChunk(source.chunks[0]))
        for chunk in source.chunks {
            #expect(assembly.admit(chunk) != .refused(.foreignItem))
        }
        #expect(assembly.isComplete)
        #expect(assembly.completion(against: source.manifest) == .refused(.notBound))
        #expect(assembly.bind(to: source.manifest) == .bound)
        #expect(assembly.completion(against: source.manifest) == .complete(blob: source.blob))
    }

    @Test func bindingCrossChecksTheManifestAndIsIdempotent() throws {
        let source = twoChunkItem()
        var assembly = try #require(MeshChunkAssembly.forChunk(source.chunks[0]))
        #expect(assembly.bind(to: source.manifest) == .bound)
        #expect(assembly.bind(to: source.manifest) == .bound)
        #expect(assembly.boundSize == source.size)

        let other = item(count: 2, lastByteCount: 500, itemID: MeshMembershipEventFixtures.proposalID)
        #expect(assembly.bind(to: other.manifest) == .refused(.foreignItem))
        // Same item, a size whose derived chunk count is not this assembly's.
        let resized = manifest(itemID: source.manifest.itemID, contentHash: source.contentHash, size: 4_096)
        #expect(assembly.bind(to: resized) == .refused(.countMismatch))
        #expect(assembly.boundSize == source.size)
    }

    @Test func bindingRevalidatesAlreadyHeldChunks() throws {
        let source = item(count: 3, lastByteCount: 1_000)
        // Parked: the last chunk arrives first, so the assembly knows only `chunkCount`.
        var assembly = try #require(MeshChunkAssembly.forChunk(source.chunks[2]))
        #expect(assembly.admit(source.chunks[2]) == .admitted(received: 1, expected: 3))
        // A manifest whose size makes that last chunk the wrong length refuses WITHOUT mutating.
        let full = MeshChunkFormat.maxChunkPayloadBytes
        let disagreeing = manifest(
            itemID: source.manifest.itemID, contentHash: source.contentHash, size: UInt64(2 * full + 7)
        )
        #expect(assembly.bind(to: disagreeing) == .refused(.payloadLengthMismatch))
        #expect(assembly.boundSize == nil)
        #expect(assembly.receivedCount == 1)
        // The honest manifest still binds.
        #expect(assembly.bind(to: source.manifest) == .bound)
    }

    // MARK: Completion

    @Test func anIncompleteAssemblyReportsPartialNotAPartialBlob() throws {
        let source = item(count: 3, lastByteCount: 1_000)
        var assembly = try #require(MeshChunkAssembly.forManifest(source.manifest))
        #expect(assembly.admit(source.chunks[0]) == .admitted(received: 1, expected: 3))
        #expect(assembly.admit(source.chunks[2]) == .admitted(received: 2, expected: 3))
        #expect(assembly.isComplete == false)
        #expect(assembly.completion(against: source.manifest) == .incomplete(received: 2, expected: 3))
    }

    /// Every chunk individually consistent, and the whole still wrong: the chunks all claim a
    /// `contentHash` their concatenation does not have.
    @Test func aTamperedBlobFailsTheFinalContentHash() throws {
        let lie = Data(repeating: 0x33, count: 32)
        let source = item(count: 2, lastByteCount: 500, contentHashOverride: lie)
        var assembly = try #require(MeshChunkAssembly.forManifest(source.manifest))
        for chunk in source.chunks {
            #expect(assembly.admit(chunk) != .refused(.foreignItem))
            #expect(MeshRoutedContentDigest.chunkHash(of: chunk.payload) == chunk.chunkHash)
        }
        #expect(assembly.isComplete)
        #expect(assembly.completion(against: source.manifest) == .refused(.contentHashMismatch))
    }

    @Test func aCompleteAssemblyReturnsTheExactOriginalBytes() throws {
        let source = item(count: 3, lastByteCount: 1_000)
        var assembly = try #require(MeshChunkAssembly.forManifest(source.manifest))
        for chunk in source.chunks {
            #expect(assembly.admit(chunk) != .refused(.foreignItem))
        }
        #expect(assembly.bytesHeld == Int(source.size))
        guard case .complete(let blob) = assembly.completion(against: source.manifest) else {
            Issue.record("expected a complete assembly")
            return
        }
        #expect(blob == source.blob)
        #expect(UInt64(blob.count) == source.manifest.size)
        #expect(MeshRoutedContentDigest.contentHash(of: blob) == source.manifest.contentHash)
    }

    /// A completion against a manifest that is not the bound one is refused rather than answered.
    @Test func aCompletionAgainstAnotherManifestIsRefused() throws {
        let source = twoChunkItem()
        var assembly = try #require(MeshChunkAssembly.forManifest(source.manifest))
        for chunk in source.chunks {
            #expect(assembly.admit(chunk) != .refused(.foreignItem))
        }
        let other = item(count: 2, lastByteCount: 500, itemID: MeshMembershipEventFixtures.proposalID)
        #expect(assembly.completion(against: other.manifest) == .refused(.foreignItem))
    }

    /// The two constructors' refusals: a size that cannot be chunked, and a malformed chunk.
    @Test func anAssemblyIsNotBuiltFromAnUnchunkableManifestOrAMalformedChunk() {
        let unchunkable = manifest(itemID: MeshChunkFixtures.itemID, contentHash: MeshChunkFixtures.contentHash, size: 0)
        #expect(MeshChunkAssembly.forManifest(unchunkable) == nil)
        let malformed = MeshChunkFixtures.chunk().replacing(payload: Data())
        #expect(MeshChunkAssembly.forChunk(malformed) == nil)
    }
}
