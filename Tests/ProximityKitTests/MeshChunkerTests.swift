// MeshChunkerTests.swift
// ProximityKitTests
//
// P5 item 2 (plan §11): the mint and the receive-side door, with real keys.
//
// The claims walled here:
//
// 1. **The origin signs each chunk; nobody re-signs.** A minted chunk verifies through the one
//    door; every signed field tampered lands on `.signatureInvalid`; and the chunker REFUSES to
//    mint for a manifest this device did not originate — a custodian is a courier, not a co-signer.
// 2. **The payload is bound through the hash, so swapping it is its own named refusal.** A
//    tampered payload is `.chunkHashMismatch`, not `.signatureInvalid`, which is exactly why the
//    hash is in the transcript and the payload is not.
// 3. **The identity of a chunk is the triple.** All three legs of the manifest cross-check have a
//    test that fails if the leg is dropped — above all the ORIGIN leg, without which an admitted
//    member could squat another origin's item id under its own valid signature and the public
//    `verify` door would answer nil.
// 4. **Chunks ride P2's existing lane with no transport change.** A real 256 KiB chunk in a real
//    signed envelope routes to `.transferStream` and fits the wire ceiling — computed from the real
//    encoders, never a predicted number — and a chunk sent in REVERSE index order across the fake
//    fabric still reassembles to the original bytes.
//
// Nothing here sleeps, touches disk, or reads a wall clock for a decision: the fake fabric moves on
// a clock the test owns and every instant is a fixture.

import Foundation
import Testing
@testable import ProximityKit

/// Mint with real identities, verify through the one door, and every refusal by name.
@MainActor
@Suite(.serialized)
struct MeshChunkerTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer
    /// has run before a cell's identities reach the keychain.
    let keychain = PackageTestEnvironment.keychain

    /// One minted item with everything a test needs to interrogate it.
    private struct Minted {
        let rig: MeshDeliveryRig
        let origin: IdentityService
        let blob: Data
        let manifest: MeshRoutedManifest
        let chunks: [MeshChunk]
        let verifier: MeshChunkVerifier
    }

    /// The size of a two-chunk item: one full interior chunk plus a short tail.
    private static let twoChunkSize = MeshChunkFormat.maxChunkPayloadBytes + 500
    /// The size of a three-chunk item: two full interior chunks plus a short tail.
    private static let threeChunkSize = 2 * MeshChunkFormat.maxChunkPayloadBytes + 1_000

    // MARK: Helpers

    /// A chunk verifier over `rig`, holding the fixture `hardDeadline` unless one is named.
    private func verifier(
        for rig: MeshDeliveryRig,
        ledger: MeshMembershipLedger? = nil,
        hardDeadline: Date? = nil,
        manifest: MeshRoutedManifest?
    ) -> MeshChunkVerifier {
        MeshChunkVerifier(
            meshID: rig.meshID,
            hardDeadline: hardDeadline ?? MeshChunkFixtures.hardDeadline,
            ledger: ledger ?? rig.ledger,
            manifest: manifest
        )
    }

    /// Mints a manifest AND its chunks from `rig`'s roster, with the origin at `originIndex`.
    /// Every parameter that is not a fixture default is a knob a specific row turns.
    private func mint(
        rig: MeshDeliveryRig,
        originIndex: Int = 0,
        byteCount: Int = 1_000,
        hardDeadline: Date? = nil,
        itemID: UUID? = nil,
        blob: Data? = nil,
        chunkAll: Bool = true
    ) throws -> Minted {
        let originFingerprint = rig.fingerprints[originIndex]
        let origin = try #require(rig.identities[originFingerprint])
        let bytes = blob ?? MeshChunkFixtures.blob(byteCount: byteCount)
        let target = MeshDeliveryTarget(
            contentID: itemID ?? MeshChunkFixtures.itemID, roster: rig.roster, selfFingerprint: originFingerprint
        )
        let manifest = try MeshRoutedManifest.signed(
            meshID: rig.meshID,
            target: target,
            typeToken: MeshRoutedManifestFixtures.typeToken,
            contentHash: MeshRoutedContentDigest.contentHash(of: bytes),
            size: UInt64(bytes.count),
            createdAt: MeshChunkFixtures.base,
            hardDeadline: hardDeadline ?? MeshChunkFixtures.hardDeadline,
            contentKey: MeshRoutedContentKeyWrapper.makeContentKey(),
            recipientKeys: rig.identities.mapValues { $0.localKeyAgreementPublicKey },
            identity: origin
        )
        let chunks = chunkAll
            ? try MeshChunker.chunks(of: bytes, for: manifest, identity: origin)
            : []
        return Minted(
            rig: rig, origin: origin, blob: bytes, manifest: manifest, chunks: chunks,
            verifier: verifier(for: rig, hardDeadline: hardDeadline, manifest: manifest)
        )
    }

    /// Test-only re-sign: the only way to produce an origin-signed chunk the chunker would never
    /// mint. Allowed here, never in shipping code.
    private func resigned(_ chunk: MeshChunk, by identity: IdentityService) throws -> MeshChunk {
        let unsigned = chunk.replacing(signature: Data())
        let signature = try identity.sign(
            canonicalBytes(for: unsigned),
            purpose: ProximityNamespace.packageTest.family.purposes.signature.meshRoutedChunkV1
        )
        return unsigned.replacing(signature: signature)
    }

    /// Reassembles `chunks` through the real assembler and returns the completion verdict.
    private func reassembled(_ chunks: [MeshChunk], against manifest: MeshRoutedManifest) throws -> MeshChunkCompletion {
        var assembly = try #require(MeshChunkAssembly.forManifest(manifest))
        for chunk in chunks {
            #expect(assembly.admit(chunk) != .refused(.foreignItem))
        }
        return assembly.completion(against: manifest)
    }

    // MARK: The mint

    @Test func aChunkedBlobRoundTripsThroughTheAssembler() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 3), byteCount: Self.threeChunkSize)
        #expect(minted.chunks.count == 3)
        for chunk in minted.chunks {
            #expect(minted.verifier.verify(chunk) == nil, "chunk \(chunk.chunkIndex)")
        }
        #expect(try reassembled(minted.chunks, against: minted.manifest) == .complete(blob: minted.blob))
    }

    @Test(arguments: [
        1,
        MeshChunkFormat.maxChunkPayloadBytes - 1,
        MeshChunkFormat.maxChunkPayloadBytes,
        MeshChunkFormat.maxChunkPayloadBytes + 1,
        3 * MeshChunkFormat.maxChunkPayloadBytes
    ])
    func chunkingIsExactAtEveryBoundary(byteCount: Int) throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 2), byteCount: byteCount)
        let expectedCount = try #require(MeshChunkFormat.chunkCount(forSize: UInt64(byteCount)))
        #expect(minted.chunks.count == expectedCount)
        for chunk in minted.chunks {
            let expected = MeshChunk.expectedPayloadByteCount(
                index: chunk.chunkIndex, count: chunk.chunkCount, size: UInt64(byteCount)
            )
            #expect(chunk.payload.count == expected, "chunk \(chunk.chunkIndex) of \(byteCount)")
            #expect(chunk.chunkCount == UInt32(expectedCount))
            #expect(chunk.isWellFormed)
        }
        #expect(try reassembled(minted.chunks, against: minted.manifest) == .complete(blob: minted.blob))
    }

    /// The primitive mints the same chunk the bounded run does — item 6 streams with it, so the two
    /// must not diverge.
    ///
    /// Compared on the SIGNED bytes plus the payload rather than on `==`: CryptoKit's Ed25519
    /// signing is hedged, so two mints of one chunk carry different 64-byte signatures over
    /// identical canonical bytes. That is precisely why the signature is excluded from the
    /// transcript — and why both signatures verify.
    @Test func theSingleChunkPrimitiveMatchesTheBoundedRun() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 2), byteCount: Self.twoChunkSize)
        let one = try MeshChunker.chunk(of: minted.blob, at: 1, for: minted.manifest, identity: minted.origin)
        #expect(canonicalBytes(for: one) == canonicalBytes(for: minted.chunks[1]))
        #expect(one.payload == minted.chunks[1].payload)
        #expect(one.replacing(signature: minted.chunks[1].signature) == minted.chunks[1])
        #expect(minted.verifier.verify(one) == nil)
        #expect(minted.verifier.verify(minted.chunks[1]) == nil)
        #expect(throws: MeshChunkMintError.indexOutOfRange(index: 2, count: 2)) {
            try MeshChunker.chunk(of: minted.blob, at: 2, for: minted.manifest, identity: minted.origin)
        }
    }

    /// An honest RE-MINT is a duplicate, not a conflict.
    ///
    /// `chunk(of:at:for:identity:)` exists so item 6 can stream **without retaining** what it
    /// minted, one item sent to two destinations is two mints, and item 8's custody transfer at
    /// departure can hand a holder a copy of what it already has. CryptoKit's Ed25519 signing is
    /// hedged, so those copies differ in the 64-byte signature alone — deciding the assembler's
    /// verdict on whole-value equality would answer `.conflictingChunk`, an integrity claim, for
    /// an honest origin's bytes on exactly the path plan §11 calls load-bearing.
    @Test func aReMintedChunkIsADuplicateNotAConflict() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 3), byteCount: Self.twoChunkSize)
        var assembly = try #require(MeshChunkAssembly.forManifest(minted.manifest))
        #expect(assembly.admit(minted.chunks[0]) == .admitted(received: 1, expected: 2))
        let reminted = try MeshChunker.chunk(of: minted.blob, at: 0, for: minted.manifest, identity: minted.origin)
        #expect(minted.verifier.verify(reminted) == nil)
        #expect(canonicalBytes(for: reminted) == canonicalBytes(for: minted.chunks[0]))
        #expect(assembly.admit(reminted) == .duplicate(received: 1))
        #expect(assembly.receivedCount == 1)
        // The item still completes: the held copy was kept and nothing was double-counted.
        #expect(assembly.admit(minted.chunks[1]) == .admitted(received: 2, expected: 2))
        #expect(assembly.completion(against: minted.manifest) == .complete(blob: minted.blob))
    }

    /// The bounded run derives its guard chain ONCE per item, not once per chunk.
    ///
    /// `validated(...)` hashes the WHOLE blob, so a `chunks()` that re-entered the validating
    /// primitive per index costs `count + 1` whole-blob SHA-256 passes — 1025 passes over 256 MiB
    /// for a maximal item, on the main actor.
    ///
    /// Measured as a RATIO against the primitive loop in the same run, never against an absolute
    /// time: the primitive validates per call by design (it is the streaming door), so `count`
    /// primitive mints are exactly the shape this test rules out of `chunks()`. Both sides do the
    /// same slicing, hashing and signing, so machine speed cancels; the minimum of three
    /// interleaved samples is taken on each side so one scheduling hiccup cannot decide it. No
    /// sleep and no wall-clock deadline.
    @Test func theBoundedRunDerivesItsGuardChainOncePerItem() throws {
        let count = 16
        let minted = try mint(
            rig: try MeshDeliveryFixtures.rig(memberCount: 2),
            byteCount: count * MeshChunkFormat.maxChunkPayloadBytes,
            chunkAll: false
        )
        let clock = ContinuousClock()
        // Warm-up: first-touch faults and the identity's first signature are not measured.
        let warm = try MeshChunker.chunks(of: minted.blob, for: minted.manifest, identity: minted.origin)
        #expect(warm.count == count)
        var bulkSamples: [Duration] = []
        var perChunkSamples: [Duration] = []
        for _ in 0..<3 {
            let bulkStart = clock.now
            let bulk = try MeshChunker.chunks(of: minted.blob, for: minted.manifest, identity: minted.origin)
            bulkSamples.append(bulkStart.duration(to: clock.now))
            let loopStart = clock.now
            var loop: [MeshChunk] = []
            for index in 0..<count {
                loop.append(try MeshChunker.chunk(
                    of: minted.blob, at: index, for: minted.manifest, identity: minted.origin
                ))
            }
            perChunkSamples.append(loopStart.duration(to: clock.now))
            #expect(bulk.map { canonicalBytes(for: $0) } == loop.map { canonicalBytes(for: $0) })
        }
        let bulk = try #require(bulkSamples.min())
        let perChunk = try #require(perChunkSamples.min())
        #expect(bulk * 2 < perChunk, "bulk \(bulk) vs \(count) validating mints \(perChunk)")
    }

    // MARK: Verification

    @Test func anOriginSignedChunkVerifies() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 3))
        let chunk = try #require(minted.chunks.first)
        #expect(chunk.isWellFormed)
        #expect(minted.verifier.verify(chunk) == nil)
    }

    @Test(arguments: MeshChunkTamper.allCases)
    func everySignedFieldTamperIsRefusedAsSignatureInvalid(tamper: MeshChunkTamper) throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 3)
        let minted = try mint(rig: rig, byteCount: Self.twoChunkSize)
        let chunk = minted.chunks[1]
        let tampered = tamper.applied(to: chunk, otherAdmittedOrigin: rig.fingerprints[1])
        #expect(tampered != chunk, "\(tamper)")
        #expect(tampered.isWellFormed, "\(tamper)")
        #expect(minted.verifier.verify(tampered) == .signatureInvalid, "\(tamper)")
    }

    /// NOT `.signatureInvalid`: the transcript excludes the payload, which is exactly why the hash
    /// is in it.
    @Test func aTamperedPayloadIsRefusedAsChunkHashMismatch() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 2))
        let chunk = try #require(minted.chunks.first)
        var payload = chunk.payload
        payload[payload.startIndex] ^= 0x01
        let swapped = chunk.replacing(payload: payload)
        #expect(canonicalBytes(for: swapped) == canonicalBytes(for: chunk))
        #expect(minted.verifier.verify(swapped) == .chunkHashMismatch)
    }

    @Test func aChunkFromAnotherMeshIsRefusedByName() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 2))
        let foreign = MeshChunkVerifier(
            meshID: MeshMembershipEventFixtures.meshID,
            hardDeadline: MeshChunkFixtures.hardDeadline,
            ledger: minted.rig.ledger,
            manifest: minted.manifest
        )
        #expect(foreign.verify(try #require(minted.chunks.first)) == .foreignMesh)
    }

    @Test func aChunkFromANeverAdmittedOriginIsRefusedByName() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 2))
        let chunk = try #require(minted.chunks.first).replacing(originFingerprint: "fp999")
        #expect(verifier(for: minted.rig, manifest: nil).verify(chunk) == .originNotAdmitted)
    }

    /// Leaving is not a retraction: the key comes from the admissions and the roster is never
    /// consulted.
    @Test func aChunkFromADepartedOriginStillVerifies() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 3))
        var records = MeshMembershipRecordVerifier(meshID: minted.rig.meshID, ledger: minted.rig.ledger)
        let departure = try SignedDepartureRecord.signed(
            meshID: minted.rig.meshID, identity: minted.origin, occurredAt: MeshMembershipEventFixtures.base
        )
        #expect(records.insert(departure) == nil)
        #expect(records.roster.contains(fingerprint: minted.origin.localFingerprint) == false)
        let door = verifier(for: minted.rig, ledger: records.ledger, manifest: minted.manifest)
        #expect(door.verify(try #require(minted.chunks.first)) == nil)
    }

    /// Removal is not departure: the removal record set is the one door that can exclude a
    /// per-recipient wrap's author, since the group-key rotation cannot reach it.
    @Test func aChunkFromARemovedOriginIsRefusedByName() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 3))
        let names = minted.rig.fingerprints
        let tallier = try #require(minted.rig.identities[names[1]])
        var records = MeshMembershipRecordVerifier(meshID: minted.rig.meshID, ledger: minted.rig.ledger)
        #expect(records.roster.quorumThreshold == 2)
        let removal = try SignedRemovalRecord.signed(
            meshID: minted.rig.meshID,
            identity: tallier,
            memberFingerprint: minted.origin.localFingerprint,
            proposalID: MeshMembershipEventFixtures.proposalID,
            voterFingerprints: [names[1], names[2]],
            occurredAt: MeshMembershipEventFixtures.base
        )
        #expect(records.insert(removal) == nil)
        let chunk = try #require(minted.chunks.first)
        let door = verifier(for: minted.rig, ledger: records.ledger, manifest: minted.manifest)
        #expect(door.verify(chunk) == .originRemoved)
        // The refusal is the removal's, not the signature's: the same bytes verify against the
        // ledger as it stood before the quorum.
        #expect(minted.verifier.verify(chunk) == nil)
    }

    /// The chunk restates no formula: its expiry must be this device's own `hardDeadline + grace`.
    @Test func aChunkWhoseExpiryIsNotTheOneFormulaIsRefused() throws {
        let minted = try mint(
            rig: try MeshDeliveryFixtures.rig(memberCount: 2),
            hardDeadline: MeshChunkFixtures.base.addingTimeInterval(21_660)
        )
        let chunk = try #require(minted.chunks.first)
        #expect(chunk.expiresAt == MeshChunkFixtures.base.addingTimeInterval(22_860))
        // The verifier holding THIS device's hard deadline refuses it by name.
        #expect(verifier(for: minted.rig, manifest: nil).verify(chunk) == .expiryMismatch)
    }

    @Test func aChunkWhoseCountDisagreesWithTheManifestSizeIsRefused() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 2))
        let chunk = try #require(minted.chunks.first)
        #expect(chunk.chunkCount == 1)
        let widened = try resigned(chunk.replacing(chunkCount: 2), by: minted.origin)
        #expect(minted.verifier.verify(widened) == .chunkCountMismatch)
    }

    @Test func aShortInteriorChunkIsRefusedAgainstTheManifest() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 2), byteCount: Self.threeChunkSize)
        let interior = minted.chunks[0]
        #expect(interior.payload.count == MeshChunkFormat.maxChunkPayloadBytes)
        let short = Data(interior.payload.prefix(1_024))
        let trimmed = try resigned(
            interior.replacing(chunkHash: MeshRoutedContentDigest.chunkHash(of: short), payload: short),
            by: minted.origin
        )
        #expect(minted.verifier.verify(trimmed) == .payloadLengthMismatch)
    }

    @Test func aChunkForAnotherItemIsRefusedAgainstTheManifest() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 2))
        let chunk = try #require(minted.chunks.first)
        let moved = try resigned(chunk.replacing(itemID: MeshMembershipEventFixtures.proposalID), by: minted.origin)
        #expect(minted.verifier.verify(moved) == .manifestMismatch)
    }

    /// The ORIGIN leg of the triple, and the squatting case it exists for: an admitted member's
    /// own valid signature over another origin's `itemID` AND `contentHash` passes guards 1–8.
    /// Without this leg, the public `verify` door would answer nil for a squatted chunk.
    @Test func aChunkFromAnotherAdmittedOriginIsRefusedAgainstTheManifest() throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 3)
        let blob = MeshChunkFixtures.blob(byteCount: 1_000)
        let origin = try mint(rig: rig, originIndex: 0, blob: blob)
        let squatter = try mint(rig: rig, originIndex: 1, blob: blob)
        let squatted = try #require(squatter.chunks.first)
        // Same item id and same content hash, a DIFFERENT origin — and its own honest signature.
        #expect(squatted.itemID == origin.manifest.itemID)
        #expect(squatted.contentHash == origin.manifest.contentHash)
        #expect(squatted.originFingerprint != origin.manifest.originFingerprint)
        #expect(squatter.verifier.verify(squatted) == nil)
        #expect(origin.verifier.verify(squatted) == .manifestMismatch)
    }

    @Test func aChunkWhoseContentHashDiffersFromTheManifestIsRefused() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 2))
        let chunk = try #require(minted.chunks.first)
        var hash = chunk.contentHash
        hash[hash.startIndex] ^= 0x01
        let relabelled = try resigned(chunk.replacing(contentHash: hash), by: minted.origin)
        #expect(minted.verifier.verify(relabelled) == .manifestMismatch)
    }

    /// C10: chunks ride streams that are not ordered against the control stream, so a chunk whose
    /// manifest has not arrived is verified and parked — and a tampered one is still refused.
    @Test func aChunkVerifiesWithoutItsManifest() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 2))
        let chunk = try #require(minted.chunks.first)
        let parked = verifier(for: minted.rig, manifest: nil)
        #expect(parked.verify(chunk) == nil)
        var payload = chunk.payload
        payload[payload.startIndex] ^= 0x01
        #expect(parked.verify(chunk.replacing(payload: payload)) == .chunkHashMismatch)
        #expect(parked.verify(chunk.replacing(itemID: MeshMembershipEventFixtures.proposalID)) == .signatureInvalid)
    }

    // MARK: Mint refusals

    @Test func theChunkerRefusesToMintForSomebodyElsesManifest() throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 3)
        let minted = try mint(rig: rig)
        let custodian = try #require(rig.identities[rig.fingerprints[1]])
        #expect(throws: MeshChunkMintError.notTheOrigin(origin: minted.manifest.originFingerprint)) {
            try MeshChunker.chunks(of: minted.blob, for: minted.manifest, identity: custodian)
        }
        #expect(throws: MeshChunkMintError.notTheOrigin(origin: minted.manifest.originFingerprint)) {
            try MeshChunker.chunk(of: minted.blob, at: 0, for: minted.manifest, identity: custodian)
        }
    }

    @Test func theChunkerRefusesABlobThatIsNotTheManifestsContent() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 2))
        var other = minted.blob
        other[other.startIndex] ^= 0x01
        #expect(throws: MeshChunkMintError.contentHashMismatch) {
            try MeshChunker.chunks(of: other, for: minted.manifest, identity: minted.origin)
        }
        let short = Data(minted.blob.prefix(minted.blob.count - 1))
        #expect(throws: MeshChunkMintError.sizeMismatch(
            blobByteCount: short.count, manifestSize: minted.manifest.size
        )) {
            try MeshChunker.chunks(of: short, for: minted.manifest, identity: minted.origin)
        }
        #expect(throws: MeshChunkMintError.emptyBlob) {
            try MeshChunker.chunks(of: Data(), for: minted.manifest, identity: minted.origin)
        }
    }

    // MARK: The frame and the lane

    /// The WHOLE of item 2's transport claim, computed from the real encoders rather than
    /// predicted: a full 256 KiB chunk in a real signed envelope earns a transfer stream by size
    /// alone, and still fits the wire ceiling both radios enforce. No transport code is touched.
    @Test func aFullChunkTakesATransferStreamAndFitsTheWireCeiling() throws {
        let minted = try mint(
            rig: try MeshDeliveryFixtures.rig(memberCount: 2),
            byteCount: MeshChunkFormat.maxChunkPayloadBytes
        )
        let chunk = try #require(minted.chunks.first)
        #expect(chunk.payload.count == MeshChunkFormat.maxChunkPayloadBytes)
        let envelope = try ProximityIdentityEnvelope.signed(
            identityService: minted.origin,
            senderDisplayName: "origin",
            payloadType: .meshRoutedChunk,
            payloadEncryption: .none,
            payloadSummary: PayloadSummary(title: "chunk"),
            payload: try JSONEncoder().encode(MeshChunkPayload(chunk: chunk)),
            createdAt: MeshMembershipEventFixtures.base
        )
        let wire = try JSONEncoder().encode(envelope)
        #expect(MeshTransferStreamTable.route(reliableByteCount: wire.count) == .transferStream)
        #expect(wire.count >= MeshTransferStreamTable.bulkFloorBytes)
        #expect(wire.count <= SealedPayloadFraming.maxInflatedByteCount)
    }

    /// Signed, not sealed — a custodian must be able to re-broadcast the frame verbatim. The
    /// `.verifyChallenge` control is what makes this prove the stance rather than the absence of an
    /// error.
    @Test func theChunkFrameIsSignedNotSealed() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 2))
        let receiver = try #require(minted.rig.identities[minted.rig.fingerprints[1]])
        let payload = try JSONEncoder().encode(MeshChunkPayload(chunk: try #require(minted.chunks.first)))
        let base = MeshMembershipEventFixtures.base

        let frame = try ProximityIdentityEnvelope.signed(
            identityService: minted.origin,
            senderDisplayName: "origin",
            recipientFingerprint: receiver.localFingerprint,
            payloadType: .meshRoutedChunk,
            payloadEncryption: .none,
            payloadSummary: PayloadSummary(title: "chunk"),
            payload: payload,
            createdAt: base
        )
        let opened = try frame.verify(identityService: receiver, replayCache: ReplayCache(dateProvider: { base }))
        #expect(opened == payload)

        let control = try ProximityIdentityEnvelope.signed(
            identityService: minted.origin,
            senderDisplayName: "origin",
            recipientFingerprint: receiver.localFingerprint,
            payloadType: .verifyChallenge,
            payloadEncryption: .none,
            payloadSummary: PayloadSummary(title: "chunk"),
            payload: payload,
            createdAt: base
        )
        #expect(throws: ProximityIdentityEnvelope.VerifyError.sealingRequired) {
            try control.verify(identityService: receiver, replayCache: ReplayCache(dateProvider: { base }))
        }
    }

    /// Chunks sent in REVERSE index order across the in-memory fabric still reassemble to the
    /// original bytes. No fake is taught about transfer streams — production makes the lane
    /// invisible above the transport — and time only moves when this test says so.
    @Test func aChunkCrossesTheFakeLaneAndReassembles() async throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 2), byteCount: Self.twoChunkSize)
        let session = FakeMeshTransportSession()
        let sender = session.makeChannel(named: "origin")
        let receiver = session.makeChannel(named: "destination")
        session.network.connect(sender.handle, receiver.handle)
        session.network.clock.advance(by: .milliseconds(20))

        for chunk in minted.chunks.reversed() {
            let envelope = try ProximityIdentityEnvelope.signed(
                identityService: minted.origin,
                senderDisplayName: "origin",
                payloadType: .meshRoutedChunk,
                payloadEncryption: .none,
                payloadSummary: PayloadSummary(title: "chunk"),
                payload: try JSONEncoder().encode(MeshChunkPayload(chunk: chunk)),
                createdAt: MeshMembershipEventFixtures.base
            )
            try await sender.channel.send(try JSONEncoder().encode(envelope), to: receiver.handle, mode: .reliable)
        }
        session.network.clock.advance(by: .milliseconds(20))

        // Sampled right after the synchronous pump, never after an `await`.
        let frames = receiver.channel.receivedFrames
        #expect(frames.count == minted.chunks.count)
        var assembly = try #require(MeshChunkAssembly.forManifest(minted.manifest))
        for frame in frames {
            let envelope = try JSONDecoder().decode(ProximityIdentityEnvelope.self, from: frame.data)
            let chunk = try JSONDecoder().decode(MeshChunkPayload.self, from: envelope.payload).chunk
            #expect(minted.verifier.verify(chunk) == nil)
            #expect(assembly.admit(chunk) != .refused(.foreignItem))
        }
        #expect(assembly.completion(against: minted.manifest) == .complete(blob: minted.blob))
    }

    /// The four `admit` parameters fit the chunk's own fields (wiring itself is item 12).
    @Test func aMintedChunkIsAdmittedOnceByTheReplayWindowThenReplayed() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 2))
        let chunk = try #require(minted.chunks.first)
        var window = MeshFrameReplayWindow(meshID: minted.rig.meshID)
        let base = MeshMembershipEventFixtures.base
        #expect(window.admit(
            frameID: chunk.chunkID, from: chunk.originFingerprint,
            meshID: chunk.meshID, expiresAt: chunk.expiresAt, now: base
        ) == .admitted)
        #expect(window.admit(
            frameID: chunk.chunkID, from: chunk.originFingerprint,
            meshID: chunk.meshID, expiresAt: chunk.expiresAt, now: base
        ) == .replayed)
        #expect(window.admit(
            frameID: chunk.chunkID, from: chunk.originFingerprint,
            meshID: chunk.meshID, expiresAt: chunk.expiresAt,
            now: chunk.expiresAt.addingTimeInterval(1)
        ) == .expired)
    }

    /// The documented precondition, exercised as the caller order it describes: a manifest reaches
    /// `MeshChunkVerifier` and `MeshChunkAssembly` only after `MeshRoutedManifestVerifier` accepted
    /// it. Nothing downstream re-checks — that is the point — so what this pins is that item 2's
    /// own tests never model the forbidden order, and it reads as the worked example item 3 copies.
    @Test func theBoundManifestIsOneTheManifestVerifierAccepted() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 3), byteCount: 4_096)
        let manifestDoor = MeshRoutedManifestVerifier(
            meshID: minted.rig.meshID,
            hardDeadline: MeshChunkFixtures.hardDeadline,
            ledger: minted.rig.ledger,
            acceptedTypeTokens: MeshRoutedManifestFixtures.acceptedTypeTokens
        )
        let rejection = manifestDoor.verify(minted.manifest)
        #expect(rejection == nil)
        guard rejection == nil else { return }

        let chunkDoor = MeshChunkVerifier(
            meshID: minted.rig.meshID, hardDeadline: MeshChunkFixtures.hardDeadline,
            ledger: minted.rig.ledger, manifest: minted.manifest
        )
        var assembly = try #require(MeshChunkAssembly.forManifest(minted.manifest))
        for chunk in minted.chunks {
            #expect(chunkDoor.verify(chunk) == nil)
            #expect(assembly.admit(chunk) == .admitted(received: Int(chunk.chunkIndex) + 1, expected: 1))
        }
        #expect(assembly.bind(to: minted.manifest) == .bound)
        #expect(assembly.completion(against: minted.manifest) == .complete(blob: minted.blob))
    }
}
