// MeshRecipientReceiptTests.swift
// ProximityKitTests
//
// P5 item 4 (plan §11, §3.6): the RECIPIENT RECEIPT — the fourth routed wire family, and the one
// that says a destination actually got the item.
//
// Four claims are walled here, each a thing a later item cannot cheaply re-derive:
//
// 1. **The signed bytes are pinned.** `goldenRecipientReceiptHex` and `goldenRecipientReceiptIDHex`
//    were derived from the FORMAT by an independent Python re-implementation that first reproduced
//    the shipped `goldenInventoryHex`, `goldenEpochHeadsHex`, `goldenRoutedManifestHex`,
//    `goldenRoutedChunkHex`, `goldenCustodyReceiptHex` AND `goldenCustodyReceiptIDHex` byte-for-byte.
//    A golden that only records what the code did proves nothing; these were computed independently
//    and then met. The frame is additive: nothing above it moves, and all three prior routed goldens
//    are re-asserted here untouched.
// 2. **Durable before acknowledged is a TYPE rule, for delivery as it is for custody.** The mint
//    takes a `MeshRecipientDeliveryWitness`, whose initialiser is `fileprivate` to the file holding
//    `committingDelivery` — so there is no argument list that produces a receipt for an
//    acknowledgement no durable write returned. Every receipt in this file comes out of a real store
//    commit.
// 3. **The recipient signs, about the origin's item, and only for itself.** Two fingerprints in two
//    fixed positions: the signing key is resolved by the RECIPIENT from the admission ledger, a
//    departed recipient's receipt still verifies, a quorum-removed one's does not, and a signer the
//    origin never addressed is refused by name — the leg custody has no analogue for.
// 4. **The derived id is stable across a re-mint, and there is exactly one per `(recipient, item)`.**
//    CryptoKit's Ed25519 signing is hedged, so two mints of one logical receipt differ in the
//    signature; `receiptID` excludes it — and excludes `receivedAt` too, because a re-mint of the
//    same claim is the same claim. One id per pair is the wire-level statement of
//    "destination-final, never per chunk".
//
// Nothing here sleeps or reads a wall clock for a decision.
//
// A partial copy (ProximityKit plan step A1, the split's first batch of copied suites): of the
// Fernlet repository's FernletTests file of the same name, this holds only
// `MeshRecipientReceiptShapeTests` and, since ProximityKit plan step A1's third batch of copied
// suites (those that reach the keychain and open a store), `MeshRecipientReceiptSigningTests` and
// `MeshRecipientReceiptVerifierTests`, with their names and tests unchanged, and the fixtures the
// package's copied suites read (`MeshRecipientReceiptFixtures`, `extension MeshRecipientReceipt`,
// `MeshRecipientReceiptShapeFault` and `MeshRecipientReceiptTamper`); its golden suite stays there,
// so what this header says of it is not held here.

import Foundation
import Testing
@testable import ProximityKit

// MARK: - Fixtures

/// Fixed values for the recipient-receipt golden vectors — every pinned byte traces to a line here;
/// nothing reads a clock. `meshID`, `itemID`, `contentHash`, `expiresAt` and `opaqueSignature` are
/// item 1's own, so the receipt vector reads beside the manifest, chunk and custody vectors as one
/// story.
enum MeshRecipientReceiptFixtures {

    static let meshID = MeshRoutedManifestFixtures.meshID
    static let itemID = MeshRoutedManifestFixtures.itemID
    static let base = MeshRoutedManifestFixtures.base
    /// The item's author — the SUBJECT of the receipt.
    static let originFingerprint = MeshRoutedManifestFixtures.originFingerprint
    static let contentHash = MeshRoutedManifestFixtures.contentHash
    static let expiresAt = MeshRoutedManifestFixtures.expiresAt
    static let hardDeadline = MeshRoutedManifestFixtures.hardDeadline
    static let opaqueSignature = MeshMembershipEventFixtures.opaqueSignature

    /// A real DESTINATION of the golden manifest — which is the whole point of the verifier's
    /// `notADestination` leg, and the deliberate difference from the custody vector's `fp004`.
    static let recipientFingerprint = "fp002"

    /// `base + 660` — the next free fixture offset (taken: +60 … +540 by items 1–3, +600 by
    /// `MeshRoutedStoreFixtures.now`).
    static let receivedAt = base.addingTimeInterval(660)

    /// The golden receipt, built from already-"signed" parts through the memberwise init.
    static func receipt() -> MeshRecipientReceipt {
        MeshRecipientReceipt(
            meshID: meshID,
            itemID: itemID,
            originFingerprint: originFingerprint,
            contentHash: contentHash,
            recipientFingerprint: recipientFingerprint,
            receivedAt: receivedAt,
            expiresAt: expiresAt,
            signature: opaqueSignature
        )
    }

    static func hex(_ data: Data) -> String {
        MeshMembershipEventFixtures.hex(data)
    }

    /// A `UUID`'s 16 network-order bytes, through the same writer the derivation uses.
    static func bytes(of uuid: UUID) -> Data {
        var writer = CanonicalByteWriter()
        writer.appendUUID(uuid)
        return writer.bytes
    }
}

// MARK: - Test-only rebuilders

extension MeshRecipientReceipt {
    /// Test-only: a copy with the named fields replaced, through the flooring memberwise init.
    func replacing(
        meshID: UUID? = nil,
        itemID: UUID? = nil,
        originFingerprint: String? = nil,
        contentHash: Data? = nil,
        recipientFingerprint: String? = nil,
        receivedAt: Date? = nil,
        expiresAt: Date? = nil,
        signature: Data? = nil
    ) -> MeshRecipientReceipt {
        MeshRecipientReceipt(
            meshID: meshID ?? self.meshID,
            itemID: itemID ?? self.itemID,
            originFingerprint: originFingerprint ?? self.originFingerprint,
            contentHash: contentHash ?? self.contentHash,
            recipientFingerprint: recipientFingerprint ?? self.recipientFingerprint,
            receivedAt: receivedAt ?? self.receivedAt,
            expiresAt: expiresAt ?? self.expiresAt,
            signature: signature ?? self.signature
        )
    }
}

/// One wrong width per case — each a refusal, never a repair.
enum MeshRecipientReceiptShapeFault: String, CaseIterable, Sendable {
    case signature63, signature65, contentHash31, contentHash33
    case emptyOrigin, origin65, emptyRecipient, recipient65, receivedAtExpiry, receivedPastExpiry

    /// The golden fixture with this one fault applied through the memberwise init.
    func applied(to base: MeshRecipientReceipt) -> MeshRecipientReceipt {
        switch self {
        case .signature63: return base.replacing(signature: Data(repeating: 0xAB, count: 63))
        case .signature65: return base.replacing(signature: Data(repeating: 0xAB, count: 65))
        case .contentHash31: return base.replacing(contentHash: Data(repeating: 0x02, count: 31))
        case .contentHash33: return base.replacing(contentHash: Data(repeating: 0x02, count: 33))
        case .emptyOrigin: return base.replacing(originFingerprint: "")
        case .origin65: return base.replacing(originFingerprint: String(repeating: "f", count: 65))
        case .emptyRecipient: return base.replacing(recipientFingerprint: "")
        case .recipient65: return base.replacing(recipientFingerprint: String(repeating: "r", count: 65))
        case .receivedAtExpiry: return base.replacing(receivedAt: base.expiresAt)
        case .receivedPastExpiry: return base.replacing(receivedAt: base.expiresAt.addingTimeInterval(1))
        }
    }
}

/// One SIGNED field per case; every case must land on `.signatureInvalid` and nothing else.
///
/// `meshID` and `expiresAt` are deliberately absent — each has an earlier, differently named refusal
/// of its own (`foreignMesh`, `expiryMismatch`), which is the point of checking the cheap ones first.
enum MeshRecipientReceiptTamper: String, CaseIterable, Sendable {
    case itemID, originFingerprint, contentHash, receivedAt, signatureByte

    /// A minted receipt with this one field changed. The origin substitute is an admitted member, so
    /// every case reaches the signature check.
    func applied(to receipt: MeshRecipientReceipt, otherAdmittedOrigin: String) -> MeshRecipientReceipt {
        switch self {
        case .itemID: return receipt.replacing(itemID: MeshMembershipEventFixtures.proposalID)
        case .originFingerprint: return receipt.replacing(originFingerprint: otherAdmittedOrigin)
        case .contentHash:
            var hash = receipt.contentHash
            hash[hash.startIndex] ^= 0x01
            return receipt.replacing(contentHash: hash)
        case .receivedAt:
            return receipt.replacing(receivedAt: receipt.receivedAt.addingTimeInterval(-1))
        case .signatureByte:
            var signature = receipt.signature
            signature[signature.startIndex] ^= 0x01
            return receipt.replacing(signature: signature)
        }
    }
}

// MARK: - Shape

/// The untrusted-bytes half: one wrong width per case, and the guards this check deliberately does
/// NOT pre-empt.
@Suite(.serialized)
struct MeshRecipientReceiptShapeTests {

    @Test(arguments: MeshRecipientReceiptShapeFault.allCases)
    func everyShapeFaultIsMalformed(fault: MeshRecipientReceiptShapeFault) {
        #expect(MeshRecipientReceiptFixtures.receipt().isWellFormed)
        #expect(fault.applied(to: MeshRecipientReceiptFixtures.receipt()).isWellFormed == false, "\(fault)")
    }

    /// A receipt whose recipient IS the origin is well-formed, so `recipientIsOrigin` stays a
    /// reachable, differently named refusal instead of collapsing into `malformed`.
    @Test func isWellFormedDoesNotPreEmptTheVerifiersOriginCheck() {
        let selfSigned = MeshRecipientReceiptFixtures.receipt()
            .replacing(recipientFingerprint: MeshRecipientReceiptFixtures.originFingerprint)
        #expect(selfSigned.isWellFormed)
    }

    /// Liveness is an injected instant at every door; nothing here reads a clock.
    @Test func livenessIsAnInjectedInstant() {
        let receipt = MeshRecipientReceiptFixtures.receipt()
        #expect(receipt.isLive(at: MeshRecipientReceiptFixtures.expiresAt.addingTimeInterval(-1)))
        #expect(receipt.isLive(at: MeshRecipientReceiptFixtures.expiresAt))
        #expect(receipt.isLive(at: MeshRecipientReceiptFixtures.expiresAt.addingTimeInterval(1)) == false)
    }

    /// Both doors floor the instants to the signed whole seconds, so a relay's re-encoding cannot
    /// produce a receipt `!=` the recipient's that still verifies.
    @Test func bothDoorsFloorTheInstantsToTheSignedWholeSeconds() throws {
        let signed = MeshRecipientReceiptFixtures.receipt()
        let fractional = signed.replacing(
            receivedAt: signed.receivedAt.addingTimeInterval(0.999),
            expiresAt: signed.expiresAt.addingTimeInterval(0.999)
        )
        #expect(fractional == signed)
        let wire = try JSONEncoder().encode(UnclampedRecipientReceiptWire(signed))
        let decoded = try JSONDecoder().decode(MeshRecipientReceipt.self, from: wire)
        #expect(decoded == signed)
        #expect(canonicalBytes(for: decoded) == canonicalBytes(for: signed))
    }
}

/// A receipt's JSON with NO floor on either instant — what a re-encoded frame from a peer looks like
/// on the wire. Same coding keys and encoder strategy as the real type, so decoding it as a
/// ``MeshRecipientReceipt`` exercises `init(from:)` exactly.
private struct UnclampedRecipientReceiptWire: Encodable {
    let meshID: UUID
    let itemID: UUID
    let originFingerprint: String
    let contentHash: Data
    let recipientFingerprint: String
    let receivedAt: Date
    let expiresAt: Date
    let signature: Data

    /// `receipt`, with both instants pushed a fraction of a second past the signed value.
    init(_ receipt: MeshRecipientReceipt) {
        meshID = receipt.meshID
        itemID = receipt.itemID
        originFingerprint = receipt.originFingerprint
        contentHash = receipt.contentHash
        recipientFingerprint = receipt.recipientFingerprint
        receivedAt = receipt.receivedAt.addingTimeInterval(0.999)
        expiresAt = receipt.expiresAt.addingTimeInterval(0.999)
        signature = receipt.signature
    }
}

// MARK: - Minting

/// The mint gate: a receipt exists only behind a real durable acknowledgement, and every refusal is
/// named.
@MainActor
@Suite(.serialized)
struct MeshRecipientReceiptSigningTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer
    /// has run before a cell's identities or stores reach the keychain.
    let keychain = PackageTestEnvironment.keychain

    private typealias Fixture = MeshRoutedStoreFixtures

    /// A rig whose item is a PHOTO, so the default table gives it a stage.
    private func photoRig(_ scope: MeshRoutedStorageScope) throws -> MeshRoutedCustodyRig {
        try MeshRoutedCustodyFixtures.rig(scope: scope, typeToken: MeshRoutedTypeToken.photo)
    }

    @Test func aReceiptCanOnlyBeMintedFromADeliveryWitness() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try photoRig(scope)
        let receipt = try MeshRoutedCustodyFixtures.recipientReceipt(rig)

        #expect(receipt.originFingerprint == rig.origin.localFingerprint)
        #expect(receipt.recipientFingerprint == rig.custodian.localFingerprint)
        #expect(receipt.meshID == rig.rig.meshID)
        #expect(receipt.itemID == rig.manifest.itemID)
        #expect(receipt.contentHash == rig.manifest.contentHash)
        #expect(receipt.expiresAt == rig.manifest.expiresAt)
        #expect(receipt.isWellFormed)
        #expect(receipt.signature.count == MeshRecipientReceiptFormat.signatureByteCount)
        #expect(IdentityService.verify(
            receipt.signature, of: canonicalBytes(for: receipt),
            by: rig.custodian.localSigningPublicKey,
            purpose: ProximityNamespace.packageTest.family.purposes.signature.meshRecipientReceiptV1
        ))
    }

    /// There is no argument list that mints a receipt without a witness, and a witness comes only
    /// from a returned durable write.
    @Test func noWitnessMeansNoReceiptEvenWithEveryOtherInputInHand() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try photoRig(scope)

        let acknowledged = MeshRoutedCustodyFixtures.commitDelivery(rig)
        #expect(MeshRoutedCustodyFixtures.deliveryWitness(acknowledged) == nil, "\(acknowledged)")
        #expect(acknowledged.refusal == .unknownItem)
    }

    @Test func aMintForAnotherIdentityIsNotTheRecipient() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try photoRig(scope)
        MeshRoutedCustodyFixtures.stageAll(rig)
        _ = MeshRoutedCustodyFixtures.commit(rig)
        let witness = try #require(
            MeshRoutedCustodyFixtures.deliveryWitness(MeshRoutedCustodyFixtures.commitDelivery(rig))
        )

        #expect(throws: MeshRecipientReceiptMintError.notTheRecipient) {
            _ = try MeshRecipientReceipt.signed(
                witness: witness, manifest: rig.manifest, identity: rig.origin
            )
        }
    }

    @Test func aMintAgainstAnotherItemsManifestIsRefused() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let other = Fixture.scope()
        defer { Fixture.tearDown(other) }
        let rig = try photoRig(scope)
        let elsewhere = try photoRig(other)
        MeshRoutedCustodyFixtures.stageAll(rig)
        _ = MeshRoutedCustodyFixtures.commit(rig)
        let witness = try #require(
            MeshRoutedCustodyFixtures.deliveryWitness(MeshRoutedCustodyFixtures.commitDelivery(rig))
        )

        #expect(throws: MeshRecipientReceiptMintError.witnessForAnotherItem) {
            _ = try MeshRecipientReceipt.signed(
                witness: witness, manifest: elsewhere.manifest, identity: rig.custodian
            )
        }
    }

    @Test func aMintAgainstAManifestWithAnotherContentHashIsRefused() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try photoRig(scope)
        MeshRoutedCustodyFixtures.stageAll(rig)
        _ = MeshRoutedCustodyFixtures.commit(rig)
        let witness = try #require(
            MeshRoutedCustodyFixtures.deliveryWitness(MeshRoutedCustodyFixtures.commitDelivery(rig))
        )
        var hash = rig.manifest.contentHash
        hash[hash.startIndex] ^= 0x01

        #expect(throws: MeshRecipientReceiptMintError.contentHashMismatch) {
            _ = try MeshRecipientReceipt.signed(
                witness: witness, manifest: rig.manifest.replacing(contentHash: hash),
                identity: rig.custodian
            )
        }
    }

    /// An origin issues itself no receipt: it is never one of its own destinations.
    ///
    /// Reaching this refusal needs a record whose ORIGIN is this device — no shipped path produces
    /// one, so the state is planted, which is exactly what makes the guard live rather than
    /// decorative.
    @Test func anOriginMintingItsOwnReceiptIsRefused() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try photoRig(scope)
        let me = rig.custodian.localFingerprint
        let selfAuthored = rig.manifest.replacing(originFingerprint: me)
        let store = MeshRoutedStore(scope: scope)
        try Fixture.plant(
            MeshRoutedIndex(items: [Self.selfAuthoredRecord(selfAuthored)]), into: store
        )

        let acknowledged = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.committingDelivery(
                item: MeshRoutedItemKey(selfAuthored), recipient: me,
                stages: .increment1, evidence: .none, now: Fixture.now
            )
        }
        let witness = try #require(MeshRoutedCustodyFixtures.deliveryWitness(acknowledged),
                                   "the planted record must acknowledge: \(acknowledged)")
        #expect(witness.originFingerprint == me)

        #expect(throws: MeshRecipientReceiptMintError.recipientIsOrigin) {
            _ = try MeshRecipientReceipt.signed(
                witness: witness, manifest: selfAuthored, identity: rig.custodian
            )
        }
    }

    /// A complete, custodied, manifest-bound record for `manifest` with no chunk files — the state
    /// no shipped writer produces, planted so an otherwise unreachable mint guard is testable.
    private static func selfAuthoredRecord(_ manifest: MeshRoutedManifest) -> MeshRoutedItemRecord {
        MeshRoutedItemRecord(
            key: MeshRoutedItemKey(manifest),
            contentHash: manifest.contentHash,
            chunkCount: 0,
            expiresAt: manifest.expiresAt,
            manifest: manifest,
            firstSeenAt: MeshRoutedManifestFixtures.base,
            custodiedAt: MeshRoutedManifestFixtures.base,
            deliveredAt: nil,
            chunks: [],
            delivery: MeshRoutedDeliveryRecord(contentID: manifest.itemID, progress: [:]),
            receipts: [],
            recipientReceipts: []
        )
    }

    /// The union-record stance, asserted rather than commented: a receipt members must forward
    /// verbatim is accepted UNSEALED, while a type that is sealing-required is not.
    @Test func aReceiptFrameIsAcceptedUnsealed() throws {
        let members = try MeshDeliveryFixtures.rig(memberCount: 2)
        let names = members.fingerprints
        let sender = try #require(members.identities[names[0]])
        let receiver = try #require(members.identities[names[1]])
        let payload = try JSONEncoder().encode(
            MeshRecipientReceiptPayload(receipt: MeshRecipientReceiptFixtures.receipt())
        )
        let base = MeshRecipientReceiptFixtures.base

        let frame = try ProximityIdentityEnvelope.signed(
            identityService: sender, senderDisplayName: "recipient",
            recipientFingerprint: receiver.localFingerprint,
            payloadType: .meshRecipientReceipt, payloadEncryption: .none,
            payloadSummary: PayloadSummary(title: "receipt"), payload: payload, createdAt: base
        )
        let opened = try frame.verify(
            identityService: receiver, replayCache: ReplayCache(dateProvider: { base })
        )
        #expect(opened == payload)

        let control = try ProximityIdentityEnvelope.signed(
            identityService: sender, senderDisplayName: "recipient",
            recipientFingerprint: receiver.localFingerprint,
            payloadType: .verifyChallenge, payloadEncryption: .none,
            payloadSummary: PayloadSummary(title: "receipt"), payload: payload, createdAt: base
        )
        #expect(throws: ProximityIdentityEnvelope.VerifyError.sealingRequired) {
            try control.verify(identityService: receiver, replayCache: ReplayCache(dateProvider: { base }))
        }
    }

    @Test func aMintPastTheItemsExpiryIsRefused() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try photoRig(scope)
        MeshRoutedCustodyFixtures.stageAll(rig)
        _ = MeshRoutedCustodyFixtures.commit(rig)
        let witness = try #require(
            MeshRoutedCustodyFixtures.deliveryWitness(MeshRoutedCustodyFixtures.commitDelivery(rig))
        )
        let expired = rig.manifest.replacing(expiresAt: witness.deliveredAt)

        #expect(throws: MeshRecipientReceiptMintError.itemExpired) {
            _ = try MeshRecipientReceipt.signed(
                witness: witness, manifest: expired, identity: rig.custodian
            )
        }
    }

    /// `meshID` and `expiresAt` come off the MANIFEST, never a parameter: no receipt can claim
    /// another mesh or a longer life than the origin signed.
    @Test func theMintTakesMeshAndExpiryFromTheManifest() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try photoRig(scope)
        MeshRoutedCustodyFixtures.stageAll(rig)
        _ = MeshRoutedCustodyFixtures.commit(rig)
        let witness = try #require(
            MeshRoutedCustodyFixtures.deliveryWitness(MeshRoutedCustodyFixtures.commitDelivery(rig))
        )
        let moved = rig.manifest.replacing(
            meshID: MeshRecipientReceiptFixtures.meshID,
            expiresAt: rig.manifest.expiresAt.addingTimeInterval(-60)
        )

        let receipt = try MeshRecipientReceipt.signed(
            witness: witness, manifest: moved, identity: rig.custodian
        )
        #expect(receipt.meshID == MeshRecipientReceiptFixtures.meshID)
        #expect(receipt.expiresAt == moved.expiresAt)
        #expect(receipt.receivedAt == witness.deliveredAt)
    }

    /// Two mints of one durable fact are byte-identical up to the hedged signature, and BOTH verify.
    @Test func twoMintsOfOneFactAreByteIdenticalUpToTheSignature() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try photoRig(scope)
        let first = try MeshRoutedCustodyFixtures.recipientReceipt(rig)
        let witness = try #require(
            MeshRoutedCustodyFixtures.deliveryWitness(MeshRoutedCustodyFixtures.commitDelivery(rig))
        )
        let second = try MeshRecipientReceipt.signed(
            witness: witness, manifest: rig.manifest, identity: rig.custodian
        )

        #expect(canonicalBytes(for: first) == canonicalBytes(for: second))
        #expect(first.receiptID == second.receiptID)
        for signed in [first, second] {
            #expect(IdentityService.verify(
                signed.signature, of: canonicalBytes(for: signed),
                by: rig.custodian.localSigningPublicKey,
                purpose: ProximityNamespace.packageTest.family.purposes.signature.meshRecipientReceiptV1
            ), "a re-mint must verify on its own signature, never by ==")
        }
    }

    @Test(arguments: MeshRecipientReceiptTamper.allCases)
    func tamperingAnySignedFieldFailsTheSignature(tamper: MeshRecipientReceiptTamper) throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try photoRig(scope)
        let receipt = try MeshRoutedCustodyFixtures.recipientReceipt(rig)
        let names = rig.rig.fingerprints
        let otherOrigin = try #require(names.first { $0 != receipt.originFingerprint
            && $0 != receipt.recipientFingerprint })

        let tampered = tamper.applied(to: receipt, otherAdmittedOrigin: otherOrigin)
        let door = MeshRecipientReceiptVerifier(
            meshID: rig.rig.meshID, hardDeadline: MeshRoutedManifestFixtures.hardDeadline,
            ledger: rig.rig.ledger, manifest: nil
        )
        #expect(door.verify(tampered) == .signatureInvalid, "\(tamper)")
    }
}

// MARK: - Verifying

/// The receive door: every rejection reachable and named, D14 in both directions, and the one leg
/// custody has no analogue for.
@MainActor
@Suite(.serialized)
struct MeshRecipientReceiptVerifierTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer
    /// has run before a cell's identities or stores reach the keychain.
    let keychain = PackageTestEnvironment.keychain

    private typealias Fixture = MeshRoutedStoreFixtures

    /// A verifier over `rig`, holding the fixture `hardDeadline`.
    private func verifier(
        _ rig: MeshRoutedCustodyRig,
        ledger: MeshMembershipLedger? = nil,
        hardDeadline: Date? = nil,
        manifest: MeshRoutedManifest? = nil
    ) -> MeshRecipientReceiptVerifier {
        MeshRecipientReceiptVerifier(
            meshID: rig.rig.meshID,
            hardDeadline: hardDeadline ?? MeshRoutedManifestFixtures.hardDeadline,
            ledger: ledger ?? rig.rig.ledger,
            manifest: manifest ?? rig.manifest
        )
    }

    private func photoRig(_ scope: MeshRoutedStorageScope) throws -> MeshRoutedCustodyRig {
        try MeshRoutedCustodyFixtures.rig(scope: scope, typeToken: MeshRoutedTypeToken.photo)
    }

    @Test func everyRejectionIsReachable() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try photoRig(scope)
        let receipt = try MeshRoutedCustodyFixtures.recipientReceipt(rig)
        let names = rig.rig.fingerprints
        #expect(verifier(rig).verify(receipt) == nil)

        #expect(verifier(rig).verify(receipt.replacing(meshID: UUID())) == .foreignMesh)
        #expect(verifier(rig).verify(receipt.replacing(signature: Data(repeating: 0x01, count: 63)))
                == .malformed)
        #expect(verifier(rig).verify(receipt.replacing(recipientFingerprint: receipt.originFingerprint))
                == .recipientIsOrigin)
        #expect(verifier(rig).verify(receipt.replacing(recipientFingerprint: "fp999"))
                == .recipientNotAdmitted)
        #expect(
            verifier(rig, hardDeadline: MeshRoutedManifestFixtures.hardDeadline.addingTimeInterval(60))
                .verify(receipt) == .expiryMismatch
        )
        #expect(verifier(rig).verify(receipt.replacing(itemID: UUID())) == .signatureInvalid)

        // A DIFFERENT item's manifest: all three legs of the identity triple are checked, so the
        // refusal is the manifest's rather than a signature failure.
        let other = try photoRig(Fixture.scope())
        defer { Fixture.tearDown(other.scope) }
        #expect(verifier(rig, manifest: other.manifest).verify(receipt) == .manifestMismatch)

        // An admission binding the recipient's fingerprint to somebody else's key.
        let founder = try #require(rig.rig.identities[names[0]])
        let forged = SignedAdmissionRecord(token: try MeshAdmissionToken.signed(
            meshID: rig.rig.meshID,
            joinerFingerprint: rig.custodian.localFingerprint,
            joinerSigningPublicKey: founder.localSigningPublicKey,
            admitterIdentity: founder,
            grantedAt: MeshMembershipEventFixtures.base
        ))
        let forgedLedger = MeshMembershipLedger(admissions: MeshMembershipRecordSet([forged]))
        #expect(verifier(rig, ledger: forgedLedger).verify(receipt) == .recipientKeyMismatch)
    }

    /// The leg with no custody analogue: a courier need not be a recipient, but a signer the origin
    /// never addressed is claiming to close a destination that does not exist.
    @Test func aSignerTheManifestDoesNotNameIsNotADestination() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try photoRig(scope)
        let receipt = try MeshRoutedCustodyFixtures.recipientReceipt(rig)
        let narrowed = rig.manifest.replacing(
            destinations: rig.manifest.destinations.filter { $0 != receipt.recipientFingerprint }
        )
        #expect(narrowed.destinations.isEmpty == false)

        #expect(verifier(rig, manifest: narrowed).verify(receipt) == .notADestination)
        // Without a manifest the leg cannot be asked, and the receipt still verifies on everything
        // else — the item may simply not have arrived here yet.
        #expect(verifier(rig, manifest: nil).verify(receipt) == nil)
    }

    /// D14, both directions: leaving is not a retraction, but a quorum removal is.
    @Test func aDepartedRecipientVerifiesAndAQuorumRemovedOneDoesNot() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try photoRig(scope)
        let receipt = try MeshRoutedCustodyFixtures.recipientReceipt(rig)
        let names = rig.rig.fingerprints

        var records = MeshMembershipRecordVerifier(meshID: rig.rig.meshID, ledger: rig.rig.ledger)
        let departure = try SignedDepartureRecord.signed(
            meshID: rig.rig.meshID, identity: rig.custodian, occurredAt: MeshMembershipEventFixtures.base
        )
        #expect(records.insert(departure) == nil)
        #expect(records.roster.contains(fingerprint: rig.custodian.localFingerprint) == false)
        #expect(verifier(rig, ledger: records.ledger).verify(receipt) == nil,
                "a departed recipient's receipt must still verify — the item did reach them")

        var removalRecords = MeshMembershipRecordVerifier(meshID: rig.rig.meshID, ledger: rig.rig.ledger)
        let tallier = try #require(rig.rig.identities[names[0]])
        let removal = try SignedRemovalRecord.signed(
            meshID: rig.rig.meshID,
            identity: tallier,
            memberFingerprint: rig.custodian.localFingerprint,
            proposalID: MeshMembershipEventFixtures.proposalID,
            voterFingerprints: [names[0], names[2]],
            occurredAt: MeshMembershipEventFixtures.base
        )
        #expect(removalRecords.insert(removal) == nil)
        #expect(removalRecords.ledger.removals.memberFingerprints.contains(rig.custodian.localFingerprint))
        #expect(verifier(rig, ledger: removalRecords.ledger).verify(receipt) == .recipientRemoved)
    }

    /// An over-long fingerprint is a cheap `malformed` rejection BEFORE any verify, because neither
    /// door clamps the scalar.
    @Test func anOverLongFingerprintIsMalformedNotSignatureInvalid() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try photoRig(scope)
        let receipt = try MeshRoutedCustodyFixtures.recipientReceipt(rig)
        let overLong = String(repeating: "r", count: MeshRecipientReceiptFormat.maxFingerprintLength + 1)
        let wide = receipt.replacing(recipientFingerprint: overLong)
        #expect(wide.recipientFingerprint.utf8.count
                == MeshRecipientReceiptFormat.maxFingerprintLength + 1, "the door must NOT clamp the scalar")
        #expect(wide.isWellFormed == false)
        #expect(verifier(rig).verify(wide) == .malformed)
    }

    /// Every rejection carries frozen English, and none of them is a localized string.
    @Test func everyRejectionCarriesFrozenEnglish() {
        for rejection in MeshRecipientReceiptRejection.allCases {
            #expect(rejection.diagnosticDescription.isEmpty == false, "\(rejection)")
            #expect(rejection.rawValue.allSatisfy { $0.isASCII }, "\(rejection)")
        }
        #expect(MeshRecipientReceiptRejection.allCases.count == 10)
    }
}
