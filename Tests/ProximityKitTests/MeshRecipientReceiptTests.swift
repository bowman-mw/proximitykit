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
// `MeshRecipientReceiptShapeTests`, with its name and tests unchanged, and the fixtures the
// package's copied suites read (`MeshRecipientReceiptFixtures`, `extension MeshRecipientReceipt`
// and `MeshRecipientReceiptShapeFault`); its other suites stay there, so what this header says of
// them is not held here.

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
