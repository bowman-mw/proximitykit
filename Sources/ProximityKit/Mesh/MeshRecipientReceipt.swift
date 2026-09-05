// MeshRecipientReceipt.swift
// ProximityKit/Mesh
//
// Network migration P5 item 4 (plan §11, §3.6): a DESTINATION's signed statement that one routed
// item reached it, finally.
//
// The whole item in one sentence: **a destination may say "this reached me" only after its own
// routed store wrote the ack instant durably — and the type system, not a comment, is what makes
// the other order unwritable.** The mint below cannot be reached without a
// `MeshRecipientDeliveryWitness`, whose initialiser is `fileprivate` to
// `MeshRoutedDeliveryCommit.swift` — the file holding `MeshRoutedStore.committingDelivery(...)` and
// nothing else. No witness ⇒ no receipt.
//
// **Custody is not delivery**, and the two receipts say different things under different domains. A
// `MeshCustodyReceipt` says a courier is holding the bytes; this says the person they were for has
// them. The signer here is a **destination** rather than a custodian, and the origin is the subject
// in both.
//
// **The ack STAGE is not on the wire.** A receipt's single meaning is "final". What made it final —
// durable storage for a photo or a text, a foreground decrypt plus a ledger commit for a heart,
// nothing at all for a control item — is resolved on both sides from the manifest's ORIGIN-signed
// `typeToken` through a `MeshRoutedAckStageTable`. A stage field would be a second source of truth,
// signed by the recipient, able to disagree with the token the origin signed.
//
// What is deliberately NOT here: any per-chunk or partial-item receipt (destination-final is
// whole-item, one receipt per `(recipient, item)`), persistence (the routed store's index holds
// receipts, this device's own included), dispatch and emission (item 6), any relay hop, hop count or
// TTL (increment 2's vocabulary, off the wire on purpose).

import CryptoKit
import FernletCrypto
import Foundation

// MARK: - MeshRecipientReceiptFormat

/// Fixed widths of the recipient-receipt wire family (network migration P5 item 4, plan §11).
///
/// Every constant is **reused, never restated** — the routed family already fixed all three, and a
/// second spelling of 64 or 32 here is how two records' bounds drift apart.
nonisolated enum MeshRecipientReceiptFormat {
    /// Ed25519 signature length. Shared with the routed manifest, chunk and custody receipt.
    static let signatureByteCount = MeshRoutedManifestFormat.signatureByteCount
    /// SHA-256 width of ``MeshRecipientReceipt/contentHash``.
    static let contentHashByteCount = MeshRoutedManifestFormat.contentHashByteCount
    /// Cap on a fingerprint's UTF-8 length, shared with the routed family.
    static let maxFingerprintLength = MeshRoutedManifestFormat.maxFingerprintLength
}

// MARK: - MeshRecipientReceipt

/// A destination's signed statement that `(originFingerprint, itemID)`, hashing to ``contentHash``,
/// reached it **finally** — under whatever condition that item's type makes final (plan §11).
///
/// It does not attest that the content was read, kept, or moved into any canonical store; it
/// attests that the condition plan §11 sets for this item's type was met and that this device's own
/// durable ack record returned before the signature existed (plan §3.6).
///
/// Carries **no ack stage** (resolved from the origin's signed `typeToken`, never stated by the
/// signer); no key epoch, branch id or partition (invariants §3.2/§3.3); no hop count or TTL
/// (increment 2's vocabulary); no destination set, type token or size (the manifest's, and
/// origin-signed); no chunk index, count or partial marker — **destination-final is whole-item**, so
/// there is exactly one receipt per `(recipient, item)` and a per-chunk one would be a second source
/// of truth under one signature; no custodian or courier chain; and **no schema integer** — the
/// `.v1` in the domain IS the version, so a wider receipt is a whole `recipient-receipt.v2` family
/// beside v1, never an optional `Codable` field which, outside the canonical bytes, would be
/// unsigned and forgeable.
///
/// Both doors normalise identically: the memberwise initializer floors both instants and
/// ``init(from:)`` routes through it, so a relay's re-encoding cannot produce a receipt `!=` the
/// recipient's that still verifies. Nothing is clamped — the receipt has no bounded collection, and
/// the two fingerprints are **scalars**, width-checked in ``isWellFormed``. Clamping a scalar would
/// make that guard unreachable and demote an over-long fingerprint from a cheap `malformed`
/// rejection to a `signatureInvalid` one.
///
/// Pure value; every instant is a parameter and nothing reads a clock.
nonisolated struct MeshRecipientReceipt: Codable, Equatable, Sendable {
    /// The mesh the item belongs to. A receipt for another mesh is a refusal, not a difference.
    let meshID: UUID
    /// The routed item — `MeshRoutedManifest.itemID`.
    let itemID: UUID
    /// The item's author: the **subject**, not the signer. Half of the store's union key (D11).
    let originFingerprint: String
    /// The whole item's content hash, copied from the manifest and never recomputed here. 32 bytes.
    let contentHash: Data
    /// The destination: the **signer**, and the one destination this receipt closes.
    let recipientFingerprint: String
    /// The instant the index write that first recorded THIS DEVICE's final ack returned, floored to
    /// whole seconds. Re-used verbatim by every later witness for the same durable fact, so two
    /// receipts for one fact are byte-identical up to the hedged signature.
    let receivedAt: Date
    /// The item's expiry — `MeshRoutedManifest.expiry(afterHardDeadline:)`, floored, copied from the
    /// manifest. Checked for **exact** equality against the receiver's own value (item 1's D6).
    let expiresAt: Date
    /// The recipient's Ed25519 signature over `canonicalBytes(for:)` under
    /// `FernletCryptoPurpose.Signature.meshRecipientReceiptV1`. Excluded from those bytes.
    let signature: Data

    /// Builds a receipt from already-signed parts, flooring both instants through
    /// ``MeshRoutedManifest/floored(_:)`` — so a decoded receipt's `Date`s are always the values the
    /// signature covers. Nothing else is normalised.
    init(
        meshID: UUID,
        itemID: UUID,
        originFingerprint: String,
        contentHash: Data,
        recipientFingerprint: String,
        receivedAt: Date,
        expiresAt: Date,
        signature: Data
    ) {
        self.meshID = meshID
        self.itemID = itemID
        self.originFingerprint = originFingerprint
        self.contentHash = contentHash
        self.recipientFingerprint = recipientFingerprint
        self.receivedAt = MeshRoutedManifest.floored(receivedAt)
        self.expiresAt = MeshRoutedManifest.floored(expiresAt)
        self.signature = signature
    }

    /// Decodes with the same floor the memberwise initializer applies (the `MeshEpochHeadsPayload`
    /// idiom): it routes through that initializer, so the two doors cannot drift.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            meshID: try container.decode(UUID.self, forKey: .meshID),
            itemID: try container.decode(UUID.self, forKey: .itemID),
            originFingerprint: try container.decode(String.self, forKey: .originFingerprint),
            contentHash: try container.decode(Data.self, forKey: .contentHash),
            recipientFingerprint: try container.decode(String.self, forKey: .recipientFingerprint),
            receivedAt: try container.decode(Date.self, forKey: .receivedAt),
            expiresAt: try container.decode(Date.self, forKey: .expiresAt),
            signature: try container.decode(Data.self, forKey: .signature)
        )
    }

    /// Whether every field has the width the format fixes. Checked on **untrusted bytes, BEFORE any
    /// signature verify**. Cross-checks against a manifest and the ledger are the verifier's.
    ///
    /// It deliberately does **not** check that the recipient differs from the origin: that would
    /// make ``MeshRecipientReceiptRejection/recipientIsOrigin`` unreachable and demote a named
    /// refusal to a shape complaint.
    var isWellFormed: Bool {
        hasWellFormedScalars && hasWellFormedInstants
    }

    /// The fixed-width and bounded-scalar half of ``isWellFormed``. The two fingerprints are
    /// width-checked here precisely because neither door clamps them.
    private var hasWellFormedScalars: Bool {
        signature.count == MeshRecipientReceiptFormat.signatureByteCount
            && contentHash.count == MeshRecipientReceiptFormat.contentHashByteCount
            && !originFingerprint.isEmpty
            && originFingerprint.utf8.count <= MeshRecipientReceiptFormat.maxFingerprintLength
            && !recipientFingerprint.isEmpty
            && recipientFingerprint.utf8.count <= MeshRecipientReceiptFormat.maxFingerprintLength
    }

    /// The instants half: a delivery claimed at or after the item stopped mattering is not a receipt
    /// this build accepts, and it is cheaper to say so before a signature verify.
    private var hasWellFormedInstants: Bool {
        receivedAt < expiresAt
    }

    /// Liveness under an injected clock: `now <= expiresAt`, the same predicate the manifest, the
    /// chunk and the custody receipt use. Never reads `Date()`.
    func isLive(at now: Date) -> Bool {
        now <= expiresAt
    }

    /// This receipt's dedup id: `UUID(SHA-256(lp(Hash.meshRecipientReceiptIDV1) ‖ uuid(itemID) ‖
    /// lp(origin) ‖ lp(recipient))[0..<16])`.
    ///
    /// **Derived, never a wire field** — a sender-chosen id is an attacker-chosen id. Deterministic,
    /// recomputable, and stable across a **re-mint**: CryptoKit's Ed25519 signing is hedged, so two
    /// mints of one logical receipt differ in the signature and nothing may compare receipts by
    /// `==`. ``receivedAt`` is deliberately not an input either: a re-mint of the same claim is the
    /// same claim, and the replay window treats it as one. This is the frame id P5 item 12 admits —
    /// under the author axis ``recipientFingerprint`` — and it is **one id per `(recipient, item)`**,
    /// the wire-level statement of "destination-final, never per chunk".
    ///
    /// The result is **not** an RFC-4122 versioned UUID: it is a 128-bit dedup key that happens to
    /// have `UUID`'s shape, which is what `MeshFrameReplayWindow` takes.
    var receiptID: UUID {
        var writer = CanonicalByteWriter()
        writer.appendLengthPrefixed(FernletCryptoPurpose.Hash.meshRecipientReceiptIDV1.data)
        writer.appendUUID(itemID)
        writer.appendString(originFingerprint)
        writer.appendString(recipientFingerprint)
        return Self.uuid(fromFirst16: Data(SHA256.hash(data: writer.bytes)))
    }

    /// The zero id ``receiptID`` falls back to if it is ever handed a short digest. Unreachable:
    /// SHA-256 is 32 bytes. Present so no `!` is needed (Power of 10 R5).
    private static let zeroID = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    /// The first 16 bytes of `data` as a `UUID`, via the tuple form — never `withUnsafeBytes`
    /// (Power of 10 R9). The same reader ``MeshCustodyReceipt/receiptID`` keeps.
    private static func uuid(fromFirst16 data: Data) -> UUID {
        guard data.count >= 16 else { return zeroID }
        let bytes = [UInt8](data.prefix(16))
        return UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                           bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
    }
}

// MARK: - MeshRecipientReceiptPayload

/// The wire frame for a ``MeshRecipientReceipt`` — `PayloadType.meshRecipientReceipt`, signed and
/// UNSEALED like the routed manifest, chunk and custody receipt beside it.
///
/// **Not in `FernletIdentityEnvelope.sealingRequiredTypes`, on purpose:** a receipt is a plan §3.2
/// union record that members must be able to forward verbatim so they converge on delivery state.
/// Pairwise sealing would make a receipt readable only by its first hop and stop the convergence it
/// exists for. It carries no content — the bytes it is about stay in the recipient's sealed sidecar.
/// Registered in item 4, dispatched from item 6 (P4's "built, unwired" shape).
nonisolated struct MeshRecipientReceiptPayload: Codable, Equatable, Sendable {
    /// The recipient's signed record.
    let receipt: MeshRecipientReceipt

    /// Wraps a receipt for the wire.
    init(receipt: MeshRecipientReceipt) {
        self.receipt = receipt
    }
}

// MARK: - MeshRecipientReceiptMintError

/// Why ``MeshRecipientReceipt/signed(witness:manifest:identity:)`` refused to mint.
///
/// Thrown, never returned as nil, and never silent. Every case is **reachable**: an unreachable case
/// is an untestable case that reads like a live guard, which is why there is no `notADestination`
/// and no `ackStageUnsatisfied` here — the store door refuses both **before** a witness exists, and
/// a mint-side re-check against a table the same caller passes would be circular.
///
/// Not `LocalizedError` — ``diagnosticDescription`` is frozen English for the audit log and is never
/// shown as user copy.
nonisolated enum MeshRecipientReceiptMintError: Error, Equatable, Sendable {
    /// The signing identity is not the witness's recipient. A device may only receipt its own
    /// delivery.
    case notTheRecipient
    /// The witness is for a different `(origin, item)` pair than the manifest.
    case witnessForAnotherItem
    /// The witness's content hash is not the manifest's.
    case contentHashMismatch
    /// This device authored the item: an origin is never one of its own destinations, and a receipt
    /// to itself would close a destination that does not exist.
    case recipientIsOrigin
    /// The durable ack instant is at or after the item's expiry, so there is nothing left to
    /// receipt.
    case itemExpired

    /// Frozen English for the diagnostic surface. Never shown as user copy.
    var diagnosticDescription: String {
        switch self {
        case .notTheRecipient: return "The signing identity is not the witness's recipient."
        case .witnessForAnotherItem: return "The delivery witness is for a different routed item."
        case .contentHashMismatch: return "The witness's content hash is not the manifest's."
        case .recipientIsOrigin: return "This device authored the item and issues itself no receipt."
        case .itemExpired: return "The item's expiry has passed, so delivery cannot be receipted."
        }
    }
}

// MARK: - Signing factory

extension MeshRecipientReceipt {

    /// Mints a recipient-signed receipt for a final ack that **has already been recorded durably**.
    ///
    /// The `witness` parameter is the whole gate: it can only be obtained from
    /// `MeshRoutedStore.committingDelivery(item:recipient:stages:evidence:now:)`, whose returned
    /// value is the one place a ``MeshRecipientDeliveryWitness`` is ever constructed. That is plan
    /// §3.6 in the type system rather than in a comment — there is no argument list that produces a
    /// receipt for an acknowledgement no durable write returned.
    ///
    /// `meshID` and `expiresAt` come off the **manifest**, never from a parameter, so a receipt
    /// cannot claim a different mesh or a longer life than the origin signed. `receivedAt` comes off
    /// the **witness**, which carries the stored instant of the first successful ack rather than the
    /// instant of this pass — which is what makes a re-mint's canonical bytes identical.
    ///
    /// - Parameters:
    ///   - witness: Proof that a durable ack write returned.
    ///   - manifest: The item's manifest, already accepted by `MeshRoutedManifestVerifier`.
    ///   - identity: The recipient. Its fingerprint must be the witness's.
    /// - Returns: The signed receipt.
    /// - Throws: ``MeshRecipientReceiptMintError`` or the identity's signing error. Never a trap.
    @MainActor
    static func signed(
        witness: MeshRecipientDeliveryWitness,
        manifest: MeshRoutedManifest,
        identity: IdentityService
    ) throws -> MeshRecipientReceipt {
        try validated(witness: witness, manifest: manifest, localFingerprint: identity.localFingerprint)
        let unsigned = MeshRecipientReceipt(
            meshID: manifest.meshID,
            itemID: manifest.itemID,
            originFingerprint: manifest.originFingerprint,
            contentHash: manifest.contentHash,
            recipientFingerprint: witness.recipientFingerprint,
            receivedAt: witness.deliveredAt,
            expiresAt: manifest.expiresAt,
            signature: Data()
        )
        let signature = try identity.sign(
            canonicalBytes(for: unsigned),
            purpose: FernletCryptoPurpose.Signature.meshRecipientReceiptV1
        )
        return MeshRecipientReceipt(
            meshID: unsigned.meshID, itemID: unsigned.itemID,
            originFingerprint: unsigned.originFingerprint, contentHash: unsigned.contentHash,
            recipientFingerprint: unsigned.recipientFingerprint, receivedAt: unsigned.receivedAt,
            expiresAt: unsigned.expiresAt, signature: signature
        )
    }

    /// The mint's guard chain, in ``MeshRecipientReceiptMintError``'s case order. Every refusal is
    /// named before a single byte is signed.
    private static func validated(
        witness: MeshRecipientDeliveryWitness,
        manifest: MeshRoutedManifest,
        localFingerprint: String
    ) throws {
        guard localFingerprint == witness.recipientFingerprint else {
            throw MeshRecipientReceiptMintError.notTheRecipient
        }
        guard manifest.itemID == witness.itemID,
              manifest.originFingerprint == witness.originFingerprint else {
            throw MeshRecipientReceiptMintError.witnessForAnotherItem
        }
        guard manifest.contentHash == witness.contentHash else {
            throw MeshRecipientReceiptMintError.contentHashMismatch
        }
        guard manifest.originFingerprint != localFingerprint else {
            throw MeshRecipientReceiptMintError.recipientIsOrigin
        }
        guard witness.deliveredAt < manifest.expiresAt else {
            throw MeshRecipientReceiptMintError.itemExpired
        }
    }
}
