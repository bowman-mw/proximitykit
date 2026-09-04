// MeshCustodyReceipt.swift
// ProximityKit/Mesh
//
// Network migration P5 item 3 (plan §11, §3.6): a custodian's signed statement that it is holding
// the complete ciphertext of one routed item, durably.
//
// The whole item in one sentence: **a custodian may say "I hold this" only after the ciphertext it
// holds survived a write that returned — and the type system, not a comment, is what makes the
// other order unwritable.** The mint below cannot be reached without a
// `MeshCustodyDurabilityWitness`, whose initializer is `fileprivate` to
// `MeshRoutedCustodyCommit.swift` — the file holding `MeshRoutedStore.committingCustody(...)` and
// nothing else. No witness ⇒ no receipt.
//
// **Custody is not delivery.** `MeshDeliveryStateToken.custodied` exists precisely to say so, and
// plan §11 requires the distinction in every UI surface. A receipt says a relay has the bytes; it
// says nothing about the destination having received them, and nothing about the custodian being
// able to READ them (a non-destination custodian holds no key wrap and never can).
//
// **Signed by the custodian, ABOUT the origin's item.** `originFingerprint` is the subject and
// `custodianFingerprint` is the signer — the other half of D11's pair, and the reason a receipt
// cannot be lifted onto another origin's item and still verify. A relay forwards a receipt verbatim
// inside its own envelope, exactly as it forwards a manifest and a chunk; there is no factory here
// that signs somebody else's receipt.
//
// What is deliberately NOT here: persistence of anyone else's receipts (the routed store's index
// holds those, bounded by the roster cap), dispatch and emission (item 6), the recipient-final
// receipt (item 4), any relay hop, hop count or TTL (increment 2's vocabulary, off the wire on
// purpose).

import CryptoKit
import FernletCrypto
import Foundation

// MARK: - MeshCustodyReceiptFormat

/// Fixed widths of the custody-receipt wire family (network migration P5 item 3, plan §11).
///
/// Every constant is **reused, never restated** — the routed family already fixed all three, and a
/// second spelling of 64 or 32 here is how two records' bounds drift apart.
nonisolated enum MeshCustodyReceiptFormat {
    /// Ed25519 signature length. Shared with the routed manifest and chunk.
    static let signatureByteCount = MeshRoutedManifestFormat.signatureByteCount
    /// SHA-256 width of ``MeshCustodyReceipt/contentHash``.
    static let contentHashByteCount = MeshRoutedManifestFormat.contentHashByteCount
    /// Cap on a fingerprint's UTF-8 length, shared with the routed family.
    static let maxFingerprintLength = MeshRoutedManifestFormat.maxFingerprintLength
}

// MARK: - MeshCustodyReceipt

/// A custodian's signed statement that, at the instant it signed, the COMPLETE ciphertext of
/// `(originFingerprint, itemID)` hashing to ``contentHash`` was in its sealed sidecar and would
/// survive a force-quit (plan §11, §3.6).
///
/// It does **not** attest that the custodian can read it, that it will still hold it later (expiry
/// and item 9's backpressure both retire custody), or DELIVERY.
///
/// Carries **no** key epoch, branch id or partition (invariants §3.2/§3.3); no hop count or TTL
/// (increment 2's vocabulary); no destination set, type token or size (the manifest's, and
/// origin-signed); no chunk index or partial count (a receipt exists only for a **complete** item,
/// so a count would be a second source of truth under one signature); no custodian chain (increment
/// 1 has one custody move); and **no schema integer** — the `.v1` in the domain IS the version, so a
/// wider receipt is a whole `custody-receipt.v2` family beside v1, never an optional `Codable` field
/// which, outside the canonical bytes, would be unsigned and forgeable.
///
/// Both doors normalise identically: the memberwise initializer floors both instants and
/// `init(from:)` routes through it, so a relay's re-encoding cannot produce a receipt `!=` the
/// custodian's that still verifies. Nothing is clamped — the receipt has no bounded collection, and
/// the two fingerprints are **scalars**, width-checked in ``isWellFormed`` exactly as the manifest's
/// is. Clamping a scalar would make that guard unreachable and demote an over-long fingerprint from
/// a cheap `malformed` rejection to a `signatureInvalid` one.
///
/// Pure value; every instant is a parameter and nothing reads a clock.
nonisolated struct MeshCustodyReceipt: Codable, Equatable, Sendable {
    /// The mesh the item belongs to. A receipt for another mesh is a refusal, not a difference.
    let meshID: UUID
    /// The routed item — `MeshRoutedManifest.itemID`.
    let itemID: UUID
    /// The item's author: the **subject**, not the signer. Half of the store's union key (D11).
    let originFingerprint: String
    /// The whole item's content hash, copied from the manifest and never recomputed here. 32 bytes.
    let contentHash: Data
    /// The custodian: the **signer**, and the value that becomes `MeshDeliveryState.custodied(by:)`.
    let custodianFingerprint: String
    /// The instant the index write that first recorded durable custody returned, floored to whole
    /// seconds. Re-used verbatim by every later witness for the same durable fact, so two receipts
    /// for one fact are byte-identical up to the hedged signature.
    let custodiedAt: Date
    /// The item's expiry — `MeshRoutedManifest.expiry(afterHardDeadline:)`, floored, copied from the
    /// manifest. Checked for **exact** equality against the receiver's own value (D6).
    let expiresAt: Date
    /// The custodian's Ed25519 signature over `canonicalBytes(for:)` under
    /// `FernletCryptoPurpose.Signature.meshCustodyReceiptV1`. Excluded from those bytes.
    let signature: Data

    /// Builds a receipt from already-signed parts, flooring both instants through
    /// ``MeshRoutedManifest/floored(_:)`` — so a decoded receipt's `Date`s are always the values the
    /// signature covers. Nothing else is normalised.
    init(
        meshID: UUID,
        itemID: UUID,
        originFingerprint: String,
        contentHash: Data,
        custodianFingerprint: String,
        custodiedAt: Date,
        expiresAt: Date,
        signature: Data
    ) {
        self.meshID = meshID
        self.itemID = itemID
        self.originFingerprint = originFingerprint
        self.contentHash = contentHash
        self.custodianFingerprint = custodianFingerprint
        self.custodiedAt = MeshRoutedManifest.floored(custodiedAt)
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
            custodianFingerprint: try container.decode(String.self, forKey: .custodianFingerprint),
            custodiedAt: try container.decode(Date.self, forKey: .custodiedAt),
            expiresAt: try container.decode(Date.self, forKey: .expiresAt),
            signature: try container.decode(Data.self, forKey: .signature)
        )
    }

    /// Whether every field has the width the format fixes. Checked on **untrusted bytes, BEFORE any
    /// signature verify**. Cross-checks against a manifest and the ledger are the verifier's.
    var isWellFormed: Bool {
        hasWellFormedScalars && hasWellFormedInstants
    }

    /// The fixed-width and bounded-scalar half of ``isWellFormed``. The two fingerprints are
    /// width-checked here precisely because neither door clamps them.
    private var hasWellFormedScalars: Bool {
        signature.count == MeshCustodyReceiptFormat.signatureByteCount
            && contentHash.count == MeshCustodyReceiptFormat.contentHashByteCount
            && !originFingerprint.isEmpty
            && originFingerprint.utf8.count <= MeshCustodyReceiptFormat.maxFingerprintLength
            && !custodianFingerprint.isEmpty
            && custodianFingerprint.utf8.count <= MeshCustodyReceiptFormat.maxFingerprintLength
    }

    /// The instants half: a claim of custody taken at or after the item stopped mattering is not a
    /// receipt this build accepts, and it is cheaper to say so before a signature verify.
    private var hasWellFormedInstants: Bool {
        custodiedAt < expiresAt
    }

    /// Liveness under an injected clock: `now <= expiresAt`, the same predicate the manifest and the
    /// chunk use. Never reads `Date()`.
    func isLive(at now: Date) -> Bool {
        now <= expiresAt
    }

    /// This receipt's dedup id: `UUID(SHA-256(lp(Hash.meshCustodyReceiptIDV1) ‖ uuid(itemID) ‖
    /// lp(origin) ‖ lp(custodian))[0..<16])`.
    ///
    /// **Derived, never a wire field** — a sender-chosen id is an attacker-chosen id. Deterministic,
    /// recomputable, and stable across a **re-mint**: CryptoKit's Ed25519 signing is hedged, so two
    /// mints of one logical receipt differ in the signature and nothing may compare receipts by
    /// `==`. ``custodiedAt`` is deliberately not an input either: a re-mint of the same claim is the
    /// same claim, and the replay window should treat it as one. This is the frame id item 12 admits.
    ///
    /// The result is **not** an RFC-4122 versioned UUID: it is a 128-bit dedup key that happens to
    /// have `UUID`'s shape, which is what `MeshFrameReplayWindow` takes.
    var receiptID: UUID {
        var writer = CanonicalByteWriter()
        writer.appendLengthPrefixed(FernletCryptoPurpose.Hash.meshCustodyReceiptIDV1.data)
        writer.appendUUID(itemID)
        writer.appendString(originFingerprint)
        writer.appendString(custodianFingerprint)
        return Self.uuid(fromFirst16: Data(SHA256.hash(data: writer.bytes)))
    }

    /// The zero id ``receiptID`` falls back to if it is ever handed a short digest. Unreachable:
    /// SHA-256 is 32 bytes. Present so no `!` is needed (Power of 10 R5).
    private static let zeroID = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    /// The first 16 bytes of `data` as a `UUID`, via the tuple form — never `withUnsafeBytes`
    /// (Power of 10 R9). The same reader `MeshRoutedContentDigest` keeps for the chunk id.
    private static func uuid(fromFirst16 data: Data) -> UUID {
        guard data.count >= 16 else { return zeroID }
        let bytes = [UInt8](data.prefix(16))
        return UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                           bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
    }
}

// MARK: - MeshCustodyReceiptPayload

/// The wire frame for a ``MeshCustodyReceipt`` — `PayloadType.meshCustodyReceipt`, signed and
/// UNSEALED like the routed manifest and chunk beside it.
///
/// **Not in `FernletIdentityEnvelope.sealingRequiredTypes`, on purpose:** a receipt is a plan §3.2
/// union record that members must be able to forward verbatim so they converge on delivery state.
/// Pairwise sealing would make a receipt readable only by its first hop and stop the convergence it
/// exists for. It carries no second claim about the custodian — the record already says, under the
/// custodian's own signature. Registered in item 3, dispatched from item 6 (P4's "built, unwired"
/// shape).
nonisolated struct MeshCustodyReceiptPayload: Codable, Equatable, Sendable {
    /// The custodian's signed record.
    let receipt: MeshCustodyReceipt

    /// Wraps a receipt for the wire.
    init(receipt: MeshCustodyReceipt) {
        self.receipt = receipt
    }
}

// MARK: - MeshCustodyReceiptMintError

/// Why ``MeshCustodyReceipt/signed(witness:manifest:identity:)`` refused to mint.
///
/// Thrown, never returned as nil, and never silent. Every case is **reachable**: an unreachable case
/// is an untestable case that reads like a live guard, which is why there is no `expiryMismatch`
/// here — `expiresAt` is copied off the manifest inside the factory, so a mismatch is structurally
/// impossible, and the reachable question ("is this item already over?") is ``itemExpired``.
///
/// Not `LocalizedError` — ``diagnosticDescription`` is frozen English for the audit log and is never
/// shown as user copy.
nonisolated enum MeshCustodyReceiptMintError: Error, Equatable, Sendable {
    /// The signing identity is not the witness's custodian. A device may only receipt its own
    /// custody.
    case notTheCustodian
    /// The witness is for a different `(origin, item)` pair than the manifest.
    case witnessForAnotherItem
    /// The witness's content hash is not the manifest's.
    case contentHashMismatch
    /// This device authored the item: it holds custody and issues no receipt to itself.
    case originIsSelf
    /// The durable custody instant is at or after the item's expiry, so there is nothing left to
    /// receipt.
    case itemExpired

    /// Frozen English for the diagnostic surface. Never shown as user copy.
    var diagnosticDescription: String {
        switch self {
        case .notTheCustodian: return "The signing identity is not the witness's custodian."
        case .witnessForAnotherItem: return "The durability witness is for a different routed item."
        case .contentHashMismatch: return "The witness's content hash is not the manifest's."
        case .originIsSelf: return "This device authored the item and issues itself no receipt."
        case .itemExpired: return "The item's expiry has passed, so custody cannot be receipted."
        }
    }
}

// MARK: - Signing factory

extension MeshCustodyReceipt {

    /// Mints a custodian-signed receipt for durable custody that **has already been proved**.
    ///
    /// The `witness` parameter is the whole gate: it can only be obtained from
    /// `MeshRoutedStore.committingCustody(item:custodian:now:)`, whose returned value is the one
    /// place a `MeshCustodyDurabilityWitness` is ever constructed. That is plan §3.6 in the type
    /// system rather than in a comment — there is no argument list that produces a receipt for bytes
    /// no durable write returned.
    ///
    /// `meshID` and `expiresAt` come off the **manifest**, never from a parameter, so a receipt
    /// cannot claim a different mesh or a longer life than the origin signed. `custodiedAt` comes
    /// off the **witness**, which carries the stored instant of the first successful commit rather
    /// than the instant of this pass — which is what makes a re-mint's canonical bytes identical.
    ///
    /// - Parameters:
    ///   - witness: Proof that a durable commit returned.
    ///   - manifest: The item's manifest, already accepted by `MeshRoutedManifestVerifier`.
    ///   - identity: The custodian. Its fingerprint must be the witness's.
    /// - Returns: The signed receipt.
    /// - Throws: ``MeshCustodyReceiptMintError`` or the identity's signing error. Never a trap.
    @MainActor
    static func signed(
        witness: MeshCustodyDurabilityWitness,
        manifest: MeshRoutedManifest,
        identity: IdentityService
    ) throws -> MeshCustodyReceipt {
        try validated(witness: witness, manifest: manifest, localFingerprint: identity.localFingerprint)
        let unsigned = MeshCustodyReceipt(
            meshID: manifest.meshID,
            itemID: manifest.itemID,
            originFingerprint: manifest.originFingerprint,
            contentHash: manifest.contentHash,
            custodianFingerprint: witness.custodianFingerprint,
            custodiedAt: witness.custodiedAt,
            expiresAt: manifest.expiresAt,
            signature: Data()
        )
        let signature = try identity.sign(
            canonicalBytes(for: unsigned),
            purpose: FernletCryptoPurpose.Signature.meshCustodyReceiptV1
        )
        return MeshCustodyReceipt(
            meshID: unsigned.meshID, itemID: unsigned.itemID,
            originFingerprint: unsigned.originFingerprint, contentHash: unsigned.contentHash,
            custodianFingerprint: unsigned.custodianFingerprint, custodiedAt: unsigned.custodiedAt,
            expiresAt: unsigned.expiresAt, signature: signature
        )
    }

    /// The mint's guard chain, in ``MeshCustodyReceiptMintError``'s case order. Every refusal is
    /// named before a single byte is signed.
    private static func validated(
        witness: MeshCustodyDurabilityWitness,
        manifest: MeshRoutedManifest,
        localFingerprint: String
    ) throws {
        guard localFingerprint == witness.custodianFingerprint else {
            throw MeshCustodyReceiptMintError.notTheCustodian
        }
        guard manifest.itemID == witness.itemID,
              manifest.originFingerprint == witness.originFingerprint else {
            throw MeshCustodyReceiptMintError.witnessForAnotherItem
        }
        guard manifest.contentHash == witness.contentHash else {
            throw MeshCustodyReceiptMintError.contentHashMismatch
        }
        guard manifest.originFingerprint != localFingerprint else {
            throw MeshCustodyReceiptMintError.originIsSelf
        }
        guard witness.custodiedAt < manifest.expiresAt else {
            throw MeshCustodyReceiptMintError.itemExpired
        }
    }
}
