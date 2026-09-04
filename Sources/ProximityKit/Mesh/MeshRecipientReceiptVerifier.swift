// MeshRecipientReceiptVerifier.swift
// ProximityKit/Mesh
//
// Network migration P5 item 4 (plan §11): the one door a received ``MeshRecipientReceipt`` passes
// through before this device may advance a destination to `delivered` or store the receipt as the
// evidence behind that rung.
//
// The shape is `MeshCustodyReceiptVerifier`'s — mesh, shape, key from the ADMISSION ledger,
// signature — with one leg it has no analogue for. A custodian that is not a destination is normal,
// so the custody verifier cannot ask; a RECIPIENT that is not a destination is a lie the origin's
// signed manifest catches, so `notADestination` is checked here whenever a manifest is held.
//
// D14 holds here as it does everywhere else: a **departed** recipient's receipt still verifies —
// leaving is not a retraction, `delivered` already outranks a later departure, and the bytes did
// reach them — while a **quorum-removed** recipient's does not. The key comes from the merged
// admission ledger by the RECEIPT's own fingerprint, never from the envelope's sender, which is
// whoever is forwarding this hop; that is what lets a receipt propagate by re-gossip like every
// other plan §3.2 union record.
//
// Verification needs public material only — signature, the ledger, and the manifest's own fields —
// so it runs on a locked device over ciphertext-only custody (item 1's D9: verify = public, unwrap =
// private). Pure value, no clock: expiry is an EQUALITY against this device's own
// `hardDeadline + grace`, not a liveness read; liveness is `MeshRecipientReceipt.isLive(at:)` with
// an injected `now`, decided by the caller.

import FernletCrypto
import Foundation

// MARK: - MeshRecipientReceiptRejection

/// Why a received ``MeshRecipientReceipt`` was refused. One frozen English token per cause, logged
/// verbatim, never localized; not `Error`, not `LocalizedError` — ``diagnosticDescription`` is the
/// audit surface (the ``MeshChunkRejection`` idiom).
nonisolated enum MeshRecipientReceiptRejection: String, CaseIterable, Equatable, Sendable {
    /// The receipt names a different mesh.
    case foreignMesh
    /// A field has the wrong width, or the ack instant is not before the item's expiry
    /// (``MeshRecipientReceipt/isWellFormed``).
    case malformed
    /// The recipient is the item's own origin. An author is never one of its own destinations, so a
    /// signed claim otherwise is a confusion of the two roles D11's pair keeps apart.
    case recipientIsOrigin
    /// The admission ledger never admitted the named recipient — there is no key to verify against.
    case recipientNotAdmitted
    /// The mesh removed the named recipient by quorum (plan §10.4). A DEPARTED recipient's receipt
    /// still verifies; removal is the mesh's moderation act and is the one that invalidates.
    case recipientRemoved
    /// The admitted key's fingerprint is not ``MeshRecipientReceipt/recipientFingerprint``.
    case recipientKeyMismatch
    /// ``MeshRecipientReceipt/expiresAt`` is not this device's `hardDeadline + grace` (item 1's D6).
    case expiryMismatch
    /// The recipient's signature did not verify over the re-derived canonical bytes.
    case signatureInvalid
    /// The receipt does not belong to the manifest this verifier holds: its item, its origin or its
    /// content hash differs. **All three legs** — a receipt matching only on `itemID` would be an
    /// admitted member claiming delivery of another origin's item under its own valid signature.
    case manifestMismatch
    /// The signer is not one of the item's signed destinations. The leg with no custody analogue: a
    /// courier need not be a recipient, but a recipient that the origin never addressed is claiming
    /// to close a destination that does not exist.
    case notADestination

    /// Frozen English for the diagnostic surface. Never shown as user copy.
    var diagnosticDescription: String {
        switch self {
        case .foreignMesh: return "The recipient receipt names a different mesh."
        case .malformed: return "A field in the recipient receipt was malformed."
        case .recipientIsOrigin: return "The recipient receipt's recipient is the item's own origin."
        case .recipientNotAdmitted: return "The recipient was never admitted to this mesh."
        case .recipientRemoved: return "The recipient was removed from this mesh by quorum."
        case .recipientKeyMismatch: return "The recipient's admitted key does not match its fingerprint."
        case .expiryMismatch: return "The receipt's expiry is not this mesh's hard deadline plus grace."
        case .signatureInvalid: return "The recipient's signature did not verify."
        case .manifestMismatch: return "The receipt does not belong to the manifest it was checked against."
        case .notADestination: return "The recipient is not one of the item's signed destinations."
        }
    }
}

// MARK: - MeshRecipientReceiptVerifier

/// The one door a received recipient receipt passes through before this device records the delivery
/// it claims.
///
/// Resolves the recipient's Ed25519 key from the **admission ledger** by the fingerprint the receipt
/// carries — never from the envelope's sender — and deliberately does NOT require the recipient to
/// be a current roster member (D14).
///
/// Pure value, `nonisolated`, no clock. All four stored properties are values; re-create it when the
/// ledger merges or the manifest arrives.
nonisolated struct MeshRecipientReceiptVerifier: Sendable {
    /// The session this device is in.
    let meshID: UUID
    /// The session's signed ceiling, from `MeshSessionContext.hardDeadline`.
    let hardDeadline: Date
    /// The merged membership ledger whose admissions bind fingerprints to signing keys.
    let ledger: MeshMembershipLedger
    /// The item's manifest, when one is held — nil is the **not yet seen** case, not a way to skip a
    /// check.
    ///
    /// - Important: a non-nil manifest must be one ``MeshRoutedManifestVerifier/verify(_:)`` has
    ///   already accepted; this type never re-verifies it, and it is the only authority on `itemID`,
    ///   `originFingerprint`, `contentHash` and the destination set.
    let manifest: MeshRoutedManifest?

    /// Binds the verifier to one session, optionally to one already-verified manifest.
    ///
    /// - Parameters:
    ///   - meshID: The session's mesh id.
    ///   - hardDeadline: The session's signed ceiling.
    ///   - ledger: The merged membership ledger.
    ///   - manifest: An already-verified manifest, or nil when the item is not held yet.
    init(meshID: UUID, hardDeadline: Date, ledger: MeshMembershipLedger, manifest: MeshRoutedManifest?) {
        self.meshID = meshID
        self.hardDeadline = hardDeadline
        self.ledger = ledger
        self.manifest = manifest
    }

    /// Checks, in order: mesh → shape → recipient is not the origin → admitted key → recipient not
    /// removed → key/fingerprint agreement → expiry equality → signature → (only with a manifest)
    /// item/origin/content-hash agreement → (only with a manifest) the signer is a destination.
    ///
    /// The shape check runs on untrusted bytes before anything expensive; the expiry equality runs
    /// before the signature because it is the cheaper refusal and needs no key.
    ///
    /// - Parameter receipt: The received receipt.
    /// - Returns: the named rejection, or nil when the receipt verified.
    func verify(_ receipt: MeshRecipientReceipt) -> MeshRecipientReceiptRejection? {
        guard receipt.meshID == meshID else { return .foreignMesh }
        guard receipt.isWellFormed else { return .malformed }
        guard receipt.recipientFingerprint != receipt.originFingerprint else {
            return .recipientIsOrigin
        }
        guard let key = recipientKey(for: receipt.recipientFingerprint) else {
            return .recipientNotAdmitted
        }
        guard !ledger.removals.memberFingerprints.contains(receipt.recipientFingerprint) else {
            return .recipientRemoved
        }
        guard fingerprintMatches(receipt.recipientFingerprint, key) else { return .recipientKeyMismatch }
        guard MeshRoutedManifest.floored(receipt.expiresAt)
                == MeshRoutedManifest.expiry(afterHardDeadline: hardDeadline) else {
            return .expiryMismatch
        }
        guard IdentityService.verify(
            receipt.signature,
            of: canonicalBytes(for: receipt),
            by: key,
            purpose: FernletCryptoPurpose.Signature.meshRecipientReceiptV1
        ) else {
            return .signatureInvalid
        }
        return manifestRejection(for: receipt)
    }

    /// The two cross-checks that need a manifest. Absent one, a well-formed, correctly signed
    /// receipt from an admitted member verifies — its item may simply not have arrived here yet.
    ///
    /// The identity check is the **triple**, spelled out: dropping the origin leg would let an
    /// admitted member claim delivery of origin O's `itemID` under its own key, and every earlier
    /// guard would pass. The destination leg is the one with no custody analogue.
    private func manifestRejection(for receipt: MeshRecipientReceipt) -> MeshRecipientReceiptRejection? {
        guard let manifest else { return nil }
        guard receipt.itemID == manifest.itemID,
              receipt.originFingerprint == manifest.originFingerprint,
              receipt.contentHash == manifest.contentHash else {
            return .manifestMismatch
        }
        guard manifest.destinations.contains(receipt.recipientFingerprint) else {
            return .notADestination
        }
        return nil
    }

    /// The signing key the ledger's admissions bound to `fingerprint`, or nil when it never admitted
    /// that member. Bounded by the admission cap. Departures are deliberately never consulted.
    private func recipientKey(for fingerprint: String) -> Data? {
        ledger.admissions.all.first { $0.memberFingerprint == fingerprint }?.signingPublicKey
    }

    /// Whether `signingPublicKey` really is the key `fingerprint` names.
    private func fingerprintMatches(_ fingerprint: String, _ signingPublicKey: Data) -> Bool {
        IdentityService.fingerprintsMatch(IdentityService.fingerprint(of: signingPublicKey), fingerprint)
    }
}
