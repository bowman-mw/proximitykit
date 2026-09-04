// MeshCustodyReceiptVerifier.swift
// ProximityKit/Mesh
//
// Network migration P5 item 3 (plan §11): the one door a received ``MeshCustodyReceipt`` passes
// through before this device may advance a destination to `custodied(by:)` or store the receipt as
// the evidence behind that rung.
//
// The shape is `MeshRoutedManifestVerifier`'s and `MeshChunkVerifier`'s — mesh, shape, key from the
// ADMISSION ledger, signature — with two deliberate differences. The signing key is resolved by the
// **custodian** fingerprint rather than the origin's, because a receipt is the one routed record its
// subject did not author; and the manifest is OPTIONAL, because a custodian's receipt can reach a
// member that has not yet seen the item's manifest, and every check that does not need one still
// runs.
//
// D14 holds here as it does everywhere else: a **departed** custodian's receipt still verifies —
// leaving is not a retraction, and the bytes it holds do not evaporate — while a **quorum-removed**
// custodian's does not. The key comes from the merged admission ledger by fingerprint, **never**
// from the envelope's sender, which is whoever is forwarding this hop.
//
// Verification needs public material only — signature, the ledger, and the manifest's own fields —
// so it runs on a locked device over ciphertext-only custody (item 1's D9: verify = public, unwrap =
// private). Pure value, no clock: expiry is an EQUALITY against this device's own
// `hardDeadline + grace`, not a liveness read; liveness is `MeshCustodyReceipt.isLive(at:)` with an
// injected `now`, decided by the caller.

import FernletCrypto
import Foundation

// MARK: - MeshCustodyReceiptRejection

/// Why a received ``MeshCustodyReceipt`` was refused. One frozen English token per cause, logged
/// verbatim, never localized; not `Error`, not `LocalizedError` — ``diagnosticDescription`` is the
/// audit surface (the ``MeshChunkRejection`` idiom).
nonisolated enum MeshCustodyReceiptRejection: String, CaseIterable, Equatable, Sendable {
    /// The receipt names a different mesh.
    case foreignMesh
    /// A field has the wrong width, or the custody instant is not before the item's expiry
    /// (``MeshCustodyReceipt/isWellFormed``).
    case malformed
    /// The custodian is the item's own origin. An author holds its own content and issues itself no
    /// receipt; a signed claim otherwise is a confusion of the two roles D11's pair keeps apart.
    case custodianIsOrigin
    /// The admission ledger never admitted the named custodian — there is no key to verify against.
    case custodianNotAdmitted
    /// The mesh removed the named custodian by quorum (plan §10.4). A DEPARTED custodian's receipt
    /// still verifies; removal is the mesh's moderation act and is the one that invalidates.
    case custodianRemoved
    /// The admitted key's fingerprint is not ``MeshCustodyReceipt/custodianFingerprint``.
    case custodianKeyMismatch
    /// ``MeshCustodyReceipt/expiresAt`` is not this device's `hardDeadline + grace` (item 1's D6).
    case expiryMismatch
    /// The custodian's signature did not verify over the re-derived canonical bytes.
    case signatureInvalid
    /// The receipt does not belong to the manifest this verifier holds: its item, its origin or its
    /// content hash differs. **All three legs** — a receipt matching only on `itemID` would be an
    /// admitted member claiming custody of another origin's item under its own valid signature.
    case manifestMismatch

    /// Frozen English for the diagnostic surface. Never shown as user copy.
    var diagnosticDescription: String {
        switch self {
        case .foreignMesh: return "The custody receipt names a different mesh."
        case .malformed: return "A field in the custody receipt was malformed."
        case .custodianIsOrigin: return "The custody receipt's custodian is the item's own origin."
        case .custodianNotAdmitted: return "The custodian was never admitted to this mesh."
        case .custodianRemoved: return "The custodian was removed from this mesh by quorum."
        case .custodianKeyMismatch: return "The custodian's admitted key does not match its fingerprint."
        case .expiryMismatch: return "The receipt's expiry is not this mesh's hard deadline plus grace."
        case .signatureInvalid: return "The custodian's signature did not verify."
        case .manifestMismatch: return "The receipt does not belong to the manifest it was checked against."
        }
    }
}

// MARK: - MeshCustodyReceiptVerifier

/// The one door a received custody receipt passes through before this device records the custody it
/// claims.
///
/// Resolves the custodian's Ed25519 key from the **admission ledger** by the fingerprint the receipt
/// carries — never from the envelope's sender, which is what lets a receipt propagate by re-gossip
/// like every other plan §3.2 union record — and deliberately does NOT require the custodian to be a
/// current roster member (D14).
///
/// Pure value, `nonisolated`, no clock. All four stored properties are values; re-create it when the
/// ledger merges or the manifest arrives.
nonisolated struct MeshCustodyReceiptVerifier: Sendable {
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
    ///   `originFingerprint` and `contentHash`.
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

    /// Checks, in order: mesh → shape → custodian is not the origin → admitted key → custodian not
    /// removed → key/fingerprint agreement → expiry equality → signature → (only with a manifest)
    /// item/origin/content-hash agreement.
    ///
    /// The shape check runs on untrusted bytes before anything expensive; the expiry equality runs
    /// before the signature because it is the cheaper refusal and needs no key.
    ///
    /// - Parameter receipt: The received receipt.
    /// - Returns: the named rejection, or nil when the receipt verified.
    func verify(_ receipt: MeshCustodyReceipt) -> MeshCustodyReceiptRejection? {
        guard receipt.meshID == meshID else { return .foreignMesh }
        guard receipt.isWellFormed else { return .malformed }
        guard receipt.custodianFingerprint != receipt.originFingerprint else {
            return .custodianIsOrigin
        }
        guard let key = custodianKey(for: receipt.custodianFingerprint) else {
            return .custodianNotAdmitted
        }
        guard !ledger.removals.memberFingerprints.contains(receipt.custodianFingerprint) else {
            return .custodianRemoved
        }
        guard fingerprintMatches(receipt.custodianFingerprint, key) else { return .custodianKeyMismatch }
        guard MeshRoutedManifest.floored(receipt.expiresAt)
                == MeshRoutedManifest.expiry(afterHardDeadline: hardDeadline) else {
            return .expiryMismatch
        }
        guard IdentityService.verify(
            receipt.signature,
            of: canonicalBytes(for: receipt),
            by: key,
            purpose: FernletCryptoPurpose.Signature.meshCustodyReceiptV1
        ) else {
            return .signatureInvalid
        }
        return manifestRejection(for: receipt)
    }

    /// The cross-check that needs a manifest. Absent one, a well-formed, correctly signed receipt
    /// from an admitted custodian verifies — its item may simply not have arrived here yet.
    ///
    /// The identity check is the **triple**, spelled out: dropping the origin leg would let an
    /// admitted member claim custody of origin O's `itemID` under its own key, and every earlier
    /// guard would pass.
    private func manifestRejection(for receipt: MeshCustodyReceipt) -> MeshCustodyReceiptRejection? {
        guard let manifest else { return nil }
        guard receipt.itemID == manifest.itemID,
              receipt.originFingerprint == manifest.originFingerprint,
              receipt.contentHash == manifest.contentHash else {
            return .manifestMismatch
        }
        return nil
    }

    /// The signing key the ledger's admissions bound to `fingerprint`, or nil when it never admitted
    /// that member. Bounded by the admission cap. Departures are deliberately never consulted.
    private func custodianKey(for fingerprint: String) -> Data? {
        ledger.admissions.all.first { $0.memberFingerprint == fingerprint }?.signingPublicKey
    }

    /// Whether `signingPublicKey` really is the key `fingerprint` names.
    private func fingerprintMatches(_ fingerprint: String, _ signingPublicKey: Data) -> Bool {
        IdentityService.fingerprintsMatch(IdentityService.fingerprint(of: signingPublicKey), fingerprint)
    }
}
