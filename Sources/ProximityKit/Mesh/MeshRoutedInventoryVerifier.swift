// MeshRoutedInventoryVerifier.swift
// ProximityKit/Mesh
//
// Network migration P5 item 5 (plan §11, §10.3): the one door a received routed-inventory digest
// passes through before its holdings may be compared against this device's.
//
// The shape is `MeshRoutedManifestVerifier`'s — mesh, caps, shape, key from the ADMISSION ledger,
// removal, key/fingerprint agreement, signature — with the routed family's D14 rule intact: a
// **departed** advertiser's digest still verifies (it may still hold custody inside the development
// grace, which is what makes a hand-off usable), while a **quorum-removed** one is refused.
// Departures are never consulted; the removal record set is the only door.
//
// Its own file and its own rejection enum, deliberately: it must not land on
// `MeshMembershipRecordVerifier` and must not reuse `MeshMembershipRecordRejection`, because the two
// digests are structurally different records that happen to share an English word.
//
// Public material only, so it verifies on a locked device over ciphertext-only custody (D9). Pure
// value, no clock: there is no freshness check on `sentAt` — it is **bound** into the signature, not
// checked against a wall clock, exactly as the membership digest's is.

import FernletCrypto
import Foundation

// MARK: - MeshRoutedInventoryRejection

/// Why a received ``MeshRoutedInventoryPayload`` was refused. One frozen English token per cause,
/// logged verbatim, never localized; not `Error`, not `LocalizedError` — ``diagnosticDescription``
/// is the audit surface (the `MeshRoutedManifestRejection` idiom).
///
/// **A verified digest that DIFFERS is not a rejection — that is the whole point of sending one.**
nonisolated enum MeshRoutedInventoryRejection: String, CaseIterable, Equatable, Sendable {
    /// The digest names a different mesh. A refusal, not a difference.
    case foreignMesh
    /// A bounded collection is over its cap. Refused **by name**, never clamped: clamping a list
    /// silently claims not to hold something.
    case overCapacity
    /// The value is not a canonical encoding of a holdings set — an unsorted or non-minimal member
    /// table, an out-of-range or unsorted signer index, a non-canonical held-chunk bitmap,
    /// mis-ordered entries, or a payload scalar of the wrong width.
    case malformed
    /// The admission ledger never admitted the advertiser — there is no key to verify against.
    case senderNotAdmitted
    /// The mesh removed the advertiser by quorum (plan §10.4). A DEPARTED advertiser's digest still
    /// verifies: it may still be holding custody inside the development grace.
    case senderRemoved
    /// The admitted key's fingerprint is not ``MeshRoutedInventoryPayload/senderFingerprint``.
    case senderKeyMismatch
    /// The advertiser's signature did not verify over the re-derived canonical bytes. Every tampered
    /// field lands here, which is the point of signing all of them.
    case signatureInvalid

    /// Frozen English for the diagnostic surface. Never shown as user copy.
    var diagnosticDescription: String {
        switch self {
        case .foreignMesh: return "The routed inventory digest names a different mesh."
        case .overCapacity: return "The routed inventory digest is over one of its caps."
        case .malformed: return "The routed inventory digest is not a canonical holdings set."
        case .senderNotAdmitted: return "The digest's advertiser was never admitted to this mesh."
        case .senderRemoved: return "The digest's advertiser was removed from this mesh by quorum."
        case .senderKeyMismatch: return "The advertiser's admitted key does not match its fingerprint."
        case .signatureInvalid: return "The advertiser's signature did not verify."
        }
    }
}

// MARK: - MeshRoutedInventoryVerifier

/// The one door a received routed-inventory digest passes through.
///
/// Resolves the advertiser's Ed25519 key from the **admission ledger** by the fingerprint the
/// payload itself carries — never from the envelope's sender — and checks the cheap, untrusted-byte
/// properties first, so an over-cap or malformed digest costs no ledger lookup and no signature
/// verification. The shape step reads the **payload's** `isWellFormed`, not the inventory's, which
/// is what makes ``MeshRoutedInventoryFormat/signatureByteCount`` enforced rather than merely
/// declared.
///
/// Pure value, `nonisolated`, no clock. Re-create it when the ledger merges.
nonisolated struct MeshRoutedInventoryVerifier: Sendable {
    /// The session this device is in.
    let meshID: UUID
    /// The merged membership ledger whose admissions bind fingerprints to signing keys.
    let ledger: MeshMembershipLedger

    /// Binds the verifier to one session. Both are values.
    init(meshID: UUID, ledger: MeshMembershipLedger) {
        self.meshID = meshID
        self.ledger = ledger
    }

    /// Checks, in order: mesh → caps → shape → admitted key → advertiser not removed →
    /// key/fingerprint agreement → signature.
    /// - Returns: the named rejection, or nil when the digest verified.
    func verify(_ payload: MeshRoutedInventoryPayload) -> MeshRoutedInventoryRejection? {
        guard payload.inventory.meshID == meshID else { return .foreignMesh }
        guard payload.isWithinCaps else { return .overCapacity }
        guard payload.isWellFormed else { return .malformed }
        guard let key = admittedSigningKey(for: payload.senderFingerprint) else {
            return .senderNotAdmitted
        }
        guard !ledger.removals.memberFingerprints.contains(payload.senderFingerprint) else {
            return .senderRemoved
        }
        guard fingerprintMatches(payload.senderFingerprint, key) else { return .senderKeyMismatch }
        guard IdentityService.verify(
            payload.signature,
            of: canonicalBytes(for: payload),
            by: key,
            purpose: FernletCryptoPurpose.Signature.meshRoutedInventoryDigestV1
        ) else {
            return .signatureInvalid
        }
        return nil
    }

    /// The signing key the ledger's admissions bound to `fingerprint`, or nil when it never admitted
    /// that member. Bounded by the admission cap (16).
    private func admittedSigningKey(for fingerprint: String) -> Data? {
        ledger.admissions.all.first { $0.memberFingerprint == fingerprint }?.signingPublicKey
    }

    /// Whether `signingPublicKey` really is the key `fingerprint` names.
    private func fingerprintMatches(_ fingerprint: String, _ signingPublicKey: Data) -> Bool {
        IdentityService.fingerprintsMatch(IdentityService.fingerprint(of: signingPublicKey), fingerprint)
    }
}
