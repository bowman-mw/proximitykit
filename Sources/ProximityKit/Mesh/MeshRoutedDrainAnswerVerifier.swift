// MeshRoutedDrainAnswerVerifier.swift
// ProximityKit/Mesh
//
// Network migration P5 item 6 (plan §11, §10.3): the one door a received drain answer passes through
// before its quiescence bit may be recorded.
//
// The shape is `MeshRoutedInventoryVerifier`'s — mesh, shape, key from the ADMISSION ledger,
// removal, key/fingerprint agreement, signature — with the routed family's D14 rule intact: a
// **departed** answerer still verifies (it may still hold custody inside the development grace, so
// its "I have nothing left for you" is still worth hearing), while a **quorum-removed** one is
// refused. Departures are never consulted; the removal record set is the only door.
//
// The two BINDING checks — "this answers an advertisement of mine" and "of that exact
// advertisement" — deliberately live at the manager, not here: they compare against per-peer session
// state this pure value has no access to and no business holding. This verifier answers "is this a
// genuine frame from an admitted member", the manager answers "is it an answer to something I
// actually said".
//
// Public material only, so it verifies on a locked device. Pure value, no clock: `sentAt` is
// **bound** into the signature, not checked against a wall clock, exactly as the two digests are.

import FernletCrypto
import Foundation

// MARK: - MeshRoutedDrainAnswerRejection

/// Why a received ``MeshRoutedDrainAnswerPayload`` was refused. One frozen English token per cause,
/// logged verbatim, never localized; not `Error`, not `LocalizedError` — ``diagnosticDescription``
/// is the audit surface (the `MeshRoutedInventoryRejection` idiom).
///
/// **A verified answer carrying `quiescent: false` is not a rejection** — that is the ordinary
/// answer while a transfer is still in flight.
nonisolated enum MeshRoutedDrainAnswerRejection: String, CaseIterable, Equatable, Sendable {
    /// The answer names a different mesh. A refusal, not a difference.
    case foreignMesh
    /// A payload scalar is the wrong width, empty, over its cap, or not a finite instant.
    case malformed
    /// The admission ledger never admitted the answerer — there is no key to verify against.
    case senderNotAdmitted
    /// The mesh removed the answerer by quorum (plan §10.4). A DEPARTED answerer still verifies: it
    /// may still be holding custody inside the development grace.
    case senderRemoved
    /// The admitted key's fingerprint is not ``MeshRoutedDrainAnswerPayload/senderFingerprint``.
    case senderKeyMismatch
    /// The answerer's signature did not verify over the re-derived canonical bytes. Every tampered
    /// field lands here, which is the point of signing all of them.
    case signatureInvalid

    /// Frozen English for the diagnostic surface. Never shown as user copy.
    var diagnosticDescription: String {
        switch self {
        case .foreignMesh: return "The routed drain answer names a different mesh."
        case .malformed: return "The routed drain answer is not a canonical frame."
        case .senderNotAdmitted: return "The answer's sender was never admitted to this mesh."
        case .senderRemoved: return "The answer's sender was removed from this mesh by quorum."
        case .senderKeyMismatch: return "The answerer's admitted key does not match its fingerprint."
        case .signatureInvalid: return "The answerer's signature did not verify."
        }
    }
}

// MARK: - MeshRoutedDrainAnswerVerifier

/// The one door a received drain answer passes through.
///
/// Resolves the answerer's Ed25519 key from the **admission ledger** by the fingerprint the payload
/// itself carries — never from the envelope's sender — and checks the cheap, untrusted-byte
/// properties first, so a malformed answer costs no ledger lookup and no signature verification.
///
/// Pure value, `nonisolated`, no clock. Re-create it when the ledger merges.
nonisolated struct MeshRoutedDrainAnswerVerifier: Sendable {
    /// The session this device is in.
    let meshID: UUID
    /// The merged membership ledger whose admissions bind fingerprints to signing keys.
    let ledger: MeshMembershipLedger

    /// Binds the verifier to one session. Both are values.
    init(meshID: UUID, ledger: MeshMembershipLedger) {
        self.meshID = meshID
        self.ledger = ledger
    }

    /// Checks, in order: mesh → shape → admitted key → answerer not removed → key/fingerprint
    /// agreement → signature.
    /// - Returns: the named rejection, or nil when the answer verified.
    func verify(_ payload: MeshRoutedDrainAnswerPayload) -> MeshRoutedDrainAnswerRejection? {
        guard payload.answer.meshID == meshID else { return .foreignMesh }
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
            purpose: FernletCryptoPurpose.Signature.meshRoutedDrainAnswerV1
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
