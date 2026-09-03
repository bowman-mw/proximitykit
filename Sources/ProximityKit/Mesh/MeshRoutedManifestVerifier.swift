// MeshRoutedManifestVerifier.swift
// ProximityKit/Mesh
//
// Network migration P5 item 1 (plan §11): the one door a received routed manifest passes through
// before the routed store may hold it.
//
// The shape is `MeshMembershipRecordVerifier`'s — mesh, shape, key from the ADMISSION ledger,
// signature — with two deliberate differences. A content record does not need a *current* member:
// a departed member's photos stay visible ("leaving is not a retraction", `MeshContentIngest`), so
// the origin is looked up in the admissions and a DEPARTURE never refuses it. A quorum REMOVAL
// does (plan §10.4): removal is the mesh's moderation act, not the member's own choice, and on the
// routed path the content key is wrapped to each recipient's static X25519 key (invariant §3.3),
// so the group-key rotation that excludes a removed member from live control traffic excludes it
// from nothing here — the removal record set is the only door that can. And the door carries the
// set of routed type tokens this build will hold or forward (D13): an unknown type is refused,
// never relayed blind, before item 11's registry exists to say what a token means.
//
// Pure value, no clock: liveness is `MeshRoutedManifest.isLive(at:)` with an injected `now`,
// decided by the caller. Verification needs public material only, so it runs on a locked device
// over ciphertext-only custody (D9); `MeshRoutedContentKeyWrapper.unwrap` is the separate,
// private-key half.

import FernletCrypto
import Foundation

// MARK: - MeshRoutedManifestRejection

/// Why a received ``MeshRoutedManifest`` was refused. One frozen English token per cause, logged
/// verbatim, never localized; not `Error`, not `LocalizedError` — ``diagnosticDescription`` is the
/// audit surface (the `MeshMembershipRecordRejection` idiom).
nonisolated enum MeshRoutedManifestRejection: String, CaseIterable, Equatable, Sendable {
    /// The manifest names a different mesh.
    case foreignMesh
    /// A field has the wrong width or a list the wrong count (``MeshRoutedManifest/isWellFormed``).
    case malformed
    /// `typeToken` is not in the verifier's accepted set (D13). Refused, never forwarded: a custodian
    /// that does not recognise a routed type must not relay it blind (plan §11). Item 11's registry
    /// becomes the set; the case and its position do not move.
    case unknownTypeToken
    /// The admission ledger never admitted the named origin — there is no key to verify against.
    case originNotAdmitted
    /// The mesh removed the named origin by quorum (plan §10.4). A DEPARTED origin's manifest still
    /// verifies — leaving is not a retraction — but removal is the mesh's moderation act, and the
    /// group-key rotation that enforces it on live traffic cannot reach a per-recipient wrap.
    case originRemoved
    /// The admitted key's fingerprint is not ``MeshRoutedManifest/originFingerprint``.
    case originKeyMismatch
    /// The origin's signature did not verify over the re-derived canonical bytes. Every tampered
    /// field lands here, which is the point of signing all of them.
    case signatureInvalid
    /// A wrap's recipient is not the same-index destination. (Signature-valid, so the ORIGIN did this.)
    case wrapsDoNotMatchDestinations
    /// The destination set repeats a member or names the origin.
    case destinationSetInvalid
    /// `expiresAt` is not this device's `hardDeadline + grace` (D6).
    case expiryMismatch

    /// Frozen English for the diagnostic surface. Never shown as user copy.
    var diagnosticDescription: String {
        switch self {
        case .foreignMesh: return "The manifest names a different mesh."
        case .malformed: return "A field in the manifest was malformed."
        case .unknownTypeToken: return "The manifest's routed type token is not accepted by this build."
        case .originNotAdmitted: return "The manifest's origin was never admitted to this mesh."
        case .originRemoved: return "The manifest's origin was removed from this mesh by quorum."
        case .originKeyMismatch: return "The origin's admitted key does not match its fingerprint."
        case .signatureInvalid: return "The origin's signature did not verify."
        case .wrapsDoNotMatchDestinations: return "The key wraps do not line up with the destinations."
        case .destinationSetInvalid: return "The destination set repeats a member or names the origin."
        case .expiryMismatch: return "The manifest's expiry is not this mesh's hard deadline plus grace."
        }
    }
}

// MARK: - MeshRoutedManifestVerifier

/// The one door a received manifest passes through before the routed store may hold it.
///
/// Resolves the origin's Ed25519 key from the **admission ledger** by the fingerprint the
/// manifest carries — never from the envelope's sender, which is what lets a custodian forward
/// the origin's exact bytes — and deliberately does NOT require the origin to be a current roster
/// member: a **departed** member's content stays valid (leaving is not a retraction); membership
/// and blocks are ingestion-time view filters. A **removed** member's does not
/// (``MeshRoutedManifestRejection/originRemoved``): the door consults the ledger's removal record
/// set — the same set ``MeshDerivedRoster`` subtracts — because a quorum removal is the mesh's
/// moderation act, and the routed path's per-recipient static-key wraps are untouched by the
/// group-key rotation that enforces removal on live control traffic. Departures are still never
/// consulted. Verification needs public material only, so it runs on a locked device over
/// ciphertext-only custody (D9). Pure value, `nonisolated`, no clock: liveness is
/// ``MeshRoutedManifest/isLive(at:)`` with an injected `now`, decided by the caller.
nonisolated struct MeshRoutedManifestVerifier: Sendable {
    /// The session this device is in.
    let meshID: UUID
    /// The session's signed ceiling, from `MeshSessionContext.hardDeadline`.
    let hardDeadline: Date
    /// The merged membership ledger whose admissions bind fingerprints to signing keys.
    let ledger: MeshMembershipLedger
    /// The routed-type tokens this build will hold or forward (D13). Item 1's callers pass a
    /// fixture set; item 11 passes the registry's. Empty means "accept nothing", which is the
    /// correct answer for a door nobody has configured.
    let acceptedTypeTokens: Set<String>

    /// Binds the verifier to one session. All four are values; re-create it when the ledger merges.
    init(meshID: UUID, hardDeadline: Date, ledger: MeshMembershipLedger, acceptedTypeTokens: Set<String>) {
        self.meshID = meshID
        self.hardDeadline = hardDeadline
        self.ledger = ledger
        self.acceptedTypeTokens = acceptedTypeTokens
    }

    /// Checks, in order: mesh → shape → type token accepted → admitted key → origin not removed →
    /// key/fingerprint agreement → signature → wrap/destination alignment → distinct set without
    /// the origin → expiry equality. Destinations are NOT looked up in the ledger (D12), and
    /// departures are never consulted.
    /// - Returns: the named rejection, or nil when the manifest verified.
    func verify(_ manifest: MeshRoutedManifest) -> MeshRoutedManifestRejection? {
        guard manifest.meshID == meshID else { return .foreignMesh }
        guard manifest.isWellFormed else { return .malformed }
        guard acceptedTypeTokens.contains(manifest.typeToken) else { return .unknownTypeToken }
        guard let key = admittedSigningKey(for: manifest.originFingerprint) else { return .originNotAdmitted }
        guard !ledger.removals.memberFingerprints.contains(manifest.originFingerprint) else {
            return .originRemoved
        }
        guard fingerprintMatches(manifest.originFingerprint, key) else { return .originKeyMismatch }
        guard IdentityService.verify(
            manifest.signature,
            of: canonicalBytes(for: manifest),
            by: key,
            purpose: FernletCryptoPurpose.Signature.meshRoutedManifestV1
        ) else {
            return .signatureInvalid
        }
        return structuralRejection(of: manifest)
    }

    /// The three cross-field checks that run only AFTER the signature verified — so each one is a
    /// statement about what the origin signed, never about what a relay changed.
    private func structuralRejection(of manifest: MeshRoutedManifest) -> MeshRoutedManifestRejection? {
        guard manifest.keyWraps.map(\.recipientFingerprint) == manifest.destinations else {
            return .wrapsDoNotMatchDestinations
        }
        guard Set(manifest.destinations).count == manifest.destinations.count,
              !manifest.destinations.contains(manifest.originFingerprint) else {
            return .destinationSetInvalid
        }
        guard MeshRoutedManifest.floored(manifest.expiresAt)
                == MeshRoutedManifest.expiry(afterHardDeadline: hardDeadline) else {
            return .expiryMismatch
        }
        return nil
    }

    /// The signing key the ledger's admissions bound to `fingerprint`, or nil when it never
    /// admitted that member. Bounded by the admission cap (16). The same one line
    /// `MeshMembershipRecordVerifier` keeps private.
    private func admittedSigningKey(for fingerprint: String) -> Data? {
        ledger.admissions.all.first { $0.memberFingerprint == fingerprint }?.signingPublicKey
    }

    /// Whether `signingPublicKey` really is the key `fingerprint` names.
    private func fingerprintMatches(_ fingerprint: String, _ signingPublicKey: Data) -> Bool {
        IdentityService.fingerprintsMatch(IdentityService.fingerprint(of: signingPublicKey), fingerprint)
    }
}
