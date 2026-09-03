// MeshChunkVerifier.swift
// ProximityKit/Mesh
//
// Network migration P5 item 2 (plan §11): the one door a received routed chunk passes through
// before the routed store may hold its bytes.
//
// The shape is `MeshRoutedManifestVerifier`'s — mesh, shape, key from the ADMISSION ledger,
// signature — with three deliberate differences. There is no type token on a chunk, because the
// type gate happened at the manifest (one registry, not two). The chunk hash is checked AFTER the
// signature, so the verdict is a statement about what the origin signed. And the manifest is
// OPTIONAL: chunks ride per-transfer streams that are not ordered against the control stream
// carrying the manifest, so a chunk that arrives first is verified and parked, and the
// manifest-dependent guards run once one is known.
//
// Verification needs public material only — signature, SHA-256 and the ledger, never a content
// key — which is what lets item 10's ciphertext-only custody verify on a locked device. That is
// item 1's D9 split (verify = public, unwrap = private) carried forward unchanged.
//
// Pure value, no clock: expiry is an EQUALITY against this device's own `hardDeadline + grace`,
// not a liveness read; liveness is `MeshChunk.isLive(at:)` with an injected `now`, decided by the
// caller.

import FernletCrypto
import Foundation

// MARK: - MeshChunkRejection

/// Why a received ``MeshChunk`` was refused. One frozen English token per cause, logged verbatim,
/// never localized; not `Error`, not `LocalizedError` — ``diagnosticDescription`` is the audit
/// surface (the ``MeshRoutedManifestRejection`` idiom).
nonisolated enum MeshChunkRejection: String, CaseIterable, Equatable, Sendable {
    /// The chunk names a different mesh.
    case foreignMesh
    /// A field has the wrong width or a count is out of bounds (``MeshChunk/isWellFormed``).
    case malformed
    /// The admission ledger never admitted the named origin — there is no key to verify against.
    case originNotAdmitted
    /// The mesh removed the named origin by quorum (plan §10.4). A DEPARTED origin's chunk still
    /// verifies — leaving is not a retraction — but removal is the mesh's moderation act, and the
    /// group-key rotation that enforces it on live traffic cannot reach a per-recipient wrap.
    case originRemoved
    /// The admitted key's fingerprint is not ``MeshChunk/originFingerprint``.
    case originKeyMismatch
    /// The origin's signature did not verify over the re-derived canonical bytes.
    case signatureInvalid
    /// ``MeshChunk/chunkHash`` does not cover ``MeshChunk/payload``. Checked AFTER the signature,
    /// so it names a payload that was swapped under an otherwise authentic chunk — which is
    /// exactly why the hash is in the signed transcript and the payload is not.
    case chunkHashMismatch
    /// ``MeshChunk/expiresAt`` is not this device's `hardDeadline + grace` (item 1's D6).
    case expiryMismatch
    /// The chunk does not belong to the manifest this verifier holds: its item, its origin or its
    /// content hash differs. **All three legs** — a chunk matching only on `itemID` would be an
    /// admitted member squatting another origin's id under its own valid signature.
    case manifestMismatch
    /// ``MeshChunk/chunkCount`` is not `ceil(manifest.size / 256 KiB)`.
    case chunkCountMismatch
    /// The payload is not the length the manifest's `size` fixes for this index — a long or short
    /// **interior** chunk is a named refusal, never a silent truncation.
    case payloadLengthMismatch

    /// Frozen English for the diagnostic surface. Never shown as user copy.
    var diagnosticDescription: String {
        switch self {
        case .foreignMesh: return "The chunk names a different mesh."
        case .malformed: return "A field in the chunk was malformed."
        case .originNotAdmitted: return "The chunk's origin was never admitted to this mesh."
        case .originRemoved: return "The chunk's origin was removed from this mesh by quorum."
        case .originKeyMismatch: return "The origin's admitted key does not match its fingerprint."
        case .signatureInvalid: return "The origin's signature did not verify."
        case .chunkHashMismatch: return "The chunk hash does not cover the chunk's payload."
        case .expiryMismatch: return "The chunk's expiry is not this mesh's hard deadline plus grace."
        case .manifestMismatch: return "The chunk does not belong to the manifest it was checked against."
        case .chunkCountMismatch: return "The chunk count disagrees with the manifest's size."
        case .payloadLengthMismatch: return "The chunk's payload is not the length its index requires."
        }
    }
}

// MARK: - MeshChunkVerifier

/// The one door a received chunk passes through before the routed store may hold its bytes.
///
/// Resolves the origin's Ed25519 key from the **admission ledger** by the fingerprint the chunk
/// carries — never from the envelope's sender, which is what lets a custodian forward the origin's
/// exact bytes — and deliberately does NOT require the origin to be a current roster member: a
/// **departed** member's content stays valid. A **removed** member's does not
/// (``MeshChunkRejection/originRemoved``). Departures are never consulted.
///
/// Verification needs public material only, so it runs on a locked device over ciphertext-only
/// custody (item 1's D9). Pure value, `nonisolated`, no clock.
nonisolated struct MeshChunkVerifier: Sendable {
    /// The session this device is in.
    let meshID: UUID
    /// The session's signed ceiling, from `MeshSessionContext.hardDeadline`.
    let hardDeadline: Date
    /// The merged membership ledger whose admissions bind fingerprints to signing keys.
    let ledger: MeshMembershipLedger
    /// The item's manifest, when one has arrived — nil is the **parked** case, not a way to skip a
    /// check.
    ///
    /// - Important: a non-nil manifest must be one ``MeshRoutedManifestVerifier/verify(_:)`` has
    ///   already accepted (returned nil) — this type never re-verifies it, and it is the only
    ///   authority on `itemID`, `originFingerprint`, `contentHash`, `size` and the derived chunk
    ///   count. `MeshRoutedManifestVerifier` is the only thing in the tree that checks a manifest's
    ///   origin signature; without this precondition the manifest guards compare a chunk against an
    ///   unauthenticated claim, and a nil verdict stops being an origin-authenticity statement
    ///   about the *item*.
    let manifest: MeshRoutedManifest?

    /// Binds the verifier to one session, optionally to one already-verified manifest. All four
    /// are values; re-create it when the ledger merges or the manifest arrives.
    ///
    /// - Parameters:
    ///   - meshID: The session's mesh id.
    ///   - hardDeadline: The session's signed ceiling.
    ///   - ledger: The merged membership ledger.
    ///   - manifest: An already-verified manifest, or nil for the parked case. See the
    ///     ``manifest`` precondition — this type never re-verifies it.
    init(meshID: UUID, hardDeadline: Date, ledger: MeshMembershipLedger, manifest: MeshRoutedManifest?) {
        self.meshID = meshID
        self.hardDeadline = hardDeadline
        self.ledger = ledger
        self.manifest = manifest
    }

    /// Checks, in order: mesh → shape → admitted key → origin not removed → key/fingerprint
    /// agreement → signature → chunk hash covers the payload → expiry equality → (only with a
    /// manifest) item/origin/content-hash agreement → chunk count → payload length.
    ///
    /// The shape check runs on untrusted bytes before the signature; the chunk hash runs *after*
    /// it, so a hash mismatch names a payload swapped under an authentic chunk.
    /// - Returns: the named rejection, or nil when the chunk verified.
    func verify(_ chunk: MeshChunk) -> MeshChunkRejection? {
        guard chunk.meshID == meshID else { return .foreignMesh }
        guard chunk.isWellFormed else { return .malformed }
        guard let key = admittedSigningKey(for: chunk.originFingerprint) else { return .originNotAdmitted }
        guard !ledger.removals.memberFingerprints.contains(chunk.originFingerprint) else {
            return .originRemoved
        }
        guard fingerprintMatches(chunk.originFingerprint, key) else { return .originKeyMismatch }
        guard IdentityService.verify(
            chunk.signature,
            of: canonicalBytes(for: chunk),
            by: key,
            purpose: FernletCryptoPurpose.Signature.meshRoutedChunkV1
        ) else {
            return .signatureInvalid
        }
        guard MeshRoutedContentDigest.chunkHash(of: chunk.payload) == chunk.chunkHash else {
            return .chunkHashMismatch
        }
        guard MeshRoutedManifest.floored(chunk.expiresAt)
                == MeshRoutedManifest.expiry(afterHardDeadline: hardDeadline) else {
            return .expiryMismatch
        }
        return manifestRejection(for: chunk)
    }

    /// The three cross-checks that need a manifest. Absent one, a well-formed, correctly signed
    /// chunk is verified and parked (its item may simply not have arrived yet).
    ///
    /// The identity check is the **triple**, spelled out: dropping the origin leg would let an
    /// admitted member A mint a well-formed, correctly-hashed, correctly-signed chunk reusing
    /// origin O's `itemID` and `contentHash`, and every earlier guard would pass on A's own key.
    private func manifestRejection(for chunk: MeshChunk) -> MeshChunkRejection? {
        guard let manifest else { return nil }
        guard chunk.itemID == manifest.itemID,
              chunk.originFingerprint == manifest.originFingerprint,
              chunk.contentHash == manifest.contentHash else {
            return .manifestMismatch
        }
        guard let derived = MeshChunkFormat.chunkCount(forSize: manifest.size),
              Int(chunk.chunkCount) == derived else {
            return .chunkCountMismatch
        }
        guard let expected = MeshChunk.expectedPayloadByteCount(
            index: chunk.chunkIndex, count: chunk.chunkCount, size: manifest.size
        ), chunk.payload.count == expected else {
            return .payloadLengthMismatch
        }
        return nil
    }

    /// The signing key the ledger's admissions bound to `fingerprint`, or nil when it never
    /// admitted that member. Bounded by the admission cap. The same one line
    /// ``MeshRoutedManifestVerifier`` keeps private.
    private func admittedSigningKey(for fingerprint: String) -> Data? {
        ledger.admissions.all.first { $0.memberFingerprint == fingerprint }?.signingPublicKey
    }

    /// Whether `signingPublicKey` really is the key `fingerprint` names.
    private func fingerprintMatches(_ fingerprint: String, _ signingPublicKey: Data) -> Bool {
        IdentityService.fingerprintsMatch(IdentityService.fingerprint(of: signingPublicKey), fingerprint)
    }
}
