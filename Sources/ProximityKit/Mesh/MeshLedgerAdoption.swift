// MeshLedgerAdoption.swift
// ProximityKit/Mesh
//
// P3 item 7 (plan §8.3, §10.5, §20.4.4): how a device that JOINED a mesh comes to hold a ledger.
//
// Item 3 left the hole this file fills, and named it: "joiners never adopt a ledger, so every
// received event on a joiner is refused `signerNotAdmitted` (fail-closed)". The founder's ledger
// bootstraps from its own signing key — `MeshMembershipRecordVerifier.founderSigningPublicKey` —
// but a joiner does not know the founder's key. It knows exactly one thing: the admission token
// the admitter signed for it, which its transport-authenticated peer handed over and which it has
// already verified.
//
// So adoption is two steps, and both are pure functions of values:
//
//   1. **Bootstrap.** Arm a verifier whose root is the ADMITTER's key and file this device's own
//      admission record. The roster is one member — this device — which is enough to be a member
//      of its own ledger, sign records, and ask a peer for theirs.
//   2. **Adopt.** A peer's ledger arrives. Re-verify it from ITS OWN root and accept that root as
//      the founder only if the resulting roster admits *this device's admitter*, bound to exactly
//      the key this device's token names. That is the chain plan §8.3 describes — "an admission
//      signed by an admitted member is valid" — checked end to end rather than assumed: root
//      admitted … admitted my admitter, and my admitter admitted me.
//
// Nothing here reads a clock, a store or a transport, so the whole joiner story is tier 1.

import Foundation

// MARK: - MeshLedgerAdoptionRefusal

/// Why a joiner refused to adopt a ledger a peer offered it.
///
/// Named rather than boolean for ``MeshMembershipRecordRejection``'s reason: "the offered ledger is
/// rooted in somebody who never admitted themself" and "the offered ledger does not know the peer
/// that admitted me" are two completely different situations, and one of them is an attack.
///
/// Frozen English in ``diagnosticDescription``, read by a developer in a log and never shown to a
/// person, so it stays out of the localization catalogs by construction.
nonisolated enum MeshLedgerAdoptionRefusal: Equatable, Sendable {

    /// The offered ledger, or this device's own admission, names a different mesh.
    case foreignMesh

    /// The offered ledger holds no admissions at all, so it has no root to chain from.
    case rootMissing

    /// The offered ledger's earliest admission is not a self-admission, so nothing in it can stand
    /// as the founder: every other record needs an already-admitted admitter.
    case rootNotSelfAdmitted

    /// The verified ledger does not admit the member that admitted THIS device — or admits it under
    /// a different signing key. The chain from the offered root to this device is broken, and a
    /// broken chain is a ledger from some other mesh's history or a forged one.
    case admitterNotChained

    /// This device's own admission record was refused by a verifier rooted at the offered founder.
    case ownAdmissionRefused(MeshMembershipRecordRejection)

    /// Frozen English for the diagnostic surface. Never user copy.
    var diagnosticDescription: String {
        switch self {
        case .foreignMesh: return "The offered ledger names a different mesh."
        case .rootMissing: return "The offered ledger holds no admission to root a roster in."
        case .rootNotSelfAdmitted: return "The offered ledger's earliest admission is not self-signed."
        case .admitterNotChained: return "The offered ledger does not admit the member that admitted this device."
        case .ownAdmissionRefused(let rejection):
            return "This device's own admission was refused: \(rejection.diagnosticDescription)"
        }
    }
}

// MARK: - MeshLedgerAdoptionOutcome

/// What an adoption attempt concluded.
///
/// A hand-rolled two-case enum rather than `Result`, for the reason ``MeshMembershipRecordRejection``
/// is not an `Error` either: `Result` would force the refusal to conform to `Error`, and an `Error`
/// in this codebase is one step from a `LocalizedError` whose message the localization wall then
/// expects to translate. These refusals are frozen English read by a developer in a log, never user
/// copy, so they stay out of that machinery by construction.
nonisolated enum MeshLedgerAdoptionOutcome {

    /// The offered ledger chained to this device and is now the verified one.
    case adopted(MeshMembershipRecordVerifier)

    /// The offered ledger was refused; the caller keeps the ledger it had.
    case refused(MeshLedgerAdoptionRefusal)
}

// MARK: - MeshLedgerAdoption

/// The joiner's half of membership: bootstrap a ledger from an admission, then converge on the
/// mesh's real one.
///
/// **Why a joiner may not simply merge.** ``MeshMembershipRecordVerifier`` looks every signing key
/// up in its own admission set and bootstraps exactly one record from
/// ``MeshMembershipRecordVerifier/founderSigningPublicKey``. A joiner armed with its admitter's key
/// as the root therefore refuses the *founder's* self-admission when it later arrives
/// (`unauthorizedAdmitter`) — the two ledgers would never converge, and every subsequent record
/// from the rest of the mesh would be refused with it. ``adopt(offered:ownAdmission:meshID:)`` is
/// the answer: it does not merge into the bootstrap ledger, it **rebases** onto the offered one and
/// re-files this device's own record there.
///
/// **What makes a rebase safe.** Adopting a root means believing a stranger's claim about who
/// founded the mesh, so the claim is checked against the one fact this device authenticated for
/// itself — the admission token its transport-verified peer signed. The offered ledger must, after
/// full record-by-record verification from its own root, admit that peer under that exact key. A
/// forged ledger cannot satisfy it without forging an admission chain that ends in a signature the
/// admitter made, which is the same bar every other record clears.
///
/// **It is only ever done once.** ``isBootstrap(_:selfFingerprint:)`` is the guard: a device whose
/// ledger has grown past its own single admission has already converged and rebasing it would
/// discard verified records. From then on a peer's ledger arrives through
/// ``MeshMembershipRecordVerifier/merge(_:)`` like everybody else's.
nonisolated enum MeshLedgerAdoption {

    /// Whether `ledger` is still the one-record bootstrap a joiner starts from, and therefore may
    /// be rebased onto a peer's ledger.
    ///
    /// A founder's ledger is also one admission long — but that admission is its own, self-signed,
    /// so `authorFingerprint == selfFingerprint` and the founder never rebases. That is the whole
    /// difference between the two, and it is a property of the record rather than of a flag some
    /// path could forget to set.
    ///
    /// - Parameters:
    ///   - ledger: The device's current ledger.
    ///   - selfFingerprint: This device's identity fingerprint.
    /// - Returns: `true` when the ledger holds exactly this device's own admission, signed by
    ///   somebody else.
    static func isBootstrap(_ ledger: MeshMembershipLedger, selfFingerprint: String) -> Bool {
        guard ledger.admissions.count == 1,
              ledger.departures.isEmpty, ledger.removals.isEmpty, ledger.terminations.isEmpty,
              let only = ledger.admissions.earliest else {
            return false
        }
        return only.memberFingerprint == selfFingerprint && only.authorFingerprint != selfFingerprint
    }

    /// Step 1: the verifier a joiner arms itself with the moment its admission verifies.
    ///
    /// The root is the ADMITTER's key, not the founder's, because the admitter's key is the one
    /// this device authenticated (the grant is refused unless the token's admitter root equals the
    /// envelope's authenticated sender — `admissionGrantIsAuthorized`). It is a deliberately
    /// provisional root: it makes this device a member of its own ledger so it can sign and file
    /// records at once, and ``adopt(offered:ownAdmission:meshID:)`` replaces it with the real one.
    ///
    /// - Parameters:
    ///   - meshID: The mesh being joined.
    ///   - ownAdmission: This device's verified admission record.
    /// - Returns: The armed verifier, or the named refusal.
    static func bootstrapVerifier(
        meshID: UUID,
        ownAdmission: SignedAdmissionRecord
    ) -> MeshLedgerAdoptionOutcome {
        guard ownAdmission.meshID == meshID else { return .refused(.foreignMesh) }
        var verifier = MeshMembershipRecordVerifier(
            meshID: meshID,
            founderSigningPublicKey: ownAdmission.token.admitterSigningPublicKey
        )
        if let rejection = verifier.insert(ownAdmission) {
            return .refused(.ownAdmissionRefused(rejection))
        }
        return .adopted(verifier)
    }

    /// Step 2: rebase onto a peer's ledger, adopting its root as the founder once the chain to this
    /// device is proven.
    ///
    /// - Parameters:
    ///   - offered: The peer's ledger, entirely untrusted.
    ///   - ownAdmission: This device's own verified admission record, re-filed into the result.
    ///   - meshID: The mesh both must name.
    /// - Returns: A verifier rooted at the offered ledger's founder and holding every record of it
    ///   that verified, plus this device's own admission — or the named refusal, in which case the
    ///   caller keeps the ledger it had.
    static func adopt(
        offered: MeshMembershipLedger,
        ownAdmission: SignedAdmissionRecord,
        meshID: UUID
    ) -> MeshLedgerAdoptionOutcome {
        guard ownAdmission.meshID == meshID else { return .refused(.foreignMesh) }
        guard let root = offered.admissions.earliest else { return .refused(.rootMissing) }
        guard root.meshID == meshID else { return .refused(.foreignMesh) }
        guard root.token.admitterFingerprint == root.token.joinerFingerprint else {
            return .refused(.rootNotSelfAdmitted)
        }
        var verifier = MeshMembershipRecordVerifier(
            meshID: meshID,
            founderSigningPublicKey: root.token.admitterSigningPublicKey
        )
        verifier.merge(offered)
        guard chains(verifier.roster, to: ownAdmission) else { return .refused(.admitterNotChained) }
        if let rejection = verifier.insert(ownAdmission) {
            return .refused(.ownAdmissionRefused(rejection))
        }
        return .adopted(verifier)
    }

    /// Whether `roster` admits this device's admitter under exactly the key its token names.
    ///
    /// Both halves matter. The fingerprint alone would let a ledger that admitted *some* member
    /// with a colliding fingerprint stand in for the admitter; the key alone would ignore which
    /// member it belongs to. Together they say: the peer that signed my admission is, in this
    /// ledger's own history, a member entitled to have signed it.
    private static func chains(
        _ roster: MeshDerivedRoster,
        to ownAdmission: SignedAdmissionRecord
    ) -> Bool {
        roster.members.contains {
            $0.fingerprint == ownAdmission.token.admitterFingerprint
                && $0.signingPublicKey == ownAdmission.token.admitterSigningPublicKey
        }
    }
}
