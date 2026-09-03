// MeshMembershipRecordVerifier.swift
// ProximityKit/Mesh
//
// P3 item 3 (plan §8.3, §10.4): the verify-then-insert seam.
//
// Item 1 left this hole open on purpose. `MeshMembershipRecordSet` is pure algebra — it will merge
// whatever it is handed — and its doc comment says so: "a record in a set is not a VERIFIED
// record". That is fine for a value type and fatal for a roster, because the sets are capped at
// sixteen and keep the EARLIEST records: a peer that can insert unverified junk with low
// timestamps does not merely add noise, it crowds a real removal out of the set on every device it
// reaches. So nothing that derives a roster may insert without coming through here.
//
// Everything below is a pure function of (ledger, record) plus Ed25519 verification — no clock, no
// store, no transport. `expiresAt` is deliberately NOT re-applied to admission records: the token's
// expiry is an admission-time freshness check, and a durable record is hours old by design.

import FernletCrypto
import Foundation

// MARK: - MeshMembershipRecordRejection

/// Why one membership record was refused before it could reach a ledger.
///
/// Every refusal names itself rather than collapsing into `false`, for the same reason
/// ``MeshIntroductionRejection`` does: "a record from another mesh", "a record signed by a
/// stranger" and "a removal three votes short" are three completely different situations, and a
/// bare boolean is exactly how they become one indistinguishable "membership didn't update".
///
/// Not an `Error` and not `LocalizedError`: ``diagnosticDescription`` is frozen English read by a
/// developer in a log, never user copy, so it stays out of the localization catalogs by
/// construction.
nonisolated enum MeshMembershipRecordRejection: Equatable, Sendable {
    /// The record names a different mesh.
    case foreignMesh
    /// A field does not have the width the format fixes.
    case malformedRecord
    /// The record is about, or signed by, a fingerprint this ledger has no admission for — so
    /// there is no key to check the signature against.
    case signerNotAdmitted
    /// The signer is admitted but no longer on the derived roster (departed, removed, or the mesh
    /// is over), so it may not author new membership facts.
    case signerNotAMember
    /// The admitter is neither a current member nor the founder, so it was not entitled to admit.
    case unauthorizedAdmitter
    /// A fingerprint in the record does not match the public key it is carried with.
    case fingerprintKeyMismatch
    /// The record is about a fingerprint that was never admitted.
    case subjectNotAdmitted
    /// A cited voter is not on the current merged roster, or is the removal's own target.
    case voterNotEligible
    /// Fewer distinct eligible votes than plan §10.4's ⌊|roster|/2⌋ + 1.
    case quorumNotMet(required: Int, presented: Int)
    /// The signature does not verify over the record's canonical bytes.
    case signatureInvalid

    /// Frozen English for the diagnostic surface. Never shown as user copy.
    var diagnosticDescription: String {
        switch self {
        case .foreignMesh: return "The record names a different mesh."
        case .malformedRecord: return "A field in the record was malformed."
        case .signerNotAdmitted: return "The record's signer was never admitted to this mesh."
        case .signerNotAMember: return "The record's signer is no longer a member."
        case .unauthorizedAdmitter: return "The admitter was not entitled to admit a member."
        case .fingerprintKeyMismatch: return "A fingerprint did not match its public key."
        case .subjectNotAdmitted: return "The record is about a member this mesh never admitted."
        case .voterNotEligible: return "A cited voter is not an eligible member."
        case .quorumNotMet(let required, let presented):
            return "The removal presented \(presented) of \(required) required votes."
        case .signatureInvalid: return "The record's signature did not verify."
        }
    }
}

// MARK: - MeshMembershipRecordVerifier

/// The only way a membership record is allowed to enter a ledger a roster is derived from.
///
/// It owns a ``MeshMembershipLedger`` and hands back a named rejection instead of inserting
/// whenever a record fails. The four `insert` overloads implement plan §8.3's authorship rules:
///
/// | Record | Who must have signed it |
/// |---|---|
/// | admission | an existing member, or the founder when the ledger is still empty |
/// | departure | the departing member itself |
/// | removal | a member, citing ⌊\|roster\|/2⌋ + 1 distinct eligible voters (§10.4) |
/// | termination | the signing member itself |
///
/// **Keys come from admissions, never from the record being checked.** A record carries a
/// fingerprint; the signing key is looked up in the ledger's own admission set, which is what turns
/// "well-formed" into "signed by somebody entitled to sign it". The single exception is the
/// bootstrap admission, whose key must equal ``founderSigningPublicKey`` — a value the caller
/// authenticated elsewhere (the descriptor, or the transport-verified peer), never one taken from
/// the record.
///
/// **Verified does not mean retained.** A verified record still merges under the cap, so the set
/// may drop it in favour of an earlier one; that is item 1's deterministic rule, identical on every
/// device. What verification guarantees is that only real records compete for the slots.
nonisolated struct MeshMembershipRecordVerifier {

    /// The mesh every accepted record must name.
    let meshID: UUID

    /// The founder's Ed25519 signing key, when the caller knows it. The ONLY key that can
    /// authorize an admission into an empty ledger; nil means this device cannot bootstrap a
    /// roster and every admission must be authored by an existing member.
    let founderSigningPublicKey: Data?

    /// The verified records accepted so far. Read-only from outside: the point of the type is that
    /// there is no other door.
    private(set) var ledger: MeshMembershipLedger

    /// Builds a verifier over an existing ledger — typically one loaded from the sealed
    /// ``MeshSessionContext``, whose contents were verified when they were first accepted.
    init(meshID: UUID, founderSigningPublicKey: Data? = nil, ledger: MeshMembershipLedger = .empty) {
        self.meshID = meshID
        self.founderSigningPublicKey = founderSigningPublicKey
        self.ledger = ledger
    }

    /// The roster derived from everything accepted so far.
    var roster: MeshDerivedRoster { ledger.derivedRoster }

    /// Merges another ledger's records one at a time, returning the rejections.
    ///
    /// This is the shape a record exchange takes (plan §10.3): a peer's whole ledger is not
    /// trusted wholesale, because a peer that forged one record would otherwise import all of
    /// them. Bounded by the four record caps, so the loop is bounded by construction.
    @discardableResult
    mutating func merge(_ other: MeshMembershipLedger) -> [MeshMembershipRecordRejection] {
        var rejections: [MeshMembershipRecordRejection] = []
        for record in other.admissions.all { rejections.appendIfPresent(insert(record)) }
        for record in other.departures.all { rejections.appendIfPresent(insert(record)) }
        for record in other.removals.all { rejections.appendIfPresent(insert(record)) }
        for record in other.terminations.all { rejections.appendIfPresent(insert(record)) }
        return rejections
    }

    // MARK: - Admission

    /// Verifies and inserts an admission record.
    ///
    /// The admitter signature is checked under the already-registered
    /// `meshAdmissionTokenV2` domain — one admission format, not a second one minted for P3. The
    /// token's `expiresAt` is deliberately not re-applied: it gates ADMISSION, not the durability
    /// of the record admission produced.
    @discardableResult
    mutating func insert(_ record: SignedAdmissionRecord) -> MeshMembershipRecordRejection? {
        guard record.meshID == meshID else { return .foreignMesh }
        guard isWellFormed(record.token) else { return .malformedRecord }
        guard fingerprintMatches(record.token.joinerFingerprint, record.signingPublicKey),
              fingerprintMatches(record.token.admitterFingerprint, record.token.admitterSigningPublicKey) else {
            return .fingerprintKeyMismatch
        }
        if let rejection = admitterAuthorization(for: record) { return rejection }
        guard IdentityService.verify(
            record.signature,
            of: canonicalBytes(for: record.token),
            by: record.token.admitterSigningPublicKey,
            purpose: FernletCryptoPurpose.Signature.meshAdmissionTokenV2
        ) else {
            return .signatureInvalid
        }
        ledger.admissions = ledger.admissions.inserting(record)
        return nil
    }

    /// Whether the admitter was entitled to admit: an existing member holding exactly that key, or
    /// the founder while the ledger is still empty.
    private func admitterAuthorization(for record: SignedAdmissionRecord) -> MeshMembershipRecordRejection? {
        let admitterKey = record.token.admitterSigningPublicKey
        if ledger.admissions.isEmpty {
            guard let founderSigningPublicKey, founderSigningPublicKey == admitterKey else {
                return .unauthorizedAdmitter
            }
            return nil
        }
        guard let known = admittedSigningKey(for: record.token.admitterFingerprint) else {
            return founderSigningPublicKey == admitterKey ? nil : .unauthorizedAdmitter
        }
        guard known == admitterKey else { return .fingerprintKeyMismatch }
        guard roster.contains(fingerprint: record.token.admitterFingerprint) else {
            return .signerNotAMember
        }
        return nil
    }

    // MARK: - Departure

    /// Verifies and inserts a departure record. Self-signed by definition: the leaver is the
    /// author, so the signing key is the one its own admission bound.
    ///
    /// A departure is accepted from any ADMITTED fingerprint, not only a current member: a member
    /// that was removed in one partition and departed in another produces both records, and both
    /// subtract, so refusing the second would only lose an audit row.
    @discardableResult
    mutating func insert(_ record: SignedDepartureRecord) -> MeshMembershipRecordRejection? {
        guard record.meshID == meshID else { return .foreignMesh }
        guard isWellFormed(record.memberFingerprint, signature: record.signature) else {
            return .malformedRecord
        }
        guard let key = admittedSigningKey(for: record.memberFingerprint) else {
            return .signerNotAdmitted
        }
        guard IdentityService.verify(
            record.signature,
            of: canonicalBytes(for: record),
            by: key,
            purpose: FernletCryptoPurpose.Signature.meshMemberDepartureV1
        ) else {
            return .signatureInvalid
        }
        ledger.departures = ledger.departures.inserting(record)
        return nil
    }

    // MARK: - Removal

    /// Verifies and inserts a completed removal, re-checking plan §10.4's quorum against THIS
    /// device's merged roster rather than trusting the tallier's arithmetic.
    @discardableResult
    mutating func insert(_ record: SignedRemovalRecord) -> MeshMembershipRecordRejection? {
        guard record.meshID == meshID else { return .foreignMesh }
        guard isWellFormed(record.authorFingerprint, signature: record.signature),
              record.memberFingerprint.utf8.count <= MeshMembershipEventFormat.maxFingerprintLength else {
            return .malformedRecord
        }
        guard admittedSigningKey(for: record.memberFingerprint) != nil else { return .subjectNotAdmitted }
        guard let key = admittedSigningKey(for: record.authorFingerprint) else { return .signerNotAdmitted }
        guard roster.contains(fingerprint: record.authorFingerprint) else { return .signerNotAMember }
        if let rejection = quorumRejection(for: record) { return rejection }
        guard IdentityService.verify(
            record.signature,
            of: canonicalBytes(for: record),
            by: key,
            purpose: FernletCryptoPurpose.Signature.meshMemberRemovalV1
        ) else {
            return .signatureInvalid
        }
        ledger.removals = ledger.removals.inserting(record)
        return nil
    }

    /// Plan §10.4's arithmetic: ⌊|roster|/2⌋ + 1 DISTINCT votes from current members, with the
    /// target excluded. The threshold comes from ``MeshDerivedRoster/quorumThreshold`` — the same
    /// helper the mesh already elects and moderates by, so there is one definition of quorum.
    private func quorumRejection(for record: SignedRemovalRecord) -> MeshMembershipRecordRejection? {
        let derived = roster
        var eligible: Set<String> = []
        for voter in record.voterFingerprints {
            guard voter != record.memberFingerprint, derived.contains(fingerprint: voter) else {
                return .voterNotEligible
            }
            eligible.insert(voter)
        }
        let required = derived.quorumThreshold
        guard eligible.count >= required else {
            return .quorumNotMet(required: required, presented: eligible.count)
        }
        return nil
    }

    // MARK: - Termination

    /// Verifies and inserts a termination record. Self-signed like a departure, and required to
    /// come from a CURRENT member: a stranger, a departed member or a removed member must not be
    /// able to end a mesh they are not in.
    ///
    /// Whether it ends the mesh or downgrades to the signer's departure is decided later, by
    /// ``MeshDerivedRoster`` reading the merged roster (plan §8.3).
    @discardableResult
    mutating func insert(_ record: SignedTerminationRecord) -> MeshMembershipRecordRejection? {
        guard record.meshID == meshID else { return .foreignMesh }
        guard isWellFormed(record.memberFingerprint, signature: record.signature) else {
            return .malformedRecord
        }
        guard let key = admittedSigningKey(for: record.memberFingerprint) else {
            return .signerNotAdmitted
        }
        guard roster.contains(fingerprint: record.memberFingerprint) else { return .signerNotAMember }
        guard IdentityService.verify(
            record.signature,
            of: canonicalBytes(for: record),
            by: key,
            purpose: FernletCryptoPurpose.Signature.meshTerminatedV1
        ) else {
            return .signatureInvalid
        }
        ledger.terminations = ledger.terminations.inserting(record)
        return nil
    }

    // MARK: - Inventory digest

    /// Verifies a peer's signed inventory digest and reports whether it matches this ledger.
    ///
    /// - Returns: the named rejection, or nil when the digest verified. A verified digest that
    ///   DIFFERS is not a rejection — that is the whole point of sending one (plan §10.5); read
    ///   ``matchesLocalInventory(_:)`` for that answer.
    func verify(_ payload: MeshInventoryDigestPayload) -> MeshMembershipRecordRejection? {
        guard payload.digest.meshID == meshID else { return .foreignMesh }
        guard payload.isWellFormed else { return .malformedRecord }
        guard let key = admittedSigningKey(for: payload.senderFingerprint) else {
            return .signerNotAdmitted
        }
        guard roster.contains(fingerprint: payload.senderFingerprint) else { return .signerNotAMember }
        guard IdentityService.verify(
            payload.signature,
            of: canonicalBytes(for: payload),
            by: key,
            purpose: FernletCryptoPurpose.Signature.meshInventoryDigestV1
        ) else {
            return .signatureInvalid
        }
        return nil
    }

    /// Verifies a peer's signed epoch-head set (P4 item 3, plan §10.3).
    ///
    /// The same five checks the inventory digest gets, under the head set's own signature domain:
    /// the heads decide the counter a merge's successor is minted at, so an unattributable set is
    /// refused rather than folded.
    ///
    /// - Returns: the named rejection, or nil when the head set verified. A verified set that
    ///   DIVERGES from this device's own heads is not a rejection — that is the whole point of
    ///   sending one.
    func verify(_ payload: MeshEpochHeadsPayload) -> MeshMembershipRecordRejection? {
        guard payload.meshID == meshID else { return .foreignMesh }
        guard payload.isWellFormed else { return .malformedRecord }
        guard let key = admittedSigningKey(for: payload.senderFingerprint) else {
            return .signerNotAdmitted
        }
        guard roster.contains(fingerprint: payload.senderFingerprint) else { return .signerNotAMember }
        guard IdentityService.verify(
            payload.signature,
            of: canonicalBytes(for: payload),
            by: key,
            purpose: FernletCryptoPurpose.Signature.meshEpochHeadsV1
        ) else {
            return .signatureInvalid
        }
        return nil
    }

    // MARK: - Removal quorum (P4 item 5)

    /// Verifies a proposer's signed removal proposal (plan §10.4).
    ///
    /// The same five checks the inventory digest and the head set get, under the proposal's own
    /// domain — and nothing more: **quorum is not checked here**, because a proposal on its own
    /// carries exactly one vote and the arithmetic belongs to ``MeshRemovalQuorum``, re-derived
    /// against the roster of the moment. What this settles is only "was this signed by a member
    /// entitled to propose".
    ///
    /// A *live* object, never a record: nothing is inserted, and the ledger is untouched whatever
    /// the answer.
    ///
    /// - Returns: the named rejection, or nil when the proposal verified.
    func verify(_ proposal: SignedRemovalProposal) -> MeshMembershipRecordRejection? {
        guard proposal.meshID == meshID else { return .foreignMesh }
        guard proposal.isWellFormed else { return .malformedRecord }
        guard let key = admittedSigningKey(for: proposal.proposerFingerprint) else {
            return .signerNotAdmitted
        }
        guard roster.contains(fingerprint: proposal.proposerFingerprint) else { return .signerNotAMember }
        guard proposal.targetFingerprint != proposal.proposerFingerprint else { return .voterNotEligible }
        guard IdentityService.verify(
            proposal.signature,
            of: canonicalBytes(for: proposal),
            by: key,
            purpose: FernletCryptoPurpose.Signature.meshRemovalProposalV1
        ) else {
            return .signatureInvalid
        }
        return nil
    }

    /// Verifies one member's signed vote on a removal proposal (plan §10.4).
    ///
    /// The target's own vote is refused here as well as discarded by the tally — belt and braces,
    /// because "the target cannot vote" is the rule that stops a mesh of two from ever removing
    /// anybody, and a rule enforced in only one place is a rule one refactor away from gone.
    ///
    /// - Returns: the named rejection, or nil when the vote verified.
    func verify(_ vote: SignedRemovalVote) -> MeshMembershipRecordRejection? {
        guard vote.meshID == meshID else { return .foreignMesh }
        guard vote.isWellFormed else { return .malformedRecord }
        guard let key = admittedSigningKey(for: vote.voterFingerprint) else { return .signerNotAdmitted }
        guard roster.contains(fingerprint: vote.voterFingerprint) else { return .signerNotAMember }
        guard vote.voterFingerprint != vote.targetFingerprint else { return .voterNotEligible }
        guard IdentityService.verify(
            vote.signature,
            of: canonicalBytes(for: vote),
            by: key,
            purpose: FernletCryptoPurpose.Signature.meshRemovalVoteV1
        ) else {
            return .signatureInvalid
        }
        return nil
    }

    /// Whether a peer's digest describes exactly the records this ledger holds. `false` means one
    /// side is missing records and a full record exchange is worth its bytes.
    func matchesLocalInventory(_ digest: MeshInventoryDigest) -> Bool {
        digest == localInventoryDigest
    }

    /// This device's own digest, for sending.
    var localInventoryDigest: MeshInventoryDigest {
        MeshInventoryDigest(meshID: meshID, ledger: ledger)
    }

    // MARK: - Shared checks

    /// The signing key the ledger's admissions bound to `fingerprint`, or nil when it never
    /// admitted that member. Bounded by the admission cap (16).
    private func admittedSigningKey(for fingerprint: String) -> Data? {
        ledger.admissions.all.first { $0.memberFingerprint == fingerprint }?.signingPublicKey
    }

    private func fingerprintMatches(_ fingerprint: String, _ signingPublicKey: Data) -> Bool {
        IdentityService.fingerprintsMatch(IdentityService.fingerprint(of: signingPublicKey), fingerprint)
    }

    private func isWellFormed(_ fingerprint: String, signature: Data) -> Bool {
        !fingerprint.isEmpty
            && fingerprint.utf8.count <= MeshMembershipEventFormat.maxFingerprintLength
            && signature.count == MeshMembershipEventFormat.signatureByteCount
    }

    private func isWellFormed(_ token: MeshAdmissionToken) -> Bool {
        isWellFormed(token.admitterFingerprint, signature: token.admitterSignature)
            && !token.joinerFingerprint.isEmpty
            && token.joinerFingerprint.utf8.count <= MeshMembershipEventFormat.maxFingerprintLength
            && token.joinerSigningPublicKey.count == MeshChannelIntroductionFormat.signingKeyByteCount
            && token.admitterSigningPublicKey.count == MeshChannelIntroductionFormat.signingKeyByteCount
    }
}

// MARK: - Rejection collection

private extension Array where Element == MeshMembershipRecordRejection {
    /// Appends a rejection when there was one. Keeps ``MeshMembershipRecordVerifier/merge(_:)``
    /// under the 60-line rule without hiding the fact that every insert's answer is kept.
    nonisolated mutating func appendIfPresent(_ rejection: MeshMembershipRecordRejection?) {
        guard let rejection else { return }
        append(rejection)
    }
}
