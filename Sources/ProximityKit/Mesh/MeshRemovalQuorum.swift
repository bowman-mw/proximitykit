// MeshRemovalQuorum.swift
// ProximityKit/Mesh
//
// Network migration P4 item 5 (plan §10.4): moderation under partition — the roster quorum.
//
// §10.4 in one sentence: a removal needs ⌊|roster|/2⌋ + 1 distinct signed votes, re-derived on the
// RECEIVER's own merged roster at evaluation time, the proposal counts as the proposer's vote, the
// target cannot vote, a proposal expires after five minutes, and only a COMPLETED removal becomes a
// record. Everything an incomplete proposal touches has to disappear without a trace — which is why
// nothing in this file is a `MeshMembershipRecord`, nothing here reaches `MeshMembershipLedger`, and
// nothing here is ever sealed. Proposals and votes are **live state, not archaeology**.
//
// Three properties are what the rest of the mesh depends on, and each is a deliberate shape here:
//
// 1. **Quorum is the receiver's arithmetic.** ``MeshRemovalQuorum`` stores raw voter fingerprints
//    and filters them against a roster handed in at *verdict* time, never at cast time alone. A
//    voter that departed while the proposal was open therefore stops counting, and a branch that
//    merged a larger roster needs more votes — both without any of the stored votes changing.
// 2. **No wall clock in the bytes decides anything.** The five-minute window is measured from the
//    RECEIVER's own `firstSeenAt`, taken from an injected clock; the signed `issuedAt` is bound into
//    the signature for the audit trail and is only ever used as a **bound** (§10.3's ±10-minute
//    clamp) so a stale replay is refused. A forged far-future stamp cannot extend a window, and a
//    forged far-past one cannot kill a live proposal, because neither is what expiry reads.
// 3. **Completion is the only durable thing.** The tally's output is a voter list; the record it
//    becomes is the existing `fernlet.mesh.member-removal.v1`, whose canonical bytes this item does
//    not touch. Two branches that complete independently mint two records for one member, which the
//    record set deduplicates to the earliest by its own total order — so a split converges on **one**
//    effective removal with no merge special case (`MeshMembershipRecordSet.normalized`).
//
// What is deliberately NOT here: the legacy two-party vote (`fernlet.mesh.removal.proposal.v1` /
// `fernlet.mesh.removal.second.v1`). Those are UNSIGNED, hard-code quorum at two and read `Date()`
// directly; they stay frozen and untouched because already-shipped builds speak them, exactly as
// `sessionGoodbye` stays frozen beside the signed departure record. The tokens below are a new,
// additive family with hyphens (`removal-proposal` / `removal-vote`), so one grep separates the
// signed quorum from the legacy pair.

import FernletCrypto
import Foundation

// MARK: - MeshRemovalQuorumBounds

/// Every bound plan §10.4 puts on a live quorum, in one place.
///
/// Each is a limit on **untrusted input** as much as a policy: a proposal and a vote both arrive
/// from a peer, and the table they land in is in memory for the life of a session.
nonisolated enum MeshRemovalQuorumBounds {

    /// Plan §10.4's window: a proposal expires five minutes after it is issued. Measured at the
    /// receiver from ``MeshRemovalOpenProposal/firstSeenAt``, never from the signed stamp.
    static let proposalLifetime: TimeInterval = 300

    /// How far a signed `issuedAt` may sit from the receiver's own clock before the proposal is
    /// refused — plan §10.3's ±10-minute clamp, reused rather than restated. It is a **bound**, not
    /// the expiry rule: a proposal inside the allowance still expires five minutes after this
    /// device first saw it.
    static let issuanceSkewAllowance: TimeInterval = 600

    /// Concurrent open proposals one device tracks. Small on purpose: the dedup key is a
    /// sender-chosen UUID, so without a cap a connected peer could spend this device's memory on
    /// distinct proposals nobody will ever vote on.
    static let maxOpenProposals = 4

    /// Votes one proposal retains, which is the roster cap — a ninth voter cannot exist.
    static let maxVotesPerProposal = MeshMembershipBounds.maxVoters
}

// MARK: - SignedRemovalProposal

/// A member's signed proposal to remove another member — and, per plan §10.4, **the proposer's own
/// vote** (wire token `fernlet.mesh.removal-proposal.v1`).
///
/// It is a separate signed object from ``SignedRemovalVote`` rather than "the first vote seen",
/// because the proposal is what binds `proposalID → (mesh, target, proposer)` under one signature.
/// If any vote could establish that binding, a hostile member could cast a vote on somebody else's
/// proposal ID naming a *different* target, and a device that happened to see the hostile vote first
/// would tally against the wrong member. Making the binding single-authored costs one extra record
/// and removes that whole class.
///
/// **`issuedAt` decides nothing.** It is bound into the signature so the audit trail is signed, and
/// a receiver refuses a proposal whose stamp is further than
/// ``MeshRemovalQuorumBounds/issuanceSkewAllowance`` from its own clock — a bound on replay, not the
/// expiry rule. Expiry is measured from ``MeshRemovalOpenProposal/firstSeenAt``.
nonisolated struct SignedRemovalProposal: Codable, Equatable, Sendable {

    /// The mesh the proposal belongs to. A proposal for another mesh is a refusal, not a difference.
    let meshID: UUID
    /// The identity every vote references, minted by the proposer.
    let proposalID: UUID
    /// The member proposed for removal. Bound into every vote too, so a vote cannot be replayed
    /// against a proposal about somebody else.
    let targetFingerprint: String
    /// The proposer — and the first voter, per plan §10.4.
    let proposerFingerprint: String
    /// When the proposer says it issued this. Signed, audited, clamped; never the expiry clock.
    let issuedAt: Date
    /// The proposer's signature over ``canonicalBytes(for:)-(SignedRemovalProposal)``.
    let signature: Data

    /// Builds a proposal from already-signed parts.
    init(
        meshID: UUID,
        proposalID: UUID,
        targetFingerprint: String,
        proposerFingerprint: String,
        issuedAt: Date,
        signature: Data
    ) {
        self.meshID = meshID
        self.proposalID = proposalID
        self.targetFingerprint = targetFingerprint
        self.proposerFingerprint = proposerFingerprint
        self.issuedAt = issuedAt
        self.signature = signature
    }

    /// Whether every field has the width the format fixes. Checked on untrusted bytes before the
    /// signature is verified, and before the proposal can occupy one of four table slots.
    var isWellFormed: Bool {
        MeshRemovalQuorumFormat.isWellFormed(targetFingerprint)
            && MeshRemovalQuorumFormat.isWellFormed(proposerFingerprint)
            && targetFingerprint != proposerFingerprint
            && signature.count == MeshMembershipEventFormat.signatureByteCount
    }
}

// MARK: - SignedRemovalVote

/// One member's signed vote on an open proposal (wire token `fernlet.mesh.removal-vote.v1`).
///
/// The target is re-bound here even though the proposal already names it: a vote's bytes are what a
/// tallier counts, and a vote that named only a proposal ID could be counted by a device that never
/// saw the proposal — which is exactly the ordering a partition produces. Binding the target means a
/// vote is only ever countable against the proposal it agrees with (``MeshRemovalQuorumRejection/proposalMismatch``).
///
/// **A vote is not a record.** It never enters a ledger, is never sealed, and leaves no trace when
/// its proposal expires — plan §10.4's "an incomplete proposal simply expires and leaves no trace in
/// the roster", taken literally.
nonisolated struct SignedRemovalVote: Codable, Equatable, Sendable {

    /// The mesh the vote belongs to.
    let meshID: UUID
    /// The proposal being voted on.
    let proposalID: UUID
    /// The member the proposal is about, re-bound so the vote cannot be moved to another proposal.
    let targetFingerprint: String
    /// The voter. Must be a current member of the receiver's merged roster, and never the target.
    let voterFingerprint: String
    /// When the voter says it voted. Signed and clamped like the proposal's stamp; decides nothing.
    let castAt: Date
    /// The voter's signature over ``canonicalBytes(for:)-(SignedRemovalVote)``.
    let signature: Data

    /// Builds a vote from already-signed parts.
    init(
        meshID: UUID,
        proposalID: UUID,
        targetFingerprint: String,
        voterFingerprint: String,
        castAt: Date,
        signature: Data
    ) {
        self.meshID = meshID
        self.proposalID = proposalID
        self.targetFingerprint = targetFingerprint
        self.voterFingerprint = voterFingerprint
        self.castAt = castAt
        self.signature = signature
    }

    /// Whether every field has the width the format fixes.
    var isWellFormed: Bool {
        MeshRemovalQuorumFormat.isWellFormed(targetFingerprint)
            && MeshRemovalQuorumFormat.isWellFormed(voterFingerprint)
            && targetFingerprint != voterFingerprint
            && signature.count == MeshMembershipEventFormat.signatureByteCount
    }
}

// MARK: - MeshRemovalQuorumFormat

/// The one width check the proposal and the vote share.
///
/// Split out so the two `isWellFormed` reads cannot drift: a fingerprint cap enforced on one frame
/// and not the other is how a hostile string reaches a table through the door nobody checked.
nonisolated enum MeshRemovalQuorumFormat {

    /// Whether a fingerprint is present and within the membership format's cap.
    static func isWellFormed(_ fingerprint: String) -> Bool {
        !fingerprint.isEmpty
            && fingerprint.utf8.count <= MeshMembershipEventFormat.maxFingerprintLength
    }
}

// MARK: - MeshRemovalQuorumRejection

/// Why a proposal or a vote was refused by the live tally.
///
/// Deliberately separate from ``MeshMembershipRecordRejection``: that enum answers "why did this
/// record not reach the ledger", and every case in it is about durable membership. These are
/// refusals of *live* state — a window that closed, a table that is full, a vote nobody can place —
/// and collapsing the two would mean a caller could not tell "the mesh refused this member's claim"
/// from "you were four seconds late". Signature and eligibility refusals are still the record
/// verifier's, and are reported under ``signerRefused(_:)`` rather than restated.
///
/// Frozen English in ``diagnosticDescription``, read by a developer in a log, never user copy.
nonisolated enum MeshRemovalQuorumRejection: Equatable, Sendable {
    /// The proposal or vote names a different mesh.
    case foreignMesh
    /// A field does not have the width the format fixes.
    case malformed
    /// The signed stamp sits further than §10.3's ±10 minutes from this device's clock.
    case issuanceOutOfRange
    /// The proposal's five-minute window has closed at this receiver.
    case proposalExpired
    /// The vote references a proposal this device does not hold.
    case unknownProposal
    /// The vote's target is not the target the proposal it references names.
    case proposalMismatch
    /// This device already holds this proposal, or already completed it.
    case duplicateProposal
    /// This voter has already been counted on this proposal.
    case duplicateVote
    /// Plan §10.4: the member a removal is about cannot vote on it.
    case targetMayNotVote
    /// The proposer or voter is not on this receiver's merged roster.
    case notAMember
    /// The bounded table is full — four open proposals, or eight votes on one.
    case tableFull
    /// The record verifier refused the signature or the signer.
    case signerRefused(MeshMembershipRecordRejection)

    /// Frozen English for the diagnostic surface. Never shown as user copy.
    var diagnosticDescription: String {
        switch self {
        case .foreignMesh: return "The proposal names a different mesh."
        case .malformed: return "A field in the proposal or vote was malformed."
        case .issuanceOutOfRange: return "The signed issuance stamp was outside the allowed skew."
        case .proposalExpired: return "The proposal's five-minute window has closed."
        case .unknownProposal: return "The vote references a proposal this device does not hold."
        case .proposalMismatch: return "The vote names a different target than its proposal."
        case .duplicateProposal: return "This proposal is already open or already completed."
        case .duplicateVote: return "This voter has already been counted on this proposal."
        case .targetMayNotVote: return "The member a removal is about cannot vote on it."
        case .notAMember: return "The proposer or voter is not on this device's merged roster."
        case .tableFull: return "The bounded proposal or vote table is full."
        case .signerRefused(let rejection): return rejection.diagnosticDescription
        }
    }
}

// MARK: - MeshRemovalQuorumVerdict

/// What the receiver's own merged roster says about one open proposal, right now.
///
/// A *verdict*, not a state: it is recomputed from (stored votes, roster, clock) on every read, so a
/// merge that grew the roster raises the bar and a departure that shrank it lowers the bar without
/// anything stored having changed. That is plan §10.4's "roster is the current merged derived roster
/// **at evaluation time**", expressed as a function rather than as a cached number.
nonisolated enum MeshRemovalQuorumVerdict: Equatable, Sendable {
    /// This device holds no such proposal (never seen, expired and pruned, or already completed).
    case unknown
    /// The window closed before quorum was reached. Plan §10.4: it leaves no trace.
    case expired
    /// Open, and short of quorum on this device's roster.
    case pending(required: Int, counted: Int)
    /// Quorum reached. The voters are the eligible, distinct signers, in roster order — the exact
    /// list the completed ``SignedRemovalRecord`` binds as its evidence.
    case complete(voterFingerprints: [String])

    /// Whether quorum is reached, for the callers that only need the yes/no.
    var isComplete: Bool {
        if case .complete = self { return true }
        return false
    }
}

// MARK: - MeshRemovalOpenProposal

/// One proposal this device is tracking, with the votes it has counted and the instant its window
/// started **here**.
///
/// `firstSeenAt` rather than the proposal's own `issuedAt` is the whole clock story: it comes from
/// the caller's injected clock at acceptance, is monotone per device, and is unforgeable because no
/// peer supplies it.
nonisolated struct MeshRemovalOpenProposal: Equatable, Sendable {

    /// The signed proposal itself.
    let proposal: SignedRemovalProposal

    /// When this device first accepted it — the start of the five-minute window.
    let firstSeenAt: Date

    /// Everyone whose signed vote this device has counted, proposer first, in arrival order and
    /// capped at ``MeshRemovalQuorumBounds/maxVotesPerProposal``. Eligibility is **not** applied
    /// here; it is applied at verdict time against the roster of the moment.
    private(set) var voterFingerprints: [String]

    /// The instant the window closes at this device.
    var expiresAt: Date { firstSeenAt.addingTimeInterval(MeshRemovalQuorumBounds.proposalLifetime) }

    /// Opens a proposal with its proposer already counted (plan §10.4: the proposal is a vote).
    init(proposal: SignedRemovalProposal, firstSeenAt: Date) {
        self.proposal = proposal
        self.firstSeenAt = firstSeenAt
        voterFingerprints = [proposal.proposerFingerprint]
    }

    /// Whether the window is still open at `now`.
    func isOpen(at now: Date) -> Bool { now < expiresAt }

    /// Counts one more voter, or says why not.
    ///
    /// - Returns: nil when the voter was added, or the refusal.
    mutating func counting(_ voterFingerprint: String) -> MeshRemovalQuorumRejection? {
        guard voterFingerprint != proposal.targetFingerprint else { return .targetMayNotVote }
        guard !voterFingerprints.contains(voterFingerprint) else { return .duplicateVote }
        guard voterFingerprints.count < MeshRemovalQuorumBounds.maxVotesPerProposal else {
            return .tableFull
        }
        voterFingerprints.append(voterFingerprint)
        return nil
    }

    /// The verdict this proposal's votes produce against `roster` at `now`.
    ///
    /// Every filter plan §10.4 names is applied *here*, on every read: the target's vote is
    /// discarded rather than counted, a signer who has since departed or been removed falls out of
    /// the roster and so falls out of the tally, and duplicates cannot exist because
    /// ``counting(_:)`` refuses them.
    func verdict(against roster: MeshDerivedRoster, at now: Date) -> MeshRemovalQuorumVerdict {
        guard isOpen(at: now) else { return .expired }
        var eligible: [String] = []
        for voter in voterFingerprints
        where voter != proposal.targetFingerprint && roster.contains(fingerprint: voter) {
            eligible.append(voter)
        }
        let required = roster.quorumThreshold
        guard eligible.count >= required else {
            return .pending(required: required, counted: eligible.count)
        }
        return .complete(voterFingerprints: eligible.sorted())
    }
}

// MARK: - MeshRemovalQuorum

/// The live, in-memory tally of every removal proposal this device is tracking (plan §10.4).
///
/// **Never persisted.** `MeshSessionContext` stays at schema 2 and no wipe row is owed, because
/// nothing here survives the session: a proposal is a five-minute conversation, and a device that
/// restarts mid-vote has simply missed it. Sealing them would turn a reversible, expiring judgement
/// into durable state and reintroduce the exact shape records exist to avoid — the same reasoning
/// P4 item 1 applied to `temporarilyDisconnected`.
///
/// **Pure.** No clock, no store, no transport, no signature checking: every entry point takes the
/// `now` and the `roster` the caller decided on, and signature/eligibility verification belongs to
/// ``MeshMembershipRecordVerifier``. That is what lets the whole of §10.4's rosters-2–8 × partition
/// shapes table run as a value test with no fabric at all.
nonisolated struct MeshRemovalQuorum: Equatable, Sendable {

    /// The open proposals, oldest first. Bounded by ``MeshRemovalQuorumBounds/maxOpenProposals``.
    private(set) var openProposals: [MeshRemovalOpenProposal] = []

    /// An empty tally — what a device that has seen no proposal holds.
    init() {}

    /// How many proposals are being tracked.
    var count: Int { openProposals.count }

    /// The proposal with this ID, when it is open here.
    func proposal(_ proposalID: UUID) -> MeshRemovalOpenProposal? {
        openProposals.first { $0.proposal.proposalID == proposalID }
    }

    /// Opens a verified proposal, counting the proposer as its first vote.
    ///
    /// The caller has already checked the signature and the signer; what is checked here is the
    /// live state — the mesh, the widths, the ±10-minute stamp bound, the target's ineligibility,
    /// membership at this moment, duplication, and the table's capacity.
    ///
    /// - Parameters:
    ///   - proposal: The verified proposal.
    ///   - meshID: The mesh this device is in.
    ///   - roster: This device's merged derived roster, right now.
    ///   - now: The injected clock. Also becomes the proposal's `firstSeenAt`.
    /// - Returns: nil when the proposal is now open, or the refusal.
    mutating func open(
        _ proposal: SignedRemovalProposal,
        meshID: UUID,
        roster: MeshDerivedRoster,
        now: Date
    ) -> MeshRemovalQuorumRejection? {
        guard proposal.meshID == meshID else { return .foreignMesh }
        guard proposal.isWellFormed else { return .malformed }
        guard abs(proposal.issuedAt.timeIntervalSince(now))
            <= MeshRemovalQuorumBounds.issuanceSkewAllowance else { return .issuanceOutOfRange }
        guard roster.contains(fingerprint: proposal.proposerFingerprint) else { return .notAMember }
        guard proposal.proposerFingerprint != proposal.targetFingerprint else { return .targetMayNotVote }
        prune(at: now)
        guard self.proposal(proposal.proposalID) == nil else { return .duplicateProposal }
        guard openProposals.count < MeshRemovalQuorumBounds.maxOpenProposals else { return .tableFull }
        openProposals.append(MeshRemovalOpenProposal(proposal: proposal, firstSeenAt: now))
        return nil
    }

    /// Counts a verified vote against the proposal it references.
    ///
    /// - Parameters:
    ///   - vote: The verified vote.
    ///   - meshID: The mesh this device is in.
    ///   - roster: This device's merged derived roster, right now.
    ///   - now: The injected clock.
    /// - Returns: nil when the vote was counted, or the refusal.
    mutating func cast(
        _ vote: SignedRemovalVote,
        meshID: UUID,
        roster: MeshDerivedRoster,
        now: Date
    ) -> MeshRemovalQuorumRejection? {
        guard vote.meshID == meshID else { return .foreignMesh }
        guard vote.isWellFormed else { return .malformed }
        guard abs(vote.castAt.timeIntervalSince(now))
            <= MeshRemovalQuorumBounds.issuanceSkewAllowance else { return .issuanceOutOfRange }
        guard roster.contains(fingerprint: vote.voterFingerprint) else { return .notAMember }
        prune(at: now)
        guard let index = openProposals.firstIndex(where: { $0.proposal.proposalID == vote.proposalID })
        else { return .unknownProposal }
        guard openProposals[index].proposal.targetFingerprint == vote.targetFingerprint else {
            return .proposalMismatch
        }
        guard openProposals[index].isOpen(at: now) else { return .proposalExpired }
        return openProposals[index].counting(vote.voterFingerprint)
    }

    /// Plan §10.4's arithmetic for one proposal, on the roster of the moment.
    ///
    /// - Returns: ``MeshRemovalQuorumVerdict/unknown`` when this device holds no such proposal —
    ///   which is also the answer for one that has expired and been pruned.
    func verdict(for proposalID: UUID, roster: MeshDerivedRoster, at now: Date) -> MeshRemovalQuorumVerdict {
        guard let open = proposal(proposalID) else { return .unknown }
        return open.verdict(against: roster, at: now)
    }

    /// Drops every proposal whose window has closed. Bounded by the table cap.
    ///
    /// Expiry is a **deletion**, not a tombstone: plan §10.4's "leaves no trace" means there is
    /// nothing left to merge, nothing to seal, and nothing a later vote can reopen.
    ///
    /// - Returns: how many were dropped.
    @discardableResult
    mutating func prune(at now: Date) -> Int {
        let before = openProposals.count
        openProposals.removeAll { !$0.isOpen(at: now) }
        return before - openProposals.count
    }

    /// Forgets one proposal — what completion does, so a late vote cannot re-complete it.
    mutating func close(_ proposalID: UUID) {
        openProposals.removeAll { $0.proposal.proposalID == proposalID }
    }

    /// Forgets everything. Called when a session ends: a tally is session state, like a slot.
    mutating func removeAll() {
        openProposals.removeAll()
    }
}

// MARK: - Signing factories

extension SignedRemovalProposal {

    /// Mints a removal proposal signed by the proposer's own identity key.
    ///
    /// `@MainActor` because `IdentityService` is; the verification counterpart on
    /// ``MeshMembershipRecordVerifier`` is `nonisolated`, exactly as the record factories are.
    ///
    /// - Parameters:
    ///   - meshID: The mesh.
    ///   - identity: The proposer, whose fingerprint is bound as `proposerFingerprint`.
    ///   - targetFingerprint: The member proposed for removal.
    ///   - proposalID: The identity every vote will reference.
    ///   - issuedAt: The signed stamp. Audited and clamped; never the expiry clock.
    /// - Throws: The identity's signing error; never a trap.
    @MainActor
    static func signed(
        meshID: UUID,
        identity: IdentityService,
        targetFingerprint: String,
        proposalID: UUID = UUID(),
        issuedAt: Date = Date()
    ) throws -> SignedRemovalProposal {
        let unsigned = SignedRemovalProposal(
            meshID: meshID,
            proposalID: proposalID,
            targetFingerprint: targetFingerprint,
            proposerFingerprint: identity.localFingerprint,
            issuedAt: issuedAt,
            signature: Data()
        )
        let signature = try identity.sign(
            canonicalBytes(for: unsigned),
            purpose: FernletCryptoPurpose.Signature.meshRemovalProposalV1
        )
        return SignedRemovalProposal(
            meshID: meshID,
            proposalID: proposalID,
            targetFingerprint: targetFingerprint,
            proposerFingerprint: identity.localFingerprint,
            issuedAt: issuedAt,
            signature: signature
        )
    }
}

extension SignedRemovalVote {

    /// Mints a vote on an open proposal, signed by the voter's own identity key.
    ///
    /// The target is copied from the proposal rather than taken as a parameter: a voter signs what
    /// it agrees to, and a caller that could pass a different target would be minting a vote whose
    /// bytes disagree with the proposal it names.
    ///
    /// - Parameters:
    ///   - proposal: The proposal being voted on.
    ///   - identity: The voter.
    ///   - castAt: The signed stamp. Audited and clamped; never the expiry clock.
    /// - Throws: The identity's signing error; never a trap.
    @MainActor
    static func signed(
        on proposal: SignedRemovalProposal,
        identity: IdentityService,
        castAt: Date = Date()
    ) throws -> SignedRemovalVote {
        let unsigned = SignedRemovalVote(
            meshID: proposal.meshID,
            proposalID: proposal.proposalID,
            targetFingerprint: proposal.targetFingerprint,
            voterFingerprint: identity.localFingerprint,
            castAt: castAt,
            signature: Data()
        )
        let signature = try identity.sign(
            canonicalBytes(for: unsigned),
            purpose: FernletCryptoPurpose.Signature.meshRemovalVoteV1
        )
        return SignedRemovalVote(
            meshID: proposal.meshID,
            proposalID: proposal.proposalID,
            targetFingerprint: proposal.targetFingerprint,
            voterFingerprint: identity.localFingerprint,
            castAt: castAt,
            signature: signature
        )
    }
}
