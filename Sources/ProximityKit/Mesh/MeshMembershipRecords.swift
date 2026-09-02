import Foundation

// MARK: - Membership records (plan §8.1, §8.3, §9)
//
// The four signed, immutable, grow-only records membership is made of. Everything a mesh knows
// about who belongs is a *union* of these (design invariant 2): two views can differ only by
// records one side is MISSING, never by records that conflict, so merging two views is set union
// and the roster is re-derived rather than reconciled. Nothing here reads a clock, touches disk,
// speaks to a transport, or mints a signature — a record's `signature` is opaque bytes it carries,
// and the crypto purpose that produces and checks those bytes belongs to the rotation item, not
// this one. That is deliberate: the algebra below is the part that must be provable at tier 1.

/// The frozen wire vocabulary naming the four membership records.
///
/// English tokens, forever — a `rawValue` here is a byte on the mesh wire and a key in the sealed
/// session context, so it never localizes (localization wall; plan invariant 8). `departure` and
/// `termination` are the tokens plan §8.3 names verbatim; `admission` and `removal` are minted in
/// the same family for the two records §8.3 implies but does not spell out.
///
/// The retired `sessionGoodbye` payload type is deliberately absent: it stays frozen/parked in
/// `PayloadType` and is translated into a departure by the wire layer, never re-used here.
nonisolated enum MeshMembershipRecordKind: String, Codable, CaseIterable, Sendable {
    /// A member was admitted to the mesh, proven by the admitter's signature.
    case admission = "fernlet.mesh.member-admission.v1"
    /// A member left of their own accord (development, hand-off, explicit leave).
    case departure = "fernlet.mesh.member-departure.v1"
    /// A member was voted out and the quorum completed (plan §10.4).
    case removal = "fernlet.mesh.member-removal.v1"
    /// A final-pair member ended the mesh for everyone.
    case termination = "fernlet.mesh.terminated.v1"
}

// MARK: - MeshMembershipBounds

/// Every cap plan §9 puts on membership state, in one place so a reader can check the table
/// against the code without reading four files.
///
/// The roster and record caps are *reused*, not restated: they are the same constants
/// ``MeshIntroductionRoster`` already enforces at the transport, because a roster the transport
/// would truncate and a roster the ledger would keep are the shape of a membership bug that only
/// shows up on the eighth device.
nonisolated enum MeshMembershipBounds {

    /// Lifetime admitted members of one mesh (plan §9: roster cap 8).
    static let maxRosterMembers = MeshIntroductionRoster.maxMembers

    /// Records retained per kind (plan §8.1/§9: 16 admissions, 16 departures, 16 removals).
    static let maxRecordsPerKind = MeshIntroductionRoster.maxBarred

    /// Termination records retained. A mesh ends once; a second record is a duplicate, and the
    /// earliest one wins by the same total order every other record set uses.
    static let maxTerminationRecords = 1

    /// Custodians one departure may name (plan §10.6's hand-off is to *reachable members*, so it
    /// can never exceed the roster).
    static let maxCustodians = maxRosterMembers

    /// Voters one completed removal may cite. Quorum is ⌊|roster|/2⌋ + 1 (plan §10.4), so the
    /// roster cap bounds the evidence too.
    static let maxVoters = maxRosterMembers
}

// MARK: - MeshMembershipRecord

/// What every membership record must expose so the union-merge and the derived roster can be
/// written once instead of four times.
///
/// The five members are exactly what the algebra needs and nothing more:
/// - `memberFingerprint` is the record's **identity for dedup** — at most one record of a kind per
///   member survives in a set, so two devices that independently recorded the same departure do
///   not spend two of the sixteen slots on it.
/// - `occurredAt`, `authorFingerprint` and `signature` give a **total order** over records
///   (``MeshMembershipRecordOrder``), which is what makes "keep the earliest N" a deterministic
///   function of the merged set rather than of the merge order.
/// - `signature` is **opaque bytes**. Nothing in this file verifies it; a record is a claim until
///   the layer that owns the crypto purpose has checked it, and callers must not insert unverified
///   records into a ledger a roster is derived from.
nonisolated protocol MeshMembershipRecord: Codable, Equatable, Sendable {

    /// The frozen token naming this record on the wire.
    static var kind: MeshMembershipRecordKind { get }

    /// How many records of this kind a set retains (plan §9).
    static var setCapacity: Int { get }

    /// The mesh the record belongs to. Records from a different mesh are another layer's refusal.
    var meshID: UUID { get }

    /// The member the record is *about* — the dedup key of the set it lives in.
    var memberFingerprint: String { get }

    /// When the event the record describes happened, as claimed by its author.
    var occurredAt: Date { get }

    /// Who signed the record. For a departure and a termination this is the member themself.
    var authorFingerprint: String { get }

    /// The author's signature over the record's canonical bytes — opaque here, checked elsewhere.
    var signature: Data { get }
}

// MARK: - MeshMembershipRecordOrder

/// The total order every record set sorts and truncates by.
///
/// It has to be **total** (never "equal but different") and derived only from record fields, or the
/// cap would keep different records on different devices from the same merged set and the roster
/// would stop converging. Timestamp first because "earliest wins" is the policy a grow-only set
/// wants; the three tie-breakers exist for the clock skew case, not the honest one.
nonisolated enum MeshMembershipRecordOrder {

    /// Whether `lhs` sorts before `rhs`: earlier `occurredAt`, then member, then author, then the
    /// signature bytes read lexicographically.
    static func precedes<Record: MeshMembershipRecord>(_ lhs: Record, _ rhs: Record) -> Bool {
        if lhs.occurredAt != rhs.occurredAt { return lhs.occurredAt < rhs.occurredAt }
        if lhs.memberFingerprint != rhs.memberFingerprint {
            return lhs.memberFingerprint < rhs.memberFingerprint
        }
        if lhs.authorFingerprint != rhs.authorFingerprint {
            return lhs.authorFingerprint < rhs.authorFingerprint
        }
        return lhs.signature.lexicographicallyPrecedes(rhs.signature)
    }
}

// MARK: - SignedAdmissionRecord

/// The durable form of "this member was admitted": the existing ``MeshAdmissionToken``, kept whole.
///
/// Deliberately a wrapper rather than a new shape. The token is already the admitter-signed
/// credential binding mesh id, joiner fingerprint and the joiner's **full signing key**, and it is
/// already the thing the admission flow produces — re-modelling it would mean a second signed
/// admission format, a second canonical encoder and a second way to get impersonation wrong.
///
/// **The token's expiry is an admission-time freshness check, not the record's lifetime.** A token
/// that has passed `expiresAt` may no longer *grant* entry, but the record it became still says the
/// member was admitted, which is what the roster derives from. The layer that accepts a record
/// verifies the admitter signature; it must not re-apply `expiresAt` as a validity test on a record
/// that is hours old by design.
///
/// The joiner's key-agreement key is intentionally absent: group-key wrapping reads the
/// handshake-verified key off the live slot, never gossip, and a roster that carried a stale
/// wrapping target would be a way to seal a key to the wrong device.
nonisolated struct SignedAdmissionRecord: MeshMembershipRecord {

    static let kind = MeshMembershipRecordKind.admission
    static let setCapacity = MeshMembershipBounds.maxRecordsPerKind

    /// The admitter-signed credential this record preserves verbatim.
    let token: MeshAdmissionToken

    var meshID: UUID { token.meshID }
    var memberFingerprint: String { token.joinerFingerprint }
    var occurredAt: Date { token.grantedAt }
    var authorFingerprint: String { token.admitterFingerprint }
    var signature: Data { token.admitterSignature }

    /// The admitted member's Ed25519 signing key — what the derived roster hands the transport so a
    /// removal can name a *key*, not only a fingerprint (plan §20.1's `barred` row).
    var signingPublicKey: Data { token.joinerSigningPublicKey }

    /// Wraps an admission credential as a durable membership record.
    init(token: MeshAdmissionToken) {
        self.token = token
    }
}

// MARK: - MeshCustodyHandoffSummary

/// What a leaving member says it handed to whom, carried inside its departure record (plan §8.3).
///
/// Bounded on construction **and on decode**: the custodian list is attacker-influenced input on
/// both paths, and a `Codable` synthesis would have clamped the first and not the second.
nonisolated struct MeshCustodyHandoffSummary: Codable, Equatable, Sendable {

    /// Members that accepted custody, capped at ``MeshMembershipBounds/maxCustodians``.
    let custodianFingerprints: [String]

    /// How many routed items were handed over. Clamped to zero, never negative.
    let handedOffItemCount: Int

    /// A hand-off that transferred nothing — a member leaving with no pending custody, and the
    /// value a legacy goodbye translates to.
    static var none: MeshCustodyHandoffSummary {
        MeshCustodyHandoffSummary(custodianFingerprints: [], handedOffItemCount: 0)
    }

    /// Builds a summary, dropping custodians past the cap rather than growing without bound.
    init(custodianFingerprints: [String], handedOffItemCount: Int) {
        self.custodianFingerprints = Array(
            custodianFingerprints.prefix(MeshMembershipBounds.maxCustodians)
        )
        self.handedOffItemCount = max(0, handedOffItemCount)
    }

    /// Decodes with the same clamps the memberwise initializer applies.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            custodianFingerprints: try container.decode([String].self, forKey: .custodianFingerprints),
            handedOffItemCount: try container.decode(Int.self, forKey: .handedOffItemCount)
        )
    }
}

// MARK: - SignedDepartureRecord

/// A member's own signed statement that it left (plan §8.3, token `fernlet.mesh.member-departure.v1`).
///
/// Self-signed by definition — the leaver is the author — which is why departure needs no quorum and
/// why a wrongly-issued termination downgrades to one safely (plan §8.3): the worst a bad signature
/// can cost is the signer's own membership.
///
/// **Grow-only, and therefore permanent.** Nothing removes a departure, so a fingerprint that has
/// departed can never be re-admitted into the same mesh: a later admission record for it is
/// subtracted straight back out by ``MeshDerivedRoster``. Rejoining means a new mesh.
nonisolated struct SignedDepartureRecord: MeshMembershipRecord {

    static let kind = MeshMembershipRecordKind.departure
    static let setCapacity = MeshMembershipBounds.maxRecordsPerKind

    let meshID: UUID
    /// The leaver. Also the author: a departure is signed by the member it is about.
    let memberFingerprint: String
    let occurredAt: Date
    /// What the leaver handed to the members it could still reach.
    let custodyHandoff: MeshCustodyHandoffSummary
    let signature: Data

    var authorFingerprint: String { memberFingerprint }

    /// Builds a departure record from already-signed bytes.
    init(
        meshID: UUID,
        memberFingerprint: String,
        occurredAt: Date,
        custodyHandoff: MeshCustodyHandoffSummary = .none,
        signature: Data
    ) {
        self.meshID = meshID
        self.memberFingerprint = memberFingerprint
        self.occurredAt = occurredAt
        self.custodyHandoff = custodyHandoff
        self.signature = signature
    }
}

// MARK: - SignedRemovalRecord

/// A **completed** removal: quorum was reached and the member is out for the life of the mesh
/// (plan §10.4).
///
/// Only completed removals are records. An expired proposal leaves no trace, which is what keeps
/// the record sets grow-only and conflict-free — there is no "un-remove", so a merge can never have
/// to decide between two states of the same proposal.
///
/// `voterFingerprints` is the quorum evidence carried with the record so a member that was
/// partitioned when the vote happened can check the arithmetic against its own merged roster rather
/// than trusting the tallier. The votes' own signatures are not modelled here: the rotation item
/// owns the signed-vote shape, and this field is the list its verification will be handed.
nonisolated struct SignedRemovalRecord: MeshMembershipRecord {

    static let kind = MeshMembershipRecordKind.removal
    static let setCapacity = MeshMembershipBounds.maxRecordsPerKind

    let meshID: UUID
    /// The removed member.
    let memberFingerprint: String
    /// The proposal the quorum formed around, so duplicate tallies of one vote are recognisable.
    let proposalID: UUID
    /// Distinct members whose signed votes made quorum, capped at the roster cap.
    let voterFingerprints: [String]
    let occurredAt: Date
    /// The member that tallied quorum and signed the record.
    let authorFingerprint: String
    let signature: Data

    /// Builds a completed-removal record, dropping voters past the cap.
    init(
        meshID: UUID,
        memberFingerprint: String,
        proposalID: UUID,
        voterFingerprints: [String],
        occurredAt: Date,
        authorFingerprint: String,
        signature: Data
    ) {
        self.meshID = meshID
        self.memberFingerprint = memberFingerprint
        self.proposalID = proposalID
        self.voterFingerprints = Array(voterFingerprints.prefix(MeshMembershipBounds.maxVoters))
        self.occurredAt = occurredAt
        self.authorFingerprint = authorFingerprint
        self.signature = signature
    }

    /// Decodes with the same voter clamp the memberwise initializer applies.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            meshID: try container.decode(UUID.self, forKey: .meshID),
            memberFingerprint: try container.decode(String.self, forKey: .memberFingerprint),
            proposalID: try container.decode(UUID.self, forKey: .proposalID),
            voterFingerprints: try container.decode([String].self, forKey: .voterFingerprints),
            occurredAt: try container.decode(Date.self, forKey: .occurredAt),
            authorFingerprint: try container.decode(String.self, forKey: .authorFingerprint),
            signature: try container.decode(Data.self, forKey: .signature)
        )
    }
}

// MARK: - SignedTerminationRecord

/// A final-pair member's signed statement that the mesh is over (plan §8.3).
///
/// The record is stored, but its *effect* is derived, and that distinction is load-bearing: a
/// receiver whose merged roster is larger than two downgrades it to a departure of the signer
/// (§8.3), so whether a termination ends the mesh depends on the roster it is read against. Deriving
/// it at read time — rather than applying it at merge time — is what keeps the union commutative:
/// merging an admission before or after the termination gives the same answer either way.
///
/// `rosterAtSigning` is the signer's view when it signed, kept for the audit trail. It is
/// deliberately **not** the roster the downgrade is judged against; the receiver's own merged roster
/// is, because a signer that had lost half the mesh is exactly the case the downgrade exists for.
nonisolated struct SignedTerminationRecord: MeshMembershipRecord {

    static let kind = MeshMembershipRecordKind.termination
    static let setCapacity = MeshMembershipBounds.maxTerminationRecords

    let meshID: UUID
    /// The signing member — and, when the record downgrades, the member it departs.
    let memberFingerprint: String
    /// The signer's own roster view at signing time, capped at the roster cap. Audit only.
    let rosterAtSigning: [String]
    let occurredAt: Date
    let signature: Data

    var authorFingerprint: String { memberFingerprint }

    /// Builds a termination record, dropping roster entries past the cap.
    init(
        meshID: UUID,
        memberFingerprint: String,
        rosterAtSigning: [String],
        occurredAt: Date,
        signature: Data
    ) {
        self.meshID = meshID
        self.memberFingerprint = memberFingerprint
        self.rosterAtSigning = Array(rosterAtSigning.prefix(MeshMembershipBounds.maxRosterMembers))
        self.occurredAt = occurredAt
        self.signature = signature
    }

    /// Decodes with the same roster clamp the memberwise initializer applies.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            meshID: try container.decode(UUID.self, forKey: .meshID),
            memberFingerprint: try container.decode(String.self, forKey: .memberFingerprint),
            rosterAtSigning: try container.decode([String].self, forKey: .rosterAtSigning),
            occurredAt: try container.decode(Date.self, forKey: .occurredAt),
            signature: try container.decode(Data.self, forKey: .signature)
        )
    }
}
