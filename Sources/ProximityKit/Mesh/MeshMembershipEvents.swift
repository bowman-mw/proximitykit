// MeshMembershipEvents.swift
// ProximityKit/Mesh
//
// P3 item 3 (plan §8.3, §9, §10.5): the membership events that MOVE on the wire, and the signed
// bytes underneath them.
//
// Item 1 built the records and the algebra; this file gives three of them a frame, a signing
// factory and a bound, and adds the inventory digest a peer sends so a counterpart can notice it is
// MISSING records and ask for a re-gossip. The frozen English tokens are the same three spellings
// in every layer — `MeshMembershipRecordKind`, `PayloadType`, `FernletCryptoPurpose.Signature` —
// so one grep finds the record, the frame and the domain.
//
// What is deliberately NOT here: emission. Nothing in this file decides WHEN a departure is sent;
// `MeshNetworkManager.emitMembershipEvent(_:)` is the seam items 5–6 fill. And nothing here
// verifies a signature — `MeshMembershipRecordVerifier` owns the verify-then-insert path, because
// a record that reached a ledger unverified is a member on a roster nobody vouched for.

import CryptoKit
import FernletCrypto
import FernletDomainModel
import Foundation

// MARK: - MeshMembershipEventFormat

/// The frozen shape of every membership event frame: widths, caps, and the one protocol version.
///
/// Every constant is a **bound on untrusted input** as much as a description of honest output. A
/// membership record arrives from a peer, is re-gossiped by peers that never saw it minted, and
/// lands in a set of only sixteen slots — so each field's width is checked before a signature is
/// verified, and a frame that fails is refused rather than trimmed.
nonisolated enum MeshMembershipEventFormat {

    /// Ed25519 signature length. A record carrying any other length is malformed by definition.
    static let signatureByteCount = MeshChannelIntroductionFormat.signatureByteCount

    /// SHA-256 digest length — the width of ``MeshInventoryDigest/recordsHash``.
    static let digestByteCount = 32

    /// Cap on a fingerprint's UTF-8 length. `IdentityService.fingerprint(of:)` returns sixteen
    /// characters; the allowance is generous so a longer future spelling is a format decision
    /// rather than a silent refusal, and small enough that a hostile string cannot be a payload.
    static let maxFingerprintLength = 64
}

// MARK: - MeshRecordIdentity

/// One record's identity inside an inventory digest: its kind plus the four fields that give
/// ``MeshMembershipRecordOrder`` its total order.
///
/// It exists so the digest is computed over a **kind-tagged flattening** of all four record sets
/// rather than four separate hashes: a departure and a removal for the same member at the same
/// instant are different records, and a digest that could not tell them apart would report
/// convergence between two ledgers that disagree about why somebody is out.
nonisolated struct MeshRecordIdentity: Equatable, Sendable {

    /// The frozen token naming the record's kind.
    let kind: MeshMembershipRecordKind
    /// The member the record is about — the dedup key of its set.
    let memberFingerprint: String
    /// When the record's event happened, as claimed by its author.
    let occurredAt: Date
    /// Who signed the record.
    let authorFingerprint: String
    /// The record's signature bytes, which are what make two otherwise-identical claims distinct.
    let signature: Data

    /// The identity of one record.
    init<Record: MeshMembershipRecord>(_ record: Record) {
        kind = Record.kind
        memberFingerprint = record.memberFingerprint
        occurredAt = record.occurredAt
        authorFingerprint = record.authorFingerprint
        signature = record.signature
    }

    /// Sorts two identities by kind token, then by the record order's own fields. Total, and
    /// derived only from record content, so two devices holding the same records emit the same
    /// sequence and therefore the same digest.
    static func precedes(_ lhs: MeshRecordIdentity, _ rhs: MeshRecordIdentity) -> Bool {
        if lhs.kind != rhs.kind { return lhs.kind.rawValue < rhs.kind.rawValue }
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

// MARK: - MeshInventoryDigest

/// A bounded, deterministic summary of everything one ledger holds (plan §10.5).
///
/// **What it is for.** Records propagate by re-gossip, not by delivery: B's departure reaches C
/// because A carries it to a later connection. So every link needs a cheap way to ask "do we hold
/// the same thing?", and this is it — a few dozen bytes instead of the whole ledger, exchanged on
/// connect. Equal digests mean converged; unequal means somebody is missing records and the full
/// record exchange is worth its bytes.
///
/// **It is a hint, never an authority.** Nothing is admitted, removed or believed because of a
/// digest; it only decides whether to ask. That is what keeps the failure mode of a wrong digest
/// bounded to a wasted exchange.
///
/// The hash is domain-separated under `FernletCryptoPurpose.Hash.meshInventoryDigestV1` and
/// computed over the sorted ``MeshRecordIdentity`` list, so it is a pure function of the record
/// SET — order of arrival, and which device is asking, cannot change it.
nonisolated struct MeshInventoryDigest: Codable, Equatable, Sendable {

    /// The mesh the digest describes. A digest for another mesh is a refusal, not a difference.
    let meshID: UUID
    /// Admission records held, clamped to the record cap.
    let admissionCount: Int
    /// Departure records held, clamped to the record cap.
    let departureCount: Int
    /// Removal records held, clamped to the record cap.
    let removalCount: Int
    /// Termination records held (zero or one).
    let terminationCount: Int
    /// SHA-256 over the domain-tagged, sorted identities of every record in the ledger.
    let recordsHash: Data

    /// Computes the digest of a ledger.
    init(meshID: UUID, ledger: MeshMembershipLedger) {
        self.meshID = meshID
        admissionCount = ledger.admissions.count
        departureCount = ledger.departures.count
        removalCount = ledger.removals.count
        terminationCount = ledger.terminations.count
        recordsHash = Self.hash(of: Self.identities(in: ledger))
    }

    /// Rebuilds a digest from already-computed parts — the decode path's memberwise entry, and
    /// what a test uses to construct a deliberately-differing digest.
    init(
        meshID: UUID,
        admissionCount: Int,
        departureCount: Int,
        removalCount: Int,
        terminationCount: Int,
        recordsHash: Data
    ) {
        let cap = MeshMembershipBounds.maxRecordsPerKind
        self.meshID = meshID
        self.admissionCount = min(max(0, admissionCount), cap)
        self.departureCount = min(max(0, departureCount), cap)
        self.removalCount = min(max(0, removalCount), cap)
        self.terminationCount = min(max(0, terminationCount), MeshMembershipBounds.maxTerminationRecords)
        self.recordsHash = recordsHash
    }

    /// Decodes with the same clamps the memberwise initializer applies — counts arrive from a peer.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            meshID: try container.decode(UUID.self, forKey: .meshID),
            admissionCount: try container.decode(Int.self, forKey: .admissionCount),
            departureCount: try container.decode(Int.self, forKey: .departureCount),
            removalCount: try container.decode(Int.self, forKey: .removalCount),
            terminationCount: try container.decode(Int.self, forKey: .terminationCount),
            recordsHash: try container.decode(Data.self, forKey: .recordsHash)
        )
    }

    /// Whether the hash has the one width SHA-256 produces. Checked before a digest is compared,
    /// so a truncated hash is a refusal rather than a cheap collision.
    var isWellFormed: Bool {
        recordsHash.count == MeshMembershipEventFormat.digestByteCount
    }

    /// How many records the digest claims in total — the read that says which side is behind.
    var recordCount: Int {
        admissionCount + departureCount + removalCount + terminationCount
    }

    /// Every record in `ledger`, kind-tagged and in the digest's deterministic order.
    ///
    /// Bounded by construction: four sets, each already capped by ``MeshMembershipBounds``.
    static func identities(in ledger: MeshMembershipLedger) -> [MeshRecordIdentity] {
        var identities: [MeshRecordIdentity] = []
        identities.append(contentsOf: ledger.admissions.all.map(MeshRecordIdentity.init))
        identities.append(contentsOf: ledger.departures.all.map(MeshRecordIdentity.init))
        identities.append(contentsOf: ledger.removals.all.map(MeshRecordIdentity.init))
        identities.append(contentsOf: ledger.terminations.all.map(MeshRecordIdentity.init))
        return identities.sorted(by: MeshRecordIdentity.precedes)
    }

    // The hash below is domain-separated by `canonicalInventoryDigestBytes(for:)`, whose leading
    // field is the registered purpose `FernletCryptoPurpose.Hash.meshInventoryDigestV1`.
    private static func hash(of identities: [MeshRecordIdentity]) -> Data {
        Data(SHA256.hash(data: canonicalInventoryDigestBytes(for: identities)))
    }
}

// MARK: - MeshMemberDeparturePayload

/// The `fernlet.mesh.member-departure.v1` frame: one signed departure record and nothing else
/// (plan §8.3).
///
/// The frame carries no separate claim about who is leaving — the record already says, and it says
/// it under the leaver's own signature. A second, unsigned copy of the same fact would only create
/// the possibility that the two disagree, which is the mistake ``MeshChannelIntroduction`` avoids
/// for the same reason.
nonisolated struct MeshMemberDeparturePayload: Codable, Equatable, Sendable {

    /// The leaver's signed statement.
    let record: SignedDepartureRecord

    /// Wraps a record for the wire.
    init(record: SignedDepartureRecord) {
        self.record = record
    }
}

// MARK: - MeshTerminationPayload

/// The `fernlet.mesh.terminated.v1` frame: one signed termination record (plan §8.3).
///
/// Whether it ends the mesh is **not decided here and not decided by the sender**. A receiver whose
/// merged roster is larger than two downgrades it to the signer's own departure
/// (``MeshDerivedRoster``), so a partitioned member who wrongly believed it was in the final pair
/// costs itself its membership and nobody else theirs.
nonisolated struct MeshTerminationPayload: Codable, Equatable, Sendable {

    /// The final-pair member's signed statement.
    let record: SignedTerminationRecord

    /// Wraps a record for the wire.
    init(record: SignedTerminationRecord) {
        self.record = record
    }
}

// MARK: - MeshInventoryDigestPayload

/// The `fernlet.mesh.inventory-digest.v1` frame: what the sender holds, signed (plan §10.5).
///
/// Signed even though the digest is only a hint, for one reason: the digest is the input to a
/// bounded re-gossip, and an unsigned one arriving on a relayed path could be forged to spend a
/// peer's exchange budget. A signature makes the request attributable to a roster member and costs
/// one Ed25519 verification per connect.
nonisolated struct MeshInventoryDigestPayload: Codable, Equatable, Sendable {

    /// What the sender's ledger holds.
    let digest: MeshInventoryDigest
    /// The member that computed and signed it.
    let senderFingerprint: String
    /// When it was signed — bound into the signature so a stale digest cannot be replayed as fresh.
    let sentAt: Date
    /// The sender's signature over ``canonicalBytes(for:)-(MeshInventoryDigestPayload)``.
    let signature: Data

    /// Builds a payload from already-signed parts.
    init(digest: MeshInventoryDigest, senderFingerprint: String, sentAt: Date, signature: Data) {
        self.digest = digest
        self.senderFingerprint = senderFingerprint
        self.sentAt = sentAt
        self.signature = signature
    }

    /// Whether every field has the width the format fixes. Checked on untrusted bytes before the
    /// signature is verified.
    var isWellFormed: Bool {
        digest.isWellFormed
            && signature.count == MeshMembershipEventFormat.signatureByteCount
            && senderFingerprint.utf8.count <= MeshMembershipEventFormat.maxFingerprintLength
            && !senderFingerprint.isEmpty
    }
}

// MARK: - Signing factories

extension SignedDepartureRecord {

    /// Mints a departure record signed by the leaver's own identity key.
    ///
    /// `@MainActor` because `IdentityService` is: signing reads the device's long-term key. The
    /// verification counterpart is `nonisolated`, so a received record can be checked off the main
    /// actor exactly as ``MeshAdmissionToken/verify(joinerSigningPublicKey:expectedMeshID:expectedAdmitterSigningPublicKey:now:)`` is.
    @MainActor
    static func signed(
        meshID: UUID,
        identity: IdentityService,
        occurredAt: Date = Date(),
        custodyHandoff: MeshCustodyHandoffSummary = .none
    ) throws -> SignedDepartureRecord {
        let unsigned = SignedDepartureRecord(
            meshID: meshID,
            memberFingerprint: identity.localFingerprint,
            occurredAt: occurredAt,
            custodyHandoff: custodyHandoff,
            signature: Data()
        )
        let signature = try identity.sign(
            canonicalBytes(for: unsigned),
            purpose: FernletCryptoPurpose.Signature.meshMemberDepartureV1
        )
        return SignedDepartureRecord(
            meshID: meshID,
            memberFingerprint: identity.localFingerprint,
            occurredAt: occurredAt,
            custodyHandoff: custodyHandoff,
            signature: signature
        )
    }
}

extension SignedTerminationRecord {

    /// Mints a termination record signed by a final-pair member.
    ///
    /// `rosterAtSigning` is the signer's own view, kept for the audit trail; the receiver judges
    /// the record against its OWN merged roster, so a wrong view here cannot end anybody else's
    /// mesh (plan §8.3).
    @MainActor
    static func signed(
        meshID: UUID,
        identity: IdentityService,
        rosterAtSigning: [String],
        occurredAt: Date = Date()
    ) throws -> SignedTerminationRecord {
        let unsigned = SignedTerminationRecord(
            meshID: meshID,
            memberFingerprint: identity.localFingerprint,
            rosterAtSigning: rosterAtSigning,
            occurredAt: occurredAt,
            signature: Data()
        )
        let signature = try identity.sign(
            canonicalBytes(for: unsigned),
            purpose: FernletCryptoPurpose.Signature.meshTerminatedV1
        )
        return SignedTerminationRecord(
            meshID: meshID,
            memberFingerprint: identity.localFingerprint,
            rosterAtSigning: rosterAtSigning,
            occurredAt: occurredAt,
            signature: signature
        )
    }
}

extension SignedRemovalRecord {

    /// Mints a completed-removal record signed by the member that tallied quorum.
    ///
    /// The caller supplies the voters it counted; the record binds them, and every receiver
    /// re-checks the arithmetic against its own merged roster
    /// (``MeshMembershipRecordVerifier``) rather than trusting this tally.
    @MainActor
    static func signed(
        meshID: UUID,
        identity: IdentityService,
        memberFingerprint: String,
        proposalID: UUID,
        voterFingerprints: [String],
        occurredAt: Date = Date()
    ) throws -> SignedRemovalRecord {
        let unsigned = SignedRemovalRecord(
            meshID: meshID,
            memberFingerprint: memberFingerprint,
            proposalID: proposalID,
            voterFingerprints: voterFingerprints,
            occurredAt: occurredAt,
            authorFingerprint: identity.localFingerprint,
            signature: Data()
        )
        let signature = try identity.sign(
            canonicalBytes(for: unsigned),
            purpose: FernletCryptoPurpose.Signature.meshMemberRemovalV1
        )
        return SignedRemovalRecord(
            meshID: meshID,
            memberFingerprint: memberFingerprint,
            proposalID: proposalID,
            voterFingerprints: unsigned.voterFingerprints,
            occurredAt: occurredAt,
            authorFingerprint: identity.localFingerprint,
            signature: signature
        )
    }
}

extension MeshInventoryDigestPayload {

    /// Computes and signs this device's inventory digest for one ledger.
    @MainActor
    static func signed(
        meshID: UUID,
        ledger: MeshMembershipLedger,
        identity: IdentityService,
        sentAt: Date = Date()
    ) throws -> MeshInventoryDigestPayload {
        let digest = MeshInventoryDigest(meshID: meshID, ledger: ledger)
        let unsigned = MeshInventoryDigestPayload(
            digest: digest,
            senderFingerprint: identity.localFingerprint,
            sentAt: sentAt,
            signature: Data()
        )
        let signature = try identity.sign(
            canonicalBytes(for: unsigned),
            purpose: FernletCryptoPurpose.Signature.meshInventoryDigestV1
        )
        return MeshInventoryDigestPayload(
            digest: digest,
            senderFingerprint: identity.localFingerprint,
            sentAt: sentAt,
            signature: signature
        )
    }
}

// MARK: - MeshLegacyGoodbyeOutcome

/// What a legacy `fernlet.session.bye.v1` frame is allowed to mean.
///
/// One case, deliberately. A goodbye is the only membership-adjacent frame with **no signature** —
/// its whole body is a `PayloadSummary` — so the strongest statement it can support is "this link
/// is going away", and that is a presence fact, not a membership one.
nonisolated enum MeshLegacyGoodbyeOutcome: Equatable, Sendable {
    /// Drop the link and treat the peer as disconnected. Membership is untouched: the peer stays
    /// on the derived roster, keeps its slot in quorum arithmetic, and may reconnect.
    case disconnected
}

// MARK: - MeshMembershipGoodbyeInterop

/// The legacy goodbye's frozen interop rule, stated once (plan §8.2, §8.3).
///
/// **Parsed, never emitted.** New builds send ``PayloadType/meshMemberDeparture`` — signed by the
/// leaver — when a member actually leaves. `.sessionGoodbye` keeps decoding so peers built before
/// the transition still close their links promptly, and it stays frozen in `PayloadType` forever
/// because a retired wire token must never be re-used for a different meaning.
///
/// **A goodbye can never become a departure record**, which is what ``departureRecord(forGoodbyeFrom:)``
/// exists to say in code rather than in a comment. Departures are grow-only and permanent
/// (``SignedDepartureRecord``): a fingerprint that has departed can never be re-admitted to the
/// same mesh. Letting an unsigned frame mint one would mean anyone who can reach the link can
/// permanently evict a member from a signed roster, with no way to undo it — disconnect ≠ removal
/// (plan §8.2). The cost of the rule is a phantom member until the ceiling if a peer leaves with
/// only legacy builds present, which is the same bounded residual plan §10.5 already accepts for
/// an unreachable leaver.
nonisolated enum MeshMembershipGoodbyeInterop {

    /// The wire token this rule is about. Frozen English, never localized.
    static let payloadType = PayloadType.sessionGoodbye

    /// What a received goodbye means: the link is gone, membership is not.
    static func outcome(forGoodbyeFrom _: String?) -> MeshLegacyGoodbyeOutcome {
        .disconnected
    }

    /// Always nil. There is no goodbye a departure record can be derived from — see the type's
    /// documentation for why an unsigned frame must not be able to subtract a signed member.
    static func departureRecord(forGoodbyeFrom _: String?) -> SignedDepartureRecord? {
        nil
    }
}
