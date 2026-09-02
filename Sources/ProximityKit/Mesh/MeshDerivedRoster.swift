import Foundation

// MARK: - Derived roster (plan §8.1, §9, §10.3)
//
// `roster = admitted − departed − removed`, derived on every read and stored nowhere. The two
// halves below are the whole membership algebra:
//
//   * ``MeshMembershipRecordSet`` — a bounded, deduplicated, deterministically ordered set of one
//     record kind, whose `merging` is commutative, associative and idempotent *including* its cap.
//   * ``MeshDerivedRoster`` — the pure function from a ledger to who is in, who is barred, and
//     whether the mesh still exists.
//
// Two devices that have seen the same records agree on the roster no matter what order they saw
// them in, which is the property plan §10.3 leans on when it says every reconnect is a merge.

/// A bounded grow-only set of one kind of membership record.
///
/// Three properties make it safe to merge two of these blind, and all three are tested:
/// - **Deduplicated by member.** At most one record per `memberFingerprint` survives — the earliest
///   under ``MeshMembershipRecordOrder``. Two devices recording the same departure spend one slot.
/// - **Deterministically ordered.** Contents are always sorted by that same total order, so equal
///   sets are `==` regardless of insertion order and the truncation below is not order-dependent.
/// - **Capped without trapping.** Past `Record.setCapacity` the *latest* records are dropped, never
///   the earliest. Keeping the k smallest of a set is what makes the cap survive merging:
///   `trunc(trunc(A) ∪ trunc(B)) == trunc(A ∪ B)`, so a capped merge is still associative and
///   commutative. Nothing throws and nothing traps; a caller that needs to know checks
///   ``isAtCapacity``.
///
/// Caps are enforced on `init`, on insert, on merge **and on decode** — a set read back from a
/// sealed sidecar or a peer's gossip is untrusted input like any other.
///
/// A record in a set is not a *verified* record. Signature checking belongs to the layer that owns
/// the crypto purpose; inserting unverified records here would put an unverified member on a roster.
nonisolated struct MeshMembershipRecordSet<Record: MeshMembershipRecord>: Codable, Equatable, Sendable {

    /// Records read off a decoder or handed to an initializer before deduplication, so a hostile
    /// input cannot make normalization do unbounded work. Four times the cap clears any honest
    /// merge (two full sets is two times) with room.
    static var maxInputRecords: Int { Record.setCapacity * 4 }

    private let ordered: [Record]

    /// The empty set — the correct starting point for a device that has joined nothing.
    static var empty: MeshMembershipRecordSet<Record> { MeshMembershipRecordSet() }

    /// An empty set.
    init() {
        ordered = []
    }

    /// Builds a set from records in any order, deduplicating, sorting and capping them.
    init(_ records: [Record]) {
        ordered = Self.normalized(records)
    }

    /// Decodes a set, applying exactly the same normalization the initializer does.
    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        ordered = Self.normalized(try container.decode([Record].self))
    }

    /// Encodes the normalized contents as a plain array.
    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(ordered)
    }

    /// The records, in the set's deterministic order (earliest first).
    var all: [Record] { ordered }

    /// How many records the set holds.
    var count: Int { ordered.count }

    /// Whether the set holds nothing.
    var isEmpty: Bool { ordered.isEmpty }

    /// Whether the set is full, so a caller can report a dropped record instead of wondering.
    var isAtCapacity: Bool { ordered.count >= Record.setCapacity }

    /// The members the set has a record for.
    var memberFingerprints: Set<String> { Set(ordered.map(\.memberFingerprint)) }

    /// The earliest record, which for a one-record kind (termination) is *the* record.
    var earliest: Record? { ordered.first }

    /// Whether the set holds a record about `fingerprint`.
    func contains(fingerprint: String) -> Bool {
        ordered.contains { $0.memberFingerprint == fingerprint }
    }

    /// The set with `record` added. An existing, earlier record for the same member wins.
    func inserting(_ record: Record) -> MeshMembershipRecordSet<Record> {
        MeshMembershipRecordSet(ordered + [record])
    }

    /// The union of two sets — the merge plan §10.3 runs on every reconnect.
    func merging(_ other: MeshMembershipRecordSet<Record>) -> MeshMembershipRecordSet<Record> {
        MeshMembershipRecordSet(ordered + other.ordered)
    }

    /// Deduplicates by member (earliest wins), sorts by the total order, then keeps the first
    /// `Record.setCapacity`.
    private static func normalized(_ records: [Record]) -> [Record] {
        var earliestByMember: [String: Record] = [:]
        for record in records.prefix(Self.maxInputRecords) {
            guard let existing = earliestByMember[record.memberFingerprint] else {
                earliestByMember[record.memberFingerprint] = record
                continue
            }
            if MeshMembershipRecordOrder.precedes(record, existing) {
                earliestByMember[record.memberFingerprint] = record
            }
        }
        let sorted = earliestByMember.values.sorted(by: MeshMembershipRecordOrder.precedes)
        return Array(sorted.prefix(Record.setCapacity))
    }
}

// MARK: - MeshMembershipLedger

/// Everything a device knows about who belongs to one mesh: the four record sets, and nothing else.
///
/// This is the union-mergeable half of plan §8.1's `MeshSessionContext` — deliberately separated
/// from it, because the context also carries a clock (`createdAt`, `hardDeadline`), a routing digest
/// and a persistence story, none of which union-merge. The ledger is pure value data with a pure
/// merge, so the convergence property tests need no store and no transport.
///
/// **Merging is the only way two views combine.** There is no "apply a record to a roster" path:
/// records go into sets, sets union, the roster is re-derived. That is what makes reconnect, merge
/// after a partition, and reload after a process death literally the same code path (plan §10.3).
nonisolated struct MeshMembershipLedger: Codable, Equatable, Sendable {

    /// Members admitted over the life of the mesh.
    var admissions: MeshMembershipRecordSet<SignedAdmissionRecord>
    /// Members that left of their own accord.
    var departures: MeshMembershipRecordSet<SignedDepartureRecord>
    /// Members voted out with a completed quorum.
    var removals: MeshMembershipRecordSet<SignedRemovalRecord>
    /// The termination record, held as a one-element set so it merges like everything else.
    var terminations: MeshMembershipRecordSet<SignedTerminationRecord>

    /// A ledger that knows nothing — the state before a mesh exists.
    static var empty: MeshMembershipLedger { MeshMembershipLedger() }

    /// Builds a ledger from any combination of record sets.
    init(
        admissions: MeshMembershipRecordSet<SignedAdmissionRecord> = .empty,
        departures: MeshMembershipRecordSet<SignedDepartureRecord> = .empty,
        removals: MeshMembershipRecordSet<SignedRemovalRecord> = .empty,
        terminations: MeshMembershipRecordSet<SignedTerminationRecord> = .empty
    ) {
        self.admissions = admissions
        self.departures = departures
        self.removals = removals
        self.terminations = terminations
    }

    /// The termination record, if one has been seen.
    var termination: SignedTerminationRecord? { terminations.earliest }

    /// The union of two ledgers: set union in all four kinds. Commutative, associative, idempotent.
    func merging(_ other: MeshMembershipLedger) -> MeshMembershipLedger {
        MeshMembershipLedger(
            admissions: admissions.merging(other.admissions),
            departures: departures.merging(other.departures),
            removals: removals.merging(other.removals),
            terminations: terminations.merging(other.terminations)
        )
    }

    /// Who is in the mesh right now, derived fresh (plan §8.1: the roster is never stored).
    var derivedRoster: MeshDerivedRoster { MeshDerivedRoster(ledger: self) }
}

// MARK: - MeshRosterStatus

/// Whether a derived roster describes a mesh that still exists.
nonisolated enum MeshRosterStatus: String, Codable, Equatable, Sendable {
    /// The mesh is live; `members` is who belongs.
    case active
    /// A final-pair member ended the mesh. `members` is empty and can never refill.
    case terminated
}

// MARK: - MeshRosterMember

/// One member of a derived roster: the fingerprint the records key on, the signing key the
/// transport judges introductions against, and when they were admitted.
///
/// The signing key is what lets a removal name a *key* rather than only a fingerprint — the gap
/// plan §20.1 records, where `MeshIntroductionRoster.barred` had to stay empty because the manager
/// held no key for a member it had dropped. Here the admission record still carries it.
nonisolated struct MeshRosterMember: Identifiable, Equatable, Sendable {
    /// The roster keys on fingerprint, as every membership record does.
    var id: String { fingerprint }
    /// The member's identity fingerprint.
    let fingerprint: String
    /// The member's Ed25519 signing public key, taken from their admission record.
    let signingPublicKey: Data
    /// When the admission record says they were admitted.
    let admittedAt: Date
}

// MARK: - MeshDerivedRoster

/// The pure function `admitted − departed − removed`, plus what the rest of the mesh reads off it.
///
/// Derived on every read and stored nowhere (plan §8.1). Two devices holding equal ledgers produce
/// equal rosters, in the same order: members and barred are sorted by fingerprint, so the
/// coordinator election, the quorum arithmetic and the transport's roster are all deterministic
/// functions of the merged records rather than of who connected first.
///
/// Three derivations that look like policy but are arithmetic, and belong here rather than in a
/// manager that could hold a different opinion per device:
/// - **Coordinator** = the lowest fingerprint present (plan §8.4, matching the existing election).
/// - **Quorum** = ⌊|members|/2⌋ + 1 (plan §10.4), which is why a 2/2 split can moderate nobody.
/// - **Termination** is applied here, not at merge: a termination whose signer is still on a roster
///   larger than two downgrades to that signer's departure (plan §8.3), and a termination signed by
///   somebody who is not a member is ignored outright.
nonisolated struct MeshDerivedRoster: Equatable, Sendable {

    /// Who belongs, sorted by fingerprint. Empty once the mesh is terminated.
    let members: [MeshRosterMember]

    /// Admitted members who are no longer in: departed, removed, or the downgraded terminator.
    /// Sorted by fingerprint. This is what fills the transport's barred list.
    let barred: [MeshRosterMember]

    /// Whether the mesh still exists.
    let status: MeshRosterStatus

    /// The empty roster — no admissions, so nobody is a member. Every introduction against it is a
    /// stranger, which is the right answer for a device that has joined nothing.
    static var empty: MeshDerivedRoster { MeshDerivedRoster(ledger: .empty) }

    /// Derives the roster from a ledger.
    init(ledger: MeshMembershipLedger) {
        let admitted = Self.admittedMembers(ledger.admissions)
        let excluded = ledger.departures.memberFingerprints.union(ledger.removals.memberFingerprints)
        let survivors = admitted.filter { !excluded.contains($0.fingerprint) }
        let outcome = Self.applyTermination(ledger.termination, to: survivors)
        let surviving = Set(outcome.members.map(\.fingerprint))
        members = outcome.members
        barred = admitted.filter { !surviving.contains($0.fingerprint) }
        status = outcome.status
    }

    /// How many members belong.
    var memberCount: Int { members.count }

    /// The member fingerprints, in the roster's deterministic order.
    var memberFingerprints: [String] { members.map(\.fingerprint) }

    /// Votes needed to remove somebody: ⌊|members|/2⌋ + 1 (plan §10.4). At least one, always, so a
    /// caller never reads "zero votes are enough" off an empty roster.
    var quorumThreshold: Int { max(1, members.count / 2 + 1) }

    /// Whether this is the final pair — the roster size that makes a termination a termination
    /// rather than a departure (plan §10.6). Judged on the derived roster, never on who is connected.
    var isFinalPair: Bool { status == .active && members.count == 2 }

    /// The deterministic coordinator: the lowest fingerprint on the roster, or nil when nobody is.
    var coordinatorFingerprint: String? { members.first?.fingerprint }

    /// Whether `fingerprint` is a member right now.
    func contains(fingerprint: String) -> Bool {
        members.contains { $0.fingerprint == fingerprint }
    }

    /// The roster in the shape the QUIC transport judges introductions against.
    ///
    /// Both lists are keys, not fingerprints, which is what makes `barred` a real answer rather than
    /// the empty list the live manager used to fall back to (plan §20.1). Barred wins over member
    /// inside ``MeshIntroductionRoster``, and the two lists here are disjoint by construction anyway.
    ///
    /// This is the **shipping** answer from P3 item 7 on: `MeshIntroductionAuthority.roster` is
    /// this function, so a peer holding a verified removal or departure record is refused at the
    /// introduction as ``MeshRosterVerdict/barred`` — named — rather than falling out of `members`
    /// and refusing as an anonymous stranger.
    ///
    /// - Parameter additionalBarred: Keys to bar on top of the derived ones. Only ever ADDS a
    ///   refusal (barred wins over member), so it cannot open a door the records closed; the
    ///   diagnostic chaos hook is its one caller.
    func introductionRoster(additionalBarred: [Data] = []) -> MeshIntroductionRoster {
        MeshIntroductionRoster(
            members: members.map(\.signingPublicKey),
            barred: barred.map(\.signingPublicKey) + additionalBarred
        )
    }

    /// The lifetime-admitted members: the earliest ``MeshMembershipBounds/maxRosterMembers``
    /// admissions, sorted by fingerprint.
    ///
    /// The roster cap (8) is tighter than the admission-record cap (16), so it is applied here, over
    /// the record set's own deterministic order — a ninth admission never displaces one of the first
    /// eight, on any device.
    private static func admittedMembers(
        _ admissions: MeshMembershipRecordSet<SignedAdmissionRecord>
    ) -> [MeshRosterMember] {
        admissions.all
            .prefix(MeshMembershipBounds.maxRosterMembers)
            .map {
                MeshRosterMember(
                    fingerprint: $0.memberFingerprint,
                    signingPublicKey: $0.signingPublicKey,
                    admittedAt: $0.occurredAt
                )
            }
            .sorted { $0.fingerprint < $1.fingerprint }
    }

    /// Applies plan §8.3's termination rule to the surviving members.
    ///
    /// A termination signed by a non-member is ignored: a stranger, a departed member or a removed
    /// member must not be able to end a mesh they are not in. Otherwise the merged roster decides —
    /// two or fewer survivors is a real final pair and the mesh ends; more means the signer was
    /// reading a partition, and the record costs them their own membership and nobody else's.
    private static func applyTermination(
        _ record: SignedTerminationRecord?,
        to survivors: [MeshRosterMember]
    ) -> (members: [MeshRosterMember], status: MeshRosterStatus) {
        guard let record,
              survivors.contains(where: { $0.fingerprint == record.memberFingerprint }) else {
            return (survivors, .active)
        }
        guard survivors.count > 2 else { return ([], .terminated) }
        return (survivors.filter { $0.fingerprint != record.memberFingerprint }, .active)
    }
}
