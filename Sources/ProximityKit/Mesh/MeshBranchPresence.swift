// MeshBranchPresence.swift
// ProximityKit/Mesh
//
// P4 item 1 (plan §10.2): what a device can SEE, held apart from what it can PROVE.
//
// A partition is neither an error state nor a membership change. `MeshMembershipLedger` and
// `MeshDerivedRoster` answer "who belongs" from signed records; nothing in this file can reach
// either of them, and that is the whole design. Unreachability is **presence** — local, reversible
// and never written down — so a 2/2 split of a roster of four leaves *both* branches deriving a
// roster of four, a quorum of three, and `isFinalPair == false`.
//
// Three consequences plan §10 spells out, which this separation makes structural rather than
// remembered at each call site:
//
//   * A partition MUST NOT shrink the roster (§10.2: "presence state, not a record"; liveness
//     eviction while split is local presence only — reversible, never a membership record).
//   * A partition MUST NOT change quorum arithmetic (§10.4: a 2/2 split of a roster of four can
//     moderate nobody, because the threshold is still ⌊4/2⌋ + 1 = 3).
//   * A partition MUST NOT make a branch a "final pair" (§10.6: judged on the MERGED roster, so a
//     2/2 split of a four-roster is not two final pairs).
//
// The P3 invariant this preserves verbatim: **disconnect ≠ removal, and it holds across a partition
// of any duration, including one that outlives a process.**
//
// **Nothing here is `Codable`, deliberately.** Presence is never sealed and `MeshSessionContext`'s
// schema stays at 2 (plan §21.3). A reversible local judgement that survived a process death would
// be exactly the durable shape signed records exist to be the only instance of — so the type system
// is asked to refuse it rather than a reviewer.
//
// There is also no timer in this file and none behind it. Detection is **on demand**, in the idiom
// of `MeshNetworkManager.enforceSessionCeiling(now:monotonicElapsed:)` and `evaluateIdleLapse(now:)`
// — P7 wires the poller that calls all three (plan §21.5).

import Foundation

// MARK: - MeshMemberPresence

/// Whether a roster member is reachable from this branch right now.
///
/// **Presence, never a record.** A member is on the roster because a signed admission says so and
/// leaves it only because a signed departure or removal says so; this enum says nothing about
/// either. `temporarilyDisconnected` is the plan's own spelling (§10.2) and it is a **frozen
/// English token** — it is logged verbatim and compared as a `rawValue`, so it never localizes. Any
/// display copy for a partition (plan §18.2, still owner-gated) forks separately as a
/// `LocalizedStringKey`.
///
/// Deliberately not `Codable`: see this file's header.
nonisolated enum MeshMemberPresence: String, Equatable, Sendable, CaseIterable {

    /// The member is reachable from this branch. This device is always present to itself.
    case present

    /// The member is on the derived roster and cannot be reached right now. Reversible, local, and
    /// never a membership record.
    case temporarilyDisconnected
}

// MARK: - MeshBranchView

/// One branch's view of its own roster: who is reachable, who is `temporarilyDisconnected`, and
/// who coordinates *this* branch (plan §10.2).
///
/// Built from a ``MeshDerivedRoster`` and a set of reachable fingerprints, and it **copies** the
/// three roster answers a partition must not move — member count, quorum threshold and the
/// final-pair test — rather than re-deriving them from the reachable set. That is the point of the
/// type: a caller holding a branch view can read the branch's coordinator and the *roster's*
/// quorum from the same value and cannot accidentally compute a quorum over the branch.
///
/// Ordering is the roster's own: members are sorted by fingerprint there, and both lists here are
/// filters of that order, so ``branchCoordinatorFingerprint`` is `first` rather than a second
/// minimum with its own opinion.
nonisolated struct MeshBranchView: Equatable, Sendable {

    /// This device's fingerprint. Always treated as reachable — a device can always reach itself,
    /// including when it is the whole branch.
    let selfFingerprint: String

    /// Roster members this device can reach, in the roster's fingerprint order.
    let presentFingerprints: [String]

    /// Roster members this device cannot reach, in the roster's fingerprint order — the
    /// ``MeshMemberPresence/temporarilyDisconnected`` set. They are still members; only their
    /// reachability has changed.
    let temporarilyDisconnectedFingerprints: [String]

    /// The size of the DERIVED roster, unchanged by unreachability. Always
    /// `presentFingerprints.count + temporarilyDisconnectedFingerprints.count`.
    let rosterMemberCount: Int

    /// The roster's quorum threshold, copied verbatim from ``MeshDerivedRoster/quorumThreshold``.
    /// A partition must not change this (§10.4).
    let rosterQuorumThreshold: Int

    /// Whether the **merged derived roster** is a final pair (§10.6) — never whether this branch
    /// happens to hold two devices.
    let rosterIsFinalPair: Bool

    /// Derives a branch view.
    ///
    /// - Parameters:
    ///   - roster: The derived roster, which unreachability does not move.
    ///   - reachable: Fingerprints this device can reach right now. Entries the roster does not
    ///     name are ignored — a stranger on a socket is not a branch member.
    ///   - selfFingerprint: This device, always present.
    init(roster: MeshDerivedRoster, reachable: Set<String>, selfFingerprint: String) {
        self.selfFingerprint = selfFingerprint
        let names = roster.memberFingerprints
        let seen = reachable.union([selfFingerprint])
        presentFingerprints = names.filter { seen.contains($0) }
        temporarilyDisconnectedFingerprints = names.filter { !seen.contains($0) }
        rosterMemberCount = roster.memberCount
        rosterQuorumThreshold = roster.quorumThreshold
        rosterIsFinalPair = roster.isFinalPair
    }

    /// Whether any roster member is out of reach — the condition plan §10.2 calls a partition.
    var isPartitioned: Bool { !temporarilyDisconnectedFingerprints.isEmpty }

    /// The present members other than this device.
    var externalPresentFingerprints: [String] { presentFingerprints.filter { $0 != selfFingerprint } }

    /// Whether this is a **partition of one**: nobody external is reachable, so nobody can
    /// heartbeat and the 30-minute idle window will run to ``MeshSessionState/localIdleStop``
    /// (§10.2). A live branch of two or more stays alive instead.
    var isAlone: Bool { externalPresentFingerprints.isEmpty }

    /// How many members this branch can see, including this device.
    var branchMemberCount: Int { presentFingerprints.count }

    /// The **branch** coordinator: the lowest fingerprint *present* (§10.2), which is what scopes
    /// this branch's 15-minute rotation to itself. Nil when the roster does not name this device
    /// (a founder before its own admission record exists), which is the honest answer — a device
    /// outside the roster coordinates nothing.
    ///
    /// Two devices on the same branch compute the same value, and the two branches of a split
    /// cannot compute the same one, which is exactly why their independently minted epochs at the
    /// same counter are distinct refs that `MeshEpochAcceptance` answers `coexist` for (§21.1).
    var branchCoordinatorFingerprint: String? { presentFingerprints.first }

    /// Whether this device is the coordinator of its own branch.
    var isLocalBranchCoordinator: Bool { branchCoordinatorFingerprint == selfFingerprint }

    /// The presence of one member, or nil when the derived roster does not name them.
    ///
    /// Nil is a real third answer and not a synonym for disconnected: a departed, removed or
    /// never-admitted fingerprint has no presence, because presence is only defined over the
    /// roster.
    func presence(of fingerprint: String) -> MeshMemberPresence? {
        if presentFingerprints.contains(fingerprint) { return .present }
        if temporarilyDisconnectedFingerprints.contains(fingerprint) { return .temporarilyDisconnected }
        return nil
    }
}

// MARK: - MeshPartitionVerdict

/// What re-evaluating reachability concluded — the session event it implies, or nothing.
///
/// Frozen English tokens: logged verbatim beside the transition they raised, never display copy.
nonisolated enum MeshPartitionVerdict: String, Equatable, Sendable, CaseIterable {

    /// Reachability moved, or did not, without crossing the partition boundary. No event is raised.
    case unchanged

    /// A member the derived roster still names became unreachable while none was before:
    /// ``MeshSessionEvent/linksLost``, which lands the session in ``MeshSessionState/partitioned``.
    case linksLost

    /// Every roster member is reachable again: ``MeshSessionEvent/linksRestored``, which is a
    /// **merge** (plan §10.3), never a fresh session.
    case linksRestored

    /// The session event this verdict raises, or nil when it raises none.
    var sessionEvent: MeshSessionEvent? {
        switch self {
        case .unchanged: return nil
        case .linksLost: return .linksLost
        case .linksRestored: return .linksRestored
        }
    }
}

// MARK: - MeshPartitionDetector

/// The pure edge-detector between two branch views (plan §10.2).
///
/// ## Only the boundary is an event
///
/// A partition that *deepens* — a second member dropping off a branch that was already split —
/// raises nothing, and neither does a partial heal that leaves somebody still unreachable. Both are
/// deliberate:
///
/// - The session is already in ``MeshSessionState/partitioned``, whose `linksLost` edge is a
///   self-edge carrying no effects; re-raising it would be noise that could not re-arm the idle
///   window anyway (the window is measured from the last authenticated external heartbeat, which is
///   the honest clock for "is anybody still here").
/// - A *partial* heal must not move the session back to `activeForeground`, because a member the
///   roster still names remains out of reach — this branch is still a branch. The peer that
///   actually reappeared enters the merge path through ``MeshSessionEvent/peerCommitted``, which
///   `partitioned` already accepts, so nothing is lost by keeping `linksRestored` for a full heal.
///
/// There is no timer here and no wall clock: the verdict is a function of two views and nothing
/// else, so a forged timestamp cannot manufacture a partition or hide one.
nonisolated enum MeshPartitionDetector {

    /// Compares the previous branch view with a freshly derived one.
    ///
    /// - Parameters:
    ///   - previous: The last view this device derived, or nil when it has derived none (treated
    ///     as "nothing was unreachable", so the first evaluation of a genuinely split branch
    ///     correctly reports ``MeshPartitionVerdict/linksLost``).
    ///   - current: The view just derived.
    /// - Returns: The verdict, and therefore the event to raise.
    static func verdict(previous: MeshBranchView?, current: MeshBranchView) -> MeshPartitionVerdict {
        switch (previous?.isPartitioned ?? false, current.isPartitioned) {
        case (false, true): return .linksLost
        case (true, false): return .linksRestored
        case (false, false), (true, true): return .unchanged
        }
    }
}
