// MeshDevelopmentPlan.swift
// ProximityKit/Mesh
//
// P4 item 6 (plan §10.6): what "the user developed the mesh" means while the mesh is SPLIT.
//
// §10.6 is three sentences and each one is a rule this file makes mechanical:
//
//   * *"Development in a split with merged roster > 2 is a departure (§8.3) with the bounded 15 s
//     handoff to the **reachable** members."* — the ending is chosen here, and the handoff targets
//     are read off ``MeshBranchView`` (presence), never off the roster.
//   * *"A 'final pair' is judged on the **merged derived roster**, not the connected pair (a 2/2
//     split of a 4-roster is not two final pairs)."* — ``MeshDerivedRoster/isFinalPair`` is the
//     only input to the ending, and ``MeshDevelopmentPlan/permitsTermination(_:)`` is the same
//     answer applied as an ISSUANCE gate, so no branch can sign a termination its own merged
//     roster contradicts.
//   * *"A wrongly-issued termination downgrades to the signer's departure at every receiver whose
//     roster is larger."* — that half is NOT here. It is a **read-time derivation**
//     (`MeshDerivedRoster.applyTermination`), because the union-merge must stay commutative,
//     associative and idempotent: a merge that mutated a record into a different record would
//     break all three. This file only stops a device *emitting* one it knows is wrong; the
//     receiver's safety never depends on the sender having this file.
//
// **Nothing here waits, sleeps or reads a wall clock of its own.** The 15-second window is a
// deadline computed from an instant the caller supplies, and ``handoffOutcome(finishedAt:)`` is a
// pure comparison — so the bound is asserted on an injected clock in tier 1 rather than by timing
// a real send. Nothing waits on the unreachable branch by construction: it is not in
// ``MeshDevelopmentPlan/handoffTargets`` at all.
//
// P5 owns the custody *content*. ``MeshDevelopmentPlan/handoffSummary`` names the custodians and
// counts zero items — the half P4 could honestly sign for — and P5 item 8 added
// ``MeshDevelopmentPlan/handoffSummary(handedOffItemCount:)``, which carries the count the routed
// store's own transfer produced. The plan still computes nothing about content: it is handed the
// number, because the number is a fact about a durable index this type deliberately cannot reach.

import Foundation
import FernletDomainModel

// MARK: - MeshDevelopmentEnding

/// Which ending a development is: a departure that costs one member, or a termination that ends
/// the mesh for everyone (plan §8.2's `handingOff → departed` and `handingOff → terminated`).
///
/// Decided on the **merged derived roster**, never on who is connected. Frozen English tokens:
/// they are logged verbatim beside the transition they raised and are never display copy.
nonisolated enum MeshDevelopmentEnding: String, Equatable, Sendable, CaseIterable {

    /// The mesh outlives this device: a signed `member-departure.v1`, roster > 2.
    case departure

    /// The mesh ends with this device: a signed `terminated.v1`, merged roster == 2.
    case termination

    /// The frozen wire token this ending emits.
    var membershipEvent: PayloadType {
        switch self {
        case .departure: return .meshMemberDeparture
        case .termination: return .meshTerminated
        }
    }

    /// The session event that opens the ending. Both land in ``MeshSessionState/handingOff``, so
    /// the durable mark is written before the frame goes out either way (plan §3.6).
    var requestedEvent: MeshSessionEvent {
        switch self {
        case .departure: return .departureRequested
        case .termination: return .terminationRequested(.finalPairTermination)
        }
    }

    /// The session event that closes it once the frame has been attempted.
    var sentEvent: MeshSessionEvent {
        switch self {
        case .departure: return .departureSent
        case .termination: return .terminationSent
        }
    }
}

// MARK: - MeshDevelopmentHandoffOutcome

/// How the bounded 15-second custody handoff ended (plan §10.6).
///
/// Frozen English tokens, logged verbatim. "Gave up" is a real, named answer rather than a silent
/// one: a development the user asked for always ends the local session, so the only honest thing
/// to do with an over-running handoff is to record it (R7).
nonisolated enum MeshDevelopmentHandoffOutcome: String, Equatable, Sendable, CaseIterable {

    /// Custody was offered to every reachable member inside the window.
    case completed

    /// There was nobody reachable to hand custody to — a partition of one developing alone.
    /// Not a failure: plan §10.5's accepted residual, in its custody form.
    case noReachableCustodian

    /// The window closed first. The session still ends; the handoff simply did not finish.
    case windowExpired
}

// MARK: - MeshDevelopmentPlan

/// The whole of plan §10.6's development decision, as one value derived before anything is signed.
///
/// Built from two inputs that are deliberately different things:
/// - the **merged derived roster**, which decides ``ending`` and can never be moved by a partition;
/// - the **branch view**, which decides ``handoffTargets`` and is nothing but reachability.
///
/// Keeping them apart is the point. A branch of two in a 2/2 split of a four-roster has a
/// *connected pair* of two and a *merged roster* of four: reading the wrong one is precisely the
/// mistake §10.6 forbids, and the type makes it impossible to make by accident because the
/// connected count is not a member of this type at all.
///
/// The plan is a pure value: no clock, no I/O, no isolation. ``MeshNetworkManager`` derives one at
/// the start of a development and then does what it says.
nonisolated struct MeshDevelopmentPlan: Equatable, Sendable {

    /// Plan §10.6's bounded handoff window. A hard constant, not a knob.
    static let handoffWindowSeconds: TimeInterval = 15

    /// Which ending this development is.
    let ending: MeshDevelopmentEnding

    /// The members custody is **offered** to: the **reachable** roster members other than this device
    /// (``MeshBranchView/externalPresentFingerprints``). The unreachable branch is deliberately
    /// absent — nothing waits on it, and their delivery is preserved instead by the custodians'
    /// records merging when the partition heals (§10.6).
    let handoffTargets: [String]

    /// When the handoff window opened.
    let startedAt: Date

    /// Derives the plan.
    ///
    /// - Parameters:
    ///   - roster: The **merged** derived roster. An empty roster (a device with no membership
    ///     ledger at all — the legacy pairwise session) yields a departure, which is the
    ///     fail-safe answer: a departure costs one member, a termination costs a mesh.
    ///   - branch: This device's branch view, or nil when reachability has never been evaluated —
    ///     in which case every roster member other than this device is assumed reachable, exactly
    ///     as an unpartitioned session would.
    ///   - selfFingerprint: This device.
    ///   - startedAt: The instant the handoff window opens.
    init(
        roster: MeshDerivedRoster,
        branch: MeshBranchView?,
        selfFingerprint: String,
        startedAt: Date
    ) {
        ending = roster.isFinalPair ? .termination : .departure
        if let branch {
            handoffTargets = branch.externalPresentFingerprints
        } else {
            handoffTargets = roster.memberFingerprints.filter { $0 != selfFingerprint }
        }
        self.startedAt = startedAt
    }

    /// When the handoff window closes.
    var handoffDeadline: Date { startedAt.addingTimeInterval(Self.handoffWindowSeconds) }

    /// Whether the window has closed at `now`.
    func handoffHasExpired(at now: Date) -> Bool { now >= handoffDeadline }

    /// What the handoff amounted to, judged at the instant it finished.
    ///
    /// - Parameter finishedAt: When the sends returned, on the same clock as ``startedAt``.
    func handoffOutcome(finishedAt: Date) -> MeshDevelopmentHandoffOutcome {
        if handoffHasExpired(at: finishedAt) { return .windowExpired }
        return handoffTargets.isEmpty ? .noReachableCustodian : .completed
    }

    /// The custody summary of a development that handed **nothing** over: a termination, a store
    /// that could not be read, an emit that was blocked, or a device holding no routed content.
    ///
    /// Kept beside ``handoffSummary(handedOffItemCount:)`` rather than deleted, because "zero items"
    /// is a real and common answer and spelling it at the call site would be one more place for a
    /// count to be invented.
    var handoffSummary: MeshCustodyHandoffSummary {
        handoffSummary(handedOffItemCount: 0)
    }

    /// The custody summary the departure record carries (plan §8.3's `custody-handoff summary`),
    /// with the count P5 item 8 fills.
    ///
    /// The plan stays a pure value and never computes the count itself: `handedOffItemCount` is a
    /// statement about the departing device's own durable routed index — how many items' rungs
    /// actually moved `pending → custodied(by:)` and survived the save — and this type has no store
    /// to ask. `MeshNetworkManager` transfers first and passes the answer in, so the number a
    /// departure record signs is never a prediction.
    ///
    /// - Parameter handedOffItemCount: What actually transferred. Clamped to zero by
    ///   ``MeshCustodyHandoffSummary``, never negative.
    func handoffSummary(handedOffItemCount: Int) -> MeshCustodyHandoffSummary {
        MeshCustodyHandoffSummary(
            custodianFingerprints: handoffTargets, handedOffItemCount: handedOffItemCount
        )
    }

    /// Whether a roster permits a termination to be **issued** at all (plan §10.6's second rule,
    /// applied at the signer rather than only at the receiver).
    ///
    /// The receiver is already safe without this — a termination from a signer on a larger roster
    /// downgrades to that signer's departure when the roster is derived — so this gate exists to
    /// stop a device *spending its own membership* on a record its own view contradicts. A roster
    /// this device has no ledger for (nil, or empty) permits it: the ceiling and the epoch-counter
    /// cap end a session that may never have had a membership ledger, and refusing there would
    /// silence an ending rather than prevent a wrong one.
    ///
    /// - Parameter roster: The merged derived roster, or nil when there is no ledger.
    static func permitsTermination(_ roster: MeshDerivedRoster?) -> Bool {
        guard let roster, !roster.members.isEmpty else { return true }
        return roster.memberCount <= 2
    }
}
