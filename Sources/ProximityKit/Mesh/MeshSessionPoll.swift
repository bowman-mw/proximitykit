// MeshSessionPoll.swift
// ProximityKit/Mesh
//
// Network migration P7 item 4: the ONE poll seam the app's run policy drives, and the joiner-side
// ceiling arm it needs to mean anything.
//
// The three consumers — `enforceSessionCeiling(now:monotonicElapsed:)`, `evaluateIdleLapse(now:)`
// and `evaluatePartition(now:)` — were built on demand so that nothing spins (P3 item 6, P4 item
// 1) and had no shipping caller through P6; five doc sites promised P7 the poller. This file is
// that promise kept on ProximityKit's side: one `public` sequencing door, ceiling → idle lapse →
// partition, in that order and no other, short-circuiting when no session is live. The TIMER is the
// app's (`FernletStore` + `ProximitySessionPoller`): started and stopped with `isSessionLive`, so
// nothing here reads a clock or owns a task — the same shape as `applyRoutedAccessGate(_:now:)`.
//
// **The arm the poller was waiting for.** `startSessionCeiling(hardDeadline:startedAt:)` had two
// shipping callers — the founder and the launch restore — so every JOINER, and the yielding half of
// every symmetric founding (whose `unwindNewbornMesh()` nilled its own), held a mesh with no
// ceiling to enforce (P6 §12.3 finding 3). `armSessionCeilingFromAdoptedMeshIfNeeded(now:)` is the
// third and fourth caller: at descriptor adoption and at the admission grant, idempotent, from the
// same `createdAt + 6 h` deadline the founder signed and `routedHardDeadline` already derives.
//
// No timer, no plaintext, nothing routed, no default collapsing a verdict.

import Foundation
import FernletFoundation

// MARK: - MeshSessionPollReport

/// What one poll did — flags, never fingerprints — so the app's timer can stop itself the moment
/// the session it polls for is gone.
///
/// ## Concurrency
///
/// A `nonisolated`, `Sendable` value.
public nonisolated struct MeshSessionPollReport: Equatable, Sendable {

    /// Whether the consumers ran at all: `false` when no session was live at the poll.
    public let polled: Bool

    /// The ceiling was reached on this poll and the session ended there.
    public let ceilingReached: Bool

    /// Plan §8.2's idle window had lapsed on this poll and the lapse was applied.
    public let idleLapsed: Bool

    /// Partition detection raised an event on this poll — links lost or restored.
    public let partitionMoved: Bool

    /// `isSessionLive` after the poll: the timer's stop condition.
    public let sessionLiveAfter: Bool

    /// A poll that found no live session and ran nothing.
    public static let skipped = MeshSessionPollReport(
        polled: false, ceilingReached: false, idleLapsed: false, partitionMoved: false,
        sessionLiveAfter: false
    )

    /// Builds a report.
    ///
    /// - Parameters:
    ///   - polled: Whether the consumers ran.
    ///   - ceilingReached: Whether the ceiling ended the session on this poll.
    ///   - idleLapsed: Whether the idle window lapsed on this poll.
    ///   - partitionMoved: Whether partition detection raised an event on this poll.
    ///   - sessionLiveAfter: Whether the session is live after the poll.
    public init(
        polled: Bool, ceilingReached: Bool, idleLapsed: Bool, partitionMoved: Bool, sessionLiveAfter: Bool
    ) {
        self.polled = polled
        self.ceilingReached = ceilingReached
        self.idleLapsed = idleLapsed
        self.partitionMoved = partitionMoved
        self.sessionLiveAfter = sessionLiveAfter
    }
}

// MARK: - MeshSessionContinuationReading

/// What a background continuation needs to know about the session it is carrying: how far through
/// the ceiling this run is, and how many friends it is holding.
///
/// Network migration P8 item 6 (plan §14). Deliberately **not** part of ``MeshSessionPollReport``:
/// that value says what one POLL did — flags, never fingerprints — and exists only on a tick, while
/// this is read at two sites, the SUBMISSION (whose request carries the friend count in its
/// subtitle) and the tick (whose progress bar carries the elapsed fraction). One read serves both,
/// and a skipped poll would otherwise have had to carry three meaningless zeros.
///
/// ## Concurrency
///
/// A `nonisolated`, `Sendable` value.
public nonisolated struct MeshSessionContinuationReading: Equatable, Sendable {

    /// Seconds of local runtime since this run's ceiling was armed, measured from the monotonic
    /// origin — never the wall clock, which a time change moves backwards and which would make a
    /// continued task's progress bar retreat, the one thing the system ends a task for.
    public let elapsedSeconds: TimeInterval

    /// This run's ceiling budget in seconds, already clamped to `0 ... MeshSessionCeiling
    /// .ceilingSeconds` at construction.
    public let budgetSeconds: TimeInterval

    /// How many friends this device is connected to right now, EXCLUDING self.
    public let connectedFriendCount: Int

    /// Builds a reading.
    ///
    /// - Parameters:
    ///   - elapsedSeconds: Monotonic seconds since the ceiling was armed.
    ///   - budgetSeconds: This run's ceiling budget.
    ///   - connectedFriendCount: Friends connected, excluding self.
    public init(elapsedSeconds: TimeInterval, budgetSeconds: TimeInterval, connectedFriendCount: Int) {
        self.elapsedSeconds = elapsedSeconds
        self.budgetSeconds = budgetSeconds
        self.connectedFriendCount = connectedFriendCount
    }
}

// MARK: - The poll seam

extension MeshNetworkManager {

    /// What a background continuation may read about this session — the narrowest public surface
    /// P8 item 6 needs, and the only one it got.
    ///
    /// `sessionCeiling`, `sessionMonotonicOrigin` and `branchView` all stay internal; this answers
    /// the three scalars the app's `MeshContinuationTaskHost` needs and nothing else. **Nil means
    /// there is no live session to continue**, which is the honest answer for a host deciding
    /// whether to advance a bar at all.
    ///
    /// The friend count prefers the BRANCH's external present members — the roster members this
    /// device can actually reach, which is what "friends connected" means once a mesh is larger than
    /// a pair — and falls back to this device's committed slots, because ``branchView`` is built by
    /// partition detection and a session's first tick has none yet.
    ///
    /// - Returns: The reading, or nil when no ceiling is armed.
    public var sessionContinuationReading: MeshSessionContinuationReading? {
        guard let ceiling = sessionCeiling,
              let verdict = sessionCeilingVerdict(now: Date(), monotonicElapsed: nil) else {
            return nil
        }
        let budget = ceiling.monotonicBudgetSeconds
        let elapsed: TimeInterval
        switch verdict {
        case .live(let remainingSeconds): elapsed = max(budget - remainingSeconds, 0)
        case .reached: elapsed = budget
        }
        let friends = branchView?.externalPresentFingerprints.count
            ?? slots.filter { $0.fingerprint != nil }.count
        return MeshSessionContinuationReading(
            elapsedSeconds: elapsed, budgetSeconds: budget, connectedFriendCount: friends
        )
    }

    /// Runs the three on-demand consumers in their one order — the ceiling, then the idle lapse,
    /// then partition detection — for a live session, and nothing for a dead one (P7 item 4).
    ///
    /// The ceiling first because it can END the session: a session past its 6-hour bound is not
    /// judged idle or partitioned, it is over, and the poll returns there. The idle lapse second
    /// because it moves the state the partition detector reads. Partition last, over the live
    /// reachable set. Each consumer keeps its own guards; this seam adds only the order and the
    /// short circuit, and audits a poll only when something moved.
    ///
    /// - Parameter now: The wall-clock instant every consumer judges against; the ceiling's
    ///   monotonic bound is measured from its own held origin.
    /// - Returns: What moved, and whether the session is still live — the app's timer stops on
    ///   ``MeshSessionPollReport/sessionLiveAfter`` being `false`.
    @discardableResult
    public func pollSession(now: Date) async -> MeshSessionPollReport {
        guard isSessionLive else { return .skipped }
        let ceiling = await enforceSessionCeiling(now: now, monotonicElapsed: nil)
        let ceilingReached = ceiling?.isReached == true
        guard isSessionLive else {
            let ended = MeshSessionPollReport(
                polled: true, ceilingReached: ceilingReached, idleLapsed: false,
                partitionMoved: false, sessionLiveAfter: false
            )
            auditSessionPoll(ended, partition: .unchanged)
            return ended
        }
        let idleLapsed = evaluateIdleLapse(now: now)
        let partition = evaluatePartition(now: now)
        let report = MeshSessionPollReport(
            polled: true, ceilingReached: ceilingReached, idleLapsed: idleLapsed,
            partitionMoved: partition != .unchanged, sessionLiveAfter: isSessionLive
        )
        auditSessionPoll(report, partition: partition)
        return report
    }

    /// One audit line per poll that moved something — never one per tick.
    private func auditSessionPoll(_ report: MeshSessionPollReport, partition: MeshPartitionVerdict) {
        guard report.ceilingReached || report.idleLapsed || report.partitionMoved else { return }
        FernletAuditLog.log("mesh.sessionPoll.moved", context: [
            "ceiling": String(report.ceilingReached),
            "idle": String(report.idleLapsed),
            "partition": partition.rawValue,
            "live": String(report.sessionLiveAfter)
        ])
    }

    /// Arms this device's session ceiling from the mesh it adopted, once (P7 item 4).
    ///
    /// The founder arms at `foundMesh(_:now:)` and the launch restore from the sealed context; a
    /// joiner — and the yielding half of a symmetric founding, whose `unwindNewbornMesh()` nilled
    /// its own — held a mesh with none, so `enforceSessionCeiling` had nothing to enforce for it
    /// (P6 §12.3 finding 3). The deadline is the one every member shares,
    /// `createdAt + MeshSessionCeiling.ceilingSeconds` — exactly `routedHardDeadline`'s derivation —
    /// so the signed bound is identical across the roster and the local monotonic bound is whatever
    /// of it remains from `now`.
    ///
    /// Idempotent: a ceiling already armed is kept, because re-arming would reset the monotonic
    /// origin. A device holding no mesh arms nothing.
    ///
    /// - Parameter now: The instant this run of the session began for this device.
    /// - Returns: Whether this call armed a ceiling.
    @discardableResult
    func armSessionCeilingFromAdoptedMeshIfNeeded(now: Date) -> Bool {
        guard sessionCeiling == nil, let mesh = currentMesh else { return false }
        startSessionCeiling(
            hardDeadline: mesh.createdAt.addingTimeInterval(MeshSessionCeiling.ceilingSeconds),
            startedAt: now
        )
        FernletAuditLog.log("mesh.sessionCeiling.armedFromAdoptedMesh")
        return true
    }
}
