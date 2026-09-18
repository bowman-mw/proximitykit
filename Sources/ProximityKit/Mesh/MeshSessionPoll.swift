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

// MARK: - The poll seam

extension MeshNetworkManager {

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
