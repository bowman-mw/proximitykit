// MeshSessionCeiling.swift
// ProximityKit/Mesh
//
// P3 item 6 (plan §8.2): the 6-hour membership ceiling, guarded at BOTH bounds.
//
// `MeshSessionContext.hardDeadline` is signed into the mesh descriptor at creation and is identical
// on every member, which is what makes it enforceable across a process death — and useless on its
// own, because it is read against a wall clock the user can set. So there are two bounds and a
// session ends at whichever is reached first:
//
// - the **signed absolute** deadline (± a 120 s skew tolerance, plan §8.2), which is what a
//   forward jump trips; and
// - a **local monotonic guard** — elapsed runtime since this run began, against the budget that was
//   left when it began — which is what a backward jump cannot escape.
//
// Neither bound can extend the other: the budget is clamped to the ceiling at construction, so a
// descriptor claiming a deadline a week out still cannot buy more than six hours of runtime.

import Foundation

// MARK: - MeshSessionCeilingBound

/// Which of the two bounds ended a session. Frozen English; a log token, never display copy.
nonisolated enum MeshSessionCeilingBound: String, Equatable, Sendable, CaseIterable {

    /// The signed, absolute `hardDeadline` (plus the skew tolerance) passed.
    case signedAbsolute

    /// The local monotonic budget ran out — this run consumed the remaining ceiling.
    case localMonotonic

    /// The durable termination reason this bound writes into the sealed context.
    var terminationReason: MeshSessionTerminationReason {
        switch self {
        case .signedAbsolute: return .hardDeadlineSigned
        case .localMonotonic: return .hardDeadlineMonotonic
        }
    }
}

// MARK: - MeshSessionCeilingVerdict

/// The answer to "may this session still run?".
nonisolated enum MeshSessionCeilingVerdict: Equatable, Sendable {

    /// Still live, with the smaller of the two bounds' remaining seconds — never negative.
    case live(remainingSeconds: TimeInterval)

    /// The ceiling was reached, at this bound.
    case reached(MeshSessionCeilingBound)

    /// Convenience for call sites that only care whether the session ended.
    var isReached: Bool {
        if case .reached = self { return true }
        return false
    }
}

// MARK: - MeshSessionCeiling

/// The dual-bound ceiling guard for one run of one session (plan §8.2).
///
/// ## Why two bounds
///
/// | attack / accident | signed absolute | local monotonic |
/// | --- | --- | --- |
/// | wall clock set BACKWARDS mid-session | says hours remain | keeps counting — **ends the session** |
/// | wall clock set FORWARDS past the deadline | **ends the session** | says time remains |
/// | small skew between two members' clocks | ± 120 s tolerance absorbs it | unaffected |
/// | a descriptor claiming a far-future deadline | would grant days | budget clamped to 6 h |
///
/// ## Concurrency
///
/// A `nonisolated`, `Sendable` value with no clock inside it: both instants are arguments to
/// ``verdict(now:monotonicElapsed:)``, so tests state time rather than wait for it, exactly like
/// `MeshEpochKeyring` and `MeshRotationTriggerQueue`.
nonisolated struct MeshSessionCeiling: Equatable, Sendable {

    /// Plan §8.2's ceiling: six hours of membership, whatever any clock says.
    static let ceilingSeconds: TimeInterval = 6 * 60 * 60

    /// Plan §8.2's ± 120 s tolerance on the signed absolute deadline, so two members whose clocks
    /// differ slightly do not end a session at visibly different moments.
    static let skewToleranceSeconds: TimeInterval = 120

    /// The signed, absolute deadline from the mesh descriptor — identical on every member.
    let hardDeadline: Date

    /// How many seconds of local runtime this run may consume before the monotonic bound is
    /// reached. Computed at construction from the deadline and the instant the run began, clamped
    /// to `0 ... ceilingSeconds`.
    let monotonicBudgetSeconds: TimeInterval

    /// Builds the guard for one run.
    ///
    /// - Parameters:
    ///   - hardDeadline: The signed absolute deadline (`createdAt + 6 h`).
    ///   - startedAt: The wall-clock instant this run began — session creation, or the restore that
    ///     brought a session back. Read ONCE, here: every later reading is monotonic, which is what
    ///     stops a clock change from moving the budget.
    init(hardDeadline: Date, startedAt: Date) {
        self.hardDeadline = hardDeadline
        let remaining = hardDeadline.timeIntervalSince(startedAt)
        monotonicBudgetSeconds = min(max(remaining, 0), Self.ceilingSeconds)
    }

    /// Judges the session against both bounds.
    ///
    /// The monotonic bound is checked FIRST on purpose: it is the one a hostile or careless clock
    /// cannot lengthen, so a session that has used its budget ends even while the wall clock claims
    /// it is still yesterday.
    ///
    /// - Parameters:
    ///   - now: The current wall-clock instant, for the signed bound.
    ///   - monotonicElapsed: Seconds of local runtime since `startedAt`, from a clock that does not
    ///     move when the wall clock does. Negative input is treated as zero — a monotonic source
    ///     that ran backwards is a broken reading, never a licence to extend.
    /// - Returns: ``MeshSessionCeilingVerdict/live(remainingSeconds:)`` or the bound that was
    ///   reached.
    func verdict(now: Date, monotonicElapsed: TimeInterval) -> MeshSessionCeilingVerdict {
        let elapsed = max(monotonicElapsed, 0)
        let monotonicRemaining = monotonicBudgetSeconds - elapsed
        guard monotonicRemaining > 0 else { return .reached(.localMonotonic) }
        let signedRemaining = hardDeadline
            .addingTimeInterval(Self.skewToleranceSeconds)
            .timeIntervalSince(now)
        guard signedRemaining > 0 else { return .reached(.signedAbsolute) }
        return .live(remainingSeconds: min(monotonicRemaining, signedRemaining))
    }
}
