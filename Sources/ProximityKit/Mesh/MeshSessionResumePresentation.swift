// MeshSessionResumePresentation.swift
// ProximityKit/Mesh
//
// Network migration P7 item 5: the DECISION half of the resume surface — what the launch restore's
// outcome means to the person holding the phone, as a pure value the Friends surface renders.
//
// P6 item 7 wired `restoreSessionContextOncePerLaunch(now:)` and proved it materially real for the
// drain, and then found that nothing presented its outcome: `lastSessionRestoreOutcome`,
// `offersForegroundResume`, `restoredSessionContext` and `rejoinBar` had zero app readers, and the
// restore door answers a `Bool` on purpose because `MeshSessionRestoreOutcome` is this module's and
// the app has no business branching on it. So the branching happens HERE, once, over the outcome
// the door recorded — a seven-case enum folded into the four things a person can be told — and the
// app reads one public value, `MeshNetworkManager.sessionResumePresentation`, and forks it into
// `LocalizedStringKey` copy (`SessionResumeCopy`, the `RoutedShareRefusalCopy` shape).
//
// What is presented, per the P7 launcher's defaults: `resumable` with the foreground offer raised
// ⇒ an offer; `corrupt` ⇒ the previous session could not be reopened and nothing already saved was
// lost; `deferred` and `refused` ⇒ SILENT (the routed re-entry retries them at the next
// protected-data rise, and a launch on a locked device is not news); an ending ⇒ the mesh ENDED,
// named by how, never "failed". Nothing modal, and nothing at all while a session surface is up.
//
// What a resume IS, so the copy does not overclaim: the restore arms no radio (invariant 5) — it
// makes the ledger, the roster, the restored key advertisements and the routed store addressable —
// and the Friends tab's own discovery, now the run policy's, re-links into the SAME mesh through the
// merge path when a member is nearby. The offer therefore asks the person to keep the tab open; it
// does not promise a reconnect.

import Foundation

// MARK: - MeshSessionEndingPresentation

/// How a previous session ended, folded to what the person is told — four sentences for eight
/// frozen reasons.
public nonisolated enum MeshSessionEndingPresentation: Hashable, Sendable, CaseIterable {

    /// The mesh ended for everyone: a verified termination, a final-pair termination, the counter
    /// cap, or this device developed it.
    case ended

    /// The 6-hour ceiling passed, at either bound.
    case expired

    /// This device left the mesh.
    case youLeft

    /// This device was removed from the roster; the mesh may well continue without it.
    case youWereRemoved
}

// MARK: - MeshSessionResumePresentation

/// What the Friends surface presents about the launch restore — nothing, an offer, an ending, or a
/// file that could not be reopened.
///
/// A value, so the whole table over `MeshSessionRestoreOutcome` is tier 1
/// (`MeshSessionResumePresentationTests`), and the surface is a `switch` over four cases.
public nonisolated enum MeshSessionResumePresentation: Hashable, Sendable {

    /// Nothing to say: no restore attempted, a green field, a deferral or refusal the re-entry will
    /// retry, a resumable context whose offer has since been consumed, or a session surface already
    /// up.
    case nothing

    /// A live context inside its ceiling, with the foreground offer raised: keep the tab open and
    /// discovery will re-link into the same mesh when a member is nearby.
    case offerResume

    /// The previous session ended, and how. Named as ended, never as failed.
    case previousSessionEnded(MeshSessionEndingPresentation)

    /// A sealed context that does not decode was set aside deliberately; nothing already saved was
    /// lost.
    case previousSessionCouldNotBeReopened

    /// The decision — pure, total over every outcome case.
    ///
    /// - Parameters:
    ///   - outcome: What the last restore attempt concluded, or nil when none was attempted.
    ///   - offersForegroundResume: Whether the state machine raised the foreground offer for it.
    ///   - isInSession: Whether a session surface is up right now — which owns the tab.
    /// - Returns: What to present.
    static func presentation(
        outcome: MeshSessionRestoreOutcome?,
        offersForegroundResume: Bool,
        isInSession: Bool
    ) -> MeshSessionResumePresentation {
        guard !isInSession, let outcome else { return .nothing }
        switch outcome {
        case .resumable:
            return offersForegroundResume ? .offerResume : .nothing
        case .terminated(_, let reason):
            return .previousSessionEnded(reason.presentation)
        case .expired:
            return .previousSessionEnded(.expired)
        case .noSession, .retryAfterUnlock, .retryAfterRefusal:
            return .nothing
        case .quarantineCorruptFile:
            return .previousSessionCouldNotBeReopened
        }
    }
}

nonisolated extension MeshSessionTerminationReason {

    /// The four-way fold of the eight frozen reasons, for the person.
    var presentation: MeshSessionEndingPresentation {
        switch self {
        case .ownDeparture: return .youLeft
        case .removedFromRoster: return .youWereRemoved
        case .hardDeadlineSigned, .hardDeadlineMonotonic: return .expired
        case .verifiedTerminationRecord, .finalPairTermination, .epochCounterExhausted, .developed:
            return .ended
        }
    }
}

// MARK: - The manager's read

extension MeshNetworkManager {

    /// What the Friends surface presents about this launch's restore (P7 item 5) — the one public
    /// read over the four restore surfaces the app could not see.
    ///
    /// Derived, never stored, from `lastSessionRestoreOutcome`, `offersForegroundResume` and
    /// `isInSession`. The first two are observation-ignored, so a view samples this on appear rather
    /// than expecting a re-render; `isInSession` is observed, so a session surface coming up hides
    /// the card by itself.
    public var sessionResumePresentation: MeshSessionResumePresentation {
        MeshSessionResumePresentation.presentation(
            outcome: lastSessionRestoreOutcome,
            offersForegroundResume: offersForegroundResume,
            isInSession: isInSession
        )
    }
}
