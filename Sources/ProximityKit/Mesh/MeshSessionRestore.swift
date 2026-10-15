// MeshSessionRestore.swift
// ProximityKit/Mesh
//
// P3 item 6 (plan §8.1, §8.2, §20.2): the durable half of the state machine — what a launch does
// with whatever `MeshSessionStore.load()` answered.
//
// The five load states map onto seven outcomes, and the split that matters is which of them may
// WRITE. `loaded` and `absent` carry a `LoadToken`; `deferred`, `refused` and `corrupt` do not, and
// this file preserves that at the outcome level rather than re-deciding it: a deferral and a
// refusal both retry (distinctly logged, because "ask again after unlock" and "custody refuses" are
// different situations), and a corrupt file is quarantined deliberately before anything is written.
// None of the three starts a session, and none of them lets a writer run.

import Foundation

// MARK: - MeshSessionRestoredDisposition

/// The shape a restored context has, as the state machine sees it (plan §8.2).
///
/// Deliberately smaller than ``MeshSessionRestoreOutcome``: the machine does not care whether the
/// file was absent or unreadable, only whether there is a session to resume, one that already
/// ended, or nothing.
nonisolated enum MeshSessionRestoredDisposition: String, Equatable, Sendable, CaseIterable {

    /// Nothing to restore — no file, or one that could not be read this time.
    case none

    /// A live context inside its ceiling: membership intact, participation stopped, resumable from
    /// the foreground through the merge path.
    case resumable

    /// The mesh itself ended (a verified termination, a final-pair termination, the epoch cap, or
    /// this device developed it).
    case terminated

    /// This device left, or was removed. The mesh may well continue without it.
    case departed

    /// The ceiling passed while the process was not running.
    case expired
}

// MARK: - MeshSessionRestoreOutcome

/// What a launch-time load means, one case per thing a launch can honestly do (plan §20.2).
///
/// | outcome | session started? | writer allowed? |
/// | --- | --- | --- |
/// | ``resumable(_:)`` | not yet — the foreground offers a resume | yes |
/// | ``terminated(_:_:)`` | never again | not needed; the file already says so |
/// | ``expired(_:)`` | never again | **yes, and it must** — the mark is written now |
/// | ``noSession`` | no | yes (a green field) |
/// | ``retryAfterUnlock(_:)`` | no | **no** |
/// | ``retryAfterRefusal(_:)`` | no | **no** |
/// | ``quarantineCorruptFile(_:)`` | no | only after the quarantine |
nonisolated enum MeshSessionRestoreOutcome: Equatable, Sendable {

    /// A live context inside its ceiling.
    case resumable(MeshSessionContext)

    /// A context that already records an ending, with the reason it records.
    case terminated(MeshSessionContext, MeshSessionTerminationReason)

    /// A live context whose ceiling passed while the process was gone. The termination mark has to
    /// be written before this device may treat it as ended by anyone else's reckoning.
    case expired(MeshSessionContext)

    /// No file: genuinely a green field.
    case noSession

    /// The load deferred (locked device, transient keychain, unreadable file). Retry later; never
    /// read as emptiness.
    case retryAfterUnlock(MeshSessionDeferral)

    /// Custody refused (plan §20.2's fifth state). Retried like a deferral and logged distinctly,
    /// because the field may well be full.
    case retryAfterRefusal(MeshSessionSealRefusal)

    /// A file exists and does not decode. Set it aside deliberately; do not overwrite it.
    case quarantineCorruptFile(MeshSessionCorruption)

    /// How the state machine should read this outcome.
    var disposition: MeshSessionRestoredDisposition {
        switch self {
        case .resumable: return .resumable
        case .expired: return .expired
        case .terminated(_, let reason): return reason.endsTheMeshForEveryone ? .terminated : .departed
        case .noSession, .retryAfterUnlock, .retryAfterRefusal, .quarantineCorruptFile: return .none
        }
    }

    /// Whether this outcome should be retried on the next unlock or foreground. Bounded by the
    /// caller — ``MeshSessionRestoreBounds/maxAttempts``.
    var isRetryable: Bool {
        switch self {
        case .retryAfterUnlock, .retryAfterRefusal: return true
        case .resumable, .terminated, .expired, .noSession, .quarantineCorruptFile: return false
        }
    }

    /// The restored context, when one was opened.
    var context: MeshSessionContext? {
        switch self {
        case .resumable(let context), .expired(let context), .terminated(let context, _): return context
        case .noSession, .retryAfterUnlock, .retryAfterRefusal, .quarantineCorruptFile: return nil
        }
    }

    /// A frozen-English log token naming the outcome. Never user copy.
    var logToken: String {
        switch self {
        case .resumable: return "resumable"
        case .terminated(_, let reason): return "terminated:\(reason.rawValue)"
        case .expired: return "expired"
        case .noSession: return "absent"
        case .retryAfterUnlock(let deferral): return "deferred:\(deferral.reason.rawValue)"
        case .retryAfterRefusal(let refusal): return "refused:\(refusal.cause.rawValue)"
        case .quarantineCorruptFile: return "corrupt"
        }
    }
}

// MARK: - MeshSessionRestoreBounds

/// Bounds on the launch restore (Power of 10 rule 2/3).
nonisolated enum MeshSessionRestoreBounds {

    /// How many times a retryable outcome is re-attempted before the device stops asking. A
    /// deferral is meant to be retried on the next unlock, not spun on — three attempts is enough
    /// to cross a first-unlock boundary and small enough that a permanently refusing custody costs
    /// three keychain reads, not a loop.
    static let maxAttempts = 3
}

// MARK: - MeshSessionRejoinBar

/// The permanent bar against re-entering one mesh (plan §8.2).
///
/// Held in memory by the session manager and **re-derived from the sealed context at every
/// launch**, which is the half that matters: a bar that lived only in memory would be lifted by a
/// force-quit, and "a developed or terminated mesh can never be rejoined" would mean "until the
/// user relaunches".
nonisolated struct MeshSessionRejoinBar: Equatable, Sendable {

    /// The mesh that may never be re-entered.
    let meshID: UUID

    /// Why. A frozen token.
    let reason: MeshSessionTerminationReason
}

// MARK: - MeshSessionRestore

/// The pure classifier from a five-state load to a seven-way launch outcome.
///
/// No I/O, no clock of its own, no store: `now` and the local fingerprint are arguments, so every
/// branch is stated as a value in a test.
nonisolated enum MeshSessionRestore {

    /// Classifies one load.
    ///
    /// The ordering inside `loaded` is deliberate: an ending that is already RECORDED wins over the
    /// ceiling, so a context that says "this device departed" is reported as departed rather than
    /// as an expiry that happens to have passed since. Only a context with no recorded ending is
    /// measured against the deadline.
    ///
    /// - Parameters:
    ///   - load: What ``MeshSessionStore/load()`` answered.
    ///   - selfFingerprint: This device's fingerprint, for the own-departure check.
    ///   - now: The current instant, for the ceiling check.
    /// - Returns: The outcome the launch must act on.
    static func outcome(
        for load: MeshSessionLoad,
        selfFingerprint: String,
        now: Date
    ) -> MeshSessionRestoreOutcome {
        switch load {
        case .absent:
            return .noSession
        case .deferred(let deferral):
            return .retryAfterUnlock(deferral)
        case .refused(let refusal):
            return .retryAfterRefusal(refusal)
        case .corrupt(let corruption):
            return .quarantineCorruptFile(corruption)
        case .loaded(let context, _):
            return outcome(forLoaded: context, selfFingerprint: selfFingerprint, now: now)
        }
    }

    /// The `loaded` half: a recorded ending first, then the ceiling, then "resumable".
    private static func outcome(
        forLoaded context: MeshSessionContext,
        selfFingerprint: String,
        now: Date
    ) -> MeshSessionRestoreOutcome {
        if let reason = context.recordedEndingReason(selfFingerprint: selfFingerprint) {
            return .terminated(context, reason)
        }
        let ceiling = MeshSessionCeiling(hardDeadline: context.hardDeadline, startedAt: context.createdAt)
        // A restore has consumed no local runtime yet, so only the signed bound can have been
        // reached while the process was gone; the monotonic bound starts counting from here.
        if ceiling.verdict(now: now, monotonicElapsed: 0).isReached {
            return .expired(context)
        }
        return .resumable(context)
    }
}
