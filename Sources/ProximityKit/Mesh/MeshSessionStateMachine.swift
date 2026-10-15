// MeshSessionStateMachine.swift
// ProximityKit/Mesh
//
// P3 item 6 (plan §8.2): the session lifecycle as a value.
//
// Everything here is pure. `transition(from:on:)` is a total function over (state, event): every
// pair either MOVES to a named state carrying an ordered effect list, or is REFUSED with a named
// reason. There is no third answer and no trap — a state machine that crashed on an unexpected
// event would be a remotely reachable crash, because most of these events arrive from the wire.
//
// The effects are the whole of the side-effect story, and their ORDER is the contract: plan §3.6
// says nothing is acknowledged before it is durable, so `.persistContext` is placed ahead of every
// effect that tells anybody anything, and the performer abandons the remainder of the list the
// moment one fails. There is deliberately no "emit a membership frame" effect — a departure or a
// termination has to reach the wire BEFORE the transport is torn down, which only an `await` at
// the call site can guarantee (see `MeshNetworkManager.leaveSessionAfterNotifyingPeers()`).

import Foundation

// MARK: - MeshSessionState

/// The ten states one device's participation in a mesh session can be in (plan §8.2).
///
/// Membership and connectivity are different things (invariant 1) and this enum is where that is
/// visible: ``partitioned`` and ``localIdleStop`` are states in which this device is still a
/// *member* — its records stand, its roster entry stands — and only its live participation has
/// stopped. Losing sockets never reaches ``departed``, ``terminated`` or ``expired``; only a signed
/// record or the ceiling does.
nonisolated enum MeshSessionState: String, Codable, Equatable, Sendable, CaseIterable {

    /// No session. The only state a session may be started from, and the state a restore begins in.
    case idle

    /// A session has been founded or joined and nothing has committed yet.
    case joining

    /// Live, in the foreground, with at least one committed peer.
    case activeForeground

    /// Live with the scene backgrounded and a continued-processing task running (plan §14).
    case continuingInBackground

    /// Links lost while roster peers remain. **Still a member**: the 30-minute idle timer runs, and
    /// a restored link is a merge (plan §10.3), never a fresh session.
    case partitioned

    /// Local participation stopped after the idle window — radios and CPT down, membership intact.
    /// Resume within the ceiling is offered from the foreground, and it goes through the merge path.
    case localIdleStop

    /// The user is developing, departing or ending the mesh: the durable half has been written and
    /// the frame that tells the peers has not been sent yet.
    case handingOff

    /// This device is no longer a member: its own signed departure was sent, or a verified removal
    /// record named it. The mesh may well continue without it.
    case departed

    /// The mesh itself ended — a verified `terminated.v1`, a final-pair termination, or the epoch
    /// counter cap (plan §8.4).
    case terminated

    /// The 6-hour ceiling was reached at one of its two bounds (plan §8.2).
    case expired

    /// Whether this state is terminal. A terminal state accepts no event at all: a developed or
    /// terminated mesh can never be rejoined, and a restart must not resurrect one.
    var hasEnded: Bool {
        switch self {
        case .departed, .terminated, .expired: return true
        case .idle, .joining, .activeForeground, .continuingInBackground,
             .partitioned, .localIdleStop, .handingOff: return false
        }
    }

    /// Whether a session exists in this state — true everywhere except ``idle`` and the terminal
    /// three. Used by the ceiling, which may be reached from any live state.
    var isLive: Bool { self != .idle && !hasEnded }
}

// MARK: - MeshSessionEvent

/// Everything that can move a session (plan §8.2's edge labels, plus the two the prose adds:
/// the ceiling and the launch restore).
///
/// Frozen vocabulary, never display copy. The associated values are all frozen tokens too, so an
/// event can be logged verbatim.
nonisolated enum MeshSessionEvent: Equatable, Sendable {

    /// The user created a mesh (foreground).
    case founded

    /// This device's admission into an existing mesh was verified (foreground).
    case joined

    /// A peer committed. The first one makes a joining session active; a later one changes nothing,
    /// and one arriving in ``MeshSessionState/partitioned`` heals the partition.
    case peerCommitted

    /// The scene backgrounded with a continued-processing task running.
    case backgrounded

    /// The scene came back to the foreground.
    case foregrounded

    /// The transport lost its links while roster peers remain. **Not a removal** — no record is
    /// minted, and the derived roster does not move.
    case linksLost

    /// Links came back. The resume is a merge (plan §10.3).
    case linksRestored

    /// The idle window elapsed with no authenticated external heartbeat: local participation stops,
    /// membership does not.
    case idleLapsed

    /// The user resumed from the foreground after an idle lapse. Deliberately the same mechanism as
    /// a partition heal — it enters the merge path, never a fresh session.
    case resumedAfterLapse

    /// The user developed the mesh. A permanent rejoin bar (plan §8.2).
    case developed

    /// This device decided to leave and has written the durable half; the signed departure has not
    /// been sent yet.
    case departureRequested

    /// This device's signed departure reached the wire.
    case departureSent

    /// This device decided the mesh ends — a final-pair termination, or the epoch counter cap.
    case terminationRequested(MeshSessionTerminationReason)

    /// This device's signed `terminated.v1` reached the wire.
    case terminationSent

    /// A peer's `terminated.v1` verified against the merged roster (plan §8.3).
    case terminationVerified

    /// A verified removal record named this device. Involuntary, and terminal for this device only
    /// — the mesh carries on, which is why it lands in ``MeshSessionState/departed``.
    case removed

    /// The 6-hour ceiling was reached, at the bound that noticed first.
    case hardDeadlineReached(MeshSessionCeilingBound)

    /// A sealed context was loaded at launch and classified. Legal only from
    /// ``MeshSessionState/idle`` — a running session does not get re-restored.
    case contextRestored(MeshSessionRestoredDisposition)

    /// The durable termination reason this event implies, or nil when it does not end anything.
    ///
    /// The one place the reason is decided, so the value written into the sealed context and the
    /// value logged beside the transition can never disagree.
    var terminationReason: MeshSessionTerminationReason? {
        switch self {
        case .developed: return .developed
        case .departureRequested: return .ownDeparture
        case .removed: return .removedFromRoster
        case .terminationVerified: return .verifiedTerminationRecord
        case .terminationRequested(let reason): return reason
        case .hardDeadlineReached(let bound): return bound.terminationReason
        case .contextRestored(let disposition):
            // A restore only WRITES a reason for the one disposition that discovered something new
            // — a ceiling that passed while the process was gone. Every other ending was already
            // recorded in the file this restore just read.
            return disposition == .expired ? .hardDeadlineSigned : nil
        case .founded, .joined, .peerCommitted, .backgrounded, .foregrounded, .linksLost,
             .linksRestored, .idleLapsed, .resumedAfterLapse, .departureSent, .terminationSent:
            return nil
        }
    }
}

// MARK: - MeshSessionEffect

/// What the owner must do when a transition is taken, in the order given.
///
/// Ordering is the durable-before-acknowledged rule made mechanical (plan §3.6): ``persistContext``
/// precedes every effect that would tell anybody anything, and the performer abandons the rest of
/// the list when one fails. Nothing here emits a membership frame — see the file header.
nonisolated enum MeshSessionEffect: String, Equatable, Sendable, CaseIterable {

    /// Stage `developedLocally` plus the durable termination mark for the context about to be saved.
    case markDeveloped

    /// Stage the durable termination mark (reason from the event) for the context about to be saved.
    case markTerminated

    /// Save the sealed context through the ONE writer. A failure abandons the remaining effects.
    case persistContext

    /// Enter the merge path: keep the existing session and reconcile ledgers and epochs with the
    /// peer that reappeared (plan §10.3). Never a fresh session, never a silent re-key.
    case beginMerge

    /// Bring the radios back up.
    case startParticipation

    /// Take the radios (and any continued-processing task) down. Local participation only.
    case stopParticipation

    /// Arm the idle window that ends in ``MeshSessionEvent/idleLapsed``.
    case armIdleTimer

    /// Disarm the idle window.
    case clearIdleTimer

    /// Tell the foreground it may offer a resume, which will take the merge path.
    case offerForegroundResume
}

// MARK: - MeshSessionTransitionRejection

/// Why a (state, event) pair is not an edge. Every non-edge names itself; none of them traps.
///
/// Frozen English diagnostics, read by a developer in a log — never user copy.
nonisolated enum MeshSessionTransitionRejection: String, Equatable, Sendable, CaseIterable {

    /// The session already ended (departed, terminated or expired). The permanent rejoin bar.
    case sessionAlreadyEnded

    /// There is no session, and the event only means something inside one.
    case noSessionYet

    /// A session is already running and the event would start a second one.
    case sessionAlreadyStarted

    /// A legal event arriving in a state that has no edge for it.
    case eventNotApplicableInState

    /// A launch restore arrived outside ``MeshSessionState/idle``.
    case restoreOnlyFromIdle

    /// Frozen English for the diagnostic surface.
    var diagnosticDescription: String {
        switch self {
        case .sessionAlreadyEnded: return "The session has ended and can never be rejoined."
        case .noSessionYet: return "There is no session for this event to apply to."
        case .sessionAlreadyStarted: return "A session is already running."
        case .eventNotApplicableInState: return "That event has no edge from this state."
        case .restoreOnlyFromIdle: return "A restored context only applies before a session starts."
        }
    }
}

// MARK: - MeshSessionTransition

/// The result of offering an event to the machine: a move with effects, or a named refusal.
nonisolated enum MeshSessionTransition: Equatable, Sendable {

    /// The edge exists. `to` may equal the current state (a deliberate self-edge, such as a second
    /// peer committing while already active).
    case moved(to: MeshSessionState, effects: [MeshSessionEffect])

    /// The pair is not an edge, and here is which rule says so.
    case rejected(MeshSessionTransitionRejection)

    /// The state after the transition, or nil when it was refused.
    var nextState: MeshSessionState? {
        if case .moved(let state, _) = self { return state }
        return nil
    }

    /// The effects to perform, in order. Empty for a refusal.
    var effects: [MeshSessionEffect] {
        if case .moved(_, let effects) = self { return effects }
        return []
    }
}

// MARK: - MeshSessionStateMachine

/// Plan §8.2's state machine, as a pure total function.
///
/// Split one function per state because a single `switch` over 10 states × 18 events is both past
/// Power of 10's 60-line limit and unreadable. The two events that behave the same from *every*
/// state — the ceiling and the launch restore — are handled once, before the per-state split, so
/// they cannot drift apart across seven copies.
nonisolated enum MeshSessionStateMachine {

    /// The most effects any single transition carries, so a performer's loop is bounded by a
    /// constant rather than by whatever the machine returned (Power of 10 rule 2).
    static let maxEffectsPerTransition = 6

    /// Offers `event` to the machine.
    ///
    /// - Parameters:
    ///   - state: The current state.
    ///   - event: What happened.
    /// - Returns: The edge taken, with its ordered effects, or a named refusal.
    static func transition(from state: MeshSessionState, on event: MeshSessionEvent) -> MeshSessionTransition {
        // The ended check comes FIRST, ahead of even the restore: a terminal state's refusal is
        // the load-bearing one ("a developed or terminated mesh can never be rejoined"), and
        // reporting a restore offered to it as merely "restore only from idle" would name the
        // weaker rule for the stronger situation.
        guard !state.hasEnded else { return .rejected(.sessionAlreadyEnded) }
        if case .contextRestored(let disposition) = event {
            guard state == .idle else { return .rejected(.restoreOnlyFromIdle) }
            return restored(disposition)
        }
        if case .hardDeadlineReached = event {
            guard state.isLive else { return .rejected(.noSessionYet) }
            return .moved(to: .expired, effects: [.markTerminated, .persistContext, .stopParticipation])
        }
        if let ending = ending(from: state, on: event) { return ending }
        switch state {
        case .idle: return fromIdle(event)
        case .joining: return fromJoining(event)
        case .activeForeground: return fromActiveForeground(event)
        case .continuingInBackground: return fromContinuingInBackground(event)
        case .partitioned: return fromPartitioned(event)
        case .localIdleStop: return fromLocalIdleStop(event)
        case .handingOff: return fromHandingOff(event)
        case .departed, .terminated, .expired: return .rejected(.sessionAlreadyEnded)
        }
    }

    /// The launch restore, which is only ever offered from ``MeshSessionState/idle``.
    ///
    /// A resumable context lands in ``MeshSessionState/localIdleStop`` rather than anything active:
    /// a relaunch never auto-reconnects (invariant 5), so the honest state is "membership intact,
    /// participation stopped, the foreground may offer a resume". The already-terminated
    /// dispositions need no save — the file already says so — while an expired one does, which is
    /// why only it carries ``MeshSessionEffect/persistContext``.
    private static func restored(_ disposition: MeshSessionRestoredDisposition) -> MeshSessionTransition {
        switch disposition {
        case .none:
            return .moved(to: .idle, effects: [])
        case .resumable:
            return .moved(to: .localIdleStop, effects: [.offerForegroundResume])
        case .terminated:
            return .moved(to: .terminated, effects: [])
        case .departed:
            return .moved(to: .departed, effects: [])
        case .expired:
            return .moved(to: .expired, effects: [.markTerminated, .persistContext])
        }
    }

    /// The endings that can be reached from **any** live state, handled once (plan §8.2's
    /// `activeForeground → handingOff` and `partitioned → handingOff`, generalised to every live
    /// state because a background or idle-stopped session can be developed or removed too).
    ///
    /// - Returns: The transition, or nil when `event` is not an ending.
    private static func ending(
        from state: MeshSessionState, on event: MeshSessionEvent
    ) -> MeshSessionTransition? {
        guard state.isLive else { return nil }
        switch event {
        case .developed:
            return .moved(to: .handingOff, effects: [.markDeveloped, .persistContext, .stopParticipation])
        case .departureRequested, .terminationRequested:
            return .moved(to: .handingOff, effects: [.markTerminated, .persistContext])
        case .terminationVerified:
            return .moved(to: .terminated, effects: [.markTerminated, .persistContext, .stopParticipation])
        case .removed:
            return .moved(to: .departed, effects: [.markTerminated, .persistContext, .stopParticipation])
        default:
            return nil
        }
    }

    /// No session yet: only a create or a join is an edge.
    private static func fromIdle(_ event: MeshSessionEvent) -> MeshSessionTransition {
        switch event {
        case .founded, .joined:
            return .moved(to: .joining, effects: [.persistContext])
        default:
            return .rejected(.noSessionYet)
        }
    }

    /// Founded or admitted, nothing committed yet.
    private static func fromJoining(_ event: MeshSessionEvent) -> MeshSessionTransition {
        switch event {
        case .peerCommitted:
            return .moved(to: .activeForeground, effects: [.persistContext, .clearIdleTimer])
        case .linksLost:
            // A link lost before anything committed is not a partition: there is no roster peer to
            // be partitioned from, so the session simply keeps waiting.
            return .moved(to: .joining, effects: [])
        case .founded, .joined:
            return .rejected(.sessionAlreadyStarted)
        default:
            return .rejected(.eventNotApplicableInState)
        }
    }

    /// Live in the foreground.
    private static func fromActiveForeground(_ event: MeshSessionEvent) -> MeshSessionTransition {
        switch event {
        case .peerCommitted, .linksRestored, .foregrounded:
            return .moved(to: .activeForeground, effects: [])
        case .backgrounded:
            return .moved(to: .continuingInBackground, effects: [])
        case .linksLost:
            return .moved(to: .partitioned, effects: [.armIdleTimer])
        case .founded, .joined:
            return .rejected(.sessionAlreadyStarted)
        default:
            return .rejected(.eventNotApplicableInState)
        }
    }

    /// Live with the scene backgrounded (plan §14's continued-processing task).
    private static func fromContinuingInBackground(_ event: MeshSessionEvent) -> MeshSessionTransition {
        switch event {
        case .foregrounded:
            return .moved(to: .activeForeground, effects: [])
        case .peerCommitted, .linksRestored, .backgrounded:
            return .moved(to: .continuingInBackground, effects: [])
        case .linksLost:
            return .moved(to: .partitioned, effects: [.armIdleTimer])
        case .founded, .joined:
            return .rejected(.sessionAlreadyStarted)
        default:
            return .rejected(.eventNotApplicableInState)
        }
    }

    /// Links lost, roster intact. The idle window is running.
    private static func fromPartitioned(_ event: MeshSessionEvent) -> MeshSessionTransition {
        switch event {
        case .linksRestored, .peerCommitted:
            return .moved(to: .activeForeground, effects: [.clearIdleTimer, .beginMerge])
        case .idleLapsed:
            return .moved(to: .localIdleStop, effects: [.stopParticipation, .clearIdleTimer])
        case .linksLost, .backgrounded, .foregrounded:
            return .moved(to: .partitioned, effects: [])
        case .founded, .joined:
            return .rejected(.sessionAlreadyStarted)
        default:
            return .rejected(.eventNotApplicableInState)
        }
    }

    /// Participation stopped, membership intact. Only a foreground resume restarts it, and the
    /// resume is the merge path — which is why ``MeshSessionEvent/peerCommitted`` is NOT an edge
    /// here: a peer reappearing at a radio this device has stopped cannot exist.
    private static func fromLocalIdleStop(_ event: MeshSessionEvent) -> MeshSessionTransition {
        switch event {
        case .resumedAfterLapse:
            return .moved(to: .activeForeground, effects: [.startParticipation, .beginMerge, .clearIdleTimer])
        case .foregrounded:
            return .moved(to: .localIdleStop, effects: [.offerForegroundResume])
        case .founded, .joined:
            return .rejected(.sessionAlreadyStarted)
        default:
            return .rejected(.eventNotApplicableInState)
        }
    }

    /// The durable half of an ending is written; the frame that tells the peers is not sent yet.
    private static func fromHandingOff(_ event: MeshSessionEvent) -> MeshSessionTransition {
        switch event {
        case .departureSent:
            return .moved(to: .departed, effects: [.stopParticipation])
        case .terminationSent:
            return .moved(to: .terminated, effects: [.stopParticipation])
        default:
            return .rejected(.eventNotApplicableInState)
        }
    }
}
