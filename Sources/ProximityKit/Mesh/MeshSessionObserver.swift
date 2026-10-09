// MeshSessionObserver.swift
// ProximityKit/Mesh
//
// ProximityKit plan step A0.5.6 (seam S15): the session observer — the one object through which a
// host hears the moments of a mesh session's life that its own features act on, each fired by the
// engine at the one site where that moment happens, in the order the engine has always run it: a
// slot commits, a slot leaves, the search stops, the session ends, a privacy wipe begins (plan step
// A0.5.9); and a session begins, is left, changes the mesh it counts against, loses a removed member,
// and sees the routed access gate change (plan step A0.5.11).
//
// The facts stay the engine's. Which commit forms a session (the first commit after a session
// ended) and whether a session has ended (`isSessionLive` going false) are decided at the engine's
// call sites, and what the engine itself still does at each moment is run there: at a forming commit,
// at the ending and at a privacy wipe's start, it advances its session-content generation, the fact a
// routed `.session` row's liveness reads, before it tells the observer; at the ending it also drains
// the session roster before, handing the drained entries to the observer in the ending itself
// (``MeshSessionEnd/drainedRoster``): the roster and its custody stay the engine's, and what the
// entries become is the host's. Every other leg is the host's, run by its observer: since plan step
// A0.5.9 the chat transcript's clear is one of them, at all three of those moments, since plan step
// A0.5.10 the session heart's reset, the ending's last, and since plan step A0.5.11 every photo leg —
// the review merge and the photo move first at the ending, the film's counters, the leftover photos'
// move and the new photo session at a session's start, the photo session forgotten when it is left,
// the film's mesh pin at each scope change, the removed member's purge from the review, and the photo
// indexes' re-read on a rising access edge. The observer is told the moment and, for a commit, whether
// it formed the session. It receives facts, never commands, and is asked for nothing back.
//
// One observer, not a list: a host composes its features behind one object, and that object's fan-out
// is where the order between features is written, so the order a host's features see a moment in is
// the host's own code, in one place.
//
// Not here: the manager's one reference (`MeshNetworkManager.sessionObserver`, held weakly) and the
// call at each moment's site, all in `MeshNetworkManager.swift`.

import Foundation

// MARK: - MeshSessionObserver

/// A host's ear on the moments of a mesh session's life (plan step A0.5.6, S15): a slot commits, a slot
/// leaves, the search stops, the session ends, a privacy wipe begins, and (plan step A0.5.11) a session
/// begins, is left, changes the mesh it counts against, loses a removed member, and sees the routed
/// access gate change.
///
/// Installed on ``MeshNetworkManager/sessionObserver``, which holds it **weakly**: the object that
/// installs it owns it, and a manager whose observer is gone runs every moment with no host leg. Every
/// method has a no-op default (below), so a conformer implements only the moments it acts on and a
/// later moment can join the protocol without breaking one.
///
/// **The contract.** Each method is called synchronously on the main actor, once per call of the
/// moment's site, from one engine position, after the engine's own state for that moment is set and
/// before the engine's own legs that follow it there:
/// - ``meshSlotDidCommit(_:)`` from every slot commit, after the session roster recorded the peer and
///   the engine decided whether this commit formed the session (and, when it did, advanced its
///   session-content generation), before the founding;
/// - ``meshSlotDidLeave(slotID:)`` when a slot is dropped, after it left the slot list and before the
///   session-end check its removal runs;
/// - ``meshSearchDidStop()`` when the search stops, before the radio is stood down;
/// - ``meshSessionDidEnd(_:)`` at the session-end moment (``MeshNetworkManager/isSessionLive`` false
///   on a teardown or slot-loss path, each time such a path runs), after the engine drained its
///   session roster into the ending and advanced its generation, as the ending's last step;
/// - ``meshPrivacyWipeDidBegin()`` when the host's delete-all funnel begins
///   (``MeshNetworkManager/beginPrivacyWipe()``), after the engine raised its projection refusal,
///   wrote its line and advanced its generation;
/// - ``meshSessionWillBegin()`` when a new search begins (``MeshNetworkManager/startJoin()``), after
///   the session's open flags are set and before the roster, the removal tallies and the state machine
///   are reset and the radio starts;
/// - ``meshSessionDidLeave()`` when this device leaves its session
///   (``MeshNetworkManager/leaveSession()``), after the teardown, and the session end it runs, are done;
/// - ``meshScopeDidChange(_:)`` at each of the three sites that change which mesh this device's session
///   counts against (``MeshScopeChange``), in the middle of that site's own steps, as each case says;
/// - ``meshMemberWasRemoved(fingerprint:)`` when a signed removal this device approved takes effect,
///   after the member left the live session roster and before this device leaves or drops the
///   member's slot;
/// - ``meshRoutedAccessGateDidChange(_:isRising:now:)`` when the host pushes a changed routed access
///   gate (``MeshNetworkManager/applyRoutedAccessGate(_:now:)``), after the engine stored it and wrote
///   `mesh.routedAccess.gateChanged`, before the re-entry pass the edge owes.
///
/// A conformer must not call back into the verb whose moment it is being told (the commit, the
/// removal, the stop, the ending, the wipe's begin, the start, the leave, the scope change or the gate
/// push) and may spawn tasks of its own, which run after the moment's site returns. Main-actor, like
/// the sites that call it; `AnyObject`, because the engine holds it weakly.
@MainActor public protocol MeshSessionObserver: AnyObject {

    /// A slot committed: its peer's handshake was verified and the peer was recorded in the session
    /// roster.
    ///
    /// Called at every commit, a re-handshake of a committed slot and a promotion's committed loop
    /// included, so a conformer that must act once per slot keeps its own record of the slots it has
    /// acted on. ``MeshSlotCommit/formsSession`` is true exactly once per session.
    ///
    /// - Parameter commit: The committed slot, its peer's verified identity and whether this commit
    ///   formed the session.
    func meshSlotDidCommit(_ commit: MeshSlotCommit)

    /// A slot was dropped: evicted, timed out or disconnected. The session may continue; whether it
    /// ended is ``meshSessionDidEnd(_:)``'s moment, which may follow at once. Not called for the slots
    /// a stopped search drops all together: ``meshSearchDidStop()`` is that moment.
    ///
    /// A peer that comes back may be seated again under the same slot id (the radio keeps a peer's
    /// identifier across a remote teardown), so a conformer forgets what it recorded for this slot.
    ///
    /// - Parameter slotID: The dropped slot's id.
    func meshSlotDidLeave(slotID: UUID)

    /// The search stopped: every slot is about to be dropped and the radio stood down. The session
    /// may continue (a mesh outlives its links); whether it ended is ``meshSessionDidEnd(_:)``'s
    /// moment, at the end of the same teardown.
    func meshSearchDidStop()

    /// The session ended: ``MeshNetworkManager/isSessionLive`` is false at a teardown or slot-loss
    /// site. Called at EVERY such site that finds the session ended, so more than once for one ending
    /// when a later teardown finds it still ended (a tab exit after End Session runs the teardown
    /// again): a conformer's leg is idempotent, and a later ending's ``MeshSessionEnd/drainedRoster``
    /// holds only the peers that committed since the last one drained it (none, for a re-run teardown).
    /// The next ``meshSlotDidCommit(_:)`` forms a new session.
    ///
    /// - Parameter end: The ending, with the session roster the engine drained at it.
    func meshSessionDidEnd(_ end: MeshSessionEnd)

    /// The host's privacy wipe began (plan step A0.5.9): its delete-all funnel called
    /// ``MeshNetworkManager/beginPrivacyWipe()``, so every routed projection is refused until the
    /// funnel's last end, and the session-content generation has moved, so nothing offered before
    /// this moment projects into the session's content again. A conformer drops the session content
    /// its features hold in memory: for Fernlet, the chat transcript.
    ///
    /// Called at every begin, a nested funnel's and one past the engine's depth cap included, so more
    /// than once for overlapping funnels: a conformer's leg is idempotent.
    func meshPrivacyWipeDidBegin()

    /// A new search began (plan step A0.5.11): ``MeshNetworkManager/startJoin()`` runs on every entry
    /// to the host's session surface and every scene reactivation, and each run is a new session by
    /// definition — so what a conformer still holds for the session before it belongs to one that
    /// ended without an answer. Told before the engine resets its session roster, its removal tallies
    /// and its session state machine, and before the radio starts.
    func meshSessionWillBegin()

    /// This device left its session (plan step A0.5.11): ``MeshNetworkManager/leaveSession()``'s local
    /// teardown, and the session end it runs, are done — the ending's ``meshSessionDidEnd(_:)`` has
    /// already been told, so whatever a conformer stamped with the session's identity at the ending was
    /// stamped while it still had one, and it forgets that identity now.
    func meshSessionDidLeave()

    /// The mesh this device's session counts against changed (plan step A0.5.11): founded at a first
    /// commit, abandoned unfounded, or left. See each ``MeshScopeChange`` case for its site and
    /// position. A per-session allowance a conformer keys on the mesh pins, refunds or resets here.
    ///
    /// - Parameter change: Which change, and for a founding the new mesh's id.
    func meshScopeDidChange(_ change: MeshScopeChange)

    /// A signed removal this device approved took effect (plan step A0.5.11): the member it names is in
    /// the removed set and out of the live session roster, and this device is about to leave (when it
    /// is the one removed) or drop the member's slot and rotate. Not told for the pairwise "Ask to
    /// remove" shortcut, which ends the session instead of removing anyone. A conformer drops what it
    /// holds about the member from the session's ending (for Fernlet, the member's keep-as-friend
    /// candidacy in the pending review), so a voted-out peer is never offered.
    ///
    /// - Parameter fingerprint: The removed member's fingerprint.
    func meshMemberWasRemoved(fingerprint: String)

    /// The host pushed a changed routed access gate (plan step A0.5.11): ``MeshNetworkManager/routedAccessGate``
    /// is `gate` now and `mesh.routedAccess.gateChanged` is written; the re-entry pass the edge owes
    /// runs after this returns. An unchanged push tells nothing.
    ///
    /// - Parameters:
    ///   - gate: The gate as the host now knows it.
    ///   - isRising: Whether a ciphertext leg rose (an unlock or a foreground: the sealed stores became
    ///     readable again) — ``MeshRoutedAccessEdge/isRising``.
    ///   - now: The instant the host pushed it, which the engine's own pass is judged against.
    func meshRoutedAccessGateDidChange(_ gate: MeshRoutedAccessGate, isRising: Bool, now: Date)
}

/// The no-op defaults: a conformer implements only the moments it acts on.
public extension MeshSessionObserver {

    /// Does nothing.
    ///
    /// - Parameter commit: The commit, ignored.
    func meshSlotDidCommit(_ commit: MeshSlotCommit) {}

    /// Does nothing.
    ///
    /// - Parameter slotID: The dropped slot's id, ignored.
    func meshSlotDidLeave(slotID: UUID) {}

    /// Does nothing.
    func meshSearchDidStop() {}

    /// Does nothing.
    ///
    /// - Parameter end: The ending, ignored.
    func meshSessionDidEnd(_ end: MeshSessionEnd) {}

    /// Does nothing.
    func meshPrivacyWipeDidBegin() {}

    /// Does nothing.
    func meshSessionWillBegin() {}

    /// Does nothing.
    func meshSessionDidLeave() {}

    /// Does nothing.
    ///
    /// - Parameter change: The change, ignored.
    func meshScopeDidChange(_ change: MeshScopeChange) {}

    /// Does nothing.
    ///
    /// - Parameter fingerprint: The removed member's fingerprint, ignored.
    func meshMemberWasRemoved(fingerprint: String) {}

    /// Does nothing.
    ///
    /// - Parameters:
    ///   - gate: The gate, ignored.
    ///   - isRising: Whether a ciphertext leg rose, ignored.
    ///   - now: The instant, ignored.
    func meshRoutedAccessGateDidChange(_ gate: MeshRoutedAccessGate, isRising: Bool, now: Date) {}
}

// MARK: - MeshSlotCommit

/// One slot commit, as the engine hands it to its ``MeshSessionObserver`` (plan step A0.5.6, S15).
///
/// Built only by the engine, at the commit. ``slot`` is the seat as it stood at the commit, the value
/// a host's feature sends to through ``MeshNetworkManager/sendFeatureEnvelope(_:encodable:via:sealed:)``
/// (a seat captured at commit is sent to as captured); ``peer`` is the identity its handshake verified;
/// ``formsSession`` is the engine's fact, never the host's: true for the first commit after a session
/// ended (or the first ever), false for every later one until the next ending.
public struct MeshSlotCommit {
    /// The committed seat, as it stood at the commit.
    public let slot: PeerSlot
    /// The peer's handshake-verified identity, its advertised capabilities included.
    public let peer: ProximityCoordinator.PeerIdentity
    /// Whether this commit formed the session: the first commit after a session ended.
    public let formsSession: Bool
}

// MARK: - MeshSessionEnd

/// One session ending, as the engine hands it to its ``MeshSessionObserver`` (plan step A0.5.6, S15).
///
/// Built only by the engine, at the session-end moment. It carries the session roster the engine
/// drained there (plan step A0.5.11): the engine keeps the roster and its custody, and empties it at
/// the ending in the same synchronous step that builds this value, so the entries reach the host
/// exactly once and a later ending carries only peers that committed after this one. Value data, so
/// `nonisolated` and `Sendable`.
public nonisolated struct MeshSessionEnd: Equatable, Sendable {
    /// Every peer whose handshake committed in the session that ended and that the engine's roster
    /// still held — not consumed by an in-session review, not removed — in the roster's own order,
    /// each with the display name its last commit or disclosure left. At most
    /// ``MeshNetworkManager/maxSessionRosterEntries``; empty when the roster held nothing (a re-run
    /// teardown, or a session with no committed peer).
    public let drainedRoster: [MeshSessionRosterEntry]
}

// MARK: - MeshScopeChange

/// Which change of scope ``MeshSessionObserver/meshScopeDidChange(_:)`` reports (plan step A0.5.11, S15):
/// the three engine sites that change the mesh this device's session counts against.
///
/// Built only by the engine. Value data, so `nonisolated` and `Sendable`.
public nonisolated enum MeshScopeChange: Equatable, Sendable {
    /// This device founded a mesh at its session's first commit (the proximity-join promotion): told
    /// after the founded descriptor became the current mesh and before the founding is sealed, so a
    /// per-session allowance keyed on the mesh pins the new id rather than resetting for it.
    case foundedAtFirstCommit(meshID: UUID)
    /// A founding whose context could not be sealed was given up (or a newborn mesh yielded to
    /// another): told after the mesh and its membership ledger were dropped and before the session
    /// state machine is reset.
    case foundingAbandoned
    /// This device left its mesh (``MeshNetworkManager/leaveMesh()``): told after the session's
    /// removal tallies were dropped and before the group key and the radio go.
    case left
}
