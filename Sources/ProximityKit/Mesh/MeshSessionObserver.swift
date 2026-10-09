// MeshSessionObserver.swift
// ProximityKit/Mesh
//
// ProximityKit plan step A0.5.6 (seam S15): the session observer — the one object through which a
// host hears the moments of a mesh session's life that its own features act on, each fired by the
// engine at the one site where that moment happens, in the order the engine has always run it: a
// slot commits, a slot leaves, the search stops, the session ends, a privacy wipe begins (plan step
// A0.5.9).
//
// The facts stay the engine's. Which commit forms a session (the first commit after a session
// ended) and whether a session has ended (`isSessionLive` going false) are decided at the engine's
// call sites, and what the engine itself still does at each moment is run there: at a forming commit,
// at the ending and at a privacy wipe's start, it advances its session-content generation, the fact a
// routed `.session` row's liveness reads, before it tells the observer; at the ending it also runs the
// roster's review promotion before. Every other leg is the host's, run by its observer: since plan
// step A0.5.9 the chat transcript's clear is one of them, at all three of those moments, and since
// plan step A0.5.10 the session heart's reset, which the engine ran after the observer until then, is
// the ending's last. The observer is told the moment and, for a commit, whether it formed the
// session. It receives facts, never commands, and is asked for nothing back.
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
/// leaves, the search stops, the session ends, a privacy wipe begins.
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
///   on a teardown or slot-loss path, each time such a path runs), after the engine's review
///   promotion and its generation advance, as the ending's last step;
/// - ``meshPrivacyWipeDidBegin()`` when the host's delete-all funnel begins
///   (``MeshNetworkManager/beginPrivacyWipe()``), after the engine raised its projection refusal,
///   wrote its line and advanced its generation.
///
/// A conformer must not call back into the verb whose moment it is being told (the commit, the
/// removal, the stop, the ending or the wipe's begin) and may spawn tasks of its own, which run after
/// the moment's site returns. Main-actor, like the sites that call it; `AnyObject`, because the engine holds it weakly.
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
    /// again): a conformer's leg is idempotent. The next ``meshSlotDidCommit(_:)`` forms a new session.
    ///
    /// - Parameter end: The ending.
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
/// Built only by the engine, at the session-end moment. It carries nothing yet: the moment is the
/// fact. Value data, so `nonisolated` and `Sendable`.
public nonisolated struct MeshSessionEnd: Equatable, Sendable {}
