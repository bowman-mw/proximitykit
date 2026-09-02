// MeshRotationPolicy.swift
// ProximityKit/Mesh
//
// P3 item 5 (plan §8.3): when a key rotation happens, and who the new key is for.
//
// Plan §8.3 widens the rotation triggers from "the 15-minute timer" to "the 15-minute timer ∪ any
// roster change ∪ any merge", and says in the same breath that removed and departed members are
// excluded from the new epoch's key distribution. Both halves are decisions over values the caller
// already holds, so both live here as pure, clock-injected types rather than inside
// `MeshNetworkManager`'s async rotation dance — where a burst-coalescing window and an exclusion
// rule could only be observed by driving a radio.
//
// Nothing in this file sends, seals, signs or sleeps. `MeshNetworkManager` owns all of that.

import Foundation

// MARK: - MeshRotationTriggerBounds

/// The two numbers plan §8.3's trigger set needs beyond the 15-minute interval itself.
nonisolated enum MeshRotationTriggerBounds {

    /// How long a trigger waits before its rotation runs, so a **burst of records rotates once**.
    ///
    /// Two seconds, and the choice is a trade between two named costs. A membership burst is real:
    /// a partition healing re-gossips every record it holds, and a removal is routinely followed by
    /// the departure of the peer that lost the vote — each of those is a roster change, and each
    /// would otherwise mint an epoch and wrap a key for every member. Against that, the window is
    /// added directly to the interval in which a voted-out member still holds the old key, which is
    /// the gap this item exists to close: two seconds is long enough to swallow a burst that
    /// arrives within a couple of local-radio round trips and short enough that the exposure it
    /// buys back is a rounding error beside the ≤ 5-minute predecessor grace
    /// (``MeshEpochBounds/predecessorGraceSeconds``) that follows every rotation anyway.
    ///
    /// It is a *coalescing* window, not a rate limit: it never delays a second rotation behind a
    /// first, because a rotation already in flight is handled by ``MeshRotationTriggerQueue``'s
    /// in-flight rule instead.
    static let debounceWindowSeconds: TimeInterval = 2

    /// Ranking used when two causes coalesce into one rotation — higher wins.
    ///
    /// Frozen policy, not taste: the *reason recorded on the wire* should be the most specific one
    /// in the burst. A merge that also produced membership records is a merge; a membership change
    /// that happened to land on the timer's heel is a membership rotation, because "the roster
    /// changed" is what a reader of that frame needs to know.
    static func rank(_ cause: MeshKeyRotationCause) -> Int {
        switch cause {
        case .timer: return 0
        case .membership: return 1
        case .merge: return 2
        }
    }
}

// MARK: - MeshRotationTriggerOutcome

/// What asking for a rotation did.
///
/// Three answers rather than a `Bool`, because the caller has to do something different with each:
/// arm a timer, leave the armed one alone, or do nothing at all until the current rotation ends.
nonisolated enum MeshRotationTriggerOutcome: Equatable, Sendable {
    /// A fresh debounce window opened; the caller arms a single task to fire at this instant.
    case scheduled(at: Date, cause: MeshKeyRotationCause)
    /// Folded into a window that is already open. The caller must NOT arm a second task — this is
    /// the whole of "a burst of records rotates once".
    case coalesced(at: Date, cause: MeshKeyRotationCause)
    /// A rotation is in flight. The cause is remembered and re-offered by
    /// ``MeshRotationTriggerQueue/finish(at:)``; nothing is armed now.
    case queuedBehindInFlight(cause: MeshKeyRotationCause)
}

// MARK: - MeshRotationTriggerQueue

/// The coalescing, non-reentrant front door to key rotation (plan §8.3).
///
/// ## What it guarantees
///
/// 1. **Each trigger fires at most one rotation.** Requests inside one debounce window collapse
///    into a single scheduled rotation whose cause is the highest-ranked of the burst.
/// 2. **A rotation never runs while one is in flight.** ``claim(at:)`` is the only way to start
///    one and it refuses while ``isRotating``; a trigger that arrives mid-rotation is remembered
///    and re-armed by ``finish(at:)``, so it is deferred, never dropped.
/// 3. **Nothing here reads a clock.** Every entry point takes `at now:`, the injected-now idiom
///    ``MeshEpochKeyring`` and `MeshLinkTable` use, so the window is a value a test states.
///
/// ## Bounds
///
/// One optional cause and one optional date: a flood of triggers cannot grow it, and there is at
/// most one armed window at a time (Power of 10 R3 — the caller's task handle is
/// cancel-and-replace for the same reason).
///
/// ## Concurrency
///
/// MainActor-isolated by the module default, and owned exclusively by ``MeshNetworkManager``.
struct MeshRotationTriggerQueue {

    /// The cause a claim would take, if one were made now. Nil when nothing is waiting.
    private(set) var pendingCause: MeshKeyRotationCause?

    /// When the open debounce window elapses. Nil when no window is open.
    private(set) var firesAt: Date?

    /// Whether a rotation is running right now. Set by ``claim(at:)``, cleared by ``finish(at:)``.
    private(set) var isRotating = false

    /// Builds an idle queue.
    init() {}

    /// Asks for a rotation.
    ///
    /// - Parameters:
    ///   - cause: Why. Coalesces with any pending cause by ``MeshRotationTriggerBounds/rank(_:)``.
    ///   - now: The instant of the request; the debounce window is measured from it.
    /// - Returns: What the caller should do — see ``MeshRotationTriggerOutcome``.
    mutating func request(_ cause: MeshKeyRotationCause, at now: Date) -> MeshRotationTriggerOutcome {
        let merged = Self.dominant(pendingCause, cause)
        pendingCause = merged
        if isRotating { return .queuedBehindInFlight(cause: merged) }
        if let firesAt { return .coalesced(at: firesAt, cause: merged) }
        let target = now.addingTimeInterval(MeshRotationTriggerBounds.debounceWindowSeconds)
        firesAt = target
        return .scheduled(at: target, cause: merged)
    }

    /// Takes the debounced cause and marks a rotation in flight.
    ///
    /// - Returns: The cause to rotate for, or nil when there is nothing to claim — no pending
    ///   trigger, the window has not elapsed, or a rotation is already running. Nil is always
    ///   "do nothing", never "rotate anyway".
    mutating func claim(at now: Date) -> MeshKeyRotationCause? {
        guard !isRotating, let firesAt, now >= firesAt, let cause = pendingCause else { return nil }
        self.firesAt = nil
        pendingCause = nil
        isRotating = true
        return cause
    }

    /// Ends the in-flight rotation and re-arms anything that arrived during it.
    ///
    /// - Returns: The outcome of re-requesting the deferred cause, or nil when nothing was
    ///   deferred. A caller that ignores a non-nil return drops a trigger.
    mutating func finish(at now: Date) -> MeshRotationTriggerOutcome? {
        isRotating = false
        guard let deferredCause = pendingCause else { return nil }
        pendingCause = nil
        return request(deferredCause, at: now)
    }

    /// Forgets every pending trigger — the session ended, so the rotation it wanted is moot.
    mutating func reset() {
        pendingCause = nil
        firesAt = nil
        isRotating = false
    }

    /// The higher-ranked of a pending cause (if any) and a new one.
    private static func dominant(
        _ pending: MeshKeyRotationCause?,
        _ incoming: MeshKeyRotationCause
    ) -> MeshKeyRotationCause {
        guard let pending else { return incoming }
        return MeshRotationTriggerBounds.rank(incoming) > MeshRotationTriggerBounds.rank(pending)
            ? incoming
            : pending
    }
}

// MARK: - MeshRotationRefusal

/// Why a rotation was not planned. Frozen English diagnostics, never user copy.
nonisolated enum MeshRotationRefusal: Equatable, Sendable {
    /// This device cannot name a canonical coordinator fingerprint, so it cannot mint an epoch it
    /// could honestly present. Refusing beats presenting a ref no peer can re-derive.
    case coordinatorFingerprintNotCanonical
    /// ``MeshEpochAcceptance`` refused the successor this device proposed to itself — the roster it
    /// would present does not make it the coordinator, or is out of bounds.
    case epochAcceptance(MeshEpochRotationRefusal)

    /// Frozen English for the audit line.
    var diagnosticDescription: String {
        switch self {
        case .coordinatorFingerprintNotCanonical:
            return "This device cannot name a canonical coordinator fingerprint for a new epoch."
        case .epochAcceptance(let refusal):
            return refusal.diagnosticDescription
        }
    }
}

// MARK: - MeshRotationPlan

/// What the coordinator should do when a trigger fires.
///
/// ``terminate`` is the case plan §8.4's counter cap demands and the reason
/// ``MeshEpochRef/successor(coordinatorFingerprint:meshID:)`` returns an optional rather than
/// trapping: a mesh that cannot mint another epoch cannot retire the key it is serving, and a
/// session that cannot retire its key must end rather than keep going with one that is now
/// permanent. It is a refusal escalated to the session, never a crash.
nonisolated enum MeshRotationPlan: Equatable, Sendable {
    /// Rotate to this epoch.
    case rotate(MeshEpochRef)
    /// The counter cap is reached. End the session (emit `terminated.v1`, then leave).
    case terminate
    /// Do not rotate, for a named reason. The session continues on its current key.
    case refuse(MeshRotationRefusal)
}

// MARK: - MeshRotationPolicy

/// Plan §8.3's two rotation decisions, as pure functions.
///
/// ## Why the exclusion rule is *subtractive*
///
/// ``recipients(acked:selfFingerprint:derivedRoster:locallyRemoved:)`` removes the members it
/// knows are out and keeps everyone else, rather than admitting only members it can positively
/// name. That is deliberate for one phase-shaped reason: the derived roster is authoritative only
/// once admissions actually reach the ledger (item 7), and a *positive* rule keyed on a ledger that
/// is still empty in shipping builds would hand the new key to nobody at all — turning a security
/// improvement into a total rotation outage. So the rule is: **anyone the ledger bars, or anyone
/// this device has voted out, is excluded, always**; and when the ledger does know a roster, the
/// recipients are additionally narrowed to it. As the ledger fills, the rule tightens on its own.
nonisolated enum MeshRotationPolicy {

    /// Plans the next epoch for a coordinator.
    ///
    /// - Parameters:
    ///   - head: The epoch this device is currently on, or nil when it holds none (the first
    ///     rotation of a mesh mints counter 1).
    ///   - coordinatorFingerprint: This device's fingerprint — it is the one minting.
    ///   - meshID: The mesh, so the derived epoch id is mesh-scoped.
    ///   - presentedRoster: The roster this device would present with the rotation. It must contain
    ///     the coordinator and the coordinator must be its lowest fingerprint, or
    ///     ``MeshEpochAcceptance`` refuses — the same test every receiver applies.
    static func plan(
        head: MeshEpochRef?,
        coordinatorFingerprint: String,
        meshID: UUID,
        presentedRoster: [String]
    ) -> MeshRotationPlan {
        let next: MeshEpochRef?
        if let head {
            guard head.counter < MeshEpochBounds.counterCap else { return .terminate }
            next = head.successor(coordinatorFingerprint: coordinatorFingerprint, meshID: meshID)
        } else {
            next = MeshEpochRef.minted(
                counter: 1, coordinatorFingerprint: coordinatorFingerprint, meshID: meshID
            )
        }
        guard let presented = next else { return .refuse(.coordinatorFingerprintNotCanonical) }
        switch MeshEpochAcceptance.rotationVerdict(
            local: head,
            presented: presented,
            presentedRoster: presentedRoster,
            presenterFingerprint: coordinatorFingerprint
        ) {
        case .accept:
            return .rotate(presented)
        case .coexist:
            // Unreachable for a strict successor of our own head, and named rather than assumed:
            // a same-counter verdict on an epoch we just incremented would mean the model changed
            // underneath this call, and rotating anyway would be the wrong recovery.
            return .refuse(.epochAcceptance(.staleCounter))
        case .reject(let refusal):
            return .refuse(.epochAcceptance(refusal))
        }
    }

    /// Who receives the new epoch's key (plan §8.3: "removed/departed members are excluded").
    ///
    /// - Parameters:
    ///   - acked: Fingerprints that acknowledged the closing epoch's drain.
    ///   - selfFingerprint: This device, which always receives its own copy — a coordinator that
    ///     did not wrap the key for itself would distribute a key it cannot read.
    ///   - derivedRoster: The ledger's roster, when this device holds one. `barred` is the
    ///     departed, removed and downgraded-terminator set.
    ///   - locallyRemoved: Fingerprints this device has voted out through the live removal flow,
    ///     whose signed record may not have reached the ledger yet.
    /// - Returns: The recipient set, always containing `selfFingerprint`.
    static func recipients(
        acked: Set<String>,
        selfFingerprint: String,
        derivedRoster: MeshDerivedRoster?,
        locallyRemoved: Set<String>
    ) -> Set<String> {
        var allowed = acked.subtracting(locallyRemoved)
        if let derivedRoster {
            allowed.subtract(Set(derivedRoster.barred.map(\.fingerprint)))
            if !derivedRoster.members.isEmpty {
                allowed.formIntersection(Set(derivedRoster.memberFingerprints))
            }
        }
        allowed.insert(selfFingerprint)
        return allowed
    }
}
