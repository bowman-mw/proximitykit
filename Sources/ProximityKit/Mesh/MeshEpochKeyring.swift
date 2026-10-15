// MeshEpochKeyring.swift
// ProximityKit/Mesh
//
// P3 item 4 (plan §8.4): the bounded keyring — the current epoch's group key plus at most three
// predecessors, each usable for at most five minutes after it was superseded. It is the reason a
// rotation does not drop the control frames already in flight when it lands, and it is the reason
// an old key stops working at a *stated* moment rather than whenever the last reference goes away.
//
// MEMORY-ONLY, FOREVER. Nothing in this file is `Codable`, nothing here reaches `MeshSessionStore`,
// and `MeshEpochRef`s — never keys — are what `MeshSessionContext.epochHeads` persists.

import Foundation

// MARK: - MeshEpochKeyringRotationRefusal

/// Why ``MeshEpochKeyring/rotate(to:key:at:)`` refused to move the head.
///
/// A refusal is never a trap and never a silent no-op: a caller that cannot rotate has to decide
/// what to do about it (plan §8.4's counter cap says terminate rather than keep serving), and it
/// can only decide if the refusal names itself.
nonisolated enum MeshEpochKeyringRotationRefusal: Error, Equatable, Sendable {
    /// The presented epoch's counter is lower than the head's — a stale or replayed rotation.
    case staleCounter
    /// The presented epoch IS the head. Idempotent re-delivery, not an advance.
    case alreadyCurrent
    /// The presented epoch shares the head's counter but is a different minting: a divergent
    /// branch, which never supersedes and never merges here (plan §8.4 — it coexists until P4's
    /// merge mints a strictly greater successor).
    case divergentBranch
}

// MARK: - MeshEpochKeyring

/// The current group key and its still-usable predecessors, keyed by ``MeshEpochRef``.
///
/// ## Bounds (plan §8.4, restated in ``MeshEpochBounds``)
///
/// - **Current + ≤ 3 predecessors.** A fourth supersession evicts the oldest immediately, whatever
///   its grace window says: the cap is on memory, the grace is on time, and both must hold.
/// - **≤ 5 minutes of grace** per predecessor, measured from the instant it was superseded — not
///   from when it was minted, so a key that was current for hours still gets exactly five minutes.
/// - After grace, ``key(for:at:)`` returns nil. That is the whole of "an old key is rejected": there
///   is no fallback path, no "try it anyway", and no other holder of the bytes.
///
/// ## The clock is injected, always
///
/// Every method that cares about time takes `at now: Date`. Nothing here reads `Date()`, so the
/// grace boundary is a value a test states rather than a duration it waits out — the same
/// injected-now idiom `MeshLinkTable` and `MeshHeartbeatSchedule` use.
///
/// ## What this is not
///
/// It is not a key *distribution* mechanism and it does not mint anything: it is handed an epoch
/// and the key that belongs to it. Deciding whether a presented rotation may be accepted at all is
/// ``MeshEpochAcceptance``'s job, and minting the successor is item 5's.
///
/// ## Concurrency
///
/// MainActor-isolated by the module default, like the ``MeshGroupKey`` values it holds: the mesh
/// manager is its only owner. Deliberately NOT `Sendable` — copy it and you have copied the
/// secret, so it lives in exactly one place and is mutated in place, never stored twice.
struct MeshEpochKeyring {

    /// One superseded epoch and the instant its grace window started.
    private struct Superseded {
        let ref: MeshEpochRef
        let key: MeshGroupKey
        let supersededAt: Date
    }

    /// The epoch this device is currently on. Every frame it *sends* uses this one's key.
    private(set) var head: MeshEpochRef

    /// The key bound to ``head``.
    private var headKey: MeshGroupKey

    /// Superseded epochs, newest first, at most ``MeshEpochBounds/keyringPredecessors``.
    private var predecessors: [Superseded] = []

    /// Starts a keyring on one epoch and its key. There is no empty keyring: a device with no
    /// group key holds no keyring at all, which is the state its `epochRef` reports as "none".
    init(head: MeshEpochRef, key: MeshGroupKey) {
        self.head = head
        self.headKey = key
    }

    /// Moves the head to a strictly newer epoch, demoting the old head into the grace window.
    ///
    /// - Parameters:
    ///   - ref: The new epoch. Must have a strictly greater counter than the head.
    ///   - key: The group key bound to `ref`.
    ///   - now: The instant the supersession happens; starts the old head's grace window.
    /// - Throws: ``MeshEpochKeyringRotationRefusal`` — never a trap, and the keyring is unchanged
    ///   on every refusal.
    mutating func rotate(to ref: MeshEpochRef, key: MeshGroupKey, at now: Date) throws {
        if ref == head { throw MeshEpochKeyringRotationRefusal.alreadyCurrent }
        if ref.counter == head.counter { throw MeshEpochKeyringRotationRefusal.divergentBranch }
        guard ref.counter > head.counter else {
            throw MeshEpochKeyringRotationRefusal.staleCounter
        }
        predecessors.insert(Superseded(ref: head, key: headKey, supersededAt: now), at: 0)
        if predecessors.count > MeshEpochBounds.keyringPredecessors {
            predecessors = Array(predecessors.prefix(MeshEpochBounds.keyringPredecessors))
        }
        head = ref
        headKey = key
        prune(at: now)
    }

    /// The key to decrypt with for a named epoch: the head first, then any predecessor still
    /// inside its grace window.
    ///
    /// - Returns: nil when the epoch is unknown, or known but past grace — the two cases a caller
    ///   must treat identically, because "we used to be able to read this" is not a reason to.
    func key(for ref: MeshEpochRef, at now: Date) -> MeshGroupKey? {
        if ref == head { return headKey }
        guard let entry = predecessors.first(where: { $0.ref == ref }) else { return nil }
        guard Self.isWithinGrace(entry.supersededAt, now: now) else { return nil }
        return entry.key
    }

    /// Whether this keyring can open a frame sent under `ref` right now. The predicate form of
    /// ``key(for:at:)``, for callers that only need the decision.
    func canOpen(_ ref: MeshEpochRef, at now: Date) -> Bool {
        key(for: ref, at: now) != nil
    }

    /// The head plus every predecessor still inside its grace window, newest first. Diagnostic and
    /// test surface; nothing routes off it.
    func openableEpochs(at now: Date) -> [MeshEpochRef] {
        [head] + predecessors
            .filter { Self.isWithinGrace($0.supersededAt, now: now) }
            .map(\.ref)
    }

    /// Drops predecessors whose grace has expired. Called on every rotation and safe to call at any
    /// time; ``key(for:at:)`` is already grace-checked, so pruning is a memory hygiene act rather
    /// than a security one.
    mutating func prune(at now: Date) {
        predecessors = predecessors.filter { Self.isWithinGrace($0.supersededAt, now: now) }
    }

    /// Whether a supersession instant is still inside the grace window at `now`.
    ///
    /// A `now` *before* the supersession (a clock that went backwards) counts as inside: the
    /// alternative is a backwards clock silently retiring keys early, which is the failure that
    /// looks like "everyone stopped being able to read anything".
    private static func isWithinGrace(_ supersededAt: Date, now: Date) -> Bool {
        now.timeIntervalSince(supersededAt) <= MeshEpochBounds.predecessorGraceSeconds
    }
}
