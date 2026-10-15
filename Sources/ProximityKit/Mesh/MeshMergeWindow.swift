// MeshMergeWindow.swift
// ProximityKit/Mesh
//
// Network migration P5 item 7 (plan §10.3, §22.1, §22.3): the merge exchange in flight, as an
// explicit **value** rather than a `Bool` and a counter.
//
// P4 deferred defect 2d by name: `concludeMerge()` closed the window on the **first** peer digest
// that matched local inventory, so across eight members a later re-gossip landed outside the window
// and rotated `.membership` instead of `.merge`. The naive fix — "close on any answered exchange" —
// reopens the 2c deadlock from the responder's side. The rule that survives both is symmetric and
// lives here:
//
//     pending = (asked ∪ answered) ∩ reachable ∖ matched      closes ⟺ pending = ∅
//
// `answered` sits INSIDE `pending`, so answering can never close anything on either side; and a
// peer's later MISMATCHING digest removes it from `matched` again, so an obligation can never be
// created and discharged by the same frame.
//
// **No clock, no I/O, no randomness.** `openedAt` is supplied by the caller and is recorded, never
// compared: nothing here is closed, re-opened or re-advertised because of elapsed time. That is what
// lets the closing law be driven with no `MeshNetworkManager` at all.

import Foundation

// MARK: - MeshMergeWindowRole

/// Which side of the exchange a window is waiting on.
///
/// Derived from the sets rather than stored, so it cannot disagree with them. A frozen English
/// diagnostic token in the idiom of `MeshMergeEntry` — read by suites and audit lines, never shown
/// to a person, never localized.
nonisolated enum MeshMergeWindowRole: String, Equatable, Sendable {

    /// Asked somebody, answered nobody.
    case initiator

    /// Answered somebody's mismatch, asked nobody.
    case responder

    /// Both halves of one exchange — the commonest shape of a real heal.
    case both

    /// Armed, but nothing asked and nothing answered yet: the verifier-less or empty-recipient open.
    case idle
}

// MARK: - MeshMergeWindowClosure

/// Why a window closed.
///
/// Frozen English `rawValue`s: these reach the `mesh.merge.converged` audit line and are matched by
/// name in suites, so they are wire-shaped vocabulary and never display copy. `CaseIterable` is
/// load-bearing — the vocabulary is frozen through `allCases`.
nonisolated enum MeshMergeWindowClosure: String, CaseIterable, Equatable, Sendable {

    /// Every peer the window was waiting on sent a digest that equalled local inventory.
    case converged

    /// The pending set emptied without a single match: the peers it waited on stopped being
    /// reachable members. An honest closure, and a different fact from ``converged``.
    case nothingOutstanding
}

// MARK: - MeshMergeWindowVerdict

/// Whether a window closes now, and if not how many peers it is still waiting on.
nonisolated enum MeshMergeWindowVerdict: Equatable, Sendable {

    /// Still waiting on `outstanding` peers.
    case open(outstanding: Int)

    /// Finished, for the stated reason.
    case closed(MeshMergeWindowClosure)
}

// MARK: - MeshMergeWindow

/// The merge exchange now in flight, as an explicit value.
///
/// Three bounded per-peer sets plus the window's own evidence, and every transition is a pure
/// function returning the next window. The manager holds one optional of this type and calls
/// transitions; `awaitingResumeMerge` is `mergeWindow != nil`, so one stored source of truth cannot
/// disagree with the observable.
///
/// **Bounds, and the direction each one fails.** All three sets and the evidence map are capped at
/// ``MeshMembershipBounds/maxRosterMembers`` through one insert helper. A refused `asked` insert
/// fails **open** (this device stops waiting for a peer); a refused `matched` or `evidence` insert
/// fails **closed** (the window stays open). Neither cap can bite: `asked` is seeded from the ≤ 3
/// active slots and extended one peer at a time, and every set is keyed by a roster member.
///
/// **What is monotone and what is not.** `asked`, `answered` and `evidence` only grow within a
/// window. `matched` is *not* monotone, and exactly two transitions remove from it. ``answering(_:)``
/// removes its peer, because a signed, verified, present-tense digest that does not equal local
/// inventory is direct evidence that an earlier match is stale; ``reAsking(_:)`` removes its peer,
/// because a re-commit is present-tense transport evidence that the peer's ledger has been out of
/// this device's sight since the match was recorded. Both are present-tense facts about *that* peer,
/// categorically different from re-deriving a stored match locally — which this type never does,
/// because local inventory grows while the stored evidence does not, and a match dropped that way
/// could never be re-earned. The opening ``asking(_:)`` un-matches nothing.
nonisolated struct MeshMergeWindow: Equatable, Sendable {

    /// The peers this window sent an inventory digest to — the opening ask plus every late one.
    private(set) var asked: Set<String>

    /// The peers whose mismatched digest this device answered. Part of `pending`, so "answered"
    /// **adds** an obligation and can never discharge one.
    private(set) var answered: Set<String>

    /// The peers whose digest equalled local inventory. Recorded even for a peer this window never
    /// asked: it is signed, verified and about the same ledger, and it can only ever help a peer
    /// that is asked later.
    private(set) var matched: Set<String>

    /// Every verified digest received **while this window was open**, keyed by sender.
    ///
    /// Deliberately the window's own evidence rather than `MeshNetworkManager.peerInventoryDigests`,
    /// which is documented as "a hint, never an authority", is cleared only at session level and
    /// survives a partition — so a digest gathered before a split could otherwise close a post-heal
    /// window. Window-scoping is the age bound.
    private(set) var evidence: [String: MeshInventoryDigest]

    /// When the window opened. **Recorded, never compared** — the `MeshMergeEntry` precedent.
    let openedAt: Date

    /// The last local inventory state this window put on the wire: the opening ask's digest, and
    /// then each post-merge proof's. What makes a proof once-per-distinct-digest.
    private(set) var provenDigest: MeshInventoryDigest?

    /// How many digests this window has advertised, capped at ``maxProofs``.
    private(set) var proofCount: Int

    /// The most digests one window may advertise.
    ///
    /// Derived from the ledger's own caps rather than picked: a window cannot fold more records than
    /// a full ledger holds, so at most this many *distinct* local digests can ever exist inside one
    /// window and the cap cannot bite before the ledger is full. It is **equal to**
    /// `MeshNetworkManager.maxReGossipFrames` — pinned by assertion in the suite rather than by
    /// reference, because that manager is `@MainActor` and this value type must stay manager-free.
    static let maxProofs = MeshMembershipBounds.maxRecordsPerKind * 3
        + MeshMembershipBounds.maxTerminationRecords

    // MARK: - Opening

    /// The window a reconnect arms, before it knows whether it has a verifier or anybody to ask.
    ///
    /// All four collections start empty, so a window that never gets recipients is `role == .idle`
    /// and closes `.nothingOutstanding` at its first evaluation.
    ///
    /// - Parameter instant: The caller's `now`. Recorded, never compared.
    static func opened(at instant: Date) -> Self {
        MeshMergeWindow(
            asked: [], answered: [], matched: [], evidence: [:],
            openedAt: instant, provenDigest: nil, proofCount: 0
        )
    }

    // MARK: - Transitions

    /// Records the **opening** ask — the slot set the exchange was born asking.
    ///
    /// Un-matches nobody: these are peers this device has been linked to all along, so the ask
    /// itself is no evidence about their ledgers. The late ask a re-committing peer gets is
    /// ``reAsking(_:)``, which is a different fact and does un-match.
    ///
    /// - Parameter peers: The peers a digest was just sent to.
    /// - Returns: The next window.
    func asking(_ peers: Set<String>) -> Self {
        var next = self
        for peer in peers.sorted().prefix(MeshMembershipBounds.maxRosterMembers) {
            next.asked = Self.inserting(peer, into: next.asked)
        }
        return next
    }

    /// Records the **late** ask a peer gets when it re-commits while this window is open — and
    /// **drops it from `matched`**.
    ///
    /// Separate from ``asking(_:)`` because the two asks carry different evidence. The opening ask
    /// is sent to slots this device has been holding all along, so it un-proves nothing; a late ask
    /// exists precisely because a peer's link dropped and re-formed, and while it was gone that peer
    /// may have linked to the other branch of a split and folded records this device has never seen.
    /// A re-commit is therefore present-tense transport evidence that the peer's ledger has been out
    /// of this device's sight — the same class of evidence ``answering(_:)`` un-matches on (D-7.27),
    /// and the direction it fails in is the safe one: a silent re-asked peer holds the window open
    /// rather than closing it `.converged` on evidence gathered before it left.
    ///
    /// - Parameter peer: The peer that just re-committed.
    /// - Returns: The next window.
    func reAsking(_ peer: String) -> Self {
        var next = self
        next.asked = Self.inserting(peer, into: next.asked)
        next.matched.remove(peer)
        return next
    }

    /// Records that this device answered `peer`'s mismatched digest.
    ///
    /// Adds the obligation **and drops the peer from `matched`**: the frame that provokes the answer
    /// is present-tense evidence that the two ledgers differ, and closing while holding it is the
    /// "converged with a known-behind peer" claim this type exists to refuse.
    ///
    /// - Parameter peer: The sender whose digest did not match.
    /// - Returns: The next window.
    func answering(_ peer: String) -> Self {
        var next = self
        next.answered = Self.inserting(peer, into: next.answered)
        next.matched.remove(peer)
        return next
    }

    /// Records that `peer`'s digest equalled local inventory.
    ///
    /// - Parameter peer: The sender.
    /// - Returns: The next window.
    func matching(_ peer: String) -> Self {
        var next = self
        next.matched = Self.inserting(peer, into: next.matched)
        return next
    }

    /// Stores a verified inbound digest as this window's own evidence, through the bounded-map
    /// idiom: already present, **or** under the roster cap.
    ///
    /// - Parameters:
    ///   - digest: The peer's verified digest.
    ///   - peer: Its sender.
    /// - Returns: The next window.
    func recording(_ digest: MeshInventoryDigest, from peer: String) -> Self {
        guard evidence[peer] != nil
                || evidence.count < MeshMembershipBounds.maxRosterMembers else { return self }
        var next = self
        next.evidence[peer] = digest
        return next
    }

    /// Records the local state just put on the wire, and spends one proof.
    ///
    /// - Parameter digest: The digest advertised.
    /// - Returns: The next window.
    func advertised(_ digest: MeshInventoryDigest) -> Self {
        var next = self
        next.provenDigest = digest
        next.proofCount = min(next.proofCount + 1, Self.maxProofs)
        return next
    }

    /// Re-tests this window's own evidence against the ledger as it stands **now**, moving every
    /// pending peer whose stored digest equals local inventory into `matched`.
    ///
    /// The free half of the closing rule: it costs no frame and it closes the one-directional case,
    /// where this device was strictly behind and the peer's digest was right all along. The local
    /// half of the comparison is always current state and the peer half cannot predate the window.
    ///
    /// - Parameters:
    ///   - local: This device's inventory digest right now.
    ///   - reachable: The peers whose slot and roster membership still stand.
    /// - Returns: The next window.
    func reEvaluated(against local: MeshInventoryDigest, reachable: Set<String>) -> Self {
        var next = self
        let outstanding = pending(reachable: reachable).sorted()
        for peer in outstanding.prefix(MeshMembershipBounds.maxRosterMembers)
        where evidence[peer] == local {
            next.matched = Self.inserting(peer, into: next.matched)
        }
        return next
    }

    // MARK: - Reads

    /// The peers this window is still waiting on: `(asked ∪ answered) ∩ reachable ∖ matched`.
    ///
    /// Dropping an unreachable peer is deliberately **not** a membership change — invariant 1 says a
    /// socket is a delivery opportunity, and `asked` is a set of asks in flight, not a roster.
    ///
    /// - Parameter reachable: Every committed slot's fingerprint ∩ the derived roster.
    /// - Returns: The outstanding peers.
    func pending(reachable: Set<String>) -> Set<String> {
        asked.union(answered).intersection(reachable).subtracting(matched)
    }

    /// Whether the window closes now, and why.
    ///
    /// - Parameter reachable: Every committed slot's fingerprint ∩ the derived roster.
    /// - Returns: The verdict.
    func verdict(reachable: Set<String>) -> MeshMergeWindowVerdict {
        let outstanding = pending(reachable: reachable)
        guard outstanding.isEmpty else { return .open(outstanding: outstanding.count) }
        return .closed(matched.isEmpty ? .nothingOutstanding : .converged)
    }

    /// Whether a post-merge proof of `digest` is worth a frame: the budget is unspent and this is
    /// not the state already advertised.
    ///
    /// - Parameter digest: The local inventory digest a fold just produced.
    /// - Returns: `true` when the proof should be sent.
    func needsProof(of digest: MeshInventoryDigest) -> Bool {
        proofCount < Self.maxProofs && digest != provenDigest
    }

    /// Which side of the exchange this window is waiting on, derived from the sets.
    var role: MeshMergeWindowRole {
        switch (asked.isEmpty, answered.isEmpty) {
        case (false, false): return .both
        case (false, true): return .initiator
        case (true, false): return .responder
        case (true, true): return .idle
        }
    }

    // MARK: - The one bounded insert

    /// Inserts `peer` into `set` under the roster cap: already present, **or** room for one more.
    ///
    /// - Parameters:
    ///   - peer: The fingerprint to record.
    ///   - set: The set to grow.
    /// - Returns: The set, grown or unchanged.
    private static func inserting(_ peer: String, into set: Set<String>) -> Set<String> {
        guard set.contains(peer)
                || set.count < MeshMembershipBounds.maxRosterMembers else { return set }
        var next = set
        next.insert(peer)
        return next
    }
}
