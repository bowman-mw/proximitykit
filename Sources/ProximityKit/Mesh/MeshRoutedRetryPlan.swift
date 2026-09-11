// MeshRoutedRetryPlan.swift
// ProximityKit
//
// Network migration P6 item 5 (plan §23.3, D-13.32): the allowance discipline for the re-entry
// pass's TWO retry lists.
//
// The re-entry pass spends a fixed 16-item allowance (`MeshRoutedDrainBounds.increment1.maxItems`)
// per list per pass, and both lists are ordered by `MeshRoutedItemKey` — origin fingerprint first,
// i.e. a position whoever mints the item chooses by grinding a fingerprint. Item 4 closed half of
// D-13.32 by marking every refusal that CANNOT change (`MeshRoutedProjectionVerdict.refusedForGood`
// → `MeshRoutedProjectionVerdict/leavesTheRetryList`), so a permanently-refusing population leaves.
// What is left is the population that refuses and is RIGHT to stay: a store that answered deferred,
// a blip-time liveness skip, an origin the ledger cannot resolve *yet* — and, from item 6, a heart
// whose ledger judgement needs a foreground this device does not have. Sixteen of those occupy the
// whole pass at every rising access edge, and a genuinely new item behind them is never reached.
//
// This file is the fix, and it is deliberately a **pure value type over keys**: it names no routed
// type token, no registry, no store and no manifest, so it cannot acquire a per-type opinion (item
// 6 supplies its heart predicate to the manager's `ackableNow(_:in:)` filter, never here). The
// per-session state is `MeshRoutedRetryRotation`, memory-only and bounded by
// `MeshRoutedStoreFormat.maxItems` — see its doc for why memory-only is honest here.

import Foundation

// MARK: - MeshRoutedRetryList

/// Which of the re-entry pass's two retry lists a rotation belongs to.
///
/// Two lists, one mechanism: ``MeshRoutedIndex/itemsAwaitingLocalAck(at:for:)`` (job 4, the
/// receipts — ciphertext facts, filed whether or not the access gate is open) and
/// ``MeshRoutedIndex/itemsAwaitingLocalProjection(at:for:types:)`` (job 5, the plaintext). They keep
/// **separate** rotations on purpose: the same item can be on both, and an item job 4 has already
/// attempted has not thereby had its turn at job 5.
///
/// Frozen English `rawValue`s — they name audit-line context, never user copy.
nonisolated enum MeshRoutedRetryList: String, CaseIterable, Equatable, Sendable {

    /// Job 4's list: this device is a destination and its own recipient receipt is not stored.
    case localAck

    /// Job 5's list: a complete, locally-destined item whose plaintext no canonical store has yet
    /// been told about.
    case localProjection
}

// MARK: - MeshRoutedRetryPlan

/// One re-entry pass's allowance, split between items this session has never attempted and items it
/// has attempted and must retry (P6 item 5, D-13.32).
///
/// ## The rule
///
/// * **Never-attempted first.** At most ``retryShareDivisor``⁻¹ of the allowance — 8 of 16 — may go
///   to keys a previous pass in this session already attempted, so a retrying population can never
///   occupy more than half the pass and the other half is reserved for work nobody has tried.
/// * **Unused slots spill, in both directions.** The share is a *floor* for new work, not a ceiling
///   on throughput: with one new key and sixteen retryables the pass runs 1 + 15, and with no new
///   keys at all it runs 16 retryables. A reserved slot is never left empty while work waits.
/// * **Round-robin inside the retry share.** `rotation` is a queue: a key the caller records as
///   still-retryable moves to its back, so the retryables a pass could not fit are tried before the
///   ones that ran. Without that, the low-sorting head of a 24-item retry population would be the
///   only part ever retried and the tail would starve — the same defect as the original, one level
///   down.
///
/// ## Why a value type
///
/// It is `nonisolated`, deterministic, allocation-bounded and total: the same four inputs always
/// give the same plan, there is no clock in it, and every output key came from `enumerated`. That is
/// what lets the whole table be tested without a mesh, a store or an item in existence — and what
/// keeps the manager's two call sites down to one line each.
nonisolated struct MeshRoutedRetryPlan: Equatable, Sendable {

    /// How the allowance is divided: at most `allowance / retryShareDivisor` slots for keys already
    /// attempted this session, the rest reserved for keys that have never been attempted.
    ///
    /// Two, i.e. half and half, which is the launcher's own number. The choice is a trade between
    /// how fast a retrying backlog drains and how long a new item can be made to wait, and half is
    /// the point where neither side can be starved by the other: with the 16-item allowance a
    /// hostile origin holding the whole retry share still leaves 8 slots it cannot touch, and a
    /// steady stream of new items still lets every retryable through in ⌈n/8⌉ passes.
    static let retryShareDivisor = 2

    /// The keys to attempt this pass — never-attempted first, then the retry share in rotation
    /// order. At most `allowance` of them, and every one of them came from `enumerated`.
    let keysToTry: [MeshRoutedItemKey]

    /// How many leading elements of ``keysToTry`` this session had never attempted.
    let neverTriedCount: Int

    /// How many attempted-retryable keys this pass could not fit. The caller audits a non-zero
    /// value: it is the only externally visible sign that a retrying population is being paced.
    let deferredRetryCount: Int

    /// How many of ``keysToTry`` are retries.
    var retriedCount: Int { keysToTry.count - neverTriedCount }

    /// Plans one pass.
    ///
    /// - Parameters:
    ///   - enumerated: The retry list, in the index's own order (origin fingerprint, then item id).
    ///   - attempted: The keys a previous pass in this session attempted and did not finish.
    ///   - rotation: Those keys as a queue, least-recently-attempted first.
    ///   - allowance: The per-pass item allowance. A value below 1 plans nothing.
    init(
        enumerated: [MeshRoutedItemKey],
        attempted: Set<MeshRoutedItemKey>,
        rotation: [MeshRoutedItemKey],
        allowance: Int
    ) {
        let budget = max(0, allowance)
        let neverTried = enumerated.filter { !attempted.contains($0) }
        let retryable = Self.rotated(enumerated.filter { attempted.contains($0) }, by: rotation)
        // The reserved half is computed from what the retry share COULD claim, so a pass with no
        // retryables hands its whole allowance to new work and one with no new work hands its whole
        // allowance to retries.
        let reserved = min(retryable.count, budget / Self.retryShareDivisor)
        let newTaken = min(neverTried.count, max(0, budget - reserved))
        let retryTaken = min(retryable.count, max(0, budget - newTaken))
        keysToTry = Array(neverTried.prefix(newTaken)) + Array(retryable.prefix(retryTaken))
        neverTriedCount = newTaken
        deferredRetryCount = retryable.count - retryTaken
    }

    /// `keys` in round-robin order: whatever `rotation` names, in its order, then whatever it does
    /// not name, in `keys`' own order.
    ///
    /// The second half is not dead code for a caller that records every attempt — it is what keeps
    /// the function **total**. A key can be in `attempted` and absent from the queue only if a
    /// caller's two halves disagree, and answering that with "last" rather than with a crash is the
    /// difference between a paced list and a trap.
    ///
    /// - Parameters:
    ///   - keys: The attempted-retryable keys this pass enumerated.
    ///   - rotation: The queue.
    /// - Returns: the keys, re-ordered.
    private static func rotated(
        _ keys: [MeshRoutedItemKey], by rotation: [MeshRoutedItemKey]
    ) -> [MeshRoutedItemKey] {
        let present = Set(keys)
        let queued = Set(rotation)
        // R2: both filters are bounded by the store's item cap, and both are hash lookups.
        return rotation.filter { present.contains($0) } + keys.filter { !queued.contains($0) }
    }
}

// MARK: - MeshRoutedRetryRotation

/// One retry list's memory-only, per-session record of what the re-entry has already attempted —
/// the state ``MeshRoutedRetryPlan`` plans against (P6 item 5).
///
/// ## Memory-only, and why that is honest
///
/// Nothing here reaches disk, the routed index stays schema 2, and the whole value is dropped by
/// `MeshNetworkManager.clearRoutedDrainState()` with the rest of the drain state. It owes no
/// `Docs/PrivacyWipeCoverage.md` row for the same reason the projected set does not.
///
/// Losing it costs exactly one thing: after a restart every held item looks never-attempted again.
/// That is what ``armed(at:)`` and ``noteCarriedOver(_:)`` exist for — an item this device already
/// held when the session's first pass ran is placed in the retry share rather than in the reserved
/// half, so re-deriving a backlog of refusals after a restart cannot evict a genuinely new item.
/// The re-derivation itself is bounded and does not recur: item 4's finals are re-derived once each,
/// at one unwrap apiece, and then leave both sets for good.
///
/// ## Bounded, and audited at the bound
///
/// ``attempted`` never grows past ``MeshRoutedStoreFormat/maxItems``, which is the cap on the items
/// that can exist to be attempted. At the bound the rotation **refuses to remember** rather than
/// growing, and says so through its caller's audit line: a key that cannot be remembered stays
/// never-attempted, which degrades toward trying new work rather than toward starving it.
nonisolated struct MeshRoutedRetryRotation: Equatable, Sendable {

    /// The keys a previous pass attempted this session and that still owe work.
    private(set) var attempted: Set<MeshRoutedItemKey> = []

    /// ``attempted`` as a queue, least-recently-attempted first — the round-robin order.
    private(set) var order: [MeshRoutedItemKey] = []

    /// When this session's first pass ran, or nil before it. The cut between "already held" and
    /// "new since this session began".
    private(set) var armedAt: Date?

    /// An empty rotation, before any pass has run.
    init() {}

    /// Whether the tried set is at its bound and can remember nothing new.
    var isAtCapacity: Bool { attempted.count >= MeshRoutedStoreFormat.maxItems }

    /// Arms the rotation on the first pass and answers the armed instant on every pass.
    ///
    /// Deliberately the FIRST PASS's instant rather than the process's start: the point of the
    /// cut is "this device already held the item when we began working through the list", and the
    /// pass is the moment work begins. An item first seen at exactly this instant is treated as new
    /// — a newcomer gets the benefit of the doubt, and a frozen-clock fixture needs the strict
    /// comparison to be able to express a new arrival at all.
    ///
    /// - Parameter now: The pass's injected instant.
    /// - Returns: the instant this session's first pass ran.
    mutating func armed(at now: Date) -> Date {
        if let armedAt { return armedAt }
        armedAt = now
        return now
    }

    /// Records that an attempted key still owes work, and moves it to the back of the queue.
    ///
    /// - Parameter key: The key the pass just attempted.
    /// - Returns: `false` when the bound refused it, which the caller audits.
    mutating func noteRetryable(_ key: MeshRoutedItemKey) -> Bool { remember(key) }

    /// Records that a key was already held before this session's first pass, so it competes for the
    /// retry share rather than for the reserved never-attempted half.
    ///
    /// Idempotent, and it never re-orders a key the pass has genuinely attempted: an item enumerated
    /// at every pass would otherwise be shuffled to the back of the queue on each one, which would
    /// undo the rotation it is meant to feed.
    ///
    /// - Parameter key: The key, from a ref whose `firstSeenAt` precedes ``armedAt``.
    /// - Returns: `false` when the bound refused it, which the caller audits.
    mutating func noteCarriedOver(_ key: MeshRoutedItemKey) -> Bool {
        guard !attempted.contains(key) else { return true }
        return remember(key)
    }

    /// Drops a key from **both** the tried set and the queue — the mark for an item that is finished
    /// or refused for a reason that cannot change.
    ///
    /// Item 4's one caller (`MeshNetworkManager.projectRoutedItemIfPermitted(key:manifest:seenAt:)`)
    /// is where job 5's verdict reaches this; job 4's is its own filed-receipt branch. A key that is
    /// not present is not an error: a live delivery can finish an item the re-entry never saw.
    ///
    /// - Parameter key: The key that leaves the retry list.
    mutating func noteFinal(_ key: MeshRoutedItemKey) {
        attempted.remove(key)
        // R3: bounded by the store's item cap.
        order.removeAll { $0 == key }
    }

    /// Plans one pass over `enumerated`.
    ///
    /// - Parameters:
    ///   - enumerated: The retry list, in the index's own order.
    ///   - allowance: The per-pass item allowance.
    /// - Returns: the plan.
    func plan(for enumerated: [MeshRoutedItemKey], allowance: Int) -> MeshRoutedRetryPlan {
        MeshRoutedRetryPlan(
            enumerated: enumerated, attempted: attempted, rotation: order, allowance: allowance
        )
    }

    /// Inserts or re-queues one key, refusing to grow past the bound.
    ///
    /// - Parameter key: The key.
    /// - Returns: whether it is remembered.
    private mutating func remember(_ key: MeshRoutedItemKey) -> Bool {
        guard attempted.contains(key) || !isAtCapacity else { return false }
        attempted.insert(key)                                         // R3: bounded set
        // R3: bounded by the store's item cap; the append keeps the queue a permutation of the set.
        order.removeAll { $0 == key }
        order.append(key)
        return true
    }
}
