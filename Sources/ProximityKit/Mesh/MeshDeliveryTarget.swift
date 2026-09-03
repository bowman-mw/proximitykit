// MeshDeliveryTarget.swift
// ProximityKit/Mesh
//
// P4 item 8 (plan §10.1): **who a piece of content is for**, held apart from **how far each copy
// has got**.
//
// §10.1 is one rule and this file is that rule as a type:
//
//   > Content created during a split is manifest-signed with the destination set = *full roster at
//   > creation time* (not the connected set). Members of the other partition are simply destinations
//   > whose delivery is pending. Content keys are wrapped per recipient identity, so nothing about
//   > content depends on which partition (or which group-key epoch) it was created in.
//
// The distinction the type exists to make structural: **reachable vs unreachable is a DELIVERY
// state, never a DESTINATION state.** A photo taken during a 2/2 split of a roster of four is for
// three people, two of whom happen to be on the far side of the split right now; they are pending
// deliveries, not non-recipients. The mistake §5(c) of the P4 launcher warns about — P5 silently
// inheriting "the connected set" as the destination set — is made unrepresentable here rather than
// remembered at each call site:
//
//   * ``MeshDeliveryTarget`` is initialized from a ``MeshDerivedRoster``. There is no initializer
//     that takes a reachable set, a ``MeshBranchView``, or a bare list of fingerprints.
//   * There is no API that removes a destination. The set is `let`, and every mutating-looking
//     method returns a value whose destination set is identical by construction or refuses by name.
//   * Unreachability reaches this file only through the two *derivations* at the bottom, which
//     partition the **outstanding** destinations into reachable and unreachable. Neither can move a
//     destination out of the set.
//
// **Nothing here is persisted and nothing here is wire.** `MeshSessionContext`'s schema stays 2, no
// `UserDefaults` key is added, and no payload gains a field. P5 persists targets inside its routed
// store, next to the manifests they belong to (plan §11); this phase owns only the vocabulary the
// manifest's destination set is expressed in.
//
// **There is no clock in this file and none behind it.** States advance by explicit calls carrying
// the receipt as evidence, never by elapsed time — so a forged stamp has nothing to influence and
// tier 1 asserts the whole lifecycle without a transport.

import Foundation

// MARK: - MeshDeliveryStateToken

/// The frozen English spelling of one delivery state.
///
/// Split out of ``MeshDeliveryState`` and ``MeshDeliveryDisposition`` so both spell a state the
/// same way and so the spellings are `CaseIterable` `rawValue`s that a test can walk. They are
/// **frozen tokens**: logged verbatim, compared as strings, and never localized. Any display copy
/// for a pending or stalled delivery (plan §18.2, still owner-gated) forks separately as a
/// `LocalizedStringKey`.
nonisolated enum MeshDeliveryStateToken: String, Equatable, Sendable, CaseIterable {

    /// Nobody has reported holding or receiving this destination's copy yet. The state an
    /// unreachable member sits in — *pending*, never absent.
    case pending

    /// A relay holds durable ciphertext for this destination (P5's `MeshCustodyReceipt`).
    /// **Custody is not delivery** (plan §11) and this token says so on its own.
    case custodied

    /// The destination has it, finally: durable recipient storage for photos and text, and for
    /// hearts only after the foreground decrypt and the ledger commit (plan §11).
    case delivered

    /// The derived roster no longer names this destination, so no further attempt can succeed.
    case departed
}

// MARK: - MeshDeliveryState

/// How far one destination's copy has got — the half that is **stored and merged**.
///
/// A three-rung monotone ladder, `pending < custodied < delivered`, and nothing walks back down it:
/// ``MeshDeliveryTarget/advancing(_:to:)`` refuses a regression by name rather than ignoring it, and
/// ``later(_:_:)`` — the merge rule — only ever moves up. ``MeshDeliveryStateToken/departed`` is
/// deliberately **not** a case here: closure is a fact about the *roster*, derived at read against a
/// current ``MeshDerivedRoster`` (see ``MeshDeliveryDisposition``), never a flag a peer can set. That
/// keeps the merged state a pure three-element chain and keeps the membership ledger the only
/// authority on who is still a member.
nonisolated enum MeshDeliveryState: Equatable, Sendable {

    /// Nothing is known to hold this destination's copy yet. The default for every destination,
    /// including one that has been unreachable since the item was created.
    case pending

    /// A relay named here holds durable ciphertext for this destination. Custody ≠ delivery.
    case custodied(by: String)

    /// The destination has it. **Terminal** (plan §11's final ack): a later departure cannot
    /// un-happen it, and no call can move it.
    case delivered

    /// This state's frozen English spelling.
    var token: MeshDeliveryStateToken {
        switch self {
        case .pending: return .pending
        case .custodied: return .custodied
        case .delivered: return .delivered
        }
    }

    /// The rung on the monotone ladder. Higher is later; equal ranks are the same rung.
    var rank: Int {
        switch self {
        case .pending: return 0
        case .custodied: return 1
        case .delivered: return 2
        }
    }

    /// The relay holding this destination's copy, or nil when nothing is custodying it.
    var custodianFingerprint: String? {
        if case .custodied(let relay) = self { return relay }
        return nil
    }

    /// The read-time answer for a destination the roster still names.
    var disposition: MeshDeliveryDisposition {
        switch self {
        case .pending: return .pending
        case .custodied(let relay): return .custodied(by: relay)
        case .delivered: return .delivered
        }
    }

    /// The later of two states — the **max under the monotone order**, which is the whole merge
    /// rule for one destination.
    ///
    /// Commutative, associative and idempotent. The only case the ladder cannot separate is two
    /// relays both custodying the same item, which is not a conflict (both really do hold it); the
    /// lexicographically least custodian fingerprint is taken so that the answer cannot depend on
    /// which receipt arrived first. It is a **tiebreak, not a preference** — P5 may relay from
    /// either custodian.
    static func later(_ lhs: MeshDeliveryState, _ rhs: MeshDeliveryState) -> MeshDeliveryState {
        if lhs.rank != rhs.rank { return lhs.rank > rhs.rank ? lhs : rhs }
        guard let left = lhs.custodianFingerprint, let right = rhs.custodianFingerprint else {
            return lhs
        }
        return left <= right ? lhs : rhs
    }
}

// MARK: - MeshDeliveryDisposition

/// What one destination reads as **right now**, against a current derived roster.
///
/// ``MeshDeliveryState`` plus the one answer that is not stored: ``departed``, derived when the
/// merged roster no longer names the destination. Three-way, and the three ways are what P5's drain
/// branches on:
///
/// | Bucket | Cases | What the drain does |
/// | --- | --- | --- |
/// | outstanding | ``pending``, ``custodied(by:)`` | keep trying |
/// | complete | ``delivered`` | stop, it arrived |
/// | closed | ``departed`` | stop, it never can |
///
/// ``delivered`` outranks a later departure: a destination that received the item before it left
/// reads `delivered`, because plan §11's final ack is a *fact*, not a status that a membership
/// record can revoke.
nonisolated enum MeshDeliveryDisposition: Equatable, Sendable {

    /// On the roster, nothing holds it yet. **An unreachable member is here, not missing.**
    case pending

    /// On the roster, a relay holds durable ciphertext for it.
    case custodied(by: String)

    /// It arrived. Terminal.
    case delivered

    /// The derived roster has dropped this destination — a signed departure or a completed removal
    /// unioned in — so no further attempt can ever succeed.
    ///
    /// **Closed forever, not closed for now.** Membership records are grow-only, so a departed or
    /// removed fingerprint can never re-enter the same mesh's roster (a later admission for it is
    /// subtracted straight back out by ``MeshDerivedRoster``); rejoining means a new mesh. That is
    /// what makes it safe for P5's drain to stop rather than back off.
    case departed

    /// This disposition's frozen English spelling.
    var token: MeshDeliveryStateToken {
        switch self {
        case .pending: return .pending
        case .custodied: return .custodied
        case .delivered: return .delivered
        case .departed: return .departed
        }
    }

    /// Whether P5's drain still has work to do for this destination.
    var isOutstanding: Bool { self == .pending || token == .custodied }

    /// Whether the roster closed this destination. Distinct from ``pending`` on purpose: a pending
    /// destination is one the drain must keep trying, a closed one is one it must stop trying.
    var isClosed: Bool { self == .departed }
}

// MARK: - MeshDeliveryRefusal

/// Why a delivery-target operation was refused. Frozen English tokens, logged verbatim.
///
/// Every one of these is a **bug at the caller**, not a knob: a target's destination set is
/// immutable and its states only rise, so nothing here is an ordinary outcome to be retried.
/// Naming them is what stops a wrong advance or a mismatched merge being applied silently.
nonisolated enum MeshDeliveryRefusal: String, Equatable, Sendable, CaseIterable {

    /// The fingerprint is not in this target's destination set. Adding one is impossible: the set
    /// was fixed from the roster at creation.
    case notADestination

    /// The destination is already ``MeshDeliveryState/delivered``, which is terminal.
    case alreadyDelivered

    /// The requested state is *below* the destination's current one on the monotone ladder.
    case wouldRegress

    /// The two targets describe different content ids, so their per-destination states are about
    /// different items.
    case differentContent

    /// The two targets disagree about **who the content is for**. A destination set is immutable
    /// and derived from the same roster at the same instant, so a mismatch means one of them was
    /// built wrongly — the merge refuses rather than picking a union or an intersection, either of
    /// which would silently invent or drop a recipient.
    case destinationSetMismatch
}

// MARK: - MeshDeliveryOutcome

/// The result of advancing or merging a ``MeshDeliveryTarget``: the new value, or a named refusal.
///
/// One outcome type for both operations, so "refused by name" is one vocabulary
/// (``MeshDeliveryRefusal``) rather than two that could drift.
nonisolated enum MeshDeliveryOutcome: Equatable, Sendable {

    /// The operation applied; the associated value is the resulting target.
    case updated(MeshDeliveryTarget)

    /// The operation was refused, and this is why.
    case refused(MeshDeliveryRefusal)

    /// The resulting target, or nil when the operation was refused.
    var target: MeshDeliveryTarget? {
        if case .updated(let target) = self { return target }
        return nil
    }

    /// The refusal, or nil when the operation applied.
    var refusal: MeshDeliveryRefusal? {
        if case .refused(let refusal) = self { return refusal }
        return nil
    }
}

// MARK: - MeshDeliveryTarget

/// Who one piece of content is for, and how far each destination's copy has got (plan §10.1).
///
/// ## The rule this type is
///
/// The destination set is the **full derived roster at creation time, minus this device** — never
/// the connected set, never the branch. It is captured once, in ``init(contentID:roster:selfFingerprint:)``,
/// and never changes for the life of the target. Reachability is expressed only as a
/// ``MeshDeliveryState``: an unreachable member is ``MeshDeliveryState/pending``, which is a
/// *delivery* state, and the far side of a partition is therefore a pending delivery rather than a
/// dropped recipient.
///
/// ## What P5 must do with it
///
/// - **Express `MeshRoutedManifest`'s destination set in this vocabulary.** The manifest's immutable
///   destination set *is* ``destinations``; the per-recipient `MeshRecipientKeyWrap`s are minted one
///   per entry in it, which is what makes content independent of the partition and the group-key
///   epoch it was created in (§10.1). This type is the vocabulary, not a second manifest — it holds
///   no hash, no size, no expiry and no key material.
/// - **Drive the drain off ``outstanding(in:)``**, which is exactly "destinations lacking a
///   `MeshRecipientReceipt`" (§11's partition duty), and stop at ``isFullyDelivered(in:)``.
/// - **Advance on evidence.** A `MeshCustodyReceipt` is ``MeshDeliveryState/custodied(by:)``; a
///   `MeshRecipientReceipt` is ``MeshDeliveryState/delivered`` — and for hearts only after the
///   foreground decrypt and the ledger commit, never on durable custody (§11: custody ≠ delivery in
///   every UI surface).
/// - **Persist it inside the routed store**, beside the manifest. Nothing here is `Codable` and
///   nothing here is on the wire, so `MeshSessionContext`'s schema stays **2**; giving the routed
///   store its own encoding is P5's decision, made once, with its own wipe-coverage row.
/// - **Merge two members' views with ``merging(_:)``**, which takes the per-destination max. Two
///   members that learned different receipts converge without either losing one.
///
/// ## What P5 must not do with it
///
/// - **Do not build one from the connected set, a ``MeshBranchView``, or a reachable-peer list.**
///   There is no such initializer, and adding one would reintroduce exactly the bug §10.1 forbids.
/// - **Do not drop a destination because it is unreachable, slow, or on the far side of a split.**
///   Nothing here can remove a destination; a member the roster later drops is reported
///   ``MeshDeliveryDisposition/departed`` at read, from the ledger, not by a caller's judgement.
/// - **Do not put a key epoch, a branch id, or a "created in partition X" on it.** It carries none
///   by design (§10.1: nothing about content depends on which partition or which epoch it was
///   created in), and `MeshNetworkManager`'s three surviving `keyEpoch` gates are retired by P5's
///   routed path (plan §21.5), not by a field here.
/// - **Do not treat custody as delivery**, and do not mark a heart delivered on receipt of bytes.
///
/// ## Equality and normalization
///
/// A destination sitting at ``MeshDeliveryState/pending`` is stored as an *absence*, so two targets
/// that mean the same thing are `==` regardless of how they got there — which is what makes the
/// merge laws assertable on `==` rather than on a hand-written comparison.
///
/// Pure value: `Sendable`, `Equatable`, no isolation, no clock, no I/O, bounded by the roster cap.
nonisolated struct MeshDeliveryTarget: Equatable, Sendable {

    /// The content this target is about — the id P5's `MeshRoutedManifest` keys on, and the same id
    /// ``MeshMergeableContent/contentID`` uses, so a merged item and its target agree.
    let contentID: UUID

    /// The immutable destination set, in the derived roster's own fingerprint order.
    private let destinationOrder: [String]

    /// Per-destination state, holding only destinations that have moved off `pending`.
    private let progress: [String: MeshDeliveryState]

    /// Captures the destination set from the **derived roster at this instant**, minus this device.
    ///
    /// The roster is the only source. A caller holding a branch view and a roster cannot pass the
    /// branch here by mistake, because the parameter's type is ``MeshDerivedRoster``.
    ///
    /// - Parameters:
    ///   - contentID: The item this target is about.
    ///   - roster: The **merged** derived roster, unmoved by any partition (plan §10.2).
    ///   - selfFingerprint: This device, which is never a destination for its own content.
    init(contentID: UUID, roster: MeshDerivedRoster, selfFingerprint: String) {
        self.contentID = contentID
        destinationOrder = roster.memberFingerprints.filter { $0 != selfFingerprint }
        progress = [:]
    }

    /// Captures a target for a merged content item — the one-call form a schedule uses when a
    /// content event fires (P4 item 9's seam, and P5's when the routed store mints a manifest).
    init(for item: some MeshMergeableContent, roster: MeshDerivedRoster, selfFingerprint: String) {
        self.init(contentID: item.contentID, roster: roster, selfFingerprint: selfFingerprint)
    }

    /// The private memberwise form, used only by operations that preserve the destination set.
    private init(contentID: UUID, destinationOrder: [String], progress: [String: MeshDeliveryState]) {
        self.contentID = contentID
        self.destinationOrder = destinationOrder
        self.progress = progress
    }

    /// Who the content is for, in the roster's deterministic order. Immutable for the target's life.
    var destinations: [String] { destinationOrder }

    /// How many destinations there are.
    var destinationCount: Int { destinationOrder.count }

    /// Whether `fingerprint` is one of the destinations.
    func names(_ fingerprint: String) -> Bool { destinationOrder.contains(fingerprint) }

    /// One destination's stored state, or nil when the target does not name it.
    ///
    /// Nil is a real third answer and never a synonym for `pending`, in the idiom of
    /// ``MeshBranchView/presence(of:)``.
    func state(of fingerprint: String) -> MeshDeliveryState? {
        guard names(fingerprint) else { return nil }
        return progress[fingerprint] ?? .pending
    }

    /// One destination's read-time disposition against `roster`, or nil when the target does not
    /// name it.
    ///
    /// - Parameter roster: The **current** merged derived roster — the departed answer is derived
    ///   from it at read, exactly as a termination downgrade is (plan §8.3), so no state has to be
    ///   rewritten when a departure record arrives.
    func disposition(of fingerprint: String, in roster: MeshDerivedRoster) -> MeshDeliveryDisposition? {
        guard let state = state(of: fingerprint) else { return nil }
        if state == .delivered { return .delivered }
        guard roster.contains(fingerprint: fingerprint) else { return .departed }
        return state.disposition
    }

    /// Every destination's disposition against `roster`, keyed by fingerprint.
    func dispositions(in roster: MeshDerivedRoster) -> [String: MeshDeliveryDisposition] {
        var answers: [String: MeshDeliveryDisposition] = [:]
        for destination in destinationOrder {
            guard let disposition = disposition(of: destination, in: roster) else { continue }
            answers[destination] = disposition
        }
        return answers
    }

    /// The destinations P5's drain still has work for — pending plus custodied — in destination
    /// order. Departed and delivered destinations are absent.
    func outstanding(in roster: MeshDerivedRoster) -> [String] {
        destinationOrder.filter { disposition(of: $0, in: roster)?.isOutstanding == true }
    }

    /// The destinations the roster has closed. The drain stops on these rather than backing off.
    func closed(in roster: MeshDerivedRoster) -> [String] {
        destinationOrder.filter { disposition(of: $0, in: roster)?.isClosed == true }
    }

    /// Whether every destination that can still receive the content has. Equivalently: nothing is
    /// outstanding.
    ///
    /// A target whose every destination has departed is fully delivered *vacuously* — there is
    /// nobody left to deliver to, which is precisely the answer that lets P5 retire the item.
    func isFullyDelivered(in roster: MeshDerivedRoster) -> Bool {
        outstanding(in: roster).isEmpty
    }

    /// Advances one destination on the monotone ladder, with the receipt as the evidence.
    ///
    /// Never a clock: nothing here advances because time passed. Refusals are named
    /// (``MeshDeliveryRefusal``) rather than applied silently, because every one of them is a caller
    /// bug — a receipt for a non-destination, or a receipt that would walk a destination backwards.
    ///
    /// Re-applying the state a destination is already in is *not* a regression: it succeeds and
    /// changes nothing, which is what makes a redelivered receipt idempotent.
    func advancing(_ fingerprint: String, to state: MeshDeliveryState) -> MeshDeliveryOutcome {
        guard let current = self.state(of: fingerprint) else { return .refused(.notADestination) }
        if current == .delivered && state != .delivered { return .refused(.alreadyDelivered) }
        guard state.rank >= current.rank else { return .refused(.wouldRegress) }
        return .updated(storing(MeshDeliveryState.later(current, state), for: fingerprint))
    }

    /// Merges another member's view of the same target: the per-destination **max** under the
    /// monotone order.
    ///
    /// Commutative, associative and idempotent, because "max under a total order" is. Two members
    /// that learned different receipts — one saw the custody, the other saw the delivery — converge
    /// on the later of the two for every destination, and neither loses what it knew.
    ///
    /// The destination sets must be identical. They are derived from the same roster at the same
    /// instant, so a mismatch is a bug rather than a state to reconcile: taking a union would invent
    /// a recipient and taking an intersection would drop one, and both are the failure §10.1 exists
    /// to prevent. It is refused by name instead.
    func merging(_ other: MeshDeliveryTarget) -> MeshDeliveryOutcome {
        guard contentID == other.contentID else { return .refused(.differentContent) }
        guard destinationOrder == other.destinationOrder else {
            return .refused(.destinationSetMismatch)
        }
        var merged: [String: MeshDeliveryState] = [:]
        for destination in destinationOrder {
            let mine = progress[destination] ?? .pending
            let theirs = other.progress[destination] ?? .pending
            let later = MeshDeliveryState.later(mine, theirs)
            if later != .pending { merged[destination] = later }
        }
        return .updated(
            MeshDeliveryTarget(contentID: contentID, destinationOrder: destinationOrder, progress: merged)
        )
    }

    /// The outstanding destinations this branch can reach right now — the custodians a handoff can
    /// actually offer content to.
    ///
    /// This is the derivation ``MeshDevelopmentPlan/handoffTargets`` already performs for a fresh
    /// target: for content nothing has been delivered or custodied for yet, it is exactly
    /// ``MeshBranchView/externalPresentFingerprints``. Reachability filters the *work*, never the
    /// destination set.
    func outstandingReachable(from branch: MeshBranchView, in roster: MeshDerivedRoster) -> [String] {
        outstanding(in: roster).filter { branch.presence(of: $0) == .present }
    }

    /// The outstanding destinations this branch cannot reach — the pending deliveries a partition
    /// is holding up.
    ///
    /// For a fresh target this is exactly ``MeshBranchView/temporarilyDisconnectedFingerprints``:
    /// item 1's "temporarily disconnected" set *is* the pending-delivery set, seen from the presence
    /// side. They stay destinations throughout.
    func outstandingUnreachable(from branch: MeshBranchView, in roster: MeshDerivedRoster) -> [String] {
        outstanding(in: roster).filter { branch.presence(of: $0) == .temporarilyDisconnected }
    }

    /// The target with one destination's state replaced, normalizing `pending` to an absence.
    private func storing(_ state: MeshDeliveryState, for fingerprint: String) -> MeshDeliveryTarget {
        var updated = progress
        if state == .pending {
            updated.removeValue(forKey: fingerprint)
        } else {
            updated[fingerprint] = state
        }
        return MeshDeliveryTarget(
            contentID: contentID, destinationOrder: destinationOrder, progress: updated
        )
    }
}
