// MeshCustodyHandoffPlan.swift
// ProximityKit/Mesh
//
// Network migration P5 item 8 (plan §10.6, §11): custody-transfer-on-departure, as pure values.
//
// **The invariant this file exists to keep.** Custody is at the ORIGIN, or — after exactly one
// transfer, at exactly one moment, a development — at the custodians
// ``MeshDevelopmentPlan/handoffTargets`` names. There is no hand-off between two live, connected
// members and no second hop. Increment 2's general "any custodian may relay to any other" is
// declined by name (plan §11 gates it on a tier-2 device measurement), and nothing here is
// speculative plumbing for it.
//
// Everything in this file is a pure value: no store, no clock, no isolation, no I/O. The choosing
// lives here so ``MeshNetworkManager``'s development path stays a ten-line narrative and so the
// choice itself is unit-testable without a manager. Every bound is an EXISTING constant —
// `MeshRoutedStoreFormat.maxItems`, `MeshMembershipBounds.maxRosterMembers`,
// `MeshRoutedDrainBounds.increment1` — because a new number is a new policy nobody decided.

import Foundation
import FernletDomainModel

// MARK: - MeshCustodyHandoffScope

/// The run-scoped entitlement a live development opens: these custodians, until this deadline.
///
/// This is item 5's **entitlement source 2** — "the peer is a custodian this device chose at
/// departure" — made finite. It is armed once, inside the development, and cleared by
/// ``MeshNetworkManager``'s session reset, which the same development runs moments later; so the
/// entitlement cannot outlive the session it belongs to. Deliberately **not** derived from
/// `lastDevelopmentPlan`, which outlives the session on purpose: reading that would turn a
/// one-moment hand-off into a permanent relay entitlement, which is increment 2 arriving without a
/// decision.
nonisolated struct MeshCustodyHandoffScope: Equatable, Sendable {

    /// The reachable members custody was offered to.
    let custodians: Set<String>

    /// When the bounded handoff window closes — ``MeshDevelopmentPlan/handoffDeadline``.
    let deadline: Date

    /// Builds a scope over one development's custodians and window.
    init(custodians: Set<String>, deadline: Date) {
        self.custodians = custodians
        self.deadline = deadline
    }

    /// Whether `peer` may be offered handed-off content at `now`.
    ///
    /// Both halves matter: a peer outside the custodian set is not entitled at any instant, and no
    /// peer is entitled once the window has closed.
    func admits(_ peer: String, at now: Date) -> Bool {
        custodians.contains(peer) && now < deadline
    }
}

// MARK: - MeshCustodyHandoffSuppression

/// Why a development handed over nothing, when "nothing" was not the honest answer.
///
/// Frozen English tokens, logged verbatim, never display copy. The distinction the enum exists for
/// is the one plan §19.5 insists on: a store that could not say what it holds is **not** a store
/// that held nothing. `nil` — no suppression — is the only value that means "this device really did
/// hand over exactly what it says it did".
nonisolated enum MeshCustodyHandoffSuppression: String, Equatable, Sendable, CaseIterable {

    /// The routed store answered `deferred`, `corrupt` or seal-`refused`, so nothing was read and
    /// nothing was written. Never conflated with an empty store.
    case storeUnavailable

    /// ``MeshDevelopmentPlan/handoffTargets`` was empty — a partition of one, developing alone.
    case noReachableCustodian

    /// The rungs were written and the departure record was never emitted, so no custodian will ever
    /// be told it is one. The count is reported as unplaced rather than transferred.
    case recordNotEmitted

    /// The bounded hand-off window had already closed when the transfer ran, so nothing was read
    /// and nothing was written.
    ///
    /// Its own case rather than `nil`: a device that held placeable items and simply ran out of
    /// clock is neither "held nothing" nor "handed over exactly what it says it did", and
    /// collapsing it into `.none` is the conflation plan §19.5 asks this enum to prevent. The
    /// clock's own answer still rides ``MeshNetworkManager/lastDevelopmentHandoffOutcome`` — the two
    /// agree here rather than one standing in for the other.
    case windowExpired
}

// MARK: - MeshCustodyHandoffResult

/// What a development's custody transfer actually did, as one observable value.
///
/// ``transferredItemCount`` is the number the departure record signs
/// (``MeshCustodyHandoffSummary/handedOffItemCount``), and it is a statement about **this device's
/// own durable index** — not about sends, not about attempts, not about candidates. Nothing can
/// retract it once the record is signed, which is why it is under-reported on every uncertain path
/// rather than over-reported on any.
nonisolated struct MeshCustodyHandoffResult: Equatable, Sendable {

    /// The items whose rung moved `pending → custodied(by:)` and whose index save succeeded.
    let transferredItemKeys: [MeshRoutedItemKey]

    /// Candidate items this device could not place with any custodian — content it is leaving
    /// behind. Named rather than silently dropped (plan §3's "nothing grows silently").
    let unplacedItemKeys: [MeshRoutedItemKey]

    /// The items whose bytes the best-effort departure push offered to the custodians.
    let pushedItemKeys: [MeshRoutedItemKey]

    /// How many held items had a delivery map this device could not restore, at the transfer.
    let unrestorableCount: Int

    /// Why this transfer handed over less than it held, or nil when nothing suppressed it.
    let suppression: MeshCustodyHandoffSuppression?

    /// The one field P5 fills in a departure record.
    var transferredItemCount: Int { transferredItemKeys.count }

    /// Builds a result.
    init(
        transferredItemKeys: [MeshRoutedItemKey],
        unplacedItemKeys: [MeshRoutedItemKey],
        pushedItemKeys: [MeshRoutedItemKey],
        unrestorableCount: Int,
        suppression: MeshCustodyHandoffSuppression?
    ) {
        self.transferredItemKeys = transferredItemKeys
        self.unplacedItemKeys = unplacedItemKeys
        self.pushedItemKeys = pushedItemKeys
        self.unrestorableCount = unrestorableCount
        self.suppression = suppression
    }

    /// A development that transferred nothing and had nothing to suppress — a termination, an empty
    /// store, a device holding no routed content at all.
    static var none: MeshCustodyHandoffResult {
        MeshCustodyHandoffResult(
            transferredItemKeys: [], unplacedItemKeys: [], pushedItemKeys: [],
            unrestorableCount: 0, suppression: nil
        )
    }

    /// A development that transferred nothing for a named reason.
    static func suppressed(_ suppression: MeshCustodyHandoffSuppression) -> MeshCustodyHandoffResult {
        MeshCustodyHandoffResult(
            transferredItemKeys: [], unplacedItemKeys: [], pushedItemKeys: [],
            unrestorableCount: 0, suppression: suppression
        )
    }

    /// The same transfer, judged after the departure record could not be emitted.
    ///
    /// The rungs stay — they are true statements about this device's own index, and this device is
    /// leaving — but nothing was **announced**, so no custodian will ever run the claim and the
    /// items are reported as unplaced. Pushing bytes to custodians that will never be told they are
    /// custodians is retention with no delivery, so the push list empties too.
    func notAnnounced() -> MeshCustodyHandoffResult {
        MeshCustodyHandoffResult(
            transferredItemKeys: [],
            unplacedItemKeys: unplacedItemKeys + transferredItemKeys,
            pushedItemKeys: [],
            unrestorableCount: unrestorableCount,
            suppression: .recordNotEmitted
        )
    }
}

// MARK: - MeshCustodyHandoffPlan

/// Which items a departing origin hands to which custodian, and over which legs — the whole
/// choosing, as one pure value derived before any store is written.
///
/// ## The three rules, stated once
///
/// 1. **Only this device's own items.** The candidate enumerator takes a required `originatedBy:`,
///    so a departing *custodian* enumerates nothing: the second hop is unrepresentable rather than
///    remembered at a call site.
/// 2. **Only a custodian that already holds the bytes.** An eligible custodian is one in
///    ``MeshDevelopmentPlan/handoffTargets`` whose **verified custody receipt this device already
///    stores** — evidence it took the complete ciphertext durably. A rung written for a custodian
///    without the bytes is a signed claim nobody can serve.
/// 3. **Only `pending` legs, minus the custodian itself.** That makes all four
///    ``MeshDeliveryRefusal`` cases unreachable, makes the tiebreak's silent no-op impossible, and
///    makes "exactly one transfer" structural: the only writer of a `custodied(by:)` rung in this
///    index is the hand-off door, so a leg already carrying one was already handed.
///
/// The custodian chosen for an item is the **lexicographically least** eligible fingerprint — the
/// same tiebreak ``MeshDeliveryState/later(_:_:)`` uses, so this device's own map and any later
/// merge agree by construction. Other holders still claim independently on their own side; that
/// redundancy is additive and never a conflict.
nonisolated struct MeshCustodyHandoffPlan: Equatable, Sendable {

    /// The transfers the hand-off door will apply, one per item.
    let transfers: [MeshRoutedCustodyHandoff]

    /// Candidate items with no eligible custodian: not counted, and named. Their bytes are what the
    /// best-effort departure push offers, so a pure courier can serve them after a heal.
    let unplacedItemKeys: [MeshRoutedItemKey]

    /// Derives the plan from one index, one roster and one set of reachable custodians.
    ///
    /// - Parameters:
    ///   - index: This device's routed index, already loaded.
    ///   - roster: The **merged** derived roster — departed destinations are derived out.
    ///   - selfFingerprint: This device, which is also the only origin whose items are enumerated.
    ///   - custodians: ``MeshDevelopmentPlan/handoffTargets``.
    ///   - now: The injected instant the window opened against.
    init(
        index: MeshRoutedIndex,
        roster: MeshDerivedRoster,
        selfFingerprint: String,
        custodians: [String],
        at now: Date
    ) {
        let eligible = Set(custodians)
        var chosen: [MeshRoutedCustodyHandoff] = []
        var unplaced: [MeshRoutedItemKey] = []
        let candidates = index.itemsAwaitingHandoff(
            at: now, in: roster, originatedBy: selfFingerprint
        )
        // R2: bounded by the store's own item cap.
        for candidate in candidates.prefix(MeshRoutedStoreFormat.maxItems) {
            guard let record = index.record(for: candidate.key),
                  let target = record.deliveryTarget else { continue }
            guard let receipt = Self.eligibleReceipt(in: record, custodians: eligible) else {
                unplaced.append(candidate.key)
                continue
            }
            let legs = Self.legs(of: target, in: roster, minus: receipt.custodianFingerprint)
            guard !legs.isEmpty else { continue }
            chosen.append(
                MeshRoutedCustodyHandoff(
                    item: candidate.key, destinations: legs, receipt: receipt
                )
            )
        }
        transfers = chosen
        unplacedItemKeys = unplaced
    }

    /// The claims a CUSTODIAN may write on its own durable evidence.
    ///
    /// Three facts, all checkable offline and after a restart: the item was originated by a member
    /// whose signed departure record names this device a custodian (`leavers`), this device
    /// **admitted that item's manifest from the origin itself** (`originServed` — the hop bound),
    /// and the item is live and complete here. The result is idempotent: after one application no
    /// leg is `pending`, so a re-run plans nothing.
    ///
    /// - Parameters:
    ///   - index: This device's routed index.
    ///   - leavers: Origins whose departure record names this device, already filtered of removed
    ///     members by the caller — a derived roster cannot separate *departed* from *removed*, so
    ///     that gate cannot live in a pure function over the roster.
    ///   - originServed: The items whose manifest arrived from their own origin.
    ///   - roster: The **merged** derived roster.
    ///   - selfFingerprint: This device, which is the custodian in every claim it plans.
    ///   - now: The injected instant.
    /// - Returns: one claim per item whose legs can still move, in index order.
    static func claims(
        in index: MeshRoutedIndex,
        from leavers: Set<String>,
        originServed: Set<MeshRoutedItemKey>,
        roster: MeshDerivedRoster,
        selfFingerprint: String,
        at now: Date
    ) -> [MeshRoutedHandoffClaim] {
        var planned: [MeshRoutedHandoffClaim] = []
        // R2: bounded by the store's own item cap.
        for record in index.items.prefix(MeshRoutedStoreFormat.maxItems)
        where leavers.contains(record.key.originFingerprint) && originServed.contains(record.key) {
            guard record.isLive(at: now), record.isComplete,
                  let target = record.deliveryTarget else { continue }
            let legs = Self.legs(of: target, in: roster, minus: selfFingerprint)
            guard !legs.isEmpty else { continue }
            planned.append(
                MeshRoutedHandoffClaim(
                    item: record.key, destinations: legs, custodian: selfFingerprint
                )
            )
        }
        return planned
    }

    /// How many of a leaver's complete, live items this device holds **without** having taken their
    /// manifest from the origin — the hop bound's own residual, counted so it can be named.
    ///
    /// A device that restarts between taking the origin's bytes and claiming lands here: nothing is
    /// served and nothing is forged, which is the fail-closed direction.
    static func notOriginServedCount(
        in index: MeshRoutedIndex,
        from leavers: Set<String>,
        originServed: Set<MeshRoutedItemKey>,
        at now: Date
    ) -> Int {
        index.items.prefix(MeshRoutedStoreFormat.maxItems).filter { record in
            leavers.contains(record.key.originFingerprint)
                && !originServed.contains(record.key)
                && record.isLive(at: now) && record.isComplete
        }.count
    }

    /// The bounded batch the departure push may put on the wire for one custodian.
    ///
    /// Built through the drain's own **narrowing** initializer, never the memberwise one: every
    /// bound — `maxItems`, `maxChunksPerAnswer`, `maxReceipts`, `maxFrames` and the per-peer session
    /// allowance — lives in that initializer, and the gap computation against the custodian's last
    /// advertised inventory comes free with it. A custodian that has never advertised is compared
    /// against an empty inventory for this mesh, which is never signed and never sent: it exists
    /// only so "the custodian lacks everything" is expressible.
    ///
    /// - Returns: the batch, or nil when the two inventories name different meshes.
    static func pushBatch(
        local: MeshRoutedInventory,
        remote: MeshRoutedInventory,
        offerable: Set<MeshRoutedItemKey>,
        refused: Set<MeshRoutedItemKey>,
        frameAllowance: Int
    ) -> MeshRoutedDrainPlan? {
        guard let delta = MeshRoutedInventoryDelta.between(
            local: local, remote: remote, offerableToPeer: offerable
        ) else { return nil }
        return MeshRoutedDrainPlan(
            delta: delta, refused: refused, bounds: MeshRoutedDrainBounds.increment1,
            frameAllowance: frameAllowance
        )
    }

    /// The stored custody receipt of the lexicographically least eligible custodian, or nil when no
    /// reachable custodian has durably taken this item's bytes.
    private static func eligibleReceipt(
        in record: MeshRoutedItemRecord, custodians: Set<String>
    ) -> MeshCustodyReceipt? {
        // R2: bounded by `MeshRoutedStoreFormat.maxReceiptsPerItem`.
        record.receipts
            .filter { custodians.contains($0.custodianFingerprint) }
            .min { $0.custodianFingerprint < $1.custodianFingerprint }
    }

    /// The legs one custodian may take: outstanding against the merged roster, still `pending`, and
    /// never the custodian's own.
    private static func legs(
        of target: MeshDeliveryTarget, in roster: MeshDerivedRoster, minus custodian: String
    ) -> [String] {
        // R2: bounded by the destination cap.
        target.outstanding(in: roster).filter {
            $0 != custodian && target.state(of: $0) == .pending
        }
    }
}
