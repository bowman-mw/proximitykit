// MeshRoutedDrainPlan.swift
// ProximityKit/Mesh
//
// Network migration P5 item 6 (plan §11, §10.3, §22.1): the **pure** half of the drain — the bounded
// batch one routed-inventory exchange may put on the wire, and the per-peer state the manager keeps
// while it does.
//
// **This file re-decides no policy.** What may be offered is item 5's
// `MeshRoutedInventoryDelta` (whose entitlement input is the manager's `offerableKeys`); what may be
// admitted is items 1–4's verifiers and store doors. The plan only *narrows*: it removes the keys
// this peer already refused for a capacity reason, truncates to the bounds and to the session's
// remaining frame allowance, and keeps the delta's canonical order. Two runs on the same inputs are
// `==`, so item 14 can drive it with no manager at all.
//
// The one number worth reading the reasoning for is ``MeshRoutedDrainBounds/maxChunksPerAnswer``:
// re-using `MeshChunkFormat.maxChunksInFlightPerPeer` (3) as a per-answer TOTAL is what would make
// every item over 768 KiB — i.e. every photo — permanently undeliverable inside one session.

import Foundation

// MARK: - MeshRoutedPeerInventory

/// What one peer last told this device its ROUTED store holds, plus **both** halves of the
/// quiescence predicate item 7 closes its window on.
///
/// Never `MeshInventoryDigest` (P4's membership summary) — the two are structurally different values
/// under one English word. Session-scoped and in memory only: nothing here is persisted, so there is
/// no wipe row and no schema (D-6.14).
///
/// Both quiescence halves are recorded in the **same pass** that mints the answer (D-6.18), because
/// `MeshRoutedInventoryDelta.converged(local:peerReportsQuiescent:)` needs both and re-deriving the
/// local half later would mean a second `load()` + `Delta.between` on the main actor.
nonisolated struct MeshRoutedPeerInventory: Equatable, Sendable {
    /// The peer's last verified holdings, or nil until it has advertised.
    var inventory: MeshRoutedInventory?
    /// That advertisement's own signed `sentAt`.
    var inventorySentAt: Date?
    /// The **minted payload's own floored `sentAt`** from the last inventory this device sent this
    /// peer — never a `now` (D-6.10). Written after the mint, and it is what an inbound answer's
    /// `advertisedAt` must equal to be recorded at all.
    var advertisedAt: Date?
    /// What the peer answered about **its** delta against this device's advertisement.
    var reportsQuiescent: Bool
    /// Which advertisement that bit answers — equal to ``advertisedAt`` when it was recorded.
    var quiescentAsOf: Date?
    /// **This** device's own `isQuiescent` against the peer's last advertisement (D-6.18).
    var localQuiescent: Bool
    /// The peer advertisement instant the local bit was computed against.
    var quiescentLocalAsOf: Date?

    /// An empty record for a peer that has not advertised yet. Neither side is quiescent until a
    /// comparison has actually happened — the fail-closed direction for item 7's window.
    init(
        inventory: MeshRoutedInventory? = nil,
        inventorySentAt: Date? = nil,
        advertisedAt: Date? = nil,
        reportsQuiescent: Bool = false,
        quiescentAsOf: Date? = nil,
        localQuiescent: Bool = false,
        quiescentLocalAsOf: Date? = nil
    ) {
        self.inventory = inventory
        self.inventorySentAt = inventorySentAt
        self.advertisedAt = advertisedAt
        self.reportsQuiescent = reportsQuiescent
        self.quiescentAsOf = quiescentAsOf
        self.localQuiescent = localQuiescent
        self.quiescentLocalAsOf = quiescentLocalAsOf
    }
}

// MARK: - MeshRoutedDrainRefusalNote

/// The last capacity refusal the drain took, kept so item 9 has a seam to surface it from.
///
/// Frozen English reason (a `MeshRoutedStoreRefusal.rawValue`), never display text: plan §18.2's
/// copy is the owner's and item 6 ships none.
nonisolated struct MeshRoutedDrainRefusalNote: Equatable, Sendable {
    /// The peer whose frame was refused.
    let peerFingerprint: String
    /// The store refusal's frozen token.
    let reason: String
    /// When it happened, on the injected clock.
    let at: Date

    /// Records one refusal.
    init(peerFingerprint: String, reason: String, at: Date) {
        self.peerFingerprint = peerFingerprint
        self.reason = reason
        self.at = at
    }
}

// MARK: - MeshRoutedDrainBounds

/// Everything one drain answer, and one peer's whole session, may spend.
///
/// Every field is a cap, none is a target, and the two session-level derivations state their
/// arithmetic rather than picking a number (plan §3 invariant 4: bounded everything, explicitly).
nonisolated struct MeshRoutedDrainBounds: Equatable, Sendable {
    /// Most manifests one answer may offer — the membership family's per-kind cap, reused.
    let maxItems: Int

    /// One ANSWER's whole chunk allowance: **64 chunks = 16 MiB**, this family's OWN constant.
    ///
    /// Deliberately **not** `MeshChunkFormat.maxChunksInFlightPerPeer` (3): that is an *in-flight*
    /// courtesy bound whose own documentation says it is not a throughput target, and re-using it as
    /// a per-answer TOTAL is what makes every item over 768 KiB — every photo — undeliverable, since
    /// there is no second batch inside a session under a one-shot. 64 completes every item this
    /// phase actually ships (a heart is one chunk) in a single answer. Pacing on a real radio stays
    /// tier 2's measurement, and this is the number tier 2 should re-measure.
    let maxChunksPerAnswer: Int

    /// Most receipts one answer may forward — the same per-kind cap.
    let maxReceipts: Int

    /// No per-item cap below the answer's own allowance: one large item may spend all of it. A
    /// smaller per-item cap would starve exactly the item this bound exists to move, and the delta's
    /// canonical order already keeps the choice deterministic.
    var maxChunksPerItem: Int { maxChunksPerAnswer }

    /// Most frames one answer may enqueue, bulk only — the drain answer itself is never charged.
    var maxFrames: Int { maxItems + maxChunksPerAnswer + maxReceipts }

    /// Builds one bounds value. Callers use ``increment1``; the memberwise door exists so the
    /// property battery can drive a deliberately tiny budget.
    init(maxItems: Int, maxChunksPerAnswer: Int, maxReceipts: Int) {
        self.maxItems = maxItems
        self.maxChunksPerAnswer = maxChunksPerAnswer
        self.maxReceipts = maxReceipts
    }

    /// Increment 1's shipping bounds.
    static let increment1 = MeshRoutedDrainBounds(
        maxItems: MeshMembershipBounds.maxRecordsPerKind,
        maxChunksPerAnswer: 64,
        maxReceipts: MeshMembershipBounds.maxRecordsPerKind
    )

    /// The bulk frames one peer may make this device serve in one SESSION (6 h,
    /// `MeshSessionCeiling.ceilingSeconds`) — the bound that replaced a once-per-peer boolean.
    ///
    /// Derived, not a literal: `MeshChunkFormat.maxChunkCount + 2 *
    /// MeshMembershipBounds.maxRecordsPerKind` = 1024 + 32, i.e. **exactly one maximal (256 MiB)
    /// item plus its manifests and receipts**. A session budget that cannot complete the chunk
    /// format's own maximal item would be a starvation bug wearing a bound's name. It still bounds
    /// abuse: a peer re-sending inventories cannot spend more than this whatever it does.
    static let sessionFramesPerPeer =
        MeshChunkFormat.maxChunkCount + 2 * MeshMembershipBounds.maxRecordsPerKind
}

// MARK: - MeshRoutedDrainChunkSend

/// One item's chunk sends inside a plan: the item, and the **already-truncated** slot indices.
///
/// Truncation happens in the plan, not at the sender, so "what will be sent" is a value two runs can
/// compare rather than a loop's side effect.
nonisolated struct MeshRoutedDrainChunkSend: Equatable, Sendable {
    /// The item — the signed pair.
    let key: MeshRoutedItemKey
    /// The slots to send, ascending, already inside every bound.
    let indices: [UInt32]

    /// Builds one item's chunk sends.
    init(key: MeshRoutedItemKey, indices: [UInt32]) {
        self.key = key
        self.indices = indices
    }
}

// MARK: - MeshRoutedDrainPlan

/// The bounded batch one exchange with one peer may put on the wire.
///
/// Pure and deterministic: no clock, no I/O, no randomness. The lists keep
/// ``MeshRoutedInventoryDelta``'s canonical order, so a truncated plan is always the delta's
/// **prefix** and the remainder is what the next exchange with that peer starts from.
///
/// ``requests`` is diagnostic only. The drain is **push-only** (D-6.4): both sides compute symmetric
/// deltas from the exchanged inventories, so there is no "send me X" frame to pace and nothing reads
/// this list but a log line and a test.
nonisolated struct MeshRoutedDrainPlan: Equatable, Sendable {
    /// Manifests to offer, in canonical order.
    let manifests: [MeshRoutedItemKey]
    /// Chunk sends, in canonical order, each already truncated.
    let chunks: [MeshRoutedDrainChunkSend]
    /// Receipts to forward, in canonical order.
    let receipts: [MeshRoutedInventoryReceiptRef]
    /// What this device still needs — **diagnostic only** under push-only.
    let requests: [MeshRoutedItemKey]
    /// Whether any bound or the session allowance dropped work this exchange would otherwise have
    /// done. The remainder is owed, never lost: nothing grows silently, and nothing vanishes either.
    let truncated: Bool

    /// How many BULK frames this plan enqueues — manifests + chunk slots + receipts. The drain
    /// answer is not among them and is never charged against the session budget.
    var frameCount: Int {
        manifests.count + chunks.reduce(0) { $0 + $1.indices.count } + receipts.count
    }

    /// Whether this plan would put nothing on the wire. An empty plan charges nothing.
    var isEmpty: Bool { frameCount == 0 }

    /// Builds a plan from already-computed lists. The narrowing initializer below is the only
    /// production caller.
    init(
        manifests: [MeshRoutedItemKey],
        chunks: [MeshRoutedDrainChunkSend],
        receipts: [MeshRoutedInventoryReceiptRef],
        requests: [MeshRoutedItemKey],
        truncated: Bool
    ) {
        self.manifests = manifests
        self.chunks = chunks
        self.receipts = receipts
        self.requests = requests
        self.truncated = truncated
    }

    /// Narrows one delta into the batch this exchange may actually send.
    ///
    /// Order of spending is the order of sending — manifests, then chunks, then receipts — so a
    /// truncated answer un-parks the peer's sets before it feeds them, and a chunk never arrives for
    /// a manifest this answer could have carried but dropped.
    ///
    /// - Parameters:
    ///   - delta: Item 5's comparison. Its entitlement was already applied by the caller.
    ///   - refused: The keys this answer withholds, from **two** sources the caller unions: keys this
    ///     peer refused for a capacity reason this session (item 9), and keys whose stored manifest
    ///     names a routed type this build does not register (item 11). Removed from **both**
    ///     directions, so a refusal does not re-fire, a refused ask is not re-logged, and an
    ///     unregistered item's receipts are not forwarded nor its completion asked for.
    ///   - bounds: The per-answer caps.
    ///   - frameAllowance: `min(bounds.maxFrames, sessionFramesPerPeer - spent)`. The session budget
    ///     **narrows** the answer rather than refusing it, so a nearly-spent peer still gets whatever
    ///     is left and ``truncated`` says the remainder is owed.
    init(
        delta: MeshRoutedInventoryDelta,
        refused: Set<MeshRoutedItemKey>,
        bounds: MeshRoutedDrainBounds,
        frameAllowance: Int
    ) {
        let allowance = max(0, frameAllowance)
        let offeredManifests = delta.manifestsToOffer.filter { !refused.contains($0) }
        let manifests = Array(offeredManifests.prefix(min(bounds.maxItems, allowance)))
        let gaps = delta.chunksToOffer.filter { !refused.contains($0.key) }
        let chunkAllowance = min(bounds.maxChunksPerAnswer, allowance - manifests.count)
        let chunks = Self.chunkSends(from: gaps, bounds: bounds, allowance: chunkAllowance)
        let sentChunks = chunks.reduce(0) { $0 + $1.indices.count }
        let forwardable = delta.receiptsToForward.filter { !refused.contains($0.key) }
        let receiptAllowance = min(bounds.maxReceipts, allowance - manifests.count - sentChunks)
        let receipts = Array(forwardable.prefix(max(0, receiptAllowance)))
        self.init(
            manifests: manifests,
            chunks: chunks,
            receipts: receipts,
            requests: delta.ask.filter { !refused.contains($0) },
            truncated: manifests.count < offeredManifests.count
                || sentChunks < gaps.reduce(0) { $0 + $1.missingCount }
                || receipts.count < forwardable.count
        )
    }

    /// Expands each gap's bitmap into slot indices, spending `allowance` in canonical order and
    /// dropping an item entirely once nothing is left rather than emitting an empty send.
    private static func chunkSends(
        from gaps: [MeshRoutedChunkGap],
        bounds: MeshRoutedDrainBounds,
        allowance: Int
    ) -> [MeshRoutedDrainChunkSend] {
        var remaining = max(0, allowance)
        var sends: [MeshRoutedDrainChunkSend] = []
        // R2: bounded by `MeshRoutedInventoryFormat.maxEntries`.
        for gap in gaps where remaining > 0 {
            let indices = gap.missingIndices().prefix(min(bounds.maxChunksPerItem, remaining))
            guard !indices.isEmpty else { continue }
            sends.append(MeshRoutedDrainChunkSend(key: gap.key, indices: Array(indices)))
            remaining -= indices.count
        }
        return sends
    }
}
