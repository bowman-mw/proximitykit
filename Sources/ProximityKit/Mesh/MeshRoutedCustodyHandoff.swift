// MeshRoutedCustodyHandoff.swift
// ProximityKit/Mesh
//
// Network migration P5 item 8 (plan §10.6, §11): the two BATCH custody doors a development needs —
// one at the departing origin, one at the custodian.
//
// Both are one `indexForWriting()`, N bounded record updates and **one** `save`. That shape is the
// whole reason they exist: `recordingCustodyTransfer(item:for:receipt:now:)` is one sealed load
// plus one sealed save per call, so looping it over a full index inside a fifteen-second window
// would be two thousand crypto passes on the main actor — a `.windowExpired` generator and a frozen
// UI. The single-item door is untouched and still pinned; these two apply **its** rules, through
// **its** helpers, so the rule has exactly one implementation.
//
// Neither door re-signs anything. A custodian is a courier, not a co-signer: the origin's manifest,
// chunks and receipts are forwarded verbatim, and the only thing a hand-off moves is a rung in a
// device's own index.
//
// The doors are **identity-free**, like every other store verb: the custodian is a parameter, never
// `identity.localFingerprint` read inside the store. `MeshRoutedCustodyHandoffWallTests` walls the
// single manager call site that supplies it.

import Foundation

// MARK: - MeshRoutedCustodyHandoff

/// One item's transfer at a development: the item, the legs the custodian is taking on, and the
/// custodian's own signed statement that it holds the ciphertext.
///
/// The custodian is not a separate field — it **is** `receipt.custodianFingerprint`, so the durable
/// state and the signature cannot disagree. Which destinations that custodian is now the courier
/// for is the caller's statement, not the receipt's; a receipt carries no destination set on purpose.
nonisolated struct MeshRoutedCustodyHandoff: Equatable, Sendable {

    /// The signed pair.
    let item: MeshRoutedItemKey

    /// The destinations this custodian is taking on. Every one must be in the item's signed
    /// manifest, and none of them may be the custodian itself.
    let destinations: [String]

    /// The custodian's verified custody receipt, already stored on this device as evidence.
    let receipt: MeshCustodyReceipt

    /// Builds one transfer.
    init(item: MeshRoutedItemKey, destinations: [String], receipt: MeshCustodyReceipt) {
        self.item = item
        self.destinations = destinations
        self.receipt = receipt
    }
}

// MARK: - MeshRoutedHandoffClaim

/// One item's claim at a CUSTODIAN: the legs this device takes over for a departed origin.
///
/// Receipt-free by construction. This device's own custody is `custodiedAt` and its receipt is
/// re-minted from the durable bytes on demand — ``MeshRoutedItemRecord/receipts`` holds *other*
/// members' receipts only, so storing a self-receipt would break that invariant and burn a
/// `maxReceiptsPerItem` slot for nothing.
nonisolated struct MeshRoutedHandoffClaim: Equatable, Sendable {

    /// The signed pair.
    let item: MeshRoutedItemKey

    /// The legs being claimed. Every one must be in the item's signed manifest.
    let destinations: [String]

    /// The device taking custody. A parameter, never read from an identity inside the store.
    let custodian: String

    /// Builds one claim.
    init(item: MeshRoutedItemKey, destinations: [String], custodian: String) {
        self.item = item
        self.destinations = destinations
        self.custodian = custodian
    }
}

// MARK: - MeshRoutedHandoffRefusalReason

/// Why one item inside a batch was refused: the **store door's** own vocabulary, or the **delivery
/// ladder's**.
///
/// Two enums, one list. A batch door applies the store's preconditions and then advances a delivery
/// map, and the two refuse in different vocabularies —
/// ``MeshRoutedStoreRefusal`` has no spelling for `alreadyDelivered` or `wouldRegress`, and inventing
/// one would give a single fact two names. Wrapping them keeps every refusal reportable **and**
/// keeps the name the door that raised it gave it, which is what "never silent" (R7) asks for.
nonisolated enum MeshRoutedHandoffRefusalReason: Equatable, Sendable {

    /// The routed store refused the request itself — an unknown item, a mismatched manifest, an
    /// expired item, a receipt that does not bind.
    case store(MeshRoutedStoreRefusal)

    /// The delivery ladder refused one named leg, so ``MeshRoutedStore/advancingAll(_:to:in:)``
    /// applied **nothing** for this item: refuse-batch is the contract, and the whole item is
    /// skipped rather than half-applied.
    case delivery(MeshDeliveryRefusal)

    /// The frozen English spelling, logged verbatim. Never display copy.
    var token: String {
        switch self {
        case .store(let refusal): return refusal.rawValue
        case .delivery(let refusal): return refusal.rawValue
        }
    }
}

// MARK: - MeshRoutedHandoffRefusal

/// One item's named refusal inside a batch — the pair a report carries so a refusal on item X never
/// says anything about item Y.
nonisolated struct MeshRoutedHandoffRefusal: Equatable, Sendable {

    /// The item the door refused.
    let item: MeshRoutedItemKey

    /// Why, by name — in whichever of the two vocabularies raised it.
    let refusal: MeshRoutedHandoffRefusalReason

    /// Builds one refusal.
    init(item: MeshRoutedItemKey, refusal: MeshRoutedHandoffRefusalReason) {
        self.item = item
        self.refusal = refusal
    }
}

// MARK: - MeshRoutedHandoffStep

/// What one item's pass through a batch door did.
///
/// Deliberately **not** a `String`-raw enum: `refusedDelivery` carries the ladder's own refusal, and
/// a raw value would have to flatten it back into a single token at the one place the distinction is
/// still available. The report is where these become lists; the tokens live on
/// ``MeshRoutedHandoffRefusalReason/token``.
nonisolated enum MeshRoutedHandoffStep: Equatable, Sendable {

    /// A rung moved and the record was updated.
    case advanced

    /// Nothing to do: every named leg was already **exactly** where the door would have put it.
    /// Reserved for a genuine no-op — a refusal is never reported this way.
    case unchanged

    /// The item is not complete yet, so no rung may be written for it. **Not a refusal** — it is a
    /// "not yet", retried when the item completes, and it has no
    /// ``MeshRoutedStoreRefusal`` spelling to be reported as.
    case incomplete

    /// The delivery ladder refused a named leg, so nothing was applied for this item.
    case refusedDelivery(MeshDeliveryRefusal)
}

// MARK: - MeshRoutedHandoffReport

/// What one batch door did, item by item.
///
/// Three lists, because three things can happen to an item and collapsing any two loses the
/// distinction a caller needs: ``advanced`` is the only one ``MeshCustodyHandoffSummary`` may count,
/// ``refused`` is caller-bug vocabulary — in either the store's or the delivery ladder's spelling —
/// that the shipping planner's pending-only leg list makes unreachable at the transfer door, and
/// ``incomplete`` is a "not yet" with no refusal token to wear.
nonisolated struct MeshRoutedHandoffReport: Equatable, Sendable {

    /// The items whose rung moved. `advanced.count` is what a departure record signs.
    let advanced: [MeshRoutedItemKey]

    /// The items the door refused, by name. A refusal skips **that** item; the batch continues.
    let refused: [MeshRoutedHandoffRefusal]

    /// The items that are not complete yet — claim door only.
    let incomplete: [MeshRoutedItemKey]

    /// Builds a report.
    init(
        advanced: [MeshRoutedItemKey],
        refused: [MeshRoutedHandoffRefusal],
        incomplete: [MeshRoutedItemKey]
    ) {
        self.advanced = advanced
        self.refused = refused
        self.incomplete = incomplete
    }
}

// MARK: - The batch doors

nonisolated extension MeshRoutedStore {

    /// Records, in ONE index write, that each transfer's custodian is now holding that item's
    /// ciphertext for the named destinations — the departing origin's half of plan §10.6.
    ///
    /// Applies ``recordingCustodyTransfer(item:for:receipt:now:)``'s preconditions in the same
    /// order and through the same helpers: record exists → manifest non-nil → the receipt's four
    /// identity equalities, the destination-set clause and the evidence cap → the delivery map
    /// restores → every named leg advances → the receipt is stored as the evidence.
    ///
    /// - Important: every `receipt` must be one `MeshCustodyReceiptVerifier.verify(_:)` has already
    ///   accepted. In practice each one came off this device's own index, where it was stored by
    ///   the drain's verified ingest.
    ///
    /// Durable-before-acknowledged holds for the whole batch at once: the save is one call, so a
    /// throw means **nothing** was written and the reported count is zero. A per-item refusal skips
    /// that item and does not abort the batch — nothing about item X's receipt says anything about
    /// item Y.
    ///
    /// - Parameters:
    ///   - transfers: The chosen transfers, at most ``MeshRoutedStoreFormat/maxItems``.
    ///   - now: The injected instant.
    /// - Returns: the per-item report, or the store's unavailability. **Nothing is written on any
    ///   unavailability.**
    func recordingCustodyHandoff(
        _ transfers: [MeshRoutedCustodyHandoff], now: Date
    ) -> MeshRoutedOutcome<MeshRoutedHandoffReport> {
        var index: MeshRoutedIndex
        let token: LoadToken
        switch indexForWriting() {
        case .unavailable(let cause): return .unavailable(cause)
        case .writable(let loaded, let vended): index = loaded; token = vended
        }
        var advanced: [MeshRoutedItemKey] = []
        var refused: [MeshRoutedHandoffRefusal] = []
        // R2: bounded by the store's own item cap.
        for transfer in transfers.prefix(MeshRoutedStoreFormat.maxItems) {
            switch applyingHandoff(transfer, in: &index) {
            case .completed(.advanced): advanced.append(transfer.item)
            case .completed(.refusedDelivery(let refusal)):
                refused.append(
                    MeshRoutedHandoffRefusal(item: transfer.item, refusal: .delivery(refusal))
                )
            case .completed: continue
            case .refused(let refusal):
                refused.append(
                    MeshRoutedHandoffRefusal(item: transfer.item, refusal: .store(refusal))
                )
            case .unavailable(let cause): return .unavailable(cause)
            }
        }
        let report = MeshRoutedHandoffReport(advanced: advanced, refused: refused, incomplete: [])
        guard !advanced.isEmpty else { return .completed(report) }
        do {
            try save(index, token: token)
        } catch {
            return .unavailable(unavailability(from: error))
        }
        return .completed(report)
    }

    /// Records, in ONE index write, that THIS device is now the courier for the named legs of items
    /// a departed origin handed it — the custodian's half of plan §10.6.
    ///
    /// The gate is ``MeshRoutedItemRecord/isComplete``, never `custodiedAt != nil`: `custodiedAt` is
    /// written by `committingCustody`, which `commitLocalCustody` gates on this very rung, so
    /// gating the rung on it closes a circle in which a pure courier could never claim. Completeness
    /// is the same durable fact — every chunk file staged and hash-checked — so the rung is a
    /// statement about ciphertext already on disk, and the rung alone acknowledges nothing to anybody.
    ///
    /// **Stores no receipt.** See ``MeshRoutedHandoffClaim``.
    ///
    /// - Parameters:
    ///   - claims: The planned claims, at most ``MeshRoutedStoreFormat/maxItems``.
    ///   - now: The injected instant; expired items are refused rather than claimed.
    /// - Returns: the per-item report, or the store's unavailability. **Nothing is written on any
    ///   unavailability.**
    func claimingHandedOffLegs(
        _ claims: [MeshRoutedHandoffClaim], now: Date
    ) -> MeshRoutedOutcome<MeshRoutedHandoffReport> {
        var index: MeshRoutedIndex
        let token: LoadToken
        switch indexForWriting() {
        case .unavailable(let cause): return .unavailable(cause)
        case .writable(let loaded, let vended): index = loaded; token = vended
        }
        var advanced: [MeshRoutedItemKey] = []
        var refused: [MeshRoutedHandoffRefusal] = []
        var incomplete: [MeshRoutedItemKey] = []
        // R2: bounded by the store's own item cap.
        for claim in claims.prefix(MeshRoutedStoreFormat.maxItems) {
            switch applyingClaim(claim, in: &index, now: now) {
            case .completed(.advanced): advanced.append(claim.item)
            case .completed(.incomplete): incomplete.append(claim.item)
            case .completed(.refusedDelivery(let refusal)):
                refused.append(
                    MeshRoutedHandoffRefusal(item: claim.item, refusal: .delivery(refusal))
                )
            case .completed: continue
            case .refused(let refusal):
                refused.append(
                    MeshRoutedHandoffRefusal(item: claim.item, refusal: .store(refusal))
                )
            case .unavailable(let cause): return .unavailable(cause)
            }
        }
        let report = MeshRoutedHandoffReport(
            advanced: advanced, refused: refused, incomplete: incomplete
        )
        guard !advanced.isEmpty else { return .completed(report) }
        do {
            try save(index, token: token)
        } catch {
            return .unavailable(unavailability(from: error))
        }
        return .completed(report)
    }

    /// One transfer applied to the in-memory index, or its named answer. Writes no file.
    private func applyingHandoff(
        _ transfer: MeshRoutedCustodyHandoff, in index: inout MeshRoutedIndex
    ) -> MeshRoutedOutcome<MeshRoutedHandoffStep> {
        guard var record = index.record(for: transfer.item) else { return .refused(.unknownItem) }
        guard let manifest = record.manifest else { return .refused(.manifestMismatch) }
        if let refusal = receiptRefusal(
            transfer.receipt, against: record, manifest: manifest,
            destinations: transfer.destinations
        ) {
            return .refused(refusal)
        }
        guard let target = record.deliveryTarget else {
            return .unavailable(
                .corrupt(MeshRoutedCorruption(detail: .undecodableJSON("deliveryRestore")))
            )
        }
        // Two different answers, kept apart. A delivery-level refusal applied NOTHING and keeps its
        // own name (the single-item door does the same by returning its outcome intact); collapsing
        // it into "nothing to do" would make a caller bug indistinguishable from a no-op and leave
        // it out of every audit line, which is exactly what R7 forbids.
        switch advancingAll(
            transfer.destinations, to: transfer.receipt.custodianFingerprint, in: target
        ) {
        case .refused(let refusal):
            return .completed(.refusedDelivery(refusal))
        case .updated(let updated):
            // `advancing` treats re-applying a destination's CURRENT state as a success that changes
            // nothing, which is what makes a redelivered receipt idempotent. Here that would be a
            // lie: `advanced.count` is signed into a record nobody can retract, so a batch that
            // moved no rung must not report one. The planner already restricts the legs to
            // `pending`; this makes "the door advanced it" and "the rung moved" the same statement
            // for every caller.
            guard updated != target else { return .completed(.unchanged) }
            record.delivery = MeshRoutedDeliveryRecord(encoding: updated)
            record.receipts = Self.storing(transfer.receipt, in: record.receipts)
            index.upsert(record)
            return .completed(.advanced)
        }
    }

    /// One claim applied to the in-memory index, or its named answer. Writes no file.
    private func applyingClaim(
        _ claim: MeshRoutedHandoffClaim, in index: inout MeshRoutedIndex, now: Date
    ) -> MeshRoutedOutcome<MeshRoutedHandoffStep> {
        guard var record = index.record(for: claim.item) else { return .refused(.unknownItem) }
        guard let manifest = record.manifest else { return .refused(.manifestMismatch) }
        guard record.isLive(at: now) else { return .refused(.itemExpired) }
        guard record.isComplete else { return .completed(.incomplete) }
        let named = Set(manifest.destinations)
        guard !claim.destinations.isEmpty,
              claim.destinations.allSatisfy({ named.contains($0) }) else {
            return .refused(.notADestination)
        }
        guard let target = record.deliveryTarget else {
            return .unavailable(
                .corrupt(MeshRoutedCorruption(detail: .undecodableJSON("deliveryRestore")))
            )
        }
        // See ``applyingHandoff(_:in:)``: a delivery-level refusal keeps its own name, and
        // re-applying a leg's current state moves nothing — a claim that moved nothing must say so,
        // which is what makes the derivation idempotent rather than merely repeatable.
        switch advancingAll(claim.destinations, to: claim.custodian, in: target) {
        case .refused(let refusal):
            return .completed(.refusedDelivery(refusal))
        case .updated(let updated):
            guard updated != target else { return .completed(.unchanged) }
            record.delivery = MeshRoutedDeliveryRecord(encoding: updated)
            index.upsert(record)
            return .completed(.advanced)
        }
    }
}
