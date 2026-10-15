// MeshMergeOffer.swift
// ProximityKit/Mesh
//
// P4 item 2 (plan §10.3): **any reconnect is a merge, and there is only one path.**
//
// A blip, a healed partition, an idle-lapse resume and a process restart are the same event wearing
// four names, so they are given one vocabulary here and one front door on the manager
// (`MeshNetworkManager.mergeReconnected(_:entry:)`, which is a thin wrapper over the single
// `mergeMembershipLedger(_:)`). Nothing in this file reaches a transport, a clock or a keychain:
// what a reconnect *offers* is a value, and the manager decides what to do with it.
//
// **No wire type lives here, deliberately.** The offer is assembled locally from frames that
// already exist — `fernlet.mesh.inventory-digest.v1` asks, and the bounded record re-gossip
// answers with the same record frames a live record arrives in (plan §10.5). Making the offer
// `Codable` would be the first step to a second wire shape for records that already have one, and
// the epoch-head half of §10.3's exchange is deliberately still local: two divergent heads cannot
// even open a tunnel today (`MeshEpochAcceptance.introductionVerdict` answers `divergent`), which
// is P4 item 3's problem and not something a new frame here would fix.
//
// Ordering, dedup and the union laws are all inherited rather than re-implemented:
// `MeshMembershipLedger.merging(_:)` is commutative, associative and idempotent including at its
// caps (P3 item 1), and `MeshEpochAcceptance.mergedHeads(_:adding:)` is the head fold. The one
// thing added is that an overflow past the head cap is **named** rather than silently truncated
// (plan §21.3: the cap is an assertion P4 tests, not a knob).

import Foundation

// MARK: - MeshMergeEntry

/// Which reconnect ran the merge (plan §10.3's four entries).
///
/// The point of the enum is that there is nothing behind it: every case reaches the *same* merge,
/// and the value exists so a log line and a test can say **which door** was used without there
/// being a second path behind any of them.
///
/// Frozen English tokens — logged verbatim and compared as `rawValue`s, never display copy.
nonisolated enum MeshMergeEntry: String, Equatable, Sendable, CaseIterable {

    /// A committed peer dropped and came back while this device still held other links, so the
    /// session never left ``MeshSessionState/activeForeground``. Also the *partial* heal: a peer
    /// reappearing on a branch that is still short of somebody enters here.
    case blip

    /// Every roster member is reachable again — ``MeshPartitionVerdict/linksRestored``.
    case partitionHeal

    /// The 30-minute idle window lapsed and the user resumed from the foreground
    /// (``MeshSessionEvent/resumedAfterLapse``).
    case idleLapseResume

    /// The process died and the sealed context was restored, so the ledger this device merges *from*
    /// came off the disk rather than out of a live session.
    case processRestart
}

// MARK: - MeshEpochHeadFold

/// The result of folding epoch heads together: the heads that survived, and how many did not.
///
/// ``droppedCount`` is a **defect signal, not a budget**. Plan §21.3 fixes the head cap at 8 and
/// says a nested re-split cannot exceed everyone-alone, so a fold that overflows means the merge
/// produced heads no partition shape can justify. Naming it here is what turns
/// ``MeshEpochAcceptance/mergedHeads(_:adding:limit:)``'s silent `prefix` into something a caller
/// can log and a suite can assert on.
nonisolated struct MeshEpochHeadFold: Equatable, Sendable {

    /// The folded heads, deduplicated and in ``MeshEpochRefOrder``, at most `limit` of them.
    let heads: [MeshEpochRef]

    /// How many distinct heads the cap pushed off the end. Non-zero is a bug in the merge.
    let droppedCount: Int
}

// MARK: - MeshMergeOffer

/// One side's half of plan §10.3's union exchange: the records it holds, and the epoch head(s) it
/// is on.
///
/// Both halves are needed for the *same* reason — a returning member may hold records this device
/// has never seen (a departure that happened in the other branch, §10.5) and an epoch this device
/// has never seen (its branch rotated independently, §8.4) — and neither half may overwrite
/// anything: records union, and heads coexist until a merge mints a strictly greater successor.
///
/// ## The laws it inherits
///
/// ``merging(_:)`` is commutative, associative and idempotent because both halves are:
/// `MeshMembershipLedger.merging(_:)` is (P3 item 1, keep-earliest-k under the records' own total
/// order, at the caps as well as below them) and the head fold is a deduplicating sort. Nothing
/// here derives termination or roster status — those are read off the derived roster, never applied
/// at merge.
///
/// ## Concurrency
///
/// A `Sendable` value of `Sendable` parts; callable from any isolation.
nonisolated struct MeshMergeOffer: Equatable, Sendable {

    /// The signed membership records the offering side holds. Untrusted: every record is verified
    /// again by ``MeshMembershipRecordVerifier`` on the way in.
    let ledger: MeshMembershipLedger

    /// The epoch branch head(s) the offering side is on. Empty is honest — a member that holds no
    /// group key names no epoch.
    let epochHeads: [MeshEpochRef]

    /// The offer that says nothing: no records, no heads. Merging it is a no-op, which is what
    /// makes it the identity the union laws want.
    static let empty = MeshMergeOffer(ledger: .empty, epochHeads: [])

    /// The most heads a fold will look at, whatever it was handed.
    ///
    /// Twice the persisted cap: a pairwise merge sees at most both sides' full head sets, and plan
    /// §9 bounds branches by the roster cap anyway. A hard constant, so the loop is bounded by
    /// something that cannot be grown by a peer (Power of 10 rule 2).
    static let maxFoldedHeads = MeshSessionContextSchema.maxEpochHeads * 2

    /// Builds an offer.
    ///
    /// - Parameters:
    ///   - ledger: The records held.
    ///   - epochHeads: The epoch head(s) held; defaults to none.
    init(ledger: MeshMembershipLedger, epochHeads: [MeshEpochRef] = []) {
        self.ledger = ledger
        self.epochHeads = epochHeads
    }

    /// Builds an offer carrying exactly one epoch head, or none.
    ///
    /// - Parameters:
    ///   - ledger: The records held.
    ///   - head: The single head the offering side named, if any.
    init(ledger: MeshMembershipLedger, head: MeshEpochRef?) {
        self.init(ledger: ledger, epochHeads: head.map { [$0] } ?? [])
    }

    /// Unions two offers.
    ///
    /// - Parameter other: The offer to fold in.
    /// - Returns: The union — records merged under the ledger's own laws, heads deduplicated and
    ///   capped. An overflow is not visible here; use ``foldedHeads(_:adding:limit:)`` when the
    ///   caller has to report one.
    func merging(_ other: MeshMergeOffer) -> MeshMergeOffer {
        MeshMergeOffer(
            ledger: ledger.merging(other.ledger),
            epochHeads: Self.foldedHeads(epochHeads, adding: other.epochHeads).heads
        )
    }

    /// Folds a set of heads into another, naming what the cap dropped instead of truncating in
    /// silence.
    ///
    /// One `mergedHeads` call per addition, so the ordering and the dedup are exactly the ones
    /// every other head write uses. The loop is bounded by ``maxFoldedHeads``, and the count that
    /// is reported as dropped is measured against the *deduplicated* union — a peer re-offering a
    /// head this device already holds can never look like an overflow.
    ///
    /// - Parameters:
    ///   - heads: The heads known so far.
    ///   - additions: The heads offered.
    ///   - limit: The cap; defaults to what ``MeshSessionContext`` persists.
    /// - Returns: The surviving heads and the overflow count.
    static func foldedHeads(
        _ heads: [MeshEpochRef],
        adding additions: [MeshEpochRef],
        limit: Int = MeshSessionContextSchema.maxEpochHeads
    ) -> MeshEpochHeadFold {
        var union = heads
        var distinct = heads
        for addition in additions.prefix(maxFoldedHeads) {
            union = MeshEpochAcceptance.mergedHeads(union, adding: addition, limit: limit)
            if !distinct.contains(addition) { distinct.append(addition) }
        }
        return MeshEpochHeadFold(heads: union, droppedCount: max(0, distinct.count - union.count))
    }
}
