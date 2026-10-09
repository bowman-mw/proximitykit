// MeshHeartCommit.swift
// ProximityKit/Mesh
//
// P4 item 7, second half (plan §10.3): the heart receipt's commit through the ledger, which ran beside
// the merge's other two rules in `MeshContentIngest.swift` until plan step A0.5.9 moved that file to
// FernletSocial with chat. The commit names only ``MeshMergedHeart`` and ``ProximityHeartLedger``, and
// the engine's heart judgement calls it, so it is parked here, in ProximityKit, for one commit: plan
// step A0.5.10 moves it to FernletSocial's heart sharing with the ledger, the merged heart and the
// judgement. Moved verbatim, but for one doc line that named FernletSocial's ledger as a link.
//
// §10.3 keeps the final receipt at the foreground decrypt + ledger commit, so the union produces
// *pending* hearts and the existing ``ProximityHeartLedger`` — its id-dedup and its 5-minute
// per-sender cooldown, not a second copy of them — arbitrates. A duplicate that crossed the split is
// collapsed by the union *before* the ledger sees it, so the cooldown is judged once, not twice.

import Foundation

// MARK: - MeshHeartCommit

/// What the local heart ledger made of a merged batch of hearts.
///
/// `judgements` is the load-bearing field: it is the number of times the ledger was *asked*, which
/// is one per distinct gift id. A duplicate that crossed the split is collapsed by the union before
/// this runs, so the 5-minute cooldown is judged once rather than twice.
nonisolated struct MeshHeartCommitOutcome: Equatable, Sendable {

    /// Gift ids the ledger committed a receipt for, in the order they were offered.
    let receivedGiftIDs: [UUID]
    /// Gift ids the ledger refused — already recorded, inside the cooldown, or the ledger is
    /// unloaded and failing closed.
    let refusedGiftIDs: [UUID]
    /// How many times the ledger was asked to judge.
    let judgements: Int

    /// Builds an outcome.
    init(receivedGiftIDs: [UUID], refusedGiftIDs: [UUID], judgements: Int) {
        self.receivedGiftIDs = receivedGiftIDs
        self.refusedGiftIDs = refusedGiftIDs
        self.judgements = judgements
    }

    /// The gift ids that became receipts, as the set FernletSocial's content ledger reads
    /// (`MeshContentLedger.heartReceipt(_:committed:)`).
    var committed: Set<UUID> { Set(receivedGiftIDs) }
}

/// Drives merged hearts through the **existing** ``ProximityHeartLedger`` — its id-dedup, its
/// 5-minute per-sender cooldown, its retention cap — rather than a second copy of those rules.
///
/// This is the "final receipt only at foreground decrypt + ledger commit" step of plan §10.3: the
/// merge hands over pending hearts, and what the ledger answers is the receipt.
enum MeshHeartCommit {

    /// Offers each merged heart to the ledger exactly once, oldest-first.
    static func commit(
        _ hearts: [MeshMergedHeart],
        into ledger: ProximityHeartLedger
    ) -> MeshHeartCommitOutcome {
        var received: [UUID] = []
        var refused: [UUID] = []
        for heart in hearts.prefix(MeshMergedHeart.setCapacity) {
            let accepted = ledger.recordReceivedHeart(
                id: heart.giftID,
                senderDisplayName: heart.senderDisplayName,
                senderFingerprint: heart.senderFingerprint
            )
            if accepted { received.append(heart.giftID) } else { refused.append(heart.giftID) }
        }
        return MeshHeartCommitOutcome(
            receivedGiftIDs: received,
            refusedGiftIDs: refused,
            judgements: received.count + refused.count
        )
    }
}
