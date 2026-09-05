// MeshContentIngest.swift
// ProximityKit/Mesh
//
// P4 item 7, second half (plan §10.3 + §21.3's decision): **what happens to merged content at the
// receiving member.** `MeshContentMerge.swift` owns the union; this file owns the three things that
// run around it.
//
//   1. **Hash validation at reassembly** (``MeshPhotoReassembly``). A manifest whose reassembled
//      bytes do not match its digest is *rejected at reassembly* — structurally, because the only
//      way into the photo set is a function that takes the bytes and returns the union unchanged
//      when they do not match. There is no path that keeps it silently.
//   2. **The gates, re-run at ingestion** (``MeshContentGates``). §21.3's decision, taken
//      deliberately: records union, but *content* does not get a free pass because another branch
//      approved it. The age gate and the local block/ban are re-applied at the **receiving** member,
//      as a **view filter over an unmutated union** — the item still merges, it simply does not
//      render where the gate refuses it. Same shape as termination-derived-at-read, and for the
//      same reason: a merge that mutated the record would break the union laws.
//   3. **The heart receipt** (``MeshHeartCommit``). §10.3 keeps the final receipt at the foreground
//      decrypt + ledger commit, so the union produces *pending* hearts and the existing
//      ``ProximityHeartLedger`` — its id-dedup and its 5-minute per-sender cooldown, not a second
//      copy of them — arbitrates. A duplicate that crossed the split is collapsed by the union
//      *before* the ledger sees it, so the cooldown is judged once, not twice.
//
// **The `keyEpoch` gates were never touched here, and P5 item 13 retired them where they lived
// (plan §21.5).** Two are gone with the path they gated — `key.epoch == photo.keyEpoch` with the
// group-key photo decrypt, and the `keyEpoch >= localJoinedEpoch` manifest filter with the pull
// protocol the routed drain replaced — because a routed item carries a per-recipient content-key
// wrap, so branch and epoch stop deciding decryptability. The third,
// `wrapper.keyEpoch == currentGroupKey?.epoch`, was KEPT: its two content arms retired, but its
// door survives with control arms that have no routed successor, and deleting the compare over
// those would be loosening a gate in place. Nothing was ever loosened, here or there — so
// ``MeshMergedPhoto`` still carries `keyEpoch` through the union untouched and this file still adds
// no epoch judgement of its own.

import Foundation
import CryptoKit

// MARK: - MeshPhotoReassembly

/// Hash validation for a photo reassembled out of a merge (plan §10.3, "hash-validated on
/// reassembly").
///
/// The digest is a **local** value — computed by whoever holds the bytes — not a wire field, so
/// nothing here moves a manifest golden or adds a payload. Integrity of a *transferred* photo is
/// still the AEAD tag's job; this is the reassembly check the union needs so a chunked photo that
/// arrives in pieces across a healed partition cannot enter the set half-formed.
nonisolated enum MeshPhotoReassembly {

    /// What reassembly decided about one photo's bytes.
    nonisolated enum Verdict: String, Equatable, Sendable {
        /// The bytes are non-empty and hash to the expected digest.
        case accepted
        /// Nothing was reassembled — an empty payload never occupies a set slot.
        case rejectedEmpty
        /// The bytes hash to something else: truncated, tampered, or a mis-keyed reassembly.
        case rejectedDigestMismatch
    }

    /// SHA-256 of `bytes` — the digest ``MeshMergedPhoto/contentDigest`` carries.
    static func digest(of bytes: Data) -> Data {
        Data(SHA256.hash(data: bytes))
    }

    /// Whether `reassembled` may become the photo `expecting` names.
    static func verdict(reassembled: Data, expecting expected: Data) -> Verdict {
        guard !reassembled.isEmpty else { return .rejectedEmpty }
        guard digest(of: reassembled) == expected else { return .rejectedDigestMismatch }
        return .accepted
    }

    /// The only way a reassembled photo enters a set: the union is returned **unchanged** unless the
    /// bytes validate, so "silently kept" is not a state this API can reach.
    ///
    /// - Returns: the set (grown only on `.accepted`) and the verdict, so a caller can report the
    ///   rejection rather than wonder where the photo went.
    static func admitting(
        _ photo: MeshMergedPhoto,
        reassembled: Data,
        into set: MeshContentSet<MeshMergedPhoto>
    ) -> (set: MeshContentSet<MeshMergedPhoto>, verdict: Verdict) {
        let verdict = verdict(reassembled: reassembled, expecting: photo.contentDigest)
        guard verdict == .accepted else { return (set, verdict) }
        return (set.inserting(photo), verdict)
    }
}

// MARK: - MeshContentGates

/// The ingestion gates one member re-runs over merged content (plan §10.3, §21.3's decision).
///
/// A value rather than a pair of closures so the filter stays pure and comparable: the live
/// predicates are folded into it once, at the call site, from the seams that already enforce them —
/// `MeshNetworkManager.isChatAllowed` for the 13+ chat gate, and `ProximityHost.isBlockedFingerprint`
/// plus `ModerationBanStore.isPeerBanned` for the local block/ban. Nothing here re-implements either
/// rule; it only carries their answers into the merge.
///
/// **Local by construction.** Two members can hold different gates over the same union, which is the
/// point: a member whose age gate refuses chat shows no transcript even though the other branch did,
/// and a member that blocked a sender filters that sender's items at itself alone.
nonisolated struct MeshContentGates: Equatable, Sendable {

    /// This member's 13+ chat gate. False empties the transcript; photos and hearts are unaffected,
    /// exactly as the live gate is (it guards `.tempMessage` and nothing else).
    let chatAllowed: Bool

    /// Fingerprints this member blocks or has locally banned. Never gossiped: moderation under
    /// partition is a local judgement (plan §10.4 keeps the *shared* half behind roster quorum).
    let blockedFingerprints: Set<String>

    /// Gates that refuse nothing — the shape a member with chat allowed and no blocks holds.
    static var open: MeshContentGates {
        MeshContentGates(chatAllowed: true, blockedFingerprints: [])
    }

    /// Builds a gate value.
    init(chatAllowed: Bool, blockedFingerprints: Set<String>) {
        self.chatAllowed = chatAllowed
        self.blockedFingerprints = blockedFingerprints
    }

    /// Folds the live predicates over the senders a merge actually produced, so the gate value can
    /// never disagree with the seam it came from.
    ///
    /// - Parameters:
    ///   - chatAllowed: `MeshNetworkManager.isChatAllowed` at this member.
    ///   - senders: the authors present in the merged ledger (``MeshContentLedger/senders``).
    ///   - isRefused: `ProximityHost.isBlockedFingerprint` ∪ `ModerationBanStore.isPeerBanned`.
    static func folding(
        chatAllowed: Bool,
        senders: Set<String>,
        isRefused: (String) -> Bool
    ) -> MeshContentGates {
        var refused: Set<String> = []
        for sender in senders.sorted() where isRefused(sender) {
            refused.insert(sender)
        }
        return MeshContentGates(chatAllowed: chatAllowed, blockedFingerprints: refused)
    }

    /// Whether content authored by `fingerprint` may be shown at this member.
    func admits(_ fingerprint: String) -> Bool {
        !blockedFingerprints.contains(fingerprint)
    }
}

// MARK: - The view filter

extension MeshContentLedger {

    /// Every author the merged ledger holds content from — the input ``MeshContentGates/folding(chatAllowed:senders:isRefused:)``
    /// needs, and never a roster (a departed member's photos stay visible; leaving is not a retraction).
    var senders: Set<String> {
        var found: Set<String> = []
        for photo in photos.all { found.insert(photo.senderFingerprint) }
        for message in messages.all { found.insert(message.senderFingerprint) }
        for heart in hearts.all { found.insert(heart.senderFingerprint) }
        return found
    }

    /// The transcript this member shows: the union re-derived in total order `(claimedSentAt clamped
    /// to ±10 min of first-seen, senderFingerprint, messageID)`, then the gates applied.
    ///
    /// **Derivation, never mutation** — ``messages`` still holds every merged record afterwards, and
    /// a member that turns its age gate back on sees them without a second merge.
    func visibleTranscript(gates: MeshContentGates) -> [MeshMergedMessage] {
        guard gates.chatAllowed else { return [] }
        return messages.all.filter { gates.admits($0.senderFingerprint) }
    }

    /// The photos this member shows, oldest-first, with the local block/ban re-applied. The 13+ gate
    /// is deliberately absent: it gates chat, and re-using it here would invent a rule the live path
    /// does not have.
    func visiblePhotos(gates: MeshContentGates) -> [MeshMergedPhoto] {
        photos.all.filter { gates.admits($0.senderFingerprint) }
    }

    /// The hearts this member shows, oldest-first, with the local block/ban re-applied.
    func visibleHearts(gates: MeshContentGates) -> [MeshMergedHeart] {
        hearts.all.filter { gates.admits($0.senderFingerprint) }
    }

    /// Whether a merged heart has become a receipt at this member.
    ///
    /// The union alone answers ``MeshHeartReceipt/pending`` for everything: only the foreground
    /// decrypt + ``ProximityHeartLedger`` commit (``MeshHeartCommit/commit(_:into:)``) can move it,
    /// and `committed` is that commit's own answer.
    func heartReceipt(_ giftID: UUID, committed: Set<UUID>) -> MeshHeartReceipt {
        committed.contains(giftID) ? .received : .pending
    }
}

// MARK: - MeshHeartReceipt

/// Whether a merged heart has been receipted at this member. Frozen tokens — never displayed.
nonisolated enum MeshHeartReceipt: String, Equatable, Sendable {
    /// Merged, not yet through the foreground decrypt + ledger commit. The state a union produces.
    case pending
    /// The local ``ProximityHeartLedger`` committed a record for it.
    case received
}

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

    /// The gift ids that became receipts, as the set ``MeshContentLedger/heartReceipt(_:committed:)``
    /// reads.
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
