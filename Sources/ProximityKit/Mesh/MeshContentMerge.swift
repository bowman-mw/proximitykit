// MeshContentMerge.swift
// ProximityKit/Mesh
//
// P4 item 7 (plan §10.3): **content merge — ordering and dedup on ingestion.**
//
// §10.3 answers "how do the messages and photos combine?" in one sentence: *by ID-keyed union +
// deterministic re-derivation; nothing is overwritten because nothing conflicting can exist (only
// missing).* This file is that sentence as code, for the three content kinds a partition can split:
//
//   * **Photos** — union by `(author, manifest ID)`, hash-validated on reassembly
//     (``MeshPhotoReassembly``), then the existing review flow.
//   * **Texts** — union by `(author, message ID)`; the visible transcript is re-derived in total
//     order `(claimedSentAt clamped to ±10 min of first-seen, senderFingerprint, messageID)`.
//   * **Hearts** — union by `(author, gift ID)`; the final receipt is still only the foreground
//     decrypt + ``ProximityHeartLedger`` commit, which is why receipt state is deliberately NOT a
//     field here.
//
// **The author is part of the identity for all three, and that is the P6 item 4 fix-review change**
// (finding P1-1; see ``MeshContentKey``). Only the TEXT set has a shipping call site today
// (`SessionMessageStore`), so only text's hazard was live — but the photo and heart sets are keyed
// the same way for the same reason: the routed index's key is `(originFingerprint, itemID)` for
// every family, a manifest publishes that id to the whole roster before delivery, and neither
// `MeshRoutedManifestVerifier` nor `MeshRoutedIndex` refuses a duplicate id from a second origin.
// Closing it at the protocol means item 6's heart wiring and any future photo wiring inherit the
// fix rather than re-deriving it. The key is LOCAL: no wire field, no golden, no persisted surface.
//
// **Deliberately the same shape as ``MeshMembershipLedger``**, and for the same reason: a pure value
// with a pure union means reconnect, merge after a partition and reload after a process death are
// literally one code path, and the convergence property needs no store and no transport. Union is
// commutative, associative and idempotent **including at the caps** — the caps keep the newest k
// under one fixed total order, and "keep the max k under a total order" composes (an item the inner
// merge dropped is greater than k items of the inner input, so it is greater than k items of the
// whole, and the outer merge would drop it too).
//
// **Nothing here is persisted and nothing here is wire.** `MeshSessionContext`'s schema stays 2,
// no `UserDefaults` key is added, and no payload gains a field — these are in-memory projections
// built from payloads that already exist. The gates that filter them live in
// `MeshContentIngest.swift`, as a **view filter over an unmutated union**, exactly as termination is
// derived at read rather than applied at merge.
//
// **What is NOT here, on purpose:** the routed inbox and the relay drain (P5), and feature routing
// (P6). This file owns the *rules* only.

import Foundation
import FernletDomainModel

// MARK: - MeshContentKey

/// The identity of one merged item: **the authenticated author AND the id that author minted**
/// (P6 item 4 fix review, finding P1-1).
///
/// The union used to key on the id alone, which is only sound while one id can belong to one
/// author. On the routed store it cannot: an item's id is chosen freely by its origin
/// (`MeshRoutedManifest.itemID`), the routed index's own key is `(originFingerprint, itemID)` and
/// `MeshRoutedManifestVerifier` has no duplicate-id rejection — two origins may legitimately hold
/// items with the same id — while the signed manifest publishing that id travels **in the clear**
/// to the whole roster at creation. So an admitted member B could read A's id off a manifest, mint
/// its own text carrying it, and win the race to a partitioned member C; A's genuine message would
/// then land `alreadyHeld`, be marked final, and be gone from C's transcript for the session while
/// A saw `.staged`. A censorship primitive between admitted members, closed here by making the
/// author part of the identity.
///
/// **This is a LOCAL key and nothing else.** It is not persisted, not serialized and never on the
/// wire: the manifest and the body are byte-for-byte what they were, no golden moves, and
/// `contentID` is still the id the inventory half of a merge exchange asks about
/// (``MeshContentSet/contentIDs``). What changed is only which pairs of items the union treats as
/// one item.
///
/// §10.3's order is untouched too, and did not need to move: ``MeshContentOrder/precedes`` already
/// ranks `senderFingerprint` above `contentID`, so two same-id items from different authors were
/// always totally ordered — the dedup was the only half that conflated them.
public nonisolated struct MeshContentKey: Hashable, Sendable {

    /// The transport-verified author. Never a wire claim.
    public let senderFingerprint: String
    /// The id that author minted.
    public let contentID: UUID

    /// Builds a merged-content identity.
    public init(senderFingerprint: String, contentID: UUID) {
        self.senderFingerprint = senderFingerprint
        self.contentID = contentID
    }
}

// MARK: - MeshMergeableContent

/// One kind of merged content: what its union keys on, and the total order it re-derives in.
///
/// Every conformer carries a `UUID` its author minted plus the transport-verified author, and the
/// union keys on **both** (``MeshContentKey``): two members holding the same pair hold the same
/// item, so a merge can only ever be missing something, never in conflict — while two *authors*
/// holding one id are two items, which is what ``MeshContentKey`` exists to say.
/// ``mergeTiebreak`` exists so that even the pathological case — two copies of one item that the
/// instant and the sender cannot separate — resolves the same way at every member, which is what
/// keeps the union commutative.
nonisolated protocol MeshMergeableContent: Equatable, Sendable {

    /// The id this item's author minted. One half of ``mergeKey``, which is what the union
    /// actually keys on: two items with equal ids are the same item only if their AUTHORS agree.
    var contentID: UUID { get }

    /// The transport-verified author. Never a wire claim, and the second key of the total order.
    var senderFingerprint: String { get }

    /// This kind's ordering instant — the first key of the total order. For a message it is the
    /// *clamped* claim, never the raw one, so a forged stamp cannot jump the queue.
    var orderingInstant: Date { get }

    /// A stable, content-derived last resort for two copies of one ``MeshContentKey`` that the
    /// instant cannot separate. Never a clock and never arrival order: either would make the union
    /// order-dependent, and the laws would fail.
    var mergeTiebreak: String { get }

    /// How many items of this kind one member keeps. Matches the live surface's own cap so a merged
    /// view and a live one bound identically.
    static var setCapacity: Int { get }
}

extension MeshMergeableContent {

    /// This item's identity for the union: its author and its id, never the id alone.
    ///
    /// Derived rather than stored, and not overridable by a conformer — the two halves are already
    /// required members of the protocol, so every kind gets the same rule and none can weaken it.
    nonisolated var mergeKey: MeshContentKey {
        MeshContentKey(senderFingerprint: senderFingerprint, contentID: contentID)
    }
}

// MARK: - MeshContentOrder

/// The one total order every merged content kind sorts and dedupes by.
///
/// `(orderingInstant, senderFingerprint, contentID, mergeTiebreak)`, ascending. The first three are
/// plan §10.3's stated transcript order verbatim; the fourth can only ever break a tie the first
/// three could not, which for distinct ids never happens.
nonisolated enum MeshContentOrder {

    /// Whether `lhs` sorts before `rhs`. A strict total order: irreflexive, transitive, and total
    /// over any two items that are not equal in all four keys.
    static func precedes<Item: MeshMergeableContent>(_ lhs: Item, _ rhs: Item) -> Bool {
        if lhs.orderingInstant != rhs.orderingInstant {
            return lhs.orderingInstant < rhs.orderingInstant
        }
        if lhs.senderFingerprint != rhs.senderFingerprint {
            return lhs.senderFingerprint < rhs.senderFingerprint
        }
        let lhsID = lhs.contentID.uuidString
        let rhsID = rhs.contentID.uuidString
        if lhsID != rhsID { return lhsID < rhsID }
        return lhs.mergeTiebreak < rhs.mergeTiebreak
    }
}

// MARK: - MeshContentSet

/// A key-keyed, order-normalized set of one content kind — the union half of plan §10.3. The key
/// is ``MeshContentKey``: the author and the id together.
///
/// Normalization runs on every construction, so a set is always: one item per ``MeshContentKey``
/// — i.e. per `(author, id)`, never per id alone (P6 item 4 fix review, finding P1-1: an id is the
/// origin's own choice and a manifest publishes it to the whole roster before delivery, so keying
/// on it alone lets one admitted member spend another's dedup slot) — with the
/// ``MeshContentOrder``-least copy winning, sorted by that same order oldest-first, and capped
/// at `Item.setCapacity` keeping the **newest** k — which is what all three live surfaces do
/// (`SessionMessageStore` drops oldest, the photo wall prefixes a newest-first list,
/// `ProximityHeartLedger` suffixes its records).
///
/// Deliberately **not** `Codable`: this is a merge-time projection, never a persisted surface. The
/// sealed `MeshSessionContext` schema stays 2 because of it.
///
/// **The precondition the cap laws rest on.** "Keep the max k under a fixed total order" composes,
/// so the laws hold at the cap for every ``MeshContentKey`` whose copies agree on their ordering
/// keys — which is
/// every honest item, because the keys are the author's own values. The single place two copies of
/// one id can disagree is a *receiver-local* field (`firstSeenAt`), and it reaches
/// ``MeshMergeableContent/orderingInstant`` only for a message whose claimed stamp is outside its
/// clamp window, i.e. a forged one. Below the cap that still resolves identically at every member
/// (the order-least copy wins, and "least" is order-independent); at the cap, a forged stamp on a
/// full set is the one shape where the inner merge could drop the copy the outer would have kept.
/// Named here rather than papered over — P5's routed store is where a per-item first-seen becomes
/// authoritative, and that is where it should be closed.
nonisolated struct MeshContentSet<Item: MeshMergeableContent>: Equatable, Sendable {

    /// Defensive bound on one normalization pass. Inputs are already-normalized sets, so a union of
    /// two is at most `2 × setCapacity`; four times that is slack, not a policy.
    static var maxInputItems: Int { Item.setCapacity * 4 }

    private let ordered: [Item]

    /// A set holding nothing.
    static var empty: MeshContentSet<Item> { MeshContentSet([]) }

    /// Builds a set, normalizing the input (dedup by id, sort, cap).
    init(_ items: [Item]) {
        ordered = Self.normalized(items)
    }

    /// The items, oldest-first in the set's total order.
    var all: [Item] { ordered }

    /// How many items the set holds.
    var count: Int { ordered.count }

    /// Whether the set holds nothing.
    var isEmpty: Bool { ordered.isEmpty }

    /// Whether the set is full, so a caller can report a dropped item instead of wondering.
    var isAtCapacity: Bool { ordered.count >= Item.setCapacity }

    /// The ids the set holds — the inventory half of a merge exchange.
    ///
    /// Still the **ids**, deliberately: "do you hold item X?" is the question a merge exchange
    /// asks, and an id is what a peer can name. The set's own identity is ``mergeKeys``, and the
    /// two differ only in the pathological case two authors minted one id.
    var contentIDs: Set<UUID> { Set(ordered.map(\.contentID)) }

    /// The identities the set holds — one per item, author included. The key a holder of the items
    /// keys its own side tables on.
    var mergeKeys: Set<MeshContentKey> { Set(ordered.map(\.mergeKey)) }

    /// Whether the set already holds `id`, from **any** author.
    func contains(_ id: UUID) -> Bool { ordered.contains { $0.contentID == id } }

    /// Whether the set already holds that author's copy of that id.
    func contains(_ key: MeshContentKey) -> Bool { ordered.contains { $0.mergeKey == key } }

    /// The set with `item` added. An existing copy of the same ``MeshContentKey`` that sorts
    /// earlier wins.
    func inserting(_ item: Item) -> MeshContentSet<Item> {
        MeshContentSet(ordered + [item])
    }

    /// The union of two sets — the merge plan §10.3 runs on every reconnect. Commutative,
    /// associative and idempotent, at the cap as well as below it.
    func merging(_ other: MeshContentSet<Item>) -> MeshContentSet<Item> {
        MeshContentSet(ordered + other.ordered)
    }

    /// Dedupes by ``MeshContentKey`` (the order-least copy wins), sorts by the total order, then
    /// keeps the newest `Item.setCapacity`.
    private static func normalized(_ items: [Item]) -> [Item] {
        var winnerByKey: [MeshContentKey: Item] = [:]
        // R2: bounded by `maxInputItems`.
        for item in items.prefix(Self.maxInputItems) {
            let key = item.mergeKey
            guard let existing = winnerByKey[key] else {
                winnerByKey[key] = item
                continue
            }
            if MeshContentOrder.precedes(item, existing) {
                winnerByKey[key] = item
            }
        }
        let sorted = winnerByKey.values.sorted(by: MeshContentOrder.precedes)
        return Array(sorted.suffix(Item.setCapacity))
    }
}

// MARK: - MeshMergedPhoto

/// One shared photo as the merge sees it: manifest id, author, the epoch it was sealed at, when it
/// was added, and the digest its reassembled bytes must match.
///
/// A projection of ``FriendPhotoManifestEntry`` plus what the holder knows about the bytes — the
/// digest is a **local** value, not a wire field, so no manifest golden moves. `keyEpoch` is carried
/// because the legacy path gated on it and a photo created in the *other* branch of a split
/// necessarily names another epoch. Since P5 item 13 the LIVE photo path gates on no epoch at all
/// (see `MeshContentIngest.swift`'s note), and this value is untouched by that retirement: it is a
/// pure value with no manager call site, and P6 owns its wiring.
nonisolated struct MeshMergedPhoto: MeshMergeableContent {

    static let setCapacity = FriendPhotoLimits.maxManifestEntries

    /// The manifest id the union keys on.
    let manifestID: UUID
    /// The photo's author, as the manifest announced it.
    let senderFingerprint: String
    /// The group-key epoch the bytes were sealed at. `0` is the legacy unencrypted shape.
    let keyEpoch: Int
    /// When the author added the photo — the set's ordering instant.
    let addedAt: Date
    /// SHA-256 of the photo's reassembled bytes, as this holder computed them.
    let contentDigest: Data

    var contentID: UUID { manifestID }
    var orderingInstant: Date { addedAt }
    var mergeTiebreak: String { contentDigest.base64EncodedString() }

    /// Builds a merged-photo projection.
    init(manifestID: UUID, senderFingerprint: String, keyEpoch: Int, addedAt: Date, contentDigest: Data) {
        self.manifestID = manifestID
        self.senderFingerprint = senderFingerprint
        self.keyEpoch = keyEpoch
        self.addedAt = addedAt
        self.contentDigest = contentDigest
    }
}

// MARK: - MeshMergedMessage

/// One session message as the merge sees it, carrying **both** clocks §10.3's order needs.
///
/// `claimedSentAt` is the sender's own stamp and is never trusted alone; `firstSeenAt` is the
/// **receiver's** clock at the moment the message entered this device's view, and it is the anchor
/// the claim is clamped against. ``orderingInstant`` is the clamped value, so a peer claiming three
/// hours ago — or three hours hence — moves at most ``claimWindow`` from where it actually arrived.
///
/// **The clamp is a bound, not a coordination mechanism.** Two members assign their own first-seen
/// instants, so convergence on an identical transcript holds for every claim *inside* its window
/// (the ordering instant is then the claim itself, which every member agrees on). A forged claim
/// outside the window is bounded at each member's own clock, which is the security property; it is
/// not a promise that a forger sorts identically everywhere.
nonisolated struct MeshMergedMessage: MeshMergeableContent {

    static let setCapacity = SessionMessageStore.maxMessages

    /// How far from first-seen a claimed stamp may reach, in either direction (plan §10.3).
    static let claimWindow: TimeInterval = 10 * 60

    /// The message id the union keys on.
    let messageID: UUID
    /// The transport-verified sender.
    let senderFingerprint: String
    /// The already-sanitized text (`SessionMessageStore.sanitize` ran at the wire boundary).
    let text: String
    /// The sender's own stamp. Untrusted; clamped before it orders anything.
    let claimedSentAt: Date
    /// The receiving member's clock when this message first entered its view. Never a wire value.
    let firstSeenAt: Date

    var contentID: UUID { messageID }
    var orderingInstant: Date { Self.clamped(claimedSentAt, around: firstSeenAt) }
    var mergeTiebreak: String { text }

    /// Builds a merged-message projection. `firstSeenAt` must come from the receiver's clock.
    init(messageID: UUID, senderFingerprint: String, text: String, claimedSentAt: Date, firstSeenAt: Date) {
        self.messageID = messageID
        self.senderFingerprint = senderFingerprint
        self.text = text
        self.claimedSentAt = claimedSentAt
        self.firstSeenAt = firstSeenAt
    }

    /// `claim` pulled into ±``claimWindow`` of `firstSeen`. A claim already inside the window is
    /// returned unchanged, which is why honest traffic sorts identically at every member.
    static func clamped(_ claim: Date, around firstSeen: Date) -> Date {
        let earliest = firstSeen.addingTimeInterval(-claimWindow)
        let latest = firstSeen.addingTimeInterval(claimWindow)
        return min(max(claim, earliest), latest)
    }
}

// MARK: - MeshMergedHeart

/// One heart as the merge sees it — and deliberately **without** a receipt field.
///
/// §10.3: the final receipt is still only the foreground decrypt + ``ProximityHeartLedger`` commit.
/// A peer's "received" is that peer's receipt, not this member's, so merging one in would be a
/// receipt this device never issued. Receipt state is therefore local and derived
/// (`MeshContentLedger.heartReceipt(_:committed:)`), never merged.
nonisolated struct MeshMergedHeart: MeshMergeableContent {

    static let setCapacity = ProximityHeartLedger.maxStoredHearts

    /// The gift id the union keys on — the wire payload's id, stable across a duplicate delivery.
    let giftID: UUID
    /// The transport-verified sender.
    let senderFingerprint: String
    /// The sender's display name, already sanitized at the wire boundary.
    let senderDisplayName: String
    /// The receiving member's clock when this heart first entered its view.
    let firstSeenAt: Date

    var contentID: UUID { giftID }
    var orderingInstant: Date { firstSeenAt }
    var mergeTiebreak: String { senderDisplayName }

    /// Builds a merged-heart projection. `firstSeenAt` must come from the receiver's clock.
    init(giftID: UUID, senderFingerprint: String, senderDisplayName: String, firstSeenAt: Date) {
        self.giftID = giftID
        self.senderFingerprint = senderFingerprint
        self.senderDisplayName = senderDisplayName
        self.firstSeenAt = firstSeenAt
    }
}

// MARK: - MeshContentLedger

/// Everything a member holds of a split's *content*: three ``MeshContentKey``-keyed sets, and
/// nothing else.
///
/// The content-side twin of ``MeshMembershipLedger`` — pure value data with a pure union, so
/// §16.2's convergence property needs no store and no transport. Merging is the only way two views
/// combine; there is no "apply an item to a transcript" path, which is what makes reconnect, merge
/// and reload one code path.
///
/// The gates that decide what a member *shows* are a separate, read-time filter
/// (`MeshContentIngest.swift`): a blocked sender's message still unions, it simply does not render
/// at the member that blocked them. Same shape as termination-derived-at-read, and for the same
/// reason — a merge that mutated records would break the union laws.
nonisolated struct MeshContentLedger: Equatable, Sendable {

    /// Photos held, by manifest id.
    var photos: MeshContentSet<MeshMergedPhoto>
    /// Messages held, by message id.
    var messages: MeshContentSet<MeshMergedMessage>
    /// Hearts held, by gift id.
    var hearts: MeshContentSet<MeshMergedHeart>

    /// A ledger holding no content.
    static var empty: MeshContentLedger { MeshContentLedger() }

    /// Builds a content ledger from any combination of sets.
    init(
        photos: MeshContentSet<MeshMergedPhoto> = .empty,
        messages: MeshContentSet<MeshMergedMessage> = .empty,
        hearts: MeshContentSet<MeshMergedHeart> = .empty
    ) {
        self.photos = photos
        self.messages = messages
        self.hearts = hearts
    }

    /// The union of two content ledgers: set union in all three kinds. Commutative, associative,
    /// idempotent — N-way merges need no special case because pairwise union already converges.
    func merging(_ other: MeshContentLedger) -> MeshContentLedger {
        MeshContentLedger(
            photos: photos.merging(other.photos),
            messages: messages.merging(other.messages),
            hearts: hearts.merging(other.hearts)
        )
    }
}
