// MeshContentMerge.swift
// ProximityKit/Mesh
//
// P4 item 7 (plan §10.3): **content merge — ordering and dedup on ingestion.**
//
// §10.3 answers "how do the messages and photos combine?" in one sentence: *by ID-keyed union +
// deterministic re-derivation; nothing is overwritten because nothing conflicting can exist (only
// missing).* This file is that sentence as code: the generic union every content kind merges by
// (``MeshContentKey``, ``MeshMergeableContent``, ``MeshContentOrder``, ``MeshContentSet``, public with
// their union laws since plan step A0.5.1), for the three content kinds a partition can split. The
// kinds themselves are their features', FernletSocial's: the photo and message kinds and the ledger
// that holds all three in `Mesh/MeshContentLedger.swift`, and the heart kind beside the heart ledger:
//
//   * **Photos** — union by `(author, manifest ID)`, hash-validated on reassembly, then the existing
//     review flow.
//   * **Texts** — union by `(author, message ID)`; the visible transcript is re-derived in total
//     order `(claimedSentAt clamped to ±10 min of first-seen, senderFingerprint, messageID)`.
//   * **Hearts** — union by `(author, gift ID)`; the final receipt is still only the foreground
//     decrypt + heart ledger commit, which is why receipt state is deliberately NOT a field of the
//     kind. The merged heart is FernletSocial's `HeartSharing/MeshMergedHeart.swift`, beside the
//     heart ledger and its commit.
//
// **The author is part of the identity for all three, and that is the P6 item 4 fix-review change**
// (finding P1-1; see ``MeshContentKey``). Only the TEXT set has a shipping call site
// (FernletSocial's `SessionMessageStore`), so only text's hazard was live — but the photo and heart
// sets are keyed the same way for the same reason: the routed index's key is
// `(originFingerprint, itemID)` for every family, a manifest publishes that id to the whole roster
// before delivery, and neither
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
// built from payloads that already exist. The gates that filter them live in FernletSocial's
// `MeshContentIngest.swift`, as a **view filter over an unmutated union**, exactly as termination is
// derived at read rather than applied at merge.
//
// **What is NOT here, on purpose:** the routed inbox and the relay drain (P5), and feature routing
// (P6). This file owns the *rules* only.

import Foundation

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
///
/// Public so a host's content kind conforms and unions in a ``MeshContentSet``. The contract a
/// conformer owes: `contentID` and `senderFingerprint` are the author's id and the
/// transport-verified author, never a wire claim; `orderingInstant` and `mergeTiebreak` are pure
/// functions of the item's own values (no clock, no arrival order), so every member orders two
/// copies alike; `setCapacity` is the live surface's own cap. Owed that, the set's union laws hold.
public nonisolated protocol MeshMergeableContent: Equatable, Sendable {

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
    /// Public as the key a holder of merged items keys its own side tables on.
    public nonisolated var mergeKey: MeshContentKey {
        MeshContentKey(senderFingerprint: senderFingerprint, contentID: contentID)
    }
}

// MARK: - MeshContentOrder

/// The one total order every merged content kind sorts and dedupes by.
///
/// `(orderingInstant, senderFingerprint, contentID, mergeTiebreak)`, ascending. The first three are
/// plan §10.3's stated transcript order verbatim; the fourth can only ever break a tie the first
/// three could not, which for distinct ids never happens.
///
/// Public as the order a ``MeshContentSet`` keeps, dedupes and caps by, so a host's view over a set
/// sorts the way the union does.
public nonisolated enum MeshContentOrder {

    /// Whether `lhs` sorts before `rhs`. A strict total order: irreflexive, transitive, and total
    /// over any two items that are not equal in all four keys.
    ///
    /// - Parameters:
    ///   - lhs: One item.
    ///   - rhs: Another item of the same kind.
    /// - Returns: whether `lhs` sorts strictly before `rhs`.
    public static func precedes<Item: MeshMergeableContent>(_ lhs: Item, _ rhs: Item) -> Bool {
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
/// at `Item.setCapacity` keeping the **newest** k — which is what Fernlet's three live surfaces do
/// (all FernletSocial's: `SessionMessageStore` drops oldest, the photo wall prefixes a newest-first
/// list, `ProximityHeartLedger` suffixes its records).
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
///
/// Public, with the members a holder of merged content needs, so a host's content kind unions in
/// the engine's set rather than a copy of it. The contract is §10.3's union laws: ``merging(_:)`` is
/// commutative, associative and idempotent, at the cap as well as below it, for every item whose
/// copies agree on their ordering keys; every value is normalized (one item per ``MeshContentKey``,
/// the ``MeshContentOrder``-least copy winning, oldest-first, the newest `Item.setCapacity` kept).
public nonisolated struct MeshContentSet<Item: MeshMergeableContent>: Equatable, Sendable {

    /// Defensive bound on one normalization pass. Inputs are already-normalized sets, so a union of
    /// two is at most `2 × setCapacity`; four times that is slack, not a policy.
    static var maxInputItems: Int { Item.setCapacity * 4 }

    private let ordered: [Item]

    /// A set holding nothing — the identity of ``merging(_:)``.
    public static var empty: MeshContentSet<Item> { MeshContentSet([]) }

    /// Builds a set, normalizing the input (dedup by id, sort, cap).
    init(_ items: [Item]) {
        ordered = Self.normalized(items)
    }

    /// The items, oldest-first in the set's total order, at most `Item.setCapacity` of them.
    public var all: [Item] { ordered }

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
    public var mergeKeys: Set<MeshContentKey> { Set(ordered.map(\.mergeKey)) }

    /// Whether the set already holds `id`, from **any** author.
    func contains(_ id: UUID) -> Bool { ordered.contains { $0.contentID == id } }

    /// Whether the set already holds that author's copy of that id.
    func contains(_ key: MeshContentKey) -> Bool { ordered.contains { $0.mergeKey == key } }

    /// The set with `item` added. An existing copy of the same ``MeshContentKey`` that sorts
    /// earlier wins, and at the cap the oldest item in the total order leaves (which may be `item`).
    ///
    /// - Parameter item: The item to add.
    /// - Returns: The normalized set holding it, or holding the copy that beat it.
    public func inserting(_ item: Item) -> MeshContentSet<Item> {
        MeshContentSet(ordered + [item])
    }

    /// The union of two sets — the merge plan §10.3 runs on every reconnect. Commutative,
    /// associative and idempotent, at the cap as well as below it.
    ///
    /// - Parameter other: The set to union with.
    /// - Returns: The normalized union.
    public func merging(_ other: MeshContentSet<Item>) -> MeshContentSet<Item> {
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
