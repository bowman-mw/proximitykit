// MeshRoutedTypeRegistry.swift
// ProximityKit/Mesh
//
// Network migration P5 item 11 (plan §11): "Unknown type tokens are rejected, not forwarded; every
// future routed type declares size cap, destination semantics, relay-retention, final-ack condition,
// and expiry at registration." That sentence, as ONE value.
//
// The registry is the source; item 4's ``MeshRoutedAckStageTable`` is its projection. Both the
// verifier's accepted-token set and the ack-stage table come from the same rows, so a build cannot
// admit a token at one door and fail to resolve it at another — the drift item 4's forward-compat
// note named ("if it instead re-lists the tokens, the two lists will drift") is closed by
// construction rather than by comment.
//
// What is deliberately NOT here: no wire (the token is already inside the origin's signature and no
// byte moves), no persistence (the index stores the origin's manifest verbatim; a resolved row that
// outlived a build would be a second source of truth), no clock, no store, no gate vocabulary
// (`MeshRoutedAccessGate`'s predicates are item 10's, and a type's declared column is not a gate),
// no dispatch and no relay-hop plumbing behind the reserved increment-2 value.

import Foundation

// MARK: - MeshRoutedDestinationSemantics

/// How a routed type's destination set is DERIVED at the mint — plan §11's "destination semantics"
/// column.
///
/// Frozen English, never localized, never on the wire: the manifest carries its destination set
/// explicitly and ``MeshRoutedManifestVerifier`` binds wraps ≡ destinations from those bytes, so
/// **no receiver ever consults this column**. It is a mint-side derivation policy, which is why a
/// value increment 1 cannot mint is refused at the mint (``MeshRoutedManifestMintError/unsupportedDestinationSemantics``)
/// rather than made unregisterable: a registered row this build cannot mint changes nothing on
/// receive, because there is no receive-side behaviour for it to fall through to.
nonisolated enum MeshRoutedDestinationSemantics: String, CaseIterable, Equatable, Sendable {
    /// The full derived roster at creation minus the origin, immutable thereafter (D7/D12) — every
    /// increment-1 type.
    case fullRosterAtCreation
    /// One named recipient, chosen by the sender and validated against the derived roster at
    /// creation (``MeshDeliveryTarget/addressing(contentID:recipient:roster:selfFingerprint:)``).
    ///
    /// **Minted by the heart row since P6 item 6.** Still no receiver-side reader: the manifest
    /// carries its destination set explicitly and `MeshRoutedManifestVerifier` binds wraps ≡
    /// destinations from those bytes, so a receiver never consults this column. What the mint can
    /// check against it is only a **shape** — one destination — because a full-roster target on a
    /// two-member mesh and a subset target are byte-identical; the real fence is the audience
    /// argument at `MeshNetworkManager`'s one origination door
    /// (``MeshRoutedManifestMintError/unsupportedDestinationSemantics``'s own doc says which door
    /// catches which direction).
    case singleRecipient
}

// MARK: - MeshRoutedRelayRetention

/// Who may hold, and therefore forward, a routed item before its destinations have it — plan §11's
/// "relay-retention" column.
///
/// Frozen English, never localized. Increment 1 ships exactly one implemented value; increment 2's
/// live third-party relay is **reserved and unregisterable** (``isRegisterableInIncrement1``), so a
/// row declaring it is dropped by ``MeshRoutedTypeRegistry/init(entries:)`` and its token then
/// answers nil at every door — fail-closed by construction, with zero hop plumbing built ahead of
/// the plan's device-measurement gate.
nonisolated enum MeshRoutedRelayRetention: String, CaseIterable, Equatable, Sendable {
    /// The origin retains custody exclusively; custody moves only at a departure, to the custodians
    /// the leaver's signed departure record names AND served (P5 item 8, D-6.15/6.16).
    case originRetainsUntilDeparture
    /// Live third-party relay of in-flight chunks — plan §11's **increment 2**, gated on device
    /// measurements. Declared so the column has a name, never registerable here.
    case relayInFlight

    /// Whether a row declaring this retention may be registered by this build.
    var isRegisterableInIncrement1: Bool { self == .originRetainsUntilDeparture }
}

// MARK: - MeshRoutedExpiryRule

/// When a routed type's items stop mattering — plan §11's "expiry" column.
///
/// One case, and it is not editable in increment 1. `expiresAt` is bound into the origin's signature
/// and checked for **exact floored equality** by four shipping verifiers that perform no rule lookup
/// at all (`MeshRoutedManifestVerifier`, `MeshChunkVerifier`, `MeshCustodyReceiptVerifier`,
/// `MeshRecipientReceiptVerifier`), so a per-type grace is a fleet-wide flag day across those four
/// sites plus this rule — P6 changes them together or receivers refuse their own types (D6).
nonisolated enum MeshRoutedExpiryRule: String, CaseIterable, Equatable, Sendable {
    /// The mesh's signed `hardDeadline` floored to whole seconds, plus plan §11's 20-minute
    /// development grace.
    case meshHardDeadlinePlusGrace

    /// The expiry this rule yields, delegated to the ONE formula so no second computation exists.
    ///
    /// - Parameter hardDeadline: The session's signed ceiling.
    /// - Returns: the instant an item of this type expires.
    func expiry(afterHardDeadline hardDeadline: Date) -> Date {
        MeshRoutedManifest.expiry(afterHardDeadline: hardDeadline)
    }
}

// MARK: - MeshRoutedCanonicalStore

/// Which canonical store a routed type's plaintext lands in once P6 routes it (plan §12) — a frozen
/// TOKEN, never a closure and never a store type, so this file stays clock-free, store-free and
/// `nonisolated`.
///
/// **Read by P6's dispatch, by nothing today.** Item 10's job 4c is a documented, counted no-op and
/// no routed code writes a canonical store in increment 1; the slot is declared now so P6 adds a row,
/// not a `switch`. Said plainly rather than dressed up as enforcement.
nonisolated enum MeshRoutedCanonicalStore: String, CaseIterable, Equatable, Sendable {
    /// The friend-photo wall behind `PrivateMediaStore` and the existing review flow.
    case friendPhotoWall
    /// The session transcript — `SessionMessageStore` is the memory-only projection; the sealed
    /// routed inbox beneath it is the durable truth (§12).
    case sessionTranscript
    /// `ProximityHeartLedger`, whose dedup, cooldown and closeness rules are never re-implemented.
    case heartLedger
}

// MARK: - MeshRoutedTypeEntry

/// One routed type's declaration — plan §11's five columns (size cap, destination semantics,
/// relay-retention, final-ack condition, expiry) plus the two adjacent ones items 4 and 10 put on
/// the same row: the foreground-decrypt requirement (derived) and the canonical store (declared).
///
/// **The normative rule, and P6 is held to it:** once a token is registered, its ``finalAck`` and
/// ``destinations`` are as frozen as the token itself. A ``finalAck`` disagreement between two builds
/// refuses nothing and diverges **silently** — a weaker recipient acknowledges a heart on ciphertext
/// alone while the origin believes it delivered. A type whose semantics change gets a NEW token
/// (`…routed-type.<kind>.v2`) registered beside the old one, and the old row stays until no build
/// mints it. Only ``maxItemByteCount`` (loosening is safe in any order; tightening only once the
/// fleet is on the new build) and ``canonicalStore`` may be edited in place; ``expiry`` is not
/// editable at all in increment 1.
///
/// **A never-minted row may be re-declared once, and P6 item 6 spent that allowance.** The rule's
/// failure mode is *silent divergence between two builds that both mint the token*, and
/// `fernlet.mesh.routed-type.heart.v1` was registered by P5 item 11 and minted by nobody — no
/// build has ever produced a heart manifest, so there was no second build to diverge from and no
/// at-rest record whose semantics would change underneath it. Item 6 used that allowance to flip
/// ``destinations`` from `.fullRosterAtCreation` to `.singleRecipient` in place (the column's own
/// doc had promised the flip since increment 1). **It is now spent:** the heart row is frozen for
/// real, and the next semantics change to it is a `…heart.v2` token registered beside it. The v2
/// route was weighed at the time and is not actually cheaper — `token(forCanonicalStore:)` breaks
/// its tie on the lowest token, which sorts `…heart.v1` ahead of `…heart.v2`, so that path needs a
/// resolver change as well as a row.
///
/// **Unit caveat for the cap** — the one thing to get right when narrowing a row.
/// ``maxItemByteCount`` is compared against `MeshRoutedManifest.size`, which is the complete sealed
/// **ciphertext** blob (marker, nonce, ciphertext, tag), while a store's byte and pixel bounds are
/// **plaintext** bounds enforced at reassembly. Two bounds, both live, and they are not the same
/// number: a ciphertext cap set to a plaintext bound refuses items that are perfectly in bounds,
/// and one set above what the seal can produce is no cap at all. So a narrowed row is written as a
/// **formula**, never a literal — the payload's plaintext bound, plus
/// ``MeshRoutedItemBodyFormat/maxFramedHeaderByteCount``, plus
/// ``MeshRoutedItemSealFormat/overheadByteCount``. P6 item 3's photo row is the worked example: it
/// is defined as ``MeshRoutedItemSealFormat/maxResidentBlobByteCount``, which is exactly that sum
/// over `PrivateMediaStore.maxIncomingPhotoBytes`, so the manifest door's per-type check and the
/// delivery projection's resident-blob guard are one number by construction. A row that narrows
/// below what its own sender can seal would have that sender mint items every receiver refuses.
///
/// **What the cap bounds, precisely: the origin-signed manifest at the manifest door — never the
/// bytes resident for an item.** A **parked** chunk set has no type at all (a chunk carries no
/// token, and none is invented for a set whose manifest has not arrived), so its growth is bounded
/// by the store's own chunk caps — `MeshChunkFormat.maxChunkCount` × `maxChunkPayloadBytes`, i.e.
/// 1024 × 256 KiB — and by ``MeshRoutedCapacity``, never by this row. That state is reachable on
/// purpose: a cap refusal **keeps** the parked bytes (the non-dropping arm), so an over-cap item's
/// chunks stay held for a build that loosens the cap, and expiry collects them if none does.
nonisolated struct MeshRoutedTypeEntry: Equatable, Sendable {

    /// The frozen wire spelling this row declares for — the registry's key, from
    /// ``MeshRoutedTypeToken``.
    let token: String

    /// The largest ciphertext an item of this type may claim, in bytes. Registerable only inside
    /// `1 … MeshRoutedManifestFormat.maxContentByteCount`: a row above the wire bound would be
    /// silently overridden by the mint's global guard, and a row of `0` would refuse every item of
    /// its type with no diagnostic.
    let maxItemByteCount: UInt64

    /// How the mint derives the destination set. No receiver reads this column.
    let destinations: MeshRoutedDestinationSemantics

    /// Who may hold and forward an item of this type before its destinations have it.
    let relayRetention: MeshRoutedRelayRetention

    /// What makes an item of this type FINAL at a destination — item 4's stage, verbatim.
    let finalAck: MeshRoutedAckStage

    /// When items of this type stop mattering.
    let expiry: MeshRoutedExpiryRule

    /// Where P6's dispatch will write this type's plaintext. Declared; no reader today.
    let canonicalStore: MeshRoutedCanonicalStore

    /// Whether an item of this type needs a FOREGROUND pass before it can be called delivered.
    ///
    /// **Derived, never stored.** A separate column could disagree with ``finalAck``, and two
    /// policies for one question is exactly what this registry exists to prevent (item 10's decrypt
    /// seam reads the same fact).
    var requiresForegroundDecryptBeforeFinal: Bool {
        finalAck == .foregroundDecryptAndLedgerCommit
    }

    /// Declares one routed type.
    ///
    /// - Parameters:
    ///   - token: The frozen wire spelling.
    ///   - maxItemByteCount: The type's ciphertext cap.
    ///   - destinations: The mint's destination-derivation policy.
    ///   - relayRetention: Who may hold and forward the item.
    ///   - finalAck: What makes it final at a destination.
    ///   - expiry: The expiry rule.
    ///   - canonicalStore: The store the delivery projection writes (P5 item 13 for photos; P6 for the other two rows).
    init(
        token: String,
        maxItemByteCount: UInt64,
        destinations: MeshRoutedDestinationSemantics,
        relayRetention: MeshRoutedRelayRetention,
        finalAck: MeshRoutedAckStage,
        expiry: MeshRoutedExpiryRule,
        canonicalStore: MeshRoutedCanonicalStore
    ) {
        self.token = token
        self.maxItemByteCount = maxItemByteCount
        self.destinations = destinations
        self.relayRetention = relayRetention
        self.finalAck = finalAck
        self.expiry = expiry
        self.canonicalStore = canonicalStore
    }
}

// MARK: - MeshRoutedTypeRegistry

/// The routed type-token registry — plan §11's "declared at registration", as one value.
///
/// A **value**, keyed by `String`, because the token arrives on the wire and the record stores the
/// origin's manifest verbatim: the type is only ever a string at rest. ``entry(for:)`` returning nil
/// **is** "unknown", and it is the one answer everywhere — the manifest verifier refuses
/// ``MeshRoutedManifestRejection/unknownTypeToken``, the ack door refuses
/// ``MeshRoutedStoreRefusal/unknownTypeToken``, the re-entry pass skips the item, and the three
/// forwarding gates (drain offer, which the departure push inherits; the answer builder's receipt and
/// ask half; the hand-off claim) offer, forward and claim nothing for it. No fourth answer is added.
///
/// **A build that narrows its own registry holds what it already has**: an at-rest record whose token
/// this build no longer registers is held, never offered, never forwarded, never asked for, never
/// claimed and never acknowledged, and is collected by expiry. It is NOT dropped — dropping stays
/// item 9's single origin-bound clause, and a build narrowing itself is not an origin's refusal.
/// *Held, and not grown either*: a further chunk for such an item is refused at the ingest door
/// wherever the type is decidable — the manifest is in hand, so the token is — because completing an
/// item nothing will ever acknowledge would only spend the store's caps (D-11.21). A PARKED set is
/// the one place with no answer to give: a chunk carries no token, so item 9's origin-bound clause
/// is what disposes of it.
///
/// **Who reads `destinations`, exactly** (amended by P6 item 6, which made the column mean two
/// different things at two doors). `MeshNetworkManager.originateRoutedItem(…)` reads it against the
/// **audience its caller states** — that is the real fence, and the only one for a full-roster row
/// handed a single recipient. `MeshRoutedManifest.validated(…)` reads it as a **shape** check —
/// a `.singleRecipient` row must arrive with exactly one destination — which is non-vacuous on a
/// roster of three or more and vacuous on a pair, because there a full-roster target and a subset
/// target are byte-identical. No receiver reads it at all.
///
/// **Every column has a shipping reader since P5 item 13.** `MeshRoutedManifest.signed(…)` gained
/// its first shipping caller — the routed sender door behind `addPhoto` — so
/// ``MeshRoutedTypeEntry/maxItemByteCount``, ``MeshRoutedTypeEntry/destinations`` and
/// ``MeshRoutedTypeEntry/expiry`` are now read at a real mint, and
/// ``MeshRoutedTypeEntry/canonicalStore`` is the dispatch key the delivery projection switches on
/// (`.friendPhotoWall` is the worked example; the other two are P6's).
///
/// **The per-type cap has a RECEIVER since P6 item 3** (D-11.4). The photo row no longer sits at the
/// shared wire bound: it is ``MeshRoutedItemSealFormat/maxResidentBlobByteCount``, the formula in the
/// unit caveat above, which makes the manifest door's check reachable for the first time — an
/// over-cap manifest is refused as ``MeshRoutedManifestRejection/sizeExceedsTypeCap`` at
/// `MeshNetworkManager.ingestRoutedManifest`, charged to the envelope sender like every pre-store
/// refusal, and its parked chunk bytes are **kept** (``MeshRoutedParkedDrop`` answers nil, because a
/// cap is a number one build chose and a later build may loosen it). The mint's own
/// ``MeshRoutedManifestMintError/sizeExceedsTypeCap`` became reachable in the same commit. The
/// remaining column ahead of a discriminating test is ``MeshRoutedTypeEntry/expiry``, which still
/// has one case (D-11.22). ``MeshRoutedItemSealFormat`` stays as the seam that bounds a seal and an
/// open — it is now *defined as* the photo row's formula rather than restating a number, so the two
/// ends the earlier note promised to move together are one expression.
///
/// Shipping code names exactly one value, ``increment1``, constructs a registry in exactly one file,
/// and branches on no routed type token anywhere — three source-scan walls in
/// `MeshRoutedStoreIsolationTests` are what keep that true. A fixture registry is a test-only
/// affordance, reached through the manager's one `@testable` seam.
nonisolated struct MeshRoutedTypeRegistry: Equatable, Sendable {

    /// The most rows one registry holds. The SAME number as ``MeshRoutedAckStageTable/maxRows``,
    /// written here rather than read across: naming that type in this file would trip the one-table
    /// wall's "shipping code names no member but `.increment1`" assertion. The equality is pinned by
    /// test, and this is the one constant item 11 restates.
    static let maxEntries = 16

    /// The resolved rows, keyed by the frozen token.
    private let entries: [String: MeshRoutedTypeEntry]

    /// Builds a registry from declarations, first row winning for a repeated token.
    ///
    /// Three registerability predicates, all fail-closed: a dropped row's token answers nil at every
    /// door, which refuses it rather than admitting it under a policy this build does not implement.
    ///
    /// - Parameter entries: The declarations, at most ``maxEntries``.
    init(entries: [MeshRoutedTypeEntry]) {
        var resolved: [String: MeshRoutedTypeEntry] = [:]
        // R2: bounded by `maxEntries`. An entry declaring a relay-retention increment 1 does not
        // implement, or a size cap outside the wire bound, is DROPPED rather than registered.
        for entry in entries.prefix(Self.maxEntries)
        where resolved[entry.token] == nil
            && entry.relayRetention.isRegisterableInIncrement1
            && entry.maxItemByteCount >= 1
            && entry.maxItemByteCount <= MeshRoutedManifestFormat.maxContentByteCount {
            resolved[entry.token] = entry
        }
        self.entries = resolved
    }

    /// Plan §11's three registered types, each column defined AS the constant or decision already
    /// shipped — so registering them changes no behaviour at any door.
    ///
    /// ``MeshRoutedTypeToken/control`` is deliberately absent: registering a token nothing mints
    /// would open a door with no handler behind it.
    static let increment1 = MeshRoutedTypeRegistry(entries: [
        // The photo row is the FIRST narrowed cap (P6 item 3, D-11.4), and it is narrowed to a
        // formula rather than a number: `MeshRoutedItemSealFormat.maxResidentBlobByteCount` is
        // `PrivateMediaStore.maxIncomingPhotoBytes` (the photo wall's PLAINTEXT bound) plus
        // `MeshRoutedItemBodyFormat.maxFramedHeaderByteCount` plus the seal's own overhead — i.e.
        // the widest CIPHERTEXT a routed photo can measure. Defined as that constant, not as a copy
        // of it, so the manifest door's check and the projection's resident-blob guard are the same
        // number and cannot drift; see the unit caveat on `MeshRoutedTypeEntry`.
        MeshRoutedTypeEntry(
            token: MeshRoutedTypeToken.photo,
            maxItemByteCount: UInt64(MeshRoutedItemSealFormat.maxResidentBlobByteCount),
            destinations: .fullRosterAtCreation,
            relayRetention: .originRetainsUntilDeparture,
            finalAck: .durableRecipientStorage,
            expiry: .meshHardDeadlinePlusGrace,
            canonicalStore: .friendPhotoWall
        ),
        // The text row's cap is the SECOND narrowed one (P6 item 4), and narrowed the same way:
        // `MeshRoutedTextBody.maxSealedBlobByteCount` is the sanitized maximum's own byte bound
        // (16 × `SessionMessageStore.maxTextLength`, because the product's cap is 500 *Characters*
        // and a grapheme cluster is unbounded in bytes) plus this body family's framed header
        // allowance plus the seal's overhead — 9 065 B. Defined as that constant, never as a copy,
        // so the mint's own refusal and the manifest door's `sizeExceedsTypeCap` are one number.
        // `canonicalStore` and `maxItemByteCount` are the two columns the freezing rule leaves
        // editable in place, so this needs no amendment to it.
        MeshRoutedTypeEntry(
            token: MeshRoutedTypeToken.tempMessage,
            maxItemByteCount: UInt64(MeshRoutedTextBody.maxSealedBlobByteCount),
            destinations: .fullRosterAtCreation,
            relayRetention: .originRetainsUntilDeparture,
            finalAck: .durableRecipientStorage,
            expiry: .meshHardDeadlinePlusGrace,
            canonicalStore: .sessionTranscript
        ),
        // The heart row's cap is the THIRD narrowed one (P6 item 6), and its formula has a **zero**
        // payload term: a heart body is header-only, so the widest ciphertext it can measure is
        // this family's framed header allowance plus the seal's overhead. `destinations` is
        // `.singleRecipient` since item 6 — the one re-declaration the freezing rule above allows a
        // never-minted row, and it is spent.
        MeshRoutedTypeEntry(
            token: MeshRoutedTypeToken.heart,
            maxItemByteCount: UInt64(MeshRoutedHeartBody.maxSealedBlobByteCount),
            destinations: .singleRecipient,
            relayRetention: .originRetainsUntilDeparture,
            finalAck: .foregroundDecryptAndLedgerCommit,
            expiry: .meshHardDeadlinePlusGrace,
            canonicalStore: .heartLedger
        )
    ])

    /// Every token this registry accepts — the verifier's `acceptedTypeTokens` (D13/D-6.9), from the
    /// same rows the ack stages come from.
    var tokens: Set<String> { Set(entries.keys) }

    /// The declaration for `token`, or nil for a token nobody registered.
    ///
    /// - Parameter token: The manifest's origin-signed token, verbatim.
    /// - Returns: the entry, or nil — which is a refusal at every door that asks.
    func entry(for token: String) -> MeshRoutedTypeEntry? {
        entries[token]
    }

    /// The token an ORIGIN mints under to reach one canonical store — the registry read a sender
    /// needs, and the reason `MeshNetworkManager` names no token spelling of its own (P5 item 13).
    ///
    /// The wall `noShippingCodeBranchesOnARoutedTypeToken` permits `MeshRoutedTypeToken.` only where
    /// the constants are declared and where these rows are built from them, and it is right to: a
    /// sender that typed `MeshRoutedTypeToken.photo` at its mint would be a second per-type source,
    /// free to drift from the row that decides what the RECEIVER does with the bytes. Asking the
    /// registry keeps one source for both directions, and gives P6's text and heart callers the same
    /// three-line shape.
    ///
    /// Deterministic when a store has more than one row — which increment 1 does not have — by
    /// taking the lowest token, so two builds cannot mint the same content under different tokens.
    ///
    /// - Parameter store: The canonical store the item is destined for.
    /// - Returns: the token, or nil when no row names that store.
    func token(forCanonicalStore store: MeshRoutedCanonicalStore) -> String? {
        entries.values.filter { $0.canonicalStore == store }.map(\.token).min()
    }

    /// The final-ack column, projected into item 4's door parameter
    /// (`MeshRoutedStore.committingDelivery(item:recipient:stages:evidence:now:)`, D-4.7).
    ///
    /// Bounded by the dictionary, itself bounded by ``maxEntries``.
    var ackStages: MeshRoutedAckStageTable {
        MeshRoutedAckStageTable(rows: entries.values.map {
            MeshRoutedAckStageRow(typeToken: $0.token, finalAck: $0.finalAck)
        })
    }
}
