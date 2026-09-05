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
    /// One named recipient. **Registerable but unmintable in increment 1**: `MeshDeliveryTarget` has
    /// no subset initializer (P4 withheld it on purpose, §22.1), so the mint refuses this row by
    /// name until P6 lands one and flips the column.
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
/// **Unit caveat for the cap**, which P6 must keep in view: `MeshRoutedManifest.size` is the
/// complete sealed *ciphertext* blob, while a store's byte and pixel bounds are *plaintext* bounds
/// enforced at reassembly. Two bounds, both live.
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
    ///   - canonicalStore: The store P6's dispatch will write.
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
/// **Three of the columns have no shipping reader yet, and this is said rather than implied.**
/// `MeshRoutedManifest.signed(…)` has zero shipping call sites — every caller in the tree is a test —
/// so ``MeshRoutedTypeEntry/maxItemByteCount``, ``MeshRoutedTypeEntry/destinations`` and
/// ``MeshRoutedTypeEntry/expiry`` are, like ``MeshRoutedTypeEntry/canonicalStore``, declarations
/// ahead of their reader: **P6 is the first shipping caller.** The guards they feed are correct and
/// tested; they are not blocking anything today.
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
        MeshRoutedTypeEntry(
            token: MeshRoutedTypeToken.photo,
            maxItemByteCount: MeshRoutedManifestFormat.maxContentByteCount,
            destinations: .fullRosterAtCreation,
            relayRetention: .originRetainsUntilDeparture,
            finalAck: .durableRecipientStorage,
            expiry: .meshHardDeadlinePlusGrace,
            canonicalStore: .friendPhotoWall
        ),
        MeshRoutedTypeEntry(
            token: MeshRoutedTypeToken.tempMessage,
            maxItemByteCount: MeshRoutedManifestFormat.maxContentByteCount,
            destinations: .fullRosterAtCreation,
            relayRetention: .originRetainsUntilDeparture,
            finalAck: .durableRecipientStorage,
            expiry: .meshHardDeadlinePlusGrace,
            canonicalStore: .sessionTranscript
        ),
        MeshRoutedTypeEntry(
            token: MeshRoutedTypeToken.heart,
            maxItemByteCount: MeshRoutedManifestFormat.maxContentByteCount,
            destinations: .fullRosterAtCreation,
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
