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
//
// The rows come from two places since plan step A0.5.9 (seam S16): the engine's resident rows, built
// here, and the host's own (`ProximityHost.meshRoutedTypeEntries`; for Fernlet, FernletSocial's
// temporary-message row, which left with chat). So the row and its column values are public: a host
// declares its rows through the entry's public initializer, and the registry that resolves them
// stays the engine's.
//
// The one `PrivateMediaStore` import came with the photo row's formula (plan step A0.5.4, from the
// seal file; it leaves with the photo row) and reaches a single Int — `maxIncomingPhotoBytes`, the
// row's payload term — never the store type, its key provider or a byte of its data.

import Foundation
import PrivateMediaStore

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
///
/// Public as a column of a host's ``MeshRoutedTypeEntry`` (plan step A0.5.9, S16).
public nonisolated enum MeshRoutedDestinationSemantics: String, CaseIterable, Equatable, Sendable {
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
///
/// Public as a column of a host's ``MeshRoutedTypeEntry`` (plan step A0.5.9, S16); which value is
/// registerable stays the engine's answer.
public nonisolated enum MeshRoutedRelayRetention: String, CaseIterable, Equatable, Sendable {
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
///
/// Public as a column of a host's ``MeshRoutedTypeEntry`` (plan step A0.5.9, S16); the expiry it
/// yields stays the engine's one formula.
public nonisolated enum MeshRoutedExpiryRule: String, CaseIterable, Equatable, Sendable {
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

// MARK: - MeshRoutedContentScope

/// How long a routed type's projected content lives on a destination — the row's content-scope
/// column (plan step A0.5.2, which replaced the canonical-store column with it).
///
/// The engine reads it for one thing. A `.session` row's items may enter only the session they were
/// first offered in, so the projection computes ``MeshTranscriptLiveness`` for each of them and hands
/// it to the row's handler, and the re-entry pass skips an item whose session has ended for good
/// before spending an allowance slot on it; a `.persistent` row's items are left to their handler.
/// Which store the plaintext lands in is the registered projection handler's business and never a
/// column: a row names no store, so this file stays clock-free, store-free and `nonisolated`. Frozen
/// English, never on the wire.
public nonisolated enum MeshRoutedContentScope: String, CaseIterable, Equatable, Sendable {
    /// Content that outlives the session it arrived in — a photo, a heart.
    case persistent
    /// Content that belongs to the session it was offered in and leaves with that session's
    /// transcript — a message.
    case session
}

// MARK: - MeshRoutedTypeEntry

/// One routed type's declaration — plan §11's five columns (size cap, destination semantics,
/// relay-retention, final-ack condition, expiry) plus the two adjacent ones items 4 and 10 put on
/// the same row: the foreground-decrypt requirement (derived) and the content scope (declared; the
/// canonical-store column until plan step A0.5.2).
///
/// **The normative rule, and P6 is held to it:** once a token is registered, its ``finalAck`` and
/// ``destinations`` are as frozen as the token itself. A ``finalAck`` disagreement between two builds
/// refuses nothing and diverges **silently** — a weaker recipient acknowledges a heart on ciphertext
/// alone while the origin believes it delivered. A type whose semantics change gets a NEW token
/// (`…routed-type.<kind>.v2`) registered beside the old one, and the old row stays until no build
/// mints it. Only ``maxItemByteCount`` (loosening is safe in any order; tightening only once the
/// fleet is on the new build) and ``contentScope`` may be edited in place; ``expiry`` is not
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
/// route was weighed at the time and is not actually cheaper: a sender mints under its own row's
/// token (its row by name: ``MeshRoutedTypeRegistry/increment1Rows(_:)``'s since plan step A0.5.2,
/// and for the heart the host's, FernletSocial's `FernletRoutedTypes`, since plan step A0.5.10; a
/// lowest-token resolver before it, which sorted `…heart.v1` ahead of `…heart.v2`), so that path
/// needs the sender re-pointed as well as a row.
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
/// is exactly that sum over `PrivateMediaStore.maxIncomingPhotoBytes`, and as the widest row it is
/// the registry's ``MeshRoutedTypeRegistry/maxItemByteCount`` — the one bound the manager holds for
/// its seal, its open and the delivery projection's resident-blob guard (plan step A0.5.4) — so the
/// manifest door's per-type check and that guard are one number by construction. A row that narrows
/// below what its own sender can seal would have that sender mint items every receiver refuses.
///
/// **What the cap bounds, precisely: the origin-signed manifest at the manifest door — never the
/// bytes resident for an item.** A **parked** chunk set has no type at all (a chunk carries no
/// token, and none is invented for a set whose manifest has not arrived), so its growth is bounded
/// by the store's own chunk caps — `MeshChunkFormat.maxChunkCount` × `maxChunkPayloadBytes`, i.e.
/// 1024 × 256 KiB — and by ``MeshRoutedCapacity``, never by this row. That state is reachable on
/// purpose: a cap refusal **keeps** the parked bytes (the non-dropping arm), so an over-cap item's
/// chunks stay held for a build that loosens the cap, and expiry collects them if none does.
///
/// **Public since plan step A0.5.9 (S16)**, with its columns and its memberwise initializer: a host
/// declares the routed types its features carry as these rows (``ProximityHost/meshRoutedTypeEntries``),
/// and every rule above binds a host's row exactly as it binds a resident one. The registry that
/// accepts or drops a row, and every door that reads one, stay the engine's.
public nonisolated struct MeshRoutedTypeEntry: Equatable, Sendable {

    /// The frozen wire spelling this row declares for — the registry's key, from the host
    /// namespace's ``ProximityNamespace/RoutedTypes``.
    public let token: String

    /// The largest ciphertext an item of this type may claim, in bytes. Registerable only inside
    /// `1 … MeshRoutedManifestFormat.maxContentByteCount`: a row above the wire bound would be
    /// silently overridden by the mint's global guard, and a row of `0` would refuse every item of
    /// its type with no diagnostic.
    public let maxItemByteCount: UInt64

    /// How the mint derives the destination set. No receiver reads this column.
    public let destinations: MeshRoutedDestinationSemantics

    /// Who may hold and forward an item of this type before its destinations have it.
    public let relayRetention: MeshRoutedRelayRetention

    /// What makes an item of this type FINAL at a destination — item 4's stage, verbatim.
    public let finalAck: MeshRoutedAckStage

    /// When items of this type stop mattering.
    public let expiry: MeshRoutedExpiryRule

    /// How long this type's projected content lives on a destination. The projection reads it to
    /// decide whether an item's session liveness applies; the store is the registered handler's.
    public let contentScope: MeshRoutedContentScope

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
    ///   - contentScope: How long the type's projected content lives on a destination.
    public init(
        token: String,
        maxItemByteCount: UInt64,
        destinations: MeshRoutedDestinationSemantics,
        relayRetention: MeshRoutedRelayRetention,
        finalAck: MeshRoutedAckStage,
        expiry: MeshRoutedExpiryRule,
        contentScope: MeshRoutedContentScope
    ) {
        self.token = token
        self.maxItemByteCount = maxItemByteCount
        self.destinations = destinations
        self.relayRetention = relayRetention
        self.finalAck = finalAck
        self.expiry = expiry
        self.contentScope = contentScope
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
/// ``MeshRoutedTypeEntry/expiry`` are now read at a real mint. Since plan step A0.5.2 the
/// delivery projection reads ``MeshRoutedTypeEntry/contentScope`` (a `.session` row's items carry
/// the engine's session liveness) and looks the token's registered projection handler up: a row
/// names no store, and no `switch` over rows exists.
///
/// **The per-type cap has a RECEIVER since P6 item 3** (D-11.4). The photo row no longer sits at the
/// shared wire bound: it is the formula in the unit caveat above, which makes the manifest door's
/// check reachable for the first time — an over-cap manifest is refused as
/// ``MeshRoutedManifestRejection/sizeExceedsTypeCap`` at `MeshNetworkManager.ingestRoutedManifest`,
/// charged to the envelope sender like every pre-store refusal, and its parked chunk bytes are
/// **kept** (``MeshRoutedParkedDrop`` answers nil, because a cap is a number one build chose and a
/// later build may loosen it). The mint's own ``MeshRoutedManifestMintError/sizeExceedsTypeCap``
/// became reachable in the same commit. The remaining column ahead of a discriminating test is
/// ``MeshRoutedTypeEntry/expiry``, which still has one case (D-11.22).
///
/// **The bound a seal and an open take is the widest row** (plan step A0.5.4). The sealer states no
/// bound of its own: ``maxItemByteCount``, the widest accepted row, is the one number, which
/// `MeshNetworkManager` clamps from its host registry once, at `init`, and passes to the seal and
/// the open and reads at the projection's resident-blob guard — so the two ends the earlier note
/// promised to move together are one value, and the photo row's formula lives only in its row.
///
/// Shipping code names exactly one value, ``increment1(_:hostEntries:)`` — the engine's resident rows
/// and its host's (plan step A0.5.9) — and the resident rows by name, ``increment1Rows(_:)``, for the
/// token the manager's built-in photo handler registers under and its photo sender mints under; it
/// constructs a registry in exactly one file, reads a routed type off the namespace only where rows
/// are built (here, and in a host's own rows: FernletSocial's `FernletRoutedTypes.swift`), and
/// branches on no routed type token anywhere — three source-scan walls in
/// `MeshRoutedStoreIsolationTests` are what keep that true. A fixture registry is a test-only
/// affordance, reached through the manager's one `@testable` seam.
nonisolated struct MeshRoutedTypeRegistry: Equatable, Sendable {

    /// The most rows one registry holds. The SAME number as ``MeshRoutedAckStageTable/maxRows``,
    /// written here rather than read across: naming that member in this file would trip the
    /// one-table wall, under which shipping code names no `MeshRoutedAckStageTable` member at all
    /// (plan step A0.5.9). The equality is pinned by test, and this is the one constant item 11
    /// restates.
    static let maxEntries = 16

    /// The resolved rows, keyed by the frozen token.
    private let entries: [String: MeshRoutedTypeEntry]

    /// The widest ciphertext cap among the rows this registry accepted, in bytes, or 0 when it
    /// accepted none — the one resident bound (plan step A0.5.4).
    ///
    /// Stored, and set once in ``init(entries:)`` from the ACCEPTED rows, so a dropped row widens
    /// nothing. `MeshNetworkManager` clamps its host registry's value into an `Int` once, at its
    /// `init`, then passes it to the seal at the mint and to the open at the delivery door, and reads
    /// it at the projection's resident-blob guard — never a test's fixture registry's, so a narrowed
    /// or widened fixture moves no bound. For Fernlet's rows it is the photo row's cap, 10 551 337
    /// bytes. A registry with no row answers 0, which refuses every seal and every open: fail-closed.
    let maxItemByteCount: UInt64

    /// Builds a registry from declarations, first row winning for a repeated token.
    ///
    /// Three registerability predicates, all fail-closed: a dropped row's token answers nil at every
    /// door, which refuses it rather than admitting it under a policy this build does not implement.
    /// The widest accepted row's cap becomes ``maxItemByteCount``.
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
        // R2: bounded by the accepted rows, at most `maxEntries`.
        self.maxItemByteCount = resolved.values.map { $0.maxItemByteCount }.max() ?? 0
    }

    /// Plan §11's registered types, as the one registry shipping code names: the engine's resident
    /// rows (``increment1Rows(_:)``), in their order, then the host's (plan step A0.5.9, S16), through
    /// ``init(entries:)``'s rules — a repeated token's first row wins, so a host row never displaces a
    /// resident one; at most ``maxEntries`` rows are read; and a row the registerability predicates
    /// refuse is dropped. For Fernlet's rows the registry is the one the engine built before the
    /// temporary-message row left it: the host's row is that row, spelled as it was, and the registry
    /// is token-keyed, so the rows' order reaches no door and no byte.
    ///
    /// `MeshNetworkManager`'s `init` is the one shipping caller, with its host's
    /// ``ProximityHost/meshRoutedTypeEntries``. No default: a registry is never built without saying
    /// which host rows it holds.
    ///
    /// - Parameters:
    ///   - routedTypes: The routed types of the namespace the caller holds.
    ///   - hostEntries: The host's own rows.
    /// - Returns: The registry of the resident rows and the host's, under their tokens.
    static func increment1(
        _ routedTypes: ProximityNamespace.RoutedTypes, hostEntries: [MeshRoutedTypeEntry]
    ) -> MeshRoutedTypeRegistry {
        MeshRoutedTypeRegistry(entries: increment1Rows(routedTypes).rows + hostEntries)
    }

    /// The engine's resident rows by name (plan step A0.5.2): the photo row, which stays the engine's
    /// until the photo feature leaves it (plan step A0.5.11), each column defined AS the constant or
    /// decision already shipped, and its token read off the routed types it is handed: this module
    /// spells no routed type of its own. The temporary-message row left with chat at plan step A0.5.9
    /// and the heart row with the session hearts at plan step A0.5.10; both are the host's now
    /// (FernletSocial's `FernletRoutedTypes`).
    ///
    /// ``increment1(_:hostEntries:)`` builds the registry from these rows and the host's.
    /// `MeshNetworkManager` also holds them by name, for the two per-row reads the registry cannot
    /// answer: the token its built-in projection handler registers under, and the token its photo
    /// sender mints under — behind its `isRoutedTypeRegistered(_:)`, so a build whose registry lost a
    /// row mints nothing for it.
    ///
    /// ``ProximityNamespace/RoutedTypes/control`` is deliberately absent: plan §11 names an
    /// `immediate` stage but neither §11 nor §12 routes a control item, and registering a token
    /// nothing mints would open a door with no handler behind it.
    ///
    /// - Parameter routedTypes: The routed types of the namespace the caller holds.
    /// - Returns: The photo row under its token.
    static func increment1Rows(_ routedTypes: ProximityNamespace.RoutedTypes) -> MeshRoutedResidentRows {
        MeshRoutedResidentRows(
            // The photo row is the FIRST narrowed cap (P6 item 3, D-11.4), and it is narrowed to a
            // formula rather than a number: `PrivateMediaStore.maxIncomingPhotoBytes` (the photo
            // wall's PLAINTEXT bound) plus `MeshRoutedItemBodyFormat.maxFramedHeaderByteCount` plus the
            // seal's own overhead — i.e. the widest CIPHERTEXT a routed photo can measure, 10 551 337 B.
            // Each term is read from the type that owns it, never copied. The formula was the seal
            // file's resident bound until plan step A0.5.4 moved it here: the bound is now the
            // registry's widest row, which this row is, so the manifest door's check and the
            // projection's resident-blob guard are the same number and cannot drift; see the unit
            // caveat on `MeshRoutedTypeEntry`.
            photo: MeshRoutedTypeEntry(
                token: routedTypes.photo,
                maxItemByteCount: UInt64(
                    PrivateMediaStore.maxIncomingPhotoBytes
                        + MeshRoutedItemBodyFormat.maxFramedHeaderByteCount
                        + MeshRoutedItemSealFormat.overheadByteCount
                ),
                destinations: .fullRosterAtCreation,
                relayRetention: .originRetainsUntilDeparture,
                finalAck: .durableRecipientStorage,
                expiry: .meshHardDeadlinePlusGrace,
                contentScope: .persistent
            )
        )
    }

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

// MARK: - MeshRoutedResidentRows

/// The engine's resident routed rows by name — the photo row
/// ``MeshRoutedTypeRegistry/increment1Rows(_:)`` declares (plan step A0.5.2; the temporary-message
/// row left for the host's rows at plan step A0.5.9, the heart row at plan step A0.5.10).
///
/// The registry is keyed by token and answers "is this token known, and under which policy"; this
/// says which token is the photo row's, which is what its sender needs to mint and its built-in
/// handler needs to register. A value, never a second registry: `MeshNetworkManager` still admits,
/// resolves and forwards by its registry alone, and asks it whether a row is registered before it
/// mints under that row's token. The row names its own token, so a registry holding a second row
/// shaped like the photo row does not change which token the photo sender mints under or which row
/// the photo handler projects.
nonisolated struct MeshRoutedResidentRows: Equatable, Sendable {
    /// The routed photo row.
    let photo: MeshRoutedTypeEntry

    /// The resident rows in their declaration order — the photo row alone — which is the order
    /// ``MeshRoutedTypeRegistry/increment1(_:hostEntries:)`` registers them in, before the host's.
    var rows: [MeshRoutedTypeEntry] { [photo] }
}
