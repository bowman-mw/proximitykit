// MeshRoutedProjectionHandler.swift
// ProximityKit/Mesh
//
// ProximityKit plan step A0.5.2 (seam S9): the routed projection handler — the contract through which
// a host's feature writes one routed type's plaintext into its own canonical store, while the engine
// keeps every guard, the one decrypt and the order.
//
// The split is the engine's on purpose. A handler is asked three things and decides nothing else:
// whether its row's items may be enumerated for projection right now, what it makes of an item
// BEFORE anything is decrypted (from the facts the delivery carries, never from plaintext), and —
// once per item, behind the engine's whole guard chain and the engine's open — what its canonical
// write makes of the opened body. The privacy-wipe refusal, the two access predicates, the registry
// row, the projected set, the ledger-resolved author with its removal and block legs, the resident
// bound, the blob read, the open with its `mesh.routedProjection.openFailed` line, and the retry-list
// marks all stay at the engine's call site, in their order; a handler never sees a decrypt door.
//
// Not here: the engine's token-keyed lookup and the box a handler is stored in
// (`MeshNetworkManager.registerRoutedProjectionHandler(_:forToken:)`), the one generic opener
// (`MeshRoutedItemDelivery.openBody`), and the verdict and liveness vocabularies, which stay beside
// the delivery door they were born at.

import Foundation

// MARK: - MeshRoutedBody

/// A routed item body a projection handler can be handed: decodable from the plaintext the engine's
/// one open produces, and carrying the item id the origin signed (plan step A0.5.2, S9).
///
/// The engine decodes the body itself: its one opener calls ``init(decoding:)`` on the opened
/// plaintext and then refuses a body whose ``routedItemID`` is not the manifest's item id, so a
/// conformer states only how its bytes decode and which of its fields is the item id.
///
/// The contract: ``init(decoding:)`` throws on any shape it refuses and never traps, and a framing
/// it cannot read throws the engine's ``MeshRoutedItemSealError/malformed``, so the engine's
/// `mesh.routedProjection.openFailed` line spells every family's refusal the same way.
/// ``routedItemID`` is the id inside the body's own header — the one the origin's signed manifest
/// must name. Bodies are values, so the protocol is `nonisolated` and `Sendable`.
public nonisolated protocol MeshRoutedBody: Sendable {

    /// Decodes one opened routed item's plaintext.
    ///
    /// - Parameter plaintext: The bytes the engine's open produced, un-decoded.
    /// - Throws: Whatever the body's framing refuses, by name. Never a trap.
    init(decoding plaintext: Data) throws

    /// The item id inside the body's own header, which must equal the id the origin signed.
    var routedItemID: UUID { get }
}

// MARK: - MeshRoutedProjectionHandler

/// A host feature's writer for one routed type's plaintext: the engine asks it, per item, whether to
/// open, and hands it the opened body to write (plan step A0.5.2, S9).
///
/// Registered under one routed type token with
/// ``MeshNetworkManager/registerRoutedProjectionHandler(_:forToken:)``, which stores nothing and
/// answers `false` for a token whose registry row is unknown or is a judge row (a row whose final
/// ack is the foreground decrypt and ledger commit: its plaintext pass is its ack ceremony, never a
/// projection).
///
/// **The engine's order, which a handler cannot change.** For each item the delivery door or the
/// re-entry pass offers, the engine runs the privacy-wipe refusal, the decrypt predicate, the
/// registry row, the projected set, the admission ledger's author with its removal and block
/// refusals, the resident bound, the mutation predicate and the blob read; then it looks the handler
/// up (none, or a judge row: one `mesh.routedProjection.noDispatchArm` line and
/// ``MeshRoutedProjectionVerdict/refusedForNow``), builds the ``MeshRoutedDelivery``, asks
/// ``verdictBeforeOpen(_:)``, opens the blob as ``Body`` through its one opener (any failure: one
/// `mesh.routedProjection.openFailed` line and ``MeshRoutedProjectionVerdict/refusedForGood``), and
/// only then calls ``projectRoutedItem(_:delivery:)``. The verdict answered decides the engine's
/// retry-list marks.
///
/// **The contract for a conformer.** ``verdictBeforeOpen(_:)`` reads no decrypted state and writes
/// nothing but its own audit line. ``projectRoutedItem(_:delivery:)`` is called at most once per
/// item per pass, never re-entrantly, and only after the mutation predicate held. Neither computes a
/// session liveness of its own: the delivery carries the engine's. A handler is registered before
/// the first re-entry pass can run — in practice while its manager is being built — and the manager
/// holds it strongly for its own lifetime, so a handler that needs the manager holds it `unowned` or
/// `weak`.
///
/// Main-actor, like the pass that calls it; `AnyObject`, because a handler is an object the engine
/// retains.
@MainActor public protocol MeshRoutedProjectionHandler: AnyObject {

    /// The body this handler's routed type decodes to.
    associatedtype Body: MeshRoutedBody

    /// Whether this handler's row may be enumerated for projection right now (R-19): items the
    /// handler would refuse anyway must not occupy slots of the pass's bounded allowance.
    ///
    /// Read each time the engine enumerates the projection's retry list, never per item.
    var isProjectable: Bool { get }

    /// What the handler makes of one item after its blob is read and before anything is decrypted.
    ///
    /// - Parameter delivery: The item's signed facts and the engine's resolution of them.
    /// - Returns: nil to have the engine open the item, or the verdict to answer without opening it.
    func verdictBeforeOpen(_ delivery: MeshRoutedDelivery) -> MeshRoutedProjectionVerdict?

    /// The canonical-store write for one opened item, behind the engine's whole guard chain and its
    /// one open.
    ///
    /// - Parameters:
    ///   - body: The body the engine opened, decoded and checked against the signed item id.
    ///   - delivery: The same delivery ``verdictBeforeOpen(_:)`` was handed.
    /// - Returns: whether the item still owes the projection anything.
    func projectRoutedItem(_ body: Body, delivery: MeshRoutedDelivery) -> MeshRoutedProjectionVerdict
}

// MARK: - MeshRoutedAuthor

/// The author of one routed item, as this device's admission ledger resolves the origin's signed
/// fingerprint (plan step A0.5.2, S9).
///
/// Never a claim the body makes: a routed body carries no identity, so the fingerprint and the
/// signing key come from the manifest's signed origin and the ledger's admission for it — the set
/// that admitted the item, admissions minus removals — with this device's block list already
/// applied. Public as a field of ``MeshRoutedDelivery``; only the engine builds one.
public nonisolated struct MeshRoutedAuthor: Equatable, Sendable {
    /// The origin's fingerprint, as the manifest signed it.
    public let fingerprint: String
    /// The origin's Ed25519 signing public key, from the admission ledger.
    public let signingPublicKey: Data
}

// MARK: - MeshRoutedDelivery

/// One routed item as the engine hands it to a projection handler: the facts the origin signed and
/// the engine's resolution of them, never plaintext (plan step A0.5.2, S9).
///
/// Built only by the engine, after its guard chain and before the handler's
/// ``MeshRoutedProjectionHandler/verdictBeforeOpen(_:)``; the same value then reaches
/// ``MeshRoutedProjectionHandler/projectRoutedItem(_:delivery:)``. Every field is either inside the
/// origin's signature (the type token, the item, the mesh and the origin) or a fact this device
/// derived once for the item: the ledger's author, the instant it first saw the item, the per-origin
/// budget key, and — for a `.session` row only — whether the item may still enter the session this
/// device is showing.
public nonisolated struct MeshRoutedDelivery: Sendable {
    /// The routed type token the origin signed.
    public let typeToken: String
    /// The item's id, as the manifest signed it.
    public let itemID: UUID
    /// The mesh the item was minted in, as the manifest signed it.
    public let meshID: UUID
    /// The origin's fingerprint, as the manifest signed it.
    public let originFingerprint: String
    /// The admission ledger's resolution of the origin.
    public let author: MeshRoutedAuthor
    /// When this device first saw the item: the index's `firstSeenAt` on the re-entry pass, the
    /// delivery door's own instant when the item has just become complete. Never a handler's clock.
    public let seenAt: Date
    /// The per-`(mesh, origin)` budget key the item is counted against: the item's own signed mesh,
    /// never the live one.
    public let quotaKey: MeshRoutedOriginQuotaKey
    /// For a row whose content scope is `.session`, whether the item may still enter the session
    /// this device is showing, computed by the engine for this pass; nil for every other row.
    public let sessionLiveness: MeshTranscriptLiveness?

    /// Builds the delivery the engine hands a handler for one item.
    ///
    /// - Parameters:
    ///   - manifest: The origin's signed manifest.
    ///   - author: The admission ledger's resolution of its origin.
    ///   - seenAt: When this device first saw the item.
    ///   - sessionLiveness: The engine's liveness for a `.session` row, nil for any other.
    init(
        manifest: MeshRoutedManifest,
        author: MeshRoutedAuthor,
        seenAt: Date,
        sessionLiveness: MeshTranscriptLiveness?
    ) {
        typeToken = manifest.typeToken
        itemID = manifest.itemID
        meshID = manifest.meshID
        originFingerprint = manifest.originFingerprint
        self.author = author
        self.seenAt = seenAt
        quotaKey = MeshRoutedOriginQuotaKey(manifest)
        self.sessionLiveness = sessionLiveness
    }
}
