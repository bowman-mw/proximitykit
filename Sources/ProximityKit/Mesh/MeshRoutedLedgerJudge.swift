// MeshRoutedLedgerJudge.swift
// ProximityKit/Mesh
//
// ProximityKit plan step A0.5.3 (seam S10): the routed ledger judge — the contract through which a
// host's feature commits one routed type's opened item to its own durable ledger, while the engine
// keeps every guard, the one decrypt, the order, the FINAL marks and the stage's evidence.
//
// The split is the engine's on purpose. A judge is asked three things and decides nothing else:
// whether the device-wide legs only it can read hold right now, whether it admits the author the
// engine resolved — before any byte of the item is read — and, once per ceremony, behind the
// engine's whole guard chain and the engine's open, whether its own durable ledger now stands
// behind THIS item. The ack door's stamp check, the stage predicate, the ledger-resolved author
// with its removal and block legs, the blob read, the open with its `mesh.routedHeart.openFailed`
// line, the `mesh.routedHeart.refused` marks and the `mesh.routedHeart.noJudgement` line all stay
// at the engine's call site, in their order. And the engine, never the judge, mints the stage's
// evidence from the judge's committed answer, bound to the judged item, so no module but this one
// can build evidence for any item at all.
//
// Not here: the engine's token-keyed lookup and the box a judge is stored in
// (`MeshNetworkManager.registerRoutedLedgerJudge(_:forToken:)`), the one generic opener
// (`MeshRoutedItemDelivery.openBody`), the delivery and author values a judge is handed (beside the
// projection handler they were born with), and the evidence itself (`MeshRoutedAckEvidence`), which
// stays internal beside the stage table it answers.

import Foundation

// MARK: - MeshRoutedLedgerJudge

/// A host feature's judge for one routed type whose final ack is a durable ledger commit: the
/// engine asks it whether it can judge right now and whether it admits an item's author, and hands
/// it the opened body to commit (plan step A0.5.3, S10).
///
/// Registered under one routed type token with
/// ``MeshNetworkManager/registerRoutedLedgerJudge(_:forToken:)``, which stores nothing and answers
/// `false` for a token whose registry row is unknown or is not a judge row (a row whose final ack is
/// the foreground decrypt and ledger commit — the one stage whose evidence the store cannot read for
/// itself).
///
/// **The engine's order, which a judge cannot change.** The ceremony runs as the ack door's
/// evidence, which the door resolves only for a delivery it accepts and a record it has not
/// stamped. Then: the stage predicate and ``isReadyToJudge``; the admission ledger's author, with its
/// removal and block refusals; ``admits(_:)``; the blob read; the open, as ``Body``, through the
/// engine's one opener; the ``MeshRoutedDelivery``, whose `seenAt` is read from the routed index only
/// after the open; and only then ``judgeRoutedItem(_:delivery:)``. A removed or blocked origin, a
/// refused admission and a body that will not open are FINAL: one `mesh.routedHeart.refused` line
/// names the reason (an open failure first writes one `mesh.routedHeart.openFailed` line) and the
/// item is marked, so it never spends an ack allowance slot again. A
/// ``MeshRoutedJudgement/committed`` answer is the only way the stage's evidence comes to exist —
/// the engine mints it, bound to the item; a ``MeshRoutedJudgement/notYet`` answer writes one
/// `mesh.routedHeart.noJudgement` line, mints nothing and marks nothing, so the item stays pending.
///
/// **The contract for a conformer.** ``isReadyToJudge`` and ``admits(_:)`` read and never write: no
/// audit line, no state. ``admits(_:)`` answers ``MeshRoutedAdmission/refusedForGood(reason:)`` only
/// for a refusal that re-derives from durable state, because the engine marks it FINAL in a
/// memory-only set. ``judgeRoutedItem(_:delivery:)`` is called at most once per item per ceremony,
/// never re-entrantly and never for a record whose delivery is already stamped; it answers
/// ``MeshRoutedJudgement/committed`` only when its own durable proof stands behind THIS item, and it
/// feeds any non-idempotent side effect of the commit on the item's first acceptance, above its own
/// proof guard, so a proof that is not ready yet loses nothing. A judge is registered before the
/// first re-entry pass can run — in practice right after its host builds the manager — and the manager
/// holds it strongly for its own lifetime, so a judge that needs the manager holds it `unowned` or
/// `weak`.
///
/// Main-actor, like the ceremony that calls it; `AnyObject`, because a judge is an object the engine
/// retains.
@MainActor public protocol MeshRoutedLedgerJudge: AnyObject {

    /// The body this judge's routed type decodes to.
    associatedtype Body: MeshRoutedBody

    /// Whether the device-wide legs only this judge can read hold right now (Fernlet's heart judge:
    /// nearby hearts are on, and its ledger has finished loading).
    ///
    /// ANDed after the engine's own stage predicate, which is read first: once per re-entry pass,
    /// for the filter that decides whether the row's items spend an allowance slot at all, and once
    /// per ceremony. Every leg must be reversible, because the engine treats `false` as "not yet":
    /// it marks nothing, and the item is judged the first time this answers `true` again.
    var isReadyToJudge: Bool { get }

    /// Whether this judge admits one item's author — asked after the engine resolved the author
    /// against the admission ledger, and before any byte of the item is read.
    ///
    /// - Parameter author: The origin as the admission ledger resolved it, with this device's block
    ///   list already applied.
    /// - Returns: ``MeshRoutedAdmission/admitted``, or the FINAL refusal with the frozen English
    ///   reason the engine's `mesh.routedHeart.refused` line names.
    func admits(_ author: MeshRoutedAuthor) -> MeshRoutedAdmission

    /// Commits one opened item to this judge's durable ledger, behind the engine's whole ceremony
    /// and its one open.
    ///
    /// - Parameters:
    ///   - body: The body the engine opened, decoded and checked against the signed item id.
    ///   - delivery: The item's signed facts and the engine's resolution of them. Its `seenAt` is
    ///     the routed index's first-seen instant for the item, or the manifest's creation instant
    ///     when the index cannot say.
    /// - Returns: ``MeshRoutedJudgement/committed`` only when this judge's own durable proof stands
    ///   behind this item, ``MeshRoutedJudgement/notYet`` otherwise.
    func judgeRoutedItem(_ body: Body, delivery: MeshRoutedDelivery) -> MeshRoutedJudgement
}

// MARK: - MeshRoutedAdmission

/// What a ledger judge makes of one item's author, before anything of the item is read (plan step
/// A0.5.3, S10).
///
/// The engine marks a refusal FINAL in a memory-only set and names its reason in one
/// `mesh.routedHeart.refused` line, so a judge refuses only for a reason that re-derives from durable
/// state, and the reason is a frozen English token, never copy.
public nonisolated enum MeshRoutedAdmission: Equatable, Sendable {
    /// The judge admits the author: the engine goes on to read and open the item.
    case admitted
    /// The judge refuses the author for a reason that cannot change; `reason` is the frozen English
    /// token the engine's audit line names (Fernlet's heart judge: `notAFriend`).
    case refusedForGood(reason: String)
}

// MARK: - MeshRoutedJudgement

/// What a ledger judge's commit made of one opened item (plan step A0.5.3, S10).
public nonisolated enum MeshRoutedJudgement: Equatable, Sendable {
    /// The judge's own durable ledger stands behind THIS item: the engine mints the stage's
    /// evidence, bound to the item, and the ack door may stamp the delivery.
    case committed
    /// No durable proof stands behind the item yet (Fernlet's heart judge: the ledger's cooldown, or
    /// a write that has not landed): the engine writes one `mesh.routedHeart.noJudgement` line,
    /// mints nothing and marks nothing, so the item stays pending and the next ceremony asks again.
    case notYet
}
