// MeshRoutedItemDelivery.swift
// ProximityKit/Mesh
//
// Network migration P5 item 13 (plan §11, §12's photo bullet, §19.5): the ONE routed plaintext
// seam — unwrap the content key, open the item blob, decode the body.
//
// It lives in its own file for a reason the walls state from both sides. `MeshRoutedLockedDeviceTests`
// pins every occurrence of the qualified unwrap spelling to one home and requires that home to name
// the decrypt predicate; `theCustodyDoorsNameNoAccessGate` forbids the predicate everywhere under
// `Mesh/` EXCEPT a file that performs exactly this unwrap. So the unwrap, the open and the decode
// belong together here, and nowhere else — splitting them across two files would make the two walls
// mutually unsatisfiable.
//
// The predicate arrives as a PARAMETER, under its exact spelling, and is the first guard in the
// door (D-13.3, amended). Naming an identifier decoratively would satisfy the containment wall
// while the file that produces the plaintext never consulted the answer — the vacuity item 10
// argued against — and P6's text and heart callers land on this same seam. So the answer is passed
// in and guarded on, fail-closed, and the manager keeps its own outer guard: two ends of one fact.
//
// Not here: the access gate value itself (a decrypting file consults the manager's predicate, never
// `routedAccessGate`), any store, any canonical-store mutation, any clock. What comes out is a
// value; who may be TOLD about it is the manager's second predicate.

import Foundation

// MARK: - MeshRoutedDeliveryError

/// Why a routed item's plaintext could not be produced. Not `LocalizedError`; frozen English
/// diagnostics, never user copy (the ``MeshRoutedItemSealError`` idiom).
nonisolated enum MeshRoutedDeliveryError: Error, Equatable, Sendable {
    /// The locked-device predicate said no. The **first** guard in the door, so no key agreement,
    /// no open and no allocation happens on a locked, backgrounded or duressed device.
    case notPermitted
    /// The manifest names no key wrap for this device. A courier holding an item it is not a
    /// destination of reaches exactly this — and keeps its custody.
    case notAddressedToMe
    /// The body's own id is not the item id the origin signed. Refused rather than handed on: the
    /// friend-photo surface keys and dedups on the photo id, so a body carrying another sender's
    /// photo id would land in that row's dedup contest.
    case bodyIdentityMismatch

    /// Frozen English for the diagnostic surface. Never shown as user copy.
    var diagnosticDescription: String {
        switch self {
        case .notPermitted: return "Routed content may not be decrypted right now."
        case .notAddressedToMe: return "The routed item names no key wrap for this device."
        case .bodyIdentityMismatch: return "The routed body's id is not the item id the origin signed."
        }
    }
}

// MARK: - MeshRoutedOriginQuotaKey

/// The per-`(mesh, origin)` budget key the incoming routed photo quota is counted against
/// (P5 item 13, D-13.23).
///
/// Keyed on the **item's** mesh, taken from the origin's signed manifest, and never on the live
/// `currentMesh`. The legacy per-sender quota reset whenever the live mesh changed, which was sound
/// while the check always ran inside the session that produced the photo; on the routed path the
/// hand-off runs at any later access-gate edge — a lock/unlock cycle, a re-entry pass, a subsequent
/// mesh — and at each of those a live-mesh-keyed counter would hand one origin a fresh budget for
/// items it had already queued.
///
/// Public since plan step A0.5.2, as the type of ``MeshRoutedDelivery/quotaKey``, so a projection
/// handler keys its own per-origin budget by it; only the engine builds one, and its two fields stay
/// internal. The contract is its equality: two items share a key exactly when they share the signed
/// mesh and the signed origin.
public nonisolated struct MeshRoutedOriginQuotaKey: Hashable, Sendable {
    /// The mesh the item was minted in — inside the origin's signature.
    let meshID: UUID
    /// The item's author.
    let originFingerprint: String

    /// Builds the budget key one manifest is counted against.
    init(_ manifest: MeshRoutedManifest) {
        meshID = manifest.meshID
        originFingerprint = manifest.originFingerprint
    }
}

// MARK: - MeshRoutedItemDelivery

/// The routed path's one plaintext door: content key out of the manifest's wrap, item blob open,
/// body decoded (P5 item 13).
///
/// Every step is authenticated before the next runs. The wrap opens only for this device's
/// fingerprint and its own agreement key; the blob's authenticated data binds the mesh, the item,
/// the origin and the routed type token, so a blob lifted into another triple fails its tag even if
/// its wrap travels with it; and the decoded body's id must be the item id the origin signed.
///
/// Deliberately **not** a place where anything is stored, cached or handed on. It answers "what are
/// these bytes"; the manager decides whether a canonical store may be told, behind its own second
/// predicate.
nonisolated enum MeshRoutedItemDelivery {

    /// Opens one routed item as `Body` and returns its body — the one generic opener every
    /// projection handler's and every ledger judge's body is opened through (plan steps A0.5.2 and
    /// A0.5.3).
    ///
    /// The plaintext comes from
    /// ``openPlaintext(_:manifest:identity:maxBlobByteCount:mayDecryptRoutedContent:)``, whose first
    /// line is the decrypt guard; the body is decoded by its own
    /// ``MeshRoutedBody/init(decoding:)``; and its ``MeshRoutedBody/routedItemID`` must be the item id
    /// the origin signed. The id guard holds for every family because every family's id is a key:
    /// the friend-photo surface keys and dedups on the photo id, so a body carrying another sender's
    /// photo id would land in that row's dedup contest, and FernletSocial's `SessionMessageStore`
    /// dedups on the message id and deliberately never forgets a dropped one, so a body carrying
    /// another member's message id would consume that id's dedup slot for the session. For a heart it
    /// holds for the strongest of the three reasons: a heart's body id **is** the gift id
    /// FernletSocial's `ProximityHeartLedger` dedups on and its `MeshRoutedHeartAck` proves, so a body
    /// carrying another member's gift id would
    /// offer the ledger a judgement about someone else's heart under this origin's signature — the
    /// enforcement half of ``ProximityNamespace/RoutedTypes/heart``'s frozen `itemID == giftID`
    /// contract.
    ///
    /// - Parameters:
    ///   - bodyType: The body family to decode — the handler's ``MeshRoutedProjectionHandler/Body``
    ///     or the judge's ``MeshRoutedLedgerJudge/Body``.
    ///   - blob: The reassembled ciphertext, already re-hashed against `manifest.contentHash` by
    ///     the store door that produced it.
    ///   - manifest: The origin's signed manifest — the binding, the wraps and the type token.
    ///   - identity: This device's identity, for the wrap's key agreement.
    ///   - maxBlobByteCount: The largest blob the open takes: `MeshNetworkManager`'s resident bound,
    ///     its host registry's widest routed row held once at its `init` — the number its mint seals
    ///     under (plan step A0.5.4). Never defaulted.
    ///   - mayDecryptRoutedContent: `MeshNetworkManager.mayDecryptRoutedContent`, passed in under
    ///     that exact spelling and guarded on as the first line of
    ///     ``openPlaintext(_:manifest:identity:maxBlobByteCount:mayDecryptRoutedContent:)``, the one
    ///     choke point every body family reaches the ciphertext through. Never defaulted. A judge
    ///     row's stronger predicate (`mayCommitRoutedHeartLedgerJudgement`) is the manager's and is
    ///     consulted before this door is reached — a decrypt is not a ledger judgement.
    /// - Returns: the decoded body.
    /// - Throws: ``MeshRoutedDeliveryError``, ``MeshRoutedKeyWrapError`` or
    ///   ``MeshRoutedItemSealError``, or whatever the body's decode refuses. Never a trap.
    @MainActor
    static func openBody<Body: MeshRoutedBody>(
        _ bodyType: Body.Type,
        blob: Data,
        manifest: MeshRoutedManifest,
        identity: IdentityService,
        maxBlobByteCount: Int,
        mayDecryptRoutedContent: Bool
    ) throws -> Body {
        let plaintext = try openPlaintext(
            blob, manifest: manifest, identity: identity, maxBlobByteCount: maxBlobByteCount,
            mayDecryptRoutedContent: mayDecryptRoutedContent
        )
        let body = try bodyType.init(decoding: plaintext)
        guard body.routedItemID == manifest.itemID else {
            throw MeshRoutedDeliveryError.bodyIdentityMismatch
        }
        return body
    }

    /// The wrap, the open and nothing else — the ONE choke point all three body families reach the
    /// ciphertext through, and the one place the decrypt predicate is guarded (P6 item 4).
    ///
    /// **The structure is the enforcement here, and the wall cannot replace it.** W2's containment
    /// half (`expectPlaintextSeamsNameTheirPredicate`) is a whole-**file** `contains`: it asks that
    /// a file naming `MeshRoutedContentKeyWrapper.unwrap(` also contain the literal
    /// `guard mayDecryptRoutedContent`, so a second entry point in *this* file that skipped the
    /// guard would stay green on the substring the other one supplies. Extracting the unwrap into
    /// one function that guards first is what makes a skipping entry point unwritable rather than
    /// merely unwalled — and it is also what keeps W2's `unwrap(` / `open(` pins at 1 each as P6
    /// adds callers.
    ///
    /// Every step is authenticated before the next runs: the wrap opens only for this device's
    /// fingerprint and its own agreement key, and the blob's authenticated data binds the mesh, the
    /// item, the origin and the routed type token, so a blob lifted into another triple fails its
    /// tag even if its wrap travels with it. The body's decode and its id guard are the CALLER's,
    /// because they are the steps that differ per family: the generic
    /// ``openBody(_:blob:manifest:identity:maxBlobByteCount:mayDecryptRoutedContent:)`` applies both
    /// through ``MeshRoutedBody``, for all three families since plan step A0.5.3.
    ///
    /// - Parameters:
    ///   - blob: The reassembled ciphertext.
    ///   - manifest: The origin's signed manifest.
    ///   - identity: This device's identity. Since ProximityKit plan step A0.2.6 the wrap opens and
    ///     the blob is authenticated under its namespace's `purposes`, the labels it was minted under.
    ///   - maxBlobByteCount: The manager's resident bound, the largest blob the item open takes
    ///     (plan step A0.5.4).
    ///   - mayDecryptRoutedContent: `MeshNetworkManager.mayDecryptRoutedContent`, the first guard.
    /// - Returns: the sealed item's plaintext, un-decoded.
    /// - Throws: ``MeshRoutedDeliveryError/notPermitted``, ``MeshRoutedDeliveryError/notAddressedToMe``,
    ///   or whatever the wrap and the seal refuse by name.
    @MainActor
    private static func openPlaintext(
        _ blob: Data,
        manifest: MeshRoutedManifest,
        identity: IdentityService,
        maxBlobByteCount: Int,
        mayDecryptRoutedContent: Bool
    ) throws -> Data {
        guard mayDecryptRoutedContent else { throw MeshRoutedDeliveryError.notPermitted }
        let localFingerprint = identity.localFingerprint
        guard let wrap = manifest.keyWraps.first(where: {
            $0.recipientFingerprint == localFingerprint
        }) else { throw MeshRoutedDeliveryError.notAddressedToMe }
        let binding = MeshRoutedWrapBinding(
            meshID: manifest.meshID, itemID: manifest.itemID,
            originFingerprint: manifest.originFingerprint
        )
        let contentKey = try MeshRoutedContentKeyWrapper.unwrap(
            wrap,
            binding: binding,
            localFingerprint: localFingerprint,
            localKeyAgreementPublicKey: identity.localKeyAgreementPublicKey,
            staticAgreement: identity.staticKeyAgreement(withEphemeralPublicKey:),
            in: identity.purposes
        )
        return try MeshRoutedItemSealer.open(
            blob, contentKey: contentKey, binding: binding, typeToken: manifest.typeToken,
            maxBlobByteCount: maxBlobByteCount, in: identity.purposes
        )
    }
}

// MARK: - MeshRoutedProjectionVerdict

/// What a projection handler made of one routed item — and therefore whether the item still owes
/// the projection pass anything (P6 item 4; item 5's distinction, arriving early for the cases item
/// 4 creates).
///
/// The projection's retry list is `MeshRoutedIndex.itemsAwaitingLocalProjection`, ordered by
/// `MeshRoutedItemKey` — i.e. by origin fingerprint, a position an attacker chooses — and the
/// per-pass allowance is 16. So sixteen permanently-refusing items sorted first occupy the whole
/// pass at every rising access edge until expiry, for **both** arms, since they share one
/// allowance. A malformed text item costs its origin ~600 bytes. Marking a refusal that can never
/// change is therefore not bookkeeping, it is the only thing between ~10 KB and a permanent
/// projection outage.
///
/// The mark itself is `MeshNetworkManager.routedProjectedItems` — memory-only, wiped on a mesh
/// change — which is honest only because every `refusedForGood` verdict is **re-derivable from the
/// bytes plus durable local state**: a malformed body and an id mismatch are facts about
/// origin-signed bytes; a blocked or removed origin is the block list and the admission ledger,
/// both durable; a spent quota and an already-held id re-derive to the same answer; and a session
/// that ended re-derives as ended for as long as it stays ended.
///
/// Public since plan step A0.5.2, as the answer of a ``MeshRoutedProjectionHandler``'s two methods.
/// The contract a handler is held to is the paragraph above: it answers ``refusedForGood`` only for
/// a refusal that re-derives from the bytes plus durable local state, because the engine marks that
/// answer FINAL in a memory-only set, and ``refusedForNow`` keeps the item, its custody and its
/// place in the retry list. Frozen English raw values, never displayed.
public nonisolated enum MeshRoutedProjectionVerdict: String, Equatable, Sendable {

    /// The canonical store was told. Frozen English token, never displayed.
    case handedOn
    /// Refused for a reason that **cannot change**, so the item leaves the retry list.
    case refusedForGood
    /// Refused for a reason that may not hold at the next pass — a deferred store, or a session
    /// that is not live right now but whose mesh and transcript generation are still this one. The
    /// item keeps its place in the retry list and its custody.
    case refusedForNow

    /// Whether the projection should stop offering this item.
    var leavesTheRetryList: Bool { self != .refusedForNow }
}

// MARK: - MeshTranscriptLiveness

/// Whether a routed text item may enter the transcript a device is showing — and if not, whether
/// that can change (P6 item 4, plan §12).
///
/// Three states rather than a `Bool` because the two refusals are not the same fact. "This mesh is
/// gone, or the transcript was cleared since this item arrived" is monotone: a mesh a device has
/// left is never rejoined by a projection, and the generation counter never goes back, so the item
/// leaves the retry list. "The session is not live *right now*, in this mesh and this generation" is
/// reversible — `startSearching()` un-ends a session the five-minute give-up door ended — so
/// marking it would lose a message from a transcript that was never cleared.
///
/// Public since plan step A0.5.2, as ``MeshRoutedDelivery/sessionLiveness``: the engine computes it
/// for every item of a row whose content scope is `.session` — from the item's signed mesh, the
/// transcript generation the item was first offered in, and whether the session is live — and a
/// handler switches on it rather than computing a liveness of its own.
///
/// Frozen English tokens; they name audit lines, never user copy.
public nonisolated enum MeshTranscriptLiveness: String, Equatable, Sendable {

    /// This mesh, this generation, and the session has not ended.
    case live
    /// Another mesh, or a transcript that has been cleared since the item was first offered.
    case endedForGood
    /// The right mesh and the right generation, but the session has ended by one of the doors that
    /// can be un-ended.
    case notLiveRightNow
}
