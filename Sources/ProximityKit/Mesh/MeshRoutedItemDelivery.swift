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

import CryptoKit
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
nonisolated struct MeshRoutedOriginQuotaKey: Hashable, Sendable {
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

    /// Opens one routed photo item and returns its body.
    ///
    /// - Parameters:
    ///   - blob: The reassembled ciphertext, already re-hashed against `manifest.contentHash` by
    ///     the store door that produced it.
    ///   - manifest: The origin's signed manifest — the binding, the wraps and the type token.
    ///   - identity: This device's identity, for the wrap's key agreement.
    ///   - mayDecryptRoutedContent: `MeshNetworkManager.mayDecryptRoutedContent`, passed in under
    ///     that exact spelling and guarded on as the first line of
    ///     ``openPlaintext(_:manifest:identity:mayDecryptRoutedContent:)``, the one choke point both
    ///     body families reach the ciphertext through. Never defaulted.
    /// - Returns: the decoded body.
    /// - Throws: ``MeshRoutedDeliveryError``, ``MeshRoutedKeyWrapError`` or
    ///   ``MeshRoutedItemSealError``. Never a trap.
    @MainActor
    static func openPhotoBody(
        _ blob: Data,
        manifest: MeshRoutedManifest,
        identity: IdentityService,
        mayDecryptRoutedContent: Bool
    ) throws -> MeshRoutedPhotoBody {
        let plaintext = try openPlaintext(
            blob, manifest: manifest, identity: identity,
            mayDecryptRoutedContent: mayDecryptRoutedContent
        )
        let body = try MeshRoutedPhotoBody(decoding: plaintext)
        guard body.header.id == manifest.itemID else {
            throw MeshRoutedDeliveryError.bodyIdentityMismatch
        }
        return body
    }

    /// Opens one routed text item and returns its body (P6 item 4).
    ///
    /// The id guard is copied from the photo door, not omitted, because text's id **is** a key:
    /// `SessionMessageStore` dedups on it and deliberately never forgets a dropped id, so a body
    /// carrying another member's message id would consume that id's dedup slot for the session.
    ///
    /// - Parameters:
    ///   - blob: The reassembled ciphertext, already re-hashed against `manifest.contentHash` by
    ///     the store door that produced it.
    ///   - manifest: The origin's signed manifest — the binding, the wraps and the type token.
    ///   - identity: This device's identity, for the wrap's key agreement.
    ///   - mayDecryptRoutedContent: `MeshNetworkManager.mayDecryptRoutedContent`, passed in under
    ///     that exact spelling and guarded on inside ``openPlaintext(_:manifest:identity:mayDecryptRoutedContent:)``.
    ///     Never defaulted.
    /// - Returns: the decoded body.
    /// - Throws: ``MeshRoutedDeliveryError``, ``MeshRoutedKeyWrapError`` or
    ///   ``MeshRoutedItemSealError``. Never a trap.
    @MainActor
    static func openTextBody(
        _ blob: Data,
        manifest: MeshRoutedManifest,
        identity: IdentityService,
        mayDecryptRoutedContent: Bool
    ) throws -> MeshRoutedTextBody {
        let plaintext = try openPlaintext(
            blob, manifest: manifest, identity: identity,
            mayDecryptRoutedContent: mayDecryptRoutedContent
        )
        let body = try MeshRoutedTextBody(decoding: plaintext)
        guard body.header.id == manifest.itemID else {
            throw MeshRoutedDeliveryError.bodyIdentityMismatch
        }
        return body
    }

    /// The wrap, the open and nothing else — the ONE choke point both body families reach the
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
    /// tag even if its wrap travels with it. The body's own id guard is the CALLER's, because it is
    /// the one step that differs per family.
    ///
    /// - Parameters:
    ///   - blob: The reassembled ciphertext.
    ///   - manifest: The origin's signed manifest.
    ///   - identity: This device's identity.
    ///   - mayDecryptRoutedContent: `MeshNetworkManager.mayDecryptRoutedContent`, the first guard.
    /// - Returns: the sealed item's plaintext, un-decoded.
    /// - Throws: ``MeshRoutedDeliveryError/notPermitted``, ``MeshRoutedDeliveryError/notAddressedToMe``,
    ///   or whatever the wrap and the seal refuse by name.
    @MainActor
    private static func openPlaintext(
        _ blob: Data,
        manifest: MeshRoutedManifest,
        identity: IdentityService,
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
            staticAgreement: identity.heartDropStaticAgreement(withEphemeralPublicKey:)
        )
        return try MeshRoutedItemSealer.open(
            blob, contentKey: contentKey, binding: binding, typeToken: manifest.typeToken
        )
    }
}

// MARK: - MeshRoutedProjectionVerdict

/// What a canonical-store arm made of one routed item's plaintext — and therefore whether the item
/// still owes the projection pass anything (P6 item 4; item 5's distinction, arriving early for the
/// cases item 4 creates).
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
nonisolated enum MeshRoutedProjectionVerdict: String, Equatable, Sendable {

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
/// Frozen English tokens; they name audit lines, never user copy.
nonisolated enum MeshTranscriptLiveness: String, Equatable, Sendable {

    /// This mesh, this generation, and the session has not ended.
    case live
    /// Another mesh, or a transcript that has been cleared since the item was first offered.
    case endedForGood
    /// The right mesh and the right generation, but the session has ended by one of the doors that
    /// can be un-ended.
    case notLiveRightNow
}
