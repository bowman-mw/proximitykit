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
    ///     that exact spelling and guarded on as the first line. Never defaulted.
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
        let plaintext = try MeshRoutedItemSealer.open(
            blob, contentKey: contentKey, binding: binding, typeToken: manifest.typeToken
        )
        let body = try MeshRoutedPhotoBody(decoding: plaintext)
        guard body.header.id == manifest.itemID else {
            throw MeshRoutedDeliveryError.bodyIdentityMismatch
        }
        return body
    }
}
