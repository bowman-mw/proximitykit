// MeshRoutedItemSeal.swift
// ProximityKit/Mesh
//
// Network migration P5 item 13 (plan §11, invariant §3.3): the ITEM seal — the reserved half of the
// pair whose wrap half item 1 shipped.
//
// Item 1 wraps a random content key per recipient; this file is what that key opens. A routed
// item's payload is sealed once, with AES-256-GCM under `AEAD.meshRoutedItemV1`, and the mesh, item,
// origin and TYPE TOKEN ride in the authenticated data. Branch and epoch therefore decide nothing:
// the same blob opens for every destination the origin wrapped for, in either half of a split,
// which is exactly what lets item 13 DELETE the three `keyEpoch` gates rather than loosen them.
//
// The blob is SELF-CONTAINED, as item 2's C12 freeze requires: the nonce and the tag live inside it,
// because the manifest carries no nonce field, and `contentHash` + `size` measure the complete
// blob — marker included. Nothing in the authenticated data derives from the blob, so the seal
// precedes the hash and the freeze holds verbatim.
//
// Not here: any key agreement (item 1's wrapper owns the private-key half), any store, clock,
// actor, envelope or identity — and no size bound of its own. The sealer is a pure function of the
// bytes and the bound handed to it, which is what keeps it outside every locked-device gate wall —
// the predicate is consulted by the delivery door that CALLS this, never by the primitive. Since
// plan step A0.5.4 the largest blob is the caller's `maxBlobByteCount`: the manager's resident
// bound, its host registry's widest routed row, held once at its `init`. So this file states no
// feature's payload size and imports no `PrivateMediaStore`; the photo row's formula lives with the
// row, in its host's rows (Fernlet's: FernletSocial's `FernletRoutedTypes.swift`, since plan step
// A0.5.11; ProximityKit's registry file from A0.5.4).

import CryptoKit
import Foundation

// MARK: - MeshRoutedItemSealFormat

/// The routed item blob's fixed widths.
///
/// The layout is `marker(5) ‖ nonce(12) ‖ ciphertext(N) ‖ tag(16)`, so a sealed blob is always
/// `overheadByteCount + N` bytes and that total is what ``MeshRoutedManifest/size`` claims and
/// ``MeshRoutedContentDigest/contentHash(of:in:)`` measures.
///
/// **One number bounds both ends** (D-13.19), and since plan step A0.5.4 it is the caller's, not
/// this type's: the seal refuses a plaintext whose length plus ``overheadByteCount`` exceeds the
/// `maxBlobByteCount` it is handed, and the open refuses a blob above the same value, so the seal
/// refuses exactly what the open would refuse. `MeshNetworkManager` hands both ends — and its
/// projection's resident-blob guard reads — one value: its host registry's widest routed row, held
/// once at its `init`. Deriving the write bound from the 256 MiB wire cap instead would let an
/// origin mint an item every recipient custodies, receipts and then refuses to open — and because
/// the photo stage is final on durable **ciphertext**, that receipt is already minted when the open
/// refuses, so the origin would read `delivered` for an item no wall can ever hold.
///
/// Public for ``overheadByteCount`` alone, the term a host's routed row adds to its body's bound to
/// state the row's ciphertext cap; the marker and the widths stay the sealer's own.
public nonisolated enum MeshRoutedItemSealFormat {

    /// The cleartext format tag every routed blob begins with: ASCII `FMRI1`.
    ///
    /// A frozen wire token, never localized. Five ASCII bytes in the clear is the `FMA2` / `FMGP2` /
    /// `FMGM2` idiom: a future v2 is tellable apart without a key, and an unmarked blob is refused
    /// **by name** (``MeshRoutedItemSealError/retiredOrForeignFormat``) instead of joining the
    /// silent-drop pile. It prefixes, and is prefixed by, none of the three.
    ///
    /// Deliberately **not** in the authenticated data: a routed blob is hash-committed by a signed
    /// manifest, so a flipped marker fails `contentHash` at assembly before any key is unwrapped.
    static let marker = Data("FMRI1".utf8)

    /// ``marker``'s width.
    static let markerByteCount = 5

    /// AES-GCM nonce width, shared with the wrap family so the two cannot drift apart.
    static let nonceByteCount = MeshRoutedManifestFormat.nonceByteCount

    /// GCM tag width.
    static let tagByteCount = 16

    /// What a seal adds to its plaintext: marker + nonce + tag = 33 bytes. Named because item 9's
    /// byte caps count the **blob**, not the payload.
    ///
    /// The contract: every sealed blob is exactly its plaintext's length plus this, so a routed
    /// type's ciphertext cap is its body's widest plaintext plus this number, written as that sum
    /// rather than a literal, and the seal takes a plaintext exactly when its length plus this is
    /// within the caller's `maxBlobByteCount`. Frozen with the blob layout.
    public static let overheadByteCount = markerByteCount + nonceByteCount + tagByteCount
}

// MARK: - MeshRoutedItemSealError

/// Why a routed item could not be sealed or opened. Not `LocalizedError`; frozen English
/// diagnostics, never user copy (the ``MeshRoutedKeyWrapError`` idiom).
///
/// Public so a host's routed body throws the engine's own refusal: a body whose framing does not
/// parse throws ``malformed``, never a raw `DecodingError`, so `String(describing:)` of the error in
/// the routed open-failure audit lines stays one frozen vocabulary whoever defined the body. The
/// cases are frozen tokens; none is ever shown.
public nonisolated enum MeshRoutedItemSealError: Error, Equatable, Sendable {
    /// The plaintext is empty. A routed item with no payload is a manifest, not an item.
    case emptyPlaintext
    /// The plaintext would seal to a blob larger than the caller's `maxBlobByteCount` — its length
    /// plus ``MeshRoutedItemSealFormat/overheadByteCount`` exceeds the bound — refused at the MINT,
    /// so no recipient ever receipts an item it could not open (D-13.19).
    case plaintextTooLarge(byteCount: Int)
    /// The content key is not 32 bytes.
    case invalidContentKey
    /// The blob does not begin with ``MeshRoutedItemSealFormat/marker`` — a retired format, another
    /// family's blob, or bytes that are not a routed item at all.
    case retiredOrForeignFormat
    /// The framing does not parse: a blob shorter than one byte of ciphertext under a full seal, a
    /// body whose header length prefix runs past the bytes that carry it, or an in-bounds header
    /// slice that is not this family's JSON. The third is CAUGHT at each body's `init(decoding:)`
    /// (the host's: FernletSocial's photo, text and heart bodies) rather than propagated, so one
    /// frozen vocabulary covers the whole framing and no raw `DecodingError` reaches a routed audit
    /// line.
    case malformed
    /// The blob is larger than the caller's `maxBlobByteCount`, the resident bound. Refused
    /// **before** any plaintext is allocated.
    case blobTooLargeToOpen(byteCount: Int)
    /// The AEAD refused — a wrong key, a moved blob, or tampered bytes. One token for all three on
    /// purpose: distinguishing them would be an oracle.
    case openFailed

    /// Frozen English for the diagnostic surface. Never shown as user copy.
    var diagnosticDescription: String {
        switch self {
        case .emptyPlaintext: return "A routed item's plaintext is empty."
        case .plaintextTooLarge(let byteCount):
            return "A routed item's plaintext is \(byteCount) bytes, above the seal bound."
        case .invalidContentKey: return "The content key is not 32 bytes."
        case .retiredOrForeignFormat: return "The blob does not carry the routed item format marker."
        case .malformed: return "A routed item's framing was malformed."
        case .blobTooLargeToOpen(let byteCount):
            return "A routed item's blob is \(byteCount) bytes, above the resident bound."
        case .openFailed: return "The routed item did not open."
        }
    }
}

// MARK: - MeshRoutedItemSealer

/// The routed item's own seal and its inverse — AES-256-GCM under `AEAD.meshRoutedItemV1`, with the
/// manifest binding and the routed type token in the authenticated data.
///
/// Four fields are authenticated and each earns its place: the **purpose**, which stops the blob
/// opening under any other AEAD domain at a shared key; **meshID + itemID + origin**, the transplant
/// proof — a blob lifted into another `(mesh, item, origin)` triple fails the tag even if its wrap
/// travels with it; and the **type token**, the one field the wrap does not carry, because the
/// receiver dispatches the plaintext on `manifest.typeToken` into a canonical store and "these bytes
/// are a photo" should be authenticated by the same tag as the bytes.
///
/// `contentHash` and `size` are deliberately **absent**: both are functions of the sealed blob, so
/// binding either would be circular (C12 — the seal precedes the hash), and both are already covered
/// by the origin's signature over the manifest. The **recipient** is absent too: one key, N wraps,
/// one blob is the whole point of the routed path.
///
/// Pure and `nonisolated`: no actor, no clock, no I/O, no identity. The locked-device predicate is
/// consulted by the delivery door that calls this, never here.
nonisolated enum MeshRoutedItemSealer {

    /// Seals one routed item's plaintext under its own content key.
    ///
    /// Order is fixed: non-empty, then the bound — the blob this plaintext would seal to, against
    /// `maxBlobByteCount`, the **same number** the open enforces — then the key width, then the
    /// primitive. The nonce is minted inside, per item, never injected and never derived: a 256-bit
    /// single-use content key separates nothing further than the authenticated data already does.
    ///
    /// - Parameters:
    ///   - maxBlobByteCount: The largest blob the caller will produce: `MeshNetworkManager`'s
    ///     resident bound, its host registry's widest routed row (plan step A0.5.4), with no default.
    ///   - purposes: The caller's namespace labels, whose `aead.meshRoutedItemV1` fronts the
    ///     authenticated data (plan step A0.2.6), with no default.
    /// - Returns: `marker ‖ nonce ‖ ciphertext ‖ tag` — the complete blob a manifest measures.
    static func seal(
        _ plaintext: Data,
        contentKey: Data,
        binding: MeshRoutedWrapBinding,
        typeToken: String,
        maxBlobByteCount: Int,
        in purposes: ProximityNamespace.Purposes
    ) throws -> Data {
        let key = try validatedPlaintext(plaintext, contentKey: contentKey, maxBlobByteCount: maxBlobByteCount)
        let aad = additionalData(binding: binding, typeToken: typeToken, in: purposes)
        let sealedBox = try AES.GCM.seal(plaintext, using: key, authenticating: aad)
        // AAD: purposes.aead.meshRoutedItemV1 ‖ binding ‖ typeToken.
        // `combined` is rebuilt from the parts rather than read as an Optional (Power of 10 R5).
        return MeshRoutedItemSealFormat.marker
            + Data(sealedBox.nonce) + sealedBox.ciphertext + sealedBox.tag
    }

    /// Opens a routed item's blob with the content key its wrap yielded.
    ///
    /// Order is fixed: marker, minimum width, resident bound (**before** any plaintext is
    /// allocated), then the primitive. Every AEAD refusal collapses to
    /// ``MeshRoutedItemSealError/openFailed``.
    ///
    /// - Parameters:
    ///   - maxBlobByteCount: The largest blob the caller will open — the resident bound, the same
    ///     value it seals under (plan step A0.5.4), with no default.
    ///   - purposes: The caller's namespace labels, whose `aead.meshRoutedItemV1` fronts the
    ///     authenticated data (plan step A0.2.6), with no default.
    static func open(
        _ blob: Data,
        contentKey: Data,
        binding: MeshRoutedWrapBinding,
        typeToken: String,
        maxBlobByteCount: Int,
        in purposes: ProximityNamespace.Purposes
    ) throws -> Data {
        try validateBlobShape(blob, maxBlobByteCount: maxBlobByteCount)
        let key = SymmetricKey(data: contentKey)
        let aad = additionalData(binding: binding, typeToken: typeToken, in: purposes)
        do {
            let combined = blob.dropFirst(MeshRoutedItemSealFormat.markerByteCount)
            let sealedBox = try AES.GCM.SealedBox(combined: combined)
            return try AES.GCM.open(sealedBox, using: key, authenticating: aad)
            // AAD: purposes.aead.meshRoutedItemV1 ‖ binding ‖ typeToken.
        } catch {
            throw MeshRoutedItemSealError.openFailed
        }
    }

    /// The authenticated data: `AEAD.meshRoutedItemV1.data ‖ meshID ‖ itemID ‖ lp(origin) ‖ lp(typeToken)`.
    ///
    /// Byte for byte ``MeshRoutedContentKeyWrapper/additionalData(binding:recipientFingerprint:in:)``
    /// with the type token in the recipient's slot: the purpose is a raw prefix, as in every other
    /// authenticated-data blob in the tree, and the four binding fields are written with
    /// ``CanonicalByteWriter`` so the layout is unambiguous by length prefix. Frozen wire-bearing
    /// bytes, pinned by an independently derived golden. The purpose is the host namespace's
    /// `purposes.aead.meshRoutedItemV1` (plan step A0.2.6).
    static func additionalData(
        binding: MeshRoutedWrapBinding, typeToken: String, in purposes: ProximityNamespace.Purposes
    ) -> Data {
        var writer = CanonicalByteWriter()
        writer.appendUUID(binding.meshID)
        writer.appendUUID(binding.itemID)
        writer.appendString(binding.originFingerprint)
        writer.appendString(typeToken)
        return purposes.aead.meshRoutedItemV1.data + writer.bytes
    }

    /// The seal's guard chain, returning the key it validated (the `MeshChunker.validated(…)`
    /// idiom — one place, so no door into the mint skips it).
    ///
    /// The bound is compared as the blob the plaintext would seal to, `plaintext.count +
    /// overheadByteCount`, against `maxBlobByteCount`, never as the plaintext against the bound less
    /// the overhead: no subtraction, so a bound below the overhead — a host that registered no
    /// routed row holds 0 — refuses every plaintext rather than reaching a negative or trapping
    /// bound (plan step A0.5.4).
    private static func validatedPlaintext(
        _ plaintext: Data, contentKey: Data, maxBlobByteCount: Int
    ) throws -> SymmetricKey {
        guard !plaintext.isEmpty else { throw MeshRoutedItemSealError.emptyPlaintext }
        guard plaintext.count + MeshRoutedItemSealFormat.overheadByteCount <= maxBlobByteCount else {
            throw MeshRoutedItemSealError.plaintextTooLarge(byteCount: plaintext.count)
        }
        guard contentKey.count == MeshRoutedManifestFormat.contentKeyByteCount else {
            throw MeshRoutedItemSealError.invalidContentKey
        }
        return SymmetricKey(data: contentKey)
    }

    /// The open's shape chain: format tag, then the widths, in that order — the marker first so a
    /// foreign or retired blob is named rather than reported as a generic malformation, the
    /// caller's `maxBlobByteCount` last (a bound of 0, a host with no routed row, refuses every blob).
    private static func validateBlobShape(_ blob: Data, maxBlobByteCount: Int) throws {
        guard blob.starts(with: MeshRoutedItemSealFormat.marker) else {
            throw MeshRoutedItemSealError.retiredOrForeignFormat
        }
        guard blob.count > MeshRoutedItemSealFormat.overheadByteCount else {
            throw MeshRoutedItemSealError.malformed
        }
        guard blob.count <= maxBlobByteCount else {
            throw MeshRoutedItemSealError.blobTooLargeToOpen(byteCount: blob.count)
        }
    }
}
