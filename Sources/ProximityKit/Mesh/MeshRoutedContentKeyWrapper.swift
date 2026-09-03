// MeshRoutedContentKeyWrapper.swift
// ProximityKit/Mesh
//
// Network migration P5 item 1 (plan §11, invariant §3.3): the per-recipient content-key wrap and
// its inverse.
//
// Every routed item gets its own random content key, and that key is sealed once per destination
// to the destination's handshake-verified X25519 identity — ephemeral X25519 → HKDF-SHA256 under
// `KeyDerivation.meshRoutedContentKeyWrapV1` → AES-256-GCM under `AEAD.meshRoutedContentKeyWrapV1`.
// This is `IdentityService.encryptGroupKey` primitive for primitive, with the routed purposes and a
// binding-carrying AAD substituted: the mesh id, item id, origin and recipient are authenticated,
// so a wrap lifted out of one manifest cannot be opened under another and one relabelled to a
// different recipient cannot be opened by anyone.
//
// Unlike the group-key wrap this type is `nonisolated` and static. Wrapping needs public keys
// only. Unwrapping takes the recipient's static agreement as a closure into `IdentityService`
// (the `HeartDropSealer.open` shape), so the private key never enters this file and the identity
// key's keychain protection is never weakened for a background decrypt (walls: locked device).

import CryptoKit
import FernletCrypto
import Foundation

// MARK: - MeshRoutedWrapBinding

/// What a wrap is bound to besides its recipient: the manifest's identity. Part of the AEAD's
/// authenticated data (D5), so a wrap cannot be transplanted between manifests, meshes or origins.
nonisolated struct MeshRoutedWrapBinding: Equatable, Sendable {
    /// The mesh the manifest belongs to.
    let meshID: UUID
    /// The item the manifest describes.
    let itemID: UUID
    /// The manifest's origin.
    let originFingerprint: String

    /// Binds a wrap to one manifest's identity.
    init(meshID: UUID, itemID: UUID, originFingerprint: String) {
        self.meshID = meshID
        self.itemID = itemID
        self.originFingerprint = originFingerprint
    }
}

// MARK: - MeshRoutedKeyWrapError

/// Why a wrap could not be minted or opened. Not `LocalizedError`; frozen English diagnostics.
nonisolated enum MeshRoutedKeyWrapError: Error, Equatable, Sendable {
    /// The recipient's X25519 public key is not a valid 32-byte Curve25519 point.
    case invalidRecipientKey(fingerprint: String)
    /// The content key is not 32 bytes.
    case invalidContentKey
    /// The wrap's recipient is not this device; refused before any key agreement.
    case notAddressedToMe
    /// A field has the wrong width (``MeshRecipientKeyWrap/isWellFormed``).
    case malformed
    /// Key agreement, derivation or the AEAD refused — a wrong key, a moved wrap, or tampered bytes.
    /// One token for all three on purpose: distinguishing them would be an oracle.
    case openFailed

    /// Frozen English for the diagnostic surface. Never shown as user copy.
    var diagnosticDescription: String {
        switch self {
        case .invalidRecipientKey(let fingerprint):
            return "The key-agreement key for destination \(fingerprint) is not a valid X25519 point."
        case .invalidContentKey: return "The content key is not 32 bytes."
        case .notAddressedToMe: return "The key wrap is addressed to another member."
        case .malformed: return "A field in the key wrap was malformed."
        case .openFailed: return "The key wrap did not open."
        }
    }
}

// MARK: - MeshRoutedContentKeyWrapper

/// The per-recipient content-key wrap of plan §11 — ephemeral X25519 → HKDF-SHA256 under
/// `KeyDerivation.meshRoutedContentKeyWrapV1` → AES-256-GCM under `AEAD.meshRoutedContentKeyWrapV1`
/// with the manifest binding and recipient in the authenticated data — and its inverse.
///
/// Mirrors `IdentityService.encryptGroupKey` primitive for primitive with the routed purposes and a
/// binding-carrying AAD substituted; unlike the group-key wrap it is `nonisolated` and static: the
/// recipient's private key never enters this type — ``unwrap(_:binding:localFingerprint:localKeyAgreementPublicKey:staticAgreement:)``
/// takes the static-agreement closure (`IdentityService.heartDropStaticAgreement(withEphemeralPublicKey:)`),
/// the `HeartDropSealer.open` shape. Wrapping needs public keys only. Both directions name their
/// purposes at the primitive.
nonisolated enum MeshRoutedContentKeyWrapper {

    /// A fresh 32-byte content key from the platform CSPRNG (the `MeshSessionKeyStore` mint idiom —
    /// `UInt8.random(in:)` draws from `SystemRandomNumberGenerator`, the same source `SymmetricKey`
    /// uses; returned as `Data` so wrapping needs no pointer API). Minted BEFORE the item is sealed
    /// and hashed; the manifest is the last thing built.
    static func makeContentKey() -> Data {
        Data((0..<MeshRoutedManifestFormat.contentKeyByteCount).map { _ in
            UInt8.random(in: UInt8.min...UInt8.max)
        })
    }

    /// Seals `contentKey` (32 bytes) to one destination.
    ///
    /// One fresh X25519 ephemeral and one fresh GCM nonce per wrap (D4). The authenticated data is
    /// ``additionalData(binding:recipientFingerprint:)``.
    static func wrap(
        contentKey: Data,
        recipientFingerprint: String,
        recipientKeyAgreementPublicKey: Data,
        binding: MeshRoutedWrapBinding
    ) throws -> MeshRecipientKeyWrap {
        guard let recipientKey = try? Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: recipientKeyAgreementPublicKey
        ) else {
            throw MeshRoutedKeyWrapError.invalidRecipientKey(fingerprint: recipientFingerprint)
        }
        guard contentKey.count == MeshRoutedManifestFormat.contentKeyByteCount else {
            throw MeshRoutedKeyWrapError.invalidContentKey
        }
        let ephemeralKey = Curve25519.KeyAgreement.PrivateKey()
        let ephemeralPublicKey = ephemeralKey.publicKey.rawRepresentation
        let shared = try ephemeralKey.sharedSecretFromKeyAgreement(with: recipientKey)
        let kek = wrappingKey(
            shared: shared, ephemeralPublicKey: ephemeralPublicKey,
            recipientPublicKey: recipientKeyAgreementPublicKey
        )
        let gcmNonce = AES.GCM.Nonce()
        let aad = additionalData(binding: binding, recipientFingerprint: recipientFingerprint)
        let sealedBox = try AES.GCM.seal(contentKey, using: kek, nonce: gcmNonce, authenticating: aad)
        // AAD: FernletCryptoPurpose.AEAD.meshRoutedContentKeyWrapV1 ‖ binding ‖ recipient.
        return MeshRecipientKeyWrap(
            recipientFingerprint: recipientFingerprint,
            ephemeralPublicKey: ephemeralPublicKey,
            // R9: `AES.GCM.Nonce` is a `Sequence` of `UInt8`; no raw-pointer walk is needed.
            nonce: Data(gcmNonce),
            sealedKey: sealedBox.ciphertext + sealedBox.tag
        )
    }

    /// Opens a wrap addressed to this device. `staticAgreement` performs X25519 against the local
    /// static private key (which never leaves `IdentityService`); `localKeyAgreementPublicKey` is
    /// its public half (second KDF `sharedInfo` slot); `localFingerprint` must equal the wrap's
    /// recipient or nothing is attempted. Returns the 32-byte content key.
    ///
    /// Every CryptoKit refusal collapses to ``MeshRoutedKeyWrapError/openFailed`` (the
    /// `decryptGroupKey` idiom); the closure's own error propagates, so an unprovisioned identity
    /// reads as `IdentityError.notProvisioned` rather than as a failed open.
    static func unwrap(
        _ wrap: MeshRecipientKeyWrap,
        binding: MeshRoutedWrapBinding,
        localFingerprint: String,
        localKeyAgreementPublicKey: Data,
        staticAgreement: (Data) throws -> SharedSecret
    ) throws -> Data {
        guard wrap.recipientFingerprint == localFingerprint else { throw MeshRoutedKeyWrapError.notAddressedToMe }
        guard wrap.isWellFormed else { throw MeshRoutedKeyWrapError.malformed }
        let shared = try staticAgreement(wrap.ephemeralPublicKey)
        let kek = wrappingKey(
            shared: shared, ephemeralPublicKey: wrap.ephemeralPublicKey,
            recipientPublicKey: localKeyAgreementPublicKey
        )
        let ciphertext = wrap.sealedKey.prefix(MeshRoutedManifestFormat.contentKeyByteCount)
        let tag = wrap.sealedKey.suffix(
            MeshRoutedManifestFormat.sealedKeyByteCount - MeshRoutedManifestFormat.contentKeyByteCount
        )
        let aad = additionalData(binding: binding, recipientFingerprint: wrap.recipientFingerprint)
        do {
            let nonce = try AES.GCM.Nonce(data: wrap.nonce)
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
            return try AES.GCM.open(sealedBox, using: kek, authenticating: aad)
            // AAD: FernletCryptoPurpose.AEAD.meshRoutedContentKeyWrapV1 ‖ binding ‖ recipient.
        } catch {
            throw MeshRoutedKeyWrapError.openFailed
        }
    }

    /// The authenticated data: `AEAD.meshRoutedContentKeyWrapV1.data ‖ meshID ‖ itemID ‖ lp(origin) ‖ lp(recipient)`.
    ///
    /// The purpose is a raw prefix, as in every other AAD in the tree; the four binding fields are
    /// written with `CanonicalByteWriter` so the layout is unambiguous by length prefix. Frozen
    /// wire-bearing bytes, pinned by an independently derived golden.
    static func additionalData(binding: MeshRoutedWrapBinding, recipientFingerprint: String) -> Data {
        var writer = CanonicalByteWriter()
        writer.appendUUID(binding.meshID)
        writer.appendUUID(binding.itemID)
        writer.appendString(binding.originFingerprint)
        writer.appendString(recipientFingerprint)
        return FernletCryptoPurpose.AEAD.meshRoutedContentKeyWrapV1.data + writer.bytes
    }

    /// The single HKDF site: the X25519 shared secret → the AES-256 key-wrapping key, salted with
    /// the routed derivation purpose and bound to both public keys in `sharedInfo`.
    private static func wrappingKey(
        shared: SharedSecret,
        ephemeralPublicKey: Data,
        recipientPublicKey: Data
    ) -> SymmetricKey {
        shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: FernletCryptoPurpose.KeyDerivation.meshRoutedContentKeyWrapV1.data,
            sharedInfo: ephemeralPublicKey + recipientPublicKey,
            outputByteCount: MeshRoutedManifestFormat.contentKeyByteCount
        )
    }
}
