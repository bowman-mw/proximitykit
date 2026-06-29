// IdentityService.swift
// Fernlet/Proximity
//
// Per-device Ed25519 signing identity + X25519 key-agreement for proximity sessions.
// Keys are split by purpose:
//   signingPrivateKey        — Ed25519, ThisDeviceOnly, never synced
//   keyAgreementPrivateKey   — X25519, ThisDeviceOnly, never synced (proximity transport only)
//   backupEscrowPrivateKey   — X25519, synchronizable (iCloud Keychain), used only for sealedBackupKey()

import Foundation
import FernletFoundation
import CryptoKit
import Security
import FernletDomainModel

// MARK: - Keychain key identifiers

private enum IdentityKeychainKey: String {
    case signingPrivateKey          = "signingPrivateKey"
    case keyAgreementPrivateKey     = "keyAgreementPrivateKey"
    case signingPublicKeyCache      = "signingPublicKeyCache"
    case keyAgreementPublicKeyCache = "keyAgreementPublicKeyCache"
    case backupEscrowPrivateKey     = "backupEscrowPrivateKey"
}

// MARK: - Errors

public enum IdentityError: Error, Equatable {
    case notProvisioned
    case invalidKeyData
    case sealFailed
    case openFailed
}

// MARK: - IdentityService

@MainActor
public final class IdentityService {

    public let keychainService: String

    private var signingKey: Curve25519.Signing.PrivateKey?
    private var keyAgreementKey: Curve25519.KeyAgreement.PrivateKey?
    private var backupEscrowKey: Curve25519.KeyAgreement.PrivateKey?

    public init(keychainService: String = "com.fernlet.identity") {
        self.keychainService = keychainService
    }

    // MARK: - Public surface

    public var localFingerprint: String {
        guard let key = signingKey else { return "" }
        return Self.fingerprint(of: key.publicKey.rawRepresentation)
    }

    public var localSigningPublicKey: Data {
        signingKey?.publicKey.rawRepresentation ?? Data()
    }

    public var localKeyAgreementPublicKey: Data {
        keyAgreementKey?.publicKey.rawRepresentation ?? Data()
    }

    /// The PUBLIC half of the backup-escrow key. Unlike the proximity key-agreement public key, the
    /// escrow key is synchronized via iCloud Keychain, so this value is STABLE across a user's devices.
    /// That is what lets a sealed-backup record sealed on one device be recognized as "mine" and
    /// restored on another (the proximity KA key is regenerated per device and must NOT bind backups).
    public var localBackupEscrowPublicKey: Data {
        backupEscrowKey?.publicKey.rawRepresentation ?? Data()
    }

    public func sign(_ data: Data) throws -> Data {
        guard let key = signingKey else { throw IdentityError.notProvisioned }
        return try key.signature(for: data)
    }

    /// Sealed-backup key derivation. ACCEPTED TRADE-OFF (explicit): backups are AES-GCM'd under a
    /// STATIC key — HKDF-SHA256(backupEscrowPrivateKey) with empty salt and fixed info, no ECDH and no
    /// ephemeral material — so there is NO forward secrecy. A single escrow-key compromise decrypts ALL
    /// past and future backups. This is intentional for a single-user, private-DB, recoverable-by-design
    /// backup: the escrow key itself is protected by iCloud Keychain end-to-end encryption, and a stable
    /// (non-ephemeral) key is what makes cross-device restore possible. Optional future hardening: mix a
    /// random per-generation salt (stored in the head chunk) into the HKDF to bound blast radius per backup.
    public func sealedBackupKey() throws -> SymmetricKey {
        guard let backupEscrowKey else { throw IdentityError.notProvisioned }
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: backupEscrowKey.rawRepresentation),
            salt: Data(),
            info: Data("com.fernlet.sealed-backup".utf8),
            outputByteCount: 32
        )
    }

    // WI-9: the three pure crypto statics below are `nonisolated` — they read no instance/actor state
    // (only their parameters + CryptoKit), so signature verification and fingerprinting can run off the
    // main actor. Required by the `nonisolated` `MeshAdmissionToken.verify` and the off-main verify path.
    public nonisolated static func verify(_ signature: Data, of data: Data, by publicKeyData: Data) -> Bool {
        guard let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData) else { return false }
        return publicKey.isValidSignature(signature, for: data)
    }

    /// X25519 ECDH → HKDF-SHA256 → ChaCha20-Poly1305 seal with forward secrecy.
    /// Wire form: ephemeralPubKey (32 B) || sealedBox.combined (nonce 12 B || ciphertext || tag 16 B).
    public func seal(_ plaintext: Data, to peerKeyAgreementPublicKey: Data) throws -> Data {
        guard let senderKey = keyAgreementKey else { throw IdentityError.notProvisioned }
        guard let peerPubKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerKeyAgreementPublicKey) else {
            throw IdentityError.sealFailed
        }

        let ephemeralKey = Curve25519.KeyAgreement.PrivateKey()
        let sharedSecret = try ephemeralKey.sharedSecretFromKeyAgreement(with: peerPubKey)
        let symKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data("fernlet.proximity.v1".utf8),
            sharedInfo: senderKey.publicKey.rawRepresentation + peerKeyAgreementPublicKey,
            outputByteCount: 32
        )

        let sealedBox = try ChaChaPoly.seal(
            plaintext,
            using: symKey,
            authenticating: senderKey.publicKey.rawRepresentation
        )
        return ephemeralKey.publicKey.rawRepresentation + sealedBox.combined
    }

    /// Inverse of seal. `peerKeyAgreementPublicKey` is the sender's long-term X25519 public key.
    public func open(_ ciphertext: Data, from peerKeyAgreementPublicKey: Data) throws -> Data {
        guard let recipientKey = keyAgreementKey else { throw IdentityError.notProvisioned }
        // Wire format: eskPub (32 B) || combined (nonce 12 B || ciphertext || tag 16 B)
        guard ciphertext.count >= 32 + 12 + 16 else { throw IdentityError.openFailed }

        let eskPubData = ciphertext.prefix(32)
        let combined = ciphertext.dropFirst(32)

        guard let ephemeralPeerPubKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: eskPubData) else {
            throw IdentityError.openFailed
        }
        let sharedSecret = try recipientKey.sharedSecretFromKeyAgreement(with: ephemeralPeerPubKey)
        let symKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data("fernlet.proximity.v1".utf8),
            sharedInfo: peerKeyAgreementPublicKey + recipientKey.publicKey.rawRepresentation,
            outputByteCount: 32
        )

        do {
            let sealedBox = try ChaChaPoly.SealedBox(combined: combined)
            return try ChaChaPoly.open(sealedBox, using: symKey, authenticating: peerKeyAgreementPublicKey)
        } catch {
            throw IdentityError.openFailed
        }
    }

    // MARK: - Group key distribution (Phase 3)

    /// Wraps a 32-byte group key for one recipient using ephemeral X25519 ECDH → HKDF-SHA256 → AES-256-GCM.
    /// Wire form: ephemeralPubKey (32 B) || nonce (12 B) || ciphertext (32 B) || tag (16 B) = 92 B total.
    public func encryptGroupKey(_ key: Data, for recipientPublicKey: Data) throws -> Data {
        guard key.count == 32 else { throw IdentityError.sealFailed }
        guard let recipientKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipientPublicKey) else {
            throw IdentityError.sealFailed
        }
        let ephemeralKey = Curve25519.KeyAgreement.PrivateKey()
        let sharedSecret = try ephemeralKey.sharedSecretFromKeyAgreement(with: recipientKey)
        let symKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data("fernlet.mesh.groupkey.v1".utf8),
            sharedInfo: ephemeralKey.publicKey.rawRepresentation + recipientPublicKey,
            outputByteCount: 32
        )
        let gcmNonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(key, using: symKey, nonce: gcmNonce)

        var bundle = Data()
        bundle.append(ephemeralKey.publicKey.rawRepresentation)          // 32 B
        gcmNonce.withUnsafeBytes { bundle.append(contentsOf: $0) }      // 12 B
        bundle.append(sealedBox.ciphertext)                              // 32 B
        bundle.append(sealedBox.tag)                                     // 16 B
        return bundle
    }

    /// Unwraps a group key bundle produced by `encryptGroupKey`.
    public func decryptGroupKey(_ bundle: Data) throws -> Data {
        guard let recipientKey = keyAgreementKey else { throw IdentityError.notProvisioned }
        guard bundle.count == 92 else { throw IdentityError.openFailed }

        let ephPubData     = bundle[bundle.startIndex ..< bundle.startIndex + 32]
        let nonceData      = bundle[bundle.startIndex + 32 ..< bundle.startIndex + 44]
        let ciphertextData = bundle[bundle.startIndex + 44 ..< bundle.startIndex + 76]
        let tagData        = bundle[bundle.startIndex + 76 ..< bundle.startIndex + 92]

        guard let ephemeralPubKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephPubData) else {
            throw IdentityError.openFailed
        }
        let sharedSecret = try recipientKey.sharedSecretFromKeyAgreement(with: ephemeralPubKey)
        let recipientPublicKey = recipientKey.publicKey.rawRepresentation
        let symKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data("fernlet.mesh.groupkey.v1".utf8),
            sharedInfo: Data(ephPubData) + recipientPublicKey,
            outputByteCount: 32
        )

        do {
            let nonce = try AES.GCM.Nonce(data: nonceData)
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertextData, tag: tagData)
            return try AES.GCM.open(sealedBox, using: symKey)
        } catch {
            throw IdentityError.openFailed
        }
    }

    // MARK: - Provisioning

    /// Bootstrap on first launch. Idempotent — returns the existing identity if already provisioned.
    ///
    /// Key separation: the proximity KA key is ThisDeviceOnly (never syncs); the backup escrow key
    /// is synchronizable so it can be recovered on another device. On existing installs the KA key
    /// is migrated to device-only and a fresh backup escrow key is generated if absent.
    public func ensureProvisioned() throws {
        if signingKey != nil && keyAgreementKey != nil && backupEscrowKey != nil { return }

        let deviceOnly = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as CFString

        // Case 1: Signing + proximity KA keys present on this device (normal relaunch).
        if let sigData = KeychainItem.load(account: IdentityKeychainKey.signingPrivateKey.rawValue, service: keychainService),
           let kaData  = KeychainItem.load(account: IdentityKeychainKey.keyAgreementPrivateKey.rawValue, service: keychainService),
           let loadedSigning = try? Curve25519.Signing.PrivateKey(rawRepresentation: sigData),
           let loadedKA      = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: kaData) {

            signingKey      = loadedSigning
            keyAgreementKey = loadedKA

            // Ensure backup escrow key exists (generated on first run post-migration).
            if let escrowData = KeychainItem.load(account: IdentityKeychainKey.backupEscrowPrivateKey.rawValue, service: keychainService),
               let loadedEscrow = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: escrowData) {
                backupEscrowKey = loadedEscrow
            } else {
                let newEscrow = Curve25519.KeyAgreement.PrivateKey()
                KeychainItem.store(newEscrow.rawRepresentation,
                                   account: IdentityKeychainKey.backupEscrowPrivateKey.rawValue,
                                   service: keychainService,
                                   accessibility: kSecAttrAccessibleAfterFirstUnlock,
                                   synchronizable: true)
                backupEscrowKey = newEscrow
            }

            // Migrate proximity KA key to device-only (removes synchronizable flag if set).
            KeychainItem.store(loadedKA.rawRepresentation,
                               account: IdentityKeychainKey.keyAgreementPrivateKey.rawValue,
                               service: keychainService,
                               accessibility: deviceOnly,
                               synchronizable: false)
            return
        }

        // Case 2: Backup escrow key synced from iCloud (new device install, post-migration).
        // Generate fresh signing + proximity KA keys; adopt the synced backup escrow key.
        //
        // KNOWN RESIDUAL (not fixed here): the cross-device restore enabled by escrow-binding SILENTLY
        // DEPENDS on the synchronizable escrow key having already synced via iCloud Keychain before a
        // fresh device first provisions. If provisioning races ahead of the sync, this Case-2 load misses
        // and Case-1's "generate if absent" branch mints a DIVERGENT escrow key — which strands restore
        // (backups were sealed under the other key) and can later conflict with the incoming synced key.
        if let escrowData = KeychainItem.load(account: IdentityKeychainKey.backupEscrowPrivateKey.rawValue, service: keychainService),
           let loadedEscrow = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: escrowData) {
            let newSigning = Curve25519.Signing.PrivateKey()
            let newKA      = Curve25519.KeyAgreement.PrivateKey()
            KeychainItem.store(newSigning.rawRepresentation,
                               account: IdentityKeychainKey.signingPrivateKey.rawValue,
                               service: keychainService, accessibility: deviceOnly)
            KeychainItem.store(newSigning.publicKey.rawRepresentation,
                               account: IdentityKeychainKey.signingPublicKeyCache.rawValue,
                               service: keychainService, accessibility: deviceOnly)
            KeychainItem.store(newKA.rawRepresentation,
                               account: IdentityKeychainKey.keyAgreementPrivateKey.rawValue,
                               service: keychainService, accessibility: deviceOnly)
            KeychainItem.store(newKA.publicKey.rawRepresentation,
                               account: IdentityKeychainKey.keyAgreementPublicKeyCache.rawValue,
                               service: keychainService, accessibility: deviceOnly)
            signingKey      = newSigning
            keyAgreementKey = newKA
            backupEscrowKey = loadedEscrow
            return
        }

        // Case 3: Legacy synced KA key present (pre-migration second-device path).
        // Promote the old KA key to backup escrow role; generate fresh device-only identity.
        if let kaData = KeychainItem.load(account: IdentityKeychainKey.keyAgreementPrivateKey.rawValue, service: keychainService),
           let loadedKA = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: kaData) {
            let newSigning = Curve25519.Signing.PrivateKey()
            let newKA      = Curve25519.KeyAgreement.PrivateKey()
            KeychainItem.store(loadedKA.rawRepresentation,
                               account: IdentityKeychainKey.backupEscrowPrivateKey.rawValue,
                               service: keychainService,
                               accessibility: kSecAttrAccessibleAfterFirstUnlock,
                               synchronizable: true)
            KeychainItem.store(newSigning.rawRepresentation,
                               account: IdentityKeychainKey.signingPrivateKey.rawValue,
                               service: keychainService, accessibility: deviceOnly)
            KeychainItem.store(newSigning.publicKey.rawRepresentation,
                               account: IdentityKeychainKey.signingPublicKeyCache.rawValue,
                               service: keychainService, accessibility: deviceOnly)
            KeychainItem.store(newKA.rawRepresentation,
                               account: IdentityKeychainKey.keyAgreementPrivateKey.rawValue,
                               service: keychainService, accessibility: deviceOnly)
            KeychainItem.store(newKA.publicKey.rawRepresentation,
                               account: IdentityKeychainKey.keyAgreementPublicKeyCache.rawValue,
                               service: keychainService, accessibility: deviceOnly)
            signingKey      = newSigning
            keyAgreementKey = newKA
            backupEscrowKey = loadedKA
            return
        }

        // Case 4: No keys at all — generate a complete fresh identity.
        let newSigning = Curve25519.Signing.PrivateKey()
        let newKA      = Curve25519.KeyAgreement.PrivateKey()
        let newEscrow  = Curve25519.KeyAgreement.PrivateKey()
        KeychainItem.store(newSigning.rawRepresentation,
                           account: IdentityKeychainKey.signingPrivateKey.rawValue,
                           service: keychainService, accessibility: deviceOnly)
        KeychainItem.store(newKA.rawRepresentation,
                           account: IdentityKeychainKey.keyAgreementPrivateKey.rawValue,
                           service: keychainService, accessibility: deviceOnly)
        KeychainItem.store(newEscrow.rawRepresentation,
                           account: IdentityKeychainKey.backupEscrowPrivateKey.rawValue,
                           service: keychainService,
                           accessibility: kSecAttrAccessibleAfterFirstUnlock,
                           synchronizable: true)
        KeychainItem.store(newSigning.publicKey.rawRepresentation,
                           account: IdentityKeychainKey.signingPublicKeyCache.rawValue,
                           service: keychainService, accessibility: deviceOnly)
        KeychainItem.store(newKA.publicKey.rawRepresentation,
                           account: IdentityKeychainKey.keyAgreementPublicKeyCache.rawValue,
                           service: keychainService, accessibility: deviceOnly)
        signingKey      = newSigning
        keyAgreementKey = newKA
        backupEscrowKey = newEscrow
    }

    /// Wipes identity. Breaks every existing trust relationship.
    public func wipe() throws {
        KeychainItem.deleteAll(service: keychainService)
        signingKey = nil
        keyAgreementKey = nil
        backupEscrowKey = nil
    }

    /// 16-char lowercase hex prefix of SHA-256(publicKey). Suitable for user-facing display.
    public nonisolated static func fingerprint(of publicKey: Data) -> String {
        let hash = SHA256.hash(data: publicKey)
        let hex = hash.compactMap { String(format: "%02x", $0) }.joined()
        return String(hex.prefix(16))
    }

    /// Matches canonical 16-char fingerprints and legacy 8-char values stored by older builds.
    /// Fingerprints remain display and routing metadata only; authorization uses full key bytes.
    public nonisolated static func fingerprintsMatch(_ first: String, _ second: String) -> Bool {
        let lhs = first.lowercased()
        let rhs = second.lowercased()
        guard [8, 16].contains(lhs.count), [8, 16].contains(rhs.count) else { return false }
        return lhs.hasPrefix(rhs) || rhs.hasPrefix(lhs)
    }
}
