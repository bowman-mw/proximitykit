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
    /// Key separation: the proximity KA key is ThisDeviceOnly (never syncs); the backup escrow key is
    /// synchronizable so it can be recovered on another device.
    ///
    /// WS-1 (escrow-race fix): provisioning generates ONLY the signing + proximity KA keys. The backup
    /// escrow key is NEVER minted here — it is adopted if one is already present (synced in via iCloud
    /// Keychain, or promoted on a prior launch) and otherwise left absent, to be minted lazily the first
    /// time the user actually enables a sealed backup (`provisionBackupEscrowKeyForSealing`). This kills
    /// the original race where a fresh second device, opened before the genuine escrow key had synced,
    /// minted a DIVERGENT synchronizable key — stranding cross-device restore and risking a key conflict.
    /// The open/restore path must never mint (see `loadBackupEscrowKeyForOpen`).
    public func ensureProvisioned() throws {
        if signingKey != nil && keyAgreementKey != nil { return }

        let deviceOnly = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as CFString

        // Case 1: Signing + proximity KA keys present on this device (normal relaunch).
        if let sigData = KeychainItem.load(account: IdentityKeychainKey.signingPrivateKey.rawValue, service: keychainService),
           let kaData  = KeychainItem.load(account: IdentityKeychainKey.keyAgreementPrivateKey.rawValue, service: keychainService),
           let loadedSigning = try? Curve25519.Signing.PrivateKey(rawRepresentation: sigData),
           let loadedKA      = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: kaData) {

            signingKey      = loadedSigning
            keyAgreementKey = loadedKA

            // Adopt an existing backup escrow key if one is present (synced preferred). Do NOT mint one
            // here — escrow generation is deferred to sealed-backup-enable time (WS-1).
            backupEscrowKey = loadExistingEscrowKey()

            // Migrate proximity KA key to device-only (removes synchronizable flag if set).
            KeychainItem.store(loadedKA.rawRepresentation,
                               account: IdentityKeychainKey.keyAgreementPrivateKey.rawValue,
                               service: keychainService,
                               accessibility: deviceOnly,
                               synchronizable: false)
            return
        }

        // Case 2: Backup escrow key synced from iCloud (new device install, post-migration).
        // Generate fresh signing + proximity KA keys; adopt the synced backup escrow key. With WS-1's
        // deferral the previous "race mints a divergent key" residual is gone: a fresh device that opens
        // before the escrow key syncs simply has no escrow key (Case 4) until enable time, and the
        // open/restore path treats absence as "not synced yet" rather than fabricating a new key.
        if let loadedEscrow = loadExistingEscrowKey() {
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
        // Promote the old (already-synced) KA key to backup escrow role; generate fresh device-only
        // identity. This reuses an existing synced key, not a fresh mint, so there is no divergence risk.
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

        // Case 4: No keys at all — generate signing + proximity KA only. The escrow key is deferred to
        // enable time (WS-1), so a fresh device never publishes a divergent synchronizable escrow key.
        let newSigning = Curve25519.Signing.PrivateKey()
        let newKA      = Curve25519.KeyAgreement.PrivateKey()
        KeychainItem.store(newSigning.rawRepresentation,
                           account: IdentityKeychainKey.signingPrivateKey.rawValue,
                           service: keychainService, accessibility: deviceOnly)
        KeychainItem.store(newKA.rawRepresentation,
                           account: IdentityKeychainKey.keyAgreementPrivateKey.rawValue,
                           service: keychainService, accessibility: deviceOnly)
        KeychainItem.store(newSigning.publicKey.rawRepresentation,
                           account: IdentityKeychainKey.signingPublicKeyCache.rawValue,
                           service: keychainService, accessibility: deviceOnly)
        KeychainItem.store(newKA.publicKey.rawRepresentation,
                           account: IdentityKeychainKey.keyAgreementPublicKeyCache.rawValue,
                           service: keychainService, accessibility: deviceOnly)
        signingKey      = newSigning
        keyAgreementKey = newKA
        backupEscrowKey = nil
    }

    // MARK: - Backup escrow key lifecycle (WS-1/WS-2/WS-3)

    /// Outcome of `reconcileBackupEscrowKey`. Each case is a NON-SILENT, audited resolution of the states
    /// that deferred (WS-1) / ThisDeviceOnly (WS-2) escrow minting can leave across a user's devices.
    public enum BackupEscrowReconcileOutcome: Equatable {
        /// No escrow material anywhere — sealed backup was never enabled on any synced device yet.
        case noEscrow
        /// A synced (authoritative) key is present and adopted.
        case usingSynced
        /// A device-only minted key was published (promoted) to `synchronizable` for cross-device restore.
        case promotedLocal
        /// A synced key DIFFERS from this device's local minted key — a real conflict. Not auto-resolved;
        /// the caller must surface a user choice (WS-3).
        case conflict
    }

    /// Loads the backup-escrow private key already present in the keychain, preferring the iCloud-synced
    /// item over a device-only one. Returns nil if no escrow key exists. NEVER mints — the open/restore
    /// path relies on this so a missing key surfaces as "not synced yet", never a divergent new identity.
    private func loadExistingEscrowKey() -> Curve25519.KeyAgreement.PrivateKey? {
        let account = IdentityKeychainKey.backupEscrowPrivateKey.rawValue
        if let data = KeychainItem.load(account: account, service: keychainService, synchronizable: .synced),
           let key = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data) {
            return key
        }
        if let data = KeychainItem.load(account: account, service: keychainService, synchronizable: .local),
           let key = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data) {
            return key
        }
        return nil
    }

    /// SEAL/enable path. Ensures `backupEscrowKey` is set so a sealed backup can be produced, without
    /// stranding cross-device restore: re-queries the keychain for a synced (or already-minted local)
    /// escrow key first and adopts it; only when none exists does it mint one — and that fresh key is
    /// stored `ThisDeviceOnly` (WS-2), never published as `synchronizable` until a later launch confirms
    /// no conflicting synced key has appeared (`reconcileBackupEscrowKey`). Returns the escrow public key.
    @discardableResult
    public func provisionBackupEscrowKeyForSealing() -> Data {
        if backupEscrowKey == nil { backupEscrowKey = loadExistingEscrowKey() }
        if backupEscrowKey == nil {
            let minted = Curve25519.KeyAgreement.PrivateKey()
            KeychainItem.store(minted.rawRepresentation,
                               account: IdentityKeychainKey.backupEscrowPrivateKey.rawValue,
                               service: keychainService,
                               accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                               synchronizable: false)
            backupEscrowKey = minted
            FernletAuditLog.log("identity.escrow.mintedLocal")
        }
        return backupEscrowKey?.publicKey.rawRepresentation ?? Data()
    }

    /// OPEN/restore path. Loads an existing escrow key (synced preferred) into memory; NEVER mints.
    /// Returns whether a key is present — `false` means "not synced yet", which the restore flow surfaces
    /// as a retryable state (WS-4) rather than fabricating a new identity.
    @discardableResult
    public func loadBackupEscrowKeyForOpen() -> Bool {
        if backupEscrowKey == nil { backupEscrowKey = loadExistingEscrowKey() }
        return backupEscrowKey != nil
    }

    /// Launch-time reconciliation of the backup-escrow key across iCloud Keychain (WS-3). Resolves, NON-
    /// SILENTLY, the states that deferred/ThisDeviceOnly minting can leave behind:
    /// - a synced key present → adopt it (authoritative); tidy a redundant identical local copy.
    /// - only a local minted key present → publish (promote) it to `synchronizable` so a future device
    ///   can restore. This runs at launch, necessarily a DIFFERENT launch than the one that minted the
    ///   key (the user enables a backup mid-session, after this has already run), honoring WS-2's
    ///   "promote only on a later launch once no conflicting synced key has appeared".
    /// - a synced key that DIFFERS from the local minted key → a genuine cross-device conflict. Do NOT
    ///   overwrite either side; return `.conflict` so the caller can surface a user choice and let the
    ///   user adopt the authoritative key + re-upload. Every branch is audited.
    ///
    /// MECHANISM (now confirmed from Apple's open-source `SecItemDataSource.c` conflict resolver +
    /// patents US9077759B2 / US9479583B2): two `synchronizable` items sharing service+account are ONE
    /// logical slot account-wide, and iCloud Keychain resolves a divergence by **newest
    /// `kSecAttrModificationDate` wins** (deterministic SHA-1-digest tiebreak only on an exact date tie).
    /// There is no coexistence of two values and no app-visible merge callback. IMPLICATION + RESIDUAL:
    /// because the genuine key is the OLDER write, withholding+promoting a fresh key (WS-2) *reduces* the
    /// chance a divergent key ever reaches the synced slot — on the common path the genuine key has synced
    /// in by the next launch and we adopt it here instead of promoting — but it does NOT *guarantee* the
    /// genuine key survives: if the genuine key is still in flight when a divergent local key is promoted,
    /// the divergent (newer) key wins and overwrites it cross-device. The real safety net is therefore the
    /// NON-SILENT `.conflict` surface here + WS-4's visible/retryable restore, not the timing of promotion.
    /// (Self-inflicted single-user race, mostly recoverable from the origin device; an attacker able to
    /// write this slot already holds the user's iCloud Keychain. Stronger-but-costlier fixes —
    /// content-derived/versioned slot, or a signed escrow envelope verified on read — are a tracked
    /// follow-up; they complicate the zero-config cross-device recovery this key exists to provide.)
    @discardableResult
    public func reconcileBackupEscrowKey() -> BackupEscrowReconcileOutcome {
        let account = IdentityKeychainKey.backupEscrowPrivateKey.rawValue
        let syncedData = KeychainItem.load(account: account, service: keychainService, synchronizable: .synced)
        let localData  = KeychainItem.load(account: account, service: keychainService, synchronizable: .local)

        switch (syncedData, localData) {
        case (nil, nil):
            return .noEscrow
        case let (synced?, local?):
            if synced == local {
                // Same key in both rows (e.g. we promoted earlier and the device-only copy lingers):
                // drop the redundant device-only copy and use the synced one.
                KeychainItem.delete(account: account, service: keychainService, synchronizable: .local)
                backupEscrowKey = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: synced)
                return .usingSynced
            }
            // Divergent keys — the worst case WS-2 guards against. Surface; never auto-resolve.
            FernletAuditLog.log("identity.escrow.conflictDetected")
            return .conflict
        case let (synced?, nil):
            backupEscrowKey = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: synced)
            return .usingSynced
        case let (nil, local?):
            // Promote our device-only key to synchronizable. Remove ONLY the local row (`replacing:
            // .local`) so a genuine key that syncs in between the check above and this store is not
            // clobbered by the implicit pre-delete.
            KeychainItem.store(local,
                               account: account,
                               service: keychainService,
                               accessibility: kSecAttrAccessibleAfterFirstUnlock,
                               synchronizable: true,
                               replacing: .local)
            backupEscrowKey = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: local)
            FernletAuditLog.log("identity.escrow.promotedLocal")
            return .promotedLocal
        }
    }

    /// WS-3 user-confirmed resolution of an escrow `.conflict`: adopt the synced (other-device) key as
    /// authoritative and discard this device's divergent local key. The caller MUST warn the user first
    /// and re-upload any device-local backups under the adopted key. Returns the adopted escrow public
    /// key, or nil if no synced key is present.
    @discardableResult
    public func adoptSyncedBackupEscrowKey() -> Data? {
        let account = IdentityKeychainKey.backupEscrowPrivateKey.rawValue
        guard let syncedData = KeychainItem.load(account: account, service: keychainService, synchronizable: .synced),
              let synced = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: syncedData) else {
            return nil
        }
        KeychainItem.delete(account: account, service: keychainService, synchronizable: .local)
        backupEscrowKey = synced
        FernletAuditLog.log("identity.escrow.adoptedSynced")
        return synced.publicKey.rawRepresentation
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
