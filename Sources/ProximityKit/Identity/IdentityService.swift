// IdentityService.swift
// Fernlet/Proximity
//
// Per-device Ed25519 signing identity + X25519 key-agreement for proximity sessions.
// Keys are split by purpose:
//   signingPrivateKey        — Ed25519, ThisDeviceOnly, never synced
//   keyAgreementPrivateKey   — X25519, ThisDeviceOnly, never synced (proximity transport only)
//   backupEscrowPrivateKey.k.<sha256(pub)> — X25519, synchronizable (iCloud Keychain), used only for
//        sealedBackupKey(). CONTENT-ADDRESSED: the account embeds a hash of the key's own public key, so
//        two DIFFERENT escrow keys land on DIFFERENT keychain slots and COEXIST under iCloud Keychain
//        rather than resolving by "newest-modification-date wins" on one shared slot. That eliminates the
//        residual where a divergent (newer) key silently overwrote the genuine (older) escrow key
//        cross-device, permanently stranding the origin device's backups. Divergence now becomes an
//        additive, non-silent `.conflict` (≥2 coexisting keys), never a destructive overwrite. The legacy
//        fixed account "backupEscrowPrivateKey" is still READ for back-compat (pre-content-addressing
//        devices) but never written to by this build.

import Foundation
import FernletCrypto
import FernletFoundation
import CryptoKit
import Security
import FernletDomainModel

// MARK: - Keychain key identifiers

/// Fixed keychain account names for the identity key material (content-addressed escrow slots
/// are derived separately from the escrow key's own public key).
///
/// The `backupEscrowPrivateKey` account is legacy: read for back-compat, never written by this
/// build.
private enum IdentityKeychainKey: String {
    case signingPrivateKey          = "signingPrivateKey"
    case keyAgreementPrivateKey     = "keyAgreementPrivateKey"
    case signingPublicKeyCache      = "signingPublicKeyCache"
    case keyAgreementPublicKeyCache = "keyAgreementPublicKeyCache"
    case backupEscrowPrivateKey     = "backupEscrowPrivateKey"
}

// MARK: - Errors

/// Failures of the identity crypto surface: keys not yet provisioned, malformed key bytes, or a
/// seal/open that could not complete.
///
/// `notProvisioned` means `ensureProvisioned()` has not run (or the keychain was wiped) — the
/// operation is retryable after provisioning; the rest mean "drop the payload".
public enum IdentityError: Error, Equatable {
    case notProvisioned
    case invalidKeyData
    case sealFailed
    case openFailed
    /// A keychain write that the identity depends on did not land (`OSStatus != errSecSuccess`).
    /// Raised instead of caching an identity that exists only in memory: adopting one would mint a
    /// DIFFERENT identity on the next launch and silently break every trust relationship.
    case keychainWriteFailed
    /// A keychain sweep the identity depends on did not land, carrying the failing `OSStatus`.
    /// Raised by ``IdentityService/wipe()`` so a "your identity is gone" promise the keychain
    /// refused is loud rather than silent — the private keys may still be on the device.
    case keychainDeleteFailed(OSStatus)
    /// A keychain READ the identity depends on failed with an `OSStatus` other than
    /// `errSecItemNotFound`, carrying that status. Raised by ``IdentityService/ensureProvisioned()``
    /// instead of treating the row as absent: every non-`found` answer there leads to a mint, and a
    /// mint `KeychainItem.store`s each identity row **delete-then-add** — so a transient read error
    /// (`errSecInteractionNotAllowed` before first unlock, `errSecNotAvailable`, an I/O failure)
    /// that fell through would overwrite the live identity and silently orphan every trust
    /// relationship built on it. Nothing is written when this is thrown; the next launch retries.
    case keychainReadFailed(OSStatus)
    /// The bytes carry no CURRENT format marker — a transport seal with no `FPT2` prefix, or a
    /// 92-byte group-key wrap with no `FGK2` prefix. Both are the shapes a peer on a pre-marker
    /// build sends, and the crypto standardization round's Phase 4 deleted the readers for them,
    /// so they are now classified and refused rather than opened under an untyped AAD.
    ///
    /// Separate from ``openFailed`` because the cause and the remedy are different: `openFailed`
    /// means the payload authenticated against nothing we hold (not for us, or tampered with),
    /// while this one means the payload is not in a shape this build reads at all — most plausibly
    /// a SENDER who needs to update Fernlet. The connection surface can say that only if the two
    /// are distinguishable.
    ///
    /// What it does NOT prove: the retired transport format had no marker to check, so "no `FPT2`"
    /// covers malformed or forged bytes as well as an older build. The 92-byte wrap is the sharper
    /// of the two — that exact length IS a discriminator. Either way the outcome is fail-closed;
    /// only the explanation differs.
    case legacyWireFormat
}

// MARK: - IdentityService

/// The per-device cryptographic identity for the proximity subsystem: Ed25519 signing, X25519
/// key agreement, heart-drop/presence tag derivation, group-key wrapping, and the iCloud-synced
/// backup-escrow key lifecycle.
///
/// Responsibilities: provisioning + caching the keychain-backed key pairs
/// (`ensureProvisioned()`, idempotent, with three migration cases documented inline); signing
/// (`sign`) and static verification (`verify`); the pairwise ECDH→HKDF→ChaChaPoly seal/open used
/// for all sealed payloads (with optional wire2 framing); domain-separated pair secrets and
/// rotating tags for presence recognition and heart-drop day tags; and the WS-1..WS-4
/// backup-escrow reconciliation, where CONTENT-ADDRESSED keychain slots make divergent escrow
/// keys coexist as a detectable `.conflict` instead of silently overwriting each other.
///
/// Key separation is the core invariant: the signing + proximity KA keys are
/// ThisDeviceOnly and never sync; only the backup-escrow key is synchronizable. The private keys
/// never leave this type — collaborators pass closures (e.g. `HeartDropSealer.open` takes
/// `heartDropStaticAgreement`). Several instances coexist in the app (mesh, presence, recipe
/// share, heart-drop service) over the same keychain rows; `wipe()` clears the rows plus THIS
/// instance's cache, so delete-all must call it on every live instance. `@MainActor`; the pure
/// crypto statics (`verify`, `fingerprint`, tag derivations) are `nonisolated` for off-main use.
@MainActor
public final class IdentityService {

    /// Prefix on the ephemeral-static transport seal, REQUIRED on both write and read. Every seal
    /// authenticates a typed AEAD purpose together with the sender's static key; the pre-marker
    /// format, which started directly with the ephemeral public key and bound no purpose, is no
    /// longer opened (Phase 4) — its absence now only classifies bytes as
    /// ``IdentityError/legacyWireFormat``.
    private nonisolated static let proximityTransportFormatV2 = Data("FPT2".utf8)
    /// Prefix on the group-key wrap, REQUIRED on both write and read. The explicit four-byte marker
    /// avoids treating an ephemeral public key as a version byte; the prior 92-byte layout is
    /// recognised by length only, so it can be refused by name rather than opened (Phase 4).
    private nonisolated static let groupKeyWrapFormatV2 = Data("FGK2".utf8)

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

    /// Signs an already domain-tagged transcript. The typed purpose is checked against the bytes at
    /// this one raw Ed25519 boundary, so a new caller cannot accidentally turn the identity into an
    /// unscoped signing oracle.
    public func sign(_ data: Data, purpose: CryptographicPurpose) throws -> Data {
        guard let key = signingKey else { throw IdentityError.notProvisioned }
        guard let signingBytes = purpose.signingBytes(data) else { throw IdentityError.invalidKeyData }
        return try key.signature(for: signingBytes)
    }

    /// Sealed-backup key derivation, **record-format v1** (the legacy static derivation).
    ///
    /// ACCEPTED TRADE-OFF (explicit): a v1 backup is AES-GCM'd under a STATIC key —
    /// HKDF-SHA256(backupEscrowPrivateKey) with empty salt and fixed info, no ECDH and no ephemeral
    /// material — so there is NO forward secrecy, and a single escrow-key compromise decrypts every v1
    /// generation. That was intentional for a single-user, private-DB, recoverable-by-design backup: the
    /// escrow key itself is protected by iCloud Keychain end-to-end encryption, and a stable
    /// (non-ephemeral) key is what makes cross-device restore possible.
    ///
    /// **Record format v2 bounds that blast radius** (hardening #4): every backup generation mints its
    /// own 32-byte random HKDF salt, so a compromised escrow key derives one key per generation instead
    /// of one key for all of them. All new writes are v2 (``sealedBackupKey(formatVersion:salt:)``);
    /// this no-argument entry point remains v1 **and must not change** — it is the derivation that opens
    /// every v1 record already sitting in users' CloudKit databases, and its output is pinned by a
    /// known-answer vector in `SealedBackupFormatPinTests`.
    public func sealedBackupKey() throws -> SymmetricKey {
        try sealedBackupKey(formatVersion: 1, salt: Data())
    }

    /// Sealed-backup key derivation for a specific record format.
    ///
    /// - Parameters:
    ///   - formatVersion: The record's format version. `1` (or anything below 2) reproduces the legacy
    ///     static derivation byte-for-byte — empty salt, info `com.fernlet.sealed-backup` — so records
    ///     in the wild keep opening. `2` (and above) mixes `salt` into HKDF under the versioned info
    ///     string `com.fernlet.sealed-backup.v2`.
    ///   - salt: The record's per-generation salt. Ignored for v1; for v2 it is the 32 random bytes
    ///     minted beside the generation counter and stamped on every chunk of that generation.
    /// - Returns: The 32-byte AES-GCM key for records of that format.
    /// - Throws: `IdentityError.notProvisioned` when no backup-escrow key has been adopted.
    public func sealedBackupKey(formatVersion: Int, salt: Data) throws -> SymmetricKey {
        guard let backupEscrowKey else { throw IdentityError.notProvisioned }
        return Self.deriveSealedBackupKey(from: backupEscrowKey, formatVersion: formatVersion, salt: salt)
    }

    /// The HKDF derivation shared by `sealedBackupKey` and `sealedBackupKeyCandidates`. Pure (reads only
    /// its parameters + CryptoKit), so it is `nonisolated`.
    ///
    /// The version selects **both** the salt and the info string. The versioned info string is
    /// belt-and-suspenders on top of the salt: even a bug that produced an empty v2 salt could not
    /// collide with a v1 key, because the two derivations are domain-separated regardless.
    private nonisolated static func deriveSealedBackupKey(
        from privateKey: Curve25519.KeyAgreement.PrivateKey,
        formatVersion: Int,
        salt: Data
    ) -> SymmetricKey {
        let isV2 = formatVersion >= 2
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: privateKey.rawRepresentation),
            salt: isV2 ? salt : Data(),
            info: (isV2
                ? FernletCryptoPurpose.KeyDerivation.sealedBackupV2
                : FernletCryptoPurpose.KeyDerivation.sealedBackupLegacyV1).data,
            outputByteCount: 32
        )
    }

    // WI-9: the three pure crypto statics below are `nonisolated` — they read no instance/actor state
    // (only their parameters + CryptoKit), so signature verification and fingerprinting can run off the
    // main actor. Required by the `nonisolated` `MeshAdmissionToken.verify` and the off-main verify path.
    /// Verifies an already domain-tagged transcript. Legacy read purposes are explicitly marked in
    /// the registry; all current transcript purposes must be embedded in the supplied bytes.
    public nonisolated static func verify(
        _ signature: Data,
        of data: Data,
        by publicKeyData: Data,
        purpose: CryptographicPurpose
    ) -> Bool {
        guard let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData) else { return false }
        guard let signingBytes = purpose.signingBytes(data) else { return false }
        return publicKey.isValidSignature(signature, for: signingBytes)
    }

    /// X25519 ECDH → HKDF-SHA256 → ChaCha20-Poly1305 seal with forward secrecy.
    /// Wire form: ephemeralPubKey (32 B) || sealedBox.combined (nonce 12 B || ciphertext || tag 16 B).
    /// `format: .wire2` deflate-compresses + bucket-pads the plaintext before sealing
    /// (`SealedPayloadFraming`); pass it only when the peer advertised the `wire2` capability.
    public func seal(_ plaintext: Data, to peerKeyAgreementPublicKey: Data, format: SealedPayloadFormat = .legacy) throws -> Data {
        guard let senderKey = keyAgreementKey else { throw IdentityError.notProvisioned }
        guard let peerPubKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerKeyAgreementPublicKey) else {
            throw IdentityError.sealFailed
        }
        let body: Data
        switch format {
        case .legacy: body = plaintext
        case .wire2:  body = SealedPayloadFraming.frame(plaintext)
        }

        let ephemeralKey = Curve25519.KeyAgreement.PrivateKey()
        let sharedSecret = try ephemeralKey.sharedSecretFromKeyAgreement(with: peerPubKey)
        let symKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: FernletCryptoPurpose.KeyDerivation.proximityTransportV1.data,
            sharedInfo: senderKey.publicKey.rawRepresentation + peerKeyAgreementPublicKey,
            outputByteCount: 32
        )

        let aad = FernletCryptoPurpose.AEAD.proximityTransportV2.data
            + senderKey.publicKey.rawRepresentation
        let sealedBox = try ChaChaPoly.seal(body, using: symKey, authenticating: aad)
        return Self.proximityTransportFormatV2 + ephemeralKey.publicKey.rawRepresentation + sealedBox.combined
    }

    /// Inverse of seal. `peerKeyAgreementPublicKey` is the sender's long-term X25519 public key.
    /// `format: .wire2` unframes tolerantly — a decrypted body without a frame tag passes through
    /// unchanged, covering the handshake race where a wire2-capable sender sealed legacy before
    /// it learned our capabilities. Pass `.wire2` only when the SENDER advertised `wire2`.
    ///
    /// - Throws: ``IdentityError/legacyWireFormat`` when the bytes carry no `FPT2` marker. That is
    ///   the shape of the retired transport format, which is refused rather than opened — though
    ///   the retired format carried no marker of its own, so malformed bytes land here too.
    public func open(_ ciphertext: Data, from peerKeyAgreementPublicKey: Data, format: SealedPayloadFormat = .legacy) throws -> Data {
        guard let recipientKey = keyAgreementKey else { throw IdentityError.notProvisioned }
        // Wire format: `FPT2` || eskPub (32 B) || combined. The pre-marker layout started directly
        // at `eskPub` and authenticated only the sender's static key, with no typed AEAD purpose;
        // Phase 4 deleted that read, so the marker's absence is a NAMED refusal, not a fallback.
        guard ciphertext.starts(with: Self.proximityTransportFormatV2) else {
            throw IdentityError.legacyWireFormat
        }
        let offset = Self.proximityTransportFormatV2.count
        guard ciphertext.count >= offset + 32 + 12 + 16 else { throw IdentityError.openFailed }

        let eskPubData = ciphertext.dropFirst(offset).prefix(32)
        let combined = ciphertext.dropFirst(offset + 32)

        guard let ephemeralPeerPubKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: eskPubData) else {
            throw IdentityError.openFailed
        }
        let sharedSecret = try recipientKey.sharedSecretFromKeyAgreement(with: ephemeralPeerPubKey)
        let symKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: FernletCryptoPurpose.KeyDerivation.proximityTransportV1.data,
            sharedInfo: peerKeyAgreementPublicKey + recipientKey.publicKey.rawRepresentation,
            outputByteCount: 32
        )

        let plaintext: Data
        do {
            let sealedBox = try ChaChaPoly.SealedBox(combined: combined)
            let aad = FernletCryptoPurpose.AEAD.proximityTransportV2.data + peerKeyAgreementPublicKey
            plaintext = try ChaChaPoly.open(sealedBox, using: symKey, authenticating: aad)
        } catch {
            throw IdentityError.openFailed
        }
        switch format {
        case .legacy:
            return plaintext
        case .wire2:
            guard SealedPayloadFraming.hasFrameTag(plaintext) else { return plaintext }
            return try SealedPayloadFraming.unframe(plaintext)
        }
    }

    // MARK: - Heart drops (bitchat adoptions Increment 3)

    /// Big-endian (MSB-first) serialization of a 64-bit counter for the domain-separated HMAC
    /// messages below — the R9-safe replacement for `withUnsafeBytes(of: value.bigEndian)`,
    /// byte-identical to it, so every pinned tag vector still matches.
    private nonisolated static func bigEndianBytes(_ value: UInt64) -> [UInt8] {
        (0..<8).map { UInt8(truncatingIfNeeded: value >> (56 - 8 * $0)) }
    }

    /// UTC day index for heart-drop tag rotation (bitchat's day-rotating courier recipient tags).
    public nonisolated static func heartDropDayEpoch(at date: Date) -> UInt64 {
        UInt64(max(0, date.timeIntervalSince1970) / 86_400)
    }

    /// Static-static pair secret for heart-drop day tags — mirrors `presencePairSecret` with its
    /// own salt so presence tags and drop tags can never collide across protocols. sharedInfo
    /// stays EMPTY: both sides must derive the same key (symmetry requirement).
    public func heartDropPairSecret(with friendKeyAgreementPublicKey: Data) throws -> SymmetricKey {
        guard let myKey = keyAgreementKey else { throw IdentityError.notProvisioned }
        guard let friendKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: friendKeyAgreementPublicKey) else {
            throw IdentityError.sealFailed
        }
        let shared = try myKey.sharedSecretFromKeyAgreement(with: friendKey)
        return shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: FernletCryptoPurpose.KeyDerivation.heartDropPairV1.data,
            sharedInfo: Data(),
            outputByteCount: 32
        )
    }

    /// A drop's public-DB record tag: HMAC-SHA256 over a domain string + the day epoch + the
    /// SENDER's KA key (the sender term gives direction asymmetry, so my outgoing tag for a
    /// friend never equals my expected incoming tag from them), truncated to 16 bytes, hex.
    /// Uncorrelatable across days without the pair secret.
    public nonisolated static func heartDropTag(
        pairSecret: SymmetricKey,
        dayEpoch: UInt64,
        senderKeyAgreementPublicKey: Data
    ) -> String {
        var message = FernletCryptoPurpose.HMAC.heartDropDayTagV1.data
        message.append(contentsOf: Self.bigEndianBytes(dayEpoch))
        message.append(senderKeyAgreementPublicKey)
        let mac = HMAC<SHA256>.authenticationCode(for: message, using: pairSecret)
        return Data(mac).prefix(16).map { String(format: "%02x", $0) }.joined()
    }

    /// ECDH against the static KA private, for opening static-fallback drops — the private key
    /// itself never leaves this service (`HeartDropSealer.open` takes this as a closure).
    public func heartDropStaticAgreement(withEphemeralPublicKey ephemeralPublicKey: Data) throws -> SharedSecret {
        guard let myKey = keyAgreementKey else { throw IdentityError.notProvisioned }
        guard let ephemeralKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephemeralPublicKey) else {
            throw IdentityError.openFailed
        }
        return try myKey.sharedSecretFromKeyAgreement(with: ephemeralKey)
    }

    // MARK: - Presence tags (mesh redesign Phase 4a)

    /// Presence epoch length in seconds. Presence tags rotate every epoch; matchers accept ±1
    /// epoch to span clock skew and the advertiser-restart flap.
    public nonisolated static let presenceEpochSeconds: TimeInterval = 900

    /// Bytes kept from the truncated presence-tag HMAC (base64 → 12 chars on the wire, which is
    /// what keeps a 24-tag roster inside the ~400 B Bonjour TXT budget).
    public nonisolated static let presenceTagByteCount = 8

    /// The presence epoch counter for a moment in time: `floor(unixTime / 900)`.
    public nonisolated static func presenceEpoch(at date: Date) -> UInt64 {
        UInt64(max(0, date.timeIntervalSince1970) / presenceEpochSeconds)
    }

    /// STATIC-STATIC X25519 DH pair secret for presence tags:
    /// `HKDF-SHA256(DH(myKA_priv, friendKA_pub))`, domain-separated from the sealing derivation
    /// (`fernlet.proximity.v1`) and the group-key wrap (`fernlet.mesh.groupkey.v1`) by its own salt,
    /// so presence material can never collide with message keys.
    ///
    /// SYMMETRIC BY CONSTRUCTION — the mutual-recognition property: `DH(aPriv, bPub) ==
    /// DH(bPriv, aPub)`, the salt is a constant, and `sharedInfo` is deliberately EMPTY (any
    /// ordering-dependent info such as sender‖recipient key bytes would give the two sides of the
    /// pair different secrets and break mutual tag derivation). Pairwise-DH is also why blocking a
    /// friend removes their tag: only someone holding one of the two private keys can derive it —
    /// a past handshake partner holding just our public keys cannot (unlike public-key-hash tags).
    public func presencePairSecret(with friendKeyAgreementPublicKey: Data) throws -> SymmetricKey {
        guard let myKey = keyAgreementKey else { throw IdentityError.notProvisioned }
        guard let friendKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: friendKeyAgreementPublicKey) else {
            throw IdentityError.invalidKeyData
        }
        let sharedSecret = try myKey.sharedSecretFromKeyAgreement(with: friendKey)
        return sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: FernletCryptoPurpose.KeyDerivation.presencePairV1.data,
            sharedInfo: Data(),
            outputByteCount: 32
        )
    }

    /// The rotating presence tag for one friend pair at one epoch:
    /// `HMAC-SHA256("fernlet.presence.epoch.v1" ‖ epoch_be64, pairSecret)` truncated to
    /// `presenceTagByteCount`. Both members of the pair derive the SAME tag for the same epoch
    /// (see `presencePairSecret`); different pairs derive independent tags. Observer-opaque:
    /// without a pair private key the tag is an unlinkable pseudorandom value that rotates every
    /// 15 minutes.
    public func presenceTag(for friendKeyAgreementPublicKey: Data, epoch: UInt64) throws -> Data {
        let secret = try presencePairSecret(with: friendKeyAgreementPublicKey)
        var message = FernletCryptoPurpose.HMAC.presenceEpochTagV1.data
        message.append(contentsOf: Self.bigEndianBytes(epoch))
        let mac = HMAC<SHA256>.authenticationCode(for: message, using: secret)
        return Data(Data(mac).prefix(Self.presenceTagByteCount))
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
            salt: FernletCryptoPurpose.KeyDerivation.meshGroupKeyWrapV1.data,
            sharedInfo: ephemeralKey.publicKey.rawRepresentation + recipientPublicKey,
            outputByteCount: 32
        )
        let gcmNonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(
            key,
            using: symKey,
            nonce: gcmNonce,
            authenticating: FernletCryptoPurpose.AEAD.meshGroupKeyWrapV2.data
        )

        var bundle = Self.groupKeyWrapFormatV2
        bundle.append(ephemeralKey.publicKey.rawRepresentation)          // 32 B
        // R9: `AES.GCM.Nonce` is a `Sequence` of `UInt8`, so the raw-pointer walk is unnecessary;
        // same 12 bytes, same order, after the explicit v2 format marker.
        bundle.append(contentsOf: gcmNonce)                              // 12 B
        bundle.append(sealedBox.ciphertext)                              // 32 B
        bundle.append(sealedBox.tag)                                     // 16 B
        return bundle
    }

    /// Unwraps a group key bundle produced by `encryptGroupKey`.
    ///
    /// - Throws: ``IdentityError/legacyWireFormat`` for the pre-marker 92-byte bundle. That length
    ///   is still RECOGNISED — it is the only thing that distinguishes an older build's wrap from
    ///   malformed bytes — but it is no longer opened (Phase 4), so the refusal names the sender's
    ///   build rather than reading as a failed unwrap.
    public func decryptGroupKey(_ bundle: Data) throws -> Data {
        guard let recipientKey = keyAgreementKey else { throw IdentityError.notProvisioned }
        // `FGK2` (4) + eph pub (32) + nonce (12) + ciphertext (32) + tag (16) = 96.
        guard bundle.count == 96, bundle.starts(with: Self.groupKeyWrapFormatV2) else {
            guard bundle.count == 92 else { throw IdentityError.openFailed }
            throw IdentityError.legacyWireFormat
        }

        let offset = Self.groupKeyWrapFormatV2.count

        let ephPubData     = bundle[bundle.startIndex + offset ..< bundle.startIndex + offset + 32]
        let nonceData      = bundle[bundle.startIndex + offset + 32 ..< bundle.startIndex + offset + 44]
        let ciphertextData = bundle[bundle.startIndex + offset + 44 ..< bundle.startIndex + offset + 76]
        let tagData        = bundle[bundle.startIndex + offset + 76 ..< bundle.startIndex + offset + 92]

        guard let ephemeralPubKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephPubData) else {
            throw IdentityError.openFailed
        }
        let sharedSecret = try recipientKey.sharedSecretFromKeyAgreement(with: ephemeralPubKey)
        let recipientPublicKey = recipientKey.publicKey.rawRepresentation
        let symKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: FernletCryptoPurpose.KeyDerivation.meshGroupKeyWrapV1.data,
            sharedInfo: Data(ephPubData) + recipientPublicKey,
            outputByteCount: 32
        )

        do {
            let nonce = try AES.GCM.Nonce(data: nonceData)
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertextData, tag: tagData)
            return try AES.GCM.open(
                sealedBox,
                using: symKey,
                authenticating: FernletCryptoPurpose.AEAD.meshGroupKeyWrapV2.data
            )
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
    ///
    /// **Fail closed on an unreadable row (F-1, P5 close-out).** Every case below Case 1 mints, and a
    /// mint `KeychainItem.store`s each identity row delete-then-add. The two identity-row reads and
    /// Case 3's legacy read therefore use `KeychainItem.loadDistinguishingAbsence`: only
    /// `errSecItemNotFound` is absence, and any other status throws
    /// ``IdentityError/keychainReadFailed(_:)`` with nothing written. The decision is
    /// ``classifyDeviceIdentityRows(signing:keyAgreement:)``, pure and tested on its own.
    public func ensureProvisioned() throws {
        if signingKey != nil && keyAgreementKey != nil { return }

        let deviceOnly = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as CFString

        // Case 1: Signing + proximity KA keys present on this device (normal relaunch). Throws —
        // never falls through — when either row could not be read.
        if let existing = try loadExistingDeviceIdentity() {
            signingKey      = existing.signing
            keyAgreementKey = existing.keyAgreement
            // Adopt an existing backup escrow key if one is present (synced preferred). Do NOT mint one
            // here — escrow generation is deferred to sealed-backup-enable time (WS-1).
            backupEscrowKey = loadExistingEscrowKey()
            migrateKeyAgreementKeyToDeviceOnly(existing.keyAgreement, accessibility: deviceOnly)
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
            try persistFreshDeviceIdentity(signing: newSigning, keyAgreement: newKA, accessibility: deviceOnly)
            signingKey      = newSigning
            keyAgreementKey = newKA
            backupEscrowKey = loadedEscrow
            return
        }

        // Case 3: Legacy synced KA key present (pre-migration second-device path).
        // Promote the old (already-synced) KA key to backup escrow role; generate fresh device-only
        // identity. This reuses an existing synced key, not a fresh mint, so there is no divergence risk —
        // and it is published at the key's CONTENT-ADDRESSED account (two devices running Case 3 derive the
        // same account from the same KA key → same slot, same value → no conflict), never the legacy slot.
        if let loadedKA = try loadLegacyKeyAgreementKey() {
            let newSigning = Curve25519.Signing.PrivateKey()
            let newKA      = Curve25519.KeyAgreement.PrivateKey()
            try promoteLegacyKeyAgreementKeyToEscrow(loadedKA)
            try persistFreshDeviceIdentity(signing: newSigning, keyAgreement: newKA, accessibility: deviceOnly)
            signingKey      = newSigning
            keyAgreementKey = newKA
            backupEscrowKey = loadedKA
            return
        }

        // Case 4: No keys at all — generate signing + proximity KA only. The escrow key is deferred to
        // enable time (WS-1), so a fresh device never publishes a divergent synchronizable escrow key.
        let newSigning = Curve25519.Signing.PrivateKey()
        let newKA      = Curve25519.KeyAgreement.PrivateKey()
        try persistFreshDeviceIdentity(signing: newSigning, keyAgreement: newKA, accessibility: deviceOnly)
        signingKey      = newSigning
        keyAgreementKey = newKA
        backupEscrowKey = nil
    }

    /// What the two private-key rows of the device identity amount to, decided from their raw
    /// keychain reads so the rule can be tested without a keychain (F-1, P5 close-out).
    ///
    /// The ORDER of the rules is the safety property: an unreadable row wins over everything else,
    /// because the only thing ``ensureProvisioned()`` does with a non-`found` answer is mint, and a
    /// mint delete-then-adds every row — including the one that could not be read.
    enum DeviceIdentityRead {
        /// Both rows present and parseable — the identity to adopt.
        case found(signing: Curve25519.Signing.PrivateKey, keyAgreement: Curve25519.KeyAgreement.PrivateKey)
        /// At least one row is authoritatively absent (`errSecItemNotFound`) and neither is
        /// unreadable — provisioning may fall through to the mint cases.
        case absent
        /// A row was read but its bytes are not a key of the expected shape. Permanent — the key
        /// can never be used — so the caller treats it as absence, but by name, with an audit line.
        /// Carries the row's account.
        case unparseable(row: String)
        /// A row could not be read (any `OSStatus` other than `errSecItemNotFound`, or a success
        /// that returned no data). Nothing may be minted. Carries the row's account and the status.
        case unreadable(row: String, status: OSStatus)
    }

    /// The pure half of Case 1: classifies the two identity-row reads.
    ///
    /// - Parameters:
    ///   - signing: The `signingPrivateKey` row's read.
    ///   - keyAgreement: The `keyAgreementPrivateKey` row's read.
    /// - Returns: what provisioning may do — see ``DeviceIdentityRead`` for the precedence.
    static func classifyDeviceIdentityRows(
        signing: KeychainItem.ReadResult,
        keyAgreement: KeychainItem.ReadResult
    ) -> DeviceIdentityRead {
        let signingRow = IdentityKeychainKey.signingPrivateKey.rawValue
        let keyAgreementRow = IdentityKeychainKey.keyAgreementPrivateKey.rawValue
        if case .unreadable(let status) = signing {
            return .unreadable(row: signingRow, status: status)
        }
        if case .unreadable(let status) = keyAgreement {
            return .unreadable(row: keyAgreementRow, status: status)
        }
        guard case .found(let sigData) = signing, case .found(let kaData) = keyAgreement else {
            return .absent
        }
        guard let loadedSigning = try? Curve25519.Signing.PrivateKey(rawRepresentation: sigData) else {
            return .unparseable(row: signingRow)
        }
        guard let loadedKA = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: kaData) else {
            return .unparseable(row: keyAgreementRow)
        }
        return .found(signing: loadedSigning, keyAgreement: loadedKA)
    }

    /// The device identity already on this device (Case 1), or nil when either private-key row is
    /// **absent** or unparseable — in which case provisioning falls through to the mint cases.
    ///
    /// Throws ``IdentityError/keychainReadFailed(_:)`` when either row is **unreadable**: a
    /// transient keychain error is not absence, and the mint cases delete-then-add every identity
    /// row, so falling through would destroy the live identity. Reads with
    /// `KeychainItem.loadDistinguishingAbsence`, never the nil-collapsing `load` — the wall in
    /// `IdentityProvisioningReadTests` pins that.
    private func loadExistingDeviceIdentity() throws
    -> (signing: Curve25519.Signing.PrivateKey, keyAgreement: Curve25519.KeyAgreement.PrivateKey)? {
        let signingRow = KeychainItem.loadDistinguishingAbsence(
            account: IdentityKeychainKey.signingPrivateKey.rawValue, service: keychainService
        )
        let keyAgreementRow = KeychainItem.loadDistinguishingAbsence(
            account: IdentityKeychainKey.keyAgreementPrivateKey.rawValue, service: keychainService
        )
        switch Self.classifyDeviceIdentityRows(signing: signingRow, keyAgreement: keyAgreementRow) {
        case .found(let signing, let keyAgreement):
            return (signing, keyAgreement)
        case .absent:
            return nil
        case .unparseable(let row):
            FernletAuditLog.log("identity.keychain.unparseableRow", context: ["row": row, "stage": "provisioning"])
            return nil
        case .unreadable(let row, let status):
            FernletAuditLog.log("identity.keychain.readFailed", context: [
                "row": row, "stage": "provisioning", "status": "\(status)"
            ])
            throw IdentityError.keychainReadFailed(status)
        }
    }

    /// Case 3's read of the legacy synced key-agreement row, on the same fail-closed rule as
    /// ``loadExistingDeviceIdentity()``: an unreadable row throws rather than falling through to
    /// Case 4, whose `KeychainItem.store(…, replacing: .any)` would delete the synced row it could
    /// not read. Absent, or present but unparseable, is nil — Case 4 is then the right answer.
    private func loadLegacyKeyAgreementKey() throws -> Curve25519.KeyAgreement.PrivateKey? {
        let row = IdentityKeychainKey.keyAgreementPrivateKey.rawValue
        switch KeychainItem.loadDistinguishingAbsence(account: row, service: keychainService) {
        case .absent:
            return nil
        case .found(let data):
            guard let key = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data) else {
                FernletAuditLog.log("identity.keychain.unparseableRow", context: ["row": row, "stage": "legacyKeyAgreement"])
                return nil
            }
            return key
        case .unreadable(let status):
            FernletAuditLog.log("identity.keychain.readFailed", context: [
                "row": row, "stage": "legacyKeyAgreement", "status": "\(status)"
            ])
            throw IdentityError.keychainReadFailed(status)
        }
    }

    /// Re-stores the loaded proximity KA key device-only (dropping a legacy synchronizable flag).
    /// LOGS rather than throws on failure: the loaded key is already valid in memory and this is a
    /// migration, so refusing to provision would be a worse outcome than an un-migrated row.
    private func migrateKeyAgreementKeyToDeviceOnly(
        _ keyAgreement: Curve25519.KeyAgreement.PrivateKey,
        accessibility: CFString
    ) {
        let status = KeychainItem.store(keyAgreement.rawRepresentation,
                                        account: IdentityKeychainKey.keyAgreementPrivateKey.rawValue,
                                        service: keychainService,
                                        accessibility: accessibility,
                                        synchronizable: false)
        guard status != errSecSuccess else { return }
        FernletAuditLog.log("identity.keychain.storeFailed", context: [
            "row": IdentityKeychainKey.keyAgreementPrivateKey.rawValue,
            "stage": "deviceOnlyMigration",
            "status": "\(status)"
        ])
    }

    /// Publishes a legacy already-synced KA key into its content-addressed escrow slot (Case 3).
    /// Throws on a failed write so the caller does not adopt an escrow key that is not on disk —
    /// sealing under a key nothing persisted makes those backups permanently unrecoverable.
    private func promoteLegacyKeyAgreementKeyToEscrow(_ legacyKey: Curve25519.KeyAgreement.PrivateKey) throws {
        let status = KeychainItem.store(legacyKey.rawRepresentation,
                                        account: Self.escrowKeychainAccount(forPublicKey: legacyKey.publicKey.rawRepresentation),
                                        service: keychainService,
                                        accessibility: kSecAttrAccessibleAfterFirstUnlock,
                                        synchronizable: true)
        guard status != errSecSuccess else { return }
        FernletAuditLog.log("identity.escrow.legacyPromoteFailed", context: ["status": "\(status)"])
        throw IdentityError.keychainWriteFailed
    }

    /// Writes a freshly minted device identity — both private keys and both public-key caches —
    /// checking every `OSStatus`. Throws on the first failure so `ensureProvisioned` never adopts
    /// an identity that exists only in memory (the next launch would mint a DIFFERENT one and every
    /// trust relationship would break with no trace).
    private func persistFreshDeviceIdentity(
        signing: Curve25519.Signing.PrivateKey,
        keyAgreement: Curve25519.KeyAgreement.PrivateKey,
        accessibility: CFString
    ) throws {
        let rows: [(account: String, data: Data)] = [
            (IdentityKeychainKey.signingPrivateKey.rawValue, signing.rawRepresentation),
            (IdentityKeychainKey.signingPublicKeyCache.rawValue, signing.publicKey.rawRepresentation),
            (IdentityKeychainKey.keyAgreementPrivateKey.rawValue, keyAgreement.rawRepresentation),
            (IdentityKeychainKey.keyAgreementPublicKeyCache.rawValue, keyAgreement.publicKey.rawRepresentation)
        ]
        for row in rows {
            let status = KeychainItem.store(row.data, account: row.account,
                                            service: keychainService, accessibility: accessibility)
            guard status == errSecSuccess else {
                FernletAuditLog.log("identity.keychain.storeFailed",
                                    context: ["row": row.account, "status": "\(status)"])
                throw IdentityError.keychainWriteFailed
            }
        }
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
        /// ≥2 distinct escrow keys COEXIST (content-addressing kept them all alive rather than overwriting)
        /// — a real cross-device conflict. Not auto-resolved; the caller must surface a user choice (WS-3).
        /// Restore still works against any surviving key meanwhile, so nothing is stranded.
        case conflict
    }

    // MARK: Content-addressed escrow slots

    /// Prefix for content-addressed escrow keychain accounts. The full account is `prefix + sha256hex(pub)`.
    /// `nonisolated` so the pure `escrowKeychainAccount(forPublicKey:)` can reference it off the main actor.
    private nonisolated static let escrowSlotPrefix = "backupEscrowPrivateKey.k."

    /// The content-addressed keychain account for an escrow key, derived from its PUBLIC key. Because the
    /// account is a function of the key's own content, two different escrow keys necessarily occupy two
    /// different accounts → two distinct iCloud-Keychain slots that coexist instead of overwriting. Exposed
    /// (nonisolated, pure) so the seal/restore tests and any tooling can address a key's slot deterministically.
    public nonisolated static func escrowKeychainAccount(forPublicKey publicKey: Data) -> String {
        let hash = SHA256.hash(data: publicKey)
        let hex = hash.compactMap { String(format: "%02x", $0) }.joined()
        return escrowSlotPrefix + hex
    }

    /// One escrow key discovered in the keychain, coalesced across its synced/local rows. `synced` is true
    /// if ANY row for this key is synchronizable; `hasLocalRow` if a device-only row exists; `contentAddressed`
    /// if it lives at a content-addressed account (vs. only the legacy fixed account).
    private struct EscrowCandidate {
        let data: Data
        let key: Curve25519.KeyAgreement.PrivateKey
        let publicKey: Data
        var synced: Bool
        var hasLocalRow: Bool
        var contentAddressed: Bool
    }

    /// Enumerates every backup-escrow key present in this service's keychain — across content-addressed
    /// slots (synced + local) AND the legacy fixed account — coalescing each key's rows. Deterministically
    /// ordered (synced first, then by public-key hash ascending) so every device picks the SAME canonical
    /// key for sealing without coordination. A content-addressed row whose account does not equal
    /// `hash(its own public key)` is rejected as corrupt/foreign (cheap integrity check).
    private func gatherEscrowCandidates() -> [EscrowCandidate] {
        var byData: [Data: EscrowCandidate] = [:]
        func ingest(account: String, data: Data, synced: Bool) {
            guard let key = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data) else { return }
            let pub = key.publicKey.rawRepresentation
            let isContentAddressed = account.hasPrefix(Self.escrowSlotPrefix)
            if isContentAddressed && account != Self.escrowKeychainAccount(forPublicKey: pub) { return }
            if var existing = byData[data] {
                existing.synced = existing.synced || synced
                existing.hasLocalRow = existing.hasLocalRow || !synced
                existing.contentAddressed = existing.contentAddressed || isContentAddressed
                byData[data] = existing
            } else {
                byData[data] = EscrowCandidate(data: data, key: key, publicKey: pub,
                                               synced: synced, hasLocalRow: !synced,
                                               contentAddressed: isContentAddressed)
            }
        }
        for (account, data) in KeychainItem.loadAll(service: keychainService, synchronizable: .synced)
        where account.hasPrefix(Self.escrowSlotPrefix) {
            ingest(account: account, data: data, synced: true)
        }
        for (account, data) in KeychainItem.loadAll(service: keychainService, synchronizable: .local)
        where account.hasPrefix(Self.escrowSlotPrefix) {
            ingest(account: account, data: data, synced: false)
        }
        // Legacy fixed account — READ ONLY for back-compat with pre-content-addressing devices.
        let legacy = IdentityKeychainKey.backupEscrowPrivateKey.rawValue
        if let data = KeychainItem.load(account: legacy, service: keychainService, synchronizable: .synced) {
            ingest(account: legacy, data: data, synced: true)
        }
        if let data = KeychainItem.load(account: legacy, service: keychainService, synchronizable: .local) {
            ingest(account: legacy, data: data, synced: false)
        }
        return byData.values.sorted { lhs, rhs in
            if lhs.synced != rhs.synced { return lhs.synced && !rhs.synced }
            return Self.escrowKeychainAccount(forPublicKey: lhs.publicKey)
                 < Self.escrowKeychainAccount(forPublicKey: rhs.publicKey)
        }
    }

    /// Loads the CANONICAL backup-escrow private key present in the keychain (synced preferred, then the
    /// smallest public-key hash — a deterministic, cross-device-stable choice), or nil if none exists.
    /// NEVER mints — the open/restore path relies on this so a missing key surfaces as "not synced yet",
    /// never a divergent new identity. When >1 key coexists (a conflict) the canonical one is returned for
    /// sealing/boot consistency; `reconcileBackupEscrowKey` separately surfaces the conflict non-silently.
    private func loadExistingEscrowKey() -> Curve25519.KeyAgreement.PrivateKey? {
        gatherEscrowCandidates().first?.key
    }

    /// SEAL/enable path. Ensures `backupEscrowKey` is set so a sealed backup can be produced, without
    /// stranding cross-device restore: re-queries the keychain for a synced (or already-minted local)
    /// escrow key first and adopts it; only when none exists does it mint one — and that fresh key is
    /// stored `ThisDeviceOnly` (WS-2), never published as `synchronizable` until a later launch confirms
    /// no conflicting synced key has appeared (`reconcileBackupEscrowKey`). The minted key is stored at its
    /// CONTENT-ADDRESSED account, so even if it is later promoted it can never overwrite a different
    /// (genuine) key — the publish targets this key's own slot. Returns the escrow public key.
    @discardableResult
    public func provisionBackupEscrowKeyForSealing() -> Data {
        if backupEscrowKey == nil { backupEscrowKey = loadExistingEscrowKey() }
        if backupEscrowKey == nil {
            let minted = Curve25519.KeyAgreement.PrivateKey()
            let account = Self.escrowKeychainAccount(forPublicKey: minted.publicKey.rawRepresentation)
            let status = KeychainItem.store(minted.rawRepresentation,
                                            account: account,
                                            service: keychainService,
                                            accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                            synchronizable: false)
            // Adopt the minted key ONLY once it is provably on disk. Adopting an unwritten key
            // seals every backup generation under a key that exists nowhere after relaunch —
            // permanently unrecoverable records. Empty return = "no escrow key", which the seal
            // path already treats as refuse-to-seal (`sealedBackupKey` throws `notProvisioned`).
            guard status == errSecSuccess else {
                FernletAuditLog.log("identity.escrow.mintFailed", context: ["status": "\(status)"])
                return Data()
            }
            guard KeychainItem.load(account: account, service: keychainService, synchronizable: .local)
                    == minted.rawRepresentation else {
                FernletAuditLog.log("identity.escrow.mintVerifyFailed")
                return Data()
            }
            backupEscrowKey = minted
            FernletAuditLog.log("identity.escrow.mintedLocal")
        }
        return backupEscrowKey?.publicKey.rawRepresentation ?? Data()
    }

    /// OPEN/restore path. Loads an existing escrow key (canonical, synced preferred) into memory; NEVER
    /// mints. Returns whether a key is present — `false` means "not synced yet", which the restore flow
    /// surfaces as a retryable state (WS-4) rather than fabricating a new identity.
    public func loadBackupEscrowKeyForOpen() -> Bool {
        if backupEscrowKey == nil { backupEscrowKey = loadExistingEscrowKey() }
        return backupEscrowKey != nil
    }

    /// Every backup-escrow key available to this device — the adopted (canonical) key plus any other
    /// coexisting content-addressed / legacy keys — as (escrow public key, derived AES-GCM key) pairs,
    /// adopted key first. The open/restore path tries each (decrypt-first) so a record sealed under a
    /// SURVIVING-but-not-adopted key — e.g. during an as-yet-unresolved cross-device escrow conflict —
    /// still restores with no manual step. Content-addressing is what guarantees those keys coexist (rather
    /// than one having silently overwritten the other), which is the whole point of trying them.
    ///
    /// Derives under **record format v1** (static, empty salt). Use
    /// ``sealedBackupKeyCandidates(formatVersion:salt:)`` to open a v2 record.
    public func sealedBackupKeyCandidates() -> [(publicKey: Data, key: SymmetricKey)] {
        sealedBackupKeyCandidates(formatVersion: 1, salt: Data())
    }

    /// The same candidate set as ``sealedBackupKeyCandidates()``, derived under a specific record format.
    ///
    /// The format changes only the *derived key* of each pair, never **which** escrow identities exist:
    /// the returned `publicKey` values (and therefore the count and order) are identical for every
    /// version, so the identity-tag classification in the open path is version-independent.
    ///
    /// - Parameters:
    ///   - formatVersion: The version of the record being opened (`1` legacy static, `2` salted).
    ///   - salt: That record's per-generation salt; ignored for v1.
    /// - Returns: (escrow public key, derived AES-GCM key) pairs, adopted key first.
    public func sealedBackupKeyCandidates(formatVersion: Int, salt: Data) -> [(publicKey: Data, key: SymmetricKey)] {
        var pairs: [(publicKey: Data, key: SymmetricKey)] = []
        var seen = Set<Data>()
        func add(_ privateKey: Curve25519.KeyAgreement.PrivateKey) {
            let pub = privateKey.publicKey.rawRepresentation
            guard seen.insert(pub).inserted else { return }
            pairs.append((
                publicKey: pub,
                key: Self.deriveSealedBackupKey(from: privateKey, formatVersion: formatVersion, salt: salt)
            ))
        }
        if let adopted = backupEscrowKey { add(adopted) }
        for candidate in gatherEscrowCandidates() { add(candidate.key) }
        return pairs
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
    /// MECHANISM + WHY THE RESIDUAL IS NOW GONE. Apple's iCloud Keychain (confirmed from the open-source
    /// `SecItemDataSource.c` conflict resolver + patents US9077759B2 / US9479583B2) treats
    /// `kSecAttrSynchronizable` + service + account as an item's primary key and resolves a divergence on a
    /// SHARED slot by **newest `kSecAttrModificationDate` wins** — no value coexistence, no merge callback.
    /// The old fixed-account design therefore had a residual: a divergent (newer) key could silently
    /// overwrite the genuine (older) key cross-device, permanently stranding the origin's backups. This
    /// build removes that by CONTENT-ADDRESSING the slot (`escrowKeychainAccount(forPublicKey:)`): two
    /// different keys have different accounts → different slots → they COEXIST. A promote/publish therefore
    /// always targets the publishing key's OWN slot and can only ever overwrite an identical copy of the
    /// same key, never a different genuine one. Divergence is now an additive, DETECTABLE state (≥2
    /// coexisting keys) surfaced as a NON-SILENT `.conflict`, not a destructive overwrite — and because all
    /// keys survive, the origin's backups are always recoverable and restore can try every key (decrypt-
    /// first, `sealedBackupKeyCandidates`). WS-2's withhold-then-promote is kept (mint ThisDeviceOnly, publish
    /// on a later launch only when no other key is present) to minimize needless key proliferation.
    public func reconcileBackupEscrowKey() -> BackupEscrowReconcileOutcome {
        let candidates = gatherEscrowCandidates()
        switch candidates.count {
        case 0:
            return .noEscrow
        case 1:
            let only = candidates[0]
            backupEscrowKey = only.key
            if only.synced {
                // Already published. Tidy a now-redundant device-only copy at this key's content-addressed
                // account (the publish below would otherwise leave it lingering). Removing only the .local
                // row for THIS key's account cannot disturb any other (different) key.
                if only.hasLocalRow && only.contentAddressed {
                    KeychainItem.delete(account: Self.escrowKeychainAccount(forPublicKey: only.publicKey),
                                        service: keychainService, synchronizable: .local)
                }
                // Migrate a genuine key that still lives ONLY at the legacy fixed account onto its
                // content-addressed slot, so legacy-origin keys gain the same overwrite-immunity as newly
                // minted ones (closes the last fixed-slot exposure for upgraded users). ADDITIVE: we write
                // the CA synced row and NEVER delete the legacy row — a still-old-build device keeps reading
                // it, and `gatherEscrowCandidates` coalesces the identical bytes into ONE candidate, so this
                // raises no false conflict and preserves zero-config recovery. Idempotent: once a CA row
                // exists, `only.contentAddressed` is true and this no-ops.
                if !only.contentAddressed {
                    let status = KeychainItem.store(only.data,
                                                    account: Self.escrowKeychainAccount(forPublicKey: only.publicKey),
                                                    service: keychainService,
                                                    accessibility: kSecAttrAccessibleAfterFirstUnlock,
                                                    synchronizable: true, replacing: .local)
                    // Log what actually happened: the pre-fix code logged the migration as done
                    // even when nothing was written.
                    if status == errSecSuccess {
                        FernletAuditLog.log("identity.escrow.migratedLegacyToContentAddressed")
                    } else {
                        FernletAuditLog.log("identity.escrow.migrateFailed", context: ["status": "\(status)"])
                    }
                }
                return .usingSynced
            }
            // Only a device-only key exists → promote (publish) it to synchronizable at its CONTENT-
            // ADDRESSED account. ADD-THEN-DELETE: the synced row is written first (`replacing: .synced`
            // can only ever displace an identical copy of THIS key, since the account is a hash of its
            // own public key), and the device-only row — potentially the last copy of the key — is
            // removed only after the publish is confirmed. The old delete-then-add order meant a failed
            // publish destroyed that last copy.
            let account = Self.escrowKeychainAccount(forPublicKey: only.publicKey)
            let status = KeychainItem.store(only.data, account: account, service: keychainService,
                                            accessibility: kSecAttrAccessibleAfterFirstUnlock,
                                            synchronizable: true, replacing: .synced)
            guard status == errSecSuccess else {
                FernletAuditLog.log("identity.escrow.promoteFailed", context: ["status": "\(status)"])
                return .promotedLocal
            }
            KeychainItem.delete(account: account, service: keychainService, synchronizable: .local)
            FernletAuditLog.log("identity.escrow.promotedLocal")
            return .promotedLocal
        default:
            // ≥2 distinct keys coexist — content-addressing kept them all alive (none overwrote another).
            // Adopt the canonical one so sealing/boot is consistent, but surface a non-silent `.conflict`;
            // the user resolves via `adoptSyncedBackupEscrowKey`. Restore meanwhile still works against any
            // of the surviving keys, so no data is stranded while the conflict is unresolved.
            backupEscrowKey = candidates[0].key
            FernletAuditLog.log("identity.escrow.conflictDetected")
            return .conflict
        }
    }

    /// WS-3 user-confirmed resolution of an escrow `.conflict`: adopt the canonical SYNCED (other-device)
    /// key as authoritative and discard THIS device's divergent device-only key(s). The caller MUST warn
    /// the user first and re-upload any device-local backups under the adopted key. Returns the adopted
    /// escrow public key, or nil if no synced key is present. (Only this device's local-only content-
    /// addressed rows are removed; synced keys are never deleted, so nothing is destroyed cross-device — a
    /// deeper conflict between two SYNCED keys keeps surfacing until the devices converge.)
    public func adoptSyncedBackupEscrowKey() -> Data? {
        let candidates = gatherEscrowCandidates()
        guard let chosen = candidates.first(where: { $0.synced }) else { return nil }
        for candidate in candidates where !candidate.synced && candidate.contentAddressed && candidate.data != chosen.data {
            KeychainItem.delete(account: Self.escrowKeychainAccount(forPublicKey: candidate.publicKey),
                                service: keychainService, synchronizable: .local)
        }
        backupEscrowKey = chosen.key
        FernletAuditLog.log("identity.escrow.adoptedSynced")
        return chosen.publicKey
    }

    /// Wipes identity. Breaks every existing trust relationship.
    ///
    /// R7: the sweep's `OSStatus` is checked, not dropped. The in-memory keys are cleared FIRST —
    /// so this process holds no identity either way — and only then is a refusing keychain reported
    /// as ``IdentityError/keychainDeleteFailed(_:)``. A caller that believed a silent wipe would
    /// tell the user their identity was destroyed while the private keys sat in the keychain.
    ///
    /// - Throws: ``IdentityError/keychainDeleteFailed(_:)`` when the keychain rows survive.
    public func wipe() throws {
        let status = KeychainItem.deleteAllReportingStatus(service: keychainService)
        signingKey = nil
        keyAgreementKey = nil
        backupEscrowKey = nil
        guard status != errSecSuccess else { return }
        FernletAuditLog.log("identity.wipe.keychainDeleteFailed", context: ["status": "\(status)"])
        throw IdentityError.keychainDeleteFailed(status)
    }

    /// 16-char lowercase hex prefix of SHA-256(publicKey). Suitable for user-facing display.
    public nonisolated static func fingerprint(of publicKey: Data) -> String {
        let hash = SHA256.hash(data: publicKey)
        let hex = hash.compactMap { String(format: "%02x", $0) }.joined()
        return String(hex.prefix(16))
    }

    /// Case-insensitive equality of canonical 16-char fingerprints — nothing else matches.
    ///
    /// The legacy 8-char prefix acceptance is GONE (bitchat-adoptions follow-up, 2026-07-25):
    /// an 8-hex-char binding is a 32-bit target, GPU-grindable to collide, which is the same
    /// weak-identity-binding class as bitchat's 2025 favorites-impersonation flaw. The only
    /// legitimate 8-char values ever persisted were trust-vault rows kept between 2026-05-26
    /// and 2026-06-12, and `ProximityTrustVault.normalized` re-derives those back to 16 chars
    /// from the row's full signing key on every load — so prefix acceptance had no remaining
    /// honest caller, only downside if an un-normalized source ever appeared. Fingerprints
    /// remain display and routing metadata; authorization uses full key bytes.
    public nonisolated static func fingerprintsMatch(_ first: String, _ second: String) -> Bool {
        let lhs = first.lowercased()
        let rhs = second.lowercased()
        guard lhs.count == 16, rhs.count == 16 else { return false }
        return lhs == rhs
    }
}
