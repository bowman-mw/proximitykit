// IdentityService.swift
// ProximityKit/Identity
//
// Per-device Ed25519 signing identity + X25519 key-agreement for proximity sessions.
// Keys are split by purpose, each a row under the identity's keychain service at the host
// namespace's `installation.keychain.identity` accounts:
//   signing private key        — Ed25519, ThisDeviceOnly, never synced
//   key-agreement private key  — X25519, ThisDeviceOnly, never synced (proximity transport only)
//   and the two public-key caches beside them.
// Keys a host keeps beside these rows, under the same service, are its own: the identity's
// provisioning hands them to its `IdentityProvisioningParticipant` at the points they must be
// accounted for, and keeps no such key itself.

import Foundation
import FernletCrypto
import CryptoKit
import Security

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
    /// mint `ProximityKeychainItem.store`s each identity row **delete-then-add** — so a transient read error
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
    /// A pair secret was asked for under a purpose this identity's namespace does not declare: a
    /// label in any role but `.keyDerivationSalt`, or a salt outside its family's feature group
    /// (``ProximityNamespace/FeaturePurposes``), a protocol salt among them. Raised by
    /// ``IdentityService/pairSecret(with:purpose:)`` before it reads a key, so no key is ever derived
    /// under a label the namespace's soundness verdict did not judge. Not retryable: the caller named
    /// another purpose than the one its namespace declares.
    case undeclaredPurpose
}

// MARK: - IdentityService

/// The per-device cryptographic identity for the proximity subsystem: Ed25519 signing, X25519
/// key agreement, the presence epoch clock and group-key wrapping.
///
/// Responsibilities: provisioning + caching the keychain-backed key pairs
/// (`ensureProvisioned()`, idempotent: it adopts the device keys already on this device, or mints
/// fresh ones, with the fail-closed reads documented inline); signing (`sign`) and static
/// verification (`verify`); the pairwise ECDH→HKDF→ChaChaPoly seal/open used for all sealed
/// payloads (with optional wire2 framing); and domain-separated pair secrets for a host's features
/// (the generic ``pairSecret(with:purpose:)`` under a declared feature salt, which FernletSocial's
/// heart-drop and presence derivations reach through, beside the rotating tags they compute over
/// it).
///
/// **A host's keys beside the device identity are its participant's.** A host that keeps keys of
/// its own under this identity's keychain service, which provisioning must account for, hands the
/// identity an ``IdentityProvisioningParticipant`` at construction (``provisioningParticipant``):
/// provisioning tells it when it adopts the device keys, asks it before it mints fresh ones over the
/// rows, handing it a fail-closed reader of the key-agreement row a previous build left, tells it when
/// the mint is on disk, and ``wipe()`` tells it when the rows are gone, in the order the protocol
/// documents. Without one an identity adopts or mints, and nothing else. Fernlet's participant is its
/// app's sealed-backup escrow key; ProximityKit keeps no such key and offers no API over one.
///
/// Key separation is the core invariant: the signing + proximity KA keys are ThisDeviceOnly and never
/// sync. The device's private keys never leave this type — collaborators pass closures (e.g.
/// FernletSocial's `HeartDropSealer.open` takes `staticKeyAgreement`); the one private key that
/// does is the key-agreement key a previous build left in the row, which the participant's reader
/// returns before a mint overwrites it and which is then no longer the device's key. Several instances
/// coexist in the app (mesh, presence, recipe share, heart-drop service) over the same keychain rows;
/// `wipe()` clears the rows plus THIS instance's cache (and its participant's), so delete-all must
/// call it on every live instance. `@MainActor`; the pure crypto statics (`verify`, `fingerprint`,
/// the presence epoch clock) are `nonisolated` for off-main use.
///
/// Every instance is built from its host's ``ProximityNamespace`` (plan step A0.2.3), which names
/// the keychain service those shared rows live under; ProximityKit holds no namespace of its own
/// and so offers no default identity (a manager asks its host, ``ProximityHost/makeProximityIdentity()``).
/// An identity of an unsound namespace refuses to provision and to wrap a group key
/// (``ensureProvisioned()``, ``encryptGroupKey(_:for:)``), so it never holds its signing or
/// key-agreement key, tells its participant of no adoption or mint, and nothing is signed, wrapped,
/// sealed to a peer or opened from one under that namespace. ``wipe()`` reads no verdict: under any
/// namespace it sweeps the rows, clears the keys and tells the participant.
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

    /// The host's protocol identity, which this identity signs, seals and keeps its rows under
    /// (ProximityKit plan step A0.2.3).
    ///
    /// Handed in at construction and never looked up: ProximityKit holds no namespace of its own, so
    /// an identity is always built from its host's. Since step A0.2.3 the identity reads its default
    /// ``keychainService`` off it, and since A0.2.4 the builders that sign with this identity (the
    /// envelope, the admission token, the membership, quorum and key-agreement records) and the
    /// envelope's `verify` read their labels from its ``purposes``; since A0.2.5 the six routed
    /// builders do too, and a verify QR made from this identity carries this namespace's scheme and
    /// QR label (the coach and duress ceremonies scan and answer under it as well); and since A0.2.6
    /// the identity's own transport ``seal(_:to:format:)`` and ``open(_:from:format:)`` and its
    /// group-key ``encryptGroupKey(_:for:)`` and ``decryptGroupKey(_:)`` take their HKDF salts and
    /// AEAD labels from its ``purposes``, as do the routed chunks, content hashes and key wraps its
    /// builders mint; and since A0.2.8 the identity's four device rows' ``accounts``, each
    /// byte-identical for Fernlet. `nonisolated`: inert `Sendable` value data, which the nonisolated verifiers and
    /// serializers read without a hop to the main actor.
    public nonisolated let namespace: ProximityNamespace

    /// The namespace's domain-separation labels, `namespace.family.purposes`, by consumer family.
    public nonisolated var purposes: ProximityNamespace.Purposes { namespace.family.purposes }

    /// The accounts of this identity's four device rows, the namespace's
    /// `installation.keychain.identity` (plan step A0.2.8): the signing and key-agreement private keys
    /// and their public-key caches. They sit under ``keychainService``, never under the rows' own
    /// `service`, so a test's throwaway service holds the namespace's accounts too.
    nonisolated var accounts: ProximityNamespace.Keychain.IdentityRows { namespace.installation.keychain.identity }

    /// The keychain service holding this identity's rows: the namespace's identity service, unless
    /// the initializer was handed another (a test's throwaway service).
    public let keychainService: String

    /// The host's keys beside this identity's rows, told of each adoption, mint and wipe in the
    /// order ``IdentityProvisioningParticipant`` documents, or `nil` for an identity that adopts or
    /// mints its device keys and nothing else. Fixed at construction, so every provisioning and wipe
    /// of this instance reaches the same participant.
    public let provisioningParticipant: (any IdentityProvisioningParticipant)?

    private var signingKey: Curve25519.Signing.PrivateKey?
    private var keyAgreementKey: Curve25519.KeyAgreement.PrivateKey?

    /// An identity under the host's namespace. Reads and writes nothing: ``ensureProvisioned()``
    /// does that.
    ///
    /// Replaces `init(keychainService: String = "com.fernlet.identity")` (plan step A0.2.3). The
    /// literal that default spelled is the namespace's `installation.keychain.identity.service` now,
    /// so a shipping identity keeps the very same rows and ProximityKit spells no app's service.
    ///
    /// - Parameters:
    ///   - namespace: The host's protocol identity. No default: every host supplies its own.
    ///   - keychainService: The service holding the identity's rows, or `nil` — every shipping path —
    ///     for the namespace's identity service. A test passes a throwaway service of its own, so it
    ///     never touches the device's real identity.
    ///   - provisioningParticipant: The host's keys beside the identity's rows (``provisioningParticipant``),
    ///     or `nil`, the default, for none. A host whose participant must see every provisioning
    ///     builds every identity with it, through one factory of its own.
    public init(
        namespace: ProximityNamespace,
        keychainService: String? = nil,
        provisioningParticipant: (any IdentityProvisioningParticipant)? = nil
    ) {
        self.namespace = namespace
        self.keychainService = keychainService ?? namespace.installation.keychain.identity.service
        self.provisioningParticipant = provisioningParticipant
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

    /// Signs an already domain-tagged transcript. The typed purpose is checked against the bytes at
    /// this one raw Ed25519 boundary, so a new caller cannot accidentally turn the identity into an
    /// unscoped signing oracle.
    ///
    /// **Transitional** (plan step A0.2.3). A namespace label signs through the
    /// `ProximityCryptographicPurpose` overload below; this one stays for FernletCrypto's registry:
    /// the activity join token's, roster snapshot's and moderation report's labels until plan step
    /// A0.5 takes them out with the mesh manager's feature parts, the app's duress and probe purposes
    /// until C1, and the tests that name them. Every core label's builder signs through the namespace
    /// overload since step A0.2.5.
    /// The purpose's type picks the overload. No deprecation attribute: warnings are errors.
    public func sign(_ data: Data, purpose: CryptographicPurpose) throws -> Data {
        guard let key = signingKey else { throw IdentityError.notProvisioned }
        guard let signingBytes = purpose.signingBytes(data) else { throw IdentityError.invalidKeyData }
        return try key.signature(for: signingBytes)
    }

    /// Signs an already domain-tagged transcript under a namespace signature label.
    ///
    /// The same single raw Ed25519 boundary as the `CryptographicPurpose` overload, with the same
    /// positional check that the transcript begins with the label's prefix (`signingBytes`). The
    /// label's role lets it refuse two things that overload cannot tell apart:
    /// - a verify-only label, `.signature(.absent)` (the legacy pair), which accepts every
    ///   transcript, so signing under it would make this identity an unscoped signing oracle;
    /// - a label in a non-signature role — a hash domain, a salt, a column seal, an AAD or an
    ///   exporter label — which never authorizes a signature.
    ///
    /// - Parameters:
    ///   - data: The transcript, already framed with `purpose`'s prefix.
    ///   - purpose: A `.signature(.lengthPrefixed)` or `.signature(.rawPrefix)` label.
    /// - Returns: The Ed25519 signature over `data`, which is signed unchanged.
    /// - Throws: ``IdentityError/notProvisioned`` before ``ensureProvisioned()`` has run; otherwise
    ///   ``IdentityError/invalidKeyData`` — the error a misframed transcript has always thrown — for
    ///   a misframed transcript, a verify-only label or a non-signature role.
    public func sign(_ data: Data, purpose: ProximityCryptographicPurpose) throws -> Data {
        guard let key = signingKey else { throw IdentityError.notProvisioned }
        guard Self.signsUnder(purpose.role), let signingBytes = purpose.signingBytes(data) else {
            throw IdentityError.invalidKeyData
        }
        return try key.signature(for: signingBytes)
    }

    /// Whether a new transcript may be signed under `role`: a length-prefixed or raw-prefix signature
    /// role, and nothing else. Exhaustive on purpose, so a role added to
    /// ``ProximityCryptographicPurpose/Role`` is classified here before anything can sign under it.
    ///
    /// - Parameter role: The role of the label a caller asked to sign under.
    /// - Returns: `true` only for `.signature(.lengthPrefixed)` and `.signature(.rawPrefix)`.
    private nonisolated static func signsUnder(_ role: ProximityCryptographicPurpose.Role) -> Bool {
        switch role {
        case .signature(.lengthPrefixed), .signature(.rawPrefix):
            return true
        case .signature(.absent), .hashDomain, .keyDerivationSalt, .columnSeal, .aeadAssociatedData,
             .tlsExporterLabel:
            return false
        }
    }

    // WI-9: the pure crypto statics below are `nonisolated` — they read no instance/actor state
    // (only their parameters + CryptoKit), so signature verification and fingerprinting can run off the
    // main actor. Required by the `nonisolated` `MeshAdmissionToken.verify` and the off-main verify path.
    /// Verifies an already domain-tagged transcript. Legacy read purposes are explicitly marked in
    /// the registry; all current transcript purposes must be embedded in the supplied bytes.
    ///
    /// **Transitional** (plan step A0.2.3), like the `CryptographicPurpose` `sign`: a namespace label
    /// verifies through the `ProximityCryptographicPurpose` overload below, and this one stays for
    /// FernletCrypto's registry until the labels it serves move.
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

    /// Verifies a signature over an already domain-tagged transcript under a namespace signature
    /// label.
    ///
    /// The transcript must begin with the label's prefix (`signingBytes`), so a label in a
    /// non-signature role verifies nothing. A verify-only `.signature(.absent)` label — the legacy
    /// pair — accepts every transcript: that is what reading a format from before domain separation
    /// takes, and why `sign` refuses one.
    ///
    /// - Parameters:
    ///   - signature: The Ed25519 signature to check.
    ///   - data: The transcript the signature claims to cover.
    ///   - publicKeyData: The signer's raw Ed25519 public key.
    ///   - purpose: The signature label `data` is framed for.
    /// - Returns: Whether `signature` is valid for `data` under `publicKeyData`, with `data` framed for
    ///   `purpose`.
    public nonisolated static func verify(
        _ signature: Data,
        of data: Data,
        by publicKeyData: Data,
        purpose: ProximityCryptographicPurpose
    ) -> Bool {
        guard let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData) else { return false }
        guard let signingBytes = purpose.signingBytes(data) else { return false }
        return publicKey.isValidSignature(signature, for: signingBytes)
    }

    /// X25519 ECDH → HKDF-SHA256 → ChaCha20-Poly1305 seal with forward secrecy.
    /// Wire form: ephemeralPubKey (32 B) || sealedBox.combined (nonce 12 B || ciphertext || tag 16 B).
    /// `format: .wire2` deflate-compresses + bucket-pads the plaintext before sealing
    /// (`SealedPayloadFraming`); pass it only when the peer advertised the `wire2` capability.
    /// The HKDF salt is this identity's `purposes.keyDerivation.proximityTransportV1` and the
    /// authenticated data `purposes.aead.proximityTransportV2` ‖ the sender's key (plan step A0.2.6).
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
            salt: purposes.keyDerivation.proximityTransportV1.data,
            sharedInfo: senderKey.publicKey.rawRepresentation + peerKeyAgreementPublicKey,
            outputByteCount: 32
        )

        let aad = purposes.aead.proximityTransportV2.data
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
            salt: purposes.keyDerivation.proximityTransportV1.data,
            sharedInfo: peerKeyAgreementPublicKey + recipientKey.publicKey.rawRepresentation,
            outputByteCount: 32
        )

        let plaintext: Data
        do {
            let sealedBox = try ChaChaPoly.SealedBox(combined: combined)
            let aad = purposes.aead.proximityTransportV2.data + peerKeyAgreementPublicKey
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

    // MARK: - Pair secrets under host feature purposes

    /// A pair secret for one of the host's features: X25519 between this device's key-agreement key
    /// and a peer's, then HKDF-SHA256 with `purpose`'s bytes as the salt, empty info and 32 bytes.
    ///
    /// Symmetric by construction, the property a feature's mutual recognition stands on:
    /// `X25519(a, B) == X25519(b, A)`, the salt is a constant and the info is empty, so both members
    /// of a pair derive the same key, and only a holder of one of the two private keys can. The salt
    /// is the host's, a ``ProximityCryptographicPurpose/featureKeyDerivationSalt(_:)`` this identity's
    /// namespace declares (``ProximityNamespace/FeaturePurposes``), and so a label the namespace's
    /// soundness verdict judged with every protocol label: no pair secret is derived under a protocol
    /// salt or under a label that collides with one. The private key never leaves this type; the call
    /// reads and writes no keychain row and writes no audit line. Main-actor, like the identity.
    ///
    /// - Parameters:
    ///   - peerKeyAgreementPublicKey: The peer's X25519 public key, parsed by the caller, who decides
    ///     what a malformed one means for its feature.
    ///   - purpose: The salt.
    /// - Returns: The 32-byte pair secret.
    /// - Throws: ``IdentityError/undeclaredPurpose``, checked first, when `purpose` is not a
    ///   key-derivation salt this identity's namespace declares; ``IdentityError/notProvisioned``
    ///   before ``ensureProvisioned()`` has loaded the key-agreement key, which it never does under an
    ///   unsound namespace; the key agreement's own error otherwise.
    public func pairSecret(
        with peerKeyAgreementPublicKey: Curve25519.KeyAgreement.PublicKey,
        purpose: ProximityCryptographicPurpose
    ) throws -> SymmetricKey {
        guard purpose.role == .keyDerivationSalt, purposes.feature.declares(purpose) else {
            throw IdentityError.undeclaredPurpose
        }
        guard let myKey = keyAgreementKey else { throw IdentityError.notProvisioned }
        let shared = try myKey.sharedSecretFromKeyAgreement(with: peerKeyAgreementPublicKey)
        return shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: purpose.data, sharedInfo: Data(), outputByteCount: 32
        )
    }

    // MARK: - Static key agreement

    /// X25519 against this identity's static key-agreement private key and a sender's ephemeral
    /// public key: the one door through which an ephemeral-static seal addressed to this device is
    /// opened by a collaborator, which takes it as a closure, so the private key itself never leaves
    /// this service.
    ///
    /// Two callers: the routed content-key unwrap (`MeshRoutedContentKeyWrapper.unwrap`, from
    /// `MeshRoutedItemDelivery`) and FernletSocial's heart dead-drop's static-key fallback
    /// (`HeartDropSealer.open`, from `HeartDropService`). Each derives its own key from the secret
    /// under its own label; this answers the raw shared secret and derives nothing.
    ///
    /// - Parameter ephemeralPublicKey: The sender's ephemeral X25519 public key, raw.
    /// - Returns: The shared secret.
    /// - Throws: ``IdentityError/notProvisioned`` when this identity holds no key-agreement key,
    ///   ``IdentityError/openFailed`` for a malformed ephemeral key, or what CryptoKit's agreement
    ///   throws.
    public func staticKeyAgreement(withEphemeralPublicKey ephemeralPublicKey: Data) throws -> SharedSecret {
        guard let myKey = keyAgreementKey else { throw IdentityError.notProvisioned }
        guard let ephemeralKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephemeralPublicKey) else {
            throw IdentityError.openFailed
        }
        return try myKey.sharedSecretFromKeyAgreement(with: ephemeralKey)
    }

    // MARK: - Presence epoch clock
    //
    // The wall-clock epoch the presence radio's posture (`PresenceEpochPosture`) is minted and
    // rotated on, and FernletSocial's presence tags rotate on (its `presenceTag(for:epoch:)`, beside
    // the pair secret it derives through `pairSecret(with:purpose:)`): one counter for the advertised
    // name, the certificate and the tags, so they can never drift onto two clocks. Pure statics that
    // read no key.

    /// Presence epoch length in seconds — **the one place 900 is written down**. Presence tags
    /// rotate every epoch; matchers accept ±1 epoch to span clock skew and the advertiser-restart
    /// flap; and since P9 item 2 (plan §17.1) the radio's advertised instance name and TLS
    /// identity rotate on the very same boundary (``PresenceEpochPosture``), so the posture and
    /// the payload can never drift onto two clocks.
    ///
    /// Anchored to the WALL CLOCK — ``presenceEpoch(at:)`` is `floor(unixTime / 900)`, absolute
    /// multiples since 1970 — and not to a per-launch phase, because two phones must land on the
    /// same epoch index without exchanging a byte for the pairwise tag to be mutual. See
    /// ``PresenceEpochPosture`` for why that anchoring is also the stronger privacy choice.
    public nonisolated static let presenceEpochSeconds: TimeInterval = 900

    /// The presence epoch counter for a moment in time: `floor(unixTime / 900)`.
    public nonisolated static func presenceEpoch(at date: Date) -> UInt64 {
        UInt64(max(0, date.timeIntervalSince1970) / presenceEpochSeconds)
    }

    /// The instant ``presenceEpoch(at:)``'s epoch BEGINS — the same absolute 900 s multiple on
    /// every device, whatever second a given device happens to ask at.
    ///
    /// The anchor anything epoch-scoped must be minted at rather than `now`. A value derived from
    /// the asking instant carries that instant at 1 s resolution: a device that switches its radio
    /// on mid-epoch would then wear a mark no other device in the room wears, which singles it out
    /// for the whole epoch and dates the moment its radio came up. Minting at the epoch start is
    /// what makes the anonymity set everyone present (``PresenceEpochPosture``, reason 3).
    public nonisolated static func presenceEpochStart(at date: Date) -> Date {
        Date(timeIntervalSince1970: Double(presenceEpoch(at: date)) * presenceEpochSeconds)
    }

    // MARK: - Group key distribution (Phase 3)

    /// Wraps a 32-byte group key for one recipient using ephemeral X25519 ECDH → HKDF-SHA256 → AES-256-GCM.
    /// Wire form: ephemeralPubKey (32 B) || nonce (12 B) || ciphertext (32 B) || tag (16 B) = 92 B total.
    /// The HKDF salt is this identity's `purposes.keyDerivation.meshGroupKeyWrapV1` and the
    /// authenticated data `purposes.aead.meshGroupKeyWrapV2`, alone (plan step A0.2.6).
    ///
    /// **Refuses an unsound namespace first.** The wrap needs no provisioned key, so the refusal in
    /// ``ensureProvisioned()`` does not cover it: under an unsound ``namespace`` it throws
    /// ``ProximityNamespaceError`` with every violation and audits `identity.namespace.unsound` (at
    /// `groupKeyWrap`) before anything is derived or sealed.
    public func encryptGroupKey(_ key: Data, for recipientPublicKey: Data) throws -> Data {
        try ProximityNamespaceGate.refuseUnsound(
            namespace.soundness, event: "identity.namespace.unsound", at: .groupKeyWrap)
        guard key.count == 32 else { throw IdentityError.sealFailed }
        guard let recipientKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipientPublicKey) else {
            throw IdentityError.sealFailed
        }
        let ephemeralKey = Curve25519.KeyAgreement.PrivateKey()
        let sharedSecret = try ephemeralKey.sharedSecretFromKeyAgreement(with: recipientKey)
        let symKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: purposes.keyDerivation.meshGroupKeyWrapV1.data,
            sharedInfo: ephemeralKey.publicKey.rawRepresentation + recipientPublicKey,
            outputByteCount: 32
        )
        let gcmNonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(
            key,
            using: symKey,
            nonce: gcmNonce,
            authenticating: purposes.aead.meshGroupKeyWrapV2.data
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
            salt: purposes.keyDerivation.meshGroupKeyWrapV1.data,
            sharedInfo: Data(ephPubData) + recipientPublicKey,
            outputByteCount: 32
        )

        do {
            let nonce = try AES.GCM.Nonce(data: nonceData)
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertextData, tag: tagData)
            return try AES.GCM.open(
                sealedBox,
                using: symKey,
                authenticating: purposes.aead.meshGroupKeyWrapV2.data
            )
        } catch {
            throw IdentityError.openFailed
        }
    }

    // MARK: - Provisioning

    /// Bootstrap on first launch. Idempotent — returns the existing identity if already provisioned.
    ///
    /// Key separation: the signing and proximity KA keys are ThisDeviceOnly (never sync). Provisioning
    /// adopts the two already on this device (the first case below) or mints both fresh (every other
    /// case), and generates no other key.
    ///
    /// **The participant, at fixed points.** With a ``provisioningParticipant``, provisioning tells it
    /// it adopted the device keys before it rewrites the key-agreement row device-only, asks it before
    /// it mints — handing it a fail-closed reader of the key-agreement row a previous build left, which
    /// the mint is about to overwrite, so whatever the participant keeps of that row is kept first —
    /// and tells it once the fresh rows are on disk and adopted, never after a failed mint. Anything the
    /// participant throws stops provisioning before this identity writes a row.
    ///
    /// **Fail closed on an unreadable row (F-1, P5 close-out).** Every case below the first mints, and
    /// a mint `ProximityKeychainItem.store`s each identity row delete-then-add. The two identity-row
    /// reads and the read of the previous build's key-agreement row therefore use
    /// `ProximityKeychainItem.loadDistinguishingAbsence`: only `errSecItemNotFound` is absence, and any
    /// other status throws ``IdentityError/keychainReadFailed(_:)`` with nothing written. The decision
    /// is ``classifyDeviceIdentityRows(signing:keyAgreement:accounts:)``, pure and tested on its own.
    ///
    /// **Refuses an unsound namespace first.** Before any row is read or written, an identity whose
    /// ``namespace`` judged itself unsound throws ``ProximityNamespaceError`` with every violation and
    /// audits `identity.namespace.unsound` (at `provision`), on every call: it never holds its signing
    /// or key-agreement key, so nothing signs, seals to a peer or opens from one under that namespace,
    /// and provisioning calls no participant (``wipe()``, which reads no verdict, still tells it).
    public func ensureProvisioned() throws {
        try ProximityNamespaceGate.refuseUnsound(
            namespace.soundness, event: "identity.namespace.unsound", at: .provision)
        if signingKey != nil && keyAgreementKey != nil { return }

        let deviceOnly = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as CFString

        // Case 1: Signing + proximity KA keys present on this device (normal relaunch). Throws —
        // never falls through — when either row could not be read.
        if let existing = try loadExistingDeviceIdentity() {
            signingKey      = existing.signing
            keyAgreementKey = existing.keyAgreement
            // The participant adopts what it keeps beside the device keys before the device-only
            // migration rewrites the key-agreement row. Nothing is minted here.
            provisioningParticipant?.identityAdoptedDeviceKeys(self)
            migrateKeyAgreementKeyToDeviceOnly(existing.keyAgreement, accessibility: deviceOnly)
            return
        }

        // Every other case mints fresh signing + proximity KA keys over the four rows, delete-then-add,
        // the key-agreement row a previous build left included. The participant is asked first, with a
        // fail-closed reader of that row; whatever it throws stops provisioning before a row is written.
        try provisioningParticipant?.identityWillMintDeviceKeys(
            self, previousKeyAgreementKey: { try self.loadLegacyKeyAgreementKey() })
        let newSigning = Curve25519.Signing.PrivateKey()
        let newKA      = Curve25519.KeyAgreement.PrivateKey()
        try persistFreshDeviceIdentity(signing: newSigning, keyAgreement: newKA, accessibility: deviceOnly)
        signingKey      = newSigning
        keyAgreementKey = newKA
        provisioningParticipant?.identityMintedDeviceKeys(self)
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
    ///   - signing: The signing private key row's read.
    ///   - keyAgreement: The key-agreement private key row's read.
    ///   - accounts: The identity's accounts (``accounts``), which name the row a refusal carries
    ///     (plan step A0.2.8).
    /// - Returns: what provisioning may do — see ``DeviceIdentityRead`` for the precedence.
    static func classifyDeviceIdentityRows(
        signing: ProximityKeychainItem.ReadResult,
        keyAgreement: ProximityKeychainItem.ReadResult,
        accounts: ProximityNamespace.Keychain.IdentityRows
    ) -> DeviceIdentityRead {
        let signingRow = accounts.signingPrivateKey
        let keyAgreementRow = accounts.keyAgreementPrivateKey
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
    /// `ProximityKeychainItem.loadDistinguishingAbsence`, never the nil-collapsing `load` — the wall in
    /// `IdentityProvisioningReadTests` pins that.
    private func loadExistingDeviceIdentity() throws
    -> (signing: Curve25519.Signing.PrivateKey, keyAgreement: Curve25519.KeyAgreement.PrivateKey)? {
        let signingRow = ProximityKeychainItem.loadDistinguishingAbsence(
            account: accounts.signingPrivateKey, service: keychainService
        )
        let keyAgreementRow = ProximityKeychainItem.loadDistinguishingAbsence(
            account: accounts.keyAgreementPrivateKey, service: keychainService
        )
        switch Self.classifyDeviceIdentityRows(signing: signingRow, keyAgreement: keyAgreementRow, accounts: accounts) {
        case .found(let signing, let keyAgreement):
            return (signing, keyAgreement)
        case .absent:
            return nil
        case .unparseable(let row):
            ProximityAudit.log("identity.keychain.unparseableRow", context: ["row": row, "stage": "provisioning"])
            return nil
        case .unreadable(let row, let status):
            ProximityAudit.log("identity.keychain.readFailed", context: [
                "row": row, "stage": "provisioning", "status": "\(status)"
            ])
            throw IdentityError.keychainReadFailed(status)
        }
    }

    /// The read of the key-agreement row a previous build left (synchronized, from before the identity
    /// was device-only), which ``ensureProvisioned()`` hands its participant as the
    /// `previousKeyAgreementKey` reader before a mint, on the same fail-closed rule as
    /// ``loadExistingDeviceIdentity()``: an unreadable row throws rather than falling through to the
    /// mint, whose `ProximityKeychainItem.store(…, replacing: .any)` would delete the row it could not
    /// read. Absent, or present but unparseable, is nil: the mint then overwrites nothing usable. Its
    /// audit lines name the stage `legacyKeyAgreement`.
    private func loadLegacyKeyAgreementKey() throws -> Curve25519.KeyAgreement.PrivateKey? {
        let row = accounts.keyAgreementPrivateKey
        switch ProximityKeychainItem.loadDistinguishingAbsence(account: row, service: keychainService) {
        case .absent:
            return nil
        case .found(let data):
            guard let key = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data) else {
                ProximityAudit.log("identity.keychain.unparseableRow", context: ["row": row, "stage": "legacyKeyAgreement"])
                return nil
            }
            return key
        case .unreadable(let status):
            ProximityAudit.log("identity.keychain.readFailed", context: [
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
        let status = ProximityKeychainItem.store(keyAgreement.rawRepresentation,
                                                 account: accounts.keyAgreementPrivateKey,
                                                 service: keychainService,
                                                 accessibility: accessibility,
                                                 synchronizable: false)
        guard status != errSecSuccess else { return }
        ProximityAudit.log("identity.keychain.storeFailed", context: [
            "row": accounts.keyAgreementPrivateKey,
            "stage": "deviceOnlyMigration",
            "status": "\(status)"
        ])
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
            (accounts.signingPrivateKey, signing.rawRepresentation),
            (accounts.signingPublicKeyCache, signing.publicKey.rawRepresentation),
            (accounts.keyAgreementPrivateKey, keyAgreement.rawRepresentation),
            (accounts.keyAgreementPublicKeyCache, keyAgreement.publicKey.rawRepresentation)
        ]
        for row in rows {
            let status = ProximityKeychainItem.store(row.data, account: row.account,
                                                     service: keychainService, accessibility: accessibility)
            guard status == errSecSuccess else {
                ProximityAudit.log("identity.keychain.storeFailed",
                                   context: ["row": row.account, "status": "\(status)"])
                throw IdentityError.keychainWriteFailed
            }
        }
    }

    /// Wipes identity. Breaks every existing trust relationship.
    ///
    /// Sweeps every row under ``keychainService``, the participant's beside the device identity's
    /// included, then clears the in-memory keys and tells the ``provisioningParticipant`` the rows
    /// are gone, so it drops what it holds in memory too. It reads no soundness verdict: an identity
    /// of an unsound namespace, which never provisioned, still sweeps, clears and tells its
    /// participant.
    ///
    /// R7: the sweep's `OSStatus` is checked, not dropped. The in-memory keys are cleared FIRST —
    /// so this process holds no identity either way — and only then is a refusing keychain reported
    /// as ``IdentityError/keychainDeleteFailed(_:)``. A caller that believed a silent wipe would
    /// tell the user their identity was destroyed while the private keys sat in the keychain.
    ///
    /// - Throws: ``IdentityError/keychainDeleteFailed(_:)`` when the keychain rows survive.
    public func wipe() throws {
        let status = ProximityKeychainItem.deleteAllReportingStatus(service: keychainService)
        signingKey = nil
        keyAgreementKey = nil
        provisioningParticipant?.identityWiped(self)
        guard status != errSecSuccess else { return }
        ProximityAudit.log("identity.wipe.keychainDeleteFailed", context: ["status": "\(status)"])
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
