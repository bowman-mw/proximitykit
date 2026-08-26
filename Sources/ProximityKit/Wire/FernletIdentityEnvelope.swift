// FernletIdentityEnvelope.swift
// Fernlet/Proximity
//
// Wire envelope for all peer-to-peer transfers between Fernlet devices.
// Every envelope is Ed25519-signed over a deterministic canonical JSON encoding.

import Foundation
import FernletCrypto
import FernletDomainModel

// MARK: - Envelope

// `nonisolated` + `Sendable` (WI-9): ProximityKit sets `.defaultIsolation(MainActor.self)`, which
// would otherwise make this wire value type — and its synthesized `Codable` conformance —
// MainActor-isolated. A MainActor-isolated `init(from:)`/`encode(to:)` can only satisfy the
// `nonisolated` Decodable/Encodable requirements under the `.v5` language-mode escape hatch; under
// Swift 6 it would forbid decoding these untrusted MCSession bytes off the main actor. Marking the
// type `nonisolated, Sendable` (matching the FernletDomainModel wire types — PayloadType/PayloadSummary)
// makes decode + signature verification safe from any isolation domain. The two members that touch
// the `@MainActor` IdentityService/ReplayCache (`verify`, `signed`) stay `@MainActor` explicitly.
/// The signed wire envelope EVERY peer-to-peer transfer between Fernlet devices travels in:
/// sender keys + display name, an optional recipient fingerprint, the (possibly sealed) payload,
/// and an Ed25519 signature over deterministic canonical bytes.
///
/// Minted only via ``signed(identityService:envelopeID:senderDisplayName:recipientFingerprint:payloadType:payloadEncryption:payloadSummary:payload:createdAt:expiresAt:)``
/// and consumed only via ``verify(identityService:replayCache:sealedPayloadFormat:)``, which
/// enforces schema version, expiry, signature, recipient match, mandatory sealing for sensitive
/// payload types, and replay protection — callers never trust a field before `verify` returns.
/// The canonical signing bytes are version-gated (legacy v1 JSON vs the v2 cross-platform binary
/// serializer in `CanonicalSignatureSerializer`). `payloadTypeToken` keeps the raw wire token so
/// an envelope from a NEWER build still decodes, re-encodes byte-identically, and verifies — the
/// unknown type is parked (`isUnknownPayloadType`) and never dispatched, fail-closed. Value type,
/// `nonisolated`/`Sendable`; only `verify`/`signed` touch main-actor state.
public nonisolated struct FernletIdentityEnvelope: Codable, Equatable, Sendable {
    public let schemaVersion: Int                 // 1
    public let envelopeID: UUID                   // for replay protection + Inspector log correlation
    public let senderSigningPublicKey: Data       // Ed25519 raw, 32 B
    public let senderKeyAgreementPublicKey: Data  // X25519 raw, 32 B
    public let senderDisplayName: String
    public let recipientFingerprint: String?      // 16-char SHA-256 prefix; nil = broadcast
    /// The raw payload-type token exactly as it appears on the wire (the `payloadType` JSON key —
    /// see `CodingKeys`). Stored as a string, not a `PayloadType`, so an envelope minted by a NEWER
    /// build — a token this build has no case for — still decodes, re-encodes byte-identically, and
    /// signature-verifies (both canonical forms sign the raw token). This is the EnumDecodeCompat
    /// freeze/park pattern adapted to the wire: the unknown token is parked here, surfaced as
    /// `payloadType == nil` / `isUnknownPayloadType`, and never dispatched to payload handlers.
    public let payloadTypeToken: String
    public let payloadEncryption: PayloadEncryption
    /// The sender-authored disclosure summary. **DO NOT LOCALIZE — this is a wire token, not UI copy.**
    ///
    /// `PayloadSummary.title` looks exactly like a display string ("Recipe share", "Session ended",
    /// "Heartbeat"), and it is one — but on the RECEIVER's screen, not the sender's. Two independent
    /// reasons it is frozen English:
    ///
    /// 1. **It is inside the signature.** `CanonicalSignatureSerializer.appendCanonical(_:_:)` writes
    ///    `summary.title` (and `subtitle`, and every `extraDetails` key/value) into the canonical
    ///    signing bytes. Localizing the title changes those bytes, so the same logical envelope signs
    ///    differently per device locale. `verify` re-derives the bytes from the DECODED envelope, so
    ///    an es-MX sender and an en-US receiver would still agree today — but any future
    ///    normalization, cross-stack port (the planned Kotlin serializer), or re-sign-on-relay turns
    ///    a locale difference into a `signatureInvalid` that nobody can reproduce in English.
    /// 2. **The sender's locale would leak onto the receiver's phone.** `ProximityCoordinator`'s
    ///    `recordEnvelope` feeds this exact title into the Connection Inspector log the RECEIVING
    ///    user reads. A localized sender would put Spanish rows in an English user's audit trail —
    ///    the opposite of what localizing was supposed to buy.
    ///
    /// A localized inspector is still possible later, and the mechanism is already on the wire:
    /// render `payloadTypeToken` through a receiver-side lookup table instead of showing this string.
    /// See the note at `ProximityCoordinator.recordEnvelope`.
    public let payloadSummary: PayloadSummary
    public let payload: Data
    public let createdAt: Date
    public let expiresAt: Date?
    public var signature: Data                     // Ed25519 over canonical JSON (this field is zeroed during signing)

    /// The payload type this build knows, or `nil` when `payloadTypeToken` came from a newer build
    /// (parked). Callers MUST gate dispatch on this being non-nil.
    public var payloadType: PayloadType? { PayloadType(rawValue: payloadTypeToken) }

    /// True when the sender used a payload type this build doesn't know. The envelope still
    /// verifies (schema/expiry/signature/recipient/replay) but its payload is never decrypted
    /// or dispatched — fail-closed by non-dispatch.
    public var isUnknownPayloadType: Bool { payloadType == nil }

    /// Wire-compatibility mapping: `payloadTypeToken` occupies the original `payloadType` key.
    ///
    /// A known type's token IS its rawValue, so the JSON emitted for every pre-existing envelope
    /// is byte-identical to the previous `PayloadType`-typed encoding (and the legacy v1 canonical
    /// bytes, which re-encode the envelope, are unchanged too).
    private enum CodingKeys: String, CodingKey {
        case schemaVersion
        case envelopeID
        case senderSigningPublicKey
        case senderKeyAgreementPublicKey
        case senderDisplayName
        case recipientFingerprint
        case payloadTypeToken = "payloadType"
        case payloadEncryption
        case payloadSummary
        case payload
        case createdAt
        case expiresAt
        case signature
    }

    public init(
        schemaVersion: Int,
        envelopeID: UUID,
        senderSigningPublicKey: Data,
        senderKeyAgreementPublicKey: Data,
        senderDisplayName: String,
        recipientFingerprint: String?,
        payloadType: PayloadType,
        payloadEncryption: PayloadEncryption,
        payloadSummary: PayloadSummary,
        payload: Data,
        createdAt: Date,
        expiresAt: Date?,
        signature: Data
    ) {
        self.init(
            schemaVersion: schemaVersion,
            envelopeID: envelopeID,
            senderSigningPublicKey: senderSigningPublicKey,
            senderKeyAgreementPublicKey: senderKeyAgreementPublicKey,
            senderDisplayName: senderDisplayName,
            recipientFingerprint: recipientFingerprint,
            payloadTypeToken: payloadType.rawValue,
            payloadEncryption: payloadEncryption,
            payloadSummary: payloadSummary,
            payload: payload,
            createdAt: createdAt,
            expiresAt: expiresAt,
            signature: signature
        )
    }

    /// Raw-token initializer — the escape hatch for re-signing/tamper fixtures and tests that need
    /// an envelope whose payload type this build doesn't know. Production signing always goes
    /// through the typed initializer above (`signed` mints only known types).
    public init(
        schemaVersion: Int,
        envelopeID: UUID,
        senderSigningPublicKey: Data,
        senderKeyAgreementPublicKey: Data,
        senderDisplayName: String,
        recipientFingerprint: String?,
        payloadTypeToken: String,
        payloadEncryption: PayloadEncryption,
        payloadSummary: PayloadSummary,
        payload: Data,
        createdAt: Date,
        expiresAt: Date?,
        signature: Data
    ) {
        self.schemaVersion = schemaVersion
        self.envelopeID = envelopeID
        self.senderSigningPublicKey = senderSigningPublicKey
        self.senderKeyAgreementPublicKey = senderKeyAgreementPublicKey
        self.senderDisplayName = senderDisplayName
        self.recipientFingerprint = recipientFingerprint
        self.payloadTypeToken = payloadTypeToken
        self.payloadEncryption = payloadEncryption
        self.payloadSummary = payloadSummary
        self.payload = payload
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.signature = signature
    }

    /// `senderDisplayName` coerced for display or persistence: control/zero-width/bidi scalars
    /// out, whitespace collapsed, capped at 24 characters.
    ///
    /// The RAW field stays untouched because it is SIGNATURE-COVERED — `verify` recomputes the
    /// canonical bytes from the decoded fields, so sanitizing in `init(from:)` or before
    /// `canonicalBytes` would invalidate every signature over a name that changes under
    /// sanitisation. Every render and every persist site must read THIS instead.
    public var sanitizedSenderDisplayName: String {
        ItemNameModeration.moderatedPeerDisplayName(senderDisplayName)
    }
}

// MARK: - Schema versions
//
// The canonical signing bytes are produced by `canonicalBytes(for:)` in CanonicalSignatureSerializer.swift.
// WI-6 replaced the cross-platform-fragile `JSONEncoder(.sortedKeys)` encoder with a deterministic
// binary serializer and bumped the schema version. The transition is version-gated:
//   * `signed` always mints `currentSchemaVersion` (v2) using the new serializer.
//   * `verify` accepts BOTH v1 (legacy `.iso8601`/`.sortedKeys` bytes) and v2 (new serializer),
//     so a not-yet-updated in-field Apple peer is never cut off.

extension FernletIdentityEnvelope {
    /// Schema version stamped onto newly-signed envelopes (new cross-platform canonical serializer).
    public static let currentSchemaVersion = 2
    /// The pre-WI-6 schema version, still accepted on verify for in-field peers.
    public static let legacySchemaVersion = 1
    /// Versions `verify` will accept. Anything else throws `schemaVersionUnsupported`.
    static let supportedSchemaVersions: Set<Int> = [legacySchemaVersion, currentSchemaVersion]
}

// MARK: - Verification

extension FernletIdentityEnvelope {
    /// The distinct ways `verify` rejects an envelope.
    ///
    /// Every case means "drop the envelope"; `replayDetected` doubles as the ``ReplayCache``'s
    /// stale-createdAt rejection.
    public enum VerifyError: Error, Equatable {
        case schemaVersionUnsupported
        case expired
        case signatureInvalid
        case recipientMismatch
        case payloadDecryptionFailed
        case replayDetected
        case sealingRequired
    }

    // Payload types that must always be delivered sealed to the recipient.
    // A misbehaving sender that omits sealing is rejected at the receiver even if the transport
    // is already encrypted, closing the misbehaving-sender gap for sensitive content.
    private static let sealingRequiredTypes: Set<PayloadType> = [.friendPhoto, .recipeShare, .clothingCatalog, .friendHeart, .tempMessage, .itemReport, .friendState, .activityOffer, .activityJoinGrant, .activityRosterSnapshot, .activitySync, .trainerPlan, .trainerPlanDelta, .workoutCompletion, .workoutLiveUpdate, .verifyChallenge, .verifyResponse]

    /// Verifies the envelope signature, recipient, expiry, and replay status; returns the plaintext payload.
    /// `@MainActor`: reads the `@MainActor` IdentityService key state (`open`, `localFingerprint`) and the
    /// `@MainActor` ReplayCache. The signature math itself (`IdentityService.verify` + `canonicalBytes`) is
    /// `nonisolated` and could run off-main, but recipient/replay/decrypt need the actor's state.
    /// `sealedPayloadFormat`: pass `.wire2` only when the SENDER advertised the `wire2` capability —
    /// sealed bodies are then unframed (tolerantly) after decryption. Unsealed payloads ignore it.
    /// `replayCache`: nil ONLY for callers with their own durable dedup that must accept envelopes
    /// older than the cache's 24 h window (the heart dead-drop, whose pickup window is 7 days) —
    /// every live-radio path keeps passing one.
    @MainActor
    public func verify(
        identityService: IdentityService,
        replayCache: ReplayCache?,
        sealedPayloadFormat: SealedPayloadFormat = .legacy
    ) throws -> Data {
        guard Self.supportedSchemaVersions.contains(schemaVersion) else {
            throw VerifyError.schemaVersionUnsupported
        }
        if let expiresAt, expiresAt < Date() { throw VerifyError.expired }

        // Version-gated canonical bytes: v1 used the legacy `.sortedKeys`/`.iso8601` JSON encoder;
        // v2+ uses the cross-platform binary serializer.
        let canon = schemaVersion == Self.legacySchemaVersion
            ? legacyCanonicalBytes(for: self)
            : canonicalBytes(for: self)
        let purpose = schemaVersion == Self.legacySchemaVersion
            ? FernletCryptoPurpose.Signature.identityEnvelopeLegacyV1
            : FernletCryptoPurpose.Signature.identityEnvelopeV2
        guard IdentityService.verify(signature, of: canon, by: senderSigningPublicKey, purpose: purpose) else {
            throw VerifyError.signatureInvalid
        }

        if let recipientFingerprint,
           !IdentityService.fingerprintsMatch(recipientFingerprint, identityService.localFingerprint) {
            throw VerifyError.recipientMismatch
        }

        if let payloadType, Self.sealingRequiredTypes.contains(payloadType), payloadEncryption == .none {
            throw VerifyError.sealingRequired
        }

        try replayCache?.recordIfNew(envelopeID: envelopeID, createdAt: createdAt)

        // Unknown (newer-build) payload type: the envelope authenticated and its ID is now
        // replay-recorded (so unknown-type spam can't bypass replay protection), but the payload
        // is parked — never decrypted, and the sealing gate above is skipped because this build
        // has no sealing semantics for the type. Fail-closed by non-dispatch: callers gate
        // dispatch on `payloadType`, and returning empty bytes keeps the payload unreadable even
        // if a caller forgets.
        guard !isUnknownPayloadType else { return Data() }

        switch payloadEncryption {
        case .none:
            return payload
        case .sealedTo:
            do {
                return try identityService.open(payload, from: senderKeyAgreementPublicKey, format: sealedPayloadFormat)
            } catch {
                throw VerifyError.payloadDecryptionFailed
            }
        }
    }
}

// MARK: - Signed factory

extension FernletIdentityEnvelope {
    /// Creates a signed envelope. `signature` is computed over the canonical bytes of all other fields.
    /// `@MainActor`: signs with the `@MainActor` IdentityService private key state.
    @MainActor
    public static func signed(
        identityService: IdentityService,
        envelopeID: UUID = UUID(),
        senderDisplayName: String,
        recipientFingerprint: String? = nil,
        payloadType: PayloadType,
        payloadEncryption: PayloadEncryption = .none,
        payloadSummary: PayloadSummary,
        payload: Data,
        createdAt: Date = Date(),
        expiresAt: Date? = nil
    ) throws -> FernletIdentityEnvelope {
        var envelope = FernletIdentityEnvelope(
            schemaVersion: currentSchemaVersion,
            envelopeID: envelopeID,
            senderSigningPublicKey: identityService.localSigningPublicKey,
            senderKeyAgreementPublicKey: identityService.localKeyAgreementPublicKey,
            senderDisplayName: senderDisplayName,
            recipientFingerprint: recipientFingerprint,
            payloadType: payloadType,
            payloadEncryption: payloadEncryption,
            payloadSummary: payloadSummary,
            payload: payload,
            createdAt: createdAt,
            expiresAt: expiresAt,
            signature: Data()
        )
        envelope.signature = try identityService.sign(
            canonicalBytes(for: envelope), purpose: FernletCryptoPurpose.Signature.identityEnvelopeV2)
        return envelope
    }
}
