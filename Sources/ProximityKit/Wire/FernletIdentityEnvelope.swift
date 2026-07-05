// FernletIdentityEnvelope.swift
// Fernlet/Proximity
//
// Wire envelope for all peer-to-peer transfers between Fernlet devices.
// Every envelope is Ed25519-signed over a deterministic canonical JSON encoding.

import Foundation
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
public nonisolated struct FernletIdentityEnvelope: Codable, Equatable, Sendable {
    public let schemaVersion: Int                 // 1
    public let envelopeID: UUID                   // for replay protection + Inspector log correlation
    public let senderSigningPublicKey: Data       // Ed25519 raw, 32 B
    public let senderKeyAgreementPublicKey: Data  // X25519 raw, 32 B
    public let senderDisplayName: String
    public let recipientFingerprint: String?      // 16-char SHA-256 prefix; nil = broadcast
    public let payloadType: PayloadType
    public let payloadEncryption: PayloadEncryption
    public let payloadSummary: PayloadSummary
    public let payload: Data
    public let createdAt: Date
    public let expiresAt: Date?
    public var signature: Data                     // Ed25519 over canonical JSON (this field is zeroed during signing)

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
        self.schemaVersion = schemaVersion
        self.envelopeID = envelopeID
        self.senderSigningPublicKey = senderSigningPublicKey
        self.senderKeyAgreementPublicKey = senderKeyAgreementPublicKey
        self.senderDisplayName = senderDisplayName
        self.recipientFingerprint = recipientFingerprint
        self.payloadType = payloadType
        self.payloadEncryption = payloadEncryption
        self.payloadSummary = payloadSummary
        self.payload = payload
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.signature = signature
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
    private static let sealingRequiredTypes: Set<PayloadType> = [.friendPhoto, .recipeShare, .clothingCatalog, .friendHeart]

    /// Verifies the envelope signature, recipient, expiry, and replay status; returns the plaintext payload.
    /// `@MainActor`: reads the `@MainActor` IdentityService key state (`open`, `localFingerprint`) and the
    /// `@MainActor` ReplayCache. The signature math itself (`IdentityService.verify` + `canonicalBytes`) is
    /// `nonisolated` and could run off-main, but recipient/replay/decrypt need the actor's state.
    @MainActor
    public func verify(identityService: IdentityService, replayCache: ReplayCache) throws -> Data {
        guard Self.supportedSchemaVersions.contains(schemaVersion) else {
            throw VerifyError.schemaVersionUnsupported
        }
        if let expiresAt, expiresAt < Date() { throw VerifyError.expired }

        // Version-gated canonical bytes: v1 used the legacy `.sortedKeys`/`.iso8601` JSON encoder;
        // v2+ uses the cross-platform binary serializer.
        let canon = schemaVersion == Self.legacySchemaVersion
            ? legacyCanonicalBytes(for: self)
            : canonicalBytes(for: self)
        guard IdentityService.verify(signature, of: canon, by: senderSigningPublicKey) else {
            throw VerifyError.signatureInvalid
        }

        if let recipientFingerprint,
           !IdentityService.fingerprintsMatch(recipientFingerprint, identityService.localFingerprint) {
            throw VerifyError.recipientMismatch
        }

        if Self.sealingRequiredTypes.contains(payloadType), payloadEncryption == .none {
            throw VerifyError.sealingRequired
        }

        try replayCache.recordIfNew(envelopeID: envelopeID, createdAt: createdAt)

        switch payloadEncryption {
        case .none:
            return payload
        case .sealedTo:
            do {
                return try identityService.open(payload, from: senderKeyAgreementPublicKey)
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
        envelope.signature = try identityService.sign(canonicalBytes(for: envelope))
        return envelope
    }
}
