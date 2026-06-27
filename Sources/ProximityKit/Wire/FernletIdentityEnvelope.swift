// FernletIdentityEnvelope.swift
// Fernlet/Proximity
//
// Wire envelope for all peer-to-peer transfers between Fernlet devices.
// Every envelope is Ed25519-signed over a deterministic canonical JSON encoding.

import Foundation
import FernletDomainModel

// MARK: - Envelope

public struct FernletIdentityEnvelope: Codable, Equatable {
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

// MARK: - Canonical encoding

/// Shared deterministic encoder for all canonical-bytes signing operations.
/// Both FernletIdentityEnvelope and MeshAdmissionToken use this configuration — keep them in sync.
public func makeCanonicalSignatureEncoder() -> JSONEncoder {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    encoder.dateEncodingStrategy = .iso8601
    return encoder
}

/// Returns the deterministic byte sequence that is signed and verified.
/// The `signature` field is zeroed so signing and verification produce identical input.
public func canonicalBytes(for envelope: FernletIdentityEnvelope) -> Data {
    var copy = envelope
    copy.signature = Data()
    return try! makeCanonicalSignatureEncoder().encode(copy)
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
    private static let sealingRequiredTypes: Set<PayloadType> = [.friendPhoto, .recipeShare]

    /// Verifies the envelope signature, recipient, expiry, and replay status; returns the plaintext payload.
    public func verify(identityService: IdentityService, replayCache: ReplayCache) throws -> Data {
        guard schemaVersion == 1 else { throw VerifyError.schemaVersionUnsupported }
        if let expiresAt, expiresAt < Date() { throw VerifyError.expired }

        let canon = canonicalBytes(for: self)
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
    /// Creates a signed envelope. `signature` is computed over the canonical JSON of all other fields.
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
            schemaVersion: 1,
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
