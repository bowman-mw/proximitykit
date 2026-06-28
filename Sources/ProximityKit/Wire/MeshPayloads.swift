import Foundation
import FernletDomainModel

// WI-9: every wire payload below is marked `nonisolated, Sendable`. ProximityKit declares
// `.defaultIsolation(MainActor.self)`, which would otherwise make these value types and their
// synthesized `Codable` conformances MainActor-isolated — only legal under the `.v5` escape hatch,
// and a hard error if these untrusted MCSession bytes were ever decoded off the main actor under
// Swift 6. `nonisolated, Sendable` matches the FernletDomainModel wire types and makes decode +
// signature verification safe from any isolation domain. `MeshAdmissionToken.signed` stays
// `@MainActor` (it signs with the `@MainActor` IdentityService key); `.verify` is `nonisolated`
// (pure signature math + canonical bytes).

public nonisolated enum MeshMode: String, Codable, Equatable, Sendable {
    case open
    case closed
}

public nonisolated struct MeshMember: Codable, Equatable, Identifiable, Sendable {
    public var id: String { fingerprint }

    public let fingerprint: String
    public var displayName: String
    public let signingPublicKey: Data
    public let keyAgreementPublicKey: Data
    public let joinedAt: Date

    public init(
        fingerprint: String,
        displayName: String,
        signingPublicKey: Data,
        keyAgreementPublicKey: Data,
        joinedAt: Date
    ) {
        self.fingerprint = fingerprint
        self.displayName = displayName
        self.signingPublicKey = signingPublicKey
        self.keyAgreementPublicKey = keyAgreementPublicKey
        self.joinedAt = joinedAt
    }
}

public nonisolated struct MeshDescriptor: Codable, Equatable, Identifiable, Sendable {
    public var id: UUID { meshID }

    public let meshID: UUID
    public var name: String
    public var mode: MeshMode
    public var members: [MeshMember]
    public var nameSetAt: Date
    public var nameSetBy: String
    public var modeSetAt: Date
    public var modeSetBy: String
    public var createdAt: Date

    public init(
        meshID: UUID,
        name: String,
        mode: MeshMode,
        members: [MeshMember],
        nameSetAt: Date,
        nameSetBy: String,
        modeSetAt: Date,
        modeSetBy: String,
        createdAt: Date
    ) {
        self.meshID = meshID
        self.name = name
        self.mode = mode
        self.members = members
        self.nameSetAt = nameSetAt
        self.nameSetBy = nameSetBy
        self.modeSetAt = modeSetAt
        self.modeSetBy = modeSetBy
        self.createdAt = createdAt
    }
}

public nonisolated struct MeshStateChangePayload: Codable, Equatable, Sendable {
    public let descriptor: MeshDescriptor

    public init(descriptor: MeshDescriptor) {
        self.descriptor = descriptor
    }
}

public nonisolated struct MeshRemovalProposalPayload: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let targetFingerprint: String
    public let targetDisplayName: String
    public let proposerFingerprint: String
    public let proposerDisplayName: String
    public let createdAt: Date
    public let expiresAt: Date

    public init(
        id: UUID,
        targetFingerprint: String,
        targetDisplayName: String,
        proposerFingerprint: String,
        proposerDisplayName: String,
        createdAt: Date,
        expiresAt: Date
    ) {
        self.id = id
        self.targetFingerprint = targetFingerprint
        self.targetDisplayName = targetDisplayName
        self.proposerFingerprint = proposerFingerprint
        self.proposerDisplayName = proposerDisplayName
        self.createdAt = createdAt
        self.expiresAt = expiresAt
    }
}

public nonisolated struct MeshRemovalSecondPayload: Codable, Equatable, Sendable {
    public let proposal: MeshRemovalProposalPayload
    public let seconderFingerprint: String

    public init(proposal: MeshRemovalProposalPayload, seconderFingerprint: String) {
        self.proposal = proposal
        self.seconderFingerprint = seconderFingerprint
    }
}

public nonisolated struct MeshAdmissionRequestPayload: Codable, Equatable, Sendable {
    public let meshID: UUID
    public let requesterFingerprint: String
    public let requesterDisplayName: String
    public let requesterSigningPublicKey: Data
    public let requesterKeyAgreementPublicKey: Data

    public init(
        meshID: UUID,
        requesterFingerprint: String,
        requesterDisplayName: String,
        requesterSigningPublicKey: Data,
        requesterKeyAgreementPublicKey: Data
    ) {
        self.meshID = meshID
        self.requesterFingerprint = requesterFingerprint
        self.requesterDisplayName = requesterDisplayName
        self.requesterSigningPublicKey = requesterSigningPublicKey
        self.requesterKeyAgreementPublicKey = requesterKeyAgreementPublicKey
    }
}

public nonisolated struct MeshAdmissionGrantPayload: Codable, Equatable, Sendable {
    public let meshID: UUID
    public let requesterFingerprint: String
    public let token: MeshAdmissionToken
    // Phase 3: pairwise-wrapped current group key for the joiner (nil = epoch 0, no key yet)
    public var encryptedCurrentKey: Data?
    public var currentKeyEpoch: Int

    public init(meshID: UUID, requesterFingerprint: String, token: MeshAdmissionToken,
         encryptedCurrentKey: Data? = nil, currentKeyEpoch: Int = 0) {
        self.meshID = meshID
        self.requesterFingerprint = requesterFingerprint
        self.token = token
        self.encryptedCurrentKey = encryptedCurrentKey
        self.currentKeyEpoch = currentKeyEpoch
    }
}

public nonisolated struct MeshAdmissionToken: Codable, Equatable, Sendable {
    public let meshID: UUID
    public let joinerFingerprint: String
    public let joinerSigningPublicKey: Data        // full Ed25519 public key bound into the admitter's signature
    public let admitterFingerprint: String
    public let grantedAt: Date
    public let expiresAt: Date
    public let admitterSigningPublicKey: Data
    public var admitterSignature: Data

    public init(
        meshID: UUID,
        joinerFingerprint: String,
        joinerSigningPublicKey: Data,
        admitterFingerprint: String,
        grantedAt: Date,
        expiresAt: Date,
        admitterSigningPublicKey: Data,
        admitterSignature: Data
    ) {
        self.meshID = meshID
        self.joinerFingerprint = joinerFingerprint
        self.joinerSigningPublicKey = joinerSigningPublicKey
        self.admitterFingerprint = admitterFingerprint
        self.grantedAt = grantedAt
        self.expiresAt = expiresAt
        self.admitterSigningPublicKey = admitterSigningPublicKey
        self.admitterSignature = admitterSignature
    }
}

/// Sent after a successful trusted handshake.
/// Lets peers label strangers as "Friend of Aisha" in the mesh roster.
/// Never persisted across app launches; cache expires after 2 hours.
public nonisolated struct MeshFriendVouchListPayload: Codable, Equatable, Sendable {
    public let voucherFingerprint: String
    public let voucherDisplayName: String
    public let trustedFingerprints: [String]
    public let expiresAt: Date

    public init(
        voucherFingerprint: String,
        voucherDisplayName: String,
        trustedFingerprints: [String],
        expiresAt: Date
    ) {
        self.voucherFingerprint = voucherFingerprint
        self.voucherDisplayName = voucherDisplayName
        self.trustedFingerprints = trustedFingerprints
        self.expiresAt = expiresAt
    }
}

// MARK: - Phase 3 Group Encryption Payloads

// Broadcast by the coordinator once per rotation.
// perMember maps each member fingerprint to their pairwise-encrypted copy of the 32-byte new key.
public nonisolated struct MeshKeyRotationPayload: Codable, Equatable, Sendable {
    public let newEpoch: Int
    public let perMember: [String: Data]
    public let rotationInitiatedAt: Date
    public let coordinatorFingerprint: String

    public init(
        newEpoch: Int,
        perMember: [String: Data],
        rotationInitiatedAt: Date,
        coordinatorFingerprint: String
    ) {
        self.newEpoch = newEpoch
        self.perMember = perMember
        self.rotationInitiatedAt = rotationInitiatedAt
        self.coordinatorFingerprint = coordinatorFingerprint
    }
}

// Sent by each member after successfully unwrapping and caching the new key.
public nonisolated struct MeshKeyAckPayload: Codable, Equatable, Sendable {
    public let epoch: Int
    public let memberFingerprint: String

    public init(epoch: Int, memberFingerprint: String) {
        self.epoch = epoch
        self.memberFingerprint = memberFingerprint
    }
}

// Broadcast by the coordinator before generating a new key.
// Members drain in-flight photo exchanges before responding with a MeshKeyAckPayload.
public nonisolated struct MeshRotationSyncPayload: Codable, Equatable, Sendable {
    public let closingEpoch: Int

    public init(closingEpoch: Int) {
        self.closingEpoch = closingEpoch
    }
}

// Broadcast by the coordinator every ~20 seconds. Never encrypted - any peer can read it.
public nonisolated struct MeshCoordinatorBeaconPayload: Codable, Equatable, Sendable {
    public let coordinatorFingerprint: String
    public let currentEpoch: Int
    public let nextRotationAt: Date
    public let sentAt: Date

    public init(
        coordinatorFingerprint: String,
        currentEpoch: Int,
        nextRotationAt: Date,
        sentAt: Date
    ) {
        self.coordinatorFingerprint = coordinatorFingerprint
        self.currentEpoch = currentEpoch
        self.nextRotationAt = nextRotationAt
        self.sentAt = sentAt
    }
}

// Closed-mode wrapper: inner payload is AES-256-GCM ciphertext over a JSON EncryptedMetadataInner.
public nonisolated struct MeshEncryptedMetadataPayload: Codable, Equatable, Sendable {
    public let ciphertext: Data   // AES-GCM ciphertext + 16-byte tag
    public let nonce: Data        // 12-byte random nonce
    public let keyEpoch: Int

    public init(ciphertext: Data, nonce: Data, keyEpoch: Int) {
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.keyEpoch = keyEpoch
    }
}

// Inner content of MeshEncryptedMetadataPayload after decryption.
public nonisolated struct EncryptedMetadataInner: Codable, Sendable {
    public let payloadType: String
    public let payload: Data

    public init(payloadType: String, payload: Data) {
        self.payloadType = payloadType
        self.payload = payload
    }
}

// Canonical signing bytes for MeshAdmissionToken live in CanonicalSignatureSerializer.swift
// (`canonicalBytes(for:)` = new cross-platform v2, `legacyCanonicalBytes(for:)` = pre-WI-6).

extension MeshAdmissionToken {
    public enum VerifyError: Error, Equatable {
        case expired
        case fingerprintMismatch
        case joinerKeyMismatch
        case signatureInvalid
        case meshMismatch
    }

    /// `@MainActor`: signs with the `@MainActor` admitter IdentityService private key state.
    @MainActor
    public static func signed(
        meshID: UUID,
        joinerFingerprint: String,
        joinerSigningPublicKey: Data,
        admitterIdentity: IdentityService,
        grantedAt: Date = Date(),
        expiresAt: Date? = nil
    ) throws -> MeshAdmissionToken {
        let resolvedExpiresAt = expiresAt ?? grantedAt.addingTimeInterval(2 * 60 * 60)
        var token = MeshAdmissionToken(
            meshID: meshID,
            joinerFingerprint: joinerFingerprint,
            joinerSigningPublicKey: joinerSigningPublicKey,
            admitterFingerprint: admitterIdentity.localFingerprint,
            grantedAt: grantedAt,
            expiresAt: resolvedExpiresAt,
            admitterSigningPublicKey: admitterIdentity.localSigningPublicKey,
            admitterSignature: Data()
        )
        token.admitterSignature = try admitterIdentity.sign(canonicalBytes(for: token))
        return token
    }

    /// Verifies the token against the key the local device actually holds.
    /// `presentedKey` must match the `joinerSigningPublicKey` bound into the token at issuance,
    /// preventing a fingerprint-collision attack from impersonating the intended joiner.
    /// `expectedMeshID` must match the signed `meshID`, so a token issued for one mesh cannot be
    /// replayed inside a grant claiming a different mesh (the grant's outer meshID is unsigned).
    /// `nonisolated` (WI-9): pure signature math (`IdentityService.verify`/`fingerprint` statics +
    /// `canonicalBytes`), touching no actor state — so a token can be verified off the main actor.
    nonisolated public func verify(joinerSigningPublicKey presentedKey: Data, expectedMeshID: UUID, now: Date = Date()) throws {
        guard meshID == expectedMeshID else { throw VerifyError.meshMismatch }
        guard expiresAt >= now else { throw VerifyError.expired }
        guard presentedKey == joinerSigningPublicKey else { throw VerifyError.joinerKeyMismatch }
        guard IdentityService.fingerprintsMatch(
            IdentityService.fingerprint(of: joinerSigningPublicKey),
            joinerFingerprint
        ) else {
            throw VerifyError.fingerprintMismatch
        }
        guard IdentityService.fingerprintsMatch(
            IdentityService.fingerprint(of: admitterSigningPublicKey),
            admitterFingerprint
        ) else {
            throw VerifyError.fingerprintMismatch
        }
        // Admission tokens carry no schema-version field, so accept EITHER the new cross-platform
        // canonical bytes (WI-6 v2) or the legacy `.sortedKeys`/`.iso8601` bytes. Each alternative
        // still requires a valid Ed25519 signature by the admitter's key, so dual acceptance only
        // broadens the legitimate formats — it does not weaken the check. New tokens are signed v2;
        // tokens minted by not-yet-updated in-field peers verify via the legacy path.
        let signatureValid =
            IdentityService.verify(admitterSignature, of: canonicalBytes(for: self), by: admitterSigningPublicKey)
            || IdentityService.verify(admitterSignature, of: legacyCanonicalBytes(for: self), by: admitterSigningPublicKey)
        guard signatureValid else {
            throw VerifyError.signatureInvalid
        }
    }
}
