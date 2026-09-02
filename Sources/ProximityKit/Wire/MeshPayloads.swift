import Foundation
import FernletCrypto
import FernletDomainModel

// WI-9: every wire payload below is marked `nonisolated, Sendable`. ProximityKit declares
// `.defaultIsolation(MainActor.self)`, which would otherwise make these value types and their
// synthesized `Codable` conformances MainActor-isolated — only legal under the `.v5` escape hatch,
// and a hard error if these untrusted MCSession bytes were ever decoded off the main actor under
// Swift 6. `nonisolated, Sendable` matches the FernletDomainModel wire types and makes decode +
// signature verification safe from any isolation domain. `MeshAdmissionToken.signed` stays
// `@MainActor` (it signs with the `@MainActor` IdentityService key); `.verify` is `nonisolated`
// (pure signature math + canonical bytes).

/// A mesh's admission posture: `open` advertises the mesh and auto-invites, `closed` stops
/// admitting and switches metadata to group-key encryption.
///
/// Set by the founding member, merged last-write-wins by `modeSetAt` in the descriptor.
public nonisolated enum MeshMode: String, Codable, Equatable, Sendable {
    case open
    case closed
}

/// One member row of a ``MeshDescriptor``: fingerprint, display name, both public keys, and join
/// time.
///
/// Descriptor-gossip data — receivers never use these key fields for sealing or key wrapping
/// (the handshake-verified slot keys are the trust input); they identify members for display and
/// merge dedup.
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

/// The shared description of a mesh — id, name, mode, member list — with per-field
/// last-write-wins timestamps so concurrent edits merge deterministically.
///
/// Broadcast as `.meshDescriptor` whenever it changes; ``MeshNetworkManager`` merges incoming
/// copies field-by-field (newer `nameSetAt`/`modeSetAt` wins, members union minus removed
/// fingerprints) rather than replacing wholesale.
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

/// The `.meshDescriptor` wire body: just the current ``MeshDescriptor``.
///
/// Sent to every slot on any descriptor change and to newly committed slots at connect.
public nonisolated struct MeshStateChangePayload: Codable, Equatable, Sendable {
    public let descriptor: MeshDescriptor

    public init(descriptor: MeshDescriptor) {
        self.descriptor = descriptor
    }
}

/// A proposal to vote a member out of the mesh, valid for 60 seconds.
///
/// Two-party removal: a proposal takes effect only once a second member seconds it
/// (``MeshRemovalSecondPayload``). Receivers cap and de-dupe pending proposals because the id
/// and proposer fields are sender-controlled.
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

/// The seconding vote that makes a removal proposal binding.
///
/// Receivers require the seconder to be the authenticated sender, distinct from both proposer
/// and target, before applying the removal and rebroadcasting.
public nonisolated struct MeshRemovalSecondPayload: Codable, Equatable, Sendable {
    public let proposal: MeshRemovalProposalPayload
    public let seconderFingerprint: String

    public init(proposal: MeshRemovalProposalPayload, seconderFingerprint: String) {
        self.proposal = proposal
        self.seconderFingerprint = seconderFingerprint
    }
}

/// A non-member's request to join a mesh, carrying its claimed identity (fingerprint + keys +
/// display name).
///
/// Receivers reject any request whose claimed fingerprint/signing key differ from the
/// transport-authenticated sender before queueing it for the user's allow/decline.
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

/// The admitter's answer to an admission request: the signed ``MeshAdmissionToken`` plus, from
/// Phase 3, the current group key pairwise-wrapped to the joiner's handshake-verified KA key.
///
/// The outer `meshID` is UNSIGNED — receivers must (and do) verify the signed `token.meshID`
/// against it, so a valid token for one mesh cannot be replayed inside a grant claiming another.
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

/// The admitter-signed membership credential: binds the joiner's fingerprint AND full signing
/// key to a mesh id, with a 2-hour default expiry.
///
/// Minted via ``signed(meshID:joinerFingerprint:joinerSigningPublicKey:admitterIdentity:grantedAt:expiresAt:)``
/// and checked via ``verify(joinerSigningPublicKey:expectedMeshID:expectedAdmitterSigningPublicKey:now:)``, which requires the
/// locally-held key to equal the bound joiner key (defeating fingerprint-collision
/// impersonation) and the signed meshID to equal the grant's claimed mesh. Verification accepts
/// both the v2 cross-platform canonical bytes and the legacy encoder — a documented permanent
/// dual-verify (see the inline F8 note), since the token carries no signed schema version.
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

/// Sent after a successful trusted handshake so peers can label strangers as "Friend of Aisha"
/// in the mesh roster.
///
/// ``MeshNetworkManager`` caches vouches in memory only — never persisted across app launches —
/// and the cache expires after 2 hours.
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

/// Why a key rotation is happening (network migration P3 item 5, plan §8.3).
///
/// Plan §8.3 makes the triggers "15-minute timer ∪ any roster change ∪ any merge", and this token
/// is how a receiver — and a log line, and a test — can tell the three apart. Without it every
/// rotation looks like the timer, and "the mesh rotated because somebody was voted out" is
/// indistinguishable from "the mesh rotated because fifteen minutes passed".
///
/// **Frozen English wire tokens.** These `rawValue`s ride the `meshKeyRotation` frame and are
/// compared byte-for-byte by peers; they never localize and never change spelling. There is no
/// display text here at all — the cause is diagnostic, and no surface shows it to a person.
public nonisolated enum MeshKeyRotationCause: String, Codable, Equatable, Sendable, CaseIterable {
    /// The 15-minute schedule came round. The only cause a pre-P3 build could ever have meant,
    /// which is why it is what a frame with no `cause` field decodes as.
    case timer
    /// A roster change: a verified admission, departure, removal or termination record entered the
    /// ledger. This is the cause that closes the voted-out-member-keeps-the-key gap.
    case membership
    /// A ledger merge changed the derived roster — two branches reconciling (P4, plan §10.3).
    case merge
}

/// Broadcast by the elected coordinator once per rotation: the new epoch plus each member
/// fingerprint's pairwise-encrypted copy of the 32-byte group key.
///
/// A member absent from `perMember` was excluded from the rotation and must re-request
/// admission. Receivers require the authenticated sender to be both the elected coordinator and
/// the payload's claimed coordinator.
///
/// ## The `cause` field, and why an absent one is `timer`
///
/// P3 item 5 extends the frame with ``MeshKeyRotationCause``. The payload is **unsigned** — it
/// rides the signed `FernletIdentityEnvelope`, so no signature transcript and no golden vector
/// moved when the field was added; `MeshKeyRotationWireTests` pins the extended JSON instead.
/// A frame from a build that predates the field decodes as ``MeshKeyRotationCause/timer``, which
/// is not a guess: the 15-minute schedule is the only rotation those builds ever perform.
public nonisolated struct MeshKeyRotationPayload: Codable, Equatable, Sendable {
    public let newEpoch: Int
    public let perMember: [String: Data]
    public let rotationInitiatedAt: Date
    public let coordinatorFingerprint: String
    /// Which of plan §8.3's three triggers fired. Defaults to `.timer` on both write and read, so
    /// neither an older call site nor an older peer's frame is a decode failure.
    public let cause: MeshKeyRotationCause

    public init(
        newEpoch: Int,
        perMember: [String: Data],
        rotationInitiatedAt: Date,
        coordinatorFingerprint: String,
        cause: MeshKeyRotationCause = .timer
    ) {
        self.newEpoch = newEpoch
        self.perMember = perMember
        self.rotationInitiatedAt = rotationInitiatedAt
        self.coordinatorFingerprint = coordinatorFingerprint
        self.cause = cause
    }

    /// Decodes a rotation frame, treating a missing `cause` as ``MeshKeyRotationCause/timer`` and
    /// an *unrecognised* one the same way — a future build's fourth cause must not stop this one
    /// adopting a key it can otherwise read. Every other field stays required.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        newEpoch = try container.decode(Int.self, forKey: .newEpoch)
        perMember = try container.decode([String: Data].self, forKey: .perMember)
        rotationInitiatedAt = try container.decode(Date.self, forKey: .rotationInitiatedAt)
        coordinatorFingerprint = try container.decode(String.self, forKey: .coordinatorFingerprint)
        cause = (try? container.decodeIfPresent(MeshKeyRotationCause.self, forKey: .cause)) ?? .timer
    }
}

/// A member's acknowledgment in the rotation protocol — sent for the closing epoch during the
/// drain phase and again after unwrapping the new key.
///
/// The coordinator collects sync-phase acks to decide who receives the next key.
public nonisolated struct MeshKeyAckPayload: Codable, Equatable, Sendable {
    public let epoch: Int
    public let memberFingerprint: String

    public init(epoch: Int, memberFingerprint: String) {
        self.epoch = epoch
        self.memberFingerprint = memberFingerprint
    }
}

/// Broadcast by the coordinator before generating a new key: "epoch N is closing".
///
/// Members drain in-flight photo exchanges, then answer with a ``MeshKeyAckPayload`` for the
/// closing epoch so the coordinator knows who is ready for the new key.
public nonisolated struct MeshRotationSyncPayload: Codable, Equatable, Sendable {
    public let closingEpoch: Int

    public init(closingEpoch: Int) {
        self.closingEpoch = closingEpoch
    }
}

/// The coordinator's ~20-second liveness beacon: who coordinates, the current epoch, and the
/// planned next rotation. Never encrypted — any peer can read it.
///
/// Members clamp `nextRotationAt` to one rotation window (anti-griefing), only honor beacons
/// from the elected fingerprint, and take over coordination when the beacon goes silent.
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

/// Closed-mode wrapper for mesh control payloads: AES-256-GCM ciphertext (over a JSON
/// ``EncryptedMetadataInner``) plus its nonce and the key epoch it was sealed under.
///
/// Receivers decrypt only when their current group key's epoch matches, then re-dispatch the
/// inner payload through the normal handlers.
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

/// Inner content of a ``MeshEncryptedMetadataPayload`` after decryption: the real payload type
/// token plus its encoded bytes.
///
/// Only a known subset of control types is re-dispatched from here (descriptor, photo
/// manifest/request, admission grant).
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
    /// Rejection reasons for an admission token.
    ///
    /// Each case pins one binding the admitter's signature must honor: mesh id, expiry, joiner
    /// key, fingerprints, or the signature itself.
    public enum VerifyError: Error, Equatable {
        case expired
        case fingerprintMismatch
        case joinerKeyMismatch
        case signatureInvalid
        case meshMismatch
        case admitterKeyMismatch
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
        token.admitterSignature = try admitterIdentity.sign(
            canonicalBytes(for: token), purpose: FernletCryptoPurpose.Signature.meshAdmissionTokenV2)
        return token
    }

    /// Verifies the token against the key the local device actually holds.
    /// `presentedKey` must match the `joinerSigningPublicKey` bound into the token at issuance,
    /// preventing a fingerprint-collision attack from impersonating the intended joiner.
    /// `expectedMeshID` must match the signed `meshID`, so a token issued for one mesh cannot be
    /// replayed inside a grant claiming a different mesh (the grant's outer meshID is unsigned).
    ///
    /// `expectedAdmitterSigningPublicKey` must match `admitterSigningPublicKey`. WITHOUT IT THIS
    /// FUNCTION PROVES NOTHING ABOUT AUTHORIZATION: the token's signature root is the admitter key
    /// carried INSIDE the token, so a self-signed token minted by a total stranger verifies
    /// perfectly. The caller supplies the key it independently authenticated (the envelope sender)
    /// and this equality is what turns "well-formed" into "granted by someone entitled to grant".
    /// The parameter has NO default value on purpose — a default is how a caller silently skips
    /// the binding, which is exactly how this bug was born.
    ///
    /// `nonisolated` (WI-9): pure signature math (`IdentityService.verify`/`fingerprint` statics +
    /// `canonicalBytes`), touching no actor state — so a token can be verified off the main actor.
    nonisolated public func verify(joinerSigningPublicKey presentedKey: Data,
                                   expectedMeshID: UUID,
                                   expectedAdmitterSigningPublicKey: Data?,
                                   now: Date = Date()) throws {
        guard let expectedAdmitter = expectedAdmitterSigningPublicKey,
              expectedAdmitter == admitterSigningPublicKey else {
            throw VerifyError.admitterKeyMismatch
        }
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
        // broadens the legitimate formats — it does not weaken the check. New tokens are signed v2
        // (tried first); tokens minted by not-yet-updated in-field peers verify via the legacy path.
        //
        // ACCEPTED TRADE-OFF (review F8): unlike the envelope path (which is version-gated and selects
        // ONE encoder), this dual-verify is permanent for the current wire format — there is no signed
        // discriminator to gate on, so the cross-platform-fragile legacy encoder cannot be retired and a
        // legacy/forged token pays two serializations + two Ed25519 verifies. Adding an UNSIGNED version
        // field would be a downgrade-confusion vector; the only clean retirement is a future
        // wire-breaking, schema-versioned token format. Left as-is deliberately (no security impact).
        let signatureValid =
            IdentityService.verify(admitterSignature, of: canonicalBytes(for: self), by: admitterSigningPublicKey,
                                   purpose: FernletCryptoPurpose.Signature.meshAdmissionTokenV2)
            || IdentityService.verify(admitterSignature, of: legacyCanonicalBytes(for: self), by: admitterSigningPublicKey,
                                      purpose: FernletCryptoPurpose.Signature.meshAdmissionTokenLegacyV1)
        guard signatureValid else {
            throw VerifyError.signatureInvalid
        }
    }
}
