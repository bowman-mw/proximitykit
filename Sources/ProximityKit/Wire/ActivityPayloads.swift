// ActivityPayloads.swift
// ProximityKit/Wire
//
// The wire envelopes + signing/verification for Group Activities (Phase 6). The pure value types
// (`ActivityDescriptor`, `ActivityParticipant`, `ActivityRosterSnapshot`, `ActivityJoinToken`) live in
// FernletDomainModel; the crypto lives HERE because it needs the `@MainActor IdentityService` +
// CryptoKit, neither of which DomainModel may name.
//
// The token + snapshot mirror `MeshAdmissionToken` (MeshPayloads.swift) — with ONE deliberate
// improvement: both carry a SIGNED `schemaVersion`, so `verify` gates a SINGLE canonical encoder on the
// version instead of accepting two encodings forever (the `MeshAdmissionToken` dual-verify trap).
//
// WI-9: every wire payload is `public nonisolated struct … : Codable, Equatable, Sendable`. ProximityKit
// sets `.defaultIsolation(MainActor.self)`, which would otherwise MainActor-isolate these value types and
// their synthesized `Codable` — a hard error when the coordinator decodes untrusted MCSession bytes off
// the main actor. `signed(...)` stays `@MainActor` (it signs with the `@MainActor` key); `verify(...)` is
// `nonisolated` (pure signature math + canonical bytes).

import Foundation
import CryptoKit
import FernletDomainModel

// MARK: - Params hash

/// SHA-256 over the canonical descriptor bytes — the stable identity of an activity's parameters
/// that the signed token binds.
///
/// Lives here (not DomainModel) so the domain model stays crypto-free, exactly like
/// ``ModerationContentHash``.
public nonisolated enum ActivityParamsHash {
    public static func of(_ descriptor: ActivityDescriptor) -> Data {
        Data(SHA256.hash(data: canonicalBytes(for: descriptor)))
    }
}

// MARK: - Wire payloads

/// A host advertises an activity it is running to a committed friend. Sealed to the recipient.
///
/// Carries the full descriptor (so the joiner can pin the host key + params) and the host's
/// current roster version (display only — the signed snapshot in the grant is the trust input).
public nonisolated struct ActivityOfferPayload: Codable, Equatable, Sendable {
    public var format = "fernlet.proximity.activity.offer"
    public var version = 1
    public let descriptor: ActivityDescriptor
    public let rosterVersion: Int

    public init(descriptor: ActivityDescriptor, rosterVersion: Int) {
        self.descriptor = descriptor
        self.rosterVersion = rosterVersion
    }

    public var isWellFormed: Bool { format == "fernlet.proximity.activity.offer" && version == 1 }
}

/// A committed peer asks to join an offered activity.
///
/// UNSEALED (mirror `clothingCatalogRequest`): it carries only the joiner's public keys + display
/// name. The host RE-VALIDATES the claimed fingerprint / signing key against the
/// transport-verified slot before minting, and binds the grant to the VERIFIED key — never the
/// claimed one — so an unsealed, spoofable body is harmless.
public nonisolated struct ActivityJoinRequestPayload: Codable, Equatable, Sendable {
    public var format = "fernlet.proximity.activity.join.request"
    public var version = 1
    public let activityID: UUID
    public let joinerFingerprint: String
    public let joinerDisplayName: String
    public let joinerSigningPublicKey: Data
    public let joinerKeyAgreementPublicKey: Data

    public init(
        activityID: UUID,
        joinerFingerprint: String,
        joinerDisplayName: String,
        joinerSigningPublicKey: Data,
        joinerKeyAgreementPublicKey: Data
    ) {
        self.activityID = activityID
        self.joinerFingerprint = joinerFingerprint
        self.joinerDisplayName = joinerDisplayName
        self.joinerSigningPublicKey = joinerSigningPublicKey
        self.joinerKeyAgreementPublicKey = joinerKeyAgreementPublicKey
    }

    public var isWellFormed: Bool {
        format == "fernlet.proximity.activity.join.request" && version == 1
            && !joinerSigningPublicKey.isEmpty && !joinerKeyAgreementPublicKey.isEmpty
    }
}

/// The host's signed grant: an invitee-key-bound token + the roster snapshot at grant time. Sealed.
///
/// The joiner verifies both the token and the snapshot under the host key it pinned from the
/// offer before treating itself as a member (`ProximityActivityManager.handleJoinGrant`).
public nonisolated struct ActivityJoinGrantPayload: Codable, Equatable, Sendable {
    public var format = "fernlet.proximity.activity.join.grant"
    public var version = 1
    public let token: ActivityJoinToken
    public let snapshot: ActivityRosterSnapshot

    public init(token: ActivityJoinToken, snapshot: ActivityRosterSnapshot) {
        self.token = token
        self.snapshot = snapshot
    }

    public var isWellFormed: Bool { format == "fernlet.proximity.activity.join.grant" && version == 1 }
}

/// A host-signed roster snapshot, gossiped opportunistically to keep members consistent. Sealed.
///
/// Anyone may relay it — it self-authenticates under the pinned host key.
public nonisolated struct ActivityRosterSnapshotPayload: Codable, Equatable, Sendable {
    public var format = "fernlet.proximity.activity.roster"
    public var version = 1
    public let snapshot: ActivityRosterSnapshot

    public init(snapshot: ActivityRosterSnapshot) {
        self.snapshot = snapshot
    }

    public var isWellFormed: Bool { format == "fernlet.proximity.activity.roster" && version == 1 }
}

/// A version digest exchanged between committed members: `[activityID: versionHeld]`. The peer holding a
/// higher verified version replies with the snapshot. Sealed; the reply is rate-limited.
public nonisolated struct ActivitySyncPayload: Codable, Equatable, Sendable {
    public var format = "fernlet.proximity.activity.sync"
    public var version = 1
    public let held: [Entry]

    /// One digest line: an activity id and the roster version the sender holds for it.
    public nonisolated struct Entry: Codable, Equatable, Sendable {
        public let activityID: UUID
        public let versionHeld: Int
        public init(activityID: UUID, versionHeld: Int) {
            self.activityID = activityID
            self.versionHeld = versionHeld
        }
    }

    public init(held: [Entry]) {
        self.held = held
    }

    public var isWellFormed: Bool { format == "fernlet.proximity.activity.sync" && version == 1 }
}

// MARK: - ActivityJoinToken signing / verification

extension ActivityJoinToken {
    /// Rejection reasons for a join token — each pins one binding the host's signature must
    /// honor (activity id, params hash, joiner key, pinned host key, expiry, fingerprints).
    public enum VerifyError: Error, Equatable {
        case schemaVersionUnsupported
        case activityMismatch
        case paramsHashMismatch
        case expired
        case joinerKeyMismatch
        case hostKeyMismatch
        case fingerprintMismatch
        case signatureInvalid
    }

    /// `@MainActor`: signs with the `@MainActor` host IdentityService private key. Binds the JOINER'S
    /// signing key (pass the TRANSPORT-VERIFIED key, never the request's claimed key).
    @MainActor
    public static func signed(
        activityID: UUID,
        activityParamsHash: Data,
        joinerFingerprint: String,
        joinerSigningPublicKey: Data,
        hostIdentity: IdentityService,
        grantedAt: Date = Date(),
        expiresAt: Date,
        rosterVersionAtGrant: Int
    ) throws -> ActivityJoinToken {
        var token = ActivityJoinToken(
            schemaVersion: ActivityJoinToken.currentSchemaVersion,
            activityID: activityID,
            activityParamsHash: activityParamsHash,
            joinerFingerprint: joinerFingerprint,
            joinerSigningPublicKey: joinerSigningPublicKey,
            hostFingerprint: hostIdentity.localFingerprint,
            hostSigningPublicKey: hostIdentity.localSigningPublicKey,
            grantedAt: grantedAt,
            expiresAt: expiresAt,
            rosterVersionAtGrant: rosterVersionAtGrant,
            hostSignature: Data()
        )
        token.hostSignature = try hostIdentity.sign(canonicalBytes(for: token))
        return token
    }

    /// Verifies the token against the key the local device actually holds. `presentedKey` must equal the
    /// bound `joinerSigningPublicKey` (defeats a fingerprint-collision impersonation). `expectedActivityID`
    /// must equal the signed `activityID` (the grant's outer id is unsigned — the `handleAdmissionGrant`
    /// lesson). `expectedParamsHash` must equal the bound hash (the host can't swap params after the
    /// descriptor the joiner pinned). `expectedHostSigningPublicKey` PINS the trust root to the host key
    /// the joiner pinned from the offer — so the token is self-sufficient as "the authorization" even if a
    /// future call site verifies it in isolation (a token naming an attacker as host is rejected here, not
    /// only by the manager's out-of-band fingerprint checks). Single-encoder verify gated on the SIGNED
    /// `schemaVersion`. `nonisolated`: pure signature math, no actor state.
    nonisolated public func verify(
        joinerSigningPublicKey presentedKey: Data,
        expectedActivityID: UUID,
        expectedParamsHash: Data,
        expectedHostSigningPublicKey pinnedHostKey: Data,
        now: Date = Date()
    ) throws {
        guard Self.supportedSchemaVersions.contains(schemaVersion) else { throw VerifyError.schemaVersionUnsupported }
        guard activityID == expectedActivityID else { throw VerifyError.activityMismatch }
        guard activityParamsHash == expectedParamsHash else { throw VerifyError.paramsHashMismatch }
        guard hostSigningPublicKey == pinnedHostKey else { throw VerifyError.hostKeyMismatch }
        guard expiresAt >= now else { throw VerifyError.expired }
        guard presentedKey == joinerSigningPublicKey else { throw VerifyError.joinerKeyMismatch }
        guard IdentityService.fingerprintsMatch(
            IdentityService.fingerprint(of: joinerSigningPublicKey), joinerFingerprint
        ) else { throw VerifyError.fingerprintMismatch }
        guard IdentityService.fingerprintsMatch(
            IdentityService.fingerprint(of: hostSigningPublicKey), hostFingerprint
        ) else { throw VerifyError.fingerprintMismatch }
        guard IdentityService.verify(hostSignature, of: canonicalBytes(for: self), by: hostSigningPublicKey) else {
            throw VerifyError.signatureInvalid
        }
    }
}

// MARK: - ActivityRosterSnapshot signing / verification

extension ActivityRosterSnapshot {
    /// Rejection reasons for a roster snapshot, including the anti-bloat bounds that stop an
    /// abusive host from signing a multi-megabyte roster we would persist and re-relay.
    public enum VerifyError: Error, Equatable {
        case schemaVersionUnsupported
        case activityMismatch
        case hostKeyMismatch
        case rosterTooLarge
        case participantFieldTooLarge
        case signatureInvalid
    }

    /// Anti-bloat upper bounds on per-participant fields. A host controls its own signature, so it could
    /// sign a valid but multi-MB roster that we'd then persist verbatim (can't sanitize without breaking
    /// the signature) and re-relay. These bounds are generous — they only reject an abusive host, never a
    /// well-formed roster (Ed25519/X25519 raw keys are 32 bytes; display names are `<= maxNameLength`).
    nonisolated static let maxParticipantKeyBytes = 128
    nonisolated static let maxParticipantStringBytes = 256

    /// `@MainActor`: signs the roster with the host's key. `participants` MUST already include the host
    /// and be `<= ActivityLimits.maxParticipants`.
    @MainActor
    public static func signed(
        activityID: UUID,
        version: Int,
        participants: [ActivityParticipant],
        issuedAt: Date = Date(),
        hostIdentity: IdentityService
    ) throws -> ActivityRosterSnapshot {
        var snapshot = ActivityRosterSnapshot(
            schemaVersion: ActivityRosterSnapshot.currentSchemaVersion,
            activityID: activityID,
            version: version,
            participants: participants,
            issuedAt: issuedAt,
            hostSigningPublicKey: hostIdentity.localSigningPublicKey,
            hostSignature: Data()
        )
        snapshot.hostSignature = try hostIdentity.sign(canonicalBytes(for: snapshot))
        return snapshot
    }

    /// Verifies the snapshot under the PINNED host key (from the descriptor pinned at join), so a
    /// different host cannot push a snapshot for this activity. `nonisolated`: pure signature math.
    nonisolated public func verify(
        expectedActivityID: UUID,
        expectedHostSigningPublicKey pinnedHostKey: Data
    ) throws {
        guard Self.supportedSchemaVersions.contains(schemaVersion) else { throw VerifyError.schemaVersionUnsupported }
        guard activityID == expectedActivityID else { throw VerifyError.activityMismatch }
        guard hostSigningPublicKey == pinnedHostKey else { throw VerifyError.hostKeyMismatch }
        guard participants.count <= ActivityLimits.maxParticipants else { throw VerifyError.rosterTooLarge }
        // Anti-bloat: reject an abusive host's oversized per-participant fields before persisting/relaying.
        for participant in participants {
            guard participant.signingPublicKey.count <= Self.maxParticipantKeyBytes,
                  participant.keyAgreementPublicKey.count <= Self.maxParticipantKeyBytes,
                  participant.fingerprint.utf8.count <= Self.maxParticipantStringBytes,
                  participant.displayName.utf8.count <= Self.maxParticipantStringBytes
            else { throw VerifyError.participantFieldTooLarge }
        }
        guard IdentityService.verify(hostSignature, of: canonicalBytes(for: self), by: hostSigningPublicKey) else {
            throw VerifyError.signatureInvalid
        }
    }
}
