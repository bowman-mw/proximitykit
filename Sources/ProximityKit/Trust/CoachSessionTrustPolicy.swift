import Foundation
import FernletDomainModel

/// Session-contract constants for the in-person coach channel (Increment 10 of
/// Docs/Plan-Prekeys-ProtectedLoad-CoachMesh-2026-07-26.md). The in-person mesh session is the
/// PRIMARY coach channel (owner decision, 2026-07-26); iMessage + CloudKit are the off-week
/// fallback.
public enum CoachSessionContract {
    /// ROLE SPLIT (decided 2026-07-26, written down so it cannot be gotten backwards): the coach
    /// runs the separate coaching app and ADVERTISES the `fernlet-coach` service; **Fernlet is
    /// the BROWSER** — it discovers the coach, completes the handshake and the verification
    /// ceremony, and receives the week's plan. `begin(role:mode:)` takes both parameters, and
    /// two advertisers never find each other. A future coach-session manager must call
    /// `begin(role: CoachSessionContract.fernletRole, mode: .trainer)`.
    public static let fernletRole: ProximityRole = .browser
    /// The coach app's side, for the shared-source FernletKit the coaching app links.
    public static let coachAppRole: ProximityRole = .advertiser
}

/// The coach channel's trust decision — deliberately NOT `FriendSessionTrustPolicy`
/// (coach spec §3.2: a coach is not a friend). The friend policy answers
/// `isTrustedProximityPeer` with an unconditional `true` because friend sessions authorize
/// through the proximity gate; injecting it into a coach coordinator would auto-confirm anyone
/// nearby as a coach. This policy answers with REMEMBERED trust, mode-scoped: only a peer the
/// user previously paired AS A COACH (an unrevoked, unblocked `.trainer`-mode vault record)
/// auto-confirms. Everyone else — including established FRIENDS — goes through the explicit
/// first-pairing confirmation and the verification ceremony.
///
/// Lifecycle semantics mirror the friend policy's shape on purpose:
/// - BLOCKED is the transport ban (silent drop / hard fail), read mode-blind from the vault —
///   a person the user blocked is blocked on every channel.
/// - REVOKED-only ("removed my coach") is an un-pairing, not a ban: they may handshake again in
///   person and be re-accepted through the full first-pairing flow. Mapping `isRevoked` to the
///   blocked check (not the revoked check) is what keeps the coordinator's hard-fail from
///   permanently locking out a re-hired coach.
public final class CoachSessionTrustPolicy: ProximityTrustPolicy {
    private let vault: ProximityTrustVault

    public init(vault: ProximityTrustVault) {
        self.vault = vault
    }

    public func isTrustedProximityPeer(signingPublicKey: Data) -> Bool {
        guard let record = vault.peer(signingPublicKey: signingPublicKey) else { return false }
        // `unknownModeToken == nil` is load-bearing, not belt-and-braces: `.trainer` is the
        // decode FREEZE DEFAULT for a mode this build doesn't know
        // (`ProximityPersistenceRecords` parks the real token), and that record's contract says
        // the default is privilege-neutral only while nothing derives a privilege from stored
        // mode. This is the first reader that does — so a record synced from a NEWER build with
        // a future mode must read as "not a coach", never auto-confirm as one.
        return record.mode == .trainer && record.unknownModeToken == nil
            && record.revokedAt == nil && record.blockedAt == nil
    }

    public func isRevokedProximitySigningKey(_ publicKey: Data) -> Bool {
        vault.isBlockedProximitySigningKey(publicKey)
    }

    public func isBlockedProximitySigningKey(_ publicKey: Data) -> Bool {
        vault.isBlockedProximitySigningKey(publicKey)
    }

    public func recordTrainerAudit(_ event: TrainerAuditEvent) {
        vault.recordTrainerAudit(event)
    }
}
