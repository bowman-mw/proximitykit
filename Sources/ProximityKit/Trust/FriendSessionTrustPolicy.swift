import Foundation
import FernletDomainModel

public final class FriendSessionTrustPolicy: ProximityTrustPolicy {
    private let vault: ProximityTrustVault

    public init(vault: ProximityTrustVault) {
        self.vault = vault
    }

    // Friend lifecycle semantics (Phase 2, Docs/Proximity-Mesh-Redesign-2026-07-10.md): the
    // friend-mode transport ban is for BLOCKED keys only. A revoked-only ("Removed") peer is an
    // unfriend, not a ban — they may handshake again in person and be re-offered by the keep
    // prompt after a fresh verified session, so the coordinator's hard-fail on this check must
    // not fire for them. Blocked stays a silent transport drop via isBlockedProximitySigningKey.
    public func isRevokedProximitySigningKey(_ publicKey: Data) -> Bool {
        vault.isBlockedProximitySigningKey(publicKey)
    }

    public func isBlockedProximitySigningKey(_ publicKey: Data) -> Bool {
        vault.isBlockedProximitySigningKey(publicKey)
    }

    // Friend sessions authorize through the proximity gate; remembered trust is not required.
    public func isTrustedProximityPeer(signingPublicKey: Data) -> Bool { true }

    public func recordTrainerAudit(_ event: TrainerAuditEvent) {
        vault.recordTrainerAudit(event)
    }
}
