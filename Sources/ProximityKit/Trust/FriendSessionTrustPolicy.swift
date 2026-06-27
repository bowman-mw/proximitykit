import Foundation
import FernletDomainModel

public final class FriendSessionTrustPolicy: ProximityTrustPolicy {
    private let vault: ProximityTrustVault

    public init(vault: ProximityTrustVault) {
        self.vault = vault
    }

    public func isRevokedProximitySigningKey(_ publicKey: Data) -> Bool {
        vault.isRevokedProximitySigningKey(publicKey)
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
