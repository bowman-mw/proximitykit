import Foundation
import FernletDomainModel

// ProximityTrustedPeerRecord and TrainerAuditEvent were carved DOWN into the FernletDomainModel
// module (FernletKit/Sources/FernletDomainModel/ProximityPersistenceRecords.swift) so the
// persistence layer can reference them without an upward edge. The audit-log LOGIC stays here.

@MainActor
public protocol ProximityTrustPolicy: AnyObject {
    func isRevokedProximitySigningKey(_ publicKey: Data) -> Bool
    func isBlockedProximitySigningKey(_ publicKey: Data) -> Bool
    func isTrustedProximityPeer(signingPublicKey: Data) -> Bool
    func recordTrainerAudit(_ event: TrainerAuditEvent)
}
