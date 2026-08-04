import Foundation
import FernletDomainModel

// ProximityTrustedPeerRecord and TrainerAuditEvent were carved DOWN into the FernletDomainModel
// module (FernletKit/Sources/FernletDomainModel/ProximityPersistenceRecords.swift) so the
// persistence layer can reference them without an upward edge. The audit-log LOGIC stays here.

/// The trust decisions a ``ProximityCoordinator`` consults while handling inbound envelopes:
/// revoked-key hard fail, blocked-key silent drop, remembered-trust auto-confirm, and the audit sink.
///
/// Three conformers give the same questions different answers per channel: ``ProximityTrustVault``
/// (the persistent record store, answering from stored peer records), ``FriendSessionTrustPolicy``
/// (friend radios — proximity IS the authorization, so trust is unconditional), and
/// ``CoachSessionTrustPolicy`` (coach channel — only a remembered `.trainer` pairing auto-confirms).
/// Coordinators hold this `weak`, so every owner must retain its policy for the connection's
/// lifetime or the revoked/blocked drops silently stop firing.
@MainActor
public protocol ProximityTrustPolicy: AnyObject {
    func isRevokedProximitySigningKey(_ publicKey: Data) -> Bool
    func isBlockedProximitySigningKey(_ publicKey: Data) -> Bool
    func isTrustedProximityPeer(signingPublicKey: Data) -> Bool
    func recordTrainerAudit(_ event: TrainerAuditEvent)
}
