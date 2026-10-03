import Foundation

// The trust questions a ProximityCoordinator asks, and the door its session audit goes out through,
// in this module's own ProximitySessionAudit (ProximitySessionAudit.swift). The records a host
// persists are the host's: Fernlet's, ProximityTrustedPeerRecord and TrainerAuditEvent, live in
// FernletDomainModel, and its policies in FernletConnections convert each audit into its row.

/// The trust decisions a ``ProximityCoordinator`` consults while handling inbound envelopes:
/// revoked-key hard fail, blocked-key silent drop, remembered-trust auto-confirm, and the audit sink.
///
/// This module ships no conformer: the session policies are the host's, handed out one per
/// connection by ``ProximityHost/makeProximityTrustPolicy()``. Fernlet's live in `FernletConnections`:
/// `FriendSessionTrustPolicy` (friend radios — proximity IS the authorization, so trust is
/// unconditional) and `CoachSessionTrustPolicy` (coach channel — only a remembered `.trainer`
/// pairing auto-confirms), each answering from a ``ProximityTrustVault`` and keeping its audits there.
/// Coordinators hold this `weak`, so every owner must retain its policy for the connection's
/// lifetime or the revoked/blocked drops silently stop firing.
@MainActor
public protocol ProximityTrustPolicy: AnyObject {
    func isRevokedProximitySigningKey(_ publicKey: Data) -> Bool
    func isBlockedProximitySigningKey(_ publicKey: Data) -> Bool
    func isTrustedProximityPeer(signingPublicKey: Data) -> Bool
    /// Records one event the coordinator reports, in this module's own type. A policy that keeps an
    /// audit trail converts it into its own row (Fernlet's, into its persisted `TrainerAuditEvent`);
    /// one that keeps none ignores it.
    func recordSessionAudit(_ audit: ProximitySessionAudit)
}
