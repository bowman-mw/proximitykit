// ProximitySessionAudit.swift
// ProximityKit/Trust
//
// What a `ProximityCoordinator` records through its trust policy as a session runs: the session's
// start, every state change, each envelope it sent, took in or refused, an envelope from a revoked
// key, the session's end and its failure. In this module's own value type, so the mechanism names
// no host's persisted record: a policy that keeps an audit trail converts each value into its own
// row. Fernlet's policies (`FernletConnections`) convert it into the `TrainerAuditEvent` their trust
// vault keeps and Fernlet's snapshot persists.
//
// `nonisolated` + `Sendable` against ProximityKit's `.defaultIsolation(MainActor.self)`: an inert
// value a policy may hand on to any actor.

import Foundation

/// One event a ``ProximityCoordinator`` records through its ``ProximityTrustPolicy``: what happened,
/// to which peer, and the payload token of the envelope it concerns.
///
/// The coordinator builds one at each of its audit sites and hands it straight to
/// ``ProximityTrustPolicy/recordSessionAudit(_:)``; it never sends, persists or reads one back. The
/// type names no host's record, and its payload token is a plain string, because what a token means
/// is the host's vocabulary: a policy that keeps an audit trail converts each value into a row of its
/// own. Fernlet's policies (`FernletConnections`) convert it into the persisted `TrainerAuditEvent`
/// their trust vault keeps, field for field, reading the token as Fernlet's `PayloadType`.
///
/// `nonisolated` and `Sendable` against this module's `defaultIsolation(MainActor.self)`: an inert
/// value a policy may hand on to any actor.
public nonisolated struct ProximitySessionAudit: Equatable, Sendable {

    /// What the coordinator saw. Each raw value is its case's name.
    public nonisolated enum Kind: String, CaseIterable, Sendable {
        /// A session began; the message names the role and mode it began in.
        case pairingStarted
        /// The coordinator entered a new state; the message is that state's label.
        case stateTransition
        /// An envelope verified and was taken in.
        case envelopeReceived
        /// An envelope was sent to the connected peer.
        case envelopeSent
        /// An inbound frame was refused: too large for a trainer-mode session, or an envelope that
        /// failed to decode or verify.
        case envelopeRejected
        /// An envelope signed by a key the policy reports revoked was refused, and the session failed.
        case revokedPeerBlocked
        /// The session ended, for its end reason or at its connection-phase timeout.
        case sessionEnded
        /// The session failed; the message is the reason.
        case error
    }

    /// Unique to this event, minted where the coordinator builds it.
    public let id: UUID
    /// When the coordinator built it: the initializer's default, the wall clock, never the
    /// coordinator's injected `now`.
    public let timestamp: Date
    /// What happened.
    public let kind: Kind
    /// The peer's fingerprint as far as the coordinator knew it then (the verified identity's, the
    /// pending one's, an inbound envelope's signer's, or the one the transport advertised), or `nil`.
    public let peerFingerprint: String?
    /// The peer's name as the coordinator records it (a disclosed name, else the fingerprint; before
    /// any handshake, the transport's display hint), or `nil`.
    public let peerDisplayName: String?
    /// The payload token of the envelope the event concerns, exactly as it was sent or arrived
    /// (`FernletIdentityEnvelope.payloadTypeToken`), a token the host does not know included; `nil`
    /// where the event names no decoded envelope.
    public let payloadType: String?
    /// What happened, as an English diagnostic line; never localized.
    public let message: String

    /// Builds one event. `id` and `timestamp` default to a fresh id and the current time, which is
    /// what the coordinator takes.
    public init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        kind: Kind,
        peerFingerprint: String? = nil,
        peerDisplayName: String? = nil,
        payloadType: String? = nil,
        message: String
    ) {
        self.id = id
        self.timestamp = timestamp
        self.kind = kind
        self.peerFingerprint = peerFingerprint
        self.peerDisplayName = peerDisplayName
        self.payloadType = payloadType
        self.message = message
    }
}
