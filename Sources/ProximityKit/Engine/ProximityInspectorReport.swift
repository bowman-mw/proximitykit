// ProximityInspectorReport.swift
// ProximityKit/Engine
//
// What a `ProximityCoordinator` reports to the `ProximityInspectorRecording` its owner attaches, in
// this module's own value types: an envelope it sent or received, a distance sample, the peer as it
// knows it at that moment, and its transport's state changes and heartbeat round trips. None names a
// host's log. A conformer that keeps one converts each value into its own record: Fernlet's app-side
// `ConnectionInspector` builds its persisted `ConnectionSessionLog` from them, field for field. Every
// value is locally observed diagnostics: this module never sends one, never persists one and never
// trusts one as wire data.
//
// `nonisolated` + `Sendable` against ProximityKit's `.defaultIsolation(MainActor.self)`: inert values
// a conformer may hand on to any actor.

import Foundation
import simd

// MARK: - Envelope

/// One signed envelope a ``ProximityCoordinator`` sent or received, as it reports it to its
/// inspector: size, verification outcome and whether it was sealed — never the payload itself.
public nonisolated struct ProximityInspectorEnvelope: Equatable, Sendable {

    /// Whether this device sent the envelope or received it from the peer.
    public nonisolated enum Direction: Equatable, Sendable {
        /// Sent by this device.
        case sent
        /// Received from the peer; the coordinator reports one only after it verified.
        case received
    }

    /// The envelope's own ID.
    public let envelopeID: UUID
    /// Whether this device sent it or received it.
    public let direction: Direction
    /// Its raw payload token, a token this build does not know included.
    public let payloadType: String
    /// The encoded envelope's size in bytes, as sent or as received.
    public let payloadByteCount: Int
    /// When the coordinator recorded it, on the coordinator's clock.
    public let timestamp: Date
    /// Whether its signature verified; `nil` where nothing was checked.
    public let signatureVerified: Bool?
    /// Whether its payload was sealed to a recipient key.
    public let encrypted: Bool
    /// The sender's summary title (frozen English, never localized), or the payload token when the
    /// payload was sealed.
    public let summary: String

    /// Builds the record of one envelope from each of its fields.
    public init(
        envelopeID: UUID,
        direction: Direction,
        payloadType: String,
        payloadByteCount: Int,
        timestamp: Date,
        signatureVerified: Bool?,
        encrypted: Bool,
        summary: String
    ) {
        self.envelopeID = envelopeID
        self.direction = direction
        self.payloadType = payloadType
        self.payloadByteCount = payloadByteCount
        self.timestamp = timestamp
        self.signatureVerified = signatureVerified
        self.encrypted = encrypted
        self.summary = summary
    }
}

// MARK: - Distance sample

/// One distance a ``ProximityCoordinator`` measured to its peer, as it reports it to its inspector:
/// when, how far, and the UWB direction when the ranging session gave one.
public nonisolated struct ProximityInspectorDistanceSample: Equatable, Sendable {
    /// When the coordinator took it, on the coordinator's clock.
    public let timestamp: Date
    /// The measured distance, in meters.
    public let meters: Double
    /// The direction to the peer, when the ranging session reported one.
    public let direction: simd_float3?

    /// Builds one sample.
    public init(timestamp: Date, meters: Double, direction: simd_float3? = nil) {
        self.timestamp = timestamp
        self.meters = meters
        self.direction = direction
    }
}

// MARK: - Peer

/// The peer as a ``ProximityCoordinator`` knows it at one moment, as it reports it to its inspector:
/// what the peer advertised and what the identity handshake verified, kept apart.
public nonisolated struct ProximityInspectorPeer: Equatable, Sendable {
    /// The name to show: the verified identity's name, its fingerprint while that name is withheld,
    /// else the transport's display hint, else `Unknown`.
    public let displayName: String
    /// The fingerprint the peer advertised before any handshake, when it advertised one.
    public let advertisedFingerprint: String?
    /// The fingerprint the identity handshake verified, once it has.
    public let confirmedFingerprint: String?
    /// The verified identity's Ed25519 signing key, once the handshake has verified one.
    public let signingPublicKey: Data?
    /// When the coordinator first saw the verified identity, or the moment of this report before
    /// there is one.
    public let firstSeenAt: Date
    /// The moment of this report, on the coordinator's clock.
    public let lastSeenAt: Date

    /// Builds the report of one peer from each of its fields.
    public init(
        displayName: String,
        advertisedFingerprint: String?,
        confirmedFingerprint: String?,
        signingPublicKey: Data?,
        firstSeenAt: Date,
        lastSeenAt: Date
    ) {
        self.displayName = displayName
        self.advertisedFingerprint = advertisedFingerprint
        self.confirmedFingerprint = confirmedFingerprint
        self.signingPublicKey = signingPublicKey
        self.firstSeenAt = firstSeenAt
        self.lastSeenAt = lastSeenAt
    }
}

// MARK: - Transport event

/// One thing a ``ProximityCoordinator`` reports about its transport to its inspector: a change of
/// the channel's state, stamped with the coordinator's own clock, or one heartbeat round trip.
///
/// A conformer that keeps transport info applies each event to it in order: the new state replaces
/// the old, a session keeps its FIRST connected stamp and its LAST disconnected one, and round trips
/// accumulate under a bound of the conformer's choosing (Fernlet's keeps the latest 50).
public nonisolated enum ProximityInspectorTransportEvent: Equatable, Sendable {
    /// The channel entered `state`, a diagnostic label: `connecting`, `connected`, `notConnected` or
    /// `failed`. `connectedAt` is the coordinator's clock reading when `state` is `connected`, else
    /// `nil`; `disconnectedAt` is its reading when the channel closed or failed, else `nil`.
    case stateChanged(state: String, connectedAt: Date?, disconnectedAt: Date?)
    /// A heartbeat's acknowledgement arrived `milliseconds` after its ping was sent, measured on the
    /// coordinator's clock and never negative.
    case roundTrip(milliseconds: Double)
}
