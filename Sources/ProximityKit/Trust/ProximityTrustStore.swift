// ProximityTrustStore.swift
// ProximityKit/Trust
//
// The trust questions ProximityKit's managers ask of the host's durable trust records, outside any
// one session's policy: whether a signing key belongs to a peer the device remembers and has not
// removed, and whether it is blocked. The records are the host's (Fernlet's `ProximityTrustVault`,
// in `FernletConnections`, mints and normalizes them and Fernlet's snapshot persists them), so this
// module asks through a protocol and keeps no record of its own.

import Foundation

/// The host's durable trust records, as the two questions ProximityKit asks of them: is a signing key
/// a remembered, unrevoked peer, and is it blocked.
///
/// The managers ask through ``ProximityHost/proximityTrustStore`` wherever a feature is for kept
/// friends only: ``MeshNetworkManager`` before it takes in or sends a friend-state payload or a
/// moderation report, and ``PresenceManager``'s heart eligibility before a heart from or to a peer is
/// recorded, in person or routed (the mesh's routed heart path asks the same check). A
/// ``ProximityTrustPolicy`` is a different thing: the rule one session's coordinator consults while
/// its connection runs, which for a friend session trusts every peer; the store answers what the
/// device remembers, whichever session is running.
///
/// This module ships no conformer and keeps no records. Fernlet's is `ProximityTrustVault`
/// (`FernletConnections`), which also mints, normalizes and keeps Fernlet's trusted-peer records and
/// audit rows for its snapshot to persist. Its answers must come from the same records as
/// ``ProximityHost/trustedProximityPeers``, which ``PresenceManager`` reads for the friends it derives
/// presence tags and a heart connection's sealing key from.
///
/// Main-actor, like ``ProximityHost`` and the managers that ask it.
@MainActor
public protocol ProximityTrustStore: AnyObject {
    /// Whether `signingPublicKey` belongs to a peer the device remembers and has not removed.
    ///
    /// - Parameter signingPublicKey: The peer's Ed25519 signing key.
    /// - Returns: `true` for a remembered, unrevoked peer.
    func isTrustedProximityPeer(signingPublicKey: Data) -> Bool

    /// Whether `publicKey` is blocked.
    ///
    /// - Parameter publicKey: The peer's Ed25519 signing key.
    /// - Returns: `true` for a blocked key.
    func isBlockedProximitySigningKey(_ publicKey: Data) -> Bool
}
