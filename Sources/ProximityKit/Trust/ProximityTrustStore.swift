// ProximityTrustStore.swift
// ProximityKit/Trust
//
// The trust questions a host's features ask of its durable trust records, outside any one session's
// policy: whether a signing key belongs to a peer the device remembers and has not removed, and
// whether it is blocked. The records are the host's (Fernlet's `ProximityTrustVault`, in
// `FernletConnections`, mints and normalizes them and Fernlet's snapshot persists them), so they are
// asked through a protocol that keeps no record of its own. The protocol stays in this module, and
// FernletConnections' vault conforms to it; since plan step A0.5.10 no code here asks it: FernletSocial's
// features do, through `FernletSocialHost`, which also holds the heart-eligibility check that asks both
// questions beside the host's fingerprint block list.

import Foundation

/// The host's durable trust records, as the two questions a host's features ask of them: is a signing
/// key a remembered, unrevoked peer, and is it blocked.
///
/// Fernlet's features ask through FernletSocial's `FernletSocialHost.proximityTrustStore` wherever a
/// feature is for kept friends only: the friend-state and moderation-report exchanges before they take
/// in or send a payload, and the heart-eligibility check,
/// `FernletSocialHost.isTrustedUnblockedPeer(signingPublicKey:fingerprint:)`, before a heart from or to
/// a peer is recorded, in person (`PresenceManager`) or routed (the session hearts' ledger judge). No
/// code in this module asks it since plan step A0.5.10, when those requirements left ``ProximityHost``.
/// A ``ProximityTrustPolicy`` is a different thing: the rule one session's coordinator
/// consults while its connection runs, which for a friend session trusts every peer; the store
/// answers what the device remembers, whichever session is running.
///
/// This module ships no conformer and keeps no records. Fernlet's is `ProximityTrustVault`
/// (`FernletConnections`), which also mints, normalizes and keeps Fernlet's trusted-peer records and
/// audit rows for its snapshot to persist. Its answers must come from the same records as
/// `FernletSocialHost.trustedProximityPeers`, which FernletSocial's `PresenceManager` reads for the
/// friends it derives presence tags and a heart connection's sealing key from.
///
/// Main-actor, like ``ProximityHost`` and the features that ask it.
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
