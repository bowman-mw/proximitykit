import Foundation
import FernletDomainModel

enum MeshEncryptionError: Error {
    case decryptionFailed
    case encryptionFailed
}

public enum SlotKind {
    case active      // full payload routing, up to 3
    case lightweight // heartbeats only, up to 2
}

public struct PeerSlot: Identifiable {
    public let id: UUID  // == peer.id
    public let peer: MultipeerPeer
    let channel: PeerChannelTransport
    public let coordinator: ProximityCoordinator
    public var kind: SlotKind
    public var fingerprint: String?
    // Handshake-verified Ed25519 key used for key-based block operations.
    var verifiedSigningPublicKey: Data? = nil
    // Handshake-verified X25519 key agreement public key used for group key wrapping.
    // Set from ProximityCoordinator.PeerIdentity after identity exchange, never descriptor gossip.
    var verifiedKeyAgreementPublicKey: Data?
    var joinedEpoch: Int = 0
    var distanceSamples: [MeshDistanceSample] = []
    var stableDistanceMeters: Double?
    var isOverflowCandidate = false
}

/// In-memory symmetric group key for the current mesh session.
/// Never written to disk or keychain; lost on app termination or mesh leave.
public struct MeshGroupKey {
    public let epoch: Int
    public let keyBytes: Data   // 32 bytes
    public let activeSince: Date

    public init(epoch: Int, keyBytes: Data, activeSince: Date) {
        self.epoch = epoch
        self.keyBytes = keyBytes
        self.activeSince = activeSince
    }
}

struct MeshDistanceSample: Equatable {
    let recordedAt: Date
    let meters: Double
}

/// A handshake-committed participant of the current proximity session, retained for the
/// post-session keep-as-friend prompt (Phase 2, Docs/Proximity-Mesh-Redesign-2026-07-10.md).
/// Deliberately NOT Codable: this is memory-only key material — never persisted, never synced,
/// never part of a snapshot. Entries survive slot teardown (the review UI fires after
/// `leaveSession` clears slots, and the non-initiating side of a 2-person session loses its slot
/// before its review fires) and reset only when the next session begins or the UI consumes them.
public nonisolated struct MeshSessionRosterEntry: Identifiable, Equatable, Sendable {
    /// Stable per-peer identity within the session; the roster dedupes on it.
    public var id: String { fingerprint }
    /// Last write wins across re-commits within a session.
    public internal(set) var displayName: String
    public let fingerprint: String
    public let signingPublicKey: Data
    public let keyAgreementPublicKey: Data

    public init(
        displayName: String,
        fingerprint: String,
        signingPublicKey: Data,
        keyAgreementPublicKey: Data
    ) {
        self.displayName = displayName
        self.fingerprint = fingerprint
        self.signingPublicKey = signingPublicKey
        self.keyAgreementPublicKey = keyAgreementPublicKey
    }
}

/// A promoted, unconsumed session-end friend review (Phase 2, "Session-end review is
/// model-state, not view-events" — Docs/Proximity-Mesh-Redesign-2026-07-10.md). The manager
/// moves the live `sessionRoster` into one of these whenever the last committed slot disappears;
/// views present off this observable state instead of `isInSession` view-events (the Social-tab
/// layout swap destroys the presenting view in the same transaction as the `isInSession` flip).
/// Like the roster entries it carries, this is deliberately NOT Codable: memory-only key
/// material — never persisted, never synced. It survives `startJoin`/`startNewMesh` so an
/// unreviewed batch from the previous session re-presents (merged) after the next teardown.
public nonisolated struct MeshFriendReviewBatch: Identifiable, Equatable, Sendable {
    public let id: UUID
    public internal(set) var entries: [MeshSessionRosterEntry]

    public init(id: UUID = UUID(), entries: [MeshSessionRosterEntry]) {
        self.id = id
        self.entries = entries
    }
}

public struct MeshSessionParticipant: Identifiable, Equatable {
    public var id: String { fingerprint }

    public let fingerprint: String
    public let displayName: String
    public let isLocal: Bool

    public init(fingerprint: String, displayName: String, isLocal: Bool) {
        self.fingerprint = fingerprint
        self.displayName = displayName
        self.isLocal = isLocal
    }
}
