import Foundation
import FernletDomainModel

/// Failures of the mesh group-key photo/metadata AES-GCM crypto.
///
/// Thrown by ``MeshNetworkManager``'s static encrypt/decrypt helpers; callers treat every case
/// as "drop the payload".
enum MeshEncryptionError: Error, Equatable {
    case decryptionFailed
    case encryptionFailed
    /// The bytes carry no `FMGP2` / `FMGM2` format marker — the shape of the retired mesh wire
    /// format a peer on an older build sends.
    ///
    /// Named separately from ``decryptionFailed`` on purpose: the crypto standardization round's
    /// Phase 4 deleted the reader for that format, and a peer that still speaks it must be refused
    /// with a reason the receiving surface can explain rather than folded into the generic "this
    /// did not decrypt" that also covers a wrong key, a stale epoch and a tampered payload. The
    /// retired format had no marker of its own, so this case cannot separate an older build from
    /// malformed bytes — it separates both from a payload that reached the AEAD and was rejected
    /// there, which is the distinction the audit trail actually needs.
    case legacyWireFormat
}

/// A slot's traffic class in the capped mesh session.
///
/// ``MeshNetworkManager`` re-ranks slots by stable distance: the nearest peers get the three
/// `active` slots (full payload routing) and the rest fall to `lightweight` (heartbeats only).
public enum SlotKind {
    case active      // full payload routing, up to 3
    case lightweight // heartbeats only, up to 2
}

/// One peer's seat in the live mesh session: the transport channel, its ``ProximityCoordinator``,
/// and the handshake-verified identity captured at commit.
///
/// Owned exclusively by ``MeshNetworkManager``, which appends a slot when an MC channel comes up
/// and fills `fingerprint` / the verified key fields only when the coordinator reaches
/// `.connected` — a nil `fingerprint` means an UNCOMMITTED candidate, which the feature-payload
/// registry gate must drop. `verifiedKeyAgreementPublicKey` is the sealing target for every
/// pairwise-sealed send (never descriptor gossip); `peerCapabilities` gates room broadcasts.
/// Memory-only session state, never persisted.
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
    /// Raw capability tokens the peer advertised in its identity intro/ack (Phase 1), captured at slot
    /// commit from `ProximityCoordinator.PeerIdentity`. `nil` = a legacy peer whose intro predates
    /// capability advertisement (treated as photos-only). Lets a room broadcast (e.g. temp messages)
    /// skip slots whose peer can't use the payload, without re-plumbing the PeerIdentity to the sender.
    var peerCapabilities: [String]? = nil
    var joinedEpoch: Int = 0
    var distanceSamples: [MeshDistanceSample] = []
    var stableDistanceMeters: Double?
    var isOverflowCandidate = false

    /// Phase 1 capability gate for room broadcasts, mirroring `ProximityCoordinator.PeerIdentity.supports`:
    /// a legacy peer with no advertised capabilities is photos-only.
    func supports(_ capability: ProximityCapability) -> Bool {
        guard let peerCapabilities else { return capability == .photos }
        return peerCapabilities.contains(capability.rawValue)
    }
}

/// In-memory symmetric group key for the current mesh session, tagged with its rotation epoch.
///
/// Distributed pairwise-wrapped by the elected coordinator (`encryptGroupKey`) and rotated every
/// 15 minutes; used for closed-mode photo/metadata AES-GCM. Never written to disk or keychain;
/// lost on app termination or mesh leave.
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

/// One timestamped UWB distance reading for a slot.
///
/// ``MeshNetworkManager`` keeps a 10-second rolling window of these per slot to compute the
/// stable distance that drives slot ranking and overflow eviction.
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

/// Display row for one member of the current session (mesh members or committed pairwise slots),
/// including the local device.
///
/// Derived on demand by `MeshNetworkManager.sessionParticipants` for the session UI and photo
/// metadata; identity is the fingerprint. Not persisted.
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
