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
