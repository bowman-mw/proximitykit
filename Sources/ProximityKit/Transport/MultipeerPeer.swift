import Foundation
import MultipeerConnectivity
import FernletDomainModel

public struct MultipeerPeer: Hashable, Identifiable {
    public let id: UUID
    public let displayName: String
    public let discoveryInfo: [String: String]?
    public let advertisedFingerprint: String?
    public let underlying: MCPeerID

    public init(
        id: UUID,
        displayName: String,
        discoveryInfo: [String: String]?,
        advertisedFingerprint: String?,
        underlying: MCPeerID
    ) {
        self.id = id
        self.displayName = displayName
        self.discoveryInfo = discoveryInfo
        self.advertisedFingerprint = advertisedFingerprint
        self.underlying = underlying
    }

    public static func == (lhs: MultipeerPeer, rhs: MultipeerPeer) -> Bool { lhs.id == rhs.id }
    public func hash(into hasher: inout Hasher) { hasher.combine(id) }
}

// Pure persistence contract — explicitly `nonisolated` so it is NOT swept into the
// target's `defaultIsolation(MainActor.self)`. The store holds no main-actor state
// (FileMCPeerIDStore is plain file I/O), so keeping it nonisolated preserves its
// off-main callability under Swift 6 mode — behaviour-identical to the prior Swift 5
// language mode, where `defaultIsolation` did not surface as a hard cross-module
// constraint. (Both MeshMultipeerSession.init and the unit tests use it off-main.)
// Mirrors WI-9's nonisolated wire types.
public protocol MCPeerIDStoring {
    nonisolated func load() -> MCPeerID?
    nonisolated func save(_ peerID: MCPeerID)
}

public struct FileMCPeerIDStore: MCPeerIDStoring {
    public nonisolated let fileURL: URL

    public nonisolated init(fileURL: URL? = nil) {
        self.fileURL = fileURL ?? {
            let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            return support.appendingPathComponent("FernletPeerID.archive")
        }()
    }

    public nonisolated func load() -> MCPeerID? {
        guard let data = try? Data(contentsOf: fileURL) else { return nil }
        return try? NSKeyedUnarchiver.unarchivedObject(ofClass: MCPeerID.self, from: data)
    }

    public nonisolated func save(_ peerID: MCPeerID) {
        guard let data = try? NSKeyedArchiver.archivedData(withRootObject: peerID, requiringSecureCoding: true) else { return }
        try? data.write(to: fileURL, options: .atomic)
    }
}
