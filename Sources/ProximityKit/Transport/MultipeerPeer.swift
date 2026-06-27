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

public protocol MCPeerIDStoring {
    func load() -> MCPeerID?
    func save(_ peerID: MCPeerID)
}

public struct FileMCPeerIDStore: MCPeerIDStoring {
    public let fileURL: URL

    public init(fileURL: URL? = nil) {
        self.fileURL = fileURL ?? {
            let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            return support.appendingPathComponent("FernletPeerID.archive")
        }()
    }

    public func load() -> MCPeerID? {
        guard let data = try? Data(contentsOf: fileURL) else { return nil }
        return try? NSKeyedUnarchiver.unarchivedObject(ofClass: MCPeerID.self, from: data)
    }

    public func save(_ peerID: MCPeerID) {
        guard let data = try? NSKeyedArchiver.archivedData(withRootObject: peerID, requiringSecureCoding: true) else { return }
        try? data.write(to: fileURL, options: .atomic)
    }
}
