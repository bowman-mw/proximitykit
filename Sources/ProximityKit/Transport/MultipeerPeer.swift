import Foundation
import MultipeerConnectivity
import FernletDomainModel
import FernletFoundation

/// A discovered MultipeerConnectivity peer, wrapped with a stable per-discovery `UUID` identity
/// and the parsed Bonjour discovery info (including the optional advertised fingerprint).
///
/// The value every transport/coordinator/manager API passes instead of raw `MCPeerID`s; equality
/// and hashing are by `id` only, so a peer whose discovery info updates stays the same peer.
/// `underlying` retains the framework `MCPeerID` for actual MC calls. Peer-supplied fields
/// (display name, discovery info) are untrusted wire data until the identity handshake verifies.
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
/// Persistence seam for the app's stable `MCPeerID`, so peer identity survives relaunches.
///
/// `MeshMultipeerSession` loads (or mints and saves) the archived ID through this at init;
/// ``FileMCPeerIDStore`` is the production conformer and tests inject in-memory fakes. The
/// ephemeral presence radio deliberately bypasses it (see `usesEphemeralPeerID`).
public protocol MCPeerIDStoring {
    nonisolated func load() -> MCPeerID?
    nonisolated func save(_ peerID: MCPeerID)
}

/// The production ``MCPeerIDStoring``: a keyed-archived `MCPeerID` in Application Support
/// (`FernletPeerID.archive`).
///
/// Best-effort file I/O — a failed load simply mints a fresh peer ID on the next launch.
/// Shared by the stable radios (mesh, recipe share) so their MC peer identity is continuous.
///
/// That continuity is exactly why the archive is part of the delete-all identity rotation
/// (``clearForDeleteAll()``): it holds `UIDevice.current.name` — in practice the user's own first
/// name — and the stable `MCPeerID` the mesh advertises, so a wipe that kept it would hand a
/// "brand-new Fernlet identity" the same name and the same on-air identifier as before.
public struct FileMCPeerIDStore: MCPeerIDStoring {
    public nonisolated let fileURL: URL

    public nonisolated init(fileURL: URL? = nil) {
        // `URL.applicationSupportDirectory` is the non-optional Foundation accessor for the same
        // path the optional `FileManager.urls(for:in:).first` used to produce (R5: no force unwrap).
        self.fileURL = fileURL ?? URL.applicationSupportDirectory
            .appendingPathComponent("FernletPeerID.archive")
    }

    public nonisolated func load() -> MCPeerID? {
        guard let data = try? Data(contentsOf: fileURL) else { return nil }
        return try? NSKeyedUnarchiver.unarchivedObject(ofClass: MCPeerID.self, from: data)
    }

    public nonisolated func save(_ peerID: MCPeerID) {
        // Best effort, but never silent: losing the archive costs MC peer-identity continuity
        // (a fresh MCPeerID next launch), so both failure paths are named in the audit log.
        let data: Data
        do {
            data = try NSKeyedArchiver.archivedData(withRootObject: peerID, requiringSecureCoding: true)
        } catch {
            FernletAuditLog.log(
                "proximity.peerIDStore.archiveFailed",
                context: ["error": String(describing: error)]
            )
            return
        }
        do {
            try data.write(to: fileURL, options: .atomic)
        } catch {
            FernletAuditLog.log(
                "proximity.peerIDStore.saveFailed",
                context: ["error": String(describing: error)]
            )
        }
    }

    /// Delete-all seam (Docs/PrivacyWipeCoverage.md): removes the archive so the next radio to
    /// start mints a fresh `MCPeerID` — a new display name and a new on-air identifier — instead of
    /// re-advertising the pre-wipe one.
    ///
    /// Safe to call with a live `MCSession`: `MeshMultipeerSession.localPeerID` is a `let` resolved
    /// once at init, so removing the file cannot mutate or invalidate a session already using it;
    /// the mint happens on the NEXT construction (see ``load()``, which returns nil for an absent
    /// file and lets the caller mint and ``save(_:)`` a replacement).
    ///
    /// - Throws: the underlying `FileManager` error when the archive exists and cannot be removed —
    ///   unlike ``save(_:)``, a wipe that silently left the identifier behind would make the
    ///   delete-all dialog's promise false. An absent archive is success.
    public nonisolated func clearForDeleteAll() throws {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return }
        do {
            try FileManager.default.removeItem(at: fileURL)
        } catch {
            FernletAuditLog.log(
                "proximity.peerIDStore.clearFailed",
                context: ["error": String(describing: error)]
            )
            throw error
        }
    }
}
