import Foundation

/// Cached prekey bundles gossiped by friends, plus this device's per-friend consumed-prekey
/// marking (bitchat adoptions Increment 3). Provenance: a bundle is only ever stored from a
/// verified, signed identity intro (`ProximityCoordinator` hands it over post-`verify`), keyed by
/// the sender's full signing key. Contents are public keys + consumption bookkeeping — a plain
/// sidecar like `HeartLedger.json`, never synced.
@MainActor
public final class HeartDropPeerBundleCache {

    private struct PeerState: Codable {
        var bundle: HeartPrekeyStore.Bundle
        var consumedIDs: Set<UUID> = []
    }

    private let fileURL: URL
    private let now: () -> Date
    private var peers: [String: PeerState] // key: signing key hex

    public init(fileURL: URL? = nil, now: @escaping () -> Date = { Date() }) {
        self.fileURL = fileURL ?? FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Fernlet/HeartDropPeerBundles.json")
        self.now = now
        if let data = try? Data(contentsOf: self.fileURL),
           let peers = try? JSONDecoder().decode([String: PeerState].self, from: data) {
            self.peers = peers
        } else {
            self.peers = [:]
        }
    }

    /// Stores/refreshes a friend's gossiped bundle. A NEW bundle id resets consumption marking;
    /// re-receiving the same bundle keeps it (so a re-intro can't reset one-time semantics).
    public func store(bundle: HeartPrekeyStore.Bundle, forFriendSigningKey key: Data) {
        let mapKey = Self.mapKey(key)
        if var existing = peers[mapKey], existing.bundle.bundleID == bundle.bundleID {
            existing.bundle = bundle
            peers[mapKey] = existing
        } else {
            peers[mapKey] = PeerState(bundle: bundle)
        }
        persist()
    }

    /// Picks an unconsumed, unexpired prekey for the friend and marks it consumed locally
    /// (sender-side one-time semantics — the recipient retains private halves until bundle
    /// expiry + grace because two senders can race the same broadcast bundle).
    public func consumePrekey(forFriendSigningKey key: Data) -> (id: UUID, publicKey: Data)? {
        let mapKey = Self.mapKey(key)
        guard var state = peers[mapKey], state.bundle.expires > now() else { return nil }
        guard let entry = state.bundle.keys.first(where: { !state.consumedIDs.contains($0.id) }) else {
            return nil
        }
        state.consumedIDs.insert(entry.id)
        peers[mapKey] = state
        persist()
        return (entry.id, entry.publicKey)
    }

    /// Delete-all seam (Docs/PrivacyWipeCoverage.md).
    public func wipeForDeleteAll() {
        peers = [:]
        try? FileManager.default.removeItem(at: fileURL)
    }

    private static func mapKey(_ key: Data) -> String {
        key.map { String(format: "%02x", $0) }.joined()
    }

    private func persist() {
        try? FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        guard let data = try? JSONEncoder().encode(peers) else { return }
        try? data.write(to: fileURL, options: [.atomic, .completeFileProtection])
    }
}
