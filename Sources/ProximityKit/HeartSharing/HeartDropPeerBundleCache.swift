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
        /// Last store/consume touch — the LRU eviction key. Optional so a sidecar written before
        /// the cap existed decodes; those rows fall back to the bundle's own `created`.
        var lastUsedAt: Date?

        func lruStamp() -> Date { lastUsedAt ?? bundle.created }
    }

    /// Cap on cached peers, with LRU eviction (bitchat's `PrekeyBundleStore` uses the same 200).
    /// Bundles arrive from every verified intro — not only from friends — so without a cap a
    /// device that meets many strangers grows this file forever.
    public static let maxPeers = 200
    /// Sanity bound on a peer-supplied bundle: the minter makes 16, so this leaves room for a
    /// future batch size while refusing a gossiped bundle built to bloat the sidecar.
    public static let maxBundleKeys = 64
    /// Refuse to SEAL to a bundle older than this, falling back to the static key. A month-old
    /// bundle's one-time keys have been sitting in the recipient's keychain the whole time, so
    /// their forward secrecy is mostly notional; bitchat draws the same 7-day line. This is a
    /// seal-side cap only — the recipient still retains its private halves to expiry, so drops
    /// already in flight against an older bundle keep opening.
    public static let maxSealBundleAge: TimeInterval = 7 * 24 * 3600

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

    /// Stores/refreshes a friend's gossiped bundle. A NEWER bundle id resets consumption marking;
    /// re-receiving the same bundle keeps it (so a re-intro can't reset one-time semantics).
    ///
    /// Monotonicity guard: bundles gossip from two coordinators (mesh and presence), so an intro
    /// built BEFORE a rotation can arrive AFTER one built later. A strictly older bundle must
    /// never replace a newer one — doing so would also clear `consumedIDs` and re-enable prekeys
    /// we already sealed to, silently degrading forward secrecy toward the static key.
    public func store(bundle: HeartPrekeyStore.Bundle, forFriendSigningKey key: Data) {
        guard !bundle.keys.isEmpty, bundle.keys.count <= Self.maxBundleKeys,
              bundle.expires > now() else { return }
        let mapKey = Self.mapKey(key)
        if var existing = peers[mapKey] {
            if existing.bundle.bundleID == bundle.bundleID {
                existing.bundle = bundle
            } else if bundle.created > existing.bundle.created {
                existing = PeerState(bundle: bundle)
            } else {
                // Same-age-or-older rival bundle: keep what we have, but count the touch so an
                // actively-gossiping peer doesn't age out of the LRU.
                existing.lastUsedAt = now()
                peers[mapKey] = existing
                persist()
                return
            }
            existing.lastUsedAt = now()
            peers[mapKey] = existing
        } else {
            peers[mapKey] = PeerState(bundle: bundle, lastUsedAt: now())
        }
        evictIfOverCap()
        persist()
    }

    /// Picks an unconsumed, unexpired, still-fresh prekey for the friend and marks it consumed
    /// locally (sender-side one-time semantics — the recipient retains private halves until bundle
    /// expiry + grace because two senders can race the same broadcast bundle). Nil means "seal to
    /// the static key instead", never "don't send".
    public func consumePrekey(forFriendSigningKey key: Data) -> (id: UUID, publicKey: Data)? {
        let mapKey = Self.mapKey(key)
        let currentTime = now()
        guard var state = peers[mapKey], state.bundle.expires > currentTime,
              currentTime.timeIntervalSince(state.bundle.created) <= Self.maxSealBundleAge else { return nil }
        guard let entry = state.bundle.keys.first(where: { !state.consumedIDs.contains($0.id) }) else {
            return nil
        }
        state.consumedIDs.insert(entry.id)
        state.lastUsedAt = currentTime
        peers[mapKey] = state
        persist()
        return (entry.id, entry.publicKey)
    }

    /// Un-consumes a prekey whose send never made it onto the wire. A one-time key burned without
    /// ever being sealed to is pure loss: the bundle holds 16, and once they are gone every drop
    /// to that friend falls back to the static key with no forward secrecy. Only un-consumes when
    /// the cached bundle still contains the id, so a rotation in between is a no-op.
    public func returnPrekey(id: UUID, forFriendSigningKey key: Data) {
        let mapKey = Self.mapKey(key)
        guard var state = peers[mapKey], state.consumedIDs.contains(id),
              state.bundle.keys.contains(where: { $0.id == id }) else { return }
        state.consumedIDs.remove(id)
        peers[mapKey] = state
        persist()
    }

    /// Delete-all seam (Docs/PrivacyWipeCoverage.md).
    public func wipeForDeleteAll() {
        peers = [:]
        try? FileManager.default.removeItem(at: fileURL)
    }

    /// Drops the least-recently-touched peers past the cap, and any bundle already past its own
    /// expiry (it can never be sealed to again).
    private func evictIfOverCap() {
        let currentTime = now()
        peers = peers.filter { $0.value.bundle.expires > currentTime }
        guard peers.count > Self.maxPeers else { return }
        let survivors = peers
            .sorted { $0.value.lruStamp() > $1.value.lruStamp() }
            .prefix(Self.maxPeers)
        peers = Dictionary(uniqueKeysWithValues: survivors.map { ($0.key, $0.value) })
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
