import Foundation
import FernletFoundation

/// Cached prekey bundles gossiped by friends, plus this device's per-friend consumed-prekey
/// marking (bitchat adoptions Increment 3). Provenance: a bundle is only ever stored from a
/// verified, signed identity intro (`ProximityCoordinator` hands it over post-`verify`), keyed by
/// the sender's full signing key. Contents are public keys + consumption bookkeeping — a plain
/// sidecar like `HeartLedger.json`, never synced.
///
/// Loads through `ProtectedSidecar` (Track A, 2026-07-26) and fails closed while unavailable:
/// `consumePrekey` returns nil (the caller seals to the static key — the existing documented
/// fallback, so availability is preserved), and `store`/`returnPrekey` no-op (the bundle
/// re-gossips at the next verified intro). A consumption mark commits only if it persists: a
/// mark that lived only in memory would vanish in a crash and let the same one-time key be
/// sealed to twice.
@MainActor
public final class HeartDropPeerBundleCache {

    /// One friend's cached prekey material: their gossiped one-time bundle, this device's
    /// consumed-id marks against it, the independently-updated signed prekey, and the LRU stamp.
    private struct PeerState: Codable {
        var bundle: HeartPrekeyStore.Bundle
        var consumedIDs: Set<UUID> = []
        /// The peer's medium-term signed prekey, in its OWN slot (Track B Increment 6): it has
        /// its own monotonicity (newer `created` wins) and its own freshness cap, independent of
        /// the one-time bundle — an SPK-only refresh must never wipe the one-time slot, and a
        /// leaner bundle must never destroy a cached SPK. Optional so pre-change rows decode.
        var signedPrekey: HeartPrekeyStore.SignedPrekey?
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
    /// The signed prekey's own seal window (O2: 14 d seal window → 29 d retention), deliberately
    /// longer than the one-time window — the SPK exists precisely for friends not seen in a
    /// while. `HeartPrekeyStore.spkRetention` must exceed this + the outbox lifetime + skew
    /// (invariant test), or drops sealed near the end of the window silently fail to open.
    public static let maxSealSignedPrekeyAge: TimeInterval = 14 * 24 * 3600
    /// Raw X25519 public-key length — the entry validation a peer-supplied bundle must satisfy.
    static let rawCurve25519KeyByteCount = 32

    private let sidecar: ProtectedSidecar<[String: PeerState]>
    private let now: () -> Date

    public init(
        fileURL: URL? = nil,
        seal: SidecarSeal? = nil,
        now: @escaping () -> Date = { Date() },
        readData: ((URL) throws -> Data)? = nil,
        writeData: ((Data, URL) throws -> Void)? = nil
    ) {
        self.now = now
        self.sidecar = ProtectedSidecar(
            fileURL: fileURL ?? Self.fileURL(in: HeartDropStorageScope.production.directory),
            empty: [:],
            seal: seal,
            auditPrefix: "heartdrop.peerBundles",
            // Corrupt → empty, overwritable: a lost cache re-fills at the next verified intro,
            // and a lost consumption mark degrades FS for one send — neither is irrecoverable.
            now: now,
            readData: readData,
            writeData: writeData
        )
    }

    /// This store's file inside a given heart-drop root — the ONE definition of its name, so the
    /// production default and a scoped (per-store) root can never name different files. See
    /// ``HeartDropStorageScope``.
    public nonisolated static func fileURL(in directory: URL) -> URL {
        directory.appendingPathComponent("HeartDropPeerBundles.json")
    }

    public var isAvailable: Bool { sidecar.state == .ready }
    /// Re-attempts the sidecar's pending recovery. Void (R7): the old Bool was exactly
    /// ``isAvailable`` afterwards, which callers read directly.
    public func retryLoad() { sidecar.retryLoad() }

    /// Stores/refreshes a friend's gossiped bundle. The two slots update INDEPENDENTLY
    /// (Track B Increment 6):
    ///  - One-time slot: a NEWER bundle id resets consumption marking; re-receiving the same
    ///    bundle keeps it (so a re-intro can't reset one-time semantics); an SPK-only bundle
    ///    never wipes it.
    ///  - Signed-prekey slot: newer `created` wins; a bundle WITHOUT an SPK never clears it
    ///    (the slot ages out via `maxSealSignedPrekeyAge` instead).
    /// No-op while the sidecar is unavailable — the bundle re-gossips at the next verified intro.
    ///
    /// Monotonicity guard: bundles gossip from two coordinators (mesh and presence), so an intro
    /// built BEFORE a rotation can arrive AFTER one built later. A strictly older bundle must
    /// never replace a newer one — doing so would also clear `consumedIDs` and re-enable prekeys
    /// we already sealed to, silently degrading forward secrecy toward the static key.
    public func store(bundle: HeartPrekeyStore.Bundle, forFriendSigningKey key: Data) {
        // R5 (validate at entry): the bundle is peer-supplied. Key MATERIAL that is not a raw
        // Curve25519 public key can never be sealed to — `HeartDropSealer.seal` throws
        // `noRecipientKey` and `queueHeart` then returns `.failed` for EVERY heart to this friend
        // instead of falling back to the static key. Reject the malformed bundle here so bad
        // gossip cannot become a persistent send failure. (The map key is deliberately NOT
        // length-checked: it is an opaque cache key, never key material.)
        guard bundle.keys.allSatisfy({ $0.publicKey.count == Self.rawCurve25519KeyByteCount }),
              bundle.signedPrekey.map({ $0.publicKey.count == Self.rawCurve25519KeyByteCount }) ?? true,
              Set(bundle.keys.map(\.id)).count == bundle.keys.count else {
            FernletAuditLog.log("heartdrop.peerBundles.rejectedMalformed")
            return
        }
        let currentTime = now()
        let hasStorableOneTime = !bundle.keys.isEmpty && bundle.keys.count <= Self.maxBundleKeys
            && bundle.expires > currentTime
        let storableSPK = bundle.signedPrekey.flatMap { spk in
            currentTime.timeIntervalSince(spk.created) <= Self.maxSealSignedPrekeyAge ? spk : nil
        }
        guard hasStorableOneTime || storableSPK != nil else { return }
        guard sidecar.read() != nil, isAvailable else { return }
        let mapKey = Self.mapKey(key)
        let stored = sidecar.mutateIfPersisted { peers in
            var state = peers[mapKey]

            if hasStorableOneTime {
                if var existing = state {
                    if existing.bundle.bundleID == bundle.bundleID {
                        existing.bundle = bundle
                        state = existing
                    } else if bundle.created > existing.bundle.created {
                        existing.bundle = bundle
                        existing.consumedIDs = []
                        state = existing
                    }
                    // else: same-age-or-older rival bundle — keep what we have (the LRU touch
                    // below still counts, so an actively-gossiping peer doesn't age out).
                } else {
                    state = PeerState(bundle: bundle)
                }
            }
            if let spk = storableSPK {
                if var existing = state {
                    if existing.signedPrekey.map({ spk.created > $0.created || spk.id == $0.id }) ?? true {
                        existing.signedPrekey = spk
                    }
                    state = existing
                } else {
                    // SPK-only gossip from a peer with no cached one-time bundle: the row's
                    // one-time slot holds a STRIPPED carrier (metadata only, never the incoming
                    // keys). The `maxBundleKeys` sanity bound lives on the one-time path, so
                    // storing the raw bundle here would let a crafted over-cap bundle ride the
                    // SPK branch straight into the sidecar (review finding, 2026-07-26).
                    let carrier = HeartPrekeyStore.Bundle(
                        bundleID: bundle.bundleID,
                        created: bundle.created,
                        expires: bundle.expires,
                        keys: []
                    )
                    state = PeerState(bundle: carrier, signedPrekey: spk)
                }
            }
            guard var updated = state else { return }
            updated.lastUsedAt = currentTime
            peers[mapKey] = updated
            Self.evictIfOverCap(&peers, at: currentTime)
        }
        if !stored {
            // Benign — the bundle re-gossips at the friend's next verified intro — but a bundle
            // that silently never cached would degrade every heart to that friend to the static
            // key with no trace (R7).
            FernletAuditLog.log("heartdrop.peerBundles.storeNotPersisted")
        }
    }

    /// Picks the best sealing key for the friend: a fresh unconsumed ONE-TIME prekey first
    /// (best forward secrecy; marked consumed sender-side — the recipient retains private
    /// halves until bundle expiry + grace because two senders can race the same broadcast
    /// bundle), else the fresh SIGNED prekey (medium-term, reusable, no consumption marking),
    /// else nil — which means "seal to the static key instead", never "don't send". Nil also
    /// while the sidecar is unavailable, or when a one-time consumption mark cannot be durably
    /// persisted (an unpersisted mark would let the same one-time key be sealed to twice).
    public func consumePrekey(forFriendSigningKey key: Data) -> (id: UUID, publicKey: Data, isOneTime: Bool)? {
        let mapKey = Self.mapKey(key)
        let currentTime = now()
        guard let peers = sidecar.read(), isAvailable else { return nil }
        guard let state = peers[mapKey] else { return nil }

        if state.bundle.expires > currentTime,
           currentTime.timeIntervalSince(state.bundle.created) <= Self.maxSealBundleAge,
           let entry = state.bundle.keys.first(where: { !state.consumedIDs.contains($0.id) }) {
            let persisted = sidecar.mutateIfPersisted { peers in
                guard var state = peers[mapKey] else { return }
                state.consumedIDs.insert(entry.id)
                state.lastUsedAt = currentTime
                peers[mapKey] = state
            }
            if persisted {
                return (entry.id, entry.publicKey, true)
            }
            // The consumption mark didn't land — fall through to the (markless) signed prekey
            // rather than straight to static.
        }

        if let spk = state.signedPrekey,
           currentTime.timeIntervalSince(spk.created) <= Self.maxSealSignedPrekeyAge {
            let touched = sidecar.mutateIfPersisted { peers in
                guard var state = peers[mapKey] else { return }
                state.lastUsedAt = currentTime
                peers[mapKey] = state
            }
            // The LRU touch is bookkeeping only — the signed prekey is reusable and nothing was
            // burned — so the seal proceeds either way; the failure is named, not swallowed (R7).
            if !touched { FernletAuditLog.log("heartdrop.peerBundles.lruTouchNotPersisted") }
            return (spk.id, spk.publicKey, false)
        }
        return nil
    }

    /// Un-consumes a prekey whose send never made it onto the wire. A one-time key burned without
    /// ever being sealed to is pure loss: the bundle holds 16, and once they are gone every drop
    /// to that friend falls back to the static key with no forward secrecy. Only un-consumes when
    /// the cached bundle still contains the id, so a rotation in between is a no-op.
    public func returnPrekey(id: UUID, forFriendSigningKey key: Data) {
        let mapKey = Self.mapKey(key)
        let returned = sidecar.mutateIfPersisted { peers in
            guard var state = peers[mapKey], state.consumedIDs.contains(id),
                  state.bundle.keys.contains(where: { $0.id == id }) else { return }
            state.consumedIDs.remove(id)
            peers[mapKey] = state
        }
        if !returned {
            // The key stays burned: one fewer one-time prekey for this friend, never a
            // correctness problem — but it is forward secrecy quietly lost, so name it (R7).
            FernletAuditLog.log("heartdrop.peerBundles.returnNotPersisted")
        }
    }

    /// Delete-all seam (Docs/PrivacyWipeCoverage.md).
    public func wipeForDeleteAll() {
        sidecar.wipe()
    }

    /// Drops the least-recently-touched peers past the cap, and any row with nothing sealable
    /// left: a bundle past its own expiry AND no signed prekey still inside its seal window.
    /// The SPK term matters — its 14-day window outlives a bundle that expires sooner, and
    /// evicting on bundle expiry alone silently degraded those friends to the static key
    /// (review finding, 2026-07-26).
    private static func evictIfOverCap(_ peers: inout [String: PeerState], at currentTime: Date) {
        peers = peers.filter { _, state in
            state.bundle.expires > currentTime
                || state.signedPrekey.map {
                    currentTime.timeIntervalSince($0.created) <= Self.maxSealSignedPrekeyAge
                } ?? false
        }
        guard peers.count > Self.maxPeers else { return }
        let survivors = peers
            .sorted { $0.value.lruStamp() > $1.value.lruStamp() }
            .prefix(Self.maxPeers)
        peers = Dictionary(uniqueKeysWithValues: survivors.map { ($0.key, $0.value) })
    }

    private static func mapKey(_ key: Data) -> String {
        key.map { String(format: "%02x", $0) }.joined()
    }
}
