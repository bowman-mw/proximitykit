import Foundation
import Observation
import FernletDomainModel

/// The friend-mesh clothing shop (Phase 3a, Docs/Proximity-Mesh-Redesign-2026-07-10.md). Replaces the
/// standalone `fernlet-clothes` radio (`ProximityClothingShareManager`, deleted): catalogs now ride the
/// friend mesh as `.clothingCatalog` payloads, exchanged pairwise-sealed during the live session, and the
/// shop OPENS at session end — a 1-hour, memory-only browse window on the Friends tab.
///
/// Owned by `MeshNetworkManager`, which drives the whole lifecycle:
///  - **Inbound** — the manager's Phase-1 payload registry dispatches verified `.clothingCatalog`
///    envelopes here, but only from COMMITTED slots (the committed-slot gate in the manager's dispatch
///    default is the security boundary — the coordinator dispatches known non-core payloads with
///    `connectedIdentity ?? pendingPeerIdentity` and no state gate) and only with a transport-VERIFIED,
///    unblocked sender fingerprint. Catalogs accumulate for the whole session; there is no mid-session
///    scene-dip clearing (radio privacy is the mesh lifecycle's job).
///  - **Outbound** — the manager sends `localCatalogProvider()` once per slot at commit, pairwise
///    sealed, and only to peers advertising the `shop` capability.
///  - **Window** — `openWindowAtSessionEnd()` fires at the same last-committed-slot-gone moment that
///    promotes `pendingFriendReview`; the window stays open `windowDuration` (1 h) and closes early on
///    the next session FORMATION (`beginNewSession()`, from the manager's first-slot-commit hook — NOT
///    from startJoin/startNewMesh, which fire automatically on every Social-tab entry and scene
///    reactivation and must never touch the window) or app quit (state is memory-only). Unlike
///    `pendingFriendReview` — which survives search starts AND session formations — the shop window
///    survives searches but not formations. Expiry is lazy: `isWindowOpen`/`remainingWindowMinutes`
///    are pure reads and `cleanupIfExpired()` drops expired state; no background timers.
///
/// Opt-out is payload-layer (`allowNearbyClothingShares` no longer stops a radio): the app wires
/// `isSharingEnabledProvider` + `localCatalogProvider` (both gate on the setting app-side, so
/// `ProximityHost` stays unchanged) — provider returns nil when off (nothing sent), inbound drops when
/// off, and the setting's OFF transition calls `clearAll()`.
///
/// Buying stays fully local (`FernletStore.buyClothingItem`); this type is pure receive/window state —
/// it never touches coins or the closet. Everything here is memory-only: never persisted, never synced.
@MainActor
@Observable
public final class MeshClothingShop {

    /// The post-session browse window. Value-typed and observable so views can key countdowns off it.
    public struct Window: Equatable {
        public let opensAt: Date
        public let expiresAt: Date
    }

    public static let windowDuration: TimeInterval = 60 * 60
    static let maxPeerCatalogs = 8
    static let perSenderRateLimitSeconds: TimeInterval = 3

    /// Catalogs received from committed peers, keyed by VERIFIED fingerprint only (a re-broadcast
    /// replaces the sender's prior catalog rather than stacking). Accumulate during the session and stay
    /// browsable through the post-session window.
    public private(set) var peerCatalogs: [ProximityClothingCatalog] = []
    /// Non-nil from session end (with catalogs held) until expiry / early close. Lazy-expired: check
    /// `isWindowOpen`, not just nil-ness.
    public private(set) var window: Window?

    /// The app supplies this device's current shop catalog; the mesh manager sends it once per slot at
    /// commit. Returning `nil` (sharing disabled) sends nothing.
    @ObservationIgnored public var localCatalogProvider: (() -> ClothingCatalogPayload?)?
    /// App-side opt-out gate (`allowNearbyClothingShares`): gates inbound accept and the `shop`
    /// capability advertisement. Wired as a closure so the settings read stays app-side and
    /// `ProximityHost` is unchanged. Absent (tests without wiring) = disabled.
    @ObservationIgnored public var isSharingEnabledProvider: (() -> Bool)?

    @ObservationIgnored private var lastAcceptedBySender: [String: Date] = [:]

    public init() {}

    public var isSharingEnabled: Bool { isSharingEnabledProvider?() ?? false }

    public var isWindowOpen: Bool { isWindowOpen(at: Date()) }

    public func isWindowOpen(at now: Date) -> Bool {
        guard let window else { return false }
        return now < window.expiresAt
    }

    /// Whole minutes left in the open window (rounded up, floored at 1 so "Shop open — 0 min" never
    /// renders), or nil when no window is open. Pure read — pair with `cleanupIfExpired()`.
    public func remainingWindowMinutes(at now: Date = Date()) -> Int? {
        guard let window, now < window.expiresAt else { return nil }
        return max(1, Int((window.expiresAt.timeIntervalSince(now) / 60).rounded(.up)))
    }

    // MARK: - Inbound (called by MeshNetworkManager's registered handler)

    /// Accepts a verified `.clothingCatalog` envelope from a committed, unblocked peer. The caller
    /// (MeshNetworkManager) has already enforced the committed-slot gate and the blocked-fingerprint
    /// drop (mirroring `.friendPhoto`); `verifiedFingerprint` is the transport-authenticated identity,
    /// never a wire-claimed value — catalogs are keyed by it exclusively.
    public func receiveCatalog(
        _ envelope: FernletIdentityEnvelope,
        plaintext: Data,
        verifiedFingerprint: String,
        now: Date = Date()
    ) {
        // Payload-layer opt-out: inbound drops while sharing is off.
        guard isSharingEnabled else { return }
        guard envelope.payloadType == .clothingCatalog,
              let payload = try? JSONDecoder().decode(ClothingCatalogPayload.self, from: plaintext),
              payload.format == "fernlet.proximity.clothing.catalog",
              payload.version == 1 else { return }

        if let lastAccepted = lastAcceptedBySender[verifiedFingerprint],
           now.timeIntervalSince(lastAccepted) < Self.perSenderRateLimitSeconds {
            return
        }
        lastAcceptedBySender[verifiedFingerprint] = now

        // Never trust the wire: bound the item count to the shop maximum FIRST (the send side caps at the
        // same limit, so a larger array is a protocol violation / hostile amplification — decoding, mapping,
        // storing, and re-sorting an unbounded array on the main actor would be a remote DoS), then clamp
        // every kept item (texture dims/indices/palette, price, name) before holding it.
        var sanitized = payload
        sanitized.items = payload.items.prefix(ClothingShopLimits.maxListedItems).map { ClothingShopLimits.sanitizedForShop($0) }

        let catalog = ProximityClothingCatalog(
            senderDisplayName: envelope.senderDisplayName,
            senderFingerprint: verifiedFingerprint,
            receivedAt: now,
            payload: sanitized
        )
        peerCatalogs.removeAll { $0.id == catalog.id }
        peerCatalogs.insert(catalog, at: 0)
        if peerCatalogs.count > Self.maxPeerCatalogs {
            peerCatalogs = Array(peerCatalogs.prefix(Self.maxPeerCatalogs))
        }
    }

    // MARK: - Session lifecycle (called by MeshNetworkManager)

    /// A NEW session has FORMED — the first slot COMMIT after a no-session state (the spec's
    /// "'Next session start' = first slot COMMIT, not search start"): the previous window closes early —
    /// the owner decision is "closes when a new session starts" — and its catalogs drop so the fresh
    /// session accumulates from a clean slate. The caller (`MeshNetworkManager`) fires this exactly once
    /// per formation; startJoin/startNewMesh (which run on every Social-tab entry / scene reactivation)
    /// must NOT call it, mirroring why `pendingFriendReview` deliberately survives them.
    public func beginNewSession() {
        window = nil
        peerCatalogs.removeAll()
        lastAcceptedBySender.removeAll()
    }

    /// The last committed slot is gone (the same moment `pendingFriendReview` promotes): if any catalogs
    /// are held, open the 1-hour browse window. Because `beginNewSession()` fires at session FORMATION
    /// (first slot commit) and nils the window, an invariant holds here: `window != nil` means NO commit
    /// has happened since that window opened — so the `window == nil` guard is exactly "only (re)open
    /// when a commit happened since the last open". Held catalogs therefore always belong to the
    /// just-ended session (a fresh window covers them), and repeated teardown funnels with no
    /// intervening commit can never extend an open window.
    public func openWindowAtSessionEnd(now: Date = Date()) {
        cleanupIfExpired(now: now)
        guard window == nil, !peerCatalogs.isEmpty else { return }
        window = Window(opensAt: now, expiresAt: now.addingTimeInterval(Self.windowDuration))
    }

    /// Lazy expiry: once the window has lapsed, drop it and every held catalog (memory-only state, gone
    /// one hour after the session regardless of anyone looking). Safe to call any time.
    public func cleanupIfExpired(now: Date = Date()) {
        guard let window, now >= window.expiresAt else { return }
        self.window = nil
        peerCatalogs.removeAll()
        lastAcceptedBySender.removeAll()
    }

    /// The opt-out's OFF transition (`setAllowNearbyClothingShares(false)`): drop every held catalog and
    /// close the window immediately — WITHOUT touching the mesh radio, which belongs to the friend
    /// session lifecycle.
    public func clearAll() {
        window = nil
        peerCatalogs.removeAll()
        lastAcceptedBySender.removeAll()
    }
}
