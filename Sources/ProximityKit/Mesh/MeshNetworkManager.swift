import Foundation
import Observation
import UIKit
import CryptoKit
import FernletCrypto
import FernletDomainModel
import FernletFoundation
import PrivateMediaStore

// MARK: - Supporting types

/// One tile on the home photo wall: a single photo, or an aggregated session carousel with its
/// chosen cover.
///
/// Derived on demand by `MeshNetworkManager.photoWallPosts` from the cached photo metadata plus
/// the wall preferences (aggregation, covers, favorites); never persisted itself.
public struct FriendPhotoWallPost: Identifiable {
    public let id: UUID
    public let session: FriendPhotoSessionMetadata?
    public let photos: [FriendPhotoPayload]
    public let coverPhoto: FriendPhotoPayload

    public init(
        id: UUID,
        session: FriendPhotoSessionMetadata?,
        photos: [FriendPhotoPayload],
        coverPhoto: FriendPhotoPayload
    ) {
        self.id = id
        self.session = session
        self.photos = photos
        self.coverPhoto = coverPhoto
    }

    public var isCarousel: Bool { photos.count > 1 }
}

/// Persisted photo-wall preferences: which sessions are aggregated into carousels, their cover
/// photos, and the per-session favorite.
///
/// Loaded/saved through the shared ``JSONSidecarFile`` helper (`MeshPhotoWallPreferences.json`,
/// `.completeFileProtection`); lives beside the photo cache, never in the synced snapshot. A
/// failed load falls back to empty preferences; a failed save is silently dropped — wall
/// cosmetics, not data of record.
private struct FriendPhotoWallPreferences: Codable, Equatable {
    var aggregatedSessionIDs: Set<UUID> = []
    var coverPhotoIDsBySession: [UUID: UUID] = [:]
    var favoritePhotoIDsBySession: [UUID: UUID] = [:]
}

// MARK: - MeshNetworkManager

/// The friend-mesh session manager — the largest orchestrator in the subsystem. Runs the
/// `fernlet-friend` radio, forms UWB dwell-committed sessions (pairwise → mesh at two commits),
/// and hosts every feature that rides the mesh: disposable-camera photos, the clothing shop,
/// live-session chat, in-session hearts, moderation relay, fuzzy friend state, Group Activities,
/// the QR verification ceremony, and the post-session keep-as-friend review.
///
/// Structure: one shared radio — held through `MeshTransportSession`, so it is the MC session on
/// every shipping path and the QUIC one only when selected — feeds per-peer channels; each channel
/// gets a ``PeerSlot`` with its own ``ProximityCoordinator`` and a
/// retained ``FriendSessionTrustPolicy``. Slots are capped (3 active + 2 lightweight, ranked by
/// stable UWB distance with hysteresis-guarded overflow eviction) and a symmetric `sid`
/// comparison picks the single inviter of a mutually-discovered pair. Core mesh-control payloads
/// are handled in the dispatch switch; feature payloads go through the Phase-1 registry, whose
/// committed-slot gate (`slot.fingerprint != nil`) is the security boundary — the coordinator
/// dispatches with a merely-pending identity and no state gate.
///
/// Session lifecycle invariants: "session formation" is the FIRST slot commit (not search start,
/// which fires on every Social-tab entry); the last-committed-slot-gone moment promotes the
/// roster into `pendingFriendReview`, opens the clothing-shop window, and clears the chat
/// transcript. Phase-3 group crypto: a lowest-fingerprint coordinator election, a 20 s beacon,
/// and a 15-minute key rotation distribute the ``MeshGroupKey`` pairwise-wrapped to
/// handshake-verified KA keys; closed-mode metadata and epoch ≥ 1 photos ride AES-GCM under it.
/// Photos persist metadata-only in the `PrivateMediaStore`-backed cache (bytes on disk,
/// rehydrated on demand) with per-sender send/receive quotas.
///
/// Capabilities (`localCapabilities()`) gate every optional feature per peer, including the 13+
/// chat age gate — enforced at advertisement, send, AND receive. `wipeIdentityForDeleteAll` is
/// this manager's leg of the delete-all seam. Memory-only session state everywhere except the
/// photo cache, wall preferences, and the activity sidecar — none of it synced.
/// `@MainActor @Observable`; the app owns start/stop via tab/scene/lock gating.
@MainActor
@Observable
public final class MeshNetworkManager: ProximityPayloadHandling {

    // Published state
    public var slots: [PeerSlot] = []
    public var currentMesh: MeshDescriptor?
    public var pendingAdmissionRequests: [MeshAdmissionRequestPayload] = []
    public var pendingRemovalProposals: [MeshRemovalProposalPayload] = []
    public var meshPhotos: [FriendPhotoPayload] = []
    /// Photos taken/received during the current proximity-join session (cleared on leaveSession).
    public private(set) var sessionPhotos: [FriendPhotoPayload] = []
    /// Every peer whose handshake COMMITTED during the current session, for the post-session
    /// keep-as-friend prompt (Phase 2, Docs/Proximity-Mesh-Redesign-2026-07-10.md). Unlike
    /// `slots`, entries survive slot teardown — the review fires after the slots are gone: when
    /// the last committed slot disappears the roster PROMOTES into `pendingFriendReview` (see
    /// promoteRosterToPendingReviewIfSessionEnded). Reset when a NEW session begins
    /// (startJoin/startNewMesh via resetSessionRosterForNewSession) or consumed scoped by the
    /// in-session camera review (consumeRosterEntries). Memory-only key material; never
    /// persisted/synced.
    public private(set) var sessionRoster: [MeshSessionRosterEntry] = []
    /// The promoted, unconsumed session-end friend review. Set by
    /// `promoteRosterToPendingReviewIfSessionEnded()` when the last committed slot disappears;
    /// cleared only by `completeFriendReview(_:)`. Views present off this observable state
    /// (`onChange` + `onAppear`) — never off `isInSession` view-events. Survives
    /// startJoin/startNewMesh by design.
    public private(set) var pendingFriendReview: MeshFriendReviewBatch?
    /// The friend-mesh clothing shop (Phase 3a): catalogs exchanged during the session + the 1-hour
    /// post-session browse window. Registered on the payload registry in `init`; lifecycle hooks fire
    /// from the same moments that drive the friend-review batch — but the two deliberately diverge on
    /// session FORMATION (the first slot commit, via `noteSlotCommittedForShop`): the review batch
    /// survives it, the shop window closes. Search starts (startJoin/startNewMesh — which fire on every
    /// Social-tab entry and scene reactivation) touch NEITHER.
    public let clothingShop = MeshClothingShop()
    /// Phase 6 (Group Activities): the state + host-authoritative roster/token brain. Rides this friend
    /// mesh (no new radio); constructed + wired in `init`. Memory + a device-local sidecar (NEVER synced).
    public let activities: ProximityActivityManager
    /// Phase 3b (one-hop moderation relay): the local user's own moderation report rows, supplied by the
    /// app so ProximityKit signs + hands them to a committed friend; and the sink for peers' verified
    /// report rows (stored + reconciled by the app).
    @ObservationIgnored public var ownModerationReportsProvider: (() -> [ModerationLedgerEntry])?
    @ObservationIgnored public var onModerationRowsReceived: (([ModerationLedgerEntry]) -> Void)?
    /// Phase 4 (fuzzy state): whether the user opted into sharing (gates the advertised capability); the
    /// local fuzzy-state + appearance payload to send; and the sink for a friend's received state.
    @ObservationIgnored public var friendStateEnabledProvider: (() -> Bool)?
    @ObservationIgnored public var friendStatePayloadProvider: (() -> FriendStatePayload?)?
    @ObservationIgnored public var onFriendStateReceived: ((String, FriendStatePayload) -> Void)?
    /// Device-local hearts ledger (received-heart records + the 5-minute per-friend rate limit),
    /// SHARED with the presence path (TF b19 item 5). In-session hearts ride the live mesh channel
    /// instead of the fragile on-demand presence connect, but they record through the SAME ledger so
    /// cooldown + dedup state stay consistent across both transports. Set by the app; `nil` in tests
    /// that don't exercise hearts (send/receive then no-op).
    @ObservationIgnored public var heartLedger: ProximityHeartLedger?
    /// Fired with the friend's fingerprint when an in-session heart is SENT / RECEIVED over the mesh,
    /// so the app feeds the closeness signal — wired to the SAME closeness hooks the presence path
    /// uses, so both transports converge (TF b19 item 5).
    @ObservationIgnored public var onHeartSent: ((String) -> Void)?
    @ObservationIgnored public var onHeartReceived: ((String) -> Void)?
    /// Test seam: fires with the slot ID whenever an in-session heart is dispatched to a slot — unit
    /// tests can't observe the real sealed channel (mirrors `onTempMessageSendForTesting`).
    @ObservationIgnored var onSessionHeartSendForTesting: ((UUID) -> Void)?
    @ObservationIgnored private var sessionHeartStateClearTask: Task<Void, Never>?
    /// Fingerprints with a session heart between dispatch and wire-write completion. The ledger's
    /// 5-minute gate can't stand in for this: it is armed consume-on-SEND, i.e. after the await.
    @ObservationIgnored private var sessionHeartSendsInFlight: Set<String> = []
    /// Phase 5: a friend session committed with this fingerprint (an in-person meeting) — feeds closeness.
    @ObservationIgnored public var onFriendSessionCommitted: ((String) -> Void)?
    /// A photo was exchanged with this friend in the current session (feeds the closeness photo signal).
    @ObservationIgnored public var onFriendPhotoSession: ((String) -> Void)?
    /// The live-session temporary-message store (Phase 5): the current session's chat transcript.
    /// Registered on the payload registry in `init`. Memory-only and deliberately NOT Codable — it can
    /// never enter a snapshot. Cleared at EVERY session-end path (the same last-committed-slot-gone
    /// moment that promotes `pendingFriendReview` / opens the shop window) and on the next session
    /// formation. Unlike the shop's 1-hour window, messages do NOT outlive the session — they vanish.
    public let sessionMessages = SessionMessageStore()
    /// In-session heart send feedback (TF b19 item 5). The mesh path is near-instant — one sealed
    /// envelope over the already-connected, transport-verified session channel — so unlike the
    /// presence pipeline's multi-second connect it only needs `.sending` briefly, then `.sent` /
    /// `.failed`, auto-clearing back to `.idle`. Observable so the in-session heart affordance
    /// surfaces state instead of failing silently. Memory-only.
    public enum SessionHeartState: Equatable, Sendable {
        case idle
        case sending(recipientName: String)
        case sent(recipientName: String)
        case failed(message: String)
    }
    public private(set) var sessionHeartState: SessionHeartState = .idle
    public var isSearching = false
    public var meshError: String?

    /// A radio start-up failure (advertising or browsing failed to begin) during discovery, kept
    /// SEPARATE from `meshError`. `meshError` is multiplexed across in-session conditions (photo
    /// quota, key-rotation exclusion) that are surfaced by `DisposableCameraView` — which only
    /// exists inside a session. A discovery failure happens BEFORE any session, so it had no
    /// reachable UI and the search spun forever in silence. This drives the Friends-screen
    /// discovery-failure banner instead. On device the near-certain cause is a declined Local
    /// Network prompt. Set only by the transport `onTransportError`; cleared on every (re)search.
    public var discoveryError: String?

    @ObservationIgnored private unowned let store: any ProximityHost
    /// The shared radio, held through ``MeshTransportSession`` so this manager never names one.
    /// `MeshTransportFactory` picks it: MultipeerConnectivity on every shipping path, the QUIC
    /// conformer only from an internal injection or the DEBUG-only launch variable.
    @ObservationIgnored private let transport: any MeshTransportSession
    /// The callbacks installed on ``transport``. Kept so a unit test can fire the events a radio
    /// drives in production — `onPeerDisconnected` above all, whose retry and local-kick bookkeeping
    /// has no other entry point.
    @ObservationIgnored private var transportHandlers = MeshTransportHandlers()
    @ObservationIgnored private let identity: IdentityService
    @ObservationIgnored private let replayCache = ReplayCache()
    @ObservationIgnored private let photoCacheStore: PrivateMediaStore
    @ObservationIgnored private let photoWallPreferencesStore: JSONSidecarFile<FriendPhotoWallPreferences>
    @ObservationIgnored private var photoWallPreferences: FriendPhotoWallPreferences
    /// True when the sealed photo index existed at init but could not be opened yet (a locked
    /// keychain before the first post-boot unlock). While set, `persistPhotoIndex` refuses to write:
    /// `meshPhotos` is empty for a reason that is NOT "the wall is empty", and the index is also the
    /// file manifest the store sweeps against, so saving it would delete every kept photo's bytes.
    /// Cleared by the first re-read that succeeds (inside `persistPhotoIndex`).
    @ObservationIgnored private var photoIndexDeferred = false
    /// Observed proxy for favorite changes. `photoWallPreferences` itself is `@ObservationIgnored`
    /// because its `photoWallPosts` getter mutates it during view-body evaluation (plainly observing
    /// it would risk update loops). This counter is bumped ONLY from `toggleFavorite` (a tap handler,
    /// never during body eval), and touch-read in `favoritePhotoID(for:)` and the `photoWallPosts`
    /// getter so the viewer heart and the wall cover both re-render when a favorite toggles.
    private var favoritesRevision = 0
    @ObservationIgnored private var slotTrustPolicies: [UUID: FriendSessionTrustPolicy] = [:]
    @ObservationIgnored private var observationTask: Task<Void, Never>?
    public private(set) var photosAddedThisSession = 0
    @ObservationIgnored private var sessionQuotaMeshID: UUID?
    /// Distinct photo IDs accepted per *authenticated* peer this mesh session. Bounds the
    /// receive path the same way `photosAddedThisSession` bounds the send path, so a single
    /// connected peer cannot flood the session with unbounded photos (each decoded, cached,
    /// and — when it claims the active session — retained in memory). Keyed on the
    /// transport-authenticated fingerprint, not the spoofable `payload.senderFingerprint`.
    @ObservationIgnored private var receivedPhotoIDsByFingerprint: [String: Set<UUID>] = [:]
    @ObservationIgnored private var receiveQuotaMeshID: UUID?
    @ObservationIgnored private var photoSessionStartedAt: Date?
    @ObservationIgnored private var activePhotoSessionID: UUID?
    // voucherFingerprint → cached payload; never persisted across app launches
    @ObservationIgnored private var vouchCache: [String: MeshFriendVouchListPayload] = [:]
    /// Re-invite attempts spent per DEVICE for failed proximity-join connections.
    ///
    /// Keyed on ``PeerEndpointKey``, not `peer.id`, and that is the whole point of the key: the
    /// budget exists for a device that keeps dropping, and a device that reconnects is exactly the
    /// case where a per-handle key would hand out a fresh budget every time. The slot lookup two
    /// lines away in `onPeerDisconnected` has always used the endpoint test; this used not to.
    @ObservationIgnored private var peerRetryCount: [PeerEndpointKey: Int] = [:]
    /// Devices this manager kicked itself (`kickEvictedPeer`) whose `.notConnected` has not arrived yet.
    /// `onPeerDisconnected` reads that event as our own eviction — never as the transient socket loss
    /// its re-invite retry exists for. Consumed on the disconnect callback, cleared in
    /// `stopSearching()`; bounded by MC's 8-peer cap in practice and hard-capped by
    /// ``maxLocallyKickedPeers`` (R3). Keyed by endpoint for the same reason as `peerRetryCount`:
    /// a deliberate eviction that stopped being recognized would be re-invited by its own retry.
    @ObservationIgnored private var locallyKickedEndpoints: Set<PeerEndpointKey> = []
    /// Slots the local shop catalog was already sent to (belt-and-braces once-per-slot guard — the
    /// commit transition in checkCoordinatorStates fires once per fingerprint change already). Pruned
    /// per-slot on eviction (removeSlot/disconnectSlot) so a rejoining friend re-exchanges — the
    /// transport's peerMap persists across a remote teardown, so a returning peer reuses its old slot
    /// UUID. `clothingCatalogRequest` responses deliberately BYPASS this set (idempotent — the receiver
    /// replaces by fingerprint).
    @ObservationIgnored private var sentShopCatalogSlotIDs: Set<UUID> = []
    /// Per-slot rate limit for `clothingCatalogRequest` responses (request-spam amplification guard:
    /// each response is a full catalog send). Pruned with `sentShopCatalogSlotIDs`.
    @ObservationIgnored private var shopCatalogRequestResponseAt: [UUID: Date] = [:]
    /// True from the first slot COMMIT of a session (formation) until the session ends (no committed
    /// slot and no mesh — the same `!isInSession` condition the review promotion keys on). Gates the
    /// Phase-3a formation hook in `noteSlotCommittedForShop` so `clothingShop.beginNewSession()` fires
    /// exactly once per formation — later commits, promoteToMesh's committed loop, and a re-handshake
    /// of the only committed slot must not re-fire it mid-session.
    @ObservationIgnored private var hasFormedShopSession = false
    /// Test seam: fires with the slot ID whenever a shop-catalog send is initiated (commit offer or
    /// request response) and the provider produced a catalog — unit tests can't observe the real
    /// channel (no live MCSession behind the test slots).
    @ObservationIgnored var onShopCatalogSendForTesting: ((UUID) -> Void)?
    /// Test seam: fires AFTER a `clothingCatalogRequest` send completes — i.e. after the commit
    /// task's last touch of manager state. Tests that drive commits await this so the async send
    /// task drains inside the test's lifetime (the manager's `unowned store` must not be reached
    /// after the test's store deallocates).
    @ObservationIgnored var onShopCatalogRequestSendForTesting: ((UUID) -> Void)?
    /// Test seam: fires with the slot ID whenever a temp message is dispatched to a slot (Phase 5) —
    /// unit tests can't observe the real sealed channel. Lets the capability-gated-send test assert a
    /// legacy peer was skipped.
    @ObservationIgnored var onTempMessageSendForTesting: ((UUID) -> Void)?
    @ObservationIgnored private(set) var removedMemberFingerprints: Set<String> = []
    @ObservationIgnored private var approvedRemovalProposalIDs: Set<UUID> = []
    @ObservationIgnored private var sessionID = UUID().uuidString
    private static let maxPeerRetries = 3
    private static let maxLocallyKickedPeers = 32

    // MARK: - Phase 3 Group Encryption State

    // Current symmetric group key. nil = epoch 0 (unencrypted). Never persisted.
    /// `slot.id` → the `meshID` we asked to join on that slot.
    ///
    /// An admission grant is only ever accepted as the answer to a request WE sent on THAT slot.
    /// Without this record a grant is unsolicited wire input that hands us a group key, which is
    /// how a non-member can push its own key onto a joiner. Written by `sendAdmissionRequest`,
    /// consumed single-use by `handleAdmissionGrant`, pruned in `removeSlot`, cleared wholesale by
    /// `clearGroupKeyState` (R3: bounded by ``maxOutstandingAdmissionRequests``).
    @ObservationIgnored private var outstandingAdmissionRequestBySlot: [UUID: UUID] = [:]

    /// Photo AUTHORS announced in manifests this session, after the block filter.
    ///
    /// A one-hop relay (`sendRequestedPhotos`) can legitimately carry a third peer's photo before
    /// that peer appears in our mesh descriptor or session roster — the manifest entry is our only
    /// advance notice of the author. `photoAuthorIsAcceptable` treats that notice as "known", which
    /// keeps the relay working while staying attacker-bounded (we asked for these ids).
    /// Bounded by ``maxSessionPhotos``; cleared with the roster at new-session reset (R3).
    @ObservationIgnored private var manifestAnnouncedPhotoAuthors: Set<String> = []

    @ObservationIgnored private(set) var currentGroupKey: MeshGroupKey?

    /// The epoch this device is on, plus the predecessors still inside their grace window
    /// (P3 item 5, plan §8.4). Nil until this device holds a group key.
    ///
    /// **Held, not derived.** Item 4's `epochRef` recomputed a ``MeshEpochRef`` on every read from
    /// `currentGroupKey.epoch` and whatever the descriptor roster said at that instant, which meant
    /// the ref could change without a rotation and gave old keys nowhere to live. The keyring is
    /// the single source of both answers now: ``MeshIntroductionAuthority/epochRef`` reads its
    /// head, and an old key stops working at the stated moment
    /// (``MeshEpochBounds/predecessorGraceSeconds``) rather than when the last reference goes away.
    /// Memory-only, forever — only the *refs* are persisted, into `MeshSessionContext.epochHeads`.
    @ObservationIgnored private(set) var epochKeyring: MeshEpochKeyring?

    /// Plan §8.3's coalescing, non-reentrant rotation front door: the 15-minute timer, every roster
    /// change and every merge pass through it.
    @ObservationIgnored private(set) var rotationTriggers = MeshRotationTriggerQueue()

    /// The single armed debounce task (R3: cancel-and-replace, never one task per trigger).
    @ObservationIgnored private var rotationDebounceTask: Task<Void, Never>?

    /// Why the last rotation this device initiated happened, and why the last one that did not
    /// happen was refused. Frozen English diagnostics, read by tests and audit lines — never
    /// display copy, and never shown to a person.
    @ObservationIgnored private(set) var lastRotationCause: MeshKeyRotationCause?

    /// The reason the most recent rotation attempt was abandoned, or nil if none was. A blocked
    /// rotation is SURFACED here and in the audit log rather than swallowed (plan §3.6).
    @ObservationIgnored private(set) var lastRotationBlockReason: String?

    // Task that fires at nextRotationAt to drive the rotation protocol as coordinator.
    @ObservationIgnored private var rotationTimer: Task<Void, Never>?
    // Task that fires every ~20s to broadcast or check for a coordinator beacon.
    @ObservationIgnored private var beaconTimer: Task<Void, Never>?
    // Fingerprints that have sent a sync-ack for the current closing epoch.
    @ObservationIgnored private var pendingRotationAcks: Set<String> = []
    // Closing epoch currently being drained for rotation (nil = no rotation in progress).
    @ObservationIgnored private var pendingRotationClosingEpoch: Int? = nil
    // The epoch this device joined at; manifest entries from earlier epochs are skipped.
    @ObservationIgnored private(set) var localJoinedEpoch: Int = 0
    // When the most recent coordinator beacon was received.
    @ObservationIgnored private var lastBeaconReceivedAt: Date?
    // Planned rotation timestamp from the most recent coordinator beacon.
    @ObservationIgnored private var lastKnownNextRotationAt: Date?
    // Log of (epoch, activeSince) pairs for the current session; used to compute peer joinedEpoch.
    // Bounded to `maxEpochLogEntries` on every append (R3) — see `recordEpoch(_:since:)`.
    @ObservationIgnored private var epochLog: [(epoch: Int, since: Date)] = []
    /// The single in-flight rotation-sync drain (see `scheduleRotationSyncAck`), so a sync flood
    /// cannot accumulate sleeping tasks (R3).
    @ObservationIgnored private var rotationSyncTask: Task<Void, Never>?
    /// Slot ids with a photo-send run in flight — at most one per slot, so a peer cannot fan out
    /// unbounded hydrating sends by re-requesting the session in a loop (R3).
    @ObservationIgnored private var photoSendsInFlight: Set<UUID> = []

    private static let rotationInterval: TimeInterval = 15 * 60   // 15 minutes
    private static let beaconInterval: TimeInterval = 20          // 20 seconds
    private static let beaconLivenessTimeout: TimeInterval = 45   // 45 seconds
    /// How long the coordinator waits for sync-acks before minting the next key, and how often it
    /// re-checks — together they are the visible bound of the ack-collection loop (R2).
    private static let rotationAckWindowSeconds: TimeInterval = 10
    private static let rotationAckPollInterval: Duration = .milliseconds(200)
    /// Drain delay a member takes before acking a rotation sync (lets outbound photo work finish).
    private static let rotationDrainSeconds: TimeInterval = 3
    /// R3 cap on the in-memory epoch log — it is a rolling record, never a full history.
    private static let maxEpochLogEntries = 8
    /// R3 cap on the sets that remember removal votes; both are fed by wire-supplied ids/strings.
    private static let maxRecordedRemovals = 64
    /// R3 cap on gossiped mesh membership: every `.meshDescriptor` merge is attacker-chosen input
    /// that is displayed, counted, and re-gossiped to every slot (amplification).
    private static let maxMeshMembers = 16
    /// R3/R5 cap on a peer-supplied mesh name before it is adopted or displayed.
    private static let maxMeshNameLength = 40
    /// R3 cap on the session roster: one entry per distinct committed fingerprint, but a peer that
    /// regenerates its identity and re-commits would otherwise add one per commit.
    private static let maxSessionRosterEntries = 32
    /// R3 cap on the observed pending-admission queue (wire input, rendered by the UI).
    private static let maxPendingAdmissionRequests = 8
    /// R3 cap on `outstandingAdmissionRequestBySlot`: at most one entry per slot, so it can never
    /// exceed the slot cap. Enforced explicitly rather than merely implied, because the writer
    /// sits on a wire-driven path.
    private static let maxOutstandingAdmissionRequests = maxTotalSlots
    /// Wall-post count at which older multi-photo sessions start collapsing into one aggregated
    /// post — the bound of the aggregation loop in `progressivelyAggregatePhotoSessions`.
    private static let maxUnaggregatedWallPosts = 24
    /// Delay before re-inviting a peer whose channel dropped pre-commit.
    private static let reinviteDelaySeconds: TimeInterval = 2

    private static let maxActiveSlots = 3
    private static let maxLightweightSlots = 2
    private static let maxTotalSlots = 5
    private static let maxSlotsDuringOverflowEvaluation = 6
    private static let distanceStabilityWindow: TimeInterval = 10
    private static let requiredStableDistanceSamples = 5
    private static let evictionHysteresis = 0.20
    private static let maxPhotosPerSenderPerSession = 10
    /// Hard cap on the in-session photo list, defending against memory growth even if the
    /// per-sender receive quota is bypassed by a future code path. With the per-sender cap
    /// this is reached only by an implausible number of peers.
    private static let maxSessionPhotos = 200
    /// Hard cap on outstanding removal proposals (backstop against spoofed proposer fingerprints).
    private static let maxPendingRemovalProposals = 16

    /// The app's entry point: a manager over the radio this build selected.
    ///
    /// That is MultipeerConnectivity everywhere it matters — ``MeshTransportFactory/shippingDefault``
    /// is the only answer a Release build can produce. A DEBUG build can be launched onto the QUIC
    /// radio with `FERNLET_MESH_TRANSPORT=quic`; nothing about the choice is stored, so it lasts one
    /// launch and owes no row on the persisted-surface wipe ledger.
    public convenience init(store: any ProximityHost) {
        self.init(store: store, transport: nil)
    }

    /// The designated initializer, taking the radio.
    ///
    /// `nil` means "whatever this build selects", which is what the public initializer passes. Tests
    /// pass an in-memory fake; that seam is the whole of P2 item 8, and what closes the long-standing
    /// gap where manager-level invite behaviour could not be asserted at tier 1 at all.
    init(store: any ProximityHost, transport: (any MeshTransportSession)?) {
        self.store = store
        self.transport = transport ?? MeshTransportFactory.makeSession(MeshTransportFactory.resolvedKind())
        let id = IdentityService()
        // Fail-soft: the manager still constructs, but a failed provisioning is NAMED (R7) —
        // otherwise every later sign/seal on this identity fails with no visible cause.
        do {
            try id.ensureProvisioned()
        } catch {
            FernletAuditLog.log(
                "mesh.identity.provisionFailed",
                context: ["error": String(describing: error)]
            )
        }
        self.identity = id
        // Per-HOST root like the photo wall below: `FernletStore.resetAll` calls
        // `meshNetworkManager.activities.clearAll()`, which removes this sidecar.
        self.activities = ProximityActivityManager(
            store: store,
            identity: id,
            fileURL: ProximityActivityManager.fileURL(in: store.proximitySupportDirectory)
        )
        // Per-HOST root, not a process-wide constant — see `ProximityHost.proximitySupportDirectory`
        // for why the wall's index cannot be shared across concurrently-live managers.
        let cacheURL = store.proximitySupportDirectory
            .appendingPathComponent("MeshPhotoCache.json")
        // Phase-5 media-key split: the wall stays on the ORIGINAL, backup-restorable row
        // (`Role.friendWall`) — stated explicitly rather than left to the default so a future
        // reader can see which side of the split this store is on. Nothing about the wall changed:
        // no re-encryption, no dual-open fallback, and delete-all still keeps both the photos and
        // the key. The user's OWN photos moved to `Role.ownPhotos` in `FernletStore`.
        self.photoCacheStore = PrivateMediaStore(
            indexURL: cacheURL,
            keyProvider: KeychainPrivateMediaKeyProvider(role: .friendWall)
        )
        let preferencesURL = cacheURL.deletingLastPathComponent().appendingPathComponent("MeshPhotoWallPreferences.json")
        let preferencesStore = JSONSidecarFile<FriendPhotoWallPreferences>(fileURL: preferencesURL)
        self.photoWallPreferencesStore = preferencesStore
        self.photoWallPreferences = preferencesStore.load() ?? FriendPhotoWallPreferences()
        // `loadIndex`, not `load`: a DEFERRED read must not look like an empty wall (see
        // `photoIndexDeferred` — the index is also the store's file manifest). An `.unrecoverable`
        // index is different: nothing can bring those entries back, so the wall starts empty and
        // saves proceed, letting the next one replace the dead file and sweep its orphans.
        switch photoCacheStore.loadIndex() {
        case .entries(let photos):
            meshPhotos = photos
        case .deferred:
            photoIndexDeferred = true
        case .unrecoverable:
            FernletAuditLog.log("mesh.photoIndex.unrecoverable")
        }
        prunePhotoWallPreferences()
        setupMeshSession()
        registerClothingShopHandler()
        registerSessionMessageHandler()
        registerSessionHeartHandler()
        registerModerationReportHandler()
        registerFriendStateHandler()
        registerActivityHandlers()
        // Phase 6: give the activity manager the two mesh seams it needs — a sealed/unsealed send to a
        // verified fingerprint's committed slot, and the list of committed peers advertising `.activities`.
        activities.send = { [weak self] type, payload, fingerprint, sealed in
            await self?.sendActivityEnvelope(type, payload, toFingerprint: fingerprint, sealed: sealed)
        }
        activities.committedActivityPeerFingerprints = { [weak self] in
            self?.committedActivityPeerFingerprints() ?? []
        }
    }

    /// Ends every long-running task the manager owns if it is released without `stopSearching()`
    /// (today it never is — it is a process-lifetime `lazy var` on the store — but the tasks must
    /// not outlive their owner: the observation loop would stay parked and the `[weak self]` timers
    /// would each spin one more tick). `isolated`: the handles are main-actor state.
    isolated deinit {
        observationTask?.cancel()
        rotationTimer?.cancel()
        rotationDebounceTask?.cancel()
        beaconTimer?.cancel()
        rotationSyncTask?.cancel()
        sessionHeartStateClearTask?.cancel()
    }

    /// Phase 3a: the shop rides the friend mesh as registered feature payloads. The dispatch default's
    /// committed-slot gate has already run by the time these fire; the remaining guards mirror
    /// `.friendPhoto`: a transport-VERIFIED fingerprint is required (catalogs are keyed by it
    /// exclusively — never a display name) and blocked fingerprints drop silently.
    private func registerClothingShopHandler() {
        registerPayloadHandler(for: .clothingCatalog) { [weak self] envelope, plaintext, peer in
            guard let self else { return }
            guard let fingerprint = peer?.fingerprint else {
                FernletAuditLog.log("mesh.clothingCatalog.droppedUnverifiedSender")
                return
            }
            guard !self.store.isBlockedFingerprint(fingerprint) else { return }
            self.clothingShop.receiveCatalog(envelope, plaintext: plaintext, verifiedFingerprint: fingerprint)
        }
        // Commit-symmetry request (spec: "Catalog delivery must not assume commit symmetry"): a
        // committed peer is asking for our catalog because ITS commit landed after OUR once-per-slot
        // send. The payload carries nothing — the verified sender identity is the whole message.
        registerPayloadHandler(for: .clothingCatalogRequest) { [weak self] _, _, peer in
            guard let self else { return }
            guard let fingerprint = peer?.fingerprint else {
                FernletAuditLog.log("mesh.clothingCatalogRequest.droppedUnverifiedSender")
                return
            }
            guard !self.store.isBlockedFingerprint(fingerprint) else { return }
            self.respondToShopCatalogRequest(fromVerifiedFingerprint: fingerprint, identity: peer)
        }
    }

    /// Phase 3b: one-hop moderation reports ride the friend mesh. The committed-slot gate has already
    /// run; the remaining guards require a transport-verified, unblocked, vault-TRUSTED sender (reports
    /// count only from friends accepted in person — the Sybil defense). `.itemReport` is sealed, so an
    /// unsealed bundle was already rejected at `verify()`; each row's Ed25519 signature is re-checked
    /// against the sender key inside `verifiedRows`, and rows the sender didn't personally sign drop.
    private func registerModerationReportHandler() {
        registerPayloadHandler(for: .itemReport) { [weak self] _, plaintext, peer in
            guard let self else { return }
            guard let peer else {
                FernletAuditLog.log("mesh.itemReport.droppedUnverifiedSender")
                return
            }
            guard !self.store.isBlockedFingerprint(peer.fingerprint) else { return }
            guard self.store.proximityTrustVault.isTrustedProximityPeer(signingPublicKey: peer.signingPublicKey) else { return }
            guard let payload = try? JSONDecoder().decode(ModerationReportPayload.self, from: plaintext) else { return }
            let rows = ModerationReportRelay.verifiedRows(
                from: payload, senderSigningKey: peer.signingPublicKey, now: Date())
            guard !rows.isEmpty else { return }
            self.onModerationRowsReceived?(rows)
        }
    }

    /// Hands this device's OWN signed reports to a committed friend (one-hop). Gated on the recipient
    /// being a vault-TRUSTED (kept-in-person) peer — symmetric with the receive handler — so your signed,
    /// non-repudiable reports never leak to a merely-committed stranger you didn't keep as a friend. No
    /// provider, an empty set, or no signable rows → sends nothing.
    private func sendModerationReports(to slot: PeerSlot, recipientSigningKey: Data) async {
        guard store.proximityTrustVault.isTrustedProximityPeer(signingPublicKey: recipientSigningKey) else { return }
        guard let rows = ownModerationReportsProvider?(), !rows.isEmpty else { return }
        let payload = ModerationReportRelay.buildPayload(ownReports: rows, identity: identity)
        guard !payload.reports.isEmpty else { return }
        await sendEnvelope(.itemReport, encodable: payload, via: slot, sealed: true)
    }

    /// Phase 4: fuzzy state + appearance exchange rides the friend session. The committed-slot gate has
    /// run; require a verified, unblocked, vault-trusted sender and a well-formed payload, then hand it to
    /// the app (which applies its own opt-in + caches). Sealed (in `sealingRequiredTypes`).
    private func registerFriendStateHandler() {
        registerPayloadHandler(for: .friendState) { [weak self] _, plaintext, peer in
            guard let self, let peer else { return }
            guard !self.store.isBlockedFingerprint(peer.fingerprint) else { return }
            guard self.store.proximityTrustVault.isTrustedProximityPeer(signingPublicKey: peer.signingPublicKey) else { return }
            guard let payload = try? JSONDecoder().decode(FriendStatePayload.self, from: plaintext),
                  payload.isWellFormed else { return }
            self.onFriendStateReceived?(peer.fingerprint, payload)
        }
    }

    /// Sends our fuzzy state + appearance to a committed friend. Gated on the recipient being a
    /// vault-TRUSTED (kept-in-person) peer — symmetric with the receive handler — so the fuzzy wellbeing
    /// vibe never leaks to a merely-committed stranger. A nil provider (opt-out) also sends nothing.
    private func sendFriendState(to slot: PeerSlot, recipientSigningKey: Data) async {
        guard store.proximityTrustVault.isTrustedProximityPeer(signingPublicKey: recipientSigningKey) else { return }
        guard let payload = friendStatePayloadProvider?() else { return }
        await sendEnvelope(.friendState, encodable: payload, via: slot, sealed: true)
    }

    /// Phase 6: Group Activities ride the friend mesh as registered feature payloads. The dispatch
    /// default's committed-slot gate has already run; the remaining guard mirrors `.clothingCatalog`
    /// (a transport-VERIFIED, unblocked sender) — NOT the vault-trust gate the friend-state/moderation
    /// handlers use. Activities are ad-hoc, in-session interactions; authorization is carried by the
    /// host-signed, invitee-key-bound `ActivityJoinToken`, not by prior vault friendship (kickoff:
    /// "authorization is independent of the shared handshake"). `.activityJoinRequest` is UNSEALED
    /// (identity-only, host re-validates against the verified slot); the other four are sealed.
    private func registerActivityHandlers() {
        registerPayloadHandler(for: .activityOffer) { [weak self] _, plaintext, peer in
            guard let self, let peer else { return }
            guard !self.store.isBlockedFingerprint(peer.fingerprint) else { return }
            guard let payload = try? JSONDecoder().decode(ActivityOfferPayload.self, from: plaintext),
                  payload.isWellFormed else { return }   // R5: format+version validated at entry
            self.activities.receiveOffer(payload, fromFingerprint: peer.fingerprint,
                                         verifiedHostSigningPublicKey: peer.signingPublicKey)
        }
        registerPayloadHandler(for: .activityJoinRequest) { [weak self] _, plaintext, peer in
            guard let self, let peer else { return }
            guard !self.store.isBlockedFingerprint(peer.fingerprint) else { return }
            guard let payload = try? JSONDecoder().decode(ActivityJoinRequestPayload.self, from: plaintext),
                  payload.isWellFormed else { return }   // R5: rejects empty keys too
            self.activities.receiveJoinRequest(payload,
                                               verifiedFingerprint: peer.fingerprint,
                                               verifiedSigningPublicKey: peer.signingPublicKey,
                                               verifiedKeyAgreementPublicKey: peer.keyAgreementPublicKey)
        }
        registerPayloadHandler(for: .activityJoinGrant) { [weak self] _, plaintext, peer in
            guard let self, let peer else { return }
            guard !self.store.isBlockedFingerprint(peer.fingerprint) else { return }
            guard let payload = try? JSONDecoder().decode(ActivityJoinGrantPayload.self, from: plaintext),
                  payload.isWellFormed else { return }   // R5: format+version validated at entry
            self.activities.receiveGrant(payload, fromFingerprint: peer.fingerprint)
        }
        registerPayloadHandler(for: .activityRosterSnapshot) { [weak self] _, plaintext, peer in
            guard let self, let peer else { return }
            guard !self.store.isBlockedFingerprint(peer.fingerprint) else { return }
            guard let payload = try? JSONDecoder().decode(ActivityRosterSnapshotPayload.self, from: plaintext),
                  payload.isWellFormed else { return }
            self.activities.receiveSnapshot(payload.snapshot)
        }
        registerPayloadHandler(for: .activitySync) { [weak self] _, plaintext, peer in
            guard let self, let peer else { return }
            guard !self.store.isBlockedFingerprint(peer.fingerprint) else { return }
            guard let payload = try? JSONDecoder().decode(ActivitySyncPayload.self, from: plaintext),
                  payload.isWellFormed else { return }   // R5: format+version validated at entry
            self.activities.receiveSync(payload, fromFingerprint: peer.fingerprint)
        }
    }

    /// Fingerprints of currently-committed slots that advertise the `.activities` capability — the
    /// activity manager's "who can I offer/gossip to right now" seam.
    private func committedActivityPeerFingerprints() -> [String] {
        slots.compactMap { slot in
            guard let fingerprint = slot.fingerprint, slot.supports(.activities) else { return nil }
            return fingerprint
        }
    }

    /// Seal + sign + transmit an activity payload to a verified fingerprint's committed slot. Nothing is
    /// sent if that peer no longer has a committed slot (they left the session).
    private func sendActivityEnvelope(_ type: PayloadType, _ payload: any Encodable, toFingerprint fingerprint: String, sealed: Bool) async {
        guard let slot = slots.first(where: { $0.fingerprint == fingerprint }) else { return }
        await sendEnvelope(type, encodable: payload, via: slot, sealed: sealed)
    }

    /// Phase 5: live-session temporary messages ride the friend mesh as registered feature payloads.
    /// The dispatch default's committed-slot gate has already run; the remaining guards mirror
    /// `.friendPhoto`/`.clothingCatalog`: a transport-VERIFIED fingerprint is required and blocked
    /// fingerprints drop silently. `.tempMessage` is in `sealingRequiredTypes`, so an unsealed message
    /// was already rejected at `verify()` — this handler only ever sees a decrypted, sealed payload.
    /// Dedup / per-sender rate limit / sanitize + cap all live in `SessionMessageStore.receiveIncoming`.
    private func registerSessionMessageHandler() {
        registerPayloadHandler(for: .tempMessage) { [weak self] envelope, plaintext, peer in
            guard let self else { return }
            // The 13+ age gate, enforced on the RECEIVE side too. Withholding `.messages` from
            // `localCapabilities()` is only an advertisement: a peer on a modified build, or one
            // holding capabilities cached from an earlier session, can still send. Dropping here is
            // what actually keeps the transcript empty.
            guard self.isChatAllowed else {
                FernletAuditLog.log("mesh.tempMessage.droppedAgeGated")
                return
            }
            guard let peerIdentity = peer else {
                FernletAuditLog.log("mesh.tempMessage.droppedUnverifiedSender")
                return
            }
            let fingerprint = peerIdentity.fingerprint
            guard !self.store.isBlockedFingerprint(fingerprint) else { return }
            guard let payload = try? JSONDecoder().decode(TempMessagePayload.self, from: plaintext) else { return }
            // Display name comes from the handshake-verified identity (peerIdentity.displayName),
            // NOT envelope.senderDisplayName — the latter is a per-message wire claim a committed
            // member could set to another member's name to impersonate them in the transcript.
            // R7: `false` means the store refused the message (duplicate id, empty after
            // sanitizing, or a per-sender flood cap). Nothing to retry — the sender is gone by now —
            // but a message that silently never appears in the transcript must be attributable.
            let accepted = self.sessionMessages.receiveIncoming(
                id: payload.id,
                senderFingerprint: fingerprint,
                senderDisplayName: peerIdentity.displayName,
                text: payload.text,
                sentAt: payload.sentAt
            )
            if !accepted {
                FernletAuditLog.log("mesh.tempMessage.refused")
            }
        }
    }

    // MARK: - In-session hearts (TF b19 item 5)

    /// In-session hearts ride the live mesh session as a registered `.friendHeart` feature payload
    /// (TF b19 item 5) instead of the fragile on-demand presence pairwise connect. The dispatch
    /// default's committed-slot gate has already run; the receiver-side gates below are MANDATORY and
    /// mirror the presence path exactly (`PresenceManager.proximityCoordinator(_:didReceive:...)`) — a
    /// past review found an opt-out bypass in a share manager, so the `allowNearbyHearts` opt-out, the
    /// trusted-friend requirement, and the block list are ALL enforced here on the RECEIVER before
    /// anything is recorded. `.friendHeart` is in `sealingRequiredTypes`, so an unsealed heart was
    /// already rejected at `verify()` — this handler only ever sees a decrypted, sealed payload.
    private func registerSessionHeartHandler() {
        registerPayloadHandler(for: .friendHeart) { [weak self] _, plaintext, peer in
            self?.receiveSessionHeart(plaintext: plaintext, from: peer)
        }
    }

    private func receiveSessionHeart(plaintext: Data, from peer: ProximityCoordinator.PeerIdentity?) {
        guard let payload = try? JSONDecoder().decode(HeartPayload.self, from: plaintext),
              payload.format == "fernlet.proximity.heart",
              payload.version == 1,
              HeartPayload.isValidDayKey(payload.sentAtDayKey) else { return }
        // Receive-side opt-out (mandatory — one of the homes of `allowNearbyHearts`). A heart to a
        // hearts-off device is silently dropped even though session membership reached us here.
        guard store.allowNearbyHearts else {
            FernletAuditLog.log("mesh.friendHeart.droppedHeartsOff")
            return
        }
        // A verified sender is required (the default dispatch already enforced the committed-slot gate).
        guard let peer else {
            FernletAuditLog.log("mesh.friendHeart.droppedUnverifiedSender")
            return
        }
        // Trusted-friend requirement + block list (signing-key block AND fingerprint block), reusing
        // the SAME eligibility gate the presence path applies.
        guard PresenceManager.isHeartEligibleFriend(peer, in: store) else {
            FernletAuditLog.log("mesh.friendHeart.droppedNonFriend")
            return
        }
        // Wire boundary: the display name is peer-supplied — sanitize (control/zero-width/bidi scalars
        // out, length-capped) before it can be persisted by the ledger.
        let senderName = ItemNameModeration.moderatedPeerDisplayName(peer.displayName)
        // Route through the SAME device-local ledger the presence path uses: it drops duplicates
        // (same id) and enforces the 5-minute per-sender receive rate. Then feed closeness identically.
        if heartLedger?.recordReceivedHeart(id: payload.id, senderDisplayName: senderName, senderFingerprint: peer.fingerprint) ?? false {
            onHeartReceived?(peer.fingerprint)
        }
    }

    /// Whether an in-session heart can ride the mesh to this friend right now: they hold a committed
    /// slot in the live session that advertises the `hearts` capability. A session peer on an older
    /// build (no `.hearts` advertisement) returns `false`, and the caller falls back to presence.
    public func canSendSessionHeart(toFingerprint fingerprint: String) -> Bool {
        slots.contains { $0.fingerprint == fingerprint && $0.supports(.hearts) }
    }

    /// Deliver a heart to a live session member over the already-connected, transport-verified mesh
    /// channel (TF b19 item 5). Honors the SAME send-side opt-out + 5-minute per-friend cooldown as the
    /// presence path, routed through the shared `heartLedger`, so cooldown/closeness converge across
    /// both transports. Drives `sessionHeartState` so the affordance surfaces sending → sent/failed.
    public func sendSessionHeart(to friend: ProximityTrustedPeerRecord) {
        let firstName = PresenceManager.firstName(of: friend.displayName)
        // Send-side opt-out gate (belt: the button hides for a hearts-off device, but never send blind).
        guard store.allowNearbyHearts else {
            failSessionHeart("Turn on nearby hearts to send \(firstName) some warmth.")
            return
        }
        // Active record only — never send to a blocked or revoked (unfriended) peer.
        guard friend.blockedAt == nil, friend.revokedAt == nil else { return }
        guard heartLedger?.canSendHeart(to: friend.fingerprint) ?? true else {
            failSessionHeart("You just sent \(firstName) some warmth — hearts settle for a few minutes.")
            return
        }
        // In-flight claim, taken BEFORE the await and released after it. The cooldown alone cannot
        // close this window: consume-on-send arms the ledger only after the wire write returns, so
        // a second tap during the first send's suspension still sees a clear cooldown and sends a
        // duplicate — which the recipient's own 5-minute receive window then silently discards,
        // while the sender is told "Sent" twice (review finding, 2026-07-27). A claim rather than
        // an early `recordHeartSent` keeps consume-on-send intact: a failed send must not burn the
        // five minutes.
        guard sessionHeartSendsInFlight.insert(friend.fingerprint).inserted else {
            failSessionHeart("Already sending \(firstName) some warmth — one moment.")
            return
        }
        guard let slot = slots.first(where: { $0.fingerprint == friend.fingerprint && $0.supports(.hearts) }) else {
            sessionHeartSendsInFlight.remove(friend.fingerprint)
            failSessionHeart("\(firstName) left the session — no heart was sent.")
            return
        }
        sessionHeartState = .sending(recipientName: friend.displayName)
        // Fire the dispatch seam synchronously (mirrors `onTempMessageSendForTesting`) so a unit test
        // can assert the target slot without a live channel behind the async wire write.
        onSessionHeartSendForTesting?(slot.id)
        let payload = HeartPayload(sentAtDayKey: FernletDate.dayKey(for: Date()))
        let fingerprint = friend.fingerprint
        let recipientName = friend.displayName
        Task { [weak self] in
            await self?.deliverSessionHeart(payload: payload, via: slot, fingerprint: fingerprint, recipientName: recipientName)
        }
    }

    private func deliverSessionHeart(
        payload: HeartPayload,
        via slot: PeerSlot,
        fingerprint: String,
        recipientName: String
    ) async {
        // The in-flight claim taken by `sendSessionHeart` is released on EVERY exit from here.
        defer { sessionHeartSendsInFlight.remove(fingerprint) }
        // Re-check the cooldown: the claim stops a concurrent duplicate, this stops a heart the
        // OTHER transport (the presence path shares this ledger) armed while we were suspended.
        guard heartLedger?.canSendHeart(to: fingerprint) ?? true else {
            failSessionHeart("You just sent \(PresenceManager.firstName(of: recipientName)) some warmth — hearts settle for a few minutes.")
            return
        }
        // Sealed to the slot's transport-verified KA key (`.friendHeart` is in `sealingRequiredTypes`).
        let sent = await sendEnvelopeReportingResult(.friendHeart, encodable: payload, via: slot, sealed: true)
        if sent {
            // Consume-on-send: only record + feed closeness after the wire write succeeds.
            heartLedger?.recordHeartSent(to: fingerprint)
            onHeartSent?(fingerprint)
            sessionHeartState = .sent(recipientName: recipientName)
        } else {
            sessionHeartState = .failed(message: "Could not send that heart just now.")
        }
        scheduleSessionHeartStateClear()
    }

    private func failSessionHeart(_ message: String) {
        sessionHeartState = .failed(message: message)
        scheduleSessionHeartStateClear()
    }

    private func scheduleSessionHeartStateClear() {
        sessionHeartStateClearTask?.cancel()
        sessionHeartStateClearTask = Task { [weak self] in
            // Cancelled: a newer heart state replaced this one, so leave it alone (R7).
            do {
                try await Task.sleep(for: .seconds(3))
            } catch {
                return
            }
            self?.sessionHeartState = .idle
        }
    }

    // MARK: - Proximity-join state

    /// True while a proximity-join session is active (started via startJoin).
    /// Controls auto-invite-all and 25 s uncommitted-channel TTL behaviour.
    public private(set) var isProximityJoin = false

    /// Controls whether additional friends can join the active Friends session.
    /// This applies before pairwise sessions are promoted to a mesh descriptor.
    public private(set) var isSessionOpen = true

    /// True when at least one peer is committed (pairwise) or a mesh exists.
    public var isInSession: Bool {
        currentMesh != nil || slots.contains(where: { $0.fingerprint != nil })
    }

    /// Shots remaining for this session (10 minus sent count, clamped to ≥ 0).
    public var filmRemaining: Int { max(0, Self.maxPhotosPerSenderPerSession - photosAddedThisSession) }

    public var localFingerprint: String { identity.localFingerprint }
    public var localSigningPublicKey: Data { identity.localSigningPublicKey }
    /// This device's X25519 public half. Public because the QR ceremony transcript binds the
    /// SCANNER's key agreement key, so anything reasoning about a round we sent — a test, a future
    /// re-verification surface — needs the same value `handleVerifyResponse` verifies against.
    public var localKeyAgreementPublicKey: Data { identity.localKeyAgreementPublicKey }

    public var sessionParticipants: [MeshSessionParticipant] {
        var participants = [
            MeshSessionParticipant(
                fingerprint: identity.localFingerprint,
                displayName: displayName,
                isLocal: true
            )
        ]
        if let mesh = currentMesh {
            participants += mesh.members
                .filter { $0.fingerprint != identity.localFingerprint }
                .map {
                    MeshSessionParticipant(
                        fingerprint: $0.fingerprint,
                        displayName: $0.displayName,
                        isLocal: false
                    )
                }
        } else {
            participants += slots.compactMap { slot in
                guard let fingerprint = slot.fingerprint else { return nil }
                return MeshSessionParticipant(
                    fingerprint: fingerprint,
                    // MCPeerID display names have no other entry point, so this is the ingest
                    // equivalent for the transport name (R5).
                    displayName: ItemNameModeration.moderatedPeerDisplayName(slot.peer.displayHint),
                    isLocal: false
                )
            }
        }
        return participants
            .filter { !removedMemberFingerprints.contains($0.fingerprint) }
            .reduce(into: []) { result, participant in
                if !result.contains(where: { $0.fingerprint == participant.fingerprint }) {
                    result.append(participant)
                }
            }
    }

    // MARK: - Session roster (Phase 2 friend minting)

    /// Records a committed peer into the session roster. Dedupe is by fingerprint; the display
    /// name is last-write-wins across re-commits. Internal so tests can drive the roster without
    /// a full handshake.
    func recordSessionParticipant(
        displayName: String,
        fingerprint: String,
        signingPublicKey: Data,
        keyAgreementPublicKey: Data
    ) {
        // Belt-and-braces: a peer the session voted out (or the user asked to remove) is never
        // re-recorded, so it can never be offered by the keep-as-friend prompt.
        guard !removedMemberFingerprints.contains(fingerprint) else { return }
        // Single ingest for the roster, so BOTH callers (the verified PeerIdentity path and
        // promoteToMesh's raw `slot.peer.displayHint`) are covered by one coercion. Nothing keys
        // off the roster display name — lookups and removal key on fingerprint — so rewriting an
        // existing entry to the sanitized form is safe.
        let name = ItemNameModeration.moderatedPeerDisplayName(displayName)
        if let index = sessionRoster.firstIndex(where: { $0.fingerprint == fingerprint }) {
            sessionRoster[index].displayName = name
        } else {
            // R3: one entry per distinct fingerprint, but a peer that regenerates its identity and
            // re-commits (auto-dwell in proximity join) would otherwise add one entry per commit.
            guard sessionRoster.count < Self.maxSessionRosterEntries else {
                FernletAuditLog.log("mesh.roster.capReached")
                return
            }
            sessionRoster.append(MeshSessionRosterEntry(
                displayName: name,
                fingerprint: fingerprint,
                signingPublicKey: signingPublicKey,
                keyAgreementPublicKey: keyAgreementPublicKey
            ))
        }
    }

    /// Drops the whole live roster. Internal/test seam only — UI finalize paths must NOT call
    /// this (it clobbered entries belonging to the NEXT session's review): the scoped consumers
    /// are `completeFriendReview(_:)` for a promoted batch and `consumeRosterEntries(fingerprints:)`
    /// for the in-session camera review.
    public func clearSessionRoster() {
        sessionRoster.removeAll()
    }

    /// Internal seam: the new-session roster reset, called by startJoin/startNewMesh and driven
    /// directly by unit tests so they never start real Bonjour radios. Deliberately does NOT
    /// touch `pendingFriendReview` — an unreviewed batch from the previous session survives into
    /// the next search cycle and re-presents (merged) at its teardown. The clothing-shop window and
    /// held catalogs are equally deliberately untouched (spec: "'Next session start' = first slot
    /// COMMIT, not search start"): startJoin fires automatically on every Social-tab entry and scene
    /// reactivation, so closing the window here would destroy it before the user could ever reach
    /// its only entry point. The shop resets at actual session FORMATION — the first committed slot
    /// (`noteSlotCommittedForShop`).
    func resetSessionRosterForNewSession() {
        sessionRoster.removeAll()
        // Manifest-announced authors are session-scoped evidence, exactly like the roster (R3).
        manifestAnnouncedPhotoAuthors.removeAll()
    }

    /// Scoped roster consume for the in-session camera review flow: removes ONLY the presented
    /// entries from the live roster, so a peer who commits mid-review stays in the roster and is
    /// offered at true session end via the promoted batch.
    public func consumeRosterEntries(fingerprints: Set<String>) {
        sessionRoster.removeAll { fingerprints.contains($0.fingerprint) }
    }

    /// Consumes the promoted friend-review batch iff `id` matches the outstanding one. The UI
    /// calls this once its review flow completes (kept, skipped, dismissed = skip all, or
    /// auto-consumed when nothing was eligible).
    public func completeFriendReview(_ id: UUID) {
        guard pendingFriendReview?.id == id else { return }
        pendingFriendReview = nil
    }

    /// Phase 2 ("Session-end review is model-state, not view-events"): when NO committed slot
    /// remains (the same condition `isInSession` derives from) and the live roster is non-empty,
    /// move the roster into `pendingFriendReview`, merging by fingerprint into any existing
    /// unconsumed batch — candidates are never dropped. Idempotent and cheap; called after every
    /// slot-removal path (removeSlot, disconnectSlot — which the checkCoordinatorStates stale
    /// eviction funnels through) and on leaveSession/stopSearching teardown.
    private func promoteRosterToPendingReviewIfSessionEnded() {
        guard !isInSession, !sessionRoster.isEmpty else { return }
        if var batch = pendingFriendReview {
            for entry in sessionRoster {
                if let index = batch.entries.firstIndex(where: { $0.fingerprint == entry.fingerprint }) {
                    batch.entries[index] = entry   // last-write-wins, matching the roster's dedupe rule
                } else if batch.entries.count < Self.maxSessionRosterEntries {
                    batch.entries.append(entry)
                }   // R3: an unreviewed batch survives sessions, so the merge honors the roster cap
            }
            pendingFriendReview = batch
        } else {
            pendingFriendReview = MeshFriendReviewBatch(entries: sessionRoster)
        }
        sessionRoster.removeAll()
    }

    /// End the current session (pairwise or mesh) and clear session photos.
    /// Call this after the develop/review flow completes.
    public func leaveSession() {
        sessionPhotos.removeAll()
        photoSessionStartedAt = nil
        activePhotoSessionID = nil
        leaveMesh()
    }

    /// Ends the session, telling every peer why first.
    ///
    /// **Sends a signed `.meshMemberDeparture`, never the legacy `.sessionGoodbye`** (plan §8.3).
    /// Item 3 removed the unsigned goodbye and left this function sending nothing at all; item 5
    /// closes that gap with the signed replacement, because a departure and the rotation it causes
    /// are one act — a receiver inserts the record, its derived roster loses this device, and its
    /// coordinator rotates the group key without waiting for the 15-minute tick.
    ///
    /// The send is **awaited before the teardown**, which is the whole reason this function is
    /// `async` and separate from ``leaveSession()``: `leaveSession` stops the radio, so a
    /// fire-and-forget departure would race the transport it needs.
    /// **Durable before acknowledged (P3 item 6, plan §3.6).** The departure is written into the
    /// sealed context first; only then does the signed frame go out. A save that fails abandons the
    /// emit — a device that told its peers it left and then came back thinking it had not is worse
    /// than one that leaves quietly — and the local teardown happens either way, because refusing
    /// to end a session the user asked to end is not an option this code gets to take.
    public func leaveSessionAfterNotifyingPeers() async {
        let transition = applySessionEvent(.departureRequested)
        // A REFUSED transition (no session was ever started through the machine) leaves the emit
        // alone; only a taken transition whose save failed blocks it.
        let blockedByStore = transition.nextState != nil && lastSessionEffectFailure != nil
        if !blockedByStore {
            await sendMembershipEvent(.meshMemberDeparture)
            applySessionEvent(.departureSent)
        }
        leaveSession()
    }

    public func finishSessionPhotos(keeping keptPhotoIDs: Set<UUID>) {
        finalizeCurrentPhotoSessionMetadata()
        let sessionPhotoIDs = Set(sessionPhotos.map(\.id))
        meshPhotos.removeAll { photo in
            sessionPhotoIDs.contains(photo.id) && !keptPhotoIDs.contains(photo.id)
        }
        sessionPhotos.removeAll()
        persistPhotoIndex(meshPhotos)
        prunePhotoWallPreferences()
    }

    public func deleteAllSessionPhotos() {
        finishSessionPhotos(keeping: [])
    }

    /// Permanently removes a single cached photo from the persistent gallery: drops it from the
    /// in-memory lists, clears any wall preference that pointed at it (favorite / aggregated cover),
    /// and re-saves the cache so the store's orphan cleanup deletes its image + thumbnail files.
    public func deletePhoto(_ photoID: UUID) {
        let existed = meshPhotos.contains { $0.id == photoID }
        meshPhotos.removeAll { $0.id == photoID }
        sessionPhotos.removeAll { $0.id == photoID }
        // Drops the favorite / aggregated-cover entries that pointed at the photo (and any other
        // entry the cache no longer backs).
        prunePhotoWallPreferences()

        guard existed else { return }
        persistPhotoIndex(meshPhotos)
    }

    /// The one seam every wall save goes through, so the deferred-index rule is enforced in a
    /// single place.
    ///
    /// While `photoIndexDeferred` holds, `meshPhotos` is empty because the index could not be READ
    /// — and ``PrivateMediaStore/save(_:)`` is a full-index rewrite that deletes every photo file
    /// the set omits, so writing it would destroy the wall this funnel deliberately keeps. Re-read
    /// first: only a successful read clears the flag, and it brings the disk entries back into
    /// `meshPhotos` (this session's arrivals win by id — they carry the bytes still to be written).
    /// Nothing was deletable while the flag was set, so nothing can be resurrected by that merge.
    private func persistPhotoIndex(_ photos: [FriendPhotoPayload]) {
        guard photoIndexDeferred else {
            photoCacheStore.save(photos)
            return
        }
        guard case .entries(let recovered) = photoCacheStore.loadIndex() else {
            FernletAuditLog.log("mesh.photoIndex.saveSkippedWhileDeferred")
            return
        }
        photoIndexDeferred = false
        let merged = Self.mergedPhotoIndex(session: photos, recovered: recovered)
        meshPhotos = merged.map { $0.withoutImageData() }
        photoCacheStore.save(merged)
    }

    /// Union of this session's index and the copy just recovered from disk: newest first, capped
    /// like the store, session entries winning by id so a payload still carrying its bytes is not
    /// replaced by the byte-less recovered row.
    private static func mergedPhotoIndex(
        session: [FriendPhotoPayload],
        recovered: [FriendPhotoPayload]
    ) -> [FriendPhotoPayload] {
        let sessionIDs = Set(session.map(\.id))
        let merged = session + recovered.filter { !sessionIDs.contains($0.id) }
        return Array(merged.sorted { $0.addedAt > $1.addedAt }.prefix(PrivateMediaStore.maxCachedPhotos))
    }

    /// Drops wall-preference entries whose session or photo no longer exists in `meshPhotos`
    /// (FIFO eviction past the 1000-photo cap, session discard, single-photo delete, or a favorite
    /// on a photo that was never kept). The sidecar is install-lifetime and survives delete-all
    /// (the wall is deliberately kept), so without this it accumulated one `aggregatedSessionIDs`
    /// + cover entry per aggregated session forever while the photos themselves rolled off (R3).
    /// Three filters over finite collections; persists only when something actually changed. Never
    /// called from `photoWallPosts` — that getter must stay mutation-free.
    private func prunePhotoWallPreferences() {
        // A deferred index means `meshPhotos` is empty because nothing could be READ, not because
        // the wall is empty; pruning against it would drop the favorite and cover of every photo
        // still on disk. Same fail-closed rule as `persistPhotoIndex`.
        guard !photoIndexDeferred else { return }
        let liveSessionIDs = Set(meshPhotos.compactMap { $0.session?.id })
        let livePhotoIDs = Set(meshPhotos.map(\.id))
        var pruned = photoWallPreferences
        pruned.aggregatedSessionIDs = pruned.aggregatedSessionIDs.filter { liveSessionIDs.contains($0) }
        pruned.coverPhotoIDsBySession = pruned.coverPhotoIDsBySession
            .filter { liveSessionIDs.contains($0.key) && livePhotoIDs.contains($0.value) }
        pruned.favoritePhotoIDsBySession = pruned.favoritePhotoIDsBySession
            .filter { liveSessionIDs.contains($0.key) && livePhotoIDs.contains($0.value) }
        guard pruned != photoWallPreferences else { return }
        photoWallPreferences = pruned
        persistPhotoWallPreferences()
    }

    // MARK: - Public API

    public func startNewMesh(name: String? = nil) {
        resetSessionRosterForNewSession()   // live roster only — pendingFriendReview survives
        let meshName = name ?? MeshNameGenerator.generate()
        let now = Date()
        let localFP = identity.localFingerprint
        let member = MeshMember(
            fingerprint: localFP,
            displayName: displayName,
            signingPublicKey: identity.localSigningPublicKey,
            keyAgreementPublicKey: identity.localKeyAgreementPublicKey,
            joinedAt: now
        )
        let created = MeshDescriptor(
            meshID: UUID(),
            name: meshName,
            mode: .open,
            members: [member],
            nameSetAt: now,
            nameSetBy: localFP,
            modeSetAt: now,
            modeSetBy: localFP,
            createdAt: now
        )
        currentMesh = created
        // P3 item 3: this device founded the mesh, so its own signing key is the one key that can
        // authorize the bootstrap admission. Joining an existing mesh adopts a ledger instead —
        // that path belongs to item 7, where the shipping roster starts deriving from records.
        prepareMembershipLedger(meshID: created.meshID, founderSigningPublicKey: identity.localSigningPublicKey)
        // P3 item 6, plan §3.6: the context reaches the disk BEFORE the UI is shown a mesh. A mesh
        // this device could not write down is a mesh it would not remember founding after a
        // force-quit, so it is abandoned rather than half-created.
        resetSessionStateMachine(keepingTerminalState: false)
        startSessionCeiling(
            hardDeadline: created.createdAt.addingTimeInterval(MeshSessionCeiling.ceilingSeconds),
            startedAt: now
        )
        applySessionEvent(.founded)
        guard lastSessionEffectFailure == nil else {
            abandonUnpersistedSession()
            return
        }
        startSearching()
    }

    /// Undoes a session start whose context could not be sealed (plan §3.6). Deliberately narrow —
    /// it unwinds exactly what ``startNewMesh(name:)`` had set, and never touches the rejoin bar.
    private func abandonUnpersistedSession() {
        FernletAuditLog.log("mesh.session.abandonedNotDurable")
        currentMesh = nil
        membershipVerifier = nil
        sessionQuotaMeshID = nil
        resetSessionStateMachine(keepingTerminalState: false)
    }

    /// Clears the run-scoped halves of the state machine.
    ///
    /// - Parameter keepingTerminalState: `true` when a session ENDED — `departed`/`terminated`/
    ///   `expired` is the answer to "what happened to it", and only a new session resets that. The
    ///   rejoin bar is never cleared here; it is the durable half and it outlives every session.
    private func resetSessionStateMachine(keepingTerminalState: Bool) {
        sessionCeiling = nil
        sessionMonotonicOrigin = nil
        stagedTermination = nil
        lastSessionEffectFailure = nil
        lastSessionTransitionRejection = nil
        awaitingResumeMerge = false
        offersForegroundResume = false
        idleLapseDeadline = nil
        restoredSessionContext = nil
        if !keepingTerminalState || !sessionState.hasEnded { sessionState = .idle }
    }

    /// Entry point for the Connect-tab proximity-join flow.
    /// Advertises + browses `fernlet-friend`, auto-invites every discovered peer,
    /// and gates commit on a 15 cm / 0.8 s dwell via ProximityCommitDetector.
    public func startJoin() {
        isProximityJoin = true
        isSessionOpen = true
        photosAddedThisSession = 0
        sessionQuotaMeshID = nil
        receivedPhotoIDsByFingerprint.removeAll()
        receiveQuotaMeshID = nil
        sessionPhotos.removeAll()
        // Live-roster reset only (new session). pendingFriendReview is deliberately untouched:
        // an unreviewed batch from the previous session survives into this search cycle.
        resetSessionRosterForNewSession()
        pendingRemovalProposals.removeAll()
        removedMemberFingerprints.removeAll()
        approvedRemovalProposalIDs.removeAll()
        photoSessionStartedAt = Date()
        activePhotoSessionID = UUID()
        // A new search cycle is a new session: the machine goes back to `idle` even if the last one
        // ended (the rejoin bar for THAT mesh survives — see `resetSessionStateMachine`).
        resetSessionStateMachine(keepingTerminalState: false)
        startSearching()
    }

    public func stopJoin() {
        isProximityJoin = false
        stopSearching()
    }

    public func leaveMesh() {
        currentMesh = nil
        // Membership records are scoped to one mesh; carrying a ledger across meshes would let a
        // record about member X in mesh A be read against mesh B's roster.
        membershipVerifier = nil
        peerInventoryDigests.removeAll()
        isSessionOpen = true
        pendingAdmissionRequests.removeAll()
        pendingRemovalProposals.removeAll()
        removedMemberFingerprints.removeAll()
        approvedRemovalProposalIDs.removeAll()
        photosAddedThisSession = 0
        sessionQuotaMeshID = nil
        receivedPhotoIDsByFingerprint.removeAll()
        receiveQuotaMeshID = nil
        clearGroupKeyState()
        clearActiveVerifyQR()
        // P3 item 6: the run-scoped halves of the machine go with the session; a TERMINAL state
        // stays, because "this device departed" is the answer until a new session is started.
        resetSessionStateMachine(keepingTerminalState: true)
        stopSearching()
    }

    public func proposeRemoval(of participant: MeshSessionParticipant) {
        guard !participant.isLocal else { return }
        let otherParticipants = sessionParticipants.filter { !$0.isLocal }
        if otherParticipants.count == 1, otherParticipants[0].fingerprint == participant.fingerprint {
            // Pairwise shortcut: asking to remove the only other peer just ends the session —
            // and a peer the user asked to remove must never be offered by the keep prompt, so
            // drop them from the roster before the teardown promotes it into the review batch.
            sessionRoster.removeAll { $0.fingerprint == participant.fingerprint }
            leaveSession()
            return
        }
        let proposal = MeshRemovalProposalPayload(
            id: UUID(),
            targetFingerprint: participant.fingerprint,
            targetDisplayName: participant.displayName,
            proposerFingerprint: identity.localFingerprint,
            proposerDisplayName: displayName,
            createdAt: Date(),
            expiresAt: Date().addingTimeInterval(60)
        )
        handleRemovalProposal(proposal, rebroadcast: true)
    }

    public func canSecondRemoval(_ proposal: MeshRemovalProposalPayload) -> Bool {
        proposal.expiresAt > Date()
            && proposal.proposerFingerprint != identity.localFingerprint
            && proposal.targetFingerprint != identity.localFingerprint
            && !approvedRemovalProposalIDs.contains(proposal.id)
    }

    public func secondRemoval(_ proposal: MeshRemovalProposalPayload) {
        guard canSecondRemoval(proposal) else { return }
        handleRemovalSecond(
            MeshRemovalSecondPayload(
                proposal: proposal,
                seconderFingerprint: identity.localFingerprint
            ),
            senderFingerprint: identity.localFingerprint,
            rebroadcast: true
        )
    }

    /// Appends to the rolling epoch log, keeping only the newest ``maxEpochLogEntries`` (R3: no
    /// append-only in-memory log fed by wire input).
    private func recordEpoch(_ epoch: Int, since: Date) {
        epochLog.append((epoch: epoch, since: since))
        if epochLog.count > Self.maxEpochLogEntries {
            epochLog = Array(epochLog.suffix(Self.maxEpochLogEntries))
        }
    }

    private func clearGroupKeyState() {
        clearEpochKeyring()
        // An outstanding join request only authorizes a grant for the session that issued it.
        outstandingAdmissionRequestBySlot.removeAll()
        rotationTriggers.reset()
        rotationDebounceTask?.cancel()
        rotationDebounceTask = nil
        lastRotationCause = nil
        lastRotationBlockReason = nil
        rotationTimer?.cancel()
        rotationTimer = nil
        beaconTimer?.cancel()
        beaconTimer = nil
        rotationSyncTask?.cancel()
        rotationSyncTask = nil
        pendingRotationAcks.removeAll()
        pendingRotationClosingEpoch = nil
        localJoinedEpoch = 0
        lastBeaconReceivedAt = nil
        lastKnownNextRotationAt = nil
        epochLog.removeAll()
    }

    public func renameMesh(_ name: String) {
        guard var mesh = currentMesh else { return }
        let now = Date()
        mesh.name = name
        mesh.nameSetAt = now
        mesh.nameSetBy = identity.localFingerprint
        currentMesh = mesh
        broadcastMeshDescriptor()
    }

    public func setMeshMode(_ mode: MeshMode) {
        guard var mesh = currentMesh else { return }
        let now = Date()
        isSessionOpen = mode == .open
        mesh.mode = mode
        mesh.modeSetAt = now
        mesh.modeSetBy = identity.localFingerprint
        currentMesh = mesh
        updateDiscoveryInfo()
        broadcastMeshDescriptor()
    }

    public func setSessionOpen(_ isOpen: Bool) {
        isSessionOpen = isOpen
        if currentMesh != nil {
            setMeshMode(isOpen ? .open : .closed)
        }
        if !isOpen {
            for slot in slots where slot.fingerprint == nil {
                removeSlot(slot)
            }
        }
    }

    public func addPhoto(_ data: Data) {
        // Reset counter when the mesh changes between calls.
        if currentMesh?.meshID != sessionQuotaMeshID {
            sessionQuotaMeshID = currentMesh?.meshID
            photosAddedThisSession = 0
        }
        guard photosAddedThisSession < Self.maxPhotosPerSenderPerSession else {
            meshError = "You've shared the maximum of \(Self.maxPhotosPerSenderPerSession) photos in this mesh session."
            return
        }
        guard let image = UIImage(data: data),
              let normalized = image.resizedForFriendSharing().jpegData(compressionQuality: 0.82) else { return }

        let wirePhoto: FriendPhotoPayload
        let session = currentPhotoSessionMetadata()
        if let key = currentGroupKey {
            // FAIL CLOSED (R7): while a group key exists the photo is sealed or not sent at all —
            // the old `try?`-into-else fallback silently downgraded it to an epoch-0 plaintext send.
            let ciphertext: Data
            let nonce: Data
            do {
                (ciphertext, nonce) = try Self.encryptPhoto(normalized, key: key)
            } catch {
                meshError = "Couldn't encrypt that photo — it wasn't shared."
                FernletAuditLog.log(
                    "mesh.photo.encryptFailed",
                    context: ["error": String(describing: error)]
                )
                return
            }
            // Epoch ≥ 1: send encrypted; cache the locally-decrypted form.
            wirePhoto = FriendPhotoPayload(
                encryptedImageData: ciphertext,
                nonce: nonce,
                keyEpoch: key.epoch,
                senderName: displayName,
                senderFingerprint: identity.localFingerprint,
                senderSigningPublicKey: identity.localSigningPublicKey,
                session: session
            )
            cachePhoto(FriendPhotoPayload(
                id: wirePhoto.id,
                imageData: normalized,
                addedAt: wirePhoto.addedAt,
                senderName: displayName,
                senderFingerprint: identity.localFingerprint,
                senderSigningPublicKey: identity.localSigningPublicKey,
                session: session
            ), includeInSession: true)
        } else {
            // Epoch 0: solo member or rotation not yet started; send unencrypted.
            wirePhoto = FriendPhotoPayload(
                imageData: normalized,
                senderName: displayName,
                senderFingerprint: identity.localFingerprint,
                senderSigningPublicKey: identity.localSigningPublicKey,
                session: session
            )
            cachePhoto(wirePhoto, includeInSession: true)
        }
        photosAddedThisSession += 1
        for slot in activeSlots {
            Task { [weak self] in
                await self?.sendEnvelope(.friendPhoto, encodable: wirePhoto, via: slot, sealed: true)
            }
        }
    }

    public func allowAdmission(_ request: MeshAdmissionRequestPayload) {
        pendingAdmissionRequests.removeAll { $0.requesterSigningPublicKey == request.requesterSigningPublicKey }
        guard var mesh = currentMesh, mesh.meshID == request.meshID else { return }
        let newMember = MeshMember(
            fingerprint: request.requesterFingerprint,
            // Belt and braces: this method is `public` and accepts an arbitrary payload, so it must
            // not rely on `handleAdmissionRequest` having sanitized the queued copy. Idempotent.
            displayName: ItemNameModeration.moderatedPeerDisplayName(request.requesterDisplayName),
            signingPublicKey: request.requesterSigningPublicKey,
            keyAgreementPublicKey: request.requesterKeyAgreementPublicKey,
            joinedAt: Date()
        )
        if !mesh.members.contains(where: { $0.signingPublicKey == request.requesterSigningPublicKey }) {
            mesh.members.append(newMember)
        }
        currentMesh = mesh
        Task { [weak self] in
            guard let self else { return }
            let token: MeshAdmissionToken
            do {
                token = try MeshAdmissionToken.signed(
                    meshID: mesh.meshID,
                    joinerFingerprint: request.requesterFingerprint,
                    joinerSigningPublicKey: request.requesterSigningPublicKey,
                    admitterIdentity: self.identity
                )
            } catch {
                // Recovery is "no grant" — the requester keeps waiting — so the drop is NAMED (R7);
                // without this the admitter looks like it simply ignored the request.
                FernletAuditLog.log(
                    "mesh.admissionGrant.signFailed",
                    context: ["error": String(describing: error)]
                )
                self.meshError = "Couldn't let them in just now — ask them to try again."
                return
            }

            // Phase 3: wrap the current group key to the slot's handshake-verified KA key,
            // not the request's claimed key, to prevent key-substitution attacks.
            var encryptedKey: Data? = nil
            var keyEpoch = 0
            if let groupKey = self.currentGroupKey {
                let kaKey = self.slots.first(where: { $0.fingerprint == request.requesterFingerprint })?
                    .verifiedKeyAgreementPublicKey ?? request.requesterKeyAgreementPublicKey
                do {
                    encryptedKey = try self.identity.encryptGroupKey(groupKey.keyBytes, for: kaKey)
                } catch {
                    // The grant still goes out (the joiner is admitted, keyless) — but a wrap
                    // failure means they will decrypt nothing until the next rotation, so name it (R7).
                    FernletAuditLog.log(
                        "mesh.admissionGrant.keyWrapFailed",
                        context: ["error": String(describing: error)]
                    )
                }
                keyEpoch = groupKey.epoch
            }

            let grant = MeshAdmissionGrantPayload(
                meshID: mesh.meshID,
                requesterFingerprint: request.requesterFingerprint,
                token: token,
                encryptedCurrentKey: encryptedKey,
                currentKeyEpoch: keyEpoch
            )
            if let slot = self.slots.first(where: { $0.fingerprint == request.requesterFingerprint }) {
                await self.sendEnvelope(.meshAdmissionGrant, encodable: grant, via: slot)
            }
            self.broadcastMeshDescriptor()
        }
    }

    public func declineAdmission(_ request: MeshAdmissionRequestPayload) {
        pendingAdmissionRequests.removeAll { $0.requesterSigningPublicKey == request.requesterSigningPublicKey }
    }

    // MARK: - Payload handler registry (Phase 1)

    /// A feature-module inbound handler. Receives exactly what the core switch cases consume: the
    /// verified envelope, the decrypted plaintext, and the transport-verified peer identity.
    public typealias MeshPayloadHandler = @MainActor (
        _ envelope: FernletIdentityEnvelope,
        _ plaintext: Data,
        _ peer: ProximityCoordinator.PeerIdentity?
    ) -> Void

    @ObservationIgnored private var registeredPayloadHandlers: [PayloadType: MeshPayloadHandler] = [:]

    /// Registration seam for feature payloads carried on the friend mesh (shop registers in
    /// Phase 3, temp messages in Phase 5). Dispatch order: the core mesh switch runs first, so a
    /// registration can never shadow mesh-control handling; the registry is consulted only for
    /// types the switch leaves unhandled; unregistered known types keep today's silent drop.
    public func registerPayloadHandler(for type: PayloadType, handler: @escaping MeshPayloadHandler) {
        registeredPayloadHandlers[type] = handler
    }

    // MARK: - ProximityPayloadHandling

    public func proximityCoordinator(
        _ coordinator: ProximityCoordinator,
        didReceive envelope: FernletIdentityEnvelope,
        plaintext: Data,
        from peer: ProximityCoordinator.PeerIdentity?
    ) {
        // Unknown (newer-build) payload types are parked by the coordinator and never dispatched
        // here; the guard is belt-and-braces for any future direct caller.
        guard let payloadType = envelope.payloadType else { return }
        let slot = slots.first { $0.coordinator === coordinator }
        let decoder = JSONDecoder()

        switch payloadType {
        case .meshDescriptor, .meshAdmissionRequest, .meshAdmissionGrant:
            dispatchMembershipPayload(payloadType, plaintext: plaintext, decoder: decoder, peer: peer, slot: slot)
        // QR verification ceremony (Increment 4): these run PRE-COMMIT by design — the registry
        // default's committed-slot gate would drop them — and carry their own binding (sealed +
        // signed + double-nonce transcript).
        case .verifyChallenge:
            handleVerifyChallenge(envelope, plaintext: plaintext, slot: slot)
        case .verifyResponse:
            handleVerifyResponse(envelope, plaintext: plaintext, slot: slot)
        case .friendPhoto, .friendPhotoManifest, .friendPhotoRequest:
            dispatchPhotoPayload(payloadType, plaintext: plaintext, decoder: decoder, peer: peer, slot: slot)
        case .meshFriendVouchList:
            if let payload = try? decoder.decode(MeshFriendVouchListPayload.self, from: plaintext) {
                receiveVouchList(payload, senderFingerprint: peer?.fingerprint)
            }
        case .meshRemovalProposal, .meshRemovalSecond:
            dispatchRemovalPayload(payloadType, plaintext: plaintext, decoder: decoder, peer: peer, slot: slot)
        case .meshEncryptedMetadata, .meshCoordinatorBeacon, .meshRotationSync, .meshKeyRotation, .meshKeyAck:
            dispatchGroupKeyPayload(payloadType, plaintext: plaintext, decoder: decoder, peer: peer, slot: slot)
        case .meshMemberDeparture, .meshMemberRemoval, .meshTerminated, .meshInventoryDigest:
            dispatchMembershipEventPayload(payloadType, plaintext: plaintext, decoder: decoder, slot: slot)
        case .sessionGoodbye:
            // Parsed, never emitted (plan §8.3). A goodbye is UNSIGNED, so it can only mean "this
            // link is going away" — `MeshMembershipGoodbyeInterop` is where that rule is stated and
            // where it is proven that no departure record can be derived from one. Membership is
            // untouched: the peer stays on the derived roster and may reconnect.
            if case .disconnected = MeshMembershipGoodbyeInterop.outcome(forGoodbyeFrom: peer?.fingerprint),
               let slot {
                removeSlot(slot)
            }
        default:
            dispatchRegistryPayload(payloadType, envelope: envelope, plaintext: plaintext, peer: peer, slot: slot)
        }
    }

    /// `.meshDescriptor` / `.meshAdmissionRequest` / `.meshAdmissionGrant` — the membership family
    /// of the dispatch switch (R4: one function per case family).
    private func dispatchMembershipPayload(
        _ type: PayloadType,
        plaintext: Data,
        decoder: JSONDecoder,
        peer: ProximityCoordinator.PeerIdentity?,
        slot: PeerSlot?
    ) {
        switch type {
        case .meshDescriptor:
            // A descriptor adopts a whole mesh identity, so it is member business: require a
            // COMMITTED slot. `peer` is the coordinator's connected-OR-PENDING identity, so a
            // merely-pending peer would otherwise reach `handleMeshDescriptor` with a fingerprint.
            // A descriptor dropped in a commit-timing race is re-sent: `onSlotConnected` sends one
            // post-commit and `promoteToMesh` re-broadcasts.
            guard slot?.fingerprint != nil else {
                FernletAuditLog.log("mesh.meshDescriptor.droppedUncommittedSlot")
                return
            }
            if let payload = try? decoder.decode(MeshStateChangePayload.self, from: plaintext) {
                handleMeshDescriptor(payload.descriptor, from: peer?.fingerprint)
            }
        case .meshAdmissionRequest:
            if let payload = try? decoder.decode(MeshAdmissionRequestPayload.self, from: plaintext) {
                handleAdmissionRequest(payload, senderFingerprint: peer?.fingerprint,
                                       senderSigningPublicKey: slot?.verifiedSigningPublicKey)
            }
        case .meshAdmissionGrant:
            if let payload = try? decoder.decode(MeshAdmissionGrantPayload.self, from: plaintext) {
                // `peer?.signingPublicKey`, NOT `slot?.verifiedSigningPublicKey`: a grant answers
                // our join request, which by design arrives BEFORE our slot commits, so the slot's
                // verified key is still nil on the legitimate path. `peer` is set only from a
                // signature-verified intro, so it is envelope-authenticated either way.
                handleAdmissionGrant(payload, slot: slot, senderSigningPublicKey: peer?.signingPublicKey)
            }
        default:
            break
        }
    }

    // MARK: - Membership events (network migration P3 item 3, plan §8.3)

    /// The verified membership ledger for the current mesh (plan §8.1).
    ///
    /// **Receive-side only, deliberately.** Item 3 wires the three membership-event frames as far
    /// as *decode → verify → insert*; nothing here emits, and nothing yet derives the shipping
    /// roster from it — pointing `MeshIntroductionAuthority` at `admitted − departed − removed` is
    /// item 7, and persisting it through ``MeshSessionStore`` is item 6. Until then it is the
    /// authoritative record of what this device has verified, and it is fail-closed by
    /// construction: with no admission records, every departure arrives from a fingerprint the
    /// ledger cannot produce a key for and is refused as ``MeshMembershipRecordRejection/signerNotAdmitted``.
    ///
    /// Memory-only, like every other mesh-session value the manager holds; it owes no wipe row
    /// until item 6 gives it a sealed home.
    @ObservationIgnored private(set) var membershipVerifier: MeshMembershipRecordVerifier?

    /// The last inventory digest each peer told us it holds, keyed by fingerprint (plan §10.5).
    ///
    /// A hint, never an authority: it says only whether a full record exchange is worth its bytes.
    /// Bounded by the roster cap so a peer cannot grow it, and cleared with the session.
    @ObservationIgnored private(set) var peerInventoryDigests: [String: MeshInventoryDigest] = [:]

    /// Prepares the verified ledger for a mesh, keyed to the founder's signing key.
    ///
    /// Idempotent for the same mesh so a re-broadcast descriptor cannot discard verified records;
    /// a DIFFERENT mesh id replaces the ledger outright, because records never cross meshes.
    func prepareMembershipLedger(meshID: UUID, founderSigningPublicKey: Data?) {
        if let existing = membershipVerifier, existing.meshID == meshID { return }
        membershipVerifier = MeshMembershipRecordVerifier(
            meshID: meshID,
            founderSigningPublicKey: founderSigningPublicKey
        )
        peerInventoryDigests.removeAll()
    }

    /// **The emission seam** — the one place to look for who sends which membership event.
    ///
    /// Fire-and-forget: it hands the work to ``sendMembershipEvent(_:)`` on a task, for callers on
    /// a synchronous path. A caller that must know the frame reached the wire *before* it does
    /// something else — above all ``leaveSessionAfterNotifyingPeers()``, which tears the transport
    /// down immediately afterwards — awaits ``sendMembershipEvent(_:)`` directly instead.
    ///
    /// - Parameter event: the signed frame to broadcast to every committed slot.
    func emitMembershipEvent(_ event: PayloadType) {
        Task { @MainActor [weak self] in
            await self?.sendMembershipEvent(event)
        }
    }

    /// Mints, signs and broadcasts one membership event, returning when the sends have been
    /// attempted (plan §8.3).
    ///
    /// Item 5 wires the two events this manager can honestly sign for itself: its own departure and
    /// the termination it signs as a final-pair member. **Removal emission is deliberately not
    /// here** — see ``emitApprovedRemovalRecord(_:)``, which is where the vote completes.
    ///
    /// - Parameter event: `.meshMemberDeparture` or `.meshTerminated`. Anything else is refused and
    ///   named rather than silently dropped.
    func sendMembershipEvent(_ event: PayloadType) async {
        guard let mesh = currentMesh else {
            FernletAuditLog.log("mesh.membershipEvent.emitNoMesh", context: ["type": event.rawValue])
            return
        }
        do {
            switch event {
            case .meshMemberDeparture:
                let record = try SignedDepartureRecord.signed(meshID: mesh.meshID, identity: identity)
                await broadcastMembershipFrame(event, MeshMemberDeparturePayload(record: record))
            case .meshTerminated:
                let record = try SignedTerminationRecord.signed(
                    meshID: mesh.meshID,
                    identity: identity,
                    rosterAtSigning: presentedRotationRoster()
                )
                await broadcastMembershipFrame(event, MeshTerminationPayload(record: record))
            default:
                FernletAuditLog.log(
                    "mesh.membershipEvent.emitUnsupported", context: ["type": event.rawValue]
                )
            }
        } catch {
            // A membership event this device could not SIGN is never sent, and never silent (R7).
            FernletAuditLog.log(
                "mesh.membershipEvent.signFailed",
                context: ["type": event.rawValue, "error": String(describing: error)]
            )
        }
    }

    /// Sends one membership frame, awaiting each write.
    ///
    /// - Parameters:
    ///   - type: The frozen wire token.
    ///   - payload: The frame.
    ///   - recipients: The fingerprints allowed to receive it, or nil for every slot. A named set
    ///     also excludes every UNCOMMITTED slot, which has no fingerprint to be in it — membership
    ///     frames are member business.
    private func broadcastMembershipFrame(
        _ type: PayloadType,
        _ payload: some Encodable,
        to recipients: Set<String>? = nil
    ) async {
        for slot in slots {
            guard let recipients else {
                await sendEnvelope(type, encodable: payload, via: slot)
                continue
            }
            guard let fingerprint = slot.fingerprint, recipients.contains(fingerprint) else { continue }
            await sendEnvelope(type, encodable: payload, via: slot)
        }
        onMembershipEventSentForTesting?(type)
    }

    /// **The removal emission seam** — the counterpart of ``emitMembershipEvent(_:)`` for the one
    /// record this device does not sign *about itself*.
    ///
    /// Separate because the record is already minted: quorum completes in
    /// ``emitApprovedRemovalRecord(_:)``, which signs the evidence it counted, files it through the
    /// verifier and only then hands the finished record here. ``sendMembershipEvent(_:)`` mints
    /// what it sends, and a removal that was re-minted at send time could bind a different voter
    /// list from the one that was filed.
    ///
    /// - Parameter record: The completed, already-signed removal.
    func emitRemovalRecord(_ record: SignedRemovalRecord) {
        Task { @MainActor [weak self] in
            await self?.sendRemovalRecord(record)
        }
    }

    /// Broadcasts a completed removal to every member except the one it removes (plan §8.3).
    ///
    /// - Parameter record: The completed, already-signed removal.
    func sendRemovalRecord(_ record: SignedRemovalRecord) async {
        await broadcastMembershipFrame(
            .meshMemberRemoval,
            MeshMemberRemovalPayload(record: record),
            to: membershipEventRecipients(excluding: record.memberFingerprint)
        )
    }

    /// Who a membership frame about `fingerprint` may reach: item 5's key-distribution exclusion
    /// rule, reused verbatim rather than restated.
    ///
    /// Reusing ``MeshRotationPolicy/recipients(acked:selfFingerprint:derivedRoster:locallyRemoved:)``
    /// is the point: the set that gets the new epoch's key and the set that gets the record saying
    /// why must not be two rules that can drift apart. The subject is unioned into the removed set
    /// here, so exclusion is a property of this function rather than of the order
    /// ``applyApprovedRemoval(_:)`` happens to do things in.
    ///
    /// - Parameter fingerprint: The member the frame is about, always excluded.
    /// - Returns: The fingerprints allowed to receive it. It contains this device, which holds no
    ///   slot of its own, so a caller filtering slots by it simply never matches self.
    func membershipEventRecipients(excluding fingerprint: String) -> Set<String> {
        MeshRotationPolicy.recipients(
            acked: Set(slots.compactMap(\.fingerprint)),
            selfFingerprint: identity.localFingerprint,
            derivedRoster: membershipVerifier?.roster,
            locallyRemoved: removedMemberFingerprints.union([fingerprint])
        )
    }

    /// **Removal record minting lives here**: the moment a removal vote reaches quorum on this
    /// device (`applyApprovedRemoval`). The signed record binds the voters this device counted, and
    /// it goes through the same verify-then-insert door a received one would, so the roster change
    /// — and the rotation that follows it (plan §8.3) — happen by one path whoever tallied.
    ///
    /// ## What still rides on the legacy path, stated plainly
    ///
    /// Item 3b gave the record its frame, so the peers now learn of a completed removal from the
    /// signed record itself (`.meshMemberRemoval`) **as well as** from the live `.meshRemovalSecond`
    /// broadcast and the re-gossiped descriptor. Both paths stay: the legacy pair is what an
    /// already-shipped build understands, and `removedMemberFingerprints` remains the interim
    /// exclusion authority until item 7 makes the derived roster the shipping one. The two agree
    /// by construction — the record's target and the set's entry are the same fingerprint, filed in
    /// the same call.
    ///
    /// The remaining shortfall closes with item 7: this ledger holds no admission records yet, so
    /// the insert below is refused `signerNotAdmitted` — fail-closed and logged. The frame is
    /// broadcast anyway, because it is honestly signed by this device and a peer that DOES hold a
    /// ledger verifies it on its own merged roster; refusing to tell anyone because this device
    /// cannot yet file its own record would be the wrong half to fail closed on.
    private func emitApprovedRemovalRecord(_ proposal: MeshRemovalProposalPayload) {
        guard let mesh = currentMesh else { return }
        do {
            let record = try SignedRemovalRecord.signed(
                meshID: mesh.meshID,
                identity: identity,
                memberFingerprint: proposal.targetFingerprint,
                proposalID: proposal.id,
                voterFingerprints: [proposal.proposerFingerprint, identity.localFingerprint]
            )
            let snapshot = membershipVerifier
            let before = membershipVerifier?.roster
            recordRejection(membershipVerifier?.insert(record), type: .meshMemberRemoval)
            // Durable before acknowledged (plan §3.6): a record this device could not write down is
            // rolled back, and a rolled-back record is not announced to anybody.
            if membershipVerifier?.roster != before,
               !commitVerifiedRecord(rollingBackTo: snapshot, type: .meshMemberRemoval) {
                return
            }
            emitRemovalRecord(record)
        } catch {
            FernletAuditLog.log(
                "mesh.membershipEvent.signFailed",
                context: ["type": "removal-record", "error": String(describing: error)]
            )
        }
    }

    /// Merges another device's ledger into this one and rotates if the roster moved (plan §8.3's
    /// third trigger). P4 owns full partition merge; this is the seam it calls.
    ///
    /// - Returns: One rejection per record the verifier refused — never a silent drop.
    @discardableResult
    func mergeMembershipLedger(_ other: MeshMembershipLedger) -> [MeshMembershipRecordRejection] {
        let snapshot = membershipVerifier
        let before = membershipVerifier?.roster
        let rejections = membershipVerifier?.merge(other) ?? []
        for rejection in rejections {
            FernletAuditLog.log(
                "mesh.membershipEvent.rejected",
                context: ["type": "merge", "reason": rejection.diagnosticDescription]
            )
        }
        awaitingResumeMerge = false
        let moved = membershipVerifier?.roster != before
        // P3 item 6: a merge that moved the roster is only ACTED on once it is durable — the
        // rotation it would trigger distributes a key against a roster this device could not write
        // down otherwise (plan §3.6).
        if moved, !commitVerifiedRecord(rollingBackTo: snapshot, type: .meshMemberDeparture) {
            return rejections
        }
        if moved { requestRotation(cause: .merge) }
        return rejections
    }

    // MARK: - Durable session context (network migration P3 item 5, plan §3.6, §8.1)

    /// **The single save seam.** Writes this device's `MeshSessionContext` through the sealed store,
    /// optionally adding one epoch head first.
    ///
    /// Item 5 wires exactly one caller pair — the rotation, on both the coordinator and the member
    /// side, before the new epoch is distributed or acknowledged. The general "who saves when"
    /// cadence (admission, heartbeat, develop, ceiling) is item 6's, and it extends this function
    /// rather than adding a second writer: two writers over one five-state load is how a refusal
    /// becomes an overwrite.
    ///
    /// ## The save cadence (item 6, plan §3.6)
    ///
    /// Every one of these points calls THIS function, and every one of them treats a `false` as
    /// "the thing did not happen":
    ///
    /// | when | what is not acknowledged if the save fails |
    /// | --- | --- |
    /// | founding a mesh | the mesh is abandoned; the UI is never shown one |
    /// | a verified admission grant | the epoch and key are not adopted; no beacon starts |
    /// | a verified membership record | the record is rolled back out of the ledger |
    /// | a merge | the merged ledger is rolled back and no rotation is requested |
    /// | every rotation (item 5) | the new epoch is not distributed |
    /// | a departure | the signed departure is not sent |
    /// | a termination or the ceiling | `terminated.v1` is not sent |
    ///
    /// - Parameters:
    ///   - head: The epoch head to merge into `epochHeads`, or nil to save the context as it stands.
    ///   - termination: The durable ending mark to write, or nil for a live save. A mark whose
    ///     reason is `.developed` also sets `developedLocally`.
    /// - Returns: `true` when the bytes are on disk. `false` means the caller must **not** proceed:
    ///   the load refused, deferred or found a corrupt file, or the seal itself refused. Every
    ///   false is named in ``lastRotationBlockReason`` and the audit log (plan §3.6).
    @discardableResult
    func persistSessionContext(
        addingEpochHead head: MeshEpochRef?,
        terminating termination: MeshSessionLocalTermination? = nil
    ) -> Bool {
        guard let identity = sessionContextIdentity else {
            recordRotationBlock("There is no mesh to persist a session context for.")
            return false
        }
        let sessionStore = MeshSessionStore(scope: store.meshSessionStorage)
        let existing: MeshSessionContext?
        let token: MeshSessionStore.LoadToken
        switch sessionStore.load() {
        case .loaded(let context, let loadToken):
            existing = context
            token = loadToken
        case .absent(let loadToken):
            existing = nil
            token = loadToken
        case .deferred(let deferral):
            recordRotationBlock("The sealed session context could not be read: \(deferral.reason.rawValue).")
            return false
        case .corrupt(let corruption):
            recordRotationBlock("The sealed session context is unreadable: \(String(describing: corruption.detail)).")
            return false
        case .refused(let refusal):
            recordRotationBlock("The sealed session context refused to open: \(refusal.cause.rawValue).")
            return false
        }
        return writeSessionContext(
            base: existing, identity: identity, head: head,
            terminating: termination, token: token, store: sessionStore
        )
    }

    /// The mesh this device would persist a context for: the live one, or — during a launch
    /// restore, when nothing is joined yet — the one that was just loaded.
    ///
    /// The restored half is what lets the expiry found at launch be WRITTEN (plan §8.2's ceiling
    /// has to survive the relaunch that noticed it), without giving the writer a second door.
    private var sessionContextIdentity: SessionContextIdentity? {
        if let mesh = currentMesh {
            return SessionContextIdentity(
                meshID: mesh.meshID,
                createdAt: mesh.createdAt,
                hardDeadline: mesh.createdAt.addingTimeInterval(MeshSessionCeiling.ceilingSeconds)
            )
        }
        guard let restored = restoredSessionContext else { return nil }
        return SessionContextIdentity(
            meshID: restored.meshID, createdAt: restored.createdAt, hardDeadline: restored.hardDeadline
        )
    }

    /// The three values a context is keyed and bounded by, from whichever source is authoritative.
    private struct SessionContextIdentity {
        let meshID: UUID
        let createdAt: Date
        let hardDeadline: Date
    }

    /// Builds the context to write (reusing the loaded one when its mesh matches) and seals it.
    private func writeSessionContext(
        base: MeshSessionContext?,
        identity meshIdentity: SessionContextIdentity,
        head: MeshEpochRef?,
        terminating termination: MeshSessionLocalTermination?,
        token: MeshSessionStore.LoadToken,
        store sessionStore: MeshSessionStore
    ) -> Bool {
        // A context for ANOTHER mesh is replaced, never merged: records never cross meshes.
        var context = (base?.meshID == meshIdentity.meshID ? base : nil) ?? MeshSessionContext(
            meshID: meshIdentity.meshID,
            protocolVersion: MeshChannelIntroductionFormat.protocolVersion,
            createdAt: meshIdentity.createdAt,
            hardDeadline: meshIdentity.hardDeadline
        )
        if let ledger = membershipVerifier?.ledger { context.ledger = ledger }
        if let head {
            context.epochHeads = MeshEpochAcceptance.mergedHeads(context.epochHeads, adding: head)
        }
        if let termination {
            context.localTermination = termination
            if termination.reason == .developed { context.developedLocally = true }
        }
        do {
            try sessionStore.save(context, token: token)
            return true
        } catch {
            recordRotationBlock("The session context could not be sealed: \(String(describing: error)).")
            return false
        }
    }

    // MARK: - Session state machine (network migration P3 item 6, plan §8.2)

    /// Where this device is in plan §8.2's lifecycle. Memory-only — the DURABLE half is the sealed
    /// context, and a relaunch re-derives this from it (``restoreSessionContextAtLaunch(now:)``).
    @ObservationIgnored private(set) var sessionState: MeshSessionState = .idle

    /// The dual-bound ceiling for this run, armed when a session starts or is restored.
    @ObservationIgnored private(set) var sessionCeiling: MeshSessionCeiling?

    /// The monotonic origin the ceiling's second bound measures from. `ContinuousClock` keeps
    /// counting across a wall-clock change and across device sleep, which is exactly the property
    /// that stops a clock set backwards from lengthening a session.
    @ObservationIgnored private var sessionMonotonicOrigin: ContinuousClock.Instant?

    /// The ending mark staged by ``MeshSessionEffect/markTerminated`` for the save that follows it.
    @ObservationIgnored private var stagedTermination: MeshSessionLocalTermination?

    /// The effect that failed, if the last transition abandoned its list. Non-nil is the signal a
    /// caller checks before acknowledging anything (plan §3.6).
    @ObservationIgnored private(set) var lastSessionEffectFailure: MeshSessionEffect?

    /// The last refused (state, event) pair, named. A refusal is never silent.
    @ObservationIgnored private(set) var lastSessionTransitionRejection: MeshSessionTransitionRejection?

    /// True between a resume/partition-heal and the merge that completes it — the flag that says
    /// this session is being MERGED back, not started fresh (plan §10.3).
    @ObservationIgnored private(set) var awaitingResumeMerge = false

    /// Whether the foreground may offer a resume for a restored or idle-stopped session.
    @ObservationIgnored private(set) var offersForegroundResume = false

    /// When the idle window lapses, or nil when it is not armed. A value, not a timer: it is
    /// evaluated on demand (``evaluateIdleLapse(now:)``) so nothing spins.
    @ObservationIgnored private(set) var idleLapseDeadline: Date?

    /// The mesh this device may never rejoin, and why (plan §8.2's permanent bar). Re-derived from
    /// the sealed context at every launch, so a restart cannot resurrect an ended session.
    @ObservationIgnored private(set) var rejoinBar: MeshSessionRejoinBar?

    /// The context a launch restore opened, kept only until a session is joined or the restore is
    /// discarded. It is what lets an expiry found at launch be written back.
    @ObservationIgnored private(set) var restoredSessionContext: MeshSessionContext?

    /// How many times the launch restore has been attempted, bounded by
    /// ``MeshSessionRestoreBounds/maxAttempts``.
    @ObservationIgnored private(set) var sessionRestoreAttempts = 0

    /// What the last restore attempt concluded.
    @ObservationIgnored private(set) var lastSessionRestoreOutcome: MeshSessionRestoreOutcome?

    /// Plan §8.2's 30-minute idle window: no authenticated external heartbeat for this long ends
    /// local *participation*, never membership.
    static let idleWindowSeconds: TimeInterval = 30 * 60

    /// Offers one event to the pure machine and performs whatever it returns.
    ///
    /// Effects run in the order the machine gave them and stop at the first failure, which is how
    /// durable-before-acknowledged is enforced mechanically rather than remembered at each call
    /// site: ``MeshSessionEffect/persistContext`` precedes every effect that tells anybody
    /// anything, so a refused seal leaves the rest of the list undone and
    /// ``lastSessionEffectFailure`` set.
    ///
    /// - Parameter event: What happened.
    /// - Returns: The transition taken, or the named refusal.
    @discardableResult
    func applySessionEvent(_ event: MeshSessionEvent) -> MeshSessionTransition {
        let transition = MeshSessionStateMachine.transition(from: sessionState, on: event)
        switch transition {
        case .rejected(let rejection):
            lastSessionTransitionRejection = rejection
            FernletAuditLog.log(
                "mesh.sessionState.rejected",
                context: ["state": sessionState.rawValue, "reason": rejection.rawValue]
            )
        case .moved(let next, let effects):
            lastSessionTransitionRejection = nil
            lastSessionEffectFailure = nil
            sessionState = next
            performSessionEffects(effects, for: event)
        }
        return transition
    }

    /// Performs an effect list in order, abandoning the remainder at the first failure.
    private func performSessionEffects(_ effects: [MeshSessionEffect], for event: MeshSessionEvent) {
        // R2: bounded by a constant, not by whatever the machine returned.
        for effect in effects.prefix(MeshSessionStateMachine.maxEffectsPerTransition) {
            guard performSessionEffect(effect, for: event) else {
                lastSessionEffectFailure = effect
                FernletAuditLog.log(
                    "mesh.sessionState.effectAbandoned",
                    context: ["effect": effect.rawValue, "state": sessionState.rawValue]
                )
                return
            }
        }
    }

    /// Performs one effect.
    ///
    /// - Returns: `false` only for a save that did not reach the disk — the one failure that must
    ///   stop the rest of the list.
    private func performSessionEffect(_ effect: MeshSessionEffect, for event: MeshSessionEvent) -> Bool {
        switch effect {
        case .markDeveloped, .markTerminated:
            stageEnding(from: event)
        case .persistContext:
            guard persistSessionContext(addingEpochHead: nil, terminating: stagedTermination) else {
                return false
            }
            stagedTermination = nil
        case .beginMerge:
            awaitingResumeMerge = true
        case .startParticipation:
            startSearching()
        case .stopParticipation:
            stopSearching()
        case .armIdleTimer:
            idleLapseDeadline = Date().addingTimeInterval(Self.idleWindowSeconds)
        case .clearIdleTimer:
            idleLapseDeadline = nil
        case .offerForegroundResume:
            offersForegroundResume = true
        }
        return true
    }

    /// Stages the durable ending mark for the save that follows it, and raises the in-memory rejoin
    /// bar in the same breath — the mark and the bar are one fact, recorded together.
    ///
    /// The bar goes up **before** the save succeeds, deliberately: if the seal fails, this device
    /// has still decided the session is over, and staying out of a mesh it meant to leave is the
    /// fail-closed side of that mistake.
    private func stageEnding(from event: MeshSessionEvent) {
        guard let reason = event.terminationReason else { return }
        stagedTermination = MeshSessionLocalTermination(reason: reason, at: Date())
        barRejoin(reason: reason)
    }

    /// Records the permanent rejoin bar for the mesh this device just left or ended.
    private func barRejoin(reason: MeshSessionTerminationReason) {
        guard let meshID = currentMesh?.meshID ?? restoredSessionContext?.meshID else { return }
        rejoinBar = MeshSessionRejoinBar(meshID: meshID, reason: reason)
        FernletAuditLog.log(
            "mesh.sessionState.rejoinBarred",
            context: ["reason": reason.rawValue]
        )
    }

    /// Why this device may never rejoin `meshID`, or nil if it may.
    ///
    /// Checked before adopting a descriptor and before accepting an admission grant: plan §8.2's
    /// "a developed or terminated mesh can never be rejoined", enforced at both doors.
    ///
    /// - Parameter meshID: The mesh being offered.
    /// - Returns: The recorded reason, or nil.
    func rejoinRefusal(for meshID: UUID) -> MeshSessionTerminationReason? {
        guard let bar = rejoinBar, bar.meshID == meshID else { return nil }
        return bar.reason
    }

    // MARK: The save cadence (plan §3.6)

    /// **The join-ack gate.** The sealed context must reach the disk before this device behaves as
    /// though it has joined — before it adopts an epoch, unwraps a group key, starts a beacon or
    /// lets the UI say "joined".
    ///
    /// - Returns: `true` when the context is durable, or when there is nothing to write yet (a
    ///   grant that arrived before the mesh descriptor: the descriptor's own adoption writes it).
    @discardableResult
    func recordVerifiedAdmissionDurably() -> Bool {
        guard currentMesh != nil else { return true }
        guard sessionState != .idle else { return joinDurably() }
        guard persistSessionContext(addingEpochHead: nil) else {
            FernletAuditLog.log("mesh.admissionGrant.droppedNotDurable")
            return false
        }
        return true
    }

    /// The first admission on a device with no session yet: `idle → joining`, which saves. A save
    /// that fails puts the machine back where it was — a half-joined state is not a state.
    private func joinDurably() -> Bool {
        applySessionEvent(.joined)
        guard lastSessionEffectFailure == nil else {
            sessionState = .idle
            FernletAuditLog.log("mesh.admissionGrant.droppedNotDurable")
            return false
        }
        return true
    }

    /// Keeps a just-verified record only if the context that now contains it reached the disk.
    ///
    /// The rollback is the point: plan §3.6 says a record is not "inserted for roster purposes"
    /// until it is durable, and the verifier is a value, so restoring the snapshot is exactly the
    /// ledger as it was. Without it, a force-quit between a verified insert and a refused seal
    /// would leave two devices deriving different rosters from the "same" records.
    ///
    /// - Parameters:
    ///   - snapshot: The verifier as it was before the insert.
    ///   - type: The frame the record arrived in, for the audit line.
    /// - Returns: `true` when the record is durable and may be acted on.
    private func commitVerifiedRecord(
        rollingBackTo snapshot: MeshMembershipRecordVerifier?,
        type: PayloadType
    ) -> Bool {
        guard persistSessionContext(addingEpochHead: nil) else {
            membershipVerifier = snapshot
            FernletAuditLog.log("mesh.membershipEvent.notDurable", context: ["type": type.rawValue])
            return false
        }
        return true
    }

    // MARK: Ceiling (both bounds)

    /// Arms the dual-bound ceiling for this run.
    ///
    /// - Parameters:
    ///   - hardDeadline: The signed absolute deadline from the descriptor or restored context.
    ///   - startedAt: The wall-clock instant this run began; read once, here.
    func startSessionCeiling(hardDeadline: Date, startedAt: Date) {
        sessionCeiling = MeshSessionCeiling(hardDeadline: hardDeadline, startedAt: startedAt)
        sessionMonotonicOrigin = ContinuousClock.now
    }

    /// Judges the session against both ceiling bounds without changing anything.
    ///
    /// - Parameters:
    ///   - now: The wall-clock instant, for the signed bound.
    ///   - monotonicElapsed: Seconds of local runtime since the ceiling was armed. Nil measures it
    ///     from the held `ContinuousClock` origin; tests pass a value instead of waiting.
    /// - Returns: The verdict, or nil when no ceiling is armed.
    func sessionCeilingVerdict(now: Date, monotonicElapsed: TimeInterval?) -> MeshSessionCeilingVerdict? {
        guard let ceiling = sessionCeiling else { return nil }
        let elapsed = monotonicElapsed ?? measuredMonotonicElapsed()
        return ceiling.verdict(now: now, monotonicElapsed: elapsed)
    }

    /// Seconds since the ceiling was armed, from the monotonic clock. Zero when nothing is armed.
    private func measuredMonotonicElapsed() -> TimeInterval {
        guard let origin = sessionMonotonicOrigin else { return 0 }
        let elapsed = origin.duration(to: ContinuousClock.now)
        return TimeInterval(elapsed.components.seconds)
    }

    /// Enforces the ceiling: at either bound the session is marked terminated, the mark is
    /// persisted, `terminated.v1` is sent, and local participation ends (plan §8.2).
    ///
    /// The emit is **awaited** rather than fired through ``emitMembershipEvent(_:)``'s task,
    /// exactly as ``terminateForExhaustedEpochs()`` does and for the same reason: the teardown that
    /// follows stops the radio the frame needs. A refused save abandons the emit — an expiry
    /// nobody could write down is not announced (plan §3.6).
    ///
    /// - Parameters:
    ///   - now: The wall-clock instant to judge against.
    ///   - monotonicElapsed: Local runtime seconds, or nil to measure.
    /// - Returns: The verdict, or nil when no ceiling is armed.
    @discardableResult
    func enforceSessionCeiling(now: Date, monotonicElapsed: TimeInterval?) async -> MeshSessionCeilingVerdict? {
        guard let verdict = sessionCeilingVerdict(now: now, monotonicElapsed: monotonicElapsed) else {
            return nil
        }
        guard case .reached(let bound) = verdict else { return verdict }
        let transition = applySessionEvent(.hardDeadlineReached(bound))
        guard transition.nextState == .expired, lastSessionEffectFailure == nil else { return verdict }
        await sendMembershipEvent(.meshTerminated)
        leaveSession()
        return verdict
    }

    /// Plan §8.2's idle window, evaluated on demand.
    ///
    /// - Parameter now: The instant to measure against.
    /// - Returns: `true` when the window had lapsed and the lapse was applied.
    @discardableResult
    func evaluateIdleLapse(now: Date) -> Bool {
        guard let deadline = idleLapseDeadline, now >= deadline else { return false }
        return applySessionEvent(.idleLapsed).nextState == .localIdleStop
    }

    // MARK: Launch restore (the durable half)

    /// Loads the sealed context at launch and maps all five load states onto what a launch may do.
    ///
    /// Nothing here reconnects: invariant 5 says a relaunch never auto-reconnects, so even a
    /// perfectly live context lands in ``MeshSessionState/localIdleStop`` with a resume on offer.
    /// The three states that carry no `LoadToken` start no session and run no writer — a deferral
    /// and a refusal are retried (bounded, and logged apart), and a corrupt file is quarantined
    /// rather than overwritten.
    ///
    /// - Parameter now: The instant the ceiling is judged against.
    /// - Returns: The outcome, also kept in ``lastSessionRestoreOutcome``.
    @discardableResult
    func restoreSessionContextAtLaunch(now: Date) -> MeshSessionRestoreOutcome {
        sessionRestoreAttempts += 1
        let sessionStore = MeshSessionStore(scope: store.meshSessionStorage)
        let outcome = MeshSessionRestore.outcome(
            for: sessionStore.load(), selfFingerprint: identity.localFingerprint, now: now
        )
        lastSessionRestoreOutcome = outcome
        FernletAuditLog.log("mesh.sessionRestore.outcome", context: ["outcome": outcome.logToken])
        if case .quarantineCorruptFile(let corruption) = outcome {
            quarantineRestoredContext(corruption, store: sessionStore)
        }
        restoredSessionContext = outcome.context
        if let context = outcome.context {
            startSessionCeiling(hardDeadline: context.hardDeadline, startedAt: now)
        }
        // An ending the FILE already records bars the rejoin straight away: the transition below
        // carries no new reason for it (nothing was discovered, it was read), so the bar is set
        // here rather than left to `barRejoin(reason:)`.
        if case .terminated(let context, let reason) = outcome {
            rejoinBar = MeshSessionRejoinBar(meshID: context.meshID, reason: reason)
        }
        applySessionEvent(.contextRestored(outcome.disposition))
        return outcome
    }

    /// Sets a corrupt file aside. The quarantine is the ONLY route from `corrupt` to a writer, and
    /// this device does not take it any further — no session starts on a file it could not read.
    private func quarantineRestoredContext(_ corruption: MeshSessionCorruption, store sessionStore: MeshSessionStore) {
        do {
            _ = try sessionStore.quarantineCorruptFile(corruption)
        } catch {
            FernletAuditLog.log(
                "mesh.sessionRestore.quarantineFailed",
                context: ["error": String(describing: error)]
            )
        }
    }

    /// Re-attempts a restore that deferred or was refused, up to
    /// ``MeshSessionRestoreBounds/maxAttempts`` in total.
    ///
    /// Called on unlock or foreground, never on a timer: a deferral means "ask again when custody
    /// changes", and a bounded count of asks is the difference between that and a busy loop.
    ///
    /// - Parameter now: The instant the ceiling is judged against.
    /// - Returns: The new outcome, or nil when nothing was pending or the attempts are spent.
    @discardableResult
    func retrySessionRestoreIfPending(now: Date) -> MeshSessionRestoreOutcome? {
        guard let last = lastSessionRestoreOutcome, last.isRetryable else { return nil }
        guard sessionRestoreAttempts < MeshSessionRestoreBounds.maxAttempts else {
            FernletAuditLog.log("mesh.sessionRestore.attemptsExhausted")
            return nil
        }
        return restoreSessionContextAtLaunch(now: now)
    }

    /// Resumes a lapsed or partitioned session **through the merge path** (plan §8.2, §10.3).
    ///
    /// Idle-lapse resume and partition heal are deliberately one mechanism: the ledgers are merged
    /// through ``mergeMembershipLedger(_:)``, and the peer's epoch head is merged into
    /// `epochHeads`, where a same-counter divergent epoch **coexists** with this device's own
    /// (plan §8.4) until a merge mints a strictly greater successor. Nothing here starts a fresh
    /// session, and nothing re-keys silently — the rotation, if any, comes from the roster having
    /// moved, with cause `.merge`.
    ///
    /// - Parameters:
    ///   - other: The ledger the returning peer presented.
    ///   - head: The epoch head that peer presented, if any.
    /// - Returns: One rejection per record the verifier refused — never a silent drop.
    @discardableResult
    func resumeSessionAfterLapse(
        mergingLedger other: MeshMembershipLedger,
        peerEpochHead head: MeshEpochRef?
    ) -> [MeshMembershipRecordRejection] {
        let transition = applySessionEvent(.resumedAfterLapse)
        if transition.nextState == nil {
            applySessionEvent(.linksRestored)
        }
        let rejections = mergeMembershipLedger(other)
        if let head {
            persistSessionContext(addingEpochHead: head)
        }
        return rejections
    }

    /// `.meshMemberDeparture` / `.meshMemberRemoval` / `.meshTerminated` / `.meshInventoryDigest` —
    /// the membership-event family of the dispatch switch (R4: one function per case family).
    ///
    /// Member business, so a COMMITTED slot is required: the same boundary the removal, photo and
    /// registry families enforce. Records are then handed to ``MeshMembershipRecordVerifier``,
    /// which is what stops a peer inserting junk with a low timestamp and crowding a real record
    /// out of a sixteen-slot set.
    private func dispatchMembershipEventPayload(
        _ type: PayloadType,
        plaintext: Data,
        decoder: JSONDecoder,
        slot: PeerSlot?
    ) {
        guard slot?.fingerprint != nil else {
            FernletAuditLog.log("mesh.membershipEvent.droppedUncommittedSlot", context: ["type": type.rawValue])
            return
        }
        guard membershipVerifier != nil else {
            FernletAuditLog.log("mesh.membershipEvent.droppedNoLedger", context: ["type": type.rawValue])
            return
        }
        let snapshot = membershipVerifier
        let rosterBefore = membershipVerifier?.roster
        let removed = insertMembershipRecord(type, plaintext: plaintext, decoder: decoder)
        // P3 item 6, plan §3.6: a record that moved the roster is durable before it counts. The
        // rollback inside `commitVerifiedRecord` is what keeps "verified" and "remembered" the
        // same set after a refused seal.
        guard membershipVerifier?.roster != rosterBefore else { return }
        guard commitVerifiedRecord(rollingBackTo: snapshot, type: type) else { return }
        if removed == identity.localFingerprint {
            applyVerifiedSelfRemoval()
            return
        }
        rotateIfRosterChanged(from: rosterBefore)
    }

    /// Decodes one membership frame and offers its record to the verifier.
    ///
    /// - Returns: The fingerprint an ACCEPTED removal record names, and nil for every other
    ///   outcome — another kind of record, a frame that did not decode, or a record the verifier
    ///   refused. A refused removal must not be able to end anybody's session, which is why the
    ///   fingerprint is returned only when `insert` answered nil.
    private func insertMembershipRecord(
        _ type: PayloadType,
        plaintext: Data,
        decoder: JSONDecoder
    ) -> String? {
        switch type {
        case .meshMemberDeparture:
            if let payload = try? decoder.decode(MeshMemberDeparturePayload.self, from: plaintext) {
                recordRejection(membershipVerifier?.insert(payload.record), type: type)
            }
        case .meshMemberRemoval:
            guard let payload = try? decoder.decode(MeshMemberRemovalPayload.self, from: plaintext) else {
                return nil
            }
            let rejection = membershipVerifier?.insert(payload.record)
            recordRejection(rejection, type: type)
            return rejection == nil ? payload.record.memberFingerprint : nil
        case .meshTerminated:
            if let payload = try? decoder.decode(MeshTerminationPayload.self, from: plaintext) {
                recordRejection(membershipVerifier?.insert(payload.record), type: type)
            }
        case .meshInventoryDigest:
            if let payload = try? decoder.decode(MeshInventoryDigestPayload.self, from: plaintext) {
                receiveInventoryDigest(payload)
            }
        default:
            break
        }
        return nil
    }

    /// A verified removal record named **this device** (plan §8.2's `removed` edge, §8.3).
    ///
    /// Item 6 built the edge and deliberately left it unapplied: deciding that a *received* record
    /// names this device needed the derived shipping roster item 7 owes. A removal needs no roster
    /// to answer that — the record names the removed fingerprint outright and this device knows its
    /// own — so the edge is wired here and `.terminationVerified` stays item 7's.
    ///
    /// The order is plan §3.6's. The record is already durable when this runs (the caller commits
    /// first), then `.removed` writes the ending mark and raises the permanent rejoin bar, and only
    /// then does the local teardown run — the same ``leaveSession()`` the legacy
    /// `.meshRemovalSecond` path takes when the vote names this device, so both paths end in one
    /// state. No rotation is requested: a device that is no longer a member has no key to hand out.
    private func applyVerifiedSelfRemoval() {
        FernletAuditLog.log("mesh.membershipEvent.selfRemoved")
        applySessionEvent(.removed)
        leaveSession()
    }

    /// Plan §8.3's roster-change trigger: a verified record that MOVED the derived roster rotates
    /// the group key. A refused record, or one that changes nothing a roster can see (a duplicate
    /// re-gossip, an inventory digest), triggers nothing — which is what keeps a peer from spending
    /// this device's rotations by replaying records it already holds.
    private func rotateIfRosterChanged(from before: MeshDerivedRoster?) {
        guard membershipVerifier?.roster != before else { return }
        requestRotation(cause: .membership)
    }

    /// Verifies a peer's digest and remembers it, so a later item can ask for the records this
    /// device is missing (plan §10.5). A digest that DIFFERS is not an error — that is the signal.
    private func receiveInventoryDigest(_ payload: MeshInventoryDigestPayload) {
        guard let verifier = membershipVerifier else { return }
        if let rejection = verifier.verify(payload) {
            FernletAuditLog.log(
                "mesh.membershipEvent.rejected",
                context: ["type": PayloadType.meshInventoryDigest.rawValue,
                          "reason": rejection.diagnosticDescription]
            )
            return
        }
        guard peerInventoryDigests[payload.senderFingerprint] != nil
                || peerInventoryDigests.count < MeshMembershipBounds.maxRosterMembers else {
            return   // R3: a bounded map, so a churning peer set cannot grow it without limit
        }
        peerInventoryDigests[payload.senderFingerprint] = payload.digest
    }

    /// Logs a refused record. Frozen English diagnostics, never user copy.
    private func recordRejection(_ rejection: MeshMembershipRecordRejection?, type: PayloadType) {
        guard let rejection else { return }
        FernletAuditLog.log(
            "mesh.membershipEvent.rejected",
            context: ["type": type.rawValue, "reason": rejection.diagnosticDescription]
        )
    }

    /// The friend-photo family: one shared photo, a manifest, or a request for missing ids
    /// (R4: one function per case family).
    private func dispatchPhotoPayload(
        _ type: PayloadType,
        plaintext: Data,
        decoder: JSONDecoder,
        peer: ProximityCoordinator.PeerIdentity?,
        slot: PeerSlot?
    ) {
        // Photos are the PERSISTENT wall, so the whole family is member business: require a
        // COMMITTED slot, the same boundary `dispatchRemovalPayload` and `dispatchRegistryPayload`
        // enforce. `peer` is the coordinator's connected-OR-PENDING identity, so without this a
        // peer that has only introduced itself — no commit, no user action — can write the wall.
        // Drop only, never fail the session: a peer must not be able to get itself disconnected
        // by mistiming a photo.
        guard slot?.fingerprint != nil else {
            FernletAuditLog.log("mesh.photoPayload.droppedUncommittedSlot", context: ["type": type.rawValue])
            return
        }
        switch type {
        case .friendPhoto:
            if let payload = try? decoder.decode(FriendPhotoPayload.self, from: plaintext) {
                handleFriendPhotoEnvelope(payload, from: peer?.fingerprint)
            }
        case .friendPhotoManifest:
            if let payload = try? decoder.decode(FriendPhotoManifestPayload.self, from: plaintext),
               let slot {
                handlePhotoManifest(payload, from: slot)
            }
        case .friendPhotoRequest:
            if let payload = try? decoder.decode(FriendPhotoRequestPayload.self, from: plaintext),
               let slot {
                sendRequestedPhotos(payload.missingPhotoIDs, to: slot)
            }
        default:
            break
        }
    }

    /// Authorizes a photo's CLAIMED author before it reaches the persistent wall.
    ///
    /// The envelope signature authenticates only the RELAYER — `sendRequestedPhotos` re-sends other
    /// peers' cached photos by design, so `senderName`/`senderFingerprint`/`senderSigningPublicKey`
    /// are an unsigned claim about a third party. Four independent checks make the claim usable:
    /// neither party blocked, the claim present at all, the claim self-consistent (fingerprint ==
    /// hash of the claimed key), and the claimed author known to THIS session (the relayer itself,
    /// a mesh member, a session-roster participant, or an author announced in a manifest we already
    /// accepted). An un-attributable photo is rejected outright: it can be neither blocked nor
    /// honestly displayed. Do NOT "fix" this by stamping the relayer over the attribution fields —
    /// that mis-attributes every legitimately relayed photo on the wall.
    private func photoAuthorIsAcceptable(_ payload: FriendPhotoPayload, relayer: String?) -> Bool {
        guard let relayer, !store.isBlockedFingerprint(relayer) else {
            FernletAuditLog.log("mesh.friendPhoto.droppedUnattributedRelayer")
            return false
        }
        guard let claimed = payload.senderFingerprint, let claimedKey = payload.senderSigningPublicKey else {
            FernletAuditLog.log("mesh.friendPhoto.droppedMissingAuthor")
            return false
        }
        guard !store.isBlockedFingerprint(claimed) else {
            FernletAuditLog.log("mesh.friendPhoto.droppedBlockedAuthor")
            return false
        }
        // The same binding `handleAdmissionRequest` applies — reuse it, don't reinvent it.
        guard IdentityService.fingerprintsMatch(IdentityService.fingerprint(of: claimedKey), claimed) else {
            FernletAuditLog.log("mesh.friendPhoto.droppedKeyFingerprintMismatch")
            return false
        }
        let known = claimed == relayer
            || currentMesh?.members.contains { $0.fingerprint == claimed } == true
            || sessionRoster.contains { $0.fingerprint == claimed }
            || manifestAnnouncedPhotoAuthors.contains(claimed)
        guard known else {
            FernletAuditLog.log("mesh.friendPhoto.droppedUnknownAuthor")
            return false
        }
        return true
    }

    /// Receives one peer photo: author authorization, per-sender quota, epoch decrypt, cache,
    /// closeness hook.
    ///
    /// The payload's peer-supplied display fields are sanitized and capped here (R3/R5) — this is
    /// where untrusted photo metadata enters the PERSISTENT wall cache.
    private func handleFriendPhotoEnvelope(_ payload: FriendPhotoPayload, from senderFingerprint: String?) {
        guard photoAuthorIsAcceptable(payload, relayer: senderFingerprint) else { return }
        guard allowIncomingPhoto(payload.id, from: senderFingerprint) else { return }
        // The payload must carry an image in the shape its epoch claims (R5) — an empty or
        // mismatched payload would otherwise occupy a wall slot and a per-sender quota unit.
        if payload.keyEpoch > 0 {
            guard payload.encryptedImageData != nil, payload.nonce != nil else { return }
        } else {
            guard payload.imageData != nil else { return }
        }
        let photo = Self.sanitizedIncomingPhoto(payload)
        let inSession = isPhotoFromCurrentSession(photo)
        if photo.keyEpoch > 0 {
            // Encrypted photo: decrypt before caching.
            guard let key = currentGroupKey, key.epoch == photo.keyEpoch,
                  let ciphertext = photo.encryptedImageData, let nonce = photo.nonce,
                  let decrypted = Self.decryptedIncomingPhoto(ciphertext, nonce: nonce, key: key) else { return }
            cachePhoto(photo.withDecryptedImageData(decrypted), includeInSession: inSession)
        } else {
            cachePhoto(photo, includeInSession: inSession)   // epoch 0: unencrypted, accept as-is
        }
        // A photo shared with this friend in the current session feeds the closeness photo signal
        // (day-capped downstream, so multiple photos from one friend count once).
        if inSession, let fingerprint = senderFingerprint { onFriendPhotoSession?(fingerprint) }
    }

    /// Opens one inbound photo, naming the single failure that is NOT "wrong key, stale epoch or
    /// tampered bytes": a payload carrying no `FMGP2` marker, i.e. the retired pre-marker format
    /// whose reader Phase 4 deleted. Every drop on this path is invisible to the user, so the audit
    /// line is the only place the reason exists, and "these bytes never reached the AEAD" has to be
    /// separable from "the AEAD rejected them" for anyone diagnosing a friend who cannot share.
    private static func decryptedIncomingPhoto(_ ciphertext: Data, nonce: Data, key: MeshGroupKey) -> Data? {
        do {
            return try decryptPhoto(ciphertext, nonce: nonce, key: key)
        } catch MeshEncryptionError.legacyWireFormat {
            FernletAuditLog.log("mesh.friendPhoto.droppedLegacyWireFormat")
            return nil
        } catch {
            return nil
        }
    }

    /// The two-party removal vote, gated at the wire boundary (R5).
    ///
    /// Removal votes are member business, so both types require a COMMITTED slot; a proposal is
    /// accepted only DIRECT from its own proposer, and a second only for a proposal we already
    /// hold — otherwise one peer could fabricate both halves of the vote and have any member
    /// (including this device) disconnected.
    private func dispatchRemovalPayload(
        _ type: PayloadType,
        plaintext: Data,
        decoder: JSONDecoder,
        peer: ProximityCoordinator.PeerIdentity?,
        slot: PeerSlot?
    ) {
        guard slot?.fingerprint != nil, let senderFingerprint = peer?.fingerprint else {
            FernletAuditLog.log("mesh.removalVote.droppedUncommittedSlot", context: ["type": type.rawValue])
            return
        }
        switch type {
        case .meshRemovalProposal:
            guard let payload = try? decoder.decode(MeshRemovalProposalPayload.self, from: plaintext) else { return }
            guard payload.proposerFingerprint == senderFingerprint else {
                FernletAuditLog.log("mesh.removalProposal.droppedForeignProposer")
                return
            }
            handleRemovalProposal(payload, rebroadcast: false)
        case .meshRemovalSecond:
            guard let payload = try? decoder.decode(MeshRemovalSecondPayload.self, from: plaintext) else { return }
            guard pendingRemovalProposals.contains(where: {
                $0.id == payload.proposal.id
                    && $0.proposerFingerprint == payload.proposal.proposerFingerprint
            }) else {
                FernletAuditLog.log("mesh.removalSecond.unknownProposal")
                return
            }
            handleRemovalSecond(payload, senderFingerprint: senderFingerprint, rebroadcast: false)
        default:
            break
        }
    }

    /// The group-crypto family: sealed metadata, coordinator beacons, and the rotation/ack
    /// three-step (R4: one function per case family). Every handler is bound to the AUTHENTICATED
    /// sender fingerprint rather than to the fingerprint the payload claims (R5).
    private func dispatchGroupKeyPayload(
        _ type: PayloadType,
        plaintext: Data,
        decoder: JSONDecoder,
        peer: ProximityCoordinator.PeerIdentity?,
        slot: PeerSlot?
    ) {
        let senderFingerprint = peer?.fingerprint
        switch type {
        case .meshEncryptedMetadata:
            if let wrapper = try? decoder.decode(MeshEncryptedMetadataPayload.self, from: plaintext),
               let slot {
                Task { [weak self] in await self?.handleEncryptedMetadata(wrapper, from: peer, slot: slot) }
            }
        case .meshCoordinatorBeacon:
            if let beacon = try? decoder.decode(MeshCoordinatorBeaconPayload.self, from: plaintext) {
                handleCoordinatorBeacon(beacon, senderFingerprint: senderFingerprint)
            }
        case .meshRotationSync:
            if let sync = try? decoder.decode(MeshRotationSyncPayload.self, from: plaintext) {
                scheduleRotationSyncAck(sync, senderFingerprint: senderFingerprint)
            }
        case .meshKeyRotation:
            if let rotation = try? decoder.decode(MeshKeyRotationPayload.self, from: plaintext) {
                Task { [weak self] in await self?.handleKeyRotation(rotation, senderFingerprint: senderFingerprint) }
            }
        case .meshKeyAck:
            if let ack = try? decoder.decode(MeshKeyAckPayload.self, from: plaintext) {
                handleKeyAck(ack, senderFingerprint: senderFingerprint)
            }
        default:
            break
        }
    }

    /// Known type outside the core mesh set: give a registered feature module a chance
    /// (Phase 1 registry); otherwise keep the pre-registry silent drop.
    ///
    /// COMMITTED SLOTS ONLY (Phase 3a hardening; a Phase-1 review fact makes this the security
    /// boundary): the coordinator dispatches known non-core payloads with
    /// `connectedIdentity ?? pendingPeerIdentity` and no state gate, so a pre-dwell (uncommitted)
    /// peer — or a coordinator that never became a slot — could otherwise reach feature handlers
    /// with a merely-pending identity. Feature payloads are for session members, not candidates.
    private func dispatchRegistryPayload(
        _ type: PayloadType,
        envelope: FernletIdentityEnvelope,
        plaintext: Data,
        peer: ProximityCoordinator.PeerIdentity?,
        slot: PeerSlot?
    ) {
        guard slot?.fingerprint != nil else {
            FernletAuditLog.log(
                "mesh.registryPayload.droppedUncommittedSlot",
                context: ["type": type.rawValue]
            )
            return
        }
        registeredPayloadHandlers[type]?(envelope, plaintext, peer)
    }

    // MARK: - Friend-of-friend labels

    /// Returns a label like "Friend of Aisha" if any cached voucher lists this fingerprint as trusted.
    public func vouchLabel(for fingerprint: String) -> String? {
        let now = Date()
        return vouchCache.values
            .first { $0.expiresAt > now && $0.trustedFingerprints.contains(fingerprint) }
            .map { "Friend of \($0.voucherDisplayName)" }
    }

    public func block(_ participant: MeshSessionParticipant) {
        let signingPublicKey = currentMesh?.members
            .first { $0.fingerprint == participant.fingerprint }?
            .signingPublicKey
            ?? slots.first { $0.fingerprint == participant.fingerprint }?
            .verifiedSigningPublicKey
        guard let signingPublicKey else { return }
        store.blockProximityPeer(signingPublicKey: signingPublicKey)
    }

    /// Phase 2 gate (Docs/Proximity-Mesh-Redesign-2026-07-10.md, "Phase 2 — Friend minting"):
    /// the vouch-list broadcast disclosed every unblocked trusted fingerprint to all session
    /// peers, and was dormant only because the trust vault had no production writers. Friend
    /// minting (Phase 2) is exactly what would have switched it on, so it is gated OFF here.
    /// Re-enable only with an explicit consent design for sharing the friend graph.
    @ObservationIgnored var isVouchListBroadcastEnabled = false

    /// The payload `sendVouchList` would broadcast, or nil while the broadcast is disabled.
    /// Internal seam so tests can pin both the gate (default off ⇒ nil) and the machinery
    /// (forced on ⇒ correct fingerprint filtering) without a live transport.
    func vouchListPayloadForBroadcast() -> MeshFriendVouchListPayload? {
        guard isVouchListBroadcastEnabled else { return nil }
        let trusted = store.trustedProximityPeers
            .filter { $0.blockedAt == nil && $0.revokedAt == nil }
            .map { $0.fingerprint }
        return MeshFriendVouchListPayload(
            voucherFingerprint: identity.localFingerprint,
            voucherDisplayName: displayName,
            trustedFingerprints: trusted,
            expiresAt: Date().addingTimeInterval(2 * 3600)
        )
    }

    private func sendVouchList(to slot: PeerSlot) async {
        guard let payload = vouchListPayloadForBroadcast() else { return }
        await sendEnvelope(.meshFriendVouchList, encodable: payload, via: slot)
    }

    /// Inbound counterpart of the Phase-2 vouch gate. While `isVouchListBroadcastEnabled` is
    /// off, inbound vouch lists are dropped wholesale — no cache write, no "Friend of …" label:
    /// the gate exists because vouch lists disclose a peer's friend graph without a consent
    /// design, and accepting/rendering them would keep that disclosure live on the receive side
    /// even with our own broadcast off. When enabled, the cached entry is hygiened: expiry is
    /// capped at the protocol's 2 h TTL (the wire value is sender-controlled) and the
    /// peer-supplied display name is sanitized before it is stored or rendered.
    /// Internal seam so tests can drive it without a live transport.
    func receiveVouchList(_ payload: MeshFriendVouchListPayload, senderFingerprint: String?) {
        guard isVouchListBroadcastEnabled else { return }
        guard payload.expiresAt > Date(),
              payload.voucherFingerprint == senderFingerprint else { return }
        let cappedExpiry = min(payload.expiresAt, Date().addingTimeInterval(2 * 3600))
        let name = ItemNameModeration.moderatedPeerDisplayName(payload.voucherDisplayName)
        vouchCache[payload.voucherFingerprint] = MeshFriendVouchListPayload(
            voucherFingerprint: payload.voucherFingerprint,
            voucherDisplayName: name,
            trustedFingerprints: payload.trustedFingerprints,
            expiresAt: cappedExpiry
        )
    }

    /// Test seam: the cached (gated, capped, sanitized) vouch payload for a voucher, if any.
    func cachedVouchList(from voucherFingerprint: String) -> MeshFriendVouchListPayload? {
        vouchCache[voucherFingerprint]
    }

    // MARK: - Private helpers

    /// The advertised local display name (shared coercion; see `PeerDisplayNames.swift`).
    private var displayName: String { store.resolvedProximityDisplayName }

    private var activeSlots: [PeerSlot] {
        slots.filter { $0.kind == .active }
    }

    /// The capability tokens advertised in this device's identity introduction. Photos always (the
    /// mesh's founding feature); `shop` only while clothing-shop sharing is enabled — the opt-out is
    /// payload-layer (Phase 3a), so an opted-out device neither advertises nor is sent catalogs.
    /// Snapshot at coordinator creation (capabilities ride the handshake intro); a mid-session toggle
    /// affects the NEXT session's advertisement, while its send/receive effect is immediate via the
    /// provider gates. Internal seam so tests can pin the gate without a live channel.
    /// Away-hearts gossip seams (bitchat adoptions Increment 3), wired by FernletStore: the local
    /// prekey bundle to ride our intros (nil = consent off or feature absent), the sink for
    /// friends' verified bundles, and the consent flag gating the `heartsAway` advertisement.
    public var heartDropBundleProvider: (() -> HeartPrekeyStore.Bundle?)?
    public var onPeerPrekeyBundle: ((Data, HeartPrekeyStore.Bundle) -> Void)?
    public var heartsAwayEnabledProvider: (() -> Bool)?

    /// Whether this device may take part in live-session chat at all — the 13+ age gate (see
    /// `AgeAssuranceRecord`). Optional-and-nil means NOT allowed, matching `heartsAwayEnabledProvider`:
    /// a manager nobody wired stays silent rather than opening a messaging surface to a child.
    ///
    /// Enforced in three places, because any one alone is insufficient:
    /// 1. `localCapabilities()` withholds `.messages`, so peers never broadcast to us in the first place.
    /// 2. `sendTempMessage` refuses, so nothing leaves this device.
    /// 3. the `.tempMessage` handler drops, because (1) is only an advertisement — a peer running a
    ///    modified build, or one that cached our capabilities from an earlier session, can still send.
    @ObservationIgnored public var chatAllowedProvider: (() -> Bool)?

    /// Resolved once per decision point so the three enforcement seams can never disagree. Public so the
    /// in-session UI can withhold the chat affordance from the same value the transport enforces.
    public var isChatAllowed: Bool { chatAllowedProvider?() == true }

    func localCapabilities() -> [String] {
        var capabilities = [ProximityCapability.photos.rawValue]
        // wire2 (bitchat adoptions Increment 2): sealed-payload compress+pad framing. A wire
        // format, not a user feature — no opt-out; advertised by every build that ships it.
        capabilities.append(ProximityCapability.wire2.rawValue)
        // heartsAway (bitchat adoptions Increment 3): advertised only when the user opted into
        // away delivery — signals our intro carries a prekey bundle and we accept drops.
        if heartsAwayEnabledProvider?() == true {
            capabilities.append(ProximityCapability.heartsAway.rawValue)
        }
        if clothingShop.isSharingEnabled {
            capabilities.append(ProximityCapability.shop.rawValue)
        }
        // Phase 5: temporary messages are a core in-session feature with no separate v1 opt-out —
        // session membership (the UWB dwell + admission) IS the consent gate. The one thing that DOES
        // withhold it is the 13+ age gate: a device below the line never advertises `messages`, so
        // friends' devices skip it in the room broadcast instead of sending into a surface it will drop.
        if isChatAllowed {
            capabilities.append(ProximityCapability.messages.rawValue)
        }
        // Content-moderation reports are a safety feature with no opt-out — always advertised so a
        // friend's device knows it may hand us the reports it has verified.
        capabilities.append(ProximityCapability.moderation.rawValue)
        // Phase 4: advertise fuzzy-state exchange only when the user opted in, so a friend sends us their
        // vibe only if we accept (and share) ours.
        if friendStateEnabledProvider?() == true {
            capabilities.append(ProximityCapability.friendState.rawValue)
        }
        // Phase 6: group activities are session-scoped; membership (the UWB dwell + the host's explicit
        // confirm) is the consent gate, so advertise unconditionally like messages. Offers are only sent
        // for activities the user chose to host, so there is nothing to opt out of.
        capabilities.append(ProximityCapability.activities.rawValue)
        // TF b19 item 5: in-session hearts ride the live mesh session. Advertise `.hearts` ONLY when this
        // device has opted in (`allowNearbyHearts`). The receiver enforces that same opt-out (plus the
        // trusted-friend requirement + block list) before recording anything, so advertising it while
        // opted out would make an opted-out device look heart-reachable: a sender would send, see a false
        // "Sent … good vibes", and burn the 5-minute cooldown even though the receiver silently drops it
        // (`receiveSessionHeart`). Gating the advertisement means opted-out peers never appear reachable,
        // so the sender's button reflects the true unavailable state. Also lets a sender skip peers on an
        // older build (no `.friendHeart` mesh handler) and fall back to presence.
        //
        // Accepted limitation: capabilities are exchanged once at the session handshake, so toggling this
        // setting mid-session does not retroactively update peers already connected in the session.
        if store.allowNearbyHearts {
            capabilities.append(ProximityCapability.hearts.rawValue)
        }
        return capabilities
    }

    /// Phase 3a outbound gate: send our catalog only to peers advertising the `shop` capability (a
    /// legacy client would park-and-drop it anyway — skip the bytes), and only while sharing is
    /// enabled locally. Internal seam so tests can pin the gate without a transport.
    func shouldOfferShopCatalog(to peerIdentity: ProximityCoordinator.PeerIdentity) -> Bool {
        clothingShop.isSharingEnabled && peerIdentity.supports(.shop)
    }

    /// Installs this manager's callbacks on its radio and, for a radio that authenticates peers
    /// itself, hands it the introduction authority.
    ///
    /// Both halves go through ``MeshTransportSession``, so the wiring reads the same whichever
    /// conformer is behind it. `attachIntroductionAuthority` is a documented no-op on the MC radio,
    /// whose peers authenticate one layer up inside the slot coordinator's identity introduction.
    private func setupMeshSession() {
        transportHandlers = makeTransportHandlers()
        transport.wire(transportHandlers)
        transport.attachIntroductionAuthority(self)
    }

    /// The callback set, built once so it can be both installed and kept (see ``transportHandlers``).
    private func makeTransportHandlers() -> MeshTransportHandlers {
        var handlers = MeshTransportHandlers()
        handlers.onPeerDiscovered = { [weak self] peer in
            self?.handlePeerDiscovered(peer)
        }
        handlers.onChannelReady = { [weak self] channel in
            self?.handleChannelReady(channel)
        }
        handlers.onPeerDisconnected = { [weak self] peer, _ in
            self?.handlePeerDisconnected(peer)
        }
        handlers.shouldAcceptInvitation = { [weak self] peer in
            guard let self else { return false }
            // Blocklist is enforced at identity-introduction time by the slot coordinator.
            if self.isProximityJoin && !self.isSessionOpen { return false }
            if self.slots.count < Self.maxTotalSlots { return true }
            return self.canEvaluateOverflowCandidate(peer)
        }
        handlers.onTransportError = { [weak self] message in
            // Discovery failed to start (e.g. a declined Local Network prompt, or a service type
            // missing from NSBonjourServices) — surface it instead of searching forever in
            // silence. Its own property, not `meshError`: the only `meshError` view lives inside a
            // session, which by definition does not exist yet at a discovery failure.
            self?.discoveryError = message
        }
        return handlers
    }

    /// A peer's link dropped: tear its slot down, then decide whether to re-invite it.
    ///
    /// Extracted from the transport wiring so the wiring stays a list of hooks and this stays
    /// readable — the retry bookkeeping is the part that has been subtly wrong before, and it is
    /// now reachable from a unit test through the injected fake rather than only through a radio.
    private func handlePeerDisconnected(_ peer: PeerHandle) {
        // Read BEFORE removeSlot (whose no-op kick of an already-dropped peer records the
        // endpoint too), then clear both records: a deliberate local eviction must not be retried.
        let wasKickedLocally = locallyKickedEndpoints.contains(peer.endpoint)
        let matchingSlot = slot(for: peer)
        let wasCommitted = matchingSlot?.fingerprint != nil
        if let slot = matchingSlot {
            removeSlot(slot)
        }
        locallyKickedEndpoints.remove(peer.endpoint)
        // P3 item 6 / invariant 1: **a disconnect is not a removal.** Losing the last committed
        // link moves the SESSION to `partitioned` and arms the idle window; it mints no record,
        // does not touch the ledger, and leaves the derived roster exactly as it was, so the peer
        // that comes back needs no re-admission.
        if wasCommitted, currentMesh != nil, !slots.contains(where: { $0.fingerprint != nil }) {
            applySessionEvent(.linksLost)
        }
        // In proximity join: if the link dropped before the peer committed and we are the
        // designated inviter (higher session id), retry up to maxPeerRetries times. Without this, a
        // transient socket failure permanently strands the session because the browser won't
        // re-fire onPeerDiscovered for a peer it already found.
        guard isProximityJoin, isSessionOpen, !wasCommitted, !wasKickedLocally else { return }
        guard shouldInitiateInvite(to: peer) else { return }
        let retryCount = peerRetryCount[peer.endpoint, default: 0]
        guard retryCount < Self.maxPeerRetries else { return }
        peerRetryCount[peer.endpoint] = retryCount + 1
        Task { [weak self] in
            // A cancelled retry must not invite (R7).
            do {
                try await Task.sleep(for: .seconds(Self.reinviteDelaySeconds))
            } catch {
                return
            }
            guard let self, self.isProximityJoin, self.isSessionOpen,
                  self.slots.count < Self.maxTotalSlots,
                  !self.hasSlot(for: peer) else { return }
            self.transport.invite(peer)
        }
    }

    private func startSearching() {
        isSearching = true
        // Clear any stale discovery failure before re-arming the radios, so a fixed permission
        // (or a fresh attempt after a transient failure) drops the banner instead of pinning it up
        // over a search that is now healthy.
        discoveryError = nil
        transport.startRadios(discoveryInfo: currentDiscoveryInfo())
        startObserving()
    }

    private func stopSearching() {
        observationTask?.cancel()
        observationTask = nil
        isSearching = false
        // A discovery failure is meaningful only while we are actively searching; leaving the tab
        // clears it so it never reappears stale on the next visit.
        discoveryError = nil
        isProximityJoin = false
        peerRetryCount.removeAll()
        locallyKickedEndpoints.removeAll()
        sentShopCatalogSlotIDs.removeAll()
        shopCatalogRequestResponseAt.removeAll()
        transport.stop()
        for slot in slots { Task { await slot.coordinator.cancel() } }
        slots.removeAll()
        slotTrustPolicies.removeAll()
        pendingQRVerifications.removeAll()
        photoSendsInFlight.removeAll()
        // Group crypto cannot outlive the slots (R2/R3): without this the 20 s beacon loop and the
        // rotation timer kept waking for the manager's lifetime after a stopJoin-ended session.
        clearGroupKeyState()
        // Teardown path (leaveSession/leaveMesh/stopJoin funnel through here): the last committed
        // slot is gone, so any unreviewed roster promotes into the pending friend-review batch and
        // any held shop catalogs open the post-session shop window (Phase 3a).
        promoteRosterToPendingReviewIfSessionEnded()
        openShopWindowIfSessionEnded()
        clearSessionMessagesIfSessionEnded()
    }

    /// The advertised TXT payload: version + the per-launch session id, plus the mesh identifiers
    /// when an OPEN mesh is up.
    ///
    /// Deliberately NO display name. Nothing on this radio ever read `discoveryInfo["name"]` — the
    /// recipe radio's recipient picker is the only reader anywhere, and it runs on
    /// `fernlet-recipe` — and unlike `sid`, a per-launch random UUID, a proximity display name is
    /// stable across launches and locations, so a passive Bonjour scanner could link sightings of
    /// one person. A peer learns our name only inside the signed identity introduction, after a
    /// connection. Same hygiene rule as `PresenceManager.discoveryInfo()`.
    ///
    /// `meshName`/`memberCount` STAY: advertising an open mesh to nearby devices is the product
    /// behaviour of open mode, and closed mode already suppresses all three (that toggle is the
    /// user-facing control). Removing them would be a product decision, not a hygiene fix.
    public func currentDiscoveryInfo() -> [String: String] {
        var info: [String: String] = [
            "v": "1",
            "sid": sessionID
        ]
        if let mesh = currentMesh, mesh.mode == .open {
            info["meshID"] = mesh.meshID.uuidString
            info["meshName"] = String(mesh.name.prefix(40))
            info["memberCount"] = "\(mesh.members.count)"
        }
        return info
    }

    private func updateDiscoveryInfo() {
        transport.updateDiscoveryInfo(currentDiscoveryInfo())
    }

    /// Decides which half of a mutually-discovered pair sends the MC invitation.
    ///
    /// Both peers browse AND advertise, so both discover each other; without a tie-break both
    /// invite simultaneously and the NW/MC layer fails the pair with errno 61 ("no clist for
    /// remoteID"). The comparison must therefore be SYMMETRIC — the same two values compared on
    /// both devices, so that exactly one side evaluates true.
    ///
    /// The previous guard compared OUR fingerprint against THEIR display name, which is not a
    /// comparison of like with like, and in practice deadlocked the mesh outright:
    ///   * `advertisedFingerprint` reads `discoveryInfo["fp"]`, but `currentDiscoveryInfo()` has
    ///     never published an `"fp"` key on this radio — so it is always nil and the fallback to
    ///     `displayName` always ran;
    ///   * `displayName` is `UIDevice.current.name`, which iOS 16+ reports as the generic
    ///     "iPhone" unless the app holds `com.apple.developer.device-information.
    ///     user-assigned-device-name` (Fernlet.entitlements does not request it);
    ///   * `localFingerprint` is 16 lowercase hex chars, so its first character is at most "f" —
    ///     always less than "i". `localFingerprint > "iPhone"` was therefore false on BOTH sides,
    ///     every time, and the transport's `invite` was unreachable from either call site.
    ///
    /// `sid` is the correct discriminator: a per-launch random UUID that both sides already
    /// broadcast in `currentDiscoveryInfo()`. It needs no new field on the wire, and — unlike a
    /// fingerprint — it is not linkable across sessions, so publishing it costs no privacy.
    /// Internal rather than private so the symmetry property can be asserted directly — the bug
    /// this replaces was invisible to every existing test because it lived inside a closure that
    /// needs live radios to reach.
    func shouldInitiateInvite(to peer: PeerHandle) -> Bool {
        Self.shouldInitiateInvite(
            localSessionID: sessionID,
            peerSessionID: peer.discoveryInfo?["sid"]
        )
    }

    /// The tie-break itself, over the two values it actually compares.
    ///
    /// Split out from ``shouldInitiateInvite(to:)`` for one reason: the instance method can only
    /// ever be evaluated with THIS manager's random per-launch `sid` on the left, so a test can
    /// pin one side of a pair but never enumerate both sides across a chosen ordering — and
    /// "exactly one of the two sides dials" is the whole property. Nothing about the decision
    /// changed; the instance method reads the peer's advertisement and delegates here.
    ///
    /// Equal session ids deliberately return false on BOTH sides. `sid` is per-launch and random,
    /// so two advertisements carrying the same one are our own echo (a stale Bonjour cache of this
    /// process — the ghost `PresenceManager` excludes by hand), and dialling ourselves is never
    /// right. The cost is that a peer which replays our `sid` back at us can suppress our invite;
    /// that is a denial of discovery it could equally achieve by not advertising at all, not an
    /// authentication bypass.
    nonisolated static func shouldInitiateInvite(
        localSessionID: String,
        peerSessionID: String?
    ) -> Bool {
        guard let peerSessionID, !peerSessionID.isEmpty else {
            // Discovery info absent (peer not yet resolved, or a build predating "sid"). Deadlock
            // is strictly worse than a redundant invite here: a simultaneous mutual invite fails
            // one side with errno 61 and the disconnect-retry path recovers it, whereas neither
            // side inviting strands the pair permanently — which is exactly the bug above.
            return true
        }
        return localSessionID > peerSessionID
    }

    /// This device's slot in the live session, matched the way every transport event must be
    /// matched: by ``PeerHandle/isSameEndpoint(as:)``, never `==`.
    ///
    /// The one spelling of "does this peer already hold a seat?", so the seat gates, the invite
    /// gates and the disconnect path cannot drift apart again — which they had (review finding #19,
    /// plan §6.4 findings 1–2): the disconnect lookup used the endpoint test while the seat gates
    /// beside it compared `id`, so a device the transport re-minted was admitted a second time by
    /// the very guard that exists to refuse it.
    private func slot(for peer: PeerHandle) -> PeerSlot? {
        slots.first { $0.peer.isSameEndpoint(as: peer) }
    }

    /// True when `peer` already holds a slot. See ``slot(for:)``.
    private func hasSlot(for peer: PeerHandle) -> Bool {
        slot(for: peer) != nil
    }

    private func handlePeerDiscovered(_ peer: PeerHandle) {
        // Proximity-join mode: auto-invite every peer silently; no browse list shown.
        if isProximityJoin {
            guard isSessionOpen else { return }
            guard shouldInitiateInvite(to: peer) else { return }
            if slots.count < Self.maxTotalSlots, !hasSlot(for: peer) {
                transport.invite(peer)
            }
            return
        }

        // Auto-invite peers into our open mesh when capacity exists, or when one
        // temporary overflow candidate can be evaluated with real distance data.
        if let mesh = currentMesh, mesh.mode == .open {
            if slots.count < Self.maxTotalSlots || canEvaluateOverflowCandidate(peer) {
                if !hasSlot(for: peer) {
                    transport.invite(peer)
                }
            }
        }
    }

    /// What ``handleChannelReady`` does with a freshly connected channel.
    ///
    /// Extracted from the guard chain so the seat decision is reachable from a unit test: what
    /// follows it in production is a live `ProximityCoordinator` over a real `NIRangingSession`,
    /// which a unit test must not build, and the decision is the half that has been wrong.
    enum ChannelAdmission: Equatable {
        /// Seat the peer: build the coordinator and append a slot.
        case seat
        /// Refuse and free the MC link. A connected peer with no slot holds a zombie link — a
        /// channel with no owner, one of the 8 MC peer slots — until the search stops.
        case kick
        /// This device already holds a live slot. Leave it entirely alone: kicking here would drop
        /// the good connection, and seating would break the slot cap from the inside.
        case alreadySeated
    }

    /// The seat decision for a freshly connected channel — see ``ChannelAdmission``.
    func channelAdmission(for peer: PeerHandle) -> ChannelAdmission {
        guard !isProximityJoin || isSessionOpen else { return .kick }
        guard slots.count < Self.maxSlotsDuringOverflowEvaluation else { return .kick }
        guard !hasSlot(for: peer) else { return .alreadySeated }
        return .seat
    }

    private func handleChannelReady(_ channel: any MeshPeerChannel) {
        switch channelAdmission(for: channel.peer) {
        case .kick:
            kickEvictedPeer(channel.peer)
            return
        case .alreadySeated:
            return
        case .seat:
            break
        }

        let isOverflowCandidate = slots.count >= Self.maxTotalSlots
        let kind: SlotKind = activeSlots.count < Self.maxActiveSlots ? .active : .lightweight
        let trustPolicy = FriendSessionTrustPolicy(vault: store.proximityTrustVault)

        let coordinator = ProximityCoordinator(
            identity: identity,
            transport: channel,
            ranging: NIRangingSession(),
            payloadHandler: self,
            trustPolicy: trustPolicy,
            replayCache: replayCache,
            displayName: displayName,
            capabilities: localCapabilities(),
            timeoutSeconds: isProximityJoin ? 25 : 60
        )
        // Away-hearts prekey gossip (Increment 3): ride our intro, ingest verified peers'.
        coordinator.heartDropPrekeyBundleProvider = { [weak self] in self?.heartDropBundleProvider?() }
        coordinator.onHeartDropPrekeyBundle = { [weak self] key, bundle in self?.onPeerPrekeyBundle?(key, bundle) }

        let slot = PeerSlot(
            id: channel.peer.id,
            peer: channel.peer,
            channel: channel,
            coordinator: coordinator,
            kind: kind,
            fingerprint: nil,
            isOverflowCandidate: isOverflowCandidate
        )
        slotTrustPolicies[slot.id] = trustPolicy
        slots.append(slot)

        Task {
            await coordinator.begin(role: .browser, mode: .friend)
            channel.notifyConnected()
        }
    }

    private func removeSlot(_ slot: PeerSlot) {
        Task { await slot.coordinator.cancel() }
        kickEvictedPeer(slot.peer)
        clearActiveVerifyQRIfBound(to: slot.id)
        // Entries die with their slot (R3): a scanned-but-unanswered round would otherwise leak
        // one entry for the manager's lifetime, and survive into a reused slot id.
        pendingQRVerifications.removeValue(forKey: slot.id)
        // Same rule for the outstanding join request: it dies with its slot, so it can neither
        // leak for the manager's lifetime nor authorize a grant on a reused slot id (R3).
        outstandingAdmissionRequestBySlot.removeValue(forKey: slot.id)
        photoSendsInFlight.remove(slot.id)
        slots.removeAll { $0.id == slot.id }
        slotTrustPolicies.removeValue(forKey: slot.id)
        pruneShopSendTracking(for: slot.id)
        rerankSlots()
        promoteRosterToPendingReviewIfSessionEnded()
        openShopWindowIfSessionEnded()
        clearSessionMessagesIfSessionEnded()
    }

    private func disconnectSlot(_ slot: PeerSlot) {
        Task { [weak self] in
            // No `.sessionGoodbye` (P3 item 3, plan §8.3): parsed, never emitted. Cancelling the
            // coordinator IS the disconnect the goodbye used to announce, and a disconnect is all
            // an unsigned frame could ever have meant — membership ends only via a signed
            // departure or removal record.
            await slot.coordinator.cancel()
            self?.kickEvictedPeer(slot.peer)
        }
        clearActiveVerifyQRIfBound(to: slot.id)
        // Entries die with their slot (R3): a scanned-but-unanswered round would otherwise leak
        // one entry for the manager's lifetime, and survive into a reused slot id.
        pendingQRVerifications.removeValue(forKey: slot.id)
        // Same rule for the outstanding join request: it dies with its slot, so it can neither
        // leak for the manager's lifetime nor authorize a grant on a reused slot id (R3).
        outstandingAdmissionRequestBySlot.removeValue(forKey: slot.id)
        photoSendsInFlight.remove(slot.id)
        slots.removeAll { $0.id == slot.id }
        slotTrustPolicies.removeValue(forKey: slot.id)
        pruneShopSendTracking(for: slot.id)
        rerankSlots()
        promoteRosterToPendingReviewIfSessionEnded()
        openShopWindowIfSessionEnded()
        clearSessionMessagesIfSessionEnded()
    }

    /// Frees the MC link of a peer whose slot this manager is evicting itself. `removeSlot` /
    /// `disconnectSlot` drop the record and cancel the coordinator, but nothing in that chain
    /// touches the shared radio (a channel's `disconnect()` only publishes `.idle` locally),
    /// so the link lingered as a zombie until `stopSearching()`: it held one of the 8 MC peer slots
    /// on both devices, kept the peer's channel in the transport's `channels`, and —
    /// because `invite` refuses connected peers and `.connected` never re-fires — made re-forming a
    /// slot with that peer impossible for the rest of the search. Best-effort with the same caveat
    /// as the sibling managers (see `MeshTransportSession.disconnectPeer`); a no-op for a peer the
    /// radio already reported gone. Records the endpoint so `onPeerDisconnected` does not treat the
    /// resulting `.notConnected` as a transient drop to retry.
    private func kickEvictedPeer(_ peer: PeerHandle) {
        if locallyKickedEndpoints.count < Self.maxLocallyKickedPeers {
            locallyKickedEndpoints.insert(peer.endpoint)
        }
        transport.disconnectPeer(peer)
    }

    /// Slot eviction prunes the shop send-tracking so a REJOINING friend re-exchanges catalogs: the
    /// transport's peerMap persists across a remote teardown, so a returning peer reuses its old slot
    /// UUID — without this, the once-per-slot guard would silently skip its re-commit send forever.
    private func pruneShopSendTracking(for slotID: UUID) {
        sentShopCatalogSlotIDs.remove(slotID)
        shopCatalogRequestResponseAt.removeValue(forKey: slotID)
    }

    private func onSlotConnected(at index: Int, identity peerIdentity: ProximityCoordinator.PeerIdentity) {
        let slot = slots[index]

        // Phase 2: capture the handshake-verified identity into the session roster at slot
        // commit, so the post-session keep-as-friend prompt still has it after slot teardown.
        recordSessionParticipant(
            displayName: peerIdentity.displayName,
            fingerprint: peerIdentity.fingerprint,
            signingPublicKey: peerIdentity.signingPublicKey,
            keyAgreementPublicKey: peerIdentity.keyAgreementPublicKey
        )

        // Phase 3a: session formation + the per-slot catalog exchange. Before the shape branches
        // below so every commit path (pairwise, promote-to-mesh, joiner) runs it.
        noteSlotCommittedForShop(slot: slot, identity: peerIdentity)

        // Proximity-join shape decision: pairwise (1 committed) → mesh (≥ 2 committed).
        // `slot.fingerprint` was set by checkCoordinatorStates before calling here, so
        // connectedCount already includes this slot.
        if isProximityJoin && currentMesh == nil {
            let connectedCount = slots.filter { $0.fingerprint != nil }.count
            if connectedCount >= 2 {
                // Promote to mesh: create descriptor and broadcast to all committed slots.
                promoteToMesh()
                return  // promoteToMesh handles descriptor + manifest sync for all slots
            }
            // First committed peer — pairwise, sync photos and return early.
            Task { [weak self] in
                guard let self else { return }
                await self.syncPhotoManifest(to: slot)
                await self.sendVouchList(to: slot)
            }
            return
        }

        if currentMesh != nil {
            Task { [weak self] in
                guard let self else { return }
                await self.sendMeshDescriptor(to: slot)
                await self.syncPhotoManifest(to: slot)
            }
        }
        // Exchange vouch lists after every successful identity verification
        Task { [weak self] in await self?.sendVouchList(to: slot) }

        // P3 item 6: the first committed peer makes a joining session active (plan §8.2).
        if currentMesh != nil { applySessionEvent(.peerCommitted) }

        // Phase 3: start the beacon loop and, if we are the coordinator, schedule the first rotation.
        if currentMesh != nil && beaconTimer == nil {
            startBeaconLoop()
            if isLocalCoordinator() && rotationTimer == nil {
                let nextAt = Date().addingTimeInterval(Self.rotationInterval)
                lastKnownNextRotationAt = nextAt
                scheduleRotationTimer(fireAt: nextAt)
            }
        }
    }

    /// Creates a MeshDescriptor in-place and broadcasts it to all committed slots
    /// without restarting search. Called on the 2nd proximity commit.
    private func promoteToMesh() {
        // A mesh we CREATE starts at epoch 0 by definition. Any key state surviving from the
        // pre-mesh pairwise phase is, by construction, not this mesh's key — clearing it here
        // removes the key-survival leg of the admission-grant attack independently of the
        // authorization guards in `handleAdmissionGrant`. Deliberately just the two fields, not
        // `clearGroupKeyState()` — no rotation/beacon timer is running pre-mesh, and cancelling
        // them here would be an unrelated behaviour change.
        clearEpochKeyring()
        localJoinedEpoch = 0
        let now = Date()
        let localFP = identity.localFingerprint
        let localMember = MeshMember(
            fingerprint: localFP,
            displayName: displayName,
            signingPublicKey: identity.localSigningPublicKey,
            keyAgreementPublicKey: identity.localKeyAgreementPublicKey,
            joinedAt: now
        )
        currentMesh = MeshDescriptor(
            meshID: UUID(),
            name: MeshNameGenerator.generate(),
            mode: isSessionOpen ? .open : .closed,
            members: [localMember],
            nameSetAt: now,
            nameSetBy: localFP,
            modeSetAt: now,
            modeSetBy: localFP,
            createdAt: now
        )
        // Keep the quota counter across pairwise→mesh promotion: pin the new meshID so
        // the addPhoto reset guard doesn't fire and grant a free extra 27 shots.
        sessionQuotaMeshID = currentMesh?.meshID
        updateDiscoveryInfo()
        let committed = slots.filter { $0.fingerprint != nil }
        // Phase 2 belt-and-braces: every committed slot already passed through onSlotConnected
        // (which recorded its verified identity), so this is insert-only — `slot.peer.displayHint`
        // is the MC transport name and must not overwrite the identity display name.
        for slot in committed {
            guard let fingerprint = slot.fingerprint,
                  !sessionRoster.contains(where: { $0.fingerprint == fingerprint }),
                  let signingKey = slot.verifiedSigningPublicKey,
                  let kaKey = slot.verifiedKeyAgreementPublicKey else { continue }
            recordSessionParticipant(
                displayName: slot.peer.displayHint,
                fingerprint: fingerprint,
                signingPublicKey: signingKey,
                keyAgreementPublicKey: kaKey
            )
        }
        Task { [weak self] in
            guard let self else { return }
            for slot in committed {
                await self.sendMeshDescriptor(to: slot)
                await self.syncPhotoManifest(to: slot)
                await self.sendVouchList(to: slot)
            }
        }
        if beaconTimer == nil {
            startBeaconLoop()
            if isLocalCoordinator() && rotationTimer == nil {
                let nextAt = Date().addingTimeInterval(Self.rotationInterval)
                lastKnownNextRotationAt = nextAt
                scheduleRotationTimer(fireAt: nextAt)
            }
        }
    }

    /// Expose per-slot manual-commit requests to the UI (non-UWB fallback).
    public var pendingManualCommits: [(slotID: UUID, peerName: String)] {
        slots.compactMap { slot in
            if case .awaitingManualCommit(let peer) = slot.coordinator.state {
                return (slot.id, peer.displayName)
            }
            return nil
        }
    }

    public func commitManualProximity(slotID: UUID) {
        guard let slot = slots.first(where: { $0.id == slotID }) else { return }
        Task { await slot.coordinator.commitManualProximity() }
    }

    // MARK: - QR verification ceremony (bitchat adoptions Increment 4)

    /// The QR currently displayed on THIS device, bound to the slot row the sheet was opened from.
    /// The slot binding is load-bearing: the sheet names ONE peer ("Verify with Bob"), so a
    /// challenge quoting this nonce from any OTHER connected peer is a third party racing the
    /// ceremony — honoring it would commit the racer's slot AND burn the single-use nonce the
    /// named peer still needs. Cleared on the first honored challenge, on sheet dismissal
    /// (`clearActiveVerifyQR`), and on expiry.
    @ObservationIgnored private var activeVerifyQR: (slotID: UUID, nonce: Data, issuedAt: Date)?
    /// Scanner-side pending rounds keyed by slot id; entries die with their slots (≤5 total, no
    /// separate timeout needed — a slot that never answers ends with the session).
    @ObservationIgnored private var pendingQRVerifications: [UUID: (qrNonce: Data, challengeNonce: Data, expectedSigningKey: Data)] = [:]

    /// The signed QR for `slotID`'s peer to scan (displayer side). Freshness-limited to 5 minutes,
    /// and only a challenge arriving on `slotID` is honored — pass the slot the sheet was opened
    /// from, never a "current" slot guessed at challenge time.
    public func makeLocalVerifyQRURL(slotID: UUID) -> URL? {
        guard let made = try? ProximityVerifyQR.makeURL(identity: identity) else { return nil }
        activeVerifyQR = (slotID: slotID, nonce: made.nonce, issuedAt: Date())
        return made.url
    }

    /// Ends the display half of the ceremony (sheet dismissed, app backgrounded, session over).
    /// The manager expires the binding on its own as well — this is what makes "a photographed QR
    /// is useless once the sheet closed" literally true rather than merely time-bounded.
    public func clearActiveVerifyQR() {
        guard activeVerifyQR != nil else { return }
        activeVerifyQR = nil
        FernletAuditLog.log("mesh.verifyQR.displayCleared")
    }

    /// Drops the binding when its slot goes away. The ceremony already fails closed without this
    /// (a challenge is only honored on the bound slot, and dispatch can't resolve a departed one),
    /// but leaving a live nonce behind a vanished peer is state nobody can ever spend.
    private func clearActiveVerifyQRIfBound(to slotID: UUID) {
        guard activeVerifyQR?.slotID == slotID else { return }
        clearActiveVerifyQR()
    }

    private func manualCommitPeer(of slot: PeerSlot) -> ProximityCoordinator.PeerIdentity? {
        if case .awaitingManualCommit(let peer) = slot.coordinator.state { return peer }
        return nil
    }

    /// The peer identity to answer a ceremony envelope to. `manualCommitPeer` only sees the
    /// pre-commit gate state, but a challenge can legitimately land on a slot that committed in
    /// the meantime (the row's plain Connect button, or the peer's own ceremony round), and a nil
    /// there silently downgrades the sealed response to the legacy format. Fall through the
    /// post-commit states so the capability read is valid at send time.
    private func ceremonyPeerIdentity(of slot: PeerSlot) -> ProximityCoordinator.PeerIdentity? {
        switch slot.coordinator.state {
        case .awaitingProximityCommit(let peer), .awaitingManualCommit(let peer),
             .awaitingUserConfirmation(let peer), .connected(let peer), .transferring(let peer, _):
            return peer
        default:
            return nil
        }
    }

    /// Scanner side: a `fernlet://verify` QR was scanned. Validates signature + freshness, then
    /// opens the sealed challenge round ONLY against `slotID` — the row the sheet was opened from.
    ///
    /// The round is never SEARCHED for: a code that is perfectly valid but belongs to a different
    /// nearby peer is refused, not silently redirected. That is the same property the displayer
    /// half already enforces (`makeLocalVerifyQRURL(slotID:)` / the `activeVerifyQR` binding), and
    /// without it "verify the person in front of you" degrades to "verify whoever is nearby".
    /// Returns false when the QR is invalid/stale, the row is gone or no longer awaiting, or the
    /// code belongs to someone else.
    ///
    /// A rejected scan is the whole point of the ceremony, so the result is not discardable (R7):
    /// the scanning row surfaces the refusal to the user rather than letting the sheet close as if
    /// the code had been accepted.
    public func beginQRVerification(with url: URL, slotID: UUID) -> Bool {
        guard let payload = ProximityVerifyQR.parse(url), ProximityVerifyQR.isValid(payload) else {
            FernletAuditLog.log("mesh.verifyQR.invalidScanned")
            return false
        }
        guard let slot = slots.first(where: { $0.id == slotID }),
              let peer = manualCommitPeer(of: slot) else {
            FernletAuditLog.log("mesh.verifyQR.noAwaitingSlotMatch")
            return false
        }
        guard peer.signingPublicKey == payload.signingPublicKey else {
            FernletAuditLog.log("mesh.verifyQR.qrPeerMismatch")
            return false
        }
        let challengeNonce = Data((0..<16).map { _ in UInt8.random(in: .min ... .max) })
        pendingQRVerifications[slot.id] = (payload.nonce, challengeNonce, payload.signingPublicKey)
        let challenge = VerifyChallengePayload(qrNonce: payload.nonce, challengeNonce: challengeNonce)
        Task { await sendVerifyEnvelope(.verifyChallenge, encodable: challenge, to: peer, via: slot) }
        FernletAuditLog.log("mesh.verifyQR.challengeSent")
        return true
    }

    private func handleVerifyChallenge(_ envelope: FernletIdentityEnvelope, plaintext: Data, slot: PeerSlot?) {
        guard let slot,
              let payload = try? JSONDecoder().decode(VerifyChallengePayload.self, from: plaintext) else { return }
        // Only honor a challenge quoting the QR THIS device is displaying right now — a
        // photographed QR is useless once the sheet closed.
        guard let active = activeVerifyQR, active.nonce == payload.qrNonce else {
            FernletAuditLog.log("mesh.verifyQR.staleChallengeDropped")
            return
        }
        // Displayer-side expiry: the QR's own timestamp bounds what the SCANNER accepts, which a
        // hostile scanner simply ignores. abs() so a backwards clock jump can't resurrect a
        // display either.
        guard abs(Date().timeIntervalSince(active.issuedAt)) <= ProximityVerifyQR.freshnessWindow else {
            activeVerifyQR = nil
            FernletAuditLog.log("mesh.verifyQR.expiredChallengeDropped")
            return
        }
        // The sheet named ONE peer, so a challenge on any other slot is a third party who can see
        // this screen. Drop it WITHOUT clearing: burning the nonce here is exactly how such a peer
        // would deny the named peer its genuine round.
        guard active.slotID == slot.id else {
            FernletAuditLog.log("mesh.verifyQR.wrongSlotChallengeDropped")
            return
        }
        // Fixed-length fields only — the transcript has no length prefixes, and nothing is signed
        // with the identity key until the wire-supplied nonce and KA key are bounded.
        guard ProximityVerifySignature.isWellFormedChallenge(
            payload, scannerKeyAgreementPublicKey: envelope.senderKeyAgreementPublicKey
        ) else {
            FernletAuditLog.log("mesh.verifyQR.malformedChallengeDropped")
            return
        }
        let message = ProximityVerifySignature.message(
            scannerKeyAgreementPublicKey: envelope.senderKeyAgreementPublicKey,
            challengeNonce: payload.challengeNonce,
            qrNonce: payload.qrNonce
        )
        let signature: Data
        do {
            signature = try identity.sign(message, purpose: FernletCryptoPurpose.Signature.proximityQRResponseV1)
        } catch {
            // Recovery is "no response" — the scanner never commits — so name it (R7) instead of
            // leaving the ceremony to die silently.
            FernletAuditLog.log(
                "mesh.verifyQR.signFailed",
                context: ["error": String(describing: error)]
            )
            return
        }
        activeVerifyQR = nil // single use
        let response = VerifyResponsePayload(challengeNonce: payload.challengeNonce, signature: signature)
        let supportsWire2 = ceremonyPeerIdentity(of: slot)?.supports(.wire2) ?? slot.supports(.wire2)
        Task {
            await sendVerifyEnvelope(
                .verifyResponse,
                encodable: response,
                toKeyAgreementKey: envelope.senderKeyAgreementPublicKey,
                fingerprint: IdentityService.fingerprint(of: envelope.senderSigningPublicKey),
                supportsWire2: supportsWire2,
                via: slot
            )
        }
        // Mutual upgrade: a sealed, signed challenge quoting OUR live display is the scanner's
        // ceremony proof — commit this side too.
        if case .awaitingManualCommit = slot.coordinator.state {
            commitManualProximity(slotID: slot.id)
            FernletAuditLog.log("mesh.verifyQR.displayerCommitted")
        }
    }

    private func handleVerifyResponse(_ envelope: FernletIdentityEnvelope, plaintext: Data, slot: PeerSlot?) {
        guard let slot,
              let pending = pendingQRVerifications[slot.id],
              let payload = try? JSONDecoder().decode(VerifyResponsePayload.self, from: plaintext),
              payload.challengeNonce == pending.challengeNonce,
              envelope.senderSigningPublicKey == pending.expectedSigningKey else { return }
        let message = ProximityVerifySignature.message(
            scannerKeyAgreementPublicKey: identity.localKeyAgreementPublicKey,
            challengeNonce: pending.challengeNonce,
            qrNonce: pending.qrNonce
        )
        guard IdentityService.verify(payload.signature, of: message, by: pending.expectedSigningKey,
                                     purpose: FernletCryptoPurpose.Signature.proximityQRResponseV1) else {
            pendingQRVerifications[slot.id] = nil
            FernletAuditLog.log("mesh.verifyQR.badResponseSignature")
            return
        }
        pendingQRVerifications[slot.id] = nil
        if case .awaitingManualCommit = slot.coordinator.state {
            commitManualProximity(slotID: slot.id)
        }
        FernletAuditLog.log("mesh.verifyQR.scannerCommitted")
    }

    private func sendVerifyEnvelope(
        _ type: PayloadType,
        encodable: some Encodable,
        to peer: ProximityCoordinator.PeerIdentity,
        via slot: PeerSlot
    ) async {
        await sendVerifyEnvelope(
            type,
            encodable: encodable,
            toKeyAgreementKey: peer.keyAgreementPublicKey,
            fingerprint: peer.fingerprint,
            supportsWire2: peer.supports(.wire2),
            via: slot
        )
    }

    /// Pre-commit sealed send: the ceremony runs BEFORE slot commit, so the slot's verified key
    /// fields aren't populated yet — seal to the identity carried by the gate state / envelope
    /// instead of `slot.verifiedKeyAgreementPublicKey` (which `sendEnvelope` uses).
    private func sendVerifyEnvelope(
        _ type: PayloadType,
        encodable: some Encodable,
        toKeyAgreementKey kaKey: Data,
        fingerprint: String?,
        supportsWire2: Bool,
        via slot: PeerSlot
    ) async {
        // Nothing retries a failed ceremony send — the user just never sees a commit — so the
        // failure is audit-logged rather than swallowed (R7).
        let sent = await sendEnvelopeCore(
            type,
            encodable: encodable,
            sealTo: (kaKey: kaKey, supportsWire2: supportsWire2),
            fingerprint: fingerprint,
            via: slot,
            auditSendFailure: true
        )
        if !sent {
            FernletAuditLog.log("mesh.verifyQR.sendFailed", context: ["type": type.rawValue])
        }
    }

    // MARK: Ceremony test seams (`internal` for `@testable` unit tests only)

    /// Backdates the live QR binding so the displayer-side expiry can be exercised without a unit
    /// test waiting out the freshness window.
    func backdateActiveVerifyQRForTesting(by seconds: TimeInterval) {
        guard let active = activeVerifyQR else { return }
        activeVerifyQR = (active.slotID, active.nonce, active.issuedAt.addingTimeInterval(-seconds))
    }

    /// The challenge nonce this device minted for `slotID`. The ceremony otherwise reveals it only
    /// inside a sealed envelope on the slot channel, which a unit test's fake session can't read.
    func pendingVerifyChallengeNonceForTesting(slotID: UUID) -> Data? {
        pendingQRVerifications[slotID]?.challengeNonce
    }

    /// Whether a full mesh may admit `peer` as the one temporary overflow candidate — a seat above
    /// the cap, held only long enough to compare real distance data against the farthest
    /// lightweight slot.
    ///
    /// The first guard is the asymmetry plan §6.4 named: it used to compare `peer.id`, so a device
    /// already holding a lightweight slot that came back under a re-minted handle was accepted as
    /// its own overflow candidate — a second seat for one device, at the exact moment the session
    /// is over capacity. `internal` so that decision is testable without live radios.
    func canEvaluateOverflowCandidate(_ peer: PeerHandle) -> Bool {
        guard !hasSlot(for: peer) else { return false }
        guard slots.count < Self.maxSlotsDuringOverflowEvaluation else { return false }
        guard !slots.contains(where: { $0.isOverflowCandidate }) else { return false }
        return farthestLightweightSlotWithStableDistance() != nil
    }

    private func updateDistanceSamples() {
        let now = Date()
        var changed = false
        for index in slots.indices {
            guard case .meters(let meters, _) = slots[index].coordinator.lastKnownDistance else { continue }
            slots[index].distanceSamples.append(MeshDistanceSample(recordedAt: now, meters: meters))
            slots[index].distanceSamples.removeAll {
                now.timeIntervalSince($0.recordedAt) > Self.distanceStabilityWindow
            }
            if slots[index].distanceSamples.count >= Self.requiredStableDistanceSamples {
                let total = slots[index].distanceSamples.reduce(0) { $0 + $1.meters }
                slots[index].stableDistanceMeters = total / Double(slots[index].distanceSamples.count)
                changed = true
            }
        }
        if changed {
            resolveOverflowIfPossible()
            rerankSlots()
        }
    }

    private func resolveOverflowIfPossible() {
        guard slots.count > Self.maxTotalSlots,
              let candidate = slots.first(where: { $0.isOverflowCandidate }) else { return }
        guard let candidateDistance = candidate.stableDistanceMeters else { return }
        guard let farthest = farthestLightweightSlotWithStableDistance(excluding: candidate.id),
              let farthestDistance = farthest.stableDistanceMeters else {
            disconnectSlot(candidate)
            return
        }

        if candidateDistance < farthestDistance * (1 - Self.evictionHysteresis) {
            disconnectSlot(farthest)
            if let candidateIndex = slots.firstIndex(where: { $0.id == candidate.id }) {
                slots[candidateIndex].isOverflowCandidate = false
            }
        } else {
            disconnectSlot(candidate)
        }
    }

    private func rerankSlots() {
        guard !slots.isEmpty else { return }
        let ranked = slots.sorted { lhs, rhs in
            switch (lhs.stableDistanceMeters, rhs.stableDistanceMeters) {
            case let (l?, r?): return l < r
            case (_?, nil): return true
            case (nil, _?): return false
            case (nil, nil): return false
            }
        }
        let activeIDs = Set(ranked.prefix(Self.maxActiveSlots).map(\.id))
        for index in slots.indices {
            slots[index].kind = activeIDs.contains(slots[index].id) ? .active : .lightweight
        }
    }

    private func farthestLightweightSlotWithStableDistance(excluding excludedID: UUID? = nil) -> PeerSlot? {
        slots
            .filter { $0.id != excludedID && $0.kind == .lightweight && $0.stableDistanceMeters != nil }
            .max { ($0.stableDistanceMeters ?? 0) < ($1.stableDistanceMeters ?? 0) }
    }

    // MARK: - Mesh descriptor

    private func handleMeshDescriptor(_ descriptor: MeshDescriptor, from senderFingerprint: String?) {
        // Validate the untrusted descriptor at entry (R3/R5): membership and the peer-supplied
        // name are attacker-chosen, displayed, re-gossiped to every slot, and (adopted wholesale
        // when we have no mesh yet) become OUR descriptor.
        guard descriptor.members.count <= Self.maxMeshMembers else {
            FernletAuditLog.log("mesh.descriptor.droppedOversizedMembership")
            return
        }
        // P3 item 6, plan §8.2: a mesh this device developed, left or saw terminated is never
        // re-entered, so its descriptor is not adopted or merged — not even after a relaunch, which
        // re-derives the bar from the sealed context.
        if let reason = rejoinRefusal(for: descriptor.meshID) {
            FernletAuditLog.log("mesh.descriptor.droppedRejoinBarred", context: ["reason": reason.rawValue])
            return
        }
        let incoming = Self.sanitizedDescriptor(descriptor)
        if let existing = currentMesh {
            mergeMeshDescriptor(existing, incoming: incoming)
        } else {
            currentMesh = incoming
        }
        isSessionOpen = currentMesh?.mode == .open
        let localFP = identity.localFingerprint
        if let mesh = currentMesh, !mesh.members.contains(where: { $0.fingerprint == localFP }) {
            sendAdmissionRequest(for: mesh)
        }
    }

    /// Coerces a peer-supplied descriptor into safe display shape before it is adopted, merged, or
    /// re-gossiped: capped name, moderated member display names, and last-write-wins timestamps
    /// clamped to the near future so a far-future stamp cannot win LWW forever (R3/R5).
    private static func sanitizedDescriptor(_ descriptor: MeshDescriptor) -> MeshDescriptor {
        let maxStamp = Date().addingTimeInterval(60)
        return MeshDescriptor(
            meshID: descriptor.meshID,
            name: String(ItemNameModeration.sanitizedName(descriptor.name).prefix(maxMeshNameLength)),
            mode: descriptor.mode,
            members: descriptor.members.prefix(maxMeshMembers).map { member in
                MeshMember(
                    fingerprint: member.fingerprint,
                    displayName: ItemNameModeration.moderatedPeerDisplayName(member.displayName),
                    signingPublicKey: member.signingPublicKey,
                    keyAgreementPublicKey: member.keyAgreementPublicKey,
                    joinedAt: member.joinedAt
                )
            },
            nameSetAt: min(descriptor.nameSetAt, maxStamp),
            nameSetBy: descriptor.nameSetBy,
            modeSetAt: min(descriptor.modeSetAt, maxStamp),
            modeSetBy: descriptor.modeSetBy,
            createdAt: descriptor.createdAt
        )
    }

    private func mergeMeshDescriptor(_ existing: MeshDescriptor, incoming: MeshDescriptor) {
        guard existing.meshID == incoming.meshID else { return }
        var merged = existing
        if incoming.nameSetAt > existing.nameSetAt {
            merged.name = incoming.name
            merged.nameSetAt = incoming.nameSetAt
            merged.nameSetBy = incoming.nameSetBy
        }
        if incoming.modeSetAt > existing.modeSetAt {
            merged.mode = incoming.mode
            merged.modeSetAt = incoming.modeSetAt
            merged.modeSetBy = incoming.modeSetBy
        }
        // Stop appending at the membership cap (R3): the incoming list is attacker-chosen and the
        // merged result is displayed, counted, and re-gossiped to every slot.
        for member in incoming.members
        where !removedMemberFingerprints.contains(member.fingerprint)
            && !merged.members.contains(where: { $0.signingPublicKey == member.signingPublicKey })
            && merged.members.count < Self.maxMeshMembers {
            merged.members.append(member)
        }
        currentMesh = merged
    }

    private func broadcastMeshDescriptor() {
        guard let mesh = currentMesh else { return }
        let payload = MeshStateChangePayload(descriptor: mesh)
        for slot in slots {
            Task { [weak self] in await self?.sendEnvelope(.meshDescriptor, encodable: payload, via: slot) }
        }
        updateDiscoveryInfo()
    }

    private func sendMeshDescriptor(to slot: PeerSlot) async {
        guard let mesh = currentMesh else { return }
        await sendEnvelope(.meshDescriptor, encodable: MeshStateChangePayload(descriptor: mesh), via: slot)
    }

    // MARK: - Admission

    private func sendAdmissionRequest(for mesh: MeshDescriptor) {
        let request = MeshAdmissionRequestPayload(
            meshID: mesh.meshID,
            requesterFingerprint: identity.localFingerprint,
            requesterDisplayName: displayName,
            requesterSigningPublicKey: identity.localSigningPublicKey,
            requesterKeyAgreementPublicKey: identity.localKeyAgreementPublicKey
        )
        for slot in slots {
            // Record what we asked for, on the slot we asked it on: `handleAdmissionGrant` accepts
            // a grant ONLY as the answer to this. Bounded by the slot cap (R3).
            if outstandingAdmissionRequestBySlot.count < Self.maxOutstandingAdmissionRequests
                || outstandingAdmissionRequestBySlot[slot.id] != nil {
                outstandingAdmissionRequestBySlot[slot.id] = mesh.meshID
            }
            Task { [weak self] in await self?.sendEnvelope(.meshAdmissionRequest, encodable: request, via: slot) }
        }
    }

    // MARK: - Member removal voting

    private func handleRemovalProposal(_ proposal: MeshRemovalProposalPayload, rebroadcast: Bool) {
        guard proposal.expiresAt > Date() else { return }
        // Prune expired proposals so they cannot accumulate, then bound growth: dedup is by a
        // sender-controlled id, so without a cap a connected peer could spam unlimited distinct
        // proposals into this observed array (driving UI + memory). One active proposal per
        // proposer, plus a hard total cap as the spoofed-fingerprint backstop.
        pendingRemovalProposals.removeAll { $0.expiresAt <= Date() }
        guard !pendingRemovalProposals.contains(where: { $0.id == proposal.id }) else { return }
        guard !pendingRemovalProposals.contains(where: { $0.proposerFingerprint == proposal.proposerFingerprint }) else { return }
        guard pendingRemovalProposals.count < Self.maxPendingRemovalProposals else { return }
        pendingRemovalProposals.append(proposal)
        if rebroadcast {
            broadcastEnvelope(.meshRemovalProposal, encodable: proposal)
        }
    }

    private func handleRemovalSecond(
        _ second: MeshRemovalSecondPayload,
        senderFingerprint: String?,
        rebroadcast: Bool
    ) {
        let proposal = second.proposal
        guard second.seconderFingerprint == senderFingerprint else { return }
        guard second.seconderFingerprint != proposal.targetFingerprint else { return }
        guard proposal.proposerFingerprint != second.seconderFingerprint else { return }
        guard proposal.expiresAt > Date() else { return }
        // R3: both removal sets are keyed by wire-supplied values and live for the whole session.
        guard approvedRemovalProposalIDs.count < Self.maxRecordedRemovals else { return }
        guard approvedRemovalProposalIDs.insert(proposal.id).inserted else { return }
        handleRemovalProposal(proposal, rebroadcast: false)
        if rebroadcast {
            broadcastEnvelope(.meshRemovalSecond, encodable: second)
        }
        applyApprovedRemoval(proposal)
    }

    private func applyApprovedRemoval(_ proposal: MeshRemovalProposalPayload) {
        pendingRemovalProposals.removeAll { $0.id == proposal.id }
        if removedMemberFingerprints.count < Self.maxRecordedRemovals {
            removedMemberFingerprints.insert(proposal.targetFingerprint)
        }
        // A voted-out peer must never be offered by the keep-as-friend prompt: purge them from
        // the live roster and from any unconsumed promoted batch (belt-and-braces — promotion
        // normally happens after this purge).
        sessionRoster.removeAll { $0.fingerprint == proposal.targetFingerprint }
        if var batch = pendingFriendReview {
            batch.entries.removeAll { $0.fingerprint == proposal.targetFingerprint }
            pendingFriendReview = batch.entries.isEmpty ? nil : batch
        }

        if proposal.targetFingerprint == identity.localFingerprint {
            leaveSession()
            return
        }
        if let slot = slots.first(where: { $0.fingerprint == proposal.targetFingerprint }) {
            disconnectSlot(slot)
        }
        // Plan §8.3: a completed removal is a roster change, so it rotates the group key at once
        // rather than letting the voted-out member keep it until the next 15-minute tick. The
        // record is minted first so the rotation's exclusion rule can see it.
        emitApprovedRemovalRecord(proposal)
        requestRotation(cause: .membership)
        if var mesh = currentMesh {
            mesh.members.removeAll { $0.fingerprint == proposal.targetFingerprint }
            currentMesh = mesh
            broadcastMeshDescriptor()
        }
    }

    private func broadcastEnvelope(_ type: PayloadType, encodable: some Encodable) {
        for slot in slots {
            Task { [weak self] in
                await self?.sendEnvelope(type, encodable: encodable, via: slot)
            }
        }
    }

    private func handleAdmissionRequest(_ request: MeshAdmissionRequestPayload,
                                        senderFingerprint: String?,
                                        senderSigningPublicKey: Data?) {
        guard let mesh = currentMesh, mesh.meshID == request.meshID else { return }
        guard !mesh.members.contains(where: { $0.signingPublicKey == request.requesterSigningPublicKey }) else { return }
        // Reject requests whose claimed fingerprint or signing key don't match the authenticated sender.
        guard let senderFP = senderFingerprint, senderFP == request.requesterFingerprint else { return }
        if let senderKey = senderSigningPublicKey {
            guard senderKey == request.requesterSigningPublicKey else { return }
        }
        // Bind key ↔ fingerprint UNCONDITIONALLY (R5): pre-commit the slot has no verified signing
        // key, so without this a peer whose pending fingerprint matches could append one row per
        // bogus signing key it invents. Dedup on the fingerprint too, and cap the queue (R3).
        //
        // DELIBERATE PRE-COMMIT EXCEPTION: `.meshAdmissionRequest` is the ONE member-family payload
        // accepted from an uncommitted slot — asking to join is precisely what a peer does before
        // it commits, so `dispatchMembershipPayload` does not gate it the way it gates
        // `.meshDescriptor`. Do NOT "fix" that asymmetry by symmetry: the binding, dedup and queue
        // cap below are what make pre-commit acceptance safe, and gating it would break every join.
        guard IdentityService.fingerprintsMatch(
            IdentityService.fingerprint(of: request.requesterSigningPublicKey),
            request.requesterFingerprint
        ) else {
            FernletAuditLog.log("mesh.admissionRequest.droppedKeyFingerprintMismatch")
            return
        }
        guard pendingAdmissionRequests.count < Self.maxPendingAdmissionRequests else {
            FernletAuditLog.log("mesh.admissionRequest.droppedQueueFull")
            return
        }
        let isKnown = pendingAdmissionRequests.contains {
            $0.requesterSigningPublicKey == request.requesterSigningPublicKey
                || $0.requesterFingerprint == request.requesterFingerprint
        }
        if !isKnown {
            // Wire boundary: `requesterDisplayName` is peer-supplied and reaches the ADMISSION
            // PROMPT — the one screen where the user decides to admit a stranger. Sanitize HERE
            // (control/zero-width/bidi scalars out, 24-char cap) so neither the prompt nor the
            // admitter's roster can be spoofed by a homoglyph or reversed by an RLO override.
            // Safe to rebuild the payload: `allowAdmission`/`declineAdmission` match on
            // `requesterSigningPublicKey`, never on the name, so dedup and removal are unaffected.
            pendingAdmissionRequests.append(MeshAdmissionRequestPayload(
                meshID: request.meshID,
                requesterFingerprint: request.requesterFingerprint,
                requesterDisplayName: ItemNameModeration.moderatedPeerDisplayName(request.requesterDisplayName),
                requesterSigningPublicKey: request.requesterSigningPublicKey,
                requesterKeyAgreementPublicKey: request.requesterKeyAgreementPublicKey
            ))
        }
    }

    /// Authorizes an inbound admission grant against state we can vouch for LOCALLY.
    ///
    /// The token itself proves only that somebody minted it: `admitterSigningPublicKey` is the
    /// token's own root, so a self-signed token from a total stranger verifies. Three independent
    /// checks close that: the grant must answer a request WE sent on THIS slot, the admitter must
    /// be the authenticated sender of the envelope that carried it, and — once we have a mesh —
    /// a current member of it. Returns false with an audit entry, never silently.
    private func admissionGrantIsAuthorized(_ grant: MeshAdmissionGrantPayload,
                                            slot: PeerSlot?,
                                            senderSigningPublicKey: Data?) -> Bool {
        guard let slot, let senderKey = senderSigningPublicKey else {
            FernletAuditLog.log("mesh.admissionGrant.droppedUnattributed")
            return false
        }
        guard outstandingAdmissionRequestBySlot[slot.id] == grant.meshID else {
            FernletAuditLog.log("mesh.admissionGrant.droppedUnsolicited")
            return false
        }
        guard grant.token.admitterSigningPublicKey == senderKey else {
            FernletAuditLog.log("mesh.admissionGrant.droppedAdmitterNotSender")
            return false
        }
        if let mesh = currentMesh {
            guard mesh.members.contains(where: { $0.signingPublicKey == senderKey }) else {
                FernletAuditLog.log("mesh.admissionGrant.droppedAdmitterNotMember")
                return false
            }
        }
        return true
    }

    private func handleAdmissionGrant(_ grant: MeshAdmissionGrantPayload,
                                      slot: PeerSlot?,
                                      senderSigningPublicKey: Data?) {
        guard currentMesh == nil || currentMesh?.meshID == grant.meshID else { return }
        // P3 item 6, plan §8.2: a developed or terminated mesh can never be rejoined, and the bar
        // is re-derived from the sealed context at launch, so a restart does not lift it.
        if let reason = rejoinRefusal(for: grant.meshID) {
            FernletAuditLog.log("mesh.admissionGrant.droppedRejoinBarred", context: ["reason": reason.rawValue])
            return
        }
        guard admissionGrantIsAuthorized(grant, slot: slot, senderSigningPublicKey: senderSigningPublicKey) else {
            return
        }
        // Bind the signed token.meshID to the mesh being joined so a valid token for another
        // mesh cannot be wrapped in a grant claiming this one (grant.meshID is unsigned), and bind
        // the token's admitter root to the authenticated sender so a self-signed token is inert.
        do {
            try grant.token.verify(joinerSigningPublicKey: identity.localSigningPublicKey,
                                   expectedMeshID: grant.meshID,
                                   expectedAdmitterSigningPublicKey: senderSigningPublicKey)
        } catch {
            FernletAuditLog.log("mesh.admissionGrant.droppedTokenVerifyFailed")
            return
        }

        // A negative epoch is malformed wire input and would poison every later epoch comparison.
        guard grant.currentKeyEpoch >= 0 else { return }
        // Epochs only move FORWARD, exactly as `handleKeyRotation` requires — otherwise a grant
        // replaying an old epoch would roll a joined member back onto a retired key.
        guard grant.currentKeyEpoch > (currentGroupKey?.epoch ?? -1),
              grant.currentKeyEpoch >= localJoinedEpoch else {
            FernletAuditLog.log("mesh.admissionGrant.droppedStaleEpoch")
            return
        }
        // P3 item 6, plan §3.6: the admission is verified, so the context is written BEFORE this
        // device adopts the epoch, unwraps the key or starts a beacon — before, in other words,
        // anything tells the user or the peers that it has joined.
        guard recordVerifiedAdmissionDurably() else { return }

        // Single use: the request it answered is now spent.
        if let slot { outstandingAdmissionRequestBySlot.removeValue(forKey: slot.id) }

        // Phase 3: unwrap the group key if one was included.
        if let bundle = grant.encryptedCurrentKey,
           let keyData = unwrappedAdmissionGrantKey(bundle) {
            let newKey = MeshGroupKey(epoch: grant.currentKeyEpoch, keyBytes: keyData, activeSince: Date())
            currentGroupKey = newKey
            // The joiner names the epoch from the roster it just joined — the same deterministic
            // coordinator every member of that branch computes (plan §8.4).
            if let ref = epochRef(
                counter: grant.currentKeyEpoch, coordinatorFingerprint: epochCoordinatorFingerprint
            ) {
                adoptEpoch(ref, key: newKey)
            }
            localJoinedEpoch = grant.currentKeyEpoch
            recordEpoch(grant.currentKeyEpoch, since: newKey.activeSince)
        } else {
            // No key included — adopt the grant's epoch, which the monotonicity guard above has
            // already proved never decreases. Resetting to 0 here let any keyless grant rewind the
            // `localJoinedEpoch` manifest filter and re-open retired epochs.
            localJoinedEpoch = grant.currentKeyEpoch
        }
        startBeaconLoop()
    }

    // MARK: - Photo handling

    /// Coerces a peer-supplied photo payload before it reaches the PERSISTENT wall cache (R3/R5):
    /// moderated sender name, moderated + capped session participants, capped mesh name. The
    /// caller has already validated that the image half matches the claimed epoch.
    private static func sanitizedIncomingPhoto(_ payload: FriendPhotoPayload) -> FriendPhotoPayload {
        let session = payload.session.map { metadata in
            FriendPhotoSessionMetadata(
                id: metadata.id,
                meshID: metadata.meshID,
                meshName: metadata.meshName.map {
                    String(ItemNameModeration.sanitizedName($0).prefix(maxMeshNameLength))
                },
                startedAt: metadata.startedAt,
                participants: metadata.participants.prefix(maxMeshMembers).map {
                    FriendPhotoSessionParticipant(
                        fingerprint: $0.fingerprint,
                        displayName: ItemNameModeration.moderatedPeerDisplayName($0.displayName)
                    )
                }
            )
        }
        let senderName = ItemNameModeration.moderatedPeerDisplayName(payload.senderName)
        if let encryptedImageData = payload.encryptedImageData, let nonce = payload.nonce,
           payload.keyEpoch > 0 {
            return FriendPhotoPayload(
                id: payload.id,
                encryptedImageData: encryptedImageData,
                nonce: nonce,
                keyEpoch: payload.keyEpoch,
                addedAt: payload.addedAt,
                senderName: senderName,
                senderFingerprint: payload.senderFingerprint,
                senderSigningPublicKey: payload.senderSigningPublicKey,
                session: session
            )
        }
        guard let imageData = payload.imageData else { return payload }
        return FriendPhotoPayload(
            id: payload.id,
            imageData: imageData,
            addedAt: payload.addedAt,
            senderName: senderName,
            senderFingerprint: payload.senderFingerprint,
            senderSigningPublicKey: payload.senderSigningPublicKey,
            session: session
        )
    }

    private func cachePhoto(_ photo: FriendPhotoPayload, includeInSession: Bool = false) {
        guard !meshPhotos.contains(where: { $0.id == photo.id }) else { return }
        let cachedPhoto = includeInSession ? photo.withSession(currentPhotoSessionMetadata()) : photo
        meshPhotos.insert(cachedPhoto.withoutImageData(), at: 0)
        // Metadata-only entries (no image bytes), so the in-memory list can mirror the disk cap.
        // Keeping it at the spec's 1000 makes the FIFO cap and the 900-photo soft-warning real;
        // the full-resolution bytes stay on disk and rehydrate on demand.
        let evictedByCap = meshPhotos.count > PrivateMediaStore.maxCachedPhotos
        meshPhotos = Array(meshPhotos.prefix(PrivateMediaStore.maxCachedPhotos))
        persistPhotoIndex(meshPhotos.map { $0.id == cachedPhoto.id ? cachedPhoto : $0 })
        if evictedByCap { prunePhotoWallPreferences() }
        if includeInSession {
            // Store metadata only; the full-resolution bytes were just persisted to the disk
            // cache above and are rehydrated on demand (see sendRequestedPhotos / imageData()).
            // Retaining raw bytes here grew unbounded in memory for the whole session.
            sessionPhotos.insert(cachedPhoto.withoutImageData(), at: 0)
            sessionPhotos = Array(sessionPhotos.prefix(Self.maxSessionPhotos))
        }
    }

    /// Enforces a per-authenticated-peer cap on *incoming* photos for the current mesh
    /// session and records acceptance. Resets when the mesh changes. Returns false once a
    /// peer has contributed `maxPhotosPerSenderPerSession` distinct photos; re-sends of an
    /// already-accepted ID are allowed so legitimate manifest re-sync is not dropped.
    private func allowIncomingPhoto(_ photoID: UUID, from authenticatedFingerprint: String?) -> Bool {
        if currentMesh?.meshID != receiveQuotaMeshID {
            receiveQuotaMeshID = currentMesh?.meshID
            receivedPhotoIDsByFingerprint.removeAll()
        }
        let key = authenticatedFingerprint ?? ""
        var accepted = receivedPhotoIDsByFingerprint[key, default: []]
        if accepted.contains(photoID) { return true }
        guard accepted.count < Self.maxPhotosPerSenderPerSession else { return false }
        accepted.insert(photoID)
        receivedPhotoIDsByFingerprint[key] = accepted
        return true
    }

    public func imageData(for photo: FriendPhotoPayload) -> Data? {
        photoCacheStore.imageData(for: photo)
    }

    public func thumbnailData(for photo: FriendPhotoPayload) -> Data? {
        photoCacheStore.thumbnailData(for: photo)
    }

    public func thumbnailData(forPhotoID photoID: UUID) -> Data? {
        guard let photo = meshPhotos.first(where: { $0.id == photoID }) else { return nil }
        return thumbnailData(for: photo)
    }

    public func hydratedPhotos(_ photos: [FriendPhotoPayload]) -> [FriendPhotoPayload] {
        photos.compactMap { photoCacheStore.hydrated($0) }
    }

    public func favoritePhotoID(for post: FriendPhotoWallPost) -> UUID? {
        _ = favoritesRevision  // observe favorite toggles so the heart re-renders (see favoritesRevision)
        guard let sessionID = post.session?.id else { return nil }
        return photoWallPreferences.favoritePhotoIDsBySession[sessionID]
    }

    /// Every photo the user has hearted (favorited), flattened from the per-session favorite map into one
    /// global id set. Read-only: the home photowall reads this to weight hearted photos higher in its
    /// rotation. Touches `favoritesRevision` so an observing surface re-picks when a favorite toggles, but
    /// NEVER mutates preferences — the `@ObservationIgnored` constraint on `photoWallPreferences` holds.
    public var allFavoritePhotoIDs: Set<UUID> {
        _ = favoritesRevision
        return Set(photoWallPreferences.favoritePhotoIDsBySession.values)
    }

    public func toggleFavorite(photoID: UUID, in post: FriendPhotoWallPost) {
        guard let sessionID = post.session?.id else { return }
        if photoWallPreferences.favoritePhotoIDsBySession[sessionID] == photoID {
            photoWallPreferences.favoritePhotoIDsBySession.removeValue(forKey: sessionID)
        } else {
            photoWallPreferences.favoritePhotoIDsBySession[sessionID] = photoID
        }
        favoritesRevision &+= 1  // notify observers of favoritePhotoID(for:) / photoWallPosts
        persistPhotoWallPreferences()
    }

    public var photoWallPosts: [FriendPhotoWallPost] {
        _ = favoritesRevision  // read-only: re-render the wall cover when a favorite toggles; NEVER bump here
        progressivelyAggregatePhotoSessions()
        return makePhotoWallPosts()
    }

    public var savedPhotoSessions: [FriendPhotoSessionMetadata] {
        Dictionary(grouping: meshPhotos.compactMap(\.session), by: \.id)
            .compactMap { $0.value.first }
            .sorted { $0.startedAt > $1.startedAt }
    }

    private func currentPhotoSessionMetadata() -> FriendPhotoSessionMetadata {
        let sessionID = activePhotoSessionID ?? UUID()
        let startedAt = photoSessionStartedAt ?? Date()
        let previousMetadata = sessionPhotos.first(where: { $0.session?.id == sessionID })?.session
        activePhotoSessionID = sessionID
        photoSessionStartedAt = startedAt
        let participants = (previousMetadata?.participants ?? []) + sessionParticipants.map {
            FriendPhotoSessionParticipant(fingerprint: $0.fingerprint, displayName: $0.displayName)
        }
        return FriendPhotoSessionMetadata(
            id: sessionID,
            meshID: currentMesh?.meshID ?? previousMetadata?.meshID,
            meshName: currentMesh?.name ?? previousMetadata?.meshName,
            startedAt: startedAt,
            participants: participants.reduce(into: []) { result, participant in
                if !result.contains(where: { $0.fingerprint == participant.fingerprint }) {
                    result.append(participant)
                }
            }
        )
    }

    private func finalizeCurrentPhotoSessionMetadata() {
        guard activePhotoSessionID != nil, !sessionPhotos.isEmpty else { return }
        let metadata = currentPhotoSessionMetadata()
        meshPhotos = meshPhotos.map { photo in
            photo.session?.id == metadata.id ? photo.withSession(metadata) : photo
        }
        sessionPhotos = sessionPhotos.map { $0.withSession(metadata) }
    }

    private func progressivelyAggregatePhotoSessions() {
        var posts = makePhotoWallPosts()
        var didChange = false
        // R2: both terminators are in the condition — the wall is below the post cap, or there is
        // no unaggregated session left (each iteration aggregates exactly one of a finite set).
        while posts.count >= Self.maxUnaggregatedWallPosts, let candidate = newestUnaggregatedSession() {
            photoWallPreferences.aggregatedSessionIDs.insert(candidate.id)
            if photoWallPreferences.coverPhotoIDsBySession[candidate.id] == nil,
               let coverID = photos(in: candidate.id).randomElement()?.id {
                photoWallPreferences.coverPhotoIDsBySession[candidate.id] = coverID
            }
            didChange = true
            posts = makePhotoWallPosts()
        }
        if didChange {
            persistPhotoWallPreferences()
        }
    }

    private func makePhotoWallPosts() -> [FriendPhotoWallPost] {
        var posts: [FriendPhotoWallPost] = []
        var emittedSessionIDs: Set<UUID> = []
        for photo in meshPhotos.sorted(by: { $0.addedAt > $1.addedAt }) {
            guard let session = photo.session,
                  photoWallPreferences.aggregatedSessionIDs.contains(session.id) else {
                posts.append(FriendPhotoWallPost(id: photo.id, session: photo.session, photos: [photo], coverPhoto: photo))
                continue
            }
            guard emittedSessionIDs.insert(session.id).inserted else { continue }
            let sessionPhotos = photos(in: session.id)
            let coverID = photoWallPreferences.favoritePhotoIDsBySession[session.id]
                ?? photoWallPreferences.coverPhotoIDsBySession[session.id]
            // `sessionPhotos.first` rather than `[0]` (R5: no trapping subscript) — `photo` is the
            // element being iterated and always belongs to this session, so it is a valid cover.
            let coverPhoto = sessionPhotos.first(where: { $0.id == coverID }) ?? sessionPhotos.first ?? photo
            posts.append(FriendPhotoWallPost(id: session.id, session: session, photos: sessionPhotos, coverPhoto: coverPhoto))
        }
        return posts
    }

    private func newestUnaggregatedSession() -> FriendPhotoSessionMetadata? {
        savedPhotoSessions
            .filter { !photoWallPreferences.aggregatedSessionIDs.contains($0.id) }
            .filter { photos(in: $0.id).count > 1 }
            .max { $0.startedAt < $1.startedAt }
    }

    private func photos(in sessionID: UUID) -> [FriendPhotoPayload] {
        meshPhotos
            .filter { $0.session?.id == sessionID }
            .sorted { $0.addedAt < $1.addedAt }
    }

    private func persistPhotoWallPreferences() {
        photoWallPreferencesStore.save(photoWallPreferences)
    }

    private func isPhotoFromCurrentSession(_ photo: FriendPhotoPayload) -> Bool {
        photoSessionStartedAt != nil && photo.session != nil
    }

    private func syncPhotoManifest(to slot: PeerSlot) async {
        let entries = sessionPhotos.map { photo in
            FriendPhotoManifestEntry(
                id: photo.id,
                senderFingerprint: photo.senderFingerprint ?? identity.localFingerprint,
                keyEpoch: photo.keyEpoch
            )
        }
        let payload = FriendPhotoManifestPayload(entries: entries)
        if currentMesh?.mode == .closed, currentGroupKey != nil {
            await sendEncryptedMetadata(.friendPhotoManifest, encodable: payload, via: slot)
        } else {
            await sendEnvelope(.friendPhotoManifest, encodable: payload, via: slot)
        }
    }

    private func handlePhotoManifest(_ manifest: FriendPhotoManifestPayload, from slot: PeerSlot) {
        // The manifest is unbounded wire input and every unknown id is reflected back inside a
        // request payload, so an oversize manifest is an amplification lever (R3/R5).
        guard manifest.entries.count <= Self.maxSessionPhotos else {
            FernletAuditLog.log("mesh.photoManifest.droppedOversized")
            return
        }
        // The entry filter below already skips a blocked AUTHOR; this is the reciprocal check on
        // the RELAYER, so a blocked peer cannot drive our request traffic at all.
        guard !store.isBlockedFingerprint(slot.fingerprint ?? "") else {
            FernletAuditLog.log("mesh.photoManifest.droppedBlockedRelayer")
            return
        }
        let haveIDs = Set(meshPhotos.map { $0.id })
        let announced = manifest.entries
            .filter { !store.isBlockedFingerprint($0.senderFingerprint) }
            .prefix(Self.maxSessionPhotos)
        // Remember the authors we accepted here so a legitimately relayed photo whose author has
        // not yet reached our descriptor or roster is still attributable (R3: bounded above).
        for entry in announced where manifestAnnouncedPhotoAuthors.count < Self.maxSessionPhotos {
            manifestAnnouncedPhotoAuthors.insert(entry.senderFingerprint)
        }
        let missing = announced
            .filter { !haveIDs.contains($0.id) }
            .filter { $0.keyEpoch >= localJoinedEpoch }   // epoch guard: skip photos we can't decrypt
            .map(\.id)
            .prefix(Self.maxSessionPhotos)
        guard !missing.isEmpty else { return }
        Task { [weak self] in
            guard let self else { return }
            let req = FriendPhotoRequestPayload(missingPhotoIDs: Array(missing))
            if self.currentMesh?.mode == .closed, self.currentGroupKey != nil {
                await self.sendEncryptedMetadata(.friendPhotoRequest, encodable: req, via: slot)
            } else {
                await self.sendEnvelope(.friendPhotoRequest, encodable: req, via: slot)
            }
        }
    }

    /// Answers a peer's request for missing session photos.
    ///
    /// R3: the id list is unbounded wire input and each hydrated photo pulls full-resolution bytes
    /// off disk, so the request is rejected above the session cap, matched through a `Set`, and
    /// sent SEQUENTIALLY from ONE task per request (previously one task per photo, with no
    /// per-slot dedupe — a peer could re-request the whole session in a loop). At most one
    /// send run per slot is in flight; a second request while one is running is dropped.
    private func sendRequestedPhotos(_ ids: [UUID], to slot: PeerSlot) {
        guard ids.count <= Self.maxSessionPhotos else {
            FernletAuditLog.log("mesh.photoRequest.droppedOversized")
            return
        }
        guard photoSendsInFlight.insert(slot.id).inserted else {
            FernletAuditLog.log("mesh.photoRequest.droppedSendInFlight")
            return
        }
        let wanted = Set(ids)
        let requested = sessionPhotos.filter { wanted.contains($0.id) }.compactMap { photoCacheStore.hydrated($0) }
        Task { [weak self] in
            defer { self?.photoSendsInFlight.remove(slot.id) }
            for photo in requested {
                await self?.sendEnvelope(.friendPhoto, encodable: photo, via: slot, sealed: true)
            }
        }
    }

    // MARK: - Clothing shop (Phase 3a)

    /// The per-commit shop hook, called from `onSlotConnected` for every slot commit. Two jobs:
    ///
    /// 1. **Session formation** (spec: "'Next session start' = first slot COMMIT, not search start"):
    ///    the FIRST commit after a no-session state is when the previous post-session window closes
    ///    and its catalogs drop — startJoin/startNewMesh must never do this (they fire on every
    ///    Social-tab entry / scene dip). `hasFormedShopSession` makes the reset once-per-formation:
    ///    later commits (including promoteToMesh's, which re-enter via onSlotConnected's fingerprint
    ///    transition) and a mid-session re-handshake of the sole committed slot can't wipe catalogs.
    ///    This also covers the transient-drop case: last slot lost mid-outing opens the window; a
    ///    re-commit lands here, closes it, clears catalogs, and the exchange re-runs.
    /// 2. **Catalog offer** — send our catalog once per slot, pairwise sealed (the same sendEnvelope
    ///    path photos use; `slot.verifiedKeyAgreementPublicKey` was set just before onSlotConnected),
    ///    capability-gated, nil provider (sharing off) sends nothing — PLUS a
    ///    `clothingCatalogRequest` for the peer's catalog: our send fires at OUR commit, but the
    ///    peer's registry gate requires the PEER's commit, so a slightly-later committer would drop
    ///    our catalog forever under once-per-slot tracking. The request, sent at its own commit,
    ///    makes the exchange commit-order-independent (spec: "Catalog delivery must not assume
    ///    commit symmetry").
    ///
    /// Internal seam so unit tests can drive a slot commit without a live handshake.
    func noteSlotCommittedForShop(slot: PeerSlot, identity peerIdentity: ProximityCoordinator.PeerIdentity) {
        // Phase 5: this committed friend is physically present — feed closeness (day-capped downstream).
        onFriendSessionCommitted?(peerIdentity.fingerprint)
        if !hasFormedShopSession {
            hasFormedShopSession = true
            clothingShop.beginNewSession()
            // Phase 5: a NEW session forms with an empty transcript. Messages already cleared at the
            // prior session end; this is belt-and-braces and covers the transient-drop → re-commit case.
            sessionMessages.clear()
            sentShopCatalogSlotIDs.removeAll()
            shopCatalogRequestResponseAt.removeAll()
        }
        if shouldOfferShopCatalog(to: peerIdentity), sentShopCatalogSlotIDs.insert(slot.id).inserted {
            Task { [weak self] in
                await self?.sendShopCatalog(to: slot)
                await self?.sendShopCatalogRequest(to: slot)
            }
        }
        // Phase 3b: hand our own signed moderation reports to this committed friend (one-hop relay).
        // The send method additionally requires the recipient be a vault-trusted (kept) friend.
        if peerIdentity.supports(.moderation) {
            let recipientKey = peerIdentity.signingPublicKey
            Task { [weak self] in await self?.sendModerationReports(to: slot, recipientSigningKey: recipientKey) }
        }
        // Phase 4: share our fuzzy vibe + appearance with this committed friend (kept friends only).
        if peerIdentity.supports(.friendState) {
            let recipientKey = peerIdentity.signingPublicKey
            Task { [weak self] in await self?.sendFriendState(to: slot, recipientSigningKey: recipientKey) }
        }
        // Phase 6: offer any activities we host to this committed peer + exchange a roster version digest
        // so the highest verified snapshot converges. The manager sends via its wired `send` closure.
        if peerIdentity.supports(.activities) {
            activities.onPeerCommitted(fingerprint: peerIdentity.fingerprint)
        }
    }

    /// Answers a verified `clothingCatalogRequest` from a committed, unblocked peer (the registry gate
    /// + handler already enforced both): re-send our catalog to that slot, BYPASSING the once-per-slot
    /// guard — idempotent, the receiver replaces by fingerprint. Rate-limited per slot so a hostile
    /// peer can't use requests as a send-amplification lever, and gated on the same sharing-enabled +
    /// capability checks as the commit-time offer.
    private func respondToShopCatalogRequest(
        fromVerifiedFingerprint fingerprint: String,
        identity peerIdentity: ProximityCoordinator.PeerIdentity?
    ) {
        guard let peerIdentity, shouldOfferShopCatalog(to: peerIdentity) else { return }
        guard let slot = slots.first(where: { $0.fingerprint == fingerprint }) else { return }
        let now = Date()
        if let last = shopCatalogRequestResponseAt[slot.id],
           now.timeIntervalSince(last) < MeshClothingShop.perSenderRateLimitSeconds {
            return
        }
        shopCatalogRequestResponseAt[slot.id] = now
        Task { [weak self] in await self?.sendShopCatalog(to: slot) }
    }

    /// Sends this device's current catalog to a committed slot, pairwise sealed. A nil provider
    /// result (sharing disabled, or the app never wired it) sends nothing — the payload-layer opt-out.
    private func sendShopCatalog(to slot: PeerSlot) async {
        guard let payload = clothingShop.localCatalogProvider?() else { return }
        onShopCatalogSendForTesting?(slot.id)
        await sendEnvelope(.clothingCatalog, encodable: payload, via: slot, sealed: true)
    }

    /// Asks a just-committed peer for its catalog (commit symmetry — see `noteSlotCommittedForShop`).
    /// Signed like every control payload but not sealed: it carries nothing (the summary is the whole
    /// body, mirroring `.sessionGoodbye`), and it is deliberately NOT in `sealingRequiredTypes`.
    private func sendShopCatalogRequest(to slot: PeerSlot) async {
        // DO NOT LOCALIZE "Clothing catalog request" — as the doc comment above says, the summary is
        // the whole body here, so this literal is signed wire bytes AND the receiving peer's
        // Inspector row. See `FernletIdentityEnvelope.payloadSummary`.
        await sendEnvelope(.clothingCatalogRequest, encodable: PayloadSummary(title: "Clothing catalog request"), via: slot)
        onShopCatalogRequestSendForTesting?(slot.id)
    }

    /// Phase 3a: the shop window opens at the same last-committed-slot-gone moment that promotes
    /// `pendingFriendReview` — call sites mirror `promoteRosterToPendingReviewIfSessionEnded()` exactly.
    /// The same moment ends the formed-session epoch: the NEXT slot commit is a new formation.
    private func openShopWindowIfSessionEnded() {
        guard !isInSession else { return }
        hasFormedShopSession = false
        clothingShop.openWindowAtSessionEnd()
    }

    // MARK: - Temporary messages (Phase 5)

    /// Send a live-session chat message to everyone in the room. Sanitizes + length-caps the text
    /// (`SessionMessageStore.sanitize`, 500-char cap), appends the local echo, then room-broadcasts it
    /// SEALED per slot to every ACTIVE committed slot advertising the `messages` capability — legacy /
    /// opted-out peers are skipped (they'd park-and-drop it anyway). No offline queue: a message only
    /// reaches peers currently in the session, and it vanishes at session end (`sessionMessages.clear`).
    public func sendTempMessage(_ rawText: String) {
        // The 13+ age gate. The compose bar is withheld below the line, so this is the defense-in-depth
        // re-check at the point of use rather than the primary gate.
        guard isChatAllowed else {
            FernletAuditLog.log("mesh.tempMessage.sendBlockedAgeGated")
            return
        }
        let text = SessionMessageStore.sanitize(rawText)
        guard !text.isEmpty else { return }
        let id = UUID()
        let now = Date()
        sessionMessages.appendOutgoing(
            id: id,
            senderFingerprint: identity.localFingerprint,
            senderDisplayName: displayName,
            text: text,
            sentAt: now
        )
        let payload = TempMessagePayload(id: id, text: text, sentAt: now)
        for slot in activeSlots where slot.fingerprint != nil && slot.supports(.messages) {
            onTempMessageSendForTesting?(slot.id)
            Task { [weak self] in
                await self?.sendEnvelope(.tempMessage, encodable: payload, via: slot, sealed: true)
            }
        }
    }

    /// Phase 5: messages VANISH at session end. Called at the same last-committed-slot-gone moment that
    /// promotes `pendingFriendReview` / opens the shop window — but where the shop KEEPS catalogs through
    /// a 1-hour window, the transcript is dropped immediately. Nothing to retain, nothing to sync.
    private func clearSessionMessagesIfSessionEnded() {
        guard !isInSession else { return }
        sessionMessages.clear()
        // TF b19 item 5: drop any lingering in-session heart feedback so a "Sending…" state can't
        // outlive the session that produced it.
        sessionHeartStateClearTask?.cancel()
        sessionHeartStateClearTask = nil
        sessionHeartState = .idle
        // The slots these claims named are gone; a stale claim would refuse the first heart of the
        // NEXT session (the deliver task's own `defer` never runs if its slot died mid-flight).
        sessionHeartSendsInFlight.removeAll()
    }

    // MARK: - Envelope sending

    /// Seal (optional) + sign + transmit a payload to a slot, best-effort.
    ///
    /// The failure is never silent — `sendEnvelopeCore` audit-logs EVERY failing stage — so this
    /// wrapper deliberately returns nothing (R7: no `@discardableResult` on a success/failure
    /// value). The one caller that must branch on the outcome uses
    /// ``sendEnvelopeReportingResult(_:encodable:via:sealed:)``.
    private func sendEnvelope(_ type: PayloadType, encodable: some Encodable, via slot: PeerSlot, sealed: Bool = false) async {
        _ = await sendEnvelopeReportingResult(type, encodable: encodable, via: slot, sealed: sealed)
    }

    /// Same send, returning whether the wire write succeeded — used by the in-session heart path
    /// (TF b19 item 5) for consume-on-send + sent/failed feedback. Never `@discardableResult`.
    private func sendEnvelopeReportingResult(
        _ type: PayloadType,
        encodable: some Encodable,
        via slot: PeerSlot,
        sealed: Bool = false
    ) async -> Bool {
        if sealed {
            guard let kaKey = slot.verifiedKeyAgreementPublicKey else { return false }
            return await sendEnvelopeCore(
                type,
                encodable: encodable,
                sealTo: (kaKey: kaKey, supportsWire2: slot.supports(.wire2)),
                fingerprint: slot.fingerprint,
                via: slot,
                auditSendFailure: true
            )
        }
        return await sendEnvelopeCore(
            type,
            encodable: encodable,
            sealTo: nil,
            fingerprint: slot.fingerprint,
            via: slot,
            auditSendFailure: true
        )
    }

    /// Shared seal+sign+send core behind `sendEnvelope` and `sendVerifyEnvelope`: encodes the
    /// payload, optionally seals it to `sealTo.kaKey` (wire2 or legacy per `sealTo.supportsWire2`;
    /// an empty key fails closed — a sealed request is never downgraded to an unsealed send),
    /// signs the envelope, and transmits it reliably on the slot channel. Returns whether the
    /// wire write succeeded; a send failure is audit-logged only when `auditSendFailure` is true
    /// (the pre-commit ceremony path swallows it silently, matching its historical behavior).
    private func sendEnvelopeCore(
        _ type: PayloadType,
        encodable: some Encodable,
        sealTo seal: (kaKey: Data, supportsWire2: Bool)?,
        fingerprint: String?,
        via slot: PeerSlot,
        auditSendFailure: Bool
    ) async -> Bool {
        // Every failing stage is NAMED (R7) — an encode/seal/sign failure used to return `false`
        // with no trace at ~30 call sites that ignore the result.
        guard let payloadData = try? JSONEncoder().encode(encodable) else {
            logSendFailure(type, stage: "encode")
            return false
        }
        let finalPayload: Data
        let encryption: PayloadEncryption
        if let seal {
            guard !seal.kaKey.isEmpty,
                  let ciphertext = try? identity.seal(
                      payloadData,
                      to: seal.kaKey,
                      format: seal.supportsWire2 ? .wire2 : .legacy
                  ) else {
                logSendFailure(type, stage: "seal")
                return false
            }
            finalPayload = ciphertext
            encryption = .sealedTo(recipientKeyAgreementPublicKey: seal.kaKey)
        } else {
            finalPayload = payloadData
            encryption = .none
        }
        guard let envelope = try? FernletIdentityEnvelope.signed(
            identityService: identity,
            senderDisplayName: displayName,
            recipientFingerprint: fingerprint,
            payloadType: type,
            payloadEncryption: encryption,
            // The mesh path deliberately uses the payload-type rawValue as the summary title rather
            // than prose — it is the ideal shape for localization later, because the receiver can map
            // this token to a `String(localized:)` label without the sender's locale entering the
            // signed bytes. DO NOT "improve" this into a friendly sentence, and never localize it.
            payloadSummary: PayloadSummary(title: type.rawValue),
            payload: finalPayload
        ) else {
            logSendFailure(type, stage: "sign")
            return false
        }
        guard let envelopeData = try? JSONEncoder().encode(envelope) else {
            logSendFailure(type, stage: "encodeEnvelope")
            return false
        }
        do {
            try await slot.channel.send(envelopeData, to: slot.peer, mode: .reliable)
            return true
        } catch {
            if auditSendFailure {
                FernletAuditLog.log("mesh.sendEnvelope.failed", context: ["type": type.rawValue, "error": error.localizedDescription])
            }
            return false
        }
    }

    /// One audit line per non-transport send failure, naming the stage that failed. Carries only
    /// the payload type — never payload content or peer identity.
    private func logSendFailure(_ type: PayloadType, stage: String) {
        FernletAuditLog.log(
            "mesh.sendEnvelope.failed",
            context: ["type": type.rawValue, "stage": stage]
        )
    }

    // MARK: - Delete-all

    /// Delete-all seam (bitchat adoptions Increment 1, Docs/PrivacyWipeCoverage.md): wipes the
    /// proximity identity keypairs + backup-escrow rows (this manager owns one of the three live
    /// `IdentityService` caches — presence and recipe share hold the others over the same
    /// keychain rows), removes the MC peer-identity archive, and drops the mesh photo cache's
    /// in-memory media key so a post-wipe write can't use the orphaned key. Breaks every trust
    /// relationship on purpose.
    ///
    /// The archive (`FernletPeerID.archive`) is the transport half of the same identity: the device
    /// name — in practice the user's own first name — and the stable `MCPeerID` every stable radio
    /// re-advertises. Kept, it would make a "brand-new Fernlet identity" recognizable on the air by
    /// exactly the identifier the keypair rotation above just retired. Cleared through a store
    /// pointed at the same default path `MeshMultipeerSession` loads from; the mint is lazy, so the
    /// next session to start gets a fresh one. Safe even if the friend radio is still up — the
    /// funnel stops the presence radio before this leg but not this one — because
    /// `MeshMultipeerSession.localPeerID` is a `let` resolved at init from an already-read archive:
    /// deleting the file cannot mutate or invalidate an `MCSession` that is running on it.
    ///
    /// Ordering: the archive clear runs FIRST — a keychain that refuses to delete must not leave the
    /// identifier behind too — but its own failure is carried to the end and thrown there, so a
    /// refusing file system cannot skip the keypair wipe or the media-key-cache drop.
    /// - Throws: ``IdentityError/keychainDeleteFailed(_:)`` when the keypair rows survive, or the
    ///   `FileManager` error when the peer-identity archive does — a wipe the user is told is
    ///   complete must not silently leave either behind.
    public func wipeIdentityForDeleteAll() throws {
        var archiveError: (any Error)?
        do {
            try FileMCPeerIDStore().clearForDeleteAll()
        } catch {
            archiveError = error
        }
        try identity.wipe()
        photoCacheStore.invalidateEncryptionKeyCache()
        guard let archiveError else { return }
        throw archiveError
    }

    // MARK: - Phase 3: Static encrypt / decrypt helpers

    /// Prefixes select a typed AEAD purpose without overloading an unauthenticated metadata field.
    /// They are REQUIRED on read: the old unprefixed blobs are no longer openable (Phase 4), and
    /// the markers now serve only to tell a current payload from one an older build sent.
    private static let groupPhotoFormatV2 = Data("FMGP2".utf8)
    private static let groupMetadataFormatV2 = Data("FMGM2".utf8)

    /// AES-256-GCM encrypt `imageData` using the group key.
    /// Returns (ciphertext + 16-byte tag, 12-byte nonce) stored separately in FriendPhotoPayload.
    public static func encryptPhoto(_ imageData: Data, key: MeshGroupKey) throws -> (ciphertext: Data, nonce: Data) {
        let symKey = SymmetricKey(data: key.keyBytes)
        let gcmNonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(
            imageData,
            using: symKey,
            nonce: gcmNonce,
            authenticating: FernletCryptoPurpose.AEAD.meshGroupPhotoV2.data
        )
        // `AES.GCM.Nonce` is a `Sequence` of `UInt8`, so the 12 bytes copy out without a pointer
        // seam (R9) — byte-identical to the previous `withUnsafeBytes` spelling.
        let nonce = Data(gcmNonce)
        var ciphertextWithTag = Self.groupPhotoFormatV2 + sealedBox.ciphertext
        ciphertextWithTag.append(sealedBox.tag)
        return (ciphertextWithTag, nonce)
    }

    /// The `FMGP2` marker is REQUIRED, not preferred. The pre-marker photo — opened with no AAD at
    /// all — was read here until the crypto standardization round's Phase 4; unmarked bytes are now
    /// refused as ``MeshEncryptionError/legacyWireFormat`` so a peer on an older build fails by name
    /// instead of failing as a generic decrypt error.
    public static func decryptPhoto(_ ciphertextWithTag: Data, nonce nonceData: Data, key: MeshGroupKey) throws -> Data {
        guard ciphertextWithTag.starts(with: Self.groupPhotoFormatV2) else {
            throw MeshEncryptionError.legacyWireFormat
        }
        let prefixLength = Self.groupPhotoFormatV2.count
        guard ciphertextWithTag.count > prefixLength + 16 else { throw MeshEncryptionError.decryptionFailed }
        let symKey = SymmetricKey(data: key.keyBytes)
        let gcmNonce = try AES.GCM.Nonce(data: nonceData)
        let ciphertext = ciphertextWithTag.dropFirst(prefixLength).dropLast(16)
        let tag = ciphertextWithTag.suffix(16)
        let box = try AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ciphertext, tag: tag)
        return try AES.GCM.open(
            box,
            using: symKey,
            authenticating: FernletCryptoPurpose.AEAD.meshGroupPhotoV2.data
        )
    }

    // Shared implementation used by closed-mode metadata wrapping.
    private static func encryptPayload(_ data: Data, key: MeshGroupKey) throws -> (ciphertext: Data, nonce: Data) {
        let symKey = SymmetricKey(data: key.keyBytes)
        let gcmNonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(
            data,
            using: symKey,
            nonce: gcmNonce,
            authenticating: FernletCryptoPurpose.AEAD.meshEncryptedMetadataV2.data
        )
        var ciphertext = Self.groupMetadataFormatV2 + sealedBox.ciphertext
        ciphertext.append(sealedBox.tag)
        return (ciphertext, Data(gcmNonce))
    }

    /// Mirror of ``decryptPhoto(_:nonce:key:)``: the `FMGM2` marker is required, and the pre-marker
    /// unauthenticated form is refused by name rather than opened (Phase 4).
    private static func decryptPayload(_ ciphertextWithTag: Data, nonce: Data, key: MeshGroupKey) throws -> Data {
        guard ciphertextWithTag.starts(with: Self.groupMetadataFormatV2) else {
            throw MeshEncryptionError.legacyWireFormat
        }
        let prefixLength = Self.groupMetadataFormatV2.count
        guard ciphertextWithTag.count > prefixLength + 16 else { throw MeshEncryptionError.decryptionFailed }
        let symKey = SymmetricKey(data: key.keyBytes)
        let gcmNonce = try AES.GCM.Nonce(data: nonce)
        let ciphertext = ciphertextWithTag.dropFirst(prefixLength).dropLast(16)
        let tag = ciphertextWithTag.suffix(16)
        let box = try AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ciphertext, tag: tag)
        return try AES.GCM.open(
            box,
            using: symKey,
            authenticating: FernletCryptoPurpose.AEAD.meshEncryptedMetadataV2.data
        )
    }

    // MARK: - Phase 3: Closed-mode metadata encryption

    /// Wraps any control payload in AES-256-GCM when the mesh is closed and a group key is established.
    private func sendEncryptedMetadata<T: Encodable>(
        _ payloadType: PayloadType,
        encodable: T,
        via slot: PeerSlot
    ) async {
        guard let key = currentGroupKey,
              let innerData = try? JSONEncoder().encode(encodable) else { return }
        let inner = EncryptedMetadataInner(payloadType: payloadType.rawValue, payload: innerData)
        guard let innerJSON = try? JSONEncoder().encode(inner) else {
            logSendFailure(payloadType, stage: "encodeEncryptedMetadata")
            return
        }
        let ciphertext: Data
        let nonce: Data
        do {
            (ciphertext, nonce) = try Self.encryptPayload(innerJSON, key: key)
        } catch {
            // Fail closed and NAMED (R7): closed-mode metadata is never downgraded to a plain send.
            FernletAuditLog.log(
                "mesh.encryptedMetadata.sealFailed",
                context: ["type": payloadType.rawValue, "error": String(describing: error)]
            )
            return
        }
        let wrapper = MeshEncryptedMetadataPayload(ciphertext: ciphertext, nonce: nonce, keyEpoch: key.epoch)
        await sendEnvelope(.meshEncryptedMetadata, encodable: wrapper, via: slot)
    }

    /// Decrypts a `meshEncryptedMetadata` wrapper and re-dispatches the inner payload.
    private func handleEncryptedMetadata(
        _ wrapper: MeshEncryptedMetadataPayload,
        from peer: ProximityCoordinator.PeerIdentity?,
        slot: PeerSlot
    ) async {
        guard wrapper.keyEpoch == currentGroupKey?.epoch, let key = currentGroupKey else { return }
        let plaintext: Data
        do {
            plaintext = try Self.decryptPayload(wrapper.ciphertext, nonce: wrapper.nonce, key: key)
        } catch MeshEncryptionError.legacyWireFormat {
            // Mirrors `mesh.encryptedMetadata.sealFailed` on the send side (R7): the one open
            // failure with a nameable cause is named, instead of joining the silent drop that also
            // covers a wrong key and a tampered wrapper.
            FernletAuditLog.log("mesh.encryptedMetadata.droppedLegacyWireFormat")
            return
        } catch {
            return
        }
        guard let inner = try? JSONDecoder().decode(EncryptedMetadataInner.self, from: plaintext),
              let innerType = PayloadType(rawValue: inner.payloadType) else { return }

        let data = inner.payload
        let decoder = JSONDecoder()
        switch innerType {
        case .meshDescriptor, .meshStateChange:
            if let payload = try? decoder.decode(MeshStateChangePayload.self, from: data) {
                handleMeshDescriptor(payload.descriptor, from: peer?.fingerprint)
            }
        case .friendPhotoManifest:
            if let payload = try? decoder.decode(FriendPhotoManifestPayload.self, from: data) {
                handlePhotoManifest(payload, from: slot)
            }
        case .friendPhotoRequest:
            if let payload = try? decoder.decode(FriendPhotoRequestPayload.self, from: data) {
                sendRequestedPhotos(payload.missingPhotoIDs, to: slot)
            }
        case .meshAdmissionGrant:
            if let payload = try? decoder.decode(MeshAdmissionGrantPayload.self, from: data) {
                // Same authorization binding as the plaintext dispatch at `handleInbound`: holding
                // the group key proves mesh membership, never the authority to admit, so an
                // encrypted-metadata wrapper must not become a way around the grant guards.
                handleAdmissionGrant(payload, slot: slot,
                                     senderSigningPublicKey: peer?.signingPublicKey)
            }
        default:
            break
        }
    }

    // MARK: - Phase 3: Coordinator election

    /// Returns true when the local device is the elected coordinator (lowest fingerprint among
    /// connected active-slot peers + self). Re-evaluated on every connect/disconnect.
    private func isLocalCoordinator() -> Bool {
        let localFP = identity.localFingerprint
        let activeFPs = activeSlots.compactMap(\.fingerprint)
        let all = [localFP] + activeFPs
        return all.min() == localFP
    }

    /// Returns true when the given fingerprint matches the currently elected coordinator.
    private func isElectedCoordinator(_ fingerprint: String) -> Bool {
        let localFP = identity.localFingerprint
        let activeFPs = activeSlots.compactMap(\.fingerprint)
        let all = [localFP] + activeFPs
        return all.min() == fingerprint
    }

    // MARK: - Phase 3: Beacon loop

    private func startBeaconLoop() {
        guard beaconTimer == nil else { return }
        beaconTimer = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                // Cancellation exits the beacon loop — that IS the recovery (R7).
                do {
                    try await Task.sleep(for: .seconds(Self.beaconInterval))
                } catch {
                    return
                }
                guard !Task.isCancelled, let self else { return }
                if self.isLocalCoordinator() {
                    self.broadcastCoordinatorBeacon()
                } else {
                    self.checkBeaconLiveness()
                }
            }
        }
    }

    private func broadcastCoordinatorBeacon() {
        guard let nextAt = lastKnownNextRotationAt else { return }
        let beacon = MeshCoordinatorBeaconPayload(
            coordinatorFingerprint: identity.localFingerprint,
            currentEpoch: currentGroupKey?.epoch ?? 0,
            nextRotationAt: nextAt,
            sentAt: Date()
        )
        for slot in slots {
            Task { [weak self] in await self?.sendEnvelope(.meshCoordinatorBeacon, encodable: beacon, via: slot) }
        }
    }

    private func handleCoordinatorBeacon(_ beacon: MeshCoordinatorBeaconPayload, senderFingerprint: String?) {
        // Bind the beacon to its AUTHENTICATED sender (R5): otherwise any peer can forge liveness
        // for the elected coordinator, keeping `lastBeaconReceivedAt` fresh so takeover never fires.
        guard let senderFingerprint, senderFingerprint == beacon.coordinatorFingerprint else { return }
        // Ignore beacons from non-elected fingerprints (Phase 4 hardening: Review Issue 2).
        guard isElectedCoordinator(beacon.coordinatorFingerprint) else { return }
        // Clamp nextRotationAt to within one rotation window + 1 min buffer to prevent griefing.
        let maxFuture = Date().addingTimeInterval(Self.rotationInterval + 60)
        let clampedNext = min(beacon.nextRotationAt, maxFuture)

        lastBeaconReceivedAt = Date()
        lastKnownNextRotationAt = clampedNext

        // If we thought we were the coordinator but now see a lower-FP winner's beacon, yield.
        if isLocalCoordinator() && beacon.coordinatorFingerprint != identity.localFingerprint {
            rotationTimer?.cancel()
            rotationTimer = nil
        } else if !isLocalCoordinator() && rotationTimer == nil {
            // Non-coordinator: schedule a shadow timer so we can take over if the beacon goes silent.
            scheduleRotationTimer(fireAt: clampedNext)
        }
    }

    private func checkBeaconLiveness() {
        guard let lastBeacon = lastBeaconReceivedAt else { return }
        guard Date().timeIntervalSince(lastBeacon) > Self.beaconLivenessTimeout else { return }
        guard isLocalCoordinator() else { return }
        // Coordinator is presumed lost; take over.
        takeOverCoordinator()
    }

    private func takeOverCoordinator() {
        let nextAt: Date
        if let known = lastKnownNextRotationAt, known > Date() {
            nextAt = known
        } else {
            // Missed or unknown — recover with a short delay.
            nextAt = Date().addingTimeInterval(60)
        }
        lastKnownNextRotationAt = nextAt
        scheduleRotationTimer(fireAt: nextAt)
        broadcastCoordinatorBeacon()
    }

    // MARK: - Phase 3: Rotation timer

    private func scheduleRotationTimer(fireAt target: Date) {
        rotationTimer?.cancel()
        let delay = max(0, target.timeIntervalSinceNow)
        rotationTimer = Task { @MainActor [weak self] in
            // A cancelled timer must NEVER initiate a rotation (R7).
            do {
                try await Task.sleep(for: .seconds(delay))
            } catch {
                return
            }
            guard !Task.isCancelled, let self else { return }
            self.requestRotation(cause: .timer)
        }
    }

    // MARK: - Rotation triggers (network migration P3 item 5, plan §8.3)

    /// The ONE entry point to key rotation: the 15-minute timer, any roster change, any merge.
    ///
    /// Every caller goes through ``MeshRotationTriggerQueue``, which is what makes a burst of
    /// records rotate once and what stops a second rotation starting while one is in flight. The
    /// coordinator check happens at *fire* time rather than here, so a trigger raised moments
    /// before this device takes over coordination is not silently dropped.
    func requestRotation(cause: MeshKeyRotationCause) {
        let outcome = rotationTriggers.request(cause, at: Date())
        switch outcome {
        case .scheduled(let target, _):
            armRotationDebounce(firingAt: target)
        case .coalesced, .queuedBehindInFlight:
            return   // a window (or a rotation) already owns this cause
        }
    }

    /// Arms the SINGLE debounce task (R3: cancel-and-replace, one task at most).
    private func armRotationDebounce(firingAt target: Date) {
        rotationDebounceTask?.cancel()
        let delay = max(0, target.timeIntervalSinceNow)
        rotationDebounceTask = Task { @MainActor [weak self] in
            do {
                try await Task.sleep(for: .seconds(delay))
            } catch {
                return   // cancelled: a cancelled window must never rotate (R7)
            }
            guard !Task.isCancelled, let self else { return }
            await self.runDebouncedRotation()
        }
    }

    /// Claims the debounced cause and runs one rotation, then re-arms anything that arrived while
    /// it was in flight. Non-coordinators claim nothing — they consume the trigger and stop.
    private func runDebouncedRotation() async {
        guard let cause = rotationTriggers.claim(at: Date()) else { return }
        if isLocalCoordinator() {
            await initiateRotation(cause: cause)
        }
        rearmDeferredRotation()
    }

    /// Re-arms the window for a trigger that arrived mid-rotation, so a deferred trigger is
    /// deferred rather than dropped.
    private func rearmDeferredRotation() {
        guard let outcome = rotationTriggers.finish(at: Date()) else { return }
        if case .scheduled(let target, _) = outcome { armRotationDebounce(firingAt: target) }
    }

    // MARK: - Phase 3: Rotation protocol

    /// Coordinator entry point for a key rotation, whatever triggered it (plan §8.3).
    ///
    /// The order of the four steps is load-bearing. The epoch is **planned** before anything moves
    /// (a plan that cannot mint a successor ends the session instead of serving a permanent key),
    /// the drain runs, the head is **persisted before the rotation is acknowledged or distributed**
    /// (plan §3.6 — a rotation nobody could write down must not be one peers act on), and only then
    /// is the key wrapped for the recipients the exclusion rule allows.
    private func initiateRotation(cause: MeshKeyRotationCause) async {
        let closingEpoch = currentGroupKey?.epoch ?? 0
        guard let plan = plannedRotation() else { return }
        guard case .rotate(let nextEpoch) = plan else {
            if case .terminate = plan { await terminateForExhaustedEpochs() }
            return
        }
        let acked = await drainForRotation(closingEpoch: closingEpoch)
        guard let acked else { return }   // cancelled mid-drain: nothing was distributed

        // Durable BEFORE acknowledged (plan §3.6): a refused or deferred save abandons the
        // rotation with the reason named, rather than handing out a key no restart can explain.
        guard persistSessionContext(addingEpochHead: nextEpoch) else { return }

        lastRotationCause = cause
        lastRotationBlockReason = nil
        await distributeRotation(nextEpoch, cause: cause, acked: acked, closingEpoch: closingEpoch)
    }

    /// Plans the next epoch, or names why there will not be one.
    ///
    /// - Returns: nil when this device cannot even name a coordinator (no mesh yet) — the same
    ///   "do nothing" as a refusal, logged the same way.
    private func plannedRotation() -> MeshRotationPlan? {
        guard let coordinator = epochCoordinatorFingerprint,
              coordinator == identity.localFingerprint else {
            recordRotationBlock("This device is not the deterministic coordinator of its roster.")
            return nil
        }
        let plan = MeshRotationPolicy.plan(
            head: epochKeyring?.head,
            coordinatorFingerprint: coordinator,
            meshID: meshID,
            presentedRoster: presentedRotationRoster()
        )
        if case .refuse(let refusal) = plan {
            recordRotationBlock(refusal.diagnosticDescription)
        }
        return plan
    }

    /// Step 1–2: announce the closing epoch, re-arm the timer, and collect the drain acks.
    ///
    /// - Returns: The acking fingerprints, or nil when the rotation was cancelled mid-drain.
    private func drainForRotation(closingEpoch: Int) async -> Set<String>? {
        let sync = MeshRotationSyncPayload(closingEpoch: closingEpoch)
        for slot in slots {
            await sendEnvelope(.meshRotationSync, encodable: sync, via: slot)
        }
        let nextAt = Date().addingTimeInterval(Self.rotationInterval)
        lastKnownNextRotationAt = nextAt
        scheduleRotationTimer(fireAt: nextAt)
        broadcastCoordinatorBeacon()

        pendingRotationAcks.removeAll()
        pendingRotationClosingEpoch = closingEpoch
        let expectedAckers = Set(activeSlots.compactMap(\.fingerprint))
        // R2: the loop's bound is the named ack window divided by the named poll interval
        // (≤ 50 iterations), and cancellation aborts it.
        let deadline = Date().addingTimeInterval(Self.rotationAckWindowSeconds)
        while Date() < deadline && !expectedAckers.subtracting(pendingRotationAcks).isEmpty {
            do {
                try await Task.sleep(for: Self.rotationAckPollInterval)
            } catch {
                // Cancelled mid-rotation: abandon it cleanly rather than distributing a key
                // nobody is waiting for (R7).
                pendingRotationClosingEpoch = nil
                pendingRotationAcks.removeAll()
                return nil
            }
        }
        pendingRotationClosingEpoch = nil
        return pendingRotationAcks.intersection(expectedAckers)
    }

    /// Step 3: mint the key, wrap it for the permitted recipients only, send, and adopt.
    private func distributeRotation(
        _ nextEpoch: MeshEpochRef,
        cause: MeshKeyRotationCause,
        acked: Set<String>,
        closingEpoch: Int
    ) async {
        // `SystemRandomNumberGenerator` (behind `UInt8.random`) is the platform CSPRNG, so this is
        // the same key material without the pointer seam (R9) or the discarded OSStatus (R7) the
        // SecRandomCopyBytes spelling had — a failed RNG can no longer ship an all-zero group key.
        let newKeyBytes = Data((0..<32).map { _ in UInt8.random(in: .min ... .max) })
        let recipients = MeshRotationPolicy.recipients(
            acked: acked,
            selfFingerprint: identity.localFingerprint,
            derivedRoster: membershipVerifier?.roster,
            locallyRemoved: removedMemberFingerprints
        )
        let perMember = wrappedGroupKey(newKeyBytes, for: recipients)
        let rotation = MeshKeyRotationPayload(
            newEpoch: closingEpoch + 1,
            perMember: perMember,
            rotationInitiatedAt: Date(),
            coordinatorFingerprint: identity.localFingerprint,
            cause: cause
        )
        for slot in slots {
            await sendEnvelope(.meshKeyRotation, encodable: rotation, via: slot)
        }
        // Apply new key locally (unwrap self-encrypted copy).
        applyRotatedKeyLocally(perMember[identity.localFingerprint], ref: nextEpoch)
        pendingRotationAcks.removeAll()
    }

    /// Pairwise-wraps one group key for each recipient that has a handshake-verified key-agreement
    /// key. A recipient with no verified key gets no copy — never the descriptor's gossiped value.
    private func wrappedGroupKey(_ keyBytes: Data, for recipients: Set<String>) -> [String: Data] {
        var perMember: [String: Data] = [:]
        for fp in recipients {
            let kaKey: Data
            if fp == identity.localFingerprint {
                kaKey = identity.localKeyAgreementPublicKey
            } else if let slot = slots.first(where: { $0.fingerprint == fp }),
                      let verified = slot.verifiedKeyAgreementPublicKey {
                // Use the handshake-verified key, not the descriptor gossip value (Review Issue 1).
                kaKey = verified
            } else {
                continue
            }
            do {
                perMember[fp] = try identity.encryptGroupKey(keyBytes, for: kaKey)
            } catch {
                // That member simply gets no copy this epoch (they rejoin on the next grant) —
                // named rather than silent (R7). Context carries no fingerprint.
                FernletAuditLog.log(
                    "mesh.keyRotation.wrapFailed",
                    context: ["error": String(describing: error)]
                )
            }
        }
        return perMember
    }

    /// The roster this device presents with a rotation: the derived roster when the ledger knows
    /// one, else the gossiped descriptor's members plus self.
    ///
    /// It must be the same set ``epochCoordinatorFingerprint`` takes its minimum from, or this
    /// device would present a roster it is not the coordinator of and refuse its own rotation.
    private func presentedRotationRoster() -> [String] {
        if let roster = membershipVerifier?.roster, !roster.members.isEmpty {
            return roster.memberFingerprints
        }
        let members = currentMesh?.members.map(\.fingerprint) ?? []
        return Array(Set(members + [identity.localFingerprint])).sorted()
    }

    /// Records a rotation that did not happen: audit line plus the readable reason (R7 — a blocked
    /// rotation is never silent).
    private func recordRotationBlock(_ reason: String) {
        lastRotationBlockReason = reason
        FernletAuditLog.log("mesh.keyRotation.blocked", context: ["reason": reason])
    }

    /// Plan §8.4's counter cap, reached: this mesh can mint no further epoch, so it cannot retire
    /// the key it is serving. Emit the signed termination and end the session — never a trap.
    private func terminateForExhaustedEpochs() async {
        recordRotationBlock("The mesh has exhausted its epoch counters and must end.")
        // P3 item 6: the ending is written down before it is announced (plan §3.6). A refused save
        // still ends the session locally — the mesh genuinely cannot mint another epoch — but it
        // does not tell the peers something this device could not record.
        let transition = applySessionEvent(.terminationRequested(.epochCounterExhausted))
        if transition.nextState == nil || lastSessionEffectFailure == nil {
            await sendMembershipEvent(.meshTerminated)
            applySessionEvent(.terminationSent)
        }
        leaveSession()
    }

    /// Unwraps a grant's group-key bundle. A generic failure still falls through to the keyless
    /// branch exactly as before; a pre-`FGK2` bundle is logged first, because the keyless branch
    /// would otherwise absorb "that phone is running an older Fernlet" into a silent epoch adoption
    /// the user could never explain.
    private func unwrappedAdmissionGrantKey(_ bundle: Data) -> Data? {
        do {
            return try identity.decryptGroupKey(bundle)
        } catch IdentityError.legacyWireFormat {
            FernletAuditLog.log("mesh.admissionGrant.droppedLegacyKeyWrap")
            return nil
        } catch {
            return nil
        }
    }

    /// Unwraps the coordinator's own copy of a freshly minted key. A failure here means the
    /// coordinator distributed a key it cannot itself read, so it is surfaced and the key dropped
    /// rather than silently keeping the closed epoch (R7).
    private func applyRotatedKeyLocally(_ selfBundle: Data?, ref: MeshEpochRef) {
        guard let selfBundle else { return }
        do {
            let keyData = try identity.decryptGroupKey(selfBundle)
            let newKey = MeshGroupKey(epoch: Int(ref.counter), keyBytes: keyData, activeSince: Date())
            currentGroupKey = newKey
            adoptEpoch(ref, key: newKey)
            recordEpoch(newKey.epoch, since: newKey.activeSince)
        } catch {
            FernletAuditLog.log(
                "mesh.keyRotation.selfUnwrapFailed",
                context: ["error": String(describing: error)]
            )
            meshError = "Couldn't start the new session key. Rejoining…"
            clearEpochKeyring()
        }
    }

    /// Moves the held ``MeshEpochKeyring`` onto a newly adopted epoch, starting the old head's
    /// grace window (plan §8.4).
    ///
    /// A refusal from the keyring is **logged, not fatal**: it means the ref did not strictly
    /// supersede the head (a replay, or a divergent branch at the same counter), and the caller has
    /// already applied its own monotonicity guard to the key itself. Rebuilding the keyring on a
    /// refusal would silently retire predecessors that are still inside their grace window.
    private func adoptEpoch(_ ref: MeshEpochRef, key: MeshGroupKey) {
        guard var keyring = epochKeyring else {
            epochKeyring = MeshEpochKeyring(head: ref, key: key)
            return
        }
        do {
            try keyring.rotate(to: ref, key: key, at: Date())
            epochKeyring = keyring
        } catch {
            FernletAuditLog.log(
                "mesh.epochKeyring.rotationRefused",
                context: ["reason": String(describing: error)]
            )
        }
    }

    /// Drops the keyring with the key it names. Called wherever `currentGroupKey` goes to nil, so
    /// the two never disagree about whether this device is on an epoch.
    private func clearEpochKeyring() {
        currentGroupKey = nil
        epochKeyring = nil
    }

    /// The ``MeshEpochRef`` a peer's rotation or grant names, derived from the counter and the
    /// coordinator both sides already agree on — no wire change, exactly as item 4 designed it.
    private func epochRef(counter: Int, coordinatorFingerprint: String?) -> MeshEpochRef? {
        guard counter >= 0, let coordinator = coordinatorFingerprint else { return nil }
        return MeshEpochRef.minted(
            counter: UInt32(clamping: counter),
            coordinatorFingerprint: coordinator,
            meshID: meshID
        )
    }

    /// Arms the SINGLE in-flight rotation-sync drain (R3: bounded task fan-out).
    ///
    /// A coordinator flooding `.meshRotationSync` used to spawn one 3-second sleeping task per
    /// frame, each acking every active slot. Cancel-and-replace keeps at most one in flight.
    private func scheduleRotationSyncAck(_ sync: MeshRotationSyncPayload, senderFingerprint: String?) {
        rotationSyncTask?.cancel()
        rotationSyncTask = Task { @MainActor [weak self] in
            await self?.handleRotationSync(sync, senderFingerprint: senderFingerprint)
            self?.rotationSyncTask = nil
        }
    }

    /// Non-coordinator: respond to a rotation sync from the coordinator.
    private func handleRotationSync(_ sync: MeshRotationSyncPayload, senderFingerprint: String?) async {
        // Accept only from the elected coordinator (sender-authenticated).
        guard let senderFP = senderFingerprint, isElectedCoordinator(senderFP) else { return }
        // Drain any pending outbound photo work before signalling ready. A cancelled drain sends
        // no ack (R7) — a newer sync has replaced this one, or the session ended.
        do {
            try await Task.sleep(for: .seconds(Self.rotationDrainSeconds))
        } catch {
            return
        }
        let ack = MeshKeyAckPayload(epoch: sync.closingEpoch, memberFingerprint: identity.localFingerprint)
        for slot in activeSlots {
            await sendEnvelope(.meshKeyAck, encodable: ack, via: slot)
        }
    }

    /// Non-coordinator: apply the new group key from a rotation payload.
    private func handleKeyRotation(_ payload: MeshKeyRotationPayload, senderFingerprint: String?) async {
        // Require the authenticated envelope sender to be both the elected coordinator
        // and the coordinator claimed in the payload.
        guard let senderFP = senderFingerprint,
              senderFP == payload.coordinatorFingerprint,
              isElectedCoordinator(senderFP) else { return }
        // Epochs only ever move FORWARD (R5): a replayed or crafted rotation with an older/equal
        // epoch would otherwise roll the group key back and grow `epochLog` on every replay.
        guard payload.newEpoch > (currentGroupKey?.epoch ?? localJoinedEpoch) else {
            FernletAuditLog.log("mesh.keyRotation.staleEpochDropped")
            return
        }

        guard let myBundle = payload.perMember[identity.localFingerprint] else {
            // Excluded from this rotation — surface a non-modal warning and initiate rejoin. This
            // is the branch a removed or departed member lands in (plan §8.3), and the reason its
            // old key still opens in-flight frames for at most the predecessor grace window.
            meshError = "You were excluded from the key rotation. Rejoining…"
            clearEpochKeyring()
            if let mesh = currentMesh {
                sendAdmissionRequest(for: mesh)
            }
            return
        }
        let keyData: Data
        do {
            keyData = try identity.decryptGroupKey(myBundle)
        } catch {
            // Silently keeping the OLD key desyncs us from every peer: encrypted photos and
            // metadata are then dropped at the epoch guards with nothing visible. Surface it and
            // rejoin instead (R7) — the same recovery as the "excluded" branch above.
            FernletAuditLog.log(
                "mesh.keyRotation.unwrapFailed",
                context: ["error": String(describing: error)]
            )
            meshError = "Couldn't join the new session key. Rejoining…"
            clearEpochKeyring()
            if let mesh = currentMesh {
                sendAdmissionRequest(for: mesh)
            }
            return
        }
        let newKey = MeshGroupKey(epoch: payload.newEpoch, keyBytes: keyData, activeSince: Date())
        currentGroupKey = newKey
        adoptRotatedEpoch(payload, key: newKey)
        recordEpoch(payload.newEpoch, since: newKey.activeSince)

        // Durable BEFORE acknowledged (plan §3.6): the ack is this member's statement that it is on
        // the new epoch, so the head is written first. A blocked save skips the ack — named, never
        // silent — rather than claiming a state a restart could not reproduce.
        guard persistSessionContext(addingEpochHead: epochKeyring?.head) else { return }
        // Send rotation-ack back to the coordinator.
        let ack = MeshKeyAckPayload(epoch: payload.newEpoch, memberFingerprint: identity.localFingerprint)
        if let coordinatorSlot = slots.first(where: { $0.fingerprint == payload.coordinatorFingerprint }) {
            await sendEnvelope(.meshKeyAck, encodable: ack, via: coordinatorSlot)
        }
    }

    /// Moves the keyring onto the epoch a coordinator's rotation names, re-deriving the ref from
    /// the counter and coordinator the frame already carries (no wire change — item 4's design).
    /// The rotation's `cause` is recorded for diagnostics only; it never changes what is accepted.
    private func adoptRotatedEpoch(_ payload: MeshKeyRotationPayload, key: MeshGroupKey) {
        lastRotationCause = payload.cause
        guard let ref = epochRef(
            counter: payload.newEpoch, coordinatorFingerprint: payload.coordinatorFingerprint
        ) else {
            FernletAuditLog.log("mesh.epochKeyring.refNotDerivable")
            return
        }
        adoptEpoch(ref, key: key)
    }

    /// Coordinator: collect acks from members.
    private func handleKeyAck(_ ack: MeshKeyAckPayload, senderFingerprint: String?) {
        guard isLocalCoordinator() else { return }
        // An ack counts only for the AUTHENTICATED sender, and only from an active slot (R5):
        // otherwise one peer can ack for every member (so the coordinator wraps the new key for
        // peers that never drained) and inflate the set with arbitrary strings (R3 — growth is
        // now bounded by the active slots).
        guard let senderFingerprint,
              senderFingerprint == ack.memberFingerprint,
              activeSlots.contains(where: { $0.fingerprint == senderFingerprint }) else { return }
        // Accept acks for the closing epoch (sync-phase acks) only.
        if let closing = pendingRotationClosingEpoch, ack.epoch == closing {
            pendingRotationAcks.insert(ack.memberFingerprint)
        }
    }

    // MARK: - Observation loop for coordinator state changes

    private func startObserving() {
        observationTask?.cancel()
        observationTask = ObservationLoop.start(
            on: self,
            tracking: { owner in
                _ = owner.slots.count
                for slot in owner.slots {
                    _ = slot.coordinator.state
                    _ = slot.coordinator.lastKnownDistance
                }
            },
            onChange: { owner in
                owner.checkCoordinatorStates()
                owner.updateDistanceSamples()
            }
        )
    }

    private func checkCoordinatorStates() {
        for index in slots.indices {
            if case .connected(let peerIdentity) = slots[index].coordinator.state {
                let fp = peerIdentity.fingerprint
                if slots[index].fingerprint != fp {
                    slots[index].fingerprint = fp
                    slots[index].verifiedSigningPublicKey = peerIdentity.signingPublicKey
                    // Store the handshake-verified KA key; used for group key wrapping (Phase 3).
                    slots[index].verifiedKeyAgreementPublicKey = peerIdentity.keyAgreementPublicKey
                    // Phase 5: capture advertised capabilities so a room broadcast (temp messages) can
                    // skip peers that can't use the payload without re-plumbing the PeerIdentity.
                    slots[index].peerCapabilities = peerIdentity.capabilities
                    onSlotConnected(at: index, identity: peerIdentity)
                }
            }
        }
        // Evict slots whose coordinators have ended (e.g. timeout or transport loss).
        let stale = slots.filter { slot in
            switch slot.coordinator.state {
            case .ended, .failed: return true
            default: return false
            }
        }
        for slot in stale { removeSlot(slot) }
    }

    // MARK: - Test seams

    /// Appends a slot for the given coordinator so unit tests can drive the registry dispatch path —
    /// the production slot path is driven by a live `MCSession` a unit test cannot fake. A non-nil
    /// `fingerprint` models a COMMITTED slot (post-dwell); nil models a pre-commit candidate, which the
    /// Phase-3a registry gate must drop. `internal` for `@testable` unit tests only.
    ///
    /// `kind` and `stableDistanceMeters` are settable because the overflow gate reads both: only a
    /// LIGHTWEIGHT slot with a settled distance makes a full mesh willing to evaluate one more
    /// candidate, which is the state the duplicate-seat check has to be exercised against.
    func addSlotForTesting(
        coordinator: ProximityCoordinator,
        peer: PeerHandle,
        fingerprint: String?,
        verifiedKeyAgreementPublicKey: Data? = nil,
        peerCapabilities: [String]? = nil,
        kind: SlotKind = .active,
        stableDistanceMeters: Double? = nil
    ) {
        var slot = PeerSlot(
            id: peer.id,
            peer: peer,
            channel: DetachedPeerChannel(peer: peer),
            coordinator: coordinator,
            kind: kind,
            fingerprint: fingerprint
        )
        slot.verifiedKeyAgreementPublicKey = verifiedKeyAgreementPublicKey
        slot.peerCapabilities = peerCapabilities
        slot.stableDistanceMeters = stableDistanceMeters
        slots.append(slot)
    }

    /// The radio this manager is driving, so a test can assert WHICH one it selected — and, when it
    /// injected a fake, read back what the manager asked the radio to do.
    var transportForTesting: any MeshTransportSession { transport }

    /// This manager's identity, so a unit test can mint the signed membership records the verifier
    /// would otherwise refuse. `internal` for `@testable` unit tests only.
    var identityForTesting: IdentityService { identity }

    /// Fires with the membership event that reached ``sendMembershipEvent(_:)``'s broadcast — the
    /// only observation point for a frame whose wire write a unit test cannot see (the slot channel
    /// is detached). Mirrors `onSessionHeartSendForTesting`.
    @ObservationIgnored var onMembershipEventSentForTesting: ((PayloadType) -> Void)?

    /// Puts a ledger on this manager without a merge, so a test can start FROM a roster instead of
    /// building one through the merge path — which would spend the rotation trigger the test is
    /// about. `internal` for `@testable` unit tests only: production code has exactly one door into
    /// a ledger (``MeshMembershipRecordVerifier``), and this is deliberately not it, which is why
    /// the records a test seeds must still be honestly signed if anything is to verify against them.
    ///
    /// - Parameters:
    ///   - meshID: The mesh the ledger belongs to.
    ///   - founderSigningPublicKey: The key that may bootstrap an admission.
    ///   - ledger: The records to start from.
    func seedMembershipLedgerForTesting(
        meshID: UUID,
        founderSigningPublicKey: Data?,
        ledger: MeshMembershipLedger
    ) {
        membershipVerifier = MeshMembershipRecordVerifier(
            meshID: meshID,
            founderSigningPublicKey: founderSigningPublicKey,
            ledger: ledger
        )
    }

    /// Puts this manager on a named epoch without a rotation, so a test can start from the counter
    /// cap (plan §8.4's terminate-rather-than-trap edge) or from a superseded predecessor.
    func seedEpochKeyringForTesting(head: MeshEpochRef, key: MeshGroupKey) {
        currentGroupKey = key
        epochKeyring = MeshEpochKeyring(head: head, key: key)
    }

    /// Runs one rotation immediately, bypassing the debounce window (which
    /// `MeshRotationTriggerQueueTests` covers on its own, with no wall clock).
    func rotateNowForTesting(cause: MeshKeyRotationCause) async {
        await initiateRotation(cause: cause)
    }

    /// The callbacks this manager installed on its radio, so a unit test can fire the events a live
    /// radio drives in production (`onPeerDisconnected` above all — the retry and local-kick
    /// bookkeeping has no other entry point). Transport-neutral by construction: the same set is
    /// what the MC session, the QUIC session and the fake are each handed.
    var transportHandlersForTesting: MeshTransportHandlers { transportHandlers }

    /// Enters proximity-join mode WITHOUT starting the radios. `startJoin()` calls
    /// `startSearching()`, which starts real advertising and browsing — a unit test must never do
    /// that. Mirrors `ProximityRecipeShareManager.markRunningForTesting`.
    func markProximityJoinForTesting() {
        isProximityJoin = true
    }

    /// How many DISTINCT devices currently hold a re-invite budget.
    ///
    /// Deliberately the entry count and not one entry's value: the value is the same either way, so
    /// it cannot tell a per-device budget from a per-handle one. The count can — a single device
    /// that reconnected under a fresh handle used to open a second entry with a full fresh budget,
    /// which is visible here and nowhere else.
    var peerRetryEntryCountForTesting: Int { peerRetryCount.count }

    /// Re-invite attempts already spent on `peer`'s device.
    func peerRetryCountForTesting(for peer: PeerHandle) -> Int {
        peerRetryCount[peer.endpoint, default: 0]
    }

    /// Devices kicked locally whose `.notConnected` has not arrived yet — the note that stops a
    /// deliberate eviction from being re-invited by its own retry path.
    var locallyKickedEndpointCountForTesting: Int { locallyKickedEndpoints.count }

    /// Evicts a slot through the production removal funnel (`removeSlot` — the path
    /// `onPeerDisconnected` and the stale-coordinator sweep share), so unit tests can drive
    /// transient-drop teardown + shop send-tracking pruning without the private MC callbacks.
    /// `internal` for `@testable` unit tests only.
    func evictSlotForTesting(peerID: UUID) {
        guard let slot = slots.first(where: { $0.id == peerID }) else { return }
        removeSlot(slot)
    }

    /// Total wall-preference entries (aggregated sessions + covers + favorites) — the number the
    /// prune must drive back to zero once the photos they describe have left the cache.
    var photoWallPreferenceEntryCountForTesting: Int {
        photoWallPreferences.aggregatedSessionIDs.count
            + photoWallPreferences.coverPhotoIDsBySession.count
            + photoWallPreferences.favoritePhotoIDsBySession.count
    }

    /// Builds AND retains a slot coordinator exactly as `handleChannelReady` does — creating the
    /// FriendSessionTrustPolicy from the store's vault and holding it in `slotTrustPolicies` so the
    /// coordinator's `weak` trustPolicy stays alive — but over an injected transport so a unit test can
    /// drive a blocked-key envelope through the coordinator (ported from the deleted
    /// `ProximityClothingShareManager.makeRetainedConnectionCoordinatorForTesting`, whose regression
    /// this retention pattern originally fixed; mirrors the heart manager's seam). If the retention
    /// regresses (`slotTrustPolicies` no longer populated), the coordinator's weak ref goes nil once
    /// this returns and the revoked/blocked-key drop this drives silently stops firing.
    func makeRetainedSlotCoordinatorForTesting(
        peer: PeerHandle,
        transport: any PeerTransport,
        ranging: any RangingProvider
    ) -> ProximityCoordinator {
        let trustPolicy = FriendSessionTrustPolicy(vault: store.proximityTrustVault)
        let coordinator = ProximityCoordinator(
            identity: identity,
            transport: transport,
            ranging: ranging,
            payloadHandler: self,
            trustPolicy: trustPolicy,
            replayCache: replayCache,
            foregroundAnchor: NoopProximityForegroundAnchor(),
            displayName: displayName,
            timeoutSeconds: 0
        )
        let slot = PeerSlot(
            id: peer.id,
            peer: peer,
            channel: DetachedPeerChannel(peer: peer),
            coordinator: coordinator,
            kind: .active,
            fingerprint: nil
        )
        slotTrustPolicies[slot.id] = trustPolicy
        slots.append(slot)
        return coordinator
    }

    // MARK: - UI test injection

    #if DEBUG
    /// `AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE`, spelled with the non-optional `UUID(uuid:)`
    /// initialiser so the fixture needs no force unwrap (R5).
    private static let uiTestOpenMeshID = UUID(uuid: (
        0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xCC, 0xCC,
        0xDD, 0xDD, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE
    ))
    /// `AAAAAAAA-BBBB-CCCC-DDDD-FFFFFFFFFFFF`, same non-optional construction.
    private static let uiTestClosedMeshID = UUID(uuid: (
        0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xCC, 0xCC,
        0xDD, 0xDD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    ))
    // Kept inside the DEBUG region with their only readers: private statics left visible in Release
    // would be unused, and warnings are errors on every target.
    #endif

    /// Seeds a canned mesh (and, optionally, a pending admission request) from `FERNLET_UI_TEST_MESH_*`
    /// so the UI suites can drive the mesh surfaces without a second device.
    ///
    /// The BODY is `#if DEBUG`, not the signature: a configuration skew between the app target and
    /// this local package would turn a wrapped signature into a hard "cannot find member" error,
    /// whereas an empty body cannot. In Release the fabricated ``MeshDescriptor`` — and the whole
    /// environment-flag read — is absent from the binary, so no shipped build can be talked into a
    /// synthetic mesh state.
    public func injectUITestStateIfNeeded() {
        #if DEBUG
        let env = ProcessInfo.processInfo.environment
        let now = Date()
        let hostFP = "aa:bb:cc:dd:00:11:test"

        if env["FERNLET_UI_TEST_MESH_OPEN"] == "1" || env["FERNLET_UI_TEST_MESH_ADMISSION"] == "1" {
            currentMesh = MeshDescriptor(
                meshID: Self.uiTestOpenMeshID,
                name: "Sunrise Meadow",
                mode: .open,
                members: [MeshMember(
                    fingerprint: hostFP,
                    displayName: "Test Host",
                    signingPublicKey: Data(),
                    keyAgreementPublicKey: Data(),
                    joinedAt: now
                )],
                nameSetAt: now, nameSetBy: hostFP,
                modeSetAt: now, modeSetBy: hostFP,
                createdAt: now
            )
        }

        if env["FERNLET_UI_TEST_MESH_CLOSED"] == "1" {
            currentMesh = MeshDescriptor(
                meshID: Self.uiTestClosedMeshID,
                name: "Closed Test Mesh",
                mode: .closed,
                members: [MeshMember(
                    fingerprint: hostFP,
                    displayName: "Test Host",
                    signingPublicKey: Data(),
                    keyAgreementPublicKey: Data(),
                    joinedAt: now
                )],
                nameSetAt: now, nameSetBy: hostFP,
                modeSetAt: now, modeSetBy: hostFP,
                createdAt: now
            )
        }

        if env["FERNLET_UI_TEST_MESH_ADMISSION"] == "1", let mesh = currentMesh {
            pendingAdmissionRequests = [MeshAdmissionRequestPayload(
                meshID: mesh.meshID,
                requesterFingerprint: "bb:cc:dd:ee:ff:test",
                requesterDisplayName: "Alice",
                requesterSigningPublicKey: Data(),
                requesterKeyAgreementPublicKey: Data()
            )]
        }
        #endif
    }
}

// MARK: - MeshIntroductionAuthority

/// What the QUIC radio must be told before it can authenticate a peer (P2 item 8's wiring).
///
/// The manager answers from exactly the state the MC path already trusts: the identity service for
/// the signing key and the signature, and the live ``MeshDescriptor`` for the mesh id, the epoch and
/// the roster. Nothing new is derived and nothing is stored — a removal takes effect on the next
/// introduction because the roster is read fresh each time.
///
/// **Scope, stated plainly.** A roster-authenticated transport can only ever admit a member. With no
/// mesh yet — a first proximity-join meeting, where the two devices have never met — the roster is
/// empty, every peer verdicts ``MeshRosterVerdict/stranger``, and the QUIC radio refuses. That is the
/// fail-closed posture plan §7.2 asks for and one more reason MultipeerConnectivity remains the
/// default: admission of a stranger is a membership question (plan §8), not a transport one, and the
/// item that migrates the app's flows is where it gets answered.
extension MeshNetworkManager: MeshIntroductionAuthority {

    /// The mesh id used when this device holds no mesh descriptor: the all-zero UUID, so two peers
    /// in the same "no mesh yet" state agree instead of each inventing a random one and rejecting
    /// the other for ``MeshIntroductionRejection/foreignMesh``. A frozen token, never on a wire in
    /// any other role.
    private static let unboundMeshID = UUID(uuid: (
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0
    ))

    var meshID: UUID { currentMesh?.meshID ?? Self.unboundMeshID }

    /// The deterministic coordinator of this mesh's epochs: the lowest fingerprint among the
    /// gossiped descriptor's members and this device (plan §8.4's "deterministic coordinator
    /// (lowest fingerprint) of the roster set they present").
    ///
    /// Deliberately the **gossiped roster** and not `activeSlots`: the roster is what both ends of a
    /// converged mesh agree on, so both compute the same coordinator and therefore the same
    /// ``MeshEpochRef`` for the same key. Two devices whose rosters have diverged compute different
    /// coordinators — which is precisely the divergence the strict epoch gate is meant to see, not
    /// a bug in this accessor.
    ///
    /// It reads the **same set** ``presentedRotationRoster()`` presents — the ledger's derived
    /// roster once it knows one, else the descriptor's members plus self. The two must move
    /// together (P3 item 5): a coordinator taken from one set and a roster presented from another
    /// is a rotation this device would refuse on arrival from anybody else.
    private var epochCoordinatorFingerprint: String? {
        guard currentMesh != nil else { return nil }
        return presentedRotationRoster().min()
    }

    /// This device's current membership epoch as a canonical ``MeshEpochRef`` string, or empty when
    /// it holds no group key.
    ///
    /// Empty is meaningful and is a *named* case of the acceptance rule rather than a wildcard:
    /// a peer that has not been given the group key yet cannot name an epoch, so it introduces as
    /// "no epoch" and adopts the keyed side's (``MeshEpochAcceptance/introductionVerdict(local:peer:)``).
    ///
    /// **Read off the held keyring** (P3 item 5), not re-derived per read. Item 4 minted a ref from
    /// `currentGroupKey.epoch` and whatever the descriptor roster said at that instant, which meant
    /// a descriptor merge could silently rename this device's epoch with no rotation behind it. The
    /// keyring's head is set exactly once per adopted key, by the same derivation, from the roster
    /// that was current when the key arrived — so it is stable for the life of the epoch and it is
    /// the same value every other member of that branch computes.
    var epochRef: String {
        epochKeyring?.head.canonicalString ?? ""
    }

    /// Who may connect right now, derived fresh from the mesh descriptor.
    ///
    /// `barred` is deliberately empty in production: a removed member is already absent from
    /// `members`, so it verdicts `.stranger` and is refused either way, and this manager keeps
    /// removals by FINGERPRINT (`removedMemberFingerprints`) — it holds no signing key for a member
    /// it has dropped, so it cannot honestly name one as barred. The refusal is identical; only the
    /// diagnostic differs.
    ///
    /// ``MeshIntroductionChaos/additionalBarredKeys`` is `[]` in every Release build and in every
    /// DEBUG launch that does not ask for it, so the production answer is unchanged. It exists so
    /// the ``MeshRosterVerdict/barred`` branch — otherwise reachable only at tier 1, for the reason
    /// just given — can be observed over a real radio. It can only ever *refuse* a peer this roster
    /// would have admitted (barred wins over member), never the reverse.
    var roster: MeshIntroductionRoster {
        MeshIntroductionRoster(
            members: currentMesh?.members.map(\.signingPublicKey) ?? [],
            barred: MeshIntroductionChaos.additionalBarredKeys
        )
    }

    func signChannelIntroduction(_ transcript: Data) throws -> Data {
        try identity.sign(transcript, purpose: FernletCryptoPurpose.Signature.meshChannelIntroductionV1)
    }
}
