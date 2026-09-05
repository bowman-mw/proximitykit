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

    /// What this device could not take or place — the ONE user-visible backpressure surface (P5 item
    /// 9, plan §11's "nothing grows silently").
    ///
    /// **Observed**, unlike every other routed seam, and that is the point: a capacity refusal that
    /// no view can re-render on is exactly the silent growth the wall forbids. Counts and a frozen
    /// cause only — no display text, and no item id (the diagnostic seams keep those).
    ///
    /// Cleared when a NEW mesh replaces the fact (``prepareMembershipLedger(meshID:founderSigningPublicKey:now:)``
    /// / ``armJoinerLedger(_:now:)``) and deliberately **not** at `leaveMesh`: held custody outlives
    /// the session, and the Friends tab is exactly where a tester goes after leaving the session that
    /// produced the refusal. Released the moment a sweep gives the store room again — a surface that
    /// keeps asserting a condition the store has escaped is the same defect as an invisible refusal.
    public private(set) var routedDeliveryHold: MeshRoutedDeliveryHold?

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
    /// The live tally of signed removal proposals and votes (P4 item 5, plan §10.4).
    ///
    /// **In memory only.** A proposal is a five-minute conversation, not a fact about the mesh, so
    /// it is never sealed: `MeshSessionContext` stays at schema 2 and no wipe row is owed. A device
    /// that restarts mid-vote has simply missed it, and only the COMPLETED removal — an ordinary
    /// `member-removal.v1` record — is durable and mergeable.
    @ObservationIgnored private(set) var removalQuorum = MeshRemovalQuorum()
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
    ///
    /// `identity` is the same kind of seam for the device's own keys, and exists for one reason: a
    /// device has exactly ONE proximity identity, so the default ``IdentityService`` is keyed on one
    /// process-wide keychain service — and two managers built in a single test process are therefore
    /// literally the same device, sharing a fingerprint. That makes a two-node tier-1 scenario
    /// (P4 item 2's wire exchange, `MeshMergeExchangeTests`) impossible to state honestly. Passing a
    /// distinctly-keyed identity is the only thing that separates them. Nothing in shipping code
    /// passes it: the public initializer above cannot, so a Release build always takes this device's
    /// real identity.
    ///
    /// - Parameters:
    ///   - store: The host this manager's roots and vaults hang off.
    ///   - transport: The radio, or nil for the one this build selects.
    ///   - identity: The device identity, or nil for this device's own.
    init(
        store: any ProximityHost,
        transport: (any MeshTransportSession)?,
        identity: IdentityService? = nil
    ) {
        self.store = store
        self.transport = transport ?? MeshTransportFactory.makeSession(MeshTransportFactory.resolvedKind())
        let id = identity ?? IdentityService()
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
        spawnHostPinned { [weak self] in
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
        // host-pin: timer — stored handle, synchronous main-actor body; a task-lifetime pin would cycle (HP2)
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

    /// Whether this device may open or accept a *link* to a discovered peer right now.
    ///
    /// A closed mesh refuses new **members**; it does not refuse new **links**, and conflating the
    /// two is what made three Simulators form a spanning star instead of a mesh (plan §8.7 finding
    /// 1, runbook "Lane C — THREE nodes"). ``isSessionOpen`` is re-derived from the *gossiped*
    /// descriptor's mode in ``handleMeshDescriptor(_:from:)``, so on a `.closed` mesh the first
    /// committed peer's descriptor latched it false on every node — and from that instant the node
    /// neither dialed nor accepted anybody, its own co-members included. Whichever node happened to
    /// have both of its edges in flight before that merge became the hub, which is why the hub was
    /// a different Simulator every run.
    ///
    /// Once this device holds a mesh, the roster — not this flag — decides who may connect, and it
    /// decides it where the peer's identity is actually known: the QUIC introduction is
    /// members-only (``roster`` answers `stranger`/`barred` before any app frame), MC's slot
    /// coordinator refuses at its identity introduction, and joining still needs an admission the
    /// user grants. Closing a session also still evicts uncommitted slots
    /// (``setSessionOpen(_:)``). So a link opened here can only ever reach a peer the roster would
    /// admit anyway — and a mesh that cannot re-dial its own members cannot heal a dropped link.
    var mayLinkToDiscoveredPeers: Bool {
        isSessionOpen || currentMesh != nil
    }

    /// Whether a slot whose peer identity has **just verified** may keep its seat.
    ///
    /// The other half of ``mayLinkToDiscoveredPeers``, and the half that keeps "closed" meaning
    /// what it says. Relaxing the three link gates is safe on the QUIC radio because its signed
    /// channel introduction is members-only *before any app frame*; **MC has no such stage** — it
    /// is the shipping default (`MeshTransportFactory.shippingDefault`), its invitation carries no
    /// identity, and the identity introduction one layer up is gated on revoked/blocked keys, not
    /// on the roster. Without this check a stranger seated on a closed mesh would be sent this
    /// device's signed identity introduction and then, on any ``broadcastMeshDescriptor()``, a
    /// **plaintext** descriptor naming the mesh, every member's fingerprint, display name and both
    /// public keys — and `setSessionOpen(false)`'s eviction of uncommitted slots would be undone by
    /// the next discovery.
    ///
    /// So: an **open** mesh (and a device with no mesh) is unchanged — admitting strangers is the
    /// join flow. A **closed** mesh keeps only peers its own roster names, asked through
    /// ``roster`` — the single spelling of "who may connect", derived records first and the
    /// gossiped descriptor as the documented fallback, with `barred` honoured. Admit-by-prompt
    /// still works because ``allowAdmission(_:)`` appends the member to `currentMesh` *before* it
    /// grants, so the requester is a member by the time it re-connects; what it does not get is a
    /// seat it can hold while the prompt is unanswered.
    ///
    /// - Parameter signingPublicKey: The Ed25519 key the identity introduction verified.
    func maySeatVerifiedPeer(signingPublicKey: Data) -> Bool {
        guard currentMesh != nil, !isSessionOpen else { return true }
        return roster.verdict(for: signingPublicKey) == .member
    }

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
    ///
    /// **P4 item 6 (plan §10.6): which ending this is depends on the MERGED derived roster.** A
    /// development on a roster larger than two is a departure with a bounded 15-second handoff to
    /// the reachable members; a genuine final pair — merged roster two, whether or not the partner
    /// is reachable — signs the termination instead. ``MeshDevelopmentPlan`` is the whole decision,
    /// and it never sees how many peers are connected.
    public func leaveSessionAfterNotifyingPeers() async {
        await leaveSessionAfterNotifyingPeers(clock: { Date() })
    }

    /// The clock-injected form, so the 15-second handoff bound is asserted on a test clock rather
    /// than by timing a real send (tier 1, plan §16.2: no wall-clock sleeps).
    ///
    /// - Parameter clock: Read **three** times on the transfer path (P5 item 8) — once when the
    ///   handoff window opens, once when custody is transferred to the reachable custodians, and
    ///   once when the sends have returned — plus once per custodian inside the best-effort push,
    ///   which stops at ``MeshDevelopmentPlan/handoffDeadline`` because a frame cap is not a time
    ///   bound. Reads two and three collapse on the `blockedByStore` path, where neither the
    ///   transfer nor the push runs. The first and last are what
    ///   ``MeshDevelopmentPlan/handoffOutcome(finishedAt:)`` judges against the window.
    func leaveSessionAfterNotifyingPeers(clock: () -> Date) async {
        let plan = developmentPlan(startedAt: clock())
        lastDevelopmentPlan = plan
        let transition = applySessionEvent(plan.ending.requestedEvent)
        // A REFUSED transition (no session was ever started through the machine) leaves the emit
        // alone; only a taken transition whose save failed blocks it.
        let blockedByStore = transition.nextState != nil && lastSessionEffectFailure != nil
        var handoff = MeshCustodyHandoffResult.none
        if !blockedByStore {
            // The count is final BEFORE the record is signed: `canonicalBytes(for:)` binds it and
            // nothing can retract it. Every transfer is a synchronous write over evidence already
            // on this device's disk — no ack, no round trip, no timer — which is exactly why an
            // honest count fits inside fifteen seconds.
            handoff = transferCustodyOnDevelopment(plan, at: clock())
            let emitted = await sendMembershipEvent(
                plan.ending.membershipEvent,
                custodyHandoff: plan.handoffSummary(handedOffItemCount: handoff.transferredItemCount)
            )
            // The push runs BEFORE the sent event, and that order is load-bearing rather than
            // stylistic: `.departureSent` carries `.stopParticipation`, which tears every slot down,
            // so a push after it would have nowhere to send. The record still goes first, so a
            // custodian sees the entitling record before or with the bytes.
            if emitted {
                await pushCustodyToCustodians(handoff, plan: plan, clock: clock)
            } else {
                handoff = handoff.notAnnounced()
                FernletAuditLog.log(
                    "mesh.development.handoffSuppressed", context: ["reason": "recordNotEmitted"]
                )
            }
            applySessionEvent(plan.ending.sentEvent)
        }
        recordDevelopmentHandoffOutcome(plan, finishedAt: clock(), handoff: handoff)
        leaveSession()
    }

    /// Derives plan §10.6's development decision from the merged roster and the branch view.
    ///
    /// - Parameter startedAt: The instant the handoff window opens.
    func developmentPlan(startedAt: Date) -> MeshDevelopmentPlan {
        MeshDevelopmentPlan(
            roster: membershipVerifier?.roster ?? .empty,
            branch: branchView,
            selfFingerprint: identity.localFingerprint,
            startedAt: startedAt
        )
    }

    /// Records how the bounded handoff ended, and what it moved. Never silent: a window that closed
    /// before the sends returned is a named outcome, not a shrug (R7).
    ///
    /// The outcome and the count answer two different questions and may legitimately disagree: the
    /// count is a statement about **this device's own index**, the outcome a statement about the
    /// **clock**. A push that ran out of window after the rungs were written and the record signed
    /// is `.windowExpired` with a non-zero count, and both are true.
    ///
    /// Counts only in the context — never a fingerprint, never content.
    private func recordDevelopmentHandoffOutcome(
        _ plan: MeshDevelopmentPlan, finishedAt: Date, handoff: MeshCustodyHandoffResult
    ) {
        let outcome = plan.handoffOutcome(finishedAt: finishedAt)
        lastDevelopmentHandoffOutcome = outcome
        lastDevelopmentHandoff = handoff
        FernletAuditLog.log(
            "mesh.development.handoff",
            context: [
                "ending": plan.ending.rawValue,
                "outcome": outcome.rawValue,
                "custodians": String(plan.handoffTargets.count),
                "items": String(handoff.transferredItemCount),
                "unplaced": String(handoff.unplacedItemKeys.count),
                "pushed": String(handoff.pushedItemKeys.count)
            ]
        )
    }

    /// Plan §10.6's custody transfer: the departing origin's outstanding content moves to the
    /// reachable custodians ``MeshDevelopmentPlan/handoffTargets`` names, in one index write.
    ///
    /// This is increment 1's **only** relay hop, and it is bounded three ways: the enumerator takes
    /// this device's own fingerprint as its origin filter, so a departing custodian transfers
    /// nothing; a custodian is eligible only if its verified custody receipt is already stored here,
    /// so no rung names a device without the bytes; and only `pending` legs move, so a leg already
    /// handed is never re-handed. A termination transfers nothing at all — the mesh is over and
    /// there is nobody left to be a courier for.
    ///
    /// A store that cannot say what it holds is `.storeUnavailable`, never an empty one: "held
    /// nothing" and "could not read" are two answers and plan §19.5 keeps them apart.
    ///
    /// - Parameters:
    ///   - plan: The development decision, already derived.
    ///   - at: The injected instant, read from the same clock the window opened on.
    /// - Returns: what actually transferred, for the departure record and for the audit line.
    private func transferCustodyOnDevelopment(
        _ plan: MeshDevelopmentPlan, at now: Date
    ) -> MeshCustodyHandoffResult {
        guard plan.ending == .departure else { return .none }
        guard !plan.handoffTargets.isEmpty else { return .suppressed(.noReachableCustodian) }
        guard !plan.handoffHasExpired(at: now) else {
            FernletAuditLog.log(
                "mesh.development.handoffSuppressed", context: ["reason": "windowExpired"]
            )
            // Its own suppression, never `.none`: a device that held placeable items and ran out of
            // clock is not a device that held nothing, and a consumer reading the result alone must
            // not be able to conclude otherwise.
            return .suppressed(.windowExpired)
        }
        guard let roster = membershipVerifier?.roster else { return .none }
        let index: MeshRoutedIndex
        switch routedStore().indexForWriting() {
        case .writable(let loaded, _): index = loaded
        case .unavailable(let cause):
            FernletAuditLog.log(
                "mesh.development.handoffSuppressed", context: ["state": cause.logToken]
            )
            return .suppressed(.storeUnavailable)
        }
        let planned = MeshCustodyHandoffPlan(
            index: index, roster: roster, selfFingerprint: identity.localFingerprint,
            custodians: plan.handoffTargets, at: now
        )
        developmentHandoff = MeshCustodyHandoffScope(
            custodians: Set(plan.handoffTargets), deadline: plan.handoffDeadline
        )
        return applyCustodyHandoff(
            planned, unrestorable: index.itemsWithUnrestorableDelivery(at: now).count, now: now
        )
    }

    /// Applies one planned transfer batch and names everything it could not do.
    private func applyCustodyHandoff(
        _ planned: MeshCustodyHandoffPlan, unrestorable: Int, now: Date
    ) -> MeshCustodyHandoffResult {
        if !planned.unplacedItemKeys.isEmpty {
            FernletAuditLog.log(
                "mesh.development.handoffUnplaced",
                context: ["items": String(planned.unplacedItemKeys.count)]
            )
            noteRoutedUnplaced(planned.unplacedItemKeys, at: now)
        }
        if unrestorable > 0 {
            FernletAuditLog.log(
                "mesh.routedDrain.deliveryUnrestorable", context: ["items": String(unrestorable)]
            )
        }
        guard !planned.transfers.isEmpty else {
            return Self.handoffResult(planned, transferred: [], unrestorable: unrestorable)
        }
        switch routedStore().recordingCustodyHandoff(planned.transfers, now: now) {
        case .completed(let report):
            // R2: bounded by the batch's own size.
            for refusal in report.refused {
                FernletAuditLog.log(
                    "mesh.development.handoffRefused",
                    context: ["reason": refusal.refusal.token]
                )
            }
            return Self.handoffResult(planned, transferred: report.advanced, unrestorable: unrestorable)
        case .refused(let refusal):
            FernletAuditLog.log(
                "mesh.development.handoffRefused", context: ["reason": refusal.rawValue]
            )
            return Self.handoffResult(planned, transferred: [], unrestorable: unrestorable)
        case .unavailable(let cause):
            FernletAuditLog.log(
                "mesh.development.handoffSuppressed", context: ["state": cause.logToken]
            )
            return .suppressed(.storeUnavailable)
        }
    }

    /// The result value one transfer produced: what moved, what could not be placed, and what the
    /// push will therefore offer. **Nothing pushed is counted** — under-reporting is the safe
    /// direction for a claim nobody can retract, and a pushed item becomes servable when the
    /// custodian completes it and its own claim re-evaluates.
    private static func handoffResult(
        _ planned: MeshCustodyHandoffPlan, transferred: [MeshRoutedItemKey], unrestorable: Int
    ) -> MeshCustodyHandoffResult {
        MeshCustodyHandoffResult(
            transferredItemKeys: transferred,
            unplacedItemKeys: planned.unplacedItemKeys,
            pushedItemKeys: planned.unplacedItemKeys,
            unrestorableCount: unrestorable,
            suppression: nil
        )
    }

    /// The best-effort half of the hand-off: the BYTES of items no stored receipt could place, sent
    /// to every reachable custodian so a **pure courier** — a custodian that is not a destination
    /// and has never seen the item — can serve after the heal.
    ///
    /// Everything sent is the origin's exact stored objects, forwarded verbatim; nothing is
    /// re-signed. The batch rides the drain's own narrowing planner, so every per-answer bound and
    /// the per-peer session frame budget apply unchanged, and the loop re-reads the **live** clock
    /// per custodian and stops at the plan's own deadline: `scope.admits(peer, at: plan.startedAt)`
    /// would be vacuous by construction, and a frame cap is not a time bound.
    ///
    /// Uncounted, and it runs only after the departure record was actually emitted — pushing bytes
    /// to custodians that will never be told they are custodians is retention with no delivery.
    private func pushCustodyToCustodians(
        _ handoff: MeshCustodyHandoffResult, plan: MeshDevelopmentPlan, clock: () -> Date
    ) async {
        guard !handoff.pushedItemKeys.isEmpty else { return }
        let pushable = Set(handoff.pushedItemKeys)
        var frames = 0
        var reached = 0
        // R2: bounded by the roster cap.
        for custodian in plan.handoffTargets.prefix(MeshMembershipBounds.maxRosterMembers) {
            let now = clock()
            guard !plan.handoffHasExpired(at: now) else {
                FernletAuditLog.log(
                    "mesh.development.handoffPushDeadline",
                    context: ["left": String(plan.handoffTargets.count - reached)]
                )
                break
            }
            reached += 1
            guard let batch = handoffPushBatch(to: custodian, limitedTo: pushable, at: now) else {
                continue
            }
            if await sendRoutedBulk(batch, to: custodian, now: now) {
                frames += batch.frameCount
            } else if batch.frameCount > 0 {
                FernletAuditLog.log(
                    "mesh.development.handoffPushBudgetSpent",
                    context: ["left": String(routedFramesRemaining(for: custodian))]
                )
            }
        }
        FernletAuditLog.log(
            "mesh.development.handoffPushed",
            context: ["items": String(pushable.count),
                      "custodians": String(reached), "frames": String(frames)]
        )
    }

    /// One custodian's push batch, built through the drain's narrowing initializer so every bound
    /// and the gap computation come from the one place they live.
    private func handoffPushBatch(
        to custodian: String, limitedTo pushable: Set<MeshRoutedItemKey>, at now: Date
    ) -> MeshRoutedDrainPlan? {
        guard let mesh = currentMesh, let index = routedIndexForAdvertising() else { return nil }
        guard let local = MeshRoutedInventory(
            meshID: mesh.meshID, index: index, selfFingerprint: identity.localFingerprint, at: now
        ) else {
            FernletAuditLog.log("mesh.routedDrain.inventoryOverCap")
            return nil
        }
        let bounds = MeshRoutedDrainBounds.increment1
        return MeshCustodyHandoffPlan.pushBatch(
            local: local,
            remote: peerRoutedInventories[custodian]?.inventory
                ?? MeshRoutedInventory(meshID: mesh.meshID, members: [], entries: []),
            offerable: offerableKeys(to: custodian, in: index, at: now).intersection(pushable),
            refused: routedRefusedKeys[custodian] ?? [],
            frameAllowance: min(bounds.maxFrames, routedFramesRemaining(for: custodian))
        )
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
        // authorize the bootstrap admission. P3 item 7: it files that admission here, so the
        // founder is on its OWN derived roster from the first instant — an empty ledger would
        // refuse every record this device signs, including the removals it tallies.
        prepareMembershipLedger(meshID: created.meshID, founderSigningPublicKey: identity.localSigningPublicKey)
        guard seedFounderAdmission(meshID: created.meshID) else {
            abandonUnpersistedSession()
            return
        }
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
        clearMergeWindow()
        offersForegroundResume = false
        idleLapseDeadline = nil
        // Presence is run-scoped: a new session has looked at nothing yet, and carrying a stale
        // branch view across one would scope the next session's rotation to the last one's branch.
        branchView = nil
        lastExternalHeartbeatAt = nil
        restoredSessionContext = nil
        // P5 item 8: every half of the hand-off is run-scoped. The entitlement a development opened
        // dies with the session it belonged to, and so does the origin-served set that bounds a
        // claim to one hop — carrying either across a session would be increment 2 arriving by
        // accident. The deferred-commit queue goes with them: it names items of THIS session's mesh.
        developmentHandoff = nil
        originServedItems.removeAll()
        deferredCustodyCommits.removeAll()
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
        removalQuorum.removeAll()
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
        reGossipedToFingerprints.removeAll()
        routedSweptFingerprints.removeAll()
        clearRoutedDrainState()
        pendingAdoptionLedger = .empty
        isSessionOpen = true
        pendingAdmissionRequests.removeAll()
        pendingRemovalProposals.removeAll()
        removedMemberFingerprints.removeAll()
        approvedRemovalProposalIDs.removeAll()
        removalQuorum.removeAll()
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
            spawnHostPinned { [weak self] in
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
        spawnHostPinned { [weak self] in
            await self?.grantAdmission(to: request, meshID: mesh.meshID)
        }
    }

    /// Mints, files and sends one admission grant.
    ///
    /// Split out of ``allowAdmission(_:)`` so each half stays inside the 60-line rule and so the
    /// ORDER is readable in one screen: sign the token, wrap the key, **file the record durably**,
    /// then answer the requester. Plan §3.6 puts the filing before the answer — a member this
    /// device could not write down is one the next rotation would exclude from the key while the
    /// joiner believed it was in.
    ///
    /// - Parameters:
    ///   - request: The admission request being granted.
    ///   - meshID: The mesh it is granted into.
    private func grantAdmission(to request: MeshAdmissionRequestPayload, meshID: UUID) async {
        let token: MeshAdmissionToken
        do {
            token = try MeshAdmissionToken.signed(
                meshID: meshID,
                joinerFingerprint: request.requesterFingerprint,
                joinerSigningPublicKey: request.requesterSigningPublicKey,
                admitterIdentity: identity
            )
        } catch {
            // Recovery is "no grant" — the requester keeps waiting — so the drop is NAMED (R7);
            // without this the admitter looks like it simply ignored the request.
            FernletAuditLog.log("mesh.admissionGrant.signFailed", context: ["error": String(describing: error)])
            meshError = Self.admissionGrantFailureMessage
            return
        }
        let wrapped = wrappedKeyForGrant(to: request)
        // P3 item 7, plan §3.6: the admitter files its own admission record — durably — BEFORE the
        // grant goes out, and the record is what carries the joiner onto every member's roster.
        guard recordGrantedAdmission(token) else {
            FernletAuditLog.log("mesh.admissionGrant.droppedNotDurable")
            meshError = Self.admissionGrantFailureMessage
            return
        }
        let grant = MeshAdmissionGrantPayload(
            meshID: meshID,
            requesterFingerprint: request.requesterFingerprint,
            token: token,
            encryptedCurrentKey: wrapped.key,
            currentKeyEpoch: wrapped.epoch
        )
        if let slot = slots.first(where: { $0.fingerprint == request.requesterFingerprint }) {
            await sendEnvelope(.meshAdmissionGrant, encodable: grant, via: slot)
        }
        broadcastMeshDescriptor()
    }

    /// Phase 3: wraps the current group key to the slot's handshake-verified key-agreement key, not
    /// the request's claimed one, so a key-substitution attempt cannot redirect the wrap.
    ///
    /// - Returns: The wrapped key and its epoch — `(nil, 0)` when this device holds no group key,
    ///   which is a keyless grant and not a failure.
    private func wrappedKeyForGrant(to request: MeshAdmissionRequestPayload) -> (key: Data?, epoch: Int) {
        guard let groupKey = currentGroupKey else { return (nil, 0) }
        let kaKey = slots.first(where: { $0.fingerprint == request.requesterFingerprint })?
            .verifiedKeyAgreementPublicKey ?? request.requesterKeyAgreementPublicKey
        do {
            return (try identity.encryptGroupKey(groupKey.keyBytes, for: kaKey), groupKey.epoch)
        } catch {
            // The grant still goes out (the joiner is admitted, keyless) — but a wrap failure means
            // they will decrypt nothing until the next rotation, so name it (R7).
            FernletAuditLog.log("mesh.admissionGrant.keyWrapFailed", context: ["error": String(describing: error)])
            return (nil, groupKey.epoch)
        }
    }

    /// What the admitter's own screen says when a grant could not be signed or could not be made
    /// durable. Display copy, held once so the two refusal paths cannot drift apart.
    private static let admissionGrantFailureMessage = "Couldn't let them in just now — ask them to try again."

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
        case .meshRemovalProposalSigned, .meshRemovalVote:
            dispatchRemovalQuorumPayload(payloadType, plaintext: plaintext, decoder: decoder, slot: slot)
        case .meshEncryptedMetadata, .meshCoordinatorBeacon, .meshRotationSync, .meshKeyRotation, .meshKeyAck:
            dispatchGroupKeyPayload(payloadType, plaintext: plaintext, decoder: decoder, peer: peer, slot: slot)
        case .meshMemberAdmission, .meshMemberDeparture, .meshMemberRemoval, .meshTerminated,
             .meshInventoryDigest, .meshEpochHeads:
            dispatchMembershipEventPayload(payloadType, plaintext: plaintext, decoder: decoder, slot: slot)
        case .meshRoutedManifest, .meshRoutedChunk, .meshCustodyReceipt, .meshRecipientReceipt,
             .meshRoutedInventoryDigest, .meshRoutedDrainAnswer:
            dispatchRoutedPayload(payloadType, plaintext: plaintext, decoder: decoder, slot: slot)
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
    /// **The shipping roster source** from P3 item 7 on: ``MeshIntroductionAuthority/roster`` is
    /// `admitted − departed − removed` derived from these records, and ``MeshRotationPolicy``
    /// narrows key distribution to the same set. It is armed on both doors — a founder files its
    /// own admission in ``startNewMesh(name:)``, a joiner files the one it was granted in
    /// ``armJoinerLedger(_:)`` — so the empty-ledger fallback below it is reachable only in tests
    /// and in interop with a build predating these records.
    ///
    /// Fail-closed by construction: a record whose signer this ledger has no admission for is
    /// refused as ``MeshMembershipRecordRejection/signerNotAdmitted``, never guessed at.
    ///
    /// Its durable half is ``MeshSessionContext/ledger`` (item 6), so it owes no wipe row of its
    /// own — the sealed context carries the disposition.
    @ObservationIgnored private(set) var membershipVerifier: MeshMembershipRecordVerifier?

    /// The last inventory digest each peer told us it holds, keyed by fingerprint (plan §10.5).
    ///
    /// A hint, never an authority: it says only whether a full record exchange is worth its bytes.
    /// Bounded by the roster cap so a peer cannot grow it, and cleared with the session.
    @ObservationIgnored private(set) var peerInventoryDigests: [String: MeshInventoryDigest] = [:]

    /// Whether the "roster came from gossip, not from records" line has been written for this
    /// manager. One line, not one per introduction: the fact is about the manager's state, and a
    /// per-read log would drown the diagnostic it exists to give.
    @ObservationIgnored private var loggedLegacyRosterFallback = false

    /// Peers this device has already answered with a bounded record re-gossip, so a peer cannot
    /// spend this device's bytes by re-sending digests. Cleared with the session, bounded by the
    /// roster cap (plan §10.5).
    @ObservationIgnored private var reGossipedToFingerprints: Set<String> = []

    // MARK: Routed drain state (network migration P5 item 6, plan §11, §10.3)

    /// What each peer last told us its ROUTED store holds, plus both halves of the quiescence
    /// predicate item 7's merge window closes on.
    ///
    /// Never ``peerInventoryDigests`` — that is the MEMBERSHIP digest and a structurally different
    /// value under one English word. Bounded by the roster cap; cleared with the session; never
    /// persisted (D-6.14), so it owes no wipe row.
    @ObservationIgnored private(set) var peerRoutedInventories: [String: MeshRoutedPeerInventory] = [:]

    /// Bulk frames this device has already served each peer THIS SESSION, so a peer cannot spend
    /// this device's bytes by re-sending inventories.
    ///
    /// A **budget**, not the once-per-peer boolean ``reGossipedToFingerprints`` is: re-gossip is a
    /// one-shot because a ledger is COMPLETE after one gossip, which a content store never is. Under
    /// a boolean, an item needing more chunks than one answer carries could never finish inside a
    /// six-hour session, and an item minted after the first batch could never be offered at all.
    /// Charged the plan's `frameCount`, so an empty plan costs nothing; refused past
    /// ``MeshRoutedDrainBounds/sessionFramesPerPeer``.
    @ObservationIgnored private var routedDrainFramesSpent: [String: Int] = [:]

    /// Keys this device REFUSED from a peer for a capacity reason, per peer, per session.
    ///
    /// Subtracted from the entitlement set and from the plan's request list, so a refusal does not
    /// re-fire. Bounded by the roster cap and, per peer, by the inventory's entry cap.
    @ObservationIgnored private var routedRefusedKeys: [String: Set<MeshRoutedItemKey>] = [:]

    /// The last capacity refusal the drain took, for item 9 to surface. Frozen reason, no display
    /// text — plan §18.2's copy is the owner's and item 6 ships none.
    @ObservationIgnored private(set) var lastRoutedDrainRefusal: MeshRoutedDrainRefusalNote?

    // MARK: Routed backpressure state (P5 item 9, plan §11)

    /// Items a capacity refusal held back this session — the `.storeFull` half of
    /// ``routedDeliveryHold``.
    ///
    /// Kept APART from the unplaced set on purpose: one key set with one cause field would publish a
    /// count that is the union of two different facts. Bounded by ``MeshRoutedStoreFormat/maxItems``,
    /// and the bound is **named** in an audit line when it is reached rather than passed in silence.
    @ObservationIgnored private var routedHeldBackKeys: Set<MeshRoutedItemKey> = []

    /// Items a departure hand-off could not place with any custodian — item 8's `unplacedItemKeys`,
    /// and the `.notPlaced` half. Same bound, same named audit line.
    @ObservationIgnored private var routedUnplacedKeys: Set<MeshRoutedItemKey> = []

    /// How many held items the byte budget can no longer complete, from the last usage walk.
    ///
    /// Keyless, because the over-commit walk yields a count and not keys, and recomputed at **every**
    /// walk, so it self-clears rather than needing its own heal.
    @ObservationIgnored private var routedUncompletableCount = 0

    /// Peers whose exchange has already spent this session's one capacity sweep, in
    /// ``reGossipedToFingerprints``' exact idiom.
    ///
    /// `answerRoutedInventory` fires once per inventory ADVERTISEMENT, so without this budget the
    /// sweep's index I/O would be per advertisement instead of roster-bounded per session. Cleared
    /// at the same three session resets.
    @ObservationIgnored private var routedSweptFingerprints: Set<String> = []

    /// Items whose MANIFEST this device admitted **from their own origin** — P5 item 8's hop bound.
    ///
    /// A departure record alone bounds nothing: `custodyHandoff.custodianFingerprints` is the whole
    /// roster minus the leaver in every production departure, so on the record alone every member
    /// would be an entitled courier for every other and content would walk A→B→C→D — increment 2's
    /// shape, reached without the device measurement plan §11 gates it on. A device may therefore
    /// claim handed-off legs only for an item the origin served it directly, which makes every
    /// courier of a departed origin's content a device that origin **both** named and served.
    ///
    /// One write site (``noteOriginServed(_:)``, called only from ``ingestRoutedManifest(_:in:)``),
    /// one read site (``claimHandedOffCustody(now:excluding:)``), bounded by the store's item cap,
    /// cleared with the session. Memory-only, so a restart between taking the bytes and claiming
    /// forfeits the claim: fail-closed, named, and item 10's to make durable if it ever should be.
    @ObservationIgnored private var originServedItems: Set<MeshRoutedItemKey> = []

    /// Items this device claimed but could not durably commit custody for inside one evaluation's
    /// cap — P5 item 8's named deferral, made real.
    ///
    /// ``mintClaimedCustody(_:at:)`` is the expensive half (``commitLocalCustody(for:manifest:now:)``
    /// re-streams and re-hashes the whole item), so it is capped per evaluation. The overflow cannot
    /// be re-planned: after the claim every named leg carries a `custodied(by:)` rung, so the
    /// planner's `pending`-only leg list is empty and a re-run plans nothing. Without this queue the
    /// deferral would therefore be permanent rather than latent — no `custodiedAt`, no advertised
    /// custody signer, no forwardable self receipt — so the overflow is carried here and drained at
    /// the **next** claim evaluation, ahead of that evaluation's own work.
    ///
    /// Bounded by the store's item cap, memory-only and session-scoped, exactly like
    /// ``originServedItems``: a commit that is merely late costs a receipt's latency, never a served
    /// byte, because the courier predicate reads the **rung**.
    @ObservationIgnored private var deferredCustodyCommits: [MeshRoutedItemKey] = []

    /// Prepares the verified ledger for a mesh, keyed to the founder's signing key.
    ///
    /// Idempotent for the same mesh so a re-broadcast descriptor cannot discard verified records;
    /// a DIFFERENT mesh id replaces the ledger outright, because records never cross meshes.
    func prepareMembershipLedger(meshID: UUID, founderSigningPublicKey: Data?, now: Date = Date()) {
        if let existing = membershipVerifier, existing.meshID == meshID { return }
        membershipVerifier = MeshMembershipRecordVerifier(
            meshID: meshID,
            founderSigningPublicKey: founderSigningPublicKey
        )
        peerInventoryDigests.removeAll()
        reGossipedToFingerprints.removeAll()
        routedSweptFingerprints.removeAll()
        clearRoutedDrainState()
        // P5 item 9: a different mesh replaces the fact, and the arm is the seam that collects the
        // PREVIOUS session's expired bytes — a routed item expires `hardDeadline + 20 min`, i.e.
        // after the session that could have swept it has ended.
        clearRoutedDeliveryHold()
        sweepRoutedExpiry(now: now)
        pendingAdoptionLedger = .empty
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
        spawnHostPinned { [weak self] in
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
    /// **P4 item 6 gate (plan §10.6).** A termination is refused at the signer when this device's
    /// own merged derived roster is larger than two. The receivers were already safe — a
    /// termination from a larger roster downgrades to the signer's departure when the roster is
    /// derived — so this only stops a device spending its own membership on a record its own view
    /// contradicts, and it is logged rather than silent.
    ///
    /// - Parameters:
    ///   - event: `.meshMemberDeparture` or `.meshTerminated`. Anything else is refused and named
    ///     rather than silently dropped.
    ///   - custodyHandoff: What the leaver hands to the members it can still reach (plan §8.3).
    ///     Only a departure carries one.
    /// - Returns: `true` only when a signed record really was broadcast. Every exit that does not
    ///   broadcast — no mesh, a refused termination, a signature that failed — answers `false`, and
    ///   P5 item 8's development path reads it: rungs written for custodians no record will ever
    ///   name are content stranded, so the count is reported **unplaced** rather than transferred
    ///   and the byte push is skipped. `@discardableResult` because the other four call sites are
    ///   fire-and-forget and were before.
    @discardableResult
    func sendMembershipEvent(
        _ event: PayloadType, custodyHandoff: MeshCustodyHandoffSummary = .none
    ) async -> Bool {
        guard let mesh = currentMesh else {
            FernletAuditLog.log("mesh.membershipEvent.emitNoMesh", context: ["type": event.rawValue])
            return false
        }
        do {
            switch event {
            case .meshMemberDeparture:
                let record = try SignedDepartureRecord.signed(
                    meshID: mesh.meshID, identity: identity, custodyHandoff: custodyHandoff
                )
                await broadcastMembershipFrame(event, MeshMemberDeparturePayload(record: record))
                return true
            case .meshTerminated:
                guard MeshDevelopmentPlan.permitsTermination(membershipVerifier?.roster) else {
                    FernletAuditLog.log("mesh.membershipEvent.terminationRefusedRosterAboveTwo")
                    return false
                }
                let record = try SignedTerminationRecord.signed(
                    meshID: mesh.meshID,
                    identity: identity,
                    rosterAtSigning: presentedRotationRoster()
                )
                await broadcastMembershipFrame(event, MeshTerminationPayload(record: record))
                return true
            default:
                FernletAuditLog.log(
                    "mesh.membershipEvent.emitUnsupported", context: ["type": event.rawValue]
                )
                return false
            }
        } catch {
            // A membership event this device could not SIGN is never sent, and never silent (R7).
            FernletAuditLog.log(
                "mesh.membershipEvent.signFailed",
                context: ["type": event.rawValue, "error": String(describing: error)]
            )
            return false
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
        // The send-side half of the same DEBUG-only diagnostic ``insertMembershipRecord`` carries:
        // a transcript that shows a frame written on one node and nothing on the other names the
        // transport, not the membership rules. Compiled to nothing in Release.
        MeshTransportConsoleLog.echo(
            "membershipFrame sent \(type.rawValue) slots=\(slots.count) "
                + "recipients=\(recipients.map { String($0.count) } ?? "all")"
        )
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
        spawnHostPinned { [weak self] in
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
        mintAndFileRemoval(
            target: proposal.targetFingerprint,
            proposalID: proposal.id,
            voterFingerprints: [proposal.proposerFingerprint, identity.localFingerprint]
        )
    }

    /// Mints, files durably and broadcasts one completed removal — the single body both quorum
    /// paths end in (the legacy two-party second, and P4 item 5's signed quorum).
    ///
    /// Shared deliberately rather than copied: "verify, file, seal, only then announce" is plan
    /// §3.6's order, and two copies of it are two places for the seal and the announcement to drift
    /// apart. The voter list is the caller's, because it is the evidence *that* caller counted.
    ///
    /// - Parameters:
    ///   - target: The member being removed.
    ///   - proposalID: The proposal the quorum formed around.
    ///   - voterFingerprints: The distinct eligible voters this device counted.
    @discardableResult
    private func mintAndFileRemoval(
        target: String,
        proposalID: UUID,
        voterFingerprints: [String]
    ) -> SignedRemovalRecord? {
        guard let mesh = currentMesh else { return nil }
        do {
            let record = try SignedRemovalRecord.signed(
                meshID: mesh.meshID,
                identity: identity,
                memberFingerprint: target,
                proposalID: proposalID,
                voterFingerprints: voterFingerprints
            )
            let snapshot = membershipVerifier
            let before = membershipVerifier?.roster
            recordRejection(membershipVerifier?.insert(record), type: .meshMemberRemoval)
            // Durable before acknowledged (plan §3.6): a record this device could not write down is
            // rolled back, and a rolled-back record is not announced to anybody.
            if membershipVerifier?.roster != before,
               !commitVerifiedRecord(rollingBackTo: snapshot, type: .meshMemberRemoval) {
                return nil
            }
            emitRemovalRecord(record)
            return record
        } catch {
            FernletAuditLog.log(
                "mesh.membershipEvent.signFailed",
                context: ["type": "removal-record", "error": String(describing: error)]
            )
            return nil
        }
    }

    // MARK: - Signed removal quorum (P4 item 5, plan §10.4)

    /// Proposes removing a member under this device's own signature, and counts itself as the first
    /// vote (plan §10.4: "the proposal counts as the proposer's vote").
    ///
    /// Additive beside ``proposeRemoval(of:)``, which is the frozen two-party path already-shipped
    /// builds speak. Nothing is removed here and no record is minted: on a roster of two the
    /// proposal can never reach quorum, which is §10.4's structural answer rather than a special
    /// case anybody had to write.
    ///
    /// - Parameters:
    ///   - targetFingerprint: The member proposed for removal.
    ///   - now: The injected clock — the proposal's own `firstSeenAt` at this device.
    /// - Returns: The signed proposal, or nil when this device could not honestly make one.
    @discardableResult
    func proposeSignedRemoval(of targetFingerprint: String, now: Date = Date()) -> SignedRemovalProposal? {
        guard let mesh = currentMesh, let roster = membershipVerifier?.roster else { return nil }
        guard targetFingerprint != identity.localFingerprint else { return nil }
        do {
            let proposal = try SignedRemovalProposal.signed(
                meshID: mesh.meshID, identity: identity,
                targetFingerprint: targetFingerprint, issuedAt: now
            )
            if let rejection = removalQuorum.open(
                proposal, meshID: mesh.meshID, roster: roster, now: now
            ) {
                logQuorumRejection(rejection, type: .meshRemovalProposalSigned)
                return nil
            }
            broadcastQuorumFrame(.meshRemovalProposalSigned, proposal, about: targetFingerprint)
            evaluateRemovalQuorum(proposal.proposalID, now: now)
            return proposal
        } catch {
            FernletAuditLog.log(
                "mesh.removalQuorum.signFailed",
                context: ["type": PayloadType.meshRemovalProposalSigned.rawValue,
                          "error": String(describing: error)]
            )
            return nil
        }
    }

    /// Votes on a proposal this device already holds.
    ///
    /// - Parameters:
    ///   - proposalID: The open proposal.
    ///   - now: The injected clock.
    /// - Returns: The signed vote, or nil when this device may not cast one.
    @discardableResult
    func voteOnSignedRemoval(_ proposalID: UUID, now: Date = Date()) -> SignedRemovalVote? {
        guard let mesh = currentMesh, let roster = membershipVerifier?.roster else { return nil }
        guard let open = removalQuorum.proposal(proposalID) else { return nil }
        do {
            let vote = try SignedRemovalVote.signed(
                on: open.proposal, identity: identity, castAt: now
            )
            if let rejection = removalQuorum.cast(
                vote, meshID: mesh.meshID, roster: roster, now: now
            ) {
                logQuorumRejection(rejection, type: .meshRemovalVote)
                return nil
            }
            broadcastQuorumFrame(.meshRemovalVote, vote, about: open.proposal.targetFingerprint)
            evaluateRemovalQuorum(proposalID, now: now)
            return vote
        } catch {
            FernletAuditLog.log(
                "mesh.removalQuorum.signFailed",
                context: ["type": PayloadType.meshRemovalVote.rawValue,
                          "error": String(describing: error)]
            )
            return nil
        }
    }

    /// Accepts a peer's signed proposal: verify the signer, then open the live tally.
    ///
    /// Verification and tallying are two different questions and stay two calls — the verifier says
    /// "a member signed this", ``MeshRemovalQuorum`` says "and it is still live, and they may vote".
    ///
    /// - Parameters:
    ///   - proposal: The proposal as it arrived.
    ///   - now: The injected clock; becomes this device's `firstSeenAt` for the five-minute window.
    func receiveSignedRemovalProposal(_ proposal: SignedRemovalProposal, now: Date = Date()) {
        guard let mesh = currentMesh, let verifier = membershipVerifier else { return }
        if let rejection = verifier.verify(proposal) {
            logQuorumRejection(.signerRefused(rejection), type: .meshRemovalProposalSigned)
            return
        }
        if let rejection = removalQuorum.open(
            proposal, meshID: mesh.meshID, roster: verifier.roster, now: now
        ) {
            logQuorumRejection(rejection, type: .meshRemovalProposalSigned)
            return
        }
        evaluateRemovalQuorum(proposal.proposalID, now: now)
    }

    /// Accepts a peer's signed vote and re-evaluates quorum on **this** device's merged roster.
    ///
    /// - Parameters:
    ///   - vote: The vote as it arrived.
    ///   - now: The injected clock.
    func receiveSignedRemovalVote(_ vote: SignedRemovalVote, now: Date = Date()) {
        guard let mesh = currentMesh, let verifier = membershipVerifier else { return }
        if let rejection = verifier.verify(vote) {
            logQuorumRejection(.signerRefused(rejection), type: .meshRemovalVote)
            return
        }
        if let rejection = removalQuorum.cast(
            vote, meshID: mesh.meshID, roster: verifier.roster, now: now
        ) {
            logQuorumRejection(rejection, type: .meshRemovalVote)
            return
        }
        evaluateRemovalQuorum(vote.proposalID, now: now)
    }

    /// Re-derives plan §10.4's arithmetic for one proposal and, on completion, mints the permanent
    /// record.
    ///
    /// **The quorum is this receiver's**, taken from its own merged roster at this instant — so the
    /// same votes complete on a branch of three and stay short on a merged roster of six, with
    /// nothing stored having changed. Completion is guarded by ``approvedRemovalProposalIDs``, the
    /// set the legacy path already uses, so one proposal mints at most one record here however many
    /// late votes arrive.
    ///
    /// Two devices completing independently across a split is expected and needs no coordination:
    /// both records name the same member, and ``MeshMembershipRecordSet`` deduplicates by member
    /// keeping the earliest, so the union converges on one effective removal.
    private func evaluateRemovalQuorum(_ proposalID: UUID, now: Date) {
        guard let roster = membershipVerifier?.roster else { return }
        guard case .complete(let voters) = removalQuorum.verdict(
            for: proposalID, roster: roster, at: now
        ) else { return }
        guard let target = removalQuorum.proposal(proposalID)?.proposal.targetFingerprint else { return }
        removalQuorum.close(proposalID)
        guard approvedRemovalProposalIDs.count < Self.maxRecordedRemovals else { return }
        guard approvedRemovalProposalIDs.insert(proposalID).inserted else { return }
        guard mintAndFileRemoval(
            target: target, proposalID: proposalID, voterFingerprints: voters
        ) != nil else { return }
        // Only AFTER the record is minted, filed and durable: a device that locally forgot a member
        // it could not write a record about would exclude them from the next key with nothing to
        // show any peer for it (plan §3.6's order, at this seam).
        if removedMemberFingerprints.count < Self.maxRecordedRemovals {
            removedMemberFingerprints.insert(target)
        }
        // Plan §8.3: a completed removal is a roster change, so it rotates at once rather than
        // letting the voted-out member hold the key until the next 15-minute tick. The live tunnel
        // is deliberately NOT cut — a removal refuses the removed member's NEXT introduction
        // (`barredMember`), which is the transport's own rule and not this seam's to duplicate.
        requestRotation(cause: .membership)
    }

    /// Broadcasts one quorum frame to every member except the one it is about.
    ///
    /// The exclusion reuses ``membershipEventRecipients(excluding:)`` — the same rule that keeps a
    /// completed removal from reaching its subject — because a target handed the proposal about
    /// itself gains nothing it may act on and a voter list to retaliate against.
    private func broadcastQuorumFrame(_ type: PayloadType, _ payload: some Encodable, about target: String) {
        let recipients = membershipEventRecipients(excluding: target)
        spawnHostPinned { [weak self] in
            await self?.broadcastMembershipFrame(type, payload, to: recipients)
        }
    }

    /// Records one quorum refusal. Never silent (R7): a vote that did not count is a thing a
    /// developer has to be able to see in a log.
    private func logQuorumRejection(_ rejection: MeshRemovalQuorumRejection, type: PayloadType) {
        FernletAuditLog.log(
            "mesh.removalQuorum.rejected",
            context: ["type": type.rawValue, "reason": rejection.diagnosticDescription]
        )
    }

    /// **The one merge path** (plan §10.3): merges another device's ledger into this one, rotates
    /// if the roster moved, and applies what the merged roster says about *this* device.
    ///
    /// Every reconnect reaches it — a blip, a healed partition, an idle-lapse resume and a process
    /// restart all arrive through ``mergeReconnected(_:entry:)``, which is a named front door onto
    /// this call and nothing more. There is deliberately no second merge: a record arriving while a
    /// merge is in flight is offered here too
    /// (``dispatchMembershipEventPayload(_:plaintext:decoder:slot:now:)``) rather than through the
    /// live-record insert, so a returning peer's whole re-gossip mints **one** `.merge` epoch
    /// instead of one `.membership` epoch per record.
    ///
    /// - Parameters:
    ///   - other: The reconnecting side's ledger.
    ///   - now: The injected instant, so P5 item 8's custody claim and item 14's property battery
    ///     run on a deterministic clock. Defaulted, so no existing call site moves.
    /// - Returns: One rejection per record the verifier refused — never a silent drop.
    @discardableResult
    func mergeMembershipLedger(
        _ other: MeshMembershipLedger, now: Date = Date()
    ) -> [MeshMembershipRecordRejection] {
        let snapshot = membershipVerifier
        let before = membershipVerifier?.roster
        let rejections = membershipVerifier?.merge(other) ?? []
        for rejection in rejections {
            FernletAuditLog.log(
                "mesh.membershipEvent.rejected",
                context: ["type": "merge", "reason": rejection.diagnosticDescription]
            )
        }
        let moved = membershipVerifier?.roster != before
        // P3 item 6: a merge that moved the roster is only ACTED on once it is durable — the
        // rotation it would trigger distributes a key against a roster this device could not write
        // down otherwise (plan §3.6).
        if moved, !commitVerifiedRecord(rollingBackTo: snapshot, type: .meshMemberDeparture) {
            return rejections
        }
        // The verdict runs BEFORE the rotation, deliberately: a merge that hands this device its own
        // removal, or a termination the merged roster agrees with, must not also ask for a key it
        // is no longer entitled to hand out (``applyVerifiedSelfRemoval()``'s rule, at the merge
        // seam). Everything else rotates exactly as P3 item 5 had it.
        if moved { refreshBranchViewAfterMerge() }
        // P5 item 8's second claim door: a departure record that arrives during a merge lands here
        // rather than through the live insert, so the claim has to be evaluated on this path too —
        // but only AFTER the verdict, and only when the verdict declined to end the session. That is
        // the same order the live-record twin ``applyRosterMove(_:from:now:)`` uses, and it is
        // load-bearing for the same reason the rotation is: a merge that hands this device its own
        // removal, or a termination the merged roster agrees with, must not first write custody
        // rungs and re-stream content for a mesh it is no longer in.
        if moved, !applyMergedRosterVerdict(from: before) {
            claimHandedOffCustody(now: now)
            requestRotation(cause: .merge)
        }
        return rejections
    }

    /// Re-derives the branch view against the roster a merge just produced.
    ///
    /// ``MeshBranchView`` is a snapshot taken at the last ``evaluatePartition(reachable:now:)``, and
    /// a merge moves the roster underneath it: a member whose departure record arrived in the union
    /// would otherwise keep answering ``MeshMemberPresence/present`` until the next evaluation,
    /// which contradicts item 1's own rule that **presence is only defined over the derived
    /// roster**. Reachability is unchanged and is carried over verbatim.
    ///
    /// Deliberately **not** ``evaluatePartition(reachable:now:)``: that runs
    /// ``MeshPartitionDetector`` and can raise `linksLost` / `linksRestored`, and a merge is not a
    /// reachability change. Nothing here raises an event, and nothing reads a clock.
    private func refreshBranchViewAfterMerge() {
        guard let previous = branchView, let roster = membershipVerifier?.roster,
              !roster.members.isEmpty else { return }
        branchView = MeshBranchView(
            roster: roster,
            reachable: Set(previous.presentFingerprints),
            selfFingerprint: identity.localFingerprint
        )
    }

    /// What a merged roster says about **this** device (plan §10.3's "hard records win over soft
    /// presence", in its sharpest form).
    ///
    /// The live-record path has ``applyRosterMove(_:from:)`` for this; the merge path needs its own
    /// because a merge applies a whole ledger rather than one decoded frame, so there is no
    /// "accepted record" to switch on. A departure or removal that happened in the other branch of
    /// a split arrives *only* as a merged record, and a merge that quietly left this device
    /// believing it was still a member — or still in a mesh whose termination it had just been
    /// handed — would be the merge failing open.
    ///
    /// Deliberately conditional on having *been* a member: a ledger that grows from empty (a
    /// founder mid-bootstrap, a joiner adopting) has never admitted this device, and that is not an
    /// ejection.
    ///
    /// - Parameter before: The derived roster as it was before the merge.
    /// - Returns: `true` when the merged roster ENDED this device's session, so the caller must not
    ///   go on to request a rotation.
    @discardableResult
    private func applyMergedRosterVerdict(from before: MeshDerivedRoster?) -> Bool {
        guard let after = membershipVerifier?.roster else { return false }
        if after.status == .terminated {
            applyVerifiedTermination()
            return true
        }
        let wasMember = before?.contains(fingerprint: identity.localFingerprint) ?? false
        guard wasMember, !after.contains(fingerprint: identity.localFingerprint) else { return false }
        applyVerifiedSelfRemoval()
        return true
    }

    // MARK: - The single merge path (network migration P4 item 2, plan §10.3)

    /// Which reconnect the merge now in flight came through, or nil when none is.
    ///
    /// Set when a merge begins and read when the records answering it arrive, so the four entries
    /// share one path *and* stay distinguishable in a log line. Memory-only: which door a merge
    /// used is not a fact about membership.
    @ObservationIgnored private(set) var pendingMergeEntry: MeshMergeEntry?

    /// The merge exchange now in flight, or nil when none is (P5 item 7, plan §22.3).
    ///
    /// The **one** stored source of truth for "a merge is open": ``awaitingResumeMerge`` is
    /// `mergeWindow != nil`, so the observable six test files read cannot disagree with the state
    /// the closing rule runs on. Memory-only and session-scoped — nothing here is persisted, so it
    /// owes no wipe row and no schema (D-7.21).
    @ObservationIgnored private(set) var mergeWindow: MeshMergeWindow?

    /// Why the last merge window closed. A frozen diagnostic token in the idiom of
    /// ``lastMergeEntry``: it lets a suite assert *why* a window closed rather than merely that it
    /// did. Never display copy.
    @ObservationIgnored private(set) var lastMergeClosure: MeshMergeWindowClosure?

    /// The entry of the last merge this device applied. A frozen diagnostic token, in the idiom of
    /// ``lastRotationCause`` — read by suites and audit lines, never shown to a person.
    @ObservationIgnored private(set) var lastMergeEntry: MeshMergeEntry?

    /// How many offers have gone through ``mergeMembershipLedger(_:)`` via the front door.
    ///
    /// The observable seam behind "there is exactly one merge path": a suite drives all four
    /// reconnects and asserts each one moved this counter, which no bypass could do.
    @ObservationIgnored private(set) var mergeApplicationCount = 0

    /// How many epoch heads the cap has pushed off the **sealed** head set, past
    /// ``MeshSessionContextSchema/maxEpochHeads``.
    ///
    /// Plan §21.3: the cap is an assertion, not a knob. Non-zero means something produced more
    /// branch heads than any partition shape can justify, so it is surfaced here and in the audit
    /// log rather than swallowed by a `prefix`.
    ///
    /// Counted **at the one context writer** (``writeSessionContext(base:identity:head:terminating:token:store:)``)
    /// and only after the bytes seal, because that is where the drop actually happens: a count
    /// taken at the merge, against the keyring head and the offer, measures a different set from
    /// the one the file holds and would be a number that is merely plausible. Every head goes
    /// through that writer, so this covers a rotation's head as well as a merge's — which is the
    /// honest scope, the cap being a property of the persisted set and not of the merge.
    @ObservationIgnored private(set) var droppedEpochHeadCount = 0

    /// Every epoch branch head this device has sealed — the memory mirror of
    /// ``MeshSessionContext/epochHeads`` (P4 item 3, plan §10.3).
    ///
    /// It exists so a merge can take plan §10.3's `max` **without a disk read on the rotation
    /// path**: the successor's counter is `max + 1` over the folded head set, and the folded set is
    /// the file's, not the keyring's — a branch that rotated twice while this one rotated once puts
    /// a higher counter in the file than this device's own key ever had.
    ///
    /// Written at exactly one place, ``writeSessionContext(base:identity:head:terminating:token:store:)``,
    /// and only **after the bytes seal** (plan §3.6): a mirror updated before the seal would name
    /// heads a restart could not reproduce, and the merge would mint a successor to an epoch that
    /// never existed. Refilled from the file at launch. Nothing new is persisted — schema stays 2.
    @ObservationIgnored private(set) var knownEpochHeads: [MeshEpochRef] = []

    /// The heads a merge still has to resolve: those at or above this device's current epoch.
    ///
    /// Once the successor is adopted, both old branch heads sit strictly below the keyring's head
    /// and drop out of this set — which is what stops a merge that has already been reconciled from
    /// asking for another `.merge` rotation on every subsequent reconnect.
    private var unresolvedEpochHeads: [MeshEpochRef] {
        guard let head = epochKeyring?.head else { return knownEpochHeads }
        var live = knownEpochHeads.filter { $0.counter >= head.counter }
        // This device's own epoch belongs in the set whether or not the file has caught up with
        // it: the divergence a merge has to see is "the branch I am on versus the branch you are
        // on", and leaving the local head out would make a two-branch merge look converged.
        if !live.contains(head) { live.append(head) }
        return live
    }

    /// The head plan §10.3's "counter = max + 1" counts up from: the highest in
    /// ``MeshEpochRefOrder`` among the sealed head set and this device's own current epoch.
    ///
    /// **Not a winner, and not a tie-break.** It contributes a *number* and nothing else — the
    /// successor's identity is derived from the minting coordinator, so neither coexisting head
    /// survives. And it cannot be steered by a clock: a ``MeshEpochRef`` carries no timestamp, so a
    /// forged far-future stamp anywhere on the wire has nothing here to influence.
    var rotationBasisHead: MeshEpochRef? {
        var candidates = knownEpochHeads
        if let head = epochKeyring?.head, !candidates.contains(head) { candidates.append(head) }
        return MeshEpochAcceptance.highestHead(candidates)
    }

    /// The heads this device presents in a `fernlet.mesh.epoch-heads.v1` frame: the epoch it is on
    /// plus every unresolved branch head it has folded. Empty for a device on no epoch, which says
    /// "no epoch" by sending nothing rather than by sending an empty set.
    private func presentedEpochHeads() -> [MeshEpochRef] {
        var heads: [MeshEpochRef] = []
        if let head = epochKeyring?.head { heads.append(head) }
        for candidate in unresolvedEpochHeads where !heads.contains(candidate) {
            heads.append(candidate)
        }
        return Array(heads.prefix(MeshSessionContextSchema.maxEpochHeads))
    }

    /// **The front door to the one merge path** (plan §10.3): applies a reconnecting peer's offer.
    ///
    /// The order is plan §3.6's. The peer's epoch heads are folded and sealed **first** — a head is
    /// not a roster change, and a device that acts on a merged roster while still unable to name
    /// the branch it is reconciling with has acknowledged something it cannot write down. Then the
    /// records go through ``mergeMembershipLedger(_:)``, which commits before it rotates.
    ///
    /// Heads *coexist*: two branches that rotated at the same counter hold distinct refs (their
    /// coordinators cannot be the same member), both survive here, and minting the strictly greater
    /// successor that retires them is P4 item 3 — deliberately not this call.
    ///
    /// - Parameters:
    ///   - offer: What the reconnecting side holds.
    ///   - entry: Which reconnect this is. Recorded, never branched on.
    ///   - now: The injected instant, threaded to ``mergeMembershipLedger(_:now:)``. Defaulted.
    /// - Returns: One rejection per record the verifier refused.
    @discardableResult
    func mergeReconnected(
        _ offer: MeshMergeOffer, entry: MeshMergeEntry, now: Date = Date()
    ) -> [MeshMembershipRecordRejection] {
        // Captured BEFORE the fold: the post-merge proof (P5 item 7) is owed exactly when this
        // fold moved the local digest, and after the fold there is nothing left to compare against.
        let previousDigest = membershipVerifier?.localInventoryDigest
        lastMergeEntry = entry
        mergeApplicationCount += 1
        foldEpochHeads(offer.epochHeads)
        let rejections = mergeMembershipLedger(offer.ledger, now: now)
        requestMergeRotationForDivergentHeads()
        advanceMergeWindowAfterFold(previousDigest: previousDigest)
        FernletAuditLog.log(
            "mesh.merge.applied",
            context: ["entry": entry.rawValue, "rejected": String(rejections.count)]
        )
        return rejections
    }

    /// Seals a reconnecting peer's epoch heads into ``MeshSessionContext/epochHeads``.
    ///
    /// One ``persistSessionContext(addingEpochHead:)`` per head, because that writer is the single
    /// seam every head goes through and it already folds through
    /// ``MeshMergeOffer/foldedHeads(_:adding:limit:)``. Nothing is counted here on purpose: the
    /// only set the cap can bite is the one being written, so ``droppedEpochHeadCount`` is measured
    /// there, against the heads that actually sealed (plan §21.3 — named, never truncated silently).
    ///
    /// - Parameter heads: The heads the peer offered; empty is the common case and does nothing.
    private func foldEpochHeads(_ heads: [MeshEpochRef]) {
        guard !heads.isEmpty else { return }
        for head in heads.prefix(MeshMergeOffer.maxFoldedHeads) {
            persistSessionContext(addingEpochHead: head)
        }
    }

    /// **The mint** (P4 item 3, plan §10.3): asks for the one `.merge` rotation that retires two
    /// coexisting heads, when the folded head set actually holds two.
    ///
    /// ## Why it asks rather than mints
    ///
    /// It goes through ``requestRotation(cause:)`` — the single rotation entry — so the mint
    /// **cannot** double-rotate. A merge that both moved the roster and reconciled a divergence
    /// calls this and ``mergeMembershipLedger(_:)``'s own `.merge` request inside the same
    /// synchronous turn, and the second lands in the first's open 2-second coalescing window: one
    /// armed task, one rotation, cause `.merge` (P3 item 5's `merge > membership > timer` rank).
    /// Which device actually runs it is settled at fire time by ``isLocalCoordinator()``, so a
    /// non-coordinator consumes the trigger and stops.
    ///
    /// ## Who mints, precisely
    ///
    /// Nothing here chooses. The minter is ``epochCoordinatorFingerprint`` — the lowest fingerprint
    /// of ``presentedRotationRoster()``, which is the merged derived roster, intersected with the
    /// present set while partitioned (item 1's branch rule). That is the whole function: the merged
    /// roster and the counters, and nothing else. When the merged view's coordinator is not at the
    /// merge, the branch scoping already answers "lowest fingerprint present among the merging
    /// parties" (§3's default), and a later merge that reaches the absent coordinator supersedes
    /// with a strictly greater counter.
    ///
    /// ## Why it is gated on still being a member
    ///
    /// ``mergeMembershipLedger(_:)`` runs ``applyMergedRosterVerdict(from:)`` before its own
    /// rotation for the reason stated there: a merge that hands this device its own removal, or a
    /// termination the merged roster agrees with, must not then ask for a key it is not entitled to
    /// distribute. This call sits after that verdict, so it repeats the check rather than
    /// re-opening the hole.
    private func requestMergeRotationForDivergentHeads() {
        guard let roster = membershipVerifier?.roster else { return }
        guard roster.status != .terminated,
              roster.contains(fingerprint: identity.localFingerprint) else { return }
        guard MeshEpochAcceptance.isDivergent(unresolvedEpochHeads) else { return }
        FernletAuditLog.log(
            "mesh.merge.epochsDivergent",
            context: ["heads": String(unresolvedEpochHeads.count)]
        )
        requestRotation(cause: .merge)
    }

    /// Sends this device's signed epoch head(s) to one peer — the **epoch half** of plan §10.3's
    /// union exchange (P4 item 3), on the ask (``beginMergeExchange(entry:now:)``) and on the answer
    /// (``receiveInventoryDigest(_:)``'s mismatch branch) alike.
    ///
    /// It is the one thing the reconnect exchange could not compose out of frames that already
    /// existed: `fernlet.mesh.inventory-digest.v1` describes *records*, and its signed bytes are
    /// pinned by a golden, so widening it to carry heads would have been a wire decision rather
    /// than a merge fix. `fernlet.mesh.epoch-heads.v1` is additive — its own token, its own
    /// registered signature domain, its own golden — and no existing golden moves.
    ///
    /// - Parameter recipients: The members to tell, or nil for every slot.
    func sendEpochHeads(to recipients: Set<String>? = nil) async {
        guard let mesh = currentMesh else { return }
        if let recipients, recipients.isEmpty { return }
        let heads = presentedEpochHeads()
        guard !heads.isEmpty else { return }
        do {
            let payload = try MeshEpochHeadsPayload.signed(
                meshID: mesh.meshID, heads: heads, identity: identity
            )
            await broadcastMembershipFrame(.meshEpochHeads, payload, to: recipients)
        } catch {
            FernletAuditLog.log(
                "mesh.membershipEvent.signFailed",
                context: ["type": PayloadType.meshEpochHeads.rawValue,
                          "error": String(describing: error)]
            )
        }
    }

    /// Folds a peer's verified epoch heads, then asks for the merge's one rotation if the union
    /// diverges (P4 item 3).
    ///
    /// A head set that differs is not an error — that is the signal, exactly as a differing
    /// inventory digest is. Nothing is adopted from it: a head is a *name*, the key that belongs to
    /// it never crossed, and the resolution is always the successor a coordinator mints.
    private func receiveEpochHeads(_ payload: MeshEpochHeadsPayload) {
        guard let verifier = membershipVerifier else { return }
        if let rejection = verifier.verify(payload) {
            FernletAuditLog.log(
                "mesh.membershipEvent.rejected",
                context: ["type": PayloadType.meshEpochHeads.rawValue,
                          "reason": rejection.diagnosticDescription]
            )
            return
        }
        foldEpochHeads(payload.heads)
        FernletAuditLog.log(
            "mesh.merge.epochHeadsFolded", context: ["count": String(payload.heads.count)]
        )
        requestMergeRotationForDivergentHeads()
    }

    /// Asks every committed peer what it holds — the **ask half** of plan §10.3's union exchange.
    ///
    /// No new frame: `fernlet.mesh.inventory-digest.v1` is the ask that already exists, and a
    /// differing digest is answered with the bounded record re-gossip (§10.5), whose frames land
    /// back in the one merge path because ``awaitingResumeMerge`` is set while this is outstanding.
    /// A peer whose digest MATCHES has proved its half; the window ends only once EVERY peer it is
    /// waiting on has done so (P5 item 7, ``concludeMergeIfConverged()``).
    ///
    /// - Parameters:
    ///   - entry: Which reconnect opened this exchange.
    ///   - now: The instant the window records as its opening. Recorded, never compared (D-7.24) —
    ///     injected so the value type needs no clock of its own.
    private func beginMergeExchange(entry: MeshMergeEntry, now: Date = Date()) {
        // A launch restore arms `.processRestart` before any session event can run, and it outranks
        // whichever door the user's resume happened to use: the ledger being merged FROM came off
        // the disk, which is the fact worth recording.
        let resolved = pendingMergeEntry == .processRestart ? MeshMergeEntry.processRestart : entry
        pendingMergeEntry = resolved
        // Armed exactly where `awaitingResumeMerge = true` stood, BEFORE both guards, so the
        // observable is bit-identical to P4's on the verifier-less and empty-recipient paths.
        mergeWindow = .opened(at: now)
        guard let verifier = membershipVerifier else { return }
        FernletAuditLog.log("mesh.merge.exchangeOpened", context: ["entry": resolved.rawValue])
        let recipients = Set(activeSlots.compactMap(\.fingerprint))
        guard !recipients.isEmpty else { return }
        mergeWindow = mergeWindow?.asking(recipients).advertised(verifier.localInventoryDigest)
        spawnHostPinned { [weak self] in await self?.sendInventoryDigest(to: recipients) }
        // The epoch half of the same exchange (§10.3, item 3). Separate frame, same ask: a member
        // on no epoch sends nothing, so a reconnect between two unkeyed devices costs no bytes.
        spawnHostPinned { [weak self] in await self?.sendEpochHeads(to: recipients) }
        // The ROUTED half of the same exchange (§10.3, §22.1, item 6). Separate `Task`, like the
        // epoch half: a store that cannot say what it holds must not stop the membership ask.
        spawnHostPinned { [weak self] in await self?.sendRoutedInventory(to: recipients) }
    }

    /// Ends the merge now in flight **iff** every peer it is still waiting on has matched.
    ///
    /// The name is the rule: P4's `concludeMerge()` closed on the FIRST peer digest that matched
    /// local inventory, which across eight members shut the window while other peers' re-gossips
    /// were still in flight — defect 2d, one record labelled `.membership` instead of `.merge`. The
    /// safe rule is `pending = (asked ∪ answered) ∩ reachable ∖ matched`, and "answered" sits inside
    /// `pending` precisely so a responder that merely answered can never close anything: that is the
    /// P4 item 2c deadlock, reopened from the other side.
    ///
    /// A function called `conclude` that may not conclude is how a counter creeps back in, so the
    /// verdict is computed by the value type and this only spends it. The audit token is unchanged.
    private func concludeMergeIfConverged() {
        guard let window = mergeWindow else { return }
        guard case .closed(let closure) = window.verdict(reachable: reachableMergePeers()) else {
            return
        }
        lastMergeClosure = closure
        clearMergeWindow()
        pendingMergeEntry = nil
        FernletAuditLog.log(
            "mesh.merge.converged",
            context: ["closure": closure.rawValue,
                      "asked": String(window.asked.count),
                      "matched": String(window.matched.count),
                      "routedConverged": routedConvergenceSummary(for: window)]
        )
    }

    /// Drops the window, and **only** the window.
    ///
    /// Deliberately not a place to clear anything else. `pendingMergeEntry` keeps its own **four**
    /// write sites — two armings (``beginMergeExchange(entry:now:)``, and the launch restore's
    /// `.processRestart`, which arms it with no window at all) and two clearings
    /// (``concludeMergeIfConverged()``, ``abandonMergeExchange()``) — because folding the entry in
    /// here would silently destroy that restore arming, which `resetSessionStateMachine` would then
    /// reach through this helper. The drain's per-peer session budget is never refunded by a flap
    /// either. `MeshRoutedDrainWallTests.theMergeWindowIsClearedAtExactlyItsOwnSites` pins all three
    /// asymmetries by name: this body and `resetSessionStateMachine`'s never mention
    /// `pendingMergeEntry`, and `abandonMergeExchange`'s mentions neither `clearRoutedDrainState()`
    /// nor `reGossipedToFingerprints`.
    private func clearMergeWindow() {
        mergeWindow = nil
    }

    /// The peers the closing rule may still be waiting on: **every committed slot** ∩ the derived
    /// roster.
    ///
    /// Deliberately not ``activeSlots`` and deliberately not ``reachableRosterFingerprints()``,
    /// which is the obvious wrong reuse. `.active` is a UWB *distance rank* capped at three of five
    /// slots, a fourth slot is born `.lightweight`, and `rerankSlots()` re-assigns every slot's kind
    /// from a ranging sample — while `broadcastMembershipFrame` iterates **all** slots, so a
    /// `.lightweight` peer sends and receives digests and re-gossip exactly like an active one.
    /// A rank change would otherwise subtract a peer that is still re-gossiping and restore 2d,
    /// triggered by a distance sample with no membership meaning.
    ///
    /// - Returns: The reachable roster members, self excluded by the slot derivation.
    private func reachableMergePeers() -> Set<String> {
        guard let roster = membershipVerifier?.roster else { return [] }
        return Set(slots.compactMap(\.fingerprint).filter { roster.contains(fingerprint: $0) })
    }

    /// Records that `peer` proved convergence, then spends the verdict.
    ///
    /// - Parameter peer: The sender whose digest equalled local inventory.
    private func recordMergeMatch(_ peer: String) {
        mergeWindow = mergeWindow?.matching(peer)
        concludeMergeIfConverged()
    }

    /// Records that this device answered `peer`'s mismatched digest — and **attempts no close**.
    ///
    /// Answering adds an obligation and un-matches its sender; it can never discharge one. The
    /// close attempt is deliberately absent so that no future edit can turn "answered" into "done".
    ///
    /// - Parameter peer: The sender whose digest did not match.
    private func recordMergeAnswer(_ peer: String) {
        mergeWindow = mergeWindow?.answering(peer)
    }

    /// Advances the window after a fold moved this device's ledger: re-evaluate, prove, then judge.
    ///
    /// The order is the mechanism. `owed` is captured **before** the re-evaluation and before the
    /// verdict, because a device whose fold both caught it up *and* emptied its pending set has
    /// converged and is the only device that can tell its peers so — gating the proof on "the window
    /// is still open" silences exactly the device that just converged, and leaves its peer holding
    /// an open window for the rest of the session.
    ///
    /// - Parameter previousDigest: This device's inventory digest before the fold, or nil when it
    ///   had no verifier.
    private func advanceMergeWindowAfterFold(previousDigest: MeshInventoryDigest?) {
        guard let window = mergeWindow, let verifier = membershipVerifier else { return }
        let reachable = reachableMergePeers()
        let owed = window.pending(reachable: reachable)
        let local = verifier.localInventoryDigest
        mergeWindow = window.reEvaluated(against: local, reachable: reachable)
        if local != previousDigest, mergeWindow?.needsProof(of: local) == true {
            readvertiseMergeProof(to: owed)
        }
        concludeMergeIfConverged()
    }

    /// Tells the peers this window still owes what this device now holds — the **occasion** the
    /// strict closing rule needs, and the only thing item 7 puts on the wire.
    ///
    /// It is not an ask: it opens no window, re-arms no ``pendingMergeEntry``, sends no epoch heads
    /// (the peer's answer to a mismatched proof already carries them) and carries **no routed
    /// twin** — a routed re-advertisement would put bulk on a door sized for three asks and re-spend
    /// the drain's per-peer session budget. Value-gated and bounded: one frame per distinct local
    /// digest, at most ``MeshMergeWindow/maxProofs`` per window, emitted only when a grow-only capped
    /// ledger actually grows. A proof that matches at the peer provokes no reply at all.
    ///
    /// - Parameter peers: The pending set captured before the fold's re-evaluation.
    private func readvertiseMergeProof(to peers: Set<String>) {
        guard !peers.isEmpty, let verifier = membershipVerifier else { return }
        mergeWindow = mergeWindow?.advertised(verifier.localInventoryDigest)
        spawnHostPinned { [weak self] in await self?.sendInventoryDigest(to: peers) }
        FernletAuditLog.log(
            "mesh.merge.proofReadvertised", context: ["peers": String(peers.count)]
        )
    }

    /// How many of the peers a window waited on are ROUTED-converged, as `"3/5"`.
    ///
    /// Recorded on the audit line and **gating nothing** (D-7.11): the membership digest closes the
    /// window, quiescence does not. Both halves of
    /// ``MeshRoutedInventoryDelta/converged(local:peerReportsQuiescent:)`` were recorded in the same
    /// pass that minted the answer (D-6.18), so this is a pure read — no `load()`, no store touch,
    /// counts only and never a fingerprint.
    ///
    /// - Parameter window: The window about to close.
    /// - Returns: The frozen `"converged/waited"` count.
    private func routedConvergenceSummary(for window: MeshMergeWindow) -> String {
        let waited = window.asked.union(window.answered)
        let converged = waited.filter { peer in
            guard let state = peerRoutedInventories[peer] else { return false }
            return state.localQuiescent && state.reportsQuiescent
        }
        return "\(converged.count)/\(waited.count)"
    }

    // MARK: - Ledger bootstrap and convergence (network migration P3 item 7, plan §8.3, §10.5)

    /// Files this device's own admission when it FOUNDS a mesh, so the ledger starts one member
    /// long instead of empty.
    ///
    /// The record is a self-admission: joiner and admitter are both this device, and the token is
    /// signed with the same key ``prepareMembershipLedger(meshID:founderSigningPublicKey:)`` just
    /// named as the root — which is exactly the bootstrap
    /// ``MeshMembershipRecordVerifier/insert(_:)-(SignedAdmissionRecord)`` allows into an empty
    /// ledger, and the one every joiner later re-verifies as the chain's root.
    ///
    /// It is also what closes item 3b's gap: with the founder on its own roster, the local insert
    /// in ``emitApprovedRemovalRecord(_:)`` stops being refused `signerNotAdmitted`.
    ///
    /// - Returns: `false` when the record could not be signed or was refused — a mesh with no
    ///   ledger root would derive an empty roster on its own founder, so the founding is abandoned
    ///   rather than half-done.
    private func seedFounderAdmission(meshID: UUID) -> Bool {
        do {
            let token = try MeshAdmissionToken.signed(
                meshID: meshID,
                joinerFingerprint: identity.localFingerprint,
                joinerSigningPublicKey: identity.localSigningPublicKey,
                admitterIdentity: identity
            )
            let rejection = membershipVerifier?.insert(SignedAdmissionRecord(token: token))
            recordRejection(rejection, type: .meshMemberAdmission)
            return rejection == nil
        } catch {
            FernletAuditLog.log(
                "mesh.membershipEvent.signFailed",
                context: ["type": "founder-admission", "error": String(describing: error)]
            )
            return false
        }
    }

    /// Arms a JOINER's ledger from the admission it has just verified (plan §8.3, §20.4.4).
    ///
    /// The root is the admitter's key rather than the founder's, because the admitter's key is the
    /// one this device authenticated: `admissionGrantIsAuthorized` refuses a grant whose token root
    /// is not the envelope's authenticated sender, and a current member of the mesh at that. The
    /// provisional root is replaced by the real founder the moment a peer's ledger arrives and
    /// ``MeshLedgerAdoption/adopt(offered:ownAdmission:meshID:)`` proves the chain reaches this
    /// device's admitter.
    ///
    /// Idempotent: a ledger that has already grown past its bootstrap is left alone, so a
    /// re-delivered grant cannot discard verified records.
    ///
    /// `internal` rather than `private` for the same reason the other join seams are: the grant path
    /// it sits on needs a live QUIC peer to drive end to end, and this is the tier-1 door.
    ///
    /// - Returns: `false` only when the verified admission was itself refused — which would leave
    ///   this device believing it had joined a mesh whose roster does not contain it.
    func armJoinerLedger(_ grant: MeshAdmissionGrantPayload, now: Date = Date()) -> Bool {
        let ownAdmission = SignedAdmissionRecord(token: grant.token)
        if let existing = membershipVerifier, existing.meshID == grant.meshID,
           !existing.ledger.admissions.isEmpty {
            return true
        }
        switch MeshLedgerAdoption.bootstrapVerifier(meshID: grant.meshID, ownAdmission: ownAdmission) {
        case .adopted(let verifier):
            membershipVerifier = verifier
            peerInventoryDigests.removeAll()
            reGossipedToFingerprints.removeAll()
            routedSweptFingerprints.removeAll()
            clearRoutedDrainState()
            // P5 item 9, as at the founder's arm: a new mesh replaces the fact, and this is where the
            // previous session's expired bytes are collected.
            clearRoutedDeliveryHold()
            sweepRoutedExpiry(now: now)
            pendingAdoptionLedger = .empty
            FernletAuditLog.log("mesh.membershipLedger.bootstrapped")
            return true
        case .refused(let refusal):
            FernletAuditLog.log(
                "mesh.membershipLedger.bootstrapRefused",
                context: ["reason": refusal.diagnosticDescription]
            )
            return false
        }
    }

    /// Sends this device's signed inventory digest to one peer — the ask half of plan §10.5's
    /// exchange. A digest is a hint: it says only whether a record exchange is worth its bytes.
    ///
    /// - Parameter recipients: The members to ask, or nil for every slot. P4 item 2 passes the
    ///   committed set explicitly on a reconnect: a digest is member business, and an empty set is
    ///   "nobody to ask", not "ask everybody".
    func sendInventoryDigest(to recipients: Set<String>? = nil) async {
        guard let mesh = currentMesh, let verifier = membershipVerifier else { return }
        if let recipients, recipients.isEmpty { return }
        do {
            let payload = try MeshInventoryDigestPayload.signed(
                meshID: mesh.meshID, ledger: verifier.ledger, identity: identity
            )
            await broadcastMembershipFrame(.meshInventoryDigest, payload, to: recipients)
        } catch {
            FernletAuditLog.log(
                "mesh.membershipEvent.signFailed",
                context: ["type": PayloadType.meshInventoryDigest.rawValue,
                          "error": String(describing: error)]
            )
        }
    }

    /// The answer half of plan §10.5: a bounded re-gossip of every record this device holds, as the
    /// frames that already carry them.
    ///
    /// No new wire token — §10.5 names none, and each record kind already has a frame it is
    /// verified from, so a peer applies a re-gossiped record through exactly the door a live one
    /// comes through. Bounded twice over: the four record sets are capped by
    /// ``MeshMembershipBounds`` (16/16/16/1), and ``maxReGossipFrames`` caps the batch itself.
    ///
    /// **Once per peer per session.** ``reGossipedToFingerprints`` is what stops a peer spending
    /// this device's bytes by re-sending digests, and it is why the exchange converges in one round
    /// trip instead of looping: a record frame never provokes another digest.
    ///
    /// - Parameter fingerprint: The member to answer.
    private func reGossipRecords(to fingerprint: String) async {
        guard let verifier = membershipVerifier else { return }
        guard reGossipedToFingerprints.count < MeshMembershipBounds.maxRosterMembers,
              reGossipedToFingerprints.insert(fingerprint).inserted else { return }
        let recipients: Set<String> = [fingerprint]
        var sent = 0
        let ledger = verifier.ledger
        for record in ledger.admissions.all.prefix(Self.maxReGossipFrames) {
            await broadcastMembershipFrame(
                .meshMemberAdmission, MeshMemberAdmissionPayload(record: record), to: recipients
            )
            sent += 1
        }
        for record in ledger.departures.all.prefix(max(0, Self.maxReGossipFrames - sent)) {
            await broadcastMembershipFrame(
                .meshMemberDeparture, MeshMemberDeparturePayload(record: record), to: recipients
            )
            sent += 1
        }
        for record in ledger.removals.all.prefix(max(0, Self.maxReGossipFrames - sent)) {
            await broadcastMembershipFrame(
                .meshMemberRemoval, MeshMemberRemovalPayload(record: record), to: recipients
            )
            sent += 1
        }
        for record in ledger.terminations.all.prefix(max(0, Self.maxReGossipFrames - sent)) {
            await broadcastMembershipFrame(
                .meshTerminated, MeshTerminationPayload(record: record), to: recipients
            )
        }
        FernletAuditLog.log("mesh.membershipLedger.reGossiped", context: ["frames": String(sent)])
    }

    /// The most record frames one re-gossip may send: exactly a full ledger at plan §9's caps
    /// (16 + 16 + 16 + 1). Derived from the bounds rather than picked, so a batch can never leave a
    /// peer short of records this device holds — and it is still a hard constant ceiling (R2/R3).
    static let maxReGossipFrames = MeshMembershipBounds.maxRecordsPerKind * 3
        + MeshMembershipBounds.maxTerminationRecords

    // MARK: - Routed drain (network migration P5 item 6, plan §11, §10.3, §22.1)
    //
    // **Reconnect ≡ merge ≡ relay drain.** There is no second reconnect path: the routed inventory
    // rides the three ASK doors `sendInventoryDigest(to:)` fires from, and the bulk it implies
    // is piggybacked on the exchange that door opened. It rides neither of the membership digest's
    // two non-ask doors (the post-merge proof and the joiner's post-adoption digest, P5 item 7):
    // those open no exchange, and a routed twin there would re-spend the per-peer session budget. The drain adds **no policy** — what may be
    // offered is item 5's `MeshRoutedInventoryDelta`, what may be admitted is items 1–4's verifiers
    // and store doors, and what may be spent is `MeshRoutedDrainPlan`'s bounds.
    //
    // Nothing here reads a `keyEpoch`, a group key, a branch id or a partition id: the routed path's
    // authorisation is the origin's signature plus the per-recipient key wrap, which is exactly what
    // lets item 13 *delete* the three epoch gates rather than loosen them.

    /// The deadline every routed record's expiry is derived from — `createdAt` plus the session
    /// ceiling, the same derivation `sessionContextIdentity` makes.
    ///
    /// Deliberately **not** `sessionCeiling?.hardDeadline`. That timer is armed only when this device
    /// founds a mesh or restores one at launch, so a device that JOINED has none for its whole first
    /// session — and a fail-closed guard on it would drop every inbound manifest, chunk and receipt
    /// on exactly the load-bearing case (a heart to a new member). `currentMesh == nil` is the only
    /// state that fails closed here.
    private var routedHardDeadline: Date? {
        guard let mesh = currentMesh else { return nil }
        return mesh.createdAt.addingTimeInterval(MeshSessionCeiling.ceilingSeconds)
    }

    /// This device's routed store, on the host's own scope. Built **per call**, exactly as
    /// `MeshSessionStore(scope: store.meshSessionStorage)` is: the store is a stateless value over a
    /// directory plus a keychain service, and holding one would invent a lifetime question.
    private func routedStore() -> MeshRoutedStore {
        MeshRoutedStore(scope: store.meshRoutedStorage)
    }

    /// Forgets every peer's routed drain state. Called from the three session resets
    /// `peerInventoryDigests` is cleared at, and nowhere else.
    ///
    /// **Not** from `abandonMergeExchange()`: a partition is not a new session, and refunding the
    /// per-peer frame budget on every flap is precisely what that budget exists to prevent.
    private func clearRoutedDrainState() {
        peerRoutedInventories.removeAll()
        routedDrainFramesSpent.removeAll()
        routedRefusedKeys.removeAll()
        lastRoutedDrainRefusal = nil
    }

    /// The index this device may advertise from, or nil when the store is not in a state that KNOWS
    /// what it holds.
    ///
    /// Two states know: `.loaded`, and `.absent`, which is answered from the file read **before the
    /// seal key is ever consulted** and therefore cannot be a locked-device artefact — its empty
    /// digest is byte-identical to a loaded empty store's, i.e. true. The other three advertise
    /// nothing: an empty digest is a positive claim ("I hold nothing"), and a `.deferred` store
    /// cannot honestly make it. Nil means **no digest, no answer, no offers** — structurally, because
    /// `routedDrainPlan(for:at:)` returns nil too, not as a second condition at a send site.
    ///
    /// Never `indexForWriting()`: that collapses `.absent` into a writable empty index and would
    /// answer out of a *deferred* classification path.
    private func routedIndexForAdvertising() -> MeshRoutedIndex? {
        switch routedStore().load() {
        case .loaded(let index, _):
            return index
        case .absent:
            return MeshRoutedIndex()
        case .deferred(let deferral):
            FernletAuditLog.log(
                "mesh.routedStore.advertisementSuppressed",
                context: ["state": "deferred", "reason": deferral.reason.rawValue]
            )
            return nil
        case .corrupt:
            FernletAuditLog.log("mesh.routedStore.advertisementSuppressed", context: ["state": "corrupt"])
            return nil
        case .refused:
            FernletAuditLog.log("mesh.routedStore.advertisementSuppressed", context: ["state": "sealRefused"])
            return nil
        }
    }

    /// Sends this device's signed ROUTED inventory to one peer or to the named set — the routed twin
    /// of ``sendInventoryDigest(to:)``, on that function's three **ask** doors and no others.
    ///
    /// An empty **named** set is "nobody to ask", not "ask everybody", exactly as the membership
    /// digest reads it. The advertisement instant recorded per peer is the **minted payload's own
    /// floored `sentAt`**, never `now` — see ``recordRoutedAdvertisement(to:at:)``.
    ///
    /// - Parameters:
    ///   - recipients: The members to advertise to, or nil for every slot.
    ///   - now: The injected instant, floored into the signed bytes.
    func sendRoutedInventory(to recipients: Set<String>? = nil, now: Date = Date()) async {
        guard let mesh = currentMesh, membershipVerifier != nil else { return }
        if let recipients, recipients.isEmpty { return }
        guard let index = routedIndexForAdvertising() else { return }
        do {
            let payload = try MeshRoutedInventoryPayload.signed(
                meshID: mesh.meshID, index: index, sentAt: now, identity: identity
            )
            await broadcastMembershipFrame(.meshRoutedInventoryDigest, payload, to: recipients)
            let told = recipients ?? Set(activeSlots.compactMap(\.fingerprint))
            // R2: bounded by the roster cap.
            for peer in told { recordRoutedAdvertisement(to: peer, at: payload.sentAt) }
        } catch {
            FernletAuditLog.log(
                "mesh.routedDrain.signFailed",
                context: ["type": PayloadType.meshRoutedInventoryDigest.rawValue,
                          "error": String(describing: error)]
            )
        }
    }

    /// Records which advertisement this device made to `peer`, so an inbound quiescence bit can be
    /// bound to something it really said.
    ///
    /// - Parameter advertisedAt: The **minted payload's** `sentAt`, floored and wire-identical.
    ///   Recording a raw `now` here makes the receiver's exact `Date` equality never hold, so every
    ///   answer is dropped as unbound and the quiescence bit is silently disabled.
    private func recordRoutedAdvertisement(to peer: String, at advertisedAt: Date) {
        guard peerRoutedInventories[peer] != nil
                || peerRoutedInventories.count < MeshMembershipBounds.maxRosterMembers else { return }
        var state = peerRoutedInventories[peer] ?? MeshRoutedPeerInventory()
        state.advertisedAt = advertisedAt
        peerRoutedInventories[peer] = state          // R3: bounded map
    }

    /// The bulk frames `peer` may still make this device serve this session, floored at zero.
    private func routedFramesRemaining(for peer: String) -> Int {
        max(0, MeshRoutedDrainBounds.sessionFramesPerPeer - (routedDrainFramesSpent[peer] ?? 0))
    }

    /// Charges `count` bulk frames to `peer`'s session budget, or refuses the whole batch.
    ///
    /// Refused **whole** rather than part-served: a partially charged batch would be a second
    /// accounting rule, and the remainder is re-planned against the true remainder at the next
    /// exchange.
    private func chargeRoutedFrames(_ count: Int, to peer: String) -> Bool {
        guard routedDrainFramesSpent[peer] != nil
                || routedDrainFramesSpent.count < MeshMembershipBounds.maxRosterMembers else {
            return false
        }
        guard routedFramesRemaining(for: peer) >= count else { return false }
        routedDrainFramesSpent[peer] = (routedDrainFramesSpent[peer] ?? 0) + count   // R3: bounded map
        return true
    }

    /// The routed family of the dispatch switch (R4: one function per case family).
    ///
    /// Member business, so a COMMITTED slot is required — the same boundary the membership, removal,
    /// photo and registry families enforce. The four CONTENT families additionally need the session's
    /// hard deadline, because every routed record's expiry is checked against it; the two digest
    /// families do not, so a device that has left still answers what it holds.
    ///
    /// `internal`, and clock-injectable, for the same reason the other tier-1 seams are: every
    /// admission, every `isLive(at:)` check and every `deliveredAt` stamp downstream of here reads
    /// this one instant, so a battery that cannot supply it is testing the wall clock.
    ///
    /// - Parameter now: The injected instant for this frame's whole ingest (D-6.12).
    func dispatchRoutedPayload(
        _ type: PayloadType,
        plaintext: Data,
        decoder: JSONDecoder,
        slot: PeerSlot?,
        now: Date = Date()
    ) {
        guard let senderFingerprint = slot?.fingerprint else {
            FernletAuditLog.log("mesh.routedDrain.droppedUncommittedSlot", context: ["type": type.rawValue])
            return
        }
        guard let mesh = currentMesh, let verifier = membershipVerifier else {
            FernletAuditLog.log("mesh.routedDrain.droppedNoLedger", context: ["type": type.rawValue])
            return
        }
        if type == .meshRoutedInventoryDigest || type == .meshRoutedDrainAnswer {
            dispatchRoutedDigest(
                type, plaintext: plaintext, decoder: decoder, from: senderFingerprint, now: now
            )
            return
        }
        guard let hardDeadline = routedHardDeadline else {
            FernletAuditLog.log("mesh.routedDrain.droppedNoCeiling", context: ["type": type.rawValue])
            return
        }
        let context = RoutedIngestContext(
            meshID: mesh.meshID, ledger: verifier.ledger, hardDeadline: hardDeadline,
            sender: senderFingerprint, now: now
        )
        dispatchRoutedContent(type, plaintext: plaintext, decoder: decoder, in: context)
    }

    /// The two digest-family frames, which need no deadline: an advertisement and an answer both
    /// describe state rather than carry content.
    private func dispatchRoutedDigest(
        _ type: PayloadType,
        plaintext: Data,
        decoder: JSONDecoder,
        from senderFingerprint: String,
        now: Date
    ) {
        switch type {
        case .meshRoutedInventoryDigest:
            guard let payload = try? decoder.decode(MeshRoutedInventoryPayload.self, from: plaintext) else {
                FernletAuditLog.log("mesh.routedDrain.undecodable", context: ["type": type.rawValue])
                return
            }
            receiveRoutedInventory(payload, from: senderFingerprint, now: now)
        default:
            guard let payload = try? decoder.decode(MeshRoutedDrainAnswerPayload.self, from: plaintext) else {
                FernletAuditLog.log("mesh.routedDrain.undecodable", context: ["type": type.rawValue])
                return
            }
            receiveRoutedDrainAnswer(payload, from: senderFingerprint)
        }
    }

    /// The four content families: manifest, chunk, custody receipt, recipient receipt. One ingest
    /// function each, one admission call site each — the shape item 12 wires its replay window into.
    private func dispatchRoutedContent(
        _ type: PayloadType,
        plaintext: Data,
        decoder: JSONDecoder,
        in context: RoutedIngestContext
    ) {
        switch type {
        case .meshRoutedManifest:
            guard let payload = try? decoder.decode(MeshRoutedManifestPayload.self, from: plaintext) else {
                FernletAuditLog.log("mesh.routedDrain.undecodable", context: ["type": type.rawValue])
                return
            }
            ingestRoutedManifest(payload, in: context)
        case .meshRoutedChunk:
            guard let payload = try? decoder.decode(MeshChunkPayload.self, from: plaintext) else {
                FernletAuditLog.log("mesh.routedDrain.undecodable", context: ["type": type.rawValue])
                return
            }
            ingestRoutedChunk(payload, in: context)
        case .meshCustodyReceipt:
            guard let payload = try? decoder.decode(MeshCustodyReceiptPayload.self, from: plaintext) else {
                FernletAuditLog.log("mesh.routedDrain.undecodable", context: ["type": type.rawValue])
                return
            }
            ingestCustodyReceipt(payload, in: context)
        default:
            guard let payload = try? decoder.decode(MeshRecipientReceiptPayload.self, from: plaintext) else {
                FernletAuditLog.log("mesh.routedDrain.undecodable", context: ["type": type.rawValue])
                return
            }
            ingestRecipientReceipt(payload, in: context)
        }
    }

    /// The four values every routed content ingest needs, gathered once at the dispatch door.
    private struct RoutedIngestContext {
        /// The session both sides are in.
        let meshID: UUID
        /// The merged membership ledger every routed verifier resolves keys from.
        let ledger: MeshMembershipLedger
        /// `createdAt + ceiling` — what every routed expiry is checked against.
        let hardDeadline: Date
        /// The committed slot's fingerprint.
        let sender: String
        /// The injected instant for this frame's whole ingest.
        let now: Date
    }

    /// A peer's advertisement: verify, record, and answer it — the drain's own door.
    ///
    /// Deliberately **not** piggybacked inside ``receiveInventoryDigest(_:)``: that function returns
    /// at its match branch before its own `Task` whenever the two membership ledgers already agree,
    /// which is the commonest blip — so a routed answer placed there would never run in exactly the
    /// case the drain exists for.
    ///
    /// `internal` for the same reason ``dispatchRoutedPayload(_:plaintext:decoder:slot:now:)`` is:
    /// the drain's battery drives one advertisement at a time, on an injected clock.
    func receiveRoutedInventory(
        _ payload: MeshRoutedInventoryPayload,
        from senderFingerprint: String,
        now: Date = Date()
    ) {
        guard let mesh = currentMesh, let verifier = membershipVerifier else { return }
        let door = MeshRoutedInventoryVerifier(meshID: mesh.meshID, ledger: verifier.ledger)
        if let rejection = door.verify(payload) {
            FernletAuditLog.log(
                "mesh.routedDrain.rejected",
                context: ["type": PayloadType.meshRoutedInventoryDigest.rawValue,
                          "reason": rejection.rawValue]
            )
            return
        }
        // A digest describes the sender's own disk and nobody forwards one on its behalf.
        guard payload.senderFingerprint == senderFingerprint else {
            FernletAuditLog.log("mesh.routedDrain.rejected", context: ["reason": "senderMismatch"])
            return
        }
        recordPeerRoutedInventory(payload, from: senderFingerprint)
        answerRoutedInventory(from: senderFingerprint, advertisedAt: payload.sentAt, now: now)
    }

    /// Stores the peer's verified holdings, bounded by the roster cap.
    private func recordPeerRoutedInventory(
        _ payload: MeshRoutedInventoryPayload,
        from senderFingerprint: String
    ) {
        guard peerRoutedInventories[senderFingerprint] != nil
                || peerRoutedInventories.count < MeshMembershipBounds.maxRosterMembers else { return }
        var state = peerRoutedInventories[senderFingerprint] ?? MeshRoutedPeerInventory()
        state.inventory = payload.inventory
        state.inventorySentAt = payload.sentAt
        peerRoutedInventories[senderFingerprint] = state          // R3: bounded map
    }

    /// Plans the answer, records **both** quiescence halves, and puts the frames on the wire in one
    /// `Task` in a fixed order: the answer bit, then manifests, then chunks, then receipts.
    ///
    /// A store that cannot say what it holds vends no plan, so this sends **nothing at all** — not an
    /// empty answer, and certainly not a `quiescent: true` a deferred store cannot honestly claim.
    private func answerRoutedInventory(from peer: String, advertisedAt: Date, now: Date) {
        // P5 item 8's fourth claim door, and the only one that fires for an item that is ALREADY
        // complete under a record that is ALREADY folded. A custodian whose store answered
        // `deferred`, `corrupt` or seal-`refused` when the departure record landed is reachable by
        // no other event: the two ledger doors need a new roster move and `finishLocalRungs` needs
        // an item to become complete. It costs nothing in the common case — the claim returns
        // before any I/O when no leaver named this device.
        claimHandedOffCustody(now: now)
        // P5 item 9's reclaim + expiry seam, one line from the claim door on purpose: this is the
        // one entry that fires on every reconnect and already re-reads the store. Budgeted once per
        // peer per session, so the cost is roster-bounded rather than per advertisement.
        sweepRoutedCapacity(for: peer, now: now)
        guard let planned = routedDrainPlan(for: peer, at: now) else { return }
        recordLocalQuiescence(planned.quiescent, for: peer, asOf: advertisedAt)
        spawnHostPinned { [weak self] in
            await self?.sendRoutedDrainAnswer(
                to: peer, advertisedAt: advertisedAt, quiescent: planned.quiescent, now: now
            )
            await self?.sendRoutedDrainBatch(planned.plan, to: peer, now: now)
        }
    }

    /// Records THIS device's own half of `converged(local:peerReportsQuiescent:)`, in the same pass
    /// that minted the answer — so item 7's window rule is a pure read rather than a second
    /// main-actor `load()` and comparison.
    private func recordLocalQuiescence(_ quiescent: Bool, for peer: String, asOf: Date) {
        guard var state = peerRoutedInventories[peer] else { return }
        state.localQuiescent = quiescent
        state.quiescentLocalAsOf = asOf
        peerRoutedInventories[peer] = state
    }

    /// The peer's answer to an advertisement of ours: verified, **bound**, then recorded.
    ///
    /// Two bindings beyond the signature, both refusing in the fail-closed direction: the answer must
    /// name **this device** as the advertiser, and must name an instant this device really
    /// advertised. Without them a replayed `quiescent: true` closes a merge window that should still
    /// be open. A bit that does not bind is logged and dropped, never recorded.
    private func receiveRoutedDrainAnswer(
        _ payload: MeshRoutedDrainAnswerPayload,
        from senderFingerprint: String
    ) {
        guard let mesh = currentMesh, let verifier = membershipVerifier else { return }
        let door = MeshRoutedDrainAnswerVerifier(meshID: mesh.meshID, ledger: verifier.ledger)
        if let rejection = door.verify(payload) {
            FernletAuditLog.log(
                "mesh.routedDrain.rejected",
                context: ["type": PayloadType.meshRoutedDrainAnswer.rawValue,
                          "reason": rejection.rawValue]
            )
            return
        }
        guard payload.senderFingerprint == senderFingerprint,
              payload.answer.advertiserFingerprint == identity.localFingerprint,
              var state = peerRoutedInventories[senderFingerprint],
              state.advertisedAt == payload.answer.advertisedAt else {
            FernletAuditLog.log("mesh.merge.routedQuiescentUnbound", context: ["peer": "redacted"])
            return
        }
        state.reportsQuiescent = payload.answer.quiescent
        state.quiescentAsOf = payload.answer.advertisedAt
        peerRoutedInventories[senderFingerprint] = state
        FernletAuditLog.log(
            "mesh.merge.routedQuiescent",
            context: ["peerQuiescent": String(payload.answer.quiescent),
                      "localQuiescent": String(state.localQuiescent)]
        )
    }

    /// A peer's manifest: verified, gated to increment 1, admitted.
    ///
    /// The gate is `self ∈ destinations || sender == origin` — an item addressed to this device, or a
    /// departing origin's hand-off. A third party's manifest is refused: without the clause any
    /// admitted member could fill this device's caps with content nobody asked it to hold, and §6.1
    /// would then mint a custody receipt for each. The second disjunct is not slack — a departure
    /// custodian is not a destination, and the custody evidence cannot land until the record exists.
    private func ingestRoutedManifest(_ payload: MeshRoutedManifestPayload, in context: RoutedIngestContext) {
        let manifest = payload.manifest
        let door = MeshRoutedManifestVerifier(
            meshID: context.meshID, hardDeadline: context.hardDeadline, ledger: context.ledger,
            acceptedTypeTokens: MeshRoutedAckStageTable.increment1.tokens
        )
        if let rejection = door.verify(manifest) {
            FernletAuditLog.log(
                "mesh.routedDrain.rejected",
                context: ["type": PayloadType.meshRoutedManifest.rawValue, "reason": rejection.rawValue]
            )
            dropParkedSetIfTerminal(rejection, manifest: manifest, in: context)
            return
        }
        guard manifest.destinations.contains(identity.localFingerprint)
                || context.sender == manifest.originFingerprint else {
            FernletAuditLog.log(
                "mesh.routedDrain.rejected", context: ["reason": "notADestinationOrHandoff"]
            )
            return
        }
        let key = MeshRoutedItemKey(manifest)
        // P5 item 8's hop bound, recorded at the ONE door that knows who sent the frame. This is
        // beside the admission clause above, never part of it: the clause is unchanged and stays
        // walled, and a device may claim handed-off legs only for an item it took from the origin
        // itself. Increment 2's `sender ∈ handoffTargets` widening is declined here by name.
        if context.sender == manifest.originFingerprint { noteOriginServed(key) }
        let outcome = routedStore().admittingManifest(manifest, now: context.now)
        recordRoutedOutcome(outcome, type: .meshRoutedManifest, key: key, in: context)
        guard let admission = outcome.value, admission.receivedCount == admission.expectedCount else {
            return
        }
        finishLocalRungs(for: key, from: context.sender, now: context.now)
    }

    /// A peer's chunk: the manifest it belongs to (nil means "not seen yet", which is admissible and
    /// parks the set), then verify, then stage.
    ///
    /// **D-6.16's second door.** For a KNOWN item the manifest gate has already run, so the chunk
    /// inherits it. For an UNKNOWN one there is nothing to inherit and `MeshChunkVerifier` has no
    /// manifest to bind against, so the retention clause is restated here: only the ORIGIN may park
    /// a set on this device. Without it the harm the manifest door refuses — any admitted member
    /// filling this device's caps with content nobody asked it to hold — is reachable through the
    /// other door, one parked chunk set at a time.
    private func ingestRoutedChunk(_ payload: MeshChunkPayload, in context: RoutedIngestContext) {
        let chunk = payload.chunk
        let key = MeshRoutedItemKey(chunk)
        let store = routedStore()
        let known = store.forwardableManifest(item: key)
        guard case .completed(let manifest) = known else {
            recordRoutedOutcome(known, type: .meshRoutedChunk, key: key, in: context)
            return
        }
        guard manifest != nil || context.sender == chunk.originFingerprint else {
            FernletAuditLog.log(
                "mesh.routedDrain.rejected", context: ["reason": "unknownItemNotFromOrigin"]
            )
            return
        }
        let door = MeshChunkVerifier(
            meshID: context.meshID, hardDeadline: context.hardDeadline,
            ledger: context.ledger, manifest: manifest
        )
        if let rejection = door.verify(chunk) {
            FernletAuditLog.log(
                "mesh.routedDrain.rejected",
                context: ["type": PayloadType.meshRoutedChunk.rawValue, "reason": rejection.rawValue]
            )
            return
        }
        let outcome = store.stagingChunk(chunk, now: context.now)
        recordRoutedOutcome(
            outcome, type: .meshRoutedChunk, key: key, in: context, verdict: RoutedDrainVerdict.of
        )
        guard let admission = outcome.value,
              case .admitted(let received, let expected) = admission, received == expected else {
            return
        }
        finishLocalRungs(for: key, from: context.sender, now: context.now)
    }

    /// A forwarded custody receipt: verified, then stored as **evidence only**. It advances no rung —
    /// the drain was handed no hand-off decision and has no honest destination list to state.
    private func ingestCustodyReceipt(
        _ payload: MeshCustodyReceiptPayload, in context: RoutedIngestContext
    ) {
        let receipt = payload.receipt
        let key = MeshRoutedItemKey(
            originFingerprint: receipt.originFingerprint, itemID: receipt.itemID
        )
        let store = routedStore()
        let known = store.forwardableManifest(item: key)
        guard case .completed(let manifest) = known else {
            recordRoutedOutcome(known, type: .meshCustodyReceipt, key: key, in: context)
            return
        }
        let door = MeshCustodyReceiptVerifier(
            meshID: context.meshID, hardDeadline: context.hardDeadline,
            ledger: context.ledger, manifest: manifest
        )
        if let rejection = door.verify(receipt) {
            FernletAuditLog.log(
                "mesh.routedDrain.rejected",
                context: ["type": PayloadType.meshCustodyReceipt.rawValue, "reason": rejection.rawValue]
            )
            return
        }
        let outcome = store.recordingCustodyEvidence(item: key, receipt: receipt, now: context.now)
        recordRoutedOutcome(outcome, type: .meshCustodyReceipt, key: key, in: context)
    }

    /// A forwarded recipient receipt: verified, then filed through the store's **one** writer of a
    /// `delivered` rung.
    private func ingestRecipientReceipt(
        _ payload: MeshRecipientReceiptPayload, in context: RoutedIngestContext
    ) {
        let receipt = payload.receipt
        let key = MeshRoutedItemKey(
            originFingerprint: receipt.originFingerprint, itemID: receipt.itemID
        )
        let store = routedStore()
        let known = store.forwardableManifest(item: key)
        guard case .completed(let manifest) = known else {
            recordRoutedOutcome(known, type: .meshRecipientReceipt, key: key, in: context)
            return
        }
        let door = MeshRecipientReceiptVerifier(
            meshID: context.meshID, hardDeadline: context.hardDeadline,
            ledger: context.ledger, manifest: manifest
        )
        if let rejection = door.verify(receipt) {
            FernletAuditLog.log(
                "mesh.routedDrain.rejected",
                context: ["type": PayloadType.meshRecipientReceipt.rawValue, "reason": rejection.rawValue]
            )
            return
        }
        let outcome = store.recordingRecipientReceipt(item: key, receipt: receipt, now: context.now)
        recordRoutedOutcome(
            outcome, type: .meshRecipientReceipt, key: key, in: context,
            verdict: RoutedDrainVerdict.of
        )
        reclaimDeliveredItem(key, now: context.now)
    }

    /// The frozen-English name of what a store verb actually did, so an admission line distinguishes
    /// a real admission from a duplicate or from an INNER refusal.
    ///
    /// `MeshRoutedOutcome.completed` means only "the door ran"; a `stagingChunk` that answers
    /// `.completed(.refused(.conflictingChunk))` — a peer offering different bytes for a slot this
    /// device already holds, which is an attack signal — is not an admission, and logging it as one
    /// satisfies "no drop is unnamed" in letter only.
    private nonisolated enum RoutedDrainVerdict {

        /// A verb whose value carries no verdict of its own.
        static let admitted = "admitted"

        /// One chunk's verdict, including the inner refusal.
        static func of(_ admission: MeshChunkAdmission) -> String {
            switch admission {
            case .admitted: return admitted
            case .duplicate: return "duplicate"
            case .refused(let refusal): return refusal.rawValue
            }
        }

        /// One delivery-map write's verdict, including the inner refusal.
        static func of(_ outcome: MeshDeliveryOutcome) -> String {
            switch outcome {
            case .updated: return admitted
            case .refused(let refusal): return refusal.rawValue
            }
        }
    }

    /// Every store outcome is named: a drop with no line is the violation, and an admission line
    /// carries the verdict BY NAME so an inner refusal cannot hide inside `.completed`.
    ///
    /// A CAPACITY refusal is additionally remembered — the key joins this peer's refused set so the
    /// exchange stops re-asking for it, and ``lastRoutedDrainRefusal`` is the seam item 9 surfaces it
    /// from. `deferred`, seal-`refused` and `corrupt` stay three distinct answers and change nothing:
    /// deferred is never treated as empty, and quarantine is the store's own explicit call.
    private func recordRoutedOutcome<Value>(
        _ outcome: MeshRoutedOutcome<Value>,
        type: PayloadType,
        key: MeshRoutedItemKey,
        in context: RoutedIngestContext,
        verdict: (Value) -> String = { _ in RoutedDrainVerdict.admitted }
    ) {
        switch outcome {
        case .completed(let value):
            FernletAuditLog.log(
                "mesh.routedDrain.admitted",
                context: ["type": type.rawValue, "verdict": verdict(value)]
            )
        case .refused(let refusal):
            FernletAuditLog.log(
                "mesh.routedDrain.refused",
                context: ["type": type.rawValue, "reason": refusal.rawValue]
            )
            guard Self.routedCapacityRefusals.contains(refusal) else { return }
            noteRoutedCapacityRefusal(refusal, key: key, from: context.sender, at: context.now)
        case .unavailable(let cause):
            FernletAuditLog.log(
                "mesh.routedDrain.unavailable",
                context: ["type": type.rawValue, "state": cause.logToken]
            )
        }
    }

    /// The store refusals that mean "this device is full", as opposed to "this frame was wrong".
    /// Only these narrow the entitlement set — a wrong frame corrects itself from the next inventory.
    static let routedCapacityRefusals: Set<MeshRoutedStoreRefusal> = [
        .capacityItems, .capacityBytes, .capacityChunkFiles, .capacityChunksPerItem,
        .capacityReceipts, .capacityRecipientReceipts
    ]

    /// The subset that may raise a **user-visible** `.storeFull` hold: the three STORE-level
    /// admission caps, and exactly the three ``MeshRoutedCapacityUsage/hasRoomToAdmit`` measures.
    ///
    /// The other three are per-**item** caps: `.capacityChunksPerItem` bounds one item's slot count,
    /// `.capacityReceipts` and `.capacityRecipientReceipts` are raised only against an item this
    /// device already holds. Two consequences follow, and both are why they are excluded rather than
    /// merely undocumented. A key refused for a receipt cap is in the index, so counting it beside
    /// `routedUncompletableCount` could count one item twice; and the store-level release predicate
    /// cannot see a per-item cap at all, so a hold raised by one would be dropped by a sweep while
    /// the door that raised it still refuses. They stay refused by name, audited and
    /// entitlement-narrowing — they are simply not "this device is full" for a reader.
    static let routedStoreFullRefusals: Set<MeshRoutedStoreRefusal> = [
        .capacityItems, .capacityBytes, .capacityChunkFiles
    ]

    /// How many orphan-sweep passes one swept peer may spend. Each pass is itself bounded by
    /// `2 × maxHeldChunkFiles` inside the store, so two passes drain any directory a bounded store
    /// can produce (R2).
    static let routedOrphanSweepPasses = 2

    /// Remembers one capacity refusal so it neither re-fires nor stays invisible.
    private func noteRoutedCapacityRefusal(
        _ refusal: MeshRoutedStoreRefusal, key: MeshRoutedItemKey, from peer: String, at now: Date
    ) {
        lastRoutedDrainRefusal = MeshRoutedDrainRefusalNote(
            peerFingerprint: peer, reason: refusal.rawValue, at: now
        )
        // Only a store-level cap is "full" for a reader — and only those three are what the release
        // predicate can ever see again.
        if Self.routedStoreFullRefusals.contains(refusal) { noteRoutedHeldBack(key, at: now) }
        guard routedRefusedKeys[peer] != nil
                || routedRefusedKeys.count < MeshMembershipBounds.maxRosterMembers else { return }
        var keys = routedRefusedKeys[peer] ?? []
        guard keys.contains(key) || keys.count < MeshRoutedInventoryFormat.maxEntries else {
            FernletAuditLog.log("mesh.routedDrain.refusedSetFull", context: ["reason": refusal.rawValue])
            return
        }
        keys.insert(key)
        routedRefusedKeys[peer] = keys                                // R3: bounded map
    }

    // MARK: Routed backpressure (P5 item 9, plan §11)

    /// Records that a capacity refusal held one key back, so the visible surface can count it.
    ///
    /// `internal` rather than `private` for the reason ``receiveRoutedInventory(_:from:now:)`` is:
    /// the bound this set names when it is full is 1024 distinct signed refusals away from any
    /// wire-driven cell, and a bound asserted only in a comment is not asserted at all. Production
    /// reaches it from exactly one place — ``noteRoutedCapacityRefusal(_:key:from:at:)``.
    func noteRoutedHeldBack(_ key: MeshRoutedItemKey, at now: Date) {
        guard routedHeldBackKeys.contains(key)
                || routedHeldBackKeys.count < MeshRoutedStoreFormat.maxItems else {
            FernletAuditLog.log("mesh.routedDrain.heldBackSetFull")
            refreshRoutedDeliveryHold(at: now)
            return
        }
        routedHeldBackKeys.insert(key)                                // R3: bounded set
        refreshRoutedDeliveryHold(at: now)
    }

    /// Records the items a departure hand-off could not place — the first honest "content this device
    /// could not pass on", given a user-visible consequence rather than one audit line.
    private func noteRoutedUnplaced(_ keys: [MeshRoutedItemKey], at now: Date) {
        // R2: bounded by the hand-off batch, itself bounded by `maxItems`.
        for key in keys {
            guard routedUnplacedKeys.contains(key)
                    || routedUnplacedKeys.count < MeshRoutedStoreFormat.maxItems else {
                FernletAuditLog.log("mesh.development.unplacedSetFull")
                break
            }
            routedUnplacedKeys.insert(key)                            // R3: bounded set
        }
        refreshRoutedDeliveryHold(at: now)
    }

    /// One key actually landed COMPLETE on this device — the one heal that means "the content is
    /// here".
    ///
    /// Deliberately **not** `recordRoutedOutcome`'s `.completed`, which means only "the door ran" and
    /// is also reached by a duplicate, by a conflicting-chunk refusal, by one staged chunk out of
    /// 1024 and by a receipt write involving no content at all. Healing there would clear the surface
    /// while the refused item was still not held — the wall's own failure mode, re-introduced through
    /// the heal.
    private func noteRoutedItemPlaced(_ key: MeshRoutedItemKey, at now: Date) {
        guard routedHeldBackKeys.contains(key) || routedUnplacedKeys.contains(key) else { return }
        routedHeldBackKeys.remove(key)
        routedUnplacedKeys.remove(key)
        refreshRoutedDeliveryHold(at: now)
    }

    /// Forgets every routed hold and the facts behind it. A different mesh replaces them.
    private func clearRoutedDeliveryHold() {
        routedHeldBackKeys.removeAll()
        routedUnplacedKeys.removeAll()
        routedUncompletableCount = 0
        routedDeliveryHold = nil
    }

    /// Derives the one published value from the three facts kept apart, under a FIXED precedence so
    /// the count never unions two of them.
    ///
    /// `.storeFull` outranks `.notPlaced` because storage pressure is the live, actionable condition
    /// while "couldn't hand these on before you left" is a settled fact about a past departure. The
    /// two `.storeFull` inputs are disjoint **because the held-back set is narrowed to the three
    /// store-level admission caps** (``routedStoreFullRefusals``): a key refused by one of those was
    /// never admitted, so it has no record and cannot also be counted as uncompletable. The per-item
    /// receipt caps, which are raised only against a record the index already holds, are excluded for
    /// exactly that reason.
    private func refreshRoutedDeliveryHold(at now: Date) {
        let full = routedHeldBackKeys.count + routedUncompletableCount
        if full > 0 {
            routedDeliveryHold = MeshRoutedDeliveryHold(cause: .storeFull, itemCount: full, at: now)
            return
        }
        guard !routedUnplacedKeys.isEmpty else {
            routedDeliveryHold = nil
            return
        }
        routedDeliveryHold = MeshRoutedDeliveryHold(
            cause: .notPlaced, itemCount: routedUnplacedKeys.count, at: now
        )
    }

    /// Folds one usage walk into the visible surface: the census line, the over-commit count, and the
    /// RELEASE rule.
    ///
    /// The release half is what keeps the surface **true** rather than merely present. A refused key
    /// stays in `routedRefusedKeys` for the session (it is never refunded), so the per-key heal is
    /// unreachable in the common case; the room predicate is what lets the hold fall away once the
    /// store has escaped the condition.
    ///
    /// - Parameters:
    ///   - index: The index just read — the same one the caller already holds, never a second load.
    ///   - store: The store that vended it: it supplies **both** its own cap model and its own chunk
    ///     directory, so the doors and the accounting are one model measured against one disk.
    ///   - now: The injected instant.
    ///   - releaseOnly: `true` at the expiry-only seams, which may clear a hold but must never raise
    ///     one: they run at a session boundary and on the Friends tab, where a fresh `.storeFull`
    ///     would be a claim nobody's action provoked.
    private func recordRoutedCapacityUsage(
        _ index: MeshRoutedIndex, in store: MeshRoutedStore, at now: Date, releaseOnly: Bool = false
    ) {
        let usage = store.capacityUsage(of: index, at: now)
        FernletAuditLog.log(
            "mesh.routedStore.capacity",
            context: ["items": String(usage.itemCount), "parked": String(usage.parkedItemCount),
                      "uncompletable": String(usage.uncompletableItemCount),
                      "unrestorable": String(usage.unrestorableItemCount)]
        )
        routedUncompletableCount = releaseOnly
            ? min(routedUncompletableCount, usage.uncompletableItemCount)
            : usage.uncompletableItemCount
        if usage.hasRoomToAdmit { routedHeldBackKeys.removeAll() }
        // "Fernlet could not hand this on" stops being true once this device no longer holds it.
        // R2: bounded by `maxItems`.
        routedUnplacedKeys = routedUnplacedKeys.filter { index.record(for: $0) != nil }
        refreshRoutedDeliveryHold(at: now)
    }

    /// Frees what has genuinely expired. **No roster**: expiry is a pure clock predicate, which is
    /// what lets this run at a session boundary, where there is no verifier at all.
    ///
    /// Every non-`loaded` state returns, so a locked device sweeps nothing.
    private func sweepRoutedExpiry(now: Date = Date()) {
        let store = routedStore()
        guard case .loaded(let index, _) = store.load() else { return }
        let current = expireIfDue(index, in: store, now: now).index
        recordRoutedCapacityUsage(current, in: store, at: now, releaseOnly: true)
    }

    /// One load in the common case: the fresh index is re-read ONLY when something was actually
    /// removed, because `sweepingExpired` answers a report rather than an index.
    ///
    /// - Returns: the current index, and how many payload files the removal could **not** unlink —
    ///   the count that makes an orphan, and therefore the orphan sweep's trigger.
    private func expireIfDue(
        _ index: MeshRoutedIndex, in store: MeshRoutedStore, now: Date
    ) -> (index: MeshRoutedIndex, filesFailed: Int) {
        guard index.items.contains(where: { !$0.isLive(at: now) }) else { return (index, 0) }
        let failed = recordRoutedSweep(
            store.sweepingExpired(now: now), reason: "expired"
        )?.chunkFilesFailed ?? 0
        guard case .loaded(let fresh, _) = store.load() else { return (index, failed) }
        return (fresh, failed)
    }

    /// Frees what is genuinely free, once per peer per session, bounded twice.
    ///
    /// The budget is spent **after** the store has answered `.loaded`, and that order is
    /// load-bearing: a locked (`deferred`), corrupt or seal-`refused` store does no work at all, and
    /// burning this peer's one entry on it would strand the reclaim — and with it the hold's release
    /// — for the whole session, on a two-node mesh for every peer there is.
    private func sweepRoutedCapacity(for peer: String, now: Date) {
        guard let roster = membershipVerifier?.roster else { return }
        let store = routedStore()
        guard case .loaded(let index, _) = store.load() else { return }
        // The re-gossip budget's idiom: `answerRoutedInventory` fires once per ADVERTISEMENT, so
        // without this the sweep's index I/O would be unbounded per session.
        guard routedSweptFingerprints.count < MeshMembershipBounds.maxRosterMembers,
              routedSweptFingerprints.insert(peer).inserted else { return }
        let expired = expireIfDue(index, in: store, now: now)
        var current = expired.index
        var filesFailed = expired.filesFailed
        let keys = reclaimableRoutedKeys(in: current, roster: roster, now: now)
        if !keys.isEmpty {
            let report = recordRoutedSweep(
                store.dropping(items: keys, reason: "delivered"), reason: "delivered"
            )
            filesFailed += report?.chunkFilesFailed ?? 0
            if case .loaded(let fresh, _) = store.load() { current = fresh }
        }
        sweepRoutedOrphans(in: store, index: current, filesFailed: filesFailed)
        recordRoutedCapacityUsage(current, in: store, at: now)
    }

    /// Reclaims payload files the index no longer names — the **file cap's only recovery route**.
    ///
    /// Orphans are produced by shipping code, which is why this has a caller at all: every drop verb
    /// saves the index **before** unlinking, so a force-quit in that window strands the whole batch,
    /// and `removeChunkFiles` counts an unlink failure rather than swallowing it. Either shows up
    /// here — a non-zero failure count, or a directory holding more payload files than the index
    /// names — and both are conditions the chunk door refuses against but no other sweep can clear.
    ///
    /// Runs inside the caller's once-per-peer budget and never on its own cadence: a directory
    /// listing is `maxHeldChunkFiles` stats on the main actor, which is not a thing to do per frame.
    private func sweepRoutedOrphans(
        in store: MeshRoutedStore, index: MeshRoutedIndex, filesFailed: Int
    ) {
        let onDisk = store.chunkDirectoryFileNames()?.count
        guard filesFailed > 0 || (onDisk ?? 0) > index.heldChunkFileCount else { return }
        // R2: a hard constant ceiling; each pass is itself bounded by `2 × maxHeldChunkFiles`.
        for _ in 0..<Self.routedOrphanSweepPasses {
            let report = recordRoutedSweep(store.sweepingOrphanChunkFiles(), reason: "orphan")
            guard report?.sweptToCeiling == true else { return }
        }
    }

    /// The courier copies this device may reclaim.
    ///
    /// ``MeshRoutedIndex/itemsReclaimableAsCustodian(at:in:for:)`` — never `itemsFullyDelivered` and
    /// never `isAcknowledgedLocally` — intersected with the POSITIVE
    /// ``MeshRoutedIndex/everyDestinationDelivered(_:in:)``, because "nothing outstanding" reads true
    /// for a destination this device's ledger has simply not heard of yet, and a drop on that answer
    /// would delete content still owed while auditing it as `delivered`.
    private func reclaimableRoutedKeys(
        in index: MeshRoutedIndex, roster: MeshDerivedRoster, now: Date
    ) -> [MeshRoutedItemKey] {
        // R2: the source walk is bounded by `maxItems` and each test by `maxDestinations`; the BATCH
        // by `MeshRoutedDrainBounds.increment1.maxItems`. The filter runs BEFORE the prefix —
        // filtering a 16-item prefix would let sixteen vacuous candidates hide every reclaimable item
        // behind them.
        Array(
            index.itemsReclaimableAsCustodian(at: now, in: roster, for: identity.localFingerprint)
                .lazy
                .map(\.key)
                .filter { index.everyDestinationDelivered($0, in: roster) }
                .prefix(MeshRoutedDrainBounds.increment1.maxItems)
        )
    }

    /// One item just became fully delivered here — the only event that can do that without an
    /// exchange. Exactly **one** item, through the same enumerator and the same positive predicate.
    private func reclaimDeliveredItem(_ key: MeshRoutedItemKey, now: Date) {
        guard let roster = membershipVerifier?.roster else { return }
        let store = routedStore()
        guard case .loaded(let index, _) = store.load() else { return }
        let reclaimable = index.itemsReclaimableAsCustodian(
            at: now, in: roster, for: identity.localFingerprint
        )
        guard reclaimable.contains(where: { $0.key == key }),
              index.everyDestinationDelivered(key, in: roster) else { return }
        recordRoutedSweep(store.dropping(item: key, reason: "delivered"), reason: "delivered")
    }

    /// Names what a sweep actually did. A removal with no line is the violation; a sweep that removed
    /// nothing writes nothing, so the census does not drown the diagnostic it exists to give.
    /// - Returns: the report when the sweep completed, so a caller can act on what it actually did —
    ///   nil for a refusal or an unavailable store, which are named on their own lines.
    @discardableResult
    private func recordRoutedSweep(
        _ outcome: MeshRoutedOutcome<MeshRoutedSweepReport>, reason: String
    ) -> MeshRoutedSweepReport? {
        switch outcome {
        case .completed(let report):
            guard report.itemsRemoved > 0 || report.chunkFilesRemoved > 0
                    || report.chunkFilesFailed > 0 else { return report }
            FernletAuditLog.log(
                "mesh.routedStore.swept",
                context: ["reason": reason, "items": String(report.itemsRemoved),
                          "files": String(report.chunkFilesRemoved),
                          "failed": String(report.chunkFilesFailed)]
            )
            return report
        case .refused(let refusal):
            FernletAuditLog.log(
                "mesh.routedStore.sweepRefused", context: ["reason": refusal.rawValue]
            )
            return nil
        case .unavailable(let cause):
            FernletAuditLog.log(
                "mesh.routedStore.sweepUnavailable", context: ["state": cause.logToken]
            )
            return nil
        }
    }

    /// A parked chunk set whose own origin sent a manifest this build refuses TERMINALLY is dropped;
    /// every other rejection keeps the bytes. The rule itself is ``MeshRoutedParkedDrop``.
    private func dropParkedSetIfTerminal(
        _ rejection: MeshRoutedManifestRejection,
        manifest: MeshRoutedManifest,
        in context: RoutedIngestContext
    ) {
        guard let reason = MeshRoutedParkedDrop.reason(
            rejection: rejection,
            senderIsClaimedOrigin: context.sender == manifest.originFingerprint
        ) else { return }
        dropParkedSet(key: MeshRoutedItemKey(manifest), reason: reason)
    }

    /// Drops one PARKED record, and only a parked one — the caller is the guard, exactly as
    /// `itemsReclaimableAsCustodian` is the reclaim's.
    ///
    /// Without the parked test an origin could retract content this device had already fully received
    /// by sending one bogus-type manifest: `dropping(item:reason:)` has no guard of its own.
    private func dropParkedSet(key: MeshRoutedItemKey, reason: MeshRoutedParkedDrop.Reason) {
        let store = routedStore()
        guard case .loaded(let index, _) = store.load(),
              index.record(for: key)?.isParked == true else { return }
        recordRoutedSweep(
            store.dropping(item: key, reason: reason.rawValue), reason: reason.rawValue
        )
    }

    /// An item just became complete on this device: take whichever rungs this device is entitled to,
    /// then send the receipts back to the peer the bytes came from.
    ///
    /// **The drain has no verb of its own that writes a rung**: every rung comes from a
    /// witness-gated commit door, and a witness's initializer is `fileprivate` to its own file.
    ///
    /// Guarded on the rungs still being outstanding, because "complete" is reached again by every
    /// re-sent frame: `admittingManifest` re-admits a byte-identical manifest and answers
    /// `received == expected`, so one cheap duplicate would otherwise re-open the seal key and
    /// re-stream, re-decrypt and re-hash the whole item — up to 256 MiB, on the main actor — and
    /// send two signed receipts back, none of it charged to the peer's frame budget.
    private func finishLocalRungs(for key: MeshRoutedItemKey, from peer: String, now: Date) {
        noteRoutedItemPlaced(key, at: now)
        guard case .completed(let held) = routedStore().forwardableManifest(item: key),
              let manifest = held else { return }
        // P5 item 8's third claim door: an item that has just BECOME complete may be one a departed
        // origin handed this device. It runs before the guard below, which answers `false` for a
        // courier that is not a destination and would return before any receipt was sent; and it
        // excludes `key`, which the next line commits itself — one item, one commit, per evaluation,
        // because `committingCustody` re-streams the whole item before it finds a stored stamp.
        claimHandedOffCustody(now: now, excluding: key)
        guard routedRungsOutstanding(for: key, manifest: manifest) else { return }
        let custody = commitLocalCustody(for: key, manifest: manifest, now: now)
        let recipient = commitLocalDelivery(for: key, manifest: manifest, now: now)
        guard custody != nil || recipient != nil else { return }
        spawnHostPinned { [weak self] in
            await self?.sendMintedReceipts(custody: custody, recipient: recipient, to: peer)
        }
    }

    /// Whether either rung this device could take for `key` is still outstanding.
    ///
    /// A store that cannot say what it holds answers **true**: the fail-closed direction here is to
    /// re-do bounded work, never to skip a rung. A held item whose custody rung is taken and whose
    /// own recipient receipt is filed has nothing left to take, so a duplicate frame is a no-op.
    private func routedRungsOutstanding(
        for key: MeshRoutedItemKey, manifest: MeshRoutedManifest
    ) -> Bool {
        guard let record = routedIndexForAdvertising()?.record(for: key) else { return true }
        guard record.custodiedAt != nil else { return true }
        let me = identity.localFingerprint
        guard manifest.destinations.contains(me) else { return false }
        return record.recipientReceipts.contains { $0.recipientFingerprint == me } == false
    }

    /// This device's own custody receipt, minted only when it has an honest claim to be holding the
    /// item: it is one of the origin's signed destinations, or a hand-off already named it custodian.
    ///
    /// Otherwise the ciphertext is **held, not claimed** — one line, no receipt, no `custodiedAt`.
    /// Minting a custody receipt for content nobody handed this device is the receipt saying
    /// something untrue. Own items are skipped: an origin is never its own custodian.
    private func commitLocalCustody(
        for key: MeshRoutedItemKey, manifest: MeshRoutedManifest, now: Date
    ) -> MeshCustodyReceipt? {
        let me = identity.localFingerprint
        guard key.originFingerprint != me else { return nil }
        guard manifest.destinations.contains(me) || holdsHandedOffLeg(of: key, as: me) else {
            FernletAuditLog.log(
                "mesh.routedDrain.heldWithoutCustodyClaim",
                context: ["type": manifest.typeToken]
            )
            return nil
        }
        let outcome = routedStore().committingCustody(item: key, custodian: me, now: now)
        guard case .completed(.committed(let witness)) = outcome else {
            FernletAuditLog.log("mesh.routedDrain.custodyNotCommitted", context: ["type": manifest.typeToken])
            return nil
        }
        do {
            return try MeshCustodyReceipt.signed(witness: witness, manifest: manifest, identity: identity)
        } catch {
            FernletAuditLog.log(
                "mesh.routedDrain.signFailed",
                context: ["type": PayloadType.meshCustodyReceipt.rawValue,
                          "error": String(describing: error)]
            )
            return nil
        }
    }

    /// Whether some destination's leg of `key` was explicitly handed to this device at a departure.
    /// ``claimHandedOffCustody(now:excluding:)`` is what writes that rung (P5 item 8); the predicate
    /// itself has not moved since item 6, which is exactly the increment-1 line.
    private func holdsHandedOffLeg(of key: MeshRoutedItemKey, as me: String) -> Bool {
        guard let target = routedIndexForAdvertising()?.record(for: key)?.deliveryTarget else {
            return false
        }
        // R2: bounded by the destination cap.
        return target.destinations.contains { target.state(of: $0) == .custodied(by: me) }
    }

    /// Records that a manifest arrived **from its own origin** — P5 item 8's hop bound.
    ///
    /// Bounded by the store's item cap, and full is a named line rather than unbounded growth.
    private func noteOriginServed(_ key: MeshRoutedItemKey) {
        guard originServedItems.contains(key)
                || originServedItems.count < MeshRoutedStoreFormat.maxItems else {
            FernletAuditLog.log("mesh.development.originServedSetFull")
            return
        }
        originServedItems.insert(key)                                 // R3: bounded set
    }

    /// Takes the custody legs a departed origin handed THIS device — plan §10.6's custodian half.
    ///
    /// **One idempotent derivation, four doors, never four event hooks.** The authority is a single
    /// signed development; the write is a derivation applied whenever its evidence becomes
    /// complete — a live roster move, a merge, an item finishing, or the next drain exchange. After
    /// the first application no named leg is `pending`, so a re-run plans nothing and writes
    /// nothing, which is what makes a duplicate record, a merge and a restart converge.
    ///
    /// Three filters, and each one is load-bearing:
    ///
    /// - the leaver's own signed departure record must name this device a custodian — the origin's
    ///   authorisation, verified, grow-only and available offline;
    /// - the leaver must not have been **removed**. `MeshMembershipRecordVerifier` accepts a
    ///   departure from any admitted fingerprint, not only a current member, and a derived roster
    ///   cannot separate *departed* from *removed* because both subtract from it — so the gate lives
    ///   here, over `ledger.removals` and ``removedMemberFingerprints``, before the pure planner
    ///   sees a leaver. A removal is the mesh's statement that this member's word no longer counts;
    ///   granting retention on it would let an ejected device park content across the mesh;
    /// - the item's manifest must have come from the origin itself (``originServedItems``), which is
    ///   what keeps the courier set one hop from the origin.
    ///
    /// The common case — nobody named this device — returns before any I/O at all.
    ///
    /// - Parameters:
    ///   - now: The injected instant.
    ///   - excluding: A key the caller is about to commit custody for itself, one line later. One
    ///     item, one commit, per evaluation: ``MeshRoutedStore/committingCustody(item:custodian:now:)``
    ///     re-streams the whole item before it finds a stored stamp, so committing twice is up to
    ///     256 MiB re-read on the main actor and two signed receipts.
    private func claimHandedOffCustody(now: Date, excluding pending: MeshRoutedItemKey? = nil) {
        guard let verifier = membershipVerifier else { return }
        let me = identity.localFingerprint
        // R2: bounded by `MeshMembershipBounds.maxRecordsPerKind`.
        let removed = Set(verifier.ledger.removals.all.map(\.memberFingerprint))
            .union(removedMemberFingerprints)
        let leavers = Set(
            verifier.ledger.departures.all
                .filter { $0.custodyHandoff.custodianFingerprints.contains(me) }
                .map(\.memberFingerprint)
                .filter { !removed.contains($0) }
        )
        guard !leavers.isEmpty, let index = routedIndexForAdvertising() else { return }
        let stranded = MeshCustodyHandoffPlan.notOriginServedCount(
            in: index, from: leavers, originServed: originServedItems, at: now
        )
        if stranded > 0 {
            FernletAuditLog.log(
                "mesh.development.handoffClaimNotOriginServed", context: ["items": String(stranded)]
            )
        }
        let claims = MeshCustodyHandoffPlan.claims(
            in: index, from: leavers, originServed: originServedItems,
            roster: verifier.roster, selfFingerprint: me, at: now
        )
        // An evaluation that plans nothing new still drains the previous one's deferred commits:
        // after a claim the planner sees no `pending` leg, so a re-plan is exactly what CANNOT
        // recover the overflow, and routing the retry through the plan would make the deferral
        // permanent (``deferredCustodyCommits``).
        guard !claims.isEmpty else { return mintClaimedCustody([], at: now) }
        applyHandedOffClaims(claims, now: now, excluding: pending)
    }

    /// Writes one planned claim batch and commits custody for what it took.
    private func applyHandedOffClaims(
        _ claims: [MeshRoutedHandoffClaim], now: Date, excluding pending: MeshRoutedItemKey?
    ) {
        switch routedStore().claimingHandedOffLegs(claims, now: now) {
        case .completed(let report):
            if !report.incomplete.isEmpty {
                FernletAuditLog.log(
                    "mesh.development.handoffClaimIncomplete",
                    context: ["items": String(report.incomplete.count)]
                )
            }
            // R2: bounded by the batch's own size.
            for refusal in report.refused {
                FernletAuditLog.log(
                    "mesh.development.handoffClaimRefused",
                    context: ["reason": refusal.refusal.token]
                )
            }
            mintClaimedCustody(report.advanced.filter { $0 != pending }, at: now)
        case .refused(let refusal):
            FernletAuditLog.log(
                "mesh.development.handoffClaimSuppressed", context: ["reason": refusal.rawValue]
            )
        case .unavailable(let cause):
            FernletAuditLog.log(
                "mesh.development.handoffClaimSuppressed", context: ["state": cause.logToken]
            )
        }
    }

    /// Commits durable custody for items this device just claimed — plus whatever a previous
    /// evaluation deferred — and mints nothing else.
    ///
    /// Capped per evaluation because this is the expensive half: ``commitLocalCustody(for:manifest:now:)``
    /// re-streams and re-hashes the whole item. The overflow is named **and carried** in
    /// ``deferredCustodyCommits``, ahead of the next evaluation's own work: the claim planner cannot
    /// recover it (after a claim no named leg is `pending`, so a re-plan is empty by design), so a
    /// queue is what makes "retried at the next evaluation" true rather than a comment. Deferring
    /// costs a receipt's latency rather than a served byte — the courier predicate reads the
    /// **rung**, not `custodiedAt`.
    ///
    /// **The minted receipts are deliberately not transmitted here.** Three of the four claim doors
    /// have no peer to send to, and a receipt broadcast to nobody is a frame with no recipient. The
    /// durable half is what matters: `custodiedAt` is what puts this device into the item's
    /// advertised custody signers, so every peer learns of the custody through the next inventory
    /// it already exchanges. Do not "fix" this by inventing a broadcast.
    ///
    /// - Parameters:
    ///   - keys: The items whose rung just moved. May be empty — an evaluation that planned nothing
    ///     new still drains the queue.
    ///   - now: The injected instant.
    private func mintClaimedCustody(_ keys: [MeshRoutedItemKey], at now: Date) {
        var seen: Set<MeshRoutedItemKey> = []
        // R3: bounded below by the store's own item cap, deduped so a re-deferred key cannot double.
        let queued = (deferredCustodyCommits + keys).filter { seen.insert($0).inserted }
        guard !queued.isEmpty else { return }
        guard let index = routedIndexForAdvertising() else {
            // Nothing was committed, so nothing may be dropped: a store that cannot say what it
            // holds defers the WHOLE queue rather than the overflow alone.
            deferredCustodyCommits = Array(queued.prefix(MeshRoutedStoreFormat.maxItems))
            return
        }
        let cap = MeshRoutedDrainBounds.increment1.maxItems
        let overflow = Array(queued.dropFirst(cap).prefix(MeshRoutedStoreFormat.maxItems))
        if !overflow.isEmpty {
            FernletAuditLog.log(
                "mesh.development.handoffCommitDeferred", context: ["items": String(overflow.count)]
            )
        }
        deferredCustodyCommits = overflow
        // R2: bounded by the per-answer item allowance.
        for key in queued.prefix(cap) {
            guard let record = index.record(for: key), record.custodiedAt == nil,
                  let manifest = record.manifest else { continue }
            _ = commitLocalCustody(for: key, manifest: manifest, now: now)
        }
    }

    /// This device's own recipient receipt, when it is a destination and the type's final-ack
    /// condition is met. A heart without foreground evidence stops at `custodied(by: self)` — the
    /// correct terminal-for-now state — and the drain never fakes foregroundness.
    private func commitLocalDelivery(
        for key: MeshRoutedItemKey, manifest: MeshRoutedManifest, now: Date
    ) -> MeshRecipientReceipt? {
        let me = identity.localFingerprint
        guard manifest.destinations.contains(me) else { return nil }
        let store = routedStore()
        let outcome = store.committingDelivery(
            item: key, recipient: me, stages: .increment1, evidence: .none, now: now
        )
        guard case .completed(let commit) = outcome else { return nil }
        guard case .acknowledged(let witness) = commit else {
            if case .unsatisfied(let shortfall) = commit {
                FernletAuditLog.log(
                    "mesh.routedDrain.deliveryPending",
                    context: ["shortfall": shortfall.diagnosticDescription]
                )
            }
            return nil
        }
        return storedRecipientReceipt(witness: witness, manifest: manifest, key: key, now: now)
    }

    /// Mints this device's recipient receipt and files it through the one rung writer. A receipt that
    /// could not be stored is not returned: nothing is acknowledged for state a restart would lose.
    private func storedRecipientReceipt(
        witness: MeshRecipientDeliveryWitness,
        manifest: MeshRoutedManifest,
        key: MeshRoutedItemKey,
        now: Date
    ) -> MeshRecipientReceipt? {
        do {
            let receipt = try MeshRecipientReceipt.signed(
                witness: witness, manifest: manifest, identity: identity
            )
            let stored = routedStore().recordingRecipientReceipt(item: key, receipt: receipt, now: now)
            guard stored.value != nil else {
                FernletAuditLog.log("mesh.routedDrain.receiptNotStored", context: ["type": manifest.typeToken])
                return nil
            }
            return receipt
        } catch {
            FernletAuditLog.log(
                "mesh.routedDrain.signFailed",
                context: ["type": PayloadType.meshRecipientReceipt.rawValue,
                          "error": String(describing: error)]
            )
            return nil
        }
    }

    /// Sends whichever receipts this device just minted, to the peer the content came from — at most
    /// two frames. The origin learns the rest through the receipt forwarding of the next exchange;
    /// pushing to anyone else here would be a send on a link that did not just open.
    private func sendMintedReceipts(
        custody: MeshCustodyReceipt?, recipient: MeshRecipientReceipt?, to peer: String
    ) async {
        if let custody {
            await broadcastMembershipFrame(
                .meshCustodyReceipt, MeshCustodyReceiptPayload(receipt: custody), to: [peer]
            )
        }
        if let recipient {
            await broadcastMembershipFrame(
                .meshRecipientReceipt, MeshRecipientReceiptPayload(receipt: recipient), to: [peer]
            )
        }
    }

    /// The keys this device may move to `peer`: item 5's entitlement source 1, narrowed to what
    /// increment 1 permits and to what this peer has not already refused.
    ///
    /// Deliberately **not** routed through `outstandingReachable`/`outstandingUnreachable`: those take
    /// a `MeshBranchView`, so entitlement would silently empty whenever no branch view is raised.
    /// `outstandingItems(at:in:)` is plan §11's "destinations lacking a `MeshRecipientReceipt`",
    /// partition-agnostic by construction.
    private func offerableKeys(
        to peer: String, in index: MeshRoutedIndex, at now: Date
    ) -> Set<MeshRoutedItemKey> {
        guard let roster = membershipVerifier?.roster else { return [] }
        let refs = index.outstandingItems(at: now, in: roster)[peer] ?? []
        var keys = Set(refs.lazy
            .filter { $0.receivedCount == Int($0.chunkCount) }
            .filter { self.mayCourier($0.key, to: peer, in: index) }
            .map(\.key))
        // P5 item 8's entitlement source 2, unioned in one place: while a development is live, the
        // custodians it named may take this device's own outstanding items even though they are not
        // destinations. It is scoped to that development and dies with the session.
        keys.formUnion(handoffEntitlement(to: peer, in: index, at: now))
        keys.subtract(routedRefusedKeys[peer] ?? [])
        return keys
    }

    /// Item 5's entitlement source 2: this device's own outstanding items, offerable to a custodian
    /// a **live** development named, until that development's window closes.
    ///
    /// Empty outside a development, empty for any peer the development did not name, and empty once
    /// the window has closed — three conditions, all read off one run-scoped value that
    /// ``resetSessionStateMachine(keepingTerminalState:)`` clears. `originatedBy:` is the enumerator's
    /// own no-second-hop wall: only content this device minted is ever offered this way.
    private func handoffEntitlement(
        to peer: String, in index: MeshRoutedIndex, at now: Date
    ) -> Set<MeshRoutedItemKey> {
        guard let scope = developmentHandoff, scope.admits(peer, at: now),
              let roster = membershipVerifier?.roster else { return [] }
        return Set(index.itemsAwaitingHandoff(
            at: now, in: roster, originatedBy: identity.localFingerprint
        ).map(\.key))
    }

    /// Increment 1's entitlement line, stated once: the origin's own item, or a destination's leg
    /// this device was **handed at a departure**. Never "this device happens to hold the ciphertext".
    ///
    /// `isCustodied` is not that line: it goes true at **every** non-origin receiver, destinations
    /// included, so `origin == self || isCustodied` would make every destination a live third-party
    /// relay for its co-destinations — increment 2 wearing increment 1's name. The rung
    /// `custodied(by: self)` is written by exactly one door, `recordingCustodyTransfer`, which no
    /// shipping code in item 6 calls: so item 6's only entitled offerer is an origin, and item 8
    /// widens the SOURCE of the rung rather than this predicate.
    private func mayCourier(_ key: MeshRoutedItemKey, to peer: String, in index: MeshRoutedIndex) -> Bool {
        if key.originFingerprint == identity.localFingerprint { return true }
        guard let target = index.record(for: key)?.deliveryTarget else { return false }
        return target.state(of: peer) == .custodied(by: identity.localFingerprint)
    }

    /// The batch this exchange with `peer` may send, and this device's own quiescence bit.
    ///
    /// Returns **nil** whenever the store does not vend an index, which is what makes a non-advertising
    /// store send no answer frame at all rather than skipping the bulk inside one.
    private func routedDrainPlan(
        for peer: String, at now: Date
    ) -> (plan: MeshRoutedDrainPlan, quiescent: Bool)? {
        guard let mesh = currentMesh,
              let remote = peerRoutedInventories[peer]?.inventory,
              let index = routedIndexForAdvertising() else { return nil }
        guard let local = MeshRoutedInventory(
            meshID: mesh.meshID, index: index, selfFingerprint: identity.localFingerprint, at: now
        ) else {
            FernletAuditLog.log("mesh.routedDrain.inventoryOverCap")
            return nil
        }
        guard let delta = MeshRoutedInventoryDelta.between(
            local: local, remote: remote, offerableToPeer: offerableKeys(to: peer, in: index, at: now)
        ) else {
            FernletAuditLog.log("mesh.routedDrain.foreignMeshDelta")
            return nil
        }
        noteUnrestorableDeliveries(index, at: now)
        let bounds = MeshRoutedDrainBounds.increment1
        let plan = MeshRoutedDrainPlan(
            delta: delta, refused: routedRefusedKeys[peer] ?? [], bounds: bounds,
            frameAllowance: min(bounds.maxFrames, routedFramesRemaining(for: peer))
        )
        return (plan, delta.isQuiescent)
    }

    /// Held ciphertext whose own delivery map will not restore is invisible to every outstanding
    /// enumerator, so it is **named** once per answer rather than silently dropped. Repair, cap
    /// accounting and any user-visible surface are item 9's.
    private func noteUnrestorableDeliveries(_ index: MeshRoutedIndex, at now: Date) {
        let stranded = index.itemsWithUnrestorableDelivery(at: now).count
        guard stranded > 0 else { return }
        FernletAuditLog.log(
            "mesh.routedDrain.deliveryUnrestorable", context: ["items": String(stranded)]
        )
    }

    /// Sends the quiescence bit for one advertisement. Signed, because an unsigned bit would let any
    /// peer close item 7's merge window early.
    private func sendRoutedDrainAnswer(
        to peer: String, advertisedAt: Date, quiescent: Bool, now: Date
    ) async {
        guard let mesh = currentMesh else { return }
        do {
            let payload = try MeshRoutedDrainAnswerPayload.signed(
                meshID: mesh.meshID, advertiser: peer, advertisedAt: advertisedAt,
                quiescent: quiescent, sentAt: now, identity: identity
            )
            await broadcastMembershipFrame(.meshRoutedDrainAnswer, payload, to: [peer])
        } catch {
            FernletAuditLog.log(
                "mesh.routedDrain.signFailed",
                context: ["type": PayloadType.meshRoutedDrainAnswer.rawValue,
                          "error": String(describing: error)]
            )
        }
    }

    /// Puts one planned batch on the wire, charging the peer's session frame budget **first**.
    ///
    /// The check-and-charge is this function's first statement, before its first `await`, because a
    /// pump can deliver two of a peer's inventories synchronously: both are planned before either
    /// `Task` body runs, so a charge that landed after the sends would double-spend. A batch that no
    /// longer fits is refused whole and re-planned at the next exchange.
    ///
    /// Extracted from ``sendRoutedDrainBatch(_:to:now:)`` by P5 item 8 so the departure push moves
    /// bytes through the identical charge-then-send sequence. It has exactly **two** call sites and
    /// deliberately logs nothing: each caller keeps its own audit vocabulary, so a drain answer and
    /// a hand-off push are never confused in a transcript.
    ///
    /// - Returns: `true` when the batch was charged and sent; `false` when the session budget
    ///   refused it whole, or when there was nothing to send.
    private func sendRoutedBulk(
        _ plan: MeshRoutedDrainPlan, to peer: String, now: Date
    ) async -> Bool {
        guard plan.frameCount > 0 else { return false }
        guard chargeRoutedFrames(plan.frameCount, to: peer) else { return false }
        // Manifests before chunks: a chunk before its manifest is admissible and parked, but the
        // reverse costs nothing and un-parks the peer's set at once.
        await sendRoutedManifests(plan.manifests, to: peer)
        await sendRoutedChunks(plan.chunks, to: peer)
        await sendRoutedReceipts(plan.receipts, to: peer, now: now)
        return true
    }

    /// The drain's own use of ``sendRoutedBulk(_:to:now:)``, with the drain's audit tokens.
    private func sendRoutedDrainBatch(
        _ plan: MeshRoutedDrainPlan, to peer: String, now: Date
    ) async {
        guard plan.frameCount > 0 else { return }
        guard await sendRoutedBulk(plan, to: peer, now: now) else {
            FernletAuditLog.log(
                "mesh.merge.routedAnswerBudgetSpent",
                context: ["left": String(routedFramesRemaining(for: peer))]
            )
            return
        }
        if plan.truncated {
            FernletAuditLog.log(
                "mesh.merge.routedAnswerTruncated", context: ["frames": String(plan.frameCount)]
            )
        }
        FernletAuditLog.log(
            "mesh.merge.routedAnswered",
            context: ["manifests": String(plan.manifests.count),
                      "chunks": String(plan.chunks.count),
                      "receipts": String(plan.receipts.count),
                      "framesLeft": String(routedFramesRemaining(for: peer))]
        )
    }

    /// Forwards the origin's stored manifests, byte-identical. A parked or unknown item is skipped
    /// with a named line — never a synthesised value.
    private func sendRoutedManifests(_ keys: [MeshRoutedItemKey], to peer: String) async {
        let store = routedStore()
        // R2: bounded by `MeshRoutedDrainBounds.increment1.maxItems`.
        for key in keys.prefix(MeshRoutedDrainBounds.increment1.maxItems) {
            switch store.forwardableManifest(item: key) {
            case .completed(let manifest):
                guard let manifest else {
                    FernletAuditLog.log("mesh.routedDrain.offerSkipped", context: ["reason": "parked"])
                    continue
                }
                await broadcastMembershipFrame(
                    .meshRoutedManifest, MeshRoutedManifestPayload(manifest: manifest), to: [peer]
                )
            case .refused(let refusal):
                FernletAuditLog.log("mesh.routedDrain.offerSkipped", context: ["reason": refusal.rawValue])
            case .unavailable(let cause):
                FernletAuditLog.log("mesh.routedDrain.unavailable", context: ["state": cause.logToken])
                return
            }
        }
    }

    /// Forwards the origin's stored chunks, one resident at a time. A slot the store can no longer
    /// stand behind is skipped: the repair it triggers corrects the next advertisement.
    private func sendRoutedChunks(_ sends: [MeshRoutedDrainChunkSend], to peer: String) async {
        let store = routedStore()
        let bound = MeshRoutedDrainBounds.increment1.maxChunksPerAnswer
        // R2: bounded by the per-answer chunk allowance.
        for send in sends.prefix(bound) {
            // R2: bounded by the per-item chunk allowance.
            for index in send.indices.prefix(bound) {
                switch store.forwardableChunk(item: send.key, index: index) {
                case .completed(let chunk):
                    guard let chunk else {
                        FernletAuditLog.log("mesh.routedDrain.offerSkipped", context: ["reason": "slotNotHeld"])
                        continue
                    }
                    await broadcastMembershipFrame(
                        .meshRoutedChunk, MeshChunkPayload(chunk: chunk), to: [peer]
                    )
                case .refused(let refusal):
                    FernletAuditLog.log("mesh.routedDrain.offerSkipped", context: ["reason": refusal.rawValue])
                case .unavailable(let cause):
                    FernletAuditLog.log("mesh.routedDrain.unavailable", context: ["state": cause.logToken])
                    return
                }
            }
        }
    }

    /// Forwards receipts verbatim, one frame each.
    ///
    /// Three cases, and only the third is not a forward: this device's OWN custody receipt is never
    /// stored (a record holds other members' only), so it is **re-minted** from the durable bytes —
    /// byte-identically, because the commit re-uses the stored `custodiedAt`. A re-mint that no
    /// longer succeeds means this device no longer holds what it advertised: log, send nothing.
    private func sendRoutedReceipts(
        _ refs: [MeshRoutedInventoryReceiptRef], to peer: String, now: Date
    ) async {
        let store = routedStore()
        // R2: bounded by `MeshRoutedDrainBounds.increment1.maxReceipts`.
        for ref in refs.prefix(MeshRoutedDrainBounds.increment1.maxReceipts) {
            if ref.kind == .recipient {
                let held = store.forwardableRecipientReceipts(item: ref.key).value ?? []
                guard let receipt = held.first(where: { $0.recipientFingerprint == ref.signer }) else {
                    FernletAuditLog.log("mesh.routedDrain.receiptSkipped", context: ["kind": ref.kind.rawValue])
                    continue
                }
                await broadcastMembershipFrame(
                    .meshRecipientReceipt, MeshRecipientReceiptPayload(receipt: receipt), to: [peer]
                )
                continue
            }
            guard let receipt = custodyReceiptToForward(ref, in: store, now: now) else { continue }
            await broadcastMembershipFrame(
                .meshCustodyReceipt, MeshCustodyReceiptPayload(receipt: receipt), to: [peer]
            )
        }
    }

    /// The custody receipt a reference names: another member's stored bytes, or — when the signer is
    /// this device — a re-mint from the durable ciphertext.
    private func custodyReceiptToForward(
        _ ref: MeshRoutedInventoryReceiptRef, in store: MeshRoutedStore, now: Date
    ) -> MeshCustodyReceipt? {
        guard ref.signer == identity.localFingerprint else {
            let held = store.forwardableCustodyReceipts(item: ref.key).value ?? []
            guard let receipt = held.first(where: { $0.custodianFingerprint == ref.signer }) else {
                FernletAuditLog.log("mesh.routedDrain.receiptSkipped", context: ["kind": ref.kind.rawValue])
                return nil
            }
            return receipt
        }
        switch store.forwardableManifest(item: ref.key) {
        case .completed(let held):
            guard let manifest = held else {
                FernletAuditLog.log(
                    "mesh.routedDrain.receiptSkipped",
                    context: ["kind": ref.kind.rawValue, "reason": "parked"]
                )
                return nil
            }
            return commitLocalCustody(for: ref.key, manifest: manifest, now: now)
        case .refused(let refusal):
            FernletAuditLog.log(
                "mesh.routedDrain.receiptSkipped",
                context: ["kind": ref.kind.rawValue, "reason": refusal.rawValue]
            )
            return nil
        case .unavailable(let cause):
            FernletAuditLog.log("mesh.routedDrain.unavailable", context: ["state": cause.logToken])
            return nil
        }
    }

    /// Broadcasts a freshly minted admission record to the members that were NOT part of minting
    /// it, so a joiner appears on every member's derived roster.
    ///
    /// Without it the admitting member is the only device that knows, and
    /// ``MeshRotationPolicy/recipients(acked:selfFingerprint:derivedRoster:locallyRemoved:)``
    /// narrows the next epoch's key distribution to the derived roster — so an unpropagated
    /// admission is a member who silently never receives the group key.
    ///
    /// - Parameter record: The admission this device signed.
    func emitAdmissionRecord(_ record: SignedAdmissionRecord) {
        spawnHostPinned { [weak self] in
            await self?.broadcastMembershipFrame(
                .meshMemberAdmission,
                MeshMemberAdmissionPayload(record: record),
                to: self?.membershipEventRecipients(excluding: record.memberFingerprint)
            )
        }
    }

    /// Files the admission this device just granted, durably, before the grant is answered.
    ///
    /// Plan §3.6 in its admitter form: a member this device could not write down is a member it
    /// would not remember admitting after a force-quit, and the roster the next rotation narrows
    /// its key distribution to would disagree with the one the joiner believes it is on.
    ///
    /// - Parameter token: The credential this device signed for the joiner.
    /// - Returns: `true` when the record is verified and durable, so the grant may go out.
    func recordGrantedAdmission(_ token: MeshAdmissionToken) -> Bool {
        guard membershipVerifier != nil else { return true }
        let record = SignedAdmissionRecord(token: token)
        let snapshot = membershipVerifier
        let before = membershipVerifier?.roster
        let rejection = membershipVerifier?.insert(record)
        recordRejection(rejection, type: .meshMemberAdmission)
        guard rejection == nil else { return false }
        guard membershipVerifier?.roster != before else { return true }
        guard commitVerifiedRecord(rollingBackTo: snapshot, type: .meshMemberAdmission) else {
            return false
        }
        emitAdmissionRecord(record)
        requestRotation(cause: .membership)
        return true
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
        // The fold and the count are ONE step, here, because here is where the cap can bite: the
        // set being written is the only set it applies to (plan §21.3).
        var droppedHeads = 0
        if let head {
            let fold = MeshMergeOffer.foldedHeads(context.epochHeads, adding: [head])
            context.epochHeads = fold.heads
            droppedHeads = fold.droppedCount
        }
        if let termination {
            context.localTermination = termination
            if termination.reason == .developed { context.developedLocally = true }
        }
        do {
            try sessionStore.save(context, token: token)
            // After the seal, never before: a refused save wrote nothing, so it dropped nothing —
            // and the mirror a merge takes its `max` from must name only heads a restart could read
            // back (plan §3.6).
            knownEpochHeads = context.epochHeads
            recordDroppedEpochHeads(droppedHeads)
            return true
        } catch {
            recordRotationBlock("The session context could not be sealed: \(String(describing: error)).")
            return false
        }
    }

    /// Names an epoch-head overflow that a seal has just made durable.
    ///
    /// Plan §21.3's "an assertion P4 tests, not a knob": a non-zero count is a defect signal — the
    /// mesh holds more branch heads than everyone-alone can justify — so it is surfaced on the
    /// manager and in the audit log instead of disappearing into a `prefix`.
    ///
    /// - Parameter count: How many distinct heads the cap pushed off the set that was written.
    private func recordDroppedEpochHeads(_ count: Int) {
        guard count > 0 else { return }
        droppedEpochHeadCount += count
        FernletAuditLog.log(
            "mesh.sessionContext.epochHeadsDropped", context: ["count": String(count)]
        )
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
    ///
    /// **Computed from ``mergeWindow``, never stored** (P5 item 7): one source of truth cannot
    /// disagree with the observable six test files and three shipping call sites read.
    var awaitingResumeMerge: Bool { mergeWindow != nil }

    /// Whether the foreground may offer a resume for a restored or idle-stopped session.
    @ObservationIgnored private(set) var offersForegroundResume = false

    /// Plan §10.6's development decision, as the last development actually took it: which ending,
    /// which custodians, and the instant the 15-second window opened. Memory-only — a decision, not
    /// a fact about membership, and the durable half is the sealed ending mark.
    @ObservationIgnored private(set) var lastDevelopmentPlan: MeshDevelopmentPlan?

    /// How that development's bounded handoff ended.
    @ObservationIgnored private(set) var lastDevelopmentHandoffOutcome: MeshDevelopmentHandoffOutcome?

    /// What the last development's custody transfer actually did (P5 item 8, plan §10.6): which
    /// items moved a rung, which could not be placed, which bytes the push offered, and why — if
    /// anything — it handed over less than it held.
    ///
    /// Memory-only and `@ObservationIgnored`, like the two properties above: it is a record of one
    /// departure's work, nothing observes it, and registering a departure-path mutation for
    /// observation would invalidate views for state no view reads. The durable half is the rungs in
    /// the routed index; the announced half is the signed departure record every survivor holds.
    @ObservationIgnored private(set) var lastDevelopmentHandoff: MeshCustodyHandoffResult?

    /// The entitlement a LIVE development opens, or nil outside one (P5 item 8).
    ///
    /// Item 5's entitlement source 2, scoped so it cannot become a permanent relay entitlement:
    /// armed once inside ``transferCustodyOnDevelopment(_:at:)``, cleared by
    /// ``resetSessionStateMachine(keepingTerminalState:)`` — which ``leaveMesh()`` runs at the end
    /// of the very same development. Deliberately not derived from ``lastDevelopmentPlan``, which
    /// outlives the session on purpose.
    @ObservationIgnored private var developmentHandoff: MeshCustodyHandoffScope?

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
    /// - Parameters:
    ///   - event: What happened.
    ///   - committedPeer: For ``MeshSessionEvent/peerCommitted`` only, the fingerprint of the peer
    ///     whose commit raised it. Read for exactly one decision — whether that peer was **already**
    ///     a roster member, which is what separates a reconnect from a new admission
    ///     (``openBlipMergeIfReconnected(_:from:peer:)``) — and ignored for every other event. The
    ///     machine never sees it: an associated value here would make the state machine's alphabet
    ///     depend on membership, which is the coupling P3 item 6 exists to avoid.
    /// - Returns: The transition taken, or the named refusal.
    @discardableResult
    func applySessionEvent(
        _ event: MeshSessionEvent, committedPeer: String? = nil
    ) -> MeshSessionTransition {
        let previous = sessionState
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
            // Splitting again abandons whatever merge was in flight: the peer whose re-gossip this
            // device was waiting on is out of reach, so the records that arrive next are live
            // records again and rotate as `.membership`. The next heal opens a fresh exchange.
            if next == .partitioned { abandonMergeExchange() }
            performSessionEffects(effects, for: event)
            openBlipMergeIfReconnected(event, from: previous, peer: committedPeer)
        }
        return transition
    }

    /// The one reconnect the machine expresses as a self-edge: a peer committing into a session
    /// that was **already live** (plan §10.3's blip, and item 1's partial heal — a peer reappearing
    /// on a branch still short of somebody, which raises no partition verdict by design).
    ///
    /// `activeForeground --peerCommitted--> activeForeground` carries no effects, so
    /// ``MeshSessionEffect/beginMerge`` never fires for it and the reconnect would otherwise
    /// silently resume against a roster that moved in the other branch. A `joining` session's first
    /// commit is deliberately excluded: that is a join, and the admission-grant path already asks
    /// its admitter what it holds.
    ///
    /// **Reconnect ≡ merge; admission ≠ reconnect.** A peer that was already on the derived roster
    /// when it committed is coming *back*, and coming back is plan §10.3's merge. A peer that was
    /// not is being admitted, and an admission is its own roster move with its own `.membership`
    /// rotation — opening a merge window for it would relabel a brand-new member's first epoch
    /// `.merge` (which outranks `.membership` in the 2 s coalescing window, so the cause would be
    /// wrong rather than merely extra) and would set this device waiting for a re-gossip that
    /// answers a question nobody asked.
    ///
    /// Membership is read **before** the commit's own effects can move it, which is what makes
    /// "already a member" the honest test: at this instant the admission record for a genuine
    /// joiner has not been filed yet. A commit that names no peer at all opens nothing — fail
    /// closed, because "not known to be a member" and "is a member" must not be the same answer.
    ///
    /// - Parameters:
    ///   - event: The event just applied.
    ///   - previous: The state it was applied from.
    ///   - peer: The committing peer's fingerprint, when the caller knows it.
    private func openBlipMergeIfReconnected(
        _ event: MeshSessionEvent, from previous: MeshSessionState, peer: String?
    ) {
        guard event == .peerCommitted, previous != .joining, previous.isLive else { return }
        guard let peer, membershipVerifier?.roster.contains(fingerprint: peer) == true else { return }
        guard !awaitingResumeMerge else {
            askOneReconnectedPeer(peer)
            return
        }
        beginMergeExchange(entry: .blip)
    }

    /// Asks **one** newly reconnected peer what it holds, without opening a second merge window
    /// (P4 item 9b).
    ///
    /// A window already being open means "a merge with somebody is in flight", and re-arming it for
    /// every later reconnect would relabel one merge as several. But it does **not** mean this peer
    /// has been asked: ``beginMergeExchange(entry:now:)`` sends to the slots that existed when it ran,
    /// and a member of a mesh healing branch by branch acquires most of its slots afterwards. Before
    /// this, such a peer was never asked and — because it may be awaiting too, and an exchange is
    /// the only thing that sends either frame — never told. On a `4/2/2` heal that left members
    /// counting the post-merge epoch up from different heads for good: the same shape P4 item 2c
    /// fixed for the *answer* half, one party wider. Found by §16.2's roster-8 row
    /// (`MeshConvergencePropertyTests`).
    ///
    /// One ask, to one peer, on the two frames the exchange already uses: no wire change, no second
    /// window, and ``awaitingResumeMerge`` deliberately untouched so the records that come back
    /// still land in the one merge path. A repeat ask costs the responder nothing it has not already
    /// spent — ``reGossipRecords(to:)`` still answers once per peer per session.
    ///
    /// - Parameter peer: The committing peer's fingerprint, already checked to be a roster member.
    private func askOneReconnectedPeer(_ peer: String) {
        guard membershipVerifier != nil else { return }
        // The same window, one peer wider — and one peer LESS proved. `reAsking` un-matches its
        // peer, because a re-commit is present-tense evidence that this peer's link dropped and
        // re-formed, and while it was gone it may have linked to the other branch and folded records
        // this device has never seen. An earlier match is evidence from before it left, so the
        // window may not close on it (P5 item 7, D-7.32).
        mergeWindow = mergeWindow?.reAsking(peer)
        FernletAuditLog.log("mesh.merge.askedLateReconnect")
        spawnHostPinned { [weak self] in
            await self?.sendInventoryDigest(to: [peer])
            await self?.sendEpochHeads(to: [peer])
            await self?.sendRoutedInventory(to: [peer])
        }
    }

    /// Drops the merge in flight without concluding it — the session partitioned again, or ended.
    private func abandonMergeExchange() {
        guard mergeWindow != nil || pendingMergeEntry != nil else { return }
        clearMergeWindow()
        pendingMergeEntry = nil
        FernletAuditLog.log("mesh.merge.abandoned")
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
            beginMergeExchange(entry: Self.mergeEntry(for: event))
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

    /// Which of plan §10.3's four reconnects raised ``MeshSessionEffect/beginMerge``.
    ///
    /// A restart is not in the switch on purpose: the event that reaches the machine after a
    /// relaunch is whatever the user's resume raises, and the restart-ness is carried by
    /// ``pendingMergeEntry`` having been armed at restore time — which is why this reads it first
    /// rather than overwriting it.
    private static func mergeEntry(for event: MeshSessionEvent) -> MeshMergeEntry {
        switch event {
        case .linksRestored: return .partitionHeal
        case .resumedAfterLapse: return .idleLapseResume
        default: return .blip
        }
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

    // MARK: - Partition detection (network migration P4 item 1, plan §10.2)

    /// What this device can currently SEE of its own roster: who is present, who is
    /// ``MeshMemberPresence/temporarilyDisconnected``, and who coordinates this branch.
    ///
    /// **Memory-only, and never sealed** (plan §21.3). Presence is a reversible local judgement;
    /// `MeshSessionContext`'s schema stays at 2 precisely because none of this is written down.
    /// Nil until ``evaluatePartition(reachable:now:)`` has run at least once with a real roster,
    /// which is the honest "this device has not looked yet".
    @ObservationIgnored private(set) var branchView: MeshBranchView?

    /// When this device last counted an authenticated heartbeat from **another** roster member.
    ///
    /// Memory-only for the same reason as ``branchView``. `MeshSessionContext.lastExternalHeartbeat`
    /// exists in the sealed schema and is deliberately still unwritten: sealing on every heartbeat
    /// would be a write per 30 seconds per link, and the idle window it feeds is a live judgement
    /// that a relaunch re-derives (a relaunch never auto-reconnects, invariant 5).
    @ObservationIgnored private(set) var lastExternalHeartbeatAt: Date?

    /// The presence of one roster member, or nil when this device has derived no branch view or the
    /// roster does not name them.
    func presence(of fingerprint: String) -> MeshMemberPresence? { branchView?.presence(of: fingerprint) }

    /// The roster fingerprints this device can reach right now: itself plus every committed active
    /// slot. Uncommitted slots are deliberately excluded — a peer whose identity introduction has
    /// not finished is not somebody this device can reach in the sense a partition means.
    func reachableRosterFingerprints() -> Set<String> {
        Set(activeSlots.compactMap(\.fingerprint) + [identity.localFingerprint])
    }

    /// Re-derives the branch view from the live transport and raises whatever it implies.
    ///
    /// - Parameter now: The instant a fresh idle window would be measured from.
    /// - Returns: What changed.
    @discardableResult
    func evaluatePartition(now: Date) -> MeshPartitionVerdict {
        evaluatePartition(reachable: reachableRosterFingerprints(), now: now)
    }

    /// Plan §10.2's partition detection, evaluated **on demand** against a supplied reachable set.
    ///
    /// There is deliberately **no new timer**: this is the same shape as
    /// ``enforceSessionCeiling(now:monotonicElapsed:)`` and ``evaluateIdleLapse(now:)``, and P7
    /// wires the one poller that drives all three (plan §21.5). Inventing a timer here would
    /// duplicate that seam and give partition its own clock.
    ///
    /// A verdict raises a session event and nothing else: **no record is minted, and the derived
    /// roster does not move.** That is the whole of "disconnect ≠ removal" at this seam.
    ///
    /// - Parameters:
    ///   - reachable: Fingerprints this device can reach. The overload above supplies the live set;
    ///     P5's routed store and the tier-1 suites supply their own.
    ///   - now: The instant a fresh idle window is measured from.
    /// - Returns: What changed. ``MeshPartitionVerdict/unchanged`` whenever there is no live
    ///   session or no derived roster to be partitioned from.
    @discardableResult
    func evaluatePartition(reachable: Set<String>, now: Date) -> MeshPartitionVerdict {
        guard sessionState.isLive, let roster = membershipVerifier?.roster,
              !roster.members.isEmpty else { return .unchanged }
        let current = MeshBranchView(
            roster: roster, reachable: reachable, selfFingerprint: identity.localFingerprint
        )
        let verdict = MeshPartitionDetector.verdict(previous: branchView, current: current)
        branchView = current
        applyPartitionVerdict(verdict, at: now)
        return verdict
    }

    /// Raises the verdict's event, if it has one, and anchors the idle window to the instant the
    /// loss was **judged** rather than to whenever the effect happened to run — so a suite that
    /// passes `now` can predict the deadline exactly and nothing here reads a wall clock.
    private func applyPartitionVerdict(_ verdict: MeshPartitionVerdict, at now: Date) {
        guard let event = verdict.sessionEvent else { return }
        let transition = applySessionEvent(event)
        if verdict == .linksLost, transition.nextState == .partitioned, idleLapseDeadline != nil {
            idleLapseDeadline = now.addingTimeInterval(Self.idleWindowSeconds)
        }
        FernletAuditLog.log(
            "mesh.partition.verdict",
            context: ["verdict": verdict.rawValue, "state": sessionState.rawValue]
        )
    }

    /// Counts an authenticated heartbeat from another roster member, pushing the idle window out.
    ///
    /// Plan §10.2: *"the idle timer does not fire while any external member heartbeats — a live
    /// partition of ≥ 2 stays alive"*. A partition of one has nobody to call this, so its window
    /// runs to ``MeshSessionState/localIdleStop`` at 30 minutes and resumes-as-merge later.
    ///
    /// "External" is mechanical rather than remembered: this device's own fingerprint never counts,
    /// and once a ledger exists only a **current member** does — a departed or removed peer cannot
    /// keep a session this device should be idling alive.
    ///
    /// - Parameters:
    ///   - fingerprint: The authenticated sender. Callers must have verified it; this is a policy
    ///     gate, not a signature check.
    ///   - instant: When the heartbeat was received.
    /// - Returns: `true` when it counted.
    @discardableResult
    func noteExternalHeartbeat(from fingerprint: String, at instant: Date) -> Bool {
        guard fingerprint != identity.localFingerprint else { return false }
        if let roster = membershipVerifier?.roster, !roster.members.isEmpty,
           !roster.contains(fingerprint: fingerprint) {
            return false
        }
        lastExternalHeartbeatAt = instant
        // Only an ARMED window moves: a heartbeat while nothing is armed is recorded and changes
        // no deadline, so this can never arm a timer the state machine did not ask for.
        if idleLapseDeadline != nil {
            idleLapseDeadline = instant.addingTimeInterval(Self.idleWindowSeconds)
        }
        return true
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
            // The heads a restart merges against come off the disk with everything else (item 3):
            // a relaunched member that forgot them would mint `own + 1` and collide with the branch
            // it is reconnecting to.
            knownEpochHeads = context.epochHeads
        }
        if case .resumable(let context) = outcome { restoreMembershipLedger(from: context) }
        // An ending the FILE already records bars the rejoin straight away: the transition below
        // carries no new reason for it (nothing was discovered, it was read), so the bar is set
        // here rather than left to `barRejoin(reason:)`.
        if case .terminated(let context, let reason) = outcome {
            rejoinBar = MeshSessionRejoinBar(meshID: context.meshID, reason: reason)
        }
        applySessionEvent(.contextRestored(outcome.disposition))
        return outcome
    }

    /// Puts the sealed ledger back on this device after a process death, so the reconnect that
    /// follows is a **merge** rather than a fresh session (plan §10.3's fourth entry).
    ///
    /// Without this a relaunched member holds no ledger at all: every membership frame a returning
    /// peer sends is dropped `droppedNoLedger`, and the derived roster falls back to whatever
    /// descriptor happens to be gossiped — which is the "restart rebuilds the ledger instead of
    /// merging what the peer sends" shape §10.3 exists to forbid.
    ///
    /// It is a **re-verification, not a trust**: ``MeshLedgerAdoption/adopt(offered:ownAdmission:meshID:)``
    /// re-derives the whole ledger from its own self-admitted root and proves the chain reaches
    /// this device's own admission before a single record counts, exactly as it does for a joiner
    /// being handed a peer's ledger. A file that does not prove that is left unadopted — the honest
    /// answer for bytes that no longer describe a mesh this device is in.
    ///
    /// Schema stays at **2**: nothing new is written, this only reads what
    /// ``MeshSessionContext/ledger`` has carried since P3 item 4.
    ///
    /// - Parameter context: The restored context.
    private func restoreMembershipLedger(from context: MeshSessionContext) {
        guard membershipVerifier == nil else { return }
        let local = identity.localFingerprint
        guard let own = context.ledger.admissions.all.first(where: { $0.memberFingerprint == local })
        else { return }
        switch MeshLedgerAdoption.adopt(
            offered: context.ledger, ownAdmission: own, meshID: context.meshID
        ) {
        case .adopted(let verifier):
            membershipVerifier = verifier
            // Armed here, spent by the first `beginMerge`: whichever door the user's resume uses,
            // the ledger being merged FROM came off the disk.
            pendingMergeEntry = .processRestart
            FernletAuditLog.log(
                "mesh.sessionRestore.ledgerRestored",
                context: ["members": String(verifier.roster.memberCount)]
            )
        case .refused(let refusal):
            FernletAuditLog.log(
                "mesh.sessionRestore.ledgerRefused",
                context: ["reason": refusal.diagnosticDescription]
            )
        }
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
        // P4 item 2: the resume does not merge for itself — it hands the returning peer's offer to
        // the one path, exactly as a blip, a heal and a restart do.
        return mergeReconnected(
            MeshMergeOffer(ledger: other, head: head),
            entry: pendingMergeEntry ?? .idleLapseResume
        )
    }

    /// One membership frame, decoded and bounded but **not** trusted (P3 item 7).
    ///
    /// Decoding is separated from insertion because a joiner still on its bootstrap ledger cannot
    /// insert anything a peer sends — its provisional root is the member that admitted it, so the
    /// mesh's real founder is `unauthorizedAdmitter` to it. Those records go into a pending ledger
    /// that ``MeshLedgerAdoption`` re-verifies as a whole, and both paths want the same decode.
    private enum DecodedMembershipRecord: Equatable {
        /// An admitter-signed admission.
        case admission(SignedAdmissionRecord)
        /// A leaver's own signed departure.
        case departure(SignedDepartureRecord)
        /// A completed, quorum-signed removal.
        case removal(SignedRemovalRecord)
        /// A member's signed statement that the mesh is over.
        case termination(SignedTerminationRecord)
        /// A peer's signed summary of what it holds.
        case digest(MeshInventoryDigestPayload)
        /// A peer's signed statement of the epoch branch head(s) it is on (P4 item 3).
        case epochHeads(MeshEpochHeadsPayload)
    }

    /// The membership-event family of the dispatch switch (R4: one function per case family) —
    /// `.meshMemberAdmission` / `.meshMemberDeparture` / `.meshMemberRemoval` / `.meshTerminated` /
    /// `.meshInventoryDigest`.
    ///
    /// Member business, so a COMMITTED slot is required: the same boundary the removal, photo and
    /// registry families enforce. Records are then handed to ``MeshMembershipRecordVerifier``,
    /// which is what stops a peer inserting junk with a low timestamp and crowding a real record
    /// out of a sixteen-slot set.
    private func dispatchMembershipEventPayload(
        _ type: PayloadType,
        plaintext: Data,
        decoder: JSONDecoder,
        slot: PeerSlot?,
        now: Date = Date()
    ) {
        guard let senderFingerprint = slot?.fingerprint else {
            FernletAuditLog.log("mesh.membershipEvent.droppedUncommittedSlot", context: ["type": type.rawValue])
            return
        }
        guard membershipVerifier != nil else {
            FernletAuditLog.log("mesh.membershipEvent.droppedNoLedger", context: ["type": type.rawValue])
            return
        }
        guard let decoded = Self.decodeMembershipFrame(type, plaintext: plaintext, decoder: decoder) else {
            return
        }
        if case .digest(let payload) = decoded {
            receiveInventoryDigest(payload)
            return
        }
        // A head set is not a record and cannot move a roster, so it never reaches the ledger path.
        if case .epochHeads(let payload) = decoded {
            receiveEpochHeads(payload)
            return
        }
        if bufferedForAdoption(decoded, from: senderFingerprint) { return }
        // P4 item 2, plan §10.3: a record arriving while a merge is in flight IS the merge — it is
        // the bounded re-gossip answering this device's digest. It goes through the one merge path
        // so the whole batch mints one `.merge` epoch, not one `.membership` epoch per record.
        if awaitingResumeMerge, let offer = Self.mergeOffer(for: decoded) {
            mergeReconnected(offer, entry: pendingMergeEntry ?? .blip, now: now)
            return
        }
        let snapshot = membershipVerifier
        let rosterBefore = membershipVerifier?.roster
        let accepted = insertMembershipRecord(decoded, type: type)
        // P3 item 6, plan §3.6: a record that moved the roster is durable before it counts. The
        // rollback inside `commitVerifiedRecord` is what keeps "verified" and "remembered" the
        // same set after a refused seal.
        guard membershipVerifier?.roster != rosterBefore else { return }
        guard commitVerifiedRecord(rollingBackTo: snapshot, type: type) else { return }
        applyRosterMove(accepted, from: rosterBefore, now: now)
    }

    /// Decodes one membership frame into the record it carries, applying the type's own bounds.
    ///
    /// - Returns: The decoded record, or nil for a frame that did not decode — never a partially
    ///   trusted value.
    private static func decodeMembershipFrame(
        _ type: PayloadType,
        plaintext: Data,
        decoder: JSONDecoder
    ) -> DecodedMembershipRecord? {
        switch type {
        case .meshMemberAdmission:
            return (try? decoder.decode(MeshMemberAdmissionPayload.self, from: plaintext))
                .map { .admission($0.record) }
        case .meshMemberDeparture:
            return (try? decoder.decode(MeshMemberDeparturePayload.self, from: plaintext))
                .map { .departure($0.record) }
        case .meshMemberRemoval:
            return (try? decoder.decode(MeshMemberRemovalPayload.self, from: plaintext))
                .map { .removal($0.record) }
        case .meshTerminated:
            return (try? decoder.decode(MeshTerminationPayload.self, from: plaintext))
                .map { .termination($0.record) }
        case .meshInventoryDigest:
            return (try? decoder.decode(MeshInventoryDigestPayload.self, from: plaintext))
                .map { .digest($0) }
        case .meshEpochHeads:
            return (try? decoder.decode(MeshEpochHeadsPayload.self, from: plaintext))
                .map { .epochHeads($0) }
        default:
            return nil
        }
    }

    /// Wraps one decoded record as a merge offer — a ledger holding exactly it.
    ///
    /// A single record and a whole ledger are the same input to
    /// ``MeshMembershipLedger/merging(_:)``, which is what lets the re-gossip that answers a
    /// reconnect run through the merge path frame by frame without a second mechanism: the union is
    /// idempotent, so a record already held changes nothing and rotates nothing.
    ///
    /// - Returns: The offer, or nil for a frame no roster can see (an inventory digest).
    private static func mergeOffer(for decoded: DecodedMembershipRecord) -> MeshMergeOffer? {
        var ledger = MeshMembershipLedger.empty
        switch decoded {
        case .admission(let record): ledger.admissions = ledger.admissions.inserting(record)
        case .departure(let record): ledger.departures = ledger.departures.inserting(record)
        case .removal(let record): ledger.removals = ledger.removals.inserting(record)
        case .termination(let record): ledger.terminations = ledger.terminations.inserting(record)
        case .digest, .epochHeads: return nil
        }
        return MeshMergeOffer(ledger: ledger)
    }

    /// Offers one decoded record to the verifier.
    ///
    /// - Returns: The record when the verifier ACCEPTED it, and nil for everything else — a record
    ///   it refused, or a frame that carried nothing a roster can see. A refused removal must not
    ///   be able to end anybody's session, which is why the value is returned only on `nil`
    ///   rejection.
    private func insertMembershipRecord(
        _ decoded: DecodedMembershipRecord,
        type: PayloadType
    ) -> DecodedMembershipRecord? {
        let rejection: MeshMembershipRecordRejection?
        switch decoded {
        case .admission(let record): rejection = membershipVerifier?.insert(record)
        case .departure(let record): rejection = membershipVerifier?.insert(record)
        case .removal(let record): rejection = membershipVerifier?.insert(record)
        case .termination(let record): rejection = membershipVerifier?.insert(record)
        case .digest, .epochHeads: return nil
        }
        recordRejection(rejection, type: type)
        // A DEBUG-only console echo, for the same reason P2 item 0 gave the transport's inbound
        // refusals one: without it, "the frame never arrived" and "the frame arrived and was
        // refused" read identically in a `--console-pty` transcript, and a lane cannot tell a
        // transport fault from a membership one. Compiled to nothing in Release.
        MeshTransportConsoleLog.echo(
            "membershipRecord \(type.rawValue) "
                + (rejection.map(\.diagnosticDescription) ?? "accepted")
        )
        return rejection == nil ? decoded : nil
    }

    /// What a durable, roster-moving record means for THIS device (plan §8.2's `removed` and
    /// `terminationVerified` edges, §8.3's rotation trigger).
    ///
    /// Exactly one of the three happens. A removal naming this device ends the session; a
    /// termination that the **merged** roster agrees with ends it too; anything else — including a
    /// termination the merged roster downgrades to its signer's departure — is a roster change like
    /// any other and rotates the key.
    private func applyRosterMove(
        _ accepted: DecodedMembershipRecord?, from before: MeshDerivedRoster?, now: Date = Date()
    ) {
        if case .removal(let record) = accepted, record.memberFingerprint == identity.localFingerprint {
            applyVerifiedSelfRemoval()
            return
        }
        if case .termination = accepted, membershipVerifier?.roster.status == .terminated {
            applyVerifiedTermination()
            return
        }
        // P5 item 8's first claim door: the record that just moved the roster is durable, so a
        // departure naming this device a custodian can be acted on now.
        claimHandedOffCustody(now: now)
        rotateIfRosterChanged(from: before)
    }

    /// A verified removal record named **this device** (plan §8.2's `removed` edge, §8.3).
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

    /// A verified termination that this device's **merged** roster agrees with: the mesh is over
    /// (plan §8.2's `terminationVerified` edge, §8.3, P3 item 7).
    ///
    /// Item 6 built the edge and left it unwired because deciding whether a received record ends
    /// the mesh or only its signer's membership needs the derived roster — ``MeshDerivedRoster``
    /// applies §8.3's downgrade rule, so by the time this runs the answer is already `terminated`
    /// and the other branch never reaches here. Ending mark, then teardown, then the permanent
    /// rejoin bar the mark raised: a terminated mesh can never be rejoined.
    private func applyVerifiedTermination() {
        FernletAuditLog.log("mesh.membershipEvent.terminationVerified")
        applySessionEvent(.terminationVerified)
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

    // MARK: Adoption (P3 item 7, plan §8.3, §10.5)

    /// Records a joiner has been sent but cannot yet insert, held until they add up to a ledger.
    ///
    /// Non-nil only while this device is on its bootstrap ledger, fed only by the peer that
    /// admitted it, and bounded by the record sets' own caps. It is untrusted throughout:
    /// ``MeshLedgerAdoption/adopt(offered:ownAdmission:meshID:)`` verifies every record in it from
    /// the offered root before a single one counts.
    @ObservationIgnored private var pendingAdoptionLedger = MeshMembershipLedger.empty

    /// Whether a decoded record was taken for adoption rather than inserted.
    ///
    /// A joiner's provisional root is the member that admitted it, so the mesh's real founder — and
    /// therefore every record chained from the founder — is `unauthorizedAdmitter` to it. Inserting
    /// one at a time can never converge; the whole offered ledger has to be re-verified from its
    /// own root. Buffering is restricted to the peer this device asked (its admitter), so a third
    /// party cannot crowd the bounded buffer with low-timestamp junk before adoption verifies it.
    ///
    /// - Returns: `true` when the record was buffered and the caller must not insert it.
    private func bufferedForAdoption(_ decoded: DecodedMembershipRecord, from senderFingerprint: String) -> Bool {
        guard let verifier = membershipVerifier,
              MeshLedgerAdoption.isBootstrap(verifier.ledger, selfFingerprint: identity.localFingerprint),
              let ownAdmission = verifier.ledger.admissions.earliest,
              senderFingerprint == ownAdmission.token.admitterFingerprint else {
            return false
        }
        switch decoded {
        case .admission(let record): pendingAdoptionLedger.admissions = pendingAdoptionLedger.admissions.inserting(record)
        case .departure(let record): pendingAdoptionLedger.departures = pendingAdoptionLedger.departures.inserting(record)
        case .removal(let record): pendingAdoptionLedger.removals = pendingAdoptionLedger.removals.inserting(record)
        case .termination(let record): pendingAdoptionLedger.terminations = pendingAdoptionLedger.terminations.inserting(record)
        case .digest, .epochHeads: return false
        }
        attemptLedgerAdoption(ownAdmission: ownAdmission, meshID: verifier.meshID)
        return true
    }

    /// Tries to rebase this device off its bootstrap ledger onto the one the buffer now describes.
    ///
    /// Failure is not an error and is not final: the chain to this device's admitter simply is not
    /// proven yet, so the buffer keeps growing until the peer's re-gossip has delivered the records
    /// that prove it. Success is durable before it counts (plan §3.6) — a rebase this device could
    /// not seal is rolled back to the bootstrap ledger.
    ///
    /// **A successful rebase owes the admitter one digest** (P5 item 7, D-7.33). The admitter's
    /// merge window may have been open when it granted the admission, in which case this device's
    /// grant-reply digest — a bootstrap ledger, one record long — mismatched, and the admitter put
    /// it in `answered`, i.e. in `pending`. Adoption is the only moment this device's ledger reaches
    /// the admitter's, and it happens through a rebase rather than
    /// ``mergeMembershipLedger(_:)``, so the post-merge proof door never fires and a joiner would
    /// otherwise have no second occasion to speak — stranding the admitter's window for the rest of
    /// the session. It is not an ask: no window opens here, and there is no routed twin (the
    /// grant reply already advertised this device's `.absent` routed store, and a second
    /// advertisement would re-spend the drain's per-peer session budget).
    private func attemptLedgerAdoption(ownAdmission: SignedAdmissionRecord, meshID: UUID) {
        let outcome = MeshLedgerAdoption.adopt(
            offered: pendingAdoptionLedger, ownAdmission: ownAdmission, meshID: meshID
        )
        guard case .adopted(let adopted) = outcome else { return }
        let snapshot = membershipVerifier
        membershipVerifier = adopted
        guard commitVerifiedRecord(rollingBackTo: snapshot, type: .meshMemberAdmission) else { return }
        pendingAdoptionLedger = .empty
        FernletAuditLog.log(
            "mesh.membershipLedger.adopted",
            context: ["members": String(adopted.roster.memberCount)]
        )
        applyAdoptedRosterVerdict(adopted.roster)
        let admitter = ownAdmission.token.admitterFingerprint
        spawnHostPinned { [weak self] in await self?.sendInventoryDigest(to: [admitter]) }
    }

    /// What a freshly adopted roster says about THIS device.
    ///
    /// The adoption path bypasses ``applyRosterMove(_:from:)`` — it rebases rather than inserting —
    /// so the two endings that can arrive *inside* the adopted ledger have to be applied here too.
    /// A joiner whose admitter hands it a ledger already carrying its own removal, or a termination,
    /// must end its session rather than sit in a mesh whose every member will refuse it at the next
    /// introduction. Narrow but real: the removal can land during the one round trip a bootstrap
    /// takes.
    private func applyAdoptedRosterVerdict(_ roster: MeshDerivedRoster) {
        if roster.status == .terminated {
            applyVerifiedTermination()
            return
        }
        guard !roster.contains(fingerprint: identity.localFingerprint) else { return }
        applyVerifiedSelfRemoval()
    }

    /// Verifies a peer's digest, remembers it, and answers with the records **and the epoch heads**
    /// this device holds when the two ledgers differ (plan §10.5). A digest that DIFFERS is not an
    /// error — that is the signal, and the answer is one bounded re-gossip per peer per session.
    ///
    /// Both sides answer, because "I hold fewer records" and "I hold different records" are not the
    /// same thing and a count cannot tell them apart. The loop is closed elsewhere: the batch is
    /// once per peer per session, and a record frame never provokes another digest — so a fresh
    /// joiner converges in one round trip rather than in a ping-pong.
    ///
    /// **The answer carries both halves of §10.3's exchange, exactly as the ask does** (P4 item 2c).
    /// A device inside an open merge window opens no second exchange
    /// (``openBlipMergeIfReconnected(_:from:peer:)``), and an exchange is the only other thing that
    /// sends a ``PayloadType/meshEpochHeads`` frame — so an answer of records alone leaves a peer
    /// that converged on this device's *ledger* still counting up from its own older head, with
    /// nothing left in flight to correct it. Found by the seeded convergence property
    /// (`MeshConvergencePropertyTests`), where a chain heal left one member on a lower
    /// ``rotationBasisHead`` than its peers for good.
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
        if peerInventoryDigests[payload.senderFingerprint] != nil
            || peerInventoryDigests.count < MeshMembershipBounds.maxRosterMembers {
            peerInventoryDigests[payload.senderFingerprint] = payload.digest   // R3: bounded map
        }
        // The WINDOW's own evidence, separate from the hint map above: it is seeded only while a
        // window is open and dies with it, so no comparison can ever use a digest from before this
        // exchange began (P5 item 7).
        mergeWindow = mergeWindow?.recording(payload.digest, from: payload.senderFingerprint)
        // A matching digest is this peer's half of plan §10.3's merge, proven. The window closes
        // only once EVERY peer it is waiting on has done the same.
        guard !verifier.matchesLocalInventory(payload.digest) else {
            recordMergeMatch(payload.senderFingerprint)
            return
        }
        // A mismatch this device answers is an obligation, never a discharge: it also un-matches
        // the sender, because a verified present-tense digest that differs is evidence any earlier
        // match is stale.
        recordMergeAnswer(payload.senderFingerprint)
        // One task, so the answer's two halves reach the wire in a fixed order: the records the
        // peer is missing, then the head this device is on. Order is not load-bearing (a fold and a
        // record commute), determinism is.
        spawnHostPinned { [weak self] in
            await self?.reGossipRecords(to: payload.senderFingerprint)
            await self?.sendEpochHeads(to: [payload.senderFingerprint])
        }
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

    /// The **signed** removal quorum family (P4 item 5, plan §10.4), gated at the wire boundary.
    ///
    /// A COMMITTED slot is required, as for every other member-business family. Unlike the legacy
    /// two-party pair, the sender fingerprint is deliberately **not** compared to the claimed
    /// proposer or voter: these frames carry their own signature over their own domain, and
    /// ``MeshMembershipRecordVerifier`` checks it against the key the ledger's admissions bound. A
    /// sender-must-be-author rule would additionally forbid relaying, which is the one thing a
    /// partitioned quorum genuinely wants.
    private func dispatchRemovalQuorumPayload(
        _ type: PayloadType,
        plaintext: Data,
        decoder: JSONDecoder,
        slot: PeerSlot?
    ) {
        guard slot?.fingerprint != nil else {
            FernletAuditLog.log("mesh.removalQuorum.droppedUncommittedSlot", context: ["type": type.rawValue])
            return
        }
        switch type {
        case .meshRemovalProposalSigned:
            guard let payload = try? decoder.decode(SignedRemovalProposal.self, from: plaintext) else { return }
            receiveSignedRemovalProposal(payload)
        case .meshRemovalVote:
            guard let payload = try? decoder.decode(SignedRemovalVote.self, from: plaintext) else { return }
            receiveSignedRemovalVote(payload)
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
                spawnHostPinned { [weak self] in await self?.handleEncryptedMetadata(wrapper, from: peer, slot: slot) }
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
                spawnHostPinned { [weak self] in await self?.handleKeyRotation(rotation, senderFingerprint: senderFingerprint) }
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

    /// Spawns a detached task that PINS this manager's host for the task's own lifetime.
    ///
    /// ``store`` is `unowned` because the host owns this manager (`FernletStore.swift`'s `lazy var`
    /// managers), and the unowned back-reference is that ownership's cycle-breaker. A detached task,
    /// however, holds `self` STRONGLY for the duration of every `self?.method()` it awaits, so it can
    /// outlive the host and then read a destroyed object — `swift_abortRetainUnowned` aborts the whole
    /// process, which is what P5 item 1a's crash reports are. Capturing the host here, read
    /// synchronously on the main actor at a point where it is provably alive, makes the read the task
    /// will later perform valid by construction (invariant HP1).
    ///
    /// The pin is safe ONLY because this task's handle is not stored on the manager: nothing the host
    /// owns can reach this closure context, so no `store → manager → task → store` cycle forms. NEVER
    /// build the same pin into a task whose handle the manager keeps (invariant HP2) — see the `// host-pin: timer`
    /// markers on the sites in this file that must not use this helper.
    ///
    /// The closure is deliberately neither `@Sendable` nor `sending`, so it inherits this manager's
    /// isolation exactly as the `Task { … }` literal it replaces did — same executor, same enqueue,
    /// same ordering. It carries no `@_implicitSelfCapture` either, so a strong `self` capture has to
    /// be spelled `self.` at the call site.
    private func spawnHostPinned(_ operation: @escaping () async -> Void) {
        let host = store
        Task {   // host-pin: helper
            await operation()
            withExtendedLifetime(host) {}
        }
    }

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
            // A closed *mesh* must still accept its own members' links — see
            // ``mayLinkToDiscoveredPeers``; this closure is the QUIC radio's `invitationGate`, and
            // a false answer here is a tunnel the far side sees die with no reason on either end.
            if self.isProximityJoin && !self.mayLinkToDiscoveredPeers { return false }
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
        guard isProximityJoin, mayLinkToDiscoveredPeers, !wasCommitted, !wasKickedLocally else { return }
        guard shouldInitiateInvite(to: peer) else { return }
        let retryCount = peerRetryCount[peer.endpoint, default: 0]
        guard retryCount < Self.maxPeerRetries else { return }
        peerRetryCount[peer.endpoint] = retryCount + 1
        spawnHostPinned { [weak self] in
            // A cancelled retry must not invite (R7).
            do {
                try await Task.sleep(for: .seconds(Self.reinviteDelaySeconds))
            } catch {
                return
            }
            guard let self, self.isProximityJoin, self.mayLinkToDiscoveredPeers,
                  self.slots.count < Self.maxTotalSlots,
                  !self.hasSlot(for: peer) else { return }
            self.transport.invite(peer)
        }
    }

    private func startSearching() {
        isSearching = true
        // P5 item 9: the Friends tab — the banner's own screen — is one tap away, so a hold whose
        // condition has since expired is corrected before it is read. Guarded on the hold, so this
        // costs nothing at all (no load, no I/O) in the overwhelmingly common case.
        if routedDeliveryHold != nil { sweepRoutedExpiry() }
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
        // host-pin: exempt — coordinator/channel only, no `self`, no host read
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
            guard mayLinkToDiscoveredPeers else { return }
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
    ///
    /// The third of the three link gates ``mayLinkToDiscoveredPeers`` corrects, and the one that
    /// survived the first two being fixed: a member of a `.closed` mesh dialed its co-member,
    /// completed the signed introduction, and was then **evicted here** — which the far side reads
    /// as its control stream dying mid-frame (`MeshTransportError.invalidFrameLength`), re-dials,
    /// and is evicted again. A `localEviction` loop, not a transport defect.
    func channelAdmission(for peer: PeerHandle) -> ChannelAdmission {
        guard !isProximityJoin || mayLinkToDiscoveredPeers else { return .kick }
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

        // host-pin: exempt — coordinator/channel only, no `self`, no host read
        Task {
            await coordinator.begin(role: .browser, mode: .friend)
            channel.notifyConnected()
        }
    }

    private func removeSlot(_ slot: PeerSlot) {
        // host-pin: exempt — coordinator/channel only, no `self`, no host read
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
        // A peer whose slot is gone leaves the merge window's reach set, so the verdict is spent at
        // the moment it changes rather than at the next inbound frame. `rerankSlots()` is NOT an
        // evaluation site and must not become one: it moves `kind`, which the rule never reads.
        concludeMergeIfConverged()
        promoteRosterToPendingReviewIfSessionEnded()
        openShopWindowIfSessionEnded()
        clearSessionMessagesIfSessionEnded()
    }

    private func disconnectSlot(_ slot: PeerSlot) {
        spawnHostPinned { [weak self] in
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
        // A peer whose slot is gone leaves the merge window's reach set, so the verdict is spent at
        // the moment it changes rather than at the next inbound frame. `rerankSlots()` is NOT an
        // evaluation site and must not become one: it moves `kind`, which the rule never reads.
        concludeMergeIfConverged()
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
            spawnHostPinned { [weak self] in
                guard let self else { return }
                await self.syncPhotoManifest(to: slot)
                await self.sendVouchList(to: slot)
            }
            return
        }

        if currentMesh != nil {
            spawnHostPinned { [weak self] in
                guard let self else { return }
                await self.sendMeshDescriptor(to: slot)
                await self.syncPhotoManifest(to: slot)
            }
        }
        // Exchange vouch lists after every successful identity verification
        spawnHostPinned { [weak self] in await self?.sendVouchList(to: slot) }

        // P3 item 6: the first committed peer makes a joining session active (plan §8.2). P4 item 2
        // hangs the blip and the partial heal off the same event inside ``applySessionEvent(_:)``,
        // so every reconnect entry is one call rather than a rule this site has to remember. The
        // fingerprint is passed because only a peer that was ALREADY a member is reconnecting — a
        // new admission keeps its own `.membership` rotation.
        if currentMesh != nil {
            applySessionEvent(.peerCommitted, committedPeer: peerIdentity.fingerprint)
        }

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
        spawnHostPinned { [weak self] in
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
        // host-pin: exempt — coordinator/channel only, no `self`, no host read
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
        spawnHostPinned { await self.sendVerifyEnvelope(.verifyChallenge, encodable: challenge, to: peer, via: slot) }
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
        spawnHostPinned {
            await self.sendVerifyEnvelope(
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

    /// Sends the current descriptor to every **committed** slot.
    ///
    /// The commit gate is defence in depth beside
    /// ``maySeatVerifiedPeer(signingPublicKey:)``: the descriptor is a plaintext envelope naming
    /// the mesh, every member's fingerprint, display name and both public keys, and an
    /// uncommitted slot is by definition one whose peer has not finished proving who it is. The
    /// loop used to walk every slot, so a pre-commit candidate — on MC, any device that had merely
    /// connected — received it.
    private func broadcastMeshDescriptor() {
        guard let mesh = currentMesh else { return }
        let payload = MeshStateChangePayload(descriptor: mesh)
        for slot in slots where slot.fingerprint != nil {
            spawnHostPinned { [weak self] in await self?.sendEnvelope(.meshDescriptor, encodable: payload, via: slot) }
        }
        updateDiscoveryInfo()
    }

    /// Sends the current descriptor to one slot. Same gate, same reason as
    /// ``broadcastMeshDescriptor()`` — every caller is a commit path, and the guard says so.
    private func sendMeshDescriptor(to slot: PeerSlot) async {
        guard let mesh = currentMesh, slot.fingerprint != nil else { return }
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
            spawnHostPinned { [weak self] in await self?.sendEnvelope(.meshAdmissionRequest, encodable: request, via: slot) }
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
            spawnHostPinned { [weak self] in
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
        // P3 item 7, plan §8.3/§20.4.4: the admission is verified, so this device arms its ledger
        // with it. Until item 7 a joiner held no ledger at all and refused every membership record
        // it was sent as `signerNotAdmitted`; from here it is a member of its own roster.
        let ledgerBeforeJoin = membershipVerifier
        guard armJoinerLedger(grant) else { return }
        // P3 item 6, plan §3.6: the admission is verified, so the context is written BEFORE this
        // device adopts the epoch, unwraps the key or starts a beacon — before, in other words,
        // anything tells the user or the peers that it has joined.
        guard recordVerifiedAdmissionDurably() else {
            membershipVerifier = ledgerBeforeJoin
            return
        }

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
        // One round trip to convergence (plan §10.5): ask the peer that admitted us what it holds.
        // Its reply is the bounded record re-gossip, and `MeshLedgerAdoption` rebases this device's
        // provisional root onto the mesh's real founder when it arrives.
        if let fingerprint = slot?.fingerprint {
            spawnHostPinned { [weak self] in
                await self?.sendInventoryDigest(to: [fingerprint])
                // A joiner's routed store is `.absent`, and saying so is what lets the admitter
                // offer it anything at all — the drain is push-only (item 6).
                await self?.sendRoutedInventory(to: [fingerprint])
            }
        }
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
        spawnHostPinned { [weak self] in
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
        spawnHostPinned { [weak self] in
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
            spawnHostPinned { [weak self] in
                await self?.sendShopCatalog(to: slot)
                await self?.sendShopCatalogRequest(to: slot)
            }
        }
        // Phase 3b: hand our own signed moderation reports to this committed friend (one-hop relay).
        // The send method additionally requires the recipient be a vault-trusted (kept) friend.
        if peerIdentity.supports(.moderation) {
            let recipientKey = peerIdentity.signingPublicKey
            spawnHostPinned { [weak self] in await self?.sendModerationReports(to: slot, recipientSigningKey: recipientKey) }
        }
        // Phase 4: share our fuzzy vibe + appearance with this committed friend (kept friends only).
        if peerIdentity.supports(.friendState) {
            let recipientKey = peerIdentity.signingPublicKey
            spawnHostPinned { [weak self] in await self?.sendFriendState(to: slot, recipientSigningKey: recipientKey) }
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
        spawnHostPinned { [weak self] in await self?.sendShopCatalog(to: slot) }
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
            spawnHostPinned { [weak self] in
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
        // host-pin: timer — stored handle; its only host reads are the pinned per-slot fan-out (HP2)
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
            spawnHostPinned { [weak self] in await self?.sendEnvelope(.meshCoordinatorBeacon, encodable: beacon, via: slot) }
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
        // host-pin: timer — stored handle, synchronous main-actor body (`requestRotation`) (HP2)
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
        // host-pin: timer — stored handle; `runDebouncedRotation()` takes the scoped pin instead (HP2)
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
        let host = store   // host-pin: scoped — spans initiateRotation's ack window and its sends
        defer { withExtendedLifetime(host) {} }
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
        await distributeRotation(nextEpoch, cause: cause, acked: acked)
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
        // P4 item 3, plan §10.3: `max + 1` over the FOLDED head set, not `own + 1`. A branch that
        // rotated twice while this one rotated once put a higher counter in the sealed heads than
        // this device's own key ever carried, and minting from the keyring head would collide with
        // an epoch that already exists.
        let plan = MeshRotationPolicy.plan(
            head: rotationBasisHead,
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
    ///
    /// It no longer takes the closing epoch: since P4 item 3 the counter on the wire is the minted
    /// ref's own (`max + 1` over the folded heads), not "one more than the key this device happens
    /// to hold" — and a parameter that could still be read would be an invitation to re-derive it
    /// the old way on a merge, where the two answers differ.
    private func distributeRotation(
        _ nextEpoch: MeshEpochRef,
        cause: MeshKeyRotationCause,
        acked: Set<String>
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
        // The counter the frame carries IS the minted ref's, because every receiver re-derives the
        // ref from it (`adoptRotatedEpoch` → `epochRef(counter:coordinatorFingerprint:)`). Before
        // P4 item 3 this was `closingEpoch + 1`, which agreed with the ref only while a rotation
        // counted up from this device's own head; a merge counts up from the folded `max`, and the
        // two spellings would then name different epochs on the two ends of the same rotation.
        let rotation = MeshKeyRotationPayload(
            newEpoch: Int(nextEpoch.counter),
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

    /// The roster this device presents with a rotation, **scoped to its branch** while partitioned
    /// (plan §10.2: each branch derives its own coordinator and runs its own 15-minute rotation).
    ///
    /// It must be the same set ``epochCoordinatorFingerprint`` takes its minimum from, or this
    /// device would present a roster it is not the coordinator of and refuse its own rotation —
    /// which is why the branch scoping happens here, once, and the coordinator falls out of it.
    ///
    /// The branch is applied as an **intersection with the current full roster**, not as a
    /// substitute for it: ``branchView`` is a snapshot that a departure or removal since the last
    /// evaluation could have outdated, and a rotation must never present a member the records have
    /// already excluded. Off a partition — including everywhere in shipping code today, since
    /// nothing calls ``evaluatePartition(reachable:now:)`` until P7 wires the poller — this is
    /// exactly the value it always was.
    private func presentedRotationRoster() -> [String] {
        let full = fullRotationRoster()
        guard let branch = branchView, branch.isPartitioned else { return full }
        let present = Set(branch.presentFingerprints)
        let scoped = full.filter { present.contains($0) }
        return scoped.isEmpty ? full : scoped
    }

    /// The whole roster this device would present absent any partition: the derived roster when the
    /// ledger knows one, else the gossiped descriptor's members plus self.
    private func fullRotationRoster() -> [String] {
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
        // host-pin: timer — stored handle; `handleRotationSync` takes the scoped pin instead (HP2)
        rotationSyncTask = Task { @MainActor [weak self] in
            await self?.handleRotationSync(sync, senderFingerprint: senderFingerprint)
            self?.rotationSyncTask = nil
        }
    }

    /// Non-coordinator: respond to a rotation sync from the coordinator.
    private func handleRotationSync(_ sync: MeshRotationSyncPayload, senderFingerprint: String?) async {
        // Accept only from the elected coordinator (sender-authenticated).
        guard let senderFP = senderFingerprint, isElectedCoordinator(senderFP) else { return }
        let host = store   // host-pin: scoped — spans the drain sleep before the meshKeyAck sends
        defer { withExtendedLifetime(host) {} }
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
        // Slots refused by the closed-mesh roster check, evicted AFTER the loop: `removeSlot`
        // mutates `slots`, and the indices this loop walks must stay valid.
        var refused: [PeerSlot] = []
        for index in slots.indices {
            if case .connected(let peerIdentity) = slots[index].coordinator.state {
                let fp = peerIdentity.fingerprint
                if slots[index].fingerprint != fp {
                    // BEFORE `onSlotConnected`, which is what sends the mesh descriptor, the photo
                    // manifest and the vouch list. A stranger on a closed mesh must never reach it
                    // — see ``maySeatVerifiedPeer(signingPublicKey:)``. The slot's `fingerprint`
                    // stays nil, so nothing downstream reads it as committed.
                    guard maySeatVerifiedPeer(signingPublicKey: peerIdentity.signingPublicKey) else {
                        FernletAuditLog.log("mesh.slot.refusedClosedMeshStranger")
                        refused.append(slots[index])
                        continue
                    }
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
        for slot in refused { removeSlot(slot) }
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
    /// `channel` defaults to a ``DetachedPeerChannel``, whose `send` throws — a test that does not
    /// care what crosses the wire must not be able to pass over a send that never happened. Pass a
    /// recording channel to assert the opposite: that a frame was NOT sent to this slot.
    func addSlotForTesting(
        coordinator: ProximityCoordinator,
        peer: PeerHandle,
        fingerprint: String?,
        verifiedKeyAgreementPublicKey: Data? = nil,
        peerCapabilities: [String]? = nil,
        kind: SlotKind = .active,
        stableDistanceMeters: Double? = nil,
        channel: (any MeshPeerChannel)? = nil
    ) {
        var slot = PeerSlot(
            id: peer.id,
            peer: peer,
            channel: channel ?? DetachedPeerChannel(peer: peer),
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

    /// The roster this device would present with a rotation right now — **branch-scoped** while
    /// partitioned (P4 item 1, plan §10.2).
    ///
    /// The derivation is private in shipping code, and a suite has to see that the branch scoping
    /// reached the *rotation* rather than only the ``branchView`` it was derived from: the two must
    /// move together, or this device presents a roster it is not the coordinator of.
    var rotationRosterForTesting: [String] { presentedRotationRoster() }

    /// The coordinator that roster elects — the fingerprint every ``MeshEpochRef`` this device
    /// mints is named after, and therefore the reason two branches' same-counter epochs are
    /// distinct refs that `coexist` (plan §21.1).
    var epochCoordinatorFingerprintForTesting: String? { epochCoordinatorFingerprint }

    /// The head a merge would count up from — plan §10.3's `max` (P4 item 3). Private in shipping
    /// code, because nothing but the rotation planner may read it.
    var rotationBasisHeadForTesting: MeshEpochRef? { rotationBasisHead }

    /// The heads this device would put in a `fernlet.mesh.epoch-heads.v1` frame right now, so a
    /// suite can prove what crossed the wire is what the device is actually on.
    var presentedEpochHeadsForTesting: [MeshEpochRef] { presentedEpochHeads() }

    /// The peers this device has already spent its once-per-session record re-gossip on (§10.5),
    /// and how many committed peers it can reach right now.
    ///
    /// Exposed for the convergence property, where "this member never learned the departure" and
    /// "every peer that knew it had already answered this member" are different diagnoses with the
    /// same symptom — and only the second is §10.5's own bound rather than a lost frame.
    var reGossipDiagnosticsForTesting: (answered: Set<String>, slots: Int) {
        (reGossipedToFingerprints, activeSlots.count)
    }

    /// The merge exchange now in flight, so a cell can assert WHICH peers a window is still
    /// waiting on rather than only that `awaitingResumeMerge` is true.
    var mergeWindowForTesting: MeshMergeWindow? { mergeWindow }

    /// Why the last merge window closed — `.converged` (every waited-on peer proved it) or
    /// `.nothingOutstanding` (they stopped being reachable members).
    var lastMergeClosureForTesting: MeshMergeWindowClosure? { lastMergeClosure }

    /// The bulk frames charged to each peer this session — D-6.5's per-peer budget.
    ///
    /// Readable so a suite can pin that the charge equals the frames actually sent (a budget nothing
    /// reads is a budget that can be deleted silently), and writable so "a peer whose budget is
    /// spent still gets the inventory and the answer bit" can be driven in one exchange rather than
    /// by sending a thousand real frames.
    var routedDrainFramesSpentForTesting: [String: Int] {
        get { routedDrainFramesSpent }
        set { routedDrainFramesSpent = newValue }
    }

    /// The items whose manifest this device admitted **from their own origin** — P5 item 8's hop
    /// bound (`originServedItems`).
    ///
    /// Readable because the bound is otherwise unobservable: a set nothing can see is a set a future
    /// widening can drop without a single test going red, and §4.2a's whole claim is that a device
    /// which took an item from a *custodian* is not entitled to courier it onward.
    var originServedItemsForTesting: Set<MeshRoutedItemKey> { originServedItems }

    /// How many durable custody commits are queued past this evaluation's cap
    /// (`deferredCustodyCommits`) — the named deferral, made observable so "retried at the next
    /// evaluation" is a measured claim rather than a comment.
    var deferredCustodyCommitCountForTesting: Int { deferredCustodyCommits.count }

    /// Runs the custody claim exactly as the four shipping doors run it.
    ///
    /// **Not a fifth door.** The doors are named in ``claimHandedOffCustody(now:excluding:)``'s own
    /// documentation and walled there; this seam exists so a suite can measure the claim's *gates*
    /// — the removed-leaver filter and the origin-served bound — directly, rather than inferring
    /// them from whichever door a scenario happened to reach. A gate whose only coverage is a
    /// scenario that short-circuits before it is a gate with no coverage at all.
    ///
    /// - Parameter now: The injected instant, so a cell asserts against a clock rather than a date.
    func claimHandedOffCustodyForTesting(now: Date) {
        claimHandedOffCustody(now: now)
    }

    /// The ref a member re-derives from the two values a rotation frame carries. It is the
    /// SHIPPING derivation, exposed rather than re-implemented, so a test proving "both ends land
    /// on the identical epoch" cannot pass against a test-local copy that has drifted.
    func epochRefForTesting(counter: Int, coordinatorFingerprint: String?) -> MeshEpochRef? {
        epochRef(counter: counter, coordinatorFingerprint: coordinatorFingerprint)
    }

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

    /// Test seam: fires the coordinator-beacon fan-out — the detached per-slot send `Task` family
    /// named by P5 item 1a's crash reports (`displayName.getter ← sendEnvelopeCore ← closure #1 in
    /// broadcastCoordinatorBeacon`). The beacon refuses without a known next rotation, so the seam
    /// supplies one. Mirrors ``rotateNowForTesting(cause:)``.
    func broadcastCoordinatorBeaconForTesting(nextRotationAt: Date = Date().addingTimeInterval(900)) {
        lastKnownNextRotationAt = nextRotationAt
        broadcastCoordinatorBeacon()
    }

    /// Test seam: arms the 20-second beacon loop — the manager's longest-lived stored `Task` handle,
    /// and the one whose closure context must NEVER pin the host (invariant HP2).
    /// `MemoryLifecycleTests` uses it to prove a store-owned manager still deallocates with the loop
    /// running, which is what stops ``spawnHostPinned(_:)`` from being copied onto `beaconTimer`.
    func startBeaconLoopForTesting() {
        startBeaconLoop()
    }

    /// Disarms whatever the debounce window is holding, and reports what it was.
    ///
    /// The determinism half of ``rotateNowForTesting(cause:)``: a scenario that asserts what a
    /// merge *asked for* and then runs that rotation by hand would otherwise leave a live 2-second
    /// task behind, and under a loaded suite that window can elapse mid-scenario and rotate a
    /// second time. Sampling and disarming in one synchronous call is the same discipline
    /// `MeshMergeExchangeTests` uses when it reads `pendingCause` inside its pump.
    @discardableResult
    func consumePendingRotationForTesting() -> MeshKeyRotationCause? {
        let pending = rotationTriggers.pendingCause
        rotationDebounceTask?.cancel()
        rotationDebounceTask = nil
        rotationTriggers.reset()
        return pending
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

    /// Whether this device may admit a tunnel to a peer on a **divergent** branch so plan §10.3's
    /// merge can reconcile the two heads (P4 item 3).
    ///
    /// ## What changed and why it is safe
    ///
    /// Before item 3, ``MeshEpochAcceptance/introductionVerdict(local:peer:)`` answered `divergent`
    /// for two well-formed unequal heads and the QUIC transport tore the tunnel down. That was a
    /// deadlock: the merge that reconciles two branches runs *over* the tunnel it was refusing, so
    /// two members that had each rotated while split could never reconnect at all.
    ///
    /// The relaxation is scoped three ways, and each one is what makes it safe rather than a
    /// widened door:
    ///
    /// 1. **It is a link-layer relaxation on a members-only transport.** ``MeshChannelIntroductionExchange``
    ///    is reached from ``NetworkMeshSession`` and nowhere else — MC never runs a signed channel
    ///    introduction — which is exactly the distinction 0b's review drew and the reason
    ///    ``maySeatVerifiedPeer(signingPublicKey:)`` exists for the other radio.
    /// 2. **Only the epoch rule moved.** The hello still has to be well formed, name this mesh,
    ///    carry a canonical epoch reference, present a fresh nonce, and — immediately after this
    ///    check — be a `member` by ``roster``'s own verdict. A stranger, a departed member, a
    ///    removed one and a foreign mesh are refused exactly as strictly as before.
    /// 3. **Only when a merge can actually run.** A device with no mesh or no membership ledger has
    ///    nothing to reconcile *with*, so it keeps the old refusal
    ///    (``MeshIntroductionRejection/divergentEpoch``) rather than admitting a tunnel that could
    ///    only sit there.
    var mayReconcileDivergentEpochs: Bool {
        currentMesh != nil && membershipVerifier != nil
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

    /// Who may connect right now: **the derived roster** `admitted − departed − removed`
    /// (P3 item 7, plan §8.1/§20.4.4), read fresh on every introduction.
    ///
    /// `barred` has real contents from here on. The gap plan §20.1 recorded — "the manager records
    /// removals by fingerprint and holds no signing key for a member it has dropped" — is closed by
    /// ``SignedAdmissionRecord``, which keeps the admitted member's signing key inside the record,
    /// so a removal or a departure names a *key*. A peer with a verified removal record is now
    /// refused as ``MeshRosterVerdict/barred`` by the shipping authority's own answer, where before
    /// it fell out of `members` and refused as an anonymous ``MeshRosterVerdict/stranger``.
    ///
    /// ## The legacy fallback, and when it can be reached
    ///
    /// With no ledger — or an empty one — the answer falls back to the gossiped descriptor's
    /// members. A founder has a one-member ledger from the instant it founds
    /// (``startNewMesh(name:)``) and a joiner from the instant its admission verifies
    /// (``handleAdmissionGrant(_:slot:senderSigningPublicKey:)``), so on a shipping path this is
    /// reachable only where a mesh descriptor arrived without either: a test that sets
    /// `currentMesh` directly, or interop with a build predating P3's records. It is logged once
    /// per manager under a distinct key so "the roster came from gossip" is never a silent answer.
    ///
    /// ``MeshIntroductionChaos/additionalBarredKeys`` is `[]` in every Release build and in every
    /// DEBUG launch that does not ask for it, so the production answer is unchanged. It survives
    /// item 7 as the ONLY way to reach the barred branch on a two-node lane, where no quorum for a
    /// real removal exists (item 9's 3-node lane retires it). It can only ever *refuse* a peer this
    /// roster would have admitted (barred wins over member), never the reverse.
    var roster: MeshIntroductionRoster {
        guard let derived = membershipVerifier?.roster, !derived.members.isEmpty else {
            return legacyIntroductionRoster()
        }
        return derived.introductionRoster(additionalBarred: MeshIntroductionChaos.additionalBarredKeys)
    }

    /// The pre-records answer: the gossiped descriptor's members, with nobody nameably barred.
    /// Logged once per manager, because a roster derived from gossip rather than from signed
    /// records is a fact a reader of the log needs (plan §20.1).
    private func legacyIntroductionRoster() -> MeshIntroductionRoster {
        if !loggedLegacyRosterFallback {
            loggedLegacyRosterFallback = true
            FernletAuditLog.log(
                "mesh.introductionAuthority.legacyRosterFallback",
                context: ["members": String(currentMesh?.members.count ?? 0)]
            )
        }
        return MeshIntroductionRoster(
            members: currentMesh?.members.map(\.signingPublicKey) ?? [],
            barred: MeshIntroductionChaos.additionalBarredKeys
        )
    }

    func signChannelIntroduction(_ transcript: Data) throws -> Data {
        try identity.sign(transcript, purpose: FernletCryptoPurpose.Signature.meshChannelIntroductionV1)
    }
}

// MARK: - Lane C harness seam (network migration P3 item 9)

#if DEBUG
extension MeshNetworkManager {

    /// Founds a mesh on the id this device ALREADY holds, instead of minting a new one.
    ///
    /// Lane C's founder/joiner shape needs this and nothing smaller. The QUIC transport is
    /// members-only by construction — `MeshChannelIntroductionExchange.receive` refuses a foreign
    /// mesh id and a stranger key — so two Simulators cannot meet at all unless each already names
    /// the other's mesh and holds the other's key. That is what the seeded descriptor
    /// (`FERNLET_MESH_MATRIX_MEMBERS`) is for, and it is why ``startNewMesh(name:)``, which mints a
    /// random id and a one-member descriptor, is unreachable from the harness.
    ///
    /// This is the same founding, re-ordered: the seeded two-member descriptor opens the tunnel,
    /// and then this call collapses the descriptor to **what `startNewMesh` would have produced —
    /// this device alone** — and arms the real ledger on it (`prepareMembershipLedger` +
    /// `seedFounderAdmission`, the shipping pair). Everything after it is the shipping path: the
    /// joiner asks, this device grants, and the derived roster grows by a signed record.
    ///
    /// It does **not** drive the session state machine or restart the radios: `startNewMesh` calls
    /// `startSearching()`, which would re-mint the Bonjour name mid-run and drop the very tunnel
    /// the founding depends on.
    ///
    /// - Returns: `false` when there is no mesh, a ledger already exists, the founder admission
    ///   could not be signed, or the context could not be sealed — each of which leaves the device
    ///   exactly where it was.
    public func armFounderLedgerForHarness() -> Bool {
        guard let mesh = currentMesh, membershipVerifier == nil else { return false }
        let founder = MeshMember(
            fingerprint: identity.localFingerprint,
            displayName: displayName,
            signingPublicKey: identity.localSigningPublicKey,
            keyAgreementPublicKey: identity.localKeyAgreementPublicKey,
            joinedAt: Date()
        )
        let seeded = currentMesh
        currentMesh = MeshDescriptor(
            meshID: mesh.meshID, name: mesh.name, mode: mesh.mode, members: [founder],
            nameSetAt: mesh.nameSetAt, nameSetBy: mesh.nameSetBy,
            modeSetAt: mesh.modeSetAt, modeSetBy: mesh.modeSetBy, createdAt: mesh.createdAt
        )
        prepareMembershipLedger(
            meshID: mesh.meshID, founderSigningPublicKey: identity.localSigningPublicKey
        )
        guard seedFounderAdmission(meshID: mesh.meshID), persistSessionContext(addingEpochHead: nil) else {
            membershipVerifier = nil
            currentMesh = seeded
            return false
        }
        return true
    }

    /// Asks every committed slot to admit this device — the shipping emitter
    /// (`sendAdmissionRequest(for:)`), triggered by the harness instead of by a descriptor arrival.
    ///
    /// The descriptor trigger is unreachable here: the joiner's seeded descriptor already lists it
    /// as a member, so `handleMeshDescriptor` never asks. Nothing else about the join is stood in
    /// for — the request, the grant, the token verification and the ledger bootstrap are all
    /// shipping code.
    ///
    /// - Returns: `false` when there is no mesh, no committed slot, or this device already holds a
    ///   ledger (so the join has already happened).
    public func requestAdmissionForHarness() -> Bool {
        guard let mesh = currentMesh, membershipVerifier == nil,
              slots.contains(where: { $0.fingerprint != nil }) else { return false }
        sendAdmissionRequest(for: mesh)
        return true
    }

    /// Files a genuinely signed ``SignedRemovalRecord`` against `targetFingerprint`, bypassing
    /// **only** plan §10.4's quorum arithmetic.
    ///
    /// A real quorum is impossible on two nodes: the threshold is ⌊2/2⌋ + 1 = 2 votes and the
    /// target is not an eligible voter, so exactly one vote can ever exist and
    /// `MeshMembershipRecordVerifier` refuses the record `quorumNotMet(required: 2, presented: 1)`.
    /// Everything else about the record is real — this device's signature under
    /// `meshMemberRemovalV1`, the mesh id, the target — and the *consequence* is entirely the
    /// shipping derivation: `MeshDerivedRoster` drops the target out of `members` and into
    /// `barred`, and the introduction refuses the peer as ``MeshIntroductionRejection/barredMember``
    /// on its own authority, not on a hook's.
    ///
    /// - Returns: `false` when there is no mesh or ledger, the record could not be signed, or the
    ///   ledger that now contains it could not be sealed.
    public func seedRemovalRecordForHarness(targetFingerprint: String) -> Bool {
        guard let mesh = currentMesh, let verifier = membershipVerifier else { return false }
        do {
            let record = try SignedRemovalRecord.signed(
                meshID: mesh.meshID,
                identity: identity,
                memberFingerprint: targetFingerprint,
                proposalID: UUID(),
                voterFingerprints: [identity.localFingerprint]
            )
            var ledger = verifier.ledger
            ledger.removals = ledger.removals.inserting(record)
            seedMembershipLedgerForTesting(
                meshID: verifier.meshID,
                founderSigningPublicKey: verifier.founderSigningPublicKey,
                ledger: ledger
            )
            return persistSessionContext(addingEpochHead: nil)
        } catch {
            FernletAuditLog.log(
                "mesh.membershipEvent.signFailed",
                context: ["type": "harness-removal", "error": String(describing: error)]
            )
            return false
        }
    }

    /// Whether this device holds a records ledger at all — the difference between a derived roster
    /// and the legacy descriptor fallback, which is precisely what Lane C could not read before.
    public var harnessHasLedger: Bool { membershipVerifier != nil }

    /// One line naming the **derived** roster and the epoch head, for the console transcript.
    ///
    /// Frozen diagnostic English, never localized and never on a wire. `ledger=absent` is the
    /// honest answer for a device whose introduction roster is still the gossiped descriptor.
    public var harnessMembershipSummary: String {
        guard let derived = membershipVerifier?.roster else {
            return "ledger=absent derived=0 barred=0 status=none epochRef=none"
        }
        return "ledger=present derived=\(derived.memberCount) barred=\(derived.barred.count) "
            + "status=\(derived.status) epochRef=\(epochRef.isEmpty ? "none" : epochRef)"
    }
}
#endif
