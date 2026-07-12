import Foundation
import MultipeerConnectivity
import Observation
import UIKit
import CryptoKit
import FernletDomainModel
import FernletFoundation
import PrivateMediaStore

// MARK: - Supporting types

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

private struct FriendPhotoWallPreferences: Codable {
    var aggregatedSessionIDs: Set<UUID> = []
    var coverPhotoIDsBySession: [UUID: UUID] = [:]
    var favoritePhotoIDsBySession: [UUID: UUID] = [:]
}

private struct FriendPhotoWallPreferencesStore {
    let fileURL: URL

    func load() -> FriendPhotoWallPreferences {
        guard let data = try? Data(contentsOf: fileURL),
              let preferences = try? JSONDecoder().decode(FriendPhotoWallPreferences.self, from: data) else {
            return FriendPhotoWallPreferences()
        }
        return preferences
    }

    func save(_ preferences: FriendPhotoWallPreferences) {
        guard let data = try? JSONEncoder().encode(preferences) else { return }
        try? FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: fileURL, options: [.atomic, .completeFileProtection])
    }
}

// MARK: - MeshNetworkManager

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
    /// The live-session temporary-message store (Phase 5): the current session's chat transcript.
    /// Registered on the payload registry in `init`. Memory-only and deliberately NOT Codable — it can
    /// never enter a snapshot. Cleared at EVERY session-end path (the same last-committed-slot-gone
    /// moment that promotes `pendingFriendReview` / opens the shop window) and on the next session
    /// formation. Unlike the shop's 1-hour window, messages do NOT outlive the session — they vanish.
    public let sessionMessages = SessionMessageStore()
    public var isSearching = false
    public var meshError: String?

    @ObservationIgnored private unowned let store: any ProximityHost
    @ObservationIgnored private let meshSession = MeshMultipeerSession()
    @ObservationIgnored private let identity: IdentityService
    @ObservationIgnored private let replayCache = ReplayCache()
    @ObservationIgnored private let photoCacheStore: PrivateMediaStore
    @ObservationIgnored private let photoWallPreferencesStore: FriendPhotoWallPreferencesStore
    @ObservationIgnored private var photoWallPreferences: FriendPhotoWallPreferences
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
    // Retry counts for failed proximity-join MC connections (peer.id → attempts)
    @ObservationIgnored private var peerRetryCount: [UUID: Int] = [:]
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
    @ObservationIgnored private var removedMemberFingerprints: Set<String> = []
    @ObservationIgnored private var approvedRemovalProposalIDs: Set<UUID> = []
    @ObservationIgnored private var sessionID = UUID().uuidString
    private static let maxPeerRetries = 3

    // MARK: - Phase 3 Group Encryption State

    // Current symmetric group key. nil = epoch 0 (unencrypted). Never persisted.
    @ObservationIgnored private(set) var currentGroupKey: MeshGroupKey?
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
    @ObservationIgnored private var epochLog: [(epoch: Int, since: Date)] = []

    private static let rotationInterval: TimeInterval = 15 * 60   // 15 minutes
    private static let beaconInterval: TimeInterval = 20          // 20 seconds
    private static let beaconLivenessTimeout: TimeInterval = 45   // 45 seconds

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

    public init(store: any ProximityHost) {
        self.store = store
        let id = IdentityService()
        try? id.ensureProvisioned()
        self.identity = id
        let cacheURL = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first!.appendingPathComponent("Fernlet/MeshPhotoCache.json")
        self.photoCacheStore = PrivateMediaStore(indexURL: cacheURL)
        let preferencesURL = cacheURL.deletingLastPathComponent().appendingPathComponent("MeshPhotoWallPreferences.json")
        let preferencesStore = FriendPhotoWallPreferencesStore(fileURL: preferencesURL)
        self.photoWallPreferencesStore = preferencesStore
        self.photoWallPreferences = preferencesStore.load()
        meshPhotos = photoCacheStore.load()
        setupMeshSession()
        registerClothingShopHandler()
        registerSessionMessageHandler()
        registerModerationReportHandler()
        registerFriendStateHandler()
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

    /// Hands this device's OWN signed reports to a committed friend (one-hop). No provider, an empty
    /// set, or no signable rows → sends nothing.
    private func sendModerationReports(to slot: PeerSlot) async {
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

    /// Sends our fuzzy state + appearance to a committed friend. A nil provider (opt-out) sends nothing.
    private func sendFriendState(to slot: PeerSlot) async {
        guard let payload = friendStatePayloadProvider?() else { return }
        await sendEnvelope(.friendState, encodable: payload, via: slot, sealed: true)
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
            self.sessionMessages.receiveIncoming(
                id: payload.id,
                senderFingerprint: fingerprint,
                senderDisplayName: peerIdentity.displayName,
                text: payload.text,
                sentAt: payload.sentAt
            )
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
                    displayName: slot.peer.displayName,
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
        if let index = sessionRoster.firstIndex(where: { $0.fingerprint == fingerprint }) {
            sessionRoster[index].displayName = displayName
        } else {
            sessionRoster.append(MeshSessionRosterEntry(
                displayName: displayName,
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
                } else {
                    batch.entries.append(entry)
                }
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

    /// Notify connected peers before tearing down transport so they can review their session photos.
    public func leaveSessionAfterNotifyingPeers() async {
        for slot in slots {
            await sendEnvelope(.sessionGoodbye, encodable: PayloadSummary(title: "Session ended"), via: slot)
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
        photoCacheStore.save(meshPhotos)
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

        var preferencesChanged = false
        for (sessionID, favoriteID) in photoWallPreferences.favoritePhotoIDsBySession where favoriteID == photoID {
            photoWallPreferences.favoritePhotoIDsBySession.removeValue(forKey: sessionID)
            preferencesChanged = true
        }
        for (sessionID, coverID) in photoWallPreferences.coverPhotoIDsBySession where coverID == photoID {
            photoWallPreferences.coverPhotoIDsBySession.removeValue(forKey: sessionID)
            preferencesChanged = true
        }
        if preferencesChanged { persistPhotoWallPreferences() }

        guard existed else { return }
        photoCacheStore.save(meshPhotos)
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
        currentMesh = MeshDescriptor(
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
        startSearching()
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
        startSearching()
    }

    public func stopJoin() {
        isProximityJoin = false
        stopSearching()
    }

    public func leaveMesh() {
        currentMesh = nil
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

    private func clearGroupKeyState() {
        currentGroupKey = nil
        rotationTimer?.cancel()
        rotationTimer = nil
        beaconTimer?.cancel()
        beaconTimer = nil
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
        if let key = currentGroupKey,
           let (ciphertext, nonce) = try? Self.encryptPhoto(normalized, key: key) {
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
            displayName: request.requesterDisplayName,
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
            guard let token = try? MeshAdmissionToken.signed(
                meshID: mesh.meshID,
                joinerFingerprint: request.requesterFingerprint,
                joinerSigningPublicKey: request.requesterSigningPublicKey,
                admitterIdentity: self.identity
            ) else { return }

            // Phase 3: wrap the current group key to the slot's handshake-verified KA key,
            // not the request's claimed key, to prevent key-substitution attacks.
            var encryptedKey: Data? = nil
            var keyEpoch = 0
            if let groupKey = self.currentGroupKey {
                let kaKey = self.slots.first(where: { $0.fingerprint == request.requesterFingerprint })?
                    .verifiedKeyAgreementPublicKey ?? request.requesterKeyAgreementPublicKey
                encryptedKey = try? self.identity.encryptGroupKey(groupKey.keyBytes, for: kaKey)
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
        case .meshDescriptor:
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
                handleAdmissionGrant(payload)
            }
        case .friendPhoto:
            if let payload = try? decoder.decode(FriendPhotoPayload.self, from: plaintext) {
                if let fp = payload.senderFingerprint, store.isBlockedFingerprint(fp) { return }
                guard allowIncomingPhoto(payload.id, from: peer?.fingerprint) else { return }
                if payload.keyEpoch > 0 {
                    // Encrypted photo: decrypt before caching.
                    guard let key = currentGroupKey, key.epoch == payload.keyEpoch,
                          let ct = payload.encryptedImageData, let nonce = payload.nonce,
                          let decrypted = try? Self.decryptPhoto(ct, nonce: nonce, key: key) else { return }
                    cachePhoto(payload.withDecryptedImageData(decrypted), includeInSession: isPhotoFromCurrentSession(payload))
                } else {
                    cachePhoto(payload, includeInSession: isPhotoFromCurrentSession(payload))   // epoch 0: unencrypted, accept as-is
                }
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
        case .meshFriendVouchList:
            if let payload = try? decoder.decode(MeshFriendVouchListPayload.self, from: plaintext) {
                receiveVouchList(payload, senderFingerprint: peer?.fingerprint)
            }
        case .meshRemovalProposal:
            if let payload = try? decoder.decode(MeshRemovalProposalPayload.self, from: plaintext) {
                handleRemovalProposal(payload, rebroadcast: false)
            }
        case .meshRemovalSecond:
            if let payload = try? decoder.decode(MeshRemovalSecondPayload.self, from: plaintext) {
                handleRemovalSecond(payload, senderFingerprint: peer?.fingerprint, rebroadcast: false)
            }
        case .meshEncryptedMetadata:
            if let wrapper = try? decoder.decode(MeshEncryptedMetadataPayload.self, from: plaintext),
               let slot {
                Task { [weak self] in await self?.handleEncryptedMetadata(wrapper, from: peer, slot: slot) }
            }
        case .meshCoordinatorBeacon:
            if let beacon = try? decoder.decode(MeshCoordinatorBeaconPayload.self, from: plaintext) {
                handleCoordinatorBeacon(beacon)
            }
        case .meshRotationSync:
            if let sync = try? decoder.decode(MeshRotationSyncPayload.self, from: plaintext) {
                let senderFingerprint = peer?.fingerprint
                Task { [weak self] in await self?.handleRotationSync(sync, senderFingerprint: senderFingerprint) }
            }
        case .meshKeyRotation:
            if let rotation = try? decoder.decode(MeshKeyRotationPayload.self, from: plaintext) {
                let senderFingerprint = peer?.fingerprint
                Task { [weak self] in await self?.handleKeyRotation(rotation, senderFingerprint: senderFingerprint) }
            }
        case .meshKeyAck:
            if let ack = try? decoder.decode(MeshKeyAckPayload.self, from: plaintext) {
                handleKeyAck(ack)
            }
        case .sessionGoodbye:
            if let slot { removeSlot(slot) }
        default:
            // Known type outside the core mesh set: give a registered feature module a chance
            // (Phase 1 registry); otherwise keep the pre-registry silent drop.
            //
            // COMMITTED SLOTS ONLY (Phase 3a hardening; a Phase-1 review fact makes this the security
            // boundary): the coordinator dispatches known non-core payloads with
            // `connectedIdentity ?? pendingPeerIdentity` and no state gate, so a pre-dwell (uncommitted)
            // peer — or a coordinator that never became a slot — could otherwise reach feature handlers
            // with a merely-pending identity. Feature payloads are for session members, not candidates.
            guard slot?.fingerprint != nil else {
                FernletAuditLog.log(
                    "mesh.registryPayload.droppedUncommittedSlot",
                    context: ["type": payloadType.rawValue]
                )
                return
            }
            registeredPayloadHandlers[payloadType]?(envelope, plaintext, peer)
        }
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
        var name = ItemNameModeration.sanitizedName(payload.voucherDisplayName)
        if name.isEmpty { name = "A friend" }
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

    private var displayName: String {
        let name = store.proximityDisplayName.trimmingCharacters(in: .whitespaces)
        return name.isEmpty ? UIDevice.current.name : name
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
    func localCapabilities() -> [String] {
        var capabilities = [ProximityCapability.photos.rawValue]
        if clothingShop.isSharingEnabled {
            capabilities.append(ProximityCapability.shop.rawValue)
        }
        // Phase 5: temporary messages are a core in-session feature with no separate v1 opt-out —
        // session membership (the UWB dwell + admission) IS the consent gate, so `messages` is
        // advertised whenever we join a friend session. (Owner may override with a `messages` setting
        // later, mirroring the `shop` gate above; see design_choices.)
        capabilities.append(ProximityCapability.messages.rawValue)
        // Content-moderation reports are a safety feature with no opt-out — always advertised so a
        // friend's device knows it may hand us the reports it has verified.
        capabilities.append(ProximityCapability.moderation.rawValue)
        // Phase 4: advertise fuzzy-state exchange only when the user opted in, so a friend sends us their
        // vibe only if we accept (and share) ours.
        if friendStateEnabledProvider?() == true {
            capabilities.append(ProximityCapability.friendState.rawValue)
        }
        return capabilities
    }

    /// Phase 3a outbound gate: send our catalog only to peers advertising the `shop` capability (a
    /// legacy client would park-and-drop it anyway — skip the bytes), and only while sharing is
    /// enabled locally. Internal seam so tests can pin the gate without a transport.
    func shouldOfferShopCatalog(to peerIdentity: ProximityCoordinator.PeerIdentity) -> Bool {
        clothingShop.isSharingEnabled && peerIdentity.supports(.shop)
    }

    private func setupMeshSession() {
        meshSession.onPeerDiscovered = { [weak self] peer in
            self?.handlePeerDiscovered(peer)
        }
        meshSession.onPeerChannelReady = { [weak self] channel in
            self?.handleChannelReady(channel)
        }
        meshSession.onPeerDisconnected = { [weak self] peer, _ in
            guard let self else { return }
            let matchingSlot = self.slots.first {
                $0.peer.id == peer.id || $0.peer.underlying == peer.underlying
            }
            let wasCommitted = matchingSlot?.fingerprint != nil
            if let slot = matchingSlot {
                self.removeSlot(slot)
            }
            // In proximity join: if the MC connection dropped before the peer committed and we
            // are the designated inviter (higher fingerprint), retry up to maxPeerRetries times.
            // Without this, a transient socket failure permanently strands the session because
            // the browser won't re-fire onPeerDiscovered for a peer it already found.
            guard self.isProximityJoin, self.isSessionOpen, !wasCommitted else { return }
            let peerFP = peer.advertisedFingerprint ?? peer.displayName
            guard self.identity.localFingerprint > peerFP else { return }
            let retryCount = self.peerRetryCount[peer.id, default: 0]
            guard retryCount < Self.maxPeerRetries else { return }
            self.peerRetryCount[peer.id] = retryCount + 1
            Task { [weak self] in
                try? await Task.sleep(for: .seconds(2))
                guard let self, self.isProximityJoin, self.isSessionOpen,
                      self.slots.count < Self.maxTotalSlots,
                      !self.slots.contains(where: { $0.peer.id == peer.id || $0.peer.underlying == peer.underlying }) else { return }
                self.meshSession.invite(peer)
            }
        }
        meshSession.shouldAcceptInvitation = { [weak self] peer in
            guard let self else { return false }
            // Blocklist is enforced at identity-introduction time by the slot coordinator.
            if self.isProximityJoin && !self.isSessionOpen { return false }
            if self.slots.count < Self.maxTotalSlots { return true }
            return self.canEvaluateOverflowCandidate(peer)
        }
        meshSession.onTransportError = { [weak self] message in
            // Discovery failed to start (e.g. a service type missing from NSBonjourServices) —
            // surface it instead of searching forever in silence.
            self?.meshError = message
        }
    }

    private func startSearching() {
        isSearching = true
        meshSession.start(serviceType: MeshMultipeerSession.friendServiceType, discoveryInfo: currentDiscoveryInfo())
        startObserving()
    }

    private func stopSearching() {
        observationTask?.cancel()
        observationTask = nil
        isSearching = false
        isProximityJoin = false
        peerRetryCount.removeAll()
        sentShopCatalogSlotIDs.removeAll()
        shopCatalogRequestResponseAt.removeAll()
        meshSession.stop()
        for slot in slots { Task { await slot.coordinator.cancel() } }
        slots.removeAll()
        slotTrustPolicies.removeAll()
        // Teardown path (leaveSession/leaveMesh/stopJoin funnel through here): the last committed
        // slot is gone, so any unreviewed roster promotes into the pending friend-review batch and
        // any held shop catalogs open the post-session shop window (Phase 3a).
        promoteRosterToPendingReviewIfSessionEnded()
        openShopWindowIfSessionEnded()
        clearSessionMessagesIfSessionEnded()
    }

    public func currentDiscoveryInfo() -> [String: String] {
        var info: [String: String] = [
            "v": "1",
            "sid": sessionID,
            "name": String(displayName.prefix(32))
        ]
        if let mesh = currentMesh, mesh.mode == .open {
            info["meshID"] = mesh.meshID.uuidString
            info["meshName"] = String(mesh.name.prefix(40))
            info["memberCount"] = "\(mesh.members.count)"
        }
        return info
    }

    private func updateDiscoveryInfo() {
        meshSession.updateDiscoveryInfo(currentDiscoveryInfo())
    }

    private func handlePeerDiscovered(_ peer: MultipeerPeer) {
        // Proximity-join mode: auto-invite every peer silently; no browse list shown.
        if isProximityJoin {
            guard isSessionOpen else { return }
            // Tie-break: only the peer with the lexicographically higher fingerprint sends
            // the MC invitation. Both sides browse+advertise so both discover each other;
            // without this guard, simultaneous mutual invites cause "Connection refused"
            // errors in the NW/MC layer (errno 61, "no clist for remoteID").
            let peerFP = peer.advertisedFingerprint ?? peer.displayName
            guard identity.localFingerprint > peerFP else { return }
            if slots.count < Self.maxTotalSlots, !slots.contains(where: { $0.peer.id == peer.id }) {
                meshSession.invite(peer)
            }
            return
        }

        // Auto-invite peers into our open mesh when capacity exists, or when one
        // temporary overflow candidate can be evaluated with real distance data.
        if let mesh = currentMesh, mesh.mode == .open {
            if slots.count < Self.maxTotalSlots || canEvaluateOverflowCandidate(peer) {
                if !slots.contains(where: { $0.peer.id == peer.id }) {
                    meshSession.invite(peer)
                }
            }
        }
    }

    private func handleChannelReady(_ channel: PeerChannelTransport) {
        guard !isProximityJoin || isSessionOpen else { return }
        guard slots.count < Self.maxSlotsDuringOverflowEvaluation else { return }
        guard !slots.contains(where: { $0.peer.id == channel.peer.id }) else { return }

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
            await self?.sendEnvelope(.sessionGoodbye, encodable: PayloadSummary(title: "Session ended"), via: slot)
            await slot.coordinator.cancel()
        }
        slots.removeAll { $0.id == slot.id }
        slotTrustPolicies.removeValue(forKey: slot.id)
        pruneShopSendTracking(for: slot.id)
        rerankSlots()
        promoteRosterToPendingReviewIfSessionEnded()
        openShopWindowIfSessionEnded()
        clearSessionMessagesIfSessionEnded()
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
        // (which recorded its verified identity), so this is insert-only — `slot.peer.displayName`
        // is the MC transport name and must not overwrite the identity display name.
        for slot in committed {
            guard let fingerprint = slot.fingerprint,
                  !sessionRoster.contains(where: { $0.fingerprint == fingerprint }),
                  let signingKey = slot.verifiedSigningPublicKey,
                  let kaKey = slot.verifiedKeyAgreementPublicKey else { continue }
            recordSessionParticipant(
                displayName: slot.peer.displayName,
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

    private func canEvaluateOverflowCandidate(_ peer: MultipeerPeer) -> Bool {
        guard !slots.contains(where: { $0.peer.id == peer.id }) else { return false }
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
        if let existing = currentMesh {
            mergeMeshDescriptor(existing, incoming: descriptor)
        } else {
            currentMesh = descriptor
        }
        isSessionOpen = currentMesh?.mode == .open
        let localFP = identity.localFingerprint
        if let mesh = currentMesh, !mesh.members.contains(where: { $0.fingerprint == localFP }) {
            sendAdmissionRequest(for: mesh)
        }
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
        for member in incoming.members
        where !removedMemberFingerprints.contains(member.fingerprint)
            && !merged.members.contains(where: { $0.signingPublicKey == member.signingPublicKey }) {
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
        guard approvedRemovalProposalIDs.insert(proposal.id).inserted else { return }
        handleRemovalProposal(proposal, rebroadcast: false)
        if rebroadcast {
            broadcastEnvelope(.meshRemovalSecond, encodable: second)
        }
        applyApprovedRemoval(proposal)
    }

    private func applyApprovedRemoval(_ proposal: MeshRemovalProposalPayload) {
        pendingRemovalProposals.removeAll { $0.id == proposal.id }
        removedMemberFingerprints.insert(proposal.targetFingerprint)
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
        if !pendingAdmissionRequests.contains(where: { $0.requesterSigningPublicKey == request.requesterSigningPublicKey }) {
            pendingAdmissionRequests.append(request)
        }
    }

    private func handleAdmissionGrant(_ grant: MeshAdmissionGrantPayload) {
        guard currentMesh == nil || currentMesh?.meshID == grant.meshID else { return }
        // Bind the signed token.meshID to the mesh being joined so a valid token for another
        // mesh cannot be wrapped in a grant claiming this one (grant.meshID is unsigned).
        do { try grant.token.verify(joinerSigningPublicKey: identity.localSigningPublicKey, expectedMeshID: grant.meshID) } catch { return }

        // Phase 3: unwrap the group key if one was included.
        if let bundle = grant.encryptedCurrentKey,
           let keyData = try? identity.decryptGroupKey(bundle) {
            let newKey = MeshGroupKey(epoch: grant.currentKeyEpoch, keyBytes: keyData, activeSince: Date())
            currentGroupKey = newKey
            localJoinedEpoch = grant.currentKeyEpoch
            epochLog.append((epoch: grant.currentKeyEpoch, since: newKey.activeSince))
        } else {
            // No key included — we start at epoch 0 (unencrypted).
            localJoinedEpoch = 0
        }
        startBeaconLoop()
    }

    // MARK: - Photo handling

    private func cachePhoto(_ photo: FriendPhotoPayload, includeInSession: Bool = false) {
        guard !meshPhotos.contains(where: { $0.id == photo.id }) else { return }
        let cachedPhoto = includeInSession ? photo.withSession(currentPhotoSessionMetadata()) : photo
        meshPhotos.insert(cachedPhoto.withoutImageData(), at: 0)
        // Metadata-only entries (no image bytes), so the in-memory list can mirror the disk cap.
        // Keeping it at the spec's 1000 makes the FIFO cap and the 900-photo soft-warning real;
        // the full-resolution bytes stay on disk and rehydrate on demand.
        meshPhotos = Array(meshPhotos.prefix(PrivateMediaStore.maxCachedPhotos))
        photoCacheStore.save(meshPhotos.map { $0.id == cachedPhoto.id ? cachedPhoto : $0 })
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
        guard let sessionID = post.session?.id else { return nil }
        return photoWallPreferences.favoritePhotoIDsBySession[sessionID]
    }

    public func toggleFavorite(photoID: UUID, in post: FriendPhotoWallPost) {
        guard let sessionID = post.session?.id else { return }
        if photoWallPreferences.favoritePhotoIDsBySession[sessionID] == photoID {
            photoWallPreferences.favoritePhotoIDsBySession.removeValue(forKey: sessionID)
        } else {
            photoWallPreferences.favoritePhotoIDsBySession[sessionID] = photoID
        }
        persistPhotoWallPreferences()
    }

    public var photoWallPosts: [FriendPhotoWallPost] {
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
        while posts.count >= 24 {
            let candidate = newestUnaggregatedSession()
            guard let candidate else { break }
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
            let coverPhoto = sessionPhotos.first(where: { $0.id == coverID }) ?? sessionPhotos[0]
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
        let haveIDs = Set(meshPhotos.map { $0.id })
        let missing = manifest.entries
            .filter { !haveIDs.contains($0.id) }
            .filter { !store.isBlockedFingerprint($0.senderFingerprint) }
            .filter { $0.keyEpoch >= localJoinedEpoch }   // epoch guard: skip photos we can't decrypt
            .map(\.id)
        guard !missing.isEmpty else { return }
        Task { [weak self] in
            guard let self else { return }
            let req = FriendPhotoRequestPayload(missingPhotoIDs: missing)
            if self.currentMesh?.mode == .closed, self.currentGroupKey != nil {
                await self.sendEncryptedMetadata(.friendPhotoRequest, encodable: req, via: slot)
            } else {
                await self.sendEnvelope(.friendPhotoRequest, encodable: req, via: slot)
            }
        }
    }

    private func sendRequestedPhotos(_ ids: [UUID], to slot: PeerSlot) {
        let requested = sessionPhotos.filter { ids.contains($0.id) }.compactMap { photoCacheStore.hydrated($0) }
        for photo in requested {
            Task { [weak self] in await self?.sendEnvelope(.friendPhoto, encodable: photo, via: slot, sealed: true) }
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
        if peerIdentity.supports(.moderation) {
            Task { [weak self] in await self?.sendModerationReports(to: slot) }
        }
        // Phase 4: share our fuzzy vibe + appearance with this committed friend.
        if peerIdentity.supports(.friendState) {
            Task { [weak self] in await self?.sendFriendState(to: slot) }
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
    }

    // MARK: - Envelope sending

    private func sendEnvelope(_ type: PayloadType, encodable: some Encodable, via slot: PeerSlot, sealed: Bool = false) async {
        guard let payloadData = try? JSONEncoder().encode(encodable) else { return }
        let finalPayload: Data
        let encryption: PayloadEncryption
        if sealed {
            guard let kaKey = slot.verifiedKeyAgreementPublicKey, !kaKey.isEmpty,
                  let ciphertext = try? identity.seal(payloadData, to: kaKey) else { return }
            finalPayload = ciphertext
            encryption = .sealedTo(recipientKeyAgreementPublicKey: kaKey)
        } else {
            finalPayload = payloadData
            encryption = .none
        }
        guard let envelope = try? FernletIdentityEnvelope.signed(
            identityService: identity,
            senderDisplayName: displayName,
            recipientFingerprint: slot.fingerprint,
            payloadType: type,
            payloadEncryption: encryption,
            payloadSummary: PayloadSummary(title: type.rawValue),
            payload: finalPayload
        ) else { return }
        guard let envelopeData = try? JSONEncoder().encode(envelope) else { return }
        do {
            try await slot.channel.send(envelopeData, to: slot.peer, mode: .reliable)
        } catch {
            FernletAuditLog.log("mesh.sendEnvelope.failed", context: ["type": type.rawValue, "error": error.localizedDescription])
        }
    }

    // MARK: - Phase 3: Static encrypt / decrypt helpers

    /// AES-256-GCM encrypt `imageData` using the group key.
    /// Returns (ciphertext + 16-byte tag, 12-byte nonce) stored separately in FriendPhotoPayload.
    public static func encryptPhoto(_ imageData: Data, key: MeshGroupKey) throws -> (ciphertext: Data, nonce: Data) {
        let symKey = SymmetricKey(data: key.keyBytes)
        let gcmNonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(imageData, using: symKey, nonce: gcmNonce)
        var nonce = Data()
        gcmNonce.withUnsafeBytes { nonce.append(contentsOf: $0) }
        var ciphertextWithTag = Data(sealedBox.ciphertext)
        ciphertextWithTag.append(sealedBox.tag)
        return (ciphertextWithTag, nonce)
    }

    public static func decryptPhoto(_ ciphertextWithTag: Data, nonce nonceData: Data, key: MeshGroupKey) throws -> Data {
        guard ciphertextWithTag.count > 16 else { throw MeshEncryptionError.decryptionFailed }
        let symKey = SymmetricKey(data: key.keyBytes)
        let gcmNonce = try AES.GCM.Nonce(data: nonceData)
        let ciphertext = ciphertextWithTag.dropLast(16)
        let tag = ciphertextWithTag.suffix(16)
        let box = try AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ciphertext, tag: tag)
        return try AES.GCM.open(box, using: symKey)
    }

    // Shared implementation used by closed-mode metadata wrapping.
    private static func encryptPayload(_ data: Data, key: MeshGroupKey) throws -> (ciphertext: Data, nonce: Data) {
        try encryptPhoto(data, key: key)
    }

    private static func decryptPayload(_ ciphertextWithTag: Data, nonce: Data, key: MeshGroupKey) throws -> Data {
        try decryptPhoto(ciphertextWithTag, nonce: nonce, key: key)
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
        guard let innerJSON = try? JSONEncoder().encode(inner),
              let (ciphertext, nonce) = try? Self.encryptPayload(innerJSON, key: key) else { return }
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
        guard let plaintext = try? Self.decryptPayload(wrapper.ciphertext, nonce: wrapper.nonce, key: key),
              let inner = try? JSONDecoder().decode(EncryptedMetadataInner.self, from: plaintext),
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
                handleAdmissionGrant(payload)
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
                try? await Task.sleep(for: .seconds(Self.beaconInterval))
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

    private func handleCoordinatorBeacon(_ beacon: MeshCoordinatorBeaconPayload) {
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
            try? await Task.sleep(for: .seconds(delay))
            guard !Task.isCancelled, let self else { return }
            if self.isLocalCoordinator() {
                await self.initiateRotation()
            }
        }
    }

    // MARK: - Phase 3: Rotation protocol

    /// Coordinator entry point for a 15-minute key rotation.
    private func initiateRotation() async {
        let closingEpoch = currentGroupKey?.epoch ?? 0

        // Step 1: Broadcast sync + update the beacon with the next rotation timestamp.
        let sync = MeshRotationSyncPayload(closingEpoch: closingEpoch)
        for slot in slots {
            await sendEnvelope(.meshRotationSync, encodable: sync, via: slot)
        }
        let nextAt = Date().addingTimeInterval(Self.rotationInterval)
        lastKnownNextRotationAt = nextAt
        scheduleRotationTimer(fireAt: nextAt)
        broadcastCoordinatorBeacon()

        // Step 2: Collect sync-acks for up to 10 seconds.
        pendingRotationAcks.removeAll()
        pendingRotationClosingEpoch = closingEpoch
        let expectedAckers = Set(activeSlots.compactMap(\.fingerprint))
        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline && !expectedAckers.subtracting(pendingRotationAcks).isEmpty {
            try? await Task.sleep(for: .milliseconds(200))
        }
        pendingRotationClosingEpoch = nil

        // Step 3: Generate new key and distribute to acked members + self.
        var newKeyBytes = Data(count: 32)
        newKeyBytes.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        let newEpoch = closingEpoch + 1
        let ackedFingerprints = pendingRotationAcks.intersection(expectedAckers)
        let allRecipients = ackedFingerprints.union([identity.localFingerprint])

        var perMember: [String: Data] = [:]
        for fp in allRecipients {
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
            if let bundle = try? identity.encryptGroupKey(newKeyBytes, for: kaKey) {
                perMember[fp] = bundle
            }
        }

        let rotation = MeshKeyRotationPayload(
            newEpoch: newEpoch,
            perMember: perMember,
            rotationInitiatedAt: Date(),
            coordinatorFingerprint: identity.localFingerprint
        )
        for slot in slots {
            await sendEnvelope(.meshKeyRotation, encodable: rotation, via: slot)
        }

        // Apply new key locally (unwrap self-encrypted copy).
        if let selfBundle = perMember[identity.localFingerprint],
           let keyData = try? identity.decryptGroupKey(selfBundle) {
            let newKey = MeshGroupKey(epoch: newEpoch, keyBytes: keyData, activeSince: Date())
            currentGroupKey = newKey
            epochLog.append((epoch: newEpoch, since: newKey.activeSince))
        }
        pendingRotationAcks.removeAll()
    }

    /// Non-coordinator: respond to a rotation sync from the coordinator.
    private func handleRotationSync(_ sync: MeshRotationSyncPayload, senderFingerprint: String?) async {
        // Accept only from the elected coordinator (sender-authenticated).
        guard let senderFP = senderFingerprint, isElectedCoordinator(senderFP) else { return }
        // Drain any pending outbound photo work before signalling ready.
        try? await Task.sleep(for: .seconds(3))
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

        guard let myBundle = payload.perMember[identity.localFingerprint] else {
            // Excluded from this rotation — surface a non-modal warning and initiate rejoin.
            meshError = "You were excluded from the key rotation. Rejoining…"
            currentGroupKey = nil
            if let mesh = currentMesh {
                sendAdmissionRequest(for: mesh)
            }
            return
        }
        guard let keyData = try? identity.decryptGroupKey(myBundle) else { return }
        let newKey = MeshGroupKey(epoch: payload.newEpoch, keyBytes: keyData, activeSince: Date())
        currentGroupKey = newKey
        epochLog.append((epoch: payload.newEpoch, since: newKey.activeSince))

        // Send rotation-ack back to the coordinator.
        let ack = MeshKeyAckPayload(epoch: payload.newEpoch, memberFingerprint: identity.localFingerprint)
        if let coordinatorSlot = slots.first(where: { $0.fingerprint == payload.coordinatorFingerprint }) {
            await sendEnvelope(.meshKeyAck, encodable: ack, via: coordinatorSlot)
        }
    }

    /// Coordinator: collect acks from members.
    private func handleKeyAck(_ ack: MeshKeyAckPayload) {
        guard isLocalCoordinator() else { return }
        // Accept acks for the closing epoch (sync-phase acks) only.
        if let closing = pendingRotationClosingEpoch, ack.epoch == closing {
            pendingRotationAcks.insert(ack.memberFingerprint)
        }
    }

    // MARK: - Observation loop for coordinator state changes

    private func startObserving() {
        observationTask?.cancel()
        observationTask = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                // AsyncStream does not finish automatically when its consumer task is
                // cancelled. Finish the continuation explicitly so repeated discovery
                // sessions do not leave suspended observer tasks behind.
                let (stream, continuation) = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
                withObservationTracking {
                    _ = self.slots.count
                    for slot in self.slots {
                        _ = slot.coordinator.state
                        _ = slot.coordinator.lastKnownDistance
                    }
                } onChange: {
                    continuation.yield(())
                }
                await withTaskCancellationHandler {
                    for await _ in stream { break }
                } onCancel: {
                    continuation.finish()
                }
                continuation.finish()
                guard !Task.isCancelled else { return }
                self.checkCoordinatorStates()
                self.updateDistanceSamples()
            }
        }
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
    func addSlotForTesting(
        coordinator: ProximityCoordinator,
        peer: MultipeerPeer,
        fingerprint: String?,
        verifiedKeyAgreementPublicKey: Data? = nil,
        peerCapabilities: [String]? = nil
    ) {
        var slot = PeerSlot(
            id: peer.id,
            peer: peer,
            channel: PeerChannelTransport(peer: peer, session: meshSession),
            coordinator: coordinator,
            kind: .active,
            fingerprint: fingerprint
        )
        slot.verifiedKeyAgreementPublicKey = verifiedKeyAgreementPublicKey
        slot.peerCapabilities = peerCapabilities
        slots.append(slot)
    }

    /// Evicts a slot through the production removal funnel (`removeSlot` — the path
    /// `onPeerDisconnected` and the stale-coordinator sweep share), so unit tests can drive
    /// transient-drop teardown + shop send-tracking pruning without the private MC callbacks.
    /// `internal` for `@testable` unit tests only.
    func evictSlotForTesting(peerID: UUID) {
        guard let slot = slots.first(where: { $0.id == peerID }) else { return }
        removeSlot(slot)
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
        peer: MultipeerPeer,
        transport: any MultipeerTransport,
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
            channel: PeerChannelTransport(peer: peer, session: meshSession),
            coordinator: coordinator,
            kind: .active,
            fingerprint: nil
        )
        slotTrustPolicies[slot.id] = trustPolicy
        slots.append(slot)
        return coordinator
    }

    // MARK: - UI test injection

    public func injectUITestStateIfNeeded() {
        let env = ProcessInfo.processInfo.environment
        let now = Date()
        let hostFP = "aa:bb:cc:dd:00:11:test"

        if env["FERNLET_UI_TEST_MESH_OPEN"] == "1" || env["FERNLET_UI_TEST_MESH_ADMISSION"] == "1" {
            currentMesh = MeshDescriptor(
                meshID: UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!,
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
                meshID: UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-FFFFFFFFFFFF")!,
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
    }
}
