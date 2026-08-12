# ``ProximityKit``

Fernlet's self-contained peer-to-peer subsystem: signed identity, MultipeerConnectivity + UWB session formation, trust lifecycle, and every in-person social feature (photos, recipes, the clothing shop, chat, hearts, activities, moderation).

## Overview

ProximityKit is the "meet in person" half of Fernlet's social layer. Nothing here talks to a
server except the heart dead-drop's injected transport seam; everything else moves over local
radios (MultipeerConnectivity for data, NearbyInteraction/UWB for distance) between two phones
that are physically together. The design center is a privacy stance the rest of the app depends
on: identities are per-device Ed25519/X25519 key pairs (``IdentityService``), every wire transfer
travels in a signed ``FernletIdentityEnvelope`` that is verified — signature, expiry, recipient,
replay, and mandatory sealing for sensitive payload types — before any handler sees it, and the
social exhaust (who you met, who sent you warmth, who you reported) lives in device-local sidecar
files that are deliberately **never** part of the synced snapshot.

**Position in the FernletKit graph and the S3 wall.** The `ProximityKit` target depends on
`PrivateMediaStore` (the sealed photo index behind the mesh photo cache), `FernletDomainModel`,
`FernletFoundation`, and `FernletUI` (for the two SwiftUI review sheets). It therefore sits on
the *protected* side of the S3 privacy wall: it may reach a sealed `Private*` store, and the
walled `AIProviders` / `CloudKitSync` targets can never import it (nor it them — the dead-drop's
CloudKit transport is injected app-side through the `HeartDropTransporting` seam, so this module
only ever hands ciphertext + rotating day tags outward). Its one seam back to app state is the
``ProximityHost`` protocol, which `FernletStore` conforms to via an app-side adapter; the
"outward edges only" rule keeps the module a black box the app drives, never the reverse. Note
the target-comment in `FernletKit/Package.swift` predates the `FernletUI` edge — the dependency
list in the manifest is the truth.

**How a session forms.** A radio owner (``MeshNetworkManager`` for the friend mesh,
``ProximityRecipeShareManager`` for recipe pairing, ``PresenceManager`` for presence hearts)
runs a `MeshMultipeerSession` — one shared MCSession multiplexed into per-peer
`PeerChannelTransport` channels. All three resolve the display name they advertise the same way
(host preference, device name as fallback), and the peer-supplied names that reach chat, hearts,
vouches, and the keep-as-friend rows pass one sanitize-or-"A friend" coercion; both live in
`PeerDisplayNames.swift`, the single home of what was a copy per call site. Each connected peer
gets a ``ProximityCoordinator``, the
per-connection engine that exchanges signed identity introductions (carrying the UWB discovery
token, advertised capability tokens, and optionally a heart-drop prekey bundle), starts ranging
through a ``RangingProvider`` (``NIRangingSession`` in production), and gates the commit on
physical closeness: a 15 cm / 0.8 s UWB dwell measured by ``ProximityCommitDetector``, a manual
confirm on non-UWB hardware, or the QR verification ceremony (``ProximityVerifyQR``) which
upgrades a manual commit to ceremony grade. Trust questions along the way go to a
``ProximityTrustPolicy`` — ``FriendSessionTrustPolicy`` for friend radios (proximity *is* the
authorization; only blocked keys ban), ``CoachSessionTrustPolicy`` for the future coach channel
(only a remembered `.trainer` pairing auto-confirms), and ``ProximityTrustVault`` as the
persistent record store behind both, holding the friend/removed/blocked/reported lifecycle and
the audit trail.

**What rides a committed session.** ``MeshNetworkManager`` owns the feature payloads: disposable
camera photos (quota-capped, cached metadata-only through `PrivateMediaStore`, optionally
AES-GCM-encrypted under the rotating ``MeshGroupKey``), the in-person clothing shop
(``MeshClothingShop``, with its 1-hour post-session browse window), vanish-at-session-end chat
(``SessionMessageStore`` — deliberately not Codable so a message can never enter a snapshot),
in-session hearts, the one-hop moderation relay (``ModerationReportRelay`` →
``ModerationLedger`` → ``ModerationBanStore``), fuzzy friend state (``FriendStateCache``), and
Group Activities (``ProximityActivityManager``, whose authorization is a host-signed,
invitee-key-bound token rather than the shared handshake). Feature payloads dispatch through a
registry whose committed-slot gate is the security boundary; the session end promotes the roster
into the keep-as-friend review (``FriendMintingReview``, ``KeepFriendsPromptSheet``,
``FriendPhotoReviewSheet``). Photo-library save failures surface through one shared mapping —
``FriendPhotoLibrarySaver``'s `userFacingFailure(for:photoCount:)` producing a
``PhotoSaveFailure`` rendered by the `photoSaveFailureAlert(_:failure:)` view modifier — so every
save surface (review sheets and the album carousel) shows identical wording.

**Presence and hearts.** ``PresenceManager`` runs a standing radio that broadcasts only rotating
pairwise-DH tags — no names, no stable identifiers, a fresh random MCPeerID per start — so kept
friends recognize each other nearby without connecting. Hearts are delivered over short-lived
connections formed on that recognition, with the sealed-introduction rule
(``SealedIntroductionEnvelope``) ensuring a tag-replay forger never sees an identity. When the
friend is away, ``HeartDropService`` seals the heart (``HeartDropSealer``, forward-secret via
``HeartPrekeyStore`` one-time/signed prekeys cached per friend in ``HeartDropPeerBundleCache``)
and queues it in the ``HeartDropOutbox`` for the injected dead-drop transport; the receive side
dedups durably (``HeartDropDedupStore``) and records into the shared ``ProximityHeartLedger``,
which enforces the bidirectional 5-minute rate limit for every heart transport.
``ClosenessLedger`` turns these interactions into the private closeness score.

**Concurrency and persistence invariants.** The target sets `defaultIsolation(MainActor.self)`
in Swift 6 language mode: managers, coordinators, and stores are `@MainActor` (most
`@Observable`), while every wire value type, the canonical signing serializer, and the pure
crypto statics are explicitly `nonisolated` + `Sendable` so untrusted bytes can be decoded and
signatures verified off the main actor (the WI-9 convention). The managers that mirror
coordinator state into their own observable properties (``MeshNetworkManager``,
``ProximityRecipeShareManager``, ``PresenceManager``) drive that mirroring through the internal
`ObservationLoop` helper (`Engine/ObservationLoop.swift`), which owns the shared
`withObservationTracking` re-arm machinery and holds its owner weakly so the loop ends when the
manager deallocates. Framework delegate callbacks (MCSession, NearbyInteraction, ActivityKit)
transfer non-Sendable objects across the main-actor
hop via documented `nonisolated(unsafe)` locals. Signing inputs come from the deterministic
binary serializer in `CanonicalSignatureSerializer.swift` (domain-tagged per signed type,
cross-platform stable; the legacy JSON encoder is retained verify-only). Persistence follows one
stance throughout: small JSON sidecars in Application Support with `.completeFileProtection`,
never synced — the best-effort stores share the internal `JSONSidecarFile` helper
(`Support/JSONSidecarFile.swift`), while the heart-sharing sidecars additionally load through
``ProtectedSidecar`` (sealed at rest via ``HeartDropSidecarSeal``), which classifies read
failures so a locked-device read can never be mistaken for "empty" and overwrite real data. Key
material lives in the keychain, ThisDeviceOnly, except the deliberately-synced backup-escrow key
whose content-addressed slot lifecycle ``IdentityService`` reconciles non-silently.

Where those sidecars live is the host's call, not a constant: the friend photo wall's index and
preferences hang off ``ProximityHost/proximitySupportDirectory``, which defaults to
``ProximitySupportLayout/defaultDirectory`` (`Application Support/Fernlet`, the path the cache has
always used). The indirection exists because the wall's index is re-saved WHOLE on every keep or
delete and re-read by every manager at init — on a single process-wide path, one live
``MeshNetworkManager`` inherits and then overwrites another's album. That is invisible in the app,
which has one manager, and a live cross-suite race under the test runner, where suites share a
process. Routing the root through the host means every `MeshNetworkManager(store:)` inherits its
store's isolation without naming a directory.

The heart sidecars sit on the same root and need one thing more, which ``HeartDropStorageScope``
carries: they are SEALED, and their key lives under the heart-drop keychain service so that
`HeartDropService.wipeForDeleteAll()` takes files and key together. A scope that moved only the
directory would be cosmetic — another store's wipe still deletes the shared key, and the isolated
file then survives as ciphertext nothing can open, which the outbox quarantines and latches as data
loss. So the scope is (directory, keychain service), always both, and scoping is never unsealing: a
store on its own scope still seals through the real ``HeartDropSidecarSeal`` key path.

Before changing anything here, read the wire-compatibility notes on the type you are touching:
canonical signing bytes, sealed-payload framing (``SealedPayloadFraming``), the freeze/park
handling of unknown payload types, and the additive-optional-key rule for intro payloads are all
compatibility contracts with in-field peers.

## Topics

### Host seam and app integration

- ``ProximityHost``
- ``ProximitySupportLayout``

### Identity and signing

- ``IdentityService``
- ``IdentityError``
- ``ReplayCache``

### Wire envelope and sealing

- ``FernletIdentityEnvelope``
- ``SealedIntroductionEnvelope``
- ``SealedPayloadFormat``
- ``SealedPayloadFraming``

### Session engine

- ``ProximityCoordinator``
- ``ProximityCommitDetector``
- ``ProximityPayloadHandling``
- ``ProximityInspectorRecording``
- ``ProximityInspectorEventRecorder``

### Transport

- ``MultipeerTransport``
- ``MultipeerPeer``
- ``MultipeerTransportState``
- ``MultipeerPendingInvite``
- ``MultipeerInboundMessage``
- ``MultipeerTransportError``
- ``MultipeerServiceType``
- ``MCPeerIDStoring``
- ``FileMCPeerIDStore``

### Ranging

- ``RangingProvider``
- ``NIRangingSession``
- ``RangingDistance``
- ``RangingState``

### Foreground anchor

- ``ProximityForegroundAnchoring``

### Trust and verification

- ``ProximityTrustPolicy``
- ``ProximityTrustVault``
- ``FriendSessionTrustPolicy``
- ``CoachSessionTrustPolicy``
- ``CoachSessionContract``
- ``CoachVerificationCeremony``
- ``FriendMintingReview``
- ``ProximityVerifyQR``
- ``ProximityVerifySignature``
- ``VerifyChallengePayload``
- ``VerifyResponsePayload``

### Friend mesh sessions

- ``MeshNetworkManager``
- ``PeerSlot``
- ``SlotKind``
- ``MeshGroupKey``
- ``MeshSessionParticipant``
- ``MeshSessionRosterEntry``
- ``MeshFriendReviewBatch``
- ``FriendPhotoWallPost``

### Mesh wire payloads

- ``MeshDescriptor``
- ``MeshMember``
- ``MeshMode``
- ``MeshStateChangePayload``
- ``MeshAdmissionRequestPayload``
- ``MeshAdmissionGrantPayload``
- ``MeshAdmissionToken``
- ``MeshRemovalProposalPayload``
- ``MeshRemovalSecondPayload``
- ``MeshFriendVouchListPayload``
- ``MeshKeyRotationPayload``
- ``MeshKeyAckPayload``
- ``MeshRotationSyncPayload``
- ``MeshCoordinatorBeaconPayload``
- ``MeshEncryptedMetadataPayload``
- ``EncryptedMetadataInner``

### Presence and closeness

- ``PresenceManager``
- ``FriendStateCache``
- ``CachedFriendState``
- ``ClosenessLedger``

### Hearts

- ``ProximityHeartLedger``
- ``ReceivedHeartRecord``
- ``HeartDropService``
- ``HeartDropOutbox``
- ``HeartDropDedupStore``
- ``HeartDropSealer``
- ``HeartPrekeyStore``
- ``HeartDropPeerBundleCache``
- ``HeartDropStorageScope``

### Protected sidecar persistence

- ``ProtectedSidecar``
- ``SidecarSeal``
- ``HeartDropSidecarSeal``

### Recipe sharing

- ``ProximityRecipeShareManager``
- ``ProximityRecipeSharePayload``
- ``ProximitySharedRecipe``
- ``ProximitySharedRecipeKind``
- ``SharedSavedRecipePayload``
- ``PendingProximityRecipeShare``
- ``ProximityRecipeShareRecipient``
- ``ProximityRecipeShareDiagnostics``
- ``ProximityRecipeShareDiagnosticEvent``

### Clothing shop

- ``MeshClothingShop``
- ``ClothingCatalogPayload``
- ``ProximityClothingCatalog``

### Live-session chat

- ``SessionMessageStore``
- ``TempMessagePayload``

### Group Activities

- ``ProximityActivityManager``
- ``ActivityParamsHash``
- ``ActivityOfferPayload``
- ``ActivityJoinRequestPayload``
- ``ActivityJoinGrantPayload``
- ``ActivityRosterSnapshotPayload``
- ``ActivitySyncPayload``

### Moderation

- ``ModerationLedger``
- ``ModerationBanStore``
- ``ModerationContentHash``
- ``ModerationReportRelay``
- ``ModerationReportPayload``
- ``SignedModerationReport``

### Trainer export

- ``TrainerExportPayload``

### Review UI

- ``KeepFriendsPromptSheet``
- ``FriendPhotoReviewSheet``
- ``FriendPhotoLibrarySaver``
- ``PhotoSaveFailure``
