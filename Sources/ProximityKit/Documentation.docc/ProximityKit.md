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
runs one shared radio multiplexed into per-peer channels — a `MeshMultipeerSession` on every
shipping path (the friend mesh *selects* its radio; see Transport below).
All three resolve the display name they advertise the same way
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
`withObservationTracking` re-arm machinery and holds its owner weakly — including across the
suspension — so the loop can never pin the manager. Every long-running task those three managers
own is also cancelled in an `isolated deinit`, and every record-drop path (stop, refresh, MC
disconnect, stale/parked sweeps, slot eviction) runs the dropped ``ProximityCoordinator``'s own
`cancel()` so ranging and the Live Activity anchor stop with it; the mesh manager additionally
kicks an evicted peer's link (`MeshTransportSession.disconnectPeer`) so no zombie link
survives a slot (`Tests/FernletTests/MemoryLifecycleTests` + `MemoryLifecycleBoundaryTests` are
the enforcement; see Docs/Memory-Leak-Review-2026-08-17.md). Framework delegate callbacks
(MCSession, NearbyInteraction, ActivityKit)
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

Where those sidecars live is the host's call, not a constant. EVERY device-local sidecar in this
module hangs off ``ProximityHost/proximitySupportDirectory`` — the friend photo wall's index and
preferences, ``ProximityHeartLedger``, the three sealed heart-drop stores, ``ModerationLedger``,
``FriendStateCache``, ``ClosenessLedger`` and ``ProximityActivityManager``'s ledger. There is
deliberately no argument-less default on ``JSONSidecarFile``: every owner states its root, because a
default that silently resolves to the process-wide `Application Support/Fernlet` is exactly how a
store rejoins the shared-root race, and the omission compiles. The root defaults to
``ProximitySupportLayout/defaultDirectory`` (`Application Support/Fernlet`, the path the cache has
always used). The indirection exists because the wall's index is re-saved WHOLE on every keep or
delete and re-read by every manager at init — on a single process-wide path, one live
``MeshNetworkManager`` inherits and then overwrites another's album. That is invisible in the app,
which has one manager, and a live cross-suite race under the test runner, where suites share a
process. Routing the root through the host means every `MeshNetworkManager(store:)` inherits its
store's isolation without naming a directory.

The wall's whole-index re-save is the sharpest version of the hazard, but not the only one: `resetAll`
calls `clearAll()` on the moderation, friend-state, closeness and activity ledgers, and turning
fuzzy-state sharing off clears the friend-state cache on its own — so a plain settings toggle in one
test, not just a wipe, used to empty another's cache.

The heart sidecars sit on the same root and need one thing more, which ``HeartDropStorageScope``
carries: they are SEALED, and their key lives under the heart-drop keychain service so that
`HeartDropService.wipeForDeleteAll()` takes files and key together. A scope that moved only the
directory would be cosmetic — another store's wipe still deletes the shared key, and the isolated
file then survives as ciphertext nothing can open, which the outbox quarantines and latches as data
loss. So the scope is (directory, keychain service), always both, and scoping is never unsealing: a
store on its own scope still seals through the real ``HeartDropSidecarSeal`` key path.

Those sealed sidecars are the module's one at-rest format surface, and Phase 3 of the
crypto-standardization plan **deleted its legacy reader**: ``HeartDropSidecarSeal`` requires the
`FSC2` marker, and the Phase 2.2 migrator that converted `FSC1` rows went in the same stroke,
because it converted *through* the branch that is now gone and a healer that can no longer heal is
worse than either alone. An `FSC1` file is refused by name —
``SidecarSeal/SealError/legacyFormatRetired``, audit-logged before it is thrown — and
`ProtectedSidecar`'s unopenable-sealed policy then quarantines it and latches the data loss.

The `FSC1` marker itself is **kept, and load-bearing**. `SidecarSeal.isSealed` still answers true
for it, and must: that predicate is what splits a file into "sealed" and "legacy PLAINTEXT v0 —
read it as JSON and re-seal it", so a marker that stopped classifying would send ciphertext down
the plaintext branch, fail to decode, and be handled as *corrupt* — salvaged-or-discarded, i.e.
destroyed. A refusal that cannot recognize what it is refusing is worse than the reader it
replaced. ``HeartDropSidecarFormatCensus`` stays for the same reason: it classifies by marker
bytes, holds no key, and counting rows nothing can open is still the only way to know they are
there. Only the three MAIN rows (outbox, peer bundles, dedup) ever mattered to that count — the
quarantine tombstone is reported and never blocking, because no reader ever opens that path.

Before changing anything here, read the wire-compatibility notes on the type you are touching:
canonical signing bytes, sealed-payload framing (``SealedPayloadFraming``), the freeze/park
handling of unknown payload types, and the additive-optional-key rule for intro payloads are all
compatibility contracts with in-field peers.

### Localization: nothing on the wire is display copy

The module owns a `Localizable.xcstrings` (added by the 2026-08-22 accessibility review's §4.0) and one copy vault, `ProximityUICopy`, for the three SwiftUI surfaces it ships — the friend-photo review sheet, the keep-friends prompt, and the photo-save failure alert. Those were bare literals, and a `LocalizedStringKey` literal inside an SPM module resolves against `Bundle.main`, which never consults this module's catalog: untranslatable English with a clean build. Six of them were hiding inside ternaries (`Button(isKept ? "Keeping" : "Keep")`) or in `LocalizedStringKey`-typed properties, where no call-site scan could see them; `LocalizationBoundaryTests.packageDisplayLiteralsPassModuleBundle()` now catches both shapes. **The vault is display copy only.** Nothing below may go in it.

This module ships English sentences that a bulk localization pass will read as UI strings and that
must never become `String(localized:)`. Every ``PayloadSummary`` title — "Recipe share",
"Session ended", "Clothing catalog request", "Hello from …", "Identity acknowledged", "Heartbeat",
"Heartbeat ack", "Good vibes" — is written into the Ed25519 canonical signing bytes by
`CanonicalSignatureSerializer`, so localizing one makes the signed bytes depend on the sender's
locale; it is also the text a *different* device shows in its Connection Inspector, so a translated
sender writes its own language into a stranger's audit log. Both halves are silent: no crash, no
log, just an audit row in the wrong language and a future cross-stack signature mismatch nobody can
reproduce in English.

The localized inspector is still reachable, and the wire already carries what it needs. Every
envelope has `payloadTypeToken`, a stable enum rawValue identical on every device. Localize on the
RECEIVING side: map that token to a `String(localized:)` label at render time, and fall back to the
raw summary for tokens this build has no case for (`isUnknownPayloadType` — a newer peer's payload
type has no local label). Senders keep emitting frozen English forever.

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

The protocol surface carries no framework peer type: `MeshMultipeerSession` keeps the
MultipeerConnectivity half private behind ``PeerEndpointKey``, so a Network.framework/QUIC conformer
slots in beside it without changing anything here. ``MCPeerIDStoring`` and ``FileMCPeerIDStore``
are the two deliberate exceptions — they persist the MC peer identity itself and retire with MC.

**Two conformers, one surface.** `MeshMultipeerSession` (MultipeerConnectivity, all four shipping
radios) and `NetworkMeshSession` (Network.framework/QUIC, the friend mesh's migration target — see
[the network migration plan](../../../../Docs/Plan-ProximityKit-Network-Migration-2026-08-27.md) §7)
are the two radios; each multiplexes into per-peer channels — `PeerChannelTransport` and
`NetworkPeerChannel` — that conform to ``PeerTransport``. Neither channel ever publishes
``PeerTransportState/discovered``: `ProximityCoordinator.shouldInviteDiscoveredPeer` is a dormant,
opposite-direction inviter policy that wakes if one does, and two policies pointing opposite ways
means neither side dials. Discovery reaches the owner through the sessions' closure hooks instead.

**Which radio a manager gets is a selection, not a hard-coding** (plan §7, P2 item 8).
`MeshNetworkManager` holds its radio as a `MeshTransportSession` — `wire(_:)` installs one
`MeshTransportHandlers` value, and start/stop/republish/invite/disconnect are the whole surface — so
the same manager runs on either conformer and, in the suite, on an in-memory fake.
`MeshTransportFactory` decides: `shippingDefault` is MultipeerConnectivity and is the only answer a
Release build can produce; QUIC is reachable from an internal injection or the DEBUG-only
`FERNLET_MESH_TRANSPORT=quic` launch variable, and **nothing about the choice is persisted** — no
setting, no UI, no `UserDefaults` key, so it owes no row on the wipe ledger. A slot's channel is held
as `MeshPeerChannel` for the same reason; `DetachedPeerChannel` is the radio-less one the manager's
test seams use. Selecting QUIC also attaches the manager as the radio's `MeshIntroductionAuthority`
(mesh id, epoch reference, roster, signing key), which the MC radio is handed and ignores by
contract — it authenticates one layer up, inside the slot coordinator's identity introduction.

Every decision the QUIC session makes is factored out of it so it can be enumerated at tier 1 with
no radios and no wall clock: `MeshLinkTable` (peer cap, per-connection state machine, three-attempt
dial budget, duplicate-tunnel suppression, endpoint cache), `MeshHeartbeatSchedule` (the 30 s
heartbeat's due times), `MeshLinkAdvertisement` (the Bonjour TXT vocabulary — `sid` carried, `fp`
withheld), `MeshSessionIdentityMap` (one session-stable ``PeerHandle`` identity per endpoint),
`NetworkMeshWire` (control-stream framing) and `EphemeralMeshTLSIdentity` (a self-signed P-256
identity minted per session and never persisted). `Tests/FernletTests/NetworkMeshTransportTests.swift`
is the battery; the session actor itself is covered by the runbook's device lanes.

**Peer authentication is the signed channel introduction, not the certificate** (plan §7.2). Before
any app frame crosses a QUIC tunnel, both ends exchange a `MeshChannelHello` and then Ed25519
signatures over one `MeshChannelIntroductionTranscript` — purpose ‖ version ‖ meshID ‖ epochRef ‖
both signing public keys ‖ both nonces ‖ the SHA-256 of this connection's TLS exporter secret —
serialized by `canonicalBytes(for:)` under
`FernletCryptoPurpose.Signature.meshChannelIntroductionV1`. `MeshChannelIntroductionExchange` holds
the whole decision as a value type: a foreign mesh, a diverged epoch, a roster-absent or barred key,
a replayed nonce, a mismatched channel binding and an invalid signature each name themselves, and
every one tears the tunnel down. `MeshIntroductionAuthority` is the seam that supplies the mesh id,
epoch reference, roster and signing key; a session without one authenticates nobody and therefore
admits nobody. The verified `sid` it yields is what lets an inbound tunnel be matched to the browsed
advertisement it came from, so duplicate-tunnel suppression ranks the pair instead of admitting both.

Verification is also where a pair that ended up with **two** tunnels is collapsed back to one.
`MeshDialPreference` deliberately admits on both sides when it cannot rank — zero tunnels is the
unrecoverable direction — and in the pre-TXT window that means both peers dial; if neither inbound
tunnel resolves to a browsed key, the two never collide and both activate (observed on the radio,
P2 item 9). `MeshTunnelConvergence` closes that: keyed on the **durable verified identity** rather
than the per-launch `sid`, it keeps the tunnel the *preferred dialer* opened — the same `sid`
comparison the dial tie-break makes, so both devices name one connection and neither can close the
one the other kept. The loser's close is benign: no dial-budget charge, no `onPeerDisconnected`, no
transport error, and its own `redundantTunnelClosed` reason so a log never reads it as a refusal.

- ``PeerTransport``
- ``PeerHandle``
- ``PeerEndpointKey``
- ``PeerDeliveryMode``
- ``PeerTransportState``
- ``PeerPendingInvite``
- ``InboundPeerFrame``
- ``PeerTransportError``
- ``MultipeerServiceType``
- ``MCPeerIDStoring``
- ``FileMCPeerIDStore``

Internal to the module, and listed here because they are where the transport SELECTION lives:
`MeshTransportSession`, `MeshTransportHandlers`, `MeshTransportKind`, `MeshTransportFactory`,
`MeshPeerChannel`, `DetachedPeerChannel`.

Internal to the module, and listed here because they are where the QUIC transport's behaviour
actually lives: `NetworkMeshSession`, `NetworkPeerChannel`, `MeshLinkTable`, `MeshLinkKey`,
`MeshLinkPhase`, `MeshLinkAdmission`, `MeshDialPreference`, `MeshTunnelConvergence`,
`MeshDialOutcome`, `MeshEndpointRecord`,
`MeshHeartbeatSchedule`, `MeshLinkAdvertisement`, `MeshSessionIdentityMap`, `NetworkMeshWire`,
`EphemeralMeshTLSIdentity`, `MeshCertificateDER`, `MeshTransportError`, `MeshChannelRole`,
`MeshChannelIntroductionFormat`, `MeshChannelHello`, `MeshChannelIntroduction`,
`MeshChannelIntroductionTranscript`, `MeshChannelIntroductionExchange`,
`MeshChannelIntroductionOutcome`, `MeshIntroductionRejection`, `MeshIntroductionRoster`,
`MeshRosterVerdict`, `MeshIntroductionNonceCache`, `MeshVerifiedPeer`, `MeshIntroductionAuthority`.

Internal to the module, DEBUG-only, and listed here so they are never mistaken for production
behaviour: `MeshTransportConsoleLog`, `MeshIntroductionChaos`, `MeshIntroductionChaosBehaviour`.
They exist so the rejection matrix above can be *observed on a real radio* rather than only
enumerated at tier 1 — the runbook's Lane C, two Simulators on one Mac. The mirror echoes lines the
`Logger` already emitted and changes no decision; the chaos seam damages this side's own outbound
introduction (a reused nonce, a flipped signature bit) or adds keys to the roster's barred set, so
every switch can only cause a *refusal* that would not otherwise happen, never an admission. In a
Release build the environment-reading half is compiled out entirely.

### Ranging

- ``RangingProvider``
- ``NIRangingSession``
- ``RangingDistance``
- ``RangingState``

### Foreground anchor

- ``ProximityForegroundAnchoring``
- ``ProximityLiveActivityReaper`` — launch-time reaper for proximity Live Activities a killed
  previous process stranded; `FernletStoreLoader.startIfNeeded()` calls `endOrphans()` once per process, before the store exists.

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
- ``HeartDropSidecarFormatCensus``

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
- ``FingerprintText``
