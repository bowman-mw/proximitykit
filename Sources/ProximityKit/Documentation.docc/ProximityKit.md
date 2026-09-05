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

### The host pin: the managers read a host they do not own (HP0/HP1/HP2)

All four proximity managers — ``MeshNetworkManager``, ``PresenceManager``,
``ProximityRecipeShareManager``, ``ProximityActivityManager`` — hold their host as
`unowned let store: any ProximityHost`. That is right: the host owns the manager (each is a `lazy
var` on `FernletStore`), so the back-reference is the cycle-breaker. It also means a manager can be
alive while its host is gone, and reading `store` then is not a nil — it is
`swift_abortRetainUnowned`, which kills the whole process. Three invariants keep that unrepresentable,
and a new manager in this subsystem inherits all three:

- **HP0 (ownership).** Whatever holds a manager holds that manager's host at least as long.
  Production satisfies this structurally. Tests satisfy it by rig discipline — never
  `MeshNetworkManager(store: makeTestStore(), …)`, whose host dies at the end of the expression.
- **HP1 (the pin).** Every detached task a manager spawns captures the host for the duration of the
  operation that will read it. That is what `spawnHostPinned(_:)` does: it reads `store`
  synchronously, on the main actor, where the host is provably alive, and releases it when the
  operation returns. Where the read happens after a suspension inside an `async` callee that a
  *stored* task re-enters, the callee takes the same pin scoped to its own call
  (`let host = store` + `defer { withExtendedLifetime(host) {} }`, marked `// host-pin: scoped`).
  That pin goes **below** any early-return guard that does not itself read the host: `let host =
  store` *is* an `unowned` read, so a resume that would have returned without touching the host must
  not be made to touch it.
- **HP2 (the bound).** No pin may outlive the operation that reads the host — and in particular no
  pin may be taken for the lifetime of a `Task` whose handle the manager STORES. Such a task is
  reachable from the host (host → manager → handle), so a pin in its closure context closes the loop:
  neither object ever deallocates, and the `isolated deinit` that ends the perpetual timers becomes
  unreachable. Those spawns stay plain `Task { … }` and carry a `// host-pin: timer — <reason>`
  marker instead.

`MemoryLifecycleBoundaryTests` rule ML4 fails any unmarked `Task` construction in a file holding an
`unowned` host; rule ML5 fails a test that builds a manager over an inline host expression.
``ProximityManagerDeallocationTests`` measures HP2 directly, with the beacon loop armed.

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
`NetworkMeshWire` (control-stream framing), `MeshTransferStreamTable` (which frames earn a stream of
their own, and how many may be open at once) and `EphemeralMeshTLSIdentity` (a self-signed P-256
identity minted per session and never persisted). `Tests/FernletTests/NetworkMeshTransportTests.swift`
is the battery; the session actor itself is covered by the runbook's device lanes.

**Bulk frames ride per-transfer streams** (plan §7.1). A reliable payload at or above
`MeshTransferStreamTable.bulkFloorBytes` is written on a QUIC stream opened for it alone, so a friend
photo cannot park a heartbeat or a chat message behind it on the control stream; everything smaller
stays in order where it was. Nothing above the transport can tell — one transfer stream carries
exactly one length-framed payload, delivered as exactly one ``InboundPeerFrame``, under the same
ceiling both radios enforce. The budget lives inside the tunnel record, so a torn-down link takes its
open transfers with it, and both exhaustion paths degrade to today's behaviour rather than to a
failure: an outbound frame with no slot free goes on the control stream, and an inbound stream with
no slot free goes back un-acked so the sender's write fails loudly.

**One frame is one write.** `sendFramed` writes the length prefix and the payload as a single
contiguous send. Two awaited sends let concurrent senders on the shared control stream interleave at
the suspension between them, and the peer then read one frame's header followed by another frame's
first bytes as a length — observed on the runbook's Lane C app-flow run, and reproduced on a loopback
pair. A per-transfer stream keeps two writes because it has exactly one writer, by construction.

**Peer authentication is the signed channel introduction, not the certificate** (plan §7.2). Before
any app frame crosses a QUIC tunnel, both ends exchange a `MeshChannelHello` and then Ed25519
signatures over one `MeshChannelIntroductionTranscript` — purpose ‖ version ‖ meshID ‖ epochRef ‖
both signing public keys ‖ both nonces ‖ the SHA-256 of this connection's TLS exporter secret —
serialized by `canonicalBytes(for:)` under
`FernletCryptoPurpose.Signature.meshChannelIntroductionV1`. `MeshChannelIntroductionExchange` holds
the whole decision as a value type: a foreign mesh, a diverged epoch, a roster-absent or barred key,
a replayed nonce, a mismatched channel binding and an invalid signature each name themselves, and
every one tears the tunnel down. **The epoch gate is strict as of P3 item 4** (plan §20.1): P2's
soft rule was `local.isEmpty || peer.isEmpty || local == peer` on raw strings, which let junk
through opposite an empty side and let two divergent branches that both rendered `"7"` agree they
matched. Every non-empty reference must now be a canonical `MeshEpochRef` (checked with the field
widths, so a bad one is `malformedHello`), equality is equality of the whole value, and the joiner
that holds no key is a named branch of `MeshEpochAcceptance.introductionVerdict` rather than a
short-circuit that skipped the comparison. `MeshIntroductionAuthority` is the seam that supplies the mesh id,
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

**Membership is a set of signed records; the roster is derived from them** (plan §8.1). The roster
the introduction is judged against is not stored state that somebody updates — it is
`admitted − departed − removed`, recomputed on every read from four grow-only record sets:
`SignedAdmissionRecord` (which keeps the existing `MeshAdmissionToken` whole rather than minting a
second signed admission format), `SignedDepartureRecord`, `SignedRemovalRecord` and
`SignedTerminationRecord`. `MeshMembershipRecordSet` holds one kind — deduplicated by member,
ordered by a total order over the record's own fields, and capped — and `MeshMembershipLedger` holds
the four; `MeshDerivedRoster` is the pure function from a ledger to who is in, who is barred, and
whether the mesh still exists, plus the three things everything else reads off it: the
lowest-fingerprint coordinator, the ⌊|roster|/2⌋ + 1 quorum, and whether this is the final pair.
Because a merge is a set union, it is commutative, associative and idempotent **including its caps**
— keeping the earliest *k* of a set is the same answer whether you cap before or after merging — so
two devices that have seen the same records agree on the roster no matter what order, or over which
radio, they saw them in. That is why a reconnect after a blip, a merge after a partition and a
reload after a process death can be one code path. Two derivations are deliberately read-time rather
than merge-time: a termination whose signer is still on a roster larger than two downgrades to that
signer's departure, and a termination signed by a non-member is ignored — applying either at merge
time would have made the union depend on arrival order. Departure is permanent by construction: the
sets only grow, so a re-admission record for a departed fingerprint is subtracted straight back out,
and rejoining means a new mesh. Nothing in this layer verifies a signature — `signature` is opaque
bytes a record carries — so records must be signature-checked by the layer that owns the crypto
purpose *before* they reach a ledger a roster is derived from. `MeshMembershipBounds` states the
plan §9 caps in one place, and reuses `MeshIntroductionRoster`'s own constants rather than
restating them: roster 8, sixteen records per kind, one termination.

**An epoch is a value, not a number** (plan §8.4, P3 item 4). `MeshEpochRef` is a Lamport counter
(cap 4096, and a counter *at* the cap refuses to mint a successor rather than trapping — a mesh that
cannot rotate must end rather than keep serving a key it cannot retire), an `epochID`, and the
fingerprint of the coordinator that minted it. The id is **derived**, not drawn:
`SHA-256(domain ‖ meshID ‖ counter ‖ coordinatorFingerprint)`, so every member of one branch
computes the same id with no wire change, while two partitions differ because their deterministic
coordinators — each partition's lowest fingerprint — cannot be the same member. That is what makes
**divergent same-counter epochs representable**: two members who rotated independently at counter 7
hold two distinct values, both belong in `MeshSessionContext.epochHeads`, and neither is wrong; they
coexist (`MeshEpochRotationVerdict.coexist`) until a merge mints a strictly greater successor. The
canonical string form `"<counter>.<32 hex>.<16 hex>"` is at most 54 characters, which is why a real
epoch reference rides the introduction's existing 96-character `epochRef` field without moving a
byte of wire framing. `MeshEpochAcceptance` is the rule — the presenter must be the deterministic
coordinator of the roster it presents and the counter must strictly advance; **epoch continuity is
never required**, so a member returning from a long partition at counter 5 syncs forward to 9
without being "stale". `MeshEpochKeyring` holds the current key plus ≤ 3 predecessors, each usable
for ≤ 5 minutes after supersession and rejected after it, on an injected clock — and it is
**memory-only**, like the `MeshGroupKey`s inside it: only the epoch *names* persist.

**Rotation triggers are the timer, any roster change and any merge** (plan §8.3, P3 item 5). The
15-minute schedule is no longer the only way the group key turns over: a verified admission,
departure, removal or termination record entering the ledger, and a ledger merge that moves the
derived roster, each raise a trigger too. That is what closes the confirmed
voted-out-member-keeps-the-key gap — before it, a member the mesh had just removed held a working
group key until the next tick. `MeshRotationTriggerQueue` is the single front door: it **coalesces a
burst into one rotation** inside a two-second window (`MeshRotationTriggerBounds`, chosen so a
healing partition's re-gossip does not mint an epoch per record, and small beside the ≤ 5-minute
predecessor grace it delays), and it is **non-reentrant** — a trigger raised while a rotation is in
flight is deferred and re-armed, never dropped and never run concurrently. The `meshKeyRotation`
frame carries a frozen English `MeshKeyRotationCause` (`timer` / `membership` / `merge`); the frame
is unsigned (it rides the signed identity envelope), so the field moved no signature transcript and
no existing golden vector — `MeshKeyRotationCauseWireTests` pins the extended JSON, and a frame with
no `cause` decodes as `timer`, which is the only rotation older builds ever performed.

`MeshRotationPolicy` holds the two decisions. `plan` mints the successor and runs it through
`MeshEpochAcceptance` before anything moves — at the counter cap it answers `terminate`, and the
manager emits `terminated.v1` and ends the session rather than trapping. `recipients` is the
exclusion rule: **removed and departed members get no copy of the new key**, subtracting both the
derived roster's `barred` set and the live vote-out set, and narrowing to the roster's members once
the ledger knows one. It is deliberately subtractive rather than positive, because a positive rule
over a ledger that is still empty in shipping builds would distribute the key to nobody at all.
`MeshNetworkManager` now **holds** its `MeshEpochKeyring` rather than re-deriving an epoch on every
read — `epochRef` is the head's canonical string — and persists the new head into
`MeshSessionContext.epochHeads` through `persistSessionContext(addingEpochHead:)` **before** the
rotation is distributed or acknowledged (plan §3.6): a refused or deferred seal abandons the
rotation and names the reason, it does not hand out a key no restart could explain.

**Replay protection does not ride epochs** (plan §8.4). Once a predecessor key can still open a
frame and a merge can bring two branches together, "the epoch no longer opens it" stops being a
replay answer. `MeshFrameReplayWindow` is the replacement: dedup by frame id, per **authenticated**
sender, with the frame's own expiry and an explicit mesh id, bounded at 8 senders × 64 ids — and it
*refuses* at the cap rather than evicting, because an LRU would let a flood of fresh frames erase
the history an attacker wants to replay into. It knows nothing about epochs, which is the point.

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
`MeshTransferStreamTable`, `MeshTransferRoute`, `MeshTransferID`,
`EphemeralMeshTLSIdentity`, `MeshCertificateDER`, `MeshTransportError`, `MeshChannelRole`,
`MeshChannelIntroductionFormat`, `MeshChannelHello`, `MeshChannelIntroduction`,
`MeshChannelIntroductionTranscript`, `MeshChannelIntroductionExchange`,
`MeshChannelIntroductionOutcome`, `MeshIntroductionRejection`, `MeshIntroductionRoster`,
`MeshRosterVerdict`, `MeshIntroductionNonceCache`, `MeshVerifiedPeer`, `MeshIntroductionAuthority`.

Internal to the module, DEBUG-only, and listed here so they are never mistaken for production
behaviour: `MeshTransportConsoleLog`, `MeshIntroductionChaos`, `MeshIntroductionChaosBehaviour`.
They exist so the rejection matrix above can be *observed on a real radio* rather than only
enumerated at tier 1 — the runbook's Lane C, two Simulators on one Mac. **Three** Simulators run on
the same lane and form a **full mesh** (3/3 runs, 2026-09-02): every node reaches `slots total=2
committed=2`, the derived roster converges to `derived=3` on all three, one epoch head is agreed by
all three, and a clean departure is accepted by both survivors. They first formed a spanning *star*,
and the cause was not in this module: `MeshNetworkManager.isSessionOpen` — the mesh-wide "admits new
**members**" rule — was gating whether a **link** could be opened at all, so the first `.closed`
descriptor a node merged stopped it dialing, accepting and seating its own co-members. See
``MeshNetworkManager`` `mayLinkToDiscoveredPeers`. Two diagnostics landed with the fix and are worth
knowing when reading a transcript: `browsed peers=<n> […]` (the browse set, on every size change) and
`dial refused <admission> for <key>`. The mirror echoes lines the
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

Internal to the module, and listed here because they are the membership model the roster is derived
from (plan §8.1): `MeshMembershipRecordKind`, `MeshMembershipRecord`, `MeshMembershipBounds`,
`MeshMembershipRecordOrder`, `SignedAdmissionRecord`, `SignedDepartureRecord`,
`SignedRemovalRecord`, `SignedTerminationRecord`, `MeshCustodyHandoffSummary`,
`MeshMembershipRecordSet`, `MeshMembershipLedger`, `MeshDerivedRoster`, `MeshRosterMember`,
`MeshRosterStatus`. The sealed store's own internal vocabulary is `MeshSessionContext`,
`MeshSessionContextSchema`, `MeshSessionContextDecodingError`, `MeshSessionLoad`,
`MeshSessionSealRefusal`, `MeshSessionDeferral`, `MeshSessionCorruption`, `MeshSessionSaveError`,
`MeshSessionSealKey` and `MeshSessionSealKeyOutcome`. P3 item 3 added the membership events that
move those records between devices: `MeshMembershipEventFormat`, `MeshRecordIdentity`,
`MeshInventoryDigest`, `MeshMemberDeparturePayload`, `MeshMemberRemovalPayload`, `MeshTerminationPayload`,
`MeshInventoryDigestPayload`, `MeshEpochHeadsPayload`, `MeshMembershipRecordVerifier`, `MeshMembershipRecordRejection`,
`MeshLegacyGoodbyeOutcome` and `MeshMembershipGoodbyeInterop`. P3 item 7 added the admission frame
and the joiner's ledger bootstrap: `MeshMemberAdmissionPayload`, `MeshLedgerAdoption`,
`MeshLedgerAdoptionOutcome` and `MeshLedgerAdoptionRefusal`. P3 item 4 added the epoch model:
`MeshEpochRef`, `MeshEpochBounds`, `MeshEpochRefParseError`, `MeshEpochRefOrder`,
`MeshEpochKeyring`, `MeshEpochKeyringRotationRefusal`, `MeshEpochAcceptance`,
`MeshEpochRotationVerdict`, `MeshEpochRotationRefusal`, `MeshEpochIntroductionVerdict`,
`MeshFrameReplayWindow` and `MeshFrameReplayVerdict`. P3 item 5 added the rotation triggers:
`MeshKeyRotationCause` (on `MeshKeyRotationPayload`), `MeshRotationTriggerBounds`,
`MeshRotationTriggerOutcome`, `MeshRotationTriggerQueue`, `MeshRotationPlan`, `MeshRotationRefusal`
and `MeshRotationPolicy`. P5 item 1 added the routed-content wire family: `MeshRoutedManifestFormat`,
`MeshRecipientKeyWrap`, `MeshRoutedManifest`, `MeshRoutedManifestPayload`, `MeshRoutedManifestMintError`,
`MeshRoutedManifestVerifier`, `MeshRoutedManifestRejection`, `MeshRoutedWrapBinding`,
`MeshRoutedKeyWrapError` and `MeshRoutedContentKeyWrapper`. P5 item 2 added the routed CHUNK family
— thirteen types: `MeshChunkFormat`, `MeshRoutedContentDigest`, `MeshChunk`, `MeshChunkPayload`,
`MeshChunkRejection`, `MeshChunkVerifier`, `MeshChunkMintError`, `MeshChunker`, `MeshChunkRefusal`,
`MeshChunkAdmission`, `MeshChunkBinding`, `MeshChunkCompletion` and `MeshChunkAssembly`. P5 item 3
added the CUSTODY RECEIPT and the sealed routed store — the module's **second** durable surface:
`MeshCustodyReceiptFormat`, `MeshCustodyReceipt`, `MeshCustodyReceiptPayload`,
`MeshCustodyReceiptMintError`, `MeshCustodyReceiptRejection`, `MeshCustodyReceiptVerifier`,
`MeshCustodyDurabilityWitness`, `MeshRoutedStorageScope`, `MeshRoutedSealKeyOutcome`,
`MeshRoutedSealKey`, `MeshRoutedIndexSchema`, `MeshRoutedStoreFormat`, `MeshRoutedIndexDecodingError`,
`MeshRoutedItemKey`, `MeshRoutedChunkDescriptor`, `MeshRoutedDeliveryProgress`,
`MeshRoutedDeliveryRecord`, `MeshRoutedItemRecord`, `MeshRoutedItemRef`, `MeshRoutedIndex`,
`MeshRoutedSealRefusal`, `MeshRoutedDeferral`, `MeshRoutedCorruption`, `MeshRoutedLoad`,
`MeshRoutedSaveError`, `MeshRoutedChunkFileRead`, `MeshRoutedStore`, `MeshRoutedRetryBounds`,
`MeshRoutedUnavailability`, `MeshRoutedStoreRefusal`, `MeshRoutedOutcome`,
`MeshRoutedManifestAdmission`, `MeshRoutedCustodyOutcome`, `MeshRoutedSweepReport`,
`MeshRoutedIndexLoad`, `MeshRoutedStagedFile`, `MeshRoutedContentHasher`, `MeshChunkDescriptor`,
`MeshChunkSetShape`, `MeshChunkAdmissionRule`, plus `MeshDeliveryRestoreRefusal` and
`MeshDeliveryRestoreOutcome` on the P4 delivery target. P5 item 4 added the RECIPIENT RECEIPT and
plan §11's acknowledgement stages — fifteen types: `MeshRoutedAckStage`, `MeshRoutedTypeToken`,
`MeshRoutedAckStageRow`, `MeshRoutedAckStageTable`, `MeshRoutedHeartAck`, `MeshRoutedAckEvidence`,
`MeshRoutedAckShortfall`, `MeshRoutedDeliveryCommitOutcome`, `MeshRecipientReceiptFormat`,
`MeshRecipientReceipt`, `MeshRecipientReceiptPayload`, `MeshRecipientReceiptMintError`,
`MeshRecipientReceiptRejection`, `MeshRecipientReceiptVerifier`, `MeshRecipientDeliveryWitness`, and
one read-only door on the heart ledger (`MeshHeartLedgerProof` + `commitProof(for:)`).

P5 item 5 added the ROUTED CONTENT digest and its pure comparison — eleven types:
`MeshRoutedInventoryFormat`, `MeshRoutedInventoryEntry`, `MeshRoutedInventory`,
`MeshRoutedInventoryPayload`, `MeshRoutedInventoryMintError`, `MeshRoutedInventoryRejection`,
`MeshRoutedInventoryVerifier`, `MeshRoutedInventoryReceiptKind`, `MeshRoutedInventoryReceiptRef`,
`MeshRoutedChunkGap` and `MeshRoutedInventoryDelta`. **None of them carries the stem
`InventoryDigest`, on purpose:** that stem belongs to P4's MEMBERSHIP digest, and the two wire tokens
deliberately share the `inventory-digest` spelling, so the Swift value-type names are what keep a
manager dispatch from reaching for the wrong family.

The mint has **one** spelling of "this device": `MeshRoutedInventoryPayload.signed(meshID:index:sentAt:identity:)`
takes no `selfFingerprint`, deriving it from the signing identity exactly as `MeshRoutedManifest.signed`
derives its origin. The reason is not tidiness — the builder's custody self-rule turns "who am I" into
an advertised `custodySigners` entry, and `custodySigners` is advertiser-asserted rather than signed
evidence, so a second, disagreeing spelling would mint a digest that verifies cleanly while claiming
custody for a member that never held the item; the peer would then ask that member for a receipt it
can never mint and the merge window item 7 closes would never close.

P5 item 6 wired the DRAIN onto that one merge path — six new types and two new store doors:
`MeshRoutedDrainAnswerFormat`, `MeshRoutedDrainAnswer`, `MeshRoutedDrainAnswerPayload`,
`MeshRoutedDrainAnswerMintError`, `MeshRoutedDrainAnswerRejection`,
`MeshRoutedDrainAnswerVerifier`, plus the pure planning values `MeshRoutedPeerInventory`,
`MeshRoutedDrainRefusalNote`, `MeshRoutedDrainBounds`, `MeshRoutedDrainChunkSend` and
`MeshRoutedDrainPlan`, and `MeshRoutedCustodyEvidence` beside
`MeshRoutedStore.recordingCustodyEvidence(item:receipt:now:)` /
`forwardableCustodyReceipts(item:)`. The drain itself is a private section of
`MeshNetworkManager` — it needs the manager's `store`, `identity`, `broadcastMembershipFrame` and
slot table, all file-scoped, so the value-type extraction above is what keeps the new *logic* out of
that file rather than a manager extension, which could not compile elsewhere. Three seams are
`internal` rather than private, and only three: `sendRoutedInventory(to:now:)`,
`dispatchRoutedPayload(_:plaintext:decoder:slot:now:)` and `receiveRoutedInventory(_:from:now:)` —
the drain's send door, its ingest door and its advertisement door, each taking an injected `now`
(D-6.12) because every admission, `isLive(at:)` check and `deliveredAt` stamp downstream reads that
one instant. A battery that cannot reach them, or cannot supply the instant, is testing the wall
clock instead of the drain.

The two store doors are deliberately asymmetric with the delivery family's. A record holds **other
members'** custody receipts only, so `forwardableCustodyReceipts` never returns this device's own —
that is the `custodiedAt` stamp, and the drain re-mints the receipt from the durable bytes, which is
byte-identical because the commit re-uses the stored instant. And `recordingCustodyEvidence` stores a
forwarded receipt while advancing **no** rung: `recordingCustodyTransfer`'s `for destinations:` is
the *caller's* statement about a hand-off, and a drain that was handed no hand-off has no honest
value for it.

**P5 item 8 shipped CUSTODY-TRANSFER-ON-DEPARTURE — increment 1's only relay hop** (plan §10.6,
§11). Custody is at the **origin**, or, after exactly one transfer at exactly one moment — a
development — at the custodians ``MeshDevelopmentPlan/handoffTargets`` names. There is no hand-off
between two live connected members, and no second hop. Ten new types across two files:
``MeshCustodyHandoffScope``, ``MeshCustodyHandoffSuppression``, ``MeshCustodyHandoffResult`` and
``MeshCustodyHandoffPlan`` (`MeshCustodyHandoffPlan.swift`, pure values with no store and no clock,
where the *choosing* lives), plus ``MeshRoutedCustodyHandoff``, ``MeshRoutedHandoffClaim``,
``MeshRoutedHandoffRefusalReason``, ``MeshRoutedHandoffRefusal``, ``MeshRoutedHandoffStep`` and
``MeshRoutedHandoffReport`` beside two new store doors in `MeshRoutedCustodyHandoff.swift`:
`MeshRoutedStore.recordingCustodyHandoff(_:now:)` (the departing origin, receipt-backed) and
`MeshRoutedStore.claimingHandedOffLegs(_:now:)` (the custodian, receipt-free). Both are **one load,
N bounded updates, one save** — looping the single-item `recordingCustodyTransfer` over a full index
would be two thousand crypto passes on the main actor inside a fifteen-second window — and both
apply that door's rules through its own now-internal helpers, so the rule has one implementation.
`recordingCustodyTransfer` itself is untouched and still has **zero** shipping callers.

Five things make the increment-1 line structural rather than a comment:

- **No new wire, no new signature.** The custodian's authority is the leaver's own
  `SignedDepartureRecord.custodyHandoff.custodianFingerprints`, already inside the departure's
  canonical bytes, verified, grow-only and available offline. `MeshDeliveryTarget`'s existing
  `pending → custodied(by:) → delivered` ladder is the whole state change; no frame, no
  `PayloadType`, no crypto purpose and no golden moved, and `MeshRoutedIndexSchema` stays 2.
- **The enumerator refuses the second hop.** ``MeshRoutedIndex/itemsAwaitingHandoff(at:in:originatedBy:)``
  takes a **required** origin filter, so a departing *custodian* enumerates nothing at all; a future
  call site cannot forget what it is not allowed to omit.
- **The hop bound is the origin-served set, not the record.** `custodyHandoff.custodianFingerprints`
  is the whole roster minus the leaver in every production departure, so the record alone would make
  every member an entitled courier for every other and content would walk A→B→C→D. A device may
  therefore claim handed-off legs only for an item whose **manifest it admitted from the origin
  itself**, recorded at the one door that knows the sender. Every courier of a departed origin's
  content is consequently a device that origin both named and served directly. The set is
  memory-only and dies with the session: a restart before claiming forfeits the claim, which is
  fail-closed and named (`mesh.development.handoffClaimNotOriginServed`).
- **Every "nothing transferred" is a named answer.** ``MeshCustodyHandoffSuppression`` distinguishes
  a store that could not say what it holds, a partition of one with nobody to hand to, a record that
  was never emitted and a window that had already closed — so `nil` really is the single value that
  means "this device handed over exactly what it says it did", and a delivery-ladder refusal inside a
  batch door keeps its own name rather than reading as "nothing to do".
- **A removed member's record grants nothing.** `MeshMembershipRecordVerifier` accepts a departure
  from any *admitted* fingerprint, not only a current member, and a derived roster cannot separate
  *departed* from *removed*; so the gate lives in the manager, over `ledger.removals` and
  `removedMemberFingerprints`, before the pure planner ever sees a leaver.

`MeshDevelopmentPlan.handoffSummary(handedOffItemCount:)` is what a departure record now signs, and
the count is defined narrowly: **distinct items whose rung this device's own durable index moved
`pending → custodied(by:)`, inside the window, and whose single save succeeded.** Not sends, not
attempts, not candidates — nothing can retract it once the record is signed, so every uncertain path
under-reports. The claim at the custodian is **one idempotent derivation applied at four doors** (a
live roster move, a merge, an item completing, and the drain-exchange entry) rather than four event
hooks; the fourth exists because a store that answered `deferred` when the record folded is reachable
by no other event. At each door the claim runs **only after** the roster verdict has declined to end
the session — a merge that hands this device its own removal ejects it before any rung is written,
which is the order ``MeshNetworkManager`` already used on the live-record path. The durable custody
commit those doors trigger is capped per evaluation, and its overflow is *carried* rather than
dropped: the planner cannot recover it, because after a claim no named leg is `pending`, so the queue
is what makes "retried at the next evaluation" true. Items no stored receipt could place are named
(`MeshCustodyHandoffResult.unplacedItemKeys`) and their bytes ride a best-effort push through the
drain's own narrowing planner and frame budget, bounded by the plan's deadline re-read per custodian
— a frame cap is not a time bound. Everything the push sends is the origin's exact stored objects:
**a custodian is a courier, never a co-signer.**

**P5 item 9 gave BACKPRESSURE a consequence** (plan §11, §3.4). Every cap was already refused by
name at every writer door and every collection already had a bound; what did not exist was one value
that *is* the cap model, any caller for the three reclaim verbs, any drop rule for a parked set whose
manifest was refused, the fourth at-rest guard, or a user-visible consequence of any of it — a
refusal ended in one audit line nobody reads, which is precisely "grows past its cap without telling
anyone". Five types close that, in two files: `MeshRoutedCapacity` (the caps as one **injectable**
value, `.production` defined *as* `MeshRoutedStoreFormat` so no number is written twice, threaded
through `MeshRoutedStore.init(scope:capacity:)` and read back off the store by everything that
accounts, so the doors and the accounting can never measure against two models), `MeshRoutedCapacityUsage`
(the accounting rule stated once — parked items count, staged bytes count, and the manifest door's
**over-commit** is named by `uncompletableItemCount` rather than fixed, because a durable reservation
would need at-rest state), `MeshRoutedParkedDrop` (the ONE-clause terminal-refusal rule) and the
bounded observable `MeshRoutedDeliveryHold` + `MeshRoutedDeliveryHoldCause`. The store gained a bulk
`dropping(items:reason:)` — one load and one seal for a whole reclaim batch, where sixteen calls to
the single-item verb would be sixteen full index seals on the main actor — and `MeshRoutedIndex`
gained `parkedItems(at:)` (C10 made countable), `everyDestinationDelivered(_:in:)` and the fourth
at-rest sibling `capacityExceeded("chunkCount")`.

Four decisions are worth reading before touching any of it:

- **The parked-set drop has exactly one clause, and it is origin-bound.** `unknownTypeToken` **and**
  `sender == manifest.originFingerprint`, because that rejection is checked *before* the signature
  and the origin is the only party the chunk door lets park a set. A clause on
  `notADestinationOrHandoff` was designed and removed: that guard's else branch fires whenever the
  sender is not the origin, so any co-destination holding the origin's genuine manifest could have
  deleted a hand-off custodian's parked ciphertext with a replayable frame. Only a **parked** record
  is ever dropped — the caller is that guard — and never on a capacity refusal, which would turn
  backpressure into data loss.
- **The reclaim reads `itemsReclaimableAsCustodian` intersected with the POSITIVE
  `everyDestinationDelivered(_:in:)`.** "Nothing outstanding" reads true for a destination this
  device's ledger has not heard of yet (an absent fingerprint derives as `departed`), so a reclaim on
  that answer would delete content still owed and audit it as `delivered`. A roster-absent
  destination therefore frees no byte; such an item waits for expiry instead.
- **The release predicate measures what the DOOR measures.** `MeshRoutedCapacityUsage.hasRoomToAdmit`
  takes the file cap against `max(index-named files, files the directory actually holds)`, exactly as
  the chunk door does, and an unreadable directory reads as "no room" rather than as room — otherwise
  the visible hold clears while the door is still refusing. Orphans are not hypothetical: every drop
  verb saves the index *before* it unlinks, and a failed unlink is counted rather than swallowed, so
  `sweepingOrphanChunkFiles()` is the file cap's only recovery route and runs inside the same
  once-per-peer budget. Only the three **store-level** caps
  (`MeshNetworkManager.routedStoreFullRefusals`) may raise the hold this predicate releases; the three
  per-item caps are refused by name and narrow the entitlement, but they are not "this device is
  full", and a store-level release must never drop a hold raised by a cap it cannot see.
- **Expiry needs no roster, so it has three seams** — the drain-exchange entry, the next session's
  ledger arm, and the Friends-tab search *while a hold is showing*. A routed item expires
  `hardDeadline + 20 minutes`, i.e. **after** the session that could have swept it: a sweep wired only
  to the exchange could never collect one in the common case. Every seam is gated on `case .loaded`,
  so nothing sweeps while protected data is unavailable.
- **The visible surface has to be TRUE, not merely present.** `MeshNetworkManager.routedDeliveryHold`
  is derived from three facts kept apart (refused keys, the over-commit count, item 8's unplaced keys)
  under a fixed precedence, so one count never unions two of them; the two key sets are bounded by
  `MeshRoutedStoreFormat.maxItems` and **name that bound in an audit line** when full, so the count
  saturates rather than lying. It is cleared by a new ledger and **not** by `leaveMesh` — the Friends
  tab is where it is read — and it is *released* the moment a sweep gives the store room again. It is
  the module's only observed routed seam, on purpose. `deferred`, seal-`refused` and `corrupt` set no
  hold at all: they are three other answers, not "full" — and the sweep budget is spent only **after**
  the store answers `.loaded`, so an exchange that did no work does not strand that peer's reclaim,
  and its release, for the rest of the session.

**Membership wire tokens (plan §8.3), and the one vocabulary rule.** A record kind's `rawValue`,
the `PayloadType` it travels as, and the `FernletCryptoPurpose` it is signed under are the SAME
frozen English spelling, so one grep finds every layer that touches those bytes:

| token | record | signed by | crypto domain |
| --- | --- | --- | --- |
| `fernlet.mesh.member-admission.v1` | `SignedAdmissionRecord` | an existing member, or the founder | `Signature.meshAdmissionTokenV2` (the token's own) |
| `fernlet.mesh.member-departure.v1` | `SignedDepartureRecord` | the departing member | `Signature.meshMemberDepartureV1` |
| `fernlet.mesh.member-removal.v1` | `SignedRemovalRecord` | the tallier, citing ⌊\|roster\|/2⌋ + 1 votes | `Signature.meshMemberRemovalV1` |
| `fernlet.mesh.terminated.v1` | `SignedTerminationRecord` | a final-pair member | `Signature.meshTerminatedV1` |
| `fernlet.mesh.inventory-digest.v1` | — (a message, not a record) — **membership records only**, never routed content | any member | `Signature.meshInventoryDigestV1` over a `Hash.meshInventoryDigestV1` digest |
| `fernlet.mesh.epoch-heads.v1` | — (a message, not a record) | any member | `Signature.meshEpochHeadsV1` |
| `fernlet.mesh.removal-proposal.v1` | — (live state, not a record) | the proposer, whose proposal IS its vote | `Signature.meshRemovalProposalV1` |
| `fernlet.mesh.removal-vote.v1` | — (live state, not a record) | any member except the target | `Signature.meshRemovalVoteV1` |
| `fernlet.mesh.routed-manifest.v1` | `MeshRoutedManifest` (a content record, not a membership record) | the origin only — relays forward it verbatim, never re-sign | `Signature.meshRoutedManifestV1`; wraps under `KeyDerivation.meshRoutedContentKeyWrapV1` + `AEAD.meshRoutedContentKeyWrapV1` |
| `fernlet.mesh.routed-chunk.v1` | `MeshChunk` (one slice of that item's ciphertext) | the origin only — a custodian forwards it verbatim, never re-signs | `Signature.meshRoutedChunkV1`; digests under `Hash.meshRoutedContentV1` (the whole item), `Hash.meshRoutedChunkV1` (one slice) and `Hash.meshRoutedChunkIDV1` (the derived replay-window id) |
| `fernlet.mesh.custody-receipt.v1` | `MeshCustodyReceipt` (a custodian durably holds one item's complete ciphertext) | the **custodian**, about the origin's item — the one routed record its subject did not sign; relays forward it verbatim | `Signature.meshCustodyReceiptV1`; the derived dedup id under `Hash.meshCustodyReceiptIDV1`; the at-rest store sealed under `KeyDerivation.meshRoutedStoreV1` |
| `fernlet.mesh.recipient-receipt.v1` | `MeshRecipientReceipt` (a destination received one item, FINALLY) | the **recipient**, about the origin's item; relays forward it verbatim, and it carries no ack stage — what "finally" meant is resolved from the origin-signed type token | `Signature.meshRecipientReceiptV1`; the derived dedup id under `Hash.meshRecipientReceiptIDV1`, one per `(recipient, item)` |
| `fernlet.mesh.routed-inventory-digest.v1` | — (a message, not a record) — the ROUTED CONTENT a device holds: a minimal fingerprint table plus one entry per live item, each with the signed `(origin, itemID)` pair, the parked flag, the chunk count, the **exact** held-chunk bitmap and the two receipt-signer lists | the **advertiser**, about its own disk — nobody forwards it on another device's behalf | `Signature.meshRoutedInventoryDigestV1`; **no** `Hash` sibling, because the entry list IS the digest |
| `fernlet.mesh.routed-drain-answer.v1` | — (a message, not a record) — the RESULT of comparing two routed inventories: whose advertisement is being answered, which one (its own signed instant), and the single bit "my delta against it is empty" | the **answerer**, about its own comparison | `Signature.meshRoutedDrainAnswerV1`; **no** `Hash` and **no** `AEAD` sibling — one Bool and two binding scalars have nothing to digest and nothing to seal |

**Nothing enters a ledger unverified.** ``MeshMembershipRecordSet`` is pure algebra and will merge
whatever it is handed; ``MeshMembershipRecordVerifier`` is the only door. That matters because the
sets are capped at sixteen and keep the EARLIEST records, so unverified junk with a low timestamp
would crowd a real removal out of the set on every device it reached. Signing keys come from the
ledger's own admissions, never from the record being checked; the single exception is the bootstrap
admission, rooted in a founder key the caller authenticated elsewhere.

**Legacy `fernlet.session.bye.v1`: parsed, never emitted.** A goodbye is unsigned, so the strongest
thing it can mean is "this link is going away" — the peer is **disconnected, not departed** (plan
§8.2). ``MeshMembershipGoodbyeInterop`` states that rule in code, including a
`departureRecord(forGoodbyeFrom:)` that is always nil: departures are grow-only and permanent, so
an unsigned frame that could mint one would make eviction forgeable by anybody who can reach the
link, with no way to undo it. New builds send ``PayloadType/meshMemberDeparture`` instead; deciding
*when* is a state-machine transition, and `MeshNetworkManager.emitMembershipEvent(_:)` is the seam
plan items 5–6 filled.

**The removal frame does not go to the member it removes** (plan §8.3, P3 item 3b).
``PayloadType/meshMemberRemoval`` carries a `MeshMemberRemovalPayload` — one quorum-signed
`SignedRemovalRecord` and nothing else — to every member *except* the removed one, who is excluded
by the same rule that keeps them out of the new epoch's key distribution
(`MeshRotationPolicy.recipients`, reused verbatim so "who gets the key" and "who is told why"
cannot drift apart). They learn of the removal as a key that no longer opens anything. On the
receiving side the record goes through ``MeshMembershipRecordVerifier`` — quorum re-derived on the
receiver's own merged roster — then through `commitVerifiedRecord(rollingBackTo:type:)`, so it is
durable before it counts; a record naming THIS device applies plan §8.2's `removed` edge and tears
participation down, which is the one state-machine edge item 6 built and could not yet wire.

### Quorum under partition (plan §10.4, P4 item 5)

A removal takes **⌊|roster|/2⌋ + 1 distinct signed votes**, and every part of that sentence is
re-derived at the *receiver*: ``MeshRemovalQuorum`` stores raw voter fingerprints and filters them
against the roster handed in at **verdict** time, so a merge that grew the roster raises the bar and
a departure that shrank it lowers the bar with nothing stored having changed. The proposal counts as
the proposer's vote, the target's vote is discarded (and refused at the door), a duplicate signer
counts once, and a signer who has since departed or been removed falls out of the roster and so out
of the tally.

**Proposals and votes are live state, never records.** They are held in memory on
`MeshNetworkManager.removalQuorum`, never sealed — `MeshSessionContext` stays at schema 2 and no
wipe row is owed — because a proposal is a five-minute conversation, not a fact about the mesh. An
incomplete one expires and leaves **no** trace: expiry is a deletion, not a tombstone, so there is
nothing to merge and nothing a late vote can reopen. Only the completed removal is durable.

**Expiry reads no wall clock from the wire.** The five-minute window is measured from the receiver's
own `firstSeenAt` on an injected clock. The signed `issuedAt` / `castAt` stamps are bound into the
signature for the audit trail and are used only as a **bound** — §10.3's ±10 minutes, reused rather
than restated — so a forged far-future stamp cannot extend a window and a forged far-past one cannot
kill a live proposal.

**Completion mints the existing record.** `evaluateRemovalQuorum` hands the voter list to
`mintAndFileRemoval`, the one body both quorum paths end in, which signs a `member-removal.v1`,
files it through the verifier, seals it, and only then announces it (plan §3.6). Two branches that
complete independently mint two records for one member; ``MeshMembershipRecordSet`` deduplicates by
member keeping the earliest, so the union converges on **one** effective removal with no merge
special case and no second ledger commit. The removed member is not cut off mid-tunnel — the record
refuses their *next* introduction as `barredMember`.

**The legacy two-party vote is untouched.** `fernlet.mesh.removal.proposal.v1` /
`fernlet.mesh.removal.second.v1` are UNSIGNED, hard-code quorum at two and read `Date()` directly.
They stay frozen and are what already-shipped builds speak, exactly as `fernlet.session.bye.v1`
stays frozen beside the signed departure record. The spelling is the tell: **dots** for the legacy
pair, **hyphens** for the signed quorum.

**The introduction authority answers from the derived roster** (plan §8.1, §20.4.4, P3 item 7).
`MeshNetworkManager.roster` is `MeshDerivedRoster.introductionRoster(additionalBarred:)`, so the
QUIC radio judges a peer against `admitted − departed − removed` and nothing else. This closes plan
§20.1's recorded gap: the manager used to keep removals by *fingerprint* and hold no signing key for
a member it had dropped, so `barred` was empty in production and a removed peer refused as an
anonymous `unknownIdentity` — matrix row 3 (`barredMember`) was produced by a DEBUG chaos hook. The
admission record keeps the member's signing key, so a verified removal or departure names a key and
`barred` has real contents. P3 item 9 then drove the `barredMember` branch on the radio with
`FERNLET_MESH_CHAOS_BARRED` **unset** — a pair, a really-signed removal record, and the shipping
derived roster's own refusal — so the hook survives only where a *real* quorum is needed
(⌊2/2⌋ + 1 = 2 votes with the target excluded leaves one eligible voter), which takes three nodes. With **no** ledger the answer falls back to the gossiped
descriptor's members and logs `mesh.introductionAuthority.legacyRosterFallback` once — reachable
only in tests and in interop with a build predating these records, because a founder files its own
admission at `startNewMesh(name:)` and a joiner files its granted one at `armJoinerLedger(_:)`.

**A joiner adopts a ledger; it does not merge into one** (plan §8.3, §10.5, P3 item 7). A founder
bootstraps from its own signing key, but a joiner does not know the founder's — it knows only the
admission token its transport-authenticated peer signed. So ``MeshLedgerAdoption`` does it in two
steps. **Bootstrap**: arm a verifier whose root is the *admitter's* key and file this device's own
admission, giving a one-member roster that can sign and file records at once. **Adopt**: when a
peer's ledger arrives, re-verify it from *its own* root and accept that root as the founder only if
the result admits this device's admitter under exactly the key its token names — the chain §8.3
describes, checked end to end. Merging record-by-record could never converge: to a ledger rooted at
the admitter, the founder's self-admission is `unauthorizedAdmitter`. Convergence is one round trip:
the joiner sends `fernlet.mesh.inventory-digest.v1`, a peer holding at least as many records answers
with a bounded re-gossip of the frames that already carry them (once per peer per session), and a
record frame never provokes another digest. `fernlet.mesh.member-admission.v1` exists for that
re-gossip and for the live case — an admission happens between two devices alone, and a third member
that never learns of it derives a roster one short, which `MeshRotationPolicy` then turns into a
member who silently never receives the group key. It moves **no new signed bytes**: the record wraps
the existing `MeshAdmissionToken`, still signed under `meshAdmissionTokenV2`.

**Plan §8.2's `terminationVerified` edge** (P3 item 7). A verified `fernlet.mesh.terminated.v1`
whose signer the *merged* roster agrees was in the final pair ends the session — ending mark,
teardown, permanent rejoin bar. Whether it ends the mesh is not the sender's decision and not the
dispatch path's: ``MeshDerivedRoster`` applies §8.3's downgrade rule first, so a termination signed
by a member of a roster larger than two costs its signer their own membership and nobody else's, and
reaches the manager as an ordinary roster change that rotates the key.

**Two durable surfaces, and the four that stay memory-only.** P3 item 2 reversed this module's
old blanket "ProximityKit persists nothing" rule (plan §17.3), and the reversal is narrow on
purpose. `MeshSessionContext` — mesh id, protocol version, `createdAt`/`hardDeadline`, the
membership ledger, epoch heads, the develop bar — is sealed at rest by ``MeshSessionStore`` under
`FernletCryptoPurpose.KeyDerivation.meshSessionContextV1`, on a per-instance
``MeshSessionStorageScope`` (directory *and* keychain service, so a wipe takes both together).
`MeshGroupKey`, `PeerSlot`, `MeshSessionRosterEntry`/`MeshFriendReviewBatch` and the
`SessionMessageStore` transcript are **still never persisted**, and `MeshGroupKey`'s doc guard is
now load-bearing by contrast: content never depends on the control key, so resume reconnects and
rotates rather than reloading a secret.

P5 item 3 added the **second** durable surface, on the same floor and with its own everything:
``MeshRoutedStore`` seals `MeshRoutedIndex.sealed` (the catalogue of routed items this device is
holding for other people, their delivery maps and the receipts other members signed) plus one
`MeshRoutedChunks/<uuid>.chunk` file per held slice, under
`FernletCryptoPurpose.KeyDerivation.meshRoutedStoreV1`, on a per-instance ``MeshRoutedStorageScope``
whose keychain service is its **own** (`com.fernlet.mesh-routed`) rather than a lodger under the
session's — one fate per service is the only arrangement a service-wide delete can express honestly.
Its schema is its own from day one (``MeshRoutedIndexSchema``, version **2** since P5 item 4 added the
durable ack instant and the recipient-receipt evidence set — an older file is `corrupt`, never
migrated, because reinterpreting one would produce a record whose two new fields the next save
silently drops; the at-rest *token* does not move, since it names the key-derivation domain);
`MeshSessionContext` stays at schema 2 and gains nothing. Chunk file names are opaque random UUIDs recorded in the index, so no
fingerprint, item id, index or hash appears in a path component; and because `ColumnCrypto`'s AAD is
purpose ‖ install binding with **no file name in it**, every read compares the opened chunk's
descriptor and payload length against the ones holding its slot — a comparison that is not redundant
and must not be removed.

**Loading either of them has five states, and three of them are not "empty".** `ColumnCrypto` is
V3-only and *refuses* to seal without a `DeviceBindingID` (owner decision D4), so before first unlock
neither file can be written at all. ``MeshRoutedLoad`` mirrors ``MeshSessionLoad`` case for case and
its refusal, deferral and corruption vocabularies carry the **same frozen rawValues** (a test asserts
the sets are equal), because invariant 7 is stated once and enforced everywhere:

| state | meaning |
| --- | --- |
| `loaded` | a context is in hand |
| `absent` | no file — genuinely a green field |
| `deferred` | ask again (locked file, transient keychain, retryable binding read error) |
| `corrupt` | bytes exist and do not decode — quarantine explicitly, never overwrite |
| `refused` | custody refused, by name (`MeshSessionSealRefusal`) |

**Seal refused ≠ deferred ≠ absent.** A refusal that is filed as `absent` is the shape that
overwrites live membership: a caller reading "no prior context" starts a fresh mesh and saves over
records the user's friends still hold. Only `loaded` and `absent` vend a `MeshSessionStore.LoadToken`,
and `save` cannot be called without one — so the distinction is enforced by the type system, not by
a comment. `save` also honours durable-before-acknowledged (plan §3.6): it throws rather than
returning success, so no membership record, custody receipt or "joined" is acknowledged over bytes
that never reached the disk.

**The at-rest schema is 2, and a v1 file is `corrupt` rather than migrated.** P3 item 4 narrowed
`epochHeads` from an opaque `[String]` placeholder to `[MeshEpochRef]` — the same JSON shape, a
strictly narrower meaning — and bumped `MeshSessionContextSchema.current`. There is no migration,
which is defensible only because of *when* it happened: the store shipped in this same phase, so no
build that wrote a v1 file has ever run on a device, and `corrupt` is exactly the state that refuses
to overwrite a file this build cannot account for. The sealing token stays `…session-context.v1`
because it names the **crypto domain**, which did not change; `current` is what carries the shape.
Item 6 added one field, `localTermination`, and did **not** bump: an additive optional whose absence
decodes to nil changes no at-rest shape, and the bump rule is about narrowing, not growing.

**The lifecycle is a value, and it is total** (P3 item 6, plan §8.2). ``MeshSessionState`` has ten
states and ``MeshSessionStateMachine/transition(from:on:)`` is a pure function over (state, event):
every pair either moves — with an ordered ``MeshSessionEffect`` list — or is refused by name
(``MeshSessionTransitionRejection``). There is no trap, because most of these events arrive from the
wire. Effect **order** is the durable-before-acknowledged rule made mechanical: `persistContext`
precedes every effect that tells anybody anything, and `MeshNetworkManager` abandons the rest of the
list when a save fails.

The edges, as a list:

| from | event | to | effects |
| --- | --- | --- | --- |
| `idle` | `founded` / `joined` | `joining` | persist |
| `idle` | `contextRestored(.resumable)` | `localIdleStop` | offer resume |
| `idle` | `contextRestored(.terminated/.departed)` | `terminated` / `departed` | — |
| `idle` | `contextRestored(.expired)` | `expired` | mark, persist |
| `joining` | `peerCommitted` | `activeForeground` | persist, clear idle timer |
| `joining` | `linksLost` | `joining` | — (nothing committed is not a partition) |
| `activeForeground` | `backgrounded` | `continuingInBackground` | — |
| `continuingInBackground` | `foregrounded` | `activeForeground` | — |
| `activeForeground` / `continuingInBackground` | `linksLost` | `partitioned` | arm idle timer |
| `partitioned` | `linksRestored` / `peerCommitted` | `activeForeground` | clear idle timer, **merge** |
| `partitioned` | `idleLapsed` | `localIdleStop` | stop participation |
| `localIdleStop` | `resumedAfterLapse` | `activeForeground` | start radios, **merge** |
| any live | `developed` | `handingOff` | mark, persist, stop |
| any live | `departureRequested` / `terminationRequested` | `handingOff` | mark, persist |
| any live | `terminationVerified` | `terminated` | mark, persist, stop |
| any live | `removed` | `departed` | mark, persist, stop |
| any live | `hardDeadlineReached` | `expired` | mark, persist, stop |
| `handingOff` | `departureSent` / `terminationSent` | `departed` / `terminated` | stop |
| `departed` / `terminated` / `expired` | anything | — | refused `sessionAlreadyEnded` |

**A disconnect is not a removal** (invariant 1): losing the last committed link moves the *session*
to `partitioned` and mints nothing — the ledger, the derived roster and the peer's admission are
untouched, so the reconnect needs no re-admission and the returning member is still a key recipient.
A member the roster actually *removed* stays excluded by `MeshRotationPolicy.recipients`.

**A partition is presence, never a record** (P4 item 1, plan §10.2). ``MeshBranchView`` is what a
device can *see* — derived from the roster plus a set of reachable fingerprints — held deliberately
apart from ``MeshMembershipLedger``, which is what it can *prove*. Unreachable members are marked
``MeshMemberPresence/temporarilyDisconnected``, and the derived roster, the quorum threshold and the
final-pair test are **copied onto the branch view unchanged**, so a 2/2 split of a roster of four
leaves both branches deriving four members, a quorum of three, and `isFinalPair == false` (§10.4,
§10.6). None of it is `Codable`: presence is never sealed, and `MeshSessionContextSchema.current`
stays at 2. ``MeshPartitionDetector`` is the pure edge-detector — only *entering* a partition raises
`linksLost` and only a *full* heal raises `linksRestored`; a partial heal keeps the branch a branch
and lets the returning peer take `peerCommitted` into the merge path.

Detection is **on demand**: `MeshNetworkManager.evaluatePartition(reachable:now:)` is the same shape
as `enforceSessionCeiling(now:monotonicElapsed:)` and `evaluateIdleLapse(now:)`, with no timer of its
own — P7 wires the one poller that drives all three. While a device is partitioned its rotation
roster is scoped to the branch (intersected with the current full roster, so a departure since the
last evaluation still excludes), which makes the **branch coordinator the lowest fingerprint
present** and is exactly why two branches rotating independently at the same counter mint distinct
``MeshEpochRef``s that `coexist`. `noteExternalHeartbeat(from:at:)` pushes the 30-minute idle window
out for a current member's authenticated heartbeat, so a live branch of two or more stays alive
while a partition of one runs to `localIdleStop` and resumes-as-merge.

**Development under partition is decided on the merged roster** (P4 item 6, plan §10.6).
``MeshDevelopmentPlan`` is the whole decision as one pure value, derived before anything is signed:
the **merged derived roster** chooses the ending (``MeshDevelopmentEnding/termination`` only when
`isFinalPair`, ``MeshDevelopmentEnding/departure`` otherwise) and the **branch view** chooses the
custodians (`presentFingerprints − self`), with the 15-second window expressed as a deadline and
``MeshDevelopmentHandoffOutcome`` as its named answer — completed, nobody reachable, or the window
closed first. The type never sees how many peers are connected, so "a 2/2 split of a four-roster is
two final pairs" is not a mistake the call site can make. P5 item 8 added
``MeshDevelopmentPlan/handoffSummary(handedOffItemCount:)`` beside the zero-argument
``MeshDevelopmentPlan/handoffSummary``, which stays as the nothing-transferred answer: the plan is
handed the count rather than computing it, because the number is a fact about a durable routed index
this pure value deliberately cannot reach. `permitsTermination(_:)` is the same rule
applied as an **issuance gate** inside `sendMembershipEvent(_:custodyHandoff:)`: a device whose own
merged roster is larger than two will not sign a `terminated.v1` at all (a device with no ledger —
the ceiling, the epoch-counter cap — still may, or an ending would be silenced rather than a wrong
one prevented). The receiver's safety never depends on that gate: ``MeshDerivedRoster`` downgrades a
termination from a larger roster to its signer's departure **at read**, which is why the union-merge
stays commutative, associative and idempotent. The derivation is stateless, so a receiver whose
roster later *grows* re-reads the same record as a departure; the one-way half is the local session,
whose ending mark and rejoin bar are durable and permanent.

**Any reconnect is a merge, and there is exactly one merge path** (P4 item 2, plan §10.3). A blip, a
healed partition, an idle-lapse resume and a process restart are four doors onto
`MeshNetworkManager.mergeReconnected(_:entry:)`, which is a named front door onto
`mergeMembershipLedger(_:)` and nothing more; ``MeshMergeEntry`` records *which* door without
anything branching on it. The union each door carries is a ``MeshMergeOffer`` — the peer's records
plus the epoch head(s) it holds. The **record** half is assembled from frames that already exist:
the signed `fernlet.mesh.inventory-digest.v1` asks, and the bounded record re-gossip answers with the
same record frames a live record arrives in — no wire bytes moved for any of it. The **epoch** half
needed one frame of its own (P4 item 3): the digest describes records, and its signed bytes are
pinned by a golden, so widening it would have been a wire decision rather than a merge fix.
`fernlet.mesh.epoch-heads.v1` is additive — its own token, its own registered signature domain
`Signature.meshEpochHeadsV1`, its own golden, its own framing-transcript case — and no existing
golden moved. P5 item 1's `fernlet.mesh.routed-manifest.v1` followed the same rule — purposes
pre-registered in P0, its own golden and framing case, no existing golden moved. So did P5 item 2's
`fernlet.mesh.routed-chunk.v1`: one new signature purpose, three new `Hash` purposes, four new
vectors (the chunk transcript, the per-chunk hash, the item hash and the derived chunk id), its own
framing-transcript case — and the manifest golden re-asserted, untouched, in the new suite. And so
did P5 item 3's `fernlet.mesh.custody-receipt.v1`: one new signature purpose, one new `Hash` purpose
for the derived receipt id, one new `KeyDerivation` purpose for the at-rest seal, two new vectors and
its own framing case — with the inventory, manifest and chunk goldens all re-asserted untouched. And
so did P5 item 4's `fernlet.mesh.recipient-receipt.v1`: one new signature purpose, one new `Hash`
purpose for its derived id, **no** new `KeyDerivation` (the at-rest seal is unchanged and item 4 adds
no file), two new vectors and its own framing case — with the inventory, manifest, chunk and
custody-receipt goldens all re-asserted untouched.
And so did P5 item 5's `fernlet.mesh.routed-inventory-digest.v1`: one new signature purpose, **no**
new `Hash` purpose (the digest carries no rollup hash — the entry list is the digest), one new
vector and its own framing case, with all four routed goldens and the membership inventory golden
re-asserted untouched. Its own token was the item's first decision, because
`fernlet.mesh.inventory-digest.v1` was already taken by the membership digest and the two summarise
structurally different things.
And so did P5 item 6's `fernlet.mesh.routed-drain-answer.v1`: one new signature purpose, **no** new
`Hash` and **no** new `AEAD`, one new vector and its own framing case — with all five routed goldens
and the membership inventory golden re-asserted untouched. Its stem is `routed-drain-`, not
`routed-inventory-`, because the frame states the result of a **comparison** rather than what a disk
holds; the two diverge at `d` vs `i` immediately after `routed-`, so neither prefixes the other.

**Both halves travel in both directions** (P4 item 2c). The ask sends the digest and the heads
together, and the answer to a *mismatched* digest sends the bounded re-gossip and the heads together,
for the same reason. A device inside an open merge window opens no second exchange, and an exchange
is the only other thing that sends a head — so an answer of records alone left a peer converged on
this device's ledger and still counting up from its own older head, with nothing in flight to correct
it. The seeded convergence property found it (`MeshConvergencePropertyTests`); the fix moves no wire
bytes, because the frame it now sends is the one the ask already sent.

Three consequences worth stating outright:

- **A record arriving while a merge is in flight is merge traffic.** While `awaitingResumeMerge` is
  set, `dispatchMembershipEventPayload` offers the decoded record to `mergeMembershipLedger(_:)`
  rather than to the live-record insert, so a returning peer's whole re-gossip mints **one** `.merge`
  epoch instead of one `.membership` epoch per record. The window opens on
  ``MeshSessionEffect/beginMerge`` (and on the `peerCommitted` self-edge, which carries no effects —
  that is the blip and item 1's partial heal). Splitting again abandons it rather than concluding it.
  **P5 item 6 wired the routed half onto exactly those doors** — `sendRoutedInventory(to:)` fires
  from the same three call sites `sendInventoryDigest(to:)` does, and nowhere else, which is the
  mechanically checkable form of "do not add a second reconnect path"
  (`MeshRoutedDrainWallTests.theDrainFiresOnlyFromTheMergeDoor`). The routed answer gets its **own**
  receive door rather than a ride inside `receiveInventoryDigest(_:)`, because that function returns
  at its match branch before its own `Task` whenever the two ledgers already agree — the commonest
  blip, and precisely the case the drain exists for. **P5 item 8 added a third door class to that
  wall** — the one-moment hand-off push, which opens no exchange and sends neither digest, but does
  carry routed bulk. It moves bytes through `sendRoutedBulk(_:to:now:)`, extracted from the drain's
  own answer so both charge the per-peer session budget before their first `await`, and it is named
  in the wall rather than left to a count that would have stayed green by accident.

- **The window is a value, and it closes only when every asked peer has matched** (P5 item 7, which
  retired P4's deferred defect 2d). ``MeshMergeWindow`` is a pure `nonisolated struct` holding three
  bounded per-peer sets — **asked**, **answered**, **matched** — plus the digests peers sent *while
  this window was open*. The rule is one line: `pending = (asked ∪ answered) ∩ reachable ∖ matched`,
  and the window closes exactly when `pending` is empty. Four things about it are load-bearing:
  - **"Answered" is inside `pending`.** A responder that merely answered a mismatch has *added* an
    obligation, never discharged one — that is P4 item 2c's deadlock staying shut by construction
    rather than by a comment. A peer's later *mismatching* digest also removes it from `matched`,
    so an obligation can never be created and discharged by the same frame. So does the **late
    ask**: a peer that re-commits while the window is open is re-asked through `reAsking(_:)`,
    which drops it from `matched`, because a link that dropped and re-formed may have carried that
    peer through the other branch of a split — the one peer whose pre-disconnect match proves
    least. The *opening* ask un-matches nobody.
  - **`reachable` is every committed slot ∩ the derived roster**, never `activeSlots`. `.active` is
    a UWB distance rank capped at three of five slots, re-assigned from ranging samples, while
    `broadcastMembershipFrame` reaches all slots — so a `.lightweight` peer re-gossips exactly like
    an active one, and subtracting it would restore 2d from a distance measurement with no
    membership meaning. A peer that departs or whose slot goes simply leaves `pending`: derived at
    read time, never a stored fourth state.
  - **The proof is the occasion, not a new frame.** Nothing else ever sent a second digest inside
    one session, so the strict rule alone would wedge every bidirectional mismatch. A fold that
    moves this device's `localInventoryDigest` re-advertises it, once per distinct digest, to the
    pending set captured **before** that fold's re-evaluation — a device that has just converged is
    precisely the device whose peers are still waiting to hear it. It rides
    `fernlet.mesh.inventory-digest.v1` unchanged: no new frame, field, purpose or golden. It opens
    no window, asks nothing, and carries no routed twin. A **joiner** gets the same treatment for
    the same reason: its grant-reply digest is a one-record bootstrap ledger, so the admitter
    answers it and holds the obligation, and adoption rebases the joiner's ledger without going
    through `mergeMembershipLedger(_:)` — so `attemptLedgerAdoption(ownAdmission:meshID:)` sends one
    digest to the admitter itself, the joiner's only other occasion to speak. Those two non-ask
    doors are why the membership ask now has **six** call sites while the routed one still has four
    — an asymmetry the wall asserts per function rather than by counting.
  - **The routed half is recorded and gates nothing.** `MeshRoutedInventoryDelta.converged(local:
    peerReportsQuiescent:)` is read at close time and logged as a count on `mesh.merge.converged`;
    it is not part of the closing rule. Gating on it would hold a window for the length of a
    256 MiB transfer, and — decisively — the capacity-refusal contract subtracts a refused key from
    the entitlement but not from the delta's ask, so a refused pair is non-quiescent for the rest of
    the session and such a window would never close again. That asymmetry is item 9's surface. The
    window's job is to route this reconnect's *records* through the merge path; it is finished when
    the ledgers agree, whatever the bytes are doing.
- **Reconnect ≡ merge; admission ≠ reconnect.** The `peerCommitted` self-edge also carries every
  genuinely new member's first commit, so `openBlipMergeIfReconnected(_:from:peer:)` opens the window
  only for a peer that was **already on the derived roster** at that instant. A new admission keeps
  its own `.membership` rotation — a merge window would relabel a brand-new member's first epoch
  `.merge` (which outranks `.membership` in the 2 s coalescing window) and leave this device waiting
  for a re-gossip nobody asked for. A commit that names no peer opens nothing: fail closed.
- **A merge applies what the merged roster says about this device.** `applyMergedRosterVerdict(from:)`
  is the merge-path counterpart of `applyRosterMove(_:from:)`: a departure or removal that happened
  in the other branch of a split arrives *only* as a merged record, so a merge that left this device
  believing it was still a member would be the merge failing open. It ejects only a device that
  **was** on the roster and no longer is, so a ledger growing from empty is never mistaken for one.
- **A merge refreshes presence.** `refreshBranchViewAfterMerge()` re-derives ``MeshBranchView``
  against the roster the union just produced, carrying reachability over verbatim, so a member whose
  departure record arrived in the merge stops answering ``MeshMemberPresence/present`` immediately
  rather than at the next evaluation. It runs no detector and raises no event — a merge is not a
  reachability change.
- **A restart merges rather than rebuilding.** `restoreMembershipLedger(from:)` puts the sealed
  ledger back through ``MeshLedgerAdoption/adopt(offered:ownAdmission:meshID:)`` — a
  re-verification from the ledger's own self-admitted root, not a trust — so a relaunched member has
  something to merge *from* instead of dropping every membership frame `droppedNoLedger`. Schema
  stays at **2**; nothing new is written.

Epoch heads **coexist**: two branches that rotated at the same counter hold distinct
``MeshEpochRef``s (their coordinators cannot be the same member), both survive
``MeshMergeOffer/foldedHeads(_:adding:limit:)`` into `epochHeads`, and an overflow past
`MeshSessionContextSchema.maxEpochHeads` is **named** (`droppedEpochHeadCount`, plan §21.3's "an
assertion, not a knob") rather than silently truncated. The count is taken **inside the one context
writer, after the bytes seal** — the set the cap can bite is the set being written, so a count taken
anywhere else measures something the file never held. Never a fresh session, never a silent re-key.

**Coexistence ends at a mint** (P4 item 3, plan §10.3). `requestMergeRotationForDivergentHeads()`
asks for **one** `.merge` rotation when the folded head set actually diverges —
``MeshEpochAcceptance/isDivergent(_:)``, two heads at one counter — and it asks through
`requestRotation(cause:)`, so a merge that both moved the roster and reconciled a divergence still
mints one epoch: the second request lands in the first's open 2-second window. The counter is
`max + 1` over the folded set, not `own + 1`: `rotationBasisHead` is the highest head in
`knownEpochHeads` ∪ the keyring's, so a branch that rotated twice against one that rotated once is
counted above rather than adopted. `MeshKeyRotationPayload.newEpoch` carries that same counter,
because every receiver re-derives the ref from it.

**Neither coexisting head wins, and no clock can pick one.** The minter is the merged view's
deterministic coordinator — `presentedRotationRoster().min()`, the merged derived roster intersected
with the branch while partitioned — so it is a pure function of the roster and the counters. When
that coordinator is not at the merge, item 1's branch rule already answers "lowest fingerprint
present among the merging parties" (plan §21.3's default), and a later merge that reaches the absent
coordinator supersedes with a strictly greater counter. A ``MeshEpochRef`` carries **no timestamp**,
so a forged far-future stamp has nothing to influence; `fernlet.mesh.epoch-heads.v1` binds `sentAt`
into its signature and nothing downstream reads it. Both old heads then die at grace expiry, and
every member ends on exactly one post-merge epoch.

**The `divergent` tunnel gate opens for that merge, and only for it.**
``MeshEpochIntroductionVerdict/reconcile(local:peer:)`` replaces P3's blanket refusal, because the
merge runs *over* the tunnel the old rule tore down — two branches that had each rotated while split
could never reconnect at all. The relaxation is scoped three ways: it is reachable only from
``NetworkMeshSession``'s signed channel introduction, which is members-only before any app frame (MC
runs no such stage — 0b's lesson, and the reason ``MeshNetworkManager/maySeatVerifiedPeer(signingPublicKey:)``
exists for the other radio); only the epoch rule moved, with the roster's `stranger` / `barred`
verdict, the mesh-ID check and the malformed-reference check untouched and still downstream of it;
and it applies only when ``MeshIntroductionAuthority/mayReconcileDivergentEpochs`` says a merge can
actually run — a device with no mesh or no ledger keeps
``MeshIntroductionRejection/divergentEpoch``, and the parameter's default is `false` so a caller that
forgets it fails closed.

**Content merges by ID-keyed union, and the gates re-run at the receiving member** (P4 item 7, plan
§10.3 + §21.3). ``MeshContentLedger`` is the content twin of ``MeshMembershipLedger``: three
``MeshContentSet``s — photos by manifest ID, messages by message ID, hearts by gift ID — each
deduped by id, sorted by one total order and capped at the same bound its live surface already
applies (`SessionMessageStore.maxMessages`, `ProximityHeartLedger.maxStoredHearts`,
`FriendPhotoLimits.maxManifestEntries`, reused rather than restated). Union is commutative,
associative and idempotent at the cap as well as below it, so an N-way partition tree converges with
pairwise merges only and no special case. Nothing conflicting can exist — only missing — so nothing
is ever overwritten, and nothing here is persisted or on the wire: `MeshSessionContext`'s schema
stays **2**.

The visible transcript is **re-derived**, never stored: total order `(claimedSentAt clamped to
±10 min of first-seen, senderFingerprint, messageID)`, where *first-seen is the receiver's own
clock*, never a stamp in the message. The clamp is a bound rather than a coordination mechanism — a
claim inside its window is returned unchanged, which is why honest traffic sorts identically at every
member, while a forged stamp moves at most ten minutes from where it actually arrived. Photos are
hash-validated at reassembly by ``MeshPhotoReassembly``, whose `admitting(_:reassembled:into:)`
returns the set **unchanged** unless the bytes match, so "silently kept" is not a reachable state.
Hearts merge without a receipt field at all: a peer's receipt is not this member's, so
``MeshHeartCommit`` drives the merged batch through the **existing** ``ProximityHeartLedger`` — its
id-dedup, its five-minute per-sender cooldown — and a duplicate that crossed the split is collapsed
by the union *before* the ledger sees it, so the cooldown is judged once rather than twice.

**A branch's approval is not a free pass** (§21.3's decision, taken deliberately). The 13+ age gate
and the local block/ban re-run at the *receiving* member through ``MeshContentGates``, folded once
from the seams that already enforce them — `isChatAllowed`, ``ProximityHost/isBlockedFingerprint(_:)``,
``ModerationBanStore/isPeerBanned(fingerprint:)``. They are a **view filter over an unmutated union**,
the same shape as the termination downgrade: a blocked sender's message still unions everywhere, and
a member whose age gate refuses chat simply renders no transcript — re-opening the gate reveals the
merged records with no second merge. The photo ``MeshMergedPhoto/keyEpoch`` rides through the union
untouched: `MeshNetworkManager`'s three `keyEpoch` gates (the manifest's
`keyEpoch >= localJoinedEpoch` filter, the photo decrypt's `key.epoch == photo.keyEpoch`, and the
metadata wrapper's `wrapper.keyEpoch == currentGroupKey?.epoch` in `handleEncryptedMetadata`) would each reject content minted in
the other branch of a split, and plan §21.5 retires them **with the path P5 replaces** rather than
loosening them here. P5 owns the routed store and the drain; P6 owns feature routing; this layer owns
only the rules.

**Delivery targets: who content is for, held apart from how far each copy has got** (P4 item 8,
plan §10.1). ``MeshDeliveryTarget`` is the vocabulary ``MeshRoutedManifest`` expresses its
destination set in (P5 item 1). The set is the **full derived roster at creation time, minus this device** —
never the connected set — and it is immutable for the life of the target: the initializer takes a
``MeshDerivedRoster``, there is no form that takes a reachable set or a ``MeshBranchView``, and no
method removes a destination. Reachability enters only as a *delivery* state, so content created
during a 2/2 split of a roster of four is for three people, both of the far side included, and they
are ``MeshDeliveryState/pending`` rather than absent. That is what stops P5 dropping a recipient who
happened to be on the other side of a split when the photo was taken.

The stored half is a three-rung monotone ladder — ``MeshDeliveryState`` `pending → custodied(by:) →
delivered`, with delivered terminal and every regression refused by a named
``MeshDeliveryRefusal`` — and `custodied` says on its own that **custody is not delivery** (§11:
hearts are final only after the foreground decrypt and the ledger commit). Closure is *not* a fourth
stored case: ``MeshDeliveryDisposition/departed`` is derived at read against the current roster, the
same shape as the termination downgrade, so a departure or removal unioning in closes a destination
with nothing rewritten — and grow-only records make that closure permanent, which is what lets the
drain stop rather than back off. `outstanding(in:)` is exactly §11's "destinations lacking a
`MeshRecipientReceipt`"; `isFullyDelivered(in:)` is its complement. Since P5 item 4 that phrase is
literal: ``MeshRoutedStore/recordingRecipientReceipt(item:receipt:now:)`` is the **only** writer of a
`delivered` rung, it advances only the receipt's own signer, and `committingDelivery` — which records
this device's durable final ack — advances no rung at all. Every `delivered` in a persisted map is
therefore receipt-backed by construction rather than by call-site discipline. `merging(_:)` takes the
per-destination max (commutative, associative, idempotent) and **refuses a destination-set mismatch
by name** rather than unioning or intersecting, either of which would invent or drop a recipient.
The type carries no key epoch, no branch id and no partition of origin, by construction. Nothing is
`Codable`: `MeshSessionContext`'s schema stays **2**, and P5 persists targets inside its routed
store. What makes an item final at a destination is plan §11's per-type table
(``MeshRoutedAckStageTable``), resolved from the ORIGIN-signed type token — photos and text on
durable recipient storage, hearts only after a foreground decrypt and a ``ProximityHeartLedger``
commit, control immediately — and the stage is never on the wire and never the recipient's to state. The two existing seams are derivations rather than duplicates —
``MeshDevelopmentPlan/handoffTargets`` is `outstandingReachable(from:in:)` and
``MeshBranchView/temporarilyDisconnectedFingerprints`` is `outstandingUnreachable(from:in:)`, with
neither type modified to say so.

**Routed manifests: the origin-signed record a delivery target is for** (P5 item 1, plan §11).
``MeshRoutedManifest`` binds item id, type token, ciphertext hash and size, `createdAt`, `expiresAt`
(= the signed `hardDeadline` + 20 min, cross-checked by every receiver against its own context), the
immutable destination set copied from ``MeshDeliveryTarget/destinations``, and one
``MeshRecipientKeyWrap`` per destination — the random content key under ephemeral X25519 → HKDF →
AES-GCM with the mesh, item, origin and recipient in the authenticated data, so a wrap cannot be
moved between manifests or recipients. Signed by the origin only under
`Signature.meshRoutedManifestV1`; a custodian forwards the exact object inside its own envelope and
``MeshRoutedManifestVerifier`` resolves the key from the admission ledger by the manifest's own
origin, never from the envelope's sender — does not require the origin to still be a member (a
departed origin's manifest verifies: leaving is not a retraction) but refuses a quorum-removed
origin's by name (``MeshRoutedManifestRejection/originRemoved``: removal is the mesh's moderation
act, and the group-key rotation that enforces it on live traffic cannot reach a static-key wrap),
does not look destinations up in the ledger (a destination outside the roster reads as departed,
bounded by expiry and the relay caps), and refuses any type token outside the accepted set it is
built with (item 11 substitutes the registry). The routed store keys on the signed pair
`(originFingerprint, itemID)`, never on `itemID` alone — the frame is unsealed and any admitted
member can mint under its own key reusing another origin's id. Verification needs public material only;
``MeshRoutedContentKeyWrapper/unwrap(_:binding:localFingerprint:localKeyAgreementPublicKey:staticAgreement:)``
is the separate, private-key half. The type carries no epoch, branch, custody or first-seen; nothing
persists it yet (item 3); nothing dispatches it yet (item 6).

**Routed chunks: the item's ciphertext, sliced, signed by the origin and reassembled in any order**
(P5 item 2, plan §11). ``MeshChunk`` carries mesh, item, origin, the whole item's `contentHash`,
`chunkIndex` of `chunkCount`, the slice's own `chunkHash`, the item's expiry and the slice — at most
``MeshChunkFormat/maxChunkPayloadBytes`` (256 KiB), at most ``MeshChunkFormat/maxChunkCount`` (1024,
derived from the 256 MiB content cap). **Signed by the origin only**, and the payload is *excluded*
from the signed transcript and bound **through** `chunkHash`, so a 256 KiB slice costs 32 transcript
bytes and a custodian forwards the exact object — signature included — inside its own envelope. Two
domain-tagged digests keep the item hash and a slice hash apart even for a one-chunk item
(``MeshRoutedContentDigest``), and the replay-window id item 12 keys on is **derived**
(``MeshChunk/chunkID``), never a wire field — its doc gives item 12 the wiring's shape plus the
caveat that `MeshFrameReplayWindow`'s 64-per-sender cap is smaller than the 1024 chunks of a maximal
item, so a P5 window must be sized before that id is keyed on. ``MeshChunker`` is the mint and
refuses to mint for a manifest this device did not originate; ``MeshChunkVerifier`` is the receive
door (mesh → shape → admitted key → not removed → signature → chunk hash → expiry, then the manifest
cross-checks, whose identity test is the **triple** `(itemID, originFingerprint, contentHash)` so an
admitted member cannot squat another origin's item id); ``MeshChunkAssembly`` collects slices in any
order — a manifest may arrive last, and completion is impossible until one binds, and a chunk
offered at an index already held is a duplicate no-op when its **signed transcript and payload**
match (an honest re-mint differs only in its hedged signature) and
``MeshChunkRefusal/conflictingChunk`` otherwise. ``MeshChunkCompletion/complete(blob:)`` is the
whole-item hash check, **necessary but never
sufficient** for a custody receipt, since it is a verdict over in-memory bytes and durability (plan
§3.6) is item 3's separate gate. Chunks ride P2's existing per-transfer stream lane with **no
transport change**: a 256 KiB payload in a signed envelope is above the 64 KiB bulk floor and below
the 16 MiB ceiling, so `NetworkMeshSession` gives it a stream of its own by size alone. Nothing here
seals the item (that is item 6 / P6 — item 2 chunks an opaque blob), forwards anything, persists
anything, or tunes the transport.

**Custody: a custodian may say "I hold this" only after the ciphertext survived a write that
returned** (P5 item 3, plan §11 and §3.6). ``MeshCustodyReceipt`` is signed by the **custodian**
about the **origin's** item — the one routed record whose subject did not author it — and it carries
mesh, item, origin, the item's `contentHash`, the custodian, the durable custody instant and the
item's expiry, and nothing else: no destination set, no chunk index, no hop count, no key epoch, no
schema integer (the `.v1` in the domain *is* the version). Its dedup id
(``MeshCustodyReceipt/receiptID``) is derived from `(itemID, origin, custodian)`, excluding both the
hedged signature and `custodiedAt`, so a re-mint of the same claim is the same id.

The order is a **type rule, not a comment**: the mint takes a ``MeshCustodyDurabilityWitness``, whose
initializer is `fileprivate` to `Mesh/MeshRoutedCustodyCommit.swift` — the file holding
``MeshRoutedStore/committingCustody(item:custodian:now:)`` and nothing else. No witness ⇒ no receipt.
The mirror-image gate is `MeshRoutedStore.LoadToken`'s own `fileprivate` initializer in
`Mesh/MeshRoutedStore.swift`, so the commit verb cannot mint its own write token either: two
`fileprivate` gates in two files, neither able to open the other's door. A grep-wall
(`MeshRoutedStoreIsolationTests`) is what notices if the type is ever moved, because moving it would
widen the gate with no compile error.

``MeshRoutedStore``'s verbs — `admittingManifest`, `stagingChunk`, `committingCustody`,
`recordingCustodyTransfer`, `forwardableManifest`/`forwardableChunk`, `sweepingExpired`,
`sweepingOrphanChunkFiles` and `dropping` — each return one ``MeshRoutedOutcome``: `completed`,
`refused` (by name, ``MeshRoutedStoreRefusal``) or `unavailable` (``MeshRoutedUnavailability``, which
is retryable for `deferred`, `notWritten` **and** `refused`, exactly as
`MeshSessionRestoreOutcome.isRetryable` answers its own refusal, and not for `corrupt`). Write
ordering is one-way: the sealed chunk file, then the index — and the writer that makes an orphan
removes it. Both chunk-set decisions are shared with ``MeshChunkAssembly`` through
``MeshChunkAdmissionRule``, so the durable form cannot answer differently from the in-memory one
(C13); ``MeshDeliveryTarget`` is persisted through the explicit ``MeshRoutedDeliveryRecord`` encoder
and restored against the destination set from the **origin's signed manifest**, never from a stored
copy and never re-derived from the current roster. A stored map that will **not** restore is a fault
in this device's own bytes, not evidence that nothing is owed: it is audited, and named at the value
level by ``MeshRoutedItemRef/deliveryRestoreRefused`` and
``MeshRoutedIndex/itemsWithUnrestorableDelivery(at:)``, because every outstanding/handoff enumerator
must skip it and a held item with outstanding destinations may not simply vanish from all of them.
For the same reason a failed `custodiedAt` stamp answers the store's own classification — a refused
seal is not an absent file (§19.5) — rather than flattening to a bare `notWritten`. The store has
**no decrypt door**: it never
unwraps a per-recipient content key and never touches the key-agreement key, so custody is
ciphertext-only by construction (item 10). Nothing here gossips, asks, drains, relays or writes the
`delivered` rung — that is items 4, 6, 8 and 11.

**The ceiling is guarded at both bounds.** ``MeshSessionCeiling`` holds the signed absolute
`hardDeadline` (± 120 s skew) *and* a local monotonic budget measured with `ContinuousClock`, clamped
to six hours at construction. A wall clock set backwards cannot lengthen a session (the monotonic
guard ends it anyway); one set forwards ends it only by the signed bound, and the recorded
``MeshSessionTerminationReason`` names which bound did it.

**The launch restore maps the five load states onto seven outcomes**
(``MeshSessionRestoreOutcome``): a terminated context restores terminated, a live one inside its
ceiling restores as `localIdleStop` with a resume on offer (a relaunch never auto-reconnects,
invariant 5), a live one past its ceiling expires *and writes the mark*, `absent` is no session, a
deferral and a refusal are retried apart and bounded at `MeshSessionRestoreBounds.maxAttempts`, and a
corrupt file is quarantined. The three token-less states start no session and run no writer.

**The save cadence extends the one writer**, `persistSessionContext(addingEpochHead:terminating:)` —
there is deliberately no second door over a five-state load. It saves on founding, on a verified
admission, on every verified record that moves the roster, on every merge, on every rotation, on a
termination and on a departure; each caller treats a `false` as "the thing did not happen", which is
why a refused seal abandons a founding, blocks a join acknowledgement, and **rolls a verified record
back out of the ledger**. A developed, departed or terminated mesh is barred from rejoining by
``MeshSessionRejoinBar``, re-derived from the sealed file at every launch so a restart cannot lift it.

- ``MeshNetworkManager``
- ``MeshSessionStore``
- ``MeshSessionStorageScope``
- ``MeshSessionState``
- ``MeshSessionEvent``
- ``MeshSessionEffect``
- ``MeshSessionTransition``
- ``MeshSessionTransitionRejection``
- ``MeshSessionStateMachine``
- ``MeshBranchView``
- ``MeshMemberPresence``
- ``MeshPartitionVerdict``
- ``MeshPartitionDetector``
- ``MeshDeliveryTarget``
- ``MeshDeliveryState``
- ``MeshDeliveryDisposition``
- ``MeshDeliveryStateToken``
- ``MeshDeliveryRefusal``
- ``MeshDeliveryOutcome``
- ``MeshDeliveryRestoreRefusal``
- ``MeshDeliveryRestoreOutcome``
- ``MeshRoutedManifestFormat``
- ``MeshRecipientKeyWrap``
- ``MeshRoutedManifest``
- ``MeshRoutedManifestPayload``
- ``MeshRoutedManifestMintError``
- ``MeshRoutedManifestVerifier``
- ``MeshRoutedManifestRejection``
- ``MeshRoutedWrapBinding``
- ``MeshRoutedKeyWrapError``
- ``MeshRoutedContentKeyWrapper``
- ``MeshChunkFormat``
- ``MeshRoutedContentDigest``
- ``MeshChunk``
- ``MeshChunkPayload``
- ``MeshChunkRejection``
- ``MeshChunkVerifier``
- ``MeshChunkMintError``
- ``MeshChunker``
- ``MeshChunkRefusal``
- ``MeshChunkAdmission``
- ``MeshChunkBinding``
- ``MeshChunkCompletion``
- ``MeshChunkAssembly``
- ``MeshChunkDescriptor``
- ``MeshChunkSetShape``
- ``MeshChunkAdmissionRule``
- ``MeshCustodyReceiptFormat``
- ``MeshCustodyReceipt``
- ``MeshCustodyReceiptPayload``
- ``MeshCustodyReceiptMintError``
- ``MeshCustodyReceiptRejection``
- ``MeshCustodyReceiptVerifier``
- ``MeshCustodyDurabilityWitness``
- ``MeshRoutedContentHasher``
- ``MeshRoutedStorageScope``
- ``MeshRoutedSealKeyOutcome``
- ``MeshRoutedSealKey``
- ``MeshRoutedIndexSchema``
- ``MeshRoutedStoreFormat``
- ``MeshRoutedIndexDecodingError``
- ``MeshRoutedItemKey``
- ``MeshRoutedChunkDescriptor``
- ``MeshRoutedDeliveryProgress``
- ``MeshRoutedDeliveryRecord``
- ``MeshRoutedItemRecord``
- ``MeshRoutedItemRef``
- ``MeshRoutedIndex``
- ``MeshRoutedSealRefusal``
- ``MeshRoutedDeferral``
- ``MeshRoutedCorruption``
- ``MeshRoutedLoad``
- ``MeshRoutedSaveError``
- ``MeshRoutedChunkFileRead``
- ``MeshRoutedStore``
- ``MeshRoutedRetryBounds``
- ``MeshRoutedUnavailability``
- ``MeshRoutedStoreRefusal``
- ``MeshRoutedOutcome``
- ``MeshRoutedManifestAdmission``
- ``MeshRoutedCustodyOutcome``
- ``MeshRoutedSweepReport``
- ``MeshRoutedIndexLoad``
- ``MeshRoutedStagedFile``
- ``MeshRoutedCapacity``
- ``MeshRoutedCapacityUsage``
- ``MeshRoutedParkedDrop``
- ``MeshRoutedDeliveryHold``
- ``MeshRoutedDeliveryHoldCause``
- ``MeshSessionCeiling``
- ``MeshSessionCeilingBound``
- ``MeshSessionCeilingVerdict``
- ``MeshSessionRestore``
- ``MeshSessionRestoreOutcome``
- ``MeshSessionRestoredDisposition``
- ``MeshSessionRestoreBounds``
- ``MeshSessionRejoinBar``
- ``MeshSessionTerminationReason``
- ``MeshSessionLocalTermination``
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

Membership-event frames are internal to the module and listed above, not here: they carry signed
records rather than app-visible state.

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
