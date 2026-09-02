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
`MeshInventoryDigestPayload`, `MeshMembershipRecordVerifier`, `MeshMembershipRecordRejection`,
`MeshLegacyGoodbyeOutcome` and `MeshMembershipGoodbyeInterop`. P3 item 4 added the epoch model:
`MeshEpochRef`, `MeshEpochBounds`, `MeshEpochRefParseError`, `MeshEpochRefOrder`,
`MeshEpochKeyring`, `MeshEpochKeyringRotationRefusal`, `MeshEpochAcceptance`,
`MeshEpochRotationVerdict`, `MeshEpochRotationRefusal`, `MeshEpochIntroductionVerdict`,
`MeshFrameReplayWindow` and `MeshFrameReplayVerdict`. P3 item 5 added the rotation triggers:
`MeshKeyRotationCause` (on `MeshKeyRotationPayload`), `MeshRotationTriggerBounds`,
`MeshRotationTriggerOutcome`, `MeshRotationTriggerQueue`, `MeshRotationPlan`, `MeshRotationRefusal`
and `MeshRotationPolicy`.

**Membership wire tokens (plan §8.3), and the one vocabulary rule.** A record kind's `rawValue`,
the `PayloadType` it travels as, and the `FernletCryptoPurpose` it is signed under are the SAME
frozen English spelling, so one grep finds every layer that touches those bytes:

| token | record | signed by | crypto domain |
| --- | --- | --- | --- |
| `fernlet.mesh.member-admission.v1` | `SignedAdmissionRecord` | an existing member, or the founder | `Signature.meshAdmissionTokenV2` (the token's own) |
| `fernlet.mesh.member-departure.v1` | `SignedDepartureRecord` | the departing member | `Signature.meshMemberDepartureV1` |
| `fernlet.mesh.member-removal.v1` | `SignedRemovalRecord` | the tallier, citing ⌊\|roster\|/2⌋ + 1 votes | `Signature.meshMemberRemovalV1` |
| `fernlet.mesh.terminated.v1` | `SignedTerminationRecord` | a final-pair member | `Signature.meshTerminatedV1` |
| `fernlet.mesh.inventory-digest.v1` | — (a message, not a record) | any member | `Signature.meshInventoryDigestV1` over a `Hash.meshInventoryDigestV1` digest |

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

**The one durable surface, and the four that stay memory-only.** P3 item 2 reversed this module's
old blanket "ProximityKit persists nothing" rule (plan §17.3), and the reversal is narrow on
purpose. `MeshSessionContext` — mesh id, protocol version, `createdAt`/`hardDeadline`, the
membership ledger, epoch heads, the develop bar — is sealed at rest by ``MeshSessionStore`` under
`FernletCryptoPurpose.KeyDerivation.meshSessionContextV1`, on a per-instance
``MeshSessionStorageScope`` (directory *and* keychain service, so a wipe takes both together).
`MeshGroupKey`, `PeerSlot`, `MeshSessionRosterEntry`/`MeshFriendReviewBatch` and the
`SessionMessageStore` transcript are **still never persisted**, and `MeshGroupKey`'s doc guard is
now load-bearing by contrast: content never depends on the control key, so resume reconnects and
rotates rather than reloading a secret.

**Loading it has five states, and three of them are not "empty".** `ColumnCrypto` is V3-only and
*refuses* to seal without a `DeviceBindingID` (owner decision D4), so before first unlock this file
cannot be written at all:

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

**Idle-lapse resume and partition heal are one mechanism**, and it is the merge path (plan §10.3):
`resumeSessionAfterLapse(mergingLedger:peerEpochHead:)` goes through `mergeMembershipLedger(_:)` and
`MeshEpochAcceptance`, where two branches that rotated independently at the same counter **coexist**
in `epochHeads` until a merge mints a strictly greater successor. Never a fresh session, never a
silent re-key.

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
