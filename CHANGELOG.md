# Changelog

ProximityKit's releases, newest first. The version rule is the README's "Versioning" section: while
the version is 0.y, y moves for a break (of the public API, a wire format, an on-disk format or a
frozen token) and z for additions and fixes; from 1.0 those become the major and the minor version. A
consumer pins `exact:`. Every tag that writes a format, or a version of one, that no earlier folder
holds adds `Tests/ProximityKitTests/Fixtures/<tag>/` with those bytes, generated once from its code by
a generator committed beside the others in `Scripts/cross-version-fixtures/` (0.1.0's is
`generate-0.1.0.swift.txt`, which no target compiles), and `CrossVersionFixtureTests` decodes every
folder with today's code, so a break in what a tag wrote is a test failure in this repository before it
is a release. The cells hold the read direction, today's decoders on a tag's bytes, and the write
direction where an encoding is deterministic (re-encoded byte for byte) and for the verification
ceremony, through today's QR writer and ceremony on both sides (each JSON payload holding every key and
value the tag wrote, a fresh nonce or signature aside); a format a tag's table marks "no fixture" is
not held.

## Unreleased

Additions and a privacy fix, so z moves (0.1.2 when tagged). No public API, wire format, on-disk format
or frozen token is changed or removed; the new wire format below is new, so it writes no format a
fixture folder holds.

### Added

- `ProximityTapRendezvous`, meeting someone new by tapping phones with nothing that identifies either
  person sent before both say yes. It runs on the pair radio's row under the host's own TXT mode,
  advertising only `v`, `mode` and the radio's per-posture `sid`, and rotates its whole posture (Bonjour
  name, TLS identity, `sid`, an in-memory X25519 key and nonce, and a fresh Nearby Interaction session
  per link) at every start and at least every 900 s. After two ephemeral hellos every message is
  ChaChaPoly-sealed under the key they agree: the ranging token, then, once this phone measured the
  15 cm dwell, the name and companion look, then the answer, and only once both people said yes the
  long-term keys, signed over the rendezvous transcript (`ProximityTapRendezvousMatch`). Rings show
  within 3 m (`closeness`). The host supplies the profile and both labels
  (`ProximityTapRendezvousProfile`).
- `MeshNetworkManager.admissibleStrangerSigningKeys`: a host may narrow the open join doors to the keys
  it names (its friends and the people a rendezvous matched); every other stranger is refused at the
  channel introduction. `nil`, the default, keeps D-4.3 Option 1's doors.

### Fixed

- The mesh's QUIC responder now sends its channel hello, the one frame carrying its long-term signing
  key, only after accepting the dialer's hello. A stranger the doors refuse, or a probe dialing to
  collect keys, is refused having been sent nothing. Accepted peers see the same frames in the same
  order as before.

## 0.1.1 — 2026-10-17

Tag `0.1.1`, commit `e09affe4` (the merge of proximitykit#6). A fix release: no public API, wire
format, on-disk format or frozen token is changed or removed, and every 0.1.0 API is kept, so z moves.
It writes no format, and no version of one, that `Fixtures/0.1.0/` does not hold, so it adds no
fixture folder.

### Fixed

- Every radio's listener now takes every inbound connection for as long as it lives. Each was
  built with a finite new-connection limit (the mesh 8, the recipe radio 3, presence 4), which
  Network.framework spends one per connection created and never refunds, so each went deaf after
  that many inbound connections since its listener was last built (refused, failed and twin
  connections included) until a start, resume, republish or epoch boundary: the mesh after eight
  inbound connections, the recipe radio after three and presence after four. The radios' own pending
  caps and identification deadlines bound an inbound flood instead (`ProximityRadioListenerTests`).
- Presence drops a pending inbound connection that delivers no dial hello within 5 s, at the next
  arrival (no timer). A connection that never opened a stream used to keep its place until the
  radio stopped, because QUIC's idle timeout fails such a connection without ending it; four of
  them refused every friend's dial for the rest of the session.
- The pair radio no longer refuses a dialer's hello because another inbound connection is pending
  without one. Only a pending connection whose dial hello has been read counts as connecting
  (`hasConnectingPeers(besides:)`, which the session's inbound gate asks), and one exists only inside
  its own ruling. Before, a dialer's own silent second connection (likeliest a dual-stack race on a
  cold start), or any device that opened a connection and stayed silent, refused every hello for as
  long as it held its place: until the radio stopped, for one that never opened a stream, or up to
  QUIC's 90 s idle timeout, for one that did. The two-device cap holds, at the radio's one-tunnel
  floor and the owner's held connection. The narrower window changes the session's two other reads
  of it too: such a connection no longer fails the user's own sends as `.connectingToAnother`; and a
  browser or listener failure at runtime now stands the radio down to retry, where such a connection
  kept it from standing down for as long as it stayed pending, and so also cancels an inbound dial
  whose hello is still being read at that moment (accepted: that dialer's share fails and can be
  retried).
- The pair radio drops a pending inbound connection that delivers no readable hello within 5 s, at
  the next arrival or the next ruling on another connection, whether or not that ruling read a hello;
  a connection whose own ruling has begun is ruled on however long its read took. The radio still owns
  no timer.

### Added

- `ProximityPairSession.inspector` (read-only, weak) and
  `ProximityPairSession.init(host:profile:inspector:)`: every pairing's coordinator reports to the
  recorder its host binds.
- Audit: `recipe.quic.helloRefused` gains `reason` (`unreadable`, `unresolved`, `ownerRefused`,
  `keptEstablished`, `tunnelHeld`) and `pending`; new `recipe.quic.pendingBooked` (`connection`,
  `pending`) and `recipe.quic.pendingEnded` (`connection`; `reason`: `admitted`, `refused`,
  `connectionEnded`, `helloDeadline`, `stopped`; `stage`: `awaitingStream`, `readingHello`,
  `helloDelivered`; `pending`); `recipe.quic.connected` gains `interface` (`wifi`, `wiredEthernet`,
  `loopback`, `cellular`, `other`, `unknown`).

### Tests, scripts and documentation

- The package's tests hold every cell of the Fernlet repository's tests that read ProximityKit's
  sources (plan step A1.3's batch D): the routed, mesh, session, continuation, photo-review, pair,
  presence, identity, golden, wipe, audit-bridge, transport and localization source walls, each over
  this repository's tree at its floor.
- The no-tracking scan holds `Sources/` to four rules the Fernlet repository's whole-tree privacy
  scans held this code to: no URL scheme on a line of code, no web view or in-app browser, no
  pasteboard, and no defaults or iCloud key-value store. A P9 honesty cell holds the recipe radio's
  `.remove` stand-in in existence.
- Versioning (plan step A2's groundwork): this file, the README's "Versioning" section, and
  `CrossVersionFixtureTests` over `Fixtures/0.1.0/`: 58 files of 0.1.0's wire and on-disk bytes, each
  SHA-256 pinned, decoded, verified and opened with today's code, the verification ceremony's QR,
  challenge, response and two signed transcripts among them, and the generator that wrote them,
  `Scripts/cross-version-fixtures/generate-0.1.0.swift.txt`. The manifest declares the folder as the
  test target's one resource (`.copy("Fixtures")`), which `Scripts/manifest-scan.py` holds whatever
  qualifies or spaces another rule, CODEOWNERS owns the folder and the suite, and `.gitattributes`
  keeps git from converting the fixtures' line endings.
- The hygiene rule I9 hosts the keychain suites of the Fernlet repository's tests as they are
  written: a suite admits `.serialized`, a display name and a literal or `.allCases` argument
  collection; a fixture enum whose every member that reaches the keychain reads the in-memory
  keychain's installer first is a kind of its own; and a file may be listed under more than one kind.
  The test support gains a participant-less `IdentityService(keychainService:)` binding and
  `PackageSwitchableInstallBinding`, an install binding a cell can switch, held to the answers of
  Fernlet's adapter case for case.
- The package's tests hold the 17 suites of the Fernlet repository's tests that reach the keychain
  and open no store (plan step A1's batch B, 157 tests), under their Fernlet names: the routed
  chunker, manifest signing, recipient key wrap, drain answer and heart target, the membership record
  verifier, key-agreement verification, a joiner's ledger adoption, the dial policy through a live
  manager, the partition's branch view, the removal quorum's arithmetic, expiry, partition table and
  signatures, an evicted slot releasing its transport link, and `IdentityServiceTests`.
- The hygiene rule I9 holds the store suites of the Fernlet repository's tests as they are written: in
  a file it lists, a line that names a mesh store is held as a keychain line, and the file's rows
  state where its stores' scopes come from; `.production(` stays refused in every file. Only `private`
  hides a member from the rule, an argument collection may not name a static member its file
  declares unless it is a literal constant, and the readers follow a declaration past a line ending
  in `=`. `PackageSwitchableInstallBinding` gains the scripted override, an answer a cell changes
  partway through the work it wraps, and `PackageTestHost` can be built over it.
- The package's tests hold batch C's 22 suites of the Fernlet repository's tests that reach the
  keychain and open a store (plan step A1, 184 tests; others that do both, such as
  `MeshSessionLifecycleManagerTests`, stay in Fernlet's tests), under their Fernlet names: the routed
  store's load, durability and error vocabulary, the inventory builder, every cap at every door it
  guards, the parked-set drop rule and the sweeps, custody's parity with the reassembler, the
  persisted delivery map and the evidence behind each custodied rung, the custody and recipient
  receipts' signing and doors, the routed inventory's signing and door, the hand-off's batch doors,
  the session store's round trip and durability, the session's restore mapping, and the removal frame
  and rotation through a live manager.
- `CrossVersionFixtureTests` drives today's verification ceremony against tag 0.1.0's:
  `ProximityVerifyQR.makeURL` writes the QR a 0.1.0 scanner reads, and `CoachVerificationCeremony`,
  as the scanner and as the displayer, interoperates with 0.1.0's response transcript, its layout read
  from the fixture; each of the ceremony's JSON payloads holds every key and value 0.1.0 wrote, a
  fresh nonce or signature aside, so a key added since is an addition, not a failure.
  `MeshRoutedCustodyCommitGuardTests` holds the custody commit's answer to a partly staged item:
  `.incomplete` from the index alone, nothing read, repaired or written.
- Rule I9 follows a keychain line through the members that name it: in a suite file, no static member
  or nested type, at any depth and in an extension too, that holds one or names one that does is
  reachable from another type unless it is `private` or nested in a `private` type; in every listed
  file but the installer's, no static stored property reaches the keychain or holds a storage scope,
  a test host or a listed fixture's or support type's value, directly or through a typealias; a
  support type holds no keychain line in a nested type; a bare declaration that a member access
  continues is a keychain line; and a fixture member's first statement ends at its first `;`. What it
  does not read is stated beside it: a parameter's default value, a `lazy` or closure-wrapped ready
  marker, and a `@Suite` nested in another type, which the inventory and the test-count floor refuse.

### Consumers

- Fernlet: re-pin to 0.1.1, moving its four pin sites together (`FernletKit/Package.swift`, the app
  project's `exactVersion` and both `Package.resolved`). Its DEBUG feasibility probe
  (`App/Fernlet/Proximity/Feasibility/NetworkMeshFeasibilityProbe.swift`) still sets the finite
  `newConnectionLimit` the radios dropped.
  `RecipeShareOverQUICTests.aSecondDialerArrivingWhileOneIsMidHelloIsRefused` stays green and now
  means "a second connection whose hello has been read refuses"; re-word it, its sibling's message
  and the fake radio's window doc. 0.1.1 changes radio behaviour, so device-check
  it on a second device before it ships: the pair radio, presence hearts past four in one epoch, and
  a long mesh session.

## 0.1.0 — 2026-10-15

Tag `0.1.0`, commit `6648094f`: the first release, and the revision the Fernlet repository consumes
(`exact: "0.1.0"`).

### What it holds

- The library `ProximityKit` (iOS 26, macOS 26, Swift tools 6.2, no package dependencies), moved here
  from the Fernlet repository's `FernletKit/Sources/ProximityKit` with its git history: the device
  identity (Ed25519 and X25519 keys in the keychain, this device only), the signed and sealed identity
  envelope, the QUIC radios over Bonjour (mesh, presence and pair), the session coordinator, the
  friend mesh (membership records, removal quorum, epochs and key rotation, key-agreement
  advertisements, routed delivery with custody and receipts, the sealed session and routed stores),
  the pair session, the presence engine, ranging over NearbyInteraction where a host provides it, and
  the trust and verification ceremonies.
- One seam to its host, `ProximityHost`, and a host-supplied `ProximityNamespace`: every signature,
  seal, key derivation, radio, keychain row and file name is bound to the host's labels, so two apps'
  bytes never validate as each other's.
- Its tests (514 tests in 60 suites at the tag), the walls in `Scripts/`, CI, and the example app
  `Examples/ProximityPing`.

### Fixed since the code left the Fernlet repository

- F1: the pair radio announces every record it browses once more after a resume, changed or not, so
  a peer the pair session forgot at a disconnect only one side saw (a refused hello) is listed again,
  and resolves as a dialer again, without a refresh (`NetworkPairSession`, `ProximityPairSessionTests`).

### Formats and their version markers

Wire (each message's labels, radios and tokens are the host namespace's):

| Format | Marker or version | Notes |
|---|---|---|
| `ProximityIdentityEnvelope` (JSON) | `schemaVersion` 2, minted; 1, verified only | v2 is signed over the binary canonical bytes, v1 over the legacy sorted-key JSON, under the namespace's verify-only legacy label, when it accepts legacy peers |
| Sealed payload (an envelope's `.sealedTo`, a sealed introduction) | `FPT2` prefix | ephemeral X25519, HKDF-SHA256, ChaCha20-Poly1305; the unmarked pre-Phase 4 format is refused by name |
| wire2 framing inside a sealed payload | tag `0x01` deflate, `0x02` raw | padded to 256, 512, 1024, 2048, 4096 bytes, then whole 4096s; used when the peer advertises the host's `wire2` capability |
| `SealedIntroductionEnvelope` (JSON) | its one key, `sealedIntroduction` | carries only ciphertext; the signed envelope is inside |
| `ProximityPrekeyBundle` (JSON) | keys and values, in no fixed order | `signedPrekey` optional and additive |
| Group-key wrap | `FGK2` prefix, 96 bytes | the unmarked 92-byte layout is refused by name |
| Mesh metadata seal | `FMGM2` prefix | read only; 0.1.0 writes none, so no fixture |
| Mesh frames on a QUIC stream (`NetworkMeshWire`) | 4-byte big-endian length | at most 16 MiB; handshake frames at most 4096 bytes |
| Mesh channel introduction (hello, signed introduction) | `protocolVersion` 1 | signed over the transcript bound to the TLS exporter's channel binding |
| Mesh payloads (`MeshPayloads.swift`): state change, admission request and grant, admission token, removal proposal and second, vouch list, key rotation, key ack, rotation sync, coordinator beacon | admission token canonical v2; the legacy JSON signature verified | JSON |
| Membership frames: admission, departure, removal, termination, inventory digest, epoch heads, signed removal proposal and vote, key-agreement advertisements | each signed under its own `…V1` label | JSON; epoch references are canonical strings with a derived epoch id |
| Routed frames: manifest, chunk, custody receipt, recipient receipt, inventory, drain answer | each signed under its own `…V1` label | JSON; content-key wraps per destination |
| Routed item seal | `FMRI1` prefix | AES-GCM under the content key |
| Pair dial hello, presence dial hello (JSON) | `v` = `1` | |
| TXT records: pair, presence, mesh link | `v` = `1` for pair and presence | the mesh link's `fp` is withheld |
| Framed labels | raw prefix, 8-byte big-endian length prefix, or none (verify-only) | per label role |
| Verification QR (`<host scheme>://verify?d=`, the base64url JSON of `ProximityVerifyQR.Payload`) | `version` 1 | Ed25519 over a fixed-width transcript: the namespace's QR label, the version byte, both public keys, the big-endian timestamp and the 16-byte nonce |
| Verification challenge and response (JSON, sealed) | none | the response signs the namespace's response label, the scanner's key-agreement key, the challenge nonce and the QR nonce, every field fixed-length |
| The session coordinator's introduction and heartbeat payloads (JSON inside its signed envelopes) | additive optional keys | private types only a running session writes and reads, so no fixture |

On disk:

| Format | Marker or version | Notes |
|---|---|---|
| Column seal (both mesh stores' files) | `0x03` (V3) | ChaCha20-Poly1305 under an HKDF key from the store's seal key, bound to the host's install binding; `0x02` (V2) and unprefixed blobs are refused as retired |
| `MeshSessionContext` | `schemaVersion` 3 | the namespace's session file, V3-sealed |
| `MeshRoutedIndex` and its chunk files | index `schemaVersion` 2 | the namespace's index file and chunk folder, each V3-sealed |
| `ProtectedSidecar` | none | the value's JSON, sealed by the host's seal when it supplies one |
| Keychain rows (identity keys, the two seal keys) | none | raw 32-byte keys under the namespace's services and accounts, after first unlock, this device only, never synchronized |
