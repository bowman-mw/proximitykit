# Changelog

ProximityKit's releases, newest first. The version rule is the README's "Versioning" section: while
the version is 0.y, y moves for a break (of the public API, a wire format, an on-disk format or a
frozen token) and z for additions and fixes; from 1.0 those become the major and the minor version. A
consumer pins `exact:`. Every tag's wire and on-disk bytes are committed under
`Tests/ProximityKitTests/Fixtures/<tag>/`, generated once from that tag's code, and
`CrossVersionFixtureTests` decodes every tag's folder with today's code, so a break is a test failure
in this repository before it is a release.

## Unreleased

Tests, scripts and documentation only: no public API, wire format, on-disk format or frozen token
changed, so nothing below needs a tag.

- The package's tests hold every cell of the Fernlet repository's tests that read ProximityKit's
  sources (plan step A1.3's batch D): the routed, mesh, session, continuation, photo-review, pair,
  presence, identity, golden, wipe, audit-bridge, transport and localization source walls, each over
  this repository's tree at its floor.
- The no-tracking scan holds `Sources/` to four rules the Fernlet repository's whole-tree privacy
  scans held this code to: no URL scheme on a line of code, no web view or in-app browser, no
  pasteboard, and no defaults or iCloud key-value store. A P9 honesty cell holds the recipe radio's
  `.remove` stand-in in existence.
- Versioning (plan step A2's groundwork): this file, the README's "Versioning" section, and
  `CrossVersionFixtureTests` over `Fixtures/0.1.0/`: 53 files of 0.1.0's wire and on-disk bytes, each
  SHA-256 pinned, decoded, verified and opened with today's code. The manifest declares the folder as
  the test target's one resource (`.copy("Fixtures")`), which `Scripts/manifest-scan.py` holds,
  CODEOWNERS owns the folder and the suite, and `.gitattributes` keeps git from converting the
  fixtures' line endings.
- The hygiene rule I9 hosts the keychain suites of the Fernlet repository's tests as they are
  written: a suite admits `.serialized`, a display name and a literal or `.allCases` argument
  collection; a fixture enum whose every member that reaches the keychain reads the in-memory
  keychain's installer first is a kind of its own; and a file may be listed under more than one kind.
  The test support gains a participant-less `IdentityService(keychainService:)` binding and
  `PackageSwitchableInstallBinding`, an install binding a cell can switch, held to the answers of
  Fernlet's adapter case for case.

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
| Mesh metadata seal | `FMGM2` prefix | read only; 0.1.0 writes none |
| Mesh frames on a QUIC stream (`NetworkMeshWire`) | 4-byte big-endian length | at most 16 MiB; handshake frames at most 4096 bytes |
| Mesh channel introduction (hello, signed introduction) | `protocolVersion` 1 | signed over the transcript bound to the TLS exporter's channel binding |
| Mesh payloads (`MeshPayloads.swift`): state change, admission request and grant, admission token, removal proposal and second, vouch list, key rotation, key ack, rotation sync, coordinator beacon | admission token canonical v2; the legacy JSON signature verified | JSON |
| Membership frames: admission, departure, removal, termination, inventory digest, epoch heads, signed removal proposal and vote, key-agreement advertisements | each signed under its own `…V1` label | JSON; epoch references are canonical strings with a derived epoch id |
| Routed frames: manifest, chunk, custody receipt, recipient receipt, inventory, drain answer | each signed under its own `…V1` label | JSON; content-key wraps per destination |
| Routed item seal | `FMRI1` prefix | AES-GCM under the content key |
| Pair dial hello, presence dial hello (JSON) | `v` = `1` | |
| TXT records: pair, presence, mesh link | `v` = `1` for pair and presence | the mesh link's `fp` is withheld |
| Framed labels | raw prefix, 8-byte big-endian length prefix, or none (verify-only) | per label role |

On disk:

| Format | Marker or version | Notes |
|---|---|---|
| Column seal (both mesh stores' files) | `0x03` (V3) | ChaCha20-Poly1305 under an HKDF key from the store's seal key, bound to the host's install binding; `0x02` (V2) and unprefixed blobs are refused as retired |
| `MeshSessionContext` | `schemaVersion` 3 | the namespace's session file, V3-sealed |
| `MeshRoutedIndex` and its chunk files | index `schemaVersion` 2 | the namespace's index file and chunk folder, each V3-sealed |
| `ProtectedSidecar` | none | the value's JSON, sealed by the host's seal when it supplies one |
| Keychain rows (identity keys, the two seal keys) | none | raw 32-byte keys under the namespace's services and accounts, after first unlock, this device only, never synchronized |
