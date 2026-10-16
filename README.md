# ProximityKit

A Swift package for in-person connections between Apple devices: discovery over Bonjour, QUIC over
peer-to-peer Wi-Fi, device identity, pairing and sealed payloads. No server and no account.

I built it for [Fernlet](https://github.com/bowman-mw/fernlet), and it lives here so other apps can
use it too.

## What it is

ProximityKit moves data only over local radios, between devices that are physically together. Each
device has its own Ed25519 and X25519 key pairs. Every transfer travels in a signed envelope that is
checked (signature, expiry, recipient, replay, and sealing for sensitive payloads) before any handler
sees it. On top of that it has:

- a friend mesh, with membership, epoch keys and routed delivery, whose features the host app plugs in;
- a one-to-one pair session, for sending something to one person in the room;
- a presence radio, which advertises under an unlinkable name that changes every epoch;
- distance over NearbyInteraction (UWB) where the host provides it.

The package has no dependencies. Its one seam back to the app is the `ProximityHost` protocol. The
host supplies what only an app can decide: its protocol namespace (the labels every signature, seal and
key derivation is bound to, so two apps' bytes can never validate as each other's), its keychain
services and install binding, the device identity, the trust policy, the ranging provider, the routed
types its features carry, and where its files live. ProximityKit computes no directory and reads no
device name of its own. The DocC catalog, `Sources/ProximityKit/Documentation.docc`, describes every
part.

It needs Swift tools 6.2 (Xcode 26 or newer) and builds for iOS 26 and macOS 26.

## Build and test

```sh
swift build
swift test
```

The tests build in Debug only. ProximityKit's keychain test door, the slot its tests fill with an
in-memory keychain, exists only under `#if DEBUG`, so `swift test -c release` does not compile.
`swift build -c release` builds the library alone and works. With Xcode, the scheme is
`ProximityKit`, on a Mac (`-destination 'platform=macOS'`) or on an iOS simulator.

The test target is unhosted: no app and no keychain entitlement. Its support folder,
`Tests/ProximityKitTests/TestSupport`, installs an in-memory keychain store and an audit sink, and gives
the tests a namespace of their own, `.packageTest`, a host built from the public API alone, and an
install binding a test can switch for the work it wraps.
`Tests/ProximityKitTests.tsv` lists every suite with its file and its number of tests.

## Versioning

ProximityKit uses semantic versioning, and while its version is 0.y it reads the rule this way:

- **y** moves for a break. After 1.0 that is the major version.
- **z** moves for everything else: additions and fixes. After 1.0 those are the minor and patch
  versions.

A break is any change a host or another device running a released version would notice:

- the public API: a type, member or parameter removed or renamed, a signature, a default or a
  documented behavior changed, or a new requirement a host must state;
- a wire format: any byte a released version writes, or any byte it accepted and now would not, for
  an envelope, a frame, a payload, a TXT record, a seal, a signature's canonical bytes or a label's
  framing;
- an on-disk format: a sealed store's schema, marker or seal, a sidecar's encoding, or a keychain
  row's service, account, accessibility class or encoding;
- a frozen token: a payload type, record kind, routed type, capability, audit or TXT key, which a host
  supplies or matches by its exact spelling.

A new format goes in beside the old one, and the old one keeps decoding, so a release never strands a
device still running the last one. That makes breaks rare: a new optional JSON key that an older
decoder ignores, or a new schema a newer reader accepts beside the old, is an addition. Retiring the
old reader is the break.

A consumer pins an exact version, `.package(url: "https://github.com/bowman-mw/proximitykit", exact:
"0.1.0")`, as the Fernlet repository does, and moves to a new one deliberately, reading its entry in
[CHANGELOG.md](CHANGELOG.md). SwiftPM's `from: "0.1.0"` means anything below 1.0.0, so it would take
0.2.0, a break, on the next resolve without a word.

Every tag that moves a format commits its wire and on-disk bytes under
`Tests/ProximityKitTests/Fixtures/<tag>/`, generated once from that tag's code and never regenerated,
each file's SHA-256 pinned in `CrossVersionFixtureTests`; a tag that moves none adds no folder. Its
generator is committed as a file no target compiles,
`Scripts/cross-version-fixtures/generate-<tag>.swift.txt` (0.1.0's is `generate-0.1.0.swift.txt`),
whose header says how to run it in a tree holding that tag's sources. The suite's cells decode every
tag's fixtures with the current code: they check the fields, the signatures and seals under the keys
the tag stored, the deterministic encodings re-encoded byte for byte, the verification ceremony's JSON
payloads re-encoded to the same JSON object, and the retired formats still refused; other JSON is held
in the read direction only, today's decoders on the tag's bytes. So a break fails in this repository's
CI before a tag exists, rather than first in a host's update to the tag (tags never move). A later
tag's folder sits beside the older ones, and the older ones keep decoding. The CHANGELOG's table for
each tag names its formats, and marks those with no fixture.

## Example app

`Examples/ProximityPing` is a small app for iOS and macOS that uses ProximityKit the way any app
would: through its public API alone, under a namespace of its own. Its labels begin
`proximityping.`, its pair radio is `_proxping-pair._udp`, and its keychain rows sit under
`org.example.proximityping`. It runs one pair session. Two copies find each other, connect over
QUIC, verify each other's signing keys under that namespace, and trade a sealed, signed ping and
pong. It is a host to read and copy from: it trusts nobody ahead of time, blocks nobody, has no
UWB (`NoopRangingProvider`, so every pairing commits without ranging) and runs no mesh.

Its one screen shows:

- the namespace: the pair radio's service type and ALPN, whether the namespace is sound, and how
  many labels it declares;
- this device: the name it advertises (a generic word and four random hex digits, never the
  device's own name), its signing-key fingerprint, whether the radio is listening, the session's
  status and the last error;
- the devices nearby, each with its fingerprint once verified, and a Ping button;
- the pings: how many were sent, came back as pongs, and were answered for the other device; the
  round trip (last, best and mean); payload bytes out and in; the pairing's state, the peer's
  advertised capabilities and the last send's outcome;
- a log of the last 300 lines: every event the pair session reports, every audit line ProximityKit
  logs, and every session audit its trust policy receives.

The numbers have limits. The app times a round trip itself, from the tap to the pong, so the first
ping also counts discovery, the QUIC handshake and the identity exchange. The byte counts are
payloads before sealing, not bytes on the wire. The log's `recipe.quic.connected` line names the
kind of interface the connection runs over (`interface=wifi`, `loopback` and so on). The
heartbeat's own round trip and each envelope's encoded size reach a host that binds a
`ProximityPairSession.inspector` (`init(host:profile:inspector:)`), which every pairing's coordinator
reports to; this app binds none yet, so its screen does not show them. A candidate for a later
release, an addition to the API: public spelling helpers for `ProximityNamespace.MeshMessages`, so
that a host that runs only the pair session can declare the thirty mesh tokens its family still needs
in a few lines.

To run it, open `Examples/ProximityPing/ProximityPing.xcodeproj` with Xcode 26 or newer. It uses
this package from the repository (`../..`), so nothing is downloaded. From the command line:

```sh
xcodebuild build -project Examples/ProximityPing/ProximityPing.xcodeproj -scheme ProximityPing \
  -destination 'generic/platform=iOS Simulator'
```

- Two simulators on one Mac reach each other over the Mac's network. Run the app on two booted iOS
  simulators, wait for each to list the other under Nearby, and tap Ping beside it. The first ping
  dials, verifies both keys and sends; the other copy answers with a pong.
- Two devices need your own team and a bundle identifier of your own in place of
  `org.example.ProximityPing`. Allow local-network access when asked, and keep Wi-Fi on.
- A Mac needs the same, and a provisioning profile: automatic signing with your team registers an
  App ID and makes one. ProximityKit's keychain queries use the data-protection keychain, which on
  macOS needs entitlements a profile authorizes (Apple's TN3137). Signed to run locally, as CI
  builds it, the Mac app builds and launches, but its identity cannot be stored: provisioning fails
  with `errSecMissingEntitlement` (-34018), the screen shows `keychainWriteFailed`, and the app
  does not start its radio.

The package's tests hold the example's namespace apart (`ExampleNamespaceTests`, on every test
lane). It is sound, shares no label, radio value or keychain row with the tests' own namespace, and
nothing signed under either verifies under the other. The suite compiles a copy of the example's
namespace file, `Tests/ProximityKitTests/TestSupport/PingNamespace.swift`, because a test target
cannot import an app, and holds the copy equal to the original byte for byte: edit the example's file
and copy it over in the same commit.

## Walls and CI

The workflow is `.github/workflows/ci.yml`. It runs on every pull request into `main` and every
push to `main`. It picks the newest Xcode 26 or later on the runner and stops if Swift is older
than 6.2. Then it runs seven walls and the first half of a test-count floor. Each is a Python
script in `Scripts/` that uses only the standard library. You can run one locally with
`python3 Scripts/<name>.py`. It exits with an error when it finds a violation.

- `power-of-10-scan.py` checks the Power of 10 rules that a line scanner can decide. That means no
  `while true` (in the tests too), no function longer than 60 lines of code, no force unwraps or
  traps, no mutable globals, no `try?` that drops an error, and only simple `#if` conditions.
  Unsafe pointers are allowed only at the two seams in `power-of-10-allowlist.json`, and each entry
  says why its seam is safe. Functions average at least one `guard` or assertion each. The example
  app is held to the same rules, but stays out of that average, which is the library's.
- `doc-coverage-scan.py` checks that every struct, class, protocol, enum and actor in `Sources/`
  and in the example app has a `///` doc comment.
- `no-tracking-scan.py` checks that no file imports a tracking, analytics, advertising or
  attribution SDK. It also checks that nothing in `Sources/` or the example app uses `URLSession`
  or any other HTTP client, that the package has no dependencies, and that the example's project
  depends on nothing but this package. And it holds the package's own code in `Sources/` to four
  rules that the Fernlet repository's whole-tree privacy scans held it to while it lived there:
  no URL scheme (`scheme://`) written on a line of code, no pasteboard, no web view or in-app
  browser, and no `UserDefaults`, `@AppStorage` or iCloud key-value store, because the host app
  owns persistence. Comments may name any of them. None has an exception: one would be a permit
  row in the script, with the reason it is safe, argued in review.
- `local-link-scan.py` checks that the local network API appears only in the three radio files in
  `Sources/ProximityKit/Transport/`, and never in the example app, which reaches the radios only
  through the package.
- `manifest-scan.py` checks that `Package.swift` has no unsafe flags and no warnings setting, that
  its one resource is the test target's fixture folder, copied whole (`.copy("Fixtures")`), and that
  it exists beside the sources.
- `codeowners-scan.py` checks that every rule in `.github/CODEOWNERS` names a path that exists,
  because GitHub never reports a rule that matches nothing, and that the walls, the manifest, the
  label registry and the inventory of the tests keep their rules.
- `ci-scan.py` checks the workflow itself: every build and test command still treats warnings as
  errors, the Release build, every test run and the example app's two builds are still there, and
  the test-count floor still reads each test run.
- `test-count-floor.py declared` checks the inventory of the package's tests,
  `Tests/ProximityKitTests.tsv`, against the floor in the workflow: at least as many tests as the
  inventory declares, and exactly as many suites. A test inside the package can count the tests it
  declares, but only a check outside the run can see that they ran.

The walls are ports of the checks that guard this code in the Fernlet repository, or counterparts
of them. The no-tracking scan's four `Sources/` rules carry checks that guarded this code there
until the Fernlet repository came to depend on this package's tag, when its scans stopped reading
this code. Then CI builds and tests the package, and every warning fails the build. The warnings
setting lives on the build commands, never in `Package.swift`, as in the Fernlet repository. CI:

- builds the package with `swift build`, and the library alone in Release with
  `swift build -c release`, because the tests only build in Debug;
- runs the tests on macOS twice, once with `swift test` and once with `xcodebuild test`;
- builds the package for the iOS Simulator, and runs the tests on an iPhone 17 simulator;
- builds the example app for macOS and for the iOS Simulator, and never runs it, because a
  connection needs two devices;
- after each test run, checks what ran with `test-count-floor.py`. The summary line of
  `swift test` must report at least the floor's number of tests, in exactly its number of suites.
  Each `xcodebuild test` result bundle must hold at least the floor's number of tests, none failed
  or skipped, run by every suite in the inventory and by no other.

Other walls are suites in the package's own tests, so they run on every test lane: the namespace
wall, the platform wall (which also keeps CloudKit out), the keychain door's wall, the tests' own
hygiene and their tree walls, the source walls over ProximityKit's code (launch hooks read only in
Debug builds, keychain rows that never sync, a purpose named beside every raw cryptographic call, and
the one escape hatch counted), the memory-lifecycle wall, the example app's namespace held apart, and
the cross-version fixtures (see "Versioning").
The source walls copied from the Fernlet repository's tests, which read ProximityKit's code there
before it moved, run on every test lane too.
`.github/CODEOWNERS` puts the package's own walls, the files they read through, the label registry,
the example's namespace and its copy, the keychain funnel and the byte formats under the owner's
review, as are the fixtures each tag wrote and the suite that pins and decodes them, and of the
source walls copied from the Fernlet repository's tests the five whose originals that repository's
CODEOWNERS owns; the other copies are not under it.

## History

The code moved here from the Fernlet repository,
[bowman-mw/fernlet](https://github.com/bowman-mw/fernlet), with its git history, from the commit that
made ProximityKit a package of its own (2026-06-27) to the last one before it moved. Its paths were
re-rooted: `FernletKit/Sources/ProximityKit` there is `Sources/ProximityKit` here,
`FernletKit/Tests/ProximityKitTests` is `Tests/ProximityKitTests`, and
`FernletKit/Tests/ProximityKitTests.tsv` is `Tests/ProximityKitTests.tsv`. The merge commit that
imported it names the Fernlet commit it came from.

The commits that came in with that merge were authored in bowman-mw/fernlet, and their messages are
unchanged. The commit hashes those messages cite are that repository's. So are their "plan step"
citations, and the many in the code's comments: they refer to that repository's plan,
`Docs/Plan-FernletCoach-ProximityKit-2026-10-01.md`. The code's history from before it became a
package stays in that repository.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
