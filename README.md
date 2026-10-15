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
the tests a namespace of their own, `.packageTest`, and a host built from the public API alone.
`Tests/ProximityKitTests.tsv` lists every suite with its file and its number of tests.

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
  says why its seam is safe. Functions average at least one `guard` or assertion each.
- `doc-coverage-scan.py` checks that every struct, class, protocol, enum and actor in `Sources/`
  has a `///` doc comment.
- `no-tracking-scan.py` checks that no file imports a tracking, analytics, advertising or
  attribution SDK. It also checks that nothing in `Sources/` uses `URLSession` or any other HTTP
  client, and that the package has no dependencies.
- `local-link-scan.py` checks that the local network API appears only in the three radio files in
  `Sources/ProximityKit/Transport/`.
- `manifest-scan.py` checks that `Package.swift` has no unsafe flags and no warnings setting, and
  that it exists beside the sources.
- `codeowners-scan.py` checks that every rule in `.github/CODEOWNERS` names a path that exists,
  because GitHub never reports a rule that matches nothing, and that the walls, the manifest, the
  label registry and the inventory of the tests keep their rules.
- `ci-scan.py` checks the workflow itself: every build and test command still treats warnings as
  errors, the Release build and every test run are still there, and the test-count floor still
  reads each test run.
- `test-count-floor.py declared` checks the inventory of the package's tests,
  `Tests/ProximityKitTests.tsv`, against the floor in the workflow: at least as many tests as the
  inventory declares, and exactly as many suites. A test inside the package can count the tests it
  declares, but only a check outside the run can see that they ran.

The walls are ports of the checks that guard this code in the Fernlet repository, or counterparts
of them. Then CI builds and tests the package, and every warning fails the build. The warnings
setting lives on the build commands, never in `Package.swift`, as in the Fernlet repository. CI:

- builds the package with `swift build`, and the library alone in Release with
  `swift build -c release`, because the tests only build in Debug;
- runs the tests on macOS twice, once with `swift test` and once with `xcodebuild test`;
- builds the package for the iOS Simulator, and runs the tests on an iPhone 17 simulator;
- after each test run, checks what ran with `test-count-floor.py`. The summary line of
  `swift test` must report at least the floor's number of tests, in exactly its number of suites.
  Each `xcodebuild test` result bundle must hold at least the floor's number of tests, none failed
  or skipped, run by every suite in the inventory and by no other.

Other walls are suites in the package's own tests, so they run on every test lane: the namespace
wall, the platform wall (which also keeps CloudKit out), the keychain door's wall, the tests' own
hygiene and their tree walls, the source walls over ProximityKit's code (launch hooks read only in
Debug builds, keychain rows that never sync, a purpose named beside every raw cryptographic call, and
the one escape hatch counted), and the memory-lifecycle wall. `.github/CODEOWNERS` puts every wall,
the files they read through, the label registry, the keychain funnel and the byte formats under the
owner's review.

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
