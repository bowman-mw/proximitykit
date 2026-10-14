# ProximityKit

A Swift package for in-person connections between Apple devices: discovery over Bonjour, QUIC over
peer-to-peer Wi-Fi, device identity, pairing and sealed payloads. No server and no account.

I built it for [Fernlet](https://github.com/bowman-mw/fernlet) and I am moving it here so other apps
can use it too.

## Status

Empty for now. The code still lives in the Fernlet repository under `FernletKit/Sources/ProximityKit`.
It moves here once it no longer depends on anything Fernlet-specific. There is nothing to build yet.

## Scaffolding

I set up the CI and the code walls before the code arrives, so they check it as soon as it lands.

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
  that it exists once the sources do.
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

The walls are ports of the checks that guard this code in the Fernlet repository today, or
counterparts of them. The code will arrive later with its git history from the Fernlet
repository. Until then there is no `Package.swift`, and CI runs the walls only, holding the checks
that need the code. Once the package is here, CI also builds and tests it, and every warning fails
the build. The warnings setting lives on the build commands, never in `Package.swift`, as in the
Fernlet repository. CI then:

- builds the package with `swift build`, and the library alone in Release with
  `swift build -c release`, because the tests only build in Debug;
- runs the tests on macOS twice, once with `swift test` and once with `xcodebuild test`;
- builds the package for the iOS Simulator, and runs the tests on an iPhone 17 simulator;
- after each test run, checks what ran with `test-count-floor.py`. The summary line of
  `swift test` must report at least the floor's number of tests, in exactly its number of suites.
  Each `xcodebuild test` result bundle must hold at least the floor's number of tests, none failed
  or skipped, run by every suite in the inventory and by no other.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
