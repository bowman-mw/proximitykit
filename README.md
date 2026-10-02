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
than 6.2. Then it runs four walls. Each wall is a Python script in `Scripts/` that uses only the
standard library. You can run one locally with `python3 Scripts/<name>.py`. It exits with an error
when it finds a violation.

- `power-of-10-scan.py` checks the Power of 10 rules that a line scanner can decide. That means no
  `while true`, no function longer than 60 lines of code, no force unwraps or traps, no mutable
  globals, no `try?` that drops an error, and only simple `#if` conditions. Unsafe pointers are
  allowed only at the three seams in `power-of-10-allowlist.json`, and each entry says why its seam
  is safe.
- `doc-coverage-scan.py` checks that every struct, class, protocol, enum and actor in `Sources/`
  has a `///` doc comment.
- `no-tracking-scan.py` checks that no file imports a tracking, analytics, advertising or
  attribution SDK. It also checks that nothing in `Sources/` uses `URLSession` or any other HTTP
  client, and that the package has no dependencies.
- `local-link-scan.py` checks that the local network API appears only in the three radio files in
  `Sources/ProximityKit/Transport/`.

The walls are ports of the checks that guard this code in the Fernlet repository today. The code
will arrive later with its git history from the Fernlet repository. Until then there is no
`Package.swift`, and CI runs the walls only. Once the package is here, CI also builds it and runs
its tests on macOS, builds it for the iOS Simulator, and runs the tests on an iPhone 17 simulator.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
