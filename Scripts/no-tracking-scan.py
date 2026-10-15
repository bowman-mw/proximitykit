#!/usr/bin/env python3
"""No-tracking wall for ProximityKit: no tracking SDK, no HTTP client, no package dependency.

Ported from Tests/FernletTests/NoTrackingBoundaryTests.swift in the Fernlet repository
(https://github.com/bowman-mw/fernlet), which enforced the same wall over this code while it
lived there. The banned lists and the HTTP-client markers are copied from that file unchanged.
Its other checks (hardcoded hosts, the private-tab session, web views, privacy manifests, the
app's Info.plist and Bonjour types) guard an app's own internet traffic and bundle, and a
package that makes no internet request and ships no bundle gives them nothing to read.

Usage: Scripts/no-tracking-scan.py
Prints one line per violation and a summary to stderr; exits 1 on any violation.

The example apps under Examples/ (plan step A1.2) are hosts of the package, built from its public
API alone, and a reader copies from them, so they are held like the package's own code: NT-SDK,
NT-SYMBOL and NT-HTTP read their Swift files, NT-SYMBOL their Info.plist, and NT-PACKAGE their
Xcode projects.

Checks:
    NT-SDK       No Swift file under Sources/, Tests/ or Examples/ imports a tracking, analytics,
                 advertising, attribution or crash-telemetry SDK (BANNED_SDK_MODULES), as an
                 `import` declaration or a `canImport(...)` condition. Matched as imports only,
                 because several SDK names are ordinary words ("Adjust servings", "Branch").
                 Test code is included on purpose: an SDK linked "only for tests" is still a
                 dependency, and one a contributor can promote later.
    NT-SYMBOL    No Swift or plist-family file under Sources/, Tests/ or Examples/ names a tracking
                 identifier (BANNED_TRACKING_SYMBOLS). These have one meaning each, so they are
                 matched at identifier boundaries anywhere in the file, comments included.
    NT-HTTP      No Swift file under Sources/ or Examples/ names an HTTP-client API or a
                 process-wide session configuration in code (HTTP_CLIENT_MARKERS,
                 FORBIDDEN_SESSION_CONFIGURATIONS). ProximityKit makes no internet request, and
                 neither does an example of it, so this family's permit set is empty and URLSession
                 is banned outright. Comment-only lines are skipped, so prose that explains the ban
                 passes; a trailing comment does not hide a call.
    NT-PACKAGE   Package.swift, when present, declares no package dependency. The allowlist is
                 exact and empty, so any `.package(` call in code fails, whichever kind it is
                 (url, path or registry id). A banned SDK name or tracking symbol anywhere in the
                 manifest fails too. An example's Xcode project (a .pbxproj under Examples/)
                 declares no remote package (`XCRemoteSwiftPackageReference`), and its one local
                 package is this one (`relativePath = ../..;`).
    NT-RESOLVED  Package.resolved, when present, pins no package.

The import matcher reads more than the one in Fernlet's S3BoundaryTests.importedModules(in:),
and only ever more: Swift 6 access-level imports (`internal import X`), scoped imports
(`import struct X.Y`) and `;`-separated imports are read too.

Before the import: the code came with its git history from the Fernlet repository. Each root has
its own floor, as each root does in Fernlet's scan. Once Sources/ProximityKit exists, a scan that
reads zero Swift files under Sources/ fails instead of passing over nothing, and once
Tests/ProximityKitTests exists, so does one that reads zero under Tests/: NT-SDK and NT-SYMBOL read
the tests, and an emptied test folder must not pass them vacuously. A tree without them, as this
repository's was until then, passes empty. Examples/ has a floor of its own on the same terms: once
Examples/ProximityPing exists, a scan that reads zero Swift files under Examples/ fails.
"""
import json
import os
import re
import sys

SOURCE_ROOT = "Sources"
TEST_ROOT = "Tests"
EXAMPLE_ROOT = "Examples"   # the example apps: hosts of the package, held like its own code
EXAMPLE_APP_ROOT = os.path.join("Examples", "ProximityPing")   # the Examples/ floor starts once this exists
IMPORT_ROOT = os.path.join("Sources", "ProximityKit")   # the Sources/ floor starts once this exists
TEST_IMPORT_ROOT = os.path.join("Tests", "ProximityKitTests")   # the Tests/ floor starts once this exists
PLIST_FAMILY = (".plist", ".entitlements", ".xcprivacy")

# Module names that may never be imported, by any file. Matched ONLY as an `import` declaration or a
# `canImport(...)` condition, never as free text. Apple's two lead the list because they are the
# only supported way to read the IDFA or ask for tracking permission: without them, App-Store-legal
# cross-app tracking is not merely forbidden here, it cannot be built.
BANNED_SDK_MODULES = (
    # Apple's advertising/tracking frameworks: the IDFA and the ATT prompt.
    "AdSupport", "AppTrackingTransparency",
    # Google / Firebase.
    "Firebase", "FirebaseAnalytics", "FirebaseCore", "FirebaseCrashlytics", "FirebaseMessaging",
    "GoogleAnalytics", "GoogleMobileAds", "Crashlytics",
    # Product analytics.
    "Amplitude", "AmplitudeSwift", "Mixpanel", "Segment", "Analytics", "PostHog", "Flurry",
    "FlurryAnalytics", "Countly", "MatomoTracker", "TelemetryDeck", "TelemetryClient",
    # Attribution / install tracking.
    "AppsFlyerLib", "Adjust", "AdjustSdk", "Branch", "BranchSDK", "Kochava", "KochavaTracker",
    "Singular", "SingularSDK", "Umeng", "UMCommon",
    # Crash / APM telemetry.
    "Sentry", "Bugsnag", "Datadog", "DatadogCore", "DatadogRUM", "DatadogLogs",
    # Marketing automation / push-with-profiles.
    "OneSignal", "OneSignalFramework", "Appboy", "BrazeKit", "Iterable", "IterableSDK",
)

# Symbols that may never appear anywhere, comments included. `identifierForVendor` is here although
# it is no advertising identifier: it is the usual substitute device ID once the IDFA is gone.
BANNED_TRACKING_SYMBOLS = (
    "ASIdentifierManager",
    "advertisingIdentifier",
    "isAdvertisingTrackingEnabled",
    "ATTrackingManager",
    "requestTrackingAuthorization",
    "trackingAuthorizationStatus",
    "NSUserTrackingUsageDescription",
    "identifierForVendor",
    "SKAdNetwork",
    "SKAdNetworkItems",
    "NSAdvertisingAttributionReportEndpoint",
)

# Raw HTTP/socket client APIs. NWConnection and NWBrowser are the legacy Network.framework
# spellings; they stay in this family on purpose, banned everywhere, so the radio files'
# local-link permission (Scripts/local-link-scan.py) can never cover them.
HTTP_CLIENT_MARKERS = (
    "URLSession", "URLRequest", "NSURLConnection", "NWConnection", "NWBrowser",
    "CFURLRequest", "WKWebView",
)

# Session configurations that carry process-wide, persistent state (a shared cookie jar, cache and
# credential store). `URLSessionConfiguration.default` does not contain the `URLSession` marker at an
# identifier boundary, so these are matched in their own right.
FORBIDDEN_SESSION_CONFIGURATIONS = (
    "URLSession.shared",
    "URLSessionConfiguration.default",
    "URLSessionConfiguration.background",
)

ACCESS_MODIFIERS = ("public", "package", "internal", "fileprivate", "private", "open")
IMPORT_KINDS = ("typealias", "struct", "class", "enum", "protocol", "let", "var", "func")
CAN_IMPORT_RE = re.compile(r"canImport\( *(\w+)")
PACKAGE_CALL_RE = re.compile(r"\.package\s*\(")


def is_identifier_char(ch):
    return ch == "_" or ch.isalnum()


def names_symbol(text, token):
    """True iff `token` occurs in `text` with no identifier character on either side, so it never
    fires inside a longer identifier (`advertisingIdentifierPolicyDoc`)."""
    start = text.find(token)
    while start != -1:
        end = start + len(token)
        left_clear = start == 0 or not is_identifier_char(text[start - 1])
        right_clear = end >= len(text) or not is_identifier_char(text[end])
        if left_clear and right_clear:
            return True
        start = text.find(token, start + 1)
    return False


def imported_modules(line):
    """The top-level modules an `import` declaration on `line` names. Attributes
    (`@preconcurrency`, `@testable`) and access levels (`internal import`) are skipped, a scoped
    import reports its module (`import struct Foo.Bar` gives Foo), and a commented line imports
    nothing."""
    modules = set()
    for statement in line.split(";"):
        trimmed = statement.split("//", 1)[0].strip()
        tokens = trimmed.split()
        while tokens and (tokens[0].startswith("@") or tokens[0] in ACCESS_MODIFIERS):
            tokens.pop(0)
        if len(tokens) < 2 or tokens[0] != "import":
            continue
        name = tokens[2] if tokens[1] in IMPORT_KINDS and len(tokens) >= 3 else tokens[1]
        modules.add(name.split(".")[0])
    return modules


def banned_sdks(line):
    """Banned SDK modules that `line` imports or names in a `canImport(...)` condition. As in
    Fernlet's conditionallyImportedModules(in:), `canImport(` counts wherever it appears, comments
    included: it is how an optional tracking dependency would be introduced "safely"."""
    modules = imported_modules(line) | set(CAN_IMPORT_RE.findall(line))
    return [m for m in BANNED_SDK_MODULES if m in modules]


def banned_symbols(line):
    return [s for s in BANNED_TRACKING_SYMBOLS if names_symbol(line, s)]


def is_comment_only(line):
    """Comment-only lines, as Fernlet's NoTrackingBoundaryTests.codeOnly(_:) drops them."""
    return line.strip().startswith(("//", "*", "/*"))


def http_markers(line):
    if is_comment_only(line):
        return []
    return [m for m in HTTP_CLIENT_MARKERS + FORBIDDEN_SESSION_CONFIGURATIONS if names_symbol(line, m)]


def read_lines(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read().split("\n")


def files_under(root, suffixes):
    if not os.path.isdir(root):
        return []
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", ".build")]
        found.extend(os.path.join(dirpath, n) for n in filenames if n.endswith(suffixes))
    return sorted(found)


def resolved_pins(path):
    """The `pins` array of a Package.resolved file in format version 1 (under `object`) or 2 and
    later (top level). Raises ValueError when the file has neither."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        pins = data.get("pins")
        if pins is None and isinstance(data.get("object"), dict):
            pins = data["object"].get("pins")
        if isinstance(pins, list):
            return pins
    raise ValueError("no pins array")


def main():
    repo = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    imported = os.path.isdir(os.path.join(repo, IMPORT_ROOT))
    tests_imported = os.path.isdir(os.path.join(repo, TEST_IMPORT_ROOT))
    example_present = os.path.isdir(os.path.join(repo, EXAMPLE_APP_ROOT))
    findings = []

    def report(check, path, number, detail, text=""):
        rel = os.path.relpath(path, repo)
        where = f"{rel}:{number}" if number else rel
        findings.append(f"{check} {where}: {detail}" + (f": {text.strip()[:140]}" if text else ""))

    source_swift = files_under(os.path.join(repo, SOURCE_ROOT), (".swift",))
    test_swift = files_under(os.path.join(repo, TEST_ROOT), (".swift",))
    example_swift = files_under(os.path.join(repo, EXAMPLE_ROOT), (".swift",))
    plist_family = (files_under(os.path.join(repo, SOURCE_ROOT), PLIST_FAMILY)
                    + files_under(os.path.join(repo, TEST_ROOT), PLIST_FAMILY)
                    + files_under(os.path.join(repo, EXAMPLE_ROOT), PLIST_FAMILY))

    # NT-SDK and NT-SYMBOL: every Swift file, tests and examples included.
    for path in source_swift + test_swift + example_swift:
        for number, line in enumerate(read_lines(path), start=1):
            sdks = banned_sdks(line)
            if sdks:
                report("NT-SDK", path, number, "imports tracking/analytics SDK " + ", ".join(sdks), line)
            symbols = banned_symbols(line)
            if symbols:
                report("NT-SYMBOL", path, number, "names tracking symbol " + ", ".join(symbols), line)
    for path in plist_family:
        for number, line in enumerate(read_lines(path), start=1):
            symbols = banned_symbols(line)
            if symbols:
                report("NT-SYMBOL", path, number, "declares tracking key " + ", ".join(symbols), line)

    # NT-HTTP: shipping code and the examples hold no HTTP client at all.
    for path in source_swift + example_swift:
        for number, line in enumerate(read_lines(path), start=1):
            markers = http_markers(line)
            if markers:
                report("NT-HTTP", path, number,
                       "names " + ", ".join(markers) + " (ProximityKit makes no internet request)", line)

    # NT-PACKAGE: an exact, empty dependency allowlist.
    manifest = os.path.join(repo, "Package.swift")
    if os.path.isfile(manifest):
        lines = read_lines(manifest)
        for number, line in enumerate(lines, start=1):
            if not is_comment_only(line) and PACKAGE_CALL_RE.search(line):
                report("NT-PACKAGE", manifest, number, "declares a package dependency (the allowlist is empty)", line)
        text = "\n".join(lines)
        named = [m for m in BANNED_SDK_MODULES if names_symbol(text, m)]
        if named:
            report("NT-PACKAGE", manifest, 0, "names tracking/analytics SDK product " + ", ".join(named))
        symbols = [s for s in BANNED_TRACKING_SYMBOLS if names_symbol(text, s)]
        if symbols:
            report("NT-PACKAGE", manifest, 0, "names tracking symbol " + ", ".join(symbols))

    # NT-PACKAGE for the examples: an example's Xcode project depends on this package by its local path
    # and on nothing else.
    for path in files_under(os.path.join(repo, EXAMPLE_ROOT), (".pbxproj",)):
        for number, line in enumerate(read_lines(path), start=1):
            if "XCRemoteSwiftPackageReference" in line:
                report("NT-PACKAGE", path, number, "an example declares a remote package dependency", line)
            if line.strip().startswith("relativePath =") and line.strip() != "relativePath = ../..;":
                report("NT-PACKAGE", path, number, "an example's local package is not this package", line)

    # NT-RESOLVED: nothing pinned.
    resolved = os.path.join(repo, "Package.resolved")
    if os.path.isfile(resolved):
        try:
            pins = resolved_pins(resolved)
        except (ValueError, OSError) as error:   # json.JSONDecodeError is a ValueError
            report("NT-RESOLVED", resolved, 0, f"unreadable, so its pins cannot be checked ({error})")
            pins = []
        for pin in pins:
            name = pin.get("identity") or pin.get("package") or "?"
            where = pin.get("location") or pin.get("repositoryURL") or "?"
            report("NT-RESOLVED", resolved, 0, f"pins {name} ({where}); the dependency allowlist is empty")

    vacuous = imported and not source_swift
    vacuous_tests = tests_imported and not test_swift
    vacuous_examples = example_present and not example_swift
    for line in findings:
        print(line)
    print(f"\nSwift files scanned: {len(source_swift)} under {SOURCE_ROOT}/, {len(test_swift)} under "
          f"{TEST_ROOT}/, {len(example_swift)} under {EXAMPLE_ROOT}/; plist-family files: {len(plist_family)}; "
          f"Package.swift "
          f"{'checked' if os.path.isfile(manifest) else 'absent'}; Package.resolved "
          f"{'checked' if os.path.isfile(resolved) else 'absent'}; violations: {len(findings)}",
          file=sys.stderr)
    if vacuous:
        print(f"no Swift files under {SOURCE_ROOT}/ although {IMPORT_ROOT} exists: refusing to pass vacuously",
              file=sys.stderr)
    elif not imported:
        print(f"{IMPORT_ROOT} does not exist yet; the {SOURCE_ROOT}/ file floor waits for it", file=sys.stderr)
    if vacuous_tests:
        print(f"no Swift files under {TEST_ROOT}/ although {TEST_IMPORT_ROOT} exists: refusing to pass vacuously",
              file=sys.stderr)
    elif not tests_imported:
        print(f"{TEST_IMPORT_ROOT} does not exist yet; the {TEST_ROOT}/ file floor waits for it", file=sys.stderr)
    if vacuous_examples:
        print(f"no Swift files under {EXAMPLE_ROOT}/ although {EXAMPLE_APP_ROOT} exists: refusing to pass "
              f"vacuously", file=sys.stderr)
    elif not example_present:
        print(f"{EXAMPLE_APP_ROOT} does not exist; the {EXAMPLE_ROOT}/ file floor waits for it", file=sys.stderr)
    sys.exit(1 if findings or vacuous or vacuous_tests or vacuous_examples else 0)


if __name__ == "__main__":
    main()
