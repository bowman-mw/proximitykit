#!/usr/bin/env python3
"""No-tracking wall for ProximityKit: no tracking SDK, no HTTP client, no package dependency, and in
the package's own code no URL, no web view, no pasteboard and no defaults store.

Ported from Tests/FernletTests/NoTrackingBoundaryTests.swift in the Fernlet repository
(https://github.com/bowman-mw/fernlet), which enforced the same wall over this code while it
lived there. The banned lists and the HTTP-client markers are copied from that file unchanged.
Its other checks (the private-tab session, privacy manifests, the app's Info.plist and Bonjour
types) guard an app's own internet traffic and bundle, and a package that makes no internet
request and ships no bundle gives them nothing to read. Two it skipped at first, hardcoded hosts
and web views, are here since that repository's plan step A1.3 (NT-URL, NT-WEBVIEW), beside two
rules of its other privacy scans (NT-PASTEBOARD, NT-DEFAULTS).

What the Fernlet repository's scans used to cover. Until its plan step A1.3 this code sat under
that repository's FernletKit/Sources, and four whole-tree checks of its tests read it there:
NoTrackingBoundaryTests' exact allowlist of hardcoded network destinations and its web-view and
in-app-browser pin, PasteboardBoundaryTests' PB1 (every general-pasteboard write device-local),
and PersistedSurfaceWipeBoundaryTests (every UserDefaults or @AppStorage surface carries a wipe
disposition). Since A1.3 that repository depends on this package's tag, and those checks read its
own code alone. NT-URL, NT-WEBVIEW, NT-PASTEBOARD and NT-DEFAULTS carry what they held this code
to, over Sources/, each stricter than the check it replaces: a package that names no destination,
renders no web content, hands nothing to a pasteboard and persists only through its host needs
none of what those checks permit an app, so each rule's permit set is empty (SOURCE_PERMITS). A
future need is a permit row with its invariant, argued in review, never a wider matcher. They read
Sources/ alone: the example app is a host, and a host owns its links, its pasteboard, its web
content and its persistence, as Fernlet's own checks hold Fernlet's.

Usage: Scripts/no-tracking-scan.py
Prints one line per violation and a summary to stderr; exits 1 on any violation.

The example apps under Examples/ (plan step A1.2) are hosts of the package, built from its public
API alone, and a reader copies from them, so they are held like the package's own code: NT-SDK,
NT-SYMBOL and NT-HTTP read their Swift files, NT-SYMBOL their Info.plist, and NT-PACKAGE their
Xcode projects. The four Sources/ rules below do not read them (see above).

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
    NT-URL       No Swift file under Sources/ spells a URL scheme separator, `://`, on a line of
                 code: no `fernlet://`, `https://` or other scheme's literal, and no URL assembled
                 around a scheme from elsewhere (`scheme + "://"`). ProximityKit names no
                 destination: the one URL it builds, the verification QR's, takes its scheme from
                 its host's namespace through URLComponents, never from a literal.
    NT-WEBVIEW   No Swift file under Sources/ imports WebKit or SafariServices (an `import` or a
                 `canImport(...)` condition on a line of code) or names a web view, a web data
                 store or an in-app browser (WEB_VIEW_MARKERS) on a line of code. A WKWebView's
                 default store is an on-disk cookie and storage jar, and an in-app Safari view or
                 web authentication session browses against Safari's own; ProximityKit renders no
                 web content, in process or out.
    NT-PASTEBOARD
                 No Swift file under Sources/ names a pasteboard API (PASTEBOARD_MARKERS) on a line
                 of code. A general-pasteboard write not marked device-local is Handoff-synced to
                 every device on the Apple Account, and nothing can read that option back;
                 ProximityKit hands nothing to a pasteboard and reads nothing from one.
    NT-DEFAULTS  No Swift file under Sources/ names a defaults domain, a SwiftUI storage property
                 or the iCloud key-value store (DEFAULTS_MARKERS) on a line of code. The host app
                 owns persistence: ProximityKit keeps its state in sealed files under the folder
                 its host names and in keychain rows behind its host's wipe seams, and a defaults
                 key would be a surface no host's wipe ledger names (the iCloud store also syncs it
                 off the device).
    These four rules skip comment-only lines, so prose that names what the code does not do
    passes; a trailing comment does not hide a line. Their markers are matched where an
    identifier starts, so a family's longer names (`WKWebViewConfiguration`,
    `CFPreferencesSetAppValue`) are read too, while a name that holds one inside it
    (`MyUserDefaultsMirror`) is not. Each rule's matcher is held to its samples on every run
    (MATCHER_SAMPLES), so a matcher that stops matching fails the scan instead of passing every
    file, and a permit row that exempts no line fails as stale.

The import matcher reads more than the one in Fernlet's S3BoundaryTests.importedModules(in:),
and only ever more: Swift 6 access-level imports (`internal import X`), scoped imports
(`import struct X.Y`) and `;`-separated imports are read too.

Before the import: the code came with its git history from the Fernlet repository. Each root has
its own floor, as each root does in Fernlet's scan. Once Sources/ProximityKit exists, a scan that
reads fewer than SOURCE_FILE_FLOOR Swift files under Sources/ fails instead of passing over a tree
that lost a folder (since plan step A1.3; the floor was any file before), and once
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
# The fewest Swift files a scan of Sources/ may read once IMPORT_ROOT exists: about four fifths of the
# 135 the module holds (plan step A1.3), the floor the package tests' walker holds the module to
# (PackageSwiftFiles.sourceFloor). NT-HTTP and the four Sources/ rules are zero-lists over that walk,
# so a walk that lost a folder must fail rather than read as clean.
SOURCE_FILE_FLOOR = 108
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

# NT-URL: a URL scheme separator, with the scheme before it when one is spelled (for the report).
URL_SEPARATOR_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*)?://")

# NT-WEBVIEW: the modules that render web content in process (WebKit) or open an in-app browser
# (SafariServices), read as an import or a `canImport(...)` condition, and the markers that name one.
# WKWebView is in HTTP_CLIENT_MARKERS too, which reads the examples as well; this family reads Sources/.
WEB_VIEW_MODULES = ("WebKit", "SafariServices")
WEB_VIEW_MARKERS = (
    "WKWebView", "WKWebsiteDataStore", "WKProcessPool", "WKHTTPCookieStore", "WebView", "WebPage",
    "SFSafariViewController", "SFAuthenticationSession", "ASWebAuthenticationSession",
)

# NT-PASTEBOARD: UIKit's and AppKit's pasteboards, UIKit's paste control and configuration, and
# SwiftUI's paste button and copy, cut and paste commands.
PASTEBOARD_MARKERS = (
    "UIPasteboard", "NSPasteboard", "UIPasteControl", "UIPasteConfiguration", "PasteButton",
    "onCopyCommand", "onCutCommand", "onPasteCommand", "pasteDestination",
)

# NT-DEFAULTS: a defaults domain by any of its APIs, SwiftUI's two storage properties (each a
# defaults key or a scene's restored state), and the iCloud key-value store.
DEFAULTS_MARKERS = (
    "UserDefaults", "NSUserDefaults", "CFPreferences", "AppStorage", "SceneStorage",
    "NSUbiquitousKeyValueStore",
)

# The Sources/ rules' permit sets, each EMPTY: {rule: {(path from the repository root, the line as
# trimmed): the invariant that makes that one line safe}}. A row exempts its exact line from its rule
# alone; a row whose line is gone fails as stale, and a row with no invariant fails. Adding one is a
# decision argued in review (.github/CODEOWNERS owns this file), never a fix for a red run.
SOURCE_PERMITS = {
    "NT-URL": {},
    "NT-WEBVIEW": {},
    "NT-PASTEBOARD": {},
    "NT-DEFAULTS": {},
}

# Each Sources/ rule's matcher held to its samples on every run: (rule, a line, whether the rule
# reads a hit on it). A matcher edited into missing its family fails here instead of passing every file.
MATCHER_SAMPLES = (
    ("NT-URL", 'let link = URL(string: "fernlet://verify?d=" + payload)', True),
    ("NT-URL", 'let page = "https://\\(host)/index"', True),
    ("NT-URL", 'let base = scheme + "://" + host', True),
    ("NT-URL", "    /// Builds the signed `fernlet://verify?d=…` URL.", False),
    ("NT-URL", "        components.scheme = identity.namespace.family.verifyQR.urlScheme", False),
    ("NT-WEBVIEW", "import WebKit", True),
    ("NT-WEBVIEW", "#if canImport(SafariServices)", True),
    ("NT-WEBVIEW", "let view = WKWebView(frame: .zero, configuration: WKWebViewConfiguration())", True),
    ("NT-WEBVIEW", "let browser = SFSafariViewController(url: url)", True),
    ("NT-WEBVIEW", "let login = ASWebAuthenticationSession(url: url, callbackURLScheme: nil) { _, _ in }", True),
    ("NT-WEBVIEW", "// a web view would keep a WKWebsiteDataStore on disk", False),
    ("NT-PASTEBOARD", "UIPasteboard.general.string = fingerprint", True),
    ("NT-PASTEBOARD", "NSPasteboard.general.setString(fingerprint, forType: .string)", True),
    ("NT-PASTEBOARD", "/// never copied to UIPasteboard", False),
    ("NT-DEFAULTS", 'UserDefaults.standard.set(true, forKey: "seen")', True),
    ("NT-DEFAULTS", '@AppStorage("seen") private var seen = false', True),
    ("NT-DEFAULTS", "let store = NSUbiquitousKeyValueStore.default", True),
    ("NT-DEFAULTS", 'CFPreferencesSetAppValue(key, value, kCFPreferencesCurrentApplication)', True),
    ("NT-DEFAULTS", "// no `UserDefaults` key is added, and no payload gains a field", False),
    ("NT-DEFAULTS", "let count = MyUserDefaultsMirror.count", False),
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


# What each Sources/ rule says when a line breaks it.
SOURCE_RULE_REASONS = {
    "NT-URL": "ProximityKit names no destination; a URL's scheme comes from its host's namespace",
    "NT-WEBVIEW": "ProximityKit renders no web content, in process or out",
    "NT-PASTEBOARD": "ProximityKit hands nothing to a pasteboard, which Handoff can carry to every device "
                     "on the Apple Account, and reads nothing from one",
    "NT-DEFAULTS": "the host app owns persistence; a defaults or iCloud key-value key is a surface no "
                   "host's wipe ledger names",
}


def names_identifier_start(text, token):
    """True iff `token` occurs in `text` where an identifier starts (no identifier character before
    it, whatever follows), so a family's longer names (`WKWebViewConfiguration`) count, and a name
    that holds the token inside it (`MyUserDefaultsMirror`) does not."""
    start = text.find(token)
    while start != -1:
        if start == 0 or not is_identifier_char(text[start - 1]):
            return True
        start = text.find(token, start + 1)
    return False


def source_rule_hits(line):
    """The Sources/ rules `line` breaks, each as (rule, what the line names). A comment-only line
    breaks none; a code line with a trailing comment is read whole."""
    if is_comment_only(line):
        return []
    modules = imported_modules(line) | set(CAN_IMPORT_RE.findall(line))
    named = {
        "NT-URL": [(m.group(1) or "") + "://" for m in URL_SEPARATOR_RE.finditer(line)],
        "NT-WEBVIEW": [m for m in WEB_VIEW_MODULES if m in modules]
                      + [m for m in WEB_VIEW_MARKERS if names_identifier_start(line, m)],
        "NT-PASTEBOARD": [m for m in PASTEBOARD_MARKERS if names_identifier_start(line, m)],
        "NT-DEFAULTS": [m for m in DEFAULTS_MARKERS if names_identifier_start(line, m)],
    }
    return [(rule, found) for rule, found in named.items() if found]


def matcher_problems():
    """Each Sources/ rule's matcher against MATCHER_SAMPLES: a sample it misreads, in either
    direction, or a rule with no sample it must hit."""
    problems = []
    for rule, line, expected in MATCHER_SAMPLES:
        hit = any(found_rule == rule for found_rule, _ in source_rule_hits(line))
        if hit != expected:
            problems.append(f"{rule} matcher: reads {'a hit' if hit else 'nothing'} on its sample "
                            f"`{line.strip()}`, which {'is one' if expected else 'is none'}")
    for rule in SOURCE_PERMITS:
        if not any(sample_rule == rule and expected for sample_rule, _, expected in MATCHER_SAMPLES):
            problems.append(f"{rule} matcher: no sample it must read as a hit, so a blind matcher would pass")
    return problems


def permit_problems(permitted):
    """SOURCE_PERMITS rows that state no invariant, or exempt no line of code (`permitted` holds the
    (rule, path, trimmed line) of every line a row exempted)."""
    problems = []
    for rule, rows in SOURCE_PERMITS.items():
        for (rel, text), invariant in rows.items():
            if not invariant.strip():
                problems.append(f"{rule} permit {rel}: `{text}` states no invariant")
            if (rule, rel, text) not in permitted:
                problems.append(f"{rule} permit {rel}: `{text}` exempts no line of code; delete the stale row")
    return problems


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

    # NT-URL, NT-WEBVIEW, NT-PASTEBOARD and NT-DEFAULTS: the package's own code, Sources/ alone, each
    # matcher held to its samples first, each exemption a permit row that must still exempt a line.
    findings.extend(matcher_problems())
    permitted = set()
    for path in source_swift:
        rel = os.path.relpath(path, repo)
        for number, line in enumerate(read_lines(path), start=1):
            for rule, found in source_rule_hits(line):
                if (rel, line.strip()) in SOURCE_PERMITS[rule]:
                    permitted.add((rule, rel, line.strip()))
                    continue
                report(rule, path, number, "names " + ", ".join(found) + " (" + SOURCE_RULE_REASONS[rule]
                       + "; no permit row names this line)", line)
    findings.extend(permit_problems(permitted))

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

    vacuous = imported and len(source_swift) < SOURCE_FILE_FLOOR
    vacuous_tests = tests_imported and not test_swift
    vacuous_examples = example_present and not example_swift
    for line in findings:
        print(line)
    permit_rows = sum(len(rows) for rows in SOURCE_PERMITS.values())
    print(f"\nSwift files scanned: {len(source_swift)} under {SOURCE_ROOT}/ (floor {SOURCE_FILE_FLOOR}), "
          f"{len(test_swift)} under "
          f"{TEST_ROOT}/, {len(example_swift)} under {EXAMPLE_ROOT}/; plist-family files: {len(plist_family)}; "
          f"Package.swift "
          f"{'checked' if os.path.isfile(manifest) else 'absent'}; Package.resolved "
          f"{'checked' if os.path.isfile(resolved) else 'absent'}; {SOURCE_ROOT}/ rules "
          f"{', '.join(SOURCE_PERMITS)}: {len(MATCHER_SAMPLES)} matcher samples, {permit_rows} permit rows; "
          f"violations: {len(findings)}",
          file=sys.stderr)
    if vacuous:
        print(f"only {len(source_swift)} Swift files under {SOURCE_ROOT}/ although {IMPORT_ROOT} exists, below "
              f"the floor of {SOURCE_FILE_FLOOR}: refusing to pass vacuously", file=sys.stderr)
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
