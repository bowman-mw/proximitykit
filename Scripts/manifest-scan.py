#!/usr/bin/env python3
"""Manifest wall for ProximityKit: Package.swift carries no unsafe flags, no warnings setting, and no
resource but the tests' fixture folder.

Power of 10 rule 10 (warnings are errors) is held on the build commands in
.github/workflows/ci.yml, never in the manifest, the way the Fernlet repository holds it for its
own packages. The warnings half of this scan is ported from
r10PackageManifestDoesNotCarryTheConflictingWarningsFlag() in that repository's
Tests/FernletTests/PowerOfTenBoundaryTests.swift (https://github.com/bowman-mw/fernlet), widened
to every warning-control setting PackageDescription offers. The unsafe-flags half is this
repository's own: the package exists to be a dependency of other packages.

Usage: Scripts/manifest-scan.py
Prints one line per violation and a summary to stderr; exits 1 on any violation.

Checks:
    MF-UNSAFE-FLAGS  No `unsafeFlags` in any setting. PackageDescription documents that unsafe
                     flags make a product ineligible for use by other packages.
    MF-WARNINGS      No warning-control setting (WARNING_SETTINGS) and no warnings compiler flag
                     (WARNING_FLAGS). The Fernlet repository measured `.treatAllWarnings` in its
                     package manifest colliding with the `-suppress-warnings` Xcode gives package
                     targets and failing its whole build. So rule 10 is set on build commands
                     instead: this repository's CI legs, and Fernlet's strict build when it
                     consumes a tag.
    MF-MISSING       Once Sources/ProximityKit exists, Package.swift exists too. Without it CI's
                     build and test steps would skip with a notice, and the job would pass on the
                     walls alone.
    MF-RESOURCES     The manifest's one resource rule is the test target's `.copy("Fixtures")`
                     (ALLOWED_RESOURCE), under the one `resources:` label, both after the
                     `.testTarget(` line, and the folder it names exists. The folder holds the bytes
                     each released tag wrote, which CrossVersionFixtureTests reads through
                     Bundle.module: copied whole, because `.process` flattens a folder and two tags'
                     files of one name would collide, and only in the tests, because a resource in
                     the library would ship inside every host's app. Any other resource rule
                     (`.copy(`, `.process(` or `.embedInCode(`, whatever qualifies it, as in
                     `Resource.process(`, and however it is spaced before its `(`) or `resources:`
                     label is refused, and so is a fixture folder on disk that the manifest does not
                     declare (SwiftPM would warn about its unhandled files and the suite would have no
                     Bundle.module).

Comment-only lines are skipped, so prose that explains the ban passes; a trailing comment does
not hide a setting. The names are matched at identifier boundaries, so a longer identifier that
contains one is not the setting; a resource rule's name is bounded by the `.` before it and the `(`
after it.

Before the import: the code came with its git history from the Fernlet repository. A tree with
neither Package.swift nor Sources/ProximityKit, as this repository's was until then, passes.
"""
import os
import re
import sys

MANIFEST = "Package.swift"
IMPORT_ROOT = os.path.join("Sources", "ProximityKit")   # MF-MISSING starts once this exists

UNSAFE_SETTINGS = ("unsafeFlags",)
# MF-RESOURCES: the one resource rule, the tests' fixture folder, and where it sits.
RESOURCE_RULES = ("copy", "process", "embedInCode")
RESOURCE_CALL = re.compile(r"\.(" + "|".join(RESOURCE_RULES) + r")\s*\(")
ALLOWED_RESOURCE = '.copy("Fixtures")'
TEST_TARGET_CALL = ".testTarget("
FIXTURE_FOLDER = os.path.join("Tests", "ProximityKitTests", "Fixtures")
# PackageDescription's warning-control settings (new in PackageDescription 6.2): Swift settings
# take the first two, C and C++ settings all four.
WARNING_SETTINGS = ("treatAllWarnings", "treatWarning", "enableWarning", "disableWarning")
WARNING_FLAGS = ("-warnings-as-errors", "-suppress-warnings")


def is_identifier_char(ch):
    return ch == "_" or ch.isalnum()


def names_symbol(text, token):
    """True iff `token` occurs in `text` with no identifier character on either side."""
    start = text.find(token)
    while start != -1:
        end = start + len(token)
        left_clear = start == 0 or not is_identifier_char(text[start - 1])
        right_clear = end >= len(text) or not is_identifier_char(text[end])
        if left_clear and right_clear:
            return True
        start = text.find(token, start + 1)
    return False


def is_comment_only(line):
    """Comment-only lines, as the other walls in Scripts/ skip them."""
    return line.strip().startswith(("//", "*", "/*"))


def scan_manifest(lines):
    """Return (check, line number, detail, text) for every banned setting or flag in `lines`."""
    findings = []
    for number, line in enumerate(lines, start=1):
        if is_comment_only(line):
            continue
        for name in UNSAFE_SETTINGS:
            if names_symbol(line, name):
                findings.append(("MF-UNSAFE-FLAGS", number, f"uses `{name}` (PackageDescription: unsafe "
                                 f"flags make a product ineligible for use by other packages)", line))
        for name in WARNING_SETTINGS:
            if names_symbol(line, name):
                findings.append(("MF-WARNINGS", number, f"uses the warnings setting `{name}` (rule 10 is "
                                 f"set on the build commands, never in the manifest)", line))
        for flag in WARNING_FLAGS:
            if flag in line:
                findings.append(("MF-WARNINGS", number, f"names the compiler flag `{flag}` (rule 10 is "
                                 f"set on the build commands, never in the manifest)", line))
    return findings


def resource_calls(text):
    """The resource rules `text` calls: each RESOURCE_RULES name right after a `.`, whatever qualifies
    it (`.process(`, `Resource.process(`), with its `(` next after any blanks (`.process (`)."""
    return [match.group(1) for match in RESOURCE_CALL.finditer(text)]


def scan_resources(lines, fixture_folder_exists):
    """Return (check, line number, detail, text) for MF-RESOURCES over `lines`."""
    findings = []
    test_target = next((number for number, line in enumerate(lines, start=1)
                        if not is_comment_only(line) and TEST_TARGET_CALL in line), None)
    allowed, labels = [], []
    for number, line in enumerate(lines, start=1):
        if is_comment_only(line):
            continue
        if names_symbol(line, "resources"):
            labels.append(number)
        calls = resource_calls(line)
        if line.strip().rstrip(",") == ALLOWED_RESOURCE:
            allowed.append(number)
        elif calls:
            findings.append(("MF-RESOURCES", number, f"declares the resource rule `.{calls[0]}(`; the one "
                             f"resource is the tests' `{ALLOWED_RESOURCE}`", line))
    if fixture_folder_exists and len(allowed) != 1:
        findings.append(("MF-RESOURCES", 0, f"{FIXTURE_FOLDER} exists but the manifest declares "
                         f"`{ALLOWED_RESOURCE}` {len(allowed)} times, not once", ""))
    if allowed and not fixture_folder_exists:
        findings.append(("MF-RESOURCES", allowed[0], f"declares `{ALLOWED_RESOURCE}` but {FIXTURE_FOLDER} "
                         f"does not exist", lines[allowed[0] - 1]))
    if len(labels) > 1 or (labels and not allowed):
        findings.append(("MF-RESOURCES", labels[-1], f"{len(labels)} `resources:` labels; the one is the "
                         f"test target's, holding `{ALLOWED_RESOURCE}`", lines[labels[-1] - 1]))
    for number in labels + allowed:
        if test_target is None or number < test_target:
            findings.append(("MF-RESOURCES", number, f"a resource declaration before the `{TEST_TARGET_CALL}` "
                             f"line: the library declares none", lines[number - 1]))
    return findings


def main():
    repo = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    imported = os.path.isdir(os.path.join(repo, IMPORT_ROOT))
    manifest = os.path.join(repo, MANIFEST)
    present = os.path.isfile(manifest)
    findings = []
    if present:
        with open(manifest, encoding="utf-8", errors="replace") as f:
            lines = f.read().split("\n")
        findings = scan_manifest(lines)
        findings += scan_resources(lines, os.path.isdir(os.path.join(repo, FIXTURE_FOLDER)))
    elif imported:
        findings.append(("MF-MISSING", 0, f"{IMPORT_ROOT} exists but {MANIFEST} does not, so CI would "
                         f"skip every build and test step", ""))

    for check, number, detail, text in findings:
        where = f"{MANIFEST}:{number}" if number else MANIFEST
        print(f"{check} {where}: {detail}" + (f": {text.strip()[:140]}" if text else ""))
    print(f"\n{MANIFEST} {'checked' if present else 'absent'}; violations: {len(findings)}", file=sys.stderr)
    if not present and not imported:
        print(f"{IMPORT_ROOT} does not exist yet; MF-MISSING waits for it", file=sys.stderr)
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
