#!/usr/bin/env python3
"""Manifest wall for ProximityKit: Package.swift carries no unsafe flags and no warnings setting.

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

Comment-only lines are skipped, so prose that explains the ban passes; a trailing comment does
not hide a setting. The names are matched at identifier boundaries, so a longer identifier that
contains one is not the setting.

Before the import: the code arrives later with its git history from the Fernlet repository. Until
then there is no Package.swift and no Sources/ProximityKit, and an empty tree passes.
"""
import os
import sys

MANIFEST = "Package.swift"
IMPORT_ROOT = os.path.join("Sources", "ProximityKit")   # MF-MISSING starts once this exists

UNSAFE_SETTINGS = ("unsafeFlags",)
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
