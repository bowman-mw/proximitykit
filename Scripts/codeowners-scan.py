#!/usr/bin/env python3
"""CODEOWNERS wall for ProximityKit: every rule protects a path that exists, and the walls stay owned.

Ported from Tests/FernletTests/CodeOwnersResolutionTests.swift in the Fernlet repository
(https://github.com/bowman-mw/fernlet). GitHub never reports a CODEOWNERS pattern that matches
nothing: it simply stops requiring review for the files the pattern used to cover. In the Fernlet
repository a restructure once left 11 of 26 rules matching nothing, every wall file among them,
while its docs went on asserting the protection. This scan fails instead.

Usage: Scripts/codeowners-scan.py
Prints one line per violation and a summary to stderr; exits 1 on any violation.

Path semantics modelled (deliberately the subset .github/CODEOWNERS uses, checked strictly): a
leading `/` anchors a pattern to the repository root; a trailing `/` means an existing directory;
anything else must exist as a file or directory. A pattern this scan does not model (unanchored,
or with a `*` glob) fails with that reason and never passes unverified.

Checks:
    CO-FORM      Every rule is a pattern and at least one @owner, the pattern root-anchored and
                 glob-free, and no pattern is on two rules (GitHub takes the last matching rule,
                 so the earlier one would protect nothing).
    CO-RESOLVE   Every pattern resolves to an existing path, and a trailing `/` to a directory.
    CO-REQUIRED  Every pattern in REQUIRED_PATTERNS is a rule (a floor set, not the whole file: a
                 path that moves fails CO-RESOLVE, and this fails even if the rule is deleted to
                 "fix" that), and the file holds at least RULE_FLOOR rules.

Before the import: the code came with its git history from the Fernlet repository. On a tree
without Package.swift, as this repository's was until then, CO-RESOLVE is held for the paths the
import brings (IMPORTED_PREFIXES); the rules for the scaffolding (Scripts/, .github/) resolve from
the start, and CO-FORM and CO-REQUIRED run in full. Once Package.swift exists, a rule naming a file
that is not there fails.
"""
import os
import sys

CODEOWNERS = os.path.join(".github", "CODEOWNERS")
MANIFEST = "Package.swift"
IMPORTED_PREFIXES = ("/Sources/", "/Tests/", "/Package.swift")

# The paths whose protection the README and the walls rest on, as CODEOWNERS spells them.
REQUIRED_PATTERNS = (
    # The label registry every signature, seal and key derivation is bound to, and the keychain
    # funnel whose Debug-only door the tests install their in-memory store through.
    "/Sources/ProximityKit/Namespace/",
    "/Sources/ProximityKit/Support/ProximityKeychainItem.swift",
    # The walls that travelled from the Fernlet repository: namespace, platform, keychain door.
    "/Tests/ProximityKitTests/ProximityNamespaceBoundaryTests.swift",
    "/Tests/ProximityKitTests/ProximityPlatformNeutralityTests.swift",
    "/Tests/ProximityKitTests/ProximityKeychainDoorTests.swift",
    # The package tests' own walls: their hygiene, the test tree's walls, the source walls and the
    # memory-lifecycle wall.
    "/Tests/ProximityKitTests/PackageTestHygieneTests.swift",
    "/Tests/ProximityKitTests/PackageTestTreeWallTests.swift",
    "/Tests/ProximityKitTests/ProximitySourceWallTests.swift",
    "/Tests/ProximityKitTests/ProximityMemoryLifecycleTests.swift",
    # The inventory of the package's tests, the test-count floor's declared pin.
    "/Tests/ProximityKitTests.tsv",
    # The manifest, the walls and the CI that runs them (CODEOWNERS included).
    "/Package.swift",
    "/Scripts/",
    "/.github/",
)
RULE_FLOOR = 19   # four fifths of the 24 rules the file held when the floor was set


def read_rules(path):
    """(line number, pattern, owners) for every rule line."""
    rules = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for number, raw in enumerate(f.read().split("\n"), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            tokens = line.split()
            rules.append((number, tokens[0], tokens[1:]))
    return rules


def main():
    repo = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    imported = os.path.isfile(os.path.join(repo, MANIFEST))
    path = os.path.join(repo, CODEOWNERS)
    findings = []
    rules = read_rules(path) if os.path.isfile(path) else []
    if not os.path.isfile(path):
        findings.append(f"CO-REQUIRED {CODEOWNERS}: missing, so no path has an owner")

    seen, held, resolved = {}, 0, 0
    for number, pattern, owners in rules:
        where = f"{CODEOWNERS}:{number}"
        if not owners or not all(owner.startswith("@") and len(owner) > 1 for owner in owners):
            findings.append(f"CO-FORM {where}: `{pattern}` needs at least one @owner, and every owner is an @name")
            continue
        if pattern in seen:
            findings.append(f"CO-FORM {where}: `{pattern}` is also the rule on line {seen[pattern]}; GitHub takes "
                            f"the last, so one of them protects nothing")
        seen.setdefault(pattern, number)
        if "*" in pattern or not pattern.startswith("/"):
            findings.append(f"CO-FORM {where}: `{pattern}` is unanchored or globbed, which this scan does not "
                            f"model; anchor it to the root, or extend the scan before using a glob")
            continue
        if not imported and pattern.startswith(IMPORTED_PREFIXES):
            held += 1
            continue
        target = os.path.join(repo, *pattern.strip("/").split("/"))
        if not os.path.exists(target):
            findings.append(f"CO-RESOLVE {where}: `{pattern}` matches nothing; the protected path moved or was "
                            f"deleted, so fix the rule in the same commit")
        elif pattern.endswith("/") and not os.path.isdir(target):
            findings.append(f"CO-RESOLVE {where}: `{pattern}` says directory (a trailing /) but is a file")
        else:
            resolved += 1

    for pattern in REQUIRED_PATTERNS:
        if pattern not in seen:
            findings.append(f"CO-REQUIRED {CODEOWNERS}: no rule owns `{pattern}`, a path the walls rest on")
    if os.path.isfile(path) and len(rules) < RULE_FLOOR:
        findings.append(f"CO-REQUIRED {CODEOWNERS}: {len(rules)} rules, below the floor of {RULE_FLOOR}; the file "
                        f"or this scan's reading of it broke")

    for line in findings:
        print(line)
    print(f"\n{CODEOWNERS}: {len(rules)} rules; resolved {resolved}; required {len(REQUIRED_PATTERNS)}; "
          f"violations: {len(findings)}", file=sys.stderr)
    if not imported:
        print(f"{MANIFEST} does not exist yet; {held} rules for the paths the import brings wait for it",
              file=sys.stderr)
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
