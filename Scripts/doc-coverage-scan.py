#!/usr/bin/env python3
"""Scan Swift sources for type declarations lacking an adjacent /// doc comment.

Ported from Scripts/doc-coverage-scan.py in the Fernlet repository
(https://github.com/bowman-mw/fernlet), where this code lived under the same rule. The matcher
is copied unchanged; the root and the pre-import floor are this repository's.

Usage: Scripts/doc-coverage-scan.py [<root or file> ...]
With no arguments, scans Sources/ (relative to the repo root, which is resolved from this
script's location). Test code is not held to the rule.

Prints one line per undocumented declaration (path:line:TypeName: decl) and a
TOTAL to stderr; exits 1 if any are found. The enforced baseline is zero: every
struct/class/protocol/enum/actor carries a /// doc comment.

Before the import: the code arrives later with its git history from the Fernlet repository.
Once Sources/ProximityKit exists, a default scan that reads zero Swift files fails instead of
passing over nothing; until then an empty tree passes.

Heuristic: a declaration is documented if, walking upward past attribute lines
(@...), the nearest preceding line is a /// line or the end of a /** */ block.
Skips lines inside block comments and multiline string literals (approximate,
line-based tracking). Requires an uppercase-or-underscore identifier after the
type keyword so `class func` / `class var` don't match.
"""
import os
import re
import sys

SOURCE_ROOTS = ("Sources",)
IMPORT_ROOT = os.path.join("Sources", "ProximityKit")   # the floor starts once this exists

DECL_RE = re.compile(
    r"^\s*(?:@\w[\w.]*(?:\([^)]*\))?\s+)*"
    r"(?:(?:public|open|internal|package|private|fileprivate|final|indirect|dynamic|nonisolated|distributed)\s+)*"
    r"(?:struct|class|protocol|enum|actor)\s+([A-Z_]\w*)"
)
ATTR_RE = re.compile(r"^\s*@\w")


def scan_file(path):
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()
    findings = []
    block_comment = 0
    in_multiline_string = False
    code_mask = []  # True if the line is (mostly) code
    for line in lines:
        stripped = line.strip()
        is_code = True
        if in_multiline_string:
            is_code = False
            if '"""' in stripped:
                in_multiline_string = False
        elif block_comment > 0:
            is_code = False
            block_comment += stripped.count("/*") - stripped.count("*/")
            if block_comment < 0:
                block_comment = 0
        else:
            if stripped.startswith("//"):
                is_code = False
            else:
                opens = stripped.count("/*") - stripped.count("*/")
                if opens > 0:
                    block_comment = opens
                if stripped.count('"""') % 2 == 1:
                    in_multiline_string = True
        code_mask.append(is_code)

    for idx, line in enumerate(lines):
        if not code_mask[idx]:
            continue
        m = DECL_RE.match(line)
        if not m:
            continue
        # walk upward past attributes / attribute-argument continuation lines
        j = idx - 1
        while j >= 0:
            prev = lines[j].strip()
            if ATTR_RE.match(prev) or prev.endswith(",") and j > 0 and ATTR_RE.match(lines[j - 1].strip()):
                j -= 1
                continue
            break
        documented = False
        if j >= 0:
            prev = lines[j].strip()
            if prev.startswith("///") or prev.endswith("*/"):
                documented = True
        if not documented:
            findings.append((idx + 1, m.group(1), line.strip()[:100]))
    return findings


def iter_swift(roots):
    for root in roots:
        if os.path.isfile(root):
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if not d.endswith(".docc") and d != ".git"]
            for name in sorted(filenames):
                if name.endswith(".swift"):
                    yield os.path.join(dirpath, name)


def main():
    repo = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    roots = sys.argv[1:]
    default_scan = not roots
    if default_scan:
        roots = [os.path.join(repo, d) for d in SOURCE_ROOTS]
    total = 0
    n_files = 0
    for path in iter_swift(roots):
        n_files += 1
        shown = os.path.relpath(os.path.realpath(path), repo)
        for lineno, type_name, text in scan_file(path):
            print(f"{shown}:{lineno}:{type_name}: {text}")
            total += 1
    print(f"\nfiles scanned: {n_files}", file=sys.stderr)
    print(f"TOTAL undocumented type declarations: {total}", file=sys.stderr)
    vacuous = False
    if n_files == 0:
        if default_scan and os.path.isdir(os.path.join(repo, IMPORT_ROOT)):
            print("no Swift files scanned: refusing to pass vacuously", file=sys.stderr)
            vacuous = True
        elif default_scan:
            print(f"no Swift files yet: {IMPORT_ROOT} does not exist, so the floor waits for it",
                  file=sys.stderr)
    sys.exit(1 if total or vacuous else 0)


if __name__ == "__main__":
    main()
