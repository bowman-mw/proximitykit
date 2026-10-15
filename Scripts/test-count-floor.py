#!/usr/bin/env python3
"""Test-count floor for ProximityKit: CI proves that the tests the package declares ran, on every lane.

A test inside the bundle can count the tests the package declares, never the ones a run executed: a
suite filtered out, a bundle that never started, or a test folder deleted whole is silent from the
inside. This floor reads each run from outside. Its run half is ported from the result-bundle reader
in Scripts/run-gated-suites.sh in the Fernlet repository (https://github.com/bowman-mw/fernlet),
which holds that repository's measured CI lines, ProximityKit's own tests among them.

Two pins, so that lowering coverage takes an edit to both:
    * the reviewed pin: the literals MIN_TESTS and MIN_SUITES in the `env:` block of
      .github/workflows/ci.yml, each raised by hand with a note saying what was measured;
    * the declared pin: the package's inventory, Tests/ProximityKitTests.tsv, one row per suite of
      the test target with its file and its declared tests. The package's own
      PackageTestHygieneTests holds that inventory to the test tree.

Usage:
    Scripts/test-count-floor.py declared
    Scripts/test-count-floor.py xcresult <bundle.xcresult> [--log <xcodebuild output>]
    Scripts/test-count-floor.py swift-test <swift test output>
Prints one line per violation and a summary to stderr; exits 1 on any violation, 2 on a usage error.

Modes:
    declared     Runs in CI's Walls step, before any build. Reads the literals (TF-LITERALS) and,
                 once Package.swift exists, the inventory and the tree (TF-INVENTORY, TF-TREE)
                 and the two pins against each other (TF-DECLARED).
    xcresult     Runs after each `xcodebuild test`, on the result bundle it wrote (TF-XCRESULT):
                 the run passed, totalTestCount >= MIN_TESTS, 0 failed, 0 skipped; the suite
                 census: every inventory suite ran at least one case, no suite ran that the
                 inventory lacks, and every node of the tree parsed. With --log, the run's console
                 output holds no restart line: xcodebuild restarts a run after a crash or a timeout
                 and re-runs suites, which inflates totalTestCount past what the floor means.
    swift-test   Runs after `swift test`, on its console output captured through `tee` with
                 `set -o pipefail` (TF-SWIFT-TEST): exactly one Swift Testing summary line,
                 "Test run with N tests in M suites passed" after a U+2714 check mark, with
                 N >= MIN_TESTS and M == MIN_SUITES. No such line is a refusal, never a pass.

Checks:
    TF-LITERALS   ci.yml defines MIN_TESTS and MIN_SUITES once each, as positive integers in an
                  `env:` block. When the environment carries either (as every CI step's does), it
                  equals the literal, so a step cannot lower the floor for itself.
    TF-INVENTORY  The inventory exists and reads: `#` lines are comments; the first other line is
                  exactly INVENTORY_HEADER; every other line has three tab-separated fields; a suite
                  is an identifier; suites run strictly ascending (so each is on one row); cells is
                  a positive integer; a file is a relative .swift path that exists under
                  Tests/ProximityKitTests. The format is the hygiene suite's rule I1.
    TF-TREE       Tests/ProximityKitTests holds Swift files. Without this, a deleted test folder
                  would only make `swift package describe` warn, and CI would pass without tests.
    TF-DECLARED   MIN_TESTS >= the inventory's declared tests (the cells' sum) and
                  MIN_SUITES == its row count.
    TF-XCRESULT   The result bundle's checks, above.
    TF-SWIFT-TEST The summary line's checks, above.

The numbers agree across lanes although four package tests are parameterized (in MeshChunkShapeTests,
MeshRecipientReceiptShapeTests and MeshRoutedInventoryShapeTests): Swift Testing counts a
parameterized test once in its summary line, a result bundle counts it once in totalTestCount and in
its census (its arguments are children of its one test case), and the inventory's cells count it
once. If a lane ever counts otherwise, measure what each lane reports before raising the literals.

Before the import: the code came with its git history from the Fernlet repository. On a tree
without Package.swift, as this repository's was until then, `declared` reads the literals only and
holds the rest with a notice.
"""
import json
import os
import re
import subprocess
import sys

WORKFLOW = os.path.join(".github", "workflows", "ci.yml")
MANIFEST = "Package.swift"
INVENTORY = os.path.join("Tests", "ProximityKitTests.tsv")
TEST_FOLDER = os.path.join("Tests", "ProximityKitTests")
TEST_BUNDLE = "ProximityKitTests"   # the test target, as a result bundle names its bundle
INVENTORY_HEADER = "suite\tfile\tcells"
LITERALS = ("MIN_TESTS", "MIN_SUITES")
RESTART_MARKER = "Restarting after unexpected exit, crash, or test timeout"
# Swift Testing's summary of a passing run, after its U+2714 check mark.
SUMMARY_RE = re.compile("^\u2714" r" Test run with (\d+) tests? in (\d+) suites? passed after ")
LITERAL_RE = re.compile(r"^(\s*)(MIN_TESTS|MIN_SUITES):(.*)$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
MAX_TREE_NODES = 1000000   # the census walk's bound: far above any tree this package can write


def indent_of(line):
    return len(line) - len(line.lstrip(" "))


def is_comment_or_blank(line):
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def parent_key(lines, index):
    """The key line the line at `index` sits under: the nearest earlier line, neither blank nor a
    comment, that is indented less."""
    own = indent_of(lines[index])
    for back in range(index - 1, -1, -1):
        line = lines[back]
        if not is_comment_or_blank(line) and indent_of(line) < own:
            return line.strip()
    return ""


def read_literals(repo, findings):
    """The floor literals from ci.yml, by name, or {} when they cannot be read (with findings)."""
    path = os.path.join(repo, WORKFLOW)
    if not os.path.isfile(path):
        findings.append(f"TF-LITERALS {WORKFLOW}: missing, so the floor literals cannot be read")
        return {}
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.read().split("\n")
    found = {}
    for index, line in enumerate(lines):
        match = LITERAL_RE.match(line)
        if not match:
            continue
        name, value = match.group(2), match.group(3).strip()
        where = f"{WORKFLOW}:{index + 1}"
        if name in found:
            findings.append(f"TF-LITERALS {where}: {name} is defined again; one definition, in the job's "
                            f"env: block, is the reviewed pin")
            continue
        if parent_key(lines, index) != "env:":
            findings.append(f"TF-LITERALS {where}: {name} is not in an env: block")
        if not value.isdigit() or int(value) < 1:
            findings.append(f"TF-LITERALS {where}: {name} is `{value}`, not a positive integer (no quotes, "
                            f"no trailing comment)")
            found[name] = None
            continue
        found[name] = int(value)
    for name in LITERALS:
        if name not in found:
            findings.append(f"TF-LITERALS {WORKFLOW}: no {name} literal in an env: block")
    literals = {name: value for name, value in found.items() if value is not None}
    for name, value in literals.items():
        environment = os.environ.get(name)
        if environment is not None and environment != str(value):
            findings.append(f"TF-LITERALS environment: {name} is `{environment}` here but {value} in "
                            f"{WORKFLOW}; nothing may override the floor for one step")
    return literals if len(literals) == len(LITERALS) else {}


def inventory_row(line):
    """One data line read into (suite, file, cells), or (None, the first field problem)."""
    fields = line.split("\t")
    if len(fields) != 3:
        return None, f"{len(fields)} tab-separated fields, not 3"
    suite, file, cells = fields
    if not IDENTIFIER_RE.match(suite):
        return None, f"`{suite}` is not a suite name"
    parts = file.split("/")
    if not file.endswith(".swift") or file.startswith("/") or ".." in parts:
        return None, f"`{file}` is not a relative Swift path under {TEST_FOLDER}"
    if not cells.isdigit() or int(cells) < 1:
        return None, f"cells `{cells}` are not a positive integer"
    return (suite, file, int(cells)), None


def read_inventory(repo, findings):
    """The inventory's rows [(suite, file, cells)], every problem appended to `findings`."""
    path = os.path.join(repo, INVENTORY)
    if not os.path.isfile(path):
        findings.append(f"TF-INVENTORY {INVENTORY}: missing; the floor's declared pin is the package's "
                        f"inventory beside {TEST_FOLDER}")
        return []
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.read().split("\n")
    rows, saw_header = [], False
    for number, line in enumerate(lines, start=1):
        if not line or line.startswith("#"):
            continue
        where = f"TF-INVENTORY {INVENTORY}:{number}"
        if not saw_header:
            saw_header = True
            if line != INVENTORY_HEADER:
                findings.append(f"{where}: the first line that is not a comment is not the header "
                                f"`suite<TAB>file<TAB>cells`")
            continue
        row, problem = inventory_row(line)
        if problem:
            findings.append(f"{where}: {problem}")
            continue
        if rows and rows[-1][0] >= row[0]:
            findings.append(f"{where}: `{row[0]}` does not sort after `{rows[-1][0]}`; rows sort by suite, "
                            f"each suite once")
        # A row whose file is gone stays a row: the run's census must still miss its suite by name.
        if not os.path.isfile(os.path.join(repo, TEST_FOLDER, *row[1].split("/"))):
            findings.append(f"{where}: `{row[1]}` does not exist under {TEST_FOLDER} (moved, renamed or "
                            f"deleted: edit the row in the same commit)")
        rows.append(row)
    if not saw_header:
        findings.append(f"TF-INVENTORY {INVENTORY}: no header line")
    elif not rows:
        findings.append(f"TF-INVENTORY {INVENTORY}: no rows")
    return rows


def swift_files(root):
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", ".build")]
        found.extend(os.path.join(dirpath, n) for n in filenames if n.endswith(".swift"))
    return found


def declared(repo):
    findings = []
    literals = read_literals(repo, findings)
    if not os.path.isfile(os.path.join(repo, MANIFEST)):
        return findings, (f"{MANIFEST} does not exist yet; the inventory, tree and declared checks wait for "
                          f"it (literals: " + ", ".join(f"{k} {v}" for k, v in sorted(literals.items())) + ")")
    tests = swift_files(os.path.join(repo, TEST_FOLDER))
    if not tests:
        findings.append(f"TF-TREE {TEST_FOLDER}: no Swift files although {MANIFEST} exists; the package "
                        f"would build with no tests and CI would pass without running any")
    rows = read_inventory(repo, findings)
    declared_tests = sum(cells for _, _, cells in rows)
    if literals and rows:
        if literals["MIN_TESTS"] < declared_tests:
            findings.append(f"TF-DECLARED {WORKFLOW}: MIN_TESTS is {literals['MIN_TESTS']} but {INVENTORY} "
                            f"declares {declared_tests} tests; raise the floor with a measurement note in the "
                            f"same commit as the tests")
        if literals["MIN_SUITES"] != len(rows):
            findings.append(f"TF-DECLARED {WORKFLOW}: MIN_SUITES is {literals['MIN_SUITES']} but {INVENTORY} "
                            f"holds {len(rows)} suites; the two pins move together, never one in passing")
    return findings, (f"Swift files under {TEST_FOLDER}: {len(tests)}; inventory: {len(rows)} suites declaring "
                      f"{declared_tests} tests; literals: " +
                      ", ".join(f"{k} {v}" for k, v in sorted(literals.items())))


def xcresult_json(kind, bundle):
    """`xcrun xcresulttool get test-results <kind>` over `bundle`, as JSON, or raises RuntimeError."""
    command = ["xcrun", "xcresulttool", "get", "test-results", kind, "--path", bundle, "--compact"]
    done = subprocess.run(command, capture_output=True, text=True)
    if done.returncode != 0:
        raise RuntimeError(f"`{' '.join(command[:5])}` exited {done.returncode}: {done.stderr.strip()[:300]}")
    try:
        return json.loads(done.stdout)
    except ValueError as error:   # json.JSONDecodeError is a ValueError
        raise RuntimeError(f"xcresulttool's {kind} output is not JSON ({error})")


def suite_census(tree):
    """Test cases per suite type, read off each top-level Test Suite node's nodeIdentifierURL
    (test://com.apple.xcode/<container>/<bundle>/<Type>), because a Swift Testing suite's `name` is
    its display name; plus the nodes that do not parse. A changed tree format is named as such,
    never read as a suite that ran nothing. Bounded: every node of the finite tree is pushed once."""
    counts, unparsed = {}, []
    stack = [(node, "", "") for node in tree.get("testNodes", []) or []]
    visited = 0
    while stack and visited < MAX_TREE_NODES:
        visited += 1
        node, bundle, suite = stack.pop()
        kind = node.get("nodeType", "")
        if kind == "Unit test bundle":
            bundle = node.get("name", "")
        if kind == "Test Suite" and not suite:
            parts = node.get("nodeIdentifierURL", "").split("/")
            if len(parts) == 6 and parts[0] == "test:" and parts[4] == bundle and parts[5]:
                suite = parts[5] if bundle == TEST_BUNDLE else f"{bundle}/{parts[5]}"
            else:
                unparsed.append(f"{bundle}/{node.get('name', '?')}")
                suite = "?"
        if kind == "Test Case":
            if not suite:
                unparsed.append(f"{bundle}/{node.get('name', '?')} (a test case outside any suite)")
            key = suite or "?"
            counts[key] = counts.get(key, 0) + 1
            continue
        stack.extend((child, bundle, suite) for child in node.get("children", []) or [])
    if stack:
        unparsed.append(f"more than {MAX_TREE_NODES} nodes")
    return counts, unparsed


def run_xcresult(repo, bundle, log):
    findings = []
    literals = read_literals(repo, findings)
    rows = read_inventory(repo, findings)
    if not os.path.isdir(bundle):
        return findings + [f"TF-XCRESULT {bundle}: no result bundle there; did the test leg write one?"], ""
    try:
        summary = xcresult_json("summary", bundle)
        tree = xcresult_json("tests", bundle)
    except RuntimeError as error:
        return findings + [f"TF-XCRESULT {bundle}: {error}"], ""
    total = int(summary.get("totalTestCount", 0))
    failed = int(summary.get("failedTests", 0))
    skipped = int(summary.get("skippedTests", 0))
    result = summary.get("result", "unknown")
    if result != "Passed" or failed:
        findings.append(f"TF-XCRESULT {bundle}: result is {result} with {failed} failed test(s)")
    if skipped:
        findings.append(f"TF-XCRESULT {bundle}: {skipped} test(s) skipped; a skipped test proves nothing")
    if literals and total < literals["MIN_TESTS"]:
        findings.append(f"TF-XCRESULT {bundle}: only {total} test(s) ran but MIN_TESTS is {literals['MIN_TESTS']}: "
                        f"a suite that did not run, a bundle that did not start, or tests deleted; never lower "
                        f"the floor in passing")
    counts, unparsed = suite_census(tree)
    if unparsed:
        findings.append(f"TF-XCRESULT {bundle}: tree nodes that do not parse (" + ", ".join(sorted(set(unparsed))[:5])
                        + "): this xcresulttool's format is not the one measured on Xcode 26.5; fix the census, "
                        "never pass the floor around it")
    else:
        inventory = [suite for suite, _, _ in rows]
        unrun = [suite for suite in inventory if counts.get(suite, 0) == 0]
        if unrun:
            findings.append(f"TF-XCRESULT {bundle}: inventory suites that ran no test case: " + ", ".join(unrun))
        unlisted = sorted(set(counts) - set(inventory))
        if rows and unlisted:
            findings.append(f"TF-XCRESULT {bundle}: suites that ran but {INVENTORY} lacks: " + ", ".join(unlisted)
                            + "; add each one's row in the same commit")
    if log is not None:
        if not os.path.isfile(log):
            findings.append(f"TF-XCRESULT {log}: the run's console output is missing, so the restart check "
                            f"cannot be read")
        else:
            with open(log, encoding="utf-8", errors="replace") as f:
                if RESTART_MARKER in f.read():
                    findings.append(f"TF-XCRESULT {log}: xcodebuild restarted the run after an unexpected exit, "
                                    f"crash or timeout; a restart re-runs suites, so the count proves nothing")
    ran = sum(counts.values())
    return findings, (f"result {result}: totalTestCount {total}, {failed} failed, {skipped} skipped; census "
                      f"{ran} test case(s) in {len(counts)} suite(s) against {len(rows)} inventory rows; "
                      f"restart check " + ("read" if log is not None else "not run (no --log)") +
                      "; literals: " + ", ".join(f"{k} {v}" for k, v in sorted(literals.items())))


def run_swift_test(repo, log):
    findings = []
    literals = read_literals(repo, findings)
    if not os.path.isfile(log):
        return findings + [f"TF-SWIFT-TEST {log}: missing; capture swift test's output with `tee` under "
                           f"`set -o pipefail`"], ""
    with open(log, encoding="utf-8", errors="replace") as f:
        matches = [SUMMARY_RE.match(line) for line in f.read().split("\n")]
    matches = [m for m in matches if m]
    if len(matches) != 1:
        what = "no" if not matches else f"{len(matches)}"
        findings.append(f"TF-SWIFT-TEST {log}: {what} Swift Testing summary line(s) \"\u2714 Test run with N tests "
                        f"in M suites passed\"; one passing run prints exactly one")
        return findings, ""
    tests, suites = int(matches[0].group(1)), int(matches[0].group(2))
    if literals and tests < literals["MIN_TESTS"]:
        findings.append(f"TF-SWIFT-TEST {log}: {tests} tests ran but MIN_TESTS is {literals['MIN_TESTS']}; never "
                        f"lower the floor in passing")
    if literals and suites != literals["MIN_SUITES"]:
        findings.append(f"TF-SWIFT-TEST {log}: {suites} suites ran but MIN_SUITES is {literals['MIN_SUITES']}: a "
                        f"suite that did not run, or one the inventory and the literal do not hold yet")
    return findings, (f"swift test ran {tests} tests in {suites} suites; literals: " +
                      ", ".join(f"{k} {v}" for k, v in sorted(literals.items())))


def usage(message):
    print(f"test-count-floor.py: {message}\nusage: test-count-floor.py declared | xcresult <bundle> "
          f"[--log <output>] | swift-test <output>", file=sys.stderr)
    sys.exit(2)


def main(argv):
    repo = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    if not argv:
        usage("a mode is required")
    mode, args = argv[0], argv[1:]
    if mode == "declared" and not args:
        findings, note = declared(repo)
    elif mode == "xcresult" and len(args) in (1, 3) and (len(args) == 1 or args[1] == "--log"):
        findings, note = run_xcresult(repo, args[0], args[2] if len(args) == 3 else None)
    elif mode == "swift-test" and len(args) == 1:
        findings, note = run_swift_test(repo, args[0])
    else:
        usage(f"unreadable arguments: {' '.join(argv)}")
    for line in findings:
        print(line)
    print(f"\ntest-count floor ({mode}): {note}{'; ' if note else ''}violations: {len(findings)}", file=sys.stderr)
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main(sys.argv[1:])
