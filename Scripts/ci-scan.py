#!/usr/bin/env python3
"""CI wall for ProximityKit: the workflow keeps every leg, its warnings-as-errors flags and the floor.

Power of 10 rule 10 (warnings are errors) is held on the build commands in
.github/workflows/ci.yml, never in the manifest (Scripts/manifest-scan.py holds that half). This
scan holds the other half: the command lines themselves. It is this repository's counterpart of
r10WallCheckScriptBuildsStrict() in the Fernlet repository's
Tests/FernletTests/PowerOfTenBoundaryTests.swift (https://github.com/bowman-mw/fernlet), which pins
the strict command of that repository's wall check. Deleting a flag, a leg or a floor check from
ci.yml is a one-line edit that every later run would pass; here it fails the Walls step instead.

Usage: Scripts/ci-scan.py
Prints one line per violation and a summary to stderr; exits 1 on any violation.

What a leg is: a command line (backslash continuations joined, shell comments skipped) in a step's
`run:` that starts with `swift build`, `swift test`, or `xcodebuild` with one of XCODEBUILD_ACTIONS,
after any leading VAR=value assignments. `xcodebuild -version` and the like are not legs.

Checks:
    CI-SHAPE   The workflow reads: one `steps:` list whose items carry `name`/`uses`, `if` and
               `run` keys in the form this file uses (a `run: |` block or a one-line `run:`). A
               build or test command that does not start its line cannot be read as a leg and
               fails here instead of passing unread.
    CI-STRICT  Every SwiftPM leg passes `-Xswiftc -warnings-as-errors`; every xcodebuild leg passes
               XCODEBUILD_OVERRIDES; no leg passes a flag in CONTRARY_FLAGS.
    CI-LEG     Every leg in REQUIRED_LEGS exists: the Debug and Release builds, both macOS test
               lanes (swift test and xcodebuild test), the iOS Simulator build and its test lane.
               A leg's own status decides its step: nothing follows it on its line but an optional
               `| tee <file>`, and a piped leg sits after `set -o pipefail` in its step.
    CI-GATE    A step holding a test leg runs if TEST_CONDITION, any other leg's step if
               BUILD_CONDITION, and no step carries `continue-on-error`.
    CI-FLOOR   After each test leg, later in its own step, the test-count floor reads what ran:
               `python3 Scripts/test-count-floor.py swift-test <the leg's tee file>` after swift
               test, and `... xcresult <the leg's -resultBundlePath> --log <its tee file>` after
               each xcodebuild test.
    CI-WALLS   The step named "Walls" runs before every leg, under no `if:`, and names every
               Python script in Scripts/ and `test-count-floor.py declared`, so a wall cannot be
               dropped from CI by leaving it out of the loop.

Before the import: ci.yml existed from the start, so nothing here is held. On a tree without
Package.swift the legs are skipped in CI, and this scan holds their text all the same.
"""
import os
import re
import shlex
import sys

WORKFLOW = os.path.join(".github", "workflows", "ci.yml")
SCRIPTS = "Scripts"
FLOOR = "Scripts/test-count-floor.py"
WALLS_STEP = "Walls"

SWIFTPM_FLAG = ("-Xswiftc", "-warnings-as-errors")
XCODEBUILD_OVERRIDES = ("SUPPRESS_WARNINGS=NO", "SWIFT_TREAT_WARNINGS_AS_ERRORS=YES",
                        "GCC_TREAT_WARNINGS_AS_ERRORS=YES")
CONTRARY_FLAGS = ("-suppress-warnings", "-no-warnings-as-errors", "SUPPRESS_WARNINGS=YES",
                  "SWIFT_TREAT_WARNINGS_AS_ERRORS=NO", "GCC_TREAT_WARNINGS_AS_ERRORS=NO")
XCODEBUILD_ACTIONS = ("build", "test", "build-for-testing", "test-without-building", "analyze", "archive")
TEST_CONDITION = "steps.describe.outputs.tests == 'true'"
BUILD_CONDITION = "steps.package.outputs.present == 'true'"
IOS_DESTINATION = "$PROXIMITYKIT_DESTINATION"
IOS_DESTINATION_EXPORT = "PROXIMITYKIT_DESTINATION=platform=iOS Simulator,"
CONTROL_TOKENS = ("|", "||", "&&", ";", "&", "|&", ";;")
BLOCK_INDICATORS = ("|", "|-", "|+", ">", ">-", ">+")

KEY_RE = re.compile(r"^([A-Za-z_][\w-]*):(?:\s+(.*))?$")
ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
LEG_WORD_RE = re.compile(r"(?<![\w-])(swift\s+(?:build|test)|xcodebuild)(?![\w-])")


def is_test(leg):
    return leg["action"] == "test"


def is_release(leg):
    tokens = leg["tokens"]
    pairs = zip(tokens, tokens[1:])
    return any(a in ("-c", "--configuration") and b == "release" for a, b in pairs) or \
        "--configuration=release" in tokens


def is_ios(leg):
    destination = leg["destination"] or ""
    return destination == IOS_DESTINATION or "platform=iOS Simulator" in destination


# Every leg the job must keep, by shape. Removing one is a weakening, whatever the step is called.
REQUIRED_LEGS = (
    ("the Debug build (swift build)",
     lambda leg: leg["tool"] == "swift" and leg["action"] == "build" and not is_release(leg)),
    ("the Release compile (swift build -c release)",
     lambda leg: leg["tool"] == "swift" and leg["action"] == "build" and is_release(leg)),
    ("the macOS test lane through SwiftPM (swift test)",
     lambda leg: leg["tool"] == "swift" and is_test(leg)),
    ("the macOS test lane through Xcode (xcodebuild test, platform=macOS)",
     lambda leg: leg["tool"] == "xcodebuild" and is_test(leg) and leg["destination"] == "platform=macOS"),
    ("the iOS Simulator build (xcodebuild build, generic/platform=iOS Simulator)",
     lambda leg: leg["tool"] == "xcodebuild" and leg["action"] == "build"
     and leg["destination"] == "generic/platform=iOS Simulator"),
    ("the iOS Simulator test lane (xcodebuild test on the pinned iPhone 17)",
     lambda leg: leg["tool"] == "xcodebuild" and is_test(leg) and is_ios(leg)),
)


def indent_of(line):
    return len(line) - len(line.lstrip(" "))


def is_comment_or_blank(line):
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def unquote(value):
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def read_key(lines, index, content, key_indent, step, findings):
    """Reads one `key: value` of a step, starting at `content` on line `index`, into `step`;
    returns the index of the first line after it. A block scalar or a nested map spans the lines
    indented deeper than the key (blank lines included); its text is kept dedented."""
    match = KEY_RE.match(content)
    if not match:
        findings.append(f"CI-SHAPE {WORKFLOW}:{index + 1}: `{content[:80]}` is not a `key: value` line of a "
                        f"step")
        return index + 1
    key, value = match.group(1), (match.group(2) or "").strip()
    if key in step["keys"]:
        findings.append(f"CI-SHAPE {WORKFLOW}:{index + 1}: the step's `{key}` is given twice")
    end = index + 1
    if value in BLOCK_INDICATORS or not value:
        while end < len(lines) and (not lines[end].strip() or indent_of(lines[end]) > key_indent):
            end += 1
        body = lines[index + 1:end]
        while body and not body[-1].strip():
            body.pop()
        depth = min((indent_of(b) for b in body if b.strip()), default=0)
        step["keys"][key] = "\n".join(b[depth:] for b in body)
        step["lines"][key] = index + 2
        return end
    step["keys"][key] = unquote(value)
    step["lines"][key] = index + 1
    return end


def read_steps(lines, findings):
    """The job's steps, each {"line", "keys", "lines"}, read from the one `steps:` list."""
    starts = [i for i, line in enumerate(lines) if line.strip() == "steps:"]
    if len(starts) != 1:
        findings.append(f"CI-SHAPE {WORKFLOW}: {len(starts)} `steps:` lists; this scan reads a job of one")
        return []
    base = indent_of(lines[starts[0]])
    steps, item_indent, index = [], None, starts[0] + 1
    while index < len(lines):
        line = lines[index]
        if is_comment_or_blank(line):
            index += 1
            continue
        indent, stripped = indent_of(line), line.strip()
        if indent <= base:
            break
        if stripped.startswith("- ") and (item_indent is None or indent == item_indent):
            item_indent = indent
            steps.append({"line": index + 1, "keys": {}, "lines": {}})
            index = read_key(lines, index, stripped[2:], indent + 2, steps[-1], findings)
        elif steps and indent == item_indent + 2:
            index = read_key(lines, index, stripped, indent, steps[-1], findings)
        else:
            findings.append(f"CI-SHAPE {WORKFLOW}:{index + 1}: a line this scan cannot place in a step")
            index += 1
    if not steps:
        findings.append(f"CI-SHAPE {WORKFLOW}: no steps read")
    return steps


def logical_lines(step):
    """The run script's command lines as (line number, text): backslash continuations joined,
    blank lines and shell comments skipped."""
    run = step["keys"].get("run")
    if run is None:
        return []
    first = step["lines"]["run"]   # the file line of the script's first line, block or one-line
    out, pending, start = [], "", None
    for offset, raw in enumerate(run.split("\n")):
        text = raw.strip()
        if not pending and (not text or text.startswith("#")):
            continue
        if start is None:
            start = first + offset
        if text.endswith("\\"):
            pending += text[:-1] + " "
            continue
        out.append((start, pending + text))
        pending, start = "", None
    if pending:
        out.append((start, pending.strip()))
    return out


def tokens_of(text):
    """Shell words of `text` with control operators split out, or None when the quoting does not read."""
    try:
        lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        return None


def read_leg(step_index, number, text, findings):
    """The leg on this command line, or None when the line holds no build or test command."""
    if not LEG_WORD_RE.search(text):
        return None
    tokens = tokens_of(text)
    where = f"{WORKFLOW}:{number}"
    if tokens is None:
        findings.append(f"CI-SHAPE {where}: a build or test command whose quoting this scan cannot read")
        return None
    words = list(tokens)
    while words and ASSIGNMENT_RE.match(words[0]):
        words.pop(0)
    cut = next((i for i, t in enumerate(words) if t in CONTROL_TOKENS), len(words))
    command, rest = words[:cut], words[cut:]
    if command[:1] == ["swift"] and len(command) > 1 and command[1] in ("build", "test"):
        tool, action = "swift", command[1]
    elif command[:1] == ["xcodebuild"]:
        action = next((t for t in command[1:] if t in XCODEBUILD_ACTIONS), None)
        if action is None:
            return None
        tool = "xcodebuild"
    else:
        if re.search(r"swift\s+(?:build|test)\b", text) or any(t in XCODEBUILD_ACTIONS for t in tokens) \
                and "xcodebuild" in text:
            findings.append(f"CI-SHAPE {where}: a build or test command that does not start its line, which "
                            f"this scan cannot hold to its flags: {text[:120]}")
        return None

    def after(flag):
        position = command.index(flag) if flag in command else -1
        return command[position + 1] if 0 <= position < len(command) - 1 else None

    tee = rest[2] if len(rest) == 3 and rest[:2] == ["|", "tee"] else None
    if rest and tee is None:
        findings.append(f"CI-LEG {where}: `{' '.join(rest)}` follows the leg; its own status must decide the "
                        f"step, so only `| tee <file>` (under pipefail) may follow it")
    return {"step": step_index, "line": number, "tool": tool, "action": action, "tokens": command,
            "destination": after("-destination"), "bundle": after("-resultBundlePath"), "tee": tee}


def check_flags(leg, findings):
    where = f"CI-STRICT {WORKFLOW}:{leg['line']}"
    tokens = leg["tokens"]
    label = f"{leg['tool']} {leg['action']}"
    if leg["tool"] == "swift":
        if not any(pair == SWIFTPM_FLAG for pair in zip(tokens, tokens[1:])):
            findings.append(f"{where}: `{label}` lacks `-Xswiftc -warnings-as-errors` (Power of 10 rule 10, "
                            f"set on the command line)")
    else:
        missing = [flag for flag in XCODEBUILD_OVERRIDES if flag not in tokens]
        if missing:
            findings.append(f"{where}: `{label}` lacks " + " ".join(missing) + " (Power of 10 rule 10, the "
                            f"strict build's overrides)")
    contrary = [t for t in tokens if t in CONTRARY_FLAGS]
    if contrary:
        findings.append(f"{where}: `{label}` passes " + " ".join(contrary) + ", which undoes warnings as "
                        f"errors")


def check_floor(leg, lines_of_step, findings):
    """The floor reads what this test leg ran, later in the same step."""
    where = f"CI-FLOOR {WORKFLOW}:{leg['line']}"
    label = f"{leg['tool']} {leg['action']}"
    if leg["tee"] is None:
        findings.append(f"{where}: `{label}` does not capture its output with `| tee <file>` for the floor")
        return
    if leg["tool"] == "swift":
        expected = ["python3", FLOOR, "swift-test", leg["tee"]]
    elif leg["bundle"] is None:
        findings.append(f"{where}: `{label}` writes no result bundle (-resultBundlePath) for the floor to read")
        return
    else:
        expected = ["python3", FLOOR, "xcresult", leg["bundle"], "--log", leg["tee"]]
    later = [tokens_of(text) for number, text in lines_of_step if number > leg["line"]]
    if expected not in later:
        findings.append(f"{where}: no `{' '.join(expected)}` after `{label}` in its step; the test-count floor "
                        f"must read every test leg's run")


def check_pipefail(leg, lines_of_step, findings):
    if leg["tee"] is None:
        return
    earlier = [tokens_of(text) or [] for number, text in lines_of_step if number < leg["line"]]
    if not any(tokens[:1] == ["set"] and "pipefail" in tokens for tokens in earlier):
        findings.append(f"CI-LEG {WORKFLOW}:{leg['line']}: `{leg['tool']} {leg['action']}` is piped through "
                        f"tee without `set -o pipefail` before it, so tee's status would decide the step")


def check_walls(steps, legs, repo, findings):
    names = [s["keys"].get("name") for s in steps]
    if names.count(WALLS_STEP) != 1:
        findings.append(f"CI-WALLS {WORKFLOW}: {names.count(WALLS_STEP)} steps named `{WALLS_STEP}`; one runs "
                        f"every wall")
        return 0
    index = names.index(WALLS_STEP)
    walls = steps[index]
    if "if" in walls["keys"]:
        findings.append(f"CI-WALLS {WORKFLOW}:{walls['line']}: the Walls step runs under `if:`; it runs on "
                        f"every event")
    if any(leg["step"] < index for leg in legs):
        findings.append(f"CI-WALLS {WORKFLOW}:{walls['line']}: a leg runs before the Walls step")
    words = [t for _, text in logical_lines(walls) for t in (tokens_of(text) or [])]
    scripts = sorted(n for n in os.listdir(os.path.join(repo, SCRIPTS)) if n.endswith(".py"))
    for name in scripts:
        if name not in words:
            findings.append(f"CI-WALLS {WORKFLOW}:{walls['line']}: the Walls step does not run Scripts/{name}")
    floor = os.path.basename(FLOOR)
    if not any(a == floor and b == "declared" for a, b in zip(words, words[1:])):
        findings.append(f"CI-WALLS {WORKFLOW}:{walls['line']}: the Walls step does not run `{floor} declared`")
    return len(scripts)


def scan(repo, findings):
    path = os.path.join(repo, WORKFLOW)
    if not os.path.isfile(path):
        findings.append(f"CI-SHAPE {WORKFLOW}: missing")
        return {}
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    steps = read_steps(text.split("\n"), findings)
    legs, floors = [], 0
    for index, step in enumerate(steps):
        lines_of_step = logical_lines(step)
        step_legs = [leg for leg in (read_leg(index, n, t, findings) for n, t in lines_of_step) if leg]
        for leg in step_legs:
            check_flags(leg, findings)
            check_pipefail(leg, lines_of_step, findings)
            if is_test(leg):
                before = len(findings)
                check_floor(leg, lines_of_step, findings)
                floors += len(findings) == before
        if "continue-on-error" in step["keys"]:
            findings.append(f"CI-GATE {WORKFLOW}:{step['line']}: `continue-on-error` lets a failing step pass "
                            f"the job")
        if step_legs:
            wanted = TEST_CONDITION if any(is_test(leg) for leg in step_legs) else BUILD_CONDITION
            if step["keys"].get("if") != wanted:
                findings.append(f"CI-GATE {WORKFLOW}:{step['line']}: the step runs if "
                                f"`{step['keys'].get('if')}`, "
                                f"not `{wanted}`")
        legs.extend(step_legs)
    for label, wanted in REQUIRED_LEGS:
        if not any(wanted(leg) for leg in legs):
            findings.append(f"CI-LEG {WORKFLOW}: no leg is {label}")
    named = any(is_ios(leg) and leg["destination"] == IOS_DESTINATION for leg in legs)
    if named and IOS_DESTINATION_EXPORT not in text:
        findings.append(f"CI-LEG {WORKFLOW}: the iOS test leg's {IOS_DESTINATION} is never set to an iOS "
                        f"Simulator")
    walls = check_walls(steps, legs, repo, findings)
    return {"steps": len(steps), "legs": legs, "floors": floors, "walls": walls}


def main():
    repo = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    findings = []
    counts = scan(repo, findings)
    for line in findings:
        print(line)
    legs = counts.get("legs", [])
    tests = sum(1 for leg in legs if is_test(leg))
    print(f"\n{WORKFLOW}: {counts.get('steps', 0)} steps; legs: {len(legs)} "
          f"({sum(1 for leg in legs if leg['tool'] == 'swift')} SwiftPM, "
          f"{sum(1 for leg in legs if leg['tool'] == 'xcodebuild')} xcodebuild), {tests} of them test legs, "
          f"{counts.get('floors', 0)} followed by the floor; walls run: {counts.get('walls', 0)} scripts; "
          f"violations: {len(findings)}", file=sys.stderr)
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
