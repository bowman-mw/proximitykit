#!/usr/bin/env python3
"""Mechanical half of the Power-of-10 wall for ProximityKit.

Ported from Scripts/power-of-10-scan.py in the Fernlet repository
(https://github.com/bowman-mw/fernlet), where this code lived and was held to Gerard Holzmann's
Power of 10 rules as that repository's Docs/Power-of-10-Swift.md adapts them to Swift. The
tokenizer, the body finder and every check are copied unchanged. What is this repository's own:
the roots, the test-code policy and the pre-import mode, all described below.

Scans Swift for the checks that a line-level tokenizer can decide, and exits 1 on any violation
not covered by Scripts/power-of-10-allowlist.json. The enforced baseline is ZERO for every
enforced check; the allowlist is the only escape hatch and every entry carries a reason.

Usage:
    Scripts/power-of-10-scan.py                 # scan Sources/ and Tests/, human-readable
    Scripts/power-of-10-scan.py --json          # same, machine-readable (one JSON object)
    Scripts/power-of-10-scan.py --advisory      # ALSO print the review-only signals (all `while`
                                                #   loops, `_ =` discards, @discardableResult,
                                                #   direct-recursion guesses, and the test-code
                                                #   hits of TEST_ADVISORY_RULES)
    Scripts/power-of-10-scan.py <root> ...      # scan specific roots/files instead
    Scripts/power-of-10-scan.py --allowlist a.json[:b.json] ...   # use these allowlist file(s) instead

Roots:
    Sources/  Shipping code. Every enforced check below applies, and only Sources/ counts toward
              the R5-DENSITY floor.
    Tests/    Test code, under the standard's test exemption: "Test code is exempt from R4/R5/R7
              (tests trap on purpose)". So R4-LENGTH, R5-FORCE, R5-TRAP and R7-SWALLOW never
              fire there, the R7-DISCARD review list skips tests, and test bodies stay out of the
              density ratio (TEST_EXEMPT_RULES). R6 and R8 are enforced in tests exactly as in
              shipping code. R2-WHILE-TRUE and R9-UNSAFE are reported in tests under --advisory
              only (TEST_ADVISORY_RULES): Fernlet's scanner never scanned test code, and its
              tests poll with `while true` and copy key bytes out through `withUnsafeBytes`, so
              enforcing those two in tests would ask the imported suites for allowlist entries
              the shipping code does not need. Deleting a rule ID from TEST_ADVISORY_RULES is the
              whole change when tests should be held to it.

Before the import:
    The code arrives later with its git history from the Fernlet repository. Until
    Sources/ProximityKit exists (IMPORT_ROOT), three checks that need the code are held, and each
    starts by itself the moment that directory appears:
      * the refusal to pass after scanning zero Swift files;
      * the unused-entry check, which fails the scan on an allowlist entry that matches nothing,
        an entry whose file is missing included;
      * the R5-DENSITY floor, while there is no logic function to measure.
    Every per-line check runs from the start, on whatever Swift exists.

Checks (IDs match the Fernlet repository's Docs/Power-of-10-Swift.md):
    R1-RECURSION   advisory: a function whose body calls its own name (direct recursion guess).
    R2-WHILE-TRUE  enforced: `while true` / `repeat ... while true` (loops without a bound).
    R2-WHILE       advisory: every `while` loop, for bound review.
    R4-LENGTH      enforced: any func/init/deinit/subscript/computed-property/`body` whose body has
                   more than 60 code lines (blank + comment-only lines do not count).
    R5-FORCE       enforced: postfix `!` force-unwrap, `try!`, `as!`, and `T!` (IUO) declarations.
    R5-TRAP        enforced: `fatalError(` / `preconditionFailure(` in shipping code (allowlist).
    R5-DENSITY     enforced floor: (guard + assert + precondition) / logic functions (func / init /
                   deinit / subscript bodies with >= 3 code lines; computed vars and closures
                   excluded) must not drop below DENSITY_FLOOR (a ratchet; raise it, never lower it).
    R6-FILE-VAR    enforced: `var` at file scope (a mutable global).
    R6-STATIC-VAR  enforced: STORED `static var` (a mutable global in a namespace); allowlist.
    R7-SWALLOW     enforced: bare-statement `try?` / `_ = try?` (error swallowed, result unused).
    R7-DISCARD     advisory: `_ = <expr>` result discards, and every @discardableResult declaration.
    R8-IF-COND     enforced: `#if` conditions outside the allowed set (DEBUG, canImport, os,
                   targetEnvironment, swift, compiler, arch; optionally negated / combined).
    R8-IF-NEST     enforced: `#if` nested inside another `#if`.
    R9-UNSAFE      enforced: Unsafe*Pointer / withUnsafe* / unsafeBitCast / Unmanaged /
                   unowned(unsafe) / nonisolated(unsafe); allowlist per file with a reason.

Allowlist entries (Scripts/power-of-10-allowlist.json, a JSON array):
    {"rule": "R9-UNSAFE", "path": "Sources/ProximityKit/...", "reason": "..."}
    {"rule": "R4-LENGTH", "path": "...", "symbol": "someFunction", "reason": "..."}
    {"rule": "R5-FORCE", "path": "...", "line_contains": "...", "reason": "..."}
`path` is repo-relative and required. `symbol` (function name) or `line_contains` (substring of the
offending code line) narrows a file-wide entry; an entry with neither covers every hit of that rule
in that file (use only for R9-UNSAFE, and say why in the reason). Unused entries are reported so the
allowlist cannot silently rot.
"""
import json
import os
import re
import sys

DENSITY_FLOOR = 0.68          # ratchet (the standard's R5 section); only ever raise it
MAX_BODY_LINES = 60           # NASA rule 4: one printed page

SHIPPING_ROOTS = ("Sources",)
TEST_ROOTS = ("Tests",)
IMPORT_ROOT = os.path.join("Sources", "ProximityKit")   # the held checks start once this exists

# The standard's test exemption: tests trap on purpose. Never reported for test code.
TEST_EXEMPT_RULES = ("R4-LENGTH", "R5-FORCE", "R5-TRAP", "R7-SWALLOW", "R7-DISCARD")
# Rules the standard keeps for tests but Fernlet's scanner never enforced there: in test code they
# are review signals, printed with --advisory, and never fail the scan.
TEST_ADVISORY_RULES = ("R2-WHILE-TRUE", "R9-UNSAFE")

ALLOWED_IF_TOKENS = ("DEBUG", "canImport", "os", "targetEnvironment", "swift", "compiler", "arch")

DECL_HEAD_RE = re.compile(
    r"^\s*(?:@\w[\w.]*(?:\([^)]*\))?\s+)*"
    r"(?:(?:public|open|internal|package|private|fileprivate|final|override|static|class|mutating|"
    r"nonmutating|nonisolated|convenience|required|dynamic|consuming|borrowing|indirect|distributed|"
    r"lazy|weak|unowned|optional|prefix|postfix|infix)\s+)*"
    r"(?:(?P<kind>func)\s+(?P<fname>[A-Za-z_]\w*|`[^`]+`|[-+*/%<>=!&|^~?.]+)"
    r"|(?P<init>init)\b[?!]?"
    r"|(?P<deinit>deinit)\b"
    r"|(?P<subscript>subscript)\b"
    r"|(?P<var>var)\s+(?P<vname>[A-Za-z_]\w*)\s*:[^{=]*?\{\s*$"
    r"|(?P<var2>var)\s+(?P<vname2>[A-Za-z_]\w*)\s*:[^{=]*$"
    r")"
)
CLOSURE_ONLY_RE = re.compile(r"^\s*(?:let|var)\s+\w+\s*(?::[^=]*)?=\s*\{")


def strip_code(line, st):
    """Return the code-only portion of `line` (strings → "", comments removed), updating tokenizer
    state `st` = {"block": nesting depth of /* */, "mls": inside a multi-line string literal,
    "raw": raw-string hash count for the open multi-line string}. Approximate but line-faithful."""
    out = []
    i, n = 0, len(line)
    if st["mls"]:
        close = '"""' + "#" * st["raw"]
        idx = line.find(close)
        if idx == -1:
            return "", st, True   # a payload line inside a multi-line string counts as code
        st["mls"] = False
        i = idx + len(close)
    if st["block"] > 0:
        while i < n and st["block"] > 0:
            o, c = line.find("/*", i), line.find("*/", i)
            if c == -1:
                return "".join(out), st, False
            if o != -1 and o < c:
                st["block"] += 1
                i = o + 2
            else:
                st["block"] -= 1
                i = c + 2
    while i < n:
        if line.startswith("//", i):
            break
        if line.startswith("/*", i):
            st["block"] = 1
            i += 2
            while i < n and st["block"] > 0:
                o, c = line.find("/*", i), line.find("*/", i)
                if c == -1:
                    return "".join(out), st, bool("".join(out).strip())
                if o != -1 and o < c:
                    st["block"] += 1
                    i = o + 2
                else:
                    st["block"] -= 1
                    i = c + 2
            continue
        # raw / multi-line / plain string literals
        m = re.match(r'(#*)"""', line[i:])
        if m:
            hashes = len(m.group(1))
            open_len = hashes + 3
            close = '"""' + "#" * hashes
            j = line.find(close, i + open_len)
            out.append('""')
            if j == -1:
                st["mls"] = True
                st["raw"] = hashes
                return "".join(out), st, True
            i = j + len(close)
            continue
        m = re.match(r'(#+)"', line[i:])
        if m:
            hashes = len(m.group(1))
            close = '"' + "#" * hashes
            j = line.find(close, i + hashes + 1)
            out.append('""')
            i = n if j == -1 else j + len(close)
            continue
        ch = line[i]
        if ch == '"':
            j, depth = i + 1, 0
            while j < n:
                cj = line[j]
                if cj == "\\":
                    if j + 1 < n and line[j + 1] == "(":
                        depth += 1
                        j += 2
                        continue
                    j += 2
                    continue
                if depth > 0:
                    if cj == "(":
                        depth += 1
                    elif cj == ")":
                        depth -= 1
                    j += 1
                    continue
                if cj == '"':
                    break
                j += 1
            out.append('""')
            i = j + 1
            continue
        out.append(ch)
        i += 1
    code = "".join(out)
    return code, st, bool(code.strip())


def tokenize(lines):
    """Return per-line (code_text, is_code_line)."""
    st = {"block": 0, "mls": False, "raw": 0}
    res = []
    for raw in lines:
        code, st, is_code = strip_code(raw.rstrip("\n"), st)
        res.append((code, is_code))
    return res


SIGNATURE_CONTINUATION = ("{", "->", "where", "throws", "rethrows", "async", "reasync")
CLOSURE_DECL_RE = re.compile(r"^\s*(?:@\w[\w.]*(?:\([^)]*\))?\s+)*(?:(?:public|private|fileprivate|internal|"
                             r"package|static|lazy|final|nonisolated|nonisolated\(unsafe\))\s+)*(?:let|var)\s+"
                             r"(?P<name>[A-Za-z_]\w*)\s*(?::[^=]*)?=\s*\{\s*$")


def _match_decl(code):
    """Return a fresh pending record for a declaration head on this line, or None."""
    m = CLOSURE_DECL_RE.match(code)
    if m:
        # `let table: [X] = {`: a closure literal initialiser is a function in disguise
        return {"name": m.group("name"), "kind": "closure", "decl": None, "paren": 0, "seen_paren": True}
    if CLOSURE_ONLY_RE.match(code):
        return None
    m = DECL_HEAD_RE.match(code)
    if not m:
        return None
    if m.group("kind"):
        return {"name": m.group("fname"), "kind": "func", "decl": None, "paren": 0, "seen_paren": False}
    if m.group("init"):
        return {"name": "init", "kind": "init", "decl": None, "paren": 0, "seen_paren": False}
    if m.group("deinit"):
        return {"name": "deinit", "kind": "deinit", "decl": None, "paren": 0, "seen_paren": True}
    if m.group("subscript"):
        return {"name": "subscript", "kind": "subscript", "decl": None, "paren": 0, "seen_paren": False}
    if m.group("var"):
        return {"name": m.group("vname"), "kind": "var", "decl": None, "paren": 0, "seen_paren": True}
    if m.group("var2"):
        # `var x: T` alone on its line is computed only if the NEXT line opens a `{`; a stored
        # property or protocol requirement is dropped when anything else follows.
        return {"name": m.group("vname2"), "kind": "var?", "decl": None, "paren": 0, "seen_paren": True}
    return None


def find_bodies(code_lines):
    """Locate function-like bodies (func / init / deinit / subscript / computed var / closure
    initialiser). Returns dicts {name, kind, start, open, close, code_lines}; line numbers are
    1-based and `code_lines` counts code lines strictly inside the braces.

    A declaration head becomes `pending` until its body brace opens. The brace that opens the body is
    the first `{` reached with the signature's parentheses balanced, so a default-value closure inside
    the parameter list (`handler: () -> Void = { }`) does not start the body early. A pending
    signature that is complete (parens balanced) and is followed by a line that does not continue it
    is a protocol requirement / stored property and is dropped; that same line is then examined
    as a fresh declaration head, so back-to-back declarations are never swallowed."""
    bodies = []
    stack = []      # (name, kind, decl_line, depth_at_open, open_line)
    depth = 0
    pending = None
    for idx, (code, _) in enumerate(code_lines):
        stripped = code.strip()
        if not stripped:
            continue
        # 1. retire a stale pending head
        if pending is not None and idx > pending["decl"]:
            if pending["kind"] == "var?":
                if not stripped.startswith("{"):
                    pending = None
            elif pending["paren"] == 0 and pending["seen_paren"]:
                if not stripped.startswith(SIGNATURE_CONTINUATION):
                    pending = None
            elif idx - pending["decl"] > 40:
                pending = None
        # 2. a fresh declaration head?
        if pending is None:
            pending = _match_decl(code)
            if pending is not None:
                pending["decl"] = idx
        # 3. scan braces / parens
        for ch in code:
            if ch == "(":
                if pending is not None:
                    pending["paren"] += 1
                    pending["seen_paren"] = True
            elif ch == ")":
                if pending is not None:
                    pending["paren"] -= 1
            elif ch == "{":
                if pending is not None and pending["paren"] <= 0:
                    kind = "var" if pending["kind"] == "var?" else pending["kind"]
                    stack.append((pending["name"], kind, pending["decl"], depth, idx))
                    pending = None
                depth += 1
            elif ch == "}":
                depth -= 1
                if stack and stack[-1][3] == depth:
                    name, kind, decl, _, open_line = stack.pop()
                    count = sum(1 for k in range(open_line + 1, idx) if code_lines[k][1])
                    bodies.append({"name": name, "kind": kind, "start": decl + 1,
                                   "open": open_line + 1, "close": idx + 1, "code_lines": count})
    return bodies


FORCE_UNWRAP_RE = re.compile(r"(?<![!=<>&|(\[,\s{])[\w\)\]\?]!(?![=])")
IUO_RE = re.compile(r"\b(?:var|let)\s+\w+\s*:\s*[A-Za-z_][\w<>.,\[\]: ]*?!\s*(?:=|$|,|\))")
TRY_BANG_RE = re.compile(r"\btry!")
AS_BANG_RE = re.compile(r"\bas!")
TRAP_RE = re.compile(r"\b(?:fatalError|preconditionFailure)\s*\(")
WHILE_TRUE_RE = re.compile(r"\bwhile\s*\(?\s*true\s*\)?\s*(?:\{|$)")
WHILE_RE = re.compile(r"^\s*(?:\w+\s*:\s*)?while\b")
SWALLOW_RE = re.compile(r"^\s*(?:_\s*=\s*)?try\?\s")
DISCARD_RE = re.compile(r"^\s*_\s*=\s*(?!try\?)")
DISCARDABLE_RE = re.compile(r"@discardableResult")
UNSAFE_RE = re.compile(r"\bUnsafe(?:Mutable)?(?:Raw)?(?:Buffer)?Pointer\b|\bwithUnsafe\w*|\bunsafeBitCast\b|"
                       r"\bUnmanaged\b|\bunowned\(unsafe\)|\bnonisolated\(unsafe\)|\bunsafeDowncast\b|"
                       r"\bunsafelyUnwrapped\b|\bUnsafeContinuation\b|\bwithUnsafeContinuation\b")
FILE_VAR_RE = re.compile(r"^(?:(?:public|private|fileprivate|internal|package|nonisolated\(unsafe\))\s+)*var\s+\w+")
STATIC_VAR_RE = re.compile(r"^\s*(?:(?:public|private|fileprivate|internal|package|nonisolated\(unsafe\)|open|final|override|class)\s+)*static\s+var\s+(\w+)(?P<rest>.*)$")
IF_RE = re.compile(r"^\s*#if\s+(.*)$")
GUARD_RE = re.compile(r"^\s*guard\b")
ASSERT_RE = re.compile(r"\b(?:assert|assertionFailure|precondition)\s*\(")
DENSITY_MIN_LINES = 3
# Density is measured over LOGIC functions only: func / init / deinit / subscript bodies. Computed
# properties (SwiftUI `body` and view fragments) and closure initialisers are excluded: a view tree
# has nothing to guard, and splitting long bodies (R4) would otherwise dilute the ratio.
DENSITY_KINDS = ("func", "init", "deinit", "subscript")


def scan_file(rel, lines):
    tokens = tokenize(lines)
    bodies = find_bodies(tokens)
    hits = []      # (rule, line, symbol, text)
    advisory = []  # (rule, line, symbol, text)

    def emit(rule, idx, symbol, text=None, adv=False):
        (advisory if adv else hits).append({"rule": rule, "path": rel, "line": idx + 1,
                                            "symbol": symbol, "text": (text or lines[idx]).strip()[:160]})

    # -- bodies: length, density, recursion
    n_funcs = 0
    n_checks = 0
    for b in bodies:
        if b["code_lines"] > MAX_BODY_LINES:
            emit("R4-LENGTH", b["start"] - 1, b["name"],
                 f"{b['kind']} {b['name']}: {b['code_lines']} code lines (max {MAX_BODY_LINES})")
        if b["code_lines"] >= DENSITY_MIN_LINES and b["kind"] in DENSITY_KINDS:
            n_funcs += 1
            for k in range(b["open"], b["close"] - 1):
                code = tokens[k][0]
                if GUARD_RE.match(code):
                    n_checks += 1
                n_checks += len(ASSERT_RE.findall(code))
        if b["kind"] == "func" and re.match(r"^[A-Za-z_]", b["name"]):
            call = re.compile(r"(?<![\w.])(?:self\.)?" + re.escape(b["name"]) + r"\s*\(")
            call_self = re.compile(r"self\." + re.escape(b["name"]) + r"\s*\(")
            for k in range(b["open"], b["close"] - 1):
                code = tokens[k][0]
                if call.search(code) or call_self.search(code):
                    if not re.match(r"^\s*(?:override\s+)?func\s+" + re.escape(b["name"]), code):
                        emit("R1-RECURSION", k, b["name"], adv=True)
                        break

    # -- line-level rules
    depth_stack = []   # #if nesting
    brace_depth = 0
    for idx, (code, is_code) in enumerate(tokens):
        stripped = code.strip()
        if not stripped:
            continue
        m = IF_RE.match(code)
        if m:
            cond = m.group(1).strip()
            toks = re.findall(r"[A-Za-z_]\w*", cond)
            bad = [t for t in toks if t not in ALLOWED_IF_TOKENS
                   and not re.search(r"\b(?:canImport|os|targetEnvironment|swift|compiler|arch)\s*\(\s*" + re.escape(t), cond)]
            if bad:
                emit("R8-IF-COND", idx, cond)
            if depth_stack:
                emit("R8-IF-NEST", idx, cond)
            depth_stack.append(idx)
        elif re.match(r"^\s*#endif\b", code):
            if depth_stack:
                depth_stack.pop()
        if TRY_BANG_RE.search(code):
            emit("R5-FORCE", idx, "try!")
        if AS_BANG_RE.search(code):
            emit("R5-FORCE", idx, "as!")
        if IUO_RE.search(code):
            emit("R5-FORCE", idx, "IUO")
        elif FORCE_UNWRAP_RE.search(code):
            emit("R5-FORCE", idx, "!")
        if TRAP_RE.search(code):
            emit("R5-TRAP", idx, TRAP_RE.search(code).group(0).rstrip("(").strip())
        if WHILE_TRUE_RE.search(code) or re.search(r"\}\s*while\s*\(?\s*true\s*\)?\s*$", code):
            emit("R2-WHILE-TRUE", idx, "while true")
        elif WHILE_RE.match(code) or re.search(r"\}\s*while\b", code):
            emit("R2-WHILE", idx, "while", adv=True)
        if SWALLOW_RE.match(code):
            emit("R7-SWALLOW", idx, "try?")
        elif DISCARD_RE.match(code):
            emit("R7-DISCARD", idx, "_ =", adv=True)
        if DISCARDABLE_RE.search(code):
            emit("R7-DISCARD", idx, "@discardableResult", adv=True)
        um = UNSAFE_RE.search(code)
        if um:
            emit("R9-UNSAFE", idx, um.group(0))
        if brace_depth == 0 and FILE_VAR_RE.match(code):
            emit("R6-FILE-VAR", idx, "var")
        sm = STATIC_VAR_RE.match(code)
        if sm:
            rest = sm.group("rest")
            # computed if a `{` opens on this line and no `=` precedes it; stored otherwise
            eq = rest.find("=")
            br = rest.find("{")
            stored = (br == -1) or (eq != -1 and eq < br)
            if stored:
                emit("R6-STATIC-VAR", idx, sm.group(1))
        brace_depth += code.count("{") - code.count("}")
    return hits, advisory, n_funcs, n_checks


def load_allowlist(repo, override=None):
    """Load the allowlist: Scripts/power-of-10-allowlist.json, or `override` (a path, or several
    joined with ':', to check a change against its own pending fragment of the allowlist)."""
    paths = override.split(":") if override else [os.path.join(repo, "Scripts", "power-of-10-allowlist.json")]
    entries = []
    for path in paths:
        if not os.path.exists(path):
            if override:
                sys.exit(f"allowlist not found: {path}")
            continue
        with open(path, encoding="utf-8") as f:
            entries.extend(json.load(f))
    for e in entries:
        for key in ("rule", "path", "reason"):
            if key not in e or not str(e[key]).strip():
                sys.exit(f"power-of-10-allowlist.json: entry missing '{key}': {e}")
        e["_used"] = 0
    return entries


def allowed(hit, allowlist):
    for e in allowlist:
        if e["rule"] != hit["rule"] or e["path"] != hit["path"]:
            continue
        if "symbol" in e and e["symbol"] != hit["symbol"]:
            continue
        if "line_contains" in e and e["line_contains"] not in hit["text"]:
            continue
        e["_used"] += 1
        return True
    return False


def iter_swift(roots):
    for root in roots:
        if os.path.isfile(root):
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if not d.endswith(".docc") and d not in (".git", ".build")]
            for name in sorted(filenames):
                if name.endswith(".swift"):
                    yield os.path.join(dirpath, name)


def is_test_path(rel):
    """True when the repo-relative path `rel` lies under one of TEST_ROOTS."""
    return rel.split(os.sep, 1)[0] in TEST_ROOTS


def apply_test_policy(hits, advisory):
    """Apply the test-code policy to one test file's findings: TEST_EXEMPT_RULES are dropped,
    TEST_ADVISORY_RULES move to the advisory list, and every other enforced hit stays enforced."""
    enforced = []
    for h in hits:
        if h["rule"] in TEST_EXEMPT_RULES:
            continue
        (advisory if h["rule"] in TEST_ADVISORY_RULES else enforced).append(h)
    return enforced, [a for a in advisory if a["rule"] not in TEST_EXEMPT_RULES]


def strip_used(entry):
    return {k: v for k, v in entry.items() if k != "_used"}


def main(argv):
    as_json = "--json" in argv
    show_adv = "--advisory" in argv
    override = None
    if "--allowlist" in argv:
        i = argv.index("--allowlist")
        override = argv[i + 1] if i + 1 < len(argv) else sys.exit("--allowlist needs a path")
        argv = argv[:i] + argv[i + 2:]
    args = [a for a in argv if not a.startswith("--")]
    # realpath on both sides: a scan through a symlinked path (/tmp is one on macOS) must still
    # produce the repo-relative paths the allowlist names.
    repo = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    imported = os.path.isdir(os.path.join(repo, IMPORT_ROOT))
    roots = args or [os.path.join(repo, r) for r in SHIPPING_ROOTS + TEST_ROOTS]
    allowlist = load_allowlist(repo, override)

    hits, advisory = [], []
    total_funcs = total_checks = 0
    n_files = 0
    for path in iter_swift(roots):
        n_files += 1
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        rel = os.path.relpath(os.path.realpath(path), repo)
        h, a, nf, nc = scan_file(rel, lines)
        if is_test_path(rel):
            h, a = apply_test_policy(h, a)
            nf = nc = 0   # R5 is lifted for tests, so test bodies stay out of the density ratio
        hits.extend(h)
        advisory.extend(a)
        total_funcs += nf
        total_checks += nc

    violations = [h for h in hits if not allowed(h, allowlist)]
    allowed_hits = len(hits) - len(violations)
    unused = [e for e in allowlist if e["_used"] == 0]
    density = (total_checks / total_funcs) if total_funcs else 0.0
    # Held before the import, while there is no logic function to measure: 0/0 is not a ratio.
    density_held = not imported and total_funcs == 0
    density_ok = density_held or density >= DENSITY_FLOOR
    if density_held:
        density_note = "held until " + IMPORT_ROOT + " exists"
    else:
        density_note = "ok" if density_ok else "BELOW FLOOR"

    if as_json:
        out = {
            "files": n_files, "violations": violations, "allowed": allowed_hits,
            "imported": imported,
            "unused_allowlist": [strip_used(e) for e in unused],
            "unused_allowlist_check": "enforced" if imported else "held until " + IMPORT_ROOT + " exists",
            "density": {"checks": total_checks, "functions": total_funcs, "value": round(density, 3),
                        "floor": DENSITY_FLOOR, "ok": density_ok, "held": density_held},
        }
        if show_adv:
            out["advisory"] = advisory
        print(json.dumps(out, indent=1))
    else:
        by_rule = {}
        for v in violations:
            by_rule.setdefault(v["rule"], []).append(v)
        for rule in sorted(by_rule):
            print(f"== {rule}: {len(by_rule[rule])} ==")
            for v in by_rule[rule]:
                print(f"{v['path']}:{v['line']}: [{v['symbol']}] {v['text']}")
        if show_adv:
            adv_by = {}
            for v in advisory:
                adv_by.setdefault(v["rule"], []).append(v)
            for rule in sorted(adv_by):
                print(f"-- advisory {rule}: {len(adv_by[rule])} --")
                for v in adv_by[rule]:
                    print(f"{v['path']}:{v['line']}: [{v['symbol']}] {v['text']}")
        for e in unused:
            if imported:
                missing = "" if os.path.exists(os.path.join(repo, e["path"])) else " (its file is missing)"
                print(f"UNUSED ALLOWLIST ENTRY{missing}: {json.dumps(strip_used(e))}")
            else:
                print(f"held until {IMPORT_ROOT} exists: allowlist entry {e['rule']} {e['path']}",
                      file=sys.stderr)
        print(f"\nfiles scanned: {n_files}; violations: {len(violations)}; allowlisted hits: {allowed_hits}; "
              f"assertion density: {total_checks}/{total_funcs} = {density:.3f} (floor {DENSITY_FLOOR}, "
              f"{density_note})", file=sys.stderr)
    bad = bool(violations) or not density_ok
    if imported:
        bad = bad or bool(unused) or n_files == 0
        if n_files == 0:
            print("no Swift files scanned: refusing to pass vacuously", file=sys.stderr)
    elif n_files == 0:
        print(f"no Swift files yet: {IMPORT_ROOT} does not exist, so the held checks wait for it",
              file=sys.stderr)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main(sys.argv[1:])
