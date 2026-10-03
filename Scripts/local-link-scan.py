#!/usr/bin/env python3
"""Local-link wall for ProximityKit: Network.framework's local-network API only in the radio files.

Ported from onlyThePinnedMeshTransportsMayHoldALocalLinkNetworkAPI() in the Fernlet repository's
Tests/FernletTests/NoTrackingBoundaryTests.swift (https://github.com/bowman-mw/fernlet), which
held this code to the same rule while it lived there. The markers and the matching are copied
from that file unchanged, and the permitted files are its permittedLocalLinkFiles, re-pathed.

Usage: Scripts/local-link-scan.py
Prints one line per violation and a summary to stderr; exits 1 on any violation.

What counts: a Swift file under Sources/ that names one of LOCAL_LINK_MARKERS in code, at an
identifier boundary. Comment-only lines are skipped (the radio files and their neighbours
document the API at length); a trailing comment does not hide a call. Test code is out of scope,
as it was in Fernlet, where the rule covered shipping code.

The rule is pinned in both directions:
  * a file outside PERMITTED_LOCAL_LINK_FILES that names the API is a new local-network
    capability, and a review moment: it fails until the file is added here with a reason;
  * a permitted file that is missing, or no longer names the API, means the scan stopped seeing
    the radios (renamed, moved, or the markers went stale), so it fails too. This direction,
    and the refusal to pass after reading zero files, start once Sources/ProximityKit exists.
    The code arrives later with its git history from the Fernlet repository; until then an
    empty tree passes.

The legacy spellings NWConnection and NWBrowser are deliberately absent from LOCAL_LINK_MARKERS.
They belong to the HTTP-client family in Scripts/no-tracking-scan.py, which permits no file at
all, so they stay banned everywhere, the radio files included. Listing them here would hand them
the radios' permission.
"""
import os
import sys

SOURCE_ROOT = "Sources"
IMPORT_ROOT = os.path.join("Sources", "ProximityKit")   # the held checks start once this exists

# Network.framework's local-link surface: the TN3213 API the radios are built on (NetworkConnection,
# NetworkListener, NetworkBrowser) plus the parameter and TXT-record types that come with it.
# NWListener and NWParameters match nothing today and are listed anyway, so the first one to appear
# is a deliberate edit here.
LOCAL_LINK_MARKERS = (
    "NetworkConnection", "NetworkListener", "NetworkBrowser",
    "NWListener", "NWParameters", "NWParametersBuilder", "NWTXTRecord",
)

# The files that may name a local-link API. All three are link-local by construction: they advertise
# and browse a Bonjour service type over QUIC with `prohibitedInterfaceTypes = [.cellular]`, and every
# byte they carry is a signed or sealed envelope between two devices in the same room. Fernlet's list
# also names NetworkMeshFeasibilityProbe.swift, a DEBUG-only spike that lives in the Fernlet app and
# stays there.
PERMITTED_LOCAL_LINK_FILES = (
    # The QUIC mesh transport: listener, browser, per-peer connections.
    "Sources/ProximityKit/Transport/NetworkMeshSession.swift",
    # The QUIC presence radio: the same three, advertising under a PresenceEpochPosture that is
    # replaced whole at every 900 s epoch boundary.
    "Sources/ProximityKit/Transport/NetworkPresenceSession.swift",
    # The QUIC recipe-share radio: the same three, advertising under a RecipeSharePosture minted per
    # start and per resume, and standing the listener and the browser down while a pairing is held.
    "Sources/ProximityKit/Transport/NetworkRecipeShareSession.swift",
)


def is_identifier_char(ch):
    return ch == "_" or ch.isalnum()


def names_symbol(text, token):
    """True iff `token` occurs in `text` with no identifier character on either side, so a longer
    name (`NetworkListenerFake`) is never the API."""
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
    """Comment-only lines, as Fernlet's NoTrackingBoundaryTests.codeOnly(_:) drops them."""
    return line.strip().startswith(("//", "*", "/*"))


def local_link_markers(line):
    if is_comment_only(line):
        return []
    return [m for m in LOCAL_LINK_MARKERS if names_symbol(line, m)]


def swift_files(root):
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", ".build")]
        found.extend(os.path.join(dirpath, n) for n in filenames if n.endswith(".swift"))
    return sorted(found)


def main():
    repo = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    imported = os.path.isdir(os.path.join(repo, IMPORT_ROOT))
    permitted = set(PERMITTED_LOCAL_LINK_FILES)
    findings = []
    holders = set()

    files = swift_files(os.path.join(repo, SOURCE_ROOT))
    for path in files:
        rel = os.path.relpath(path, repo).replace(os.sep, "/")
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().split("\n")
        for number, line in enumerate(lines, start=1):
            markers = local_link_markers(line)
            if not markers:
                continue
            holders.add(rel)
            if rel not in permitted:
                findings.append(f"LL-UNPERMITTED {rel}:{number}: names {', '.join(markers)} outside the radio "
                                f"files: {line.strip()[:140]}")

    if imported:
        for rel in PERMITTED_LOCAL_LINK_FILES:
            if not os.path.isfile(os.path.join(repo, rel)):
                findings.append(f"LL-MISSING {rel}: a permitted radio file is missing (renamed or moved?); "
                                f"fix PERMITTED_LOCAL_LINK_FILES in the same commit")
            elif rel not in holders:
                findings.append(f"LL-STALE {rel}: a permitted radio file no longer names a local-link API "
                                f"(the markers went stale, or the radio moved); coverage dropped")

    vacuous = imported and not files
    for line in findings:
        print(line)
    print(f"\nSwift files scanned under {SOURCE_ROOT}/: {len(files)}; files naming a local-link API: "
          f"{len(holders)} ({len(holders & permitted)} of {len(permitted)} permitted); "
          f"violations: {len(findings)}", file=sys.stderr)
    if vacuous:
        print(f"no Swift files under {SOURCE_ROOT}/ although {IMPORT_ROOT} exists: refusing to pass vacuously",
              file=sys.stderr)
    elif not imported:
        print(f"{IMPORT_ROOT} does not exist yet; the permitted-file and floor checks wait for it",
              file=sys.stderr)
    sys.exit(1 if findings or vacuous else 0)


if __name__ == "__main__":
    main()
