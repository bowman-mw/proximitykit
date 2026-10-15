// MeshP7AcceptanceTests.swift
// ProximityKitTests
//
// Network migration **P7's acceptance battery** (plan §13.4, launcher item 7): one serialized suite
// per clause, each promoting the named tier-1 claims of the item it speaks for and running its
// clause END TO END on the shipping seams, so CI gating a clause fails on this battery's own
// assertions. Where an exhaustive space already exists it is CITED and re-run whole rather than
// sampled — the §11.4 idiom, and the reason the run-policy clause evaluates all 23 040 rows here.
// That is 2⁷ flag rows again with a different seventh Bool: P9-3-A's fix retired `appLockEngaged`
// (23 040 → 11 520, 2026-09-22) and session photos U3 added `sessionPhotoReviewBlocksDiscovery`
// (11 520 → 23 040, 2026-09-30).
//
// **Six suites.** The run policy (item 1), the gate's single writer (item 2), the radios' seams
// (item 3), the poller's three consumers each driven to a verdict (item 4), the resume decision
// over every restore outcome (item 5), and an honesty suite naming what the battery does not claim.
// `CIGateSelectorBoundaryTests` therefore moves its battery pin from 36 to 42.
//
// **Written without a toolchain.** The session that wrote this battery (2026-09-18) could not build
// or run it; its first Mac run is its first execution, and the honesty suite says so rather than
// leaving it to be inferred. The two determinism digests keep their one home in
// `MeshP5DeterminismAcceptanceTests`; nothing in P7 touched the overlay, a schedule draw or
// `MeshScheduleEvent`, and this file spells neither digest.
//
// A partial copy (ProximityKit plan step A1.3, batch D: the cells of the Fernlet repository's tests
// that read this module's sources, copied before Fernlet deletes its in-tree copy of the module): of
// that repository's FernletTests file of the same name, this holds only the half of
// `MeshP7HonestyAcceptanceTests.theBatteryNamesWhatItDoesNotClaim` that reads ProximityKit's code,
// under the suite's and the test's names, and the source walker and home list it and the copied P8 and
// P9 cells read through (`MeshP7Acceptance`), which walks this module through `PackageSwiftFiles`.
// The rest of the file, and the cell's other half (the run vocabulary, the app's continuation feed and
// the digest homes), stay there, so what this header says of the rest is not held here.

import Foundation
import Testing

// MARK: - MeshP7Acceptance

/// The thin rig the copied P7, P8 and P9 source cells share: the walker over ProximityKit's module and
/// the per-occurrence home list. Fernlet's `MeshP7Acceptance.sources(under:)` walks a folder of that
/// repository; this one walks the module's own folder through ``PackageSwiftFiles/sources()``, or one
/// of its subfolders, and reads each file comment-stripped (``MeshRoutedSourceScan/codeOnly(_:)``), by
/// its file name, as the original does.
///
/// **Floors.** It holds none: each caller expects its read at or above its own floor, in its own cell.
///
/// **Concurrency.** Stateless: every member reads the disk or a value; safe from any isolation.
nonisolated enum MeshP7Acceptance {

    /// Every Swift file of ProximityKit's module, comment-stripped, by file name, sorted by path.
    ///
    /// - Returns: Each file's name and its code.
    /// - Throws: The walker's read error.
    static func sources() throws -> [(name: String, code: String)] {
        try sources(under: nil)
    }

    /// Every Swift file under `folder` of ProximityKit's module (a path under
    /// ``PackageSwiftFiles/sourceFolder``, e.g. `PairSession`), or of the whole module when `folder` is
    /// nil, comment-stripped, by file name, sorted by path.
    ///
    /// - Parameter folder: A folder under the module's source folder, or nil for the whole module.
    /// - Returns: Each file's name and its code.
    /// - Throws: The walker's read error.
    static func sources(under folder: String?) throws -> [(name: String, code: String)] {
        var sources: [(name: String, code: String)] = []
        // R2: bounded by the module's own file list.
        for file in try PackageSwiftFiles.sources() {
            if let folder, !file.path.hasPrefix(folder + "/") { continue }
            let name = file.path.split(separator: "/").last.map(String.init) ?? file.path
            sources.append((name, MeshRoutedSourceScan.codeOnly(file.text)))
        }
        return sources
    }

    /// The file names in which `needle` occurs, one entry per occurrence.
    ///
    /// - Parameters:
    ///   - needle: The text to find.
    ///   - sources: The files to read, as ``sources()`` returns them.
    /// - Returns: A file's name once per occurrence of `needle` in its code.
    static func homes(of needle: String, in sources: [(name: String, code: String)]) -> [String] {
        var homes: [String] = []
        // R2: bounded by the file list.
        for source in sources {
            let count = source.code.components(separatedBy: needle).count - 1
            homes.append(contentsOf: Array(repeating: source.name, count: count))
        }
        return homes
    }
}

// MARK: - (f) Honesty

/// **What P7's battery deliberately does NOT claim, named rather than implied**: the half of its
/// honesty cell that reads ProximityKit's code.
@MainActor
@Suite(.serialized)
struct MeshP7HonestyAcceptanceTests {

    /// `.continuingInBackground` is reached by no path P7 owns — P8 item 5 gave the two scene events
    /// one shipping raiser each, so this cell pins that pair rather than a zero. The original cell's
    /// other claims (the run vocabulary's four values, the app's continuation feed, the digest homes)
    /// read Fernlet's types and files and stay in Fernlet's copy of the cell.
    @Test func theBatteryNamesWhatItDoesNotClaim() throws {
        let kit = try MeshP7Acceptance.sources()
        #expect(kit.count >= 100, "the ProximityKit scan lost its files")
        let raised = MeshP7Acceptance.homes(of: "applySessionEvent(.backgrounded", in: kit)
            + MeshP7Acceptance.homes(of: "applySessionEvent(.foregrounded", in: kit)
        #expect(raised == ["MeshNetworkManager.swift", "MeshNetworkManager.swift"], """
            P8 item 5 gave the two scene events their first shipping raisers — the public \
            beginBackgroundContinuation() / endBackgroundContinuation() pair, one each, in the \
            manager — so .continuingInBackground is reachable from a shipping path as of that item \
            and P7's unreachable claim retired with it. The live count lives in \
            MeshContinuationRaiseWallTests
            """)
    }
}
