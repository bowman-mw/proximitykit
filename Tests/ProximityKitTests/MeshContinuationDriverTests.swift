// MeshContinuationDriverTests.swift
// ProximityKitTests
//
// Network migration P8 item 5 (plan §14, §24.1, §25.1), in three suites:
//
// 1. `MeshContinuationRaiseWallTests` — **pass 1's wall.** `MeshSessionEvent.backgrounded` and
//    `.foregrounded` had NO shipping raiser at all before this item (P7's own honesty cell counted
//    zero and said so), so `MeshSessionState.continuingInBackground` was unreachable and the heart
//    stage's third leg could not be exercised by anything but a test. The wall says the raises now
//    exist and that there is exactly ONE of each, in one place, reached from the app through one
//    narrow public pair and from one file: three counts, comment-stripped, path-anchored, floored on
//    the file count so a moved root fails loudly rather than passing over nothing.
//
// 2. `MeshContinuationDriverTests` — the driver's own behaviour over a manager with no session:
//    which deliveries are adopted and how, which endings complete, and — the load-bearing negative —
//    that an ending with no task in hand raises nothing at all. On an `idle` manager every raise is
//    refused BY NAME (`lastSessionTransitionRejection == .noSessionYet`), which makes "a raise
//    arrived" and "no raise arrived" two different observable values rather than one silence.
//    Under the spot cells sits the **exhaustive sweep** (item 5's fix round, F3): every sequence of
//    driver calls to depth three — 1463 walks over an eleven-wide alphabet — with the two raises
//    COUNTED through the `MeshContinuationRaising` seam and held to one per entry into
//    (`running` ∧ a dark scene) and one per exit from it. The SCENE is a letter of that alphabet as
//    of item 6's fix round (F2): a delivery arrives lit or dark, and the scene can darken under a
//    task already in hand. It is item 4's 48-row table one layer up: item 4 walls the table, this
//    walls the two guards that decide when the driver speaks.
//
// 3. `MeshContinuationDisagreementTests` — **pass 2, the cell §24.1 and §25.1 name**, on a real
//    two-node founding: a task running with the scene backgrounded means the pushed gate leg is
//    false AND the session is `continuingInBackground`, the re-entry pass does not run, the heart
//    stage's predicate is closed, a custodied heart DEFERS with nothing marked, and one foreground
//    edge plus one reopened gate judge it exactly once. Then the four corners of the two legs, which
//    is the independence claim: neither leg is written in terms of the other, and only both together
//    open the stage. Item 5's fix round adds the two round trips that are only observable on a live
//    session: a `reset()` **mid-task** gives the session leg back (F1 — the adversarial verify's
//    probe, red on all three legs before `reset()` was split), and an ownerless delivery leaves
//    nothing behind once it is ended (F5). Item 6's fix round adds the one that says WHEN the
//    handover happens (F2): a task delivered while the app is still on screen keeps judging hearts,
//    and only the scene going dark hands the session over.
//
// **The deferred-quarter cell this copies** is `MeshRoutedHeartCeremonyTests`'
// `aBackgroundedRecipientDefersAndTheNextForegroundEdgeJudges`, which drives the state machine
// directly. The difference is the whole item: this one drives it through the SHIPPING path —
// `MeshContinuationDriver.taskDidStart(sceneIsDark:)` → `MeshNetworkManager.beginBackgroundContinuation()` —
// so `MeshP6HonestyAcceptanceTests`' note that "no shipping path reaches it yet" is false as of this
// commit, and is corrected there in the same commit.
//
// The rig helper here is deliberately its own: the ceremony's `founded(...)` is `private` to that
// suite, and this one closes the recipient's gate rather than leaving it open, which is the
// difference the cell is about.
//
// A partial copy (ProximityKit plan step A1.3's batch D, which copies here every Fernlet test cell that
// reads this module's sources before Fernlet stops holding them): of the Fernlet repository's
// FernletTests file of the same name, this holds only `MeshContinuationRaiseWallTests`' two cells that
// read ProximityKit's sources (`eachSceneEventIsRaisedExactlyOnceAndInsideItsOwnPublicDoor`,
// `neitherLegIsWrittenInTermsOfTheOther`), with the suite's and the tests' names unchanged and only
// each cell's half that reads this module's code, now through `PackageRoot` and the package's walker.
// Each cell's half that reads the app's or Fernlet's other modules' code, the suite's other cells and
// the file's other suites stay there, so what this header says of them is not held here.

import Foundation
import Testing

// MARK: - The wall

/// **Pass 1's wall.** The two session-state raises have one home each in ProximityKit, the app
/// reaches them through one public pair spoken in one file, and the app reaches the session machine
/// no other way. This copy holds the ProximityKit half; the app-side half stays in the Fernlet
/// repository.
struct MeshContinuationRaiseWallTests {

    /// The one file in ProximityKit allowed to raise either scene event.
    private static let manager = "MeshNetworkManager.swift"

    /// Every `.swift` file of ProximityKit's sources (``PackageSwiftFiles/sources()``), by file name,
    /// comment-stripped (``MeshRoutedSourceScan/codeOnly(_:)``), sorted by path.
    ///
    /// The package's form of the walker the original reads, the Fernlet repository's
    /// `MeshP7Acceptance.sources(under:)` over a folder of that repository: here the folder is this
    /// module's own, walked by the package's walker. Whole-line comments go so a wall states
    /// something about CODE rather than about the prose explaining it — the raise pair's own doc names
    /// its callers at length.
    private static func codeSources() throws -> [(name: String, code: String)] {
        try PackageSwiftFiles.sources().map { file in
            (name: file.path.components(separatedBy: "/").last ?? file.path,
             code: MeshRoutedSourceScan.codeOnly(file.text))
        }
    }

    /// The file names in which `needle` occurs, one entry per occurrence (the Fernlet repository's
    /// `MeshP7Acceptance.homes(of:in:)`, copied).
    private static func homes(of needle: String, in sources: [(name: String, code: String)]) -> [String] {
        var homes: [String] = []
        // R2: bounded by the file list.
        for source in sources {
            let count = source.code.components(separatedBy: needle).count - 1
            homes.append(contentsOf: Array(repeating: source.name, count: count))
        }
        return homes
    }

    /// **(a)** Each scene event is raised exactly once in the whole package, and each raise sits
    /// inside the public door named for it — brace-matched, so a raise that drifted out of the pair
    /// into the file around it reddens.
    ///
    /// **This copy's half** (plan step A1.3): the walk is of this module's sources, held to the
    /// package walker's source floor; the original walks every module of the Fernlet repository's
    /// package, held to 100 files, and its zero-list over the modules that are not ProximityKit stays
    /// there.
    @Test func eachSceneEventIsRaisedExactlyOnceAndInsideItsOwnPublicDoor() throws {
        let kit = try Self.codeSources()
        #expect(kit.count >= PackageSwiftFiles.sourceFloor, "the package scan lost its files")
        #expect(Self.homes(of: "applySessionEvent(.backgrounded", in: kit) == [Self.manager],
                "the backgrounded raise has exactly one home, and it is the manager's own door")
        #expect(Self.homes(of: "applySessionEvent(.foregrounded", in: kit) == [Self.manager],
                "and so does the foregrounded raise")
        let source = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Mesh/\(Self.manager)"))
        let began = try #require(
            MeshRoutedSourceScan.bracedBody(after: "public func beginBackgroundContinuation()", in: source),
            "the public begin door is gone")
        #expect(began.contains("applySessionEvent(.backgrounded)"),
                "and it is what raises the backgrounded event")
        let ended = try #require(
            MeshRoutedSourceScan.bracedBody(after: "public func endBackgroundContinuation()", in: source),
            "the public end door is gone")
        #expect(ended.contains("applySessionEvent(.foregrounded)"),
                "and its sibling raises the foregrounded one")
    }

    /// **The independence pin, in source.** The gate writer decides nothing from the session
    /// machine, and neither raise reads the gate. Two legs that read each other are one leg with two
    /// names, and the disagreement §24.1 asks for would be unstatable.
    ///
    /// **This copy's half** (plan step A1.3): neither raise reads the gate. That the gate writer, the
    /// app store's run-policy core, reads no session state is the app's half, held in the original.
    @Test func neitherLegIsWrittenInTermsOfTheOther() throws {
        let source = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Mesh/\(Self.manager)"))
        // R2: bounded by the two doors.
        for door in ["public func beginBackgroundContinuation()", "public func endBackgroundContinuation()"] {
            let body = try #require(MeshRoutedSourceScan.bracedBody(after: door, in: source),
                                    "a public raise door is gone")
            #expect(!body.contains("routedAccessGate") && !body.contains("Gate"),
                    "a raise that read the routed access gate would make one leg the other")
        }
    }
}
