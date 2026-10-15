// MeshContinuationTaskHostTests.swift
// ProximityKitTests
//
// Network migration P8 item 6: the task wiring, driven end to end through two fakes, plus the wall
// that keeps the host on its own side of every P7 boundary.
//
// **Why fakes at all.** `BGTaskScheduler` refuses a continued-processing submission on a Simulator
// outright (error 1) and nothing can make iOS deliver a task to a unit test, so a host written
// against the framework would have zero tier-1 coverage of the five things item 6 IS: register,
// submit, expire, cancel, and complete EXACTLY ONCE. `BackgroundContinuationScheduling` and
// `ContinuationTaskHandle` exist for this suite; `BGTaskSchedulerContinuationScheduler` and
// `BGContinuationTaskHandle` are the untested remainder and are item 9's device rows.
//
// **What only a device can prove**, and is therefore claimed nowhere below: that the registration is
// accepted by the real scheduler, that a `.fail` submission is granted, that the launch handler
// fires, that the expiration handler fires, and that the QUIC tunnel survives the whole of it.
//
// **The fix round adds the scene** (F2). A continued-processing task is delivered promptly after the
// submission, normally while the app is still ON SCREEN, so the host holds the one decided-once
// foreground fact and hands it to the driver at the delivery: adopted at once, raised only once the
// scene is dark. The observable for a raise in this suite is the manager's own refusal latch — the
// mesh here has no session, so a raise that was made is refused by name and a raise that was never
// made leaves it nil — while the COUNT of raises is the driver sweep's.
//
// A partial copy (ProximityKit plan step A1.3's batch D, which copies here every Fernlet test cell that
// reads this module's sources before Fernlet stops holding them): of the Fernlet repository's
// FernletTests file of the same name, this holds only `MeshContinuationTaskHostWallTests`' two cells
// that read ProximityKit's sources (`theMeshsSlotCoordinatorRaisesNoLiveActivity`,
// `theOneToOneForegroundAnchorsAreRetired`), with the suite's and the tests' names unchanged and only
// each cell's half that reads this module's code, now through `PackageRoot` and the package's walker.
// Each cell's half that reads the app's or Fernlet's other modules' code, the suite's other cells and
// the file's other suites stay there, so what this header says of them is not held here.

import Foundation
import Testing

// MARK: - The wall

/// **Item 6's wall.** The `BackgroundTasks` framework has one home, the host speaks no radio verb and
/// no gate, the feed is its only route to a radio, the funnel never calls it back, the mesh raises no
/// Live Activity, and the concrete identifier is inside the plist's wildcard.
///
/// P9 item 5 added cell (g): the mesh's door was only half the claim, and the other half — the
/// coordinator's DEFAULT anchor, which the 1:1 paths take — is now the no-op too, so the app raises
/// no proximity Live Activity anywhere.
struct MeshContinuationTaskHostWallTests {

    /// Cell (g)'s one permitted home for the proximity Live Activity's attributes type, by file name:
    /// the app's own reaper, since plan step A0.6 moved it and its attributes out of ProximityKit.
    ///
    /// Here it is named in the walk's failure messages only: the reaper is a file of the Fernlet app,
    /// which this package cannot read.
    private static let reaperFile = "ProximityLiveActivityReaper.swift"

    /// Cell (g)'s first walk root: ProximityKit, the module whose coordinator defaults the anchor.
    /// Since plan step A0.6 it holds no proximity Live Activity spelling at all: the reaper and its
    /// attributes type are the app's, and ProximityKit builds for platforms with no ActivityKit. Here,
    /// this module's source folder under the package root, walked by the package's walker.
    private static let proximityKitRoot = PackageSwiftFiles.sourceFolder

    /// Floor under that walk, so a broken root cannot pass by enumerating nothing. Measured 143 on
    /// 2026-09-20; the floor is deliberately below it, since files come and go. (135 in this package
    /// at plan step A1.3.)
    private static let minimumProximityKitFilesWalked = 120

    /// The files the walk must read, by name (this copy's anchor, plan step A1.3): the coordinator,
    /// whose default anchor is the claim, and the two engines that seat a coordinator, the mesh's
    /// channel-ready door (cell (e)) and the pair session's, which takes the default. The floor alone
    /// would pass a walk that lost a small folder: the coordinator's `Engine/` holds five of the 135.
    private static let expectedHomes = ["ProximityCoordinator.swift", "MeshNetworkManager.swift", "ProximityPairSession.swift"]

    /// Spellings P9 item 5 retired outright: no file in ProximityKit or `FernletSocial` may hold one.
    private static let retiredAnchorSpellings = [
        "ActivityKitProximityForegroundAnchor",
        "Activity.request"
    ]

    /// Spellings only the once-per-launch orphan reaper needs. Since plan step A0.6 the reaper is the
    /// app's, so no file in ProximityKit or `FernletSocial` may hold one either.
    private static let reaperOnlySpellings = [
        "import ActivityKit",
        "canImport(ActivityKit)",
        "ProximityConnectionActivityAttributes"
    ]

    /// What needle (2) also refuses, as patterns over each walked file's code lexed (comments dropped,
    /// literals emptied), since the two lists above are literal spellings a respelling escapes:
    /// ActivityKit named as a whole identifier, which every import form (`import class
    /// ActivityKit.Activity` among them), `canImport` condition and qualified name spells; and a request
    /// through `Activity`, its generic argument inferred or written out (`Activity<…>.request`), applied
    /// or not.
    private static let activityKitPatterns = [
        (spelling: "ActivityKit", pattern: #"(?<![A-Za-z0-9_])ActivityKit(?![A-Za-z0-9_])"#),
        (spelling: "Activity<…>.request",
         pattern: #"(?<![A-Za-z0-9_])Activity\s*(?:<[^>]*>)?\s*\.\s*request(?![A-Za-z0-9_])"#)
    ]

    /// Every `.swift` file of ProximityKit's sources (``PackageSwiftFiles/sources()``), by file name,
    /// comment-stripped (``MeshRoutedSourceScan/codeOnly(_:)``), sorted by path.
    ///
    /// The package's form of the walker the original reads, the Fernlet repository's
    /// `MeshP7Acceptance.sources(under:)` over a folder of that repository: here the folder is this
    /// module's own, walked by the package's walker.
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

    /// Needle (2) over one walked module: no file holds a retired or reaper-only spelling, and no file's
    /// code, lexed, matches one of ``activityKitPatterns``.
    private static func expectNoProximityLiveActivity(in sources: [(name: String, code: String)], under root: String) {
        // R2: bounded by the five spellings.
        for needle in Self.retiredAnchorSpellings + Self.reaperOnlySpellings {
            let homes = Set(Self.homes(of: needle, in: sources)).sorted()
            #expect(homes.isEmpty,
                    "`\(needle)` is under \(root), in \(homes) — only the app's \(Self.reaperFile) may name a proximity Live Activity")
        }
        let lexed = sources.map { (name: $0.name, code: SwiftSourceLexer.lex($0.code).code) }
        // R2: bounded by the two patterns.
        for (spelling, pattern) in Self.activityKitPatterns {
            let homes = lexed.filter { $0.code.range(of: pattern, options: .regularExpression) != nil }.map(\.name)
            #expect(homes.isEmpty,
                    "`\(spelling)` is under \(root), in \(homes.sorted()) — only the app's \(Self.reaperFile) may name a proximity Live Activity")
        }
    }

    /// **(e)** The mesh's shipping slot coordinator raises no `ProximityForegroundAnchor` Live
    /// Activity (plan §14: no duplicate UI beside the continued task's own system card).
    ///
    /// Brace-matched on the door that seats a channel, because the `Noop` injection two thousand
    /// lines away at `makeRetainedSlotCoordinatorForTesting` is a TEST seam and proves nothing about
    /// what a real session raises — which is exactly the reading that made this look already done.
    ///
    /// **What it buys is honest and small** (the fix round's F1): the requests were never renderable
    /// — the proximity attributes type was internal to ProximityKit (the app's since plan step A0.6)
    /// and no widget in `App/FernletWidgets` declares an `ActivityConfiguration` for it — so a person
    /// sees no change on a phone. What goes away is up to five doomed `Activity.request` calls per
    /// session, each of which either threw or spent one of the per-app Live Activity slots a workout
    /// or cooking activity needs.
    ///
    /// Since P9 item 5 the coordinator's DEFAULT anchor is the no-op too (cell (g)), so this
    /// argument is belt to that braces. It is deliberately kept: the mesh's door should say what it
    /// raises without the reader having to know a default two files away.
    ///
    /// **This copy's half** (plan step A1.3): the mesh's door. That the app's store loader still runs
    /// the once-per-launch orphan reaper is the app's half, held in the original.
    @Test func theMeshsSlotCoordinatorRaisesNoLiveActivity() throws {
        let manager = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift"))
        let door = try #require(
            MeshRoutedSourceScan.bracedBody(after: "private func handleChannelReady(", in: manager),
            "the channel-ready door is gone")
        #expect(door.contains("foregroundAnchor: NoopProximityForegroundAnchor()"),
                """
                a mesh seats up to five coordinators, and each was ATTEMPTING one `Activity.request` \
                — the duplicate §14 forbids, and, since none of them can render in this app, five \
                doomed calls rather than a card anyone ever saw
                """)
    }

    /// **(g)** P9 item 5: the 1:1 foreground anchors are RETIRED. Nothing in the app requests a
    /// PROXIMITY Live Activity (the workout/cooking kinds are a different attributes type, raised by
    /// `App/Fernlet/LiveActivityStarter.swift`, and are not in scope here); the once-per-launch
    /// orphan reaper is the only code that still names the proximity attributes type, and since plan
    /// step A0.6 both are the app's (the original's `reaperPath`), not ProximityKit's.
    ///
    /// Cell (e) pinned the mesh's door. This pins the half P8 left open — the coordinator's
    /// DEFAULT anchor, which three shipping construction sites take by omitting the argument
    /// (`ProximityPairSession.handleChannelReady`, and `FernletSocial`'s `PresenceManager`'s
    /// heart door and its teardown seam). Until P9 that default was the ActivityKit conformer, whose
    /// every request was doomed: the attributes type was internal to ProximityKit and
    /// `App/FernletWidgets/FernletWidgetsBundle.swift` declares no `ActivityConfiguration` for it,
    /// so each call either threw (audited) or spent a per-app Live Activity slot on something
    /// nothing draws.
    ///
    /// Five independently reddenable needles: re-adding a request to the reaper's file, in any spelling
    /// the original's `reaperRequestSpellings` reads (ActivityKit's `request` as a whole identifier, specialised,
    /// aliased, unapplied or bare, the app's `LiveActivityStarter` and its `LiveActivityRunReflectable`,
    /// or a `typealias`) — or moving the enumeration out of the reaper's own brace-matched body, or
    /// naming the attributes type in the file's code outside that body anywhere but its declaration (a
    /// stored value, a metatype, a factory) — reddens (1); naming the retired class, a request through
    /// `Activity` (its generic argument inferred or written out), ActivityKit in any form (an import of
    /// any kind, a `canImport`, a qualified name) or the attributes type from ANY file under ProximityKit
    /// or `FernletSocial` reddens (2); naming the attributes type from any app file but the reaper's own
    /// reddens (3);
    /// restoring the `#if canImport` default reddens (4); declaring a proximity configuration in the
    /// widget bundle reddens (5) — which is the honest signal that "retire" has been reversed and this
    /// cell must be rewritten rather than deleted.
    ///
    /// Needle (2) is a WALK of each module, not the four hand-listed files it replaced (the fix
    /// round's F2): those four made the comment's claim — "anywhere else in shipping source" —
    /// false for the case that actually ships, a NEW ProximityKit file that imports ActivityKit and
    /// requests one while every needle stays green. It walks `FernletSocial` too, because presence's
    /// heart door lives there: a walk of ProximityKit alone would read a request raised beside it as
    /// a clean module. Needle (3) walks the app's sources, the widget folder included, for the
    /// attributes type alone: `Activity.request` has a legitimate home there, the workout/cooking
    /// starter, and the type's one home is the reaper's file, matched by name, so the walk must see
    /// exactly one file of that name.
    ///
    /// **This copy's half** (plan step A1.3): needle (2) over ProximityKit and needle (4). The walk
    /// also expects to read the files ``expectedHomes`` names, so a walk that lost a folder cannot
    /// read the module clean. Needles (1), (3) and (5) read the app's files, and needle (2)'s walk of
    /// `FernletSocial` reads a Fernlet module: they stay in the original.
    @Test func theOneToOneForegroundAnchorsAreRetired() throws {
        // (2) ProximityKit, WALKED (the suite's own `codeSources`/`homes`, comment-stripped, and lexed
        // for the patterns), not hand-listed: since plan step A0.6 the module may not spell the
        // retired conformer, a request, ActivityKit or the attributes type at all.
        let sources = try Self.codeSources()
        #expect(sources.count >= Self.minimumProximityKitFilesWalked,
                "walked only \(sources.count) files under \(Self.proximityKitRoot) (floor \(Self.minimumProximityKitFilesWalked)) — the walk is broken, not the module clean")
        let walked = Set(sources.map(\.name))
        #expect(walked.isSuperset(of: Self.expectedHomes),
                "the walk under \(Self.proximityKitRoot) read none of \(Set(Self.expectedHomes).subtracting(walked).sorted()) — the walk is broken, not the module clean")
        Self.expectNoProximityLiveActivity(in: sources, under: Self.proximityKitRoot)

        // (4) The coordinator's default is the no-op unconditionally — no ActivityKit branch left.
        let coordinatorPath = "Sources/ProximityKit/Engine/ProximityCoordinator.swift"
        let coordinator = MeshRoutedSourceScan.codeOnly(try PackageRoot.source(coordinatorPath))
        #expect(!coordinator.contains("ActivityKit"),
                "the default anchor is unconditional; no `#if canImport` branch remains")
        #expect(coordinator.contains("foregroundAnchor ?? NoopProximityForegroundAnchor()"),
                "and the default it falls back to is the no-op")
    }
}
