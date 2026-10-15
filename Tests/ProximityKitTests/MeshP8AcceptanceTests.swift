// MeshP8AcceptanceTests.swift
// ProximityKitTests
//
// Network migration **P8's acceptance battery** (plan §14, launcher item 10): one serialized suite
// per clause, each promoting the named tier-1 claims of the item it speaks for and running its
// clause END TO END on the shipping seams, so CI gating a clause fails on this battery's own
// assertions rather than on a unit suite's. The P7 battery is the template and the rule is the same
// — where an exhaustive space already exists it is RE-WALKED here rather than sampled, and never by
// calling the unit suite's oracle: clause (a) carries its own 48-row expectation, spelled
// EVENT-outermost with every state a literal row — a THIRD decomposition, neither the shipped
// table's state-first helpers nor `MeshContinuationProduct`'s event-first predicates — so a table
// and an oracle that drifted together would still redden here, and a sweep that rewrites a
// production helper finds no identically-shaped twin in this file to rewrite with it.
//
// **Six suites.** The coordinator's table whole (item 4), the hold verb (item 3), the two raises and
// the disagreement on a real founding (item 5), the presentation table (item 7), the task wiring
// through item 6's fakes (item 6), and an honesty suite naming — by §15 row — what no Simulator can
// run. `CIGateSelectorBoundaryTests` therefore moves its battery pin from 42 to 48, and the same
// commit gates the six `MeshContinuation*` suites items 4/5/7 left on no CI line at all plus item
// 6's two.
//
// **What this battery does NOT claim** is in the honesty suite, by name and not by omission:
// `BGTaskScheduler` refuses a continued-processing submission on a Simulator (error 1), so every
// wiring cell drives a fake; §15.1–§15.4 are hardware gates; and the QUIC hold on real radios is
// item 3's tier-2 row. The two determinism digests keep their one home in `MeshP5AcceptanceTests`,
// this file spells neither, and the gate that runs it re-runs the three determinism suites.
//
// A partial copy (ProximityKit plan step A1.3, batch D: the cells of the Fernlet repository's tests
// that read this module's sources, copied before Fernlet deletes its in-tree copy of the module): of
// that repository's FernletTests file of the same name, this holds only the half of
// `MeshP8RaiseAndDisagreementAcceptanceTests.eachRaiseHasOneHomeAndTheAppReachesTheSessionMachineNoOtherWay`
// that reads ProximityKit's code, under the suite's and the test's names, walking the module through
// `MeshP7Acceptance` (this target's MeshP7AcceptanceTests.swift). The original walks every module of
// Fernlet's package; the raises' one home is this module's, so this half holds it here, and Fernlet's
// half holds every other module of its package, and its app, to no raise. The rest of the file stays
// there, so what this header says of the rest is not held here.

import Foundation
import Testing

// MARK: - (c) The raises and the disagreement

/// **Item 5: the two session-state raises**: the half of the wall's re-walk that reads ProximityKit's
/// code.
@MainActor
@Suite(.serialized)
struct MeshP8RaiseAndDisagreementAcceptanceTests {

    /// The wall, re-walked: one raise of each scene event in the whole module, each inside the public
    /// door named for it. The original cell's other half (no other module of Fernlet's package raises
    /// either event; the app speaks each public raise exactly once and only from the driver, and offers
    /// the session machine no event directly) stays in Fernlet's copy of the cell.
    @Test func eachRaiseHasOneHomeAndTheAppReachesTheSessionMachineNoOtherWay() throws {
        let kit = try MeshP7Acceptance.sources()
        #expect(kit.count >= 100, "the package scan lost its files")
        #expect(MeshP7Acceptance.homes(of: "applySessionEvent(.backgrounded", in: kit) == ["MeshNetworkManager.swift"],
                "the backgrounded raise has exactly one home")
        #expect(MeshP7Acceptance.homes(of: "applySessionEvent(.foregrounded", in: kit) == ["MeshNetworkManager.swift"],
                "and so does the foregrounded raise")
        let manager = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift"))
        let began = try #require(
            MeshRoutedSourceScan.bracedBody(after: "public func beginBackgroundContinuation()", in: manager),
            "the public begin door is gone")
        #expect(began.contains("applySessionEvent(.backgrounded)"), "and the begin door is what raises it")
        let ended = try #require(
            MeshRoutedSourceScan.bracedBody(after: "public func endBackgroundContinuation()", in: manager),
            "the public end door is gone")
        #expect(ended.contains("applySessionEvent(.foregrounded)"), "and its sibling raises the other")
    }
}
