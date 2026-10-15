// MeshRoutedRefusalBudgetTests.swift
// ProximityKitTests
//
// The P5 review's finding 3, closing D-12.14: routed content frames refused BEFORE any store verb
// were replayable without bound by a committed member — the replay window records only a
// `.completed` outcome on a verified author, and every pre-store refusal (a verifier rejection,
// `notADestinationOrHandoff`, `unknownItemNotFromOrigin`, `unregisteredTypeChunk`, an undecodable
// frame) costs an Ed25519 verify or a sealed-index load. `MeshRoutedRefusalBudget` bounds them per
// authenticated envelope sender; this file is its decision table, one real cell through the drain's
// own dispatch door, and the wall that keeps every refusal exit on the one charging door.
//
// The audit log is process-global and suites run in parallel, so every claim about a logged line is
// a containment claim; the per-instance budget on the receiving manager is the exact witness.
//
// A partial copy (ProximityKit plan step A1.3's batch D, the routed track): of the Fernlet
// repository's FernletTests file of the same name, this holds only its source wall,
// `MeshRoutedRefusalBudgetTests.everyPreStoreRefusalGoesThroughTheOneChargingDoor`, with the digest
// doors' helper it calls, under its suite's name and its own; the suite's decision-table and drain
// cells stay there, so what this header says of them is not held here.

import Foundation
import Testing

/// The pre-store refusal budget: its table, its one drain cell, and its source wall.
@MainActor
@Suite(.serialized)
struct MeshRoutedRefusalBudgetTests {

    // MARK: - The wall

    /// Every pre-store refusal exit in the four content doors charges the sender: inside the doors
    /// the rejected token is never spelled directly (every exit goes through the one charging
    /// door), the dispatch decode goes through it too, the gate sits at the dispatch, and the
    /// budget is reset with the drain state — nowhere else. The two digest doors are outside the
    /// budget by design (D-5.12 / D-6.10: a digest costs one verify, is bound to its slot, and its
    /// answer is bounded by the per-peer frame budget), and what pins them is a **count over their
    /// brace-matched bodies**, not a list of spellings (P6 item 10 SET A, the item 7 fix review's
    /// P2-A).
    ///
    /// The spelling list was wrong the day it was written. It said "four spellings, so a fifth
    /// cannot appear unnoticed"; the digest family's refusal exits were already **five** — the
    /// drain answer's binding guard (`mesh.merge.routedQuiescentUnbound`,
    /// `receiveRoutedDrainAnswer`) is a pre-store refusal in one of the two doors the sentence is
    /// about and was pinned nowhere in `Tests/`. Enumerating spellings is the failure mode: a sixth
    /// exit under a fresh token is invisible to a list and visible to a count. So the doors are
    /// brace-matched and every `ProximityAudit.log(` inside them is counted — **six**: two
    /// refusals + one guard + two refusals, plus the one SUCCESS line
    /// (`mesh.merge.routedQuiescent`), which is deliberately inside the count. A new line of any
    /// kind, refusal or not, reds here and has to be argued for.
    ///
    /// The token counts are kept beside it because they say something the body count cannot: that
    /// the *shared* rejected token has not spread to a content door, and that item 7's stamp guard
    /// still refuses under its own name.
    @Test func everyPreStoreRefusalGoesThroughTheOneChargingDoor() throws {
        let code = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift")
        )
        let token = "\"mesh.routedDrain.rejected\""
        let total = code.components(separatedBy: token).count - 1
        #expect(total == 5, "the probe, the charging door and the three digest-door lines; found \(total)")
        let stale = "\"mesh.routedInventory.staleSentAt\""
        #expect(code.components(separatedBy: stale).count - 1 == 1,
                "P6 item 7's stamp guard no longer refuses under its own token")
        try digestDoorAuditLinesAreCounted(in: code)

        let doorsStart = try #require(code.range(of: "private func ingestRoutedManifest("))
        let doorsEnd = try #require(code.range(of: "private nonisolated enum RoutedDrainVerdict"))
        let doors = String(code[doorsStart.lowerBound..<doorsEnd.lowerBound])
        #expect(!doors.contains(token), "a content door spells the rejected token instead of charging the sender")
        let doorCalls = doors.components(separatedBy: "refuseRoutedFrameBeforeStore(").count - 1
        #expect(doorCalls == 8, "manifest ×3, chunk ×3, custody ×1, recipient ×1; found \(doorCalls)")

        let dispatchStart = try #require(code.range(of: "private func dispatchRoutedContent("))
        let dispatchEnd = try #require(code.range(of: "private struct RoutedIngestContext"))
        let dispatch = String(code[dispatchStart.lowerBound..<dispatchEnd.lowerBound])
        #expect(dispatch.contains("guard !routedRefusalBudget.isSpent(context.sender) else { return }"),
                "a spent sender is dropped at the dispatch, before the decode")
        #expect(dispatch.components(separatedBy: "refuseRoutedFrameBeforeStore(").count - 1 == 4,
                "all four undecodable exits charge the sender")
        #expect(!dispatch.contains("ProximityAudit.log("),
                "the dispatch writes no audit line of its own — every refusal there goes through the charging door")

        let resets = code.components(separatedBy: "routedRefusalBudget.reset()").count - 1
        #expect(resets == 1, "the budget is reset with the drain state only — never on a disconnect or a flap")
        #expect(code.contains("routedRefusalBudget = MeshRoutedRefusalBudget()"))
    }

    /// The digest family's three brace-matched bodies and the one number that covers all of them.
    ///
    /// `routedInventoryStampIsStale(_:from:)` is counted with the two doors because it is the
    /// inventory door's own refusal exit, lifted into a named function so one verdict could decide
    /// both the record and the quiescence re-stamp (P6 item 7). Leaving it out would let a fourth
    /// exit hide in the lift.
    private func digestDoorAuditLinesAreCounted(in code: String) throws {
        let doors = [
            "func receiveRoutedInventory(",
            "private func routedInventoryStampIsStale(",
            "private func receiveRoutedDrainAnswer("
        ]
        var lines = 0
        // R2: a fixed three-element list.
        for door in doors {
            let body = try #require(
                MeshRoutedSourceScan.bracedBody(after: door, in: code),
                "a digest door was renamed, or its brace-matched body does not close"
            )
            lines += body.components(separatedBy: "ProximityAudit.log(").count - 1
        }
        #expect(lines == 6, """
            the digest doors write an audit line this wall does not know about. Six are expected: \
            the inventory verifier's rejection, the sender mismatch, item 7's stale stamp, the \
            answer verifier's rejection, the answer's unbound binding guard, and the one success \
            line. A seventh is a refusal exit nobody pinned — the shape P6 item 10 SET A closed
            """)
    }
}
