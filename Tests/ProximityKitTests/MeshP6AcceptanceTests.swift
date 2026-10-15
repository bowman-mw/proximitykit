// MeshP6AcceptanceTests.swift
// ProximityKitTests
//
// Network migration **P6's acceptance battery** (plan §12.4, launcher item 9): one serialized suite
// per clause, each promoting the named tier-1 claims of the item it speaks for and adding the
// property the item's own cells could not reach.
//
// The shape is `MeshP5AcceptanceTests.swift`'s, deliberately: one clause per suite, run END TO END
// rather than a list of other suites' names, so CI gating a clause fails on this battery's own
// assertions. Where an exhaustive space already exists it is CITED in the doc comment and not
// re-run — §11.4's idiom.
//
// **Eight suites, not the launcher's seven.** P5's separate Honesty suite earned its place by giving
// the rectangle's wholeness and the not-claimed list a home, and P6's rectangle G needs the same.
// `CIGateSelectorBoundaryTests` therefore moves its battery pin from 28 to 36.
//
// **What lives elsewhere, and why.** The feature pipeline, its seams and rectangle G live in
// `MeshRoutedDrainConvergenceTests.swift`, not here and not in a new file: a new
// `Mesh…ConvergenceTests` suite would not match `CIGateSelectorBoundaryTests.isMeshBattery`'s
// `MeshP<n>…AcceptanceTests` shape and could sit ungated the day it was written. The two determinism
// digests keep their one home in `MeshP5DeterminismAcceptanceTests`; this file's determinism clause
// says so rather than copying a literal.
//
// A partial copy (ProximityKit plan step A1.3, batch D: the cells of the Fernlet repository's tests
// that read this module's sources, copied before Fernlet deletes its in-tree copy of the module): of
// that repository's FernletTests file of the same name, this holds only the half of
// `MeshP6HonestyAcceptanceTests.theBatteryNamesWhatItDoesNotClaim` that reads ProximityKit's code
// through `PackageRoot`, under the suite's and the test's names. The rest of the file, and the cell's
// other half (increment 1's three registered types), stay there, so what this header says of the rest
// is not held here.

import Foundation
import Testing

// MARK: - (g) Honesty

/// **What P6's battery does NOT claim is named**: the half of its honesty cell that reads
/// ProximityKit's code.
@MainActor
@Suite(.serialized)
struct MeshP6HonestyAcceptanceTests {

    /// **The asleep quarter proves the gate's arithmetic; since P8 item 5 a shipping path reaches that
    /// state too.** The heart stage's third leg is the session state, and the state the asleep quarter
    /// drives is named in the session machine. The original cell's other claim (increment 1's three
    /// registered types) stays in Fernlet's copy of the cell.
    @Test func theBatteryNamesWhatItDoesNotClaim() throws {
        let manager = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift")
        )
        #expect(manager.contains("sessionState == .activeForeground"), """
            the heart stage's third leg is the session state and nothing weaker — a gate-only \
            predicate would defer the text projection with it
            """)
        let app = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Mesh/MeshSessionStateMachine.swift")
        )
        #expect(app.contains("case continuingInBackground"),
                "the state the asleep quarter drives, by name")
    }
}
