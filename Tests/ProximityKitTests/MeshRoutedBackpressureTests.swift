// MeshRoutedBackpressureTests.swift
// ProximityKitTests
//
// Network migration P5 item 9 (plan §11): the MANAGER half — a capacity refusal made visible and
// bounded, the parked-set drop rule at the door that raises it, the sweeps that finally have
// callers, and the app-side copy the hold resolves to.
//
// Tier 1 only, on item 6's existing `MeshRoutedDrainRig` — never a parallel rig. The three fixture
// facts that file states apply verbatim: one pinned install binding (`MeshP3Acceptance.install`), one
// time anchor (`MeshRoutedDrainRig.createdAt` — exactly 1.8e9 until 2026-12-16, a month before
// that instant falls due, and the wall clock plus that month from the crossover on (item 6a); it
// is also the anchor the development instants below take), and joiner-shaped nodes with no session
// ceiling.
//
// **The expiry trap, which is not hypothetical.** `MeshRoutedStoreFixtures.record()` stamps the
// manifest fixtures' anchor (1.7e9), which is already past at this rig's `now` — so a planted hog
// would be freed by item 9's own expiry sweep before the refusal it was planted to cause. Every
// planted record here therefore passes `MeshRoutedDrainRig.expiry` explicitly, except the two cells
// whose whole claim IS that an expired record is swept.
//
// A partial copy (ProximityKit plan step A1.3's batch D, the routed track): of the Fernlet
// repository's FernletTests file of the same name, this holds only the one cell of
// `MeshRoutedParkedDropDoorTests` that reads ProximityKit's source,
// `theDropHasOneCallSiteAndItIsTheVerifierBranch`, under its suite's name and its own; the suite's
// other cells and the file's other suites stay there, so what this header says of them is not held
// here.

import Foundation
import Testing

// MARK: - The parked-set drop rule, at the door

/// The one clause that turns a refused manifest into dropped bytes, driven through the real ingest.
@MainActor
@Suite(.serialized)
struct MeshRoutedParkedDropDoorTests {

    /// The structural half: the drop has EXACTLY one call site, and it is the verifier-rejection
    /// branch — so neither the `notADestinationOrHandoff` guard nor a capacity refusal can ever
    /// reach it, whatever a future edit intends.
    @Test func theDropHasOneCallSiteAndItIsTheVerifierBranch() throws {
        let source = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift")
        )
        let lines = source.split(separator: "\n", omittingEmptySubsequences: false)
        let calls = lines.enumerated().filter { $0.element.contains("dropParkedSetIfTerminal(") }
        #expect(calls.count == 2, "one definition and one call site")
        let callSite = try #require(calls.first)
        let window = lines[max(0, callSite.offset - 8)..<callSite.offset].joined(separator: "\n")
        #expect(window.contains("door.verify(manifest)"),
                "the drop must hang off the verifier's rejection and nothing else")
        #expect(source.contains("dropParkedSet(key:") )
    }
}
