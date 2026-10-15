// MeshP5AcceptanceTests.swift
// ProximityKitTests
//
// P5 item 14: **the P5 acceptance battery** (plan §11's testing lane, verbatim).
//
//     Custody, receipts, dedup, backpressure and the drain are tier 1. … a property-test extension
//     asserting every outstanding delivery reaches `delivered` or a closed state under a bounded
//     schedule, no content lost, no double-counted receipt. All on `FakePeerNetwork` +
//     `FakeMeshTransportSession` + an injected clock, no wall-clock sleeps.
//
// …and §16.1's routed clauses, which are what "tier 1" has to end in:
//
//     chunk dedup/TTL/caps/backpressure; custody vs final receipts; heart foreground-commit rule;
//     locked/deferred/corrupt sidecars; exactly-once task completion; wipe-wall + delete-all
//     resurrection checks for every new sidecar.
//
// Items 1–13 each shipped their own exhaustive suites, and those remain the fine-grained evidence:
// the manifest and its wraps (`MeshRoutedManifestTests`), chunks and assembly (`MeshChunkTests`),
// the five-state store (`MeshRoutedStoreTests`, `MeshRoutedCustodyTests`), the ack stages
// (`MeshRoutedDeliveryAckTests`, `MeshRecipientReceiptTests`), the inventory and its delta
// (`MeshRoutedInventoryTests`, `MeshRoutedInventoryBuilderTests`, `MeshRoutedInventoryDeltaTests`),
// the drain (`MeshRoutedDrainTests`), the merge window (`MeshMergeWindowTests`), custody transfer
// (`MeshRoutedCustodyHandoffTests`), backpressure (`MeshRoutedBackpressureTests`,
// `MeshRoutedCapacityTests`), the access gate (`MeshRoutedAccessGateTests`), the type registry
// (`MeshRoutedTypeRegistryTests`), the replay window (`MeshFrameReplayWindowTests`) and the sealed
// photo path (`MeshRoutedPhotoDeliveryTests`). The 40-cell routed rectangle is
// `MeshRoutedDrainConvergenceTests`.
//
// **This file is deliberately not those suites again, and it is deliberately not a list of their
// names either.** Each suite below is one acceptance clause, run end to end as its own compact
// scenario against the same shipping seams — so the battery fails on its own evidence rather than
// on somebody else's, and CI can gate on it by name. Where the exhaustive file is the full space,
// the suite's doc comment says so and this file runs the canonical corner of it.
//
// **The fixed seed is the battery's, not a run-time draw.** Every scenario generates its schedule
// from ``MeshConvergenceSeeds/root`` — `0x00F32B1C00090002` — and its routed side-plan from
// `seed ^ MeshScheduleGenerator.routedSalt`. `MeshP5DeterminismAcceptanceTests` pins both
// constants, the eight-seed family, byte-identical overlay replay, one byte-identical run replay, a
// grep-wall over the routed convergence file, and **two literal digests** over the 80 generated
// membership schedules and the 40 generated overlays — which is the only artefact that can go red
// for "a draw was added inside `schedule(…)`".
//
// Nothing here sleeps and nothing decides on a wall clock: instants are arguments and the fabric's
// clock is advanced by hand.
//
// **Publishing caveat.** A `-only-testing` line naming a non-existent suite — or a *file* rather
// than a `@Suite` struct — matches zero tests and still prints `TEST EXECUTE SUCCEEDED`. Every
// name below was verified against a run showing a non-zero per-suite count before it was published.
//
// A partial copy (ProximityKit plan step A1.3, batch D: the cells of the Fernlet repository's tests
// that read this module's sources, copied before Fernlet deletes its in-tree copy of the module): of
// that repository's FernletTests file of the same name, this holds only the half of
// `MeshP5HonestyAcceptanceTests.theBatteryNamesWhatItDoesNotClaim` that reads ProximityKit's code
// through `PackageRoot`, under the suite's and the test's names. The rest of the file, and the cell's
// other half (the routed vocabulary and type registry, read through Fernlet's fixtures), stay there,
// so what this header says of the rest is not held here.

import Foundation
import Testing

// MARK: - Honesty

/// **What the battery deliberately does NOT claim, named rather than implied**: the half of its
/// honesty cell that reads ProximityKit's code.
@Suite(.serialized)
struct MeshP5HonestyAcceptanceTests {

    /// **P5's own deferrals, named so no reader takes a bound that does not exist.** D-12.14 left
    /// three **pre-store refusal channels** — `notADestinationOrHandoff`,
    /// `unknownItemNotFromOrigin` and `unregisteredTypeChunk` — unbounded in count; the P5 review's
    /// correction bounded them per authenticated sender (`MeshRoutedRefusalBudget`), and the three
    /// names still stand in the source as the refusals that budget charges. The original cell's
    /// other claims (the routed vocabulary's fourteen tokens and increment 1's three registered types)
    /// stay in Fernlet's copy of the cell.
    @Test func theBatteryNamesWhatItDoesNotClaim() throws {
        // The three refusal channels are named in the shipping source, not in an enum this file can
        // read, so the record is pinned the way the grep-wall pins the other unassertable facts:
        // a rename or a deletion moves this line, and the doc comment above stops being true. Since
        // the P5 review's correction each is charged to the sender's budget, whose spend line is
        // pinned beside them.
        let source = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift")
        )
        // R2: a fixed three-element list.
        for reason in ["notADestinationOrHandoff", "unknownItemNotFromOrigin",
                       "unregisteredTypeChunk"] {
            #expect(source.contains(reason),
                    "a pre-store refusal D-12.14 named is no longer named")
        }
        #expect(source.contains("mesh.routedDrain.refusalBudgetSpent"),
                "the per-sender bound the review added to D-12.14's channels is gone")
    }
}
