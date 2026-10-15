// MeshNameWithholdingTests.swift
// ProximityKitTests
//
// Stranger-admission Option 1b (the owner's call of 2026-09-22), the MESH half. The coordinator
// withholds this device's display name until it commits (`ProximityCoordinatorTests`), but every
// mesh frame is signed at `MeshNetworkManager.sendEnvelopeCore`, and six broadcasts reach slots this
// device has NOT committed — the coordinator beacon every 20 s, the admission request, rotation sync,
// key rotation and ack, the removal votes, departure and termination frames — plus the QR ceremony.
// The item's blind verify found them all still naming this device to a stranger (BLOCKER), with
// `MeshHostPinTests` asserting the leak as the expected value. The gate now sits at that one door:
// an uncommitted slot gets an empty envelope name, and a `MeshPeerNameRedactable` payload arrives
// with every name blanked — this device's own, and on a relayed vote OTHER members' too.
//
// House rules: no sleeps and no wall clock; the per-slot sends are spawned on the main actor and
// drained with a bounded yield loop, as `MeshHostPinTests` does.
//
// A partial copy (ProximityKit plan step A1.3, batch D: the cells of the Fernlet repository's tests
// that read this module's sources, copied before Fernlet deletes its in-tree copy of the module): of
// that repository's FernletTests file of the same name, this holds only the one cell that reads
// ProximityKit's code, `MeshNameWithholdingTests.theDisclosureSubscriberIsWiredToRenameOnly`, under its
// suite's and its test's names, reading the manager through `PackageRoot`. The rest of the file (its rig
// and the cells that drive the door) stays there, so what this header says of the rest is not held here.

import Foundation
import Testing

/// The mesh door withholds every name from a slot this device has not committed — and only from it.
/// Of the original's cells this holds the one that reads ProximityKit's code: the disclosure
/// subscriber's wiring.
@MainActor
@Suite(.serialized)
struct MeshNameWithholdingTests {

    /// **The disclosure subscriber stays rename-only** — the WIRING, not just the helper: rewiring it
    /// back to `recordSessionParticipant` (which appends) passed every suite (the re-verify's FIX).
    /// A refused stranger's named frame in the teardown window must not mint it a roster row.
    @Test func theDisclosureSubscriberIsWiredToRenameOnly() throws {
        let source = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift")
        )
        let closure = try #require(
            MeshRoutedSourceScan.bracedBody(after: "coordinator.onPeerDisplayNameDisclosed =", in: source),
            "the manager no longer subscribes to the coordinator's disclosure"
        )
        #expect(closure.contains("renameSessionParticipant("), "the subscriber renames")
        #expect(!closure.contains("recordSessionParticipant("), "and never records — recording appends a row")
    }
}
