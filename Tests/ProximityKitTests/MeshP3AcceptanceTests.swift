// MeshP3AcceptanceTests.swift
// ProximityKitTests
//
// P3 item 8: **the P3 acceptance battery** (plan §8.4's acceptance list, verbatim).
//
//     Acceptance (P3): unit tests for every state edge; disconnect ≠ removal; idle-lapse resume;
//     ceiling at both bounds; rotation on removal/departure/merge with old-key rejection after
//     grace; context load/deferred/corrupt matrix; legacy `sessionGoodbye` interop.
//
// Items 1–7 each shipped their own unit tests, and those remain the fine-grained evidence: the
// pure state machine's totality (`MeshSessionStateMachineTests`), the epoch model
// (`MeshEpochModelTests`), the five-state sealed store (`MeshSessionStoreTests`), the rotation
// triggers (`MeshRotationTriggerTests`), the wire tokens (`MeshMembershipEventWireTests`) and the
// derived-roster authority (`MeshIntroductionAuthorityTests`).
//
// **This file is deliberately not those tests again.** Each scenario below walks one acceptance
// line across the *integrated* `MeshNetworkManager` — its sealed store, its verifier, its epoch
// keyring, its radio and its state machine at once, on `FakeMeshTransportSession` with every
// instant passed in — because the failure mode a unit test cannot see is the one where each half
// is right and the seam between them is not. Where an existing unit test already IS the evidence
// for a line, the scenario's doc comment names it and adds only what the unit test cannot reach.
//
// Nothing here reads a wall clock for a *decision*: `now` and `monotonicElapsed` are arguments,
// the grace window is measured from an instant the test captured, and the only real time that
// passes is whatever the seal takes.
//
// A partial copy (ProximityKit plan step A1.3, batch D: the cells of the Fernlet repository's tests
// that read this module's sources, copied before Fernlet deletes its in-tree copy of the module): of
// that repository's FernletTests file of the same name, this holds only the half of
// `MeshP3InteropAcceptanceTests.theGoodbyeGrepWallStillHolds` that reads ProximityKit's code, under the
// suite's and the test's names, over every Swift file of the module through `PackageSwiftFiles`, at the
// walk's floor. The original walks every shipping root of Fernlet's, this module's folder included; its
// other half, Fernlet's own roots, stays there with the rest of the file, so what this header says of
// the rest is not held here.

import Foundation
import Testing

// MARK: - The interop and propagation lines

/// Plan §8.4 acceptance, line 7 (**"legacy `sessionGoodbye` interop"**): the half of its grep-wall
/// that reads ProximityKit's code.
@MainActor
@Suite(.serialized)
struct MeshP3InteropAcceptanceTests {

    /// The other half of the interop line: no shipping source EMITS a goodbye any more. Item 3's
    /// `MeshMembershipEventWireTests.noShippingSourceEmitsAGoodbye` is the same wall
    /// (`MeshLegacyGoodbyeInteropTests` in this target); the battery re-affirms it here because "parsed,
    /// never emitted" is half of the acceptance line.
    ///
    /// **Not vacuous.** The walk reads at least ``PackageSwiftFiles/sourceFloor`` files; the needle's
    /// stem, `sendEnvelope(`, is still spelled on some line of them, so a sender renamed out from under
    /// the needle reddens rather than leaving it matching nothing; and the token the wall is about is
    /// still a case (`case sessionGoodbye`), so "never emitted" is said of a live frame.
    @Test func theGoodbyeGrepWallStillHolds() throws {
        let files = try PackageSwiftFiles.sources()
        #expect(files.count >= PackageSwiftFiles.sourceFloor, """
            the goodbye grep-wall read \(files.count) Swift files under \(PackageSwiftFiles.sourceFolder), \
            below its floor \(PackageSwiftFiles.sourceFloor): the walk is broken, not the module clean
            """)
        var offenders: [String] = []
        var senders = 0
        // R2: bounded by the module's file list × each file's lines.
        for file in files {
            for line in file.text.components(separatedBy: .newlines) where line.contains("sendEnvelope(") {
                senders += 1
                if line.contains("sendEnvelope(.sessionGoodbye") { offenders.append(file.path) }
            }
        }
        #expect(offenders.isEmpty, "still emitting `.sessionGoodbye`: \(offenders.sorted())")
        #expect(senders >= 1, """
            no line of the module calls `sendEnvelope(`, the stem of the wall's needle: the sender was \
            renamed or moved, and the wall now matches nothing
            """)
        #expect(files.contains { $0.text.contains("case sessionGoodbye") },
                "the goodbye is no longer a case of the module's roles, so the wall speaks of no frame")
    }
}
