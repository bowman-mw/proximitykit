// SessionMessageTests.swift
// Phase 5 — live-session temporary messages on the friend mesh
// (Docs/Proximity-Mesh-Redesign-2026-07-10.md).
//
// Owner decision (binding): messages are exchanged ONLY during a live session and VANISH at session
// end — nothing retained on device, nothing synced, no dead-drop, no offline queue. Covers: the wire
// codec round trip; the registry dispatch path (committed-slot gate drops an uncommitted sender;
// blocked-fingerprint drop, mirroring .friendPhoto); the store's hostile-input guards (sanitize + cap,
// dedup, per-sender rate limit); the transcript clearing on EVERY session-end path (leaveSession,
// leaveMesh, removeSlot via evictSlotForTesting) AND on the next session formation; the structural
// guarantee that the transcript never reaches the persisted snapshot; and the capability-gated room
// broadcast (a legacy / photos-only peer is skipped). Since ProximityKit plan step A0.5.9 the
// transcript, the sender and the gate are FernletSocial's chat (`store.meshFeatures.chat`), and the
// mesh keeps the session-content generation, which it advances at the three moments the chat's
// transcript is dropped: two cells hold it to exactly those moments.
//
// A partial copy (ProximityKit plan step A1.3's batch D, which copies here every Fernlet test cell that
// reads this module's sources before Fernlet stops holding them): of the Fernlet repository's
// FernletTests file of the same name, this holds only `SessionMessageTests`' one cell that reads
// ProximityKit's sources (`theGenerationHasOneWriterWhoseThreeCallersPrecedeTheirObserverMoments`),
// with the suite's and the tests' names unchanged and only each cell's half that reads this module's
// code, now through `PackageRoot` and the package's walker. Each cell's half that reads the app's or
// Fernlet's other modules' code, the suite's other cells and the file's other suites stay there, so
// what this header says of them is not held here.

import Foundation
import Testing

/// The live session's temporary messages: here, only the mesh's half of the transcript generation's
/// one writer, read from this module's source (the original's other cells drive the app's store).
@Suite(.serialized) @MainActor
struct SessionMessageTests {

    /// **…and nowhere else** (plan step A0.5.9): the generation has ONE writer,
    /// `advanceTranscriptGeneration()`, which adds one, and that writer has exactly three callers — the
    /// forming commit, the session's end and the privacy wipe's begin — each before its session
    /// observer moment. The composition drops the chat's transcript in exactly those three observer
    /// legs, in the order the manager ran them (the formation's between the shop's reset and its
    /// send-tracking clear, the end's after the shop's window), and the chat in one place. A source
    /// pin, because "never elsewhere" is a claim about every path, which no behaviour enumerates.
    ///
    /// **This copy's half** (plan step A1.3): the mesh's writer and its three callers, each before
    /// its observer moment. The composition's three observer legs and the chat's one clear are
    /// `FernletSocial`'s (`FernletMeshFeatures.swift`, `MeshSessionChat.swift`) and stay in the
    /// original.
    @Test func theGenerationHasOneWriterWhoseThreeCallersPrecedeTheirObserverMoments() throws {
        let engine = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift"))
        #expect(engine.components(separatedBy: "transcriptGeneration +=").count - 1 == 1,
                "the generation is advanced in exactly one place")
        #expect(engine.components(separatedBy: "transcriptGeneration = ").count - 1 == 1,
                "and assigned only by its declaration")
        let writer = try #require(MeshRoutedSourceScan.bracedBody(
            after: "private func advanceTranscriptGeneration(", in: engine), "the generation's writer is gone")
        #expect(writer.contains("transcriptGeneration += 1"), "the writer advances it by one")
        #expect(engine.components(separatedBy: "advanceTranscriptGeneration()").count - 1 == 4,
                "the writer's declaration and exactly three callers")
        let moments = [("func noteSlotCommittedForShop(", "sessionObserver?.meshSlotDidCommit("),
                       ("private func endSessionIfEnded(", "sessionObserver?.meshSessionDidEnd("),
                       ("public func beginPrivacyWipe(", "sessionObserver?.meshPrivacyWipeDidBegin(")]
        // R2: bounded by the three moments.
        for (site, observer) in moments {
            let body = try #require(MeshRoutedSourceScan.bracedBody(after: site, in: engine), "\(site) is gone")
            let advance = try #require(body.range(of: "advanceTranscriptGeneration()"), "\(site) advances nothing")
            let told = try #require(body.range(of: observer), "\(site) tells no observer")
            #expect(advance.upperBound <= told.lowerBound, "\(site) advances after its observer moment")
        }
    }
}
