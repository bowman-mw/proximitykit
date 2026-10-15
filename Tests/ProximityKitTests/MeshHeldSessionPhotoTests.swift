// MeshHeldSessionPhotoTests.swift
// ProximityKitTests
//
// The owner, 2026-09-30, answering "should the review survive a process kill": "Yes; the pop up
// screen for selecting photos should be the first thing shown. None of the photos should be saved
// to the camera roll until this selection has been made."
//
// Unit 2 of the session-photo design (the model): every session photo — taken here or received —
// is HELD in the sealed pending corpus (`PendingSessionPhotoStore`) from the moment it exists, and
// reaches the friend wall only through the person's answer. These cells pin the design's model
// invariants on the manager: nothing on the wall before the answer (I1), the answer is exact (I4),
// an answered photo never comes back from the mesh (I5), the ending writes nothing (I6), the review
// survives a kill (I7), the launch reconcile waits for a readable wall (I8), duress reveals and
// accepts nothing (I13), the corpus is bounded (I14), peers' photos follow the same rule and "live"
// is the signed mesh id's call (I16), no timer removes a held photo (I19), a keep never loses a photo
// (I22), identity is origin + item id (I23), and a wall that cannot be read never deadlocks the
// review (I25's model half).
//
// Every cell that answers pushes an open routed gate first: the answer reads plaintext (to re-seal
// kept photos under the wall key) and so runs only where the gate is open.
//
// A partial copy (ProximityKit plan step A1.3's batch D, which copies here every Fernlet test cell that
// reads this module's sources before Fernlet stops holding them): of the Fernlet repository's
// FernletTests file of the same name, this holds only `MeshHeldSessionPhotoTests`' one cell that reads
// ProximityKit's sources (`theRoutedRefusalPrecedesTheDecryptAndTheQuota`), with the suite's and the
// tests' names unchanged and only each cell's half that reads this module's code, now through
// `PackageRoot` and the package's walker. Each cell's half that reads the app's or Fernlet's other
// modules' code, the suite's other cells and the file's other suites stay there, so what this header
// says of them is not held here.

import Foundation
import Testing

// MARK: - The model

/// The held-photo model on one manager.
@MainActor
@Suite(.serialized)
struct MeshHeldSessionPhotoTests {

    /// The I5 source half: the tombstone refusal is the photo row's pre-open verdict, which the
    /// engine asks BEFORE the body is opened (no decrypt) and so before the quota (spent inside the
    /// canonical write), and the ending's memory move never names a store (I6).
    ///
    /// Three brace-matched bodies since plan step A0.5.2, because the order is now held in three
    /// places: `dispatchRoutedPlaintext` asks the handler's `.verdictBeforeOpen(` before it invokes
    /// the box's open-then-project step; that step, built by `registerRoutedProjectionHandler`,
    /// opens through `MeshRoutedItemDelivery.openBody(` before it calls the handler's
    /// `.projectRoutedItem(`; and the photo handler's `verdictBeforeOpen` is the settlement. The first
    /// two are the engine's, in the manager; the third is the session photos' projection adapter's,
    /// in `MeshSessionPhotos.swift`, since plan step A0.5.11 (the manager's built-in's before it).
    ///
    /// **This copy's half** (plan step A1.3): the engine's two bodies, and the manager naming neither
    /// the wall-first hold nor the header's liveness test. The settlement in the photo handler and the
    /// same two absences in `FernletSocial`'s `MeshSessionPhotos.swift` stay in the original.
    @Test func theRoutedRefusalPrecedesTheDecryptAndTheQuota() throws {
        let source = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift")
        )
        let dispatch = try #require(MeshRoutedSourceScan.bracedBody(after: "private func dispatchRoutedPlaintext(", in: source))
        let verdict = try #require(dispatch.range(of: ".verdictBeforeOpen(delivery)"))
        let open = try #require(dispatch.range(of: ".openThenProject("))
        #expect(verdict.lowerBound < open.lowerBound, "the pre-open verdict is read before anything is decrypted")
        let register = try #require(MeshRoutedSourceScan.bracedBody(after: "func registerRoutedProjectionHandler<", in: source))
        let decrypt = try #require(register.range(of: "MeshRoutedItemDelivery.openBody("))
        let write = try #require(register.range(of: ".projectRoutedItem("))
        #expect(decrypt.lowerBound < write.lowerBound, "the open precedes the canonical write, and the quota inside it")
        #expect(!source.contains("cachePhoto("),
                "the wall-first hold is gone from the engine")
        #expect(!source.contains("isPhotoFromCurrentSession"),
                "live is the signed mesh id's call, never the header's")
    }
}
