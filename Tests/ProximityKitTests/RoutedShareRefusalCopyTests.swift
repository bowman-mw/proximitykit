// RoutedShareRefusalCopyTests.swift
// ProximityKitTests
//
// The P5 review's finding 5: a refused routed share used to reach the user as a `String` composed
// inside ProximityKit, which renders English in every language. The manager now publishes the
// frozen cause on `routedShareRefusal`, and the app forks it into `LocalizedStringKey` copy.
//
// A partial copy (ProximityKit plan step A1.3's batch D, which copies here every Fernlet test cell that
// reads this module's sources before Fernlet stops holding them): of the Fernlet repository's
// FernletTests file of the same name, this holds only `RoutedShareRefusalCopyTests`' one cell that
// reads ProximityKit's sources (`theRefusalLeavesThePackageAsATokenOnly`), with the suite's and the
// tests' names unchanged and only each cell's half that reads this module's code, now through
// `PackageRoot` and the package's walker. Each cell's half that reads the app's or Fernlet's other
// modules' code, the suite's other cells and the file's other suites stay there, so what this header
// says of them is not held here.

import Foundation
import Testing

/// The app-side copy the share refusal resolves to: localized by construction, one sentence per
/// frozen cause, and the seam it replaced closed by a wall.
@MainActor
@Suite struct RoutedShareRefusalCopyTests {

    /// The package composes no sentence and the camera presents the typed cause.
    ///
    /// **This copy's half** (plan step A1.3): the package composes no sentence and publishes the
    /// frozen token. The camera's fork of the token into copy and the chat panel's fork of its own
    /// outcome are the app's and stay in the original.
    @Test func theRefusalLeavesThePackageAsATokenOnly() throws {
        let manager = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift")
        )
        #expect(!manager.contains("Couldn't share that photo"),
                "the refusal sentence is composed in the app, never in the package")
        #expect(manager.contains("routedShareRefusal = refusal"),
                "the refusal is published as its frozen token")
    }
}
