// PrivacyWipeCoverageTests.swift
// ProximityKitTests
//
// Mechanical enforcement of the Fernlet repository's Docs/PrivacyWipeCoverage.md: that repository's
// "Delete everything" path must keep clearing every persistence surface in its manifest, and every
// holder of a live identity must keep the seam that path calls to drop the identity's in-memory
// caches with its keychain rows.
//
// A partial copy (ProximityKit plan step A1.3, which copies into the package every cell of the Fernlet
// repository's tests that reads this module's sources before that repository stops holding them): of
// the Fernlet repository's FernletTests file of the same name, this holds only the ProximityKit half of
// `PrivacyWipeCoverageTests.everyLiveIdentityCacheHasAWipeSeam`, with the suite's name and its own
// unchanged: the two identity holders that are this module's, each read through `PackageRoot`. The
// third holder, FernletSocial's presence manager, the wipe path's own scans and the behavioural suites
// stay in that repository's original, so what this header says of them is not held here.

import Foundation
import Testing

/// Every identity holder of this module keeps its wipe seam: the host's "delete everything" path drops
/// a live identity's in-memory caches through it, so a holder that lost it would keep the identity
/// alive after its keychain rows are gone.
@Suite
struct PrivacyWipeCoverageTests {

    /// This module's identity holders whose live in-memory identity caches must die with the keychain
    /// rows: the mesh manager and the recipe pair session (whose owner, the host's recipe-share
    /// manager, forwards the store's wipe to it), by their paths under the package root. The third
    /// holder the Fernlet repository's original lists, its presence manager, is FernletSocial's.
    private static let identitySeamFiles = [
        "Sources/ProximityKit/Mesh/MeshNetworkManager.swift",
        "Sources/ProximityKit/PairSession/ProximityPairSession.swift",
    ]

    /// Each identity holder's source still declares `wipeIdentityForDeleteAll`.
    @Test func everyLiveIdentityCacheHasAWipeSeam() throws {
        // R2: bounded by the two holders.
        for file in Self.identitySeamFiles {
            let source = try PackageRoot.source(file)
            #expect(source.contains("func wipeIdentityForDeleteAll"), "\(file) owns a live IdentityService but lost its wipe seam.")
        }
    }
}
