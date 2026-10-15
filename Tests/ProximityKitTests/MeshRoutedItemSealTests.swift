// MeshRoutedItemSealTests.swift
// ProximityKitTests
//
// P5 item 13, pass A (plan §11, invariant §3.3): the routed ITEM seal and the routed photo BODY —
// the reserved half of item 1's pair, now written.
//
// Four claims are walled here:
//
// 1. **The authenticated data is pinned, and derived independently.** `goldenItemAADHex` and
//    `goldenItemBlobHex` were computed from the FORMAT by a Python re-implementation
//    (`derive_golden_item.py`) that first reproduced item 1's shipped `goldenWrapAADHex`
//    byte-for-byte. A golden that only records what the code did proves nothing; these were
//    computed apart and then met. The blob vector is an OPEN-side vector, so no test-only nonce
//    injection reaches production.
// 2. **The seal is a transplant proof.** Perturbing any one of the four authenticated fields —
//    mesh, item, origin, type token — refuses the open, which is what lets branch and epoch stop
//    deciding decryptability.
// 3. **One number bounds both ends.** The seal refuses exactly the plaintext the open would refuse,
//    so no recipient can receipt an item it will later decline to open.
// 4. **The body framing is frozen**: a length-prefixed JSON header and the image RAW, never one
//    `Codable` blob, because base64 would inflate every byte bound in the phase by a third. Two
//    vectors pin it — one without a `session` and one with, since a populated `session` is the only
//    part of the routed body whose keys belong to `FernletDomainModel` rather than to this module.
//
// Nothing here sleeps, touches disk, or reads a wall clock for a decision.
//
// A partial copy (ProximityKit plan step A1.3's batch D, the routed track): of the Fernlet
// repository's FernletTests file of the same name, this holds only the ProximityKit half
// of `MeshRoutedItemSealTests.theRoutedPhotoBodyNamesNoEpoch`, under its suite's name and its own: the
// item seal's file names no epoch. The body's half (FernletSocial's `MeshRoutedPhotoBody.swift`), the
// suite's other cells, the fixtures and the golden suite stay there, so what this header says of them
// is not held here.

import Foundation
import Testing

// MARK: - Seal and open

/// The routed item seal and the routed photo body, value by value; this copy holds the one cell
/// that reads ProximityKit's source.
struct MeshRoutedItemSealTests {

    // MARK: - Body

    /// B-2: the sealed plaintext names no epoch — the property that makes branch and epoch stop
    /// deciding decryptability. The body is FernletSocial's since plan step A0.5.11
    /// (`MeshRoutedPhotoBody.swift`, moved from ProximityKit's `MeshRoutedItemBody.swift`).
    ///
    /// **The package half** (ProximityKit plan step A1.3's batch D): the item seal's file, which is
    /// ProximityKit's; the body's file is FernletSocial's, and the Fernlet repository keeps that half.
    @Test func theRoutedPhotoBodyNamesNoEpoch() throws {
        let seal = try PackageRoot.source("Sources/ProximityKit/Mesh/MeshRoutedItemSeal.swift")
        #expect(!MeshRoutedSourceScan.codeOnly(seal).contains("keyEpoch"))
    }
}
