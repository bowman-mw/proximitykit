// PackageTestBindings.swift
// ProximityKitTests
//
// ProximityKit plan step A1.1: the call shapes ProximityKit's package suites were written against,
// restored over the package tests' namespace, `.packageTest` (TestSupport/PackageTestNamespace.swift).
// ProximityKit offers no namespace default: every API that used to spell an app's bytes for itself takes
// the host's `ProximityNamespace`, or a value read off it. The suites that moved here from FernletTests
// were written against the old shapes, which FernletTests restores over Fernlet's namespace in
// Tests/FernletTests/ProximityNamespaceTestBindings.swift. Each shape here is that file's binding, its
// code copied verbatim with `.fernlet` replaced by `.packageTest` and its doc comment saying what it
// binds to here.
//
// A REPLACEMENT, NOT A TWIN. A twin is one file both test targets compile alike; this file and Fernlet's
// cannot be one, because this half binds to the package tests' namespace and Fernlet's to Fernlet's,
// which the package cannot name. CIGateSelectorBoundaryTests.everyTwinMatchesItsOriginal() holds the
// pair as a replacement: every declaration here equals one declaration of Fernlet's file once
// `.packageTest` reads `.fernlet`, so a shape cannot drift from the one the suites were written
// against, and the extensions both files declare are declared nowhere else. THE RULE is Fernlet's
// file's: a binding restores a call SHAPE, never a value, passing `.packageTest`, the one namespace the
// package's suites compute under. Only the shapes a package suite fails to compile without are here.

import Foundation
@testable import ProximityKit

// MARK: - Hashes, AEAD, salts, epoch: the routed digests and ids

/// The routed digest's chunk id in the shape the suites were written against, over the package tests'
/// labels.
extension MeshRoutedContentDigest {

    /// `chunkID(itemID:chunkIndex:in: .packageTest)`.
    static func chunkID(itemID: UUID, chunkIndex: UInt32) -> UUID {
        chunkID(itemID: itemID, chunkIndex: chunkIndex, in: .packageTest)
    }
}

// MARK: - Hashes, AEAD, salts, epoch: the epoch

/// The epoch's two minting doors in the shapes the suites were written against, over the package
/// tests' labels: every epoch id is derived under `.packageTest`'s epoch domain.
extension MeshEpochRef {

    /// `minted(counter:coordinatorFingerprint:meshID:in: .packageTest)`.
    static func minted(counter: UInt32, coordinatorFingerprint: String, meshID: UUID) -> MeshEpochRef? {
        minted(counter: counter, coordinatorFingerprint: coordinatorFingerprint, meshID: meshID, in: .packageTest)
    }

    /// `successor(coordinatorFingerprint:meshID:in: .packageTest)`.
    func successor(coordinatorFingerprint: String, meshID: UUID) -> MeshEpochRef? {
        successor(coordinatorFingerprint: coordinatorFingerprint, meshID: meshID, in: .packageTest)
    }
}

// MARK: - The radios

/// The friend mesh radio's argument-less initializer, restored over `init(namespace:)` with the
/// package tests' namespace. The radio is internal, so this file imports ProximityKit `@testable`; it
/// inherits the class's main-actor isolation, as the initializer it replaces had.
extension NetworkMeshSession {

    /// `NetworkMeshSession(namespace: .packageTest)`: the friend mesh's radio on the package tests'
    /// wire, the radio the retired `init()` built on Fernlet's.
    convenience init() {
        self.init(namespace: .packageTest)
    }
}
