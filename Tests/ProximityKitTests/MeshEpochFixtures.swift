// MeshEpochFixtures.swift
//
// The epoch fixtures: refs minted at a counter by a coordinator in a mesh, fixture group keys and the
// instant every clock-bearing epoch test measures from. A twin (ProximityKit plan step A1.1): the same
// file at Tests/FernletTests and FernletKit/Tests/ProximityKitTests, held identical but for its imports
// by CIGateSelectorBoundaryTests.everyTwinMatchesItsOriginal(), because the package's four epoch suites
// (MeshEpochModelTests.swift) and three FernletTests files (the P3 acceptance, rotation trigger and
// session store suites) build fixtures with it, and a test target cannot import another. Its one mint,
// `MeshEpochRef.minted(counter:coordinatorFingerprint:meshID:)`, is a test binding, so each half mints
// under its own target's namespace: in FernletTests through ProximityNamespaceTestBindings.swift, under
// Fernlet's labels (`.fernlet`, the values the staying suites always saw), and in ProximityKit's package
// tests through TestSupport/PackageTestBindings.swift, under the package tests' namespace
// (`.packageTest`).

import Foundation
import Testing
@testable import ProximityKit

/// Fixtures shared by the epoch suites and by `MeshSessionStoreTests`, which persists these.
enum MeshEpochFixtures {

    /// The mesh every fixture ref is minted against.
    static let meshID = UUID(uuidString: "1D3F9A0C-0305-4F89-9A0C-0305E82C3301") ?? UUID()

    /// A second mesh, for proving the derivation is mesh-scoped.
    static let otherMeshID = UUID(uuidString: "2D3F9A0C-0305-4F89-9A0C-0305E82C3302") ?? UUID()

    /// The default coordinator fingerprint: canonical 16-character lowercase hex.
    static let coordinatorA = "00000000000000aa"

    /// A second coordinator — what a *different partition's* lowest fingerprint looks like.
    static let coordinatorB = "00000000000000bb"

    /// A ref at `counter`, minted by `coordinator` in `meshID`.
    ///
    /// No `!` and no `fatalError` (Power of 10 rule 7): minting *refuses* rather than traps, so the
    /// fixture records the issue and falls back to the module-internal validated-parts initializer
    /// with an all-zero id. Every suite below asserts on values whose mint cannot refuse, so the
    /// fallback is never the value under test — it exists so a broken fixture fails an assertion
    /// instead of crashing the whole suite.
    static func ref(
        _ counter: UInt32,
        coordinator: String = coordinatorA,
        meshID: UUID = meshID
    ) -> MeshEpochRef {
        guard let minted = MeshEpochRef.minted(
            counter: counter, coordinatorFingerprint: coordinator, meshID: meshID
        ) else {
            Issue.record("fixture could not mint epoch \(counter) for \(coordinator)")
            return MeshEpochRef(counter: 0, epochID: UUID(), coordinatorFingerprint: coordinatorA)
        }
        return minted
    }

    /// A group key bound to a counter. The bytes are fixture bytes; nothing here is a real key.
    @MainActor
    static func key(_ counter: UInt32) -> MeshGroupKey {
        MeshGroupKey(
            epoch: Int(counter),
            keyBytes: Data(repeating: UInt8(truncatingIfNeeded: counter), count: 32),
            activeSince: base
        )
    }

    /// The fixed instant every clock-bearing test measures from.
    static let base = Date(timeIntervalSince1970: 1_800_000_000)
}
