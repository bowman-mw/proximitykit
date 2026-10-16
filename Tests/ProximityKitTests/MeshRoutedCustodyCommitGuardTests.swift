// MeshRoutedCustodyCommitGuardTests.swift
// ProximityKitTests
//
// The routed store's custody commit (`MeshRoutedStore.committingCustody(item:custodian:now:)`) on an item
// it holds only part of: a cell of this package's own, beside the suites copied from the Fernlet
// repository's tests, which commit whole items. The commit answers an item whose index holds fewer chunks
// than its manifest names from the index alone, before it opens the seal key or reads a chunk file, so a
// partial item is never measured, repaired or rewritten there. The stream past that guard would answer
// the same `.incomplete` when every held slot's file is sound; it differs when one is not: a missing file
// drops its slot from the index, which is rewritten, and the item answers one chunk fewer. So the cell
// stages one slot of three, deletes that slot's file, and holds the answer to the index's count and the
// store's files to the bytes they held before the commit.
//
// The store is on a scope of the cell's own, built per call by `MeshRoutedStoreFixtures.scope()` on a
// fresh folder under the temporary directory and a `.test.` service, and torn down after.

import Foundation
@testable import ProximityKit
import Testing

/// The custody commit answers a partly staged item `.incomplete` from its index, writing nothing.
@MainActor
@Suite(.serialized) struct MeshRoutedCustodyCommitGuardTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer has
    /// run before a cell builds a store, whose seal key the keychain holds.
    let keychain = PackageTestEnvironment.keychain

    /// **A partly staged item answers `.incomplete` before a chunk file is read.** A three-chunk item
    /// with only its first slot staged, that slot's file deleted, commits to
    /// `.completed(.incomplete(received: 1, expected: 3))`, the index's own count, and the store's files
    /// are byte for byte what they were before the commit: the slot whose file is gone was not read,
    /// dropped or repaired, and the index was not rewritten.
    @Test func aPartlyStagedItemAnswersIncompleteBeforeReadingAChunkFile() throws {
        let scope = MeshRoutedStoreFixtures.scope()
        defer { MeshRoutedStoreFixtures.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope, byteCount: 2 * MeshChunkFormat.maxChunkPayloadBytes + 1_000)
        try #require(rig.chunks.count == 3, "the rig minted \(rig.chunks.count) chunks, not three")
        let first = try #require(rig.chunks.first)
        PackageSwitchableInstallBinding.testOverride.withValue(.identifier(MeshRoutedStoreFixtures.installA)) {
            let admitted = rig.store.admittingManifest(rig.manifest, now: MeshRoutedStoreFixtures.now)
            #expect(admitted.value != nil, "manifest admission: \(admitted)")
            let staged = rig.store.stagingChunk(first, now: MeshRoutedStoreFixtures.now)
            #expect(staged.value != nil, "staging slot 0: \(staged)")
        }
        let files = MeshRoutedCustodyFixtures.chunkFilesOnDisk(scope)
        try #require(files.count == 1, "one staged slot left \(files.count) chunk files")
        try FileManager.default.removeItem(at: try #require(files.first))
        let before = MeshRoutedStoreFixtures.snapshot(scope)

        let outcome = MeshRoutedCustodyFixtures.commit(rig)
        guard case .completed(.incomplete(let received, let expected)) = outcome else {
            Issue.record("a partly staged item's custody commit answered \(outcome)")
            return
        }
        #expect(received == 1 && expected == 3, "the commit counted \(received) of \(expected), not the index's 1 of 3")
        #expect(MeshRoutedStoreFixtures.snapshot(scope) == before,
                "the commit wrote to the store: it read the missing file and repaired the index")
        #expect(MeshRoutedCustodyFixtures.loadedIndex(rig.store)?.record(for: rig.key)?.receivedCount == 1,
                "the index no longer holds the staged slot")
    }
}
