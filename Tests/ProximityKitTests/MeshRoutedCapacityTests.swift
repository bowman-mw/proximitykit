// MeshRoutedCapacityTests.swift
// ProximityKitTests
//
// Network migration P5 item 9 (plan §11's backpressure clause, §3.4's "bounded everything"): the
// STORE half — every cap refused by its own name at every door, the cap model as one injectable
// value, the parked-set drop rule, and the sweeps that finally have callers.
//
// Three disciplines the whole file runs on:
//
// - **Injected small bounds wherever the claim is about a cap rather than about the constant.**
//   `MeshRoutedStore(scope:capacity:)` is the seam, and it is the SAME model the doors and the
//   accounting read — cell `theUsageReadsTheStoresOwnCapacity` is what stops those diverging.
// - **The at-rest guards stay the FORMAT's.** `init(from:)` is a `Codable` initialiser with no
//   injection point, and an injected capacity is always ≤ production, so an index written under
//   small bounds still decodes clean. Two cells pin exactly that.
// - **Backpressure is not data loss.** A capacity refusal writes nothing and drops nothing; the one
//   rule that removes held bytes on a refusal is `unknownTypeToken` **from the set's own origin**,
//   and the rest of the ten-case table is asserted, not merely written down.
//
// Every test runs on its own scope (temp directory + a `.test.` keychain service), in
// `MeshRoutedStoreIsolationTests`' idiom.
//
// Since ProximityKit plan step A1's third batch of copied suites (those that reach the keychain and open
// a store), this holds the whole of the Fernlet repository's FernletTests file of the same name as it
// stood before that repository's plan step A1.3: `MeshRoutedCapacityTests` with all twenty-two cells, two
// of which, `everyIndexGrowthSiteAnswersACap` and `theStoreHasExactlyTwoAdmissionDoors`, read
// ProximityKit's sources and came here first with the two source-scanning helpers they call, at plan step
// A1.3's batch D, and the suite's fixtures and the file's two other suites, `MeshRoutedParkedDropTests`
// and `MeshRoutedSweepTests`, with their names and tests unchanged.

import CryptoKit
import Foundation
import Testing
@testable import ProximityKit

// MARK: - Fixtures

/// Item 9's own small helpers over ``MeshRoutedStoreFixtures``.
@MainActor
enum MeshRoutedCapacityFixtures {

    /// Production's cap model with the named fields overridden — so a cell that means "the item cap"
    /// says so, and never restates a number it does not care about.
    static func bounds(
        maxItems: Int = MeshRoutedStoreFormat.maxItems,
        maxContentBytes: UInt64 = MeshRoutedStoreFormat.maxContentBytes,
        maxChunksPerItem: Int = MeshRoutedStoreFormat.maxChunksPerItem,
        maxHeldChunkFiles: Int = MeshRoutedStoreFormat.maxHeldChunkFiles,
        maxReceiptsPerItem: Int = MeshRoutedStoreFormat.maxReceiptsPerItem
    ) -> MeshRoutedCapacity {
        _ = PackageTestEnvironment.keychain
        return MeshRoutedCapacity(
            maxItems: maxItems, maxContentBytes: maxContentBytes,
            maxChunksPerItem: maxChunksPerItem, maxHeldChunkFiles: maxHeldChunkFiles,
            maxReceiptsPerItem: maxReceiptsPerItem
        )
    }

    /// The loaded index under the pinned install binding, or nil for every other state.
    static func index(of store: MeshRoutedStore) -> MeshRoutedIndex? {
        _ = PackageTestEnvironment.keychain
        let load = PackageSwitchableInstallBinding.testOverride.withValue(
            .identifier(MeshRoutedStoreFixtures.installA)
        ) {
            store.load()
        }
        guard case .loaded(let index, _) = load else { return nil }
        return index
    }

    /// A synthetic record carrying a manifest and a delivery map — what the reclaim enumerators need
    /// and `MeshRoutedStoreFixtures.record` deliberately does not build.
    static func delivered(
        _ manifest: MeshRoutedManifest,
        to states: [String: String],
        chunks: [MeshRoutedChunkDescriptor] = [],
        receipts: [MeshCustodyReceipt] = [],
        recipientReceipts: [MeshRecipientReceipt] = []
    ) -> MeshRoutedItemRecord {
        var progress: [String: MeshRoutedDeliveryProgress] = [:]
        for (destination, token) in states {
            progress[destination] = MeshRoutedDeliveryProgress(token: token, custodian: nil)
        }
        return MeshRoutedItemRecord(
            key: MeshRoutedItemKey(manifest),
            contentHash: manifest.contentHash,
            chunkCount: 1,
            expiresAt: manifest.expiresAt,
            manifest: manifest,
            firstSeenAt: MeshRoutedManifestFixtures.base,
            custodiedAt: nil,
            deliveredAt: nil,
            chunks: chunks,
            delivery: MeshRoutedDeliveryRecord(contentID: manifest.itemID, progress: progress),
            receipts: receipts,
            recipientReceipts: recipientReceipts
        )
    }

    /// A manifest for `destinations` with a fresh item id, through the test-only rebuilder — no
    /// signature is checked at a store door, and minting one per cell would cost seconds.
    static func manifest(
        for destinations: [String], size: UInt64? = nil, expiresAt: Date? = nil
    ) -> MeshRoutedManifest {
        MeshRoutedManifestFixtures.manifest().replacing(
            itemID: UUID(),
            size: size,
            expiresAt: expiresAt,
            destinations: destinations,
            keyWraps: destinations.enumerated().map { offset, name in
                MeshRoutedManifestFixtures.fixtureWrap(name, fill: UInt8(truncatingIfNeeded: offset))
            }
        )
    }
}

// MARK: - The caps

/// Every cap, refused by its own name at every door it guards — under INJECTED bounds, so the claim
/// is about the cap and not about how long it takes to reach 1024 records.
@MainActor
@Suite(.serialized)
struct MeshRoutedCapacityTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer
    /// has run before a cell's identities or stores reach the keychain.
    let keychain = PackageTestEnvironment.keychain

    private typealias Fixture = MeshRoutedStoreFixtures
    private typealias Caps = MeshRoutedCapacityFixtures

    private func admitting(
        _ manifest: MeshRoutedManifest, in store: MeshRoutedStore
    ) -> MeshRoutedOutcome<MeshRoutedManifestAdmission> {
        PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.admittingManifest(manifest, now: Fixture.now)
        }
    }

    private func staging(
        _ chunk: MeshChunk, in store: MeshRoutedStore
    ) -> MeshRoutedOutcome<MeshChunkAdmission> {
        PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.stagingChunk(chunk, now: Fixture.now)
        }
    }

    /// The item cap is the FIRST answer at both admission doors — the manifest's and the chunk's.
    @Test func theItemCapRefusesAtBothAdmissionDoors() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope, capacity: Caps.bounds(maxItems: 2))
        try Fixture.plant(MeshRoutedIndex(items: [Fixture.record(), Fixture.record()]), into: store)

        #expect(admitting(MeshRoutedManifestFixtures.manifest(), in: store).refusal == .capacityItems)

        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope, byteCount: 2_000)
        let first = try #require(rig.chunks.first)
        #expect(staging(first, in: store).refusal == .capacityItems)
        #expect(Caps.index(of: store)?.itemCount == 2, "a refusal writes nothing")
    }

    /// The byte cap likewise, and nothing at all is written on either refusal.
    @Test func theByteCapRefusesAtBothAdmissionDoors() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope, capacity: Caps.bounds(maxContentBytes: 4_096))
        let hog = Fixture.record(chunks: [Fixture.descriptor(index: 0, count: 1, bytes: 4_096)])
        try Fixture.plant(MeshRoutedIndex(items: [hog]), into: store)
        let before = Fixture.snapshot(scope)

        #expect(admitting(MeshRoutedManifestFixtures.manifest(), in: store).refusal == .capacityBytes)

        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope, byteCount: 2_000)
        let first = try #require(rig.chunks.first)
        #expect(staging(first, in: store).refusal == .capacityBytes)
        #expect(Fixture.snapshot(scope) == before, "a capacity refusal writes no byte")
    }

    /// The file cap, and the chunk door's DIRECTORY half: an orphan cannot hide from the one cap
    /// that bounds it.
    @Test func theFileCapRefusesAtBothAdmissionDoors() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope, capacity: Caps.bounds(maxHeldChunkFiles: 2))
        let held = Fixture.record(chunkCount: 2, chunks: [
            Fixture.descriptor(index: 0, count: 2, bytes: 1),
            Fixture.descriptor(index: 1, count: 2, bytes: 1)
        ])
        try Fixture.plant(MeshRoutedIndex(items: [held]), into: store)

        #expect(admitting(MeshRoutedManifestFixtures.manifest(), in: store).refusal == .capacityChunkFiles)

        // The same cap, reached through the DIRECTORY rather than the index: an empty index and two
        // orphan files on disk still refuse.
        try Fixture.plant(MeshRoutedIndex(items: []), into: store)
        try FileManager.default.createDirectory(
            at: store.chunkDirectory, withIntermediateDirectories: true
        )
        for _ in 0..<2 {
            try Data([0x01]).write(to: store.chunkFileURL(named: MeshRoutedStore.newChunkFileName()))
        }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope, byteCount: 2_000)
        let first = try #require(rig.chunks.first)
        #expect(staging(first, in: store).refusal == .capacityChunkFiles)
    }

    /// The per-item chunk cap belongs to the chunk door alone.
    @Test func thePerItemChunkCapRefusesAtTheChunkDoor() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope, capacity: Caps.bounds(maxChunksPerItem: 1))
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        #expect(rig.chunks.count == 2, "the default rig blob is two chunks")

        #expect(admitting(rig.manifest, in: store).value != nil)
        #expect(staging(rig.chunks[0], in: store).value != nil)
        #expect(staging(rig.chunks[1], in: store).refusal == .capacityChunksPerItem)
    }

    /// The custody-receipt cap, at both doors that can grow the evidence set.
    @Test func theReceiptCapRefusesAtTheTransferAndEvidenceDoors() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope, capacity: Caps.bounds(maxReceiptsPerItem: 1))
        let manifest = MeshRoutedManifestFixtures.manifest()
        let held = MeshCustodyReceiptFixtures.receipt().replacing(custodianFingerprint: "fpc0")
        try Fixture.plant(
            MeshRoutedIndex(items: [Caps.delivered(manifest, to: [:], receipts: [held])]),
            into: store
        )
        let fresh = MeshCustodyReceiptFixtures.receipt().replacing(custodianFingerprint: "fpc9")

        let transfer = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.recordingCustodyTransfer(
                item: MeshRoutedItemKey(manifest), for: ["fp002"], receipt: fresh, now: Fixture.now
            )
        }
        #expect(transfer.refusal == .capacityReceipts)

        let evidence = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.recordingCustodyEvidence(
                item: MeshRoutedItemKey(manifest), receipt: fresh, now: Fixture.now
            )
        }
        #expect(evidence.refusal == .capacityReceipts)
    }

    /// The recipient-receipt cap keeps its own token beside the custody one.
    @Test func theRecipientReceiptCapRefusesAtTheDeliveryDoor() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope, capacity: Caps.bounds(maxReceiptsPerItem: 1))
        let manifest = MeshRoutedManifestFixtures.manifest()
            .replacing(typeToken: MeshRoutedTypeToken.photo)
        let held = MeshRecipientReceiptFixtures.receipt().replacing(recipientFingerprint: "fp003")
        try Fixture.plant(
            MeshRoutedIndex(items: [Caps.delivered(manifest, to: [:], recipientReceipts: [held])]),
            into: store
        )

        let outcome = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.recordingRecipientReceipt(
                item: MeshRoutedItemKey(manifest),
                receipt: MeshRecipientReceiptFixtures.receipt(), now: Fixture.now
            )
        }
        #expect(outcome.refusal == .capacityRecipientReceipts)
    }

    /// The shipping model is the format constants and nothing else — no number is written twice.
    @Test func theProductionCapacityIsExactlyTheFormatConstants() {
        let production = MeshRoutedCapacity.production
        #expect(production.maxItems == MeshRoutedStoreFormat.maxItems)
        #expect(production.maxContentBytes == MeshRoutedStoreFormat.maxContentBytes)
        #expect(production.maxChunksPerItem == MeshRoutedStoreFormat.maxChunksPerItem)
        #expect(production.maxHeldChunkFiles == MeshRoutedStoreFormat.maxHeldChunkFiles)
        #expect(production.maxReceiptsPerItem == MeshRoutedStoreFormat.maxReceiptsPerItem)
        #expect(MeshRoutedStore(scope: Fixture.scope()).capacity == production,
                "the default store takes the shipping model")
    }

    /// D-3.12 unchanged: an index over the FORMAT cap is corrupt at rest, byte-for-byte preserved.
    @Test func anAtRestOverCapIndexIsCorruptAndUnchanged() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        let over = (0...MeshRoutedStoreFormat.maxItems).map { _ in Fixture.record() }
        try Fixture.plant(MeshRoutedIndex(items: over), into: store)
        let sealed = try Data(contentsOf: store.indexURL)

        let load = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.load()
        }
        guard case .corrupt(let corruption) = load else {
            Issue.record("an over-cap index must load corrupt: \(load)")
            return
        }
        #expect(corruption.detail == .undecodableJSON("capacityExceeded:items"))
        #expect(try Data(contentsOf: store.indexURL) == sealed, "a corrupt load repairs nothing")
    }

    /// The injected bound is a WRITER bound, never an at-rest one — a `Codable` init has no
    /// injection point, and an injected cap is always ≤ production.
    @Test func injectedBoundsDoNotReclassifyAnAtRestIndex() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let planting = MeshRoutedStore(scope: scope)
        try Fixture.plant(
            MeshRoutedIndex(items: (0..<4).map { _ in Fixture.record() }), into: planting
        )

        let small = MeshRoutedStore(scope: scope, capacity: Caps.bounds(maxItems: 1))
        #expect(Caps.index(of: small)?.itemCount == 4, "the at-rest bound is the format's")
        #expect(admitting(MeshRoutedManifestFixtures.manifest(), in: small).refusal == .capacityItems)
    }

    /// The fourth at-rest sibling: the DECLARED chunk count, guarded beside the three collections.
    @Test func aChunkCountAboveTheCapIsRefusedAtRest() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        try Fixture.plant(
            MeshRoutedIndex(items: [Fixture.record(chunkCount: UInt32.max)]), into: store
        )

        let load = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.load()
        }
        guard case .corrupt(let corruption) = load else {
            Issue.record("an over-cap chunkCount must load corrupt: \(load)")
            return
        }
        #expect(corruption.detail == .undecodableJSON("capacityExceeded:chunkCount"))
    }

    /// Exactly the cap, at rest, is admitted — the guard is `<=`, so a maximal item still loads.
    @Test func aChunkCountAtTheCapStillLoads() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        let atCap = UInt32(MeshRoutedStoreFormat.maxChunksPerItem)
        try Fixture.plant(MeshRoutedIndex(items: [Fixture.record(chunkCount: atCap)]), into: store)

        #expect(Caps.index(of: store)?.items.first?.chunkCount == atCap)
    }

    /// C10 made countable: parked sets are named by their own enumerator and by the usage value.
    @Test func parkedSetsAreCountedAndEnumerated() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        let parked = Fixture.record(chunks: [Fixture.descriptor(index: 0, count: 1, bytes: 512)])
        let manifested = Caps.delivered(MeshRoutedManifestFixtures.manifest(), to: [:])
        try Fixture.plant(MeshRoutedIndex(items: [parked, manifested]), into: store)
        let index = try #require(Caps.index(of: store))

        #expect(index.parkedItems(at: Fixture.now).map(\.key) == [parked.key])
        let usage = store.capacityUsage(of: index, at: Fixture.now)
        #expect(usage.itemCount == 2, "a parked item is a real item")
        #expect(usage.parkedItemCount == 1)
        #expect(usage.parkedContentBytes == 512)
    }

    /// The accounting reads the STORE's own model, never `.production` beside an injected door.
    @Test func theUsageReadsTheStoresOwnCapacity() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope, capacity: Caps.bounds(maxItems: 1))
        try Fixture.plant(MeshRoutedIndex(items: [Fixture.record()]), into: store)
        let index = try #require(Caps.index(of: store))

        let mine = store.capacityUsage(of: index, at: Fixture.now)
        #expect(mine.hasRoomToAdmit == false, "the injected cap is the one that decides")
        let production = MeshRoutedCapacityUsage(
            index: index, at: Fixture.now, capacity: .production, directoryFileCount: 0
        )
        #expect(production.hasRoomToAdmit, "and the two models really do differ here")
    }

    /// The release predicate measures **what the chunk door measures**: the file cap against
    /// `max(index, directory)`, so a hold cannot clear while the door is still refusing.
    ///
    /// Orphans are not hypothetical — every drop verb saves the index before it unlinks, and
    /// `removeChunkFiles` counts a failed unlink rather than swallowing it.
    @Test func theRoomPredicateMeasuresWhatTheChunkDoorMeasures() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope, capacity: Caps.bounds(maxHeldChunkFiles: 2))
        try Fixture.plant(MeshRoutedIndex(items: []), into: store)
        try FileManager.default.createDirectory(
            at: store.chunkDirectory, withIntermediateDirectories: true
        )
        // R2: a hard constant ceiling — the injected file cap.
        for _ in 0..<2 {
            try Data([0x01]).write(to: store.chunkFileURL(named: MeshRoutedStore.newChunkFileName()))
        }
        let index = try #require(Caps.index(of: store))

        let usage = store.capacityUsage(of: index, at: Fixture.now)
        #expect(usage.chunkFileCount == 0, "the index names none of them — that is what an orphan is")
        #expect(usage.directoryFileCount == 2)
        #expect(usage.hasRoomToAdmit == false,
                "the visible hold would have cleared while the door still refused")
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope, byteCount: 2_000)
        let first = try #require(rig.chunks.first)
        #expect(staging(first, in: store).refusal == .capacityChunkFiles, "the door agrees")

        // And the recovery route the predicate implies actually exists.
        let swept = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.sweepingOrphanChunkFiles()
        }
        #expect(swept.value?.chunkFilesRemoved == 2)
        let after = try #require(Caps.index(of: store))
        #expect(store.capacityUsage(of: after, at: Fixture.now).hasRoomToAdmit,
                "the sweep is what releases the file cap")
    }

    /// A directory this device cannot list is **not** room: an unmeasurable cap reads as full.
    @Test func anUnreadableChunkDirectoryIsNotRoom() {
        let usage = MeshRoutedCapacityUsage(
            index: MeshRoutedIndex(), at: Fixture.now, capacity: .production, directoryFileCount: nil
        )
        #expect(usage.hasRoomToAdmit == false, "an unmeasurable file cap must never read as room")
        #expect(
            MeshRoutedCapacityUsage(
                index: MeshRoutedIndex(), at: Fixture.now, capacity: .production,
                directoryFileCount: 0
            ).hasRoomToAdmit,
            "and an empty one is"
        )
    }

    /// The over-commit map §3(a) named: two items that both admitted and neither can finish.
    @Test func theUsageCountsUnrestorableAndUncompletableItems() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope, capacity: Caps.bounds(maxContentBytes: 100_000))
        let first = Caps.delivered(Caps.manifest(for: ["fp002"], size: 65_536), to: [:])
        let second = Caps.delivered(Caps.manifest(for: ["fp002"], size: 65_536), to: [:])
        // A stored map naming a destination the manifest does not: it will not restore.
        let stranded = Caps.delivered(
            Caps.manifest(for: ["fp002"]), to: ["fp009": MeshDeliveryStateToken.delivered.rawValue]
        )
        try Fixture.plant(MeshRoutedIndex(items: [first, second, stranded]), into: store)
        let index = try #require(Caps.index(of: store))

        let usage = store.capacityUsage(of: index, at: Fixture.now)
        #expect(usage.uncompletableItemCount >= 2, "both 64 KiB items want more than 100 000 bytes")
        #expect(usage.unrestorableItemCount == 1)
        #expect(index.itemCount == 3, "neither condition drops anything")
    }

    /// Every index growth site answers a cap — the census that makes "nothing grows silently"
    /// mechanical rather than a promise.
    @Test func everyIndexGrowthSiteAnswersACap() throws {
        let expected = [
            "MeshRoutedCustody.swift": 5, "MeshRoutedCustodyHandoff.swift": 2,
            "MeshRoutedCustodyCommit.swift": 1, "MeshRoutedDeliveryCommit.swift": 1,
            "MeshRoutedDeliveryIngest.swift": 1
        ]
        var receivers: Set<String> = []
        var total = 0
        for (name, count) in expected.sorted(by: { $0.key < $1.key }) {
            let code = MeshRoutedSourceScan.codeOnly(
                try PackageRoot.source("Sources/ProximityKit/Mesh/\(name)")
            )
            let sites = Self.upsertReceivers(in: code)
            #expect(sites.count == count, "a new growth site owes a capacity answer: \(name)")
            receivers.formUnion(sites)
            total += sites.count
        }
        #expect(total == 10)
        // A THIRD receiver spelling would hide an eleventh site behind a green census: today the
        // sites are spelled `index.upsert(` and `updated.upsert(`, and one of the two admission
        // doors is the latter.
        #expect(receivers == ["index", "updated"])
    }

    /// Every `capacity*` refusal is in the manager's "this device is full" set — a new one that never
    /// becomes visible fails here rather than shipping silent.
    @Test func everyCapacityRefusalIsInTheDeviceIsFullSet() {
        let named = Set(
            MeshRoutedStoreRefusal.allCases
                .filter { $0.rawValue.hasPrefix("capacity") }
        )
        #expect(named == MeshNetworkManager.routedCapacityRefusals)
        #expect(named.count == 6)
        // The narrower subset that may raise the user-visible hold is exactly the three STORE-level
        // admission caps — exactly what `hasRoomToAdmit` can measure again, so no hold is released
        // by a predicate that never saw the cap that raised it.
        #expect(MeshNetworkManager.routedStoreFullRefusals
                == [.capacityItems, .capacityBytes, .capacityChunkFiles])
        #expect(MeshNetworkManager.routedStoreFullRefusals
                .isSubset(of: MeshNetworkManager.routedCapacityRefusals))
        #expect(named.subtracting(MeshNetworkManager.routedStoreFullRefusals)
                == [.capacityChunksPerItem, .capacityReceipts, .capacityRecipientReceipts],
                "the excluded three are the per-item caps, and nothing else")
    }

    /// The "own items" wall (D-9.2): the store has exactly TWO admission doors, and both carry the
    /// capacity check. P6's mint inherits the refusal or fails here.
    @Test func theStoreHasExactlyTwoAdmissionDoors() throws {
        let code = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Mesh/MeshRoutedCustody.swift")
        )
        #expect(Self.occurrences(of: "recordAdmitting(", in: code) == 2, "one definition, one caller")
        #expect(Self.occurrences(of: "recordStaging(", in: code) == 2)
        #expect(Self.occurrences(of: "capacityRefusal(", in: code) == 7,
                "three definitions and four call sites — one per capacity-guarded door")
    }

    /// The origin's own staging into a full store is refused at the door P6's mint will use.
    @Test func anOriginAtCapIsRefusedAtTheDoorAMintWillUse() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope, capacity: Caps.bounds(maxItems: 1))
        try Fixture.plant(MeshRoutedIndex(items: [Fixture.record()]), into: store)

        let own = Caps.manifest(for: ["fp002", "fp003"])
        #expect(admitting(own, in: store).refusal == .capacityItems)
        #expect(Caps.index(of: store)?.itemCount == 1)
    }

    /// The batch hand-off door refuses BY NAME per item, and the batch continues for its sibling —
    /// `capacityReceipts` reached through the batch for the first time (item 8 left it defensive).
    @Test func theTransferDoorRefusesByNameAndTheBatchContinues() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope, capacity: Caps.bounds(maxReceiptsPerItem: 1))
        let full = Caps.manifest(for: ["fp002", "fp003"])
        let room = Caps.manifest(for: ["fp002", "fp003"])
        let held = MeshCustodyReceiptFixtures.receipt().replacing(custodianFingerprint: "fpc0")
        try Fixture.plant(
            MeshRoutedIndex(items: [
                Caps.delivered(full, to: [:], receipts: [held.replacing(itemID: full.itemID)]),
                Caps.delivered(room, to: [:])
            ]),
            into: store
        )
        let fresh = MeshCustodyReceiptFixtures.receipt().replacing(custodianFingerprint: "fpc9")
        let transfers = [full, room].map {
            MeshRoutedCustodyHandoff(
                item: MeshRoutedItemKey($0), destinations: ["fp002"],
                receipt: fresh.replacing(itemID: $0.itemID)
            )
        }

        let outcome = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.recordingCustodyHandoff(transfers, now: Fixture.now)
        }
        guard case .completed(let report) = outcome else {
            Issue.record("the batch door must complete: \(outcome)")
            return
        }
        #expect(report.refused.map(\.refusal.token) == [MeshRoutedStoreRefusal.capacityReceipts.rawValue])
        #expect(report.advanced == [MeshRoutedItemKey(room)], "a per-item refusal never aborts a batch")
        let stored = Caps.index(of: store)?.record(for: MeshRoutedItemKey(full))
        #expect(stored?.receipts.count == 1, "nothing was written for the refused item")
    }

    /// A claim writes rungs and no receipts, so it can never answer a capacity refusal — and it is
    /// NEW retention, which is why the reclaim exists at all.
    @Test func aClaimAddsNoBytesAndNeverRefusesForCapacity() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope, capacity: Caps.bounds(maxReceiptsPerItem: 1))
        let manifest = Caps.manifest(for: ["fp002", "fp003"])
        let held = MeshCustodyReceiptFixtures.receipt()
            .replacing(itemID: manifest.itemID, custodianFingerprint: "fpc0")
        let record = Caps.delivered(
            manifest, to: [:],
            chunks: [Fixture.descriptor(index: 0, count: 1, bytes: 8)], receipts: [held]
        )
        try Fixture.plant(MeshRoutedIndex(items: [record]), into: store)

        let outcome = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.claimingHandedOffLegs(
                [MeshRoutedHandoffClaim(
                    item: MeshRoutedItemKey(manifest), destinations: ["fp002"], custodian: "fpc0"
                )],
                now: Fixture.now
            )
        }
        guard case .completed(let report) = outcome else {
            Issue.record("the claim door must complete: \(outcome)")
            return
        }
        #expect(report.refused.isEmpty, "a claim has no capacity refusal to answer")
        #expect(Caps.index(of: store)?.record(for: MeshRoutedItemKey(manifest))?.chunks.count == 1,
                "a claim adds no bytes")
    }

    // MARK: Source scanning

    /// The receiver names of every `.upsert(` call in `code`.
    private static func upsertReceivers(in code: String) -> [String] {
        var found: [String] = []
        var scanner = Substring(code)
        while let range = scanner.range(of: ".upsert(") {
            let head = scanner[scanner.startIndex..<range.lowerBound]
            let name = head.reversed().prefix { $0.isLetter || $0.isNumber }
            found.append(String(name.reversed()))
            scanner = scanner[range.upperBound...]
        }
        return found
    }

    /// How many times `needle` appears in `code`.
    private static func occurrences(of needle: String, in code: String) -> Int {
        var count = 0
        var scanner = Substring(code)
        while let range = scanner.range(of: needle) {
            count += 1
            scanner = scanner[range.upperBound...]
        }
        return count
    }
}

// MARK: - The parked-set drop rule

/// The ONE clause that turns a refused manifest into dropped bytes, and the ten that do not.
@MainActor
@Suite(.serialized)
struct MeshRoutedParkedDropTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer
    /// has run before a cell's identities or stores reach the keychain.
    let keychain = PackageTestEnvironment.keychain

    /// The whole rule, asserted case by case rather than described.
    @Test func onlyAnUnknownTypeTokenFromTheOriginDrops() {
        for rejection in MeshRoutedManifestRejection.allCases {
            let fromOrigin = MeshRoutedParkedDrop.reason(
                rejection: rejection, senderIsClaimedOrigin: true
            )
            let expected: MeshRoutedParkedDrop.Reason? =
                rejection == .unknownTypeToken ? .unknownTypeToken : nil
            #expect(fromOrigin == expected, "the eleven-case table is the whole rule")
        }
    }

    /// The delete lever, closed: a third party's refusal drops nothing, whatever the rejection.
    @Test func aThirdPartysRefusalNeverDrops() {
        for rejection in MeshRoutedManifestRejection.allCases {
            #expect(
                MeshRoutedParkedDrop.reason(rejection: rejection, senderIsClaimedOrigin: false) == nil,
                "only the party that could have parked the set may drop it"
            )
        }
    }

    /// The reason vocabulary is frozen English with exactly one member this phase.
    @Test func theDropReasonVocabularyIsFrozen() {
        #expect(MeshRoutedParkedDrop.Reason.allCases.map(\.rawValue) == ["unknownTypeToken"])
    }

    /// Only a PARKED record is ever removed by the rule's door — `dropping(item:reason:)` has no
    /// guard of its own, so the caller is the guard.
    @Test func theDropDoorRemovesTheRecordAndItsFiles() throws {
        let scope = MeshRoutedStoreFixtures.scope()
        defer { MeshRoutedStoreFixtures.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope, byteCount: 2_000)
        MeshRoutedCustodyFixtures.stageAll(rig)
        let before = MeshRoutedCapacityFixtures.index(of: store)
        #expect(before?.heldChunkFileCount == 1)

        let outcome = PackageSwitchableInstallBinding.testOverride.withValue(
            .identifier(MeshRoutedStoreFixtures.installA)
        ) {
            store.dropping(item: rig.key, reason: MeshRoutedParkedDrop.Reason.unknownTypeToken.rawValue)
        }
        #expect(outcome.value?.itemsRemoved == 1)
        #expect(outcome.value?.chunkFilesRemoved == 1)
        #expect(MeshRoutedCapacityFixtures.index(of: store)?.itemCount == 0)
    }
}

// MARK: - The sweeps

/// The reclaim and expiry verbs, which until item 9 had no production caller at all.
@MainActor
@Suite(.serialized)
struct MeshRoutedSweepTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer
    /// has run before a cell's identities or stores reach the keychain.
    let keychain = PackageTestEnvironment.keychain

    private typealias Fixture = MeshRoutedStoreFixtures
    private typealias Caps = MeshRoutedCapacityFixtures

    /// An expired parked set goes with its payload files.
    @Test func anExpiredParkedSetIsSweptWithItsFiles() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope, byteCount: 2_000)
        MeshRoutedCustodyFixtures.stageAll(rig)

        let outcome = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.sweepingExpired(now: rig.manifest.expiresAt.addingTimeInterval(1))
        }
        #expect(outcome.value?.itemsRemoved == 1)
        #expect(outcome.value?.chunkFilesRemoved == 1)
        #expect(outcome.value?.chunkFilesFailed == 0)
        #expect(Caps.index(of: store)?.itemCount == 0)
    }

    /// A live item is never swept — the predicate is the clock and nothing else.
    @Test func aLiveItemSurvivesTheExpirySweep() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        try Fixture.plant(MeshRoutedIndex(items: [Fixture.record()]), into: store)

        let outcome = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.sweepingExpired(now: Fixture.now)
        }
        #expect(outcome.value?.itemsRemoved == 0)
        #expect(Caps.index(of: store)?.itemCount == 1)
    }

    /// The bulk verb is ONE index write for a whole batch, and it skips a key it does not hold.
    @Test func theReclaimIsBoundedPerCallAndWritesTheIndexOnce() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        let records = (0..<40).map { _ in Fixture.record() }
        try Fixture.plant(MeshRoutedIndex(items: records), into: store)
        let batch = MeshRoutedDrainBounds.increment1.maxItems

        let first = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.dropping(items: Array(records.prefix(batch).map(\.key)), reason: "delivered")
        }
        #expect(first.value?.itemsRemoved == batch)
        #expect(Caps.index(of: store)?.itemCount == 40 - batch)

        // Idempotent under a replay: the same batch again removes nothing and writes nothing.
        let sealed = try Data(contentsOf: store.indexURL)
        let replay = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.dropping(items: Array(records.prefix(batch).map(\.key)), reason: "delivered")
        }
        #expect(replay.value?.itemsRemoved == 0)
        #expect(try Data(contentsOf: store.indexURL) == sealed)
    }

    /// The positive predicate: a destination merely ABSENT from the roster is not `delivered`, so it
    /// frees no byte — the difference between a reclaim and a deletion.
    @Test func theReclaimRequiresEveryDestinationDelivered() throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 3)
        let names = rig.fingerprints
        let delivered = MeshDeliveryStateToken.delivered.rawValue
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        let known = Caps.manifest(for: [names[1], names[2]])
        let stranger = Caps.manifest(for: [names[1], "fp-not-in-roster"])
        try Fixture.plant(
            MeshRoutedIndex(items: [
                Caps.delivered(known, to: [names[1]: delivered, names[2]: delivered]),
                Caps.delivered(stranger, to: [names[1]: delivered])
            ]),
            into: store
        )
        let index = try #require(Caps.index(of: store))

        #expect(index.everyDestinationDelivered(MeshRoutedItemKey(known), in: rig.roster))
        #expect(index.everyDestinationDelivered(MeshRoutedItemKey(stranger), in: rig.roster) == false,
                "a roster-absent destination reads as departed, never as delivered")
        // The vacuous answer the predicate exists to refuse.
        #expect(index.itemsFullyDelivered(at: Fixture.now, in: rig.roster).count == 2)
    }

    /// A copy this device is a DESTINATION for is never reclaimable — the enumerator is the guard.
    @Test func theReclaimNeverTakesAnItemThisDeviceIsADestinationFor() throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 3)
        let names = rig.fingerprints
        let delivered = MeshDeliveryStateToken.delivered.rawValue
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        let mine = Caps.manifest(for: [names[0], names[1]])
        let courier = Caps.manifest(for: [names[1], names[2]])
        try Fixture.plant(
            MeshRoutedIndex(items: [
                Caps.delivered(mine, to: [names[0]: delivered, names[1]: delivered]),
                Caps.delivered(courier, to: [names[1]: delivered, names[2]: delivered])
            ]),
            into: store
        )
        let index = try #require(Caps.index(of: store))

        let reclaimable = index.itemsReclaimableAsCustodian(
            at: Fixture.now, in: rig.roster, for: names[0]
        )
        #expect(reclaimable.map(\.key) == [MeshRoutedItemKey(courier)])
    }

    /// Reclaimed capacity really is capacity: at the cap, refuse; sweep; the same manifest admits.
    @Test func reclaimedCapacityAdmitsTheNextItem() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope, capacity: Caps.bounds(maxItems: 1))
        let held = Fixture.record()
        try Fixture.plant(MeshRoutedIndex(items: [held]), into: store)
        let manifest = MeshRoutedManifestFixtures.manifest()

        let refused = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.admittingManifest(manifest, now: Fixture.now)
        }
        #expect(refused.refusal == .capacityItems)

        let swept = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.dropping(items: [held.key], reason: "delivered")
        }
        #expect(swept.value?.itemsRemoved == 1)

        let admitted = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.admittingManifest(manifest, now: Fixture.now)
        }
        #expect(admitted.value != nil, "the freed slot is spendable")
    }
}
