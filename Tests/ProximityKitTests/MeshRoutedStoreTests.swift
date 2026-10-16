// MeshRoutedStoreTests.swift
// ProximityKitTests
//
// P5 item 3 (plan §11, §19.5): the sealed routed-content store — its five-state load, its write
// token, its caps, and the one claim the whole item exists to make.
//
// The claims worth walling here are the ones a later item cannot cheaply re-check:
//
// 1. **A refusal is never an absence.** Three of the five states mean "the field may be full" and
//    NONE of them vends a write token, so a caller holding one structurally cannot overwrite —
//    which, for a store holding other people's ciphertext, is the difference between deferring and
//    destroying custody. D4 makes it live rather than theoretical on every shipping build.
// 2. **Durable before acknowledged (plan §3.6).** No `MeshCustodyReceipt` exists for anything a
//    restart would lose, because a receipt needs a `MeshCustodyDurabilityWitness` and only a
//    returned durable write mints one.
// 3. **The index is authoritative, one way.** Bytes we cannot authenticate are bytes we do not
//    have; bytes we could not read *right now* repair nothing at all.
// 4. **Bounded growth is refused by name at the writer doors and refused as CORRUPTION at rest** —
//    never clamped, because clamping a durable record away is a restart quietly losing acknowledged
//    state.
//
// Every test runs on its OWN scope (temp directory + `com.fernlet.mesh-routed.test.<uuid>` keychain
// service). `MeshRoutedStoreIsolationTests` is the grep-wall that keeps it that way.

import CryptoKit
import Foundation
import Testing
@testable import ProximityKit

// MARK: - Fixtures

/// Per-test scope, index and custody fixtures. Nothing here reads a wall clock or the production
/// scope.
@MainActor
enum MeshRoutedStoreFixtures {

    /// Install identity pinned by most tests, so the binding is deterministic rather than whatever
    /// the simulator's real row happens to be.
    nonisolated static let installA = Data(repeating: 0xA7, count: 16)

    /// A second install, for the "sealed elsewhere" case.
    nonisolated static let installB = Data(repeating: 0xB9, count: 16)

    /// The instant every routed fixture is anchored to, and the injected `now` the verbs take.
    nonisolated static let now = MeshRoutedManifestFixtures.base.addingTimeInterval(600)

    /// A scope nobody else in the process shares: temp directory + a `.test.` keychain service (the
    /// spelling `PrivacyWipeCoverageTests`' service discovery deliberately skips), under the package
    /// tests' namespace, so the store writes `.packageTest`'s names and seal-key account and measures
    /// under its labels (plan step A0.2.8), and the package's switchable install binding, so the store
    /// seals and opens under whatever `PackageSwitchableInstallBinding.testOverride` answers at that
    /// moment (plan step A0.2.9), as Fernlet's adapter answers under its own override.
    static func scope() -> MeshRoutedStorageScope {
        _ = PackageTestEnvironment.keychain
        return MeshRoutedStorageScope(
            namespace: .packageTest,
            directory: FileManager.default.temporaryDirectory
                .appendingPathComponent("MeshRoutedStore-\(UUID().uuidString)", isDirectory: true),
            keychainService: "com.fernlet.mesh-routed.test.\(UUID().uuidString)",
            installBinding: PackageSwitchableInstallBinding()
        )
    }

    /// The write token a load vends, or nil for the three states that vend none.
    static func token(_ load: MeshRoutedLoad) -> MeshRoutedStore.LoadToken? {
        _ = PackageTestEnvironment.keychain
        switch load {
        case .loaded(_, let token), .absent(let token): return token
        case .deferred, .corrupt, .refused: return nil
        }
    }

    /// Saves `index` under a pinned install binding, from an `absent`/`loaded` token.
    static func save(
        _ index: MeshRoutedIndex,
        into store: MeshRoutedStore,
        install: Data = installA
    ) throws {
        try PackageSwitchableInstallBinding.testOverride.withValue(.identifier(install)) {
            guard let token = token(store.load()) else {
                throw MeshRoutedSaveError.tokenFromAnotherStore
            }
            try store.save(index, token: token)
        }
    }

    /// Writes raw bytes straight into the store's index file, bypassing the sealer — the only way to
    /// produce truncated, garbage or empty files.
    static func writeRaw(_ bytes: Data, into store: MeshRoutedStore) throws {
        _ = PackageTestEnvironment.keychain
        try FileManager.default.createDirectory(
            at: store.scope.directory, withIntermediateDirectories: true
        )
        try bytes.write(to: store.indexURL, options: .atomic)
    }

    /// Seals an arbitrary `Encodable` through the store's own sealer and plants it as the index —
    /// the only way to produce a well-sealed file whose CONTENT this build refuses (a wrong schema,
    /// an at-rest cap violation).
    static func plant(_ value: some Encodable, into store: MeshRoutedStore, install: Data = installA) throws {
        _ = PackageTestEnvironment.keychain
        try PackageSwitchableInstallBinding.testOverride.withValue(.identifier(install)) {
            let sealed = try store.sealBytes(value, contentKey: try store.sealKey())
            try writeRaw(sealed, into: store)
        }
    }

    /// Every file under the scope, as `path → bytes` — the file-system spy that proves a refused or
    /// deferred attempt wrote nothing at all.
    static func snapshot(_ scope: MeshRoutedStorageScope) -> [String: Data] {
        let manager = FileManager.default
        guard let walker = manager.enumerator(at: scope.directory, includingPropertiesForKeys: nil) else {
            return [:]
        }
        var found: [String: Data] = [:]
        for case let url as URL in walker {
            guard let bytes = try? Data(contentsOf: url) else { continue }
            found[url.path] = bytes
        }
        return found
    }

    /// Destroys a scope's files and key so a finished test leaves nothing behind.
    static func tearDown(_ scope: MeshRoutedStorageScope) {
        _ = PackageTestEnvironment.keychain
        MeshRoutedStore.wipeForDeleteAll(scope: scope)
        try? FileManager.default.removeItem(at: scope.directory)
    }

    // MARK: Synthetic index records

    /// A descriptor for a chunk that was never minted — enough for the caps to count, and nothing
    /// else. Used only to plant at-rest states no shipped writer would produce.
    static func descriptor(index: UInt32, count: UInt32, bytes: Int) -> MeshRoutedChunkDescriptor {
        MeshRoutedChunkDescriptor(
            descriptor: MeshChunkDescriptor(
                meshID: MeshRoutedManifestFixtures.meshID, itemID: UUID(),
                originFingerprint: "fp001", contentHash: MeshRoutedManifestFixtures.contentHash,
                chunkIndex: index, chunkCount: count,
                chunkHash: MeshRoutedManifestFixtures.contentHash,
                expiresAt: MeshRoutedManifestFixtures.expiresAt
            ),
            payloadByteCount: bytes,
            fileName: "\(UUID().uuidString).chunk"
        )
    }

    /// A synthetic held item with `chunks` descriptors and no manifest.
    ///
    /// `expiresAt` defaults to the manifest fixtures' anchor (1.7e9). Any rig running on the P3
    /// acceptance anchor (1.8e9) MUST pass its own: a planted record stamped with the default is
    /// already expired at that rig's `now`, so P5 item 9's expiry sweep frees it before the cell's
    /// refusal can happen and the cell goes green for the wrong reason.
    static func record(
        origin: String = "fp001",
        itemID: UUID = UUID(),
        chunkCount: UInt32 = 1,
        chunks: [MeshRoutedChunkDescriptor] = [],
        expiresAt: Date = MeshRoutedManifestFixtures.expiresAt
    ) -> MeshRoutedItemRecord {
        MeshRoutedItemRecord(
            key: MeshRoutedItemKey(originFingerprint: origin, itemID: itemID),
            contentHash: MeshRoutedManifestFixtures.contentHash,
            chunkCount: chunkCount,
            expiresAt: expiresAt,
            manifest: nil,
            firstSeenAt: MeshRoutedManifestFixtures.base,
            custodiedAt: nil,
            deliveredAt: nil,
            chunks: chunks,
            delivery: nil,
            receipts: [],
            recipientReceipts: []
        )
    }
}

// MARK: - The custody rig

/// One real item, really signed, really staged — the rig the durability and evidence claims run on.
///
/// `origin` authored the item; `custodian` is this device. Nothing here is faked: the manifest and
/// every chunk carry real Ed25519 signatures from distinct provisioned identities, and the store is
/// on its own directory and keychain service.
@MainActor
struct MeshRoutedCustodyRig {
    /// The signed membership rig the roster and the identities come from.
    let rig: MeshDeliveryRig
    /// The item's author.
    let origin: IdentityService
    /// This device — the custodian, and a destination of the item.
    let custodian: IdentityService
    /// The origin-signed manifest.
    let manifest: MeshRoutedManifest
    /// Every origin-signed chunk of the item, in index order.
    let chunks: [MeshChunk]
    /// The store under test.
    let store: MeshRoutedStore
    /// The store's scope.
    let scope: MeshRoutedStorageScope

    /// The item's signed pair.
    var key: MeshRoutedItemKey { MeshRoutedItemKey(manifest) }

    /// The destinations that are not this device.
    var otherDestinations: [String] {
        manifest.destinations.filter { $0 != custodian.localFingerprint }
    }
}

/// Builds ``MeshRoutedCustodyRig``s. Separate from ``MeshRoutedStoreFixtures`` so the pure-value
/// suites need no identities.
@MainActor
enum MeshRoutedCustodyFixtures {

    /// A two-chunk item: one full 256 KiB slice and one short remainder, so index order, per-slot
    /// binding and the remainder rule are all exercised by the default rig.
    nonisolated static let blobByteCount = MeshChunkFormat.maxChunkPayloadBytes + 1_000

    /// A deterministic pseudo-random blob. Non-repeating over 64 KiB, so a mis-sliced boundary
    /// changes the reassembled bytes.
    /// A payload size that fits the registered CAP of `typeToken`, clamping the requested one.
    ///
    /// Needed from P6 item 6 onward: every routed row is now narrowed to a formula over its own
    /// body, and the heart row's body is HEADER-ONLY — 553 B of ciphertext, i.e. 520 B of plaintext
    /// — so an opaque 1–2 KB fixture blob under the heart token is refused
    /// `sizeExceedsTypeCap` at the mint, which is the cap working. A fixture must mint something a
    /// shipping sender could mint.
    ///
    /// It only ever SHRINKS. A cell that means to exceed a cap builds its manifest directly with an
    /// explicit `size:` (`MeshRoutedTypeRegistryTests`' own mints), so a clamp here cannot turn one
    /// of those green.
    ///
    /// - Parameters:
    ///   - typeToken: The row to fit.
    ///   - requested: The size the caller wanted.
    /// - Returns: the plaintext byte count to use.
    static func blobByteCount(for typeToken: String, requested: Int = blobByteCount) -> Int {
        guard let cap = MeshRoutedTypeRegistry.increment1.entry(for: typeToken)?.maxItemByteCount
        else { return requested }
        let plaintextRoom = Int(cap) - MeshRoutedItemSealFormat.overheadByteCount
        return max(1, min(requested, plaintextRoom))
    }

    static func blob(byteCount: Int = blobByteCount) -> Data {
        Data((0..<byteCount).map { UInt8(truncatingIfNeeded: ($0 &* 31 &+ 7) ^ ($0 >> 8)) })
    }

    /// A rig on `scope`, with the item minted but nothing staged yet.
    ///
    /// `typeToken` defaults to item 1's golden-fixture spelling — a token
    /// ``MeshRoutedAckStageTable/increment1`` deliberately does not know, so a rig that does not name
    /// one exercises the `unknownTypeToken` refusal rather than accidentally acquiring a stage.
    static func rig(
        scope: MeshRoutedStorageScope,
        memberCount: Int = 3,
        byteCount: Int = blobByteCount,
        typeToken: String = MeshRoutedManifestFixtures.typeToken
    ) throws -> MeshRoutedCustodyRig {
        _ = PackageTestEnvironment.keychain
        let members = try MeshDeliveryFixtures.rig(memberCount: memberCount)
        let names = members.fingerprints
        let origin = try #require(members.identities[names[0]])
        let custodian = try #require(members.identities[names[1]])
        let payload = blob(byteCount: blobByteCount(for: typeToken, requested: byteCount))
        // The target's SHAPE follows the type's registered column (P6 item 6): a `.singleRecipient`
        // row — the heart's, since item 6 flipped it — is refused by the mint's own shape guard when
        // handed a full-roster target on a roster of three or more, which this rig's default is. The
        // recipient is the CUSTODIAN, because that is the fingerprint every ack cell here commits
        // for. Read from the registry rather than branched on the token, so a fourth type needs no
        // edit here.
        let contentID = UUID()
        let target: MeshDeliveryTarget
        if MeshRoutedTypeRegistry.increment1.entry(for: typeToken)?.destinations == .singleRecipient {
            guard case .updated(let subset) = MeshDeliveryTarget.addressing(
                contentID: contentID, recipient: custodian.localFingerprint,
                roster: members.roster, selfFingerprint: origin.localFingerprint
            ) else {
                #expect(Bool(false), "the custodian must be addressable in the rig's own roster")
                throw MeshRoutedItemSealError.malformed
            }
            target = subset
        } else {
            target = MeshDeliveryTarget(
                contentID: contentID, roster: members.roster,
                selfFingerprint: origin.localFingerprint
            )
        }
        let manifest = try MeshRoutedManifest.signed(
            meshID: members.meshID,
            target: target,
            typeToken: typeToken,
            contentHash: MeshRoutedContentDigest.contentHash(of: payload),
            size: UInt64(payload.count),
            createdAt: MeshRoutedManifestFixtures.createdAt,
            hardDeadline: MeshRoutedManifestFixtures.hardDeadline,
            contentKey: Data(repeating: 0x33, count: 32),
            recipientKeys: members.identities.mapValues(\.localKeyAgreementPublicKey),
            identity: origin
        )
        return MeshRoutedCustodyRig(
            rig: members, origin: origin, custodian: custodian, manifest: manifest,
            chunks: try MeshChunker.chunks(of: payload, for: manifest, identity: origin),
            store: MeshRoutedStore(scope: scope), scope: scope
        )
    }

    /// Admits the manifest and stages every chunk under a pinned install binding.
    static func stageAll(_ rig: MeshRoutedCustodyRig, install: Data = MeshRoutedStoreFixtures.installA) {
        _ = PackageTestEnvironment.keychain
        PackageSwitchableInstallBinding.testOverride.withValue(.identifier(install)) {
            let admitted = rig.store.admittingManifest(rig.manifest, now: MeshRoutedStoreFixtures.now)
            #expect(admitted.value != nil, "manifest admission: \(admitted)")
            for chunk in rig.chunks {
                let staged = rig.store.stagingChunk(chunk, now: MeshRoutedStoreFixtures.now)
                #expect(staged.value != nil, "chunk \(chunk.chunkIndex) staging: \(staged)")
            }
        }
    }

    /// Commits custody under a pinned install binding and returns the outcome.
    static func commit(
        _ rig: MeshRoutedCustodyRig,
        install: Data = MeshRoutedStoreFixtures.installA,
        now: Date = MeshRoutedStoreFixtures.now
    ) -> MeshRoutedOutcome<MeshRoutedCustodyOutcome> {
        _ = PackageTestEnvironment.keychain
        return PackageSwitchableInstallBinding.testOverride.withValue(.identifier(install)) {
            rig.store.committingCustody(
                item: rig.key, custodian: rig.custodian.localFingerprint, now: now
            )
        }
    }

    /// The witness a successful commit produced, or nil.
    static func witness(_ outcome: MeshRoutedOutcome<MeshRoutedCustodyOutcome>) -> MeshCustodyDurabilityWitness? {
        guard case .completed(.committed(let witness)) = outcome else { return nil }
        return witness
    }

    /// Stages everything, commits, and mints the receipt — the whole durable-before-acknowledged
    /// ladder in one call.
    static func receipt(_ rig: MeshRoutedCustodyRig) throws -> MeshCustodyReceipt {
        stageAll(rig)
        let committed = commit(rig)
        let proof = try #require(witness(committed), "commit did not produce a witness: \(committed)")
        return try MeshCustodyReceipt.signed(
            witness: proof, manifest: rig.manifest, identity: rig.custodian
        )
    }

    /// Commits this device's final ack under a pinned install binding and returns the outcome
    /// (P5 item 4). Nothing is staged or committed here — the caller decides how far the ladder has
    /// got, which is the whole point of the per-stage matrix.
    static func commitDelivery(
        _ rig: MeshRoutedCustodyRig,
        stages: MeshRoutedAckStageTable = .increment1,
        evidence: MeshRoutedAckEvidence = .none,
        install: Data = MeshRoutedStoreFixtures.installA,
        now: Date = MeshRoutedStoreFixtures.now
    ) -> MeshRoutedOutcome<MeshRoutedDeliveryCommitOutcome> {
        _ = PackageTestEnvironment.keychain
        return PackageSwitchableInstallBinding.testOverride.withValue(.identifier(install)) {
            rig.store.committingDelivery(
                item: rig.key, recipient: rig.custodian.localFingerprint,
                stages: stages, evidence: evidence, now: now
            )
        }
    }

    /// The witness a successful delivery commit produced, or nil.
    static func deliveryWitness(
        _ outcome: MeshRoutedOutcome<MeshRoutedDeliveryCommitOutcome>
    ) -> MeshRecipientDeliveryWitness? {
        guard case .completed(.acknowledged(let witness)) = outcome else { return nil }
        return witness
    }

    /// Stages everything, commits custody, commits the final ack, mints this device's recipient
    /// receipt **and ingests it** — the whole delivery ladder in one call.
    ///
    /// The last step is not optional: the `delivered` rung is written only by
    /// `recordingRecipientReceipt`, so a helper that stopped at the mint would leave every caller
    /// asserting against a rung that had not moved.
    static func recipientReceipt(
        _ rig: MeshRoutedCustodyRig,
        stages: MeshRoutedAckStageTable = .increment1,
        evidence: MeshRoutedAckEvidence = .none
    ) throws -> MeshRecipientReceipt {
        _ = PackageTestEnvironment.keychain
        stageAll(rig)
        let custody = commit(rig)
        #expect(witness(custody) != nil, "custody commit did not produce a witness: \(custody)")
        let acknowledged = commitDelivery(rig, stages: stages, evidence: evidence)
        let proof = try #require(deliveryWitness(acknowledged),
                                 "delivery commit did not acknowledge: \(acknowledged)")
        let receipt = try MeshRecipientReceipt.signed(
            witness: proof, manifest: rig.manifest, identity: rig.custodian
        )
        let ingested = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(MeshRoutedStoreFixtures.installA)) {
            rig.store.recordingRecipientReceipt(
                item: rig.key, receipt: receipt, now: MeshRoutedStoreFixtures.now
            )
        }
        #expect(ingested.value?.target != nil, "own receipt was not ingested: \(ingested)")
        return receipt
    }

    /// The store's loaded index under a pinned install binding, or nil for the three writer-less
    /// states.
    static func loadedIndex(
        _ store: MeshRoutedStore,
        install: Data = MeshRoutedStoreFixtures.installA
    ) -> MeshRoutedIndex? {
        _ = PackageTestEnvironment.keychain
        let load = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(install)) { store.load() }
        guard case .loaded(let index, _) = load else { return nil }
        return index
    }

    /// The `.chunk` files actually on disk under a scope.
    static func chunkFilesOnDisk(_ scope: MeshRoutedStorageScope) -> [URL] {
        let directory = scope.directory.appendingPathComponent(ProximityNamespace.packageTest.installation.storage.meshRoutedChunkDirectoryName, isDirectory: true)
        let contents = try? FileManager.default.contentsOfDirectory(
            at: directory, includingPropertiesForKeys: nil
        )
        return (contents ?? []).filter { $0.pathExtension == "chunk" }.sorted { $0.path < $1.path }
    }
}

// MARK: - The five states

/// The load classification, state by state, and the writer that only two of them can reach.
@MainActor
@Suite(.serialized)
struct MeshRoutedStoreLoadTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer
    /// has run before a cell's identities or stores reach the keychain.
    let keychain = PackageTestEnvironment.keychain

    private typealias Fixture = MeshRoutedStoreFixtures

    @Test func anEmptyScopeLoadsAsAbsentAndVendsAWriteToken() {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)

        let load = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.load()
        }

        guard case .absent = load else {
            Issue.record("an empty scope loaded as \(load) rather than .absent")
            return
        }
        #expect(Fixture.token(load) != nil, "`absent` is a green field and must vend a write token")
    }

    @Test func aSavedIndexReloadsValueForValue() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        let index = MeshRoutedIndex(items: [Fixture.record(), Fixture.record(origin: "fp002")])
        try Fixture.save(index, into: store)

        let load = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.load()
        }
        guard case .loaded(let reloaded, _) = load else {
            Issue.record("a saved index reloaded as \(load)")
            return
        }
        #expect(reloaded == index)
        #expect(reloaded.itemCount == 2)
    }

    /// A binding read ERROR is retryable by contract, so it defers — and the very next call under a
    /// good binding loads, with nothing written in between.
    @Test func aTransientBindingReadErrorDefersAndSelfHeals() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        let index = MeshRoutedIndex(items: [Fixture.record()])
        try Fixture.save(index, into: store)
        let before = Fixture.snapshot(scope)

        let deferred = PackageSwitchableInstallBinding.testOverride.withValue(.readError) { store.load() }
        guard case .deferred(let deferral) = deferred else {
            Issue.record("a binding read error loaded as \(deferred)")
            return
        }
        #expect(deferral.reason == .installBindingReadError)
        #expect(Fixture.token(deferred) == nil)
        #expect(Fixture.snapshot(scope) == before, "a deferral wrote to the store")

        let healed = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) { store.load() }
        guard case .loaded(let reloaded, _) = healed else {
            Issue.record("the retry after a deferral loaded as \(healed)")
            return
        }
        #expect(reloaded == index)
    }

    @Test func truncatedCiphertextIsCorruptNotAbsent() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        try Fixture.save(MeshRoutedIndex(items: [Fixture.record()]), into: store)
        let sealed = try Data(contentsOf: store.indexURL)
        try Fixture.writeRaw(sealed.prefix(sealed.count - 4), into: store)

        let load = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) { store.load() }
        guard case .corrupt(let corruption) = load else {
            Issue.record("truncated ciphertext loaded as \(load)")
            return
        }
        #expect(corruption.detail == .authenticationFailed)
        #expect(FileManager.default.fileExists(atPath: store.indexURL.path), "corruption must not delete")
    }

    /// The fifth state, over a NON-EMPTY file: an authoritatively absent binding refuses, and a
    /// refusal is never "there is nothing here".
    @Test func anAbsentInstallBindingRefusesRatherThanReportingAbsent() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        try Fixture.save(MeshRoutedIndex(items: [Fixture.record()]), into: store)

        let load = PackageSwitchableInstallBinding.testOverride.withValue(.unavailable) { store.load() }
        guard case .refused(let refusal) = load else {
            Issue.record("an absent install binding loaded as \(load)")
            return
        }
        #expect(refusal.operation == .open)
        #expect(refusal.cause == .installBindingUnavailable)
        #expect(refusal.summary.contains("routed"))
    }

    @Test func noWriterIsReachableFromRefusedDeferredOrCorrupt() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        try Fixture.save(MeshRoutedIndex(items: [Fixture.record()]), into: store)
        let before = Fixture.snapshot(scope)

        let refused = PackageSwitchableInstallBinding.testOverride.withValue(.unavailable) { store.load() }
        let deferred = PackageSwitchableInstallBinding.testOverride.withValue(.readError) { store.load() }
        try Fixture.writeRaw(Data([0x03, 0x00, 0x01]), into: store)
        let corrupt = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) { store.load() }

        for load in [refused, deferred, corrupt] {
            #expect(Fixture.token(load) == nil, "\(load) vended a write token")
        }
        #expect(Fixture.snapshot(scope).keys.sorted() == before.keys.sorted())
    }

    @Test func aRefusedSealOverAnExistingIndexChangesNothing() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        let index = MeshRoutedIndex(items: [Fixture.record()])
        try Fixture.save(index, into: store)
        let before = Fixture.snapshot(scope)

        let outcome = PackageSwitchableInstallBinding.testOverride.withValue(.unavailable) {
            store.stagingChunk(
                MeshChunkFixtures.chunk(index: 0, count: 1, payload: Data([0x01])),
                now: Fixture.now
            )
        }
        #expect(outcome.unavailability?.logToken == "refused:installBindingUnavailable")
        #expect(Fixture.snapshot(scope) == before, "a refused seal changed bytes on disk")

        let reloaded = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) { store.load() }
        guard case .loaded(let value, _) = reloaded else {
            Issue.record("reload after a refusal answered \(reloaded)")
            return
        }
        #expect(value == index)
    }

    @Test func aTokenMintedByAnotherStoreCannotAuthoriseAWrite() throws {
        let mine = Fixture.scope()
        let theirs = Fixture.scope()
        defer { Fixture.tearDown(mine); Fixture.tearDown(theirs) }
        let myStore = MeshRoutedStore(scope: mine)
        let theirStore = MeshRoutedStore(scope: theirs)

        try PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            let foreign = try #require(Fixture.token(theirStore.load()))
            #expect(throws: MeshRoutedSaveError.tokenFromAnotherStore) {
                try myStore.save(MeshRoutedIndex(items: [Fixture.record()]), token: foreign)
            }
        }
        #expect(FileManager.default.fileExists(atPath: myStore.indexURL.path) == false)
    }

    @Test func quarantineIsTheOnlyRouteFromCorruptToAWriter() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        // Establish the seal key first: with no key row a present file answers `refused`, not
        // `corrupt` — custody is classified before content, which is its own rule and not this test's.
        try Fixture.save(MeshRoutedIndex(), into: store)
        let garbage = Data([0x03, 0xDE, 0xAD, 0xBE, 0xEF])
        try Fixture.writeRaw(garbage, into: store)

        let load = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) { store.load() }
        guard case .corrupt(let corruption) = load else {
            Issue.record("garbage loaded as \(load)")
            return
        }
        #expect(Fixture.token(load) == nil)

        let token = try store.quarantineCorruptIndex(corruption)
        #expect(try Data(contentsOf: store.quarantineURL) == garbage, "the corrupt bytes must be preserved")
        #expect(FileManager.default.fileExists(atPath: store.indexURL.path) == false)
        try PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            try store.save(MeshRoutedIndex(), token: token)
        }
    }

    @Test func aSchemaZeroIndexIsCorruptAndNamesTheVersion() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        try Fixture.plant(WrongSchemaIndexWire(schemaVersion: 0), into: store)

        let load = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) { store.load() }
        guard case .corrupt(let corruption) = load else {
            Issue.record("a schema-0 index loaded as \(load)")
            return
        }
        #expect(corruption.detail == .unsupportedSchemaVersion(0))
    }

    @Test func aSchemaThreeIndexIsCorruptToo() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        try Fixture.plant(WrongSchemaIndexWire(schemaVersion: 3), into: store)

        let load = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) { store.load() }
        #expect(load == .corrupt(MeshRoutedCorruption(detail: .unsupportedSchemaVersion(3))))
    }

    /// The 1 → 2 migration statement itself (P5 item 4): an item-3 file is refused **as a whole**,
    /// never partially reinterpreted into a record whose two new durable fields the next save would
    /// silently drop.
    @Test func aSchemaOneIndexIsCorruptAfterTheBump() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        try Fixture.plant(WrongSchemaIndexWire(schemaVersion: 1), into: store)

        let load = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) { store.load() }
        #expect(load == .corrupt(MeshRoutedCorruption(detail: .unsupportedSchemaVersion(1))))
    }

    /// An at-rest cap violation is CORRUPTION with the cap named, never a clamp: clamping would
    /// silently drop a durable record whose payload files stay on disk as orphans.
    @Test func anAtRestIndexOverACapIsCorruptNotClamped() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        let overCap = (0...MeshRoutedStoreFormat.maxItems).map { _ in Fixture.record() }
        try Fixture.plant(MeshRoutedIndex(items: overCap), into: store)

        let load = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) { store.load() }
        #expect(load == .corrupt(MeshRoutedCorruption(detail: .undecodableJSON("capacityExceeded:items"))))
        #expect(FileManager.default.fileExists(atPath: store.indexURL.path), "an over-cap file must survive")

        let perItem = Fixture.record(
            chunkCount: 1,
            chunks: (0...MeshRoutedStoreFormat.maxChunksPerItem).map {
                Fixture.descriptor(index: UInt32($0), count: 1, bytes: 1)
            }
        )
        try Fixture.plant(MeshRoutedIndex(items: [perItem]), into: store)
        let second = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) { store.load() }
        #expect(second == .corrupt(MeshRoutedCorruption(detail: .undecodableJSON("capacityExceeded:chunksPerItem"))))
    }

    /// An index sealed under another install authenticates for nobody here — and that is corruption
    /// of the bytes, not a custody refusal.
    @Test func anIndexSealedUnderAnotherInstallIsCorrupt() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        try Fixture.save(MeshRoutedIndex(items: [Fixture.record()]), into: store, install: Fixture.installB)

        let load = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) { store.load() }
        #expect(load == .corrupt(MeshRoutedCorruption(detail: .authenticationFailed)))
    }
}

/// An index whose only wrong field is its schema version — the one shape a real writer can never
/// produce, and the one a build that does not own the file must refuse whole.
private struct WrongSchemaIndexWire: Encodable {
    /// The version to stamp.
    let schemaVersion: Int
    /// An empty item list, so the refusal is unambiguously about the version.
    let items: [MeshRoutedItemRecord] = []
}

// MARK: - Vocabulary parity and the derived hash

/// The routed store's error vocabulary against P3's, and the streaming digest against the one-shot.
@MainActor
@Suite(.serialized)
struct MeshRoutedVocabularyTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer
    /// has run before a cell's identities or stores reach the keychain.
    let keychain = PackageTestEnvironment.keychain

    /// One vocabulary, two types: `MeshSessionSealRefusal.summary` hard-codes "mesh session
    /// context", so the routed store needs its own type — and a same-named case set that drifted
    /// would be two vocabularies wearing one name.
    @Test func theRoutedVocabularyMatchesTheSessionStoresExactly() {
        #expect(
            Set(MeshRoutedSealRefusal.Cause.allCases.map(\.rawValue))
                == Set(MeshSessionSealRefusal.Cause.allCases.map(\.rawValue))
        )
        #expect(
            Set(MeshRoutedSealRefusal.Operation.allCases.map(\.rawValue))
                == Set(MeshSessionSealRefusal.Operation.allCases.map(\.rawValue))
        )
        #expect(
            Set(MeshRoutedDeferral.Reason.allCases.map(\.rawValue))
                == Set(MeshSessionDeferral.Reason.allCases.map(\.rawValue))
        )
    }

    /// The corruption details have associated values and no raw type, so there is no `allCases` set
    /// to compare, the way ``theRoutedVocabularyMatchesTheSessionStoresExactly`` compares one.
    ///
    /// The case-set half is therefore **compile-enforced, not list-enforced**: `name(_:)` and its
    /// session twin below are exhaustive `switch`es with no `default`, so a fifth case on either
    /// side fails to build THIS file. (A hand-written list of four on each side could not: two
    /// identical literal arrays stay equal no matter what the enums grow.) The
    /// `String(describing:)` comparison stays beside it because it is the half that catches an
    /// associated-value LABEL drift, which an exhaustive switch does not see.
    ///
    /// - Note: enum growth needs a clean build to be seen across module boundaries; that hazard is
    ///   the codebase's, not this test's.
    @Test func theCorruptionDetailsAreTheSameFourCases() {
        let routed: [MeshRoutedCorruption.Detail] = [
            .emptyFile, .undecodableJSON("x"), .unsupportedSchemaVersion(3), .authenticationFailed
        ]
        let session: [MeshSessionCorruption.Detail] = [
            .emptyFile, .undecodableJSON("x"), .unsupportedSchemaVersion(3), .authenticationFailed
        ]
        #expect(routed.map { Self.name($0) } == session.map { Self.name($0) })
        #expect(routed.map { String(describing: $0) } == session.map { String(describing: $0) })
    }

    /// The routed detail's case name, as an exhaustive `switch` with **no `default`** — adding a
    /// case to `MeshRoutedCorruption.Detail` fails to compile here.
    private static func name(_ detail: MeshRoutedCorruption.Detail) -> String {
        switch detail {
        case .emptyFile: return "emptyFile"
        case .undecodableJSON: return "undecodableJSON"
        case .unsupportedSchemaVersion: return "unsupportedSchemaVersion"
        case .authenticationFailed: return "authenticationFailed"
        }
    }

    /// The session twin, same shape and same reason: a fifth case on P3's side has to break P5's
    /// parity claim at build time, not slip past two matching literal lists.
    private static func name(_ detail: MeshSessionCorruption.Detail) -> String {
        switch detail {
        case .emptyFile: return "emptyFile"
        case .undecodableJSON: return "undecodableJSON"
        case .unsupportedSchemaVersion: return "unsupportedSchemaVersion"
        case .authenticationFailed: return "authenticationFailed"
        }
    }

    /// One contract behind two same-named accessors: a refusal is retried, because the dominant
    /// cause at this seam is the pre-first-unlock window that self-heals on unlock.
    @Test func theRetryabilityAnswerMatchesP3sForTheSameState() {
        let refusal = MeshRoutedSealRefusal(operation: .seal, cause: .installBindingUnavailable)
        let sessionRefusal = MeshSessionSealRefusal(operation: .seal, cause: .installBindingUnavailable)
        #expect(
            MeshRoutedUnavailability.refused(refusal).isRetryable
                == MeshSessionRestoreOutcome.retryAfterRefusal(sessionRefusal).isRetryable
        )
        let deferral = MeshRoutedDeferral(reason: .fileUnreadable, detail: "x")
        let sessionDeferral = MeshSessionDeferral(reason: .fileUnreadable, detail: "x")
        #expect(
            MeshRoutedUnavailability.deferred(deferral).isRetryable
                == MeshSessionRestoreOutcome.retryAfterUnlock(sessionDeferral).isRetryable
        )
        let corruption = MeshRoutedCorruption(detail: .emptyFile)
        #expect(
            MeshRoutedUnavailability.corrupt(corruption).isRetryable
                == MeshSessionRestoreOutcome.quarantineCorruptFile(
                    MeshSessionCorruption(detail: .emptyFile)
                ).isRetryable
        )
        #expect(MeshRoutedRetryBounds.maxAttempts == MeshSessionRestoreBounds.maxAttempts)
    }

    @Test func everyUnavailabilityNamesItselfInItsLogToken() {
        #expect(
            MeshRoutedUnavailability.deferred(
                MeshRoutedDeferral(reason: .fileUnreadable, detail: "x")
            ).logToken == "deferred:fileUnreadable"
        )
        #expect(
            MeshRoutedUnavailability.refused(
                MeshRoutedSealRefusal(operation: .open, cause: .installBindingUnavailable)
            ).logToken == "refused:installBindingUnavailable"
        )
        #expect(MeshRoutedUnavailability.notWritten("x").logToken == "notWritten")
    }

    /// One domain, two shapes. A second domain for the streamed form would mean a custodian's
    /// whole-item check and the origin's manifest field measured different things.
    @Test func theStreamingContentHasherAgreesWithTheOneShotDigest() {
        let blob = MeshRoutedCustodyFixtures.blob(byteCount: 5_000)
        for split in [0, 1, 999, 2_500, 4_999, 5_000] {
            var hasher = MeshRoutedContentHasher()
            hasher.update(blob.prefix(split))
            hasher.update(blob.dropFirst(split))
            #expect(hasher.finalized() == MeshRoutedContentDigest.contentHash(of: blob), "split \(split)")
        }
        var single = MeshRoutedContentHasher()
        single.update(blob)
        #expect(single.finalized() == MeshRoutedContentDigest.contentHash(of: blob))
    }

    /// The two caps that happen to be equal, and the one constant that is deliberately reused.
    @Test func theCapsReuseTheConstantsTheyAreDerivedFrom() {
        #expect(MeshRoutedStoreFormat.maxContentBytes == MeshRoutedManifestFormat.maxContentByteCount)
        #expect(MeshRoutedStoreFormat.maxChunksPerItem == MeshChunkFormat.maxChunkCount)
        #expect(MeshRoutedStoreFormat.maxReceiptsPerItem == MeshMembershipBounds.maxRosterMembers)
        #expect(MeshRoutedStoreFormat.maxItems == 1024)
        #expect(MeshRoutedStoreFormat.maxHeldChunkFiles == 4096)
        #expect(MeshRoutedIndexSchema.current == 2, "P5 item 4 bumped the routed index schema")
        #expect(
            MeshSessionContextSchema.current == 3,
            """
            P6 item 1 moved the session schema (the key advertisements). The routed sidecar still must
            not move it: this pin is here so a routed-index bump cannot ride along on one.
            """
        )
    }
}

// MARK: - Durable before acknowledged

/// The claim the whole item exists to make, and the repairs that keep it honest.
@MainActor
@Suite(.serialized)
struct MeshRoutedStoreDurabilityTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer
    /// has run before a cell's identities or stores reach the keychain.
    let keychain = PackageTestEnvironment.keychain

    private typealias Fixture = MeshRoutedStoreFixtures

    @Test func noReceiptExistsForAnythingARestartWouldLose() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        let receipt = try MeshRoutedCustodyFixtures.receipt(rig)

        // A NEW store instance on the same scope — everything the receipt claims survived the
        // process that made it.
        let reopened = MeshRoutedStore(scope: scope)
        let recommitted = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            reopened.committingCustody(
                item: rig.key, custodian: rig.custodian.localFingerprint, now: Fixture.now
            )
        }
        let second = try #require(MeshRoutedCustodyFixtures.witness(recommitted))
        #expect(second.custodiedAt == receipt.custodiedAt, "a re-commit must re-use the stored instant")

        let remint = try MeshCustodyReceipt.signed(
            witness: second, manifest: rig.manifest, identity: rig.custodian
        )
        #expect(canonicalBytes(for: remint) == canonicalBytes(for: receipt))
        #expect(remint.receiptID == receipt.receiptID)

        let verifier = MeshCustodyReceiptVerifier(
            meshID: rig.rig.meshID, hardDeadline: MeshRoutedManifestFixtures.hardDeadline,
            ledger: rig.rig.ledger, manifest: rig.manifest
        )
        #expect(verifier.verify(receipt) == nil)
        #expect(verifier.verify(remint) == nil)
    }

    @Test func aCommitWhoseIndexWriteFailsMintsNoWitness() throws {
        let scope = Fixture.scope()
        defer {
            try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: scope.directory.path)
            Fixture.tearDown(scope)
        }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        MeshRoutedCustodyFixtures.stageAll(rig)
        let before = try Data(contentsOf: rig.store.indexURL)

        // Make the directory unwritable so the atomic rename cannot land.
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o500], ofItemAtPath: scope.directory.path
        )
        let outcome = MeshRoutedCustodyFixtures.commit(rig)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755], ofItemAtPath: scope.directory.path
        )

        #expect(MeshRoutedCustodyFixtures.witness(outcome) == nil, "a failed index write minted a witness")
        guard case .unavailable(let cause) = outcome else {
            Issue.record("an unwritable index answered \(outcome)")
            return
        }
        #expect(cause.logToken == "notWritten")
        // …and the answer is CLASSIFIED from the thrown error rather than hard-coded at the call
        // site: a hard-coded one would name the index file. The seal-refusal shape cannot be planted
        // at this seam — `load()` and `openKey()` both consult custody before the stamp is reached,
        // so within one call a refused seal is unreachable — which is exactly why the collapse was
        // invisible; `theStampsFailureIsClassifiedByTheStoresOwnMapper` covers the mapping itself.
        guard case .notWritten(let detail) = cause else {
            Issue.record("an unwritable directory answered \(cause.logToken)")
            return
        }
        #expect(detail != rig.store.indexFileName, "the failure must name the write error, not the file")
        #expect(detail.isEmpty == false)
        #expect(try Data(contentsOf: rig.store.indexURL) == before, "the previous index must be byte-identical")
    }

    /// The commit's `custodiedAt` stamp was the one writer in the store that flattened every failed
    /// index write to a bare `notWritten`, erasing the §19.5 distinction the item exists to keep:
    /// "seal refused" is not "absent", and it is not "try again silently" either.
    ///
    /// It now routes through the same `unavailability(from:)` every other writer uses
    /// (`admittingManifest`, `stagedOutcome`, `repairing`, `sweepingExpired`, `dropping`), so the
    /// three shapes stay distinguishable at the seam even though only the write-failure shape is
    /// reachable through the public door today.
    @Test func theStampsFailureIsClassifiedByTheStoresOwnMapper() {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)

        #expect(
            store.unavailability(
                from: MeshRoutedSealRefusal(operation: .seal, cause: .installBindingUnavailable)
            ) == .refused(MeshRoutedSealRefusal(operation: .seal, cause: .installBindingUnavailable))
        )
        #expect(
            store.unavailability(
                from: MeshRoutedSaveError.deferred(
                    MeshRoutedDeferral(reason: .sealKeyTransientlyUnreadable, detail: "x")
                )
            ).logToken == "deferred:sealKeyTransientlyUnreadable"
        )
        #expect(
            store.unavailability(from: MeshRoutedSaveError.notWritten("disk"))
                == .notWritten("disk")
        )
        #expect(
            store.unavailability(from: MeshRoutedSaveError.tokenFromAnotherStore)
                == .notWritten("tokenFromAnotherStore")
        )
    }

    /// The fifth wrinkle, end to end: with the binding unavailable every custody verb refuses, the
    /// refusal is distinguishable from a deferral AND from an absence, and nothing is acknowledged.
    @Test func aRefusedSealYieldsNoReceiptAndIsNotAbsent() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        MeshRoutedCustodyFixtures.stageAll(rig)
        let before = Fixture.snapshot(scope)

        let refused = PackageSwitchableInstallBinding.testOverride.withValue(.unavailable) {
            (
                admit: rig.store.admittingManifest(rig.manifest, now: Fixture.now),
                commit: rig.store.committingCustody(
                    item: rig.key, custodian: rig.custodian.localFingerprint, now: Fixture.now
                ),
                load: rig.store.load()
            )
        }
        #expect(refused.admit.unavailability?.logToken == "refused:installBindingUnavailable")
        #expect(refused.commit.unavailability?.logToken == "refused:installBindingUnavailable")
        #expect(MeshRoutedCustodyFixtures.witness(refused.commit) == nil)

        // Distinguishable from `deferred` and from `absent`, in three separate assertions.
        guard case .refused = refused.load else {
            Issue.record("a refusal presented as \(refused.load)")
            return
        }
        let deferred = PackageSwitchableInstallBinding.testOverride.withValue(.readError) { rig.store.load() }
        guard case .deferred = deferred else {
            Issue.record("a read error presented as \(deferred)")
            return
        }
        let empty = MeshRoutedStore(scope: Fixture.scope())
        defer { Fixture.tearDown(empty.scope) }
        let emptyLoad = PackageSwitchableInstallBinding.testOverride.withValue(.unavailable) { empty.load() }
        guard case .absent = emptyLoad else {
            Issue.record("a missing file consulted custody instead of answering absent")
            return
        }
        #expect(Fixture.snapshot(scope) == before, "a refused custody attempt wrote to the store")
    }

    @Test func aRefusalAtTheFirstUnlockSeamIsRetryableAndSucceedsOnTheNextCall() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        let before = Fixture.snapshot(scope)

        let refused = PackageSwitchableInstallBinding.testOverride.withValue(.unavailable) {
            rig.store.admittingManifest(rig.manifest, now: Fixture.now)
        }
        let cause = try #require(refused.unavailability)
        // A green field answers `absent` WITHOUT consulting custody (the first ordering rule), so the
        // refusal arrives at the SEAL rather than at the open — which is exactly the pre-first-unlock
        // shape: the store has nothing to read and still may not write.
        #expect(cause == .refused(MeshRoutedSealRefusal(operation: .seal, cause: .installBindingUnavailable)))
        #expect(cause.isRetryable, "the pre-first-unlock refusal is the one that MUST be retried")
        #expect(Fixture.snapshot(scope) == before, "the refused attempt wrote something")

        let healed = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            rig.store.admittingManifest(rig.manifest, now: Fixture.now)
        }
        #expect(healed.value?.isNew == true)
    }

    @Test func aStagedButUncommittedChunkFileIsSweptAndACommittedOneIsNot() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        MeshRoutedCustodyFixtures.stageAll(rig)
        #expect(MeshRoutedCustodyFixtures.chunkFilesOnDisk(scope).count == rig.chunks.count)

        // A crash between the file write and the index write leaves exactly one orphan.
        let orphan = scope.directory
            .appendingPathComponent(ProximityNamespace.packageTest.installation.storage.meshRoutedChunkDirectoryName, isDirectory: true)
            .appendingPathComponent("\(UUID().uuidString).chunk", isDirectory: false)
        try Data([0x03, 0x01]).write(to: orphan)
        #expect(MeshRoutedCustodyFixtures.chunkFilesOnDisk(scope).count == rig.chunks.count + 1)

        let swept = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            rig.store.sweepingOrphanChunkFiles()
        }
        let report = try #require(swept.value)
        #expect(report.chunkFilesRemoved == 1)
        #expect(report.chunkFilesFailed == 0)
        #expect(report.sweptToCeiling == false)
        #expect(MeshRoutedCustodyFixtures.chunkFilesOnDisk(scope).count == rig.chunks.count)

        // And the committed ones are still there, so the item still commits.
        #expect(MeshRoutedCustodyFixtures.witness(MeshRoutedCustodyFixtures.commit(rig)) != nil)
    }

    @Test func aQuarantineIsFollowedByAnOrphanSweepThatEmptiesTheDirectory() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        MeshRoutedCustodyFixtures.stageAll(rig)
        let sealed = try Data(contentsOf: rig.store.indexURL)
        try Fixture.writeRaw(sealed.prefix(sealed.count - 4), into: rig.store)

        let load = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) { rig.store.load() }
        guard case .corrupt(let corruption) = load else {
            Issue.record("the truncated index loaded as \(load)")
            return
        }
        _ = try rig.store.quarantineCorruptIndex(corruption)
        let swept = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            rig.store.sweepingOrphanChunkFiles()
        }
        #expect(swept.value?.chunkFilesRemoved == rig.chunks.count)
        #expect(MeshRoutedCustodyFixtures.chunkFilesOnDisk(scope).isEmpty)
        #expect(try Data(contentsOf: rig.store.quarantineURL).count == sealed.count - 4)
    }

    /// Idempotent means "does not refuse", never "skips the check": an item whose file went away
    /// since the first commit hands out no witness, and its durable custody claim is cleared.
    @Test func aRecommitAfterALostChunkFileMintsNoWitnessAndClearsCustodiedAt() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        _ = try MeshRoutedCustodyFixtures.receipt(rig)

        let files = MeshRoutedCustodyFixtures.chunkFilesOnDisk(scope)
        try FileManager.default.removeItem(at: try #require(files.first))

        let recommitted = MeshRoutedCustodyFixtures.commit(rig)
        #expect(MeshRoutedCustodyFixtures.witness(recommitted) == nil)
        guard case .completed(.incomplete(let received, let expected)) = recommitted else {
            Issue.record("a lost chunk file answered \(recommitted)")
            return
        }
        #expect(received == rig.chunks.count - 1)
        #expect(expected == rig.chunks.count)

        let load = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) { rig.store.load() }
        guard case .loaded(let index, _) = load else {
            Issue.record("reload after a repair answered \(load)")
            return
        }
        let record = try #require(index.record(for: rig.key))
        #expect(record.custodiedAt == nil, "a repair must clear the durable custody claim")
        #expect(record.isCustodied == false)
    }

    /// The seal's AAD is purpose ‖ install only, so two swapped payload files both authenticate. The
    /// descriptor comparison is what catches it — on the forward path, where the whole-item content
    /// hash never runs.
    @Test func aChunkFileInTheWrongSlotIsCaughtOnEveryRead() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        MeshRoutedCustodyFixtures.stageAll(rig)
        #expect(rig.chunks.count >= 2, "the swap case needs at least two slots")

        let files = MeshRoutedCustodyFixtures.chunkFilesOnDisk(scope)
        let first = try #require(files.first)
        let second = try #require(files.dropFirst().first)
        let firstBytes = try Data(contentsOf: first)
        try Data(contentsOf: second).write(to: first, options: .atomic)
        try firstBytes.write(to: second, options: .atomic)

        let forwarded = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            rig.store.forwardableChunk(item: rig.key, index: 0)
        }
        #expect(forwarded.refusal == .chunkFileMismatch || forwarded.value == nil,
                "a swapped file must never be emitted: \(forwarded)")

        let committed = MeshRoutedCustodyFixtures.commit(rig)
        #expect(MeshRoutedCustodyFixtures.witness(committed) == nil,
                "a swapped file must not commit: \(committed)")
    }

    /// A directory that got OVER the cap is exactly what orphans produce, so the sweep's bound is
    /// twice the cap and it reports when it stopped at it.
    @Test func anOverCapDirectoryDrainsAcrossBoundedSweeps() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        try Fixture.save(MeshRoutedIndex(), into: store)
        let directory = store.chunkDirectory
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let planted = 2 * MeshRoutedStoreFormat.maxHeldChunkFiles + 3
        for _ in 0..<planted {
            try Data([0x03]).write(
                to: directory.appendingPathComponent("\(UUID().uuidString).chunk", isDirectory: false)
            )
        }

        let first = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.sweepingOrphanChunkFiles()
        }
        let firstReport = try #require(first.value)
        #expect(firstReport.sweptToCeiling)
        #expect(firstReport.chunkFilesRemoved == 2 * MeshRoutedStoreFormat.maxHeldChunkFiles)

        let second = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.sweepingOrphanChunkFiles()
        }
        let secondReport = try #require(second.value)
        #expect(secondReport.sweptToCeiling == false)
        #expect(secondReport.chunkFilesRemoved == 3)
        #expect(MeshRoutedCustodyFixtures.chunkFilesOnDisk(scope).isEmpty)
    }

    @Test func wipeForDeleteAllRemovesTheIndexTheQuarantineEveryChunkFileAndTheKey() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        MeshRoutedCustodyFixtures.stageAll(rig)
        try Data([0x03, 0x02]).write(to: rig.store.quarantineURL)
        #expect(FileManager.default.fileExists(atPath: rig.store.indexURL.path))
        #expect(MeshRoutedCustodyFixtures.chunkFilesOnDisk(scope).isEmpty == false)

        #expect(MeshRoutedStore.wipeForDeleteAll(scope: scope))

        #expect(FileManager.default.fileExists(atPath: rig.store.indexURL.path) == false)
        #expect(FileManager.default.fileExists(atPath: rig.store.quarantineURL.path) == false)
        #expect(FileManager.default.fileExists(atPath: rig.store.chunkDirectory.path) == false)
        #expect(MeshRoutedCustodyFixtures.chunkFilesOnDisk(scope).isEmpty)
        // The store is a green field again, not a refusal: nothing is left for a reader to trip on.
        let load = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            MeshRoutedStore(scope: scope).load()
        }
        guard case .absent = load else {
            Issue.record("a wiped scope loaded as \(load)")
            return
        }
    }

    /// A wipe of a scope that never existed is success — the funnel asks for the end state, not for
    /// work to have been done.
    @Test func wipingAnEmptyScopeIsSuccess() {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        #expect(MeshRoutedStore.wipeForDeleteAll(scope: scope))
    }

    /// The key half of the wipe, asserted on its own: after a wipe the seal key row is gone, so a
    /// surviving file would be unopenable rather than readable.
    @Test func theWipeTakesTheSealKeyWithTheFiles() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        try Fixture.save(MeshRoutedIndex(items: [Fixture.record()]), into: store)
        guard case .available = MeshRoutedSealKey.forOpen(service: scope.keychainService) else {
            Issue.record("a saved index left no seal key")
            return
        }
        #expect(MeshRoutedStore.wipeForDeleteAll(scope: scope))
        guard case .refused(let cause) = MeshRoutedSealKey.forOpen(service: scope.keychainService) else {
            Issue.record("the seal key survived the wipe")
            return
        }
        #expect(cause == .sealKeyMissingForSealedFile)
    }
}
