// MeshRoutedCustodyTests.swift
// ProximityKitTests
//
// P5 item 3 (plan §11, C13): the custody verbs — the chunk-set decisions the durable store shares
// with the in-memory reassembler, the delivery map it persists, and the evidence behind every
// `custodied` rung.
//
// Three claims are walled here:
//
// 1. **One decision, two forms (C13).** `MeshChunkAssembly` and `MeshRoutedStore` reach the same
//    verdict for the same inputs on BOTH doors — per-chunk admission and manifest binding — because
//    they call the same pure function. The differential drives identical event sequences through
//    both and compares value for value; item 2's own `MeshChunkAssemblyTests` pass unmodified beside
//    it, which is what makes the extraction a refactor rather than a rewrite.
// 2. **The delivery map round-trips through the ORIGIN'S SIGNED MANIFEST.** The destination set is
//    never stored, `departed` is never encoded and is refused on decode, and a restored target still
//    refuses a regression and a set mismatch.
// 3. **Every `custodied` rung is backed by stored evidence**, written in the same index write as the
//    rung it evidences — and the recorded custodian is the receipt's SIGNER, because there is no
//    other parameter that could disagree with it.
//
// Nothing here sleeps, and every instant is injected.
//
// Since ProximityKit plan step A1's third batch of copied suites (those that reach the keychain and open
// a store), this holds the whole of the Fernlet repository's FernletTests file of the same name as it
// stood before that repository's plan step A1.3: `MeshRoutedCustodyParityTests`,
// `MeshRoutedDeliveryPersistenceTests` and `MeshRoutedCustodyEvidenceTests` with all seventeen cells, one
// of which, `theRoutedStoreNamesNoDecryptionSeam`, reads ProximityKit's sources and came here first, at
// plan step A1.3's batch D, with their names and tests unchanged.

import CryptoKit
import Foundation
import Testing
@testable import ProximityKit

// MARK: - C13 parity

/// The durable form and the in-memory form agree on every verdict, on both doors.
@MainActor
@Suite(.serialized)
struct MeshRoutedCustodyParityTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer
    /// has run before a cell's identities or stores reach the keychain.
    let keychain = PackageTestEnvironment.keychain

    private typealias Fixture = MeshRoutedStoreFixtures

    /// A two-chunk item's chunks, hand-built (the store verifies no signature — that is
    /// `MeshChunkVerifier`'s precondition), so the differential needs no identities.
    private func pair() -> (first: MeshChunk, second: MeshChunk) {
        let head = MeshChunkFixtures.blob(byteCount: MeshChunkFormat.maxChunkPayloadBytes)
        let tail = MeshChunkFixtures.blob(byteCount: 1_000)
        // The REAL item digest over the bytes these two reassemble, so the completion door is a live
        // check rather than one the fixture could never satisfy.
        let contentHash = MeshRoutedContentDigest.contentHash(of: head + tail)
        return (
            MeshChunkFixtures.chunk(index: 0, count: 2, payload: head, contentHash: contentHash),
            MeshChunkFixtures.chunk(index: 1, count: 2, payload: tail, contentHash: contentHash)
        )
    }

    /// The store's verdict for one chunk, under a pinned install binding.
    private func staged(_ chunk: MeshChunk, in store: MeshRoutedStore) -> MeshChunkAdmission? {
        PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.stagingChunk(chunk, now: Fixture.now).value
        }
    }

    /// Forward, reverse, duplicate, conflict and out-of-range — every verdict, both forms.
    @Test func theDurableFormAndTheAssemblyAgreeOnEveryPerChunkVerdict() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        let (first, second) = pair()
        var assembly = try #require(MeshChunkAssembly.forChunk(first))

        let events: [MeshChunk] = [
            second,                                   // out of order: parked sets are order-free
            first,
            second,                                   // a retransmission is a duplicate no-op
            MeshChunkFixtures.chunk(
                index: 1, count: 2, payload: MeshChunkFixtures.blob(byteCount: 999),
                contentHash: first.contentHash
            ),
            MeshChunkFixtures.chunk(
                index: 2, count: 2, payload: Data([0x01]), contentHash: first.contentHash
            ),
            MeshChunkFixtures.chunk(
                index: 0, count: 3, payload: Data([0x01]), contentHash: first.contentHash
            ),
            // The identity triple's third leg. A chunk under a DIFFERENT itemID is not a foreign
            // chunk to the store at all — it is a new item, which is the one place the two forms
            // legitimately differ, so the parity case is the shared key with a different content
            // hash.
            MeshChunkFixtures.chunk(
                index: 0, count: 2, payload: Data([0x01]),
                contentHash: Data(repeating: 0x09, count: 32)
            )
        ]
        for chunk in events {
            let memory = assembly.admit(chunk)
            let durable = staged(chunk, in: store)
            #expect(durable == memory, "index \(chunk.chunkIndex): durable \(String(describing: durable)) vs memory \(memory)")
        }
        #expect(assembly.receivedCount == 2)
    }

    /// A chunk whose payload does NOT hash to its own declared `chunkHash`, arriving at an occupied
    /// index with an identical transcript, conflicts in both forms — the substitution's pathological
    /// input, and the reason the duplicate check reads `payloadHash == held.chunkHash`.
    @Test func aChunkWhosePayloadDoesNotHashToItsOwnChunkHashConflicts() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        let (first, _) = pair()
        var assembly = try #require(MeshChunkAssembly.forChunk(first))
        #expect(assembly.admit(first) == .admitted(received: 1, expected: 2))
        #expect(staged(first, in: store) == .admitted(received: 1, expected: 2))

        // Identical transcript (same declared chunkHash), different payload — so the payload no
        // longer hashes to the hash the transcript carries.
        let liar = first.replacing(
            payload: Data(MeshChunkFixtures.blob(byteCount: MeshChunkFormat.maxChunkPayloadBytes).reversed())
        )
        #expect(canonicalBytes(for: liar) == canonicalBytes(for: first))
        #expect(liar.payload != first.payload)
        #expect(assembly.admit(liar) == .refused(.conflictingChunk))
        #expect(staged(liar, in: store) == .refused(.conflictingChunk))
    }

    /// Descriptor equality IS transcript equality: the descriptor mirrors exactly the eight fields
    /// the canonical transcript writes, so one cannot drift from the other.
    @Test func descriptorEqualityIsTranscriptEquality() {
        let base = MeshChunkFixtures.chunk()
        let mutations: [MeshChunk] = [
            base.replacing(meshID: UUID()),
            base.replacing(itemID: UUID()),
            base.replacing(originFingerprint: "fp099"),
            base.replacing(contentHash: Data(repeating: 0x77, count: 32)),
            base.replacing(chunkIndex: base.chunkIndex + 1),
            base.replacing(chunkCount: base.chunkCount + 1),
            base.replacing(chunkHash: Data(repeating: 0x66, count: 32)),
            base.replacing(expiresAt: base.expiresAt.addingTimeInterval(1))
        ]
        for mutated in mutations {
            #expect(MeshChunkDescriptor(mutated) != MeshChunkDescriptor(base))
            #expect(canonicalBytes(for: mutated) != canonicalBytes(for: base))
        }
        // And the two fields the transcript excludes move neither.
        let resigned = base.replacing(signature: Data(repeating: 0x5A, count: 64))
        let repayloaded = base.replacing(payload: Data([0x00, 0x01]))
        for unchanged in [resigned, repayloaded] {
            #expect(MeshChunkDescriptor(unchanged) == MeshChunkDescriptor(base))
            #expect(canonicalBytes(for: unchanged) == canonicalBytes(for: base))
        }
    }

    /// The BINDING door, all four outcomes, mapped through the store's refusal table — and a refused
    /// bind mutates nothing on either side.
    @Test func theDurableFormAndTheAssemblyAgreeOnEveryBindingVerdict() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        let (first, second) = pair()
        let blob = first.payload + second.payload
        var assembly = try #require(MeshChunkAssembly.forChunk(first))
        for chunk in [first, second] {
            _ = assembly.admit(chunk)
            _ = staged(chunk, in: store)
        }

        let matching = manifest(forSize: UInt64(blob.count), contentHash: first.contentHash, itemID: first.itemID)
        let wrongCount = manifest(forSize: 1_000, contentHash: first.contentHash, itemID: first.itemID)
        let wrongLength = manifest(
            forSize: UInt64(MeshChunkFormat.maxChunkPayloadBytes + 2_000),
            contentHash: first.contentHash, itemID: first.itemID
        )
        let foreign = manifest(
            forSize: UInt64(blob.count), contentHash: Data(repeating: 0x09, count: 32), itemID: first.itemID
        )

        var probe = assembly
        #expect(probe.bind(to: wrongCount) == .refused(.countMismatch))
        #expect(probe.boundSize == nil, "a refused bind must not mutate")
        #expect(admitted(wrongCount, in: store)?.refusal == .chunkCountMismatch)

        #expect(probe.bind(to: wrongLength) == .refused(.payloadLengthMismatch))
        #expect(probe.boundSize == nil)
        #expect(admitted(wrongLength, in: store)?.refusal == .heldChunkLengthMismatch)

        #expect(probe.bind(to: foreign) == .refused(.foreignItem))
        #expect(admitted(foreign, in: store)?.refusal == .manifestMismatch)

        #expect(assembly.bind(to: matching) == .bound)
        let durable = try #require(admitted(matching, in: store))
        #expect(durable.value?.boundAParkedSet == true)
        #expect(durable.value?.receivedCount == 2)

        // And the completion twins agree, case for case.
        guard case .complete(let reassembled) = assembly.completion(against: matching) else {
            Issue.record("the in-memory form did not complete")
            return
        }
        #expect(reassembled == blob)
    }

    /// An unsigned manifest is fine here: the store's precondition is that
    /// `MeshRoutedManifestVerifier` already accepted one, and this suite is about the SET decision.
    private func manifest(forSize size: UInt64, contentHash: Data, itemID: UUID) -> MeshRoutedManifest {
        MeshRoutedManifestFixtures.manifest().replacing(
            itemID: itemID, originFingerprint: MeshChunkFixtures.originFingerprint,
            contentHash: contentHash, size: size
        )
    }

    /// The store's admission outcome under a pinned install binding.
    private func admitted(
        _ manifest: MeshRoutedManifest,
        in store: MeshRoutedStore
    ) -> MeshRoutedOutcome<MeshRoutedManifestAdmission>? {
        PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.admittingManifest(manifest, now: Fixture.now)
        }
    }
}

// MARK: - The delivery map

/// The persisted half of `MeshDeliveryTarget`, and the destination set that comes back from the
/// origin's signed manifest rather than from a file.
@MainActor
@Suite(.serialized)
struct MeshRoutedDeliveryPersistenceTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer
    /// has run before a cell's identities or stores reach the keychain.
    let keychain = PackageTestEnvironment.keychain

    /// A target over three destinations with the states a real item passes through.
    private func target() throws -> (target: MeshDeliveryTarget, roster: MeshDerivedRoster, names: [String]) {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 4)
        let names = rig.fingerprints
        let target = MeshDeliveryTarget(
            contentID: MeshRoutedManifestFixtures.itemID, roster: rig.roster, selfFingerprint: names[0]
        )
        return (target, rig.roster, names)
    }

    @Test func aDeliveryRecordRoundTripsForEveryStateCombination() throws {
        let (fresh, _, names) = try target()
        let custodied = try #require(fresh.advancing(names[1], to: .custodied(by: names[3])).target)
        let both = try #require(custodied.advancing(names[2], to: .delivered).target)

        for original in [fresh, custodied, both] {
            let record = MeshRoutedDeliveryRecord(encoding: original)
            let wire = try JSONEncoder().encode(record)
            let decoded = try JSONDecoder().decode(MeshRoutedDeliveryRecord.self, from: wire)
            guard case .restored(let restored) = decoded.restored(destinations: original.destinations) else {
                Issue.record("a delivery record did not restore")
                return
            }
            #expect(restored == original)
        }
    }

    /// `pending` is an ABSENCE on both sides, so two records that mean the same thing are `==`.
    @Test func pendingIsNeverStored() throws {
        let (fresh, _, _) = try target()
        #expect(MeshRoutedDeliveryRecord(encoding: fresh).progress.isEmpty)
    }

    @Test func departedIsNeverEncodedAndIsRefusedOnDecode() throws {
        let (fresh, roster, names) = try target()
        // A departed destination is DERIVED at read; nothing about it reaches the encoder.
        let custodied = try #require(fresh.advancing(names[1], to: .custodied(by: names[2])).target)
        let encoded = MeshRoutedDeliveryRecord(encoding: custodied)
        #expect(encoded.progress.values.allSatisfy { $0.token != MeshDeliveryStateToken.departed.rawValue })
        #expect(custodied.dispositions(in: roster).values.contains(.departed) == false)

        let planted = MeshRoutedDeliveryRecord(
            contentID: custodied.contentID,
            progress: [names[1]: MeshRoutedDeliveryProgress(token: "departed", custodian: nil)]
        )
        #expect(planted.restored(destinations: custodied.destinations)
                == .refused(.departedIsDerived))
    }

    @Test func everyRestoreRefusalIsReachable() throws {
        let (fresh, _, names) = try target()
        let destinations = fresh.destinations
        let contentID = fresh.contentID
        func record(_ progress: [String: MeshRoutedDeliveryProgress]) -> MeshRoutedDeliveryRecord {
            MeshRoutedDeliveryRecord(contentID: contentID, progress: progress)
        }

        #expect(record([:]).restored(destinations: []) == .refused(.emptyDestinations))
        #expect(record([:]).restored(destinations: [names[1], names[1]])
                == .refused(.duplicateDestination))
        #expect(record([:]).restored(
            destinations: (0...MeshRoutedManifestFormat.maxDestinations).map { "fp\($0)" }
        ) == .refused(.tooManyDestinations))
        #expect(record(["fp404": MeshRoutedDeliveryProgress(token: "custodied", custodian: names[1])])
                .restored(destinations: destinations) == .refused(.progressKeyIsNotADestination))
        #expect(record([names[1]: MeshRoutedDeliveryProgress(token: "departed", custodian: nil)])
                .restored(destinations: destinations) == .refused(.departedIsDerived))
        #expect(record([names[1]: MeshRoutedDeliveryProgress(token: "held", custodian: nil)])
                .restored(destinations: destinations) == .refused(.unknownStateToken))
        #expect(record([names[1]: MeshRoutedDeliveryProgress(token: "custodied", custodian: "")])
                .restored(destinations: destinations) == .refused(.emptyCustodian))
        #expect(record([names[1]: MeshRoutedDeliveryProgress(token: "custodied", custodian: nil)])
                .restored(destinations: destinations) == .refused(.custodianMissing))
        #expect(record([names[1]: MeshRoutedDeliveryProgress(token: "delivered", custodian: names[2])])
                .restored(destinations: destinations) == .refused(.custodianOnANonCustodiedState))
        #expect(MeshDeliveryRestoreRefusal.allCases.count == 9)
    }

    @Test func aRestoredTargetStillRefusesARegressionAndASetMismatch() throws {
        let (fresh, _, names) = try target()
        let custodied = try #require(fresh.advancing(names[1], to: .custodied(by: names[2])).target)
        guard case .restored(let restored) = MeshRoutedDeliveryRecord(encoding: custodied)
            .restored(destinations: custodied.destinations) else {
            Issue.record("the record did not restore")
            return
        }
        #expect(restored.advancing(names[1], to: .pending).refusal == .wouldRegress)
        #expect(restored.advancing("fp404", to: .delivered).refusal == .notADestination)
        #expect(restored.merging(custodied).target == restored)

        let (other, _, _) = try target()
        let narrowed = try #require(
            MeshRoutedDeliveryRecord(encoding: other)
                .restored(destinations: Array(other.destinations.dropLast())).target
        )
        #expect(restored.merging(narrowed).refusal == .destinationSetMismatch)
    }

    /// A held item whose OWN stored delivery map will not restore is invisible to every
    /// enumeration door — and must therefore be named at the value level, or items 6 and 8 lose it
    /// with no signal at all (plan §11's "nothing grows silently", §3.6's "no silent drop").
    ///
    /// The two nil answers `deliveryTarget` gives are structurally different: a **parked** item
    /// genuinely knows no destinations (no manifest, so no signed set), while this one is holding
    /// ciphertext for destinations its own bytes can no longer account for.
    @Test func anItemWhoseDeliveryMapWillNotRestoreIsNamedNotSilentlyDropped() throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 4)
        let names = rig.fingerprints
        let mine = names[0]
        let destinations = Array(names.dropFirst())
        let refusing = MeshRoutedManifestFixtures.manifest().replacing(destinations: destinations)
        let healthy = refusing.replacing(itemID: UUID())
        let now = MeshRoutedStoreFixtures.now

        // The map's key is not one of the signed destinations — one of the nine restore refusals.
        let unrestorable = MeshRoutedDeliveryRecord(
            contentID: refusing.itemID,
            progress: ["fp404": MeshRoutedDeliveryProgress(token: "custodied", custodian: names[1])]
        )
        #expect(unrestorable.restored(destinations: refusing.destinations)
                == .refused(.progressKeyIsNotADestination))
        let index = MeshRoutedIndex(items: [
            Self.record(refusing, delivery: unrestorable),
            Self.record(healthy, delivery: MeshRoutedDeliveryRecord(
                encoding: MeshDeliveryTarget(
                    contentID: healthy.itemID, roster: rig.roster, selfFingerprint: mine
                )
            ))
        ])
        let refusedKey = MeshRoutedItemKey(refusing)
        let healthyKey = MeshRoutedItemKey(healthy)
        let branch = MeshDeliveryFixtures.branch(rig, selfFingerprint: mine, reachable: [mine, names[1]])

        // The healthy item is enumerated by all of them…
        #expect(index.outstandingDestinations(for: healthyKey, in: rig.roster) == destinations)
        let origin = refusing.originFingerprint
        #expect(index.itemsAwaitingHandoff(at: now, in: rig.roster, originatedBy: origin)
                .map(\.key) == [healthyKey])
        #expect(index.handoffCandidateCount(at: now, in: rig.roster, originatedBy: origin) == 1)
        #expect(index.outstandingItems(at: now, in: rig.roster).count == destinations.count)

        // …and the one that will not restore by none of them.
        #expect(index.outstandingDestinations(for: refusedKey, in: rig.roster).isEmpty)
        #expect(index.outstandingReachable(for: refusedKey, from: branch, in: rig.roster).isEmpty)
        #expect(index.outstandingUnreachable(for: refusedKey, from: branch, in: rig.roster).isEmpty)
        #expect(
            index.outstandingItems(at: now, in: rig.roster)
                .values.allSatisfy { bucket in bucket.allSatisfy { $0.key != refusedKey } }
        )

        // It is named instead of dropped, and a parked item is NOT named — it has no signed set.
        #expect(index.itemsWithUnrestorableDelivery(at: now).map(\.key) == [refusedKey])
        #expect(index.itemsWithUnrestorableDelivery(at: now).allSatisfy { $0.deliveryRestoreRefused })
        let healthyRef = try #require(
            index.itemsAwaitingHandoff(at: now, in: rig.roster, originatedBy: origin).first
        )
        #expect(healthyRef.deliveryRestoreRefused == false)
        let parked = MeshRoutedIndex(items: [MeshRoutedStoreFixtures.record()])
        #expect(parked.itemsWithUnrestorableDelivery(at: now).isEmpty)
        #expect(parked.items.allSatisfy { $0.deliveryRestoreRefused == false })
    }

    /// A complete one-chunk record carrying `manifest` and `delivery`, so the handoff enumerator's
    /// completeness precondition is met without staging real files.
    private static func record(
        _ manifest: MeshRoutedManifest,
        delivery: MeshRoutedDeliveryRecord
    ) -> MeshRoutedItemRecord {
        MeshRoutedItemRecord(
            key: MeshRoutedItemKey(manifest),
            contentHash: manifest.contentHash,
            chunkCount: 1,
            expiresAt: manifest.expiresAt,
            manifest: manifest,
            firstSeenAt: MeshRoutedManifestFixtures.base,
            custodiedAt: nil,
            deliveredAt: nil,
            chunks: [MeshRoutedStoreFixtures.descriptor(index: 0, count: 1, bytes: 16)],
            delivery: delivery,
            receipts: [],
            recipientReceipts: []
        )
    }

    /// A custodian's own restored destination set may name the custodian: filtering it out would be
    /// a silent shrink of a signed set, and item 6 owns what "this was addressed to me too" means.
    @Test func aRestoredSetIsTheSignedOneEvenWhenItNamesTheReader() throws {
        let (fresh, _, names) = try target()
        guard case .restored(let restored) = MeshRoutedDeliveryRecord(encoding: fresh)
            .restored(destinations: fresh.destinations) else {
            Issue.record("the record did not restore")
            return
        }
        #expect(restored.destinations == fresh.destinations)
        #expect(restored.names(names[1]))
    }
}

// MARK: - Evidence, caps and first-seen

/// What the store writes, refuses and counts.
@MainActor
@Suite(.serialized)
struct MeshRoutedCustodyEvidenceTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer
    /// has run before a cell's identities or stores reach the keychain.
    let keychain = PackageTestEnvironment.keychain

    private typealias Fixture = MeshRoutedStoreFixtures

    /// The store's loaded index under a pinned install binding.
    private func index(of store: MeshRoutedStore) -> MeshRoutedIndex? {
        let load = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.load()
        }
        guard case .loaded(let index, _) = load else { return nil }
        return index
    }

    @Test func everyCustodiedRungIsBackedByStoredEvidence() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        let receipt = try MeshRoutedCustodyFixtures.receipt(rig)
        let named = rig.otherDestinations
        #expect(named.isEmpty == false)

        let outcome = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            rig.store.recordingCustodyTransfer(
                item: rig.key, for: named, receipt: receipt, now: Fixture.now
            )
        }
        let advanced = try #require(outcome.value?.target)
        for destination in named {
            #expect(advanced.state(of: destination) == .custodied(by: receipt.custodianFingerprint))
        }

        let record = try #require(index(of: rig.store)?.record(for: rig.key))
        let stored = try #require(record.receipts.first)
        #expect(record.receipts.count == 1)
        #expect(stored.custodianFingerprint == receipt.custodianFingerprint)
        #expect(stored.signature == receipt.signature)
        #expect(canonicalBytes(for: stored) == canonicalBytes(for: receipt))
        // This device's OWN custody is backed by `custodiedAt`, not by a self-receipt.
        #expect(record.custodiedAt != nil)
        #expect(record.receipts.contains { $0.custodianFingerprint == rig.origin.localFingerprint } == false)
    }

    @Test func aCustodyTransferRecordsTheSignerAndOnlyTheNamedDestinations() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        let receipt = try MeshRoutedCustodyFixtures.receipt(rig)
        let named = rig.otherDestinations
        let before = try #require(index(of: rig.store)?.record(for: rig.key))

        // A destination the signed manifest does not name writes nothing.
        let stranger = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            rig.store.recordingCustodyTransfer(
                item: rig.key, for: ["fp404"], receipt: receipt, now: Fixture.now
            )
        }
        #expect(stranger.refusal == .notADestination)
        #expect(index(of: rig.store)?.record(for: rig.key) == before)

        // A receipt about another item writes nothing either.
        let mismatched = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            rig.store.recordingCustodyTransfer(
                item: rig.key, for: named,
                receipt: receipt.replacing(itemID: UUID()), now: Fixture.now
            )
        }
        #expect(mismatched.refusal == .manifestMismatch)
        #expect(index(of: rig.store)?.record(for: rig.key) == before)

        // An unknown item is refused by name.
        let unknown = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            rig.store.recordingCustodyTransfer(
                item: MeshRoutedItemKey(originFingerprint: "fp404", itemID: UUID()),
                for: named, receipt: receipt, now: Fixture.now
            )
        }
        #expect(unknown.refusal == .unknownItem)

        // The custodian is the SIGNER, and the destinations it is now courier for are the caller's
        // statement — the custodian need not be among them.
        let applied = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            rig.store.recordingCustodyTransfer(
                item: rig.key, for: named, receipt: receipt, now: Fixture.now
            )
        }
        let target = try #require(applied.value?.target)
        #expect(named.contains(receipt.custodianFingerprint) == false,
                "the fp004 case: the custodian is a destination of the ITEM, not of this transfer")
        #expect(target.state(of: receipt.custodianFingerprint) == .pending)
    }

    /// The evidence set is bounded by the roster cap, and a full one refuses by name without
    /// writing.
    @Test func theEvidenceSetIsBoundedByTheRosterCap() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        let manifest = MeshRoutedManifestFixtures.manifest()
        let full = (0..<MeshRoutedStoreFormat.maxReceiptsPerItem).map {
            MeshCustodyReceiptFixtures.receipt().replacing(custodianFingerprint: "fpc\($0)")
        }
        try Fixture.plant(MeshRoutedIndex(items: [record(for: manifest, receipts: full)]), into: store)

        let outcome = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.recordingCustodyTransfer(
                item: MeshRoutedItemKey(manifest), for: ["fp002"],
                receipt: MeshCustodyReceiptFixtures.receipt().replacing(custodianFingerprint: "fpc999"),
                now: Fixture.now
            )
        }
        #expect(outcome.refusal == .capacityReceipts)
        #expect(index(of: store)?.record(for: MeshRoutedItemKey(manifest))?.receipts.count
                == MeshRoutedStoreFormat.maxReceiptsPerItem)

        // Re-recording an EXISTING custodian's receipt is not growth, so it is not refused.
        let replaced = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.recordingCustodyTransfer(
                item: MeshRoutedItemKey(manifest), for: ["fp002"],
                receipt: MeshCustodyReceiptFixtures.receipt().replacing(custodianFingerprint: "fpc0"),
                now: Fixture.now
            )
        }
        #expect(replaced.value?.target != nil)
    }

    @Test func everyCapRefusesByItsOwnName() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        let manifest = MeshRoutedManifestFixtures.manifest()

        let items = (0..<MeshRoutedStoreFormat.maxItems).map { _ in Fixture.record() }
        try Fixture.plant(MeshRoutedIndex(items: items), into: store)
        #expect(admitting(manifest, in: store).refusal == .capacityItems)

        let hog = Fixture.record(chunks: [
            Fixture.descriptor(index: 0, count: 1, bytes: Int(MeshRoutedStoreFormat.maxContentBytes))
        ])
        try Fixture.plant(MeshRoutedIndex(items: [hog]), into: store)
        #expect(admitting(manifest, in: store).refusal == .capacityBytes)

        let filesPerItem = MeshRoutedStoreFormat.maxChunksPerItem
        let fileHogs = (0..<(MeshRoutedStoreFormat.maxHeldChunkFiles / filesPerItem)).map { _ in
            Fixture.record(
                chunkCount: UInt32(filesPerItem),
                chunks: (0..<filesPerItem).map { Fixture.descriptor(index: UInt32($0), count: UInt32(filesPerItem), bytes: 1) }
            )
        }
        try Fixture.plant(MeshRoutedIndex(items: fileHogs), into: store)
        #expect(admitting(manifest, in: store).refusal == .capacityChunkFiles)
    }

    /// The store admits nothing it could never finish: the file-slot budget is reserved at
    /// ADMISSION from the manifest's derived chunk count, exactly as the byte budget is.
    @Test func admissionReservesFileSlotsAsWellAsBytes() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        let manifest = MeshRoutedManifestFixtures.manifest()
        let derived = try #require(MeshChunkFormat.chunkCount(forSize: manifest.size))
        #expect(derived == 1)

        // One free slot: an item needing exactly one fits, an item needing two would not.
        let filesPerItem = MeshRoutedStoreFormat.maxChunksPerItem
        let hogs = (0..<(MeshRoutedStoreFormat.maxHeldChunkFiles / filesPerItem)).map { index in
            Fixture.record(
                chunkCount: UInt32(filesPerItem),
                chunks: (0..<(index == 0 ? filesPerItem - 1 : filesPerItem)).map {
                    Fixture.descriptor(index: UInt32($0), count: UInt32(filesPerItem), bytes: 1)
                }
            )
        }
        try Fixture.plant(MeshRoutedIndex(items: hogs), into: store)
        #expect(admitting(manifest, in: store).value?.isNew == true)

        try Fixture.plant(MeshRoutedIndex(items: hogs), into: store)
        let twoChunks = manifest.replacing(
            itemID: UUID(), size: UInt64(MeshChunkFormat.maxChunkPayloadBytes + 1)
        )
        #expect(admitting(twoChunks, in: store).refusal == .capacityChunkFiles)
    }

    /// A per-item chunk cap fires at the door even when the per-chunk rule would admit — the
    /// bounded-growth statement said where the array actually grows.
    @Test func aFullPerItemChunkArrayRefusesByName() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        let count = UInt32(MeshRoutedStoreFormat.maxChunksPerItem)
        let chunk = MeshChunkFixtures.chunk(index: count - 1, count: count, payload: Data([0x01]))
        // A decodable index whose descriptor ARRAY is at the cap while one slot is still free: the
        // exact state the per-item cap exists to bound, and the only one the per-chunk rule cannot
        // reach on its own.
        var descriptors = (0..<Int(count) - 1).map {
            Fixture.descriptor(index: UInt32($0), count: count, bytes: 1)
        }
        descriptors.append(Fixture.descriptor(index: 0, count: count, bytes: 1))
        let record = MeshRoutedItemRecord(
            key: MeshRoutedItemKey(chunk), contentHash: chunk.contentHash, chunkCount: count,
            expiresAt: chunk.expiresAt, manifest: nil, firstSeenAt: MeshRoutedManifestFixtures.base,
            custodiedAt: nil, deliveredAt: nil, chunks: descriptors, delivery: nil,
            receipts: [], recipientReceipts: []
        )
        #expect(record.chunks.count == MeshRoutedStoreFormat.maxChunksPerItem)
        try Fixture.plant(MeshRoutedIndex(items: [record]), into: store)

        let outcome = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.stagingChunk(chunk, now: Fixture.now)
        }
        #expect(outcome.refusal == .capacityChunksPerItem)
    }

    @Test func parkedManifestLessChunksCountTowardEveryCap() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        let chunk = MeshChunkFixtures.chunk(index: 0, count: 1, payload: Data(repeating: 0x5A, count: 128))

        let staged = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.stagingChunk(chunk, now: Fixture.now)
        }
        #expect(staged.value == .admitted(received: 1, expected: 1))
        let loaded = try #require(index(of: store))
        #expect(loaded.itemCount == 1)
        #expect(loaded.heldChunkFileCount == 1)
        #expect(loaded.totalContentBytesHeld == 128)
        #expect(loaded.record(for: MeshRoutedItemKey(chunk))?.isParked == true)
        #expect(MeshRoutedCustodyFixtures.chunkFilesOnDisk(scope).count == 1)
    }

    @Test func firstSeenIsMonotoneAndNeverAdoptedFromAPeer() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        let manifest = MeshRoutedManifestFixtures.manifest()
        #expect(admitting(manifest, in: store, now: Fixture.now).value?.isNew == true)
        let first = try #require(index(of: store)?.firstSeenAt(of: MeshRoutedItemKey(manifest)))
        #expect(first == Fixture.now)

        // A later sighting does not move it, and neither does the origin's own claimed `createdAt`,
        // which is far earlier — receiver-local first-seen is never adopted from the wire.
        #expect(admitting(manifest, in: store, now: Fixture.now.addingTimeInterval(3_600)).value?.isNew == false)
        #expect(index(of: store)?.firstSeenAt(of: MeshRoutedItemKey(manifest)) == first)
        #expect(manifest.createdAt < first)
    }

    @Test func aManifestForAHeldItemIdUnderAnotherOriginIsRefusedAtTheDoor() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        let manifest = MeshRoutedManifestFixtures.manifest()
        let squatted = Fixture.record(origin: "fpZZZ", itemID: manifest.itemID)
        try Fixture.plant(MeshRoutedIndex(items: [squatted]), into: store)

        #expect(admitting(manifest, in: store).refusal == .duplicateItemID)
    }

    /// The store never names a decryption seam: no unwrap, no content key, no key-agreement key —
    /// which is what makes custody ciphertext-only on a locked device by construction.
    ///
    /// `MeshRoutedAccessGate.swift` joined the list at P5 item 10: it is the file that answers
    /// *whether plaintext may exist*, so it is precisely the file a future "just decrypt it here"
    /// would be tempted into — and it must stay as free of a decryption seam as the store itself.
    @Test func theRoutedStoreNamesNoDecryptionSeam() throws {
        let files = [
            "MeshRoutedStore.swift", "MeshRoutedCustody.swift", "MeshRoutedCustodyCommit.swift",
            "MeshRoutedIndex.swift", "MeshRoutedStoreKey.swift", "MeshRoutedContentHasher.swift",
            "MeshChunkAdmissionRule.swift", "MeshRoutedCustodyHandoff.swift",
            "MeshRoutedCapacity.swift", "MeshRoutedDeliveryHold.swift",
            "MeshRoutedAccessGate.swift", "MeshRoutedRefusalBudget.swift"
        ]
        var scanned = 0
        var sealing: [String] = []
        for name in files {
            let code = MeshRoutedSourceScan.codeOnly(try PackageRoot.source("Sources/ProximityKit/Mesh/\(name)"))
            scanned += 1
            for forbidden in ["MeshRoutedContentKeyWrapper", "localKeyAgreement", ".unwrap("] {
                #expect(code.contains(forbidden) == false, "\(name) names \(forbidden)")
            }
            if code.contains("ColumnCrypto") { sealing.append(name) }
        }
        #expect(scanned == files.count)
        // `ColumnCrypto` is reached in exactly one of them: the at-rest seal, and nothing else.
        #expect(sealing == ["MeshRoutedStore.swift"], "the at-rest seal must live in one file: \(sealing)")
    }

    /// The forwarding doors hand back the ORIGIN's exact signed bytes — a custodian is a courier,
    /// not a co-signer.
    @Test func theForwardingDoorsReturnTheOriginsExactBytes() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        MeshRoutedCustodyFixtures.stageAll(rig)

        let forwarded = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            (
                manifest: rig.store.forwardableManifest(item: rig.key),
                chunk: rig.store.forwardableChunk(item: rig.key, index: 0)
            )
        }
        let manifest = try #require(forwarded.manifest.value ?? nil)
        #expect(manifest == rig.manifest)
        #expect(canonicalBytes(for: manifest) == canonicalBytes(for: rig.manifest))
        #expect(manifest.signature == rig.manifest.signature)

        let chunk = try #require(forwarded.chunk.value ?? nil)
        #expect(chunk == rig.chunks[0])
        #expect(chunk.signature == rig.chunks[0].signature)
        #expect(canonicalBytes(for: chunk) == canonicalBytes(for: rig.chunks[0]))

        let indices = index(of: rig.store)?.heldChunkIndices(of: rig.key)
        #expect(indices == (0..<UInt32(rig.chunks.count)).map { $0 })
    }

    /// Expiry retires an item, its payload files and its stored receipts together.
    @Test func sweepingExpiredTakesFilesAndReceiptsWithTheItem() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        let receipt = try MeshRoutedCustodyFixtures.receipt(rig)
        _ = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            rig.store.recordingCustodyTransfer(
                item: rig.key, for: rig.otherDestinations, receipt: receipt, now: Fixture.now
            )
        }
        #expect(index(of: rig.store)?.record(for: rig.key)?.receipts.isEmpty == false)

        let swept = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            rig.store.sweepingExpired(now: rig.manifest.expiresAt.addingTimeInterval(1))
        }
        let report = try #require(swept.value)
        #expect(report.itemsRemoved == 1)
        #expect(report.chunkFilesRemoved == rig.chunks.count)
        #expect(index(of: rig.store)?.itemCount == 0)
        #expect(MeshRoutedCustodyFixtures.chunkFilesOnDisk(scope).isEmpty)
    }

    /// Item 11's door: a parked set whose manifest this build will not accept is dropped whole.
    @Test func droppingAnItemTakesItsFilesWithIt() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        let chunk = MeshChunkFixtures.chunk(index: 0, count: 1, payload: Data([0x11, 0x22]))
        _ = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.stagingChunk(chunk, now: Fixture.now)
        }
        #expect(MeshRoutedCustodyFixtures.chunkFilesOnDisk(scope).count == 1)

        let dropped = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.dropping(item: MeshRoutedItemKey(chunk), reason: "unknownTypeToken")
        }
        #expect(dropped.value?.itemsRemoved == 1)
        #expect(dropped.value?.chunkFilesRemoved == 1)
        #expect(MeshRoutedCustodyFixtures.chunkFilesOnDisk(scope).isEmpty)
        let again = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.dropping(item: MeshRoutedItemKey(chunk), reason: "unknownTypeToken")
        }
        #expect(again.refusal == .unknownItem)
    }

    /// **P5 item 6's evidence-only door.** A forwarded custody receipt is stored as evidence and
    /// moves **no rung**: the drain has no honest value for `recordingCustodyTransfer`'s
    /// `for destinations:`, which is the caller's statement about a hand-off nobody made.
    @Test func recordingCustodyEvidenceStoresWithoutMovingARung() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        let receipt = try MeshRoutedCustodyFixtures.receipt(rig)
        let before = try #require(index(of: rig.store)?.record(for: rig.key)?.deliveryTarget)

        let outcome = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            rig.store.recordingCustodyEvidence(item: rig.key, receipt: receipt, now: Fixture.now)
        }
        let evidence = try #require(outcome.value)
        #expect(evidence.custodian == receipt.custodianFingerprint)
        #expect(evidence.isNew)

        let record = try #require(index(of: rig.store)?.record(for: rig.key))
        let stored = try #require(record.receipts.first)
        #expect(record.receipts.count == 1)
        #expect(canonicalBytes(for: stored) == canonicalBytes(for: receipt))
        #expect(stored.signature == receipt.signature, "a courier forwards, it never re-signs")
        #expect(record.deliveryTarget == before, "an evidence write advances no delivery rung")

        // A second arrival replaces by signer and grows nothing.
        let again = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            rig.store.recordingCustodyEvidence(item: rig.key, receipt: receipt, now: Fixture.now)
        }
        #expect(again.value?.isNew == false)
        #expect(index(of: rig.store)?.record(for: rig.key)?.receipts.count == 1)
    }

    /// The evidence door applies the transfer door's identity equalities, in the same order.
    @Test func recordingCustodyEvidenceRefusesAMismatchedReceipt() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        let receipt = try MeshRoutedCustodyFixtures.receipt(rig)
        let before = try #require(index(of: rig.store)?.record(for: rig.key))

        for broken in [
            receipt.replacing(itemID: UUID()),
            receipt.replacing(originFingerprint: "fp404"),
            receipt.replacing(contentHash: Data(repeating: 0x77, count: 32)),
            receipt.replacing(meshID: UUID())
        ] {
            let outcome = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
                rig.store.recordingCustodyEvidence(item: rig.key, receipt: broken, now: Fixture.now)
            }
            #expect(outcome.refusal == .manifestMismatch)
        }
        #expect(index(of: rig.store)?.record(for: rig.key) == before, "nothing is written on a refusal")

        let unknown = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            rig.store.recordingCustodyEvidence(
                item: MeshRoutedItemKey(originFingerprint: "fp404", itemID: UUID()),
                receipt: receipt, now: Fixture.now
            )
        }
        #expect(unknown.refusal == .unknownItem)
    }

    @Test func recordingCustodyEvidenceRefusesPastTheReceiptCap() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        let manifest = MeshRoutedManifestFixtures.manifest()
        let full = (0..<MeshRoutedStoreFormat.maxReceiptsPerItem).map {
            MeshCustodyReceiptFixtures.receipt().replacing(custodianFingerprint: "fpc\($0)")
        }
        try Fixture.plant(MeshRoutedIndex(items: [record(for: manifest, receipts: full)]), into: store)

        let outcome = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.recordingCustodyEvidence(
                item: MeshRoutedItemKey(manifest),
                receipt: MeshCustodyReceiptFixtures.receipt().replacing(custodianFingerprint: "fpc999"),
                now: Fixture.now
            )
        }
        #expect(outcome.refusal == .capacityReceipts)
        #expect(index(of: store)?.record(for: MeshRoutedItemKey(manifest))?.receipts.count
                == MeshRoutedStoreFormat.maxReceiptsPerItem)

        // Replacing an EXISTING custodian's receipt is not growth, so it is not refused.
        let replaced = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.recordingCustodyEvidence(
                item: MeshRoutedItemKey(manifest),
                receipt: MeshCustodyReceiptFixtures.receipt().replacing(custodianFingerprint: "fpc0"),
                now: Fixture.now
            )
        }
        #expect(replaced.value?.isNew == false)
    }

    /// The refusal-helper split item 6 made must leave item 8's transfer door behaving exactly as it
    /// did: identity, then destinations, then capacity — in that order.
    @Test func recordingCustodyTransferIsUnchanged() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        let receipt = try MeshRoutedCustodyFixtures.receipt(rig)

        // Identity outranks destinations: a receipt about another item refuses `manifestMismatch`
        // even though the destination list is also wrong.
        let both = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            rig.store.recordingCustodyTransfer(
                item: rig.key, for: ["fp404"],
                receipt: receipt.replacing(itemID: UUID()), now: Fixture.now
            )
        }
        #expect(both.refusal == .manifestMismatch)

        let empty = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            rig.store.recordingCustodyTransfer(
                item: rig.key, for: [], receipt: receipt, now: Fixture.now
            )
        }
        #expect(empty.refusal == .notADestination)

        let applied = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            rig.store.recordingCustodyTransfer(
                item: rig.key, for: rig.otherDestinations, receipt: receipt, now: Fixture.now
            )
        }
        let target = try #require(applied.value?.target)
        for destination in rig.otherDestinations {
            #expect(target.state(of: destination) == .custodied(by: receipt.custodianFingerprint))
        }
    }

    /// The store's admission outcome under a pinned install binding.
    private func admitting(
        _ manifest: MeshRoutedManifest,
        in store: MeshRoutedStore,
        now: Date = MeshRoutedStoreFixtures.now
    ) -> MeshRoutedOutcome<MeshRoutedManifestAdmission> {
        PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.admittingManifest(manifest, now: now)
        }
    }

    /// A held record for `manifest` with a delivery map and a receipt evidence set.
    private func record(
        for manifest: MeshRoutedManifest,
        receipts: [MeshCustodyReceipt]
    ) -> MeshRoutedItemRecord {
        MeshRoutedItemRecord(
            key: MeshRoutedItemKey(manifest),
            contentHash: manifest.contentHash,
            chunkCount: 1,
            expiresAt: manifest.expiresAt,
            manifest: manifest,
            firstSeenAt: MeshRoutedManifestFixtures.base,
            custodiedAt: nil,
            deliveredAt: nil,
            chunks: [],
            delivery: MeshRoutedDeliveryRecord(contentID: manifest.itemID, progress: [:]),
            receipts: receipts,
            recipientReceipts: []
        )
    }
}
