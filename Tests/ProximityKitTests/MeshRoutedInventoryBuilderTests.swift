// MeshRoutedInventoryBuilderTests.swift
// ProximityKitTests
//
// P5 item 5 (plan §11): deriving a routed inventory from a real routed store.
//
// The claims here are the ones a wire golden cannot make: that each field comes off the store door
// the design names, that the two halves of the custody self-rule are both live, that nothing is
// silently dropped from the advertisement, and that the held-chunk bitmap is the EXACT set — a
// repaired hole shows up as a missing bit even when the count still matches another peer's.
//
// Every test that touches disk runs on its OWN scope (temp directory + `.test.` keychain service),
// so the shared-disk-root flake family gains no member. Nothing here sleeps or reads a wall clock.

import Foundation
import Testing
@testable import ProximityKit

/// The builder against the store's own doors.
@MainActor
@Suite(.serialized)
struct MeshRoutedInventoryBuilderTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer
    /// has run before a cell's identities or stores reach the keychain.
    let keychain = PackageTestEnvironment.keychain

    private typealias Fixture = MeshRoutedStoreFixtures

    /// The injected instant every case builds at — inside the fixture item's life.
    private nonisolated static let now = MeshRoutedInventoryFixtures.sentAt

    /// This device, for the cases that do not need a real identity.
    private nonisolated static let me = "fp007"

    /// A record carrying whatever evidence a case needs, planted rather than staged.
    private static func record(
        origin: String = "fp001",
        itemID: UUID = UUID(),
        chunkCount: UInt32 = 3,
        heldIndices: [UInt32] = [0, 1, 2],
        manifest: MeshRoutedManifest? = nil,
        custodiedAt: Date? = nil,
        delivery: MeshRoutedDeliveryRecord? = nil,
        receipts: [MeshCustodyReceipt] = [],
        recipientReceipts: [MeshRecipientReceipt] = [],
        expiresAt: Date = MeshRoutedManifestFixtures.expiresAt
    ) -> MeshRoutedItemRecord {
        MeshRoutedItemRecord(
            key: MeshRoutedItemKey(originFingerprint: origin, itemID: itemID),
            contentHash: MeshRoutedManifestFixtures.contentHash,
            chunkCount: chunkCount,
            expiresAt: expiresAt,
            manifest: manifest,
            firstSeenAt: MeshRoutedManifestFixtures.base,
            custodiedAt: custodiedAt,
            deliveredAt: nil,
            chunks: heldIndices.map { Fixture.descriptor(index: $0, count: chunkCount, bytes: 16) },
            delivery: delivery,
            receipts: receipts,
            recipientReceipts: recipientReceipts
        )
    }

    /// The inventory `index` implies for `me`, at the fixture instant.
    private static func inventory(
        _ index: MeshRoutedIndex, selfFingerprint: String = me
    ) throws -> MeshRoutedInventory {
        try #require(MeshRoutedInventory(
            meshID: MeshRoutedInventoryFixtures.meshID, index: index,
            selfFingerprint: selfFingerprint, at: now
        ))
    }

    // MARK: The two halves of the custody self-rule

    /// After a real durable custody commit on somebody else's item, this device advertises ITSELF as
    /// a custody signer — even though its own receipt is never stored (it is re-minted from the
    /// witness). Without this half a custody transfer is invisible and the origin never learns who
    /// is holding the item.
    @Test func ourOwnCustodyOfAnotherOriginsItemAppearsEvenThoughItIsNotStored() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        MeshRoutedCustodyFixtures.stageAll(rig)
        #expect(MeshRoutedCustodyFixtures.witness(MeshRoutedCustodyFixtures.commit(rig)) != nil)
        let index = try #require(MeshRoutedCustodyFixtures.loadedIndex(rig.store))
        let me = rig.custodian.localFingerprint

        let stored = try #require(index.record(for: rig.key))
        #expect(stored.isCustodied)
        #expect(stored.receipts.isEmpty, "this device's OWN custody receipt is never stored")

        let digest = try Self.inventory(index, selfFingerprint: me)
        let entry = try #require(digest.entries.first)
        let signers = entry.custodySigners.map { digest.members[Int($0)] }
        #expect(signers == [me])
        #expect(digest.isWellFormed)
    }

    /// The other half: an origin never advertises custody of its own item.
    ///
    /// Pure index, so both halves are contrasted in one value: a record originated ELSEWHERE and
    /// custodied names this device, and a self-authored one custodied names nobody.
    @Test func weNeverAdvertiseCustodyOfOurOwnItem() throws {
        let mine = Self.record(
            origin: Self.me, itemID: MeshRoutedInventoryFixtures.itemID,
            custodiedAt: MeshRoutedManifestFixtures.base
        )
        let theirs = Self.record(
            origin: "fp001", itemID: MeshRoutedInventoryFixtures.parkedItemID,
            custodiedAt: MeshRoutedManifestFixtures.base
        )
        let digest = try Self.inventory(MeshRoutedIndex(items: [mine, theirs]))

        let ours = try #require(digest.entries.first { digest.key(of: $0)?.originFingerprint == Self.me })
        let other = try #require(digest.entries.first { digest.key(of: $0)?.originFingerprint == "fp001" })
        #expect(ours.custodySigners.isEmpty, "an origin issues itself no custody receipt")
        #expect(other.custodySigners.map { digest.members[Int($0)] } == [Self.me])
        #expect(digest.isWellFormed)
    }

    /// And the reason, asserted rather than commented: for a self-authored item the receipt a peer
    /// would then ask for is **unmintable**, so advertising custody of it would leave the peer asking
    /// forever.
    @Test func theReceiptForOurOwnItemIsUnmintableWhichIsWhyWeNeverAdvertiseIt() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let members = try MeshDeliveryFixtures.rig(memberCount: 3)
        let me = try #require(members.identities[members.fingerprints[0]])
        let payload = MeshRoutedCustodyFixtures.blob(byteCount: 1_024)
        let manifest = try MeshRoutedManifest.signed(
            meshID: members.meshID,
            target: MeshDeliveryTarget(
                contentID: UUID(), roster: members.roster, selfFingerprint: me.localFingerprint
            ),
            typeToken: MeshRoutedManifestFixtures.typeToken,
            contentHash: MeshRoutedContentDigest.contentHash(of: payload),
            size: UInt64(payload.count),
            createdAt: MeshRoutedManifestFixtures.createdAt,
            hardDeadline: MeshRoutedManifestFixtures.hardDeadline,
            contentKey: Data(repeating: 0x33, count: 32),
            recipientKeys: members.identities.mapValues(\.localKeyAgreementPublicKey),
            identity: me
        )
        let store = MeshRoutedStore(scope: scope)
        PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            #expect(store.admittingManifest(manifest, now: Fixture.now).value != nil)
            for chunk in (try? MeshChunker.chunks(of: payload, for: manifest, identity: me)) ?? [] {
                #expect(store.stagingChunk(chunk, now: Fixture.now).value != nil)
            }
        }
        let committed = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            store.committingCustody(
                item: MeshRoutedItemKey(manifest), custodian: me.localFingerprint, now: Fixture.now
            )
        }
        let witness = try #require(MeshRoutedCustodyFixtures.witness(committed), "\(committed)")
        #expect(throws: MeshCustodyReceiptMintError.originIsSelf) {
            _ = try MeshCustodyReceipt.signed(witness: witness, manifest: manifest, identity: me)
        }

        let index = try #require(MeshRoutedCustodyFixtures.loadedIndex(store))
        let digest = try Self.inventory(index, selfFingerprint: me.localFingerprint)
        let entry = try #require(digest.entries.first)
        #expect(entry.isComplete)
        #expect(entry.custodySigners.isEmpty, "custodied, complete, and still never advertised")
    }

    // MARK: Evidence doors

    @Test func aPeersCustodyReceiptAppearsAsACustodySigner() throws {
        let peerReceipt = MeshCustodyReceiptFixtures.receipt()
        let index = MeshRoutedIndex(items: [
            Self.record(itemID: MeshRoutedInventoryFixtures.itemID, receipts: [peerReceipt])
        ])

        let digest = try Self.inventory(index)
        let entry = try #require(digest.entries.first)
        let signers = entry.custodySigners.map { digest.members[Int($0)] }
        #expect(signers == [peerReceipt.custodianFingerprint])
        #expect(entry.recipientSigners.isEmpty)
        #expect(digest.isWellFormed)
    }

    /// The "delivered" evidence door: a recipient receipt IS delivery state, so the digest needs no
    /// field of its own for it.
    @Test func aPeersRecipientReceiptAppearsAsARecipientSigner() throws {
        let peerReceipt = MeshRecipientReceiptFixtures.receipt()
        let index = MeshRoutedIndex(items: [
            Self.record(itemID: MeshRoutedInventoryFixtures.itemID, recipientReceipts: [peerReceipt])
        ])

        let digest = try Self.inventory(index)
        let entry = try #require(digest.entries.first)
        let signers = entry.recipientSigners.map { digest.members[Int($0)] }
        #expect(signers == [peerReceipt.recipientFingerprint])
        #expect(entry.custodySigners.isEmpty)
    }

    /// This device's OWN recipient receipt IS stored, unlike its custody receipt — so it needs no
    /// self-rule, and the digest must show it after a real delivery ladder.
    @Test func ourOwnRecipientReceiptAppearsAsARecipientSigner() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope, typeToken: MeshRoutedTypeToken.photo)
        let receipt = try MeshRoutedCustodyFixtures.recipientReceipt(rig)
        let index = try #require(MeshRoutedCustodyFixtures.loadedIndex(rig.store))
        let me = rig.custodian.localFingerprint

        let digest = try Self.inventory(index, selfFingerprint: me)
        let entry = try #require(digest.entries.first)
        let signers = entry.recipientSigners.map { digest.members[Int($0)] }
        #expect(signers == [receipt.recipientFingerprint])
        #expect(receipt.recipientFingerprint == me)
    }

    // MARK: What is advertised, and what is not

    /// A parked item is advertised WITHOUT a manifest, never hidden — it is how a parked device
    /// asks its way to one.
    @Test func aParkedItemIsAdvertisedWithoutAManifest() throws {
        let index = MeshRoutedIndex(items: [Self.record(chunkCount: 2, heldIndices: [0])])

        let digest = try Self.inventory(index)
        let entry = try #require(digest.entries.first)
        #expect(entry.holdsManifest == false)
        #expect(entry.heldChunks == Data([0x01]))
        #expect(entry.custodySigners.isEmpty, "a parked record can hold no receipts")
        #expect(entry.recipientSigners.isEmpty)
    }

    /// An item whose stored delivery map will not restore is HELD, so it is advertised — even though
    /// no delivery enumerator can name its destinations.
    @Test func anItemWithAnUnrestorableDeliveryMapIsStillAdvertised() throws {
        let manifest = MeshRoutedManifestFixtures.manifest()
        let unrestorable = MeshRoutedDeliveryRecord(
            contentID: manifest.itemID,
            progress: ["fp404": MeshRoutedDeliveryProgress(token: "custodied", custodian: "fp002")]
        )
        let index = MeshRoutedIndex(items: [
            Self.record(
                origin: manifest.originFingerprint, itemID: manifest.itemID, chunkCount: 1,
                heldIndices: [0], manifest: manifest, delivery: unrestorable
            )
        ])
        let key = MeshRoutedItemKey(manifest)
        #expect(index.itemsWithUnrestorableDelivery(at: Self.now).map(\.key) == [key])
        #expect(index.outstandingItems(at: Self.now, in: MeshMembershipLedger.empty.derivedRoster).isEmpty)

        let digest = try Self.inventory(index)
        #expect(digest.entries.count == 1)
        #expect(digest.key(of: try #require(digest.entries.first)) == key)
    }

    /// The one filter, and the reason for it: two peers sweeping expiries at different moments must
    /// not differ forever.
    @Test func anExpiredItemIsAbsent() throws {
        let live = Self.record(origin: "fp001", chunkCount: 1, heldIndices: [0])
        let dead = Self.record(
            origin: "fp002", chunkCount: 1, heldIndices: [0],
            expiresAt: Self.now.addingTimeInterval(-1)
        )
        let index = MeshRoutedIndex(items: [live, dead])

        let digest = try Self.inventory(index)
        #expect(digest.entries.count == 1)
        #expect(digest.members == ["fp001"], "an expired item's origin leaves the member table too")
    }

    // MARK: The table, the order and determinism

    @Test func theMemberTableIsExactlyTheReferencedSetSorted() throws {
        let index = MeshRoutedIndex(items: [
            Self.record(origin: "fp005", receipts: [MeshCustodyReceiptFixtures.receipt()]),
            Self.record(origin: "fp001", recipientReceipts: [MeshRecipientReceiptFixtures.receipt()])
        ])

        let digest = try Self.inventory(index)
        #expect(digest.members == ["fp001", "fp002", "fp004", "fp005"])
        #expect(digest.isWellFormed, "the table must be sorted, distinct AND minimal")
    }

    @Test func entryOrderEqualsTheIndexOrder() throws {
        let index = MeshRoutedIndex(items: [
            Self.record(origin: "fp003", itemID: MeshRoutedInventoryFixtures.parkedItemID),
            Self.record(origin: "fp001", itemID: MeshRoutedInventoryFixtures.itemID),
            Self.record(origin: "fp001", itemID: MeshRoutedInventoryFixtures.parkedItemID)
        ])

        let digest = try Self.inventory(index)
        let keys = try digest.entries.map { try #require(digest.key(of: $0)) }
        #expect(keys == index.items.map(\.key))
        #expect(digest.isWellFormed)
    }

    @Test func twoBuildsFromTheSameInputsAreEqual() throws {
        let index = MeshRoutedIndex(items: [
            Self.record(origin: "fp001", itemID: MeshRoutedInventoryFixtures.itemID),
            Self.record(origin: "fp002", itemID: MeshRoutedInventoryFixtures.parkedItemID)
        ])
        #expect(try Self.inventory(index) == (try Self.inventory(index)))
    }

    /// Read-only, asserted with the file-system spy rather than by inspection.
    @Test func buildingWritesNothing() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        try Fixture.save(MeshRoutedIndex(items: [Self.record()]), into: store)
        let index = try #require(MeshRoutedCustodyFixtures.loadedIndex(store))
        let before = Fixture.snapshot(scope)

        _ = try Self.inventory(index)

        #expect(Fixture.snapshot(scope) == before, "building a digest wrote to the store")
    }

    @Test func aDigestSurvivesASaveLoadRoundTrip() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshRoutedStore(scope: scope)
        let index = MeshRoutedIndex(items: [
            Self.record(origin: "fp001", itemID: MeshRoutedInventoryFixtures.itemID,
                        chunkCount: 4, heldIndices: [0, 2]),
            Self.record(origin: "fp004", itemID: MeshRoutedInventoryFixtures.parkedItemID,
                        chunkCount: 2, heldIndices: [1])
        ])
        let before = try Self.inventory(index)
        try Fixture.save(index, into: store)
        let reloaded = try #require(MeshRoutedCustodyFixtures.loadedIndex(store))

        #expect(try Self.inventory(reloaded) == before)
    }

    // MARK: The exact held set

    @Test func partialHoldingsReportTheExactHeldSet() throws {
        let index = MeshRoutedIndex(items: [Self.record(chunkCount: 4, heldIndices: [0, 2])])

        let entry = try #require(try Self.inventory(index).entries.first)
        #expect(entry.heldChunks == Data([0b0000_0101]))
        #expect(entry.heldChunkCount == 2)
        #expect(entry.holdsChunk(1) == false)
        #expect(entry.isComplete == false)
    }

    /// The D-5.14 regression, pinned at the builder as well as at the delta: a repaired hole is a
    /// MISSING BIT, and a count-only summary would tie with a peer holding a different pair.
    @Test func aRepairedHoleIsVisibleInTheBitmap() throws {
        let whole = MeshRoutedIndex(items: [Self.record(chunkCount: 4, heldIndices: [0, 1, 2])])
        let repaired = MeshRoutedIndex(items: [Self.record(chunkCount: 4, heldIndices: [0, 2])])
        let peer = MeshRoutedIndex(items: [Self.record(chunkCount: 4, heldIndices: [0, 1])])

        let before = try #require(try Self.inventory(whole).entries.first)
        let after = try #require(try Self.inventory(repaired).entries.first)
        let theirs = try #require(try Self.inventory(peer).entries.first)

        #expect(before.heldChunkCount == 3)
        #expect(after.heldChunks == Data([0b0000_0101]))
        #expect(after.heldChunkCount == theirs.heldChunkCount, "the counts tie…")
        #expect(after.heldChunks != theirs.heldChunks, "…and the SETS do not, which is the whole point")
    }

    /// A descriptor with no slot in the item the origin signed has no canonical bit, so it is
    /// skipped rather than breaking the trailing-zero rule the comparison rests on.
    @Test func aChunkIndexAboveTheDeclaredCountIsNotAdvertised() throws {
        let index = MeshRoutedIndex(items: [Self.record(chunkCount: 2, heldIndices: [0, 7])])

        let entry = try #require(try Self.inventory(index).entries.first)
        #expect(entry.heldChunks == Data([0x01]))
        #expect(MeshRoutedInventoryEntry.bitmapIsCanonical(entry.heldChunks, for: entry.chunkCount))
    }

    /// A planted at-rest `chunkCount` never becomes an allocation size.
    ///
    /// The claim is about the **memberwise** path, which stays deliberately unguarded: the doors own
    /// the caps, and the handoff/claim appliers only replace records already present. (P5 item 9 added
    /// the fourth at-rest sibling, `capacityExceeded("chunkCount")`, so this value can no longer
    /// arrive by DECODING one of our own sealed files — but `MeshRoutedIndex(items:)` still admits
    /// it, and the builder is the first consumer that turns it into a byte count: a bare `UInt32`
    /// would size a half-gigabyte `Data` before any shape check ran.) The bitmap comes back **empty**
    /// rather than clamped, so the built inventory refuses its own shape check: the honest answer for
    /// malformed durable state, and the same one a planted zero already gets.
    @Test func aChunkCountAboveTheCapIsNeverTurnedIntoABitmapAllocation() throws {
        let planted = Self.record(chunkCount: UInt32.max, heldIndices: [])
        let index = MeshRoutedIndex(items: [planted])

        let digest = try Self.inventory(index)
        let entry = try #require(digest.entries.first)
        #expect(entry.chunkCount == UInt32.max, "the record's own value is carried verbatim")
        #expect(entry.heldChunks.isEmpty)
        #expect(digest.isWellFormed == false, "an out-of-range chunk count is refused, not repaired")

        let zeroed = try Self.inventory(MeshRoutedIndex(items: [Self.record(chunkCount: 0, heldIndices: [])]))
        let zeroedEntry = try #require(zeroed.entries.first)
        #expect(zeroedEntry.heldChunks.isEmpty)
        #expect(zeroed.isWellFormed == false)
    }
}
