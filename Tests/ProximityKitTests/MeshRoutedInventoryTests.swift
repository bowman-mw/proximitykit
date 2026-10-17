// MeshRoutedInventoryTests.swift
// ProximityKitTests
//
// P5 item 5 (plan §11, §10.3): the ROUTED CONTENT digest — the fifth routed wire family, and the
// one that says what a device is holding rather than what it received.
//
// Four claims are walled here, each a thing a later item cannot cheaply re-derive:
//
// 1. **The signed bytes are pinned.** `goldenRoutedInventoryHex` was derived from the FORMAT by an
//    independent Python re-implementation that first reproduced ALL EIGHT prior vectors —
//    `goldenInventoryHex`, `goldenEpochHeadsHex`, `goldenRoutedManifestHex`, `goldenRoutedChunkHex`,
//    `goldenCustodyReceiptHex`, `goldenCustodyReceiptIDHex`, `goldenRecipientReceiptHex` and
//    `goldenRecipientReceiptIDHex` — byte-for-byte. The frame is additive: nothing above it moves.
// 2. **The two digest families do not collide.** `MeshInventoryDigest` summarises a MEMBERSHIP
//    ledger; this summarises a routed STORE. The wire spellings deliberately share the
//    `inventory-digest` stem, so `grep` is NOT decisive — what is decisive is the value-type stems,
//    asserted clause by clause below.
// 3. **An over-cap or non-canonical digest is REFUSED BY NAME, never repaired.** Clamping a count
//    loses precision; clamping a *list* silently claims not to hold something, and repairing an
//    order would make the refusal unreachable and set equality meaningless.
// 4. **The advertiser signs, and D14 holds.** A departed advertiser's digest still verifies (it may
//    still hold custody inside the development grace); a quorum-removed one does not.
//
// Nothing here sleeps or reads a wall clock for a decision.
//
// A partial copy (ProximityKit plan step A1, the split's first batch of copied suites): of the
// Fernlet repository's FernletTests file of the same name, this holds only
// `MeshRoutedInventoryShapeTests` and, since ProximityKit plan step A1's third batch of copied suites
// (those that reach the keychain and open a store), `MeshRoutedInventorySigningTests` and
// `MeshRoutedInventoryVerifierTests`, with their names and tests unchanged, and the fixtures the
// package's copied suites read (`MeshRoutedInventoryFixtures`, `extension
// MeshRoutedInventoryEntry`, `extension MeshRoutedInventory`, `extension
// MeshRoutedInventoryPayload`, `MeshRoutedInventoryShapeFault`, `MeshRoutedInventoryCapFault` and
// `MeshRoutedInventoryTamper`); its golden suite stays there, so what this header says of it is not
// held here.

import Foundation
import Testing
@testable import ProximityKit

// MARK: - Fixtures

/// Fixed values for the routed-inventory golden vector — every pinned byte traces to a line here;
/// nothing reads a clock. `meshID` and the first `itemID` are item 1's own, so the vector reads
/// beside the manifest, chunk and receipt vectors as one story.
enum MeshRoutedInventoryFixtures {

    static let meshID = MeshRoutedManifestFixtures.meshID
    static let base = MeshRoutedManifestFixtures.base
    static let opaqueSignature = MeshMembershipEventFixtures.opaqueSignature

    /// The item the manifest, chunk and both receipt vectors are about — held complete here.
    static let itemID = MeshRoutedManifestFixtures.itemID

    /// A second item, held PARKED (chunks, no manifest) so the vector carries both shapes.
    static let parkedItemID = UUID(uuidString: "6B6B6B6B-7C7C-4E4E-9F9F-4A4A4A4A4A4A") ?? UUID()

    /// The ADVERTISER — the device whose disk the digest describes.
    static let senderFingerprint = "fp001"

    /// `base + 720` — the next free fixture offset (+60 … +660 are taken by items 1–4, +600 by
    /// `MeshRoutedStoreFixtures.now`).
    static let sentAt = base.addingTimeInterval(720)

    /// The minimal fingerprint table: the first item's origin and the second's, the latter also
    /// being the first item's custody signer.
    static let members = ["fp001", "fp004"]

    /// The complete, manifest-bound item: 3 chunks, all held (`0b0000_0111`), one custody signer.
    static func completeEntry() -> MeshRoutedInventoryEntry {
        MeshRoutedInventoryEntry(
            originIndex: 0, itemID: itemID, holdsManifest: true, chunkCount: 3,
            heldChunks: Data([0x07]), custodySigners: [1], recipientSigners: []
        )
    }

    /// The parked item: 2 chunks, index 0 only (`0b0000_0001`), and — as a parked record always
    /// must — empty signer lists.
    static func parkedEntry() -> MeshRoutedInventoryEntry {
        MeshRoutedInventoryEntry(
            originIndex: 1, itemID: parkedItemID, holdsManifest: false, chunkCount: 2,
            heldChunks: Data([0x01]), custodySigners: [], recipientSigners: []
        )
    }

    /// The golden inventory.
    static func inventory() -> MeshRoutedInventory {
        MeshRoutedInventory(meshID: meshID, members: members, entries: [completeEntry(), parkedEntry()])
    }

    /// The golden payload, built from already-"signed" parts through the memberwise init.
    static func payload() -> MeshRoutedInventoryPayload {
        MeshRoutedInventoryPayload(
            inventory: inventory(), senderFingerprint: senderFingerprint,
            sentAt: sentAt, signature: opaqueSignature
        )
    }

    static func hex(_ data: Data) -> String {
        MeshMembershipEventFixtures.hex(data)
    }

    /// A synthetic maximal inventory: `maxEntries` entries, `maxReferencedMembers` members, both
    /// signer lists at their caps, and the widest bitmap. Shape is not asserted — only size is.
    static func maximalInventory() -> MeshRoutedInventory {
        let table = (0..<MeshRoutedInventoryFormat.maxReferencedMembers).map { "fp\(String(format: "%03d", $0))" }
        let custody = (0..<MeshRoutedInventoryFormat.maxCustodySignersPerEntry).map { UInt8($0) }
        let recipient = (0..<MeshRoutedInventoryFormat.maxRecipientSignersPerEntry).map { UInt8($0) }
        let widest = Data(repeating: 0xFF, count: MeshRoutedInventoryFormat.maxHeldChunkBitmapBytes)
        let entries = (0..<MeshRoutedInventoryFormat.maxEntries).map { position in
            MeshRoutedInventoryEntry(
                originIndex: UInt8(position % MeshRoutedInventoryFormat.maxReferencedMembers),
                itemID: UUID(), holdsManifest: true,
                chunkCount: UInt32(MeshRoutedInventoryFormat.maxChunkCount),
                heldChunks: widest, custodySigners: custody, recipientSigners: recipient
            )
        }
        return MeshRoutedInventory(meshID: meshID, members: table, entries: entries)
    }
}

// MARK: - Test-only rebuilders

extension MeshRoutedInventoryEntry {
    /// Test-only: a copy with the named fields replaced, through the verbatim memberwise init.
    func replacing(
        originIndex: UInt8? = nil,
        itemID: UUID? = nil,
        holdsManifest: Bool? = nil,
        chunkCount: UInt32? = nil,
        heldChunks: Data? = nil,
        custodySigners: [UInt8]? = nil,
        recipientSigners: [UInt8]? = nil
    ) -> MeshRoutedInventoryEntry {
        MeshRoutedInventoryEntry(
            originIndex: originIndex ?? self.originIndex,
            itemID: itemID ?? self.itemID,
            holdsManifest: holdsManifest ?? self.holdsManifest,
            chunkCount: chunkCount ?? self.chunkCount,
            heldChunks: heldChunks ?? self.heldChunks,
            custodySigners: custodySigners ?? self.custodySigners,
            recipientSigners: recipientSigners ?? self.recipientSigners
        )
    }
}

extension MeshRoutedInventory {
    /// Test-only: a copy with the named fields replaced, through the verbatim memberwise init.
    func replacing(
        meshID: UUID? = nil, members: [String]? = nil, entries: [MeshRoutedInventoryEntry]? = nil
    ) -> MeshRoutedInventory {
        MeshRoutedInventory(
            meshID: meshID ?? self.meshID,
            members: members ?? self.members,
            entries: entries ?? self.entries
        )
    }
}

extension MeshRoutedInventoryPayload {
    /// Test-only: a copy with the named fields replaced, through the flooring memberwise init.
    func replacing(
        inventory: MeshRoutedInventory? = nil,
        senderFingerprint: String? = nil,
        sentAt: Date? = nil,
        signature: Data? = nil
    ) -> MeshRoutedInventoryPayload {
        MeshRoutedInventoryPayload(
            inventory: inventory ?? self.inventory,
            senderFingerprint: senderFingerprint ?? self.senderFingerprint,
            sentAt: sentAt ?? self.sentAt,
            signature: signature ?? self.signature
        )
    }
}

/// One non-canonical encoding per case — each a refusal, never a repair.
enum MeshRoutedInventoryShapeFault: String, CaseIterable, Sendable {
    case unsortedMembers, duplicateMember, unreferencedMember, emptyMemberFingerprint
    case originIndexOutOfRange, signerIndexOutOfRange, unsortedSignerList, duplicateSignerIndex
    case duplicateEntry, entriesOutOfCanonicalOrder
    case chunkCountZero, chunkCountAboveTheCap
    case bitmapOneByteShort, bitmapOneByteLong, bitSetAboveTheChunkCount

    /// The golden inventory with this one fault applied through the verbatim memberwise init.
    func applied(to base: MeshRoutedInventory) -> MeshRoutedInventory {
        if let members = replacementMembers(base) { return base.replacing(members: members) }
        return base.replacing(entries: replacementEntries(base))
    }

    /// The member-table faults, or nil when this case rewrites entries instead.
    private func replacementMembers(_ base: MeshRoutedInventory) -> [String]? {
        switch self {
        case .unsortedMembers: return base.members.reversed()
        case .duplicateMember: return [base.members[0], base.members[0]]
        case .unreferencedMember: return base.members + ["fp009"]
        case .emptyMemberFingerprint: return ["", base.members[1]]
        default: return nil
        }
    }

    /// The entry faults.
    private func replacementEntries(_ base: MeshRoutedInventory) -> [MeshRoutedInventoryEntry] {
        let first = base.entries[0]
        let second = base.entries[1]
        switch self {
        case .originIndexOutOfRange: return [first.replacing(originIndex: 9), second]
        case .signerIndexOutOfRange: return [first.replacing(custodySigners: [9]), second]
        case .unsortedSignerList: return [first.replacing(custodySigners: [1, 0]), second]
        case .duplicateSignerIndex: return [first.replacing(custodySigners: [1, 1]), second]
        case .duplicateEntry: return [first, first]
        case .entriesOutOfCanonicalOrder: return [second, first]
        case .chunkCountZero: return [first.replacing(chunkCount: 0, heldChunks: Data()), second]
        case .chunkCountAboveTheCap:
            // An over-cap chunk count has no canonical bitmap (its width would be 129 bytes, itself
            // over a cap), so this fault carries a short map: clauses 3 and 4 both fire, and the
            // refusal is `.malformed` rather than `.overCapacity`.
            let over = UInt32(MeshRoutedInventoryFormat.maxChunkCount + 1)
            return [first.replacing(chunkCount: over, heldChunks: Data([0x00])), second]
        case .bitmapOneByteShort: return [first.replacing(heldChunks: Data()), second]
        case .bitmapOneByteLong: return [first.replacing(heldChunks: Data([0x07, 0x00])), second]
        case .bitSetAboveTheChunkCount: return [first.replacing(heldChunks: Data([0x0F])), second]
        default: return base.entries
        }
    }
}

/// One over-cap collection per case — each `.overCapacity` **by name**, and distinct from
/// `.malformed`: the two refusals mean different things and a single boolean would blur them.
enum MeshRoutedInventoryCapFault: String, CaseIterable, Sendable {
    case tooManyEntries, tooManyMembers, tooManyCustodySigners, tooManyRecipientSigners
    case overLongMemberFingerprint

    /// The golden inventory with this one cap broken.
    func applied(to base: MeshRoutedInventory) -> MeshRoutedInventory {
        switch self {
        case .tooManyEntries:
            let entries = (0...MeshRoutedInventoryFormat.maxEntries).map { _ in
                base.entries[0].replacing(itemID: UUID())
            }
            return base.replacing(entries: entries)
        case .tooManyMembers:
            let table = (0...MeshRoutedInventoryFormat.maxReferencedMembers)
                .map { "fp\(String(format: "%03d", $0))" }
            return base.replacing(members: table)
        case .tooManyCustodySigners:
            let signers = (0...MeshRoutedInventoryFormat.maxCustodySignersPerEntry).map { UInt8($0) }
            return base.replacing(entries: [base.entries[0].replacing(custodySigners: signers)])
        case .tooManyRecipientSigners:
            let signers = (0...MeshRoutedInventoryFormat.maxRecipientSignersPerEntry).map { UInt8($0) }
            return base.replacing(entries: [base.entries[0].replacing(recipientSigners: signers)])
        case .overLongMemberFingerprint:
            let wide = String(repeating: "f", count: MeshRoutedInventoryFormat.maxFingerprintLength + 1)
            return base.replacing(members: [base.members[0], wide])
        }
    }
}

/// One SIGNED field per case; every case must land on `.signatureInvalid` and nothing else.
///
/// `meshID` is deliberately absent — it has an earlier, differently named refusal (`foreignMesh`),
/// which is the point of checking the cheap ones first.
enum MeshRoutedInventoryTamper: String, CaseIterable, Sendable {
    case memberFingerprint, heldChunkBitmap, chunkCount, signerIndex, holdsManifest
    case senderFingerprint, sentAt, signatureByte

    /// A minted payload with this one field changed. `otherAdmitted` is a real admitted member, so
    /// the sender substitution still reaches the signature check.
    func applied(to payload: MeshRoutedInventoryPayload, otherAdmitted: String) -> MeshRoutedInventoryPayload {
        if let inventory = tamperedInventory(payload.inventory) {
            return payload.replacing(inventory: inventory)
        }
        switch self {
        case .senderFingerprint: return payload.replacing(senderFingerprint: otherAdmitted)
        case .sentAt: return payload.replacing(sentAt: payload.sentAt.addingTimeInterval(-60))
        case .signatureByte:
            var signature = payload.signature
            signature[signature.startIndex] ^= 0x01
            return payload.replacing(signature: signature)
        default: return payload
        }
    }

    /// The inventory-side tampers, or nil when this case rewrites a payload scalar instead.
    private func tamperedInventory(_ inventory: MeshRoutedInventory) -> MeshRoutedInventory? {
        let first = inventory.entries[0]
        switch self {
        case .memberFingerprint:
            return inventory.replacing(members: inventory.members.map { $0 + "z" })
        case .heldChunkBitmap:
            return inventory.replacing(entries: [first.replacing(heldChunks: Data([0x03]))]
                                       + inventory.entries.dropFirst())
        case .chunkCount:
            return inventory.replacing(entries: [first.replacing(chunkCount: 2, heldChunks: Data([0x03]))]
                                       + inventory.entries.dropFirst())
        case .signerIndex:
            // Flip rather than assign: the minted fixture's signer lists are empty, and assigning
            // the value a field already holds is not a tamper at all.
            let signers: [UInt8] = first.custodySigners.isEmpty ? [0] : []
            return inventory.replacing(entries: [first.replacing(custodySigners: signers)]
                                       + inventory.entries.dropFirst())
        case .holdsManifest:
            return inventory.replacing(entries: [first.replacing(holdsManifest: !first.holdsManifest)]
                                       + inventory.entries.dropFirst())
        default: return nil
        }
    }
}

// MARK: - Shape

/// The untrusted-bytes half: one non-canonical encoding per case, refused and never repaired, and
/// the two caps that are deliberately different numbers.
@Suite(.serialized)
struct MeshRoutedInventoryShapeTests {

    /// A verifier whose ledger knows nobody: the caps and shape steps run before any lookup, so a
    /// well-formed payload reaches `.senderNotAdmitted` and a broken one does not.
    private func door() -> MeshRoutedInventoryVerifier {
        MeshRoutedInventoryVerifier(meshID: MeshRoutedInventoryFixtures.meshID, ledger: .empty)
    }

    @Test func theGoldenFixtureIsCanonical() {
        let inventory = MeshRoutedInventoryFixtures.inventory()
        #expect(inventory.isWithinCaps)
        #expect(inventory.isWellFormed)
        #expect(MeshRoutedInventoryFixtures.payload().isWellFormed)
        #expect(door().verify(MeshRoutedInventoryFixtures.payload()) == .senderNotAdmitted)
    }

    @Test(arguments: MeshRoutedInventoryShapeFault.allCases)
    func everyShapeFaultIsMalformed(fault: MeshRoutedInventoryShapeFault) {
        let broken = fault.applied(to: MeshRoutedInventoryFixtures.inventory())
        #expect(broken.isWellFormed == false, "\(fault)")
        let payload = MeshRoutedInventoryFixtures.payload().replacing(inventory: broken)
        #expect(door().verify(payload) == .malformed, "\(fault)")
    }

    @Test(arguments: MeshRoutedInventoryCapFault.allCases)
    func everyCapFaultIsOverCapacityByName(fault: MeshRoutedInventoryCapFault) {
        let broken = fault.applied(to: MeshRoutedInventoryFixtures.inventory())
        #expect(broken.isWithinCaps == false, "\(fault)")
        let payload = MeshRoutedInventoryFixtures.payload().replacing(inventory: broken)
        #expect(door().verify(payload) == .overCapacity, "\(fault)")
    }

    /// A decode repairs nothing: a mis-ordered or over-cap value survives the wire unchanged, which
    /// is what makes the refusal reachable at the verifier rather than unreachable behind a clamp.
    @Test func aDecodeNeitherSortsNorClampsNorRepairs() throws {
        let unordered = MeshRoutedInventoryShapeFault.entriesOutOfCanonicalOrder
            .applied(to: MeshRoutedInventoryFixtures.inventory())
        let wire = try JSONEncoder().encode(unordered)
        let decoded = try JSONDecoder().decode(MeshRoutedInventory.self, from: wire)
        #expect(decoded == unordered)
        #expect(decoded.entries.map(\.originIndex) == [1, 0])
        #expect(decoded.isWellFormed == false)
    }

    /// The two payload scalars no door clamps, checked BEFORE the ledger lookup.
    @Test func aWrongWidthSignatureIsMalformed() {
        let narrow = MeshRoutedInventoryFixtures.payload()
            .replacing(signature: Data(repeating: 0xAB, count: 63))
        #expect(narrow.isWellFormed == false)
        #expect(door().verify(narrow) == .malformed)
    }

    @Test func anEmptyOrOverLongSenderFingerprintIsMalformed() {
        let empty = MeshRoutedInventoryFixtures.payload().replacing(senderFingerprint: "")
        let wide = MeshRoutedInventoryFixtures.payload().replacing(
            senderFingerprint: String(repeating: "s", count: MeshRoutedInventoryFormat.maxFingerprintLength + 1)
        )
        #expect(empty.isWellFormed == false)
        #expect(wide.senderFingerprint.utf8.count
                == MeshRoutedInventoryFormat.maxFingerprintLength + 1, "the door must NOT clamp the scalar")
        #expect(wide.isWellFormed == false)
        #expect(door().verify(empty) == .malformed)
        #expect(door().verify(wide) == .malformed)
    }

    /// The bitmap's frozen bit order and its derived reads, for every width shape.
    @Test func theBitmapIsCanonicalForEveryChunkCount() {
        for count in [1, 7, 8, 9, MeshRoutedInventoryFormat.maxChunkCount] {
            let width = MeshRoutedInventoryEntry.bitmapByteCount(forChunkCount: UInt32(count))
            #expect(width == (count + 7) / 8, "\(count)")
            let full = Data((0..<width).map { byte in
                var value: UInt8 = 0
                for bit in 0..<8 where byte * 8 + bit < count { value |= UInt8(1) << UInt8(bit) }
                return value
            })
            #expect(MeshRoutedInventoryEntry.bitmapIsCanonical(full, for: UInt32(count)), "\(count)")
            let entry = MeshRoutedInventoryFixtures.completeEntry()
                .replacing(chunkCount: UInt32(count), heldChunks: full)
            #expect(entry.heldChunkCount == count, "\(count)")
            #expect(entry.isComplete, "\(count)")
        }
    }

    /// The reads the delta depends on, over a hole-punched set: `{0, 2}` of 4.
    @Test func partialHoldingsReportTheExactHeldSet() {
        let entry = MeshRoutedInventoryFixtures.completeEntry()
            .replacing(chunkCount: 4, heldChunks: Data([0b0000_0101]))
        #expect(entry.heldChunkCount == 2)
        #expect(entry.isComplete == false)
        #expect(entry.holdsChunk(0))
        #expect(entry.holdsChunk(1) == false)
        #expect(entry.holdsChunk(2))
        #expect(entry.holdsChunk(3) == false)
        #expect(entry.holdsChunk(9) == false, "an index past the map is not held, never a crash")
    }
}

// MARK: - Minting

/// The mint: real provisioned identities, the one named refusal, and the re-mint stability every
/// signed record in this family owes.
@MainActor
@Suite(.serialized)
struct MeshRoutedInventorySigningTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer
    /// has run before a cell's identities or stores reach the keychain.
    let keychain = PackageTestEnvironment.keychain

    /// A rig plus a two-item index, built from synthetic records so no store is needed.
    private func rigAndIndex() throws -> (rig: MeshDeliveryRig, index: MeshRoutedIndex) {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 3)
        let index = MeshRoutedIndex(items: [
            MeshRoutedStoreFixtures.record(
                origin: "fp001", itemID: MeshRoutedInventoryFixtures.itemID,
                chunkCount: 3,
                chunks: (0..<3).map { MeshRoutedStoreFixtures.descriptor(index: $0, count: 3, bytes: 16) }
            ),
            MeshRoutedStoreFixtures.record(
                origin: "fp004", itemID: MeshRoutedInventoryFixtures.parkedItemID,
                chunkCount: 2,
                chunks: [MeshRoutedStoreFixtures.descriptor(index: 0, count: 2, bytes: 16)]
            )
        ])
        return (rig, index)
    }

    /// The minted payload for `rig`'s first member.
    private func mint(
        _ rig: MeshDeliveryRig, _ index: MeshRoutedIndex, sentAt: Date? = nil
    ) throws -> MeshRoutedInventoryPayload {
        let advertiser = try #require(rig.identities[rig.fingerprints[0]])
        return try MeshRoutedInventoryPayload.signed(
            meshID: rig.meshID, index: index,
            sentAt: sentAt ?? MeshRoutedInventoryFixtures.sentAt, identity: advertiser
        )
    }

    @Test func aMintedPayloadVerifies() throws {
        let (rig, index) = try rigAndIndex()
        let advertiser = try #require(rig.identities[rig.fingerprints[0]])
        let payload = try mint(rig, index)

        #expect(payload.senderFingerprint == advertiser.localFingerprint)
        #expect(payload.inventory.meshID == rig.meshID)
        #expect(payload.inventory.entries.count == 2)
        #expect(payload.isWithinCaps)
        #expect(payload.isWellFormed)
        #expect(payload.signature.count == MeshRoutedInventoryFormat.signatureByteCount)
        #expect(IdentityService.verify(
            payload.signature, of: canonicalBytes(for: payload),
            by: advertiser.localSigningPublicKey,
            purpose: ProximityNamespace.packageTest.family.purposes.signature.meshRoutedInventoryDigestV1
        ))
        #expect(MeshRoutedInventoryVerifier(meshID: rig.meshID, ledger: rig.ledger).verify(payload) == nil)
    }

    /// **The mint has exactly one spelling of "this device", and it is the signer.**
    ///
    /// The builder's custody self-rule turns "who am I" into an advertised `custodySigners` entry, so
    /// a mint taking a caller-supplied fingerprint *beside* the signing identity could produce a
    /// fully valid, verifiable digest whose custody claim named a member that never held the item.
    /// No receive-side door catches that: `custodySigners` is advertiser-asserted, not signed
    /// evidence, and both fingerprints are legal members. The peer would ask that member for a
    /// custody receipt it can never mint, the ask would re-fire every exchange, and the window item 7
    /// closes on "every asked peer matched" would never close. The signature below is over the
    /// advertiser's own key, and the custody claim resolves to that same fingerprint.
    @Test func theMintTakesItsSelfFingerprintFromTheSignerAndNowhereElse() throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 3)
        let advertiser = try #require(rig.identities[rig.fingerprints[0]])
        let someoneElse = rig.fingerprints[1]
        let index = MeshRoutedIndex(items: [Self.custodiedForAnotherOrigin()])

        let payload = try MeshRoutedInventoryPayload.signed(
            meshID: rig.meshID, index: index,
            sentAt: MeshRoutedInventoryFixtures.sentAt, identity: advertiser
        )
        let entry = try #require(payload.inventory.entries.first)
        let claimed = entry.custodySigners.map { payload.inventory.members[Int($0)] }
        #expect(claimed == [advertiser.localFingerprint])
        #expect(claimed.contains(someoneElse) == false)
        #expect(payload.senderFingerprint == advertiser.localFingerprint)

        let asSomeoneElse = try #require(MeshRoutedInventory(
            meshID: rig.meshID, index: index, selfFingerprint: someoneElse,
            at: MeshRoutedInventoryFixtures.sentAt
        ))
        #expect(payload.inventory != asSomeoneElse, "a second spelling would be advertised here")
        #expect(MeshRoutedInventoryVerifier(meshID: rig.meshID, ledger: rig.ledger).verify(payload) == nil)
    }

    /// A record this device holds custody of for **another** origin — the one state the custody
    /// self-rule reads, planted rather than staged (no store, no files).
    private static func custodiedForAnotherOrigin() -> MeshRoutedItemRecord {
        MeshRoutedItemRecord(
            key: MeshRoutedItemKey(
                originFingerprint: "fp001", itemID: MeshRoutedInventoryFixtures.itemID
            ),
            contentHash: MeshRoutedManifestFixtures.contentHash,
            chunkCount: 1,
            expiresAt: MeshRoutedManifestFixtures.expiresAt,
            manifest: nil,
            firstSeenAt: MeshRoutedManifestFixtures.base,
            custodiedAt: MeshRoutedManifestFixtures.base,
            deliveredAt: nil,
            chunks: [MeshRoutedStoreFixtures.descriptor(index: 0, count: 1, bytes: 16)],
            delivery: nil,
            receipts: [],
            recipientReceipts: []
        )
    }

    /// The builder's one failure, named — and it is a THROW, so a caller has something to log.
    @Test func theMintNamesItsOneRefusal() throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 3)
        let advertiser = try #require(rig.identities[rig.fingerprints[0]])
        let crowded = MeshRoutedIndex(items: (0...MeshRoutedInventoryFormat.maxReferencedMembers).map {
            MeshRoutedStoreFixtures.record(
                origin: "fp\(String(format: "%03d", $0))", itemID: UUID(), chunkCount: 1
            )
        })
        #expect(MeshRoutedInventory(
            meshID: rig.meshID, index: crowded, selfFingerprint: advertiser.localFingerprint,
            at: MeshRoutedInventoryFixtures.sentAt
        ) == nil)

        #expect(throws: MeshRoutedInventoryMintError.tooManyReferencedMembers) {
            _ = try MeshRoutedInventoryPayload.signed(
                meshID: rig.meshID, index: crowded,
                sentAt: MeshRoutedInventoryFixtures.sentAt, identity: advertiser
            )
        }
        #expect(MeshRoutedInventoryMintError.tooManyReferencedMembers.diagnosticDescription.isEmpty == false)
    }

    @Test func sentAtIsFlooredToWholeSeconds() throws {
        let (rig, index) = try rigAndIndex()
        let fractional = try mint(rig, index, sentAt: MeshRoutedInventoryFixtures.sentAt.addingTimeInterval(0.999))
        let whole = try mint(rig, index)

        #expect(fractional.sentAt == MeshRoutedInventoryFixtures.sentAt)
        #expect(canonicalBytes(for: fractional) == canonicalBytes(for: whole))
    }

    /// Two mints of one holdings set are byte-identical up to the hedged signature, and BOTH verify.
    @Test func aReMintIsByteIdenticalExceptTheSignature() throws {
        let (rig, index) = try rigAndIndex()
        let advertiser = try #require(rig.identities[rig.fingerprints[0]])
        let first = try mint(rig, index)
        let second = try mint(rig, index)

        #expect(canonicalBytes(for: first) == canonicalBytes(for: second))
        #expect(first.inventory == second.inventory)
        for signed in [first, second] {
            #expect(IdentityService.verify(
                signed.signature, of: canonicalBytes(for: signed),
                by: advertiser.localSigningPublicKey,
                purpose: ProximityNamespace.packageTest.family.purposes.signature.meshRoutedInventoryDigestV1
            ), "a re-mint must verify on its own signature, never by ==")
        }
    }

    @Test(arguments: MeshRoutedInventoryTamper.allCases)
    func everyTamperedFieldFailsVerification(tamper: MeshRoutedInventoryTamper) throws {
        let (rig, index) = try rigAndIndex()
        let payload = try mint(rig, index)
        let other = try #require(rig.fingerprints.first { $0 != payload.senderFingerprint })
        let tampered = tamper.applied(to: payload, otherAdmitted: other)
        let door = MeshRoutedInventoryVerifier(meshID: rig.meshID, ledger: rig.ledger)
        #expect(door.verify(tampered) == .signatureInvalid, "\(tamper)")
    }

    /// The union-record stance, asserted rather than commented: a digest members must be able to
    /// exchange across a divergent pair is accepted UNSEALED, while a sealing-required type is not.
    @Test func aDigestFrameIsAcceptedUnsealed() throws {
        let members = try MeshDeliveryFixtures.rig(memberCount: 2)
        let names = members.fingerprints
        let sender = try #require(members.identities[names[0]])
        let receiver = try #require(members.identities[names[1]])
        let payload = try JSONEncoder().encode(MeshRoutedInventoryFixtures.payload())
        let base = MeshRoutedInventoryFixtures.base

        let frame = try ProximityIdentityEnvelope.signed(
            identityService: sender, senderDisplayName: "advertiser",
            recipientFingerprint: receiver.localFingerprint,
            payloadType: .meshRoutedInventoryDigest, payloadEncryption: .none,
            payloadSummary: PayloadSummary(title: "digest"), payload: payload, createdAt: base
        )
        let opened = try frame.verify(
            identityService: receiver, replayCache: ReplayCache(dateProvider: { base })
        )
        #expect(opened == payload)

        let control = try ProximityIdentityEnvelope.signed(
            identityService: sender, senderDisplayName: "advertiser",
            recipientFingerprint: receiver.localFingerprint,
            payloadType: .verifyChallenge, payloadEncryption: .none,
            payloadSummary: PayloadSummary(title: "digest"), payload: payload, createdAt: base
        )
        #expect(throws: ProximityIdentityEnvelope.VerifyError.sealingRequired) {
            try control.verify(identityService: receiver, replayCache: ReplayCache(dateProvider: { base }))
        }
    }
}

// MARK: - Verifying

/// The receive door: every rejection reachable and named, D14 in both directions, and the claim the
/// whole frame exists for — a digest that DIFFERS is not a rejection.
@MainActor
@Suite(.serialized)
struct MeshRoutedInventoryVerifierTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer
    /// has run before a cell's identities or stores reach the keychain.
    let keychain = PackageTestEnvironment.keychain

    private func rigAndPayload() throws -> (rig: MeshDeliveryRig, payload: MeshRoutedInventoryPayload) {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 3)
        let advertiser = try #require(rig.identities[rig.fingerprints[0]])
        let index = MeshRoutedIndex(items: [
            MeshRoutedStoreFixtures.record(
                origin: "fp001", itemID: MeshRoutedInventoryFixtures.itemID, chunkCount: 3,
                chunks: (0..<3).map { MeshRoutedStoreFixtures.descriptor(index: $0, count: 3, bytes: 16) }
            )
        ])
        let payload = try MeshRoutedInventoryPayload.signed(
            meshID: rig.meshID, index: index,
            sentAt: MeshRoutedInventoryFixtures.sentAt, identity: advertiser
        )
        return (rig, payload)
    }

    private func door(_ rig: MeshDeliveryRig, ledger: MeshMembershipLedger? = nil) -> MeshRoutedInventoryVerifier {
        MeshRoutedInventoryVerifier(meshID: rig.meshID, ledger: ledger ?? rig.ledger)
    }

    @Test func everyRejectionIsReachable() throws {
        let (rig, payload) = try rigAndPayload()
        #expect(door(rig).verify(payload) == nil)

        let foreign = payload.replacing(inventory: payload.inventory.replacing(meshID: UUID()))
        #expect(door(rig).verify(foreign) == .foreignMesh)

        let overCap = payload.replacing(
            inventory: MeshRoutedInventoryCapFault.tooManyMembers.applied(to: payload.inventory)
        )
        #expect(door(rig).verify(overCap) == .overCapacity)

        let malformed = payload.replacing(signature: Data(repeating: 0x01, count: 63))
        #expect(door(rig).verify(malformed) == .malformed)

        #expect(door(rig).verify(payload.replacing(senderFingerprint: "fp999")) == .senderNotAdmitted)

        // An admission binding the advertiser's fingerprint to somebody else's key.
        let other = try #require(rig.identities[rig.fingerprints[1]])
        let forged = SignedAdmissionRecord(token: try MeshAdmissionToken.signed(
            meshID: rig.meshID,
            joinerFingerprint: payload.senderFingerprint,
            joinerSigningPublicKey: other.localSigningPublicKey,
            admitterIdentity: other,
            grantedAt: MeshMembershipEventFixtures.base
        ))
        let forgedLedger = MeshMembershipLedger(admissions: MeshMembershipRecordSet([forged]))
        #expect(door(rig, ledger: forgedLedger).verify(payload) == .senderKeyMismatch)

        let tampered = payload.replacing(sentAt: payload.sentAt.addingTimeInterval(-60))
        #expect(door(rig).verify(tampered) == .signatureInvalid)
    }

    /// D14, both directions: leaving is not a retraction — a departed advertiser may still be
    /// holding custody inside the development grace, which is what makes a hand-off usable — but a
    /// quorum removal is.
    @Test func aDepartedAdvertiserVerifiesAndAQuorumRemovedOneDoesNot() throws {
        let (rig, payload) = try rigAndPayload()
        let advertiser = try #require(rig.identities[payload.senderFingerprint])
        let names = rig.fingerprints

        var records = MeshMembershipRecordVerifier(meshID: rig.meshID, ledger: rig.ledger)
        let departure = try SignedDepartureRecord.signed(
            meshID: rig.meshID, identity: advertiser, occurredAt: MeshMembershipEventFixtures.base
        )
        #expect(records.insert(departure) == nil)
        #expect(records.roster.contains(fingerprint: payload.senderFingerprint) == false)
        #expect(door(rig, ledger: records.ledger).verify(payload) == nil,
                "a departed advertiser's digest must still verify — it may still hold custody")

        var removalRecords = MeshMembershipRecordVerifier(meshID: rig.meshID, ledger: rig.ledger)
        let tallier = try #require(rig.identities[names[1]])
        let removal = try SignedRemovalRecord.signed(
            meshID: rig.meshID,
            identity: tallier,
            memberFingerprint: payload.senderFingerprint,
            proposalID: MeshMembershipEventFixtures.proposalID,
            voterFingerprints: [names[1], names[2]],
            occurredAt: MeshMembershipEventFixtures.base
        )
        #expect(removalRecords.insert(removal) == nil)
        #expect(removalRecords.ledger.removals.memberFingerprints.contains(payload.senderFingerprint))
        #expect(door(rig, ledger: removalRecords.ledger).verify(payload) == .senderRemoved)
    }

    /// The whole point of sending one: a legally DIFFERENT inventory verifies.
    @Test func aVerifiedDigestThatDiffersIsNotARejection() throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 3)
        let advertiser = try #require(rig.identities[rig.fingerprints[0]])
        let mine = MeshRoutedIndex(items: [
            MeshRoutedStoreFixtures.record(origin: "fp001", itemID: UUID(), chunkCount: 1)
        ])
        let theirs = MeshRoutedIndex(items: [
            MeshRoutedStoreFixtures.record(origin: "fp002", itemID: UUID(), chunkCount: 1),
            MeshRoutedStoreFixtures.record(origin: "fp003", itemID: UUID(), chunkCount: 1)
        ])
        let payload = try MeshRoutedInventoryPayload.signed(
            meshID: rig.meshID, index: theirs,
            sentAt: MeshRoutedInventoryFixtures.sentAt, identity: advertiser
        )
        let local = try #require(MeshRoutedInventory(
            meshID: rig.meshID, index: mine, selfFingerprint: advertiser.localFingerprint,
            at: MeshRoutedInventoryFixtures.sentAt
        ))
        #expect(local != payload.inventory)
        #expect(door(rig).verify(payload) == nil)
    }

    /// Every rejection carries frozen English, and none of them is a localized string.
    @Test func everyRejectionHasADiagnosticDescription() {
        var seen: Set<String> = []
        for rejection in MeshRoutedInventoryRejection.allCases {
            #expect(rejection.diagnosticDescription.isEmpty == false, "\(rejection)")
            #expect(rejection.rawValue.allSatisfy { $0.isASCII }, "\(rejection)")
            seen.insert(rejection.diagnosticDescription)
        }
        #expect(seen.count == MeshRoutedInventoryRejection.allCases.count)
        #expect(MeshRoutedInventoryRejection.allCases.count == 7)
    }
}
