// MeshCustodyReceiptTests.swift
// ProximityKitTests
//
// P5 item 3 (plan §11, §3.6): the CUSTODY RECEIPT — the third routed wire family, and the one
// record whose subject did not sign it.
//
// Four claims are walled here, each one a thing a later item cannot cheaply re-derive:
//
// 1. **The signed bytes are pinned.** `goldenCustodyReceiptHex` and `goldenCustodyReceiptIDHex` were
//    derived from the FORMAT by an independent Python re-implementation that first reproduced the
//    shipped `goldenInventoryHex`, `goldenEpochHeadsHex`, `goldenRoutedManifestHex` AND
//    `goldenRoutedChunkHex` byte-for-byte. A golden that only records what the code did proves
//    nothing; these were computed independently and then met. The frame is additive: nothing above
//    it moves, and both routed goldens are re-asserted here untouched.
// 2. **Durable before acknowledged is a TYPE rule.** The mint takes a
//    `MeshCustodyDurabilityWitness`, whose initializer is `fileprivate` to the file holding
//    `committingCustody` — so there is no argument list that produces a receipt for bytes no durable
//    write returned. Every receipt in this file comes out of a real store commit.
// 3. **The custodian signs, about the origin's item.** Two fingerprints in two fixed positions: the
//    signing key is resolved by the CUSTODIAN from the admission ledger, a departed custodian's
//    receipt still verifies, a quorum-removed one's does not, and a receipt lifted onto another
//    origin's item fails.
// 4. **The derived id is stable across a re-mint.** CryptoKit's Ed25519 signing is hedged, so two
//    mints of one logical receipt differ in the signature; `receiptID` excludes it — and excludes
//    `custodiedAt` too, because a re-mint of the same claim is the same claim.
//
// Nothing here sleeps or reads a wall clock for a decision.
//
// A partial copy (ProximityKit plan step A1, the split's third batch of copied suites: those that reach
// the keychain and open a store): of the Fernlet repository's FernletTests file of the same name, this
// holds only `MeshCustodyReceiptSigningTests` and `MeshCustodyReceiptVerifierTests`, with their names and
// tests unchanged, and the fixtures the package's copied suites read (`MeshCustodyReceiptFixtures`,
// `extension MeshCustodyReceipt` and `MeshCustodyReceiptTamper`); its golden suite and the fixtures only
// it reads stay there, so what this header says of them is not held here.

import CryptoKit
import Foundation
import Testing
@testable import ProximityKit

// MARK: - Fixtures

/// Fixed values for the receipt golden vectors — every pinned byte traces to a line here; nothing
/// reads a clock. `meshID`, `itemID`, `contentHash`, `expiresAt` and `opaqueSignature` are item 1's
/// own, so the receipt vector reads beside the manifest and chunk vectors as one story.
enum MeshCustodyReceiptFixtures {

    static let meshID = MeshRoutedManifestFixtures.meshID
    static let itemID = MeshRoutedManifestFixtures.itemID
    static let base = MeshRoutedManifestFixtures.base
    /// The item's author — the SUBJECT of the receipt.
    static let originFingerprint = MeshRoutedManifestFixtures.originFingerprint
    static let contentHash = MeshRoutedManifestFixtures.contentHash
    static let expiresAt = MeshRoutedManifestFixtures.expiresAt
    static let hardDeadline = MeshRoutedManifestFixtures.hardDeadline
    static let opaqueSignature = MeshMembershipEventFixtures.opaqueSignature

    /// Deliberately **neither the origin nor a destination** (`fp002`/`fp003` are the manifest's), so
    /// the golden itself says a custodian need not be a recipient of the item it is holding.
    static let custodianFingerprint = "fp004"

    /// `base + 540` — the offset item 2's design reserved for item 3 (taken: +60 … +480).
    static let custodiedAt = base.addingTimeInterval(540)

    /// The golden receipt, built from already-"signed" parts through the memberwise init.
    static func receipt() -> MeshCustodyReceipt {
        MeshCustodyReceipt(
            meshID: meshID,
            itemID: itemID,
            originFingerprint: originFingerprint,
            contentHash: contentHash,
            custodianFingerprint: custodianFingerprint,
            custodiedAt: custodiedAt,
            expiresAt: expiresAt,
            signature: opaqueSignature
        )
    }

    static func hex(_ data: Data) -> String {
        MeshMembershipEventFixtures.hex(data)
    }

    /// A `UUID`'s 16 network-order bytes, through the same writer the derivation uses.
    static func bytes(of uuid: UUID) -> Data {
        var writer = CanonicalByteWriter()
        writer.appendUUID(uuid)
        return writer.bytes
    }
}

// MARK: - Test-only rebuilders

extension MeshCustodyReceipt {
    /// Test-only: a copy with the named fields replaced, through the flooring memberwise init.
    func replacing(
        meshID: UUID? = nil,
        itemID: UUID? = nil,
        originFingerprint: String? = nil,
        contentHash: Data? = nil,
        custodianFingerprint: String? = nil,
        custodiedAt: Date? = nil,
        expiresAt: Date? = nil,
        signature: Data? = nil
    ) -> MeshCustodyReceipt {
        MeshCustodyReceipt(
            meshID: meshID ?? self.meshID,
            itemID: itemID ?? self.itemID,
            originFingerprint: originFingerprint ?? self.originFingerprint,
            contentHash: contentHash ?? self.contentHash,
            custodianFingerprint: custodianFingerprint ?? self.custodianFingerprint,
            custodiedAt: custodiedAt ?? self.custodiedAt,
            expiresAt: expiresAt ?? self.expiresAt,
            signature: signature ?? self.signature
        )
    }
}

/// One SIGNED field per case; every case must land on `.signatureInvalid` and nothing else.
///
/// `meshID` and `expiresAt` are deliberately absent — each has an earlier, differently named refusal
/// of its own (`foreignMesh`, `expiryMismatch`), which is the point of checking the cheap ones first.
enum MeshCustodyReceiptTamper: String, CaseIterable, Sendable {
    case itemID, originFingerprint, contentHash, custodianFingerprint, custodiedAt, signatureByte

    /// A minted receipt with this one field changed. The origin and custodian substitutes are BOTH
    /// admitted members, so every case reaches the signature check.
    func applied(
        to receipt: MeshCustodyReceipt,
        otherAdmittedOrigin: String,
        otherAdmittedCustodian: String
    ) -> MeshCustodyReceipt {
        switch self {
        case .itemID: return receipt.replacing(itemID: MeshMembershipEventFixtures.proposalID)
        case .originFingerprint: return receipt.replacing(originFingerprint: otherAdmittedOrigin)
        case .contentHash:
            var hash = receipt.contentHash
            hash[hash.startIndex] ^= 0x01
            return receipt.replacing(contentHash: hash)
        case .custodianFingerprint:
            return receipt.replacing(custodianFingerprint: otherAdmittedCustodian)
        case .custodiedAt:
            return receipt.replacing(custodiedAt: receipt.custodiedAt.addingTimeInterval(-1))
        case .signatureByte:
            var signature = receipt.signature
            signature[signature.startIndex] ^= 0x01
            return receipt.replacing(signature: signature)
        }
    }
}

// MARK: - Minting

/// The mint gate: a receipt exists only behind a real durable commit, and every refusal is named.
@MainActor
@Suite(.serialized)
struct MeshCustodyReceiptSigningTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer
    /// has run before a cell's identities or stores reach the keychain.
    let keychain = PackageTestEnvironment.keychain

    private typealias Fixture = MeshRoutedStoreFixtures

    @Test func aMintedReceiptNamesTheOriginAsSubjectAndTheDeviceAsSigner() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        let receipt = try MeshRoutedCustodyFixtures.receipt(rig)

        #expect(receipt.originFingerprint == rig.origin.localFingerprint)
        #expect(receipt.custodianFingerprint == rig.custodian.localFingerprint)
        #expect(receipt.meshID == rig.rig.meshID)
        #expect(receipt.itemID == rig.manifest.itemID)
        #expect(receipt.contentHash == rig.manifest.contentHash)
        #expect(receipt.expiresAt == rig.manifest.expiresAt)
        #expect(receipt.isWellFormed)
        #expect(receipt.signature.count == MeshCustodyReceiptFormat.signatureByteCount)
    }

    /// The one claim the item exists to make: there is no argument list that mints a receipt without
    /// a witness, and a witness comes only from a returned durable write.
    @Test func noWitnessMeansNoReceiptEvenWithEveryOtherInputInHand() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)

        // Nothing staged: the commit refuses and hands out no witness, so the mint is unreachable.
        let committed = MeshRoutedCustodyFixtures.commit(rig)
        #expect(MeshRoutedCustodyFixtures.witness(committed) == nil, "\(committed)")
        #expect(committed.refusal == .unknownItem)
    }

    @Test(arguments: MeshCustodyReceiptTamper.allCases)
    func tamperingAnySignedFieldInvalidatesTheSignature(tamper: MeshCustodyReceiptTamper) throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        let receipt = try MeshRoutedCustodyFixtures.receipt(rig)
        let names = rig.rig.fingerprints
        let verifier = MeshCustodyReceiptVerifier(
            meshID: rig.rig.meshID, hardDeadline: MeshRoutedManifestFixtures.hardDeadline,
            ledger: rig.rig.ledger, manifest: nil
        )
        #expect(verifier.verify(receipt) == nil)

        let tampered = tamper.applied(
            to: receipt, otherAdmittedOrigin: names[2], otherAdmittedCustodian: names[2]
        )
        #expect(verifier.verify(tampered) == .signatureInvalid, "\(tamper)")
    }

    /// Every mint refusal, one test each — none of them unreachable.
    @Test func everyMintRefusalIsReachable() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        MeshRoutedCustodyFixtures.stageAll(rig)
        let committed = MeshRoutedCustodyFixtures.commit(rig)
        let witness = try #require(MeshRoutedCustodyFixtures.witness(committed))
        let names = rig.rig.fingerprints
        let other = try #require(rig.rig.identities[names[2]])

        #expect(throws: MeshCustodyReceiptMintError.notTheCustodian) {
            try MeshCustodyReceipt.signed(witness: witness, manifest: rig.manifest, identity: other)
        }
        let foreign = try MeshRoutedCustodyFixtures.rig(scope: Fixture.scope(), memberCount: 3)
        defer { Fixture.tearDown(foreign.scope) }
        #expect(throws: MeshCustodyReceiptMintError.witnessForAnotherItem) {
            try MeshCustodyReceipt.signed(
                witness: witness, manifest: foreign.manifest, identity: rig.custodian
            )
        }
        var hash = rig.manifest.contentHash
        hash[hash.startIndex] ^= 0x01
        let rehashed = try resigned(rig.manifest.replacing(contentHash: hash), by: rig.origin)
        #expect(throws: MeshCustodyReceiptMintError.contentHashMismatch) {
            try MeshCustodyReceipt.signed(
                witness: witness, manifest: rehashed, identity: rig.custodian
            )
        }
    }

    /// A device never receipts its own item: it holds custody by authoring it, and a self-receipt
    /// would be a signature over nothing anybody else needs.
    @Test func aDeviceIssuesItselfNoReceiptForAnItemItAuthored() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        MeshRoutedCustodyFixtures.stageAll(rig)
        let committedAsOrigin = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) {
            rig.store.committingCustody(
                item: rig.key, custodian: rig.origin.localFingerprint, now: Fixture.now
            )
        }
        let witness = try #require(MeshRoutedCustodyFixtures.witness(committedAsOrigin))
        #expect(throws: MeshCustodyReceiptMintError.originIsSelf) {
            try MeshCustodyReceipt.signed(witness: witness, manifest: rig.manifest, identity: rig.origin)
        }
    }

    /// A witness dated at or after the item's expiry has nothing left to receipt.
    @Test func anExpiredItemIsNotReceipted() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        MeshRoutedCustodyFixtures.stageAll(rig)
        // A commit stamped one second before the expiry still commits; the manifest re-signed with an
        // EARLIER expiry is what makes the witness "late" without touching the store.
        let committed = MeshRoutedCustodyFixtures.commit(rig)
        let witness = try #require(MeshRoutedCustodyFixtures.witness(committed))
        let earlier = try resigned(
            rig.manifest.replacing(expiresAt: witness.custodiedAt), by: rig.origin
        )
        #expect(throws: MeshCustodyReceiptMintError.itemExpired) {
            try MeshCustodyReceipt.signed(witness: witness, manifest: earlier, identity: rig.custodian)
        }
    }

    /// Re-signs a rebuilt manifest as the origin, so a tampered-field fixture is still an honest
    /// origin-signed record.
    private func resigned(_ manifest: MeshRoutedManifest, by origin: IdentityService) throws -> MeshRoutedManifest {
        let unsigned = manifest.replacing(signature: Data())
        let signature = try origin.sign(
            canonicalBytes(for: unsigned),
            purpose: ProximityNamespace.packageTest.family.purposes.signature.meshRoutedManifestV1
        )
        return unsigned.replacing(signature: signature)
    }
}

// MARK: - Verification

/// Every rejection by name, and D14 in both directions.
@MainActor
@Suite(.serialized)
struct MeshCustodyReceiptVerifierTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer
    /// has run before a cell's identities or stores reach the keychain.
    let keychain = PackageTestEnvironment.keychain

    private typealias Fixture = MeshRoutedStoreFixtures

    /// A verifier over `rig`, holding the fixture `hardDeadline`.
    private func verifier(
        _ rig: MeshRoutedCustodyRig,
        ledger: MeshMembershipLedger? = nil,
        hardDeadline: Date? = nil,
        manifest: MeshRoutedManifest? = nil
    ) -> MeshCustodyReceiptVerifier {
        MeshCustodyReceiptVerifier(
            meshID: rig.rig.meshID,
            hardDeadline: hardDeadline ?? MeshRoutedManifestFixtures.hardDeadline,
            ledger: ledger ?? rig.rig.ledger,
            manifest: manifest ?? rig.manifest
        )
    }

    @Test func everyRejectionIsReachable() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        let receipt = try MeshRoutedCustodyFixtures.receipt(rig)
        let names = rig.rig.fingerprints
        #expect(verifier(rig).verify(receipt) == nil)

        #expect(verifier(rig).verify(receipt.replacing(meshID: UUID())) == .foreignMesh)
        #expect(verifier(rig).verify(receipt.replacing(signature: Data(repeating: 0x01, count: 63)))
                == .malformed)
        #expect(verifier(rig).verify(receipt.replacing(custodianFingerprint: receipt.originFingerprint))
                == .custodianIsOrigin)
        #expect(verifier(rig).verify(receipt.replacing(custodianFingerprint: "fp999"))
                == .custodianNotAdmitted)
        #expect(
            verifier(rig, hardDeadline: MeshRoutedManifestFixtures.hardDeadline.addingTimeInterval(60))
                .verify(receipt) == .expiryMismatch
        )
        #expect(verifier(rig).verify(receipt.replacing(itemID: UUID())) == .signatureInvalid)

        // A DIFFERENT item's manifest: all three legs of the identity triple are checked, so the
        // refusal is the manifest's rather than a signature failure.
        let other = try MeshRoutedCustodyFixtures.rig(scope: Fixture.scope())
        defer { Fixture.tearDown(other.scope) }
        #expect(verifier(rig, manifest: other.manifest).verify(receipt) == .manifestMismatch)

        // An admission binding the custodian's fingerprint to somebody else's key.
        let founder = try #require(rig.rig.identities[names[0]])
        let forged = SignedAdmissionRecord(token: try MeshAdmissionToken.signed(
            meshID: rig.rig.meshID,
            joinerFingerprint: rig.custodian.localFingerprint,
            joinerSigningPublicKey: founder.localSigningPublicKey,
            admitterIdentity: founder,
            grantedAt: MeshMembershipEventFixtures.base
        ))
        let forgedLedger = MeshMembershipLedger(admissions: MeshMembershipRecordSet([forged]))
        #expect(verifier(rig, ledger: forgedLedger).verify(receipt) == .custodianKeyMismatch)
    }

    /// D14, both directions: leaving is not a retraction, but a quorum removal is.
    @Test func aDepartedCustodianVerifiesAndAQuorumRemovedOneDoesNot() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        let receipt = try MeshRoutedCustodyFixtures.receipt(rig)
        let names = rig.rig.fingerprints

        var records = MeshMembershipRecordVerifier(meshID: rig.rig.meshID, ledger: rig.rig.ledger)
        let departure = try SignedDepartureRecord.signed(
            meshID: rig.rig.meshID, identity: rig.custodian, occurredAt: MeshMembershipEventFixtures.base
        )
        #expect(records.insert(departure) == nil)
        #expect(records.roster.contains(fingerprint: rig.custodian.localFingerprint) == false)
        #expect(verifier(rig, ledger: records.ledger).verify(receipt) == nil,
                "a departed custodian's receipt must still verify — the bytes did not evaporate")

        var removalRecords = MeshMembershipRecordVerifier(meshID: rig.rig.meshID, ledger: rig.rig.ledger)
        let tallier = try #require(rig.rig.identities[names[0]])
        let removal = try SignedRemovalRecord.signed(
            meshID: rig.rig.meshID,
            identity: tallier,
            memberFingerprint: rig.custodian.localFingerprint,
            proposalID: MeshMembershipEventFixtures.proposalID,
            voterFingerprints: [names[0], names[2]],
            occurredAt: MeshMembershipEventFixtures.base
        )
        #expect(removalRecords.insert(removal) == nil)
        #expect(removalRecords.ledger.removals.memberFingerprints.contains(rig.custodian.localFingerprint))
        #expect(verifier(rig, ledger: removalRecords.ledger).verify(receipt) == .custodianRemoved)
    }

    /// Without the manifest every check that does not need one still runs — a receipt can reach a
    /// member that has not seen the item yet, and that is a normal case, not a way to skip a check.
    @Test func aReceiptVerifiesWithoutTheManifestAndStillRefusesTheRest() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        let receipt = try MeshRoutedCustodyFixtures.receipt(rig)
        let door = MeshCustodyReceiptVerifier(
            meshID: rig.rig.meshID, hardDeadline: MeshRoutedManifestFixtures.hardDeadline,
            ledger: rig.rig.ledger, manifest: nil
        )
        #expect(door.verify(receipt) == nil)
        #expect(door.verify(receipt.replacing(meshID: UUID())) == .foreignMesh)
        #expect(door.verify(receipt.replacing(signature: Data(repeating: 0x02, count: 64)))
                == .signatureInvalid)
    }

    /// An over-long fingerprint is a cheap `malformed` rejection BEFORE any verify, because neither
    /// door clamps the scalar — clamping would have made this guard unreachable and demoted the
    /// answer to `signatureInvalid`.
    @Test func anOverLongFingerprintIsMalformedNotSignatureInvalid() throws {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let rig = try MeshRoutedCustodyFixtures.rig(scope: scope)
        let receipt = try MeshRoutedCustodyFixtures.receipt(rig)
        let overLong = String(repeating: "c", count: MeshCustodyReceiptFormat.maxFingerprintLength + 1)
        let wide = receipt.replacing(custodianFingerprint: overLong)
        #expect(wide.custodianFingerprint.utf8.count == MeshCustodyReceiptFormat.maxFingerprintLength + 1,
                "the door must NOT clamp the scalar")
        #expect(wide.isWellFormed == false)
        #expect(verifier(rig).verify(wide) == .malformed)
    }

    /// Every rejection carries frozen English, and none of them is a localized string.
    @Test func everyRejectionCarriesFrozenEnglish() {
        for rejection in MeshCustodyReceiptRejection.allCases {
            #expect(rejection.diagnosticDescription.isEmpty == false, "\(rejection)")
            #expect(rejection.rawValue.allSatisfy { $0.isASCII }, "\(rejection)")
        }
        #expect(MeshCustodyReceiptRejection.allCases.count == 9)
    }
}
