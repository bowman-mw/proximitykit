// MeshRoutedManifestTests.swift
// ProximityKitTests
//
// P5 item 1 (plan §11): the routed-content manifest, the first routed wire family.
//
// Four claims are walled here, each one a thing a later item cannot cheaply re-derive:
//
// 1. **The signed bytes are pinned.** `goldenRoutedManifestHex` and `goldenWrapAADHex` were derived
//    from the FORMAT by an independent Python re-implementation that first reproduced
//    `goldenInventoryHex` and `goldenEpochHeadsHex` byte-for-byte. A golden that only records what
//    the code did proves nothing; these were computed independently and then met. The frame is
//    additive: nothing above it moves, and the inventory golden is re-asserted here untouched.
// 2. **The origin signs; nobody re-signs.** A relay forwards the exact object inside its own
//    envelope and the origin's signature still verifies; the only factory stamps the signer as the
//    origin, so "re-signing" someone else's manifest produces a different record. A since-departed
//    origin still verifies (leaving is not a retraction); a quorum-REMOVED origin is refused by name.
// 3. **The destination set is the roster at creation, not the connected set** — copied verbatim from
//    `MeshDeliveryTarget`, with exactly one wrap per destination in the same order, and the clamp on
//    both doors makes an over-cap list unrepresentable rather than trusted.
// 4. **Every refusal is named**, the verifier decides on public material only, and nothing traps on
//    a hostile instant an admitted origin can sign.
//
// Nothing here sleeps, touches disk, or reads a wall clock for a decision.
//
// A partial copy (ProximityKit plan step A1, the split's first batch of copied suites): of the
// Fernlet repository's FernletTests file of the same name, this holds only the fixtures the
// package's copied suites read (`MeshRoutedManifestFixtures` and `extension MeshRoutedManifest`),
// unchanged; and, since ProximityKit plan step A1's second batch of copied suites (those that reach
// the keychain and open no store), `MeshRoutedManifestSigningTests`, with its name and tests
// unchanged, and the fixtures it reads (`extension MeshRecipientKeyWrap`, `UnclampedManifestWire`,
// `MeshRoutedManifestShapeFault`, `MeshRoutedManifestTamper` and `MeshRoutedManifestMintFault`); its
// golden suite stays there, so what this header says of it is not held here.

import CryptoKit
import Foundation
import Testing
@testable import ProximityKit

// MARK: - Fixtures

/// Fixed values for the golden vectors — every pinned byte traces to a line here; nothing reads a
/// clock. `meshID`, `base` and `opaqueSignature` are the membership family's own, so the routed
/// vector reads beside the membership vectors as one story.
enum MeshRoutedManifestFixtures {

    static let meshID = MeshMembershipEventFixtures.meshID
    /// The item id. The `?? UUID()` fallback silently randomises a typo, so a test asserts the
    /// literal parsed.
    static let itemID = UUID(uuidString: "5A5A5A5A-6B6B-4C4C-8D8D-3E3E3E3E3E3E") ?? UUID()
    static let base = MeshMembershipEventFixtures.base
    static let originFingerprint = "fp001"
    /// The golden's type token (42 bytes). Item 11 will never register it.
    static let typeToken = "fernlet.mesh.routed-type.golden-fixture.v1"
    /// A second accepted token, so the tamper battery can change `typeToken` and still reach the
    /// signature check rather than `unknownTypeToken`.
    static let altTypeToken = "fernlet.mesh.routed-type.golden-fixture-alt.v1"
    /// What every item 1 verifier is built with (D13).
    static let acceptedTypeTokens: Set<String> = [typeToken, altTypeToken]
    /// `00 01 … 1f`.
    static let contentHash = Data((0..<32).map { UInt8($0) })
    static let size: UInt64 = 65_536
    /// `base + 480` — the next unused fixture offset (taken: +60 … +420).
    static let createdAt = base.addingTimeInterval(480)
    /// A mesh founded at `base`: `base + 6 h`.
    static let hardDeadline = base.addingTimeInterval(21_600)
    /// `hardDeadline + 20 min` = `base + 22_800`.
    static let expiresAt = base.addingTimeInterval(22_800)
    static let destinations = ["fp002", "fp003"]
    static let opaqueSignature = MeshMembershipEventFixtures.opaqueSignature

    /// Opaque fixture wrap bytes: the serializer treats them as `lp(Data)`, so they need no real
    /// crypto — real wraps are random and are exercised by the round-trip suite, never the golden.
    static func fixtureWrap(_ fingerprint: String, fill: UInt8) -> MeshRecipientKeyWrap {
        MeshRecipientKeyWrap(
            recipientFingerprint: fingerprint,
            ephemeralPublicKey: Data(repeating: fill, count: 32),
            nonce: Data(repeating: fill &+ 1, count: 12),
            sealedKey: Data(repeating: fill &+ 2, count: 48)
        )
    }

    /// fp002: `0x11×32 / 0x12×12 / 0x13×48`; fp003: `0x21×32 / 0x22×12 / 0x23×48`.
    static func keyWraps() -> [MeshRecipientKeyWrap] {
        [fixtureWrap("fp002", fill: 0x11), fixtureWrap("fp003", fill: 0x21)]
    }

    /// The golden manifest, built from already-"signed" parts through the memberwise init.
    static func manifest() -> MeshRoutedManifest {
        MeshRoutedManifest(
            meshID: meshID,
            itemID: itemID,
            originFingerprint: originFingerprint,
            typeToken: typeToken,
            contentHash: contentHash,
            size: size,
            createdAt: createdAt,
            expiresAt: expiresAt,
            destinations: destinations,
            keyWraps: keyWraps(),
            signature: opaqueSignature
        )
    }

    /// The golden manifest's wrap binding.
    static var binding: MeshRoutedWrapBinding {
        MeshRoutedWrapBinding(meshID: meshID, itemID: itemID, originFingerprint: originFingerprint)
    }

    static func hex(_ data: Data) -> String {
        MeshMembershipEventFixtures.hex(data)
    }
}

// MARK: - Test-only rebuilders

extension MeshRoutedManifest {
    /// Test-only: a copy with the named fields replaced, through the clamping memberwise init.
    func replacing(
        meshID: UUID? = nil,
        itemID: UUID? = nil,
        originFingerprint: String? = nil,
        typeToken: String? = nil,
        contentHash: Data? = nil,
        size: UInt64? = nil,
        createdAt: Date? = nil,
        expiresAt: Date? = nil,
        destinations: [String]? = nil,
        keyWraps: [MeshRecipientKeyWrap]? = nil,
        signature: Data? = nil
    ) -> MeshRoutedManifest {
        MeshRoutedManifest(
            meshID: meshID ?? self.meshID,
            itemID: itemID ?? self.itemID,
            originFingerprint: originFingerprint ?? self.originFingerprint,
            typeToken: typeToken ?? self.typeToken,
            contentHash: contentHash ?? self.contentHash,
            size: size ?? self.size,
            createdAt: createdAt ?? self.createdAt,
            expiresAt: expiresAt ?? self.expiresAt,
            destinations: destinations ?? self.destinations,
            keyWraps: keyWraps ?? self.keyWraps,
            signature: signature ?? self.signature
        )
    }
}

extension MeshRecipientKeyWrap {
    /// Test-only: a copy with the named fields replaced.
    func replacing(
        recipientFingerprint: String? = nil,
        ephemeralPublicKey: Data? = nil,
        nonce: Data? = nil,
        sealedKey: Data? = nil
    ) -> MeshRecipientKeyWrap {
        MeshRecipientKeyWrap(
            recipientFingerprint: recipientFingerprint ?? self.recipientFingerprint,
            ephemeralPublicKey: ephemeralPublicKey ?? self.ephemeralPublicKey,
            nonce: nonce ?? self.nonce,
            sealedKey: sealedKey ?? self.sealedKey
        )
    }
}

/// A manifest's JSON with NO clamp on the two lists — what a padded frame from a peer looks like
/// on the wire. Same coding keys and encoder strategy as the real type, so decoding it as a
/// ``MeshRoutedManifest`` exercises `init(from:)`'s clamp exactly.
private struct UnclampedManifestWire: Encodable {
    let meshID: UUID
    let itemID: UUID
    let originFingerprint: String
    let typeToken: String
    let contentHash: Data
    let size: UInt64
    let createdAt: Date
    let expiresAt: Date
    let destinations: [String]
    let keyWraps: [MeshRecipientKeyWrap]
    let signature: Data

    /// `manifest` with `padding` appended to both lists.
    init(_ manifest: MeshRoutedManifest, padding: [MeshRecipientKeyWrap]) {
        meshID = manifest.meshID
        itemID = manifest.itemID
        originFingerprint = manifest.originFingerprint
        typeToken = manifest.typeToken
        contentHash = manifest.contentHash
        size = manifest.size
        createdAt = manifest.createdAt
        expiresAt = manifest.expiresAt
        destinations = manifest.destinations + padding.map(\.recipientFingerprint)
        keyWraps = manifest.keyWraps + padding
        signature = manifest.signature
    }

    /// Encodes the padded wire form and decodes it through the real type's clamping door.
    func decodedManifest() throws -> MeshRoutedManifest {
        try JSONDecoder().decode(MeshRoutedManifest.self, from: JSONEncoder().encode(self))
    }

    /// The same wire with the two instants replaced by UNFLOORED values — what a relay that
    /// re-encoded the JSON with a sub-second fraction puts on the wire. The real type floors on
    /// its memberwise init, so this mirror is the only way to get a fraction onto the wire.
    func paddedWith(createdAt: Date, expiresAt: Date) -> UnclampedManifestWire {
        UnclampedManifestWire(
            meshID: meshID, itemID: itemID, originFingerprint: originFingerprint, typeToken: typeToken,
            contentHash: contentHash, size: size, createdAt: createdAt, expiresAt: expiresAt,
            destinations: destinations, keyWraps: keyWraps, signature: signature
        )
    }

    /// Memberwise, for ``paddedWith(createdAt:expiresAt:)``.
    private init(
        meshID: UUID, itemID: UUID, originFingerprint: String, typeToken: String, contentHash: Data,
        size: UInt64, createdAt: Date, expiresAt: Date, destinations: [String],
        keyWraps: [MeshRecipientKeyWrap], signature: Data
    ) {
        self.meshID = meshID
        self.itemID = itemID
        self.originFingerprint = originFingerprint
        self.typeToken = typeToken
        self.contentHash = contentHash
        self.size = size
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.destinations = destinations
        self.keyWraps = keyWraps
        self.signature = signature
    }
}

/// One wrong width or count per case — each a refusal, never a repair. No over-cap row: a count
/// above the destination cap is unrepresentable after either door's clamp.
enum MeshRoutedManifestShapeFault: String, CaseIterable, Sendable {
    case hash31, signature63, emptyToken, token65, emptyOrigin, sizeZero, sizeOverCap, noDestinations
    case sevenDestinationsSixWraps, twoDestinationsThreeWraps
    case wrapEphemeral31, wrapNonce11, wrapSealedKey47

    /// The golden fixture with this one fault applied through the memberwise init.
    func applied(to base: MeshRoutedManifest) -> MeshRoutedManifest {
        switch self {
        case .hash31: return base.replacing(contentHash: Data(repeating: 0x01, count: 31))
        case .signature63: return base.replacing(signature: Data(repeating: 0xAB, count: 63))
        case .emptyToken: return base.replacing(typeToken: "")
        case .token65: return base.replacing(typeToken: String(repeating: "t", count: 65))
        case .emptyOrigin: return base.replacing(originFingerprint: "")
        case .sizeZero: return base.replacing(size: 0)
        case .sizeOverCap: return base.replacing(size: MeshRoutedManifestFormat.maxContentByteCount + 1)
        case .noDestinations: return base.replacing(destinations: [], keyWraps: [])
        case .sevenDestinationsSixWraps:
            let names = (2...8).map { String(format: "fp%03d", $0) }
            let wraps = names.prefix(6).map { MeshRoutedManifestFixtures.fixtureWrap($0, fill: 0x11) }
            return base.replacing(destinations: names, keyWraps: Array(wraps))
        case .twoDestinationsThreeWraps:
            return base.replacing(keyWraps: base.keyWraps + [MeshRoutedManifestFixtures.fixtureWrap("fp004", fill: 0x31)])
        case .wrapEphemeral31:
            return base.replacing(keyWraps: Self.firstWrapReplaced(in: base) {
                $0.replacing(ephemeralPublicKey: Data(repeating: 0x11, count: 31))
            })
        case .wrapNonce11:
            return base.replacing(keyWraps: Self.firstWrapReplaced(in: base) {
                $0.replacing(nonce: Data(repeating: 0x12, count: 11))
            })
        case .wrapSealedKey47:
            return base.replacing(keyWraps: Self.firstWrapReplaced(in: base) {
                $0.replacing(sealedKey: Data(repeating: 0x13, count: 47))
            })
        }
    }

    /// The manifest's wraps with the first one rewritten.
    static func firstWrapReplaced(
        in manifest: MeshRoutedManifest, _ rewrite: (MeshRecipientKeyWrap) -> MeshRecipientKeyWrap
    ) -> [MeshRecipientKeyWrap] {
        var wraps = manifest.keyWraps
        guard let first = wraps.first else { return wraps }
        wraps[0] = rewrite(first)
        return wraps
    }
}

/// One signed field per case; every case must land on `.signatureInvalid` and nothing else, which
/// is the point of signing all of them.
enum MeshRoutedManifestTamper: String, CaseIterable, Sendable {
    case itemID, originFingerprint, typeToken, contentHash, size, createdAt, expiresAt
    case destinationsReversed, destinationReplaced, wrapsReversed
    case wrapEphemeralPublicKey, wrapNonce, wrapSealedKey, wrapRecipientFingerprint
    case signatureByte

    /// A minted manifest with this one field changed, through the memberwise init. The origin
    /// substitute and the destination substitute are BOTH admitted members, so every case reaches
    /// the signature check.
    func applied(to manifest: MeshRoutedManifest) -> MeshRoutedManifest {
        switch self {
        case .itemID: return manifest.replacing(itemID: MeshMembershipEventFixtures.proposalID)
        case .originFingerprint: return manifest.replacing(originFingerprint: manifest.destinations[0])
        case .typeToken: return manifest.replacing(typeToken: MeshRoutedManifestFixtures.altTypeToken)
        case .contentHash:
            var hash = manifest.contentHash
            hash[hash.startIndex] ^= 0x01
            return manifest.replacing(contentHash: hash)
        case .size: return manifest.replacing(size: manifest.size + 1)
        case .createdAt: return manifest.replacing(createdAt: manifest.createdAt.addingTimeInterval(1))
        case .expiresAt: return manifest.replacing(expiresAt: manifest.expiresAt.addingTimeInterval(1))
        case .destinationsReversed: return manifest.replacing(destinations: manifest.destinations.reversed())
        case .destinationReplaced:
            var destinations = manifest.destinations
            destinations[0] = destinations[1]
            return manifest.replacing(destinations: destinations)
        case .wrapsReversed: return manifest.replacing(keyWraps: manifest.keyWraps.reversed())
        case .wrapEphemeralPublicKey:
            return manifest.replacing(keyWraps: MeshRoutedManifestShapeFault.firstWrapReplaced(in: manifest) {
                $0.replacing(ephemeralPublicKey: Data(repeating: 0x5A, count: 32))
            })
        case .wrapNonce:
            return manifest.replacing(keyWraps: MeshRoutedManifestShapeFault.firstWrapReplaced(in: manifest) {
                $0.replacing(nonce: Data(repeating: 0x5A, count: 12))
            })
        case .wrapSealedKey:
            return manifest.replacing(keyWraps: MeshRoutedManifestShapeFault.firstWrapReplaced(in: manifest) {
                $0.replacing(sealedKey: Data(repeating: 0x5A, count: 48))
            })
        case .wrapRecipientFingerprint:
            return manifest.replacing(keyWraps: MeshRoutedManifestShapeFault.firstWrapReplaced(in: manifest) {
                $0.replacing(recipientFingerprint: manifest.originFingerprint)
            })
        case .signatureByte:
            var signature = manifest.signature
            signature[signature.startIndex] ^= 0x01
            return manifest.replacing(signature: signature)
        }
    }
}

/// The mint refusals that are input faults rather than target faults, each with the error it
/// must name.
enum MeshRoutedManifestMintFault: String, CaseIterable, Sendable {
    case shortContentKey, shortContentHash, zeroSize, emptyTypeToken

    var expected: MeshRoutedManifestMintError {
        switch self {
        case .shortContentKey: return .invalidContentKey
        case .shortContentHash: return .invalidContentHash
        case .zeroSize: return .invalidSize
        case .emptyTypeToken: return .invalidTypeToken
        }
    }
}

// MARK: - Signing and verification

/// Sign with real keys, verify through the one door, and every refusal by name.
@MainActor
@Suite(.serialized)
struct MeshRoutedManifestSigningTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer
    /// has run before a cell's identities reach the keychain.
    let keychain = PackageTestEnvironment.keychain

    /// One minted manifest with everything a test needs to interrogate it.
    private struct Minted {
        let rig: MeshDeliveryRig
        let origin: IdentityService
        let target: MeshDeliveryTarget
        let manifest: MeshRoutedManifest
        let verifier: MeshRoutedManifestVerifier
        let contentKey: Data
    }

    /// A verifier over `rig`, holding the fixture `hardDeadline` and the fixture token set.
    private func verifier(
        for rig: MeshDeliveryRig,
        ledger: MeshMembershipLedger? = nil,
        acceptedTypeTokens: Set<String>? = nil
    ) -> MeshRoutedManifestVerifier {
        MeshRoutedManifestVerifier(
            meshID: rig.meshID,
            hardDeadline: MeshRoutedManifestFixtures.hardDeadline,
            ledger: ledger ?? rig.ledger,
            acceptedTypeTokens: acceptedTypeTokens ?? MeshRoutedManifestFixtures.acceptedTypeTokens
        )
    }

    private func allRecipientKeys(_ rig: MeshDeliveryRig) -> [String: Data] {
        rig.identities.mapValues { $0.localKeyAgreementPublicKey }
    }

    /// Mints from `rig`'s roster with the origin at `originIndex`. Every parameter that is not a
    /// fixture default is a knob a specific row turns.
    private func mint(
        rig: MeshDeliveryRig,
        originIndex: Int = 0,
        hardDeadline: Date? = nil,
        target: MeshDeliveryTarget? = nil,
        createdAt: Date? = nil,
        typeToken: String? = nil,
        contentHash: Data? = nil,
        size: UInt64? = nil,
        contentKey: Data? = nil,
        recipientKeys: [String: Data]? = nil
    ) throws -> Minted {
        let originFingerprint = rig.fingerprints[originIndex]
        let origin = try #require(rig.identities[originFingerprint])
        let target = target ?? MeshDeliveryTarget(
            contentID: MeshRoutedManifestFixtures.itemID, roster: rig.roster, selfFingerprint: originFingerprint
        )
        let key = contentKey ?? MeshRoutedContentKeyWrapper.makeContentKey()
        let manifest = try MeshRoutedManifest.signed(
            meshID: rig.meshID,
            target: target,
            typeToken: typeToken ?? MeshRoutedManifestFixtures.typeToken,
            contentHash: contentHash ?? MeshRoutedManifestFixtures.contentHash,
            size: size ?? MeshRoutedManifestFixtures.size,
            createdAt: createdAt ?? MeshRoutedManifestFixtures.base,
            hardDeadline: hardDeadline ?? MeshRoutedManifestFixtures.hardDeadline,
            contentKey: key,
            recipientKeys: recipientKeys ?? allRecipientKeys(rig),
            identity: origin
        )
        return Minted(
            rig: rig, origin: origin, target: target, manifest: manifest,
            verifier: verifier(for: rig), contentKey: key
        )
    }

    /// Test-only re-sign: the only way to produce an origin-signed manifest the factory would
    /// refuse to mint. Allowed here, never in shipping code.
    private func resigned(_ manifest: MeshRoutedManifest, by identity: IdentityService) throws -> MeshRoutedManifest {
        let unsigned = manifest.replacing(signature: Data())
        let signature = try identity.sign(
            canonicalBytes(for: unsigned),
            purpose: ProximityNamespace.packageTest.family.purposes.signature.meshRoutedManifestV1
        )
        return unsigned.replacing(signature: signature)
    }

    // MARK: Destination set and the mint

    @Test func anOriginMintsAManifestWhoseDestinationsAreTheTargetsRosterAtCreation() throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 4)
        let minted = try mint(rig: rig)
        let names = rig.fingerprints
        #expect(minted.manifest.destinations == minted.target.destinations)
        #expect(minted.manifest.destinations == [names[1], names[2], names[3]])
        #expect(minted.manifest.originFingerprint == names[0])
        #expect(minted.manifest.itemID == minted.target.contentID)
    }

    /// A 2/2 split of a roster of four: a target built from the roster still names the unreachable
    /// half. The load-bearing wall is the mint's TYPE SIGNATURE — `signed(...)` has no reachable-set
    /// or branch parameter, so the `MeshBranchView` below cannot be an input to it and the only way
    /// this could fail is the mint or `MeshDeliveryTarget` dropping members, which
    /// ``anOriginMintsAManifestWhoseDestinationsAreTheTargetsRosterAtCreation`` pins against the
    /// roster itself. This test reads the consequence, not the cause.
    @Test func aTargetBuiltFromTheRosterStillNamesTheUnreachableHalf() throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 4)
        let names = rig.fingerprints
        let branch = MeshDeliveryFixtures.branch(rig, selfFingerprint: names[0], reachable: [names[0], names[1]])
        let minted = try mint(rig: rig)
        #expect(branch.temporarilyDisconnectedFingerprints == [names[2], names[3]])
        #expect(minted.manifest.destinations.count == 3)
        #expect(Set(minted.manifest.destinations).isSuperset(of: branch.temporarilyDisconnectedFingerprints))
    }

    @Test func aMintedManifestVerifiesThroughTheOneDoor() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 4))
        #expect(minted.manifest.isWellFormed)
        #expect(minted.verifier.verify(minted.manifest) == nil)
    }

    @Test func aMintedManifestIsLiveAndFlooredToWholeSeconds() throws {
        let base = MeshRoutedManifestFixtures.base
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 2), createdAt: base.addingTimeInterval(0.4))
        #expect(minted.manifest.createdAt == base)
        #expect(minted.manifest.expiresAt == base.addingTimeInterval(22_800))
        #expect(minted.manifest.isLive(at: base.addingTimeInterval(22_800)))
        #expect(minted.manifest.isLive(at: base.addingTimeInterval(22_801)) == false)
    }

    // MARK: Refusals by name

    @Test(arguments: MeshRoutedManifestTamper.allCases)
    func tamperingAnyFieldIsRefusedAsSignatureInvalid(tamper: MeshRoutedManifestTamper) throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 4))
        let tampered = tamper.applied(to: minted.manifest)
        #expect(tampered != minted.manifest, "\(tamper)")
        #expect(minted.verifier.verify(tampered) == .signatureInvalid, "\(tamper)")
    }

    @Test func aManifestForAnotherMeshIsForeign() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 2))
        let foreign = MeshRoutedManifestVerifier(
            meshID: MeshMembershipEventFixtures.meshID,
            hardDeadline: MeshRoutedManifestFixtures.hardDeadline,
            ledger: minted.rig.ledger,
            acceptedTypeTokens: MeshRoutedManifestFixtures.acceptedTypeTokens
        )
        #expect(foreign.verify(minted.manifest) == .foreignMesh)
    }

    @Test func aManifestFromAnUnadmittedOriginIsRefusedByName() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 2))
        #expect(minted.verifier.verify(minted.manifest.replacing(originFingerprint: "fp999")) == .originNotAdmitted)
    }

    /// D13: unknown tokens are refused, never forwarded — before the origin lookup.
    @Test func aManifestWithAnUnregisteredTypeTokenIsRefusedByName() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 2))
        let unregistered = try resigned(
            minted.manifest.replacing(typeToken: "fernlet.mesh.routed-type.nobody-registered.v1"), by: minted.origin
        )
        #expect(minted.verifier.verify(unregistered) == .unknownTypeToken)
        #expect(verifier(for: minted.rig, acceptedTypeTokens: []).verify(minted.manifest) == .unknownTypeToken)
        // The refusal precedes the origin lookup: an unregistered token from an unadmitted origin
        // is still `unknownTypeToken`.
        #expect(minted.verifier.verify(unregistered.replacing(originFingerprint: "fp999")) == .unknownTypeToken)
    }

    /// D12: destinations are trusted on the origin's signature, bounded — never looked up in the
    /// ledger. A never-admitted destination reads as departed at read, held until expiry.
    @Test func aManifestNamingANeverAdmittedDestinationStillVerifies() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 4))
        let phantomKey = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation
        let phantomWrap = try MeshRoutedContentKeyWrapper.wrap(
            contentKey: minted.contentKey,
            recipientFingerprint: "fp999",
            recipientKeyAgreementPublicKey: phantomKey,
            binding: MeshRoutedWrapBinding(
                meshID: minted.rig.meshID, itemID: minted.manifest.itemID,
                originFingerprint: minted.manifest.originFingerprint
            )
        )
        let widened = try resigned(
            minted.manifest.replacing(
                destinations: minted.manifest.destinations + ["fp999"],
                keyWraps: minted.manifest.keyWraps + [phantomWrap]
            ),
            by: minted.origin
        )
        #expect(minted.rig.roster.contains(fingerprint: "fp999") == false)
        #expect(minted.verifier.verify(widened) == nil)
    }

    /// Leaving is not a retraction: the origin's key is looked up in the admissions, and the
    /// roster is never consulted.
    @Test func aManifestFromASinceDepartedOriginStillVerifies() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 3))
        var records = MeshMembershipRecordVerifier(meshID: minted.rig.meshID, ledger: minted.rig.ledger)
        let departure = try SignedDepartureRecord.signed(
            meshID: minted.rig.meshID, identity: minted.origin, occurredAt: MeshMembershipEventFixtures.base
        )
        #expect(records.insert(departure) == nil)
        #expect(records.roster.contains(fingerprint: minted.origin.localFingerprint) == false)
        #expect(verifier(for: minted.rig, ledger: records.ledger).verify(minted.manifest) == nil)
    }

    /// Removal is not departure: a quorum-removed origin's manifest is refused by name. The same
    /// roster subtraction as the departed test, reached through the removal record set instead —
    /// the group-key rotation that enforces a removal on live traffic cannot reach a static-key wrap.
    @Test func aManifestFromARemovedOriginIsRefusedByName() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 3))
        let names = minted.rig.fingerprints
        let tallier = try #require(minted.rig.identities[names[1]])
        var records = MeshMembershipRecordVerifier(meshID: minted.rig.meshID, ledger: minted.rig.ledger)
        #expect(records.roster.quorumThreshold == 2)
        let removal = try SignedRemovalRecord.signed(
            meshID: minted.rig.meshID,
            identity: tallier,
            memberFingerprint: minted.origin.localFingerprint,
            proposalID: MeshMembershipEventFixtures.proposalID,
            voterFingerprints: [names[1], names[2]],
            occurredAt: MeshMembershipEventFixtures.base
        )
        #expect(records.insert(removal) == nil)
        #expect(records.roster.contains(fingerprint: minted.origin.localFingerprint) == false)
        #expect(records.ledger.removals.memberFingerprints.contains(minted.origin.localFingerprint))
        #expect(verifier(for: minted.rig, ledger: records.ledger).verify(minted.manifest) == .originRemoved)
        // The refusal is the removal's, not the signature's: the same bytes verify against the
        // ledger as it stood before the quorum.
        #expect(minted.verifier.verify(minted.manifest) == nil)
    }

    /// An admission whose signing key is not the key its fingerprint names is refused by name —
    /// BEFORE the signature is checked, so the refusal never reads as a mere `signatureInvalid`.
    /// `MeshMembershipRecordSet` holds whatever it is handed (verification is the verifier's job),
    /// which is exactly how such a record can reach a ledger.
    @Test func aManifestWhoseAdmittedKeyDoesNotMatchItsFingerprintIsRefusedByName() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 3))
        let names = minted.rig.fingerprints
        let founder = try #require(minted.rig.identities[names[0]])
        let other = try #require(minted.rig.identities[names[1]])
        let forged = SignedAdmissionRecord(token: try MeshAdmissionToken.signed(
            meshID: minted.rig.meshID,
            joinerFingerprint: minted.origin.localFingerprint,
            joinerSigningPublicKey: other.localSigningPublicKey,
            admitterIdentity: founder,
            grantedAt: MeshMembershipEventFixtures.base
        ))
        let forgedLedger = MeshMembershipLedger(admissions: MeshMembershipRecordSet([forged]))
        #expect(forgedLedger.admissions.contains(fingerprint: minted.origin.localFingerprint))
        let door = verifier(for: minted.rig, ledger: forgedLedger)
        #expect(door.verify(minted.manifest) == .originKeyMismatch)
        // Precedes the signature check: a manifest that would ALSO fail the signature still lands
        // on the key mismatch, and the honest ledger still verifies the untouched manifest.
        #expect(door.verify(MeshRoutedManifestTamper.signatureByte.applied(to: minted.manifest)) == .originKeyMismatch)
        #expect(minted.verifier.verify(minted.manifest) == nil)
    }

    // MARK: Relays

    @Test func aRelayForwardsTheOriginsBytesVerbatimAndTheOriginSignatureVerifies() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 3))
        let relay = try #require(minted.rig.identities[minted.rig.fingerprints[1]])
        let wire = try JSONEncoder().encode(MeshRoutedManifestPayload(manifest: minted.manifest))
        let envelope = try ProximityIdentityEnvelope.signed(
            identityService: relay,
            senderDisplayName: "relay",
            payloadType: .meshRoutedManifest,
            payloadSummary: PayloadSummary(title: "manifest"),
            payload: wire,
            createdAt: MeshMembershipEventFixtures.base
        )
        #expect(envelope.senderSigningPublicKey == relay.localSigningPublicKey)
        #expect(envelope.senderSigningPublicKey != minted.origin.localSigningPublicKey)
        let forwarded = try JSONDecoder().decode(MeshRoutedManifestPayload.self, from: envelope.payload).manifest
        #expect(forwarded == minted.manifest)
        #expect(canonicalBytes(for: forwarded) == canonicalBytes(for: minted.manifest))
        #expect(minted.verifier.verify(forwarded) == nil)
    }

    /// The only factory stamps the signer as the origin: a relay minting for the origin's target
    /// is refused (it is a destination), and minting for its own target yields a DIFFERENT record.
    @Test func aRelayCannotReSignAnotherOriginsManifest() throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 3)
        let minted = try mint(rig: rig)
        #expect(throws: MeshRoutedManifestMintError.originIsADestination) {
            try mint(rig: rig, originIndex: 1, target: minted.target)
        }
        let relayMinted = try mint(rig: rig, originIndex: 1)
        #expect(relayMinted.manifest.originFingerprint == rig.fingerprints[1])
        #expect(relayMinted.manifest.originFingerprint != minted.manifest.originFingerprint)
        #expect(relayMinted.manifest.destinations != minted.manifest.destinations)
        #expect(canonicalBytes(for: relayMinted.manifest) != canonicalBytes(for: minted.manifest))
    }

    // MARK: Expiry

    @Test func aManifestSignedForALongerExpiryIsRefusedByName() throws {
        let minted = try mint(
            rig: try MeshDeliveryFixtures.rig(memberCount: 2),
            hardDeadline: MeshRoutedManifestFixtures.base.addingTimeInterval(21_660)
        )
        #expect(minted.manifest.expiresAt == MeshRoutedManifestFixtures.base.addingTimeInterval(22_860))
        #expect(minted.verifier.verify(minted.manifest) == .expiryMismatch)
    }

    /// An admitted origin can sign any `Date` the wire's default strategy decodes; nothing traps
    /// on it, and the expiry is refused by name. `createdAt` is never decided on and never trapped on.
    @Test(arguments: [1e300, -1e300, Double.infinity, Double.nan])
    func aHostileExpiryNeverTrapsAndIsRefusedByName(value: Double) throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 2))
        let hostile = Date(timeIntervalSince1970: value)

        let expiryForged = try resigned(minted.manifest.replacing(expiresAt: hostile), by: minted.origin)
        #expect(minted.verifier.verify(expiryForged) == .expiryMismatch)
        let createdForged = try resigned(minted.manifest.replacing(createdAt: hostile), by: minted.origin)
        #expect(minted.verifier.verify(createdForged) == nil)

        guard value.isFinite else { return }
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()
        let expiryWire = try encoder.encode(MeshRoutedManifestPayload(manifest: expiryForged))
        let expiryDecoded = try decoder.decode(MeshRoutedManifestPayload.self, from: expiryWire).manifest
        #expect(minted.verifier.verify(expiryDecoded) == .expiryMismatch)
        let createdWire = try encoder.encode(MeshRoutedManifestPayload(manifest: createdForged))
        let createdDecoded = try decoder.decode(MeshRoutedManifestPayload.self, from: createdWire).manifest
        #expect(minted.verifier.verify(createdDecoded) == nil)
    }

    // MARK: Clamps

    /// Padding past a FULL roster is trimmed back to the origin's exact bytes, so the signature
    /// still verifies: nothing signed was touched.
    @Test func aPaddingPastAFullRosterIsDiscardedAndTheOriginsBytesStillVerify() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 8))
        #expect(minted.manifest.destinations.count == MeshRoutedManifestFormat.maxDestinations)
        let padded = try UnclampedManifestWire(
            minted.manifest, padding: [MeshRoutedManifestFixtures.fixtureWrap("fp999", fill: 0x41)]
        ).decodedManifest()
        #expect(padded.destinations.count == 7)
        #expect(padded.keyWraps.count == 7)
        #expect(padded.isWellFormed)
        #expect(padded == minted.manifest)
        #expect(minted.verifier.verify(padded) == nil)
    }

    /// The clamp fired AND what it left is not what the origin signed — refused, never trusted
    /// after a trim.
    @Test func aPaddedManifestIsClampedOnDecodeAndThenRefused() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 4))
        #expect(minted.manifest.destinations.count == 3)
        let synthetic = (0..<5).map { MeshRoutedManifestFixtures.fixtureWrap("fp99\($0)", fill: 0x41) }
        let padded = try UnclampedManifestWire(minted.manifest, padding: synthetic).decodedManifest()
        #expect(padded.destinations.count == 7)
        #expect(padded.keyWraps.count == 7)
        #expect(padded.isWellFormed)
        #expect(minted.verifier.verify(padded) == .signatureInvalid)
    }

    // MARK: What the origin itself may not sign

    @Test func anOriginThatSignedMisalignedWrapsIsRefusedByName() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 3))
        let misaligned = try resigned(
            minted.manifest.replacing(keyWraps: minted.manifest.keyWraps.reversed()), by: minted.origin
        )
        #expect(minted.verifier.verify(misaligned) == .wrapsDoNotMatchDestinations)
    }

    @Test func anOriginThatSignedADuplicateDestinationIsRefusedByName() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 3))
        let member = minted.manifest.destinations[0]
        let wrap = minted.manifest.keyWraps[0]
        let duplicated = try resigned(
            minted.manifest.replacing(destinations: [member, member], keyWraps: [wrap, wrap]), by: minted.origin
        )
        #expect(minted.verifier.verify(duplicated) == .destinationSetInvalid)
        let selfNamed = try resigned(
            minted.manifest.replacing(
                destinations: [member, minted.manifest.originFingerprint],
                keyWraps: [wrap, wrap.replacing(recipientFingerprint: minted.manifest.originFingerprint)]
            ),
            by: minted.origin
        )
        #expect(minted.verifier.verify(selfNamed) == .destinationSetInvalid)
    }

    // MARK: Mint refusals

    /// D1: a missing handshake-verified key refuses the WHOLE mint; the wrap set is never narrowed.
    @Test func aMintWithAMissingRecipientKeyIsRefusedByName() throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 4)
        let dropped = rig.fingerprints[2]
        var keys = allRecipientKeys(rig)
        keys.removeValue(forKey: dropped)
        #expect(throws: MeshRoutedManifestMintError.missingRecipientKey(fingerprint: dropped)) {
            try mint(rig: rig, recipientKeys: keys)
        }
    }

    @Test func aMintForATargetNamingTheOriginIsRefused() throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 3)
        let othersTarget = MeshDeliveryTarget(
            contentID: MeshRoutedManifestFixtures.itemID, roster: rig.roster, selfFingerprint: rig.fingerprints[1]
        )
        #expect(othersTarget.names(rig.fingerprints[0]))
        #expect(throws: MeshRoutedManifestMintError.originIsADestination) {
            try mint(rig: rig, originIndex: 0, target: othersTarget)
        }
    }

    @Test func aMintForARosterOfOneIsRefused() throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 1)
        #expect(throws: MeshRoutedManifestMintError.noDestinations) {
            try mint(rig: rig)
        }
    }

    @Test(arguments: MeshRoutedManifestMintFault.allCases)
    func aMintWithABadContentKeyOrHashOrSizeIsRefusedByName(fault: MeshRoutedManifestMintFault) throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 2)
        #expect(throws: fault.expected) {
            switch fault {
            case .shortContentKey: try mint(rig: rig, contentKey: Data(repeating: 0x01, count: 16))
            case .shortContentHash: try mint(rig: rig, contentHash: Data(repeating: 0x01, count: 31))
            case .zeroSize: try mint(rig: rig, size: 0)
            case .emptyTypeToken: try mint(rig: rig, typeToken: "")
            }
        }
    }

    @Test func everyRejectionHasAFrozenDiagnostic() {
        #expect(MeshRoutedManifestRejection.allCases.count == 11)
        let allRejectionsNamed = MeshRoutedManifestRejection.allCases.allSatisfy { !$0.diagnosticDescription.isEmpty }
        #expect(allRejectionsNamed)
        let mintErrors: [MeshRoutedManifestMintError] = [
            .noDestinations, .tooManyDestinations(count: 9), .originIsADestination, .invalidTypeToken,
            .invalidContentHash, .invalidSize, .invalidContentKey, .missingRecipientKey(fingerprint: "fp999"),
            // P5 item 11's two registry refusals. `MeshRoutedManifestMintError` has associated
            // values, so there is no `allCases` to catch a gap — a new case ships outside this
            // census with a clean build unless it is added here in the same commit.
            .sizeExceedsTypeCap(token: "fernlet.mesh.routed-type.golden-fixture.v1"),
            .unsupportedDestinationSemantics(token: "fernlet.mesh.routed-type.golden-fixture.v1")
        ]
        let allMintErrorsNamed = mintErrors.allSatisfy { !$0.diagnosticDescription.isEmpty }
        #expect(allMintErrorsNamed)
    }

    // MARK: The frame

    /// Signed, not sealed — a custodian must be able to re-broadcast the frame verbatim. The
    /// `.verifyChallenge` control is what makes this prove the stance rather than the absence of an
    /// error.
    @Test func theManifestFrameIsSignedNotSealed() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 2))
        let receiver = try #require(minted.rig.identities[minted.rig.fingerprints[1]])
        let payload = try JSONEncoder().encode(MeshRoutedManifestPayload(manifest: minted.manifest))
        let base = MeshMembershipEventFixtures.base

        let manifestFrame = try ProximityIdentityEnvelope.signed(
            identityService: minted.origin,
            senderDisplayName: "origin",
            recipientFingerprint: receiver.localFingerprint,
            payloadType: .meshRoutedManifest,
            payloadEncryption: .none,
            payloadSummary: PayloadSummary(title: "manifest"),
            payload: payload,
            createdAt: base
        )
        let opened = try manifestFrame.verify(
            identityService: receiver, replayCache: ReplayCache(dateProvider: { base })
        )
        #expect(opened == payload)

        // Positive control: the same call for a type in `.packageTest`'s sealing set is fail-closed.
        let control = try ProximityIdentityEnvelope.signed(
            identityService: minted.origin,
            senderDisplayName: "origin",
            recipientFingerprint: receiver.localFingerprint,
            payloadType: .verifyChallenge,
            payloadEncryption: .none,
            payloadSummary: PayloadSummary(title: "manifest"),
            payload: payload,
            createdAt: base
        )
        #expect(throws: ProximityIdentityEnvelope.VerifyError.sealingRequired) {
            try control.verify(identityService: receiver, replayCache: ReplayCache(dateProvider: { base }))
        }
    }

    /// The four `admit` parameters fit the manifest's fields (wiring itself is item 12).
    @Test func aMintedManifestIsAdmittedOnceByTheReplayWindowThenReplayed() throws {
        let minted = try mint(rig: try MeshDeliveryFixtures.rig(memberCount: 2))
        var window = MeshFrameReplayWindow(meshID: minted.rig.meshID)
        let base = MeshMembershipEventFixtures.base
        #expect(window.admit(
            frameID: minted.manifest.itemID, from: minted.manifest.originFingerprint,
            meshID: minted.manifest.meshID, expiresAt: minted.manifest.expiresAt, now: base
        ) == .admitted)
        #expect(window.admit(
            frameID: minted.manifest.itemID, from: minted.manifest.originFingerprint,
            meshID: minted.manifest.meshID, expiresAt: minted.manifest.expiresAt, now: base
        ) == .replayed)
        #expect(window.admit(
            frameID: minted.manifest.itemID, from: minted.manifest.originFingerprint,
            meshID: minted.manifest.meshID, expiresAt: minted.manifest.expiresAt,
            now: minted.manifest.expiresAt.addingTimeInterval(1)
        ) == .expired)
    }
}
