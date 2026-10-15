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
// unchanged; its suites stay there, so what this header says of them is not held here.

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
