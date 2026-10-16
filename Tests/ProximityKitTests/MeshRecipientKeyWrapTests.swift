// MeshRecipientKeyWrapTests.swift
// ProximityKitTests
//
// P5 item 1 (plan §11, invariant §3.3): the per-recipient content-key wrap.
//
// The claims walled here: the addressed recipient opens the key and nobody else does; a wrap
// relabelled to another recipient opens for NEITHER of them (the AAD binds the recipient at the key
// layer, beneath the manifest signature); a wrap bound to one manifest opens under no other
// binding; every wrap draws a fresh ephemeral and nonce; every refusal is named; and an
// unprovisioned identity surfaces its own error rather than a failed open.
//
// Real keys throughout, no radio, no disk beyond the identities' own keychain rows.

import CryptoKit
import Foundation
import Testing
@testable import ProximityKit

/// One binding field per case, each changed alone.
enum MeshRoutedWrapBindingPerturbation: String, CaseIterable, Sendable {
    case itemID, meshID, originFingerprint

    /// `binding` with this one field changed.
    func applied(to binding: MeshRoutedWrapBinding) -> MeshRoutedWrapBinding {
        switch self {
        case .itemID:
            return MeshRoutedWrapBinding(
                meshID: binding.meshID, itemID: MeshMembershipEventFixtures.proposalID,
                originFingerprint: binding.originFingerprint
            )
        case .meshID:
            return MeshRoutedWrapBinding(
                meshID: MeshMembershipEventFixtures.proposalID, itemID: binding.itemID,
                originFingerprint: binding.originFingerprint
            )
        case .originFingerprint:
            return MeshRoutedWrapBinding(meshID: binding.meshID, itemID: binding.itemID, originFingerprint: "fp999")
        }
    }
}

/// The wrap's two directions, and every refusal by name.
@MainActor
@Suite(.serialized)
struct MeshRecipientKeyWrapTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer
    /// has run before a cell's identities reach the keychain.
    let keychain = PackageTestEnvironment.keychain

    /// Three provisioned identities, the golden fixture's binding with the real origin, and one
    /// random content key.
    private struct Trio {
        let origin: IdentityService
        let alice: IdentityService
        let bob: IdentityService
        let binding: MeshRoutedWrapBinding
        let key: Data
    }

    private func makeTrio() throws -> Trio {
        let origin = try MeshPartitionFixtures.identity("routedwrap-origin")
        let alice = try MeshPartitionFixtures.identity("routedwrap-alice")
        let bob = try MeshPartitionFixtures.identity("routedwrap-bob")
        let key = MeshRoutedContentKeyWrapper.makeContentKey()
        #expect(key.count == MeshRoutedManifestFormat.contentKeyByteCount)
        return Trio(
            origin: origin, alice: alice, bob: bob,
            binding: MeshRoutedWrapBinding(
                meshID: MeshRoutedManifestFixtures.meshID,
                itemID: MeshRoutedManifestFixtures.itemID,
                originFingerprint: origin.localFingerprint
            ),
            key: key
        )
    }

    private func wrap(_ trio: Trio, for recipient: IdentityService) throws -> MeshRecipientKeyWrap {
        try MeshRoutedContentKeyWrapper.wrap(
            contentKey: trio.key,
            recipientFingerprint: recipient.localFingerprint,
            recipientKeyAgreementPublicKey: recipient.localKeyAgreementPublicKey,
            binding: trio.binding
        )
    }

    /// The production shape: the private key never leaves the identity; the closure is the DH.
    private func open(
        _ wrap: MeshRecipientKeyWrap, as identity: IdentityService, binding: MeshRoutedWrapBinding
    ) throws -> Data {
        try MeshRoutedContentKeyWrapper.unwrap(
            wrap,
            binding: binding,
            localFingerprint: identity.localFingerprint,
            localKeyAgreementPublicKey: identity.localKeyAgreementPublicKey,
            staticAgreement: { [identity] ephemeral in
                try identity.heartDropStaticAgreement(withEphemeralPublicKey: ephemeral)
            }
        )
    }

    @Test func theAddressedRecipientUnwrapsTheContentKey() throws {
        let trio = try makeTrio()
        let wrapped = try wrap(trio, for: trio.alice)
        #expect(try open(wrapped, as: trio.alice, binding: trio.binding) == trio.key)
    }

    @Test func aWrapAddressedToAnotherMemberIsRefusedBeforeAnyCrypto() throws {
        let trio = try makeTrio()
        let wrapped = try wrap(trio, for: trio.alice)
        #expect(throws: MeshRoutedKeyWrapError.notAddressedToMe) {
            try open(wrapped, as: trio.bob, binding: trio.binding)
        }
    }

    @Test func aRelabelledWrapCannotBeOpenedByTheNewRecipient() throws {
        let trio = try makeTrio()
        let relabelled = try wrap(trio, for: trio.alice).replacing(recipientFingerprint: trio.bob.localFingerprint)
        #expect(throws: MeshRoutedKeyWrapError.openFailed) {
            try open(relabelled, as: trio.bob, binding: trio.binding)
        }
    }

    /// The DH agrees (alice's key), the KDF agrees (alice's public half) — only the AAD's
    /// recipient differs, so this is the AAD refusing on its own.
    @Test func aRelabelledWrapCannotBeOpenedByTheOriginalRecipientEither() throws {
        let trio = try makeTrio()
        let relabelled = try wrap(trio, for: trio.alice).replacing(recipientFingerprint: trio.bob.localFingerprint)
        let alice = trio.alice
        #expect(throws: MeshRoutedKeyWrapError.openFailed) {
            try MeshRoutedContentKeyWrapper.unwrap(
                relabelled,
                binding: trio.binding,
                localFingerprint: trio.bob.localFingerprint,
                localKeyAgreementPublicKey: alice.localKeyAgreementPublicKey,
                staticAgreement: { ephemeral in try alice.heartDropStaticAgreement(withEphemeralPublicKey: ephemeral) }
            )
        }
    }

    @Test(arguments: MeshRoutedWrapBindingPerturbation.allCases)
    func aWrapBoundToOneManifestOpensUnderNoOtherBinding(perturbation: MeshRoutedWrapBindingPerturbation) throws {
        let trio = try makeTrio()
        let wrapped = try wrap(trio, for: trio.alice)
        let other = perturbation.applied(to: trio.binding)
        #expect(other != trio.binding)
        #expect(throws: MeshRoutedKeyWrapError.openFailed) {
            try open(wrapped, as: trio.alice, binding: other)
        }
        // And still opens under its own.
        #expect(try open(wrapped, as: trio.alice, binding: trio.binding) == trio.key)
    }

    @Test func everyDestinationGetsExactlyOneWrapInDestinationOrder() throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 4)
        let originFingerprint = rig.fingerprints[0]
        let origin = try #require(rig.identities[originFingerprint])
        let target = MeshDeliveryTarget(
            contentID: MeshRoutedManifestFixtures.itemID, roster: rig.roster, selfFingerprint: originFingerprint
        )
        let manifest = try MeshRoutedManifest.signed(
            meshID: rig.meshID,
            target: target,
            typeToken: MeshRoutedManifestFixtures.typeToken,
            contentHash: MeshRoutedManifestFixtures.contentHash,
            size: MeshRoutedManifestFixtures.size,
            createdAt: MeshRoutedManifestFixtures.base,
            hardDeadline: MeshRoutedManifestFixtures.hardDeadline,
            contentKey: MeshRoutedContentKeyWrapper.makeContentKey(),
            recipientKeys: rig.identities.mapValues { $0.localKeyAgreementPublicKey },
            identity: origin
        )
        #expect(manifest.keyWraps.map(\.recipientFingerprint) == manifest.destinations)
        #expect(manifest.keyWraps.count == 3)
        let allWellFormed = manifest.keyWraps.allSatisfy(\.isWellFormed)
        #expect(allWellFormed)
    }

    @Test func eachWrapUsesAFreshEphemeralKeyAndNonce() throws {
        let trio = try makeTrio()
        let first = try wrap(trio, for: trio.alice)
        let second = try wrap(trio, for: trio.alice)
        #expect(first.ephemeralPublicKey != second.ephemeralPublicKey)
        #expect(first.nonce != second.nonce)
        #expect(first.sealedKey != second.sealedKey)
        #expect(try open(first, as: trio.alice, binding: trio.binding) == trio.key)
        #expect(try open(second, as: trio.alice, binding: trio.binding) == trio.key)
    }

    @Test func theWrapWidthsAreFixed() throws {
        let trio = try makeTrio()
        let wrapped = try wrap(trio, for: trio.alice)
        #expect(wrapped.ephemeralPublicKey.count == 32)
        #expect(wrapped.nonce.count == 12)
        #expect(wrapped.sealedKey.count == 48)
        #expect(wrapped.isWellFormed)
    }

    @Test func aTamperedSealedKeyDoesNotOpen() throws {
        let trio = try makeTrio()
        let wrapped = try wrap(trio, for: trio.alice)
        var sealedKey = wrapped.sealedKey
        sealedKey[sealedKey.startIndex] ^= 0x01
        #expect(throws: MeshRoutedKeyWrapError.openFailed) {
            try open(wrapped.replacing(sealedKey: sealedKey), as: trio.alice, binding: trio.binding)
        }
    }

    /// The width check precedes the DH: the closure is never called.
    @Test func aMalformedWrapIsRefusedBeforeKeyAgreement() throws {
        let trio = try makeTrio()
        let malformed = try wrap(trio, for: trio.alice).replacing(nonce: Data(repeating: 0x12, count: 11))
        let alice = trio.alice
        var agreements = 0
        do {
            _ = try MeshRoutedContentKeyWrapper.unwrap(
                malformed,
                binding: trio.binding,
                localFingerprint: alice.localFingerprint,
                localKeyAgreementPublicKey: alice.localKeyAgreementPublicKey,
                staticAgreement: { ephemeral in
                    agreements += 1
                    return try alice.heartDropStaticAgreement(withEphemeralPublicKey: ephemeral)
                }
            )
            Issue.record("a malformed wrap opened")
        } catch MeshRoutedKeyWrapError.malformed {
            // expected
        } catch {
            Issue.record("unexpected error \(error)")
        }
        #expect(agreements == 0)
    }

    @Test func aWrapToAnInvalidRecipientKeyIsRefusedByName() throws {
        let trio = try makeTrio()
        #expect(throws: MeshRoutedKeyWrapError.invalidRecipientKey(fingerprint: "fp999")) {
            try MeshRoutedContentKeyWrapper.wrap(
                contentKey: trio.key,
                recipientFingerprint: "fp999",
                recipientKeyAgreementPublicKey: Data(repeating: 0x01, count: 31),
                binding: trio.binding
            )
        }
    }

    @Test func aWrapOfANon32ByteKeyIsRefused() throws {
        let trio = try makeTrio()
        #expect(throws: MeshRoutedKeyWrapError.invalidContentKey) {
            try MeshRoutedContentKeyWrapper.wrap(
                contentKey: Data(count: 16),
                recipientFingerprint: trio.alice.localFingerprint,
                recipientKeyAgreementPublicKey: trio.alice.localKeyAgreementPublicKey,
                binding: trio.binding
            )
        }
    }

    @Test func twoContentKeysAreNeverEqual() {
        let first = MeshRoutedContentKeyWrapper.makeContentKey()
        let second = MeshRoutedContentKeyWrapper.makeContentKey()
        #expect(first.count == 32)
        #expect(second.count == 32)
        #expect(first != second)
    }

    /// The closure's own error propagates: an unprovisioned identity is `notProvisioned`, never a
    /// failed open. Called directly with alice's PUBLIC material, because an unprovisioned
    /// service's `localFingerprint` is `""` and would land on `notAddressedToMe` before the closure.
    @Test func anUnprovisionedRecipientSurfacesItsOwnError() throws {
        let trio = try makeTrio()
        let unprovisioned = IdentityService(keychainService: "test.mesh.routedwrap.unprovisioned.\(UUID().uuidString)")
        defer { ProximityKeychainItem.deleteAll(service: unprovisioned.keychainService) }
        let wrapped = try wrap(trio, for: trio.alice)
        let alice = trio.alice
        #expect(throws: IdentityError.notProvisioned) {
            try MeshRoutedContentKeyWrapper.unwrap(
                wrapped,
                binding: trio.binding,
                localFingerprint: alice.localFingerprint,
                localKeyAgreementPublicKey: alice.localKeyAgreementPublicKey,
                staticAgreement: { ephemeral in
                    try unprovisioned.heartDropStaticAgreement(withEphemeralPublicKey: ephemeral)
                }
            )
        }
    }

    @Test func everyWrapErrorHasAFrozenDiagnostic() {
        let errors: [MeshRoutedKeyWrapError] = [
            .invalidRecipientKey(fingerprint: "fp999"), .invalidContentKey, .notAddressedToMe, .malformed, .openFailed
        ]
        let allNamed = errors.allSatisfy { !$0.diagnosticDescription.isEmpty }
        #expect(allNamed)
    }
}
