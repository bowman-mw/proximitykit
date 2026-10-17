// IdentityServiceTests.swift
// ProximityKitTests
//
// Tests for IdentityService (Phase 7.1).
// Every test uses a UUID-scoped Keychain service and cleans up in a defer block
// so tests never touch each other's state and never reach the production service.

@testable import ProximityKit
import Foundation
import Testing
import CryptoKit

@MainActor
@Suite(.serialized)
struct IdentityServiceTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer
    /// has run before a cell's identities reach the keychain.
    let keychain = PackageTestEnvironment.keychain

    // MARK: - Harness helpers

    private func makeService() -> (IdentityService, String) {
        let serviceID = "com.fernlet.identity.test.\(UUID().uuidString)"
        return (IdentityService(keychainService: serviceID), serviceID)
    }

    private func cleanup(_ serviceID: String) {
        ProximityKeychainItem.deleteAll(service: serviceID)
    }

    // MARK: - Provisioning

    @Test func ensureProvisionedCreatesIdentityOnFirstCall() throws {
        let (svc, id) = makeService()
        defer { cleanup(id) }

        #expect(ProximityKeychainItem.load(account: ProximityNamespace.packageTest.installation.keychain.identity.signingPrivateKey, service: id) == nil,
                "Keychain should be empty before provisioning")

        try svc.ensureProvisioned()

        #expect(ProximityKeychainItem.load(account: ProximityNamespace.packageTest.installation.keychain.identity.signingPrivateKey, service: id) != nil)
        #expect(ProximityKeychainItem.load(account: ProximityNamespace.packageTest.installation.keychain.identity.keyAgreementPrivateKey, service: id) != nil)
        #expect(!svc.localSigningPublicKey.isEmpty)
        #expect(!svc.localKeyAgreementPublicKey.isEmpty)
    }

    @Test func ensureProvisionedIsIdempotent() throws {
        let (svc, id) = makeService()
        defer { cleanup(id) }

        try svc.ensureProvisioned()
        let pubKey1 = svc.localSigningPublicKey
        let kaKey1  = svc.localKeyAgreementPublicKey

        try svc.ensureProvisioned()

        #expect(svc.localSigningPublicKey == pubKey1)
        #expect(svc.localKeyAgreementPublicKey == kaKey1)
    }

    @Test func ensureProvisionedLoadsExistingIdentityFromKeychain() throws {
        let (svc1, id) = makeService()
        defer { cleanup(id) }
        try svc1.ensureProvisioned()
        let pubKey1 = svc1.localSigningPublicKey

        let svc2 = IdentityService(keychainService: id)
        try svc2.ensureProvisioned()

        #expect(svc2.localSigningPublicKey == pubKey1,
                "New instance should load the same identity from Keychain")
    }

    // MARK: - Signing

    /// A signature purpose whose transcripts really are the concatenation `purpose ‖ payload`, which
    /// is how the three round-trip tests below build their bytes.
    ///
    /// It matters which one: these used to name `identityEnvelopeV2`, whose transcripts come out of
    /// `CanonicalByteWriter` with the domain as a LENGTH-PREFIXED field, not a raw prefix. A
    /// hand-concatenated transcript under that purpose is mis-framed, and the guard at the signing
    /// boundary is supposed to reject it — see `signRefusesAMisframedTranscript`.
    private static let rawPrefixedPurpose = ProximityNamespace.packageTest.family.purposes.signature.proximityQRResponseV1

    @Test func signAndVerifyRoundTrip() throws {
        let (svc, id) = makeService()
        defer { cleanup(id) }
        try svc.ensureProvisioned()

        let purpose = Self.rawPrefixedPurpose
        let data = purpose.data + Data("hello world".utf8)
        let sig  = try svc.sign(data, purpose: purpose)

        #expect(IdentityService.verify(sig, of: data, by: svc.localSigningPublicKey, purpose: purpose))
    }

    @Test func verifyRejectsTamperedData() throws {
        let (svc, id) = makeService()
        defer { cleanup(id) }
        try svc.ensureProvisioned()

        let purpose = Self.rawPrefixedPurpose
        let data = purpose.data + Data("hello world".utf8)
        let sig  = try svc.sign(data, purpose: purpose)

        var tampered = data
        tampered[0] ^= 0xFF

        #expect(!IdentityService.verify(sig, of: tampered, by: svc.localSigningPublicKey, purpose: purpose))
    }

    @Test func verifyRejectsWrongPublicKey() throws {
        let (svc1, id1) = makeService()
        defer { cleanup(id1) }
        try svc1.ensureProvisioned()

        let (svc2, id2) = makeService()
        defer { cleanup(id2) }
        try svc2.ensureProvisioned()

        let purpose = Self.rawPrefixedPurpose
        let data = purpose.data + Data("hello".utf8)
        let sig  = try svc1.sign(data, purpose: purpose)

        #expect(!IdentityService.verify(sig, of: data, by: svc2.localSigningPublicKey, purpose: purpose))
    }

    /// The signing boundary refuses bytes that do not carry their purpose in that purpose's own
    /// framing — the property that makes `sign` something other than an unscoped signing oracle.
    ///
    /// Pinned here, at the boundary, as well as inside `ProximityCryptographicPurpose`: the check is only
    /// worth anything if it is actually wired into `sign`/`verify`. The transcript below is the
    /// mistake that is easy to make — the domain concatenated raw under a purpose whose serializer
    /// length-prefixes it — and it must throw rather than sign.
    @Test func signRefusesAMisframedTranscript() throws {
        let (svc, id) = makeService()
        defer { cleanup(id) }
        try svc.ensureProvisioned()

        let canonical = ProximityNamespace.packageTest.family.purposes.signature.identityEnvelopeV2
        let misframed = canonical.data + Data("hello world".utf8)

        #expect(throws: IdentityError.invalidKeyData) {
            _ = try svc.sign(misframed, purpose: canonical)
        }
        #expect(!IdentityService.verify(
            Data(repeating: 0, count: 64), of: misframed,
            by: svc.localSigningPublicKey, purpose: canonical
        ))
    }

    // MARK: - Fingerprint

    @Test func localFingerprintIsStable() throws {
        let (svc, id) = makeService()
        defer { cleanup(id) }
        try svc.ensureProvisioned()

        #expect(svc.localFingerprint == svc.localFingerprint)
        #expect(!svc.localFingerprint.isEmpty)
    }

    @Test func localFingerprintIs16HexChars() throws {
        let (svc, id) = makeService()
        defer { cleanup(id) }
        try svc.ensureProvisioned()

        let fp = svc.localFingerprint
        #expect(fp.count == 16)
        #expect(fp.allSatisfy { $0.isHexDigit })
    }

    @Test func fingerprintMatcherRejectsLegacyEightCharacterPrefix() throws {
        // Tightened 2026-07-25 (bitchat-adoptions follow-up): an 8-hex prefix is a 32-bit,
        // grindable binding. The vault normalizes stored legacy rows back to 16 chars, so the
        // matcher accepts ONLY exact 16-char equality (case-insensitive).
        let (svc, id) = makeService()
        defer { cleanup(id) }
        try svc.ensureProvisioned()

        let canonical = svc.localFingerprint
        let legacy = String(canonical.prefix(8))
        #expect(!IdentityService.fingerprintsMatch(canonical, legacy))
        #expect(!IdentityService.fingerprintsMatch(legacy, canonical))
        #expect(!IdentityService.fingerprintsMatch(legacy, legacy), "even two identical short values must not match")
        #expect(!IdentityService.fingerprintsMatch(canonical, String(canonical.dropLast()) ))
        #expect(IdentityService.fingerprintsMatch(canonical, canonical))
        #expect(IdentityService.fingerprintsMatch(canonical, canonical.uppercased()))
    }

    @Test func fingerprintOfDifferentKeysDiffers() {
        var fingerprints = Set<String>()
        for _ in 0..<100 {
            let key = Curve25519.Signing.PrivateKey()
            fingerprints.insert(IdentityService.fingerprint(of: key.publicKey.rawRepresentation))
        }
        #expect(fingerprints.count == 100,
                "All 100 randomly generated keys should produce distinct fingerprints")
    }

    // MARK: - Seal / Open

    @Test func sealOpenRoundTrip() throws {
        let (alice, aliceID) = makeService()
        defer { cleanup(aliceID) }
        try alice.ensureProvisioned()

        let (bob, bobID) = makeService()
        defer { cleanup(bobID) }
        try bob.ensureProvisioned()

        let plaintext = Data("secret message".utf8)
        let sealed = try alice.seal(plaintext, to: bob.localKeyAgreementPublicKey)
        let opened = try bob.open(sealed, from: alice.localKeyAgreementPublicKey)

        #expect(opened == plaintext)
    }

    @Test func openRejectsTamperedCiphertext() throws {
        let (alice, aliceID) = makeService()
        defer { cleanup(aliceID) }
        try alice.ensureProvisioned()

        let (bob, bobID) = makeService()
        defer { cleanup(bobID) }
        try bob.ensureProvisioned()

        var sealed = try alice.seal(Data("secret".utf8), to: bob.localKeyAgreementPublicKey)
        sealed[sealed.count - 1] ^= 0xFF

        #expect(throws: IdentityError.openFailed) {
            try bob.open(sealed, from: alice.localKeyAgreementPublicKey)
        }
    }

    @Test func openRejectsWrongRecipientKey() throws {
        let (bob, bobID) = makeService()
        defer { cleanup(bobID) }
        try bob.ensureProvisioned()

        let (carol, carolID) = makeService()
        defer { cleanup(carolID) }
        try carol.ensureProvisioned()

        let (eve, eveID) = makeService()
        defer { cleanup(eveID) }
        try eve.ensureProvisioned()

        // Bob seals to Carol; Eve tries to open
        let sealed = try bob.seal(Data("for carol".utf8), to: carol.localKeyAgreementPublicKey)

        #expect(throws: IdentityError.openFailed) {
            try eve.open(sealed, from: bob.localKeyAgreementPublicKey)
        }
    }

    /// Phase 4 of the crypto standardization round deleted the pre-`FPT2` transport read — the
    /// branch that opened a seal under the sender's bare static key with no typed AEAD purpose.
    /// Bytes in that shape must be refused with a DIFFERENT error from a tampered or misaddressed
    /// payload: it is the only thing that lets the Connection Inspector separate "these bytes never
    /// reached the AEAD" from "the AEAD rejected them".
    @Test func openRefusesUnmarkedLegacyTransportByName() throws {
        let (alice, aliceID) = makeService()
        defer { cleanup(aliceID) }
        try alice.ensureProvisioned()

        let (bob, bobID) = makeService()
        defer { cleanup(bobID) }
        try bob.ensureProvisioned()

        let sealed = try alice.seal(Data("secret".utf8), to: bob.localKeyAgreementPublicKey)
        let unmarked = Data(sealed.dropFirst(4))   // strip `FPT2`: the pre-marker layout

        #expect(throws: IdentityError.legacyWireFormat) {
            try bob.open(unmarked, from: alice.localKeyAgreementPublicKey)
        }
    }

    // MARK: - Wipe

    @Test func wipeRemovesAllKeyMaterial() throws {
        let (svc, id) = makeService()
        defer { cleanup(id) }
        try svc.ensureProvisioned()
        let fp1 = svc.localFingerprint

        try svc.wipe()

        #expect(svc.localSigningPublicKey.isEmpty, "Public key should be cleared after wipe")
        #expect(ProximityKeychainItem.load(account: ProximityNamespace.packageTest.installation.keychain.identity.signingPrivateKey, service: id) == nil,
                "Keychain entry should be gone after wipe")

        try svc.ensureProvisioned()
        let fp2 = svc.localFingerprint

        #expect(fp1 != fp2, "Fresh identity after wipe should have a different fingerprint")
    }
}
