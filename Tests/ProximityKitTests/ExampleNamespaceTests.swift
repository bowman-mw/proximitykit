// ExampleNamespaceTests.swift
// ProximityKitTests
//
// ProximityKit plan step A1.2: the example app, Examples/ProximityPing, runs under a namespace of its own,
// `.proximityPing`, and these cells hold it apart. The plan asks that the example's labels never validate
// as Fernlet's; the package cannot name Fernlet's namespace, so `.packageTest`, the package tests' own,
// stands in for "another app's", and the cells hold the property both ways: the example's namespace is
// sound, shares no label, radio value or keychain row with `.packageTest`, and nothing signed under one
// verifies under the other. A test target cannot import an app target, so the suite compiles a twin of the
// example's namespace file, TestSupport/PingNamespace.swift, which the last cell holds byte for byte to
// Examples/ProximityPing/ProximityPing/PingNamespace.swift.

import Foundation
import ProximityKit
import Testing

/// The example app's namespace stays its own: sound, disjoint from the package tests' namespace, and
/// unable to verify, or be verified by, anything signed under it; and its twin here is the example's file.
@MainActor
@Suite struct ExampleNamespaceTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so every identity
    /// here provisions into it.
    let keychain = PackageTestEnvironment.keychain

    /// `.proximityPing` passes every soundness rule, and validating its parts gives it back.
    @Test func theExamplesNamespaceIsSound() throws {
        let namespace = ProximityNamespace.proximityPing
        #expect(namespace.soundness == .sound, "the example's namespace is unsound: \(namespace.soundness)")
        let validated = try ProximityNamespace.validated(
            family: namespace.family, installation: namespace.installation)
        #expect(validated == namespace)
    }

    /// No label of either namespace equals or prefixes the other's, no radio value, heartbeat or QR
    /// scheme is shared, and no keychain service, folder or log subsystem either, read from both sides.
    @Test func theExampleAndThePackageTestsShareNothing() {
        let example = ProximityNamespace.proximityPing
        let other = ProximityNamespace.packageTest
        #expect(example.familyCollisions(with: other).isEmpty, "\(example.familyCollisions(with: other))")
        #expect(other.familyCollisions(with: example).isEmpty, "\(other.familyCollisions(with: example))")
        #expect(example.installationCollisions(with: other).isEmpty)
        #expect(other.installationCollisions(with: example).isEmpty)
        #expect(example.labelRows.count == 37, "the 39 protocol labels less the legacy pair the example refuses")
    }

    /// A ping envelope an example identity signs and seals verifies at another example identity and is
    /// refused, `signatureInvalid`, at a `.packageTest` identity; and one a `.packageTest` identity signs
    /// is refused at an example identity.
    @Test func anEnvelopeMintedUnderOneNamespaceNeverVerifiesUnderTheOther() throws {
        let sender = PackageTestHost(namespace: .proximityPing).makeProximityIdentity()
        let peer = PackageTestHost(namespace: .proximityPing).makeProximityIdentity()
        let foreign = PackageTestHost(namespace: .packageTest).makeProximityIdentity()
        try sender.ensureProvisioned()
        try peer.ensureProvisioned()
        try foreign.ensureProvisioned()

        let plaintext = Data("{\"seq\":1}".utf8)
        let envelope = try ProximityIdentityEnvelope.signed(
            identityService: sender, senderDisplayName: "Ping", payloadTypeToken: PingPayload.ping,
            payloadEncryption: .sealedTo(recipientKeyAgreementPublicKey: peer.localKeyAgreementPublicKey),
            payloadSummary: PayloadSummary(title: "Ping"),
            payload: try sender.seal(plaintext, to: peer.localKeyAgreementPublicKey))
        #expect(try envelope.verify(identityService: peer, replayCache: ReplayCache()) == plaintext)
        #expect(throws: ProximityIdentityEnvelope.VerifyError.signatureInvalid) {
            try envelope.verify(identityService: foreign, replayCache: ReplayCache())
        }

        let reverse = try ProximityIdentityEnvelope.signed(
            identityService: foreign, senderDisplayName: "Test", payloadTypeToken: "pktest.wave.v1",
            payloadSummary: PayloadSummary(title: "Wave"), payload: plaintext)
        #expect(throws: ProximityIdentityEnvelope.VerifyError.signatureInvalid) {
            try reverse.verify(identityService: peer, replayCache: ReplayCache())
        }
    }

    /// A signature over a transcript framed for any example signature label verifies under that label
    /// and under no `.packageTest` label that binds a domain. The legacy pair (`.signature(.absent)`)
    /// is left out on purpose: it binds no domain and accepts every transcript, which is why a family
    /// that accepts legacy formats verifies them only through their own legacy shapes.
    @Test func everyExampleSignatureIsRefusedUnderEveryOtherLabel() throws {
        let identity = PackageTestHost(namespace: .proximityPing).makeProximityIdentity()
        try identity.ensureProvisioned()
        let key = identity.localSigningPublicKey
        let others = ProximityNamespace.packageTest.labelRows.map(\.purpose)
            .filter { $0.role != .signature(.absent) }
        var signed = 0
        // R2: bounded by the example's 37 label rows, each against `.packageTest`'s 39 domain-binding labels.
        for row in ProximityNamespace.proximityPing.labelRows
        where row.purpose.role == .signature(.lengthPrefixed) || row.purpose.role == .signature(.rawPrefix) {
            let transcript = row.purpose.prefixBytes + Data("the same bytes".utf8)
            let signature = try identity.sign(transcript, purpose: row.purpose)
            #expect(IdentityService.verify(signature, of: transcript, by: key, purpose: row.purpose), "\(row.field)")
            for other in others {
                #expect(!IdentityService.verify(signature, of: transcript, by: key, purpose: other),
                        "\(row.field) verified under \(other.rawValue)")
            }
            signed += 1
        }
        #expect(signed == 19, "the 17 canonical and 2 fixed-width signature labels")
    }

    /// The twin this suite compiles is the example's own file, byte for byte, so a label the example
    /// changes is a label these cells read.
    @Test func theTwinIsTheExamplesFile() throws {
        let twin = try String(
            contentsOf: PackageRoot.url("Tests").appendingPathComponent("ProximityKitTests/TestSupport/PingNamespace.swift"),
            encoding: .utf8)
        let original = try PackageRoot.source("Examples/ProximityPing/ProximityPing/PingNamespace.swift")
        #expect(twin == original, "TestSupport/PingNamespace.swift drifted from the example's")
    }
}
