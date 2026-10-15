// PackageTestNamespace.swift
//
// ProximityKit plan step A1.1: the namespace ProximityKit's package tests compute under, `.packageTest`,
// built from ProximityKit's public API alone out of literals no app ships: `pktest.*` labels in the
// shapes Fernlet's take (legacy peers accepted, two feature salts), `_pktest-*._udp` radios with the
// presence prefix `pk-`, `org.example.pktest.*` keychain services and a peer-name cap of 24. A twin: the
// same file at FernletKit/Tests/ProximityKitTests/TestSupport and Tests/FernletTests, held identical but
// for its imports by CIGateSelectorBoundaryTests.everyTwinMatchesItsOriginal(), because the package's
// suites compute under it (through TestSupport/PackageTestBindings.swift) while FernletTests holds it
// disjoint from Fernlet's namespace, which the package cannot name, and a test target cannot import
// another. It is declared at each level a binding hands ProximityKit (the namespace, its family and its
// labels) and its installation, as Fernlet's namespace is.

import Foundation
import ProximityKit

// MARK: - The namespace

extension ProximityNamespace {

    /// The namespace ProximityKit's package tests compute under: the package tests' family and
    /// installation. Sound by construction (`PackageTestSupportTests` in the package holds it so), and
    /// overlapping Fernlet's namespace nowhere (`ProximityNamespaceGoldenTests` in FernletTests holds
    /// that from both sides), so a package suite never signs, derives, advertises or stores under one of
    /// Fernlet's labels, radio values or rows.
    static let packageTest = ProximityNamespace(family: .packageTest, installation: .packageTest)
}

// MARK: - Family

extension ProximityNamespace.Family {

    /// The package tests' 41 labels, three radios, `pktest` QR scheme and payload vocabulary.
    static let packageTest = ProximityNamespace.Family(
        purposes: .packageTest,
        radios: PackageTestLiterals.radios,
        verifyQR: ProximityNamespace.VerifyQR(urlScheme: "pktest"),
        vocabulary: PackageTestLiterals.vocabulary
    )
}

extension ProximityNamespace.Purposes {

    /// The package tests' 41 domain-separation labels: 39 protocol labels, the verify-only legacy pair
    /// among them, then two feature salts, in the groups Fernlet's take.
    static let packageTest = ProximityNamespace.Purposes(
        signature: PackageTestLiterals.signature,
        keyDerivation: PackageTestLiterals.keyDerivation,
        aead: PackageTestLiterals.aead,
        hash: PackageTestLiterals.hash,
        feature: PackageTestLiterals.feature
    )
}

// MARK: - Installation

extension ProximityNamespace.Installation {

    /// The package tests' keychain rows, storage names, log subsystem and peer-name policy: every
    /// service under `org.example.pktest`, the folder `PackageTest`, and a peer's name shown at most 24
    /// characters long, as Fernlet's is, or as "A test peer".
    static let packageTest = ProximityNamespace.Installation(
        keychain: ProximityNamespace.Keychain(
            identity: ProximityNamespace.Keychain.IdentityRows(
                service: "org.example.pktest.identity", signingPrivateKey: "signing.private",
                keyAgreementPrivateKey: "agreement.private", signingPublicKeyCache: "signing.public",
                keyAgreementPublicKeyCache: "agreement.public"),
            meshSessionSealKey: ProximityNamespace.Keychain.Row(service: "org.example.pktest.mesh-session",
                                                                account: "session.seal"),
            meshRoutedSealKey: ProximityNamespace.Keychain.Row(service: "org.example.pktest.mesh-routed",
                                                               account: "routed.seal")),
        storage: ProximityNamespace.Storage(
            directoryName: "PackageTest", meshSessionContextFileName: "Session.sealed",
            meshRoutedIndexFileName: "Routed.sealed", meshRoutedChunkDirectoryName: "RoutedChunks"),
        logSubsystem: "org.example.pktest",
        peerNames: ProximityNamespace.PeerNames(maxLength: 24, floor: "A test peer")
    )
}

// MARK: - The literals

/// `.packageTest`'s groups, each built once from its literals. Labels are source literals
/// (`StaticString`), as ProximityKit requires of every label; tokens are strings.
private enum PackageTestLiterals {

    /// Nineteen signature labels, and the legacy pair accepted (verify-only), as Fernlet's family has.
    static let signature = ProximityNamespace.Signature(
        identityEnvelopeV2: "pktest.canonical.identity-envelope.v2",
        meshAdmissionTokenV2: "pktest.canonical.mesh-admission-token.v2",
        meshChannelIntroductionV1: "pktest.mesh.channel-introduction.v1",
        meshMemberDepartureV1: "pktest.mesh.member-departure.v1",
        meshMemberRemovalV1: "pktest.mesh.member-removal.v1",
        meshTerminatedV1: "pktest.mesh.terminated.v1",
        meshInventoryDigestV1: "pktest.mesh.inventory-digest.v1",
        meshEpochHeadsV1: "pktest.mesh.epoch-heads.v1",
        meshRemovalProposalV1: "pktest.mesh.removal-proposal.v1",
        meshRemovalVoteV1: "pktest.mesh.removal-vote.v1",
        meshKeyAgreementV1: "pktest.mesh.key-agreement.v1",
        meshRoutedManifestV1: "pktest.mesh.routed-manifest.v1",
        meshRoutedChunkV1: "pktest.mesh.routed-chunk.v1",
        meshCustodyReceiptV1: "pktest.mesh.custody-receipt.v1",
        meshRecipientReceiptV1: "pktest.mesh.recipient-receipt.v1",
        meshRoutedInventoryDigestV1: "pktest.mesh.routed-inventory-digest.v1",
        meshRoutedDrainAnswerV1: "pktest.mesh.routed-drain-answer.v1",
        proximityQRIdentityV1: "pktest.verify.qr.v1",
        proximityQRResponseV1: "pktest.verify.response.v1",
        legacyV1: .accepted(
            identityEnvelopeV1: "pktest.canonical.identity-envelope.v1",
            meshAdmissionTokenV1: "pktest.canonical.mesh-admission-token.v1"
        )
    )

    /// The six key-derivation labels.
    static let keyDerivation = ProximityNamespace.KeyDerivation(
        proximityTransportV1: "pktest.proximity.v1",
        meshGroupKeyWrapV1: "pktest.mesh.groupkey.v1",
        meshTLSExporterV1: "pktest.mesh.tls-exporter.v1",
        meshRoutedContentKeyWrapV1: "pktest.mesh.routed.content-key.v1",
        meshSessionContextV1: "pktest.mesh.session-context.v1",
        meshRoutedStoreV1: "pktest.mesh.routed-store.v1"
    )

    /// The five AEAD labels.
    static let aead = ProximityNamespace.AEAD(
        proximityTransportV2: "pktest.proximity.transport.aead.v2",
        meshGroupKeyWrapV2: "pktest.mesh.groupkey.wrap.aead.v2",
        meshEncryptedMetadataV2: "pktest.mesh.encrypted-metadata.aead.v2",
        meshRoutedContentKeyWrapV1: "pktest.mesh.routed.content-key.wrap.aead.v1",
        meshRoutedItemV1: "pktest.mesh.routed.item.aead.v1"
    )

    /// The seven hash labels, the epoch id's domain last.
    static let hash = ProximityNamespace.Hash(
        meshInventoryDigestV1: "pktest.mesh.inventory-digest.hash.v1",
        meshRoutedContentV1: "pktest.mesh.routed-content.hash.v1",
        meshRoutedChunkV1: "pktest.mesh.routed-chunk.hash.v1",
        meshRoutedChunkIDV1: "pktest.mesh.routed-chunk-id.hash.v1",
        meshCustodyReceiptIDV1: "pktest.mesh.custody-receipt-id.hash.v1",
        meshRecipientReceiptIDV1: "pktest.mesh.recipient-receipt-id.hash.v1",
        meshEpochIDV1: "pktest.mesh.epoch.v1"
    )

    /// Two pair-secret salts, as Fernlet's family declares two: a drop pair's, then a nearby pair's.
    static let feature = ProximityNamespace.FeaturePurposes([
        "dropPairV1": ProximityCryptographicPurpose.featureKeyDerivationSalt("pktest.feature.drop-pair.v1"),
        "nearPairV1": ProximityCryptographicPurpose.featureKeyDerivationSalt("pktest.feature.near-pair.v1")
    ])

    /// The mesh, presence and pair radios, the heartbeat datagram, the mesh instance-name prefix, the
    /// presence one (two letters and its `-`, as Fernlet's) and the certificates' common name.
    static let radios = ProximityNamespace.Radios(
        mesh: ProximityNamespace.Radio(serviceType: "_pktest-mesh._udp", alpn: "pktest-mesh-v1"),
        presence: ProximityNamespace.Radio(serviceType: "_pktest-near._udp", alpn: "pktest-near-v1"),
        pair: ProximityNamespace.Radio(serviceType: "_pktest-pair._udp", alpn: "pktest-pair-v1"),
        meshHeartbeat: Data("pktest-mesh-heartbeat".utf8),
        meshInstanceNamePrefix: "pktest-mesh-",
        presenceInstanceNamePrefix: "pk-",
        tlsCommonName: "pktest-mesh"
    )

    /// The package tests' token for the mesh message named `name`.
    static func meshToken(_ name: String) -> String { "pktest.mesh.\(name).v1" }

    /// The payload vocabulary: three session messages; the payload rules over those three, three
    /// features' tokens and the thirty mesh messages, the notes, the sketches and the two verify
    /// messages arriving sealed; three capabilities, the notes assumed for a legacy peer; the four
    /// record kinds; the four routed types; and the mesh messages.
    static let vocabulary = ProximityNamespace.Vocabulary(
        session: ProximityNamespace.SessionMessages(
            identityIntroduction: ProximityNamespace.SessionMessage(payloadType: "pktest.session.hello.v1",
                                                                    summaryTitle: "Test hello"),
            identityAcknowledge: ProximityNamespace.SessionMessage(payloadType: "pktest.session.welcome.v1",
                                                                   summaryTitle: "Test welcome"),
            heartbeat: ProximityNamespace.Heartbeat(payloadType: "pktest.session.beat.v1", pingTitle: "Test beat",
                                                    replyTitle: "Test beat back")),
        payloads: ProximityNamespace.PayloadRules(
            known: Set(["pktest.session.hello.v1", "pktest.session.welcome.v1", "pktest.session.beat.v1",
                        "pktest.note.v1", "pktest.sketch.v1", "pktest.wave.v1"]
                       + ProximityNamespace.MeshMessages.tokens(meshToken)),
            sealingRequired: ["pktest.note.v1", "pktest.sketch.v1", meshToken("verifyChallenge"),
                              meshToken("verifyResponse")]),
        capabilities: ProximityNamespace.Capabilities(
            known: ["pktest-notes", "pktest-sketches", "pktest-framing"], wire2: "pktest-framing",
            assumedForLegacyPeers: ["pktest-notes"]),
        membershipRecordKinds: ProximityNamespace.MembershipRecordKinds(
            admission: "pktest.member.joined.v1", departure: "pktest.member.left.v1",
            removal: "pktest.member.removed.v1", termination: "pktest.group.ended.v1"),
        routedTypes: ProximityNamespace.RoutedTypes(
            photo: "pktest.routed.picture.v1", tempMessage: "pktest.routed.note.v1",
            heart: "pktest.routed.wave.v1", control: "pktest.routed.control.v1"),
        mesh: .spelled(meshToken)
    )
}
