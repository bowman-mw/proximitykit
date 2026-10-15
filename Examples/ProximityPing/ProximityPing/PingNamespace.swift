// PingNamespace.swift
// ProximityPing
//
// The example's protocol namespace: every label, radio value, token, keychain row and file name
// ProximityKit reads, spelled for this app and for no other. Labels begin `proximityping.`, the
// radios are `_proxping-*._udp`, and the keychain rows sit under `org.example.proximityping`, so
// nothing here can validate as another app's bytes, share its keychain rows, or browse its radios.
//
// ProximityKit offers no default namespace and no builder: a label is a source literal
// (`StaticString`), so a host spells each one. That is most of this file.

import Foundation
import ProximityKit

extension ProximityNamespace {

    /// The example's namespace: its own family (labels, radios, QR scheme, vocabulary) and its own
    /// installation (keychain rows, storage names, log subsystem, peer-name policy).
    nonisolated static let proximityPing = ProximityNamespace(
        family: ProximityNamespace.Family(
            purposes: ProximityPingLiterals.purposes,
            radios: ProximityPingLiterals.radios,
            verifyQR: ProximityNamespace.VerifyQR(urlScheme: "proxping"),
            vocabulary: ProximityPingLiterals.vocabulary
        ),
        installation: ProximityPingLiterals.installation
    )
}

extension ProximityPairProfile {

    /// The one kind of connection the example makes: a pair session on its namespace's pair radio,
    /// advertising and believing the TXT mode `ping`.
    nonisolated static let proximityPing = ProximityPairProfile(
        auditArea: "ping",
        radio: ProximityNamespace.proximityPing.family.radios.pair,
        advertisementMode: "ping"
    )
}

/// The example's two payload tokens: a ping, and the pong that answers it. Both are in the
/// namespace's `payloads.known` and must arrive sealed.
nonisolated enum PingPayload {
    /// A ping's payload token.
    static let ping = "proximityping.ping.v1"
    /// A pong's payload token.
    static let pong = "proximityping.pong.v1"
}

/// The example namespace's literals, one group per property.
private nonisolated enum ProximityPingLiterals {

    /// The protocol labels: 37 of the 39, all but the legacy pair, because the family refuses legacy
    /// formats; and no feature salts.
    static let purposes = ProximityNamespace.Purposes(
        signature: ProximityNamespace.Signature(
            identityEnvelopeV2: "proximityping.canonical.identity-envelope.v2",
            meshAdmissionTokenV2: "proximityping.canonical.mesh-admission-token.v2",
            meshChannelIntroductionV1: "proximityping.mesh.channel-introduction.v1",
            meshMemberDepartureV1: "proximityping.mesh.member-departure.v1",
            meshMemberRemovalV1: "proximityping.mesh.member-removal.v1",
            meshTerminatedV1: "proximityping.mesh.terminated.v1",
            meshInventoryDigestV1: "proximityping.mesh.inventory-digest.v1",
            meshEpochHeadsV1: "proximityping.mesh.epoch-heads.v1",
            meshRemovalProposalV1: "proximityping.mesh.removal-proposal.v1",
            meshRemovalVoteV1: "proximityping.mesh.removal-vote.v1",
            meshKeyAgreementV1: "proximityping.mesh.key-agreement.v1",
            meshRoutedManifestV1: "proximityping.mesh.routed-manifest.v1",
            meshRoutedChunkV1: "proximityping.mesh.routed-chunk.v1",
            meshCustodyReceiptV1: "proximityping.mesh.custody-receipt.v1",
            meshRecipientReceiptV1: "proximityping.mesh.recipient-receipt.v1",
            meshRoutedInventoryDigestV1: "proximityping.mesh.routed-inventory-digest.v1",
            meshRoutedDrainAnswerV1: "proximityping.mesh.routed-drain-answer.v1",
            proximityQRIdentityV1: "proximityping.verify.qr.v1",
            proximityQRResponseV1: "proximityping.verify.response.v1",
            legacyV1: .refused
        ),
        keyDerivation: ProximityNamespace.KeyDerivation(
            proximityTransportV1: "proximityping.proximity.v1",
            meshGroupKeyWrapV1: "proximityping.mesh.groupkey.v1",
            meshTLSExporterV1: "proximityping.mesh.tls-exporter.v1",
            meshRoutedContentKeyWrapV1: "proximityping.mesh.routed.content-key.v1",
            meshSessionContextV1: "proximityping.mesh.session-context.v1",
            meshRoutedStoreV1: "proximityping.mesh.routed-store.v1"
        ),
        aead: ProximityNamespace.AEAD(
            proximityTransportV2: "proximityping.proximity.transport.aead.v2",
            meshGroupKeyWrapV2: "proximityping.mesh.groupkey.wrap.aead.v2",
            meshEncryptedMetadataV2: "proximityping.mesh.encrypted-metadata.aead.v2",
            meshRoutedContentKeyWrapV1: "proximityping.mesh.routed.content-key.wrap.aead.v1",
            meshRoutedItemV1: "proximityping.mesh.routed.item.aead.v1"
        ),
        hash: ProximityNamespace.Hash(
            meshInventoryDigestV1: "proximityping.mesh.inventory-digest.hash.v1",
            meshRoutedContentV1: "proximityping.mesh.routed-content.hash.v1",
            meshRoutedChunkV1: "proximityping.mesh.routed-chunk.hash.v1",
            meshRoutedChunkIDV1: "proximityping.mesh.routed-chunk-id.hash.v1",
            meshCustodyReceiptIDV1: "proximityping.mesh.custody-receipt-id.hash.v1",
            meshRecipientReceiptIDV1: "proximityping.mesh.recipient-receipt-id.hash.v1",
            meshEpochIDV1: "proximityping.mesh.epoch.v1"
        )
    )

    /// The three radios (only the pair radio runs here), the mesh heartbeat, the instance-name
    /// prefixes and the certificates' common name. The service types are the ones Info.plist lists
    /// under `NSBonjourServices`.
    static let radios = ProximityNamespace.Radios(
        mesh: ProximityNamespace.Radio(serviceType: "_proxping-mesh._udp", alpn: "proxping-mesh-v1"),
        presence: ProximityNamespace.Radio(serviceType: "_proxping-near._udp", alpn: "proxping-near-v1"),
        pair: ProximityNamespace.Radio(serviceType: "_proxping-pair._udp", alpn: "proxping-pair-v1"),
        meshHeartbeat: Data("proxping-mesh-heartbeat".utf8),
        meshInstanceNamePrefix: "proxping-",
        presenceInstanceNamePrefix: "pp-",
        tlsCommonName: "proxping"
    )

    /// The thirty mesh messages' field names, in the order `MeshMessages` declares them.
    static let meshNames = [
        "descriptor", "admissionGrant", "admissionRequest", "stateChange", "friendVouchList",
        "removalProposal", "removalSecond", "memberDeparture", "memberAdmission", "memberRemoval", "terminated",
        "inventoryDigest", "epochHeads", "keyAgreement", "removalProposalSigned", "removalVote",
        "routedManifest", "routedChunk", "custodyReceipt", "recipientReceipt", "routedInventoryDigest",
        "routedDrainAnswer", "keyRotation", "keyAck", "rotationSync", "encryptedMetadata", "coordinatorBeacon",
        "verifyChallenge", "verifyResponse", "sessionGoodbye"
    ]

    /// The token of the mesh message named `name`.
    static func meshToken(_ name: String) -> String { "proximityping.mesh.\(name).v1" }

    /// The mesh engine's thirty messages. The example runs no mesh, but a family names them all.
    static let mesh = ProximityNamespace.MeshMessages(
        descriptor: meshToken("descriptor"), admissionGrant: meshToken("admissionGrant"),
        admissionRequest: meshToken("admissionRequest"), stateChange: meshToken("stateChange"),
        friendVouchList: meshToken("friendVouchList"), removalProposal: meshToken("removalProposal"),
        removalSecond: meshToken("removalSecond"), memberDeparture: meshToken("memberDeparture"),
        memberAdmission: meshToken("memberAdmission"), memberRemoval: meshToken("memberRemoval"),
        terminated: meshToken("terminated"), inventoryDigest: meshToken("inventoryDigest"),
        epochHeads: meshToken("epochHeads"), keyAgreement: meshToken("keyAgreement"),
        removalProposalSigned: meshToken("removalProposalSigned"), removalVote: meshToken("removalVote"),
        routedManifest: meshToken("routedManifest"), routedChunk: meshToken("routedChunk"),
        custodyReceipt: meshToken("custodyReceipt"), recipientReceipt: meshToken("recipientReceipt"),
        routedInventoryDigest: meshToken("routedInventoryDigest"),
        routedDrainAnswer: meshToken("routedDrainAnswer"), keyRotation: meshToken("keyRotation"),
        keyAck: meshToken("keyAck"), rotationSync: meshToken("rotationSync"),
        encryptedMetadata: meshToken("encryptedMetadata"), coordinatorBeacon: meshToken("coordinatorBeacon"),
        verifyChallenge: meshToken("verifyChallenge"), verifyResponse: meshToken("verifyResponse"),
        sessionGoodbye: meshToken("sessionGoodbye")
    )

    /// The session's own three messages, the ping and the pong, and the mesh's messages; the ping,
    /// the pong and the two verify messages must arrive sealed.
    static let vocabulary = ProximityNamespace.Vocabulary(
        session: ProximityNamespace.SessionMessages(
            identityIntroduction: ProximityNamespace.SessionMessage(
                payloadType: "proximityping.session.hello.v1", summaryTitle: "Ping hello"),
            identityAcknowledge: ProximityNamespace.SessionMessage(
                payloadType: "proximityping.session.welcome.v1", summaryTitle: "Ping welcome"),
            heartbeat: ProximityNamespace.Heartbeat(
                payloadType: "proximityping.session.beat.v1", pingTitle: "Ping beat", replyTitle: "Ping beat back")),
        payloads: ProximityNamespace.PayloadRules(
            known: Set(["proximityping.session.hello.v1", "proximityping.session.welcome.v1",
                        "proximityping.session.beat.v1", PingPayload.ping, PingPayload.pong]
                       + meshNames.map(meshToken)),
            sealingRequired: [PingPayload.ping, PingPayload.pong, meshToken("verifyChallenge"),
                              meshToken("verifyResponse")]),
        capabilities: ProximityNamespace.Capabilities(
            known: ["proximityping-framing"], wire2: "proximityping-framing", assumedForLegacyPeers: []),
        membershipRecordKinds: ProximityNamespace.MembershipRecordKinds(
            admission: "proximityping.member.joined.v1", departure: "proximityping.member.left.v1",
            removal: "proximityping.member.removed.v1", termination: "proximityping.group.ended.v1"),
        routedTypes: ProximityNamespace.RoutedTypes(
            photo: "proximityping.routed.photo.v1", tempMessage: "proximityping.routed.note.v1",
            heart: "proximityping.routed.heart.v1", control: "proximityping.routed.control.v1"),
        mesh: mesh
    )

    /// The keychain rows, storage names, log subsystem and peer-name policy of this app alone.
    static let installation = ProximityNamespace.Installation(
        keychain: ProximityNamespace.Keychain(
            identity: ProximityNamespace.Keychain.IdentityRows(
                service: "org.example.proximityping.identity", signingPrivateKey: "signing.private",
                keyAgreementPrivateKey: "agreement.private", signingPublicKeyCache: "signing.public",
                keyAgreementPublicKeyCache: "agreement.public"),
            meshSessionSealKey: ProximityNamespace.Keychain.Row(
                service: "org.example.proximityping.mesh-session", account: "session.seal"),
            meshRoutedSealKey: ProximityNamespace.Keychain.Row(
                service: "org.example.proximityping.mesh-routed", account: "routed.seal")),
        storage: ProximityNamespace.Storage(
            directoryName: "ProximityPing", meshSessionContextFileName: "Session.sealed",
            meshRoutedIndexFileName: "Routed.sealed", meshRoutedChunkDirectoryName: "RoutedChunks"),
        logSubsystem: "org.example.proximityping",
        peerNames: ProximityNamespace.PeerNames(maxLength: 24, floor: "A nearby device")
    )
}
