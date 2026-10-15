// ProximityNamespaceSoundnessTests.swift
//
// ProximityKit plan step A0.2.1: the soundness rules, the byte rules and the collision checks of
// ProximityKit's protocol namespace, over namespaces built entirely from literals that belong to no
// shipping app. The file names no app's values on purpose: it moves with ProximityKit when the package
// leaves for its own repository, and the values an app ships are pinned by that app's own goldens.

import Foundation
import ProximityKit
import Testing

/// Every soundness rule refused by name, the byte rules of each framing, and the two collision checks.
///
/// One cell per ``ProximityNamespace/Violation`` case, and one more for each bound a field takes from
/// another group (a mesh message's from a summary title, the peer-name cap's from the identifiers the
/// name display hides): each changes one literal of a sound namespace and expects exactly the
/// violation that change causes, both recorded by the initializer and thrown by `validated`, then
/// shows the rule's accepting edge. Where two rules see one change by design (a malformed session
/// token is unknown too), the cell expects both, in rule order. A declared feature salt is judged by
/// the label rules with the protocol's labels, so two more cells declare one that repeats or prefixes
/// a label, and a collision cell compares the salts two families declare.
@Suite struct ProximityNamespaceSoundnessTests {

    // MARK: - A sound namespace

    /// A namespace built entirely from literals that belong to no shipping app passes every rule, and
    /// `validated` hands it back rather than throwing.
    @Test func aForeignNamespaceBuiltFromLiteralsIsSound() throws {
        let namespace = AlphaApp.namespace()
        #expect(namespace.soundness == .sound)
        #expect(throws: Never.self) {
            try ProximityNamespace.validated(family: AlphaApp.family(), installation: AlphaApp.installation())
        }
        let validated = try ProximityNamespace.validated(family: AlphaApp.family(), installation: AlphaApp.installation())
        #expect(validated == namespace, "the same value the initializer builds")
        #expect(BravoApp.namespace().soundness == .sound, "and so is the second app the collision cells use")
        let renamed = ProximityNamespace(family: AlphaApp.family(urlScheme: "alpha2"), installation: AlphaApp.installation())
        #expect(renamed != namespace, "one changed value is a different namespace")
    }

    // MARK: - Roles and rows

    /// Every label row, in declaration order, carries the role its field fixes: the host wrote only the
    /// bytes.
    @Test func everyFieldMintsTheRoleProximityKitFixesForIt() {
        let canonical = ProximityCryptographicPurpose.Role.signature(.lengthPrefixed)
        let fixedWidth = ProximityCryptographicPurpose.Role.signature(.rawPrefix)
        let verifyOnly = ProximityCryptographicPurpose.Role.signature(.absent)
        let framedHash = ProximityCryptographicPurpose.Role.hashDomain(.lengthPrefixed)
        let signature = "family.purposes.signature."
        let keyDerivation = "family.purposes.keyDerivation."
        let aead = "family.purposes.aead."
        let hash = "family.purposes.hash."
        let expected: [(String, ProximityCryptographicPurpose.Role)] = [
            (signature + "identityEnvelopeV2", canonical),
            (signature + "meshAdmissionTokenV2", canonical),
            (signature + "meshChannelIntroductionV1", canonical),
            (signature + "meshMemberDepartureV1", canonical),
            (signature + "meshMemberRemovalV1", canonical),
            (signature + "meshTerminatedV1", canonical),
            (signature + "meshInventoryDigestV1", canonical),
            (signature + "meshEpochHeadsV1", canonical),
            (signature + "meshRemovalProposalV1", canonical),
            (signature + "meshRemovalVoteV1", canonical),
            (signature + "meshKeyAgreementV1", canonical),
            (signature + "meshRoutedManifestV1", canonical),
            (signature + "meshRoutedChunkV1", canonical),
            (signature + "meshCustodyReceiptV1", canonical),
            (signature + "meshRecipientReceiptV1", canonical),
            (signature + "meshRoutedInventoryDigestV1", canonical),
            (signature + "meshRoutedDrainAnswerV1", canonical),
            (signature + "proximityQRIdentityV1", fixedWidth),
            (signature + "proximityQRResponseV1", fixedWidth),
            (signature + "legacyV1.identityEnvelopeV1", verifyOnly),
            (signature + "legacyV1.meshAdmissionTokenV1", verifyOnly),
            (keyDerivation + "proximityTransportV1", .keyDerivationSalt),
            (keyDerivation + "meshGroupKeyWrapV1", .keyDerivationSalt),
            (keyDerivation + "meshTLSExporterV1", .tlsExporterLabel),
            (keyDerivation + "meshRoutedContentKeyWrapV1", .keyDerivationSalt),
            (keyDerivation + "meshSessionContextV1", .columnSeal),
            (keyDerivation + "meshRoutedStoreV1", .columnSeal),
            (aead + "proximityTransportV2", .aeadAssociatedData),
            (aead + "meshGroupKeyWrapV2", .aeadAssociatedData),
            (aead + "meshEncryptedMetadataV2", .aeadAssociatedData),
            (aead + "meshRoutedContentKeyWrapV1", .aeadAssociatedData),
            (aead + "meshRoutedItemV1", .aeadAssociatedData),
            (hash + "meshInventoryDigestV1", framedHash),
            (hash + "meshRoutedContentV1", framedHash),
            (hash + "meshRoutedChunkV1", framedHash),
            (hash + "meshRoutedChunkIDV1", framedHash),
            (hash + "meshCustodyReceiptIDV1", framedHash),
            (hash + "meshRecipientReceiptIDV1", framedHash),
            (hash + "meshEpochIDV1", .hashDomain(.rawPrefix))
        ]
        let rows = AlphaApp.namespace().labelRows
        #expect(rows.count == 39, "17 canonical + 2 QR + the legacy pair + 6 + 5 + 7")
        #expect(rows.map { $0.field } == expected.map { $0.0 })
        #expect(rows.map { $0.purpose.role } == expected.map { $0.1 })
    }

    /// `labelRows` lists every label the four protocol groups store, in declaration order, under its
    /// field's path; this app declares no feature salt. Read by reflection, so a label added to a group
    /// without a row cannot pass.
    @Test func labelRowsListEveryStoredLabelInDeclarationOrder() {
        let namespace = AlphaApp.namespace()
        var reflected: [(field: String, purpose: ProximityCryptographicPurpose)] = []
        var pending: [(path: String, value: Any)] = [(path: "family.purposes", value: namespace.family.purposes)]
        var visits = 0
        // Bounded: the purposes, five groups (the feature group and its empty entry list among them),
        // the legacy holder and its two labels, and 37 more labels.
        while let node = pending.popLast(), visits < 64 {
            visits += 1
            if let purpose = node.value as? ProximityCryptographicPurpose {
                reflected.append((field: node.path, purpose: purpose))
                continue
            }
            let children = Mirror(reflecting: node.value).children.compactMap { child in
                child.label.map { (path: node.path + "." + $0, value: child.value) }
            }
            pending.append(contentsOf: children.reversed())
        }
        #expect(pending.isEmpty, "the walk finished inside its bound")
        #expect(reflected.count == 39)
        #expect(reflected.map { $0.field } == namespace.labelRows.map { $0.field })
        #expect(reflected.map { $0.purpose } == namespace.labelRows.map { $0.purpose })
    }

    /// A refused legacy pair adds no rows. An accepted one adds two, straight after the QR labels, both
    /// verify-only.
    @Test func theLegacyPairJoinsTheRowsOnlyWhenAccepted() throws {
        #expect(ProximityNamespace.LegacyV1.refused.identityEnvelopeV1 == nil)
        #expect(ProximityNamespace.LegacyV1.refused.meshAdmissionTokenV1 == nil)
        let refused = ProximityNamespace(
            family: AlphaApp.family(signature: AlphaApp.signature(legacyV1: .refused)),
            installation: AlphaApp.installation()
        )
        #expect(refused.soundness == .sound)
        #expect(refused.labelRows.count == 37)
        #expect(!refused.labelRows.contains { $0.field.contains(".legacyV1.") })

        let accepted = AlphaApp.namespace().labelRows
        try #require(accepted.count == 39)
        #expect(accepted[18].field == "family.purposes.signature.proximityQRResponseV1")
        #expect(accepted[19].field == "family.purposes.signature.legacyV1.identityEnvelopeV1")
        #expect(accepted[20].field == "family.purposes.signature.legacyV1.meshAdmissionTokenV1")
        #expect(accepted[21].field == "family.purposes.keyDerivation.proximityTransportV1")
    }

    // MARK: - Byte rules

    /// `rawValue` is the literal and `data` its UTF-8 bytes, with no terminator and no normalization.
    @Test func dataIsTheLiteralsBytesWithNoTerminator() {
        let purpose = AlphaApp.namespace().family.purposes.signature.proximityQRIdentityV1
        #expect(purpose.rawValue == "alpha.verify.qr.v1")
        #expect(purpose.data == Data("alpha.verify.qr.v1".utf8))
        #expect(purpose.data.count == 18)
        #expect(purpose.data.last == UInt8(ascii: "1"), "no trailing NUL")
    }

    /// A canonical transcript's label sits behind its 8-byte big-endian count, and `signingBytes`
    /// accepts only a transcript that begins with exactly that, in that position.
    @Test func aLengthPrefixedSignatureLabelSitsBehindItsEightByteCount() {
        let purpose = AlphaApp.namespace().family.purposes.signature.identityEnvelopeV2
        #expect(purpose.role == .signature(.lengthPrefixed))
        // 36 bytes, so the count is 0x24, then the label's ASCII.
        #expect(hex(purpose.prefixBytes)
                == "0000000000000024616c7068612e63616e6f6e6963616c2e6964656e746974792d656e76656c6f70652e7632")
        let body = Data([0xB0, 0xD1])
        let framed = purpose.prefixBytes + body
        #expect(purpose.signingBytes(framed) == framed, "accepted, and returned unmodified")
        #expect(purpose.signingBytes(purpose.data + body) == nil, "its own raw spelling is refused")
        #expect(purpose.signingBytes(Data([0x00]) + framed) == nil, "a transcript shifted by one byte is refused")
        #expect(purpose.signingBytes(Data([0, 0, 0, 0, 0, 0, 0, 0x25]) + purpose.data + body) == nil,
                "a wrong count is refused")
        #expect(purpose.signingBytes(purpose.prefixBytes.dropLast()) == nil, "a truncated label is refused")
        #expect(purpose.signingBytes(body) == nil)
        #expect(purpose.signingBytes(Data()) == nil)
    }

    /// A fixed-width transcript's label is its own bytes at the very front.
    @Test func aRawPrefixSignatureLabelIsItsOwnBytes() {
        let purpose = AlphaApp.namespace().family.purposes.signature.proximityQRIdentityV1
        #expect(purpose.role == .signature(.rawPrefix))
        #expect(hex(purpose.prefixBytes) == "616c7068612e7665726966792e71722e7631")
        let body = Data([0x01, 0x02])
        #expect(purpose.signingBytes(purpose.data + body) == purpose.data + body)
        #expect(purpose.signingBytes(Data([0, 0, 0, 0, 0, 0, 0, 0x12]) + purpose.data + body) == nil,
                "the length-prefixed shape is refused")
        #expect(purpose.signingBytes(Data([0x20]) + purpose.data + body) == nil, "shifted by one byte")
        #expect(purpose.signingBytes(purpose.data.dropLast() + body) == nil, "a truncated label")
        #expect(purpose.signingBytes(body) == nil)
    }

    /// A legacy label writes nothing, so every transcript qualifies: verify-only by construction.
    @Test func anAbsentSignatureLabelAcceptsEveryTranscript() throws {
        let purpose = try #require(AlphaApp.namespace().family.purposes.signature.legacyV1.identityEnvelopeV1)
        #expect(purpose.role == .signature(.absent))
        #expect(purpose.prefixBytes.isEmpty)
        #expect(purpose.data == Data("alpha.canonical.identity-envelope.v1".utf8), "its bytes exist, only to be compared")
        let json = Data(#"{"schemaVersion":1}"#.utf8)
        #expect(purpose.signingBytes(json) == json)
        #expect(purpose.signingBytes(Data()) == Data())
        #expect(purpose.signingBytes(purpose.data + json) == purpose.data + json)
    }

    /// Hash domains are framed like transcripts, but no hash label ever authorizes a signature.
    @Test func hashDomainsAreFramedButNeverAuthorizeASignature() {
        let hash = AlphaApp.namespace().family.purposes.hash
        #expect(hash.meshRoutedChunkV1.role == .hashDomain(.lengthPrefixed))
        // 31 bytes, so the count is 0x1f.
        #expect(hex(hash.meshRoutedChunkV1.prefixBytes)
                == "000000000000001f616c7068612e6d6573682e726f757465642d6368756e6b2e686173682e7631")
        #expect(hash.meshRoutedChunkV1.signingBytes(hash.meshRoutedChunkV1.prefixBytes + Data([0x01])) == nil)
        #expect(hash.meshEpochIDV1.role == .hashDomain(.rawPrefix))
        #expect(hex(hash.meshEpochIDV1.prefixBytes) == "616c7068612e6d6573682e65706f63682e7631")
        #expect(hash.meshEpochIDV1.signingBytes(hash.meshEpochIDV1.data + Data([0x01])) == nil)
    }

    /// A salt, a column seal, an AAD and an exporter label are taken whole: their prefix is their bytes,
    /// and none of them ever authorizes a signature.
    @Test func labelsTakenWholeAreTheirBytesAndNeverAuthorizeASignature() {
        let purposes = AlphaApp.namespace().family.purposes
        let whole: [(ProximityCryptographicPurpose, ProximityCryptographicPurpose.Role)] = [
            (purposes.keyDerivation.proximityTransportV1, .keyDerivationSalt),
            (purposes.keyDerivation.meshTLSExporterV1, .tlsExporterLabel),
            (purposes.keyDerivation.meshSessionContextV1, .columnSeal),
            (purposes.aead.proximityTransportV2, .aeadAssociatedData)
        ]
        for (purpose, role) in whole {
            #expect(purpose.role == role)
            #expect(purpose.prefixBytes == purpose.data)
            #expect(purpose.signingBytes(purpose.data) == nil)
            #expect(purpose.signingBytes(purpose.data + Data([0x01])) == nil)
        }
        #expect(hex(purposes.keyDerivation.meshTLSExporterV1.prefixBytes)
                == "616c7068612e6d6573682e746c732d6578706f727465722e7631")
    }

    // MARK: - One cell per violation

    /// Labels: empty, over 255 bytes, or a byte outside 0x21–0x7E.
    @Test func aMalformedLabelIsRefusedByName() {
        let field = "family.purposes.signature.identityEnvelopeV2"
        func family(_ label: StaticString) -> ProximityNamespace.Family {
            AlphaApp.family(signature: AlphaApp.signature(identityEnvelopeV2: label))
        }
        expectOnly([.malformedLabel(field: field)], family: family("alpha.canonical identity-envelope.v2"), note: "a space")
        expectOnly([.malformedLabel(field: field)], family: family("alpha.canonical.identity-envelope.v2\u{7F}"), note: "DEL")
        expectOnly([.malformedLabel(field: field)], family: family("alpha.canonical.identity-envelope.v2\u{9}"), note: "a tab")
        expectOnly([.malformedLabel(field: field)], family: family("alpha.canonical.idéntity-envelope.v2"), note: "not ASCII")
        expectOnly([.malformedLabel(field: field)], family: family("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"), note: "256 bytes")
        expectSound(family: family("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"))
        expectSound(family: family("!alpha.canonical.identity-envelope.v2~"))

        // Empty is malformed, and also a prefix of every other label: both rules see it.
        let empty = ProximityNamespace(family: family(""), installation: AlphaApp.installation())
        guard case .unsound(let violations) = empty.soundness else {
            Issue.record("an empty label passed")
            return
        }
        #expect(violations.first == .malformedLabel(field: field))
        let prefixes = violations.dropFirst().filter { violation in
            if case .labelIsPrefix(shorter: field, longer: _) = violation { return true }
            return false
        }
        #expect(violations.count == 39 && prefixes.count == 38, "malformed, then a prefix of each of the other 38")
    }

    /// Two labels with the same bytes, wherever they sit: across groups, and in the verify-only pair.
    @Test func aDuplicateLabelIsRefusedByName() {
        expectOnly(
            [.duplicateLabel(field: "family.purposes.signature.meshRoutedChunkV1",
                             otherField: "family.purposes.keyDerivation.meshRoutedStoreV1")],
            family: AlphaApp.family(keyDerivation: AlphaApp.keyDerivation(meshRoutedStoreV1: "alpha.mesh.routed-chunk.v1"))
        )
        let sameLegacy = ProximityNamespace.LegacyV1.accepted(
            identityEnvelopeV1: "alpha.legacy.v1",
            meshAdmissionTokenV1: "alpha.legacy.v1"
        )
        expectOnly(
            [.duplicateLabel(field: "family.purposes.signature.legacyV1.identityEnvelopeV1",
                             otherField: "family.purposes.signature.legacyV1.meshAdmissionTokenV1")],
            family: AlphaApp.family(signature: AlphaApp.signature(legacyV1: sameLegacy))
        )
    }

    /// One label's bytes beginning another's, whichever is declared first.
    @Test func aLabelThatBeginsAnotherIsRefusedByName() {
        expectOnly(
            [.labelIsPrefix(shorter: "family.purposes.hash.meshEpochIDV1",
                            longer: "family.purposes.signature.meshEpochHeadsV1")],
            family: AlphaApp.family(hash: AlphaApp.hash(meshEpochIDV1: "alpha.mesh.epoch")),
            note: "the shorter declared later"
        )
        expectOnly(
            [.labelIsPrefix(shorter: "family.purposes.signature.identityEnvelopeV2",
                            longer: "family.purposes.aead.meshGroupKeyWrapV2")],
            family: AlphaApp.family(signature: AlphaApp.signature(identityEnvelopeV2: "alpha.mesh.groupkey.wrap")),
            note: "the shorter declared first"
        )
    }

    /// A declared feature salt is a label like any other: one with a protocol label's bytes is a
    /// duplicate, and so is one with another feature salt's, each named by its field path under
    /// `family.purposes.feature`. The accepting edge: a fresh salt is sound, and its row, in the
    /// `.keyDerivationSalt` role, follows the hash rows.
    @Test func aFeatureSaltEqualToAnotherLabelIsRefusedByName() throws {
        expectOnly(
            [.duplicateLabel(field: "family.purposes.signature.meshRoutedChunkV1",
                             otherField: "family.purposes.feature.pairV1")],
            family: AlphaApp.family(feature: ProximityNamespace.FeaturePurposes([
                "pairV1": .featureKeyDerivationSalt("alpha.mesh.routed-chunk.v1")
            ])),
            note: "a protocol label's bytes"
        )
        expectOnly(
            [.duplicateLabel(field: "family.purposes.feature.pairV1", otherField: "family.purposes.feature.tagV1")],
            family: AlphaApp.family(feature: ProximityNamespace.FeaturePurposes([
                "pairV1": .featureKeyDerivationSalt("alpha.feature.pair.v1"),
                "tagV1": .featureKeyDerivationSalt("alpha.feature.pair.v1")
            ])),
            note: "another feature salt's bytes"
        )
        let declared = ProximityNamespace(
            family: AlphaApp.family(feature: ProximityNamespace.FeaturePurposes([
                "pairV1": .featureKeyDerivationSalt("alpha.feature.pair.v1")
            ])),
            installation: AlphaApp.installation()
        )
        #expect(declared.soundness == .sound)
        let rows = declared.labelRows
        try #require(rows.count == 40)
        #expect(rows[38].field == "family.purposes.hash.meshEpochIDV1", "the feature row follows the hash rows")
        #expect(rows[39].field == "family.purposes.feature.pairV1")
        #expect(rows[39].purpose.role == .keyDerivationSalt)
        #expect(rows[39].purpose.data == Data("alpha.feature.pair.v1".utf8))
    }

    /// A declared feature salt that begins a protocol label, or that a protocol label begins, is a
    /// prefix like any other, whichever is shorter: the feature row, declared last, is named as the
    /// shorter field or as the longer one.
    @Test func aFeatureSaltThatBeginsOrExtendsAProtocolLabelIsRefusedByName() {
        expectOnly(
            [.labelIsPrefix(shorter: "family.purposes.feature.pairV1",
                            longer: "family.purposes.signature.proximityQRIdentityV1")],
            family: AlphaApp.family(feature: ProximityNamespace.FeaturePurposes([
                "pairV1": .featureKeyDerivationSalt("alpha.verify.qr")
            ])),
            note: "the feature salt the shorter"
        )
        expectOnly(
            [.labelIsPrefix(shorter: "family.purposes.hash.meshEpochIDV1",
                            longer: "family.purposes.feature.pairV1")],
            family: AlphaApp.family(feature: ProximityNamespace.FeaturePurposes([
                "pairV1": .featureKeyDerivationSalt("alpha.mesh.epoch.v1.pair")
            ])),
            note: "the protocol label the shorter"
        )
    }

    /// Service types: `_name._udp`, the name 1–15 of `[a-z0-9-]` with a letter and no stray hyphen.
    @Test func aMalformedServiceTypeIsRefusedByName() {
        func family(_ serviceType: String) -> ProximityNamespace.Family {
            AlphaApp.family(radios: AlphaApp.radios(mesh: .init(serviceType: serviceType, alpn: "alpha-mesh-v1")))
        }
        let refused = [
            "_alpha-mesh._tcp", "alpha-mesh._udp", "_alpha-mesh.udp", "_alpha-mesh._udp.",
            "_Alpha-mesh._udp", "_alpha_mesh._udp", "_._udp", "_abcdefghijklmnop._udp",
            "_2026._udp", "_-alpha._udp", "_alpha-._udp", "_alpha--mesh._udp"
        ]
        for serviceType in refused {
            expectOnly([.malformedServiceType(field: "family.radios.mesh.serviceType")],
                       family: family(serviceType), note: serviceType)
        }
        for serviceType in ["_abcdefghijklmno._udp", "_a._udp", "_a1-b2._udp"] {
            expectSound(family: family(serviceType), note: serviceType)
        }
    }

    /// ALPNs: 1–255 bytes of printable ASCII.
    @Test func aMalformedALPNIsRefusedByName() {
        func family(_ alpn: String) -> ProximityNamespace.Family {
            AlphaApp.family(radios: AlphaApp.radios(presence: .init(serviceType: "_alpha-near._udp", alpn: alpn)))
        }
        let refused = ["", String(repeating: "n", count: 256), "alpha-near-v1\u{1F}", "alpha-near-v1\u{7F}", "alpha-néar-v1"]
        for alpn in refused {
            expectOnly([.malformedALPN(field: "family.radios.presence.alpn")], family: family(alpn), note: alpn)
        }
        for alpn in [String(repeating: "n", count: 255), "alpha near v1", "~"] {
            expectSound(family: family(alpn), note: alpn)
        }
    }

    /// Two radios sharing a service type, or two sharing an ALPN. A service type that spells another
    /// radio's ALPN breaks no rule: the two never meet.
    @Test func aDuplicateRadioValueIsRefusedByName() {
        expectOnly(
            [.duplicateRadioValue(field: "family.radios.mesh.serviceType",
                                  otherField: "family.radios.pair.serviceType")],
            family: AlphaApp.family(radios: AlphaApp.radios(
                pair: .init(serviceType: "_alpha-mesh._udp", alpn: "alpha-recipe-v1")))
        )
        expectOnly(
            [.duplicateRadioValue(field: "family.radios.presence.alpn", otherField: "family.radios.pair.alpn")],
            family: AlphaApp.family(radios: AlphaApp.radios(
                pair: .init(serviceType: "_alpha-recipe._udp", alpn: "alpha-near-v1")))
        )
        expectSound(family: AlphaApp.family(radios: AlphaApp.radios(
            mesh: .init(serviceType: "_alpha-mesh._udp", alpn: "_alpha-near._udp"))))
    }

    /// The heartbeat: 1–64 bytes, never beginning with `{`, the first byte of every app frame.
    @Test func aMalformedHeartbeatIsRefusedByName() {
        for heartbeat in [Data(), Data(repeating: 0x68, count: 65), Data(#"{"beat":1}"#.utf8)] {
            expectOnly([.malformedHeartbeat], family: AlphaApp.family(radios: AlphaApp.radios(meshHeartbeat: heartbeat)),
                       note: hex(heartbeat))
        }
        for heartbeat in [Data(repeating: 0x68, count: 64), Data("h{".utf8), Data([0x00])] {
            expectSound(family: AlphaApp.family(radios: AlphaApp.radios(meshHeartbeat: heartbeat)), note: hex(heartbeat))
        }
    }

    /// The QR scheme: a lowercase RFC 3986 scheme.
    @Test func aMalformedURLSchemeIsRefusedByName() {
        for scheme in ["", "Alpha", "1alpha", "-alpha", "al pha", "al_pha", "alphä", "alpha:"] {
            expectOnly([.malformedURLScheme], family: AlphaApp.family(urlScheme: scheme), note: scheme)
        }
        for scheme in ["a", "alpha+v1.x-2"] {
            expectSound(family: AlphaApp.family(urlScheme: scheme), note: scheme)
        }
    }

    /// Keychain names: none empty, whether service or account.
    @Test func aMalformedKeychainNameIsRefusedByName() {
        let identity = ProximityNamespace.Keychain.IdentityRows(
            service: "org.example.alpha.identity", signingPrivateKey: "signing.private",
            keyAgreementPrivateKey: "agreement.private", signingPublicKeyCache: "",
            keyAgreementPublicKeyCache: "agreement.public"
        )
        expectOnly([.malformedKeychainName(field: "installation.keychain.identity.signingPublicKeyCache")],
                   installation: AlphaApp.installation(keychain: AlphaApp.keychain(identity: identity)))
        expectOnly([.malformedKeychainName(field: "installation.keychain.meshSessionSealKey.service")],
                   installation: AlphaApp.installation(keychain: AlphaApp.keychain(
                       meshSessionSealKey: .init(service: "", account: "session.seal"))))
        expectOnly([.malformedKeychainName(field: "installation.keychain.meshRoutedSealKey.account")],
                   installation: AlphaApp.installation(keychain: AlphaApp.keychain(
                       meshRoutedSealKey: .init(service: "org.example.alpha.mesh-routed", account: ""))))
    }

    /// Two keychain services equal, or two identity accounts. The two seal keys may share an account
    /// name, because each lives under its own service.
    @Test func aDuplicateKeychainNameIsRefusedByName() {
        expectOnly(
            [.duplicateKeychainName(field: "installation.keychain.identity.service",
                                    otherField: "installation.keychain.meshRoutedSealKey.service")],
            installation: AlphaApp.installation(keychain: AlphaApp.keychain(
                meshRoutedSealKey: .init(service: "org.example.alpha.identity", account: "routed.seal")))
        )
        let identity = ProximityNamespace.Keychain.IdentityRows(
            service: "org.example.alpha.identity", signingPrivateKey: "signing.private",
            keyAgreementPrivateKey: "agreement.private", signingPublicKeyCache: "signing.public",
            keyAgreementPublicKeyCache: "signing.private"
        )
        expectOnly(
            [.duplicateKeychainName(field: "installation.keychain.identity.signingPrivateKey",
                                    otherField: "installation.keychain.identity.keyAgreementPublicKeyCache")],
            installation: AlphaApp.installation(keychain: AlphaApp.keychain(identity: identity))
        )
        expectSound(installation: AlphaApp.installation(keychain: AlphaApp.keychain(
            meshSessionSealKey: .init(service: "org.example.alpha.mesh-session", account: "seal"),
            meshRoutedSealKey: .init(service: "org.example.alpha.mesh-routed", account: "seal"))))
    }

    /// Storage names: one path component each — not empty, `.` or `..`, and no `/`, `:` or NUL.
    @Test func aMalformedPathComponentIsRefusedByName() {
        for name in ["", ".", "..", "Alpha/Sub", "Alpha:Sub", "Alpha\u{0}Sub"] {
            expectOnly([.malformedPathComponent(field: "installation.storage.directoryName")],
                       installation: AlphaApp.installation(storage: AlphaApp.storage(directoryName: name)),
                       note: name)
        }
        expectOnly([.malformedPathComponent(field: "installation.storage.meshRoutedChunkDirectoryName")],
                   installation: AlphaApp.installation(storage: AlphaApp.storage(
                       meshRoutedChunkDirectoryName: "Routed/Chunks")))
        for name in ["...", ".alpha", "Alpha Support"] {
            expectSound(installation: AlphaApp.installation(storage: AlphaApp.storage(directoryName: name)), note: name)
        }
    }

    /// Two names inside the storage directory equal, ignoring case. The directory itself may share a
    /// name with an entry inside it.
    @Test func aDuplicateFileNameIsRefusedByName() {
        expectOnly(
            [.duplicateFileName(field: "installation.storage.meshSessionContextFileName",
                                otherField: "installation.storage.meshRoutedIndexFileName")],
            installation: AlphaApp.installation(storage: AlphaApp.storage(meshRoutedIndexFileName: "Session.sealed"))
        )
        expectOnly(
            [.duplicateFileName(field: "installation.storage.meshSessionContextFileName",
                                otherField: "installation.storage.meshRoutedChunkDirectoryName")],
            installation: AlphaApp.installation(storage: AlphaApp.storage(meshRoutedChunkDirectoryName: "session.SEALED")),
            note: "ignoring case"
        )
        expectSound(installation: AlphaApp.installation(storage: AlphaApp.storage(directoryName: "RoutedChunks")))
    }

    /// The log subsystem: not empty.
    @Test func anEmptyLogSubsystemIsRefusedByName() {
        expectOnly([.emptyLogSubsystem], installation: AlphaApp.installation(logSubsystem: ""))
    }

    /// Tokens: empty, past the group's bound, or a byte outside 0x21–0x7E — a payload token or record
    /// kind past 255 bytes, a mesh message past 200 (the next cell), a capability token past 32, a
    /// routed type past 64. A set or a list is named once, by its own path, however many of its members
    /// break the rule.
    @Test func aMalformedTokenIsRefusedByName() {
        let departure = "family.vocabulary.membershipRecordKinds.departure"
        func kinds(_ token: String) -> ProximityNamespace.Family {
            AlphaApp.family(vocabulary: AlphaApp.vocabulary(membershipRecordKinds: AlphaApp.recordKinds(departure: token)))
        }
        let refused = ["", "alpha.member left.v1", "alpha.member.left.v1\u{7F}", "alpha.member.left.v1\u{9}",
                       "alpha.membér.left.v1", String(repeating: "k", count: 256)]
        for token in refused {
            expectOnly([.malformedToken(field: departure)], family: kinds(token), note: token)
        }
        for token in [String(repeating: "k", count: 255), "!alpha.member.left.v1~"] {
            expectSound(family: kinds(token), note: token)
        }

        func routed(_ heart: String) -> ProximityNamespace.Family {
            AlphaApp.family(vocabulary: AlphaApp.vocabulary(routedTypes: AlphaApp.routedTypes(heart: heart)))
        }
        expectOnly([.malformedToken(field: "family.vocabulary.routedTypes.heart")],
                   family: routed(String(repeating: "r", count: 65)), note: "65 bytes")
        expectSound(family: routed(String(repeating: "r", count: 64)), note: "64 bytes")

        func capabilities(_ known: [String]) -> ProximityNamespace.Family {
            AlphaApp.family(vocabulary: AlphaApp.vocabulary(capabilities: AlphaApp.capabilities(known: known)))
        }
        expectOnly([.malformedToken(field: "family.vocabulary.capabilities.known")],
                   family: capabilities(AlphaApp.capabilityTokens + [String(repeating: "c", count: 33)]), note: "33 bytes")
        expectOnly([.malformedToken(field: "family.vocabulary.capabilities.known")],
                   family: capabilities(AlphaApp.capabilityTokens + [String(repeating: "c", count: 33), "alpha notes"]),
                   note: "two malformed members, one violation")
        expectSound(family: capabilities(AlphaApp.capabilityTokens + [String(repeating: "c", count: 32)]), note: "32 bytes")

        let known = "family.vocabulary.payloads.known"
        expectOnly([.malformedToken(field: known)],
                   family: AlphaApp.family(vocabulary: AlphaApp.vocabulary(
                       payloads: AlphaApp.payloads(known: AlphaApp.payloadTokens.union(["", "alpha draft.v1"])))))
        // A sealed token must also be known, so a malformed one breaks the rule in both sets.
        let sealed = "alpha.diary\u{0}.v1"
        expectOnly([.malformedToken(field: known), .malformedToken(field: "family.vocabulary.payloads.sealingRequired")],
                   family: AlphaApp.family(vocabulary: AlphaApp.vocabulary(payloads: AlphaApp.payloads(
                       known: AlphaApp.payloadTokens.union([sealed]), sealingRequired: [sealed]))))
        // A malformed session token is outside `known` too: both rules see it, the malformed one first.
        let introduction = "family.vocabulary.session.identityIntroduction.payloadType"
        expectOnly([.malformedToken(field: introduction), .unknownToken(field: introduction)],
                   family: AlphaApp.family(vocabulary: AlphaApp.vocabulary(
                       session: AlphaApp.session(introductionType: "alpha session hello"))))
        // So is a malformed mesh message, a payload token past 255 bytes among them.
        let beacon = "family.vocabulary.mesh.coordinatorBeacon"
        for token in ["alpha mesh beacon", String(repeating: "b", count: 256)] {
            expectOnly([.malformedToken(field: beacon), .unknownToken(field: beacon)],
                       family: AlphaApp.family(vocabulary: AlphaApp.vocabulary(
                           mesh: AlphaApp.meshMessages(replacing: ["coordinatorBeacon": token]))), note: token)
        }
    }

    /// A mesh message is a summary title too: the mesh signs every frame with its token as the
    /// envelope's summary title, and a receiver's bounded summary decode refuses a title past 200
    /// characters, so a mesh message past 200 bytes is refused although a payload token may run to
    /// 255. Listed in `payloads.known`, which takes it, a 201-byte message breaks that rule alone; at
    /// 200 bytes it is sound.
    @Test func aMeshMessageLongerThanASummaryTitleIsRefusedByName() {
        func beacon(_ length: Int) -> ProximityNamespace.Family {
            let token = "alpha.mesh.beacon." + String(repeating: "b", count: length - 18)
            return AlphaApp.family(vocabulary: AlphaApp.vocabulary(
                payloads: AlphaApp.payloads(known: AlphaApp.payloadTokens.union([token])),
                mesh: AlphaApp.meshMessages(replacing: ["coordinatorBeacon": token])))
        }
        expectOnly([.malformedToken(field: "family.vocabulary.mesh.coordinatorBeacon")], family: beacon(201),
                   note: "201 bytes")
        expectSound(family: beacon(200), note: "200 bytes")
        expectSound(family: AlphaApp.family(vocabulary: AlphaApp.vocabulary(
            payloads: AlphaApp.payloads(known: AlphaApp.payloadTokens.union([String(repeating: "k", count: 255)])))),
                    note: "a 255-byte payload token that is no mesh message")
    }

    /// Two tokens of one group with the same bytes: two session payload tokens, two capability tokens
    /// (each named by its index), two record kinds, two routed types, two mesh messages, or a session
    /// payload token and a mesh message, which one dispatch path tells apart by token alone. Tokens of
    /// other groups may match, as a record kind may spell the mesh message that carries its record,
    /// and so may two titles.
    @Test func aDuplicateTokenIsRefusedByName() {
        let session = "family.vocabulary.session."
        expectOnly([.duplicateToken(field: session + "identityIntroduction.payloadType",
                                    otherField: session + "heartbeat.payloadType")],
                   family: AlphaApp.family(vocabulary: AlphaApp.vocabulary(
                       session: AlphaApp.session(heartbeatType: AlphaApp.sessionTokens[0]))))
        expectOnly([.duplicateToken(field: "family.vocabulary.capabilities.known[0]",
                                    otherField: "family.vocabulary.capabilities.known[3]")],
                   family: AlphaApp.family(vocabulary: AlphaApp.vocabulary(
                       capabilities: AlphaApp.capabilities(known: AlphaApp.capabilityTokens + ["alpha-notes"]))))
        expectOnly([.duplicateToken(field: "family.vocabulary.membershipRecordKinds.admission",
                                    otherField: "family.vocabulary.membershipRecordKinds.departure")],
                   family: AlphaApp.family(vocabulary: AlphaApp.vocabulary(
                       membershipRecordKinds: AlphaApp.recordKinds(departure: "alpha.member.joined.v1"))))
        expectOnly([.duplicateToken(field: "family.vocabulary.routedTypes.photo",
                                    otherField: "family.vocabulary.routedTypes.heart")],
                   family: AlphaApp.family(vocabulary: AlphaApp.vocabulary(
                       routedTypes: AlphaApp.routedTypes(heart: "alpha.routed.picture.v1"))))
        let mesh = "family.vocabulary.mesh."
        expectOnly([.duplicateToken(field: mesh + "keyRotation", otherField: mesh + "keyAck")],
                   family: AlphaApp.family(vocabulary: AlphaApp.vocabulary(
                       mesh: AlphaApp.meshMessages(replacing: ["keyAck": AlphaApp.meshToken("keyRotation")]))))
        expectOnly([.duplicateToken(field: session + "heartbeat.payloadType", otherField: mesh + "coordinatorBeacon")],
                   family: AlphaApp.family(vocabulary: AlphaApp.vocabulary(
                       mesh: AlphaApp.meshMessages(replacing: ["coordinatorBeacon": AlphaApp.sessionTokens[2]]))))
        expectSound(family: AlphaApp.family(vocabulary: AlphaApp.vocabulary(
            session: AlphaApp.session(pingTitle: "Alpha beat", replyTitle: "Alpha beat"),
            membershipRecordKinds: AlphaApp.recordKinds(admission: "alpha.note.v1"),
            routedTypes: AlphaApp.routedTypes(photo: "alpha-sketches"))), note: "tokens shared across groups")
        expectSound(family: AlphaApp.family(vocabulary: AlphaApp.vocabulary(
            membershipRecordKinds: AlphaApp.recordKinds(admission: AlphaApp.meshToken("memberAdmission"),
                                                        departure: AlphaApp.meshToken("memberDeparture")),
            routedTypes: AlphaApp.routedTypes(photo: AlphaApp.meshToken("routedManifest")))),
                    note: "record kinds spelling the mesh messages that carry their records")
    }

    /// A token a rule names that the vocabulary does not know: a session payload token, a sealed token
    /// or a mesh message outside `payloads.known`, and `wire2` or an assumed capability outside
    /// `capabilities.known`. A set or a list is named once.
    @Test func anUnknownTokenIsRefusedByName() {
        expectOnly([.unknownToken(field: "family.vocabulary.session.identityAcknowledge.payloadType")],
                   family: AlphaApp.family(vocabulary: AlphaApp.vocabulary(
                       session: AlphaApp.session(acknowledgeType: "alpha.session.other.v1"))))
        expectOnly([.unknownToken(field: "family.vocabulary.mesh.verifyResponse")],
                   family: AlphaApp.family(vocabulary: AlphaApp.vocabulary(
                       mesh: AlphaApp.meshMessages(replacing: ["verifyResponse": "alpha.unlisted.v3"]))))
        expectOnly([.unknownToken(field: "family.vocabulary.payloads.sealingRequired")],
                   family: AlphaApp.family(vocabulary: AlphaApp.vocabulary(payloads: AlphaApp.payloads(
                       sealingRequired: ["alpha.note.v1", "alpha.unlisted.v1", "alpha.unlisted.v2"]))),
                   note: "two unknown members, one violation")
        expectOnly([.unknownToken(field: "family.vocabulary.capabilities.wire2")],
                   family: AlphaApp.family(vocabulary: AlphaApp.vocabulary(
                       capabilities: AlphaApp.capabilities(wire2: "alpha-unlisted"))))
        expectOnly([.unknownToken(field: "family.vocabulary.capabilities.assumedForLegacyPeers")],
                   family: AlphaApp.family(vocabulary: AlphaApp.vocabulary(
                       capabilities: AlphaApp.capabilities(assumedForLegacyPeers: ["alpha-notes", "alpha-unlisted"]))))
        expectSound(family: AlphaApp.family(vocabulary: AlphaApp.vocabulary(
            payloads: AlphaApp.payloads(sealingRequired: []),
            capabilities: AlphaApp.capabilities(assumedForLegacyPeers: []))), note: "nothing sealed, nothing assumed")
    }

    /// Summary titles: 1 to 200 characters, counted as the receiver's bounded decode counts them, so a
    /// letter with its combining mark is one character however many bytes it takes.
    @Test func aMalformedSummaryTitleIsRefusedByName() {
        func titled(_ session: ProximityNamespace.SessionMessages) -> ProximityNamespace.Family {
            AlphaApp.family(vocabulary: AlphaApp.vocabulary(session: session))
        }
        let session = "family.vocabulary.session."
        expectOnly([.malformedSummaryTitle(field: session + "identityIntroduction.summaryTitle")],
                   family: titled(AlphaApp.session(introductionTitle: "")), note: "empty")
        expectOnly([.malformedSummaryTitle(field: session + "identityAcknowledge.summaryTitle")],
                   family: titled(AlphaApp.session(acknowledgeTitle: String(repeating: "t", count: 201))),
                   note: "201 characters")
        expectOnly([.malformedSummaryTitle(field: session + "heartbeat.pingTitle"),
                    .malformedSummaryTitle(field: session + "heartbeat.replyTitle")],
                   family: titled(AlphaApp.session(pingTitle: "", replyTitle: String(repeating: "e\u{301}", count: 201))),
                   note: "both heartbeat titles, in declaration order")
        expectSound(family: titled(AlphaApp.session(introductionTitle: String(repeating: "t", count: 200))),
                    note: "200 characters")
        expectSound(family: titled(AlphaApp.session(replyTitle: String(repeating: "e\u{301}", count: 200))),
                    note: "200 characters in 600 bytes")
    }

    /// Instance-name prefixes: bytes of `[a-z0-9-]`, at least one, leaving a 63-byte DNS-SD name room
    /// for the hex after them — the mesh prefix at most 51 bytes, the presence prefix at most 47. Under
    /// a peer-name cap of 63, which no prefix here outgrows, so the cap's own bound is not in play.
    @Test func aMalformedInstanceNamePrefixIsRefusedByName() {
        let mesh = "family.radios.meshInstanceNamePrefix"
        let roomy = AlphaApp.installation(peerNames: AlphaApp.peerNames(maxLength: 63))
        let refused = ["", "Alpha-mesh-", "alpha_mesh-", "alpha mesh-", "alphä-mesh-", String(repeating: "m", count: 52)]
        for prefix in refused {
            expectOnly([.malformedInstanceNamePrefix(field: mesh)],
                       family: AlphaApp.family(radios: AlphaApp.radios(meshInstanceNamePrefix: prefix)),
                       installation: roomy, note: prefix)
        }
        expectOnly([.malformedInstanceNamePrefix(field: "family.radios.presenceInstanceNamePrefix")],
                   family: AlphaApp.family(radios: AlphaApp.radios(
                       presenceInstanceNamePrefix: String(repeating: "p", count: 48))),
                   installation: roomy, note: "48 bytes")
        let accepted: [(mesh: String, presence: String)] = [
            (String(repeating: "m", count: 51), String(repeating: "p", count: 47)), ("2026-", "a"), ("-", "a-b-")
        ]
        for prefixes in accepted {
            expectSound(family: AlphaApp.family(radios: AlphaApp.radios(
                meshInstanceNamePrefix: prefixes.mesh, presenceInstanceNamePrefix: prefixes.presence)),
                installation: roomy, note: "\(prefixes.mesh) and \(prefixes.presence)")
        }
    }

    /// The certificates' common name: 1 to 64 bytes of printable ASCII, the space included.
    @Test func aMalformedCommonNameIsRefusedByName() {
        for name in ["", String(repeating: "n", count: 65), "alpha\u{9}mesh", "alpha-mesh\u{7F}", "alphä-mesh"] {
            expectOnly([.malformedCommonName], family: AlphaApp.family(radios: AlphaApp.radios(tlsCommonName: name)),
                       note: name)
        }
        for name in [String(repeating: "n", count: 64), "Alpha Mesh", "~"] {
            expectSound(family: AlphaApp.family(radios: AlphaApp.radios(tlsCommonName: name)), note: name)
        }
    }

    /// The peer-name policy: a cap of at most 63 characters (and at least the identifiers the next cell
    /// holds it to, 16 here), and a floor that is not empty and is exactly what ProximityKit's sanitizer
    /// makes of it under the cap — so no longer than the cap, with no invisible or control scalar, no
    /// tab or doubled space, and no space at either end. Each field is named by its path; a cap below
    /// one names the floor too, since no floor fits under it. The accepting edges count characters, so
    /// a letter and its combining mark are one.
    @Test func aMalformedPeerNamePolicyIsRefusedByName() {
        let (capField, floorField) = ("installation.peerNames.maxLength", "installation.peerNames.floor")
        func installation(maxLength: Int = 32, floor: String = "An alpha friend") -> ProximityNamespace.Installation {
            AlphaApp.installation(peerNames: AlphaApp.peerNames(maxLength: maxLength, floor: floor))
        }
        for maxLength in [64, 1_000] {
            expectOnly([.malformedPeerNames(field: capField)], installation: installation(maxLength: maxLength),
                       note: "a cap of \(maxLength)")
        }
        for maxLength in [0, -1] {
            expectOnly([.malformedPeerNames(field: capField), .malformedPeerNames(field: floorField)],
                       installation: installation(maxLength: maxLength), note: "a cap of \(maxLength)")
        }
        let unfit = ["", "   ", "An alpha\u{200B} friend", "An alpha  friend", " An alpha friend", "An alpha friend ",
                     "An\talpha friend", "An alpha friend\u{7}", "\u{202E}An alpha friend", String(repeating: "f", count: 33)]
        for text in unfit {
            expectOnly([.malformedPeerNames(field: floorField)], installation: installation(floor: text),
                       note: text.debugDescription)
        }
        let accepted: [(maxLength: Int, floor: String)] = [
            (16, "A"), (32, String(repeating: "f", count: 32)), (63, String(repeating: "f", count: 63)),
            (16, String(repeating: "Zo\u{EB}\u{1F331}", count: 4)), (16, String(repeating: "Cafe\u{301}", count: 4))
        ]
        for policy in accepted {
            expectSound(installation: installation(maxLength: policy.maxLength, floor: policy.floor),
                        note: "\(policy.floor.debugDescription) under a cap of \(policy.maxLength)")
        }
    }

    /// The peer-name cap against the identifiers the name display hides: `PeerNameDisplay` cuts a name
    /// to the cap before it looks for a fingerprint filed as a name (16 characters) or a mesh instance
    /// name (the family's prefix, then hex), so a cap shorter than either would cut one to a name it
    /// shows as a person's. The cap is refused below a fingerprint's length and below the family's mesh
    /// prefix, once however many it falls short of, and accepted at each length.
    @Test func aPeerNameCapShorterThanAnIdentifierItHidesIsRefusedByName() {
        let capField = "installation.peerNames.maxLength"
        func installation(maxLength: Int) -> ProximityNamespace.Installation {
            AlphaApp.installation(peerNames: AlphaApp.peerNames(maxLength: maxLength, floor: "An alpha pal"))
        }
        // Alpha's mesh prefix, `alpha-mesh-`, is 11 characters: the fingerprint is the longer bound.
        expectOnly([.malformedPeerNames(field: capField)], installation: installation(maxLength: 15),
                   note: "a cap of 15, under a fingerprint's 16")
        expectSound(installation: installation(maxLength: 16), note: "a cap of 16, a fingerprint's length")
        let prefix = "alpha-mesh-instance-"
        let longPrefix = AlphaApp.family(radios: AlphaApp.radios(meshInstanceNamePrefix: prefix))
        for maxLength in [prefix.count - 1, 12] {
            expectOnly([.malformedPeerNames(field: capField)], family: longPrefix,
                       installation: installation(maxLength: maxLength),
                       note: "a cap of \(maxLength), under the \(prefix.count)-character mesh prefix")
        }
        expectSound(family: longPrefix, installation: installation(maxLength: prefix.count),
                    note: "a cap of \(prefix.count), the mesh prefix's length")
    }

    /// The green control of the vocabulary and presentation rules: every rule's accepting edge at once
    /// — each token at its group's longest (a mesh message at a summary title's 200 bytes), each title
    /// at 200 characters, both prefixes at their room, the longest common name, nothing sealed and
    /// nothing assumed, and the peer-name cap at the 51-character mesh prefix's length — makes a sound
    /// namespace, and the family carries the values exactly as given.
    @Test func everyVocabularyAndPresentationRuleAcceptsItsEdgeAtOnce() {
        func token(_ tag: String, _ length: Int) -> String { tag + String(repeating: "x", count: length - tag.utf8.count) }
        func title(_ letter: String) -> String { String(repeating: letter, count: 200) }
        let meshToken = { (name: String) in token("mesh." + name, 200) }
        let vocabulary = ProximityNamespace.Vocabulary(
            session: ProximityNamespace.SessionMessages(
                identityIntroduction: .init(payloadType: token("i", 255), summaryTitle: title("t")),
                identityAcknowledge: .init(payloadType: token("a", 255), summaryTitle: title("u")),
                heartbeat: .init(payloadType: token("h", 255), pingTitle: title("v"), replyTitle: title("w"))),
            payloads: .init(known: Set([token("i", 255), token("a", 255), token("h", 255)]
                                       + ProximityNamespace.MeshMessages.tokens(meshToken)), sealingRequired: []),
            capabilities: .init(known: [token("c", 32), token("d", 32)], wire2: token("d", 32), assumedForLegacyPeers: []),
            membershipRecordKinds: .init(admission: token("j", 255), departure: token("l", 255),
                                         removal: token("r", 255), termination: token("e", 255)),
            routedTypes: .init(photo: token("p", 64), tempMessage: token("m", 64), heart: token("h", 64),
                               control: token("c", 64)),
            mesh: .spelled(meshToken))
        let radios = AlphaApp.radios(meshInstanceNamePrefix: String(repeating: "m", count: 51),
                                     presenceInstanceNamePrefix: String(repeating: "p", count: 47),
                                     tlsCommonName: String(repeating: "n", count: 64))
        let namespace = ProximityNamespace(family: AlphaApp.family(radios: radios, vocabulary: vocabulary),
                                           installation: AlphaApp.installation(peerNames: AlphaApp.peerNames(maxLength: 51)))
        #expect(namespace.soundness == .sound, "\(namespace.soundness)")
        #expect(namespace.family.vocabulary == vocabulary, "the family carries another vocabulary")
        #expect(namespace.family.radios == radios, "the family carries other radios")
    }

    /// The spelling rule the fixtures build their mesh messages with names the thirty fields once
    /// each, in declaration order, and hands each field its own name's token: what reflection reads
    /// off a value it builds is exactly the field-name list and those tokens.
    @Test func theMeshGroupsFieldNamesAreItsFieldsInOrder() {
        let names = ProximityNamespace.MeshMessages.fieldNames
        let children = Mirror(reflecting: ProximityNamespace.MeshMessages.spelled { "probe.\($0)" }).children
        #expect(names.count == 30 && Set(names).count == 30, "\(names.count) names, \(Set(names).count) distinct")
        #expect(children.compactMap(\.label) == names, "the stored fields are \(children.compactMap(\.label))")
        #expect(children.map { $0.value as? String } == names.map { "probe.\($0)" },
                "a field was handed another field's token")
    }

    /// Several broken rules are all recorded, in rule order, and thrown in that order: the labels,
    /// radios, scheme, keychain, storage and log subsystem first, then the vocabulary's tokens and
    /// titles, then the radios' presentation strings, then the peer-name policy.
    @Test func everyViolationIsRecordedInRuleOrder() {
        let family = AlphaApp.family(
            signature: AlphaApp.signature(identityEnvelopeV2: "alpha.canonical identity-envelope.v2"),
            radios: AlphaApp.radios(meshHeartbeat: Data(), meshInstanceNamePrefix: "Alpha", tlsCommonName: ""),
            urlScheme: "Alpha",
            vocabulary: AlphaApp.vocabulary(
                session: AlphaApp.session(pingTitle: ""),
                capabilities: AlphaApp.capabilities(wire2: "alpha-unlisted"),
                membershipRecordKinds: AlphaApp.recordKinds(departure: ""),
                routedTypes: AlphaApp.routedTypes(heart: "alpha.routed.picture.v1"),
                mesh: AlphaApp.meshMessages(replacing: ["keyAck": "alpha.unlisted.v4"]))
        )
        let installation = AlphaApp.installation(
            keychain: AlphaApp.keychain(
                meshRoutedSealKey: .init(service: "org.example.alpha.identity", account: "routed.seal")),
            storage: AlphaApp.storage(directoryName: ".."),
            logSubsystem: "",
            peerNames: AlphaApp.peerNames(floor: "")
        )
        expectOnly([
            .malformedLabel(field: "family.purposes.signature.identityEnvelopeV2"),
            .malformedHeartbeat,
            .malformedURLScheme,
            .duplicateKeychainName(field: "installation.keychain.identity.service",
                                   otherField: "installation.keychain.meshRoutedSealKey.service"),
            .malformedPathComponent(field: "installation.storage.directoryName"),
            .emptyLogSubsystem,
            .malformedToken(field: "family.vocabulary.membershipRecordKinds.departure"),
            .duplicateToken(field: "family.vocabulary.routedTypes.photo", otherField: "family.vocabulary.routedTypes.heart"),
            .unknownToken(field: "family.vocabulary.capabilities.wire2"),
            .unknownToken(field: "family.vocabulary.mesh.keyAck"),
            .malformedSummaryTitle(field: "family.vocabulary.session.heartbeat.pingTitle"),
            .malformedInstanceNamePrefix(field: "family.radios.meshInstanceNamePrefix"),
            .malformedCommonName,
            .malformedPeerNames(field: "installation.peerNames.floor")
        ], family: family, installation: installation)
    }

    // MARK: - Collisions

    /// An equal label, a label that begins another in each direction, a service type another radio
    /// advertises, an ALPN, the heartbeat and the scheme (ignoring case): each reported once, in order,
    /// with the asking namespace's field first.
    @Test func familyCollisionsReportEqualAndPrefixLabelsAndEqualRadioValues() {
        let alpha = AlphaApp.namespace()
        let bravo = ProximityNamespace(
            family: BravoApp.family(
                signature: BravoApp.signature(meshRoutedChunkV1: "alpha.mesh.routed-chunk.v1"),
                aead: BravoApp.aead(meshRoutedItemV1: "alpha.mesh.routed.item"),
                hash: BravoApp.hash(meshEpochIDV1: "alpha.mesh.epoch.v1.extended"),
                radios: BravoApp.radios(
                    mesh: .init(serviceType: "_alpha-near._udp", alpn: "bravo-mesh-v1"),
                    pair: .init(serviceType: "_bravo-recipe._udp", alpn: "alpha-recipe-v1"),
                    meshHeartbeat: Data("alpha-heartbeat".utf8)
                ),
                urlScheme: "ALPHA"
            ),
            installation: BravoApp.installation()
        )
        let expected = [
            Overlap("family.purposes.signature.meshRoutedChunkV1", "family.purposes.signature.meshRoutedChunkV1", .equal),
            Overlap("family.purposes.aead.meshRoutedItemV1", "family.purposes.aead.meshRoutedItemV1", .prefix),
            Overlap("family.purposes.hash.meshEpochIDV1", "family.purposes.hash.meshEpochIDV1", .prefix),
            Overlap("family.radios.presence.serviceType", "family.radios.mesh.serviceType", .equal),
            Overlap("family.radios.pair.alpn", "family.radios.pair.alpn", .equal),
            Overlap("family.radios.meshHeartbeat", "family.radios.meshHeartbeat", .equal),
            Overlap("family.verifyQR.urlScheme", "family.verifyQR.urlScheme", .equal)
        ]
        #expect(alpha.familyCollisions(with: bravo).map { Overlap($0) } == expected)
        #expect(bravo.familyCollisions(with: alpha).map { Overlap($0) } == expected.map { $0.swapped },
                "seen from the other side, the same overlaps")
        #expect(alpha.installationCollisions(with: bravo).isEmpty, "and the installations stay apart")
    }

    /// An equal keychain service across rows, the same directory name in another case, and the same log
    /// subsystem.
    @Test func installationCollisionsReportEqualServicesDirectoryAndSubsystem() {
        let alpha = AlphaApp.namespace()
        let bravo = ProximityNamespace(
            family: BravoApp.family(),
            installation: BravoApp.installation(
                keychain: BravoApp.keychain(
                    meshSessionSealKey: .init(service: "org.example.alpha.identity", account: "session.seal")),
                storage: BravoApp.storage(directoryName: "ALPHA"),
                logSubsystem: "org.example.alpha"
            )
        )
        #expect(alpha.installationCollisions(with: bravo).map { Overlap($0) } == [
            Overlap("installation.keychain.identity.service", "installation.keychain.meshSessionSealKey.service", .equal),
            Overlap("installation.storage.directoryName", "installation.storage.directoryName", .equal),
            Overlap("installation.logSubsystem", "installation.logSubsystem", .equal)
        ])
        #expect(alpha.familyCollisions(with: bravo).isEmpty, "and the families stay apart")
    }

    /// Two apps of one family, such as an app and its companion, collide on every family value by design
    /// and on nothing of their installations: the case `installationCollisions` exists for.
    @Test func aSharedFamilyCollidesOnlyAsAFamily() {
        let alpha = AlphaApp.namespace()
        let companion = ProximityNamespace(family: AlphaApp.family(), installation: BravoApp.installation())
        #expect(companion.soundness == .sound)
        #expect(companion.installationCollisions(with: alpha).isEmpty)
        let shared = companion.familyCollisions(with: alpha)
        #expect(shared.count == 39 + 3 + 3 + 1 + 1, "every label, service type and ALPN, the heartbeat and the scheme")
        #expect(shared.allSatisfy { $0.kind == .equal && $0.field == $0.otherField })
    }

    /// The feature salts each family declares are compared across families like every other label: a
    /// salt equal to the other family's declared salt, and one that begins the other family's protocol
    /// label, are each reported once, named by its field path in each namespace, from either side.
    @Test func familyCollisionsReportTheFeatureSaltsTwoFamiliesShare() {
        let alpha = ProximityNamespace(
            family: AlphaApp.family(feature: ProximityNamespace.FeaturePurposes([
                "pairV1": .featureKeyDerivationSalt("shared.feature.pair.v1"),
                "tagV1": .featureKeyDerivationSalt("bravo.verify.qr")
            ])),
            installation: AlphaApp.installation()
        )
        let bravo = ProximityNamespace(
            family: BravoApp.family(feature: ProximityNamespace.FeaturePurposes([
                "handshakeV1": .featureKeyDerivationSalt("shared.feature.pair.v1")
            ])),
            installation: BravoApp.installation()
        )
        #expect(alpha.soundness == .sound && bravo.soundness == .sound, "each family is sound on its own")
        #expect(alpha.familyCollisions(with: bravo).map { Overlap($0) } == [
            Overlap("family.purposes.feature.pairV1", "family.purposes.feature.handshakeV1", .equal),
            Overlap("family.purposes.feature.tagV1", "family.purposes.signature.proximityQRIdentityV1", .prefix)
        ])
        #expect(bravo.familyCollisions(with: alpha).map { Overlap($0) } == [
            Overlap("family.purposes.signature.proximityQRIdentityV1", "family.purposes.feature.tagV1", .prefix),
            Overlap("family.purposes.feature.handshakeV1", "family.purposes.feature.pairV1", .equal)
        ], "seen from the other side, the same overlaps in its own row order")
        #expect(alpha.installationCollisions(with: bravo).isEmpty, "and the installations stay apart")
    }

    /// Two unrelated apps overlap nowhere, from either side.
    @Test func twoUnrelatedAppsDoNotCollide() {
        let alpha = AlphaApp.namespace()
        let bravo = BravoApp.namespace()
        #expect(alpha.familyCollisions(with: bravo).isEmpty)
        #expect(alpha.installationCollisions(with: bravo).isEmpty)
        #expect(bravo.familyCollisions(with: alpha).isEmpty)
        #expect(bravo.installationCollisions(with: alpha).isEmpty)
    }

    // MARK: - Storage

    /// An installation's folder is its name, as a directory, directly under whatever base its host
    /// picks (plan step A0.6.6: the module computes no directory of its own): under Application
    /// Support, where an iOS host keeps its files, and under a scratch base, as an unsandboxed Mac host
    /// would pick one no other app shares. Pure: nothing is read or created on disk.
    @Test func anInstallationsFolderIsItsNameUnderTheBaseItsHostPicks() {
        let scratch = FileManager.default.temporaryDirectory
            .appendingPathComponent("ProximityNamespaceSoundness-\(UUID().uuidString)", isDirectory: true)
        // R2: bounded by the two bases.
        for base in [URL.applicationSupportDirectory, scratch] {
            let directory = AlphaApp.installation().storage.directory(under: base)
            #expect(directory.lastPathComponent == "Alpha", "the folder under \(base.path) is \(directory.lastPathComponent)")
            #expect(directory.hasDirectoryPath, "the folder under \(base.path) is not a directory URL")
            #expect(directory.deletingLastPathComponent().standardizedFileURL == base.standardizedFileURL,
                    "the folder's parent is not \(base.path)")
        }
    }

    // MARK: - Helpers

    /// Expects exactly `expected`, in order, both as the initializer records them and as `validated`
    /// throws them.
    private func expectOnly(
        _ expected: [ProximityNamespace.Violation],
        family: ProximityNamespace.Family = AlphaApp.family(),
        installation: ProximityNamespace.Installation = AlphaApp.installation(),
        note: String = "",
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        let namespace = ProximityNamespace(family: family, installation: installation)
        #expect(namespace.soundness == .unsound(expected), Comment(rawValue: note), sourceLocation: sourceLocation)
        let thrown = #expect(throws: ProximityNamespaceError.self, Comment(rawValue: note), sourceLocation: sourceLocation) {
            try ProximityNamespace.validated(family: family, installation: installation)
        }
        #expect(thrown?.violations == expected, Comment(rawValue: note), sourceLocation: sourceLocation)
    }

    /// Expects a sound namespace: a rule's accepting edge.
    private func expectSound(
        family: ProximityNamespace.Family = AlphaApp.family(),
        installation: ProximityNamespace.Installation = AlphaApp.installation(),
        note: String = "",
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        let soundness = ProximityNamespace(family: family, installation: installation).soundness
        #expect(soundness == .sound, Comment(rawValue: note), sourceLocation: sourceLocation)
    }

    /// Lowercase hex, two digits a byte.
    private func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Fixtures

/// A collision as plain values, so a cell can spell the ones it expects (the type's initializer is
/// ProximityKit's own).
private struct Overlap: Equatable, CustomStringConvertible {
    let field: String
    let otherField: String
    let kind: ProximityNamespace.Collision.Kind

    init(_ field: String, _ otherField: String, _ kind: ProximityNamespace.Collision.Kind) {
        self.field = field
        self.otherField = otherField
        self.kind = kind
    }

    init(_ collision: ProximityNamespace.Collision) {
        self.init(collision.field, collision.otherField, collision.kind)
    }

    /// The same overlap, seen from the other namespace.
    var swapped: Overlap { Overlap(otherField, field, kind) }

    var description: String { "\(field) ~ \(otherField) (\(kind))" }
}

/// An app that does not exist, "alpha", its namespace built entirely from literals.
///
/// Every label is printable ASCII, distinct and prefix-free, and every radio, keychain and storage value
/// is well-formed and distinct, so the namespace is sound. A cell changes one literal through a parameter.
private enum AlphaApp {

    static let legacy = ProximityNamespace.LegacyV1.accepted(
        identityEnvelopeV1: "alpha.canonical.identity-envelope.v1",
        meshAdmissionTokenV1: "alpha.canonical.mesh-admission-token.v1"
    )

    static let identityRows = ProximityNamespace.Keychain.IdentityRows(
        service: "org.example.alpha.identity", signingPrivateKey: "signing.private",
        keyAgreementPrivateKey: "agreement.private", signingPublicKeyCache: "signing.public",
        keyAgreementPublicKeyCache: "agreement.public"
    )

    static func namespace() -> ProximityNamespace {
        ProximityNamespace(family: family(), installation: installation())
    }

    static func family(
        signature: ProximityNamespace.Signature = AlphaApp.signature(),
        keyDerivation: ProximityNamespace.KeyDerivation = AlphaApp.keyDerivation(),
        aead: ProximityNamespace.AEAD = AlphaApp.aead(),
        hash: ProximityNamespace.Hash = AlphaApp.hash(),
        feature: ProximityNamespace.FeaturePurposes = .none,
        radios: ProximityNamespace.Radios = AlphaApp.radios(),
        urlScheme: String = "alpha",
        vocabulary: ProximityNamespace.Vocabulary = AlphaApp.vocabulary()
    ) -> ProximityNamespace.Family {
        ProximityNamespace.Family(
            purposes: ProximityNamespace.Purposes(
                signature: signature, keyDerivation: keyDerivation, aead: aead, hash: hash, feature: feature),
            radios: radios,
            verifyQR: ProximityNamespace.VerifyQR(urlScheme: urlScheme),
            vocabulary: vocabulary
        )
    }

    static func signature(
        identityEnvelopeV2: StaticString = "alpha.canonical.identity-envelope.v2",
        legacyV1: ProximityNamespace.LegacyV1 = AlphaApp.legacy
    ) -> ProximityNamespace.Signature {
        ProximityNamespace.Signature(
            identityEnvelopeV2: identityEnvelopeV2,
            meshAdmissionTokenV2: "alpha.canonical.mesh-admission-token.v2",
            meshChannelIntroductionV1: "alpha.mesh.channel-introduction.v1",
            meshMemberDepartureV1: "alpha.mesh.member-departure.v1",
            meshMemberRemovalV1: "alpha.mesh.member-removal.v1",
            meshTerminatedV1: "alpha.mesh.terminated.v1",
            meshInventoryDigestV1: "alpha.mesh.inventory-digest.v1",
            meshEpochHeadsV1: "alpha.mesh.epoch-heads.v1",
            meshRemovalProposalV1: "alpha.mesh.removal-proposal.v1",
            meshRemovalVoteV1: "alpha.mesh.removal-vote.v1",
            meshKeyAgreementV1: "alpha.mesh.key-agreement.v1",
            meshRoutedManifestV1: "alpha.mesh.routed-manifest.v1",
            meshRoutedChunkV1: "alpha.mesh.routed-chunk.v1",
            meshCustodyReceiptV1: "alpha.mesh.custody-receipt.v1",
            meshRecipientReceiptV1: "alpha.mesh.recipient-receipt.v1",
            meshRoutedInventoryDigestV1: "alpha.mesh.routed-inventory-digest.v1",
            meshRoutedDrainAnswerV1: "alpha.mesh.routed-drain-answer.v1",
            proximityQRIdentityV1: "alpha.verify.qr.v1",
            proximityQRResponseV1: "alpha.verify.response.v1",
            legacyV1: legacyV1
        )
    }

    static func keyDerivation(
        meshRoutedStoreV1: StaticString = "alpha.mesh.routed-store.v1"
    ) -> ProximityNamespace.KeyDerivation {
        ProximityNamespace.KeyDerivation(
            proximityTransportV1: "alpha.proximity.v1",
            meshGroupKeyWrapV1: "alpha.mesh.groupkey.v1",
            meshTLSExporterV1: "alpha.mesh.tls-exporter.v1",
            meshRoutedContentKeyWrapV1: "alpha.mesh.routed.content-key.v1",
            meshSessionContextV1: "alpha.mesh.session-context.v1",
            meshRoutedStoreV1: meshRoutedStoreV1
        )
    }

    static func aead() -> ProximityNamespace.AEAD {
        ProximityNamespace.AEAD(
            proximityTransportV2: "alpha.proximity.transport.aead.v2",
            meshGroupKeyWrapV2: "alpha.mesh.groupkey.wrap.aead.v2",
            meshEncryptedMetadataV2: "alpha.mesh.encrypted-metadata.aead.v2",
            meshRoutedContentKeyWrapV1: "alpha.mesh.routed.content-key.wrap.aead.v1",
            meshRoutedItemV1: "alpha.mesh.routed.item.aead.v1"
        )
    }

    static func hash(meshEpochIDV1: StaticString = "alpha.mesh.epoch.v1") -> ProximityNamespace.Hash {
        ProximityNamespace.Hash(
            meshInventoryDigestV1: "alpha.mesh.inventory-digest.hash.v1",
            meshRoutedContentV1: "alpha.mesh.routed-content.hash.v1",
            meshRoutedChunkV1: "alpha.mesh.routed-chunk.hash.v1",
            meshRoutedChunkIDV1: "alpha.mesh.routed-chunk-id.hash.v1",
            meshCustodyReceiptIDV1: "alpha.mesh.custody-receipt-id.hash.v1",
            meshRecipientReceiptIDV1: "alpha.mesh.recipient-receipt-id.hash.v1",
            meshEpochIDV1: meshEpochIDV1
        )
    }

    static func radios(
        mesh: ProximityNamespace.Radio = .init(serviceType: "_alpha-mesh._udp", alpn: "alpha-mesh-v1"),
        presence: ProximityNamespace.Radio = .init(serviceType: "_alpha-near._udp", alpn: "alpha-near-v1"),
        pair: ProximityNamespace.Radio = .init(serviceType: "_alpha-recipe._udp", alpn: "alpha-recipe-v1"),
        meshHeartbeat: Data = Data("alpha-heartbeat".utf8),
        meshInstanceNamePrefix: String = "alpha-mesh-",
        presenceInstanceNamePrefix: String = "an-",
        tlsCommonName: String = "alpha-mesh"
    ) -> ProximityNamespace.Radios {
        ProximityNamespace.Radios(mesh: mesh, presence: presence, pair: pair, meshHeartbeat: meshHeartbeat,
                                  meshInstanceNamePrefix: meshInstanceNamePrefix,
                                  presenceInstanceNamePrefix: presenceInstanceNamePrefix, tlsCommonName: tlsCommonName)
    }

    /// The three session payload tokens, each also one of ``payloadTokens``.
    static let sessionTokens = ["alpha.session.hello.v1", "alpha.session.welcome.v1", "alpha.session.beat.v1"]

    /// Alpha's token for the mesh message named `name`.
    static func meshToken(_ name: String) -> String { "alpha.mesh.\(name).v1" }

    /// Every payload token alpha dispatches: the session's three, three of its features' and its
    /// thirty mesh messages.
    static let payloadTokens = Set(sessionTokens + ["alpha.note.v1", "alpha.sketch.v1", "alpha.wave.v1"]
                                   + ProximityNamespace.MeshMessages.tokens(AlphaApp.meshToken))

    /// Alpha's capability tokens, in order.
    static let capabilityTokens = ["alpha-notes", "alpha-sketches", "alpha-framing"]

    static func vocabulary(
        session: ProximityNamespace.SessionMessages = AlphaApp.session(),
        payloads: ProximityNamespace.PayloadRules = AlphaApp.payloads(),
        capabilities: ProximityNamespace.Capabilities = AlphaApp.capabilities(),
        membershipRecordKinds: ProximityNamespace.MembershipRecordKinds = AlphaApp.recordKinds(),
        routedTypes: ProximityNamespace.RoutedTypes = AlphaApp.routedTypes(),
        mesh: ProximityNamespace.MeshMessages = AlphaApp.meshMessages()
    ) -> ProximityNamespace.Vocabulary {
        ProximityNamespace.Vocabulary(session: session, payloads: payloads, capabilities: capabilities,
                                      membershipRecordKinds: membershipRecordKinds, routedTypes: routedTypes,
                                      mesh: mesh)
    }

    /// Alpha's thirty mesh messages, each ``meshToken(_:)`` of its field's name, but for the fields
    /// `replacing` names, which carry the token it gives them.
    static func meshMessages(replacing: [String: String] = [:]) -> ProximityNamespace.MeshMessages {
        .spelled { replacing[$0] ?? meshToken($0) }
    }

    static func session(
        introductionType: String = AlphaApp.sessionTokens[0],
        acknowledgeType: String = AlphaApp.sessionTokens[1],
        heartbeatType: String = AlphaApp.sessionTokens[2],
        introductionTitle: String = "Alpha hello",
        acknowledgeTitle: String = "Alpha welcome",
        pingTitle: String = "Alpha beat",
        replyTitle: String = "Alpha beat back"
    ) -> ProximityNamespace.SessionMessages {
        ProximityNamespace.SessionMessages(
            identityIntroduction: .init(payloadType: introductionType, summaryTitle: introductionTitle),
            identityAcknowledge: .init(payloadType: acknowledgeType, summaryTitle: acknowledgeTitle),
            heartbeat: .init(payloadType: heartbeatType, pingTitle: pingTitle, replyTitle: replyTitle)
        )
    }

    static func payloads(
        known: Set<String> = AlphaApp.payloadTokens,
        sealingRequired: Set<String> = ["alpha.note.v1", "alpha.sketch.v1"]
    ) -> ProximityNamespace.PayloadRules {
        ProximityNamespace.PayloadRules(known: known, sealingRequired: sealingRequired)
    }

    static func capabilities(
        known: [String] = AlphaApp.capabilityTokens,
        wire2: String = "alpha-framing",
        assumedForLegacyPeers: [String] = ["alpha-notes"]
    ) -> ProximityNamespace.Capabilities {
        ProximityNamespace.Capabilities(known: known, wire2: wire2, assumedForLegacyPeers: assumedForLegacyPeers)
    }

    static func recordKinds(
        admission: String = "alpha.member.joined.v1",
        departure: String = "alpha.member.left.v1"
    ) -> ProximityNamespace.MembershipRecordKinds {
        ProximityNamespace.MembershipRecordKinds(
            admission: admission, departure: departure,
            removal: "alpha.member.removed.v1", termination: "alpha.group.ended.v1"
        )
    }

    static func routedTypes(
        photo: String = "alpha.routed.picture.v1",
        heart: String = "alpha.routed.wave.v1"
    ) -> ProximityNamespace.RoutedTypes {
        ProximityNamespace.RoutedTypes(
            photo: photo, tempMessage: "alpha.routed.note.v1", heart: heart, control: "alpha.routed.control.v1"
        )
    }

    static func installation(
        keychain: ProximityNamespace.Keychain = AlphaApp.keychain(),
        storage: ProximityNamespace.Storage = AlphaApp.storage(),
        logSubsystem: String = "org.example.alpha",
        peerNames: ProximityNamespace.PeerNames = AlphaApp.peerNames()
    ) -> ProximityNamespace.Installation {
        ProximityNamespace.Installation(keychain: keychain, storage: storage, logSubsystem: logSubsystem,
                                        peerNames: peerNames)
    }

    static func peerNames(maxLength: Int = 32, floor: String = "An alpha friend") -> ProximityNamespace.PeerNames {
        ProximityNamespace.PeerNames(maxLength: maxLength, floor: floor)
    }

    static func keychain(
        identity: ProximityNamespace.Keychain.IdentityRows = AlphaApp.identityRows,
        meshSessionSealKey: ProximityNamespace.Keychain.Row = .init(service: "org.example.alpha.mesh-session", account: "session.seal"),
        meshRoutedSealKey: ProximityNamespace.Keychain.Row = .init(service: "org.example.alpha.mesh-routed", account: "routed.seal")
    ) -> ProximityNamespace.Keychain {
        ProximityNamespace.Keychain(identity: identity, meshSessionSealKey: meshSessionSealKey, meshRoutedSealKey: meshRoutedSealKey)
    }

    static func storage(
        directoryName: String = "Alpha",
        meshSessionContextFileName: String = "Session.sealed",
        meshRoutedIndexFileName: String = "Routed.sealed",
        meshRoutedChunkDirectoryName: String = "RoutedChunks"
    ) -> ProximityNamespace.Storage {
        ProximityNamespace.Storage(
            directoryName: directoryName,
            meshSessionContextFileName: meshSessionContextFileName,
            meshRoutedIndexFileName: meshRoutedIndexFileName,
            meshRoutedChunkDirectoryName: meshRoutedChunkDirectoryName
        )
    }
}

/// A second app that does not exist, "bravo": disjoint from ``AlphaApp`` everywhere until a cell makes
/// the two collide.
private enum BravoApp {

    static let legacy = ProximityNamespace.LegacyV1.accepted(
        identityEnvelopeV1: "bravo.canonical.identity-envelope.v1",
        meshAdmissionTokenV1: "bravo.canonical.mesh-admission-token.v1"
    )

    static func namespace() -> ProximityNamespace {
        ProximityNamespace(family: family(), installation: installation())
    }

    static func family(
        signature: ProximityNamespace.Signature = BravoApp.signature(),
        aead: ProximityNamespace.AEAD = BravoApp.aead(),
        hash: ProximityNamespace.Hash = BravoApp.hash(),
        feature: ProximityNamespace.FeaturePurposes = .none,
        radios: ProximityNamespace.Radios = BravoApp.radios(),
        urlScheme: String = "bravo"
    ) -> ProximityNamespace.Family {
        let keyDerivation = ProximityNamespace.KeyDerivation(
            proximityTransportV1: "bravo.proximity.v1",
            meshGroupKeyWrapV1: "bravo.mesh.groupkey.v1",
            meshTLSExporterV1: "bravo.mesh.tls-exporter.v1",
            meshRoutedContentKeyWrapV1: "bravo.mesh.routed.content-key.v1",
            meshSessionContextV1: "bravo.mesh.session-context.v1",
            meshRoutedStoreV1: "bravo.mesh.routed-store.v1"
        )
        return ProximityNamespace.Family(
            purposes: ProximityNamespace.Purposes(
                signature: signature, keyDerivation: keyDerivation, aead: aead, hash: hash, feature: feature),
            radios: radios,
            verifyQR: ProximityNamespace.VerifyQR(urlScheme: urlScheme),
            vocabulary: vocabulary()
        )
    }

    static func vocabulary() -> ProximityNamespace.Vocabulary {
        let meshToken = { (name: String) in "bravo.mesh.\(name).v1" }
        return ProximityNamespace.Vocabulary(
            session: ProximityNamespace.SessionMessages(
                identityIntroduction: .init(payloadType: "bravo.session.hello.v1", summaryTitle: "Bravo hello"),
                identityAcknowledge: .init(payloadType: "bravo.session.welcome.v1", summaryTitle: "Bravo welcome"),
                heartbeat: .init(payloadType: "bravo.session.beat.v1", pingTitle: "Bravo beat", replyTitle: "Bravo beat back")
            ),
            payloads: ProximityNamespace.PayloadRules(
                known: Set(["bravo.session.hello.v1", "bravo.session.welcome.v1", "bravo.session.beat.v1", "bravo.note.v1"]
                           + ProximityNamespace.MeshMessages.tokens(meshToken)),
                sealingRequired: ["bravo.note.v1"]
            ),
            capabilities: ProximityNamespace.Capabilities(
                known: ["bravo-notes", "bravo-framing"], wire2: "bravo-framing", assumedForLegacyPeers: []
            ),
            membershipRecordKinds: ProximityNamespace.MembershipRecordKinds(
                admission: "bravo.member.joined.v1", departure: "bravo.member.left.v1",
                removal: "bravo.member.removed.v1", termination: "bravo.group.ended.v1"
            ),
            routedTypes: ProximityNamespace.RoutedTypes(
                photo: "bravo.routed.picture.v1", tempMessage: "bravo.routed.note.v1",
                heart: "bravo.routed.wave.v1", control: "bravo.routed.control.v1"
            ),
            mesh: .spelled(meshToken)
        )
    }

    static func signature(
        meshRoutedChunkV1: StaticString = "bravo.mesh.routed-chunk.v1"
    ) -> ProximityNamespace.Signature {
        ProximityNamespace.Signature(
            identityEnvelopeV2: "bravo.canonical.identity-envelope.v2",
            meshAdmissionTokenV2: "bravo.canonical.mesh-admission-token.v2",
            meshChannelIntroductionV1: "bravo.mesh.channel-introduction.v1",
            meshMemberDepartureV1: "bravo.mesh.member-departure.v1",
            meshMemberRemovalV1: "bravo.mesh.member-removal.v1",
            meshTerminatedV1: "bravo.mesh.terminated.v1",
            meshInventoryDigestV1: "bravo.mesh.inventory-digest.v1",
            meshEpochHeadsV1: "bravo.mesh.epoch-heads.v1",
            meshRemovalProposalV1: "bravo.mesh.removal-proposal.v1",
            meshRemovalVoteV1: "bravo.mesh.removal-vote.v1",
            meshKeyAgreementV1: "bravo.mesh.key-agreement.v1",
            meshRoutedManifestV1: "bravo.mesh.routed-manifest.v1",
            meshRoutedChunkV1: meshRoutedChunkV1,
            meshCustodyReceiptV1: "bravo.mesh.custody-receipt.v1",
            meshRecipientReceiptV1: "bravo.mesh.recipient-receipt.v1",
            meshRoutedInventoryDigestV1: "bravo.mesh.routed-inventory-digest.v1",
            meshRoutedDrainAnswerV1: "bravo.mesh.routed-drain-answer.v1",
            proximityQRIdentityV1: "bravo.verify.qr.v1",
            proximityQRResponseV1: "bravo.verify.response.v1",
            legacyV1: BravoApp.legacy
        )
    }

    static func aead(meshRoutedItemV1: StaticString = "bravo.mesh.routed.item.aead.v1") -> ProximityNamespace.AEAD {
        ProximityNamespace.AEAD(
            proximityTransportV2: "bravo.proximity.transport.aead.v2",
            meshGroupKeyWrapV2: "bravo.mesh.groupkey.wrap.aead.v2",
            meshEncryptedMetadataV2: "bravo.mesh.encrypted-metadata.aead.v2",
            meshRoutedContentKeyWrapV1: "bravo.mesh.routed.content-key.wrap.aead.v1",
            meshRoutedItemV1: meshRoutedItemV1
        )
    }

    static func hash(meshEpochIDV1: StaticString = "bravo.mesh.epoch.v1") -> ProximityNamespace.Hash {
        ProximityNamespace.Hash(
            meshInventoryDigestV1: "bravo.mesh.inventory-digest.hash.v1",
            meshRoutedContentV1: "bravo.mesh.routed-content.hash.v1",
            meshRoutedChunkV1: "bravo.mesh.routed-chunk.hash.v1",
            meshRoutedChunkIDV1: "bravo.mesh.routed-chunk-id.hash.v1",
            meshCustodyReceiptIDV1: "bravo.mesh.custody-receipt-id.hash.v1",
            meshRecipientReceiptIDV1: "bravo.mesh.recipient-receipt-id.hash.v1",
            meshEpochIDV1: meshEpochIDV1
        )
    }

    static func radios(
        mesh: ProximityNamespace.Radio = .init(serviceType: "_bravo-mesh._udp", alpn: "bravo-mesh-v1"),
        pair: ProximityNamespace.Radio = .init(serviceType: "_bravo-recipe._udp", alpn: "bravo-recipe-v1"),
        meshHeartbeat: Data = Data("bravo-heartbeat".utf8)
    ) -> ProximityNamespace.Radios {
        ProximityNamespace.Radios(
            mesh: mesh,
            presence: .init(serviceType: "_bravo-near._udp", alpn: "bravo-near-v1"),
            pair: pair,
            meshHeartbeat: meshHeartbeat,
            meshInstanceNamePrefix: "bravo-mesh-",
            presenceInstanceNamePrefix: "bn-",
            tlsCommonName: "bravo-mesh"
        )
    }

    static func installation(
        keychain: ProximityNamespace.Keychain = BravoApp.keychain(),
        storage: ProximityNamespace.Storage = BravoApp.storage(),
        logSubsystem: String = "org.example.bravo"
    ) -> ProximityNamespace.Installation {
        ProximityNamespace.Installation(keychain: keychain, storage: storage, logSubsystem: logSubsystem,
                                        peerNames: ProximityNamespace.PeerNames(maxLength: 20, floor: "A bravo friend"))
    }

    static func keychain(
        meshSessionSealKey: ProximityNamespace.Keychain.Row = .init(service: "org.example.bravo.mesh-session", account: "session.seal")
    ) -> ProximityNamespace.Keychain {
        ProximityNamespace.Keychain(
            identity: .init(
                service: "org.example.bravo.identity", signingPrivateKey: "signing.private",
                keyAgreementPrivateKey: "agreement.private", signingPublicKeyCache: "signing.public",
                keyAgreementPublicKeyCache: "agreement.public"
            ),
            meshSessionSealKey: meshSessionSealKey,
            meshRoutedSealKey: .init(service: "org.example.bravo.mesh-routed", account: "routed.seal")
        )
    }

    static func storage(directoryName: String = "Bravo") -> ProximityNamespace.Storage {
        ProximityNamespace.Storage(
            directoryName: directoryName,
            meshSessionContextFileName: "Session.sealed",
            meshRoutedIndexFileName: "Routed.sealed",
            meshRoutedChunkDirectoryName: "RoutedChunks"
        )
    }
}
