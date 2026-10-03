// ProximityNamespace+Family.swift
// ProximityKit/Namespace
//
// The family half of `ProximityNamespace`: what every interoperating app shares. The labels are
// grouped and named like FernletCrypto's registry (Signature, KeyDerivation, AEAD, Hash), so each read
// site A0.2's later commits re-pointed only re-cased the family name. Every label initializer takes
// `StaticString` and mints each purpose with the role its field fixes; nothing here takes a role. The
// payload vocabulary the family also carries is declared in `ProximityNamespace+Vocabulary.swift`.

import Foundation

nonisolated extension ProximityNamespace {

    // MARK: - Family

    /// What every interoperating app shares: the domain-separation labels, the radios, the QR scheme
    /// and the payload vocabulary.
    ///
    /// Two apps that supply one family speak one wire. That is the only way two namespaces can, which
    /// is why a family is built from the host's literals and never from another app's value by default.
    public nonisolated struct Family: Hashable, Sendable {
        /// Every domain-separation label, by consumer family.
        public let purposes: Purposes
        /// The three radios' discovery and protocol values, the mesh heartbeat and the radios'
        /// presentation strings.
        public let radios: Radios
        /// The verify QR's URL scheme.
        public let verifyQR: VerifyQR
        /// The payload vocabulary: session messages, payload and capability tokens, record kinds and
        /// routed types.
        public let vocabulary: Vocabulary

        /// Assembles a family.
        ///
        /// - Parameters:
        ///   - purposes: Every domain-separation label.
        ///   - radios: The radios' service types, ALPNs, heartbeat and presentation strings.
        ///   - verifyQR: The verify QR's URL scheme.
        ///   - vocabulary: The payload vocabulary.
        public init(purposes: Purposes, radios: Radios, verifyQR: VerifyQR, vocabulary: Vocabulary) {
            self.purposes = purposes
            self.radios = radios
            self.verifyQR = verifyQR
            self.vocabulary = vocabulary
        }
    }

    // MARK: - Purposes

    /// Every domain-separation label, grouped and named like FernletCrypto's registry so that a read
    /// site only re-cases the family name.
    public nonisolated struct Purposes: Hashable, Sendable {
        /// The labels at the front of signature transcripts.
        public let signature: Signature
        /// The labels key derivations, column seals and the TLS exporter take whole.
        public let keyDerivation: KeyDerivation
        /// The labels at the front of AEAD authenticated data.
        public let aead: AEAD
        /// The labels at the front of hash preimages.
        public let hash: Hash

        /// Assembles the four groups.
        ///
        /// - Parameters:
        ///   - signature: The signature transcript labels.
        ///   - keyDerivation: The key-derivation, column-seal and exporter labels.
        ///   - aead: The authenticated-data labels.
        ///   - hash: The hash-preimage labels.
        public init(signature: Signature, keyDerivation: KeyDerivation, aead: AEAD, hash: Hash) {
            self.signature = signature
            self.keyDerivation = keyDerivation
            self.aead = aead
            self.hash = hash
        }
    }

    // MARK: - Signature

    /// The labels at the front of Ed25519 signature transcripts.
    ///
    /// Roles, fixed here: the seventeen canonical transcripts are `.signature(.lengthPrefixed)`, because
    /// the canonical serializer writes every field, the domain included, behind an 8-byte count; the two
    /// verify-QR transcripts are `.signature(.rawPrefix)`, fixed-width layouts that begin with the
    /// label's bytes; and the legacy pair in ``legacyV1`` is `.signature(.absent)`.
    public nonisolated struct Signature: Hashable, Sendable {
        /// The identity envelope's canonical transcript: every envelope on every radio is signed under it.
        public let identityEnvelopeV2: ProximityCryptographicPurpose
        /// The mesh admission token's canonical transcript, and the admission record built from it.
        public let meshAdmissionTokenV2: ProximityCryptographicPurpose
        /// The mutually signed QUIC channel introduction that authenticates a mesh tunnel.
        public let meshChannelIntroductionV1: ProximityCryptographicPurpose
        /// A leaver's signed departure record.
        public let meshMemberDepartureV1: ProximityCryptographicPurpose
        /// The tallier's signed removal record.
        public let meshMemberRemovalV1: ProximityCryptographicPurpose
        /// A final-pair member's signed termination record.
        public let meshTerminatedV1: ProximityCryptographicPurpose
        /// The signed membership inventory digest message.
        public let meshInventoryDigestV1: ProximityCryptographicPurpose
        /// The signed epoch-heads message.
        public let meshEpochHeadsV1: ProximityCryptographicPurpose
        /// A signed removal proposal.
        public let meshRemovalProposalV1: ProximityCryptographicPurpose
        /// A signed removal vote.
        public let meshRemovalVoteV1: ProximityCryptographicPurpose
        /// A member's signed key-agreement advertisement.
        public let meshKeyAgreementV1: ProximityCryptographicPurpose
        /// A routed item's signed manifest.
        public let meshRoutedManifestV1: ProximityCryptographicPurpose
        /// A signed routed chunk.
        public let meshRoutedChunkV1: ProximityCryptographicPurpose
        /// A signed custody receipt.
        public let meshCustodyReceiptV1: ProximityCryptographicPurpose
        /// A signed recipient receipt.
        public let meshRecipientReceiptV1: ProximityCryptographicPurpose
        /// The signed routed inventory digest.
        public let meshRoutedInventoryDigestV1: ProximityCryptographicPurpose
        /// A signed routed drain answer.
        public let meshRoutedDrainAnswerV1: ProximityCryptographicPurpose
        /// The verify QR's fixed-width identity transcript.
        public let proximityQRIdentityV1: ProximityCryptographicPurpose
        /// The verify ceremony's fixed-width challenge response.
        public let proximityQRResponseV1: ProximityCryptographicPurpose
        /// The verify-only legacy pair, or ``LegacyV1/refused``.
        public let legacyV1: LegacyV1

        /// Mints every signature label from the host's literals, each with the role its field fixes.
        ///
        /// - Parameters:
        ///   - identityEnvelopeV2: The identity envelope's canonical transcript label.
        ///   - meshAdmissionTokenV2: The admission token's canonical transcript label.
        ///   - meshChannelIntroductionV1: The QUIC channel introduction's label.
        ///   - meshMemberDepartureV1: The departure record's label.
        ///   - meshMemberRemovalV1: The removal record's label.
        ///   - meshTerminatedV1: The termination record's label.
        ///   - meshInventoryDigestV1: The inventory digest message's label.
        ///   - meshEpochHeadsV1: The epoch-heads message's label.
        ///   - meshRemovalProposalV1: The removal proposal's label.
        ///   - meshRemovalVoteV1: The removal vote's label.
        ///   - meshKeyAgreementV1: The key-agreement advertisement's label.
        ///   - meshRoutedManifestV1: The routed manifest's label.
        ///   - meshRoutedChunkV1: The routed chunk's label.
        ///   - meshCustodyReceiptV1: The custody receipt's label.
        ///   - meshRecipientReceiptV1: The recipient receipt's label.
        ///   - meshRoutedInventoryDigestV1: The routed inventory digest's label.
        ///   - meshRoutedDrainAnswerV1: The routed drain answer's label.
        ///   - proximityQRIdentityV1: The verify QR identity transcript's label.
        ///   - proximityQRResponseV1: The verify challenge response's label.
        ///   - legacyV1: The legacy pair, or ``LegacyV1/refused``.
        public init(
            identityEnvelopeV2: StaticString, meshAdmissionTokenV2: StaticString,
            meshChannelIntroductionV1: StaticString, meshMemberDepartureV1: StaticString,
            meshMemberRemovalV1: StaticString, meshTerminatedV1: StaticString,
            meshInventoryDigestV1: StaticString, meshEpochHeadsV1: StaticString,
            meshRemovalProposalV1: StaticString, meshRemovalVoteV1: StaticString,
            meshKeyAgreementV1: StaticString, meshRoutedManifestV1: StaticString,
            meshRoutedChunkV1: StaticString, meshCustodyReceiptV1: StaticString,
            meshRecipientReceiptV1: StaticString, meshRoutedInventoryDigestV1: StaticString,
            meshRoutedDrainAnswerV1: StaticString, proximityQRIdentityV1: StaticString,
            proximityQRResponseV1: StaticString, legacyV1: LegacyV1
        ) {
            let canonical = ProximityCryptographicPurpose.Role.signature(.lengthPrefixed)
            let fixedWidth = ProximityCryptographicPurpose.Role.signature(.rawPrefix)
            self.identityEnvelopeV2 = ProximityCryptographicPurpose(identityEnvelopeV2, role: canonical)
            self.meshAdmissionTokenV2 = ProximityCryptographicPurpose(meshAdmissionTokenV2, role: canonical)
            self.meshChannelIntroductionV1 = ProximityCryptographicPurpose(meshChannelIntroductionV1, role: canonical)
            self.meshMemberDepartureV1 = ProximityCryptographicPurpose(meshMemberDepartureV1, role: canonical)
            self.meshMemberRemovalV1 = ProximityCryptographicPurpose(meshMemberRemovalV1, role: canonical)
            self.meshTerminatedV1 = ProximityCryptographicPurpose(meshTerminatedV1, role: canonical)
            self.meshInventoryDigestV1 = ProximityCryptographicPurpose(meshInventoryDigestV1, role: canonical)
            self.meshEpochHeadsV1 = ProximityCryptographicPurpose(meshEpochHeadsV1, role: canonical)
            self.meshRemovalProposalV1 = ProximityCryptographicPurpose(meshRemovalProposalV1, role: canonical)
            self.meshRemovalVoteV1 = ProximityCryptographicPurpose(meshRemovalVoteV1, role: canonical)
            self.meshKeyAgreementV1 = ProximityCryptographicPurpose(meshKeyAgreementV1, role: canonical)
            self.meshRoutedManifestV1 = ProximityCryptographicPurpose(meshRoutedManifestV1, role: canonical)
            self.meshRoutedChunkV1 = ProximityCryptographicPurpose(meshRoutedChunkV1, role: canonical)
            self.meshCustodyReceiptV1 = ProximityCryptographicPurpose(meshCustodyReceiptV1, role: canonical)
            self.meshRecipientReceiptV1 = ProximityCryptographicPurpose(meshRecipientReceiptV1, role: canonical)
            self.meshRoutedInventoryDigestV1 = ProximityCryptographicPurpose(meshRoutedInventoryDigestV1, role: canonical)
            self.meshRoutedDrainAnswerV1 = ProximityCryptographicPurpose(meshRoutedDrainAnswerV1, role: canonical)
            self.proximityQRIdentityV1 = ProximityCryptographicPurpose(proximityQRIdentityV1, role: fixedWidth)
            self.proximityQRResponseV1 = ProximityCryptographicPurpose(proximityQRResponseV1, role: fixedWidth)
            self.legacyV1 = legacyV1
        }
    }

    // MARK: - LegacyV1

    /// Schema-v1 identity envelopes and the admission tokens from before canonical serialization:
    /// formats that carry no label, verified for read compatibility only.
    ///
    /// Role `.signature(.absent)`: every transcript qualifies, so neither label is ever written or signed
    /// under, and its bytes matter only for being distinct. A family with no legacy peers takes
    /// ``refused``, and its verifiers then accept no legacy format.
    public nonisolated struct LegacyV1: Hashable, Sendable {
        /// A family with no legacy peers: neither label exists, and no legacy format verifies.
        public static let refused = LegacyV1(identityEnvelopeV1: nil, meshAdmissionTokenV1: nil)

        /// The schema-v1 identity envelope's label; `nil` when ``refused``.
        public let identityEnvelopeV1: ProximityCryptographicPurpose?
        /// The legacy admission token's label; `nil` when ``refused``.
        public let meshAdmissionTokenV1: ProximityCryptographicPurpose?

        /// A family whose peers may still send the two legacy formats, verified and never written.
        ///
        /// - Parameters:
        ///   - identityEnvelopeV1: The schema-v1 identity envelope's label.
        ///   - meshAdmissionTokenV1: The legacy admission token's label.
        /// - Returns: The accepted pair, both `.signature(.absent)`.
        public static func accepted(
            identityEnvelopeV1: StaticString,
            meshAdmissionTokenV1: StaticString
        ) -> LegacyV1 {
            let verifyOnly = ProximityCryptographicPurpose.Role.signature(.absent)
            return LegacyV1(
                identityEnvelopeV1: ProximityCryptographicPurpose(identityEnvelopeV1, role: verifyOnly),
                meshAdmissionTokenV1: ProximityCryptographicPurpose(meshAdmissionTokenV1, role: verifyOnly)
            )
        }

        /// The two doors are ``refused`` and ``accepted(identityEnvelopeV1:meshAdmissionTokenV1:)``,
        /// so a pair with one label and not the other cannot be built.
        private init(
            identityEnvelopeV1: ProximityCryptographicPurpose?,
            meshAdmissionTokenV1: ProximityCryptographicPurpose?
        ) {
            self.identityEnvelopeV1 = identityEnvelopeV1
            self.meshAdmissionTokenV1 = meshAdmissionTokenV1
        }
    }

    // MARK: - KeyDerivation

    /// The labels that key derivations, column seals and the TLS exporter take whole.
    ///
    /// Roles, fixed here: three HKDF salts (`.keyDerivationSalt`), the QUIC channel binding's exporter
    /// label (`.tlsExporterLabel`) and the two sealed mesh stores' column seals (`.columnSeal`). The
    /// stored properties follow the initializer's order, which is also the order of
    /// ``ProximityNamespace/labelRows``.
    public nonisolated struct KeyDerivation: Hashable, Sendable {
        /// HKDF salt of the pairwise sealed payload: every sealed payload and sealed introduction.
        public let proximityTransportV1: ProximityCryptographicPurpose
        /// HKDF salt of the mesh group-key wrap.
        public let meshGroupKeyWrapV1: ProximityCryptographicPurpose
        /// The TLS exporter label of the QUIC mesh channel binding.
        public let meshTLSExporterV1: ProximityCryptographicPurpose
        /// HKDF salt of the routed per-recipient content-key wrap.
        public let meshRoutedContentKeyWrapV1: ProximityCryptographicPurpose
        /// Column seal of the sealed mesh-session context file.
        public let meshSessionContextV1: ProximityCryptographicPurpose
        /// Column seal of the routed store's sealed index and chunks.
        public let meshRoutedStoreV1: ProximityCryptographicPurpose

        /// Mints every key-derivation label from the host's literals, each with the role its field fixes.
        ///
        /// - Parameters:
        ///   - proximityTransportV1: The sealed payload's HKDF salt.
        ///   - meshGroupKeyWrapV1: The group-key wrap's HKDF salt.
        ///   - meshTLSExporterV1: The channel binding's TLS exporter label.
        ///   - meshRoutedContentKeyWrapV1: The routed content-key wrap's HKDF salt.
        ///   - meshSessionContextV1: The mesh-session context file's column seal.
        ///   - meshRoutedStoreV1: The routed store's column seal.
        public init(
            proximityTransportV1: StaticString, meshGroupKeyWrapV1: StaticString,
            meshTLSExporterV1: StaticString, meshRoutedContentKeyWrapV1: StaticString,
            meshSessionContextV1: StaticString, meshRoutedStoreV1: StaticString
        ) {
            let salt = ProximityCryptographicPurpose.Role.keyDerivationSalt
            let seal = ProximityCryptographicPurpose.Role.columnSeal
            self.proximityTransportV1 = ProximityCryptographicPurpose(proximityTransportV1, role: salt)
            self.meshGroupKeyWrapV1 = ProximityCryptographicPurpose(meshGroupKeyWrapV1, role: salt)
            self.meshTLSExporterV1 = ProximityCryptographicPurpose(meshTLSExporterV1, role: .tlsExporterLabel)
            self.meshRoutedContentKeyWrapV1 = ProximityCryptographicPurpose(meshRoutedContentKeyWrapV1, role: salt)
            self.meshSessionContextV1 = ProximityCryptographicPurpose(meshSessionContextV1, role: seal)
            self.meshRoutedStoreV1 = ProximityCryptographicPurpose(meshRoutedStoreV1, role: seal)
        }
    }

    // MARK: - AEAD

    /// The labels at the front of AEAD authenticated data.
    ///
    /// Role, fixed here: `.aeadAssociatedData` for every field, whether the consumer authenticates the
    /// label alone or the label before its own suffix.
    public nonisolated struct AEAD: Hashable, Sendable {
        /// The pairwise sealed payload's authenticated data, before the sender's key-agreement key.
        public let proximityTransportV2: ProximityCryptographicPurpose
        /// The mesh group-key wrap's authenticated data, whole.
        public let meshGroupKeyWrapV2: ProximityCryptographicPurpose
        /// The closed-mode group metadata's authenticated data, whole.
        public let meshEncryptedMetadataV2: ProximityCryptographicPurpose
        /// The routed content-key wrap's authenticated data, before the ids and fingerprints it binds.
        public let meshRoutedContentKeyWrapV1: ProximityCryptographicPurpose
        /// The routed item seal's authenticated data, before the ids, origin and type token it binds.
        public let meshRoutedItemV1: ProximityCryptographicPurpose

        /// Mints every AEAD label from the host's literals.
        ///
        /// - Parameters:
        ///   - proximityTransportV2: The sealed payload's authenticated-data label.
        ///   - meshGroupKeyWrapV2: The group-key wrap's authenticated-data label.
        ///   - meshEncryptedMetadataV2: The group metadata's authenticated-data label.
        ///   - meshRoutedContentKeyWrapV1: The routed content-key wrap's authenticated-data label.
        ///   - meshRoutedItemV1: The routed item seal's authenticated-data label.
        public init(
            proximityTransportV2: StaticString, meshGroupKeyWrapV2: StaticString,
            meshEncryptedMetadataV2: StaticString, meshRoutedContentKeyWrapV1: StaticString,
            meshRoutedItemV1: StaticString
        ) {
            let associatedData = ProximityCryptographicPurpose.Role.aeadAssociatedData
            self.proximityTransportV2 = ProximityCryptographicPurpose(proximityTransportV2, role: associatedData)
            self.meshGroupKeyWrapV2 = ProximityCryptographicPurpose(meshGroupKeyWrapV2, role: associatedData)
            self.meshEncryptedMetadataV2 = ProximityCryptographicPurpose(meshEncryptedMetadataV2, role: associatedData)
            self.meshRoutedContentKeyWrapV1 = ProximityCryptographicPurpose(meshRoutedContentKeyWrapV1, role: associatedData)
            self.meshRoutedItemV1 = ProximityCryptographicPurpose(meshRoutedItemV1, role: associatedData)
        }
    }

    // MARK: - Hash

    /// The labels at the front of SHA-256 preimages.
    ///
    /// Roles, fixed here: the six mesh hashes are `.hashDomain(.lengthPrefixed)`, and the epoch id is
    /// `.hashDomain(.rawPrefix)`. FernletCrypto's registry declares the six with its default raw
    /// framing, but ProximityKit has always hashed them behind an 8-byte count, and a role states what
    /// the consumer does.
    public nonisolated struct Hash: Hashable, Sendable {
        /// The membership inventory digest's records hash.
        public let meshInventoryDigestV1: ProximityCryptographicPurpose
        /// A routed item's whole-content hash.
        public let meshRoutedContentV1: ProximityCryptographicPurpose
        /// A routed chunk's payload hash.
        public let meshRoutedChunkV1: ProximityCryptographicPurpose
        /// A routed chunk's id.
        public let meshRoutedChunkIDV1: ProximityCryptographicPurpose
        /// A custody receipt's id.
        public let meshCustodyReceiptIDV1: ProximityCryptographicPurpose
        /// A recipient receipt's id.
        public let meshRecipientReceiptIDV1: ProximityCryptographicPurpose
        /// A minted epoch's id: the label, then the mesh id, the counter and the coordinator, raw.
        public let meshEpochIDV1: ProximityCryptographicPurpose

        /// Mints every hash label from the host's literals, each with the role its field fixes.
        ///
        /// - Parameters:
        ///   - meshInventoryDigestV1: The membership records hash label.
        ///   - meshRoutedContentV1: The routed content hash label.
        ///   - meshRoutedChunkV1: The routed chunk hash label.
        ///   - meshRoutedChunkIDV1: The routed chunk id label.
        ///   - meshCustodyReceiptIDV1: The custody receipt id label.
        ///   - meshRecipientReceiptIDV1: The recipient receipt id label.
        ///   - meshEpochIDV1: The epoch id label.
        public init(
            meshInventoryDigestV1: StaticString, meshRoutedContentV1: StaticString,
            meshRoutedChunkV1: StaticString, meshRoutedChunkIDV1: StaticString,
            meshCustodyReceiptIDV1: StaticString, meshRecipientReceiptIDV1: StaticString,
            meshEpochIDV1: StaticString
        ) {
            let framed = ProximityCryptographicPurpose.Role.hashDomain(.lengthPrefixed)
            self.meshInventoryDigestV1 = ProximityCryptographicPurpose(meshInventoryDigestV1, role: framed)
            self.meshRoutedContentV1 = ProximityCryptographicPurpose(meshRoutedContentV1, role: framed)
            self.meshRoutedChunkV1 = ProximityCryptographicPurpose(meshRoutedChunkV1, role: framed)
            self.meshRoutedChunkIDV1 = ProximityCryptographicPurpose(meshRoutedChunkIDV1, role: framed)
            self.meshCustodyReceiptIDV1 = ProximityCryptographicPurpose(meshCustodyReceiptIDV1, role: framed)
            self.meshRecipientReceiptIDV1 = ProximityCryptographicPurpose(meshRecipientReceiptIDV1, role: framed)
            self.meshEpochIDV1 = ProximityCryptographicPurpose(meshEpochIDV1, role: .hashDomain(.rawPrefix))
        }
    }

    // MARK: - Radios

    /// One radio's discovery and protocol values.
    public nonisolated struct Radio: Hashable, Sendable {
        /// The Bonjour service type, `_name._udp`. The host must also list it under `NSBonjourServices`,
        /// or discovery dies on device with no log.
        public let serviceType: String
        /// The TLS application protocol the radio's QUIC connections negotiate.
        public let alpn: String

        /// Assembles one radio's values.
        ///
        /// - Parameters:
        ///   - serviceType: The Bonjour service type, `_name._udp`.
        ///   - alpn: The QUIC connections' ALPN.
        public init(serviceType: String, alpn: String) {
            self.serviceType = serviceType
            self.alpn = alpn
        }
    }

    /// The three radios' values, the mesh heartbeat and the radios' presentation strings.
    ///
    /// The presentation strings name the family to a Bonjour listing or a packet capture, never a
    /// device: they ride in the family because a display layer on one device must recognize the
    /// instance names another device of the family advertises. ProximityKit's radios and its peer-name
    /// display still read constants of their own for them until plan step A0.3 re-points them here.
    public nonisolated struct Radios: Hashable, Sendable {
        /// The friend mesh's radio.
        public let mesh: Radio
        /// The presence radio.
        public let presence: Radio
        /// The recipe-share radio. Plan step A0.7 turns it into the recipe pair-session profile.
        public let recipeShare: Radio
        /// The mesh heartbeat datagram, which the receive path drops by byte equality alone.
        public let meshHeartbeat: Data
        /// The start of the mesh and recipe-share radios' Bonjour instance names, which go on with 12
        /// lowercase hex characters. A display layer never shows a name that begins with it as a
        /// person's name.
        public let meshInstanceNamePrefix: String
        /// The start of the presence radio's rotating Bonjour instance names, any separator included,
        /// which go on with 16 lowercase hex characters.
        public let presenceInstanceNamePrefix: String
        /// The common name of every radio's ephemeral TLS certificate, as subject and issuer. Nothing
        /// verifies it: it names the protocol, never the device.
        public let tlsCommonName: String

        /// Assembles the radios' values.
        ///
        /// - Parameters:
        ///   - mesh: The friend mesh's radio.
        ///   - presence: The presence radio.
        ///   - recipeShare: The recipe-share radio.
        ///   - meshHeartbeat: The mesh heartbeat datagram.
        ///   - meshInstanceNamePrefix: The mesh and recipe-share radios' instance-name prefix.
        ///   - presenceInstanceNamePrefix: The presence radio's instance-name prefix.
        ///   - tlsCommonName: The ephemeral certificates' common name.
        public init(
            mesh: Radio, presence: Radio, recipeShare: Radio, meshHeartbeat: Data,
            meshInstanceNamePrefix: String, presenceInstanceNamePrefix: String, tlsCommonName: String
        ) {
            self.mesh = mesh
            self.presence = presence
            self.recipeShare = recipeShare
            self.meshHeartbeat = meshHeartbeat
            self.meshInstanceNamePrefix = meshInstanceNamePrefix
            self.presenceInstanceNamePrefix = presenceInstanceNamePrefix
            self.tlsCommonName = tlsCommonName
        }
    }

    // MARK: - VerifyQR

    /// The verify QR's per-host value.
    public nonisolated struct VerifyQR: Hashable, Sendable {
        /// The URL scheme the host app is registered for. The QR's host `verify`, its query key `d` and
        /// its version 1 stay ProximityKit format constants: they name a format, not an app.
        public let urlScheme: String

        /// Assembles the QR's value.
        ///
        /// - Parameter urlScheme: The scheme the host app is registered for.
        public init(urlScheme: String) {
            self.urlScheme = urlScheme
        }
    }
}

// MARK: - Label rows

nonisolated extension ProximityNamespace.LabelRow {

    /// One row per named label, each field path under `path`, in the order given.
    ///
    /// - Parameters:
    ///   - named: Field names and their labels, in declaration order.
    ///   - path: The group's path from the namespace root.
    /// - Returns: The rows.
    static func rows(
        _ named: [(name: String, purpose: ProximityCryptographicPurpose)],
        under path: String
    ) -> [ProximityNamespace.LabelRow] {
        named.map { ProximityNamespace.LabelRow(field: path + "." + $0.name, purpose: $0.purpose) }
    }
}

nonisolated extension ProximityNamespace.Purposes {

    /// Every label in the four groups, in declaration order, under `path`.
    func labelRows(under path: String) -> [ProximityNamespace.LabelRow] {
        signature.labelRows(under: path + ".signature")
            + keyDerivation.labelRows(under: path + ".keyDerivation")
            + aead.labelRows(under: path + ".aead")
            + hash.labelRows(under: path + ".hash")
    }
}

nonisolated extension ProximityNamespace.Signature {

    /// The nineteen signature labels, then the legacy pair when accepted, under `path`.
    func labelRows(under path: String) -> [ProximityNamespace.LabelRow] {
        let named: [(name: String, purpose: ProximityCryptographicPurpose)] = [
            ("identityEnvelopeV2", identityEnvelopeV2),
            ("meshAdmissionTokenV2", meshAdmissionTokenV2),
            ("meshChannelIntroductionV1", meshChannelIntroductionV1),
            ("meshMemberDepartureV1", meshMemberDepartureV1),
            ("meshMemberRemovalV1", meshMemberRemovalV1),
            ("meshTerminatedV1", meshTerminatedV1),
            ("meshInventoryDigestV1", meshInventoryDigestV1),
            ("meshEpochHeadsV1", meshEpochHeadsV1),
            ("meshRemovalProposalV1", meshRemovalProposalV1),
            ("meshRemovalVoteV1", meshRemovalVoteV1),
            ("meshKeyAgreementV1", meshKeyAgreementV1),
            ("meshRoutedManifestV1", meshRoutedManifestV1),
            ("meshRoutedChunkV1", meshRoutedChunkV1),
            ("meshCustodyReceiptV1", meshCustodyReceiptV1),
            ("meshRecipientReceiptV1", meshRecipientReceiptV1),
            ("meshRoutedInventoryDigestV1", meshRoutedInventoryDigestV1),
            ("meshRoutedDrainAnswerV1", meshRoutedDrainAnswerV1),
            ("proximityQRIdentityV1", proximityQRIdentityV1),
            ("proximityQRResponseV1", proximityQRResponseV1)
        ]
        return ProximityNamespace.LabelRow.rows(named, under: path)
            + legacyV1.labelRows(under: path + ".legacyV1")
    }
}

nonisolated extension ProximityNamespace.LegacyV1 {

    /// The legacy pair under `path` when accepted; no rows when refused.
    func labelRows(under path: String) -> [ProximityNamespace.LabelRow] {
        guard let identityEnvelopeV1, let meshAdmissionTokenV1 else { return [] }
        return ProximityNamespace.LabelRow.rows(
            [("identityEnvelopeV1", identityEnvelopeV1), ("meshAdmissionTokenV1", meshAdmissionTokenV1)],
            under: path
        )
    }
}

nonisolated extension ProximityNamespace.KeyDerivation {

    /// The six key-derivation labels under `path`.
    func labelRows(under path: String) -> [ProximityNamespace.LabelRow] {
        ProximityNamespace.LabelRow.rows([
            ("proximityTransportV1", proximityTransportV1),
            ("meshGroupKeyWrapV1", meshGroupKeyWrapV1),
            ("meshTLSExporterV1", meshTLSExporterV1),
            ("meshRoutedContentKeyWrapV1", meshRoutedContentKeyWrapV1),
            ("meshSessionContextV1", meshSessionContextV1),
            ("meshRoutedStoreV1", meshRoutedStoreV1)
        ], under: path)
    }
}

nonisolated extension ProximityNamespace.AEAD {

    /// The five AEAD labels under `path`.
    func labelRows(under path: String) -> [ProximityNamespace.LabelRow] {
        ProximityNamespace.LabelRow.rows([
            ("proximityTransportV2", proximityTransportV2),
            ("meshGroupKeyWrapV2", meshGroupKeyWrapV2),
            ("meshEncryptedMetadataV2", meshEncryptedMetadataV2),
            ("meshRoutedContentKeyWrapV1", meshRoutedContentKeyWrapV1),
            ("meshRoutedItemV1", meshRoutedItemV1)
        ], under: path)
    }
}

nonisolated extension ProximityNamespace.Hash {

    /// The seven hash labels under `path`.
    func labelRows(under path: String) -> [ProximityNamespace.LabelRow] {
        ProximityNamespace.LabelRow.rows([
            ("meshInventoryDigestV1", meshInventoryDigestV1),
            ("meshRoutedContentV1", meshRoutedContentV1),
            ("meshRoutedChunkV1", meshRoutedChunkV1),
            ("meshRoutedChunkIDV1", meshRoutedChunkIDV1),
            ("meshCustodyReceiptIDV1", meshCustodyReceiptIDV1),
            ("meshRecipientReceiptIDV1", meshRecipientReceiptIDV1),
            ("meshEpochIDV1", meshEpochIDV1)
        ], under: path)
    }
}
