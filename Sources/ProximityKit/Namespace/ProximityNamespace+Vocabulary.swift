// ProximityNamespace+Vocabulary.swift
// ProximityKit/Namespace
//
// The family's payload vocabulary: the tokens every interoperating app signs into its envelopes and
// routed manifests and hashes into its membership digests, and the payload rules that hang on them.
// Tokens are the host's `String`s, like the radios' service types and ALPNs: wire data, never crypto
// labels, so none is a `StaticString` and none takes a role. ProximityKit reads every group here: the
// identity envelope the payload rules (it seals and parks by them), the session coordinator the
// session messages and the capabilities, the mesh and presence managers the wire2 token they
// advertise (and the mesh frames by), the inventory digest the membership record kinds, the routed
// type registry the routed types, and the mesh manager the mesh messages its engine signs and
// dispatches its own frames under. The mesh features' payload and capability tokens are still
// Fernlet's `PayloadType` and `ProximityCapability` cases until plan steps A0.4 and A0.5 move them,
// and for Fernlet the two spellings are equal, which `ProximityVocabularyGoldenTests` holds.

import Foundation

nonisolated extension ProximityNamespace {

    // MARK: - Vocabulary

    /// The tokens every interoperating app shares besides its labels: the session's own messages,
    /// the payload tokens and which of them must arrive sealed, the capability tokens, the membership
    /// record kinds, the routed-type tokens and the mesh engine's own messages.
    ///
    /// Shared wire, which is why it rides in the ``Family``: two apps that supply one family send and
    /// accept the same tokens. Every token is frozen wire data, never localized, and
    /// ``ProximityNamespace/soundness`` holds each to the bytes its receivers accept. Decoding never
    /// produces one: a value that arrives over the wire carries its raw token, which a reader resolves
    /// against the vocabulary its namespace holds.
    public nonisolated struct Vocabulary: Hashable, Sendable {
        /// The coordinator's own session messages: the introduction, its acknowledgement, the heartbeat.
        public let session: SessionMessages
        /// Every payload token the host dispatches, and those whose payload must arrive sealed.
        public let payloads: PayloadRules
        /// The capability tokens a device advertises in its introduction.
        public let capabilities: Capabilities
        /// The four membership record kinds the signed inventory digest hashes.
        public let membershipRecordKinds: MembershipRecordKinds
        /// The routed engine's type tokens.
        public let routedTypes: RoutedTypes
        /// The mesh engine's own messages: the tokens its membership, admission, routed, group-key and
        /// verify frames travel under.
        public let mesh: MeshMessages

        /// Assembles a vocabulary.
        ///
        /// - Parameters:
        ///   - session: The coordinator's session messages.
        ///   - payloads: The payload tokens and the sealing rule.
        ///   - capabilities: The capability tokens.
        ///   - membershipRecordKinds: The membership record kinds.
        ///   - routedTypes: The routed-type tokens.
        ///   - mesh: The mesh engine's own messages.
        public init(
            session: SessionMessages, payloads: PayloadRules, capabilities: Capabilities,
            membershipRecordKinds: MembershipRecordKinds, routedTypes: RoutedTypes, mesh: MeshMessages
        ) {
            self.session = session
            self.payloads = payloads
            self.capabilities = capabilities
            self.membershipRecordKinds = membershipRecordKinds
            self.routedTypes = routedTypes
            self.mesh = mesh
        }
    }

    // MARK: - SessionMessages

    /// The three messages the session coordinator signs on its own: the identity introduction, its
    /// acknowledgement, and the heartbeat with its reply.
    ///
    /// Each envelope's summary title is written into its signed canonical bytes
    /// (`CanonicalSignatureSerializer`), so a title is a wire token like the payload type beside it:
    /// frozen, never localized. A localized title would make the signed bytes depend on the sender's
    /// locale.
    public nonisolated struct SessionMessages: Hashable, Sendable {
        /// The identity introduction each side sends when a link opens.
        public let identityIntroduction: SessionMessage
        /// The acknowledgement each side sends once it has verified the other's introduction.
        public let identityAcknowledge: SessionMessage
        /// The session heartbeat: a ping and the reply it is answered with, under one payload token.
        public let heartbeat: Heartbeat

        /// Assembles the session messages.
        ///
        /// - Parameters:
        ///   - identityIntroduction: The identity introduction.
        ///   - identityAcknowledge: The identity acknowledgement.
        ///   - heartbeat: The heartbeat and its reply.
        public init(identityIntroduction: SessionMessage, identityAcknowledge: SessionMessage, heartbeat: Heartbeat) {
            self.identityIntroduction = identityIntroduction
            self.identityAcknowledge = identityAcknowledge
            self.heartbeat = heartbeat
        }
    }

    /// One session message: the payload token it is sent under and the summary title it is signed with.
    public nonisolated struct SessionMessage: Hashable, Sendable {
        /// The payload token the envelope carries. One of ``PayloadRules/known``.
        public let payloadType: String
        /// The summary title signed into the envelope: a wire token, never localized.
        public let summaryTitle: String

        /// Names one session message.
        ///
        /// - Parameters:
        ///   - payloadType: The payload token the envelope carries.
        ///   - summaryTitle: The signed summary title.
        public init(payloadType: String, summaryTitle: String) {
            self.payloadType = payloadType
            self.summaryTitle = summaryTitle
        }
    }

    /// The session heartbeat: one payload token, and the titles of the ping and of its reply.
    public nonisolated struct Heartbeat: Hashable, Sendable {
        /// The payload token both the ping and its reply carry. One of ``PayloadRules/known``.
        public let payloadType: String
        /// The summary title signed into a ping: a wire token, never localized.
        public let pingTitle: String
        /// The summary title signed into the reply to a ping: a wire token, never localized.
        public let replyTitle: String

        /// Names the heartbeat.
        ///
        /// - Parameters:
        ///   - payloadType: The payload token the ping and its reply carry.
        ///   - pingTitle: The ping's signed summary title.
        ///   - replyTitle: The reply's signed summary title.
        public init(payloadType: String, pingTitle: String, replyTitle: String) {
            self.payloadType = payloadType
            self.pingTitle = pingTitle
            self.replyTitle = replyTitle
        }
    }

    // MARK: - PayloadRules

    /// The payload tokens the host dispatches, and the ones whose payload must arrive sealed.
    public nonisolated struct PayloadRules: Hashable, Sendable {
        /// Every payload token the host dispatches. An envelope whose token is outside this set still
        /// authenticates, but it is parked: never opened and never dispatched, so a newer peer's
        /// payload type is set aside, never misread.
        public let known: Set<String>
        /// The tokens whose payload must arrive sealed to the recipient: an envelope carrying one
        /// unsealed is refused even over an encrypted transport. Each is one of ``known``.
        public let sealingRequired: Set<String>

        /// Assembles the payload rules.
        ///
        /// - Parameters:
        ///   - known: Every payload token the host dispatches.
        ///   - sealingRequired: The tokens whose payload must arrive sealed.
        public init(known: Set<String>, sealingRequired: Set<String>) {
            self.known = known
            self.sealingRequired = sealingRequired
        }
    }

    // MARK: - Capabilities

    /// The capability tokens a device advertises in its identity introduction.
    public nonisolated struct Capabilities: Hashable, Sendable {
        /// Every capability token this family knows, in order. A receiver keeps at most twice as
        /// many tokens from one peer's introduction, so a newer build's additions still fit.
        public let known: [String]
        /// The token that marks the wire2 sealed-payload framing: sealed bodies between two peers
        /// that both advertise it are compressed and padded before sealing. One of ``known``.
        public let wire2: String
        /// What a peer whose introduction carries no capability list is taken to support: every
        /// device that predates capability advertisement could do exactly this much. Each is one of
        /// ``known``.
        public let assumedForLegacyPeers: [String]

        /// Assembles the capability tokens.
        ///
        /// - Parameters:
        ///   - known: Every capability token, in order.
        ///   - wire2: The token that marks the wire2 framing.
        ///   - assumedForLegacyPeers: What a peer that lists no capabilities supports.
        public init(known: [String], wire2: String, assumedForLegacyPeers: [String]) {
            self.known = known
            self.wire2 = wire2
            self.assumedForLegacyPeers = assumedForLegacyPeers
        }
    }

    // MARK: - MembershipRecordKinds

    /// The four membership record kinds. Each record's kind is hashed into the signed inventory
    /// digest, and the digest lists a ledger's records by their kind tokens' bytes. ProximityKit's
    /// `MeshMembershipRecordKind` names the four roles and reads each one's token here.
    public nonisolated struct MembershipRecordKinds: Hashable, Sendable {
        /// A member admitted to the mesh.
        public let admission: String
        /// A member who left of their own accord.
        public let departure: String
        /// A member voted out by a completed quorum.
        public let removal: String
        /// A final-pair member who ended the mesh for everyone.
        public let termination: String

        /// Names the four record kinds.
        ///
        /// - Parameters:
        ///   - admission: The admission record's kind.
        ///   - departure: The departure record's kind.
        ///   - removal: The removal record's kind.
        ///   - termination: The termination record's kind.
        public init(admission: String, departure: String, removal: String, termination: String) {
            self.admission = admission
            self.departure = departure
            self.removal = removal
            self.termination = termination
        }
    }

    // MARK: - RoutedTypes

    /// The routed engine's type tokens: the three types it registers rows for, and one reserved.
    ///
    /// A type token is signed into every routed manifest and bound into the routed item seal's
    /// authenticated data. These are the engine's three registered types plus the reserved one:
    /// ProximityKit's routed type registry builds its three rows from them and reads them nowhere
    /// else. They become host-registered rows when plan step A0.5 moves their features out.
    public nonisolated struct RoutedTypes: Hashable, Sendable {
        /// A friend photo.
        public let photo: String
        /// A session-scoped temporary message.
        public let tempMessage: String
        /// A heart, whose manifest's item id is the gift id.
        public let heart: String
        /// Reserved: registered for nothing, so no routed item of this type is accepted.
        public let control: String

        /// Names the routed-type tokens.
        ///
        /// - Parameters:
        ///   - photo: The friend photo's token.
        ///   - tempMessage: The temporary message's token.
        ///   - heart: The heart's token.
        ///   - control: The reserved control token.
        public init(photo: String, tempMessage: String, heart: String, control: String) {
            self.photo = photo
            self.tempMessage = tempMessage
            self.heart = heart
            self.control = control
        }
    }

    // MARK: - MeshMessages

    /// The mesh engine's own messages: one payload token per frame its membership, admission,
    /// routed-delivery, group-key and verify-ceremony doors sign and dispatch, and the legacy goodbye
    /// it parses and never sends.
    ///
    /// ProximityKit's mesh manager names each by role (`MeshPayloadRole`) and reads its token here at
    /// every send and at its dispatch door, so a frame travels under the host's token and is signed
    /// with that token as its summary title too. Each is one of ``PayloadRules/known``, and all are
    /// distinct from each other and from the session messages' tokens, because the coordinator and
    /// the manager dispatch on them one after the other. A membership record kind may spell the
    /// token of the message that carries its record, as Fernlet's do.
    public nonisolated struct MeshMessages: Hashable, Sendable {
        /// The mesh's descriptor, which a committed member adopts.
        public let descriptor: String
        /// The admitter's grant: the joiner's admission token and the current group key.
        public let admissionGrant: String
        /// A joiner's request to be admitted.
        public let admissionRequest: String
        /// A mesh state change, which the mesh opens only inside closed-mode group metadata.
        public let stateChange: String
        /// A member's vouch list, the source of friend-of-friend labels.
        public let friendVouchList: String
        /// The legacy unsigned two-party removal's proposal.
        public let removalProposal: String
        /// The legacy unsigned two-party removal's second.
        public let removalSecond: String
        /// A leaver's signed departure record.
        public let memberDeparture: String
        /// An admitter's signed admission record.
        public let memberAdmission: String
        /// A completed quorum's signed removal record.
        public let memberRemoval: String
        /// A final-pair member's signed termination record.
        public let terminated: String
        /// A member's signed membership inventory digest.
        public let inventoryDigest: String
        /// A member's signed epoch heads.
        public let epochHeads: String
        /// A batch of members' signed key-agreement advertisements.
        public let keyAgreement: String
        /// A signed removal proposal.
        public let removalProposalSigned: String
        /// A signed removal vote.
        public let removalVote: String
        /// A routed item's signed manifest.
        public let routedManifest: String
        /// A signed routed chunk.
        public let routedChunk: String
        /// A signed custody receipt.
        public let custodyReceipt: String
        /// A signed recipient receipt.
        public let recipientReceipt: String
        /// A member's signed routed inventory digest.
        public let routedInventoryDigest: String
        /// A signed routed drain answer.
        public let routedDrainAnswer: String
        /// The elected coordinator's group-key rotation.
        public let keyRotation: String
        /// A member's acknowledgement of a rotation.
        public let keyAck: String
        /// The coordinator's rotation sync, which drains a member's sends before a rotation.
        public let rotationSync: String
        /// Closed-mode group metadata: a control message sealed under the group key, received only.
        public let encryptedMetadata: String
        /// The elected coordinator's liveness beacon.
        public let coordinatorBeacon: String
        /// The verify ceremony's challenge.
        public let verifyChallenge: String
        /// The verify ceremony's response.
        public let verifyResponse: String
        /// The legacy goodbye: parsed, never sent, and never more than "this link is going away".
        public let sessionGoodbye: String

        /// Names the mesh messages.
        ///
        /// - Parameters:
        ///   - descriptor: The mesh descriptor's token.
        ///   - admissionGrant: The admission grant's token.
        ///   - admissionRequest: The admission request's token.
        ///   - stateChange: The state change's token.
        ///   - friendVouchList: The vouch list's token.
        ///   - removalProposal: The legacy removal proposal's token.
        ///   - removalSecond: The legacy removal second's token.
        ///   - memberDeparture: The departure record's token.
        ///   - memberAdmission: The admission record's token.
        ///   - memberRemoval: The removal record's token.
        ///   - terminated: The termination record's token.
        ///   - inventoryDigest: The membership inventory digest's token.
        ///   - epochHeads: The epoch heads' token.
        ///   - keyAgreement: The key-agreement advertisements' token.
        ///   - removalProposalSigned: The signed removal proposal's token.
        ///   - removalVote: The signed removal vote's token.
        ///   - routedManifest: The routed manifest's token.
        ///   - routedChunk: The routed chunk's token.
        ///   - custodyReceipt: The custody receipt's token.
        ///   - recipientReceipt: The recipient receipt's token.
        ///   - routedInventoryDigest: The routed inventory digest's token.
        ///   - routedDrainAnswer: The routed drain answer's token.
        ///   - keyRotation: The key rotation's token.
        ///   - keyAck: The key acknowledgement's token.
        ///   - rotationSync: The rotation sync's token.
        ///   - encryptedMetadata: The encrypted metadata's token.
        ///   - coordinatorBeacon: The coordinator beacon's token.
        ///   - verifyChallenge: The verify challenge's token.
        ///   - verifyResponse: The verify response's token.
        ///   - sessionGoodbye: The legacy goodbye's token.
        public init(
            descriptor: String, admissionGrant: String, admissionRequest: String, stateChange: String,
            friendVouchList: String, removalProposal: String, removalSecond: String,
            memberDeparture: String, memberAdmission: String, memberRemoval: String, terminated: String,
            inventoryDigest: String, epochHeads: String, keyAgreement: String,
            removalProposalSigned: String, removalVote: String,
            routedManifest: String, routedChunk: String, custodyReceipt: String, recipientReceipt: String,
            routedInventoryDigest: String, routedDrainAnswer: String,
            keyRotation: String, keyAck: String, rotationSync: String, encryptedMetadata: String,
            coordinatorBeacon: String, verifyChallenge: String, verifyResponse: String, sessionGoodbye: String
        ) {
            self.descriptor = descriptor
            self.admissionGrant = admissionGrant
            self.admissionRequest = admissionRequest
            self.stateChange = stateChange
            self.friendVouchList = friendVouchList
            self.removalProposal = removalProposal
            self.removalSecond = removalSecond
            self.memberDeparture = memberDeparture
            self.memberAdmission = memberAdmission
            self.memberRemoval = memberRemoval
            self.terminated = terminated
            self.inventoryDigest = inventoryDigest
            self.epochHeads = epochHeads
            self.keyAgreement = keyAgreement
            self.removalProposalSigned = removalProposalSigned
            self.removalVote = removalVote
            self.routedManifest = routedManifest
            self.routedChunk = routedChunk
            self.custodyReceipt = custodyReceipt
            self.recipientReceipt = recipientReceipt
            self.routedInventoryDigest = routedInventoryDigest
            self.routedDrainAnswer = routedDrainAnswer
            self.keyRotation = keyRotation
            self.keyAck = keyAck
            self.rotationSync = rotationSync
            self.encryptedMetadata = encryptedMetadata
            self.coordinatorBeacon = coordinatorBeacon
            self.verifyChallenge = verifyChallenge
            self.verifyResponse = verifyResponse
            self.sessionGoodbye = sessionGoodbye
        }
    }
}
