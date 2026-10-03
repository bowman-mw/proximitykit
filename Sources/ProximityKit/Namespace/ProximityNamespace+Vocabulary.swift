// ProximityNamespace+Vocabulary.swift
// ProximityKit/Namespace
//
// The family's payload vocabulary: the tokens every interoperating app signs into its envelopes and
// routed manifests and hashes into its membership digests, and the payload rules that hang on them.
// Tokens are the host's `String`s, like the radios' service types and ALPNs: wire data, never crypto
// labels, so none is a `StaticString` and none takes a role. ProximityKit reads the membership record
// kinds (the inventory digest hashes them) and the routed types (the routed type registry builds its
// rows from them) here; its other consumers still read constants of their own for the rest
// until plan step A0.3 re-points each one here, and for Fernlet the two are equal, which
// `ProximityVocabularyGoldenTests` holds.

import Foundation

nonisolated extension ProximityNamespace {

    // MARK: - Vocabulary

    /// The tokens every interoperating app shares besides its labels: the session's own messages,
    /// the payload tokens and which of them must arrive sealed, the capability tokens, the membership
    /// record kinds and the routed-type tokens.
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

        /// Assembles a vocabulary.
        ///
        /// - Parameters:
        ///   - session: The coordinator's session messages.
        ///   - payloads: The payload tokens and the sealing rule.
        ///   - capabilities: The capability tokens.
        ///   - membershipRecordKinds: The membership record kinds.
        ///   - routedTypes: The routed-type tokens.
        public init(
            session: SessionMessages, payloads: PayloadRules, capabilities: Capabilities,
            membershipRecordKinds: MembershipRecordKinds, routedTypes: RoutedTypes
        ) {
            self.session = session
            self.payloads = payloads
            self.capabilities = capabilities
            self.membershipRecordKinds = membershipRecordKinds
            self.routedTypes = routedTypes
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
}
