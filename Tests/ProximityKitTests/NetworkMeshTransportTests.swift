import Combine
import CryptoKit
import Foundation
import Security
import Testing
@testable import ProximityKit

// MARK: - MeshIntroductionHarness

/// Two endpoints and one channel, enough to drive plan §7.2's introduction end to end without a
/// radio, a keychain, or an `IdentityService`.
///
/// Signing goes through `CryptographicPurpose.signingBytes` exactly as `IdentityService.sign` does,
/// so a transcript that would be refused at the real signing boundary is refused here too — the
/// harness cannot accidentally mint bytes production could not.
enum MeshIntroductionHarness {

    /// The channel binding both ends of an untampered tunnel derive.
    static let binding = Data(repeating: 0xB1, count: MeshChannelIntroductionFormat.channelBindingByteCount)

    /// A different one — what the two ends see when they are not on the same tunnel.
    static let otherBinding = Data(repeating: 0xB2, count: MeshChannelIntroductionFormat.channelBindingByteCount)

    /// The mesh epoch references are minted against. Fixed so two calls agree.
    static let epochMeshID = UUID(uuidString: "3F2504E0-4F89-11D3-9A0C-0305E82C3301") ?? UUID()

    /// A canonical `MeshEpochRef` string, the only shape a hello's `epochRef` may now take besides
    /// empty. `coordinator` is what makes two same-counter epochs *divergent* rather than equal —
    /// exactly as two partitions with different lowest fingerprints would produce.
    static func epoch(_ counter: UInt32, coordinator: String = "00000000000000aa") -> String {
        MeshEpochRef.minted(
            counter: counter, coordinatorFingerprint: coordinator, meshID: epochMeshID
        )?.canonicalString ?? ""
    }

    /// One side of an introduction: its signing key and the hello it sends.
    struct Endpoint {
        let signingKey: Curve25519.Signing.PrivateKey
        let hello: MeshChannelHello

        var publicKey: Data { signingKey.publicKey.rawRepresentation }
    }

    static func endpoint(
        meshID: UUID,
        epochRef: String = MeshIntroductionHarness.epoch(7),
        sessionID: String,
        protocolVersion: Int = MeshChannelIntroductionFormat.protocolVersion,
        nonce: Data = MeshChannelIntroductionFormat.randomNonce()
    ) -> Endpoint {
        let key = Curve25519.Signing.PrivateKey()
        return Endpoint(signingKey: key, hello: MeshChannelHello(
            protocolVersion: protocolVersion,
            meshID: meshID,
            epochRef: epochRef,
            signingPublicKey: key.publicKey.rawRepresentation,
            nonce: nonce,
            sessionID: sessionID
        ))
    }

    static func roster(
        _ endpoints: Endpoint...,
        barred: [Data] = [],
        doorsOpen: Bool = false
    ) -> MeshIntroductionRoster {
        MeshIntroductionRoster(
            members: endpoints.map(\.publicKey), barred: barred,
            admitsStrangersProvisionally: doorsOpen
        )
    }

    /// Signs a transcript the way `IdentityService.sign` does — through the purpose's framing check.
    static func signature(over transcript: Data, by key: Curve25519.Signing.PrivateKey) throws -> Data {
        let purpose = ProximityNamespace.packageTest.family.purposes.signature.meshChannelIntroductionV1
        let bytes = try #require(
            purpose.signingBytes(transcript),
            "the transcript does not satisfy meshChannelIntroductionV1's declared framing"
        )
        return try key.signature(for: bytes)
    }

    static func introduction(
        over transcript: Data,
        binding: Data,
        by key: Curve25519.Signing.PrivateKey
    ) throws -> MeshChannelIntroduction {
        MeshChannelIntroduction(
            channelBindingHash: binding,
            signature: try signature(over: transcript, by: key)
        )
    }

    /// Everything one run of the handshake produced, so a test can assert on any stage of it.
    struct Run {
        var initiator: MeshChannelIntroductionExchange
        var responder: MeshChannelIntroductionExchange
        var initiatorHelloRejection: MeshIntroductionRejection?
        var responderHelloRejection: MeshIntroductionRejection?
        var initiatorTranscript: Data?
        var responderTranscript: Data?
        var initiatorOutcome: MeshChannelIntroductionOutcome?
        var responderOutcome: MeshChannelIntroductionOutcome?
    }

    /// Drives both sides through hello → bind → sign → review, stopping at the first refusal.
    ///
    /// Each side gets its own nonce cache, matching production: the caches are per session, not per
    /// mesh, so a replay is only a replay to the side that already saw it.
    /// - Parameters:
    ///   - roster: What the RESPONDER judges the initiator's hello against.
    ///   - initiatorRoster: What the INITIATOR judges the responder's hello against, when the two
    ///     ends do not hold the same view. Nil means "the same roster", which is every symmetric
    ///     row; D-4.3's first-meeting rows are asymmetric by nature — a mesh-less joiner's roster is
    ///     empty while the founder's names itself — so they pass both.
    static func run(
        initiator: Endpoint,
        responder: Endpoint,
        roster: MeshIntroductionRoster,
        initiatorRoster: MeshIntroductionRoster? = nil,
        initiatorBinding: Data = binding,
        responderBinding: Data = binding
    ) throws -> Run {
        var state = Run(
            initiator: MeshChannelIntroductionExchange(role: .initiator, localHello: initiator.hello),
            responder: MeshChannelIntroductionExchange(role: .responder, localHello: responder.hello)
        )
        var initiatorNonces = MeshIntroductionNonceCache()
        var responderNonces = MeshIntroductionNonceCache()
        state.responderHelloRejection = state.responder.receive(
            initiator.hello, roster: roster, nonces: &responderNonces
        )
        state.initiatorHelloRejection = state.initiator.receive(
            responder.hello, roster: initiatorRoster ?? roster, nonces: &initiatorNonces
        )
        guard state.responderHelloRejection == nil, state.initiatorHelloRejection == nil else { return state }
        state.initiatorTranscript = state.initiator.bind(channelBindingHash: initiatorBinding)
        state.responderTranscript = state.responder.bind(channelBindingHash: responderBinding)
        guard let initiatorTranscript = state.initiatorTranscript,
              let responderTranscript = state.responderTranscript else { return state }
        state.responderOutcome = state.responder.review(
            try introduction(over: initiatorTranscript, binding: initiatorBinding, by: initiator.signingKey)
        )
        state.initiatorOutcome = state.initiator.review(
            try introduction(over: responderTranscript, binding: responderBinding, by: responder.signingKey)
        )
        return state
    }
}
