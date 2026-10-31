import Foundation

// MARK: - ProximityTapRendezvousMatch

/// The person both people said yes to: their long-term keys, proven held, and what they revealed.
///
/// The only value a rendezvous ever hands its host that names anyone, and it exists only after both
/// people tapped Start hangout and the peer's card verified against this rendezvous's transcript.
public nonisolated struct ProximityTapRendezvousMatch: Equatable, Sendable {
    /// The peer's long-term Ed25519 signing key.
    public let signingPublicKey: Data
    /// The peer's long-term X25519 key-agreement key.
    public let keyAgreementPublicKey: Data
    /// ``IdentityService/fingerprint(of:)`` of ``signingPublicKey``.
    public let fingerprint: String
    /// The name they appear as.
    public let displayName: String
    /// Their companion's look, as their host encoded it.
    public let look: Data
}

// MARK: - TapRendezvousLongTermIdentity

/// This side's long-term keys and a signer for the card.
///
/// A link is handed one only when the person taps Start hangout, so no code path before that moment
/// can reach a long-term key to send it.
struct TapRendezvousLongTermIdentity {
    /// This device's long-term Ed25519 signing key.
    let signingKey: Data
    /// This device's long-term X25519 key-agreement key.
    let keyAgreementKey: Data
    /// Signs a card transcript under the profile's card label.
    let sign: (Data) throws -> Data
}

// MARK: - TapRendezvousLinkOutput

/// What one link asks its engine to do. The link does no I/O itself.
enum TapRendezvousLinkOutput: Equatable {
    /// Send these bytes to the peer.
    case send(Data)
    /// Start ranging with the peer's token.
    case startRanging(peerToken: Data)
    /// The peer is within 3 m, at this strength (0 far … 1 touching).
    case close(strength: Double)
    /// The peer is no longer within 3 m, or ranging said nothing.
    case notClose
    /// This phone measured the tap.
    case tapped
    /// Both phones tapped and revealed: ask the question.
    case ask(name: String, look: Data)
    /// Both said yes and the peer's card verified.
    case matched(ProximityTapRendezvousMatch)
    /// The link is over.
    case end(TapRendezvousLinkEnd)
}

/// Why a link ended.
enum TapRendezvousLinkEnd: Equatable {
    /// This person said Not now.
    case declinedHere
    /// The other person said Not now.
    case declinedThere
    /// The peer broke the protocol: a bad frame, a reused key, an early card or a bad signature.
    case refused(String)
}

// MARK: - TapRendezvousLink

/// One rendezvous with one nearby phone, as a state machine with no I/O.
///
/// The order it enforces is the privacy contract (spec §1.5 P1):
/// 1. hellos in the clear: ephemeral keys and nonces only;
/// 2. sealed `range`: this rotation's Nearby Interaction token;
/// 3. sealed `reveal`, sent only once THIS phone measured the 15 cm dwell: name and companion;
/// 4. sealed `answer`;
/// 5. sealed `card`, sent only once this person said yes AND the peer's yes arrived: the long-term
///    keys, signed over the transcript so they cannot be lifted onto another rendezvous.
/// A card that arrives before this person said yes is refused, and a frame out of order is refused.
struct TapRendezvousLink {

    private let secrets: TapRendezvousSecrets
    private let profile: ProximityTapRendezvousProfile
    private let detector = ProximityCommitDetector(
        proximityThreshold: TapRendezvousFormat.tapDistanceMeters,
        dwellSeconds: TapRendezvousFormat.tapDwellSeconds,
        minimumSamples: TapRendezvousFormat.tapMinimumSamples
    )
    private(set) var channel: TapRendezvousChannel?
    private var sentSequence = 0
    private var receivedSequence = 0
    private var localToken: Data?
    private var tokenSent = false
    private var rangingStarted = false
    private var isClose = false
    private(set) var hasTapped = false
    private var peerReveal: (name: String, look: Data)?
    private var asked = false
    private var localAnswer: Bool?
    private var peerAnswer: Bool?
    private var longTerm: TapRendezvousLongTermIdentity?
    private var cardSent = false
    private var peerCard: ProximityTapRendezvousMatch?
    private(set) var isFinished = false

    init(secrets: TapRendezvousSecrets, profile: ProximityTapRendezvousProfile) {
        self.secrets = secrets
        self.profile = profile
    }

    /// Whether the question is up or answered: the link a rotation must wait for.
    var isInConversation: Bool { hasTapped && !isFinished }

    /// The first frame: this side's hello.
    mutating func begin() -> [TapRendezvousLinkOutput] {
        guard let bytes = try? TapRendezvousEnvelope.hello(secrets.hello).encoded() else {
            return finish(.refused("hello did not encode"))
        }
        return [.send(bytes)]
    }

    /// This rotation's own Nearby Interaction token, once ranging minted it.
    mutating func setLocalRangingToken(_ token: Data) -> [TapRendezvousLinkOutput] {
        guard !isFinished, localToken == nil else { return [] }
        localToken = token
        return sendTokenIfKeyed()
    }

    /// One frame from the peer.
    mutating func receive(_ data: Data) -> [TapRendezvousLinkOutput] {
        guard !isFinished else { return [] }
        guard let envelope = TapRendezvousEnvelope.decoded(data) else { return finish(.refused("unreadable frame")) }
        if let hello = envelope.hello { return receiveHello(hello) }
        guard let channel, let box = envelope.sealed, let message = channel.open(box) else {
            return finish(.refused("a sealed frame before the hellos, or one that does not open"))
        }
        guard message.sequence == receivedSequence + 1 else { return finish(.refused("out-of-order message")) }
        receivedSequence = message.sequence
        switch message.kind {
        case .range: return receiveRange(message)
        case .reveal: return receiveReveal(message)
        case .answer: return receiveAnswer(message)
        case .card: return receiveCard(message, channel: channel)
        }
    }

    /// One distance reading from this phone's own ranging.
    mutating func distance(
        _ meters: Double, at date: Date, reveal: () -> (name: String, look: Data)
    ) -> [TapRendezvousLinkOutput] {
        guard !isFinished, channel != nil else { return [] }
        var outputs = closeness(meters)
        guard !hasTapped, detector.ingest(distanceMeters: meters, at: date) else { return outputs }
        hasTapped = true
        outputs.append(.tapped)
        let local = reveal()
        let name = Self.bounded(local.name)
        let look = local.look.count <= TapRendezvousFormat.maxLookByteCount ? local.look : Data()
        outputs += sendSealed(TapRendezvousMessage(kind: .reveal, sequence: sentSequence + 1, name: name, look: look))
        return outputs + askIfReady()
    }

    /// The person's answer to the question. `identity` is non-nil exactly when `yes`.
    mutating func answer(_ yes: Bool, identity: TapRendezvousLongTermIdentity?) -> [TapRendezvousLinkOutput] {
        guard !isFinished, asked, localAnswer == nil else { return [] }
        localAnswer = yes
        var outputs = sendSealed(TapRendezvousMessage(kind: .answer, sequence: sentSequence + 1, yes: yes))
        guard yes, let identity else { return outputs + finish(.declinedHere) }
        longTerm = identity
        outputs += sendCardIfBothSaidYes()
        return outputs + matchIfComplete()
    }

    // MARK: Receiving

    private mutating func receiveHello(_ hello: TapRendezvousHello) -> [TapRendezvousLinkOutput] {
        guard channel == nil, hello.isWellFormed, hello.ephemeralKey != secrets.hello.ephemeralKey,
              hello.nonce != secrets.hello.nonce else { return finish(.refused("a second, malformed or reflected hello")) }
        guard let derived = try? TapRendezvousChannel.derive(secrets: secrets, peer: hello, salt: profile.sealSalt) else {
            return finish(.refused("the peer's ephemeral key does not agree"))
        }
        channel = derived
        return sendTokenIfKeyed()
    }

    private mutating func receiveRange(_ message: TapRendezvousMessage) -> [TapRendezvousLinkOutput] {
        guard !rangingStarted, let token = message.rangingToken else { return finish(.refused("a second token")) }
        rangingStarted = true
        return [.startRanging(peerToken: token)]
    }

    private mutating func receiveReveal(_ message: TapRendezvousMessage) -> [TapRendezvousLinkOutput] {
        guard peerReveal == nil, let name = message.name, let look = message.look else {
            return finish(.refused("a second reveal"))
        }
        peerReveal = (name, look)
        return askIfReady()
    }

    private mutating func receiveAnswer(_ message: TapRendezvousMessage) -> [TapRendezvousLinkOutput] {
        guard peerAnswer == nil, peerReveal != nil, let yes = message.yes else {
            return finish(.refused("an answer before a reveal, or a second answer"))
        }
        peerAnswer = yes
        guard yes else { return finish(.declinedThere) }
        return sendCardIfBothSaidYes() + matchIfComplete()
    }

    private mutating func receiveCard(
        _ message: TapRendezvousMessage, channel: TapRendezvousChannel
    ) -> [TapRendezvousLinkOutput] {
        guard peerCard == nil, localAnswer == true, peerAnswer == true,
              let signingKey = message.signingKey, let keyAgreementKey = message.keyAgreementKey,
              let signature = message.signature, let reveal = peerReveal else {
            return finish(.refused("a card before both said yes"))
        }
        let signed = channel.cardTranscript(
            purpose: profile.cardSignature, senderKey: channel.peerKey,
            signingKey: signingKey, keyAgreementKey: keyAgreementKey
        )
        guard IdentityService.verify(signature, of: signed, by: signingKey, purpose: profile.cardSignature) else {
            return finish(.refused("the card's signature does not verify"))
        }
        peerCard = ProximityTapRendezvousMatch(
            signingPublicKey: signingKey, keyAgreementPublicKey: keyAgreementKey,
            fingerprint: IdentityService.fingerprint(of: signingKey), displayName: reveal.name, look: reveal.look
        )
        return matchIfComplete()
    }

    // MARK: Sending

    private mutating func sendTokenIfKeyed() -> [TapRendezvousLinkOutput] {
        guard channel != nil, !tokenSent, let token = localToken else { return [] }
        tokenSent = true
        return sendSealed(TapRendezvousMessage(kind: .range, sequence: sentSequence + 1, rangingToken: token))
    }

    private mutating func sendCardIfBothSaidYes() -> [TapRendezvousLinkOutput] {
        guard !cardSent, localAnswer == true, peerAnswer == true, let longTerm, let channel else { return [] }
        let signed = channel.cardTranscript(
            purpose: profile.cardSignature, senderKey: channel.localKey,
            signingKey: longTerm.signingKey, keyAgreementKey: longTerm.keyAgreementKey
        )
        let signature: Data
        do {
            signature = try longTerm.sign(signed)
        } catch {
            return finish(.refused("this device could not sign its card: \(error)"))
        }
        cardSent = true
        return sendSealed(TapRendezvousMessage(
            kind: .card, sequence: sentSequence + 1, signingKey: longTerm.signingKey,
            keyAgreementKey: longTerm.keyAgreementKey, signature: signature
        ))
    }

    private mutating func sendSealed(_ message: TapRendezvousMessage) -> [TapRendezvousLinkOutput] {
        guard let channel, message.sequence <= TapRendezvousFormat.maxMessagesPerLink,
              let box = try? channel.seal(message),
              let bytes = try? TapRendezvousEnvelope.sealed(box).encoded() else {
            return finish(.refused("a message did not seal"))
        }
        sentSequence = message.sequence
        return [.send(bytes)]
    }

    // MARK: State

    private mutating func closeness(_ meters: Double) -> [TapRendezvousLinkOutput] {
        guard meters.isFinite, meters >= 0, meters <= TapRendezvousFormat.closeDistanceMeters else {
            guard isClose else { return [] }
            isClose = false
            return [.notClose]
        }
        isClose = true
        return [.close(strength: 1 - meters / TapRendezvousFormat.closeDistanceMeters)]
    }

    private mutating func askIfReady() -> [TapRendezvousLinkOutput] {
        guard hasTapped, !asked, let reveal = peerReveal else { return [] }
        asked = true
        return [.ask(name: reveal.name, look: reveal.look)]
    }

    private mutating func matchIfComplete() -> [TapRendezvousLinkOutput] {
        guard cardSent, let peerCard, !isFinished else { return [] }
        isFinished = true
        return [.matched(peerCard)]
    }

    /// `name` cut at a character boundary to ``TapRendezvousFormat/maxNameByteCount`` UTF-8 bytes.
    static func bounded(_ name: String) -> String {
        var cut = Substring(name)
        // R2: bounded by the name's character count; each pass drops one character.
        for _ in 0..<name.count where cut.utf8.count > TapRendezvousFormat.maxNameByteCount {
            cut = cut.dropLast()
        }
        return String(cut)
    }

    private mutating func finish(_ reason: TapRendezvousLinkEnd) -> [TapRendezvousLinkOutput] {
        guard !isFinished else { return [] }
        isFinished = true
        return [.end(reason)]
    }
}
