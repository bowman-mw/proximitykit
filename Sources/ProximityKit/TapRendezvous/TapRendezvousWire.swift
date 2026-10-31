import CryptoKit
import Foundation

// MARK: - ProximityTapRendezvousProfile

/// What a host hands ``ProximityTapRendezvous``: the pair-radio profile it is found under, and the two
/// labels its cryptography is separated by.
///
/// ProximityKit mints no label of its own (the namespace wall), so both labels are the host's:
/// ``cardSignature`` from ``ProximityCryptographicPurpose/featureSignature(_:framing:)`` and
/// ``sealSalt`` from ``ProximityCryptographicPurpose/featureKeyDerivationSalt(_:)``. The pair profile's
/// advertisement mode must be the rendezvous's own, so the recipe radio sharing the namespace's pair
/// row never dials a rendezvous and a rendezvous never dials the recipe radio (each owner keeps only
/// advertisements of its own mode).
public nonisolated struct ProximityTapRendezvousProfile: Hashable, Sendable {

    /// The pair-radio row and TXT mode the rendezvous advertises and browses under.
    public let pair: ProximityPairProfile

    /// The host's label for the card signature — the one place a long-term key signs anything here.
    public let cardSignature: ProximityCryptographicPurpose

    /// The host's HKDF salt label for the sealing key two ephemeral keys agree.
    public let sealSalt: ProximityCryptographicPurpose

    /// A profile.
    ///
    /// - Parameters:
    ///   - pair: The pair-radio row and the rendezvous's own TXT mode.
    ///   - cardSignature: A `.signature` label the host minted.
    ///   - sealSalt: A `.keyDerivationSalt` label the host minted.
    public init(
        pair: ProximityPairProfile,
        cardSignature: ProximityCryptographicPurpose,
        sealSalt: ProximityCryptographicPurpose
    ) {
        self.pair = pair
        self.cardSignature = cardSignature
        self.sealSalt = sealSalt
    }
}

// MARK: - TapRendezvousFormat

/// The frozen shape of the tap rendezvous: field widths, caps and the distances it acts on.
///
/// Every constant is wire format or a bound on untrusted input, never display text. A frame whose
/// fields miss these widths is refused before anything in it is used.
nonisolated enum TapRendezvousFormat {

    /// The protocol version in every hello. No negotiation and no fallback.
    static let version = 1

    /// An X25519 public key, and an Ed25519 public key: both 32 bytes.
    static let keyByteCount = 32

    /// Bytes of fresh randomness each side contributes to the transcript.
    static let nonceByteCount = 16

    /// An Ed25519 signature.
    static let signatureByteCount = 64

    /// Largest frame read off the tunnel. A sealed reveal carrying the largest look, base64'd twice,
    /// stays under it.
    static let maxFrameByteCount = 24_576

    /// Cap on a revealed name's UTF-8 bytes.
    static let maxNameByteCount = 96

    /// Cap on a revealed companion look, which the host encodes and ProximityKit never reads.
    static let maxLookByteCount = 8_192

    /// Cap on an archived Nearby Interaction discovery token.
    static let maxRangingTokenByteCount = 2_048

    /// Sealed messages one side may send on one link: a range, a reveal, an answer and a card, with
    /// room to spare. A peer that sends more is refused (Power of 10 rule 3).
    static let maxMessagesPerLink = 8

    /// Within this distance the rings show ("Someone with Fernlet is close").
    static let closeDistanceMeters = 3.0

    /// The tap: the same 15 cm, 0.8 s, three-reading dwell the friend mesh's commit uses.
    static let tapDistanceMeters = 0.15
    static let tapDwellSeconds = 0.8
    static let tapMinimumSamples = 3

    /// The longest one ephemeral identity is worn while running: presence's epoch.
    static let rotationInterval: TimeInterval = 900

    /// `count` bytes from the platform CSPRNG (`SystemRandomNumberGenerator`).
    static func randomBytes(_ count: Int) -> Data {
        Data((0..<count).map { _ in UInt8.random(in: .min ... .max) })
    }
}

// MARK: - TapRendezvousHello

/// The one frame sent in the clear: a fresh X25519 key and a nonce. Nothing in it outlives the
/// rotation that minted it, and nothing in it names the person, the device or a long-term key.
nonisolated struct TapRendezvousHello: Codable, Equatable, Sendable {

    /// ``TapRendezvousFormat/version``.
    let version: Int
    /// This rotation's X25519 public key.
    let ephemeralKey: Data
    /// This rotation's nonce.
    let nonce: Data

    /// The frozen one-letter wire keys.
    enum CodingKeys: String, CodingKey {
        case version = "v"
        case ephemeralKey = "e"
        case nonce = "n"
    }

    /// Whether every field has the width the format fixes.
    var isWellFormed: Bool {
        version == TapRendezvousFormat.version
            && ephemeralKey.count == TapRendezvousFormat.keyByteCount
            && nonce.count == TapRendezvousFormat.nonceByteCount
    }
}

// MARK: - TapRendezvousEnvelope

/// The outer frame: a hello, or one sealed message.
nonisolated struct TapRendezvousEnvelope: Codable, Equatable, Sendable {

    /// `hello` or `sealed`.
    let kind: String
    /// The hello, for `hello`.
    let hello: TapRendezvousHello?
    /// A ChaChaPoly box (`combined`), for `sealed`.
    let sealed: Data?

    static let helloKind = "hello"
    static let sealedKind = "sealed"

    /// The frozen one-letter wire keys.
    enum CodingKeys: String, CodingKey {
        case kind = "k"
        case hello = "h"
        case sealed = "s"
    }

    /// A hello envelope.
    static func hello(_ hello: TapRendezvousHello) -> TapRendezvousEnvelope {
        TapRendezvousEnvelope(kind: helloKind, hello: hello, sealed: nil)
    }

    /// A sealed envelope.
    static func sealed(_ box: Data) -> TapRendezvousEnvelope {
        TapRendezvousEnvelope(kind: sealedKind, hello: nil, sealed: box)
    }

    /// The envelope's bytes, keys sorted.
    func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(self)
        guard data.count <= TapRendezvousFormat.maxFrameByteCount else {
            throw MeshTransportError.oversizedFrame(byteCount: data.count)
        }
        return data
    }

    /// The envelope in `data`, or `nil` for an oversized, unreadable or mis-shaped frame.
    static func decoded(_ data: Data) -> TapRendezvousEnvelope? {
        guard data.count <= TapRendezvousFormat.maxFrameByteCount,
              let envelope = try? JSONDecoder().decode(TapRendezvousEnvelope.self, from: data) else { return nil }
        switch envelope.kind {
        case helloKind where envelope.hello != nil && envelope.sealed == nil: return envelope
        case sealedKind where envelope.sealed != nil && envelope.hello == nil: return envelope
        default: return nil
        }
    }
}

// MARK: - TapRendezvousMessage

/// One sealed message. Exactly the fields of its ``Kind`` are present; anything else is malformed.
nonisolated struct TapRendezvousMessage: Codable, Equatable, Sendable {

    /// What the message carries.
    enum Kind: String, Codable, Sendable {
        /// This rotation's Nearby Interaction token.
        case range
        /// The name the person appears as and their companion's look — sent only after this phone
        /// measured the tap.
        case reveal
        /// Start hangout, or Not now.
        case answer
        /// The long-term keys, signed — sent only after both people said yes.
        case card
    }

    let kind: Kind
    /// Strictly increasing per sender, from 1.
    let sequence: Int
    var rangingToken: Data?
    var name: String?
    var look: Data?
    var yes: Bool?
    var signingKey: Data?
    var keyAgreementKey: Data?
    var signature: Data?

    /// The frozen one-letter wire keys.
    enum CodingKeys: String, CodingKey {
        case kind = "k"
        case sequence = "q"
        case rangingToken = "t"
        case name
        case look
        case yes
        case signingKey = "sk"
        case keyAgreementKey = "ka"
        case signature = "sig"
    }

    /// Whether exactly the fields of ``kind`` are present, each within its bound.
    var isWellFormed: Bool {
        guard sequence >= 1, sequence <= TapRendezvousFormat.maxMessagesPerLink else { return false }
        switch kind {
        case .range:
            return onlyFields(token: true)
                && (rangingToken?.count ?? 0) <= TapRendezvousFormat.maxRangingTokenByteCount
                && !(rangingToken?.isEmpty ?? true)
        case .reveal:
            return onlyFields(name: true, look: true)
                && (name?.utf8.count ?? .max) <= TapRendezvousFormat.maxNameByteCount
                && (look?.count ?? .max) <= TapRendezvousFormat.maxLookByteCount
        case .answer:
            return onlyFields(yes: true)
        case .card:
            return onlyFields(card: true)
                && signingKey?.count == TapRendezvousFormat.keyByteCount
                && keyAgreementKey?.count == TapRendezvousFormat.keyByteCount
                && signature?.count == TapRendezvousFormat.signatureByteCount
        }
    }

    /// Whether the present fields are exactly the named ones.
    private func onlyFields(
        token: Bool = false, name hasName: Bool = false, look hasLook: Bool = false,
        yes hasYes: Bool = false, card: Bool = false
    ) -> Bool {
        (rangingToken != nil) == token && (name != nil) == hasName && (look != nil) == hasLook
            && (yes != nil) == hasYes && (signingKey != nil) == card && (keyAgreementKey != nil) == card
            && (signature != nil) == card
    }
}

// MARK: - TapRendezvousSecrets

/// One rotation's ephemeral secrets: an X25519 private key and the hello that publishes its half.
///
/// In memory only — no keychain row, no file, no `UserDefaults` key — and dropped at the next
/// rotation, so nothing a peer saw before a rotation can be matched to anything after it.
nonisolated struct TapRendezvousSecrets {

    /// The X25519 private key.
    let privateKey: Curve25519.KeyAgreement.PrivateKey
    /// The hello carrying its public key and this rotation's nonce.
    let hello: TapRendezvousHello

    /// Fresh secrets.
    static func fresh() -> TapRendezvousSecrets {
        let key = Curve25519.KeyAgreement.PrivateKey()
        let hello = TapRendezvousHello(
            version: TapRendezvousFormat.version,
            ephemeralKey: key.publicKey.rawRepresentation,
            nonce: TapRendezvousFormat.randomBytes(TapRendezvousFormat.nonceByteCount)
        )
        return TapRendezvousSecrets(privateKey: key, hello: hello)
    }
}

// MARK: - TapRendezvousChannel

/// The sealing key two hellos agree, and the transcript both sides bind everything after to.
///
/// `transcript` orders the two hellos by ephemeral key, so both sides build the same bytes without
/// agreeing who dialed. Each message is sealed with ChaChaPoly under the shared key and authenticated
/// with its sender's ephemeral key as associated data, so a message cannot be reflected back at its
/// sender. A relay that swaps the hellos derives a different key on each leg and reads nothing; one
/// that forwards them unchanged cannot open a box either.
nonisolated struct TapRendezvousChannel {

    /// The ChaChaPoly key.
    let key: SymmetricKey
    /// Ordered ephemeral keys and nonces.
    let transcript: Data
    /// This side's ephemeral public key.
    let localKey: Data
    /// The peer's ephemeral public key.
    let peerKey: Data

    /// The channel `secrets` and `peer` agree, salted with the host's label.
    ///
    /// - Throws: a CryptoKit error for a key that is not a valid X25519 point.
    static func derive(
        secrets: TapRendezvousSecrets, peer: TapRendezvousHello, salt: ProximityCryptographicPurpose
    ) throws -> TapRendezvousChannel {
        let peerPublic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peer.ephemeralKey)
        let shared = try secrets.privateKey.sharedSecretFromKeyAgreement(with: peerPublic)
        let transcript = transcript(secrets.hello, peer)
        // Domain: the host's seal-salt purpose, as the salt's prefix and as the info.
        let key = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: salt.data + transcript, sharedInfo: salt.data, outputByteCount: 32
        )
        return TapRendezvousChannel(
            key: key, transcript: transcript, localKey: secrets.hello.ephemeralKey, peerKey: peer.ephemeralKey
        )
    }

    /// The two hellos' keys and nonces, the lower key's first.
    static func transcript(_ first: TapRendezvousHello, _ second: TapRendezvousHello) -> Data {
        let ordered = first.ephemeralKey.lexicographicallyPrecedes(second.ephemeralKey)
            ? [first, second] : [second, first]
        var bytes = Data()
        for hello in ordered {
            bytes.append(hello.ephemeralKey)
            bytes.append(hello.nonce)
        }
        return bytes
    }

    /// `message`, sealed from this side.
    func seal(_ message: TapRendezvousMessage) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let plain = try encoder.encode(message)
        // Domain: the key's own purpose (the host's seal salt); authenticated with the sender's key.
        return try ChaChaPoly.seal(plain, using: key, authenticating: localKey).combined
    }

    /// The message in a box the peer sealed, or `nil` for one that does not open or decode.
    func open(_ box: Data) -> TapRendezvousMessage? {
        // Domain: the key's own purpose (the host's seal salt); authenticated with the peer's key.
        guard let sealed = try? ChaChaPoly.SealedBox(combined: box),
              let plain = try? ChaChaPoly.open(sealed, using: key, authenticating: peerKey),
              let message = try? JSONDecoder().decode(TapRendezvousMessage.self, from: plain),
              message.isWellFormed else { return nil }
        return message
    }

    /// What a card's long-term key signs: the host's label, the transcript, the sender's ephemeral
    /// key and the two long-term keys the card carries.
    func cardTranscript(
        purpose: ProximityCryptographicPurpose, senderKey: Data, signingKey: Data, keyAgreementKey: Data
    ) -> Data {
        purpose.prefixBytes + transcript + senderKey + signingKey + keyAgreementKey
    }
}
