import CryptoKit
import Foundation
import Network
import Security

// MARK: - MeshCertificateDER

/// The few DER constructions a self-signed P-256 certificate needs, and nothing else.
///
/// Hand-rolled because there is no certificate-creation API on iOS: `Security` can *read* a
/// certificate (`SecCertificateCreateWithData`) but cannot mint one, and QUIC's listener side
/// requires a `sec_identity_t`, which requires a certificate. The alternative — the shape the DEBUG
/// feasibility probe uses — is a fixed certificate and private key baked into the source, which is
/// exactly what plan §7.2 says a shipping transport must not do.
///
/// Deliberately a *writer* only. Nothing here parses attacker-controlled bytes: every input is a
/// value this process just produced, so the encoder needs no error paths for malformed input and
/// the peer's certificate is never decoded at all (see ``EphemeralMeshTLSIdentity`` for why
/// certificate validation is not the authentication decision).
nonisolated enum MeshCertificateDER {

    /// DER identifier octets, in the order they appear in a certificate.
    static let integerTag: UInt8 = 0x02
    static let bitStringTag: UInt8 = 0x03
    static let objectIdentifierTag: UInt8 = 0x06
    static let utf8StringTag: UInt8 = 0x0C
    static let sequenceTag: UInt8 = 0x30
    static let setTag: UInt8 = 0x31
    static let utcTimeTag: UInt8 = 0x17

    /// Bound on a DER length field's own byte count. Two long-form bytes cover 65 535 content
    /// bytes; a P-256 self-signed certificate is under 400, so this can only ever be exceeded by a
    /// programming error (Power of 10 rule 2: the loop that writes it is bounded regardless).
    static let maxLengthByteCount = 4

    /// `id-ecPublicKey`, 1.2.840.10045.2.1.
    static let ecPublicKeyOID: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]
    /// `prime256v1` (NIST P-256), 1.2.840.10045.3.1.7.
    static let prime256v1OID: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
    /// `ecdsa-with-SHA256`, 1.2.840.10045.4.3.2.
    static let ecdsaWithSHA256OID: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]
    /// `id-at-commonName`, 2.5.4.3.
    static let commonNameOID: [UInt8] = [0x55, 0x04, 0x03]

    /// `YYMMDDHHmmSS'Z'` in UTC — X.509 `UTCTime`, valid for 1950…2049 and therefore correct for
    /// any certificate this code can mint (they live for a day).
    static let utcTimeFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyMMddHHmmss'Z'"
        return formatter
    }()

    /// A tag-length-value triple — the one primitive every other constructor here is built from.
    static func tagged(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        [tag] + length(content.count) + content
    }

    /// DER definite-length encoding: short form below 128, long form above.
    static func length(_ count: Int) -> [UInt8] {
        guard count >= 0x80 else { return [UInt8(count)] }
        var remaining = count
        var bytes: [UInt8] = []
        for _ in 0..<maxLengthByteCount where remaining > 0 {
            bytes.insert(UInt8(remaining & 0xFF), at: 0)
            remaining >>= 8
        }
        return [UInt8(0x80 | bytes.count)] + bytes
    }

    /// `SEQUENCE { content }`.
    static func sequence(_ content: [UInt8]) -> [UInt8] {
        tagged(sequenceTag, content)
    }

    /// `SET { content }`.
    static func set(_ content: [UInt8]) -> [UInt8] {
        tagged(setTag, content)
    }

    /// `[index] EXPLICIT { content }` — context-specific constructed, used for the version field.
    static func explicit(_ index: UInt8, _ content: [UInt8]) -> [UInt8] {
        tagged(0xA0 | index, content)
    }

    /// A positive `INTEGER`. Leading zero bytes are stripped and one is re-added when the high bit
    /// would otherwise make the value negative, which is the whole of DER's integer rule.
    static func integer(_ magnitude: [UInt8]) -> [UInt8] {
        var bytes = magnitude
        for _ in 0..<magnitude.count where bytes.count > 1 && bytes[0] == 0x00 {
            bytes.removeFirst()
        }
        guard let first = bytes.first else { return tagged(integerTag, [0x00]) }
        return tagged(integerTag, first & 0x80 == 0 ? bytes : [0x00] + bytes)
    }

    /// A `BIT STRING` with no unused trailing bits — the only kind a certificate contains.
    static func bitString(_ bytes: [UInt8]) -> [UInt8] {
        tagged(bitStringTag, [0x00] + bytes)
    }

    /// `OBJECT IDENTIFIER` from its already-encoded content octets.
    static func objectIdentifier(_ content: [UInt8]) -> [UInt8] {
        tagged(objectIdentifierTag, content)
    }

    /// `UTF8String`.
    static func utf8String(_ value: String) -> [UInt8] {
        tagged(utf8StringTag, Array(value.utf8))
    }

    /// `UTCTime`.
    static func utcTime(_ date: Date) -> [UInt8] {
        tagged(utcTimeTag, Array(utcTimeFormatter.string(from: date).utf8))
    }

    /// An X.501 `Name` carrying a single common-name attribute — the whole subject and issuer of a
    /// certificate whose distinguished name means nothing (see ``EphemeralMeshTLSIdentity``).
    static func distinguishedName(commonName: String) -> [UInt8] {
        sequence(set(sequence(objectIdentifier(commonNameOID) + utf8String(commonName))))
    }

    /// `AlgorithmIdentifier { ecdsa-with-SHA256 }`, with the absent-parameters form ECDSA requires.
    static func ecdsaWithSHA256AlgorithmIdentifier() -> [UInt8] {
        sequence(objectIdentifier(ecdsaWithSHA256OID))
    }

    /// `SubjectPublicKeyInfo` for an uncompressed P-256 point.
    static func subjectPublicKeyInfo(x963PublicKey: [UInt8]) -> [UInt8] {
        let algorithm = sequence(objectIdentifier(ecPublicKeyOID) + objectIdentifier(prime256v1OID))
        return sequence(algorithm + bitString(x963PublicKey))
    }
}

// MARK: - EphemeralMeshTLSIdentity

/// Errors the QUIC mesh transport raises before any peer frame exists.
///
/// Deliberately **not** a `LocalizedError`: none of these is user-facing copy. They surface through
/// `NetworkMeshSession.onTransportError` as diagnostic English, exactly as the MC session's
/// `didNotStart*` messages do, and the localization wall's rule G governs error types that *are*
/// read by a person.
nonisolated enum MeshTransportError: Error, Equatable {
    /// A `sec_identity_t` could not be built for this session's freshly minted key pair.
    case tlsIdentityUnavailable
    /// An outbound frame is larger than ``NetworkMeshSession/maxInboundWireBytes``.
    case oversizedFrame(byteCount: Int)
    /// An inbound length header names an implausible payload size.
    case invalidFrameLength
    /// A send was asked for on a peer with no live control stream.
    case noControlStream
    /// One connection delivered ``NetworkMeshSession/maxInboundFramesPerConnection`` frames. The
    /// bound exists so the receive loop is bounded (Power of 10 rule 2); reaching it ends the
    /// tunnel loudly rather than leaving a link that looks connected and reads nothing.
    case frameBudgetSpent

    /// Frozen English for the diagnostic surface. Never shown as user copy.
    var diagnosticDescription: String {
        switch self {
        case .tlsIdentityUnavailable:
            return "The mesh transport could not mint its ephemeral TLS identity."
        case .oversizedFrame(let byteCount):
            return "The mesh transport refused a \(byteCount)-byte outbound frame."
        case .invalidFrameLength:
            return "The mesh transport received an invalid control-frame length."
        case .noControlStream:
            return "The mesh transport has no control stream for that peer."
        case .frameBudgetSpent:
            return "The mesh transport reached one connection's frame budget."
        }
    }
}

/// The TLS identity one mesh session presents, minted at session start and thrown away with it.
///
/// **This is not a Fernlet identity and it is not a trust anchor** (plan §7.2). A fresh self-signed
/// P-256 key pair is generated per session, never persisted, never reused across meshes, and never
/// written anywhere — so it links no two sessions to one device, which the archived `MCPeerID` it
/// replaces did. Peer authentication is *not* certificate validation: it is the signed identity
/// introduction the coordinator already exchanges over the connection, and — once P2 item 7 lands —
/// the TLS-exporter-bound channel introduction on top of it. That is why the transport pairs this
/// identity with an accept-any certificate validator: the certificate exists because QUIC's TLS
/// handshake requires the listener to present one, and it is asked to prove nothing.
///
/// The certificate's common name is a fixed English token for the same reason: it identifies the
/// protocol, not the device, and a device-derived name here would re-introduce exactly the passive
/// linkability the random Bonjour instance name exists to remove.
nonisolated enum EphemeralMeshTLSIdentity {

    /// The certificate's subject and issuer. A frozen token, never localized, never a device name.
    static let commonName = "fernlet-mesh"

    /// How long a minted certificate claims to be valid. A day is far longer than any session and
    /// far shorter than anything worth caching; nothing validates it, so the field exists only
    /// because X.509 requires one.
    static let lifetimeSeconds: TimeInterval = 24 * 60 * 60

    /// Backdating for clock skew between two phones in a room. Certificate validation is disabled,
    /// so this cannot matter today; it is set because a future build that *does* validate would
    /// otherwise fail on a peer whose clock is a minute behind.
    static let clockSkewSeconds: TimeInterval = 5 * 60

    /// Serial-number bytes. Eight random bytes, high bit cleared so the DER integer stays positive.
    static let serialByteCount = 8

    /// The P-256 uncompressed-point prefix, `0x04`. Asserted rather than assumed: a key whose x9.63
    /// representation is not an uncompressed point would produce a certificate no peer can parse.
    static let uncompressedPointPrefix: UInt8 = 0x04

    /// One minted identity: what QUIC needs, plus the bytes it was built from.
    struct Minted {
        /// The `sec_identity_t` handed to the QUIC listener and connection parameters.
        let identity: sec_identity_t
        /// The certificate's DER. Not secret, and not the private key.
        ///
        /// Kept rather than discarded for a named future reader: plan §7.2's documented fallback,
        /// if a later SDK stops exposing the TLS exporter secret, is to bind the signed channel
        /// introduction to both peers' certificate fingerprints instead — which needs these bytes.
        let certificateDER: Data
    }

    /// Mints a fresh identity for one session.
    ///
    /// - Parameter now: the instant validity is anchored to; a parameter so the encoder can be
    ///   tested against fixed dates rather than the wall clock.
    static func mint(now: Date = Date()) throws -> Minted {
        let privateKey = P256.Signing.PrivateKey()
        let der = try selfSignedCertificateDER(
            for: privateKey,
            notBefore: now.addingTimeInterval(-clockSkewSeconds),
            notAfter: now.addingTimeInterval(lifetimeSeconds),
            serial: randomSerial()
        )
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else {
            throw MeshTransportError.tlsIdentityUnavailable
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 256
        ]
        guard let secKey = SecKeyCreateWithData(
            privateKey.x963Representation as CFData,
            attributes as CFDictionary,
            nil
        ), let identity = SecIdentityCreate(nil, certificate, secKey),
            let protocolIdentity = sec_identity_create(identity) else {
            throw MeshTransportError.tlsIdentityUnavailable
        }
        return Minted(identity: protocolIdentity, certificateDER: der)
    }

    /// The DER of a minimal v3 self-signed certificate over `privateKey`'s public half.
    ///
    /// Pure and separately testable: given a key and two dates it returns bytes, and a test can
    /// hand those bytes to `SecCertificateCreateWithData` to prove the platform parser accepts
    /// them — which is the only correctness claim that matters, since nothing else ever reads one.
    static func selfSignedCertificateDER(
        for privateKey: P256.Signing.PrivateKey,
        notBefore: Date,
        notAfter: Date,
        serial: [UInt8]
    ) throws -> Data {
        let publicKey = [UInt8](privateKey.publicKey.x963Representation)
        guard publicKey.first == uncompressedPointPrefix else {
            throw MeshTransportError.tlsIdentityUnavailable
        }
        let algorithm = MeshCertificateDER.ecdsaWithSHA256AlgorithmIdentifier()
        let name = MeshCertificateDER.distinguishedName(commonName: commonName)
        let validity = MeshCertificateDER.sequence(
            MeshCertificateDER.utcTime(notBefore) + MeshCertificateDER.utcTime(notAfter)
        )
        let tbs = MeshCertificateDER.sequence(
            MeshCertificateDER.explicit(0, MeshCertificateDER.integer([0x02]))
                + MeshCertificateDER.integer(serial)
                + algorithm + name + validity + name
                + MeshCertificateDER.subjectPublicKeyInfo(x963PublicKey: publicKey)
        )
        // The transcript below is the DER TBSCertificate itself, and X.509 fixes it exactly: a
        // Fernlet domain prefix would produce bytes no TLS stack can parse. What makes that safe is
        // scope rather than a domain — this key signs nothing else, exists for one session, and is
        // thrown away with it — and nothing in Fernlet ever verifies the result: peer
        // authentication is the signed identity introduction exchanged over the connection.
        // cryptographic-domain: x509-self-signature
        let signature = try privateKey.signature(for: Data(tbs)).derRepresentation
        return Data(MeshCertificateDER.sequence(tbs + algorithm + MeshCertificateDER.bitString([UInt8](signature))))
    }

    /// ``serialByteCount`` random bytes with the high bit of the first cleared, so the DER integer
    /// is unambiguously positive without needing a padding byte.
    static func randomSerial() -> [UInt8] {
        var bytes = (0..<serialByteCount).map { _ in UInt8.random(in: UInt8.min...UInt8.max) }
        guard let first = bytes.first else { return [0x01] }
        bytes[0] = first & 0x7F
        return bytes
    }
}
