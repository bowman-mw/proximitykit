import Foundation
import CryptoKit
import FernletCrypto

/// QR verification ceremony (bitchat adoptions Increment 4,
/// Docs/Plan-Bitchat-Adoptions-2026-07-25.md — bitchat's signed verify-QR + in-session
/// challenge/response, adapted): upgrades a non-UWB `awaitingManualCommit` slot to ceremony
/// grade. The QR proves "this signing key is on the screen physically in front of you"; the
/// sealed challenge/response proves the live session peer HOLDS that key — together they bind
/// the person to the cryptographic identity, which is exactly the binding bitchat's 2025
/// favorites-impersonation flaw lacked.
public nonisolated enum ProximityVerifyQR {

    /// Thrown by `makeURL` when the payload could not be JSON-encoded into a URL.
    public enum VerifyQRError: Error { case encodingFailed }

    public static let urlScheme = "fernlet"
    public static let urlHost = "verify"
    /// Bounds replay of a photographed QR to minutes; both devices are physically together, so
    /// generous skew tolerance isn't needed.
    public static let freshnessWindow: TimeInterval = 5 * 60
    static let signingDomain = FernletCryptoPurpose.Signature.proximityQRIdentityV1.data

    /// The self-signed content of a `fernlet://verify` QR: both public keys, a timestamp, a
    /// single-use display nonce, and the Ed25519 signature over their canonical bytes.
    ///
    /// Verified by `isValid` (shape + freshness + signature) on the scanner side before any
    /// challenge is minted.
    public struct Payload: Codable, Equatable, Sendable {
        public let version: Int
        public let signingPublicKey: Data
        public let keyAgreementPublicKey: Data
        /// Unix seconds — an integer on the wire so canonical bytes can't drift on date coding.
        public let timestamp: UInt64
        /// 16 B, minted per display; the challenge must quote it, making a lifted QR image
        /// useless once the sheet is dismissed (the displayer only honors its live nonce).
        public let nonce: Data
        public let signature: Data

        public init(
            version: Int,
            signingPublicKey: Data,
            keyAgreementPublicKey: Data,
            timestamp: UInt64,
            nonce: Data,
            signature: Data
        ) {
            self.version = version
            self.signingPublicKey = signingPublicKey
            self.keyAgreementPublicKey = keyAgreementPublicKey
            self.timestamp = timestamp
            self.nonce = nonce
            self.signature = signature
        }
    }

    static func canonicalBytes(
        version: Int,
        signingPublicKey: Data,
        keyAgreementPublicKey: Data,
        timestamp: UInt64,
        nonce: Data
    ) -> Data {
        var bytes = signingDomain
        bytes.append(UInt8(clamping: version))
        bytes.append(signingPublicKey)
        bytes.append(keyAgreementPublicKey)
        // 8-byte big-endian, shifted out in pure Swift (R9: no pointer seam). Byte-identical to
        // the previous `withUnsafeBytes(of: timestamp.bigEndian)`.
        for shift in stride(from: 56, through: 0, by: -8) {
            bytes.append(UInt8(truncatingIfNeeded: timestamp >> UInt64(shift)))
        }
        bytes.append(nonce)
        return bytes
    }

    /// Builds the signed `fernlet://verify?d=…` URL. Returns the nonce too — the caller must
    /// remember it (single-use display, bound to one slot; see `MeshNetworkManager.activeVerifyQR`).
    @MainActor
    public static func makeURL(identity: IdentityService, now: Date = Date()) throws -> (url: URL, nonce: Data) {
        let nonce = Data((0..<16).map { _ in UInt8.random(in: .min ... .max) })
        let timestamp = UInt64(max(0, now.timeIntervalSince1970))
        let signature = try identity.sign(canonicalBytes(
            version: 1,
            signingPublicKey: identity.localSigningPublicKey,
            keyAgreementPublicKey: identity.localKeyAgreementPublicKey,
            timestamp: timestamp,
            nonce: nonce
        ), purpose: FernletCryptoPurpose.Signature.proximityQRIdentityV1)
        let payload = Payload(
            version: 1,
            signingPublicKey: identity.localSigningPublicKey,
            keyAgreementPublicKey: identity.localKeyAgreementPublicKey,
            timestamp: timestamp,
            nonce: nonce,
            signature: signature
        )
        guard let json = try? JSONEncoder().encode(payload) else { throw VerifyQRError.encodingFailed }
        var components = URLComponents()
        components.scheme = urlScheme
        components.host = urlHost
        components.queryItems = [URLQueryItem(name: "d", value: base64URLEncode(json))]
        guard let url = components.url else { throw VerifyQRError.encodingFailed }
        return (url, nonce)
    }

    public static func parse(_ url: URL) -> Payload? {
        guard url.scheme?.lowercased() == urlScheme,
              url.host?.lowercased() == urlHost,
              let encoded = URLComponents(url: url, resolvingAgainstBaseURL: false)?
                  .queryItems?.first(where: { $0.name == "d" })?.value,
              let data = base64URLDecode(encoded) else { return nil }
        return try? JSONDecoder().decode(Payload.self, from: data)
    }

    /// Shape + signature + freshness.
    public static func isValid(_ payload: Payload, at now: Date = Date()) -> Bool {
        guard payload.version == 1,
              payload.nonce.count == ProximityVerifySignature.nonceByteCount,
              // Exact Curve25519 lengths, not merely non-empty: `canonicalBytes` concatenates these
              // two keys with no length prefix, so variable-length keys would make the signed bytes
              // ambiguous across different (signing, keyAgreement) splits.
              payload.signingPublicKey.count == ProximityVerifySignature.publicKeyByteCount,
              payload.keyAgreementPublicKey.count == ProximityVerifySignature.publicKeyByteCount
        else { return false }
        let age = abs(now.timeIntervalSince1970 - TimeInterval(payload.timestamp))
        guard age <= freshnessWindow else { return false }
        return IdentityService.verify(
            payload.signature,
            of: canonicalBytes(
                version: payload.version,
                signingPublicKey: payload.signingPublicKey,
                keyAgreementPublicKey: payload.keyAgreementPublicKey,
                timestamp: payload.timestamp,
                nonce: payload.nonce
            ),
            by: payload.signingPublicKey,
            purpose: FernletCryptoPurpose.Signature.proximityQRIdentityV1
        )
    }

    // MARK: - base64url

    public static func base64URLEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// The most `=` characters base64 padding can ever need: a quantum is four characters, so a
    /// length that is 1, 2, or 3 short of a multiple of four is the worst case. R2: the bound of
    /// the padding loop below, named at the loop, because the string being padded is untrusted
    /// scanned/peer input.
    private static let maxBase64PaddingCharacters = 3

    public static func base64URLDecode(_ string: String) -> Data? {
        var padded = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        var appended = 0
        while padded.count % 4 != 0, appended < maxBase64PaddingCharacters {
            padded.append("=")
            appended += 1
        }
        return Data(base64Encoded: padded)
    }
}

/// Scanner → displayer, sealed (`sealingRequiredTypes`): quotes the scanned QR's nonce (so only
/// the live display is honored) plus a fresh challenge nonce.
public nonisolated struct VerifyChallengePayload: Codable, Equatable, Sendable {
    public let qrNonce: Data
    public let challengeNonce: Data
    public init(qrNonce: Data, challengeNonce: Data) {
        self.qrNonce = qrNonce
        self.challengeNonce = challengeNonce
    }
}

/// Displayer → scanner, sealed: Ed25519 proof of key possession over the ceremony transcript.
public nonisolated struct VerifyResponsePayload: Codable, Equatable, Sendable {
    public let challengeNonce: Data
    public let signature: Data
    public init(challengeNonce: Data, signature: Data) {
        self.challengeNonce = challengeNonce
        self.signature = signature
    }
}

/// The QR ceremony's response-transcript rules: fixed field lengths, the well-formedness gate,
/// and the exact byte layout the displayer signs.
///
/// Shared by both ceremony implementations (`MeshNetworkManager`'s slot-bound flow and
/// ``CoachVerificationCeremony``) so their transcripts can never diverge. The transcript has no
/// length prefixes, which is why `isWellFormedChallenge` is mandatory before anything is signed
/// with the long-term identity key.
public nonisolated enum ProximityVerifySignature {
    static let domain = FernletCryptoPurpose.Signature.proximityQRResponseV1.data

    /// Byte length every nonce in the ceremony must have. The transcript below concatenates its
    /// fields WITHOUT length prefixes, so it is unambiguous only while every field is fixed-length
    /// — which is why `isWellFormedChallenge` is mandatory before anything is signed.
    public static let nonceByteCount = 16
    /// Curve25519 raw public-key length, for both the scanner's KA key and the QR's keys.
    public static let publicKeyByteCount = 32

    /// Whether an inbound challenge's fields are the fixed lengths the transcript assumes. Callers
    /// MUST check this before signing: `qrNonce` is pinned by the equality check against the live
    /// display nonce, but `challengeNonce` and the scanner's KA key come straight off the wire, and
    /// an unbounded, unstructured signing oracle over the long-term identity key is one refactor
    /// away from being exploitable (review finding, 2026-07-27).
    public static func isWellFormedChallenge(
        _ payload: VerifyChallengePayload,
        scannerKeyAgreementPublicKey: Data
    ) -> Bool {
        payload.challengeNonce.count == nonceByteCount
            && payload.qrNonce.count == nonceByteCount
            && scannerKeyAgreementPublicKey.count == publicKeyByteCount
    }

    /// The signed transcript: domain ‖ the SCANNER's KA key (binds the response to who asked) ‖
    /// both nonces. Signed by the displayer's identity signing key. Every field is fixed-length by
    /// `isWellFormedChallenge`, which the callers gate on — do not sign an unchecked payload.
    public static func message(
        scannerKeyAgreementPublicKey: Data,
        challengeNonce: Data,
        qrNonce: Data
    ) -> Data {
        domain + scannerKeyAgreementPublicKey + challengeNonce + qrNonce
    }
}
