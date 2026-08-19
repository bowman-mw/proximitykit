import Foundation
import CryptoKit
import FernletDomainModel

/// Outer seal for offline heart drops (bitchat adoptions Increment 3,
/// Docs/Plan-Bitchat-Adoptions-2026-07-25.md).
///
/// Wire form:
///
///     [version: UInt8 = 1] [prekeyID: 16 B (all-zeros = sealed to the static key)]
///     [ephemeral X25519 pub: 32 B] [ChaChaPoly combined: nonce 12 B || ct || tag 16 B]
///
/// KDF: eph-static ECDH → HKDF-SHA256(salt "fernlet.heartdrop.seal.v1",
/// sharedInfo ephPub ‖ recipientPub) → ChaChaPoly with the 17-byte header as AAD. Unlike the
/// live-radio `IdentityService.seal`, the sender's static key is deliberately NOT in the KDF —
/// the opener can't know the sender before decrypting (sealed-sender, as in bitchat's one-way
/// Noise X mail). Sender authenticity comes from the INNER `FernletIdentityEnvelope`'s Ed25519
/// signature, verified after opening.
///
/// The plaintext is always the wire2-framed inner envelope JSON (compressed + padded — every
/// drop lands in the same size bucket, so the public database can't size-class anything). Forward
/// secrecy: sealed to one of the recipient's gossiped one-time prekeys when an unconsumed one is
/// cached, else to the static key (availability over FS; the header says which, leaking only a
/// bit the server could infer from client version anyway).
public nonisolated enum HeartDropSealer {

    /// Why a drop could not be sealed or opened: malformed/oversized wire bytes, an unknown
    /// format version, a missing/unresolvable recipient key, or an AEAD failure.
    ///
    /// Callers treat every case as "leave the record alone / don't send" — no case is retried
    /// with different keys.
    public enum SealError: Error, Equatable {
        case malformed
        case unknownVersion
        case noRecipientKey
        case openFailed
        case oversized
    }

    /// Hard cap on a drop's wire size, enforced on BOTH ends (bitchat caps courier ciphertext at
    /// 16 KiB the same way). A heart is ~256 B of payload by construction — no free text, no
    /// numbers — and the framed inner envelope pads to the 1–2 KiB bucket, so 8 KiB leaves roughly
    /// 4× headroom for envelope growth.
    ///
    /// The wire cap does NOT bound the receiver's work on its own: DEFLATE reaches ~1032:1, so
    /// 8 KiB of ciphertext could still inflate to ~8 MB under the framing's 16 MiB default guard.
    /// `open` therefore hands `SealedPayloadFraming.unframe` the matching
    /// `HeartDropWireLimits.maxInflatedByteCount` instead of relying on that default.
    ///
    /// Aliased to `HeartDropWireLimits` so the ProximityKit sealer, the receiver's pre-decrypt gate
    /// and the CloudKitSync ferry cannot drift apart — CloudKitSync may not import this module.
    public static let maxWireByteCount = HeartDropWireLimits.maxRecordByteCount

    static let wireVersion: UInt8 = 1
    static let headerLength = 1 + 16
    private static let hkdfSalt = Data("fernlet.heartdrop.seal.v1".utf8)
    private static let zeroPrekeyID = Data(count: 16)

    /// Seals `innerEnvelopeJSON` (a signed `friendHeartDrop` envelope) for the recipient.
    public static func seal(
        innerEnvelopeJSON: Data,
        toPrekey prekey: (id: UUID, publicKey: Data)?,
        orStaticKey staticKeyAgreementPublicKey: Data
    ) throws -> Data {
        let recipientPublicKeyData = prekey?.publicKey ?? staticKeyAgreementPublicKey
        guard let recipientKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipientPublicKeyData) else {
            throw SealError.noRecipientKey
        }
        let framed = SealedPayloadFraming.frame(innerEnvelopeJSON)
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let ephemeralPublic = ephemeral.publicKey.rawRepresentation
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipientKey)
        let symmetricKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: hkdfSalt,
            sharedInfo: ephemeralPublic + recipientPublicKeyData,
            outputByteCount: 32
        )
        var header = Data([wireVersion])
        header.append(prekey.map { uuidData($0.id) } ?? zeroPrekeyID)
        let box = try ChaChaPoly.seal(framed, using: symmetricKey, authenticating: header)
        let wire = header + ephemeralPublic + box.combined
        guard wire.count <= maxWireByteCount else { throw SealError.oversized }
        return wire
    }

    /// Opens a drop. `prekeyPrivateKey` resolves a prekey id to its retained private half;
    /// `staticAgreement` performs ECDH against the recipient's static KA private (the key itself
    /// never leaves `IdentityService`); `staticPublicKey` is the matching public half (second
    /// KDF sharedInfo slot for the static path). Returns the inner envelope JSON — the caller
    /// MUST then decode + `verify` the envelope before trusting anything.
    public static func open(
        _ wire: Data,
        prekeyPrivateKey: (UUID) -> Curve25519.KeyAgreement.PrivateKey?,
        staticAgreement: (Data) throws -> SharedSecret,
        staticPublicKey: Data
    ) throws -> Data {
        let bytes = Data(wire) // normalize slice indices
        guard bytes.count >= headerLength + 32 + 12 + 16 else { throw SealError.malformed }
        // Size gate BEFORE any key agreement or inflation: the public database accepts writes from
        // any authenticated iCloud user, so an oversized record is a stranger's bytes, not ours.
        guard bytes.count <= maxWireByteCount else { throw SealError.oversized }
        guard bytes[0] == wireVersion else { throw SealError.unknownVersion }
        let header = bytes.prefix(headerLength)
        let prekeyIDBytes = bytes.subdata(in: 1..<headerLength)
        let ephemeralPublic = bytes.subdata(in: headerLength..<(headerLength + 32))
        let combined = bytes.suffix(from: headerLength + 32)

        let shared: SharedSecret
        let recipientPublicKeyData: Data
        if prekeyIDBytes == zeroPrekeyID {
            shared = try staticAgreement(ephemeralPublic)
            recipientPublicKeyData = staticPublicKey
        } else {
            guard let id = uuid(from: prekeyIDBytes),
                  let privateKey = prekeyPrivateKey(id) else {
                throw SealError.noRecipientKey
            }
            guard let ephemeralKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephemeralPublic) else {
                throw SealError.malformed
            }
            shared = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralKey)
            recipientPublicKeyData = privateKey.publicKey.rawRepresentation
        }

        let symmetricKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: hkdfSalt,
            sharedInfo: ephemeralPublic + recipientPublicKeyData,
            outputByteCount: 32
        )
        do {
            let box = try ChaChaPoly.SealedBox(combined: combined)
            let framed = try ChaChaPoly.open(box, using: symmetricKey, authenticating: header)
            // Tight, drop-specific inflate ceiling: the 8 KiB wire cap above admits ~8 MB of
            // inflation under the framing's 16 MiB default, and this runs on the main actor.
            return try SealedPayloadFraming.unframe(
                framed, maxInflated: HeartDropWireLimits.maxInflatedByteCount)
        } catch let error as SealedPayloadFraming.FramingError {
            throw error == .inflatedTooLarge ? SealError.malformed : SealError.openFailed
        } catch {
            throw SealError.openFailed
        }
    }

    // MARK: - UUID ↔ bytes

    static func uuidData(_ id: UUID) -> Data {
        // R9: the tuple form, not `withUnsafeBytes(of:)` — `uuid_t` is 16 `UInt8` in wire order,
        // so this is byte-identical to the pointer walk and mirrors `uuid(from:)` below.
        let raw = id.uuid
        return Data([
            raw.0, raw.1, raw.2, raw.3, raw.4, raw.5, raw.6, raw.7,
            raw.8, raw.9, raw.10, raw.11, raw.12, raw.13, raw.14, raw.15
        ])
    }

    static func uuid(from data: Data) -> UUID? {
        guard data.count == 16 else { return nil }
        let bytes = [UInt8](data)
        return UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                           bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
    }
}
