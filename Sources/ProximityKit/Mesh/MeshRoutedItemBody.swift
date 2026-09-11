// MeshRoutedItemBody.swift
// ProximityKit/Mesh
//
// Network migration P5 item 13 (plan §11, §12's photo bullet): the PLAINTEXT a routed photo item
// carries — what `MeshRoutedItemSealer` seals and what the delivery door hands to the friend-photo
// wall.
//
// Two fields the legacy `.friendPhoto` wire carried are deliberately ABSENT: `senderFingerprint`
// and `senderSigningPublicKey`. Both are filled at hand-off from authenticated sources — the
// manifest's signed `originFingerprint`, and the admission ledger's roster entry for that origin —
// which is strictly stronger than a claim inside the payload plus a hash check, and removes two
// spoofable fields from the sealed contract. There is no `keyEpoch` field either, and there never
// will be: an epoch inside the routed body would put back exactly what item 13 retired.
//
// The framing is FROZEN (D-13.20): a length-prefixed JSON header followed by the image bytes RAW.
// `JSONEncoder` base64s a `Data` property, so encoding the whole struct as one `Codable` value
// would ship the JPEG at 4/3 its size — silently re-scaling `manifest.size`, the chunk count charged
// against item 9's caps, the per-peer frame budget, the resident bound, and the very number tier 2
// exists to measure. A length-prefixed header plus raw bytes keeps the metadata half JSON-tolerant
// (invariant 8: unknown fields ignored, no key ever reused for a new meaning) and needs no second
// length, because the image runs to the end of the plaintext.
//
// Not here: any key, any store, any clock, any dispatch. This file is a value and its wire shape.

import FernletDomainModel
import Foundation

// MARK: - MeshRoutedItemBodyFormat

/// The routed body's frozen framing constants and its two coder factories.
///
/// **Frozen wire contract.** The bytes are
/// `u64BE(headerJSON.count) ‖ headerJSON ‖ imageData`, with the header encoded under sorted keys,
/// unescaped slashes and dates as seconds since 1970 — the three options that make one header value
/// produce one byte string on every device and in every Foundation build. Changing any of them is a
/// wire decision and moves the body framing golden's pinned vector, never a formatting preference.
nonisolated enum MeshRoutedItemBodyFormat {

    /// Width of the header's big-endian length prefix — `CanonicalByteWriter`'s own u64.
    static let headerLengthPrefixByteCount = 8

    /// What the header JSON is allowed inside a routed type's ciphertext cap — 64 KiB.
    ///
    /// **An allowance, not a second refusal** (P6 item 3). Nothing enforces it: the framing is
    /// frozen and carries no header bound, and adding one would be a new refusal on a field the
    /// origin already signs. What it does is make a type's ciphertext cap a *formula* — payload
    /// bound + this + the seal's overhead — rather than a literal, so the number the manifest door
    /// checks and the number the sealer can produce are the same number by construction.
    ///
    /// The largest well-formed ``MeshRoutedPhotoHeader`` — a UUID, a date, a display name and up to
    /// `FriendPhotoLimits.maxParticipants` (32) participants, each a fingerprint and a name bounded
    /// by `ItemNameModeration.maxNameLength` — **measures ~4.2 KB**, so 64 KiB is ~15× it.
    /// `theHeaderAllowanceCoversAMaximalHeader` is that claim, measured rather than asserted, and it
    /// pins an 8× floor rather than the measured multiple so an honest header can grow without a
    /// test edit.
    ///
    /// **The allowance is an HONEST-SENDER figure.** Nothing bounds a header on receive: the framing
    /// carries no header bound, and a gossiped participant name has no wire length bound of its own,
    /// so a header wider than this allowance is representable. It is not admitted under a looser
    /// rule — it eats into the payload's room, and the receive side is bounded fail-closed twice
    /// over: the manifest door refuses any blob above the type's ciphertext cap
    /// (``MeshRoutedManifestRejection/sizeExceedsTypeCap``), and the sealer refuses the whole
    /// plaintext **by name** (``MeshRoutedItemSealError/plaintextTooLarge``) at either end.
    static let maxHeaderJSONByteCount = 64 * 1024

    /// The framed header's allowance: the u64 length prefix plus ``maxHeaderJSONByteCount``.
    ///
    /// Derived, never written twice — a type's cap formula reserves exactly the bytes
    /// ``MeshRoutedPhotoBody/encoded()`` prepends to the raw payload.
    static let maxFramedHeaderByteCount = headerLengthPrefixByteCount + maxHeaderJSONByteCount

    /// The frozen header encoder.
    static func headerEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .secondsSince1970
        return encoder
    }

    /// The frozen header decoder — the exact inverse of ``headerEncoder()``.
    static func headerDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return decoder
    }
}

// MARK: - MeshRoutedPhotoHeader

/// The small, tolerant half of a routed photo body: everything the friend-photo wall needs about a
/// shared photo that is not the image itself.
///
/// Frozen JSON keys (invariant 8). Unknown fields are ignored on decode, and no key is ever reused
/// for a new meaning.
///
/// **``id`` MUST equal the manifest's item id, and the delivery door enforces it.** The seal binds
/// `binding.itemID` — the MANIFEST's id — and deliberately not this field, so an origin picks the
/// body's id freely inside an otherwise fully authenticated blob. `MeshRoutedItemDelivery.openPhotoBody`
/// closes that with `guard body.header.id == manifest.itemID`, throwing
/// ``MeshRoutedDeliveryError/bodyIdentityMismatch``, and cell `aBodyWhoseIDIsNotTheItemIDIsRefused`
/// is the claim. The equality is therefore a fact about what a receiver will accept, not only an
/// obligation on the mint. The consequence, stated so the guard cannot be dropped: the friend-photo
/// surface keys and dedups on the photo id (`FriendPhotoPayload.id`, `MeshContentSet`'s content-id
/// dedup), so a body carrying ANOTHER sender's photo id would land in that row's dedup contest.
/// A P6 body type that copies this framing copies the guard with it, or says why its id is not a
/// key anywhere.
///
/// Carries **no identity claim**: who sent this is `manifest.originFingerprint`, signed, and the
/// signing key is the admission ledger's roster entry for that origin.
nonisolated struct MeshRoutedPhotoHeader: Codable, Equatable, Sendable {

    /// The photo's id, equal to the routed item id the manifest signs.
    let id: UUID
    /// When the origin captured it.
    let addedAt: Date
    /// The origin's display name, as the sender chose to show it. Display copy, never a token.
    let senderName: String
    /// The session this photo belongs to, when the origin attached one.
    let session: FriendPhotoSessionMetadata?

    /// Builds the header half of a routed photo body.
    init(id: UUID, addedAt: Date, senderName: String, session: FriendPhotoSessionMetadata?) {
        self.id = id
        self.addedAt = addedAt
        self.senderName = senderName
        self.session = session
    }
}

// MARK: - MeshRoutedPhotoBody

/// The complete plaintext of a routed photo item: a ``MeshRoutedPhotoHeader`` and the resized JPEG.
///
/// Sealed by ``MeshRoutedItemSealer`` under the item's own content key, so its bytes are what
/// `manifest.contentHash` and `manifest.size` measure once the seal has added its 33 bytes.
///
/// The framing is frozen — see ``MeshRoutedItemBodyFormat``. The image is carried RAW and runs to
/// the end of the body, which is why no second length prefix exists and why a JPEG is never
/// inflated by a third.
nonisolated struct MeshRoutedPhotoBody: Equatable, Sendable {

    /// The metadata half.
    let header: MeshRoutedPhotoHeader
    /// The resized JPEG, exactly as `resizedForFriendSharing()` produced it.
    let imageData: Data

    /// Builds a routed photo body from its two halves.
    init(header: MeshRoutedPhotoHeader, imageData: Data) {
        self.header = header
        self.imageData = imageData
    }

    /// Decodes a body from the sealed plaintext.
    ///
    /// The header length is bounded against the bytes that remain **before** anything is sliced, so
    /// a hostile prefix yields ``MeshRoutedItemSealError/malformed`` rather than a trap or a
    /// truncated read.
    ///
    /// All THREE hostile framing shapes land on that one token — too short to carry the prefix, a
    /// prefix past the remaining bytes, and an in-bounds slice that is not the header's JSON. The
    /// third is caught rather than propagated on purpose: a raw `DecodingError` escaping here would
    /// put a second, unfrozen error vocabulary on the routed body's audit line.
    init(decoding bytes: Data) throws {
        let prefixWidth = MeshRoutedItemBodyFormat.headerLengthPrefixByteCount
        guard bytes.count >= prefixWidth else { throw MeshRoutedItemSealError.malformed }
        let start = bytes.startIndex
        var headerLength: UInt64 = 0
        // R2: bounded by the fixed prefix width.
        for byte in bytes[start..<(start + prefixWidth)] {
            headerLength = (headerLength << 8) | UInt64(byte)
        }
        guard headerLength <= UInt64(bytes.count - prefixWidth) else {
            throw MeshRoutedItemSealError.malformed
        }
        let headerEnd = start + prefixWidth + Int(headerLength)
        let headerJSON = Data(bytes[(start + prefixWidth)..<headerEnd])
        let decoded: MeshRoutedPhotoHeader
        do {
            decoded = try MeshRoutedItemBodyFormat.headerDecoder()
                .decode(MeshRoutedPhotoHeader.self, from: headerJSON)
        } catch {
            throw MeshRoutedItemSealError.malformed
        }
        header = decoded
        imageData = Data(bytes[headerEnd...])
    }

    /// The framed plaintext: `u64BE(headerJSON.count) ‖ headerJSON ‖ imageData`.
    func encoded() throws -> Data {
        let headerJSON = try MeshRoutedItemBodyFormat.headerEncoder().encode(header)
        var writer = CanonicalByteWriter()
        writer.appendLengthPrefixed(headerJSON)
        return writer.bytes + imageData
    }
}
