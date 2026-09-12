// MeshRoutedItemBody.swift
// ProximityKit/Mesh
//
// Network migration P5 item 13 (plan §11, §12's photo bullet): the PLAINTEXT a routed item carries
// — what `MeshRoutedItemSealer` seals and what the delivery door hands to a canonical store.
//
// THREE body families live here (item 4 added the second, item 6 the third):
// `MeshRoutedPhotoBody` for the friend-photo wall, `MeshRoutedTextBody` for the session transcript
// and `MeshRoutedHeartBody` for the heart ledger. They share the frozen framing constants
// deliberately — one file, one wire shape, one place a coder option can move — and each states its
// own payload bound and its own header allowance, because a cap is only a cap when it is sized for
// the body it bounds. The heart's payload bound is **zero**: its body is its header.
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
    ///
    /// **The allowance is per BODY FAMILY, not per routed item** (P6 item 4). This one is sized for
    /// ``MeshRoutedPhotoHeader``'s 32 participants; text has its own,
    /// ``maxTextHeaderJSONByteCount``, because reusing 64 KiB would put the text row's ciphertext
    /// cap at 73 577 B — a cap that constrains nothing.
    static let maxFramedHeaderByteCount = headerLengthPrefixByteCount + maxHeaderJSONByteCount

    /// What a ``MeshRoutedTextHeader``'s JSON is allowed inside the text row's ciphertext cap — 1 KiB.
    ///
    /// The same kind of figure as ``maxHeaderJSONByteCount`` and narrowed for one reason: it is a
    /// term of the text row's **cap** (`maxItemByteCount`), and the shared 64 KiB would make that
    /// cap 73 577 B while a maximal text header measures ~210 B. A cap four times the widest honest
    /// body is a bound; a cap three hundred times it is decoration, and it hands a hostile origin
    /// 64 KiB of header per message inside a row whose payload bound is 8 000 B.
    ///
    /// Not a second refusal either: nothing enforces a header bound on receive (the framing is
    /// frozen and carries none). What refuses an over-wide header is the type cap at the manifest
    /// door and the sealer's own `plaintextTooLarge`, at both ends.
    ///
    /// `theTextHeaderAllowanceCoversAMaximalHeader` is the same measured claim the photo header's
    /// twin makes, at a **4× floor rather than 8×** — and the difference is a fact about the two
    /// headers, not a weaker standard. The photo header's dominant term is a gossiped list of up to
    /// 32 participants whose names arrive from peers, so its allowance has to absorb growth it does
    /// not control. A text header is a UUID, a date and ONE display name whose byte bound
    /// ``MeshRoutedTextBody/maxSenderNameUTF8ByteCount`` sets in this file.
    static let maxTextHeaderJSONByteCount = 1024

    /// The framed text header's allowance: the u64 length prefix plus
    /// ``maxTextHeaderJSONByteCount``. Derived, never written twice.
    static let maxFramedTextHeaderByteCount = headerLengthPrefixByteCount + maxTextHeaderJSONByteCount

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

// MARK: - MeshRoutedTextHeader

/// The metadata half of a routed **text** body: everything the session transcript needs about one
/// message that is not the message itself (P6 item 4, plan §12's temporary-text row).
///
/// Frozen JSON keys (invariant 8). Unknown fields are ignored on decode, and no key is ever reused
/// for a new meaning.
///
/// **``id`` MUST equal the manifest's item id, and the delivery door enforces it** — the guard
/// ``MeshRoutedPhotoHeader`` tells a P6 body type to copy or to say why its id is no key. Text's id
/// *is* a key: `SessionMessageStore` dedups on it (`seenIDs`, which deliberately never forgets a
/// dropped id), so a body carrying another member's message id would consume that id's dedup slot.
/// `MeshRoutedItemDelivery.openTextBody` closes it with `MeshRoutedDeliveryError.bodyIdentityMismatch`.
///
/// **``senderName`` is a display CLAIM, exactly as the photo header's is** — and that is a decision,
/// not an oversight. The identity is bound elsewhere and more strongly: the author is
/// `manifest.originFingerprint`, signed, resolved against `admissions − removals` with the block
/// list applied before the unwrap (D-13.33), and that fingerprint is what the transcript row
/// carries. The ledger holds **no name at all** (`MeshRosterMember` is a fingerprint, a signing key
/// and an admission instant; `MeshAdmissionToken` has no name field), so a projection that refused
/// to take the name from the body would have to take it from the memory-only session roster — which
/// a restart, an idle-lapse resume or a rejoin does not restore — or from the gossiped descriptor,
/// which is strictly WEAKER because a descriptor carries rows for fingerprints other than the
/// sender's. `SessionMessageStore.receiveIncoming` re-applies
/// `ItemNameModeration.moderatedPeerDisplayName` to it, so the arm adds no second moderation. Its
/// LENGTH, unlike its content, is refused rather than coerced: a decoded name above
/// ``MeshRoutedTextBody/maxSenderNameUTF8ByteCount`` is `malformed` (P6 item 4 fix review, P3-1).
nonisolated struct MeshRoutedTextHeader: Codable, Equatable, Sendable {

    /// The message id, equal to the routed item id the manifest signs.
    let id: UUID
    /// When the origin sent it — plan §10.3's `claimedSentAt`, clamped before it orders anything.
    let sentAt: Date
    /// The origin's display name, as the sender chose to show it. Display copy, never a token.
    let senderName: String

    /// Builds the header half of a routed text body.
    init(id: UUID, sentAt: Date, senderName: String) {
        self.id = id
        self.sentAt = sentAt
        self.senderName = senderName
    }
}

// MARK: - MeshRoutedTextBody

/// The complete plaintext of a routed text item: a ``MeshRoutedTextHeader`` and the message's own
/// UTF-8 bytes (P6 item 4).
///
/// Sealed by ``MeshRoutedItemSealer`` under the item's own content key, so its bytes are what
/// `manifest.contentHash` and `manifest.size` measure once the seal has added its 33 bytes.
///
/// The framing is the family's frozen one — see ``MeshRoutedItemBodyFormat`` — with the text carried
/// RAW and running to the end of the body, which is why no second length prefix exists. A `String`
/// inside one `Codable` blob would be escaped and re-normalised by `JSONEncoder`, so the same
/// message would not produce the same bytes on every build.
nonisolated struct MeshRoutedTextBody: Equatable, Sendable {

    /// The widest message this device will put on the wire, as a formula rather than a literal:
    /// sixteen bytes per `Character` of `SessionMessageStore.maxTextLength`.
    ///
    /// **The sanitized maximum has no byte bound at all, which is why this exists.**
    /// `SessionMessageStore.sanitize` caps with `prefix(maxTextLength)` — 500 **`Character`s** —
    /// and a `Character` is a grapheme cluster of unbounded length: combining marks are neither
    /// control characters nor in the sanitizer's invisible-scalar list, so `"a"` plus a thousand
    /// combining acutes is ONE Character and 2 001 bytes. Sixteen bytes per Character covers any
    /// plausible honest message (a flag is 8 bytes, a skin-toned emoji 8, a base plus two marks 5)
    /// and keeps the whole item inside a single chunk.
    ///
    /// Enforced at the SENDER (``boundedText(_:)``), so the bound is never a surprise refusal for
    /// honest input; the receiver never needs it, because `receiveIncoming` re-sanitizes and
    /// re-caps at 500 Characters, so 8 000 ASCII bytes still displays as 500 characters.
    static let maxTextUTF8ByteCount = 16 * SessionMessageStore.maxTextLength

    /// The widest display name this device will put in a text header, in bytes.
    ///
    /// `ItemNameModeration.maxNameLength` is 24 **Characters** and has the same unbounded-in-bytes
    /// property the text cap exists for, so the header's own field is byte-bounded too — otherwise
    /// one long grapheme cluster in the local user's own name could push the header past
    /// ``MeshRoutedItemBodyFormat/maxTextHeaderJSONByteCount`` and the seal would refuse the whole
    /// message by name with nothing the user could act on.
    ///
    /// 128 bytes covers 24 Characters of anything but a name made entirely of the widest clusters
    /// (a flag is 8 bytes, so 16 of them fit), and it is what keeps a maximal header at a quarter of
    /// its allowance: the name is the header's ONLY variable-length field, so bounding it here is
    /// what makes the allowance a statement about this family rather than a hope.
    ///
    /// **Enforced on the WIRE as well as at the sender** (P6 item 4 fix review, P3-1): a body whose
    /// decoded name exceeds it is ``MeshRoutedItemSealError/malformed``. The allowance's whole claim
    /// is arithmetic over *this* bound, so a receiver that accepted an 8 KB name would be holding a
    /// header the formula says cannot exist — and the name is a peer's claim, not honest input this
    /// device produced. It is the one place the family departs from its "an allowance, not a
    /// refusal" doctrine, and it departs by refusing a shape no shipped sender can mint.
    static let maxSenderNameUTF8ByteCount = 128

    /// The text row's registry cap: the widest CIPHERTEXT a routed text item can measure, stated as
    /// a formula beside the photo row's (P6 item 3's idiom, D-11.4).
    ///
    /// ```
    /// maxSealedBlobByteCount
    ///   = maxTextUTF8ByteCount                                   // the PLAINTEXT payload bound
    ///   + MeshRoutedItemBodyFormat.maxFramedTextHeaderByteCount  // this family's framed header
    ///   + MeshRoutedItemSealFormat.overheadByteCount             // marker + nonce + tag
    /// ```
    ///
    /// Every term is read from the type that owns it, so the number the manifest door checks and
    /// the number this device can produce are the same number by construction. 8 000 + 1 032 + 33 =
    /// **9 065 B**.
    static let maxSealedBlobByteCount = maxTextUTF8ByteCount
        + MeshRoutedItemBodyFormat.maxFramedTextHeaderByteCount
        + MeshRoutedItemSealFormat.overheadByteCount

    /// The metadata half.
    let header: MeshRoutedTextHeader
    /// The message, already sanitized and byte-bounded by the sender.
    let text: String

    /// Builds a routed text body from its two halves.
    init(header: MeshRoutedTextHeader, text: String) {
        self.header = header
        self.text = text
    }

    /// `text` with whole trailing `Character`s dropped until it fits ``maxTextUTF8ByteCount``.
    ///
    /// A **wire** bound, deliberately not folded into `SessionMessageStore.sanitize`: that function
    /// is the product's Character cap and is also the receive-side coercion, so putting a wire
    /// constant in it would make one number answer two questions. Character-aligned, because
    /// truncating UTF-8 mid-cluster is how a sanitizer produces a scalar nobody wrote.
    ///
    /// **It can return the empty string** — one base plus four thousand combining marks is a single
    /// Character above the bound — so the sender re-checks emptiness after calling it rather than
    /// minting and echoing an empty row (the design check's finding A3b).
    ///
    /// - Parameter text: The sanitized message.
    /// - Returns: the message, at most ``maxTextUTF8ByteCount`` UTF-8 bytes long.
    static func boundedText(_ text: String) -> String {
        bounded(text, toUTF8ByteCount: maxTextUTF8ByteCount)
    }

    /// ``boundedText(_:)``'s rule for the header's display name, at its own bound.
    ///
    /// - Parameter name: The display name to carry.
    /// - Returns: the name, at most ``maxSenderNameUTF8ByteCount`` UTF-8 bytes long.
    static func boundedSenderName(_ name: String) -> String {
        bounded(name, toUTF8ByteCount: maxSenderNameUTF8ByteCount)
    }

    /// Drops whole trailing `Character`s until the UTF-8 bound holds.
    private static func bounded(_ text: String, toUTF8ByteCount limit: Int) -> String {
        guard text.utf8.count > limit else { return text }
        var kept = text
        // R2: bounded by the input's own Character count, which `sanitize` caps at
        // `SessionMessageStore.maxTextLength`; each pass removes exactly one Character.
        while !kept.isEmpty, kept.utf8.count > limit {
            kept.removeLast()
        }
        return kept
    }

    /// Decodes a body from the sealed plaintext.
    ///
    /// The header length is bounded against the bytes that remain **before** anything is sliced, so
    /// a hostile prefix yields ``MeshRoutedItemSealError/malformed`` rather than a trap or a
    /// truncated read.
    ///
    /// **FIVE hostile shapes for text**, all landing on that one frozen token: too short to carry
    /// the prefix, a prefix past the remaining bytes, an in-bounds slice that is not the header's
    /// JSON, **payload bytes that are not valid UTF-8** — and a decoded ``MeshRoutedTextHeader``
    /// whose `senderName` exceeds ``maxSenderNameUTF8ByteCount`` (P6 item 4 fix review, P3-1: the
    /// header allowance's arithmetic is over that bound, so accepting a wider name would admit a
    /// header the formula says cannot exist). The fourth is text's
    /// own, and it is the one a copy of ``MeshRoutedPhotoBody/init(decoding:)`` gets wrong:
    /// `String(decoding:as:)` **cannot fail**, it substitutes U+FFFD, and U+FFFD is neither a
    /// control character nor in `SessionMessageStore.sanitize`'s invisible-scalar list — so the
    /// tempting spelling silently admits arbitrary bytes as replacement characters and displays
    /// them. Refuse, do not repair.
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
        let decoded: MeshRoutedTextHeader
        do {
            decoded = try MeshRoutedItemBodyFormat.headerDecoder()
                .decode(MeshRoutedTextHeader.self, from: headerJSON)
        } catch {
            throw MeshRoutedItemSealError.malformed
        }
        guard decoded.senderName.utf8.count <= Self.maxSenderNameUTF8ByteCount else {
            throw MeshRoutedItemSealError.malformed
        }
        guard let decodedText = String(data: Data(bytes[headerEnd...]), encoding: .utf8) else {
            throw MeshRoutedItemSealError.malformed
        }
        header = decoded
        text = decodedText
    }

    /// The framed plaintext: `u64BE(headerJSON.count) ‖ headerJSON ‖ text.utf8`.
    func encoded() throws -> Data {
        let headerJSON = try MeshRoutedItemBodyFormat.headerEncoder().encode(header)
        var writer = CanonicalByteWriter()
        writer.appendLengthPrefixed(headerJSON)
        return writer.bytes + Data(text.utf8)
    }
}

// MARK: - MeshRoutedHeartHeader

/// The whole plaintext of a routed heart, minus its framing: a gift id, the day the sender says it
/// was sent, and the sender's display name (P6 item 6).
///
/// Frozen JSON keys (invariant 8). Unknown fields are ignored on decode, and no key is ever reused
/// for a new meaning.
///
/// **``id`` IS the gift id, and it MUST equal the manifest's item id.** For
/// ``MeshRoutedTypeToken/heart`` that equality is the type's frozen contract rather than a
/// convenience: `ProximityHeartLedger` dedups on the gift id, `MeshRoutedHeartAck` refuses any
/// proof whose `giftID` is not the item's, and the replay window, the delivery target and the
/// ledger therefore all key on one value with no second mapping table. The receiver enforces it in
/// ``MeshRoutedItemDelivery/openHeartBody(_:manifest:identity:mayDecryptRoutedContent:)`` exactly as
/// the photo door does, so it is a fact about what a receiver accepts and not only an obligation on
/// the mint.
///
/// Carries **no identity claim**: who sent this is `manifest.originFingerprint`, signed, and the
/// signing key is the admission ledger's roster entry for that origin. The display name is the one
/// exception and it is display copy — see ``senderName``.
nonisolated struct MeshRoutedHeartHeader: Codable, Equatable, Sendable {

    /// The gift id, equal to the routed item id the manifest signs.
    let id: UUID

    /// The day key the sender stamped, `yyyy-MM-dd` — `HeartPayload`'s own field, carried for
    /// parity with the transport this row replaced and shape-checked on receive.
    ///
    /// **Read by nothing, and that was true of the legacy path too**: the retired handler validated
    /// this field and then discarded it, because `ProximityHeartLedger.recordReceivedHeart` takes no
    /// instant. The authenticated instant for a routed heart is `manifest.createdAt`, and the
    /// receiver's own is the index record's `firstSeenAt`. Kept rather than dropped because dropping
    /// a field from a registered type's body is a `…heart.v2` decision, not a v1 edit; refused
    /// rather than coerced on receive, because it is a peer's claim in a fixed shape.
    let sentAtDayKey: String

    /// The origin's display name, as the sender chose to show it. Display copy, never a token.
    ///
    /// A claim, exactly as ``MeshRoutedTextHeader/senderName`` and
    /// ``MeshRoutedPhotoHeader/senderName`` are, and for the same reason: the admission ledger holds
    /// no name (`MeshRosterMember` is a fingerprint, a signing key and an admission instant), while
    /// `recordReceivedHeart(senderDisplayName:)` needs one. It is **stronger** than what the legacy
    /// transport used, which was the envelope's unsigned `senderDisplayName`: here the claim sits
    /// inside an AEAD blob bound to the signed origin. Re-moderated at the receiver with
    /// `ItemNameModeration.moderatedPeerDisplayName`, and its LENGTH refused rather than coerced
    /// (``MeshRoutedHeartBody/maxSenderNameUTF8ByteCount``).
    let senderName: String

    /// Builds the header of a routed heart body.
    init(id: UUID, sentAtDayKey: String, senderName: String) {
        self.id = id
        self.sentAtDayKey = sentAtDayKey
        self.senderName = senderName
    }
}

// MARK: - MeshRoutedHeartBody

/// The complete plaintext of a routed heart item — a ``MeshRoutedHeartHeader`` and **nothing else**
/// (P6 item 6).
///
/// The third body family in this file, and the first with no payload half. It keeps the family's
/// frozen framing anyway — `u64BE(headerJSON.count) ‖ headerJSON`, with the payload length zero —
/// rather than shipping bare JSON, for three reasons: one framing means one place a coder option can
/// move, `MeshRoutedItemSealer` refuses an empty plaintext by name
/// (``MeshRoutedItemSealError/emptyPlaintext``: "a routed item with no payload is a manifest, not an
/// item") and a framed header is not empty, and a future `…heart.v2` that carries something can add
/// it without a framing change.
///
/// One thing it does that its two siblings do not: it **refuses a non-empty remainder**. A photo's
/// remainder is the image and a message's is the text, so both read to the end of the plaintext; a
/// heart's remainder is nothing, and bytes an authenticated blob carries but nobody reads are a
/// malleability seam inside it.
nonisolated struct MeshRoutedHeartBody: Equatable, Sendable {

    /// The widest display name a routed heart header will carry, in bytes.
    ///
    /// The same figure and the same reasoning as ``MeshRoutedTextBody/maxSenderNameUTF8ByteCount``
    /// — `ItemNameModeration.maxNameLength` is 24 **Characters** and a grapheme cluster is unbounded
    /// in bytes — and here it does more work than there, because the name is this header's only
    /// variable-length field at all: the row's whole cap is arithmetic over this bound. Enforced at
    /// the mint (``bounded(senderName:)``) and on the WIRE (a wider decoded name is
    /// ``MeshRoutedItemSealError/malformed``), so the cap cannot be breached from either end.
    static let maxSenderNameUTF8ByteCount = 128

    /// What a ``MeshRoutedHeartHeader``'s JSON is allowed inside the heart row's ciphertext cap —
    /// 512 bytes.
    ///
    /// Narrower than the text family's 1 KiB because the header is narrower: a UUID (36 bytes
    /// quoted), a ten-character day key and one name bounded at 128 bytes, which measures ~215 B at
    /// its widest. `theHeartHeaderAllowanceCoversAMaximalHeader` is that claim, measured rather than
    /// asserted, at the text family's 2× floor rather than the photo family's 8× — and the
    /// difference is a fact about the headers, not a weaker standard: a photo header absorbs a
    /// gossiped list of up to 32 peer-supplied names, a heart header has one field this file bounds.
    ///
    /// Not a second refusal: nothing enforces a header bound on receive (the framing is frozen and
    /// carries none). What refuses an over-wide header is the type cap at the manifest door and the
    /// sealer's own `plaintextTooLarge`, at both ends.
    static let maxHeaderJSONByteCount = 512

    /// The framed heart header's allowance: the u64 length prefix plus ``maxHeaderJSONByteCount``.
    /// Derived, never written twice.
    static let maxFramedHeaderByteCount =
        MeshRoutedItemBodyFormat.headerLengthPrefixByteCount + maxHeaderJSONByteCount

    /// The heart row's registry cap: the widest CIPHERTEXT a routed heart can measure, stated as a
    /// formula beside the photo and text rows' (P6 item 3's idiom, D-11.4).
    ///
    /// ```
    /// maxSealedBlobByteCount
    ///   = 0                                          // a heart body has NO payload half
    ///   + maxFramedHeaderByteCount                   // this family's framed header
    ///   + MeshRoutedItemSealFormat.overheadByteCount // marker + nonce + tag
    /// ```
    ///
    /// 520 + 33 = **553 B**. Every term is read from the type that owns it, so the number the
    /// manifest door checks and the number this device can produce are the same number by
    /// construction. It replaces `MeshRoutedManifestFormat.maxContentByteCount` (256 MiB) on the
    /// row, which is what makes `sizeExceedsTypeCap` reachable for a heart at all and what bounds a
    /// hostile origin's heart to half a kilobyte instead of a quarter of a gigabyte.
    static let maxSealedBlobByteCount =
        maxFramedHeaderByteCount + MeshRoutedItemSealFormat.overheadByteCount

    /// The metadata half, which is the whole body.
    let header: MeshRoutedHeartHeader

    /// Builds a routed heart body.
    init(header: MeshRoutedHeartHeader) {
        self.header = header
    }

    /// `name` with whole trailing `Character`s dropped until it fits
    /// ``maxSenderNameUTF8ByteCount`` — the mint's own bound, so the sender cannot breach its own
    /// row's cap with its own display name.
    ///
    /// - Parameter senderName: The local display name to carry.
    /// - Returns: the name, at most ``maxSenderNameUTF8ByteCount`` UTF-8 bytes long.
    static func bounded(senderName: String) -> String {
        guard senderName.utf8.count > maxSenderNameUTF8ByteCount else { return senderName }
        var kept = senderName
        // R2: bounded by the input's own Character count; each pass removes exactly one Character.
        while !kept.isEmpty, kept.utf8.count > maxSenderNameUTF8ByteCount {
            kept.removeLast()
        }
        return kept
    }

    /// Decodes a body from the sealed plaintext.
    ///
    /// The header length is bounded against the bytes that remain **before** anything is sliced, so
    /// a hostile prefix yields ``MeshRoutedItemSealError/malformed`` rather than a trap or a
    /// truncated read.
    ///
    /// **FOUR hostile shapes for a heart**, all landing on that one frozen token: too short to carry
    /// the prefix, a prefix past the remaining bytes, an in-bounds slice that is not the header's
    /// JSON, and **a non-empty remainder** — the shape this family adds, because a heart body ends
    /// at its header. Two field-level refusals ride with them, and both are shapes rather than
    /// judgements: a `senderName` above ``maxSenderNameUTF8ByteCount``, and a `sentAtDayKey` that is
    /// not `HeartPayload`'s ten-character `yyyy-MM-dd` (the retired handler's own check, kept at the
    /// same position in the pipeline).
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
        let decoded: MeshRoutedHeartHeader
        do {
            decoded = try MeshRoutedItemBodyFormat.headerDecoder()
                .decode(MeshRoutedHeartHeader.self, from: Data(bytes[(start + prefixWidth)..<headerEnd]))
        } catch {
            throw MeshRoutedItemSealError.malformed
        }
        guard headerEnd == bytes.endIndex else { throw MeshRoutedItemSealError.malformed }
        guard decoded.senderName.utf8.count <= Self.maxSenderNameUTF8ByteCount else {
            throw MeshRoutedItemSealError.malformed
        }
        guard HeartPayload.isValidDayKey(decoded.sentAtDayKey) else {
            throw MeshRoutedItemSealError.malformed
        }
        header = decoded
    }

    /// The framed plaintext: `u64BE(headerJSON.count) ‖ headerJSON`, with no payload half.
    func encoded() throws -> Data {
        let headerJSON = try MeshRoutedItemBodyFormat.headerEncoder().encode(header)
        var writer = CanonicalByteWriter()
        writer.appendLengthPrefixed(headerJSON)
        return writer.bytes
    }
}
