// MeshRoutedItemBody.swift
// ProximityKit/Mesh
//
// Network migration P5 item 13 (plan §11, §12's photo bullet): the framing of the PLAINTEXT a routed
// item carries — what `MeshRoutedItemSealer` seals and what the delivery door hands to a canonical
// store.
//
// Three body families share this framing (item 4 added the second, item 6 the third), and all three
// are the host's now: `MeshRoutedTextBody` for the session transcript left for FernletSocial with chat
// at plan step A0.5.9 (`Messaging/MeshRoutedTextBody.swift` there, its header allowance an extension of
// ``MeshRoutedItemBodyFormat``), `MeshRoutedHeartBody` for the heart ledger with the session hearts at
// plan step A0.5.10 (`HeartSharing/MeshRoutedHeartBody.swift` there), and `MeshRoutedPhotoBody` for the
// friend-photo wall with the photos at plan step A0.5.11 (`Mesh/MeshRoutedPhotoBody.swift` there, its
// two header allowances the body's own constants). They share the frozen framing constants
// deliberately — one wire shape, one place a coder option can move — and each states its own payload
// bound and its own header allowance, because a cap is only a cap when it is sized for the body it
// bounds. The heart's payload bound is **zero**: its body is its header.
//
// The framing is FROZEN (D-13.20): a length-prefixed JSON header followed by the payload bytes RAW.
// `JSONEncoder` base64s a `Data` property, so encoding a whole body as one `Codable` value would ship
// a JPEG at 4/3 its size — silently re-scaling `manifest.size`, the chunk count charged against item
// 9's caps, the per-peer frame budget, the resident bound, and the very number tier 2 exists to
// measure. A length-prefixed header plus raw bytes keeps the metadata half JSON-tolerant (invariant
// 8: unknown fields ignored, no key ever reused for a new meaning) and needs no second length,
// because the payload runs to the end of the plaintext.
//
// Not here: any body, any key, any store, any clock, any dispatch. This file is the framing's
// constants and its two coders.

import Foundation

// MARK: - MeshRoutedItemBodyFormat

/// The routed body's frozen framing constants and its two coder factories.
///
/// **Frozen wire contract.** The bytes are
/// `u64BE(headerJSON.count) ‖ headerJSON ‖ payload`, with the header encoded under sorted keys,
/// unescaped slashes and dates as seconds since 1970 — the three options that make one header value
/// produce one byte string on every device and in every Foundation build. Changing any of them is a
/// wire decision and moves the body framing golden's pinned vector, never a formatting preference.
///
/// Public — the prefix width and the two coder factories — so a host's routed body frames and
/// unframes itself in exactly these bytes: `u64BE(headerJSON.count) ‖ headerJSON ‖ payload`, the
/// prefix written by ``CanonicalByteWriter/appendLengthPrefixed(_:)``, the payload running raw to the
/// end of the plaintext. A body that refuses a shape throws ``MeshRoutedItemSealError/malformed``, so
/// the routed audit lines carry one frozen vocabulary. The per-family header allowances stay with
/// the bodies they size — every family's is its host's since the photo body's left with the photos
/// (plan step A0.5.11).
public nonisolated enum MeshRoutedItemBodyFormat {

    /// Width of the header's big-endian length prefix — `CanonicalByteWriter`'s own u64. Frozen at 8.
    public static let headerLengthPrefixByteCount = 8

    /// The frozen header encoder: sorted keys, unescaped slashes, dates as seconds since 1970. A fresh
    /// encoder per call, so a caller's change to one cannot reach another.
    ///
    /// - Returns: An encoder producing the header's frozen bytes.
    public static func headerEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .secondsSince1970
        return encoder
    }

    /// The frozen header decoder — the exact inverse of ``headerEncoder()``: dates as seconds since
    /// 1970, unknown keys ignored. A fresh decoder per call.
    ///
    /// - Returns: A decoder for the header's frozen bytes.
    public static func headerDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return decoder
    }
}
