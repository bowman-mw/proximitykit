// CanonicalSignatureSerializer.swift
// Fernlet/Proximity
//
// Deterministic, cross-platform-stable canonical byte serializer for Ed25519 signing (WI-6).
//
// WHY THIS EXISTS
// ---------------
// The original canonical encoder was a Foundation `JSONEncoder` configured with `.sortedKeys`.
// `.sortedKeys` sorts keys by UTF-16 code units, and Foundation makes NO guarantee that the byte
// encoding of numbers / strings is identical across Foundation versions or a non-Apple stack (the
// planned Android port — see Docs/cross-platform-direction). Any divergence in the canonical bytes
// produces a `signatureInvalid` for an envelope/token that was legitimately signed. That is a
// latent interoperability fault, not a confidentiality leak, but it must be closed before any
// cross-stack signing exists.
//
// This serializer is a positional, length-prefixed BINARY format with no key names, no
// number/locale formatting, and a fixed integer/date encoding. It is trivially reproducible
// byte-for-byte in Swift and Kotlin/Java. Ed25519 signs arbitrary bytes, so the signing input does
// not need to be (and is not) JSON.
//
// FORMAT (canonical v2) — all integers big-endian:
//   * A leading length-prefixed domain tag distinguishes the two signed types (identity envelope vs
//     mesh admission token), so a signature computed over one type can never validate over the other.
//   * Fixed-width fields: Int64 (8 B, two's complement), UUID (16 raw bytes, network order),
//     bool / enum-discriminant (1 B).
//   * Variable-width fields: every `Data` / `String` is a UInt64 (8 B) length prefix followed by the
//     raw bytes (UTF-8 for `String`).
//   * Optionals: a single presence byte (0 = absent, 1 = present); if present, the value follows.
//   * Dates: Int64 whole SECONDS since 1970-01-01T00:00:00Z, floored. Whole-second granularity is
//     deliberate — envelopes transit as JSON and `verify` re-derives canonical bytes from the
//     DECODED date, so the canonical granularity must be no finer than what survives the wire. It
//     matches the legacy `.iso8601` precision exactly, so sign-time and verify-time bytes always
//     agree. The seconds→Int64 conversion saturates (never traps) because `verify` runs over
//     untrusted, attacker-controlled bytes.
//   * Maps (`[String: String]`): a UInt64 entry count, then entries sorted by the RAW UTF-8 bytes of
//     the key (byte-lexicographic — unambiguous and identical on every stack, unlike `.sortedKeys`).
//
// This is signing INPUT only. It is never the wire format, never persisted, never transmitted.
// The wire format remains the types' synthesized `Codable` conformance (unchanged).

import Foundation
import FernletDomainModel

// WI-9: every declaration in this file is `nonisolated`. ProximityKit sets
// `.defaultIsolation(MainActor.self)`, which would otherwise MainActor-isolate this pure signing-byte
// serializer. The canonical bytes are derived from value-type fields with no actor state, so signing
// and signature verification must be runnable from any isolation domain — `MeshAdmissionToken.verify`
// is `nonisolated` and calls straight into `canonicalBytes`/`legacyCanonicalBytes` below.

// MARK: - Canonical byte writer

/// Append-only binary writer for canonical signing bytes. The format is positional and
/// length-prefixed: the field order in the `canonicalBytes(for:)` functions below IS the schema.
nonisolated struct CanonicalByteWriter {
    private(set) var bytes = Data()

    mutating func appendByte(_ value: UInt8) {
        bytes.append(value)
    }

    /// 8-byte big-endian. Endianness is pinned by `bigEndian`, so the on-wire bytes are identical
    /// regardless of host byte order.
    mutating func appendUInt64(_ value: UInt64) {
        var bigEndian = value.bigEndian
        withUnsafeBytes(of: &bigEndian) { bytes.append(contentsOf: $0) }
    }

    /// 8-byte big-endian two's-complement.
    mutating func appendInt64(_ value: Int64) {
        appendUInt64(UInt64(bitPattern: value))
    }

    /// UInt64 big-endian length prefix followed by the raw bytes.
    mutating func appendLengthPrefixed(_ data: Data) {
        appendUInt64(UInt64(data.count))
        bytes.append(data)
    }

    /// Length-prefixed UTF-8.
    mutating func appendString(_ string: String) {
        appendLengthPrefixed(Data(string.utf8))
    }

    /// 16 raw bytes in network order (no length prefix — a UUID is always 16 bytes).
    mutating func appendUUID(_ uuid: UUID) {
        withUnsafeBytes(of: uuid.uuid) { bytes.append(contentsOf: $0) }
    }

    /// Whole seconds since the Unix epoch, floored. Saturating: an out-of-range or non-finite value
    /// (only reachable from a hostile decoded envelope) clamps instead of trapping.
    mutating func appendDate(_ date: Date) {
        let seconds = date.timeIntervalSince1970.rounded(.down)
        let clamped: Int64
        if !seconds.isFinite {
            clamped = 0
        } else if seconds >= Double(Int64.max) {
            clamped = .max
        } else if seconds <= Double(Int64.min) {
            clamped = .min
        } else {
            clamped = Int64(seconds)
        }
        appendInt64(clamped)
    }

    mutating func appendOptional(_ date: Date?) {
        if let date {
            appendByte(1)
            appendDate(date)
        } else {
            appendByte(0)
        }
    }

    mutating func appendOptional(_ string: String?) {
        if let string {
            appendByte(1)
            appendString(string)
        } else {
            appendByte(0)
        }
    }
}

// MARK: - Byte-lexicographic key ordering

/// Orders two strings by their raw UTF-8 bytes. Deterministic and identical across stacks — unlike
/// Foundation's `.sortedKeys`, which orders by UTF-16 code units (different for non-BMP scalars).
nonisolated func canonicalUTF8Ordered(_ lhs: String, _ rhs: String) -> Bool {
    let a = Array(lhs.utf8)
    let b = Array(rhs.utf8)
    let shared = min(a.count, b.count)
    var index = 0
    while index < shared {
        if a[index] != b[index] { return a[index] < b[index] }
        index += 1
    }
    return a.count < b.count
}

// MARK: - Domain tags

// Distinct per signed type so a signature over one type cannot validate over the other.
private nonisolated let canonicalEnvelopeDomain = Data("fernlet.canonical.identity-envelope.v2".utf8)
private nonisolated let canonicalAdmissionTokenDomain = Data("fernlet.canonical.mesh-admission-token.v2".utf8)

// MARK: - Identity envelope

/// Canonical signing bytes for a `FernletIdentityEnvelope` (schema v2+). The `signature` field is
/// excluded entirely (it is the output of signing these bytes).
public nonisolated func canonicalBytes(for envelope: FernletIdentityEnvelope) -> Data {
    var writer = CanonicalByteWriter()
    writer.appendLengthPrefixed(canonicalEnvelopeDomain)
    writer.appendInt64(Int64(envelope.schemaVersion))
    writer.appendUUID(envelope.envelopeID)
    writer.appendLengthPrefixed(envelope.senderSigningPublicKey)
    writer.appendLengthPrefixed(envelope.senderKeyAgreementPublicKey)
    writer.appendString(envelope.senderDisplayName)
    writer.appendOptional(envelope.recipientFingerprint)
    // The RAW wire token, not the enum case: canonical bytes must be computable for payload types
    // this build doesn't know, so signatures on newer-build envelopes still verify (Phase 1
    // forward tolerance). For known types the token IS the rawValue — bytes unchanged.
    writer.appendString(envelope.payloadTypeToken)
    appendCanonical(&writer, envelope.payloadEncryption)
    appendCanonical(&writer, envelope.payloadSummary)
    writer.appendLengthPrefixed(envelope.payload)
    writer.appendDate(envelope.createdAt)
    writer.appendOptional(envelope.expiresAt)
    // signature: deliberately excluded.
    return writer.bytes
}

private nonisolated func appendCanonical(_ writer: inout CanonicalByteWriter, _ encryption: PayloadEncryption) {
    switch encryption {
    case .none:
        writer.appendByte(0)
    case .sealedTo(let recipientKeyAgreementPublicKey):
        writer.appendByte(1)
        writer.appendLengthPrefixed(recipientKeyAgreementPublicKey)
    }
}

private nonisolated func appendCanonical(_ writer: inout CanonicalByteWriter, _ summary: PayloadSummary) {
    writer.appendString(summary.title)
    writer.appendOptional(summary.subtitle)
    writer.appendInt64(Int64(summary.itemCount))
    if let dateRange = summary.dateRange {
        writer.appendByte(1)
        writer.appendDate(dateRange.start)
        writer.appendDate(dateRange.end)
    } else {
        writer.appendByte(0)
    }
    let orderedDetails = summary.extraDetails.sorted { canonicalUTF8Ordered($0.key, $1.key) }
    writer.appendUInt64(UInt64(orderedDetails.count))
    for (key, value) in orderedDetails {
        writer.appendString(key)
        writer.appendString(value)
    }
}

// MARK: - Mesh admission token

/// Canonical signing bytes for a `MeshAdmissionToken` (canonical v2). The `admitterSignature` field
/// is excluded entirely (it is the output of signing these bytes).
public nonisolated func canonicalBytes(for token: MeshAdmissionToken) -> Data {
    var writer = CanonicalByteWriter()
    writer.appendLengthPrefixed(canonicalAdmissionTokenDomain)
    writer.appendUUID(token.meshID)
    writer.appendString(token.joinerFingerprint)
    writer.appendLengthPrefixed(token.joinerSigningPublicKey)
    writer.appendString(token.admitterFingerprint)
    writer.appendDate(token.grantedAt)
    writer.appendDate(token.expiresAt)
    writer.appendLengthPrefixed(token.admitterSigningPublicKey)
    // admitterSignature: deliberately excluded.
    return writer.bytes
}

// MARK: - Legacy (pre-WI-6) canonical encoder

// Retained ONLY to verify signatures minted by in-field peers that predate WI-6 (envelope schema
// v1 / unversioned tokens). It is never used to SIGN. Removing it would silently reject every
// not-yet-updated Apple peer, so it stays until those builds age out.

/// The exact Foundation encoder configuration used before WI-6. Do not change — its byte output is a
/// compatibility contract with already-signed, in-field data.
private nonisolated func makeLegacyCanonicalSignatureEncoder() -> JSONEncoder {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    encoder.dateEncodingStrategy = .iso8601
    return encoder
}

/// Legacy (schema v1) canonical bytes for an envelope. `try?`/`?? Data()` keeps the untrusted
/// verify path non-throwing; an empty result simply fails the signature check.
public nonisolated func legacyCanonicalBytes(for envelope: FernletIdentityEnvelope) -> Data {
    var copy = envelope
    copy.signature = Data()
    return (try? makeLegacyCanonicalSignatureEncoder().encode(copy)) ?? Data()
}

/// Legacy (pre-WI-6) canonical bytes for an admission token.
public nonisolated func legacyCanonicalBytes(for token: MeshAdmissionToken) -> Data {
    var copy = token
    copy.admitterSignature = Data()
    return (try? makeLegacyCanonicalSignatureEncoder().encode(copy)) ?? Data()
}
