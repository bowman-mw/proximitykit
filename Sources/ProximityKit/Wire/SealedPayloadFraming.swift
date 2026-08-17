import Foundation
import Compression

/// How a sealed payload body is framed inside the AEAD (wire2, bitchat adoptions Increment 2,
/// Docs/Plan-Bitchat-Adoptions-2026-07-25.md). Threaded through `IdentityService.seal/open` and
/// `FernletIdentityEnvelope.verify`; derived at call sites from the peer's advertised
/// capabilities, never from the bytes alone.
public nonisolated enum SealedPayloadFormat: Equatable, Sendable {
    /// Pre-wire2 behavior: the plaintext is sealed as-is.
    case legacy
    /// Compress + pad framing. Sealing always frames; opening unframes tolerantly (a body without
    /// a frame tag passes through unchanged, covering the handshake race where a wire2-capable
    /// sender sealed legacy before it learned our capabilities).
    case wire2
}

/// wire2 sealed-plaintext framing: deflate-compress when it helps, pad to a size bucket, THEN
/// seal — so a radio or server observer can't size-class sealed payloads (a heart vs a message vs
/// a photo), and base64-heavy JSON bodies stop paying +33% on the wire. Applied only between
/// peers that both advertise the `wire2` capability; the dead-drop wire (Increment 3) uses it
/// unconditionally because its only readers are new clients by construction.
///
/// Frame layout (this is the SEALED PLAINTEXT — ChaChaPoly provides integrity, so the padding
/// needs no MAC of its own):
///
///     [tag: UInt8] [body] [zero padding] [padCount: UInt16 big-endian]
///
/// tag 0x01 = body is a raw-DEFLATE stream of the original bytes; 0x02 = body is the original.
/// `padCount` counts only the zero-padding bytes. The total frame length lands on a bucket:
/// 256 / 512 / 1024 / 2048 / 4096, then the next 4 KiB multiple (bitchat pads to the same
/// power-of-two ladder; the 4 KiB tail keeps photo padding waste under ~0.7%).
///
/// Compatibility invariant (do not break): every legacy (unframed) sealed body in this codebase
/// is a JSON object — first byte 0x7B — so 0x01/0x02 are collision-free reserved discriminators.
/// The receive gate only attempts unframing when the sender advertised `wire2` AND
/// `hasFrameTag(_:)` holds. Never introduce a sealed payload whose unframed body can start with
/// 0x01 or 0x02.
///
/// Senders must respect payload caps upstream (e.g. the 10 MB friend-photo receiver cap):
/// `frame(_:)` accepts any size, but `unframe(_:)` rejects anything that would inflate past
/// `maxInflatedByteCount`.
public nonisolated enum SealedPayloadFraming {

    /// Unframe failures: structurally invalid frame bytes, or a compressed body that would
    /// inflate past `maxInflatedByteCount` (the inflate-bomb guard).
    public enum FramingError: Error, Equatable {
        case malformed
        case inflatedTooLarge
    }

    static let compressionTag: UInt8 = 0x01
    static let rawTag: UInt8 = 0x02

    /// Compress only when the body is at least this long AND deflate actually shrinks it
    /// (bitchat uses 100 B; tiny bodies pad to the 256 bucket either way).
    static let compressionThresholdBytes = 128

    /// Inflate bomb guard — comfortably above the 10 MB friend-photo receiver cap.
    public static let maxInflatedByteCount = 16 * 1024 * 1024

    /// Smallest bucket that fits `frameLength`: 256/512/1024/2048/4096, then next 4 KiB multiple.
    static func bucketLength(for frameLength: Int) -> Int {
        for bucket in [256, 512, 1024, 2048, 4096] where frameLength <= bucket {
            return bucket
        }
        let unit = 4096
        return ((frameLength + unit - 1) / unit) * unit
    }

    /// Compress-if-smaller, then pad to the bucket. Total infallible: a compression failure
    /// falls back to the raw tag rather than failing the send.
    public static func frame(_ plaintext: Data) -> Data {
        var tag = rawTag
        var body = plaintext
        if plaintext.count >= compressionThresholdBytes,
           let compressed = try? stream(COMPRESSION_STREAM_ENCODE, input: plaintext, limit: Int.max),
           compressed.count < plaintext.count {
            tag = compressionTag
            body = compressed
        }
        let unpaddedLength = 1 + body.count + 2
        let padCount = bucketLength(for: unpaddedLength) - unpaddedLength
        var framed = Data(capacity: unpaddedLength + padCount)
        framed.append(tag)
        framed.append(body)
        if padCount > 0 { framed.append(Data(count: padCount)) }
        framed.append(contentsOf: [UInt8((padCount >> 8) & 0xFF), UInt8(padCount & 0xFF)])
        return framed
    }

    /// Strict inverse of `frame(_:)`. Callers gate on the sender's advertised `wire2` capability
    /// plus `hasFrameTag(_:)` — a legacy body must never reach this.
    public static func unframe(_ framed: Data) throws -> Data {
        guard framed.count >= 3 else { throw FramingError.malformed }
        let bytes = Data(framed) // normalize slice indices
        let tag = bytes[0]
        guard tag == compressionTag || tag == rawTag else { throw FramingError.malformed }
        let padCount = (Int(bytes[bytes.count - 2]) << 8) | Int(bytes[bytes.count - 1])
        guard padCount <= bytes.count - 3 else { throw FramingError.malformed }
        let body = bytes.subdata(in: 1..<(bytes.count - 2 - padCount))
        if tag == rawTag { return body }
        guard !body.isEmpty else { throw FramingError.malformed }
        return try stream(COMPRESSION_STREAM_DECODE, input: body, limit: maxInflatedByteCount)
    }

    /// Whether a sealed plaintext opens with a wire2 frame tag. Used by the tolerant receive path
    /// together with the sender's advertised `wire2` capability — never alone.
    public static func hasFrameTag(_ plaintext: Data) -> Bool {
        guard let first = plaintext.first else { return false }
        return first == compressionTag || first == rawTag
    }

    // MARK: - zlib streaming (raw DEFLATE — Compression's COMPRESSION_ZLIB, no zlib header,
    // standard enough for the future Android stack: Inflater(nowrap: true) reads it as-is)

    private static func stream(
        _ operation: compression_stream_operation,
        input: Data,
        limit: Int
    ) throws -> Data {
        guard !input.isEmpty else { throw FramingError.malformed }

        let streamPointer = UnsafeMutablePointer<compression_stream>.allocate(capacity: 1)
        defer { streamPointer.deallocate() }
        guard compression_stream_init(streamPointer, operation, COMPRESSION_ZLIB) != COMPRESSION_STATUS_ERROR else {
            throw FramingError.malformed
        }
        defer { compression_stream_destroy(streamPointer) }

        let destinationCapacity = 64 * 1024
        let destinationBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: destinationCapacity)
        defer { destinationBuffer.deallocate() }

        var output = Data()
        try input.withUnsafeBytes { (source: UnsafeRawBufferPointer) in
            guard let sourceBase = source.bindMemory(to: UInt8.self).baseAddress else {
                throw FramingError.malformed
            }
            streamPointer.pointee.src_ptr = sourceBase
            streamPointer.pointee.src_size = input.count
            streamPointer.pointee.dst_ptr = destinationBuffer
            streamPointer.pointee.dst_size = destinationCapacity

            // R2 bound, visible at the loop: every iteration either consumes at least one source
            // byte (≤ input.count iterations) or produces at least one output byte (≤ limit /
            // destinationCapacity + 1 iterations, and `limit` is the inflate-bomb cap); an
            // iteration that does neither throws below, so the loop cannot spin.
            var status = COMPRESSION_STATUS_OK
            while status != COMPRESSION_STATUS_END {
                let sourceBefore = streamPointer.pointee.src_size
                status = compression_stream_process(streamPointer, Int32(COMPRESSION_STREAM_FINALIZE.rawValue))
                guard status != COMPRESSION_STATUS_ERROR else { throw FramingError.malformed }
                let produced = destinationCapacity - streamPointer.pointee.dst_size
                if produced > 0 {
                    output.append(destinationBuffer, count: produced)
                    guard output.count <= limit else { throw FramingError.inflatedTooLarge }
                    streamPointer.pointee.dst_ptr = destinationBuffer
                    streamPointer.pointee.dst_size = destinationCapacity
                }
                // Non-terminal status that neither produced output nor consumed source: a
                // truncated/garbage stream that would otherwise spin — reject.
                guard status == COMPRESSION_STATUS_END
                        || produced > 0
                        || streamPointer.pointee.src_size < sourceBefore else {
                    throw FramingError.malformed
                }
            }
        }
        return output
    }
}
