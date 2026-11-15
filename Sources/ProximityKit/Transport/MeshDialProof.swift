import CryptoKit
import Foundation

// MARK: - MeshDialProof

/// The friend proof two ends of a mesh tunnel exchange **before either sends its hello** (0.2.0,
/// `Docs/Mesh-Dialer-Privacy-Design.md` in the Fernlet repository, the owner's "Go A+B" of 2026-11-15).
///
/// The hello carries the sender's long-term signing key. Through 0.1.x the dialer sent it to whatever
/// advertisement it dialed, before it knew who was behind it. A phone advertising the mesh's service
/// type during a search could learn that key, and a key is a stable identifier across days. Now:
///
/// 1. **Dialer → responder: ``Frame``.** Exactly ``slotCount`` tags, one per peer the dialer would
///    accept on this tunnel (each `HMAC-SHA256(k, 0x01 ‖ binding)` truncated to ``tagByteCount``, where
///    `k` is ``IdentityService/meshDialProofKey(with:)`` for that peer and `binding` is the tunnel's TLS
///    exporter hash), padded with random tags and shuffled, so the frame says nothing about how many
///    friends the dialer has.
/// 2. **Responder.** Derives the same tag for each of its own candidates. No match: it closes the
///    tunnel having sent nothing. A match: it answers ``Accept``, `HMAC-SHA256(k, 0x02 ‖ binding)`
///    truncated to ``acceptByteCount``, which only a holder of that pair key can produce.
/// 3. **Dialer.** Checks the accept against its candidates' keys. Only then does either side send its
///    hello, and the signed introduction still decides who the peer is.
///
/// A stranger sees random-looking values bound to one TLS connection: nothing to replay into another
/// tunnel, nothing to link to another dial, and no key. Relaying a real friend's advertisement does not
/// help, because each leg of a relay has its own exporter secret.
///
/// Pure values and functions, so the whole exchange settles at tier 1. Every constant is wire format.
nonisolated enum MeshDialProof {

    /// The frame's frozen version: the introduction protocol version it was introduced with.
    static let version = 2

    /// Tags in every proof frame, whatever the candidate count.
    static let slotCount = 24

    /// Bytes of one tag.
    static let tagByteCount = 12

    /// Bytes of the accept.
    static let acceptByteCount = 16

    /// Candidates a responder tries a frame against (Power of 10 rule 2: at most this many keys times
    /// ``slotCount`` comparisons, each an HMAC the responder computes once per candidate).
    static let maxResponderCandidates = 256

    /// The role byte in front of the binding in a dial tag.
    private static let dialRole: UInt8 = 0x01

    /// The role byte in front of the binding in an accept.
    private static let acceptRole: UInt8 = 0x02

    /// The dialer's frame: the tags, base64 on the wire, under the frozen keys `v` and `t`.
    struct Frame: Codable, Equatable, Sendable {
        /// ``MeshDialProof/version``.
        let version: Int
        /// Exactly ``MeshDialProof/slotCount`` tags of ``MeshDialProof/tagByteCount`` bytes each.
        let tags: [Data]

        /// The frame's frozen wire keys.
        enum CodingKeys: String, CodingKey {
            case version = "v"
            case tags = "t"
        }

        /// Whether the frame has exactly the shape the format fixes. Checked on untrusted bytes before
        /// a single tag is compared.
        var isWellFormed: Bool {
            version == MeshDialProof.version && tags.count == MeshDialProof.slotCount
                && tags.allSatisfy { $0.count == MeshDialProof.tagByteCount }
        }
    }

    /// The responder's accept, under the frozen keys `v` and `a`.
    struct Accept: Codable, Equatable, Sendable {
        /// ``MeshDialProof/version``.
        let version: Int
        /// ``MeshDialProof/acceptByteCount`` bytes.
        let proof: Data

        /// The accept's frozen wire keys.
        enum CodingKeys: String, CodingKey {
            case version = "v"
            case proof = "a"
        }

        /// Whether the accept has exactly the shape the format fixes.
        var isWellFormed: Bool {
            version == MeshDialProof.version && proof.count == MeshDialProof.acceptByteCount
        }
    }

    /// The dial tag for one pair key on one tunnel.
    static func tag(key: SymmetricKey, binding: Data) -> Data {
        mac(key: key, role: dialRole, binding: binding, length: tagByteCount)
    }

    /// The accept for one pair key on one tunnel.
    static func accept(key: SymmetricKey, binding: Data) -> Data {
        mac(key: key, role: acceptRole, binding: binding, length: acceptByteCount)
    }

    /// The dialer's frame for `keys` (its candidates' pair keys; the first ``slotCount`` are used),
    /// padded with random tags and shuffled.
    static func frame(keys: [SymmetricKey], binding: Data) -> Frame {
        var tags = keys.prefix(slotCount).map { tag(key: $0, binding: binding) }
        for _ in tags.count..<slotCount {
            tags.append(Data((0..<tagByteCount).map { _ in UInt8.random(in: .min ... .max) }))
        }
        tags.shuffle()
        return Frame(version: version, tags: tags)
    }

    /// The responder's reading of a frame: the index into `keys` of the first candidate whose tag the
    /// frame carries, or nil for a malformed frame or no match. Constant-time comparison per tag.
    static func match(_ frame: Frame, keys: [SymmetricKey], binding: Data) -> Int? {
        guard frame.isWellFormed else { return nil }
        for (index, key) in keys.prefix(maxResponderCandidates).enumerated() {
            let expected = tag(key: key, binding: binding)
            if frame.tags.contains(where: { constantTimeEqual($0, expected) }) { return index }
        }
        return nil
    }

    /// The dialer's reading of an accept: the index into `keys` whose accept it is, or nil.
    static func verify(_ accept: Accept, keys: [SymmetricKey], binding: Data) -> Int? {
        guard accept.isWellFormed else { return nil }
        for (index, key) in keys.prefix(slotCount).enumerated()
        where constantTimeEqual(accept.proof, self.accept(key: key, binding: binding)) {
            return index
        }
        return nil
    }

    private static func mac(key: SymmetricKey, role: UInt8, binding: Data, length: Int) -> Data {
        var message = Data([role])
        message.append(binding)
        // The purpose is the key's: it is HKDF'd under the namespace's `keyDerivation.meshDialProofV1`
        // (`IdentityService.meshDialProofKey(with:)`); the role byte parts a tag from an accept.
        return Data(Data(HMAC<SHA256>.authenticationCode(for: message, using: key)).prefix(length))
    }

    /// Byte equality whose time depends on the length alone.
    private static func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for (left, right) in zip(lhs, rhs) { difference |= left ^ right }
        return difference == 0
    }
}
