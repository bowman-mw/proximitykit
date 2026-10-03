// ProximityCryptographicPurpose.swift
// ProximityKit/Namespace
//
// ProximityKit plan step A0.2.1 (Docs/Plan-FernletCoach-ProximityKit-2026-10-01.md §4 A0.2, §13 item
// 1): ProximityKit's own domain-separation value. It keeps the byte rules of FernletCrypto's
// `CryptographicPurpose` exactly — the same `data`, the same three framings, the same positional
// `signingBytes` test — but the host supplies the bytes, as a source literal handed to a
// `ProximityNamespace` group initializer (or, for a salt one of its own features derives under, to
// `featureKeyDerivationSalt(_:)`), and ProximityKit decides how each label is consumed.
// A0.2's later commits routed ProximityKit's label reads through the namespace, so every protocol
// label ProximityKit consumes is one of these.

import Foundation

// MARK: - ProximityCryptographicPurpose

/// One domain-separation label and the one way ProximityKit consumes it.
///
/// A purpose is cryptographic format data, never display text. Its bytes reach a signed transcript, a
/// hash preimage, a key derivation, an authenticated-data layout or a TLS exporter, so changing one
/// changes a key, a digest, or the bytes an existing signature verifies.
///
/// **Why a label is a source literal.** The host hands the bytes over as a `StaticString`, and a
/// `StaticString` can only be written as a literal. It does so two ways: to a ``ProximityNamespace``
/// group initializer, for a field the protocol fixes, or to ``featureKeyDerivationSalt(_:)``, for an
/// HKDF salt one of its own features derives under, which reaches its one door only when the host's
/// namespace declares it (``ProximityNamespace/FeaturePurposes``). Every label is therefore a reviewed
/// spelling in somebody's source: a domain assembled at run time is a domain nobody reviewed, and one
/// assembled from peer or user input lets an attacker choose where their bytes are accepted. There is
/// no public initializer (the one host-callable mint takes a `StaticString` and fixes the role
/// itself), no `Codable` conformance and no decoding path, so a purpose never arrives over the wire or
/// from configuration. FernletCrypto's registry gets the same guarantee from a `fileprivate`
/// initializer; a host in another module cannot reach one of those, and a `StaticString` parameter
/// keeps the guarantee structural across the module boundary.
///
/// **Why ProximityKit fixes the role.** ``role`` says which ProximityKit consumer reads the bytes and
/// how: a length-prefixed transcript, a raw-prefix one, a salt, a column seal, an AAD, an exporter
/// label. That is a fact about ProximityKit's code, not a host preference, so the namespace field a
/// label fills decides it, the feature-salt mint gives its one role, and no initializer takes one. A
/// host free to choose could only get it wrong: a raw-prefix role on a length-prefixed transcript
/// makes ``signingBytes(_:)`` refuse every signature, and an `.absent` role on a live transcript would
/// accept any bytes at all.
///
/// `nonisolated` against the module's `defaultIsolation(MainActor.self)`: inert `Sendable` value data,
/// read from the nonisolated serializers, verifiers and stores.
public nonisolated struct ProximityCryptographicPurpose: Hashable, Sendable {

    /// Where the label sits at the front of a signed transcript or a hash preimage.
    ///
    /// The byte layouts are already signed by shipped peers, so the framing describes the format rather
    /// than reshaping it. Naming it per field keeps ``ProximityCryptographicPurpose/signingBytes(_:)`` an
    /// exact positional match: a substring search would accept a label buried in attacker-chosen fields.
    public nonisolated enum Framing: Hashable, Sendable {
        /// The input begins with the label's bytes, verbatim.
        case rawPrefix
        /// The label is the input's first length-prefixed field: an 8-byte big-endian byte count, then
        /// the bytes. The canonical serializer writes every variable-length field this way, the domain
        /// included.
        case lengthPrefixed
        /// A format from before domain separation, which carries no label bytes, so every input
        /// qualifies. Legacy and verify-only: never the framing of a new write format.
        case absent
    }

    /// The consumer of the bytes. The namespace field the label fills fixes it; the host never chooses
    /// it.
    public nonisolated enum Role: Hashable, Sendable {
        /// An Ed25519 signature transcript that begins with the label under the given framing.
        case signature(Framing)
        /// A SHA-256 preimage that begins with the label under the given framing.
        case hashDomain(Framing)
        /// An HKDF salt: the label's bytes, whole.
        case keyDerivationSalt
        /// A sealed store's column seal: the HKDF `info` of its column key and the front of its AEAD
        /// authenticated data.
        case columnSeal
        /// The front of an AEAD's authenticated data, alone or before the consumer's own suffix.
        case aeadAssociatedData
        /// The label a QUIC connection's TLS exporter derives its channel-binding secret under.
        case tlsExporterLabel
    }

    /// The label's spelling, exactly as the host's literal wrote it. For goldens, validation and
    /// diagnostics only: a consumer takes ``data`` or ``prefixBytes``.
    public let rawValue: String

    /// How ProximityKit consumes ``data``, fixed by the namespace field this label fills.
    public let role: Role

    /// Mints a purpose from a host's literal.
    ///
    /// Internal on purpose: only the ``ProximityNamespace`` group initializers call it, each with the
    /// role its field fixes, and ``featureKeyDerivationSalt(_:)``, with the one role a host may mint
    /// for itself. `description` copies the literal into a `String` without touching
    /// `StaticString`'s unsafe-pointer accessors (Power of 10 R9).
    ///
    /// - Parameters:
    ///   - spelling: The host's source literal.
    ///   - role: The role the namespace field fixes.
    init(_ spelling: StaticString, role: Role) {
        self.rawValue = spelling.description
        self.role = role
    }

    /// Mints a host feature's HKDF salt from the host's literal: the one role a host may mint a label
    /// for itself.
    ///
    /// The protocol's labels fill the fixed fields of the namespace's groups. A host's feature that
    /// derives a pair secret (Fernlet's heart dead-drop and presence, for two) needs a salt of its
    /// own, so the host mints it here, in the `.keyDerivationSalt` role, whole, and declares it in its
    /// namespace's family (``ProximityNamespace/FeaturePurposes``). The label reaches its one door,
    /// ``IdentityService/pairSecret(with:purpose:)``, only when that namespace declares it, so the
    /// namespace's one soundness verdict has judged it with every protocol label (well-formed,
    /// distinct, prefix-free): a salt minted here and declared nowhere derives nothing. Total and
    /// pure: it reads nothing but its argument.
    ///
    /// - Parameter spelling: The host's source literal.
    /// - Returns: The salt, its role ``Role/keyDerivationSalt``.
    public static func featureKeyDerivationSalt(_ spelling: StaticString) -> ProximityCryptographicPurpose {
        ProximityCryptographicPurpose(spelling, role: .keyDerivationSalt)
    }

    /// `Data(rawValue.utf8)`: the label's bytes, with no terminator and no normalization.
    public var data: Data { Data(rawValue.utf8) }

    /// What the consumer writes first: ``data`` for a raw-prefix role and for every role that takes the
    /// label whole, the 8-byte big-endian byte count then ``data`` for a length-prefixed one, and nothing
    /// for ``Framing/absent``.
    ///
    /// A golden cell per consumer checks that the bytes it writes begin with this value, so a role and
    /// the code that consumes it cannot drift apart.
    public var prefixBytes: Data {
        switch framing {
        case .rawPrefix:
            return data
        case .lengthPrefixed:
            return Self.lengthPrefixed(data)
        case .absent:
            return Data()
        }
    }

    /// `transcript`, unchanged, when ``role`` is a signature role and the transcript begins with
    /// ``prefixBytes``; otherwise `nil`.
    ///
    /// The positional rule of FernletCrypto's `CryptographicPurpose.signingBytes(_:)`: a
    /// length-prefixed label refuses its own raw spelling and a transcript shifted by one byte, and an
    /// `.absent` label accepts every transcript. A label in any other role refuses every transcript, so
    /// a salt, a seal or an AAD label can never authorize a signature.
    ///
    /// - Parameter transcript: The bytes about to be signed or verified.
    /// - Returns: The same bytes, unmodified, so the check can sit directly at the signing boundary.
    public func signingBytes(_ transcript: Data) -> Data? {
        guard case .signature = role else { return nil }
        guard transcript.starts(with: prefixBytes) else { return nil }
        return transcript
    }

    /// The framing ``role`` puts the label under. A role that takes the label whole — a salt, a column
    /// seal, an AAD, an exporter label — reads it as a raw prefix of its input.
    private var framing: Framing {
        switch role {
        case .signature(let framing), .hashDomain(let framing):
            return framing
        case .keyDerivationSalt, .columnSeal, .aeadAssociatedData, .tlsExporterLabel:
            return .rawPrefix
        }
    }

    /// `bytes` behind their 8-byte big-endian count, shifted out one byte at a time exactly as the
    /// canonical serializer's `appendUInt64` and FernletCrypto's `CryptographicPurpose` write it.
    ///
    /// - Parameter bytes: A label's bytes.
    /// - Returns: The count, then the bytes.
    private static func lengthPrefixed(_ bytes: Data) -> Data {
        var prefixed = Data()
        let count = UInt64(bytes.count)
        // R2: eight iterations, one per byte of the count.
        for shift in stride(from: 56, through: 0, by: -8) {
            prefixed.append(UInt8(truncatingIfNeeded: count >> UInt64(shift)))
        }
        prefixed.append(bytes)
        return prefixed
    }
}
