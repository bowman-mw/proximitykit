// ProximityColumnCrypto.swift
// ProximityKit/Support
//
// ProximityKit plan step A0.2.9 (Docs/Plan-FernletCoach-ProximityKit-2026-10-01.md §4 A0.2, "Copied into
// ProximityKit: … `ColumnCrypto`, byte for byte (used by the mesh session and routed stores)"): the V3
// column seal of the two sealed mesh stores, copied out of FernletCrypto so that ProximityKit seals
// under its own purpose type, read off the host's namespace, and the host's install binding, rather
// than FernletCrypto's registry and its `DeviceBindingID`. The bytes do not move: every blob either
// store wrote before the copy opens with it, and every blob it writes opens with FernletCrypto's
// `ColumnCrypto`. `ProximityNamespaceGoldenTests` runs the A0.2.0 column vectors through both, both
// ways.

import CryptoKit
import Foundation

/// The V3 column seal of ProximityKit's two sealed mesh stores: FernletCrypto's `ColumnCrypto`, byte for
/// byte, under the host's label and the host's install binding.
///
/// **The format.** Every blob is `0x03` ‖ nonce (12 bytes) ‖ ciphertext ‖ tag (16 bytes): the
/// ChaCha20-Poly1305 sealed box's `combined` bytes behind the V3 marker. The key is HKDF-SHA256 of the
/// store's content key with no salt, the purpose's bytes as `info` and 32 bytes out. The authenticated
/// data is the purpose's bytes, then the install binding's (`purpose ‖ binding`, never the other order),
/// so a blob refuses to authenticate under another column's label, another content key or another
/// install. The `Codable` pair seals `JSONEncoder()`'s default output. Changing any of it orphans every
/// mesh-session context and routed index and chunk already on disk.
///
/// **What came across, and what did not.** The seal, the open, the key derivation, the open's three
/// named refusals (``SealedColumnOpenError``) and the seal's one (``SealedColumnStrictSealError``) came
/// across. FernletCrypto's `init(label:)` and `deriveColumnKey(info:)` stayed behind, because they spell
/// Fernlet's private-store labels, and so did the string seal and the census helpers, which no mesh
/// store calls. There was no legacy reader to leave out: FernletCrypto's `ColumnCrypto` has opened V3
/// alone since its Phase 3, and it refuses an unprefixed or `0x02` blob by name rather than reading it.
/// A mesh store that meets one today refuses it the same way, so the marker classifier
/// (``StoredFormat``) came across and no reader did.
///
/// **The purpose and the binding.** A store hands its scope namespace's column seal
/// (`family.purposes.keyDerivation.meshSessionContextV1` or `.meshRoutedStoreV1`, the two fields
/// ``ProximityNamespace/KeyDerivation`` mints with the
/// ``ProximityCryptographicPurpose/Role/columnSeal`` role) and its scope's ``ProximityInstallBinding``.
/// The binding is read at the moment of each seal and each open, never cached here, so whatever the
/// host answers at that moment is what the blob is sealed or opened under.
///
/// Failure modes, as the original's: a seal refuses with ``SealedColumnStrictSealError/bindingUnavailable``
/// when the host has no durable binding, or its read failed, and otherwise rethrows CryptoKit's errors.
/// An open refuses with a ``SealedColumnOpenError`` when the bytes are not openable V3 at all or the
/// binding is authoritatively absent, propagates ``ProximityInstallBindingReadError`` unchanged when the
/// binding's read failed (retryable, never an authentication claim), and fails with CryptoKit's
/// authentication error for a V3 blob that is truncated, tampered with or sealed under another key,
/// label or install. The `Codable` pair also rethrows JSON coding errors.
///
/// `nonisolated` against the module's `defaultIsolation(MainActor.self)`, and `Sendable`, as the original
/// is: a pure value the nonisolated stores hold and call synchronously. Its state is an immutable purpose
/// and the host's `Sendable` binding, so the conformance is compiler-checked.
nonisolated struct ProximityColumnCrypto: Sendable {

    /// Which at-rest generation a stored blob's marker byte says it is: FernletCrypto's
    /// `ColumnCryptoStoredFormat`, without its census helpers.
    ///
    /// The classifier outlived the readers of the two older generations so that a refusal can say what
    /// it refused. It reads the first byte and nothing else, exactly as the open's dispatch does, so a
    /// legacy blob whose random first nonce byte equals a marker is classified by that marker.
    nonisolated enum StoredFormat: Hashable, Sendable {
        /// First byte `0x03`: the current format, `purpose ‖ binding` as authenticated data.
        case v3Marked
        /// First byte `0x02`: the retired device-bound format, the binding alone as authenticated data.
        case v2Marked
        /// Any other first byte: a retired bare `combined` blob with no marker and no authenticated data.
        case unprefixed
        /// No bytes at all.
        case empty

        /// Classifies a stored blob from its first byte alone. Never decrypts and never reads the binding.
        ///
        /// - Parameter data: One stored blob.
        /// - Returns: The bucket the open's dispatch puts these bytes in.
        static func classify(_ data: Data) -> StoredFormat {
            guard let marker = data.first else { return .empty }
            switch marker {
            case ProximityColumnCrypto.deviceBoundFormatVersionV3:
                return .v3Marked
            case ProximityColumnCrypto.deviceBoundFormatVersionV2:
                return .v2Marked
            default:
                return .unprefixed
            }
        }
    }

    /// Why a stored blob could not be opened, named by what the bytes are: the original's three cases.
    ///
    /// Deliberately not thrown for a tampered or wrong-key V3 blob, where CryptoKit's own error is the
    /// honest answer, nor when the binding's read failed, which throws the retryable
    /// ``ProximityInstallBindingReadError`` so that an outage never reads as a dead format.
    nonisolated enum SealedColumnOpenError: Error, Sendable, Equatable {
        /// The marker byte names a generation this build no longer reads (`0x02`, or none). Terminal.
        case retiredFormat(StoredFormat)
        /// The blob holds zero bytes. No writer produces one, so this is a store fault, not a format.
        case emptyBlob
        /// The blob is V3, and the install binding its authenticated data needs is authoritatively
        /// absent, so it cannot be opened on this install. Terminal, and not an authentication failure.
        case installBindingMissing
    }

    /// Why a seal refused: the original's one case. The seal writes V3 or nothing.
    nonisolated enum SealedColumnStrictSealError: Error, Equatable {
        /// The host produced no durable install binding, so the authenticated data cannot be built. The
        /// seal refuses (owner decision D4) and never writes an unbound blob: the caller sees a failed
        /// save.
        case bindingUnavailable
    }

    /// The column's label: the HKDF `info` of its key and the front of its authenticated data.
    let purpose: ProximityCryptographicPurpose

    /// The host's install binding, read at each seal and each open.
    let installBinding: any ProximityInstallBinding

    /// The retired V2 marker. A classifier constant only: nothing here opens these bytes.
    static let deviceBoundFormatVersionV2: UInt8 = 0x02

    /// The V3 marker in front of every blob written or read. Part of the at-rest format.
    static let deviceBoundFormatVersionV3: UInt8 = 0x03

    /// A column seal under one label and one install binding.
    ///
    /// - Parameters:
    ///   - purpose: The column's label, a ``ProximityCryptographicPurpose/Role/columnSeal`` field of the
    ///     store's scope namespace.
    ///   - installBinding: The store's scope's install binding.
    init(purpose: ProximityCryptographicPurpose, installBinding: any ProximityInstallBinding) {
        self.purpose = purpose
        self.installBinding = installBinding
    }

    // MARK: - Codable

    /// JSON-encodes `value` with `JSONEncoder()`'s defaults and seals it as V3.
    ///
    /// - Parameters:
    ///   - value: The value to seal.
    ///   - contentKey: The store's content key, from which the column key is derived.
    /// - Returns: `0x03` ‖ `combined`, sealed with `purpose ‖ binding` as authenticated data.
    /// - Throws: ``SealedColumnStrictSealError/bindingUnavailable`` without a durable binding; otherwise
    ///   JSON encoding and CryptoKit errors.
    func seal<T: Encodable>(_ value: T, contentKey: SymmetricKey) throws -> Data {
        let plaintext = try JSONEncoder().encode(value)
        return try sealPlaintextV3Strict(plaintext, contentKey: contentKey)
    }

    /// Opens a V3 blob and JSON-decodes its plaintext.
    ///
    /// - Parameters:
    ///   - data: The stored blob, or `nil` for a column never sealed.
    ///   - contentKey: The store's content key.
    /// - Returns: `nil` for `nil` data; the decoded value otherwise.
    /// - Throws: A ``SealedColumnOpenError``, ``ProximityInstallBindingReadError``, CryptoKit's
    ///   authentication error, or a JSON decoding error.
    func open<T: Decodable>(_ data: Data?, contentKey: SymmetricKey) throws -> T? {
        guard let data else { return nil }
        let plaintext = try openBlob(data, contentKey: contentKey)
        return try JSONDecoder().decode(T.self, from: plaintext)
    }

    // MARK: - The V3 core

    /// The one seal entry: `0x03` ‖ `combined`, with `purpose ‖ binding` as authenticated data.
    ///
    /// The binding is the host's ``ProximityInstallBindingAccess/seal`` answer. A read that throws there
    /// means the binding's state is unknown, which refuses the seal exactly as no binding does:
    /// `DeviceBindingID.current()`, which the original read, answers `nil` for both.
    private func sealPlaintextV3Strict(_ plaintext: Data, contentKey: SymmetricKey) throws -> Data {
        let key = columnKey(from: contentKey)
        guard let binding = try? installBinding.read(for: .seal) else {
            throw SealedColumnStrictSealError.bindingUnavailable
        }
        let aad = purpose.data + binding
        let combined = try ChaChaPoly.seal(plaintext, using: key, authenticating: aad).combined
        return Data([Self.deviceBoundFormatVersionV3]) + combined
    }

    /// Opens one blob. V3 is the only readable generation.
    ///
    /// The marker is classified before the binding is read, so a retired blob is refused by name even
    /// while the binding cannot be read. The binding's read error is not caught here: the row's state is
    /// unknown, and it must reach the store as itself rather than as an open failure.
    private func openBlob(_ data: Data, contentKey: SymmetricKey) throws -> Data {
        let format = StoredFormat.classify(data)
        switch format {
        case .v3Marked:
            break
        case .empty:
            throw SealedColumnOpenError.emptyBlob
        case .v2Marked, .unprefixed:
            throw SealedColumnOpenError.retiredFormat(format)
        }
        guard let binding = try installBinding.read(for: .open) else {
            throw SealedColumnOpenError.installBindingMissing
        }
        let key = columnKey(from: contentKey)
        let box = try ChaChaPoly.SealedBox(combined: data.dropFirst())
        return try ChaChaPoly.open(box, using: key, authenticating: purpose.data + binding)
    }

    // MARK: - Key derivation

    /// The column-key derivation: salt-free HKDF-SHA256 of the content key, with the purpose's bytes as
    /// `info`. Part of the at-rest format.
    ///
    /// Internal so the golden suite can pin its known answers; production reaches it only through the
    /// seal and the open.
    ///
    /// - Parameters:
    ///   - contentKey: The input key material.
    ///   - purpose: The column's label.
    ///   - outputByteCount: The key's length in bytes, 32 for a ChaCha20 key.
    /// - Returns: The derived key.
    static func deriveColumnKey(
        contentKey: SymmetricKey,
        purpose: ProximityCryptographicPurpose,
        outputByteCount: Int
    ) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: contentKey, info: purpose.data, outputByteCount: outputByteCount)
    }

    /// This column's 32-byte key.
    private func columnKey(from contentKey: SymmetricKey) -> SymmetricKey {
        Self.deriveColumnKey(contentKey: contentKey, purpose: purpose, outputByteCount: 32)
    }
}
