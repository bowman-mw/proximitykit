// MeshRoutedContentHasher.swift
// ProximityKit/Mesh
//
// Network migration P5 item 3 (plan §11): the streaming sibling of
// `MeshRoutedContentDigest.contentHash(of:)`.
//
// One domain, two shapes — never a second domain. The one-shot form hashes a blob that is already
// resident; the durable store never holds one (256 MiB), so it feeds the same domain one chunk file
// at a time. A separate digest domain for the streamed form would mean a custodian's whole-item
// check and the origin's manifest field measured different things.

import CryptoKit
import FernletCrypto
import Foundation

// MARK: - MeshRoutedContentHasher

/// An incremental accumulator over exactly ``MeshRoutedContentDigest/contentHash(of:)``'s domain:
/// `SHA-256(lp(Hash.meshRoutedContentV1) ‖ blob)`, fed one slice at a time so a 256 MiB item is
/// never resident.
///
/// Seeded at ``init()`` with the length-prefixed purpose exactly as the one-shot form is, then fed
/// the item's payload slices **in index order**. The two agree byte for byte for any split of the
/// same bytes — the property `MeshRoutedStore.committingCustody` rests its whole-item verdict on,
/// and the one a test pins across several split points.
///
/// Pure value, no clock, no I/O: the caller owns the file reads and hands over `Data` slices.
nonisolated struct MeshRoutedContentHasher {

    /// The running SHA-256 state, already seeded with the domain prefix.
    private var hasher: SHA256

    /// Starts an accumulator seeded with `lp(Hash.meshRoutedContentV1)`, the same prefix the
    /// one-shot digest writes before the body.
    init() {
        var writer = CanonicalByteWriter()
        writer.appendLengthPrefixed(FernletCryptoPurpose.Hash.meshRoutedContentV1.data)
        var seeded = SHA256()
        seeded.update(data: writer.bytes)
        hasher = seeded
    }

    /// Feeds the next slice of the item's ciphertext, in index order.
    ///
    /// - Parameter slice: One chunk's payload. Order is the caller's responsibility and is what the
    ///   store's bounded `0..<chunkCount` loop provides.
    mutating func update(_ slice: Data) {
        hasher.update(data: slice)
    }

    /// The 32-byte digest over everything fed so far.
    ///
    /// - Returns: The same bytes ``MeshRoutedContentDigest/contentHash(of:)`` returns for the
    ///   concatenation of every slice passed to ``update(_:)``.
    func finalized() -> Data {
        Data(hasher.finalize())
    }
}
