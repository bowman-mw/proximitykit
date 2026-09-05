// MeshRoutedCustodyCommit.swift
// ProximityKit/Mesh
//
// Network migration P5 item 3 (plan §3.6, §11): the durability gate, and nothing else.
//
// This file holds ONE type and ONE function on purpose. `MeshCustodyDurabilityWitness`'s initialiser
// is `fileprivate`, and `fileprivate` is FILE scope — so the only way anywhere in the app to hold a
// witness is to have completed `MeshRoutedStore.committingCustody(item:custodian:now:)`, which lives
// here beside it. `MeshCustodyReceipt.signed(witness:manifest:identity:)` takes a witness as a
// parameter, so the forbidden order — receipt first, durability later — is not merely discouraged,
// it is unwritable.
//
// The mirror-image rule is why this file holds nothing else: `MeshRoutedStore.LoadToken`'s
// initialiser is `fileprivate` to `MeshRoutedStore.swift`, so the verb below cannot mint its own
// write token either. Two `fileprivate` gates in two files, neither able to open the other's door.
//
// Widening either initialiser to `internal` would let any file in ProximityKit mint a receipt for
// bytes no durable write returned — plan §3.6 demoted from a type rule back to a comment. If the
// witness ever must be `internal`, the lost compile-time guarantee is replaced by the grep-wall in
// `MeshRoutedStoreIsolationTests`, never by a comment.
//
// **Idempotent means "does not refuse", never "skips the check".** Every call re-streams every chunk
// file, compares each opened chunk against the descriptor holding its slot, and gates on size then
// content hash before any witness exists. A short-circuit on "we committed once already" would let a
// repaired, now-incomplete item hand out a witness — a receipt asserting complete durable ciphertext
// this device no longer holds.

import CryptoKit
import Foundation
import FernletFoundation

// MARK: - MeshCustodyDurabilityWitness

/// Proof that a durable custody commit **returned** (plan §3.6).
///
/// Its initialiser is `fileprivate` and it is declared in `Mesh/MeshRoutedCustodyCommit.swift`, the
/// file that holds ``MeshRoutedStore/committingCustody(item:custodian:now:)`` and nothing else — so
/// the only way to hold one is to have completed that verb. This is durable-before-acknowledged in
/// the type system: no witness ⇒ no ``MeshCustodyReceipt`` ⇒ the forbidden order is unwritable,
/// here and in items 4, 6 and 8.
///
/// A value, not a handle: it carries what a receipt needs and nothing that could go stale.
nonisolated struct MeshCustodyDurabilityWitness: Equatable, Sendable {
    /// The item's author — the receipt's subject.
    let originFingerprint: String
    /// The routed item.
    let itemID: UUID
    /// The whole item's content hash, as re-measured over the durable bytes on this pass.
    let contentHash: Data
    /// This device — the receipt's signer.
    let custodianFingerprint: String
    /// The instant the index write that FIRST recorded durable custody returned, floored — read back
    /// from the stored record, not the instant of this pass.
    ///
    /// A re-commit re-verifies the bytes and re-uses this stored value, so two receipts for one
    /// durable fact are byte-identical up to the hedged signature. "The instant the write returned"
    /// is undetermined on a re-mint (no write happens), and leaving a **signed wire field** to depend
    /// on which reading an implementer picked is how a golden stops being reproducible.
    let custodiedAt: Date

    /// The one construction site's initialiser. `fileprivate` on purpose — see the type's
    /// documentation.
    fileprivate init(
        originFingerprint: String,
        itemID: UUID,
        contentHash: Data,
        custodianFingerprint: String,
        custodiedAt: Date
    ) {
        self.originFingerprint = originFingerprint
        self.itemID = itemID
        self.contentHash = contentHash
        self.custodianFingerprint = custodianFingerprint
        self.custodiedAt = custodiedAt
    }
}

// MARK: - MeshRoutedStreamResult

/// What streaming one item's durable chunk files produced.
///
/// The three failure answers are kept apart for the reason plan §19.5 exists: a missing or
/// unauthentic file makes the item **incomplete** and repairs the index, while a file that could not
/// be read *right now* repairs nothing at all.
private nonisolated enum MeshRoutedStreamResult {
    /// Every slot opened and matched. The item's durable byte count and content hash.
    case measured(bytes: UInt64, contentHash: Data)
    /// A slot's bytes are gone or are not that slot's. The index was repaired.
    case incomplete(received: Int, expected: Int)
    /// A slot's bytes did not match the descriptor holding it. The index was repaired and nothing
    /// was emitted.
    case refused(MeshRoutedStoreRefusal)
    /// The store could not be read or written right now. **Nothing was repaired.**
    case unavailable(MeshRoutedUnavailability)
}

// MARK: - MeshRoutedStampResult

/// What writing the durable custody instant produced.
///
/// Two cases, not an optional `Date`: the failure carries the store's OWN classification, so a
/// refused seal, a deferral and a write that failed stay three different answers here exactly as
/// they do at every other writer door (plan §19.5). A `Date?` collapsed all three into one, which
/// is the distinction the whole item exists to preserve.
private nonisolated enum MeshRoutedStampResult {
    /// The instant now stored on the record — this pass's write, or the one an earlier commit made.
    case stamped(Date)
    /// Nothing was stamped, for the named reason. No witness may exist.
    case unavailable(MeshRoutedUnavailability)
}

// MARK: - The commit

nonisolated extension MeshRoutedStore {

    /// Verifies that this device durably holds the COMPLETE ciphertext of `item`, and mints the one
    /// witness a ``MeshCustodyReceipt`` needs.
    ///
    /// Always streams every chunk file in index order, compares each opened chunk against the
    /// descriptor holding its slot, and gates on `manifest.size` then `manifest.contentHash` —
    /// exactly the checks `MeshChunkAssembly.completion(against:)` performs over in-memory bytes,
    /// re-expressed over durable ones. On the FIRST success it writes `custodiedAt`; on a later call
    /// it re-runs the whole verification and re-uses the **stored** instant, so a re-mint's canonical
    /// bytes are byte-identical.
    ///
    /// An item whose chunk file was removed or swapped since the first commit answers `incomplete`
    /// (or the named refusal), mints no witness, and has its `custodiedAt` cleared. A failed index
    /// write mints no witness either: nothing is acknowledged for state a restart would lose.
    ///
    /// - Parameters:
    ///   - item: The signed pair.
    ///   - custodian: This device's fingerprint. The mint re-checks it against the signing identity.
    ///   - now: The injected instant — the value stamped as `custodiedAt` on a first commit.
    /// - Returns: the witness, the incompleteness, or a named refusal; or the store's unavailability.
    func committingCustody(
        item: MeshRoutedItemKey,
        custodian: String,
        now: Date
    ) -> MeshRoutedOutcome<MeshRoutedCustodyOutcome> {
        var index: MeshRoutedIndex
        let token: LoadToken
        switch indexForWriting() {
        case .unavailable(let cause): return .unavailable(cause)
        case .writable(let loaded, let vended): index = loaded; token = vended
        }
        guard let record = index.record(for: item) else { return .refused(.unknownItem) }
        guard let manifest = record.manifest else { return .completed(.refused(.notBound)) }
        guard record.isLive(at: now) else { return .refused(.itemExpired) }
        guard record.isComplete else {
            return .completed(.incomplete(received: record.receivedCount, expected: Int(record.chunkCount)))
        }
        let contentKey: SymmetricKey
        switch openKey() {
        case .available(let key): contentKey = key
        case .deferred(let reason):
            return .unavailable(.deferred(MeshRoutedDeferral(reason: reason, detail: Self.chunkDirectoryName)))
        case .refused(let cause):
            return .unavailable(.refused(MeshRoutedSealRefusal(operation: .open, cause: cause)))
        }
        return committed(record, manifest: manifest, custodian: custodian, now: now,
                         index: &index, token: token, contentKey: contentKey)
    }

    /// The measuring half of ``committingCustody(item:custodian:now:)``: stream, gate on size then
    /// content hash, stamp `custodiedAt` once, and only then mint the witness.
    private func committed(
        _ record: MeshRoutedItemRecord,
        manifest: MeshRoutedManifest,
        custodian: String,
        now: Date,
        index: inout MeshRoutedIndex,
        token: LoadToken,
        contentKey: SymmetricKey
    ) -> MeshRoutedOutcome<MeshRoutedCustodyOutcome> {
        let measured: (bytes: UInt64, contentHash: Data)
        switch streamedContentHash(of: record, in: &index, token: token, contentKey: contentKey) {
        case .measured(let bytes, let hash): measured = (bytes, hash)
        case .incomplete(let received, let expected):
            return .completed(.incomplete(received: received, expected: expected))
        case .refused(let refusal): return .refused(refusal)
        case .unavailable(let cause): return .unavailable(cause)
        }
        guard measured.bytes == manifest.size else { return .completed(.refused(.sizeMismatch)) }
        guard measured.contentHash == manifest.contentHash else {
            return .completed(.refused(.contentHashMismatch))
        }
        let custodiedAt: Date
        switch stampedCustodyInstant(record, now: now, index: &index, token: token) {
        case .stamped(let stamped): custodiedAt = stamped
        case .unavailable(let cause): return .unavailable(cause)
        }
        return .completed(
            .committed(
                witness(for: record, custodian: custodian, contentHash: measured.contentHash,
                        custodiedAt: custodiedAt)
            )
        )
    }

    /// The stored custody instant, writing it on the FIRST successful commit and re-using it on
    /// every later one.
    ///
    /// A failed write answers with the store's OWN classification
    /// (``MeshRoutedStore/unavailability(from:)``), never a flattened "not written": a refused seal
    /// is not an absent file, and a deferral is not a silent retry (plan §19.5). Losing that
    /// distinction here would make this the one writer in the store that erases it. No witness
    /// exists on any failure — that half is what plan §3.6 requires.
    private func stampedCustodyInstant(
        _ record: MeshRoutedItemRecord,
        now: Date,
        index: inout MeshRoutedIndex,
        token: LoadToken
    ) -> MeshRoutedStampResult {
        if let stored = record.custodiedAt { return .stamped(stored) }
        let stamped = MeshRoutedManifest.floored(now)
        var updated = record
        updated.custodiedAt = stamped
        index.upsert(updated)
        do {
            try save(index, token: token)
        } catch {
            let cause = unavailability(from: error)
            FernletAuditLog.log(
                "mesh.routedStore.custodyNotWritten",
                context: ["cause": cause.logToken, "error": String(describing: error)]
            )
            return .unavailable(cause)
        }
        return .stamped(stamped)
    }

    /// The one place a ``MeshCustodyDurabilityWitness`` is constructed, in the file that alone can
    /// reach its `fileprivate` initialiser.
    private func witness(
        for record: MeshRoutedItemRecord,
        custodian: String,
        contentHash: Data,
        custodiedAt: Date
    ) -> MeshCustodyDurabilityWitness {
        MeshCustodyDurabilityWitness(
            originFingerprint: record.key.originFingerprint,
            itemID: record.key.itemID,
            contentHash: contentHash,
            custodianFingerprint: custodian,
            custodiedAt: custodiedAt
        )
    }

    /// Streams every chunk file in index order through ``MeshRoutedContentHasher``, one file resident
    /// at a time, comparing each opened chunk against the descriptor holding its slot.
    ///
    /// A missing or unauthentic file takes the repair branch — the descriptor is dropped,
    /// `custodiedAt` is cleared and the file removed — because the index is authoritative over what
    /// we have and bytes we cannot authenticate are bytes we do not have. A file that could not be
    /// READ, or a custody state that refuses, repairs **nothing**.
    private func streamedContentHash(
        of record: MeshRoutedItemRecord,
        in index: inout MeshRoutedIndex,
        token: LoadToken,
        contentKey: SymmetricKey
    ) -> MeshRoutedStreamResult {
        var hasher = MeshRoutedContentHasher()
        var bytes: UInt64 = 0
        // R2: bounded by `maxChunksPerItem`.
        for slot in 0..<Int(record.chunkCount) {
            guard let stored = record.chunk(at: UInt32(slot)) else {
                return .incomplete(received: record.receivedCount, expected: Int(record.chunkCount))
            }
            switch readChunkFile(expecting: stored, contentKey: contentKey) {
            case .chunk(let chunk):
                hasher.update(chunk.payload)
                bytes += UInt64(chunk.payload.count)
            case .unavailable(let cause):
                return .unavailable(cause)
            case .missing:
                return repaired(record.key, dropping: stored, in: &index, token: token, refusing: nil)
            case .unauthentic:
                return repaired(record.key, dropping: stored, in: &index, token: token,
                                refusing: .chunkFileMismatch)
            }
        }
        return .measured(bytes: bytes, contentHash: hasher.finalized())
    }

    // MARK: - The reassembly read (P5 item 13)

    /// The complete ciphertext blob of `item`, or nil when this device cannot stand behind it.
    ///
    /// The one read door that returns a whole item, added for P5 item 13's delivery projection.
    /// ``forwardableChunk(item:index:)``'s doc says there is deliberately no such API and that a
    /// caller iterates the held indices — which is right for the FORWARD path, where one chunk is
    /// resident at a time and each is sent as it is read. It is the wrong shape for an open: that
    /// spelling costs an `indexForWriting()` and an `openKey()` **per chunk**, so a maximal item
    /// would be 1024 sealed-index loads on the main actor before a single byte was decrypted.
    ///
    /// This is a **ciphertext** door like every other one here: custody is never gated on the
    /// access gate, nothing about a lock is consulted, and the caller has already bounded
    /// `manifest.size` before it asks — residency is bounded before the first byte is read. The
    /// blob is returned **only** when the re-measured digest equals the manifest's, so a caller can
    /// never open bytes this store cannot re-authenticate.
    ///
    /// - Parameters:
    ///   - item: The signed pair.
    ///   - manifest: The origin's manifest, whose `size` and `contentHash` the bytes must meet.
    /// - Returns: the blob, `nil` when the item is incomplete or does not measure up, or the
    ///   store's unavailability.
    func assembledBlob(
        item: MeshRoutedItemKey,
        expecting manifest: MeshRoutedManifest
    ) -> MeshRoutedOutcome<Data?> {
        var index: MeshRoutedIndex
        let token: LoadToken
        switch indexForWriting() {
        case .unavailable(let cause): return .unavailable(cause)
        case .writable(let loaded, let vended): index = loaded; token = vended
        }
        guard let record = index.record(for: item) else { return .refused(.unknownItem) }
        guard record.manifest == manifest, record.isComplete else { return .completed(nil) }
        let contentKey: SymmetricKey
        switch openKey() {
        case .available(let key): contentKey = key
        case .deferred(let reason):
            return .unavailable(.deferred(MeshRoutedDeferral(reason: reason, detail: Self.chunkDirectoryName)))
        case .refused(let cause):
            return .unavailable(.refused(MeshRoutedSealRefusal(operation: .open, cause: cause)))
        }
        return assembled(record, manifest: manifest, index: &index, token: token, contentKey: contentKey)
    }

    /// The streaming half of ``assembledBlob(item:expecting:)``: read every slot in index order,
    /// hash while concatenating, and hand back the bytes only if they measure up.
    ///
    /// The repair branch is ``streamedContentHash(of:in:token:contentKey:)``'s, verbatim: a missing
    /// or unauthentic file drops the descriptor and clears `custodiedAt`, because the index is
    /// authoritative over what this device has and bytes it cannot authenticate are bytes it does
    /// not have.
    private func assembled(
        _ record: MeshRoutedItemRecord,
        manifest: MeshRoutedManifest,
        index: inout MeshRoutedIndex,
        token: LoadToken,
        contentKey: SymmetricKey
    ) -> MeshRoutedOutcome<Data?> {
        var hasher = MeshRoutedContentHasher()
        var blob = Data()
        // R2: bounded by `maxChunksPerItem`.
        for slot in 0..<Int(record.chunkCount) {
            guard let stored = record.chunk(at: UInt32(slot)) else { return .completed(nil) }
            switch readChunkFile(expecting: stored, contentKey: contentKey) {
            case .chunk(let chunk):
                hasher.update(chunk.payload)
                blob.append(chunk.payload)
            case .unavailable(let cause):
                return .unavailable(cause)
            case .missing:
                return repairedBlob(record.key, dropping: stored, in: &index, token: token, refusing: nil)
            case .unauthentic:
                return repairedBlob(record.key, dropping: stored, in: &index, token: token,
                                    refusing: .chunkFileMismatch)
            }
        }
        guard UInt64(blob.count) == manifest.size else { return .completed(nil) }
        guard hasher.finalized() == manifest.contentHash else { return .completed(nil) }
        return .completed(blob)
    }

    /// ``repaired(_:dropping:in:token:refusing:)`` in the blob door's own answer shape: nothing is
    /// returned once a descriptor has been dropped, because the item is no longer complete.
    private func repairedBlob(
        _ key: MeshRoutedItemKey,
        dropping stored: MeshRoutedChunkDescriptor,
        in index: inout MeshRoutedIndex,
        token: LoadToken,
        refusing refusal: MeshRoutedStoreRefusal?
    ) -> MeshRoutedOutcome<Data?> {
        if let cause = repairing(key, dropping: stored, in: &index, token: token) {
            return .unavailable(cause)
        }
        if let refusal { return .refused(refusal) }
        return .completed(nil)
    }

    /// Applies the repair and reports what the commit should answer once it has been written.
    private func repaired(
        _ key: MeshRoutedItemKey,
        dropping stored: MeshRoutedChunkDescriptor,
        in index: inout MeshRoutedIndex,
        token: LoadToken,
        refusing refusal: MeshRoutedStoreRefusal?
    ) -> MeshRoutedStreamResult {
        if let cause = repairing(key, dropping: stored, in: &index, token: token) {
            return .unavailable(cause)
        }
        if let refusal { return .refused(refusal) }
        let repairedRecord = index.record(for: key)
        return .incomplete(
            received: repairedRecord?.receivedCount ?? 0,
            expected: Int(repairedRecord?.chunkCount ?? 0)
        )
    }
}
