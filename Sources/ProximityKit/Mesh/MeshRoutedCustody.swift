// MeshRoutedCustody.swift
// ProximityKit/Mesh
//
// Network migration P5 item 3 (plan §11): the custody VERBS — the calls items 4, 6, 8, 9, 10 and 11
// make on the routed store, each returning exactly one named outcome.
//
// The floor (`load` / `save` / `quarantineCorruptIndex` / `wipeForDeleteAll`) is
// `MeshRoutedStore.swift`'s. These verbs are a thin layer on top of it, and they are thin on
// purpose: a verb cannot bypass the floor, because `MeshRoutedStore.LoadToken`'s initialiser is
// `fileprivate` to *that* file, so every verb here obtains its write token from `load()` like any
// other caller. That is the type-level form of "a save is reachable only from `loaded`/`absent`".
//
// `committingCustody` is deliberately NOT here. It lives alone with
// `MeshCustodyDurabilityWitness` in `MeshRoutedCustodyCommit.swift`, because `fileprivate` is FILE
// scope: keeping the witness and its one minting verb in a file that holds nothing else makes that
// verb the only possible construction site, while leaving `LoadToken`'s mint unreachable from it.
// Two `fileprivate` gates, two files, neither able to open the other's door.
//
// Three channels, no fourth, and nothing silent: `completed`, `refused` (the store door said no, by
// name), `unavailable` (one of the three writer-less states, or the write itself failed). Every
// entry point has a defined answer for each of the three writer-less states, and none of them is
// "there is nothing here".

import CryptoKit
import Foundation
import FernletFoundation

// MARK: - MeshRoutedRetryBounds

/// How many times a caller may retry a routed-store attempt that answered
/// ``MeshRoutedUnavailability/isRetryable``.
nonisolated enum MeshRoutedRetryBounds {
    /// **Reused, never restated** — P3 already chose this number for the same question, and two
    /// spellings of "three attempts" is how two retry policies drift.
    static let maxAttempts = MeshSessionRestoreBounds.maxAttempts
}

// MARK: - MeshRoutedUnavailability

/// Why a routed-store verb could not complete for reasons that are not a refusal of the *request*.
///
/// Three of the four are the writer-less load states; the fourth is a write that failed with the
/// previous index intact. None of them means "there is nothing here".
nonisolated enum MeshRoutedUnavailability: Equatable, Sendable {
    /// Ask again; NOTHING is known and nothing was written.
    case deferred(MeshRoutedDeferral)
    /// The index is present and undecodable. Quarantine it deliberately before writing.
    case corrupt(MeshRoutedCorruption)
    /// Custody refuses; **the field may be FULL**. Never read as an empty store.
    case refused(MeshRoutedSealRefusal)
    /// The write itself failed. The previous index is byte-identical and nothing was acknowledged.
    case notWritten(String)

    /// A frozen English log token — `"deferred:fileUnreadable"`, `"refused:installBindingUnavailable"`,
    /// `"corrupt:emptyFile"`, `"notWritten"`. Logged verbatim, never localized, never user copy.
    var logToken: String {
        switch self {
        case .deferred(let deferral): return "deferred:\(deferral.reason.rawValue)"
        case .corrupt(let corruption): return "corrupt:\(String(describing: corruption.detail))"
        case .refused(let refusal): return "refused:\(refusal.cause.rawValue)"
        case .notWritten: return "notWritten"
        }
    }

    /// Whether the caller may come back. `true` for ``deferred(_:)``, ``notWritten(_:)`` **and
    /// ``refused(_:)``**; `false` only for ``corrupt(_:)``, which needs a deliberate quarantine
    /// first.
    ///
    /// A DERIVED accessor, never a stored flag, and the same answer
    /// `MeshSessionRestoreOutcome.isRetryable` gives for its own `.retryAfterRefusal` — one contract
    /// behind two same-named accessors. Bounded by ``MeshRoutedRetryBounds/maxAttempts`` at the
    /// caller (item 6's drain), because nothing here loops.
    ///
    /// "Retryable" and "will eventually succeed" are not the same claim. Per cause:
    ///
    /// | ``MeshRoutedSealRefusal/Cause`` | retried because | when it stops refusing |
    /// | --- | --- | --- |
    /// | `installBindingUnavailable` | the D4 pre-first-unlock window this item is about; the field may well be full | at first unlock, on its own |
    /// | `sealKeyNotPersisted` | the mint's read-back failed once; the next attempt mints again | on the next successful mint |
    /// | `sealKeyMalformed` | only so the bounded attempt count is spent uniformly and the refusal is logged each time | not without an operator-visible repair |
    /// | `sealKeyMissingForSealedFile` | same | not on its own; the bytes are unopenable and deleting them is a decision |
    /// | `retiredAtRestFormat` | same | not on its own |
    ///
    /// Retrying the last three costs three bounded log lines and buys one thing that matters: a
    /// caller cannot tell them apart from the first two *without* reading `cause`, so a caller that
    /// branched on `isRetryable` alone would silently stop retrying the pre-first-unlock case — the
    /// only one that matters at this seam.
    var isRetryable: Bool {
        switch self {
        case .deferred, .refused, .notWritten: return true
        case .corrupt: return false
        }
    }
}

// MARK: - MeshRoutedStoreRefusal

/// Why a routed-store door said no to the request itself. Frozen English tokens, logged verbatim,
/// never localized — item 9 owns the user-visible backpressure failure, and item 3 ships zero
/// display text.
nonisolated enum MeshRoutedStoreRefusal: String, CaseIterable, Equatable, Sendable {
    /// The store already holds ``MeshRoutedStoreFormat/maxItems`` logical items, parked ones included.
    case capacityItems
    /// Admitting this would take the held CONTENT bytes past ``MeshRoutedStoreFormat/maxContentBytes``.
    case capacityBytes
    /// Admitting this would take the held payload FILES past
    /// ``MeshRoutedStoreFormat/maxHeldChunkFiles``. Checked against the directory as well as the
    /// index, because an orphan is on disk and not in the index.
    case capacityChunkFiles
    /// This item already holds ``MeshRoutedStoreFormat/maxChunksPerItem`` chunks.
    case capacityChunksPerItem
    /// The item id is already held under a DIFFERENT origin — the door D11's signed pair names.
    case duplicateItemID
    /// A second, different manifest for the same `(origin, item)` pair, or a manifest whose identity
    /// triple is not the held set's.
    case manifestMismatch
    /// No record for that key.
    case unknownItem
    /// The item's expiry has passed at the injected instant.
    case itemExpired
    /// The manifest's derived chunk count is not the held set's — the binding rule's `countMismatch`.
    case chunkCountMismatch
    /// An already-held chunk is the wrong length for the manifest's size — the binding rule's
    /// `payloadLengthMismatch`. Refused **without mutating** the parked set.
    case heldChunkLengthMismatch
    /// A named destination the item's signed manifest does not name.
    case notADestination
    /// An opened chunk file does not match the descriptor holding its slot. The bytes were not
    /// emitted, and the index was repaired.
    case chunkFileMismatch
    /// The item's evidence set already holds ``MeshRoutedStoreFormat/maxReceiptsPerItem`` receipts.
    case capacityReceipts
    /// The item's RECIPIENT-receipt evidence set already holds
    /// ``MeshRoutedStoreFormat/maxReceiptsPerItem`` receipts (P5 item 4). Its own token beside
    /// ``capacityReceipts``: two evidence arrays with two signer roles want two log tokens.
    case capacityRecipientReceipts
    /// The item's origin-signed type token is one the caller's stage table does not know (P5 item
    /// 4). Plan §11's "unknown type tokens are rejected, not forwarded", answered at the ack seam:
    /// nothing is acknowledged and nothing is written.
    case unknownTypeToken

    /// Frozen English for the diagnostic surface. Never shown as user copy.
    var diagnosticDescription: String {
        switch self {
        case .capacityItems: return "The routed store is holding its maximum number of items."
        case .capacityBytes: return "The routed store is holding its maximum content byte count."
        case .capacityChunkFiles: return "The routed store is holding its maximum number of chunk files."
        case .capacityChunksPerItem: return "The item is holding its maximum number of chunks."
        case .duplicateItemID: return "The item id is already held under a different origin."
        case .manifestMismatch: return "The manifest is not this held item's."
        case .unknownItem: return "The routed store holds no such item."
        case .itemExpired: return "The item's expiry has passed."
        case .chunkCountMismatch: return "The manifest's chunk count disagrees with the held set's."
        case .heldChunkLengthMismatch: return "A held chunk is the wrong length for the manifest's size."
        case .notADestination: return "The named destination is not in the item's signed manifest."
        case .chunkFileMismatch: return "A stored chunk file does not match the descriptor holding its slot."
        case .capacityReceipts: return "The item's custody-receipt evidence set is full."
        case .capacityRecipientReceipts: return "The item's recipient-receipt evidence set is full."
        case .unknownTypeToken: return "The item's type token is not one this build's stage table knows."
        }
    }
}

// MARK: - MeshRoutedOutcome

/// The one outcome channel every routed-store verb returns.
///
/// Three answers, no fourth: the verb completed, the door refused it **by name**, or the store was
/// unavailable in one of the four ways above. Deterministic given (inputs, injected `now`), which is
/// the shape item 14's property battery needs — one call per schedule event.
nonisolated enum MeshRoutedOutcome<Value: Equatable & Sendable>: Equatable, Sendable {
    /// The verb ran; the associated value is what it produced.
    case completed(Value)
    /// The store door refused the request, by name. Nothing was written.
    case refused(MeshRoutedStoreRefusal)
    /// The store could not be read or written right now. Nothing was written and nothing is known.
    case unavailable(MeshRoutedUnavailability)

    /// The produced value, or nil when the verb refused or the store was unavailable.
    var value: Value? {
        if case .completed(let value) = self { return value }
        return nil
    }

    /// The named refusal, or nil.
    var refusal: MeshRoutedStoreRefusal? {
        if case .refused(let refusal) = self { return refusal }
        return nil
    }

    /// The unavailability, or nil.
    var unavailability: MeshRoutedUnavailability? {
        if case .unavailable(let cause) = self { return cause }
        return nil
    }
}

// MARK: - MeshRoutedManifestAdmission

/// What ``MeshRoutedStore/admittingManifest(_:now:)`` did with one manifest.
nonisolated struct MeshRoutedManifestAdmission: Equatable, Sendable {
    /// The item's signed pair.
    let key: MeshRoutedItemKey
    /// Whether the store had no record for this key at all before the call.
    let isNew: Bool
    /// Whether the manifest BOUND an already-parked chunk set — the manifest-last case, which is
    /// normal rather than an attack.
    let boundAParkedSet: Bool
    /// How many chunk indices are held.
    let receivedCount: Int
    /// How many the item has.
    let expectedCount: Int
}

// MARK: - MeshRoutedCustodyOutcome

/// What ``MeshRoutedStore/committingCustody(item:custodian:now:)`` found. The durable twin of
/// `MeshChunkCompletion`, value for value — where the in-memory form returns a blob, this returns
/// proof that a durable write happened.
nonisolated enum MeshRoutedCustodyOutcome: Equatable, Sendable {
    /// Every chunk file opened, matched its slot, and the whole item's size and content hash agree.
    /// The witness is the **only** thing that can mint a ``MeshCustodyReceipt``.
    case committed(MeshCustodyDurabilityWitness)
    /// Some index is missing — including one whose file has gone since the last commit. No witness.
    case incomplete(received: Int, expected: Int)
    /// The commit was refused, by name — the same tokens the in-memory completion uses, including
    /// `notBound` for a parked item.
    case refused(MeshChunkRefusal)
}

// MARK: - MeshRoutedCustodyEvidence

/// What ``MeshRoutedStore/recordingCustodyEvidence(item:receipt:now:)`` stored.
///
/// Deliberately **not** a `MeshDeliveryOutcome`: an evidence write moves no delivery rung, so
/// returning the delivery vocabulary would invite a caller to read a rung out of it. What it does
/// carry is enough for a log line and for a drain to know whether anything changed.
nonisolated struct MeshRoutedCustodyEvidence: Equatable, Sendable {
    /// The item the receipt is about.
    let key: MeshRoutedItemKey
    /// The receipt's signer.
    let custodian: String
    /// Whether this custodian had no stored receipt before. `false` means replace-by-signer, which
    /// is what makes a re-forwarded receipt grow nothing.
    let isNew: Bool

    /// Records one evidence write.
    init(key: MeshRoutedItemKey, custodian: String, isNew: Bool) {
        self.key = key
        self.custodian = custodian
        self.isNew = isNew
    }
}

// MARK: - MeshRoutedSweepReport

/// What one bounded sweep removed.
nonisolated struct MeshRoutedSweepReport: Equatable, Sendable {
    /// How many item records were removed.
    let itemsRemoved: Int
    /// How many sealed payload files were removed.
    let chunkFilesRemoved: Int
    /// How many payload files could not be removed. Audited, never swallowed.
    let chunkFilesFailed: Int
    /// Whether the sweep stopped at its bound rather than finishing. A directory that got **over**
    /// the cap — which is exactly what orphans do — must be able to drain across repeated bounded
    /// calls instead of stalling half-swept, so the caller repeats while this is `true`.
    let sweptToCeiling: Bool
}

// MARK: - MeshRoutedIndexLoad

/// The loaded index plus its write token, or the writer-less state that says why there is none.
///
/// One translation of ``MeshRoutedLoad``'s five states into the two a verb can act on: `absent`
/// becomes an **empty index** with its token (a green field really is writable), and the other three
/// become ``MeshRoutedUnavailability``. Read-only verbs use it too and simply ignore the token —
/// which is deliberate, because a read must answer `deferred` rather than "nothing held" for exactly
/// the same reasons a write must.
nonisolated enum MeshRoutedIndexLoad: Sendable {
    /// An index is in hand and a write is authorised.
    case writable(MeshRoutedIndex, MeshRoutedStore.LoadToken)
    /// No writer, and no index: the named reason.
    case unavailable(MeshRoutedUnavailability)
}

// MARK: - MeshRoutedStagedFile

/// The result of sealing and writing one payload file, before the index that names it is saved.
nonisolated enum MeshRoutedStagedFile: Sendable {
    /// The file is on disk under this descriptor. The index does not name it yet.
    case written(MeshRoutedChunkDescriptor)
    /// Nothing was written, for the named reason.
    case unavailable(MeshRoutedUnavailability)
}

// MARK: - The verbs

nonisolated extension MeshRoutedStore {

    // MARK: Load translation

    /// ``MeshRoutedLoad``'s five states as the two a verb can act on.
    func indexForWriting() -> MeshRoutedIndexLoad {
        switch load() {
        case .loaded(let index, let token): return .writable(index, token)
        case .absent(let token): return .writable(MeshRoutedIndex(), token)
        case .deferred(let deferral): return .unavailable(.deferred(deferral))
        case .corrupt(let corruption): return .unavailable(.corrupt(corruption))
        case .refused(let refusal): return .unavailable(.refused(refusal))
        }
    }

    /// A thrown save error as the unavailability a verb reports. A refusal stays a refusal; a token
    /// from another store is a write that did not happen.
    func unavailability(from error: Error) -> MeshRoutedUnavailability {
        if let refusal = error as? MeshRoutedSealRefusal { return .refused(refusal) }
        guard let saveError = error as? MeshRoutedSaveError else {
            return .notWritten(String(describing: error))
        }
        switch saveError {
        case .tokenFromAnotherStore: return .notWritten("tokenFromAnotherStore")
        case .deferred(let deferral): return .deferred(deferral)
        case .notWritten(let detail): return .notWritten(detail)
        }
    }

    // MARK: Manifest admission

    /// Admits an origin-signed manifest, binding it onto an already-parked chunk set if one is held.
    ///
    /// - Important: `manifest` must be one `MeshRoutedManifestVerifier.verify(_:)` — including item
    ///   11's accepted type tokens — has already accepted. This verb re-checks nothing about the
    ///   signature and hard-codes no type policy.
    ///
    /// Binding goes through ``MeshChunkAdmissionRule/bindingVerdict(for:in:)``, the same function
    /// `MeshChunkAssembly.bind(to:)` calls, so a parked set the assembly would refuse is not admitted
    /// durably here and left to fail much later at the commit's hash gate.
    ///
    /// - Parameters:
    ///   - manifest: The verified manifest.
    ///   - now: The injected instant; nothing here reads a clock.
    /// - Returns: what the admission did, or the named refusal, or the store's unavailability.
    func admittingManifest(
        _ manifest: MeshRoutedManifest,
        now: Date
    ) -> MeshRoutedOutcome<MeshRoutedManifestAdmission> {
        var index: MeshRoutedIndex
        let token: LoadToken
        switch indexForWriting() {
        case .unavailable(let cause): return .unavailable(cause)
        case .writable(let loaded, let vended): index = loaded; token = vended
        }
        guard manifest.isLive(at: now) else { return .refused(.itemExpired) }
        let key = MeshRoutedItemKey(manifest)
        let existing = index.record(for: key)
        guard !index.holdsItemID(manifest.itemID, underAnotherOriginThan: manifest.originFingerprint) else {
            return .refused(.duplicateItemID)
        }
        if let refusal = admissionRefusal(manifest, existing: existing, in: index) {
            return .refused(refusal)
        }
        guard let derived = MeshChunkFormat.chunkCount(forSize: manifest.size) else {
            return .refused(.chunkCountMismatch)
        }
        let record = recordAdmitting(manifest, existing: existing, derivedCount: derived, now: now)
        index.upsert(record)
        do {
            try save(index, token: token)
        } catch {
            return .unavailable(unavailability(from: error))
        }
        return .completed(
            MeshRoutedManifestAdmission(
                key: key, isNew: existing == nil, boundAParkedSet: existing?.isParked == true,
                receivedCount: record.receivedCount, expectedCount: Int(record.chunkCount)
            )
        )
    }

    /// Everything ``admittingManifest(_:now:)`` refuses before it writes: the held item's own
    /// consistency, then the two capacity reservations.
    private func admissionRefusal(
        _ manifest: MeshRoutedManifest,
        existing: MeshRoutedItemRecord?,
        in index: MeshRoutedIndex
    ) -> MeshRoutedStoreRefusal? {
        if let held = existing?.manifest, held != manifest { return .manifestMismatch }
        if let existing, existing.manifest == nil {
            let binding = MeshChunkAdmissionRule.bindingVerdict(
                for: manifest, in: parkedShape(of: existing)
            )
            if case .refused(let refusal) = binding { return Self.storeRefusal(forBinding: refusal) }
        }
        return capacityRefusal(forManifest: manifest, existing: existing, in: index)
    }

    /// The binding rule's three refusals as this store's named ones (D-3.14's mapping table).
    private static func storeRefusal(forBinding refusal: MeshChunkRefusal) -> MeshRoutedStoreRefusal {
        switch refusal {
        case .countMismatch: return .chunkCountMismatch
        case .payloadLengthMismatch: return .heldChunkLengthMismatch
        default: return .manifestMismatch
        }
    }

    /// A parked record as the binding rule reads it. `held` is nil because a binding decision is
    /// about the SET, not about one incoming slot.
    private func parkedShape(of record: MeshRoutedItemRecord) -> MeshChunkSetShape {
        var lengths: [UInt32: Int] = [:]
        // R2: bounded by `maxChunksPerItem`.
        for chunk in record.chunks {
            lengths[chunk.descriptor.chunkIndex] = chunk.payloadByteCount
        }
        return MeshChunkSetShape(
            itemID: record.key.itemID, originFingerprint: record.key.originFingerprint,
            contentHash: record.contentHash, chunkCount: record.chunkCount, boundSize: nil,
            bytesHeld: record.contentBytesHeld, held: nil, heldPayloadLengths: lengths
        )
    }

    /// **Both** capacity reservations, symmetrically: an item that could never be completed is
    /// refused now rather than half-staged. The chunk count is known from `manifest.size`, so the
    /// file-slot budget can be reserved exactly as the byte budget is.
    private func capacityRefusal(
        forManifest manifest: MeshRoutedManifest,
        existing: MeshRoutedItemRecord?,
        in index: MeshRoutedIndex
    ) -> MeshRoutedStoreRefusal? {
        guard existing != nil || index.itemCount < capacity.maxItems else {
            return .capacityItems
        }
        guard let derived = MeshChunkFormat.chunkCount(forSize: manifest.size) else {
            return .chunkCountMismatch
        }
        let otherBytes = index.totalContentBytesHeld - (existing?.contentBytesHeld ?? 0)
        guard UInt64(otherBytes) + manifest.size <= capacity.maxContentBytes else {
            return .capacityBytes
        }
        let otherFiles = index.heldChunkFileCount - (existing?.chunks.count ?? 0)
        guard otherFiles + derived <= capacity.maxHeldChunkFiles else {
            return .capacityChunkFiles
        }
        return nil
    }

    /// The record the admission writes: a fresh one stamped with `firstSeenAt`, or the held one with
    /// its manifest and delivery map filled in. `firstSeenAt` is never moved by a later sighting.
    private func recordAdmitting(
        _ manifest: MeshRoutedManifest,
        existing: MeshRoutedItemRecord?,
        derivedCount: Int,
        now: Date
    ) -> MeshRoutedItemRecord {
        var record = existing ?? MeshRoutedItemRecord(
            key: MeshRoutedItemKey(manifest), contentHash: manifest.contentHash,
            chunkCount: UInt32(derivedCount), expiresAt: manifest.expiresAt, manifest: nil,
            firstSeenAt: now, custodiedAt: nil, deliveredAt: nil, chunks: [], delivery: nil,
            receipts: [], recipientReceipts: []
        )
        record.manifest = manifest
        if record.delivery == nil {
            record.delivery = MeshRoutedDeliveryRecord(contentID: manifest.itemID, progress: [:])
        }
        return record
    }

    // MARK: Chunk staging

    /// Stages one origin-signed chunk: seals it to its own payload file, **then** records it in the
    /// index.
    ///
    /// - Important: `chunk` must be one `MeshChunkVerifier.verify(_:)` has already accepted.
    ///
    /// File before index, never the reverse: if the index went first and the payload write failed,
    /// the index would claim bytes that are not there and the item would look more complete than it
    /// is. This way a failed index write leaves an orphan file — nothing claims it, the previous
    /// index is byte-identical — **and the writer that made it removes it**, so the store's own cap
    /// keeps counting what is actually on disk.
    ///
    /// - Parameters:
    ///   - chunk: The verified chunk.
    ///   - now: The injected instant.
    /// - Returns: the same `MeshChunkAdmission` the in-memory assembly would produce, or a store
    ///   refusal, or the store's unavailability.
    func stagingChunk(_ chunk: MeshChunk, now: Date) -> MeshRoutedOutcome<MeshChunkAdmission> {
        var index: MeshRoutedIndex
        let token: LoadToken
        switch indexForWriting() {
        case .unavailable(let cause): return .unavailable(cause)
        case .writable(let loaded, let vended): index = loaded; token = vended
        }
        guard chunk.isLive(at: now) else { return .refused(.itemExpired) }
        let key = MeshRoutedItemKey(chunk)
        let existing = index.record(for: key)
        guard existing != nil
                || !index.holdsItemID(chunk.itemID, underAnotherOriginThan: chunk.originFingerprint) else {
            return .refused(.duplicateItemID)
        }
        let verdict = MeshChunkAdmissionRule.verdict(
            for: chunk, payloadHash: MeshRoutedContentDigest.chunkHash(of: chunk.payload),
            in: stagingShape(for: chunk, existing: existing), receivedCount: existing?.receivedCount ?? 0
        )
        guard case .admitted = verdict else { return .completed(verdict) }
        guard let directoryNames = chunkDirectoryFileNames() else {
            return .unavailable(
                .deferred(MeshRoutedDeferral(reason: .fileUnreadable, detail: Self.chunkDirectoryName))
            )
        }
        if let refusal = capacityRefusal(
            forChunk: chunk, existing: existing, in: index, directoryFileCount: directoryNames.count
        ) {
            return .refused(refusal)
        }
        return stagedOutcome(chunk, key: key, existing: existing, verdict: verdict, index: index,
                             token: token, now: now)
    }

    /// The write half of ``stagingChunk(_:now:)``: seal the file, add the descriptor, save the index,
    /// and on a failed save remove the file this call just wrote.
    private func stagedOutcome(
        _ chunk: MeshChunk,
        key: MeshRoutedItemKey,
        existing: MeshRoutedItemRecord?,
        verdict: MeshChunkAdmission,
        index: MeshRoutedIndex,
        token: LoadToken,
        now: Date
    ) -> MeshRoutedOutcome<MeshChunkAdmission> {
        let descriptor: MeshRoutedChunkDescriptor
        switch stagedFile(for: chunk) {
        case .unavailable(let cause): return .unavailable(cause)
        case .written(let written): descriptor = written
        }
        var updated = index
        updated.upsert(recordStaging(chunk, key: key, existing: existing, descriptor: descriptor, now: now))
        do {
            try save(updated, token: token)
        } catch {
            removingOrphanedChunkFile(named: descriptor.fileName)
            return .unavailable(unavailability(from: error))
        }
        return .completed(verdict)
    }

    /// Seals `chunk` — the WHOLE origin-signed object, so a custodian can re-emit it verbatim — into
    /// a fresh opaque file.
    private func stagedFile(for chunk: MeshChunk) -> MeshRoutedStagedFile {
        let name = Self.newChunkFileName()
        do {
            let contentKey = try sealKey()
            let sealed = try sealBytes(chunk, contentKey: contentKey)
            try writeAtomically(sealed, to: chunkFileURL(named: name))
        } catch {
            return .unavailable(unavailability(from: error))
        }
        return .written(
            MeshRoutedChunkDescriptor(
                descriptor: MeshChunkDescriptor(chunk),
                payloadByteCount: chunk.payload.count,
                fileName: name
            )
        )
    }

    /// Best-effort removal of a payload file this call wrote and then could not name in the index.
    /// Audited either way — cheaper and more honest than deferring unaccounted ciphertext to a sweep
    /// item 3 ships no poller for, especially as a caller's retry would write a second copy.
    private func removingOrphanedChunkFile(named name: String) {
        let removed = removeChunkFile(named: name)
        FernletAuditLog.log(
            removed ? "mesh.routedStore.orphanRemoved" : "mesh.routedStore.orphanRemovalFailed",
            context: ["file": name]
        )
    }

    /// The held set as the per-chunk rule reads it, for a held item or for a brand-new one.
    private func stagingShape(
        for chunk: MeshChunk,
        existing: MeshRoutedItemRecord?
    ) -> MeshChunkSetShape {
        guard let existing else {
            return MeshChunkSetShape(
                itemID: chunk.itemID, originFingerprint: chunk.originFingerprint,
                contentHash: chunk.contentHash, chunkCount: chunk.chunkCount, boundSize: nil,
                bytesHeld: 0, held: nil, heldPayloadLengths: [:]
            )
        }
        var lengths: [UInt32: Int] = [:]
        // R2: bounded by `maxChunksPerItem`.
        for held in existing.chunks { lengths[held.descriptor.chunkIndex] = held.payloadByteCount }
        return MeshChunkSetShape(
            itemID: existing.key.itemID, originFingerprint: existing.key.originFingerprint,
            contentHash: existing.contentHash, chunkCount: existing.chunkCount,
            boundSize: existing.manifest?.size, bytesHeld: existing.contentBytesHeld,
            held: existing.chunk(at: chunk.chunkIndex)?.descriptor, heldPayloadLengths: lengths
        )
    }

    /// The store's caps at the chunk door. The FILE cap is applied to `max(index, directory)` so an
    /// orphan cannot hide from the one cap that bounds it.
    private func capacityRefusal(
        forChunk chunk: MeshChunk,
        existing: MeshRoutedItemRecord?,
        in index: MeshRoutedIndex,
        directoryFileCount: Int
    ) -> MeshRoutedStoreRefusal? {
        guard existing != nil || index.itemCount < capacity.maxItems else {
            return .capacityItems
        }
        guard (existing?.chunks.count ?? 0) < capacity.maxChunksPerItem else {
            return .capacityChunksPerItem
        }
        let bytes = index.totalContentBytesHeld + chunk.payload.count
        guard UInt64(bytes) <= capacity.maxContentBytes else { return .capacityBytes }
        let files = max(index.heldChunkFileCount, directoryFileCount)
        guard files < capacity.maxHeldChunkFiles else { return .capacityChunkFiles }
        return nil
    }

    /// The record the staging writes: a fresh parked one stamped with `firstSeenAt`, or the held one
    /// with the new descriptor inserted in index order.
    private func recordStaging(
        _ chunk: MeshChunk,
        key: MeshRoutedItemKey,
        existing: MeshRoutedItemRecord?,
        descriptor: MeshRoutedChunkDescriptor,
        now: Date
    ) -> MeshRoutedItemRecord {
        var record = existing ?? MeshRoutedItemRecord(
            key: key, contentHash: chunk.contentHash, chunkCount: chunk.chunkCount,
            expiresAt: chunk.expiresAt, manifest: nil, firstSeenAt: now, custodiedAt: nil,
            deliveredAt: nil, chunks: [], delivery: nil, receipts: [], recipientReceipts: []
        )
        record.chunks.append(descriptor)
        record.chunks.sort { $0.descriptor.chunkIndex < $1.descriptor.chunkIndex }
        return record
    }

    // MARK: Custody transfer (item 8's writer)

    /// Records that `receipt`'s custodian is now holding this item's ciphertext for the named
    /// destinations, storing the receipt as the evidence in the **same index write**.
    ///
    /// There is no `to custodian:` parameter: the custodian **is** the signer, so the durable state
    /// and the signature cannot disagree. Which destinations that custodian is now the courier for is
    /// the CALLER's statement, not the receipt's — a receipt carries no destination set on purpose,
    /// and a receipt from a custodian that is not itself a destination is normal and is recorded.
    ///
    /// - Important: `receipt` must be one `MeshCustodyReceiptVerifier.verify(_:)` has already
    ///   accepted (returned nil).
    ///
    /// - Parameters:
    ///   - item: The signed pair.
    ///   - destinations: The destinations this custodian is taking on. Every one must be in the
    ///     item's signed manifest.
    ///   - receipt: The custodian's signed statement.
    ///   - now: The injected instant.
    /// - Returns: the advanced delivery target, or a delivery-level refusal, or a store refusal.
    ///   **Nothing is written on any refusal.**
    func recordingCustodyTransfer(
        item: MeshRoutedItemKey,
        for destinations: [String],
        receipt: MeshCustodyReceipt,
        now: Date
    ) -> MeshRoutedOutcome<MeshDeliveryOutcome> {
        var index: MeshRoutedIndex
        let token: LoadToken
        switch indexForWriting() {
        case .unavailable(let cause): return .unavailable(cause)
        case .writable(let loaded, let vended): index = loaded; token = vended
        }
        guard var record = index.record(for: item) else { return .refused(.unknownItem) }
        guard let manifest = record.manifest else { return .refused(.manifestMismatch) }
        if let refusal = receiptRefusal(receipt, against: record, manifest: manifest,
                                        destinations: destinations) {
            return .refused(refusal)
        }
        guard let target = record.deliveryTarget else {
            return .unavailable(.corrupt(MeshRoutedCorruption(detail: .undecodableJSON("deliveryRestore"))))
        }
        let advanced = advancingAll(destinations, to: receipt.custodianFingerprint, in: target)
        guard let updatedTarget = advanced.target else { return .completed(advanced) }
        record.delivery = MeshRoutedDeliveryRecord(encoding: updatedTarget)
        record.receipts = Self.storing(receipt, in: record.receipts)
        index.upsert(record)
        do {
            try save(index, token: token)
        } catch {
            return .unavailable(unavailability(from: error))
        }
        return .completed(advanced)
    }

    /// The four identity equalities plus the destination-set and evidence-capacity guards, in the
    /// transfer door's order: identity → destinations → capacity.
    ///
    /// Split into ``identityRefusal(_:against:manifest:)`` and
    /// ``capacityRefusal(forCustodyReceipt:against:)`` in P5 item 6 so the evidence-only door
    /// (``recordingCustodyEvidence(item:receipt:now:)``) applies **the same two** checks in **the
    /// same order**, minus the destination clause it has no honest value for. Behaviour here is
    /// unchanged, which `recordingCustodyTransferIsUnchanged` pins.
    ///
    /// Internal since P5 item 8 so the batch hand-off door applies the identical rule; the rule has
    /// exactly one implementation.
    func receiptRefusal(
        _ receipt: MeshCustodyReceipt,
        against record: MeshRoutedItemRecord,
        manifest: MeshRoutedManifest,
        destinations: [String]
    ) -> MeshRoutedStoreRefusal? {
        if let refusal = identityRefusal(receipt, against: record, manifest: manifest) {
            return refusal
        }
        let named = Set(manifest.destinations)
        guard !destinations.isEmpty, destinations.allSatisfy({ named.contains($0) }) else {
            return .notADestination
        }
        return capacityRefusal(forCustodyReceipt: receipt, against: record)
    }

    /// The four identity equalities: the receipt is about **this** record's item, origin, bytes and
    /// mesh. A store that trusts its caller's word about which item a receipt is for has no
    /// invariant left.
    private func identityRefusal(
        _ receipt: MeshCustodyReceipt,
        against record: MeshRoutedItemRecord,
        manifest: MeshRoutedManifest
    ) -> MeshRoutedStoreRefusal? {
        guard receipt.itemID == record.key.itemID,
              receipt.originFingerprint == record.key.originFingerprint,
              receipt.contentHash == record.contentHash,
              receipt.meshID == manifest.meshID else {
            return .manifestMismatch
        }
        return nil
    }

    /// The evidence cap, applied by SIGNER: replacing an existing custodian's receipt is always
    /// allowed, and only a genuinely new signer can push the set over its bound.
    private func capacityRefusal(
        forCustodyReceipt receipt: MeshCustodyReceipt,
        against record: MeshRoutedItemRecord
    ) -> MeshRoutedStoreRefusal? {
        let alreadyStored = record.receipts.contains { $0.custodianFingerprint == receipt.custodianFingerprint }
        guard alreadyStored || record.receipts.count < capacity.maxReceiptsPerItem else {
            return .capacityReceipts
        }
        return nil
    }

    /// Advances every named destination to `custodied(by:)`, stopping at the first delivery-level
    /// refusal so nothing is half-applied.
    ///
    /// Internal since P5 item 8 so the batch hand-off door applies the identical rule; the rule has
    /// exactly one implementation. Refuse-batch is the contract, not an accident: the caller owes a
    /// refusal-free list, because "nothing is half-applied" is what keeps an unretractable signed
    /// count honest.
    func advancingAll(
        _ destinations: [String],
        to custodian: String,
        in target: MeshDeliveryTarget
    ) -> MeshDeliveryOutcome {
        var current = target
        // R2: bounded by the destination cap.
        for destination in destinations {
            let outcome = current.advancing(destination, to: .custodied(by: custodian))
            guard let advanced = outcome.target else { return outcome }
            current = advanced
        }
        return .updated(current)
    }

    /// The evidence set with `receipt` inserted or replaced for its custodian, in custodian order.
    ///
    /// Internal since P5 item 8 so the batch hand-off door applies the identical rule; the rule has
    /// exactly one implementation.
    static func storing(
        _ receipt: MeshCustodyReceipt,
        in receipts: [MeshCustodyReceipt]
    ) -> [MeshCustodyReceipt] {
        var stored = receipts.filter { $0.custodianFingerprint != receipt.custodianFingerprint }
        stored.append(receipt)
        return stored.sorted { $0.custodianFingerprint < $1.custodianFingerprint }
    }

    /// Stores one verified custody receipt as **evidence only** — the drain's ingest door.
    ///
    /// The difference from ``recordingCustodyTransfer(item:for:receipt:now:)`` is the whole reason
    /// this door exists: that one takes a `for destinations:` list, which is the **caller's**
    /// statement about which legs the custodian is now the courier for, and advances those rungs.
    /// A drain receiving a forwarded receipt has no honest value for that list — nobody handed it a
    /// hand-off decision — so it records the signature and **moves no rung at all**. Inferring a
    /// destination list from the manifest would be this device inventing somebody else's hand-off.
    ///
    /// Applies exactly the transfer door's identity and capacity checks, in the same order, minus
    /// the destination clause it has no input for.
    ///
    /// - Important: `receipt` must be one `MeshCustodyReceiptVerifier.verify(_:)` has already
    ///   accepted (returned nil). The door re-checks identity anyway.
    ///
    /// - Parameters:
    ///   - item: The signed pair.
    ///   - receipt: The custodian's signed statement, forwarded verbatim.
    ///   - now: The injected instant. Nothing here reads a clock; the parameter keeps the door's
    ///     shape identical to every other verb the property battery drives.
    /// - Returns: what was stored, or a named refusal, or the store's unavailability. **Nothing is
    ///   written on any refusal.**
    func recordingCustodyEvidence(
        item: MeshRoutedItemKey,
        receipt: MeshCustodyReceipt,
        now: Date
    ) -> MeshRoutedOutcome<MeshRoutedCustodyEvidence> {
        var index: MeshRoutedIndex
        let token: LoadToken
        switch indexForWriting() {
        case .unavailable(let cause): return .unavailable(cause)
        case .writable(let loaded, let vended): index = loaded; token = vended
        }
        guard var record = index.record(for: item) else { return .refused(.unknownItem) }
        guard let manifest = record.manifest else { return .refused(.manifestMismatch) }
        if let refusal = identityRefusal(receipt, against: record, manifest: manifest) {
            return .refused(refusal)
        }
        if let refusal = capacityRefusal(forCustodyReceipt: receipt, against: record) {
            return .refused(refusal)
        }
        let isNew = !record.receipts.contains { $0.custodianFingerprint == receipt.custodianFingerprint }
        record.receipts = Self.storing(receipt, in: record.receipts)
        index.upsert(record)
        do {
            try save(index, token: token)
        } catch {
            return .unavailable(unavailability(from: error))
        }
        return .completed(
            MeshRoutedCustodyEvidence(key: item, custodian: receipt.custodianFingerprint, isNew: isNew)
        )
    }

    // MARK: Forwarding (the origin's exact bytes)

    /// The stored custody receipts for `item`, byte-identical, ordered by custodian fingerprint.
    ///
    /// The mirror of ``forwardableRecipientReceipts(item:)``, with one deliberate asymmetry stated
    /// on both: a record stores **other members'** custody receipts only. This device's own custody
    /// is the `custodiedAt` stamp, and its receipt is re-minted from the durable bytes when it is
    /// needed — a custody claim is re-measurable forever, which is exactly what a recipient receipt's
    /// one-shot ledger judgement is not.
    ///
    /// - Parameter item: The signed pair.
    /// - Returns: the receipts (empty when the item is unknown or holds none), or the store's
    ///   unavailability.
    func forwardableCustodyReceipts(
        item: MeshRoutedItemKey
    ) -> MeshRoutedOutcome<[MeshCustodyReceipt]> {
        switch indexForWriting() {
        case .unavailable(let cause):
            return .unavailable(cause)
        case .writable(let index, _):
            return .completed(index.record(for: item)?.receipts ?? [])
        }
    }

    /// The origin's stored manifest for `item`, byte-identical — a custodian is a courier, not a
    /// co-signer.
    ///
    /// - Returns: the manifest, `nil` when the item is unknown or still parked, or the store's
    ///   unavailability.
    func forwardableManifest(item: MeshRoutedItemKey) -> MeshRoutedOutcome<MeshRoutedManifest?> {
        switch indexForWriting() {
        case .unavailable(let cause):
            return .unavailable(cause)
        case .writable(let index, _):
            return .completed(index.record(for: item)?.manifest)
        }
    }

    /// The origin's stored chunk at `chunkIndex`, byte-identical, one chunk resident at a time.
    ///
    /// There is deliberately **no** API that returns every chunk or a reassembled blob: the caller
    /// iterates `MeshRoutedIndex.heldChunkIndices(of:)`. Every read compares the opened chunk to the
    /// descriptor holding its slot, because the seal's AAD is purpose ‖ install only and nothing at
    /// rest binds a file to a slot — a mismatch answers ``MeshRoutedStoreRefusal/chunkFileMismatch``
    /// and emits nothing.
    ///
    /// - Returns: the chunk, `nil` when that slot is not held (including after a repair), or the
    ///   store's unavailability.
    func forwardableChunk(
        item: MeshRoutedItemKey,
        index chunkIndex: UInt32
    ) -> MeshRoutedOutcome<MeshChunk?> {
        var index: MeshRoutedIndex
        let token: LoadToken
        switch indexForWriting() {
        case .unavailable(let cause): return .unavailable(cause)
        case .writable(let loaded, let vended): index = loaded; token = vended
        }
        guard let record = index.record(for: item),
              let stored = record.chunk(at: chunkIndex) else {
            return .completed(nil)
        }
        let contentKey: SymmetricKey
        switch openKey() {
        case .available(let key): contentKey = key
        case .deferred(let reason):
            return .unavailable(.deferred(MeshRoutedDeferral(reason: reason, detail: stored.fileName)))
        case .refused(let cause):
            return .unavailable(.refused(MeshRoutedSealRefusal(operation: .open, cause: cause)))
        }
        return forwarded(stored, of: item, in: &index, token: token, contentKey: contentKey)
    }

    /// The read half of ``forwardableChunk(item:index:)``, including the repair branch.
    private func forwarded(
        _ stored: MeshRoutedChunkDescriptor,
        of item: MeshRoutedItemKey,
        in index: inout MeshRoutedIndex,
        token: LoadToken,
        contentKey: SymmetricKey
    ) -> MeshRoutedOutcome<MeshChunk?> {
        switch readChunkFile(expecting: stored, contentKey: contentKey) {
        case .chunk(let chunk):
            return .completed(chunk)
        case .unavailable(let cause):
            return .unavailable(cause)
        case .missing:
            if let cause = repairing(item, dropping: stored, in: &index, token: token) {
                return .unavailable(cause)
            }
            return .completed(nil)
        case .unauthentic:
            if let cause = repairing(item, dropping: stored, in: &index, token: token) {
                return .unavailable(cause)
            }
            return .refused(.chunkFileMismatch)
        }
    }

    /// Drops one descriptor the store can no longer stand behind, clears `custodiedAt` — the item is
    /// no longer complete, so the durable claim behind any witness is gone — removes the file, and
    /// saves.
    ///
    /// The delivery record's custody rung is left untouched on purpose: a receipt already sent is a
    /// point-in-time claim, not a running promise.
    ///
    /// - Returns: nil when the repair was written, or the unavailability that stopped it.
    func repairing(
        _ item: MeshRoutedItemKey,
        dropping stored: MeshRoutedChunkDescriptor,
        in index: inout MeshRoutedIndex,
        token: LoadToken
    ) -> MeshRoutedUnavailability? {
        guard var record = index.record(for: item) else { return nil }
        record.chunks.removeAll { $0.fileName == stored.fileName }
        record.custodiedAt = nil
        index.upsert(record)
        do {
            try save(index, token: token)
        } catch {
            return unavailability(from: error)
        }
        removeChunkFile(named: stored.fileName)
        FernletAuditLog.log(
            "mesh.routedStore.chunkRepaired",
            context: ["index": String(stored.descriptor.chunkIndex)]
        )
        return nil
    }

    // MARK: Sweeps (on demand, never on a timer)

    /// Removes every item whose expiry has passed, taking its payload files and its stored receipts
    /// with it.
    ///
    /// On demand only — P7 owns the poller, exactly as `enforceSessionCeiling` and
    /// `evaluatePartition` are on-demand.
    func sweepingExpired(now: Date) -> MeshRoutedOutcome<MeshRoutedSweepReport> {
        var index: MeshRoutedIndex
        let token: LoadToken
        switch indexForWriting() {
        case .unavailable(let cause): return .unavailable(cause)
        case .writable(let loaded, let vended): index = loaded; token = vended
        }
        let expired = index.items.filter { !$0.isLive(at: now) }.map(\.key)
        guard !expired.isEmpty else {
            return .completed(
                MeshRoutedSweepReport(itemsRemoved: 0, chunkFilesRemoved: 0, chunkFilesFailed: 0,
                                      sweptToCeiling: false)
            )
        }
        var names: [String] = []
        // R2: bounded by `maxItems`.
        for key in expired { names.append(contentsOf: index.remove(key)) }
        do {
            try save(index, token: token)
        } catch {
            return .unavailable(unavailability(from: error))
        }
        let removal = removeChunkFiles(named: names)
        return .completed(
            MeshRoutedSweepReport(itemsRemoved: expired.count, chunkFilesRemoved: removal.removed,
                                  chunkFilesFailed: removal.failed, sweptToCeiling: false)
        )
    }

    /// Removes one item deliberately — item 11's door for a parked set whose manifest was refused an
    /// unknown type token — taking its payload files and receipts with it.
    ///
    /// - Parameters:
    ///   - item: The signed pair to drop.
    ///   - reason: A frozen English audit token naming why. Never localized, never user copy.
    func dropping(item: MeshRoutedItemKey, reason: String) -> MeshRoutedOutcome<MeshRoutedSweepReport> {
        var index: MeshRoutedIndex
        let token: LoadToken
        switch indexForWriting() {
        case .unavailable(let cause): return .unavailable(cause)
        case .writable(let loaded, let vended): index = loaded; token = vended
        }
        guard index.record(for: item) != nil else { return .refused(.unknownItem) }
        let names = index.remove(item)
        do {
            try save(index, token: token)
        } catch {
            return .unavailable(unavailability(from: error))
        }
        FernletAuditLog.log("mesh.routedStore.itemDropped", context: ["reason": reason])
        let removal = removeChunkFiles(named: names)
        return .completed(
            MeshRoutedSweepReport(itemsRemoved: 1, chunkFilesRemoved: removal.removed,
                                  chunkFilesFailed: removal.failed, sweptToCeiling: false)
        )
    }

    /// Removes a whole batch of items deliberately — P5 item 9's reclaim — in **one** load and
    /// **one** save.
    ///
    /// The bulk sibling exists for a cost reason worth stating: ``dropping(item:reason:)`` opens its
    /// own `indexForWriting()` and re-seals the whole index per item, so a sixteen-item reclaim
    /// through it is sixteen loads and sixteen full seals on the main actor. This is
    /// ``sweepingExpired(now:)``'s exact shape with an explicit key list instead of a clock
    /// predicate.
    ///
    /// It has **no destination, parked or liveness guard of its own** — the caller is the guard,
    /// exactly as it is for the single-item verb. A key the store does not hold is skipped, so the
    /// batch is idempotent under a replay.
    ///
    /// - Parameters:
    ///   - items: The signed pairs to drop. The caller owes the bound; item 9's reclaim passes at
    ///     most ``MeshRoutedDrainBounds/increment1``'s item allowance.
    ///   - reason: A frozen English audit token naming why. Never localized, never user copy.
    /// - Returns: what was removed, or the store's unavailability. An empty list writes nothing.
    func dropping(items: [MeshRoutedItemKey], reason: String) -> MeshRoutedOutcome<MeshRoutedSweepReport> {
        var index: MeshRoutedIndex
        let token: LoadToken
        switch indexForWriting() {
        case .unavailable(let cause): return .unavailable(cause)
        case .writable(let loaded, let vended): index = loaded; token = vended
        }
        var names: [String] = []
        var removed = 0
        // R2: bounded by the caller's list, itself bounded by `maxItems`.
        for key in items where index.record(for: key) != nil {
            names.append(contentsOf: index.remove(key))
            removed += 1
        }
        guard removed > 0 else {
            return .completed(
                MeshRoutedSweepReport(itemsRemoved: 0, chunkFilesRemoved: 0, chunkFilesFailed: 0,
                                      sweptToCeiling: false)
            )
        }
        do {
            try save(index, token: token)
        } catch {
            return .unavailable(unavailability(from: error))
        }
        FernletAuditLog.log(
            "mesh.routedStore.itemDropped", context: ["reason": reason, "items": String(removed)]
        )
        let removal = removeChunkFiles(named: names)
        return .completed(
            MeshRoutedSweepReport(itemsRemoved: removed, chunkFilesRemoved: removal.removed,
                                  chunkFilesFailed: removal.failed, sweptToCeiling: false)
        )
    }

    /// Removes payload files the index does not name.
    ///
    /// The loop is bounded by **twice** ``MeshRoutedStoreFormat/maxHeldChunkFiles``, not by the cap
    /// itself: a directory that got OVER the cap is exactly what orphans produce, and a loop bounded
    /// by the cap could not drain one. ``MeshRoutedSweepReport/sweptToCeiling`` says whether to call
    /// again.
    ///
    /// - Important: this is the call ``quarantineCorruptIndex(_:)``'s contract requires its token to
    ///   be spent on first — after a quarantine the index is empty and every payload file is an
    ///   orphan.
    func sweepingOrphanChunkFiles() -> MeshRoutedOutcome<MeshRoutedSweepReport> {
        let index: MeshRoutedIndex
        switch indexForWriting() {
        case .unavailable(let cause): return .unavailable(cause)
        case .writable(let loaded, _): index = loaded
        }
        guard let onDisk = chunkDirectoryFileNames() else {
            return .unavailable(
                .deferred(MeshRoutedDeferral(reason: .fileUnreadable, detail: Self.chunkDirectoryName))
            )
        }
        let ceiling = 2 * MeshRoutedStoreFormat.maxHeldChunkFiles
        let orphans = onDisk.subtracting(index.heldChunkFileNames).sorted()
        let removal = removeChunkFiles(named: Array(orphans.prefix(ceiling)))
        return .completed(
            MeshRoutedSweepReport(itemsRemoved: 0, chunkFilesRemoved: removal.removed,
                                  chunkFilesFailed: removal.failed,
                                  sweptToCeiling: orphans.count > ceiling)
        )
    }

    /// Removes the named payload files, counting the failures rather than swallowing them.
    private func removeChunkFiles(named names: [String]) -> (removed: Int, failed: Int) {
        var removed = 0
        var failed = 0
        // R2: bounded by the caller's list, itself bounded by `2 × maxHeldChunkFiles`.
        for name in names {
            if removeChunkFile(named: name) { removed += 1 } else { failed += 1 }
        }
        return (removed, failed)
    }
}
