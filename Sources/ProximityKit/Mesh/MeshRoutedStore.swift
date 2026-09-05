// MeshRoutedStore.swift
// ProximityKit/Mesh
//
// Network migration P5 item 3 (plan §11, §19.5): the sealed sidecar that makes "I am holding this
// person's ciphertext" a fact that survives a force-quit — and the five-state load that keeps a
// REFUSAL from ever looking like an empty field.
//
// The floor is `MeshSessionStore`'s, method for method, deliberately: `load` / `save(_:token:)` /
// `quarantineCorruptIndex(_:)` / `wipeForDeleteAll(scope:)`, five states, a `fileprivate`-minted
// write token, no cache. Invariant 7 is stated once and enforced everywhere, so the second durable
// mesh surface must not paraphrase the first. What is new is the SECOND file kind: one sealed
// `MeshRoutedChunks/<uuid>.chunk` per held chunk, so 256 MiB of custody never has to be resident.
//
// The fifth state is the whole design, and here it is load-bearing twice over. `ColumnCrypto` is
// V3-only and refuses to seal without a `DeviceBindingID` (owner decision D4), so before first
// unlock this store cannot be written — not slower, not retried silently, refused. Under plan §3.6
// that means: **if you cannot seal, you must not acknowledge.** A custody receipt for bytes no
// durable write returned is exactly the lie the type system in `MeshRoutedCustodyCommit.swift`
// makes unwritable, and this file is the half that decides when a write returned.
//
// What is deliberately NOT here: any decryption of routed CONTENT. The store never calls
// `MeshRoutedContentKeyWrapper.unwrap`, never touches the key-agreement key, never names a content
// key — `forwardableChunk` hands back the origin's sealed blob as the origin signed it. Every read
// is therefore ciphertext-only by construction, which is what lets custody continue on a locked
// device after first unlock (item 10). The only crypto in the routed store is the AT-REST seal, and
// it lives in this file alone.

import CryptoKit
import Foundation
import FernletCrypto
import FernletFoundation

// MARK: - MeshRoutedSealRefusal

/// A seal or open that was **refused**, naming what was refused and why (plan §19.5).
///
/// `MeshSessionSealRefusal`'s sibling, with **identical frozen rawValues** — a test asserts the two
/// case sets are equal, so one vocabulary cannot become two. A separate type rather than a reuse
/// because `MeshSessionSealRefusal.summary` hard-codes "mesh session context", and a routed log line
/// that said that would be a lie.
///
/// Distinct from a deferral in kind, not in degree: a deferral says "ask again", a refusal says
/// "this cannot be done under the present custody". Both are distinct from `absent`, which says
/// "there is genuinely nothing here" — the one answer a writer may treat as a green field.
nonisolated struct MeshRoutedSealRefusal: Error, Equatable, Sendable {

    /// Which half of the store refused.
    nonisolated enum Operation: String, CaseIterable, Equatable, Sendable {
        /// A write refused; nothing reached the disk.
        case seal
        /// A read refused; the bytes exist and cannot be opened under this custody.
        case open
    }

    /// Why it refused. Every case is terminal *for this attempt* and none of them means "empty".
    nonisolated enum Cause: String, CaseIterable, Equatable, Sendable {
        /// `DeviceBindingID` produced no durable install binding, so v3 cannot be minted or its AAD
        /// reconstructed. The canonical D4 refusal — the pre-first-unlock window §19.5 is about,
        /// and the one cause that self-heals on unlock.
        case installBindingUnavailable
        /// A sealed file exists but its keychain row is authoritatively gone. Nothing can open
        /// these bytes again; deleting them is a decision, not a fallback.
        case sealKeyMissingForSealedFile
        /// The keychain row exists but is not a 32-byte key. It never sealed anything readable, and
        /// overwriting it blindly would destroy whatever did.
        case sealKeyMalformed
        /// A freshly minted key did not survive its read-back verify, so sealing against it would
        /// write ciphertext nothing can ever open.
        case sealKeyNotPersisted
        /// The blob claims an at-rest generation this build no longer reads. Named rather than
        /// reported as an authentication failure, because nothing is wrong with the ciphertext.
        case retiredAtRestFormat
    }

    /// Whether the refusal happened while sealing or while opening.
    let operation: Operation

    /// The named reason.
    let cause: Cause

    /// A frozen-English one-liner for logs and test failure messages. Never localized, never shown
    /// to a user as-is.
    var summary: String { "mesh routed store: \(operation.rawValue) refused — \(cause.rawValue)" }
}

// MARK: - MeshRoutedDeferral

/// A load or save that could not proceed **right now** and must be retried, with nothing decided and
/// nothing written. `MeshSessionDeferral`'s sibling, same frozen rawValues.
///
/// Deliberately coarse on the read side: any file read error is a deferral, never "absent". Treating
/// an error as emptiness is how a store overwrites its own data — and here, how a transient outage
/// would destroy other people's custody.
nonisolated struct MeshRoutedDeferral: Equatable, Sendable {

    /// Why the attempt was deferred.
    nonisolated enum Reason: String, CaseIterable, Equatable, Sendable {
        /// The keychain could not answer for the seal key (locked, interaction required, transient
        /// failure). The row's existence is UNKNOWN, which is exactly why this is not a refusal.
        case sealKeyTransientlyUnreadable
        /// The install-binding keychain read errored, which `DeviceBindingID` defines as retryable —
        /// as opposed to an authoritatively absent binding, which refuses.
        case installBindingReadError
        /// The file exists but could not be read. Protected-data-unavailable and ordinary I/O errors
        /// are one case on purpose: neither is licence to overwrite or to delete.
        case fileUnreadable
    }

    /// The named reason.
    let reason: Reason

    /// Frozen-English detail for logs (an underlying error description, or the seam that deferred).
    let detail: String
}

// MARK: - MeshRoutedCorruption

/// A sealed file that exists, is readable, and is not something this build can use.
///
/// Corrupt is NOT absent and NOT refused: the bytes are here, the custody is fine, and they still do
/// not decode. Recovering from it is an explicit act — ``MeshRoutedStore/quarantineCorruptIndex(_:)``
/// — never an implicit overwrite.
nonisolated struct MeshRoutedCorruption: Equatable, Sendable {

    /// What is wrong with the bytes. **Exactly `MeshSessionCorruption.Detail`'s four cases — no
    /// fifth.** An at-rest cap violation rides in ``undecodableJSON(_:)``'s string
    /// (`"capacityExceeded:items"`), because the decode genuinely failed, and because a fifth case
    /// would break the parity a test asserts between the two vocabularies.
    nonisolated enum Detail: Equatable, Sendable {
        /// Zero bytes on disk. No writer produces an empty file, so this is a store fault.
        case emptyFile
        /// The blob decrypted but the JSON did not decode. Carries the decoder's description, or
        /// `"capacityExceeded:<cap>"` for an at-rest cap violation.
        case undecodableJSON(String)
        /// The JSON decoded far enough to read a `schemaVersion` this build does not own.
        case unsupportedSchemaVersion(Int)
        /// Poly1305 authentication failed: truncated, tampered with, sealed under a different key or
        /// install — or, for a chunk file, an opened chunk that is not the one the index says holds
        /// that slot.
        case authenticationFailed
    }

    /// What is wrong.
    let detail: Detail
}

// MARK: - MeshRoutedLoad

/// The **five-state** result of loading the sealed routed index (plan invariant 7 + §19.5's fifth
/// consideration).
///
/// | state | meaning | may a writer overwrite? |
/// | --- | --- | --- |
/// | ``loaded(_:_:)`` | an index is in hand | yes — token vended |
/// | ``absent(_:)`` | no file; genuinely a green field | yes — token vended |
/// | ``deferred(_:)`` | ask again; nothing is known | **no** |
/// | ``corrupt(_:)`` | bytes exist and do not decode | **no**, until quarantined |
/// | ``refused(_:)`` | custody refuses; the field may be full | **no** |
///
/// The last three carry no ``MeshRoutedStore/LoadToken``, and `save` cannot be called without one.
/// That is the type-level form of "seal refused ≠ deferred ≠ absent": there is no way to hold a
/// refusal and still address the writer.
nonisolated enum MeshRoutedLoad: Equatable, Sendable {
    /// An index was opened. The token authorises writing back to the same file.
    case loaded(MeshRoutedIndex, MeshRoutedStore.LoadToken)
    /// There is no index file. The only other state that vends a write token.
    case absent(MeshRoutedStore.LoadToken)
    /// Retry later; nothing was decided and nothing may be written.
    case deferred(MeshRoutedDeferral)
    /// The file is present and undecodable. Quarantine it deliberately before writing.
    case corrupt(MeshRoutedCorruption)
    /// Custody refused, naming what it refused. **Never** read as "nothing is held".
    case refused(MeshRoutedSealRefusal)
}

// MARK: - MeshRoutedSaveError

/// Why a save did not happen. A thrown error always means **nothing durable changed**.
nonisolated enum MeshRoutedSaveError: Error, Equatable, Sendable {
    /// The token was minted by a store on a different file. Guards against a token from one scope
    /// authorising a write into another — the type-level guard's runtime half.
    case tokenFromAnotherStore
    /// The write could not proceed right now; retry.
    case deferred(MeshRoutedDeferral)
    /// The bytes could not be written (directory creation or the atomic write failed). Carries the
    /// underlying description. The previous file is untouched.
    case notWritten(String)
}

// MARK: - MeshRoutedChunkFileRead

/// What reading one sealed chunk file produced — the three-way split of plan §19.5, one level down
/// from the index (D-3.6).
///
/// The asymmetry is the point. Bytes we cannot **authenticate** are bytes we do not have, so the
/// index is repaired against them; bytes we could not **read right now** are a deferral, and
/// repairing on one would delete real custody during the pre-first-unlock window — a silent data
/// loss with a green test suite.
nonisolated enum MeshRoutedChunkFileRead: Sendable {
    /// The file opened, authenticated, and matches the descriptor holding its slot.
    case chunk(MeshChunk)
    /// There is no file at that name. The item is incomplete; the index is repaired.
    case missing
    /// The bytes are here and are not this slot's chunk. The index is repaired, and the reason is
    /// carried so the repair can be audited by name.
    case unauthentic(MeshRoutedCorruption.Detail)
    /// The file could not be read or opened under the present custody. **Repairs nothing.**
    case unavailable(MeshRoutedUnavailability)
}

// MARK: - MeshRoutedStore

/// The sealed, per-scope store for the routed content this device is holding (plan §11, §19.5).
///
/// ## Invariants
///
/// 1. **Durable before acknowledged (plan §3.6).** A write returns only with the bytes on disk, and
///    a `MeshCustodyReceipt` cannot exist without a `MeshCustodyDurabilityWitness`, which only a
///    returned durable write mints. Force-quit gives no callback to save you afterwards.
/// 2. **A refusal is never an absence.** ``load()`` has five states and only `loaded` and `absent`
///    vend a ``LoadToken``. A caller holding `refused`, `deferred` or `corrupt` structurally cannot
///    call the writer.
/// 3. **The index is authoritative over the files.** A chunk file the index does not name is an
///    orphan; a descriptor whose file is gone, or whose bytes do not authenticate as that slot's
///    chunk, is bytes we do not have. Repairs run one way only.
/// 4. **No decrypt door.** Nothing here unwraps a content key or touches the key-agreement key.
///    Custody is ciphertext-only by construction, on a locked device as much as an unlocked one.
/// 5. **Per-instance scope.** Directory *and* keychain service come from ``MeshRoutedStorageScope``
///    at init, so no two live stores share state — the shared-disk-root flake family gains no member
///    (`MeshRoutedStoreIsolationTests`).
///
/// ## Concurrency
///
/// A `nonisolated`, `Sendable` value with no mutable state: every call re-reads the files and the
/// key, so there is no cache to go stale and nothing to synchronise. Callers that need serialisation
/// own it (item 6's drain).
public nonisolated struct MeshRoutedStore: Sendable {

    /// Permission to write, vended only by a ``MeshRoutedLoad`` that established the field is safe
    /// to write: `loaded` (we read what is there) or `absent` (there is nothing there).
    ///
    /// Its initialiser is `fileprivate`, so nothing outside **this file** can mint one — including
    /// the custody verbs, which live in `MeshRoutedCustody.swift` and
    /// `MeshRoutedCustodyCommit.swift` and therefore have to obtain a token from ``load()`` like
    /// everyone else. There is no "force" overload. The stored file URL is checked at save time so a
    /// token from one scope cannot authorise a write into another.
    public nonisolated struct LoadToken: Equatable, Sendable {
        /// The file this token authorises a write to.
        let fileURL: URL

        /// Mints a token. `fileprivate` on purpose — see the type's documentation.
        fileprivate init(fileURL: URL) {
            self.fileURL = fileURL
        }
    }

    /// How a raw file read turned out, before any crypto is attempted.
    private enum FileRead {
        /// No file at the path.
        case absent
        /// The file's bytes.
        case bytes(Data)
        /// The file exists and could not be read.
        case deferred(MeshRoutedDeferral)
    }

    /// Name of the sealed catalogue inside the scope's directory.
    static let indexFileName = "MeshRoutedIndex.sealed"

    /// Extension appended when a corrupt index is set aside.
    static let quarantineExtension = "corrupt"

    /// Directory holding the sealed payload files, one per held chunk.
    static let chunkDirectoryName = "MeshRoutedChunks"

    /// Extension every payload file carries. The stem is a fresh random UUID and means nothing.
    static let chunkFileExtension = "chunk"

    /// This store's directory + keychain service.
    let scope: MeshRoutedStorageScope

    /// The one sealing path, bound to this surface's reviewed purpose. **The only `ColumnCrypto` in
    /// the routed store**, and the reason a grep-wall can assert the store names no decryption seam.
    private let crypto = ColumnCrypto(purpose: FernletCryptoPurpose.KeyDerivation.meshRoutedStoreV1)

    /// The caps this store refuses at, as ONE value (P5 item 9).
    ///
    /// Read back by everything that *accounts* — ``capacityUsage(of:at:)`` is the one seam that
    /// builds a usage for a real store, and it hands over this value and this store's own chunk
    /// directory, never ``MeshRoutedCapacity/production`` — so the writer doors and the sweep can
    /// never measure against two different models or two different disks. The at-rest guards in `MeshRoutedIndex` keep
    /// reading ``MeshRoutedStoreFormat`` directly and deliberately: a `Codable` initialiser has no
    /// injection point, and an injected capacity is always ≤ production, so an index written under
    /// small bounds still decodes clean.
    let capacity: MeshRoutedCapacity

    /// Builds a store on one scope.
    ///
    /// - Parameters:
    ///   - scope: Directory + keychain service. Pass ``MeshRoutedStorageScope/production`` in the
    ///     app; tests pass a temp directory and a unique service.
    ///   - capacity: The cap model this store's doors refuse at. Shipping code takes the default;
    ///     a test drives a door to its bound in milliseconds by injecting a small one.
    init(scope: MeshRoutedStorageScope, capacity: MeshRoutedCapacity = .production) {
        self.scope = scope
        self.capacity = capacity
    }

    /// The sealed catalogue.
    var indexURL: URL {
        scope.directory.appendingPathComponent(Self.indexFileName, isDirectory: false)
    }

    /// Where a corrupt index is moved so it is preserved rather than destroyed.
    var quarantineURL: URL {
        indexURL.appendingPathExtension(Self.quarantineExtension)
    }

    /// The directory of sealed payload files.
    var chunkDirectory: URL {
        scope.directory.appendingPathComponent(Self.chunkDirectoryName, isDirectory: true)
    }

    /// The file one opaque chunk name resolves to.
    func chunkFileURL(named name: String) -> URL {
        chunkDirectory.appendingPathComponent(name, isDirectory: false)
    }

    /// A fresh opaque payload file name: a random UUID plus the fixed extension. No fingerprint,
    /// item id, index or hash ever appears in a path component.
    static func newChunkFileName() -> String {
        "\(UUID().uuidString).\(chunkFileExtension)"
    }

    // MARK: Load

    /// Loads the sealed index, classified into all five states.
    ///
    /// Ordering is deliberate and load-bearing: the FILE is classified before the key is fetched, so
    /// a missing index answers `absent` without ever consulting custody, and a present file that
    /// cannot be read answers `deferred` rather than pretending to be empty. Read-only — the expiry
    /// and orphan sweeps are explicit calls that take a token, never side effects of a load that may
    /// be running in a state where the store knows nothing.
    ///
    /// - Returns: One of the five ``MeshRoutedLoad`` states. Only two of them carry a write token.
    func load() -> MeshRoutedLoad {
        let raw: Data
        switch readFile(at: indexURL) {
        case .absent:
            return .absent(LoadToken(fileURL: indexURL))
        case .deferred(let deferral):
            return .deferred(deferral)
        case .bytes(let data):
            raw = data
        }
        guard !raw.isEmpty else {
            return .corrupt(MeshRoutedCorruption(detail: .emptyFile))
        }
        switch MeshRoutedSealKey.forOpen(service: scope.keychainService) {
        case .available(let key):
            return openIndex(from: raw, contentKey: key)
        case .deferred(let reason):
            return .deferred(MeshRoutedDeferral(reason: reason, detail: Self.indexFileName))
        case .refused(let cause):
            return .refused(MeshRoutedSealRefusal(operation: .open, cause: cause))
        }
    }

    /// Opens sealed bytes into an index, mapping every failure onto the state it belongs in.
    ///
    /// The three-way split of `ColumnCrypto`'s errors is the point: a retryable binding READ error
    /// defers, an authoritatively absent binding refuses, and anything wrong with the BYTES is
    /// corruption. An at-rest cap violation is corruption too — never a clamp, which would silently
    /// drop a durable record whose payload files stay on disk.
    private func openIndex(from raw: Data, contentKey: SymmetricKey) -> MeshRoutedLoad {
        do {
            let index: MeshRoutedIndex? = try crypto.open(raw, contentKey: contentKey)
            guard let index else {
                return .corrupt(MeshRoutedCorruption(detail: .authenticationFailed))
            }
            return .loaded(index, LoadToken(fileURL: indexURL))
        } catch MeshRoutedIndexDecodingError.unsupportedSchemaVersion(let version) {
            return .corrupt(MeshRoutedCorruption(detail: .unsupportedSchemaVersion(version)))
        } catch MeshRoutedIndexDecodingError.capacityExceeded(let cap) {
            return .corrupt(MeshRoutedCorruption(detail: .undecodableJSON("capacityExceeded:\(cap)")))
        } catch let error as ColumnCrypto.SealedColumnOpenError {
            return Self.loadState(forOpenError: error)
        } catch is DeviceBindingID.ReadError {
            return .deferred(
                MeshRoutedDeferral(reason: .installBindingReadError, detail: Self.indexFileName)
            )
        } catch let error as DecodingError {
            return .corrupt(MeshRoutedCorruption(detail: .undecodableJSON(String(describing: error))))
        } catch {
            return .corrupt(MeshRoutedCorruption(detail: .authenticationFailed))
        }
    }

    /// Maps `ColumnCrypto`'s named open refusals onto load states.
    ///
    /// `installBindingMissing` is a REFUSAL (custody, not content — the ciphertext is fine); a
    /// retired format is a refusal too, and by name; an empty column is corruption.
    private static func loadState(forOpenError error: ColumnCrypto.SealedColumnOpenError) -> MeshRoutedLoad {
        switch error {
        case .installBindingMissing:
            return .refused(MeshRoutedSealRefusal(operation: .open, cause: .installBindingUnavailable))
        case .retiredFormat:
            return .refused(MeshRoutedSealRefusal(operation: .open, cause: .retiredAtRestFormat))
        case .emptyBlob:
            return .corrupt(MeshRoutedCorruption(detail: .emptyFile))
        }
    }

    /// Classifies a raw file read. A read error is NEVER reported as absence.
    private func readFile(at url: URL) -> FileRead {
        guard FileManager.default.fileExists(atPath: url.path) else { return .absent }
        do {
            return .bytes(try Data(contentsOf: url))
        } catch {
            return .deferred(MeshRoutedDeferral(reason: .fileUnreadable, detail: String(describing: error)))
        }
    }

    // MARK: Save

    /// Seals `index` and writes it, atomically, under the token's authority.
    ///
    /// Durable before acknowledged: this returns only when the bytes are on disk. Every failure path
    /// throws with the previous file untouched — a refused seal never truncates, never writes a
    /// partial file, and never degrades to an un-domained format.
    ///
    /// - Parameters:
    ///   - index: The catalogue to persist.
    ///   - token: Permission from a `loaded` or `absent` load of THIS store.
    /// - Throws: ``MeshRoutedSealRefusal`` when custody refuses, ``MeshRoutedSaveError`` when the
    ///   token belongs elsewhere, the attempt must be retried, or the write itself failed.
    func save(_ index: MeshRoutedIndex, token: LoadToken) throws {
        guard token.fileURL == indexURL else { throw MeshRoutedSaveError.tokenFromAnotherStore }
        let contentKey = try sealKey()
        let sealed = try sealBytes(index, contentKey: contentKey)
        try writeAtomically(sealed, to: indexURL)
    }

    /// The seal key, or the named refusal/deferral as a thrown error. Shared by the index save and
    /// the chunk-file writer so both answer the pre-first-unlock window identically.
    ///
    /// - Throws: ``MeshRoutedSealRefusal`` or ``MeshRoutedSaveError/deferred(_:)``.
    func sealKey() throws -> SymmetricKey {
        switch MeshRoutedSealKey.forSeal(service: scope.keychainService) {
        case .available(let key):
            return key
        case .deferred(let reason):
            throw MeshRoutedSaveError.deferred(
                MeshRoutedDeferral(reason: reason, detail: Self.indexFileName)
            )
        case .refused(let cause):
            throw MeshRoutedSealRefusal(operation: .seal, cause: cause)
        }
    }

    /// The key for OPENING sealed bytes, as an outcome rather than a throw — the read paths branch
    /// on all three answers and never mint.
    func openKey() -> MeshRoutedSealKeyOutcome {
        MeshRoutedSealKey.forOpen(service: scope.keychainService)
    }

    /// Seals any value under this store's one purpose, translating `ColumnCrypto`'s D4 refusal into
    /// this store's named one.
    ///
    /// - Important: there is **no write-side deferral for the install binding**.
    ///   `DeviceBindingID.current()` collapses "unavailable" and "read error" into nil, so the seal
    ///   refuses, fail-closed. Do not add one to make background custody "work": that is precisely
    ///   plan §19.5's "background custody must never assume it can seal".
    func sealBytes(_ value: some Encodable, contentKey: SymmetricKey) throws -> Data {
        do {
            return try crypto.seal(value, contentKey: contentKey)
        } catch ColumnCrypto.SealedColumnStrictSealError.bindingUnavailable {
            throw MeshRoutedSealRefusal(operation: .seal, cause: .installBindingUnavailable)
        }
    }

    /// Creates the containing directory if needed, then writes the bytes atomically (temp file +
    /// rename, which is what `.atomic` performs) with the file protection this surface's custody
    /// requires.
    ///
    /// `.completeFileProtectionUntilFirstUserAuthentication`, not `.completeFileProtection`: routed
    /// custody continues in the background with the device locked, and a file that cannot be written
    /// then is custody that cannot be acknowledged. The bytes are sealed and device-bound
    /// regardless, so this is protection class, not the whole protection. **Do not lower it to "fix"
    /// a refusal.**
    ///
    /// Backup exclusion is best-effort defence in depth — the seal key is `ThisDeviceOnly`, so these
    /// bytes could never be opened from a restored backup anyway — but a failure is audited rather
    /// than swallowed.
    func writeAtomically(_ bytes: Data, to url: URL) throws {
        do {
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try bytes.write(
                to: url,
                options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication]
            )
        } catch {
            throw MeshRoutedSaveError.notWritten(String(describing: error))
        }
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var mutableURL = url
        do {
            try mutableURL.setResourceValues(values)
        } catch {
            FernletAuditLog.log(
                "mesh.routedStore.backupExclusionFailed",
                context: ["error": String(describing: error)]
            )
        }
    }

    // MARK: Chunk files

    /// Reads one sealed payload file and checks it really is the chunk the index says holds that
    /// slot.
    ///
    /// **The comparison is not redundant.** `ColumnCrypto` authenticates with
    /// `aad = purpose ‖ install binding` — no file name, item id or index is in it — so under one
    /// key and one install every `MeshRoutedChunks/<uuid>.chunk` blob authenticates in *any* slot.
    /// The binding of a file to a slot is restored by comparing all eight canonical fields and the
    /// payload length, on **every** read. Without it, two swapped files are caught only by the
    /// whole-item content hash at commit time, and never at all on the forward path.
    ///
    /// - Parameters:
    ///   - stored: The descriptor claiming this file.
    ///   - contentKey: The store's seal key, fetched once by the caller.
    /// - Returns: the opened chunk, or the classification that says what to do about its absence.
    func readChunkFile(
        expecting stored: MeshRoutedChunkDescriptor,
        contentKey: SymmetricKey
    ) -> MeshRoutedChunkFileRead {
        switch readFile(at: chunkFileURL(named: stored.fileName)) {
        case .absent:
            return .missing
        case .deferred(let deferral):
            return .unavailable(.deferred(deferral))
        case .bytes(let raw):
            guard !raw.isEmpty else { return .unauthentic(.emptyFile) }
            return openChunkBlob(raw, expecting: stored, contentKey: contentKey)
        }
    }

    /// Opens one payload blob and classifies every failure, in the same three-way split the index
    /// load uses: unreadable custody defers, absent custody refuses, wrong bytes are unauthentic.
    private func openChunkBlob(
        _ raw: Data,
        expecting stored: MeshRoutedChunkDescriptor,
        contentKey: SymmetricKey
    ) -> MeshRoutedChunkFileRead {
        do {
            let chunk: MeshChunk? = try crypto.open(raw, contentKey: contentKey)
            guard let chunk else { return .unauthentic(.authenticationFailed) }
            guard MeshChunkDescriptor(chunk) == stored.descriptor,
                  chunk.payload.count == stored.payloadByteCount else {
                FernletAuditLog.log(
                    "mesh.routedStore.chunkFileMismatch",
                    context: ["index": String(stored.descriptor.chunkIndex)]
                )
                return .unauthentic(.authenticationFailed)
            }
            return .chunk(chunk)
        } catch let error as ColumnCrypto.SealedColumnOpenError {
            return Self.chunkRead(forOpenError: error)
        } catch is DeviceBindingID.ReadError {
            return .unavailable(
                .deferred(MeshRoutedDeferral(reason: .installBindingReadError, detail: stored.fileName))
            )
        } catch let error as DecodingError {
            return .unauthentic(.undecodableJSON(String(describing: error)))
        } catch {
            return .unauthentic(.authenticationFailed)
        }
    }

    /// The chunk-file counterpart of ``loadState(forOpenError:)``: custody refusals stay refusals
    /// (they repair nothing), an empty column is unauthentic.
    private static func chunkRead(
        forOpenError error: ColumnCrypto.SealedColumnOpenError
    ) -> MeshRoutedChunkFileRead {
        switch error {
        case .installBindingMissing:
            return .unavailable(
                .refused(MeshRoutedSealRefusal(operation: .open, cause: .installBindingUnavailable))
            )
        case .retiredFormat:
            return .unavailable(
                .refused(MeshRoutedSealRefusal(operation: .open, cause: .retiredAtRestFormat))
            )
        case .emptyBlob:
            return .unauthentic(.emptyFile)
        }
    }

    /// Every payload file name the chunk directory actually contains, or nil when it could not be
    /// enumerated (which is a deferral at the caller, never an empty answer).
    ///
    /// The cap that bounds file growth is applied to this, not only to the index, so an orphan
    /// cannot hide from the one cap that bounds it.
    func chunkDirectoryFileNames() -> Set<String>? {
        guard FileManager.default.fileExists(atPath: chunkDirectory.path) else { return [] }
        guard let contents = try? FileManager.default.contentsOfDirectory(
            at: chunkDirectory, includingPropertiesForKeys: nil
        ) else {
            return nil
        }
        return Set(
            contents
                .filter { $0.pathExtension == Self.chunkFileExtension }
                .map(\.lastPathComponent)
        )
    }

    /// What this index is spending against **this store's** caps, measured with the file cap taken
    /// against the real directory exactly as the chunk door takes it (P5 item 9).
    ///
    /// The one seam that builds a ``MeshRoutedCapacityUsage`` for a real store, so the accounting and
    /// the doors can never measure a different capacity or a different disk. A directory that cannot
    /// be listed reaches the usage as nil, which reads as "no room" rather than as room.
    ///
    /// - Parameters:
    ///   - index: The index just loaded — never a second load.
    ///   - now: The injected instant; expiry-sensitive counts are taken against it.
    /// - Returns: the usage value.
    func capacityUsage(of index: MeshRoutedIndex, at now: Date) -> MeshRoutedCapacityUsage {
        MeshRoutedCapacityUsage(
            index: index, at: now, capacity: capacity,
            directoryFileCount: chunkDirectoryFileNames()?.count
        )
    }

    /// Removes one payload file, auditing (never swallowing) a failure.
    ///
    /// - Returns: `true` when the file is gone — including when it was never there.
    @discardableResult
    func removeChunkFile(named name: String) -> Bool {
        Self.removeIfPresent(chunkFileURL(named: name), audit: "mesh.routedStore.chunkRemovalFailed")
    }

    // MARK: Recovery and wipe

    /// Sets a corrupt index aside and vends a write token for the now-empty field.
    ///
    /// The ONLY route from ``MeshRoutedLoad/corrupt(_:)`` to a writer, and it is explicit for a
    /// reason: the bytes are preserved beside the file rather than deleted, so a corruption is
    /// investigable instead of merely survived. Requiring the corruption value as an argument means
    /// a caller cannot reach this path without having classified the file first.
    ///
    /// - Important: **the caller must spend the returned token on
    ///   ``sweepingOrphanChunkFiles()`` before anything else.** After a quarantine the index is empty
    ///   and every payload file is an orphan that no cap sees and no scheduled work removes. The
    ///   chunk files are deliberately NOT quarantined with the index: that ciphertext is unreadable
    ///   without a manifest and a content key this device may never have had, so preserving it buys
    ///   nothing, while deleting it *inside* this function would turn a recovery path into a bulk
    ///   delete.
    ///
    /// - Parameter corruption: The classification that justified the quarantine; audited.
    /// - Returns: A token authorising a fresh write.
    /// - Throws: A file-system error if the file could not be moved — in which case no token is
    ///   vended and the corrupt bytes stay exactly where they are.
    func quarantineCorruptIndex(_ corruption: MeshRoutedCorruption) throws -> LoadToken {
        let manager = FileManager.default
        guard manager.fileExists(atPath: indexURL.path) else { return LoadToken(fileURL: indexURL) }
        if manager.fileExists(atPath: quarantineURL.path) {
            try manager.removeItem(at: quarantineURL)
        }
        try manager.moveItem(at: indexURL, to: quarantineURL)
        FernletAuditLog.log(
            "mesh.routedStore.quarantined",
            context: ["detail": String(describing: corruption.detail)]
        )
        return LoadToken(fileURL: indexURL)
    }

    /// Destroys this scope's routed custody — the index, its quarantine sibling, every sealed
    /// payload file, and the keychain row that seals them — for "Delete everything"
    /// (Docs/PrivacyWipeCoverage.md; plan §17.3).
    ///
    /// Every half together, always: files whose key survives are ciphertext nobody can read, and a
    /// key whose files survive is a promise to decrypt them. A missing file counts as success — the
    /// funnel asks for the end state, not for work to have been done.
    ///
    /// - Parameter scope: The scope to wipe.
    /// - Returns: `false` if something that existed could not be removed, so the funnel can report an
    ///   incomplete store. The result is not discardable.
    @discardableResult
    public static func wipeForDeleteAll(scope: MeshRoutedStorageScope) -> Bool {
        let store = MeshRoutedStore(scope: scope)
        let indexRemoved = removeIfPresent(store.indexURL, audit: "mesh.routedStore.wipeFailed")
        let quarantineRemoved = removeIfPresent(store.quarantineURL, audit: "mesh.routedStore.wipeFailed")
        let chunksRemoved = removeIfPresent(store.chunkDirectory, audit: "mesh.routedStore.wipeFailed")
        MeshRoutedSealKey.wipe(service: scope.keychainService)
        return indexRemoved && quarantineRemoved && chunksRemoved
    }

    /// Removes `url` if it exists — a directory recursively, so the payload files need no loop —
    /// auditing (not swallowing) a failure.
    static func removeIfPresent(_ url: URL, audit token: String) -> Bool {
        guard FileManager.default.fileExists(atPath: url.path) else { return true }
        do {
            try FileManager.default.removeItem(at: url)
            return true
        } catch {
            FernletAuditLog.log(token, context: ["error": String(describing: error)])
            return false
        }
    }
}
