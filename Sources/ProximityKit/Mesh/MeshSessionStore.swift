// MeshSessionStore.swift
// ProximityKit/Mesh
//
// P3 item 2 (plan §8.1, §20.2, §20.4.2): the sealed sidecar that makes "an earlier session" a
// concept the code can hold across a process death — and the five-state load that keeps a REFUSAL
// from ever looking like an empty field.
//
// The fifth state is the whole design. `ColumnCrypto` is V3-only and refuses to seal without a
// `DeviceBindingID` (owner decision D4), so before first unlock this file cannot be written — not
// slower, not retried, refused. Collapsing that into `absent` is the shape that overwrites live
// membership: a consumer reading "no prior context" starts a fresh mesh and saves over records the
// user's friends still hold. So `refused` is its own type, it names what it refused, and the WRITER
// is gated on a token only `loaded` and `absent` can vend.

import CryptoKit
import Foundation
import FernletCrypto
import FernletFoundation

// MARK: - MeshSessionSealRefusal

/// A seal or open that was **refused**, naming what was refused and why (plan §20.2).
///
/// Distinct from a deferral in kind, not in degree: a deferral says "ask again", a refusal says
/// "this cannot be done under the present custody". Both are distinct from `absent`, which says
/// "there is genuinely nothing here" — the one answer a writer may treat as a green field.
///
/// Thrown by `MeshSessionStore.save(_:token:)` and carried in
/// ``MeshSessionLoad/refused(_:)``; frozen English throughout (a refusal reason is a log token, not
/// display copy).
nonisolated struct MeshSessionSealRefusal: Error, Equatable, Sendable {

    /// Which half of the store refused.
    nonisolated enum Operation: String, Equatable, Sendable {
        /// A write refused; nothing reached the disk.
        case seal
        /// A read refused; the bytes exist and cannot be opened under this custody.
        case open
    }

    /// Why it refused. Every case is terminal *for this attempt* and none of them means "empty".
    nonisolated enum Cause: String, Equatable, Sendable {
        /// `DeviceBindingID` produced no durable install binding, so v3 cannot be minted or its
        /// AAD reconstructed. The canonical D4 refusal — the pre-first-unlock window.
        case installBindingUnavailable
        /// A sealed file exists but its keychain row is authoritatively gone. Nothing can open
        /// these bytes again; deleting them is a decision, not a fallback.
        case sealKeyMissingForSealedFile
        /// The keychain row exists but is not a 32-byte key. It never sealed anything readable,
        /// and overwriting it blindly would destroy whatever did.
        case sealKeyMalformed
        /// A freshly minted key did not survive its read-back verify, so sealing against it would
        /// write ciphertext nothing can ever open.
        case sealKeyNotPersisted
        /// The blob claims an at-rest generation this build no longer reads (`ColumnCrypto` v2 or
        /// the unprefixed legacy format). Named rather than reported as an authentication failure,
        /// because nothing is wrong with the ciphertext.
        case retiredAtRestFormat
    }

    /// Whether the refusal happened while sealing or while opening.
    let operation: Operation

    /// The named reason.
    let cause: Cause

    /// A frozen-English one-liner for logs and test failure messages. Never localized, never shown
    /// to a user as-is.
    var summary: String { "mesh session context: \(operation.rawValue) refused — \(cause.rawValue)" }
}

// MARK: - MeshSessionDeferral

/// A load or save that could not proceed **right now** and must be retried, with nothing decided
/// and nothing written.
///
/// Deliberately coarse on the read side: any file read error is a deferral, never "absent". That
/// asymmetry is the same one `ProtectedSidecar` documents — a `.completeFileProtection…` file
/// touched while the device is locked reads as an error, and treating an error as emptiness is how
/// a store overwrites its own data.
nonisolated struct MeshSessionDeferral: Equatable, Sendable {

    /// Why the attempt was deferred.
    nonisolated enum Reason: String, Equatable, Sendable {
        /// The keychain could not answer for the seal key (locked, interaction required, transient
        /// failure). The row's existence is UNKNOWN, which is exactly why this is not a refusal.
        case sealKeyTransientlyUnreadable
        /// The install-binding keychain read errored, which `DeviceBindingID` defines as retryable
        /// — as opposed to an authoritatively absent binding, which refuses.
        case installBindingReadError
        /// The file exists but could not be read. Protected-data-unavailable and ordinary I/O
        /// errors are one case on purpose: neither is licence to overwrite.
        case fileUnreadable
    }

    /// The named reason.
    let reason: Reason

    /// Frozen-English detail for logs (an underlying error description, or the seam that deferred).
    let detail: String
}

// MARK: - MeshSessionCorruption

/// A sealed file that exists, is readable, and is not a context this build can use.
///
/// Corrupt is NOT absent and NOT refused: the bytes are here, the custody is fine, and they still
/// do not decode. Recovering from it is an explicit act —
/// ``MeshSessionStore/quarantineCorruptFile(_:)`` — never an implicit overwrite.
nonisolated struct MeshSessionCorruption: Equatable, Sendable {

    /// What is wrong with the bytes.
    nonisolated enum Detail: Equatable, Sendable {
        /// Zero bytes on disk. No writer produces an empty file, so this is a store fault.
        case emptyFile
        /// The blob decrypted but the JSON did not decode as a context. Carries the decoder's
        /// description.
        case undecodableJSON(String)
        /// The JSON decoded far enough to read a `schemaVersion` this build does not own.
        case unsupportedSchemaVersion(Int)
        /// Poly1305 authentication failed: truncated, tampered with, or sealed under a different
        /// key or install.
        case authenticationFailed
    }

    /// What is wrong.
    let detail: Detail
}

// MARK: - MeshSessionLoad

/// The **five-state** result of loading the sealed session context (plan invariant 7 + §20.2's
/// fifth consideration).
///
/// | state | meaning | may a writer overwrite? |
/// | --- | --- | --- |
/// | ``loaded(_:_:)`` | a context is in hand | yes — token vended |
/// | ``absent(_:)`` | no file; genuinely a green field | yes — token vended |
/// | ``deferred(_:)`` | ask again; nothing is known | **no** |
/// | ``corrupt(_:)`` | bytes exist and do not decode | **no**, until quarantined |
/// | ``refused(_:)`` | custody refuses; the field may be full | **no** |
///
/// The last three carry no ``MeshSessionStore/LoadToken``, and `save` cannot be called without one.
/// That is the type-level form of "seal refused ≠ deferred ≠ absent": there is no way to hold a
/// refusal and still address the writer.
nonisolated enum MeshSessionLoad: Equatable, Sendable {
    /// A context was opened. The token authorises writing back to the same file.
    case loaded(MeshSessionContext, MeshSessionStore.LoadToken)
    /// There is no file. The only other state that vends a write token.
    case absent(MeshSessionStore.LoadToken)
    /// Retry later; nothing was decided and nothing may be written.
    case deferred(MeshSessionDeferral)
    /// The file is present and undecodable. Quarantine it deliberately before writing.
    case corrupt(MeshSessionCorruption)
    /// Custody refused, naming what it refused. **Never** read as "no prior context".
    case refused(MeshSessionSealRefusal)
}

// MARK: - MeshSessionSaveError

/// Why a save did not happen. A thrown error always means **nothing durable changed**.
nonisolated enum MeshSessionSaveError: Error, Equatable, Sendable {
    /// The token was minted by a store on a different file. Guards against a token from one scope
    /// authorising a write into another — the type-level guard's runtime half.
    case tokenFromAnotherStore
    /// The write could not proceed right now; retry.
    case deferred(MeshSessionDeferral)
    /// The bytes could not be written (directory creation or the atomic write failed). Carries the
    /// underlying description.
    case notWritten(String)
}

// MARK: - MeshSessionStore

/// The sealed, per-scope store for one device's ``MeshSessionContext`` (plan §8.1, §20.4.2).
///
/// ## Invariants
///
/// 1. **Durable before acknowledged (plan §3.6).** ``save(_:token:)`` returns only after the bytes
///    are on disk. If it cannot seal, it throws — a caller must not acknowledge a membership
///    record, a custody receipt, or a "joined" it could not persist, because force-quit gives no
///    callback to save you afterwards.
/// 2. **A refusal is never an absence.** ``load()`` has five states, and only `loaded` and `absent`
///    vend a ``LoadToken``. A caller holding `refused`, `deferred` or `corrupt` structurally cannot
///    call the writer.
/// 3. **No plaintext writer exists.** Every byte goes through `ColumnCrypto`'s v3 path under
///    `FernletCryptoPurpose.KeyDerivation.meshSessionContextV1`, sealed with this install's
///    `DeviceBindingID` in the AAD.
/// 4. **The group control key is not here.** `MeshGroupKey` stays memory-only, forever (plan
///    §8.1). This store is what makes that doc guard load-bearing rather than incidental.
/// 5. **Per-instance scope.** Directory *and* keychain service come from
///    ``MeshSessionStorageScope`` at init, so no two live stores share state — the shared-disk-root
///    flake family gains no member (`MeshSessionStoreIsolationTests`).
///
/// ## Concurrency
///
/// A `nonisolated`, `Sendable` value with no mutable state: every call re-reads the file and the
/// key, so there is no cache to go stale and nothing to synchronise. Callers that need
/// serialisation own it (the session manager, item 2b).
public nonisolated struct MeshSessionStore: Sendable {

    /// Permission to write, vended only by a ``MeshSessionLoad`` that established the field is
    /// safe to write: `loaded` (we read what is there) or `absent` (there is nothing there).
    ///
    /// Its initialiser is `fileprivate`, so nothing outside this file can mint one — a caller
    /// cannot construct a token from a refusal, and there is no "force" overload. The stored file
    /// URL is checked at save time so a token from one scope cannot authorise a write into another.
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
        case deferred(MeshSessionDeferral)
    }

    /// Name of the sealed sidecar inside the scope's directory.
    static let fileName = "MeshSessionContext.sealed"

    /// Extension appended when a corrupt file is set aside.
    static let quarantineExtension = "corrupt"

    /// This store's directory + keychain service.
    let scope: MeshSessionStorageScope

    /// The one sealing path, bound to this surface's reviewed purpose.
    private let crypto = ColumnCrypto(purpose: FernletCryptoPurpose.KeyDerivation.meshSessionContextV1)

    /// Builds a store on one scope.
    ///
    /// - Parameter scope: Directory + keychain service. Pass ``MeshSessionStorageScope/production``
    ///   in the app; tests pass a temp directory and a unique service.
    init(scope: MeshSessionStorageScope) {
        self.scope = scope
    }

    /// The sealed context file.
    var fileURL: URL {
        scope.directory.appendingPathComponent(Self.fileName, isDirectory: false)
    }

    /// Where a corrupt file is moved so it is preserved rather than destroyed.
    var quarantineURL: URL {
        fileURL.appendingPathExtension(Self.quarantineExtension)
    }

    // MARK: Load

    /// Loads the sealed context, classified into all five states.
    ///
    /// Ordering is deliberate: the FILE is classified before the key is fetched, so a missing file
    /// answers `absent` without ever consulting custody, and a present file that cannot be read
    /// answers `deferred` rather than pretending to be empty.
    ///
    /// - Returns: One of the five ``MeshSessionLoad`` states. Only two of them carry a write token.
    func load() -> MeshSessionLoad {
        let raw: Data
        switch readFile() {
        case .absent:
            return .absent(LoadToken(fileURL: fileURL))
        case .deferred(let deferral):
            return .deferred(deferral)
        case .bytes(let data):
            raw = data
        }
        guard !raw.isEmpty else {
            return .corrupt(MeshSessionCorruption(detail: .emptyFile))
        }
        switch MeshSessionSealKey.forOpen(service: scope.keychainService) {
        case .available(let key):
            return openContext(from: raw, contentKey: key)
        case .deferred(let reason):
            return .deferred(MeshSessionDeferral(reason: reason, detail: Self.fileName))
        case .refused(let cause):
            return .refused(MeshSessionSealRefusal(operation: .open, cause: cause))
        }
    }

    /// Opens sealed bytes into a context, mapping every failure onto the state it belongs in.
    ///
    /// The three-way split of `ColumnCrypto`'s errors is the point: a retryable binding READ error
    /// defers, an authoritatively absent binding refuses, and anything wrong with the BYTES is
    /// corruption. Collapsing any pair loses the distinction plan §20.2 exists to preserve.
    private func openContext(from raw: Data, contentKey: SymmetricKey) -> MeshSessionLoad {
        do {
            let context: MeshSessionContext? = try crypto.open(raw, contentKey: contentKey)
            guard let context else {
                return .corrupt(MeshSessionCorruption(detail: .authenticationFailed))
            }
            return .loaded(context, LoadToken(fileURL: fileURL))
        } catch MeshSessionContextDecodingError.unsupportedSchemaVersion(let version) {
            return .corrupt(MeshSessionCorruption(detail: .unsupportedSchemaVersion(version)))
        } catch let error as ColumnCrypto.SealedColumnOpenError {
            return Self.loadState(forOpenError: error)
        } catch is DeviceBindingID.ReadError {
            return .deferred(MeshSessionDeferral(reason: .installBindingReadError, detail: Self.fileName))
        } catch let error as DecodingError {
            return .corrupt(MeshSessionCorruption(detail: .undecodableJSON(String(describing: error))))
        } catch {
            return .corrupt(MeshSessionCorruption(detail: .authenticationFailed))
        }
    }

    /// Maps `ColumnCrypto`'s named open refusals onto load states.
    ///
    /// `installBindingMissing` is a REFUSAL (custody, not content — the ciphertext is fine); a
    /// retired format is a refusal too, and by name, so the log says "this build stopped reading
    /// that generation" rather than "authentication failed"; an empty column is corruption.
    private static func loadState(forOpenError error: ColumnCrypto.SealedColumnOpenError) -> MeshSessionLoad {
        switch error {
        case .installBindingMissing:
            return .refused(MeshSessionSealRefusal(operation: .open, cause: .installBindingUnavailable))
        case .retiredFormat:
            return .refused(MeshSessionSealRefusal(operation: .open, cause: .retiredAtRestFormat))
        case .emptyBlob:
            return .corrupt(MeshSessionCorruption(detail: .emptyFile))
        }
    }

    /// Classifies the raw file read. A read error is NEVER reported as absence.
    private func readFile() -> FileRead {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return .absent }
        do {
            return .bytes(try Data(contentsOf: fileURL))
        } catch {
            return .deferred(MeshSessionDeferral(reason: .fileUnreadable, detail: String(describing: error)))
        }
    }

    // MARK: Save

    /// Seals `context` and writes it, atomically, under the token's authority.
    ///
    /// Durable before acknowledged: this returns only when the bytes are on disk. Every failure
    /// path throws with the previous file untouched — a refused seal never truncates, never writes
    /// a partial file, and never degrades to an un-domained format.
    ///
    /// - Parameters:
    ///   - context: The context to persist.
    ///   - token: Permission from a `loaded` or `absent` load of THIS store.
    /// - Throws: ``MeshSessionSealRefusal`` when custody refuses, ``MeshSessionSaveError`` when the
    ///   token belongs elsewhere, the attempt must be retried, or the write itself failed.
    func save(_ context: MeshSessionContext, token: LoadToken) throws {
        guard token.fileURL == fileURL else { throw MeshSessionSaveError.tokenFromAnotherStore }
        let contentKey: SymmetricKey
        switch MeshSessionSealKey.forSeal(service: scope.keychainService) {
        case .available(let key):
            contentKey = key
        case .deferred(let reason):
            throw MeshSessionSaveError.deferred(MeshSessionDeferral(reason: reason, detail: Self.fileName))
        case .refused(let cause):
            throw MeshSessionSealRefusal(operation: .seal, cause: cause)
        }
        let sealed = try sealBytes(context, contentKey: contentKey)
        try writeAtomically(sealed)
    }

    /// Seals the context, translating `ColumnCrypto`'s D4 refusal into this store's named one.
    private func sealBytes(_ context: MeshSessionContext, contentKey: SymmetricKey) throws -> Data {
        do {
            return try crypto.seal(context, contentKey: contentKey)
        } catch ColumnCrypto.SealedColumnStrictSealError.bindingUnavailable {
            throw MeshSessionSealRefusal(operation: .seal, cause: .installBindingUnavailable)
        }
    }

    /// Creates the directory if needed, then writes the bytes atomically (temp file + rename, which
    /// is what `.atomic` performs) with the file protection this surface's custody requires.
    ///
    /// `.completeFileProtectionUntilFirstUserAuthentication`, not `.completeFileProtection`: a mesh
    /// session continues in the background with the device locked, and a file that cannot be
    /// written then is a membership record that cannot be acknowledged. The bytes are sealed and
    /// device-bound regardless, so this is protection class, not the whole protection.
    ///
    /// Backup exclusion is best-effort defence in depth — the context is device-scoped ephemeral
    /// state whose key is `ThisDeviceOnly`, so it could never be opened from a restored backup
    /// anyway — but a failure is audited rather than swallowed.
    private func writeAtomically(_ bytes: Data) throws {
        do {
            try FileManager.default.createDirectory(
                at: scope.directory,
                withIntermediateDirectories: true
            )
            try bytes.write(
                to: fileURL,
                options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication]
            )
        } catch {
            throw MeshSessionSaveError.notWritten(String(describing: error))
        }
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var mutableURL = fileURL
        do {
            try mutableURL.setResourceValues(values)
        } catch {
            FernletAuditLog.log(
                "mesh.sessionContext.backupExclusionFailed",
                context: ["error": String(describing: error)]
            )
        }
    }

    // MARK: Recovery and wipe

    /// Sets a corrupt file aside and vends a write token for the now-empty field.
    ///
    /// The ONLY route from ``MeshSessionLoad/corrupt(_:)`` to a writer, and it is explicit for a
    /// reason: the bytes are preserved beside the file rather than deleted, so a corruption is
    /// investigable instead of merely survived. Requiring the corruption value as an argument means
    /// a caller cannot reach this path without having classified the file first.
    ///
    /// - Parameter corruption: The classification that justified the quarantine; audited.
    /// - Returns: A token authorising a fresh write.
    /// - Throws: A file-system error if the file could not be moved — in which case no token is
    ///   vended and the corrupt bytes stay exactly where they are.
    func quarantineCorruptFile(_ corruption: MeshSessionCorruption) throws -> LoadToken {
        let manager = FileManager.default
        guard manager.fileExists(atPath: fileURL.path) else { return LoadToken(fileURL: fileURL) }
        if manager.fileExists(atPath: quarantineURL.path) {
            try manager.removeItem(at: quarantineURL)
        }
        try manager.moveItem(at: fileURL, to: quarantineURL)
        FernletAuditLog.log(
            "mesh.sessionContext.quarantined",
            context: ["detail": String(describing: corruption.detail)]
        )
        return LoadToken(fileURL: fileURL)
    }

    /// Destroys this scope's sealed context — the file, its quarantine sibling, and the keychain
    /// row that seals them — for "Delete everything"
    /// (Docs/PrivacyWipeCoverage.md; plan §17.3).
    ///
    /// Both halves together, always: files whose key survives are ciphertext nobody can read, and a
    /// key whose files survive is a promise to decrypt them. A missing file counts as success — the
    /// funnel asks for the end state, not for work to have been done.
    ///
    /// - Parameter scope: The scope to wipe.
    /// - Returns: `false` if a file that existed could not be removed, so the funnel can report an
    ///   incomplete store. R7: the result is not discardable.
    @discardableResult
    public static func wipeForDeleteAll(scope: MeshSessionStorageScope) -> Bool {
        let store = MeshSessionStore(scope: scope)
        let fileRemoved = removeIfPresent(store.fileURL)
        let quarantineRemoved = removeIfPresent(store.quarantineURL)
        MeshSessionSealKey.wipe(service: scope.keychainService)
        return fileRemoved && quarantineRemoved
    }

    /// Removes `url` if it exists, auditing (not swallowing) a failure.
    private static func removeIfPresent(_ url: URL) -> Bool {
        guard FileManager.default.fileExists(atPath: url.path) else { return true }
        do {
            try FileManager.default.removeItem(at: url)
            return true
        } catch {
            FernletAuditLog.log(
                "mesh.sessionContext.wipeFailed",
                context: ["error": String(describing: error)]
            )
            return false
        }
    }
}
