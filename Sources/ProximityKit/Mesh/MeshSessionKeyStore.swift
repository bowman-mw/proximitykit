// MeshSessionKeyStore.swift
// ProximityKit/Mesh
//
// Where ONE device's sealed mesh-session state lives — the sidecar directory and the keychain
// service holding the key that seals it — plus the key row itself.
//
// Both halves travel in one value for the reason FernletSocial's `HeartDropStorageScope` documents at
// length: a scope that isolated only the directory would be cosmetic, because a wipe elsewhere in the
// process still deletes the shared key and the isolated file then opens for nobody.

import CryptoKit
import Foundation
import Security

// MARK: - MeshSessionStorageScope

/// The storage identity of one device's sealed mesh-session state: the directory holding
/// `MeshSessionContext.sealed` (and its `.corrupt` quarantine sibling) and the keychain service
/// holding the key that seals it, plus the host's ``ProximityNamespace``, whose
/// `installation.storage` and `installation.keychain` name the file and the key's account (plan step
/// A0.2.8; Fernlet's are the names above) and whose `family.purposes` holds the file's column seal,
/// and the host's ``ProximityInstallBinding``, which every seal and open of the file reads (plan step
/// A0.2.9).
///
/// **Why the two travel together.** `MeshSessionStore.wipeForDeleteAll(scope:)` destroys both, so
/// isolating one without the other isolates nothing: files on a private root sealed by a shared key
/// survive somebody else's wipe as ciphertext nothing can open, which is strictly worse than losing
/// them. Same lesson, same shape, as FernletSocial's `HeartDropStorageScope`.
///
/// **Why that matters outside production.** XCTest and Swift Testing suites run in parallel in ONE
/// process, so on the production scope every live store shares one file and one key, and any test
/// running "delete everything" destroys both for every concurrently-running suite. That is the
/// shared-disk-root flake family (`PhotoDirectoryIsolationTests`), and this scope is what keeps it
/// from gaining a new member — `MeshSessionStoreIsolationTests` is the grep-wall that enforces it.
/// A host's shipped scope is ``production(for:installBinding:)``. Fernlet's app derives each store's
/// service instead, through FernletSocial's `keychainService(besideHeartDrop:in:)` extension of this
/// type, which maps the production heart-drop service to that same production service and an
/// isolated one to a sibling of its own.
///
/// `nonisolated` against the module's `defaultIsolation(MainActor.self)`: configuration, read from
/// nonisolated stores and from `FernletStore`'s nonisolated stored properties. Not `Equatable` since
/// plan step A0.2.9: it carries the host's install binding, a capability with no equality.
public nonisolated struct MeshSessionStorageScope: Sendable {

    /// The host's protocol identity: the store reads its file name off
    /// `installation.storage.meshSessionContextFileName` and its seal key's account off
    /// `installation.keychain.meshSessionSealKey.account` (plan step A0.2.8), and seals the file under
    /// `family.purposes.keyDerivation.meshSessionContextV1` (plan step A0.2.9). None of it is an
    /// isolation axis — ``directory`` and ``keychainService`` are — so two scopes of one host differ
    /// in those two alone.
    public let namespace: ProximityNamespace

    /// Directory holding `MeshSessionContext.sealed` and its `.corrupt` quarantine sibling.
    public let directory: URL

    /// Keychain service holding the seal key for the files in ``directory``.
    public let keychainService: String

    /// The host's install binding, which the store's column seal reads at every seal and every open
    /// and places after the column label in the file's authenticated data (plan step A0.2.9). Not an
    /// isolation axis either: one install has one binding, which every scope of the host carries.
    public let installBinding: any ProximityInstallBinding

    /// Builds a scope from the host's namespace, a directory, a keychain service and its install
    /// binding.
    ///
    /// - Parameters:
    ///   - namespace: The host's protocol identity, which names the file and the key's account and
    ///     holds the file's column seal.
    ///   - directory: Where the sealed context file lives.
    ///   - keychainService: Keychain service holding that file's seal key.
    ///   - installBinding: The host's install binding, which the file is sealed and opened under.
    public init(
        namespace: ProximityNamespace,
        directory: URL,
        keychainService: String,
        installBinding: any ProximityInstallBinding
    ) {
        self.namespace = namespace
        self.directory = directory
        self.keychainService = keychainService
        self.installBinding = installBinding
    }

    /// The shipped scope of a host: the namespace's `installation.storage.defaultDirectory` (for
    /// Fernlet `Application Support/Fernlet`, the path every proximity sidecar already uses) plus its
    /// `installation.keychain.meshSessionSealKey.service` (for Fernlet `com.fernlet.mesh-session`: its
    /// own service, not a lodger under `com.fernlet.heartdrop`, because delete-all takes this one
    /// whole while the heart-drop service has a different survivor story, and one service per fate
    /// is the only arrangement a service-wide delete can express honestly). Replaces the static
    /// `production` and `productionKeychainService` (plan step A0.2.8); takes the host's install
    /// binding since plan step A0.2.9.
    ///
    /// - Parameters:
    ///   - namespace: The host's protocol identity.
    ///   - installBinding: The host's install binding.
    /// - Returns: The namespace's production scope.
    public static func production(
        for namespace: ProximityNamespace,
        installBinding: any ProximityInstallBinding
    ) -> MeshSessionStorageScope {
        MeshSessionStorageScope(
            namespace: namespace,
            directory: namespace.installation.storage.defaultDirectory,
            keychainService: namespace.installation.keychain.meshSessionSealKey.service,
            installBinding: installBinding
        )
    }
}

// MARK: - MeshSessionSealKeyOutcome

/// The result of asking for the mesh-session seal key, in the three shapes the store's five-state
/// load has to keep apart.
///
/// The whole point is that "no key right now" is never one answer. A transient keychain outage must
/// defer (retry later, touch nothing); a definitively absent key over existing ciphertext must
/// refuse by name (nobody can ever open those bytes, and a caller must not read that as an empty
/// field it may overwrite).
nonisolated enum MeshSessionSealKeyOutcome: Sendable {
    /// The key is in hand.
    case available(SymmetricKey)
    /// The keychain could not answer right now. Retryable; nothing has been decided.
    case deferred(MeshSessionDeferral.Reason)
    /// Terminal for this attempt, and named: the row is gone, malformed, or could not be persisted.
    case refused(MeshSessionSealRefusal.Cause)
}

// MARK: - MeshSessionSealKey

/// The keychain-backed content key that seals ``MeshSessionContext``.
///
/// A **sibling custody row beside the friend photo wall's `friendWall` key**, and deliberately not
/// another case inside `KeychainPrivateMediaKeyProvider.Role`: that provider vends the at-rest
/// MEDIA keys, and its contract is that NONE is deleted by "delete everything". This row's
/// contract is the opposite — a mesh session is ephemeral state (6-hour ceiling) that a wipe must
/// take with it — so it gets its own service, its own accessibility, and its own wipe row rather
/// than contradicting that one in place.
///
/// ## Custody
///
/// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, the keychain counterpart of the sealed
/// file's `.completeFileProtectionUntilFirstUserAuthentication`:
/// - **After first unlock**, not `WhenUnlocked`, because a mesh session legitimately continues in
///   the background while the device is locked (plan §8.2's `continuingInBackground`), and a
///   `WhenUnlocked` key would make every background membership acceptance unsealable — which,
///   under durable-before-acknowledged (plan §3.6), means unacceptable.
/// - **ThisDeviceOnly**, because the sealed bytes are device-bound anyway: `ProximityColumnCrypto`'s
///   V3 format authenticates this install's binding (the host's ``ProximityInstallBinding``; Fernlet's
///   `DeviceBindingID`), so a key restored onto another phone would open nothing. A
///   backup-restorable row would be a promise the ciphertext cannot keep.
///
/// The key is read on every use with no in-memory cache, so a wiped key can never be resurrected by
/// a stale copy — the same rule FernletSocial's `HeartDropSidecarSeal` follows.
///
/// There is deliberately no argument-less production variant: every caller states its scope's service
/// and account.
nonisolated enum MeshSessionSealKey {

    /// Key length in bytes.
    static let keyByteCount = 32

    /// Reads the key for OPENING an existing sealed file. Never mints: a fresh random key opens
    /// nothing, and writing one would install a row that later looks authoritative.
    ///
    /// - Parameters:
    ///   - service: The scope's keychain service.
    ///   - account: The row's account, the scope namespace's
    ///     `installation.keychain.meshSessionSealKey.account` (plan step A0.2.8).
    /// - Returns: The key, a deferral (keychain unreadable — retry), or a refusal (row absent or
    ///   malformed, so these bytes are terminally unopenable).
    static func forOpen(service: String, account: String) -> MeshSessionSealKeyOutcome {
        switch ProximityKeychainItem.loadDistinguishingAbsence(account: account, service: service) {
        case .found(let data) where data.count == keyByteCount:
            return .available(SymmetricKey(data: data))
        case .found:
            return .refused(.sealKeyMalformed)
        case .absent:
            return .refused(.sealKeyMissingForSealedFile)
        case .unreadable:
            return .deferred(.sealKeyTransientlyUnreadable)
        }
    }

    /// Reads the key for SEALING, minting one only when the keychain reports the row
    /// **definitively** absent.
    ///
    /// The absent-vs-unreadable distinction is the whole safety property: a plain "read returned
    /// nil ⇒ mint" would, during the window before the first post-boot unlock, replace the real key
    /// and turn every sealed context into permanent garbage with no failure signal.
    ///
    /// - Parameters:
    ///   - service: The scope's keychain service.
    ///   - account: The row's account, the scope namespace's
    ///     `installation.keychain.meshSessionSealKey.account` (plan step A0.2.8).
    /// - Returns: The key, a deferral, or a refusal naming why no key could be established.
    static func forSeal(service: String, account: String) -> MeshSessionSealKeyOutcome {
        switch ProximityKeychainItem.loadDistinguishingAbsence(account: account, service: service) {
        case .found(let data) where data.count == keyByteCount:
            return .available(SymmetricKey(data: data))
        case .found:
            // Refuse rather than silently overwrite whatever put a malformed row here.
            return .refused(.sealKeyMalformed)
        case .unreadable:
            return .deferred(.sealKeyTransientlyUnreadable)
        case .absent:
            return mint(service: service, account: account)
        }
    }

    /// Deletes every row under the scope's service. Used by the delete-all funnel; the file half is
    /// `MeshSessionStore.wipeForDeleteAll(scope:)`.
    ///
    /// - Parameter service: The scope's keychain service.
    static func wipe(service: String) {
        ProximityKeychainItem.deleteAll(service: service)
    }

    /// Mints, stores and READ-BACK-VERIFIES a fresh key.
    ///
    /// The verify is not ceremony: a full or locked keychain can silently drop the row, and sealing
    /// against an unverified key writes ciphertext nothing can ever open.
    private static func mint(service: String, account: String) -> MeshSessionSealKeyOutcome {
        // R5/R9: mint the raw bytes and build the key from them, so no `withUnsafeBytes` export of
        // a CryptoKit key is needed. `UInt8.random(in:)` draws from `SystemRandomNumberGenerator`,
        // the platform CSPRNG — the same source `SymmetricKey` uses.
        let keyData = Data((0..<keyByteCount).map { _ in UInt8.random(in: UInt8.min...UInt8.max) })
        let status = ProximityKeychainItem.store(
            keyData,
            account: account,
            service: service,
            accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            synchronizable: false
        )
        guard status == errSecSuccess else {
            return .deferred(.sealKeyTransientlyUnreadable)
        }
        guard case .found(let echoed) = ProximityKeychainItem.loadDistinguishingAbsence(
            account: account,
            service: service
        ), echoed == keyData else {
            ProximityAudit.log("mesh.sessionContext.sealKey.verifyFailed")
            return .refused(.sealKeyNotPersisted)
        }
        return .available(SymmetricKey(data: keyData))
    }
}
