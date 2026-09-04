// MeshRoutedStoreKey.swift
// ProximityKit/Mesh
//
// Network migration P5 item 3 (plan §11, §19.5): where ONE device's sealed routed-content custody
// lives — the sidecar directory holding the index and the chunk files, the keychain service holding
// the key that seals all of them — plus the key row itself.
//
// Both halves travel in one value for the reason `MeshSessionStorageScope` and
// `HeartDropStorageScope` document at length: a scope that isolated only the directory would be
// cosmetic, because a wipe elsewhere in the process still deletes the shared key and the isolated
// files then open for nobody.
//
// Its OWN keychain service, not a lodger under `com.fernlet.mesh-session`: one fate per service is
// the only arrangement a service-wide `KeychainItem.deleteAll(service:)` can express honestly, and
// sharing would let a session wipe silently orphan routed ciphertext this device is holding for
// other people.

import CryptoKit
import Foundation
import FernletCrypto
import FernletFoundation
import Security

// MARK: - MeshRoutedStorageScope

/// The storage identity of one device's sealed routed-content store: the directory holding
/// `MeshRoutedIndex.sealed` (with its `.corrupt` quarantine sibling and the `MeshRoutedChunks`
/// payload directory) and the keychain service holding the key that seals them.
///
/// **Why the two travel together.** ``MeshRoutedStore/wipeForDeleteAll(scope:)`` destroys both, so
/// isolating one without the other isolates nothing: files on a private root sealed by a shared key
/// survive somebody else's wipe as ciphertext nothing can open, which is strictly worse than losing
/// them. Same lesson, same shape, as ``MeshSessionStorageScope``.
///
/// **Why that matters outside production.** XCTest and Swift Testing suites run in parallel in ONE
/// process, so on the production scope every live store shares one index, one chunk directory and
/// one key, and any test running "delete everything" destroys all of them for every
/// concurrently-running suite. That is the shared-disk-root flake family
/// (`PhotoDirectoryIsolationTests`), and this scope is what keeps it from gaining a new member —
/// `MeshRoutedStoreIsolationTests` is the grep-wall that enforces it.
///
/// `nonisolated` against the module's `defaultIsolation(MainActor.self)`: inert configuration, read
/// from nonisolated stores and from `FernletStore`'s nonisolated stored properties.
public nonisolated struct MeshRoutedStorageScope: Sendable, Equatable {

    /// The production keychain service. Its own service, not a lodger under
    /// `com.fernlet.mesh-session`: delete-all takes this one whole
    /// (`KeychainItem.deleteAll(service:)`), and one service per fate is the only arrangement a
    /// service-wide delete can express honestly.
    public static let productionKeychainService = "com.fernlet.mesh-routed"

    /// Directory holding `MeshRoutedIndex.sealed`, its `.corrupt` quarantine sibling, and the
    /// `MeshRoutedChunks` directory of sealed payload files.
    public let directory: URL

    /// Keychain service holding the seal key for everything under ``directory``.
    public let keychainService: String

    /// Builds a scope from a directory and a keychain service.
    ///
    /// - Parameters:
    ///   - directory: Where the sealed index, its quarantine sibling and the chunk directory live.
    ///   - keychainService: Keychain service holding those files' seal key.
    public init(directory: URL, keychainService: String) {
        self.directory = directory
        self.keychainService = keychainService
    }

    /// The shipped scope: `Application Support/Fernlet` (the path every proximity sidecar already
    /// uses) plus ``productionKeychainService``.
    public static var production: MeshRoutedStorageScope {
        MeshRoutedStorageScope(
            directory: ProximitySupportLayout.defaultDirectory,
            keychainService: productionKeychainService
        )
    }

    /// The routed-store keychain service that belongs beside a given heart-drop service.
    ///
    /// The app derives its scope this way rather than carrying a fourth injectable seam, and that
    /// is a deliberate reuse of an isolation axis the test walls ALREADY enforce: every test file
    /// that reaches `deleteAllData` and builds a `FernletStore` directly is already required to
    /// pass `heartDropKeychainService:` (`PhotoDirectoryIsolationTests`), so a store isolated for
    /// hearts is isolated for routed custody for free — and one that is not fails an existing wall
    /// rather than silently sharing this key.
    ///
    /// - Parameter heartDropService: The store's heart-drop keychain service.
    /// - Returns: ``productionKeychainService`` when the input is the production heart-drop
    ///   service; a distinct sibling of the caller's isolated service otherwise.
    public static func keychainService(besideHeartDrop heartDropService: String) -> String {
        heartDropService == HeartPrekeyStore.keychainService
            ? productionKeychainService
            : heartDropService + ".mesh-routed"
    }
}

// MARK: - MeshRoutedSealKeyOutcome

/// The result of asking for the routed store's seal key, in the three shapes the store's
/// five-state load has to keep apart.
///
/// The whole point is that "no key right now" is never one answer. A transient keychain outage must
/// defer (retry later, touch nothing); a definitively absent key over existing ciphertext must
/// refuse by name (nobody can ever open those bytes, and a caller must not read that as an empty
/// field it may overwrite). ``MeshSessionSealKeyOutcome``'s sibling, deliberately identical in
/// shape so one vocabulary cannot become two.
nonisolated enum MeshRoutedSealKeyOutcome: Sendable {
    /// The key is in hand.
    case available(SymmetricKey)
    /// The keychain could not answer right now. Retryable; nothing has been decided.
    case deferred(MeshRoutedDeferral.Reason)
    /// Terminal for this attempt, and named: the row is gone, malformed, or could not be persisted.
    case refused(MeshRoutedSealRefusal.Cause)
}

// MARK: - MeshRoutedSealKey

/// The keychain-backed content key that seals the routed store's index **and every chunk file**.
///
/// One key for the whole surface, on its own service. ``MeshSessionSealKey``'s sibling row, and
/// deliberately not a second account under `com.fernlet.mesh-session`: the two surfaces have the
/// same fate today, but a separate service keeps the two wipes independently expressible and stops
/// a session wipe from orphaning routed ciphertext as unopenable bytes.
///
/// ## Custody
///
/// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, the keychain counterpart of the sealed
/// files' `.completeFileProtectionUntilFirstUserAuthentication`:
/// - **After first unlock**, not `WhenUnlocked`, because routed custody legitimately continues in
///   the background while the device is locked, and a `WhenUnlocked` key would make every
///   background custody write unsealable — which, under durable-before-acknowledged (plan §3.6),
///   means unacknowledgeable.
/// - **ThisDeviceOnly**, because the sealed bytes are device-bound anyway: `ColumnCrypto`'s v3
///   format authenticates this install's `DeviceBindingID`, so a key restored onto another phone
///   would open nothing.
///
/// The key is read on every use with no in-memory cache, so a wiped key can never be resurrected by
/// a stale copy. There is deliberately no argument-less production variant: every caller states its
/// scope.
nonisolated enum MeshRoutedSealKey {

    /// The single account under the scope's service.
    static let keychainAccount = "meshRoutedStoreKey"

    /// Key length in bytes.
    static let keyByteCount = 32

    /// Reads the key for OPENING existing sealed bytes. Never mints: a fresh random key opens
    /// nothing, and writing one would install a row that later looks authoritative.
    ///
    /// - Parameter service: The scope's keychain service.
    /// - Returns: The key, a deferral (keychain unreadable — retry), or a refusal (row absent or
    ///   malformed, so these bytes are terminally unopenable).
    static func forOpen(service: String) -> MeshRoutedSealKeyOutcome {
        switch KeychainItem.loadDistinguishingAbsence(account: keychainAccount, service: service) {
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
    /// and turn every sealed chunk file into permanent garbage with no failure signal.
    ///
    /// - Parameter service: The scope's keychain service.
    /// - Returns: The key, a deferral, or a refusal naming why no key could be established.
    static func forSeal(service: String) -> MeshRoutedSealKeyOutcome {
        switch KeychainItem.loadDistinguishingAbsence(account: keychainAccount, service: service) {
        case .found(let data) where data.count == keyByteCount:
            return .available(SymmetricKey(data: data))
        case .found:
            // Refuse rather than silently overwrite whatever put a malformed row here.
            return .refused(.sealKeyMalformed)
        case .unreadable:
            return .deferred(.sealKeyTransientlyUnreadable)
        case .absent:
            return mint(service: service)
        }
    }

    /// Deletes every row under the scope's service. Used by the delete-all funnel; the file half is
    /// ``MeshRoutedStore/wipeForDeleteAll(scope:)``.
    ///
    /// - Parameter service: The scope's keychain service.
    static func wipe(service: String) {
        KeychainItem.deleteAll(service: service)
    }

    /// Mints, stores and READ-BACK-VERIFIES a fresh key.
    ///
    /// The verify is not ceremony: a full or locked keychain can silently drop the row, and sealing
    /// against an unverified key writes ciphertext nothing can ever open — which, for a store whose
    /// whole job is durable custody, is a receipt for bytes that are already lost.
    private static func mint(service: String) -> MeshRoutedSealKeyOutcome {
        // R5/R9: mint the raw bytes and build the key from them, so no `withUnsafeBytes` export of
        // a CryptoKit key is needed. `UInt8.random(in:)` draws from `SystemRandomNumberGenerator`,
        // the platform CSPRNG — the same source `SymmetricKey` uses.
        let keyData = Data((0..<keyByteCount).map { _ in UInt8.random(in: UInt8.min...UInt8.max) })
        let status = KeychainItem.store(
            keyData,
            account: keychainAccount,
            service: service,
            accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            synchronizable: false
        )
        guard status == errSecSuccess else {
            return .deferred(.sealKeyTransientlyUnreadable)
        }
        guard case .found(let echoed) = KeychainItem.loadDistinguishingAbsence(
            account: keychainAccount,
            service: service
        ), echoed == keyData else {
            FernletAuditLog.log("mesh.routedStore.sealKey.verifyFailed")
            return .refused(.sealKeyNotPersisted)
        }
        return .available(SymmetricKey(data: keyData))
    }
}
