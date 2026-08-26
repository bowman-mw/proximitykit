import Foundation
import CryptoKit
import FernletCrypto
import Security
import FernletFoundation

/// Keychain-backed ChaChaPoly seal for the heart-drop sidecars (Increment 4 of
/// Docs/Plan-Prekeys-ProtectedLoad-CoachMesh-2026-07-26.md).
///
/// What the plaintext sidecars exposed: `friendSigningKey` joins directly against the trust
/// vault (names WHICH friend), `createdAt` gives the second, and `recordName` proves this
/// device wrote that public-DB record — a timestamped log of who the user sent affection to,
/// with proof of authorship. Sealing closes file-only exfiltration (unencrypted backups,
/// app-group read bugs, a future export walker).
///
/// The file protection class stays `.completeFileProtection` and the key is
/// `WhenUnlockedThisDeviceOnly` on purpose: sealing alone is a strict gain, but sealing plus an
/// after-first-unlock key would hand an AFU-state attacker both the ciphertext and the key that
/// opens it — a net loss. Relax only when a background writer genuinely exists, and then only
/// for the store that writer must write, moving the key's accessibility in the same commit.
///
/// Wipe: the key lives under the existing `com.fernlet.heartdrop` service, so
/// `HeartPrekeyStore.wipeForDeleteAll()`'s `KeychainItem.deleteAll(service:)` already removes it
/// — no new wipe-manifest row (the service is a documented `knownKeychainServices` entry).
public enum HeartDropSidecarSeal {

    /// Same service as the prekey blob so both share the delete-all fate — the invariant
    /// ``HeartDropStorageScope`` carries as a single value, and the reason a scope has to move the
    /// key along with the files.
    public static let keychainService = HeartPrekeyStore.keychainService
    static let keychainAccount = "sidecarSealKey"
    /// Read-only v1 prefix. Its box had no AAD, so it cannot be relabelled in place.
    static let legacyMagic = Data("FSC1".utf8)
    /// Current prefix. v2 authenticates a stable sidecar purpose, separating it from every other
    /// blob that could ever be sealed under this service's reusable key.
    static let magic = Data("FSC2".utf8)

    /// The seal for the three heart-drop sidecars, on whichever service the caller's
    /// ``HeartDropStorageScope`` names — `com.fernlet.heartdrop` in production, a UUID-scoped
    /// service for a test store (IdentityServiceTests convention). Constructed per store; the key
    /// is one keychain row per service, read on each use (no in-memory cache, so a wiped key can
    /// never be resurrected by a stale copy).
    ///
    /// There is deliberately no argument-less production variant: every caller states its scope, so
    /// a store cannot end up with isolated files sealed by a key somebody else's wipe deletes.
    public static func make(keychainService service: String) -> SidecarSeal {
        SidecarSeal(
            isSealed: { $0.starts(with: magic) || $0.starts(with: legacyMagic) },
            open: { data in
                let key = try loadKeyForOpen(service: service)
                do {
                    if data.starts(with: magic) {
                        let box = try ChaChaPoly.SealedBox(combined: data.dropFirst(magic.count))
                        return try ChaChaPoly.open(
                            box,
                            using: key,
                            authenticating: FernletCryptoPurpose.AEAD.heartDropSidecarV2.data
                        )
                    }
                    let box = try ChaChaPoly.SealedBox(combined: data.dropFirst(legacyMagic.count))
                    return try ChaChaPoly.open(box, using: key) // cryptographic-domain: legacy-read
                } catch {
                    throw SidecarSeal.SealError.openFailed
                }
            },
            seal: { plaintext in
                let key = try loadOrMintKey(service: service)
                do {
                    let box = try ChaChaPoly.seal(
                        plaintext,
                        using: key,
                        authenticating: FernletCryptoPurpose.AEAD.heartDropSidecarV2.data
                    )
                    return magic + box.combined
                } catch {
                    throw SidecarSeal.SealError.sealFailed
                }
            }
        )
    }

    // MARK: - Key management

    private static func loadKeyForOpen(service: String) throws -> SymmetricKey {
        switch KeychainItem.loadDistinguishingAbsence(account: keychainAccount, service: service) {
        case .found(let data) where data.count == 32:
            return SymmetricKey(data: data)
        case .found:
            // A malformed key row can never have sealed anything readable.
            throw SidecarSeal.SealError.openFailed
        case .absent:
            throw SidecarSeal.SealError.keyMissingForSealedFile
        case .unreadable:
            throw SidecarSeal.SealError.keyTransientlyUnavailable
        }
    }

    private static func loadOrMintKey(service: String) throws -> SymmetricKey {
        switch KeychainItem.loadDistinguishingAbsence(account: keychainAccount, service: service) {
        case .found(let data) where data.count == 32:
            return SymmetricKey(data: data)
        case .found:
            // Malformed row: refuse to seal rather than silently overwrite whatever put it there.
            throw SidecarSeal.SealError.sealFailed
        case .unreadable:
            throw SidecarSeal.SealError.keyTransientlyUnavailable
        case .absent:
            // R9: mint the raw bytes first and build the key from them, so the keychain row needs
            // no `withUnsafeBytes` export of a CryptoKit key. `UInt8.random(in:)` draws from
            // `SystemRandomNumberGenerator`, the platform CSPRNG — the same source `SymmetricKey`
            // uses.
            let keyData = Data((0..<32).map { _ in UInt8.random(in: UInt8.min...UInt8.max) })
            let key = SymmetricKey(data: keyData)
            let status = KeychainItem.store(
                keyData,
                account: keychainAccount,
                service: service,
                accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                synchronizable: false
            )
            guard status == errSecSuccess else {
                throw SidecarSeal.SealError.keyTransientlyUnavailable
            }
            // Read-back-verify BEFORE sealing anything: a full or locked keychain can silently
            // drop the row, and sealing against an unverified key writes ciphertext nothing can
            // ever open (bitchat's MessageOutboxStore does the same).
            guard case .found(let echoed) = KeychainItem.loadDistinguishingAbsence(account: keychainAccount, service: service), echoed == keyData else {
                FernletAuditLog.log("heartdrop.sidecarKey.verifyFailed")
                throw SidecarSeal.SealError.sealFailed
            }
            return key
        }
    }
}
