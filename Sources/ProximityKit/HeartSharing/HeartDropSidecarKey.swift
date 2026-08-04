import Foundation
import CryptoKit
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

    /// Same service as the prekey blob so both share the delete-all fate.
    public static let keychainService = HeartPrekeyStore.keychainService
    static let keychainAccount = "sidecarSealKey"
    /// Version prefix distinguishing a sealed file from a legacy plaintext v0 JSON file (which
    /// always starts with `[` or `{`). Bump the digit for any future format change.
    static let magic = Data("FSC1".utf8)

    /// The production seal for the three heart-drop sidecars. Constructed per store; the key is
    /// one shared keychain row, read on each use (no in-memory cache, so a wiped key can never
    /// be resurrected by a stale copy).
    public static func production() -> SidecarSeal {
        make(keychainService: keychainService)
    }

    /// UUID-scoped-service variant for tests (IdentityServiceTests convention).
    public static func make(keychainService service: String) -> SidecarSeal {
        SidecarSeal(
            isSealed: { $0.starts(with: magic) },
            open: { data in
                let key = try loadKeyForOpen(service: service)
                do {
                    let box = try ChaChaPoly.SealedBox(combined: data.dropFirst(magic.count))
                    return try ChaChaPoly.open(box, using: key)
                } catch {
                    throw SidecarSeal.SealError.openFailed
                }
            },
            seal: { plaintext in
                let key = try loadOrMintKey(service: service)
                do {
                    let box = try ChaChaPoly.seal(plaintext, using: key)
                    return magic + box.combined
                } catch {
                    throw SidecarSeal.SealError.sealFailed
                }
            }
        )
    }

    // MARK: - Key management

    private static func loadKeyForOpen(service: String) throws -> SymmetricKey {
        switch readKeyRow(service: service) {
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
        switch readKeyRow(service: service) {
        case .found(let data) where data.count == 32:
            return SymmetricKey(data: data)
        case .found:
            // Malformed row: refuse to seal rather than silently overwrite whatever put it there.
            throw SidecarSeal.SealError.sealFailed
        case .unreadable:
            throw SidecarSeal.SealError.keyTransientlyUnavailable
        case .absent:
            let key = SymmetricKey(size: .bits256)
            let keyData = key.withUnsafeBytes { Data($0) }
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
            guard case .found(let echoed) = readKeyRow(service: service), echoed == keyData else {
                FernletAuditLog.log("heartdrop.sidecarKey.verifyFailed")
                throw SidecarSeal.SealError.sealFailed
            }
            return key
        }
    }

    /// Three-way keychain read result — the absent-vs-unreadable distinction is what lets the
    /// seal fail closed on a transient error instead of minting over an unreadable key.
    private enum RowRead {
        case found(Data)
        case absent
        case unreadable(OSStatus)
    }

    /// `KeychainItem.load` collapses every failure into nil; the seal needs
    /// absent-vs-unreadable (unrecoverable vs transient), so it issues the query itself —
    /// same shape as `HeartPrekeyStore.readRow()`.
    private static func readKeyRow(service: String) -> RowRead {
        var result: AnyObject?
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: keychainAccount,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true,
            kSecUseDataProtectionKeychain as String: true
        ]
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else { return .unreadable(status) }
            return .found(data)
        case errSecItemNotFound:
            return .absent
        default:
            return .unreadable(status)
        }
    }
}
