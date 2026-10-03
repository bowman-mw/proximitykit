// ProximityKeychainItem.swift
// ProximityKit/Support
//
// ProximityKit plan step A0.2.11 (Docs/Plan-FernletCoach-ProximityKit-2026-10-01.md §4 A0.2, "Copied
// into ProximityKit: … the `KeychainItem` mechanism (not Fernlet's `Account` enum)"): the generic
// data-protection keychain accessors ProximityKit's key stores call, copied from FernletFoundation's
// `KeychainItem` member for member. Only the mechanism came across: the ten members this module used,
// the scope and result types they need, and the delete audit lines, which now go through
// `ProximityAudit` under the same event names and context. Fernlet's catalogue stayed behind: the
// `Account` names, the typed overloads, the service constants, the device sealing-key mint and the
// update-in-place primitive nothing here calls.

import Foundation
import Security

/// Generic data-protection keychain accessors for ProximityKit's key stores: a copy of
/// FernletFoundation's `KeychainItem` mechanism (plan step A0.2.11).
///
/// Every operation targets a generic-password item in the data-protection keychain
/// (`kSecUseDataProtectionKeychain`), keyed by service + account, and issues exactly the query
/// FernletFoundation's `KeychainItem` issues for the same call: the same class, keys, accessibility,
/// synchronizable value and data-protection flag. So the two are interchangeable over one keychain:
/// every row written before this copy existed reads back unchanged, and a host may still read, list or
/// clear ProximityKit's services with its own accessor (Fernlet's tests do).
/// `ProximityNamespaceGoldenTests` holds each query dictionary here to FernletFoundation's.
///
/// Two subtleties carried over unchanged:
/// - The keychain treats `kSecAttrSynchronizable` as part of an item's primary key, so an
///   iCloud-synced item and a device-only item can coexist under one service + account as two
///   distinct rows. ``SynchronizableScope`` targets one of them; the identity's backup-escrow
///   reconciliation depends on telling them apart.
/// - ``store(_:account:service:accessibility:synchronizable:replacing:)`` is delete-then-add, and its
///   `replacing` scope decides which variant the delete removes: a narrow scope when promoting an
///   escrow item, so a genuine key that just synced in is not clobbered.
///
/// ``delete(account:service:synchronizable:)`` and ``deleteAll(service:)`` audit a failed delete
/// through ``ProximityAudit`` as `keychain.delete.failed` (context `service`, `account`, `status`) and
/// `keychain.deleteAll.failed` (`service`, `status`), FernletFoundation's names and keys, so a host's
/// audit sees the lines it always saw.
///
/// Mechanism only: no account, service or accessibility class of its own. Each caller passes its
/// row's names and class, which is where the key-custody walls read them. `nonisolated`: pure
/// Security-framework calls with no shared state, called from main-actor managers and from the
/// `nonisolated` seal-key helpers alike.
nonisolated enum ProximityKeychainItem {

    /// Which synchronizable variant of an item a query should match.
    ///
    /// The default `.any` matches either (`kSecAttrSynchronizableAny`). `.synced` / `.local` tell an
    /// iCloud-Keychain-replicated item from a device-only one when both can exist under the same
    /// service + account, which the identity's backup-escrow reconciliation relies on.
    enum SynchronizableScope {
        /// Match either variant (`kSecAttrSynchronizableAny`), the default.
        case any
        /// Match only the iCloud-Keychain-replicated variant.
        case synced
        /// Match only the device-only (non-synchronizable) variant.
        case local

        /// The `kSecAttrSynchronizable` value a read or delete query carries for this scope.
        fileprivate var queryValue: Any {
            switch self {
            case .any:    return kSecAttrSynchronizableAny
            case .synced: return true
            case .local:  return false
            }
        }
    }

    /// Three-way result of a keychain read that distinguishes "no such item" from "the keychain
    /// could not be read", the distinction ``load(account:service:synchronizable:)`` collapses into
    /// `nil`. Stores that mint a fresh secret on absence use it to fail closed on a transient error
    /// instead of minting over an unreadable row.
    enum ReadResult {
        /// The item exists; carries its data.
        case found(Data)
        /// No item matches the query (`errSecItemNotFound`): safe to treat as "never stored".
        case absent
        /// The keychain call failed (any other `OSStatus`), or reported success without returning
        /// data; the item's existence is unknown, so callers must not mint a replacement.
        case unreadable(OSStatus)
    }

    /// Two-way result of a keychain enumeration that distinguishes "this service holds nothing" from
    /// "this service could not be read", the distinction ``loadAll(service:synchronizable:)``
    /// collapses into `[]`. A caller whose contract is a promise about the row set (the
    /// delete-everything funnel) uses it so an unreadable keychain cannot read as an empty one.
    enum EnumerationResult {
        /// The enumeration succeeded; carries every matching item. An empty array is a genuinely
        /// empty slot (`errSecItemNotFound`, or a success with no decodable rows), not a failure.
        case rows([(account: String, data: Data)])
        /// The keychain call failed (any status other than success and `errSecItemNotFound`), or
        /// reported success without returning the attribute array the query asked for. The row set is
        /// unknown: never treat it as empty. In the second case the carried status is `errSecSuccess`:
        /// the case, not the status, is the failure signal.
        case unreadable(OSStatus)
    }

    // MARK: - Reads and writes

    /// Stores `data`, first removing any colliding item. `replacing` controls which synchronizable
    /// variant is removed before the add: the default `.any` overwrites whatever is there; `.local`
    /// (or `.synced`) removes only that variant, for promoting a device-only escrow item without
    /// removing a genuine key that just synced in under the same account.
    ///
    /// - Returns: the `SecItemAdd` status (`errSecSuccess` on success). Not discardable (R7): a failed
    ///   add means the secret was never persisted, and every caller is minting key material whose
    ///   loss is silent until the next read.
    static func store(
        _ data: Data,
        account: String,
        service: String,
        accessibility: CFString,
        synchronizable: Bool = false,
        replacing: SynchronizableScope = .any
    ) -> OSStatus {
        // R5: an empty account/service/payload is a caller bug, not a keychain condition — SecItemAdd
        // would file a row under an empty key that no load ever finds again.
        guard !account.isEmpty, !service.isEmpty, !data.isEmpty else { return errSecParam }
        delete(account: account, service: service, synchronizable: replacing)
        let query = addQuery(data, account: account, service: service, accessibility: accessibility,
                             synchronizable: synchronizable)
        return SecItemAdd(query as CFDictionary, nil)
    }

    /// Loads the data of the single item matching `service` + `account` within `synchronizable`
    /// scope, or `nil` when no item matches (or the keychain call fails).
    static func load(account: String, service: String, synchronizable: SynchronizableScope = .any) -> Data? {
        guard !account.isEmpty, !service.isEmpty else { return nil }   // R5: no row is ever filed under an empty key.
        var result: AnyObject?
        let query = readQuery(account: account, service: service, synchronizable: synchronizable)
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return nil }
        return result as? Data
    }

    /// Loads the single item matching `service` + `account` within `synchronizable` scope,
    /// distinguishing the three outcomes ``load(account:service:synchronizable:)`` collapses:
    /// ``ReadResult/found(_:)`` with the item's data, ``ReadResult/absent`` when no item exists, and
    /// ``ReadResult/unreadable(_:)`` carrying the failing `OSStatus`. Used by every store whose
    /// mint-on-absent path must fail closed on a transient read error: the identity rows, both mesh
    /// seal keys, the heart-drop prekey blob and the sidecar seal key.
    static func loadDistinguishingAbsence(
        account: String,
        service: String,
        synchronizable: SynchronizableScope = .any
    ) -> ReadResult {
        // R5: an empty key can never have been stored, but it is a caller bug rather than a clean
        // absence — report it as unreadable so mint-on-absent callers fail closed instead of minting.
        guard !account.isEmpty, !service.isEmpty else { return .unreadable(errSecParam) }
        var result: AnyObject?
        let query = readQuery(account: account, service: service, synchronizable: synchronizable)
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

    /// Enumerates every generic-password item under `service` (optionally restricted to a
    /// synchronizable scope), returning each item's account + data. Used by the content-addressed
    /// backup-escrow store, whose keys live at accounts derived from their own public keys, so the
    /// reconcile path enumerates to discover the full set. Query `.synced` and `.local` separately to
    /// learn each row's sync status. Returns `[]` on no match or error.
    ///
    /// - Important: the error collapse is the whole difference from
    ///   ``loadAllDistinguishingFailure(service:synchronizable:)``, and it is only safe where an
    ///   unreadable service and an empty one warrant the same behavior (the escrow reconcile finds
    ///   nothing to reconcile and retries later). A caller that promises something about the row set
    ///   must use the distinguishing variant.
    static func loadAll(service: String, synchronizable: SynchronizableScope = .any) -> [(account: String, data: Data)] {
        switch loadAllDistinguishingFailure(service: service, synchronizable: synchronizable) {
        case .rows(let rows):  return rows
        case .unreadable:      return []   // the documented collapse; see the note above.
        }
    }

    /// ``loadAll(service:synchronizable:)`` reporting its outcome: the rows, or the `OSStatus` that
    /// stopped the enumeration from producing them.
    ///
    /// The distinction is load-bearing where a promise is made about the row set (that every row was
    /// found, so every row was cleared): a failed enumeration must not read as "nothing to delete"
    /// under a clean result. No store in this module makes that promise, so
    /// ``loadAll(service:synchronizable:)``, the backup-escrow reconcile's enumeration, which collapses
    /// the failure on purpose, is this member's one caller. `errSecItemNotFound` is not such a failure:
    /// a service that holds nothing lands in ``EnumerationResult/rows(_:)`` as `[]`.
    static func loadAllDistinguishingFailure(
        service: String,
        synchronizable: SynchronizableScope = .any
    ) -> EnumerationResult {
        // R5: an empty service is a caller bug rather than an empty slot — report it as unreadable so
        // a caller promising it cleared the slot fails closed instead of promising it cleared "".
        guard !service.isEmpty else { return .unreadable(errSecParam) }
        var result: AnyObject?
        let query = enumerationQuery(service: service, synchronizable: synchronizable)
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        return enumerationResult(status: status, matches: result as? [[String: Any]])
    }

    /// Classifies one `SecItemCopyMatching` enumeration into an ``EnumerationResult``: the pure
    /// status-to-outcome mapping inside ``loadAllDistinguishingFailure(service:synchronizable:)``.
    ///
    /// Split out because it is the half the wipe funnel's honesty rests on (`errSecItemNotFound` is an
    /// empty slot, every other failing status an unknown one), while the statuses that matter most
    /// (`errSecInteractionNotAllowed` before first unlock, `errSecNotAvailable`) cannot be provoked
    /// against a simulator keychain. Pure: no keychain call, no state.
    ///
    /// - Parameters:
    ///   - status: the status `SecItemCopyMatching` returned.
    ///   - matches: its out-parameter cast to the attribute dictionaries the query asked for, or `nil`
    ///     when it returned nothing (as `errSecItemNotFound` does) or a value of another shape.
    static func enumerationResult(status: OSStatus, matches: [[String: Any]]?) -> EnumerationResult {
        switch status {
        case errSecSuccess:
            guard let matches else { return .unreadable(status) }
            // Bounded: one pass over the finite row set the keychain returned. A row missing either
            // attribute is dropped rather than failing the whole enumeration — it is not one of ours.
            let rows: [(account: String, data: Data)] = matches.compactMap { item in
                guard let account = item[kSecAttrAccount as String] as? String,
                      let data = item[kSecValueData as String] as? Data else { return nil }
                return (account, data)
            }
            return .rows(rows)
        case errSecItemNotFound:
            return .rows([])
        default:
            return .unreadable(status)
        }
    }

    // MARK: - Deletes

    /// Deletes the item matching `service` + `account` within `synchronizable` scope. A no-match
    /// result is ignored, so the call is safe to make unconditionally.
    ///
    /// R7: `SecItemDelete`'s status is inspected rather than dropped. `errSecItemNotFound` is the
    /// benign outcome; anything else (`errSecInteractionNotAllowed` before first unlock,
    /// `errSecNotAvailable`) means a row the caller believes removed is still there, so it is audited
    /// as `keychain.delete.failed`, FernletFoundation's line. Use
    /// ``deleteReportingStatus(account:service:synchronizable:)`` where the caller must act on it.
    static func delete(account: String, service: String, synchronizable: SynchronizableScope = .any) {
        let status = deleteReportingStatus(account: account, service: service, synchronizable: synchronizable)
        guard status != errSecSuccess else { return }
        ProximityAudit.log("keychain.delete.failed", context: [
            "service": service, "account": account, "status": "\(status)"
        ])
    }

    /// ``delete(account:service:synchronizable:)`` reporting its outcome: `errSecSuccess` when the row
    /// is gone (including the `errSecItemNotFound` "was never there" case, normalized), else the
    /// failing `OSStatus`. For callers whose contract depends on the row actually being removed.
    static func deleteReportingStatus(
        account: String,
        service: String,
        synchronizable: SynchronizableScope = .any
    ) -> OSStatus {
        guard !account.isEmpty, !service.isEmpty else { return errSecParam }   // R5: nothing is filed under an empty key.
        let query = deleteQuery(account: account, service: service, synchronizable: synchronizable)
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecItemNotFound ? errSecSuccess : status
    }

    /// Deletes every item under `service`, both synced and device-only variants, to clear a whole
    /// service slot at once.
    ///
    /// R7: a non-benign `SecItemDelete` status is audited rather than dropped, as
    /// `keychain.deleteAll.failed`, FernletFoundation's line: these flows promise the slot is empty
    /// afterwards.
    static func deleteAll(service: String) {
        let status = deleteAllReportingStatus(service: service)
        guard status != errSecSuccess else { return }
        ProximityAudit.log("keychain.deleteAll.failed", context: ["service": service, "status": "\(status)"])
    }

    /// ``deleteAll(service:)`` reporting its outcome, with `errSecItemNotFound` normalized to
    /// `errSecSuccess` (an empty slot is a cleared slot).
    static func deleteAllReportingStatus(service: String) -> OSStatus {
        guard !service.isEmpty else { return errSecParam }   // R5: refuse to sweep an unnamed slot.
        let query = deleteAllQuery(service: service)
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecItemNotFound ? errSecSuccess : status
    }

    // MARK: - Query dictionaries

    // One builder per query shape, each spelling exactly the dictionary FernletFoundation's
    // `KeychainItem` spells inline for the same call, and each the only place its shape is spelled
    // here, so the dictionary the golden suite compares is the one every member issues.

    /// The `SecItemAdd` dictionary of ``store(_:account:service:accessibility:synchronizable:replacing:)``.
    static func addQuery(
        _ data: Data,
        account: String,
        service: String,
        accessibility: CFString,
        synchronizable: Bool
    ) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: accessibility,
            kSecAttrSynchronizable as String: synchronizable,
            kSecUseDataProtectionKeychain as String: true,
            kSecValueData as String: data
        ]
    }

    /// The `SecItemCopyMatching` dictionary of the two single-item reads,
    /// ``load(account:service:synchronizable:)`` and ``loadDistinguishingAbsence(account:service:synchronizable:)``.
    static func readQuery(account: String, service: String, synchronizable: SynchronizableScope) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: synchronizable.queryValue,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true,
            kSecUseDataProtectionKeychain as String: true
        ]
    }

    /// The `SecItemCopyMatching` dictionary of ``loadAllDistinguishingFailure(service:synchronizable:)``.
    static func enumerationQuery(service: String, synchronizable: SynchronizableScope) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrSynchronizable as String: synchronizable.queryValue,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true,
            kSecUseDataProtectionKeychain as String: true
        ]
    }

    /// The `SecItemDelete` dictionary of ``deleteReportingStatus(account:service:synchronizable:)``.
    static func deleteQuery(account: String, service: String, synchronizable: SynchronizableScope) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: synchronizable.queryValue,
            kSecUseDataProtectionKeychain as String: true
        ]
    }

    /// The `SecItemDelete` dictionary of ``deleteAllReportingStatus(service:)``: every row under the
    /// service, synced or not.
    static func deleteAllQuery(service: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
            kSecUseDataProtectionKeychain as String: true
        ]
    }
}
