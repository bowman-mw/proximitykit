// ProximityKeychainItem.swift
// ProximityKit/Support
//
// ProximityKit plan step A0.2.11 (Docs/Plan-FernletCoach-ProximityKit-2026-10-01.md §4 A0.2, "Copied
// into ProximityKit: … the `KeychainItem` mechanism (not Fernlet's `Account` enum)"): the generic
// data-protection keychain accessors ProximityKit's key stores call, copied from FernletFoundation's
// `KeychainItem` member for member. Only the mechanism came across: ten members (the type's doc says
// which this module's stores still call), the scope and result types they need, and the delete audit
// lines, which now go through `ProximityAudit` under the same event names and context. Fernlet's
// catalogue stayed behind: the `Account` names, the typed overloads, the service constants, the device
// sealing-key mint and the update-in-place primitive nothing here calls.
//
// ProximityKit plan step A1.1: the add, the match and the delete reach the keychain through one
// backend, `ProximityKeychainBackend`, handed each query dictionary exactly as its builder spells it.
// The system keychain is the backend every shipping build has; a Debug build also holds the slot
// through which ProximityKit's own package tests, unhosted and so without a keychain, install an
// in-memory store.

import Foundation
import Security
import Synchronization

/// The three keychain calls ``ProximityKeychainItem`` makes, as one replaceable seam: an add, a match
/// and a delete, each handed the query dictionary the funnel's builders spelled, unchanged.
///
/// ``ProximityKeychainItem/SystemKeychain`` is the conformer every shipping build uses: it passes each
/// dictionary to `SecItemAdd`, `SecItemCopyMatching` or `SecItemDelete` exactly as the funnel's members
/// call them, so every row's bytes and every status are the system keychain's. The only other
/// conformer is the in-memory store ProximityKit's own package tests install, in a Debug build, through
/// ``ProximityKeychainItem/installBackend(_:)``: that bundle runs unhosted, where the system keychain
/// answers `errSecMissingEntitlement` (-34018) on the simulator and would reach the developer's own
/// keychain on a Mac.
///
/// Each requirement is synchronous and `nonisolated`, like the call it stands for, and the protocol
/// refines `Sendable` because one value serves every caller in the process, main-actor managers and
/// `nonisolated` seal-key helpers alike.
nonisolated protocol ProximityKeychainBackend: Sendable {

    /// Adds the item `query` describes, as `SecItemAdd(query, nil)` does.
    ///
    /// - Parameter query: The add dictionary
    ///   (``ProximityKeychainItem/addQuery(_:account:service:accessibility:synchronizable:)``).
    /// - Returns: The add's status: `errSecDuplicateItem` when an item with the same primary key
    ///   (class, service, account and synchronizable flag) is already there.
    func add(_ query: [String: Any]) -> OSStatus

    /// Matches the items `query` describes, as `SecItemCopyMatching(query, &result)` does.
    ///
    /// - Parameters:
    ///   - query: A single-item read or an enumeration dictionary
    ///     (``ProximityKeychainItem/readQuery(account:service:synchronizable:)``,
    ///     ``ProximityKeychainItem/enumerationQuery(service:synchronizable:)``).
    ///   - result: Set to what the query asks back on success: the one item's data, or every match's
    ///     attribute dictionary with its data. Left as it is when the call fails.
    /// - Returns: The match's status: `errSecItemNotFound` when nothing matches.
    func copyMatching(_ query: [String: Any], result: inout AnyObject?) -> OSStatus

    /// Deletes every item `query` matches, as `SecItemDelete(query)` does.
    ///
    /// - Parameter query: One row's or a whole service's delete dictionary
    ///   (``ProximityKeychainItem/deleteQuery(account:service:synchronizable:)``,
    ///   ``ProximityKeychainItem/deleteAllQuery(service:)``).
    /// - Returns: The delete's status: `errSecItemNotFound` when nothing matched.
    func delete(_ query: [String: Any]) -> OSStatus
}

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
///   distinct rows. ``SynchronizableScope`` targets one of them; an escrow store that keeps both
///   variants depends on telling them apart.
/// - ``store(_:account:service:accessibility:synchronizable:replacing:)`` is delete-then-add, and its
///   `replacing` scope decides which variant the delete removes: a narrow scope when promoting an
///   escrow item, so a genuine key that just synced in is not clobbered.
///
/// **Members this module no longer calls stay.** ProximityKit's own stores (the identity's four
/// device rows and the two mesh seal keys) use the reads that distinguish absence, `store` under its
/// default scopes and the whole-service deletes. The nil-collapsing ``load(account:service:synchronizable:)``,
/// the two enumerations, the `.synced` / `.local` scopes and a narrow `replacing:` have no caller
/// here: they served the sealed-backup escrow, which is its host's (Fernlet's `SealedBackupEscrowKey`,
/// in the app, through FernletFoundation's original). They stay because this type is that original
/// copied member for member, and `ProximityNamespaceGoldenTests` holds every query dictionary to the
/// original's, so the two keep reading, listing and clearing each other's rows alike.
///
/// ``delete(account:service:synchronizable:)`` and ``deleteAll(service:)`` audit a failed delete
/// through ``ProximityAudit`` as `keychain.delete.failed` (context `service`, `account`, `status`) and
/// `keychain.deleteAll.failed` (`service`, `status`), FernletFoundation's names and keys, so a host's
/// audit sees the lines it always saw.
///
/// Mechanism only: no account, service or accessibility class of its own. Each caller passes its
/// row's names and class, which is where the key-custody walls read them. `nonisolated`: called from
/// main-actor managers and from the `nonisolated` seal-key helpers alike.
///
/// **One backend (plan step A1.1).** Every member reaches the keychain through ``backend``: the add,
/// the match and the delete each hand the dictionary its builder spelled to a
/// ``ProximityKeychainBackend``. Its system conformer, ``SystemKeychain``, is the only backend a
/// shipping build has, and calls `SecItemAdd`, `SecItemCopyMatching` and `SecItemDelete` with that
/// dictionary unchanged, so the rows and the statuses are the system keychain's. A Debug build also
/// holds one slot, filled only by ProximityKit's own package tests through ``installBackend(_:)``
/// with an in-memory store, because their unhosted bundle has no keychain. The slot is this type's
/// one piece of shared state, a `Mutex` it owns; with nothing installed, which is every shipping
/// process and Fernlet's hosted tests, ``backend`` is the system keychain.
nonisolated enum ProximityKeychainItem {

    /// Which synchronizable variant of an item a query should match.
    ///
    /// The default `.any` matches either (`kSecAttrSynchronizableAny`). `.synced` / `.local` tell an
    /// iCloud-Keychain-replicated item from a device-only one when both can exist under the same
    /// service + account, which an escrow reconciliation relies on; no store in this module passes
    /// either (see the type's doc for why they stay).
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
    /// variant is removed before the add: the default `.any` overwrites whatever is there, and every
    /// store in this module passes it; `.local` (or `.synced`) removes only that variant, for promoting
    /// a device-only escrow item without removing a genuine key that just synced in under the same
    /// account.
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
        return backend.add(query)
    }

    /// Loads the data of the single item matching `service` + `account` within `synchronizable`
    /// scope, or `nil` when no item matches (or the keychain call fails).
    static func load(account: String, service: String, synchronizable: SynchronizableScope = .any) -> Data? {
        guard !account.isEmpty, !service.isEmpty else { return nil }   // R5: no row is ever filed under an empty key.
        var result: AnyObject?
        let query = readQuery(account: account, service: service, synchronizable: synchronizable)
        guard backend.copyMatching(query, result: &result) == errSecSuccess else { return nil }
        return result as? Data
    }

    /// Loads the single item matching `service` + `account` within `synchronizable` scope,
    /// distinguishing the three outcomes ``load(account:service:synchronizable:)`` collapses:
    /// ``ReadResult/found(_:)`` with the item's data, ``ReadResult/absent`` when no item exists, and
    /// ``ReadResult/unreadable(_:)`` carrying the failing `OSStatus`. Used by every store whose
    /// mint-on-absent path must fail closed on a transient read error: the identity rows and both
    /// mesh seal keys.
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
        let status = backend.copyMatching(query, result: &result)
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
    /// synchronizable scope), returning each item's account + data. Written for a content-addressed
    /// escrow store, whose keys live at accounts derived from their own public keys, so its reconcile
    /// path enumerates to discover the full set; no store in this module enumerates (see the type's
    /// doc for why it stays). Query `.synced` and `.local` separately to learn each row's sync status.
    /// Returns `[]` on no match or error.
    ///
    /// - Important: the error collapse is the whole difference from
    ///   ``loadAllDistinguishingFailure(service:synchronizable:)``, and it is only safe where an
    ///   unreadable service and an empty one warrant the same behavior (an escrow reconcile finds
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
    /// under a clean result. No store in this module makes that promise or enumerates at all, so
    /// ``loadAll(service:synchronizable:)``, which collapses the failure on purpose, is this member's one
    /// caller, and has none here itself. `errSecItemNotFound` is not such a failure: a service that
    /// holds nothing lands in ``EnumerationResult/rows(_:)`` as `[]`.
    static func loadAllDistinguishingFailure(
        service: String,
        synchronizable: SynchronizableScope = .any
    ) -> EnumerationResult {
        // R5: an empty service is a caller bug rather than an empty slot — report it as unreadable so
        // a caller promising it cleared the slot fails closed instead of promising it cleared "".
        guard !service.isEmpty else { return .unreadable(errSecParam) }
        var result: AnyObject?
        let query = enumerationQuery(service: service, synchronizable: synchronizable)
        let status = backend.copyMatching(query, result: &result)
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
        let status = backend.delete(query)
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
        let status = backend.delete(query)
        return status == errSecItemNotFound ? errSecSuccess : status
    }

    // MARK: - Backend

    /// The system keychain, the backend every shipping build has: each requirement is the Security
    /// call the funnel's members make, handed the builder's dictionary bridged to `CFDictionary`.
    nonisolated struct SystemKeychain: ProximityKeychainBackend {

        /// `SecItemAdd(query, nil)`.
        func add(_ query: [String: Any]) -> OSStatus {
            SecItemAdd(query as CFDictionary, nil)
        }

        /// `SecItemCopyMatching(query, &result)`.
        func copyMatching(_ query: [String: Any], result: inout AnyObject?) -> OSStatus {
            SecItemCopyMatching(query as CFDictionary, &result)
        }

        /// `SecItemDelete(query)`.
        func delete(_ query: [String: Any]) -> OSStatus {
            SecItemDelete(query as CFDictionary)
        }
    }

    #if DEBUG
    /// The backend ProximityKit's own package tests installed, or nil for none.
    ///
    /// Compiled in a Debug build only. The one process-global in this type: an immutable `let` that
    /// owns its lock (R6/R9), written only by ``installBackend(_:)`` and read only by ``backend``, each
    /// inside `withLock`; the backend is `Sendable`, so nothing else needs guarding.
    private static let installedBackend = Mutex<(any ProximityKeychainBackend)?>(nil)

    /// Installs the backend every later keychain call goes to, replacing any installed before it.
    ///
    /// For ProximityKit's own package tests alone: their bundle runs unhosted, with no keychain
    /// entitlement on the simulator and the developer's own keychain on a Mac, so its installer puts an
    /// in-memory store here once, before the bundle's first keychain call. No shipping code installs a
    /// backend, and Fernlet's hosted tests install none, so they exercise the system keychain. The door
    /// is compiled in a Debug build only: a Release build has no way to install one, and its ``backend``
    /// is the system keychain without a slot to read. This module's own package tests
    /// (`ProximityKeychainDoorTests`) hold the door's one caller to their installer and its declaration
    /// to this `#if DEBUG` branch; a host's walls hold that it calls none (Fernlet's
    /// `KeyCustodyBoundaryTests`).
    ///
    /// - Parameter backend: The backend; called synchronously, from any executor.
    static func installBackend(_ backend: any ProximityKeychainBackend) {
        installedBackend.withLock { $0 = backend }
    }

    /// The backend every keychain call goes through: the one ProximityKit's package tests installed,
    /// else the system keychain.
    static var backend: any ProximityKeychainBackend {
        guard let installed = installedBackend.withLock({ $0 }) else { return SystemKeychain() }
        return installed
    }
    #else
    /// The backend every keychain call goes through: in a Release build, always the system keychain,
    /// the only backend such a build has.
    static var backend: any ProximityKeychainBackend {
        SystemKeychain()
    }
    #endif

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
