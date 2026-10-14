// PackageKeychainStore.swift
// ProximityKitTests
//
// ProximityKit plan step A1.1: the keychain ProximityKit's package tests run against. Their bundle is
// unhosted: on the simulator the system keychain answers every call errSecMissingEntitlement (-34018), and
// on a Mac a package test must not reach the system keychain whatever it answers (Apple's TN3137 gives
// -34018 for a process without keychain entitlements). So the bundle's
// installer (PackageTestEnvironment.swift) installs this store as ProximityKit's keychain backend before
// the bundle's first keychain call, and every identity row and seal key a package test writes lives here,
// in memory, for the life of the test process. It reads the query dictionaries ProximityKeychainItem's
// builders spell, by their Security keys, which is why this file imports Security.

import Foundation
@testable import ProximityKit
import Security
import Synchronization

/// An in-memory keychain that answers ProximityKit's keychain funnel, `ProximityKeychainItem`, as the
/// system keychain answers the dictionaries that funnel issues: the package test bundle's keychain backend
/// (`PackageTestEnvironment.keychain`).
///
/// **What it models, and only that.** Generic-password rows keyed, as the keychain keys them, by service,
/// account and synchronizable flag, so a synced row and a device-only row of one account are two rows.
/// An add of a row whose key is taken is `errSecDuplicateItem` (the funnel's `store` deletes first, under
/// its `replacing:` scope); a single-row read answers the row's data, an enumeration every match's
/// attributes with its data; a delete removes every match, one account's or a whole service's; a match is
/// either variant under `kSecAttrSynchronizableAny` and one under `true` or `false`; and a read, an
/// enumeration or a delete that matches nothing is `errSecItemNotFound`. A dictionary of another shape
/// than the funnel's builders spell (another class, no data-protection flag, a missing name, an unknown
/// match limit) is refused with `errSecParam` rather than served, and so is a synchronizable add under a
/// `ThisDeviceOnly` class, which SecItem.h forbids. Accessibility is recorded, never enforced: the store
/// has no lock state. Where the keychain promises no order (an enumeration, or a single-row read under
/// `kSecAttrSynchronizableAny` that matches both variants) the store answers in its own order, by account
/// and then the device-only variant first; a suite must not rely on that order.
///
/// **An unreadable service on demand.** ``makeUnreadable(service:)`` makes every call on one service
/// answer `errSecInteractionNotAllowed`, the status a keychain answers before the first unlock, which no
/// simulator keychain can be made to return, until ``makeReadable(service:)``; other services are
/// untouched, so parallel suites, each on its own `.test.` service, cannot disturb one another.
///
/// **Concurrency.** One immutable `let` owns the state behind a `Mutex`; every call reads or writes it
/// inside `withLock` and returns only `Sendable` values, so the store is `Sendable` with no stored
/// `static var`, and one instance serves every suite in the process.
final class PackageKeychainStore: ProximityKeychainBackend {

    /// One row as the store holds it.
    struct Row: Equatable, Sendable {
        /// `kSecAttrService`.
        let service: String
        /// `kSecAttrAccount`.
        let account: String
        /// `kSecAttrSynchronizable`: whether this is the synced variant of the account's row.
        let synchronizable: Bool
        /// `kSecAttrAccessible`, the class the add named, recorded and never enforced.
        let accessibility: String
        /// `kSecValueData`.
        let data: Data
    }

    /// A row's primary key, as the keychain keys a generic password.
    private struct RowKey: Hashable, Sendable {
        /// `kSecAttrService`.
        let service: String
        /// `kSecAttrAccount`.
        let account: String
        /// `kSecAttrSynchronizable`.
        let synchronizable: Bool
    }

    /// What one query matches: a service, one account of it or every one, and one variant or either.
    private struct Match {
        /// `kSecAttrService`.
        let service: String
        /// `kSecAttrAccount`, or nil for every account of the service.
        let account: String?
        /// `kSecAttrSynchronizable` as `true` or `false`, or nil for `kSecAttrSynchronizableAny`.
        let synchronizable: Bool?

        /// Whether the row under `key` is one this query matches.
        func matches(_ key: RowKey) -> Bool {
            key.service == service
                && (account.map { $0 == key.account } ?? true)
                && (synchronizable.map { $0 == key.synchronizable } ?? true)
        }
    }

    /// The store's state: its rows, and the services made unreadable with their status.
    private struct State: Sendable {
        /// Every row, by its primary key.
        var rows: [RowKey: Row] = [:]
        /// The services every call answers with a failing status, and that status.
        var unreadable: [String: OSStatus] = [:]
    }

    /// The state, owned with its lock.
    private let state = Mutex(State())

    // MARK: - The funnel's three calls

    /// Adds the row an add dictionary describes: `errSecDuplicateItem` when its key is taken, and
    /// `errSecParam` for a synchronizable row under a `ThisDeviceOnly` class.
    func add(_ query: [String: Any]) -> OSStatus {
        guard let match = Self.match(query), let account = match.account, let synchronizable = match.synchronizable,
              let accessibility = query[kSecAttrAccessible as String] as? String,
              let data = query[kSecValueData as String] as? Data else { return errSecParam }
        let deviceOnlyClasses = [kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                 kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly].map { $0 as String }
        guard !(synchronizable && deviceOnlyClasses.contains(accessibility)) else { return errSecParam }
        let key = RowKey(service: match.service, account: account, synchronizable: synchronizable)
        let row = Row(service: match.service, account: account, synchronizable: synchronizable,
                      accessibility: accessibility, data: data)
        return state.withLock { state in
            if let status = state.unreadable[match.service] { return status }
            guard state.rows[key] == nil else { return errSecDuplicateItem }
            state.rows[key] = row
            return errSecSuccess
        }
    }

    /// Answers a single-row read with the first match's data, or an enumeration with every match's
    /// attributes (and data, when asked), matches in ``rows(service:)``'s order; `errSecItemNotFound`
    /// when nothing matches.
    func copyMatching(_ query: [String: Any], result: inout AnyObject?) -> OSStatus {
        let limit = query[kSecMatchLimit as String] as? String
        let returnsData = query[kSecReturnData as String] as? Bool == true
        let returnsAttributes = query[kSecReturnAttributes as String] as? Bool == true
        guard let match = Self.match(query), returnsData || returnsAttributes,
              limit == kSecMatchLimitOne as String || limit == kSecMatchLimitAll as String else { return errSecParam }
        let (status, rows) = state.withLock { state -> (OSStatus, [Row]) in
            if let status = state.unreadable[match.service] { return (status, []) }
            let rows = state.rows.filter { match.matches($0.key) }.values.sorted(by: Self.inOrder)
            return (rows.isEmpty ? errSecItemNotFound : errSecSuccess, rows)
        }
        let answers: [AnyObject] = rows.map { row in
            returnsAttributes ? Self.attributes(of: row, withData: returnsData) as AnyObject : row.data as AnyObject
        }
        guard status == errSecSuccess, let first = answers.first else { return status }
        result = (limit == kSecMatchLimitOne as String) ? first : (answers as AnyObject)
        return errSecSuccess
    }

    /// Deletes every row a delete dictionary matches: `errSecItemNotFound` when none does.
    func delete(_ query: [String: Any]) -> OSStatus {
        guard let match = Self.match(query) else { return errSecParam }
        return state.withLock { state in
            if let status = state.unreadable[match.service] { return status }
            let matched = state.rows.keys.filter(match.matches)
            // R2: bounded by the store's finite row set.
            for key in matched {
                state.rows[key] = nil
            }
            return matched.isEmpty ? errSecItemNotFound : errSecSuccess
        }
    }

    // MARK: - What a suite reads and sets

    /// Every row under `service`, by account, then the device-only variant before the synced one.
    func rows(service: String) -> [Row] {
        state.withLock { state in
            state.rows.values.filter { $0.service == service }.sorted(by: Self.inOrder)
        }
    }

    /// Makes every call on `service` answer `errSecInteractionNotAllowed`, as a keychain does before the
    /// first unlock, until ``makeReadable(service:)``; the service's rows stay as they are.
    ///
    /// - Returns: The status the service now answers.
    func makeUnreadable(service: String) -> OSStatus {
        state.withLock { state in
            state.unreadable[service] = errSecInteractionNotAllowed
            return errSecInteractionNotAllowed
        }
    }

    /// Makes `service` answer from its rows again.
    func makeReadable(service: String) {
        state.withLock { state in
            state.unreadable[service] = nil
        }
    }

    /// The device-only class ProximityKit's stores write their rows under,
    /// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, for a suite that does not import Security (a
    /// package file outside `TestSupport/` may not: `CIGateSelectorBoundaryTests`' rule I11).
    static var deviceOnly: CFString {
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    }

    /// The class a synced row is written under, `kSecAttrAccessibleAfterFirstUnlock`, for the same suites.
    static var afterFirstUnlock: CFString {
        kSecAttrAccessibleAfterFirstUnlock
    }

    /// `errSecSuccess`, for the same suites.
    static let success: OSStatus = errSecSuccess

    /// `errSecDuplicateItem`, for the same suites.
    static let duplicateItem: OSStatus = errSecDuplicateItem

    // MARK: - Reading a dictionary

    /// What `query` matches, or nil when it is not a dictionary the funnel's builders spell: a generic
    /// password in the data-protection keychain, under a named service, an account when one is given and
    /// a synchronizable value of `true`, `false` or `kSecAttrSynchronizableAny`.
    private static func match(_ query: [String: Any]) -> Match? {
        guard query[kSecClass as String] as? String == kSecClassGenericPassword as String,
              query[kSecUseDataProtectionKeychain as String] as? Bool == true,
              let service = query[kSecAttrService as String] as? String, !service.isEmpty else { return nil }
        let account = query[kSecAttrAccount as String] as? String
        guard account?.isEmpty != true else { return nil }
        let flag = query[kSecAttrSynchronizable as String]
        if let synchronizable = flag as? Bool {
            return Match(service: service, account: account, synchronizable: synchronizable)
        }
        guard flag as? String == kSecAttrSynchronizableAny as String else { return nil }
        return Match(service: service, account: account, synchronizable: nil)
    }

    /// The attribute dictionary an enumeration answers for `row`, with its data when the query asked.
    private static func attributes(of row: Row, withData: Bool) -> [String: Any] {
        var attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: row.service,
            kSecAttrAccount as String: row.account,
            kSecAttrSynchronizable as String: row.synchronizable,
            kSecAttrAccessible as String: row.accessibility
        ]
        if withData {
            attributes[kSecValueData as String] = row.data
        }
        return attributes
    }

    /// The store's row order: by account, then the device-only variant before the synced one.
    private static func inOrder(_ first: Row, _ second: Row) -> Bool {
        guard first.account == second.account else { return first.account < second.account }
        return !first.synchronizable && second.synchronizable
    }
}
