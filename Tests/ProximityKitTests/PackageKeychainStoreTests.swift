// PackageKeychainStoreTests.swift
// ProximityKitTests
//
// ProximityKit plan step A1.1: the canary of the package tests' keychain. This bundle is unhosted: on the
// simulator the system keychain answers every call errSecMissingEntitlement (-34018), and on a Mac a package
// test must not reach the system keychain whatever it answers (Apple's TN3137 gives -34018 for a process
// without keychain entitlements); PackageTestEnvironment installs an in-memory store
// (TestSupport/PackageKeychainStore.swift) as ProximityKit's keychain backend before the first keychain call. These cells hold that it did, and that
// ProximityKit's identity and its two seal keys provision, read back, defer and wipe through the store as
// they do through the keychain: a row reads back, an absent row is absent, an unreadable row is never read
// as absent, and a service sees only its own rows. Every keychain service here is a `.test.` service of
// one `.packageTest` names, with a fresh UUID, so parallel cells never share a row.

import Foundation
@testable import ProximityKit
import Testing

/// The package tests' keychain: ProximityKit's funnel resolves the bundle's store, and the identity and
/// both seal keys keep their rows in it as they keep them in the keychain.
@Suite struct PackageKeychainStoreTests {

    /// The bundle's store, read as each cell's suite instance is built, so the installer has run before
    /// the cell's first keychain call.
    let store = PackageTestEnvironment.keychain

    // MARK: - The slot

    /// The installer put the bundle's store in ProximityKit's keychain slot: the funnel resolves that very
    /// instance, not the system keychain and not a second store, so no keychain call in this bundle
    /// reaches the system keychain.
    @Test func theFunnelResolvesTheBundlesStore() {
        let resolved = ProximityKeychainItem.backend
        #expect((resolved as? PackageKeychainStore) === store,
                "ProximityKit's keychain funnel resolves \(type(of: resolved)), not the bundle's store")
        #expect(PackageTestEnvironment.keychain === store, "the environment handed out a second store")
    }

    // MARK: - The identity

    /// An identity under `.packageTest` on a `.test.` service provisions its four device rows into the
    /// store, each device-only and never synchronized; a second identity on that service reads the same
    /// public keys back rather than minting; and a wipe empties the service, after which a third identity
    /// mints keys of its own.
    @MainActor @Test func anIdentityProvisionsReadsItsKeysBackAndWipes() throws {
        let rows = ProximityNamespace.packageTest.installation.keychain.identity
        let service = Self.testService(under: rows.service)
        let first = try Self.provisionedIdentity(on: service)
        let stored = store.rows(service: service)
        let accounts = [rows.signingPrivateKey, rows.keyAgreementPrivateKey, rows.signingPublicKeyCache,
                        rows.keyAgreementPublicKeyCache]
        #expect(stored.map(\.account) == accounts.sorted(), "the identity's rows are \(stored.map(\.account))")
        #expect(stored.allSatisfy { !$0.synchronizable && $0.accessibility == PackageKeychainStore.deviceOnly as String },
                "an identity row is synchronized or not device-only: \(stored)")

        let second = try Self.provisionedIdentity(on: service)
        #expect(first.localSigningPublicKey.count == 32 && second.localSigningPublicKey == first.localSigningPublicKey,
                "a second identity on the service minted a signing key instead of reading the first's back")
        #expect(second.localKeyAgreementPublicKey == first.localKeyAgreementPublicKey,
                "a second identity on the service minted a key-agreement key instead of reading the first's back")
        #expect(store.rows(service: service).count == accounts.count, "reading the identity back added a row")

        try first.wipe()
        #expect(store.rows(service: service).isEmpty, "the identity's wipe left \(store.rows(service: service))")
        let third = try Self.provisionedIdentity(on: service)
        #expect(third.localSigningPublicKey != first.localSigningPublicKey, "a wiped identity's key came back")
        try third.wipe()
    }

    // MARK: - The seal keys

    /// On a session scope and a routed scope, each on a `.test.` service, asking for the key to seal
    /// mints it into the store as one 32-byte device-only row under the scope's account; asking again,
    /// and asking for the key to open, read that same key back; and a wipe empties the service, after
    /// which the key to open is refused as missing and the key to seal is a new one.
    @Test func eachSealKeyIsMintedReadBackAndWiped() {
        // R2: bounded by the two scopes.
        for scope in [Self.sessionScope(), Self.routedScope()] {
            let minted = Self.key(scope, opening: false)
            let stored = store.rows(service: scope.service)
            #expect(stored.map(\.account) == [scope.account] && stored.first?.data.count == 32,
                    "\(scope.name): the minted key's rows are \(stored)")
            #expect(stored.allSatisfy { !$0.synchronizable && $0.accessibility == PackageKeychainStore.deviceOnly as String },
                    "\(scope.name): the seal key's row is synchronized or not device-only")
            #expect(minted == "available \(stored.first.map { Self.hex($0.data) } ?? "none")",
                    "\(scope.name): the key handed out is not the row stored: \(minted)")
            #expect(Self.key(scope, opening: false) == minted, "\(scope.name): asking again minted another key")
            #expect(Self.key(scope, opening: true) == minted, "\(scope.name): opening read another key")

            Self.wipe(scope)
            #expect(store.rows(service: scope.service).isEmpty, "\(scope.name): the wipe left a row")
            #expect(Self.key(scope, opening: true) == "refused sealKeyMissingForSealedFile",
                    "\(scope.name): opening after the wipe answered otherwise")
            let reminted = Self.key(scope, opening: false)
            #expect(reminted.hasPrefix("available ") && reminted != minted,
                    "\(scope.name): sealing after the wipe answered \(reminted)")
            Self.wipe(scope)
        }
    }

    // MARK: - Absent and unreadable

    /// A service the store answers with `errSecInteractionNotAllowed`, as a keychain does before the first
    /// unlock, is never read as empty, and no other service is: the funnel's read reports it unreadable
    /// with that very status, an identity refuses to provision with it and a seal key defers, sealing and
    /// opening alike, an add and a delete on it answer that status too, and none of them writes a row. Once the services read again, the same calls find them absent: the read says so,
    /// opening is refused as a missing key, and the identity and the seal key mint.
    @MainActor @Test func anUnreadableServiceIsNeverReadAsAbsent() throws {
        let rows = ProximityNamespace.packageTest.installation.keychain.identity
        let service = Self.testService(under: rows.service)
        let scope = Self.sessionScope()
        let status = store.makeUnreadable(service: service)
        #expect(store.makeUnreadable(service: scope.service) == status)
        #expect(Self.signingRow(on: Self.testService(under: rows.service)) == "absent",
                "making one service unreadable reached another")

        #expect(Self.signingRow(on: service) == "unreadable \(status)", "the funnel's read lost the status")
        #expect(throws: IdentityError.keychainReadFailed(status)) { try Self.provisionedIdentity(on: service) }
        #expect(Self.key(scope, opening: false) == "deferred sealKeyTransientlyUnreadable")
        #expect(Self.key(scope, opening: true) == "deferred sealKeyTransientlyUnreadable")
        #expect(ProximityKeychainItem.store(Data([0x01]), account: "row", service: service,
                                            accessibility: PackageKeychainStore.deviceOnly) == status,
                "an add on an unreadable service did not answer its status")
        #expect(ProximityKeychainItem.deleteAllReportingStatus(service: service) == status,
                "a delete on an unreadable service did not answer its status")
        #expect(store.rows(service: service).isEmpty && store.rows(service: scope.service).isEmpty,
                "an unreadable service was minted over")

        store.makeReadable(service: service)
        store.makeReadable(service: scope.service)
        #expect(Self.signingRow(on: service) == "absent", "a readable empty service is not absent")
        #expect(Self.key(scope, opening: true) == "refused sealKeyMissingForSealedFile",
                "an absent key is refused for opening, never deferred")
        let identity = try Self.provisionedIdentity(on: service)
        #expect(store.rows(service: service).count == 4, "the identity did not mint once the service read again")
        #expect(Self.key(scope, opening: false).hasPrefix("available "), "the seal key did not mint once readable")
        try identity.wipe()
        Self.wipe(scope)
    }

    // MARK: - Isolation

    /// Two session scopes on two services, and a routed scope on a third, never see each other's rows:
    /// the two session scopes share one account, so the service alone tells them apart, and each mints a
    /// key of its own; a wipe of one leaves the others' keys readable and unchanged.
    @Test func scopesOnDifferentServicesNeverSeeEachOthersRows() {
        let scopes = [Self.sessionScope(), Self.sessionScope(), Self.routedScope()]
        #expect(scopes[0].account == scopes[1].account, "the two session scopes do not share an account")
        let keys = scopes.map { Self.key($0, opening: false) }
        #expect(Set(keys).count == scopes.count && keys.allSatisfy { $0.hasPrefix("available ") },
                "the three scopes' keys are \(keys)")
        // R2: bounded by the three scopes.
        for scope in scopes {
            #expect(store.rows(service: scope.service).count == 1, "\(scope.name) holds another scope's row")
        }

        Self.wipe(scopes[0])
        #expect(Self.key(scopes[0], opening: true) == "refused sealKeyMissingForSealedFile")
        #expect(Self.key(scopes[1], opening: true) == keys[1], "a wipe of one session service reached the other")
        #expect(Self.key(scopes[2], opening: true) == keys[2], "a wipe of a session service reached the routed one")
        Self.wipe(scopes[1])
        Self.wipe(scopes[2])
    }

    // MARK: - The keychain's model

    /// The store keeps the keychain's two synchronizable variants of one account apart, as the funnel's
    /// scopes and `store`'s `replacing:` rely on: a device-only row and its synced twin coexist, each
    /// under the class it was added with; `.synced` and `.local` each list and read exactly their own row
    /// and `.any` both, in the store's order; a device-only add over the device-only row a narrow
    /// `.synced` delete leaves is a duplicate, which keeps that row as it was; an enumeration lists both
    /// rows with their accounts, in the store's order; a `.local` delete leaves the synced twin; a
    /// synchronizable add under a `ThisDeviceOnly` class is refused and adds no row; and a whole-service
    /// delete leaves an empty slot, which enumerates as no rows rather than as unreadable, and a delete
    /// of a row that is gone succeeds.
    @Test func theStoreKeepsTheSynchronizableVariantsApart() {
        let service = Self.testService(under: ProximityNamespace.packageTest.installation.keychain.identity.service)
        let account = "escrow"
        let (local, synced, again) = (Data(repeating: 0x70, count: 4), Data(repeating: 0x90, count: 4),
                                      Data(repeating: 0xB0, count: 4))
        let deviceOnly = PackageKeychainStore.deviceOnly
        #expect(ProximityKeychainItem.store(local, account: account, service: service, accessibility: deviceOnly)
                    == PackageKeychainStore.success)
        #expect(ProximityKeychainItem.store(synced, account: account, service: service,
                                            accessibility: PackageKeychainStore.afterFirstUnlock, synchronizable: true,
                                            replacing: .synced) == PackageKeychainStore.success)
        #expect(store.rows(service: service).map(\.accessibility)
                    == [deviceOnly as String, PackageKeychainStore.afterFirstUnlock as String],
                "the store did not keep each row's class")
        let scopes: [(ProximityKeychainItem.SynchronizableScope, [Data])] = [
            (.synced, [synced]), (.local, [local]), (.any, [local, synced])
        ]
        // R2: bounded by the three scopes.
        for (scope, expected) in scopes {
            let listed = ProximityKeychainItem.loadAll(service: service, synchronizable: scope).map(\.data)
            #expect(listed == expected, "the \(scope) scope listed \(listed)")
            let read = ProximityKeychainItem.load(account: account, service: service, synchronizable: scope)
            #expect(read == expected.first, "the \(scope) scope read \(String(describing: read))")
        }

        #expect(ProximityKeychainItem.store(again, account: account, service: service, accessibility: deviceOnly,
                                            replacing: .synced) == PackageKeychainStore.duplicateItem,
                "a device-only add over the device-only row is not a duplicate")
        #expect(store.rows(service: service).map(\.data) == [local], "the duplicate add changed the rows")
        #expect(ProximityKeychainItem.store(synced, account: account, service: service,
                                            accessibility: PackageKeychainStore.afterFirstUnlock, synchronizable: true,
                                            replacing: .synced) == PackageKeychainStore.success)
        let listing = ProximityKeychainItem.loadAllDistinguishingFailure(service: service)
        #expect(Self.spelled(listing) == "rows escrow=70707070 escrow=90909090", "the enumeration is \(listing)")

        #expect(ProximityKeychainItem.deleteReportingStatus(account: account, service: service, synchronizable: .local)
                    == PackageKeychainStore.success)
        #expect(store.rows(service: service).map(\.data) == [synced], "a .local delete reached the synced twin")
        #expect(ProximityKeychainItem.store(local, account: "synced-device-only", service: service, accessibility: deviceOnly,
                                            synchronizable: true) != PackageKeychainStore.success,
                "a synchronizable add under a ThisDeviceOnly class was stored")
        #expect(store.rows(service: service).map(\.data) == [synced], "the refused add changed the rows")
        #expect(ProximityKeychainItem.deleteAllReportingStatus(service: service) == PackageKeychainStore.success)
        #expect(store.rows(service: service).isEmpty, "the whole-service delete left a row")
        let emptied = ProximityKeychainItem.loadAllDistinguishingFailure(service: service)
        #expect(Self.spelled(emptied) == "rows", "an emptied service enumerates as \(emptied)")
        #expect(ProximityKeychainItem.deleteReportingStatus(account: account, service: service)
                    == PackageKeychainStore.success, "a delete of a row that is gone did not succeed")
    }

    // MARK: - Helpers

    /// One seal key's scope, the session store's or the routed store's, each on a `.test.` service of
    /// its own under `.packageTest`'s service for it and a scratch folder nothing creates.
    private enum SealScope {
        /// The session store's scope.
        case session(MeshSessionStorageScope)
        /// The routed store's scope.
        case routed(MeshRoutedStorageScope)

        /// The scope's name, for a failure message.
        var name: String {
            switch self {
            case .session(let scope): "session \(scope.keychainService)"
            case .routed(let scope): "routed \(scope.keychainService)"
            }
        }

        /// The keychain service holding the scope's seal key.
        var service: String {
            switch self {
            case .session(let scope): scope.keychainService
            case .routed(let scope): scope.keychainService
            }
        }

        /// The seal key's account, the scope namespace's.
        var account: String {
            switch self {
            case .session(let scope): scope.namespace.installation.keychain.meshSessionSealKey.account
            case .routed(let scope): scope.namespace.installation.keychain.meshRoutedSealKey.account
            }
        }
    }

    /// An install binding for the scopes these cells build: sixteen fixed bytes, which no seal-key read
    /// consults.
    private struct FixedInstallBinding: ProximityInstallBinding {
        /// The same sixteen bytes for sealing and opening alike.
        func read(for access: ProximityInstallBindingAccess) throws(ProximityInstallBindingReadError) -> Data? {
            Data(repeating: 0x5A, count: 16)
        }
    }

    /// A fresh `.test.` service under `base`: `<base>.test.<UUID>`.
    private static func testService(under base: String) -> String {
        "\(base).test.\(UUID().uuidString)"
    }

    /// A scratch folder for a scope, under the temporary directory, which nothing here creates.
    private static func scratchFolder() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("PackageKeychainStoreTests-\(UUID().uuidString)")
    }

    /// A session scope under `.packageTest` on a fresh `.test.` service.
    private static func sessionScope() -> SealScope {
        let rows = ProximityNamespace.packageTest.installation.keychain
        return .session(MeshSessionStorageScope(
            namespace: .packageTest, directory: scratchFolder(),
            keychainService: testService(under: rows.meshSessionSealKey.service), installBinding: FixedInstallBinding()))
    }

    /// A routed scope under `.packageTest` on a fresh `.test.` service.
    private static func routedScope() -> SealScope {
        let rows = ProximityNamespace.packageTest.installation.keychain
        return .routed(MeshRoutedStorageScope(
            namespace: .packageTest, directory: scratchFolder(),
            keychainService: testService(under: rows.meshRoutedSealKey.service), installBinding: FixedInstallBinding()))
    }

    /// An identity under `.packageTest` on `service`, provisioned.
    @MainActor private static func provisionedIdentity(on service: String) throws -> IdentityService {
        let identity = IdentityService(namespace: .packageTest, keychainService: service)
        try identity.ensureProvisioned()
        return identity
    }

    /// The scope's seal key, asked for to seal (which may mint) or to open (which never does), spelled:
    /// `available <the key's bytes in hex>`, `deferred <reason>` or `refused <cause>`.
    private static func key(_ scope: SealScope, opening: Bool) -> String {
        switch scope {
        case .session:
            switch opening ? MeshSessionSealKey.forOpen(service: scope.service, account: scope.account)
                           : MeshSessionSealKey.forSeal(service: scope.service, account: scope.account) {
            case .available(let key): return "available \(hex(key))"
            case .deferred(let reason): return "deferred \(reason)"
            case .refused(let cause): return "refused \(cause)"
            }
        case .routed:
            switch opening ? MeshRoutedSealKey.forOpen(service: scope.service, account: scope.account)
                           : MeshRoutedSealKey.forSeal(service: scope.service, account: scope.account) {
            case .available(let key): return "available \(hex(key))"
            case .deferred(let reason): return "deferred \(reason)"
            case .refused(let cause): return "refused \(cause)"
            }
        }
    }

    /// Wipes the scope's seal key, as its store's delete-all does.
    private static func wipe(_ scope: SealScope) {
        switch scope {
        case .session: MeshSessionSealKey.wipe(service: scope.service)
        case .routed: MeshRoutedSealKey.wipe(service: scope.service)
        }
    }

    /// The funnel's absence-distinguishing read of the `.packageTest` identity's signing row on `service`,
    /// spelled `found <hex>`, `absent` or `unreadable <status>`.
    private static func signingRow(on service: String) -> String {
        let account = ProximityNamespace.packageTest.installation.keychain.identity.signingPrivateKey
        switch ProximityKeychainItem.loadDistinguishingAbsence(account: account, service: service) {
        case .found(let data): return "found \(hex(data))"
        case .absent: return "absent"
        case .unreadable(let status): return "unreadable \(status)"
        }
    }

    /// An enumeration's outcome, spelled `rows` and each row's `<account>=<hex>`, or `unreadable <status>`.
    private static func spelled(_ listing: ProximityKeychainItem.EnumerationResult) -> String {
        switch listing {
        case .rows(let rows): return (["rows"] + rows.map { "\($0.account)=\(hex($0.data))" }).joined(separator: " ")
        case .unreadable(let status): return "unreadable \(status)"
        }
    }

    /// Bytes as lowercase hex, read through Foundation's `ContiguousBytes`, so a key needs no CryptoKit
    /// import here (rule I11, `PackageTestHygieneTests`, holds the package's imports).
    private static func hex(_ bytes: some ContiguousBytes) -> String {
        bytes.withUnsafeBytes { Data($0) }.map { String(format: "%02x", $0) }.joined()
    }
}
