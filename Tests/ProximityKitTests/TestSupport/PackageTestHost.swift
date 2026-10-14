// PackageTestHost.swift
// ProximityKitTests
//
// ProximityKit plan step A1.1: the host ProximityKit's package tests build a manager over. ProximityKit
// reaches the app it runs in only through `ProximityHost`, and the package's tests cannot name Fernlet's
// store or any of Fernlet's test hosts, which lean on FernletConnections and FernletSocial. So this one is
// built from ProximityKit's public API alone, states every requirement itself, keeps its files on a
// scratch root and its keychain rows on `.test.` services of its own, in the bundle's in-memory keychain,
// and makes sure the bundle's keychain store and audit sink are installed before anything is built over it.

import Foundation
import ProximityKit

/// A ``ProximityHost`` of ProximityKit's alone, on a scratch root and keychain services of its own: the
/// host a package suite builds a mesh manager or a pair session over.
///
/// **Every requirement stated here.** The protocol's thirteen requirements, the two storage scopes it
/// would default included, are this class's own members, and nothing in the package's tests extends
/// `ProximityHost` (Fernlet's tests declare their defaults in such an extension, and this target's
/// `PackageTestHygieneTests` refuses one):
/// - the namespace it is handed, `.packageTest` unless a cell hands it another;
/// - the display name it is handed, `"Tester"` by default, and the fallback name `"Test device"`;
/// - its own blocked, revoked and trusted sets, which ``isBlockedFingerprint(_:)``,
///   ``blockProximityPeer(signingPublicKey:)`` and every ``PackageTrustPolicy`` it hands out read;
/// - a scratch root, `temporaryDirectory/PackageTestHost-<UUID>`, never Application Support: nothing
///   here creates it (a store a cell opens does), and ``tearDown()`` removes it;
/// - both storage scopes on that root, under its namespace and its install binding, on the `.test.`
///   services `org.example.pktest.mesh-session.test.<UUID>` and `org.example.pktest.mesh-routed.test.<UUID>`;
/// - a ``PinnedInstallBinding`` of sixteen fixed bytes, read with no keychain;
/// - a fresh ``PackageTrustPolicy`` per ``makeProximityTrustPolicy()`` call and a fresh
///   `NoopRangingProvider` per ``makeProximityRangingProvider()`` call;
/// - a fresh identity under its namespace per ``makeProximityIdentity()`` call, every one on the host's
///   one `.test.` service ``identityService``, `org.example.pktest.identity.test.<UUID>`, with no
///   provisioning participant;
/// - three routed rows, the temporary-message, heart and photo rows on its namespace's tokens, in the
///   shapes Fernlet's rows take and with the caps Fernlet's rows computed to at plan step A1.1, written
///   here as literals (the constants they are computed from are FernletSocial's); none under the
///   reserved `control` token.
///
/// One UUID per host names its root and its three services, so two hosts share no file and no row.
///
/// **The bundle's environment first.** Its initializer reads `PackageTestEnvironment.keychain` and
/// `PackageTestEnvironment.audit` before anything else, so the in-memory keychain store and the audit
/// sink are ProximityKit's before a manager built over the host provisions its identity or logs a line:
/// every identity row and seal key lands in the store, never a keychain, and every line reaches the
/// bundle's captures.
///
/// **Held by this target's walls.** `PackageTestTreeWallTests` reads this file as the package tests' host
/// double: a double that states its root states both scopes. Its ML5 refuses a manager or a pair session
/// built over a host expression that is a call, so a cell builds one over a host it holds in a `let` that
/// outlives the manager.
@MainActor
final class PackageTestHost: ProximityHost {

    /// The bundle's in-memory keychain, where every row this host's identity and scopes write lives.
    let keychain: PackageKeychainStore

    /// The namespace this host was handed.
    let proximityNamespace: ProximityNamespace

    /// The name this device goes by, as this host was handed it.
    let proximityDisplayName: String

    /// The name this device goes by when its own name trims to nothing.
    let proximityFallbackDisplayName = "Test device"

    /// The scratch root: `temporaryDirectory/PackageTestHost-<UUID>`.
    let proximitySupportDirectory: URL

    /// The sealed mesh-session scope: the root, under this host's namespace and binding, on a `.test.`
    /// service of its own.
    let meshSessionStorage: MeshSessionStorageScope

    /// The sealed routed scope: the root, under this host's namespace and binding, on a `.test.` service
    /// of its own.
    let meshRoutedStorage: MeshRoutedStorageScope

    /// Sixteen fixed bytes, read with no keychain.
    let proximityInstallBinding: any ProximityInstallBinding

    /// The keychain service every identity this host builds keeps its rows under:
    /// `org.example.pktest.identity.test.<UUID>`.
    let identityService: String

    /// The fingerprints this host has blocked.
    var blockedFingerprints: Set<String> = []

    /// The signing keys this host has blocked.
    var blockedSigningKeys: Set<Data> = []

    /// The signing keys this host treats as revoked.
    var revokedSigningKeys: Set<Data> = []

    /// The signing keys this host trusts.
    var trustedSigningKeys: Set<Data> = []

    /// A host of `namespace`, whose user goes by `displayName`, on a fresh scratch root and fresh `.test.`
    /// services. Reads the bundle's keychain store and audit sink first, so both are installed; creates
    /// nothing on disk and writes no keychain row.
    ///
    /// - Parameters:
    ///   - namespace: The host's namespace; `.packageTest` by default.
    ///   - displayName: The name this device goes by; `"Tester"` by default.
    init(namespace: ProximityNamespace = .packageTest, displayName: String = "Tester") {
        keychain = PackageTestEnvironment.keychain
        _ = PackageTestEnvironment.audit
        let id = UUID().uuidString
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("PackageTestHost-\(id)", isDirectory: true)
        let binding = PinnedInstallBinding(bytes: Data(repeating: 0xA5, count: 16))
        proximityNamespace = namespace
        proximityDisplayName = displayName
        proximitySupportDirectory = root
        proximityInstallBinding = binding
        identityService = "org.example.pktest.identity.test.\(id)"
        meshSessionStorage = MeshSessionStorageScope(
            namespace: namespace, directory: root,
            keychainService: "org.example.pktest.mesh-session.test.\(id)", installBinding: binding)
        meshRoutedStorage = MeshRoutedStorageScope(
            namespace: namespace, directory: root,
            keychainService: "org.example.pktest.mesh-routed.test.\(id)", installBinding: binding)
    }

    /// Whether this host has blocked the peer whose fingerprint this is.
    ///
    /// - Parameter fingerprint: The peer's fingerprint.
    /// - Returns: Whether ``blockedFingerprints`` holds it.
    func isBlockedFingerprint(_ fingerprint: String) -> Bool {
        blockedFingerprints.contains(fingerprint)
    }

    /// Blocks the peer with this signing key: the key joins ``blockedSigningKeys`` and its fingerprint
    /// ``blockedFingerprints``. An empty key blocks nothing.
    ///
    /// - Parameter signingPublicKey: The peer's signing public key.
    func blockProximityPeer(signingPublicKey: Data) {
        guard !signingPublicKey.isEmpty else { return }
        blockedSigningKeys.insert(signingPublicKey)
        blockedFingerprints.insert(IdentityService.fingerprint(of: signingPublicKey))
    }

    /// A fresh trust policy over this host's sets, for one connection.
    ///
    /// - Returns: A new ``PackageTrustPolicy``.
    func makeProximityTrustPolicy() -> any ProximityTrustPolicy {
        PackageTrustPolicy(host: self)
    }

    /// A fresh provider that never ranges, for one connection.
    ///
    /// - Returns: A new `NoopRangingProvider`.
    func makeProximityRangingProvider() -> any RangingProvider {
        NoopRangingProvider()
    }

    /// A fresh identity under this host's namespace, on ``identityService``, with no participant.
    ///
    /// - Returns: A new identity, which reads and writes nothing until it is provisioned.
    func makeProximityIdentity() -> IdentityService {
        IdentityService(namespace: proximityNamespace, keychainService: identityService)
    }

    /// The temporary-message, heart and photo rows on this host's namespace's routed types: the shapes
    /// Fernlet's rows take, and the caps they computed to at plan step A1.1 (9 065, 553 and 10 551 337
    /// bytes) as literals.
    var meshRoutedTypeEntries: [MeshRoutedTypeEntry] {
        let types = proximityNamespace.family.vocabulary.routedTypes
        return [
            MeshRoutedTypeEntry(
                token: types.tempMessage, maxItemByteCount: 9_065, destinations: .fullRosterAtCreation,
                relayRetention: .originRetainsUntilDeparture, finalAck: .durableRecipientStorage,
                expiry: .meshHardDeadlinePlusGrace, contentScope: .session),
            MeshRoutedTypeEntry(
                token: types.heart, maxItemByteCount: 553, destinations: .singleRecipient,
                relayRetention: .originRetainsUntilDeparture, finalAck: .foregroundDecryptAndLedgerCommit,
                expiry: .meshHardDeadlinePlusGrace, contentScope: .persistent),
            MeshRoutedTypeEntry(
                token: types.photo, maxItemByteCount: 10_551_337, destinations: .fullRosterAtCreation,
                relayRetention: .originRetainsUntilDeparture, finalAck: .durableRecipientStorage,
                expiry: .meshHardDeadlinePlusGrace, contentScope: .persistent)
        ]
    }

    /// Removes the scratch root and everything under it, when anything created it. The keychain rows stay
    /// in the bundle's in-memory store, on services no other host names, and end with the process.
    ///
    /// - Throws: The file manager's error when the root exists and cannot be removed.
    func tearDown() throws {
        guard FileManager.default.fileExists(atPath: proximitySupportDirectory.path) else { return }
        try FileManager.default.removeItem(at: proximitySupportDirectory)
    }
}

/// A session trust policy over a ``PackageTestHost``'s own sets: revoked, blocked and trusted are what
/// the host's sets say at the moment of the question, and every audit the coordinator reports is kept.
///
/// The host hands out a new one per connection; the coordinator holds it `weak`, so its owner keeps it.
/// It holds its host strongly: the host holds no policy, so there is no cycle.
@MainActor
final class PackageTrustPolicy: ProximityTrustPolicy {

    /// The host whose sets it answers from.
    let host: PackageTestHost

    /// Every audit the coordinator reported to this policy, in order.
    private(set) var audits: [ProximitySessionAudit] = []

    /// A policy over `host`'s sets.
    ///
    /// - Parameter host: The host it answers from.
    init(host: PackageTestHost) {
        self.host = host
    }

    /// Whether the host treats this signing key as revoked.
    ///
    /// - Parameter publicKey: The peer's signing public key.
    /// - Returns: Whether the host's revoked set holds it.
    func isRevokedProximitySigningKey(_ publicKey: Data) -> Bool {
        host.revokedSigningKeys.contains(publicKey)
    }

    /// Whether the host has blocked this signing key.
    ///
    /// - Parameter publicKey: The peer's signing public key.
    /// - Returns: Whether the host's blocked set holds it.
    func isBlockedProximitySigningKey(_ publicKey: Data) -> Bool {
        host.blockedSigningKeys.contains(publicKey)
    }

    /// Whether the host trusts the peer with this signing key.
    ///
    /// - Parameter signingPublicKey: The peer's signing public key.
    /// - Returns: Whether the host's trusted set holds it.
    func isTrustedProximityPeer(signingPublicKey: Data) -> Bool {
        host.trustedSigningKeys.contains(signingPublicKey)
    }

    /// Keeps one audit the coordinator reported.
    ///
    /// - Parameter audit: The event.
    func recordSessionAudit(_ audit: ProximitySessionAudit) {
        audits.append(audit)
    }
}

/// An install binding of fixed bytes, read with no keychain: what a ``PackageTestHost`` and its scopes
/// seal under, the same for sealing and opening alike.
struct PinnedInstallBinding: ProximityInstallBinding {

    /// The bytes every read answers.
    let bytes: Data

    /// Answers ``bytes``, whatever the access.
    ///
    /// - Parameter access: Whether the caller seals or opens; read the same either way.
    /// - Returns: ``bytes``.
    func read(for access: ProximityInstallBindingAccess) throws(ProximityInstallBindingReadError) -> Data? {
        bytes
    }
}
