// PackageTestHostTests.swift
// ProximityKitTests
//
// ProximityKit plan step A1.1: the canary of the package tests' host double and audit sink. This bundle is
// unhosted: no app installs a ProximityAudit sink, so ProximityKit would drop every line, and no app hands
// a manager a host, so a package suite could build none. PackageTestEnvironment installs a sink of the
// bundle's own (TestSupport/PackageAuditCapture.swift), and PackageTestHost (TestSupport/PackageTestHost.swift)
// is a host of ProximityKit's alone on a scratch root and `.test.` services. These cells hold that the sink
// delivers each line to the captures scoped to it and to no other, that the host's root and keychain
// services are scratch of its own, that it states its rows, its policy and its radio itself, and that a
// mesh manager built over it, unhosted, provisions its identity into the bundle's in-memory keychain and
// logs nothing, while one whose identity cannot be read logs its failure.

import Foundation
@testable import ProximityKit
import Testing

/// The package tests' host and audit sink: the sink delivers ProximityKit's lines to the captures scoped
/// to them, the host keeps its files and rows to itself and states every requirement itself, and a
/// manager built over the host works unhosted.
@Suite struct PackageTestHostTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer has
    /// run before a cell builds a host or a manager whose identity reaches the keychain.
    let keychain = PackageTestEnvironment.keychain

    // MARK: - The audit sink

    /// The bundle's sink is installed and delivers a line ProximityKit logs to a capture whose context
    /// scope the line holds, unchanged and before the call returns, and to none scoped to another rig's
    /// context; a capture built `markedOnly` keeps only what was logged inside its own marking; and a
    /// stopped capture keeps nothing more.
    @Test func theBundlesSinkDeliversEachLineToTheCapturesScopedToIt() {
        let rig = UUID().uuidString
        let mine = PackageAuditCapture(context: ["rig": rig])
        let other = PackageAuditCapture(context: ["rig": UUID().uuidString])
        let context = ["rig": rig, "peer": "0a1b2c3d4e5f", "reason": "canary", "count": "3"]
        ProximityAudit.log("packageAudit.canary", context: context)
        #expect(mine.lines == [PackageAuditLine(event: "packageAudit.canary", context: context)], """
            a ProximityKit line did not reach the capture scoped to its rig as one unchanged line before the \
            call returned (kept \(mine.lines)): the bundle's sink is not installed, was replaced, or does \
            not forward in line
            """)
        #expect(other.lines.isEmpty, "a capture scoped to another rig kept \(other.lines)")

        let marked = PackageAuditCapture(markedOnly: true)
        ProximityAudit.log("packageAudit.canary.unmarked", context: ["rig": rig])
        marked.marking { ProximityAudit.log("packageAudit.canary.marked", context: ["rig": rig]) }
        #expect(marked.lines.map(\.event) == ["packageAudit.canary.marked"],
                "a capture built markedOnly kept \(marked.lines.map(\.event))")
        #expect(mine.lines.map(\.event) == ["packageAudit.canary", "packageAudit.canary.unmarked",
                                            "packageAudit.canary.marked"],
                "the rig's capture kept \(mine.lines.map(\.event))")

        #expect(mine.stop(), "a live capture was not registered with the bundle's sink")
        ProximityAudit.log("packageAudit.canary.afterStop", context: ["rig": rig])
        #expect(mine.lines.count == 3, "a stopped capture kept \(mine.lines.map(\.event))")
        #expect(!mine.stop(), "a stopped capture was still registered")
        #expect(other.stop() && marked.stop(), "a live capture was not registered with the bundle's sink")
    }

    // MARK: - The host's files and rows

    /// A host's root is a fresh folder directly under the temporary directory, never under Application
    /// Support, which building the host does not create; both its scopes live on that root, under its
    /// namespace and its sixteen-byte binding; every keychain service it states is a `.test.` service of
    /// `.packageTest`'s, its identity's among them; and two hosts share no root and no service. The scopes
    /// are read through `any ProximityHost`, as a manager reads them, so a host whose own scope no longer
    /// answers the requirement (and leaves its default, the production scope, in place) fails here.
    @MainActor @Test func aHostsRootAndServicesAreScratchOfItsOwn() throws {
        let host = PackageTestHost()
        let second = PackageTestHost()
        let root = host.proximitySupportDirectory.standardizedFileURL
        let scratch = FileManager.default.temporaryDirectory.standardizedFileURL
        #expect(root.deletingLastPathComponent().path == scratch.path && root.lastPathComponent.hasPrefix("PackageTestHost-"),
                "the host's root \(root.path) is not a PackageTestHost folder directly under \(scratch.path)")
        #expect(!root.pathComponents.contains("Application Support"), "the host's root is under Application Support")
        #expect(!FileManager.default.fileExists(atPath: root.path), "building the host created its root")
        let asHost: any ProximityHost = host
        #expect(asHost.meshSessionStorage.directory == host.proximitySupportDirectory
                    && asHost.meshRoutedStorage.directory == host.proximitySupportDirectory,
                "a scope a manager reads lives off the host's root")
        #expect(asHost.meshSessionStorage.namespace == .packageTest && asHost.meshRoutedStorage.namespace == .packageTest,
                "a scope a manager reads is not under the host's namespace")
        #expect(asHost.meshSessionStorage.installBinding is PinnedInstallBinding
                    && asHost.meshRoutedStorage.installBinding is PinnedInstallBinding,
                "a scope a manager reads is not sealed under the host's binding")
        let sealing = try host.proximityInstallBinding.read(for: .seal)
        let opening = try host.proximityInstallBinding.read(for: .open)
        #expect(sealing?.count == 16 && opening == sealing,
                "the host's binding read \(String(describing: sealing)) to seal and \(String(describing: opening)) to open")

        let services = Self.services(of: host)
        #expect(services.count == 3 && services.allSatisfy { $0.hasPrefix("org.example.pktest.") && $0.contains(".test.") },
                "the host states a keychain service that is not a .test. service of .packageTest's: \(services.sorted())")
        #expect(host.makeProximityIdentity().keychainService == host.identityService,
                "the host's identity is not on its identity service")
        #expect(host.proximitySupportDirectory != second.proximitySupportDirectory, "two hosts share a root")
        #expect(services.isDisjoint(with: Self.services(of: second)), "two hosts share a keychain service")
        try host.tearDown()
        try second.tearDown()
    }

    /// A host states its rows, its policy and its radio itself: the three routed rows on `.packageTest`'s
    /// temporary-message, heart and photo tokens, none on the reserved control token, each with its cap,
    /// every one registered by the engine's registry; a fresh policy and a fresh provider per call; a
    /// policy that answers from the host's sets as they stand and keeps its audits; a block that reaches
    /// the host's fingerprint check; and its two names.
    @MainActor @Test func aHostStatesItsRowsItsPolicyAndItsRadioItself() throws {
        let host = PackageTestHost()
        let types = ProximityNamespace.packageTest.family.vocabulary.routedTypes
        let rows = host.meshRoutedTypeEntries
        #expect(rows.map(\.token) == [types.tempMessage, types.heart, types.photo], "the host's rows are \(rows.map(\.token))")
        #expect(rows.map(\.maxItemByteCount) == [9_065, 553, 10_551_337], "the rows' caps are \(rows.map(\.maxItemByteCount))")
        #expect(MeshRoutedTypeRegistry(entries: rows).tokens == Set(rows.map(\.token)) && !rows.contains { $0.token == types.control },
                "the engine's registry dropped a row, or a row is on the reserved token")

        let policy = host.makeProximityTrustPolicy()
        #expect(policy !== host.makeProximityTrustPolicy(), "the host handed out one policy twice")
        let (blocked, revoked, trusted) = (Data(repeating: 0x42, count: 32), Data(repeating: 0x43, count: 32),
                                           Data(repeating: 0x44, count: 32))
        let fingerprint = IdentityService.fingerprint(of: blocked)
        #expect(!policy.isBlockedProximitySigningKey(blocked) && !host.isBlockedFingerprint(fingerprint),
                "a peer nobody blocked is blocked")
        host.blockProximityPeer(signingPublicKey: blocked)
        host.revokedSigningKeys.insert(revoked)
        host.trustedSigningKeys.insert(trusted)
        #expect(policy.isBlockedProximitySigningKey(blocked) && host.isBlockedFingerprint(fingerprint),
                "a blocked peer is not blocked by key and by fingerprint")
        #expect(policy.isRevokedProximitySigningKey(revoked) && !policy.isRevokedProximitySigningKey(trusted),
                "the policy does not answer revoked from the host's set")
        #expect(policy.isTrustedProximityPeer(signingPublicKey: trusted) && !policy.isTrustedProximityPeer(signingPublicKey: blocked),
                "the policy does not answer trusted from the host's set")
        let audit = ProximitySessionAudit(kind: .pairingStarted, message: "canary")
        policy.recordSessionAudit(audit)
        #expect((policy as? PackageTrustPolicy)?.audits == [audit], "the policy did not keep the audit")

        let provider = host.makeProximityRangingProvider()
        #expect(provider is NoopRangingProvider && provider !== host.makeProximityRangingProvider(),
                "the host's provider is \(type(of: provider)), or one provider was handed out twice")
        #expect(host.proximityDisplayName == "Tester" && host.proximityFallbackDisplayName == "Test device",
                "the host's names are \(host.proximityDisplayName) and \(host.proximityFallbackDisplayName)")
        try host.tearDown()
    }

    // MARK: - A manager over the host

    /// A mesh manager built over a host, unhosted, provisions its identity into the bundle's in-memory
    /// keychain: the identity's four rows land on the host's identity service, a fresh identity of the
    /// host's reads the manager's signing key back from them without minting, and building it logs no
    /// line at all. A manager over a host whose identity service the store answers as unreadable logs
    /// the identity's unreadable row and then exactly one `mesh.identity.provisionFailed` line, each
    /// carrying the store's status, writes no row and holds no key: the same capture sees those lines,
    /// so its first read of nothing is not vacuous.
    @MainActor @Test func aManagerOverTheHostProvisionsItsIdentityIntoTheStore() throws {
        let host = PackageTestHost()
        let capture = PackageAuditCapture(markedOnly: true)
        #expect(host.keychain.rows(service: host.identityService).isEmpty, "a fresh host's identity service holds rows")
        let manager = capture.marking { MeshNetworkManager(store: host) }
        #expect(capture.lines.isEmpty, "building a manager over the host logged \(capture.lines)")
        #expect(manager.localSigningPublicKey.count == 32, "the manager holds no provisioned identity")
        let accounts = ProximityNamespace.packageTest.installation.keychain.identity
        let expected = [accounts.signingPrivateKey, accounts.keyAgreementPrivateKey, accounts.signingPublicKeyCache,
                        accounts.keyAgreementPublicKeyCache].sorted()
        #expect(host.keychain.rows(service: host.identityService).map(\.account) == expected,
                "the identity's rows in the store are \(host.keychain.rows(service: host.identityService).map(\.account))")
        let readBack = host.makeProximityIdentity()
        try readBack.ensureProvisioned()
        #expect(readBack.localSigningPublicKey == manager.localSigningPublicKey,
                "a fresh identity of the host's minted a key instead of reading the manager's back")
        #expect(host.keychain.rows(service: host.identityService).count == expected.count, "reading the identity back added a row")

        let refused = PackageTestHost()
        let status = refused.keychain.makeUnreadable(service: refused.identityService)
        let failing = capture.marking { MeshNetworkManager(store: refused) }
        let failures = capture.lines(named: "mesh.identity.provisionFailed")
        #expect(capture.lines.map(\.event) == ["identity.keychain.readFailed", "mesh.identity.provisionFailed"],
                "a manager whose identity cannot be read logged \(capture.lines)")
        #expect(capture.lines.first?.context["status"] == "\(status)" && failures.count == 1
                    && failures.first?.context["error"]?.contains("\(status)") == true,
                "the lines do not carry the store's status \(status): \(capture.lines)")
        #expect(failing.localSigningPublicKey.isEmpty, "a manager whose identity cannot be read holds a key")
        #expect(refused.keychain.rows(service: refused.identityService).isEmpty, "an unreadable identity service was minted over")
        refused.keychain.makeReadable(service: refused.identityService)
        #expect(capture.stop(), "the capture was not registered with the bundle's sink")
        try readBack.wipe()
        try host.tearDown()
        try refused.tearDown()
    }

    // MARK: - Helpers

    /// Every keychain service `host` states: its identity's and both scopes', each scope read through
    /// `any ProximityHost`, as a manager reads it.
    @MainActor private static func services(of host: PackageTestHost) -> Set<String> {
        let asHost: any ProximityHost = host
        return [host.identityService, asHost.meshSessionStorage.keychainService, asHost.meshRoutedStorage.keychainService]
    }
}
