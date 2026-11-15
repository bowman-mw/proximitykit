// PairDialAndEnvelopeFixesTests.swift
// ProximityKitTests
//
// Three 0.2.0 fixes that were left over from 0.1.x:
//
//   - a pair-radio dial that fails before its channel opens re-lists the peer, whose record is still
//     on the air, at once. The owner forgets a peer at every disconnect, and only a resume used to owe
//     its sighting, so a dial that never paired left the picker without a row until a refresh;
//   - every mesh envelope `sendEnvelopeCore` signs carries an expiry. That is held in source, because
//     the door is private to the mesh manager and reached only over a live slot;
//   - the pair radio's frozen diagnostic tokens are `pair.quic.*`, the package's own name for the
//     radio, and no `recipe.quic` token is left in the module.
//
// The radio runs with its framework objects suppressed, so nothing starts Bonjour.

import Foundation
@testable import ProximityKit
import Testing

/// 0.2.0's leftovers: the failed dial's row, the mesh envelope's expiry, the radio's token names.
@Suite @MainActor struct PairDialAndEnvelopeFixesTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built.
    let keychain = PackageTestEnvironment.keychain

    /// **A dial that fails before its channel opens lists the peer again, at once.**
    @Test func aDialThatFailsBeforeItsChannelOpensListsThePeerAgain() throws {
        let host = PackageTestHost()
        let profile = ProximityPairProfile(
            auditArea: "pktest.pair", radio: host.proximityNamespace.family.radios.pair, advertisementMode: "pair")
        let radio = NetworkPairSession(namespace: host.proximityNamespace, profile: profile)
        try radio.runWithoutRadiosForTesting()
        let session = ProximityPairSession(host: host, profile: profile, makeRadio: { radio })
        session.markRunningForTesting()

        let name = host.proximityNamespace.family.radios.meshInstanceNamePrefix + "d1a100000001"
        let key = MeshLinkKey("\(name).\(radio.serviceType).local.")
        let record = ProximityPairAdvertisement.publishedFields(
            from: ProximityPairAdvertisement.ownerFields(mode: "pair", name: "Drew", friendTags: []),
            sessionID: "drew-sid")
        radio.noteBrowsedForTesting(key, instanceName: name, advertisement: record)
        #expect(session.nearbyPeers.map(\.displayName) == ["Drew"])

        radio.bookTunnelForTesting(key, role: .initiator)
        radio.failDialForTesting(key)
        #expect(radio.tunnelCountForTesting == 0, "the failed dial's tunnel is still booked")
        #expect(!radio.isDiscoveryPaused, "a dial that never paired paused the radio")
        #expect(session.nearbyPeers.map(\.displayName) == ["Drew"],
                "the failed dial left the picker without Drew, whose record is still on the air: \(session.nearbyPeers)")
        #expect(session.resolveDialerForTesting("drew-sid") != nil, "and her own dial no longer resolves")
        session.stop()
        try host.tearDown()
    }

    /// **Every mesh envelope is signed with an expiry, the coordinator's five minutes.**
    @Test func everyMeshEnvelopeIsSignedWithAnExpiry() throws {
        let code = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift"))
        let core = try #require(MeshRoutedSourceScan.bracedBody(after: "private func sendEnvelopeCore(", in: code),
                                "the mesh's one signing door is gone")
        #expect(core.components(separatedBy: "ProximityIdentityEnvelope.signed(").count - 1 == 1,
                "the door no longer signs exactly once")
        #expect(core.contains("expiresAt: signedAt.addingTimeInterval(Self.meshEnvelopeLifetime)"),
                "the mesh envelope is signed without an expiry again")
        #expect(MeshNetworkManager.meshEnvelopeLifetime == 5 * 60, "the lifetime moved off the coordinator's five minutes")
    }

    /// **The pair radio's tokens are `pair.quic.*`, and no `recipe.quic` token is left.**
    @Test func thePairRadiosTokensAreItsOwnName() throws {
        let files = try PackageSwiftFiles.sources()
        #expect(files.count > 50, "the source walk lost its files")
        let stale = files.filter { $0.text.contains("recipe" + ".quic") }.map(\.path)
        #expect(stale.isEmpty, "a `recipe.quic` token is still in \(stale)")
        let radio = try PackageRoot.source("Sources/ProximityKit/Transport/NetworkPairSession.swift")
        #expect(radio.contains(#"category: "proximity.pair.quic""#), "the radio's log category is not its own name")
    }
}
