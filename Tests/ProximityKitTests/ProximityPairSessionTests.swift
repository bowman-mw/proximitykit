// ProximityPairSessionTests.swift
// ProximityKitTests
//
// The pair session, `ProximityPairSession`, driven in ProximityKit's own package tests over its real
// radio, `NetworkPairSession`, with the radio's framework objects suppressed
// (`runWithoutRadiosForTesting`), so every decision around the listener and the browser runs and no
// cell starts Bonjour (the unit-test invariant for proximity). The session is built over a
// `PackageTestHost` under `.packageTest` and handed the radio through its internal `makeRadio` seam;
// its identity provisions into the bundle's in-memory keychain.
//
// What the cell holds: a peer the session forgot at a disconnect only one side saw (a refused hello:
// the refusing device never paired, so it never re-minted its posture, and its record comes back
// unchanged) is listed again, and resolves as a dialer again, at the resumed radio's first sighting of
// it, with no refresh; and an unchanged record is otherwise announced once.

import Foundation
@testable import ProximityKit
import Testing

/// The pair session over its real radio, framework objects suppressed: what a resume owes the session's
/// picker after a disconnect only one side saw.
@Suite @MainActor struct ProximityPairSessionTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer has
    /// run before a cell builds a session whose identity reaches the keychain.
    let keychain = PackageTestEnvironment.keychain

    // MARK: - Rediscovery after a resume

    /// **A peer forgotten at a one-sided disconnect is listed again when the resumed radio browses it,
    /// unchanged, with no refresh.**
    ///
    /// The shape two simulators showed on a first run: this device dials Blair, its channel
    /// opens (the pairing is registered and the radio pauses), and Blair refuses the hello and closes the
    /// connection; the radio ends the tunnel and tells the session, which forgets Blair (her row and her
    /// discovered handle, as it forgets every disconnected peer) and reopens the radio under a fresh
    /// posture. Blair never paired, so she never paused or re-minted: the resumed browser finds her under
    /// the very record the radio already holds. That sighting lists her again, and her `sid` resolves her
    /// own dial again. A radio that announced only a changed record left her out of the picker, and
    /// refused her dial, until a refresh or a stop. Around it, the dedup that keeps an unchanged record
    /// from being announced twice holds: before the pairing, and once the owed sighting is paid.
    @Test func aPeerForgottenAtAOneSidedDisconnectIsListedAgainWhenTheResumedRadioBrowsesIt() throws {
        let host = PackageTestHost()
        let profile = ProximityPairProfile(
            auditArea: "pktest.pair", radio: host.proximityNamespace.family.radios.pair, advertisementMode: "pair")
        let radio = NetworkPairSession(namespace: host.proximityNamespace, profile: profile)
        try radio.runWithoutRadiosForTesting()
        let session = ProximityPairSession(host: host, profile: profile, makeRadio: { radio })
        var events: [ProximityPairSession.Event] = []
        session.onEvent = { events.append($0) }
        session.markRunningForTesting()

        let name = host.proximityNamespace.family.radios.meshInstanceNamePrefix + "b1a1700000f1"
        let key = MeshLinkKey("\(name).\(radio.serviceType).local.")
        let record = ProximityPairAdvertisement.publishedFields(
            from: [ProximityPairAdvertisement.versionKey: ProximityPairAdvertisement.version,
                   ProximityPairAdvertisement.modeKey: profile.advertisementMode,
                   ProximityPairAdvertisement.nameKey: "Blair"],
            sessionID: "blair-sid")
        radio.noteBrowsedForTesting(key, instanceName: name, advertisement: record)
        radio.noteBrowsedForTesting(key, instanceName: name, advertisement: record)
        let blair = radio.handleForTesting(key)
        #expect(session.nearbyPeers.map(\.id) == [blair.id] && events == [.discovered(name: "Blair")],
                "Blair's sighting and the same record again left the rows \(session.nearbyPeers) and the events \(events)")

        // This device dials Blair: the channel opens, the pairing is registered and the radio goes quiet.
        radio.bookTunnelForTesting(key, role: .initiator)
        _ = session.makeRetainedConnectionCoordinatorForTesting(
            peer: blair, transport: radio.channel(for: blair), ranging: NoopRangingProvider())
        let worn = radio.advertisedSessionID
        #expect(radio.isDiscoveryPaused, "registering the pairing did not pause the radio")

        // Blair refuses the hello and closes the connection: the radio ends the tunnel and tells the
        // session, as its receive loop does when a connection ends under it.
        radio.endTunnel(blair)
        radio.onPeerDisconnected?(blair, "The outbound recipe-share connection ended")
        #expect(!radio.isDiscoveryPaused && radio.advertisedSessionID != worn && events.contains(.reopened),
                "the eviction did not reopen the radio under a fresh posture: \(events)")
        #expect(session.nearbyPeers.isEmpty && session.resolveDialerForTesting("blair-sid") == nil,
                "the session still lists Blair after her disconnect, though it forgets a disconnected peer")

        // The resumed browser finds Blair under her unchanged record, and then again.
        let before = events.count
        radio.noteBrowsedForTesting(key, instanceName: name, advertisement: record)
        #expect(session.nearbyPeers.map(\.id) == [blair.id], """
            the resumed radio's sighting of Blair's unchanged record did not list her again, so the picker \
            stays empty until a refresh: rows \(session.nearbyPeers), events since the disconnect \
            \(Array(events.dropFirst(before)))
            """)
        #expect(session.resolveDialerForTesting("blair-sid")?.id == blair.id,
                "Blair's own dial still resolves to nobody, so this device would refuse her hello")
        radio.noteBrowsedForTesting(key, instanceName: name, advertisement: record)
        #expect(Array(events.dropFirst(before)) == [.discovered(name: "Blair")],
                "the resumed radio's sightings of an unchanged record announced \(Array(events.dropFirst(before)))")
        #expect(!events.contains(.discoveryRefreshed), "the cell refreshed discovery: \(events)")
        session.stop()
        try host.tearDown()
    }
}
