// MeshDialPolicyTests.swift
// ProximityKitTests
//
// A partial copy (ProximityKit plan step A1, the split's second batch of copied suites: those that reach
// the keychain and open no store): of the Fernlet repository's FernletTests file of the same name, this
// holds only `MeshDialPolicyManagerTests`, with its name and tests unchanged; its other suite,
// `MeshDialPolicyTests`, stays there.

import Foundation
import Testing
@testable import ProximityKit

// MARK: - MeshDialPolicyManagerTests

/// The manager half: the same decision reached through a live `MeshNetworkManager`, over the
/// discovery info it actually advertises.
///
/// The decision AND the act are observable now. `MeshNetworkManager` used to own its
/// `MeshMultipeerSession` outright (`private let meshSession = MeshMultipeerSession()`), so nothing
/// at tier 1 could assert an invite was actually SENT without starting real radios — only that the
/// policy said to send one. P2 item 8 replaced that with an injected ``MeshTransportSession``, so
/// the last three tests here drive discovery through a `FakeMeshTransportSession` and read the
/// invite off it.
@Suite(.serialized) @MainActor
struct MeshDialPolicyManagerTests {
    let store = PackageTestHost()

    /// Self-comparison through the real advertisement: a manager shown its own discovery info must
    /// not invite. This is the production shape of the equal-value case — `sid` is per-launch, so
    /// an advertisement carrying ours IS ours.
    @Test func manager_neverInvitesItsOwnAdvertisement() {
        let manager = MeshNetworkManager(store: store)
        let ownAdvertisement = PeerHandle(
            id: UUID(),
            displayHint: "iPhone",
            discoveryInfo: manager.currentDiscoveryInfo(),
            advertisedFingerprint: nil
        )

        #expect(!manager.shouldInitiateInvite(to: ownAdvertisement),
                "A manager must never invite its own echoed advertisement")
    }

    /// The instance method and the pure policy must not drift: the instance is only a reader of
    /// `discoveryInfo["sid"]` in front of the same comparison.
    @Test func manager_agreesWithThePurePolicyOnEveryAdvertisementState() {
        let manager = MeshNetworkManager(store: store)
        let localSessionID = manager.currentDiscoveryInfo()["sid"] ?? ""
        #expect(!localSessionID.isEmpty, "test premise: a manager always advertises a session id")

        let peerStates: [String?] = [
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            localSessionID,
            nil,
            ""
        ]
        for peerSessionID in peerStates {
            let expected = MeshNetworkManager.shouldInitiateInvite(
                localSessionID: localSessionID, peerSessionID: peerSessionID
            )
            #expect(manager.shouldInitiateInvite(to: Self.peer(sessionID: peerSessionID)) == expected,
                    "Instance and policy disagree for peer sid \(peerSessionID ?? "nil")")
        }
    }

    /// The production analogue of a late TXT record: a peer first seen without an advertisement is
    /// invited (unrankable ⇒ invite), and can stop being the one we invite once its `sid` arrives.
    ///
    /// Same monotone direction as the probe's classification rule — the degraded reading is the
    /// permissive one, so a late advertisement can only ever withdraw our invite, never create a
    /// window where neither side had one.
    @Test func manager_aPeerThatLaterAdvertisesASessionIDCanStopBeingTheOneWeInvite() {
        let manager = MeshNetworkManager(store: store)
        let localSessionID = manager.currentDiscoveryInfo()["sid"] ?? ""
        #expect(!localSessionID.isEmpty, "test premise: a manager always advertises a session id")

        #expect(manager.shouldInitiateInvite(to: Self.peer(sessionID: nil)),
                "An unresolved peer must be invited rather than waited on")

        let higher = "ffffffff-ffff-ffff-ffff-ffffffffffff"
        #expect(localSessionID < higher, "test premise: a lowercase sid sorts above an uppercase one")
        #expect(!manager.shouldInitiateInvite(to: Self.peer(sessionID: higher)),
                "Once the peer's higher sid arrives, it becomes the inviter and we stop")
        #expect(manager.shouldInitiateInvite(to: Self.peer(sessionID: "00000000-0000-0000-0000-000000000000")),
                "A peer whose arriving sid sorts below ours leaves us the inviter")
    }

    // MARK: - Through the injected transport

    /// The decision, now followed all the way to the radio: a peer this manager outranks is not
    /// merely *judged* invitable, an invite is handed to the transport.
    @Test func manager_actuallySendsTheInviteForAPeerItOutranks() {
        let transport = FakeMeshTransportSession()
        let manager = MeshNetworkManager(store: store, transport: transport)
        manager.markProximityJoinForTesting()
        let lower = Self.peer(sessionID: "00000000-0000-0000-0000-000000000000")
        #expect(manager.shouldInitiateInvite(to: lower), "test premise: we outrank this peer")

        transport.discover(lower)

        #expect(transport.invitedPeers.map(\.id) == [lower.id],
                "the manager must hand the invite to its transport, not merely decide to")
    }

    /// The other side of the tie-break, at the same vantage point: a peer that outranks US must
    /// leave the radio untouched. Deadlock is what this asymmetry exists to prevent, and until the
    /// seam landed nothing could observe the silent half at all.
    @Test func manager_sendsNoInviteToAPeerThatOutranksIt() {
        let transport = FakeMeshTransportSession()
        let manager = MeshNetworkManager(store: store, transport: transport)
        manager.markProximityJoinForTesting()
        let higher = Self.peer(sessionID: "ffffffff-ffff-ffff-ffff-ffffffffffff")
        #expect(!manager.shouldInitiateInvite(to: higher), "test premise: this peer outranks us")

        transport.discover(higher)

        #expect(transport.invitedPeers.isEmpty, "the higher-sid peer is the inviter; we stay silent")
    }

    /// A device that already holds a seat must not be invited again, however often discovery
    /// re-reports it. The seat gate is checked by ``PeerHandle/isSameEndpoint(as:)``, so a
    /// re-minted handle for the same device is still refused.
    @Test func manager_sendsNoInviteToADeviceThatAlreadyHoldsASlot() {
        let transport = FakeMeshTransportSession()
        let manager = MeshNetworkManager(store: store, transport: transport)
        manager.markProximityJoinForTesting()
        let endpoint = PeerEndpointKey(UUID())
        let seated = Self.peer(sessionID: "00000000-0000-0000-0000-000000000000", endpoint: endpoint)
        let rediscovered = Self.peer(sessionID: "00000000-0000-0000-0000-000000000000", endpoint: endpoint)
        manager.addSlotForTesting(coordinator: Self.throwawayCoordinator(), peer: seated, fingerprint: nil)

        transport.discover(rediscovered)

        #expect(transport.invitedPeers.isEmpty, "a seated device must never be invited a second time")
    }

    /// A never-begun coordinator, so a slot can be seeded without a live radio or ranging session.
    static func throwawayCoordinator() -> ProximityCoordinator {
        ProximityCoordinator(
            identity: IdentityService(keychainService: "test.mesh.dialpolicy.\(UUID().uuidString)"),
            transport: MockMultipeerTransport(),
            ranging: MockRangingProvider(),
            inspector: nil,
            replayCache: ReplayCache(),
            foregroundAnchor: nil,
            displayName: "Local",
            timeoutSeconds: 0
        )
    }

    /// A peer handle carrying exactly the advertisement under test. `endpoint` is supplied only
    /// when a test needs two handles to stand for the SAME device.
    static func peer(sessionID: String?, endpoint: PeerEndpointKey? = nil) -> PeerHandle {
        var info: [String: String] = ["v": "1"]
        if let sessionID { info["sid"] = sessionID }
        return PeerHandle(
            id: UUID(),
            displayHint: "iPhone",
            discoveryInfo: info,
            advertisedFingerprint: nil,
            endpoint: endpoint ?? PeerEndpointKey()
        )
    }
}
