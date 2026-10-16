import Foundation
@testable import ProximityKit

// The manager-side half of the transport seam P2 item 8 introduced. `FakePeerTransport` beside it is
// a per-peer CHANNEL on an in-memory fabric; this is the shared RADIO that vends those channels and
// records what its owner asked it to do.
//
// Before the seam existed, `MeshNetworkManager` owned `private let meshSession =
// MeshMultipeerSession()` outright, so nothing at tier 1 could observe an invite being SENT — only
// the decision to send one. Everything recorded here is a thing the manager did to its radio, and
// everything in "Driving the owner" is a thing a radio does to the manager.

/// An in-memory ``MeshTransportSession``: records every call the manager makes, and lets a test fire
/// every callback a live radio would.
///
/// Deliberately not a state machine. A fake that invented advertising/browsing behaviour would test
/// a shape production does not have — the two real conformers each own that themselves, and what the
/// manager can be held to is only what crosses this surface.
@MainActor
final class FakeMeshTransportSession: MeshTransportSession {

    /// The fabric this session's channels live on, so a test that wants to move frames between two
    /// endpoints has one ready. Unused by the manager itself, which never touches a channel's wire.
    let network = FakePeerNetwork()

    // MARK: Recorded calls

    private(set) var handlers = MeshTransportHandlers()
    /// The authority the owner attached, if any. `nil` after construction is the honest reading of
    /// "this radio cannot authenticate anybody".
    private(set) weak var attachedAuthority: (any MeshIntroductionAuthority)?
    private(set) var startedDiscoveryInfo: [[String: String]] = []
    private(set) var republishedDiscoveryInfo: [[String: String]] = []
    private(set) var stopCount = 0
    /// How many times the owner stood the browser/advertiser down while KEEPING the session — the
    /// radio half of `MeshNetworkManager.holdCommittedLinks()`, and the counter that tells a hold
    /// apart from a `stop()`.
    private(set) var pauseDiscoveryCount = 0
    /// How many times a paused radio was reopened through the protocol's own verb. Zero in every
    /// tier-1 run today: the owner's one re-arm funnel goes through `startRadios(discoveryInfo:)`,
    /// and each real conformer reopens itself from there.
    private(set) var resumeDiscoveryCount = 0
    private(set) var invitedPeers: [PeerHandle] = []
    private(set) var disconnectedPeers: [PeerHandle] = []
    /// One entry per ``disconnectedPeers`` entry, in the same order: why the owner freed it.
    private(set) var disconnectCauses: [MeshSlotEvictionCause] = []
    /// Every far-end-close wait the owner asked for, in order: whose links, and the bound it gave.
    private(set) var remoteCloseWaits: [(peers: [PeerHandle], seconds: TimeInterval)] = []
    /// ``stopCount`` at the moment of each wait — the ORDER claim a leaver's wait exists for: it
    /// must come before the radio goes down, or there is no link left for the partner to close.
    private(set) var stopCountAtRemoteCloseWaits: [Int] = []
    /// What every far-end-close wait answers. The fake has no far end, so it is the test's to say.
    var remoteCloseOutcome: MeshRemoteCloseOutcome = .nothingToWaitFor
    /// The signing key this fake "proved" for each endpoint — a test's stand-in for the QUIC radio's
    /// signed channel introduction. An endpoint with no entry proved nothing, which is the
    /// fail-closed answer the protocol's default gives.
    var verifiedSigningKeys: [PeerEndpointKey: Data] = [:]

    // MARK: - MeshTransportSession

    func wire(_ handlers: MeshTransportHandlers) {
        self.handlers = handlers
    }

    func attachIntroductionAuthority(_ authority: any MeshIntroductionAuthority) {
        attachedAuthority = authority
    }

    func startRadios(discoveryInfo: [String: String]) {
        startedDiscoveryInfo.append(discoveryInfo)
    }

    func stop() {
        stopCount += 1
    }

    func pauseDiscovery() {
        pauseDiscoveryCount += 1
    }

    func resumeDiscovery() {
        resumeDiscoveryCount += 1
    }

    func updateDiscoveryInfo(_ info: [String: String]) {
        republishedDiscoveryInfo.append(info)
    }

    func invite(_ peer: PeerHandle) {
        invitedPeers.append(peer)
    }

    func disconnectPeer(_ peer: PeerHandle) {
        disconnectPeer(peer, cause: .ownerDecision)
    }

    /// Records the CAUSE alongside the peer, so a cell can prove which arm of the owner's eviction
    /// funnel it drove — the distinction the QUIC radio's re-propose budget turns on
    /// (``MeshSlotEvictionCause``). The default protocol implementation would swallow it.
    func disconnectPeer(_ peer: PeerHandle, cause: MeshSlotEvictionCause) {
        disconnectedPeers.append(peer)
        disconnectCauses.append(cause)
    }

    /// Records the wait and answers at once with ``remoteCloseOutcome``: this fabric has no far end
    /// whose close could answer it, so recording it changes no cell's timing.
    func awaitRemoteClose(
        of peers: [PeerHandle], within seconds: TimeInterval
    ) async -> MeshRemoteCloseOutcome {
        remoteCloseWaits.append((peers, seconds))
        stopCountAtRemoteCloseWaits.append(stopCount)
        return remoteCloseOutcome
    }

    /// The key a test set for this endpoint in ``verifiedSigningKeys``, or nil.
    func verifiedSigningPublicKey(for peer: PeerHandle) -> Data? {
        verifiedSigningKeys[peer.endpoint]
    }

    // MARK: - Driving the owner

    /// Adds an endpoint to the fabric and returns the channel a radio would hand up for it.
    func makeChannel(named name: String) -> (channel: FakePeerTransport, handle: PeerHandle) {
        let endpoint = network.addEndpoint(named: name)
        return (endpoint.transport, endpoint.handle)
    }

    /// A peer appeared in discovery.
    func discover(_ peer: PeerHandle) {
        handlers.onPeerDiscovered?(peer)
    }

    /// A peer's channel came up.
    func connect(_ channel: FakePeerTransport) {
        handlers.onChannelReady?(channel)
    }

    /// A peer's link dropped.
    func drop(_ peer: PeerHandle, reason: String = "Peer disconnected") {
        handlers.onPeerDisconnected?(peer, reason)
    }

    /// Asks the owner's admission gate about an inbound connection. Fails closed when nothing is
    /// wired, exactly as both real radios do.
    func offerInboundConnection(from peer: PeerHandle) -> Bool {
        handlers.shouldAcceptInvitation?(peer) ?? false
    }

    /// Discovery failed to start.
    func failDiscovery(_ message: String) {
        handlers.onTransportError?(message)
    }
}
