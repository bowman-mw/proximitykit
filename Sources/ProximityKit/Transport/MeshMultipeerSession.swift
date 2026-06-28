import Foundation
import MultipeerConnectivity
import Combine
import UIKit
import FernletDomainModel

// MARK: - PeerChannelTransport

/// Per-peer MultipeerTransport adapter for mesh slots.
/// MeshMultipeerSession manages the shared MCSession; this type routes
/// state and data events for a single peer without managing MC lifecycle.
@MainActor
final class PeerChannelTransport: MultipeerTransport {
    let peer: MultipeerPeer
    private weak var session: MeshMultipeerSession?

    private let stateSubject = CurrentValueSubject<MultipeerTransportState, Never>(.idle)
    private let inboundSubject = PassthroughSubject<MultipeerInboundMessage, Never>()

    var state: AnyPublisher<MultipeerTransportState, Never> { stateSubject.eraseToAnyPublisher() }
    var inbound: AnyPublisher<MultipeerInboundMessage, Never> { inboundSubject.eraseToAnyPublisher() }
    var connectedPeers: [MultipeerPeer] { [] }

    init(peer: MultipeerPeer, session: MeshMultipeerSession) {
        self.peer = peer
        self.session = session
    }

    // MC advertising/browsing is handled by MeshMultipeerSession, not per-channel
    func startAdvertising(serviceType: String, discoveryInfo: [String: String]) async throws {}
    func startBrowsing(serviceType: String) async throws {}
    func invite(_ peer: MultipeerPeer) async throws {}
    func accept(_ invite: MultipeerPendingInvite) async throws {}

    func send(_ data: Data, to peer: MultipeerPeer, mode: MCSessionSendDataMode) async throws {
        guard let session else { throw MultipeerTransportError.unexpectedState }
        try await session.send(data, to: peer, mode: mode)
    }

    func disconnect() async {
        // Only signals idle locally — does not disconnect the shared MCSession
        stateSubject.send(.idle)
    }

    // MARK: - Called by MeshMultipeerSession

    func notifyConnected() {
        stateSubject.send(.connected(peer))
    }

    func notifyDisconnected(reason: String = "Peer disconnected") {
        stateSubject.send(.disconnected(reason: reason))
    }

    func receive(_ data: Data) {
        inboundSubject.send(MultipeerInboundMessage(
            peer: peer,
            data: data,
            receivedAt: Date(),
            bytesReceived: data.count
        ))
    }
}

// MARK: - MeshMultipeerSession

/// Owns a single MCSession shared across all mesh peers.
/// Creates PeerChannelTransport instances on demand and routes MC delegate
/// callbacks to the appropriate channel.
@MainActor
final class MeshMultipeerSession: NSObject {

    nonisolated static let friendServiceType   = "fernlet-friend"

    let localPeerID: MCPeerID
    private(set) var channels: [MCPeerID: PeerChannelTransport] = [:]
    private(set) var peerInfoCache: [MCPeerID: [String: String]] = [:]
    private var peerMap: [MCPeerID: MultipeerPeer] = [:]
    private var mcSession: MCSession?
    private var advertiser: MCNearbyServiceAdvertiser?
    private var browser: MCNearbyServiceBrowser?
    private var activeServiceType: String = MeshMultipeerSession.friendServiceType
    private var pendingConnectionPeers: [MCPeerID: UUID] = [:]

    var onPeerDiscovered: ((MultipeerPeer) -> Void)?
    var onPeerLost: ((MultipeerPeer) -> Void)?
    var onPeerChannelReady: ((PeerChannelTransport) -> Void)?
    var onPeerDisconnected: ((MultipeerPeer, String) -> Void)?
    var shouldAcceptInvitation: ((MultipeerPeer) -> Bool)?

    init(peerIDStore: (any MCPeerIDStoring)? = nil) {
        let store: any MCPeerIDStoring = peerIDStore ?? FileMCPeerIDStore()
        if let existing = store.load() {
            self.localPeerID = existing
        } else {
            let new = MCPeerID(displayName: UIDevice.current.name)
            self.localPeerID = new
            store.save(new)
        }
        super.init()
    }

    func start(serviceType: String = MeshMultipeerSession.friendServiceType, discoveryInfo: [String: String] = [:]) {
        activeServiceType = serviceType
        ensureSession()
        startAdvertiser(info: discoveryInfo)
        startBrowser()
    }

    func updateDiscoveryInfo(_ info: [String: String]) {
        advertiser?.stopAdvertisingPeer()
        startAdvertiser(info: info)
    }

    func stop() {
        advertiser?.stopAdvertisingPeer()
        browser?.stopBrowsingForPeers()
        mcSession?.disconnect()
        advertiser = nil
        browser = nil
        mcSession = nil
        channels.removeAll()
        peerInfoCache.removeAll()
        peerMap.removeAll()
        pendingConnectionPeers.removeAll()
    }

    func invite(_ peer: MultipeerPeer) {
        guard let session = mcSession, let browser else { return }
        guard !session.connectedPeers.contains(peer.underlying) else { return }
        guard pendingConnectionPeers[peer.underlying] == nil else { return }
        let inviteID = UUID()
        pendingConnectionPeers[peer.underlying] = inviteID
        Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(31))
            guard self?.pendingConnectionPeers[peer.underlying] == inviteID else { return }
            self?.pendingConnectionPeers.removeValue(forKey: peer.underlying)
        }
        _ = prepareChannel(for: peer.underlying)
        browser.invitePeer(peer.underlying, to: session, withContext: nil, timeout: 30)
    }

    func send(_ data: Data, to peer: MultipeerPeer, mode: MCSessionSendDataMode) async throws {
        guard let session = mcSession else {
            throw MultipeerTransportError.unexpectedState
        }
        do {
            try session.send(data, toPeers: [peer.underlying], with: mode)
        } catch {
            throw MultipeerTransportError.sendFailed(reason: error.localizedDescription)
        }
    }

    func prepareChannel(for mcPeerID: MCPeerID) -> PeerChannelTransport {
        if let existing = channels[mcPeerID] { return existing }
        let p = peer(for: mcPeerID)
        let channel = PeerChannelTransport(peer: p, session: self)
        channels[mcPeerID] = channel
        return channel
    }

    // MARK: - Private helpers

    private func ensureSession() {
        guard mcSession == nil else { return }
        let session = MCSession(peer: localPeerID, securityIdentity: nil, encryptionPreference: .required)
        session.delegate = self
        mcSession = session
    }

    private func startAdvertiser(info: [String: String]) {
        let adv = MCNearbyServiceAdvertiser(peer: localPeerID, discoveryInfo: info, serviceType: activeServiceType)
        adv.delegate = self
        advertiser = adv
        adv.startAdvertisingPeer()
    }

    private func startBrowser() {
        let br = MCNearbyServiceBrowser(peer: localPeerID, serviceType: activeServiceType)
        br.delegate = self
        browser = br
        br.startBrowsingForPeers()
    }

    private func peer(for mcPeerID: MCPeerID, discoveryInfo: [String: String]? = nil) -> MultipeerPeer {
        let info = discoveryInfo ?? peerInfoCache[mcPeerID]
        if let existing = peerMap[mcPeerID] {
            guard let info, info != existing.discoveryInfo else { return existing }
            let updated = MultipeerPeer(
                id: existing.id,
                displayName: existing.displayName,
                discoveryInfo: info,
                advertisedFingerprint: info["fp"],
                underlying: existing.underlying
            )
            peerMap[mcPeerID] = updated
            peerInfoCache[mcPeerID] = info
            return updated
        }
        let p = MultipeerPeer(
            id: UUID(),
            displayName: mcPeerID.displayName,
            discoveryInfo: info,
            advertisedFingerprint: info?["fp"],
            underlying: mcPeerID
        )
        peerMap[mcPeerID] = p
        if let discoveryInfo { peerInfoCache[mcPeerID] = discoveryInfo }
        return p
    }
}

// MARK: - MCSessionDelegate

extension MeshMultipeerSession: MCSessionDelegate {
    nonisolated func session(_ session: MCSession, peer peerID: MCPeerID, didChange state: MCSessionState) {
        // MCPeerID is non-Sendable, so capturing it into the @MainActor `Task` hop is a
        // Swift 6 `sending` data-race error. Transfer it via a nonisolated(unsafe) local:
        // MCPeerID is an immutable value object that is only read on the MainActor after
        // the hop, so this is data-race-free and behaviour-identical to the prior Swift 5
        // language mode (which performed the same capture implicitly). Same pattern below.
        nonisolated(unsafe) let peerID = peerID
        Task { @MainActor [weak self] in
            guard let self else { return }
            let peer = self.peer(for: peerID)
            switch state {
            case .connected:
                self.pendingConnectionPeers.removeValue(forKey: peerID)
                let channel = self.prepareChannel(for: peerID)
                // onPeerChannelReady creates the coordinator and queues begin() as a Task.
                // begin() suspends at `await transport.disconnect()`, which would let a
                // concurrently-queued notifyConnected() fire before currentMode is set —
                // causing handleTransportState(.connected) to enter .awaitingTapConfirmation
                // instead of .awaitingIdentityIntroduction and permanently stalling the handshake.
                // The channel owner calls notifyConnected() after its awaited begin() completes.
                self.onPeerChannelReady?(channel)
            case .notConnected:
                self.pendingConnectionPeers.removeValue(forKey: peerID)
                if let channel = self.channels[peerID] {
                    channel.notifyDisconnected()
                }
                self.channels.removeValue(forKey: peerID)
                self.onPeerDisconnected?(peer, "Peer disconnected")
            case .connecting:
                if self.pendingConnectionPeers[peerID] == nil {
                    let inviteID = UUID()
                    self.pendingConnectionPeers[peerID] = inviteID
                    Task { @MainActor [weak self] in
                        try? await Task.sleep(for: .seconds(31))
                        guard self?.pendingConnectionPeers[peerID] == inviteID else { return }
                        self?.pendingConnectionPeers.removeValue(forKey: peerID)
                    }
                }
            @unknown default:
                break
            }
        }
    }

    nonisolated func session(_ session: MCSession, didReceive data: Data, fromPeer peerID: MCPeerID) {
        nonisolated(unsafe) let peerID = peerID  // non-Sendable MCPeerID across the @MainActor hop
        Task { @MainActor [weak self] in
            guard let self, let channel = self.channels[peerID] else { return }
            channel.receive(data)
        }
    }

    nonisolated func session(_ session: MCSession, didReceive stream: InputStream, withName streamName: String, fromPeer peerID: MCPeerID) {}
    nonisolated func session(_ session: MCSession, didStartReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, with progress: Progress) {}
    nonisolated func session(_ session: MCSession, didFinishReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, at localURL: URL?, withError error: Error?) {}
}

// MARK: - MCNearbyServiceAdvertiserDelegate

extension MeshMultipeerSession: MCNearbyServiceAdvertiserDelegate {
    nonisolated func advertiser(
        _ advertiser: MCNearbyServiceAdvertiser,
        didReceiveInvitationFromPeer peerID: MCPeerID,
        withContext context: Data?,
        invitationHandler: @escaping (Bool, MCSession?) -> Void
    ) {
        nonisolated(unsafe) let peerID = peerID  // non-Sendable MCPeerID across the @MainActor hop
        // invitationHandler is a non-Sendable closure; it is invoked exactly once on the
        // MainActor after the hop, so the unsafe transfer is behaviour-preserving.
        nonisolated(unsafe) let invitationHandler = invitationHandler
        Task { @MainActor [weak self] in
            guard let self else { invitationHandler(false, nil); return }
            let peer = self.peer(for: peerID)
            let accept = self.shouldAcceptInvitation?(peer) ?? false
            if accept {
                let inviteID = UUID()
                self.pendingConnectionPeers[peerID] = inviteID
                Task { @MainActor [weak self] in
                    try? await Task.sleep(for: .seconds(31))
                    guard self?.pendingConnectionPeers[peerID] == inviteID else { return }
                    self?.pendingConnectionPeers.removeValue(forKey: peerID)
                }
                _ = self.prepareChannel(for: peerID)
            }
            invitationHandler(accept, accept ? self.mcSession : nil)
        }
    }

    nonisolated func advertiser(_ advertiser: MCNearbyServiceAdvertiser, didNotStartAdvertisingPeer error: Error) {}
}

// MARK: - MCNearbyServiceBrowserDelegate

extension MeshMultipeerSession: MCNearbyServiceBrowserDelegate {
    nonisolated func browser(_ browser: MCNearbyServiceBrowser, foundPeer peerID: MCPeerID, withDiscoveryInfo info: [String: String]?) {
        nonisolated(unsafe) let peerID = peerID  // non-Sendable MCPeerID across the @MainActor hop
        Task { @MainActor [weak self] in
            guard let self else { return }
            if let info { self.peerInfoCache[peerID] = info }
            let peer = self.peer(for: peerID, discoveryInfo: info)
            self.onPeerDiscovered?(peer)
        }
    }

    nonisolated func browser(_ browser: MCNearbyServiceBrowser, lostPeer peerID: MCPeerID) {
        nonisolated(unsafe) let peerID = peerID  // non-Sendable MCPeerID across the @MainActor hop
        Task { @MainActor [weak self] in
            guard let self else { return }
            let peer = self.peer(for: peerID)
            if self.channels[peerID] == nil {
                self.peerInfoCache.removeValue(forKey: peerID)
                self.peerMap.removeValue(forKey: peerID)
            }
            self.onPeerLost?(peer)
        }
    }

    nonisolated func browser(_ browser: MCNearbyServiceBrowser, didNotStartBrowsingForPeers error: Error) {}
}
