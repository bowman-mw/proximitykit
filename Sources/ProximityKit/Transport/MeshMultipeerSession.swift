import Foundation
import MultipeerConnectivity
import Combine
import UIKit
import os
import FernletDomainModel

// MARK: - PeerChannelTransport

/// Per-peer ``MultipeerTransport`` adapter for mesh slots.
///
/// ``MeshMultipeerSession`` manages the shared MCSession; this type routes state and data events
/// for a single peer without managing MC lifecycle — the advertise/browse/invite/accept
/// requirements are deliberate no-ops, `send` forwards to the shared session, and `disconnect`
/// only signals idle locally. The owning session calls `notifyConnected` /
/// `notifyDisconnected` / `receive` to feed the publishers the peer's ``ProximityCoordinator``
/// subscribes to.
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

/// The shared MultipeerConnectivity radio: one MCSession, advertiser, and browser, multiplexed
/// into per-peer ``PeerChannelTransport`` channels.
///
/// Every multi-peer radio (mesh, recipe share, presence) owns an instance. Responsibilities:
/// stable-vs-ephemeral peer identity (`usesEphemeralPeerID: true` mints a random, never-persisted
/// MCPeerID for the presence radio — it must NOT touch the shared ``FileMCPeerIDStore``);
/// discovery lifecycle including `pauseDiscovery`/`resumeDiscovery` (radio quiet to new peers,
/// live connections kept — with the CONTRACT that `invite(_:)` never runs while paused);
/// connecting-window tracking with 31 s self-expiring entries so acceptance gates can close the
/// pending-connection race; and loud surfacing of `didNotStart*` failures via `onTransportError`
/// (a service type missing from `NSBonjourServices`, or a declined Local Network prompt, is
/// otherwise silently dead). All MC delegate callbacks arrive nonisolated and transfer their
/// non-Sendable `MCPeerID`/handler values to the main actor via `nonisolated(unsafe)` locals —
/// see the inline notes. `@MainActor`; owners wire behavior through the closure hooks.
@MainActor
final class MeshMultipeerSession: NSObject {

    nonisolated static let friendServiceType   = "fernlet-friend"

    // Discovery-failure surfacing (Phase 1): the empty didNotStart* delegates are how the
    // missing-NSBonjourServices bug shipped invisibly — a service type absent from Info.plist
    // fails here on device (iOS 14+ local-network privacy) with no other signal.
    nonisolated private static let logger = Logger(subsystem: "com.fernlet", category: "proximity.transport")

    let localPeerID: MCPeerID
    private(set) var channels: [MCPeerID: PeerChannelTransport] = [:]
    private(set) var peerInfoCache: [MCPeerID: [String: String]] = [:]
    private var peerMap: [MCPeerID: MultipeerPeer] = [:]
    private var mcSession: MCSession?
    private var advertiser: MCNearbyServiceAdvertiser?
    private var browser: MCNearbyServiceBrowser?
    private var activeServiceType: String = MeshMultipeerSession.friendServiceType
    private var activeDiscoveryInfo: [String: String] = [:]
    private var pendingConnectionPeers: [MCPeerID: UUID] = [:]
    /// True while the radio is "closed": advertising + browsing stopped but the MCSession (and
    /// any live connections) kept alive. See `pauseDiscovery()`/`resumeDiscovery()`.
    private(set) var isDiscoveryPaused = false

    var onPeerDiscovered: ((MultipeerPeer) -> Void)?
    var onPeerLost: ((MultipeerPeer) -> Void)?
    var onPeerChannelReady: ((PeerChannelTransport) -> Void)?
    var onPeerDisconnected: ((MultipeerPeer, String) -> Void)?
    var shouldAcceptInvitation: ((MultipeerPeer) -> Bool)?
    /// Invoked (on the MainActor) with a human-readable message when the advertiser or browser
    /// fails to start — discovery is silently dead without it. Owners route this into their
    /// diagnostic surface; the failure is os_log'd here regardless.
    var onTransportError: ((String) -> Void)?

    /// `usesEphemeralPeerID: true` (presence radio, Phase 4a): a fresh RANDOM MCPeerID per
    /// instance, NEVER persisted — identifier hygiene for the standing presence advertiser
    /// (cross-launch unlinkable; the random display name carries no user info). It MUST NOT
    /// write through the shared `FileMCPeerIDStore`: the other radios rely on that archived
    /// ID staying stable, and clobbering it would break their peer identity continuity.
    init(peerIDStore: (any MCPeerIDStoring)? = nil, usesEphemeralPeerID: Bool = false) {
        if usesEphemeralPeerID {
            self.localPeerID = MCPeerID(displayName: Self.randomEphemeralDisplayName())
            super.init()
            return
        }
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

    /// Random per-instance display name for ephemeral peer IDs. Deliberately NOT the device
    /// name: a per-start random token is exactly as linkable as the per-start random MCPeerID
    /// itself (nothing), and it lets the owner recognize its own previous-start ghost
    /// advertisements (presence self-exclusion).
    nonisolated static func randomEphemeralDisplayName() -> String {
        String(UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(12)).lowercased()
    }

    func start(serviceType: String = MeshMultipeerSession.friendServiceType, discoveryInfo: [String: String] = [:]) {
        activeServiceType = serviceType
        activeDiscoveryInfo = discoveryInfo
        isDiscoveryPaused = false
        ensureSession()
        startAdvertiser(info: discoveryInfo)
        startBrowser()
    }

    func updateDiscoveryInfo(_ info: [String: String]) {
        activeDiscoveryInfo = info
        // While paused, only remember the info — resumeDiscovery() applies it. Restarting the
        // advertiser here would silently un-pause a closed radio.
        guard !isDiscoveryPaused else { return }
        advertiser?.stopAdvertisingPeer()
        startAdvertiser(info: info)
    }

    /// "Closes" the radio: stops advertising AND browsing while KEEPING the advertiser/browser
    /// instances and the live MCSession — established connections keep flowing; the radio just
    /// goes quiet to new peers (hard 2-device recipe cap, mesh redesign Phase 3b).
    ///
    /// CONTRACT: `resumeDiscovery()` MUST precede any further `invite(_:)` — calling
    /// `invitePeer` while browsing is stopped is undocumented MultipeerConnectivity behavior
    /// and must never be relied on (`invite(_:)` drops the call and logs if violated).
    func pauseDiscovery() {
        guard !isDiscoveryPaused else { return }
        isDiscoveryPaused = true
        advertiser?.stopAdvertisingPeer()
        browser?.stopBrowsingForPeers()
    }

    /// Reopens a paused radio. Recreates the advertiser and browser rather than restarting the
    /// stopped instances — the same stop-and-recreate pattern `updateDiscoveryInfo` uses, which
    /// is the reliable way to bring an MCNearbyService* object back up. No-op unless paused.
    func resumeDiscovery() {
        guard isDiscoveryPaused else { return }
        isDiscoveryPaused = false
        guard mcSession != nil else { return }  // never started — nothing to resume
        advertiser?.stopAdvertisingPeer()
        startAdvertiser(info: activeDiscoveryInfo)
        browser?.stopBrowsingForPeers()
        startBrowser()
    }

    /// Number of peers in the "connecting window" — invited (or invitation accepted) but not
    /// yet MC-connected. Acceptance gates consult this to close the connecting-window race.
    var pendingConnectionCount: Int { pendingConnectionPeers.count }

    /// True when a connection attempt is in flight to any peer OTHER than `peer` — the
    /// same-peer carve-out lets a retrying peer through its own pending window.
    func hasPendingConnections(besides peer: MultipeerPeer?) -> Bool {
        pendingConnectionPeers.keys.contains { $0 != peer?.underlying }
    }

    /// Best-effort targeted disconnect. `MCSession.cancelConnectPeer` is documented only for
    /// peers still in the connecting window; for already-connected peers it acts as a de-facto
    /// kick on current iOS but is NOT documented to — callers must treat this as
    /// belt-and-braces and never depend on it alone (manager-level record eviction is what
    /// actually drives teardown/reopen decisions).
    func disconnectPeer(_ peer: MultipeerPeer) {
        onDisconnectPeerRequestedForTesting?(peer)
        pendingConnectionPeers.removeValue(forKey: peer.underlying)
        mcSession?.cancelConnectPeer(peer.underlying)
    }

    /// Fired synchronously at the top of `disconnectPeer` so unit tests — which cannot start a
    /// real `MCSession` — can assert that an owner's eviction path requested the MC kick
    /// (`MeshNetworkManagerTests`: an evicted slot must not leave a zombie link).
    var onDisconnectPeerRequestedForTesting: ((MultipeerPeer) -> Void)?

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
        isDiscoveryPaused = false
    }

    func invite(_ peer: MultipeerPeer) {
        guard let session = mcSession, let browser else { return }
        guard !session.connectedPeers.contains(peer.underlying) else { return }
        guard pendingConnectionPeers[peer.underlying] == nil else { return }
        // CONTRACT (see pauseDiscovery): inviting on a stopped browser is undocumented — drop
        // loudly instead of relying on it. Callers must resumeDiscovery() first.
        guard !isDiscoveryPaused else {
            Self.logger.error("invite(_:) while discovery is paused — dropped; resumeDiscovery() must precede invites")
            return
        }
        registerPendingConnection(peer.underlying)
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

    /// Length of the connecting window in seconds — deliberately the `invitePeer` timeout (30 s)
    /// plus one, so a pending entry outlives the MC-level attempt it tracks. Keep the class
    /// doc's "31 s" note in sync if this changes.
    private static let connectingWindowSeconds: Int64 = 31

    /// Opens (or refreshes) the connecting window for `peerID`: mints a fresh invite token,
    /// writes it into `pendingConnectionPeers`, and schedules a self-expiry task that removes
    /// the entry after ``connectingWindowSeconds`` — unless a newer registration or a
    /// `.connected`/`.notConnected` transition already replaced or cleared it.
    ///
    /// Deliberately UNCONDITIONAL: re-registering overwrites the token and thereby refreshes
    /// the window (the advertiser-accept path relies on this in the cross-invite race).
    /// Callers that must NOT refresh an in-flight window guard on
    /// `pendingConnectionPeers[peerID] == nil` themselves (the `.connecting` delegate branch).
    private func registerPendingConnection(_ peerID: MCPeerID) {
        let inviteID = UUID()
        pendingConnectionPeers[peerID] = inviteID
        Task { @MainActor [weak self] in
            // A cancelled expiry leaves the entry to the .connected/.notConnected transitions,
            // which is the existing contract (R7: cancellation is the recovery, not a swallow).
            do {
                try await Task.sleep(for: .seconds(Self.connectingWindowSeconds))
            } catch {
                return
            }
            guard self?.pendingConnectionPeers[peerID] == inviteID else { return }
            self?.pendingConnectionPeers.removeValue(forKey: peerID)
        }
    }

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

    // MARK: - Test seam

    /// Registers a synthetic connecting-window entry so unit tests can exercise the
    /// pending-connection acceptance/cap gates without starting real radios (the production
    /// writers are `invite(_:)` and the MC delegate paths, all of which need live transport).
    func registerPendingConnectionForTesting(_ peer: MultipeerPeer) {
        pendingConnectionPeers[peer.underlying] = UUID()
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
                // The nil-guard is load-bearing: invite -> .connecting is the normal sequence,
                // and re-registering here would refresh (extend) the invite-time window.
                if self.pendingConnectionPeers[peerID] == nil {
                    self.registerPendingConnection(peerID)
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
                self.registerPendingConnection(peerID)
                _ = self.prepareChannel(for: peerID)
            }
            invitationHandler(accept, accept ? self.mcSession : nil)
        }
    }

    nonisolated func advertiser(_ advertiser: MCNearbyServiceAdvertiser, didNotStartAdvertisingPeer error: Error) {
        let message = "Advertising failed to start for service \"\(advertiser.serviceType)\": \(error.localizedDescription)"
        Self.logger.error("\(message, privacy: .public)")
        Task { @MainActor [weak self] in
            self?.onTransportError?(message)
        }
    }
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

    nonisolated func browser(_ browser: MCNearbyServiceBrowser, didNotStartBrowsingForPeers error: Error) {
        let message = "Browsing failed to start for service \"\(browser.serviceType)\": \(error.localizedDescription)"
        Self.logger.error("\(message, privacy: .public)")
        Task { @MainActor [weak self] in
            self?.onTransportError?(message)
        }
    }
}
