import Foundation
import Observation
import UIKit
import FernletDomainModel

private struct ClothingShareConnection: Identifiable {
    let id: UUID
    let peer: MultipeerPeer
    let channel: PeerChannelTransport
    let coordinator: ProximityCoordinator
    var fingerprint: String?
    var verifiedKeyAgreementPublicKey: Data?
    /// Whether this device has already auto-sent its shop catalog to this peer (sent once on connect).
    var sentCatalog: Bool
}

/// Drives the in-person clothing shop exchange (Increment 3). Cloned from `ProximityRecipeShareManager`,
/// but the shop is the inverse of recipe-share: instead of a sender pushing one item to a chosen recipient,
/// each connected peer AUTO-BROADCASTS its (capped, shareable) catalog and the user BROWSES the peer's.
///
/// Two behaviours diverge from the recipe template and are net-new here:
///  1. The peer's catalog is held in memory FOR THE SESSION ONLY and cleared the moment the peer
///     disconnects (decision §2.3) — the recipe manager keeps its inbound queue across disconnects.
///  2. There is no targeted send: on each verified connection the device sends its own catalog (from
///     `localCatalogProvider`, supplied by the app) without the user picking a recipient.
///
/// Buying is local (spend coins + copy the already-received item, in the app layer), so the manager is a
/// pure transport — it never touches coins or the closet, and it reaches app state only through the narrow
/// `ProximityHost` seam (display name, trust vault, block checks), exactly like the recipe manager.
@MainActor
@Observable
public final class ProximityClothingShareManager: ProximityPayloadHandling {
    public private(set) var nearbyShopPeers: [ProximityClothingShopPeer] = []
    /// Catalogs broadcast by connected peers, held for THIS SESSION ONLY. Cleared on disconnect.
    public private(set) var peerCatalogs: [ProximityClothingCatalog] = []
    public private(set) var diagnosticEvents: [ProximityRecipeShareDiagnosticEvent] = []

    /// The app supplies this device's current shop catalog; it is sent automatically to each peer on
    /// connect. Returning `nil` (e.g. sharing disabled) sends nothing.
    @ObservationIgnored public var localCatalogProvider: (() -> ClothingCatalogPayload?)?

    @ObservationIgnored private unowned let store: any ProximityHost
    @ObservationIgnored private let session = MeshMultipeerSession()
    @ObservationIgnored private let identity: IdentityService
    @ObservationIgnored private let replayCache = ReplayCache()
    @ObservationIgnored private var connections: [ClothingShareConnection] = []
    @ObservationIgnored private var discoveredPeers: [UUID: MultipeerPeer] = [:]
    @ObservationIgnored private var observationTask: Task<Void, Never>?
    @ObservationIgnored private var isRunning = false
    private var connectionObservationRevision = 0
    @ObservationIgnored private var sessionID = UUID().uuidString

    private static let serviceType = "fernlet-clothes"
    private static let maxConnections = 4
    private static let maxPeerCatalogs = 8
    private static let perSenderRateLimitSeconds: TimeInterval = 3
    @ObservationIgnored private var lastAcceptedBySender: [String: Date] = [:]

    public init(store: any ProximityHost) {
        self.store = store
        let id = IdentityService()
        try? id.ensureProvisioned()
        self.identity = id
        setupSession()
    }

    public func start() {
        guard !isRunning else { return }
        isRunning = true
        recordDiagnostic("Clothing shop discovery started.")
        session.start(serviceType: Self.serviceType, discoveryInfo: discoveryInfo())
        startObserving()
    }

    public func stop() {
        if isRunning {
            recordDiagnostic("Clothing shop discovery stopped.")
        }
        isRunning = false
        observationTask?.cancel()
        observationTask = nil
        session.stop()
        nearbyShopPeers.removeAll()
        discoveredPeers.removeAll()
        connections.removeAll()
        // Ephemeral: leaving discovery ends the session, so no peer catalog survives.
        peerCatalogs.removeAll()
        lastAcceptedBySender.removeAll()
    }

    public func refreshDiscovery() {
        let shouldRestart = isRunning
        recordDiagnostic("Clothing shop discovery refreshed.")
        observationTask?.cancel()
        observationTask = nil
        session.stop()
        nearbyShopPeers.removeAll()
        discoveredPeers.removeAll()
        connections.removeAll()
        peerCatalogs.removeAll()
        lastAcceptedBySender.removeAll()
        isRunning = false
        if shouldRestart {
            start()
        }
    }

    /// The catalog a peer (by id) has broadcast this session, if any.
    public func catalog(for peerID: String) -> ProximityClothingCatalog? {
        peerCatalogs.first { $0.id == peerID }
    }

    public func proximityCoordinator(
        _ coordinator: ProximityCoordinator,
        didReceive envelope: FernletIdentityEnvelope,
        plaintext: Data,
        from peer: ProximityCoordinator.PeerIdentity?
    ) {
        guard envelope.payloadType == .clothingCatalog,
              let payload = try? JSONDecoder().decode(ClothingCatalogPayload.self, from: plaintext),
              payload.format == "fernlet.proximity.clothing.catalog",
              payload.version == 1 else { return }

        let senderKey = peer?.fingerprint ?? envelope.senderDisplayName
        let now = Date()
        if let lastAccepted = lastAcceptedBySender[senderKey],
           now.timeIntervalSince(lastAccepted) < Self.perSenderRateLimitSeconds {
            recordDiagnostic("Rate-limited shop catalog from \(envelope.senderDisplayName).")
            return
        }
        lastAcceptedBySender[senderKey] = now

        // Never trust the wire: bound the item count to the shop maximum FIRST (the send side caps at the
        // same limit, so a larger array is a protocol violation / hostile amplification — decoding, mapping,
        // storing, and re-sorting an unbounded array on the main actor would be a remote DoS), then clamp
        // every kept item (texture dims/indices/palette, price, name) before holding it.
        var sanitized = payload
        sanitized.items = payload.items.prefix(ClothingShopLimits.maxListedItems).map { ClothingShopLimits.sanitizedForShop($0) }

        let catalog = ProximityClothingCatalog(
            senderDisplayName: envelope.senderDisplayName,
            senderFingerprint: peer?.fingerprint,
            receivedAt: now,
            payload: sanitized
        )
        peerCatalogs.removeAll { $0.id == catalog.id }
        peerCatalogs.insert(catalog, at: 0)
        if peerCatalogs.count > Self.maxPeerCatalogs {
            peerCatalogs = Array(peerCatalogs.prefix(Self.maxPeerCatalogs))
        }
        recordDiagnostic("Received shop catalog (\(sanitized.items.count) items) from \(envelope.senderDisplayName).")
    }

    // MARK: - Session

    private func setupSession() {
        session.onPeerDiscovered = { [weak self] peer in
            self?.handlePeerDiscovered(peer)
        }
        session.onPeerLost = { [weak self] peer in
            self?.handlePeerLost(peer)
        }
        session.onPeerChannelReady = { [weak self] channel in
            self?.handleChannelReady(channel)
        }
        session.onPeerDisconnected = { [weak self] peer, _ in
            guard let self else { return }
            self.handlePeerLost(peer)
            self.removeConnections(matching: peer)
            self.recordDiagnostic("\(peer.displayName) disconnected.")
        }
        session.shouldAcceptInvitation = { [weak self] peer in
            guard let self else { return false }
            // Blocklist is enforced at identity-introduction time by the coordinator.
            return self.connections.count < Self.maxConnections
                || self.connections.contains(where: { $0.peer.id == peer.id })
        }
    }

    private func discoveryInfo() -> [String: String] {
        [
            "v": "1",
            "sid": sessionID,
            "name": String(displayName.prefix(32)),
            "mode": "clothes"
        ]
    }

    private var displayName: String {
        let name = store.proximityDisplayName.trimmingCharacters(in: .whitespaces)
        return name.isEmpty ? UIDevice.current.name : name
    }

    private func handlePeerDiscovered(_ peer: MultipeerPeer) {
        if let remoteSID = peer.discoveryInfo?["sid"], remoteSID == sessionID { return }
        discoveredPeers[peer.id] = peer
        let shopPeer = ProximityClothingShopPeer(
            id: peer.id,
            displayName: peer.discoveryInfo?["name"] ?? peer.displayName,
            fingerprint: nil
        )
        nearbyShopPeers.removeAll { $0.id == shopPeer.id }
        nearbyShopPeers.append(shopPeer)
        nearbyShopPeers.sort { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending }
        recordDiagnostic("Discovered \(shopPeer.displayName).")
    }

    private func handlePeerLost(_ peer: MultipeerPeer) {
        let lostName = nearbyShopPeers.first { $0.id == peer.id }?.displayName ?? peer.displayName
        discoveredPeers.removeValue(forKey: peer.id)
        nearbyShopPeers.removeAll { $0.id == peer.id }
        recordDiagnostic("\(lostName) is no longer nearby.")
    }

    private func handleChannelReady(_ channel: PeerChannelTransport) {
        guard !connections.contains(where: { $0.peer.id == channel.peer.id }) else { return }
        recordDiagnostic("Secure shop channel opened with \(channel.peer.displayName).")
        let trustPolicy = FriendSessionTrustPolicy(vault: store.proximityTrustVault)
        let coordinator = ProximityCoordinator(
            identity: identity,
            transport: channel,
            ranging: NIRangingSession(),
            payloadHandler: self,
            trustPolicy: trustPolicy,
            replayCache: replayCache,
            displayName: displayName,
            timeoutSeconds: 25
        )
        let connection = ClothingShareConnection(
            id: channel.peer.id,
            peer: channel.peer,
            channel: channel,
            coordinator: coordinator,
            fingerprint: nil,
            verifiedKeyAgreementPublicKey: nil,
            sentCatalog: false
        )
        connections.append(connection)
        connectionObservationRevision += 1

        Task { [weak self] in
            await coordinator.begin(role: .browser, mode: .friend)
            channel.notifyConnected()
            self?.checkCoordinatorStates()
        }
    }

    private func startObserving() {
        observationTask?.cancel()
        observationTask = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                let (stream, continuation) = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
                withObservationTracking {
                    _ = self.connectionObservationRevision
                    _ = self.connections.count
                    for connection in self.connections {
                        _ = connection.coordinator.state
                    }
                } onChange: {
                    continuation.yield(())
                }
                await withTaskCancellationHandler {
                    for await _ in stream { break }
                } onCancel: {
                    continuation.finish()
                }
                continuation.finish()
                guard !Task.isCancelled else { return }
                self.checkCoordinatorStates()
            }
        }
    }

    private func checkCoordinatorStates() {
        for index in connections.indices {
            switch connections[index].coordinator.state {
            case .awaitingManualCommit, .awaitingProximityCommit:
                let coordinator = connections[index].coordinator
                recordDiagnostic("Shop peer verified; confirming proximity.")
                Task { await coordinator.commitManualProximity() }
            default:
                break
            }

            if case .connected(let peerIdentity) = connections[index].coordinator.state {
                let fingerprint = peerIdentity.fingerprint
                if connections[index].fingerprint != fingerprint {
                    connections[index].fingerprint = fingerprint
                    connections[index].verifiedKeyAgreementPublicKey = peerIdentity.keyAgreementPublicKey
                    ensureShopPeer(for: connections[index], identity: peerIdentity)
                    recordDiagnostic("Verified \(peerIdentity.displayName).")
                }
                // Auto-broadcast our catalog once per connection.
                if !connections[index].sentCatalog {
                    connections[index].sentCatalog = true
                    let connection = connections[index]
                    Task { [weak self] in await self?.sendLocalCatalog(via: connection) }
                }
            }
        }

        let stale = connections.filter { connection in
            switch connection.coordinator.state {
            case .ended, .failed: return true
            default: return false
            }
        }
        for connection in stale {
            clearCatalog(for: connection)
            connections.removeAll { $0.id == connection.id }
        }
        if !stale.isEmpty {
            connectionObservationRevision += 1
        }
    }

    private func removeConnections(matching peer: MultipeerPeer) {
        let dropped = connections.filter { $0.peer.id == peer.id || $0.peer.underlying == peer.underlying }
        guard !dropped.isEmpty else { return }
        for connection in dropped { clearCatalog(for: connection) }
        connections.removeAll { connection in
            connection.peer.id == peer.id || connection.peer.underlying == peer.underlying
        }
        connectionObservationRevision += 1
    }

    /// Drop the peer's broadcast catalog the moment we lose them — the catalog is session-scoped (§2.3).
    private func clearCatalog(for connection: ClothingShareConnection) {
        guard let fingerprint = connection.fingerprint else { return }
        peerCatalogs.removeAll { $0.id == fingerprint }
    }

    private func ensureShopPeer(for connection: ClothingShareConnection, identity peerIdentity: ProximityCoordinator.PeerIdentity) {
        let shopPeer = ProximityClothingShopPeer(
            id: connection.id,
            displayName: peerIdentity.displayName,
            fingerprint: peerIdentity.fingerprint
        )
        nearbyShopPeers.removeAll { $0.id == shopPeer.id || $0.fingerprint == shopPeer.fingerprint }
        nearbyShopPeers.append(shopPeer)
        nearbyShopPeers.sort { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending }
    }

    private func sendLocalCatalog(via connection: ClothingShareConnection) async {
        guard let payload = localCatalogProvider?() else { return }
        do {
            let summary = PayloadSummary(title: "Clothing shop", itemCount: payload.items.count)
            let payloadData = try JSONEncoder().encode(payload)
            try await connection.coordinator.sendPayload(
                type: .clothingCatalog,
                summary: summary,
                payload: payloadData,
                sealed: true
            )
            recordDiagnostic("Sent shop catalog (\(payload.items.count) items) to \(connection.peer.displayName).")
        } catch {
            recordDiagnostic("Could not send shop catalog to \(connection.peer.displayName).")
        }
    }

    private func recordDiagnostic(_ message: String) {
        diagnosticEvents = ProximityRecipeShareDiagnostics.appending(
            ProximityRecipeShareDiagnosticEvent(message: message),
            to: diagnosticEvents
        )
    }
}
