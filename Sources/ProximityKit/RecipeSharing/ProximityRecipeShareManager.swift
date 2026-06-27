import Foundation
import Observation
import UIKit
import FernletDomainModel

private struct RecipeShareConnection: Identifiable {
    let id: UUID
    let peer: MultipeerPeer
    let channel: PeerChannelTransport
    let coordinator: ProximityCoordinator
    var fingerprint: String?
    var verifiedKeyAgreementPublicKey: Data?
}

public struct ProximityRecipeShareDiagnosticEvent: Identifiable, Equatable {
    public let id: UUID
    public let timestamp: Date
    public let message: String

    public init(id: UUID = UUID(), timestamp: Date = Date(), message: String) {
        self.id = id
        self.timestamp = timestamp
        self.message = message
    }
}

public enum ProximityRecipeShareDiagnostics {
    public static let maxEvents = 40

    public static func appending(
        _ event: ProximityRecipeShareDiagnosticEvent,
        to events: [ProximityRecipeShareDiagnosticEvent],
        maxCount: Int = maxEvents
    ) -> [ProximityRecipeShareDiagnosticEvent] {
        guard maxCount > 0 else { return [] }
        return Array((events + [event]).suffix(maxCount))
    }
}

@MainActor
@Observable
public final class ProximityRecipeShareManager: ProximityPayloadHandling {
    public enum SendState: Equatable {
        case idle
        case connecting(recipientName: String)
        case sending(recipientName: String)
        case sent(recipientName: String)
        case failed(message: String)
    }

    public private(set) var nearbyRecipients: [ProximityRecipeShareRecipient] = []
    public private(set) var sendState: SendState = .idle
    public private(set) var diagnosticEvents: [ProximityRecipeShareDiagnosticEvent] = []
    public var pendingRecipeShares: [PendingProximityRecipeShare] = []

    @ObservationIgnored private unowned let store: any ProximityHost
    @ObservationIgnored private let session = MeshMultipeerSession()
    @ObservationIgnored private let identity: IdentityService
    @ObservationIgnored private let replayCache = ReplayCache()
    @ObservationIgnored private var connections: [RecipeShareConnection] = []
    @ObservationIgnored private var discoveredPeers: [UUID: MultipeerPeer] = [:]
    @ObservationIgnored private var observationTask: Task<Void, Never>?
    @ObservationIgnored private var clearStatusTask: Task<Void, Never>?
    @ObservationIgnored private var pendingOutgoing: (payload: ProximityRecipeSharePayload, recipient: ProximityRecipeShareRecipient)?
    @ObservationIgnored private var isRunning = false
    private var connectionObservationRevision = 0
    @ObservationIgnored private var sessionID = UUID().uuidString

    private static let serviceType = "fernlet-recipe"
    private static let maxPendingShares = 8
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
        recordDiagnostic("Recipe share discovery started.")
        session.start(serviceType: Self.serviceType, discoveryInfo: discoveryInfo())
        startObserving()
    }

    public func stop() {
        if isRunning {
            recordDiagnostic("Recipe share discovery stopped.")
        }
        isRunning = false
        observationTask?.cancel()
        observationTask = nil
        clearStatusTask?.cancel()
        clearStatusTask = nil
        session.stop()
        nearbyRecipients.removeAll()
        pendingOutgoing = nil
        discoveredPeers.removeAll()
        connections.removeAll()
        sendState = .idle
    }

    public func refreshDiscovery() {
        let shouldRestart = isRunning
        recordDiagnostic("Recipe share discovery refreshed.")
        observationTask?.cancel()
        observationTask = nil
        session.stop()
        nearbyRecipients.removeAll()
        pendingOutgoing = nil
        discoveredPeers.removeAll()
        connections.removeAll()
        sendState = .idle
        isRunning = false
        if shouldRestart {
            start()
        }
    }

    public func sendRecipeShare(_ payload: ProximityRecipeSharePayload, to recipient: ProximityRecipeShareRecipient) {
        start()
        pendingOutgoing = (payload, recipient)
        sendState = .connecting(recipientName: recipient.displayName)
        recordDiagnostic("Connecting to \(recipient.displayName).")

        if let connection = connections.first(where: { $0.id == recipient.id }),
           connection.verifiedKeyAgreementPublicKey != nil {
            Task { [weak self] in await self?.sendPendingPayload(via: connection) }
            return
        }

        guard let peer = peer(for: recipient) else {
            sendState = .failed(message: "That nearby Fernlet is no longer available.")
            recordDiagnostic("Recipe share failed: \(recipient.displayName) is no longer available.")
            scheduleStatusClear()
            return
        }
        session.invite(peer)
    }

    public func dismissRecipeShare(_ share: PendingProximityRecipeShare) {
        pendingRecipeShares.removeAll { $0.id == share.id }
    }

    public func dismissRecipeShare(id: UUID) {
        pendingRecipeShares.removeAll { $0.id == id }
    }

    public func proximityCoordinator(
        _ coordinator: ProximityCoordinator,
        didReceive envelope: FernletIdentityEnvelope,
        plaintext: Data,
        from peer: ProximityCoordinator.PeerIdentity?
    ) {
        guard envelope.payloadType == .recipeShare,
              let payload = try? JSONDecoder().decode(ProximityRecipeSharePayload.self, from: plaintext),
              payload.format == "fernlet.proximity.recipe",
              payload.version == 1 else { return }

        let senderFP = peer?.fingerprint ?? envelope.senderDisplayName
        let now = Date()
        if let lastAccepted = lastAcceptedBySender[senderFP],
           now.timeIntervalSince(lastAccepted) < Self.perSenderRateLimitSeconds {
            recordDiagnostic("Rate-limited recipe share from \(envelope.senderDisplayName).")
            return
        }
        guard pendingRecipeShares.count < Self.maxPendingShares else {
            recordDiagnostic("Dropped recipe share from \(envelope.senderDisplayName): queue full.")
            return
        }
        lastAcceptedBySender[senderFP] = now

        let pending = PendingProximityRecipeShare(
            senderDisplayName: envelope.senderDisplayName,
            senderFingerprint: peer?.fingerprint,
            receivedAt: now,
            payload: payload
        )
        pendingRecipeShares.removeAll { $0.id == pending.id }
        pendingRecipeShares.insert(pending, at: 0)
        if pendingRecipeShares.count > Self.maxPendingShares {
            pendingRecipeShares = Array(pendingRecipeShares.prefix(Self.maxPendingShares))
        }
        recordDiagnostic("Received recipe share from \(envelope.senderDisplayName).")
    }

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
            return self.connections.count < 1 || self.connections.contains(where: { $0.peer.id == peer.id })
        }
    }

    private func discoveryInfo() -> [String: String] {
        [
            "v": "1",
            "sid": sessionID,
            "name": String(displayName.prefix(32)),
            "mode": "recipe"
        ]
    }

    private var displayName: String {
        let name = store.proximityDisplayName.trimmingCharacters(in: .whitespaces)
        return name.isEmpty ? UIDevice.current.name : name
    }

    private func handlePeerDiscovered(_ peer: MultipeerPeer) {
        // Exclude self using session ID comparison; blocklist is enforced post-introduction.
        if let remoteSID = peer.discoveryInfo?["sid"], remoteSID == sessionID { return }
        discoveredPeers[peer.id] = peer
        let recipient = ProximityRecipeShareRecipient(
            id: peer.id,
            displayName: peer.discoveryInfo?["name"] ?? peer.displayName,
            fingerprint: nil
        )
        nearbyRecipients.removeAll { $0.id == recipient.id }
        nearbyRecipients.append(recipient)
        nearbyRecipients.sort { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending }
        recordDiagnostic("Discovered \(recipient.displayName).")
    }

    private func handlePeerLost(_ peer: MultipeerPeer) {
        let displayName = nearbyRecipients.first { $0.id == peer.id }?.displayName ?? peer.displayName
        discoveredPeers.removeValue(forKey: peer.id)
        nearbyRecipients.removeAll { $0.id == peer.id }
        recordDiagnostic("\(displayName) is no longer nearby.")
    }

    private func handleChannelReady(_ channel: PeerChannelTransport) {
        guard !connections.contains(where: { $0.peer.id == channel.peer.id }) else { return }
        recordDiagnostic("Secure recipe-share channel opened with \(channel.peer.displayName).")
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
        let connection = RecipeShareConnection(
            id: channel.peer.id,
            peer: channel.peer,
            channel: channel,
            coordinator: coordinator,
            fingerprint: nil,
            verifiedKeyAgreementPublicKey: nil
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
                recordDiagnostic("Recipe share recipient verified; confirming selected recipient.")
                Task { await coordinator.commitManualProximity() }
            default:
                break
            }

            if case .connected(let peerIdentity) = connections[index].coordinator.state {
                let fingerprint = peerIdentity.fingerprint
                if connections[index].fingerprint != fingerprint {
                    connections[index].fingerprint = fingerprint
                    connections[index].verifiedKeyAgreementPublicKey = peerIdentity.keyAgreementPublicKey
                    ensureRecipient(for: connections[index], identity: peerIdentity)
                    recordDiagnostic("Verified \(peerIdentity.displayName).")
                }
                if pendingOutgoing?.recipient.id == connections[index].id {
                    let connection = connections[index]
                    Task { [weak self] in await self?.sendPendingPayload(via: connection) }
                }
            }
        }

        let stale = connections.filter { connection in
            switch connection.coordinator.state {
            case .ended, .failed: return true
            default: return false
            }
        }
        for connection in stale { connections.removeAll { $0.id == connection.id } }
        if !stale.isEmpty {
            connectionObservationRevision += 1
        }
    }

    private func removeConnections(matching peer: MultipeerPeer) {
        let before = connections.count
        connections.removeAll { connection in
            connection.peer.id == peer.id || connection.peer.underlying == peer.underlying
        }
        if connections.count != before {
            connectionObservationRevision += 1
        }
    }

    private func ensureRecipient(for connection: RecipeShareConnection, identity peerIdentity: ProximityCoordinator.PeerIdentity) {
        let recipient = ProximityRecipeShareRecipient(
            id: connection.id,
            displayName: peerIdentity.displayName,
            fingerprint: peerIdentity.fingerprint
        )
        nearbyRecipients.removeAll { $0.id == recipient.id || $0.fingerprint == recipient.fingerprint }
        nearbyRecipients.append(recipient)
        nearbyRecipients.sort { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending }
    }

    private func sendPendingPayload(via connection: RecipeShareConnection) async {
        guard let outgoing = pendingOutgoing,
              outgoing.recipient.id == connection.id else { return }
        pendingOutgoing = nil
        sendState = .sending(recipientName: outgoing.recipient.displayName)
        recordDiagnostic("Sending \(outgoing.payload.recipe.title) to \(outgoing.recipient.displayName).")
        do {
            let summary = PayloadSummary(
                title: "Recipe share",
                subtitle: nil,
                itemCount: outgoing.payload.recipe.ingredientCount
            )
            let payloadData = try JSONEncoder().encode(outgoing.payload)
            try await connection.coordinator.sendPayload(
                type: .recipeShare,
                summary: summary,
                payload: payloadData,
                sealed: true
            )
            sendState = .sent(recipientName: outgoing.recipient.displayName)
            recordDiagnostic("Sent \(outgoing.payload.recipe.title) to \(outgoing.recipient.displayName).")
        } catch {
            sendState = .failed(message: "Could not send that recipe.")
            recordDiagnostic("Recipe share failed while sending to \(outgoing.recipient.displayName).")
        }
        scheduleStatusClear()
    }

    private func peer(for recipient: ProximityRecipeShareRecipient) -> MultipeerPeer? {
        if let connection = connections.first(where: { $0.id == recipient.id }) {
            return connection.peer
        }
        return discoveredPeers[recipient.id]
            ?? session.channels.values.map(\.peer).first { $0.id == recipient.id }
    }

    private func scheduleStatusClear() {
        clearStatusTask?.cancel()
        clearStatusTask = Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(2.5))
            guard !Task.isCancelled else { return }
            self?.sendState = .idle
        }
    }

    private func recordDiagnostic(_ message: String) {
        diagnosticEvents = ProximityRecipeShareDiagnostics.appending(
            ProximityRecipeShareDiagnosticEvent(message: message),
            to: diagnosticEvents
        )
    }
}
