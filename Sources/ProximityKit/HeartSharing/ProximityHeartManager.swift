// ProximityHeartManager.swift
// ProximityKit/HeartSharing
//
// In-person "send good vibes" hearts (spec §10, proximity-only v1). A thin clone of
// ProximityRecipeShareManager with three deliberate divergences:
//   1. Hearts are FRIEND-DIRECTED: the send API takes a ProximityTrustedPeerRecord and only ever
//      sends over a connection whose VERIFIED fingerprint matches that record — never to a peer
//      matched by display name. Inbound hearts from senders who are not (still-)trusted friends
//      are dropped.
//   2. The manager auto-connects to discovered heart peers (deterministic single-sided invite via
//      the session-id tie-break) instead of inviting only on send, so "reachable" means an
//      identity-verified live connection and the FriendListView heart button can light up honestly.
//   3. The per-friend-per-day rate limit persists across relaunch via ProximityHeartLedger
//      (the recipe manager's in-memory 3-second limiter would forget on restart; the daily ledger
//      subsumes it on the receive side too, since only the first heart per friend per day lands).
//
// Lifecycle is owned by ContentView (consent toggle + scene phase + tab + lock), exactly like the
// recipe/clothing listeners. `sendHeart` does NOT start discovery itself: the send UI is only
// enabled while the listener is running and the friend is verified-reachable.

import Foundation
import Observation
import UIKit
import FernletDomainModel
import FernletFoundation

private struct HeartShareConnection: Identifiable {
    let id: UUID
    let peer: MultipeerPeer
    let channel: PeerChannelTransport
    let coordinator: ProximityCoordinator
    var fingerprint: String?
    var verifiedKeyAgreementPublicKey: Data?
}

@MainActor
@Observable
public final class ProximityHeartManager: ProximityPayloadHandling {
    public enum SendState: Equatable {
        case idle
        case sending(recipientName: String)
        case sent(recipientName: String)
        case failed(message: String)
    }

    public private(set) var sendState: SendState = .idle
    /// Verified fingerprints of live heart-service connections — the honest definition of
    /// "this friend is here right now".
    public private(set) var reachableFingerprints: Set<String> = []
    public private(set) var diagnosticEvents: [ProximityRecipeShareDiagnosticEvent] = []

    @ObservationIgnored private unowned let store: any ProximityHost
    @ObservationIgnored private let ledger: ProximityHeartLedger
    @ObservationIgnored private let session = MeshMultipeerSession()
    @ObservationIgnored private let identity: IdentityService
    @ObservationIgnored private let replayCache = ReplayCache()
    @ObservationIgnored private var connections: [HeartShareConnection] = []
    @ObservationIgnored private var discoveredPeers: [UUID: MultipeerPeer] = [:]
    @ObservationIgnored private var observationTask: Task<Void, Never>?
    @ObservationIgnored private var clearStatusTask: Task<Void, Never>?
    @ObservationIgnored private var isRunning = false
    private var connectionObservationRevision = 0
    @ObservationIgnored private var sessionID = UUID().uuidString

    private static let serviceType = "fernlet-heart"
    private static let maxConnections = 4

    public init(store: any ProximityHost, ledger: ProximityHeartLedger) {
        self.store = store
        self.ledger = ledger
        let id = IdentityService()
        try? id.ensureProvisioned()
        self.identity = id
        setupSession()
    }

    public func start() {
        guard !isRunning else { return }
        isRunning = true
        recordDiagnostic("Heart discovery started.")
        session.start(serviceType: Self.serviceType, discoveryInfo: discoveryInfo())
        startObserving()
    }

    public func stop() {
        if isRunning {
            recordDiagnostic("Heart discovery stopped.")
        }
        isRunning = false
        observationTask?.cancel()
        observationTask = nil
        clearStatusTask?.cancel()
        clearStatusTask = nil
        session.stop()
        discoveredPeers.removeAll()
        connections.removeAll()
        reachableFingerprints.removeAll()
        sendState = .idle
    }

    // MARK: - Send

    /// True when this trusted friend is on a live, identity-verified heart connection right now.
    public func isReachable(fingerprint: String) -> Bool {
        reachableFingerprints.contains { IdentityService.fingerprintsMatch($0, fingerprint) }
    }

    /// One heart per friend per day, in person. The button that calls this is disabled unless the
    /// friend is reachable and today's heart is unsent; the guards here are the belt to that brace.
    public func sendHeart(to friend: ProximityTrustedPeerRecord) {
        let firstName = Self.firstName(of: friend.displayName)
        guard friend.blockedAt == nil, friend.revokedAt == nil else { return }
        guard ledger.canSendHeart(to: friend.fingerprint) else {
            sendState = .failed(message: "You've already sent \(firstName) some warmth today.")
            scheduleStatusClear()
            return
        }
        guard let connection = verifiedConnection(fingerprint: friend.fingerprint) else {
            sendState = .failed(message: "\(firstName) isn't nearby right now — hearts travel in person for now.")
            scheduleStatusClear()
            return
        }
        sendState = .sending(recipientName: friend.displayName)
        Task { [weak self] in await self?.sendHeart(via: connection, to: friend) }
    }

    private func verifiedConnection(fingerprint: String) -> HeartShareConnection? {
        connections.first { connection in
            guard let verified = connection.fingerprint else { return false }
            return IdentityService.fingerprintsMatch(verified, fingerprint)
        }
    }

    private func sendHeart(via connection: HeartShareConnection, to friend: ProximityTrustedPeerRecord) async {
        // Re-check right before the wire write (the day may have been consumed by a racing send).
        guard ledger.canSendHeart(to: friend.fingerprint) else {
            sendState = .failed(message: "You've already sent \(Self.firstName(of: friend.displayName)) some warmth today.")
            scheduleStatusClear()
            return
        }
        do {
            let payload = HeartPayload(sentAtDayKey: FernletDate.dayKey(for: Date()))
            let payloadData = try JSONEncoder().encode(payload)
            // Sealed to the coordinator's verified peer — the same identity the fingerprint match
            // above pinned to `friend`, so a heart can never land on a different device.
            try await connection.coordinator.sendPayload(
                type: .friendHeart,
                summary: PayloadSummary(title: "Good vibes"),
                payload: payloadData,
                sealed: true
            )
            ledger.recordHeartSent(to: friend.fingerprint)
            sendState = .sent(recipientName: friend.displayName)
            recordDiagnostic("Sent good vibes to \(friend.displayName).")
        } catch {
            sendState = .failed(message: "Could not send that heart just now.")
            recordDiagnostic("Heart send to \(friend.displayName) failed.")
        }
        scheduleStatusClear()
    }

    /// First word of a display name for warm copy ("Aisha" from "Aisha Bloom"). Pure, so
    /// `nonisolated` — usable from any UI context.
    public nonisolated static func firstName(of displayName: String) -> String {
        let trimmed = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let first = trimmed.split(separator: " ").first, !first.isEmpty else { return "your friend" }
        return String(first)
    }

    // MARK: - Receive

    public func proximityCoordinator(
        _ coordinator: ProximityCoordinator,
        didReceive envelope: FernletIdentityEnvelope,
        plaintext: Data,
        from peer: ProximityCoordinator.PeerIdentity?
    ) {
        guard envelope.payloadType == .friendHeart,
              let payload = try? JSONDecoder().decode(HeartPayload.self, from: plaintext),
              payload.format == "fernlet.proximity.heart",
              payload.version == 1,
              HeartPayload.isValidDayKey(payload.sentAtDayKey) else { return }

        // Hearts are friends-only: require a verified sender identity that is a still-trusted,
        // unblocked friend. The coordinator already rejects blocked/revoked senders at
        // introduction time; these checks close the gap for a record that changed mid-session
        // and are the explicit blocked-sender rejection mirror of the recipe manager's policy.
        guard let peer else {
            recordDiagnostic("Dropped a heart from an unverified sender.")
            return
        }
        let vault = store.proximityTrustVault
        guard vault.isTrustedProximityPeer(signingPublicKey: peer.signingPublicKey),
              !vault.isBlockedProximitySigningKey(peer.signingPublicKey),
              !store.isBlockedFingerprint(peer.fingerprint) else {
            recordDiagnostic("Dropped a heart from a non-friend.")
            return
        }

        // Wire boundary: the display name is peer-supplied — sanitize (control/zero-width/bidi
        // scalars out, length-capped) before it is persisted, per the knownDesignerNames precedent.
        var senderName = ItemNameModeration.sanitizedName(peer.displayName)
        if senderName.isEmpty { senderName = "A friend" }

        // The ledger drops duplicates beyond the first per friend per day silently (the envelope
        // ReplayCache already rejected true replays upstream).
        if ledger.recordReceivedHeart(id: payload.id, senderDisplayName: senderName, senderFingerprint: peer.fingerprint) {
            recordDiagnostic("Received good vibes from \(senderName).")
        }
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
            "mode": "heart"
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
        inviteIfNeeded(peer)
    }

    /// Deterministic single-sided auto-invite: of the two devices that discover each other, only
    /// the one with the lexicographically smaller session id invites (a missing remote sid — a
    /// non-heart or older peer — falls back to inviting, which Multipeer dedupes). Auto-connecting
    /// is what makes a trusted friend "reachable" without either user picking from a peer list.
    private func inviteIfNeeded(_ peer: MultipeerPeer) {
        guard isRunning, connections.count < Self.maxConnections else { return }
        guard !connections.contains(where: { $0.peer.id == peer.id }) else { return }
        if let remoteSID = peer.discoveryInfo?["sid"], sessionID >= remoteSID { return }
        session.invite(peer)
    }

    private func handlePeerLost(_ peer: MultipeerPeer) {
        discoveredPeers.removeValue(forKey: peer.id)
    }

    private func handleChannelReady(_ channel: PeerChannelTransport) {
        guard !connections.contains(where: { $0.peer.id == channel.peer.id }) else { return }
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
        let connection = HeartShareConnection(
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
                Task { await coordinator.commitManualProximity() }
            default:
                break
            }

            if case .connected(let peerIdentity) = connections[index].coordinator.state {
                let fingerprint = peerIdentity.fingerprint
                if connections[index].fingerprint != fingerprint {
                    connections[index].fingerprint = fingerprint
                    connections[index].verifiedKeyAgreementPublicKey = peerIdentity.keyAgreementPublicKey
                    recordDiagnostic("Verified \(peerIdentity.displayName).")
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
        refreshReachability()
    }

    private func removeConnections(matching peer: MultipeerPeer) {
        let before = connections.count
        connections.removeAll { connection in
            connection.peer.id == peer.id || connection.peer.underlying == peer.underlying
        }
        if connections.count != before {
            connectionObservationRevision += 1
        }
        refreshReachability()
    }

    private func refreshReachability() {
        let current = Set(connections.compactMap(\.fingerprint))
        if current != reachableFingerprints {
            reachableFingerprints = current
        }
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
