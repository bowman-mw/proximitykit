import Foundation
import Combine
import MultipeerConnectivity
import Observation
import UIKit
import FernletDomainModel

@MainActor
public protocol ProximityInspectorRecording: AnyObject {
    func beginSession(role: ProximityCoordinator.Role, mode: ProximityCoordinator.Mode, localFingerprint: String)
    func recordCoordinatorEvent(_ message: String)
    func recordEnvelope(_ record: ConnectionSessionLog.EnvelopeRecord)
    func recordRangingSample(_ sample: ConnectionSessionLog.DistanceSample)
    func updatePeer(_ peer: ConnectionSessionLog.PeerInfo)
    func updateTransport(_ block: (inout ConnectionSessionLog.TransportInfo) -> Void)
    func updateRangingMode(_ mode: ProximityCoordinator.RangingMode)
    func recordError(domain: String, message: String, recoverable: Bool)
    func endSession(endState: String)
}

@MainActor
public protocol ProximityPayloadHandling: AnyObject {
    func proximityCoordinator(
        _ coordinator: ProximityCoordinator,
        didReceive envelope: FernletIdentityEnvelope,
        plaintext: Data,
        from peer: ProximityCoordinator.PeerIdentity?
    )
}

extension ProximityInspectorRecording {
    public func beginSession(role: ProximityCoordinator.Role, mode: ProximityCoordinator.Mode, localFingerprint: String) {}
    public func recordEnvelope(_ record: ConnectionSessionLog.EnvelopeRecord) {}
    public func recordRangingSample(_ sample: ConnectionSessionLog.DistanceSample) {}
    public func updatePeer(_ peer: ConnectionSessionLog.PeerInfo) {}
    public func updateTransport(_ block: (inout ConnectionSessionLog.TransportInfo) -> Void) {}
    public func updateRangingMode(_ mode: ProximityCoordinator.RangingMode) {}
    public func recordError(domain: String, message: String, recoverable: Bool) {}
    public func endSession(endState: String) {}
}

@MainActor
public final class ProximityInspectorEventRecorder: ProximityInspectorRecording {
    public private(set) var events: [String] = []

    public init() {}

    public func recordCoordinatorEvent(_ message: String) {
        events.append(message)
    }
}

// WI-9: mesh wire payloads decoded from peer plaintext — `nonisolated, Sendable` so the decode is
// not pinned to the MainActor by ProximityKit's `.defaultIsolation(MainActor.self)` (see MeshPayloads.swift).
private nonisolated struct IdentityRangingPayload: Codable, Sendable {
    let rangingMode: String
    let discoveryToken: Data?
    /// Phase 1 capability advertisement — an ADDITIVE JSON key: old clients' decoders ignore it,
    /// and an old client's intro decodes here as `nil` (legacy = photos-only, see
    /// `PeerIdentity.supports(_:)`). Raw `ProximityCapability` tokens, kept as strings so a newer
    /// build's capability names survive the round-trip.
    let capabilities: [String]?
    /// Heart-drop prekey bundle gossip (bitchat adoptions Increment 3) — another additive key old
    /// decoders ignore. Rides the SIGNED intro envelope, so bundle provenance is the envelope's
    /// Ed25519 signature; there is no second standalone bundle signature to drift out of sync.
    /// nil when the sender hasn't opted into away hearts (`heartsAway` capability absent too).
    let heartDropPrekeyBundle: HeartPrekeyStore.Bundle?

    init(rangingMode: String, discoveryToken: Data?, capabilities: [String]?,
         heartDropPrekeyBundle: HeartPrekeyStore.Bundle? = nil) {
        self.rangingMode = rangingMode
        self.discoveryToken = discoveryToken
        self.capabilities = capabilities
        self.heartDropPrekeyBundle = heartDropPrekeyBundle
    }
}

private nonisolated struct SessionHeartbeatPayload: Codable, Sendable {
    enum Kind: String, Codable, Sendable {
        case ping
        case ack
    }

    let kind: Kind
    let heartbeatID: UUID
    let sentAt: Date
    let responseTo: UUID?
}

@MainActor
@Observable
public final class ProximityCoordinator {
    // Role/Mode/RangingMode hoisted to FernletDomainModel (ProximityRole/ProximityMode/
    // ProximityRangingMode); typealiases keep every `ProximityCoordinator.Role` / bare `Role`
    // reference across the proximity subtree compiling unchanged.
    public typealias Role = ProximityRole
    public typealias Mode = ProximityMode

    public private(set) var state: State = .idle
    public private(set) var lastKnownDistance: RangingDistance?

    @ObservationIgnored private let identity: IdentityService
    @ObservationIgnored private let transport: any MultipeerTransport
    @ObservationIgnored private let ranging: any RangingProvider
    @ObservationIgnored private weak var inspector: (any ProximityInspectorRecording)?
    @ObservationIgnored private weak var payloadHandler: (any ProximityPayloadHandling)?
    @ObservationIgnored private weak var trustPolicy: (any ProximityTrustPolicy)?
    @ObservationIgnored private let replayCache: ReplayCache
    @ObservationIgnored private let foregroundAnchor: any ProximityForegroundAnchoring
    @ObservationIgnored private let displayName: String
    // Capability tokens advertised in this radio's identity intro/ack (Phase 1). Empty = this
    // radio offers none of the mesh feature payloads (e.g. the recipe radio).
    @ObservationIgnored private let localCapabilities: [String]
    // SEALED-INTRODUCTION rule (Phase 4b): non-nil ONLY for a presence-originated heart connection.
    // It is the intended friend's vault KA public key. When set, this coordinator SEALS its outbound
    // identity intro/ack to that key (never emits identity in the clear) and OPENS an inbound sealed
    // intro/ack with the local KA private key — closing the tag-replay identity leak. Every other
    // radio (mesh photo/shop/recipe/admission, trainer) leaves this nil and its handshake unchanged.
    @ObservationIgnored private let sealedIntroductionPeerKey: Data?
    @ObservationIgnored private let timeoutSeconds: TimeInterval
    @ObservationIgnored private let now: () -> Date

    @ObservationIgnored private var cancellables: Set<AnyCancellable> = []
    @ObservationIgnored private var timeoutTask: Task<Void, Never>?
    @ObservationIgnored private var heartbeatTask: Task<Void, Never>?
    @ObservationIgnored private let tapDetector: ProximityCommitDetector        // trainer-mode tap gate (0.05 m / 1.0 s)
    @ObservationIgnored private let commitDetector: ProximityCommitDetector     // friend-mode proximity gate (0.15 m / 0.8 s)
    @ObservationIgnored private var rangingStarted = false
    @ObservationIgnored private var currentRole: Role?
    @ObservationIgnored private var currentMode: Mode?
    @ObservationIgnored private var currentTransportPeer: MultipeerPeer?
    @ObservationIgnored private var pendingInvite: MultipeerPendingInvite?
    @ObservationIgnored private var pendingPeerIdentity: PeerIdentity?
    @ObservationIgnored private var connectedPeerIdentity: PeerIdentity?
    @ObservationIgnored private var rangingMode: RangingMode = .none
    @ObservationIgnored private var lastInboundHeartbeatAt: Date?
    @ObservationIgnored private var lastTransferCompletedAt: Date?
    @ObservationIgnored private var bytesSent = 0
    @ObservationIgnored private var bytesReceived = 0
    @ObservationIgnored private var heartbeatSendFailures = 0
    @ObservationIgnored private var pendingHeartbeatSentAtByID: [UUID: Date] = [:]
    @ObservationIgnored private var autoReconnect = false
    @ObservationIgnored private var reconnectTask: Task<Void, Never>?
    // Ephemeral per-session random ID advertised in Bonjour TXT instead of the persistent fingerprint.
    @ObservationIgnored private var sessionID = UUID().uuidString

    public init(
        identity: IdentityService,
        transport: any MultipeerTransport,
        ranging: any RangingProvider,
        inspector: (any ProximityInspectorRecording)? = nil,
        payloadHandler: (any ProximityPayloadHandling)? = nil,
        trustPolicy: (any ProximityTrustPolicy)? = nil,
        replayCache: ReplayCache,
        foregroundAnchor: (any ProximityForegroundAnchoring)? = nil,
        displayName: String = "Fernlet",
        capabilities: [String] = [],
        sealedIntroductionPeerKeyAgreementKey: Data? = nil,
        timeoutSeconds: TimeInterval = 30,
        now: @escaping () -> Date = Date.init
    ) {
        self.identity = identity
        self.transport = transport
        self.ranging = ranging
        self.inspector = inspector
        self.payloadHandler = payloadHandler
        self.trustPolicy = trustPolicy
        self.replayCache = replayCache
        if let foregroundAnchor {
            self.foregroundAnchor = foregroundAnchor
        } else {
            #if canImport(ActivityKit)
            self.foregroundAnchor = ActivityKitProximityForegroundAnchor()
            #else
            self.foregroundAnchor = NoopProximityForegroundAnchor()
            #endif
        }
        self.displayName = displayName
        self.localCapabilities = capabilities
        self.sealedIntroductionPeerKey = sealedIntroductionPeerKeyAgreementKey
        self.timeoutSeconds = timeoutSeconds
        self.now = now
        self.tapDetector = ProximityCommitDetector(proximityThreshold: 0.05, dwellSeconds: 1.0, minimumSamples: 3)
        self.commitDetector = ProximityCommitDetector(proximityThreshold: 0.15, dwellSeconds: 0.8, minimumSamples: 3)
        self.rangingMode = ranging.isHardwareSupported ? .uwb : .rssi
        subscribeToTransport()
        subscribeToRanging()
    }

    deinit {
        timeoutTask?.cancel()
        heartbeatTask?.cancel()
    }

    func attachPayloadHandler(_ payloadHandler: any ProximityPayloadHandling) {
        self.payloadHandler = payloadHandler
    }

    public func begin(role: Role, mode: Mode) async {
        await transport.disconnect()
        do {
            try prepareSession(role: role, mode: mode)

            switch role {
            case .advertiser:
                try await transport.startAdvertising(
                    serviceType: serviceType(for: mode),
                    discoveryInfo: discoveryInfo(for: role, mode: mode)
                )
            case .browser:
                try await transport.startBrowsing(serviceType: serviceType(for: mode))
            }
            transition(to: .discovering)
        } catch {
            fail(error.localizedDescription)
        }
    }

    public func beginFriendJoin() async {
        await transport.disconnect()
        do {
            try prepareSession(role: .browser, mode: .friend)
            try await transport.startAdvertising(
                serviceType: serviceType(for: .friend),
                discoveryInfo: discoveryInfo(for: .browser, mode: .friend)
            )
            try await transport.startBrowsing(serviceType: serviceType(for: .friend))
            transition(to: .discovering)
        } catch {
            fail(error.localizedDescription)
        }
    }

    private func prepareSession(role: Role, mode: Mode) throws {
        sessionID = UUID().uuidString
        try identity.ensureProvisioned()
        currentRole = role
        currentMode = mode
        inspector?.beginSession(role: role, mode: mode, localFingerprint: identity.localFingerprint)
        trustPolicy?.recordTrainerAudit(TrainerAuditEvent(
            kind: .pairingStarted,
            peerFingerprint: nil,
            peerDisplayName: nil,
            message: "Pairing started as \(role.rawValue) in \(mode.rawValue) mode"
        ))
        currentTransportPeer = nil
        connectedPeerIdentity = nil
        pendingPeerIdentity = nil
        pendingInvite = nil
        lastInboundHeartbeatAt = nil
        lastTransferCompletedAt = nil
        bytesSent = 0
        bytesReceived = 0
        pendingHeartbeatSentAtByID.removeAll()
        tapDetector.reset()
        commitDetector.reset()
        rangingStarted = false
        rangingMode = ranging.isHardwareSupported ? .uwb : .rssi
        transition(to: .starting)
        armTimeoutIfNeeded()
    }

    public func acceptPendingInvite() async {
        guard let invite = pendingInvite else {
            fail("No pending invite to accept")
            return
        }

        do {
            try await transport.accept(invite)
            currentTransportPeer = invite.peer
            if currentMode == .friend {
                transition(to: .awaitingIdentityIntroduction(peer: invite.peer))
                inspector?.recordCoordinatorEvent("invite accepted — sending intro")
                await sendIdentityIntroduction(to: invite.peer)
            } else {
                transition(to: .awaitingTapConfirmation(peer: invite.peer))
                inspector?.recordCoordinatorEvent("invite accepted")
            }
        } catch {
            fail(error.localizedDescription)
        }
    }

    public func rejectPendingInvite() async {
        if case .awaitingUserConfirmation = state {
            await end(.userCancelled)
            return
        }

        pendingInvite?.respond(false)
        pendingInvite = nil
        currentTransportPeer = nil
        transition(to: .idle)
        inspector?.recordCoordinatorEvent("invite rejected")
    }

    public func tapToConfirm() async {
        guard case .awaitingTapConfirmation(let peer) = state else { return }
        await finishTapConfirmation(for: peer)
    }

    public func confirmPeerIdentity() async {
        guard let peer = pendingPeerIdentity else {
            fail("No peer identity awaiting confirmation")
            return
        }
        pendingPeerIdentity = nil
        connectedPeerIdentity = peer
        updateInspectorPeer(identity: peer, transportPeer: currentTransportPeer)
        updateInspectorRangingMode(peer.rangingMode)
        transition(to: .connected(peer: peer))
        timeoutTask?.cancel()
        lastInboundHeartbeatAt = now()
        heartbeatSendFailures = 0
        if currentMode == .friend { autoReconnect = true }
        startHeartbeatLoop()
        // Send one immediate ping so the peer can auto-commit without waiting 30 seconds.
        if currentMode == .friend { Task { [weak self] in await self?.heartbeatTick() } }
        await foregroundAnchor.start(peerName: peer.displayName, startedAt: now())
        inspector?.recordCoordinatorEvent("identity confirmed \(peer.fingerprint)")
    }

    public func send(_ envelope: FernletIdentityEnvelope) async throws {
        guard let peer = currentTransportPeer, let identity = connectedIdentity else {
            throw CoordinatorError.notConnected
        }

        transition(to: .transferring(peer: identity, progress: 0.0))
        defer { if case .transferring = state { transition(to: .connected(peer: identity)) } }
        let data = try JSONEncoder().encode(envelope)
        try await transport.send(data, to: peer, mode: .reliable)
        recordEnvelope(envelope, direction: .sent, byteCount: data.count, signatureVerified: true)
        bytesSent += data.count
        await foregroundAnchor.update(bytesSent: bytesSent, bytesReceived: bytesReceived)
        inspector?.recordCoordinatorEvent("envelope sent \(envelope.payloadTypeToken)")
        trustPolicy?.recordTrainerAudit(TrainerAuditEvent(
            kind: .envelopeSent,
            peerFingerprint: identity.fingerprint,
            peerDisplayName: identity.displayName,
            payloadType: envelope.payloadType,
            message: "Sent \(envelope.payloadTypeToken)"
        ))
        lastTransferCompletedAt = now()
        transition(to: .connected(peer: identity))
    }

    func sendPayload(type: PayloadType, summary: PayloadSummary, payload: Data, sealed: Bool = false) async throws {
        guard currentTransportPeer != nil else { throw CoordinatorError.notConnected }
        let (finalPayload, encryption) = try sealIfNeeded(payload, sealed: sealed)
        let sentAt = now()
        let envelope = try FernletIdentityEnvelope.signed(
            identityService: identity,
            senderDisplayName: displayName,
            recipientFingerprint: connectedIdentity?.fingerprint,
            payloadType: type,
            payloadEncryption: encryption,
            payloadSummary: summary,
            payload: finalPayload,
            createdAt: sentAt,
            expiresAt: sentAt.addingTimeInterval(5 * 60)
        )
        try await send(envelope)
    }

    private func sealIfNeeded(_ payload: Data, sealed: Bool) throws -> (Data, PayloadEncryption) {
        guard sealed, let kaKey = connectedIdentity?.keyAgreementPublicKey, !kaKey.isEmpty else {
            return (payload, .none)
        }
        let ciphertext = try identity.seal(payload, to: kaKey, format: peerSealedPayloadFormat)
        return (ciphertext, .sealedTo(recipientKeyAgreementPublicKey: kaKey))
    }

    /// wire2 gate (bitchat adoptions Increment 2): frame sealed bodies we SEND only when the peer
    /// advertised `wire2`; unframe sealed bodies we RECEIVE only when the sender advertised it.
    /// Both directions key off the same intro exchange, so interpretation is deterministic; the
    /// tolerant tag check inside `open(format: .wire2)` covers the window where a wire2-capable
    /// sender hadn't yet learned OUR capabilities and sealed legacy. Intro/ack envelopes evaluate
    /// before any peer identity exists → `.legacy`, which is exactly right (intros are never
    /// framed — capabilities are unknown when they're built).
    private var peerSealedPayloadFormat: SealedPayloadFormat {
        (connectedIdentity ?? pendingPeerIdentity)?.supports(.wire2) == true ? .wire2 : .legacy
    }

    public func cancel() async {
        autoReconnect = false
        reconnectTask?.cancel()
        reconnectTask = nil
        await end(.userCancelled)
    }

    private var connectedIdentity: PeerIdentity? {
        switch state {
        case .connected(let peer), .transferring(let peer, _):
            return peer
        default:
            return connectedPeerIdentity
        }
    }

    private func subscribeToTransport() {
        transport.state
            .sink { [weak self] transportState in
                Task { @MainActor [weak self] in
                    await self?.handleTransportState(transportState)
                }
            }
            .store(in: &cancellables)

        transport.inbound
            .sink { [weak self] message in
                Task { @MainActor [weak self] in
                    await self?.handleInbound(message)
                }
            }
            .store(in: &cancellables)
    }

    private func subscribeToRanging() {
        ranging.distance
            .sink { [weak self] distance in
                Task { @MainActor [weak self] in
                    await self?.handleDistance(distance)
                }
            }
            .store(in: &cancellables)

        ranging.state
            .sink { [weak self] rangingState in
                Task { @MainActor [weak self] in
                    self?.handleRangingState(rangingState)
                }
            }
            .store(in: &cancellables)
    }

    private var isSessionLive: Bool {
        switch state {
        case .connected, .transferring, .awaitingIdentityIntroduction, .awaitingUserConfirmation,
             .awaitingProximityCommit, .awaitingManualCommit:
            return true
        default:
            return false
        }
    }

    private func handleTransportState(_ transportState: MultipeerTransportState) async {
        switch transportState {
        case .advertising, .browsing:
            if isSessionLive { return }
            transition(to: .discovering)
        case .discovered(let peers):
            if isSessionLive { return }
            guard let peer = peers.first else {
                transition(to: .discovering)
                return
            }
            currentTransportPeer = peer
            updateInspectorPeer(transportPeer: peer)
            transition(to: .peerInRange(peer: peer, distance: .unknown))
            guard currentRole == .browser else { return }
            guard shouldInviteDiscoveredPeer(peer) else { return }
            do {
                try await transport.invite(peer)
                inspector?.recordCoordinatorEvent("invite sent to \(peer.displayName)")
            } catch {
                fail(error.localizedDescription)
            }
        case .awaitingPeerAcceptance(let peer):
            currentTransportPeer = peer
            updateInspectorPeer(transportPeer: peer)
            updateInspectorTransport(state: "connecting")
            transition(to: .awaitingTapConfirmation(peer: peer))
        case .awaitingLocalAcceptance(let invite):
            pendingInvite = invite
            currentTransportPeer = invite.peer
            updateInspectorPeer(transportPeer: invite.peer)
            if currentMode == .friend {
                await acceptPendingInvite()
            } else {
                transition(to: .pendingInvite(invite))
            }
        case .connecting(let peer):
            currentTransportPeer = peer
            updateInspectorPeer(transportPeer: peer)
            updateInspectorTransport(state: "connecting")
            if case .awaitingTapConfirmation = state { return }
            if case .awaitingIdentityIntroduction = state { return }
            if case .awaitingProximityCommit = state { return }
            if case .awaitingManualCommit = state { return }
            if case .connected = state { return }
            transition(to: .awaitingTapConfirmation(peer: peer))
        case .connected(let peer):
            currentTransportPeer = peer
            updateInspectorPeer(transportPeer: peer)
            updateInspectorTransport(state: "connected")
            if case .connected = state { return }
            if case .awaitingTapConfirmation = state { return }
            if case .awaitingIdentityIntroduction = state { return }
            if case .awaitingProximityCommit = state { return }
            if case .awaitingManualCommit = state { return }
            // Friend mode: skip the tap gate; send identity intro immediately so ranging
            // can start before the commit, and the 15 cm dwell drives auto-connect.
            if currentMode == .friend {
                transition(to: .awaitingIdentityIntroduction(peer: peer))
                await sendIdentityIntroduction(to: peer)
                return
            }
            transition(to: .awaitingTapConfirmation(peer: peer))
        case .disconnected:
            updateInspectorTransport(state: "notConnected", disconnected: true)
            await end(.transportLost)
        case .failed(let error):
            updateInspectorTransport(state: "failed", disconnected: true)
            inspector?.recordError(domain: "Multipeer", message: String(describing: error), recoverable: false)
            fail(String(describing: error))
        case .idle:
            break
        }
    }

    private func shouldInviteDiscoveredPeer(_ peer: MultipeerPeer) -> Bool {
        guard currentMode == .friend else { return true }
        guard let remoteSID = peer.discoveryInfo?["sid"] else { return true }
        if sessionID == remoteSID {
            return displayName < peer.displayName  // self-discovery tie-break
        }
        return sessionID < remoteSID  // deterministic single-inviter selection
    }

    private func handleRangingState(_ rangingState: RangingState) {
        switch rangingState {
        case .fallback(let rssiOnly) where rssiOnly:
            rangingMode = .rssi
            updateInspectorRangingMode(.rssi)
            inspector?.recordCoordinatorEvent("ranging fallback: rssi only")
        case .running:
            rangingMode = .uwb
            updateInspectorRangingMode(.uwb)
            inspector?.recordCoordinatorEvent("ranging started: uwb")
        case .invalidated(let reason):
            rangingStarted = false
            rangingMode = .rssi
            updateInspectorRangingMode(.rssi)
            inspector?.recordError(domain: "Ranging", message: reason, recoverable: true)
            inspector?.recordCoordinatorEvent("ranging invalidated, falling back to manual commit: \(reason)")
            if case .awaitingProximityCommit(let peerIdentity) = state {
                transition(to: .awaitingManualCommit(peer: peerIdentity))
            }
        case .idle, .fallback:
            break
        }
    }

    private func handleDistance(_ distance: RangingDistance) async {
        lastKnownDistance = distance
        if case .meters(let meters, let direction) = distance {
            inspector?.recordRangingSample(ConnectionSessionLog.DistanceSample(
                timestamp: now(),
                meters: meters,
                direction: direction
            ))
        }
        guard ranging.isHardwareSupported, case .meters(let meters, _) = distance else { return }

        // Friend mode: 15 cm / 0.8 s average dwell commits the connection.
        if case .awaitingProximityCommit(let peerIdentity) = state {
            if commitDetector.ingest(distanceMeters: meters, at: now()) {
                inspector?.recordCoordinatorEvent("proximity commit at \(String(format: "%.2f", meters)) m")
                pendingPeerIdentity = peerIdentity
                await confirmPeerIdentity()
            }
            return
        }

        // Trainer mode: tight tap gate drives manual confirmation
        guard case .awaitingTapConfirmation(let peer) = state else { return }
        if tapDetector.ingest(distanceMeters: meters, at: now()) {
            await finishTapConfirmation(for: peer)
        }
    }

    /// Manual proximity confirmation — works for both non-UWB (awaitingManualCommit)
    /// and UWB devices where the debug Force button overrides the proximity gate.
    func commitManualProximity() async {
        switch state {
        case .awaitingManualCommit(let peerIdentity), .awaitingProximityCommit(let peerIdentity):
            inspector?.recordCoordinatorEvent("manual proximity commit")
            pendingPeerIdentity = peerIdentity
            await confirmPeerIdentity()
        default:
            return
        }
    }

    private func finishTapConfirmation(for peer: MultipeerPeer) async {
        currentTransportPeer = peer
        transition(to: .awaitingIdentityIntroduction(peer: peer))
        inspector?.recordCoordinatorEvent("tap confirmed")
        await sendIdentityIntroduction(to: peer)
    }

    /// True ONLY for a presence-originated heart connection (SEALED-INTRODUCTION rule, Phase 4b):
    /// identity intro/ack are sealed to the intended friend's KA key and never emitted in the clear.
    private var usesSealedIntroduction: Bool { sealedIntroductionPeerKey != nil }

    /// Encodes an identity intro/ack for the wire. On an ordinary radio this is the plain signed
    /// envelope. On a presence-heart connection it is SEALED to the intended friend's KA key and
    /// wrapped so the wire carries no cleartext identity — fail-closed: a missing/empty expected KA
    /// key throws (never falls back to unsealed), which fails the connection at the call site.
    private func encodeIdentityEnvelopeForTransport(_ envelope: FernletIdentityEnvelope) throws -> Data {
        guard usesSealedIntroduction else {
            return try JSONEncoder().encode(envelope)
        }
        guard let key = sealedIntroductionPeerKey, !key.isEmpty else {
            throw CoordinatorError.sealedIntroductionKeyMissing
        }
        let inner = try JSONEncoder().encode(envelope)
        let ciphertext = try identity.seal(inner, to: key)
        return try JSONEncoder().encode(SealedIntroductionEnvelope(sealedIntroduction: ciphertext))
    }

    private enum SealedIntroUnwrap {
        case notWrapped          // a plain envelope (e.g. a post-commit heartbeat) — process as-is
        case opened(Data)        // a sealed wrapper opened with the local KA private key
        case failed              // a wrapper we could NOT open (a tag-replay forger) — fail-closed
    }

    /// On a sealed-introduction coordinator, an inbound identity intro/ack arrives as a
    /// `SealedIntroductionEnvelope`. Open it with the local KA private key, expecting the friend's
    /// KA key the coordinator was created with (that expectation is what a forger cannot satisfy —
    /// `open` is cryptographically bound to the sender's KA key via the HKDF sharedInfo). A plain
    /// envelope (no `sealedIntroduction` key) returns `.notWrapped`; a wrapper we cannot decrypt
    /// returns `.failed`.
    private func unwrapSealedIntroduction(_ data: Data) -> SealedIntroUnwrap {
        guard let wrapper = try? JSONDecoder().decode(SealedIntroductionEnvelope.self, from: data) else {
            return .notWrapped
        }
        guard let key = sealedIntroductionPeerKey, !key.isEmpty,
              let inner = try? identity.open(wrapper.sealedIntroduction, from: key) else {
            return .failed
        }
        return .opened(inner)
    }

    private func sendIdentityIntroduction(to peer: MultipeerPeer) async {
        do {
            let sentAt = now()
            let envelope = try FernletIdentityEnvelope.signed(
                identityService: identity,
                senderDisplayName: displayName,
                recipientFingerprint: peer.advertisedFingerprint,
                payloadType: .identityIntroduction,
                payloadSummary: PayloadSummary(title: "Hello from \(displayName)"),
                payload: try await makeIdentityRangingPayload(),
                createdAt: sentAt,
                expiresAt: sentAt.addingTimeInterval(5 * 60)
            )
            let data = try encodeIdentityEnvelopeForTransport(envelope)
            try await transport.send(data, to: peer, mode: .reliable)
            recordEnvelope(envelope, direction: .sent, byteCount: data.count, signatureVerified: true)
            inspector?.recordCoordinatorEvent("identity introduction sent")
        } catch {
            fail(error.localizedDescription)
        }
    }

    private func handleInbound(_ message: MultipeerInboundMessage) async {
        currentTransportPeer = message.peer

        // SEALED-INTRODUCTION rule (Phase 4b): on a presence-heart connection the identity
        // intro/ack arrives sealed to us. Open it first; a wrapper we cannot decrypt is a
        // tag-replay forger (no matching KA private key) — fail with NO identity emitted and no
        // further intro. A plain envelope (a post-commit heartbeat) passes straight through.
        var envelopeData = message.data
        var cameFromSealedWrapper = false
        if usesSealedIntroduction {
            switch unwrapSealedIntroduction(message.data) {
            case .notWrapped:
                break
            case .opened(let inner):
                envelopeData = inner
                cameFromSealedWrapper = true
            case .failed:
                inspector?.recordCoordinatorEvent("sealed introduction could not be opened — failing")
                fail("sealed introduction open failed")
                return
            }
        }

        do {
            let envelope = try JSONDecoder().decode(FernletIdentityEnvelope.self, from: envelopeData)

            // On a sealed-introduction connection an identity intro/ack MUST arrive sealed. A PLAIN
            // identity envelope (a forger sending their own intro to bait a cleartext ack) is
            // rejected outright — the sealed wrapper is the only channel for identity here.
            if usesSealedIntroduction, !cameFromSealedWrapper,
               let plainType = envelope.payloadType,
               plainType == .identityIntroduction || plainType == .identityAcknowledge {
                inspector?.recordCoordinatorEvent("rejected unsealed identity envelope on a sealed connection")
                fail("unsealed identity envelope on a sealed-introduction connection")
                return
            }

            if trustPolicy?.isRevokedProximitySigningKey(envelope.senderSigningPublicKey) == true {
                let fingerprint = IdentityService.fingerprint(of: envelope.senderSigningPublicKey)
                trustPolicy?.recordTrainerAudit(TrainerAuditEvent(
                    kind: .revokedPeerBlocked,
                    peerFingerprint: fingerprint,
                    peerDisplayName: envelope.senderDisplayName,
                    payloadType: envelope.payloadType,
                    message: "Blocked envelope from revoked key"
                ))
                fail("revokedKey")
                return
            }
            if trustPolicy?.isBlockedProximitySigningKey(envelope.senderSigningPublicKey) == true {
                return  // silent drop — no audit entry visible to sender
            }
            let plaintext = try envelope.verify(
                identityService: identity,
                replayCache: replayCache,
                sealedPayloadFormat: peerSealedPayloadFormat
            )
            recordEnvelope(envelope, direction: .received, byteCount: message.bytesReceived, signatureVerified: true)
            bytesReceived += message.bytesReceived
            await foregroundAnchor.update(bytesSent: bytesSent, bytesReceived: bytesReceived)
            inspector?.recordCoordinatorEvent("envelope received \(envelope.payloadTypeToken)")
            trustPolicy?.recordTrainerAudit(TrainerAuditEvent(
                kind: .envelopeReceived,
                peerFingerprint: IdentityService.fingerprint(of: envelope.senderSigningPublicKey),
                peerDisplayName: envelope.senderDisplayName,
                payloadType: envelope.payloadType,
                message: "Received \(envelope.payloadTypeToken)"
            ))

            // Phase 1 forward tolerance: a payload type only a NEWER build knows arrived on a live
            // session. The envelope authenticated (schema/expiry/signature/replay were all enforced
            // by `verify` above), so this is a well-behaved future peer, not an attack — park it
            // and keep the session alive. Never dispatched to the payload handler, never `fail()`.
            guard let payloadType = envelope.payloadType else {
                inspector?.recordCoordinatorEvent("parked unknown payload type \(envelope.payloadTypeToken)")
                return
            }

            switch payloadType {
            case .identityIntroduction, .identityAcknowledge:
                try await handleIdentityEnvelope(envelope, plaintext: plaintext, from: message.peer)
            case .sessionHeartbeat:
                await handleHeartbeat(envelope, plaintext: plaintext, from: message.peer)
            default:
                inspector?.recordCoordinatorEvent("envelope verified \(envelope.payloadTypeToken)")
                payloadHandler?.proximityCoordinator(self, didReceive: envelope, plaintext: plaintext, from: connectedIdentity ?? pendingPeerIdentity)
            }
        } catch {
            trustPolicy?.recordTrainerAudit(TrainerAuditEvent(
                kind: .envelopeRejected,
                peerFingerprint: message.peer.advertisedFingerprint,
                peerDisplayName: message.peer.displayName,
                message: "Envelope verification failed: \(error)"
            ))
            inspector?.recordError(domain: "Envelope", message: String(describing: error), recoverable: false)
            fail("Envelope verification failed: \(error)")
        }
    }

    /// Heart-drop prekey gossip seams (bitchat adoptions Increment 3), set post-init by the
    /// owning manager — nil provider means no bundle rides our intro (consent off or feature
    /// absent), nil receiver means received bundles are ignored. The receiver fires ONLY after
    /// the intro envelope verified, keyed by the sender's full signing key.
    public var heartDropPrekeyBundleProvider: (() -> HeartPrekeyStore.Bundle?)?
    public var onHeartDropPrekeyBundle: ((_ senderSigningPublicKey: Data, _ bundle: HeartPrekeyStore.Bundle) -> Void)?

    private func makeIdentityRangingPayload() async throws -> Data {
        let token: Data?
        if ranging.isHardwareSupported {
            token = try? await ranging.myDiscoveryToken()
        } else {
            token = nil
        }
        let payload = IdentityRangingPayload(
            rangingMode: ranging.isHardwareSupported ? RangingMode.uwb.rawValue : RangingMode.rssi.rawValue,
            discoveryToken: token,
            capabilities: localCapabilities,
            heartDropPrekeyBundle: heartDropPrekeyBundleProvider?()
        )
        return try JSONEncoder().encode(payload)
    }

    private func sendIdentityAcknowledgement(to peer: MultipeerPeer) async {
        do {
            let sentAt = now()
            let envelope = try FernletIdentityEnvelope.signed(
                identityService: identity,
                senderDisplayName: displayName,
                recipientFingerprint: peer.advertisedFingerprint,
                payloadType: .identityAcknowledge,
                payloadSummary: PayloadSummary(title: "Identity acknowledged"),
                payload: try await makeIdentityRangingPayload(),
                createdAt: sentAt,
                expiresAt: sentAt.addingTimeInterval(5 * 60)
            )
            let data = try encodeIdentityEnvelopeForTransport(envelope)
            try await transport.send(data, to: peer, mode: .reliable)
            recordEnvelope(envelope, direction: .sent, byteCount: data.count, signatureVerified: true)
            inspector?.recordCoordinatorEvent("identity acknowledge sent")
        } catch {
            // A sealed-introduction connection must NEVER continue past a failed seal — a silent
            // continue could otherwise proceed toward commit without the acknowledgement the peer
            // needs. Fail-closed; ordinary radios keep the best-effort log-and-continue behavior.
            if usesSealedIntroduction {
                fail("sealed identity acknowledgement failed: \(error.localizedDescription)")
            } else {
                inspector?.recordCoordinatorEvent("identity acknowledge failed")
            }
        }
    }

    private func handleHeartbeat(
        _ envelope: FernletIdentityEnvelope,
        plaintext: Data,
        from peer: MultipeerPeer
    ) async {
        // SEALED-INTRODUCTION rule (Phase 4b): never respond to a heartbeat before the peer's
        // identity has been verified via the sealed intro. `sendHeartbeatAcknowledgement` emits our
        // signing/KA keys + display name in the CLEAR, and a connected tag-replay forger (who can't
        // complete the sealed handshake) could otherwise ping us in `awaitingIdentityIntroduction`
        // and read that ack — deanonymizing us. Once `pendingPeerIdentity`/`connectedPeerIdentity`
        // is set, the peer is provably the real friend (only a valid sealed intro sets it).
        if usesSealedIntroduction, pendingPeerIdentity == nil, connectedPeerIdentity == nil {
            inspector?.recordCoordinatorEvent("dropped a heartbeat before sealed identity verification")
            return
        }
        lastInboundHeartbeatAt = now()
        inspector?.recordCoordinatorEvent("heartbeat received")

        // Heartbeats are only sent after the remote peer commits. If we receive one while
        // still waiting to commit (e.g. the other side used Force), auto-confirm our side —
        // identity is already verified and the remote has accepted the connection.
        if currentMode == .friend {
            switch state {
            case .awaitingProximityCommit(let peerIdentity), .awaitingManualCommit(let peerIdentity):
                inspector?.recordCoordinatorEvent("auto-commit triggered by peer heartbeat")
                pendingPeerIdentity = peerIdentity
                await confirmPeerIdentity()
            default:
                break
            }
        }

        guard let heartbeat = try? JSONDecoder().decode(SessionHeartbeatPayload.self, from: plaintext) else { return }
        switch heartbeat.kind {
        case .ping:
            await sendHeartbeatAcknowledgement(for: heartbeat.heartbeatID, to: peer)
        case .ack:
            guard let responseTo = heartbeat.responseTo,
                  let sentAt = pendingHeartbeatSentAtByID.removeValue(forKey: responseTo) else { return }
            let rttMs = max(0, now().timeIntervalSince(sentAt) * 1000)
            inspector?.updateTransport { transport in
                transport.rttSamplesMs.append(rttMs)
                transport.rttSamplesMs = Array(transport.rttSamplesMs.suffix(50))
            }
            inspector?.recordCoordinatorEvent(String(format: "heartbeat rtt %.0fms", rttMs))
        }
    }

    private func sendHeartbeatAcknowledgement(for heartbeatID: UUID, to peer: MultipeerPeer) async {
        do {
            let now = now()
            let payload = SessionHeartbeatPayload(
                kind: .ack,
                heartbeatID: UUID(),
                sentAt: now,
                responseTo: heartbeatID
            )
            let envelope = try FernletIdentityEnvelope.signed(
                identityService: identity,
                senderDisplayName: displayName,
                recipientFingerprint: peer.advertisedFingerprint,
                payloadType: .sessionHeartbeat,
                payloadSummary: PayloadSummary(title: "Heartbeat ack"),
                payload: try JSONEncoder().encode(payload),
                createdAt: now,
                expiresAt: now.addingTimeInterval(30)
            )
            let data = try JSONEncoder().encode(envelope)
            try await transport.send(data, to: peer, mode: .unreliable)
            recordEnvelope(envelope, direction: .sent, byteCount: data.count, signatureVerified: true)
            bytesSent += data.count
            await foregroundAnchor.update(bytesSent: bytesSent, bytesReceived: bytesReceived)
            inspector?.recordCoordinatorEvent("heartbeat ack sent")
        } catch {
            inspector?.recordCoordinatorEvent("heartbeat ack failed")
        }
    }

    private func recordEnvelope(
        _ envelope: FernletIdentityEnvelope,
        direction: ConnectionSessionLog.EnvelopeRecord.Direction,
        byteCount: Int,
        signatureVerified: Bool?
    ) {
        let encrypted: Bool
        switch envelope.payloadEncryption {
        case .none:
            encrypted = false
        case .sealedTo:
            encrypted = true
        }
        inspector?.recordEnvelope(ConnectionSessionLog.EnvelopeRecord(
            envelopeID: envelope.envelopeID,
            direction: direction,
            payloadType: envelope.payloadTypeToken,
            payloadByteCount: byteCount,
            timestamp: now(),
            signatureVerified: signatureVerified,
            encrypted: encrypted,
            summary: encrypted ? envelope.payloadTypeToken : envelope.payloadSummary.title
        ))
    }

    private func updateInspectorPeer(identity: PeerIdentity? = nil, transportPeer: MultipeerPeer? = nil) {
        let displayName = identity?.displayName ?? transportPeer?.displayName ?? "Unknown"
        let advertisedFingerprint = transportPeer?.advertisedFingerprint
        let confirmedFingerprint = identity?.fingerprint
        inspector?.updatePeer(ConnectionSessionLog.PeerInfo(
            displayName: displayName,
            advertisedFingerprint: advertisedFingerprint,
            confirmedFingerprint: confirmedFingerprint,
            signingPublicKey: identity?.signingPublicKey,
            firstSeenAt: identity?.firstSeenAt ?? now(),
            lastSeenAt: now()
        ))
    }

    private func updateInspectorTransport(state: String, disconnected: Bool = false) {
        inspector?.updateTransport { transport in
            transport.mcSessionState = state
            if state == "connected", transport.connectedAt == nil {
                transport.connectedAt = now()
            }
            if disconnected {
                transport.disconnectedAt = now()
            }
        }
    }

    private func updateInspectorRangingMode(_ mode: RangingMode) {
        inspector?.updateRangingMode(mode)
    }

    private func handleIdentityEnvelope(_ envelope: FernletIdentityEnvelope, plaintext: Data, from peer: MultipeerPeer) async throws {
        let fingerprint = IdentityService.fingerprint(of: envelope.senderSigningPublicKey)
        if let advertised = peer.advertisedFingerprint,
           !IdentityService.fingerprintsMatch(advertised, fingerprint) {
            throw CoordinatorError.fingerprintMismatch
        }

        let rangingPayload = try? JSONDecoder().decode(IdentityRangingPayload.self, from: plaintext)
        await startRangingIfPossible(with: rangingPayload, from: peer)

        let peerIdentity = PeerIdentity(
            id: peer.id,
            displayName: envelope.senderDisplayName,
            signingPublicKey: envelope.senderSigningPublicKey,
            keyAgreementPublicKey: envelope.senderKeyAgreementPublicKey,
            fingerprint: fingerprint,
            rangingMode: rangingMode,
            firstSeenAt: now(),
            capabilities: rangingPayload?.capabilities
        )
        updateInspectorPeer(identity: peerIdentity, transportPeer: peer)

        // Heart-drop prekey gossip (Increment 3): the intro envelope verified above, so the
        // bundle's provenance is established — hand it to the cache keyed by the FULL signing key.
        if let bundle = rangingPayload?.heartDropPrekeyBundle {
            onHeartDropPrekeyBundle?(envelope.senderSigningPublicKey, bundle)
        }

        if envelope.payloadType == .identityAcknowledge {
            if pendingPeerIdentity == nil && connectedPeerIdentity == nil {
                pendingPeerIdentity = peerIdentity
            }
            inspector?.recordCoordinatorEvent("identity acknowledge received \(fingerprint)")
            // Friend mode: if we sent the intro first and are still waiting, now gate on proximity
            if currentMode == .friend, case .awaitingIdentityIntroduction = state {
                transitionToProximityGate(peerIdentity: peerIdentity)
            }
            return
        }

        pendingPeerIdentity = peerIdentity
        await sendIdentityAcknowledgement(to: peer)

        if currentMode == .friend {
            // Friend mode: identity verified — now wait for proximity dwell instead of auto-confirming
            inspector?.recordCoordinatorEvent("identity verified \(fingerprint) — awaiting proximity commit")
            transitionToProximityGate(peerIdentity: peerIdentity)
        } else if trustPolicy?.isTrustedProximityPeer(signingPublicKey: peerIdentity.signingPublicKey) == true {
            inspector?.recordCoordinatorEvent("trusted peer auto-confirmed \(fingerprint)")
            await confirmPeerIdentity()
        } else {
            transition(to: .awaitingUserConfirmation(peer: peerIdentity))
            inspector?.recordCoordinatorEvent("identity verified \(fingerprint)")
        }
    }

    private func transitionToProximityGate(peerIdentity: PeerIdentity) {
        // Identity is verified — cancel the short connection-phase timeout and replace it with a
        // generous proximity-gate timeout so the coordinator doesn't evict before the peer's
        // first heartbeat (sent immediately on commit) has a chance to arrive.
        timeoutTask?.cancel()
        timeoutTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 5 * 60 * 1_000_000_000)
            guard !Task.isCancelled, let self else { return }
            switch self.state {
            case .idle, .connected, .transferring, .ended, .failed: break
            default:
                self.transition(to: .ended(reason: .timeout))
                self.inspector?.recordCoordinatorEvent("ended: proximity gate timeout")
                self.inspector?.endSession(endState: "timeout")
            }
        }
        // Use rangingMode (negotiated with this specific peer) not just local hardware support.
        // If the peer has no UWB token, startRangingIfPossible already set rangingMode to .rssi,
        // so we fall back to manual commit even on a UWB-capable device.
        if rangingMode == .uwb {
            transition(to: .awaitingProximityCommit(peer: peerIdentity))
        } else {
            transition(to: .awaitingManualCommit(peer: peerIdentity))
        }
    }

    private func startRangingIfPossible(with payload: IdentityRangingPayload?, from peer: MultipeerPeer) async {
        guard !rangingStarted else { return }  // idempotent — NI session must not be restarted mid-session
        guard ranging.isHardwareSupported else {
            rangingMode = .rssi
            updateInspectorRangingMode(.rssi)
            inspector?.recordCoordinatorEvent("ranging fallback: rssi estimate unavailable")
            return
        }
        guard payload?.rangingMode == RangingMode.uwb.rawValue,
              let discoveryToken = payload?.discoveryToken else {
            rangingMode = .rssi
            updateInspectorRangingMode(.rssi)
            inspector?.recordCoordinatorEvent("ranging fallback: peer token unavailable")
            return
        }

        rangingStarted = true
        do {
            try await ranging.start(with: discoveryToken)
            rangingMode = .uwb
            updateInspectorRangingMode(.uwb)
            inspector?.recordCoordinatorEvent("ranging token accepted from \(peer.displayName)")
        } catch {
            rangingMode = .rssi
            updateInspectorRangingMode(.rssi)
            inspector?.recordError(domain: "Ranging", message: error.localizedDescription, recoverable: true)
            inspector?.recordCoordinatorEvent("ranging fallback: \(error.localizedDescription)")
        }
    }

    private func serviceType(for mode: Mode) -> String {
        switch mode {
        case .trainer: return MultipeerServiceType.trainer
        case .friend: return "fernlet-friend"
        }
    }

    private func discoveryInfo(for role: Role, mode: Mode) -> [String: String] {
        let advertisedRole: String
        switch mode {
        case .trainer:
            advertisedRole = role == .advertiser ? "trainer" : "client"
        case .friend:
            advertisedRole = "peer"
        }

        return [
            "v": "1",
            "role": advertisedRole,
            "sid": sessionID,
            "fp": identity.localFingerprint,
            "name": String(displayName.prefix(32)),
            "caps": mode == .trainer ? "plan,live,delta" : "share"
        ]
    }

    private func transition(to newState: State) {
        state = newState
        inspector?.recordCoordinatorEvent("state: \(newState.debugLabel)")
        trustPolicy?.recordTrainerAudit(TrainerAuditEvent(
            kind: .stateTransition,
            peerFingerprint: connectedIdentity?.fingerprint ?? pendingPeerIdentity?.fingerprint ?? currentTransportPeer?.advertisedFingerprint,
            peerDisplayName: connectedIdentity?.displayName ?? pendingPeerIdentity?.displayName ?? currentTransportPeer?.displayName,
            message: newState.debugLabel
        ))
    }

    private func fail(_ reason: String) {
        timeoutTask?.cancel()
        heartbeatTask?.cancel()
        lastKnownDistance = nil
        transition(to: .failed(reason: reason))
        inspector?.recordCoordinatorEvent("failed: \(reason)")
        trustPolicy?.recordTrainerAudit(TrainerAuditEvent(
            kind: .error,
            peerFingerprint: connectedIdentity?.fingerprint ?? pendingPeerIdentity?.fingerprint ?? currentTransportPeer?.advertisedFingerprint,
            peerDisplayName: connectedIdentity?.displayName ?? pendingPeerIdentity?.displayName ?? currentTransportPeer?.displayName,
            message: reason
        ))
        inspector?.endSession(endState: "failed")
        Task { [weak self] in
            await self?.ranging.stop()
            await self?.transport.disconnect()
            await self?.foregroundAnchor.stop()
        }
    }

    private func end(_ reason: EndReason) async {
        timeoutTask?.cancel()
        heartbeatTask?.cancel()
        lastKnownDistance = nil
        await ranging.stop()
        await transport.disconnect()
        await foregroundAnchor.stop()

        trustPolicy?.recordTrainerAudit(TrainerAuditEvent(
            kind: .sessionEnded,
            peerFingerprint: connectedIdentity?.fingerprint ?? pendingPeerIdentity?.fingerprint ?? currentTransportPeer?.advertisedFingerprint,
            peerDisplayName: connectedIdentity?.displayName ?? pendingPeerIdentity?.displayName ?? currentTransportPeer?.displayName,
            message: "\(reason)"
        ))

        if autoReconnect && reason == .transportLost {
            inspector?.recordCoordinatorEvent("transport lost, reconnecting")
            inspector?.endSession(endState: "reconnecting")
            transition(to: .discovering)
            reconnectTask = Task { [weak self] in
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                guard !Task.isCancelled, let self, self.autoReconnect,
                      case .discovering = self.state else { return }
                await self.beginFriendJoin()
            }
            return
        }

        transition(to: .ended(reason: reason))
        inspector?.endSession(endState: "ended.\(reason)")
    }

    private func startHeartbeatLoop() {
        heartbeatTask?.cancel()
        heartbeatTask = Task { [weak self] in
            while !Task.isCancelled {
                let interval = await MainActor.run { self?.heartbeatInterval ?? 0 }
                guard interval > 0 else {
                    try? await Task.sleep(nanoseconds: 1_000_000_000)
                    continue
                }
                let nanoseconds = UInt64(interval * 1_000_000_000)
                try? await Task.sleep(nanoseconds: nanoseconds)
                guard !Task.isCancelled else { return }
                await self?.heartbeatTick()
            }
        }
    }

    public var heartbeatInterval: TimeInterval {
        switch state {
        case .idle, .ended, .failed:
            return 0
        case .transferring:
            return 3
        case .connected:
            if let lastTransferCompletedAt,
               now().timeIntervalSince(lastTransferCompletedAt) < 30 {
                return 10
            }
            return 30
        default:
            return 0
        }
    }

    public func heartbeatTick() async {
        let interval = heartbeatInterval
        guard interval > 0 else { return }
        if case .connected = state, let lastInboundHeartbeatAt,
           now().timeIntervalSince(lastInboundHeartbeatAt) > interval * 3 {
            await end(.transportLost)
            return
        }
        guard let peer = currentTransportPeer else { return }
        do {
            let sentAt = now()
            let heartbeatID = UUID()
            let payload = SessionHeartbeatPayload(
                kind: .ping,
                heartbeatID: heartbeatID,
                sentAt: sentAt,
                responseTo: nil
            )
            let envelope = try FernletIdentityEnvelope.signed(
                identityService: identity,
                senderDisplayName: displayName,
                recipientFingerprint: peer.advertisedFingerprint,
                payloadType: .sessionHeartbeat,
                payloadSummary: PayloadSummary(title: "Heartbeat"),
                payload: try JSONEncoder().encode(payload),
                createdAt: sentAt,
                expiresAt: sentAt.addingTimeInterval(interval * 2)
            )
            let data = try JSONEncoder().encode(envelope)
            try await transport.send(data, to: peer, mode: .unreliable)
            pendingHeartbeatSentAtByID[heartbeatID] = sentAt
            let pruneThreshold = sentAt.addingTimeInterval(-(interval * 5))
            pendingHeartbeatSentAtByID = pendingHeartbeatSentAtByID.filter { $0.value > pruneThreshold }
            heartbeatSendFailures = 0
            recordEnvelope(envelope, direction: .sent, byteCount: data.count, signatureVerified: true)
            bytesSent += data.count
            await foregroundAnchor.update(bytesSent: bytesSent, bytesReceived: bytesReceived)
            inspector?.recordCoordinatorEvent("heartbeat sent")
        } catch {
            heartbeatSendFailures += 1
            inspector?.recordCoordinatorEvent("heartbeat send failed (\(heartbeatSendFailures))")
            if heartbeatSendFailures >= 3 {
                await end(.transportLost)
            }
        }
    }

    private func armTimeoutIfNeeded() {
        timeoutTask?.cancel()
        guard timeoutSeconds > 0 else { return }
        let timeoutSeconds = self.timeoutSeconds
        // Task inherits @MainActor from the calling context — no MainActor.run hop needed.
        timeoutTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(timeoutSeconds * 1_000_000_000))
            guard !Task.isCancelled, let self else { return }
            switch self.state {
            case .idle, .connected, .transferring, .ended, .failed:
                break
            default:
                self.transition(to: .ended(reason: .timeout))
                self.trustPolicy?.recordTrainerAudit(TrainerAuditEvent(
                    kind: .sessionEnded,
                    peerFingerprint: self.connectedIdentity?.fingerprint ?? self.pendingPeerIdentity?.fingerprint ?? self.currentTransportPeer?.advertisedFingerprint,
                    peerDisplayName: self.connectedIdentity?.displayName ?? self.pendingPeerIdentity?.displayName ?? self.currentTransportPeer?.displayName,
                    message: "timeout"
                ))
                self.inspector?.recordCoordinatorEvent("ended: timeout")
                self.inspector?.endSession(endState: "timeout")
            }
        }
    }
}

extension ProximityCoordinator {
    public enum State: Equatable {
        case idle
        case starting
        case discovering
        case peerInRange(peer: MultipeerPeer, distance: RangingDistance)
        case pendingInvite(MultipeerPendingInvite)
        case awaitingTapConfirmation(peer: MultipeerPeer)
        case awaitingIdentityIntroduction(peer: MultipeerPeer)
        case awaitingProximityCommit(peer: PeerIdentity)   // friend mode, UWB: waiting for 15 cm dwell
        case awaitingManualCommit(peer: PeerIdentity)      // friend mode, no UWB: waiting for on-screen confirm
        case awaitingUserConfirmation(peer: PeerIdentity)
        case connected(peer: PeerIdentity)
        case transferring(peer: PeerIdentity, progress: Double)
        case ended(reason: EndReason)
        case failed(reason: String)

        public var debugLabel: String {
            switch self {
            case .idle: return "idle"
            case .starting: return "starting"
            case .discovering: return "discovering"
            case .peerInRange: return "peerInRange"
            case .pendingInvite: return "pendingInvite"
            case .awaitingTapConfirmation: return "awaitingTapConfirmation"
            case .awaitingIdentityIntroduction: return "awaitingIdentityIntroduction"
            case .awaitingProximityCommit: return "awaitingProximityCommit"
            case .awaitingManualCommit: return "awaitingManualCommit"
            case .awaitingUserConfirmation: return "awaitingUserConfirmation"
            case .connected: return "connected"
            case .transferring: return "transferring"
            case .ended(let reason): return "ended(\(reason))"
            case .failed(let reason): return "failed(\(reason))"
            }
        }
    }

    public struct PeerIdentity: Equatable, Identifiable {
        public let id: UUID
        public let displayName: String
        public let signingPublicKey: Data
        public let keyAgreementPublicKey: Data
        public let fingerprint: String
        public let rangingMode: RangingMode
        public let firstSeenAt: Date
        /// Raw capability tokens the peer advertised in its identity intro/ack (Phase 1).
        /// `nil` = a legacy peer whose intro predates capability advertisement.
        public let capabilities: [String]?

        public init(
            id: UUID,
            displayName: String,
            signingPublicKey: Data,
            keyAgreementPublicKey: Data,
            fingerprint: String,
            rangingMode: RangingMode,
            firstSeenAt: Date,
            capabilities: [String]? = nil
        ) {
            self.id = id
            self.displayName = displayName
            self.signingPublicKey = signingPublicKey
            self.keyAgreementPublicKey = keyAgreementPublicKey
            self.fingerprint = fingerprint
            self.rangingMode = rangingMode
            self.firstSeenAt = firstSeenAt
            self.capabilities = capabilities
        }

        /// Phase 1 capability gate: senders skip payload kinds the peer can't use. `nil`
        /// capabilities = a legacy peer — every pre-capability friend radio could only exchange
        /// photos, so legacy is treated as photos-only.
        public func supports(_ capability: ProximityCapability) -> Bool {
            guard let capabilities else { return capability == .photos }
            return capabilities.contains(capability.rawValue)
        }
    }

    public typealias RangingMode = ProximityRangingMode

    public enum EndReason: Equatable {
        case userCancelled
        case peerCancelled
        case timeout
        case verificationFailed
        case transportLost
        case completedSuccessfully
    }

    public enum CoordinatorError: Error, Equatable {
        case notConnected
        case fingerprintMismatch
        /// A sealed-introduction connection was asked to emit an identity envelope but the expected
        /// friend KA key is missing/empty — fail-closed, never send the intro unsealed.
        case sealedIntroductionKeyMissing
    }
}
