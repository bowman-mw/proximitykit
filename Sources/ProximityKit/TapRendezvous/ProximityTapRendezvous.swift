import Combine
import Foundation
import Observation

// MARK: - ProximityTapRendezvousQuestion

/// The question a rendezvous asks once both phones tapped: "Start a hangout with Rae?".
public nonisolated struct ProximityTapRendezvousQuestion: Equatable, Sendable {
    /// The name the other person appears as, exactly as they revealed it. Untrusted display text:
    /// the host sanitizes it before drawing it.
    public let displayName: String
    /// Their companion's look, as their host encoded it.
    public let look: Data
}

/// How a rendezvous conversation ended without a match.
public nonisolated enum ProximityTapRendezvousEnd: Equatable, Sendable {
    /// This person said Not now, or left the question unanswered.
    case declinedHere
    /// The other person said Not now.
    case declinedThere
    /// The link dropped or the peer broke the protocol after the tap.
    case lost
}

// MARK: - ProximityTapRendezvous

/// Meeting someone new by tapping phones, with nothing that identifies either person sent before both
/// say yes (spec §1.5, P1 and P2).
///
/// **What goes on the air.** The pair radio's row under the profile's own TXT mode, advertising only
/// `v`, `mode` and the radio's per-posture `sid` — no name, no fingerprint, no mesh fields. The
/// radio mints a fresh Bonjour instance name, TLS identity and `sid` at every ``start()``, and this
/// engine mints fresh X25519 secrets with them, so every rotation is a new stranger to anyone
/// listening. It rotates at every start (a Home visit) and at least every
/// ``TapRendezvousFormat/rotationInterval`` while running; a rotation waits only while a question is
/// up, at most ``questionTimeout``.
///
/// **What crosses, and when** (``TapRendezvousLink``): ephemeral hellos; a sealed, fresh Nearby
/// Interaction token per link; at the tap, the name and companion; and only after both people said
/// yes, the long-term keys — the first time this engine even reaches them — signed over the
/// rendezvous transcript. ``onMatched`` then hands the host the peer it may admit.
///
/// **One link at a time** (the pair radio's single tunnel). The side with the lower `sid` dials;
/// a link that never comes within 3 m gives up after ``idleLinkTimeout`` and cools for
/// ``coolingSeconds`` so the next nearby phone gets its turn.
///
/// `@MainActor` (the module default). The host starts and stops it from its run policy only.
@Observable
public final class ProximityTapRendezvous {

    /// Whether the radio is up.
    public private(set) var isRunning = false
    /// Strength (0 far … 1 touching) of a Fernlet within 3 m, or `nil` when none is: the rings.
    public private(set) var closeness: Double?
    /// The question, once both phones tapped and revealed.
    public private(set) var question: ProximityTapRendezvousQuestion?
    /// This person said yes and the other has not answered yet.
    public private(set) var isWaitingForPeer = false

    /// This phone measured the tap (the host plays its one firm haptic).
    @ObservationIgnored public var onTap: (() -> Void)?
    /// Both said yes and the peer's card verified.
    @ObservationIgnored public var onMatched: ((ProximityTapRendezvousMatch) -> Void)?
    /// A conversation that reached the tap ended without a match.
    @ObservationIgnored public var onEnded: ((ProximityTapRendezvousEnd) -> Void)?
    /// This person's companion look, read at the tap. Empty by default.
    @ObservationIgnored public var companionLook: () -> Data = { Data() }
    /// The name this person appears as, read at the tap; `nil` reads the host's
    /// ``ProximityHost/proximityDisplayName``.
    @ObservationIgnored public var revealedName: (() -> String)?

    /// A link with no reading within 3 m for this long gives up.
    static let idleLinkTimeout: TimeInterval = 30
    /// A peer given up on, or declined, is not dialed or accepted again for this long.
    static let coolingSeconds: TimeInterval = 45
    /// An unanswered question counts as Not now after this long.
    static let questionTimeout: TimeInterval = 120
    /// Cap on browsed advertisements and cooling entries (Power of 10 rule 3).
    static let maxTracked = 32

    /// Held weakly: the host owns this engine, and an engine that outlives it does nothing.
    @ObservationIgnored private weak var host: (any ProximityHost)?
    /// The profile it advertises and signs under.
    @ObservationIgnored public nonisolated let profile: ProximityTapRendezvousProfile
    @ObservationIgnored private let radio: any ProximityPairRadioSession
    @ObservationIgnored private let makeRanging: () -> any RangingProvider
    @ObservationIgnored private let now: () -> Date
    @ObservationIgnored private let profileIsOfNamespace: Bool
    @ObservationIgnored private(set) var secrets = TapRendezvousSecrets.fresh()
    @ObservationIgnored private var discovered: [UUID: PeerHandle] = [:]
    @ObservationIgnored private var cooling: [String: Date] = [:]
    @ObservationIgnored private var active: ActiveLink?
    @ObservationIgnored private var rotationTask: Task<Void, Never>?
    @ObservationIgnored private var watchdogTask: Task<Void, Never>?
    /// How many rotations have run since construction (a start counts as one).
    @ObservationIgnored private(set) var rotations = 0

    /// A rendezvous on the host's pair radio, ranging with the host's provider.
    public convenience init(host: any ProximityHost, profile: ProximityTapRendezvousProfile) {
        self.init(host: host, profile: profile, makeRadio: nil, makeRanging: nil, now: Date.init)
    }

    /// The seam a unit test builds through: a radio and ranging of its own, and a clock.
    init(
        host: any ProximityHost,
        profile: ProximityTapRendezvousProfile,
        makeRadio: (() -> any ProximityPairRadioSession)?,
        makeRanging: (() -> any RangingProvider)?,
        now: @escaping () -> Date
    ) {
        self.host = host
        self.profile = profile
        self.now = now
        self.profileIsOfNamespace = ProximityPairSession.check(profile.pair, isOf: host.proximityNamespace)
        self.radio = makeRadio?() ?? NetworkPairSession(namespace: host.proximityNamespace, profile: profile.pair)
        self.makeRanging = makeRanging ?? { [weak host] in host?.makeProximityRangingProvider() ?? NoopRangingProvider() }
        wireRadio()
    }

    deinit {
        rotationTask?.cancel()
        watchdogTask?.cancel()
    }

    // MARK: Lifecycle

    /// Brings the radio up under fresh secrets. A no-op while running.
    public func start() {
        guard !isRunning else { return }
        guard profileIsOfNamespace else {
            ProximityAudit.log("\(profile.pair.auditArea).profile.namespaceMismatch", context: ["at": "start"])
            return
        }
        isRunning = true
        bringUp()
    }

    /// Stands everything down and forgets every secret, peer and question.
    public func stop() {
        guard isRunning else { return }
        isRunning = false
        tearDown()
        rotationTask?.cancel()
        rotationTask = nil
        watchdogTask?.cancel()
        watchdogTask = nil
        cooling.removeAll()
    }

    /// The person's answer to ``question``.
    public func answer(_ yes: Bool) {
        guard let active, question != nil else { return }
        let identity = yes ? longTermIdentity() : nil
        guard !yes || identity != nil else {
            apply(active.link.answer(false, identity: nil), to: active)
            return
        }
        question = nil
        isWaitingForPeer = yes
        apply(active.link.answer(yes, identity: identity), to: active)
    }

    /// Drops this rotation's posture, secrets and peers and comes back up as a stranger.
    func rotate() {
        guard isRunning else { return }
        if let active, active.link.isInConversation, now().timeIntervalSince(active.tappedAt ?? now()) < Self.questionTimeout {
            armRotation(after: 5)
            return
        }
        tearDown()
        bringUp()
    }

    private func bringUp() {
        secrets = .fresh()
        rotations += 1
        do {
            try radio.start(advertisement: [
                ProximityPairAdvertisement.versionKey: ProximityPairAdvertisement.version,
                ProximityPairAdvertisement.modeKey: profile.pair.advertisementMode
            ])
        } catch {
            ProximityAudit.log("\(profile.pair.auditArea).radioDidNotStart", context: ["error": "\(error)"])
            isRunning = false
            return
        }
        armRotation(after: TapRendezvousFormat.rotationInterval)
        armWatchdog()
    }

    private func tearDown() {
        if let active { end(active, reason: nil) }
        radio.stop()
        discovered.removeAll()
        closeness = nil
        question = nil
        isWaitingForPeer = false
    }

    private func armRotation(after seconds: TimeInterval) {
        rotationTask?.cancel()
        rotationTask = Task { @MainActor [weak self] in
            do {
                try await Task.sleep(for: .seconds(seconds))
            } catch {
                return   // cancelled: a stop or a newer rotation owns the clock
            }
            self?.rotate()
        }
    }

    /// Every five seconds: give up an idle link, time out a question, and dial the next peer.
    private func armWatchdog() {
        watchdogTask?.cancel()
        watchdogTask = Task { @MainActor [weak self] in
            // R2: bounded by cancellation; stop() and every rotation cancel it.
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: .seconds(5))
                } catch {
                    return   // cancelled by stop() or a rotation
                }
                self?.sweep()
            }
        }
    }

    /// The watchdog's one pass (also a test seam).
    func sweep() {
        let date = now()
        cooling = cooling.filter { $0.value > date }
        if let active {
            if let tappedAt = active.tappedAt, question != nil, date.timeIntervalSince(tappedAt) >= Self.questionTimeout {
                answer(false)
            } else if !active.link.hasTapped, date.timeIntervalSince(active.lastCloseAt) >= Self.idleLinkTimeout {
                end(active, reason: nil)
            }
        }
        dialNextIfIdle()
    }

    // MARK: Radio

    private func wireRadio() {
        radio.onPeerDiscovered = { [weak self] peer in self?.handleDiscovered(peer) }
        radio.onPeerLost = { [weak self] peer in self?.handleLost(peer) }
        radio.onPeerChannelReady = { [weak self] channel in self?.handleChannelReady(channel) }
        radio.onPeerDisconnected = { [weak self] peer, _ in self?.handleLost(peer) }
        radio.resolveDialer = { [weak self] sessionID in self?.peer(advertising: sessionID) }
        radio.shouldAcceptDialer = { [weak self] peer in self?.mayAccept(peer) ?? false }
        radio.onTransportError = { [weak self] message in
            guard let self else { return }
            ProximityAudit.log("\(self.profile.pair.auditArea).radioFailed", context: ["error": message])
            self.stop()
        }
    }

    private func sessionID(of peer: PeerHandle) -> String? {
        ProximityPairAdvertisement.sessionID(from: peer.discoveryInfo, mode: profile.pair.advertisementMode)
    }

    private func handleDiscovered(_ peer: PeerHandle) {
        guard isRunning, let sid = sessionID(of: peer), sid != radio.advertisedSessionID,
              discovered[peer.id] != nil || discovered.count < Self.maxTracked else { return }
        discovered[peer.id] = peer
        dialNextIfIdle()
    }

    private func handleLost(_ peer: PeerHandle) {
        discovered.removeValue(forKey: peer.id)
        guard let active, active.peer.isSameEndpoint(as: peer) else { return }
        end(active, reason: active.link.hasTapped ? .lost : nil)
    }

    private func peer(advertising sessionID: String) -> PeerHandle? {
        guard !sessionID.isEmpty else { return nil }
        return discovered.values.first { self.sessionID(of: $0) == sessionID }
    }

    private func isCooling(_ sid: String) -> Bool {
        (cooling[sid] ?? .distantPast) > now()
    }

    private func mayAccept(_ peer: PeerHandle) -> Bool {
        guard isRunning, active == nil, let sid = sessionID(of: peer), !isCooling(sid) else { return false }
        return !radio.hasConnectingPeers(besides: peer)
    }

    /// The lower `sid` dials, so two phones that see each other open one tunnel, not two.
    private func dialNextIfIdle() {
        guard isRunning, active == nil, !radio.hasConnectingPeers(besides: nil) else { return }
        let own = radio.advertisedSessionID
        guard !own.isEmpty else { return }
        let next = discovered.values
            .compactMap { peer in sessionID(of: peer).map { (peer, $0) } }
            .filter { own < $0.1 && !isCooling($0.1) }
            .min { $0.1 < $1.1 }
        guard let next else { return }
        radio.dial(next.0, helloSID: own)
    }

    private func handleChannelReady(_ channel: NetworkPeerChannel) {
        guard isRunning, active == nil, let sid = sessionID(of: channel.peer) ?? discoveredSID(for: channel.peer) else {
            radio.endTunnel(channel.peer)
            return
        }
        let entry = ActiveLink(
            peer: channel.peer, channel: channel, ranging: makeRanging(), sessionID: sid,
            link: TapRendezvousLink(secrets: secrets, profile: profile), openedAt: now()
        )
        active = entry
        subscribe(entry)
        channel.notifyConnected()
        apply(entry.link.begin(), to: entry)
        let ranging = entry.ranging
        Task { @MainActor [weak self, weak entry] in
            guard let token = try? await ranging.myDiscoveryToken(), let self, let entry, self.active === entry else { return }
            self.apply(entry.link.setLocalRangingToken(token), to: entry)
        }
    }

    private func discoveredSID(for peer: PeerHandle) -> String? {
        discovered.values.first { $0.isSameEndpoint(as: peer) }.flatMap(sessionID(of:))
    }

    private func subscribe(_ entry: ActiveLink) {
        entry.channel.inbound
            .sink { [weak self, weak entry] frame in
                Task { @MainActor [weak self, weak entry] in
                    guard let self, let entry, self.active === entry else { return }
                    self.apply(entry.link.receive(frame.data), to: entry)
                }
            }
            .store(in: &entry.cancellables)
        entry.ranging.distance
            .sink { [weak self, weak entry] distance in
                Task { @MainActor [weak self, weak entry] in
                    guard let self, let entry, self.active === entry, case .meters(let meters, _) = distance else { return }
                    self.handleDistance(meters, on: entry)
                }
            }
            .store(in: &entry.cancellables)
    }

    private func handleDistance(_ meters: Double, on entry: ActiveLink) {
        let date = now()
        if meters <= TapRendezvousFormat.closeDistanceMeters { entry.lastCloseAt = date }
        let look = companionLook()
        let name = revealedName?() ?? host?.proximityDisplayName ?? ""
        apply(entry.link.distance(meters, at: date) { (name, look) }, to: entry)
    }

    // MARK: Outputs

    private func apply(_ outputs: [TapRendezvousLinkOutput], to entry: ActiveLink) {
        // R2: bounded by one link step's outputs (at most five).
        for output in outputs {
            guard active === entry else { return }
            perform(output, on: entry)
        }
    }

    private func perform(_ output: TapRendezvousLinkOutput, on entry: ActiveLink) {
        switch output {
        case .send(let bytes):
            let channel = entry.channel
            let peer = entry.peer
            Task { @MainActor [weak self, weak entry] in
                do {
                    try await channel.send(bytes, to: peer, mode: .reliable)
                } catch {
                    guard let self, let entry, self.active === entry else { return }
                    self.end(entry, reason: entry.link.hasTapped ? .lost : nil)
                }
            }
        case .startRanging(let token):
            let ranging = entry.ranging
            let area = profile.pair.auditArea
            Task { @MainActor in
                do {
                    try await ranging.start(with: token)
                } catch {
                    // A phone without UWB, or a token NI refused: no rings, and no tap, on this link.
                    ProximityAudit.log("\(area).ranging.didNotStart", context: ["error": "\(error)"])
                }
            }
        case .close(let strength):
            closeness = strength
        case .notClose:
            closeness = nil
        case .tapped:
            entry.tappedAt = now()
            onTap?()
        case .ask(let name, let look):
            question = ProximityTapRendezvousQuestion(displayName: name, look: look)
        case .matched(let match):
            end(entry, reason: nil)
            guard let host, !host.isBlockedFingerprint(match.fingerprint) else { return }
            onMatched?(match)
        case .end(let reason):
            end(entry, reason: Self.publicEnd(reason))
        }
    }

    private static func publicEnd(_ reason: TapRendezvousLinkEnd) -> ProximityTapRendezvousEnd {
        switch reason {
        case .declinedHere: return .declinedHere
        case .declinedThere: return .declinedThere
        case .refused: return .lost
        }
    }

    /// Ends `entry`: stops its ranging, ends its tunnel, cools its peer and clears what it drew.
    private func end(_ entry: ActiveLink, reason: ProximityTapRendezvousEnd?) {
        guard active === entry else { return }
        active = nil
        entry.cancellables.removeAll()
        let ranging = entry.ranging
        Task { @MainActor in await ranging.stop() }
        radio.endTunnel(entry.peer)
        if cooling.count < Self.maxTracked { cooling[entry.sessionID] = now().addingTimeInterval(Self.coolingSeconds) }
        closeness = nil
        question = nil
        isWaitingForPeer = false
        if let reason, entry.link.hasTapped { onEnded?(reason) }
    }

    private func longTermIdentity() -> TapRendezvousLongTermIdentity? {
        guard let host else { return nil }
        let identity = host.makeProximityIdentity()
        do {
            try identity.ensureProvisioned()
        } catch {
            ProximityAudit.log("\(profile.pair.auditArea).identity.provisionFailed", context: ["error": "\(error)"])
            return nil
        }
        let purpose = profile.cardSignature
        return TapRendezvousLongTermIdentity(
            signingKey: identity.localSigningPublicKey,
            keyAgreementKey: identity.localKeyAgreementPublicKey,
            sign: { try identity.sign($0, purpose: purpose) }
        )
    }

    // MARK: Test seams

    /// What the radio was last started advertising, for the rotation and hygiene cells.
    var advertisedSessionIDForTesting: String { radio.advertisedSessionID }
}

// MARK: - ActiveLink

/// The one live link: its tunnel, its ranging and its state machine.
private final class ActiveLink {
    let peer: PeerHandle
    let channel: NetworkPeerChannel
    let ranging: any RangingProvider
    let sessionID: String
    var link: TapRendezvousLink
    var cancellables: Set<AnyCancellable> = []
    var lastCloseAt: Date
    var tappedAt: Date?

    init(
        peer: PeerHandle, channel: NetworkPeerChannel, ranging: any RangingProvider, sessionID: String,
        link: TapRendezvousLink, openedAt: Date
    ) {
        self.peer = peer
        self.channel = channel
        self.ranging = ranging
        self.sessionID = sessionID
        self.link = link
        self.lastCloseAt = openedAt
    }
}
