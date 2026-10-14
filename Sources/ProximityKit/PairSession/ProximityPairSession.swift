import Foundation
import Observation

/// What makes one kind of one-to-one connection itself: the radio it runs on, the TXT `mode` value
/// it advertises and believes, and the area its own audit events go under.
///
/// A host builds one per kind of connection from its own namespace (Fernlet's recipe profile is
/// FernletConnections' `ProximityPairProfile.recipeShare(in:)`). Every field is a token: never
/// localized, never shown. A ``ProximityPairSession`` checks its profile against its host's namespace
/// once, at construction, and refuses one that is not of it (see
/// ``ProximityPairSession/init(host:profile:)``), so namespace soundness still covers every value the
/// radio runs on.
public nonisolated struct ProximityPairProfile: Hashable, Sendable {
    /// The area of the session's own audit events: `<auditArea>.identity.namespaceMismatch`,
    /// `<auditArea>.identity.provisionFailed` and `<auditArea>.profile.namespaceMismatch`.
    public let auditArea: String
    /// The radio the session listens, browses and dials on: one of its host namespace's pair-session
    /// radios (`family.radios.pair`), which namespace soundness vets. The session checks it at
    /// construction: a profile naming any other radio is refused (see
    /// ``ProximityPairSession/init(host:profile:)``). The host lists the service type under
    /// `NSBonjourServices`, or discovery dies on device with no log.
    public let radio: ProximityNamespace.Radio
    /// The TXT record's `mode` value: advertised beside `v`, `sid` and `name`; a browsed record is
    /// believed only when it carries it. Non-empty and at most 64 UTF-8 bytes (the advertisement's
    /// field bound), or the session refuses the profile.
    public let advertisementMode: String

    /// A profile.
    ///
    /// - Parameters:
    ///   - auditArea: The area of the session's own audit events.
    ///   - radio: The pair-session radio of the host's namespace the session runs on.
    ///   - advertisementMode: The TXT record's `mode` value.
    public init(auditArea: String, radio: ProximityNamespace.Radio, advertisementMode: String) {
        self.auditArea = auditArea
        self.radio = radio
        self.advertisementMode = advertisementMode
    }
}

/// A nearby device a pair session can send to, as a picker row (Fernlet's recipe share sheet lists
/// them).
///
/// `id` is the discovered peer's handle id; `fingerprint` stays nil until the pairing's identity
/// introduction verifies, after which the row carries the verified fingerprint and, when the peer
/// disclosed one, its name.
public struct ProximityPairPeer: Identifiable, Equatable {
    /// The discovered peer's handle id: what a send names and what ``ProximityPairSendOutcome``
    /// reports back as its `recipientID`.
    public var id: UUID
    /// The name the row shows: the name the device advertised, or, once its introduction verifies,
    /// the name it disclosed there. A row the radio never discovered (an inbound pairing's) whose peer
    /// withheld its name is filed under its verified fingerprint.
    public var displayName: String
    /// The verified signing-key fingerprint, nil until the identity introduction completes.
    public var fingerprint: String?

    /// A row.
    public init(id: UUID, displayName: String, fingerprint: String?) {
        self.id = id
        self.displayName = displayName
        self.fingerprint = fingerprint
    }
}

/// One live pairing: the peer, its channel + coordinator, and (once the handshake completes) the
/// verified fingerprint and KA key.
///
/// Under the hard 2-device cap the session holds at most one of these at a time.
private struct PairConnection: Identifiable {
    let id: UUID
    let peer: PeerHandle
    let channel: NetworkPeerChannel
    let coordinator: ProximityCoordinator
    /// The host's trust policy for this pairing (`ProximityHost.makeProximityTrustPolicy()`),
    /// retained for the connection's lifetime so the coordinator's `weak` trustPolicy stays alive —
    /// otherwise the revoked/blocked-key envelope rejection + audit calls silently no-op (they would
    /// evaluate `nil?.isRevokedProximitySigningKey(...) == true` → false, and every recordSessionAudit
    /// becomes a no-op). Mirrors MeshNetworkManager's `slotTrustPolicies` and the heart manager's
    /// HeartShareConnection.
    let trustPolicy: any ProximityTrustPolicy
    var fingerprint: String?
    var verifiedKeyAgreementPublicKey: Data?
}

/// The send the user is making, as its outcome will name it: the row they tapped, the send's
/// subject, the ``ProximityPairTransfer`` token it was minted under, and whether its pairing ever came
/// up.
///
/// Kept beside the transfer record rather than inside it because the record is a pure, identity-free
/// state machine and this is display context. `pairingSeen` is what lets a connection-record
/// eviction fail THIS send as `couldNotConnect` without failing a send whose dial is still
/// legitimately in flight. It is set when a connection record for this recipient's device is
/// registered, or already exists when the send is minted.
private struct LiveSend {
    let recipient: ProximityPairPeer
    let subject: String
    let token: UUID
    var pairingSeen: Bool
}

/// A one-to-one connection between two devices, driven by a ``ProximityPairProfile``: discovery on
/// the profile's radio, at most one verified pairing at a time, and sealed, signed payloads over it.
///
/// It owns its radio (a ``ProximityPairRadioSession``, the QUIC ``NetworkPairSession`` in
/// production, on the profile's row), this device's ``IdentityService`` cache and a ``ReplayCache``.
/// Each pairing is a ``ProximityCoordinator`` over the host's ranging provider and a trust policy the
/// session retains for the pairing's life, ``ProximityHost/makeProximityTrustPolicy()`` (the
/// coordinator's trust ref is `weak` — dropping the retention silently disables the revoked/blocked
/// drops), begun in friend mode as the browser on both ends and committed at the proximity gate
/// without a user step; its verified payloads go to ``payloadHandler``. The hard 2-device cap is
/// enforced at four layers: the inbound dialer gate, the outbound send guard, the connecting-window
/// check, and the belt-and-braces channel admission — with the radio PAUSED while paired
/// (`pauseDiscovery`) and reopened, under a freshly minted posture, only on session-level record
/// eviction, never on a transport disconnect event (a failed handshake fires none). That pause/resume
/// contract and the send pipeline's state machine are tier-1 values (``ProximityPairDiscoveryGate``,
/// ``ProximityPairTransfer``), and the radio is bound to those tables rather than to a reading of
/// two guard chains.
/// Timeouts: a 12 s pre-connect timer (the peer-is-busy case), the coordinator's 25 s handshake
/// budget, a 30 s sweep of pairings stalled before verification, and a 2.5 s clear of a terminal
/// status.
///
/// Every send ends in exactly one ``lastSendOutcome`` (``ProximityPairSendOutcome``): `sent`, or
/// `notSent` with a frozen ``ProximityPairSendFailure``, including a pairing that came up and died
/// before the send (`couldNotConnect`) and a teardown that cut a send off (`interrupted` /
/// `sendIncomplete`). **Sent is not received**: `sent` means the sealed payload was handed to the
/// transport, and nothing ever comes back from the other device, so no outcome here can say
/// "delivered", "accepted" or "saved".
///
/// The session composes no copy: its ``status`` is typed, and what it does that a person might be
/// shown is an ``Event``, in order, through ``onEvent``, for its owner to render (Fernlet's recipe
/// share renders both in FernletSocial).
///
/// `@MainActor @Observable`. The host is held `unowned` (it owns the session's owner); every detached
/// task pins it for its own lifetime.
@MainActor
@Observable
public final class ProximityPairSession {

    /// The send pipeline's status line, typed. Display state, not a record: a terminal value returns
    /// to ``Status/idle`` 2.5 s later (`scheduleStatusClear`). A surface that must stay up reads
    /// ``lastSendOutcome``.
    public nonisolated enum Status: Equatable, Sendable {
        /// Between sends.
        case idle
        /// A send has begun and has not started sending yet: its pairing may still be connecting or
        /// verifying, or may already be verified, its send about to start; the picked row's name.
        case connecting(recipientName: String)
        /// The verified pairing is sending the payload; the picked row's name.
        case sending(recipientName: String)
        /// The sealed payload was handed to the transport (never "delivered"); the picked row's name.
        case sent(recipientName: String)
        /// The send, or a search, was refused or failed, for the given reason.
        case failed(Failure)

        /// Why the status line shows a failure.
        public nonisolated enum Failure: Equatable, Sendable {
            /// A search restart refused while paired; the name of the device holding the pairing.
            case searchRefusedWhilePaired(pairedWith: String)
            /// The picked row's device was no longer discoverable.
            case recipientUnavailable
            /// A connection attempt to another device was in flight.
            case connectingToAnother
            /// A send refused while paired with another device; that device's name.
            case pairedWithAnother(pairedWith: String)
            /// The pre-connect timer ran out; the picked row's name.
            case noAnswer(recipientName: String)
            /// The pairing came up and ended before the send; the picked row's name.
            case couldNotConnect(recipientName: String)
            /// A second send of one record was refused.
            case duplicateSend
            /// The send threw.
            case sendFailed
        }
    }

    /// What the session did, refused or saw, for its owner's diagnostics, emitted through
    /// ``ProximityPairSession/onEvent`` in the order it acts: each case carries only names the user
    /// already saw (a picker row's, a send's subject) or, for a radio failure, the radio's own
    /// diagnostic text, and no copy. An owner renders every case: a new one is a build error in an
    /// exhaustive renderer until it has its sentence.
    public nonisolated enum Event: Equatable, Sendable {
        /// `start()` brought the radio up (emitted before the radio's start).
        case discoveryStarted
        /// `stop()` stood a running radio down.
        case discoveryStopped
        /// `refreshDiscovery()` restarted the search.
        case discoveryRefreshed
        /// A start failure stood the radio down; the run-policy seam retries on its next run.
        case listeningWillRetry
        /// The radio's `start(advertisement:)` threw; the error, as `"\(error)"` spells it.
        case radioDidNotStart(error: String)
        /// The radio reported a start failure; its own message, verbatim.
        case radioFailed(message: String)
        /// A search restart refused while paired; the name of the device holding the pairing.
        case searchSkippedWhilePaired(pairedWith: String)
        /// A send began; the picked row's name.
        case connecting(recipientName: String)
        /// The picked row's device was no longer discoverable; its name.
        case recipientUnavailable(recipientName: String)
        /// A send refused while a connection to another device was in flight; the picked row's name.
        case connectingToAnother(recipientName: String)
        /// A send refused while paired with another device; the picked row's name and that device's.
        case sendRefusedWhilePaired(recipientName: String, pairedWith: String)
        /// The pre-connect timer ran out; the picked row's name.
        case noAnswer(recipientName: String)
        /// The pairing came up and ended before the send; the picked row's name.
        case couldNotConnect(recipientName: String)
        /// The verified pairing began the send; the send's subject and the picked row's name.
        case sending(subject: String, recipientName: String)
        /// A second send of one record was refused; the send's subject.
        case duplicateSendRefused(subject: String)
        /// A send completed against a newer send record, so its completion was not counted.
        case completionNotCounted
        /// The sealed payload was handed to the transport; the send's subject and the row's name.
        case sent(subject: String, recipientName: String)
        /// The send threw; the picked row's name.
        case sendFailed(recipientName: String)
        /// An outcome arrived for a superseded send and was not shown.
        case outcomeSuperseded
        /// The radio discovered a device; the name its row shows.
        case discovered(name: String)
        /// A discovered device went away; the name its row showed.
        case lost(name: String)
        /// The radio reported a device's disconnect; the device's name.
        case disconnected(name: String)
        /// A third device's channel was refused under the two-device cap; its name.
        case turnedAway(name: String)
        /// A channel was admitted and its pairing begins; the device's name.
        case channelOpened(name: String)
        /// A pairing was registered and discovery closed; the paired device's name.
        case closedToOthers(pairedWith: String)
        /// A pairing reached the proximity gate and is being committed.
        case confirming
        /// A pairing's identity verified; the verified name, or the fingerprint when none was disclosed.
        case verified(name: String)
        /// The last pairing's record was evicted and discovery reopened.
        case reopened
        /// A pairing stalled before verification was dropped by the sweep; the device's name.
        case droppedStalled(name: String)
    }

    /// One payload for the session to deliver to a picked peer, sealed to the verified peer and
    /// signed: what the owner hands ``ProximityPairSession/send(_:to:)``.
    public struct Outgoing {
        /// The envelope's payload token, from the host's vocabulary (`payloads.known`).
        public let payloadTypeToken: String
        /// The envelope's summary: frozen literals, signed into the canonical bytes and shown in the
        /// receiving device's inspector. Never localized.
        public let summary: PayloadSummary
        /// What the send is of, as the user picked it (a recipe's title): it names the send in
        /// ``ProximityPairSession/lastSendOutcome`` and in ``ProximityPairSession/Event``s. Never sent.
        public let subject: String
        /// The payload's bytes, produced once, when the pairing has verified and the send begins; a
        /// throw ends the send as `interrupted`, as a send that failed before it began.
        public let encode: () throws -> Data

        /// A send.
        ///
        /// - Parameters:
        ///   - payloadTypeToken: The envelope's payload token.
        ///   - summary: The envelope's summary, frozen literals.
        ///   - subject: What the send is of, in the owner's words.
        ///   - encode: Produces the payload's bytes when the send begins.
        public init(
            payloadTypeToken: String, summary: PayloadSummary, subject: String,
            encode: @escaping () throws -> Data
        ) {
            self.payloadTypeToken = payloadTypeToken
            self.summary = summary
            self.subject = subject
            self.encode = encode
        }
    }

    /// The picker's rows: every nearby device the radio discovered, sorted by name, each re-filed
    /// under its verified fingerprint (and the name it disclosed, if it disclosed one) once its
    /// pairing verifies; and every device whose pairing verified though the radio never discovered it
    /// (an inbound pairing), added when it verifies, named as it disclosed or, when it withheld its
    /// name, by its verified fingerprint.
    public private(set) var nearbyPeers: [ProximityPairPeer] = []
    /// The send pipeline's status line, typed (see ``Status``); its owner renders it.
    public private(set) var status: Status = .idle
    /// How the most recent send ended — the value an owner's confirmation is built from.
    ///
    /// Published exactly once per send, at its terminal moment, through `finishShare(_:token:)`
    /// (or directly, for the outbound-cap refusal that happens before a send is minted). Unlike
    /// ``status`` it is never auto-cleared, carries a frozen cause, and gets a fresh
    /// ``ProximityPairSendOutcome/id`` every time. Cleared at the start of each send and by
    /// ``wipeIdentityForDeleteAll()``. A teardown (`stop()`, a search restart) that ends a send
    /// still in flight publishes `interrupted` or `sendIncomplete` here, so an observer that was
    /// NOT waiting on that send (a sheet that is itself closing) must ignore it.
    public private(set) var lastSendOutcome: ProximityPairSendOutcome?
    /// The peer this session is currently engaged with — connecting to, sending to, or holding the
    /// (hard-capped, one-at-a-time) verified connection with. A picker disables every other row
    /// while this is set; nil when idle.
    public private(set) var engagedPeerID: UUID?

    @ObservationIgnored private unowned let store: any ProximityHost
    /// The host's protocol identity, read once from ``store`` at construction and kept as this
    /// session's own copy, so no later read reaches back to the host. The default identity, the
    /// host's ``ProximityHost/makeProximityIdentity()``, is checked against it, and so is
    /// ``profile``; the radio reads its instance-name prefix, TLS common name, log subsystem and
    /// soundness verdict off it. `nonisolated`: inert `Sendable` value data.
    @ObservationIgnored public nonisolated let namespace: ProximityNamespace
    /// The kind of connection this session is: the radio it runs on, the TXT mode it advertises and
    /// believes, and its audit events' area. Checked against ``namespace`` at construction.
    @ObservationIgnored public nonisolated let profile: ProximityPairProfile
    /// Called once per ``Event``, synchronously, in the order the session acts. Set it once, before
    /// ``start()``, capturing the owner weakly: the owner holds the session.
    @ObservationIgnored public var onEvent: ((Event) -> Void)?
    /// Receives the verified payloads the session's pairings deliver: every pairing's coordinator is
    /// built with it. Held weakly; set it once, before ``start()``.
    @ObservationIgnored public weak var payloadHandler: (any ProximityPayloadHandling)?
    /// The radio this session drives. Built once, at construction, because several of this
    /// session's decisions (the inbound gate, the pause flag, a discovery callback) are reachable
    /// before `start()` ever runs — which is also what lets a unit test hand in an in-memory
    /// conformer through the init seam and exercise them with no Bonjour anywhere.
    @ObservationIgnored private let session: any ProximityPairRadioSession
    @ObservationIgnored private let identity: IdentityService
    /// Whether ``identity`` is of ``namespace``, decided once at `init`. False only when the identity
    /// this session holds, handed in through the `identity:` seam or answered by the host's
    /// ``ProximityHost/makeProximityIdentity()``, is of another namespace: the session still
    /// constructs, as it does when provisioning fails, and ``start()`` refuses every start of the radio
    /// (`<auditArea>.identity.namespaceMismatch`), so nothing is advertised under two namespaces.
    @ObservationIgnored private let identityIsOfNamespace: Bool
    /// Whether ``profile`` is of ``namespace`` (``check(_:isOf:)``), decided once at `init`. False
    /// only when a host's profile names a radio that is not one of its namespace's pair-session rows,
    /// or a TXT mode the advertisement could not publish: the session still constructs, and
    /// ``start()`` refuses every start of the radio (`<auditArea>.profile.namespaceMismatch`), so no
    /// radio runs on a row namespace soundness never vetted.
    @ObservationIgnored private let profileIsOfNamespace: Bool
    @ObservationIgnored private let replayCache = ReplayCache()
    @ObservationIgnored private var connections: [PairConnection] = []
    @ObservationIgnored private var discoveredPeers: [UUID: PeerHandle] = [:]
    @ObservationIgnored private var observationTask: Task<Void, Never>?
    @ObservationIgnored private var clearStatusTask: Task<Void, Never>?
    @ObservationIgnored private var connectTimeoutTask: Task<Void, Never>?
    @ObservationIgnored private var parkedSweepTask: Task<Void, Never>?
    @ObservationIgnored private var parkedSince: [UUID: Date] = [:]
    @ObservationIgnored private var pendingOutgoing: (outgoing: Outgoing, recipient: ProximityPairPeer)?
    /// The send the user is currently making, as ``ProximityPairTransfer`` records it — the exchange's
    /// state machine, alongside `status`'s display state rather than instead of it. Minted in
    /// `send(_:to:)`, cleared by `stop()`/`refreshDiscovery()`. Its one production effect is the
    /// once-only send start in `sendPendingPayload`.
    @ObservationIgnored private var transfer: ProximityPairTransfer?
    /// What ``lastSendOutcome`` will name for the send in flight, minted beside ``transfer`` and
    /// cleared the moment that send's outcome is published or discarded.
    @ObservationIgnored private var liveShare: LiveSend?
    @ObservationIgnored private var isRunning = false
    private var connectionObservationRevision = 0

    /// How long a coordinator may sit in a pre-verification state (.idle/.starting/
    /// .discovering/.peerInRange) before its connection record is force-evicted. The
    /// coordinator's own handshake timeout is 25 s; this is that plus slack, so the parked
    /// sweep only ever catches records the coordinator's timeout can no longer convert to
    /// .ended (the friend-mode auto-reconnect path re-parks in .discovering).
    private static let parkedConnectionTimeoutSeconds: TimeInterval = 30
    private static let parkedSweepIntervalSeconds: TimeInterval = 5
    /// Sender-side connect timeout (mesh redesign Phase 3b): under a hard 2-device cap,
    /// "the other Fernlet is already paired and ignoring invites" is the COMMON failure, and
    /// without this it looked like an eternal "Connecting…". Scoped to the PRE-CONNECT stage
    /// only — it is cancelled the moment the connection record exists (`registerConnection`,
    /// fired by handleChannelReady): from there the coordinator's own 25 s handshake budget
    /// governs, and letting this shorter timer keep running would best-effort kick a pairing
    /// that is still progressing. Internal (not private) so tests can shorten it.
    @ObservationIgnored var connectTimeoutSeconds: TimeInterval = 12

    /// A session for `host` under `profile`. Builds the radio and starts nothing.
    ///
    /// The identity is the host's ``ProximityHost/makeProximityIdentity()``; one of another
    /// namespace is refused: the session constructs, audits `<auditArea>.identity.namespaceMismatch`,
    /// and never starts its radio. A profile that is not of `host.proximityNamespace` (its radio is
    /// not one of the namespace's pair-session rows, or its `advertisementMode` is empty or over 64
    /// UTF-8 bytes) is refused the same way, under `<auditArea>.profile.namespaceMismatch`: written
    /// once at `construction` and at every refused start.
    public convenience init(host: any ProximityHost, profile: ProximityPairProfile) {
        self.init(host: host, profile: profile, makeRadio: nil)
    }

    /// The seam a unit test builds this session through: `makeRadio` supplies the radio.
    ///
    /// The production default is the QUIC radio on the profile's row and nothing in shipping code
    /// passes a factory — the counterpart of ``ProximityPresenceSession``'s internal `makeRadio` for a
    /// session that owns its radio from construction rather than from `start()`. It is an **optional
    /// closure resolved in the body** rather than a default argument because `NetworkPairSession` is
    /// `@MainActor` and a main-actor type cannot be a default-argument value.
    ///
    /// `identity` is the same seam `PresenceManager` and `MeshNetworkManager` already take (owner-calls
    /// item 4c, 2026-09-22): nil is this device's own identity, the host's
    /// ``ProximityHost/makeProximityIdentity()``, under its ``ProximityHost/proximityNamespace`` on its
    /// production keychain service, and a test passes one on a service of its own. Without it a test
    /// that exercised ``wipeIdentityForDeleteAll()`` would have wiped the TEST HOST's real identity —
    /// the test bundle runs inside the app on that Simulator and shares its keychain — so the wipe's
    /// EFFECT was untestable here and only its existence was pinned. An identity of another namespace
    /// than the host's is refused: the session constructs, audits
    /// `<auditArea>.identity.namespaceMismatch` and never starts its radio; so is a profile that is not
    /// of the host's namespace, under `<auditArea>.profile.namespaceMismatch`.
    init(
        host store: any ProximityHost,
        profile: ProximityPairProfile,
        makeRadio: (() -> any ProximityPairRadioSession)?,
        identity injected: IdentityService? = nil
    ) {
        self.store = store
        let namespace = store.proximityNamespace
        self.namespace = namespace
        self.profile = profile
        self.profileIsOfNamespace = Self.check(profile, isOf: namespace)
        self.session = makeRadio?() ?? NetworkPairSession(namespace: namespace, profile: profile)
        let id = injected ?? store.makeProximityIdentity()
        self.identityIsOfNamespace = ProximityNamespaceGate.checkIdentity(
            id, isOf: namespace, event: "\(profile.auditArea).identity.namespaceMismatch")
        do {
            try id.ensureProvisioned()
        } catch {
            // Benign: every session start re-attempts provisioning and fails visibly
            // (`fail(error.localizedDescription)`) — but the FIRST failure must not vanish.
            ProximityAudit.log("\(profile.auditArea).identity.provisionFailed",
                               context: ["error": String(describing: error)])
        }
        self.identity = id
        setupSession()
    }

    /// Whether `profile` is of `namespace`: its radio is one of the namespace's pair-session rows
    /// (`family.radios.pair`), and its TXT mode is non-empty and within the advertisement's
    /// field bound. On `false` it writes `<auditArea>.profile.namespaceMismatch` at `construction`,
    /// the identity check's line shape.
    static func check(_ profile: ProximityPairProfile, isOf namespace: ProximityNamespace) -> Bool {
        let isOf = profile.radio == namespace.family.radios.pair
            && !profile.advertisementMode.isEmpty
            && profile.advertisementMode.utf8.count <= MeshLinkAdvertisement.maxFieldValueLength
        if !isOf {
            ProximityAudit.log("\(profile.auditArea).profile.namespaceMismatch",
                               context: ["at": ProximityNamespaceGate.Site.construction.rawValue])
        }
        return isOf
    }

    /// Delete-all seam (Docs/PrivacyWipeCoverage.md): clears THIS instance's in-memory identity
    /// key cache; keychain rows are shared with the mesh/presence instances (idempotent).
    ///
    /// Also drops the last send's outcome and the live send's context first, whatever the
    /// keychain answers, so no subject or peer name outlives the wipe in memory.
    public func wipeIdentityForDeleteAll() throws {
        lastSendOutcome = nil
        liveShare = nil
        try identity.wipe()
    }

    /// Ends every long-running task the session owns if it is released without `stop()` (the
    /// production instance never is — process-lifetime on the store — but tasks must not outlive
    /// their owner: the observation loop would stay parked, the timers spin one more tick).
    /// `isolated`: the handles are main-actor state.
    isolated deinit {
        observationTask?.cancel()
        clearStatusTask?.cancel()
        connectTimeoutTask?.cancel()
        parkedSweepTask?.cancel()
    }

    /// Whether the listener is up right now — the radio's own account, not the last verdict the
    /// run policy applied to it. The seam (`ProximityRunTransition`) reads it to re-apply a verdict
    /// the radio no longer matches: after a `didNotStart*` self-stop, `start()` is owed even
    /// though the verdict never moved (P8 item 0, device finding (b)).
    public var isListening: Bool { isRunning }

    /// Brings the radio up, advertising the profile's mode and this device's display name; idempotent.
    ///
    /// Refused first, writing its audit line every time, when the identity or the profile is not of
    /// the session's namespace (`<auditArea>.identity.namespaceMismatch`,
    /// `<auditArea>.profile.namespaceMismatch`, at `start`). A radio that cannot start is stood down
    /// again (``Event/radioDidNotStart(error:)``, then ``Event/listeningWillRetry``), so
    /// ``isListening`` tells the truth.
    public func start() {
        // One namespace per session: an identity of another namespace starts no radio.
        guard ProximityNamespaceGate.mayStart(
            identityIsOfNamespace: identityIsOfNamespace, event: "\(profile.auditArea).identity.namespaceMismatch"
        ) else { return }
        // …and neither does a profile whose radio or mode its namespace never vetted.
        guard profileIsOfNamespace else {
            ProximityAudit.log("\(profile.auditArea).profile.namespaceMismatch",
                               context: ["at": ProximityNamespaceGate.Site.start.rawValue])
            return
        }
        guard !isRunning else { return }
        isRunning = true
        emit(.discoveryStarted)
        do {
            try session.start(advertisement: discoveryInfo())
        } catch {
            // The same stand-down door a post-start failure goes through: the radio never came up,
            // so `isListening` must say so and the run-policy seam re-applies a running verdict at
            // its next run (P8 item 0, device finding (b)).
            handleTransportError(.radioDidNotStart(error: "\(error)"))
            return
        }
        startObserving()
    }

    /// Stands the whole radio down: tasks, coordinators, the radio, every peer, connection and the
    /// live send.
    ///
    /// A send still in flight is not dropped silently: it is published to ``lastSendOutcome`` as
    /// `interrupted` (nothing had been handed over yet) or `sendIncomplete` (the send had begun), so
    /// a sheet that is still open (the run seam stops the radio when the scene goes inactive or the
    /// lock engages) can say so. A sheet that is closing ignores it.
    public func stop() {
        if isRunning {
            emit(.discoveryStopped)
        }
        isRunning = false
        observationTask?.cancel()
        observationTask = nil
        clearStatusTask?.cancel()
        clearStatusTask = nil
        connectTimeoutTask?.cancel()
        connectTimeoutTask = nil
        parkedSweepTask?.cancel()
        parkedSweepTask = nil
        parkedSince.removeAll()
        cancelCoordinators(of: connections)
        session.stop()
        nearbyPeers.removeAll()
        pendingOutgoing = nil
        discoveredPeers.removeAll()
        connections.removeAll()
        // The record is DISCARDED here, not cancelled: an `applyTransfer(.cancelled)` before this
        // line would move a value nothing can read afterwards. The one path that leaves a cancelled
        // record behind is the pre-connect timeout, which keeps it. Its outcome is published first,
        // while the phase that decides `interrupted` versus `sendIncomplete` is still readable.
        finishShareEndedByTeardown()
        transfer = nil
        engagedPeerID = nil
        status = .idle
    }

    public func refreshDiscovery() {
        // Hard 2-device cap: refreshing must NEVER tear down a live pairing — the old
        // stop-and-restart body would have dropped the verified connection mid-share. Refuse
        // visibly instead; discovery reopens on its own when the connection record is evicted.
        if let connection = connections.first {
            let name = displayName(for: connection)
            emit(.searchSkippedWhilePaired(pairedWith: name))
            status = .failed(.searchRefusedWhilePaired(pairedWith: name))
            scheduleStatusClear()
            return
        }
        let shouldRestart = isRunning
        emit(.discoveryRefreshed)
        observationTask?.cancel()
        observationTask = nil
        connectTimeoutTask?.cancel()
        connectTimeoutTask = nil
        parkedSweepTask?.cancel()
        parkedSweepTask = nil
        parkedSince.removeAll()
        cancelCoordinators(of: connections)
        session.stop()
        nearbyPeers.removeAll()
        pendingOutgoing = nil
        discoveredPeers.removeAll()
        connections.removeAll()
        finishShareEndedByTeardown()
        transfer = nil   // discarded, not cancelled — see `stop()`
        engagedPeerID = nil
        status = .idle
        isRunning = false
        if shouldRestart {
            start()
        }
    }

    /// Sends `outgoing` to the picked row: reuses a verified pairing, or dials the device and lets
    /// the handshake carry the send; refuses while paired with a different device or while another
    /// connection is in flight.
    ///
    /// Every way this send can end publishes exactly one ``lastSendOutcome``: the outbound-cap
    /// refusal here (before a send is minted, so it never touches a live send), and every later
    /// end through `finishShare(_:token:)`. The previous outcome is cleared first.
    public func send(_ outgoing: Outgoing, to recipient: ProximityPairPeer) {
        connectTimeoutTask?.cancel()
        lastSendOutcome = nil

        // Hard 2-device cap (outbound): refuse — visibly, never silently — while a connection
        // to a DIFFERENT peer exists. The radio is paused while paired, so an invite could not
        // go out anyway (see ProximityPairRadioSession.pauseDiscovery's contract).
        if let connection = connections.first, !isSameDevice(connection, as: recipient) {
            refuseWhilePaired(with: connection, outgoing: outgoing, recipient: recipient)
            return
        }

        start()
        pendingOutgoing = (outgoing, recipient)
        let token = mintTransfer(for: recipient.id)
        liveShare = LiveSend(
            recipient: recipient,
            subject: outgoing.subject,
            token: token,
            pairingSeen: connection(with: recipient) != nil
        )
        status = .connecting(recipientName: recipient.displayName)
        engagedPeerID = recipient.id
        emit(.connecting(recipientName: recipient.displayName))

        if let connection = connection(with: recipient),
           connection.verifiedKeyAgreementPublicKey != nil {
            // The pairing is already verified, so the exchange skips the connect leg entirely —
            // without this the once-only gate below would refuse the send from `.connecting`.
            applyTransfer(.peerVerified)
            spawnHostPinned { [weak self] in await self?.sendPendingPayload(via: connection) }
            return
        }

        guard let peer = peer(for: recipient) else {
            failLiveShare(
                .recipientUnavailable,
                status: .recipientUnavailable,
                event: .recipientUnavailable(recipientName: recipient.displayName))
            return
        }
        // Hard 2-device cap (connecting window): an attempt to a different peer is already in
        // flight — inviting a second one could race two connections past the cap.
        if session.hasConnectingPeers(besides: peer) {
            failLiveShare(
                .connectingToAnother,
                status: .connectingToAnother,
                event: .connectingToAnother(recipientName: recipient.displayName))
            return
        }
        session.dial(peer, helloSID: session.advertisedSessionID)
        armConnectTimeout(for: recipient)
    }

    /// The outbound-cap refusal: this device is paired with a different device, so the send is
    /// refused before it is minted. Publishes its own outcome directly (naming who holds the link)
    /// and leaves the live pairing, and any live send on it, untouched.
    private func refuseWhilePaired(
        with connection: PairConnection,
        outgoing: Outgoing,
        recipient: ProximityPairPeer
    ) {
        let name = displayName(for: connection)
        status = .failed(.pairedWithAnother(pairedWith: name))
        emit(.sendRefusedWhilePaired(recipientName: recipient.displayName, pairedWith: name))
        scheduleStatusClear()
        lastSendOutcome = ProximityPairSendOutcome(
            recipientID: recipient.id,
            recipientName: recipient.displayName,
            subject: outgoing.subject,
            otherPeerName: name,
            result: .notSent(.pairedWithAnother)
        )
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
            self.emit(.disconnected(name: self.displayName(for: peer)))
        }
        session.resolveDialer = { [weak self] sessionID in
            self?.peerAdvertising(sessionID: sessionID)
        }
        session.shouldAcceptDialer = { [weak self] peer in
            guard let self else { return false }
            // Blocklist is enforced at identity-introduction time by the coordinator.
            // Hard 2-device cap (inbound): accept only when we hold no connection AND no
            // connecting-window peer — checking `connections` alone leaves a race where a second
            // dialer slips in while the first is still connecting. The SAME peer re-dialing (retry
            // of a dropped attempt) is always let through.
            if self.connections.contains(where: { $0.peer.isSameEndpoint(as: peer) }) {
                return true
            }
            guard self.connections.isEmpty else { return false }
            return !self.session.hasConnectingPeers(besides: peer)
        }
        session.onTransportError = { [weak self] message in
            self?.handleTransportError(.radioFailed(message: message))
        }
    }

    /// The radio reported a START failure — a listener or browser that could not come up (the
    /// Local Network permission prompt on a fresh install's very first start, or the re-listen
    /// after a record eviction's `resumeDiscovery`).
    ///
    /// Stands the radio down. With `isRunning` left true the idempotent `start()` no-ops forever
    /// and passive listening stays dark; stopping fully makes `isListening` tell the truth, and the
    /// app's run-policy seam reads it on every policy run and re-applies a running verdict to a
    /// stopped listener (P8 item 0, device finding (b)) rather than waiting for a verdict edge or
    /// the share sheet's own `start()`.
    ///
    /// **Only a start failure reaches here.** A per-dial miss, a refused hello and a transfer that
    /// failed are logged by the radio and never reported — under the retired transport this door
    /// was reachable from `didNotStart*` alone, and a QUIC radio that reported a per-operation
    /// refusal through it would stand the whole radio down on an ordinary evening.
    ///
    /// The guard covers the whole of "something would be lost": a live pairing, and equally the
    /// **connecting window** — a dial in flight or an inbound connection mid-hello lives in the
    /// radio's tunnels and pending map, not in `connections`, and `stop()` cancels both. Under MC
    /// that window was unreachable from here (the door opened at start and nowhere else); a QUIC
    /// browser failing mid-evening would otherwise abort the user's tap and clear the picker. The
    /// failure itself, `first` (the radio's own message, or the error a `start()` caught), is
    /// emitted either way, so nothing about it is silent.
    private func handleTransportError(_ first: Event) {
        emit(first)
        guard connections.isEmpty, !session.hasConnectingPeers(besides: nil), isRunning else { return }
        stop()
        emit(.listeningWillRetry)
    }

    /// The browsed peer advertising `sessionID`, for the radio's inbound dialer resolution.
    ///
    /// The QUIC counterpart of the resolution the retired transport did for free: an inbound
    /// connection carries a connection id that belongs to no browse result, so the dialer names the
    /// `sid` from its own TXT record and this answers which discovered peer that is. A `sid` no
    /// discovered peer carries resolves to nobody, and the radio refuses the connection before any
    /// channel or handle exists.
    private func peerAdvertising(sessionID: String) -> PeerHandle? {
        guard !sessionID.isEmpty else { return nil }
        for peer in discoveredPeers.values.sorted(by: { $0.id.uuidString < $1.id.uuidString })
        where ProximityPairAdvertisement.sessionID(
            from: peer.discoveryInfo, mode: profile.advertisementMode) == sessionID {
            return peer
        }
        return nil
    }

    /// The advertised fields. `name` is bounded in BYTES rather than Characters — see
    /// ``ProximityPairAdvertisedName`` for why a 32-Character cap is not a bound at all once these
    /// fields become a Bonjour TXT record, and why an over-long value is dropped rather than cut.
    ///
    /// The bound narrows the wire on a second axis too: the sanitizer caps at the namespace's
    /// `installation.peerNames.maxLength` (Fernlet's 24) Characters and strips zero-width/bidi scalars,
    /// where MultipeerConnectivity advertised 32 raw ones. Invisible to a reader — the receiver
    /// re-caps at that cap with the same function — but it is a narrowing, not just a re-expression.
    ///
    /// A name that cannot be published at all (one grapheme wider than the byte bound) omits the
    /// `name` key rather than advertising an empty one, matching
    /// ``MeshLinkAdvertisement/publishedFields``: an absent name falls back to the peer's transport
    /// hint, an empty one would render as the host's peer-name floor.
    /// The `sid` is deliberately **absent**: it belongs to the radio, which mints it with its
    /// instance name and TLS identity at every `start()` and every resume, and joins it to these
    /// fields in ``ProximityPairAdvertisement/publishedFields(from:sessionID:)``. A copy kept here
    /// would go stale at the first resume.
    private func discoveryInfo() -> [String: String] {
        var fields = [
            ProximityPairAdvertisement.versionKey: ProximityPairAdvertisement.version,
            ProximityPairAdvertisement.modeKey: profile.advertisementMode
        ]
        let name = ProximityPairAdvertisedName.publishable(displayName, in: namespace)
        if !name.isEmpty { fields[ProximityPairAdvertisement.nameKey] = name }
        return fields
    }

    /// The advertised local display name (shared coercion; see `PeerDisplayNames.swift`).
    private var displayName: String { store.resolvedProximityDisplayName }

    /// Spawns a detached task that PINS this session's host for the task's own lifetime.
    ///
    /// ``store`` is `unowned` because the host owns this session's owner (Fernlet's
    /// `FernletStore.swift`'s `lazy var` managers), and the unowned back-reference is that ownership's
    /// cycle-breaker. A detached task,
    /// however, holds `self` STRONGLY for the duration of every `self?.method()` it awaits, so it can
    /// outlive the host and then read a destroyed object — `swift_abortRetainUnowned` aborts the whole
    /// process, which is what P5 item 1a's crash reports are. Capturing the host here, read
    /// synchronously on the main actor at a point where it is provably alive, makes the read the task
    /// will later perform valid by construction (invariant HP1).
    ///
    /// The pin is safe ONLY because this task's handle is not stored on the session: nothing the host
    /// owns can reach this closure context, so no `store → session → task → store` cycle forms. NEVER
    /// build the same pin into a task whose handle the session keeps (invariant HP2) — see the `// host-pin: timer`
    /// markers on the sites in this file that must not use this helper.
    ///
    /// The closure is deliberately neither `@Sendable` nor `sending`, so it inherits this session's
    /// isolation exactly as the `Task { … }` literal it replaces did — same executor, same enqueue,
    /// same ordering. It carries no `@_implicitSelfCapture` either, so a strong `self` capture has to
    /// be spelled `self.` at the call site.
    private func spawnHostPinned(_ operation: @escaping () async -> Void) {
        let host = store
        Task {   // host-pin: helper
            await operation()
            withExtendedLifetime(host) {}
        }
    }

    private func handlePeerDiscovered(_ peer: PeerHandle) {
        // Self-exclusion, second layer: the radio already drops its own registration by instance
        // name (which it mints and therefore recognizes even before a TXT record arrives), and
        // this catches an echo that reaches the owner carrying our own advertised `sid`.
        // Blocklist is enforced post-introduction.
        if let remoteSID = ProximityPairAdvertisement.sessionID(
            from: peer.discoveryInfo, mode: profile.advertisementMode),
           remoteSID == session.advertisedSessionID { return }
        discoveredPeers[peer.id] = peer
        let recipient = ProximityPairPeer(
            id: peer.id,
            // Pre-handshake label straight off the wire — the picker, the browse list and the
            // diagnostics all read it back from here, so this is the one ingest to coerce. The
            // QUIC radio publishes NO transport hint (see `NetworkPairSession.handle(for:)`),
            // so an absent or empty `name` falls through to the placeholder rather than to a random
            // Bonjour instance name — see `displayName(for peer:)`.
            displayName: displayName(for: peer),
            fingerprint: nil
        )
        nearbyPeers.removeAll { $0.id == recipient.id }
        nearbyPeers.append(recipient)
        nearbyPeers.sort { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending }
        emit(.discovered(name: recipient.displayName))
    }

    private func handlePeerLost(_ peer: PeerHandle) {
        let name = displayName(for: peer)
        discoveredPeers.removeValue(forKey: peer.id)
        nearbyPeers.removeAll { $0.id == peer.id }
        emit(.lost(name: name))
    }

    /// True when `peer`'s DEVICE already holds the pairing.
    ///
    /// The one spelling of "are we already paired with this device?", matched the way every stored
    /// record must be matched against a transport event — by ``PeerHandle/isSameEndpoint(as:)``,
    /// never `==` — so the inbound-invitation gate, the admission check and the channel-ready gate
    /// cannot drift apart again.
    private func isConnected(to peer: PeerHandle) -> Bool {
        connections.contains { $0.peer.isSameEndpoint(as: peer) }
    }

    /// True when `connection` is with the DEVICE the picker row `recipient` names.
    ///
    /// The recipient half of ``isConnected(to:)``. Every transport-facing gate in this file
    /// recognizes a device by ``PeerHandle/isSameEndpoint(as:)``, but the send pipeline compares a
    /// row `id` against a connection `id` — and both are ``PeerHandle/id``s, so a device that
    /// re-appears under a churned handle (a bounded identity-map eviction, a transport
    /// `stop()`/restart) fails the comparison against its own live pairing. Three arms, cheapest
    /// first: the id the row was minted from, the handshake-proven fingerprint (durable identity,
    /// available once verified), and the endpoint of the handle the row was minted from. None can
    /// match a different device — ids and endpoints are minted as a pair, and the fingerprint is
    /// proven — so the disjunction only ever recovers matches an id test would have lost.
    private func isSameDevice(
        _ connection: PairConnection,
        as recipient: ProximityPairPeer
    ) -> Bool {
        if connection.id == recipient.id { return true }
        if let verified = connection.fingerprint, let claimed = recipient.fingerprint,
           IdentityService.fingerprintsMatch(verified, claimed) {
            return true
        }
        guard let handle = discoveredPeers[recipient.id] else { return false }
        return connection.peer.isSameEndpoint(as: handle)
    }

    /// The live connection with the DEVICE `recipient` names, if any — see
    /// ``isSameDevice(_:as:)``.
    private func connection(with recipient: ProximityPairPeer) -> PairConnection? {
        connections.first { isSameDevice($0, as: recipient) }
    }

    /// Belt-and-braces admission check for a just-connected channel (hard 2-device cap):
    /// true only when no connection exists or the peer already holds it. A third peer can
    /// still slip past both dialer gates in the connecting window; this is the last line.
    func shouldAdmitChannel(for peer: PeerHandle) -> Bool {
        connections.isEmpty || isConnected(to: peer)
    }

    /// What ``handleChannelReady`` does with a freshly connected channel.
    ///
    /// Extracted from the guard chain so the decision is reachable from a unit test: what follows
    /// it in production is a live `ProximityCoordinator` over the ranging provider its host builds
    /// (`NIRangingSession` on Fernlet's iOS host), which a unit test must not build, and the decision
    /// is the half that was wrong. Mirrors `MeshNetworkManager.ChannelAdmission`.
    enum ChannelAdmission: Equatable {
        /// Open the pairing: build the coordinator and record the connection.
        case admit
        /// Refuse and free the tunnel. A connected peer with no connection record holds a zombie
        /// link — a channel with no owner, occupying the radio's one tunnel slot — until the radio
        /// stops.
        case turnAway
        /// This device already holds the pairing. Leave it entirely alone: disconnecting here would
        /// drop the good connection, and admitting would seat one device twice.
        case alreadyConnected
    }

    /// The admission decision for a freshly connected channel — see ``ChannelAdmission``.
    ///
    /// Recognizes the peer by endpoint, exactly as ``shouldAdmitChannel(for:)`` and the inbound
    /// dialer gate beside it do. The duplicate check used to compare `peer.id` alone (plan
    /// §6.4), so a paired device whose handle churned — a bounded identity-map eviction, a
    /// transport `stop()`/restart — fell through to ``shouldAdmitChannel(for:)``, which DID
    /// recognize it, and was admitted a second time: two connection records, two coordinators and
    /// two ranging sessions for one device, on a radio capped at two devices.
    func channelAdmission(for peer: PeerHandle) -> ChannelAdmission {
        guard !isConnected(to: peer) else { return .alreadyConnected }
        guard shouldAdmitChannel(for: peer) else { return .turnAway }
        return .admit
    }

    private func handleChannelReady(_ channel: NetworkPeerChannel) {
        switch channelAdmission(for: channel.peer) {
        case .alreadyConnected:
            return
        case .turnAway:
            // Hard 2-device cap, belt-and-braces: a third peer that won the connecting-window race
            // anyway is never admitted — end its tunnel and leave the existing pairing untouched.
            emit(.turnedAway(name: displayName(for: channel.peer)))
            session.endTunnel(channel.peer)
            return
        case .admit:
            break
        }
        emit(.channelOpened(name: displayName(for: channel.peer)))
        let trustPolicy = store.makeProximityTrustPolicy()
        let coordinator = ProximityCoordinator(
            identity: identity,
            transport: channel,
            ranging: store.makeProximityRangingProvider(),
            payloadHandler: payloadHandler,
            trustPolicy: trustPolicy,
            replayCache: replayCache,
            displayName: displayName,
            timeoutSeconds: 25
        )
        // Stranger-admission Option 1b (2026-09-22): the introduction carries no display name, so
        // `ensureRecipient` first files this peer under its fingerprint. That call is guarded by a
        // fingerprint change and runs once, so without this SUBSCRIBER the picker would show a
        // fingerprint for the rest of the session even after the peer disclosed.
        coordinator.onPeerDisplayNameDisclosed = { [weak self] identity in
            guard let self,
                  let connection = self.connections.first(where: { $0.fingerprint == identity.fingerprint })
            else { return }
            self.ensureRecipient(for: connection, identity: identity)
        }
        let connection = PairConnection(
            id: channel.peer.id,
            peer: channel.peer,
            channel: channel,
            coordinator: coordinator,
            trustPolicy: trustPolicy,
            fingerprint: nil,
            verifiedKeyAgreementPublicKey: nil
        )
        registerConnection(connection)

        spawnHostPinned { [weak self] in
            await coordinator.begin(role: .browser, mode: .friend)
            channel.notifyConnected()
            self?.checkCoordinatorStates()
        }
    }

    /// Single add-path for connection records. Pauses discovery the moment a connection is
    /// established — this runs for BOTH roles (handleChannelReady fires on inviter and invitee
    /// alike), which is the owner's "the mesh closes once two devices connect": the recipient's
    /// radio goes quiet while paired too. `resumeDiscovery` is keyed on record eviction in
    /// `finalizeConnectionRemovals`.
    private func registerConnection(_ connection: PairConnection) {
        connections.append(connection)
        connectionObservationRevision += 1
        // The connect stage for the engaged recipient is over: from here the coordinator's own
        // 25 s handshake budget (plus the parked sweep) governs — the shorter pre-connect timer
        // must not fire and best-effort kick a pairing that is progressing.
        if let outgoing = pendingOutgoing, isSameDevice(connection, as: outgoing.recipient) {
            connectTimeoutTask?.cancel()
            connectTimeoutTask = nil
            // …and from here a record eviction before the send is this share's failure to
            // connect (`failLiveShareIfItsPairingWasLost`), not a pre-connect miss.
            liveShare?.pairingSeen = true
        }
        applyDiscoveryGate(.connectionRegistered)
        emit(.closedToOthers(pairedWith: displayName(for: connection)))
        updateEngagedRecipient()
        startParkedSweepIfNeeded()
    }

    private func startObserving() {
        observationTask?.cancel()
        observationTask = ObservationLoop.start(
            on: self,
            tracking: { owner in
                _ = owner.connectionObservationRevision
                _ = owner.connections.count
                for connection in owner.connections {
                    _ = connection.coordinator.state
                }
            },
            onChange: { owner in
                owner.checkCoordinatorStates()
            }
        )
    }

    private func checkCoordinatorStates() {
        for index in connections.indices {
            switch connections[index].coordinator.state {
            case .awaitingManualCommit, .awaitingProximityCommit:
                let coordinator = connections[index].coordinator
                emit(.confirming)
                // host-pin: exempt — coordinator/channel only, no `self`, no host read
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
                    emit(.verified(name: peerIdentity.displayNameOrFingerprint))
                }
                if let outgoing = pendingOutgoing, isSameDevice(connections[index], as: outgoing.recipient) {
                    applyTransfer(.peerVerified)
                    let connection = connections[index]
                    spawnHostPinned { [weak self] in await self?.sendPendingPayload(via: connection) }
                }
            }
        }

        let stale = connections.filter { connection in
            switch connection.coordinator.state {
            case .ended, .failed: return true
            default: return false
            }
        }
        let before = connections.count
        cancelCoordinators(of: stale)
        for connection in stale {
            // A coordinator can fail/end without the transport ever reporting a disconnect (a
            // failed handshake never fires one) — end the tunnel so it doesn't linger as a zombie
            // while the record eviction below reopens discovery.
            session.endTunnel(connection.peer)
            parkedSince.removeValue(forKey: connection.id)
            connections.removeAll { $0.id == connection.id }
        }
        finalizeConnectionRemovals(previousCount: before)
    }

    private func removeConnections(matching peer: PeerHandle) {
        let before = connections.count
        let evicted = connections.filter { connection in
            connection.peer.isSameEndpoint(as: peer)
        }
        cancelCoordinators(of: evicted)
        for connection in evicted { parkedSince.removeValue(forKey: connection.id) }
        let evictedIDs = Set(evicted.map(\.id))
        connections.removeAll { evictedIDs.contains($0.id) }
        finalizeConnectionRemovals(previousCount: before)
    }

    /// Runs the coordinators' OWN teardown for records being evicted. A `PairConnection`
    /// is the only strong owner of its ``ProximityCoordinator``; dropping the record without
    /// `cancel()` frees the Swift graph but skips `end()` — the NISession invalidate, the
    /// foreground anchor's Live Activity end, and the `.sessionEnded` audit — because the
    /// coordinator's own `.disconnected` hop is a weak-self Task that finds nothing. Every drop
    /// path (stop, refresh, peer disconnect, parked sweep, stale sweep) funnels here. For an
    /// `.ended` record `cancel()` is idempotent; for a `.failed` one it is what guarantees the
    /// teardown runs (`fail()` only enqueues it, and this sweep can drop the last reference
    /// first). Capturing the whole record keeps the coordinator's weak trust policy alive for the
    /// audit; the Task releases it afterwards.
    private func cancelCoordinators(of evicted: [PairConnection]) {
        for connection in evicted {
            // host-pin: exempt — coordinator/channel only, no `self`, no host read
            Task { [connection] in await connection.coordinator.cancel() }
        }
    }

    /// Every connection-record removal funnels through here. Reopening the radio is keyed on
    /// MANAGER-LEVEL record eviction, deliberately NOT on transport disconnect events: a failed
    /// handshake never fires one, so waiting for one would leave the radio paused
    /// forever with no connection — the deadlock class the redesign closes. Covered removal
    /// paths: `onPeerDisconnected` (via removeConnections), the stale-coordinator sweep
    /// (.ended/.failed) in checkCoordinatorStates, and the parked-.discovering sweep.
    ///
    /// It is also where a share whose pairing came up and then died before the send is failed
    /// (`failLiveShareIfItsPairingWasLost`). Before that, nothing here touched the send pipeline,
    /// so a handshake that failed after the channel opened left "Connecting to …" on screen, and
    /// every other row locked, until the sheet closed.
    private func finalizeConnectionRemovals(previousCount: Int) {
        guard connections.count != previousCount else { return }
        connectionObservationRevision += 1
        failLiveShareIfItsPairingWasLost()
        updateEngagedRecipient()
        guard connections.isEmpty else { return }
        parkedSweepTask?.cancel()
        parkedSweepTask = nil
        parkedSince.removeAll()
        if applyDiscoveryGate(.connectionsEvicted) == .resume {
            emit(.reopened)
        }
    }

    /// Derived observable: connection first (it outlives the send), pending outgoing second.
    ///
    /// The sheet reads this back as a ROW id, so when the connection is with the device the user
    /// picked, publish the id of the row they picked — a connection seated under a churned handle
    /// carries an id no row has, which would lock out every row including the engaged one.
    private func updateEngagedRecipient() {
        guard let connection = connections.first else {
            engagedPeerID = pendingOutgoing?.recipient.id
            return
        }
        if let outgoing = pendingOutgoing, isSameDevice(connection, as: outgoing.recipient) {
            engagedPeerID = outgoing.recipient.id
            return
        }
        engagedPeerID = connection.id
    }

    private func displayName(for connection: PairConnection) -> String {
        displayName(for: connection.peer)
    }

    /// The name to show for a peer, in the picker row and in every "Connection details" line: the
    /// row this device already drew for it, else the name it advertised, else the host's peer-name
    /// floor, the picker's own placeholder.
    ///
    /// **The one rule for naming a peer in anything a user reads**, and a function rather than
    /// `peer.displayHint` because the hint changed meaning with the transport. Under
    /// MultipeerConnectivity it was a name a person had chosen for their phone; under QUIC the
    /// radio holds only its random Bonjour instance name and the endpoint key containing it, and
    /// publishes NEITHER — `displayHint` is empty. A reader that kept the old assumption printed
    /// `fernlet-mesh-3f2a9c81b4de` into the picker and the connection log.
    ///
    /// No new display string: the placeholder is the floor
    /// `ProximityDisplayName.peerDisplayName(_:in:)` already answers for an empty name under the
    /// session's namespace, which is what every other pre-handshake surface in this subsystem renders.
    private func displayName(for peer: PeerHandle) -> String {
        if let row = nearbyPeers.first(where: { $0.id == peer.id }) { return row.displayName }
        return ProximityDisplayName.peerDisplayName(
            ProximityPairAdvertisedName.received(
                peer.discoveryInfo?[ProximityPairAdvertisement.nameKey], hint: ""
            ),
            in: namespace
        )
    }

    /// Arms the sender-side connect timeout for the PRE-CONNECT stage only. Under the hard
    /// 2-device cap the peer being busy (paired with someone else, silently rejecting invites)
    /// is the common case — surface it as a distinct visible failure instead of an eternal
    /// "Connecting…". `registerConnection` cancels this the moment the channel comes up;
    /// past that point the coordinator's 25 s handshake budget owns failure.
    private func armConnectTimeout(for recipient: ProximityPairPeer) {
        connectTimeoutTask?.cancel()
        let timeout = connectTimeoutSeconds
        // host-pin: timer — stored handle, synchronous main-actor body (connect-timeout failure) (HP2)
        connectTimeoutTask = Task { @MainActor [weak self] in
            // Cancelled by `registerConnection`/`stop` ⇒ the connect stage succeeded or the
            // session went away; not firing IS the recovery.
            do { try await Task.sleep(for: .seconds(timeout)) } catch { return }
            guard let self else { return }
            guard let outgoing = self.pendingOutgoing, outgoing.recipient.id == recipient.id else { return }
            // Belt-and-braces stage check (registerConnection already cancels this task): a
            // connection record means the connect stage succeeded — never fail or kick a
            // handshake in progress from here.
            guard self.connection(with: recipient) == nil else { return }
            self.failLiveShare(
                .noAnswer,
                status: .noAnswer(recipientName: recipient.displayName),
                event: .noAnswer(recipientName: recipient.displayName))
            // End the half-open attempt so it doesn't linger in the connecting window and
            // block the next accepted dial.
            if let peer = self.peer(for: recipient) {
                self.session.endTunnel(peer)
            }
        }
    }

    // MARK: - Share outcome

    /// The one tail every failure of the live share before its send takes: drop the queued
    /// payload, cancel the exchange record, show the (auto-clearing) failed status line, emit the
    /// event, release the engaged row, and publish the frozen cause, in that order.
    ///
    /// The four copies of this tail it replaces (recipient unavailable, connecting window, connect
    /// timeout, and the lost-pairing path) differed only in their status, their event and their
    /// cause, so they are one function and cannot drift apart.
    private func failLiveShare(_ reason: ProximityPairSendFailure, status failure: Status.Failure, event: Event) {
        pendingOutgoing = nil
        applyTransfer(.cancelled)
        status = .failed(failure)
        emit(event)
        updateEngagedRecipient()
        scheduleStatusClear()
        finishShare(.notSent(reason), token: nil)
    }

    /// Fails the live share as `couldNotConnect` when its pairing had come up and has now been
    /// evicted before the send began.
    ///
    /// Three conditions, and each is load-bearing. `pairingSeen`: a share whose dial has not been
    /// answered yet is still legitimately in flight (the 12 s connect timeout owns it), and an
    /// eviction of some OTHER device's record must not fail it. A pre-send phase: once the send has
    /// begun, its own `catch` owns the failure (`sendIncomplete`). No remaining connection with the
    /// recipient's device: the record that went may not have been this share's.
    ///
    /// The pairing is recognized by the `pairingSeen` latch rather than by matching the evicted
    /// records, because `onPeerDisconnected` removes the discovered handle before the record, which
    /// defeats `isSameDevice`'s endpoint arm for a device that answered under a churned handle.
    private func failLiveShareIfItsPairingWasLost() {
        guard let live = liveShare, live.pairingSeen,
              let record = transfer, record.token == live.token,
              record.phase == .connecting || record.phase == .verified,
              connection(with: live.recipient) == nil else { return }
        let name = live.recipient.displayName
        failLiveShare(
            .couldNotConnect,
            status: .couldNotConnect(recipientName: name),
            event: .couldNotConnect(recipientName: name))
    }

    /// Publishes the outcome of a share a teardown (`stop()`, a search restart) ended while it was
    /// still in flight — `sendIncomplete` if its send had begun, `interrupted` if not — then forgets
    /// the live share either way. Must run BEFORE the teardown discards the transfer record, since
    /// the record's phase is what tells the two apart.
    private func finishShareEndedByTeardown() {
        defer { liveShare = nil }
        guard let phase = transfer?.phase, !phase.isTerminal else { return }
        finishShare(.notSent(phase == .sending ? .sendIncomplete : .interrupted), token: nil)
    }

    /// Publishes the live share's terminal outcome to ``lastSendOutcome`` — the one writer for a
    /// share that was minted.
    ///
    /// `token` attributes an outcome a SEND produced (`sendPendingPayload`) to the share that began
    /// it, exactly as `applyTransfer(_:token:)` does: a completion that belongs to a superseded share
    /// is recorded as a diagnostic and never shown, and one that arrives after a teardown (no live
    /// share) is dropped, because the teardown already published that share's outcome. Outcomes that
    /// belong to whatever share is live (a refusal, a timeout, a lost pairing, a teardown) pass nil.
    private func finishShare(_ result: ProximityPairSendOutcome.Result, token: UUID?) {
        guard let live = liveShare else { return }
        guard token == nil || token == live.token else {
            emit(.outcomeSuperseded)
            return
        }
        liveShare = nil
        lastSendOutcome = ProximityPairSendOutcome(
            recipientID: live.recipient.id,
            recipientName: live.recipient.displayName,
            subject: live.subject,
            result: result
        )
    }

    // MARK: - Parked-connection sweep

    private func startParkedSweepIfNeeded() {
        guard parkedSweepTask == nil else { return }
        // host-pin: timer — stored handle, synchronous main-actor body (`sweepParkedConnections`) (HP2)
        parkedSweepTask = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                // Cancellation ends the sweep loop here rather than spinning one more iteration.
                do { try await Task.sleep(for: .seconds(Self.parkedSweepIntervalSeconds)) } catch { return }
                guard let self else { return }
                self.sweepParkedConnections(now: Date())
                if self.connections.isEmpty {
                    self.parkedSweepTask = nil
                    return
                }
            }
        }
    }

    /// Evicts connection records whose coordinator has parked in a pre-verification state
    /// (.idle/.starting/.discovering/.peerInRange) past `parkedConnectionTimeoutSeconds`. The
    /// .ended/.failed sweep in checkCoordinatorStates can never catch these: a transport that
    /// dies pre-verification fires no transport disconnect, and the friend-mode auto-reconnect path
    /// parks a once-connected coordinator back in .discovering — with the radio paused, such a
    /// record would hold the 2-device cap closed forever. Internal so tests can drive it with
    /// synthetic dates; production calls it from the periodic sweep task.
    func sweepParkedConnections(now: Date) {
        var evicted: [PairConnection] = []
        for connection in connections {
            switch connection.coordinator.state {
            case .idle, .starting, .discovering, .peerInRange:
                if let since = parkedSince[connection.id] {
                    if now.timeIntervalSince(since) >= Self.parkedConnectionTimeoutSeconds {
                        evicted.append(connection)
                    }
                } else {
                    parkedSince[connection.id] = now
                }
            default:
                parkedSince.removeValue(forKey: connection.id)
            }
        }
        guard !evicted.isEmpty else { return }
        let before = connections.count
        cancelCoordinators(of: evicted)
        for connection in evicted {
            // Same zombie caveat as the stale sweep: the tunnel may still be up even though
            // the coordinator stalled — end it.
            session.endTunnel(connection.peer)
            parkedSince.removeValue(forKey: connection.id)
            emit(.droppedStalled(name: displayName(for: connection)))
            connections.removeAll { $0.id == connection.id }
        }
        finalizeConnectionRemovals(previousCount: before)
    }

    private func ensureRecipient(for connection: PairConnection, identity peerIdentity: ProximityCoordinator.PeerIdentity) {
        // Option 1b: until the peer discloses its signed name, keep the row's own label — the name
        // this radio's Bonjour record already advertised (by design: the picker shows it) — rather
        // than swapping it for the fingerprint and back a moment later (the item's blind verify).
        // The fingerprint is the label only for a row this radio never discovered.
        let shownName = peerIdentity.isDisplayNameWithheld
            ? (nearbyPeers.first { $0.id == connection.id }?.displayName ?? peerIdentity.fingerprint)
            : peerIdentity.displayName
        let recipient = ProximityPairPeer(
            id: connection.id,
            displayName: shownName,
            fingerprint: peerIdentity.fingerprint
        )
        nearbyPeers.removeAll { $0.id == recipient.id || $0.fingerprint == recipient.fingerprint }
        nearbyPeers.append(recipient)
        nearbyPeers.sort { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending }
    }

    private func sendPendingPayload(via connection: PairConnection) async {
        guard let pending = pendingOutgoing,
              isSameDevice(connection, as: pending.recipient) else { return }
        connectTimeoutTask?.cancel()  // connected + verified — the connect phase is over
        // The record this send belongs to, captured BEFORE the first `await`. A second send to the
        // same already-paired peer mints a new record while this one is in flight; every outcome
        // below is attributed to the record that began it, or refused.
        let token = transfer?.token
        pendingOutgoing = nil
        updateEngagedRecipient()
        status = .sending(recipientName: pending.recipient.displayName)
        emit(.sending(subject: pending.outgoing.subject, recipientName: pending.recipient.displayName))
        do {
            // The owner's bytes, produced here, once: the summary it built is signed beside them.
            let payloadData = try pending.outgoing.encode()
            // The exchange's once-only start. `pendingOutgoing = nil` above already makes a second
            // entry return, so this is belt-and-braces — but it is the half a pass-2 session cannot
            // quietly lose, and a refusal is surfaced rather than swallowed. It publishes NO send
            // outcome: every way to reach it (a superseding send, a record a teardown or failure
            // already ended, a duplicate while the first send is still going) leaves the outcome to
            // the path that owns it, and publishing here would drop that one.
            guard applyTransfer(.sendBegan(wireByteCount: payloadData.count), token: token) else {
                status = .failed(.duplicateSend)
                emit(.duplicateSendRefused(subject: pending.outgoing.subject))
                scheduleStatusClear()
                return
            }
            try await connection.coordinator.sendPayload(
                payloadTypeToken: pending.outgoing.payloadTypeToken,
                summary: pending.outgoing.summary,
                payload: payloadData,
                sealed: true
            )
            // A completion is attributed to the record that BEGAN this send, by its token: two
            // overlapping sends to one already-paired peer carry the same `recipientID`, so
            // without the token this completion would be counted against whichever record is live
            // — crediting the wrong subject. A refusal means a newer send has superseded this one;
            // the payload DID land, so it is reported rather than failed — but the status line
            // belongs to the live record, and writing `.sent` over its `.sending` would announce a
            // send the user is no longer watching. The observable half is the half the token was
            // meant to protect.
            guard applyTransfer(.sendCompleted, token: token) else {
                emit(.completionNotCounted)
                return
            }
            status = .sent(recipientName: pending.recipient.displayName)
            emit(.sent(subject: pending.outgoing.subject, recipientName: pending.recipient.displayName))
            finishShare(.sent, token: token)
        } catch {
            // Whether anything had been handed over: the encode above can throw before `sendBegan`.
            let hadBegun = transfer?.phase == .sending
            applyTransfer(.sendFailed, token: token)
            status = .failed(.sendFailed)
            emit(.sendFailed(recipientName: pending.recipient.displayName))
            finishShare(.notSent(hadBegun ? .sendIncomplete : .interrupted), token: token)
        }
        scheduleStatusClear()
    }

    private func peer(for recipient: ProximityPairPeer) -> PeerHandle? {
        if let connection = connection(with: recipient) {
            return connection.peer
        }
        return discoveredPeers[recipient.id]
            ?? session.connectedPeers.first { $0.id == recipient.id }
    }

    private func scheduleStatusClear() {
        clearStatusTask?.cancel()
        // host-pin: timer — stored handle, synchronous main-actor body (`status = .idle`) (HP2)
        clearStatusTask = Task { @MainActor [weak self] in
            // A superseding `scheduleStatusClear` cancels this one — NOT clearing the status is
            // the correct recovery, because the newer timer owns it.
            do { try await Task.sleep(for: .seconds(2.5)) } catch { return }
            self?.status = .idle
        }
    }

    /// Hands what the session just did to its owner, ``onEvent``, synchronously, so the owner's
    /// diagnostics run in the order the session acts.
    private func emit(_ event: Event) {
        onEvent?(event)
    }

    // MARK: - Exchange and discovery gate

    /// Applies ``ProximityPairDiscoveryGate``'s verdict for `event` to the radio and tells the live
    /// exchange which way the door moved.
    ///
    /// The two bare pause/resume call sites the recipe radio's owner used to hold are one table, so the
    /// QUIC session can be bound to the contract rather than to a reading of two guard chains. The
    /// verdict is returned rather than swallowed because the resume's diagnostic line is conditional
    /// on it and the pause's is not — exactly as they are today.
    @discardableResult
    private func applyDiscoveryGate(_ event: ProximityPairDiscoveryGate.Event) -> ProximityPairDiscoveryGate.Verdict {
        let radio = ProximityPairDiscoveryGate.Radio(
            isRunning: isRunning,
            isPaused: session.isDiscoveryPaused,
            connectionCount: connections.count
        )
        let verdict = ProximityPairDiscoveryGate.verdict(for: event, radio: radio)
        switch verdict {
        case .pause:
            session.pauseDiscovery()
            applyTransfer(.discoveryPaused)
        case .resume:
            session.resumeDiscovery()
            applyTransfer(.discoveryResumed)
        case .unchanged:
            break
        }
        return verdict
    }

    /// Mints the live exchange record for `recipientID`, seeded from the radio's own stand-down
    /// state.
    ///
    /// **One mint site, deliberately.** The shipping send and `beginTransferForTesting` held two
    /// copies of this expression, and only the test seam was ever executed — so restoring pass 1's
    /// own defect on the shipping line (`radioIsQuiet: false`) left every cell green. The seed is
    /// read from the radio rather than defaulted because a second send to an ALREADY-PAIRED peer
    /// is minted while discovery is already standing down and fires no gate transition of its own:
    /// a record born `radioIsQuiet == false` would claim an open radio for that whole send.
    ///
    /// - Returns: the new record's token, which `send(_:to:)` also files on the live send so
    ///   its outcome is attributed exactly as its send events are.
    @discardableResult
    private func mintTransfer(for recipientID: UUID) -> UUID {
        let record = ProximityPairTransfer(recipientID: recipientID, radioIsQuiet: session.isDiscoveryPaused)
        transfer = record
        return record.token
    }

    /// Applies one event to the live exchange record.
    ///
    /// - Parameters:
    ///   - event: What happened.
    ///   - token: The record the event belongs to, for the events a SEND owns
    ///     (`sendBegan`/`sendCompleted`/`sendFailed`). A mismatch is refused rather than applied to
    ///     whatever record happens to be live: two overlapping sends to one already-paired peer
    ///     carry the same `recipientID`, so without this the first send's completion lands on the
    ///     second send's record and the status line credits the wrong subject. Events that belong
    ///     to whatever send is live — a verification, a teardown, a discovery pause — pass nil.
    /// - Returns: whether the exchange took the event. **True when there is no exchange**: every
    ///   send path mints one, so a missing record means a teardown has already run and the caller's
    ///   own guards have handled it — a refusal here would turn that into a silent dropped send.
    @discardableResult
    private func applyTransfer(_ event: ProximityPairTransfer.Event, token: UUID? = nil) -> Bool {
        guard var live = transfer else { return true }
        if let token, live.token != token { return false }
        let accepted = live.apply(event)
        transfer = live
        return accepted
    }

    // MARK: - Test seam

    /// Builds AND retains a connection exactly as `handleChannelReady` does — asking the host for the
    /// pairing's trust policy (`makeProximityTrustPolicy()`) and holding it on the connection struct so the
    /// coordinator's `weak` trustPolicy survives past this method's scope — but over an injected transport
    /// so a unit test can drive a revoked/blocked-key envelope through the coordinator. Returns the
    /// connection's coordinator. `internal` for `@testable` unit tests only: the production connection path
    /// is driven by a live QUIC radio a unit test cannot fake (mirrors the clothing manager's
    /// `clearCatalogs(...)` and the heart manager's `evaluateConnectedCoordinatorForTesting(...)`). If the
    /// retention regresses (policy no longer stored on the connection), the coordinator's weak ref goes nil
    /// once this returns and the revoked-key drop this drives silently stops firing.
    func makeRetainedConnectionCoordinatorForTesting(
        peer: PeerHandle,
        transport: any PeerTransport,
        ranging: any RangingProvider
    ) -> ProximityCoordinator {
        let trustPolicy = store.makeProximityTrustPolicy()
        let coordinator = ProximityCoordinator(
            identity: identity,
            transport: transport,
            ranging: ranging,
            payloadHandler: payloadHandler,
            trustPolicy: trustPolicy,
            replayCache: replayCache,
            foregroundAnchor: NoopProximityForegroundAnchor(),
            displayName: displayName,
            timeoutSeconds: 0
        )
        let connection = PairConnection(
            id: peer.id,
            peer: peer,
            channel: session.channel(for: peer),
            coordinator: coordinator,
            trustPolicy: trustPolicy,
            fingerprint: nil,
            verifiedKeyAgreementPublicKey: nil
        )
        // Routed through the production add-path so cap tests exercise the real
        // pause-on-connect behavior (and the retention noted above still holds).
        registerConnection(connection)
        return coordinator
    }

    /// The radio, exposed for cap tests only: they assert the pause/resume flag and drive the
    /// session's own radio callbacks (`onPeerDiscovered`, `onPeerDisconnected`,
    /// `shouldAcceptDialer`) — the production writers need live radios a unit test must never
    /// start. A cell that needs to *drive* the radio hands one in through the init seam instead.
    var radioForTesting: any ProximityPairRadioSession { session }

    var connectionCountForTesting: Int { connections.count }

    /// The run flag, exposed so the transport-error recovery tests can pin that a failed
    /// discovery (re)start flips it false — the property `start()`'s idempotence gate reads.
    var isRunningForTesting: Bool { isRunning }

    /// Marks the session running WITHOUT starting the radio — `start()` would bring up a real
    /// advertiser/browser, which unit tests must never do. The resume-on-eviction gate checks
    /// `isRunning`, so cap tests need this to observe reopen behavior.
    func markRunningForTesting() {
        isRunning = true
    }

    /// Drives the production inbound-dialer gate closure exactly as the radio would, once a dial
    /// hello has resolved to a browsed peer. Fails closed, as the hook itself does.
    func shouldAcceptDialerForTesting(_ peer: PeerHandle) -> Bool {
        session.shouldAcceptDialer?(peer) ?? false
    }

    /// Drives the production dialer RESOLUTION closure exactly as the radio would: which browsed
    /// peer, if any, is advertising `sessionID`.
    func resolveDialerForTesting(_ sessionID: String) -> PeerHandle? {
        session.resolveDialer?(sessionID) ?? nil
    }

    /// Runs the stale-coordinator sweep deterministically (production runs it from the
    /// observation loop, which only spins after a real `start()`).
    func checkCoordinatorStatesForTesting() {
        checkCoordinatorStates()
    }

    /// The live exchange record — the read the state-table cells assert against.
    var transferForTesting: ProximityPairTransfer? { transfer }

    /// Publishes a send outcome through the PRODUCTION `finishShare(_:token:)`, attributed to
    /// `token` exactly as `sendPendingPayload` attributes a send's result. A unit test cannot drive a
    /// real verified send (that needs a live coordinator over a real channel), so this is how the
    /// token gate — a live send publishes, a superseded or torn-down one does not — is reachable.
    func finishShareForTesting(_ result: ProximityPairSendOutcome.Result, token: UUID?) {
        finishShare(result, token: token)
    }

    /// Mints the exchange record exactly as `send(_:to:)` does — through the SAME private
    /// helper, not through a second copy of its expression — with no radio and no recipient row,
    /// so the table is reachable at tier 1. See ``mintTransfer(for:)``.
    func beginTransferForTesting(recipientID: UUID) {
        mintTransfer(for: recipientID)
    }

    /// Drives one exchange event through the production helper.
    @discardableResult
    func applyTransferForTesting(_ event: ProximityPairTransfer.Event) -> Bool {
        applyTransfer(event)
    }

    /// Drives one exchange event through the production helper, ATTRIBUTED to `token` — the path a
    /// send's own outcome takes. An event whose token is not the live record's is refused.
    @discardableResult
    func applyTransferForTesting(_ event: ProximityPairTransfer.Event, token: UUID?) -> Bool {
        applyTransfer(event, token: token)
    }

    /// Drives the discovery gate exactly as a session event does — the production pause/resume path,
    /// reachable without starting a radio.
    @discardableResult
    func applyDiscoveryGateForTesting(
        _ event: ProximityPairDiscoveryGate.Event
    ) -> ProximityPairDiscoveryGate.Verdict {
        applyDiscoveryGate(event)
    }

    /// The fields the radio advertises — so the name bound is assertable off the production builder.
    var discoveryInfoForTesting: [String: String] { discoveryInfo() }
}
