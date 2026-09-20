import CryptoKit
import Foundation
import Network
import os
import Security
import FernletFoundation

// MARK: - RecipeShareRadioSession

/// The recipe-share radio, as the surface ``ProximityRecipeShareManager`` actually drives.
///
/// The seam the recipe manager did not have. `MeshNetworkManager` has held its radio behind
/// `MeshTransportSession` since P2 item 8 and `PresenceManager` behind ``PresenceRadioSession``
/// since P9 item 2; the recipe manager constructed its session inline, which is why not one of its
/// advertise, dial, admission or stand-down decisions was reachable without starting a real radio.
/// Everything the manager asks of a radio is here and nothing else is: no browse internals, no
/// tunnels, no framework type.
///
/// The hooks are settable rather than delegate methods because that is the shape all three radios
/// already publish, and because the manager wires them once at construction and never again.
@MainActor
protocol RecipeShareRadioSession: AnyObject {

    /// A peer appeared in the browse results, with its advertisement.
    var onPeerDiscovered: ((PeerHandle) -> Void)? { get set }
    /// A peer left the browse results.
    var onPeerLost: ((PeerHandle) -> Void)? { get set }
    /// A tunnel came up and its channel is live.
    var onPeerChannelReady: ((NetworkPeerChannel) -> Void)? { get set }
    /// A tunnel went down, with a diagnostic reason.
    var onPeerDisconnected: ((PeerHandle, String) -> Void)? { get set }
    /// The listener or browser failed to start.
    var onTransportError: ((String) -> Void)? { get set }
    /// Resolves an inbound dialer's claimed session id to the browsed peer it names, or nil to
    /// refuse. Fails closed when unwired.
    var resolveDialer: ((String) -> PeerHandle?)? { get set }
    /// The owner's inbound admission gate — the hard 2-device cap's first layer, asked once the
    /// dialer has resolved to a browsed peer. **Fails closed** when unwired, exactly as the
    /// retired advertiser's `?? false` did.
    var shouldAcceptDialer: ((PeerHandle) -> Bool)? { get set }

    /// Whether discovery is standing down right now.
    var isDiscoveryPaused: Bool { get }
    /// The session id this radio is advertising — minted per ``start()`` and per
    /// ``resumeDiscovery()``, empty while the radio is down.
    var advertisedSessionID: String { get }
    /// Peers this radio currently holds a tunnel to.
    var connectedPeers: [PeerHandle] { get }

    /// Brings the radio up, advertising the owner's `advertisement` fields beside this radio's own
    /// session id.
    func start(advertisement: [String: String]) throws
    /// Tears the radio down and drops everything it held.
    func stop()
    /// Opens a tunnel to a browsed peer, claiming `helloSID`.
    func dial(_ peer: PeerHandle, helloSID: String)
    /// Ends a peer's tunnel at the owner's request.
    func endTunnel(_ peer: PeerHandle)
    /// Whether any peer other than `peer` is mid-connect — the connecting-window half of the hard
    /// 2-device cap.
    func hasConnectingPeers(besides peer: PeerHandle?) -> Bool
    /// Stands the listener and the browser down, keeping every live tunnel.
    func pauseDiscovery()
    /// Reopens a paused radio under a freshly minted posture.
    func resumeDiscovery()
    /// The channel this radio would hand the owner for `peer`, built exactly as the live path
    /// builds one — the seam a unit test uses to stand a connection up with no radio.
    func channel(for peer: PeerHandle) -> NetworkPeerChannel
}

// MARK: - RecipeSharePosture

/// The ephemeral identity one recipe-share radio wears: the Bonjour instance name it is found by,
/// the TLS identity it presents, and the session id it advertises.
///
/// **Deliberately not a ``PresenceEpochPosture``.** That type carries an `epoch` and anchors its
/// certificate to `IdentityService.presenceEpochStart`; its whole contract is "this rotates every
/// 900 s, on a boundary every device agrees on". The recipe radio's lifetime is a Food-tab visit,
/// and it mints one of these per `start()` and per resume — wearing a type whose contract said
/// otherwise would be a silent mismatch, and a rotation timer here would be a second timer on a
/// subsystem that is allowed one.
///
/// **What it improves on, and what it does not.** The retired radio advertised the *persistent,
/// device-name-derived* peer identity, so a passive Bonjour scanner could link a person's
/// sightings across days and places and read their device's name off the air. This name is 12 hex
/// characters of fresh entropy and means nothing. It does **not** make an advertiser unlinkable:
/// the TXT record still carries the user's chosen display name, on purpose, because the picker on
/// the other phone shows it. What the ephemeral posture removes is the identifier the user never
/// chose.
///
/// Nothing here is persisted: no keychain row, no file, no `UserDefaults` key. A dropped posture
/// is gone.
nonisolated struct RecipeSharePosture {

    /// The service instance name this radio is found by.
    let instanceName: String

    /// The session id advertised in the TXT record and claimed in a ``RecipeShareDialHello``.
    let sessionID: String

    /// The TLS identity the listener presents. Accept-any validated by both ends — certificate
    /// validation is not the authentication decision here; the coordinator's sealed introduction
    /// is.
    let tlsIdentity: EphemeralMeshTLSIdentity.Minted

    /// A freshly minted posture: a random instance name, a random session id, and a new key pair.
    ///
    /// - Throws: ``MeshTransportError/tlsIdentityUnavailable`` when the platform refuses the mint,
    ///   which the caller reports as a start failure rather than advertising without an identity.
    static func minted(now: Date = Date()) throws -> RecipeSharePosture {
        RecipeSharePosture(
            instanceName: MeshLinkAdvertisement.randomInstanceName(),
            sessionID: UUID().uuidString,
            tlsIdentity: try EphemeralMeshTLSIdentity.mint(now: now)
        )
    }
}

// MARK: - NetworkRecipeShareSession

/// The recipe-share radio's Network.framework/QUIC surface: one listener, one browser, and the
/// single short-lived pairwise tunnel the hard 2-device cap allows, multiplexed into a
/// ``NetworkPeerChannel``.
///
/// The third radio of plan §17.1, and — like ``NetworkPresenceSession`` — a separate, much smaller
/// session than ``NetworkMeshSession`` rather than a parameterization of it. What the three share
/// is reused by symbol: ``ProximityQUICParameters``, ``NetworkMeshWire``,
/// ``MeshSessionIdentityMap``, ``MeshLinkKey``, ``MeshTunnelConvergence``,
/// ``MeshTransferStreamTable`` and ``NetworkPeerChannel`` itself. What makes it its own type:
///
/// * **One tunnel, and the pause that goes with it.** Recipe sharing links two Fernlets at a time,
///   and while a pairing is held this radio goes *quiet* — ``pauseDiscovery()`` stands the
///   listener and the browser down so a third Fernlet can neither see this one nor invite it.
///   That is shipped, user-visible behaviour (``RecipeShareDiscoveryGate`` is its contract), and
///   it is precisely what a naive transport swap loses silently: the bytes still flow, the share
///   still lands, and the only symptom is a third device that can suddenly see a paired one.
/// * **There is no signed channel introduction.** The mesh authenticates a tunnel with
///   ``MeshChannelIntroduction`` against its roster before a single app frame crosses. This radio
///   must not: `ProximityCoordinator`'s SEALED introduction is the recipe handshake, and its whole
///   point is that identity never travels in the clear.
/// * **There IS a per-transfer stream, which presence has none of.** A shared recipe crosses as
///   ONE sealed frame — there is no chunking and no resume — but a recipe carrying a picture
///   (`ProximityRecipeSharePayload.maxImageBytes`, 512 KiB, base64'd into the JSON) clears
///   ``MeshTransferStreamTable/bulkFloorBytes`` and earns a stream of its own, exactly as a friend
///   photo does on the mesh. A text-only recipe stays on the control stream.
/// * **No timer at all.** The posture is minted per `start()` and per resume and never rotates on
///   a clock, which is what keeps the proximity subsystem's one-timer rule true after the
///   migration.
///
/// ## Inbound peer resolution
///
/// The retired radio resolved an inbound peer for free: an invitation arrives bearing the peer the
/// browser already found. QUIC does not — an inbound connection carries a connection id that
/// belongs to no browse result — so the dialer opens with one ``RecipeShareDialHello`` naming the
/// session id it advertises, and the owner resolves that id to a peer it has already browsed
/// through ``resolveDialer``, then rules on it through ``shouldAcceptDialer``. A hello that names
/// no such peer, or names this device itself, is refused before any channel or handle exists. See
/// ``RecipeShareDialHello`` for why that frame discloses nothing the air did not.
///
/// ## Glare
///
/// Two Fernlets that sight each other at the same moment can both dial. Refusing the inbound on
/// both sides ends with **zero** tunnels — the refusal closes the peer's connection, so each
/// side's own dial dies at the other end. So a second connection under a held key is **collapsed
/// rather than refused**, by the mesh's own rule (``MeshTunnelConvergence``) applied to the only
/// pair of values both devices hold and agree on before any handshake has run: the two advertised
/// instance names. Both sides compute the same verdict from the same two strings.
///
/// ## Security posture
///
/// TLS presents the posture's identity with an accept-any validator, exactly as the other two
/// radios do and for the same reason. `prohibitedInterfaceTypes` is `[.cellular]` on every
/// listener, browser and connection — the local-link claim, enforced by the OS. The ALPN is this
/// radio's own, so a recipe connection and a mesh or presence connection can never negotiate.
///
/// **Fail closed without an owner.** A session whose owner wired no ``resolveDialer`` resolves
/// nobody, and one whose owner wired no ``shouldAcceptDialer`` admits nobody.
///
/// `@MainActor`; framework callbacks arrive `@Sendable` and hop in.
@MainActor
final class NetworkRecipeShareSession: RecipeShareRadioSession, NetworkChannelHost {

    /// The recipe radio's QUIC service type. A frozen wire token: it must also appear in the app's
    /// Info.plist `NSBonjourServices` or discovery is silently dead on device.
    ///
    /// Deliberately **not** a reuse of the retired radio's `_fernlet-recipe._tcp`/`._udp`. Those
    /// entries survive until P9 item 4 deletes them, and reusing a name during the migration
    /// window would put this listener and the old advertiser on one service type, where each would
    /// browse the other's registrations as a peer.
    nonisolated static let serviceType = "_fernlet-recipe2._udp"

    /// ALPN for the recipe-share protocol. A frozen wire token, distinct from the mesh's
    /// `fernlet-mesh-v1` and presence's `fernlet-near-v1` so no two radios can negotiate.
    nonisolated static let alpn = "fernlet-recipe-v1"

    /// Hard ceiling on one inbound frame, enforced before the bytes reach any channel or decoder.
    /// The same value the other two transports enforce, so all three refuse identically.
    nonisolated static let maxInboundWireBytes = NetworkMeshSession.maxInboundWireBytes

    /// The QUIC stream id the control stream always has — RFC 9000 §2.1 numbers client-initiated
    /// bidirectional streams 0, 4, 8 … and a recipe dialer opens exactly one before anything else.
    nonisolated static let controlStreamID: UInt64 = 0

    /// Live tunnels this radio may hold: **one**, because recipe sharing links two Fernlets at a
    /// time.
    ///
    /// The owner enforces that cap at four layers of its own; this copy is the floor that still
    /// holds when the owner's does not — a radio whose owner is wired wrong, or not wired at all,
    /// must not seat a second device.
    nonisolated static let maxTunnels = 1

    /// Inbound connections that may be mid-hello at once.
    ///
    /// A silent dialer is reaped by QUIC's own idle timeout — the same
    /// ``MeshHeartbeatSchedule/idleTimeoutMilliseconds`` the mesh declares — which ends the
    /// connection and throws its owning task out of `inboundStreams`. That is deliberately the
    /// only reaper: a sweep would need a clock, and this radio owns no timer.
    nonisolated static let maxPendingInbound = 2

    /// Frames one tunnel may deliver before its receive loop retires (Power of 10 rule 2). Three
    /// orders of magnitude above a recipe exchange, which is a sealed introduction and one share.
    nonisolated static let maxInboundFramesPerConnection = 2_000

    /// Browse results considered in one callback. Bounded for the same reason the other radios
    /// bound theirs: a crowded room is untrusted input.
    nonisolated static let maxBrowsedEndpoints = MeshSessionIdentityMap.maxTrackedEndpoints

    /// Bytes of per-session salt behind ``peerLabel(for:)`` — 256 bits, drawn once per session.
    nonisolated static let peerLabelSaltByteCount = 32

    /// Characters of the salted digest one peer label carries.
    nonisolated static let peerLabelLength = 12

    /// The label a peer gets when this session has no salt to hide it behind — the fail-closed
    /// direction, and the only branch of ``peerLabel(for:)`` that is not a digest.
    nonisolated static let unlabelledPeer = "unlabelled"

    /// Frozen diagnostic English for the benign close that collapses a double dial.
    ///
    /// Deliberately not a ``MeshTransportError``: nothing failed and nothing was refused. It leads
    /// with its own token so a log reader — and the tier-2 runner's grep — can tell a collapsed
    /// duplicate from a rejected peer at a glance. Never localized, never user copy.
    nonisolated static let redundantTunnelCloseReason =
        "redundantTunnelClosed: a duplicate recipe-share connection to one peer was collapsed."

    private static let logger = Logger(subsystem: "com.fernlet", category: "proximity.recipe.quic")

    // MARK: Hooks

    /// A peer appeared in the browse results, with its advertisement.
    var onPeerDiscovered: ((PeerHandle) -> Void)?
    /// A peer left the browse results.
    var onPeerLost: ((PeerHandle) -> Void)?
    /// A tunnel came up and its channel is live.
    var onPeerChannelReady: ((NetworkPeerChannel) -> Void)?
    /// A tunnel went down, with a diagnostic reason.
    var onPeerDisconnected: ((PeerHandle, String) -> Void)?
    /// Invoked with frozen diagnostic English when the listener or browser fails to start. Without
    /// it a missing `NSBonjourServices` entry or a declined Local Network prompt is silent.
    var onTransportError: ((String) -> Void)?
    /// Resolves an inbound dialer's claimed session id to the browsed peer it names, or nil to
    /// refuse the connection. **Fails closed**: a radio nobody has wired resolves nobody.
    var resolveDialer: ((String) -> PeerHandle?)?
    /// The owner's inbound admission gate. **Fails closed** for the same reason.
    var shouldAcceptDialer: ((PeerHandle) -> Bool)?

    // MARK: State

    /// One live or in-flight tunnel. `controlStream != nil` is the readiness test: a connection
    /// that never got one is still connecting, and one that had a stream and lost it disconnected.
    private struct Tunnel {

        /// The peer this tunnel carries.
        let peer: PeerHandle

        /// The channel the owner was handed, or will be handed at activation.
        let channel: NetworkPeerChannel

        /// Which end opened this connection, named from **this** device: `.initiator` is a tunnel
        /// ``dial(_:helloSID:)`` opened, `.responder` one ``serveInbound(stream:pendingKey:)``
        /// accepted. The discriminator the glare tie-break ranks against an arriving connection.
        let role: MeshChannelRole

        /// The peer's control stream, recorded at activation.
        var controlStream: Network.QUIC.Stream<QUICStream>?

        /// The connection every per-transfer stream is opened on. Recorded at activation beside
        /// the control stream, which is what makes "a transfer stream can never carry a frame from
        /// a connection this radio has not admitted" structural rather than checked.
        var connection: NetworkConnection<QUIC>?

        /// Which frames earn a stream of their own, and how many may be open at once. Held **in**
        /// the tunnel so a budget can never outlive the link it bounded.
        var transfers = MeshTransferStreamTable()

        /// Owns the connection: cancelling it is how the connection is torn down.
        var task: Task<Void, Never>?

        /// Owns the inbound transfer-stream acceptor on the dialing side. The listening side has
        /// no such task — its `inboundStreams` acceptor is already running and routes every stream
        /// past the control one itself.
        var transferAcceptorTask: Task<Void, Never>?

        /// Cancels every task this tunnel owns.
        func cancelTasks() {
            task?.cancel()
            transferAcceptorTask?.cancel()
        }
    }

    private var tunnels: [MeshLinkKey: Tunnel] = [:]
    private var pendingInbound: [MeshLinkKey: Task<Void, Never>] = [:]
    private var identities = MeshSessionIdentityMap()
    private var browsedEndpoints: [MeshLinkKey: Bonjour.Endpoint] = [:]
    private var browsedRecords: [MeshLinkKey: MeshEndpointRecord] = [:]
    private var listener: NetworkListener<QUIC>?
    private var browser: NetworkBrowser<Bonjour>?
    private var listenerTask: Task<Void, Never>?
    private var browserTask: Task<Void, Never>?
    private var listenerIsReady = false
    private var listenerIsAdvertised = false

    /// The posture this radio is wearing — the ONLY source of the advertised instance name, the
    /// TLS identity and the session id. Minted here, per ``start()`` and per
    /// ``resumeDiscovery()``, and dropped by ``stop()``.
    private var posture: RecipeSharePosture?

    /// The owner's half of the TXT record, recorded at ``start(advertisement:)`` so a resume can
    /// republish it under the new posture without asking the owner again.
    private var ownerFields: [String: String] = [:]

    /// The instance name the PREVIOUS posture advertised, kept across exactly one browse cycle.
    ///
    /// A re-mint withdraws a registration and publishes another, and an mDNS cache does not forget
    /// the withdrawn one at the same instant: an echo of THIS device's own previous name passes a
    /// filter that knows only the current one, and the owner's second layer compares the CURRENT
    /// `sid`, so the stale record matches neither. The user's own device then sits in the user's
    /// own picker and fails at the connect timeout. Cleared by the first browse cycle after the
    /// mint, so at most two names are ever excluded.
    private var previousInstanceName: String?

    /// The inbound connection whose hello is being adjudicated right now, excluded from the
    /// connecting window for exactly that adjudication.
    ///
    /// ``acceptInbound(_:)`` has to book a pending connection BEFORE the hello can be read — there
    /// is nothing to read it with otherwise — so by the time the owner's gate is asked, the very
    /// connection it is ruling on is already sitting in `pendingInbound`. Without this exclusion
    /// ``hasConnectingPeers(besides:)`` answers "something else is mid-connect" about the
    /// connection itself, and an owner whose gate ends in that question refuses **every** inbound
    /// dial there is. The retired radio had no such window: it asked its invitation gate first and
    /// registered the pending peer only after an accept.
    ///
    /// Set and cleared inside one synchronous main-actor run
    /// (``adjudicateInbound(_:pendingKey:)``), so one slot is enough for the two connections
    /// ``maxPendingInbound`` allows: they adjudicate strictly one after the other, and each counts
    /// the other.
    private var adjudicatingInbound: MeshLinkKey?

    private(set) var isRunning = false

    /// Whether ``pauseDiscovery()`` is holding this radio.
    ///
    /// **Cleared by ``stop()``.** ``RecipeShareDiscoveryGate``'s three "unchanged" rows —
    /// `refreshRequested`, `transportErrorWhileListening` and `stopped` — all resolve through the
    /// radio's own `stop()`/`start()` rather than through the gate, which is only true if the flag
    /// resets in this teardown. A pause that survived a stop would leave the next `start()`
    /// advertising behind a radio that believes it is open, or not advertising at all.
    private(set) var isDiscoveryPaused = false

    /// Set only by ``runWithoutRadiosForTesting(advertisement:)``: every decision this class makes
    /// runs, and the two framework objects are not built.
    ///
    /// A unit test must never bring up a real `NetworkListener` — it registers a Bonjour service on
    /// the machine running the suite. The alternative to this flag is a test that reaches past the
    /// production entry points and sets the state they would have set, which is how a cell comes to
    /// pass over the very line it was written for (the pause/resume re-mint is exactly such a
    /// line). Shipping code never reads it and nothing sets it in shipping code.
    private var radiosSuppressed = false

    /// The random salt every peer label in this session's diagnostics is taken under.
    ///
    /// Drawn once at construction and never again: not persisted, not advertised, not on the wire,
    /// and gone with the session. It is what makes ``peerLabel(for:)`` opaque *to a reader who
    /// holds the peer's name* — a ``MeshLinkKey`` under this radio is the browsed Bonjour
    /// endpoint's id, which contains the peer's advertised instance name verbatim, and an unsalted
    /// digest of it would be recomputable by anyone who can hash.
    private let peerLabelSalt: [UInt8] =
        PresenceEpochPosture.systemEntropy(NetworkRecipeShareSession.peerLabelSaltByteCount)

    /// The session id this radio is advertising, or "" while it is down.
    var advertisedSessionID: String { posture?.sessionID ?? "" }

    /// Peers this radio currently holds a tunnel to, in no particular order.
    var connectedPeers: [PeerHandle] { tunnels.values.map(\.peer) }

    init() {}

    /// Cancels every task this radio owns (memory-lifecycle rule ML1). ``stop()`` already does it;
    /// this is for the owner that is released without calling it.
    isolated deinit {
        listenerTask?.cancel()
        browserTask?.cancel()
        for tunnel in tunnels.values { tunnel.cancelTasks() }
        for task in pendingInbound.values { task.cancel() }
    }

    // MARK: - Lifecycle

    /// Brings the radio up under a freshly minted posture, advertising `advertisement` beside the
    /// posture's own session id.
    ///
    /// Throws rather than reporting, because the owner's `start()` is the one caller and it stands
    /// the radio down on a failure — the `didNotStart*` shape P8 item 0's device finding (b)
    /// fixed.
    func start(advertisement: [String: String]) throws {
        guard !isRunning else { return }
        ownerFields = advertisement
        posture = try RecipeSharePosture.minted()
        isRunning = true
        isDiscoveryPaused = false
        do {
            try startListener()
        } catch {
            isRunning = false
            posture = nil
            throw error
        }
    }

    /// Tears the radio down and drops everything it was holding — including the posture and the
    /// pause flag, so a stood-down radio keeps no name, no identity and no hold to come back up
    /// under.
    func stop() {
        let stopped = isRunning
        for tunnel in tunnels.values { tunnel.cancelTasks() }
        for task in pendingInbound.values { task.cancel() }
        cancelListener()
        cancelBrowser()
        tunnels.removeAll()
        pendingInbound.removeAll()
        browsedEndpoints.removeAll()
        browsedRecords.removeAll()
        identities.removeAll()
        ownerFields.removeAll()
        posture = nil
        isRunning = false
        isDiscoveryPaused = false
        guard stopped else { return }
        FernletAuditLog.log("recipe.quic.stopped", context: [:])
    }

    /// Stands the listener AND the browser down while keeping every live tunnel — the whole of
    /// "the radio closes once two devices connect".
    ///
    /// Both halves are load-bearing. Standing the **listener** down is the only way to withdraw
    /// the Bonjour registration, so a third Fernlet stops seeing this one; standing the **browser**
    /// down is what stops this one seeing a third. What the pause deliberately does NOT touch is
    /// the pairing: an outbound tunnel is its own connection and an inbound one is owned by its own
    /// task, neither by the listener, so a share in flight is untouched by the very event that
    /// closes the door behind it. ``RecipeShareTransfer``'s pause rows are the wall against getting
    /// that wrong.
    func pauseDiscovery() {
        guard isRunning, !isDiscoveryPaused else { return }
        isDiscoveryPaused = true
        cancelBrowser()
        cancelListener()
        FernletAuditLog.log("recipe.quic.paused", context: ["tunnels": String(tunnels.count)])
    }

    /// Reopens a paused radio under a **wholly new posture**: a fresh instance name, a fresh TLS
    /// identity and a fresh session id.
    ///
    /// Re-minting rather than re-advertising the old name is deliberate. A pause and its resume
    /// bracket a pairing, and the device is on the air on both sides of it; coming back under the
    /// same name would hand any passive scanner in the room "the device that went quiet at 19:04 is
    /// the device that came back at 19:11", which is exactly the link the ephemeral posture exists
    /// to break. The cost is one key pair per pairing, on a radio that mints one per tab visit
    /// anyway.
    func resumeDiscovery() {
        guard isRunning, isDiscoveryPaused else { return }
        do {
            // Mint BEFORE the flag clears. A mint that threw with the flag already down would
            // leave an unpaused radio wearing the PRE-PAUSE posture and answering
            // `advertisedSessionID` with a `sid` it has already withdrawn — which the owner would
            // then write into a dial hello. The flag clears only once there is a posture to wear.
            let fresh = try RecipeSharePosture.minted()
            previousInstanceName = posture?.instanceName
            posture = fresh
            isDiscoveryPaused = false
            try startListener()
            FernletAuditLog.log("recipe.quic.resumed", context: auditContext(for: fresh))
        } catch {
            report("The recipe-share listener could not be resumed: \(error)")
        }
    }

    // MARK: - Dialing

    /// Opens a tunnel to a browsed peer and writes the dial hello claiming `helloSID`.
    ///
    /// The owner's call, not this radio's — the recipe radio dials only when the user has picked a
    /// recipient, and the decision of when belongs with the gates that own it.
    ///
    /// A dial this radio cannot make is a **dial refusal and nothing more**: it is logged and the
    /// call returns. It is emphatically not a ``report(_:)``, because that hook is the owner's
    /// START-failure door and it stands the whole radio down. The reachable miss is routine — a
    /// peer whose registration went away between the picker row being drawn and the user tapping
    /// it — and the owner already surfaces that as its own connect timeout.
    func dial(_ peer: PeerHandle, helloSID: String) {
        guard isRunning else { return }
        guard let key = identities.key(for: peer) else {
            // The peer's identity aged out of the bounded map between the picker row being drawn
            // and the tap. The only branch of this audit that cannot name its peer: there is no
            // key left to take a label from.
            FernletAuditLog.log(
                "recipe.quic.dialRefused",
                context: ["peer": Self.unlabelledPeer, "reason": "identityAgedOut"]
            )
            return
        }
        guard let endpoint = browsedEndpoints[key] else {
            auditDialRefused(key, reason: "noBrowsedEndpoint")
            return
        }
        guard tunnels[key] == nil, tunnels.count < Self.maxTunnels else {
            auditDialRefused(key, reason: "tunnelHeld")
            return
        }
        let connection = NetworkConnection(
            to: endpoint,
            using: ProximityQUICParameters.connection(alpn: Self.alpn)
        ).start()
        let channel = prepareChannel(for: key)
        tunnels[key] = Tunnel(peer: channel.peer, channel: channel, role: .initiator)
        tunnels[key]?.task = Task { @MainActor [weak self] in
            await self?.runInitiator(connection, key: key, helloSID: helloSID)
        }
    }

    /// Ends a peer's tunnel at the owner's request, without reporting it back to the owner.
    ///
    /// `notifyOwner: false` is the load-bearing half: this is an eviction the owner *asked* for,
    /// and the disconnect hook fires synchronously, so telling the owner would re-enter its own
    /// eviction path from inside it.
    func endTunnel(_ peer: PeerHandle) {
        guard let key = identities.key(for: peer) else { return }
        endTunnel(key, reason: "This peer's recipe-share connection was closed locally.", notifyOwner: false)
    }

    /// Whether any peer other than `peer` is mid-connect.
    ///
    /// The connecting-window half of the hard 2-device cap, and the QUIC counterpart of the
    /// retired radio's pending-connection set. Two populations count: a tunnel whose control
    /// stream has not arrived yet (our own dial, in flight) and an inbound connection that is
    /// mid-hello — every one of those **except** the connection currently being adjudicated, which
    /// is the one the caller is ruling on. A connection that counted itself would refuse every
    /// inbound dial there is; a SECOND one that went uncounted would let two devices past the cap.
    /// See ``adjudicatingInbound``.
    func hasConnectingPeers(besides peer: PeerHandle?) -> Bool {
        guard pendingInbound.keys.allSatisfy({ $0 == adjudicatingInbound }) else { return true }
        let excluded = peer.flatMap { identities.key(for: $0) }
        for (key, tunnel) in tunnels where key != excluded && tunnel.controlStream == nil {
            return true
        }
        return false
    }

    /// Hands a START failure to the owner's transport-error hook, which stands the radio down.
    /// Never a per-dial or per-connection refusal — see ``dial(_:helloSID:)``.
    func reportTransportError(_ message: String) {
        report(message)
    }

    // MARK: - NetworkChannelHost

    /// Sends one frame to the paired peer.
    ///
    /// A recipe crosses as ONE sealed frame, and which pipe it rides is decided by its size alone:
    /// a frame at or above ``MeshTransferStreamTable/bulkFloorBytes`` — a recipe carrying a
    /// picture — takes a stream of its own, and everything smaller rides the tunnel's control
    /// stream in order. `mode` is accepted and ignored: this radio negotiates no datagram flow, and
    /// delivering a frame more reliably than asked is always allowed while dropping it silently is
    /// not.
    func send(_ data: Data, to peer: PeerHandle, mode: PeerDeliveryMode) async throws {
        guard let key = identities.key(for: peer), let tunnel = tunnels[key] else {
            throw PeerTransportError.unexpectedState
        }
        guard data.count <= Self.maxInboundWireBytes else {
            throw PeerTransportError.sendFailed(
                reason: MeshTransportError.oversizedFrame(byteCount: data.count).diagnosticDescription
            )
        }
        if let claim = claimTransferStream(key, byteCount: data.count) {
            try await sendOverTransferStream(data, key: key, claim: claim)
            return
        }
        guard let stream = tunnel.controlStream else {
            throw PeerTransportError.sendFailed(
                reason: MeshTransportError.noControlStream.diagnosticDescription
            )
        }
        var frame = NetworkMeshWire.header(for: data.count)
        frame.append(data)
        do {
            try await stream.send(frame)
        } catch {
            throw PeerTransportError.sendFailed(reason: error.localizedDescription)
        }
    }

    /// How many per-transfer streams are open on the peer's tunnel, outbound plus inbound.
    ///
    /// Zero on a settled tunnel. The read exists so a test — and a Lane C transcript — can assert
    /// that a picture recipe released its slot rather than infer it from a later send succeeding.
    func openTransferCount(for peer: PeerHandle) -> Int {
        guard let key = identities.key(for: peer), let tunnel = tunnels[key] else { return 0 }
        return tunnel.transfers.outbound.openCount + tunnel.transfers.inbound.openCount
    }

    // MARK: - Peer labels

    /// The opaque, session-scoped label this radio names `key` by in **every** diagnostic line it
    /// writes — the audit rows and the `os.Logger` lines alike.
    ///
    /// The first ``peerLabelLength`` hexadecimal characters of SHA-256 over this session's random
    /// ``peerLabelSalt`` followed by the key's bytes. The same rule, and the same three reasons, as
    /// `NetworkPresenceSession.peerLabel(for:)`: a ``MeshLinkKey`` looks opaque and is not (it is
    /// the browsed endpoint id, which carries the peer's advertised instance name verbatim); an
    /// unsalted digest is recomputable by anyone holding that public name; and the label must stay
    /// stable within the session so a sighting, a collapse and a teardown read as one peer's story.
    func peerLabel(for key: MeshLinkKey) -> String {
        guard !peerLabelSalt.isEmpty else { return Self.unlabelledPeer }
        var hasher = SHA256()
        hasher.update(data: Data(peerLabelSalt))
        hasher.update(data: Data(key.rawValue.utf8))
        let hexadecimal = PresenceEpochPosture.hexadecimal(Array(hasher.finalize()))
        return String(hexadecimal.prefix(Self.peerLabelLength))
    }

    // MARK: - Test seam

    /// The instance name this radio is advertising right now, or nil while it is down.
    var advertisedInstanceNameForTesting: String? { posture?.instanceName }

    /// The certificate this radio is presenting right now, or nil while it is down — the read that
    /// lets a cell say a resume re-minted the identity and not only the name.
    var advertisedCertificateForTesting: Data? { posture?.tlsIdentity.certificateDER }

    /// The TXT fields this radio would put on the air right now.
    var advertisedFieldsForTesting: [String: String] {
        guard let posture else { return [:] }
        return RecipeShareAdvertisement.publishedFields(
            from: ownerFields, sessionID: posture.sessionID
        )
    }

    /// How many tunnels are live.
    var tunnelCountForTesting: Int { tunnels.count }

    /// How many inbound connections are mid-hello.
    var pendingInboundCountForTesting: Int { pendingInbound.count }

    /// Which end of a peer's surviving connection this radio is holding, or nil for no tunnel.
    func tunnelRoleForTesting(at key: MeshLinkKey) -> MeshChannelRole? { tunnels[key]?.role }

    /// Brings this radio up WITHOUT a listener or a browser: it wears a freshly minted posture and
    /// reads as running, which is every precondition ``dial(_:helloSID:)``, ``admitInbound(at:)``
    /// and ``resolveInbound(_:)`` test, and nothing at all that touches Bonjour.
    ///
    /// ``start(advertisement:)`` creates a real `NetworkListener`, which a unit test must never do.
    @discardableResult
    func runWithoutRadiosForTesting(advertisement: [String: String] = [:]) throws -> RecipeSharePosture {
        radiosSuppressed = true
        try start(advertisement: advertisement)
        guard let posture else { throw MeshTransportError.tlsIdentityUnavailable }
        return posture
    }

    /// The session-stable handle for an endpoint key, minting the identity exactly as a browse
    /// result does.
    func handleForTesting(_ key: MeshLinkKey) -> PeerHandle { handle(for: key) }

    /// Records a browsed endpoint's instance name exactly as ``noteBrowsed(_:key:at:)`` records it,
    /// minus the framework endpoint a unit test cannot build. That name is the peer's half of the
    /// tie-break.
    func noteBrowsedNameForTesting(_ key: MeshLinkKey, instanceName: String) {
        browsedRecords[key] = MeshEndpointRecord(
            key: key,
            instanceName: instanceName,
            advertisement: [:],
            lastSeenAt: Date()
        )
    }

    /// Drives one whole SIGHTING exactly as a browse result drives it — the record, the
    /// `recipe.quic.sighted` audit line and the owner's discovery callback — minus the framework
    /// endpoint a unit test cannot build.
    func noteBrowsedForTesting(
        _ key: MeshLinkKey,
        instanceName: String,
        advertisement: [String: String]
    ) {
        recordBrowsed(key: key, instanceName: instanceName, advertisement: advertisement, at: Date())
    }

    /// Books a tunnel exactly as ``dial(_:helloSID:)`` and ``serveInbound(stream:pendingKey:)``
    /// record one, minus the framework connection and stream a unit test cannot build.
    func bookTunnelForTesting(_ key: MeshLinkKey, role: MeshChannelRole) {
        let channel = prepareChannel(for: key)
        tunnels[key] = Tunnel(peer: channel.peer, channel: channel, role: role)
    }

    /// Runs the glare gate ``serveInbound(stream:pendingKey:)`` runs, and answers exactly what it
    /// answers: may an inbound connection that resolved to `key` take that key's tunnel slot?
    func admitInboundForTesting(at key: MeshLinkKey) -> Bool {
        admitInbound(at: key)
    }

    /// Runs the whole inbound resolution ``serveInbound(stream:pendingKey:)`` runs on a decoded
    /// hello: the self-dial refusal, the owner's resolver and the owner's admission gate.
    func resolveInboundForTesting(_ hello: RecipeShareDialHello) -> PeerHandle? {
        resolveInbound(hello)
    }

    /// Books a pending inbound connection exactly as ``acceptInbound(_:)`` books one — BEFORE any
    /// hello can be read — minus the framework connection a unit test cannot build.
    func bookPendingInboundForTesting(_ pendingKey: MeshLinkKey) {
        pendingInbound[pendingKey] = Task { @MainActor in }
    }

    /// Runs the whole adjudication ``serveInbound(stream:pendingKey:connection:)`` runs on a
    /// decoded hello — the owner's gate asked with this connection excluded from the connecting
    /// window — and answers the key it admitted, or nil for a refusal.
    func adjudicateInboundForTesting(
        _ hello: RecipeShareDialHello,
        pendingKey: MeshLinkKey
    ) -> MeshLinkKey? {
        adjudicateInbound(hello, pendingKey: pendingKey)?.key
    }

    /// Runs the browser-failure classifier ``browserStateChanged(_:)`` routes a `.failed` through,
    /// minus the framework error a unit test cannot build.
    func reportBrowserFailureForTesting(_ message: String) {
        reportBrowserFailure(message)
    }

    /// Runs the withdrawn-registration path ``listenerRegistrationChanged(_:)``'s `.remove` branch
    /// runs, minus the framework endpoint a unit test cannot build.
    func republishListenerForTesting() {
        republishListener()
    }

    /// Whether this radio holds a browser right now — the read that lets a cell say a browser
    /// failure stood the browser down without standing the radio down.
    var hasBrowserForTesting: Bool { browser != nil }

    /// Claims one outbound transfer slot on a booked tunnel — the **budget** half of what
    /// ``send(_:to:mode:)`` does, minus the framework connection a unit test cannot build. Nil
    /// means "send it on the control stream", whether because the frame is under the floor or
    /// because the direction is full.
    func claimOutboundTransferForTesting(_ key: MeshLinkKey, byteCount: Int) -> MeshTransferID? {
        guard var tunnel = tunnels[key],
              let id = tunnel.transfers.openOutbound(reliableByteCount: byteCount) else { return nil }
        tunnels[key] = tunnel
        return id
    }

    /// Releases one outbound transfer slot, exactly as ``sendOverTransferStream(_:key:claim:)``'s
    /// `defer` releases it on both the success and the failure path.
    func releaseOutboundTransferForTesting(_ key: MeshLinkKey, id: MeshTransferID) {
        tunnels[key]?.transfers.closeOutbound(id)
    }

    /// Takes one inbound transfer slot on a tunnel, exactly as the acceptor takes one — the read
    /// that lets a cell drive the budget to exhaustion without a framework stream.
    func claimInboundTransferForTesting(_ key: MeshLinkKey) -> MeshTransferID? {
        claimInboundTransfer(key)
    }

    /// The channel this radio would hand the owner for `peer`, built exactly as the live path
    /// builds one. ``RecipeShareRadioSession`` requirement.
    func channel(for peer: PeerHandle) -> NetworkPeerChannel {
        NetworkPeerChannel(peer: peer, host: self)
    }
}

// MARK: - Listener and browser

private extension NetworkRecipeShareSession {

    /// Brings up the QUIC listener over Bonjour under the posture's name and identity.
    func startListener() throws {
        guard let posture else { throw MeshTransportError.tlsIdentityUnavailable }
        guard !radiosSuppressed else {
            FernletAuditLog.log("recipe.quic.advertised", context: auditContext(for: posture))
            return
        }
        let fields = RecipeShareAdvertisement.publishedFields(
            from: ownerFields, sessionID: posture.sessionID
        )
        let listener = try NetworkListener(
            for: .bonjour(
                name: posture.instanceName,
                type: Self.serviceType,
                txtRecord: NWTXTRecord(fields)
            ),
            using: ProximityQUICParameters.listener(
                alpn: Self.alpn,
                identity: posture.tlsIdentity.identity
            )
        ).newConnectionLimit(Self.maxTunnels + Self.maxPendingInbound)
        self.listener = listener
        listener.onStateUpdate { [weak self] _, state in
            Task { @MainActor in self?.listenerStateChanged(state) }
        }
        listener.onServiceRegistrationUpdate { [weak self] _, change in
            Task { @MainActor in self?.listenerRegistrationChanged(change) }
        }
        listenerTask = Task { @MainActor [weak self, listener] in
            do {
                try await listener.run { connection in
                    self?.acceptInbound(connection)
                }
            } catch {
                // A cancel is this radio tidying itself, never a failure: ``pauseDiscovery()``
                // cancels this task every time a pairing forms, because standing the listener down
                // is the only way to withdraw a Bonjour registration. Reporting a
                // `CancellationError` would hand the owner a start failure and stand the whole
                // radio down on the very event that is supposed to keep it up and quiet.
                guard !Task.isCancelled else { return }
                self?.report("The recipe-share listener stopped: \(error)")
            }
        }
        FernletAuditLog.log("recipe.quic.advertised", context: auditContext(for: posture))
    }

    /// Stands the listener down and forgets it, keeping every tunnel.
    func cancelListener() {
        listenerTask?.cancel()
        listenerTask = nil
        listener = nil
        listenerIsReady = false
        listenerIsAdvertised = false
    }

    /// Stands the browser down and forgets it, keeping every tunnel.
    func cancelBrowser() {
        browserTask?.cancel()
        browserTask = nil
        browser = nil
    }

    /// Starts browsing once the listener is both ready and advertised — browsing earlier finds
    /// peers this device cannot yet be found by.
    func startBrowser() {
        guard isRunning, !isDiscoveryPaused, browser == nil else { return }
        let browser = NetworkBrowser(
            for: .bonjour(Self.serviceType, includeTxtRecord: true),
            using: ProximityQUICParameters.connection(alpn: Self.alpn).parameters
        )
        self.browser = browser
        browser.onStateUpdate { [weak self] _, state in
            Task { @MainActor in self?.browserStateChanged(state) }
        }
        browserTask = Task { @MainActor [weak self, browser] in
            do {
                try await browser.run { endpoints in
                    self?.observe(endpoints)
                }
            } catch {
                // Same rule as the listener task above: ``pauseDiscovery()`` and ``stop()`` both
                // cancel this one, and a cancellation reported as a start failure stands the radio
                // down on the way down.
                guard !Task.isCancelled else { return }
                self?.reportBrowserFailure("The recipe-share browser stopped: \(error)")
            }
        }
    }

    func listenerStateChanged(_ state: NetworkListener<QUIC>.State) {
        guard isRunning, !isDiscoveryPaused else { return }
        switch state {
        case .ready:
            listenerIsReady = true
            startBrowserWhenReady()
        case .waiting(let error):
            Self.logger.debug("recipe listener waiting: \(error.localizedDescription, privacy: .public)")
        case .failed(let error):
            report("The recipe-share listener failed: \(error.localizedDescription)")
        case .setup, .cancelled:
            break
        @unknown default:
            break
        }
    }

    func listenerRegistrationChanged(_ change: NetworkListener<QUIC>.ServiceRegistrationChange) {
        guard isRunning, !isDiscoveryPaused else { return }
        switch change {
        case .add:
            listenerIsAdvertised = true
            startBrowserWhenReady()
        case .remove:
            listenerIsAdvertised = false
            republishListener()
        @unknown default:
            break
        }
    }

    /// Re-mints and re-listens after the service registration was withdrawn under a running,
    /// unpaused radio.
    ///
    /// Left silent this is P8 item 0's device finding (b) in its exact shape: nothing on the air,
    /// `listenerIsAdvertised` the only thing that noticed, and the owner's `isListening` — which is
    /// its `isRunning` — answering yes forever. This radio publishes exactly once per
    /// `start()`/`resumeDiscovery()` and owns no timer, so nothing would ever republish it;
    /// ``NetworkPresenceSession`` survives the same event only because its 900 s epoch boundary
    /// republishes its listener anyway.
    ///
    /// Coming back under a FRESH posture rather than re-publishing the withdrawn name is the same
    /// decision ``resumeDiscovery()`` makes, for the same reason: a name that went away and came
    /// back is a link. ``startListener()`` writes the `recipe.quic.advertised` line that says the
    /// radio is back, and a republish that cannot mint or cannot listen reaches ``report(_:)``, so
    /// the failure is an honest stand-down and never a silently dark radio. There is no flap loop
    /// in it: a `.remove` follows an `.add`, and a republish that never registers never gets one.
    func republishListener() {
        FernletAuditLog.log("recipe.quic.registrationWithdrawn", context: [:])
        cancelListener()
        do {
            let fresh = try RecipeSharePosture.minted()
            previousInstanceName = posture?.instanceName
            posture = fresh
            try startListener()
        } catch {
            report("The recipe-share listener could not be republished: \(error)")
        }
    }

    func startBrowserWhenReady() {
        guard listenerIsReady, listenerIsAdvertised else { return }
        startBrowser()
    }

    func browserStateChanged(_ state: NetworkBrowser<Bonjour>.State) {
        guard isRunning, !isDiscoveryPaused else { return }
        switch state {
        case .failed(let error):
            reportBrowserFailure("The recipe-share browser failed: \(error.localizedDescription)")
        case .waiting(let error):
            Self.logger.debug("recipe browser waiting: \(error.localizedDescription, privacy: .public)")
        case .ready, .setup, .cancelled:
            break
        @unknown default:
            break
        }
    }

    /// The diagnostic context for one posture: this device's OWN instance name and certificate
    /// digest, under `FernletAuditLog`'s `.private` redaction.
    ///
    /// Every value here is ours, which is the whole of the exception — it is what a tier-2 runner
    /// reads a pause and its resume off, on each device, with no byte in common. No PEER's name is
    /// logged anywhere in this file; a browsed peer is named by ``peerLabel(for:)``.
    func auditContext(for posture: RecipeSharePosture) -> [String: String] {
        [
            "name": posture.instanceName,
            "certificate": Self.certificateDigest(of: posture)
        ]
    }

    /// The first 16 hexadecimal characters of the SHA-256 of a posture's certificate — a per-mint
    /// label for a diagnostic line, never an identity and never on the wire. Not a cryptographic
    /// decision: nothing compares two of these.
    static func certificateDigest(of posture: RecipeSharePosture) -> String {
        let digest = SHA256.hash(data: posture.tlsIdentity.certificateDER)
        return String(PresenceEpochPosture.hexadecimal(Array(digest)).prefix(16))
    }

    func report(_ message: String) {
        Self.logger.error("\(message, privacy: .public)")
        onTransportError?(message)
    }

    /// A BROWSER failure, which is not a start failure and must not stand the radio down while
    /// anything is in flight.
    ///
    /// The browser is the *find* half. Under the retired transport this door was reachable only
    /// from `didNotStartBrowsingForPeers` — at start and nowhere else — so routing it to the
    /// owner's stand-down hook was right by construction. A QUIC browser fails at runtime too (an
    /// interface going away mid-evening), and a stand-down cancels every tunnel and every pending
    /// connection: a browse failure arriving while the user's dial was in flight would abort the
    /// tap and clear the picker, for an event a dial in flight does not need a browser for.
    ///
    /// So the browser is stood down here and audited, and the message still reaches the owner —
    /// which records it as a diagnostic and, since the fix, applies its stand-down only when
    /// nothing is held and nothing is mid-connect. A browser stood down under a live pairing is
    /// re-created by the next ``resumeDiscovery()``; one stood down under a dial, by the owner's
    /// own refresh.
    func reportBrowserFailure(_ message: String) {
        cancelBrowser()
        let busy = !tunnels.isEmpty || hasConnectingPeers(besides: nil)
        FernletAuditLog.log("recipe.quic.browserFailed", context: ["busy": String(busy)])
        report(message)
    }

    /// The one audit line for a dial this radio would not make. A refusal, never a failure: it
    /// never reaches ``report(_:)`` and never stands the radio down.
    func auditDialRefused(_ key: MeshLinkKey, reason: String) {
        FernletAuditLog.log(
            "recipe.quic.dialRefused",
            context: ["peer": peerLabel(for: key), "reason": reason]
        )
    }
}

// MARK: - Discovery

private extension NetworkRecipeShareSession {

    /// One browse result set: refresh what is known, announce arrivals, announce departures.
    ///
    /// The local advertisement is filtered out by instance name — the posture's, which is minted
    /// here, plus the one a re-mint has just withdrawn — rather than by session id alone, so an
    /// echo of this device's own registration is dropped before it can reach the owner even if the
    /// TXT record has not arrived with it. See ``previousInstanceName``.
    func observe(_ endpoints: [Bonjour.Endpoint]) {
        guard isRunning, !isDiscoveryPaused else { return }
        let now = Date()
        // At most two names, and the second only until this cycle ends.
        let ownNames = Set([posture?.instanceName, previousInstanceName].compactMap { $0 })
        previousInstanceName = nil
        var seen: Set<MeshLinkKey> = []
        for endpoint in endpoints.prefix(Self.maxBrowsedEndpoints) where !ownNames.contains(endpoint.name) {
            let key = MeshLinkKey(endpoint.id)
            seen.insert(key)
            noteBrowsed(endpoint, key: key, at: now)
        }
        for key in Array(browsedEndpoints.keys) where !seen.contains(key) {
            noteLost(key)
        }
    }

    /// Records a browsed endpoint and announces it when it is new or its advertisement changed.
    ///
    /// Re-announcing on change is load-bearing: a Bonjour peer is routinely seen before its TXT
    /// record arrives, so a first sighting can carry no `name` and no `sid` at all, and the owner
    /// would never re-evaluate it if the late record went unannounced.
    func noteBrowsed(_ endpoint: Bonjour.Endpoint, key: MeshLinkKey, at now: Date) {
        browsedEndpoints[key] = endpoint
        recordBrowsed(
            key: key,
            instanceName: endpoint.name,
            advertisement: MeshLinkAdvertisement.advertisement(from: endpoint.txtRecord.dictionary),
            at: now
        )
    }

    /// The framework-free half of ``noteBrowsed(_:key:at:)``: everything a browse result does to
    /// this session's own state, the audit line included, with no `Bonjour.Endpoint` in sight.
    func recordBrowsed(
        key: MeshLinkKey,
        instanceName: String,
        advertisement: [String: String],
        at now: Date
    ) {
        let previous = browsedRecords[key]?.advertisement
        browsedRecords[key] = MeshEndpointRecord(
            key: key,
            instanceName: instanceName,
            advertisement: advertisement,
            lastSeenAt: now
        )
        guard previous != advertisement else { return }
        // The line names the peer by ``peerLabel(for:)`` and never by the endpoint key, which
        // CONTAINS the instance name the peer advertises; and it says only whether the record was
        // a recipe advertisement at all. Neither the peer's chosen name nor its session id is a
        // value a log is a good place to accumulate.
        FernletAuditLog.log(
            "recipe.quic.sighted",
            context: [
                "peer": peerLabel(for: key),
                "recipe": String(RecipeShareAdvertisement.isRecipeAdvertisement(advertisement))
            ]
        )
        onPeerDiscovered?(handle(for: key))
    }

    /// Drops an endpoint that left the browse results. Its cache entry survives only while a
    /// tunnel to it does, so a live pairing is never stranded without an endpoint to answer on.
    func noteLost(_ key: MeshLinkKey) {
        let peer = handle(for: key)
        browsedEndpoints.removeValue(forKey: key)
        if tunnels[key] == nil { browsedRecords.removeValue(forKey: key) }
        onPeerLost?(peer)
    }

    /// The session-stable handle for an endpoint.
    ///
    /// `advertisedFingerprint` is always nil: this radio publishes no `fp` and believes no inbound
    /// one. `displayHint` is deliberately **empty**, which is this handle's way of saying "no name
    /// from the transport".
    ///
    /// Under the retired transport the hint was a name a person had chosen for their phone
    /// (`UIDevice.current.name` — "Alex's iPhone"), and every reader of it rendered it as one.
    /// The only two tokens this radio could put there instead are the peer's random Bonjour
    /// instance name and the endpoint key that CONTAINS that name, and both are exactly what
    /// P9-2-A's salted peer labelling exists to keep out of anything anyone reads. An absent hint
    /// makes ``RecipeShareAdvertisedName/received(_:hint:)`` fall through to the picker's existing
    /// "A friend" placeholder for a peer that published no `name`, which is the right answer.
    func handle(for key: MeshLinkKey) -> PeerHandle {
        let identity = identities.identity(for: key)
        let record = browsedRecords[key]
        return PeerHandle(
            id: identity.id,
            displayHint: "",
            discoveryInfo: record?.advertisement,
            advertisedFingerprint: nil,
            endpoint: identity.endpoint
        )
    }

    /// The channel for an endpoint, reusing the live one so a reconnect does not orphan the
    /// publishers an owner is already subscribed to.
    func prepareChannel(for key: MeshLinkKey) -> NetworkPeerChannel {
        if let existing = tunnels[key]?.channel { return existing }
        return NetworkPeerChannel(peer: handle(for: key), host: self)
    }
}

// MARK: - Tunnels

private extension NetworkRecipeShareSession {

    /// Dialing side: open the control stream, write the dial hello, then read app frames.
    ///
    /// The channel is handed to the owner as soon as the hello is written rather than after any
    /// acknowledgement, because there is none to wait for: a responder that refuses the hello
    /// cancels its connection, which surfaces here as an ended tunnel and, above, as the owner's
    /// pre-connect timeout. That is the same shape the retired radio had — an invitation that is
    /// declined produces a disconnect, not a rejection message.
    func runInitiator(_ connection: NetworkConnection<QUIC>, key: MeshLinkKey, helloSID: String) async {
        do {
            let stream = try await connection.openStream()
            let hello = try RecipeShareDialHello.encoded(sessionID: helloSID)
            var frame = NetworkMeshWire.header(for: hello.count)
            frame.append(hello)
            try await stream.send(frame)
            activate(key, stream: stream, connection: connection)
            startTransferAcceptor(on: connection, key: key)
            try await receiveFrames(for: key, from: stream)
        } catch {
            guard !Task.isCancelled else { return }
            endTunnel(key, reason: "The outbound recipe-share connection ended: \(error.localizedDescription)")
        }
    }

    /// Takes an inbound QUIC connection as *pending*: nothing is admitted, no channel exists and no
    /// handle is minted for an owner until the dial hello has resolved to a browsed peer the owner
    /// accepts.
    func acceptInbound(_ connection: NetworkConnection<QUIC>) {
        guard isRunning, !isDiscoveryPaused else { return }
        let pendingKey = MeshLinkKey(connection.id)
        guard pendingInbound[pendingKey] == nil, pendingInbound.count < Self.maxPendingInbound else {
            Self.logger.debug(
                "recipe connection refused pre-hello for \(self.peerLabel(for: pendingKey), privacy: .public)"
            )
            return
        }
        pendingInbound[pendingKey] = Task { @MainActor [weak self] in
            await self?.runResponder(connection, pendingKey: pendingKey)
        }
    }

    /// Listening side: serve the peer's control stream, and every later stream as a transfer.
    ///
    /// The control stream is the peer's stream 0 and only ever that — the dialer opens exactly one
    /// before anything else — so the id alone names it, and any other stream is a per-transfer
    /// stream carrying a picture recipe.
    func runResponder(_ connection: NetworkConnection<QUIC>, pendingKey: MeshLinkKey) async {
        do {
            try await connection.inboundStreams { stream in
                guard stream.streamID == Self.controlStreamID else {
                    await self.serveTransferStream(stream, on: connection)
                    return
                }
                guard self.pendingInbound[pendingKey] != nil else { return }
                await self.serveInbound(stream: stream, pendingKey: pendingKey, connection: connection)
            }
        } catch {
            guard !Task.isCancelled else { return }
            dropPendingInbound(pendingKey)
        }
    }

    /// Reads the dial hello and, only if it resolves to a browsed peer the owner accepts and
    /// ``admitInbound(at:)`` gives it the slot, promotes the pending connection to a real tunnel.
    ///
    /// Every early return drops the pending connection whole: no channel is built and no handle is
    /// minted for an owner. That is the "no leakage" property, and it holds by construction —
    /// everything downstream needs a resolved ``PeerHandle`` this path does not have.
    ///
    /// The guard chain itself is ``adjudicateInbound(_:pendingKey:)``, which runs it with this
    /// connection excluded from the connecting window.
    func serveInbound(
        stream: Network.QUIC.Stream<QUICStream>,
        pendingKey: MeshLinkKey,
        connection: NetworkConnection<QUIC>
    ) async {
        guard let hello = await readDialHello(from: stream),
              let admitted = adjudicateInbound(hello, pendingKey: pendingKey) else {
            auditHelloRefused(pendingKey)
            dropPendingInbound(pendingKey)
            return
        }
        let key = admitted.key
        let channel = prepareChannel(for: key)
        tunnels[key] = Tunnel(peer: channel.peer, channel: channel, role: .responder, task: admitted.task)
        activate(key, stream: stream, connection: connection)
        do {
            try await receiveFrames(for: key, from: stream)
        } catch {
            guard !Task.isCancelled else { return }
            endTunnel(key, reason: "The inbound recipe-share connection ended: \(error.localizedDescription)")
        }
    }

    /// The whole SYNCHRONOUS half of inbound adjudication, run with `pendingKey` excluded from
    /// the connecting window: resolve the hello to a browsed peer the owner accepts, check the
    /// pending entry, take that peer's tunnel slot, and hand back the task owning the connection.
    ///
    /// The pending entry is checked BEFORE ``admitInbound(at:)`` and removed after, so the one
    /// guard in the chain with an effect (it may close a tunnel) can never run for a connection
    /// that has already been dropped — which is also what refuses a SECOND hello on one connection.
    ///
    /// There is deliberately no suspension point between the set and the `defer`: see
    /// ``adjudicatingInbound`` for why one slot is then enough.
    func adjudicateInbound(
        _ hello: RecipeShareDialHello,
        pendingKey: MeshLinkKey
    ) -> (key: MeshLinkKey, task: Task<Void, Never>)? {
        adjudicatingInbound = pendingKey
        defer { adjudicatingInbound = nil }
        guard let peer = resolveInbound(hello),
              let key = identities.key(for: peer),
              pendingInbound[pendingKey] != nil,
              admitInbound(at: key),
              let owning = pendingInbound.removeValue(forKey: pendingKey) else { return nil }
        return (key, owning)
    }

    /// The owner-facing half of inbound resolution: refuse our OWN session id, then ask the
    /// owner's resolver for the browsed peer that id names, then ask the owner's admission gate.
    ///
    /// Both hooks fail closed, and the self-dial refusal is this radio's own: a session id we are
    /// advertising can only reach us from an echo of our own registration or from a replay, and
    /// neither is a peer.
    func resolveInbound(_ hello: RecipeShareDialHello) -> PeerHandle? {
        guard hello.sessionID != posture?.sessionID else { return nil }
        guard let peer = resolveDialer?(hello.sessionID) else { return nil }
        guard shouldAcceptDialer?(peer) == true else { return nil }
        return peer
    }

    /// Whether an inbound connection that resolved to `key` may take that key's one tunnel slot,
    /// closing whatever it displaces — the glare resolution the type's ## Glare section describes.
    ///
    /// The verdict is the mesh's ``MeshTunnelConvergence``, computed over the two advertised
    /// **instance names** in place of the mesh's two session ids. They are the same shape of value
    /// — a random token each side publishes and the other browses — and they are the only pair of
    /// facts both devices hold and agree on here, because this radio runs no signed channel
    /// introduction and so has no verified identity to rank at this point.
    ///
    /// `.keepEstablished` drops the arriving connection and disturbs nothing; `.keepIncoming` (and
    /// the unrepresentable `.keepBoth`) ends the held tunnel with the owner TOLD, which is
    /// load-bearing rather than incidental: the owner's channel-ready gate answers "already
    /// connected" for a device it still holds a record for, so a yield that stayed quiet would hand
    /// the fresh channel to an owner that dropped it and leave a coordinator waiting on a dead
    /// connection. Answers `false` when either name is missing, which is the fail-closed direction.
    func admitInbound(at key: MeshLinkKey) -> Bool {
        guard let established = tunnels[key] else { return tunnels.count < Self.maxTunnels }
        guard let localName = posture?.instanceName,
              let peerName = browsedRecords[key]?.instanceName else { return false }
        let verdict = MeshTunnelConvergence.resolve(
            incomingRole: .responder,
            establishedRole: established.role,
            localSessionID: localName,
            peerSessionID: peerName
        )
        guard verdict != .keepEstablished else {
            auditRedundantTunnelClosed(key, kept: "established")
            return false
        }
        endTunnel(key, reason: Self.redundantTunnelCloseReason)
        auditRedundantTunnelClosed(key, kept: "incoming")
        return true
    }

    /// The one audit line for a collapsed duplicate, naming the peer by ``peerLabel(for:)`` and
    /// which half survived.
    func auditRedundantTunnelClosed(_ key: MeshLinkKey, kept: String) {
        FernletAuditLog.log(
            "recipe.quic.redundantTunnelClosed",
            context: ["peer": peerLabel(for: key), "kept": kept]
        )
    }

    /// The one audit line for an inbound connection refused at the hello. Named by the PENDING
    /// key — a connection id, not a browsed endpoint — because a refused dialer is by definition
    /// one this radio never resolved to a peer.
    func auditHelloRefused(_ pendingKey: MeshLinkKey) {
        FernletAuditLog.log(
            "recipe.quic.helloRefused",
            context: ["connection": peerLabel(for: pendingKey)]
        )
    }

    /// Reads exactly one length-framed ``RecipeShareDialHello``, or nil for anything else.
    ///
    /// The frame's own ceiling is ``RecipeShareDialHello/maxEncodedBytes``, which is far below
    /// ``maxInboundWireBytes``: a first frame the size of a payload is not a hello, and refusing it
    /// here is what keeps an unresolved connection from ever allocating one.
    func readDialHello(from stream: Network.QUIC.Stream<QUICStream>) async -> RecipeShareDialHello? {
        do {
            let header = try await stream.receive(exactly: NetworkMeshWire.headerByteCount).content
            let length = try NetworkMeshWire.payloadLength(
                from: header,
                ceiling: RecipeShareDialHello.maxEncodedBytes
            )
            let payload = try await stream.receive(exactly: length).content
            return RecipeShareDialHello.decoded(payload)
        } catch {
            return nil
        }
    }

    /// Drops a pending inbound connection, cancelling the task that owns it. Idempotent, and safe
    /// to call from inside that task — cancelling itself is how the connection is closed.
    func dropPendingInbound(_ key: MeshLinkKey) {
        pendingInbound.removeValue(forKey: key)?.cancel()
    }

    /// Records the control stream and the connection, then hands the channel to the owner.
    ///
    /// The connection is recorded HERE and nowhere else, which is what makes "a transfer stream
    /// can never carry a frame from a connection this radio has not admitted" structural: a stream
    /// arriving on an unadmitted connection resolves to no tunnel in
    /// ``serveTransferStream(_:on:)`` and is refused before a byte is read.
    func activate(
        _ key: MeshLinkKey,
        stream: Network.QUIC.Stream<QUICStream>,
        connection: NetworkConnection<QUIC>
    ) {
        guard var tunnel = tunnels[key] else { return }
        tunnel.controlStream = stream
        tunnel.connection = connection
        tunnels[key] = tunnel
        FernletAuditLog.log("recipe.quic.connected", context: ["tunnels": String(tunnels.count)])
        onPeerChannelReady?(tunnel.channel)
    }

    /// Reads length-framed app frames off a control stream and routes them to the channel.
    func receiveFrames(for key: MeshLinkKey, from stream: Network.QUIC.Stream<QUICStream>) async throws {
        for _ in 0..<Self.maxInboundFramesPerConnection {
            guard !Task.isCancelled, tunnels[key] != nil else { return }
            let header = try await stream.receive(exactly: NetworkMeshWire.headerByteCount).content
            let length = try NetworkMeshWire.payloadLength(from: header, ceiling: Self.maxInboundWireBytes)
            let payload = try await stream.receive(exactly: length).content
            tunnels[key]?.channel.receive(payload, at: Date())
        }
        throw MeshTransportError.frameBudgetSpent
    }

    /// Ends a tunnel, telling the channel either way and the owner unless it asked for the end.
    func endTunnel(_ key: MeshLinkKey, reason: String, notifyOwner: Bool = true) {
        guard let tunnel = tunnels.removeValue(forKey: key) else { return }
        tunnel.cancelTasks()
        Self.logger.notice(
            "recipe tunnel ended for \(self.peerLabel(for: key), privacy: .public): \(reason, privacy: .public)"
        )
        tunnel.channel.notifyDisconnected(reason: reason)
        guard notifyOwner else { return }
        onPeerDisconnected?(tunnel.peer, reason)
    }
}

// MARK: - Per-transfer streams

/// One claimed outbound recipe transfer: the budget slot it holds and the connection its stream is
/// opened on.
///
/// The two are claimed together and released together, so a slot cannot be taken for a tunnel whose
/// connection has already gone.
private struct RecipeShareTransferClaim {

    /// The budget slot this transfer holds, released when it finishes however it finishes.
    let id: MeshTransferID

    /// The connection to open this transfer's stream on.
    let connection: NetworkConnection<QUIC>
}

private extension NetworkRecipeShareSession {

    /// Claims a transfer stream for one outbound frame, or answers nil to send it on the control
    /// stream.
    ///
    /// Both answers mean the same thing to the caller — a recipe under
    /// ``MeshTransferStreamTable/bulkFloorBytes`` and a recipe that arrived while the direction was
    /// full both ride the control stream — which is why they are one value.
    func claimTransferStream(_ key: MeshLinkKey, byteCount: Int) -> RecipeShareTransferClaim? {
        guard var tunnel = tunnels[key], let connection = tunnel.connection,
              let id = tunnel.transfers.openOutbound(reliableByteCount: byteCount) else { return nil }
        tunnels[key] = tunnel
        return RecipeShareTransferClaim(id: id, connection: connection)
    }

    /// Writes one length-framed payload on a stream of its own and waits for the peer's ack.
    ///
    /// **The ack is not a protocol feature, it is what keeps the stream open.** A
    /// `Network.QUIC.Stream`'s lifetime is its Swift object's: returning the moment the last write
    /// returns releases the stream, and a peer that had not finished reading sees it reset. Reading
    /// one byte back is the shortest thing that holds the object until the payload has landed — and
    /// it turns a peer that vanished mid-share into a thrown send, which the owner already renders
    /// as "Could not send that recipe."
    func sendOverTransferStream(
        _ payload: Data,
        key: MeshLinkKey,
        claim: RecipeShareTransferClaim
    ) async throws {
        defer { tunnels[key]?.transfers.closeOutbound(claim.id) }
        do {
            let stream = try await claim.connection.openStream()
            try await stream.send(NetworkMeshWire.header(for: payload.count))
            try await stream.send(payload, endOfStream: true)
            _ = try await stream.receive(exactly: MeshTransferStreamTable.ack.count)
            noteTransfer("sent", bytes: payload.count, key: key)
        } catch {
            noteTransfer("failed", bytes: payload.count, key: key)
            throw PeerTransportError.sendFailed(reason: error.localizedDescription)
        }
    }

    /// Starts the dialing side's inbound-stream acceptor.
    ///
    /// It exists because that side has none: it opens its own control stream, so every stream
    /// arriving *at* it is a per-transfer stream and there is nothing to disambiguate. The
    /// listening side needs no equivalent — its `inboundStreams` acceptor is already running and
    /// routes past the control stream itself.
    func startTransferAcceptor(on connection: NetworkConnection<QUIC>, key: MeshLinkKey) {
        guard var tunnel = tunnels[key], tunnel.transferAcceptorTask == nil else { return }
        tunnel.transferAcceptorTask = Task { @MainActor [weak self] in
            await self?.acceptTransferStreams(on: connection, key: key)
        }
        tunnels[key] = tunnel
    }

    /// Serves every stream the peer opens after the control stream.
    func acceptTransferStreams(on connection: NetworkConnection<QUIC>, key: MeshLinkKey) async {
        do {
            try await connection.inboundStreams { stream in
                await self.serveTransferStream(stream, on: connection)
            }
        } catch {
            guard !Task.isCancelled else { return }
            Self.logger.debug(
                "recipe transfer acceptor ended for \(self.peerLabel(for: key), privacy: .public)"
            )
        }
    }

    /// Reads one whole transfer, hands it to the peer's channel as a single frame, and acks it.
    ///
    /// **Nothing crosses from a connection this radio has not admitted, structurally.** A tunnel
    /// records its connection only at ``activate(_:stream:connection:)``, which is only ever
    /// reached once the dial hello resolved to a browsed peer the owner accepted — so a stream
    /// opened by an unresolved connection resolves to no tunnel here, is refused, and never reaches
    /// a channel or a decoder. (Identity itself is decided a layer up, by the coordinator's sealed
    /// introduction; this is admission, not authentication.)
    ///
    /// A refused or failed transfer is dropped rather than fatal, and the stream goes back un-acked
    /// so the sender's write fails loudly. Neither branch touches the tunnel: never disconnect at
    /// this layer, or one malformed transfer could end a pairing mid-share.
    func serveTransferStream(
        _ stream: Network.QUIC.Stream<QUICStream>,
        on connection: NetworkConnection<QUIC>
    ) async {
        guard let key = tunnelKey(for: connection), let id = claimInboundTransfer(key) else {
            FernletAuditLog.log("recipe.quic.transferStreamRefused", context: [:])
            return
        }
        defer { tunnels[key]?.transfers.closeInbound(id) }
        do {
            let header = try await stream.receive(exactly: NetworkMeshWire.headerByteCount).content
            let length = try NetworkMeshWire.payloadLength(from: header, ceiling: Self.maxInboundWireBytes)
            let payload = try await stream.receive(exactly: length).content
            tunnels[key]?.channel.receive(payload, at: Date())
            noteTransfer("received", bytes: length, key: key)
            try await stream.send(MeshTransferStreamTable.ack, endOfStream: true)
        } catch {
            FernletAuditLog.log("recipe.quic.transferStreamFailed", context: [:])
        }
    }

    /// Takes one inbound transfer slot on a tunnel, or answers nil when the peer already holds
    /// ``MeshTransferStreamTable/maxConcurrentInbound``.
    func claimInboundTransfer(_ key: MeshLinkKey) -> MeshTransferID? {
        guard var tunnel = tunnels[key], let id = tunnel.transfers.openInbound() else { return nil }
        tunnels[key] = tunnel
        return id
    }

    /// The tunnel a connection belongs to, by object identity. Bounded by ``maxTunnels``.
    func tunnelKey(for connection: NetworkConnection<QUIC>) -> MeshLinkKey? {
        for candidate in tunnels.keys.sorted(by: { $0.rawValue < $1.rawValue })
        where tunnels[candidate]?.connection === connection {
            return candidate
        }
        return nil
    }

    /// Records one transfer crossing: the verb, the payload size, and the opaque peer label. Byte
    /// counts only — no payload, no recipe title, no peer name.
    func noteTransfer(_ verb: String, bytes: Int, key: MeshLinkKey) {
        FernletAuditLog.log(
            "recipe.quic.transferStream",
            context: ["verb": verb, "bytes": String(bytes), "peer": peerLabel(for: key)]
        )
    }
}
