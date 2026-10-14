import Foundation

// MARK: - ProximityPeerChannel

/// One peer's channel on the presence radio, as a ``ProximityPresenceSession`` hands it to its host
/// through ``ProximityPresenceSession/onPeerChannelReady``: the ``PeerTransport`` the host builds that
/// connection's ``ProximityCoordinator`` over, plus the two things a host needs beyond it.
///
/// The radio's own per-peer channel conforms, and nothing else needs to: a host never makes one, it
/// is handed one. Main-actor, like the transport it refines.
@MainActor
public protocol ProximityPeerChannel: PeerTransport {

    /// The peer this channel carries: the handle the session's discovery, ``ProximityPresenceSession/dial(_:helloTag:)``
    /// and ``ProximityPresenceSession/disconnectPeer(_:)`` name the same device by.
    var peer: PeerHandle { get }

    /// Publishes the channel's `.connected` state, once, **after** the coordinator built over this
    /// channel has begun (its `begin(role:mode:)` has returned), never before: published earlier, it
    /// would put the coordinator in the wrong branch of its handshake. That ordering is the host's
    /// obligation, because the coordinator is the host's.
    func notifyConnected()
}

// MARK: - ProximityPresenceSession

/// The presence radio as one engine: it builds the radio for its host's namespace, wears the epoch
/// posture that radio advertises under, and speaks the presence TXT vocabulary, so a host advertises
/// and reads *tags* and never a record, a posture or a radio.
///
/// ## What it owns
///
/// - **The radio.** A fresh QUIC presence radio for ``namespace`` at every ``start(tags:)``, stood
///   down and dropped by ``stop()``. Its six hooks are wired to this session's before the radio
///   starts; the host wires this session's hooks, once, before its first start.
/// - **The epoch posture.** The instance name the radio advertises and the TLS identity it presents
///   for one presence epoch (`IdentityService.presenceEpoch(at:)`, the clock the host's tags rotate
///   on), minted by ``rotatePosture(at:)`` when none is worn and replaced *whole* — new name, new key
///   pair, new certificate — the first time it is asked across a boundary, so two sightings 901
///   seconds apart share no byte. It is memory-only and ``stop()`` drops it: a stood-down radio keeps
///   no name and no identity to come back up under.
/// - **Self-exclusion by name.** Every instance name this session has worn, the most recent
///   ``maxRememberedInstanceNames`` of them, survives ``stop()``; a sighting advertised under one of
///   them is this device's own ghost (a stale Bonjour cache can still carry a previous epoch's or a
///   previous start's registration) and is dropped before the host hears of it.
/// - **The TXT vocabulary.** ``start(tags:)`` and ``republish(tags:)`` advertise the host's tags as
///   the presence record (the version, then the sorted tags chunked to fit DNS-SD's 255-byte entry),
///   and a sighting reaches ``onPeerDiscovered`` only when it is a presence record of this version,
///   with its tags decoded and bounded.
///
/// ## What it leaves to its host
///
/// The tags themselves and what they match, every decision about a sighting beyond its name, when a
/// boundary is crossed, how often a failed mint is retried and what is logged about it, whether a
/// dialer is admitted (``resolveDialer``, which fails closed when unwired), and every connection's
/// coordinator. The session owns **no timer and no task**: a host that wants the posture to rotate
/// at each boundary asks ``rotatePosture(at:)`` from a tick of its own and then republishes, and a
/// host that never asks advertises one name for as long as the radio is up, which is the linkability
/// the posture exists to remove.
///
/// `@MainActor`, like the radio it drives. Building one starts nothing.
@MainActor
public final class ProximityPresenceSession {

    /// R3 cap on the own-name ring: a start or a boundary adds one name, and only the last few can
    /// still have a Bonjour ghost on the air, so remembering 32 is generous.
    static let maxRememberedInstanceNames = 32

    // MARK: Hooks

    /// A presence advertisement appeared or changed, with its tags: called only for a record of this
    /// version under a name this session never wore.
    public var onPeerDiscovered: ((PeerHandle, Set<String>) -> Void)?
    /// A peer left the browse results.
    public var onPeerLost: ((PeerHandle) -> Void)?
    /// Resolves an inbound dialer's claimed tag to the browsed peer it names, or nil to refuse the
    /// connection. **Fails closed**: unwired, the radio resolves nobody and admits nobody.
    public var resolveDialer: ((String) -> PeerHandle?)?
    /// A tunnel came up: its channel, live, for the host to build a coordinator over.
    public var onPeerChannelReady: ((any ProximityPeerChannel) -> Void)?
    /// A tunnel went down, with a diagnostic reason. Never called for a tunnel the host ended.
    public var onPeerDisconnected: ((PeerHandle, String) -> Void)?
    /// The radio's listener or browser failed after it started, in frozen diagnostic English.
    public var onTransportError: ((String) -> Void)?

    // MARK: State

    /// The host's protocol identity: the radio's service type, ALPN, log subsystem and soundness
    /// verdict, and the posture's instance-name prefix and TLS common name, are read off it.
    let namespace: ProximityNamespace

    /// Test seam: the radio ``start(tags:)`` brings up. The production default, set in `init`, is the
    /// QUIC presence radio for ``namespace``, and nothing in shipping code writes this; a test
    /// substitutes an in-memory radio so the advertise, republish, dial and stand-down decisions are
    /// reachable without starting Bonjour.
    var makeRadio: () -> any PresenceRadioSession

    /// Test seam: the posture mint, as `(posture worn now, instant) -> the posture to wear`. The
    /// production default, set in `init`, is the posture's own production path (the system CSPRNG
    /// and the module's one certificate path) under ``namespace``'s presence instance-name prefix and
    /// TLS common name, and nothing in shipping code writes this; a test substitutes a failing mint.
    var postureMint: (PresenceEpochPosture?, Date) throws -> PresenceEpochPosture

    /// The posture worn now: the one source of the advertised instance name and TLS identity.
    private(set) var posture: PresenceEpochPosture?

    /// The radio, from ``start(tags:)`` to ``stop()``.
    private var radio: (any PresenceRadioSession)?

    /// The instance names this session has worn, for self-exclusion by name.
    private var ownInstanceNames: Set<String> = []

    /// Insertion order for ``ownInstanceNames``, so the cap evicts the OLDEST name.
    private var ownInstanceNameOrder: [String] = []

    /// A session that speaks `namespace`'s presence wire: its radio advertises and browses the
    /// namespace's presence service type, and its posture is minted under the namespace's presence
    /// instance-name prefix and TLS common name. Starts nothing and mints nothing.
    ///
    /// - Parameter namespace: The host's protocol identity.
    public init(namespace: ProximityNamespace) {
        self.namespace = namespace
        self.makeRadio = { NetworkPresenceSession(namespace: namespace) }
        let prefix = namespace.family.radios.presenceInstanceNamePrefix
        let commonName = namespace.family.radios.tlsCommonName
        self.postureMint = { held, now in
            try held?.rotated(at: now, instanceNamePrefix: prefix, commonName: commonName)
                ?? PresenceEpochPosture.minted(at: now, instanceNamePrefix: prefix, commonName: commonName)
        }
    }

    // MARK: - Posture

    /// The presence epoch of the posture worn now, or nil when none is.
    public var postureEpoch: UInt64? { posture?.epoch }

    /// Wears the posture for the epoch containing `now` and answers that epoch.
    ///
    /// Inside the worn posture's epoch this is a no-op; with no posture, or across a boundary, it
    /// mints an entirely fresh one, remembers its instance name for self-exclusion and wears it. It
    /// has no clock of its own: `now` is the host's, and the epoch is `IdentityService.presenceEpoch(at:)`.
    /// It republishes nothing: a host that rotated calls ``republish(tags:)`` with its tags for the
    /// new epoch, so the name, the identity and the tags change together.
    ///
    /// - Parameter now: The host's clock reading.
    /// - Returns: The epoch of the posture now worn.
    /// - Throws: Whatever the mint throws. A failed mint leaves **no** posture rather than a stale
    ///   one, so a running radio keeps the registration it has and a later ``start(tags:)`` or
    ///   ``republish(tags:)`` advertises nothing until a mint succeeds; how often to retry is the host's.
    public func rotatePosture(at now: Date) throws -> UInt64 {
        let epoch = IdentityService.presenceEpoch(at: now)
        if let posture, posture.epoch == epoch { return epoch }
        do {
            let rotated = try postureMint(posture, now)
            posture = rotated
            rememberOwnInstanceName(rotated.instanceName)
            return rotated.epoch
        } catch {
            posture = nil
            throw error
        }
    }

    // MARK: - Lifecycle

    /// Brings a fresh radio up under the worn posture, advertising `tags` as the presence record.
    ///
    /// The radio's hooks are wired to this session's before it starts. A session whose radio is
    /// already up ignores the call.
    ///
    /// - Parameter tags: The host's own tags for the posture's epoch.
    /// - Throws: `MeshTransportError.tlsIdentityUnavailable` with no posture worn (nothing to
    ///   advertise under), or whatever the radio's start throws, refusing an unsound namespace
    ///   first; the radio stays held, so ``stop()`` stands it down.
    public func start(tags: Set<String>) throws {
        guard radio == nil else { return }
        guard let posture else { throw MeshTransportError.tlsIdentityUnavailable }
        let radio = makeRadio()
        wire(radio)
        self.radio = radio
        try radio.start(posture: posture, discoveryInfo: Self.advertisedFields(for: tags))
    }

    /// Re-advertises `tags` under the worn posture.
    ///
    /// The radio withdraws its registration and registers again, so a posture rotated since the last
    /// advertisement replaces the old name whole, with no instant at which both are on the air. With
    /// no posture worn there is nothing to advertise under, and the radio is left as it is; with no
    /// radio up, nothing happens.
    ///
    /// - Parameter tags: The host's own tags for the posture's epoch.
    public func republish(tags: Set<String>) {
        guard let posture else { return }
        radio?.republish(posture: posture, discoveryInfo: Self.advertisedFields(for: tags))
    }

    /// Stands the radio down and drops it, with the posture. The own-name ring survives.
    public func stop() {
        radio?.stop()
        radio = nil
        posture = nil
    }

    // MARK: - Tunnels

    /// Opens a tunnel to a browsed peer, claiming `helloTag`, one of the host's own advertised tags,
    /// in the dial hello; the channel arrives through ``onPeerChannelReady``. A no-op with no radio up.
    ///
    /// - Parameters:
    ///   - peer: A peer this session reported through ``onPeerDiscovered``.
    ///   - helloTag: The tag the far side resolves this connection by.
    public func dial(_ peer: PeerHandle, helloTag: String) {
        radio?.dial(peer, helloTag: helloTag)
    }

    /// Ends a peer's tunnel at the host's request, without a call to ``onPeerDisconnected``.
    ///
    /// - Parameter peer: The peer whose tunnel ends.
    public func disconnectPeer(_ peer: PeerHandle) {
        radio?.disconnectPeer(peer)
    }

    // MARK: - The record

    /// The presence record for `tags`: the version, then the tags sorted and chunked
    /// (``PresenceAdvertisement/publishedFields(tags:)``), so the record is a function of the set.
    static func advertisedFields(for tags: Set<String>) -> [String: String] {
        PresenceAdvertisement.publishedFields(tags: tags.sorted())
    }

    // MARK: - The radio's hooks

    /// Points `radio`'s six hooks at this session, each holding it weakly: the session owns the radio.
    private func wire(_ radio: any PresenceRadioSession) {
        radio.onPeerDiscovered = { [weak self] peer in
            self?.radioDiscovered(peer)
        }
        radio.onPeerLost = { [weak self] peer in
            self?.onPeerLost?(peer)
        }
        radio.resolveDialer = { [weak self] tag in
            self?.resolveDialer?(tag)
        }
        radio.onPeerChannelReady = { [weak self] channel in
            self?.onPeerChannelReady?(channel)
        }
        radio.onPeerDisconnected = { [weak self] peer, reason in
            self?.onPeerDisconnected?(peer, reason)
        }
        radio.onTransportError = { [weak self] message in
            self?.onTransportError?(message)
        }
    }

    /// One sighting: a record that is not a presence record of this version, or one advertised under
    /// a name this session wore, ends here; any other reaches the host with its tags.
    private func radioDiscovered(_ peer: PeerHandle) {
        guard PresenceAdvertisement.isPresenceAdvertisement(peer.discoveryInfo) else { return }
        // Self-exclusion by name: our own ghost from a previous epoch or a previous start (a stale
        // Bonjour cache) advertises under one of the posture instance names this session has worn.
        guard !ownInstanceNames.contains(peer.displayHint) else { return }
        onPeerDiscovered?(peer, PresenceAdvertisement.tags(from: peer.discoveryInfo))
    }

    /// Records one of this session's posture instance names, evicting the oldest past
    /// ``maxRememberedInstanceNames`` so repeated starts and rotations cannot grow the set (R3).
    private func rememberOwnInstanceName(_ name: String) {
        guard ownInstanceNames.insert(name).inserted else { return }
        ownInstanceNameOrder.append(name)
        // R2: bounded by the cap; one name in, at most one name out.
        while ownInstanceNameOrder.count > Self.maxRememberedInstanceNames {
            let oldest = ownInstanceNameOrder.removeFirst()
            ownInstanceNames.remove(oldest)
        }
    }

    // MARK: - Test seams (no real radios: unit tests must never start Bonjour)

    /// Remembers `name` as one this session wore, exactly as a successful mint does.
    func registerOwnInstanceNameForTesting(_ name: String) {
        rememberOwnInstanceName(name)
    }

    /// Drives one sighting exactly as the radio's discovery hook does, with no radio up.
    func noteDiscoveredForTesting(_ peer: PeerHandle) {
        radioDiscovered(peer)
    }

    /// The channel the radio would hand the host for `peer`, built exactly as the live path builds
    /// one: on the running radio, or on a QUIC presence radio built for ``namespace`` and never
    /// started — the seam a heart rig stands a connection up with, no radio running.
    func channelForTesting(_ peer: PeerHandle) -> NetworkPeerChannel {
        (radio ?? NetworkPresenceSession(namespace: namespace)).channel(for: peer)
    }
}
