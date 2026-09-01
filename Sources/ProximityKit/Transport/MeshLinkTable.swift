import Foundation

// MARK: - MeshLinkKey

/// The transport-neutral name of one remote endpoint a QUIC mesh session may dial.
///
/// Under ``NetworkMeshSession`` this is the browsed Bonjour endpoint's `id` — a string the
/// framework mints and keeps stable for as long as that service instance is advertised. It is
/// deliberately **not** ``PeerEndpointKey``: the endpoint key is minted once an endpoint has become
/// a *peer* and is handed to every ``PeerHandle`` built for it, while this one exists from the first
/// browse result, before any handle exists at all. Keeping the two distinct is what lets every dial
/// decision below be written — and exhaustively tested — with no framework and no clock in sight.
///
/// **Never leaves the process.** Not persisted, not advertised, not on the wire; it is a routing
/// handle for one run of one session and nothing else.
nonisolated struct MeshLinkKey: Hashable, Sendable {
    /// The framework's opaque endpoint identifier, verbatim. A frozen token, never localized.
    let rawValue: String

    /// Wraps a transport-supplied endpoint identifier. Tests construct these directly; that is the
    /// point of the type being a plain string wrapper rather than a framework value.
    init(_ rawValue: String) {
        self.rawValue = rawValue
    }
}

// MARK: - MeshLinkPhase

/// Where one remote endpoint stands in the QUIC session's per-connection state machine.
///
/// The five phases are exhaustive and every transition below names both its trigger and its
/// successor, so "what happens next" is never a property of the calling order. Two of them —
/// ``dialing`` and ``connected`` — occupy a slot against ``MeshLinkTable/maxConcurrentLinks``;
/// the other three do not, which is what stops a room full of unreachable advertisements from
/// consuming the roster cap.
nonisolated enum MeshLinkPhase: Equatable, Sendable {
    /// Known (or newly browsed) endpoint with nothing in flight. Holds no slot.
    case idle
    /// An outbound tunnel attempt is open. Holds a slot.
    case dialing
    /// The last attempt failed and the 2 s backoff is running. Holds no slot: a peer that is not
    /// answering must not keep a seat a reachable peer could use.
    case backingOff
    /// A tunnel is up. Holds a slot.
    case connected
    /// Every dial attempt in the budget is spent; this session will not dial the endpoint again on
    /// its own. Holds no slot — and is not a refusal to *accept*, only to *dial*.
    case exhausted
}

// MARK: - MeshDialPreference

/// Which side of a mutually-dialing pair is entitled to keep its own outbound tunnel.
///
/// Both peers browse *and* advertise, so both discover each other, and without a rule both dial and
/// the pair ends up holding two tunnels for one link. The rule is the production tie-break —
/// `MeshNetworkManager.shouldInitiateInvite`, which ranks the per-launch random `sid` both sides
/// publish — reduced to the only three answers this table needs.
///
/// ``unranked`` is not a formality and it is not "unknown, treat as local". A Bonjour peer is
/// routinely *seen* before its TXT record arrives, so the ranking genuinely does not exist yet; and
/// the safe direction there is **admit**, never refuse. Refusing an inbound tunnel closes the
/// peer's outbound one, so if both sides refuse while each believes it outranks the other, the pair
/// ends with zero tunnels and waits for a retry — a deadlock. Admitting on both sides ends with two
/// tunnels, which is wasteful and self-correcting. Same asymmetry the probe's dial policy records:
/// a late TXT may only ever *withdraw* permission, never grant one.
nonisolated enum MeshDialPreference: Equatable, Sendable {
    /// Both sides are ranked and this one is the designated dialer.
    case localDials
    /// Both sides are ranked and the peer is the designated dialer.
    case peerDials
    /// The peer's `sid` has not arrived, so no ranking exists yet.
    case unranked

    /// The preference implied by the two session ids the production tie-break compares.
    ///
    /// Deliberately the same comparison as `MeshNetworkManager.shouldInitiateInvite` — the higher
    /// `sid` dials — so the transport and the manager can never disagree about which side is the
    /// dialer. Two divergences, both intentional:
    ///
    /// * **An absent peer `sid` is ``unranked`` here and "invite anyway" there.** The manager is
    ///   choosing whether to *dial* an unrankable peer, where a redundant invite beats a deadlock;
    ///   this is choosing whether to *refuse* an inbound tunnel, where a refusal on both sides is
    ///   the deadlock. Both answers point the same way: never let an unranked pair end with nothing.
    /// * **Equal ids are ``unranked``.** `sid` is a per-launch random UUID, so two advertisements
    ///   carrying the same one are this process's own echo. The manager refuses to dial itself;
    ///   there is nothing to rank, so an inbound tunnel is admitted on its own merits.
    ///
    /// Antisymmetric wherever it ranks: for any two distinct non-empty ids, one side gets
    /// ``localDials`` and the other ``peerDials``, which is what makes "both sides refuse" — the
    /// only deadlocking combination — unreachable from real inputs.
    static func rank(localSessionID: String, peerSessionID: String?) -> MeshDialPreference {
        guard let peerSessionID, !peerSessionID.isEmpty, !localSessionID.isEmpty else {
            return .unranked
        }
        guard localSessionID != peerSessionID else { return .unranked }
        return localSessionID > peerSessionID ? .localDials : .peerDials
    }
}

// MARK: - MeshLinkAdmission

/// The answer to "may this session open — or accept — a tunnel for this endpoint right now?"
///
/// Every refusal names its own reason rather than collapsing into `false`: the three are acted on
/// differently (a duplicate is dropped silently, a capacity refusal is a roster-cap decision the
/// owner may want to surface, and a spent retry budget must not be retried again on a timer), and a
/// single boolean is exactly how those three become one indistinguishable "it didn't connect".
nonisolated enum MeshLinkAdmission: Equatable, Sendable {
    /// Proceed: the caller may dial, or may keep the inbound tunnel it just accepted.
    case admit
    /// A tunnel for this endpoint already exists or is being built, in the carried phase.
    case refusedDuplicateTunnel(MeshLinkPhase)
    /// ``MeshLinkTable/maxConcurrentLinks`` links are already dialing or connected.
    case refusedAtCapacity
    /// Every attempt in ``MeshLinkTable/maxDialAttempts`` is spent for this endpoint.
    case refusedRetryBudgetSpent
}

// MARK: - MeshDialOutcome

/// What becomes of a link whose dial attempt just ended without a tunnel.
nonisolated enum MeshDialOutcome: Equatable, Sendable {
    /// Try again: `attempt` is the 1-based number of the attempt about to be made, `delay` the
    /// backoff before it.
    case retry(attempt: Int, delay: Duration)
    /// The budget is spent after `attempts` attempts; the endpoint moves to
    /// ``MeshLinkPhase/exhausted`` and is dialed again only if something re-opens it.
    case giveUp(attempts: Int)
}

// MARK: - MeshEndpointRecord

/// What a session remembers about one browsed endpoint, so a re-dial does not have to wait for
/// Bonjour to find it again.
///
/// The transport-neutral half of the endpoint cache described in plan §7.3. The framework half —
/// the `Bonjour.Endpoint` value a connection is actually opened to — stays inside
/// ``NetworkMeshSession``, keyed by the same ``MeshLinkKey``, because it cannot cross into a
/// framework-free type. What lives here is everything a *decision* needs.
///
/// **Session-scoped and memory-only.** Never written to disk, `UserDefaults`, or the keychain, and
/// dropped whole by ``MeshLinkTable/removeAll()`` at teardown — which is what keeps it off
/// `Docs/PrivacyWipeCoverage.md` (nothing survives to be wiped) and keeps the per-session random
/// Bonjour instance name unlinkable across runs.
nonisolated struct MeshEndpointRecord: Equatable, Sendable {
    /// The endpoint this record describes.
    let key: MeshLinkKey
    /// The advertised Bonjour instance name — a random per-session token, a display *hint* only,
    /// never an identity claim.
    let instanceName: String
    /// The peer's advertisement as ``MeshLinkAdvertisement`` parsed it: untrusted wire data,
    /// bounded in field count and value length, with the withheld keys already stripped.
    let advertisement: [String: String]
    /// When the browser last reported this endpoint.
    var lastSeenAt: Date
}

// MARK: - MeshLinkTable

/// Every per-endpoint decision a QUIC mesh session makes, with no framework and no clock inside it.
///
/// This is plan §7.3's duty list — peer cap, per-connection state machine, dial retry budget,
/// duplicate-tunnel suppression, endpoint cache — factored out of the session actor so it can be
/// enumerated exhaustively at tier 1. Time enters only as a `now:` parameter, so a test advances a
/// ``VirtualClock`` rather than sleeping, and the whole table is a value type, so a scenario is a
/// sequence of calls with no radios, no tasks, and no ordering hazards.
///
/// The session actor's job on top of this is mechanical: ask, then act on the answer.
///
/// **Bounded by construction** (Power of 10 rule 3): links are capped by the roster cap and the
/// cache by ``maxCachedEndpoints`` with oldest-first eviction, so a crowded room cannot grow either
/// map without end.
nonisolated struct MeshLinkTable {

    /// Simultaneous tunnels. The roster cap (plan §9): eight members, so at most eight directly
    /// reachable peers, so at most eight QUIC connections. Only ``MeshLinkPhase/dialing`` and
    /// ``MeshLinkPhase/connected`` count against it.
    static let maxConcurrentLinks = 8

    /// Dial attempts per endpoint before this session stops trying on its own — the initial dial
    /// plus two retries. Matches the DEBUG probe's `maxOutboundTunnelAttempts`, which is the bound
    /// the feasibility lane actually ran under, and the MC re-invite budget it replaces.
    static let maxDialAttempts = 3

    /// Backoff between dial attempts, in seconds. Flat, not exponential: the mesh is a room, not a
    /// datacentre — a peer that is 2 s away from answering is far more likely than one that needs a
    /// minute, and the whole budget is spent in under five seconds either way.
    static let dialRetryDelaySeconds: TimeInterval = 2

    /// ``dialRetryDelaySeconds`` as a `Duration`, for callers scheduling the retry. Computed from
    /// the one stored constant so the two spellings cannot drift apart.
    static var dialRetryDelay: Duration { .seconds(dialRetryDelaySeconds) }

    /// Cap on remembered endpoints. Four times the roster cap: enough that a busy room's arrivals
    /// and departures stay re-dialable, small enough that the cache is obviously bounded.
    static let maxCachedEndpoints = 32

    /// One endpoint's dial bookkeeping. Private because the phase is the only part callers reason
    /// about, and the attempt count must not be settable from outside the transitions that own it.
    private struct Link: Equatable {
        var phase: MeshLinkPhase
        var dialAttempts: Int
        var retryDueAt: Date?
    }

    private var links: [MeshLinkKey: Link] = [:]
    private var cache: [MeshLinkKey: MeshEndpointRecord] = [:]
    /// First-seen order, for the cache's oldest-first eviction.
    private var cacheOrder: [MeshLinkKey] = []

    /// An empty table. A session owns exactly one for its whole run.
    init() {}

    // MARK: - Reading

    /// The phase this endpoint is in. An endpoint the table has never seen is
    /// ``MeshLinkPhase/idle`` — "nothing in flight" is the honest answer for a stranger.
    func phase(of key: MeshLinkKey) -> MeshLinkPhase {
        links[key]?.phase ?? .idle
    }

    /// How many links hold a slot against ``maxConcurrentLinks`` right now.
    var occupiedSlotCount: Int {
        links.values.filter { $0.phase == .dialing || $0.phase == .connected }.count
    }

    /// How many tunnels are up.
    var connectedCount: Int {
        links.values.filter { $0.phase == .connected }.count
    }

    /// Dial attempts already spent on this endpoint, for diagnostics and for the retry log line.
    func dialAttempts(for key: MeshLinkKey) -> Int {
        links[key]?.dialAttempts ?? 0
    }

    // MARK: - Dialing

    /// Decides whether to open an outbound tunnel to `key`, and books the attempt when the answer
    /// is ``MeshLinkAdmission/admit``.
    ///
    /// Order matters and is deliberate: the duplicate and budget answers are checked **before**
    /// capacity, because a peer that already holds a slot would otherwise be reported as a capacity
    /// refusal — the one answer that would send an owner looking at the roster cap for a bug that
    /// is not there.
    mutating func admitDial(to key: MeshLinkKey, now: Date) -> MeshLinkAdmission {
        let link = links[key] ?? Link(phase: .idle, dialAttempts: 0, retryDueAt: nil)
        switch link.phase {
        case .dialing, .connected:
            return .refusedDuplicateTunnel(link.phase)
        case .exhausted:
            return .refusedRetryBudgetSpent
        case .backingOff:
            guard let due = link.retryDueAt, due <= now else {
                return .refusedDuplicateTunnel(.backingOff)
            }
        case .idle:
            break
        }
        guard occupiedSlotCount < Self.maxConcurrentLinks else { return .refusedAtCapacity }
        links[key] = Link(phase: .dialing, dialAttempts: link.dialAttempts + 1, retryDueAt: nil)
        return .admit
    }

    /// Decides whether to keep an inbound tunnel that just arrived from `key`.
    ///
    /// The duplicate-tunnel suppression of plan §7.1, and the only place the dial tie-break is
    /// consulted for anything other than dialing. While this side is mid-dial to the same endpoint
    /// exactly one of the two tunnels may survive, and the rule picks the one the *ranked dialer*
    /// opened — see ``MeshDialPreference`` for why an unranked pair admits rather than refuses.
    ///
    /// A ``MeshLinkPhase/dialing`` link that admits an inbound tunnel does **not** need a second
    /// slot: it already holds one, and the caller cancels its own outbound attempt.
    mutating func admitInbound(
        from key: MeshLinkKey,
        preference: MeshDialPreference,
        now: Date
    ) -> MeshLinkAdmission {
        let current = phase(of: key)
        guard current != .connected else { return .refusedDuplicateTunnel(.connected) }
        guard !(current == .dialing && preference == .localDials) else {
            return .refusedDuplicateTunnel(.dialing)
        }
        guard current == .dialing || occupiedSlotCount < Self.maxConcurrentLinks else {
            return .refusedAtCapacity
        }
        links[key] = Link(phase: .connected, dialAttempts: 0, retryDueAt: nil)
        remember(lastSeen: key, at: now)
        return .admit
    }

    /// ``admitInbound(from:preference:now:)`` over the two session ids the production tie-break
    /// compares — the spelling a transport calls, so the mapping from `sid`s to a preference is on
    /// the live path rather than restated at each call site.
    ///
    /// `peerSessionID` is nil until the peer says who it is, which the signed channel introduction
    /// (plan §7.2) is what carries; ``MeshDialPreference/rank(localSessionID:peerSessionID:)``
    /// turns that into ``MeshDialPreference/unranked``, whose behaviour is defined and tested.
    mutating func admitInbound(
        from key: MeshLinkKey,
        localSessionID: String,
        peerSessionID: String?,
        now: Date
    ) -> MeshLinkAdmission {
        admitInbound(
            from: key,
            preference: .rank(localSessionID: localSessionID, peerSessionID: peerSessionID),
            now: now
        )
    }

    /// Records that a tunnel to `key` reached ready. Resets the retry budget: the three attempts
    /// are a budget for *reaching* a peer, not a lifetime quota, so a peer that connects and later
    /// drops gets a fresh campaign rather than inheriting a spent one.
    mutating func noteReady(_ key: MeshLinkKey, now: Date) {
        links[key] = Link(phase: .connected, dialAttempts: 0, retryDueAt: nil)
        remember(lastSeen: key, at: now)
    }

    /// Records that an outbound attempt to `key` ended without a tunnel, and says what happens next.
    ///
    /// An endpoint with no booked attempt (a failure reported twice, or one for a link the table has
    /// already forgotten) reads as a spent budget rather than starting a new campaign — a retry loop
    /// that can be re-armed by a duplicate callback is exactly the unbounded loop rule 2 forbids.
    mutating func noteDialFailed(_ key: MeshLinkKey, now: Date) -> MeshDialOutcome {
        let attempts = links[key]?.dialAttempts ?? Self.maxDialAttempts
        guard attempts < Self.maxDialAttempts else {
            links[key] = Link(phase: .exhausted, dialAttempts: Self.maxDialAttempts, retryDueAt: nil)
            return .giveUp(attempts: Self.maxDialAttempts)
        }
        links[key] = Link(
            phase: .backingOff,
            dialAttempts: attempts,
            retryDueAt: now.addingTimeInterval(Self.dialRetryDelaySeconds)
        )
        return .retry(attempt: attempts + 1, delay: Self.dialRetryDelay)
    }

    /// Records that a live tunnel to `key` went down. The endpoint returns to
    /// ``MeshLinkPhase/idle`` with a full budget — a disconnect is not a dial failure, and charging
    /// it to the retry budget is how a peer that reconnects a few times becomes permanently
    /// undialable.
    mutating func noteClosed(_ key: MeshLinkKey) {
        links[key] = Link(phase: .idle, dialAttempts: 0, retryDueAt: nil)
    }

    /// Endpoints whose backoff has elapsed, oldest key first for a deterministic order.
    ///
    /// The retry driver: a session polls this on its own timer instead of holding one timer per
    /// endpoint, so retries cannot outlive the table that owns them.
    func dueRetries(now: Date) -> [MeshLinkKey] {
        links
            .filter { $0.value.phase == .backingOff && ($0.value.retryDueAt ?? now) <= now }
            .keys
            .sorted { $0.rawValue < $1.rawValue }
    }

    /// Drops every record for `key` — its link state and its cache entry. Called when the browser
    /// reports the endpoint lost *and* nothing is connected to it.
    mutating func forget(_ key: MeshLinkKey) {
        links.removeValue(forKey: key)
        cache.removeValue(forKey: key)
        cacheOrder.removeAll { $0 == key }
    }

    /// Drops everything. The teardown call: link state and endpoint cache both die with the
    /// session, which is the privacy constraint that keeps this table off the wipe ledger.
    mutating func removeAll() {
        links.removeAll()
        cache.removeAll()
        cacheOrder.removeAll()
    }

    // MARK: - Endpoint cache

    /// Remembers (or refreshes) what the browser just reported about an endpoint.
    ///
    /// Bounded oldest-first: a re-sighting refreshes the record in place and does **not** move it
    /// up the eviction order, so the order stays strictly first-seen and a long-lived endpoint
    /// cannot pin a full cache forever.
    mutating func remember(_ record: MeshEndpointRecord) {
        guard cache[record.key] != nil else {
            evictOldestCachedEndpointIfFull()
            cacheOrder.append(record.key)
            cache[record.key] = record
            return
        }
        cache[record.key] = record
    }

    /// What this session last knew about `key`, or nil if it has never seen it (or evicted it).
    func cachedEndpoint(_ key: MeshLinkKey) -> MeshEndpointRecord? {
        cache[key]
    }

    /// Every cached endpoint in first-seen order — the direct re-dial candidates when Bonjour has
    /// gone quiet (plan §7.3; the input P8's background reconnection needs).
    var cachedEndpoints: [MeshEndpointRecord] {
        cacheOrder.compactMap { cache[$0] }
    }

    /// How many endpoints the cache is holding.
    var cachedEndpointCount: Int {
        cache.count
    }

    /// The cached endpoint advertising `sessionID`, if this session has browsed one.
    ///
    /// **This is what the signed channel introduction unlocks.** An inbound QUIC connection arrives
    /// as a host and port, and a browsed peer is a Bonjour service instance; nothing at accept time
    /// matches the two, which is why an inbound tunnel had no ranking at all and fell through to
    /// ``MeshDialPreference/unranked``. Once the introduction has verified the peer, its `sid` is
    /// attributable, and the `sid` is exactly what the TXT record carries — so an inbound tunnel can
    /// be resolved to the same ``MeshLinkKey`` an outbound dial to that peer uses, and the two
    /// collide in this table instead of coexisting as a duplicate pair.
    ///
    /// An empty id never matches: `MeshLinkAdvertisement` drops empty values, so a cached
    /// advertisement cannot hold one, and treating "no id" as a match would attach a tunnel to an
    /// arbitrary endpoint.
    ///
    /// Bounded by ``maxCachedEndpoints`` and scanned in first-seen order, so the answer is
    /// deterministic when two advertisements somehow carry the same id (Power of 10 rule 2).
    func key(advertisingSessionID sessionID: String) -> MeshLinkKey? {
        guard !sessionID.isEmpty else { return nil }
        for key in cacheOrder
        where cache[key]?.advertisement[MeshLinkAdvertisement.sessionIDKey] == sessionID {
            return key
        }
        return nil
    }

    /// Makes room for one more cache entry, dropping the oldest when the cache is full.
    private mutating func evictOldestCachedEndpointIfFull() {
        guard cacheOrder.count >= Self.maxCachedEndpoints, let oldest = cacheOrder.first else {
            return
        }
        cacheOrder.removeFirst()
        cache.removeValue(forKey: oldest)
    }

    /// Refreshes an existing cache entry's `lastSeenAt` without inventing one for an endpoint the
    /// browser never reported (an inbound tunnel from a peer this side never browsed is normal).
    private mutating func remember(lastSeen key: MeshLinkKey, at now: Date) {
        guard var record = cache[key] else { return }
        record.lastSeenAt = now
        cache[key] = record
    }
}
