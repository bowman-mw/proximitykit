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

// MARK: - MeshTunnelConvergence

/// Which of a verified pair's two tunnels survives when both sides dialed and both dials succeeded.
///
/// ``MeshDialPreference`` keeps a mutually-dialing pair from ending with **zero** tunnels, and pays
/// for that with **two**: an unranked pair admits on both sides, which is safe and wasteful. This is
/// where the waste is collected. Once both ends have completed the signed channel introduction, each
/// knows both verified identities *and* both `sid`s — so the ranking that did not exist during the
/// pre-TXT dial window exists now, and the pair can be collapsed to the one tunnel plan §7.1
/// promises.
///
/// ## Why closing one is safe here when refusing one was not safe earlier
///
/// A refusal during the dial window is a decision made on one side's *incomplete* knowledge, and two
/// sides refusing on incomplete knowledge is exactly the deadlock ``MeshDialPreference`` exists to
/// avoid. A convergence verdict is a pure function of values **both sides hold and agree on** — the
/// two session ids, and which end dialed — so both sides compute the same answer and close the same
/// connection. Closing a connection closes it at *both* ends, so the surviving tunnel is the same
/// one on both devices however the two sides interleave, including when both act at once.
///
/// ## The rule
///
/// Keep the tunnel whose **dialer is the preferred dialer**: the higher `sid`, the identical
/// comparison `MeshNetworkManager.shouldInitiateInvite` and ``MeshDialPreference`` already make, so
/// the transport and the manager can never disagree about which direction is the real one. On the
/// preferred dialer that is the tunnel it opened (``MeshChannelRole/initiator``); on the other side
/// it is the tunnel it accepted (``MeshChannelRole/responder``) — one connection, named from each
/// end.
nonisolated enum MeshTunnelConvergence: Equatable, Sendable {

    /// No symmetric rule exists, so nothing is closed. Two tunnels is wasteful and self-correcting;
    /// zero is not recoverable without a retry, and that asymmetry decides every undecidable case.
    case keepBoth
    /// The tunnel now activating survives; the established one is the redundant duplicate.
    case keepIncoming
    /// The established tunnel survives; the one now activating is the redundant duplicate.
    case keepEstablished

    /// Frozen diagnostic English for a benign duplicate-collapse close.
    ///
    /// Deliberately **not** a `MeshTransportError` case: nothing failed, nothing was refused, and a
    /// dedup close is charged to no budget. It leads with its own token so a log reader — and the
    /// feasibility runbook's Lane C grep — can tell a collapsed duplicate from a rejected peer at a
    /// glance, which is the whole reason it is named rather than folded into a disconnect reason.
    static let closeReason =
        "redundantTunnelClosed: a duplicate tunnel to the same verified peer was collapsed."

    /// The verdict for one activating tunnel judged against one established tunnel to the *same*
    /// verified peer.
    ///
    /// `localSessionID` is this device's advertised `sid`; `peerSessionID` is the one the signed
    /// introduction attributed to a verified identity. The roles say which end opened each
    /// connection.
    ///
    /// Two answers are deliberate:
    ///
    /// * **An unranked pair keeps both.** Ranking fails only when this side advertises no `sid`, or
    ///   the two are identical — this process's own echo. Neither is two real devices disagreeing,
    ///   and inventing a tie-break for them risks the one outcome no timer-free path recovers from.
    /// * **Two tunnels in the same direction keep the established one.** Direction is the only fact
    ///   both ends name identically, so a same-direction pair has no symmetric discriminator;
    ///   keeping the established one never flaps, and still converges, because the connection this
    ///   side closes is closed at the peer's end too.
    static func resolve(
        incomingRole: MeshChannelRole,
        establishedRole: MeshChannelRole,
        localSessionID: String,
        peerSessionID: String
    ) -> MeshTunnelConvergence {
        let survivor: MeshChannelRole
        switch MeshDialPreference.rank(localSessionID: localSessionID, peerSessionID: peerSessionID) {
        case .unranked: return .keepBoth
        case .localDials: survivor = .initiator
        case .peerDials: survivor = .responder
        }
        guard incomingRole != establishedRole else { return .keepEstablished }
        return incomingRole == survivor ? .keepIncoming : .keepEstablished
    }
}

// MARK: - MeshTunnelEndReason

/// Why one QUIC tunnel stopped carrying traffic — the vocabulary that turns a silent teardown into
/// a readable line.
///
/// **The defect this exists to close.** Before P2 item 15, a *live* tunnel that ended emitted
/// nothing at all: `NetworkMeshSession.endTunnel` booked the close, told the channel and called the
/// owner's disconnect hook without a single `Logger` line. A dial failure logged, a refusal logged,
/// a give-up logged — a healthy tunnel dropping did not. Three sequential tunnels therefore read as
/// three coexisting ones for a fortnight (Lane C, item 13), and the churn itself went undiagnosed
/// for as long again because nothing on the disconnect path said the word "ended".
///
/// Every case is a **frozen automation token**: it is the grep target a Lane C transcript is read
/// with, never a display string, never localized, and never persisted. The English that accompanies
/// it on the line is the carried `detail`, which is the framework's own error text.
///
/// The distinctions are the ones an operator has to make. `heartbeatSendFailed` and
/// `controlStreamEnded` both mean "the link stopped working", but the first says *this side could
/// not write* and the second says *the pipe went away* — one points at the heartbeat channel, the
/// other at the connection. `localEviction` and `redundantDuplicate` are not failures at all, and a
/// reader who cannot tell them from the first two will go looking for a network bug that is not
/// there.
nonisolated enum MeshTunnelEndReason: String, CaseIterable, Sendable {

    /// The periodic heartbeat could not be written to its channel. The link cannot carry the
    /// smallest frame the transport has, so it is not a link.
    case heartbeatSendFailed

    /// The control stream's receive loop threw: the connection failed, the peer closed it, or QUIC
    /// timed it out. The carried detail is the framework's error text, which is what tells the
    /// three apart.
    case controlStreamEnded

    /// The signed channel introduction did not complete, so no tunnel was ever established. Charged
    /// to the dial budget rather than reported as a disconnect.
    case introductionFailed

    /// The bounded receive loop retired after its frame budget. Not a fault — a Power of 10 rule 2
    /// bound doing its job — but a tunnel ending all the same.
    case frameBudgetSpent

    /// The owner evicted this peer's slot. A local decision, not a network event.
    case localEviction

    /// A duplicate tunnel to the same verified peer was collapsed. Benign, charged to nothing.
    case redundantDuplicate

    /// Frozen stand-in for the fingerprint of a tunnel that ended before it verified anyone. A
    /// tunnel can die mid-introduction, and the line still has to name *something* in the slot the
    /// fingerprint occupies or a transcript reader cannot align the columns.
    static let unverifiedFingerprint = "unverified"

    /// Whether this end is an ordinary part of the radio's operation rather than a fault.
    ///
    /// Read by the log level: a benign end is a `notice`, a fault is an `error`. Without the split
    /// every tidy-up looks like a failure in Console, which is the noise that gets a diagnostic
    /// filtered out and then forgotten.
    var isBenign: Bool {
        switch self {
        case .localEviction, .redundantDuplicate: return true
        case .heartbeatSendFailed, .controlStreamEnded, .introductionFailed, .frameBudgetSpent:
            return false
        }
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
    /// the feasibility lane actually ran under, and the MC re-invite budget it replaced.
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

    /// Times the re-propose sweep may offer one endpoint to the owner in a session.
    ///
    /// **Deliberately never reset**, unlike ``maxDialAttempts``, which `noteReady` refills on every
    /// successful connect. That refill is right for dialing — a peer that connects and later drops
    /// deserves a fresh campaign — and wrong for re-proposing, because the loop this bounds is
    /// exactly *connect → the owner refuses the seat → disconnect → idle with a full budget*: a
    /// locally-kicked peer, or a removed member, would otherwise be re-offered every sweep for the
    /// life of the session. Six is generous for the case the sweep exists for (an owner whose gate
    /// was momentarily shut) and finite for the case it must not sustain. Nothing else is capped by
    /// it: the browser's own announcement and the dial retry budget are untouched.
    ///
    /// The one thing that gives a booking back is ``refundRepropose(_:)``, and it is not a refill:
    /// it consumes the **booking** that paid for one tunnel, and only when that tunnel ended in a
    /// pre-commit timeout — not the loop above, because nobody refused anything. A refusal's own
    /// teardown consumes its booking, so six refusals still end the sweep for the session however
    /// many timeouts are interleaved on the same endpoint, and an inbound tunnel — which books
    /// nothing — can never hand back a booking an offer paid for.
    static let maxReproposalsPerEndpoint = 6

    /// Times a pre-commit timeout may hand one endpoint's booking back in a session.
    ///
    /// **Never reset either**, and for the cap above's own reason. A refund is right for the pair
    /// who missed the 15 cm hold and will manage it next time; it is wrong as an unlimited
    /// allowance, because a peer whose *every* tunnel ends in a timeout would refund every offer it
    /// was ever made and the six-offer cap would never be reached — the sweep would re-offer it for
    /// the life of the session, which is exactly the unbounded shape
    /// ``maxReproposalsPerEndpoint`` exists to forbid. The five-minute proximity gate
    /// (`Engine/ProximityCoordinator.swift:1320`) rate-limits that loop to roughly one offer per
    /// five minutes per endpoint; it does not bound it, and a bound is what this table trades in.
    /// Two is what the refund is for — an endpoint gets its six offers plus two more, eight in all
    /// — and it is finite for the shape it must not sustain.
    static let maxTimeoutRefundsPerEndpoint = 2

    /// One endpoint's dial bookkeeping. Private because the phase is the only part callers reason
    /// about, and the attempt count must not be settable from outside the transitions that own it.
    private struct Link: Equatable {
        var phase: MeshLinkPhase
        var dialAttempts: Int
        var retryDueAt: Date?

        /// Whether a re-propose offer paid for this link.
        ///
        /// The booking, not the counter, is what ``refundRepropose(_:)`` consumes: set by
        /// ``admitRepropose(_:)``, carried through the dial and the live tunnel, cleared by the
        /// refund and by every other end. That is what makes a refund answer *this* tunnel — an
        /// inbound tunnel starts unbooked because no offer preceded it, a second timeout reported
        /// for the same tunnel finds the booking already spent, and a tunnel the owner refused has
        /// it cleared by its own teardown before any later timeout can reach it.
        ///
        /// Deliberately without a default, so a new construction site has to decide.
        var reproposeBooked: Bool
    }

    private var links: [MeshLinkKey: Link] = [:]
    /// Re-proposals booked per endpoint. Bounded by the endpoint cache: entries are only ever added
    /// for a browsed key, and they die with the cache entry in ``forget(_:)``, the oldest-first
    /// eviction and ``removeAll()``.
    private var reproposals: [MeshLinkKey: Int] = [:]
    /// Timeout refunds already given per endpoint, against ``maxTimeoutRefundsPerEndpoint``.
    /// Bounded and evicted exactly as ``reproposals`` is, and for the same reason.
    private var reproposalRefunds: [MeshLinkKey: Int] = [:]
    private var cache: [MeshLinkKey: MeshEndpointRecord] = [:]
    /// First-seen order, for the cache's oldest-first eviction.
    private var cacheOrder: [MeshLinkKey] = []
    /// The signing key a dial of this device's proved for a browsed endpoint (2026-09-23) — see
    /// ``noteProvenOwner(_:signingPublicKey:)``. Bounded by the endpoint cache: a key is added only
    /// for a cached endpoint and dies with its cache entry in ``forget(_:)``, the oldest-first
    /// eviction and ``removeAll()``.
    private var provenOwners: [MeshLinkKey: Data] = [:]

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

    /// Books one re-proposal of `key` to the owner and says whether the sweep may make it.
    ///
    /// Booking on the *refused* answer too is the point: a cap that only counted accepted offers
    /// would never be reached by the loop it exists to stop. See ``maxReproposalsPerEndpoint``.
    ///
    /// It books in two places, and the second is what makes the refund honest: the per-endpoint
    /// counter the cap reads, and ``Link/reproposeBooked`` on the link itself — the marker saying
    /// *this* link was paid for by an offer, which is the only thing ``refundRepropose(_:)`` gives
    /// back.
    mutating func admitRepropose(_ key: MeshLinkKey) -> Bool {
        let spent = reproposals[key, default: 0]
        guard spent < Self.maxReproposalsPerEndpoint else { return false }
        reproposals[key] = spent + 1
        var link = links[key] ?? Link(
            phase: .idle, dialAttempts: 0, retryDueAt: nil, reproposeBooked: false
        )
        link.reproposeBooked = true
        links[key] = link
        return true
    }

    /// Consumes the re-propose **booking** that paid for this endpoint's link, handing the offer
    /// back when — and only when — that link ended in a pre-commit timeout.
    ///
    /// The only caller is a ``MeshSlotEvictionCause/preCommitTimeout``: the owner seated the peer,
    /// nobody refused it, and the pre-commit deadline simply ran out. That deadline is **five
    /// minutes**, not the 25 s / 60 s connection-phase timer `handleChannelReady` arms:
    /// `ProximityCoordinator.transitionToProximityGate` cancels that one the moment the identity
    /// introduction verifies and replaces it with a five-minute gate
    /// (`Engine/ProximityCoordinator.swift:1320`) — which is exactly the state a provisionally
    /// admitted stranger sits in. Charging that end to a budget the table deliberately never
    /// refills is how a genuine friend who cannot get two phones together on the sixth attempt is
    /// locked out for the rest of the session (D-4.3 Option 1's "two bounds to name").
    ///
    /// **It is the booking that is consumed, not the counter**, and that is the whole of why it
    /// cannot become the refill ``maxReproposalsPerEndpoint``'s doc rules out:
    ///
    /// * an INBOUND tunnel books nothing — ``admitInbound(from:preference:now:)`` starts the link
    ///   unbooked — so a peer that dialed *this* device and then timed out gives back nothing,
    ///   least of all a booking an earlier owner refusal had spent;
    /// * a second timeout reported for the same link finds the booking already spent;
    /// * a link the owner refused has its booking cleared by its own teardown (``noteClosed(_:)``),
    ///   so six refusals still end the sweep with timeouts interleaved on that same endpoint.
    ///
    /// And it is capped: ``maxTimeoutRefundsPerEndpoint`` refunds per endpoint per session, never
    /// reset, so an endpoint whose every tunnel times out is offered eight times in all and then
    /// never again. The booking is consumed even when that cap is spent — the link it paid for is
    /// over either way, and leaving it set would let some later end refund it.
    mutating func refundRepropose(_ key: MeshLinkKey) {
        guard links[key]?.reproposeBooked == true else { return }
        links[key]?.reproposeBooked = false
        let refunded = reproposalRefunds[key, default: 0]
        guard refunded < Self.maxTimeoutRefundsPerEndpoint else { return }
        let spent = reproposals[key, default: 0]
        guard spent > 0 else { return }
        reproposalRefunds[key] = refunded + 1
        reproposals[key] = spent - 1
    }

    /// Re-proposals booked for this endpoint so far — the read a test asserts the cap through.
    func reproposalCount(of key: MeshLinkKey) -> Int {
        reproposals[key, default: 0]
    }

    /// Timeout refunds already given for this endpoint — the read a test asserts
    /// ``maxTimeoutRefundsPerEndpoint`` through, and the one that tells "the refund was declined"
    /// apart from "there was nothing to refund" in a failure message.
    func reproposalRefundCount(of key: MeshLinkKey) -> Int {
        reproposalRefunds[key, default: 0]
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
        let link = links[key] ?? Link(
            phase: .idle, dialAttempts: 0, retryDueAt: nil, reproposeBooked: false
        )
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
        // The booking travels with the link it paid for: this dial IS the offer being taken up.
        links[key] = Link(
            phase: .dialing, dialAttempts: link.dialAttempts + 1, retryDueAt: nil,
            reproposeBooked: link.reproposeBooked
        )
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
        // `reproposeBooked: false` is load-bearing. An inbound tunnel is not preceded by an offer,
        // so it must not inherit a booking an earlier offer to this endpoint spent: a timeout on it
        // would otherwise refund something this side never paid for.
        links[key] = Link(phase: .connected, dialAttempts: 0, retryDueAt: nil, reproposeBooked: false)
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
        links[key] = Link(
            phase: .connected, dialAttempts: 0, retryDueAt: nil,
            // Carried, not reset: a tunnel that reaches ready is the tunnel the offer paid for, and
            // it is the one a pre-commit timeout may hand back.
            reproposeBooked: links[key]?.reproposeBooked ?? false
        )
        remember(lastSeen: key, at: now)
    }

    /// Records that an outbound attempt to `key` ended without a tunnel, and says what happens next.
    ///
    /// An endpoint with no booked attempt (a failure reported twice, or one for a link the table has
    /// already forgotten) reads as a spent budget rather than starting a new campaign — a retry loop
    /// that can be re-armed by a duplicate callback is exactly the unbounded loop rule 2 forbids.
    mutating func noteDialFailed(_ key: MeshLinkKey, now: Date) -> MeshDialOutcome {
        let attempts = links[key]?.dialAttempts ?? Self.maxDialAttempts
        // A dial campaign that is still running is still the offer's: the retry that follows is the
        // same attempt to reach the peer the sweep proposed.
        let booked = links[key]?.reproposeBooked ?? false
        guard attempts < Self.maxDialAttempts else {
            links[key] = Link(
                phase: .exhausted, dialAttempts: Self.maxDialAttempts, retryDueAt: nil,
                reproposeBooked: booked
            )
            return .giveUp(attempts: Self.maxDialAttempts)
        }
        links[key] = Link(
            phase: .backingOff,
            dialAttempts: attempts,
            retryDueAt: now.addingTimeInterval(Self.dialRetryDelaySeconds),
            reproposeBooked: booked
        )
        return .retry(attempt: attempts + 1, delay: Self.dialRetryDelay)
    }

    /// Records that a live tunnel to `key` went down. The endpoint returns to
    /// ``MeshLinkPhase/idle`` with a full budget — a disconnect is not a dial failure, and charging
    /// it to the retry budget is how a peer that reconnects a few times becomes permanently
    /// undialable.
    ///
    /// The re-propose booking dies with the tunnel, and that is the other half of
    /// ``refundRepropose(_:)``'s honesty: whatever ended this link, it was not a pre-commit timeout
    /// — the refund runs *before* the teardown that lands here — so the offer that paid for it is
    /// spent, and a later timeout on a re-dial has to have been paid for again.
    ///
    /// **An endpoint the cache does not hold keeps NO record** (owner-calls item 4, 2026-09-22). An
    /// inbound tunnel from a peer this side never browsed is keyed by its pending key, which the
    /// cache never holds and ``forget(_:)`` — driven by the browser's *lost* — never reaches, so the
    /// idle record written here was the table's one unbounded growth path: one per inbound tunnel
    /// ever closed, for the session's life. Dropping it changes no answer a reachable path asks:
    /// an idle record with a full budget, no retry and no booking reads as a key never seen
    /// (``phase(of:)`` answers ``MeshLinkPhase/idle``, nothing is booked, nothing is due). The ONE
    /// reader that tells the two apart is ``noteDialFailed(_:now:)`` — an absent key reads as a
    /// spent budget, an idle record as a retry — and no path reaches it here: `endTunnel` reports a
    /// dial failure OR a close for a tunnel, never both (the owner-calls re-verify). A cached
    /// endpoint still gets its idle record, bounded by the cache and reaped with its entry
    /// (``evictOldestCachedEndpointIfFull()``, ``forget(_:)``).
    mutating func noteClosed(_ key: MeshLinkKey) {
        guard cache[key] != nil else {
            links.removeValue(forKey: key)
            return
        }
        links[key] = Link(phase: .idle, dialAttempts: 0, retryDueAt: nil, reproposeBooked: false)
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
        reproposals.removeValue(forKey: key)
        reproposalRefunds.removeValue(forKey: key)
        cache.removeValue(forKey: key)
        cacheOrder.removeAll { $0 == key }
        provenOwners.removeValue(forKey: key)
    }

    /// Drops everything. The teardown call: link state and endpoint cache both die with the
    /// session, which is the privacy constraint that keeps this table off the wipe ledger.
    mutating func removeAll() {
        links.removeAll()
        reproposals.removeAll()
        reproposalRefunds.removeAll()
        cache.removeAll()
        cacheOrder.removeAll()
        provenOwners.removeAll()
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

    /// How many link records the table is holding — the value the bounded-growth cells read.
    var linkRecordCount: Int {
        links.count
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
    /// **Attributable is not bound** (2026-09-23). The `sid` is the verified peer's unsigned CLAIM,
    /// and nothing ties an advertisement to a key, so the answer here is only a candidate: the
    /// radio keys an inbound tunnel under it only when ``claimResolves(_:to:heldBy:)`` finds nothing
    /// this device verified that contradicts the claim.
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

    // MARK: - Advertisement ownership (2026-09-23)

    /// Records that a dial of this device's to `key` reached a listener that proved
    /// `signingPublicKey` in the signed channel introduction — the one fact about who answers a
    /// browsed advertisement that is not a peer's own word.
    ///
    /// **Why a dial, and nothing else.** An INBOUND tunnel is tied to a browsed advertisement only
    /// by the `sid` its hello claims (``key(advertisingSessionID:)``), and that claim is unsigned
    /// and unbindable: the TXT record that publishes a `sid` withholds `fp` on purpose, so nothing
    /// ties an advertisement to a key, and signing the claim would only prove the claimant chose to
    /// make it (``MeshChannelHello/sessionID``). A dial is opened to the advertisement's own
    /// endpoint, so the key its introduction proves is the key of whoever answers there — as far
    /// as the local link's Bonjour resolution can be trusted, which is the trust every dial already
    /// places in it. The owner is bound to the endpoint, not to the `sid` it happens to carry.
    ///
    /// A key the cache does not hold is not recorded, so the map is bounded by the cache.
    mutating func noteProvenOwner(_ key: MeshLinkKey, signingPublicKey: Data) {
        guard cache[key] != nil else { return }
        provenOwners[key] = signingPublicKey
    }

    /// The key a dial of this device's proved for `key`, or nil when no dial has.
    func provenOwner(of key: MeshLinkKey) -> Data? {
        provenOwners[key]
    }

    /// How many advertisements have a proven owner — the read the bounded-growth cells use.
    var provenOwnerCount: Int {
        provenOwners.count
    }

    /// Whether an inbound tunnel that proved `signingPublicKey` may live under `key`, the browsed
    /// advertisement its unsigned `sid` names (the reviewer's squat, 2026-09-23).
    ///
    /// No when something this device verified contradicts the claim:
    /// * a dial of this device's proved a DIFFERENT key answers that advertisement
    ///   (``provenOwner(of:)``) — the claimant is naming somebody else's `sid`;
    /// * a live tunnel verified as a different key already holds `key` (`holder`) — two identities
    ///   claim one advertisement, and at most one of them is telling the truth.
    ///
    /// The tunnel then keeps its own connection key, which is what an inbound tunnel whose `sid`
    /// matches nothing browsed has always done. Before this, the first case let a verified peer
    /// take an absent member's key, and the second REFUSED that member's own re-link as a duplicate
    /// of the squatter's tunnel — locked out until the squatter's tunnel ended. Neither answer can
    /// move an honest peer: a `sid` is a per-launch random UUID, so no honest device claims one
    /// another device advertises.
    ///
    /// - Parameters:
    ///   - key: The browsed endpoint the claimed `sid` resolved to.
    ///   - signingPublicKey: The key the inbound tunnel's own introduction proved.
    ///   - holder: The key a live tunnel under `key` was verified as, or nil when none holds it.
    /// - Returns: `true` when the tunnel may take `key`.
    func claimResolves(_ key: MeshLinkKey, to signingPublicKey: Data, heldBy holder: Data?) -> Bool {
        if let owner = provenOwners[key], owner != signingPublicKey { return false }
        if let holder, holder != signingPublicKey { return false }
        return true
    }

    /// Whether the re-propose sweep must pass over the idle browsed endpoint `key`, because the
    /// device behind it is already connected under ANOTHER key — or because nothing can say.
    ///
    /// The losing half of a collapsed duplicate returns to idle on purpose, and re-offering it would
    /// re-dial a device this session already holds a tunnel to, every interval, forever. The test
    /// used to be the advertised `sid` against the `sid` on each live tunnel — a peer's own unsigned
    /// claim, so a peer claiming an absent member's `sid` on its own tunnel made that member read as
    /// connected, and it was never re-dialed (2026-09-23). When a dial of this device's has proven
    /// who answers `key` (``provenOwner(of:)``), the test is that IDENTITY among the live tunnels,
    /// which no claim can fake; the `sid` test is the fallback for an advertisement no dial has
    /// proven yet.
    ///
    /// An advertisement with no `sid` at all is passed over, exactly as the sweep always passed
    /// over it.
    ///
    /// - Parameters:
    ///   - key: An idle browsed endpoint holding no tunnel.
    ///   - liveSessionIDs: The `sid` every live verified tunnel claimed.
    ///   - liveSigningKeys: The key every live verified tunnel proved.
    /// - Returns: `true` when the sweep must not offer `key` to the owner.
    func sweepSkips(
        _ key: MeshLinkKey,
        liveSessionIDs: Set<String>,
        liveSigningKeys: Set<Data>
    ) -> Bool {
        guard let advertised = cache[key]?.advertisement[MeshLinkAdvertisement.sessionIDKey] else {
            return true
        }
        guard let owner = provenOwners[key] else { return liveSessionIDs.contains(advertised) }
        return liveSigningKeys.contains(owner)
    }

    /// Makes room for one more cache entry, dropping the oldest when the cache is full.
    private mutating func evictOldestCachedEndpointIfFull() {
        guard cacheOrder.count >= Self.maxCachedEndpoints, let oldest = cacheOrder.first else {
            return
        }
        cacheOrder.removeFirst()
        cache.removeValue(forKey: oldest)
        // The re-propose budget is keyed by browsed endpoint, so it is bounded by this cache and
        // must be evicted with it — otherwise a busy room grows one map without end. The booking
        // goes with the counters so the two cannot disagree about an endpoint whose budget is gone.
        reproposals.removeValue(forKey: oldest)
        reproposalRefunds.removeValue(forKey: oldest)
        provenOwners.removeValue(forKey: oldest)
        links[oldest]?.reproposeBooked = false
        // Owner-calls item 4 (2026-09-22): the link record goes with its cache entry when it is
        // IDLE — the one phase whose record answers every reachable reader as having none (only
        // `noteDialFailed` tells them apart, and an idle key has no dial in flight to fail), so the
        // eviction loses nothing. A live link (dialing, connected) keeps its slot, and a backing-off or exhausted
        // one keeps the retry state that stops a spent peer being hammered; both are reaped by
        // `forget(_:)` when the browser loses the endpoint, as before.
        if links[oldest]?.phase == .idle { links.removeValue(forKey: oldest) }
    }

    /// Refreshes an existing cache entry's `lastSeenAt` without inventing one for an endpoint the
    /// browser never reported (an inbound tunnel from a peer this side never browsed is normal).
    private mutating func remember(lastSeen key: MeshLinkKey, at now: Date) {
        guard var record = cache[key] else { return }
        record.lastSeenAt = now
        cache[key] = record
    }
}
