import Foundation

// MARK: - MeshHeartbeatChannel

/// Which of a tunnel's two pipes one heartbeat rides.
///
/// Plan §7.1 maps heartbeats onto QUIC datagrams, and that is still the preference — an unreliable
/// 22-byte frame is exactly what a liveness beat wants, and it costs the control stream nothing.
/// What the plan did not say is what happens when the datagram flow will not carry one.
///
/// **It routinely will not.** RFC 9221 datagrams exist only if the *peer* advertised a non-zero
/// `max_datagram_frame_size`. On the simulator↔simulator lane both ends request 1024 bytes and both
/// read a usable size of **0** — measured first by the feasibility probe (Lane A2, 2026-08-31) and
/// reproduced against the shipping transport in P2 item 15, so it is a property of the lane and not
/// of the probe. A heartbeat written into that flow cannot arrive.
///
/// ## Why the reported size is evidence and not the gate
///
/// `usableDatagramFrameSize` is only exposed on the **parent connection**, and the underlying
/// `nw_quic_get_stream_usable_datagram_frame_size` is documented as reading *a QUIC datagram flow's*
/// metadata. A parent connection is not a datagram flow, so a zero there is consistent with two very
/// different worlds: datagrams did not negotiate, or they did and this is the wrong object to ask.
/// Gating on it would silently pick one. Attempting the write instead **asks the transport**, and
/// the answer lands in the log either way — which is how this settles the loop's oldest open
/// question rather than restating it.
///
/// So: try the designed channel once per tunnel, believe the result, and never try again on that
/// tunnel. `datagramWriteFailed` is that one-shot latch.
///
/// ## What a failed beat must not do
///
/// Tear the tunnel down. Treating a write failure on a channel that was never usable as proof the
/// *peer* is gone is how a healthy tunnel was reaped and silently re-dialed. The answer is not to
/// stop beating — a dead-peer detector that has been switched off detects nothing — but to beat on
/// the pipe that exists. The control stream is already length-framed, already carried the signed
/// introduction, and 22 bytes twice a minute is not a cost worth a second mechanism.
///
/// A pure function of two booleans, so the choice is settled at tier 1 and the transport only acts
/// on the answer.
nonisolated enum MeshHeartbeatChannel: Equatable, Sendable {

    /// A QUIC datagram — the plan's channel, and the one tried first on every fresh tunnel.
    case datagram

    /// The reliable control stream, length-framed like every other frame on it. The fallback, and
    /// the only channel that exists at all when the datagram flow will not carry a beat.
    case controlStream

    /// The channel this tunnel's next heartbeat rides.
    ///
    /// A tunnel with no datagram flow at all answers ``controlStream`` without an experiment; one
    /// whose datagram write has already failed answers the same and does not repeat it. Everything
    /// else gets the designed channel.
    static func choice(hasDatagramFlow: Bool, datagramWriteFailed: Bool) -> MeshHeartbeatChannel {
        guard hasDatagramFlow, !datagramWriteFailed else { return .controlStream }
        return .datagram
    }
}

// MARK: - MeshHeartbeatSchedule

/// When each live QUIC link is next due a heartbeat datagram, with no timer inside it.
///
/// Plan §7.1 maps MultipeerConnectivity's `.unreliable` sends onto QUIC datagrams and §7.3 asks for
/// a 30 s heartbeat. The *scheduling* half is separated from the sending half for the same reason
/// ``MeshLinkTable`` is separated from ``NetworkMeshSession``: a per-link `Task.sleep` loop is
/// untestable except by waiting, and this repository has a documented flake family whose root cause
/// was exactly that. Here time is a `now:` argument, so a test advances a ``VirtualClock`` and reads
/// ``due(now:)``.
///
/// One shared poll drives every link. That is deliberate: N self-rescheduling timers is N ways for
/// a heartbeat to outlive the connection it was beating for, and the MC transport has already been
/// bitten once by a scheduled closure surviving its owner.
///
/// **What this does not do.** It does not decide that a silent peer is gone. QUIC surfaces
/// connection loss through its own state machine, which is what ``NetworkMeshSession`` acts on
/// today; a heartbeat-derived liveness verdict would be a second, independent disconnect policy and
/// belongs with the membership work in P3, not here.
nonisolated struct MeshHeartbeatSchedule {

    /// Seconds between heartbeats on a live link (plan §7.3).
    static let intervalSeconds: TimeInterval = 30

    /// ``intervalSeconds`` as a `Duration`, computed from the one stored constant so the two
    /// spellings cannot drift.
    static var interval: Duration { .seconds(intervalSeconds) }

    /// Heartbeats a link may miss before QUIC's own idle timer reaps the connection.
    ///
    /// Three, not one: a single dropped beat on a link-local radio is a hiccup, and a transport that
    /// cannot survive one has made its keepalive into a coin flip.
    static let missedBeatsBeforeIdleReap = 3

    /// The QUIC `max_idle_timeout` this transport declares, in milliseconds.
    ///
    /// **The defect this closes, measured on the radio in P2 item 15.** The heartbeat interval was
    /// set to 30 s and the idle timeout was left at whatever Network.framework defaults to — which
    /// is also about 30 s. So the first beat was scheduled to go out at the exact moment the thing
    /// it existed to prevent had already happened, and the idle timer won nearly every race: Lane C
    /// logged `NWError 60 - Operation timed out` on both sides, roughly every 37 s, with the beat
    /// almost never firing at all. A keepalive that fires no sooner than the timeout it is
    /// keeping alive against is not a keepalive.
    ///
    /// Derived from ``intervalSeconds`` rather than written out, so the two cannot drift into that
    /// race again: whatever the interval becomes, the timeout stays ``missedBeatsBeforeIdleReap``
    /// intervals above it. QUIC negotiates the **minimum** of the two endpoints' advertised values
    /// (RFC 9000 §10.1), and both ends of a Fernlet mesh run this same constant, so the effective
    /// timeout is this one.
    ///
    /// This does not weaken dead-peer detection, it relocates it. The app's heartbeat is the
    /// detector; QUIC's idle timer is the backstop behind it. Before this, the backstop *was* the
    /// detector, firing so early that the detector never ran.
    static var idleTimeoutMilliseconds: Int {
        Int(intervalSeconds) * missedBeatsBeforeIdleReap * 1_000
    }

    /// Cap on tracked links — the connection cap, since only a live link is ever beaten. Bounded by
    /// construction (Power of 10 rule 3) rather than by trusting the caller to stop what it starts.
    static let maxTrackedLinks = MeshLinkTable.maxConcurrentLinks

    private var nextDueAt: [MeshLinkKey: Date] = [:]

    /// An empty schedule. A session owns exactly one.
    init() {}

    /// Starts beating `key`, first heartbeat one interval from now.
    ///
    /// Refuses silently once ``maxTrackedLinks`` links are tracked — a caller that leaks links past
    /// the connection cap has a bug the schedule must not amplify, and re-starting an already
    /// tracked link (a reconnect) is always allowed because it replaces rather than adds.
    mutating func start(_ key: MeshLinkKey, now: Date) {
        guard nextDueAt[key] != nil || nextDueAt.count < Self.maxTrackedLinks else { return }
        nextDueAt[key] = now.addingTimeInterval(Self.intervalSeconds)
    }

    /// Re-arms `key` after a heartbeat went out. A key that is not tracked stays untracked: a send
    /// on a stopped link must not resurrect its schedule.
    mutating func noteSent(_ key: MeshLinkKey, now: Date) {
        guard nextDueAt[key] != nil else { return }
        nextDueAt[key] = now.addingTimeInterval(Self.intervalSeconds)
    }

    /// Links whose heartbeat is due at `now`, oldest key first for a deterministic order.
    ///
    /// Due times are absolute, so a poll that runs late fires every link it passed exactly once —
    /// it never has to catch up by firing one link repeatedly.
    func due(now: Date) -> [MeshLinkKey] {
        nextDueAt
            .filter { $0.value <= now }
            .keys
            .sorted { $0.rawValue < $1.rawValue }
    }

    /// Stops beating `key`. Called on disconnect, on eviction, and on a refused duplicate tunnel.
    mutating func stop(_ key: MeshLinkKey) {
        nextDueAt.removeValue(forKey: key)
    }

    /// Stops everything — the teardown call, alongside ``MeshLinkTable/removeAll()``.
    mutating func removeAll() {
        nextDueAt.removeAll()
    }

    /// How many links are being beaten. The read that lets a test assert the schedule is empty
    /// after teardown instead of inferring it from silence.
    var trackedCount: Int {
        nextDueAt.count
    }
}
