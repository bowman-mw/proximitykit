import Foundation

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
