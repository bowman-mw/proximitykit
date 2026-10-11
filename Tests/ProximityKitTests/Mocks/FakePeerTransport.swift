import Combine
import Foundation
@testable import ProximityKit

// The deterministic in-memory transport fabric. `MockMultipeerTransport` beside it stays: it is a
// single-peer script for coordinator handshake tests and does its job. This is the other thing —
// a multi-endpoint medium with links that can be delayed, cut and healed on a clock a test owns,
// which is what plan §16.2's partition matrix needs and what a scripted single-peer mock cannot be
// bent into.
//
// The one rule that governs the whole file: **no wall-clock sleeps**. This repository has a
// documented flake family whose root cause was wait helpers with no deadline floor, and a partition
// suite that slept would reproduce it at scale. Time here only moves when `VirtualClock.advance`
// says so, so a scenario either completes deterministically or hangs visibly on the assertion —
// never intermittently, and never differently under CI load.

/// A clock a test owns outright: it reads whatever the test set, and work scheduled on it runs only
/// when the test advances past its due time.
///
/// Ordering is by due time, then by insertion, so two items due at the same instant fire in the
/// order they were scheduled. Work scheduled *during* an advance is honoured within the same
/// advance if it falls due inside the window — that is what lets a latency chain (send → deliver →
/// reply → deliver) settle in one call.
@MainActor
final class VirtualClock {
    /// Ceiling on how many scheduled items one ``advance(by:)`` may fire. A scenario that exceeds it
    /// is looping — an item rescheduling itself at zero delay — and should fail loudly rather than
    /// spin (Power of 10 rule 2: every loop bounded).
    static let maxFiringsPerAdvance = 4_096

    private(set) var now: Date
    private var pending: [Entry] = []
    private var nextSequence: UInt64 = 0

    /// One scheduled unit of work. `sequence` breaks due-time ties so ordering is total.
    private struct Entry {
        let due: Date
        let sequence: UInt64
        let work: () -> Void
    }

    init(now: Date = Date(timeIntervalSince1970: 1_700_000_000)) {
        self.now = now
    }

    /// Schedules `work` to run once the clock passes `delay` from the current instant. A
    /// non-positive delay is due immediately — at the *current* instant, so it still waits for the
    /// next ``advance(by:)`` rather than running inline.
    func schedule(after delay: Duration, _ work: @escaping () -> Void) {
        pending.append(Entry(due: now.addingTimeInterval(Self.seconds(delay)), sequence: nextSequence, work: work))
        nextSequence &+= 1
    }

    /// Moves time forward, firing everything that comes due in order.
    ///
    /// - Returns: how many items fired, so a test can assert that a step did something rather than
    ///   silently nothing.
    @discardableResult
    func advance(by duration: Duration) -> Int {
        let target = now.addingTimeInterval(Self.seconds(duration))
        var fired = 0
        while fired < Self.maxFiringsPerAdvance {
            let dueIndex = pending.indices
                .filter { pending[$0].due <= target }
                .min { lhs, rhs in
                    let (a, b) = (pending[lhs], pending[rhs])
                    return a.due == b.due ? a.sequence < b.sequence : a.due < b.due
                }
            guard let dueIndex else { break }
            let entry = pending.remove(at: dueIndex)
            now = max(now, entry.due)
            entry.work()
            fired += 1
        }
        now = max(now, target)
        return fired
    }

    /// Number of items still waiting. A scenario that ends with work pending has an unfinished
    /// link — usually a frame stuck behind a partition, which is exactly what a test wants to
    /// assert about.
    var pendingCount: Int { pending.count }

    private nonisolated static func seconds(_ duration: Duration) -> TimeInterval {
        let parts = duration.components
        return TimeInterval(parts.seconds) + TimeInterval(parts.attoseconds) / 1e18
    }
}

/// The in-memory medium a set of ``FakePeerTransport`` endpoints share: who can reach whom, how
/// long a frame takes, and what a cut link does to the frames already in flight across it.
///
/// Endpoints are addressed by ``PeerHandle``, and a handle's ``PeerEndpointKey`` is what the fabric
/// routes on — deliberately, because that is the identity a real transport preserves across a
/// re-discovery. A test that wants to model discovery churn hands out two handles with different
/// `id`s and the same endpoint key, and the fabric treats them as one device, exactly as
/// `NetworkMeshSession` does (and the retired `MeshMultipeerSession` did before it).
@MainActor
final class FakePeerNetwork {
    /// Cap on endpoints in one fabric — the roster cap (8) with headroom, so a runaway scenario
    /// generator fails an assertion instead of allocating without end.
    static let maxEndpoints = 32

    let clock: VirtualClock

    private var endpoints: [PeerEndpointKey: FakePeerTransport] = [:]
    private var handles: [PeerEndpointKey: PeerHandle] = [:]
    /// Every link is symmetric and starts absent; `connect` creates it, `partition` suspends it.
    private var connected: Set<Link> = []
    private var partitioned: Set<Link> = []
    private var latencies: [Link: Duration] = [:]

    /// Default one-hop delay. Non-zero on purpose: a fabric that delivered instantly would let a
    /// test pass that depends on ordering the real radio does not guarantee.
    static let defaultLatency: Duration = .milliseconds(20)

    /// An unordered endpoint pair. Keeping "A cannot reach B" and "B cannot reach A" as ONE value is
    /// what stops the two halves of a link drifting apart — the bug a directional model invites.
    ///
    /// A set, not a sorted pair: sorting would need a total order over an opaque key, and the
    /// obvious one (hash value) is not injective, so two colliding keys would produce two different
    /// "canonical" pairs and the symmetry it exists to guarantee would silently fail.
    private struct Link: Hashable {
        private let members: Set<PeerEndpointKey>

        init(_ a: PeerEndpointKey, _ b: PeerEndpointKey) {
            members = [a, b]
        }
    }

    /// A `@MainActor` type cannot be a default argument value, so the default is expressed as nil
    /// and resolved in the body — the same shape every other main-actor default in this repo takes.
    init(clock: VirtualClock? = nil) {
        self.clock = clock ?? VirtualClock()
    }

    // MARK: - Building the fabric

    /// Adds an endpoint and returns its transport. The returned handle is what other endpoints
    /// address it by; `displayHint` is a label only, as it is in production.
    func addEndpoint(named name: String) -> (transport: FakePeerTransport, handle: PeerHandle) {
        precondition(endpoints.count < Self.maxEndpoints, "FakePeerNetwork endpoint cap exceeded")
        let handle = PeerHandle(
            id: UUID(),
            displayHint: name,
            discoveryInfo: nil,
            advertisedFingerprint: nil
        )
        let transport = FakePeerTransport(handle: handle, network: self)
        endpoints[handle.endpoint] = transport
        handles[handle.endpoint] = handle
        return (transport, handle)
    }

    /// Opens a link and publishes `.connected` at both ends after one hop of latency.
    func connect(_ a: PeerHandle, _ b: PeerHandle) {
        let link = Link(a.endpoint, b.endpoint)
        guard !connected.contains(link) else { return }
        connected.insert(link)
        let delay = latencies[link] ?? Self.defaultLatency
        clock.schedule(after: delay) { [weak self] in
            self?.endpoints[a.endpoint]?.deliverConnected(b)
            self?.endpoints[b.endpoint]?.deliverConnected(a)
        }
    }

    /// Closes a link and publishes `.disconnected` at both ends after one hop.
    ///
    /// Distinct from ``partition(_:from:)``: a disconnect is a link the endpoints are *told* about,
    /// a partition is one that silently stops carrying frames. Plan §3 invariant 1 turns on that
    /// difference, so the fabric must be able to produce each without the other.
    func disconnect(_ a: PeerHandle, _ b: PeerHandle, reason: String = "Simulated disconnect") {
        let link = Link(a.endpoint, b.endpoint)
        guard connected.remove(link) != nil else { return }
        let delay = latencies[link] ?? Self.defaultLatency
        clock.schedule(after: delay) { [weak self] in
            self?.endpoints[a.endpoint]?.deliverDisconnected(reason: reason)
            self?.endpoints[b.endpoint]?.deliverDisconnected(reason: reason)
        }
    }

    /// Cuts a link without telling either side. Frames sent across it are dropped, not queued —
    /// matching a radio that has simply stopped reaching the other end.
    func partition(_ a: PeerHandle, from b: PeerHandle) {
        partitioned.insert(Link(a.endpoint, b.endpoint))
    }

    /// Restores a partitioned link. Frames dropped while it was cut stay dropped; convergence after
    /// a heal is the *application's* job, and a fabric that silently replayed them would prove a
    /// property the real world does not provide.
    func heal(_ a: PeerHandle, from b: PeerHandle) {
        partitioned.remove(Link(a.endpoint, b.endpoint))
    }

    /// Splits the fabric into mutually unreachable groups. Links inside a group are left alone;
    /// every link that crosses a group boundary is cut.
    func partition(into groups: [[PeerHandle]]) {
        for (index, group) in groups.enumerated() {
            for other in groups.indices where other != index {
                for near in group {
                    for far in groups[other] {
                        partition(near, from: far)
                    }
                }
            }
        }
    }

    /// Sets the one-hop delay for a link.
    func setLatency(_ latency: Duration, between a: PeerHandle, and b: PeerHandle) {
        latencies[Link(a.endpoint, b.endpoint)] = latency
    }

    /// True when a frame sent now would arrive: the link exists and is not cut.
    func canReach(_ a: PeerHandle, _ b: PeerHandle) -> Bool {
        let link = Link(a.endpoint, b.endpoint)
        return connected.contains(link) && !partitioned.contains(link)
    }

    // MARK: - Carrying frames

    /// Schedules one frame for delivery, or drops it. Called by ``FakePeerTransport/send(_:to:mode:)``.
    ///
    /// - Returns: false when the frame was dropped, so the sender can decide whether that is an
    ///   error. A partitioned link drops silently — the sender of a `bestEffort` frame is not told,
    ///   and neither is the sender of a reliable one, because a real radio does not know either
    ///   until its own timeout fires.
    @discardableResult
    func carry(_ frame: Data, from sender: PeerHandle, to recipient: PeerHandle) -> Bool {
        guard canReach(sender, recipient) else { return false }
        let link = Link(sender.endpoint, recipient.endpoint)
        let delay = latencies[link] ?? Self.defaultLatency
        clock.schedule(after: delay) { [weak self] in
            guard let self, self.canReach(sender, recipient) else { return }
            self.endpoints[recipient.endpoint]?.deliverInbound(frame, from: sender)
        }
        return true
    }
}

/// One endpoint's ``PeerTransport``: everything it does routes through the shared
/// ``FakePeerNetwork``, so a scenario is written against the fabric and observed here.
///
/// Discovery is deliberately not modelled — the production conformer, `NetworkPeerChannel`, does
/// not model it either (the shared session owns advertise/browse), so a fake that invented a
/// discovery state machine would test a shape production does not have. `startAdvertising` records
/// its discovery dictionary, `startBrowsing` its call, and each publishes the matching state, and
/// that is all. Neither takes a service type: the protocol's discovery doors carry none.
@MainActor
final class FakePeerTransport: PeerTransport {
    /// This endpoint's own handle — what other endpoints address it by.
    let handle: PeerHandle

    /// The fabric this endpoint routes through — **`weak`, never `unowned`** (P5 item 1a).
    ///
    /// The fabric is owned by the rig that built the scenario, while an endpoint is handed to a
    /// manager and lives in its `PeerSlot`. Since the manager now PINS its host for the lifetime of
    /// every detached send (invariant HP1), a send queued at the end of a cell genuinely REACHES
    /// this class after that rig — and its fabric — has gone. Held `unowned`, that read was
    /// `swift_abortRetainUnowned`, i.e. the whole test process, which is the same trap one layer
    /// down from the one item 1a closed. Weak makes the honest answer available instead: no fabric,
    /// nothing carries, and the frame is recorded in ``fabricGoneFrames`` — deliberately NOT in
    /// ``droppedFrames``, so a released rig can never satisfy a partition assertion.
    private weak var network: FakePeerNetwork?
    private let stateSubject = CurrentValueSubject<PeerTransportState, Never>(.idle)
    private let inboundSubject = PassthroughSubject<InboundPeerFrame, Never>()

    var state: AnyPublisher<PeerTransportState, Never> { stateSubject.eraseToAnyPublisher() }
    var inbound: AnyPublisher<InboundPeerFrame, Never> { inboundSubject.eraseToAnyPublisher() }
    private(set) var connectedPeers: [PeerHandle] = []

    // MARK: Recorded calls

    private(set) var sentFrames: [(data: Data, peer: PeerHandle, mode: PeerDeliveryMode)] = []
    /// Frames a LIVE fabric refused to carry, in send order. A dropped frame is the observable
    /// consequence of a partition, so it is recorded rather than thrown away.
    ///
    /// One cause only: ``FakePeerNetwork/carry(_:from:to:)`` returned false. A send that finds no
    /// fabric at all is a rig-lifetime fact, not a partition, and lands in ``fabricGoneFrames``
    /// instead (P5 item 1a review) — so a partition assertion can never be satisfied by a fabric
    /// that simply deallocated mid-cell.
    private(set) var droppedFrames: [(data: Data, peer: PeerHandle, mode: PeerDeliveryMode)] = []
    /// Frames sent after the fabric itself went away, in send order.
    ///
    /// Since ``network`` is `weak` (see its note), a send that outlives its rig reaches this class
    /// with nothing to route through. That is a statement about the RIG's lifetime, so it is kept
    /// apart from ``droppedFrames``, whose only meaning is "a live fabric refused to carry".
    private(set) var fabricGoneFrames: [(data: Data, peer: PeerHandle, mode: PeerDeliveryMode)] = []
    private(set) var receivedFrames: [InboundPeerFrame] = []
    /// A suspension a cell can install inside ``send(_:to:mode:)``, given the index of the send.
    ///
    /// The one thing this fabric does not reproduce about a real channel: `send` is `async` in the
    /// protocol and a radio genuinely parks inside it, while this implementation runs to completion
    /// with no suspension point at all. A cell whose claim is about what a SECOND MainActor door
    /// does while the first send is in flight has nothing to interleave with otherwise — the child
    /// task simply finishes first and the interleaving the production code must survive is never
    /// reached. Nil for every other cell, so nothing else changes shape.
    var sendSuspension: ((Int) async -> Void)?
    private(set) var lastDiscoveryInfo: [String: String]?
    /// How many times the coordinator asked this endpoint to browse.
    private(set) var browseStartCount = 0
    private(set) var disconnectCallCount = 0
    private(set) var isDiscoveryPaused = false

    init(handle: PeerHandle, network: FakePeerNetwork) {
        self.handle = handle
        self.network = network
    }

    // MARK: - PeerTransport

    func startAdvertising(discoveryInfo: [String: String]) async throws {
        lastDiscoveryInfo = discoveryInfo
        stateSubject.send(.advertising)
    }

    func startBrowsing() async throws {
        browseStartCount += 1
        stateSubject.send(.browsing)
    }

    func invite(_ peer: PeerHandle) async throws {
        // The pause contract, reproduced: inviting on a paused radio is undocumented behaviour in
        // production and is dropped loudly there, so the fake refuses it rather than quietly
        // working — a test that relies on it would be proving something production denies.
        guard !isDiscoveryPaused else { throw PeerTransportError.unexpectedState }
        stateSubject.send(.awaitingPeerAcceptance(peer))
    }

    func accept(_ invite: PeerPendingInvite) async throws {
        invite.respond(true)
    }

    func send(_ data: Data, to peer: PeerHandle, mode: PeerDeliveryMode) async throws {
        if let sendSuspension { await sendSuspension(sentFrames.count) }
        sentFrames.append((data, peer, mode))
        // A gone fabric carries nothing, and neither does a partitioned one — but they are DIFFERENT
        // facts, recorded apart. A pinned send may now outlive the rig that owned the fabric; that
        // must never be able to impersonate the partition a cell is asserting on.
        guard let network else {
            fabricGoneFrames.append((data, peer, mode))
            return
        }
        guard network.carry(data, from: handle, to: peer) else {
            droppedFrames.append((data, peer, mode))
            return
        }
    }

    func disconnect() async {
        disconnectCallCount += 1
        connectedPeers = []
        stateSubject.send(.idle)
    }

    // MARK: - Pause contract

    /// Matches the shipping radio (and the retired `MeshMultipeerSession` before it): the radio
    /// goes quiet to new peers while live links keep flowing, and `invite(_:)` must not be called
    /// until ``resumeDiscovery()``.
    func pauseDiscovery() { isDiscoveryPaused = true }
    func resumeDiscovery() { isDiscoveryPaused = false }

    // MARK: - Called by FakePeerNetwork

    func deliverConnected(_ peer: PeerHandle) {
        if !connectedPeers.contains(where: { $0.isSameEndpoint(as: peer) }) {
            connectedPeers.append(peer)
        }
        stateSubject.send(.connected(peer))
    }

    func deliverDisconnected(reason: String) {
        connectedPeers = []
        stateSubject.send(.disconnected(reason: reason))
    }

    func deliverInbound(_ data: Data, from peer: PeerHandle) {
        // Only the fabric calls this, so it is alive here; the guard is what `weak` costs, and it
        // states the same fact as the send path rather than forcing an optional read.
        guard let network else { return }
        let frame = InboundPeerFrame(
            peer: peer,
            data: data,
            receivedAt: network.clock.now,
            bytesReceived: data.count
        )
        receivedFrames.append(frame)
        inboundSubject.send(frame)
    }
}

// MARK: - MeshPeerChannel

/// The fake also serves as a mesh slot CHANNEL, so `FakeMeshTransportSession` can hand
/// `MeshNetworkManager` a real endpoint of this fabric where production hands it a
/// `NetworkPeerChannel` (the retired MC radio handed a `PeerChannelTransport` in its place).
///
/// `peer` is this endpoint's own handle: a slot addresses its channel by the peer that channel
/// carries, and on the fabric that is the endpoint itself. `notifyConnected()` publishes
/// `.connected` WITHOUT touching `connectedPeers`, which the fabric owns — an endpoint recording
/// itself as its own connected peer would quietly corrupt every reach test in this file.
extension FakePeerTransport: MeshPeerChannel {

    var peer: PeerHandle { handle }

    func notifyConnected() {
        stateSubject.send(.connected(handle))
    }

    func notifyDisconnected(reason: String) {
        stateSubject.send(.disconnected(reason: reason))
    }
}
