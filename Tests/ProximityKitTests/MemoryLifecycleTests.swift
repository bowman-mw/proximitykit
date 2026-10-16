// MemoryLifecycleTests.swift
// ProximityKitTests
//
// Regression suite for the 2026-08-17 memory-leak review (Docs/Memory-Leak-Review-2026-08-17.md).
// Every test here pins one retention edge that review found broken — or one lifecycle guarantee
// it found merely asserted in a comment — so it cannot silently regress:
//
//  - ObservationLoop must not PIN its owner across the suspension (the "loop ends on owner
//    dealloc" header was void: a `guard let owner` above the await held the owner, and every slot,
//    coordinator and transport it owns, until a change that could no longer come).
//  - The three proximity managers must deallocate when released, with or without `stop()`, and so
//    must the pair session the recipe-share manager drives, which holds its radio and its tasks.
//  - MeshNetworkManager must free the transport link (the MC link then, the QUIC tunnel now) of every slot it evicts (a zombie link ate one of
//    MC's 8 peer slots and made re-forming a slot with that peer impossible for the search).
//  - PresenceManager must release a discovered peer whose match a re-evaluation dropped, and must
//    run the coordinator's own teardown (ranging + Live Activity anchor) when the MC channel drops.
//  - ProximityRecipeShareManager must run that teardown on every record-drop path.
//  - Photo-wall preferences must shrink with the photo cache (install-lifetime sidecar).
//  - The synced Core Data store must prune un-consumed persistent history when it is loaded
//    without CloudKit mirroring.
//
// No test starts a radio (the unit-test invariant for proximity); every wait uses the deadline +
// minimum-poll-floor helper so a starved main actor cannot time it out spuriously.
//
// A partial copy (ProximityKit plan step A1, the split's first batch of copied suites): of the
// Fernlet repository's FernletTests file of the same name, this holds only
// `ObservationLoopLifecycleTests` and, since ProximityKit plan step A1's second batch of copied suites
// (those that reach the keychain and open no store), `MeshEvictionReleasesTransportLinkTests`, with
// their names and tests unchanged, and the two helpers the second reads (`makePeer` and
// `makeThrowawayCoordinator`); its other suites stay there, so what this header says of them is not
// held here.

@testable import ProximityKit
import Foundation
import Observation
import Testing

// MARK: - Fixtures

/// A tracked object the observation loop reads. Outlives the loop owner in the pin test so the
/// registrar entry it holds cannot be what releases the owner.
@MainActor
@Observable
private final class TrackedCounter {
    var value = 0
}

/// A minimal owner for ``ObservationLoop``: holds the tracked object and counts change callbacks.
@MainActor
private final class LoopOwner {
    let counter: TrackedCounter
    private(set) var changes = 0
    init(counter: TrackedCounter) { self.counter = counter }
    func noteChange() { changes += 1 }
}

/// Gives up only once the deadline has passed AND `minimumPolls` observations have been made
/// (wall-clock alone expires while a `@MainActor` suite is starved in a loaded full-suite run).
@MainActor
private func waitUntil(
    timeout: Duration = .seconds(2),
    minimumPolls: Int = 400,
    condition: @escaping @MainActor () -> Bool
) async {
    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: timeout)
    var polls = 0
    while !condition() {
        polls += 1
        if polls >= minimumPolls, clock.now >= deadline { return }
        try? await Task.sleep(for: .milliseconds(5))
    }
}

@MainActor
private func makePeer(name: String = "peer-\(UUID().uuidString.prefix(8))") -> PeerHandle {
    PeerHandle(
        id: UUID(),
        displayHint: name,
        discoveryInfo: nil,
        advertisedFingerprint: nil
    )
}

/// A never-begun coordinator over mock transports (mirrors MeshNetworkManagerTests). The ranging
/// mock is created inside — a `@MainActor` type can never be a default-argument value.
@MainActor
private func makeThrowawayCoordinator() -> ProximityCoordinator {
    let identity = IdentityService(keychainService: "test.memory.lifecycle.\(UUID().uuidString)")
    return ProximityCoordinator(
        identity: identity,
        transport: MockMultipeerTransport(),
        ranging: MockRangingProvider(),
        inspector: nil,
        replayCache: ReplayCache(),
        foregroundAnchor: nil,
        displayName: "Local",
        timeoutSeconds: 0
    )
}

// MARK: - ObservationLoop

/// The shared coordinator-state observation loop: it must react to changes, end promptly on
/// cancel, and — the reviewed defect — never keep its owner alive across the suspension.
@MainActor
@Suite(.serialized)
struct ObservationLoopLifecycleTests {

    /// Sanity: the refactored loop still fires `onChange` after a tracked mutation and re-arms.
    @Test func loopReactsToTrackedChangesAndReArms() async {
        let counter = TrackedCounter()
        let owner = LoopOwner(counter: counter)
        let task = ObservationLoop.start(
            on: owner,
            tracking: { _ = $0.counter.value },
            onChange: { $0.noteChange() }
        )
        try? await Task.sleep(for: .milliseconds(20))
        counter.value += 1
        await waitUntil { owner.changes == 1 }
        #expect(owner.changes == 1)
        counter.value += 1
        await waitUntil { owner.changes == 2 }
        #expect(owner.changes == 2, "the loop must re-arm after each change")
        task.cancel()
        _ = await task.value
    }

    /// Cancelling the returned task ends the loop even while it is suspended on a change that
    /// never comes (the AsyncStream continuation is finished from the cancellation handler).
    @Test func cancelEndsASuspendedLoop() async {
        let counter = TrackedCounter()
        let owner = LoopOwner(counter: counter)
        let task = ObservationLoop.start(
            on: owner,
            tracking: { _ = $0.counter.value },
            onChange: { $0.noteChange() }
        )
        try? await Task.sleep(for: .milliseconds(20))
        task.cancel()
        var finished = false
        let watcher = Task { @MainActor in
            _ = await task.value
            finished = true
        }
        await waitUntil { finished }
        #expect(finished, "a cancelled loop must return, not stay parked on its stream")
        watcher.cancel()
    }

    /// THE reviewed defect. The owner's only remaining reference is the loop's; once the caller
    /// drops it, the owner must deallocate even though the tracked object never changes again.
    /// Before the fix a `guard let owner` above the await pinned it for the whole suspension —
    /// which, with no other reference left to mutate anything, was forever.
    @Test func suspendedLoopDoesNotPinItsOwner() async {
        let counter = TrackedCounter()
        weak var weakOwner: LoopOwner?
        var task: Task<Void, Never>?
        do {
            let owner = LoopOwner(counter: counter)
            weakOwner = owner
            task = ObservationLoop.start(
                on: owner,
                tracking: { _ = $0.counter.value },
                onChange: { $0.noteChange() }
            )
            // Let the loop arm its tracking and suspend before the owner goes out of scope.
            try? await Task.sleep(for: .milliseconds(30))
        }
        await waitUntil { weakOwner == nil }
        #expect(weakOwner == nil, "the loop must hold its owner weakly across the suspension")
        task?.cancel()
        if let task { _ = await task.value }
    }
}

// MARK: - MeshNetworkManager: evicted slots free their transport link (the MC link when this was written)

@MainActor
@Suite(.serialized)
struct MeshEvictionReleasesTransportLinkTests {
    let store = PackageTestHost()

    /// `removeSlot` (timeouts, stale sweep, remote goodbye, session close, transport loss) must
    /// request the per-peer kick — before the fix nothing in the eviction chain touched the shared
    /// radio, so the link lingered until the whole search stopped.
    ///
    /// Asserted on the INJECTED radio rather than through a hook inside the MC session, which is
    /// what the P2 item-8 seam bought: the claim is now "the eviction chain reached the transport",
    /// read off the transport, and it holds whichever conformer is behind it.
    @Test func evictingASlotRequestsTheTransportKick() {
        let transport = FakeMeshTransportSession()
        let manager = MeshNetworkManager(store: store, transport: transport)
        let peer = makePeer()
        manager.addSlotForTesting(coordinator: makeThrowawayCoordinator(), peer: peer, fingerprint: nil)

        manager.evictSlotForTesting(peerID: peer.id)

        #expect(transport.disconnectedPeers.map(\.id) == [peer.id],
                "the evicted peer's link must be released, not left as a zombie")
    }
}
