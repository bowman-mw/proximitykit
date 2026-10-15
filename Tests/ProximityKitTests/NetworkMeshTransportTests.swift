import Combine
import CryptoKit
import Foundation
import Security
import Testing
@testable import ProximityKit

// MARK: - NetworkMeshTransportTests

// The tier-1 battery for P2's QUIC transport, written against the parts that were deliberately
// factored OUT of the session actor so they could be enumerated here: the link table, the dial
// preference, the heartbeat schedule, the TXT vocabulary, the ephemeral TLS identity, and the
// control-stream framing.
//
// The session actor itself — listener, browser, connections — needs two radios and is covered by
// the runbook's device lanes, not by anything in this file. What IS covered here is every decision
// that actor makes, which is the whole reason those decisions do not live inside it.
//
// **No test in this file sleeps.** Time is a `VirtualClock` a test advances by hand, matching the
// rule the deterministic fabric in Mocks/FakePeerTransport.swift was built around: a scenario either
// completes deterministically or fails visibly, never intermittently under CI load.

/// The link table's five phases, its caps, and its budgets — enumerated rather than sampled.
@MainActor
@Suite(.serialized)
struct MeshLinkTableTests {

    static let alpha = MeshLinkKey("alpha")
    static let beta = MeshLinkKey("beta")

    /// Drives a fresh table into `phase` for ``alpha``, returning both.
    ///
    /// Every phase test starts here so a phase is always reached the way production reaches it —
    /// a table whose fields were poked into place would prove nothing about the transitions.
    static func table(in phase: MeshLinkPhase, clock: VirtualClock) -> MeshLinkTable {
        var table = MeshLinkTable()
        switch phase {
        case .idle:
            return table
        case .dialing:
            _ = table.admitDial(to: alpha, now: clock.now)
        case .backingOff:
            _ = table.admitDial(to: alpha, now: clock.now)
            _ = table.noteDialFailed(alpha, now: clock.now)
        case .connected:
            table.noteReady(alpha, now: clock.now)
        case .exhausted:
            for _ in 0..<MeshLinkTable.maxDialAttempts {
                _ = table.admitDial(to: alpha, now: clock.now)
                _ = table.noteDialFailed(alpha, now: clock.now)
                clock.advance(by: MeshLinkTable.dialRetryDelay)
            }
        }
        return table
    }

    // MARK: Phases

    /// Every phase is reachable exactly as the fixture claims. Without this the matrices below
    /// could all be passing against a table that never left `.idle`.
    @Test func everyPhaseIsReachable() {
        let clock = VirtualClock()
        let phases: [MeshLinkPhase] = [.idle, .dialing, .backingOff, .connected, .exhausted]
        for phase in phases {
            let table = Self.table(in: phase, clock: clock)
            #expect(table.phase(of: Self.alpha) == phase, "fixture did not reach \(phase)")
        }
    }

    /// Only `.dialing` and `.connected` hold a slot. A room full of unreachable advertisements must
    /// not consume the roster cap — that is the difference between a mesh that fills up with peers
    /// it cannot reach and one that keeps trying the ones it can.
    @Test func onlyDialingAndConnectedLinksHoldASlot() {
        let clock = VirtualClock()
        let expected: [MeshLinkPhase: Int] = [
            .idle: 0, .dialing: 1, .backingOff: 0, .connected: 1, .exhausted: 0
        ]
        for (phase, slots) in expected {
            let table = Self.table(in: phase, clock: clock)
            #expect(table.occupiedSlotCount == slots, "\(phase) should hold \(slots) slot(s)")
        }
    }

    // MARK: admitDial

    /// The outbound admission for every phase, exhaustively.
    @Test func dialAdmissionCoversEveryPhase() {
        let clock = VirtualClock()
        let expected: [MeshLinkPhase: MeshLinkAdmission] = [
            .idle: .admit,
            .dialing: .refusedDuplicateTunnel(.dialing),
            .backingOff: .refusedDuplicateTunnel(.backingOff),
            .connected: .refusedDuplicateTunnel(.connected),
            .exhausted: .refusedRetryBudgetSpent
        ]
        for (phase, admission) in expected {
            var table = Self.table(in: phase, clock: clock)
            #expect(table.admitDial(to: Self.alpha, now: clock.now) == admission, "phase \(phase)")
        }
    }

    /// A backing-off link becomes dialable the instant its delay elapses, and not a moment before.
    /// The boundary is the interesting part: a rule written with `<` instead of `<=` would leave a
    /// link waiting for the next poll tick, every retry, forever.
    @Test func aBackingOffLinkIsDialableExactlyWhenItsDelayElapses() {
        let clock = VirtualClock()
        var table = Self.table(in: .backingOff, clock: clock)

        clock.advance(by: .seconds(MeshLinkTable.dialRetryDelaySeconds - 0.001))
        #expect(table.admitDial(to: Self.alpha, now: clock.now) == .refusedDuplicateTunnel(.backingOff))
        #expect(table.dueRetries(now: clock.now).isEmpty)

        clock.advance(by: .milliseconds(1))
        #expect(table.dueRetries(now: clock.now) == [Self.alpha])
        #expect(table.admitDial(to: Self.alpha, now: clock.now) == .admit)
    }

    /// Exactly ``MeshLinkTable/maxDialAttempts`` attempts, then the budget is spent — and the
    /// outcome names which attempt is next, so a log line cannot drift from the real count.
    @Test func theDialBudgetIsExactlyThreeAttempts() {
        let clock = VirtualClock()
        var table = MeshLinkTable()
        var outcomes: [MeshDialOutcome] = []
        for _ in 0..<MeshLinkTable.maxDialAttempts {
            #expect(table.admitDial(to: Self.alpha, now: clock.now) == .admit)
            outcomes.append(table.noteDialFailed(Self.alpha, now: clock.now))
            clock.advance(by: MeshLinkTable.dialRetryDelay)
        }
        #expect(outcomes == [
            .retry(attempt: 2, delay: MeshLinkTable.dialRetryDelay),
            .retry(attempt: 3, delay: MeshLinkTable.dialRetryDelay),
            .giveUp(attempts: 3)
        ])
        #expect(table.phase(of: Self.alpha) == .exhausted)
        #expect(table.dueRetries(now: clock.now).isEmpty, "an exhausted link must not be re-armed")
    }

    /// A duplicate failure callback for a link the table has already given up on — or has never
    /// booked — must not start a new campaign. A retry loop re-armable by a repeated callback is an
    /// unbounded loop with extra steps.
    @Test func aFailureForAnUnbookedLinkDoesNotOpenAFreshBudget() {
        let clock = VirtualClock()
        var table = MeshLinkTable()
        #expect(table.noteDialFailed(Self.alpha, now: clock.now) == .giveUp(attempts: 3))
        #expect(table.phase(of: Self.alpha) == .exhausted)
        #expect(table.noteDialFailed(Self.alpha, now: clock.now) == .giveUp(attempts: 3))
    }

    /// Connecting resets the budget, and a later disconnect leaves a full one. The budget is for
    /// *reaching* a peer, not a lifetime quota — charging disconnects to it is how a peer that
    /// reconnects a few times becomes permanently undialable.
    @Test func connectingResetsTheBudgetAndDisconnectingDoesNotSpendIt() {
        let clock = VirtualClock()
        var table = MeshLinkTable()
        _ = table.admitDial(to: Self.alpha, now: clock.now)
        _ = table.noteDialFailed(Self.alpha, now: clock.now)
        #expect(table.dialAttempts(for: Self.alpha) == 1)

        table.noteReady(Self.alpha, now: clock.now)
        #expect(table.dialAttempts(for: Self.alpha) == 0)

        table.noteClosed(Self.alpha)
        #expect(table.phase(of: Self.alpha) == .idle)
        #expect(table.dialAttempts(for: Self.alpha) == 0)
        #expect(table.admitDial(to: Self.alpha, now: clock.now) == .admit)
    }

    // MARK: Capacity

    /// The eighth link is admitted and the ninth is not — and the refusal says `atCapacity`, not
    /// `duplicate`, because those two send a reader to opposite parts of the code.
    @Test func theNinthSimultaneousLinkIsRefusedAtCapacity() {
        let clock = VirtualClock()
        var table = MeshLinkTable()
        for index in 0..<MeshLinkTable.maxConcurrentLinks {
            #expect(table.admitDial(to: MeshLinkKey("peer-\(index)"), now: clock.now) == .admit)
        }
        #expect(table.occupiedSlotCount == MeshLinkTable.maxConcurrentLinks)
        #expect(table.admitDial(to: Self.alpha, now: clock.now) == .refusedAtCapacity)
        #expect(
            table.admitInbound(from: Self.alpha, preference: .unranked, now: clock.now)
                == .refusedAtCapacity
        )
    }

    /// Links that are backing off or exhausted free their slots, so a full table of unreachable
    /// peers still admits a reachable one.
    @Test func unreachableLinksDoNotHoldTheRosterCap() {
        let clock = VirtualClock()
        var table = MeshLinkTable()
        for index in 0..<MeshLinkTable.maxConcurrentLinks {
            let key = MeshLinkKey("peer-\(index)")
            _ = table.admitDial(to: key, now: clock.now)
            _ = table.noteDialFailed(key, now: clock.now)
        }
        #expect(table.occupiedSlotCount == 0)
        #expect(table.admitDial(to: Self.alpha, now: clock.now) == .admit)
    }

    /// An inbound tunnel accepted while this side is mid-dial reuses the slot the dial already
    /// holds, rather than needing a ninth.
    @Test func anAdmittedInboundTunnelReusesTheDialingSlot() {
        let clock = VirtualClock()
        var table = MeshLinkTable()
        for index in 0..<(MeshLinkTable.maxConcurrentLinks - 1) {
            _ = table.admitDial(to: MeshLinkKey("peer-\(index)"), now: clock.now)
        }
        _ = table.admitDial(to: Self.alpha, now: clock.now)
        #expect(table.occupiedSlotCount == MeshLinkTable.maxConcurrentLinks)
        #expect(table.admitInbound(from: Self.alpha, preference: .peerDials, now: clock.now) == .admit)
        #expect(table.occupiedSlotCount == MeshLinkTable.maxConcurrentLinks)
        #expect(table.connectedCount == 1)
    }

    // MARK: admitInbound — the full 5 × 3 matrix

    /// Every phase against every preference. Fifteen cells, all of them stated.
    ///
    /// The one that matters is `.dialing`: it is the only row where the preference changes the
    /// answer, and it is the duplicate-tunnel suppression of plan §7.1. Everything else admits
    /// unless a tunnel already exists.
    @Test func inboundAdmissionCoversEveryPhaseAndPreference() {
        let clock = VirtualClock()
        let preferences: [MeshDialPreference] = [.localDials, .peerDials, .unranked]
        let expected: [MeshLinkPhase: [MeshDialPreference: MeshLinkAdmission]] = [
            .idle: [.localDials: .admit, .peerDials: .admit, .unranked: .admit],
            .dialing: [
                .localDials: .refusedDuplicateTunnel(.dialing),
                .peerDials: .admit,
                .unranked: .admit
            ],
            .backingOff: [.localDials: .admit, .peerDials: .admit, .unranked: .admit],
            .connected: [
                .localDials: .refusedDuplicateTunnel(.connected),
                .peerDials: .refusedDuplicateTunnel(.connected),
                .unranked: .refusedDuplicateTunnel(.connected)
            ],
            .exhausted: [.localDials: .admit, .peerDials: .admit, .unranked: .admit]
        ]
        for (phase, row) in expected {
            for preference in preferences {
                var table = Self.table(in: phase, clock: clock)
                let admission = table.admitInbound(
                    from: Self.alpha, preference: preference, now: clock.now
                )
                #expect(admission == row[preference], "phase \(phase) × preference \(preference)")
            }
        }
    }

    /// A spent dial budget refuses a *dial* and admits an *accept*. The budget is about this side
    /// giving up on reaching a peer; a peer that reaches us has answered the question.
    @Test func aSpentBudgetStillAcceptsAnInboundTunnel() {
        let clock = VirtualClock()
        var table = Self.table(in: .exhausted, clock: clock)
        #expect(table.admitDial(to: Self.alpha, now: clock.now) == .refusedRetryBudgetSpent)
        #expect(table.admitInbound(from: Self.alpha, preference: .unranked, now: clock.now) == .admit)
        #expect(table.phase(of: Self.alpha) == .connected)
        #expect(table.dialAttempts(for: Self.alpha) == 0)
    }

    /// **The anti-deadlock property.** For every pair of session ids a real pair of devices could
    /// hold — including the pre-TXT window where one or both sides know nothing — at least one side
    /// of a mutually-dialing pair keeps a tunnel.
    ///
    /// Refusing an inbound tunnel closes the peer's outbound one, so "both refuse" ends with zero
    /// tunnels and a wait for the retry timer: the exact failure the MC tie-break produced once, and
    /// the reason this table consults the ranking at all. Two tunnels is wasteful and self-corrects;
    /// zero does not.
    @Test func aMutuallyDialingPairNeverEndsWithZeroTunnels() {
        let clock = VirtualClock()
        let ids: [String?] = ["aaaa", "zzzz", nil, ""]
        for localID in ids {
            for peerID in ids {
                let local = localID ?? ""
                let remote = peerID ?? ""
                var here = Self.table(in: .dialing, clock: clock)
                var there = Self.table(in: .dialing, clock: clock)
                let hereAdmits = here.admitInbound(
                    from: Self.alpha, localSessionID: local, peerSessionID: peerID, now: clock.now
                ) == .admit
                let thereAdmits = there.admitInbound(
                    from: Self.alpha, localSessionID: remote, peerSessionID: localID, now: clock.now
                ) == .admit
                #expect(
                    hereAdmits || thereAdmits,
                    "both sides refused for local=\(local) peer=\(remote) — that is the deadlock"
                )
            }
        }
    }

    // MARK: Endpoint cache

    /// The cache is bounded oldest-first, and a re-sighting refreshes in place without reordering —
    /// so a long-lived endpoint cannot pin a full cache against newcomers forever.
    @Test func theEndpointCacheIsBoundedOldestFirst() {
        let clock = VirtualClock()
        var table = MeshLinkTable()
        for index in 0..<(MeshLinkTable.maxCachedEndpoints + 4) {
            table.remember(Self.record(named: "peer-\(index)", at: clock.now))
        }
        #expect(table.cachedEndpointCount == MeshLinkTable.maxCachedEndpoints)
        #expect(table.cachedEndpoint(MeshLinkKey("peer-0")) == nil, "oldest should have been evicted")
        #expect(table.cachedEndpoint(MeshLinkKey("peer-4")) != nil)

        let firstSurvivor = table.cachedEndpoints.first?.key
        table.remember(Self.record(named: "peer-4", at: clock.now.addingTimeInterval(60)))
        #expect(table.cachedEndpointCount == MeshLinkTable.maxCachedEndpoints, "a refresh must not grow the cache")
        #expect(table.cachedEndpoints.first?.key == firstSurvivor, "a refresh must not reorder eviction")
    }

    /// The cache is what makes a re-dial possible after Bonjour goes quiet: the record survives the
    /// endpoint leaving the browse results as long as something still holds it, and `forget` is the
    /// one call that drops it.
    @Test func forgettingAnEndpointDropsItsLinkStateAndItsCacheEntry() {
        let clock = VirtualClock()
        var table = MeshLinkTable()
        table.remember(Self.record(named: "alpha", at: clock.now))
        _ = table.admitDial(to: Self.alpha, now: clock.now)
        #expect(table.cachedEndpoint(Self.alpha) != nil)

        table.forget(Self.alpha)
        #expect(table.cachedEndpoint(Self.alpha) == nil)
        #expect(table.phase(of: Self.alpha) == .idle)
        #expect(table.cachedEndpoints.isEmpty)
    }

    // MARK: Bounded link records (owner-calls item 4, 2026-09-22)

    /// **The finding's first path.** An inbound tunnel from a peer this side never browsed is keyed
    /// by a pending key the cache never holds and `forget` never reaches, so its closed record used
    /// to stay for the session's life. Forty such tunnels now leave NONE — and every answer the
    /// table gives about those keys is the one it gave before (idle, full budget, dialable).
    @Test func aClosedLinkToAnUncachedEndpointKeepsNoRecord() {
        let clock = VirtualClock()
        var table = MeshLinkTable()
        // R2: bounded by the stated count.
        for index in 0..<40 {
            let key = MeshLinkKey("inbound-\(index)")
            #expect(table.admitInbound(from: key, preference: .unranked, now: clock.now) == .admit)
            table.noteClosed(key)
        }
        #expect(table.linkRecordCount == 0, "forty closed inbound tunnels from never-browsed peers leave no record")
        let key = MeshLinkKey("inbound-7")
        #expect(table.phase(of: key) == .idle && table.dialAttempts(for: key) == 0,
                "and the answers are the defaults an idle record would have given")
        #expect(table.admitDial(to: key, now: clock.now) == .admit, "the endpoint is as dialable as before")

        table.remember(Self.record(named: "alpha", at: clock.now))
        table.noteReady(Self.alpha, now: clock.now)
        table.noteClosed(Self.alpha)
        #expect(table.linkRecordCount == 2, "a CACHED endpoint still keeps its idle record — the change is scoped (plus inbound-7's live dial)")
    }

    /// **The finding's second path**, the one the ledger named: the cache eviction reaped the
    /// counters but never the link map, so a crowded room grew it for the session's life. Ninety-six
    /// endpoints through a 32-entry cache, each connected and closed, now leave exactly the 32
    /// the cache still holds.
    @Test func aCrowdedRoomsLinkRecordsAreBoundedByTheCache() {
        let clock = VirtualClock()
        var table = MeshLinkTable()
        let seen = MeshLinkTable.maxCachedEndpoints * 3
        // R2: bounded by three cache-fulls.
        for index in 0..<seen {
            let key = MeshLinkKey("peer-\(index)")
            table.remember(Self.record(named: "peer-\(index)", at: clock.now))
            table.noteReady(key, now: clock.now)
            table.noteClosed(key)
        }
        #expect(table.cachedEndpointCount == MeshLinkTable.maxCachedEndpoints, "the cache is at its bound")
        #expect(table.linkRecordCount == MeshLinkTable.maxCachedEndpoints,
                "and so are the link records — 32, not 96: each idle record left with its cache entry")
        #expect(table.phase(of: MeshLinkKey("peer-0")) == .idle, "an evicted endpoint reads idle, as it always did")
    }

    /// The eviction is lossless by construction: only an IDLE record — identical to having none —
    /// leaves with its cache entry. An exhausted endpoint keeps the state that stops this session
    /// hammering a peer that never answered, until the browser loses it.
    @Test func onlyAnIdleRecordLeavesWithItsCacheEntry() {
        let clock = VirtualClock()
        var table = MeshLinkTable()
        let idle = MeshLinkKey("peer-0")
        let spent = MeshLinkKey("peer-1")
        table.remember(Self.record(named: "peer-0", at: clock.now))
        table.remember(Self.record(named: "peer-1", at: clock.now))
        table.noteReady(idle, now: clock.now)
        table.noteClosed(idle)
        // R2: bounded by the retry budget.
        for _ in 0..<MeshLinkTable.maxDialAttempts {
            _ = table.admitDial(to: spent, now: clock.now)
            _ = table.noteDialFailed(spent, now: clock.now)
            clock.advance(by: MeshLinkTable.dialRetryDelay)
        }
        #expect(table.phase(of: spent) == .exhausted, "the fixture really spent peer-1's budget")
        #expect(table.linkRecordCount == 2)
        // R2: bounded by one cache-full.
        for index in 2..<(MeshLinkTable.maxCachedEndpoints + 2) {
            table.remember(Self.record(named: "peer-\(index)", at: clock.now))
        }
        #expect(table.cachedEndpoint(idle) == nil && table.cachedEndpoint(spent) == nil, "both were evicted from the cache")
        #expect(table.linkRecordCount == 1, "the idle record left with its entry")
        #expect(table.phase(of: spent) == .exhausted, "and the spent one kept its state — no fresh campaign")
    }

    /// Teardown leaves nothing — the privacy constraint, asserted directly rather than inferred.
    @Test func removeAllLeavesNothingBehind() {
        let clock = VirtualClock()
        var table = MeshLinkTable()
        table.remember(Self.record(named: "alpha", at: clock.now))
        table.remember(Self.record(named: "beta", at: clock.now))
        _ = table.admitDial(to: Self.alpha, now: clock.now)
        table.noteReady(Self.beta, now: clock.now)

        table.removeAll()
        #expect(table.cachedEndpointCount == 0)
        #expect(table.occupiedSlotCount == 0)
        #expect(table.connectedCount == 0)
        #expect(table.phase(of: Self.alpha) == .idle)
        #expect(table.dueRetries(now: clock.now).isEmpty)
    }

    /// Due retries come back in a deterministic order, so a failure names one combination rather
    /// than a dictionary's iteration order.
    @Test func dueRetriesAreSortedAndOnlyIncludeElapsedBackoffs() {
        let clock = VirtualClock()
        var table = MeshLinkTable()
        for name in ["charlie", "alpha", "beta"] {
            let key = MeshLinkKey(name)
            _ = table.admitDial(to: key, now: clock.now)
            _ = table.noteDialFailed(key, now: clock.now)
        }
        let late = MeshLinkKey("delta")
        clock.advance(by: MeshLinkTable.dialRetryDelay)
        _ = table.admitDial(to: late, now: clock.now)
        _ = table.noteDialFailed(late, now: clock.now)

        #expect(table.dueRetries(now: clock.now) == [MeshLinkKey("alpha"), MeshLinkKey("beta"), MeshLinkKey("charlie")])
    }

    // MARK: - Re-propose budget (0b review finding 2)

    /// The budget the re-propose sweep spends, and the loop it exists to stop.
    ///
    /// The sweep re-offers an `idle`, untunnelled browsed peer to the owner every five seconds, and
    /// the owner has reasons to refuse a seat this radio cannot see — a locally-kicked peer, a
    /// removed member, a capacity race. Each refusal ends the tunnel, which returns the link to
    /// `idle` **with a full dial budget**, so without a second, separately-counted budget that is an
    /// unbounded connect/refuse/re-dial cycle.
    @Test func theReproposeBudgetIsSpentAndNeverRefilled() {
        var table = MeshLinkTable()
        let clock = VirtualClock()

        for attempt in 1...MeshLinkTable.maxReproposalsPerEndpoint {
            let admitted = table.admitRepropose(Self.alpha)
            #expect(admitted, "re-proposal \(attempt) is inside the budget")
            #expect(table.reproposalCount(of: Self.alpha) == attempt)
        }
        let overBudget = table.admitRepropose(Self.alpha)
        #expect(!overBudget, "the budget must refuse once it is spent")

        // The loop this closes, spelled out: a connect and a disconnect refill the DIAL budget and
        // must not refill this one.
        table.noteReady(Self.alpha, now: clock.now)
        table.noteClosed(Self.alpha)
        #expect(table.dialAttempts(for: Self.alpha) == 0, "test premise: connecting refills the dial budget")
        let afterReconnect = table.admitRepropose(Self.alpha)
        #expect(!afterReconnect, "a reconnect must NOT refill the re-propose budget")
        #expect(table.reproposalCount(of: Self.alpha) == MeshLinkTable.maxReproposalsPerEndpoint)
    }

    /// A pre-commit TIMEOUT gives its booking back; an owner refusal does not (D-4.3 Option 1's
    /// "two bounds to name").
    ///
    /// The budget exists for *connect → the owner refuses the seat → disconnect → idle → re-offer*,
    /// and provisional admission makes the other shape common: a stranger is seated and then evicted
    /// by the five-minute proximity gate (`ProximityCoordinator.transitionToProximityGate`) with nobody having
    /// refused anything. Six of those used to strand a genuine friend for the rest of the session.
    ///
    /// It is NOT the refill the cap's own doc rules out, and what makes that true is that the refund
    /// consumes the **booking** rather than the counter. The interleave below is therefore on ONE
    /// endpoint, which is the only place the two rules can actually meet: a refusal ends the tunnel
    /// (`noteClosed`), which consumes that offer's booking, so the timeout reported for the same
    /// endpoint afterwards has nothing to hand back and the sixth refusal still stops the sweep.
    @Test func aTimeoutRefundsItsReproposalAndARefusalDoesNot() {
        var table = MeshLinkTable()
        let clock = VirtualClock()

        // One offer, taken up, ending in a pre-commit timeout: the booking comes back.
        // Every mutating call is hoisted out of `#expect`: the macro captures its expression in a
        // closure, where `table` is immutable.
        let firstOffer = table.admitRepropose(Self.alpha)
        #expect(firstOffer)
        #expect(table.reproposalCount(of: Self.alpha) == 1)
        let firstDial = table.admitDial(to: Self.alpha, now: clock.now)
        #expect(firstDial == .admit)
        table.noteReady(Self.alpha, now: clock.now)
        table.refundRepropose(Self.alpha)
        #expect(table.reproposalCount(of: Self.alpha) == 0, "a timeout eviction spends nothing")

        // The SAME timeout reported twice refunds once: what the refund consumes is the booking.
        table.refundRepropose(Self.alpha)
        #expect(table.reproposalCount(of: Self.alpha) == 0, "a second report of one timeout is free")
        #expect(table.reproposalRefundCount(of: Self.alpha) == 1, "and only one refund was spent")

        // Refunds cannot mint offers: an INBOUND tunnel books nothing, so a peer that dialed this
        // device and timed out has nothing to give back — not even on an endpoint an earlier offer
        // paid for and an owner refusal spent.
        let betaOffer = table.admitRepropose(Self.beta)
        #expect(betaOffer)
        table.noteClosed(Self.beta)
        let betaInbound = table.admitInbound(from: Self.beta, preference: .peerDials, now: clock.now)
        #expect(betaInbound == .admit)
        table.refundRepropose(Self.beta)
        #expect(table.reproposalCount(of: Self.beta) == 1,
                "an inbound tunnel books nothing, so its timeout refunds nothing")
        #expect(table.reproposalRefundCount(of: Self.beta) == 0)

        // Six REFUSALS still end the sweep on ONE endpoint, with timeouts interleaved on that very
        // endpoint — the case the two-endpoint version of this could never reach.
        var interleaved = MeshLinkTable()
        for attempt in 1...MeshLinkTable.maxReproposalsPerEndpoint {
            let offer = interleaved.admitRepropose(Self.alpha)
            #expect(offer, "refusal offer \(attempt) is inside the budget")
            let dial = interleaved.admitDial(to: Self.alpha, now: clock.now)
            #expect(dial == .admit)
            interleaved.noteReady(Self.alpha, now: clock.now)
            interleaved.noteClosed(Self.alpha)   // the owner refused the seat; the tunnel ended
            interleaved.refundRepropose(Self.alpha)  // a timeout reported for the same endpoint
        }
        let seventh = interleaved.admitRepropose(Self.alpha)
        #expect(!seventh,
                "six refusals spend the budget, however many timeouts are interleaved on them")
        #expect(interleaved.reproposalCount(of: Self.alpha) == MeshLinkTable.maxReproposalsPerEndpoint)
        #expect(interleaved.reproposalRefundCount(of: Self.alpha) == 0,
                "and not one of those timeouts found a booking to refund")
    }

    /// The refund is bounded, so an endpoint whose EVERY tunnel times out cannot be re-offered for
    /// the life of the session.
    ///
    /// The shape the cap closes: a provisional stranger is seated, nobody dwells, the five-minute
    /// proximity gate ends the slot as `.ended(reason: .timeout)`, the eviction refunds, and the
    /// 5 s sweep offers the same endpoint again — for ever, with the six-offer cap never reached.
    /// Five minutes rate-limits that to about one offer per five minutes per endpoint; it does not
    /// bound it, so the refunds themselves are capped instead, never reset, in
    /// ``MeshLinkTable/maxReproposalsPerEndpoint``'s own spirit.
    @Test func timeoutRefundsAreCappedSoAnAllTimeoutEndpointStops() {
        var table = MeshLinkTable()
        let clock = VirtualClock()
        let bound = MeshLinkTable.maxReproposalsPerEndpoint + MeshLinkTable.maxTimeoutRefundsPerEndpoint

        var offers = 0
        // R2: a fixed bound, comfortably past the total this endpoint can ever be offered.
        for _ in 0..<(bound + 3) {
            guard table.admitRepropose(Self.alpha) else { continue }
            offers += 1
            let dial = table.admitDial(to: Self.alpha, now: clock.now)
            #expect(dial == .admit)
            table.noteReady(Self.alpha, now: clock.now)
            table.refundRepropose(Self.alpha)   // every one of this endpoint's tunnels times out
            table.noteClosed(Self.alpha)
        }

        #expect(offers == bound, """
            an all-timeout endpoint gets its six offers plus two refunded ones and then stops; \
            an unlimited refund would have taken every one of the \(bound + 3) rounds
            """)
        #expect(table.reproposalRefundCount(of: Self.alpha) == MeshLinkTable.maxTimeoutRefundsPerEndpoint)
        #expect(table.reproposalCount(of: Self.alpha) == MeshLinkTable.maxReproposalsPerEndpoint,
                "and the offer budget ends the session fully spent")
    }

    /// Budgets are per endpoint, and die with the endpoint — so the map cannot grow without bound.
    @Test func theReproposeBudgetIsPerEndpointAndDiesWithIt() {
        var table = MeshLinkTable()
        let booked = table.admitRepropose(Self.alpha)
        #expect(booked)
        #expect(table.reproposalCount(of: Self.beta) == 0, "one endpoint's budget is not another's")

        table.forget(Self.alpha)
        #expect(table.reproposalCount(of: Self.alpha) == 0, "forgetting an endpoint drops its budget")

        _ = table.admitRepropose(Self.beta)
        table.removeAll()
        #expect(table.reproposalCount(of: Self.beta) == 0, "teardown drops every budget")
    }

    static func record(named name: String, at now: Date) -> MeshEndpointRecord {
        MeshEndpointRecord(
            key: MeshLinkKey(name),
            instanceName: "fernlet-mesh-\(name)",
            advertisement: ["sid": name],
            lastSeenAt: now
        )
    }
}

// MARK: - MeshDialPreferenceTests

/// The ranking that decides which side of a mutually-dialing pair keeps its tunnel, and its
/// agreement with the production tie-break the mesh has already been deadlocked by once.
@Suite(.serialized)
struct MeshDialPreferenceTests {

    static let sessionIDs = ["aaaa", "aaab", "m", "zzzz", "0000", "ffffffff"]

    /// Antisymmetric wherever it ranks. This is the property that makes "both sides refuse"
    /// unreachable from real inputs, so it is asserted over every ordered pair rather than sampled.
    @Test func rankingIsAntisymmetricForDistinctSessionIDs() {
        for local in Self.sessionIDs {
            for peer in Self.sessionIDs where peer != local {
                let here = MeshDialPreference.rank(localSessionID: local, peerSessionID: peer)
                let there = MeshDialPreference.rank(localSessionID: peer, peerSessionID: local)
                #expect(here != .unranked, "\(local) vs \(peer) should rank")
                #expect(
                    (here == .localDials && there == .peerDials) || (here == .peerDials && there == .localDials),
                    "\(local)/\(peer) ranked \(here)/\(there) — not antisymmetric"
                )
            }
        }
    }

    /// The three cases where no ranking exists: absent, empty, and equal. Each is `.unranked`,
    /// which admits — the safe direction.
    @Test func absentEmptyAndEqualSessionIDsAreUnranked() {
        #expect(MeshDialPreference.rank(localSessionID: "aaaa", peerSessionID: nil) == .unranked)
        #expect(MeshDialPreference.rank(localSessionID: "aaaa", peerSessionID: "") == .unranked)
        #expect(MeshDialPreference.rank(localSessionID: "", peerSessionID: "aaaa") == .unranked)
        #expect(MeshDialPreference.rank(localSessionID: "aaaa", peerSessionID: "aaaa") == .unranked)
    }

    /// Where both policies rank, they agree: the transport's `.localDials` is exactly the manager's
    /// "we dial". A divergence here would put the two halves of one decision on opposite sides.
    ///
    /// The two deliberate divergences are asserted too, so they stay deliberate: an absent peer
    /// `sid` makes the manager invite (a redundant invite beats a deadlock) while the transport
    /// declines to rank (a refusal on both sides IS the deadlock), and an equal `sid` is this
    /// process's own echo — the manager refuses to dial itself, the transport has nothing to rank.
    @Test func rankingAgreesWithTheProductionInviteTieBreak() {
        for local in Self.sessionIDs {
            for peer in Self.sessionIDs where peer != local {
                let dials = MeshNetworkManager.shouldInitiateInvite(
                    localSessionID: local, peerSessionID: peer
                )
                let preference = MeshDialPreference.rank(localSessionID: local, peerSessionID: peer)
                #expect(
                    dials == (preference == .localDials),
                    "manager says dial=\(dials) but transport ranked \(preference) for \(local)/\(peer)"
                )
            }
        }
        #expect(MeshNetworkManager.shouldInitiateInvite(localSessionID: "aaaa", peerSessionID: nil))
        #expect(MeshDialPreference.rank(localSessionID: "aaaa", peerSessionID: nil) == .unranked)
        #expect(!MeshNetworkManager.shouldInitiateInvite(localSessionID: "aaaa", peerSessionID: "aaaa"))
        #expect(MeshDialPreference.rank(localSessionID: "aaaa", peerSessionID: "aaaa") == .unranked)
    }
}

// MARK: - MeshHeartbeatScheduleTests

/// The 30 s heartbeat's due times, on a clock the test owns.
@MainActor
@Suite(.serialized)
struct MeshHeartbeatScheduleTests {

    static let alpha = MeshLinkKey("alpha")

    /// Nothing is due before the interval, and the link is due exactly at it.
    @Test func aLinkIsDueExactlyOneIntervalAfterItStarts() {
        let clock = VirtualClock()
        var schedule = MeshHeartbeatSchedule()
        schedule.start(Self.alpha, now: clock.now)

        clock.advance(by: .seconds(MeshHeartbeatSchedule.intervalSeconds - 0.001))
        #expect(schedule.due(now: clock.now).isEmpty)

        clock.advance(by: .milliseconds(1))
        #expect(schedule.due(now: clock.now) == [Self.alpha])
    }

    /// A link stays due until it is beaten, then goes quiet for another interval. A schedule that
    /// re-armed on the *read* would beat a link whose send failed, forever.
    @Test func aLinkStaysDueUntilItIsBeaten() {
        let clock = VirtualClock()
        var schedule = MeshHeartbeatSchedule()
        schedule.start(Self.alpha, now: clock.now)
        clock.advance(by: MeshHeartbeatSchedule.interval)

        #expect(schedule.due(now: clock.now) == [Self.alpha])
        #expect(schedule.due(now: clock.now) == [Self.alpha], "reading must not re-arm")

        schedule.noteSent(Self.alpha, now: clock.now)
        #expect(schedule.due(now: clock.now).isEmpty)
        clock.advance(by: MeshHeartbeatSchedule.interval)
        #expect(schedule.due(now: clock.now) == [Self.alpha])
    }

    /// A poll that runs late fires each passed link exactly once — absolute due times, not a
    /// countdown that has to catch up.
    @Test func aLatePollFiresEachLinkOnce() {
        let clock = VirtualClock()
        var schedule = MeshHeartbeatSchedule()
        schedule.start(MeshLinkKey("alpha"), now: clock.now)
        schedule.start(MeshLinkKey("beta"), now: clock.now)

        clock.advance(by: .seconds(MeshHeartbeatSchedule.intervalSeconds * 5))
        #expect(schedule.due(now: clock.now) == [MeshLinkKey("alpha"), MeshLinkKey("beta")])
    }

    /// Stopped and untracked links stay silent: a send on a stopped link must not resurrect it.
    @Test func stoppedLinksStaySilent() {
        let clock = VirtualClock()
        var schedule = MeshHeartbeatSchedule()
        schedule.start(Self.alpha, now: clock.now)
        schedule.stop(Self.alpha)

        schedule.noteSent(Self.alpha, now: clock.now)
        clock.advance(by: MeshHeartbeatSchedule.interval)
        #expect(schedule.due(now: clock.now).isEmpty)
        #expect(schedule.trackedCount == 0)
    }

    /// Tracking is bounded by the connection cap, and a restart of an already-tracked link replaces
    /// rather than adds — so a reconnect never counts twice against the bound.
    @Test func trackingIsBoundedByTheConnectionCap() {
        let clock = VirtualClock()
        var schedule = MeshHeartbeatSchedule()
        for index in 0..<(MeshHeartbeatSchedule.maxTrackedLinks + 3) {
            schedule.start(MeshLinkKey("peer-\(index)"), now: clock.now)
        }
        #expect(schedule.trackedCount == MeshHeartbeatSchedule.maxTrackedLinks)

        schedule.start(MeshLinkKey("peer-0"), now: clock.now)
        #expect(schedule.trackedCount == MeshHeartbeatSchedule.maxTrackedLinks)

        schedule.removeAll()
        #expect(schedule.trackedCount == 0)
        clock.advance(by: MeshHeartbeatSchedule.interval)
        #expect(schedule.due(now: clock.now).isEmpty)
    }
}

// MARK: - MeshHeartbeatLivenessTests

/// The two numbers and the one choice that decide whether a live tunnel survives its own keepalive.
///
/// **The defect these pin, measured on the radio in P2 item 15.** A verified pair churned — a tunnel
/// formed, ended and re-formed roughly every 37 s — with no dial failure, no refusal and no
/// transport error on either side. Instrumenting the disconnect path named it: `NWError 60 -
/// Operation timed out`, QUIC's own idle timer, firing at the default of about 30 s. The heartbeat
/// that existed to prevent exactly that was scheduled 30 s after activation, so it was due *at or
/// after* the reap and lost the race nearly every time. And on the lane where it did fire, its
/// datagram flow reported a usable frame size of 0, so it could not have arrived anyway.
///
/// Two independent faults, one symptom. Both are held here, at tier 1, on arithmetic and a pure
/// function — no radio, no clock, no sleep.
@Suite(.serialized)
struct MeshHeartbeatLivenessTests {

    /// The keepalive must fire strictly inside the timeout it defends against, with room for a
    /// dropped beat. Equality is the bug: a beat due exactly at the reap is a coin flip, and it is
    /// what the framework default produced.
    @Test func theIdleTimeoutOutlastsSeveralHeartbeats() {
        let beatMilliseconds = Int(MeshHeartbeatSchedule.intervalSeconds) * 1_000
        #expect(beatMilliseconds > 0)
        #expect(MeshHeartbeatSchedule.idleTimeoutMilliseconds > beatMilliseconds,
                "a keepalive due no sooner than the idle reap is not a keepalive")
        #expect(MeshHeartbeatSchedule.missedBeatsBeforeIdleReap >= 2,
                "surviving one dropped beat is the point of the margin")
        #expect(MeshHeartbeatSchedule.idleTimeoutMilliseconds
                == beatMilliseconds * MeshHeartbeatSchedule.missedBeatsBeforeIdleReap,
                "the timeout is derived from the interval so the two cannot drift back into a race")
    }

    /// The margin holds however the interval is retuned — the property, not today's numbers.
    @Test func theMarginSurvivesRetuningTheInterval() {
        let beats = MeshHeartbeatSchedule.missedBeatsBeforeIdleReap
        for seconds in [1, 5, 30, 120, 600] {
            #expect(seconds * beats * 1_000 > seconds * 1_000)
        }
    }

    /// A fresh tunnel tries the designed channel; one that has no datagram flow does not.
    @Test func afreshTunnelPrefersTheDatagramChannel() {
        #expect(MeshHeartbeatChannel.choice(hasDatagramFlow: true, datagramWriteFailed: false)
                == .datagram)
        #expect(MeshHeartbeatChannel.choice(hasDatagramFlow: false, datagramWriteFailed: false)
                == .controlStream)
    }

    /// Once the datagram write has been refused the tunnel never asks again — the one-shot latch.
    /// Without it, the lane whose usable frame size is 0 pays a failed write on every beat forever.
    @Test func arefusedDatagramLatchesOntoTheControlStream() {
        #expect(MeshHeartbeatChannel.choice(hasDatagramFlow: true, datagramWriteFailed: true)
                == .controlStream)
        #expect(MeshHeartbeatChannel.choice(hasDatagramFlow: false, datagramWriteFailed: true)
                == .controlStream)
    }

    /// Every combination is answered, and the control stream is the answer wherever the datagram
    /// flow is not both present and unrefused. Exhaustive, so a later input cannot fall through.
    @Test func theChannelChoiceIsTotal() {
        for hasFlow in [true, false] {
            for failed in [true, false] {
                let choice = MeshHeartbeatChannel.choice(
                    hasDatagramFlow: hasFlow,
                    datagramWriteFailed: failed
                )
                #expect(choice == (hasFlow && !failed ? .datagram : .controlStream))
            }
        }
    }
}

// MARK: - MeshTunnelEndReasonTests

/// The vocabulary that ended the silence on the disconnect path.
///
/// Before P2 item 15 a live tunnel that ended emitted nothing at all, which is why item 13 read
/// three sequential tunnels as three coexisting ones and why the churn behind that misreading went
/// undiagnosed for another fortnight. These hold the two properties a transcript reader depends on:
/// the tokens are frozen, and a benign tidy-up is distinguishable from a fault.
@Suite(.serialized)
struct MeshTunnelEndReasonTests {

    /// Frozen automation tokens. Editing one silently breaks every runbook grep and every
    /// transcript already captured, so the spellings are pinned rather than trusted.
    @Test func theTokensAreFrozen() {
        #expect(MeshTunnelEndReason.heartbeatSendFailed.rawValue == "heartbeatSendFailed")
        #expect(MeshTunnelEndReason.controlStreamEnded.rawValue == "controlStreamEnded")
        #expect(MeshTunnelEndReason.introductionFailed.rawValue == "introductionFailed")
        #expect(MeshTunnelEndReason.frameBudgetSpent.rawValue == "frameBudgetSpent")
        #expect(MeshTunnelEndReason.localEviction.rawValue == "localEviction")
        #expect(MeshTunnelEndReason.redundantDuplicate.rawValue == "redundantDuplicate")
        #expect(MeshTunnelEndReason.unverifiedFingerprint == "unverified")
    }

    /// Every reason round-trips through its own raw value, and no two share one — the property that
    /// makes a token in a transcript resolve to exactly one cause.
    @Test func everyReasonIsDistinctAndRoundTrips() {
        let all = MeshTunnelEndReason.allCases
        #expect(Set(all.map(\.rawValue)).count == all.count)
        for reason in all {
            #expect(MeshTunnelEndReason(rawValue: reason.rawValue) == reason)
        }
    }

    /// Exactly the two ends that are the radio tidying itself are benign; every other end is a
    /// fault. The split is what keeps an owner's slot eviction from reading as a radio failure —
    /// and, the other way, keeps a real timeout out of the noise floor.
    @Test func onlyTheRadiosOwnTidyUpIsBenign() {
        let benign = MeshTunnelEndReason.allCases.filter(\.isBenign)
        #expect(Set(benign) == Set([.localEviction, .redundantDuplicate]))
        #expect(!MeshTunnelEndReason.controlStreamEnded.isBenign,
                "the idle-timeout reap that caused the churn must never be filed as routine")
        #expect(!MeshTunnelEndReason.heartbeatSendFailed.isBenign)
    }
}

// MARK: - MeshLinkAdvertisementTests

/// The TXT vocabulary: what the QUIC radio publishes, and what it believes.
@Suite(.serialized)
struct MeshLinkAdvertisementTests {

    /// The real advertisement `MeshNetworkManager.currentDiscoveryInfo()` produces for an open mesh.
    static let managerAdvertisement: [String: String] = [
        "v": "1",
        "sid": "6C61CB0E-6B0A-4E29-9A4C-1E1E1F0B4E2A",
        "meshID": "0E0F1A2B-3C4D-5E6F-7A8B-9C0D1E2F3A4B",
        "meshName": "Saturday",
        "memberCount": "3"
    ]

    /// The whole manager advertisement survives a publish/parse round trip unchanged. If `sid` did
    /// not, the tie-break would silently degrade to both-sides-dial with nothing failing.
    @Test func theManagerAdvertisementRoundTripsIntact() {
        let published = MeshLinkAdvertisement.publishedFields(from: Self.managerAdvertisement)
        #expect(published == Self.managerAdvertisement)
        #expect(MeshLinkAdvertisement.advertisement(from: published) == Self.managerAdvertisement)
        #expect(published[MeshLinkAdvertisement.sessionIDKey] != nil)
    }

    /// `fp` is withheld in BOTH directions — not published, and not believed when a peer publishes
    /// it. An asymmetry here is how a peer gets a fingerprint claim into a handle that this build
    /// would never make itself, and the fingerprint gate treats a mismatch as fatal.
    @Test func theFingerprintKeyIsWithheldInBothDirections() {
        var withFingerprint = Self.managerAdvertisement
        withFingerprint["fp"] = "0123456789abcdef"

        #expect(MeshLinkAdvertisement.publishedFields(from: withFingerprint)["fp"] == nil)
        #expect(MeshLinkAdvertisement.advertisement(from: withFingerprint)["fp"] == nil)
        #expect(MeshLinkAdvertisement.publishedFields(from: withFingerprint) == Self.managerAdvertisement)
    }

    /// The DEBUG probe's TXT record carries no `sid` — the hazard recorded for this item. Copying
    /// the probe's advertisement verbatim would leave every peer unrankable, and an unrankable peer
    /// is invited by both sides.
    @Test func theProbeAdvertisementCarriesNoSessionIDAndIsUnrankable() {
        let probeTXT = ["mesh-probe-host": "simulator"]
        let parsed = MeshLinkAdvertisement.advertisement(from: probeTXT)
        #expect(parsed[MeshLinkAdvertisement.sessionIDKey] == nil)
        #expect(
            MeshDialPreference.rank(
                localSessionID: "aaaa",
                peerSessionID: parsed[MeshLinkAdvertisement.sessionIDKey]
            ) == .unranked
        )
    }

    /// `sid` survives the field cap even when a peer floods the record; the cap drops labels, never
    /// the discriminator.
    @Test func theFieldCapNeverDropsTheSessionID() {
        var flooded: [String: String] = ["sid": "keep-me"]
        for index in 0..<40 {
            flooded["k\(index)"] = "v\(index)"
        }
        let parsed = MeshLinkAdvertisement.advertisement(from: flooded)
        #expect(parsed.count == MeshLinkAdvertisement.maxFields)
        #expect(parsed["sid"] == "keep-me")
    }

    /// An over-long value is dropped whole, never truncated. A truncated `sid` still looks like a
    /// `sid` and would rank — deciding the wrong side dials, silently and permanently.
    @Test func anOverlongValueIsDroppedRatherThanTruncated() {
        let long = String(repeating: "x", count: MeshLinkAdvertisement.maxFieldValueLength + 1)
        let parsed = MeshLinkAdvertisement.advertisement(from: ["sid": long, "v": "1"])
        #expect(parsed["sid"] == nil)
        #expect(parsed["v"] == "1")

        let atLimit = String(repeating: "x", count: MeshLinkAdvertisement.maxFieldValueLength)
        #expect(MeshLinkAdvertisement.advertisement(from: ["sid": atLimit])["sid"] == atLimit)
    }

    /// Empty values contribute nothing in either direction — an empty `sid` reads as absent to the
    /// tie-break anyway, and publishing empty keys only widens what a passive scanner sees.
    @Test func emptyValuesAreDropped() {
        let parsed = MeshLinkAdvertisement.publishedFields(from: ["sid": "", "v": "", "meshName": "x"])
        #expect(parsed == ["meshName": "x"])
    }

    /// The instance name is random per session, prefixed, and short enough for Bonjour's 63-byte
    /// instance-name limit. Random is the point: the archived MC peer id it replaces was stable
    /// across launches, so a passive scanner could link sightings of one person. The prefix is the
    /// host's, so the cell names `.packageTest`'s.
    @Test func theInstanceNameIsRandomAndBounded() {
        let prefix = ProximityNamespace.packageTest.family.radios.meshInstanceNamePrefix
        let names = (0..<8).map { _ in MeshLinkAdvertisement.randomInstanceName(prefix: prefix) }
        #expect(Set(names).count == names.count, "instance names must not repeat")
        for name in names {
            #expect(name.hasPrefix(prefix))
            #expect(name.utf8.count <= 63)
            #expect(name.lowercased() == name, "the token is a frozen lowercase wire value")
        }
    }
}

// MARK: - NetworkMeshWireTests

/// The control stream's length framing, including the header a hostile peer controls.
@Suite(.serialized)
struct NetworkMeshWireTests {

    /// Round trip over the sizes that matter, including both boundaries.
    @Test func lengthsRoundTripUpToTheCeiling() throws {
        let ceiling = NetworkMeshSession.maxInboundWireBytes
        for length in [1, 2, 127, 128, 255, 256, 65_535, 65_536, ceiling] {
            let header = NetworkMeshWire.header(for: length)
            #expect(header.count == NetworkMeshWire.headerByteCount)
            #expect(try NetworkMeshWire.payloadLength(from: header, ceiling: ceiling) == length)
        }
    }

    /// A zero length, an over-ceiling length, and a short header are all refused BEFORE any payload
    /// byte is read — the length field is the one input that decides how much memory the next read
    /// allocates.
    @Test func implausibleHeadersAreRefusedBeforeAnyPayloadIsRead() {
        let ceiling = NetworkMeshSession.maxInboundWireBytes
        #expect(throws: MeshTransportError.invalidFrameLength) {
            _ = try NetworkMeshWire.payloadLength(from: NetworkMeshWire.header(for: 0), ceiling: ceiling)
        }
        #expect(throws: MeshTransportError.invalidFrameLength) {
            _ = try NetworkMeshWire.payloadLength(
                from: NetworkMeshWire.header(for: ceiling + 1), ceiling: ceiling
            )
        }
        #expect(throws: MeshTransportError.invalidFrameLength) {
            _ = try NetworkMeshWire.payloadLength(from: Data([0x00, 0x01]), ceiling: ceiling)
        }
        #expect(throws: MeshTransportError.invalidFrameLength) {
            _ = try NetworkMeshWire.payloadLength(
                from: Data([0xFF, 0xFF, 0xFF, 0xFF]), ceiling: ceiling
            )
        }
    }

    /// The inbound ceiling IS the framing's inflate cap. Until the deletion round this cell pinned
    /// the QUIC radio's ceiling to the MultipeerConnectivity radio's (a payload that rode one radio
    /// and was dropped by the other was a bug that only appeared once the fleet was mixed); with one
    /// radio left, the invariant that outlives it is the one `MeshTransportErrorSurfacingTests`
    /// pinned on the MC side and took with it — the transport floor stays pinned to the inflate
    /// ceiling every sealed body obeys, so a frame the framing would refuse to inflate is never read.
    @Test func theInboundCeilingIsTheFramingsInflateCap() {
        #expect(NetworkMeshSession.maxInboundWireBytes == SealedPayloadFraming.maxInflatedByteCount,
                "The transport floor must stay pinned to the inflate ceiling every sealed body obeys")
    }

    /// The radio's OWN size gate, not the wire header's: `receiveDatagrams` drops an over-ceiling
    /// datagram before it reaches a channel and `send` refuses an over-ceiling frame before any byte
    /// goes out, and both ask `withinWireCeiling(_:)`. The retired MultipeerConnectivity suite
    /// pinned the drop by driving a delegate; tier 1 cannot build a live `Network.QUIC.Datagrams`,
    /// so the predicate is pinned as a VALUE here and the two call sites by source needle below —
    /// a `>=`, a doubled ceiling or an inlined comparison at either site reddens one or the other.
    @Test func theRadioAdmitsAFrameAtExactlyTheCeilingAndRefusesOneByteOver() {
        let ceiling = NetworkMeshSession.maxInboundWireBytes
        #expect(NetworkMeshSession.withinWireCeiling(ceiling), "a frame at exactly the ceiling must pass")
        #expect(NetworkMeshSession.withinWireCeiling(0), "an empty frame is the framing's problem, not the gate's")
        #expect(!NetworkMeshSession.withinWireCeiling(ceiling + 1), "one byte over the ceiling must be refused")
        #expect(!NetworkMeshSession.withinWireCeiling(Int.max), "and so must anything absurd")
    }

    /// Both wire directions consult the predicate at their guard, spelled exactly so — the datagram
    /// receive path (a DROP, `mesh.quic.droppedOversizedDatagram`) and `send` (an outbound refusal).
    @Test func bothWireDirectionsAskThePredicateAtTheirGuard() throws {
        let source = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Transport/NetworkMeshSession.swift"))
        #expect(source.contains("guard Self.withinWireCeiling(payload.count) else {"),
                "the datagram receive path no longer gates on withinWireCeiling(_:)")
        #expect(source.contains("guard Self.withinWireCeiling(data.count) else {"),
                "send(_:to:mode:) no longer gates on withinWireCeiling(_:)")
        #expect(!source.contains("count <= Self.maxInboundWireBytes"),
                "an inline comparison against the ceiling bypasses the one predicate the cells pin")
    }

    /// Every failure the transport can raise says something. This is the surface that makes a dead
    /// radio visible instead of silent, so an unnamed case would defeat its own purpose.
    @Test func everyTransportErrorCarriesADiagnostic() {
        let errors: [MeshTransportError] = [
            .tlsIdentityUnavailable, .oversizedFrame(byteCount: 99),
            .invalidFrameLength, .noControlStream, .frameBudgetSpent
        ]
        for error in errors {
            #expect(!error.diagnosticDescription.isEmpty, "\(error) has no diagnostic")
        }
        #expect(MeshTransportError.oversizedFrame(byteCount: 99).diagnosticDescription.contains("99"))
    }
}

// MARK: - EphemeralMeshTLSIdentityTests

/// The per-session self-signed certificate: parseable by the platform, and different every time.
@Suite(.serialized)
struct EphemeralMeshTLSIdentityTests {

    static let anchor = Date(timeIntervalSince1970: 1_800_000_000)

    /// The DER this code writes is a certificate the platform parser accepts, carrying the public
    /// key it was built from and the common name it was handed (`.packageTest`'s). That is the only
    /// correctness claim worth making: nothing in Fernlet reads a peer's certificate, so "Security
    /// parses it" is exactly what has to hold.
    @Test func theMintedCertificateParsesAndCarriesItsOwnPublicKey() throws {
        let privateKey = P256.Signing.PrivateKey()
        let commonName = ProximityNamespace.packageTest.family.radios.tlsCommonName
        let der = try EphemeralMeshTLSIdentity.selfSignedCertificateDER(
            for: privateKey,
            commonName: commonName,
            notBefore: Self.anchor,
            notAfter: Self.anchor.addingTimeInterval(86_400),
            serial: [0x01, 0x02, 0x03, 0x04]
        )
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else {
            Issue.record("Security refused the DER this encoder produced")
            return
        }
        guard let summary = SecCertificateCopySubjectSummary(certificate) else {
            Issue.record("the certificate has no readable subject summary")
            return
        }
        #expect(summary as String == commonName)

        guard let publicKey = SecCertificateCopyKey(certificate),
              let external = SecKeyCopyExternalRepresentation(publicKey, nil) else {
            Issue.record("the certificate's public key could not be read back")
            return
        }
        #expect(external as Data == privateKey.publicKey.x963Representation)
    }

    /// Two mints share nothing. "Never reused across meshes" is the plan's wording; this is what it
    /// means in bytes.
    @Test func everyMintIsANewIdentity() throws {
        let first = try EphemeralMeshTLSIdentity.mint(now: Self.anchor)
        let second = try EphemeralMeshTLSIdentity.mint(now: Self.anchor)
        #expect(first.certificateDER != second.certificateDER)
        #expect(!first.certificateDER.isEmpty)
    }

    /// A certificate minted with the production validity window is a well-formed trust input —
    /// the shape a TLS stack will hand to its (accept-any) validator.
    @Test func aMintedCertificateIsAWellFormedTrustInput() throws {
        let der = try EphemeralMeshTLSIdentity.selfSignedCertificateDER(
            for: P256.Signing.PrivateKey(),
            notBefore: Self.anchor.addingTimeInterval(-EphemeralMeshTLSIdentity.clockSkewSeconds),
            notAfter: Self.anchor.addingTimeInterval(EphemeralMeshTLSIdentity.lifetimeSeconds),
            serial: EphemeralMeshTLSIdentity.randomSerial()
        )
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else {
            Issue.record("Security refused the DER this encoder produced")
            return
        }
        let policy = SecPolicyCreateBasicX509()
        var trust: SecTrust?
        #expect(SecTrustCreateWithCertificates(certificate, policy, &trust) == errSecSuccess)
        #expect(trust != nil, "a self-signed certificate must still be a well-formed one")
    }

    /// Serial numbers are positive and bounded — a negative DER integer is a certificate some
    /// parsers reject outright.
    @Test func serialNumbersArePositiveAndBounded() {
        for _ in 0..<32 {
            let serial = EphemeralMeshTLSIdentity.randomSerial()
            #expect(serial.count == EphemeralMeshTLSIdentity.serialByteCount)
            #expect((serial.first ?? 0xFF) < 0x80, "the high bit must be clear so the integer is positive")
        }
    }

    /// The DER primitives: short-form and long-form lengths, and the integer padding rule.
    @Test func theDEREncoderFollowsTheLengthAndIntegerRules() {
        #expect(MeshCertificateDER.length(0) == [0x00])
        #expect(MeshCertificateDER.length(127) == [0x7F])
        #expect(MeshCertificateDER.length(128) == [0x81, 0x80])
        #expect(MeshCertificateDER.length(300) == [0x82, 0x01, 0x2C])

        // High bit set → one padding byte, so the value stays positive.
        #expect(MeshCertificateDER.integer([0x80]) == [0x02, 0x02, 0x00, 0x80])
        // Leading zeros stripped.
        #expect(MeshCertificateDER.integer([0x00, 0x00, 0x2A]) == [0x02, 0x01, 0x2A])
        // All-zero collapses to a single zero rather than nothing.
        #expect(MeshCertificateDER.integer([0x00, 0x00]) == [0x02, 0x01, 0x00])
        #expect(MeshCertificateDER.bitString([0xAB]) == [0x03, 0x02, 0x00, 0xAB])
        #expect(MeshCertificateDER.sequence([0x05, 0x00]) == [0x30, 0x02, 0x05, 0x00])
    }
}

// MARK: - NetworkMeshSessionTests

/// The QUIC session's observable surface: what its channel publishes, and what it leaves behind.
@MainActor
@Suite(.serialized)
struct NetworkMeshSessionTests {

    /// The channel publishes `.idle`, `.connected` and `.disconnected`, and never `.discovered`.
    ///
    /// The parity that matters: `ProximityCoordinator.shouldInviteDiscoveredPeer` is a second,
    /// dormant inviter policy comparing `sessionID < remoteSID` — the OPPOSITE direction to the live
    /// `MeshNetworkManager.shouldInitiateInvite` (`>`). It wakes the moment a conformer emits a
    /// discovered state, and two policies pointing opposite ways means neither side dials.
    @Test func theChannelNeverPublishesADiscoveredState() async throws {
        let session = NetworkMeshSession()
        let peer = PeerHandle(
            id: UUID(), displayHint: "fernlet-mesh-abc", discoveryInfo: ["sid": "aaaa"],
            advertisedFingerprint: nil
        )
        let channel = NetworkPeerChannel(peer: peer, host: session)

        var observed: [PeerTransportState] = []
        let subscription = channel.state.sink { observed.append($0) }
        defer { subscription.cancel() }

        try await channel.startAdvertising(discoveryInfo: [:])
        try await channel.startBrowsing()
        try await channel.invite(peer)
        channel.notifyConnected()
        channel.receive(Data([0x01]), at: Date())
        channel.notifyDisconnected(reason: "test")
        await channel.disconnect()

        #expect(observed == [.idle, .connected(peer), .disconnected(reason: "test"), .idle])
        for state in observed {
            if case .discovered = state {
                Issue.record("the QUIC channel published .discovered — the dormant opposite-direction policy wakes")
            }
        }
    }

    /// The source itself never constructs a discovered state. The publisher test above can only
    /// cover the paths it drives; this covers the ones nobody has written yet.
    @Test func theTransportSourceNeverConstructsADiscoveredState() throws {
        let path = "Sources/ProximityKit/Transport/NetworkMeshSession.swift"
        let source = try String(contentsOf: PackageRoot.url.appendingPathComponent(path), encoding: .utf8)
        let offenders = source
            .components(separatedBy: .newlines)
            .enumerated()
            .filter { _, line in
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                guard !trimmed.hasPrefix("//"), !trimmed.hasPrefix("*") else { return false }
                return line.contains(".discovered(") || line.contains("PeerTransportState.discovered")
            }
            .map { "\(path):\($0.offset + 1)" }
        #expect(
            offenders.isEmpty,
            "the QUIC transport constructs PeerTransportState.discovered at \(offenders) — see the type's docs"
        )
    }

    /// A frame delivered to the channel reaches its inbound publisher with the peer and byte count
    /// the coordinator's size gate reads.
    @Test func inboundFramesCarryTheirPeerAndByteCount() {
        let session = NetworkMeshSession()
        let peer = PeerHandle(
            id: UUID(), displayHint: "fernlet-mesh-abc", discoveryInfo: nil, advertisedFingerprint: nil
        )
        let channel = NetworkPeerChannel(peer: peer, host: session)

        var frames: [InboundPeerFrame] = []
        let subscription = channel.inbound.sink { frames.append($0) }
        defer { subscription.cancel() }

        let now = Date(timeIntervalSince1970: 1_800_000_000)
        channel.receive(Data(repeating: 0x07, count: 12), at: now)

        #expect(frames.count == 1)
        #expect(frames.first?.peer == peer)
        #expect(frames.first?.bytesReceived == 12)
        #expect(frames.first?.receivedAt == now)
    }

    /// **The `.preCommitTimeout` arm, driven.** The refund rule itself is pinned on the table; this
    /// is the cell that proves the radio reaches it — that
    /// ``NetworkMeshSession/disconnectPeer(_:cause:)`` resolves the owner's handle back to the
    /// endpoint key and consumes *that endpoint's* booking — and that the arm is a pair: the
    /// cause-blind entry point charges, exactly as an owner refusal must.
    ///
    /// Two offers are booked, so the second timeout has something it *could* take. With one,
    /// "the refund did nothing" and "there was nothing left to take" read identically.
    @Test func aPreCommitTimeoutEvictionConsumesExactlyOneReproposeBooking() {
        let session = NetworkMeshSession()
        let key = MeshLinkKey("timed-out-endpoint")
        let verified = MeshVerifiedPeer(
            signingPublicKey: Data(repeating: 0x11, count: 32),
            fingerprint: "abcd-efgh-ijkl",
            sessionID: "aaaa"
        )
        #expect(session.bookReproposalForTesting(key), "test premise: the first offer books")
        #expect(session.bookReproposalForTesting(key), "test premise: and so does the second")
        #expect(session.linkTableForTesting.reproposalCount(of: key) == 2, "test premise: two offers")

        session.bookTunnelForTesting(key, role: .initiator, verified: verified)
        guard let peer = session.connectedPeers.first else {
            Issue.record("a booked tunnel must carry a peer handle")
            return
        }

        session.disconnectPeer(peer, cause: .preCommitTimeout)
        #expect(session.linkTableForTesting.reproposalCount(of: key) == 1,
                "the eviction handed back the booking that paid for this tunnel")
        #expect(session.linkTableForTesting.reproposalRefundCount(of: key) == 1)

        session.disconnectPeer(peer, cause: .preCommitTimeout)
        #expect(session.linkTableForTesting.reproposalCount(of: key) == 1, """
            and a second report of the one timeout took nothing more: what the arm consumes is the \
            booking, not the counter
            """)
        #expect(session.linkTableForTesting.reproposalRefundCount(of: key) == 1)

        // The other half of the pair: an owner decision CHARGES, which is the loop the budget is
        // for. Same endpoint, same handle, a fresh offer and a fresh tunnel.
        #expect(session.bookReproposalForTesting(key), "test premise: a third offer is in budget")
        session.bookTunnelForTesting(key, role: .initiator, verified: verified)
        session.disconnectPeer(peer)
        #expect(session.linkTableForTesting.reproposalCount(of: key) == 2,
                "an owner's eviction spends its offer — six of those still end the sweep")
        #expect(session.linkTableForTesting.reproposalRefundCount(of: key) == 1)
    }

    /// Teardown leaves no peer identities behind. The map exists only to keep one device the same
    /// peer for the life of a session; keeping it past a stop would link two runs of the radio to
    /// one device, which is what the per-session random Bonjour name exists to prevent.
    ///
    /// The introduction's replay cache and its pending inbound connections die with it for the same
    /// reason: nothing this radio learns survives its own stop, so nothing owes a wipe-ledger row.
    @Test func stopClearsEverySessionScopedMap() {
        let session = NetworkMeshSession()
        session.stop()
        #expect(session.trackedEndpointCountForTesting == 0)
        #expect(session.linkTableForTesting.occupiedSlotCount == 0)
        #expect(session.linkTableForTesting.cachedEndpointCount == 0)
        #expect(session.trackedIntroductionNonceCountForTesting == 0)
        #expect(session.pendingInboundCountForTesting == 0)
        #expect(session.connectedPeers.isEmpty)
        #expect(!session.isRunning)
    }

    /// **P8 item 3, review findings F-3 / F-5: a republish must not un-pause a held radio.**
    ///
    /// `updateDiscoveryInfo(_:)` re-mints the listener, which is the only way to withdraw and
    /// re-register the Bonjour name — and re-registering is exactly what a hold may not do, because
    /// the accept path comes back up with it. `MeshMultipeerSession` has always guarded this; the
    /// QUIC copy did not. The fields are still RECORDED, because `resumeDiscovery()` re-mints from
    /// them and a resume that republished stale fields would advertise another moment's member
    /// count — the same reason `startRadios(discoveryInfo:)`'s early return may not throw the
    /// caller's fields away.
    ///
    /// Tier 1 cannot start this radio (a real listener, and the Local Network permission with it),
    /// so the behaviour is asserted on the shape tier 1 does own — a radio that never started takes
    /// the same early return — plus the ORDER of the three statements, which is the whole rule. The
    /// proof behind a live listener is owed to the tier-2 lane.
    @Test func aRepublishIsRememberedRatherThanReMintedWhileDiscoveryIsPaused() throws {
        let session = NetworkMeshSession()
        session.pauseDiscovery()
        #expect(!session.isDiscoveryPausedForTesting,
                "a radio that never started has no discovery to pause")

        session.updateDiscoveryInfo(["sid": "abcd", "memberCount": "3"])
        #expect(session.advertisedFieldsForTesting["sid"] == "abcd", """
            the fields are recorded before either early return, so what a held radio is told is \
            what it advertises when it comes back
            """)
        #expect(session.advertisedFieldsForTesting["memberCount"] == "3")
        session.stop()
        #expect(!session.isDiscoveryPausedForTesting, "and a stop clears the pause with the rest")

        let quic = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Transport/NetworkMeshSession.swift")
        )
        let republish = try #require(MeshRoutedSourceScan.bracedBody(
            after: "func updateDiscoveryInfo(_ discoveryInfo:", in: quic
        ))
        let recorded = try #require(republish.range(of: "advertisedFields = MeshLinkAdvertisement"))
        let held = try #require(republish.range(of: "guard !isDiscoveryPaused else { return }"))
        let reMint = try #require(republish.range(of: "cancelListener()"))
        #expect(recorded.upperBound < held.lowerBound,
                "record the caller's fields FIRST, or a held radio resumes onto stale ones")
        #expect(held.upperBound < reMint.lowerBound,
                "and refuse while held BEFORE the re-mint, or the pause is silently undone")

        let selection = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Transport/MeshTransportSelection.swift")
        )
        #expect(selection.contains("updateDiscoveryInfo(discoveryInfo)\n            resumeDiscovery()"), """
            and the one re-arm funnel's early return records the caller's fields before resuming, \
            instead of resuming onto whatever was advertised when the radio last started
            """)
    }

    /// A connection that never finishes its introduction is dropped, not held forever.
    ///
    /// The seat it holds is pre-authentication and there are only eight of them, so an unbounded
    /// wait on a peer that says nothing is how eight silent connections keep every real member out.
    /// The sweep rides the one poll the radio already owns, so there is no timer per connection.
    @Test func aPendingIntroductionThatNeverFinishesIsSweptAway() {
        let session = NetworkMeshSession()
        let started = Date(timeIntervalSince1970: 1_800_000_000)
        session.bookPendingInboundForTesting(MeshLinkKey("silent"), startedAt: started)
        session.bookPendingInboundForTesting(MeshLinkKey("prompt"), startedAt: started)
        #expect(session.pendingInboundCountForTesting == 2)

        // A hair inside the deadline: both survive.
        session.expirePendingInboundForTesting(
            now: started.addingTimeInterval(NetworkMeshSession.introductionDeadlineSeconds)
        )
        #expect(session.pendingInboundCountForTesting == 2)

        session.expirePendingInboundForTesting(
            now: started.addingTimeInterval(NetworkMeshSession.introductionDeadlineSeconds + 0.001)
        )
        #expect(session.pendingInboundCountForTesting == 0)
        #expect(
            NetworkMeshSession.maxPendingInboundTunnels == MeshLinkTable.maxConcurrentLinks,
            "a pending seat must never be scarcer than a roster seat, or a member is refused before a stranger"
        )
        #expect(session.linkTableForTesting.occupiedSlotCount == 0, "a pending connection holds no roster slot")
    }

    /// The accept path cannot be reached without a verified peer.
    ///
    /// Item 5 left exactly one `peerSessionID: nil` in the transport, which made every inbound
    /// tunnel ``MeshDialPreference/unranked``. This pins the closure: the only `admitInbound` call in
    /// the file takes its `sid` from a ``MeshVerifiedPeer``, so an unauthenticated connection can no
    /// longer reach duplicate-tunnel suppression at all — the publisher test above can only cover
    /// paths it drives, and this covers the one nobody can drive without two radios.
    @Test func theAcceptPathIsUnreachableWithoutAVerifiedPeer() throws {
        let path = "Sources/ProximityKit/Transport/NetworkMeshSession.swift"
        let source = try String(contentsOf: PackageRoot.url.appendingPathComponent(path), encoding: .utf8)
        let lines = source.components(separatedBy: .newlines)
        let code = lines.filter { line in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            return !trimmed.hasPrefix("//") && !trimmed.hasPrefix("*") && !trimmed.hasPrefix("///")
        }
        #expect(
            !code.contains { $0.contains("peerSessionID: nil") },
            "the QUIC transport still admits an inbound tunnel with no peer session id — item 5's residual is open"
        )
        let admissions = code.filter { $0.contains("links.admitInbound(") }
        #expect(admissions.count == 1, "expected exactly one inbound admission site, found \(admissions.count)")
        #expect(
            code.contains { $0.contains("peerSessionID: verified.sessionID") },
            "the inbound admission must rank on the session id the signed introduction verified"
        )
    }

    /// The listener and browser task bodies check for cancellation before they report.
    ///
    /// A source claim because it has to be: `NetworkListener.run` is a framework call a unit test
    /// cannot make throw. The order is the whole of it — `updateDiscoveryInfo(_:)` cancels the
    /// listener task on EVERY republish (a mesh-mode change, a merge, a member-count change) and
    /// `pauseDiscovery()` cancels both at every hold, because re-creating the listener is the only
    /// way to withdraw a Bonjour registration. The owner's only reader is `discoveryError`, the
    /// Friends-screen banner: the republish path never clears it, and the hold and stop paths clear
    /// it BEFORE the cancel lands, so a `CancellationError` reported as a failure is a "discovery
    /// failed" banner pinned over a healthy search until the user leaves the tab. Mirrors
    /// `PresenceOverQUICTests.theListenerAndBrowserTasksDoNotReportTheirOwnCancellation`.
    @Test func theListenerAndBrowserTasksDoNotReportTheirOwnCancellation() throws {
        let code = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Transport/NetworkMeshSession.swift")
        )
        for signature in ["func startListener() throws", "func startBrowser()"] {
            let body = try #require(
                MeshRoutedSourceScan.bracedBody(after: signature, in: code),
                "\(signature) is gone or its braces do not close"
            )
            let guardIndex = try #require(
                body.range(of: "guard !Task.isCancelled else { return }")?.lowerBound,
                "\(signature)'s task body reports without checking for its own cancellation first"
            )
            let reportIndex = try #require(
                body.range(of: "report(")?.lowerBound, "\(signature) no longer reports at all"
            )
            #expect(guardIndex < reportIndex, "\(signature) guards AFTER it reports, which guards nothing")
        }
    }

    /// A session identity is minted once per endpoint and both halves are minted together, so a
    /// re-sighting resolves to the same `id` AND the same endpoint key — the property every slot,
    /// QR binding and device cap above the transport depends on.
    @Test func oneIdentityPerEndpointIsMintedOnceAndPairedForever() {
        var map = MeshSessionIdentityMap()
        let key = MeshLinkKey("alpha")
        let first = map.identity(for: key)
        let again = map.identity(for: key)

        #expect(first == again)
        #expect(map.trackedCount == 1)

        let handle = PeerHandle(
            id: first.id, displayHint: "x", discoveryInfo: nil,
            advertisedFingerprint: nil, endpoint: first.endpoint
        )
        #expect(map.key(for: handle) == key)

        let other = map.identity(for: MeshLinkKey("beta"))
        #expect(other.id != first.id)
        #expect(other.endpoint != first.endpoint)
    }

    /// The identity map is bounded oldest-first, and eviction drops BOTH directions — a map where
    /// one direction outlived the other would route a handle to an endpoint that no longer owns it.
    @Test func theIdentityMapIsBoundedAndEvictsBothDirections() {
        var map = MeshSessionIdentityMap()
        let first = map.identity(for: MeshLinkKey("peer-0"))
        let firstHandle = PeerHandle(
            id: first.id, displayHint: "x", discoveryInfo: nil,
            advertisedFingerprint: nil, endpoint: first.endpoint
        )
        for index in 1...MeshSessionIdentityMap.maxTrackedEndpoints {
            _ = map.identity(for: MeshLinkKey("peer-\(index)"))
        }
        #expect(map.trackedCount == MeshSessionIdentityMap.maxTrackedEndpoints)
        #expect(map.key(for: firstHandle) == nil, "the evicted endpoint must not still route")

        map.removeAll()
        #expect(map.trackedCount == 0)
    }

    /// **The browse transcript logs its COUNT publicly and its peer NAMES privately.**
    ///
    /// Plan §8.7 finding 1's "one item owed before QUIC ships", taken in the cutover that made this
    /// radio the shipping one (2026-09-21). Until then `noteBrowseSet` built one string and logged
    /// it whole at `privacy: .public`, so every nearby device's Bonjour instance name went into the
    /// system log — and into a sysdiagnose, off the device, naming who else was in the room.
    ///
    /// **Hygiene, not a leak fix.** A mesh instance name is `MeshLinkAdvertisement`'s random
    /// per-session token: it identifies no device across sessions and says nothing a scanner on the
    /// same link could not read for itself. What the downgrade buys is that the transcript stops
    /// being where a stable-looking identifier would accumulate if that ever changed.
    ///
    /// Source, not behaviour, and deliberately so: `os.Logger`'s redaction happens inside the
    /// unified logging system and a unit test cannot observe which interpolation was public. What
    /// IS observable is the shape of the call, and the shape is the whole decision — one
    /// interpolation each, count public, names private, and the string never re-assembled and
    /// logged whole. The DEBUG console echo is checked in the OTHER direction: it must still carry
    /// the names, because it is the transcript the runbook's Simulator lanes grep and a lane that
    /// could not see them could not tell the three-node star from the mesh.
    @Test func theBrowseTranscriptLogsItsCountPubliclyAndItsPeerNamesPrivately() throws {
        let quic = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Transport/NetworkMeshSession.swift")
        )
        let body = try #require(
            MeshRoutedSourceScan.bracedBody(after: "func noteBrowseSet(_ keys: Set<MeshLinkKey>)", in: quic),
            "noteBrowseSet is gone — the browse transcript this cell walls has no home"
        )
        #expect(body.contains("privacy: .private)]\")"), """
            the browsed-peers line no longer redacts its peer names. Nearby devices' Bonjour \
            instance names must interpolate at `privacy: .private`; plan §8.7 finding 1 is the \
            item this closed, and re-opening it puts a transcript of who was nearby into every \
            sysdiagnose
            """)
        #expect(body.contains("browsed peers=\\(keys.count, privacy: .public)"), """
            and the COUNT is no longer public. The count identifies nobody and is the whole reason \
            a reader opens this transcript — redacting it to `<private>` would cost the diagnostic \
            and buy nothing
            """)
        #expect(!body.contains("\\(line, privacy: .public)"), """
            the line is re-assembled and logged whole again, which is exactly the shape the \
            downgrade removed — one public interpolation carrying both halves
            """)
        #expect(body.contains("MeshTransportConsoleLog.echo(\"browsed peers=\\(keys.count) [\\(names)]\")"), """
            the DEBUG console echo lost the peer names. That echo is a no-op outside DEBUG and is \
            the transcript the runbook's Simulator lanes grep: a lane that cannot see the names \
            cannot tell a three-node star from a three-node mesh, which is the defect this line \
            was added for
            """)
    }

    // MARK: Peer-derived values in the shipping radio's system log

    /// The literal a public interpolation ends with, and the marker the scan walks.
    static let publicInterpolationMarker = ", privacy: .public)"

    /// How a peer-derived value is spelled on this radio: the browsed endpoint id and its
    /// `rawValue`, the ``MeshLinkKey`` it is wrapped in, the advertised instance name, and the
    /// verified identity fingerprint.
    static let peerDerivedTokens = [
        "key", "endpoint", "rawvalue", "fingerprint", "instance", "name", "peer"
    ]

    /// Every expression interpolated at `privacy: .public` on one line of Swift.
    ///
    /// Walks to each marker and takes the nearest `\(` *before* it, so a line carrying a public
    /// and a private interpolation yields only the public one — which is exactly the shape
    /// `noteTunnelEnded` writes, and reading it per-LINE rather than per-INTERPOLATION would
    /// condemn the fix for the leak it closed.
    static func publicInterpolations(in line: String) -> [String] {
        var found: [String] = []
        var rest = Substring(line)
        // R2: every pass consumes at least the marker, and the line is finite.
        while let marker = rest.range(of: publicInterpolationMarker) {
            let head = rest[rest.startIndex..<marker.lowerBound]
            if let open = head.range(of: "\\(", options: .backwards) {
                found.append(String(head[open.upperBound...]))
            }
            rest = rest[marker.upperBound...]
        }
        return found
    }

    /// Whether one publicly-interpolated expression carries a value derived from a peer.
    ///
    /// Two exemptions, and both are the point of the fix rather than holes in it:
    /// ``NetworkMeshSession/peerLabel(for:)`` is the sanctioned labeller (its own call names two
    /// forbidden tokens), and a `.count` identifies nobody — `browsed peers=\(keys.count)` is the
    /// one peer-shaped interpolation the cutover deliberately KEPT public.
    static func isPeerDerived(_ expression: String) -> Bool {
        let normalized = expression.lowercased()
        guard !normalized.contains("peerlabel(") else { return false }
        guard !normalized.hasSuffix(".count") else { return false }
        return peerDerivedTokens.contains { normalized.contains($0) }
    }

    /// **Nothing peer-derived reaches the shipping radio's system log.**
    ///
    /// The cutover (2026-09-21) made `NetworkMeshSession` the radio every launch gets, and moved
    /// none of its diagnostics. Ten of them interpolated `MeshLinkKey.rawValue` — the browsed
    /// Bonjour endpoint id, which contains the peer's advertised instance name verbatim — at
    /// `privacy: .public`, and `noteTunnelEnded` interpolated the peer's **stable** 16-character
    /// identity fingerprint, the value the ledger and the moderation record are keyed on, at
    /// `.public` on every single teardown. `409b714` redacted only `browsed peers=`. The two
    /// sibling radios had run on a salted, session-scoped `peerLabel(for:)` since they shipped;
    /// this radio now does too, and this is the wall that keeps it there.
    ///
    /// Source, not behaviour, and deliberately so — `os.Logger`'s redaction happens inside the
    /// unified logging system and a unit test cannot observe which interpolation was public. What
    /// IS observable is the shape of the call, and the shape is the whole decision.
    ///
    /// Three claims, because one alone leaves the hole the leak actually came through:
    ///
    /// 1. No `privacy: .public` interpolation names a peer-derived token.
    /// 2. `peerLines(_:key:detail:)` still builds its two halves differently — the logged one
    ///    through the label, the echoed one through the raw id. Collapse them and claim 1 stays
    ///    green while every line goes back to naming peers.
    /// 3. Outside those two builders, no string literal in the file interpolates the raw endpoint
    ///    id at all — which is the indirection that let `let line = "… \(key.rawValue)"` followed
    ///    by `\(line, privacy: .public)` read as clean to a per-interpolation scan.
    @Test func noPublicDiagnosticOnTheShippingRadioCarriesAPeerDerivedValue() throws {
        let code = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Transport/NetworkMeshSession.swift")
        )

        var offenders: [String] = []
        for line in code.split(separator: "\n", omittingEmptySubsequences: false) {
            let text = String(line)
            for expression in Self.publicInterpolations(in: text) where Self.isPeerDerived(expression) {
                offenders.append("\(expression) — in: \(text.trimmingCharacters(in: .whitespaces))")
            }
        }
        #expect(offenders.isEmpty, """
            the shipping mesh radio logs a peer-derived value at `privacy: .public` again. Every \
            such value — the link key, the browsed endpoint id, the advertised instance name, the \
            identity fingerprint — must interpolate through `peerLabel(for:)`, which is salted \
            per session and gone with it. Counts, causes, capacities and durations stay public. \
            Offending interpolations:
            \(offenders.joined(separator: "\n"))
            """)

        let builder = try #require(
            MeshRoutedSourceScan.bracedBody(after: "private func peerLines(", in: code),
            "peerLines is gone — the split between the logged line and the echoed one has no home"
        )
        #expect(builder.contains("logged: \"\\(body) for \\(peerLabel(for: key))\\(tail)\""), """
            the LOGGED half of a peer-scoped line no longer names the peer by its session label. \
            That half goes to `os.Logger`, is persisted, and leaves the device in a sysdiagnose
            """)
        #expect(builder.contains("echoed: \"\\(body) for \\(key.rawValue)\\(tail)\""), """
            the ECHOED half lost the raw endpoint id. That half goes to \
            `MeshTransportConsoleLog`, which is an empty function outside DEBUG, and it is the \
            transcript the runbook's Simulator lanes grep — a lane that cannot match a tunnel \
            line against its own `browsed peers=` list cannot tell a star from a mesh
            """)

        let tunnelEnded = try #require(
            MeshRoutedSourceScan.bracedBody(after: "private func noteTunnelEnded(", in: code),
            "noteTunnelEnded is gone — the teardown line that leaked the fingerprint has no home"
        )
        #expect(tunnelEnded.contains("fingerprint=\\(fingerprint, privacy: .private)"), """
            the teardown line stopped redacting the peer's identity fingerprint. It is STABLE — \
            the ledger, the roster and the moderation record are keyed on it — and it was public \
            on every teardown of the shipping radio until the cutover's fix
            """)

        let remainder = code
            .replacingOccurrences(of: builder, with: "")
            .replacingOccurrences(of: tunnelEnded, with: "")
        #expect(!remainder.contains("\\(key.rawValue)"), """
            a string literal outside `peerLines` and `noteTunnelEnded` interpolates the raw \
            endpoint id. That is the indirection the leak travelled through: a `let line = "… \
            \\(key.rawValue)"` logged as `\\(line, privacy: .public)` names a peer while \
            reading as clean to a per-interpolation scan. Build peer-scoped lines with \
            `peerLines(_:key:detail:)`
            """)
    }
}

// MARK: - MeshIntroductionHarness

/// Two endpoints and one channel, enough to drive plan §7.2's introduction end to end without a
/// radio, a keychain, or an `IdentityService`.
///
/// Signing goes through `CryptographicPurpose.signingBytes` exactly as `IdentityService.sign` does,
/// so a transcript that would be refused at the real signing boundary is refused here too — the
/// harness cannot accidentally mint bytes production could not.
enum MeshIntroductionHarness {

    /// The channel binding both ends of an untampered tunnel derive.
    static let binding = Data(repeating: 0xB1, count: MeshChannelIntroductionFormat.channelBindingByteCount)

    /// A different one — what the two ends see when they are not on the same tunnel.
    static let otherBinding = Data(repeating: 0xB2, count: MeshChannelIntroductionFormat.channelBindingByteCount)

    /// The mesh epoch references are minted against. Fixed so two calls agree.
    static let epochMeshID = UUID(uuidString: "3F2504E0-4F89-11D3-9A0C-0305E82C3301") ?? UUID()

    /// A canonical `MeshEpochRef` string, the only shape a hello's `epochRef` may now take besides
    /// empty. `coordinator` is what makes two same-counter epochs *divergent* rather than equal —
    /// exactly as two partitions with different lowest fingerprints would produce.
    static func epoch(_ counter: UInt32, coordinator: String = "00000000000000aa") -> String {
        MeshEpochRef.minted(
            counter: counter, coordinatorFingerprint: coordinator, meshID: epochMeshID
        )?.canonicalString ?? ""
    }

    /// One side of an introduction: its signing key and the hello it sends.
    struct Endpoint {
        let signingKey: Curve25519.Signing.PrivateKey
        let hello: MeshChannelHello

        var publicKey: Data { signingKey.publicKey.rawRepresentation }
    }

    static func endpoint(
        meshID: UUID,
        epochRef: String = MeshIntroductionHarness.epoch(7),
        sessionID: String,
        protocolVersion: Int = MeshChannelIntroductionFormat.protocolVersion,
        nonce: Data = MeshChannelIntroductionFormat.randomNonce()
    ) -> Endpoint {
        let key = Curve25519.Signing.PrivateKey()
        return Endpoint(signingKey: key, hello: MeshChannelHello(
            protocolVersion: protocolVersion,
            meshID: meshID,
            epochRef: epochRef,
            signingPublicKey: key.publicKey.rawRepresentation,
            nonce: nonce,
            sessionID: sessionID
        ))
    }

    static func roster(
        _ endpoints: Endpoint...,
        barred: [Data] = [],
        doorsOpen: Bool = false
    ) -> MeshIntroductionRoster {
        MeshIntroductionRoster(
            members: endpoints.map(\.publicKey), barred: barred,
            admitsStrangersProvisionally: doorsOpen
        )
    }

    /// Signs a transcript the way `IdentityService.sign` does — through the purpose's framing check.
    static func signature(over transcript: Data, by key: Curve25519.Signing.PrivateKey) throws -> Data {
        let purpose = ProximityNamespace.packageTest.family.purposes.signature.meshChannelIntroductionV1
        let bytes = try #require(
            purpose.signingBytes(transcript),
            "the transcript does not satisfy meshChannelIntroductionV1's declared framing"
        )
        return try key.signature(for: bytes)
    }

    static func introduction(
        over transcript: Data,
        binding: Data,
        by key: Curve25519.Signing.PrivateKey
    ) throws -> MeshChannelIntroduction {
        MeshChannelIntroduction(
            channelBindingHash: binding,
            signature: try signature(over: transcript, by: key)
        )
    }

    /// Everything one run of the handshake produced, so a test can assert on any stage of it.
    struct Run {
        var initiator: MeshChannelIntroductionExchange
        var responder: MeshChannelIntroductionExchange
        var initiatorHelloRejection: MeshIntroductionRejection?
        var responderHelloRejection: MeshIntroductionRejection?
        var initiatorTranscript: Data?
        var responderTranscript: Data?
        var initiatorOutcome: MeshChannelIntroductionOutcome?
        var responderOutcome: MeshChannelIntroductionOutcome?
    }

    /// Drives both sides through hello → bind → sign → review, stopping at the first refusal.
    ///
    /// Each side gets its own nonce cache, matching production: the caches are per session, not per
    /// mesh, so a replay is only a replay to the side that already saw it.
    /// - Parameters:
    ///   - roster: What the RESPONDER judges the initiator's hello against.
    ///   - initiatorRoster: What the INITIATOR judges the responder's hello against, when the two
    ///     ends do not hold the same view. Nil means "the same roster", which is every symmetric
    ///     row; D-4.3's first-meeting rows are asymmetric by nature — a mesh-less joiner's roster is
    ///     empty while the founder's names itself — so they pass both.
    static func run(
        initiator: Endpoint,
        responder: Endpoint,
        roster: MeshIntroductionRoster,
        initiatorRoster: MeshIntroductionRoster? = nil,
        initiatorBinding: Data = binding,
        responderBinding: Data = binding
    ) throws -> Run {
        var state = Run(
            initiator: MeshChannelIntroductionExchange(role: .initiator, localHello: initiator.hello),
            responder: MeshChannelIntroductionExchange(role: .responder, localHello: responder.hello)
        )
        var initiatorNonces = MeshIntroductionNonceCache()
        var responderNonces = MeshIntroductionNonceCache()
        state.responderHelloRejection = state.responder.receive(
            initiator.hello, roster: roster, nonces: &responderNonces
        )
        state.initiatorHelloRejection = state.initiator.receive(
            responder.hello, roster: initiatorRoster ?? roster, nonces: &initiatorNonces
        )
        guard state.responderHelloRejection == nil, state.initiatorHelloRejection == nil else { return state }
        state.initiatorTranscript = state.initiator.bind(channelBindingHash: initiatorBinding)
        state.responderTranscript = state.responder.bind(channelBindingHash: responderBinding)
        guard let initiatorTranscript = state.initiatorTranscript,
              let responderTranscript = state.responderTranscript else { return state }
        state.responderOutcome = state.responder.review(
            try introduction(over: initiatorTranscript, binding: initiatorBinding, by: initiator.signingKey)
        )
        state.initiatorOutcome = state.initiator.review(
            try introduction(over: responderTranscript, binding: responderBinding, by: responder.signingKey)
        )
        return state
    }
}

// MARK: - MeshChannelIntroductionTests

/// Plan §7.2's signed channel introduction: the decision that lets a stranger onto the mesh, or
/// does not.
///
/// Every refusal below asserts two things, never one — that the introduction was rejected, **and**
/// that nothing about the peer survived it. A rejection that still handed a `sid` or a handle to the
/// accept path would be a degraded accept wearing a rejection's name, which is exactly what plan
/// §7.2 forbids.
@Suite(.serialized)
struct MeshChannelIntroductionTests {

    // MARK: Happy path

    /// Both directions of one untampered channel: each side verifies the other, and both agree on
    /// exactly the same transcript bytes.
    @Test func bothSidesVerifyEachOtherOverOneChannel() throws {
        let meshID = UUID()
        let alice = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "alice-sid")
        let bob = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "bob-sid")
        let run = try MeshIntroductionHarness.run(
            initiator: alice, responder: bob, roster: MeshIntroductionHarness.roster(alice, bob)
        )

        #expect(run.initiatorHelloRejection == nil)
        #expect(run.responderHelloRejection == nil)
        #expect(run.initiatorTranscript == run.responderTranscript, "both ends must sign identical bytes")
        #expect(run.responderOutcome?.verifiedPeer?.signingPublicKey == alice.publicKey)
        #expect(run.responderOutcome?.verifiedPeer?.sessionID == "alice-sid")
        #expect(run.initiatorOutcome?.verifiedPeer?.signingPublicKey == bob.publicKey)
        #expect(run.initiatorOutcome?.verifiedPeer?.sessionID == "bob-sid")
        #expect(
            run.initiatorOutcome?.verifiedPeer?.fingerprint == IdentityService.fingerprint(of: bob.publicKey)
        )
    }

    /// A peer being admitted holds no group key, so it presents no epoch. Requiring equality
    /// outright would make admission itself impossible — the joining side could never introduce
    /// itself to the mesh it is asking to join.
    ///
    /// Under the strict rule (plan §8.4, §20.1) this is no longer an empty-string *bypass*: the
    /// joiner goes through `MeshEpochAcceptance.introductionVerdict`, which admits it only because
    /// the keyed side's reference is itself a canonical `MeshEpochRef`.
    @Test func aPeerWithNoEpochYetIsAdmitted() throws {
        let meshID = UUID()
        let nine = MeshIntroductionHarness.epoch(9)
        let joiner = MeshIntroductionHarness.endpoint(meshID: meshID, epochRef: "", sessionID: "joiner")
        let member = MeshIntroductionHarness.endpoint(meshID: meshID, epochRef: nine, sessionID: "member")
        let run = try MeshIntroductionHarness.run(
            initiator: joiner, responder: member, roster: MeshIntroductionHarness.roster(joiner, member)
        )

        #expect(run.responderOutcome?.verifiedPeer?.signingPublicKey == joiner.publicKey)
        #expect(run.initiatorOutcome?.verifiedPeer?.signingPublicKey == member.publicKey)
        #expect(run.initiatorTranscript == run.responderTranscript)
        #expect(MeshChannelIntroductionExchange.agreedEpoch("", nine) == nine)
        #expect(MeshChannelIntroductionExchange.agreedEpoch(nine, "") == nine)
        // Two devices that hold no epoch at all still converge — on nothing.
        #expect(MeshChannelIntroductionExchange.epochsConverge("", ""))
        // The tightening: an empty side no longer waves through whatever the other side sent.
        #expect(!MeshChannelIntroductionExchange.epochsConverge("", "9"))
        #expect(!MeshChannelIntroductionExchange.epochsConverge("7", ""))
    }

    // MARK: Refusals

    /// A tampered or forged signature never verifies, and hands nothing onward.
    @Test func aBadSignatureIsRefusedAndLeaksNothing() throws {
        let meshID = UUID()
        let alice = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "alice-sid")
        let bob = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "bob-sid")
        var exchange = MeshChannelIntroductionExchange(role: .responder, localHello: bob.hello)
        var nonces = MeshIntroductionNonceCache()
        let helloRejection = exchange.receive(
            alice.hello, roster: MeshIntroductionHarness.roster(alice, bob), nonces: &nonces
        )
        #expect(helloRejection == nil)
        let bound = exchange.bind(channelBindingHash: MeshIntroductionHarness.binding)
        let transcript = try #require(bound)

        // Signed by a key that is not the one the hello claims.
        let impostor = Curve25519.Signing.PrivateKey()
        let forged = try MeshIntroductionHarness.introduction(
            over: transcript, binding: MeshIntroductionHarness.binding, by: impostor
        )
        #expect(exchange.review(forged) == .rejected(.signatureInvalid))
        #expect(exchange.review(forged).verifiedPeer == nil)

        // A single flipped byte in an otherwise valid signature.
        var bytes = [UInt8](try MeshIntroductionHarness.signature(over: transcript, by: alice.signingKey))
        bytes[0] ^= 0xFF
        let mangled = MeshChannelIntroduction(
            channelBindingHash: MeshIntroductionHarness.binding, signature: Data(bytes)
        )
        #expect(exchange.review(mangled) == .rejected(.signatureInvalid))
        #expect(exchange.review(mangled).verifiedPeer == nil)
    }

    /// A peer naming another mesh is refused before anything is signed, and the exchange keeps no
    /// hello — so there is no transcript to sign and no identity to hand onward.
    @Test func aForeignMeshIsRefusedAndLeavesNoTranscript() {
        let alice = MeshIntroductionHarness.endpoint(meshID: UUID(), sessionID: "alice-sid")
        let stranger = MeshIntroductionHarness.endpoint(meshID: UUID(), sessionID: "stranger-sid")
        var exchange = MeshChannelIntroductionExchange(role: .responder, localHello: alice.hello)
        var nonces = MeshIntroductionNonceCache()

        let rejection = exchange.receive(
            stranger.hello, roster: MeshIntroductionHarness.roster(alice, stranger), nonces: &nonces
        )

        let bound = exchange.bind(channelBindingHash: MeshIntroductionHarness.binding)
        #expect(rejection == .foreignMesh)
        #expect(bound == nil)
        #expect(exchange.derivedTranscript == nil)
    }

    /// Two peers each holding a DIFFERENT epoch are on diverged branches, and this side may not
    /// reconcile — `mayReconcileDivergentEpochs` is left at its **fail-closed default**, which is
    /// what a device holding no mesh or no ledger answers. The tunnel is refused and leaves nothing
    /// behind. (P4 item 3's opposite case, where the authority says a merge can run, is
    /// `MeshEpochReconciliationTests`.)
    @Test func aDivergentEpochIsRefusedAndLeavesNoTranscript() {
        let meshID = UUID()
        let four = MeshIntroductionHarness.epoch(4)
        let nine = MeshIntroductionHarness.epoch(9)
        let local = MeshIntroductionHarness.endpoint(meshID: meshID, epochRef: four, sessionID: "local")
        let peer = MeshIntroductionHarness.endpoint(meshID: meshID, epochRef: nine, sessionID: "peer")
        var exchange = MeshChannelIntroductionExchange(role: .initiator, localHello: local.hello)
        var nonces = MeshIntroductionNonceCache()

        let rejection = exchange.receive(
            peer.hello, roster: MeshIntroductionHarness.roster(local, peer), nonces: &nonces
        )

        let bound = exchange.bind(channelBindingHash: MeshIntroductionHarness.binding)
        #expect(rejection == .divergentEpoch)
        #expect(bound == nil)
        #expect(exchange.derivedTranscript == nil)
        #expect(!MeshChannelIntroductionExchange.epochsConverge(four, nine))
        #expect(MeshChannelIntroductionExchange.epochsConverge(four, four))
    }

    /// The tightening plan §20.1 asked for, on the axis a decimal counter could not express: two
    /// partitions that each rotated to counter 7 both used to send `"7"` and the gate agreed they
    /// matched. Same counter, different minting coordinator, is now SEEN — and, with no authority
    /// saying a merge can run, still refused.
    @Test func twoBranchesSharingACounterNoLongerLookEqual() {
        let meshID = UUID()
        let ours = MeshIntroductionHarness.epoch(7, coordinator: "00000000000000aa")
        let theirs = MeshIntroductionHarness.epoch(7, coordinator: "00000000000000bb")
        #expect(ours != theirs, "two branches at one counter must not share a canonical string")
        let local = MeshIntroductionHarness.endpoint(meshID: meshID, epochRef: ours, sessionID: "local")
        let peer = MeshIntroductionHarness.endpoint(meshID: meshID, epochRef: theirs, sessionID: "peer")
        var exchange = MeshChannelIntroductionExchange(role: .initiator, localHello: local.hello)
        var nonces = MeshIntroductionNonceCache()

        let rejection = exchange.receive(
            peer.hello, roster: MeshIntroductionHarness.roster(local, peer), nonces: &nonces
        )
        #expect(rejection == .divergentEpoch)
        #expect(exchange.derivedTranscript == nil)
    }

    /// A non-empty epoch reference that is not a canonical `MeshEpochRef` is a malformed hello —
    /// refused with the width checks, before any epoch is compared. Under the soft rule these all
    /// sailed through whenever the other side happened to hold no epoch.
    @Test func aNonCanonicalEpochReferenceIsAMalformedHello() {
        let meshID = UUID()
        let local = MeshIntroductionHarness.endpoint(meshID: meshID, epochRef: "", sessionID: "local")
        var nonces = MeshIntroductionNonceCache()

        for junk in ["7", "0007.deadbeef", "not-an-epoch", "\(MeshEpochBounds.counterCap + 1).x"] {
            let peer = MeshIntroductionHarness.endpoint(meshID: meshID, epochRef: junk, sessionID: "peer")
            var exchange = MeshChannelIntroductionExchange(role: .initiator, localHello: local.hello)
            let rejection = exchange.receive(
                peer.hello, roster: MeshIntroductionHarness.roster(local, peer), nonces: &nonces
            )
            #expect(rejection == .malformedHello, "\(junk) was not refused as malformed")
            #expect(exchange.derivedTranscript == nil)
        }
    }

    /// A peer the roster has never heard of is refused, whatever else it gets right.
    @Test func aRosterAbsentPeerIsRefusedAndLeavesNoTranscript() {
        let meshID = UUID()
        let local = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "local")
        let outsider = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "outsider")
        var exchange = MeshChannelIntroductionExchange(role: .responder, localHello: local.hello)
        var nonces = MeshIntroductionNonceCache()

        // Everything about the hello is well-formed and on-mesh; only membership is missing.
        let rejection = exchange.receive(
            outsider.hello, roster: MeshIntroductionHarness.roster(local), nonces: &nonces
        )

        let bound = exchange.bind(channelBindingHash: MeshIntroductionHarness.binding)
        #expect(rejection == .unknownIdentity)
        #expect(bound == nil)
        #expect(exchange.derivedTranscript == nil)
    }

    /// A departed, removed, revoked or blocked key is refused even while it is still on the member
    /// list — the removal that rotates the group key must already be enforced at the transport.
    @Test func aBarredMemberIsRefusedEvenWhileStillListed() {
        let meshID = UUID()
        let local = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "local")
        let removed = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "removed")
        var exchange = MeshChannelIntroductionExchange(role: .responder, localHello: local.hello)
        var nonces = MeshIntroductionNonceCache()

        let rejection = exchange.receive(
            removed.hello,
            roster: MeshIntroductionHarness.roster(local, removed, barred: [removed.publicKey]),
            nonces: &nonces
        )

        #expect(rejection == .barredMember)
        #expect(exchange.derivedTranscript == nil)
    }

    /// A nonce this session already accepted is a replay, and so is one that reflects this side's
    /// own — the two are the same attack from different directions.
    @Test func aReplayedOrReflectedNonceIsRefused() {
        let meshID = UUID()
        let local = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "local")
        let peer = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "peer")
        let roster = MeshIntroductionHarness.roster(local, peer)
        var nonces = MeshIntroductionNonceCache()

        var first = MeshChannelIntroductionExchange(role: .responder, localHello: local.hello)
        let accepted = first.receive(peer.hello, roster: roster, nonces: &nonces)
        #expect(accepted == nil)

        // The same peer re-introducing itself with the nonce this session already accepted.
        var replay = MeshChannelIntroductionExchange(role: .responder, localHello: local.hello)
        let replayed = replay.receive(peer.hello, roster: roster, nonces: &nonces)
        let replayBound = replay.bind(channelBindingHash: MeshIntroductionHarness.binding)
        #expect(replayed == .replayedNonce)
        #expect(replayBound == nil)
        #expect(replay.derivedTranscript == nil)

        // A peer echoing this side's own nonce back at it.
        let mirror = MeshIntroductionHarness.endpoint(
            meshID: meshID, sessionID: "mirror", nonce: local.hello.nonce
        )
        var reflected = MeshChannelIntroductionExchange(role: .responder, localHello: local.hello)
        let reflection = reflected.receive(
            mirror.hello, roster: MeshIntroductionHarness.roster(local, mirror), nonces: &nonces
        )
        #expect(reflection == .replayedNonce)
        #expect(reflected.derivedTranscript == nil)
    }

    /// The two ends of a tampered channel derive different exporter secrets, so neither accepts the
    /// other. Named separately from an invalid signature: "someone is between you" and "that peer
    /// signed badly" send a developer to completely different places.
    @Test func aTamperedChannelIsRefusedOnBothSides() throws {
        let meshID = UUID()
        let alice = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "alice-sid")
        let bob = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "bob-sid")

        let run = try MeshIntroductionHarness.run(
            initiator: alice,
            responder: bob,
            roster: MeshIntroductionHarness.roster(alice, bob),
            initiatorBinding: MeshIntroductionHarness.binding,
            responderBinding: MeshIntroductionHarness.otherBinding
        )

        #expect(run.initiatorTranscript != run.responderTranscript, "different channels, different bytes")
        #expect(run.initiatorOutcome == .rejected(.channelBindingMismatch))
        #expect(run.responderOutcome == .rejected(.channelBindingMismatch))
        #expect(run.initiatorOutcome?.verifiedPeer == nil)
        #expect(run.responderOutcome?.verifiedPeer == nil)
    }

    /// A peer that reports the right binding but signed under a different one still fails: the hash
    /// is inside the signed bytes, not merely beside them.
    @Test func aBindingThatOnlyLooksRightStillFailsTheSignature() throws {
        let meshID = UUID()
        let alice = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "alice-sid")
        let bob = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "bob-sid")
        var exchange = MeshChannelIntroductionExchange(role: .responder, localHello: bob.hello)
        var nonces = MeshIntroductionNonceCache()
        let localRejection = exchange.receive(
            alice.hello, roster: MeshIntroductionHarness.roster(alice, bob), nonces: &nonces
        )
        #expect(localRejection == nil)
        _ = exchange.bind(channelBindingHash: MeshIntroductionHarness.binding)

        var elsewhere = MeshChannelIntroductionExchange(role: .initiator, localHello: alice.hello)
        var otherNonces = MeshIntroductionNonceCache()
        let peerRejection = elsewhere.receive(
            bob.hello, roster: MeshIntroductionHarness.roster(alice, bob), nonces: &otherNonces
        )
        #expect(peerRejection == nil)
        let otherBound = elsewhere.bind(channelBindingHash: MeshIntroductionHarness.otherBinding)
        let otherTranscript = try #require(otherBound)
        let mismatched = MeshChannelIntroduction(
            channelBindingHash: MeshIntroductionHarness.binding,
            signature: try MeshIntroductionHarness.signature(over: otherTranscript, by: alice.signingKey)
        )

        #expect(exchange.review(mismatched) == .rejected(.signatureInvalid))
        #expect(exchange.review(mismatched).verifiedPeer == nil)
    }

    /// Width checks run first, on untrusted bytes, so no later step reasons about a short key.
    @Test func malformedFramesAreRefusedBeforeAnythingElse() {
        let meshID = UUID()
        let local = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "local")
        let peer = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "peer")
        var exchange = MeshChannelIntroductionExchange(role: .responder, localHello: local.hello)
        var nonces = MeshIntroductionNonceCache()

        let short = MeshChannelHello(
            protocolVersion: MeshChannelIntroductionFormat.protocolVersion,
            meshID: meshID,
            epochRef: MeshIntroductionHarness.epoch(7),
            signingPublicKey: Data(repeating: 3, count: 16),
            nonce: peer.hello.nonce,
            sessionID: "peer"
        )
        let shortRejection = exchange.receive(short, roster: .empty, nonces: &nonces)
        #expect(shortRejection == .malformedHello)
        let long = MeshChannelHello(
            protocolVersion: MeshChannelIntroductionFormat.protocolVersion,
            meshID: meshID,
            epochRef: String(repeating: "e", count: MeshChannelIntroductionFormat.maxEpochRefLength + 1),
            signingPublicKey: peer.publicKey,
            nonce: peer.hello.nonce,
            sessionID: "peer"
        )
        let longRejection = exchange.receive(long, roster: .empty, nonces: &nonces)
        #expect(longRejection == .malformedHello)

        let goodRejection = exchange.receive(
            peer.hello, roster: MeshIntroductionHarness.roster(local, peer), nonces: &nonces
        )
        #expect(goodRejection == nil)
        _ = exchange.bind(channelBindingHash: MeshIntroductionHarness.binding)
        let stub = MeshChannelIntroduction(
            channelBindingHash: MeshIntroductionHarness.binding, signature: Data(repeating: 9, count: 8)
        )
        #expect(exchange.review(stub) == .rejected(.malformedIntroduction))
    }

    /// Version, self-connection and caller-order faults each name themselves.
    @Test func theRemainingRefusalsEachNameThemselves() {
        let meshID = UUID()
        let local = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "local")
        var nonces = MeshIntroductionNonceCache()

        var versions = MeshChannelIntroductionExchange(role: .responder, localHello: local.hello)
        let future = MeshIntroductionHarness.endpoint(
            meshID: meshID, sessionID: "future",
            protocolVersion: MeshChannelIntroductionFormat.protocolVersion + 1
        )
        let versionRejection = versions.receive(
            future.hello, roster: MeshIntroductionHarness.roster(local, future), nonces: &nonces
        )
        #expect(versionRejection == .unsupportedProtocolVersion)

        var mirror = MeshChannelIntroductionExchange(role: .responder, localHello: local.hello)
        let echo = MeshChannelHello(
            protocolVersion: local.hello.protocolVersion,
            meshID: meshID,
            epochRef: local.hello.epochRef,
            signingPublicKey: local.publicKey,
            nonce: MeshChannelIntroductionFormat.randomNonce(),
            sessionID: "echo"
        )
        let echoRejection = mirror.receive(
            echo, roster: MeshIntroductionHarness.roster(local), nonces: &nonces
        )
        #expect(echoRejection == .selfIntroduction)

        let unarmed = MeshChannelIntroductionExchange(role: .initiator, localHello: local.hello)
        let stub = MeshChannelIntroduction(
            channelBindingHash: MeshIntroductionHarness.binding,
            signature: Data(repeating: 1, count: MeshChannelIntroductionFormat.signatureByteCount)
        )
        #expect(unarmed.review(stub) == .rejected(.missingPeerHello))

        for rejection: MeshIntroductionRejection in [
            .malformedHello, .unsupportedProtocolVersion, .foreignMesh, .divergentEpoch,
            .selfIntroduction, .replayedNonce, .unknownIdentity, .barredMember,
            .malformedIntroduction, .channelBindingMismatch, .signatureInvalid, .missingPeerHello
        ] {
            #expect(!rejection.diagnosticDescription.isEmpty)
        }
    }

    /// A binding of the wrong width is never signed over — the exchange refuses to produce bytes
    /// rather than committing to a value it cannot have derived from a real exporter.
    @Test func aMalformedBindingProducesNoTranscript() {
        let meshID = UUID()
        let local = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "local")
        let peer = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "peer")
        var exchange = MeshChannelIntroductionExchange(role: .responder, localHello: local.hello)
        var nonces = MeshIntroductionNonceCache()
        let rejection = exchange.receive(
            peer.hello, roster: MeshIntroductionHarness.roster(local, peer), nonces: &nonces
        )
        #expect(rejection == nil)

        let bound = exchange.bind(channelBindingHash: Data(repeating: 7, count: 8))
        #expect(bound == nil)
        #expect(exchange.derivedTranscript == nil)
    }

    // MARK: Provisional stranger admission (D-4.3 Option 1)

    /// Doors shut is the unchanged answer: a key nobody here knows is `unknownIdentity`, and the
    /// exchange keeps nothing — no transcript to sign, no identity to hand onward.
    ///
    /// `MeshIntroductionRoster.empty` and every roster built without the flag answer this way, which
    /// is the fail-closed direction the whole seam runs in: a transport that has not been told the
    /// join doors are open must refuse.
    @Test func aStrangerIsRefusedWhileTheJoinDoorsAreShut() {
        let meshID = UUID()
        let local = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "local")
        let stranger = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "stranger")
        var exchange = MeshChannelIntroductionExchange(role: .responder, localHello: local.hello)
        var nonces = MeshIntroductionNonceCache()

        let rejection = exchange.receive(
            stranger.hello, roster: MeshIntroductionHarness.roster(local), nonces: &nonces
        )
        let bound = exchange.bind(channelBindingHash: MeshIntroductionHarness.binding)

        #expect(rejection == .unknownIdentity)
        #expect(bound == nil, "a refused hello is not recorded, so there is nothing to sign")
        #expect(exchange.derivedTranscript == nil)
        #expect(!MeshIntroductionRoster.empty.admitsStrangersProvisionally,
                "the empty roster keeps the doors shut, or a transport with no owner admits everyone")
        #expect(!MeshIntroductionHarness.roster(local).admitsStrangersProvisionally,
                "and so does every roster built without the flag")
    }

    /// Doors open: the same stranger's exchange PROCEEDS — and still has to prove it holds the key
    /// it presented. Provisional is a tunnel, not a pass.
    @Test func aStrangerIntroducesWhileTheDoorsAreOpenAndStillProvesItsKey() throws {
        let meshID = UUID()
        let local = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "local")
        let stranger = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "stranger")
        let open = MeshIntroductionHarness.roster(local, doorsOpen: true)
        var exchange = MeshChannelIntroductionExchange(role: .responder, localHello: local.hello)
        var nonces = MeshIntroductionNonceCache()

        let admitted = exchange.receive(stranger.hello, roster: open, nonces: &nonces)
        #expect(admitted == nil)
        let bound = exchange.bind(channelBindingHash: MeshIntroductionHarness.binding)
        let transcript = try #require(bound)

        // Somebody else's signature over the right bytes is still nobody.
        let impostor = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "impostor")
        let forged = try MeshIntroductionHarness.introduction(
            over: transcript, binding: MeshIntroductionHarness.binding, by: impostor.signingKey
        )
        #expect(exchange.review(forged) == .rejected(.signatureInvalid),
                "review still verifies against the hello's key — the open doors moved no signature check")
        #expect(exchange.review(forged).verifiedPeer == nil,
                "and a rejected review hands nothing onward")

        let honest = try MeshIntroductionHarness.introduction(
            over: transcript, binding: MeshIntroductionHarness.binding, by: stranger.signingKey
        )
        let outcome = exchange.review(honest)
        #expect(outcome.verifiedPeer?.signingPublicKey == stranger.publicKey)
        #expect(outcome.verifiedPeer?.sessionID == "stranger")
    }

    /// `barred` is tested first and the open doors cannot reach it. A departed, removed, revoked or
    /// blocked key is refused by name with the doors wide open — which is what the rotation that
    /// follows a removal assumes.
    @Test func barredBeatsProvisionalAdmission() {
        let meshID = UUID()
        let local = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "local")
        let removed = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "removed")
        var exchange = MeshChannelIntroductionExchange(role: .responder, localHello: local.hello)
        var nonces = MeshIntroductionNonceCache()

        let rejection = exchange.receive(
            removed.hello,
            roster: MeshIntroductionHarness.roster(local, barred: [removed.publicKey], doorsOpen: true),
            nonces: &nonces
        )

        let bound = exchange.bind(channelBindingHash: MeshIntroductionHarness.binding)
        #expect(rejection == .barredMember)
        #expect(bound == nil, "and it kept nothing, exactly as a shut-doors refusal does")

        // A barred key naming ANOTHER mesh is refused too — the mesh-id tolerance is for strangers
        // alone, so this one never reaches the barred arm and dies one guard earlier. Both answers
        // are refusals; which one it is, is the diagnostic.
        var foreign = MeshChannelIntroductionExchange(role: .responder, localHello: local.hello)
        let elsewhere = MeshIntroductionHarness.endpoint(meshID: UUID(), sessionID: "elsewhere")
        let foreignRejection = foreign.receive(
            elsewhere.hello,
            roster: MeshIntroductionHarness.roster(local, barred: [elsewhere.publicKey], doorsOpen: true),
            nonces: &nonces
        )
        #expect(foreignRejection == .foreignMesh)
        #expect(foreign.derivedTranscript == nil)
    }

    /// The first meeting the equality rule used to make impossible: a device with **no mesh** —
    /// which can only send the all-zero `unboundMeshID` — dials an established OPEN mesh.
    ///
    /// Both ends see a stranger and both have their doors open, so both tolerate the mismatch, and
    /// the transcript takes the RESPONDER's id on both sides. Without that last rule each end would
    /// sign different bytes and the meeting would fail as `signatureInvalid` instead.
    @Test func aMeshlessDialerIntroducesToAnOpenMesh() throws {
        let hostMesh = UUID()
        let unbound = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        let joiner = MeshIntroductionHarness.endpoint(meshID: unbound, epochRef: "", sessionID: "joiner")
        let host = MeshIntroductionHarness.endpoint(meshID: hostMesh, sessionID: "host")

        let run = try MeshIntroductionHarness.run(
            initiator: joiner, responder: host,
            roster: MeshIntroductionHarness.roster(host, doorsOpen: true),
            initiatorRoster: MeshIntroductionHarness.roster(doorsOpen: true)
        )

        #expect(run.initiatorHelloRejection == nil, "the joiner admits the host it dialed")
        #expect(run.responderHelloRejection == nil, "and the host admits the stranger asking in")
        #expect(run.initiatorTranscript == run.responderTranscript, "both ends must sign identical bytes")
        #expect(run.initiator.derivedTranscript?.meshID == hostMesh,
                "the transcript names the mesh being asked INTO, on both sides")
        #expect(run.responder.derivedTranscript?.meshID == hostMesh)
        #expect(run.responderOutcome?.verifiedPeer?.signingPublicKey == joiner.publicKey)
        #expect(run.initiatorOutcome?.verifiedPeer?.signingPublicKey == host.publicKey)
    }

    /// The double mint, which on this radio was a DEADLOCK rather than a nuisance: both halves of a
    /// founding pair mint their own `meshID` at their own first commit, and with no MC radio left to
    /// repair it, an unconditional equality check refused every re-dial for the rest of the session.
    ///
    /// Each side's one-member roster makes the other a stranger, so the tolerance covers it with no
    /// newborn-specific arm at all.
    @Test func twoNewbornFoundersEachHoldingTheirOwnMeshIDStillIntroduce() throws {
        let alice = MeshIntroductionHarness.endpoint(meshID: UUID(), sessionID: "alice")
        let bob = MeshIntroductionHarness.endpoint(meshID: UUID(), sessionID: "bob")

        let run = try MeshIntroductionHarness.run(
            initiator: alice, responder: bob,
            roster: MeshIntroductionHarness.roster(bob, doorsOpen: true),
            initiatorRoster: MeshIntroductionHarness.roster(alice, doorsOpen: true)
        )

        #expect(run.initiatorHelloRejection == nil)
        #expect(run.responderHelloRejection == nil)
        #expect(run.initiatorTranscript == run.responderTranscript)
        #expect(run.initiator.derivedTranscript?.meshID == bob.hello.meshID,
                "the responder's id, deterministically, so the two derivations agree")
        #expect(run.responderOutcome?.verifiedPeer?.signingPublicKey == alice.publicKey)
        #expect(run.initiatorOutcome?.verifiedPeer?.signingPublicKey == bob.publicKey)

        // With the doors SHUT the same pair is refused at the roster, not at the mesh id: the
        // tolerance and the admission are one decision, so neither survives the other.
        let shut = try MeshIntroductionHarness.run(
            initiator: alice, responder: bob,
            roster: MeshIntroductionHarness.roster(bob),
            initiatorRoster: MeshIntroductionHarness.roster(alice)
        )
        #expect(shut.responderHelloRejection == .foreignMesh)
    }

    /// A key this roster NAMES, arriving under another mesh's id, is still `foreignMesh`. The
    /// tolerance is for a peer asking its way in, never for a member claiming to be somewhere else —
    /// that is a branch this tunnel must not join, and plan §7.2's bullet is untouched for it.
    @Test func twoMembersOfDifferentMeshesAreStillForeignMesh() throws {
        let alice = MeshIntroductionHarness.endpoint(meshID: UUID(), sessionID: "alice")
        let bob = MeshIntroductionHarness.endpoint(meshID: UUID(), sessionID: "bob")
        let bothNamed = MeshIntroductionHarness.roster(alice, bob, doorsOpen: true)

        let run = try MeshIntroductionHarness.run(initiator: alice, responder: bob, roster: bothNamed)

        #expect(run.responderHelloRejection == .foreignMesh)
        #expect(run.initiatorHelloRejection == .foreignMesh)
        #expect(run.responder.derivedTranscript == nil, "and neither side kept anything")
        #expect(run.initiator.derivedTranscript == nil)
    }

    /// The transcript's mesh-id rule, stated on its own: the responder's, always, whichever way the
    /// two hellos disagree — and identical to the old answer whenever they agree, which is why no
    /// existing golden moves.
    @Test func theTranscriptTakesTheRespondersMeshID() {
        let dialed = UUID()
        let dialer = UUID()
        #expect(MeshChannelIntroductionExchange.agreedMeshID(dialer, dialed) == dialed)
        #expect(MeshChannelIntroductionExchange.agreedMeshID(dialed, dialed) == dialed,
                "equal ids are the only case that could exist before D-4.3, and it is unchanged")
        #expect(MeshChannelIntroductionExchange.agreedMeshID(dialed, dialer) == dialer)
    }
}

// MARK: - MeshChannelIntroductionTranscriptTests

/// The bytes both peers sign: their layout, and that every field in them is load-bearing.
@Suite(.serialized)
struct MeshChannelIntroductionTranscriptTests {

    static func transcript(
        protocolVersion: Int = MeshChannelIntroductionFormat.protocolVersion,
        meshID: UUID = UUID(uuidString: "00000000-0000-0000-0000-0000000000AA") ?? UUID(),
        epochRef: String = "7",
        initiatorSigningPublicKey: Data = Data(repeating: 1, count: 32),
        responderSigningPublicKey: Data = Data(repeating: 2, count: 32),
        initiatorNonce: Data = Data(repeating: 3, count: 16),
        responderNonce: Data = Data(repeating: 4, count: 16),
        channelBindingHash: Data = Data(repeating: 5, count: 32)
    ) -> MeshChannelIntroductionTranscript {
        MeshChannelIntroductionTranscript(
            protocolVersion: protocolVersion,
            meshID: meshID,
            epochRef: epochRef,
            initiatorSigningPublicKey: initiatorSigningPublicKey,
            responderSigningPublicKey: responderSigningPublicKey,
            initiatorNonce: initiatorNonce,
            responderNonce: responderNonce,
            channelBindingHash: channelBindingHash
        )
    }

    /// Changing any field changes the bytes. A field that did not would be a field the signature
    /// does not actually cover — which is how "the epoch is bound into the transcript" becomes a
    /// comment rather than a property.
    @Test func everyTranscriptFieldReachesTheSignedBytes() {
        let base = canonicalBytes(for: Self.transcript())
        let variants: [String: MeshChannelIntroductionTranscript] = [
            "protocolVersion": Self.transcript(protocolVersion: 2),
            "meshID": Self.transcript(meshID: UUID()),
            "epochRef": Self.transcript(epochRef: "8"),
            "initiatorSigningPublicKey": Self.transcript(initiatorSigningPublicKey: Data(repeating: 9, count: 32)),
            "responderSigningPublicKey": Self.transcript(responderSigningPublicKey: Data(repeating: 9, count: 32)),
            "initiatorNonce": Self.transcript(initiatorNonce: Data(repeating: 9, count: 16)),
            "responderNonce": Self.transcript(responderNonce: Data(repeating: 9, count: 16)),
            "channelBindingHash": Self.transcript(channelBindingHash: Data(repeating: 9, count: 32))
        ]
        for (field, variant) in variants {
            #expect(canonicalBytes(for: variant) != base, "\(field) does not reach the signed bytes")
        }
    }

    /// Swapping the two roles produces different bytes, which is what makes "who dialed whom" part
    /// of the signature rather than a convention the two ends have to agree on separately.
    @Test func theRolesAreNotInterchangeable() {
        let forward = Self.transcript()
        let swapped = Self.transcript(
            initiatorSigningPublicKey: forward.responderSigningPublicKey,
            responderSigningPublicKey: forward.initiatorSigningPublicKey,
            initiatorNonce: forward.responderNonce,
            responderNonce: forward.initiatorNonce
        )
        #expect(canonicalBytes(for: forward) != canonicalBytes(for: swapped))
    }

    /// The transcript begins with the domain as a length-prefixed field, in plan §7.2's order, and
    /// the domain is the production spelling — never the DEBUG probe's.
    @Test func theTranscriptOpensWithItsLengthPrefixedDomain() {
        let purpose = ProximityNamespace.packageTest.family.purposes.signature.meshChannelIntroductionV1
        let bytes = canonicalBytes(for: Self.transcript())
        let expectedCount = Data([0, 0, 0, 0, 0, 0, 0, UInt8(purpose.data.count)])

        #expect(bytes.starts(with: expectedCount + purpose.data))
        #expect(purpose.signingBytes(bytes) != nil)
        #expect(!purpose.rawValue.contains(".probe."))
    }
}

// MARK: - MeshIntroductionRosterTests

/// Who the introduction is judged against: bounded, and fail-closed where the two lists overlap.
@Suite(.serialized)
struct MeshIntroductionRosterTests {

    static func key(_ byte: UInt8) -> Data { Data(repeating: byte, count: 32) }

    @Test func aMemberIsAdmittedAndAStrangerIsNot() {
        let roster = MeshIntroductionRoster(members: [Self.key(1), Self.key(2)])
        #expect(roster.verdict(for: Self.key(1)) == .member)
        #expect(roster.verdict(for: Self.key(3)) == .stranger)
        #expect(MeshIntroductionRoster.empty.verdict(for: Self.key(1)) == .stranger)
    }

    /// A key on both lists is barred. A removal that raced an admission must not be resolved in the
    /// removed member's favour — the rotation that follows a removal assumes exactly this.
    @Test func barredWinsOverMember() {
        let roster = MeshIntroductionRoster(members: [Self.key(1)], barred: [Self.key(1)])
        #expect(roster.verdict(for: Self.key(1)) == .barred)
    }

    @Test func bothListsAreBoundedByConstruction() {
        let members = (0..<UInt8(MeshIntroductionRoster.maxMembers + 4)).map(Self.key)
        let barred = (100..<UInt8(100 + MeshIntroductionRoster.maxBarred + 4)).map(Self.key)
        let roster = MeshIntroductionRoster(members: members, barred: barred)
        #expect(roster.memberCount == MeshIntroductionRoster.maxMembers)
        #expect(roster.barredCount == MeshIntroductionRoster.maxBarred)
    }

    /// The posture bit defaults shut and changes no verdict (D-4.3 Option 1). It says whether a
    /// `stranger` may hold a tunnel, never who is a stranger — so a member stays a member, a barred
    /// key stays barred, and a caller that never heard of the flag keeps the old behaviour exactly.
    @Test func theProvisionalFlagDefaultsShutAndMovesNoVerdict() {
        let shut = MeshIntroductionRoster(members: [Self.key(1)], barred: [Self.key(2)])
        #expect(!shut.admitsStrangersProvisionally)
        #expect(!MeshIntroductionRoster.empty.admitsStrangersProvisionally)

        let open = MeshIntroductionRoster(
            members: [Self.key(1)], barred: [Self.key(2)], admitsStrangersProvisionally: true
        )
        #expect(open.admitsStrangersProvisionally)
        for byte: UInt8 in [1, 2, 3] {
            #expect(open.verdict(for: Self.key(byte)) == shut.verdict(for: Self.key(byte)),
                    "the flag is posture, not membership: key \(byte) verdicts the same either way")
        }
        #expect(open.verdict(for: Self.key(3)) == .stranger, "and a stranger is still named one")
    }
}

// MARK: - MeshIntroductionNonceCacheTests

/// The replay cache: what it refuses, and exactly how far its bound reaches.
@Suite(.serialized)
struct MeshIntroductionNonceCacheTests {

    @Test func aSecondSightingOfANonceIsRefused() {
        var cache = MeshIntroductionNonceCache()
        let nonce = MeshChannelIntroductionFormat.randomNonce()
        let firstAdmit = cache.admit(nonce)
        let secondAdmit = cache.admit(nonce)
        let otherAdmit = cache.admit(MeshChannelIntroductionFormat.randomNonce())
        #expect(firstAdmit)
        #expect(!secondAdmit)
        #expect(otherAdmit)
        #expect(cache.trackedCount == 2)
    }

    /// Bounded oldest-first. The evicted nonce becomes admissible again — which is safe only
    /// because the exporter binding, not the nonce, is what makes a cross-tunnel replay useless.
    @Test func theCacheIsBoundedOldestFirst() {
        var cache = MeshIntroductionNonceCache()
        let first = MeshChannelIntroductionFormat.randomNonce()
        let seeded = cache.admit(first)
        #expect(seeded)
        var everyFillAdmitted = true
        for _ in 0..<MeshIntroductionNonceCache.maxTrackedNonces {
            everyFillAdmitted = cache.admit(MeshChannelIntroductionFormat.randomNonce()) && everyFillAdmitted
        }
        #expect(everyFillAdmitted)
        #expect(cache.trackedCount == MeshIntroductionNonceCache.maxTrackedNonces)
        let readmitted = cache.admit(first)
        #expect(readmitted, "the oldest nonce should have been evicted")

        cache.removeAll()
        #expect(cache.trackedCount == 0)
    }

    /// Nonces are 16 bytes of platform CSPRNG output — distinct in practice, which is what makes the
    /// cache a replay check rather than a collision generator.
    @Test func nonceMintingIsTheRightWidthAndDoesNotRepeat() {
        var seen: Set<Data> = []
        for _ in 0..<64 {
            let nonce = MeshChannelIntroductionFormat.randomNonce()
            #expect(nonce.count == MeshChannelIntroductionFormat.nonceByteCount)
            seen.insert(nonce)
        }
        #expect(seen.count == 64)
    }
}

// MARK: - MeshInboundRankingTests

/// Item 5's named residual, closed: an inbound tunnel is ranked once the introduction has named its
/// peer, so duplicate-tunnel suppression makes a real decision instead of falling through to
/// ``MeshDialPreference/unranked``.
@MainActor
@Suite(.serialized)
struct MeshInboundRankingTests {

    static func table(withBrowsed sessionID: String, as key: MeshLinkKey, at now: Date) -> MeshLinkTable {
        var table = MeshLinkTable()
        table.remember(MeshEndpointRecord(
            key: key,
            instanceName: "fernlet-mesh-abcdef123456",
            advertisement: [MeshLinkAdvertisement.sessionIDKey: sessionID, "meshName": "Quiet Fern"],
            lastSeenAt: now
        ))
        return table
    }

    /// The verified `sid` resolves an inbound connection to the browsed advertisement it came from.
    /// Without it the two are a host/port and a Bonjour instance, with nothing in common.
    @Test func aVerifiedSessionIDResolvesToTheBrowsedEndpoint() {
        let clock = VirtualClock()
        let browsed = MeshLinkKey("browsed-endpoint")
        let table = Self.table(withBrowsed: "peer-sid", as: browsed, at: clock.now)

        #expect(table.key(advertisingSessionID: "peer-sid") == browsed)
        #expect(table.key(advertisingSessionID: "someone-else") == nil)
        #expect(table.key(advertisingSessionID: "") == nil, "an absent id must never match an endpoint")
    }

    /// The pair that used to end with two tunnels now ends with one: this side is mid-dial, the peer
    /// outranks it, and the inbound tunnel is admitted onto the SAME key the dial is using.
    @Test func aRankedInboundTunnelCollidesWithTheOutboundDial() {
        let clock = VirtualClock()
        let browsed = MeshLinkKey("browsed-endpoint")
        var table = Self.table(withBrowsed: "zzzz", as: browsed, at: clock.now)
        let dialAdmission = table.admitDial(to: browsed, now: clock.now)
        #expect(dialAdmission == .admit)
        #expect(table.phase(of: browsed) == .dialing)

        // The peer's sid outranks the local one, so the peer is the designated dialer.
        let resolved = table.key(advertisingSessionID: "zzzz")
        #expect(resolved == browsed)
        #expect(MeshDialPreference.rank(localSessionID: "aaaa", peerSessionID: "zzzz") == .peerDials)
        let inboundAdmission = table.admitInbound(
            from: browsed, localSessionID: "aaaa", peerSessionID: "zzzz", now: clock.now
        )
        #expect(inboundAdmission == .admit)
        #expect(table.phase(of: browsed) == .connected)
        #expect(table.occupiedSlotCount == 1, "the inbound tunnel reuses the dialing slot, never a second one")
    }

    /// The other direction: this side outranks the peer, so its own dial survives and the inbound
    /// tunnel is refused as the duplicate it is. Under `unranked` this case admitted both.
    @Test func theOutrankingDialerKeepsItsOwnTunnel() {
        let clock = VirtualClock()
        let browsed = MeshLinkKey("browsed-endpoint")
        var table = Self.table(withBrowsed: "aaaa", as: browsed, at: clock.now)
        _ = table.admitDial(to: browsed, now: clock.now)

        #expect(MeshDialPreference.rank(localSessionID: "zzzz", peerSessionID: "aaaa") == .localDials)
        let refusal = table.admitInbound(
            from: browsed, localSessionID: "zzzz", peerSessionID: "aaaa", now: clock.now
        )
        #expect(refusal == .refusedDuplicateTunnel(.dialing))
        #expect(table.phase(of: browsed) == .dialing)
    }

    /// A peer this side never browsed keeps its own connection key, and is still admitted — an
    /// inbound tunnel from an un-browsed member is normal, not suspicious.
    @Test func anUnbrowsedPeerKeepsItsConnectionKey() {
        let clock = VirtualClock()
        var table = MeshLinkTable()
        let connectionKey = MeshLinkKey("quic-connection-1")

        #expect(table.key(advertisingSessionID: "peer-sid") == nil)
        let admission = table.admitInbound(
            from: connectionKey, localSessionID: "aaaa", peerSessionID: "peer-sid", now: clock.now
        )
        #expect(admission == .admit)
        #expect(table.phase(of: connectionKey) == .connected)
    }
}

// MARK: - MeshTunnelConvergenceTests

/// P2 item 13: a verified pair must converge to exactly ONE tunnel — and to the *same* one on both
/// sides.
///
/// The defect these pin was found on the radio, not here: two Simulators running the production mesh
/// over QUIC each logged `tunnel activated` twice for one peer. The chain is three documented,
/// individually-correct behaviours meeting: in the pre-TXT window neither side can rank the other so
/// **both dial** (the deadlock-avoiding fallback ``MeshDialPreference`` exists for); an inbound
/// tunnel whose verified `sid` still matches no cached advertisement keeps its own connection key;
/// and two keys never collide, so ``MeshLinkTable``'s duplicate suppression is never asked. The pair
/// stayed selective — both tunnels were verified — and stopped converging.
///
/// Nothing here sleeps or opens a socket. The rule is a pure function, and the session's half is
/// driven through the same functions the radio calls.
@MainActor
@Suite(.serialized)
struct MeshTunnelConvergenceTests {

    // MARK: The rule

    /// **The property the whole item exists for.** Over every pair of session ids two real devices
    /// could hold, both ends keep the same connection — and neither ends with none.
    ///
    /// Read the two sides as one wire: connection A→B is A's ``MeshChannelRole/initiator`` tunnel
    /// and B's ``MeshChannelRole/responder`` tunnel; B→A is the mirror. A verdict pair is correct
    /// only when the tunnel A keeps and the tunnel B keeps name the *same* connection — that is,
    /// exactly one of the two sides keeps its own dial.
    @Test func bothSidesOfAMutuallyDialedPairKeepTheSameConnection() {
        let ids = ["aaaa", "mmmm", "zzzz"]
        for local in ids {
            for peer in ids where peer != local {
                let localKeepsOwnDial = Self.keepsOwnDial(localSessionID: local, peerSessionID: peer)
                let peerKeepsOwnDial = Self.keepsOwnDial(localSessionID: peer, peerSessionID: local)
                #expect(
                    localKeepsOwnDial != peerKeepsOwnDial,
                    "local=\(local) peer=\(peer): the two sides did not name one connection"
                )
            }
        }
    }

    /// Whether this side keeps its own dial — asked BOTH ways round, because which tunnel activated
    /// second is a race and the verdict must not depend on it. The equality is the race-safety
    /// property, asserted on every input the callers above enumerate.
    static func keepsOwnDial(localSessionID: String, peerSessionID: String) -> Bool {
        let peerDialArrivedSecond = MeshTunnelConvergence.resolve(
            incomingRole: .responder, establishedRole: .initiator,
            localSessionID: localSessionID, peerSessionID: peerSessionID
        )
        let ownDialArrivedSecond = MeshTunnelConvergence.resolve(
            incomingRole: .initiator, establishedRole: .responder,
            localSessionID: localSessionID, peerSessionID: peerSessionID
        )
        #expect(
            (peerDialArrivedSecond == .keepEstablished) == (ownDialArrivedSecond == .keepIncoming),
            "the verdict changed with activation order — a race would leave the pair disagreeing"
        )
        return peerDialArrivedSecond == .keepEstablished
    }

    /// The survivor is always the connection the *preferred dialer* opened — the same `sid`
    /// comparison `MeshNetworkManager.shouldInitiateInvite` and ``MeshDialPreference`` make, so the
    /// transport can never collapse onto the direction the manager would not have dialed.
    @Test func theSurvivorIsTheConnectionThePreferredDialerOpened() {
        for (local, peer) in [("zzzz", "aaaa"), ("aaaa", "zzzz"), ("mmmm", "aaaa")] {
            let preference = MeshDialPreference.rank(localSessionID: local, peerSessionID: peer)
            #expect(Self.keepsOwnDial(localSessionID: local, peerSessionID: peer)
                    == (preference == .localDials),
                    "local=\(local) peer=\(peer): the collapse and the dial tie-break disagree")
        }
    }

    /// An unranked pair keeps BOTH. Ranking fails only for this process's own echo or a session
    /// advertising no `sid`; inventing a tie-break there risks the one outcome — zero tunnels — that
    /// no timer-free path recovers from.
    @Test func anUnrankedPairKeepsBothRatherThanRiskingNone() {
        let roles: [(MeshChannelRole, MeshChannelRole)] = [
            (.initiator, .responder), (.responder, .initiator),
            (.initiator, .initiator), (.responder, .responder)
        ]
        for (local, peer) in [("", "aaaa"), ("aaaa", ""), ("same", "same"), ("", "")] {
            for (incoming, established) in roles {
                #expect(MeshTunnelConvergence.resolve(
                    incomingRole: incoming, establishedRole: established,
                    localSessionID: local, peerSessionID: peer
                ) == .keepBoth, "local=\(local) peer=\(peer) closed a tunnel it cannot rank")
            }
        }
    }

    /// Two tunnels in the SAME direction have no symmetric discriminator — direction is the only
    /// fact both ends name identically — so the established one stays and the newcomer yields. It
    /// still converges: the connection this side closes is closed at the peer's end too.
    @Test func aSameDirectionDuplicateKeepsTheEstablishedTunnel() {
        for role in [MeshChannelRole.initiator, .responder] {
            for (local, peer) in [("zzzz", "aaaa"), ("aaaa", "zzzz")] {
                #expect(MeshTunnelConvergence.resolve(
                    incomingRole: role, establishedRole: role,
                    localSessionID: local, peerSessionID: peer
                ) == .keepEstablished)
            }
        }
    }

    /// The close names itself. A collapsed duplicate and a refused peer are two different events,
    /// and a log that spells them the same way is how a healthy radio reads as a hostile one.
    @Test func theDedupCloseNamesItselfRatherThanLookingLikeARefusal() {
        #expect(MeshTunnelConvergence.closeReason.hasPrefix("redundantTunnelClosed"))
        #expect(!MeshTunnelConvergence.closeReason.lowercased().contains("refus"))
    }

    // MARK: The session

    /// One peer's verified identity. The keys are the durable half — the collapse matches on the
    /// signing key, never on the fingerprint string or the per-launch `sid`.
    static let peerSigningKey = Data(repeating: 0x11, count: 32)
    static let otherSigningKey = Data(repeating: 0x22, count: 32)

    static func verified(
        _ signingPublicKey: Data,
        sessionID: String,
        fingerprint: String = "abcd-efgh-ijkl"
    ) -> MeshVerifiedPeer {
        MeshVerifiedPeer(
            signingPublicKey: signingPublicKey, fingerprint: fingerprint, sessionID: sessionID
        )
    }

    /// A stopped session advertising `sessionID`. `updateDiscoveryInfo` is production API and a
    /// documented no-op for the radios while stopped, so giving a session its own `sid` needs no seam.
    static func session(advertising sessionID: String) -> NetworkMeshSession {
        let session = NetworkMeshSession()
        session.updateDiscoveryInfo([MeshLinkAdvertisement.sessionIDKey: sessionID])
        session.invitationGate = { _ in true }
        return session
    }

    /// **The item-9 repro.** Both sides dialed, both verified, and the peer's tunnel landed under
    /// its own connection key because no cached advertisement carried its `sid` yet — the state two
    /// Simulators were in when each logged `accepted … tunnel activated` twice.
    ///
    /// Also the budget and owner-path assertions: a dedup close returns the link to
    /// ``MeshLinkPhase/idle`` with a FULL dial budget (a dial-failure charge would have left it
    /// backing off or exhausted), fires no `onPeerDisconnected`, and is not a transport error.
    @Test func aMutuallyDialedPairConvergesToOneTunnel() {
        let session = Self.session(advertising: "zzzz")
        var disconnects: [String] = []
        var errors: [String] = []
        session.onPeerDisconnected = { _, reason in disconnects.append(reason) }
        session.onTransportError = { errors.append($0) }
        let peer = Self.verified(Self.peerSigningKey, sessionID: "aaaa")
        let ownDial = MeshLinkKey("browsed-endpoint")
        let peerDial = MeshLinkKey("quic-connection-1")

        session.bookTunnelForTesting(ownDial, role: .initiator, verified: peer)
        // The peer's connection, through the production admission: unresolvable to any browsed
        // advertisement, so it keeps its own key and collides with nothing.
        #expect(session.admitVerifiedInboundForTesting(peer, pendingKey: peerDial) == peerDial)
        session.bookTunnelForTesting(peerDial, role: .responder, verified: nil)
        #expect(session.tunnelKeysForTesting.count == 2, "the pre-fix state: one peer, two tunnels")
        #expect(session.linkTableForTesting.phase(of: peerDial) == .connected)

        // "zzzz" > "aaaa": this side is the preferred dialer, so its own dial is the survivor.
        #expect(!session.admitActivationForTesting(at: peerDial, role: .responder, verified: peer))

        #expect(session.tunnelKeysForTesting == [ownDial])
        #expect(session.linkTableForTesting.connectedCount == 1)
        #expect(session.linkTableForTesting.phase(of: ownDial) == .connected)
        #expect(session.linkTableForTesting.phase(of: peerDial) == .idle,
                "a dedup close is not a dial failure")
        #expect(session.linkTableForTesting.dialAttempts(for: peerDial) == 0,
                "a dedup close must not spend the three-attempt dial budget")
        #expect(disconnects.isEmpty, "a dedup close must not re-enter the owner's removal funnel")
        #expect(errors.isEmpty, "a dedup close is not a transport error")
    }

    /// Both devices, one wire. The tunnel each side keeps must be the same connection — the whole
    /// reason the rule ranks instead of letting each side prefer its own dial.
    @Test func bothSessionsKeepOneConnectionBetweenThem() {
        let alpha = Self.session(advertising: "zzzz")
        let bravo = Self.session(advertising: "aaaa")
        let bravoSeenByAlpha = Self.verified(Self.peerSigningKey, sessionID: "aaaa")
        let alphaSeenByBravo = Self.verified(Self.otherSigningKey, sessionID: "zzzz")

        let alphaOwn = MeshLinkKey("alpha-dialed-bravo")
        let alphaInbound = MeshLinkKey("alpha-conn-1")
        alpha.bookTunnelForTesting(alphaOwn, role: .initiator, verified: bravoSeenByAlpha)
        _ = alpha.admitVerifiedInboundForTesting(bravoSeenByAlpha, pendingKey: alphaInbound)
        alpha.bookTunnelForTesting(alphaInbound, role: .responder, verified: nil)
        let alphaKeepsPeerDial = alpha.admitActivationForTesting(
            at: alphaInbound, role: .responder, verified: bravoSeenByAlpha
        )

        let bravoOwn = MeshLinkKey("bravo-dialed-alpha")
        let bravoInbound = MeshLinkKey("bravo-conn-1")
        bravo.bookTunnelForTesting(bravoOwn, role: .initiator, verified: alphaSeenByBravo)
        _ = bravo.admitVerifiedInboundForTesting(alphaSeenByBravo, pendingKey: bravoInbound)
        bravo.bookTunnelForTesting(bravoInbound, role: .responder, verified: nil)
        let bravoKeepsPeerDial = bravo.admitActivationForTesting(
            at: bravoInbound, role: .responder, verified: alphaSeenByBravo
        )

        #expect(alpha.tunnelKeysForTesting == [alphaOwn], "alpha holds the higher sid: its dial wins")
        #expect(bravo.tunnelKeysForTesting == [bravoInbound], "bravo keeps the tunnel alpha opened")
        #expect(!alphaKeepsPeerDial)
        #expect(bravoKeepsPeerDial)
        #expect(alpha.linkTableForTesting.connectedCount == 1)
        #expect(bravo.linkTableForTesting.connectedCount == 1)
    }

    /// **The simultaneous case.** Either connection may activate first on either side, and both
    /// sides may act at once. The verdict depends on no ordering, so the same connection survives
    /// either way — and a second pass over the loser (two callbacks racing) changes nothing.
    @Test func theCollapseIsIndependentOfWhichTunnelActivatedFirst() {
        for peerDialActivatedFirst in [true, false] {
            let session = Self.session(advertising: "zzzz")
            let peer = Self.verified(Self.peerSigningKey, sessionID: "aaaa")
            let ownDial = MeshLinkKey("browsed-endpoint")
            let peerDial = MeshLinkKey("quic-connection-1")
            let first = peerDialActivatedFirst ? peerDial : ownDial
            let firstRole: MeshChannelRole = peerDialActivatedFirst ? .responder : .initiator
            let second = peerDialActivatedFirst ? ownDial : peerDial
            let secondRole: MeshChannelRole = peerDialActivatedFirst ? .initiator : .responder

            session.bookTunnelForTesting(first, role: firstRole, verified: peer)
            session.bookTunnelForTesting(second, role: secondRole, verified: nil)
            let admitted = session.admitActivationForTesting(
                at: second, role: secondRole, verified: peer
            )
            // What `activate` records next, and the reason the re-check below is meaningful: the
            // survivor is only recognisable as this peer's once its verified identity is on it.
            if admitted { session.bookTunnelForTesting(second, role: secondRole, verified: peer) }

            #expect(admitted == peerDialActivatedFirst)
            #expect(session.tunnelKeysForTesting == [ownDial],
                    "the preferred dialer's own connection must survive either activation order")
            #expect(!session.admitActivationForTesting(at: peerDial, role: .responder, verified: peer))
            #expect(session.tunnelKeysForTesting == [ownDial], "the collapse is idempotent")
        }
    }

    /// A dedup close touches exactly one link: another peer's tunnel, budget and slot are untouched.
    @Test func aDedupCloseLeavesAnUnrelatedPeerAlone() {
        let session = Self.session(advertising: "zzzz")
        let peer = Self.verified(Self.peerSigningKey, sessionID: "aaaa")
        let stranger = Self.verified(Self.otherSigningKey, sessionID: "mmmm", fingerprint: "zzzz-yyyy-xxxx")
        let ownDial = MeshLinkKey("browsed-endpoint")
        let peerDial = MeshLinkKey("quic-connection-1")
        let unrelated = MeshLinkKey("other-peer-endpoint")
        session.bookTunnelForTesting(ownDial, role: .initiator, verified: peer)
        session.bookTunnelForTesting(unrelated, role: .initiator, verified: stranger)
        session.bookTunnelForTesting(peerDial, role: .responder, verified: nil)

        #expect(!session.admitActivationForTesting(at: peerDial, role: .responder, verified: peer))
        #expect(session.tunnelKeysForTesting == [ownDial, unrelated])
        #expect(session.linkTableForTesting.phase(of: unrelated) == .connected)
        #expect(session.linkTableForTesting.connectedCount == 2)
    }

    /// The collapse keys on the **durable verified identity**, never on the per-launch `sid`: two
    /// devices that happen to advertise one `sid` are two peers, and closing one of their tunnels
    /// would be a disconnection dressed up as a dedup.
    @Test func twoIdentitiesSharingOneSessionIDAreNotADuplicate() {
        let session = Self.session(advertising: "zzzz")
        let first = Self.verified(Self.peerSigningKey, sessionID: "aaaa")
        let second = Self.verified(Self.otherSigningKey, sessionID: "aaaa")
        let one = MeshLinkKey("peer-one")
        let two = MeshLinkKey("peer-two")
        session.bookTunnelForTesting(one, role: .initiator, verified: first)
        session.bookTunnelForTesting(two, role: .responder, verified: nil)

        #expect(session.admitActivationForTesting(at: two, role: .responder, verified: second))
        #expect(session.tunnelKeysForTesting == [one, two])
    }

    /// The same-key half of the collapse.
    ///
    /// When a side HAS cached the peer's `sid`, both connections resolve to one ``MeshLinkKey`` and
    /// the table refuses the second as a duplicate — correct only if the peer's side refuses the
    /// mirror, which it must not: two refusals close one connection each and leave the pair with
    /// none. The same rule runs here, so the side that does not outrank the peer **yields** its own
    /// dial rather than refusing the peer's, and the channel above it is kept — one link key is one
    /// peer to every owner, and evicting a live coordinator to hand back an identical one is not a
    /// dedup.
    @Test func aSameKeyDuplicateYieldsInsteadOfRefusingOnBothSides() {
        let shared = MeshLinkKey("browsed-endpoint")

        let outranked = Self.session(advertising: "aaaa")
        let higherPeer = Self.verified(Self.peerSigningKey, sessionID: "zzzz")
        outranked.bookTunnelForTesting(shared, role: .initiator, verified: higherPeer)
        #expect(outranked.admitVerifiedInboundForTesting(higherPeer, pendingKey: shared) == shared,
                "the outranked side must yield its own dial, not refuse the peer's")
        #expect(outranked.tunnelKeysForTesting == [shared], "the channel is kept, not re-minted")
        #expect(outranked.linkTableForTesting.phase(of: shared) == .connected)
        #expect(outranked.linkTableForTesting.dialAttempts(for: shared) == 0)

        let outranking = Self.session(advertising: "zzzz")
        let lowerPeer = Self.verified(Self.otherSigningKey, sessionID: "aaaa")
        outranking.bookTunnelForTesting(shared, role: .initiator, verified: lowerPeer)
        #expect(outranking.admitVerifiedInboundForTesting(lowerPeer, pendingKey: shared) == nil,
                "the outranking side keeps its own dial")
        #expect(outranking.tunnelKeysForTesting == [shared])
        #expect(outranking.linkTableForTesting.connectedCount == 1)
    }
}

// MARK: - MeshTransferStreamTableTests

/// The per-transfer stream budget: which frames earn a stream of their own, how many may be open at
/// once, and what happens on every way a transfer can end — including the peer vanishing mid-flight.
///
/// The policy is a pure value, so all of it is enumerable here. The framework half — opening the
/// stream, writing the frame, reading the ack — needs two radios and is the runbook's Lane C.
@MainActor
@Suite(.serialized)
struct MeshTransferStreamTableTests {

    static let floor = MeshTransferStreamTable.bulkFloorBytes

    // MARK: The floor

    /// The fork itself. Below the floor a frame stays in order on the control stream; at or above it
    /// the frame earns a stream of its own. The boundary is inclusive, and pinned here because "at
    /// the floor" is the one value an off-by-one would move.
    @Test func theBulkFloorSplitsControlFramesFromTransfers() {
        #expect(MeshTransferStreamTable.route(reliableByteCount: Self.floor - 1) == .controlStream)
        #expect(MeshTransferStreamTable.route(reliableByteCount: Self.floor) == .transferStream)
        #expect(MeshTransferStreamTable.route(reliableByteCount: Self.floor + 1) == .transferStream)
    }

    /// Zero and one byte are control frames, not a degenerate transfer. A frame with no payload
    /// never reaches the transport (`payloadLength` refuses a zero header), but the route must still
    /// answer honestly rather than by accident of arithmetic.
    @Test func anEmptyOrTinyFrameIsAControlFrame() {
        #expect(MeshTransferStreamTable.route(reliableByteCount: 0) == .controlStream)
        #expect(MeshTransferStreamTable.route(reliableByteCount: 1) == .controlStream)
    }

    /// Every frame the mesh sends in the ordinary course stays on the control stream, in order. This
    /// is the assertion that keeps the reordering the fork buys away from the identity handshake,
    /// chat, hearts, capabilities and moderation — the traffic whose order matters.
    @Test func ordinaryTrafficNeverLeavesTheControlStream() {
        // A sealed envelope around: a 500-character message, a capability list, a heart, a
        // moderation signal, and a generous membership record.
        for byteCount in [64, 512, 2_048, 8_192, 32_768] {
            #expect(MeshTransferStreamTable.route(reliableByteCount: byteCount) == .controlStream,
                    "a \(byteCount)-byte frame must stay in order on the control stream")
        }
    }

    /// A friend photo — the payload plan §7.1 named — does cross the floor. 1400 px at q0.82 is
    /// hundreds of kilobytes before the two base64 inflations, so this is the low end of real.
    @Test func aFriendPhotoCrossesTheFloor() {
        #expect(MeshTransferStreamTable.route(reliableByteCount: 200 * 1024) == .transferStream)
    }

    /// Totality: the route is one of exactly two answers, and both are reachable.
    @Test func everyRouteIsReachable() {
        let observed = Set([0, Self.floor].map { MeshTransferStreamTable.route(reliableByteCount: $0) })
        #expect(observed == [.controlStream, .transferStream])
    }

    // MARK: Open, transfer, close

    /// The whole life of one transfer: it takes a slot, holds it while it is open, and gives it back.
    @Test func oneTransferTakesASlotAndGivesItBack() {
        var table = MeshTransferStreamTable()
        #expect(table.outbound.openCount == 0)

        guard let id = table.openOutbound(reliableByteCount: Self.floor) else {
            Issue.record("a bulk frame must be admitted on an empty budget")
            return
        }
        #expect(table.outbound.openCount == 1)
        #expect(table.outbound.isOpen(id))

        table.closeOutbound(id)
        #expect(table.outbound.openCount == 0)
        #expect(!table.outbound.isOpen(id))
    }

    /// A sub-floor frame is not merely routed to the control stream — it never touches the budget.
    /// A claim that consumed a slot and then declined to use it would starve real transfers.
    @Test func aControlFrameNeverSpendsATransferSlot() {
        var table = MeshTransferStreamTable()
        #expect(table.openOutbound(reliableByteCount: Self.floor - 1) == nil)
        #expect(table.outbound.openCount == 0)
    }

    /// The cap is exactly its capacity, and passing it falls back to the control stream rather than
    /// failing: nil is the same answer a sub-floor frame gets, and it means the same thing.
    @Test func theOutboundCapIsExactAndOverflowFallsBackToTheControlStream() {
        var table = MeshTransferStreamTable()
        var ids: [MeshTransferID] = []
        for _ in 0..<MeshTransferStreamTable.maxConcurrentOutbound {
            guard let id = table.openOutbound(reliableByteCount: Self.floor) else {
                Issue.record("the budget refused a transfer below its own capacity")
                return
            }
            ids.append(id)
        }
        #expect(table.outbound.openCount == MeshTransferStreamTable.maxConcurrentOutbound)
        #expect(table.openOutbound(reliableByteCount: Self.floor) == nil, "the cap is the cap")

        // One finishing makes room for exactly one more.
        table.closeOutbound(ids[0])
        #expect(table.openOutbound(reliableByteCount: Self.floor) != nil)
        #expect(table.openOutbound(reliableByteCount: Self.floor) == nil)
    }

    /// The inbound cap is exact too, and a refused inbound transfer is the receiver declining to
    /// serve a stream — the sender learns because its ack never arrives.
    @Test func theInboundCapIsExact() {
        var table = MeshTransferStreamTable()
        for _ in 0..<MeshTransferStreamTable.maxConcurrentInbound {
            #expect(table.openInbound() != nil)
        }
        #expect(table.openInbound() == nil)
        #expect(table.inbound.openCount == MeshTransferStreamTable.maxConcurrentInbound)
    }

    /// The two directions are independent budgets. A peer sending us four photos must not stop us
    /// sending it one.
    @Test func theTwoDirectionsDoNotShareABudget() {
        var table = MeshTransferStreamTable()
        for _ in 0..<MeshTransferStreamTable.maxConcurrentInbound {
            #expect(table.openInbound() != nil)
        }
        #expect(table.openInbound() == nil, "inbound is full")
        #expect(table.openOutbound(reliableByteCount: Self.floor) != nil, "outbound is untouched")
    }

    // MARK: The failure path

    /// **The peer vanished mid-transfer.** The write throws, the `defer` releases, and the slot is
    /// free again — with nothing else disturbed. The budget is the thing that must not wedge, and
    /// the release is keyed by id so it releases only its own.
    @Test func aTransferThatFailsMidFlightReleasesItsOwnSlotAndNoOther() {
        var table = MeshTransferStreamTable()
        guard let doomed = table.openOutbound(reliableByteCount: Self.floor),
              let survivor = table.openOutbound(reliableByteCount: Self.floor) else {
            Issue.record("two transfers must fit an empty budget")
            return
        }
        table.closeOutbound(doomed)
        #expect(table.outbound.openCount == 1)
        #expect(table.outbound.isOpen(survivor), "the surviving transfer keeps its slot")
        #expect(!table.outbound.isOpen(doomed))
    }

    /// Releasing twice is a no-op. Both a `defer` and a teardown can reach the same transfer, and a
    /// counter would have handed out a slot that was never free.
    @Test func releasingTheSameTransferTwiceFreesOneSlotNotTwo() {
        var table = MeshTransferStreamTable()
        guard let first = table.openOutbound(reliableByteCount: Self.floor),
              table.openOutbound(reliableByteCount: Self.floor) != nil else {
            Issue.record("two transfers must fit an empty budget")
            return
        }
        table.closeOutbound(first)
        table.closeOutbound(first)
        #expect(table.outbound.openCount == 1, "a double release must not free a live transfer's slot")
    }

    /// Ids are never reused while the budget churns, so a late release from a transfer that already
    /// ended cannot free a slot a later transfer is holding.
    @Test func anIdIsNeverHandedOutTwice() {
        var table = MeshTransferStreamTable()
        var seen: Set<MeshTransferID> = []
        for _ in 0..<(MeshTransferStreamTable.maxConcurrentOutbound * 4) {
            guard let id = table.openOutbound(reliableByteCount: Self.floor) else {
                Issue.record("the budget must have room after each release")
                return
            }
            #expect(seen.insert(id).inserted, "a transfer id was reused")
            table.closeOutbound(id)
        }
    }

    // MARK: The ack

    /// The ack is one frozen byte. It is a wire token, not copy, and its size is what the sender
    /// reads back — the two must not drift.
    @Test func theAckIsOneFrozenByte() {
        #expect(MeshTransferStreamTable.ack == Data([0x06]))
        #expect(MeshTransferStreamTable.ack.count == 1)
        #expect(MeshTransferStreamTable.ackByte == 0x06)
    }

    // MARK: Wiring

    /// The budget is reachable through the production read a channel exposes, and a claim shows up
    /// on it. `bookTunnelForTesting` mints the same channel `activate` hands an owner, so this walks
    /// the real path: channel → session → identity map → tunnel → table.
    @Test func aClaimIsVisibleThroughTheChannelsOwnRead() {
        let session = NetworkMeshSession()
        let key = MeshLinkKey("browsed-endpoint")
        session.bookTunnelForTesting(
            key,
            role: .initiator,
            verified: MeshVerifiedPeer(
                signingPublicKey: Data(repeating: 0x11, count: 32),
                fingerprint: "abcd-efgh-ijkl",
                sessionID: "aaaa"
            )
        )
        guard let channel = session.channels.first else {
            Issue.record("a booked tunnel must carry a channel")
            return
        }
        #expect(channel.openTransferCount == 0)

        guard let id = session.claimOutboundTransferForTesting(key, byteCount: Self.floor) else {
            Issue.record("a bulk frame must be admitted on a live tunnel")
            return
        }
        #expect(channel.openTransferCount == 1)

        session.releaseOutboundTransferForTesting(key, id: id)
        #expect(channel.openTransferCount == 0)
    }

    /// A control-sized frame claims nothing through the production path either.
    @Test func aControlSizedFrameClaimsNothingOnALiveTunnel() {
        let session = NetworkMeshSession()
        let key = MeshLinkKey("browsed-endpoint")
        session.bookTunnelForTesting(key, role: .initiator, verified: nil)
        #expect(session.claimOutboundTransferForTesting(key, byteCount: Self.floor - 1) == nil)
        #expect(session.channels.first?.openTransferCount == 0)
    }

    /// **A budget cannot outlive the tunnel that bounded it.** The table is stored in the tunnel
    /// record, so a torn-down link takes its open transfers with it — which is what makes "a peer
    /// that vanished mid-transfer cannot wedge the budget" structural rather than a swept invariant.
    @Test func aTornDownTunnelTakesItsOpenTransfersWithIt() {
        let session = NetworkMeshSession()
        let key = MeshLinkKey("browsed-endpoint")
        session.bookTunnelForTesting(key, role: .initiator, verified: nil)
        #expect(session.claimOutboundTransferForTesting(key, byteCount: Self.floor) != nil)
        #expect(session.channels.first?.openTransferCount == 1)

        session.stop()
        #expect(session.tunnelKeysForTesting.isEmpty)
        #expect(session.claimOutboundTransferForTesting(key, byteCount: Self.floor) == nil,
                "there is no tunnel left to claim a slot on")
    }

    /// A peer with no tunnel has no transfers, and asking does not mint one.
    @Test func anUnknownPeerHasNoOpenTransfers() {
        let session = NetworkMeshSession()
        let stranger = PeerHandle(
            id: UUID(), displayHint: "stranger", discoveryInfo: nil, advertisedFingerprint: nil
        )
        #expect(session.openTransferCount(for: stranger) == 0)
        #expect(session.tunnelKeysForTesting.isEmpty)
    }

    // MARK: The control stream's id

    /// The control stream is named by RFC 9000's stream numbering, not by a latch. The dialing side
    /// opens exactly one stream before the introduction, so the listening side can recognise it by
    /// id alone — and every other inbound stream is a transfer.
    @Test func theControlStreamIsTheDialingSidesFirstStream() {
        #expect(NetworkMeshSession.controlStreamID == 0)
    }
}
