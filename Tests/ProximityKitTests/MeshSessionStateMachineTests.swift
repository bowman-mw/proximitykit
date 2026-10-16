// MeshSessionStateMachineTests.swift
// ProximityKitTests
//
// P3 item 6 (plan §8.1, §8.2, §3.6): the session state machine, the ceiling at both bounds, the
// launch restore, and the save cadence.
//
// The claims worth walling here:
//
// 1. **The transition function is total.** Every (state, event) pair either moves or names a
//    refusal — never a trap. Most of these events arrive from the wire, so a state machine that
//    crashed on an unexpected one would be a remotely reachable crash.
// 2. **The ceiling is guarded at both bounds.** A wall clock set backwards cannot lengthen a
//    session (the monotonic guard ends it anyway) and one set forwards cannot end it earlier than
//    the signed absolute deadline allows.
// 3. **A disconnect is not a removal** (invariant 1): the roster does not move, no record is
//    minted, and the peer that comes back needs no re-admission — while a *removed* member stays
//    out of the next epoch's key.
// 4. **Idle-lapse resume IS the merge path** (plan §10.3): two members that rotated independently
//    at the same counter come back with both epochs recorded — coexistence, not a re-key.
// 5. **Developed / terminated never rejoin**, and a relaunch re-derives that from the sealed file.
// 6. **Durable before acknowledged** (plan §3.6): a join is not acknowledged and a record is not
//    inserted until the context that contains it is on the disk.
//
// Time is always an argument here — `now` and `monotonicElapsed` are passed in, exactly like
// `MeshEpochKeyring` and `MeshRotationTriggerQueue` — so nothing waits and nothing flakes.
//
// A partial copy (ProximityKit plan step A1, the split's first batch of copied suites): of the
// Fernlet repository's FernletTests file of the same name, this holds only
// `MeshSessionStateMachineTests` and `MeshSessionCeilingTests` and, since ProximityKit plan step A1's
// third batch of copied suites (those that reach the keychain and open a store),
// `MeshSessionRestoreMappingTests`, with their names and tests unchanged; its last suite,
// `MeshSessionLifecycleManagerTests`, stays there, so what this header says of it is not held here.

import Foundation
import Testing
@testable import ProximityKit

// MARK: - MeshSessionStateMachineTests

/// Plan §8.2's edges, its non-edges, and the totality of the function over both.
@Suite(.serialized)
struct MeshSessionStateMachineTests {

    /// Every event, built from the `CaseIterable` payload enums so a new payload case cannot slip
    /// past the totality sweep.
    private static var allEvents: [MeshSessionEvent] {
        var events: [MeshSessionEvent] = [
            .founded, .joined, .peerCommitted, .backgrounded, .foregrounded, .linksLost,
            .linksRestored, .idleLapsed, .resumedAfterLapse, .developed, .departureRequested,
            .departureSent, .terminationSent, .terminationVerified, .removed
        ]
        events.append(contentsOf: MeshSessionTerminationReason.allCases.map { .terminationRequested($0) })
        events.append(contentsOf: MeshSessionCeilingBound.allCases.map { .hardDeadlineReached($0) })
        events.append(contentsOf: MeshSessionRestoredDisposition.allCases.map { .contextRestored($0) })
        return events
    }

    /// The function is TOTAL: every pair answers, and a terminal state answers "ended" to all of
    /// them. Nothing traps, and nothing falls through to a default that quietly moves.
    @Test func everyStateAnswersEveryEventWithoutTrapping() {
        for state in MeshSessionState.allCases {
            for event in Self.allEvents {
                let transition = MeshSessionStateMachine.transition(from: state, on: event)
                if state.hasEnded {
                    #expect(transition == .rejected(.sessionAlreadyEnded),
                            "\(state) must refuse \(event) as an ended session")
                    continue
                }
                #expect(transition.nextState != nil || transition.effects.isEmpty,
                        "a refusal must carry no effects (\(state) / \(event))")
            }
        }
    }

    /// The happy path across §8.2's spine: idle → joining → active → background → active.
    @Test func theForegroundSpineFollowsTheDiagram() {
        #expect(MeshSessionStateMachine.transition(from: .idle, on: .founded)
                == .moved(to: .joining, effects: [.persistContext]))
        #expect(MeshSessionStateMachine.transition(from: .idle, on: .joined)
                == .moved(to: .joining, effects: [.persistContext]))
        #expect(MeshSessionStateMachine.transition(from: .joining, on: .peerCommitted)
                == .moved(to: .activeForeground, effects: [.persistContext, .clearIdleTimer]))
        #expect(MeshSessionStateMachine.transition(from: .activeForeground, on: .backgrounded)
                == .moved(to: .continuingInBackground, effects: []))
        #expect(MeshSessionStateMachine.transition(from: .continuingInBackground, on: .foregrounded)
                == .moved(to: .activeForeground, effects: []))
    }

    /// Losing links partitions from either live state and arms the idle window; it never ends
    /// membership (invariant 1).
    @Test func lostLinksPartitionFromEitherLiveState() {
        for state in [MeshSessionState.activeForeground, .continuingInBackground] {
            #expect(MeshSessionStateMachine.transition(from: state, on: .linksLost)
                    == .moved(to: .partitioned, effects: [.armIdleTimer]),
                    "\(state) must partition, not end")
        }
    }

    /// A partition heals through the merge path, and an idle lapse stops participation only.
    @Test func aPartitionHealsAsAMergeAndLapsesIntoLocalIdleStop() {
        #expect(MeshSessionStateMachine.transition(from: .partitioned, on: .linksRestored)
                == .moved(to: .activeForeground, effects: [.clearIdleTimer, .beginMerge]))
        #expect(MeshSessionStateMachine.transition(from: .partitioned, on: .peerCommitted)
                == .moved(to: .activeForeground, effects: [.clearIdleTimer, .beginMerge]),
                "a peer reappearing is a heal, and a heal is a merge")
        #expect(MeshSessionStateMachine.transition(from: .partitioned, on: .idleLapsed)
                == .moved(to: .localIdleStop, effects: [.stopParticipation, .clearIdleTimer]))
    }

    /// Resume after a lapse restarts the radios and enters the merge path — the same mechanism as
    /// a partition heal, which is the whole point of plan §10.3.
    @Test func resumeAfterALapseIsTheMergePath() {
        let transition = MeshSessionStateMachine.transition(from: .localIdleStop, on: .resumedAfterLapse)
        #expect(transition == .moved(
            to: .activeForeground, effects: [.startParticipation, .beginMerge, .clearIdleTimer]
        ))
        #expect(MeshSessionStateMachine.transition(from: .localIdleStop, on: .peerCommitted)
                == .rejected(.eventNotApplicableInState),
                "a stopped radio has no peer to commit — the resume comes first")
    }

    /// The two endings §8.2 draws out of `handingOff`, and the durable-before-acknowledged order:
    /// the mark and the save happen on the REQUEST, the state moves on the SEND.
    @Test func handingOffSavesFirstAndMovesOnTheSend() {
        #expect(MeshSessionStateMachine.transition(from: .activeForeground, on: .departureRequested)
                == .moved(to: .handingOff, effects: [.markTerminated, .persistContext]))
        #expect(MeshSessionStateMachine.transition(from: .handingOff, on: .departureSent)
                == .moved(to: .departed, effects: [.stopParticipation]))
        #expect(MeshSessionStateMachine.transition(
            from: .partitioned, on: .terminationRequested(.finalPairTermination)
        ) == .moved(to: .handingOff, effects: [.markTerminated, .persistContext]))
        #expect(MeshSessionStateMachine.transition(from: .handingOff, on: .terminationSent)
                == .moved(to: .terminated, effects: [.stopParticipation]))
    }

    /// Developing marks the permanent bar and saves before anything else happens.
    @Test func developingMarksTheBarBeforeItIsAnnounced() {
        let transition = MeshSessionStateMachine.transition(from: .activeForeground, on: .developed)
        #expect(transition == .moved(
            to: .handingOff, effects: [.markDeveloped, .persistContext, .stopParticipation]
        ))
        #expect(MeshSessionEvent.developed.terminationReason == .developed)
    }

    /// The ceiling ends the session from EVERY live state — plan §8.2 draws the edge from
    /// `localIdleStop`, and the prose ("the 6-hour ceiling is the membership death") is broader.
    @Test func theCeilingEndsEveryLiveState() {
        for state in MeshSessionState.allCases where state.isLive {
            for bound in MeshSessionCeilingBound.allCases {
                let transition = MeshSessionStateMachine.transition(from: state, on: .hardDeadlineReached(bound))
                #expect(transition == .moved(
                    to: .expired, effects: [.markTerminated, .persistContext, .stopParticipation]
                ), "\(state) must expire at \(bound)")
            }
        }
        #expect(MeshSessionStateMachine.transition(from: .idle, on: .hardDeadlineReached(.signedAbsolute))
                == .rejected(.noSessionYet), "there is no session to expire before one starts")
    }

    /// A removal is involuntary and terminal for this device; a verified termination ends the mesh.
    @Test func removalAndVerifiedTerminationAreTerminal() {
        #expect(MeshSessionStateMachine.transition(from: .activeForeground, on: .removed)
                == .moved(to: .departed, effects: [.markTerminated, .persistContext, .stopParticipation]))
        #expect(MeshSessionStateMachine.transition(from: .partitioned, on: .terminationVerified)
                == .moved(to: .terminated, effects: [.markTerminated, .persistContext, .stopParticipation]))
        #expect(MeshSessionEvent.removed.terminationReason == .removedFromRoster)
    }

    /// Every terminal state refuses every event by the same named rule: a developed or terminated
    /// mesh can never be rejoined.
    @Test func aTerminalStateNeverRejoins() {
        for state in [MeshSessionState.departed, .terminated, .expired] {
            for event in [MeshSessionEvent.founded, .joined, .resumedAfterLapse, .linksRestored,
                          .contextRestored(.resumable)] {
                #expect(MeshSessionStateMachine.transition(from: state, on: event)
                        == .rejected(.sessionAlreadyEnded),
                        "\(state) must refuse \(event)")
            }
        }
    }

    /// The named non-edges, each by its own rule rather than one catch-all.
    @Test func everyNonEdgeNamesItsRule() {
        #expect(MeshSessionStateMachine.transition(from: .idle, on: .peerCommitted)
                == .rejected(.noSessionYet))
        #expect(MeshSessionStateMachine.transition(from: .activeForeground, on: .founded)
                == .rejected(.sessionAlreadyStarted))
        #expect(MeshSessionStateMachine.transition(from: .joining, on: .idleLapsed)
                == .rejected(.eventNotApplicableInState))
        #expect(MeshSessionStateMachine.transition(from: .activeForeground, on: .contextRestored(.resumable))
                == .rejected(.restoreOnlyFromIdle))
        #expect(MeshSessionStateMachine.transition(from: .handingOff, on: .peerCommitted)
                == .rejected(.eventNotApplicableInState))
    }

    /// A link lost before anything committed is not a partition — there is no roster peer yet.
    @Test func aLinkLostWhileJoiningIsNotAPartition() {
        #expect(MeshSessionStateMachine.transition(from: .joining, on: .linksLost)
                == .moved(to: .joining, effects: []))
    }

    /// The launch restore's four dispositions, including the one that must WRITE.
    @Test func restoreMapsEveryDispositionFromIdle() {
        #expect(MeshSessionStateMachine.transition(from: .idle, on: .contextRestored(.none))
                == .moved(to: .idle, effects: []))
        #expect(MeshSessionStateMachine.transition(from: .idle, on: .contextRestored(.resumable))
                == .moved(to: .localIdleStop, effects: [.offerForegroundResume]),
                "a relaunch never auto-reconnects — it offers a resume")
        #expect(MeshSessionStateMachine.transition(from: .idle, on: .contextRestored(.terminated))
                == .moved(to: .terminated, effects: []))
        #expect(MeshSessionStateMachine.transition(from: .idle, on: .contextRestored(.departed))
                == .moved(to: .departed, effects: []))
        #expect(MeshSessionStateMachine.transition(from: .idle, on: .contextRestored(.expired))
                == .moved(to: .expired, effects: [.markTerminated, .persistContext]),
                "a ceiling that passed while the process was gone is written down now")
    }

    /// `persistContext` precedes every effect that tells anybody anything (plan §3.6), and no
    /// transition exceeds the performer's bound.
    @Test func everySaveComesBeforeEveryAnnouncement() {
        for state in MeshSessionState.allCases {
            for event in Self.allEvents {
                let effects = MeshSessionStateMachine.transition(from: state, on: event).effects
                #expect(effects.count <= MeshSessionStateMachine.maxEffectsPerTransition)
                guard let saveIndex = effects.firstIndex(of: .persistContext) else { continue }
                for marker in [MeshSessionEffect.markTerminated, .markDeveloped] {
                    if let markIndex = effects.firstIndex(of: marker) {
                        #expect(markIndex < saveIndex, "the mark must be staged before the save")
                    }
                }
            }
        }
    }
}

// MARK: - MeshSessionCeilingTests

/// The 6-hour ceiling at both of its bounds, including the clock jumps each one exists for.
@Suite(.serialized)
struct MeshSessionCeilingTests {

    private let created = Date(timeIntervalSince1970: 1_800_000_000)

    private var deadline: Date { created.addingTimeInterval(MeshSessionCeiling.ceilingSeconds) }

    /// A fresh session has the full ceiling on both bounds.
    @Test func aFreshSessionHasTheWholeCeiling() {
        let ceiling = MeshSessionCeiling(hardDeadline: deadline, startedAt: created)
        #expect(ceiling.monotonicBudgetSeconds == MeshSessionCeiling.ceilingSeconds)
        #expect(ceiling.verdict(now: created, monotonicElapsed: 0)
                == .live(remainingSeconds: MeshSessionCeiling.ceilingSeconds))
    }

    /// The signed bound ends the session, and only after the skew tolerance.
    @Test func theSignedBoundEndsItAfterTheSkewTolerance() {
        let ceiling = MeshSessionCeiling(hardDeadline: deadline, startedAt: created)
        let tolerance = MeshSessionCeiling.skewToleranceSeconds

        #expect(!ceiling.verdict(now: deadline.addingTimeInterval(tolerance - 1), monotonicElapsed: 0).isReached,
                "inside the ± 120 s tolerance the session is still live")
        #expect(ceiling.verdict(now: deadline.addingTimeInterval(tolerance), monotonicElapsed: 0)
                == .reached(.signedAbsolute))
    }

    /// The monotonic bound ends the session on runtime alone.
    @Test func theMonotonicBoundEndsItOnRuntimeAlone() {
        let ceiling = MeshSessionCeiling(hardDeadline: deadline, startedAt: created)
        let budget = MeshSessionCeiling.ceilingSeconds

        #expect(!ceiling.verdict(now: created, monotonicElapsed: budget - 1).isReached)
        #expect(ceiling.verdict(now: created, monotonicElapsed: budget) == .reached(.localMonotonic))
    }

    /// **A wall clock set backwards cannot extend a session.** The signed bound says a day remains;
    /// the monotonic guard ends it anyway.
    @Test func aBackwardClockJumpCannotExtendTheSession() {
        let ceiling = MeshSessionCeiling(hardDeadline: deadline, startedAt: created)
        let yesterday = created.addingTimeInterval(-86_400)

        #expect(ceiling.verdict(now: yesterday, monotonicElapsed: MeshSessionCeiling.ceilingSeconds)
                == .reached(.localMonotonic),
                "a clock set backwards must not buy a single second of extra membership")
    }

    /// **A forward jump cannot end a session earlier than the signed absolute allows.** Inside the
    /// tolerance it is still live; past it, the signed bound — not the monotonic one — is what ends
    /// it, and the reason recorded says so.
    @Test func aForwardClockJumpEndsItOnlyByTheSignedBound() {
        let ceiling = MeshSessionCeiling(hardDeadline: deadline, startedAt: created)

        #expect(ceiling.verdict(now: created.addingTimeInterval(60), monotonicElapsed: 5) ==
                .live(remainingSeconds: MeshSessionCeiling.ceilingSeconds - 5),
                "the tighter of the two bounds is what remains")
        let verdict = ceiling.verdict(now: deadline.addingTimeInterval(3_600), monotonicElapsed: 5)
        #expect(verdict == .reached(.signedAbsolute))
        #expect(MeshSessionCeilingBound.signedAbsolute.terminationReason == .hardDeadlineSigned)
        #expect(MeshSessionCeilingBound.localMonotonic.terminationReason == .hardDeadlineMonotonic)
    }

    /// A descriptor claiming a deadline days out still buys no more than the ceiling, and a restore
    /// gets only the time that was left.
    @Test func theBudgetIsClampedToTheCeilingAndToWhatIsLeft() {
        let forged = MeshSessionCeiling(
            hardDeadline: created.addingTimeInterval(7 * 86_400), startedAt: created
        )
        #expect(forged.monotonicBudgetSeconds == MeshSessionCeiling.ceilingSeconds)

        let restoredHalfway = MeshSessionCeiling(
            hardDeadline: deadline, startedAt: created.addingTimeInterval(3 * 3_600)
        )
        #expect(restoredHalfway.monotonicBudgetSeconds == 3 * 3_600)

        let restoredLate = MeshSessionCeiling(hardDeadline: deadline, startedAt: deadline.addingTimeInterval(60))
        #expect(restoredLate.monotonicBudgetSeconds == 0)
        #expect(restoredLate.verdict(now: created, monotonicElapsed: 0) == .reached(.localMonotonic),
                "a session restored past its deadline has no budget at all")
    }

    /// A monotonic source that ran backwards is a broken reading, never a licence to extend.
    @Test func aNegativeMonotonicReadingIsTreatedAsZero() {
        let ceiling = MeshSessionCeiling(hardDeadline: deadline, startedAt: created)
        #expect(ceiling.verdict(now: created, monotonicElapsed: -10_000)
                == .live(remainingSeconds: MeshSessionCeiling.ceilingSeconds))
    }
}

// MARK: - MeshSessionRestoreMappingTests

/// The five load states → seven launch outcomes, as a pure mapping.
@Suite(.serialized)
struct MeshSessionRestoreMappingTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer
    /// has run before a cell's identities or stores reach the keychain.
    let keychain = PackageTestEnvironment.keychain

    private typealias Fixture = MeshSessionStoreFixtures

    private let selfFingerprint = MeshMembershipFixtures.fingerprint(0)

    /// A live context, well inside its ceiling.
    private func liveContext(termination: MeshSessionLocalTermination? = nil) -> MeshSessionContext {
        MeshSessionContext(
            meshID: MeshMembershipFixtures.meshID,
            protocolVersion: 3,
            createdAt: MeshMembershipFixtures.base,
            hardDeadline: MeshMembershipFixtures.base.addingTimeInterval(6 * 3_600),
            localTermination: termination
        )
    }

    /// A token-carrying `loaded`, built through the store so the token is a real one.
    private func loaded(_ context: MeshSessionContext) throws -> MeshSessionLoad {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshSessionStore(scope: scope)
        try Fixture.save(context, into: store)
        return PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) { store.load() }
    }

    /// Outcome 1: a live context inside the ceiling resumes.
    @Test func aLiveContextIsResumable() throws {
        let context = liveContext()
        let outcome = MeshSessionRestore.outcome(
            for: try loaded(context),
            selfFingerprint: selfFingerprint,
            now: MeshMembershipFixtures.base.addingTimeInterval(3_600)
        )
        #expect(outcome.disposition == .resumable)
        #expect(outcome.context?.meshID == context.meshID)
        #expect(!outcome.isRetryable)
    }

    /// Outcome 2: a context that already records an ending comes back ended, by every one of the
    /// four authorities that can record one.
    @Test func aRecordedEndingComesBackEnded() {
        var developed = liveContext()
        developed.developedLocally = true
        #expect(developed.recordedEndingReason(selfFingerprint: selfFingerprint) == .developed)

        var terminatedLedger = liveContext()
        terminatedLedger.ledger.terminations = MeshMembershipRecordSet([MeshMembershipFixtures.termination(1)])
        #expect(terminatedLedger.recordedEndingReason(selfFingerprint: selfFingerprint)
                == .verifiedTerminationRecord)

        var departed = liveContext()
        departed.ledger.departures = MeshMembershipRecordSet([MeshMembershipFixtures.departure(0)])
        #expect(departed.recordedEndingReason(selfFingerprint: selfFingerprint) == .ownDeparture)

        let marked = liveContext(termination: MeshSessionLocalTermination(
            reason: .epochCounterExhausted, at: MeshMembershipFixtures.base
        ))
        #expect(marked.recordedEndingReason(selfFingerprint: selfFingerprint) == .epochCounterExhausted)
    }

    /// A recorded ending beats the ceiling: the reason on the file is what the launch reports.
    @Test func aRecordedEndingBeatsThePassedCeiling() throws {
        let context = liveContext(termination: MeshSessionLocalTermination(
            reason: .ownDeparture, at: MeshMembershipFixtures.base
        ))
        let outcome = MeshSessionRestore.outcome(
            for: try loaded(context),
            selfFingerprint: selfFingerprint,
            now: MeshMembershipFixtures.base.addingTimeInterval(86_400)
        )
        #expect(outcome == .terminated(context, .ownDeparture))
        #expect(outcome.disposition == .departed, "a departure ends this device, not the mesh")
    }

    /// Outcome 3: a live context whose ceiling passed while the process was gone.
    @Test func aPassedCeilingIsExpired() throws {
        let context = liveContext()
        let outcome = MeshSessionRestore.outcome(
            for: try loaded(context),
            selfFingerprint: selfFingerprint,
            now: context.hardDeadline.addingTimeInterval(MeshSessionCeiling.skewToleranceSeconds + 1)
        )
        #expect(outcome == .expired(context))
        #expect(outcome.disposition == .expired)
    }

    /// Outcomes 4–7: absent, deferred, refused and corrupt, each distinct and only one of them a
    /// green field.
    @Test func theFourNonLoadedStatesStayDistinct() {
        let scope = Fixture.scope()
        defer { Fixture.tearDown(scope) }
        let store = MeshSessionStore(scope: scope)
        let absent = PackageSwitchableInstallBinding.testOverride.withValue(.identifier(Fixture.installA)) { store.load() }
        #expect(MeshSessionRestore.outcome(for: absent, selfFingerprint: selfFingerprint, now: .now)
                == .noSession)

        let deferral = MeshSessionDeferral(reason: .fileUnreadable, detail: "x")
        let deferred = MeshSessionRestore.outcome(
            for: .deferred(deferral), selfFingerprint: selfFingerprint, now: .now
        )
        #expect(deferred == .retryAfterUnlock(deferral))
        #expect(deferred.isRetryable)
        #expect(deferred.logToken == "deferred:fileUnreadable")

        let refusal = MeshSessionSealRefusal(operation: .open, cause: .installBindingUnavailable)
        let refused = MeshSessionRestore.outcome(
            for: .refused(refusal), selfFingerprint: selfFingerprint, now: .now
        )
        #expect(refused == .retryAfterRefusal(refusal))
        #expect(refused.isRetryable)
        #expect(refused.logToken == "refused:installBindingUnavailable",
                "a refusal is logged apart from a deferral")

        let corruption = MeshSessionCorruption(detail: .emptyFile)
        let corrupt = MeshSessionRestore.outcome(
            for: .corrupt(corruption), selfFingerprint: selfFingerprint, now: .now
        )
        #expect(corrupt == .quarantineCorruptFile(corruption))
        #expect(!corrupt.isRetryable, "a corrupt file is quarantined, not retried")
    }

    /// None of the three token-less states starts a session.
    @Test func noTokenlessStateStartsASession() {
        let outcomes: [MeshSessionRestoreOutcome] = [
            .retryAfterUnlock(MeshSessionDeferral(reason: .sealKeyTransientlyUnreadable, detail: "x")),
            .retryAfterRefusal(MeshSessionSealRefusal(operation: .open, cause: .sealKeyMalformed)),
            .quarantineCorruptFile(MeshSessionCorruption(detail: .authenticationFailed))
        ]
        for outcome in outcomes {
            #expect(outcome.disposition == .none)
            #expect(outcome.context == nil)
        }
    }
}
