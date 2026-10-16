// MeshRoutedHeartTests.swift
// ProximityKitTests
//
// Network migration P6 item 6 (plan §12): hearts on the routed store — the body's framing, the
// registry flip and its subset target, and the ACK CEREMONY end to end on a real two-node founding.
//
// **What tier 1 proves, and what it does not.** A mesh heart needs mutual trust-vault rows, and a
// row appears when `pendingFriendReview` completes — which fires at session END. So inside the
// session that produced a heart those rows CANNOT exist, and every ceremony cell here seeds them
// directly. That seeding stands in for a second session, so these cells prove the ceremony's
// mechanics and nothing about the product's first session: **item 10's two-session Lane C script is
// the only honest proof of the feature.** The explicit negative
// (`aHeartFromANonFriendIsRefusedFinalAndCustodyIsKept`, vault empty) is what keeps the seeding
// from being the whole argument.
//
// Three more fixture facts, each easy to get wrong here specifically:
//
// - **The rig is `MeshFoundingRig`**, because the ceremony needs a mesh the REAL commit path
//   founded: `MeshRoutedDrainRig` hand-seeds a ledger and fakes its commits, and the key
//   advertisements a single-recipient mint resolves its wrap against are minted by the production
//   founding doors. A heart cell on a seeded rig is green over nothing (item 1's own warning).
// - **`judgementsForGift`, never the batch counter.** The ceremony hands `MeshHeartCommit.commit` a
//   ONE-element batch, so `MeshHeartCommitOutcome.judgements` and
//   `MeshRoutedHeartAck.judgementsForGift` coincide at every shipping call site. The exactly-once
//   claim is therefore witnessed by counting `onHeartJudgedForTesting` firings per gift, and
//   `aTwoHeartBatchSeparatesTheBatchCounterFromThePerGiftCount` is the fixture-only cell proving the
//   two fields really are different questions.
// - **The ack the wall pins must be the SHIPPING one.** W2's pins scan shipping sources only (the
//   ack's one construction lives in FernletSocial's `MeshSessionHearts.swift` since plan step
//   A0.5.10), so a `MeshRoutedHeartAck` a test constructs is invisible to them — which is why the
//   ceremony cells assert a stored `MeshRecipientReceipt` produced by the real `commitLocalDelivery`,
//   never an ack value a cell built.
//
// A partial copy (ProximityKit plan step A1, the split's second batch of copied suites: those that reach
// the keychain and open no store): of the Fernlet repository's FernletTests file of the same name, this
// holds only `MeshRoutedHeartTargetTests`, with its name and tests unchanged; its other suites stay
// there, so what this header says of them is not held here.

@testable import ProximityKit
import Foundation
import Testing

// MARK: - The registry flip and the subset target

/// The `.singleRecipient` column at a real mint: the flip, the capture door's two refusals, and the
/// shape fence in BOTH directions.
@MainActor
@Suite(.serialized)
struct MeshRoutedHeartTargetTests {

    /// The flip itself, plus the per-token map that replaced "every row is full-roster".
    @Test func theHeartRowIsSingleRecipient() throws {
        let registry = MeshRoutedTypeRegistry.increment1
        let semantics: [String: MeshRoutedDestinationSemantics] = [
            MeshRoutedTypeToken.photo: .fullRosterAtCreation,
            MeshRoutedTypeToken.tempMessage: .fullRosterAtCreation,
            MeshRoutedTypeToken.heart: .singleRecipient
        ]
        // R2: bounded by the registry's own tokens.
        for token in registry.tokens {
            let entry = try #require(registry.entry(for: token), "\(token)")
            #expect(entry.destinations == semantics[token], "\(token)")
        }
    }

    /// The capture door names only its recipient, and the roster is still the only authority.
    @Test func aSubsetTargetNamesOnlyItsRecipient() throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 3)
        let me = rig.fingerprints[0]
        let recipient = rig.fingerprints[2]
        guard case .updated(let target) = MeshDeliveryTarget.addressing(
            contentID: UUID(), recipient: recipient, roster: rig.roster, selfFingerprint: me
        ) else {
            Issue.record("a roster member must be addressable")
            return
        }
        #expect(target.destinations == [recipient])
        #expect(target.destinationCount == 1)
        #expect(!target.names(rig.fingerprints[1]),
                "and NOT the third member, which a full-roster capture would have included")
    }

    @Test func aRecipientOutsideTheRosterAtCreationIsRefusedByName() throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 3)
        #expect(MeshDeliveryTarget.addressing(
            contentID: UUID(), recipient: "fp-stranger", roster: rig.roster,
            selfFingerprint: rig.fingerprints[0]
        ) == .refused(.recipientNotInRoster))
    }

    /// Self is checked FIRST on purpose: a roster always contains this device, so the other order
    /// would report the wrong fact.
    @Test func aRecipientThatIsThisDeviceIsRefusedByName() throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 3)
        let me = rig.fingerprints[0]
        #expect(rig.roster.contains(fingerprint: me), "the precondition that makes the order matter")
        #expect(MeshDeliveryTarget.addressing(
            contentID: UUID(), recipient: me, roster: rig.roster, selfFingerprint: me
        ) == .refused(.recipientIsSelf))
    }

    /// A one-destination progress map restores: `restoring` refuses an EMPTY set, a duplicate and an
    /// over-cap one, and deliberately has no smaller-than-roster refusal.
    @Test func aOneDestinationDeliveryMapRestores() throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 3)
        let recipient = rig.fingerprints[2]
        guard case .restored(let target) = MeshDeliveryTarget.restoring(
            contentID: UUID(), destinations: [recipient], progress: [recipient: .delivered]
        ) else {
            Issue.record("a single-destination map must restore")
            return
        }
        #expect(target.destinations == [recipient])
        #expect(target.state(of: recipient) == .delivered)
    }

    @Test func theDeliveryRefusalVocabularyIsFrozen() {
        #expect(MeshDeliveryRefusal.allCases.map(\.rawValue) == [
            "notADestination", "alreadyDelivered", "wouldRegress",
            "differentContent", "destinationSetMismatch",
            "recipientIsSelf", "recipientNotInRoster"
        ], "audit vocabulary; two cases joined it at P6 item 6")
    }
}
