// MeshDeliveryTargetTests.swift
// ProximityKitTests
//
// P4 item 8 (plan §10.1, launcher §5(c)): delivery-target semantics for P5.
//
// The claims walled here, in the order §10.1 makes them:
//
//  1. **The destination set is the full derived roster at creation time, minus self.** A photo taken
//     during a 2/2 split of a roster of four is for three people, and both members on the far side
//     are in that three. The wrong construction is unrepresentable: no initializer takes a reachable
//     set, a branch view or a bare fingerprint list, and no method removes a destination.
//  2. **Reachable vs unreachable is a DELIVERY state, never a DESTINATION state.** The far side is
//     `pending`, not absent; a member becoming reachable moves no destination; states advance
//     `pending → custodied → delivered` and never backwards, with `delivered` terminal and every
//     regression refused **by name**.
//  3. **Independent of partition and epoch** — structurally (no `keyEpoch`, no branch id, no
//     "created in partition X" member) and behaviourally (two targets minted on opposite sides of
//     one split are equal).
//  4. **A departed destination is closed, a temporarily disconnected one is not.** The roster is the
//     authority and the answer is derived at read, so a real signed departure closes a destination
//     while item 1's `temporarilyDisconnected` leaves it pending.
//  5. **Completeness is derivable** through a full lifecycle, including a destination that closes by
//     departure.
//  6. **Union-merge safe**: per-destination max under the monotone order, commutative, associative
//     and idempotent, and a destination-set mismatch is refused by name.
//  7. **The two existing seams are one-line derivations** — `MeshDevelopmentPlan.handoffTargets` and
//     `MeshBranchView.temporarilyDisconnectedFingerprints` — and neither type is modified to get it.
//
// Nothing here sleeps and nothing reads a wall clock for a decision: a target has no clock, and
// every state moves by an explicit call carrying its receipt.
//
// A partial copy (ProximityKit plan step A1, the split's second batch of copied suites: those that reach
// the keychain and open no store): of the Fernlet repository's FernletTests file of the same name, this
// holds only the fixtures the package's copied suites read (`MeshDeliveryRig` and
// `MeshDeliveryFixtures`); its suite stays there, so what this header says of it is not held here. Each
// fixture member here that reaches the keychain gains one first statement that reads
// `PackageTestEnvironment.keychain` (the package's hygiene rule I9).

import Foundation
import Testing
@testable import ProximityKit

// MARK: - Shared fixtures

/// One mesh's identities, ledger and derived roster, with the identities addressable by fingerprint.
///
/// Fingerprints come out of real signing keys, so their order is not knowable in advance — every
/// scenario addresses members by rank ("the lowest") and looks the signing identity back up by
/// fingerprint, which is also how the shipping code reads them.
@MainActor
struct MeshDeliveryRig {

    /// The mesh every record in ``ledger`` is bound to.
    let meshID: UUID

    /// Identity services keyed by their own fingerprint, so a departure can be signed by the member
    /// it is about.
    let identities: [String: IdentityService]

    /// The membership ledger the roster is derived from.
    var ledger: MeshMembershipLedger

    /// The derived roster, re-derived on every read exactly as the shipping code does.
    var roster: MeshDerivedRoster { ledger.derivedRoster }

    /// The roster's fingerprints, in its own sorted order.
    var fingerprints: [String] { roster.memberFingerprints }
}

/// Builds the rigs and branch views the suite below shares.
@MainActor
enum MeshDeliveryFixtures {

    /// A rig of `memberCount` honestly-signed members, reusing item 1's identity and ledger
    /// fixtures rather than growing a second copy of them.
    static func rig(memberCount: Int) throws -> MeshDeliveryRig {
        _ = PackageTestEnvironment.keychain
        let services = try (0..<memberCount).map {
            try MeshPartitionFixtures.identity("delivery\($0)")
        }
        let founder = try #require(services.first)
        let meshID = UUID()
        let ledger = try MeshPartitionFixtures.ledger(
            founder: founder, others: Array(services.dropFirst()), meshID: meshID
        )
        var byFingerprint: [String: IdentityService] = [:]
        for service in services { byFingerprint[service.localFingerprint] = service }
        let rig = MeshDeliveryRig(meshID: meshID, identities: byFingerprint, ledger: ledger)
        // An unprovisioned identity reports a placeholder fingerprint, which would silently dedupe
        // the roster and make every assertion below vacuous (P4 item 1's lesson).
        #expect(rig.roster.memberCount == memberCount)
        return rig
    }

    /// A branch view over `rig`'s roster in which only `reachable` can be reached.
    static func branch(_ rig: MeshDeliveryRig, selfFingerprint: String, reachable: [String]) -> MeshBranchView {
        MeshBranchView(
            roster: rig.roster, reachable: Set(reachable), selfFingerprint: selfFingerprint
        )
    }
}
