// MeshRoutedPhotoDeliveryTests.swift
// ProximityKitTests
//
// Network migration P5 item 13 (plan §11, §12's photo bullet): the friend-photo wall, end to end,
// on the routed store — and the three `keyEpoch` gates retired with the path that carried it.
//
// Tier 1 only: `FakePeerNetwork` + `FakeMeshTransportSession` + an injected clock, no radio and no
// wall-clock sleeps. The rig is `MeshRoutedDrainRig`, item 6's, extended by one seam — the
// handshake-verified agreement keys a real mint needs, which the drain's own cells never needed
// because `MeshRoutedDrainItem.mint` hands the whole roster's keys over by hand.
//
// Three fixture facts this suite is built on, each of which the drain rig paid for once:
//
// - **One pinned install binding.** `MeshP3Acceptance.install`, around every store-touching call —
//   including `addPhoto`, which now writes the routed store on the SENDER's side.
// - **The gate starts closed.** `MeshNetworkManager.routedAccessGate` is `.closed` until the app
//   pushes it, so a cell that wants plaintext must open it and a cell that wants ciphertext-only
//   custody simply does not.
// - **The rig's nodes are joiner-shaped**, so no node has a `sessionCeiling`; every routed instant
//   derives from `MeshRoutedDrainRig.createdAt` and the manager's own `routedHardDeadline`.
//
// A partial copy (ProximityKit plan step A1.3's batch D, the routed track): of the Fernlet
// repository's FernletTests file of the same name, this holds only the one cell of
// `MeshKeyAdvertisementDeliveryTests` that reads ProximityKit's source,
// `theKeyAgreementFrameIsRoutedDecodedAndDispatched`, under its suite's name and its own; the suite's
// other cells, the rig extension and the fixtures, and the file's other suites stay there, so what
// this header and the suite's doc say of them is not held here.

import Foundation
import Testing

/// What the key advertisement buys the mint, and what it deliberately does not.
///
/// Every cell here drives the real doors: the real send at a real link-open, the real membership
/// dispatch at the receiver, the real verifier against the receiver's own admission set. The rig's
/// one seam is `armKeyAdvertisements()`, which calls the production self-mint — the tier-1 rigs arm
/// their ledgers through a seed that bypasses both arming doors, so without it no node would have
/// its own row to relay.
///
/// The honest labels, which the plan's §11.3/§23.4 rewrite must use verbatim: of D-13.22's three
/// refusals the advertisement converts **one** into a delivery (the resumption, `R-16`) and the
/// other two — the **star** and the **over-cap roster** — into a successful mint whose delivery
/// waits for a link or a departure hand-off. `relayInFlight` is increment 2's, so a destination that
/// holds an item never forwards it: a cell that asserted only "`.staged`, no refusal" would be green
/// while the unlinked member held nothing at all.
@MainActor
@Suite(.serialized)
struct MeshKeyAdvertisementDeliveryTests {

    /// **Three lines carry the frame in, and a missing one of them is SILENT.** Pinned by source.
    ///
    /// This is not paranoia: the first draft of pass B had the `decodeMembershipFrame` arm, the
    /// `DecodedMembershipRecord` case and the dispatch arm — and not the top-level routing line — and
    /// every advertisement was dropped at the dispatch switch's `default` with no audit line at all.
    /// Two of the three are compile-fenced (`mergeOffer(for:)`, `insertMembershipRecord` and
    /// `bufferedForAdoption` are `default`-free switches over `DecodedMembershipRecord`); the other
    /// two are not, and `decodeMembershipFrame`'s `default: return nil` plus
    /// `dispatchMembershipEventPayload`'s unaudited `guard let decoded` is exactly how a forgotten
    /// arm becomes a frame that never arrived.
    @Test func theKeyAgreementFrameIsRoutedDecodedAndDispatched() throws {
        let source = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift")
        )
        #expect(source.contains(".meshInventoryDigest, .meshEpochHeads, .meshKeyAgreement:"),
                "the top-level switch must route the token to the membership-event family")
        #expect(source.contains("case .meshKeyAgreement:"),
                "decodeMembershipFrame must have its own arm, or the frame decodes to nil")
        #expect(source.contains("case .keyAdvertisements(let payload) = decoded"),
                "and the dispatch must hand the decoded batch to the receive door")
        #expect(source.contains("receiveKeyAdvertisements(payload, from: senderFingerprint)"),
                "with the AUTHENTICATED sender, never the frame's own audit-only field")
    }
}
