// MeshSessionIDClaimTests.swift
// ProximityKitTests
//
// 2026-09-23 — a reviewer's note on 31fafd6. The `sid` in the QUIC channel introduction's hello is
// NOT in the signed transcript, and it is what resolves an inbound tunnel to the browsed
// advertisement it came from (`MeshLinkTable.key(advertisingSessionID:)`). Every advertisement's
// `sid` is public in its TXT record, so a verified peer — a member, or a stranger while the join
// doors are open — could claim an ABSENT member's `sid`, take that member's browsed key, and hold it
// until its own tunnel ended. The member's re-link was then refused as a duplicate of the
// claimant's tunnel, this device's dial to it was refused as "already connected", and the re-dial
// sweep passed it over because a live tunnel carried its `sid`. Signing the field would not help:
// nothing binds an advertisement to a key (the TXT withholds `fp` on purpose), so a signature would
// only prove the claimant chose the claim.
//
// What this device CAN verify is its own dial: a tunnel it opened to an advertisement's endpoint
// proves who answers there. The claims walled here:
//
//  1. A claim cannot take an advertisement a dial of this device's proved belongs to another key.
//  2. A claim never REFUSES a member because another key holds the advertisement its `sid` names:
//     the member keeps its own connection key and re-links.
//  3. The re-dial sweep trusts a proven owner over a claimed `sid`, so a claimant's tunnel carrying
//     the member's `sid` cannot keep the member from being re-dialed.
//  4. Honest paths do not move: a re-dial by the proven owner still lands on its advertisement,
//     and every rule falls back to what it did when nothing is proven.
//  5. The residual is stated, not implied: before any dial of this device's has proven who answers
//     an advertisement and while no tunnel holds it, a claimant can still name it first.
//  6. The proven-owner record is bounded by the endpoint cache, and the radio asks the table at all
//     three sites (the call sites are pinned by source needle: the session actor's framework half
//     is not reachable at tier 1).
//
// Nothing here opens a socket or sleeps: the table is a value type, and the session's half is driven
// through the same functions the radio calls.

import Foundation
import Testing
@testable import ProximityKit

// MARK: - MeshSessionIDClaimTests

/// A `sid` is a claim: it may not take an advertisement a dial proved for another key, may not lock a
/// member out of its own re-link, and may not stop the sweep re-dialing it.
@MainActor
@Suite(.serialized)
struct MeshSessionIDClaimTests {

    static let member = Data(repeating: 0x11, count: 32)
    static let claimant = Data(repeating: 0x22, count: 32)
    static let memberSID = "member-sid"
    /// The member's browsed advertisement.
    static let advertisement = MeshLinkKey("browsed-member")

    static func verified(_ signingPublicKey: Data, claiming sessionID: String) -> MeshVerifiedPeer {
        MeshVerifiedPeer(signingPublicKey: signingPublicKey, fingerprint: "claim-fp", sessionID: sessionID)
    }

    static func record(_ key: MeshLinkKey, sessionID: String?) -> MeshEndpointRecord {
        MeshEndpointRecord(
            key: key, instanceName: "fernlet-mesh-\(key.rawValue)",
            advertisement: sessionID.map { [MeshLinkAdvertisement.sessionIDKey: $0] } ?? [:],
            lastSeenAt: Date()
        )
    }

    /// A stopped session that has browsed the member's advertisement and whose owner admits. Its
    /// own `sid` outranks the member's, so THIS device is the member's designated dialer — the
    /// direction in which a member that lost its link waits to be dialed rather than dialing.
    static func session() -> NetworkMeshSession {
        let session = NetworkMeshSession()
        session.updateDiscoveryInfo([MeshLinkAdvertisement.sessionIDKey: "zzzz-local"])
        session.invitationGate = { _ in true }
        session.rememberBrowsedForTesting(
            advertisement, instanceName: "fernlet-mesh-member",
            advertisement: [MeshLinkAdvertisement.sessionIDKey: memberSID]
        )
        return session
    }

    // MARK: Claim 1 — a dial's proof outranks a claim

    /// The reviewer's squat on a member this device has dialed before: the member's link drops,
    /// and a claimant names its `sid`. It used to take the member's advertisement.
    @Test func aClaimCannotTakeAnAdvertisementADialProvedBelongsToAnotherKey() throws {
        let session = Self.session()
        session.bookTunnelForTesting(
            Self.advertisement, role: .initiator, verified: Self.verified(Self.member, claiming: Self.memberSID)
        )
        #expect(session.linkTableForTesting.provenOwner(of: Self.advertisement) == Self.member,
                "precondition: this device's own dial proved who answers the advertisement")
        // The member's tunnel ends through the radio's one removal funnel. A booked tunnel carries
        // no control stream, so `endTunnel` books the end as a failed dial (backing off) rather than
        // a close (idle) — either way nothing holds the advertisement, which is the state that
        // matters: the member is gone.
        session.disconnectPeer(try #require(session.connectedPeers.first))
        #expect(!session.tunnelKeysForTesting.contains(Self.advertisement), "precondition: the member is gone")
        let before = session.linkTableForTesting.phase(of: Self.advertisement)

        let connection = MeshLinkKey("quic-connection-claimant")
        let key = session.admitVerifiedInboundForTesting(
            Self.verified(Self.claimant, claiming: Self.memberSID), pendingKey: connection
        )

        #expect(key == connection, "the claimant keeps its own connection key")
        #expect(session.linkTableForTesting.phase(of: Self.advertisement) == before,
                "and the member's advertisement is left exactly as it was, free for this device's re-dial")
        #expect(session.linkTableForTesting.phase(of: Self.advertisement) != .connected)
    }

    // MARK: Claim 2 — a claim never refuses the member

    /// The advertisement is held by a tunnel verified as a DIFFERENT key (here the residual put it
    /// there). The member dials back claiming its own `sid`, and used to be refused as a duplicate —
    /// locked out until the claimant's tunnel ended.
    @Test func aMemberIsNeverRefusedBecauseAnotherKeyHoldsTheAdvertisementItsSIDNames() {
        let session = Self.session()
        let claimantConnection = MeshLinkKey("quic-connection-claimant")
        let taken = session.admitVerifiedInboundForTesting(
            Self.verified(Self.claimant, claiming: Self.memberSID), pendingKey: claimantConnection
        )
        #expect(taken == Self.advertisement, """
            the documented residual: before any dial of this device's has proven who answers the \
            advertisement, and while no tunnel holds it, a claimant can still name it first
            """)
        session.bookTunnelForTesting(
            Self.advertisement, role: .responder, verified: Self.verified(Self.claimant, claiming: Self.memberSID)
        )

        let memberConnection = MeshLinkKey("quic-connection-member")
        let key = session.admitVerifiedInboundForTesting(
            Self.verified(Self.member, claiming: Self.memberSID), pendingKey: memberConnection
        )

        #expect(key == memberConnection, "the member links under its own connection key instead of being refused")
        #expect(session.linkTableForTesting.phase(of: memberConnection) == .connected)
    }

    // MARK: Claim 3 — the sweep trusts a proof over a claim

    /// A claimant's tunnel carrying the member's `sid` made the member read as "already connected
    /// under another key", so the sweep never offered it for a re-dial. With a proven owner the
    /// question is that identity among the live tunnels, which no claim can fake.
    @Test func theReDialSweepTrustsAProvenOwnerOverAClaimedSID() {
        var table = MeshLinkTable()
        let key = MeshLinkKey("browsed")
        table.remember(Self.record(key, sessionID: Self.memberSID))

        #expect(table.sweepSkips(key, liveSessionIDs: [Self.memberSID], liveSigningKeys: [Self.claimant]),
                "unproven: a live tunnel claiming the sid reads as connected — the old rule, unchanged")
        #expect(!table.sweepSkips(key, liveSessionIDs: [], liveSigningKeys: []))

        table.noteProvenOwner(key, signingPublicKey: Self.member)
        #expect(!table.sweepSkips(key, liveSessionIDs: [Self.memberSID], liveSigningKeys: [Self.claimant]),
                "proven: a claimant's tunnel carrying the member's sid no longer keeps the member from being re-dialed")
        #expect(table.sweepSkips(key, liveSessionIDs: [], liveSigningKeys: [Self.member]),
                "while the member really connected under another key is still passed over")

        let bare = MeshLinkKey("no-sid")
        table.remember(Self.record(bare, sessionID: nil))
        #expect(table.sweepSkips(bare, liveSessionIDs: [], liveSigningKeys: []),
                "an advertisement with no sid is passed over, as it always was")
    }

    // MARK: Claim 4 — honest paths do not move

    /// The member dials back after a drop: its claim is its own `sid` and its key is the proven one,
    /// so it lands on its advertisement exactly as it did — the collision the table exists to rank.
    @Test func theProvenOwnersReDialStillLandsOnItsAdvertisement() throws {
        let session = Self.session()
        session.bookTunnelForTesting(
            Self.advertisement, role: .initiator, verified: Self.verified(Self.member, claiming: Self.memberSID)
        )
        session.disconnectPeer(try #require(session.connectedPeers.first))

        let key = session.admitVerifiedInboundForTesting(
            Self.verified(Self.member, claiming: Self.memberSID), pendingKey: MeshLinkKey("quic-connection-redial")
        )

        #expect(key == Self.advertisement)
    }

    /// The claim rule refuses only what a proof contradicts.
    @Test func theClaimRuleRefusesOnlyWhatAProofContradicts() {
        var table = MeshLinkTable()
        let key = MeshLinkKey("browsed")
        table.remember(Self.record(key, sessionID: Self.memberSID))

        #expect(table.claimResolves(key, to: Self.member, heldBy: nil), "nothing proven, nobody holding it")
        #expect(table.claimResolves(key, to: Self.member, heldBy: Self.member),
                "the same identity holding it: the duplicate path decides, as before")
        #expect(!table.claimResolves(key, to: Self.member, heldBy: Self.claimant), "another identity holds it")

        table.noteProvenOwner(key, signingPublicKey: Self.member)
        #expect(table.claimResolves(key, to: Self.member, heldBy: nil), "the proven owner's own claim")
        #expect(!table.claimResolves(key, to: Self.claimant, heldBy: nil), "a dial proved somebody else answers it")
    }

    // MARK: Claim 6 — bounded, and asked at every site

    @Test func aProvenOwnerIsBoundedByTheEndpointCache() {
        var table = MeshLinkTable()
        table.noteProvenOwner(MeshLinkKey("never-browsed"), signingPublicKey: Self.member)
        #expect(table.provenOwnerCount == 0, "an endpoint the cache does not hold is not recorded")

        let forgotten = MeshLinkKey("forgotten")
        table.remember(Self.record(forgotten, sessionID: "a"))
        table.noteProvenOwner(forgotten, signingPublicKey: Self.member)
        #expect(table.provenOwnerCount == 1)
        table.forget(forgotten)
        #expect(table.provenOwnerCount == 0, "the browser's lost takes it with the cache entry")

        let oldest = MeshLinkKey("oldest")
        table.remember(Self.record(oldest, sessionID: "b"))
        table.noteProvenOwner(oldest, signingPublicKey: Self.member)
        // R2: bounded by the cache cap.
        for index in 0..<MeshLinkTable.maxCachedEndpoints {
            table.remember(Self.record(MeshLinkKey("filler-\(index)"), sessionID: "f\(index)"))
        }
        #expect(table.provenOwner(of: oldest) == nil, "the oldest-first eviction takes it with its entry")

        let last = MeshLinkKey("last")
        table.remember(Self.record(last, sessionID: "c"))
        table.noteProvenOwner(last, signingPublicKey: Self.member)
        table.removeAll()
        #expect(table.provenOwnerCount == 0, "and teardown takes everything")
    }

    /// The session actor's framework half (`runInitiator`, the browser, the listener) is not
    /// reachable at tier 1, so the three places it must ask the table are pinned by needle: a dial's
    /// activation records the proof, the inbound path resolves through the claim rule, and the
    /// sweep asks the table rather than comparing `sid`s itself.
    @Test func theRadioAsksTheTableAtAllThreeSites() throws {
        let source = try PackageRoot.source("Sources/ProximityKit/Transport/NetworkMeshSession.swift")
        func body(of header: String) -> Substring? {
            guard let start = source.range(of: header) else { return nil }
            let rest = source[start.upperBound...]
            let end = rest.range(of: "\n    func ")?.lowerBound ?? rest.endIndex
            return rest[..<end]
        }

        #expect(body(of: "func activate(")?.contains("links.noteProvenOwner(") == true,
                "a dial's verified key is recorded as the advertisement's proven owner")
        #expect(body(of: "func admitVerifiedInbound(")?.contains("inboundKey(for:") == true,
                "the inbound path keys a tunnel through the claim rule")
        #expect(body(of: "func inboundKey(")?.contains("links.claimResolves(") == true)
        #expect(body(of: "func reproposeIdleBrowsedPeers(")?.contains("links.sweepSkips(") == true,
                "the sweep asks the table who is reachable")
    }
}
