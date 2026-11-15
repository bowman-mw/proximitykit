// PairNameDisclosureTests.swift
// ProximityKitTests
//
// SEC-L29 (0.2.0): the pair radio (Fernlet's recipe radio) stops advertising the device's name. The
// record carries the host's rotating friend tags instead, a kept friend's phone names the row from its
// own records through `ProximityPairSession.resolveFriendName`, and a stranger sees the host's
// peer-name floor. The name goes back on the air only when the host opts in with
// `setNameDisclosure(toEveryone: true, …)`.
//
// What the cells hold:
//
//   - the record: by default no `name` key at all, the friend tags present; with the opt-in, the name;
//   - the read: a full roster of tags survives the inbound bound (both chunks) and every entry fits one
//     DNS-SD TXT entry, so a friend twenty tags deep is still recognized;
//   - the naming: a record whose tags match is named by the host's resolver, ahead of any advertised
//     name; a record with neither tags that match nor a name shows the floor;
//   - the republish: a changed record re-registers a running radio under a fresh `sid`, and an
//     unchanged one does not.
//
// Every cell runs the real radio with its framework objects suppressed, so nothing starts Bonjour.

import Foundation
@testable import ProximityKit
import Testing

/// The pair radio's name disclosure (SEC-L29): friends by tag, strangers see nothing, everyone only by
/// opt-in.
@Suite @MainActor struct PairNameDisclosureTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built.
    let keychain = PackageTestEnvironment.keychain

    /// **By default the record carries no name, only the friend tags.**
    @Test func theRecordCarriesNoNameUnlessTheHostOptsIn() throws {
        let host = PackageTestHost(displayName: "Robin")
        let (radio, session) = try makeSession(on: host)
        session.setNameDisclosure(toEveryone: false, friendTags: ["AAAAAAAAAAA=", "BBBBBBBBBBB="])
        let quiet = radio.advertisedFieldsForTesting
        #expect(quiet[ProximityPairAdvertisement.nameKey] == nil, "the default record still names the device: \(quiet)")
        #expect(ProximityPairAdvertisement.friendTags(from: quiet, mode: radio.advertisementMode)
                == ["AAAAAAAAAAA=", "BBBBBBBBBBB="], "the friend tags are not on the air: \(quiet)")
        #expect(!session.advertisesNameToEveryone)

        session.setNameDisclosure(toEveryone: true, friendTags: ["AAAAAAAAAAA="])
        let open = radio.advertisedFieldsForTesting
        #expect(open[ProximityPairAdvertisement.nameKey] == "Robin", "the opt-in did not publish the name: \(open)")
        #expect(session.advertisesNameToEveryone)
        session.stop()
        try host.tearDown()
    }

    /// **A full roster of friend tags survives the read, and every entry fits the TXT limit.**
    @Test func aFullRosterOfFriendTagsSurvivesTheInboundBound() {
        let tags = Set((0..<ProximityPairAdvertisement.maxFriendTags).map { String(format: "tag%08d=", $0) })
        let owner = ProximityPairAdvertisement.ownerFields(mode: "pair", name: "", friendTags: tags)
        let published = ProximityPairAdvertisement.publishedFields(
            from: owner, sessionID: UUID().uuidString)
        #expect(ProximityPairAdvertisement.entriesFitTheTXTLimit(published), "an entry overflows: \(published)")
        let read = ProximityPairAdvertisement.advertisement(from: published)
        #expect(ProximityPairAdvertisement.friendTags(from: read, mode: "pair") == tags,
                "the read lost tags: \(read)")
        #expect(read[ProximityPairAdvertisement.sessionIDKey] == published[ProximityPairAdvertisement.sessionIDKey])
        let extra = ProximityPairAdvertisement.ownerFields(
            mode: "pair", name: "", friendTags: tags.union(["zzzzzzzzzzz="]))
        #expect(ProximityPairAdvertisement.friendTags(from: extra, mode: "pair").count
                == ProximityPairAdvertisement.maxFriendTags, "the record carries more tags than the cap")
    }

    /// **A kept friend is named by the host's resolver; a stranger shows the floor.**
    @Test func aKeptFriendIsNamedByItsTagsAndAStrangerByTheFloor() throws {
        let host = PackageTestHost()
        let (radio, session) = try makeSession(on: host)
        session.resolveFriendName = { tags in tags.contains("friendtag01=") ? "Sam" : nil }

        browse("f00000000001", tags: ["friendtag01="], name: "Spoofed", sid: "sam-sid", on: radio)
        browse("f00000000002", tags: ["unknowntag1="], name: "", sid: "stranger-sid", on: radio)
        let names = session.nearbyPeers.map(\.displayName).sorted()
        let floor = host.proximityNamespace.installation.peerNames.floor
        #expect(names == [floor, "Sam"].sorted(), "the rows were named \(names)")
        session.stop()
        try host.tearDown()
    }

    /// **A changed record re-registers the radio under a fresh `sid`; an unchanged one does not.**
    @Test func aChangedRecordReRegistersUnderAFreshSessionID() throws {
        let host = PackageTestHost()
        let (radio, session) = try makeSession(on: host)
        session.setNameDisclosure(toEveryone: false, friendTags: ["AAAAAAAAAAA="])
        let first = radio.advertisedSessionID
        session.setNameDisclosure(toEveryone: false, friendTags: ["AAAAAAAAAAA="])
        #expect(radio.advertisedSessionID == first, "an unchanged record re-minted the posture")
        session.setNameDisclosure(toEveryone: false, friendTags: ["CCCCCCCCCCC="])
        #expect(radio.advertisedSessionID != first && !radio.advertisedSessionID.isEmpty,
                "the rotated friend tags went out under the old sid")
        session.stop()
        try host.tearDown()
    }

    // MARK: - Helpers

    private func makeSession(on host: PackageTestHost) throws -> (NetworkPairSession, ProximityPairSession) {
        let profile = ProximityPairProfile(
            auditArea: "pktest.pair", radio: host.proximityNamespace.family.radios.pair, advertisementMode: "pair")
        let radio = NetworkPairSession(namespace: host.proximityNamespace, profile: profile)
        try radio.runWithoutRadiosForTesting()
        let session = ProximityPairSession(host: host, profile: profile, makeRadio: { radio })
        session.markRunningForTesting()
        return (radio, session)
    }

    private func browse(
        _ suffix: String, tags: Set<String>, name: String, sid: String, on radio: NetworkPairSession
    ) {
        let instance = ProximityNamespace.packageTest.family.radios.meshInstanceNamePrefix + suffix
        let key = MeshLinkKey("\(instance).\(radio.serviceType).local.")
        let record = ProximityPairAdvertisement.publishedFields(
            from: ProximityPairAdvertisement.ownerFields(mode: radio.advertisementMode, name: name, friendTags: tags),
            sessionID: sid)
        radio.noteBrowsedForTesting(key, instanceName: instance, advertisement: record)
    }
}
