// TapRendezvousTests.swift
// ProximityKitTests
//
// The tap rendezvous's two privacy requirements (Fernlet's World Friends spec §1.5): P1, nothing that
// identifies a person crosses before both people say yes, and P2, everything sent before the tap is
// short-lived, rotates and carries nothing across a rotation. The link cells drive two state machines
// back to back and read every byte each one put on the wire, sealed and opened; the engine cells drive
// the engine over a radio fake of their own.

import CryptoKit
import Foundation
import Testing
@testable import ProximityKit

// MARK: - Support

/// The profile every cell uses: the package namespace's pair row under its own `tap` mode.
private let tapProfile = ProximityTapRendezvousProfile(
    pair: ProximityPairProfile(
        auditArea: "tapTest", radio: ProximityNamespace.packageTest.family.radios.pair, advertisementMode: "tap"),
    cardSignature: .featureSignature("pktest.feature.tap-card.v1", framing: .lengthPrefixed),
    sealSalt: .featureKeyDerivationSalt("pktest.feature.tap-seal.v1")
)

/// A person's long-term identity, in memory, with a count of how often it signed.
@MainActor
private final class Person {
    let name: String
    let signing = Curve25519.Signing.PrivateKey()
    let agreement = Curve25519.KeyAgreement.PrivateKey()
    var signatures = 0
    var signatureOverride: Data?

    init(_ name: String) { self.name = name }

    /// The 16-hex-character fingerprint the engine reports, computed here without the identity type.
    var fingerprint: String {
        String(SHA256.hash(data: signing.publicKey.rawRepresentation).map { String(format: "%02x", $0) }
            .joined().prefix(16))
    }

    var identity: TapRendezvousLongTermIdentity {
        TapRendezvousLongTermIdentity(
            signingKey: signing.publicKey.rawRepresentation,
            keyAgreementKey: agreement.publicKey.rawRepresentation,
            sign: { [self] data in
                signatures += 1
                return try signatureOverride ?? signing.signature(for: data)
            }
        )
    }

    /// Byte strings that would identify this person if they appeared on the wire: each key raw and as
    /// the base64 a JSON frame would carry it in, the fingerprint, and the name.
    var identifyingBytes: [Data] {
        let keys = [signing.publicKey.rawRepresentation, agreement.publicKey.rawRepresentation]
        return keys + keys.map { Data($0.base64EncodedString().utf8) } + [Data(fingerprint.utf8), Data(name.utf8)]
    }
}

/// Two links wired back to back, with every frame each side sent.
@MainActor
private struct LinkPair {
    var a: TapRendezvousLink
    var b: TapRendezvousLink
    var wireA: [Data] = []
    var wireB: [Data] = []
    var outputsA: [TapRendezvousLinkOutput] = []
    var outputsB: [TapRendezvousLinkOutput] = []

    init() {
        a = TapRendezvousLink(secrets: .fresh(), profile: tapProfile)
        b = TapRendezvousLink(secrets: .fresh(), profile: tapProfile)
    }

    /// Delivers every `.send` in `outputs` to the other side, and on, until nothing is left in flight.
    mutating func pump(_ outputs: [TapRendezvousLinkOutput], fromA: Bool) {
        var queue: [(outputs: [TapRendezvousLinkOutput], fromA: Bool)] = [(outputs, fromA)]
        // R2: bounded; a rendezvous is at most a dozen frames each way.
        for _ in 0..<64 {
            guard !queue.isEmpty else { return }
            let step = queue.removeFirst()
            if step.fromA { outputsA += step.outputs } else { outputsB += step.outputs }
            for case .send(let bytes) in step.outputs {
                if step.fromA {
                    wireA.append(bytes)
                    queue.append((b.receive(bytes), false))
                } else {
                    wireB.append(bytes)
                    queue.append((a.receive(bytes), true))
                }
            }
        }
    }

    /// Hellos both ways, then each side's ranging token.
    mutating func greetAndRange() {
        pump(a.begin(), fromA: true)
        pump(b.begin(), fromA: false)
        pump(a.setLocalRangingToken(Data("token-a".utf8)), fromA: true)
        pump(b.setLocalRangingToken(Data("token-b".utf8)), fromA: false)
    }

    /// Both phones hold within 15 cm for a second.
    mutating func tap(rae: Person, sam: Person) {
        let start = Date(timeIntervalSince1970: 1_000)
        for step in 0..<4 {
            let at = start.addingTimeInterval(Double(step) * 0.4)
            pump(a.distance(0.1, at: at) { (rae.name, Data("look-rae".utf8)) }, fromA: true)
            pump(b.distance(0.1, at: at) { (sam.name, Data("look-sam".utf8)) }, fromA: false)
        }
    }

    /// The messages one side sent, opened with the other side's channel.
    func opened(fromA: Bool) -> [TapRendezvousMessage] {
        let receiver = fromA ? b.channel : a.channel
        return (fromA ? wireA : wireB).compactMap { bytes in
            TapRendezvousEnvelope.decoded(bytes)?.sealed.flatMap { receiver?.open($0) }
        }
    }
}

private func contains(_ haystack: Data, _ needle: Data) -> Bool {
    !needle.isEmpty && haystack.range(of: needle) != nil
}

// MARK: - P1: nothing identifying before both say yes

/// The link's order is the privacy contract: ephemeral hellos, a sealed ranging token, the name and
/// companion only after the tap, the long-term keys only after both said yes.
@MainActor
struct TapRendezvousLinkTests {

    @Test func nothingIdentifyingCrossesBeforeBothSayYes() {
        let rae = Person("Rae Okafor"), sam = Person("Sam Delacroix")
        var pair = LinkPair()
        pair.greetAndRange()
        // Before the tap: no name, no key, no fingerprint, sealed or clear.
        for bytes in pair.wireA { for secret in rae.identifyingBytes { #expect(!contains(bytes, secret)) } }
        #expect(pair.opened(fromA: true).map(\.kind) == [.range])
        pair.tap(rae: rae, sam: sam)
        #expect(pair.outputsA.contains(.tapped) && pair.outputsB.contains(.tapped))
        #expect(pair.outputsA.contains(.ask(name: sam.name, look: Data("look-sam".utf8))))
        #expect(pair.opened(fromA: true).map(\.kind) == [.range, .reveal])
        pair.pump(pair.a.answer(true, identity: rae.identity), fromA: true)
        // Rae said yes, Sam has not: still nothing long-term, and no signature was made.
        #expect(rae.signatures == 0)
        #expect(!pair.opened(fromA: true).contains { $0.kind == .card || $0.signingKey != nil })
        // The wire itself never carries a key, a fingerprint or a name in the clear.
        for bytes in pair.wireA { for secret in rae.identifyingBytes { #expect(!contains(bytes, secret)) } }
        pair.pump(pair.b.answer(true, identity: sam.identity), fromA: false)
        let kindsA = pair.opened(fromA: true).map(\.kind)
        #expect(kindsA == [.range, .reveal, .answer, .card])
        #expect(pair.opened(fromA: false).map(\.kind) == [.range, .reveal, .answer, .card])
        for bytes in pair.wireA + pair.wireB {
            for secret in rae.identifyingBytes + sam.identifyingBytes { #expect(!contains(bytes, secret)) }
        }
        let matchedA = pair.outputsA.compactMap { if case .matched(let m) = $0 { m } else { nil } }
        let matchedB = pair.outputsB.compactMap { if case .matched(let m) = $0 { m } else { nil } }
        #expect(matchedA.map(\.fingerprint) == [sam.fingerprint] && matchedA.first?.displayName == sam.name)
        #expect(matchedB.map(\.signingPublicKey) == [rae.signing.publicKey.rawRepresentation])
    }

    @Test func notNowSendsNoCardAndSignsNothing() {
        let rae = Person("Rae Okafor"), sam = Person("Sam Delacroix")
        var pair = LinkPair()
        pair.greetAndRange()
        pair.tap(rae: rae, sam: sam)
        pair.pump(pair.a.answer(true, identity: rae.identity), fromA: true)
        pair.pump(pair.b.answer(false, identity: nil), fromA: false)
        #expect(pair.outputsA.contains(.end(.declinedThere)))
        #expect(pair.outputsB.contains(.end(.declinedHere)))
        #expect(rae.signatures == 0 && sam.signatures == 0)
        #expect(!(pair.opened(fromA: true) + pair.opened(fromA: false)).contains { $0.kind == .card })
    }

    @Test func aCardBeforeThisPersonSaidYesIsRefused() throws {
        let rae = Person("Rae Okafor"), sam = Person("Sam Delacroix")
        var pair = LinkPair()
        pair.greetAndRange()
        pair.tap(rae: rae, sam: sam)
        let channel = try #require(pair.b.channel)
        let early = TapRendezvousMessage(
            kind: .card, sequence: 3, signingKey: sam.signing.publicKey.rawRepresentation,
            keyAgreementKey: sam.agreement.publicKey.rawRepresentation, signature: Data(count: 64))
        let bytes = try TapRendezvousEnvelope.sealed(channel.seal(early)).encoded()
        #expect(pair.a.receive(bytes) == [.end(.refused("a card before both said yes"))])
    }

    @Test func aRelayThatSwapsTheHellosReadsNothing() {
        var a = TapRendezvousLink(secrets: .fresh(), profile: tapProfile)
        var b = TapRendezvousLink(secrets: .fresh(), profile: tapProfile)
        var relayToA = TapRendezvousLink(secrets: .fresh(), profile: tapProfile)
        var relayToB = TapRendezvousLink(secrets: .fresh(), profile: tapProfile)
        guard case .send(let helloA) = a.begin().first, case .send(let helloRA) = relayToA.begin().first,
              case .send(let helloRB) = relayToB.begin().first else { Issue.record("no hello"); return }
        _ = a.receive(helloRA)
        _ = b.receive(helloRB)
        _ = relayToA.receive(helloA)
        guard case .send(let range) = a.setLocalRangingToken(Data("token-a".utf8)).first else {
            Issue.record("no range"); return
        }
        // Forwarded unchanged to B, Rae's sealed token does not open under B's key with the relay.
        #expect(b.receive(range).first.map { if case .end(.refused) = $0 { true } else { false } } == true)
    }

    @Test func aReflectedHelloIsRefused() {
        var a = TapRendezvousLink(secrets: .fresh(), profile: tapProfile)
        guard case .send(let hello) = a.begin().first else { Issue.record("no hello"); return }
        #expect(a.receive(hello) == [.end(.refused("a second, malformed or reflected hello"))])
    }

    @Test func aCardSignedForAnotherRendezvousDoesNotVerify() {
        let rae = Person("Rae Okafor"), sam = Person("Sam Delacroix")
        var first = LinkPair()
        first.greetAndRange()
        first.tap(rae: rae, sam: sam)
        first.pump(first.a.answer(true, identity: rae.identity), fromA: true)
        first.pump(first.b.answer(true, identity: sam.identity), fromA: false)
        let stale = first.opened(fromA: false).first { $0.kind == .card }?.signature
        sam.signatureOverride = stale
        var second = LinkPair()
        second.greetAndRange()
        second.tap(rae: rae, sam: sam)
        second.pump(second.a.answer(true, identity: rae.identity), fromA: true)
        second.pump(second.b.answer(true, identity: sam.identity), fromA: false)
        #expect(second.outputsA.contains(.end(.refused("the card's signature does not verify"))))
        #expect(!second.outputsA.contains { if case .matched = $0 { true } else { false } })
    }
}

// MARK: - P2: short-lived, rotating, unlinkable

/// A radio fake that records what it was started with and mints a session id per start, as the pair
/// radio's posture does.
@MainActor
private final class RecordingPairRadio: ProximityPairRadioSession {
    var onPeerDiscovered: ((PeerHandle) -> Void)?
    var onPeerLost: ((PeerHandle) -> Void)?
    var onPeerChannelReady: ((NetworkPeerChannel) -> Void)?
    var onPeerDisconnected: ((PeerHandle, String) -> Void)?
    var onTransportError: ((String) -> Void)?
    var resolveDialer: ((String) -> PeerHandle?)?
    var shouldAcceptDialer: ((PeerHandle) -> Bool)?
    let isDiscoveryPaused = false
    private(set) var advertisedSessionID = ""
    let connectedPeers: [PeerHandle] = []
    private(set) var advertisements: [[String: String]] = []
    private(set) var sessionIDs: [String] = []
    private(set) var stops = 0

    func start(advertisement: [String: String]) throws {
        advertisements.append(advertisement)
        advertisedSessionID = UUID().uuidString
        sessionIDs.append(advertisedSessionID)
    }
    func stop() {
        stops += 1
        advertisedSessionID = ""
    }
    func dial(_ peer: PeerHandle, helloSID: String) {}
    func endTunnel(_ peer: PeerHandle) {}
    func hasConnectingPeers(besides peer: PeerHandle?) -> Bool { false }
    func pauseDiscovery() {}
    func resumeDiscovery() {}
    func channel(for peer: PeerHandle) -> NetworkPeerChannel { NetworkPeerChannel(peer: peer, host: Sink()) }

    /// A channel host that drops every send.
    private final class Sink: NetworkChannelHost {
        func send(_ data: Data, to peer: PeerHandle, mode: PeerDeliveryMode) async throws {}
        func openTransferCount(for peer: PeerHandle) -> Int { 0 }
    }
}

/// Every start and every rotation is a new stranger: fresh secrets, a fresh radio posture, and an
/// advertisement that names nobody.
@MainActor
struct TapRendezvousRotationTests {

    @Test func everyStartAndRotationIsAFreshStranger() {
        let host = PackageTestHost()
        let radio = RecordingPairRadio()
        let engine = ProximityTapRendezvous(
            host: host, profile: tapProfile, makeRadio: { radio }, makeRanging: { MockRangingProvider() }, now: Date.init)
        engine.start()
        let first = engine.secrets.hello
        engine.rotate()
        let second = engine.secrets.hello
        engine.stop()
        engine.start()
        let third = engine.secrets.hello
        engine.stop()
        let hellos = [first, second, third]
        #expect(Set(hellos.map(\.ephemeralKey)).count == 3)
        #expect(Set(hellos.map(\.nonce)).count == 3)
        #expect(Set(radio.sessionIDs).count == 3 && radio.advertisements.count == 3)
        #expect(radio.stops == 3 && engine.rotations == 3)
        // The owner's fields are the version and the mode alone: no name, no fingerprint, no mesh.
        for advertisement in radio.advertisements {
            #expect(advertisement == ["v": "1", "mode": "tap"])
        }
    }

    @Test func theRotationIsAtMostPresencesEpochAndASlowQuestionCannotHoldItForever() {
        #expect(TapRendezvousFormat.rotationInterval <= 900)
        #expect(ProximityTapRendezvous.questionTimeout < TapRendezvousFormat.rotationInterval)
        #expect(TapRendezvousFormat.closeDistanceMeters == 3.0 && TapRendezvousFormat.tapDistanceMeters == 0.15)
    }

    @Test func aStoppedRendezvousForgetsEverything() {
        let host = PackageTestHost()
        let radio = RecordingPairRadio()
        let engine = ProximityTapRendezvous(
            host: host, profile: tapProfile, makeRadio: { radio }, makeRanging: { MockRangingProvider() }, now: Date.init)
        engine.start()
        radio.onPeerDiscovered?(PeerHandle(
            id: UUID(), displayHint: "", discoveryInfo: ["v": "1", "mode": "tap", "sid": "zzz"], advertisedFingerprint: nil))
        engine.stop()
        #expect(!engine.isRunning && engine.closeness == nil && engine.question == nil)
        #expect(engine.advertisedSessionIDForTesting.isEmpty)
    }
}

// MARK: - The mesh's narrowed stranger door

/// A host that meets new people by tapping narrows the mesh's open doors to the keys it already has a
/// reason to admit. Every other stranger is refused at the channel introduction, with nothing recorded.
struct MeshStrangerDoorTests {

    @Test func narrowedDoorsAdmitOnlyTheirKeys() {
        let meshID = UUID()
        let local = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "local")
        let matched = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "matched")
        let bystander = MeshIntroductionHarness.endpoint(meshID: meshID, sessionID: "bystander")
        let roster = MeshIntroductionRoster(
            members: [local.hello.signingPublicKey], admitsStrangersProvisionally: true,
            admissibleStrangers: [matched.hello.signingPublicKey])
        var nonces = MeshIntroductionNonceCache()
        var forMatched = MeshChannelIntroductionExchange(role: .responder, localHello: local.hello)
        var forBystander = MeshChannelIntroductionExchange(role: .responder, localHello: local.hello)
        #expect(forMatched.receive(matched.hello, roster: roster, nonces: &nonces) == nil)
        #expect(forBystander.receive(bystander.hello, roster: roster, nonces: &nonces) == .unknownIdentity)
        #expect(forBystander.bind(channelBindingHash: MeshIntroductionHarness.binding) == nil)
    }

    @Test func unnarrowedDoorsAreUnchangedAndShutDoorsAdmitNobody() {
        let key = Data(repeating: 7, count: 32)
        #expect(MeshIntroductionRoster(members: [], admitsStrangersProvisionally: true).admitsStrangerProvisionally(key))
        #expect(!MeshIntroductionRoster(members: [], admissibleStrangers: [key]).admitsStrangerProvisionally(key))
        let many = Set((0..<40).map { Data(repeating: UInt8($0), count: 32) })
        let capped = MeshIntroductionRoster(members: [], admitsStrangersProvisionally: true, admissibleStrangers: many)
        #expect(capped.admissibleStrangers?.count == MeshIntroductionRoster.maxAdmissibleStrangers)
    }
}

/// A yes can be taken back while the other person has not answered, and a yes nobody answers ends.
@MainActor
struct TapRendezvousWaitingTests {

    @Test func withdrawingWithNothingUpIsANoOpAndTheWaitIsBounded() {
        let host = PackageTestHost()
        let engine = ProximityTapRendezvous(
            host: host, profile: tapProfile, makeRadio: { RecordingPairRadio() }, makeRanging: { MockRangingProvider() },
            now: Date.init)
        engine.start()
        engine.withdraw()
        engine.sweep()
        #expect(engine.isRunning && engine.question == nil && !engine.isWaitingForPeer)
        #expect(ProximityTapRendezvous.questionTimeout <= 120)
        engine.stop()
    }
}
