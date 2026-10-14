// ProximityPresenceSessionTests.swift
// ProximityKitTests
//
// ProximityKit plan step A1.1: the presence engine, `ProximityPresenceSession`, built and driven in
// ProximityKit's own package tests over an in-memory radio, so the engine's contract travels with the
// package rather than living only in its host's suites. Every cell builds a session under the package
// tests' namespace (`.packageTest`), hands it the radio below through its internal `makeRadio` seam and
// mints its postures through the engine's own production mint, so no cell starts Bonjour (the unit-test
// invariant for proximity). A boundary is crossed with a clock reading 1 800 seconds on, which is always
// a later presence epoch.
//
// What the cells hold, each a fact of the engine's own that no other package cell reached: a sighting
// under a name the session wore, or of another record version, never reaches the host, and the ring of
// worn names forgets only its oldest name past its cap; a failed mint drops the worn posture, so the
// radio is never re-advertised under the previous epoch's name; a start and a republish advertise the
// very tags they are handed, with every hook of the radio wired before it starts; each of the radio's
// hooks reaches the host's hook it stands for and no other; and the engine and its radio are released
// when the host lets go of them without a stop.

import Foundation
@testable import ProximityKit
import Testing

/// The presence engine's contract, over an in-memory radio: self-exclusion by name and version, the
/// failed-mint stand-down, the advertised record, the hooks' forwarding and the release without a stop.
@Suite @MainActor struct ProximityPresenceSessionTests {

    /// A clock reading that is not on an epoch boundary, so a reading 1 800 seconds on is two epochs
    /// later and never the same epoch.
    private static let start = Date(timeIntervalSince1970: 1_780_000_000)

    /// Seconds that always cross at least one presence epoch boundary (an epoch is 900 seconds).
    private static let acrossABoundary: TimeInterval = 1_800

    // MARK: - Self-exclusion by name and by version

    /// A sighting advertised under a name this session wore, the current one, one worn before a
    /// boundary or one worn before a stop, is this device's own ghost and never reaches the host; a
    /// record of another version never does either; a stranger's version-1 record reaches it with its
    /// tags. The ring keeps the last ``ProximityPresenceSession/maxRememberedInstanceNames`` names, and
    /// only one name past that cap forgets the oldest, first in first out.
    @Test func aSightingUnderAWornNameOrAnotherVersionNeverReachesTheHost() throws {
        let (engine, radio) = Self.engine()
        var heard: [(name: String, tags: Set<String>)] = []
        engine.onPeerDiscovered = { peer, tags in heard.append((name: peer.displayHint, tags: tags)) }

        _ = try engine.rotatePosture(at: Self.start)
        let firstName = try #require(engine.posture?.instanceName)
        try engine.start(tags: ["own"])
        _ = try engine.rotatePosture(at: Self.start + Self.acrossABoundary)
        let secondName = try #require(engine.posture?.instanceName)
        engine.stop()
        _ = try engine.rotatePosture(at: Self.start + 2 * Self.acrossABoundary)
        let thirdName = try #require(engine.posture?.instanceName)
        try engine.start(tags: ["own"])
        #expect(Set([firstName, secondName, thirdName]).count == 3, "two of the three postures wore one name")

        // R2: bounded by the three worn names.
        for worn in [firstName, secondName, thirdName] {
            radio.onPeerDiscovered?(Self.sighting(under: worn, tags: ["t1"]))
        }
        #expect(heard.isEmpty, "a sighting under a name this session wore reached the host: \(heard.map(\.name))")
        radio.onPeerDiscovered?(Self.sighting(under: "not-ours", tags: ["t1", "t2"]))
        #expect(heard.map(\.name) == ["not-ours"] && heard.first?.tags == ["t1", "t2"],
                "a stranger's version-1 sighting did not reach the host with its tags: \(heard.map(\.name))")
        var nextVersion = PresenceAdvertisement.publishedFields(tags: ["t3"])
        nextVersion[PresenceAdvertisement.versionKey] = "2"
        radio.onPeerDiscovered?(PeerHandle(id: UUID(), displayHint: "not-ours-2", discoveryInfo: nextVersion,
                                           advertisedFingerprint: nil))
        #expect(heard.count == 1, "a record of another version reached the host: \(heard.map(\.name))")

        let room = ProximityPresenceSession.maxRememberedInstanceNames - 3
        // R2: bounded by the ring's cap.
        for index in 0..<room {
            engine.registerOwnInstanceNameForTesting("filler-\(index)")
        }
        radio.onPeerDiscovered?(Self.sighting(under: firstName, tags: ["t1"]))
        #expect(heard.count == 1, "the oldest worn name was forgotten before the ring held its cap of names")
        engine.registerOwnInstanceNameForTesting("filler-\(room)")
        radio.onPeerDiscovered?(Self.sighting(under: firstName, tags: ["t1"]))
        radio.onPeerDiscovered?(Self.sighting(under: secondName, tags: ["t1"]))
        #expect(heard.map(\.name) == ["not-ours", firstName], """
            one name past the cap forgets exactly the oldest worn name, first in first out: the host heard \
            \(heard.map(\.name))
            """)
        engine.stop()
    }

    // MARK: - A failed mint

    /// A mint that fails across a boundary leaves no posture rather than the previous epoch's: the
    /// session reports no epoch, a republish then advertises nothing (never the next epoch's tags under
    /// the previous epoch's name and certificate), and the radio keeps the registration it has, neither
    /// stopped nor re-advertised.
    @Test func aFailedMintDropsTheWornPostureAndRepublishesNothing() throws {
        let (engine, radio) = Self.engine()
        let worn = try engine.rotatePosture(at: Self.start)
        try engine.start(tags: ["own"])
        #expect(engine.postureEpoch == worn && radio.advertised.count == 1, "the session did not come up")

        engine.postureMint = { _, _ in throw PresencePostureError.entropyUnavailable(byteCount: 0) }
        #expect(throws: PresencePostureError.entropyUnavailable(byteCount: 0)) {
            try engine.rotatePosture(at: Self.start + Self.acrossABoundary)
        }
        #expect(engine.postureEpoch == nil, "a failed mint left the previous epoch's posture worn")
        engine.republish(tags: ["next"])
        #expect(radio.republished.isEmpty, "a republish after a failed mint advertised under a stale posture")
        #expect(radio.stopCount == 0 && radio.advertised.count == 1, "the radio was stopped or brought up again")
        engine.stop()
    }

    // MARK: - The advertised record

    /// A start advertises the tags it is handed as the presence record, with all six of the radio's
    /// hooks already wired when the radio starts; after a boundary, a republish advertises the tags it
    /// is handed under the new posture's name and certificate, never the start's tags.
    @Test func startAndRepublishAdvertiseTheTagsTheyAreHanded() throws {
        let (engine, radio) = Self.engine()
        let first: Set<String> = ["c", "a", "b"]
        let second: Set<String> = ["e", "d"]
        _ = try engine.rotatePosture(at: Self.start)
        try engine.start(tags: first)
        let up = try #require(radio.advertised.first)
        #expect(radio.advertised.count == 1, "the radio came up \(radio.advertised.count) times")
        #expect(up.fields == PresenceAdvertisement.publishedFields(tags: first.sorted()),
                "the start advertised \(up.fields), not the presence record of its tags")
        #expect(up.instanceName == engine.posture?.instanceName, "the start did not advertise under the worn name")
        #expect(radio.hooksWiredAtStart == RecordingPresenceRadio.hookNames,
                "the radio started with only \(radio.hooksWiredAtStart.sorted()) of its hooks wired")

        _ = try engine.rotatePosture(at: Self.start + Self.acrossABoundary)
        engine.republish(tags: second)
        let again = try #require(radio.republished.last)
        #expect(again.fields == PresenceAdvertisement.publishedFields(tags: second.sorted()),
                "the republish advertised \(again.fields), not the presence record of its tags")
        #expect(again.instanceName == engine.posture?.instanceName && again.instanceName != up.instanceName,
                "the republish did not advertise under the new posture's name")
        #expect(again.certificateDER != up.certificateDER, "the republish kept the previous posture's certificate")
        engine.stop()
    }

    // MARK: - The hooks

    /// Each of the radio's hooks reaches the host's hook it stands for, with its own value, once: a
    /// lost peer, a channel come up, a tunnel gone down with its reason, a transport error, and an
    /// inbound dialer's tag, whose answer the radio gets back. A crossed pair fails two rows.
    @Test func everyRadioHookReachesTheHostThroughTheEngine() throws {
        let (engine, radio) = Self.engine()
        let browsed = Self.sighting(under: "peer-a", tags: ["x"])
        var lost: [UUID] = []
        var channels: [any ProximityPeerChannel] = []
        var disconnected: [(peer: UUID, reason: String)] = []
        var errors: [String] = []
        var dialerTags: [String] = []
        engine.onPeerLost = { lost.append($0.id) }
        engine.onPeerChannelReady = { channels.append($0) }
        engine.onPeerDisconnected = { peer, reason in disconnected.append((peer: peer.id, reason: reason)) }
        engine.onTransportError = { errors.append($0) }
        engine.resolveDialer = { tag in
            dialerTags.append(tag)
            return tag == "known" ? browsed : nil
        }
        _ = try engine.rotatePosture(at: Self.start)
        try engine.start(tags: ["own"])

        radio.onPeerLost?(browsed)
        let channel = radio.channel(for: browsed)
        radio.onPeerChannelReady?(channel)
        radio.onPeerDisconnected?(browsed, "closed by the peer")
        radio.onTransportError?("The presence listener failed.")
        let resolved = radio.resolveDialer.flatMap { $0("known") }
        let refused = radio.resolveDialer.flatMap { $0("unknown") }

        #expect(lost == [browsed.id], "the lost hook delivered \(lost)")
        #expect(channels.count == 1 && (channels.first as? NetworkPeerChannel) === channel,
                "the channel hook delivered \(channels.count) channels, not the radio's")
        #expect(disconnected.map(\.peer) == [browsed.id] && disconnected.map(\.reason) == ["closed by the peer"],
                "the disconnect hook delivered \(disconnected)")
        #expect(errors == ["The presence listener failed."], "the transport-error hook delivered \(errors)")
        #expect(dialerTags == ["known", "unknown"] && resolved?.id == browsed.id && refused == nil,
                "the dialer hook was asked \(dialerTags) and answered \(String(describing: resolved?.id))")
        engine.stop()
    }

    // MARK: - Release

    /// A session its host lets go of without a stop, its radio up, is released, and its radio with
    /// it: the radio's hooks hold the session weakly, so the two hold no cycle a stop would have to
    /// break.
    @Test func theEngineAndItsRadioReleaseWithoutStop() throws {
        weak var releasedEngine: ProximityPresenceSession?
        weak var releasedRadio: RecordingPresenceRadio?
        do {
            let (engine, radio) = Self.engine()
            releasedEngine = engine
            releasedRadio = radio
            _ = try engine.rotatePosture(at: Self.start)
            try engine.start(tags: ["own"])
            #expect(radio.advertised.count == 1, "the session did not come up")
        }
        #expect(releasedEngine == nil, "a session released without a stop is still alive: a hook holds it")
        #expect(releasedRadio == nil, "a radio whose session was released without a stop is still alive")
    }

    // MARK: - Helpers

    /// A session under the package tests' namespace whose every start brings up the returned radio.
    private static func engine() -> (ProximityPresenceSession, RecordingPresenceRadio) {
        let radio = RecordingPresenceRadio()
        let engine = ProximityPresenceSession(namespace: .packageTest)
        engine.makeRadio = { radio }
        return (engine, radio)
    }

    /// A browsed peer advertising `tags` as a version-1 presence record under `name`.
    private static func sighting(under name: String, tags: [String]) -> PeerHandle {
        PeerHandle(id: UUID(), displayHint: name, discoveryInfo: PresenceAdvertisement.publishedFields(tags: tags),
                   advertisedFingerprint: nil)
    }
}

/// The in-memory presence radio the engine's cells hand it: records what it was asked to advertise,
/// how often it was stopped and which of its hooks were wired when it started, and vends real
/// `NetworkPeerChannel`s with itself as their host. File-private, so it is no helper the package shares
/// and no name Fernlet's own fake radio could collide with.
@MainActor
private final class RecordingPresenceRadio: PresenceRadioSession, NetworkChannelHost {

    /// One advertisement the radio was asked to put on the air.
    struct Advertisement {
        /// The instance name it was asked to advertise under.
        let instanceName: String
        /// The certificate it was asked to present.
        let certificateDER: Data
        /// The posture's epoch.
        let epoch: UInt64
        /// The TXT record.
        let fields: [String: String]
    }

    /// The names of the six hooks the engine wires.
    static let hookNames: Set<String> = [
        "onPeerDiscovered", "onPeerLost", "onPeerChannelReady", "onPeerDisconnected", "onTransportError", "resolveDialer"
    ]

    /// A browse result appeared.
    var onPeerDiscovered: ((PeerHandle) -> Void)?
    /// A browse result went away.
    var onPeerLost: ((PeerHandle) -> Void)?
    /// A tunnel came up.
    var onPeerChannelReady: ((NetworkPeerChannel) -> Void)?
    /// A tunnel went down.
    var onPeerDisconnected: ((PeerHandle, String) -> Void)?
    /// The listener or browser failed.
    var onTransportError: ((String) -> Void)?
    /// An inbound dialer's tag to resolve.
    var resolveDialer: ((String) -> PeerHandle?)?

    /// Every start's advertisement, in order.
    private(set) var advertised: [Advertisement] = []
    /// Every republish's advertisement, in order.
    private(set) var republished: [Advertisement] = []
    /// How often the radio was stopped.
    private(set) var stopCount = 0
    /// The hooks that were wired when the radio last started, by name.
    private(set) var hooksWiredAtStart: Set<String> = []

    /// Records the advertisement and which hooks are wired.
    func start(posture: PresenceEpochPosture, discoveryInfo: [String: String]) throws {
        let wired: [(String, Bool)] = [
            ("onPeerDiscovered", onPeerDiscovered != nil), ("onPeerLost", onPeerLost != nil),
            ("onPeerChannelReady", onPeerChannelReady != nil), ("onPeerDisconnected", onPeerDisconnected != nil),
            ("onTransportError", onTransportError != nil), ("resolveDialer", resolveDialer != nil)
        ]
        hooksWiredAtStart = Set(wired.filter(\.1).map(\.0))
        advertised.append(Self.advertisement(posture, discoveryInfo))
    }

    /// Records the advertisement.
    func republish(posture: PresenceEpochPosture, discoveryInfo: [String: String]) {
        republished.append(Self.advertisement(posture, discoveryInfo))
    }

    /// Counts the stop.
    func stop() {
        stopCount += 1
    }

    /// Opens nothing.
    func dial(_ peer: PeerHandle, helloTag: String) {}

    /// Ends nothing.
    func disconnectPeer(_ peer: PeerHandle) {}

    /// A channel to `peer` with this radio as its host.
    func channel(for peer: PeerHandle) -> NetworkPeerChannel {
        NetworkPeerChannel(peer: peer, host: self)
    }

    /// Sends nothing.
    func send(_ data: Data, to peer: PeerHandle, mode: PeerDeliveryMode) async throws {}

    /// Opens no transfer stream.
    func openTransferCount(for peer: PeerHandle) -> Int {
        0
    }

    /// The advertisement a call made under `posture` with `fields`.
    private static func advertisement(_ posture: PresenceEpochPosture, _ fields: [String: String]) -> Advertisement {
        Advertisement(instanceName: posture.instanceName, certificateDER: posture.tlsIdentity.certificateDER,
                      epoch: posture.epoch, fields: fields)
    }
}
