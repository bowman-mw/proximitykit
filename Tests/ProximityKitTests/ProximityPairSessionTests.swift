// ProximityPairSessionTests.swift
// ProximityKitTests
//
// The pair session, `ProximityPairSession`, driven in ProximityKit's own package tests over its real
// radio, `NetworkPairSession`, with the radio's framework objects suppressed
// (`runWithoutRadiosForTesting`), so every decision around the listener and the browser runs and no
// cell starts Bonjour (the unit-test invariant for proximity). The session is built over a
// `PackageTestHost` under `.packageTest` and handed the radio through its internal `makeRadio` seam;
// its identity provisions into the bundle's in-memory keychain.
//
// What the cells hold:
//
//   - rediscovery: a peer the session forgot at a disconnect only one side saw (a refused hello: the
//     refusing device never paired, so it never re-minted its posture, and its record comes back
//     unchanged) is listed again, and resolves as a dialer again, at the resumed radio's first
//     sighting of it, with no refresh; and an unchanged record is otherwise announced once;
//   - the inbound hello (0.1.1): a pending connection that has sent no hello refuses nobody, the
//     owner's gate included; the hello deadline drops a connection silent past it, on a clock the cell
//     hands in; every ruling applies the deadline to the connections beside it first, a read hello's
//     only after marking it read, so a late hello is still admitted and an unreadable one still refused
//     by its own reason; two connections that have both delivered hellos still refuse, the two-device
//     cap; and every refusal's line names its reason and how many connections were pending;
//   - the diagnostics (0.1.1): the radio's `connected` line names the kind of interface its connection
//     runs over, and every pairing reports to the inspector its session was built with.
//
// No verdict here rests on the wall clock: the deadline runs on the instants each cell hands the radio.
// The one seam that reads the clock, the Fernlet repository's `bookPendingInboundForTesting(_:)`, books a
// connection whose hello was read, which the deadline never touches.

import Foundation
@testable import ProximityKit
import Testing

/// The pair session over its real radio, framework objects suppressed: what a resume owes the session's
/// picker after a disconnect only one side saw, how the radio rules on an inbound hello and when it lets
/// a pending connection go, and what its diagnostics name.
@Suite @MainActor struct ProximityPairSessionTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer has
    /// run before a cell builds a session whose identity reaches the keychain.
    let keychain = PackageTestEnvironment.keychain

    // MARK: - Rediscovery after a resume

    /// **A peer forgotten at a one-sided disconnect is listed again when the resumed radio browses it,
    /// unchanged, with no refresh.**
    ///
    /// The shape two simulators showed on a first run: this device dials Blair, its channel
    /// opens (the pairing is registered and the radio pauses), and Blair refuses the hello and closes the
    /// connection; the radio ends the tunnel and tells the session, which forgets Blair (her row and her
    /// discovered handle, as it forgets every disconnected peer) and reopens the radio under a fresh
    /// posture. Blair never paired, so she never paused or re-minted: the resumed browser finds her under
    /// the very record the radio already holds. That sighting lists her again, and her `sid` resolves her
    /// own dial again. A radio that announced only a changed record left her out of the picker, and
    /// refused her dial, until a refresh or a stop. Around it, the dedup that keeps an unchanged record
    /// from being announced twice holds: before the pairing, and once the owed sighting is paid.
    @Test func aPeerForgottenAtAOneSidedDisconnectIsListedAgainWhenTheResumedRadioBrowsesIt() throws {
        let host = PackageTestHost()
        let profile = ProximityPairProfile(
            auditArea: "pktest.pair", radio: host.proximityNamespace.family.radios.pair, advertisementMode: "pair")
        let radio = NetworkPairSession(namespace: host.proximityNamespace, profile: profile)
        try radio.runWithoutRadiosForTesting()
        let session = ProximityPairSession(host: host, profile: profile, makeRadio: { radio })
        var events: [ProximityPairSession.Event] = []
        session.onEvent = { events.append($0) }
        session.markRunningForTesting()

        let name = host.proximityNamespace.family.radios.meshInstanceNamePrefix + "b1a1700000f1"
        let key = MeshLinkKey("\(name).\(radio.serviceType).local.")
        let record = ProximityPairAdvertisement.publishedFields(
            from: [ProximityPairAdvertisement.versionKey: ProximityPairAdvertisement.version,
                   ProximityPairAdvertisement.modeKey: profile.advertisementMode,
                   ProximityPairAdvertisement.nameKey: "Blair"],
            sessionID: "blair-sid")
        radio.noteBrowsedForTesting(key, instanceName: name, advertisement: record)
        radio.noteBrowsedForTesting(key, instanceName: name, advertisement: record)
        let blair = radio.handleForTesting(key)
        #expect(session.nearbyPeers.map(\.id) == [blair.id] && events == [.discovered(name: "Blair")],
                "Blair's sighting and the same record again left the rows \(session.nearbyPeers) and the events \(events)")

        // This device dials Blair: the channel opens, the pairing is registered and the radio goes quiet.
        radio.bookTunnelForTesting(key, role: .initiator)
        _ = session.makeRetainedConnectionCoordinatorForTesting(
            peer: blair, transport: radio.channel(for: blair), ranging: NoopRangingProvider())
        let worn = radio.advertisedSessionID
        #expect(radio.isDiscoveryPaused, "registering the pairing did not pause the radio")

        // Blair refuses the hello and closes the connection: the radio ends the tunnel and tells the
        // session, as its receive loop does when a connection ends under it.
        radio.endTunnel(blair)
        radio.onPeerDisconnected?(blair, "The outbound recipe-share connection ended")
        #expect(!radio.isDiscoveryPaused && radio.advertisedSessionID != worn && events.contains(.reopened),
                "the eviction did not reopen the radio under a fresh posture: \(events)")
        #expect(session.nearbyPeers.isEmpty && session.resolveDialerForTesting("blair-sid") == nil,
                "the session still lists Blair after her disconnect, though it forgets a disconnected peer")

        // The resumed browser finds Blair under her unchanged record, and then again.
        let before = events.count
        radio.noteBrowsedForTesting(key, instanceName: name, advertisement: record)
        #expect(session.nearbyPeers.map(\.id) == [blair.id], """
            the resumed radio's sighting of Blair's unchanged record did not list her again, so the picker \
            stays empty until a refresh: rows \(session.nearbyPeers), events since the disconnect \
            \(Array(events.dropFirst(before)))
            """)
        #expect(session.resolveDialerForTesting("blair-sid")?.id == blair.id,
                "Blair's own dial still resolves to nobody, so this device would refuse her hello")
        radio.noteBrowsedForTesting(key, instanceName: name, advertisement: record)
        #expect(Array(events.dropFirst(before)) == [.discovered(name: "Blair")],
                "the resumed radio's sightings of an unchanged record announced \(Array(events.dropFirst(before)))")
        #expect(!events.contains(.discoveryRefreshed), "the cell refreshed discovery: \(events)")
        session.stop()
        try host.tearDown()
    }

    // MARK: - The inbound hello

    /// **A pending connection that has sent nothing does not refuse the hello of the dialer beside it.**
    ///
    /// The cold-start shape: Blair's dial reaches this device as two QUIC connections (the likeliest
    /// source, Network.framework racing a second attempt across the service's addresses), one carrying
    /// her hello and one that never opens a stream. Both are booked as they arrive. The radio's
    /// connecting window used to count every pending connection but the one being ruled on, so the
    /// owner's gate (the session's own, wired here) refused Blair's hello beside her own silent twin,
    /// and her every dial failed until the radio stopped, since QUIC's idle timeout fails a connection
    /// that never opened a stream without ending it. Only a connection that has delivered a readable
    /// hello counts now: the gate admits her, nothing is refused, and the twin is left to its deadline.
    @Test func aStreamlessPendingConnectionDoesNotRefuseTheHelloOfTheDialerBesideIt() throws {
        let host = PackageTestHost()
        let (radio, session) = try makeSession(on: host)
        let blair = browse("b1a1700000f1", named: "Blair", sid: "blair-sid", on: radio)
        let booked = Date(timeIntervalSinceReferenceDate: 812_000_000)
        let twin = MeshLinkKey("blair-silent-twin")
        let dial = MeshLinkKey("blair-dial")
        #expect(radio.bookPendingInboundForTesting(twin, stage: .awaitingStream, at: booked)
                    && radio.bookPendingInboundForTesting(dial, stage: .readingHello, at: booked),
                "the radio did not book the two arrivals")
        #expect(!radio.hasConnectingPeers(besides: nil), "a connection that has sent nothing counts as mid-connect")
        #expect(session.shouldAcceptDialerForTesting(blair.peer),
                "the session's gate refuses Blair while her own silent twin is pending")

        let capture = PackageAuditCapture(markedOnly: true)
        let admitted = capture.marking {
            radio.ruleOnHelloForTesting(
                ProximityPairDialHello(sessionID: "blair-sid"), pendingKey: dial, now: booked.addingTimeInterval(0.2))
        }
        #expect(admitted == blair.key, "Blair's hello was refused beside a connection that never sent one")
        #expect(capture.lines(named: "recipe.quic.helloRefused").isEmpty,
                "a hello was refused: \(capture.lines(named: "recipe.quic.helloRefused"))")
        #expect(capture.lines(named: "recipe.quic.pendingEnded").map(\.context) == [[
            "connection": radio.peerLabel(for: dial), "reason": "admitted", "stage": "helloDelivered", "pending": "1"
        ]], "the admission's line: \(capture.lines(named: "recipe.quic.pendingEnded"))")
        #expect(radio.pendingInboundStageForTesting(twin) == .awaitingStream,
                "the silent twin was dropped by the admission rather than left to its deadline")
        session.stop()
        try host.tearDown()
    }

    /// **The hello deadline drops a connection that stays silent past it, on the clock the cell hands in.**
    ///
    /// Each arrival and each ruling applies the deadline at the instant it read, so the radio owns no
    /// clock: here the cell hands in every instant. Two silent connections hold both pending places, and a
    /// third arrival is turned away while neither is past five seconds; five seconds exactly is within
    /// it. Half a second later an arrival reaps the connection that never opened a stream and takes its
    /// place. Then the connection whose stream arrived but whose hello never finished is reaped too, and
    /// a connection whose hello was read never is, however long its ruling waits.
    @Test func theHelloDeadlineDropsASilentConnectionOnTheClockTheCellHandsIn() throws {
        let radio = try makeRadio().radio
        let booked = Date(timeIntervalSinceReferenceDate: 812_000_000)
        let silent = MeshLinkKey("silent")
        let slow = MeshLinkKey("slow-hello")
        let late = MeshLinkKey("late-arrival")
        let delivered = MeshLinkKey("hello-delivered")
        let capture = PackageAuditCapture(markedOnly: true)
        capture.marking {
            #expect(radio.bookPendingInboundForTesting(silent, stage: .awaitingStream, at: booked))
            #expect(radio.bookPendingInboundForTesting(slow, stage: .readingHello, at: booked.addingTimeInterval(1)))
            #expect(!radio.bookPendingInboundForTesting(late, stage: .awaitingStream, at: booked.addingTimeInterval(3)),
                    "a third arrival was booked while two connections inside their deadline held both places")
            radio.expireStalledInboundForTesting(now: booked.addingTimeInterval(NetworkPairSession.helloDeadlineSeconds))
            #expect(radio.pendingInboundCountForTesting == 2, "a connection was dropped at exactly its deadline")
            #expect(radio.bookPendingInboundForTesting(late, stage: .awaitingStream, at: booked.addingTimeInterval(5.5)),
                    "the arrival did not reap the connection silent past its deadline to take its place")
            radio.expireStalledInboundForTesting(now: booked.addingTimeInterval(6.5))
            #expect(radio.bookPendingInboundForTesting(delivered, stage: .helloDelivered, at: booked.addingTimeInterval(6.5)))
            radio.expireStalledInboundForTesting(now: booked.addingTimeInterval(60))
        }
        #expect(NetworkPairSession.helloDeadlineSeconds == 5, "the deadline is \(NetworkPairSession.helloDeadlineSeconds) s")
        #expect(radio.pendingInboundCountForTesting == 1 && radio.pendingInboundStageForTesting(delivered) == .helloDelivered,
                "a connection whose hello was read was reaped, or a silent one survived")
        let ended = capture.lines(named: "recipe.quic.pendingEnded").map(\.context)
        #expect(ended == [
            ["connection": radio.peerLabel(for: silent), "reason": "helloDeadline", "stage": "awaitingStream", "pending": "1"],
            ["connection": radio.peerLabel(for: slow), "reason": "helloDeadline", "stage": "readingHello", "pending": "1"],
            ["connection": radio.peerLabel(for: late), "reason": "helloDeadline", "stage": "awaitingStream", "pending": "1"]
        ], "the deadline's lines: \(ended)")
        #expect(capture.lines(named: "recipe.quic.pendingBooked").map { $0.context["pending"] } == ["1", "2", "2", "2"],
                "the bookings' lines: \(capture.lines(named: "recipe.quic.pendingBooked"))")
        #expect(capture.lines(named: "recipe.quic.helloRefused").isEmpty, "the deadline is not a refusal")
        radio.stop()
    }

    /// **A ruling applies the deadline, and only after it has marked its own hello read.**
    ///
    /// Blair's dial, its stream open, and a connection that opened none are booked at one instant, and
    /// her hello is ruled on six seconds later, when both have run past the deadline. The ruling marks
    /// her hello read before it applies the deadline, so a hello that arrived is ruled on however long
    /// it took, and she is admitted; the deadline it then applies reaps the silent connection, whose line
    /// comes before her admission's. A ruling that skipped the deadline left the silent one pending, and
    /// one that applied it before marking the hello reaped Blair's own connection and admitted nobody.
    @Test func aRulingAppliesTheDeadlineAfterMarkingItsOwnHelloRead() throws {
        let host = PackageTestHost()
        let (radio, session) = try makeSession(on: host)
        let blair = browse("b1a1700000f1", named: "Blair", sid: "blair-sid", on: radio)
        let booked = Date(timeIntervalSinceReferenceDate: 812_000_000)
        let dial = MeshLinkKey("blair-dial")
        let silent = MeshLinkKey("silent")
        #expect(radio.bookPendingInboundForTesting(dial, stage: .readingHello, at: booked)
                    && radio.bookPendingInboundForTesting(silent, stage: .awaitingStream, at: booked),
                "the radio did not book the two arrivals")

        let capture = PackageAuditCapture(markedOnly: true)
        let admitted = capture.marking {
            radio.ruleOnHelloForTesting(
                ProximityPairDialHello(sessionID: "blair-sid"), pendingKey: dial, now: booked.addingTimeInterval(6))
        }
        #expect(admitted == blair.key, "Blair's hello, ruled on six seconds after her connection arrived, was not admitted")
        let ended = capture.lines(named: "recipe.quic.pendingEnded").map(\.context)
        #expect(ended == [
            ["connection": radio.peerLabel(for: silent), "reason": "helloDeadline", "stage": "awaitingStream", "pending": "1"],
            ["connection": radio.peerLabel(for: dial), "reason": "admitted", "stage": "helloDelivered", "pending": "0"]
        ], "the ruling's lines: \(ended)")
        #expect(capture.lines(named: "recipe.quic.helloRefused").isEmpty,
                "a hello was refused: \(capture.lines(named: "recipe.quic.helloRefused"))")
        #expect(radio.pendingInboundCountForTesting == 0, "a connection is still pending after the ruling")
        session.stop()
        try host.tearDown()
    }

    /// **A ruling on no readable hello applies the deadline too, to every connection but the one it
    /// refuses.**
    ///
    /// A connection whose stream opened but whose hello never came off it and a twin that opened no
    /// stream are booked at one instant, and the read ends with nothing six seconds later, when both have
    /// run past the deadline. The ruling reaps the twin first, so its refusal counts only connections that
    /// could still deliver (`pending=1`), and then refuses the connection it rules on for its own reason,
    /// `unreadable`: that connection's ruling ends it, not the deadline. A ruling that refused first counted
    /// the stalled twin and left it pending, and one that let the deadline take the ruled connection wrote
    /// no refusal at all.
    @Test func aRulingOnNoReadableHelloReapsTheStalledConnectionsBesideItFirst() throws {
        let radio = try makeRadio().radio
        let booked = Date(timeIntervalSinceReferenceDate: 812_000_000)
        let unreadable = MeshLinkKey("unreadable-hello")
        let twin = MeshLinkKey("silent-twin")
        #expect(radio.bookPendingInboundForTesting(unreadable, stage: .readingHello, at: booked)
                    && radio.bookPendingInboundForTesting(twin, stage: .awaitingStream, at: booked),
                "the radio did not book the two arrivals")

        let capture = PackageAuditCapture(markedOnly: true)
        let admitted = capture.marking {
            radio.ruleOnHelloForTesting(nil, pendingKey: unreadable, now: booked.addingTimeInterval(6))
        }
        #expect(admitted == nil, "a ruling on no readable hello admitted \(String(describing: admitted))")
        #expect(capture.lines(named: "recipe.quic.helloRefused").map(\.context) == [[
            "connection": radio.peerLabel(for: unreadable), "reason": "unreadable", "pending": "1"
        ]], "the refusal's line: \(capture.lines(named: "recipe.quic.helloRefused"))")
        let ended = capture.lines(named: "recipe.quic.pendingEnded").map(\.context)
        #expect(ended == [
            ["connection": radio.peerLabel(for: twin), "reason": "helloDeadline", "stage": "awaitingStream", "pending": "1"],
            ["connection": radio.peerLabel(for: unreadable), "reason": "refused", "stage": "readingHello", "pending": "0"]
        ], "the ruling's lines: \(ended)")
        #expect(radio.pendingInboundCountForTesting == 0, "a connection is still pending after the ruling")
        radio.stop()
    }

    /// **Two connections that have both delivered hellos still refuse: the two-device cap holds.**
    ///
    /// Blair's hello and Casey's have both been read, booked through the seam the Fernlet repository's
    /// `aSecondDialerArrivingWhileOneIsMidHelloIsRefused` books through, which books a connection at
    /// that stage now. That cell's bare adjudication still refuses Blair beside Casey and drops nothing,
    /// the session's own gate refuses her too, and the ruling the live path runs refuses her with a line
    /// that says the owner refused and that two were pending, drops her connection, and leaves Casey's.
    /// The deadline never touches a read hello, so the instant the ruling is handed does not matter.
    @Test func twoConnectionsThatHaveBothDeliveredHellosStillRefuse() throws {
        let host = PackageTestHost()
        let (radio, session) = try makeSession(on: host)
        let blair = browse("b1a1700000f1", named: "Blair", sid: "blair-sid", on: radio)
        _ = browse("ca5e70000001", named: "Casey", sid: "casey-sid", on: radio)
        let fromBlair = MeshLinkKey("blair-dial")
        let fromCasey = MeshLinkKey("casey-dial")
        radio.bookPendingInboundForTesting(fromBlair)
        radio.bookPendingInboundForTesting(fromCasey)
        #expect([fromBlair, fromCasey].allSatisfy { radio.pendingInboundStageForTesting($0) == .helloDelivered },
                "the seam the Fernlet repository's cell books through no longer books a hello-bearing connection")
        let hello = ProximityPairDialHello(sessionID: "blair-sid")
        #expect(radio.adjudicateInboundForTesting(hello, pendingKey: fromBlair) == nil,
                "Blair's hello was admitted beside Casey's, which was being ruled on")
        #expect(radio.pendingInboundCountForTesting == 2, "the bare adjudication dropped a connection")
        #expect(!session.shouldAcceptDialerForTesting(blair.peer), "the session's gate admits Blair beside Casey's hello")

        let capture = PackageAuditCapture(markedOnly: true)
        let admitted = capture.marking {
            radio.ruleOnHelloForTesting(hello, pendingKey: fromBlair, now: Date(timeIntervalSinceReferenceDate: 812_000_000))
        }
        #expect(admitted == nil, "a second device's hello was admitted while a first one's was being ruled on")
        #expect(capture.lines(named: "recipe.quic.helloRefused").map(\.context) == [[
            "connection": radio.peerLabel(for: fromBlair), "reason": "ownerRefused", "pending": "2"
        ]], "the refusal's line: \(capture.lines(named: "recipe.quic.helloRefused"))")
        #expect(capture.lines(named: "recipe.quic.pendingEnded").map(\.context) == [[
            "connection": radio.peerLabel(for: fromBlair), "reason": "refused", "stage": "helloDelivered", "pending": "1"
        ]], "the refused connection's line: \(capture.lines(named: "recipe.quic.pendingEnded"))")
        #expect(radio.pendingInboundStageForTesting(fromCasey) == .helloDelivered, "the refusal dropped Casey's connection")
        session.stop()
        try host.tearDown()
    }

    /// **Every refused hello's line names why, and how many connections were pending.**
    ///
    /// One connection at a time, each ruled on alone (`pending=1`), through every refusal the ruling
    /// has: no readable hello; a session id no browsed peer carries, and this device's own; the owner's
    /// gate saying no; a tunnel to the same peer that the glare rule keeps; and a tunnel to another
    /// device, the radio's own one-tunnel floor. Then the same hello with nothing in its way is admitted.
    /// Before 0.1.1 all five wrote one line with no reason, so a device log could not say which it was.
    @Test func everyRefusedHelloNamesWhyAndHowManyConnectionsWerePending() throws {
        let (radio, posture) = try makeRadio()
        let blairKey = MeshLinkKey("blair-endpoint")
        let caseyKey = MeshLinkKey("casey-endpoint")
        // A bare prefix ranks below every posture's name, so this device's own dial is the survivor.
        radio.noteBrowsedNameForTesting(blairKey, instanceName: ProximityNamespace.packageTest.family.radios.meshInstanceNamePrefix)
        let blair = radio.handleForTesting(blairKey)
        var ownerAccepts = false
        radio.resolveDialer = { $0 == "blair-sid" ? blair : nil }
        radio.shouldAcceptDialer = { _ in ownerAccepts }
        let booked = Date(timeIntervalSinceReferenceDate: 812_000_000)
        var dials = 0
        let capture = PackageAuditCapture(markedOnly: true)
        let rule = { (sessionID: String?) -> MeshLinkKey? in
            dials += 1
            let pending = MeshLinkKey("dial-\(dials)")
            radio.bookPendingInboundForTesting(pending, stage: .readingHello, at: booked)
            return capture.marking {
                radio.ruleOnHelloForTesting(sessionID.map(ProximityPairDialHello.init(sessionID:)), pendingKey: pending, now: booked)
            }
        }
        let unadmitted = [rule(nil), rule("nobody-sid"), rule(posture.sessionID), rule("blair-sid")]
        #expect(unadmitted.allSatisfy { $0 == nil }, "a hello was admitted before any could be: \(unadmitted)")
        ownerAccepts = true
        radio.bookTunnelForTesting(blairKey, role: .initiator)
        #expect(rule("blair-sid") == nil, "a hello beside a held tunnel the glare rule keeps was admitted")
        radio.endTunnel(blair)
        radio.bookTunnelForTesting(caseyKey, role: .initiator)
        #expect(rule("blair-sid") == nil, "a second device was admitted beside a tunnel to another one")
        radio.endTunnel(radio.handleForTesting(caseyKey))
        #expect(rule("blair-sid") == blairKey, "the hello with nothing in its way was refused")

        let refused = capture.lines(named: "recipe.quic.helloRefused")
        #expect(refused.map { $0.context["reason"] } == [
            "unreadable", "unresolved", "unresolved", "ownerRefused", "keptEstablished", "tunnelHeld"
        ], "the refusals' reasons: \(refused)")
        #expect(Set(refused.compactMap { $0.context["reason"] }) == Set(NetworkPairSession.HelloRefusal.allCases.map(\.rawValue)),
                "a refusal reason no cell reaches: \(NetworkPairSession.HelloRefusal.allCases)")
        #expect(refused.allSatisfy { $0.context["pending"] == "1" }, "a lone connection's refusal counts \(refused)")
        #expect(capture.lines(named: "recipe.quic.pendingEnded").map { $0.context["reason"] }
                    == Array(repeating: "refused", count: 6) + ["admitted"],
                "each refused connection was not dropped once, with its line")
        #expect(capture.lines(named: "recipe.quic.redundantTunnelClosed").map { $0.context["kept"] } == ["established"],
                "the glare refusal did not keep the established tunnel")
        radio.stop()
    }

    // MARK: - Diagnostics

    /// **The radio's `connected` line names the kind of interface its connection runs over.**
    ///
    /// The tokens are frozen, and the line is written at activation, which needs a live QUIC stream a
    /// unit test cannot build, so its spelling is held in source: one `recipe.quic.connected` line in
    /// the activation, whose context carries the tunnel count and the interface read off the
    /// connection's current path.
    @Test func theConnectedLineNamesTheKindOfInterfaceItsConnectionRunsOver() throws {
        #expect(PairTunnelInterface.allCases.map(\.rawValue)
                    == ["wifi", "wiredEthernet", "loopback", "cellular", "other", "unknown"],
                "the interface tokens are frozen: \(PairTunnelInterface.allCases)")
        let code = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Transport/NetworkPairSession.swift"))
        let activation = try #require(MeshRoutedSourceScan.bracedBody(after: "func activate(", in: code),
                                      "the radio's activation is gone")
        #expect(activation.components(separatedBy: #""recipe.quic.connected""#).count - 1 == 1,
                "the activation writes no single `connected` line")
        #expect(activation.contains("PairTunnelInterface(connection.currentPath?.availableInterfaces.first?.type)"),
                "the activation no longer reads the interface off the connection's path")
        #expect(activation.contains(#"context: ["tunnels": String(tunnels.count), "interface": interface.rawValue]"#),
                "the `connected` line no longer carries the interface key")
    }

    /// **Every pairing reports to the inspector its session was built with, held weakly.**
    ///
    /// The public initializer binds the recorder, read-only after it; a recorder its host releases is
    /// gone from the session; and a pairing's coordinator, built as the channel-ready door builds one,
    /// reports its session's start to that recorder. The door itself needs a live channel a unit test
    /// cannot open, so its hand-over is held in source: its coordinator is built with the session's
    /// inspector, once.
    @Test func everyPairingReportsToTheInspectorItsSessionWasBuiltWith() async throws {
        let door = try #require(MeshRoutedSourceScan.bracedBody(
            after: "private func handleChannelReady(",
            in: MeshRoutedSourceScan.codeOnly(
                try PackageRoot.source("Sources/ProximityKit/PairSession/ProximityPairSession.swift"))),
            "the pair session's channel-ready door is gone")
        #expect(door.components(separatedBy: "inspector: inspector,").count - 1 == 1,
                "the channel-ready door builds its coordinator without the session's inspector")
        let host = PackageTestHost()
        let recorder = SessionStartRecorder()
        let bound = ProximityPairSession(host: host, profile: pairProfile(for: host), inspector: recorder)
        #expect(bound.inspector === recorder, "the public initializer did not bind its recorder")
        var released: SessionStartRecorder? = SessionStartRecorder()
        let unbound = ProximityPairSession(host: host, profile: pairProfile(for: host), inspector: released)
        released = nil
        #expect(unbound.inspector == nil && released == nil, "the session kept a recorder its host released")

        let radio = NetworkPairSession(namespace: host.proximityNamespace, profile: pairProfile(for: host))
        try radio.runWithoutRadiosForTesting()
        let session = ProximityPairSession(
            host: host, profile: pairProfile(for: host), makeRadio: { radio }, inspector: recorder)
        let blair = radio.handleForTesting(MeshLinkKey("blair-endpoint"))
        let coordinator = session.makeRetainedConnectionCoordinatorForTesting(
            peer: blair, transport: radio.channel(for: blair), ranging: NoopRangingProvider())
        await coordinator.begin(role: .browser, mode: .friend)
        #expect(recorder.roles == [.browser], "the pairing's coordinator reported to no inspector: \(recorder.roles)")
        session.stop()
        try host.tearDown()
    }

    // MARK: - Helpers

    /// The pair profile every cell runs under: the host namespace's pair radio, TXT mode `pair`.
    private func pairProfile(for host: PackageTestHost) -> ProximityPairProfile {
        ProximityPairProfile(
            auditArea: "pktest.pair", radio: host.proximityNamespace.family.radios.pair, advertisementMode: "pair")
    }

    /// A radio under `.packageTest`'s pair profile, its framework objects suppressed, running, and the
    /// posture it wears.
    private func makeRadio() throws -> (radio: NetworkPairSession, posture: ProximityPairPosture) {
        let profile = ProximityPairProfile(
            auditArea: "pktest.pair", radio: ProximityNamespace.packageTest.family.radios.pair, advertisementMode: "pair")
        let radio = NetworkPairSession(namespace: .packageTest, profile: profile)
        let posture = try radio.runWithoutRadiosForTesting()
        return (radio, posture)
    }

    /// A session over `host` driving a radio of its own, framework objects suppressed, both running.
    private func makeSession(on host: PackageTestHost) throws -> (NetworkPairSession, ProximityPairSession) {
        let radio = NetworkPairSession(namespace: host.proximityNamespace, profile: pairProfile(for: host))
        try radio.runWithoutRadiosForTesting()
        let session = ProximityPairSession(host: host, profile: pairProfile(for: host), makeRadio: { radio })
        session.markRunningForTesting()
        return (radio, session)
    }

    /// Browses a peer exactly as a browse result does: instance name `suffix` under the host namespace's
    /// prefix, its advertisement naming `name` under `sid`. Answers its endpoint key and handle.
    private func browse(
        _ suffix: String, named name: String, sid: String, on radio: NetworkPairSession
    ) -> (key: MeshLinkKey, peer: PeerHandle) {
        let instance = ProximityNamespace.packageTest.family.radios.meshInstanceNamePrefix + suffix
        let key = MeshLinkKey("\(instance).\(radio.serviceType).local.")
        let record = ProximityPairAdvertisement.publishedFields(
            from: [ProximityPairAdvertisement.versionKey: ProximityPairAdvertisement.version,
                   ProximityPairAdvertisement.modeKey: radio.advertisementMode,
                   ProximityPairAdvertisement.nameKey: name],
            sessionID: sid)
        radio.noteBrowsedForTesting(key, instanceName: instance, advertisement: record)
        return (key, radio.handleForTesting(key))
    }
}

/// A recorder that keeps the role of every session a coordinator begins with it: the read that shows a
/// pairing's coordinator was built with its session's inspector. Every other report is the protocol's
/// default no-op, or dropped.
@MainActor
private final class SessionStartRecorder: ProximityInspectorRecording {

    /// The roles of the sessions begun with it, in order.
    private(set) var roles: [ProximityRole] = []

    /// Keeps the session's role.
    func beginSession(role: ProximityRole, mode: ProximitySessionMode, localFingerprint: String) {
        roles.append(role)
    }

    /// Drops the event: the cell reads only the session starts.
    func recordCoordinatorEvent(_ message: String) {}
}
