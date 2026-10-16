// ProximityRadioListenerTests.swift
// ProximityKitTests
//
// The three radios' listeners (the mesh's `NetworkMeshSession`, the recipe radio's `NetworkPairSession`
// and presence's `NetworkPresenceSession`), and what bounds the inbound connections each one hands its
// radio (0.1.1).
//
// Each radio used to build its listener with a finite new-connection limit (the mesh 8, the recipe radio
// 3, presence 4), read as a cap on connections at once. Network.framework spends it instead: the limit
// counts down by one for every connection the listener creates and never back up when one ends, and at
// zero the listener stops handing connections over. Measured on macOS 26.6.2, with a throwaway package
// running a real `NetworkListener` over loopback under the radios' own QUIC and TLS parameters, twice:
// limited to 2, the limit read back 1 and then 0 after the first two dials, each closed and ended before
// the next, and the third and fourth were never handed over (the third's dialer, watched for 30 s, never
// became ready and never failed); with no limit, and with the limit re-armed from the live count at each
// end, all four were; a limit set again while a dial waited handed over a connection that had already
// failed (`Connection refused`); and a connection that never opened a stream, closed by its dialer or
// failed by QUIC's idle timeout, never ended its `inboundStreams` (over 20 s past the failure) until its
// owning task was cancelled. So each radio went deaf after that many inbound connections since its
// listener was last built, and presence, whose only reaper was meant to be that idle timeout, kept a
// silent connection's pending place until it stopped.
//
// The package's tests cannot run that listener: they import no `Network` (rule I11 of
// `PackageTestHygieneTests`), and a radio's listener advertises over Bonjour, which no cell may start. So
// the limit is held in source, and the admission that bounds a flood in its place by the radios' caps and
// presence's new deadline, driven through the production booking on instants each cell hands in:
//
//   - no listener in the module is built with a finite limit, or has one set on it later: every
//     `newConnectionLimit` in its code is the three radios' `startListener()` handing the factory's one
//     unlimited value, `ProximityQUICParameters.listenerNewConnectionLimit`, the framework's infinite
//     marker;
//   - each radio caps what it holds pending and reaps what stays silent: the recipe radio and presence
//     apply their five-second hello deadline before their cap at every arrival, the mesh its ten-second
//     introduction deadline on its one poll, each cap and deadline at its value;
//   - a silent presence connection gives up its place at the first arrival past its deadline, five
//     seconds exactly being within it, and the cap turns an arrival away while every place is held.

import Foundation
@testable import ProximityKit
import Testing

/// Every radio's listener hands its radio every connection it creates, and each radio caps and reaps the
/// inbound connections it holds pending in the listener's place: three cells.
@Suite @MainActor struct ProximityRadioListenerTests {

    /// The three radios' files, by path under the package root.
    static let radioPaths = [
        "Sources/ProximityKit/Transport/NetworkMeshSession.swift",
        "Sources/ProximityKit/Transport/NetworkPairSession.swift",
        "Sources/ProximityKit/Transport/NetworkPresenceSession.swift"
    ]

    /// The one spelling a listener's limit may take: the factory's unlimited value.
    static let unlimitedSpelling = ").newConnectionLimit(ProximityQUICParameters.listenerNewConnectionLimit)"

    // MARK: - The listeners

    /// **No listener goes deaf.** Over every Swift file of the module at the walk's floor, each code line
    /// that names `newConnectionLimit` is exactly the factory's unlimited value handed to a listener being
    /// built, there are three, one in each radio's file and inside its `startListener()`; no other line
    /// names it, so none sets a finite limit or re-arms one; the value is declared as the framework's
    /// infinite marker, and reads at least as large as the C API's (`UInt32.max`). Each radio's old
    /// finite limit, a re-armed one, or a finite value behind the shared name fails here.
    @Test func everyRadioListenerHandsItsRadioEveryConnection() throws {
        let files = try PackageSwiftFiles.sources()
        #expect(files.count >= PackageSwiftFiles.sourceFloor, """
            the listener scan read \(files.count) ProximityKit files (floor \(PackageSwiftFiles.sourceFloor)): \
            the walk is broken, not the module clean
            """)
        var homes: [String] = []
        // R2: bounded by the module's file list.
        for file in files {
            let code = MeshRoutedSourceScan.codeOnly(file.text)
            // R2: bounded by the file's lines.
            for line in code.split(separator: "\n") where line.contains("newConnectionLimit") {
                #expect(line.trimmingCharacters(in: .whitespaces) == Self.unlimitedSpelling, """
                    \(file.path) sets a listener's new-connection limit other than the unlimited one: \
                    `\(line.trimmingCharacters(in: .whitespaces))`. A finite limit is spent, one per connection \
                    the listener creates, and never refunded; at zero the radio is deaf
                    """)
                homes.append(file.path)
            }
        }
        #expect(homes.sorted() == Self.radioPaths.map { String($0.dropFirst("Sources/ProximityKit/".count)) },
                "each radio's listener names the limit once, and nothing else names it: \(homes)")
        // R2: bounded by the three radios.
        for path in Self.radioPaths {
            let code = MeshRoutedSourceScan.codeOnly(try PackageRoot.source(path))
            let body = try #require(
                MeshRoutedSourceScan.bracedBody(after: "func startListener() throws", in: code),
                "\(path)'s startListener() is gone or its braces do not close")
            #expect(body.contains(Self.unlimitedSpelling), "\(path)'s listener is not built unlimited")
        }
        let factory = MeshRoutedSourceScan.codeOnly(try PackageRoot.source(Self.radioPaths[0]))
        #expect(factory.contains("static let listenerNewConnectionLimit = NWListener.InfiniteConnectionLimit"),
                "the shared value is the framework's infinite marker")
        #expect(ProximityQUICParameters.listenerNewConnectionLimit >= Int(UInt32.max),
                "the shared value reads \(ProximityQUICParameters.listenerNewConnectionLimit), a finite budget")
    }

    // MARK: - What bounds an inbound flood instead

    /// **Each radio caps and reaps what its listener hands it.** The caps and deadlines at their values:
    /// the recipe radio's 2 pending places and 5 s hello deadline, the mesh's 8 places and 10 s
    /// introduction deadline on a 1 s poll, presence's 4 places and 5 s hello deadline. In source: the
    /// recipe radio's and presence's arrival books through `bookPendingInbound`, which applies the deadline
    /// at the arrival's instant before it tests the cap; the mesh's arrival tests its cap, and its poll's
    /// tick sweeps the deadline. A radio that lost its cap would hold whatever a flood sends it, and one
    /// that lost its deadline would keep a silent connection's place until it stops.
    @Test func everyRadioCapsAndReapsTheConnectionsItsListenerHandsIt() throws {
        #expect(NetworkPairSession.maxPendingInbound == 2)
        #expect(NetworkPairSession.helloDeadlineSeconds == 5)
        #expect(NetworkMeshSession.maxPendingInboundTunnels == 8)
        #expect(NetworkMeshSession.introductionDeadlineSeconds == 10)
        #expect(NetworkMeshSession.pollIntervalSeconds == 1)
        #expect(NetworkPresenceSession.maxPendingInbound == 4)
        #expect(NetworkPresenceSession.helloDeadlineSeconds == 5)

        // R2: bounded by the two radios that book through a hello deadline.
        for path in [Self.radioPaths[1], Self.radioPaths[2]] {
            let code = MeshRoutedSourceScan.codeOnly(try PackageRoot.source(path))
            let accept = try #require(MeshRoutedSourceScan.bracedBody(after: "func acceptInbound(", in: code),
                                      "\(path)'s acceptInbound is gone")
            #expect(accept.contains("bookPendingInbound("), "\(path)'s arrival no longer books through the deadline")
            let book = try #require(MeshRoutedSourceScan.bracedBody(after: "func bookPendingInbound(", in: code),
                                    "\(path)'s bookPendingInbound is gone")
            let expire = try #require(book.range(of: "expireStalledInbound(now: now)")?.lowerBound,
                                      "\(path)'s booking applies no hello deadline")
            let capped = try #require(book.range(of: "pendingInbound.count < Self.maxPendingInbound")?.lowerBound,
                                      "\(path)'s booking holds no cap")
            #expect(expire < capped, "\(path) tests its cap before it frees the places past the deadline")
        }
        let mesh = MeshRoutedSourceScan.codeOnly(try PackageRoot.source(Self.radioPaths[0]))
        let meshAccept = try #require(MeshRoutedSourceScan.bracedBody(after: "func acceptInbound(", in: mesh),
                                      "the mesh's acceptInbound is gone")
        #expect(meshAccept.contains("pendingInbound.count < Self.maxPendingInboundTunnels"),
                "the mesh's arrival holds no cap")
        let tick = try #require(MeshRoutedSourceScan.bracedBody(after: "func tick(now: Date)", in: mesh),
                                "the mesh's poll tick is gone")
        #expect(tick.contains("expirePendingInbound(now: now)"), "the mesh's poll sweeps no introduction deadline")
    }

    /// **A silent presence connection gives up its place at the next arrival past its deadline.** Four
    /// connections booked at one instant hold every place; an arrival five seconds later, exactly the
    /// deadline, is turned away by the cap and drops none of them; one five and a half seconds later frees
    /// all four and is booked, alone; and a second booking under a held key is refused. Before the
    /// deadline, nothing but a stop freed those places.
    @Test func aSilentPresenceConnectionGivesUpItsPlaceAtTheNextArrivalPastItsDeadline() {
        let radio = NetworkPresenceSession(namespace: .packageTest)
        let start = Date(timeIntervalSinceReferenceDate: 800_000_000)
        let silent = (0..<NetworkPresenceSession.maxPendingInbound).map { MeshLinkKey("silent-\($0)") }
        // R2: bounded by the radio's pending cap.
        for key in silent {
            #expect(radio.bookPendingInboundForTesting(key, at: start), "a free place books \(key.rawValue)")
        }
        #expect(radio.pendingInboundCountForTesting == NetworkPresenceSession.maxPendingInbound)

        let arrival = MeshLinkKey("arrival")
        #expect(!radio.bookPendingInboundForTesting(arrival, at: start.addingTimeInterval(5)),
                "five seconds exactly is within the deadline, so every place is still held and the cap refuses")
        #expect(radio.pendingInboundCountForTesting == NetworkPresenceSession.maxPendingInbound)

        #expect(radio.bookPendingInboundForTesting(arrival, at: start.addingTimeInterval(5.5)),
                "past the deadline the silent connections' places are free again")
        #expect(radio.pendingInboundCountForTesting == 1)
        #expect(radio.isPendingInboundForTesting(arrival))
        // R2: bounded by the radio's pending cap.
        for key in silent {
            #expect(!radio.isPendingInboundForTesting(key), "\(key.rawValue) outlived its hello deadline")
        }
        #expect(!radio.bookPendingInboundForTesting(arrival, at: start.addingTimeInterval(6)),
                "a key already pending is never booked twice")
    }
}
