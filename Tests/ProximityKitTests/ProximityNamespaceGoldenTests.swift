// ProximityNamespaceGoldenTests.swift
// ProximityKitTests
//
// Every byte string `ProximityNamespace.fernlet` carries besides its payload vocabulary, its radios'
// presentation strings and its peer-name policy, each pinned by a literal written by hand before any
// of them moved onto the namespace (Docs/Plan-FernletCoach-ProximityKit-2026-10-01.md §4 A0.2), and
// every ProximityKit reader of those values held to the namespace it is handed. Moving a value onto
// the namespace moves no byte; this file is how that claim is checked rather than asserted.
//
// A partial copy (ProximityKit plan step A1.3, which copies into the package every cell of the Fernlet
// repository's tests that reads this module's sources before that repository stops holding them): of
// the Fernlet repository's FernletTests file of the same name, this holds only the three cells of
// `ProximityNamespaceGoldenTests` that read this module's sources, with the suite's name and theirs
// unchanged, each source read through `PackageRoot` and the module walk through the package's walker
// (`TestSupport/PackageSwiftFiles.swift`) at its floor:
//
//   - the radios' log subsystem, read off the namespace in each radio's source: its ProximityKit half.
//     The golden row it stands beside, `.fernlet`'s log subsystem against its frozen literal, names
//     Fernlet's namespace and stays in that repository's original;
//   - the mesh radio's heartbeat and channel binding taking their values whole: the source pins, and
//     the exporter label's role read off `.packageTest` where the original reads `.fernlet`'s, which
//     that repository's original keeps;
//   - the keychain-copy walk: ProximityKit's code reaches the keychain through its own copy and names
//     the original `KeychainItem` nowhere.
//
// The golden table, the known answers, the transcripts and every other group name Fernlet's namespace
// or its stores and stay there, so what the first paragraph says of them is not held here.

import Foundation
import Testing
@testable import ProximityKit

/// The namespace's readers held in ProximityKit's sources: each radio builds its one `Logger` from the
/// namespace's log subsystem, the mesh radio's heartbeat and channel binding take the values they are
/// handed whole, and the module reaches the keychain only through its own copy of the funnel.
@MainActor
@Suite(.serialized)
struct ProximityNamespaceGoldenTests {

    // MARK: Group 1 — the golden table

    /// The radios' log subsystem: since step A0.2.7 each radio builds its one `Logger` in
    /// `init(namespace:)` from the namespace it is handed. A `Logger` does not expose its subsystem, so
    /// that read is pinned in each radio's source: exactly one `Logger` built from
    /// `namespace.installation.logSubsystem`, and no subsystem spelled as a literal. (The Fernlet
    /// repository's original also holds `.fernlet`'s log-subsystem row to its frozen literal first;
    /// that row names Fernlet's namespace and stays there.)
    @Test func theThreeRadiosLogUnderTheFrozenSubsystem() throws {
        let fromNamespace = "Logger(subsystem: namespace.installation.logSubsystem, category: \""
        let radios = [
            "Sources/ProximityKit/Transport/NetworkMeshSession.swift",
            "Sources/ProximityKit/Transport/NetworkPresenceSession.swift",
            "Sources/ProximityKit/Transport/NetworkPairSession.swift"
        ]
        // R2: bounded by the three radios.
        for path in radios {
            let code = MeshRoutedSourceScan.codeOnly(try PackageRoot.source(path))
            let literals = Self.loggerSubsystems(in: code)
            #expect(literals.isEmpty, "\(path) still declares a Logger under the literal subsystem \(literals)")
            let built = code.components(separatedBy: fromNamespace).count - 1
            #expect(built == 1, "\(path) builds \(built) Loggers from the namespace's log subsystem, not one")
        }
    }

    // MARK: Group 12 — the radios (A0.2.7)

    /// The mesh radio's two consumers of a moved value, against what their fields promise. Tier 1
    /// cannot open the live QUIC connection both run over, so they are pinned in source, the way
    /// `NetworkMeshWireTests` pins the wire ceiling's two call sites:
    ///
    /// - the heartbeat goes out on both pipes as the radio's own `heartbeatDatagram`, and both receive
    ///   loops drop it by byte equality against that same value before anything decodes a frame;
    /// - the channel binding derives under the label it is handed, whole, as the `.tlsExporterLabel`
    ///   role says (its `prefixBytes` are its bytes): the TLS exporter gets the label's bytes and their
    ///   count, no terminator and no count in front. It names no registry purpose, and its one caller
    ///   hands it the label the radio read off its namespace.
    ///
    /// The role is read off `.packageTest`'s exporter label, built by the same family initializer as
    /// every namespace's; the Fernlet repository's original reads `.fernlet`'s, and keeps that read.
    @Test func theMeshRadiosHeartbeatAndChannelBindingTakeTheirValuesWhole() throws {
        let code = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Transport/NetworkMeshSession.swift"))
        func count(_ needle: String) -> Int { code.components(separatedBy: needle).count - 1 }
        #expect(count("guard payload != heartbeatDatagram else {") == 2,
                "both receive loops must drop the heartbeat by byte equality")
        #expect(count("try await self.sendFramed(self.heartbeatDatagram, over: stream)") == 1,
                "the control-stream beat must send the radio's own heartbeat")
        #expect(count("try await datagrams.send(self.heartbeatDatagram)") == 1,
                "the datagram beat must send the radio's own heartbeat")

        let label = ProximityNamespace.packageTest.family.purposes.keyDerivation.meshTLSExporterV1
        #expect(label.role == .tlsExporterLabel && label.prefixBytes == label.data, "an exporter label is taken whole")
        let binding = try #require(MeshRoutedSourceScan.bracedBody(after: "static func channelBindingHash(", in: code),
                                   "the channel binding's derivation is gone")
        #expect(binding.contains("let label = exporterLabel.rawValue"), "the binding derives under another label")
        #expect(binding.contains("label.utf8.count,"), "the exporter is not handed the label's own byte count")
        #expect(!binding.contains("FernletCryptoPurpose"), "the binding names a registry purpose again")
        #expect(count("Self.channelBindingHash(for: connection, exporterLabel: tlsExporterLabel)") == 1,
                "the introduction no longer binds under the radio's own exporter label")
        #expect(count("tlsExporterLabel = namespace.family.purposes.keyDerivation.meshTLSExporterV1") == 1,
                "the radio no longer reads its exporter label off the namespace")
    }

    // MARK: Group 15 — the keychain mechanism (A0.2.11)

    /// ProximityKit's code reaches the keychain through its own copy and names FernletFoundation's
    /// `KeychainItem` nowhere, so the move is whole: a call that went back to the original, from a
    /// file that still imports FernletFoundation for something else, fails here. Comments may name
    /// `KeychainItem` (the copy's own explain where it came from); the scan reads code lines only.
    /// In the package the original cannot be imported at all (ProximityKit depends on nothing), so
    /// what this holds here is that no code line names a bare `KeychainItem`, a local type or alias of
    /// that name included, and that the copy is still the funnel the module calls. The walk is the
    /// package's walker, held to its floor, where the original held its own walk to 50 files.
    @Test func proximityKitReachesTheKeychainOnlyThroughItsOwnCopy() throws {
        let files = try PackageSwiftFiles.sources()
        let original = try NSRegularExpression(pattern: #"(?<![A-Za-z0-9_])KeychainItem\b"#)
        var copyUses = 0
        var offenders: [String] = []
        // R2: bounded by the module's own file list.
        for file in files {
            let code = MeshRoutedSourceScan.codeOnly(file.text)
            copyUses += code.components(separatedBy: "ProximityKeychainItem.").count - 1
            if original.firstMatch(in: code, range: NSRange(code.startIndex..., in: code)) != nil {
                offenders.append(file.path)
            }
        }
        #expect(files.count >= PackageSwiftFiles.sourceFloor, """
            the ProximityKit sweep read only \(files.count) Swift files (floor \(PackageSwiftFiles.sourceFloor))
            """)
        #expect(copyUses > 0, "the sweep found no `ProximityKeychainItem.` use: wrong tree?")
        #expect(offenders.isEmpty, """
            ProximityKit code names FernletFoundation's KeychainItem in \(offenders). Reach the keychain \
            through `ProximityKeychainItem`, which issues the same queries.
            """)
    }

    // MARK: - Helpers

    /// The subsystems of every `Logger(subsystem: "…"` spelled with a literal in `source`.
    private static func loggerSubsystems(in source: String) -> [String] {
        let opener = "Logger(subsystem: \""
        var found: [String] = []
        var rest = Substring(source)
        // R2: each pass consumes the opener it found, so the loop ends within the source's length.
        while let start = rest.range(of: opener) {
            let tail = rest[start.upperBound...]
            guard let close = tail.firstIndex(of: "\"") else { break }
            found.append(String(tail[..<close]))
            rest = tail[close...]
        }
        return found
    }
}
