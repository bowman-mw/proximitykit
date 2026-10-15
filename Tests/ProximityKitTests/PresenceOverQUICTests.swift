// PresenceOverQUICTests.swift
// ProximityKitTests
//
// P9 item 2 pass 2 (plan §17.1): the presence radio's move onto Network.framework/QUIC — the
// BIND between `PresenceEpochPosture` and what actually goes on the air, the epoch boundary's
// re-advertisement, the dial hello that replaces MultipeerConnectivity's free inbound-peer
// resolution, and the stand-down on a start failure.
//
// A partial copy (ProximityKit plan step A1.3, which copies into the package every cell of the Fernlet
// repository's tests that reads this module's sources before that repository stops holding them): of
// the Fernlet repository's FernletTests file of the same name, this holds only the two cells of
// `PresenceOverQUICTests` that read this module's sources, with the suite's name and theirs unchanged,
// each source read through `PackageRoot`. Of `theManagerNoLongerNamesTheRetiredRadio` it holds the
// ProximityKit half, the presence engine's; the half over FernletSocial's presence manager stays in
// that repository's original. Its other cells, which drive the manager over a radio fake, and its host
// stay there too, so what this header says of them is not held here.

import Foundation
import Testing

/// The presence radio's source walls: the listener and browser tasks' cancellation guards, and the
/// presence engine driving the QUIC radio through the presence TXT vocabulary. Each reads this module's
/// sources as text through `PackageRoot`; none starts a radio.
@MainActor
@Suite(.serialized)
struct PresenceOverQUICTests {

    // MARK: - A dial that cannot be made

    /// The listener and browser task bodies check for cancellation before they report.
    ///
    /// A source claim because it has to be: `NetworkListener.run` is a framework call a unit test
    /// cannot make throw. The order is the whole of it — `republish(posture:discoveryInfo:)`
    /// cancels the listener task at EVERY epoch boundary and every roster refresh, because
    /// re-creating the listener is the only way to withdraw a Bonjour registration, so a
    /// `CancellationError` reported as a start failure would stand presence down every 900 s.
    @Test func theListenerAndBrowserTasksDoNotReportTheirOwnCancellation() throws {
        let code = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Transport/NetworkPresenceSession.swift")
        )
        // R2: bounded by the two signatures.
        for signature in ["func startListener() throws", "func startBrowser()"] {
            let body = try #require(
                MeshRoutedSourceScan.bracedBody(after: signature, in: code),
                "\(signature) is gone or its braces do not close"
            )
            let guardIndex = try #require(
                body.range(of: "guard !Task.isCancelled else { return }")?.lowerBound,
                "\(signature)'s task body reports without checking for its own cancellation first"
            )
            let reportIndex = try #require(
                body.range(of: "report(")?.lowerBound, "\(signature) no longer reports at all"
            )
            #expect(guardIndex < reportIndex, "\(signature) guards AFTER it reports, which guards nothing")
        }
    }

    // MARK: - The retirement scan

    /// The presence engine drives the QUIC presence radio and speaks its TXT vocabulary.
    ///
    /// The rule-7 gate for a two-pass item: pass 1 changed nothing on the air, so the only
    /// mechanical proof that pass 2 RAN is that the MC path is gone from the manager and the engine
    /// builds the QUIC radio. This is the ProximityKit half of the Fernlet repository's cell of the
    /// same name, the engine's: that cell's other half, the retired radio's needles (in code and in
    /// comments) absent from FernletSocial's presence manager and the manager driving this engine,
    /// reads a file only that repository holds, and stays there.
    @Test func theManagerNoLongerNamesTheRetiredRadio() throws {
        let engine = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Presence/ProximityPresenceSession.swift"))
        #expect(engine.contains("NetworkPresenceSession"), "whose production conformer the engine builds")
        #expect(engine.contains("PresenceAdvertisement"), "through the presence TXT vocabulary")
    }
}
