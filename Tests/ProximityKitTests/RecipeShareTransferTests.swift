// RecipeShareTransferTests.swift
// ProximityKitTests
//
// P9 item 3 pass 1 (Docs/Plan-ProximityKit-Network-Migration-2026-08-27.md §17.1): the recipe-share
// radio's PAUSE/RESUME CONTRACT and its SEND PIPELINE as tier-1 values, settled before the bytes
// move to QUIC.
//
// The premise correction these cells encode: the recipe share is not a chunked transfer and never
// was — the payload crosses as one sealed frame — so "preserving pause/resume semantics" means
// preserving the RADIO's pause/resume, the shipped behaviour that closes this Fernlet to a third
// device while a pairing is held and reopens it when the pairing's record is evicted. The two bare
// calls that used to carry it are now one total table (`ProximityPairDiscoveryGate`), and the one that
// a transport swap would most plausibly get wrong — "pause" meaning "stand the connection down" —
// is refused by construction: a discovery pause is accepted in every phase of an exchange and moves
// none of them.
//
// A partial copy (ProximityKit plan step A1.3, which copies into the package every cell of the Fernlet
// repository's tests that reads this module's sources before that repository stops holding them): of
// the Fernlet repository's FernletTests file of the same name, this holds only the two rule-7 needles
// of `RecipeShareTransferTests` over the pair session's source, with the suite's name and theirs
// unchanged, the source read through `PackageRoot`. Its tables, its manager cells and its host stay
// there, so what this header says of them is not held here.

import Foundation
import Testing

/// The pair session's discovery contract and its advertised name's cap, held in its source: the
/// discovery gate is the one door to the radio's pause and resume, and no Character cap stands beside
/// the byte bound.
@MainActor
struct RecipeShareTransferTests {

    // MARK: - Rule-7 needles for pass 2

    /// The gate is the ONLY door to the radio's discovery. Pass 2 swaps the session out; a bare
    /// `pauseDiscovery()` added back beside it would leave the contract with two owners again, and
    /// the table would stop being the contract.
    ///
    /// Counting whole-file occurrences alone does not say that: deleting the call from inside the
    /// gate and adding one back in `registerConnection` keeps the count at 1 while handing the
    /// contract two owners. So the count is paired with CONTAINMENT — every occurrence must sit
    /// inside `applyDiscoveryGate`'s brace-matched body — which is what reddens on a relocation.
    /// (The usual grep-wall caveat stands: `let radio = session; radio.pauseDiscovery()` evades
    /// both halves. The wall is against drift, not against a determined author.)
    @Test func theManagerTouchesDiscoveryThroughTheGateAlone() throws {
        let source = MeshRoutedSourceScan.codeOnly(try Self.managerSource())
        let gateBody = try #require(
            MeshRoutedSourceScan.bracedBody(after: "private func applyDiscoveryGate(", in: source),
            "applyDiscoveryGate is gone — the discovery contract has no door"
        )
        // R2: bounded by the two verbs.
        for verb in ["session.pauseDiscovery()", "session.resumeDiscovery()"] {
            let whole = Self.occurrences(of: verb, in: source)
            let insideGate = Self.occurrences(of: verb, in: gateBody)
            #expect(whole == 1, "\(verb) is called \(whole) times; the gate is the one door")
            #expect(insideGate == whole, "\(verb) is called outside applyDiscoveryGate's own body")
        }
    }

    /// The advertised name's cap is the byte bound and nothing else: the Character cap it replaced
    /// must not come back beside it.
    @Test func theAdvertisementNameHasNoCharacterCap() throws {
        let source = try Self.managerSource()
        #expect(source.contains("ProximityPairAdvertisedName.publishable(displayName, in: namespace)"))
        #expect(source.contains("displayName.prefix(") == false,
                "a Character cap is back on the advertised name")
    }

    // MARK: - Helpers

    /// The recipe radio's owner's source: ProximityKit's pair session (the recipe-share manager's
    /// mechanism until plan step A0.7.3, when the manager left for FernletSocial over it).
    private static func managerSource() throws -> String {
        try PackageRoot.source("Sources/ProximityKit/PairSession/ProximityPairSession.swift")
    }

    /// How many times `needle` occurs in `source`, without overlap.
    private static func occurrences(of needle: String, in source: String) -> Int {
        source.components(separatedBy: needle).count - 1
    }
}
