// RecipeShareOverQUICTests.swift
// ProximityKitTests
//
// P9 item 3 pass 2 (Docs/Plan-ProximityKit-Network-Migration-2026-08-27.md §17.1): the recipe-share
// radio's move onto Network.framework/QUIC — the posture that goes on the air, the dial hello that
// replaces the retired transport's free inbound-peer resolution, the pause/resume that closes this
// Fernlet to a third device while a pairing is held, and the per-transfer stream a picture recipe
// earns.
//
// A partial copy (ProximityKit plan step A1.3, which copies into the package every cell of the Fernlet
// repository's tests that reads this module's sources before that repository stops holding them): of
// the Fernlet repository's FernletTests file of the same name, this holds only the four cells of
// `RecipeShareOverQUICTests` that read this module's sources, with the suite's name and theirs
// unchanged, each source read through `PackageRoot` and the pair-session walk through the package's
// walker (`TestSupport/PackageSwiftFiles.swift`) at its floor. Of
// `theRecipeServiceTypeIsItsOwnAndIsDeclared` it holds the ProximityKit half, the session's ALPN reads;
// the recipe radio's values under Fernlet's namespace and Fernlet's Info.plist stay in that
// repository's original. Its other cells, its radio fake and its host stay there too, so what this
// header says of them is not held here.

import Foundation
import Testing

/// The recipe radio's source walls: the withdrawn registration's republish, the listener and browser
/// tasks' cancellation guards, the retired radio gone from the pair session and every file that
/// extends it, and the ALPN the session binds read off its pair profile. Each reads this module's
/// sources as text through `PackageRoot`; none starts a radio.
@MainActor
struct RecipeShareOverQUICTests {

    // MARK: - Runtime failures of the listener and the browser

    /// And the source needle that the `.remove` branch is not a bare assignment — the shape the
    /// whole finding is: a state flag cleared and nothing else done about it. (The behaviour half,
    /// a withdrawn registration republishing under a fresh posture, stays in the Fernlet
    /// repository's original suite.)
    @Test func theRegistrationRemoveBranchIsNotABareAssignment() throws {
        let code = MeshRoutedSourceScan.codeOnly(try Self.sessionSource())
        let body = try #require(
            MeshRoutedSourceScan.bracedBody(after: "func listenerRegistrationChanged(", in: code),
            "listenerRegistrationChanged is gone or its braces do not close"
        )
        let removeIndex = try #require(body.range(of: "case .remove:")?.upperBound,
                                       "the `.remove` branch is gone")
        #expect(body[removeIndex...].contains("republishListener()"),
                "a withdrawn registration is silent again: nothing on the air, isListening still true")
    }

    // MARK: - Rule-7 gates

    /// The listener and browser task bodies check for cancellation before they report.
    ///
    /// A source claim because it has to be: `NetworkListener.run` is a framework call a unit test
    /// cannot make throw. The order is the whole of it — `pauseDiscovery()` cancels the listener
    /// task every time a pairing forms, so a `CancellationError` reported as a start failure would
    /// stand the radio down on the very event that is supposed to keep it up and quiet.
    @Test func theListenerAndBrowserTasksDoNotReportTheirOwnCancellation() throws {
        let code = MeshRoutedSourceScan.codeOnly(try Self.sessionSource())
        // The browser's door is `reportBrowserFailure(` since the runtime-failure fix — a browser
        // failure is not a start failure — so each task is pinned to the door it actually uses.
        let doors = [
            "func startListener() throws": "report(",
            "func startBrowser()": "reportBrowserFailure("
        ]
        // R2: bounded by the two doors.
        for (signature, door) in doors.sorted(by: { $0.key < $1.key }) {
            let body = try #require(
                MeshRoutedSourceScan.bracedBody(after: signature, in: code),
                "\(signature) is gone or its braces do not close"
            )
            let guardIndex = try #require(
                body.range(of: "guard !Task.isCancelled else { return }")?.lowerBound,
                "\(signature)'s task body reports without checking for its own cancellation first"
            )
            let reportIndex = try #require(
                body.range(of: door)?.lowerBound, "\(signature) no longer reports at all"
            )
            #expect(guardIndex < reportIndex, "\(signature) guards AFTER it reports, which guards nothing")
        }
    }

    /// **The rule-7 gate for pass 2.** Pass 1 changed nothing on the air, so the only mechanical
    /// proof that pass 2 RAN is that the retired radio is gone from the manager, the new service
    /// type is declared, and the session binds its own ALPN.
    ///
    /// Pinned in both directions — a file that names neither has been renamed or emptied, not
    /// cleaned.
    ///
    /// Vacuous by design since the deletion round (2026-09-22): the framework is gone from the tree,
    /// so these needles can no longer match anything. Kept anyway — they cost nothing and they are
    /// the per-manager half of the tree-wide wall (`TransportNeutralityBoundaryTests`, in the Fernlet
    /// repository; the package's platform wall refuses the framework's import in this module).
    @Test func theManagerNoLongerNamesTheRetiredRadio() throws {
        let source = try Self.managerSource()
        let code = MeshRoutedSourceScan.codeOnly(source)
        // R2: bounded by the needle list.
        for needle in ["MeshMultipeerSession", "MCPeerID", "MCSession", "MultipeerConnectivity",
                       "PeerChannelTransport", "shouldAcceptInvitation", "hasPendingConnections",
                       "disconnectPeer"] {
            #expect(!code.contains(needle), "ProximityPairSession still names `\(needle)` in code")
        }
        // One FILE is not the unit: an `extension ProximityPairSession` in a new file, or a
        // `typealias`, reintroduces every needle above without reddening a scan of this one. The
        // subtree is, and `displayHint` joins the list — under QUIC the hint is empty, so a reader
        // that still prefers it renders nothing where a name belongs.
        // R2: bounded by the module's file list.
        for (path, other) in try Self.pairSessionSources() where path != Self.managerPath {
            let otherCode = MeshRoutedSourceScan.codeOnly(other)
            // R2: bounded by the needle list.
            for needle in ["MeshMultipeerSession", "MCPeerID", "MCSession", "MultipeerConnectivity",
                           "displayHint"] {
                #expect(!otherCode.contains(needle), "\(path) names `\(needle)` in code")
            }
        }
        #expect(!code.contains("displayHint"),
                "a user-visible line names a peer by the transport hint again — see displayName(for peer:)")
        #expect(code.contains("ProximityPairRadioSession"), "and it drives the QUIC recipe radio's seam")
        #expect(code.contains("NetworkPairSession"), "whose production conformer it builds")
        #expect(code.contains("ProximityPairAdvertisement"), "through the recipe TXT vocabulary")

        // Comments get the narrower rule the presence retirement drew: a framework API TYPE name in
        // prose describes machinery this file no longer has, while the framework's NAME describes
        // history and is the sentence that explains why the posture is ephemeral at all.
        // R2: bounded by the needle list.
        for needle in ["MCPeerID", "MCSession", "MCNearbyServiceAdvertiser", "MCNearbyServiceBrowser"] {
            #expect(!source.contains(needle),
                    "a ProximityPairSession comment still describes `\(needle)` machinery")
        }
    }

    /// The recipe radio's ALPN is its own: the session reads it off its pair profile's radio and
    /// binds it.
    ///
    /// A shared ALPN would let a recipe dial complete a TLS handshake with a mesh or presence
    /// listener. This is the ProximityKit half of the Fernlet repository's cell of the same name:
    /// that cell's other half, Fernlet's recipe radio row (its service type and ALPN, apart from the
    /// mesh's and presence's) and the service type's declaration in Fernlet's Info.plist, reads
    /// values and a file only that repository holds, and stays there.
    @Test func theRecipeServiceTypeIsItsOwnAndIsDeclared() throws {
        let session = try Self.sessionSource()
        #expect(session.contains("alpn = profile.radio.alpn"),
                "the session reads its ALPN off its pair profile's radio, the host namespace's recipe row")
        #expect(session.contains("alpn: alpn"), "the session must actually bind its ALPN")
    }

    // MARK: - Helpers

    /// The recipe radio's owner, ProximityKit's pair session (the recipe-share manager's mechanism
    /// until plan step A0.7.3, when the manager left for FernletSocial over it), by its path under the
    /// package root.
    private static let managerPath = "Sources/ProximityKit/PairSession/ProximityPairSession.swift"

    /// The pair session's source.
    private static func managerSource() throws -> String {
        try PackageRoot.source(managerPath)
    }

    /// Every Swift file under `PairSession/`, plus any file ANYWHERE in ProximityKit that
    /// extends the pair session — the unit the rule-7 scan has to cover, because one file is not it.
    /// Each by its path under the package root, read through the package's walker, which is held to
    /// its floor here, so a walk that stops resolving fails rather than finding no extension.
    private static func pairSessionSources() throws -> [(String, String)] {
        let files = try PackageSwiftFiles.sources()
        #expect(files.count >= PackageSwiftFiles.sourceFloor, """
            the pair-session scan walked \(files.count) ProximityKit files (floor \(PackageSwiftFiles.sourceFloor)): \
            the walk is broken, and a search for an extension of the pair session would pass vacuously
            """)
        let directory = files.filter { $0.path.hasPrefix("PairSession/") }
        #expect(directory.count >= 3, "the PairSession directory moved or emptied — the scan would pass vacuously")
        let extending = files.filter {
            !$0.path.hasPrefix("PairSession/") && $0.text.contains("extension ProximityPairSession")
        }
        return (directory + extending).map { (PackageSwiftFiles.sourceFolder + "/" + $0.path, $0.text) }
    }

    /// The recipe radio's source.
    private static func sessionSource() throws -> String {
        try PackageRoot.source("Sources/ProximityKit/Transport/NetworkPairSession.swift")
    }
}
