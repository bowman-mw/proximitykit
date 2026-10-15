// MeshP9AcceptanceTests.swift
// ProximityKitTests
//
// Network migration **P9's acceptance battery** (plan §17.1, launcher item 9): one serialized suite
// per clause, each promoting the named tier-1 claims of the item it speaks for and running its
// clause END TO END on the shipping seams, so CI gating a clause fails on this battery's own
// assertions rather than on a unit suite's. The P8 battery is the template and the rule is the same
// — where an exhaustive space already exists it is RE-WALKED here rather than sampled, and never by
// calling the unit suite's oracle: clause (c) carries its own 60-row expectation of the discovery
// gate, spelled EVENT-outermost with every radio reading a literal row, so a table and a unit
// oracle that drifted together would still redden here.
//
// **Five suites.** The ephemeral posture both radios wear (item 2 pass 1 + item 3's posture
// decision), the presence swap (item 2 pass 2), the recipe swap with pause/resume (item 3), the
// MultipeerConnectivity retirement (item 4), and an honesty suite naming — by ledger row — what no
// CI machine can run. `CIGateSelectorBoundaryTests` therefore moves its battery pin from 48 to 53,
// and the same commit gates the suites items 2, 3 and 4 left on no CI line at all: the seven this
// battery promotes, plus the twenty-one the fix review's own accounting found beside them. Which
// suites those are is DERIVED (`MeshP9HonestyAcceptanceTests.p9TouchedSuites`) rather than
// hand-listed — the first cut listed seven by hand and missed `ProximityRecipeShareCapTests`, 31
// cells holding the very pause/resume behaviour clause (c) leans on.
//
// **Rule 7 — "a row that lands in two passes needs its gate to assert the later pass RAN."** Items
// 2 and 3 are two-pass by shape (a value, then the radio wearing it), and pass 1 changed nothing on
// the air. Every clause below therefore carries at least one needle that is FALSE at the pass-1
// commit and true at the pass-2 one: the manager naming its QUIC radio (`NetworkPresenceSession` until
// ProximityKit plan step A1.1; since then the presence engine, `ProximityPresenceSession`, which builds
// that radio) / `NetworkPairSession` and no `serviceType` at all; the QUIC service type declared in
// `Info.plist`; the radio advertising the posture's OWN bytes; `makeSession:` existing to inject a
// fake through. A needle satisfied by a rename alone is named as such in `GATES.md` and is not one.
//
// **What this battery does NOT claim** is in clause (e), by name and not by omission: item 4 was
// SPLIT; the MC->QUIC FLIP landed on 2026-09-21 and the DELETION on 2026-09-22, so clause (d) is
// now the zero-list it was always meant to become (the two MC files absent, the framework imported
// nowhere, the _fernlet-friend pair retired); the two lane rows (9.2.2, 9.3.2) are tier-2
// sim↔sim observations; item 0's rows need phones in the owner's hands; P9-3-A was a product
// decision on P7's run-policy table. The two determinism digests keep their one home in
// `MeshP5AcceptanceTests`, this file spells neither, and the gate that runs it re-runs the
// determinism suites.
//
// A partial copy (ProximityKit plan step A1.3, batch D: the cells of the Fernlet repository's tests
// that read this module's sources, copied before Fernlet deletes its in-tree copy of the module): of
// that repository's FernletTests file of the same name, this holds only the eight cells of clauses
// (a) to (d) that read ProximityKit's code, under their suites' and tests' names, each holding the
// half of its original that reads this module's files, through `PackageRoot` and, for a walk, through
// `MeshP7Acceptance` (this target's MeshP7AcceptanceTests.swift), which walks the module through
// `PackageSwiftFiles`: clause (c)'s gate-and-subtree cell whole, and of the other seven the needles
// over the posture, the two radios, the presence engine, the pair session, the manager and the
// channel introduction, and the module's half of each walk. Every walk the original made over the
// module together with FernletSocial or the app is split by root: this half holds the module's share
// of each home list and zero-list, and Fernlet's copy holds the rest. The rest of the file (the
// rigs, the behaviour cells, the Bonjour partition, the record-survival cell and clause (e), the
// honesty suite) and each cell's other half (Fernlet's namespace, its Info.plist, its docs, its
// presence manager and its roots) stay there, so what this header says of the rest is not held here.

import Foundation
import Testing

// MARK: - MeshP9Acceptance

/// The paths P9's copied source cells read, each relative to the package root. Fernlet's rig also
/// holds the two radio rigs, the posture walk, the Bonjour partition and the presence manager's,
/// app's and workflow's paths; none of them reads this module's code, so they stay there.
///
/// **Concurrency.** Constants only; safe from any isolation.
nonisolated enum MeshP9Acceptance {

    // MARK: Paths

    /// The presence posture value (item 2 pass 1).
    static let posturePath = "Sources/ProximityKit/Presence/PresenceEpochPosture.swift"

    /// The presence radio (item 2 pass 2).
    static let presenceSessionPath = "Sources/ProximityKit/Transport/NetworkPresenceSession.swift"

    /// ProximityKit's presence engine (plan step A1.1): the one owner of the presence radio, the
    /// posture it wears and the TXT record it advertises.
    static let presenceEnginePath = "Sources/ProximityKit/Presence/ProximityPresenceSession.swift"

    /// The recipe radio, which also declares `ProximityPairPosture` (item 3 pass 2).
    static let recipeSessionPath = "Sources/ProximityKit/Transport/NetworkPairSession.swift"

    /// The recipe radio's owner: ProximityKit's pair session.
    static let recipePairSessionPath =
        "Sources/ProximityKit/PairSession/ProximityPairSession.swift"

    /// The two files that owned MultipeerConnectivity until the deletion round (2026-09-22), sorted —
    /// pinned ABSENT now (item 4's `[SPLIT: LATER]` half, taken).
    static let multipeerFiles = [
        "Sources/ProximityKit/Transport/MCPeerIDStore.swift",
        "Sources/ProximityKit/Transport/MeshMultipeerSession.swift"
    ]

    /// A file the shipping radio lives in, in the folder the two retired files lived in: present, so
    /// the absence above is read in a folder that still resolves rather than in one that moved.
    static let transportFolderWitness = "Sources/ProximityKit/Transport/NetworkMeshSession.swift"
}

// MARK: - (a) The ephemeral posture

/// **Items 2 (pass 1) and 3: the posture is the product, and the two radios wear different ones on
/// purpose.** Of the original's cells this holds the halves of the two that read ProximityKit's code:
/// the two posture types pinned apart in source, and neither posture persisted or scheduling.
@Suite(.serialized)
struct MeshP9EphemeralPostureAcceptanceTests {

    /// **The two radios wear different postures by decision, and neither wears the other's.**
    ///
    /// The ledger's two posture decisions, which no single unit suite spans. Presence is anchored to
    /// a 900 s epoch every device agrees on, with the certificate minted at the epoch START; recipe
    /// share is minted per `start()` and per `resume()` because its lifetime is a Food-tab visit,
    /// and giving it the epoch type would be a silent mismatch plus a second timer on a subsystem
    /// allowed one. The needle is narrow on purpose: the recipe session legitimately reuses
    /// `PresenceEpochPosture.systemEntropy` / `.hexadecimal` as byte helpers, so the ban is on the
    /// posture's own MINT and on the epoch clock, not on the type's name.
    ///
    /// Rule 7: `ProximityPairPosture` and its three mint sites exist only because pass 2 landed. The
    /// original cell's other half (two mints at one instant share no name, session id or certificate)
    /// runs the posture, not its source, and stays in Fernlet's copy of the cell.
    @Test func theTwoRadiosWearDifferentPosturesByDecisionAndNeitherWearsTheOthers() throws {
        let posture = MeshRoutedSourceScan.codeOnly(try PackageRoot.source(MeshP9Acceptance.posturePath))
        #expect(posture.contains("IdentityService.presenceEpochStart(at: now)"),
                "the presence certificate is minted at the epoch start")
        #expect(posture.contains("IdentityService.presenceEpoch(at: now)"),
                "and the epoch comes from the one presence clock")
        #expect(!posture.contains("randomInstanceName"),
                "the presence name is drawn here, not borrowed from the mesh advertisement")

        let session = MeshRoutedSourceScan.codeOnly(try PackageRoot.source(MeshP9Acceptance.recipeSessionPath))
        #expect(!session.contains("PresenceEpochPosture.minted"),
                "the recipe radio must not wear the 900 s posture — its lifetime is a tab visit")
        #expect(!session.contains("presenceEpoch"), "and it must not read the presence clock")
        // R2: bounded by the three banned clock spellings.
        for banned in ["Timer", "rotateEpochIfNeeded", "presenceEpochSeconds"] {
            #expect(!session.contains(banned),
                    "`\(banned)` is a rotation timer on a radio the ledger allows none")
        }
        let started = try #require(
            MeshRoutedSourceScan.bracedBody(
                after: "func start(advertisement: [String: String]) throws {", in: session),
            "the recipe radio's start door is gone")
        #expect(started.contains("ProximityPairPosture.minted("), "a fresh posture per start()")
        let resumed = try #require(
            MeshRoutedSourceScan.bracedBody(after: "func resumeDiscovery() {", in: session),
            "the recipe radio's resume door is gone")
        #expect(resumed.contains("ProximityPairPosture.minted("), "and a fresh one per resume()")
    }

    /// **Neither posture is persisted, and neither file schedules anything.**
    ///
    /// P9's wipe-wall row, inverted: the phase added no persisted surface, so a posture that reached
    /// for the keychain, a file or `UserDefaults` would owe a wipe row and delete-all wiring that do
    /// not exist. Widened past the unit suite's presence-only cell to the recipe posture, which has no
    /// cell of its own, and restricted to the value declarations — `NetworkPairSession` as a whole
    /// legitimately holds tasks. The original cell's other half (Fernlet's wipe coverage doc names
    /// neither posture) reads Fernlet's docs and stays in Fernlet's copy of the cell.
    @Test func neitherPostureIsPersistedAndTheValuesScheduleNothing() throws {
        let posture = MeshRoutedSourceScan.codeOnly(try PackageRoot.source(MeshP9Acceptance.posturePath))
        let session = MeshRoutedSourceScan.codeOnly(try PackageRoot.source(MeshP9Acceptance.recipeSessionPath))
        let recipePosture = try #require(
            MeshRoutedSourceScan.bracedBody(after: "nonisolated struct ProximityPairPosture {", in: session),
            "the recipe posture's declaration is gone")
        // The vendor-identifier symbol is deliberately not spelled: the no-tracking wall bans it in
        // every file, comments included, so naming it here would only indict this suite.
        let forbidden = ["UserDefaults", "Keychain", "KeychainItem", "SecItem", "FileManager",
                         "write(to:", "JSONSidecarFile", "UIDevice", "hostName", "bundleIdentifier"]
        // R2: bounded by the forbidden list × the two sources.
        for marker in forbidden {
            #expect(!posture.contains(marker), "PresenceEpochPosture reaches for '\(marker)'")
            #expect(!recipePosture.contains(marker), "ProximityPairPosture reaches for '\(marker)'")
        }
        // R2: bounded by the three scheduling spellings.
        for marker in ["Task", "Timer", "sleep"] {
            #expect(!posture.contains(marker), "a value schedules nothing: PresenceEpochPosture '\(marker)'")
            #expect(!recipePosture.contains(marker), "nor does ProximityPairPosture: '\(marker)'")
        }
    }
}

// MARK: - (b) The presence swap

/// **Item 2 pass 2: the presence radio on Network.framework/QUIC.** Of the original's cells this
/// holds the halves of the two that read ProximityKit's code: the radio binds its own ALPN off the
/// host's namespace, and the module's share of the seam's homes and of the presence engine's order.
@MainActor
@Suite(.serialized)
struct MeshP9PresenceSwapAcceptanceTests {

    /// **The presence radio is its own service.** A shared ALPN would let a presence dial complete a
    /// TLS handshake with a mesh or recipe listener, so the radio reads its own field off the host's
    /// namespace and binds it. The original cell's other half (Fernlet's three radios' values, and its
    /// Info.plist's declared and retired service types) reads Fernlet's namespace and bundle and stays
    /// in Fernlet's copy of the cell.
    @Test func thePresenceRadioIsItsOwnServiceAndItsPredecessorIsOffTheAir() throws {
        let session = MeshRoutedSourceScan.codeOnly(try PackageRoot.source(MeshP9Acceptance.presenceSessionPath))
        #expect(session.contains("alpn = namespace.family.radios.presence.alpn"),
                "the session reads its ALPN off the host's namespace, from its own radio's field")
        #expect(session.contains("alpn: alpn"), "the session must actually bind its own ALPN")
    }

    /// **The seam has its homes in this module, and the engine wires a radio before it starts it.**
    ///
    /// The original walks the whole package and FernletSocial (and, for the engine's construction,
    /// the app) so an `extension PresenceManager` in a new file of either cannot reintroduce a needle
    /// silently. Split by root: here, over every file of this module at the original's floor, the
    /// presence seam has exactly its two homes (the engine that drives it and the conformer that is
    /// it), the posture is minted in the engine alone, and the module constructs no presence engine of
    /// its own; and the engine's half of the two orders. Fernlet's copy holds the presence manager's
    /// needles, FernletSocial's share of the homes (none), the one construction of the engine in the
    /// manager, and the manager's half of the orders.
    @Test func theManagerNamesNoRetiredRadioAndReachesTheAirThroughTheSeamAlone() throws {
        try Self.expectThePresenceOrdersHold()

        let kit = try MeshP7Acceptance.sources()
        // Anti-vacuity floors, RE-MEASURED at item 9's fix review (NOTE 4) and set within ~20%
        // of reality rather than at a round 100: 141 files here (143 before the deletion round). A floor a deleted third of the
        // package still clears is a floor that cannot fail. It holds ProximityKit's part of the walk.
        #expect(kit.count >= 120, "the ProximityKit scan lost its files (141 when this was measured)")
        #expect(Set(MeshP7Acceptance.homes(of: "PresenceRadioSession", in: kit))
                == ["ProximityPresenceSession.swift", "NetworkPresenceSession.swift"], """
                the presence seam has exactly two homes in the package — the engine \
                that drives it and the conformer that is it. A third is a second owner for one radio
                """)
        #expect(MeshP7Acceptance.homes(of: "PresenceEpochPosture.minted", in: kit) == ["ProximityPresenceSession.swift"],
                "and the posture is minted from one place: the engine the manager's epoch tick asks")
        #expect(MeshP7Acceptance.homes(of: "ProximityPresenceSession(", in: kit).isEmpty,
                "one presence engine per process: the host's. The module builds none of its own, or a second engine on the same namespace would read the first one's advertisements as a stranger's")
    }

    /// The engine's half of the two orders the presence engine's move kept, read off the code: the
    /// engine wires a fresh radio's hooks before it starts it (so no browse result, tunnel or failure
    /// reaches an unwired radio). Each spelling occurs exactly once in the engine's file and inside its
    /// `start(tags:)`, in that order, and the engine's start defers nothing, so a call moved out of that
    /// body reddens. The manager's half (its heart door's `begin` before `notifyConnected()`) reads
    /// FernletSocial's presence manager and stays in Fernlet's copy.
    static func expectThePresenceOrdersHold() throws {
        let engine = MeshRoutedSourceScan.codeOnly(try PackageRoot.source(MeshP9Acceptance.presenceEnginePath))
        let start = try #require(MeshRoutedSourceScan.bracedBody(after: "public func start(tags:", in: engine),
                                 "the engine's `start(tags:)` is gone or its braces do not close")
        let orders = [
            (engine, start, "the engine", "wire(radio)", "try radio.start(posture:")
        ]
        // R2: bounded by the one order this half holds.
        for (code, body, file, first, then) in orders {
            let firsts = code.components(separatedBy: first).count - 1
            let thens = code.components(separatedBy: then).count - 1
            #expect(firsts == 1 && thens == 1, "\(file) spells `\(first)` \(firsts) times and `\(then)` \(thens) times")
            guard let early = body.range(of: first), let late = body.range(of: then) else {
                Issue.record("\(file)'s `\(first)` and `\(then)` are not both inside the body they belong to")
                continue
            }
            #expect(early.upperBound <= late.lowerBound, "\(file) reaches `\(then)` before `\(first)`")
        }
        #expect(!start.contains("defer"), "the engine's start defers a call, which runs after the radio's start")
    }
}

// MARK: - (c) The recipe swap, with pause/resume

/// **Item 3: the recipe radio on QUIC with the shipped pause/resume behaviour intact.** Of the
/// original's cells this holds the two that read ProximityKit's code: the radio binds its own ALPN
/// (that cell's source half), and the one door discovery moves through (whole).
@MainActor
@Suite(.serialized)
struct MeshP9RecipeSwapAcceptanceTests {

    /// **The recipe radio binds its own ALPN.** A shared ALPN would let a recipe dial complete a TLS
    /// handshake with a mesh or presence listener. The original cell's other half (Fernlet's radio
    /// values, its Info.plist's declared and retired service types, and the radio's two-device cap as
    /// a value) reads Fernlet's namespace and bundle or runs the radio's type, and stays in Fernlet's
    /// copy of the cell.
    @Test func theRecipeRadioIsItsOwnServiceAndItsPredecessorIsOffTheAir() throws {
        let session = MeshRoutedSourceScan.codeOnly(try PackageRoot.source(MeshP9Acceptance.recipeSessionPath))
        #expect(session.contains("alpn = profile.radio.alpn"),
                "the session reads its ALPN off its pair profile's radio, the host namespace's recipe row")
        #expect(session.contains("alpn: alpn"), "the session must actually bind its ALPN")
    }

    /// **Discovery moves through the gate alone, and no file of the subtree names the retired
    /// radio.**
    ///
    /// The containment pairing, not text proximity: `occurrences(verb) == 1` alone stayed green when
    /// the call was moved OUT of `applyDiscoveryGate`, so the whole-file count is paired with the
    /// count inside the function's brace-matched body. And the unit is the SUBTREE, not one file —
    /// an `extension ProximityPairSession` in a new file reintroduces every needle without
    /// reddening a scan of the session alone.
    ///
    /// Rule 7 for item 3: the seam and its conformer in the manager (`ProximityPairRadioSession` /
    /// `NetworkPairSession`, spelled `RecipeShareRadioSession` / `NetworkRecipeShareSession` until plan
    /// step A1.0) are false at `79f6b15` and true at `ba34491`.
    @Test func discoveryMovesThroughTheGateAloneAndNoRecipeFileNamesTheRetiredRadio() throws {
        let manager = MeshRoutedSourceScan.codeOnly(try PackageRoot.source(MeshP9Acceptance.recipePairSessionPath))
        let gate = try #require(
            MeshRoutedSourceScan.bracedBody(after: "private func applyDiscoveryGate(", in: manager),
            "applyDiscoveryGate is gone — the discovery contract has no door")
        // R2: bounded by the two discovery verbs.
        for verb in ["session.pauseDiscovery()", "session.resumeDiscovery()"] {
            let whole = manager.components(separatedBy: verb).count - 1
            let inside = gate.components(separatedBy: verb).count - 1
            #expect(whole == 1, "\(verb) is called \(whole) times; the gate is the one door")
            #expect(inside == whole, "\(verb) is called outside applyDiscoveryGate's own body")
        }
        #expect(manager.contains("ProximityPairRadioSession"), "the manager drives the QUIC seam")
        #expect(manager.contains("NetworkPairSession"), "whose production conformer it builds")

        // The BIRTH SEED has one mint site (item 9's fix review, FIX 3). `beginTransferForTesting`
        // is what every cell of this battery and of `RecipeShareTransferTests` drives; the pair
        // session's `send(_:to:)` is what ships, and no cell of either executes it (one golden does,
        // `FernletFeatureGoldenTests`' recipe pairing, which reads the bytes, not the seed) — so
        // while the seed was spelled twice, item 3 pass 1's own defect (`radioIsQuiet: false` on
        // the shipping line) could be restored with the whole tree green. Containment, not
        // proximity: the shipping door's brace-matched body must call the helper, and the record
        // may be constructed in exactly one place.
        let send = try #require(
            MeshRoutedSourceScan.bracedBody(after: "public func send(", in: manager),
            "the pair session's shipping send is gone")
        #expect(send.contains("mintTransfer(for: recipient.id)"), """
            the pair session's send mints its exchange record somewhere other than the one seeded helper — \
            which is how the shipping seed and the seed every test drives came apart before
            """)
        let mints = manager.components(separatedBy: "ProximityPairTransfer(recipientID:").count - 1
        #expect(mints == 1, "the exchange record is constructed in \(mints) places; the helper is the one")

        let subtree = try MeshP7Acceptance.sources(under: "PairSession")
        // Four since 2026-09-29: `ProximityPairSendOutcome.swift` (the send's frozen outcome tokens,
        // added as `RecipeShareOutcome.swift`) was read against the needle walk below, which it
        // passes — it names no radio at all.
        #expect(subtree.count == 4, """
            the PairSession subtree holds \(subtree.count) files, not the four it held when this \
            was measured (the pair session, the advertisement, the transfer record and the send \
            outcome). A fifth is a file this cell's retired-radio walk has never been read against; \
            a fourth gone is a scan that lost its root. EXACT on purpose — `>= 4` was satisfied by \
            the tree it was written against and by every tree that could ever follow it
            """)
        // R2: bounded by the retired-radio spellings × the subtree's files.
        for needle in ["MeshMultipeerSession", "MCPeerID", "MCSession", "MultipeerConnectivity",
                       "PeerChannelTransport", "displayHint"] {
            let homes = Set(MeshP7Acceptance.homes(of: needle, in: subtree)).sorted()
            #expect(homes.isEmpty, "`\(needle)` is back in the recipe subtree, in \(homes)")
        }
    }
}

// MARK: - (d) The MultipeerConnectivity retirement — an HONESTY row, not a zero-list

/// **Item 4 — the zero-list, at last.** Of the original's cells this holds the halves of the two that
/// read ProximityKit's code: the two files absent and the selection seam gone from the module, and the
/// framework imported and named nowhere in it. The Bonjour partition and the record-survival cell read
/// Fernlet's Info.plist and docs and stay in Fernlet's copy, as does each split walk's FernletSocial
/// and app share.
@Suite(.serialized)
struct MeshP9McRetirementAcceptanceTests {

    /// **Both MultipeerConnectivity files are gone, and the selection seam went with them.**
    ///
    /// The zero-list half of item 4, in both directions. The two files are pinned ABSENT (a
    /// re-created one reddens here with the deletion checklist in reverse), in a folder pinned to
    /// still resolve; the selection seam that existed only to choose between two radios —
    /// `MeshTransportKind`, `MeshTransportFactory`, the `quicSelectionEnvironmentKey` read, the MC
    /// conformance — is pinned OUT of the module by identifier, over every file of it at the walk's
    /// floor; and the one default the deletion left is pinned IN by its source text: the manager's
    /// `transport ?? NetworkMeshSession(namespace: namespace)`, the line the survey called "the
    /// cutover". The original walks FernletSocial beside the module for the four identifiers;
    /// Fernlet's copy holds that share.
    ///
    /// The stranger-admission needle stays, unchanged: D-4.3's refusal-made-CONDITIONAL is what let
    /// the deletion ship without losing first-meeting founding, and the unseeded pair run of
    /// 2026-09-22 is its tier-2 observation. Widening it further is a second decision, and it must
    /// not land silently either.
    @MainActor
    @Test func theMultipeerFilesAreGoneAndTheSelectionSeamWithThem() throws {
        #expect(FileManager.default.fileExists(atPath: PackageRoot.url(MeshP9Acceptance.transportFolderWitness).path),
                "the transport folder moved, so the two files' absence below is read in a folder that is not there")
        // R2: bounded by the two deleted files.
        for path in MeshP9Acceptance.multipeerFiles {
            #expect(!FileManager.default.fileExists(atPath: PackageRoot.url(path).path), """
                \(path) is back in the tree. MultipeerConnectivity was deleted in the deletion round \
                (2026-09-22) after the flip (2026-09-21) and the unseeded Lane C observation; \
                re-adding the radio is a phase decision that owes the permit list, the plist pair, \
                the CI name count and this cell in the same commit — it is not a fix for a red
                """)
        }
        // A code LINE, not a substring of the comment-stripped file: `codeOnly` drops whole-line
        // comments only, so a trailing `// transport ?? NetworkMeshSession(namespace: namespace)`
        // would otherwise satisfy this pin (the deletion round's verify, finding 7).
        let manager = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift"))
        let needle = "transport ?? NetworkMeshSession(namespace: namespace)"
        let initDefault = manager.split(separator: "\n").contains { line in
            (line.components(separatedBy: "//").first ?? "").contains(needle)
        }
        #expect(initDefault, """
            MeshNetworkManager.init no longer defaults its radio to \
            `NetworkMeshSession(namespace: namespace)` directly. There is no selection seam left to \
            route through: a second radio, a factory or a launch variable here is the seam the \
            deletion round removed coming back
            """)
        // The WHOLE module, not the one file the seam used to live in (the deletion round's verify,
        // finding 6). Comment-stripped sources, as every walk in this battery, at the walk's floor.
        let kit = try MeshP7Acceptance.sources()
        #expect(kit.count >= PackageSwiftFiles.sourceFloor, """
            the selection-seam walk read \(kit.count) Swift files under \(PackageSwiftFiles.sourceFolder), \
            below its floor \(PackageSwiftFiles.sourceFloor): the walk is broken, not the module clean
            """)
        // R2: bounded by the four retired identifiers.
        for retired in ["MeshTransportKind", "MeshTransportFactory", "quicSelectionEnvironmentKey",
                        "MeshMultipeerSession"] {
            let homes = Set(MeshP7Acceptance.homes(of: retired, in: kit)).sorted()
            #expect(homes.isEmpty, """
                `\(retired)` is back, in \(homes). The selection seam retired with the second radio \
                (Variant A of the survey's patch); `MeshTransportSession` and `MeshPeerChannel` are \
                the whole surface now, and a second radio is a phase decision
                """)
        }
        // The second reason, at the line that enforces it rather than in the note that states it: a
        // stranger is refused unless the owner's join doors are open (D-4.3, Option 1), so the
        // needle still fails if the arm is deleted, if it stops naming a refusal, or if the refusal
        // stops being the default.
        let introduction = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Transport/MeshChannelIntroduction.swift"))
        #expect(
            introduction.contains("guard roster.admitsStrangersProvisionally else { return .unknownIdentity }"),
            """
            the QUIC channel introduction no longer refuses a peer the roster calls a stranger \
            BY DEFAULT. Since D-4.3 the refusal is conditional on the owner's join doors being \
            open, and `unknownIdentity` must stay the answer when they are shut — widening it \
            further is a second decision, and it must not land silently either
            """
        )
    }

    /// **The framework import has no home, and no framework type is named anywhere in the module.**
    ///
    /// The *claim* is re-spelled as a literal empty home list here and the *walker* is
    /// `MeshP7Acceptance.sources()`, never forked. The walk is over comment-STRIPPED sources: prose
    /// about MultipeerConnectivity is fine and deliberately so. The original walks FernletSocial and the
    /// app beside the module (the app at its own floor); Fernlet's copy holds that share.
    @Test func theFrameworkImportHasNoHomeAndNoFrameworkTypeIsNamed() throws {
        let kit = try MeshP7Acceptance.sources()
        // MEASURED floors (NOTE 4): 141 files after the deletion. See clause (b) for why not 100.
        #expect(kit.count >= 120, "the ProximityKit scan lost its files (141 when this was measured)")
        let homes = Set(MeshP7Acceptance.homes(of: "import MultipeerConnectivity", in: kit)).sorted()
        #expect(homes.isEmpty, """
            MultipeerConnectivity is imported in \(homes). The framework left the tree in the \
            deletion round (2026-09-22); a new import is a new dependency on a retired radio
            """)
        // The type check is deliberately narrower than the import check: these three names have no
        // prefix collision anywhere, so a substring walk is sound for them.
        // R2: bounded by the three unambiguous framework type names.
        for symbol in ["MCNearbyServiceAdvertiser", "MCNearbyServiceBrowser", "MCSessionState"] {
            let anywhere = Set(MeshP7Acceptance.homes(of: symbol, in: kit)).sorted()
            #expect(anywhere.isEmpty, "`\(symbol)` is named in \(anywhere); the framework is gone")
        }
    }
}
