// MeshRoutedStoreIsolationTests.swift
// ProximityKitTests
//
// Grep-wall keeping every test `MeshRoutedStore` on its OWN scope — directory AND keychain service —
// in the idiom of `MeshSessionStoreIsolationTests` and `PhotoDirectoryIsolationTests`; plus the
// one-construction-site wall over `MeshCustodyDurabilityWitness`. "Test" means the app's unit tests;
// ProximityKit's own package tests hold the same rules over theirs (`PackageTestTreeWallTests`).
//
// The shared-disk-root flake family is a well-documented cross-suite hazard in this tree: XCTest and
// Swift Testing suites run in parallel inside ONE process, so anything rooted at a process-global
// path or a fixed keychain service is destroyed for every concurrently-running suite the moment one
// of them wipes. P5 item 3 adds a NEW persisted surface — `MeshRoutedIndex.sealed`, its `.corrupt`
// sibling, a whole directory of `MeshRoutedChunks/<uuid>.chunk` payload files, and the
// `com.fernlet.mesh-routed` key that seals all of them — and `MeshRoutedStore.wipeForDeleteAll`
// destroys every one of them by service and by path. The family must not gain a member.
//
// Source-scanning is the only way to catch the omission:
// `MeshRoutedStore(scope: .production(for: namespace, directory: root, installBinding: binding))`
// compiles, passes in isolation every time, and lands its damage in somebody else's suite.
//
// The witness wall is a different kind of claim and lives here because it is the same tool. The
// compile-time gate on `MeshCustodyDurabilityWitness` is `fileprivate`, which is FILE scope — so it
// holds only while the type and its one minting verb share a file that holds nothing else. Moving
// the type would widen the gate silently, with no compile error and no failing behaviour test. This
// is the wall that notices.
//
// A partial copy (ProximityKit plan step A1.3's batch D, the routed track): of the Fernlet
// repository's FernletTests file of the same name, this holds only the cells of
// `MeshRoutedStoreIsolationTests` that read ProximityKit's sources, under their suite's name and
// their own: the witness and commit-file walls, the ack-stage table, type registry and routed-token
// walls and their scanners' fixture, and the ack path's decrypt wall. Where the original swept
// ProximityKit and FernletSocial together, this holds the ProximityKit half and the Fernlet
// repository keeps FernletSocial's. The test-tree and app halves, the scratch-root needle and the
// ack-table scanner's fixture read no ProximityKit source and stay there; the source-scan helper
// is this target's `TestSupport/MeshRoutedSourceScan.swift`, and the construction scanner
// `PackageTestTreeWallTests.constructionArguments(of:in:)`.

import Foundation
import Testing

/// The store isolation walls' ProximityKit half: the witnesses' and the commit files' gates, one
/// ack-stage table, one type registry and no per-type branch in ProximityKit's code, and the ack path's
/// missing decrypt seam.
struct MeshRoutedStoreIsolationTests {

    // MARK: - The durability gate

    /// `MeshCustodyDurabilityWitness` has exactly one construction site, and it is the file holding
    /// `committingCustody` and nothing else.
    ///
    /// The compile-time gate is `fileprivate`, so this wall is not redundant with it — it is what
    /// notices when someone MOVES the type, which widens the gate with no compile error. If the
    /// witness ever has to become `internal`, this wall is the replacement for the guarantee that is
    /// lost, and it must then be tightened rather than deleted.
    ///
    /// **The package's walk** (ProximityKit plan step A1.3's batch D): this package's walker over
    /// ProximityKit's module, held to its floor (``PackageSwiftFiles/sourceFloor``), where the Fernlet
    /// original enumerated the folder under a floor of 8 files.
    @Test func theDurabilityWitnessHasExactlyOneConstructionSite() throws {
        var scanned = 0
        var constructionSites: [String] = []
        // R2: bounded by the module's own file list.
        for file in try PackageSwiftFiles.sources() {
            scanned += 1
            let code = MeshRoutedSourceScan.codeOnly(file.text)
            if code.contains("MeshCustodyDurabilityWitness(") {
                constructionSites.append(URL(fileURLWithPath: file.path).lastPathComponent)
            }
        }
        #expect(scanned >= PackageSwiftFiles.sourceFloor,
                "the ProximityKit sweep found only \(scanned) files — scanner broken?")
        #expect(
            constructionSites == ["MeshRoutedCustodyCommit.swift"],
            """
            `MeshCustodyDurabilityWitness(` is constructed in \(constructionSites) — it must be built \
            in exactly one file, the one holding `committingCustody` and nothing else. A second site \
            means a receipt can be minted for bytes no durable write returned.
            """
        )
    }

    /// The file that holds the witness holds the commit verb and nothing else — the property that
    /// makes `fileprivate` a real gate rather than a comment.
    @Test func theCommitFileHoldsOnlyTheWitnessAndItsVerb() throws {
        let source = try PackageRoot.source(
            "Sources/ProximityKit/Mesh/MeshRoutedCustodyCommit.swift"
        )
        let code = MeshRoutedSourceScan.codeOnly(source)
        #expect(code.contains("struct MeshCustodyDurabilityWitness"))
        #expect(code.contains("fileprivate init("))
        #expect(code.contains("func committingCustody("))
        // The write token's own gate is in another file, so this one cannot mint one either.
        #expect(code.contains("LoadToken(fileURL:") == false,
                "the commit file must not be able to mint a write token")
        let store = try PackageRoot.source("Sources/ProximityKit/Mesh/MeshRoutedStore.swift")
        #expect(MeshRoutedSourceScan.codeOnly(store).contains("fileprivate init(fileURL:"))
    }

    // MARK: - The delivery gate (P5 item 4)

    /// `MeshRecipientDeliveryWitness` has exactly one construction site, and it is the file holding
    /// `committingDelivery` and nothing else.
    ///
    /// Same claim, same reason as the custody witness above: the compile-time gate is `fileprivate`,
    /// so this wall is what notices when someone MOVES the type, which widens the gate with no
    /// compile error.
    ///
    /// **The package half** (ProximityKit plan step A1.3's batch D): the sweep over ProximityKit's
    /// module, which holds the witness and its one site; the Fernlet repository keeps the sweep over
    /// FernletSocial, where no site stands.
    @Test func theRecipientWitnessCanOnlyBeMintedInItsOwnFile() throws {
        var constructionSites: [String] = []
        for (file, code) in try Self.proximitySources() where code.contains("MeshRecipientDeliveryWitness(") {
            constructionSites.append(file)
        }
        #expect(
            constructionSites == ["MeshRoutedDeliveryCommit.swift"],
            """
            `MeshRecipientDeliveryWitness(` is constructed in \(constructionSites) — it must be built \
            in exactly one file, the one holding `committingDelivery` and nothing else. A second site \
            means a recipient receipt can be minted for an acknowledgement no durable write returned.
            """
        )
    }

    /// The file that holds the delivery witness holds the commit verb and nothing else — the property
    /// that makes `fileprivate` a real gate rather than a comment.
    @Test func theDeliveryCommitFileHoldsTheWitnessAndTheVerbAndNothingElse() throws {
        let code = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Mesh/MeshRoutedDeliveryCommit.swift")
        )
        #expect(code.contains("struct MeshRecipientDeliveryWitness"))
        #expect(code.contains("fileprivate init("))
        #expect(code.contains("func committingDelivery("))
        // The write token's own gate is in another file, so this one cannot mint one either.
        #expect(code.contains("LoadToken(fileURL:") == false,
                "the delivery commit file must not be able to mint a write token")
        // And it holds no OTHER store verb: the ingest door lives next door on purpose.
        #expect(code.contains("func recordingRecipientReceipt(") == false)
        #expect(code.contains("func committingCustody(") == false)
    }

    /// The commit verb writes no delivery rung — the source half of the invariant its behavioural
    /// twin asserts.
    ///
    /// Cheap, and it is what stops the split being quietly re-merged by a later edit: the
    /// `delivered` rung has exactly ONE writer, and it takes a signed receipt whose signer is that
    /// destination.
    @Test func theCommitVerbWritesNoDeliveryRung() throws {
        let code = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Mesh/MeshRoutedDeliveryCommit.swift")
        )
        #expect(code.contains("advancing(") == false,
                "the delivery commit file advances a rung — only the receipt door may")
        #expect(code.contains("MeshRoutedDeliveryRecord(encoding:") == false,
                "the delivery commit file re-encodes a delivery map — only the receipt door may")
        let ingest = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Mesh/MeshRoutedDeliveryIngest.swift")
        )
        #expect(ingest.contains("advancing(receipt.recipientFingerprint, to: .delivered)"),
                "the receipt door is where a rung moves, on the SIGNER's own destination")
    }

    /// `MeshHeartLedgerProof` can only be built inside the ledger's own file — the heart half of
    /// durable-before-acknowledged, gated the same way. The ledger is FernletSocial's
    /// (`HeartSharing/ProximityHeartLedger.swift`), and the sweep reads both modules, so a
    /// construction in either is seen.
    ///
    /// **The package half** (ProximityKit plan step A1.3's batch D): the sweep over ProximityKit's
    /// module, where the ledger does not live, so no file may construct the proof at all. The Fernlet
    /// repository keeps the ledger's half: its one site is FernletSocial's `ProximityHeartLedger.swift`,
    /// which declares the proof with its `fileprivate` initializer.
    @Test func theHeartLedgerProofCanOnlyBeMintedInTheLedgersOwnFile() throws {
        var constructionSites: [String] = []
        for (file, code) in try Self.proximitySources() where code.contains("MeshHeartLedgerProof(") {
            constructionSites.append(file)
        }
        #expect(
            constructionSites.isEmpty,
            """
            `MeshHeartLedgerProof(` is constructed in \(constructionSites) — only the ledger may vend \
            one, and the ledger is a host's (Fernlet's is FernletSocial's), never ProximityKit's. A second \
            site means a heart receipt can be minted for a gift the ledger never stored.
            """
        )
    }

    /// Shipping code names exactly ONE ack-stage table.
    ///
    /// Injection alone does not deliver "a recipient cannot claim a weaker rule" — the table is a
    /// door parameter, so a second shipping value would be a second policy. A fixture table is a
    /// test-only affordance, and this is what keeps it one.
    ///
    /// The construction half uses the same paren-matching scanner the store walls above use, not a
    /// `contains("MeshRoutedAckStageTable(rows:")`: the literal form is blind to a construction
    /// wrapped between the paren and the `rows:` label, and this wall is the ONLY thing standing
    /// between a caller and a table mapping `…routed-type.heart.v1` to `.durableRecipientStorage` —
    /// a heart reported delivered on ciphertext alone, with no foreground decrypt and no ledger
    /// commit. Unlike the witness and the ledger proof, the table has no `fileprivate` gate.
    ///
    /// **P5 item 11 moved the construction site, and the wall moved with it in the same commit.**
    /// The table is now a PROJECTION of `MeshRoutedTypeRegistry`'s rows, so the one place a table is
    /// built is the registry's own file — and the sentence above stays true word for word, with the
    /// registry standing where the ack file used to. **The member half has no exemption**: no
    /// shipping file — ProximityKit's or FernletSocial's, the registry's included — names any
    /// `MeshRoutedAckStageTable.` member at all (the `increment1` table is the test target's binding,
    /// over Fernlet's rows, for the suites); the one table a door is handed is the registry's
    /// `ackStages` (which is why the registry
    /// declares its own `maxEntries` rather than reading `maxRows` across — the equality is pinned
    /// from the test target by `theRegistrysCapEqualsTheAckTablesCap`).
    ///
    /// **The package half** (ProximityKit plan step A1.3's batch D): the sweep over ProximityKit's
    /// module, which holds the one construction; the Fernlet repository keeps the sweep over
    /// FernletSocial, which holds none and names no member.
    @Test func shippingCodeNamesOneAckStageTable() throws {
        var constructionSites: [String] = []
        var otherValues: [String] = []
        for (file, code) in try Self.proximitySources() {
            for _ in PackageTestTreeWallTests.constructionArguments(
                of: "MeshRoutedAckStageTable(", in: code
            ) {
                constructionSites.append(file)
            }
            for fragment in code.components(separatedBy: "MeshRoutedAckStageTable.").dropFirst() {
                otherValues.append("\(file): …MeshRoutedAckStageTable.\(fragment.prefix(24))")
            }
        }
        #expect(constructionSites == ["MeshRoutedTypeRegistry.swift"],
                "a second shipping `MeshRoutedAckStageTable(rows:)` is a second policy: \(constructionSites)")
        #expect(otherValues.isEmpty,
                "shipping code names an ack-stage table member, a second value beside the registry's: \(otherValues)")
    }

    /// Shipping code names exactly ONE routed type registry (P5 item 11).
    ///
    /// The ack-stage wall's exact shape, one level up. The registry is the single source of the
    /// verifier's accepted-token set, the ack-stage projection, the mint's per-type guards and the
    /// four forwarding gates — so a second shipping registry would be a second answer to "is this
    /// type known", and that is the one question plan §11 says must have one answer everywhere.
    ///
    /// The construction half is why `MeshNetworkManager`'s `init` spells the registry it builds out in
    /// full (`MeshRoutedTypeRegistry(entries: store.meshRoutedTypeEntries)`, its host's rows alone): a
    /// leading-dot `.init(entries:)` is invisible to this scanner. The member half admits no member at
    /// all: the registry has no builder, only that one construction from the host's rows. The sweep
    /// reads FernletSocial too, where Fernlet's rows are declared, so the host's rows cannot become a
    /// second registry there either. The mint takes its registry with no default, so the registry the
    /// manager builds is the one value position left.
    /// `theTypeRegistryScannersMatchAcrossLines` fixtures that blind spot from both sides, asserting
    /// the manager's file still names the type in full.
    ///
    /// **The package half** (ProximityKit plan step A1.3's batch D): the sweep over ProximityKit's
    /// module, which holds the one construction; the Fernlet repository keeps the sweep over
    /// FernletSocial, which holds none and names no member.
    @Test func shippingCodeNamesOneTypeRegistry() throws {
        var constructionSites: [String] = []
        var otherValues: [String] = []
        for (file, code) in try Self.proximitySources() {
            for _ in PackageTestTreeWallTests.constructionArguments(
                of: "MeshRoutedTypeRegistry(", in: code
            ) {
                constructionSites.append(file)
            }
            for fragment in code.components(separatedBy: "MeshRoutedTypeRegistry.").dropFirst() {
                otherValues.append("\(file): …MeshRoutedTypeRegistry.\(fragment.prefix(24))")
            }
        }
        #expect(constructionSites == ["MeshNetworkManager.swift"],
                "a second shipping `MeshRoutedTypeRegistry(entries:)` is a second policy: \(constructionSites)")
        #expect(otherValues.isEmpty,
                "shipping code names a type registry other than the manager's one construction: \(otherValues)")
    }

    /// No shipping code branches on a routed type token — the registry IS the only per-type switch.
    ///
    /// The allowlist is **per substring**, not per file, because the spelling needles have different
    /// single-source rules. The tokens are the host's: a routed type may be read off the namespace's
    /// routed types (`routedTypes.photo` and its three siblings) only where rows are built from them —
    /// FernletSocial's host rows, every row the mesh registers — and in the namespace's own soundness
    /// rules, which name each field's path. No
    /// ProximityKit or FernletSocial file may spell one: the raw `fernlet.mesh.routed-type.` literal
    /// lives in FernletConnections, which spells Fernlet's, and the old `MeshRoutedTypeToken.`
    /// constants are gone (the test target's binding keeps that spelling for the suites), so typing a
    /// spelling straight into a row would give one token two sources that drift silently.
    ///
    /// Legal by construction, and it must stay legal: passing `manifest.typeToken` as a **lookup
    /// argument**, logging it as a context value, and branching on a **resolved** value
    /// (`entry.requiresForegroundDecryptBeforeFinal`, `switch stage`, a retention comparison) are the
    /// point of the registry, not violations of it.
    ///
    /// `MeshRoutedSourceScan.codeOnly` strips whole-line comments only, so string literals survive
    /// (which is what makes the literal needle work at all) and so do trailing comments on code
    /// lines — a `let x = y  // see fernlet.mesh.routed-type.photo.v1` would be a false positive
    /// here. Noted rather than designed around: it fails loudly and the fix is to move the comment.
    ///
    /// **The package half, floored** (ProximityKit plan step A1.3's batch D; Census 2 §4's silent-shrink
    /// zero-list): the sweep over ProximityKit's module, at the module walk's floor, with its field home
    /// among the files read, so a sweep that read nothing, or lost the home its allowance names, fails
    /// rather than passing over nothing. The Fernlet repository keeps the sweep over FernletSocial, with
    /// its own field home.
    @Test func noShippingCodeBranchesOnARoutedTypeToken() throws {
        var violations: [String] = []
        let sources = try Self.proximitySources()
        let swept = Set(sources.map(\.0))
        #expect(Self.routedTypeFieldHomes.isSubset(of: swept),
                "a routed-type field home is gone from the sweep: \(Self.routedTypeFieldHomes.subtracting(swept).sorted())")
        for (file, code) in sources {
            for (needle, files) in Self.routedTokenNeedles
            where code.contains(needle) && !files.contains(file) {
                violations.append("\(file): \(needle)")
            }
        }
        #expect(violations.isEmpty,
                "a per-type branch or a second token spelling outside the registry: \(violations)")
    }

    /// Wall 3's needles and their per-substring allowlists — **the wall's data, hoisted so the wall
    /// and its fixture read the same dictionary.**
    ///
    /// Held here rather than inside `noShippingCodeBranchesOnARoutedTypeToken` because a fixture that
    /// re-typed the needles as literals could not fail: deleting `"typeToken =="` from a local
    /// dictionary would blind the wall while every `"…".contains("typeToken ==")` assertion stayed
    /// green. `theTypeRegistryScannersMatchAcrossLines` drives THIS value, so removing or widening a
    /// row is a test failure rather than a silent narrowing of what the wall catches.
    private static let routedTokenNeedles: [String: Set<String>] = [
        "MeshRoutedTypeToken.": [],
        "fernlet.mesh.routed-type.": [],
        "routedTypes.photo": routedTypeFieldHomes,
        "routedTypes.tempMessage": routedTypeFieldHomes,
        "routedTypes.heart": routedTypeFieldHomes,
        "routedTypes.control": routedTypeFieldHomes,
        "typeToken ==": [],
        "== manifest.typeToken": [],
        "switch manifest.typeToken": [],
        "typeToken.hasPrefix(": []
    ]

    /// The two files that may read a single routed type off the namespace's routed types: the
    /// namespace's soundness rules, whose field paths spell each one, and FernletSocial's host rows,
    /// which build every row Fernlet declares through its host (`ProximityHost.meshRoutedTypeEntries`).
    /// The registry builds no row of its own, so it is no home.
    ///
    /// **The package half** (ProximityKit plan step A1.3's batch D): the soundness rules' file, the one
    /// home that is ProximityKit's; the host rows' file is FernletSocial's, and the Fernlet repository's
    /// half of the wall allows it there.
    private static let routedTypeFieldHomes: Set<String> = [
        "ProximityNamespace+Soundness.swift"
    ]

    /// The four bare per-type branch forms, each written so that EXACTLY ONE needle catches it.
    ///
    /// The uniqueness is the point. `if manifest.typeToken == MeshRoutedTypeToken.heart {` is caught
    /// by `"MeshRoutedTypeToken."` as well, so a fixture built on it would stay green with all four
    /// branch needles deleted. Each form here names a local instead, so the only thing that can catch
    /// it is its own needle.
    private static let routedTokenBranchForms: [String: String] = [
        "typeToken ==": "if manifest.typeToken == token {",
        "== manifest.typeToken": "if token == manifest.typeToken {",
        "switch manifest.typeToken": "switch manifest.typeToken {",
        "typeToken.hasPrefix(": "if manifest.typeToken.hasPrefix(prefix) {"
    ]

    /// The registry scanners themselves, fixtured — the matcher is the wall.
    ///
    /// Every fixture here drives a **shared** value, never a literal re-typed beside its own
    /// assertion: the construction cases run `MeshSessionStoreIsolationTests.constructionArguments`,
    /// and the needle cases run `Self.routedTokenNeedles`, the dictionary
    /// `noShippingCodeBranchesOnARoutedTypeToken` scans with. So deleting `"typeToken =="` from that
    /// dictionary, or widening `"fernlet.mesh.routed-type."`'s empty allowlist to admit any file,
    /// fails HERE rather than silently narrowing what wall 3 catches.
    ///
    /// The scanners' blind spot is fixtured from both sides: a leading-dot `= .init(entries: …)` is
    /// invisible to both (the negative), and the one shipping file that holds a registry value in a
    /// **type-inferred position** is asserted to spell the type out in full (the positive) — which is
    /// the only thing keeping the blind spot documented rather than occupied.
    @Test func theTypeRegistryScannersMatchAcrossLines() throws {
        let oneLine = "static let x = MeshRoutedTypeRegistry(entries: [row])"
        let wrapped = """
            static let x = MeshRoutedTypeRegistry(
                entries: [row]
            )
            """
        for (label, source) in [("one line", oneLine), ("wrapped", wrapped)] {
            #expect(
                PackageTestTreeWallTests.constructionArguments(
                    of: "MeshRoutedTypeRegistry(", in: source
                ).count == 1,
                "the registry scanner missed a \(label) construction"
            )
        }
        let dotRead = "let y = MeshRoutedTypeRegistry.maxEntries"
        #expect(
            PackageTestTreeWallTests.constructionArguments(
                of: "MeshRoutedTypeRegistry(", in: dotRead
            ).isEmpty,
            "the registry scanner counted a dot-member read as a construction"
        )
        try Self.expectTheMemberScannersBlindSpotIsStillEmpty()
        Self.expectTheWallsNeedlesStillDiscriminate()
    }

    /// The blind spot, both ways: the inferred form is invisible to both scanners, and no shipping
    /// value-position read has moved into it.
    ///
    /// `MeshNetworkManager.swift` (the registry its `init` builds) is the one place a registry value
    /// stands where a leading dot would compile — and where `shippingCodeNamesOneTypeRegistry` would
    /// then see nothing at all. The manifest mint's `types:` takes no default, so it holds none.
    ///
    /// The positive needle is the construction spelled in full, `MeshRoutedTypeRegistry(entries:`: the
    /// manager builds its registry from its host's rows directly, with no builder between them.
    private static func expectTheMemberScannersBlindSpotIsStillEmpty() throws {
        let inferred = "self.hostRoutedTypeRegistry = .init(entries: store.meshRoutedTypeEntries)"
        #expect(inferred.components(separatedBy: "MeshRoutedTypeRegistry.").count == 1,
                "the member scanner's blind spot moved: an inferred member is now visible to it")
        #expect(PackageTestTreeWallTests.constructionArguments(
                    of: "MeshRoutedTypeRegistry(", in: inferred
                ).isEmpty,
                "the construction scanner's blind spot moved: an inferred construction is now visible to it")
        let sources = try proximitySources()
        for name in ["MeshNetworkManager.swift"] {
            let code = try #require(sources.first { $0.0 == name }?.1,
                                    "the sweep no longer reaches a file that holds a registry value")
            #expect(code.contains("MeshRoutedTypeRegistry(entries:"),
                    "\(name) shortened its registry value to a form the one-registry wall cannot see")
        }
    }

    /// Wall 3's needles, driven as data: each bare branch form is caught by exactly its own needle, a
    /// registry lookup and the manager's registry read are caught by none, a sender reading one
    /// routed type off its namespace is caught by that type's needle, and the raw literal's allowlist
    /// is still empty.
    private static func expectTheWallsNeedlesStillDiscriminate() {
        for (needle, form) in routedTokenBranchForms {
            #expect(routedTokenNeedles[needle]?.isEmpty == true,
                    "the wall dropped the per-type branch needle \(needle), or allowlisted a file for it")
            #expect(routedTokenNeedles.keys.filter { form.contains($0) } == [needle],
                    "the wall's needles no longer catch exactly one per-type branch form: \(form)")
        }
        let lookup = "routedTypes.entry(for: manifest.typeToken)"
        #expect(routedTokenNeedles.keys.contains { lookup.contains($0) } == false,
                "a registry lookup is being read as a per-type branch")
        let registryRead = "MeshRoutedTypeRegistry(entries: store.meshRoutedTypeEntries)"
        #expect(routedTokenNeedles.keys.contains { registryRead.contains($0) } == false,
                "the manager's registry read is being read as a per-type read")
        let senderRead = "let token = namespace.family.vocabulary.routedTypes.heart"
        #expect(routedTokenNeedles.keys.filter { senderRead.contains($0) } == ["routedTypes.heart"],
                "the field needles no longer catch a sender reading a routed type off its namespace")
        let rawInRegistry = "let token = \"fernlet.mesh.routed-type.photo.v1\""
        #expect(routedTokenNeedles.keys.contains { rawInRegistry.contains($0) },
                "the raw-literal needle stopped matching a spelling written into a row")
        #expect(routedTokenNeedles["fernlet.mesh.routed-type."] == [],
                "the raw literal may now be typed into a ProximityKit file")
    }

    /// The ack path calls no decryption seam: a photo or a text is final on durable CIPHERTEXT, and
    /// the store never unwraps a content key.
    @Test func theAckPathNamesNoDecryptSeam() throws {
        let files = [
            "MeshRoutedAck.swift", "MeshRecipientReceipt.swift", "MeshRecipientReceiptVerifier.swift",
            "MeshRoutedDeliveryCommit.swift", "MeshRoutedDeliveryIngest.swift"
        ]
        for name in files {
            let code = MeshRoutedSourceScan.codeOnly(
                try PackageRoot.source("Sources/ProximityKit/Mesh/\(name)")
            )
            #expect(code.contains("MeshRoutedContentKeyWrapper") == false, "\(name)")
            #expect(code.contains(".unwrap(") == false, "\(name)")
            #expect(code.contains("openKey()") == false, "\(name)")
        }
    }

    // MARK: - Scanner

    /// Every `.swift` file under ProximityKit's source folder, as `(filename, code-only source)`, in
    /// path order, held to the module walk's floor (``PackageSwiftFiles/sourceFloor``).
    ///
    /// The package half (ProximityKit plan step A1.3's batch D) of the Fernlet repository's sweep, which
    /// read ProximityKit and FernletSocial, ProximityKit's first, under a floor of 8 files for the two:
    /// FernletSocial is swept there because the routed-type rows come from it (`FernletRoutedTypes.swift`)
    /// and so do the projection handlers and the ledger judge the engine calls by token, and that
    /// repository keeps that half. Read through the package's walker in place of a directory
    /// enumerator over a repository-relative path.
    private static func proximitySources() throws -> [(String, String)] {
        var sources: [(String, String)] = []
        // R2: bounded by the module's own file list.
        for file in try PackageSwiftFiles.sources() {
            sources.append((
                URL(fileURLWithPath: file.path).lastPathComponent,
                MeshRoutedSourceScan.codeOnly(file.text)
            ))
        }
        #expect(sources.count >= PackageSwiftFiles.sourceFloor, "the ProximityKit sweep found only \(sources.count) files")
        return sources
    }
}
