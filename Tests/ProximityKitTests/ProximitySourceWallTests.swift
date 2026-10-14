// ProximitySourceWallTests.swift
// ProximityKitTests
//
// ProximityKit plan step A1.1: the walls over ProximityKit's own code whose rules a host also holds over
// its shipping code, held in this module's tests so they travel with the package. No compiler checks
// any of these rules: a launch hook read outside `#if DEBUG`, a keychain row that syncs, or a raw
// CryptoKit call that names no purpose compiles clean and passes every other test. This suite reads
// every Swift file of the module as text, through `PackageRoot` and the package's walker
// (TestSupport/PackageSwiftFiles.swift), at the walk's floor, and holds four rules, each matcher held to
// its samples:
//
//   the launch hooks (TH1)  every line of ProximityKit's code that reads one of its DEBUG
//        launch-environment keys, `PROXIMITYKIT_UI_TEST_*` (the mesh manager's canned-mesh flags) or
//        `PROXIMITYKIT_MESH*` (the transport's console mirror and its two chaos keys), sits inside an
//        open `#if DEBUG` region, so no hook ships in Release; and each family is read at its floor, so a
//        matcher that stops seeing one fails rather than passes;
//   key custody  no keychain row ProximityKit writes syncs through iCloud Keychain
//        (`synchronizable: true` nowhere in its code), and every accessibility class it names is a
//        `ThisDeviceOnly` one: a host that syncs a key, or keeps one a backup restores, writes that row
//        itself;
//   the purpose wall  every line of ProximityKit's code that opens a raw primitive call (nine CryptoKit
//        markers: signing and verifying, HKDF, HMAC, ChaChaPoly and AES-GCM) names a purpose within an
//        asymmetric window, three lines above it to six below, so a new primitive call cannot rely on a
//        reviewer remembering the domain-separation policy; and at least a floor of such lines is read,
//        so a marker list or a walk that stops seeing the calls fails rather than passes;
//   the escape-hatch census  the calls that answer that demand with an escape-hatch comment instead
//        are counted: their total, the count per label they give themselves, the files they sit in, no
//        legacy read path among them, and no documentation line naming the marker within reach of a
//        call. One hatch stands, the transport's X.509 certificate self-signature, its justification
//        beside its pin.
//
// A host's own walls hold the same rules over the host's code; in the Fernlet repository,
// `TestHookBoundaryTests`, `KeyCustodyBoundaryTests`, `CryptographicPurposeBoundaryTests` and
// `CryptographicEscapeHatchCensusTests`, which read Fernlet's shipping roots but this module's folder.

import Foundation
import Testing

/// ProximityKit's code reads its launch hooks only inside `#if DEBUG`, each family still read, writes no
/// synchronizable keychain row and names no accessibility class that is not `ThisDeviceOnly`, names a
/// purpose at every raw cryptographic call, and answers that demand with no escape hatch but the one
/// pinned: twelve cells, two of them the matchers' samples.
@Suite struct ProximitySourceWallTests {

    // MARK: - The cells: the launch hooks

    /// **The hook families.** The scan reads at least ``PackageSwiftFiles/sourceFloor`` files of the
    /// module, and each of ``hookTokens`` matches at least its floor in ``hookTokenFloors`` of its code
    /// lines; every token has a floor and every floor a token. A family whose keys are renamed away, or a
    /// prefix edited to something no line carries, would otherwise leave its hooks silently unwalled
    /// while the other family stayed green. A file the walk finds but cannot read throws, failing here.
    @Test func everyProximityKitHookFamilyStillMatches() throws {
        let scan = try Self.scan()
        #expect(scan.filesScanned >= PackageSwiftFiles.sourceFloor, """
            the hook scan read \(scan.filesScanned) ProximityKit files (floor \(PackageSwiftFiles.sourceFloor)): \
            the walk is broken, not the module clean
            """)
        let byToken = Dictionary(grouping: scan.reads, by: \.token)
        // R2: bounded by the two families.
        for token in Self.hookTokens {
            let floor = Self.hookTokenFloors[token] ?? 1
            let found = byToken[token]?.count ?? 0
            #expect(found >= floor, """
                Family \(token) matched only \(found) ProximityKit lines (floor \(floor)) — either its \
                hooks were removed (then remove the token and its floor in the same commit) or the \
                matcher stopped seeing them. Do not lower the floor to make this pass.
                """)
        }
        #expect(Set(Self.hookTokenFloors.keys) == Set(Self.hookTokens),
                "every token needs a floor, and a floor without a token walls nothing")
    }

    /// **TH1.** Every hook read in ProximityKit's code (``hookReads(for:source:)``) sits inside an open
    /// `#if DEBUG` region: a condition that names `DEBUG` as a whole word, alone or with others, where
    /// an `#else` or `#elseif` leaves the region. So no hook, and nothing it selects, ships in Release.
    @Test func everyProximityKitHookReadSitsInsideDebug() throws {
        let violations = try Self.scan().reads
            .filter { !$0.insideDebug }
            .map { "\($0.path):\($0.line): \($0.text)" }
        #expect(violations.isEmpty, """
            TH1: these lines read a PROXIMITYKIT_UI_TEST_* / PROXIMITYKIT_MESH_* launch hook outside any \
            `#if DEBUG` region, so the hook — and whatever canned mesh, console mirror or handshake \
            misbehaviour it selects — ships in Release. Wrap the BODY (never a `public func` signature \
            crossing the package boundary), and keep any hoisted `let environment` binding inside the \
            region so it is not an unused-variable error in Release. The two-half pattern \
            (`#if DEBUG` … `#else` no-op … `#endif`) is how MeshTransportDebugHooks keeps an unguarded \
            CALL site legal:
            \(violations.joined(separator: "\n"))
            """)
    }

    /// The hook reader trips on a planted read and passes its near-misses: an unguarded read is
    /// reported; one inside `#if DEBUG`, alone or `&& canImport(…)`, is not; a condition that does not
    /// name `DEBUG`, and the `#else` half of one that does, are no guard; prose naming a key is no read.
    /// And ProximityKit's two families score as its real hooks do (``expectProximityKitFamiliesTrip()``).
    @Test func theHookReaderTripsOnPlantedTokens() {
        let unguarded = "func f() {\n    if ProcessInfo.processInfo.environment[\"PROXIMITYKIT_UI_TEST_X\"] == \"1\" { return }\n}\n"
        let guarded = "func f() {\n    #if DEBUG\n    if ProcessInfo.processInfo.environment[\"PROXIMITYKIT_UI_TEST_X\"] == \"1\" { return }\n    #endif\n}\n"
        let conjunction = "#if DEBUG && canImport(UIKit)\nlet x = ProcessInfo.processInfo.environment[\"PROXIMITYKIT_UI_TEST_X\"]\n#endif\n"
        let wrongCondition = "#if canImport(UIKit)\nlet x = ProcessInfo.processInfo.environment[\"PROXIMITYKIT_MESH_X\"]\n#endif\n"
        let releaseHalf = "#if DEBUG\nlet a = 1\n#else\nlet x = ProcessInfo.processInfo.environment[\"PROXIMITYKIT_MESH_X\"]\n#endif\n"
        let commentOnly = "// PROXIMITYKIT_UI_TEST_X is documented here only\n/// and here: PROXIMITYKIT_MESH_X\n"

        // Evaluated into locals rather than inline: `contains`/`allSatisfy` are `rethrows`, and the
        // #expect macro expands them as throwing calls inside a non-throwing test.
        let unguardedReported = Self.hookReads(for: "a.swift", source: unguarded).filter { !$0.insideDebug }
        let guardedOutsideDebug = Self.hookReads(for: "b.swift", source: guarded).filter { !$0.insideDebug }
        let conjunctionOutsideDebug = Self.hookReads(for: "c.swift", source: conjunction).filter { !$0.insideDebug }
        let wrongConditionReported = Self.hookReads(for: "d.swift", source: wrongCondition).filter { !$0.insideDebug }
        let releaseHalfReported = Self.hookReads(for: "e.swift", source: releaseHalf).filter { !$0.insideDebug }
        let commentReads = Self.hookReads(for: "f.swift", source: commentOnly)

        #expect(!unguardedReported.isEmpty, "an unguarded hook read must be reported")
        #expect(guardedOutsideDebug.isEmpty, "a #if DEBUG-guarded hook read must not be reported")
        #expect(conjunctionOutsideDebug.isEmpty,
                "#if DEBUG && canImport(UIKit) is still a DEBUG region")
        #expect(!wrongConditionReported.isEmpty,
                "a non-DEBUG condition must not count as a guard")
        #expect(!releaseHalfReported.isEmpty,
                "the #else half of a DEBUG directive is the Release half")
        #expect(commentReads.isEmpty, "prose mentioning a hook is not a read")
        Self.expectProximityKitFamiliesTrip()
    }

    // MARK: - The cells: key custody

    /// **No synchronizable row.** No ProximityKit source's text holds `synchronizable: true`
    /// (``containsSynchronizableTrue(_:)``), over every Swift file of the module at the walk's floor: an
    /// exact set, the empty one. Every row ProximityKit writes is this device's alone; a host that syncs a
    /// key through iCloud Keychain writes that row in its own code, which its own wall holds.
    @Test func proximityKitWritesNoSynchronizableKeychainRow() throws {
        let files = try PackageSwiftFiles.sources()
        #expect(files.count >= PackageSwiftFiles.sourceFloor, """
            the custody scan read \(files.count) Swift files under \(PackageSwiftFiles.sourceFolder), below its \
            floor \(PackageSwiftFiles.sourceFloor): the walk is broken, not the module clean
            """)
        let hits = files.filter { Self.containsSynchronizableTrue($0.text) }.map(\.path)
        #expect(hits.isEmpty, """
            ProximityKit writes an iCloud-Keychain-synchronizable keychain row in \(hits): every row it writes \
            is this device's alone; a host that syncs a key (Fernlet's sealed-backup escrow) writes that row \
            itself
            """)
    }

    /// **`ThisDeviceOnly` classes only.** No ProximityKit source's text names a bare accessibility class
    /// (``bareAccessibilityTokens(in:)``: `kSecAttrAccessibleAfterFirstUnlock`, `…WhenUnlocked` or
    /// `…Always` with no `ThisDeviceOnly` after it), over every Swift file of the module at the walk's
    /// floor: an exact set, the empty one. A row under a bare class leaves the device in a backup; a host
    /// that keeps one restorable writes that row in its own code, which its own wall holds.
    @Test func proximityKitUsesOnlyThisDeviceOnlyAccessibilityClasses() throws {
        let files = try PackageSwiftFiles.sources()
        #expect(files.count >= PackageSwiftFiles.sourceFloor, """
            the custody scan read \(files.count) Swift files under \(PackageSwiftFiles.sourceFolder), below its \
            floor \(PackageSwiftFiles.sourceFloor): the walk is broken, not the module clean
            """)
        let hits = files.filter { !Self.bareAccessibilityTokens(in: $0.text).isEmpty }.map(\.path)
        #expect(hits.isEmpty, """
            ProximityKit names a non-device-bound accessibility class in \(hits): every row it writes is \
            ThisDeviceOnly
            """)
    }

    /// Both custody matchers fire on planted violations and stay quiet on the device-bound spellings, so
    /// the two walls above cannot rot into always-passing.
    @Test func theCustodyMatchersFlagPlantedViolations() {
        #expect(Self.containsSynchronizableTrue(
            "KeychainItem.store(d, account: a, service: s, accessibility: x, synchronizable: true)"))
        #expect(!Self.containsSynchronizableTrue(
            "KeychainItem.store(d, account: a, service: s, accessibility: x, synchronizable: false)"))

        #expect(Self.bareAccessibilityTokens(in: "let a = kSecAttrAccessibleAfterFirstUnlock") == ["kSecAttrAccessibleAfterFirstUnlock"])
        #expect(Self.bareAccessibilityTokens(in: "let a = kSecAttrAccessibleWhenUnlocked,") == ["kSecAttrAccessibleWhenUnlocked"])
        #expect(Self.bareAccessibilityTokens(in: "let a = kSecAttrAccessibleAlways").count == 1)
        #expect(Self.bareAccessibilityTokens(in: "let a = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly").isEmpty)
        #expect(Self.bareAccessibilityTokens(in: "let a = kSecAttrAccessibleWhenUnlockedThisDeviceOnly").isEmpty)
    }

    // MARK: - The cells: the purpose wall

    /// **The purpose wall.** Every line of ProximityKit's code that opens a raw primitive call
    /// (``CryptoScan/primitiveCalls(in:)``) names a purpose within the window around it, over every Swift
    /// file of the module at the walk's floor, and at least ``CryptoScan/primitiveCallFloor`` such lines
    /// are read, so a marker list or a walk that stops seeing the calls fails rather than passes. The
    /// matcher is held to its samples first (``expectThePurposeMatcherTripsOnPlantedCalls()``).
    @Test func everyRawCryptographicCallInProximityKitNamesAPurpose() throws {
        Self.expectThePurposeMatcherTripsOnPlantedCalls()
        let files = try PackageSwiftFiles.sources()
        #expect(files.count >= PackageSwiftFiles.sourceFloor, """
            the purpose wall read \(files.count) ProximityKit files (floor \(PackageSwiftFiles.sourceFloor)): \
            the walk is broken, not the module clean
            """)
        var callLines = 0
        // R2: bounded by the module's file count.
        for file in files {
            let calls = CryptoScan.primitiveCalls(in: file.text)
            callLines += calls.count
            // R2: bounded by the file's primitive-call lines.
            for call in calls {
                #expect(call.namesAPurpose,
                        "Raw crypto call without a purpose at \(PackageSwiftFiles.sourceFolder)/\(file.path):\(call.line)")
            }
        }
        #expect(callLines >= CryptoScan.primitiveCallFloor, """
            the purpose wall read only \(callLines) primitive-call lines in ProximityKit (floor \
            \(CryptoScan.primitiveCallFloor)): the marker list or the walk is broken
            """)
    }

    // MARK: - The cells: the escape-hatch census

    /// **The total.** The hatches in ProximityKit's code (``hatchScan()``, documentation lines left out)
    /// number exactly the sum of ``pinnedByLabel``, over every Swift file of the module at the walk's
    /// floor: a hatch added anywhere in the module fails here.
    @Test func theEscapeHatchTotalIsPinned() throws {
        let scan = try Self.hatchScan()
        #expect(scan.filesScanned >= PackageSwiftFiles.sourceFloor, """
            the hatch census read \(scan.filesScanned) ProximityKit files (floor \(PackageSwiftFiles.sourceFloor)): \
            the walk is broken, not the module clean
            """)
        let hatches = scan.hatches.filter { !$0.isProse }
        let expected = Self.pinnedByLabel.values.reduce(0, +)
        let sites = hatches.map { "  \($0.printed) — \($0.label)" }.joined(separator: "\n")
        #expect(hatches.count == expected, """
            Escape-hatch total moved: \(hatches.count) found, \(expected) pinned. Adding one is a policy act — \
            update pinnedByLabel and its justification here in the same commit.
            \(sites)
            """)
    }

    /// **Per label.** Every label a hatch gives itself, and every label of ``pinnedByLabel``, stands at
    /// exactly its pinned count: a hatch added while another is removed, a hatch relabelled into a more
    /// benign category, and a label the pin does not know each fail here, the total unmoved.
    @Test func everyEscapeHatchLabelIsPinnedAtItsOwnCount() throws {
        let hatches = try Self.hatchScan().hatches.filter { !$0.isProse }
        let found = Dictionary(grouping: hatches, by: \.label).mapValues(\.count)
        // R2: bounded by the labels found and pinned.
        for label in Set(found.keys).union(Self.pinnedByLabel.keys).sorted() {
            let sites = found[label] ?? 0
            let pinned = Self.pinnedByLabel[label] ?? 0
            #expect(sites == pinned, """
                Escape-hatch label '\(label)': \(sites) found, \(pinned) pinned. A label the pin does not know \
                is a NEW category of exemption, not a count change — say what it means beside `pinnedByLabel` \
                before pinning it.
                """)
        }
    }

    /// **No legacy read path.** `legacy-read` is absent from ``pinnedByLabel`` and from every hatch in
    /// ProximityKit's code. Deliberately redundant with ``everyEscapeHatchLabelIsPinnedAtItsOwnCount()``,
    /// which already fails a legacy reader as "1 found, 0 pinned": that wall lives in the absence of a
    /// key, and absence is repaired by typing `"legacy-read": 1`, a one-line edit that reads as a count
    /// update in a diff. This cell cannot be satisfied that way, so restoring a legacy reader means
    /// deleting a test whose name says what is being done.
    @Test func noLegacyReadPathExistsInProximityKit() throws {
        #expect(Self.pinnedByLabel["legacy-read"] == nil, """
            `legacy-read` is back in pinnedByLabel. The pin is not the place to re-authorize a legacy read \
            path — take it to the owner.
            """)
        let legacy = try Self.hatchScan().hatches.filter { !$0.isProse && $0.label == "legacy-read" }
        let sites = legacy.map { "  \($0.printed)" }.joined(separator: "\n")
        #expect(legacy.isEmpty, """
            \(legacy.count) legacy read path(s) have come back:
            \(sites)
            ProximityKit reads no format older than its current one: the crypto standardization round \
            deleted its legacy wire readers (four, in its mesh manager and its identity). A path that opens \
            older bytes is a deliberate reversal of that, not a fix — take it to the owner before making \
            this test pass.
            """)
    }

    /// **The files.** The hatches in ProximityKit's code sit in exactly ``pinnedFileCount`` distinct
    /// files, so a hatch spreading into a file that held none fails here.
    @Test func escapeHatchesStayInTheFilesThatAlreadyHaveThem() throws {
        let hatches = try Self.hatchScan().hatches.filter { !$0.isProse }
        let files = Set(hatches.map(\.path))
        let listed = files.sorted().map { "  \($0)" }.joined(separator: "\n")
        #expect(files.count == Self.pinnedFileCount, """
            Escape hatches now span \(files.count) files, pinned at \(Self.pinnedFileCount):
            \(listed)
            """)
    }

    /// **Prose.** A documentation line (`///`) naming the escape-hatch marker is prose about a hatch, not
    /// a hatch; but the purpose wall reads a raw window, so such a line within reach of a primitive call
    /// silences it exactly as a real hatch would. The prose mentions in ProximityKit's code stand exactly
    /// at ``pinnedProseMentions`` (none), and none sits within reach of a call. The census's reader is
    /// held to its samples first (``expectTheHatchReaderReadsItsSamples()``).
    @Test func proseMentionsCannotSilenceThePurposeWall() throws {
        Self.expectTheHatchReaderReadsItsSamples()
        let prose = try Self.hatchScan().hatches.filter(\.isProse)
        let found = Dictionary(grouping: prose, by: \.path).mapValues(\.count)
        let foundList = found.sorted { $0.key < $1.key }
        let pinnedList = Self.pinnedProseMentions.sorted { $0.key < $1.key }
        #expect(found == Self.pinnedProseMentions,
                "Prose mentions of the escape-hatch marker moved. Found: \(foundList), pinned: \(pinnedList).")
        // R2: bounded by the prose mentions found.
        for mention in prose {
            #expect(!mention.reachesAPrimitiveCall, """
                The prose mention at \(mention.printed) sits within the purpose wall's context window of a raw \
                primitive call, so it silences the wall exactly as a real hatch would. Move the sentence, or \
                make it an honest hatch and pin it.
                """)
        }
    }

    // MARK: - The launch hooks

    /// The tokens that name one of ProximityKit's DEBUG launch hooks, its UI-test family first.
    ///
    /// The mesh family is matched WITHOUT a trailing underscore (`PROXIMITYKIT_MESH`, not
    /// `PROXIMITYKIT_MESH_`), so a bare future `PROXIMITYKIT_MESH` cannot slip past the prefix. That is
    /// safe against double-counting because ``hookReads(for:source:)`` records one read per LINE however
    /// many tokens match, to the first family in this list it names, and it is deliberate that
    /// `PROXIMITYKIT_UI_TEST_MESH_*`, three real flags, score to `PROXIMITYKIT_UI_TEST_` rather than to the
    /// mesh family.
    static let hookTokens = ["PROXIMITYKIT_UI_TEST_", "PROXIMITYKIT_MESH"]

    /// Each family's floor, its measured lines, MEASURED at ProximityKit plan step A1.1.15 (2026-10-14):
    /// the mesh manager's three UI-test reads (`Mesh/MeshNetworkManager.swift`'s
    /// `injectUITestStateIfNeeded()`) and the transport's three key constants
    /// (`Transport/MeshTransportDebugHooks.swift`: the console mirror's and the two chaos keys'). The six
    /// keys are a closed set the package named at plan step A1.0, so a read that leaves, or a key renamed
    /// away, fails here by family until its floor is lowered in the same commit. They do not move for an
    /// ADDED hook.
    static let hookTokenFloors: [String: Int] = ["PROXIMITYKIT_UI_TEST_": 3, "PROXIMITYKIT_MESH": 3]

    /// One hook read: where it is, which family named it, and whether a `#if DEBUG` region was open at
    /// that point.
    struct HookRead: Hashable, Sendable {
        /// The file, by its path under the package root (`Sources/ProximityKit/…`).
        let path: String
        /// The 1-based line.
        let line: Int
        /// The line, trimmed, its first 120 characters.
        let text: String
        /// The first entry of ``ProximitySourceWallTests/hookTokens`` this line matched: the family it
        /// counts toward.
        let token: String
        /// Whether an open `#if` region named `DEBUG` at this line.
        let insideDebug: Bool
    }

    /// The hook scan over ProximityKit's sources: how many files it read, and every hook read.
    struct TreeScan: Sendable {
        /// The Swift files the walk read.
        let filesScanned: Int
        /// Every hook read across them.
        let reads: [HookRead]
    }

    /// Reads every Swift file of the module (``PackageSwiftFiles/sources()``) for hook reads. A file the
    /// walk found but cannot read as UTF-8 throws, so an unreadable file fails the cell that asked rather
    /// than reading as clean.
    static func scan() throws -> TreeScan {
        let files = try PackageSwiftFiles.sources()
        var reads: [HookRead] = []
        // R2: bounded by the module's file count.
        for file in files {
            reads += hookReads(for: PackageSwiftFiles.sourceFolder + "/" + file.path, source: file.text)
        }
        return TreeScan(filesScanned: files.count, reads: reads)
    }

    /// Every hook read in one file, each tagged with whether a DEBUG region was open.
    ///
    /// Comment stripping is load-bearing: the keys' doc comments name them as prose (the transport's
    /// console mirror's and chaos keys' among them), and a wall that counted those would be satisfied by
    /// documentation while real reads shipped.
    static func hookReads(for path: String, source: String) -> [HookRead] {
        var reads: [HookRead] = []
        var regions: [Bool] = []          // one entry per open `#if`; true when it is a DEBUG region
        var inBlockComment = false
        // R2: bounded by the source's line count.
        for (index, rawLine) in source.components(separatedBy: "\n").enumerated() {
            let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
            if inBlockComment {
                if trimmed.contains("*/") { inBlockComment = false }
                continue
            }
            if trimmed.hasPrefix("/*") {
                if !trimmed.contains("*/") { inBlockComment = true }
                continue
            }
            updateRegions(&regions, with: trimmed)
            guard !trimmed.hasPrefix("//") else { continue }
            guard let token = hookTokens.first(where: { trimmed.contains($0) }) else { continue }
            reads.append(HookRead(path: path, line: index + 1, text: String(trimmed.prefix(120)),
                                  token: token, insideDebug: regions.contains(true)))
        }
        return reads
    }

    /// Tracks the `#if` stack. A condition counts as DEBUG when it names `DEBUG` as a whole word, so
    /// `#if DEBUG && canImport(UIKit)` counts and a bare `#if canImport(UIKit)` does not; `#else` /
    /// `#elseif` leave the DEBUG region (the Release half of the same directive).
    private static func updateRegions(_ regions: inout [Bool], with trimmed: String) {
        if trimmed.hasPrefix("#if") {
            regions.append(namesDebug(trimmed))
        } else if trimmed.hasPrefix("#elseif") {
            if !regions.isEmpty { regions[regions.count - 1] = namesDebug(trimmed) }
        } else if trimmed.hasPrefix("#else") {
            if !regions.isEmpty { regions[regions.count - 1] = false }
        } else if trimmed.hasPrefix("#endif") {
            if !regions.isEmpty { regions.removeLast() }
        }
    }

    /// Whether a `#if`/`#elseif` condition names `DEBUG` as a whole word (never `NOT_DEBUG_X`).
    private static func namesDebug(_ directive: String) -> Bool {
        let separators = CharacterSet(charactersIn: " \t()!&|,")
        return directive.components(separatedBy: separators).contains("DEBUG")
    }

    /// ProximityKit's two families, each in the exact shape its real hooks take (the transport's key
    /// constants, the mesh manager's inline reads): an unguarded key constant and an unguarded read are
    /// reported in their own families, a DEBUG-guarded key constant is still read but not reported, and
    /// a UI-test flag whose name holds MESH scores to the UI-test family, once.
    static func expectProximityKitFamiliesTrip() {
        let meshKey = "static let behaviourKey = \"PROXIMITYKIT_MESH_CHAOS\"\n"
        let uiTestRead = "if env[\"PROXIMITYKIT_UI_TEST_MESH_CLOSED\"] == \"1\" {\n"
        let meshGuarded = "#if DEBUG\nstatic let enabledKey = \"PROXIMITYKIT_MESH_CONSOLE_LOG\"\n#endif\n"
        let uiTestMesh = "#if DEBUG\nif env[\"PROXIMITYKIT_UI_TEST_MESH_OPEN\"] == \"1\" {\n#endif\n"

        let meshKeyReported = hookReads(for: "k.swift", source: meshKey).filter { !$0.insideDebug }
        let uiTestReadReported = hookReads(for: "l.swift", source: uiTestRead).filter { !$0.insideDebug }
        let meshGuardedReads = hookReads(for: "m.swift", source: meshGuarded)
        let meshGuardedOutsideDebug = meshGuardedReads.filter { !$0.insideDebug }
        let uiTestMeshReads = hookReads(for: "n.swift", source: uiTestMesh)

        #expect(meshKeyReported.map(\.token) == ["PROXIMITYKIT_MESH"],
                "an unguarded PROXIMITYKIT_MESH_* key constant must be reported, in its own family")
        #expect(uiTestReadReported.map(\.token) == ["PROXIMITYKIT_UI_TEST_"],
                "an unguarded PROXIMITYKIT_UI_TEST_* read must be reported, in its own family")
        #expect(meshGuardedReads.map(\.token) == ["PROXIMITYKIT_MESH"],
                "a DEBUG-guarded ProximityKit mesh hook is still read, in its own family")
        #expect(meshGuardedOutsideDebug.isEmpty, "a DEBUG-guarded ProximityKit mesh hook must not be reported")
        #expect(uiTestMeshReads.map(\.token) == ["PROXIMITYKIT_UI_TEST_"],
                "PROXIMITYKIT_UI_TEST_MESH_* is a UI-test flag, and must score to that family exactly once")
    }

    // MARK: - Key custody

    /// Matcher: does this source opt a keychain write into iCloud Keychain sync?
    static func containsSynchronizableTrue(_ source: String) -> Bool {
        source.contains("synchronizable: true")
    }

    /// Matcher: every bare (non-`ThisDeviceOnly`) accessibility-class token in `source`.
    /// A constant name immediately followed by `ThisDeviceOnly` is device-bound and ignored.
    static func bareAccessibilityTokens(in source: String) -> [String] {
        let bareClasses = ["kSecAttrAccessibleAfterFirstUnlock", "kSecAttrAccessibleWhenUnlocked", "kSecAttrAccessibleAlways"]
        var hits: [String] = []
        // R2: bounded by the three classes × each one's occurrences in a finite string.
        for token in bareClasses {
            var searchRange = source.startIndex..<source.endIndex
            // R2: each pass moves past one occurrence.
            while let range = source.range(of: token, range: searchRange) {
                let suffixStart = range.upperBound
                if !source[suffixStart...].hasPrefix("ThisDeviceOnly") {
                    hits.append(token)
                }
                searchRange = range.upperBound..<source.endIndex
            }
        }
        return hits
    }

    // MARK: - The purpose wall

    /// The purpose wall's reader: the primitive markers, the escape-hatch marker, the window around a
    /// call, and the words that name a purpose in it. The markers, the hatch marker and the window are a
    /// host purpose wall's own (Fernlet's `CryptographicWallScan`), so the rule reads the same lines in
    /// either repository; the purpose words are narrower (``purposeWords``).
    ///
    /// **Concurrency.** Stateless: every member is a constant or a pure function of its arguments.
    enum CryptoScan {

        /// The raw CryptoKit call sites the purpose wall demands a domain at.
        static let primitiveMarkers = [
            "signature(for:", "isValidSignature(", "hkdfDerivedSymmetricKey", "HKDF<", "HMAC<",
            "ChaChaPoly.seal", "ChaChaPoly.open", "AES.GCM.seal", "AES.GCM.open"
        ]

        /// The comment that silences the purpose wall, for the paths with no domain to name: an escape
        /// hatch, which the census (``ProximitySourceWallTests/pinnedByLabel``) counts by the label after it.
        static let escapeHatchMarker = "cryptographic-domain:"

        /// The words that name a purpose in a call's window: ProximityKit's purpose type, a `purpose`
        /// argument or binding, an authenticated-data binding, or an escape hatch. A host registry's type
        /// is not among them, though a host's own wall accepts its own (Fernlet's accepts
        /// `FernletCryptoPurpose`): ProximityKit names that type nowhere (the namespace wall's rule 2), so
        /// a window naming only it names no purpose ProximityKit holds.
        static let purposeWords = ["CryptographicPurpose", "purpose", "authenticated", escapeHatchMarker]

        /// The fewest primitive-call lines the wall may read in ProximityKit's code: about four fifths of
        /// the 21, in six files, MEASURED at ProximityKit plan step A1.1.16 (2026-10-14), so a marker list
        /// or a walk that stops seeing the calls fails rather than reading as clean. It does not move for
        /// an added call; a removal lowers it only with the removal argued.
        static let primitiveCallFloor = 16

        /// One primitive-call line of a source.
        struct Call: Sendable {
            /// The 1-based line.
            let line: Int
            /// Whether a purpose word (``CryptoScan/hasPurpose(_:)``) stands in its window.
            let namesAPurpose: Bool
        }

        /// Every line of `source` that opens a raw primitive call (``isPrimitiveCall(_:)``), each with
        /// whether its window (``context(around:in:)``) names a purpose.
        static func primitiveCalls(in source: String) -> [Call] {
            let lines = source.components(separatedBy: .newlines)
            var calls: [Call] = []
            // R2: bounded by the source's line count.
            for index in lines.indices where isPrimitiveCall(lines[index]) {
                calls.append(Call(line: index + 1, namesAPurpose: hasPurpose(context(around: index, in: lines))))
            }
            return calls
        }

        /// The window the purpose wall reads around the call at `index`: three lines above it to six below.
        ///
        /// Asymmetric: a multi-line primitive call names its purpose inside its own argument list, which
        /// sits BELOW the call's opening line, never above it.
        static func context(around index: Int, in lines: [String]) -> String {
            guard lines.indices.contains(index) else { return "" }
            let lower = max(0, index - 3)
            let upper = min(lines.count - 1, index + 6)
            return lines[lower...upper].joined(separator: "\n")
        }

        /// Whether a line opens a raw primitive call the wall demands a domain at.
        static func isPrimitiveCall(_ line: String) -> Bool {
            primitiveMarkers.contains(where: line.contains)
        }

        /// Whether a call's window names a purpose (``purposeWords``).
        static func hasPurpose(_ context: String) -> Bool {
            purposeWords.contains(where: context.contains)
        }
    }

    /// The purpose matcher trips on a planted call and passes its near-misses: a call with no purpose
    /// word in reach is reported; one whose `purpose:` argument sits below it, or whose escape hatch sits
    /// above it, is not; the window reaches six lines below a call but not four above it; a call that
    /// names only a host registry's type is reported; and a line naming a purpose with no call is no call.
    static func expectThePurposeMatcherTripsOnPlantedCalls() {
        let bare = "let s = try key.signature(for: bytes)\n"
        let argumentBelow = "let s = try identity.sign(\n    key.signature(for: bytes),\n    purpose: label)\n"
        let hatchAbove = "// cryptographic-domain: x509-self-signature\nlet s = try key.signature(for: tbs)\n"
        let sixBelow = "let s = try key.signature(for: bytes)\n" + String(repeating: "let a = 1\n", count: 5)
            + "let p = purpose\n"
        let fourAbove = "let p = purpose\n" + String(repeating: "let a = 1\n", count: 3)
            + "let s = try key.signature(for: bytes)\n"
        let hostRegistryOnly = "let s = try key.signature(for: FernletCryptoPurpose.Signature.probe.signingBytes(bytes))\n"
        let noCall = "let p = purpose\n"

        let bareNamed = CryptoScan.primitiveCalls(in: bare).map(\.namesAPurpose)
        let argumentNamed = CryptoScan.primitiveCalls(in: argumentBelow).map(\.namesAPurpose)
        let hatchNamed = CryptoScan.primitiveCalls(in: hatchAbove).map(\.namesAPurpose)
        let sixBelowNamed = CryptoScan.primitiveCalls(in: sixBelow).map(\.namesAPurpose)
        let fourAboveNamed = CryptoScan.primitiveCalls(in: fourAbove).map(\.namesAPurpose)
        let hostNamed = CryptoScan.primitiveCalls(in: hostRegistryOnly).map(\.namesAPurpose)
        let noCallLines = CryptoScan.primitiveCalls(in: noCall).map(\.line)

        #expect(bareNamed == [false], "a raw call with no purpose word in reach must be reported")
        #expect(argumentNamed == [true], "a call whose `purpose:` argument sits below it names a purpose")
        #expect(hatchNamed == [true], "an escape hatch above a call answers the wall")
        #expect(sixBelowNamed == [true], "the window reaches six lines below a call")
        #expect(fourAboveNamed == [false], "the window does not reach four lines above a call")
        #expect(hostNamed == [false], "a host registry's type is no purpose ProximityKit holds")
        #expect(noCallLines.isEmpty, "a line naming a purpose with no primitive call is no call")
    }

    // MARK: - The escape-hatch census

    /// The label → count pin over ProximityKit's code: one label, one hatch, MEASURED at ProximityKit plan
    /// step A1.1.16 (2026-10-14). A hatch added or removed changes its label's count here, with what the
    /// label means said beside it, in the same commit; a label that reaches zero is removed rather than
    /// pinned at 0, since a label at zero reads as a category that still exists and happens to be empty.
    ///
    /// **`x509-self-signature`, 1: `Transport/EphemeralMeshTLSIdentity.swift`'s certificate
    /// self-signature, added with the QUIC mesh transport.** It is the one place ProximityKit produces a
    /// raw signature over a transcript it does not define, and its justification is that the format is
    /// somebody else's. QUIC's listener must present a certificate, and X.509 fixes exactly what a
    /// certificate's self-signature covers, the DER `TBSCertificate`: a domain prefix there would produce
    /// bytes no TLS stack can parse, so there is no domain to bind. What makes it safe is scope rather than
    /// a domain: the key is a P-256 pair minted at session start, used for this one signature and nothing
    /// else, never persisted, and thrown away with the session, so there is no second use for the first to
    /// be confused with, which is what domain separation buys. Nor is it a trust decision: nothing in
    /// ProximityKit verifies this signature (the transport's certificate validator accepts any
    /// certificate), and peer authentication is the signed identity introduction exchanged over the
    /// connection, with the TLS-exporter-bound channel introduction on top of it. A future hatch claiming
    /// this label must be another foreign signature format, not a transcript of ProximityKit's own that
    /// skipped its purpose.
    static let pinnedByLabel: [String: Int] = ["x509-self-signature": 1]

    /// The number of distinct files holding a hatch in ProximityKit's code, MEASURED at ProximityKit plan
    /// step A1.1.16 (2026-10-14): one, `Transport/EphemeralMeshTLSIdentity.swift`.
    static let pinnedFileCount = 1

    /// The documentation lines in ProximityKit's code that name the escape-hatch marker, by path under
    /// the package root: none, MEASURED at ProximityKit plan step A1.1.16 (2026-10-14). An empty pin is
    /// still a pin: a new prose mention fails here.
    static let pinnedProseMentions: [String: Int] = [:]

    /// One escape hatch, located and classified.
    struct EscapeHatch: Sendable {
        /// The file, by its path under the package root (`Sources/ProximityKit/…`).
        let path: String
        /// The 1-based line.
        let line: Int
        /// The text after the marker, trimmed of spaces, tabs and backticks: the label the hatch gives
        /// itself.
        let label: String
        /// Whether the marker sits in a `///` documentation line (prose about a hatch) rather than on a
        /// line of code or a plain comment (a hatch).
        let isProse: Bool
        /// Whether a primitive call stands within the purpose wall's reach of this line
        /// (``ProximitySourceWallTests/reachesAPrimitiveCall(from:in:)``).
        let reachesAPrimitiveCall: Bool

        /// `path:line`, for the failure messages.
        var printed: String { "\(path):\(line)" }
    }

    /// The census over ProximityKit's sources: how many files it read, and every marker it found.
    struct HatchScan: Sendable {
        /// The Swift files the walk read.
        let filesScanned: Int
        /// Every marker across them, hatches and prose alike.
        let hatches: [EscapeHatch]
    }

    /// Reads every Swift file of the module (``PackageSwiftFiles/sources()``) for escape-hatch markers. A
    /// file the walk found but cannot read as UTF-8 throws, so an unreadable file fails the cell that
    /// asked rather than reading as clean.
    static func hatchScan() throws -> HatchScan {
        let files = try PackageSwiftFiles.sources()
        var hatches: [EscapeHatch] = []
        // R2: bounded by the module's file count.
        for file in files {
            hatches += Self.hatches(in: file.text, path: PackageSwiftFiles.sourceFolder + "/" + file.path)
        }
        return HatchScan(filesScanned: files.count, hatches: hatches)
    }

    /// Every escape-hatch marker in one file, each classified. A documentation comment is prose about a
    /// hatch; a plain `//` line is not exempt, since a marker on its own line above a call silences the
    /// wall just as a trailing one does, so it counts.
    static func hatches(in source: String, path: String) -> [EscapeHatch] {
        let lines = source.components(separatedBy: .newlines)
        var found: [EscapeHatch] = []
        // R2: bounded by the source's line count.
        for index in lines.indices {
            guard let range = lines[index].range(of: CryptoScan.escapeHatchMarker) else { continue }
            let label = String(lines[index][range.upperBound...])
                .trimmingCharacters(in: CharacterSet(charactersIn: " \t`"))
            let isProse = lines[index].trimmingCharacters(in: .whitespaces).hasPrefix("///")
            found.append(EscapeHatch(path: path, line: index + 1, label: label, isProse: isProse,
                                     reachesAPrimitiveCall: reachesAPrimitiveCall(from: index, in: lines)))
        }
        return found
    }

    /// Whether a primitive call stands within the purpose wall's reach of line `index`. The wall reads
    /// [call − 3, call + 6], so a line at `index` is reachable from any call in [index − 6, index + 3]:
    /// the same asymmetry, mirrored.
    static func reachesAPrimitiveCall(from index: Int, in lines: [String]) -> Bool {
        guard lines.indices.contains(index) else { return false }
        let lower = max(0, index - 6)
        let upper = min(lines.count - 1, index + 3)
        return lines[lower...upper].contains(where: CryptoScan.isPrimitiveCall)
    }

    /// The census's reader on its samples: a hatch on its own line and a trailing one are hatches, each
    /// reading its label with backticks trimmed; a `///` line naming the marker is prose; and prose one
    /// line above a call is within the wall's reach, while prose five lines above one is not.
    static func expectTheHatchReaderReadsItsSamples() {
        let code = "// cryptographic-domain: x509-self-signature\nlet s = try key.signature(for: tbs)\n"
            + "let t = try key.signature(for: d) // cryptographic-domain: `key-derived`\n"
        let nearProse = "/// The cryptographic-domain: marker is named here.\nlet s = try key.signature(for: tbs)\n"
        let farProse = "/// The cryptographic-domain: marker is named here.\n" + String(repeating: "let a = 1\n", count: 4)
            + "let s = try key.signature(for: tbs)\n"

        let codeHatches = hatches(in: code, path: "a.swift")
        let codeLabels = codeHatches.map(\.label)
        let codeProse = codeHatches.filter(\.isProse)
        let near = hatches(in: nearProse, path: "b.swift")
        let far = hatches(in: farProse, path: "c.swift")

        #expect(codeLabels == ["x509-self-signature", "key-derived"],
                "a hatch on its own line and a trailing one each read their label, backticks trimmed")
        #expect(codeProse.isEmpty, "a `//` hatch is a hatch, not prose")
        #expect(near.map(\.isProse) == [true], "a `///` line naming the marker is prose")
        #expect(near.map(\.reachesAPrimitiveCall) == [true], "prose one line above a call is within the wall's reach")
        #expect(far.map(\.reachesAPrimitiveCall) == [false], "prose five lines above a call is out of the wall's reach")
    }
}
