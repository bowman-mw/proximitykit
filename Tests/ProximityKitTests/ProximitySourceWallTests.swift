// ProximitySourceWallTests.swift
// ProximityKitTests
//
// ProximityKit plan step A1.1: the walls over ProximityKit's own code whose rules a host also holds over
// its shipping code, held in this module's tests so they travel with the package. No compiler checks
// either rule: a launch hook read outside `#if DEBUG`, or a keychain row that syncs, compiles clean and
// passes every other test. This suite reads every Swift file of the module as text, through `PackageRoot`
// and the package's walker (TestSupport/PackageSwiftFiles.swift), at the walk's floor, and holds two
// rules, each matcher held to its samples:
//
//   the launch hooks (TH1)  every line of ProximityKit's code that reads one of its DEBUG
//        launch-environment keys, `PROXIMITYKIT_UI_TEST_*` (the mesh manager's canned-mesh flags) or
//        `PROXIMITYKIT_MESH*` (the transport's console mirror and its two chaos keys), sits inside an
//        open `#if DEBUG` region, so no hook ships in Release; and each family is read at its floor, so a
//        matcher that stops seeing one fails rather than passes;
//   key custody  no keychain row ProximityKit writes syncs through iCloud Keychain
//        (`synchronizable: true` nowhere in its code), and every accessibility class it names is a
//        `ThisDeviceOnly` one: a host that syncs a key, or keeps one a backup restores, writes that row
//        itself.
//
// A host's own walls hold the same rules over the host's code; in the Fernlet repository,
// `TestHookBoundaryTests` and `KeyCustodyBoundaryTests`, which read Fernlet's shipping roots but this
// module's folder.

import Foundation
import Testing

/// ProximityKit's code reads its launch hooks only inside `#if DEBUG`, each family still read, writes no
/// synchronizable keychain row and names no accessibility class that is not `ThisDeviceOnly`: six cells,
/// two of them the matchers' samples.
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
}
