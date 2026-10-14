// ProximityKeychainDoorTests.swift
// ProximityKitTests
//
// ProximityKit plan step A1.1: the wall around ProximityKit's keychain door, held in ProximityKit's own
// package tests so it travels with the package. ProximityKit's keychain funnel reaches the keychain through
// one backend, and a Debug build has a door, `installBackend(_:)`, that replaces that backend for the whole
// process; the package tests' installer (TestSupport/PackageTestEnvironment.swift) is its one caller, which
// puts their in-memory keychain store behind the funnel. A call of the door anywhere else would move every
// ProximityKit keychain row of its process out of the keychain without a byte of the funnel changing, and
// a door outside the `#if DEBUG` branch, or a second writer of its slot, would give a Release build one.
// This suite reads the module's sources and the package's tests as text through `PackageRoot` and their
// code through the package's lexer, so it holds both wherever the package sits. A host's own walls hold
// that it calls the door nowhere (Fernlet's `KeyCustodyBoundaryTests`).

import Foundation
import Testing

/// ProximityKit's keychain door is declared once, in the funnel's `#if DEBUG` branch, whose text is
/// pinned, and is called by the package tests' installer alone.
@Suite struct ProximityKeychainDoorTests {

    /// The module's sources, relative to the package root.
    private static let sourceRoot = "Sources/ProximityKit"

    /// The package's tests, the folder of that name under the package root's `Tests` folder.
    private static let testFolder = "ProximityKitTests"

    /// The fewest Swift files the module walk may read: about four fifths of the 135 it read when the
    /// wall was written, so a root that stops resolving fails rather than reading as clean.
    private static let sourceFloor = 108

    /// The fewest Swift files the test walk may read: about four fifths of the 28 it read then.
    private static let testFloor = 22

    /// The one file that declares the door, relative to the module root: the keychain funnel.
    private static let declarationFile = "Support/ProximityKeychain" + "Item.swift"

    /// The one file that calls the door, relative to the test folder: the package tests' installer.
    private static let installerFile = "TestSupport/PackageTestEnvironment.swift"

    /// The funnel's `#if DEBUG` region as lexed code, from its `#if DEBUG` through its `#endif` with every
    /// run of whitespace read as one space: the backend slot, the door that writes it, the Debug build's
    /// backend that reads it, and the Release build's backend, the system keychain with no slot to read.
    /// The lexer drops comments, so a doc edit leaves it as it is.
    static let backendDoorRegion = "#if DEBUG private static let installedBackend = "
        + "Mutex<(any ProximityKeychainBackend)?>(nil) static func installBackend(_ backend: any "
        + "ProximityKeychainBackend) { installedBackend.withLock { $0 = backend } } static var backend: any "
        + "ProximityKeychainBackend { guard let installed = installedBackend.withLock({ $0 }) else { return "
        + "SystemKeychain() } return installed } #else static var backend: any ProximityKeychainBackend { "
        + "SystemKeychain() } #endif"

    /// The door is declared once, in the keychain funnel and inside its `#if DEBUG` branch, and called
    /// from exactly one file, the package tests' installer: from no file of the module and from no other
    /// file of the package's tests. Every spelling of the door's name counts: a call, however it is
    /// qualified, and a reference with no call (`let door = Funnel.installBackend`), which a later call
    /// could apply. The funnel holds one `#if` directive, and the region from its `#if DEBUG` through its
    /// `#endif` is ``backendDoorRegion``, so no second writer of the slot can sit beside the door and
    /// the Release branch is the system keychain. No CI step compiles a Release build, so this text is
    /// what holds the Release branch: it can only break where the Debug one does. Read as lexed code, so
    /// a comment or a string that spells the door is not one, over both walks at their file floors, with
    /// the readers held to their samples and neighbours first.
    @Test func theKeychainDoorIsDeclaredOnceUnderDebugAndCalledOnlyByTheInstaller() throws {
        Self.expectTheDoorReadersSeeTheirSamplesAndNoNeighbour()
        let sources = try Self.files(under: PackageRoot.url(Self.sourceRoot), folder: Self.sourceRoot)
        let tests = try Self.files(under: PackageRoot.url("Tests").appendingPathComponent(Self.testFolder),
                                   folder: Self.testFolder)
        #expect(sources.count >= Self.sourceFloor,
                "the door wall read \(sources.count) Swift files under \(Self.sourceRoot), below its floor \(Self.sourceFloor)")
        #expect(tests.count >= Self.testFloor,
                "the door wall read \(tests.count) Swift files under \(Self.testFolder), below its floor \(Self.testFloor)")

        var declarations: [String] = []
        var moduleUses: [String] = []
        // R2: bounded by the module's file list.
        for file in sources {
            let found = Self.doorLines(in: file.code)
            moduleUses += found.uses.map { "\(file.path):\($0)" }
            // R2: bounded by the file's declarations of the door.
            for line in found.declarations {
                declarations.append(Self.isInDebugBranch(line: line, of: file.code) ? file.path : "\(file.path):\(line) outside #if DEBUG")
            }
        }
        var testUses: [String] = []
        var testDeclarations: [String] = []
        // R2: bounded by the test folder's file list.
        for file in tests {
            let found = Self.doorLines(in: file.code)
            testUses += found.uses.map { _ in file.path }
            testDeclarations += found.declarations.map { "\(file.path):\($0)" }
        }
        #expect(declarations == [Self.declarationFile], """
            the keychain door is declared at \(declarations); it must be declared once, in \
            \(Self.declarationFile), inside its `#if DEBUG` branch, so a Release build has no door
            """)
        #expect(moduleUses.isEmpty, """
            ProximityKit's own code names its keychain door at \(moduleUses): a module that installed a backend \
            would move its every keychain row out of the keychain in a shipping process
            """)
        #expect(testUses == [Self.installerFile] && testDeclarations.isEmpty, """
            the package's tests name the keychain door in \(testUses) and declare one at \(testDeclarations); \
            only \(Self.installerFile) may name it, once: a second install would replace the bundle's store \
            for every suite running beside it
            """)

        let funnel = try #require(sources.first { $0.path == Self.declarationFile },
                                  "the door wall read no \(Self.declarationFile)")
        let region = Self.debugRegion(of: funnel.code)
        #expect(region.directives == 1, """
            \(Self.declarationFile) holds \(region.directives) `#if` directives; the door's `#if DEBUG` must be \
            its only one, so no other conditional branch can hold a door or a slot
            """)
        #expect(region.text == Self.backendDoorRegion, """
            \(Self.declarationFile)'s `#if DEBUG` region reads `\(region.text)`, not the pinned \
            ``backendDoorRegion``: a second writer of the backend slot, a door outside the Debug branch or a \
            Release backend other than the system keychain changed it
            """)
    }

    // MARK: - Readers

    /// Every Swift file under `root`, each by its path under `folder` and lexed, sorted by path.
    private static func files(under root: URL, folder: String) throws -> [(path: String, code: String)] {
        let walker = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil)
        let urls = (walker?.allObjects as? [URL] ?? []).filter { $0.pathExtension == "swift" }
        var files: [(path: String, code: String)] = []
        // R2: bounded by the folder's file list.
        for url in urls.sorted(by: { $0.path < $1.path }) {
            let source = try String(contentsOf: url, encoding: .utf8)
            files.append((path: relativePath(of: url, under: folder), code: SwiftSourceLexer.lex(source).code))
        }
        return files
    }

    /// `url`'s path under `folder`, read off the path's last `/<folder>/` component so a symlinked
    /// checkout resolves alike; the full path when it is not under one, which then matches no expected
    /// path and fails loudly.
    private static func relativePath(of url: URL, under folder: String) -> String {
        let path = url.path
        guard let range = path.range(of: "/" + folder + "/", options: .backwards) else { return path }
        return String(path[range.upperBound...])
    }

    /// The 1-based lines of lexed `code` that spell the door's name, as a use (a call however it is
    /// qualified, a reference with no call, a backtick-quoted name) and as a declaration
    /// (`func installBackend`, generic or not), or `[-1]` for both, which no sample expects and no file
    /// passes, when the pattern does not compile. A longer name holding it (`installBackendCount`,
    /// `reinstallBackend`) is neither.
    static func doorLines(in code: String) -> (uses: [Int], declarations: [Int]) {
        let pattern = #"(?<![A-Za-z0-9_])(func\s+)?installBackend(?![A-Za-z0-9_])"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return ([-1], [-1]) }
        let text = code as NSString
        var uses: [Int] = []
        var declarations: [Int] = []
        // R2: bounded by the matches in one source.
        for match in regex.matches(in: code, range: NSRange(location: 0, length: text.length)) {
            let line = text.substring(to: match.range.location).count(where: { $0 == "\n" }) + 1
            if match.range(at: 1).location == NSNotFound {
                uses.append(line)
            } else {
                declarations.append(line)
            }
        }
        return (uses, declarations)
    }

    /// Whether 1-based `line` of lexed `code` sits in the branch of a `#if DEBUG`, before that
    /// directive's `#elseif`, `#else` or `#endif`. The Power-of-10 wall refuses a nested `#if`, so the
    /// last directive above the line decides; only the exact directive `#if DEBUG` opens such a branch.
    static func isInDebugBranch(line: Int, of code: String) -> Bool {
        var inDebug = false
        // R2: bounded by the lines above `line`.
        for text in code.components(separatedBy: "\n").prefix(max(line - 1, 0)) {
            let directive = text.trimmingCharacters(in: .whitespaces)
            if directive.hasPrefix("#if") {
                inDebug = directive == "#if DEBUG"
            } else if directive.hasPrefix("#else") || directive.hasPrefix("#endif") {
                inDebug = false
            }
        }
        return inDebug
    }

    /// The count of `#if` directives in lexed `code`, and the text from its first `#if DEBUG` line
    /// through the next `#endif` line with every run of whitespace read as one space (empty when there
    /// is no such region).
    static func debugRegion(of code: String) -> (directives: Int, text: String) {
        let lines = code.components(separatedBy: "\n")
        let trimmed = lines.map { $0.trimmingCharacters(in: .whitespaces) }
        let directives = trimmed.filter { $0.hasPrefix("#if") }.count
        guard let open = trimmed.firstIndex(of: "#if DEBUG"),
              let close = trimmed[open...].firstIndex(where: { $0.hasPrefix("#endif") }) else { return (directives, "") }
        let words = lines[open...close].joined(separator: "\n").components(separatedBy: .whitespacesAndNewlines)
        return (directives, words.filter { !$0.isEmpty }.joined(separator: " "))
    }

    /// The door reader reads every way a use and a declaration are spelled and none of their nearest
    /// neighbours (a longer name, the slot, a comment, a string); the branch reader puts a line inside
    /// `#if DEBUG` only between that exact directive and its `#elseif`, `#else` or `#endif`, never in a
    /// `#if DEBUG || …` branch or an `#elseif`; and the region reader reads one region whitespace-blind.
    /// Every sample is lexed first, as the files are, and qualified with a neutral name.
    private static func expectTheDoorReadersSeeTheirSamplesAndNoNeighbour() {
        let uses = [
            "Funnel.installBackend(store)", "Self.installBackend(store)", "installBackend (store)",
            "Funnel\n    .installBackend(store)", "let door = Funnel.installBackend",
            "[store].forEach(Funnel.installBackend)", "`installBackend`(store)"
        ]
        let declarations = [
            "static func installBackend(_ backend: any ProximityKeychainBackend) {", "func  installBackend(_ b: B) {}",
            "static func installBackend<B: ProximityKeychainBackend>(_ b: B) {}"
        ]
        let neither = [
            "let installBackendCount = 1", "reinstallBackend(store)", "installedBackend.withLock { $0 = backend }",
            "/// Funnel.installBackend(store)", #"let s = "installBackend(store)""#
        ]
        // R2: bounded by the three fixture lists.
        for sample in uses {
            let found = doorLines(in: SwiftSourceLexer.lex(sample).code)
            #expect(found.uses.count == 1 && found.declarations.isEmpty, "missed the use in: \(sample)")
        }
        for sample in declarations {
            let found = doorLines(in: SwiftSourceLexer.lex(sample).code)
            #expect(found.declarations == [1] && found.uses.isEmpty, "missed the declaration in: \(sample)")
        }
        for neighbour in neither {
            let found = doorLines(in: SwiftSourceLexer.lex(neighbour).code)
            #expect(found.uses.isEmpty && found.declarations.isEmpty, "read the door in: \(neighbour)")
        }
        let debug = "#if DEBUG\nstatic func installBackend() {}\n#else\nstatic var backend: Int { 0 }\n#endif\nlet x = 1"
        #expect(isInDebugBranch(line: 2, of: debug), "a line in the `#if DEBUG` branch read as outside it")
        #expect(!isInDebugBranch(line: 4, of: debug) && !isInDebugBranch(line: 6, of: debug),
                "a line after `#else` or `#endif` read as inside the `#if DEBUG` branch")
        #expect(!isInDebugBranch(line: 2, of: "#if os(iOS)\nfunc installBackend() {}\n#endif"),
                "a line under another condition read as inside a `#if DEBUG` branch")
        #expect(!isInDebugBranch(line: 1, of: "func installBackend() {}"), "an unguarded line read as guarded")
        #expect(!isInDebugBranch(line: 2, of: "#if DEBUG || os(macOS)\nfunc installBackend() {}\n#endif"),
                "a `#if DEBUG || …` branch read as Debug-only")
        #expect(!isInDebugBranch(line: 4, of: "#if DEBUG\nlet a = 1\n#elseif os(macOS)\nfunc installBackend() {}\n#endif"),
                "an `#elseif` branch read as Debug-only")
        let region = debugRegion(of: "let a = 1\n    #if DEBUG\n    let b =   2\n\n    #else\n    let c = 3\n    #endif\nlet d = 4")
        #expect(region.directives == 1 && region.text == "#if DEBUG let b = 2 #else let c = 3 #endif",
                "the region reader read \(region)")
        #expect(debugRegion(of: "#if os(iOS)\nlet a = 1\n#endif").text.isEmpty, "a region with no `#if DEBUG` was read")
    }
}
