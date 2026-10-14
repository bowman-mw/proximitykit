// PackageTestTreeWallTests.swift
// ProximityKitTests
//
// ProximityKit plan step A1.1: the walls over ProximityKit's package tests as a tree, held in those tests
// so they travel with the package. XCTest and Swift Testing run every suite of a bundle in one process, in
// parallel, so a test that replaces a process-wide slot, roots a store at a shared location or seals it
// under a shared key, or builds a manager over a host that dies at once, compiles clean, passes alone and
// lands its damage in another suite. This suite reads every Swift file of the target, and for one rule
// ProximityKit's sources, as text through `PackageRoot` and the package's walker
// (TestSupport/PackageSwiftFiles.swift), each read at its walk's floor, and holds four rules, each
// matcher held to its samples:
//
//   the audit install  ProximityKit's audit sink is installed in these tests by their installer
//        (TestSupport/PackageTestEnvironment.swift) alone, once, and by no file of ProximityKit's code, and
//        outside ProximityAudit's own file no code extends it, aliases it or takes its metatype;
//   the store walls  every session or routed store a test builds names a scope, none reaches a
//        production scope by any spelling, and every host double that states a root of its own states
//        both scopes on it;
//   ML5  no test builds a mesh manager or a pair session over a host expression that is itself a call,
//        whose host dies at the end of the expression;
//   the digest homes  no test file is a home of either determinism digest: the batteries that pin them
//        are a host's, and a copied determinism suite names its own file here in the same commit.
//
// A host's own walls hold the same rules over the host's trees; in the Fernlet repository,
// `ProximityAuditBridgeTests`, `MeshSessionStoreIsolationTests`, `MeshRoutedStoreIsolationTests`,
// `MemoryLifecycleBoundaryTests`' ML5 and the acceptance batteries' digest homes, which read Fernlet's
// trees and not this folder.

import Foundation
import Testing

/// ProximityKit's package tests install the audit sink once, in their installer, and ProximityKit's code
/// installs none; every store they build is on a scope of their own; no manager is built over a host
/// nobody holds; and no file is a home of a determinism digest: six cells, one of them the store
/// scanners' samples.
@Suite struct PackageTestTreeWallTests {

    /// This file, by its path under the test target's folder. Its samples spell the store
    /// constructions, production scopes and inline hosts the store and ML5 sweeps refuse, so those
    /// sweeps leave out exactly this path; the audit and host-double reads lex it (its samples are
    /// literals), and its digest spellings are split, which the digest cell checks.
    static let wallFile = "PackageTestTreeWallTests.swift"

    // MARK: - The cells

    /// **The audit install.** `ProximityAudit.install` is named in exactly one file of the package's
    /// tests, ``installerFile``, once, and in no file of ProximityKit's sources: the bundle runs on the
    /// one sink its installer put in place, which every `PackageAuditCapture` reads, and ProximityKit's
    /// own code installs none (a host installs its own). A reference with no call counts, since a later
    /// call could apply it. Outside ``auditDeclarationFile`` no code extends `ProximityAudit`, aliases it
    /// or takes its metatype: inside such an extension a bare `install(` names the slot, and through an
    /// alias or a metatype an `install` call no longer spells the type, so either would reach the slot
    /// unseen. Read as lexed code (`SwiftSourceLexer`), so a comment or a string that spells the name is
    /// not one, over both walks at their file floors, with the matchers held to their samples first.
    @Test func onlyThePackageTestsInstallerInstallsAnAuditSink() throws {
        Self.expectTheInstallMatchersSeeTheirSamplesAndNoNeighbour()
        let sources = try PackageSwiftFiles.sources()
        let tests = try PackageSwiftFiles.tests()
        #expect(sources.count >= PackageSwiftFiles.sourceFloor, """
            the install-site scan saw \(sources.count) Swift files under \(PackageSwiftFiles.sourceFolder), \
            below its floor \(PackageSwiftFiles.sourceFloor)
            """)
        #expect(tests.count >= PackageSwiftFiles.testFloor, """
            the install-site scan saw \(tests.count) Swift files under \(PackageSwiftFiles.testFolder), below \
            its floor \(PackageSwiftFiles.testFloor)
            """)
        let read = Self.auditReads(sources: sources, tests: tests)
        #expect(read.sites == Self.installSites, """
            `ProximityAudit.install` is named in \(read.sites.sorted { $0.key < $1.key }); only \
            \(Self.installerFile) may name it, once: a second install in the package's tests replaces the \
            sink every package capture reads, and ProximityKit's own code installs none
            """)
        #expect(read.aliases.isEmpty, """
            `ProximityAudit` is extended, aliased or taken as a metatype at \(read.aliases); outside \
            \(Self.auditDeclarationFile) none may be, since a bare `install(` in an extension, or an \
            `install` through an alias or a metatype, reaches the sink's slot by a spelling the install \
            count cannot see
            """)
    }

    /// **The session store wall.** Over every package test file but this one, at the walk's floor:
    /// every `MeshSessionStore(…)` passes an explicit `scope:` (the initializer has no default today, so
    /// the cheapest future convenience, a defaulted production scope, is what this refuses); no file
    /// spells `MeshSessionStorageScope.production`, nor reaches a production scope through the
    /// type-prefixed spelling broken before its `.` or the shorthand `.production(for:directory:
    /// installBinding:)` wherever a scope is expected (read over lexed code); and no hand-built
    /// `MeshSessionStorageScope(…)` names a production directory or keychain service
    /// (``productionArgumentNeedles``). No construction floor: the package's tests build no session store
    /// today, and a suite that does is held here.
    @Test func everyPackageSessionStoreIsOnAScopeOfItsOwn() throws {
        let files = try PackageSwiftFiles.tests()
        #expect(files.count >= PackageSwiftFiles.testFloor, """
            the store walls read \(files.count) Swift files under \(PackageSwiftFiles.testFolder), below its \
            floor \(PackageSwiftFiles.testFloor): the root moved, or the reader stopped reading it, and a \
            store or a host double there is unseen
            """)
        var problems: [String] = []
        // R2: bounded by the package's file count.
        for file in files where file.path != Self.wallFile {
            problems += Self.storeProblems(in: file, of: .session)
        }
        #expect(problems.isEmpty, "\(problems.joined(separator: "\n"))")
    }

    /// **The routed store wall and the scratch-root needle.** The session wall's refusals over the routed
    /// family, at the same floor; and every class declared at file scope that conforms to `ProximityHost`
    /// and states `proximitySupportDirectory` at the top level of its body states both
    /// `meshSessionStorage` and `meshRoutedStorage` there too. A double that spells no scope takes
    /// `ProximityHost`'s default scopes, the namespace's production rows on whatever root it states, so
    /// on a scratch root of its own it would seal its files under the production keys, which any wipe in
    /// the process deletes, while spelling neither a construction nor a `.production` the needles above
    /// could see. At least ``minimumHostDoubles`` doubles must be read, so a broken reader cannot pass on
    /// an empty read.
    @Test func everyPackageRoutedStoreAndHostDoubleIsOnAScopeOfItsOwn() throws {
        let files = try PackageSwiftFiles.tests()
        #expect(files.count >= PackageSwiftFiles.testFloor, """
            the store walls read \(files.count) Swift files under \(PackageSwiftFiles.testFolder), below its \
            floor \(PackageSwiftFiles.testFloor): the root moved, or the reader stopped reading it, and a \
            store or a host double there is unseen
            """)
        var problems: [String] = []
        var doubles: [HostDouble] = []
        // R2: bounded by the package's file count.
        for file in files where file.path != Self.wallFile {
            problems += Self.storeProblems(in: file, of: .routed)
            doubles += try Self.hostDoubles(in: SwiftSourceLexer.lex(file.text).code)
        }
        #expect(problems.isEmpty, "\(problems.joined(separator: "\n"))")
        #expect(doubles.count >= Self.minimumHostDoubles, "read only \(doubles.count) host doubles — scanner broken?")
        let unscoped = Self.unscopedRootedDoubles(doubles)
        #expect(unscoped.isEmpty, """
            \(unscoped) state a sidecar root of their own but not both storage scopes, so the manager a \
            test builds over one seals its files on that root under the namespace's PRODUCTION seal keys \
            (`ProximityHost`'s default scopes since ProximityKit plan step A0.6.6), which any \
            concurrently-running wipe deletes. State `meshSessionStorage` and `meshRoutedStorage` on that \
            root with `.test.` services of the double's own, as PackageTestHost does.
            """)
    }

    /// The store walls' scanners, held to their samples both ways, because the matcher is the wall. The
    /// shorthand scanner sees `.production(for:directory:installBinding:)` in every place a scope goes:
    /// an argument, a typed binding wrapped across lines, a host's computed property, a `return`. The
    /// type-prefixed scanner sees its own type's spelling on one line and broken before the `.`, and not
    /// its twin's. Neither reads another type's `.production`, nor a production read through a value. The
    /// host-double reader reads a file-scope double with what the top level of its body states, and no
    /// class that is no host, a nested class, or one in a comment or a literal.
    @Test func theStoreScopeScannersSeeEverySpellingAndOnlyThose() throws {
        Self.expectTheProductionScopeScannersFixtured()
        try Self.expectTheScratchRootReaderFixtured()
    }

    /// **ML5, the package's half.** No package test file but this one builds one of ProximityKit's two
    /// `unowned` host holders, a mesh manager or a pair session, over a host expression that is itself a
    /// call (``inlineHostPattern``): the host dies at the end of the expression, so the holder is born
    /// with a dangling `unowned` host (invariant HP0). Read over each file's text at the walk's floor,
    /// the matcher held to its samples first. Known narrowness, as the host's ML5: a multi-line call
    /// with its host label on a line of its own is not matched.
    @Test func packageTestsNeverBuildAManagerOverAnInlineHost() throws {
        Self.expectTheInlineHostMatcherFixtured()
        let files = try PackageSwiftFiles.tests()
        #expect(files.count >= PackageSwiftFiles.testFloor, """
            ML5 read \(files.count) Swift files under \(PackageSwiftFiles.testFolder), below its floor \
            \(PackageSwiftFiles.testFloor): the walk is broken, not the tree clean
            """)
        var violations: [String] = []
        // R2: bounded by the package's file count.
        for file in files where file.path != Self.wallFile {
            violations += Self.inlineHostViolations(in: file.text).map { "\(file.path):\($0)" }
        }
        #expect(violations.isEmpty, """
            ML5: these build a proximity manager over a host expression that dies at the end of the \
            expression, so the manager is born with a dangling unowned host (invariant HP0). Hoist the \
            host into its own `let` that outlives the manager:
            \(violations.joined(separator: "\n"))
            """)
    }

    /// **The digest homes.** Neither determinism digest, the schedule's or the overlay's, has a home
    /// in the package's tests: a host's acceptance battery pins each in one file of its own, and a
    /// determinism suite copied here names its own file in this pin in the same commit, so a digest
    /// that moves is a red, never a re-pin. Read over every package test file with its whole-line
    /// comments dropped (``codeOnly(_:)``), at the walk's floor; each digest is spelled split here, and
    /// the last check holds this file to that.
    @Test func noPackageTestIsAHomeOfADeterminismDigest() throws {
        let files = try PackageSwiftFiles.tests()
        #expect(files.count >= PackageSwiftFiles.testFloor, """
            the digest-home scan read \(files.count) Swift files under \(PackageSwiftFiles.testFolder), below \
            its floor \(PackageSwiftFiles.testFloor): the walk is broken, not the tree clean
            """)
        let code = files.map { (name: $0.path, code: Self.codeOnly($0.text)) }
        let schedule = Self.homes(of: "ca898" + "bcc", in: code)
        #expect(schedule.isEmpty, """
            the schedule digest has a home in the package's tests, \(schedule): a copied determinism suite \
            raises this pin to its own file in the same commit; a move is a red, never a re-pin
            """)
        let overlay = Self.homes(of: "594b6" + "f77", in: code)
        #expect(overlay.isEmpty, """
            and so does the overlay digest, \(overlay): a copied determinism suite raises this pin to its own \
            file in the same commit; a move is a red, never a re-pin
            """)
        let me = try #require(code.first { $0.name == Self.wallFile }, "the digest-home scan read no \(Self.wallFile)")
        let spellsADigest = me.code.contains("ca898" + "bcc") || me.code.contains("594b6" + "f77")
        #expect(!spellsADigest, "and this file spells neither contiguously")
    }

    // MARK: - The audit install

    /// The one file of the package's tests that installs the bundle's audit sink, by its path under the
    /// test target's folder.
    static let installerFile = "TestSupport/PackageTestEnvironment.swift"

    /// The file that declares `ProximityAudit`, by its path under the module's source folder: the one
    /// place its extensions, an alias for it or its metatype belong.
    static let auditDeclarationFile = "Support/ProximityAudit.swift"

    /// The files that install a sink, each with its one call: the package tests' installer,
    /// `PackageTestEnvironment.audit`, once, for their unhosted bundle. ProximityKit's sources install
    /// none.
    static let installSites: [String: Int] = [installerFile: 1]

    /// The install sites and alias lines the two walks hold, each file read as lexed code once it spells
    /// `ProximityAudit`: a test file by its path under the test folder, a source file by its path under
    /// the package root (``PackageSwiftFiles/sourceFolder`` and its path under it), and the aliases of
    /// every file but ``auditDeclarationFile``.
    static func auditReads(sources: [PackageSwiftFiles.File], tests: [PackageSwiftFiles.File])
        -> (sites: [String: Int], aliases: [String]) {
        let module: [(path: String, text: String, declares: Bool)] = sources.map {
            (path: PackageSwiftFiles.sourceFolder + "/" + $0.path, text: $0.text, declares: $0.path == auditDeclarationFile)
        }
        let named = module + tests.map { (path: $0.path, text: $0.text, declares: false) }
        var sites: [String: Int] = [:]
        var aliases: [String] = []
        // R2: bounded by the two walks' file lists.
        for file in named where file.text.contains("ProximityAudit") {
            let code = SwiftSourceLexer.lex(file.text).code
            let calls = installCalls(in: code)
            if calls > 0 {
                sites[file.path] = calls
            }
            if !file.declares {
                aliases += auditAliasLines(in: code).map { "\(file.path):\($0)" }
            }
        }
        return (sites, aliases)
    }

    /// The spellings of `ProximityAudit.install` in lexed `code`, a call or a reference, the type and its
    /// member read across whitespace and line breaks, or -1, which no file and no sample yields, when the
    /// pattern does not compile.
    static func installCalls(in code: String) -> Int {
        guard let regex = try? NSRegularExpression(pattern: #"(?<![A-Za-z0-9_])ProximityAudit\s*\.\s*install(?![A-Za-z0-9_])"#) else {
            return -1
        }
        return regex.numberOfMatches(in: code, range: NSRange(code.startIndex..., in: code))
    }

    /// The 1-based lines of lexed `code` that extend `ProximityAudit`, alias it or take its metatype,
    /// qualified by its module or not, or `[-1]`, which no file and no sample yields, when the pattern
    /// does not compile. A longer name holding it (`ProximityAuditSink`) is not one.
    static func auditAliasLines(in code: String) -> [Int] {
        let pattern = #"(?<![A-Za-z0-9_])extension\s+(?:ProximityKit\s*\.\s*)?ProximityAudit\b"#
            + #"|(?<![A-Za-z0-9_])typealias\s+\w+\s*=\s*(?:ProximityKit\s*\.\s*)?ProximityAudit\b"#
            + #"|(?<![A-Za-z0-9_])ProximityAudit\s*\.\s*self\b"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [-1] }
        let text = code as NSString
        return regex.matches(in: code, range: NSRange(location: 0, length: text.length)).map {
            text.substring(to: $0.range.location).count(where: { $0 == "\n" }) + 1
        }
    }

    /// The install matcher reads every way the name is spelled, a call and a reference, and none of its
    /// nearest neighbours (a longer name, the declaration, another member, a comment, a string); the alias
    /// matcher reads an extension of the type, an alias for it and its metatype, and none of the sink
    /// protocol's. Each sample is lexed first, as the files are.
    private static func expectTheInstallMatchersSeeTheirSamplesAndNoNeighbour() {
        let calls = [
            "ProximityAudit.install(PackageAuditSink())", "ProximityAudit\n    .install(sink)",
            "ProximityKit.ProximityAudit.install(sink)", "ProximityAudit . install (sink)",
            "let put = ProximityAudit.install", "[sink].forEach(ProximityAudit.install)"
        ]
        let neither = [
            "nonisolated public static func install(_ sink: any ProximityAuditSink) {", "MyProximityAudit.install(sink)",
            "ProximityAudit.installed(sink)", "ProximityAudit.log(\"install\")", "/// ProximityAudit.install(sink)",
            #"let s = "ProximityAudit.install(sink)""#
        ]
        let aliases = [
            "extension ProximityAudit {", "extension ProximityKit.ProximityAudit {", "typealias PA = ProximityAudit",
            "let t = ProximityAudit.self"
        ]
        let notAliases = ["extension ProximityAuditSink {", "typealias S = ProximityAuditSink", "/// extension ProximityAudit {"]
        // R2: bounded by the four fixture lists.
        for sample in calls {
            #expect(installCalls(in: SwiftSourceLexer.lex(sample).code) == 1, "missed the call in: \(sample)")
        }
        for neighbour in neither {
            #expect(installCalls(in: SwiftSourceLexer.lex(neighbour).code) == 0, "read a call in: \(neighbour)")
        }
        for sample in aliases {
            #expect(auditAliasLines(in: SwiftSourceLexer.lex(sample).code) == [1], "missed the alias in: \(sample)")
        }
        for neighbour in notAliases {
            #expect(auditAliasLines(in: SwiftSourceLexer.lex(neighbour).code).isEmpty, "read an alias in: \(neighbour)")
        }
    }

    // MARK: - The store walls

    /// One store family the store walls hold: the session store and its scope, or the routed store and
    /// its scope, each with what its failure messages name.
    struct StoreFamily: Sendable {
        /// The store's construction, as the sweep reads it: `MeshSessionStore(`.
        let construction: String
        /// The store's type name, as its messages name it.
        let store: String
        /// The scope's type name: `MeshSessionStorageScope`.
        let scope: String
        /// The scope as the messages name it: `mesh-session` or `routed`.
        let kind: String
        /// What a store with no scope shares with every other live store, and what a wipe destroys.
        let shared: String
        /// What the production scope shares with every concurrent suite.
        let real: String
        /// The production seal key's service as a hand-built scope would spell it.
        let productionService: String
        /// The namespace's production seal-key service as a hand-built scope would read it.
        let namespaceService: String
        /// The twin wall's name in the shorthand message: the other family's.
        let twin: String

        /// The session family.
        static let session = StoreFamily(
            construction: "MeshSessionStore(", store: "MeshSessionStore", scope: "MeshSessionStorageScope",
            kind: "mesh-session",
            shared: """
                the process-wide sealed-context file and the process-wide `com.fernlet.mesh-session` keychain \
                row with every other live store — any concurrent test that runs "delete everything" destroys \
                both
                """,
            real: "the real file and the real keychain row",
            productionService: "\"com.fernlet.mesh-session\"",
            namespaceService: "installation.keychain.meshSessionSealKey.service", twin: "routed")

        /// The routed family.
        static let routed = StoreFamily(
            construction: "MeshRoutedStore(", store: "MeshRoutedStore", scope: "MeshRoutedStorageScope",
            kind: "routed",
            shared: """
                the process-wide sealed index, the process-wide chunk directory and the process-wide \
                `com.fernlet.mesh-routed` keychain row with every other live store — any concurrent test that \
                runs "delete everything" destroys all three
                """,
            real: "the real index, the real chunk directory and the real keychain row",
            productionService: "\"com.fernlet.mesh-routed\"",
            namespaceService: "installation.keychain.meshRoutedSealKey.service", twin: "session")
    }

    /// What a hand-built scope's arguments may not name, each with where it puts the scope: the
    /// production sidecar directory's spelling, Fernlet's production directory, the process's
    /// Application Support, and (from the family) the production keychain service's literal and a
    /// namespace's production seal-key service.
    static func productionArgumentNeedles(of family: StoreFamily) -> [(needle: String, puts: String)] {
        [
            (needle: "ProximitySupportLayout.defaultDirectory", puts: "on the production sidecar directory"),
            (needle: family.productionService, puts: "on the production keychain service"),
            (needle: "FernletProximityStorage.productionDirectory", puts: "on Fernlet's production directory"),
            (needle: "applicationSupportDirectory", puts: "under the process's Application Support"),
            (needle: family.namespaceService, puts: "on a namespace's production keychain service")
        ]
    }

    /// One package file's store problems for `family`: a construction with no `scope:`; the production
    /// scope's type-prefixed spelling as text; a production scope read over lexed code, type-prefixed or
    /// shorthand; and a hand-built scope whose arguments name a ``productionArgumentNeedles(of:)`` needle.
    static func storeProblems(in file: PackageSwiftFiles.File, of family: StoreFamily) -> [String] {
        var problems: [String] = []
        // R2: bounded by the file's constructions of the store.
        for arguments in constructionArguments(of: family.construction, in: file.text) where !arguments.contains("scope:") {
            problems.append("""
                \(file.path) constructs \(family.store) without `scope:`, so it shares \(family.shared). Pass a \
                scope of the test's own (PackageTestHost's scopes are one).
                """)
        }
        if file.text.contains(family.scope + ".production") {
            problems.append("\(file.path) uses the PRODUCTION \(family.kind) scope — it shares \(family.real) with every concurrent suite.")
        }
        let code = SwiftSourceLexer.lex(file.text).code
        let reads = typePrefixedProductionScopes(of: family.scope, in: code) + shorthandProductionScopes(in: code)
        if !reads.isEmpty {
            problems.append("""
                \(file.path) reaches a PRODUCTION storage scope through \(reads) — it shares \(family.real) \
                with every concurrent suite. A shorthand `.production(for:directory:installBinding:)` does not \
                say which scope it builds (only the mesh-session and routed scopes declare it), so this wall \
                and its \(family.twin) twin both refuse it.
                """)
        }
        // R2: bounded by the file's hand-built scopes × the needle list.
        for arguments in constructionArguments(of: family.scope + "(", in: file.text) {
            for needle in productionArgumentNeedles(of: family) where arguments.contains(needle.needle) {
                problems.append("\(file.path) builds a \(family.kind) scope \(needle.puts): \(arguments)")
            }
        }
        return problems
    }

    /// The argument text of every `name…)` construction in `source`, matched by depth so nested
    /// parentheses do not truncate an argument list.
    static func constructionArguments(of name: String, in source: String) -> [String] {
        var found: [String] = []
        var searchStart = source.startIndex
        // R2: each pass consumes at least one character of a finite string.
        while let head = source.range(of: name, range: searchStart..<source.endIndex) {
            searchStart = head.upperBound
            guard let close = matchingParenthesis(in: source, after: head.upperBound) else { continue }
            found.append(String(source[head.upperBound..<close]))
        }
        return found
    }

    /// Every implicit-member `.production(…)` in `code` whose arguments name `installBinding:`, with
    /// its argument text: the shorthand that builds a production storage scope wherever a scope is
    /// expected (`MeshSessionStore(scope: .production(for: namespace, directory: root,
    /// installBinding: binding))`, a host's `var meshSessionStorage: MeshSessionStorageScope {
    /// .production(…) }`), which no type-prefixed needle can see. Only the mesh-session and routed
    /// scopes declare `production(for:directory:installBinding:)`, so this finds both and cannot tell
    /// them apart. A member access is not shorthand: `MeshSessionStorageScope.production(`, the same
    /// broken across lines, `scope?.production(`. Pass lexed code (`SwiftSourceLexer.lex(_:).code`), so
    /// prose about the shorthand, and a fixture string spelling it, are not read as using it.
    static func shorthandProductionScopes(in code: String) -> [String] {
        var found: [String] = []
        var searchStart = code.startIndex
        // R2: each pass consumes at least one character of a finite string.
        while let head = code.range(of: ".production", range: searchStart..<code.endIndex) {
            searchStart = head.upperBound
            guard startsAnImplicitMember(at: head.lowerBound, in: code) else { continue }
            let rest = code[head.upperBound...].drop(while: \.isWhitespace)
            guard rest.first == "(",
                  let close = matchingParenthesis(in: code, after: code.index(after: rest.startIndex))
            else { continue }
            let arguments = code[code.index(after: rest.startIndex)..<close]
            if arguments.contains("installBinding:") { found.append(".production(\(arguments))") }
        }
        return found
    }

    /// Every `typeName.production` in `code`, whitespace and line breaks allowed around the `.`: the
    /// spelling the substring needle misses when a chain is broken before its `.`. Pass lexed code.
    static func typePrefixedProductionScopes(of typeName: String, in code: String) -> [String] {
        var found: [String] = []
        var searchStart = code.startIndex
        // R2: each pass consumes at least one character of a finite string.
        while let head = code.range(of: typeName, range: searchStart..<code.endIndex) {
            searchStart = head.upperBound
            if head.lowerBound > code.startIndex, isIdentifierCharacter(code[code.index(before: head.lowerBound)]) {
                continue
            }
            let dot = code[head.upperBound...].drop(while: \.isWhitespace)
            guard dot.first == "." else { continue }
            let member = dot.dropFirst().drop(while: \.isWhitespace)
            guard member.hasPrefix("production") else { continue }
            let after = member.dropFirst("production".count)
            if let next = after.first, isIdentifierCharacter(next) { continue }
            found.append(String(code[head.lowerBound..<after.startIndex]))
        }
        return found
    }

    /// Whether the `.` at `dot` starts an implicit member expression: what precedes it, past any
    /// whitespace, cannot end an expression the `.` continues, or is a keyword.
    private static func startsAnImplicitMember(at dot: String.Index, in code: String) -> Bool {
        var index = dot
        // R2: bounded by the characters before `dot`.
        while index > code.startIndex, code[code.index(before: index)].isWhitespace {
            index = code.index(before: index)
        }
        guard index > code.startIndex else { return true }
        let last = code[code.index(before: index)]
        if last == ")" || last == "]" { return false }
        if index == dot, "?!>".contains(last) { return false }
        guard isIdentifierCharacter(last) else { return true }
        let word = String(code[..<index].reversed().prefix(while: isIdentifierCharacter).reversed())
        return ["return", "in", "case", "try", "await", "throw", "else"].contains(word)
    }

    /// Whether `character` can be part of a Swift identifier, as far as these scanners need.
    private static func isIdentifierCharacter(_ character: Character) -> Bool {
        character.isLetter || character.isNumber || character == "_"
    }

    /// Index of the `)` closing the parenthesis that opened just before `start`, or nil.
    private static func matchingParenthesis(in source: String, after start: String.Index) -> String.Index? {
        var depth = 1
        var index = start
        // R2: bounded by the remaining characters.
        while index < source.endIndex {
            let character = source[index]
            if character == "(" { depth += 1 }
            if character == ")" {
                depth -= 1
                if depth == 0 { return index }
            }
            index = source.index(after: index)
        }
        return nil
    }

    /// The two production-scope scanners, both ways: the shorthand in each place a scope goes, the
    /// type-prefixed spelling on one line and broken before its `.`, the twin type's never read as this
    /// one's, and neither scanner reading another type's `.production` or a production read through a
    /// value.
    private static func expectTheProductionScopeScannersFixtured() {
        let shorthand = [
            "MeshSessionStore(scope: .production(for: namespace, directory: root, installBinding: binding))",
            "let scope: MeshSessionStorageScope = .production(\n    for: .fernlet, directory: root, installBinding: binding\n)",
            "var meshSessionStorage: MeshSessionStorageScope { .production(for: ns, directory: d, installBinding: b) }",
            "var meshSessionStorage: MeshSessionStorageScope { return .production(for: ns, directory: d, installBinding: b) }"
        ]
        // R2: bounded by the fixed list.
        for source in shorthand {
            #expect(shorthandProductionScopes(in: source).count == 1, "the shorthand scanner missed: \(source)")
        }
        let typePrefixed = [
            "MeshSessionStorageScope.production(\n    for: namespace, directory: root, installBinding: FernletDeviceBindingAdapter()\n)",
            "MeshSessionStorageScope\n    .production(for: namespace, directory: root, installBinding: binding)"
        ]
        // R2: bounded by the fixed list.
        for source in typePrefixed {
            #expect(shorthandProductionScopes(in: source).isEmpty, "read as shorthand: \(source)")
            #expect(typePrefixedProductionScopes(of: "MeshSessionStorageScope", in: source).count == 1,
                    "the type-prefixed scanner missed: \(source)")
            #expect(typePrefixedProductionScopes(of: "MeshRoutedStorageScope", in: source).isEmpty,
                    "the routed scanner read the session scope's spelling: \(source)")
        }
        let neither = [
            "index: index, at: now, capacity: .production, directoryFileCount: 0",
            "let inputs = CryptoFormatCensus.Inputs.production(for: store)",
            "let scope = host?.production(for: namespace, directory: root, installBinding: binding)"
        ]
        // R2: bounded by the fixed list.
        for source in neither {
            #expect(shorthandProductionScopes(in: source).isEmpty
                    && typePrefixedProductionScopes(of: "MeshSessionStorageScope", in: source).isEmpty,
                    "a production scanner misread: \(source)")
        }
    }

    // MARK: - The scratch-root needle

    /// One `ProximityHost` class a package file declares at file scope: its name, and what the top
    /// level of its body declares.
    struct HostDouble: Equatable, Sendable {
        /// The class's name.
        let name: String
        /// Whether its body declares `proximitySupportDirectory` (a `var` or a `let`) at its top level.
        let statesRoot: Bool
        /// Whether its body declares both `meshSessionStorage` and `meshRoutedStorage` at its top level.
        let statesBothScopes: Bool
    }

    /// Fewer host doubles than this and the reader is broken, or the test folder went dark, not the tree
    /// clean: the package's tests declare one, `PackageTestHost`, MEASURED at ProximityKit plan step
    /// A1.1.14 (2026-10-14).
    static let minimumHostDoubles = 1

    /// The doubles that state a root of their own without both scopes.
    static func unscopedRootedDoubles(_ doubles: [HostDouble]) -> [String] {
        doubles.filter { $0.statesRoot && !$0.statesBothScopes }.map(\.name)
    }

    /// Every class declared at file scope in `code` (lexed: comments dropped, literals emptied) whose
    /// inheritance clause names `ProximityHost`, with what the top level of its body declares. A class
    /// nested in another declaration is not read, and neither is a declaration inside a member: a local
    /// in `init` states nothing about the double.
    static func hostDoubles(in code: String) throws -> [HostDouble] {
        let opener = try NSRegularExpression(
            pattern: #"(?<![A-Za-z0-9_])class\s+([A-Za-z_]\w*)\s*:([^{]*)\{"#)
        let conformance = try NSRegularExpression(
            pattern: #"(?<![A-Za-z0-9_])ProximityHost(?![A-Za-z0-9_])"#)
        var doubles: [HostDouble] = []
        // R2: bounded by the class declarations in one file.
        for match in opener.matches(in: code, range: NSRange(code.startIndex..., in: code)) {
            guard let whole = Range(match.range, in: code), let name = Range(match.range(at: 1), in: code),
                  let inherited = Range(match.range(at: 2), in: code) else { continue }
            let clause = String(code[inherited])
            let conforms = conformance.firstMatch(in: clause, range: NSRange(clause.startIndex..., in: clause)) != nil
            guard conforms, braceDepth(before: whole.lowerBound, in: code) == 0 else { continue }
            let body = topLevelBody(openingAt: code.index(before: whole.upperBound), in: code)
            let root = try declares("proximitySupportDirectory", in: body)
            let session = try declares("meshSessionStorage", in: body)
            let routed = try declares("meshRoutedStorage", in: body)
            doubles.append(HostDouble(name: String(code[name]), statesRoot: root, statesBothScopes: session && routed))
        }
        return doubles
    }

    /// How many braces are open at `index` in `code`: 0 at file scope.
    static func braceDepth(before index: String.Index, in code: String) -> Int {
        code[..<index].reduce(0) { depth, character in
            character == "{" ? depth + 1 : (character == "}" ? depth - 1 : depth)
        }
    }

    /// The text directly inside the brace pair that opens at `open` in `code`, every nested pair's
    /// contents left out; whatever was read when the pair never closes.
    static func topLevelBody(openingAt open: String.Index, in code: String) -> String {
        var depth = 0
        var text = ""
        var index = open
        // R2: bounded by the remaining characters of a finite string.
        while index < code.endIndex {
            let character = code[index]
            if character == "{" {
                depth += 1
            } else if character == "}" {
                depth -= 1
                if depth == 0 { return text }
            } else if depth == 1 {
                text.append(character)
            }
            index = code.index(after: index)
        }
        return text
    }

    /// Whether `body` declares `name` with `var` or `let`, as a whole identifier.
    static func declares(_ name: String, in body: String) throws -> Bool {
        let declaration = try NSRegularExpression(
            pattern: #"(?<![A-Za-z0-9_])(?:var|let)\s+"# + name + #"(?![A-Za-z0-9_])"#)
        return declaration.firstMatch(in: body, range: NSRange(body.startIndex..., in: body)) != nil
    }

    /// The scratch-root needle's reader and rule, both ways: a double stating a root and both scopes
    /// passes, and one stating a root alone is refused, its scopes declared only as locals in a member; a
    /// double stating no root is read and not refused; and a class that is no host, a class nested in
    /// another declaration, and one in a comment or a string literal are not read.
    private static func expectTheScratchRootReaderFixtured() throws {
        let read = try hostDoubles(in: SwiftSourceLexer.lex("""
            private final class Scoped: ProximityHost {
                let proximitySupportDirectory: URL
                let meshSessionStorage: MeshSessionStorageScope
                var meshRoutedStorage: MeshRoutedStorageScope { routed }
            }
            final class Bare: ProximityHost {
                let proximitySupportDirectory = uniqueProximityDirectory()
                init() { let meshSessionStorage = 1; let meshRoutedStorage = 2 }
            }
            final class Unrooted: ProximityHost {
                var proximityDisplayName: String { "Golden" }
            }
            final class NotAHost: NSObject { let proximitySupportDirectory = root }
            struct Outer {
                final class Nested: ProximityHost { let proximitySupportDirectory = root }
            }
            // final class Commented: ProximityHost { let proximitySupportDirectory = root }
            let quoted = "final class Quoted: ProximityHost { let proximitySupportDirectory = root }"
            """).code)
        #expect(read == [
            HostDouble(name: "Scoped", statesRoot: true, statesBothScopes: true),
            HostDouble(name: "Bare", statesRoot: true, statesBothScopes: false),
            HostDouble(name: "Unrooted", statesRoot: false, statesBothScopes: false)
        ], "read the host doubles as \(read)")
        #expect(unscopedRootedDoubles(read) == ["Bare"], "the rule refused \(unscopedRootedDoubles(read))")
    }

    // MARK: - ML5

    /// ML5's package half: one of ProximityKit's two `unowned` host holders built over a host expression
    /// that is itself a call. `MeshNetworkManager(store: makeHost(), …)` and
    /// `ProximityPairSession(host: makeHost(), …)` trip; the same over a host held in a `let` pass.
    static let inlineHostPattern = #"MeshNetworkManager\(\s*store:\s*\w+\(|ProximityPairSession\(\s*host:\s*\w+\("#

    /// ML5's matcher over one source, as 1-based line numbers. Shared by the scan and its samples.
    static func inlineHostViolations(in source: String) -> [Int] {
        guard let regex = try? NSRegularExpression(pattern: inlineHostPattern, options: []) else { return [] }
        let range = NSRange(source.startIndex..., in: source)
        return regex.matches(in: source, options: [], range: range).compactMap { match in
            guard let matched = Range(match.range, in: source) else { return nil }
            return source[..<matched.lowerBound].components(separatedBy: "\n").count
        }
    }

    /// The inline-host matcher reads both holders built over a call and neither built over a held host.
    private static func expectTheInlineHostMatcherFixtured() {
        #expect(inlineHostViolations(in: "let bare = MeshNetworkManager(store: makeTestStore(), transport: t)\n") == [1],
                "ML5 missed a manager built over an inline host")
        #expect(inlineHostViolations(in: "let held = MeshNetworkManager(store: host)\n").isEmpty,
                "ML5 read a manager built over a held host")
        #expect(inlineHostViolations(in: "let pair = ProximityPairSession(host: makeHost(), profile: p)\n") == [1],
                "ML5 missed a pair session built over an inline host")
        #expect(inlineHostViolations(in: "let pair = ProximityPairSession(host: host, profile: p)\n").isEmpty,
                "ML5 read a pair session built over a held host")
    }

    // MARK: - The digest homes

    /// `source` with every whole-line comment removed, so the digest pin states something about code
    /// rather than about prose that names a digest.
    static func codeOnly(_ source: String) -> String {
        source
            .split(separator: "\n", omittingEmptySubsequences: false)
            .filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("//") }
            .joined(separator: "\n")
    }

    /// The file names in which `needle` occurs, one entry per occurrence.
    static func homes(of needle: String, in sources: [(name: String, code: String)]) -> [String] {
        var homes: [String] = []
        // R2: bounded by the file list.
        for source in sources {
            let count = source.code.components(separatedBy: needle).count - 1
            homes.append(contentsOf: Array(repeating: source.name, count: count))
        }
        return homes
    }
}
