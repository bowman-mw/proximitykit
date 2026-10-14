// PackageTestHygieneTests.swift
// ProximityKitTests
//
// ProximityKit plan step A1.1: the hygiene of ProximityKit's own package tests, held in those tests so it
// travels with the package. The bundle is unhosted (the simulator's `xctest` agent, or `swift test` on a
// Mac): no keychain entitlement and no app, so its test support installs an in-memory keychain store and
// an audit sink of its own on first touch (TestSupport/PackageTestEnvironment.swift). What it still cannot
// serve compiles clean and fails only where it runs, or passes having reached the developer's own Mac: a
// keychain call made before that store is installed, a store's production scope, a production or
// process-shared location, a path of a host repository. This suite reads every Swift file of the target
// as text, through `PackageRoot` and the package's walker (TestSupport/PackageSwiftFiles.swift), and holds
// four rules, the readers of each fixtured both ways:
//
//   I9   no file reaches what the bundle cannot serve: a needle stands only on an allowlist row, a
//        keychain needle only in a listed keychain file that keeps its kind's structure, and a wall file
//        (this one first) is read as code, so the needles it holds as data are not refused;
//   I11  every module a file imports travels with the package;
//   the target's own inventory, ProximityKitTests.tsv beside the target's folder under the package
//        root's `Tests`, is the tree: each suite's file and its declared tests (I1, I2, I4, I7), the
//        table CI's test-count floor reads;
//   and nothing extends `ProximityHost`, whose thirteen requirements `PackageTestHost` states itself.
//
// In the Fernlet repository, Fernlet's selector wall (`CIGateSelectorBoundaryTests`) holds its own rows
// of this target to this inventory, and keeps what is Fernlet's: which CI line runs which suite.

import Foundation
import Testing

/// ProximityKit's package tests reach nothing their unhosted bundle cannot serve, import only what
/// travels with the package, are exactly the suites and declared tests of their own inventory, and extend
/// no `ProximityHost`: six cells, two of them the readers' samples.
@Suite struct PackageTestHygieneTests {

    // MARK: - The cells

    /// **I9.** No package file reaches what the unhosted bundle cannot serve (``packageHazardProblems(in:)``),
    /// over every Swift file of the target at the walk's floor.
    @Test func nothingInThePackageTestsReachesWhatTheUnhostedBundleCannotServe() throws {
        let files = try PackageSwiftFiles.tests()
        #expect(files.count >= PackageSwiftFiles.testFloor, """
            I9 read \(files.count) Swift files under \(PackageSwiftFiles.testFolder), below its floor \
            \(PackageSwiftFiles.testFloor): the walk is broken, not the tree clean
            """)
        let problems = Self.packageHazardProblems(in: files)
        #expect(problems.isEmpty, """
            I9, what the unhosted bundle cannot serve — the package's tests and their rule disagree; edit the \
            row or the file in the same commit, never the rule to fit the file:
            \(problems.joined(separator: "\n"))
            """)
    }

    /// I9's readers read their samples: the needle reader holds a keychain type however it is constructed
    /// or reached, a seal key's wipe, a raw `SecItem` call but not a status that spells it inside its name,
    /// and every platform directory but the temporary ones; the structure reader passes a keychain file
    /// that keeps its kind's structure and names each way one breaks it; and a wall file's literal is
    /// data while the same needle in its code is read.
    @Test func theHazardReadersReadTheirSamples() {
        Self.expectTheNeedleReaderFixtured()
        Self.expectTheSuiteKeychainFileReaderFixtured()
        Self.expectTheInstallerAndSupportTypeReadersFixtured()
        let literal = PackageSwiftFiles.File(path: "W.swift", text: "let sample = \"_ = UserDefaults.standard\"\n")
        let literalProblems = Self.wallFileProblems(literal, invariant: "")
        #expect(literalProblems.isEmpty, "a wall file's literal was read as code: \(literalProblems)")
        let code = PackageSwiftFiles.File(path: "W.swift", text: "func f() { _ = UserDefaults.standard }\n")
        let codeProblems = Self.wallFileProblems(code, invariant: "")
        #expect(codeProblems.contains { $0.contains("(a wall file, read as code)") },
                "a wall file's code needle was not read: \(codeProblems)")
        let quiet = PackageSwiftFiles.File(path: "W.swift", text: "let x = 1\n")
        #expect(Self.wallFileProblems(quiet, invariant: "").contains { $0.contains("spells no needle in its text") },
                "a wall file that spells no needle was not named")
    }

    /// **I11.** Every module a package file imports (``importedModules(in:)``, read over its code) is in
    /// ``packageImportAllowlist``, or, for ``packageSecurityImportFile``, in ``packageSecurityImports``,
    /// over every Swift file of the target at the walk's floor, the reader held to its samples first.
    @Test func everyPackageTestImportTravelsWithThePackage() throws {
        Self.expectTheImportReaderFixtured()
        let files = try PackageSwiftFiles.tests()
        #expect(files.count >= PackageSwiftFiles.testFloor, """
            I11 read \(files.count) Swift files under \(PackageSwiftFiles.testFolder), below its floor \
            \(PackageSwiftFiles.testFloor): the walk is broken, not the tree clean
            """)
        let problems = Self.packageImportProblems(in: files)
        #expect(problems.isEmpty, """
            I11, the package's imports — a file imports a module that does not travel with ProximityKit's \
            tests; drop the import, never widen the allowlist to fit the file:
            \(problems.joined(separator: "\n"))
            """)
    }

    /// **The inventory is the tree.** ``inventoryFile`` reads as a header and three-field rows sorted by
    /// suite (I1), holds ``measuredInventoryRows`` rows (I2), each suite declared at column 0 in exactly
    /// its row's file (I4), and each row's declared tests, summed over every file of the target, are its
    /// cells, every tested type is a row, no test counts toward no type, no `@Test` is free at column 0,
    /// and the rows sum to ``measuredDeclaredTests`` (I7). It is count conservation's static half for the
    /// package: a suite lost, doubled or moved, or a test dropped, is red here before anything runs.
    @Test func theInventoryIsTheTree() throws {
        let files = try PackageSwiftFiles.tests()
        #expect(files.count >= PackageSwiftFiles.testFloor, """
            the inventory's walk read \(files.count) Swift files under \(PackageSwiftFiles.testFolder), below \
            its floor \(PackageSwiftFiles.testFloor): the walk is broken, not the tree clean
            """)
        let text = try String(contentsOf: PackageRoot.url("Tests").appendingPathComponent(Self.inventoryFile),
                              encoding: .utf8)
        let read = Self.inventory(in: text)
        var problems = read.problems.map { "I1: " + $0 }
        if read.rows.count != Self.measuredInventoryRows {
            problems.append("""
                I2: \(Self.inventoryFile) holds \(read.rows.count) rows; \(Self.measuredInventoryRows) were \
                measured. A row deleted is a suite leaving CI's sight; a suite added or moved changes \
                measuredInventoryRows in the same commit, argued and measured
                """)
        }
        problems += Self.inventoryHomeProblems(read.rows, files: files)
        problems += Self.declaredTestProblems(read.rows, files: files)
        #expect(problems.isEmpty, """
            the package's inventory (\(Self.inventoryFile)) and the tree disagree; edit the row in the same \
            commit as the suite, never the tree to fit the row:
            \(problems.joined(separator: "\n"))
            """)
    }

    /// The inventory's readers read their samples: the declared-test reader counts every `@Test` token
    /// toward its type and none in a comment, a literal or a multi-line literal; the free-test reader finds
    /// a column-0 `@Test` and no suite's declaration; the declaration reader names a column-0 type past its
    /// attributes and modifiers and no nested, commented or file-scoped one; and the inventory reader keeps
    /// a good row and reports a short one.
    @Test func theInventoryReadersReadTheirSamples() {
        Self.expectTheDeclarationReaderFixtured()
        Self.expectTheDeclaredTestReaderFixtured()
        Self.expectTheLiteralAndFreeTestReadersFixtured()
        Self.expectTheInventoryReaderFixtured()
    }

    /// **`ProximityHost` is extended nowhere.** No package file's lexed code holds an extension of
    /// `ProximityHost` (``hostExtensionPattern``), over every Swift file of the target at the walk's floor,
    /// the matcher held to its samples and neighbours first. `PackageTestHost` states all thirteen
    /// requirements itself, so no default here can stand in for one a cell never states; a host's own tests
    /// declare their defaults in an extension in their own target.
    @Test func nothingInThePackageTestsExtendsProximityHost() throws {
        Self.expectTheHostExtensionReaderFixtured()
        let files = try PackageSwiftFiles.tests()
        #expect(files.count >= PackageSwiftFiles.testFloor, """
            the ProximityHost cell read \(files.count) Swift files under \(PackageSwiftFiles.testFolder), below \
            its floor \(PackageSwiftFiles.testFloor): the walk is broken, not the tree clean
            """)
        var found: [String] = []
        // R2: bounded by the package's file count × each file's matches.
        for file in files {
            for line in Self.matchLines(Self.hostExtensionPattern, in: SwiftSourceLexer.lex(file.text).code) {
                found.append("""
                    \(file.path):\(line) extends `ProximityHost`: PackageTestHost states all thirteen requirements \
                    itself, so no default in the package's tests may stand in for one a cell never states (a host's \
                    own tests declare their defaults in their own target)
                    """)
            }
        }
        #expect(found.isEmpty, "\(found.joined(separator: "\n"))")
    }

    // MARK: - I9: what the unhosted bundle cannot serve

    /// What ProximityKit's unhosted package test bundle cannot serve, by needle, each with its reason
    /// (rule I9). Matched as a substring of every code line of every Swift file of the target
    /// (``packageHazardNeedles(onLine:)``), but for ``packageIdentifierStartNeedles``, read only where an
    /// identifier starts. The keychain needles name the keychain calls themselves (`SecItem`,
    /// `KeychainItem`), the statics known to call one directly, and the types whose construction or statics
    /// reach one, each type by its bare name, so `Type(`, `Type.init(`, `let x: Type = .init(` and its
    /// statics are all held, the two seal keys' `wipe(service:)` among them (``packageKeychainNeedles``).
    /// The bundle's keychain is an in-memory store its installer (`TestSupport/PackageTestEnvironment.swift`)
    /// puts behind ProximityKit's keychain funnel on first touch, so what the keychain needles hold is a
    /// call made before anything touched it, which reaches the system keychain instead. A keychain needle
    /// stands only in a file on ``packageKeychainFiles`` (or on a ``packageHazardAllowlist`` row), each
    /// listed file held to the structure its kind names, which keeps its every keychain line behind a read
    /// of the installer (``packageKeychainFileProblems(_:source:)``); and a raw `SecItem` call stands in no
    /// file, listed or not, since it bypasses the funnel the store answers. It is a needle list, not a
    /// call-graph closure: a path it misses fails with -34018 on the simulator only where the failure
    /// surfaces, and a delete through `ProximityKeychainItem.deleteAll` only audits its failure, which no
    /// cell sees unless it captures that line, so it passes silently. There is no audit needle: the bundle
    /// installs its own sink (`PackageTestEnvironment.audit`), and every `PackageAuditCapture` registers
    /// with it as it is built, so no capture reads before the sink is installed. The location needles are
    /// every platform directory the platform wall holds ProximityKit's code to
    /// (`ProximityPlatformNeutralityTests.directoryNeedles`) but the temporary ones, which are scratch a
    /// test may use, and the process-shared defaults and main bundle. A file on ``packageWallFiles`` is read
    /// as code: the needles it holds in its literals are a wall's data.
    static let packageHazards: [(needle: String, reason: String)] = {
        let keychain = """
            the bundle's keychain is the in-memory store PackageTestEnvironment installs on first touch, \
            and a call made before anything touched it reaches the system keychain: on the simulator it \
            answers every call errSecMissingEntitlement (-34018), and on a Mac a package test must not reach \
            it whatever it answers (Apple's TN3137 gives -34018 for a process without keychain \
            entitlements). A line that reaches the keychain stands only in a file on packageKeychainFiles, \
            whose kind keeps it behind a read of PackageTestEnvironment.keychain, and a raw SecItem call \
            stands nowhere
            """
        let stores = """
            a store seals its files under a seal key it reads from the keychain, so it needs an allowlist \
            row whose invariant says what reads PackageTestEnvironment.keychain first, and writes them \
            under its scope's directory, which this target's PackageTestTreeWallTests holds to a scope of \
            the test's own, never the production one
            """
        let location = "a production or process-shared location; on an unsandboxed Mac, the developer's own"
        let repo = """
            a package test reads a file through PackageRoot (TestSupport/PackageRoot.swift), whose markers \
            hold in both repositories, by a path relative to the package root: RepoRoot and a host \
            repository's paths do not travel with the package, a path computed from a source file's \
            own location breaks when a layout moves, and a relative path read from the unhosted agent \
            has no defined base
            """
        let storeNeedles = ["MeshRoutedStore", "MeshSessionStore", ".production("]
        let scratch: Set<String> = ["temporaryDirectory", "NSTemporaryDirectory"]
        let locationNeedles = ProximityPlatformNeutralityTests.directoryNeedles.map(\.token)
            .filter { !scratch.contains($0) } + ["UserDefaults", "Bundle.main"]
        let repoNeedles = ["RepoRoot", "#filePath", "\"App/", "\"Docs/", "\"Tests/", "\".github/",
                           "\"FernletKit/", "\"Scripts/"]
        return packageKeychainNeedles.map { (needle: $0, reason: keychain) }
            + storeNeedles.map { (needle: $0, reason: stores) }
            + locationNeedles.map { (needle: $0, reason: location) }
            + repoNeedles.map { (needle: $0, reason: repo) }
    }()

    /// The keychain needles of ``packageHazards`` (rule I9): the keychain calls themselves, the statics
    /// known to call one directly, and the types whose construction or statics reach one.
    static let packageKeychainNeedles = [
        "SecItem", "KeychainItem", "ensureProvisioned(", "IdentityService", "DeviceBindingID", "StoragePreferences",
        "ColumnCrypto", "ProtectedSidecar", ".forSeal(", ".forOpen(", "wipeForDeleteAll(", "MeshSessionSealKey",
        "MeshRoutedSealKey", "MeshNetworkManager", "ProximityPairSession", "ProximityCoordinator"
    ]

    /// The needles rule I9 reads only where an identifier starts: `SecItem`, so a Security status that holds
    /// it inside its own name (`errSecItemNotFound`) is no keychain call, while every raw `SecItem…` call is
    /// one. It stands in no package file, a file on ``packageKeychainFiles`` included: a raw call bypasses
    /// ProximityKit's keychain funnel, so the bundle's in-memory store never answers it.
    static let packageIdentifierStartNeedles: Set<String> = ["SecItem"]

    /// How a file on ``packageKeychainFiles`` keeps every one of its keychain lines behind a read of
    /// `PackageTestEnvironment.keychain` (rule I9): each kind is a structure
    /// ``packageKeychainFileProblems(_:source:)`` checks, so a file that loses it fails.
    enum PackageKeychainFileKind: Equatable, Sendable {
        /// A suite file: every keychain line sits in a `@Suite` type whose first stored property reads
        /// a ready marker (``packageKeychainReadyMarkers``), which Swift Testing evaluates as it builds
        /// the suite instance for each cell, before the cell runs; and the file runs nothing without an
        /// instance: no static or free test, no test arguments or traits on a test or a suite, no static
        /// or global stored property with an initializer, and no keychain line in a static member that
        /// is not `private`.
        case suite
        /// The installer: every keychain line sits in the initializer of its `static let keychain`,
        /// which is the read.
        case installer
        /// A support type's file: every keychain line sits in an instance member of the named type,
        /// never in a static member or a stored property's initializer, and every initializer of the
        /// type reads `PackageTestEnvironment.keychain` in its first statement.
        case readsFirst(type: String)
    }

    /// One file a keychain needle may stand in (rule I9): the file, the structure that keeps its keychain
    /// lines behind the installer, and the invariant a reviewer checks the file against.
    struct PackageKeychainFile: Sendable {
        /// The file, by its path under the test target's folder.
        let file: String
        /// The structure it keeps.
        let kind: PackageKeychainFileKind
        /// Why its keychain lines reach the in-memory store, never the system keychain.
        let invariant: String
    }

    /// What a ``PackageKeychainFileKind/suite`` file's first stored property reads (rule I9): the
    /// installer itself, or a package test host, whose initializer reads it first.
    static let packageKeychainReadyMarkers = ["PackageTestEnvironment.keychain", "PackageTestHost("]

    /// The invariant every ``PackageKeychainFileKind/suite`` file keeps (rule I9).
    static let packageKeychainSuiteInvariant = """
        every keychain line of the file sits in a @Suite type whose first stored property reads \
        PackageTestEnvironment.keychain, or builds a PackageTestHost, whose initializer reads it first, and \
        Swift Testing evaluates that property as it builds the suite instance for each cell, before the cell \
        runs; and nothing in the file runs without an instance (no static or free test, no test arguments or \
        traits, no static or global stored property with an initializer, no keychain line in a static member \
        another file could call): the installer has put the in-memory store behind ProximityKit's keychain \
        funnel before the line runs, so a call on it reaches the store, never the system keychain
        """

    /// The files a keychain needle may stand in (rule I9, ProximityKit plan step A1.1.10): one row per
    /// file, each with the structure its kind names, which the rule checks, and the rule fails a listed
    /// file that is gone or holds no keychain line.
    static let packageKeychainFiles: [PackageKeychainFile] = [
        PackageKeychainFile(
            file: "TestSupport/PackageTestEnvironment.swift", kind: .installer,
            invariant: """
                the bundle's installer: its one keychain line installs the in-memory store it has just built as \
                ProximityKit's keychain backend, inside the initializer of `static let keychain`, which the \
                runtime runs once, as PackageTestEnvironment.keychain is first read, and makes no keychain call \
                itself, so every keychain call after it reaches the store
                """),
        PackageKeychainFile(
            file: "TestSupport/PackageTestHost.swift",
            kind: .readsFirst(type: "PackageTestHost"),
            invariant: """
                every initializer of PackageTestHost reads PackageTestEnvironment.keychain first and every \
                keychain line of the file sits in one of its instance members, so none runs before a host \
                exists and the in-memory store is ProximityKit's keychain backend: the identity the host builds \
                on its own .test. service reaches the store, never the system keychain; \
                IdentityService.fingerprint(of:) is a pure function of a key's bytes, and a declaration only \
                names the type
                """),
        PackageKeychainFile(
            file: "PackageKeychainStoreTests.swift", kind: .suite,
            invariant: packageKeychainSuiteInvariant),
        PackageKeychainFile(
            file: "PackageTestHostTests.swift", kind: .suite,
            invariant: packageKeychainSuiteInvariant)
    ]

    /// The namespace wall (rule I9), whose lines that spell a keychain needle as data
    /// ``packageHazardAllowlist`` lists under ``packageNamespaceWallInvariant``.
    static let packageNamespaceWallFile = "ProximityNamespaceBoundaryTests.swift"

    /// What makes every line of ``packageNamespaceWallLines`` safe in the unhosted bundle.
    static let packageNamespaceWallInvariant = """
        the line is data the namespace wall reads as text and never runs: string literals holding a line \
        of ProximityKit-shaped source, which the wall lexes and holds a matcher to missing (a neighbour of \
        rule 4's domain-type matcher or of rule 6's moved-type matcher), or the names of types rule 6's \
        matcher must find declared in ProximityKit's sources (its floor); nothing on it names, builds or \
        calls a type in code, so it reaches no keychain
        """

    /// The namespace wall's lines that spell a keychain needle inside a literal, each exact as trimmed
    /// (rule I9).
    static let packageNamespaceWallLines = [
        #""func beginSession(role: ProximityCoordinator.Role, mode: ProximityCoordinator.Mode, localFingerprint: String)","#,
        #""public final class ProximityCoordinator {","#,
        #""IdentityService", "ProximityHost", "ProximityPrekeyBundle", "PresenceAdvertisement", "ProtectedSidecar""#
    ]

    /// The package's platform wall (rule I9), whose lines that spell a keychain or location needle as data
    /// ``packageHazardAllowlist`` lists under ``packagePlatformWallInvariant``.
    static let packagePlatformWallFile = "ProximityPlatformNeutralityTests.swift"

    /// What makes every line of ``packagePlatformWallLines`` safe in the unhosted bundle.
    static let packagePlatformWallInvariant = """
        the needle stands only inside a literal the platform wall reads as text and never runs: a \
        needle's spelling that its third rule matches in ProximityKit's lexed code (a Foundation API for a \
        platform directory), a line of ProximityKit-shaped source its token readers are fixtured on, a \
        failure message, or the package-relative path of a ProximityKit file a seam row or a \
        channel-ready door names, which the wall reads as text through PackageRoot; the code around it \
        only builds needles, rows and doors and lexes or matches text, so the line reaches no keychain \
        and reads, writes and creates nothing at any location
        """

    /// The platform wall's lines that spell a keychain or location needle inside a literal, each exact
    /// as trimmed (rule I9).
    static let packagePlatformWallLines = [
        #"SeamRow(path: "HeartSharing/ProtectedSidecar.swift", module: "UIKit","#,
        #".identifier("applicationSupportDirectory"), .identifier("documentDirectory"),"#,
        #".identifier("documentsDirectory"), .identifier("cachesDirectory"), .identifier("libraryDirectory"),"#,
        #".identifier("temporaryDirectory"), .identifier("NSTemporaryDirectory"), .identifier("NSHomeDirectory"),"#,
        #".identifier("NSHomeDirectoryForUser"), .identifier("homeDirectory"), .identifier("homeDirectoryForCurrentUser"),"#,
        #".identifier("NSSearchPathForDirectoriesInDomains"), .identifier("downloadsDirectory"),"#,
        #".identifier("desktopDirectory"), .identifier("sharedPublicDirectory"), .identifier("applicationDirectory"),"#,
        #".identifier("userDirectory"), .identifier("moviesDirectory"), .identifier("musicDirectory"),"#,
        #".identifier("picturesDirectory"), .identifier("trashDirectory"), .identifier("currentDirectory"),"#,
        #".identifier("currentDirectoryPath"), .identifier("containerURL"),"#,
        #"let lookup = lexedCode("_ = FileManager.default.urls(for: .cachesDirectory, in: mask)\n")"#,
        #"#expect(try mentions(of: .call("url", label: "for"), in: lookup) == 0, "urls(for: read as url(for:")"#,
        #"#expect(try mentions(of: .call("URL", label: "for"), in: lookup) == 0, "urls(for: read as URL(for:")"#,
        #"#expect(try mentions(of: .call("urls", label: "for"), in: lookup) == 1, "urls(for: was not read")"#,
        #"let ubiquity = lexedCode("_ = FileManager.default.url(forUbiquityContainerIdentifier: nil)\n")"#,
        #""url(forUbiquityContainerIdentifier: read as url(for:")"#,
        #"Door(path: "Sources/ProximityKit/Mesh/MeshNetworkManager.swift","#,
        #"Door(path: "Sources/ProximityKit/PairSession/ProximityPairSession.swift","#
    ]

    /// The package lines a ``packageHazards`` needle may stand on (rule I9): the file, the line's exact
    /// trimmed text, and the invariant that makes it safe. A row is added only with an invariant a reviewer
    /// can check against the line it names, and a row whose line is gone or changed is a failure, so no row
    /// outlives the line it excuses. 23 rows since ProximityKit plan step A1.1.10, when the per-file rule
    /// (``packageKeychainFiles``) replaced the per-line rows of the files that reach the keychain; moved here
    /// at A1.1.13. The rows spell a needle the per-file rule does not cover: the soundness suite's
    /// storage cell, which reads `URL.applicationSupportDirectory` as a value; the package's file locator's
    /// one read of its own source's path; and the namespace and platform walls' needles inside literals
    /// (``packageNamespaceWallLines``, ``packagePlatformWallLines``), each set under one invariant.
    static let packageHazardAllowlist: [(file: String, line: String, invariant: String)] = [
        (file: "ProximityNamespaceSoundnessTests.swift",
         line: "for base in [URL.applicationSupportDirectory, scratch] {",
         invariant: """
            anInstallationsFolderIsItsNameUnderTheBaseItsHostPicks builds a URL value under each base \
            with Storage.directory(under:) and compares it; nothing is read, written or created there
            """),
        (file: "TestSupport/PackageRoot.swift",
         line: "let origin = URL(fileURLWithPath: #filePath)",
         invariant: """
            PackageRoot only locates the package root: from its own source's path it walks up to the \
            first folder holding Package.swift and Sources/ProximityKit, reading, writing and creating \
            nothing; a package suite reads only Package.swift, Sources/ProximityKit/** and Tests/** \
            under that root, by a path relative to it
            """)
    ] + packageNamespaceWallLines.map {
        (file: packageNamespaceWallFile, line: $0, invariant: packageNamespaceWallInvariant)
    } + packagePlatformWallLines.map {
        (file: packagePlatformWallFile, line: $0, invariant: packagePlatformWallInvariant)
    }

    /// The wall files rule I9 reads as code (ProximityKit plan step A1.1.13): a wall's file holds the
    /// needles it reads, their reasons and its fixtures as data in literals, which a line-by-line read of
    /// its text would refuse. So I9 reads a listed file's lexed code (`SwiftSourceLexer`: comments dropped,
    /// literals emptied), each line against every needle, and refuses a needle there as anywhere; no
    /// allowlist row and no keychain structure applies to it. A listed file that is gone, or that spells no
    /// needle in its text and so needs no exemption, is a failure, and so is a file on both this list and
    /// ``packageKeychainFiles``. The repository-path needles carry a quote, so they never match lexed code:
    /// a wall file may spell a path in a literal, which it reads through `PackageRoot`.
    static let packageWallFiles: [(file: String, invariant: String)] = [
        (file: "PackageTestHygieneTests.swift",
         invariant: """
            rule I9's own file: its needles, reasons, allowlist rows and fixtures, and rule I11's and the \
            inventory readers' fixtures, are data in literals it reads as text and never runs; I9 reads its \
            code, comments dropped and literals emptied, and refuses a needle there as anywhere
            """),
        (file: "PackageTestTreeWallTests.swift",
         invariant: """
            the tree walls' own file: the stores, scopes, production directories and services, inline \
            hosts and audit installs its matchers and samples spell are data in literals it reads as text \
            and never runs; I9 reads its code, comments dropped and literals emptied, and refuses a needle \
            there as anywhere
            """),
        (file: "ProximitySourceWallTests.swift",
         invariant: """
            the source walls' own file: the keychain writes, accessibility classes, identity \
            constructions, launch-hook reads, primitive calls and escape-hatch markers its matcher samples \
            spell are data in literals it reads as text and never runs, and it reads ProximityKit's sources \
            only as text through the walls' walker and lexer; I9 reads its code, comments dropped and \
            literals emptied, and refuses a needle there as anywhere
            """),
        (file: "ProximityMemoryLifecycleTests.swift",
         invariant: """
            the memory-lifecycle wall's own file: the managers, observers and task spellings its messages \
            and matcher samples name are data in literals it reads as text and never runs, and it reads \
            ProximityKit's sources only as text through the walls' walker; I9 reads its code, comments \
            dropped and literals emptied, and refuses a needle there as anywhere
            """)
    ]

    /// I9: no package file's code line (trimmed text not starting `//`) holds a ``packageHazards`` needle,
    /// except a ``packageHazardAllowlist`` row's exact line and a keychain needle in a file on
    /// ``packageKeychainFiles`` that keeps its kind's structure (``packageKeychainFileProblems(_:source:)``);
    /// a ``packageIdentifierStartNeedles`` needle (a raw `SecItem` call) stands in no file, listed or not; a
    /// file on ``packageWallFiles`` holds no needle in its lexed code (``wallFileProblems(_:invariant:)``);
    /// every allowlist row still matches a line; every listed keychain or wall file still exists; and no
    /// file is on both lists.
    static func packageHazardProblems(in files: [PackageSwiftFiles.File]) -> [String] {
        let paths = Set(files.map(\.path))
        var problems: [String] = []
        // R2: bounded by the keychain file list.
        for listed in packageKeychainFiles where !paths.contains(listed.file) {
            problems.append("I9: \(listed.file), a file on packageKeychainFiles, is gone; delete its row with its invariant (\(listed.invariant))")
        }
        // R2: bounded by the wall file list.
        for wall in packageWallFiles {
            if !paths.contains(wall.file) {
                problems.append("I9: \(wall.file), a file on packageWallFiles, is gone; delete its row with its invariant (\(wall.invariant))")
            }
            if packageKeychainFiles.contains(where: { $0.file == wall.file }) {
                problems.append("I9: \(wall.file) is on both packageKeychainFiles and packageWallFiles")
            }
        }
        var allowed: Set<Int> = []
        // R2: bounded by the package's file count.
        for file in files {
            if let wall = packageWallFiles.first(where: { $0.file == file.path }) {
                problems += wallFileProblems(file, invariant: wall.invariant)
                continue
            }
            let read = ordinaryFileProblems(file)
            allowed.formUnion(read.allowed)
            problems += read.problems
        }
        // R2: bounded by the allowlist.
        for (index, row) in packageHazardAllowlist.enumerated() where !allowed.contains(index) {
            problems.append("I9: the allowlist row \(row.file), `\(row.line)` matches no line; delete it with its invariant (\(row.invariant))")
        }
        return problems
    }

    /// One file's I9 problems when it is on no wall list: every code line's needles but an allowlist row's
    /// line and, in a file on ``packageKeychainFiles``, its keychain needles, which its kind's structure
    /// holds instead; and the indices of the allowlist rows its lines matched.
    static func ordinaryFileProblems(_ file: PackageSwiftFiles.File) -> (problems: [String], allowed: Set<Int>) {
        var problems: [String] = []
        var allowed: Set<Int> = []
        let listed = packageKeychainFiles.first { $0.file == file.path }
        // R2: bounded by the file's line count × the needle list.
        for line in file.text.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.hasPrefix("//") else { continue }
            if let row = packageHazardAllowlist.firstIndex(where: { $0.file == file.path && $0.line == trimmed }) {
                allowed.insert(row)
                continue
            }
            for hazard in packageHazardNeedles(onLine: trimmed)
            where listed == nil || !isListedKeychainNeedle(hazard.needle) {
                problems.append("I9: \(file.path): `\(trimmed)` holds `\(hazard.needle)`: \(hazard.reason)")
            }
        }
        if let listed {
            problems += packageKeychainFileProblems(listed, source: file.text)
        }
        return (problems, allowed)
    }

    /// One wall file's I9 problems (``packageWallFiles``): every line of its lexed code (comments dropped,
    /// literals emptied) holds no needle, and its text spells at least one, or it needs no exemption.
    static func wallFileProblems(_ file: PackageSwiftFiles.File, invariant: String) -> [String] {
        var problems: [String] = []
        // R2: bounded by the file's line count × the needle list.
        for line in SwiftSourceLexer.lex(file.text).code.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            for hazard in packageHazardNeedles(onLine: trimmed) {
                problems.append("I9: \(file.path) (a wall file, read as code): `\(trimmed)` holds `\(hazard.needle)`: \(hazard.reason)")
            }
        }
        let spells = file.text.components(separatedBy: "\n").contains { !packageHazardNeedles(onLine: $0).isEmpty }
        if !spells {
            problems.append("I9: \(file.path), a file on packageWallFiles, spells no needle in its text; delete its row with its invariant (\(invariant))")
        }
        return problems
    }

    /// The ``packageHazards`` a code line's text holds (rule I9): each as a substring, but each of
    /// ``packageIdentifierStartNeedles`` only where an identifier starts.
    static func packageHazardNeedles(onLine line: String) -> [(needle: String, reason: String)] {
        packageHazards.filter { hazard in
            packageIdentifierStartNeedles.contains(hazard.needle)
                ? startsAnIdentifier(hazard.needle, in: line) : line.contains(hazard.needle)
        }
    }

    /// Whether `needle` occurs in `line` with no identifier character (an ASCII letter or digit, or `_`)
    /// just before it.
    static func startsAnIdentifier(_ needle: String, in line: String) -> Bool {
        var rest = line[...]
        // R2: bounded by the line's length; each pass moves past one occurrence.
        while let found = rest.range(of: needle) {
            let preceded = found.lowerBound > line.startIndex
                && isIdentifierCharacter(line[line.index(before: found.lowerBound)])
            if !preceded { return true }
            rest = line[found.upperBound...]
        }
        return false
    }

    /// Whether `character` may stand inside a Swift identifier, as rule I9's readers spell one: an ASCII
    /// letter or digit, or `_`.
    private static func isIdentifierCharacter(_ character: Character) -> Bool {
        character == "_" || (character.isASCII && (character.isLetter || character.isNumber))
    }

    /// Whether `needle` may stand in a file on ``packageKeychainFiles`` (rule I9): a keychain needle that
    /// is not read only where an identifier starts, so a raw `SecItem` call stands in no file.
    static func isListedKeychainNeedle(_ needle: String) -> Bool {
        packageKeychainNeedles.contains(needle) && !packageIdentifierStartNeedles.contains(needle)
    }

    /// The 1-based code lines of `source` (trimmed text not starting `//`) that hold a keychain needle a
    /// file on ``packageKeychainFiles`` may hold, an allowlist row of `file` aside (rule I9).
    static func packageKeychainLines(in source: String, file: String) -> [Int] {
        var lines: [Int] = []
        // R2: bounded by the source's line count.
        for (offset, line) in source.components(separatedBy: "\n").enumerated() {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.hasPrefix("//"),
                  !packageHazardAllowlist.contains(where: { $0.file == file && $0.line == trimmed }) else { continue }
            if packageHazardNeedles(onLine: trimmed).contains(where: { isListedKeychainNeedle($0.needle) }) {
                lines.append(offset + 1)
            }
        }
        return lines
    }

    // MARK: - The structure a keychain file keeps (rule I9)

    /// One declaration rule I9's structure reader reads, over lexed code (`SwiftSourceLexer`: comments
    /// dropped, literals emptied, lines kept): a type at the top level, or one direct member of a type's
    /// body. Indices are 0-based lines.
    struct StructureDeclaration: Sendable {
        /// Its first line: an attribute on a line of its own, or the line its keyword stands on.
        let first: Int
        /// The line its keyword stands on.
        let head: Int
        /// Its last line: where the braces its head line opens close, or its head line when it opens none.
        let last: Int
        /// Its keyword (`struct`, `func`, `let`, `init`, …).
        let keyword: String
        /// Its first line through its last, joined: attributes, modifiers, signature and body.
        let text: String

        /// Its first line through its keyword's line, joined: what its attributes and modifiers say.
        let heading: String

        /// Whether it is a static member: `static`, or `class` before `func`, `var` or `subscript`.
        var isStatic: Bool {
            PackageTestHygieneTests.matchLines(#"(?<![A-Za-z0-9_.])(?:static|class\s+(?:func|var|subscript))(?![A-Za-z0-9_])"#,
                                               in: heading).isEmpty == false
        }

        /// Whether it is `private` or `fileprivate` (`private(set)` is a setter's access, not its own).
        var isPrivate: Bool {
            PackageTestHygieneTests.matchLines(#"(?<![A-Za-z0-9_])(?:private|fileprivate)(?![A-Za-z0-9_(])"#,
                                               in: heading).isEmpty == false
        }

        /// Whether it is a stored property: a `let` or `var` with an initializer before any brace, or with
        /// no brace at all.
        var isStoredProperty: Bool {
            guard keyword == "let" || keyword == "var" else { return false }
            let beforeBrace = text.prefix { $0 != "{" }
            return beforeBrace.contains("=") || !text.contains("{")
        }
    }

    /// The pattern a declaration's keyword line matches over its trimmed lexed text: attributes, then
    /// modifiers, then the keyword, captured.
    private static let declarationKeywordPattern = #"^(?:@[A-Za-z_][A-Za-z0-9_.]*(?:\([^)]*\))?\s+)*"#
        + #"(?:(?:public|internal|private|fileprivate|package|open|final|static|class|nonisolated|override|"#
        + #"mutating|nonmutating|lazy|weak|unowned|convenience|required|dynamic|indirect)(?:\([A-Za-z]+\))?\s+)*"#
        + #"(func|var|let|init|deinit|subscript|struct|class|enum|actor|protocol|extension|typealias|case)(?![A-Za-z0-9_])"#

    /// The keyword a lexed line declares with, or nil for a line that declares nothing.
    static func declarationKeyword(_ line: String) -> String? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard let regex = try? NSRegularExpression(pattern: declarationKeywordPattern) else { return nil }
        let text = trimmed as NSString
        guard let match = regex.firstMatch(in: trimmed, range: NSRange(location: 0, length: text.length)) else { return nil }
        return text.substring(with: match.range(at: 1))
    }

    /// Whether a lexed line holds attributes and nothing else (`@MainActor`, `@Suite`).
    private static func isAttributeOnly(_ line: String) -> Bool {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        return trimmed.hasPrefix("@") && !matchLines(#"^(?:@[A-Za-z_][A-Za-z0-9_.]*(?:\([^)]*\))?\s*)+$"#, in: trimmed).isEmpty
    }

    /// Each lexed line's brace depth at its start.
    static func braceDepths(of code: [String]) -> [Int] {
        var depths: [Int] = []
        var depth = 0
        // R2: bounded by the line count.
        for line in code {
            depths.append(depth)
            depth += line.filter { $0 == "{" }.count - line.filter { $0 == "}" }.count
        }
        return depths
    }

    /// The last line of the declaration whose keyword stands on `head`: where the first brace opened at
    /// or after it closes, or `head` when its line opens no brace.
    static func declarationEnd(from head: Int, in code: [String]) -> Int {
        guard code[head].contains("{") else { return head }
        var depth = 0
        // R2: bounded by the lines from `head` on.
        for index in head..<code.count {
            depth += code[index].filter { $0 == "{" }.count - code[index].filter { $0 == "}" }.count
            if depth <= 0 { return index }
        }
        return code.count - 1
    }

    /// The declarations among lexed `code`'s lines `range` that stand at brace depth `depth`, each from
    /// its attribute lines through its end, in order.
    static func structureDeclarations(in code: [String], range: Range<Int>, depth: Int) -> [StructureDeclaration] {
        let depths = braceDepths(of: code)
        var found: [StructureDeclaration] = []
        var pending: Int?
        // R2: bounded by the range.
        for index in range where depths[index] == depth {
            if isAttributeOnly(code[index]) {
                pending = pending ?? index
                continue
            }
            defer { pending = nil }
            guard let keyword = declarationKeyword(code[index]) else { continue }
            let first = pending ?? index
            let last = declarationEnd(from: index, in: code)
            found.append(StructureDeclaration(
                first: first, head: index, last: last, keyword: keyword,
                text: code[first...last].joined(separator: "\n"), heading: code[first...index].joined(separator: "\n")))
        }
        return found
    }

    /// The types lexed `code` declares at the top level, each with its name and whether a `@Suite`
    /// attribute marks it.
    static func topLevelTypes(in code: [String]) -> [(name: String, isSuite: Bool, declaration: StructureDeclaration)] {
        let types: Set<String> = ["struct", "class", "enum", "actor"]
        return structureDeclarations(in: code, range: 0..<code.count, depth: 0)
            .filter { types.contains($0.keyword) }
            .compactMap { type in
                let pattern = #"(?:struct|class|enum|actor)\s+([A-Za-z_][A-Za-z0-9_]*)"#
                guard let regex = try? NSRegularExpression(pattern: pattern) else { return nil }
                let head = code[type.head] as NSString
                guard let match = regex.firstMatch(in: code[type.head], range: NSRange(location: 0, length: head.length)) else {
                    return nil
                }
                let suite = !matchLines(#"@Suite(?![A-Za-z0-9_])"#, in: type.heading).isEmpty
                return (name: head.substring(with: match.range(at: 1)), isSuite: suite, declaration: type)
            }
    }

    /// The direct members of the type `type` declares in lexed `code`, in order.
    static func structureMembers(of type: StructureDeclaration, in code: [String]) -> [StructureDeclaration] {
        guard type.last > type.head else { return [] }
        let depth = braceDepths(of: code)[type.head] + 1
        return structureDeclarations(in: code, range: (type.head + 1)..<type.last, depth: depth)
    }

    /// The member among `members` whose lines hold 0-based `line`: the last one starting at or before it
    /// (the caller holds `line` inside the type the members belong to).
    static func owningMember(of line: Int, in members: [StructureDeclaration]) -> StructureDeclaration? {
        members.last { $0.first <= line }
    }

    /// The 1-based lines of `code` on which `pattern` matches, or `[-1]` when it does not compile.
    static func matchLines(_ pattern: String, in code: String) -> [Int] {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [-1] }
        let text = code as NSString
        return regex.matches(in: code, range: NSRange(location: 0, length: text.length)).map {
            text.substring(to: $0.range.location).count(where: { $0 == "\n" }) + 1
        }
    }

    /// The ways a file on ``packageKeychainFiles`` fails the structure its kind names (rule I9), read
    /// over its lexed code: its keychain lines (``packageKeychainLines(in:file:)``) each sit where its kind
    /// says, and it holds at least one, since a listed file with none would outlive its need.
    static func packageKeychainFileProblems(_ listed: PackageKeychainFile, source: String) -> [String] {
        let code = SwiftSourceLexer.lex(source).code.components(separatedBy: "\n")
        let keychain = packageKeychainLines(in: source, file: listed.file).map { $0 - 1 }
        var problems: [String] = keychain.isEmpty ? ["holds no keychain needle; delete its row on packageKeychainFiles"] : []
        switch listed.kind {
        case .suite:
            problems += suiteKeychainProblems(code: code, source: source, keychain: keychain)
        case .installer:
            problems += installerKeychainProblems(code: code, keychain: keychain)
        case .readsFirst(let type):
            problems += readsFirstKeychainProblems(code: code, type: type, keychain: keychain)
        }
        return problems.map { "I9: \(listed.file) \($0)" }
    }

    /// A suite file's structure (rule I9, ``PackageKeychainFileKind/suite``), its keychain lines 0-based.
    private static func suiteKeychainProblems(code: [String], source: String, keychain: [Int]) -> [String] {
        var problems: [String] = []
        let suites = topLevelTypes(in: code).filter(\.isSuite)
        if suites.isEmpty {
            problems.append("declares no @Suite type, so its keychain lines sit in no suite instance")
        }
        // R2: bounded by the file's suites.
        for suite in suites {
            let first = structureMembers(of: suite.declaration, in: code).first { $0.isStoredProperty && !$0.isStatic }
            let marked = first.map { member in packageKeychainReadyMarkers.contains { member.text.contains($0) } } ?? false
            if !marked {
                problems.append("`\(suite.name)`'s first stored property reads none of \(packageKeychainReadyMarkers), so a cell may reach the keychain before the installer has run")
            }
        }
        // R2: bounded by the file's keychain lines.
        for line in keychain {
            guard let suite = suites.first(where: { $0.declaration.first <= line && line <= $0.declaration.last }) else {
                problems.append("line \(line + 1) reaches the keychain outside every @Suite type")
                continue
            }
            let owner = owningMember(of: line, in: structureMembers(of: suite.declaration, in: code))
            if let owner, owner.isStatic && !owner.isPrivate {
                problems.append("line \(line + 1) reaches the keychain in a static member that is not private, which another file can call before any suite instance exists")
            }
        }
        let lexed = code.joined(separator: "\n")
        let staticTest = #"@Test(?![A-Za-z0-9_])(?:\s*\([^)]*\))?(?:\s+@[A-Za-z_]+(?:\([^)]*\))?)*\s+"#
            + #"(?:(?:private|fileprivate|internal|public|nonisolated|final)\s+)*(?:static|class)\s+func"#
        let runsAlone: [(lines: [Int], what: String)] = [
            (matchLines(staticTest, in: lexed), "declares a static test"),
            (freeTestLines(in: source), "declares a free test"),
            (matchLines(#"@(?:Test|Suite)\s*\("#, in: lexed), "hands a test or a suite arguments or traits"),
            (matchLines(#"(?<![A-Za-z0-9_])static\s+(?:let|var)\s+[A-Za-z_][A-Za-z0-9_]*\s*(?::[^={\n]*)?="#, in: lexed),
             "declares a static stored property with an initializer"),
            (structureDeclarations(in: code, range: 0..<code.count, depth: 0)
                .filter { $0.keyword == "let" || $0.keyword == "var" }.map { $0.head + 1 },
             "declares a global stored property")
        ]
        // R2: bounded by the five rules × their lines.
        for rule in runsAlone {
            for line in rule.lines {
                problems.append("line \(line) \(rule.what), which runs without a suite instance")
            }
        }
        return problems
    }

    /// The installer's structure (rule I9, ``PackageKeychainFileKind/installer``), its keychain lines
    /// 0-based: every one inside the initializer of a `static let keychain`.
    private static func installerKeychainProblems(code: [String], keychain: [Int]) -> [String] {
        let reads = topLevelTypes(in: code).flatMap { structureMembers(of: $0.declaration, in: code) }
            .filter { !matchLines(#"static\s+let\s+keychain(?![A-Za-z0-9_])"#, in: $0.heading).isEmpty }
        guard !reads.isEmpty else { return ["declares no `static let keychain`, the read its keychain lines must sit in"] }
        return keychain.filter { line in !reads.contains { $0.first <= line && line <= $0.last } }
            .map { "line \($0 + 1) reaches the keychain outside the initializer of `static let keychain`" }
    }

    /// A support type's structure (rule I9, ``PackageKeychainFileKind/readsFirst(type:)``), its keychain
    /// lines 0-based: every initializer of `type` reads `PackageTestEnvironment.keychain` in its first
    /// statement, and every keychain line sits in an instance member of it that is no stored property.
    private static func readsFirstKeychainProblems(code: [String], type name: String, keychain: [Int]) -> [String] {
        guard let type = topLevelTypes(in: code).first(where: { $0.name == name }) else {
            return ["declares no `\(name)`, the type its keychain lines must sit in"]
        }
        var problems: [String] = []
        let members = structureMembers(of: type.declaration, in: code)
        let inits = members.filter { $0.keyword == "init" }
        if inits.isEmpty {
            problems.append("`\(name)` declares no initializer, so nothing reads PackageTestEnvironment.keychain before its members")
        }
        // R2: bounded by the type's initializers.
        for initializer in inits where !firstStatement(of: initializer, in: code).contains("PackageTestEnvironment.keychain") {
            problems.append("`\(name)`'s initializer on line \(initializer.head + 1) does not read PackageTestEnvironment.keychain in its first statement")
        }
        // R2: bounded by the file's keychain lines.
        for line in keychain {
            guard type.declaration.first <= line && line <= type.declaration.last,
                  let owner = owningMember(of: line, in: members) else {
                problems.append("line \(line + 1) reaches the keychain outside every member of `\(name)`")
                continue
            }
            if owner.isStatic || owner.isStoredProperty {
                problems.append("line \(line + 1) reaches the keychain in a static member or a stored property's initializer of `\(name)`, which runs before or without its initializer")
            }
        }
        return problems
    }

    /// The first statement of the body `declaration` opens, trimmed: the code after its first brace on
    /// that line, or else the next line that holds code; empty when it opens no body.
    static func firstStatement(of declaration: StructureDeclaration, in code: [String]) -> String {
        // R2: bounded by the declaration's lines.
        for index in declaration.head...declaration.last {
            guard let brace = code[index].firstIndex(of: "{") else { continue }
            let rest = code[index][code[index].index(after: brace)...].trimmingCharacters(in: .whitespaces)
            if !rest.isEmpty { return rest }
            let next = code[(index + 1)..<(declaration.last + 1)].first { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
            return next?.trimmingCharacters(in: .whitespaces) ?? ""
        }
        return ""
    }

    // MARK: - I11: the imports

    /// The modules a package file may import (rule I11): ProximityKit, the test target's one declared
    /// dependency, and the system modules its files use. No host's module is here: ProximityKit depends on
    /// no other package, so dependency validation already refuses a package test that imports one, and this
    /// rule names the refusal for what it is. A host's modules hold the host's own values (its crypto
    /// purposes' labels, its payload types' tokens), so a package test that imported one could pin a host's
    /// byte and could not travel.
    static let packageImportAllowlist: Set<String> = [
        "ProximityKit", "Foundation", "Testing", "Combine", "simd", "Synchronization"
    ]

    /// The one package file that may also import ``packageSecurityImports`` (rule I11), by its exact path:
    /// the package tests' in-memory keychain store, which answers ProximityKit's keychain funnel by the
    /// Security keys of the query dictionaries it is handed (`kSecClass`, `kSecAttrService`,
    /// `kSecMatchLimit`, …) and with Security's statuses. A store renamed or moved fails I11 rather than
    /// taking the allowance with it.
    static let packageSecurityImportFile = "TestSupport/PackageKeychainStore.swift"

    /// The modules ``packageSecurityImportFile`` may import besides ``packageImportAllowlist`` (rule
    /// I11): Security, a system module, so it travels with the package; held to that one file, so a suite
    /// or any other support file reads the keychain through ProximityKit and the store and never spells a
    /// keychain query of its own.
    static let packageSecurityImports: Set<String> = ["Security"]

    /// I11's problems over the package's files: each module a file imports that its allowance lacks.
    static func packageImportProblems(in files: [PackageSwiftFiles.File]) -> [String] {
        var problems: [String] = []
        // R2: bounded by the package's file count × each file's imports.
        for file in files {
            let allowed = file.path == packageSecurityImportFile
                ? packageImportAllowlist.union(packageSecurityImports) : packageImportAllowlist
            for module in importedModules(in: file.text) where !allowed.contains(module) {
                problems.append("I11: \(file.path) imports `\(module)`; a file there may import only \(allowed.sorted()) (a host's module does not travel with ProximityKit's tests, and Security is the keychain store's alone)")
            }
        }
        return problems
    }

    /// The modules a Swift source imports, in order: the first path component after `import` on every
    /// line of its code, past leading attributes (`@testable`, `@preconcurrency`), an access level
    /// (`internal import X`) and an import kind (`import struct X.Y`), the words split on any whitespace
    /// (a tab included). The source is read as `SwiftSourceLexer` reads it, comments dropped and literals
    /// emptied, so neither a commented-out import nor a line of a literal is one: the platform wall
    /// fixtures its module reader on literals that spell `import UIKit`, which only a reader of the file's
    /// text, not of its code, would take for this file's own.
    static func importedModules(in source: String) -> [String] {
        let levels: Set<String> = ["public", "package", "internal", "fileprivate", "private", "open"]
        let kinds: Set<String> = ["struct", "class", "enum", "protocol", "typealias", "func", "var", "let", "actor"]
        var modules: [String] = []
        // R2: bounded by the source's line count.
        for line in SwiftSourceLexer.lex(source).code.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            var tokens = ArraySlice(trimmed.split(whereSeparator: \.isWhitespace).map(String.init))
            tokens = tokens.drop { $0.hasPrefix("@") }
            if let first = tokens.first, levels.contains(first) { tokens = tokens.dropFirst() }
            guard tokens.first == "import" else { continue }
            tokens = tokens.dropFirst()
            if let first = tokens.first, kinds.contains(first) { tokens = tokens.dropFirst() }
            guard let path = tokens.first, let module = path.split(separator: ".").first else { continue }
            modules.append(String(module))
        }
        return modules
    }

    // MARK: - The inventory (I1, I2, I4, I7)

    /// The target's own inventory, by its name under the package root's `Tests` folder, beside the target's
    /// folder: outside the folder, since a non-source file in a SwiftPM target's folder is an unhandled-file
    /// diagnostic, and under `Tests`, so it travels with the package.
    static let inventoryFile = "ProximityKitTests.tsv"

    /// The inventory's header, its first line that is not a `#` comment.
    static let inventoryHeader = "suite\tfile\tcells"

    /// One inventory row: a suite, the file declaring it, and its declared tests.
    struct InventoryRow: Equatable, Sendable {
        /// The suite's type name, as Swift Testing reports it.
        let suite: String
        /// The file whose column-0 line declares the suite, by its path under the test target's folder.
        let file: String
        /// The suite's declared tests: its `@Test` attributes summed over every file of the folder, an
        /// extension's included; a parameterized test is one.
        let cells: Int
    }

    /// The MEASURED row count (rule I2). MEASURED at ProximityKit plan step A1.1.13 (2026-10-14): the 21
    /// suites the package held at A1.1.10 and this one. RAISED at A1.1.14 (2026-10-14): 22 → 23, for the
    /// package's NEW `PackageTestTreeWallTests`. RAISED at A1.1.15 (2026-10-14): 23 → 24, for the
    /// package's NEW `ProximitySourceWallTests`. RAISED at A1.1.17 (2026-10-14): 24 → 25, for the
    /// package's NEW `ProximityMemoryLifecycleTests`. A suite added, moved out or deleted changes it in the
    /// same commit, argued and measured; a deletion lowers it only with the retirement argued.
    static let measuredInventoryRows = 25

    /// The MEASURED sum of the rows' declared tests (rule I7). MEASURED at ProximityKit plan step A1.1.13
    /// (2026-10-14): 173 at A1.1.10 + this suite's 6. RAISED at A1.1.14 (2026-10-14): 179 → 185, for
    /// `PackageTestTreeWallTests`' 6. RAISED at A1.1.15 (2026-10-14): 185 → 191, for
    /// `ProximitySourceWallTests`' 6. RAISED at A1.1.16 (2026-10-14): 191 → 197, for the six cells the
    /// purpose wall and the escape-hatch census add to `ProximitySourceWallTests`. RAISED at A1.1.17
    /// (2026-10-14): 197 → 203, for `ProximityMemoryLifecycleTests`' 5 and the identity-construction cell
    /// `ProximitySourceWallTests` gains. A test added or removed changes it in the same commit.
    static let measuredDeclaredTests = 203

    /// Reads the inventory's text into its rows and its format problems by line (rule I1): `#` lines are
    /// comments; the first other line is exactly ``inventoryHeader``; every data line has three
    /// tab-separated fields; `suite` is an identifier; `file` is a relative `.swift` path with no `..`;
    /// `cells` is a positive integer; rows run strictly ascending by suite; a suite is on one row only. A
    /// line with a field problem is reported and left out of `rows`.
    static func inventory(in text: String) -> (rows: [InventoryRow], problems: [String]) {
        var rows: [InventoryRow] = []
        var problems: [String] = []
        var sawHeader = false
        var suites: Set<String> = []
        // R2: bounded by the text's line count.
        for (offset, line) in text.components(separatedBy: "\n").enumerated() {
            guard !line.isEmpty, !line.hasPrefix("#") else { continue }
            guard sawHeader else {
                sawHeader = true
                if line != inventoryHeader {
                    problems.append("line \(offset + 1): the first line that is not a comment is not the header")
                }
                continue
            }
            let read = inventoryRow(line)
            guard let row = read.row else {
                problems.append("line \(offset + 1): \(read.problem ?? "unreadable")")
                continue
            }
            if let previous = rows.last, previous.suite >= row.suite {
                problems.append("line \(offset + 1): `\(row.suite)` does not sort after `\(previous.suite)` — rows sort by suite")
            }
            if !suites.insert(row.suite).inserted {
                problems.append("line \(offset + 1): `\(row.suite)` is on more than one row")
            }
            rows.append(row)
        }
        if !sawHeader { problems.append("no header line") }
        return (rows, problems)
    }

    /// One data line read into a row, or the first field problem that keeps it out (rule I1).
    private static func inventoryRow(_ line: String) -> (row: InventoryRow?, problem: String?) {
        let fields = line.components(separatedBy: "\t")
        guard fields.count == 3 else { return (nil, "\(fields.count) tab-separated fields, not 3") }
        let (suite, file, cells) = (fields[0], fields[1], fields[2])
        guard isIdentifier(suite) else { return (nil, "`\(suite)` is not a suite name") }
        let parts = file.split(separator: "/", omittingEmptySubsequences: false)
        guard file.hasSuffix(".swift"), !file.hasPrefix("/"), !parts.contains("..") else {
            return (nil, "`\(file)` is not a Swift file under \(PackageSwiftFiles.testFolder)")
        }
        guard let count = Int(cells), count > 0 else { return (nil, "cells `\(cells)` are not a positive integer") }
        return (InventoryRow(suite: suite, file: file, cells: count), nil)
    }

    /// An identifier as a row spells a suite: non-empty ASCII letters, digits and `_`.
    private static func isIdentifier(_ text: String) -> Bool {
        guard !text.isEmpty else { return false }
        return text.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_") }
    }

    /// I4: each row's suite is declared at column 0 (``topLevelTypeName(_:)``) in exactly its row's file
    /// among the package's files.
    static func inventoryHomeProblems(_ rows: [InventoryRow], files: [PackageSwiftFiles.File]) -> [String] {
        var declared: [String: [String]] = [:]
        // R2: bounded by the package's file count × each file's line count.
        for file in files {
            for line in file.text.components(separatedBy: "\n") {
                guard let name = topLevelTypeName(line), declared[name]?.contains(file.path) != true else { continue }
                declared[name, default: []].append(file.path)
            }
        }
        var problems: [String] = []
        // R2: bounded by the row count.
        for row in rows {
            let homes = declared[row.suite] ?? []
            if homes.isEmpty {
                problems.append("I4: `\(row.suite)` is declared in no file of \(PackageSwiftFiles.testFolder); its row says \(row.file)")
            } else if homes != [row.file] {
                problems.append("I4: `\(row.suite)` is declared in \(homes.joined(separator: ", ")), not exactly in its row's \(row.file)")
            }
        }
        return problems
    }

    /// I7: each row's declared tests (``declaredTestCounts(in:)`` of its suite, summed over every package
    /// file, so an extension in a second file counts toward its suite) are its cells and sum to
    /// ``measuredDeclaredTests``; every type a package file declares a test for is a row; no test counts
    /// toward no type (a test before any declaration the reader names, indented or not); and no package
    /// line is a free `@Test` at column 0.
    static func declaredTestProblems(_ rows: [InventoryRow], files: [PackageSwiftFiles.File]) -> [String] {
        let listed = Set(rows.map(\.suite))
        var declared: [String: Int] = [:]
        var problems: [String] = []
        // R2: bounded by the package's file count × each file's tested types.
        for file in files {
            for (type, count) in declaredTestCounts(in: file.text).sorted(by: { $0.key < $1.key }) {
                declared[type, default: 0] += count
                if type.isEmpty {
                    problems.append("I7: \(file.path) declares \(count) test(s) before any declaration the reader can name, so no suite holds them")
                } else if !listed.contains(type) {
                    problems.append("I7: \(file.path) declares \(count) test(s) for `\(type)`, which is no row")
                }
            }
            for line in freeTestLines(in: file.text) {
                problems.append("I7: \(file.path):\(line) is a free `@Test` at column 0, which no suite holds")
            }
        }
        var sum = 0
        // R2: bounded by the row count.
        for row in rows {
            let counted = declared[row.suite] ?? 0
            sum += counted
            if counted != row.cells {
                problems.append("I7: `\(row.suite)` declares \(counted) test(s) across \(PackageSwiftFiles.testFolder); its row says \(row.cells)")
            }
        }
        if sum != measuredDeclaredTests {
            problems.append("I7: the rows' declared tests sum to \(sum); \(measuredDeclaredTests) were measured")
        }
        return problems
    }

    // MARK: - The declaration reader (I4, I7)

    /// The modifiers a column-0 declaration may carry before its keyword, each read past at most once:
    /// `nonisolated`, the four access levels that leave a type visible outside its file, and `final` and
    /// `indirect`, which may stand before an access level (`final public class X`). `private` and
    /// `fileprivate` are not here: such a type is file-scoped, and is no suite a row can name.
    private static let visibleModifiers = [
        "nonisolated ", "public ", "internal ", "package ", "open ", "final ", "indirect "
    ]

    /// The type keywords a suite or a helper type is declared with.
    private static let typeKeywords = ["struct ", "final class ", "class ", "actor ", "enum "]

    /// The type a column-0 declaration line names, or nil for anything else. Leading attributes on the
    /// same line (`@Suite struct X`, `@Suite(.serialized) struct X`, `@MainActor final class X`) and
    /// ``visibleModifiers`` (`nonisolated struct X`) are skipped; a leading space means a nested type, and a
    /// `private` or `fileprivate` type is file-scoped.
    static func topLevelTypeName(_ line: String) -> String? {
        guard let rest = afterAttributes(line, readingPast: visibleModifiers) else { return nil }
        return typeName(rest)
    }

    /// A column-0 line with its leading attributes and then the given modifiers read past (each modifier
    /// at most once, in any order), or nil for a line that does not start at column 0 with an attribute or
    /// a letter (a nested declaration, a comment, a blank line).
    private static func afterAttributes(_ line: String, readingPast modifiers: [String]) -> Substring? {
        guard line.hasPrefix("@") || line.first?.isLetter == true else { return nil }
        var rest = Substring(line)
        // R2: bounded by the line's attribute count — each pass consumes at least one character.
        while rest.hasPrefix("@") {
            var depth = 0
            var index = rest.startIndex
            // R2: bounded by the line length.
            while index < rest.endIndex {
                let character = rest[index]
                if character == "(" { depth += 1 } else if character == ")" { depth -= 1 }
                if character == " " && depth == 0 { break }
                index = rest.index(after: index)
            }
            rest = rest[index...].drop { $0 == " " }
        }
        var unread = modifiers
        // R2: bounded by the modifier list — each pass removes one entry from `unread`.
        while let index = unread.firstIndex(where: { rest.hasPrefix($0) }) {
            rest = rest.dropFirst(unread[index].count)
            unread.remove(at: index)
        }
        return rest
    }

    /// The name a declaration's remainder gives a type after one of ``typeKeywords``, or nil.
    private static func typeName(_ rest: Substring) -> String? {
        // R2: bounded by the keyword list.
        for keyword in typeKeywords where rest.hasPrefix(keyword) {
            let name = rest.dropFirst(keyword.count).prefix { $0.isLetter || $0.isNumber || $0 == "_" }
            return name.isEmpty ? nil : String(name)
        }
        return nil
    }

    /// The type an `extension` declaration's remainder extends: its name up to a `:`, `{`, `<`, a space or
    /// a `where` clause, or nil when the remainder is not an extension.
    private static func extendedTypeName(_ rest: Substring) -> String? {
        guard rest.hasPrefix("extension ") else { return nil }
        let name = rest.dropFirst("extension ".count).prefix { !":{< ".contains($0) }
        return name.isEmpty ? nil : String(name)
    }

    /// The type a column-0 line's tests count toward (the declared-test reader's attribution): a type
    /// ``topLevelTypeName(_:)`` reads, a `private` or `fileprivate` type (file-scoped, but its tests are
    /// still its own), or the type an `extension` extends. Nil for any other line, which leaves the
    /// current type unchanged.
    private static func attributionName(_ line: String) -> String? {
        let modifiers = visibleModifiers + ["private ", "fileprivate "]
        guard let rest = afterAttributes(line, readingPast: modifiers) else { return nil }
        return typeName(rest) ?? extendedTypeName(rest)
    }

    // MARK: - The declared-test reader (I7)

    /// The tests a Swift source declares, by the type they belong to (rule I7). Per line, in order: a line
    /// whose trimmed text starts `//` is skipped, string literals are blanked and a trailing `//` comment
    /// is cut (``codePart(of:)``; a multi-line literal's lines are skipped whole); a column-0 declaration
    /// then becomes the current type (``attributionName(_:)``: a type, a `private` or `fileprivate` type,
    /// or the type an `extension` extends); and every `@Test` attribute token on the line (`@Test func`,
    /// `@Test(...)`, `@MainActor @Test func`, and the one in `@Suite struct S { @Test func a() {} }`) and
    /// every XCTest method (`func test…(` after `@MainActor`, `override` or `final`) counts one toward the
    /// current type. A parameterized `@Test` is one test case in the result bundle and one here. A test
    /// before any declaration counts under `""`; a type with no test has no key.
    static func declaredTestCounts(in source: String) -> [String: Int] {
        var counts: [String: Int] = [:]
        // R2: bounded by the source's line count.
        for line in codeLines(of: source) {
            let found = testAttributeCount(in: line.code) + (isXCTestMethod(line.code) ? 1 : 0)
            if found > 0 { counts[line.type, default: 0] += found }
        }
        return counts
    }

    /// One code line of a Swift source as the declared-test reader walks it (rule I7).
    struct CodeLine: Sendable {
        /// The line's 1-based number.
        let number: Int
        /// The line's whole text.
        let text: String
        /// Its code (``codePart(of:)``): literals blanked, a trailing comment cut.
        let code: String
        /// The type its tests count toward: the last column-0 declaration's, or `""` before any.
        let type: String
    }

    /// The code lines of a Swift source, in order, each with the type its tests count toward: a line whose
    /// trimmed text starts `//` is not one, nor is a line inside a multi-line literal (from the line after
    /// the one that opens `"""` up to and including the one that closes it), so neither the declared-test
    /// reader nor the free-test reader reads a literal's lines as code.
    static func codeLines(of source: String) -> [CodeLine] {
        var lines: [CodeLine] = []
        var current = ""
        var inMultilineString = false
        // R2: bounded by the source's line count.
        for (offset, line) in source.components(separatedBy: "\n").enumerated() {
            guard !inMultilineString else {
                inMultilineString = !line.contains("\"\"\"")
                continue
            }
            guard !line.trimmingCharacters(in: .whitespaces).hasPrefix("//") else { continue }
            let read = codePart(of: line)
            inMultilineString = read.opensMultilineString
            if let name = attributionName(line) { current = name }
            lines.append(CodeLine(number: offset + 1, text: line, code: read.code, type: current))
        }
        return lines
    }

    /// A line's code: each string literal's contents blanked (its quotes kept), a trailing `//` comment
    /// outside a literal cut, and whether a multi-line literal (`"""`) opens on the line, whose following
    /// lines up to its closing delimiter are not code.
    private static func codePart(of line: String) -> (code: String, opensMultilineString: Bool) {
        let characters = Array(line)
        var code = ""
        var inString = false
        var escaped = false
        var index = 0
        // R2: bounded by the line's length — each pass consumes one character or returns.
        while index < characters.count {
            let character = characters[index]
            index += 1
            if inString {
                if escaped {
                    escaped = false
                } else if character == "\\" {
                    escaped = true
                } else if character == "\"" {
                    inString = false
                    code.append(character)
                }
                continue
            }
            if character == "\"", index + 1 < characters.count, characters[index] == "\"", characters[index + 1] == "\"" {
                return (code, true)
            }
            if character == "/", index < characters.count, characters[index] == "/" { break }
            inString = character == "\""
            code.append(character)
        }
        return (code, false)
    }

    /// The `@Test` attribute tokens in a line's code: `@Test` at the start of the code or after whitespace,
    /// `{`, `;` or `(`, and not followed by an identifier character (`@Tests` is not one).
    private static func testAttributeCount(in code: String) -> Int {
        let characters = Array(code)
        let token = Array("@Test")
        var count = 0
        // R2: bounded by the code's length.
        for start in characters.indices where start + token.count <= characters.count {
            guard characters[start..<(start + token.count)].elementsEqual(token) else { continue }
            let before: Character = start == 0 ? " " : characters[start - 1]
            let end = start + token.count
            let after: Character = end < characters.count ? characters[end] : " "
            let opens = before.isWhitespace || "{;(".contains(before)
            let closes = !(after.isLetter || after.isNumber || after == "_")
            if opens && closes { count += 1 }
        }
        return count
    }

    /// Whether a line's code declares an XCTest method: `func test…(`, after any of `@MainActor`,
    /// `override` and `final`.
    private static func isXCTestMethod(_ code: String) -> Bool {
        var rest = Substring(code.trimmingCharacters(in: .whitespaces))
        var unread = ["@MainActor ", "override ", "final "]
        // R2: bounded by the prefix list — each pass removes one entry from `unread`.
        while let index = unread.firstIndex(where: { rest.hasPrefix($0) }) {
            rest = rest.dropFirst(unread[index].count).drop { $0 == " " }
            unread.remove(at: index)
        }
        guard rest.hasPrefix("func test") else { return false }
        let name = rest.dropFirst("func ".count).prefix { $0.isLetter || $0.isNumber || $0 == "_" }
        return rest.dropFirst("func ".count + name.count).hasPrefix("(")
    }

    /// The 1-based numbers of a source's code lines (``codeLines(of:)``, so a multi-line literal's lines
    /// are not code) that hold a `@Test` at column 0 outside any type declaration (a free test function),
    /// which the inventory cannot pin to a suite.
    static func freeTestLines(in source: String) -> [Int] {
        codeLines(of: source).filter { line in
            line.text.hasPrefix("@") && attributionName(line.text) == nil && testAttributeCount(in: line.code) > 0
        }.map(\.number)
    }

    // MARK: - `ProximityHost` extended nowhere

    /// An extension of `ProximityHost` in lexed code, bare or qualified by its module, with or without a
    /// conformance or a `where` clause, and never a longer name that holds it.
    static let hostExtensionPattern = #"(?<![A-Za-z0-9_])extension\s+(?:ProximityKit\s*\.\s*)?ProximityHost(?![A-Za-z0-9_])"#

    /// The extension matcher reads each spelling of an extension of `ProximityHost` and none of its
    /// neighbours: a longer type's extension, a conformance, and a comment or a literal once lexed.
    private static func expectTheHostExtensionReaderFixtured() {
        let extensions = [
            "extension ProximityHost {", "extension ProximityKit.ProximityHost where Self: AnyObject {",
            "extension ProximityHost: Sendable {}"
        ]
        let neighbours = [
            "extension ProximityHostAdapter {", "final class H: ProximityHost {", "/// extension ProximityHost {",
            #"let s = "extension ProximityHost {""#
        ]
        // R2: bounded by the two fixed lists.
        for sample in extensions {
            #expect(matchLines(hostExtensionPattern, in: SwiftSourceLexer.lex(sample).code) == [1],
                    "missed the extension in: \(sample)")
        }
        for sample in neighbours {
            #expect(matchLines(hostExtensionPattern, in: SwiftSourceLexer.lex(sample).code).isEmpty,
                    "read an extension in: \(sample)")
        }
    }

    // MARK: - The readers' samples

    /// The needle reader (rule I9): it holds a keychain type however it is constructed or reached, a seal
    /// key's wipe, a raw `SecItem` call but not a status that spells it inside its name, and every
    /// platform directory but the temporary ones.
    private static func expectTheNeedleReaderFixtured() {
        let hazardous = [
            "let id = IdentityService.init(namespace: ns)", "let s: MeshSessionStore = .init(scope: scope)",
            "MeshSessionSealKey.wipe(service: service)", "MeshRoutedSealKey.wipe(service: service)",
            "let root = URL.documentsDirectory.appending(path: \"scratch\")", "let home = NSHomeDirectory()",
            "FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)", "let home = URL.homeDirectory",
            "let defaults = UserDefaults(suiteName: \"x\")", "let status = SecItemCopyMatching(query, &result)",
            "_ = SecItemDelete(query as CFDictionary)"
        ]
        // R2: bounded by the fixed list.
        for line in hazardous {
            #expect(!packageHazardNeedles(onLine: line).isEmpty, "I9 holds no needle on `\(line)`")
        }
        // R2: bounded by the fixed list.
        for line in ["let cache = ReplayCache(maxEntries: 3)", "let scratch = FileManager.default.temporaryDirectory",
                     "return matched.isEmpty ? errSecItemNotFound : errSecSuccess"] {
            #expect(packageHazardNeedles(onLine: line).isEmpty, "I9 holds a needle on `\(line)`")
        }
    }

    /// The structure reader's problems for a fixture `source` read as a listed file of `kind` (rule I9).
    private static func fixtureKeychainProblems(_ kind: PackageKeychainFileKind, _ source: String) -> [String] {
        packageKeychainFileProblems(PackageKeychainFile(file: "F.swift", kind: kind, invariant: ""), source: source)
    }

    /// The structure reader over a suite file (rule I9), both ways. A suite whose first stored property
    /// reads the installer, with its keychain lines in its instance tests and a private static helper,
    /// passes, and each way a suite file reaches the keychain without an instance is named: no marker, or a
    /// marker second; a helper that is not private; a static or a free test; test arguments or a suite
    /// trait; a static or a global stored property; a keychain line outside every suite; and a listed file
    /// with no keychain line.
    private static func expectTheSuiteKeychainFileReaderFixtured() {
        let read = fixtureKeychainProblems
        let suite = """
            @Suite struct S {
                let store = PackageTestEnvironment.keychain
                @Test func a() { _ = ProximityKeychainItem.backend }
                @MainActor @Test func b() throws { try Self.identity().ensureProvisioned() }
                @MainActor private static func identity() -> IdentityService {
                    IdentityService(namespace: .packageTest, keychainService: "s")
                }
            }
            """
        #expect(read(.suite, suite).isEmpty, "a suite file that keeps its structure was refused: \(read(.suite, suite))")
        let marker = "    let store = PackageTestEnvironment.keychain"
        let suites: [(source: String, names: String)] = [
            (suite.replacingOccurrences(of: marker, with: "    let name = \"x\""), "first stored property reads none"),
            (suite.replacingOccurrences(of: marker, with: "    let name = \"x\"\n" + marker), "first stored property reads none"),
            (suite.replacingOccurrences(of: "@MainActor private static", with: "@MainActor static"), "static member that is not private"),
            (suite.replacingOccurrences(of: "@Test func a()", with: "@Test static func a()"), "declares a static test"),
            (suite.replacingOccurrences(of: "@Test func a()", with: "@Test(arguments: [1]) func a(v: Int)"), "arguments or traits"),
            (suite.replacingOccurrences(of: "@Suite struct S {", with: "@Suite(.serialized) struct S {"), "arguments or traits"),
            (suite.replacingOccurrences(of: marker, with: marker + "\n    private static let cache = 1"),
             "static stored property"),
            (suite + "\nlet shared = 1", "global stored property"),
            (suite + "\n@Test func free() {}", "declares a free test"),
            (suite + "\nfunc helper() { _ = ProximityKeychainItem.backend }", "outside every @Suite type"),
            ("@Suite struct S {\n" + marker + "\n    @Test func a() {}\n}", "holds no keychain needle")
        ]
        // R2: bounded by the fixed list.
        for (source, names) in suites {
            let problems = read(.suite, source)
            #expect(problems.contains { $0.contains(names) }, "a suite file that \(names) was read as \(problems)")
        }
    }

    /// The structure reader over the installer and a support type (rule I9), both ways. An installer passes
    /// with its one line in `static let keychain` and fails with it outside, or with no such read. A support
    /// type passes with its lines in instance members behind an initializer that reads the installer first,
    /// and fails with a late read, a static member, a stored property, a line outside its members, or no
    /// such type.
    private static func expectTheInstallerAndSupportTypeReadersFixtured() {
        let read = fixtureKeychainProblems
        let installer = """
            enum Environment {
                static let keychain: Store = {
                    let store = Store()
                    ProximityKeychainItem.installBackend(store)
                    return store
                }()
            }
            """
        #expect(read(.installer, installer).isEmpty, "an installer that keeps its structure was refused: \(read(.installer, installer))")
        let installers: [(source: String, names: String)] = [
            (installer.replacingOccurrences(of: "}()\n}", with: "}()\n    static func again() { ProximityKeychainItem.installBackend(Store()) }\n}"),
             "outside the initializer of `static let keychain`"),
            (installer.replacingOccurrences(of: "static let keychain", with: "static let other"), "declares no `static let keychain`")
        ]
        // R2: bounded by the fixed list.
        for (source, names) in installers {
            let problems = read(.installer, source)
            #expect(problems.contains { $0.contains(names) }, "an installer whose structure is broken was read as \(problems)")
        }

        let host = """
            final class Host {
                let store: Store
                init() {
                    store = PackageTestEnvironment.keychain
                }
                func identity() -> IdentityService {
                    IdentityService(namespace: .packageTest, keychainService: "s")
                }
            }
            """
        let kind = PackageKeychainFileKind.readsFirst(type: "Host")
        #expect(read(kind, host).isEmpty, "a support type that keeps its structure was refused: \(read(kind, host))")
        let identity = "    func identity() -> IdentityService {"
        let hosts: [(kind: PackageKeychainFileKind, source: String, names: String)] = [
            (kind, host.replacingOccurrences(of: "    init() {\n", with: "    init() {\n        let x = 1\n"),
             "does not read PackageTestEnvironment.keychain in its first statement"),
            (kind, host.replacingOccurrences(of: identity, with: "    static func identity() -> IdentityService {"),
             "static member or a stored property's initializer"),
            (kind, host.replacingOccurrences(of: "    let store: Store\n",
                                             with: "    let store: Store\n    let early = IdentityService(namespace: .packageTest)\n"),
             "static member or a stored property's initializer"),
            (kind, host + "\nfunc loose() { _ = IdentityService(namespace: .packageTest) }", "outside every member of `Host`"),
            (.readsFirst(type: "Other"), host, "declares no `Other`")
        ]
        // R2: bounded by the fixed list.
        for (kind, source, names) in hosts {
            let problems = read(kind, source)
            #expect(problems.contains { $0.contains(names) }, "a support type whose structure is broken was read as \(problems)")
        }
    }

    /// The import reader (rule I11): a module past attributes, an access level and an import kind, split
    /// on any whitespace, and no import a literal or a comment spells.
    private static func expectTheImportReaderFixtured() {
        let imports = "import Foundation\n@testable import ProximityKit\ninternal import FernletDomainModel\n"
            + "@preconcurrency import struct FernletCrypto.FernletCryptoPurpose\n// import FernletFoundation\nlet x = 1"
        #expect(importedModules(in: imports) == ["Foundation", "ProximityKit", "FernletDomainModel", "FernletCrypto"])
        #expect(importedModules(in: "import\tUIKit\n@testable\timport  ProximityKit\n") == ["UIKit", "ProximityKit"],
                "an import whose words a tab or a run of spaces separates was not read")
        let fixture = "import Testing\nlet sample = \"\"\"\n    import UIKit\n    @preconcurrency import NearbyInteraction\n"
            + "    \"\"\"\n/* import FernletFoundation */ let y = \"import FernletCrypto\""
        #expect(importedModules(in: fixture) == ["Testing"], "a literal's or a block comment's import was read as the file's")
    }

    /// The column-0 declaration reader (rule I4): attributes skipped, the visible modifiers read past, and
    /// a nested, commented or file-scoped type no suite.
    private static func expectTheDeclarationReaderFixtured() {
        #expect(topLevelTypeName("@Suite struct PackageTestHygieneTests {") == "PackageTestHygieneTests")
        #expect(topLevelTypeName("@Suite(.serialized) struct MeshP5HonestyAcceptanceTests {") == "MeshP5HonestyAcceptanceTests")
        #expect(topLevelTypeName("@MainActor final class Rig: XCTestCase {") == "Rig")
        #expect(topLevelTypeName("final class MeshRoutedBackpressureAuditCapture {") == "MeshRoutedBackpressureAuditCapture")
        #expect(topLevelTypeName("    struct Nested {") == nil, "a nested type is not a suite")
        #expect(topLevelTypeName("// struct InAComment") == nil)
        #expect(topLevelTypeName("nonisolated struct FormatMigratorTests {") == "FormatMigratorTests",
                "a nonisolated suite is read")
        #expect(topLevelTypeName("public final class Visible {") == "Visible")
        #expect(topLevelTypeName("private struct FileScoped {") == nil, "a file-scoped type is no suite")
        #expect(topLevelTypeName("@Suite package struct PackageScoped {") == "PackageScoped")
        #expect(topLevelTypeName("final public class FinalFirst {") == "FinalFirst")
        #expect(topLevelTypeName("open class Open {") == "Open")
    }

    /// The declared-test reader counts every `@Test` attribute token, each toward the type its column-0
    /// declaration names: a `@MainActor @Test` and a one-line suite's count, a comment and a string literal
    /// do not, an extension's tests are its type's, and a type with no test has no key; an XCTest method is
    /// `func test…(`; and a free test at column 0 is found, a suite's declaration is not.
    private static func expectTheDeclaredTestReaderFixtured() {
        let source = """
            @Suite struct A {
                @Test func one() {}
                @MainActor @Test func two() {}
                // @Test func commented() {}
            }

            private struct P {
                let value = 1
            }

            extension A {
                @Test(arguments: [1, 2]) func three(value: Int) {}
            }

            @Suite struct S { @Test func a() {} }

            @Suite struct B {
                @Test func four() { let text = "@Test inside a string" }
            }
            """
        #expect(declaredTestCounts(in: source) == ["A": 3, "B": 1, "S": 1])
        let xctest = """
            final class X: XCTestCase {
                func testA() {}
                override func setUp() {}
                @MainActor func testB() async throws {}
                func helperTest() {}
            }
            """
        #expect(declaredTestCounts(in: xctest) == ["X": 2], "an XCTest method is `func test…(`")
        #expect(freeTestLines(in: "@Suite struct S {}\n@Test func free() {}\n@MainActor @Test func alsoFree() {}") == [2, 3],
                "a free test at column 0 is found, a suite's declaration is not")
    }

    /// The two readers share one walker: a multi-line literal's lines are not code, so a column-0 `@Test`
    /// or `struct` inside one is neither counted, nor a free test, nor the current type; and a test before
    /// any declaration the reader names, indented or not, counts toward `""`, which rule I7 reports.
    private static func expectTheLiteralAndFreeTestReadersFixtured() {
        let literal = """
            @Suite struct M {
                @Test func one() {
                    let text = \"\"\"
            @Test func notATest() {}
            struct NotAType {
            \"\"\"
                    #expect(!text.isEmpty)
                }
                @Test func two() {}
            }
            """
        #expect(declaredTestCounts(in: literal) == ["M": 2], "a multi-line literal's lines are not code")
        #expect(freeTestLines(in: literal).isEmpty, "a column-0 `@Test` inside a literal is not a free test")
        let unnamed = "    @Test func indented() {}\n@Suite package struct P {\n    @Test func a() {}\n}"
        #expect(declaredTestCounts(in: unnamed) == ["": 1, "P": 1],
                "an indented test before any declaration counts toward no type, and `package struct` is read")
    }

    /// The inventory reader (rule I1): comments skipped, the header read, a good row kept, and a row with
    /// two fields reported and left out.
    private static func expectTheInventoryReaderFixtured() {
        let text = [
            "# a comment",
            inventoryHeader,
            "ReplayCacheTests\tReplayCacheTests.swift\t1",
            "ShortRow\tShortRow.swift",
            ""
        ].joined(separator: "\n")
        let read = inventory(in: text)
        #expect(read.rows == [InventoryRow(suite: "ReplayCacheTests", file: "ReplayCacheTests.swift", cells: 1)])
        #expect(read.problems.count == 1, "the two-field row is the one problem: \(read.problems)")
        let unsorted = [inventoryHeader, "B\tB.swift\t1", "A\tA.swift\t1"].joined(separator: "\n")
        #expect(inventory(in: unsorted).problems.contains { $0.contains("does not sort after") },
                "a row out of order was not reported")
    }
}
