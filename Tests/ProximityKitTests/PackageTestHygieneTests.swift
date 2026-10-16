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
//        keychain needle or a store's name only in a listed keychain file that keeps its kinds'
//        structure, and a wall file (this one first) is read as code, so the needles it holds as data
//        are not refused;
//   I11  every module a file imports travels with the package;
//   the target's own inventory, ProximityKitTests.tsv beside the target's folder under the package
//        root's `Tests`, is the tree: each suite's file and its declared tests (I1, I2, I4, I7), the
//        table the package repository's CI test-count floor reads;
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
    /// every platform directory but the temporary ones, and each location call by itself; the structure
    /// reader passes a keychain file that keeps its kinds' structure, its store lines among its keychain
    /// lines, and names each way one breaks it; and a wall file's literal is data while the same needle in
    /// its code is read, and a literal of it that starts with a repository folder is refused.
    @Test func theHazardReadersReadTheirSamples() {
        Self.expectTheNeedleReaderFixtured()
        Self.expectTheSuiteKeychainFileReaderFixtured()
        Self.expectTheFixtureEnumReaderFixtured()
        Self.expectTheStoreLineReaderFixtured()
        Self.expectTheInstallerAndSupportTypeReadersFixtured()
        Self.expectTheWallFileReaderFixtured()
    }

    /// **I11.** Every module a package file imports (``importedModules(in:)``, read over its code) is in
    /// ``packageImportAllowlist``, over every Swift file of the target at the walk's floor, the reader
    /// held to its samples first.
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
    /// listed file held to the structure its kinds name, which keeps its every keychain line behind a read
    /// of the installer (``packageKeychainFileProblems(_:source:)``); and a raw `SecItem` call stands in no
    /// file, listed or not, since it bypasses the funnel the store answers. The store needles are the two
    /// mesh stores' names, whose every store seals under a seal key it reads from the keychain, and the
    /// shorthand of a production scope (``packageStoreNeedles``): since ProximityKit plan step A1's third
    /// batch of copied suites, a store's name stands in a listed file too, held there as a keychain line
    /// under ``packageKeychainFileStoreInvariant`` (``packageListedStoreNeedles``), while a production
    /// scope's shorthand stands in no file but on an allowlist row. It is a needle list, not a
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
            a store seals its files under a seal key it reads from the keychain, so its name stands only in \
            a file on packageKeychainFiles, whose kind keeps it behind a read of \
            PackageTestEnvironment.keychain and one of whose rows states packageKeychainFileStoreInvariant, \
            or on an allowlist row whose invariant says what reads the installer first; it writes them \
            under its scope's directory, which this target's PackageTestTreeWallTests holds to a scope of \
            the test's own, never the production one, and a production scope's shorthand stands only on an \
            allowlist row
            """
        let location = "a production or process-shared location; on an unsandboxed Mac, the developer's own"
        let repo = """
            a package test reads a file through PackageRoot (TestSupport/PackageRoot.swift), whose markers \
            hold in both repositories, by a path relative to the package root: RepoRoot and a host \
            repository's paths do not travel with the package, a path computed from a source file's \
            own location breaks when a layout moves, and a relative path read from the unhosted agent \
            has no defined base
            """
        let scratch: Set<String> = ["temporaryDirectory", "NSTemporaryDirectory"]
        let locationNeedles = ProximityPlatformNeutralityTests.directoryNeedles.map(\.token)
            .filter { !scratch.contains($0) } + ["UserDefaults", "Bundle.main"]
        let repoNeedles = ["RepoRoot", "#filePath", "\"App/", "\"Docs/", "\"Tests/", "\".github/",
                           "\"FernletKit/", "\"Scripts/"]
        return packageKeychainNeedles.map { (needle: $0, reason: keychain) }
            + packageStoreNeedles.map { (needle: $0, reason: stores) }
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

    /// The store needles of ``packageHazards`` (rule I9): the two mesh stores' names, each matched as a
    /// substring so a construction, a static and a name that holds one (`MeshRoutedStoreFormat`) are all
    /// held, and the shorthand of a production scope.
    static let packageStoreNeedles = ["MeshRoutedStore", "MeshSessionStore", ".production("]

    /// The store needles a file on ``packageKeychainFiles`` may hold (rule I9; ProximityKit plan step A1's
    /// third batch of copied suites, whose store suites hold too many such lines for per-line rows): the
    /// two stores' names, each line held as a keychain line by the file's kinds, since a store reads its seal
    /// key from the keychain as it seals or opens, and the file's rows stating
    /// ``packageKeychainFileStoreInvariant``. A production scope's shorthand is not among them: it stands
    /// in no file, listed or not, but on an allowlist row.
    static let packageListedStoreNeedles: Set<String> = ["MeshRoutedStore", "MeshSessionStore"]

    /// How a file on ``packageKeychainFiles`` keeps every one of its keychain lines behind a read of
    /// `PackageTestEnvironment.keychain` (rule I9): each kind is a structure
    /// ``packageKeychainFileProblems(_:source:)`` checks, so a file that loses it fails. A line that names
    /// a store (``packageListedStoreNeedles``) is a keychain line here, since the store reads its seal key
    /// from the keychain as it seals or opens, so each kind holds it as it holds an identity. A file may be
    /// listed under more than one kind, one row each (a suite file that also holds a fixture enum): each
    /// kind then holds the keychain lines inside the types it names (``keychainDomain(of:in:)``), and a
    /// keychain line inside none of them fails.
    enum PackageKeychainFileKind: Equatable, Sendable {
        /// A suite file: every keychain line sits in a `@Suite` type whose first stored property reads
        /// a ready marker (``packageKeychainReadyMarkers``), which Swift Testing evaluates as it builds
        /// the suite instance for each cell, before the cell runs; and the file runs nothing that
        /// reaches the keychain without an instance: no static or free test; no trait or argument on a
        /// test or a suite but `.serialized`, a display name, and argument collections that are a
        /// literal array or a type's `.allCases` with no call, no keychain needle and no name of a
        /// static member of the file but a literal constant (``attributeArgumentProblems(in:)``), which
        /// Swift Testing evaluates before any instance exists; no static stored property whose
        /// initializer reaches the keychain (spells a keychain needle or names a static member of the
        /// file that holds a keychain line, an initializer that starts on the line below its `=`
        /// included); no global stored property; and no keychain line in a static member or a nested
        /// type that is not `private` (`fileprivate` reaches a second suite of the file, which may hold
        /// no marker).
        /// A `@Suite` type that holds no keychain line needs no marker: it reaches the keychain only
        /// through another type, which that type's own kind holds.
        case suite
        /// The installer: every keychain line sits in the initializer of its `static let keychain`,
        /// which is the read.
        case installer
        /// A support type's file: every keychain line sits in an instance member of the named type,
        /// never in a static member or a stored property's initializer, and every initializer of the
        /// type reads `PackageTestEnvironment.keychain` in its first statement. The type's own head
        /// line, which declares nothing else, runs nothing (``isBareTypeHead(_:of:in:)``).
        case readsFirst(type: String)
        /// A fixture enum (ProximityKit plan step A1's second batch of copied suites, whose keychain
        /// fixtures are enums of static functions): every keychain line of its domain sits in a member
        /// of the named top-level enum that is a function, an initializer, a subscript or a computed
        /// property, never in a stored property's initializer (which runs on first touch, before any
        /// read), and every member that holds one, whatever its access, reads
        /// `PackageTestEnvironment.keychain` in its first statement. So the read precedes the line
        /// whoever calls the member, from a suite instance, another fixture or another file. The enum's
        /// own head line, which declares nothing else, runs nothing (``isBareTypeHead(_:of:in:)``).
        case fixtureEnum(type: String)
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
        runs; and nothing in the file that reaches the keychain runs without an instance (no static or free \
        test; no trait or argument but .serialized, a display name and a literal or .allCases collection \
        with no call, no keychain needle and no static member of the file but a literal constant; no \
        static stored property whose initializer reaches the keychain; no global stored property; no \
        keychain line in a static member or a nested type another type could reach, fileprivate ones \
        included): the installer has put the in-memory store behind ProximityKit's keychain funnel before \
        the line runs, so a call on it reaches the store, never the system keychain
        """

    /// The invariant every ``PackageKeychainFileKind/fixtureEnum(type:)`` row keeps (rule I9).
    static let packageKeychainFixtureEnumInvariant = """
        every keychain line of the named fixture enum sits in a function, initializer, subscript or computed \
        property of it whose first statement reads PackageTestEnvironment.keychain, never in a stored \
        property's initializer: whoever calls the member, a suite instance, another fixture or another file, \
        the installer has put the in-memory store behind ProximityKit's keychain funnel before the line runs, \
        so a call on it reaches the store, never the system keychain
        """

    /// What makes a file's store lines safe in the unhosted bundle (rule I9; ProximityKit plan step A1's
    /// third batch of copied suites): a listed file whose keychain lines name a store
    /// (``packageListedStoreNeedles``) states it in one of its rows, and a file whose lines name none states
    /// it in none (``storeClauseProblems(_:source:keychain:)``), so the clause stands exactly where a store
    /// does.
    static let packageKeychainFileStoreInvariant = """
        every line of the file that names a store (MeshRoutedStore, MeshSessionStore) is held as a keychain \
        line, since a store reads its seal key from the keychain as it seals or opens, so the installer has \
        put the in-memory store behind ProximityKit's keychain funnel before the line runs; and every store \
        it builds is on a scope of the cell's own: one its fixture hand-builds per call on a fresh folder \
        under the temporary directory named for a fresh UUID, with a keychain service ending in .test. and a \
        fresh UUID, or one of a PackageTestHost's two scopes, on that host's own fresh root and services; \
        PackageTestTreeWallTests holds every store construction to an explicit scope:, no production scope \
        by any spelling and no hand-built scope on a production directory or service, and this rule refuses \
        a production scope's shorthand in every file, listed or not, so no production directory or row is \
        reachable; and no scope or store outlives the cell or the suite instance that built it in a static \
        stored property (the suite, support-type and fixture kinds each refuse a store line in a static \
        stored property's initializer, and a fixture builds its scope inside the member that reads the \
        installer first), so a cell reaches no scope another cell built
        """

    /// ``packageKeychainSuiteInvariant`` and ``packageKeychainFileStoreInvariant``: the invariant of a
    /// ``PackageKeychainFileKind/suite`` row in a file that holds a store line (rule I9).
    static let packageKeychainStoreSuiteInvariant = packageKeychainSuiteInvariant + "; and "
        + packageKeychainFileStoreInvariant

    /// ``packageKeychainFixtureEnumInvariant`` and ``packageKeychainFileStoreInvariant``: the invariant of a
    /// ``PackageKeychainFileKind/fixtureEnum(type:)`` row in a file that holds a store line (rule I9).
    static let packageKeychainStoreFixtureEnumInvariant = packageKeychainFixtureEnumInvariant + "; and "
        + packageKeychainFileStoreInvariant

    /// The files a keychain needle may stand in (rule I9, ProximityKit plan step A1.1.10): one row per
    /// file and kind (since plan step A1's second batch of copied suites, a file may hold a suite and a
    /// fixture enum, one row each), each with the structure its kind names, which the rule checks, and
    /// the rule fails a listed file that is gone or holds no keychain line, and a file listed twice under
    /// one kind.
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
            file: "ExampleNamespaceTests.swift", kind: .suite,
            invariant: packageKeychainSuiteInvariant),
        PackageKeychainFile(
            file: "PackageKeychainStoreTests.swift", kind: .suite,
            invariant: packageKeychainSuiteInvariant),
        PackageKeychainFile(
            file: "PackageTestHostTests.swift", kind: .suite,
            invariant: packageKeychainSuiteInvariant),
        PackageKeychainFile(
            file: "ProximityPairSessionTests.swift", kind: .suite,
            invariant: packageKeychainSuiteInvariant),
        PackageKeychainFile(
            file: "CrossVersionFixtureTests.swift", kind: .suite,
            invariant: packageKeychainSuiteInvariant),
        // Plan step A1's second batch of copied suites: the suites of Fernlet's tests that reach the
        // keychain and open no store, and the fixtures they build their identities through.
        PackageKeychainFile(
            file: "IdentityServiceTests.swift", kind: .suite,
            invariant: packageKeychainSuiteInvariant),
        PackageKeychainFile(
            file: "MemoryLifecycleTests.swift", kind: .suite,
            invariant: packageKeychainSuiteInvariant),
        PackageKeychainFile(
            file: "MeshChunkerTests.swift", kind: .suite,
            invariant: packageKeychainSuiteInvariant),
        PackageKeychainFile(
            file: "MeshDeliveryTargetTests.swift", kind: .fixtureEnum(type: "MeshDeliveryFixtures"),
            invariant: packageKeychainFixtureEnumInvariant),
        PackageKeychainFile(
            file: "MeshDialPolicyTests.swift", kind: .suite,
            invariant: packageKeychainSuiteInvariant),
        PackageKeychainFile(
            file: "MeshIntroductionAuthorityTests.swift", kind: .readsFirst(type: "MeshLedgerChainFixture"),
            invariant: """
                the fixture's one initializer reads PackageTestEnvironment.keychain first and every keychain \
                line of the file sits in one of its instance members (the initializer that provisions its \
                three identities, the teardown that deletes their rows and the admission it signs), so none \
                runs before a fixture exists and the in-memory store is ProximityKit's keychain backend; the \
                file's suite builds its identities only through the fixture
                """),
        PackageKeychainFile(
            file: "MeshKeyAgreementAdvertisementTests.swift", kind: .fixtureEnum(type: "MeshKeyAgreementFixtures"),
            invariant: packageKeychainFixtureEnumInvariant),
        PackageKeychainFile(
            file: "MeshKeyAgreementAdvertisementTests.swift", kind: .suite,
            invariant: packageKeychainSuiteInvariant),
        PackageKeychainFile(
            file: "MeshMembershipEventWireTests.swift", kind: .suite,
            invariant: packageKeychainSuiteInvariant),
        PackageKeychainFile(
            file: "MeshPartitionDetectionTests.swift", kind: .fixtureEnum(type: "MeshPartitionFixtures"),
            invariant: packageKeychainFixtureEnumInvariant),
        PackageKeychainFile(
            file: "MeshRecipientKeyWrapTests.swift", kind: .suite,
            invariant: packageKeychainSuiteInvariant),
        PackageKeychainFile(
            file: "MeshRoutedManifestTests.swift", kind: .suite,
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
    /// (``packageKeychainFiles``) replaced the per-line rows of the files that reach the keychain; moved
    /// here at A1.1.13; 43 since plan step A1, when the suites copied from Fernlet's tests brought 20; 76
    /// since plan step A1.3's batch D (the routed track), when the routed source walls copied from
    /// Fernlet's tests brought 33; 89 since its mesh track, when the cells of Fernlet's mesh tests that
    /// read this module's sources brought 13; 97 since its session track, when the session copies brought
    /// 8; 121 since its pair track, when the pair copies brought 24; 122 since its review, when the goodbye
    /// walls' home list brought 1; 124 since plan step A2's groundwork, when the cross-version fixture
    /// suite's two store constructions brought 2; 125 since plan step A1's second batch of copied suites,
    /// its support, when the identity's call-shape binding brought 1 (``packageTestBindingLines``); 136
    /// since its copies, when the bindings they need brought 2 more and the copies 9 (two pure static
    /// reads, one bare declaration in a file on no keychain list and six throwaway-coordinator lines); 140
    /// since plan step A1's third batch of copied suites, its support, when the two seal keys' open-read
    /// bindings brought 4. The rows spell a needle the per-file rule does not cover: the soundness suite's
    /// storage cell, which reads `URL.applicationSupportDirectory` as a value; the package's file locator's
    /// one read of its own source's path; the routed store isolation walls' suite, whose own name spells
    /// the store's; the namespace and platform walls' needles inside literals
    /// (``packageNamespaceWallLines``, ``packagePlatformWallLines``); the package's call-shape bindings'
    /// lines that name a keychain-reaching type (``packageTestBindingLines``); the copied suites' reads of
    /// a keychain-reaching type's statics, their source walls' needles inside literals, their bare
    /// declarations in a file on no keychain list and their throwaway coordinators
    /// (``packageCopiedStaticLines``, ``packageCopiedSourceTextLines``, ``packageCopiedRoutedWallLines``,
    /// ``packageCopiedDeclarationLines``, ``packageCopiedCoordinatorLines``); and the cross-version fixture
    /// suite's two stores over copies of a tag's fixture folders (``packageCrossVersionStoreLines``); each
    /// set under one invariant.
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
            nothing; a package suite reads only Package.swift, Sources/ProximityKit/**, Tests/** and the \
            example app's namespace file, Examples/ProximityPing/ProximityPing/PingNamespace.swift, under \
            that root, by a path relative to it
            """),
        (file: "MeshRoutedStoreIsolationTests.swift",
         line: "struct MeshRoutedStoreIsolationTests {",
         invariant: """
            the needle is the head of the suite's own name, which the copy keeps from the Fernlet \
            repository's tests so it reads beside its original (ProximityKit plan step A1.3's batch D); \
            the line declares a suite of source walls that read ProximityKit's code as text, so it builds \
            no store, reaches no keychain and reads, writes and creates nothing at any location
            """)
    ] + packageNamespaceWallLines.map {
        (file: packageNamespaceWallFile, line: $0, invariant: packageNamespaceWallInvariant)
    } + packagePlatformWallLines.map {
        (file: packagePlatformWallFile, line: $0, invariant: packagePlatformWallInvariant)
    } + packageCopiedStaticLines.map {
        (file: $0.file, line: $0.line, invariant: packageCopiedStaticInvariant)
    } + packageCopiedSourceTextLines.map {
        (file: $0.file, line: $0.line, invariant: packageCopiedSourceTextInvariant)
    } + packageCopiedRoutedWallLines.map {
        (file: $0.file, line: $0.line, invariant: packageCopiedRoutedWallInvariant)
    } + packageCrossVersionStoreLines.map {
        (file: $0.file, line: $0.line, invariant: packageCrossVersionStoreInvariant)
    } + packageTestBindingLines.map {
        (file: "TestSupport/PackageTestBindings.swift", line: $0, invariant: packageTestBindingInvariant)
    } + packageCopiedDeclarationLines.map {
        (file: $0.file, line: $0.line, invariant: packageCopiedDeclarationInvariant)
    } + packageCopiedCoordinatorLines.map {
        (file: $0.file, line: $0.line, invariant: packageCopiedCoordinatorInvariant)
    }

    /// What makes every line of ``packageCrossVersionStoreLines`` safe in the unhosted bundle (rule I9).
    static let packageCrossVersionStoreInvariant = """
        the store is built in a cell of CrossVersionFixtureTests, a file on packageKeychainFiles whose suite \
        reads PackageTestEnvironment.keychain first, over a scope of the cell's own: a fresh folder under the \
        temporary directory named for the suite instance, holding a copy of a released tag's fixture \
        folder, and a keychain service of the instance's own (the fixture's service and the instance's \
        suffix) that the cell seeded with the fixture's seal-key row just before; so the store reads and \
        writes only that copy and that row, never the bundle's fixtures, a production directory or a row \
        another cell holds
        """

    /// The cross-version fixture suite's store constructions, each exact as trimmed (rule I9; ProximityKit
    /// plan step A2's groundwork): Bob's routed store and session store, opened over copies of the
    /// `0.1.0` fixture folders his stores wrote.
    static let packageCrossVersionStoreLines: [(file: String, line: String)] = [
        (file: "CrossVersionFixtureTests.swift", line: "let store = MeshRoutedStore(scope: scope)"),
        (file: "CrossVersionFixtureTests.swift", line: "return MeshSessionStore(scope: scope).load()")
    ]

    /// What makes every line of ``packageCopiedStaticLines`` safe in the unhosted bundle (rule I9).
    static let packageCopiedStaticInvariant = """
        the needle is a type's name in front of one of its statics: a constant \
        (MeshNetworkManager.maxReGossipFrames, IdentityService.presenceEpochSeconds, and \
        MeshRoutedStoreFormat.maxItems, whose type's name holds the store's) or a nonisolated pure \
        function of its arguments (MeshNetworkManager.shouldInitiateInvite(localSessionID:peerSessionID:), \
        IdentityService.fingerprint(of:), IdentityService.verify(_:of:by:purpose:)); nothing on the line \
        builds an instance, so no identity provisions, no store opens and nothing reaches the keychain
        """

    /// The copied suites' lines that read a keychain-reaching type's static, each exact as trimmed (rule
    /// I9; ProximityKit plan step A1, the split's first batch of copied suites).
    static let packageCopiedStaticLines: [(file: String, line: String)] = [
        (file: "MeshMergeWindowTests.swift",
         line: "#expect(MeshMergeWindow.maxProofs == MeshNetworkManager.maxReGossipFrames,"),
        (file: "MeshRoutedRetryAllowanceTests.swift",
         line: "for position in 0..<MeshRoutedStoreFormat.maxItems where !refusedInsideTheCap {"),
        (file: "MeshRoutedRetryAllowanceTests.swift",
         line: "#expect(rotation.attempted.count == MeshRoutedStoreFormat.maxItems)"),
        (file: "MeshRoutedRetryAllowanceTests.swift",
         line: "let overCap = try Self.key(MeshRoutedStoreFormat.maxItems)"),
        (file: "MeshRoutedRetryAllowanceTests.swift",
         line: #"#expect(rotation.attempted.count == MeshRoutedStoreFormat.maxItems, "and does not grow")"#),
        (file: "MeshRoutedRetryAllowanceTests.swift",
         line: "#expect(rotation.order.count == MeshRoutedStoreFormat.maxItems)"),
        (file: "NetworkMeshTransportTests.swift",
         line: "let dials = MeshNetworkManager.shouldInitiateInvite("),
        (file: "NetworkMeshTransportTests.swift",
         line: #"#expect(MeshNetworkManager.shouldInitiateInvite(localSessionID: "aaaa", peerSessionID: nil))"#),
        (file: "NetworkMeshTransportTests.swift",
         line: #"#expect(!MeshNetworkManager.shouldInitiateInvite(localSessionID: "aaaa", peerSessionID: "aaaa"))"#),
        (file: "NetworkMeshTransportTests.swift",
         line: "run.initiatorOutcome?.verifiedPeer?.fingerprint == IdentityService.fingerprint(of: bob.publicKey)"),
        (file: "PresenceEpochPostureTests.swift",
         line: "at: Self.anchor.addingTimeInterval(IdentityService.presenceEpochSeconds + 431),"),
        (file: "PresenceEpochPostureTests.swift",
         line: "#expect(mintInstants.last == Self.anchor.addingTimeInterval(IdentityService.presenceEpochSeconds),"),
        (file: "PresenceEpochPostureTests.swift",
         line: #"#expect(IdentityService.presenceEpochSeconds == 900, "the one named constant")"#),
        // Plan step A1's second batch of copied suites: a signature checked against a public key.
        (file: "MeshQuorumPartitionTests.swift", line: "#expect(IdentityService.verify("),
        (file: "MeshRoutedDrainAnswerTests.swift", line: "#expect(IdentityService.verify(")
    ]

    /// What makes every line of ``packageTestBindingLines`` safe in the unhosted bundle (rule I9).
    static let packageTestBindingInvariant = """
        the line declares a call-shape binding over a type that can reach the keychain: an extension of \
        IdentityService (its participant-less initializer under .packageTest and its static agreement's \
        old spelling) or a parameter of that type (the manifest mint and the typed envelope mint), or an \
        extension of a mesh store's seal key and the signature of its open read under .packageTest's \
        account, which names the type and runs nothing until a suite calls the binding; an identity's \
        initializer reads and writes nothing, and signing and the static agreement use the keys an \
        identity already holds, so whatever provisions an identity through a binding is a file whose own \
        kind reads PackageTestEnvironment.keychain first, and a seal key's open read reaches the keychain \
        only as a cell of such a file calls it
        """

    /// The package's call-shape bindings' lines that spell a keychain needle, each exact as trimmed, in
    /// TestSupport/PackageTestBindings.swift (rule I9; ProximityKit plan step A1's second batch of copied
    /// suites, which restored Fernlet's identity and envelope shapes there, and its third, which restored
    /// the two seal keys' open reads).
    static let packageTestBindingLines = [
        "extension IdentityService {",
        "identity: IdentityService",
        "identityService: IdentityService, envelopeID: UUID = UUID(), senderDisplayName: String,",
        "extension MeshSessionSealKey {",
        "static func forOpen(service: String) -> MeshSessionSealKeyOutcome {",
        "extension MeshRoutedSealKey {",
        "static func forOpen(service: String) -> MeshRoutedSealKeyOutcome {"
    ]

    /// What makes every line of ``packageCopiedDeclarationLines`` safe in the unhosted bundle (rule I9).
    static let packageCopiedDeclarationInvariant = """
        the line declares a stored property of a fixture value type with its type and no initializer \
        (a quorum roster's identities), in a file on no keychain list: it names IdentityService and runs \
        nothing, and the identities it holds are provisioned by a fixture enum that reads \
        PackageTestEnvironment.keychain first (MeshPartitionFixtures)
        """

    /// The copied suites' bare declarations of a keychain-reaching type in a file on no keychain list,
    /// each exact as trimmed (rule I9; ProximityKit plan step A1's second batch of copied suites). A bare
    /// declaration in a listed file needs no row (``isBareDeclaration(_:)``).
    static let packageCopiedDeclarationLines: [(file: String, line: String)] = [
        (file: "MeshQuorumPartitionTests.swift", line: "let identities: [IdentityService]")
    ]

    /// What makes every line of ``packageCopiedCoordinatorLines`` safe in the unhosted bundle (rule I9).
    static let packageCopiedCoordinatorInvariant = """
        the line builds a never-begun coordinator over a throwaway identity, a slot's stand-in that no \
        cell begins: an identity's initializer reads and writes nothing, and a coordinator provisions its \
        identity only when a session begins (its prepareSession), so neither the helper's declaration nor \
        its body reaches the keychain, whoever calls it and whenever
        """

    /// The copied suites' throwaway-coordinator helpers' lines, each exact as trimmed (rule I9;
    /// ProximityKit plan step A1's second batch of copied suites): a file-scoped helper and a suite's
    /// static, which the suite kind's structure would refuse as a keychain line outside a suite or in a
    /// static member that is not private.
    static let packageCopiedCoordinatorLines: [(file: String, line: String)] = [
        (file: "MemoryLifecycleTests.swift", line: "private func makeThrowawayCoordinator() -> ProximityCoordinator {"),
        (file: "MemoryLifecycleTests.swift",
         line: #"let identity = IdentityService(keychainService: "test.memory.lifecycle.\(UUID().uuidString)")"#),
        (file: "MemoryLifecycleTests.swift", line: "return ProximityCoordinator("),
        (file: "MeshDialPolicyTests.swift", line: "static func throwawayCoordinator() -> ProximityCoordinator {"),
        (file: "MeshDialPolicyTests.swift", line: "ProximityCoordinator("),
        (file: "MeshDialPolicyTests.swift",
         line: #"identity: IdentityService(keychainService: "test.mesh.dialpolicy.\(UUID().uuidString)"),"#)
    ]

    /// What makes every line of ``packageCopiedSourceTextLines`` safe in the unhosted bundle (rule I9).
    static let packageCopiedSourceTextInvariant = """
        the needle stands only inside a literal a copied source wall reads as text and never runs: the \
        package-relative path of a ProximityKit source the wall reads through PackageRoot, the name of a \
        ProximityKit source file the wall expects a walk of the module's sources to read or a home list \
        to find a needle in, a needle it looks for in that source's code (PresenceEpochPostureTests' and \
        MeshP9EphemeralPostureAcceptanceTests' lists of what a posture must never reach, the retry \
        planner's forbidden types, the presence clock's two calls, the identity's keychain reads, the \
        keychain item type the namespace golden counts), a sample line a copied matcher must read or pass \
        (the localization rules' fixtures), or a failure message; the code around it only reads and \
        matches text, so the line builds, provisions and installs nothing, reaches no keychain, opens no \
        store and reads, writes and creates nothing at any location
        """

    /// The copied suites' lines that spell a needle inside a source wall's literal, each exact as trimmed
    /// (rule I9; ProximityKit plan step A1, the split's first batch of copied suites, and plan step A1.3's
    /// batch D, the mesh, session and pair copies of the cells of Fernlet's tests that read this module's
    /// sources; the routed copies' rows are ``packageCopiedRoutedWallLines``).
    static let packageCopiedSourceTextLines: [(file: String, line: String)] = [
        (file: "MeshRoutedCustodyHandoffTests.swift",
         line: #"try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift")"#),
        (file: "MeshRoutedCustodyHandoffTests.swift",
         line: #""\(door) is gone from MeshNetworkManager.swift")"#),
        // The routed store's name and its parenthesis are two literals here, so the package's store walls
        // (`PackageTestTreeWallTests`), which read every package file's raw text for a construction of the
        // store, read none in this file.
        (file: "MeshRoutedRetryAllowanceTests.swift",
         line: #""MeshRoutedStore"# + #"(", "MeshRoutedIndex(", "ProximityAudit"] {"#),
        (file: "PresenceEpochPostureTests.swift",
         line: #""the posture must not write 900 down again — IdentityService.presenceEpochSeconds is the one home")"#),
        (file: "PresenceEpochPostureTests.swift",
         line: #"#expect(code.contains { $0.contains("IdentityService.presenceEpoch(at:") },"#),
        (file: "PresenceEpochPostureTests.swift",
         line: #""fingerprint", "Keychain", "KeychainItem", "SecItem", "kSecAttrService","#),
        (file: "PresenceEpochPostureTests.swift",
         line: #""UserDefaults", "FileManager", "write(to:", "JSONSidecarFile","#),
        // Plan step A1.3, batch D's mesh copies: the halves of the Fernlet repository's mesh tests that read
        // this module's sources.
        (file: "MeshNameWithholdingTests.swift",
         line: #"try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift")"#),
        (file: "MeshP5AcceptanceTests.swift",
         line: #"try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift")"#),
        (file: "MeshP6AcceptanceTests.swift",
         line: #"try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift")"#),
        (file: "MeshP7AcceptanceTests.swift",
         line: #"#expect(raised == ["MeshNetworkManager.swift", "MeshNetworkManager.swift"], """"#),
        (file: "MeshP8AcceptanceTests.swift",
         line: #"#expect(MeshP7Acceptance.homes(of: "applySessionEvent(.backgrounded", in: kit) == ["MeshNetworkManager.swift"],"#),
        (file: "MeshP8AcceptanceTests.swift",
         line: #"#expect(MeshP7Acceptance.homes(of: "applySessionEvent(.foregrounded", in: kit) == ["MeshNetworkManager.swift"],"#),
        (file: "MeshP8AcceptanceTests.swift",
         line: #"try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift"))"#),
        (file: "MeshP9AcceptanceTests.swift",
         line: #""Sources/ProximityKit/PairSession/ProximityPairSession.swift""#),
        (file: "MeshP9AcceptanceTests.swift",
         line: #"#expect(posture.contains("IdentityService.presenceEpochStart(at: now)"),"#),
        (file: "MeshP9AcceptanceTests.swift",
         line: #"#expect(posture.contains("IdentityService.presenceEpoch(at: now)"),"#),
        (file: "MeshP9AcceptanceTests.swift",
         line: #"let forbidden = ["UserDefaults", "Keychain", "KeychainItem", "SecItem", "FileManager","#),
        (file: "MeshP9AcceptanceTests.swift",
         line: #"try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift"))"#),
        (file: "MeshP9AcceptanceTests.swift",
         line: #"MeshNetworkManager.init no longer defaults its radio to \"#),
        (file: "MeshMembershipEventWireTests.swift",
         line: #"(file: "Mesh/MeshNetworkManager.swift", line: "case .sessionGoodbye:"),"#),
        // Plan step A1.3, batch D's session copies: the halves of the Fernlet repository's session,
        // continuation and photo-review cells that read this module's sources.
        (file: "MeshContinuationDriverTests.swift",
         line: #"private static let manager = "MeshNetworkManager.swift""#),
        (file: "MeshContinuationTaskHostTests.swift",
         line: #"private static let expectedHomes = ["ProximityCoordinator.swift", "MeshNetworkManager.swift", "ProximityPairSession.swift"]"#),
        (file: "MeshContinuationTaskHostTests.swift",
         line: #"try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift"))"#),
        (file: "MeshContinuationTaskHostTests.swift",
         line: #"let coordinatorPath = "Sources/ProximityKit/Engine/ProximityCoordinator.swift""#),
        (file: "MeshHeldSessionPhotoTests.swift",
         line: #"try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift")"#),
        (file: "MeshLastMemberPhotoReviewTests.swift",
         line: #"try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift")"#),
        (file: "RoutedShareRefusalCopyTests.swift",
         line: #"try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift")"#),
        (file: "SessionMessageTests.swift",
         line: #"try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift"))"#),
        // Plan step A1.3, batch D's pair copies: the source walls of the Fernlet repository's pair-session,
        // identity, golden, wipe, transport and localization tests that read this module's sources.
        (file: "FernletFeatureGoldenTests.swift",
         line: #"static let recipeDoorPath = "Sources/ProximityKit/PairSession/ProximityPairSession.swift""#),
        (file: "IdentityProvisioningReadTests.swift",
         line: #"let source = try PackageRoot.source("Sources/ProximityKit/Identity/IdentityService.swift")"#),
        (file: "IdentityProvisioningReadTests.swift",
         line: #"#expect(!source.contains("KeychainItem.load(account: accounts.\(row)"),"#),
        (file: "IdentityProvisioningReadTests.swift",
         line: #"let distinguishingReads = source.components(separatedBy: "KeychainItem.loadDistinguishingAbsence(").count - 1"#),
        (file: "LocalizationBoundaryTests.swift",
         line: #"Inside a package that resolves against Bundle.main, finds no catalog entry, and silently \"#),
        (file: "LocalizationBoundaryTests.swift",
         line: #"Bundle.main and will render untranslated English FOREVER — clean build, no warning, no \"#),
        (file: "LocalizationBoundaryTests.swift",
         line: #"own. A key carries no bundle, so it resolves against Bundle.main and never sees the \"#),
        (file: "LocalizationBoundaryTests.swift",
         line: ##"#expect(Self.localizedCalls(in: #"String(localized: "Saved", bundle: Bundle.main)"#).first?.passesBundle == false)"##),
        (file: "PrivacyWipeCoverageTests.swift",
         line: #""Sources/ProximityKit/Mesh/MeshNetworkManager.swift","#),
        (file: "PrivacyWipeCoverageTests.swift",
         line: #""Sources/ProximityKit/PairSession/ProximityPairSession.swift","#),
        (file: "PrivacyWipeCoverageTests.swift",
         line: #"#expect(source.contains("func wipeIdentityForDeleteAll"), "\(file) owns a live IdentityService but lost its wipe seam.")"#),
        (file: "ProximityNamespaceGoldenTests.swift",
         line: ##"let original = try NSRegularExpression(pattern: #"(?<![A-Za-z0-9_])KeychainItem\b"#)"##),
        (file: "ProximityNamespaceGoldenTests.swift",
         line: #"copyUses += code.components(separatedBy: "ProximityKeychainItem.").count - 1"#),
        (file: "ProximityNamespaceGoldenTests.swift",
         line: #"#expect(copyUses > 0, "the sweep found no `ProximityKeychainItem.` use: wrong tree?")"#),
        (file: "ProximityNamespaceGoldenTests.swift",
         line: #"ProximityKit code names FernletFoundation's KeychainItem in \(offenders). Reach the keychain \"#),
        (file: "ProximityNamespaceGoldenTests.swift",
         line: #"through `ProximityKeychainItem`, which issues the same queries."#),
        (file: "RecipeShareOverQUICTests.swift",
         line: #"#expect(!code.contains(needle), "ProximityPairSession still names `\(needle)` in code")"#),
        (file: "RecipeShareOverQUICTests.swift",
         line: #""a ProximityPairSession comment still describes `\(needle)` machinery")"#),
        (file: "RecipeShareOverQUICTests.swift",
         line: #"private static let managerPath = "Sources/ProximityKit/PairSession/ProximityPairSession.swift""#),
        (file: "RecipeShareOverQUICTests.swift",
         line: #"!$0.path.hasPrefix("PairSession/") && $0.text.contains("extension ProximityPairSession")"#),
        (file: "RecipeShareTransferTests.swift",
         line: #"try PackageRoot.source("Sources/ProximityKit/PairSession/ProximityPairSession.swift")"#),
        (file: "TransportNeutralityBoundaryTests.swift",
         line: #""Sources/ProximityKit/Engine/ProximityCoordinator.swift","#),
        (file: "TransportNeutralityBoundaryTests.swift",
         line: #""Sources/ProximityKit/Mesh/MeshNetworkManager.swift","#),
        (file: "TransportNeutralityBoundaryTests.swift",
         line: #""Sources/ProximityKit/PairSession/ProximityPairSession.swift","#)
    ]

    /// What makes every line of ``packageCopiedRoutedWallLines`` safe in the unhosted bundle (rule I9).
    static let packageCopiedRoutedWallInvariant = """
        the needle stands only inside a literal of a routed source wall copied from Fernlet's tests, which \
        reads ProximityKit's code as text and never runs it: the package-relative path or the file name of \
        a ProximityKit source the wall reads through PackageRoot or the walls' walker, a needle it counts \
        in that source's code, or a failure message; the code around it only reads and matches text, so \
        the line builds no store, reaches no keychain and reads, writes and creates nothing at any location
        """

    /// The routed source walls' lines that spell a needle inside a literal, each exact as trimmed (rule
    /// I9; ProximityKit plan step A1.3's batch D, the routed track: the walls copied from Fernlet's
    /// routed suites that read ProximityKit's sources).
    static let packageCopiedRoutedWallLines: [(file: String, line: String)] = [
        (file: "MeshRoutedBackpressureTests.swift",
         line: #"try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift")"#),
        (file: "MeshRoutedCustodyTests.swift",
         line: #""MeshRoutedStore.swift", "MeshRoutedCustody.swift", "MeshRoutedCustodyCommit.swift","#),
        (file: "MeshRoutedCustodyTests.swift",
         line: #""MeshRoutedIndex.swift", "MeshRoutedStoreKey.swift", "MeshRoutedContentHasher.swift","#),
        (file: "MeshRoutedCustodyTests.swift",
         line: #"if code.contains("ColumnCrypto") { sealing.append(name) }"#),
        (file: "MeshRoutedCustodyTests.swift",
         line: #"#expect(sealing == ["MeshRoutedStore.swift"], "the at-rest seal must live in one file: \(sealing)")"#),
        (file: "MeshRoutedDrainTests.swift",
         line: #"try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift")"#),
        (file: "MeshRoutedDrainTests.swift",
         line: #""\(door) is gone from MeshNetworkManager.swift")"#),
        (file: "MeshRoutedDrainTests.swift",
         line: #""\(declaration) is gone from MeshNetworkManager.swift")"#),
        (file: "MeshRoutedDrainTests.swift",
         line: #"Issue.record("\(declaration) is gone from MeshNetworkManager.swift")"#),
        (file: "MeshRoutedDrainTests.swift",
         line: #""\(symbol) came back to MeshNetworkManager.swift")"#),
        (file: "MeshRoutedDrainTests.swift",
         line: #"Issue.record("the routed drain section is gone from MeshNetworkManager.swift")"#),
        (file: "MeshRoutedDrainTests.swift",
         line: #""routedReplayCapacity is gone from MeshNetworkManager.swift""#),
        (file: "MeshRoutedDrainTests.swift",
         line: #"#expect(source.contains("MeshRoutedStore(scope: store.meshRoutedStorage)"))"#),
        (file: "MeshRoutedLockedDeviceTests.swift",
         line: #""MeshRoutedStore.swift", "MeshRoutedCustody.swift", "MeshRoutedCustodyCommit.swift","#),
        (file: "MeshRoutedLockedDeviceTests.swift",
         line: #""MeshRoutedIndex.swift", "MeshRoutedStoreKey.swift", "MeshRoutedContentHasher.swift","#),
        (file: "MeshRoutedLockedDeviceTests.swift",
         line: #"("routedCanonicalDispatch(", ["MeshNetworkManager.swift"], 0),"#),
        (file: "MeshRoutedLockedDeviceTests.swift",
         line: #"("dispatchRoutedPlaintext(", ["MeshNetworkManager.swift"], 2),"#),
        (file: "MeshRoutedLockedDeviceTests.swift",
         line: #"(".projectRoutedItem(", ["MeshNetworkManager.swift"], 1),"#),
        (file: "MeshRoutedLockedDeviceTests.swift",
         line: #"(".openThenProject(", ["MeshNetworkManager.swift"], 1),"#),
        (file: "MeshRoutedLockedDeviceTests.swift",
         line: #"(".judgeRoutedItem(", ["MeshNetworkManager.swift"], 1),"#),
        (file: "MeshRoutedLockedDeviceTests.swift",
         line: #"(".openThenJudge(", ["MeshNetworkManager.swift"], 1),"#),
        (file: "MeshRoutedLockedDeviceTests.swift",
         line: #"(".ledgerCommit(", ["MeshRoutedDeliveryCommit.swift", "MeshNetworkManager.swift"], 2)"#),
        (file: "MeshRoutedLockedDeviceTests.swift",
         line: #"let allowed: Set<String> = ["MeshRoutedAccessGate.swift", "MeshNetworkManager.swift"]"#),
        (file: "MeshRoutedLockedDeviceTests.swift",
         line: #"where !["MeshRoutedAccessGate.swift", "MeshNetworkManager.swift"].contains(source.name) {"#),
        (file: "MeshRoutedLockedDeviceTests.swift",
         line: #"let doors = Set(Self.custodyDoorFiles + ["MeshNetworkManager.swift"])"#),
        (file: "MeshRoutedLockedDeviceTests.swift",
         line: #""Sources/ProximityKit/Mesh/MeshRoutedStoreKey.swift","#),
        (file: "MeshRoutedLockedDeviceTests.swift",
         line: #""Sources/ProximityKit/Identity/IdentityService.swift""#),
        (file: "MeshRoutedPhotoDeliveryTests.swift",
         line: #"try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift")"#),
        (file: "MeshRoutedRefusalBudgetTests.swift",
         line: #"try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift")"#),
        (file: "MeshRoutedStoreIsolationTests.swift",
         line: #"let store = try PackageRoot.source("Sources/ProximityKit/Mesh/MeshRoutedStore.swift")"#),
        (file: "MeshRoutedStoreIsolationTests.swift",
         line: #"#expect(constructionSites == ["MeshNetworkManager.swift"],"#),
        (file: "MeshRoutedStoreIsolationTests.swift",
         line: #"for name in ["MeshNetworkManager.swift"] {"#)
    ]

    /// The wall files rule I9 reads as code (ProximityKit plan step A1.1.13): a wall's file holds the
    /// needles it reads, their reasons and its fixtures as data in literals, which a line-by-line read of
    /// its text would refuse. So I9 reads a listed file's lexed code (`SwiftSourceLexer`: comments dropped,
    /// literals emptied), each line against every needle, and refuses a needle there as anywhere; no
    /// allowlist row and no keychain structure applies to it. A listed file that is gone, or that spells no
    /// needle in its text and so needs no exemption, is a failure, and so is a file on both this list and
    /// ``packageKeychainFiles``. The repository-path needles carry a quote, which lexed code never holds,
    /// so a wall file's literals are read at their start instead (``packageRepoPathFolders``): one that
    /// starts with a repository folder is refused, as the quoted needle refuses it on any other file's
    /// line, and a wall file reads a file through `PackageRoot` as every package file does.
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
    /// ``packageKeychainFiles`` that keeps its kinds' structure (``packageKeychainFileProblems(_:source:)``);
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
        // R2: bounded by the keychain file list, squared.
        for (index, listed) in packageKeychainFiles.enumerated()
        where packageKeychainFiles[..<index].contains(where: { $0.file == listed.file && $0.kind == listed.kind }) {
            problems.append("I9: \(listed.file) is on packageKeychainFiles twice under one kind")
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
    /// line and, in a file on ``packageKeychainFiles``, its keychain needles and its stores' names
    /// (``isListedFileNeedle(_:)``), which its kinds' structure holds instead; and the indices of the
    /// allowlist rows its lines matched.
    static func ordinaryFileProblems(_ file: PackageSwiftFiles.File) -> (problems: [String], allowed: Set<Int>) {
        var problems: [String] = []
        var allowed: Set<Int> = []
        let rows = packageKeychainFiles.filter { $0.file == file.path }
        // R2: bounded by the file's line count × the needle list.
        for line in file.text.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.hasPrefix("//") else { continue }
            if let row = packageHazardAllowlist.firstIndex(where: { $0.file == file.path && $0.line == trimmed }) {
                allowed.insert(row)
                continue
            }
            for hazard in packageHazardNeedles(onLine: trimmed)
            where rows.isEmpty || !isListedFileNeedle(hazard.needle) {
                problems.append("I9: \(file.path): `\(trimmed)` holds `\(hazard.needle)`: \(hazard.reason)")
            }
        }
        if !rows.isEmpty {
            problems += packageKeychainFileProblems(rows, source: file.text)
        }
        return (problems, allowed)
    }

    /// The repository folders a quoted repository-path needle of ``packageHazards`` names, each with its
    /// reason: the needle without its quote. A wall file's lexed code holds no quote, so its literals are
    /// read against these at their start (``wallFileProblems(_:invariant:)``).
    static let packageRepoPathFolders: [(folder: String, reason: String)] = packageHazards
        .filter { $0.needle.hasPrefix("\"") }
        .map { (folder: String($0.needle.dropFirst()), reason: $0.reason) }

    /// One wall file's I9 problems (``packageWallFiles``): every line of its lexed code (comments dropped,
    /// literals emptied) holds no needle, no literal of it starts with a repository folder
    /// (``packageRepoPathFolders``), and its text spells at least one needle, or it needs no exemption.
    static func wallFileProblems(_ file: PackageSwiftFiles.File, invariant: String) -> [String] {
        var problems: [String] = []
        let lexed = SwiftSourceLexer.lex(file.text)
        // R2: bounded by the file's line count × the needle list.
        for line in lexed.code.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            for hazard in packageHazardNeedles(onLine: trimmed) {
                problems.append("I9: \(file.path) (a wall file, read as code): `\(trimmed)` holds `\(hazard.needle)`: \(hazard.reason)")
            }
        }
        // R2: bounded by the file's literals × the folder list.
        for literal in lexed.literals {
            for path in packageRepoPathFolders where literal.text.hasPrefix(path.folder) {
                problems.append("I9: \(file.path):\(literal.line) (a wall file, its literal read at its start): `\(literal.text.prefix(80))` starts with `\(path.folder)`: \(path.reason)")
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
    /// is not read only where an identifier starts, so a raw `SecItem` call stands in no file, or a
    /// store's name (``packageListedStoreNeedles``), so a production scope's shorthand stands in none.
    static func isListedFileNeedle(_ needle: String) -> Bool {
        (packageKeychainNeedles.contains(needle) && !packageIdentifierStartNeedles.contains(needle))
            || packageListedStoreNeedles.contains(needle)
    }

    /// The 1-based code lines of `source` (trimmed text not starting `//`) that hold a needle a file on
    /// ``packageKeychainFiles`` may hold (``isListedFileNeedle(_:)``: a keychain needle or a store's
    /// name), an allowlist row of `file` and a bare declaration (``isBareDeclaration(_:)``) aside (rule
    /// I9).
    static func packageKeychainLines(in source: String, file: String) -> [Int] {
        var lines: [Int] = []
        // R2: bounded by the source's line count.
        for (offset, line) in source.components(separatedBy: "\n").enumerated() {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.hasPrefix("//"), !isBareDeclaration(trimmed),
                  !packageHazardAllowlist.contains(where: { $0.file == file && $0.line == trimmed }) else { continue }
            if packageHazardNeedles(onLine: trimmed).contains(where: { isListedFileNeedle($0.needle) }) {
                lines.append(offset + 1)
            }
        }
        return lines
    }

    /// Whether a trimmed line of a file on ``packageKeychainFiles`` is a bare declaration (rule I9): a
    /// stored property's or a parameter's name and type, with no initializer or default value, no call,
    /// member access, accessor or body, and no trailing comment, whole on its line (`let origin:
    /// IdentityService`, `of joiner: IdentityService,`, `founder: IdentityService, others:
    /// [IdentityService], meshID: UUID`). It names a type and runs nothing, so it reaches no keychain
    /// wherever it stands; a line that goes on to an initializer, a default, a call or a body holds `=`,
    /// `(`, `.` or `{` and stays a keychain line.
    static func isBareDeclaration(_ line: String) -> Bool {
        let pattern = #"^(?:(?:private|fileprivate|internal|public|package|nonisolated|weak|unowned)(?:\([a-z]+\))?\s+)*"#
            + #"(?:(?:let|var)\s+)?(?:[A-Za-z_][A-Za-z0-9_]*\s+)?[A-Za-z_][A-Za-z0-9_]*\s*:\s*[^=/{}().]+$"#
        return matchLines(pattern, in: line) == [1]
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

        /// Whether it is `private`: reachable from its own type and that type's extensions in the file,
        /// and from no other type. `fileprivate` is not: another type of the file, a second suite among
        /// them, reaches it; and `private(set)` is a setter's access, not its own.
        var isPrivate: Bool {
            PackageTestHygieneTests.matchLines(#"(?<![A-Za-z0-9_])private(?![A-Za-z0-9_(])"#,
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

    /// The last line of the declaration whose keyword stands on `head`: its heading runs on while the
    /// parentheses and brackets opened from `head` stay open (a signature or an initializer written over
    /// several lines) or a line ends with an assignment's `=` (an initializer that starts on the next
    /// line); then, when the heading opens a brace, the declaration ends where that brace closes, and
    /// otherwise with its heading.
    static func declarationEnd(from head: Int, in code: [String]) -> Int {
        var heading = head
        var open = 0
        // R2: bounded by the lines from `head` on.
        for index in head..<code.count {
            open += code[index].filter { "([".contains($0) }.count - code[index].filter { ")]".contains($0) }.count
            heading = index
            if open <= 0 && !endsWithAssignment(code[index]) { break }
        }
        guard code[head...heading].contains(where: { $0.contains("{") }) else { return heading }
        var depth = 0
        // R2: bounded by the lines from `head` on.
        for index in head..<code.count {
            depth += code[index].filter { $0 == "{" }.count - code[index].filter { $0 == "}" }.count
            if depth <= 0 && index >= heading { return index }
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

    /// The ways a file on ``packageKeychainFiles`` fails the structure its kinds name (rule I9), read
    /// over its lexed code: its keychain lines (``packageKeychainLines(in:file:)``) each sit where one of
    /// its kinds says, and it holds at least one, since a listed file with none would outlive its need.
    /// A file listed under one kind hands that kind every keychain line; a file listed under several
    /// hands each kind the lines inside the types it names (``keychainDomain(of:in:)``), and a line inside
    /// none of them is a problem of its own. A file whose keychain lines name a store
    /// (``packageListedStoreNeedles``) states ``packageKeychainFileStoreInvariant`` in one of its rows, and
    /// a file whose lines name none states it in none (``storeClauseProblems(_:source:keychain:)``).
    ///
    /// - Parameters:
    ///   - rows: The file's rows on ``packageKeychainFiles``, one per kind.
    ///   - source: The file's text.
    static func packageKeychainFileProblems(_ rows: [PackageKeychainFile], source: String) -> [String] {
        guard let file = rows.first?.file else { return [] }
        let code = SwiftSourceLexer.lex(source).code.components(separatedBy: "\n")
        let keychain = packageKeychainLines(in: source, file: file).map { $0 - 1 }
        var problems: [String] = keychain.isEmpty ? ["holds no keychain needle; delete its rows on packageKeychainFiles"] : []
        let domains = rows.map { keychainDomain(of: $0.kind, in: code) }
        var owned: [[Int]] = rows.map { _ in [] }
        // R2: bounded by the file's keychain lines × its rows.
        for line in keychain {
            if let index = domains.firstIndex(where: { $0.contains(line) }) {
                owned[index].append(line)
            } else if rows.count == 1 {
                owned[0].append(line)
            } else {
                problems.append("line \(line + 1) reaches the keychain outside every type its rows name (\(rows.map { describe($0.kind) }.joined(separator: ", ")))")
            }
        }
        // R2: bounded by the file's rows.
        for (index, row) in rows.enumerated() {
            problems += keychainKindProblems(row.kind, code: code, source: source, keychain: owned[index], all: keychain)
        }
        problems += storeClauseProblems(rows, source: source, keychain: keychain)
        return problems.map { "I9: \(file) \($0)" }
    }

    /// Whether a listed file's rows state ``packageKeychainFileStoreInvariant`` exactly when one of its
    /// keychain lines (`keychain`, 0-based) names a store (rule I9): a store line under no row that states
    /// the clause, or a row stating it over a file that holds none, is a problem.
    static func storeClauseProblems(_ rows: [PackageKeychainFile], source: String, keychain: [Int]) -> [String] {
        let lines = source.components(separatedBy: "\n")
        let stores = keychain.filter { line in
            packageHazardNeedles(onLine: lines[line].trimmingCharacters(in: .whitespaces))
                .contains { packageListedStoreNeedles.contains($0.needle) }
        }
        let states = rows.contains { $0.invariant.contains(packageKeychainFileStoreInvariant) }
        if let first = stores.first, !states {
            return ["line \(first + 1) names a store, but none of its rows on packageKeychainFiles states packageKeychainFileStoreInvariant"]
        }
        if stores.isEmpty && states {
            return ["states packageKeychainFileStoreInvariant but names no store on a keychain line; drop the store clause from its rows"]
        }
        return []
    }

    /// One kind's problems over the keychain lines it holds, `keychain`, of the file's, `all` (rule I9),
    /// 0-based.
    private static func keychainKindProblems(
        _ kind: PackageKeychainFileKind, code: [String], source: String, keychain: [Int], all: [Int]
    ) -> [String] {
        switch kind {
        case .suite:
            return suiteKeychainProblems(code: code, source: source, keychain: keychain, all: all)
        case .installer:
            return installerKeychainProblems(code: code, keychain: keychain)
        case .readsFirst(let type):
            return readsFirstKeychainProblems(code: code, type: type, keychain: keychain)
        case .fixtureEnum(let type):
            return fixtureEnumKeychainProblems(code: code, type: type, keychain: keychain)
        }
    }

    /// The 0-based lexed lines a kind holds in a file listed under several (rule I9): every `@Suite`
    /// type's lines for ``PackageKeychainFileKind/suite``, the named top-level type's for
    /// ``PackageKeychainFileKind/readsFirst(type:)`` and ``PackageKeychainFileKind/fixtureEnum(type:)``,
    /// and the whole file for the installer.
    static func keychainDomain(of kind: PackageKeychainFileKind, in code: [String]) -> Set<Int> {
        let types = topLevelTypes(in: code)
        let spans: [StructureDeclaration]
        switch kind {
        case .suite:
            spans = types.filter(\.isSuite).map(\.declaration)
        case .installer:
            return Set(code.indices)
        case .readsFirst(let name), .fixtureEnum(let name):
            spans = types.filter { $0.name == name }.map(\.declaration)
        }
        return Set(spans.flatMap { Array($0.first...$0.last) })
    }

    /// A kind as a problem names it.
    private static func describe(_ kind: PackageKeychainFileKind) -> String {
        switch kind {
        case .suite: return "@Suite types"
        case .installer: return "the installer"
        case .readsFirst(let type): return "`\(type)`"
        case .fixtureEnum(let type): return "the fixture enum `\(type)`"
        }
    }

    /// A suite file's structure (rule I9, ``PackageKeychainFileKind/suite``), its keychain lines 0-based:
    /// each sits in a `@Suite` type, never in one of its static members or nested types that is not
    /// `private`; every `@Suite` type that holds one reads a ready marker in its first stored property; and
    /// nothing in the file that reaches the keychain runs without an instance
    /// (``suiteRunsAloneProblems(code:source:keychain:)``), over the file's keychain lines, `all`.
    private static func suiteKeychainProblems(code: [String], source: String, keychain: [Int], all: [Int]) -> [String] {
        var problems: [String] = []
        let suites = topLevelTypes(in: code).filter(\.isSuite)
        if suites.isEmpty {
            problems.append("declares no @Suite type, so its keychain lines sit in no suite instance")
        }
        var holding: Set<String> = []
        // R2: bounded by the file's keychain lines.
        for line in keychain {
            guard let suite = suites.first(where: { $0.declaration.first <= line && line <= $0.declaration.last }) else {
                problems.append("line \(line + 1) reaches the keychain outside every @Suite type")
                continue
            }
            holding.insert(suite.name)
            let owner = owningMember(of: line, in: structureMembers(of: suite.declaration, in: code))
            guard let owner, !owner.isPrivate else { continue }
            if owner.isStatic {
                problems.append("line \(line + 1) reaches the keychain in a static member that is not private, which another file can call before any suite instance exists")
            } else if nestedTypeKeywords.contains(owner.keyword) {
                problems.append("line \(line + 1) reaches the keychain in a nested type that is not private, which another file can reach before any suite instance exists")
            }
        }
        // R2: bounded by the file's suites.
        for suite in suites where holding.contains(suite.name) {
            let first = structureMembers(of: suite.declaration, in: code).first { $0.isStoredProperty && !$0.isStatic }
            let marked = first.map { member in packageKeychainReadyMarkers.contains { member.text.contains($0) } } ?? false
            if !marked {
                problems.append("`\(suite.name)`'s first stored property reads none of \(packageKeychainReadyMarkers), so a cell may reach the keychain before the installer has run")
            }
        }
        return problems + suiteRunsAloneProblems(code: code, source: source, keychain: all)
    }

    /// The keywords of a type declared as a member of another.
    private static let nestedTypeKeywords: Set<String> = ["struct", "class", "enum", "actor"]

    /// What a suite file runs without an instance that may reach the keychain (rule I9,
    /// ``PackageKeychainFileKind/suite``), by 1-based line: a static or a free test; a trait or an
    /// argument but `.serialized`, a display name and a literal or `.allCases` collection with no call and
    /// no keychain needle (``attributeArgumentProblems(in:)``); a static stored property whose initializer
    /// spells a keychain needle or names a static member of the file that holds a keychain line
    /// (``keychainStaticPropertyLines(code:keychain:)``); and a global stored property. `keychain` is the
    /// file's keychain lines, 0-based.
    private static func suiteRunsAloneProblems(code: [String], source: String, keychain: [Int]) -> [String] {
        let lexed = code.joined(separator: "\n")
        let staticTest = #"@Test(?![A-Za-z0-9_])(?:\s*\([^)]*\))?(?:\s+@[A-Za-z_]+(?:\([^)]*\))?)*\s+"#
            + #"(?:(?:private|fileprivate|internal|public|nonisolated|final)\s+)*(?:static|class)\s+func"#
        let runsAlone: [(lines: [Int], what: String)] = [
            (matchLines(staticTest, in: lexed), "declares a static test"),
            (freeTestLines(in: source), "declares a free test"),
            (keychainStaticPropertyLines(code: code, keychain: keychain),
             "declares a static stored property whose initializer reaches the keychain"),
            (structureDeclarations(in: code, range: 0..<code.count, depth: 0)
                .filter { $0.keyword == "let" || $0.keyword == "var" }.map { $0.head + 1 },
             "declares a global stored property")
        ]
        var problems: [String] = []
        // R2: bounded by the four rules × their lines.
        for rule in runsAlone {
            for line in rule.lines {
                problems.append("line \(line) \(rule.what), which runs without a suite instance")
            }
        }
        // R2: bounded by the file's test and suite attributes.
        for refused in attributeArgumentProblems(in: lexed) {
            problems.append("line \(refused.line) hands a test or a suite arguments or traits that run before any suite instance exists: `\(refused.item)` (only .serialized, a display name, and a literal array or a type's .allCases with no call and no keychain needle)")
        }
        return problems
    }

    /// The 1-based lines of the static stored properties of lexed `code` whose initializer reaches the
    /// keychain (rule I9): it spans one of the file's keychain lines (`keychain`, 0-based), or names, as an
    /// identifier, a static member of one of the file's top-level types that holds one. Such a property
    /// runs on its first touch, which an argument collection can make before any suite instance exists.
    static func keychainStaticPropertyLines(code: [String], keychain lines: [Int]) -> [Int] {
        let keychain = Set(lines)
        var statics: Set<String> = []
        // R2: bounded by the file's top-level types × their members.
        for type in topLevelTypes(in: code) {
            for member in structureMembers(of: type.declaration, in: code)
            where member.isStatic && (member.first...member.last).contains(where: keychain.contains) {
                statics.formUnion(declaredNames(in: member.heading))
            }
        }
        let pattern = #"(?<![A-Za-z0-9_])static\s+(?:let|var)\s+[A-Za-z_][A-Za-z0-9_]*\s*(?::[^={\n]*)?="#
        var lines: [Int] = []
        // R2: bounded by the file's static stored properties.
        for head in matchLines(pattern, in: code.joined(separator: "\n")).map({ $0 - 1 }) where head >= 0 {
            let end = expressionEnd(from: head, in: code)
            let text = code[head...end].joined(separator: "\n")
            let named = statics.contains { !matchLines("(?<![A-Za-z0-9_])\($0)(?![A-Za-z0-9_])", in: text).isEmpty }
            if (head...end).contains(where: keychain.contains) || named {
                lines.append(head + 1)
            }
        }
        return lines
    }

    /// The names a member's heading declares: its function's, property's or subscript's.
    private static func declaredNames(in heading: String) -> Set<String> {
        guard let regex = try? NSRegularExpression(pattern: #"(?:func|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)"#) else { return [] }
        let text = heading as NSString
        return Set(regex.matches(in: heading, range: NSRange(location: 0, length: text.length))
            .map { text.substring(with: $0.range(at: 1)) })
    }

    /// The last 0-based line of the expression that starts on `head`: where its parentheses, brackets
    /// and braces, counted from the line's start, close, past every line that ends with an assignment's
    /// `=` (an initializer that starts on the next line).
    static func expressionEnd(from head: Int, in code: [String]) -> Int {
        var depth = 0
        // R2: bounded by the lines from `head` on.
        for index in head..<code.count {
            depth += code[index].filter { "([{".contains($0) }.count - code[index].filter { ")]}".contains($0) }.count
            if depth <= 0 && !endsWithAssignment(code[index]) { return index }
        }
        return code.count - 1
    }

    /// Whether a lexed line ends with an assignment's `=` (not `==`), so the expression it opens goes on
    /// on the next line.
    static func endsWithAssignment(_ line: String) -> Bool {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        return trimmed.hasSuffix("=") && !trimmed.hasSuffix("==")
    }

    /// Every item of a `@Test(…)` or `@Suite(…)` attribute in lexed code that runs code before a suite
    /// instance exists (rule I9), with the 1-based line of its attribute: anything but `.serialized`, a
    /// display name (a literal with no interpolation, `""` once lexed), and, after `arguments:`, a
    /// collection that is a literal array holding no call (no `(`), no keychain needle and no name of a
    /// static member the file declares but a literal constant (``argumentStaticNames(in:)``), or a type's
    /// `.allCases` the file does not declare itself. Swift Testing evaluates an attribute's items as it
    /// plans the run, before it builds any suite instance, so they may reach nothing the installer must
    /// precede, and a static member the file declares may reach the keychain however it is spelled.
    static func attributeArgumentProblems(in lexed: String) -> [(line: Int, item: String)] {
        guard let regex = try? NSRegularExpression(pattern: #"@(?:Test|Suite)(?![A-Za-z0-9_])\s*\("#) else { return [(-1, "")] }
        let statics = argumentStaticNames(in: lexed.components(separatedBy: "\n"))
        let text = Array(lexed)
        let ns = lexed as NSString
        var found: [(line: Int, item: String)] = []
        // R2: bounded by the file's attributes.
        for match in regex.matches(in: lexed, range: NSRange(location: 0, length: ns.length)) {
            let open = ns.substring(to: match.range.location + match.range.length).count
            let line = ns.substring(to: match.range.location).count(where: { $0 == "\n" }) + 1
            var collections = false
            // R2: bounded by the attribute's items.
            for item in attributeItems(text, from: open) {
                if item == "\"\"" || item == ".serialized" { continue }
                if item.hasPrefix("arguments:") {
                    collections = true
                    if isPlainCollection(String(item.dropFirst("arguments:".count)), statics: statics) { continue }
                } else if collections && isPlainCollection(item, statics: statics) {
                    continue
                }
                found.append((line, item))
            }
        }
        return found
    }

    /// The top-level items of the attribute argument list that opens just before `start` in `text`,
    /// each trimmed, up to the parenthesis that closes it.
    private static func attributeItems(_ text: [Character], from start: Int) -> [String] {
        var items: [String] = []
        var current = ""
        var depth = 0
        // R2: bounded by the text from `start` on; the list ends at its closing parenthesis.
        for character in text[start...] {
            if "([{".contains(character) { depth += 1 }
            if ")]}".contains(character) {
                if depth == 0 { break }
                depth -= 1
            }
            if character == "," && depth == 0 {
                items.append(current.trimmingCharacters(in: .whitespacesAndNewlines))
                current = ""
            } else {
                current.append(character)
            }
        }
        items.append(current.trimmingCharacters(in: .whitespacesAndNewlines))
        return items.filter { !$0.isEmpty }
    }

    /// Whether an argument collection evaluates nothing the installer must precede (rule I9): a type's
    /// `.allCases`, or a literal array that holds no call, no keychain needle and no store's name; and
    /// either way, no name among `statics`, the static members the file declares but its literal
    /// constants (an `allCases` the file declares itself among them).
    private static func isPlainCollection(_ text: String, statics: Set<String>) -> Bool {
        let collection = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let names = matchedNames(#"[A-Za-z_][A-Za-z0-9_]*"#, in: collection)
        guard names.isDisjoint(with: statics) else { return false }
        if matchLines(#"^[A-Za-z_][A-Za-z0-9_.]*\.allCases$"#, in: collection) == [1] { return true }
        guard collection.hasPrefix("["), collection.hasSuffix("]"), !collection.contains("(") else { return false }
        return !packageHazardNeedles(onLine: collection).contains { isListedFileNeedle($0.needle) }
    }

    /// The names of the static members lexed `code` declares, at any depth, that an argument collection
    /// may not name (rule I9): every static or class function, subscript and property, but a static `let`
    /// whose initializer, whole on its line, is a literal constant (a number, a string with no
    /// interpolation, `true` or `false`), which evaluates nothing.
    static func argumentStaticNames(in code: [String]) -> Set<String> {
        let pattern = #"^(?:@[A-Za-z_][A-Za-z0-9_.]*(?:\([^)]*\))?\s+)*(?:[a-z]+(?:\([a-z]+\))?\s+)*"#
            + #"(?:static|class)\s+(?:[a-z]+(?:\([a-z]+\))?\s+)*(let|var|func|subscript)\s*([A-Za-z_][A-Za-z0-9_]*)?(.*)$"#
        let constant = #"^\s*(?::[^=]*)?=\s*(?:-?[0-9][0-9_]*(?:\.[0-9_]+)?|""|true|false)\s*$"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        var names: Set<String> = []
        // R2: bounded by the code's lines.
        for line in code {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            let text = trimmed as NSString
            guard let match = regex.firstMatch(in: trimmed, range: NSRange(location: 0, length: text.length)),
                  match.range(at: 2).location != NSNotFound else { continue }
            let keyword = text.substring(with: match.range(at: 1))
            if keyword == "let" && matchLines(constant, in: text.substring(with: match.range(at: 3))) == [1] { continue }
            names.insert(text.substring(with: match.range(at: 2)))
        }
        return names
    }

    /// The distinct texts `pattern` matches in `text`.
    private static func matchedNames(_ pattern: String, in text: String) -> Set<String> {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let ns = text as NSString
        return Set(regex.matches(in: text, range: NSRange(location: 0, length: ns.length)).map { ns.substring(with: $0.range) })
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
        for line in keychain where !isBareTypeHead(line, of: type.declaration, in: code) {
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

    /// A fixture enum's structure (rule I9, ``PackageKeychainFileKind/fixtureEnum(type:)``), its keychain
    /// lines 0-based: every one sits in a member of the top-level enum `name` that is a function, an
    /// initializer, a subscript or a computed property, never a stored property's initializer or a nested
    /// type, and every member that holds one, whatever its access, reads `PackageTestEnvironment.keychain`
    /// in its first statement.
    private static func fixtureEnumKeychainProblems(code: [String], type name: String, keychain: [Int]) -> [String] {
        guard let type = topLevelTypes(in: code).first(where: { $0.name == name && $0.declaration.keyword == "enum" }) else {
            return ["declares no enum `\(name)`, the fixture its keychain lines must sit in"]
        }
        var problems: [String] = []
        let members = structureMembers(of: type.declaration, in: code)
        var unread: Set<Int> = []
        // R2: bounded by the file's keychain lines.
        for line in keychain where !isBareTypeHead(line, of: type.declaration, in: code) {
            guard type.declaration.first <= line && line <= type.declaration.last,
                  let owner = owningMember(of: line, in: members) else {
                problems.append("line \(line + 1) reaches the keychain outside every member of the fixture enum `\(name)`")
                continue
            }
            if owner.isStoredProperty || nestedTypeKeywords.contains(owner.keyword) {
                problems.append("line \(line + 1) reaches the keychain in a stored property's initializer or a nested type of `\(name)`, which runs on first touch, before any read of PackageTestEnvironment.keychain")
            } else if !firstStatement(of: owner, in: code).contains("PackageTestEnvironment.keychain") {
                unread.insert(owner.head)
            }
        }
        // R2: bounded by the members that hold a keychain line.
        for head in unread.sorted() {
            problems.append("`\(name)`'s member on line \(head + 1) reaches the keychain but does not read PackageTestEnvironment.keychain in its first statement")
        }
        return problems
    }

    /// Whether 0-based `line` is the head of `type`'s own declaration and declares nothing else (rule I9):
    /// the line its keyword stands on, its lexed code ending at the one brace that opens the type's body.
    /// A type's name runs nothing, so a fixture or support type whose own name holds a needle (the store
    /// fixtures' `MeshRoutedStoreFixtures`, ProximityKit plan step A1's third batch of copied suites) does
    /// not reach the keychain on that line; a member written on the same line is still read.
    static func isBareTypeHead(_ line: Int, of type: StructureDeclaration, in code: [String]) -> Bool {
        let trimmed = code[line].trimmingCharacters(in: .whitespaces)
        return line == type.head && trimmed.hasSuffix("{") && trimmed.filter { $0 == "{" }.count == 1
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
    /// byte and could not travel. Every system module here travels with the package, on every platform it
    /// builds for. CryptoKit, Observation and Security joined at plan step A1 for the suites copied from
    /// Fernlet's tests: the TLS identity's certificate mint and parse (`SecCertificate…`), the channel
    /// introduction harness's `Curve25519` keys and the observation loop's `@Observable` fixture. Security
    /// names no keychain call by itself: rule I9 refuses a raw `SecItem` call in every file, so a file that
    /// imports Security still reaches the keychain only through ProximityKit's funnel and the in-memory
    /// store, whose own file imports it to read the funnel's query dictionaries by their Security keys.
    static let packageImportAllowlist: Set<String> = [
        "ProximityKit", "Foundation", "Testing", "Combine", "CryptoKit", "Observation", "Security", "simd",
        "Synchronization"
    ]

    /// I11's problems over the package's files: each module a file imports that the allowlist lacks.
    static func packageImportProblems(in files: [PackageSwiftFiles.File]) -> [String] {
        var problems: [String] = []
        // R2: bounded by the package's file count × each file's imports.
        for file in files {
            for module in importedModules(in: file.text) where !packageImportAllowlist.contains(module) {
                problems.append("I11: \(file.path) imports `\(module)`; a file there may import only \(packageImportAllowlist.sorted()) (a host's module does not travel with ProximityKit's tests)")
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
    /// package's NEW `ProximityMemoryLifecycleTests`. RAISED at plan step A1 (2026-10-14): 25 → 58, for
    /// the 33 suites copied from Fernlet's tests (the split's first batch), each run on macOS and the iOS
    /// simulator. RAISED at plan step A1.2 (2026-10-15): 58 → 59, for the NEW `ExampleNamespaceTests`,
    /// which holds the example app's namespace apart. RAISED at the pair radio's rediscovery fix
    /// (2026-10-15): 59 → 60, for the package's NEW `ProximityPairSessionTests`. RAISED at plan step
    /// A1.3's batch D, the routed track (2026-10-15): 60 → 69, for the nine routed suites whose
    /// ProximityKit source walls are copied from Fernlet's tests. RAISED at plan step A1.3's batch D,
    /// mesh (2026-10-15): 69 → 82, for the 13 suites holding the cells of Fernlet's mesh tests that read
    /// this module's sources. RAISED at plan step A1.3's batch D, session (2026-10-15): 82 → 88, for the
    /// six suites of batch D's session copies, each holding the cells of the Fernlet suite of its name
    /// that read ProximityKit's sources (`LastMemberPhotoReviewSourceWallTests`,
    /// `MeshContinuationRaiseWallTests`, `MeshContinuationTaskHostWallTests`, `MeshHeldSessionPhotoTests`,
    /// `RoutedShareRefusalCopyTests`, `SessionMessageTests`). RAISED at plan step A1.3's batch D, pair
    /// (2026-10-15): 88 → 98, for the ten suites holding the cells of Fernlet's pair, presence, identity,
    /// golden, wipe, audit, transport and localization tests that read ProximityKit's sources. RAISED at
    /// plan step A1.3's final review (2026-10-15): 98 → 99, for the NEW `MeshP9HonestyAcceptanceTests`,
    /// which holds the `.remove` branch's stand-in that Fernlet's P9 honesty cell can no longer read.
    /// RAISED at plan step A2's groundwork (2026-10-15): 99 → 100, for the NEW `CrossVersionFixtureTests`,
    /// which decodes tag 0.1.0's wire and on-disk fixtures with today's code. RAISED at plan step A1's
    /// second batch of copied suites (2026-10-16): 100 → 117, for the 17 suites of Fernlet's tests that
    /// reach the keychain and open no store, sixteen of them and `IdentityServiceTests`, each copied with
    /// its name and run here. RAISED at the 0.1.1 listener fix (2026-10-16): 117 → 118, for the NEW
    /// `ProximityRadioListenerTests`, which holds every radio's listener unlimited and each radio's own cap
    /// and deadline in its place. A suite added, moved out or deleted changes it in the same commit, argued
    /// and measured; a deletion lowers it only with the retirement argued.
    static let measuredInventoryRows = 118

    /// The MEASURED sum of the rows' declared tests (rule I7). MEASURED at ProximityKit plan step A1.1.13
    /// (2026-10-14): 173 at A1.1.10 + this suite's 6. RAISED at A1.1.14 (2026-10-14): 179 → 185, for
    /// `PackageTestTreeWallTests`' 6. RAISED at A1.1.15 (2026-10-14): 185 → 191, for
    /// `ProximitySourceWallTests`' 6. RAISED at A1.1.16 (2026-10-14): 191 → 197, for the six cells the
    /// purpose wall and the escape-hatch census add to `ProximitySourceWallTests`. RAISED at A1.1.17
    /// (2026-10-14): 197 → 203, for `ProximityMemoryLifecycleTests`' 5 and the identity-construction cell
    /// `ProximitySourceWallTests` gains. RAISED at plan step A1 (2026-10-14): 203 → 508, for the copied
    /// suites' 305. RAISED at plan step A1.2 (2026-10-15): 508 → 513, for `ExampleNamespaceTests`' 5.
    /// RAISED at the pair radio's rediscovery fix (2026-10-15): 513 → 514, for
    /// `ProximityPairSessionTests`' 1. RAISED at plan step A1.3's batch D, the routed track (2026-10-15):
    /// 514 → 557, for the 43 routed source walls copied from Fernlet's tests. RAISED at plan step A1.3's
    /// batch D, mesh (2026-10-15): 557 → 575, for the 18 cells of Fernlet's mesh tests that read this
    /// module's sources. RAISED at plan step A1.3's batch D, session (2026-10-15): 575 → 583, for batch
    /// D's session copies' 8 (2 + 2 + 1 + 1 + 1 + 1). RAISED at plan step A1.3's batch D, pair
    /// (2026-10-15): 583 → 618, for the 35 tests of the ten suites holding the pair track's cells of
    /// Fernlet's tests that read ProximityKit's sources. RAISED at plan step A1.3's final review
    /// (2026-10-15): 618 → 619, for `MeshP9HonestyAcceptanceTests`' 1. RAISED at plan step A2's
    /// groundwork (2026-10-15): 619 → 643, for `CrossVersionFixtureTests`' 24. RAISED at plan step A1's
    /// second batch of copied suites, its support (2026-10-16): 643 → 644, for the
    /// `PackageTestSupportTests` cell that holds the switchable install binding to Fernlet's adapter,
    /// case for case. RAISED at its copies (2026-10-16): 644 → 801, for the 157 tests of its 17 suites
    /// (141 in the sixteen that reach the keychain and open no store, and `IdentityServiceTests`' 16).
    /// RAISED at the 0.1.1 inbound-hello fixes and diagnostics (2026-10-16): 801 → 807, for the six cells
    /// `ProximityPairSessionTests` gains (the stream-less connection, the hello deadline, the two-hello
    /// cap, the refusal reasons, the interface key and the inspector). RAISED at the 0.1.1 listener fix
    /// (2026-10-16): 807 → 810, for `ProximityRadioListenerTests`' 3 (the unlimited listeners, the caps and
    /// deadlines, presence's hello deadline). RAISED at the 0.1.1 hello deadline applied at every ruling
    /// and tag 0.1.0's verification ceremony fixtures (2026-10-16): 810 → 814, for the two cells
    /// `ProximityPairSessionTests` gains (a ruling's deadline after its own hello is marked read, and
    /// before an unreadable hello's refusal) and the two `CrossVersionFixtureTests` gains (the
    /// verification QR, and the challenge and response). RAISED at plan step A1's third batch of copied
    /// suites, its support (2026-10-16): 814 → 815, for the `PackageTestSupportTests` cell that holds the
    /// switchable install binding's scripted override, an answer a cell changes partway through the work
    /// it wraps, to the answers of Fernlet's adapter under `DeviceBindingID`'s. A test added or removed
    /// changes it in the same commit.
    static let measuredDeclaredTests = 815

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
    /// key's wipe, a raw `SecItem` call but not a status that spells it inside its name, every platform
    /// directory but the temporary ones, and each of the four location calls on a line that holds that
    /// call's needle and no other, so a call needle the platform wall's list loses fails here.
    private static func expectTheNeedleReaderFixtured() {
        let calls: [(line: String, needle: String)] = [
            (line: "let u = try FileManager.default.url(for: directory, in: mask, appropriateFor: nil, create: false)",
             needle: "url(for:"),
            (line: "let all = FileManager.default.urls(for: directory, in: mask)", needle: "urls(for:"),
            (line: "let u = try URL(for: directory, in: mask, appropriateFor: nil, create: false)", needle: "URL(for:"),
            (line: "let c = FileManager.default.url(forUbiquityContainerIdentifier: nil)",
             needle: "url(forUbiquityContainerIdentifier:")
        ]
        // R2: bounded by the fixed list.
        for call in calls {
            let read = packageHazardNeedles(onLine: call.line).map(\.needle)
            #expect(read == [call.needle], "I9 read \(read) on `\(call.line)`, not its one location call")
        }
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

    /// The wall-file reader (rule I9): a needle in a literal is data and the same needle in code is read;
    /// a literal that starts with each repository folder is refused at its start, while one that only
    /// names a folder inside its text is not; and a file that spells no needle is named.
    private static func expectTheWallFileReaderFixtured() {
        let literal = PackageSwiftFiles.File(path: "W.swift", text: "let sample = \"_ = UserDefaults.standard\"\n")
        let literalProblems = wallFileProblems(literal, invariant: "")
        #expect(literalProblems.isEmpty, "a wall file's literal was read as code: \(literalProblems)")
        let code = PackageSwiftFiles.File(path: "W.swift", text: "func f() { _ = UserDefaults.standard }\n")
        let codeProblems = wallFileProblems(code, invariant: "")
        #expect(codeProblems.contains { $0.contains("(a wall file, read as code)") },
                "a wall file's code needle was not read: \(codeProblems)")
        let quotedPaths = [
            "let t = try String(contentsOfFile: \"Tests/ProximityKitTests.tsv\", encoding: .utf8)",
            "let a = \"App/Fernlet/FernletApp.swift\"", "let d = \"Docs/FileIndex.md\"",
            "let w = \".github/workflows/s3-wall.yml\"", "let k = \"FernletKit/Package.swift\"",
            "let s = \"Scripts/spm-wall-check.sh\""
        ]
        // R2: bounded by the fixed list.
        for line in quotedPaths {
            let problems = wallFileProblems(PackageSwiftFiles.File(path: "W.swift", text: line + "\n"), invariant: "")
            #expect(problems.contains { $0.contains("(a wall file, its literal read at its start)") },
                    "a wall file's literal repository path was not read: \(line)")
        }
        let inside = PackageSwiftFiles.File(path: "W.swift", text: "let n = \"reads Tests/x through PackageRoot\"\n")
        #expect(!wallFileProblems(inside, invariant: "").contains { $0.contains("its literal read at its start") },
                "a literal that only names a folder inside its text was refused")
        let quiet = PackageSwiftFiles.File(path: "W.swift", text: "let x = 1\n")
        #expect(wallFileProblems(quiet, invariant: "").contains { $0.contains("spells no needle in its text") },
                "a wall file that spells no needle was not named")
    }

    /// The structure reader's problems for a fixture `source` read as a listed file of `kind` (rule I9).
    private static func fixtureKeychainProblems(_ kind: PackageKeychainFileKind, _ source: String) -> [String] {
        packageKeychainFileProblems([PackageKeychainFile(file: "F.swift", kind: kind, invariant: "")], source: source)
    }

    /// The structure reader's problems for a fixture `source` read as a file listed under every one of
    /// `kinds` (rule I9).
    private static func fixtureKeychainProblems(_ kinds: [PackageKeychainFileKind], _ source: String) -> [String] {
        packageKeychainFileProblems(kinds.map { PackageKeychainFile(file: "F.swift", kind: $0, invariant: "") },
                                    source: source)
    }

    /// The structure reader over a suite file (rule I9), both ways. A suite whose first stored property
    /// reads the installer, with its keychain lines in its instance tests and a private static helper,
    /// passes, and so do the traits, arguments and statics that run nothing the installer must precede
    /// (`.serialized`, a display name, a literal array with no call and no needle, a type's `.allCases`, a
    /// static stored property that reaches no keychain, a literal constant of the suite's named in an
    /// argument), a bare declaration of a keychain type in a public nested type, and a second suite that
    /// holds no keychain line and so needs no marker; and each way a suite file reaches the keychain
    /// without an instance is named: no marker, or a marker second; a helper, a `fileprivate` one
    /// included, or a nested type that is not private; a keychain call inside a static helper's
    /// multi-line call; a static or a free test; an argument that calls, that names a keychain type or a
    /// static member of the file that is no literal constant, or that is no collection, a second
    /// collection that calls, and any other trait; a static stored property that builds a keychain type,
    /// on its own line, inside a multi-line call or on the line below its `=`, or names a static member
    /// that does, one whose initializer starts below its `=` included; a global stored property; a keychain line outside every suite; and a listed file with
    /// no keychain line.
    private static func expectTheSuiteKeychainFileReaderFixtured() {
        let read = fixtureKeychainProblems as (PackageKeychainFileKind, String) -> [String]
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
        let admitted = [
            suite.replacingOccurrences(of: "@Suite struct S {", with: "@Suite(\"A display name\", .serialized) struct S {"),
            suite.replacingOccurrences(of: "@Test func a()", with: "@Test(\"named\", arguments: [1, Int.max - 1]) func a(v: Int)"),
            suite.replacingOccurrences(of: "@Test func a()", with: "@Test(arguments: [\n        1,\n        2\n    ], [true]) func a(v: Int, w: Bool)"),
            suite.replacingOccurrences(of: "@Test func a()", with: "@Test(arguments: Fault.Kind.allCases) func a(v: Fault.Kind)"),
            suite.replacingOccurrences(of: marker, with: marker + "\n    private static let size = MeshChunkFormat.maxChunkPayloadBytes + 1"),
            suite.replacingOccurrences(of: marker, with: marker + "\n    struct Pair {\n        let origin: IdentityService\n    }"),
            suite + "\n@Suite(.serialized) struct T {\n    @Test func c() {}\n}",
            suite.replacingOccurrences(of: marker, with: marker + "\n    private static let size = 3")
                .replacingOccurrences(of: "@Test func a()", with: "@Test(arguments: [Self.size, 4]) func a(v: Int)")
        ]
        // R2: bounded by the fixed list.
        for source in admitted {
            #expect(read(.suite, source).isEmpty, "a suite file that runs nothing reaching the keychain was refused: \(read(.suite, source))")
        }
        let suites: [(source: String, names: String)] = [
            (suite.replacingOccurrences(of: marker, with: "    let name = \"x\""), "first stored property reads none"),
            (suite.replacingOccurrences(of: marker, with: "    let name = \"x\"\n" + marker), "first stored property reads none"),
            (suite.replacingOccurrences(of: "@MainActor private static", with: "@MainActor static"), "static member that is not private"),
            (suite.replacingOccurrences(of: marker, with: marker + "\n    struct Pair {\n        let origin = IdentityService(namespace: .packageTest)\n    }"),
             "nested type that is not private"),
            (suite.replacingOccurrences(of: "@Test func a()", with: "@Test static func a()"), "declares a static test"),
            (suite.replacingOccurrences(of: "@Test func a()", with: "@Test(arguments: Self.cases()) func a(v: Int)"), "arguments or traits"),
            (suite.replacingOccurrences(of: "@Test func a()", with: "@Test(arguments: [IdentityService.fingerprint(of: Data())]) func a(v: String)"),
             "arguments or traits"),
            (suite.replacingOccurrences(of: "@Test func a()", with: "@Test(arguments: [IdentityService.presenceEpochSeconds]) func a(v: Double)"),
             "arguments or traits"),
            (suite.replacingOccurrences(of: "@Test func a()", with: "@Test(arguments: Self.cases) func a(v: Int)"), "arguments or traits"),
            (suite.replacingOccurrences(of: "@Suite struct S {", with: "@Suite(.tags(.slow)) struct S {"), "arguments or traits"),
            (suite.replacingOccurrences(of: "@Suite struct S {", with: "@Suite(\"\\(name)\") struct S {"), "arguments or traits"),
            (suite.replacingOccurrences(of: "@Test func a()", with: "@Test(.enabled(if: true)) func a()"), "arguments or traits"),
            (suite.replacingOccurrences(of: marker, with: marker + "\n    private static let cache = IdentityService(namespace: .packageTest)"),
             "static stored property whose initializer reaches the keychain"),
            (suite.replacingOccurrences(of: marker, with: marker + "\n    private static let cache = Self.identity()"),
             "static stored property whose initializer reaches the keychain"),
            (suite + "\nlet shared = 1", "global stored property"),
            (suite + "\n@Test func free() {}", "declares a free test"),
            (suite + "\nfunc helper() { _ = ProximityKeychainItem.backend }", "outside every @Suite type"),
            ("@Suite struct S {\n" + marker + "\n    @Test func a() {}\n}", "holds no keychain needle"),
            (suite.replacingOccurrences(of: "@MainActor private static", with: "@MainActor fileprivate static"),
             "static member that is not private"),
            (suite.replacingOccurrences(of: marker, with: marker + "\n    private static var seeded: String { identity().localFingerprint }")
                .replacingOccurrences(of: "@Test func a()", with: "@Test(arguments: [Self.seeded]) func a(v: String)"),
             "arguments or traits"),
            (suite.replacingOccurrences(of: "@Test func a()", with: "@Test(arguments: [Self.make()]) func a(v: Int)"),
             "arguments or traits"),
            (suite.replacingOccurrences(of: "@Test func a()", with: "@Test(arguments: [1], Self.cases()) func a(v: Int, w: Int)"),
             "arguments or traits"),
            (suite.replacingOccurrences(of: marker, with: marker
                + "\n    static func wrapped() -> Wrapper {\n        Wrapper(\n            identity: IdentityService(keychainService: \"x\")\n        )\n    }"),
             "static member that is not private"),
            (suite.replacingOccurrences(of: marker, with: marker
                + "\n    private static let cache = Wrapper(\n        IdentityService(namespace: .packageTest)\n    )"),
             "static stored property whose initializer reaches the keychain"),
            (suite.replacingOccurrences(of: marker, with: marker
                + "\n    private static let cache =\n        IdentityService(namespace: .packageTest)"),
             "static stored property whose initializer reaches the keychain"),
            (suite.replacingOccurrences(of: marker, with: marker
                + "\n    private static let made =\n        IdentityService(namespace: .packageTest)\n    private static let alias = made"),
             "line 5 declares a static stored property whose initializer reaches the keychain"),
            (suite.replacingOccurrences(of: marker, with: marker + "\n    private static let alias =\n        identity()"),
             "line 3 declares a static stored property whose initializer reaches the keychain")
        ]
        // R2: bounded by the fixed list.
        for (source, names) in suites {
            let problems = read(.suite, source)
            #expect(problems.contains { $0.contains(names) }, "a suite file that \(names) was read as \(problems)")
        }
    }

    /// The structure reader over a fixture enum, alone and beside a suite (rule I9), both ways. An enum
    /// whose members that reach the keychain, private or not, each read the installer first passes, with
    /// its constants and a member that reaches nothing reading nothing; and each way one breaks it is
    /// named: a member that reads it second or not at all, a private one included; a stored property that
    /// builds a keychain type; a keychain line outside the enum (a file listed under the fixture kind
    /// alone); no such enum. Beside a suite, each kind holds the lines in its own types: a fixture's
    /// lines need no suite marker and a suite's no read in its tests, and a line in neither type is named.
    private static func expectTheFixtureEnumReaderFixtured() {
        let read = fixtureKeychainProblems as (PackageKeychainFileKind, String) -> [String]
        let fixture = """
            @MainActor
            enum Fixtures {
                static let label = "fixture"
                static func identity() throws -> IdentityService {
                    _ = PackageTestEnvironment.keychain
                    let service = IdentityService(keychainService: label)
                    try service.ensureProvisioned()
                    return service
                }
                private static func pair(
                    founder: IdentityService
                ) -> [IdentityService] {
                    _ = PackageTestEnvironment.keychain
                    return [founder]
                }
                static func count(_ values: [Int]) -> Int { values.count }
            }
            """
        let kind = PackageKeychainFileKind.fixtureEnum(type: "Fixtures")
        #expect(read(kind, fixture).isEmpty, "a fixture enum that keeps its structure was refused: \(read(kind, fixture))")
        let first = "        _ = PackageTestEnvironment.keychain\n        let service"
        let broken: [(kind: PackageKeychainFileKind, source: String, names: String)] = [
            (kind, fixture.replacingOccurrences(of: first, with: "        let service"), "does not read PackageTestEnvironment.keychain"),
            (kind, fixture.replacingOccurrences(of: first, with: "        let other = label\n" + first),
             "does not read PackageTestEnvironment.keychain"),
            (kind, fixture.replacingOccurrences(of: ") -> [IdentityService] {\n        _ = PackageTestEnvironment.keychain\n",
                                                with: ") -> [IdentityService] {\n"),
             "does not read PackageTestEnvironment.keychain"),
            (kind, fixture.replacingOccurrences(of: "    static let label = \"fixture\"",
                                                with: "    static let shared = IdentityService(keychainService: \"s\")"),
             "stored property's initializer"),
            (kind, fixture + "\nstruct Loose {\n    func f() { _ = IdentityService(keychainService: \"l\") }\n}",
             "outside every member of the fixture enum"),
            (.fixtureEnum(type: "Other"), fixture, "declares no enum `Other`")
        ]
        // R2: bounded by the fixed list.
        for (kind, source, names) in broken {
            let problems = read(kind, source)
            #expect(problems.contains { $0.contains(names) }, "a fixture enum that \(names) was read as \(problems)")
        }
        let suite = """
            @Suite struct S {
                let keychain = PackageTestEnvironment.keychain
                @Test func a() throws { _ = try Fixtures.identity(); ProximityKeychainItem.deleteAll(service: "s") }
            }
            """
        let both: [PackageKeychainFileKind] = [.suite, kind]
        let together = fixture + "\n" + suite
        #expect(fixtureKeychainProblems(both, together).isEmpty,
                "a suite and a fixture enum listed together were refused: \(fixtureKeychainProblems(both, together))")
        let loose = together + "\nstruct Loose {\n    func f() { _ = IdentityService(keychainService: \"l\") }\n}"
        #expect(fixtureKeychainProblems(both, loose).contains { $0.contains("outside every type its rows name") },
                "a keychain line in neither listed type was read as \(fixtureKeychainProblems(both, loose))")
        let unmarked = together.replacingOccurrences(of: "    let keychain = PackageTestEnvironment.keychain\n", with: "")
        #expect(fixtureKeychainProblems(both, unmarked).contains { $0.contains("first stored property reads none") },
                "a suite with a keychain line and no marker beside a fixture enum was read as \(fixtureKeychainProblems(both, unmarked))")
    }

    /// The structure reader over store lines (rule I9; ProximityKit plan step A1's third batch of copied
    /// suites), both ways. A listed file may hold a store's name, and neither a production scope's
    /// shorthand nor a raw `SecItem` call, and an unlisted file's store line is refused. A suite whose cell
    /// builds a store behind its marker passes under a row that states the store clause, and so does a
    /// fixture enum whose member reads the installer before it builds one, its own name holding a store's
    /// or not; and each way a store line escapes the installer is named: no marker; a static helper that
    /// is not private, a static stored property or a free function that builds one; a store's name in an
    /// argument collection; a fixture member that builds one before its read, or a stored property that
    /// does, or one written on the enum's head line. And the store clause stands
    /// exactly where a store does: a store line under rows that state none is refused, and so is a row
    /// stating it over a file that names no store.
    private static func expectTheStoreLineReaderFixtured() {
        #expect(isListedFileNeedle("MeshRoutedStore") && isListedFileNeedle("MeshSessionStore"),
                "a listed file may not hold a store's name")
        #expect(!isListedFileNeedle(".production(") && !isListedFileNeedle("SecItem"),
                "a listed file may hold a production scope's shorthand or a raw SecItem call")
        let loose = PackageSwiftFiles.File(path: "Unlisted.swift", text: "let s = MeshSessionStore(scope: scope)\n")
        #expect(ordinaryFileProblems(loose).problems.contains { $0.contains("holds `MeshSessionStore`") },
                "an unlisted file's store line was not refused")
        let read = { (kind: PackageKeychainFileKind, invariant: String, source: String) in
            packageKeychainFileProblems([PackageKeychainFile(file: "F.swift", kind: kind, invariant: invariant)],
                                        source: source)
        }
        let stores = packageKeychainStoreSuiteInvariant
        let suite = """
            @Suite struct S {
                let keychain = PackageTestEnvironment.keychain
                @Test func a() { _ = MeshRoutedStore(scope: Self.scope()).load() }
                private static func scope() -> MeshRoutedStorageScope { Fixtures.scope() }
                private static func wipe(_ scope: MeshRoutedStorageScope) { MeshRoutedStore.wipeForDeleteAll(scope: scope) }
            }
            """
        #expect(read(.suite, stores, suite).isEmpty, "a suite whose store lines sit behind its marker was refused: \(read(.suite, stores, suite))")
        let cell = "    @Test func a() { _ = MeshRoutedStore(scope: Self.scope()).load() }"
        let refused: [(source: String, invariant: String, names: String)] = [
            (suite.replacingOccurrences(of: "    let keychain = PackageTestEnvironment.keychain\n", with: ""), stores,
             "first stored property reads none"),
            (suite.replacingOccurrences(of: "    private static func wipe", with: "    static func wipe"), stores,
             "static member that is not private"),
            (suite.replacingOccurrences(of: cell, with: cell + "\n    private static let shared = MeshSessionStore(scope: .init())"),
             stores, "static stored property whose initializer reaches the keychain"),
            (suite + "\nfunc loose() { _ = MeshRoutedStore(scope: s) }", stores, "outside every @Suite type"),
            (suite.replacingOccurrences(of: "@Test func a()", with: "@Test(arguments: [MeshRoutedStoreFormat.maxItems]) func a(v: Int)"),
             stores, "arguments or traits"),
            (suite, packageKeychainSuiteInvariant, "names a store, but none of its rows"),
            ("@Suite struct S {\n    let keychain = PackageTestEnvironment.keychain\n    @Test func a() { _ = ProximityKeychainItem.backend }\n}",
             stores, "names no store on a keychain line")
        ]
        // R2: bounded by the fixed list.
        for (source, invariant, names) in refused {
            let problems = read(.suite, invariant, source)
            #expect(problems.contains { $0.contains(names) }, "a suite file whose store line \(names) was read as \(problems)")
        }
        let fixture = """
            enum Fixtures {
                static func store(_ scope: MeshSessionStorageScope) -> MeshSessionStore {
                    _ = PackageTestEnvironment.keychain
                    return MeshSessionStore(scope: scope)
                }
            }
            """
        let kind = PackageKeychainFileKind.fixtureEnum(type: "Fixtures")
        let enums = packageKeychainStoreFixtureEnumInvariant
        #expect(read(kind, enums, fixture).isEmpty, "a fixture enum that reads before its store was refused: \(read(kind, enums, fixture))")
        let named = fixture.replacingOccurrences(of: "enum Fixtures {", with: "enum MeshSessionStoreFixtures {")
        let storeNamed = PackageKeychainFileKind.fixtureEnum(type: "MeshSessionStoreFixtures")
        #expect(read(storeNamed, enums, named).isEmpty,
                "a fixture enum whose own name holds a store's was refused on its head line: \(read(storeNamed, enums, named))")
        let broken: [(source: String, names: String)] = [
            (named.replacingOccurrences(of: "enum MeshSessionStoreFixtures {\n",
                                        with: "enum MeshSessionStoreFixtures { static func s() { _ = MeshSessionStore.self }\n"),
             "outside every member of the fixture enum"),
            (fixture.replacingOccurrences(of: "        _ = PackageTestEnvironment.keychain\n", with: ""),
             "does not read PackageTestEnvironment.keychain"),
            (fixture.replacingOccurrences(of: "enum Fixtures {\n", with: "enum Fixtures {\n    static let shared = MeshSessionStore(scope: .init())\n"),
             "stored property's initializer")
        ]
        // R2: bounded by the fixed list.
        for (source, names) in broken {
            let problems = read(source.contains("MeshSessionStoreFixtures") ? storeNamed : kind, enums, source)
            #expect(problems.contains { $0.contains(names) }, "a fixture enum whose store line \(names) was read as \(problems)")
        }
    }

    /// The structure reader over the installer and a support type (rule I9), both ways. An installer passes
    /// with its one line in `static let keychain` and fails with it outside, or with no such read. A support
    /// type passes with its lines in instance members behind an initializer that reads the installer first,
    /// and fails with a late read, a static member, a stored property, a line outside its members, or no
    /// such type.
    private static func expectTheInstallerAndSupportTypeReadersFixtured() {
        let read = fixtureKeychainProblems as (PackageKeychainFileKind, String) -> [String]
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
