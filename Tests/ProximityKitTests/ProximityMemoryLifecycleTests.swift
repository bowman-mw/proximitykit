// ProximityMemoryLifecycleTests.swift
// ProximityKitTests
//
// ProximityKit plan step A1.1: the memory-lifecycle wall over ProximityKit's own code, held in this
// module's tests so it travels with the package. No compiler checks any of its rules: a stored task
// nobody cancels, an observer token the notification center keeps forever, a hand-rolled observation
// loop, or a detached task that outlives the `unowned` host it reads all compile clean, and the last
// aborts the whole process. This suite reads every Swift file of the module as text, through
// `PackageRoot` and the package's walker (TestSupport/PackageSwiftFiles.swift), at the walk's floor, and
// holds four disciplines, each matcher held to its samples:
//
//   ML1  a type that STORES a `Task<…>` handle owns a long-running job, and cancels it in a `deinit` or
//        `isolated deinit`; ProximityKit's code holds no exemption;
//   ML2  a block-based `NotificationCenter.addObserver(forName:…)` token is retained by the center, with
//        everything its block captures, until it is removed, so the file removes it;
//   ML3  `withObservationTracking` re-arm loops live in exactly one place, `Engine/ObservationLoop.swift`,
//        which holds its owner weakly across the suspension; any other use is a hand-rolled copy of the
//        machinery that leaked before it was extracted;
//   ML4  a file holding an `unowned` `ProximityHost` (the mesh manager's and the pair session's) may not
//        contain an UNMARKED `Task` construction. Those managers read a host they do not own, so a task
//        that outlives the host reads destroyed memory and `swift_abortRetainUnowned` kills the process.
//        Every such spawn goes through the file's one `spawnHostPinned(_:)`, which pins the host for the
//        operation that reads it (HP1); the literals that stay carry a `// host-pin:` marker of exactly one
//        kind: `helper` (the one inside `spawnHostPinned`), `timer — <reason>` (a spawn whose handle the
//        manager STORES, which must never be pinned: that pin is a permanent cycle, HP2) or
//        `exempt — <reason>` (a spawn touching neither `self` nor the host). The scoped pin taken inside
//        an async callee is marked `scoped — <reason>` and sits on no `Task` line.
//
// ML5, the same trap in tests (a manager built over a host expression nobody holds), is this target's
// `PackageTestTreeWallTests`'. A host's own wall holds the same rules over the host's code; in the Fernlet
// repository, `MemoryLifecycleBoundaryTests`, which reads Fernlet's shipping roots but this module's folder.

import Foundation
import Testing

/// ProximityKit's code cancels every task handle it stores in a deinit, removes every block observer it
/// registers, tracks observation only in `ObservationLoop`, and constructs no unmarked `Task` in a file
/// that holds an `unowned` host: five cells, one of them the matchers' samples.
@Suite struct ProximityMemoryLifecycleTests {

    // MARK: - The cells

    /// **ML1.** Every file of the module that stores a `Task<…>` handle (``FileFacts/storesTaskHandle``)
    /// cancels one in a `deinit` or `isolated deinit`, and at least ``minimumTaskHolderFiles`` such files
    /// are read, over every Swift file of the module at the walk's floor. ProximityKit's code holds no
    /// exemption: a manager that owns a job ends it when it goes.
    @Test func ml1EveryStoredTaskHandleIsCancelledInDeinit() throws {
        let files = try Self.scan()
        #expect(files.count >= PackageSwiftFiles.sourceFloor, """
            the lifecycle scan read \(files.count) ProximityKit files (floor \(PackageSwiftFiles.sourceFloor)): \
            the walk is broken, not the module clean
            """)
        let holders = files.filter(\.storesTaskHandle)
        #expect(holders.count >= Self.minimumTaskHolderFiles, """
            Found only \(holders.count) task-holding files in ProximityKit (floor \(Self.minimumTaskHolderFiles)) \
            — the property matcher has stopped matching
            """)
        let violations = holders.filter { !$0.cancelsInDeinit }.map { Self.printed($0.path) }
        #expect(violations.isEmpty, """
            ML1: these ProximityKit files store a Task<…> handle but cancel none in a deinit / isolated \
            deinit. Add `isolated deinit { <handle>?.cancel() }`, the pattern MeshNetworkManager, \
            ProximityPairSession, ProximityCoordinator and the three network sessions use; ProximityKit's \
            code holds no exemption from this rule:
            \(violations.joined(separator: "\n"))
            """)
    }

    /// **ML2.** Every file of the module that registers a block-based observer
    /// (``FileFacts/addsBlockObserver``) removes it, and at least ``minimumObserverFiles`` such files are
    /// read, over every Swift file of the module at the walk's floor.
    @Test func ml2EveryBlockObserverIsRemoved() throws {
        let files = try Self.scan()
        #expect(files.count >= PackageSwiftFiles.sourceFloor, """
            the lifecycle scan read \(files.count) ProximityKit files (floor \(PackageSwiftFiles.sourceFloor)): \
            the walk is broken, not the module clean
            """)
        let registrars = files.filter(\.addsBlockObserver)
        #expect(registrars.count >= Self.minimumObserverFiles, """
            Found only \(registrars.count) block-observer files in ProximityKit (floor \(Self.minimumObserverFiles)) \
            — the observer matcher has stopped matching
            """)
        let violations = registrars.filter { !$0.removesObserver }.map { Self.printed($0.path) }
        #expect(violations.isEmpty, """
            ML2: these ProximityKit files register a block-based NotificationCenter observer (the center \
            retains the block and everything it captures) but never removeObserver it. Hold the token and \
            remove it in an isolated deinit, as ProtectedSidecar does; ProximityKit's code holds no exemption \
            from this rule:
            \(violations.joined(separator: "\n"))
            """)
    }

    /// **ML3.** `withObservationTracking` is used in ``observationLoopFile`` and in no other file of the
    /// module, over every Swift file of the module at the walk's floor; the home's own use is the
    /// matcher's floor, so a matcher that stops seeing it fails rather than passes.
    @Test func ml3ObservationTrackingLivesOnlyInObservationLoop() throws {
        let files = try Self.scan()
        #expect(files.count >= PackageSwiftFiles.sourceFloor, """
            the lifecycle scan read \(files.count) ProximityKit files (floor \(PackageSwiftFiles.sourceFloor)): \
            the walk is broken, not the module clean
            """)
        let users = files.filter(\.usesObservationTracking).map(\.path)
        #expect(users.contains(Self.observationLoopFile),
                "ObservationLoop.swift no longer uses withObservationTracking — the matcher or the file moved; update observationLoopFile")
        let strays = users.filter { $0 != Self.observationLoopFile }.map { Self.printed($0) }
        #expect(strays.isEmpty, """
            ML3: withObservationTracking may only be used through ObservationLoop.start (owner held weakly \
            across the suspension, cancellation finishes the stream). Route these through it instead of \
            hand-rolling the loop:
            \(strays.joined(separator: "\n"))
            """)
    }

    /// **ML4.** In every file of the module that holds an `unowned` `ProximityHost`
    /// (``FileFacts/holdsUnownedHost``), every `Task` construction carries a `// host-pin:` marker of a
    /// known kind with its reason, no marker strays off a `Task` line but the scoped pin, the file declares
    /// exactly one `spawnHostPinned(_:)` helper, and it constructs at least one `Task` (the helper's own);
    /// at least ``minimumHostHoldingFiles`` such files are read. The marker's own `— <reason>` text is the
    /// per-site invariant, so the counts stay floors or are derived from the files found.
    @Test func ml4HostHoldingFilesPinOrMarkEveryTaskConstruction() throws {
        let files = try Self.scan()
        #expect(files.count >= PackageSwiftFiles.sourceFloor, """
            the lifecycle scan read \(files.count) ProximityKit files (floor \(PackageSwiftFiles.sourceFloor)): \
            the walk is broken, not the module clean
            """)
        let holders = files.filter(\.holdsUnownedHost)
        #expect(holders.count >= Self.minimumHostHoldingFiles, """
            Found only \(holders.count) files holding an unowned ProximityHost in ProximityKit (floor \
            \(Self.minimumHostHoldingFiles)) — the matcher has stopped matching, or a holder has left the scan
            """)
        let unmarked = holders.flatMap { file in file.hostPin.unmarkedSpawns.map { "\(Self.printed(file.path)):\($0)" } }
        #expect(unmarked.isEmpty, """
            ML4: these Task constructions live in a file that reads an unowned ProximityHost, so a task \
            outliving the host reads destroyed memory and aborts the whole process. Route them through \
            spawnHostPinned(_:), or mark them `// host-pin: timer — <reason>` (a handle the manager \
            stores: a pin there is a permanent cycle, HP2) / `// host-pin: exempt — <reason>` (no self, \
            no host read):
            \(unmarked.joined(separator: "\n"))
            """)
        let badKinds = holders.flatMap { file in file.hostPin.badKinds.map { "\(Self.printed(file.path)):\($0)" } }
        #expect(badKinds.isEmpty, "ML4: a host-pin marker's kind must be helper / timer / exempt: \(badKinds)")
        let reasonless = holders.flatMap { file in file.hostPin.reasonlessMarkers.map { "\(Self.printed(file.path)):\($0)" } }
        #expect(reasonless.isEmpty, "ML4: every timer / exempt / scoped marker states the invariant that makes it safe: \(reasonless)")
        let strays = holders.flatMap { file in file.hostPin.strayMarkers.map { "\(Self.printed(file.path)):\($0)" } }
        #expect(strays.isEmpty, "ML4: only the `scoped` pin may carry a host-pin marker off a Task line: \(strays)")
        let helperCounts = holders.filter { $0.hostPin.helperMarkers != 1 }
            .map { "\(Self.printed($0.path)) has \($0.hostPin.helperMarkers)" }
        #expect(helperCounts.isEmpty, "ML4: each host-holding file declares exactly one spawnHostPinned helper: \(helperCounts)")
        let silent = holders.filter { $0.hostPin.spawns == 0 }.map { Self.printed($0.path) }
        #expect(silent.isEmpty, "ML4: a host-holding file with no Task construction at all has lost its helper: \(silent)")
    }

    /// Each matcher trips on a planted token and passes its near-misses: a stored task handle (but not a
    /// SwiftUI `@State` one), a deinit that cancels, a block observer (but not a selector one) and its
    /// removal, an observation-tracking call (but not prose about one), an `unowned` host (but not a
    /// strongly held one), every spelling of a `Task` construction (but not a declaration, a yield or a
    /// documentation line), and the host-pin markers' kinds, reasons and strays.
    @Test func theLifecycleMatchersTripOnPlantedTokens() {
        let taskHolder = "final class X {\n    @ObservationIgnored private var job: Task<Void, Never>?\n}\n"
        let stateHolder = "struct V: View {\n    @State private var job: Task<Void, Never>?\n}\n"
        let holderWithDeinit = taskHolder + "extension X {}\n" + "final class Y {\n    var t: Task<Void, Never>?\n    isolated deinit {\n        t?.cancel()\n    }\n}\n"
        #expect(Self.facts(for: "a.swift", source: taskHolder).storesTaskHandle)
        #expect(!Self.facts(for: "b.swift", source: stateHolder).storesTaskHandle, "@State handles are excluded")
        #expect(!Self.facts(for: "a.swift", source: taskHolder).cancelsInDeinit)
        #expect(Self.facts(for: "c.swift", source: holderWithDeinit).cancelsInDeinit)

        let blockObserver = "let t = NotificationCenter.default.addObserver(\n    forName: .x, object: nil, queue: nil) { _ in }\n"
        let selectorObserver = "NotificationCenter.default.addObserver(self, selector: #selector(f), name: .x, object: nil)\n"
        #expect(Self.facts(for: "d.swift", source: blockObserver).addsBlockObserver)
        #expect(!Self.facts(for: "e.swift", source: selectorObserver).addsBlockObserver, "selector observers are not retained blocks")
        #expect(Self.facts(for: "f.swift", source: blockObserver + "deinit { NotificationCenter.default.removeObserver(t) }").removesObserver)

        #expect(Self.facts(for: "g.swift", source: "withObservationTracking {\n  _ = x\n} onChange: {}\n").usesObservationTracking)
        #expect(!Self.facts(for: "h.swift", source: "// withObservationTracking is discussed here only\n").usesObservationTracking)

        let host = "    private unowned let store: any ProximityHost\n"
        #expect(Self.facts(for: "i.swift", source: host).holdsUnownedHost)
        #expect(Self.facts(for: "j.swift", source: "    private let store: any ProximityHost\n").holdsUnownedHost == false,
                "a strongly held host is not ML4's subject")
        // R2: bounded by the four spellings.
        for spelling in ["Task {", "Task.detached {", "Task(priority: .background) {", "Task<Void, Never> {"] {
            let planted = Self.facts(for: "k.swift", source: host + "        \(spelling) await f() }\n")
            #expect(planted.hostPin.unmarkedSpawns == [2], "\(spelling) must trip ML4")
        }
        let nearMisses = host + "    var t: Task<Void, Never>?\n    await Task.yield()\n    /// as the `Task { … }` literal\n"
        #expect(Self.facts(for: "l.swift", source: nearMisses).hostPin.spawns == 0, "declarations, yields and docs are not spawns")
        let marked = host + "        Task {   // host-pin: helper\n        }\n        // host-pin: exempt — no self, no host read\n        Task { await c.cancel() }\n"
        let markedAudit = Self.facts(for: "m.swift", source: marked).hostPin
        #expect(markedAudit.unmarkedSpawns.isEmpty && markedAudit.helperMarkers == 1 && markedAudit.spawns == 2)
        let emptyReason = host + "        // host-pin: timer —\n        Task { await f() }\n"
        #expect(Self.facts(for: "n.swift", source: emptyReason).hostPin.reasonlessMarkers == [3], "a reasonless marker must trip")
        let strayKind = host + "        // host-pin: whatever — not a kind\n        let x = 1\n"
        #expect(Self.facts(for: "o.swift", source: strayKind).hostPin.strayMarkers.isEmpty == false, "only `scoped` may sit off a Task line")
    }

    // MARK: - Floors and the one home

    /// Files of the module that store a `Task<…>` handle, MEASURED at ProximityKit plan step A1.1.17
    /// (2026-10-14): six, the coordinator, the mesh manager, the pair session and the three network
    /// sessions, each cancelling in its `isolated deinit`. A wall that finds fewer has stopped looking; a
    /// new holder raises the count and is held to ML1.
    static let minimumTaskHolderFiles = 6

    /// Files of the module with a block-based observer, MEASURED at ProximityKit plan step A1.1.17
    /// (2026-10-14): one, `HeartSharing/ProtectedSidecar.swift`, which removes it. A wall that finds fewer
    /// has stopped looking.
    static let minimumObserverFiles = 1

    /// Files of the module holding an `unowned` `ProximityHost`, MEASURED at ProximityKit plan step
    /// A1.1.17 (2026-10-14): two, `Mesh/MeshNetworkManager.swift` and
    /// `PairSession/ProximityPairSession.swift` (a host's managers over this module hold theirs in the
    /// host's code, which the host's own wall reads). A matcher that finds fewer has stopped looking, or a
    /// holder has left the scan; a new holder raises the count, and is found and held to ML4.
    static let minimumHostHoldingFiles = 2

    /// The single sanctioned home of `withObservationTracking`, by its path under the module.
    static let observationLoopFile = "Engine/ObservationLoop.swift"

    // MARK: - The scan

    /// One file's lifecycle-relevant facts.
    struct FileFacts: Hashable, Sendable {
        /// The file, by its path under the module (`Engine/ObservationLoop.swift`).
        let path: String
        /// Whether it stores a `Task<…>` handle that is not a SwiftUI `@State` one (ML1).
        let storesTaskHandle: Bool
        /// Whether a `deinit` or `isolated deinit` in it cancels a task (ML1).
        let cancelsInDeinit: Bool
        /// Whether it registers a block-based `addObserver(forName:…)` observer (ML2).
        let addsBlockObserver: Bool
        /// Whether it calls `removeObserver(` (ML2).
        let removesObserver: Bool
        /// Whether it calls `withObservationTracking` (ML3).
        let usesObservationTracking: Bool
        /// Whether the file declares an `unowned` `ProximityHost` — the ML4 trigger.
        let holdsUnownedHost: Bool
        /// ML4's per-file audit; all-zero for a file that holds no such host (the rule is silent there).
        let hostPin: HostPinAudit
    }

    /// One host-holding file's `// host-pin:` audit — ML4's inputs.
    ///
    /// Line numbers are 1-based and name the `Task` construction, not the marker line, because that
    /// is the line an author has to edit. Empty for every file that does not hold an `unowned`
    /// `ProximityHost`.
    struct HostPinAudit: Hashable, Sendable {
        /// `Task` constructions carrying no `// host-pin:` marker on their own line or the one above.
        var unmarkedSpawns: [Int] = []
        /// Markers on a `Task` construction whose kind is not `helper` / `timer` / `exempt`.
        var badKinds: [String] = []
        /// `timer` / `exempt` / `scoped` markers with nothing after the em-dash.
        var reasonlessMarkers: [Int] = []
        /// `// host-pin:` markers attached to no `Task` construction; only `scoped` may be one.
        var strayMarkers: [String] = []
        /// `// host-pin: helper` markers — exactly one per host-holding file, derived from the file
        /// list rather than written down as a total.
        var helperMarkers: Int = 0
        /// Every `Task` construction found, marked or not — the matcher's own floor.
        var spawns: Int = 0

        /// Files the rule does not apply to.
        static let none = HostPinAudit()

        /// Records the marker found on a `Task` construction at `line`.
        mutating func record(spawnKind kind: String, reason: String, line: Int) {
            switch kind {
            case "helper": helperMarkers += 1
            case "timer", "exempt": if reason.isEmpty { reasonlessMarkers.append(line) }
            default: badKinds.append("\(line): \(kind)")
            }
        }

        /// Records a marker that sits on no `Task` construction. Only the scoped pin may.
        mutating func record(strayKind kind: String, reason: String, line: Int) {
            guard kind == "scoped" else { return strayMarkers.append("\(line): \(kind)") }
            if reason.isEmpty { reasonlessMarkers.append(line) }
        }
    }

    /// Reads every Swift file of the module (``PackageSwiftFiles/sources()``) into its facts. A file the
    /// walk found but cannot read as UTF-8 throws, so an unreadable file fails the cell that asked rather
    /// than reading as clean.
    static func scan() throws -> [FileFacts] {
        try PackageSwiftFiles.sources().map { facts(for: $0.path, source: $0.text) }
    }

    /// A file's path under the module, as the messages print it: under the package root.
    static func printed(_ path: String) -> String {
        PackageSwiftFiles.sourceFolder + "/" + path
    }

    /// A stored `Task<…>` property that is not a SwiftUI `@State` (views are structs; their tasks
    /// are cancelled by `.task`/`onDisappear`, a different discipline). Matches `var name: Task<`
    /// and dictionary-of-tasks properties like `[UUID: Task<`.
    static let storedTaskPattern = #"^\s*(@ObservationIgnored\s+)?(private\s+|fileprivate\s+|internal\s+|public\s+)?(private\(set\)\s+)?var\s+[A-Za-z_][A-Za-z_0-9]*\s*:\s*(\[[A-Za-z_][A-Za-z_0-9]*\s*:\s*)?Task<"#

    /// A `deinit` (plain or `isolated`) whose body — the next few lines — cancels a task. The
    /// look-ahead window is generous on purpose: what matters is that the file's teardown site
    /// cancels *something*.
    static let deinitCancelPattern = #"(?s)\bdeinit\s*\{[^}]*?\.cancel\(\)"#

    /// A block-based observer registration (`addObserver(forName:` possibly split across lines).
    static let blockObserverPattern = #"(?s)\.addObserver\(\s*forName:"#

    /// A manager that holds its host `unowned`. Deliberately looser than the one spelling in the module
    /// today (`unowned let store: any ProximityHost`): a third manager written `unowned var`, or holding
    /// the host under another name, is SCANNED AND FAILED rather than silently skipped. A host's
    /// refinement of the protocol is the host's to hold, in the host's code.
    static let unownedHostPattern = #"unowned\s+(let|var)\s+\w+\s*:\s*any ProximityHost"#

    /// A `Task` CONSTRUCTION in any of its spellings — `Task {`, `Task.detached {`,
    /// `Task(priority: .background) {`, `Task<Void, Never> {`. All four spawn the same detached,
    /// un-cancellable task, and `Task.detached` additionally drops `@_inheritActorContext` so it
    /// would start off the main actor as well. The trailing `{` keeps property declarations
    /// (`var beaconTimer: Task<Void, Never>?`) and `await Task.yield()` out of the match.
    static let spawnPattern = #"\bTask\b\s*(?:\.detached)?\s*(?:<[^>]*>)?\s*(?:\([^)]*\))?\s*\{"#

    /// Whether `line` constructs a `Task`. `///` documentation lines are excluded (the helper's own
    /// doc comment quotes the literal it replaces), as is a match that sits after a `//` on the line.
    static func isSpawnConstruction(_ line: String) -> Bool {
        guard !line.trimmingCharacters(in: .whitespaces).hasPrefix("///"),
              let regex = try? NSRegularExpression(pattern: spawnPattern, options: []),
              let match = regex.firstMatch(in: line, options: [], range: NSRange(line.startIndex..., in: line)),
              let matched = Range(match.range, in: line) else { return false }
        if let comment = line.range(of: "//"), comment.lowerBound < matched.lowerBound { return false }
        return true
    }

    /// The `// host-pin:` marker on a line, split into its kind and the reason after the em-dash.
    /// `///` documentation lines carry none, so the helper may quote the marker vocabulary it names.
    static func hostPinMarker(in line: String) -> (kind: String, reason: String)? {
        guard !line.trimmingCharacters(in: .whitespaces).hasPrefix("///"),
              let start = line.range(of: "// host-pin:") else { return nil }
        let rest = line[start.upperBound...].trimmingCharacters(in: .whitespaces)
        guard let dash = rest.range(of: "\u{2014}") else { return (rest, "") }
        return (String(rest[..<dash.lowerBound]).trimmingCharacters(in: .whitespaces),
                String(rest[dash.upperBound...]).trimmingCharacters(in: .whitespaces))
    }

    /// Audits one host-holding file's `Task` constructions against ML4.
    static func hostPinAudit(of source: String) -> HostPinAudit {
        let lines = source.components(separatedBy: "\n")
        var audit = HostPinAudit()
        // R2: bounded by the source's line count.
        for (index, line) in lines.enumerated() {
            let marker = hostPinMarker(in: line)
            guard isSpawnConstruction(line) else {
                let attached = index + 1 < lines.count && isSpawnConstruction(lines[index + 1])
                if let marker, !attached { audit.record(strayKind: marker.kind, reason: marker.reason, line: index + 1) }
                continue
            }
            audit.spawns += 1
            let own = marker ?? (index > 0 ? hostPinMarker(in: lines[index - 1]) : nil)
            guard let own else {
                audit.unmarkedSpawns.append(index + 1)
                continue
            }
            audit.record(spawnKind: own.kind, reason: own.reason, line: index + 1)
        }
        return audit
    }

    /// Reduces one file to its facts. Line-based for the property rule (which is line-shaped) and
    /// whole-source for the multi-line ones.
    static func facts(for path: String, source: String) -> FileFacts {
        let holdsHost = matches(unownedHostPattern, in: source)
        return FileFacts(
            path: path,
            storesTaskHandle: storesTaskHandle(source),
            cancelsInDeinit: matches(deinitCancelPattern, in: source),
            addsBlockObserver: matches(blockObserverPattern, in: source),
            removesObserver: source.contains("removeObserver("),
            usesObservationTracking: source.contains("withObservationTracking {") || source.contains("withObservationTracking("),
            holdsUnownedHost: holdsHost,
            hostPin: holdsHost ? hostPinAudit(of: source) : .none
        )
    }

    /// Whether `source` stores a `Task<…>` handle (``storedTaskPattern``) on a line that does not carry
    /// `@State`.
    static func storesTaskHandle(_ source: String) -> Bool {
        guard let taskRegex = try? NSRegularExpression(pattern: storedTaskPattern, options: [.anchorsMatchLines]) else {
            return false
        }
        let candidates = taskRegex.matches(in: source, options: [], range: NSRange(source.startIndex..., in: source))
        return candidates.contains { match in
            guard let lineRange = Range(match.range, in: source) else { return false }
            let lineStart = source[..<lineRange.lowerBound].lastIndex(of: "\n").map(source.index(after:)) ?? source.startIndex
            let lineEnd = source[lineRange.upperBound...].firstIndex(of: "\n") ?? source.endIndex
            return !source[lineStart..<lineEnd].contains("@State")
        }
    }

    /// Whether `pattern` matches anywhere in `source`; false when the pattern does not compile, which the
    /// matchers' samples then fail.
    private static func matches(_ pattern: String, in source: String) -> Bool {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: []) else { return false }
        return regex.firstMatch(in: source, options: [], range: NSRange(source.startIndex..., in: source)) != nil
    }
}
