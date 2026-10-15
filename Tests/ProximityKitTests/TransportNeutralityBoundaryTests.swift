// TransportNeutralityBoundaryTests.swift
// ProximityKitTests
//
// A partial copy (ProximityKit plan step A1.3, which copies into the package every cell of the Fernlet
// repository's tests that reads this module's sources before that repository stops holding them): the
// Fernlet repository's FernletTests suite of this name walks five roots, this module's among them, and
// holds five of its six floor files in this module. This copy holds its three cells over this module's
// root alone, with the suite's name and theirs unchanged, the module walked through the package's
// walker (`TestSupport/PackageSwiftFiles.swift`) at its floor, the five floor files by their paths
// under the package root. The other four roots (FernletProximityUI, FernletConnections, FernletSocial
// and the app) and the presence manager's floor file stay in that repository's original. The package's
// platform wall (`ProximityPlatformNeutralityTests`) also refuses the framework's import in this
// module, more strictly: every module ProximityKit names must be a neutral baseline module or a
// declared seam.

import Foundation
import Testing

/// Grep-wall for what P1 set up and the deletion round finished: **MultipeerConnectivity is gone.**
///
/// Transport neutrality is only worth having if it stays true. Nothing in the compiler enforces it —
/// `MultipeerConnectivity` is an SDK framework, so no package dependency rule can see it, and
/// re-adding `import MultipeerConnectivity` to a manager compiles clean and passes every existing test.
/// This scan, beside the platform wall's import rule, is what would notice.
///
/// P1 narrowed the framework to two files so a later phase could delete them; P9 crossed the three
/// radios to Network.framework QUIC behind that seam, the cutover round flipped the default, and the
/// deletion round (2026-09-22) removed the two files. The wall stays because the risk it names never
/// went away: a stray framework type in a manager would compile clean today exactly as it would
/// have in P2, and this scan is still what would notice.
struct TransportNeutralityBoundaryTests {

    /// The files allowed to name MultipeerConnectivity types, by their paths under the package root.
    /// **Empty, and that is the point.**
    ///
    /// P1 narrowed the framework to two files so a later phase could delete them; the deletion round
    /// (2026-09-22) did. An empty permit list does not switch this wall off — both scans below still
    /// walk every Swift file of the module and assert **zero** occurrences, which is the strongest
    /// this wall has ever been. Do not prune the suite for looking vacuous: it stands between the
    /// module and a re-added `import MultipeerConnectivity`, which would compile clean and pass every
    /// test but the walls.
    ///
    /// Re-adding an entry here is a phase decision, not a fix for a red.
    private static let permittedFiles: [String] = []

    /// Framework type prefixes, matched as whole identifiers.
    ///
    /// The whole-identifier rule outlived the names it was written for (`MCPeerIDStoring`,
    /// `FileMCPeerIDStore`, `MeshMultipeerSession` — Fernlet's own, all deleted in the deletion
    /// round). It stays because the rule is the correct one: a future `MCSessionFoo` of the module's
    /// own would otherwise be reported under `MCSession`, and `MCSessionSendDataMode` must be
    /// reported once, under its own entry. ``containsIdentifier(_:in:)`` is where it lives.
    private static let frameworkSymbols = [
        "MCSession",
        "MCPeerID",
        "MCNearbyServiceAdvertiser",
        "MCNearbyServiceBrowser",
        "MCSessionSendDataMode",
        "MCSessionState",
        "MCError"
    ]

    /// A hard floor: these files were neutralized in P1 and must stay scanned. If one is renamed out
    /// of the module the scan would silently stop covering it, which is how a wall quietly stops
    /// being one. By their paths under the package root; the Fernlet repository's original also
    /// holds its presence manager, FernletSocial's.
    private static let floorFiles = [
        "Sources/ProximityKit/Engine/ProximityCoordinator.swift",
        "Sources/ProximityKit/Mesh/MeshNetworkManager.swift",
        "Sources/ProximityKit/PairSession/ProximityPairSession.swift",
        "Sources/ProximityKit/Transport/PeerTransport.swift",
        "Sources/ProximityKit/Transport/PeerHandle.swift"
    ]

    /// No file of the module imports MultipeerConnectivity.
    @Test func multipeerConnectivityIsNotImportedAnywhere() throws {
        var offenders: [String] = []
        // R2: bounded by the module's file list.
        for (path, source) in try Self.scannedSwiftFiles() where !Self.permittedFiles.contains(path) {
            // R2: bounded by the file's lines.
            for (index, line) in source.components(separatedBy: .newlines).enumerated()
            where line.hasPrefix("import MultipeerConnectivity") {
                offenders.append("\(path):\(index + 1)")
            }
        }
        #expect(
            offenders.isEmpty,
            """
            \(offenders.count) file(s) import MultipeerConnectivity outside the two files that own it.
            The shared transport surface is framework-free so a QUIC conformer can slot in beside the
            MC one (plan §6/§7); an import here is how that quietly stops being true:
            \(offenders.sorted().joined(separator: "\n"))
            """
        )
    }

    /// No code line of the module names a MultipeerConnectivity type.
    @Test func noFrameworkPeerTypeAppearsAnywhere() throws {
        var offenders: [String] = []
        // R2: bounded by the module's file list.
        for (path, source) in try Self.scannedSwiftFiles() where !Self.permittedFiles.contains(path) {
            // R2: bounded by the file's lines.
            for (index, line) in source.components(separatedBy: .newlines).enumerated() {
                offenders.append(contentsOf: Self.violations(in: line, at: index, of: path))
            }
        }
        #expect(
            offenders.isEmpty,
            """
            \(offenders.count) MultipeerConnectivity type reference(s) outside the two files that own
            them. Prose about MC is fine — a type is not:
            \(offenders.sorted().joined(separator: "\n"))
            """
        )
    }

    /// Every floor file exists and is inside the scan, so coverage cannot drop by a rename.
    @Test func everyFloorFileIsStillCovered() throws {
        let scanned = Set(try Self.scannedSwiftFiles().map(\.path))
        // R2: bounded by the floor list.
        for path in Self.floorFiles {
            #expect(scanned.contains(path), "floor file dropped out of the scan: \(path)")
        }
        // R2: bounded by the permit list.
        for path in Self.permittedFiles {
            #expect(
                FileManager.default.fileExists(atPath: PackageRoot.url(path).path),
                "permitted file no longer exists — prune the entry or the wall is scanning nothing: \(path)"
            )
        }
    }

    // MARK: - Scanning

    /// Every Swift file of the module, by its path under the package root, with its text: the
    /// package's walker, held to its floor, so a walk that stops resolving fails here rather than
    /// reading as clean (the Fernlet repository's original skips a root that does not resolve).
    private static func scannedSwiftFiles() throws -> [(path: String, text: String)] {
        let files = try PackageSwiftFiles.sources()
        #expect(files.count >= PackageSwiftFiles.sourceFloor, """
            the transport-neutrality scan walked \(files.count) ProximityKit files (floor \
            \(PackageSwiftFiles.sourceFloor)): the walk is broken, not the module clean
            """)
        return files.map { (path: PackageSwiftFiles.sourceFolder + "/" + $0.path, text: $0.text) }
    }

    /// Framework symbols used as CODE on one line. Comment lines are skipped: the neutralized files
    /// deliberately explain what the MC layer beneath them does, and prose is not a dependency.
    private static func violations(in line: String, at index: Int, of path: String) -> [String] {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard !trimmed.hasPrefix("//"), !trimmed.hasPrefix("*") else { return [] }
        let code = withoutStringLiterals(withoutTrailingComment(line))
        var hits: [String] = []
        // R2: bounded by the symbol list.
        for symbol in frameworkSymbols where containsIdentifier(symbol, in: code) {
            hits.append("\(path):\(index + 1) — \(symbol)")
        }
        return hits
    }

    /// Drops a trailing `//` comment. Prose beside code is prose; only the code half is a dependency.
    private static func withoutTrailingComment(_ line: String) -> String {
        guard let marker = line.range(of: "//") else { return line }
        return String(line[line.startIndex..<marker.lowerBound])
    }

    /// Blanks out double-quoted literals. A UI label or an audit key that spells a framework type
    /// names it for a human, and is not a compile-time dependency on it.
    private static func withoutStringLiterals(_ line: String) -> String {
        var result = ""
        var insideLiteral = false
        var escaped = false
        // R2: bounded by the line's characters.
        for character in line {
            if escaped {
                escaped = false
                continue
            }
            if character == "\\" && insideLiteral {
                escaped = true
                continue
            }
            if character == "\"" {
                insideLiteral.toggle()
                continue
            }
            if !insideLiteral { result.append(character) }
        }
        return result
    }

    /// Whole-identifier match: the character before must not be a Swift identifier character (so
    /// `FileMCPeerIDStore` does not match `MCPeerID`) and the character after must not continue the
    /// identifier (so `MCSessionSendDataMode` is reported once, under its own entry, not as
    /// `MCSession`).
    private static func containsIdentifier(_ symbol: String, in line: String) -> Bool {
        var searchStart = line.startIndex
        // R2: each pass moves past one occurrence, so the loop ends within the line's length.
        while let range = line.range(of: symbol, range: searchStart..<line.endIndex) {
            let beforeOK = range.lowerBound == line.startIndex
                || !isIdentifierCharacter(line[line.index(before: range.lowerBound)])
            let afterOK = range.upperBound == line.endIndex
                || !isIdentifierCharacter(line[range.upperBound])
            if beforeOK && afterOK { return true }
            searchStart = range.upperBound
        }
        return false
    }

    /// Whether `character` may stand inside a Swift identifier.
    private static func isIdentifierCharacter(_ character: Character) -> Bool {
        character.isLetter || character.isNumber || character == "_"
    }
}
