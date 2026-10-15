// MeshKeyAgreementAdvertisementTests.swift
// ProximityKitTests
//
// P6 item 1 (plan §11.3 item 13(ii)): the signed key-advertisement family, below the manager.
//
// Four claims are walled here, each one a thing a later pass cannot cheaply re-derive:
//
// 1. **The verifier refuses by name, over the whole table.** Wrong mesh, malformed widths, a
//    non-admitted signer, a departed signer, a removed signer, a tampered key, a tampered instant,
//    a re-stamped mesh id and a cross-domain signature each land on their own frozen name.
// 2. **Verification happens BEFORE any conflict decision.** An unverified advertisement that could
//    mark a fingerprint conflicted would let any peer in radio range permanently un-address any
//    member with a few forged bytes. The negative control is non-negotiable, and the compile fence
//    beneath it is `MeshVerifiedKeyAgreementAdvertisement`'s `fileprivate` initializer.
// 3. **The fold refuses a conflict rather than picking one.** `MeshMembershipRecordSet.merging` is
//    earliest-wins and silently keeps ONE of two rows; for a key that is a fail-open, so the set is
//    its own type with its own fold and no merge door at all.
// 4. **The schema bump is real in both directions.** A v2 blob is `corrupt`, not migrated, and the
//    retired `routingInventoryDigest` is gone from the shape rather than left decoding.
//
// The goldens and the framing pairs live where every other membership vector does —
// `MeshMembershipEventGoldenTests` and `CryptographicPurposeBoundaryTests` — so a new vector cannot
// drift away from the family it belongs to.
//
// Fixture instants are anchored to `MeshMembershipEventFixtures.base`, the one epoch every
// membership golden shares, rather than to `MeshRoutedFixtureClock`: nothing under test here reads
// a clock, and nothing here has an expiry, a deadline or a settle path for a wall clock to overtake.
//
// A partial copy (ProximityKit plan step A1.3, batch D: the cells of the Fernlet repository's tests
// that read this module's sources, copied before Fernlet deletes its in-tree copy of the module): of
// that repository's FernletTests file of the same name, this holds only the three cells that read
// ProximityKit's code, under their suites' and tests' names: claim 3's two source walls
// (`MeshKeyAgreementFoldTests.theAdvertisementSetNamesNoSilentMergeDoor`, its walk's half over this
// module, and `.theSetsOwnConstructionSitesAreAllowlistedByFunction`, whole) and claim 4's zero-list
// (`MeshKeyAgreementSchemaTests.theRetiredRoutingInventoryDigestIsGone`, its walk's half over this
// module), with the readers they need. The originals walk every shipping root of Fernlet's, this
// module's folder included; each walk here reads every Swift file of the module through
// `PackageSwiftFiles`, at the walk's floor and with its expected home. The rest of the file, and each
// walk's other half (Fernlet's own roots), stay there, so what this header says of the rest is not held
// here.

import Foundation
import Testing

// MARK: - The fold

/// The set's decision table: what folding one advertisement does, and what it refuses to do. Of the
/// original's cells this holds the two that read ProximityKit's code: the set names no silent merge
/// door, and its own construction sites are allowlisted by function.
@MainActor
@Suite(.serialized)
struct MeshKeyAgreementFoldTests {

    /// Every spelling that reaches the at-rest initializer, matched against **whitespace-collapsed**
    /// text rather than against a raw line.
    ///
    /// The collapse is the third review's P2. This module's house form for a multi-argument
    /// initializer puts the first label on the NEXT line — the declaring file's own
    /// `init(from decoder:)` writes `self.init(` and then `advertisements:` below it — so a per-line
    /// `contains` never saw the declaring file's own construction site, and the allowlist entry that
    /// had been written for it (`init(from decoder: Decoder) throws {`) matched nothing at all.
    /// Every needle here is whitespace-free, which is what lets one `contains` over collapsed text
    /// answer for a site written across two lines as well as for one written on a single line.
    ///
    /// The first needle is the BARE type-with-paren, not `…Set(advertisements:` (pass B review
    /// finding 6) — the same hazard from the other side, where a labelled needle was defeated by a
    /// line break. The second closes `X.init(`, which does not contain `X(`. The third names no type
    /// at all, which is what catches an inferred `= .init(advertisements:`, a bare `.init(` and the
    /// decoder's `self.init(` alike (second fix review finding 9, third review P2).
    static let constructionNeedles = [
        "MeshKeyAgreementAdvertisementSet(",
        "MeshKeyAgreementAdvertisementSet.init(",
        ".init(advertisements:"
    ]

    /// `text` with every whole-line comment dropped and every whitespace character removed.
    ///
    /// Comments go first for the reason `MeshRoutedSourceScan.codeOnly(_:)` exists: a header that
    /// *names* the constructor it forbids is the documentation of the rule, not a violation of it.
    /// Whitespace goes next so a needle can span the line break the house form puts inside a call.
    static func collapsed(_ text: String) -> String {
        MeshRoutedSourceScan.codeOnly(text).filter { !$0.isWhitespace }
    }

    /// The set has no silent merge door, and nothing outside its own file may hand it a row.
    ///
    /// `MeshMembershipRecordSet.merging(_:)`/`.inserting(_:)` dedup earliest-wins and silently keep
    /// ONE of two conflicting rows — for a key that is a fail-open every cell above would pass
    /// straight through, because they all drive the per-element door. So the type declares no
    /// `merging` at all, and its two mutating doors take a value only the verifier can mint.
    ///
    /// **The at-rest constructor is the third door, and it is walled here too** (pass A review,
    /// finding 1): it takes RAW rows and normalization marks conflicts from them, so shipping code
    /// that reached for `MeshKeyAgreementAdvertisementSet(advertisements: payload.advertisements)`
    /// would make conflict decisions on unverified bytes with nothing to stop it. Only the
    /// declaring file — the decoder and the two verified doors — may name it. `markingConflicted(`
    /// is walled on the same principle from the other side: only the fold may mark a member
    /// unaddressable, whatever receiver name a caller gives the set.
    ///
    /// **The needles this cell carries, by name** (third review P3 11 — they had drifted onto the
    /// constant's own doc comment): the three in ``constructionNeedles``, which are the at-rest
    /// initializer's spellings, plus `keyAdvertisements.merging(`, `keyAdvertisements.inserting(`
    /// and `markingConflicted(`, which are the receiver-named doors. Every one of them is tested
    /// against ``collapsed(_:)`` text, so a line break inside a call defeats none of them, and four
    /// union-door declarations (`merging`, `folded`, `union`, `combining`) are refused in the
    /// declaring file itself.
    @Test func theAdvertisementSetNamesNoSilentMergeDoor() throws {
        let declaring = Self.declaringFile
        let source = try PackageRoot.source(PackageSwiftFiles.sourceFolder + "/" + declaring)
        #expect(source.count > 2_000, "the source scan must not be reading an empty file")
        // R2: bounded by the needle list.
        for spelling in ["func merging(", "func folded(", "func union(", "func combining("] {
            #expect(!source.contains(spelling), "the set must not grow a union door: \(spelling)")
        }
        let files = try PackageSwiftFiles.sources()
        #expect(files.count >= PackageSwiftFiles.sourceFloor, """
            the merge-door wall read \(files.count) Swift files under \(PackageSwiftFiles.sourceFolder), \
            below its floor \(PackageSwiftFiles.sourceFloor): the walk is broken, not the module clean
            """)
        #expect(files.contains { $0.path == declaring }, "the walk no longer reaches the set's declaring file")
        #expect(Self.namesADoor(source), """
            the set's declaring file no longer spells a door this wall reads: the set or its doors were \
            renamed, and the needles now match nothing anywhere
            """)
        var namedElsewhere: [String] = []
        // R2: bounded by the module's source file list.
        for file in files {
            let path = file.path
            guard path != declaring else { continue }
            guard Self.namesADoor(file.text) else { continue }
            namedElsewhere.append(path)
        }
        #expect(
            namedElsewhere.isEmpty,
            """
            The advertisement set may only be folded through `MeshKeyAdvertisementFold`, which
            verifies first. These files reach around it: \(namedElsewhere.joined(separator: ", "))
            """
        )
    }

    /// The set's declaring file, by its path under the module's source folder: the one file the
    /// merge-door wall exempts.
    static let declaringFile = "Mesh/MeshKeyAgreementAdvertisement.swift"

    /// Whether `text`, collapsed (``collapsed(_:)``), names the at-rest initializer by any of
    /// ``constructionNeedles`` or one of the receiver-named doors: the original cell's per-file test,
    /// a function here so the declaring file's own spelling is read by the same test, as the wall's
    /// positive control.
    static func namesADoor(_ text: String) -> Bool {
        let collapsed = Self.collapsed(text)
        return Self.constructionNeedles.contains(where: collapsed.contains)
            || collapsed.contains("keyAdvertisements.merging(")
            || collapsed.contains("keyAdvertisements.inserting(")
            || collapsed.contains("markingConflicted(")
    }

    /// The declaring file's exemption is per **declaring type and function**, not per file.
    ///
    /// The at-rest initializer verifies nothing, so even inside the type's own file only the
    /// functions that ARE the set's algebra may name it — otherwise a new fold door added there
    /// reaches the unverified constructor under cover of the file exemption the wall above grants.
    /// Allowlisted by file + **enclosing type** + enclosing declaration, so a new site has to be
    /// argued for by name.
    ///
    /// The type half is the third review's P3 2: the park (`MeshKeyAdvertisementPark`) declares its
    /// own `static var empty:`, which made a declaration-only entry written for the SET into a
    /// second, unintended exemption inside a different type — and the two `init(from decoder:)`
    /// declarations in this file are textually identical, so the pair is the only thing that can
    /// tell them apart. The six entries below are the six sites that exist.
    @Test func theSetsOwnConstructionSitesAreAllowlistedByFunction() throws {
        let allowed = [
            "MeshKeyAgreementAdvertisementSet / static var empty:",
            "MeshKeyAgreementAdvertisementSet / init(from decoder: Decoder) throws {",
            "MeshKeyAgreementAdvertisementSet / func inserting(_ verified:",
            "MeshKeyAgreementAdvertisementSet / func markingConflicted(",
            "MeshKeyAgreementAdvertisementSet / func clearingConflicts(outside",
            "MeshKeyAdvertisementFold / static func restoring("
        ]
        let source = try PackageRoot.source(
            "Sources/ProximityKit/Mesh/MeshKeyAgreementAdvertisement.swift"
        )
        let lines = source.components(separatedBy: "\n")
        var unallowlisted: [String] = []
        var matched: Set<String> = []
        // R2: bounded by the file's own line count.
        for index in lines.indices {
            let window = Self.constructionWindow(at: index, in: lines)
            guard Self.constructionNeedles.contains(where: window.contains) else { continue }
            let site = Self.enclosingSite(of: index, in: lines)
            guard let entry = allowed.first(where: { site.hasPrefix($0) }) else {
                unallowlisted.append("line \(index + 1) in \(site)")
                continue
            }
            matched.insert(entry)
        }
        #expect(
            unallowlisted.isEmpty,
            """
            Only the set's own algebra may name the at-rest initializer, which verifies nothing.
            Unallowlisted sites: \(unallowlisted.joined(separator: " | "))
            """
        )
        // An entry that matches nothing is an exemption for a site that no longer exists — which is
        // exactly what the third review found, and it is indistinguishable from a wall doing its job
        // unless it is asserted (third review P2).
        #expect(matched.count == allowed.count,
                "every allowlist entry must match a real site, or it is exempting nothing")
        #expect(lines.count > 100, "the line scan must not be reading an empty file")
    }

    /// The line at `index`, collapsed, with its continuation folded in when the module's house form
    /// split a construction across two lines.
    ///
    /// The continuation is appended only while the collapsed window **ends at an open paren**, which
    /// is exactly the shape that defeated the per-line scan (`self.init(` with `advertisements:`
    /// below). Extending every line unconditionally would report one site twice — once at its own
    /// line and once at the signature line above it, whose return type names the same set.
    ///
    /// **The fold walks forward rather than taking exactly one line** (final review P3). A blank
    /// line or a whole-line comment between the paren and the first label collapses to the empty
    /// string, so a single-line fold left the window still ending at `(` and matched nothing — a
    /// two-character edit that took a construction site out of the allowlist's sight entirely. The
    /// walk is bounded at ``constructionFoldLimit`` lines, which is more than the house form can
    /// produce and far less than the next declaration.
    private static func constructionWindow(at index: Int, in lines: [String]) -> String {
        var window = Self.collapsed(lines[index])
        var next = index + 1
        // R2: bounded by the fold limit and by the file's own line count.
        while window.hasSuffix("("), next < lines.count, next - index <= Self.constructionFoldLimit {
            window += Self.collapsed(lines[next])
            next += 1
        }
        return window
    }

    /// How many following lines a construction window may fold in while it still ends at an open
    /// paren. Four: the house form needs one, and a blank line or a comment between the paren and
    /// the first label needs the rest.
    private static let constructionFoldLimit = 4

    /// The enclosing type and declaration of the line at `index`, as `"Type / declaration"` — the
    /// key the allowlist is written in.
    private static func enclosingSite(of index: Int, in lines: [String]) -> String {
        let type = Self.enclosingType(of: index, in: lines)
        return "\(type) / \(Self.enclosingDeclaration(of: index, in: lines))"
    }

    /// The nearest declaration at or above `index` — a construction site's owning function.
    ///
    /// **Indentation plus a keyword set**, not a list of modifier spellings (third review P3 3).
    /// The old rule enumerated six starter and five member prefixes, and `public var`,
    /// `private(set) var`, `lazy var`, `internal let` and `public static func` matched none of them:
    /// a construction site inside one walked straight past its own declaration and inherited an
    /// allowlisted function's name from up to forty lines above. Any line at the type's own member
    /// indent of four spaces whose first keyword is `let`/`var`/`func`/`init`/`subscript`/`case` is
    /// now the boundary. A **local** is indented eight, which is what keeps
    /// `restoring(_:verifiedBy:)`'s two local `var`s from standing in for a declaration; the same
    /// indent rule is what makes a stored or computed property a boundary rather than a pass.
    private static func enclosingDeclaration(of index: Int, in lines: [String]) -> String {
        // R2: a construction site is never forty lines from its own signature.
        for offset in 0..<min(40, index + 1) {
            let line = lines[index - offset]
            let text = line.trimmingCharacters(in: .whitespaces)
            guard line.prefix(while: { $0 == " " }).count == 4,
                  Self.declaresMember(text) else { continue }
            return text
        }
        return "no enclosing declaration"
    }

    /// Whether `text` declares a member: any run of modifiers followed by a member keyword.
    ///
    /// The prefix scan is what recognises `@ObservationIgnored private(set) var` and
    /// `public static func` as declarations without naming either spelling. A false positive only
    /// ever NARROWS the allowlist, which is the safe direction for a wall.
    private static func declaresMember(_ text: String) -> Bool {
        let keywords: Set<String> = ["let", "var", "func", "init", "subscript", "case"]
        // R2: bounded by the modifier words one declaration can carry.
        for word in text.split(separator: " ").prefix(6) {
            if keywords.contains(String(word.prefix { $0.isLetter })) { return true }
        }
        return false
    }

    /// The top-level type the line at `index` sits inside, by name.
    ///
    /// A declaration at indent zero that ends in a brace, read from the first type keyword it
    /// carries — so `nonisolated struct MeshKeyAgreementAdvertisementSet: Codable, …` answers
    /// `MeshKeyAgreementAdvertisementSet` however its modifiers and conformances move.
    private static func enclosingType(of index: Int, in lines: [String]) -> String {
        let starters = ["struct ", "enum ", "class ", "actor ", "extension ", "protocol "]
        // R2: bounded by the file's own line count.
        for offset in 0..<(index + 1) {
            let line = lines[index - offset]
            guard line.first?.isWhitespace == false, line.hasSuffix("{") else { continue }
            // R2: bounded by the starter list.
            for starter in starters {
                guard let range = line.range(of: starter) else { continue }
                let name = line[range.upperBound...].prefix {
                    $0.isLetter || $0.isNumber || $0 == "_"
                }
                guard !name.isEmpty else { continue }
                return String(name)
            }
        }
        return "no enclosing type"
    }
}

// MARK: - Schema 3

/// The at-rest half: the set round-trips, a v2 blob is refused, and the retired field is gone. Of the
/// original's cells this holds the one that reads ProximityKit's code: the retired field is gone.
@Suite(.serialized)
struct MeshKeyAgreementSchemaTests {

    /// The retired field, as a zero-list. `routingInventoryDigest` had been provably dead since P5
    /// item 5 (always nil) and was still a decoded field of the schema-2 blob; item 1's bump is the
    /// cheap moment to remove it, and this cell is what stops it coming back by copy-paste.
    ///
    /// The needles are **declaration and use** shapes rather than the bare identifier, because
    /// ``MeshSessionContextSchema``'s own version history says in prose what version 3 retired —
    /// the same way the record kinds' doc still names the retired `sessionGoodbye`. A wall that
    /// forbade the word would forbid the record of the removal.
    @Test func theRetiredRoutingInventoryDigestIsGone() throws {
        let needles = [
            "var routingInventoryDigest", "let routingInventoryDigest",
            ".routingInventoryDigest", "routingInventoryDigest:"
        ]
        let files = try PackageSwiftFiles.sources()
        #expect(files.count >= PackageSwiftFiles.sourceFloor, """
            the retired-field wall read \(files.count) Swift files under \(PackageSwiftFiles.sourceFolder), \
            below its floor \(PackageSwiftFiles.sourceFloor): the walk is broken, not the module clean
            """)
        let record = files.first { $0.path == Self.removalRecordFile }
        #expect(record?.text.contains("routingInventoryDigest") == true, """
            \(Self.removalRecordFile), whose schema history records in prose that version 3 retired the \
            field, is no longer read with that record: the walk lost it, or the reader stopped reading \
            raw text, and the zero below could be a zero over nothing
            """)
        var survivors: [String] = []
        // R2: bounded by the module's source file list.
        for file in files {
            guard needles.contains(where: file.text.contains) else { continue }
            survivors.append(file.path)
        }
        #expect(
            survivors.isEmpty,
            "the retired field is declared or read again in: \(survivors.joined(separator: ", "))"
        )
    }

    /// The file whose schema history records the field's retirement in prose, by its path under the
    /// module's source folder: the wall's expected home, read with the walk.
    static let removalRecordFile = "Mesh/MeshSessionContext.swift"
}
