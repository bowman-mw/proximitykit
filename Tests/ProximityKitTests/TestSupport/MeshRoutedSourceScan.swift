// MeshRoutedSourceScan.swift
// ProximityKitTests
//
// ProximityKit plan step A1, the split's first batch of copied suites: the source-scan helpers the
// copied source-reading cells read ProximityKit's code through, copied verbatim from the Fernlet
// repository's FernletTests (its `MeshRoutedStoreIsolationTests.swift`, whose store isolation wall the
// package did not copy then, so the helper takes a file of its own here; since plan step A1.3's batch D
// the package's file of that name holds 11 of that suite's cells, its source walls). Each copied cell
// hands it a source it read through `PackageRoot`.

import Foundation

/// Source-scan helpers shared by the routed walls and, since plan step A1.3's batch D, by the mesh,
/// session and pair copies of Fernlet's source walls too. A free enum rather than a static on a suite,
/// because the suites that need it are not all main-actor isolated.
enum MeshRoutedSourceScan {

    /// `source` with every whole-line comment removed, so a grep-wall states something about CODE
    /// rather than about the prose that explains why the code does not do a thing.
    static func codeOnly(_ source: String) -> String {
        source
            .split(separator: "\n", omittingEmptySubsequences: false)
            .filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("//") }
            .joined(separator: "\n")
    }

    /// The brace-matched body of the declaration whose signature starts with `signature`, braces
    /// included — or nil when the signature is absent or its braces do not close.
    ///
    /// Added by P6 item 10's SET A for the two walls the item 7 fix review found measuring TEXT
    /// PROXIMITY rather than CONTAINMENT (its P2-A and P3-c): "the door's refusals" and "the
    /// statement inside that closure" are claims about a *body*, and `components(separatedBy:)`
    /// answers them with whatever happens to lie between two literals — which stays green when the
    /// thing moves out of the body into the next one. Pass `codeOnly(_:)` output: a whole-line
    /// comment mentioning a brace would otherwise be counted.
    ///
    /// - Parameters:
    ///   - signature: A declaration prefix unique in `source` (e.g. `"private func foo("`).
    ///   - source: Comment-stripped Swift.
    /// - Returns: `{ … }` for the first match, nil when there is none.
    static func bracedBody(after signature: String, in source: String) -> String? {
        guard let head = source.range(of: signature) else { return nil }
        guard let open = openingBrace(in: source, from: head.lowerBound) else { return nil }
        var depth = 0
        var index = open
        // R2: bounded by the remaining characters of a finite string.
        while index < source.endIndex {
            let character = source[index]
            if character == "{" { depth += 1 }
            if character == "}" {
                depth -= 1
                if depth == 0 { return String(source[open...index]) }
            }
            index = source.index(after: index)
        }
        return nil
    }

    /// Index of the `{` that opens the declaration's body — the first one not inside the signature's
    /// own parentheses, so a defaulted closure argument does not steal it.
    private static func openingBrace(in source: String, from start: String.Index) -> String.Index? {
        var parens = 0
        var index = start
        // R2: bounded by the remaining characters.
        while index < source.endIndex {
            let character = source[index]
            if character == "(" { parens += 1 }
            if character == ")" { parens -= 1 }
            if character == "{" && parens == 0 { return index }
            index = source.index(after: index)
        }
        return nil
    }
}
