// PackageRoot.swift
// ProximityKitTests
//
// ProximityKit plan step A1.1: the file locator ProximityKit's package tests read a source through. A
// package suite that pins a call site by needle reads this module's own files off disk, and the path it
// names has to mean the same file wherever the package sits: inside the Fernlet repository, where the
// package is the `FernletKit` folder, and at the root of ProximityKit's own repository. So the paths are
// relative to the package root, and the root is found by the two entries that mark it in both places.

import Foundation

/// Locates ProximityKit's package root for the package tests that read a file off disk: the first
/// directory at or above this file's folder that holds both `Package.swift` and `Sources/ProximityKit`.
/// Inside the Fernlet repository that is its `FernletKit` folder, never the repository's root (which
/// holds no manifest); in ProximityKit's own repository it is that repository's root. Paths are
/// relative to it (`Sources/ProximityKit/Transport/NetworkMeshSession.swift`), so a suite names the same
/// path in either.
///
/// **Why markers, not a depth.** A suite that counted `deletingLastPathComponent()` calls up from its
/// own file would resolve one directory off the day the layout moved, and a source-reading cell handed
/// a wrong root reads nothing and can pass vacuously. Anchored on markers, a layout change either still
/// resolves or stops the run.
///
/// **What it reads.** It only locates the root. A package suite reads only `Package.swift`,
/// `Sources/ProximityKit/**` and `Tests/**` under it, never a path above it: the invariant
/// `PackageTestHygieneTests.packageHazardAllowlist` states for this file's one line that reads the
/// compiler's path of its own source.
///
/// **Concurrency.** `url` is an immutable `let` resolved once on first touch; safe from any isolation.
nonisolated enum PackageRoot {

    /// The entries that together mark the package root, relative to it: the manifest and this module's
    /// source folder. Both must resolve, so a directory holding some other package's manifest cannot
    /// satisfy the search.
    private static let markers = ["Package.swift", "Sources/ProximityKit"]

    /// The package root, found by walking up from this file's folder until every entry in ``markers``
    /// resolves.
    ///
    /// Traps rather than returning a fallback: a suite that cannot find the package's sources must stop
    /// the run, not read an empty directory and call itself green.
    static let url: URL = {
        let origin = URL(fileURLWithPath: #filePath)
        var candidate = origin.deletingLastPathComponent()
        // R2: bounded by the path's component count; each pass removes one component.
        while candidate.pathComponents.count > 1 {
            if markers.allSatisfy({
                FileManager.default.fileExists(atPath: candidate.appendingPathComponent($0).path)
            }) {
                return candidate
            }
            candidate.deleteLastPathComponent()
        }
        fatalError("""
            Could not locate ProximityKit's package root by walking up from \(origin.path).
            Expected an ancestor containing all of: \(markers.joined(separator: ", ")).
            If the package's layout moved, update PackageRoot.markers; do NOT let a suite fall back to a \
            guessed path, because a wrong root makes a source-reading cell pass without reading.
            """)
    }()

    /// `url` joined with a package-root-relative path, e.g. `Sources/ProximityKit/ProximityHost.swift`.
    ///
    /// - Parameter relativePath: A path relative to the package root.
    /// - Returns: The file's URL under the package root.
    static func url(_ relativePath: String) -> URL {
        url.appendingPathComponent(relativePath)
    }

    /// The UTF-8 contents of a package-root-relative file. Throws if it is missing, so a rename fails
    /// loudly instead of yielding an empty string that every `contains` check would pass against.
    ///
    /// - Parameter relativePath: A path relative to the package root.
    /// - Returns: The file's text.
    /// - Throws: The read's error when the file is missing or is not UTF-8.
    static func source(_ relativePath: String) throws -> String {
        try String(contentsOf: url(relativePath), encoding: .utf8)
    }
}
