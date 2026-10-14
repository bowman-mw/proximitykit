// PackageSwiftFiles.swift
// ProximityKitTests
//
// ProximityKit plan step A1.1: the walker the package's own walls read the package's Swift files
// through. A wall over the package's tests reads every Swift file of the test target as text, a wall
// over ProximityKit's code every Swift file of the module, and the folder it walks has to mean the same
// files wherever the package sits: inside the Fernlet repository, where the package is the `FernletKit`
// folder, and at the root of ProximityKit's own repository. So each folder is found through
// `PackageRoot`, the test folder by its name under the package root's `Tests` folder and the module by
// its path under the package root, and each file is named by its path under its folder, which is the
// same in both. A blind walker would make every wall that reads through it vacuous, so the walker holds
// no floor of its own: each caller holds its read to ``PackageSwiftFiles/testFloor`` or
// ``PackageSwiftFiles/sourceFloor`` in its own cell, with its own message.

import Foundation

/// The package's Swift files read off disk through ``PackageRoot``: every Swift file under the test
/// target's folder, or under the module's source folder, each by its path under that folder and its
/// text, sorted by path.
///
/// **Floors.** ``testFloor`` and ``sourceFloor`` are the fewest files a walk of the test folder and of
/// the source folder may return. The walker never checks them itself: an expectation here would report
/// against no cell, so each caller expects its read at or above the floor, in the cell that leans on the
/// read, with a message naming that cell's rule.
///
/// **Paths.** A file's path is read off its URL's last `/<folder>/` component, so a symlinked checkout
/// names its files alike. A file outside the folder keeps its full path, which matches no expected path
/// and fails loudly.
///
/// **Concurrency.** Stateless: every member is a constant or a read of the disk; safe from any isolation.
nonisolated enum PackageSwiftFiles {

    /// The test target's folder, by its name under the package root's `Tests` folder.
    static let testFolder = "ProximityKitTests"

    /// The fewest Swift files a walk of ``testFolder`` may return: about four fifths of the 28 the folder
    /// held when the keychain door's wall was written (plan step A1.1.10), the door wall's own floor, so a
    /// folder that stops resolving fails its caller rather than reading as clean.
    static let testFloor = 22

    /// The module's source folder, by its path under the package root.
    static let sourceFolder = "Sources/ProximityKit"

    /// The fewest Swift files a walk of ``sourceFolder`` may return: about four fifths of the 135 the
    /// module held when the keychain door's wall was written (plan step A1.1.10), the door wall's own
    /// floor, so a folder that stops resolving fails its caller rather than reading as clean.
    static let sourceFloor = 108

    /// One Swift file a walk read.
    struct File: Sendable {
        /// Its path under the folder walked, e.g. `TestSupport/PackageRoot.swift` under the test folder or
        /// `Support/ProximityAudit.swift` under the source folder.
        let path: String
        /// Its text, exactly as written: a caller lexes what it needs.
        let text: String
    }

    /// Every Swift file under the test target's folder, sorted by path.
    ///
    /// - Returns: Each file's path under ``testFolder`` and its text.
    /// - Throws: A read's error when a file the walk found cannot be read as UTF-8.
    static func tests() throws -> [File] {
        try files(under: PackageRoot.url("Tests").appendingPathComponent(testFolder), folder: testFolder)
    }

    /// Every Swift file under the module's source folder, sorted by path.
    ///
    /// - Returns: Each file's path under ``sourceFolder`` and its text.
    /// - Throws: A read's error when a file the walk found cannot be read as UTF-8.
    static func sources() throws -> [File] {
        try files(under: PackageRoot.url(sourceFolder), folder: sourceFolder)
    }

    /// Every Swift file under `root`, each by its path under `folder`, sorted by path.
    private static func files(under root: URL, folder: String) throws -> [File] {
        let walker = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil)
        let urls = (walker?.allObjects as? [URL] ?? []).filter { $0.pathExtension == "swift" }
        var files: [File] = []
        // R2: bounded by the folder's file list.
        for url in urls.sorted(by: { $0.path < $1.path }) {
            files.append(File(path: relativePath(of: url, under: folder), text: try String(contentsOf: url, encoding: .utf8)))
        }
        return files
    }

    /// `url`'s path under `folder`, read off the path's last `/<folder>/` component so a symlinked
    /// checkout resolves alike; the full path when it is not under one.
    private static func relativePath(of url: URL, under folder: String) -> String {
        let path = url.path
        guard let range = path.range(of: "/" + folder + "/", options: .backwards) else { return path }
        return String(path[range.upperBound...])
    }
}
