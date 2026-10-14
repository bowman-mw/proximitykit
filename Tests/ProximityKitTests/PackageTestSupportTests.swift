// PackageTestSupportTests.swift
// ProximityKitTests
//
// ProximityKit plan step A1.1: the facts the package tests' support stands on, held where the support
// lives. Every package suite that computes under `.packageTest` (TestSupport/PackageTestNamespace.swift)
// assumes it is sound, and every package suite that reads a source assumes `PackageRoot`
// (TestSupport/PackageRoot.swift) resolves to this package's own folder; a wrong namespace would turn
// every mint and derivation into a refusal, and a wrong root every source read into a vacuous one.
// That `.packageTest` overlaps Fernlet's namespace nowhere is held in FernletTests, which can name both.

import Foundation
import ProximityKit
import Testing

/// The package tests' namespace is sound and their file locator finds this package.
@Suite struct PackageTestSupportTests {

    /// `.packageTest` passes every soundness rule, at every level a binding hands ProximityKit:
    /// `soundness` is `.sound`, the throwing builder returns the same namespace, and its family's labels
    /// are the `Purposes` value the bindings pass for a label group.
    @Test func thePackageTestNamespaceIsSound() throws {
        let namespace = ProximityNamespace.packageTest
        #expect(namespace.soundness == .sound, "the package tests' namespace is unsound: \(namespace.soundness)")
        let validated = try ProximityNamespace.validated(family: .packageTest, installation: .packageTest)
        #expect(validated == namespace, "the throwing builder builds the same namespace")
        #expect(namespace.family.purposes == .packageTest, "the bindings' label group is the namespace's own")
        #expect(namespace.family.purposes.feature.entries.count == 2, "two feature salts, as Fernlet's family declares")
    }

    /// `PackageRoot` is this package's own folder: both markers resolve under it (the manifest a file,
    /// this module's sources a folder), its manifest declares this test target, a source file reads
    /// through it, and inside the Fernlet repository, whose package manifest is named `FernletKit`, the
    /// root is that folder and not the repository's.
    @Test func thePackageRootIsThisPackagesOwnFolder() throws {
        var isDirectory: ObjCBool = false
        let manifest = PackageRoot.url("Package.swift").path
        #expect(FileManager.default.fileExists(atPath: manifest, isDirectory: &isDirectory) && !isDirectory.boolValue,
                "no manifest file at the package root \(PackageRoot.url.path)")
        let sources = PackageRoot.url("Sources/ProximityKit").path
        #expect(FileManager.default.fileExists(atPath: sources, isDirectory: &isDirectory) && isDirectory.boolValue,
                "no ProximityKit source folder at the package root \(PackageRoot.url.path)")

        let manifestText = try PackageRoot.source("Package.swift")
        #expect(manifestText.contains("name: \"ProximityKitTests\""),
                "the root's manifest does not declare this test target, so it is some other package's")
        if manifestText.contains("name: \"FernletKit\"") {
            #expect(PackageRoot.url.lastPathComponent == "FernletKit",
                    "inside the Fernlet repository the root is its FernletKit folder, not \(PackageRoot.url.path)")
        }

        let host = try PackageRoot.source("Sources/ProximityKit/ProximityHost.swift")
        #expect(host.contains("protocol ProximityHost"), "a source read through the root is this module's own")
    }
}
