// PackageTestSupportTests.swift
// ProximityKitTests
//
// ProximityKit plan step A1.1: the facts the package tests' support stands on, held where the support
// lives. Every package suite that computes under `.packageTest` (TestSupport/PackageTestNamespace.swift)
// assumes it is sound, and every package suite that reads a source assumes `PackageRoot`
// (TestSupport/PackageRoot.swift) resolves to this package's own folder; a wrong namespace would turn
// every mint and derivation into a refusal, and a wrong root every source read into a vacuous one.
// That `.packageTest` overlaps Fernlet's namespace nowhere is held in FernletTests, which can name both.
// Since ProximityKit plan step A1's second batch of copied suites, the install binding a cell can switch
// (TestSupport/PackageSwitchableInstallBinding.swift) is held here too: the store suites copied from
// Fernlet's tests read it where they read Fernlet's adapter over `DeviceBindingID`, so it must answer as
// that adapter does, or each such cell would test a binding Fernlet's never was.

import Foundation
import ProximityKit
import Security
import Testing

/// The package tests' namespace is sound, their file locator finds this package, and their switchable
/// install binding answers as Fernlet's adapter answers.
@Suite struct PackageTestSupportTests {

    /// `.packageTest` passes every soundness rule, at every level a binding hands ProximityKit:
    /// `soundness` is `.sound`, the throwing builder returns the same namespace, and its family's labels
    /// are the package tests' own `Purposes` (`.packageTest`).
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

    /// The switchable install binding answers as Fernlet's adapter over `DeviceBindingID` does, case for
    /// case: its install's bytes with no override, for a seal and an open alike; an override's bytes for
    /// both; nothing for both while the binding is unavailable; and, while a read fails, nothing for a
    /// seal and the retryable error with `errSecIO` for an open. The override holds only inside the work
    /// it wraps.
    @Test func theSwitchableInstallBindingAnswersAsTheOverrideInForce() throws {
        let binding = PackageSwitchableInstallBinding()
        let own = PackageSwitchableInstallBinding.installBytes
        #expect(own.count == 16, "an install's binding is sixteen bytes, as Fernlet's binding row is")
        #expect(try binding.read(for: .seal) == own)
        #expect(try binding.read(for: .open) == own)
        let other = Data(repeating: 0x0B, count: 16)
        let switched = try PackageSwitchableInstallBinding.testOverride.withValue(.identifier(other)) {
            (seal: try binding.read(for: .seal), open: try binding.read(for: .open))
        }
        #expect(switched.seal == other && switched.open == other, "another install's bytes, for a seal and an open alike")
        let absent = try PackageSwitchableInstallBinding.testOverride.withValue(.unavailable) {
            (seal: try binding.read(for: .seal), open: try binding.read(for: .open))
        }
        #expect(absent.seal == nil && absent.open == nil, "an unavailable binding answers nothing to either")
        let failing = try PackageSwitchableInstallBinding.testOverride.withValue(.readError) {
            let open = { () throws(ProximityInstallBindingReadError) -> Data? in try binding.read(for: .open) }
            return (seal: try binding.read(for: .seal), open: Result(catching: open))
        }
        #expect(failing.seal == nil, "a seal whose read fails refuses, as an absent binding does")
        #expect(failing.open == .failure(ProximityInstallBindingReadError(status: errSecIO)),
                "an open whose read fails defers, with the status Fernlet's binding throws")
        #expect(try binding.read(for: .seal) == own, "the override held outside the work it wrapped")
    }
}
