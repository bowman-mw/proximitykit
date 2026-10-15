// MeshRoutedCapacityTests.swift
// ProximityKitTests
//
// Network migration P5 item 9 (plan §11's backpressure clause, §3.4's "bounded everything"): the
// STORE half — every cap refused by its own name at every door, the cap model as one injectable
// value, the parked-set drop rule, and the sweeps that finally have callers.
//
// Three disciplines the whole file runs on:
//
// - **Injected small bounds wherever the claim is about a cap rather than about the constant.**
//   `MeshRoutedStore(scope:capacity:)` is the seam, and it is the SAME model the doors and the
//   accounting read — cell `theUsageReadsTheStoresOwnCapacity` is what stops those diverging.
// - **The at-rest guards stay the FORMAT's.** `init(from:)` is a `Codable` initialiser with no
//   injection point, and an injected capacity is always ≤ production, so an index written under
//   small bounds still decodes clean. Two cells pin exactly that.
// - **Backpressure is not data loss.** A capacity refusal writes nothing and drops nothing; the one
//   rule that removes held bytes on a refusal is `unknownTypeToken` **from the set's own origin**,
//   and the rest of the ten-case table is asserted, not merely written down.
//
// Every test runs on its own scope (temp directory + a `.test.` keychain service), in
// `MeshRoutedStoreIsolationTests`' idiom.
//
// A partial copy (ProximityKit plan step A1.3's batch D, the routed track): of the Fernlet
// repository's FernletTests file of the same name, this holds only the two cells of
// `MeshRoutedCapacityTests` that read ProximityKit's sources, `everyIndexGrowthSiteAnswersACap` and
// `theStoreHasExactlyTwoAdmissionDoors`, with the two source-scanning helpers they call, under their
// suite's name and their own; the suite's other cells, its fixtures and the file's other suites stay
// there, so what this header says of them is not held here.

import Foundation
import Testing

// MARK: - The caps

/// Every cap, refused by its own name at every door it guards — under INJECTED bounds, so the claim
/// is about the cap and not about how long it takes to reach 1024 records.
@MainActor
@Suite(.serialized)
struct MeshRoutedCapacityTests {

    /// Every index growth site answers a cap — the census that makes "nothing grows silently"
    /// mechanical rather than a promise.
    @Test func everyIndexGrowthSiteAnswersACap() throws {
        let expected = [
            "MeshRoutedCustody.swift": 5, "MeshRoutedCustodyHandoff.swift": 2,
            "MeshRoutedCustodyCommit.swift": 1, "MeshRoutedDeliveryCommit.swift": 1,
            "MeshRoutedDeliveryIngest.swift": 1
        ]
        var receivers: Set<String> = []
        var total = 0
        for (name, count) in expected.sorted(by: { $0.key < $1.key }) {
            let code = MeshRoutedSourceScan.codeOnly(
                try PackageRoot.source("Sources/ProximityKit/Mesh/\(name)")
            )
            let sites = Self.upsertReceivers(in: code)
            #expect(sites.count == count, "a new growth site owes a capacity answer: \(name)")
            receivers.formUnion(sites)
            total += sites.count
        }
        #expect(total == 10)
        // A THIRD receiver spelling would hide an eleventh site behind a green census: today the
        // sites are spelled `index.upsert(` and `updated.upsert(`, and one of the two admission
        // doors is the latter.
        #expect(receivers == ["index", "updated"])
    }

    /// Every `capacity*` refusal is in the manager's "this device is full" set — a new one that never
    /// The "own items" wall (D-9.2): the store has exactly TWO admission doors, and both carry the
    /// capacity check. P6's mint inherits the refusal or fails here.
    @Test func theStoreHasExactlyTwoAdmissionDoors() throws {
        let code = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Mesh/MeshRoutedCustody.swift")
        )
        #expect(Self.occurrences(of: "recordAdmitting(", in: code) == 2, "one definition, one caller")
        #expect(Self.occurrences(of: "recordStaging(", in: code) == 2)
        #expect(Self.occurrences(of: "capacityRefusal(", in: code) == 7,
                "three definitions and four call sites — one per capacity-guarded door")
    }

    /// The origin's own staging into a full store is refused at the door P6's mint will use.
    // MARK: Source scanning

    /// The receiver names of every `.upsert(` call in `code`.
    private static func upsertReceivers(in code: String) -> [String] {
        var found: [String] = []
        var scanner = Substring(code)
        while let range = scanner.range(of: ".upsert(") {
            let head = scanner[scanner.startIndex..<range.lowerBound]
            let name = head.reversed().prefix { $0.isLetter || $0.isNumber }
            found.append(String(name.reversed()))
            scanner = scanner[range.upperBound...]
        }
        return found
    }

    /// How many times `needle` appears in `code`.
    private static func occurrences(of needle: String, in code: String) -> Int {
        var count = 0
        var scanner = Substring(code)
        while let range = scanner.range(of: needle) {
            count += 1
            scanner = scanner[range.upperBound...]
        }
        return count
    }
}
