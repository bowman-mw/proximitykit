// MeshRoutedCustodyTests.swift
// ProximityKitTests
//
// P5 item 3 (plan §11, C13): the custody verbs — the chunk-set decisions the durable store shares
// with the in-memory reassembler, the delivery map it persists, and the evidence behind every
// `custodied` rung.
//
// Three claims are walled here:
//
// 1. **One decision, two forms (C13).** `MeshChunkAssembly` and `MeshRoutedStore` reach the same
//    verdict for the same inputs on BOTH doors — per-chunk admission and manifest binding — because
//    they call the same pure function. The differential drives identical event sequences through
//    both and compares value for value; item 2's own `MeshChunkAssemblyTests` pass unmodified beside
//    it, which is what makes the extraction a refactor rather than a rewrite.
// 2. **The delivery map round-trips through the ORIGIN'S SIGNED MANIFEST.** The destination set is
//    never stored, `departed` is never encoded and is refused on decode, and a restored target still
//    refuses a regression and a set mismatch.
// 3. **Every `custodied` rung is backed by stored evidence**, written in the same index write as the
//    rung it evidences — and the recorded custodian is the receipt's SIGNER, because there is no
//    other parameter that could disagree with it.
//
// Nothing here sleeps, and every instant is injected.
//
// A partial copy (ProximityKit plan step A1.3's batch D, the routed track): of the Fernlet
// repository's FernletTests file of the same name, this holds only the one cell of
// `MeshRoutedCustodyEvidenceTests` that reads ProximityKit's sources,
// `theRoutedStoreNamesNoDecryptionSeam`, under its suite's name and its own; the suite's other cells,
// its fixtures and the file's other suites stay there, so what this header says of them is not held
// here.

import Foundation
import Testing

// MARK: - Evidence, caps and first-seen

/// What the store writes, refuses and counts.
@MainActor
@Suite(.serialized)
struct MeshRoutedCustodyEvidenceTests {

    /// The store never names a decryption seam: no unwrap, no content key, no key-agreement key —
    /// which is what makes custody ciphertext-only on a locked device by construction.
    ///
    /// `MeshRoutedAccessGate.swift` joined the list at P5 item 10: it is the file that answers
    /// *whether plaintext may exist*, so it is precisely the file a future "just decrypt it here"
    /// would be tempted into — and it must stay as free of a decryption seam as the store itself.
    @Test func theRoutedStoreNamesNoDecryptionSeam() throws {
        let files = [
            "MeshRoutedStore.swift", "MeshRoutedCustody.swift", "MeshRoutedCustodyCommit.swift",
            "MeshRoutedIndex.swift", "MeshRoutedStoreKey.swift", "MeshRoutedContentHasher.swift",
            "MeshChunkAdmissionRule.swift", "MeshRoutedCustodyHandoff.swift",
            "MeshRoutedCapacity.swift", "MeshRoutedDeliveryHold.swift",
            "MeshRoutedAccessGate.swift", "MeshRoutedRefusalBudget.swift"
        ]
        var scanned = 0
        var sealing: [String] = []
        for name in files {
            let code = MeshRoutedSourceScan.codeOnly(try PackageRoot.source("Sources/ProximityKit/Mesh/\(name)"))
            scanned += 1
            for forbidden in ["MeshRoutedContentKeyWrapper", "localKeyAgreement", ".unwrap("] {
                #expect(code.contains(forbidden) == false, "\(name) names \(forbidden)")
            }
            if code.contains("ColumnCrypto") { sealing.append(name) }
        }
        #expect(scanned == files.count)
        // `ColumnCrypto` is reached in exactly one of them: the at-rest seal, and nothing else.
        #expect(sealing == ["MeshRoutedStore.swift"], "the at-rest seal must live in one file: \(sealing)")
    }
}
