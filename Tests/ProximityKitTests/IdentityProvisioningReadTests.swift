// IdentityProvisioningReadTests.swift
// ProximityKitTests
//
// F-1 (P5 close-out, plan §11.3 / §23.4): `IdentityService.ensureProvisioned()` must never mint over
// an identity it could not READ. Before this fix the two identity-row reads went through the
// nil-collapsing `KeychainItem.load`, so a transient keychain error (`errSecInteractionNotAllowed`
// before first unlock, `errSecNotAvailable`, an I/O failure) looked exactly like a fresh device —
// and the mint that followed `KeychainItem.store`s every row delete-then-add, destroying the live
// identity and every trust relationship built on it.
//
// The keychain cannot be made to fail on demand in a test, so the rule lives in a PURE function
// (`classifyDeviceIdentityRows`) over `ProximityKeychainItem.ReadResult` values, tabled here; the one path a
// real keychain can drive (a present-but-unparseable row) is driven for real; and a source wall pins
// that the identity rows are never read nil-collapsing again.
//
// A partial copy (ProximityKit plan step A1.3, which copies into the package every cell of the Fernlet
// repository's tests that reads this module's sources before that repository stops holding them): of
// the Fernlet repository's FernletTests file of the same name, this holds only the source wall,
// `IdentityProvisioningReadTests.theIdentityRowsAreNeverReadNilCollapsing`, with the suite's name and
// its own unchanged, the identity's source read through `PackageRoot`. The decision table and the
// keychain-drivable path reach a keychain and stay in that repository's original, so what this header
// says of them is not held here.

import Foundation
import Testing

/// The fail-closed identity read's source wall: neither identity private-key row is read
/// nil-collapsing, and the unreadable arm throws.
@MainActor
@Suite(.serialized)
struct IdentityProvisioningReadTests {

    /// The signing private key's account field, as the identity's `accounts` names it.
    private static let signingRow = "signingPrivateKey"
    /// The key-agreement private key's account field, as the identity's `accounts` names it.
    private static let keyAgreementRow = "keyAgreementPrivateKey"

    // MARK: - The wall

    /// Neither identity private-key row is read nil-collapsing anywhere in the service, the
    /// distinguishing read is used for both rows and Case 3's legacy read, and the unreadable arm
    /// throws rather than returns. The rows are named by the identity's `accounts` (the namespace's
    /// `installation.keychain.identity`) since ProximityKit plan step A0.2.8, which deleted the
    /// `IdentityKeychainKey` cases the needle used to spell. Since step A0.2.11 the service reads
    /// through ProximityKit's copy, `ProximityKeychainItem`; each needle below spells
    /// FernletFoundation's `KeychainItem.…`, which the copy's `ProximityKeychainItem.…` contains, so
    /// the wall holds both: a nil-collapsing read through either is caught, and a distinguishing read
    /// through either counts.
    @Test func theIdentityRowsAreNeverReadNilCollapsing() throws {
        let source = try PackageRoot.source("Sources/ProximityKit/Identity/IdentityService.swift")
        // R2: bounded by the two rows.
        for row in [Self.signingRow, Self.keyAgreementRow] {
            #expect(!source.contains("KeychainItem.load(account: accounts.\(row)"),
                    "\(row) is read with the nil-collapsing load again — a transient error would mint over it")
        }
        let distinguishingReads = source.components(separatedBy: "KeychainItem.loadDistinguishingAbsence(").count - 1
        #expect(distinguishingReads >= 3, "signing, key-agreement and the legacy Case-3 read all distinguish absence")
        #expect(source.components(separatedBy: "throw IdentityError.keychainReadFailed(status)").count - 1 == 2,
                "both fail-closed reads throw, neither returns nil on an error")
        #expect(source.contains("case keychainReadFailed(OSStatus)"), "the error case is named")
    }
}
