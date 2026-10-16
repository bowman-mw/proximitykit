// PackageTestBindings.swift
// ProximityKitTests
//
// ProximityKit plan step A1.1: the call shapes ProximityKit's package suites were written against,
// restored over the package tests' namespace, `.packageTest` (TestSupport/PackageTestNamespace.swift).
// ProximityKit offers no namespace default: every API that used to spell an app's bytes for itself takes
// the host's `ProximityNamespace`, or a value read off it. The suites that moved here from FernletTests
// were written against the old shapes, which FernletTests restores over Fernlet's namespace in
// Tests/FernletTests/ProximityNamespaceTestBindings.swift. Each shape here is that file's binding, its
// code copied verbatim with `.fernlet` replaced by `.packageTest` and its doc comment saying what it
// binds to here, but for those named below, which restore a shape from another of Fernlet's files.
//
// A REPLACEMENT, NOT A TWIN. A twin is one file both test targets compile alike; this file and Fernlet's
// cannot be one, because this half binds to the package tests' namespace and Fernlet's to Fernlet's,
// which the package cannot name. Until Fernlet's plan step A1.3 deleted its in-tree copy of this
// target, CIGateSelectorBoundaryTests.everyTwinMatchesItsOriginal() held the pair as a replacement:
// every declaration here equalled one declaration of Fernlet's file once `.packageTest` read `.fernlet`,
// so a shape could not drift from the one the suites were written against. Since then review holds it.
// THE RULE is Fernlet's file's: a binding restores a call SHAPE, never a value, passing `.packageTest`,
// the one namespace the package's suites compute under. Only the shapes a package suite fails to compile
// without are here.
//
// From another of Fernlet's files (ProximityKit plan step A1's second batch of copied suites), over the
// package's own stand-in for the Fernlet value it bound: the identity's `init(keychainService:)`, which
// Fernlet's FernletAppTestBindings.swift restores with Fernlet's sealed-backup escrow and this file with
// no provisioning participant.

import CryptoKit
import Foundation
@testable import ProximityKit

// MARK: - IdentityService

/// The identity initializer the suites were written against, restored over
/// `init(namespace:keychainService:provisioningParticipant:)` with the package tests' namespace and no
/// provisioning participant. Fernlet's tests restore the same shape with Fernlet's namespace and Fernlet's
/// sealed-backup escrow (`FernletAppTestBindings.swift`), which is the app's and which this package cannot
/// name; no copied suite reads the participant, so the package's identity is ProximityKit's alone, as the
/// one `PackageTestHost.makeProximityIdentity()` builds.
extension IdentityService {

    /// `IdentityService(namespace: .packageTest, keychainService:)`: an identity on a keychain service of
    /// the test's own with no participant, the identity the retired `init(keychainService:)` built. Reads
    /// and writes nothing: provisioning it reaches the keychain, so its caller reads
    /// `PackageTestEnvironment.keychain` first.
    ///
    /// - Parameter keychainService: The test's own service, usually a throwaway one.
    convenience init(keychainService: String) {
        self.init(namespace: .packageTest, keychainService: keychainService)
    }
}

// MARK: - Signed transcripts I: verifiers and helpers

/// The digest initializer the suites were written against, restored over `init(meshID:ledger:family:)`
/// with the package tests' family (its labels and record kinds).
extension MeshInventoryDigest {

    /// The digest of `ledger`, its records hashed under the package tests' labels over their record kinds.
    init(meshID: UUID, ledger: MeshMembershipLedger) {
        self.init(meshID: meshID, ledger: ledger, family: .packageTest)
    }
}

// MARK: - Signed transcripts II: the canonical bytes

/// `canonicalBytes(for: transcript, in: .packageTest)`: a channel introduction under the package tests'
/// labels.
func canonicalBytes(for transcript: MeshChannelIntroductionTranscript) -> Data {
    canonicalBytes(for: transcript, in: .packageTest)
}

/// `canonicalBytes(for: chunk, in: .packageTest)`: a routed chunk under the package tests' labels.
func canonicalBytes(for chunk: MeshChunk) -> Data {
    canonicalBytes(for: chunk, in: .packageTest)
}

/// `canonicalBytes(for: receipt, in: .packageTest)`: a recipient receipt under the package tests' labels.
func canonicalBytes(for receipt: MeshRecipientReceipt) -> Data {
    canonicalBytes(for: receipt, in: .packageTest)
}

// MARK: - Signed transcripts II: the verifiers and the exchange

/// The routed-inventory door's initializer the suites were written against, keeping the package tests'
/// labels as its copy.
extension MeshRoutedInventoryVerifier {

    /// `init(meshID:ledger:purposes: .packageTest)`.
    init(meshID: UUID, ledger: MeshMembershipLedger) {
        self.init(meshID: meshID, ledger: ledger, purposes: .packageTest)
    }
}

/// The channel-introduction exchange's initializer the suites were written against, keeping the
/// package tests' labels as its copy.
extension MeshChannelIntroductionExchange {

    /// `init(role:localHello:purposes: .packageTest)`.
    init(role: MeshChannelRole, localHello: MeshChannelHello) {
        self.init(role: role, localHello: localHello, purposes: .packageTest)
    }
}

// MARK: - Hashes, AEAD, salts, epoch: the routed digests and ids

/// The routed digests in the shapes the suites were written against, over the package tests' labels.
extension MeshRoutedContentDigest {

    /// `contentHash(of: blob, in: .packageTest)`.
    static func contentHash(of blob: Data) -> Data {
        contentHash(of: blob, in: .packageTest)
    }

    /// `chunkHash(of: payload, in: .packageTest)`.
    static func chunkHash(of payload: Data) -> Data {
        chunkHash(of: payload, in: .packageTest)
    }

    /// `chunkID(itemID:chunkIndex:in: .packageTest)`.
    static func chunkID(itemID: UUID, chunkIndex: UInt32) -> UUID {
        chunkID(itemID: itemID, chunkIndex: chunkIndex, in: .packageTest)
    }
}

/// A chunk's replay-window id as the property the suites were written against, over the package tests'
/// labels.
extension MeshChunk {

    /// `chunkID(in: .packageTest)`.
    var chunkID: UUID { chunkID(in: .packageTest) }
}

/// The in-memory reassembler's two verbs in the shapes the suites were written against, over the
/// package tests' labels.
extension MeshChunkAssembly {

    /// `admit(chunk, in: .packageTest)`.
    mutating func admit(_ chunk: MeshChunk) -> MeshChunkAdmission {
        admit(chunk, in: .packageTest)
    }

    /// `completion(against: manifest, in: .packageTest)`.
    func completion(against manifest: MeshRoutedManifest) -> MeshChunkCompletion {
        completion(against: manifest, in: .packageTest)
    }
}

// MARK: - Hashes, AEAD, salts, epoch: the epoch

/// The epoch's two minting doors in the shapes the suites were written against, over the package
/// tests' labels: every epoch id is derived under `.packageTest`'s epoch domain.
extension MeshEpochRef {

    /// `minted(counter:coordinatorFingerprint:meshID:in: .packageTest)`.
    static func minted(counter: UInt32, coordinatorFingerprint: String, meshID: UUID) -> MeshEpochRef? {
        minted(counter: counter, coordinatorFingerprint: coordinatorFingerprint, meshID: meshID, in: .packageTest)
    }

    /// `successor(coordinatorFingerprint:meshID:in: .packageTest)`.
    func successor(coordinatorFingerprint: String, meshID: UUID) -> MeshEpochRef? {
        successor(coordinatorFingerprint: coordinatorFingerprint, meshID: meshID, in: .packageTest)
    }
}

/// The rotation plan in the shape the suites were written against, over the package tests' labels.
extension MeshRotationPolicy {

    /// `plan(head:coordinatorFingerprint:meshID:presentedRoster:in: .packageTest)`.
    static func plan(
        head: MeshEpochRef?, coordinatorFingerprint: String, meshID: UUID, presentedRoster: [String]
    ) -> MeshRotationPlan {
        plan(head: head, coordinatorFingerprint: coordinatorFingerprint, meshID: meshID,
             presentedRoster: presentedRoster, in: .packageTest)
    }
}

// MARK: - The radios

/// The friend mesh radio's argument-less initializer, restored over `init(namespace:)` with the
/// package tests' namespace. The radio is internal, so this file imports ProximityKit `@testable`; it
/// inherits the class's main-actor isolation, as the initializer it replaces had.
extension NetworkMeshSession {

    /// `NetworkMeshSession(namespace: .packageTest)`: the friend mesh's radio on the package tests'
    /// wire, the radio the retired `init()` built on Fernlet's.
    convenience init() {
        self.init(namespace: .packageTest)
    }
}

// MARK: - Presentation strings

/// The certificate path's two doors in the shapes the suites were written against, with the package
/// tests' common name, `.packageTest`'s `family.radios.tlsCommonName`, read off the value, never
/// respelled here.
extension EphemeralMeshTLSIdentity {

    /// `mint(commonName:now:)` with `.packageTest`'s `family.radios.tlsCommonName`.
    static func mint(now: Date = Date()) throws -> Minted {
        try mint(commonName: ProximityNamespace.packageTest.family.radios.tlsCommonName, now: now)
    }

    /// `selfSignedCertificateDER(for:commonName:notBefore:notAfter:serial:)` with `.packageTest`'s
    /// `family.radios.tlsCommonName`.
    static func selfSignedCertificateDER(
        for privateKey: P256.Signing.PrivateKey, notBefore: Date, notAfter: Date, serial: [UInt8]
    ) throws -> Data {
        try selfSignedCertificateDER(
            for: privateKey, commonName: ProximityNamespace.packageTest.family.radios.tlsCommonName,
            notBefore: notBefore, notAfter: notAfter, serial: serial)
    }
}

/// The presence posture's minting, rotation and naming doors in the shapes the suites were written
/// against, with `.packageTest`'s presence prefix and, where a door mints the certificate itself, its
/// common name.
extension PresenceEpochPosture {

    /// `minted(at:instanceNamePrefix:commonName:)` with `.packageTest`'s values.
    static func minted(at now: Date) throws -> PresenceEpochPosture {
        let radios = ProximityNamespace.packageTest.family.radios
        return try minted(
            at: now, instanceNamePrefix: radios.presenceInstanceNamePrefix, commonName: radios.tlsCommonName)
    }

    /// `minted(at:instanceNamePrefix:entropy:mintIdentity:)` with `.packageTest`'s presence prefix.
    static func minted(
        at now: Date, entropy: (Int) -> [UInt8], mintIdentity: (Date) throws -> EphemeralMeshTLSIdentity.Minted
    ) throws -> PresenceEpochPosture {
        try minted(
            at: now, instanceNamePrefix: ProximityNamespace.packageTest.family.radios.presenceInstanceNamePrefix,
            entropy: entropy, mintIdentity: mintIdentity)
    }

    /// `rotated(at:instanceNamePrefix:commonName:)` with `.packageTest`'s values.
    func rotated(at now: Date) throws -> PresenceEpochPosture {
        let radios = ProximityNamespace.packageTest.family.radios
        return try rotated(
            at: now, instanceNamePrefix: radios.presenceInstanceNamePrefix, commonName: radios.tlsCommonName)
    }

    /// `rotated(at:instanceNamePrefix:entropy:mintIdentity:)` with `.packageTest`'s presence prefix.
    func rotated(
        at now: Date, entropy: (Int) -> [UInt8], mintIdentity: (Date) throws -> EphemeralMeshTLSIdentity.Minted
    ) throws -> PresenceEpochPosture {
        try rotated(
            at: now, instanceNamePrefix: ProximityNamespace.packageTest.family.radios.presenceInstanceNamePrefix,
            entropy: entropy, mintIdentity: mintIdentity)
    }

    /// `instanceName(prefix:entropy:)` with `.packageTest`'s presence prefix.
    static func instanceName(entropy: (Int) -> [UInt8]) throws -> String {
        try instanceName(prefix: ProximityNamespace.packageTest.family.radios.presenceInstanceNamePrefix, entropy: entropy)
    }
}
