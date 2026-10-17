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
// From another of Fernlet's files (ProximityKit plan step A1's second batch of copied suites), each over
// the package's own stand-in for the Fernlet value it bound: the identity's `init(keychainService:)`,
// which Fernlet's FernletAppTestBindings.swift restores with Fernlet's sealed-backup escrow and this file
// with no provisioning participant; the routed registry the suites call `increment1`, and its ack-stage
// projection, which Fernlet's FernletSocialTestBindings.swift builds over FernletSocial's host rows and
// this file over `PackageTestHost`'s; and the typed envelope mint, which Fernlet's tests reach through FernletConnections'
// typed view of the payload token and this file restores over ProximityKit's own `MeshPayloadRole`.

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

/// The verifier initializer the suites were written against, restored over
/// `init(meshID:founderSigningPublicKey:ledger:family:)` with the package tests' family.
extension MeshMembershipRecordVerifier {

    /// A verifier keeping the package tests' family (its labels and record kinds) as its copy, otherwise
    /// exactly the retired initializer.
    ///
    /// - Parameters:
    ///   - meshID: The mesh every accepted record must name.
    ///   - founderSigningPublicKey: The key that may bootstrap an admission, if known.
    ///   - ledger: The records to start from.
    init(meshID: UUID, founderSigningPublicKey: Data? = nil, ledger: MeshMembershipLedger = .empty) {
        self.init(meshID: meshID, founderSigningPublicKey: founderSigningPublicKey, ledger: ledger,
                  family: .packageTest)
    }
}

/// The joiner's two ledger steps in the shapes the suites were written against, restored over their
/// `in family:` forms with the package tests' family.
extension MeshLedgerAdoption {

    /// `bootstrapVerifier(meshID:ownAdmission:in: .packageTest)`.
    static func bootstrapVerifier(meshID: UUID, ownAdmission: SignedAdmissionRecord) -> MeshLedgerAdoptionOutcome {
        bootstrapVerifier(meshID: meshID, ownAdmission: ownAdmission, in: .packageTest)
    }

    /// `adopt(offered:ownAdmission:meshID:in: .packageTest)`.
    static func adopt(
        offered: MeshMembershipLedger, ownAdmission: SignedAdmissionRecord, meshID: UUID
    ) -> MeshLedgerAdoptionOutcome {
        adopt(offered: offered, ownAdmission: ownAdmission, meshID: meshID, in: .packageTest)
    }
}

/// `canonicalBytes(for: proposal, in: .packageTest)`: a removal proposal under the package tests' labels.
func canonicalBytes(for proposal: SignedRemovalProposal) -> Data {
    canonicalBytes(for: proposal, in: .packageTest)
}

/// `canonicalBytes(for: vote, in: .packageTest)`: a removal vote under the package tests' labels.
func canonicalBytes(for vote: SignedRemovalVote) -> Data {
    canonicalBytes(for: vote, in: .packageTest)
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

/// `canonicalBytes(for: manifest, in: .packageTest)`: a routed manifest under the package tests' labels.
func canonicalBytes(for manifest: MeshRoutedManifest) -> Data {
    canonicalBytes(for: manifest, in: .packageTest)
}

/// `canonicalBytes(for: payload, in: .packageTest)`: a routed drain answer under the package tests'
/// labels.
func canonicalBytes(for payload: MeshRoutedDrainAnswerPayload) -> Data {
    canonicalBytes(for: payload, in: .packageTest)
}

/// `canonicalBytes(for: receipt, in: .packageTest)`: a custody receipt under the package tests' labels.
func canonicalBytes(for receipt: MeshCustodyReceipt) -> Data {
    canonicalBytes(for: receipt, in: .packageTest)
}

/// `canonicalBytes(for: receipt, in: .packageTest)`: a recipient receipt under the package tests' labels.
func canonicalBytes(for receipt: MeshRecipientReceipt) -> Data {
    canonicalBytes(for: receipt, in: .packageTest)
}

/// `canonicalBytes(for: payload, in: .packageTest)`: a routed inventory digest under the package tests'
/// labels.
func canonicalBytes(for payload: MeshRoutedInventoryPayload) -> Data {
    canonicalBytes(for: payload, in: .packageTest)
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

/// The manifest door's initializer the suites were written against, keeping the package tests' labels
/// as its copy.
extension MeshRoutedManifestVerifier {

    /// `init(meshID:hardDeadline:ledger:acceptedTypeTokens:purposes: .packageTest)`.
    init(meshID: UUID, hardDeadline: Date, ledger: MeshMembershipLedger, acceptedTypeTokens: Set<String>) {
        self.init(meshID: meshID, hardDeadline: hardDeadline, ledger: ledger,
                  acceptedTypeTokens: acceptedTypeTokens, purposes: .packageTest)
    }
}

/// The chunk door's initializer the suites were written against, keeping the package tests' labels as
/// its copy.
extension MeshChunkVerifier {

    /// `init(meshID:hardDeadline:ledger:manifest:purposes: .packageTest)`.
    init(meshID: UUID, hardDeadline: Date, ledger: MeshMembershipLedger, manifest: MeshRoutedManifest?) {
        self.init(meshID: meshID, hardDeadline: hardDeadline, ledger: ledger, manifest: manifest,
                  purposes: .packageTest)
    }
}

/// The custody-receipt door's initializer the suites were written against, keeping the package tests'
/// labels as its copy.
extension MeshCustodyReceiptVerifier {

    /// `init(meshID:hardDeadline:ledger:manifest:purposes: .packageTest)`.
    init(meshID: UUID, hardDeadline: Date, ledger: MeshMembershipLedger, manifest: MeshRoutedManifest?) {
        self.init(meshID: meshID, hardDeadline: hardDeadline, ledger: ledger, manifest: manifest,
                  purposes: .packageTest)
    }
}

/// The recipient-receipt door's initializer the suites were written against, keeping the package tests'
/// labels as its copy.
extension MeshRecipientReceiptVerifier {

    /// `init(meshID:hardDeadline:ledger:manifest:purposes: .packageTest)`.
    init(meshID: UUID, hardDeadline: Date, ledger: MeshMembershipLedger, manifest: MeshRoutedManifest?) {
        self.init(meshID: meshID, hardDeadline: hardDeadline, ledger: ledger, manifest: manifest,
                  purposes: .packageTest)
    }
}

/// The drain-answer door's initializer the suites were written against, keeping the package tests'
/// labels as its copy.
extension MeshRoutedDrainAnswerVerifier {

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

/// A custody receipt's dedup id as the property the suites were written against, over the package tests'
/// labels.
extension MeshCustodyReceipt {

    /// `receiptID(in: .packageTest)`.
    var receiptID: UUID { receiptID(in: .packageTest) }
}

/// A recipient receipt's dedup id as the property the suites were written against, over the package
/// tests' labels.
extension MeshRecipientReceipt {

    /// `receiptID(in: .packageTest)`.
    var receiptID: UUID { receiptID(in: .packageTest) }
}

/// The streaming content hasher's initializer the suites were written against, over the package tests'
/// labels.
extension MeshRoutedContentHasher {

    /// `MeshRoutedContentHasher(purposes: .packageTest)`.
    init() {
        self.init(purposes: .packageTest)
    }
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

/// The content-key wrap's two doors in the shapes the suites were written against, over the package
/// tests' labels.
extension MeshRoutedContentKeyWrapper {

    /// `wrap(contentKey:recipientFingerprint:recipientKeyAgreementPublicKey:binding:in: .packageTest)`.
    static func wrap(
        contentKey: Data, recipientFingerprint: String, recipientKeyAgreementPublicKey: Data,
        binding: MeshRoutedWrapBinding
    ) throws -> MeshRecipientKeyWrap {
        try wrap(contentKey: contentKey, recipientFingerprint: recipientFingerprint,
                 recipientKeyAgreementPublicKey: recipientKeyAgreementPublicKey, binding: binding, in: .packageTest)
    }

    /// `unwrap(_:binding:localFingerprint:localKeyAgreementPublicKey:staticAgreement:in: .packageTest)`.
    static func unwrap(
        _ wrap: MeshRecipientKeyWrap, binding: MeshRoutedWrapBinding, localFingerprint: String,
        localKeyAgreementPublicKey: Data, staticAgreement: (Data) throws -> SharedSecret
    ) throws -> Data {
        try unwrap(wrap, binding: binding, localFingerprint: localFingerprint,
                   localKeyAgreementPublicKey: localKeyAgreementPublicKey, staticAgreement: staticAgreement,
                   in: .packageTest)
    }
}

/// The static key agreement in the spelling the suites were written against: a pure rename, which
/// takes no namespace and so passes nothing at all. It inherits the class's main-actor isolation, as
/// the method it restores has.
extension IdentityService {

    /// `staticKeyAgreement(withEphemeralPublicKey:)`.
    func heartDropStaticAgreement(withEphemeralPublicKey key: Data) throws -> SharedSecret {
        try staticKeyAgreement(withEphemeralPublicKey: key)
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

// MARK: - Record kinds and routed types
//
// ProximityKit spells no routed type: the registry builds its rows from the ones a host hands it, and
// the manifest mint takes its registry with no default. The routed-type constants, the registry the
// suites call `increment1` and the mint's old shape come back here over `.packageTest`'s
// `family.vocabulary.routedTypes`, read off the value, and over the package host's rows
// (`PackageTestHost.routedTypeEntries(_:)`), the shapes and caps Fernlet's rows take, as Fernlet's
// tests restore them over Fernlet's host rows.

/// The routed-type tokens the suites were written against, each read off `.packageTest`'s
/// `family.vocabulary.routedTypes`, never respelled here.
enum MeshRoutedTypeToken {
    /// `.packageTest`'s routed photo type.
    static let photo = ProximityNamespace.packageTest.family.vocabulary.routedTypes.photo
    /// `.packageTest`'s routed temporary-message type.
    static let tempMessage = ProximityNamespace.packageTest.family.vocabulary.routedTypes.tempMessage
    /// `.packageTest`'s routed heart type, whose manifest's item id is the gift id.
    static let heart = ProximityNamespace.packageTest.family.vocabulary.routedTypes.heart
    /// `.packageTest`'s reserved control type, registered for nothing.
    static let control = ProximityNamespace.packageTest.family.vocabulary.routedTypes.control
}

/// The shipping registry in the shapes the suites were written against, over the package host's rows
/// (`PackageTestHost.routedTypeEntries(_:)`), as Fernlet's tests restore them over Fernlet's host rows
/// (FernletSocial's `FernletRoutedTypes.entries(_:)`, in `FernletSocialTestBindings.swift`).
extension MeshRoutedTypeRegistry {

    /// `init(entries:)` over the package host's rows read off `routedTypes`.
    static func increment1(_ routedTypes: ProximityNamespace.RoutedTypes) -> MeshRoutedTypeRegistry {
        MeshRoutedTypeRegistry(entries: PackageTestHost.routedTypeEntries(routedTypes))
    }

    /// ``increment1(_:)`` over `.packageTest`'s `family.vocabulary.routedTypes`.
    static var increment1: MeshRoutedTypeRegistry {
        increment1(ProximityNamespace.packageTest.family.vocabulary.routedTypes)
    }
}

/// The ack-stage table in the shape the suites were written against: the `finalAck` column of the
/// package host's registry (``MeshRoutedTypeRegistry/increment1``), keyed by `.packageTest`'s tokens, as
/// Fernlet's tests restore it over FernletSocial's rows (`FernletSocialTestBindings.swift`).
extension MeshRoutedAckStageTable {

    /// The table the retired `increment1` value held: ``MeshRoutedTypeRegistry/increment1``'s ack stages.
    static var increment1: MeshRoutedAckStageTable {
        MeshRoutedTypeRegistry.increment1.ackStages
    }
}

/// The manifest mint in the shape the suites were written against, with the registry its retired
/// `types:` default named. It inherits the mint's main-actor isolation.
extension MeshRoutedManifest {

    /// `signed(...types:)` with `.packageTest`'s registry, ``MeshRoutedTypeRegistry/increment1(_:)`` over
    /// its routed types.
    @MainActor
    static func signed(
        meshID: UUID, target: MeshDeliveryTarget, typeToken: String, contentHash: Data, size: UInt64,
        createdAt: Date, hardDeadline: Date, contentKey: Data, recipientKeys: [String: Data],
        identity: IdentityService
    ) throws -> MeshRoutedManifest {
        try signed(
            meshID: meshID, target: target, typeToken: typeToken, contentHash: contentHash, size: size,
            createdAt: createdAt, hardDeadline: hardDeadline, contentKey: contentKey,
            recipientKeys: recipientKeys, identity: identity,
            types: MeshRoutedTypeRegistry.increment1(ProximityNamespace.packageTest.family.vocabulary.routedTypes))
    }
}

/// The typed envelope mint the suites were written against: Fernlet's tests sign through Fernlet's
/// typed view of the payload token (FernletConnections' `signed(...payloadType:...)` over its
/// `PayloadType`), which this package cannot name. The mesh frames those suites sign are ProximityKit's
/// own roles, so the shape comes back over ``MeshPayloadRole``, each role's token read off `.packageTest`'s
/// mesh messages, never respelled here. It inherits the raw factory's main-actor signing.
extension ProximityIdentityEnvelope {

    /// `signed(...payloadTypeToken:...)` with `payloadType`'s token in `.packageTest`'s mesh messages.
    @MainActor
    static func signed(
        identityService: IdentityService, envelopeID: UUID = UUID(), senderDisplayName: String,
        recipientFingerprint: String? = nil, payloadType: MeshPayloadRole,
        payloadEncryption: PayloadEncryption = .none, payloadSummary: PayloadSummary, payload: Data,
        createdAt: Date = Date(), expiresAt: Date? = nil
    ) throws -> ProximityIdentityEnvelope {
        try signed(
            identityService: identityService, envelopeID: envelopeID, senderDisplayName: senderDisplayName,
            recipientFingerprint: recipientFingerprint,
            payloadTypeToken: payloadType.token(in: ProximityNamespace.packageTest.family.vocabulary.mesh),
            payloadEncryption: payloadEncryption, payloadSummary: payloadSummary, payload: payload,
            createdAt: createdAt, expiresAt: expiresAt)
    }
}

// MARK: - The installation's rows
//
// The mesh stores' seal-key accounts are the namespace's installation rows; each seal key's open read
// comes back in the shape the suites were written against with `.packageTest`'s account, read off the
// value, never respelled here.

/// The mesh-session seal key's open read in the shape the suites were written against, with
/// `.packageTest`'s mesh-session seal-key account.
extension MeshSessionSealKey {

    /// `forOpen(service:account:)` with `.packageTest`'s `installation.keychain.meshSessionSealKey.account`.
    static func forOpen(service: String) -> MeshSessionSealKeyOutcome {
        forOpen(service: service, account: ProximityNamespace.packageTest.installation.keychain.meshSessionSealKey.account)
    }
}

/// The routed seal key's open read in the shape the suites were written against, with `.packageTest`'s
/// routed seal-key account.
extension MeshRoutedSealKey {

    /// `forOpen(service:account:)` with `.packageTest`'s `installation.keychain.meshRoutedSealKey.account`.
    static func forOpen(service: String) -> MeshRoutedSealKeyOutcome {
        forOpen(service: service, account: ProximityNamespace.packageTest.installation.keychain.meshRoutedSealKey.account)
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
