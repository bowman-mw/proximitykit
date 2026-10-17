// MeshRoutedDrainAnswerTests.swift
// ProximityKitTests
//
// Network migration P5 item 6 (plan §11, §10.3, §22.1): the drain-answer frame — its pinned golden,
// its shape, its mint and its receive door.
//
// The vector was derived by extending item 5's independent Python re-implementation of the FORMAT
// header (`…/p5/item6/derive_golden_drain_answer.py`) and was proved honest the same way items 1–5's
// were: by first reproducing all NINE shipped vectors byte-for-byte before this one was minted.
//
// A failing golden is a WIRE decision — never re-pin it from Swift's output to go green.
//
// A partial copy (ProximityKit plan step A1, the split's second batch of copied suites: those that reach
// the keychain and open no store): of the Fernlet repository's FernletTests file of the same name, this
// holds only `MeshRoutedDrainAnswerSigningTests` and `MeshRoutedDrainAnswerVerifierTests`, with their
// names and tests unchanged, and the fixtures they read (`MeshRoutedDrainAnswerFixtures` and the two
// test-only rebuilders); its other suites stay there, so what this header says of them is not held here.

import Foundation
import Testing
@testable import ProximityKit

// MARK: - Fixtures

/// The golden drain answer: `fp004` telling `fp001` that its delta against `fp001`'s item-5 golden
/// advertisement is empty.
enum MeshRoutedDrainAnswerFixtures {

    static let meshID = MeshRoutedManifestFixtures.meshID
    static let base = MeshRoutedManifestFixtures.base
    static let opaqueSignature = MeshMembershipEventFixtures.opaqueSignature

    /// The peer whose inventory is being answered — item 5's advertiser.
    static let advertiserFingerprint = "fp001"

    /// The answering device — the custody signer of item 5's complete entry.
    static let senderFingerprint = "fp004"

    /// `base + 720` — item 5's golden `sentAt`, copied verbatim, because that is exactly what the
    /// binding check compares against.
    static let advertisedAt = base.addingTimeInterval(720)

    /// `base + 780` — the next free fixture offset.
    static let sentAt = base.addingTimeInterval(780)

    static func answer(quiescent: Bool = true) -> MeshRoutedDrainAnswer {
        MeshRoutedDrainAnswer(
            meshID: meshID, advertiserFingerprint: advertiserFingerprint,
            advertisedAt: advertisedAt, quiescent: quiescent
        )
    }

    static func payload(quiescent: Bool = true) -> MeshRoutedDrainAnswerPayload {
        MeshRoutedDrainAnswerPayload(
            answer: answer(quiescent: quiescent), senderFingerprint: senderFingerprint,
            sentAt: sentAt, signature: opaqueSignature
        )
    }

    static func hex(_ data: Data) -> String { MeshMembershipEventFixtures.hex(data) }
}

// MARK: - Test-only rebuilders

extension MeshRoutedDrainAnswer {
    /// Test-only: a copy with the named fields replaced, through the verbatim memberwise init.
    func replacing(
        meshID: UUID? = nil,
        advertiserFingerprint: String? = nil,
        advertisedAt: Date? = nil,
        quiescent: Bool? = nil
    ) -> MeshRoutedDrainAnswer {
        MeshRoutedDrainAnswer(
            meshID: meshID ?? self.meshID,
            advertiserFingerprint: advertiserFingerprint ?? self.advertiserFingerprint,
            advertisedAt: advertisedAt ?? self.advertisedAt,
            quiescent: quiescent ?? self.quiescent
        )
    }
}

extension MeshRoutedDrainAnswerPayload {
    /// Test-only: a copy with the named fields replaced, through the verbatim memberwise init.
    func replacing(
        answer: MeshRoutedDrainAnswer? = nil,
        senderFingerprint: String? = nil,
        sentAt: Date? = nil,
        signature: Data? = nil
    ) -> MeshRoutedDrainAnswerPayload {
        MeshRoutedDrainAnswerPayload(
            answer: answer ?? self.answer,
            senderFingerprint: senderFingerprint ?? self.senderFingerprint,
            sentAt: sentAt ?? self.sentAt,
            signature: signature ?? self.signature
        )
    }
}

// MARK: - Signing

/// The mint: one spelling of "this device", both named refusals, and the frame's unsealed carriage.
@MainActor
@Suite(.serialized)
struct MeshRoutedDrainAnswerSigningTests {

    private func mint(
        _ rig: MeshDeliveryRig, quiescent: Bool = true
    ) throws -> MeshRoutedDrainAnswerPayload {
        let sender = try #require(rig.identities[rig.fingerprints[0]])
        return try MeshRoutedDrainAnswerPayload.signed(
            meshID: rig.meshID, advertiser: rig.fingerprints[1],
            advertisedAt: MeshRoutedDrainAnswerFixtures.advertisedAt,
            quiescent: quiescent, sentAt: MeshRoutedDrainAnswerFixtures.sentAt, identity: sender
        )
    }

    @Test func aMintedAnswerVerifies() throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 3)
        let sender = try #require(rig.identities[rig.fingerprints[0]])
        let payload = try mint(rig)

        #expect(payload.senderFingerprint == sender.localFingerprint)
        #expect(payload.answer.advertiserFingerprint == rig.fingerprints[1])
        #expect(payload.answer.quiescent)
        #expect(payload.isWellFormed)
        #expect(payload.signature.count == MeshRoutedDrainAnswerFormat.signatureByteCount)
        #expect(IdentityService.verify(
            payload.signature, of: canonicalBytes(for: payload),
            by: sender.localSigningPublicKey,
            purpose: ProximityNamespace.packageTest.family.purposes.signature.meshRoutedDrainAnswerV1
        ))
        #expect(MeshRoutedDrainAnswerVerifier(meshID: rig.meshID, ledger: rig.ledger)
            .verify(payload) == nil)
    }

    /// The mint takes no `selfFingerprint`: the signer IS the sender, so the two cannot disagree.
    @Test func theSenderIsTheSignerAndNowhereElse() throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 3)
        let sender = try #require(rig.identities[rig.fingerprints[0]])
        #expect(try mint(rig).senderFingerprint == sender.localFingerprint)
    }

    @Test func theMintNamesItsTwoRefusals() throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 2)
        let sender = try #require(rig.identities[rig.fingerprints[0]])
        #expect(throws: MeshRoutedDrainAnswerMintError.advertiserIsSelf) {
            try MeshRoutedDrainAnswerPayload.signed(
                meshID: rig.meshID, advertiser: sender.localFingerprint,
                advertisedAt: MeshRoutedDrainAnswerFixtures.advertisedAt, quiescent: true,
                sentAt: MeshRoutedDrainAnswerFixtures.sentAt, identity: sender
            )
        }
        #expect(throws: MeshRoutedDrainAnswerMintError.malformedAdvertiser) {
            try MeshRoutedDrainAnswerPayload.signed(
                meshID: rig.meshID, advertiser: "",
                advertisedAt: MeshRoutedDrainAnswerFixtures.advertisedAt, quiescent: true,
                sentAt: MeshRoutedDrainAnswerFixtures.sentAt, identity: sender
            )
        }
    }

    /// A re-mint over the same inputs is byte-identical except the (hedged) signature.
    @Test func aReMintIsByteIdenticalExceptTheSignature() throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 2)
        let first = try mint(rig)
        let second = try mint(rig)
        #expect(canonicalBytes(for: first) == canonicalBytes(for: second))
        #expect(MeshRoutedDrainAnswerVerifier(meshID: rig.meshID, ledger: rig.ledger)
            .verify(second) == nil)
    }

    /// Signed and UNSEALED: the property that lets the bit cross a divergent pair.
    @Test func anAnswerIsAcceptedUnsealed() throws {
        let members = try MeshDeliveryFixtures.rig(memberCount: 2)
        let names = members.fingerprints
        let sender = try #require(members.identities[names[0]])
        let receiver = try #require(members.identities[names[1]])
        let payload = try JSONEncoder().encode(MeshRoutedDrainAnswerFixtures.payload())
        let base = MeshRoutedDrainAnswerFixtures.base

        let frame = try ProximityIdentityEnvelope.signed(
            identityService: sender, senderDisplayName: "answerer",
            recipientFingerprint: receiver.localFingerprint,
            payloadType: .meshRoutedDrainAnswer, payloadEncryption: .none,
            payloadSummary: PayloadSummary(title: "answer"), payload: payload, createdAt: base
        )
        let opened = try frame.verify(
            identityService: receiver, replayCache: ReplayCache(dateProvider: { base })
        )
        #expect(opened == payload)
    }
}

// MARK: - Verifying

/// The receive door: every rejection reachable and named, and D14 in both directions.
@MainActor
@Suite(.serialized)
struct MeshRoutedDrainAnswerVerifierTests {

    private func rigAndPayload() throws -> (rig: MeshDeliveryRig, payload: MeshRoutedDrainAnswerPayload) {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 3)
        let sender = try #require(rig.identities[rig.fingerprints[0]])
        let payload = try MeshRoutedDrainAnswerPayload.signed(
            meshID: rig.meshID, advertiser: rig.fingerprints[1],
            advertisedAt: MeshRoutedDrainAnswerFixtures.advertisedAt, quiescent: true,
            sentAt: MeshRoutedDrainAnswerFixtures.sentAt, identity: sender
        )
        return (rig, payload)
    }

    private func door(
        _ rig: MeshDeliveryRig, ledger: MeshMembershipLedger? = nil
    ) -> MeshRoutedDrainAnswerVerifier {
        MeshRoutedDrainAnswerVerifier(meshID: rig.meshID, ledger: ledger ?? rig.ledger)
    }

    @Test func everyRejectionIsReachable() throws {
        let (rig, payload) = try rigAndPayload()
        #expect(door(rig).verify(payload) == nil)

        let foreign = payload.replacing(answer: payload.answer.replacing(meshID: UUID()))
        #expect(door(rig).verify(foreign) == .foreignMesh)

        let malformed = payload.replacing(signature: Data(repeating: 0x01, count: 63))
        #expect(door(rig).verify(malformed) == .malformed)

        #expect(door(rig).verify(payload.replacing(senderFingerprint: "fp999")) == .senderNotAdmitted)

        let other = try #require(rig.identities[rig.fingerprints[1]])
        let forged = SignedAdmissionRecord(token: try MeshAdmissionToken.signed(
            meshID: rig.meshID,
            joinerFingerprint: payload.senderFingerprint,
            joinerSigningPublicKey: other.localSigningPublicKey,
            admitterIdentity: other,
            grantedAt: MeshMembershipEventFixtures.base
        ))
        let forgedLedger = MeshMembershipLedger(admissions: MeshMembershipRecordSet([forged]))
        #expect(door(rig, ledger: forgedLedger).verify(payload) == .senderKeyMismatch)

        let tampered = payload.replacing(sentAt: payload.sentAt.addingTimeInterval(-60))
        #expect(door(rig).verify(tampered) == .signatureInvalid)
    }

    /// Every signed field, flipped one at a time, lands on `.signatureInvalid` — which is the point
    /// of signing all of them.
    @Test func eachTamperedFieldFailsVerification() throws {
        let (rig, payload) = try rigAndPayload()
        let tampered = [
            payload.replacing(answer: payload.answer.replacing(
                advertiserFingerprint: rig.fingerprints[2]
            )),
            payload.replacing(answer: payload.answer.replacing(
                advertisedAt: payload.answer.advertisedAt.addingTimeInterval(60)
            )),
            payload.replacing(answer: payload.answer.replacing(quiescent: false)),
            payload.replacing(sentAt: payload.sentAt.addingTimeInterval(60))
        ]
        for broken in tampered {
            #expect(door(rig).verify(broken) == .signatureInvalid)
        }
    }

    /// D14, both directions: leaving is not a retraction — a departed answerer may still be holding
    /// custody inside the development grace — but a quorum removal is.
    @Test func aDepartedSenderVerifiesAndAQuorumRemovedOneDoesNot() throws {
        let (rig, payload) = try rigAndPayload()
        let sender = try #require(rig.identities[payload.senderFingerprint])
        let names = rig.fingerprints

        var records = MeshMembershipRecordVerifier(meshID: rig.meshID, ledger: rig.ledger)
        let departure = try SignedDepartureRecord.signed(
            meshID: rig.meshID, identity: sender, occurredAt: MeshMembershipEventFixtures.base
        )
        #expect(records.insert(departure) == nil)
        #expect(door(rig, ledger: records.ledger).verify(payload) == nil,
                "a departed answerer's bit must still verify — it may still hold custody")

        var removalRecords = MeshMembershipRecordVerifier(meshID: rig.meshID, ledger: rig.ledger)
        let tallier = try #require(rig.identities[names[1]])
        let removal = try SignedRemovalRecord.signed(
            meshID: rig.meshID,
            identity: tallier,
            memberFingerprint: payload.senderFingerprint,
            proposalID: MeshMembershipEventFixtures.proposalID,
            voterFingerprints: [names[1], names[2]],
            occurredAt: MeshMembershipEventFixtures.base
        )
        #expect(removalRecords.insert(removal) == nil)
        #expect(door(rig, ledger: removalRecords.ledger).verify(payload) == .senderRemoved)
    }

    /// `quiescent: false` is the ordinary answer while a transfer is in flight, not a rejection.
    @Test func aNonQuiescentAnswerIsNotARejection() throws {
        let rig = try MeshDeliveryFixtures.rig(memberCount: 2)
        let sender = try #require(rig.identities[rig.fingerprints[0]])
        let payload = try MeshRoutedDrainAnswerPayload.signed(
            meshID: rig.meshID, advertiser: rig.fingerprints[1],
            advertisedAt: MeshRoutedDrainAnswerFixtures.advertisedAt, quiescent: false,
            sentAt: MeshRoutedDrainAnswerFixtures.sentAt, identity: sender
        )
        #expect(door(rig).verify(payload) == nil)
        #expect(payload.answer.quiescent == false)
    }

    /// Every rejection carries frozen English, and none of them is a localized string.
    @Test func everyRejectionHasADiagnosticDescription() {
        var seen: Set<String> = []
        for rejection in MeshRoutedDrainAnswerRejection.allCases {
            #expect(rejection.diagnosticDescription.isEmpty == false, "\(rejection)")
            #expect(rejection.rawValue.allSatisfy { $0.isASCII }, "\(rejection)")
            seen.insert(rejection.diagnosticDescription)
        }
        #expect(seen.count == MeshRoutedDrainAnswerRejection.allCases.count)
        #expect(MeshRoutedDrainAnswerRejection.allCases.count == 6)
    }
}
