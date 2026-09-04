// MeshRoutedDrainAnswer.swift
// ProximityKit/Mesh
//
// Network migration P5 item 6 (plan §11, §10.3, §22.1): the **quiescence bit** — one signed frame
// that says "against the inventory you just advertised, I have nothing left to ask you for and
// nothing left to offer you".
//
// **This is not the routed inventory digest, and the stems are deliberately different.** D-5.1 froze
// the `MeshRoutedInventory…` stem for *what a disk holds*; this frame states the result of a
// **comparison** between two such digests, which is why it carries no entry list, no member table
// and no item id — only which advertisement it answers and the one Bool
// `MeshRoutedInventoryDelta.isQuiescent` produced. Its token
// `fernlet.mesh.routed-drain-answer.v1` diverges from `fernlet.mesh.routed-inventory-digest.v1` at
// `d` vs `i` immediately after `routed-`, so neither prefixes the other.
//
// **Why it is signed** (D-6.10, and the reason an unsigned bit is not an option): item 7's merge
// window closes on quiescence, so a forged `quiescent: true` closes a window that should still be
// open — the fail-open direction. On top of the signature the receiver requires the two bindings
// this frame exists to carry: ``MeshRoutedDrainAnswer/advertiserFingerprint`` must be the receiver
// itself, and ``MeshRoutedDrainAnswer/advertisedAt`` must be an instant it really advertised. Both
// halves of that equality are the **minted payload's own floored `sentAt`**, never a `now` — see
// the note on ``MeshRoutedDrainAnswer/advertisedAt``.
//
// Signed and **unsealed**, like every other routed frame: that is what lets it cross a divergent
// pair on a reconciling tunnel, which is exactly the partition the drain exists to heal.

import FernletCrypto
import Foundation

// MARK: - MeshRoutedDrainAnswerFormat

/// Fixed bounds of the drain-answer frame (network migration P5 item 6, plan §11).
///
/// Both constants are **aliases of the routed family's**, never fresh literals: a second spelling of
/// "how long may a fingerprint be" is how two bounds drift apart.
nonisolated enum MeshRoutedDrainAnswerFormat {
    /// Cap on a fingerprint's UTF-8 length, shared with the routed family.
    static let maxFingerprintLength = MeshRoutedManifestFormat.maxFingerprintLength

    /// Ed25519 signature length, shared with the routed family.
    static let signatureByteCount = MeshRoutedManifestFormat.signatureByteCount
}

// MARK: - MeshRoutedDrainAnswer

/// One device's answer to one routed-inventory advertisement: *which* advertisement, and whether the
/// answering device's own delta against it is empty.
///
/// The three identifying fields are all binding material and none is decorative:
/// - ``meshID`` refuses a foreign mesh outright rather than folding it (D-5.16's rule, restated for
///   the answer);
/// - ``advertiserFingerprint`` says **whose** inventory this answers, so a bit meant for someone
///   else cannot be replayed at this device;
/// - ``advertisedAt`` says **which** advertisement, so a stale `true` cannot close a window opened
///   by a later one.
nonisolated struct MeshRoutedDrainAnswer: Codable, Equatable, Sendable {
    /// The session both sides are in. A different mesh is refused, never merged.
    let meshID: UUID

    /// The device whose routed inventory this answers — the **receiver** of the frame. A frame whose
    /// value is not the receiver's own fingerprint is dropped, never recorded (D-6.10).
    let advertiserFingerprint: String

    /// The advertisement's own signed instant, copied **verbatim** from
    /// `MeshRoutedInventoryPayload.sentAt`.
    ///
    /// - Important: this is never the answering device's `now`, and never the advertiser's `now`
    ///   either. `MeshRoutedInventoryPayload` floors its `sentAt` to whole seconds, while the
    ///   manager's drain entry points default `now` to a sub-second `Date()`. Recording a raw `now`
    ///   at either end makes the exact `Date` equality the receiver checks **never** hold, so every
    ///   answer is dropped as unbound and the quiescence bit is silently disabled — no error, no
    ///   log the reader would connect to the cause. Both ends therefore read the minted payload.
    let advertisedAt: Date

    /// The answering device's own `MeshRoutedInventoryDelta.isQuiescent` against that inventory.
    ///
    /// Strictly one-sided by construction — it is half of
    /// ``MeshRoutedInventoryDelta/converged(local:peerReportsQuiescent:)``, never a claim about the
    /// pair.
    let quiescent: Bool

    /// Builds an answer verbatim, flooring the advertisement instant so the stored value is
    /// byte-identical to what the canonical writer emits. The floor is idempotent: the value copied
    /// off the wire is already floored.
    init(meshID: UUID, advertiserFingerprint: String, advertisedAt: Date, quiescent: Bool) {
        self.meshID = meshID
        self.advertiserFingerprint = advertiserFingerprint
        self.advertisedAt = MeshRoutedManifest.floored(advertisedAt)
        self.quiescent = quiescent
    }

    /// Decodes through the memberwise initializer, applying the same floor.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            meshID: try container.decode(UUID.self, forKey: .meshID),
            advertiserFingerprint: try container.decode(String.self, forKey: .advertiserFingerprint),
            advertisedAt: try container.decode(Date.self, forKey: .advertisedAt),
            quiescent: try container.decode(Bool.self, forKey: .quiescent)
        )
    }
}

// MARK: - MeshRoutedDrainAnswerPayload

/// The `fernlet.mesh.routed-drain-answer.v1` frame: the answer, its signer, and the signature.
///
/// **Not in `FernletIdentityEnvelope.sealingRequiredTypes`, on purpose:** signed-and-unsealed is
/// what lets a frame cross a **divergent** pair, the property that already carries the membership
/// digest, the epoch heads and item 5's routed digest over a reconciling tunnel. A sealed answer
/// would be dropped in exactly the partition the drain exists to heal. Additive: older builds park
/// the token and still verify the envelope.
nonisolated struct MeshRoutedDrainAnswerPayload: Codable, Equatable, Sendable {
    /// What was answered.
    let answer: MeshRoutedDrainAnswer

    /// The **answering device** — resolved against the admission ledger by this fingerprint, never
    /// by the envelope's sender.
    let senderFingerprint: String

    /// When it was signed, floored to whole seconds — **bound into the signature**, so a stale
    /// answer cannot be replayed as fresh.
    let sentAt: Date

    /// The answerer's Ed25519 signature over `canonicalBytes(for:)` under
    /// `FernletCryptoPurpose.Signature.meshRoutedDrainAnswerV1`. Excluded from those bytes.
    let signature: Data

    /// Builds a payload from already-signed parts, flooring `sentAt` so the stored value is
    /// byte-identical to what the canonical writer emits.
    init(answer: MeshRoutedDrainAnswer, senderFingerprint: String, sentAt: Date, signature: Data) {
        self.answer = answer
        self.senderFingerprint = senderFingerprint
        self.sentAt = MeshRoutedManifest.floored(sentAt)
        self.signature = signature
    }

    /// Decodes through the memberwise initializer, applying the same floor.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            answer: try container.decode(MeshRoutedDrainAnswer.self, forKey: .answer),
            senderFingerprint: try container.decode(String.self, forKey: .senderFingerprint),
            sentAt: try container.decode(Date.self, forKey: .sentAt),
            signature: try container.decode(Data.self, forKey: .signature)
        )
    }

    /// The four untrusted scalars no other door clamps: both fingerprints, both instants, and the
    /// signature's width.
    ///
    /// Re-applied at the verifier **before** any ledger lookup or signature check, so a malformed
    /// frame costs neither. Refused, never repaired.
    var isWellFormed: Bool {
        signature.count == MeshRoutedDrainAnswerFormat.signatureByteCount
            && isWellFormedFingerprint(senderFingerprint)
            && isWellFormedFingerprint(answer.advertiserFingerprint)
            && sentAt.timeIntervalSince1970.isFinite
            && answer.advertisedAt.timeIntervalSince1970.isFinite
    }

    /// Whether one fingerprint is non-empty and inside the family's cap.
    private func isWellFormedFingerprint(_ fingerprint: String) -> Bool {
        !fingerprint.isEmpty
            && fingerprint.utf8.count <= MeshRoutedDrainAnswerFormat.maxFingerprintLength
    }
}

// MARK: - MeshRoutedDrainAnswerMintError

/// Why ``MeshRoutedDrainAnswerPayload/signed(meshID:advertiser:advertisedAt:quiescent:sentAt:identity:)``
/// refused to mint.
///
/// Thrown, never returned as nil and never silent — the whole P5 family answers that way so a
/// caller's "logs it and sends nothing" has something to log.
///
/// Not `LocalizedError` — ``diagnosticDescription`` is frozen English for the audit log and is never
/// shown as user copy.
nonisolated enum MeshRoutedDrainAnswerMintError: Error, Equatable, Sendable {
    /// The advertiser this answer names is this device itself. An answer is always *about somebody
    /// else's* advertisement; a self-addressed one could only ever be a loop.
    case advertiserIsSelf

    /// The advertiser's fingerprint is empty or over the family's cap — a frame the receiver's own
    /// shape check would refuse, so it is refused here rather than put on the wire.
    case malformedAdvertiser

    /// Frozen English for the diagnostic surface. Never shown as user copy.
    var diagnosticDescription: String {
        switch self {
        case .advertiserIsSelf:
            return "A drain answer cannot answer this device's own inventory advertisement."
        case .malformedAdvertiser:
            return "The drain answer's advertiser fingerprint is empty or over its cap."
        }
    }
}

// MARK: - Signing factory

extension MeshRoutedDrainAnswerPayload {

    /// Signs one drain answer.
    ///
    /// There is deliberately **no `selfFingerprint` parameter** — this device has exactly one
    /// spelling here, `identity.localFingerprint`, and it is the same value that signs the frame
    /// (D-5.18's rule, which cost item 5 a review round). There is also no `sentAt: Date = Date()`
    /// default: every P5 instant is injected.
    ///
    /// - Parameters:
    ///   - meshID: The session both sides are in.
    ///   - advertiser: The peer whose inventory this answers.
    ///   - advertisedAt: That advertisement's own **minted, floored** `sentAt`, copied verbatim.
    ///   - quiescent: This device's `MeshRoutedInventoryDelta.isQuiescent` against it.
    ///   - sentAt: The injected instant, floored into the signed bytes.
    ///   - identity: The answering device, and the sole source of "this device".
    /// - Returns: The signed frame.
    /// - Throws: ``MeshRoutedDrainAnswerMintError`` or the identity's signing error. Never a trap.
    @MainActor
    static func signed(
        meshID: UUID,
        advertiser: String,
        advertisedAt: Date,
        quiescent: Bool,
        sentAt: Date,
        identity: IdentityService
    ) throws -> MeshRoutedDrainAnswerPayload {
        let sender = identity.localFingerprint
        guard advertiser != sender else { throw MeshRoutedDrainAnswerMintError.advertiserIsSelf }
        guard !advertiser.isEmpty,
              advertiser.utf8.count <= MeshRoutedDrainAnswerFormat.maxFingerprintLength else {
            throw MeshRoutedDrainAnswerMintError.malformedAdvertiser
        }
        let answer = MeshRoutedDrainAnswer(
            meshID: meshID, advertiserFingerprint: advertiser,
            advertisedAt: advertisedAt, quiescent: quiescent
        )
        let unsigned = MeshRoutedDrainAnswerPayload(
            answer: answer, senderFingerprint: sender, sentAt: sentAt, signature: Data()
        )
        let signature = try identity.sign(
            canonicalBytes(for: unsigned),
            purpose: FernletCryptoPurpose.Signature.meshRoutedDrainAnswerV1
        )
        return MeshRoutedDrainAnswerPayload(
            answer: unsigned.answer, senderFingerprint: unsigned.senderFingerprint,
            sentAt: unsigned.sentAt, signature: signature
        )
    }
}
