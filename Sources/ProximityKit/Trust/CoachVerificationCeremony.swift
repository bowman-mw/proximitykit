import Foundation
import FernletFoundation

/// Verification ceremony for the in-person coach session (Increment 10 of
/// Docs/Plan-Prekeys-ProtectedLoad-CoachMesh-2026-07-26.md).
///
/// The friend mesh's QR ceremony is structurally bound to `PeerSlot`s
/// (`MeshNetworkManager.beginQRVerification` matches `awaitingManualCommit` slots and keys
/// `pendingQRVerifications` by slot id) — a coach session has no slot, so this is a fresh
/// implementation over the SAME wire primitives (`ProximityVerifyQR`, `VerifyChallengePayload`,
/// `VerifyResponsePayload`, `ProximityVerifySignature` — all slot-independent, and the
/// `.verifyChallenge`/`.verifyResponse` payload types already exist and are sealing-required).
/// A coach session is single-peer, so the binding is to the PEER'S SIGNING KEY instead of a slot.
///
/// Carried forward from the 2026-07-25 review round — the defect that is easy to reintroduce in
/// a fresh implementation, and whose blast radius is larger on a coach channel:
///  1. the displayed nonce is bound to the SPECIFIC peer the sheet was opened for;
///  2. the response is signed only AFTER that binding check passes;
///  3. a wrong-peer challenge is dropped WITHOUT clearing the nonce — burning it is exactly how
///     a racing third party would deny the named peer their genuine round.
@MainActor
public final class CoachVerificationCeremony {

    /// What to do with an inbound challenge (displayer side). Only `.respond` carries a
    /// signature — every drop verdict is produced BEFORE any signing happens.
    public enum ChallengeVerdict: Equatable {
        /// All checks passed; send this sealed response and treat the scanner as ceremony-proven
        /// (a sealed, signed challenge quoting our live display is the scanner's proof).
        case respond(VerifyResponsePayload)
        /// No live display, or the challenge quotes a nonce we are not showing.
        case droppedStale
        /// The display outlived the freshness window; the binding is cleared.
        case droppedExpired
        /// The challenge came from a peer OTHER than the one the sheet was opened for.
        /// The display binding is deliberately KEPT — see rule 3 above.
        case droppedWrongPeer
    }

    private let identity: IdentityService
    private let now: () -> Date
    /// Displayer side: the QR currently shown on THIS device, bound to the one named peer.
    private var activeDisplay: (peerSigningKey: Data, nonce: Data, issuedAt: Date)?
    /// Scanner side: the open challenge round (single-peer session ⇒ at most one).
    private var pendingRound: (qrNonce: Data, challengeNonce: Data, expectedSigningKey: Data)?

    public init(identity: IdentityService, now: @escaping () -> Date = Date.init) {
        self.identity = identity
        self.now = now
    }

    // MARK: - Displayer side

    /// The signed QR for the named peer to scan. The sheet says "Verify with <coach>", so the
    /// binding is minted here, at display time — never guessed at challenge time.
    public func makeDisplayURL(forPeerSigningKey peerSigningKey: Data) -> URL? {
        guard !peerSigningKey.isEmpty,
              let made = try? ProximityVerifyQR.makeURL(identity: identity, now: now()) else { return nil }
        activeDisplay = (peerSigningKey: peerSigningKey, nonce: made.nonce, issuedAt: now())
        return made.url
    }

    /// Ends the display half (sheet dismissed, session over). This — not just the timestamp —
    /// is what makes a photographed QR useless once the sheet closed.
    public func clearDisplay() {
        guard activeDisplay != nil else { return }
        activeDisplay = nil
        FernletAuditLog.log("coach.verify.displayCleared")
    }

    /// An inbound sealed challenge arrived from the session peer whose envelope VERIFIED as
    /// `senderSigningPublicKey`/`senderKeyAgreementPublicKey` (the caller passes the envelope's
    /// verified sender fields, never transport-claimed ones).
    public func handleChallenge(
        _ payload: VerifyChallengePayload,
        senderSigningPublicKey: Data,
        senderKeyAgreementPublicKey: Data
    ) -> ChallengeVerdict {
        // Only honor a challenge quoting the QR THIS device is displaying right now.
        guard let active = activeDisplay, active.nonce == payload.qrNonce else {
            FernletAuditLog.log("coach.verify.staleChallengeDropped")
            return .droppedStale
        }
        // Displayer-side expiry: the QR's own timestamp only bounds what an honest scanner
        // accepts. abs() so a backwards clock jump can't resurrect a display.
        guard abs(now().timeIntervalSince(active.issuedAt)) <= ProximityVerifyQR.freshnessWindow else {
            activeDisplay = nil
            FernletAuditLog.log("coach.verify.expiredChallengeDropped")
            return .droppedExpired
        }
        // The sheet named ONE peer. A challenge from anyone else is a third party who can see
        // this screen — drop it WITHOUT clearing, so the named peer keeps their round. Checked
        // BEFORE anything is signed.
        guard senderSigningPublicKey == active.peerSigningKey else {
            FernletAuditLog.log("coach.verify.wrongPeerChallengeDropped")
            return .droppedWrongPeer
        }
        // Fixed-length fields only — the transcript has no length prefixes, and nothing is signed
        // with the identity key until the wire-supplied nonce and KA key are bounded.
        guard ProximityVerifySignature.isWellFormedChallenge(
            payload, scannerKeyAgreementPublicKey: senderKeyAgreementPublicKey
        ) else {
            FernletAuditLog.log("coach.verify.malformedChallengeDropped")
            return .droppedStale
        }
        let message = ProximityVerifySignature.message(
            scannerKeyAgreementPublicKey: senderKeyAgreementPublicKey,
            challengeNonce: payload.challengeNonce,
            qrNonce: payload.qrNonce
        )
        guard let signature = try? identity.sign(message) else {
            FernletAuditLog.log("coach.verify.signFailed")
            return .droppedStale
        }
        activeDisplay = nil // single use, spent only on the named peer's genuine round
        FernletAuditLog.log("coach.verify.responded")
        return .respond(VerifyResponsePayload(challengeNonce: payload.challengeNonce, signature: signature))
    }

    // MARK: - Scanner side

    /// A `fernlet://verify` QR was scanned during a coach session. Validates signature +
    /// freshness AND that the QR belongs to the SESSION PEER — a coach session has exactly one
    /// counterpart, so a valid QR from anyone else is refused outright rather than searched for.
    /// Returns the sealed challenge to send, or nil when nothing should be sent.
    public func beginVerification(
        scannedURL: URL,
        expectedPeerSigningKey: Data
    ) -> VerifyChallengePayload? {
        guard let payload = ProximityVerifyQR.parse(scannedURL),
              ProximityVerifyQR.isValid(payload, at: now()) else {
            FernletAuditLog.log("coach.verify.invalidScanned")
            return nil
        }
        guard !expectedPeerSigningKey.isEmpty, payload.signingPublicKey == expectedPeerSigningKey else {
            FernletAuditLog.log("coach.verify.qrPeerMismatch")
            return nil
        }
        let challengeNonce = Data((0..<16).map { _ in UInt8.random(in: .min ... .max) })
        pendingRound = (qrNonce: payload.nonce, challengeNonce: challengeNonce,
                        expectedSigningKey: payload.signingPublicKey)
        FernletAuditLog.log("coach.verify.challengeSent")
        return VerifyChallengePayload(qrNonce: payload.nonce, challengeNonce: challengeNonce)
    }

    /// The sealed response arrived from the sender whose envelope VERIFIED as
    /// `senderSigningPublicKey`. True = the peer holds the displayed key: ceremony proven.
    public func handleResponse(
        _ payload: VerifyResponsePayload,
        senderSigningPublicKey: Data
    ) -> Bool {
        guard let pending = pendingRound,
              payload.challengeNonce == pending.challengeNonce,
              senderSigningPublicKey == pending.expectedSigningKey else {
            FernletAuditLog.log("coach.verify.unexpectedResponseDropped")
            return false
        }
        let message = ProximityVerifySignature.message(
            scannerKeyAgreementPublicKey: identity.localKeyAgreementPublicKey,
            challengeNonce: pending.challengeNonce,
            qrNonce: pending.qrNonce
        )
        guard IdentityService.verify(payload.signature, of: message, by: pending.expectedSigningKey) else {
            pendingRound = nil
            FernletAuditLog.log("coach.verify.badResponseSignature")
            return false
        }
        pendingRound = nil
        FernletAuditLog.log("coach.verify.proven")
        return true
    }
}
