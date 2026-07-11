import Foundation
import FernletDomainModel

/// Pure decision logic for the post-session "keep as friend" prompt (Phase 2,
/// Docs/Proximity-Mesh-Redesign-2026-07-10.md). Kept view-free so the session-end flows in
/// ConnectView / DisposableCameraView stay unit-testable.
public nonisolated enum FriendMintingReview {

    /// What the session-end review presents.
    public enum SessionEndReview: Equatable, Sendable {
        /// Photos exist — the photo review sheet presents (the keep-as-friend section rides
        /// along inside it when candidates exist).
        case photoReview
        /// No photos, but eligible new-friend candidates — the compact standalone prompt.
        case friendPromptOnly
        /// Nothing to review; the caller should consume the roster and present nothing.
        case none
    }

    public static func sessionEndReview(hasPhotos: Bool, eligibleCandidateCount: Int) -> SessionEndReview {
        if hasPhotos { return .photoReview }
        return eligibleCandidateCount > 0 ? .friendPromptOnly : .none
    }

    /// Roster entries that may be offered as new friends. Eligibility is computed against the
    /// trust vault at PRESENTATION time (not capture time), so a peer trusted or blocked
    /// mid-session never reaches the sheet. Per the Phase-2 friend lifecycle semantics
    /// (Docs/Proximity-Mesh-Redesign-2026-07-10.md):
    /// - BLOCKED records exclude — a ban is never re-offered (block() mints its never-trusted
    ///   stubs with both timestamps set, so empty-KA stub records land here too; the roster
    ///   entry itself carries fresh handshake keys, so the stub concern is vault-side only);
    /// - ACTIVE records (revokedAt == nil, blockedAt == nil) exclude — already a friend;
    /// - REVOKED-ONLY records (revokedAt != nil, blockedAt == nil) do NOT exclude — "Removed"
    ///   is a reversible unfriend, and this fresh verified in-person session re-offers the peer;
    /// - defensively, roster entries missing either key never reach the sheet (a committed
    ///   handshake always has both).
    public static func eligibleCandidates(
        roster: [MeshSessionRosterEntry],
        trustedPeers: [ProximityTrustedPeerRecord]
    ) -> [MeshSessionRosterEntry] {
        roster.filter { entry in
            guard !entry.signingPublicKey.isEmpty, !entry.keyAgreementPublicKey.isEmpty else {
                return false
            }
            // Match on the signing key first (authorization identity) and fall back to the
            // display/routing fingerprint so legacy 8-char records still apply.
            let matching = trustedPeers.filter { record in
                record.signingPublicKey == entry.signingPublicKey
                    || IdentityService.fingerprintsMatch(record.fingerprint, entry.fingerprint)
            }
            if matching.contains(where: { $0.blockedAt != nil }) { return false }   // banned
            if matching.contains(where: { $0.revokedAt == nil }) { return false }   // active friend
            return true   // no record, or revoked-only — re-offerable
        }
    }
}
