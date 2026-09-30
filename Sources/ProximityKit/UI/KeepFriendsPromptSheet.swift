import SwiftUI
import FernletUI
import FernletDomainModel

// Phase 2 friend minting (Docs/Proximity-Mesh-Redesign-2026-07-10.md): the per-participant
// "keep as a friend?" affordance shown at session end. One-sided and local-only — keeping mints
// a trust-vault record on THIS device only; skipping does nothing, and the peer is never
// notified either way.

/// The keep-as-friend rows. Embedded in FriendPhotoReviewSheet when the session produced photos,
/// or hosted by KeepFriendsPromptSheet when it didn't.
struct KeepFriendsSection: View {
    let candidates: [MeshSessionRosterEntry]
    @Binding var keptFingerprints: Set<String>

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(verbatim: ProximityUICopy.KeepFriends.sectionTitle)
                .font(.fernlet(.headerMedium))
                .foregroundStyle(Color.bark)

            Text(verbatim: ProximityUICopy.KeepFriends.explainer)
                .font(.fernlet(.bodySmall))
                .foregroundStyle(Color.slate)
                .fernletWrappingText()

            VStack(spacing: 8) {
                ForEach(candidates) { candidate in
                    KeepFriendRow(
                        candidate: candidate,
                        isKept: keptFingerprints.contains(candidate.fingerprint),
                        toggle: { toggle(candidate.fingerprint) }
                    )
                }
            }
        }
    }

    private func toggle(_ fingerprint: String) {
        if keptFingerprints.contains(fingerprint) {
            keptFingerprints.remove(fingerprint)
        } else {
            keptFingerprints.insert(fingerprint)
        }
    }
}

/// One keep-as-friend row: the person's name and the Keep/Keeping chip.
///
/// Private child of ``KeepFriendsSection``; the toggle closure flips membership in the shared
/// kept-fingerprints binding. No fingerprint (owner decision 2026-09-29): an identifier string
/// is not a name, and the roster files the fingerprint AS the name when the link dropped before
/// the name arrived, so that case reads "Someone you met" instead.
private struct KeepFriendRow: View {
    let candidate: MeshSessionRosterEntry
    let isKept: Bool
    let toggle: () -> Void

    /// The display name is peer-supplied wire input: ``PeerNameDisplay`` sanitizes it (control,
    /// zero-width and bidi scalars out) and turns an identifier filed as a name into the placeholder.
    private var displayName: String {
        PeerNameDisplay.shown(candidate.displayName, fingerprint: candidate.fingerprint, placeholder: .met)
    }

    var body: some View {
        HStack(spacing: 12) {
            Text(verbatim: displayName)
                .font(.fernlet(.headerMedium))
                .foregroundStyle(Color.bark)

            Spacer(minLength: 12)

            Button(isKept ? ProximityUICopy.KeepFriends.keeping : ProximityUICopy.KeepFriends.keep) { toggle() }
                .buttonStyle(ChipButtonStyle(selected: isKept))
                .accessibilityIdentifier("friends.keepFriend.\(candidate.fingerprint)")
        }
        .padding(12)
        .background(Color.cream, in: RoundedRectangle(cornerRadius: 12))
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(isKept ? Color.moss : Color.bark.opacity(0.08), lineWidth: isKept ? 1.5 : 1)
        )
        // Deliberately no accessibilityIdentifier on this container — a container id would
        // shadow the per-row button id above (known settings-toggle gotcha).
    }
}

/// Compact standalone prompt for sessions that ended with no photos to review but with eligible
/// new-friend candidates. Dismissing without choosing = skip all (the host clears the roster in
/// onDismiss and mints only what was toggled).
public struct KeepFriendsPromptSheet: View {
    let candidates: [MeshSessionRosterEntry]
    @Binding var keptFingerprints: Set<String>
    let done: () -> Void

    public init(candidates: [MeshSessionRosterEntry], keptFingerprints: Binding<Set<String>>, done: @escaping () -> Void) {
        self.candidates = candidates
        self._keptFingerprints = keptFingerprints
        self.done = done
    }

    public var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    Text(verbatim: ProximityUICopy.KeepFriends.sessionTitle)
                        .font(.fernlet(.displayMedium))
                        .foregroundStyle(Color.bark)

                    KeepFriendsSection(candidates: candidates, keptFingerprints: $keptFingerprints)
                }
                .padding(20)
                .padding(.bottom, 10)
            }

            // "Done" finishes the flow (and mints the keeps), so it is a call-to-action pill, not a
            // 34pt selection chip.
            Button(ProximityUICopy.KeepFriends.done) { done() }
                .buttonStyle(ActionPillButtonStyle(.primary))
                .frame(maxWidth: .infinity)
                .padding(16)
                .background(Color.parchment)
                .accessibilityIdentifier("friends.keepFriends.done")
        }
        .background(Color.parchment)
    }
}
