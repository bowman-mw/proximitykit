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
            Text("Keep as friends?")
                .font(.fernlet(.headerMedium))
                .foregroundStyle(Color.bark)

            Text("Friends stay on your list for good vibes and future hangouts. This is just for you — they won't be notified either way.")
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

/// One keep-as-friend row: sanitized display name, fingerprint, and the Keep/Keeping chip.
///
/// Private child of ``KeepFriendsSection``; the toggle closure flips membership in the shared
/// kept-fingerprints binding.
private struct KeepFriendRow: View {
    let candidate: MeshSessionRosterEntry
    let isKept: Bool
    let toggle: () -> Void

    /// The display name is peer-supplied wire input — sanitize for display (control/zero-width/
    /// bidi scalars out), matching how the heart manager renders peer names.
    private var displayName: String {
        let sanitized = ItemNameModeration.sanitizedName(candidate.displayName)
        return sanitized.isEmpty ? "A friend" : sanitized
    }

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text(displayName)
                    .font(.fernlet(.headerMedium))
                    .foregroundStyle(Color.bark)
                Text(candidate.fingerprint)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(Color.slate)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            Spacer(minLength: 12)

            Button(isKept ? "Keeping" : "Keep") { toggle() }
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
                    Text("Nice hangout!")
                        .font(.fernlet(.displayMedium))
                        .foregroundStyle(Color.bark)

                    KeepFriendsSection(candidates: candidates, keptFingerprints: $keptFingerprints)
                }
                .padding(20)
                .padding(.bottom, 10)
            }

            Button("Done") { done() }
                .buttonStyle(ChipButtonStyle(selected: true))
                .frame(maxWidth: .infinity)
                .padding(16)
                .background(Color.parchment)
                .accessibilityIdentifier("friends.keepFriends.done")
        }
        .background(Color.parchment)
    }
}
