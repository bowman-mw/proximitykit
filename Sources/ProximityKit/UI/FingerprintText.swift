import SwiftUI
import FernletUI

/// A peer's identity fingerprint, rendered identically everywhere one is shown.
///
/// Fingerprints appear on four surfaces — the friend detail card, the join prompt (where two people
/// read them off each other's screens), the activity roster, and the keep-as-friend rows — and each
/// had hand-rolled its own `.system(.caption, design: .monospaced)`, which is a system font in an app
/// whose type is entirely bundled. This centralizes the treatment on the design system's `stat` role
/// (DM Sans Medium, tabular figures), with a little extra tracking so a hex string still reads
/// character by character.
///
/// Middle truncation is deliberate: the head and tail of a fingerprint are what people compare, so a
/// clipped tail would defeat the only thing the string is for.
public struct FingerprintText: View {
    private let fingerprint: String
    /// Ink colour; defaults to `slate` inside `body` — a `@MainActor` colour token can never be a
    /// default argument in this module.
    private let color: Color?
    private let lineLimit: Int

    public init(_ fingerprint: String, color: Color? = nil, lineLimit: Int = 1) {
        self.fingerprint = fingerprint
        self.color = color
        self.lineLimit = lineLimit
    }

    public var body: some View {
        Text(fingerprint)
            .font(.fernlet(.stat))
            .tracking(0.5)
            .foregroundStyle(color ?? Color.slate)
            .lineLimit(lineLimit)
            .truncationMode(.middle)
    }
}
