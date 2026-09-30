import SwiftUI
import FernletUI

/// A peer's identity fingerprint, for the one place a person may deliberately look one up.
///
/// Since 2026-09-29 that place is the friend detail card's collapsed "Safety code" disclosure in
/// Friends & Blocks, and nowhere else (owner decision: an identifier string is a debugging aid, not
/// part of the connect experience). The join prompt, the activity roster, the keep-as-friend rows
/// and the Friends-tab connect row used to render it too; they now show the person's name, or a
/// plain placeholder, through ``PeerNameDisplay``, and the row-bound QR ceremony is the verification
/// path on the connect side. `PeerNameDisplayTests` pins that no connect-path file renders this view.
///
/// The treatment was centralized when four surfaces had each hand-rolled
/// `.system(.caption, design: .monospaced)`, a system font in an app whose type is entirely bundled:
/// the design system's `stat` role (DM Sans Medium, tabular figures), with a little extra tracking
/// so a hex string still reads character by character.
///
/// Middle truncation is deliberate: the head and tail of a fingerprint are what people compare, so a
/// clipped tail would defeat the only thing the string is for.
///
/// The same argument decides the speech treatment (accessibility review T2-20): hex read as words
/// ("ad be" for `adbe`) is unintelligible and unverifiable, so the view carries
/// `.speechSpellsOutCharacters()`. It lives here, on the component, rather than at the call site,
/// for exactly the reason the font treatment does: a fingerprint is only ever read to compare it,
/// character by character. Braille needs nothing: a
/// braille display already mirrors the string literally, which is the one place the two assistive
/// technologies genuinely diverge.
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
            .speechSpellsOutCharacters()
    }
}
