// PeerDisplayNames.swift
// ProximityKit
//
// The two shared display-name coercions of the proximity subsystem: the LOCAL name a radio
// advertises (host preference → device-name fallback), and the wire-boundary coercion every
// PEER-supplied name passes through before it is shown or persisted, under the cap and floor of the
// host's peer-name policy (`ProximityNamespace.PeerNames`). Previously duplicated across the mesh /
// recipe-share / presence managers and their consumers.
//
// Deliberately NOT adopted by the app-side FernletStore.shopDisplayName or the HeartDropService
// name paths — those variants differ on purpose.

import UIKit

extension ProximityHost {
    /// The local display name a proximity radio advertises: `proximityDisplayName` trimmed of
    /// whitespace, falling back to the device name when the user hasn't set one. The single home
    /// of the three previously identical private `displayName` vars in `MeshNetworkManager`,
    /// `ProximityRecipeShareManager`, and `PresenceManager`.
    ///
    /// Public because the UI has to be able to SAY the resolved name: the Friends surfaces show it
    /// as the "You appear as" placeholder/hint so an unset name doesn't silently broadcast "iPhone".
    /// Re-deriving that fallback app-side would be a second copy of the wire's rule.
    public var resolvedProximityDisplayName: String {
        let name = proximityDisplayName.trimmingCharacters(in: .whitespaces)
        return name.isEmpty ? UIDevice.current.name : name
    }
}

/// The wire-boundary coercion for a PEER-supplied display name, and the generic sanitizer under it.
///
/// The sanitizer is mechanism: ``sanitized(_:maxLength:)`` is FernletDomainModel's
/// `ItemNameModeration.sanitizedName`, copied scalar for scalar so ProximityKit's core no longer
/// reaches into Fernlet's domain model for it (`ProximityVocabularyGoldenTests` holds the two equal).
/// The cap and the floor are the host's presentation: ``peerDisplayName(_:in:)`` reads them off the
/// namespace its caller holds (`installation.peerNames`), and the namespace's soundness rules judge
/// the floor by ``sanitized(_:maxLength:)`` itself.
///
/// `nonisolated` against the module's `defaultIsolation(MainActor.self)`: pure functions over values,
/// called from the main-actor managers, the nonisolated envelope and the namespace's soundness rules.
///
/// Public, with ``peerDisplayName(_:in:)``, as settled mechanism: every peer-supplied name a host's
/// feature shows or records passes the one coercion the namespace's soundness rule judges. The
/// sanitizer under it stays internal.
public nonisolated enum ProximityDisplayName {

    /// Coerces a (possibly untrusted, e.g. wire-received) name into a safe shape WITHOUT throwing: drops
    /// control / zero-width / bidi-override scalars, collapses whitespace runs, and caps the length.
    /// Does NOT screen profanity.
    ///
    /// A cap below one keeps nothing; for every cap from zero up the result is exactly
    /// `ItemNameModeration.sanitizedName(raw, maxLength:)`'s, which traps on a negative one. The cap
    /// arrives here from a host's namespace, so the guard keeps a malformed one from trapping.
    ///
    /// - Parameters:
    ///   - raw: The name as received or typed.
    ///   - maxLength: The most characters (`Character`s) the result keeps.
    /// - Returns: The sanitized name; empty when nothing displayable is left.
    static func sanitized(_ raw: String, maxLength: Int) -> String {
        guard maxLength > 0 else { return "" }
        // Order is load-bearing, and the three legs are not interchangeable:
        //  1. Invisible scalars are dropped OUTRIGHT, never turned into a space. They render as
        //     nothing, so "Ali<ZWSP>ce" is seen by a human as "Alice" and must sanitize to "Alice";
        //     emitting a space instead would invent a name nobody typed. This leg runs first
        //     because Foundation counts ZERO WIDTH SPACE as whitespace, so leg 2 would claim it.
        //  2. Visible whitespace — including the control scalars \n, \r and \t — becomes a SPACE
        //     rather than vanishing. Deleting it glues the words either side together
        //     ("Soup\nIgnore this" -> "SoupIgnore this"), which reads wrong and lets externally
        //     authored text forge a phrase it never wrote. Runs before leg 3 because those three
        //     are themselves control characters.
        //  3. Every remaining control scalar is dropped, so the result carries none.
        let normalized = raw.unicodeScalars.compactMap { scalar -> Unicode.Scalar? in
            if invisibleScalars.contains(scalar) { return nil }
            if CharacterSet.whitespacesAndNewlines.contains(scalar) { return " " }
            if CharacterSet.controlCharacters.contains(scalar) { return nil }
            return scalar
        }
        let collapsed = String(String.UnicodeScalarView(normalized))
            .components(separatedBy: .whitespacesAndNewlines)
            .filter { !$0.isEmpty }
            .joined(separator: " ")
        return String(collapsed.prefix(maxLength))
    }

    /// A peer-supplied display name as this device shows and records it: ``sanitized(_:maxLength:)``
    /// under the host's cap, or the host's floor when nothing displayable remains. The single home of
    /// the sanitize-or-floor idiom used by the heart receive paths, the vouch-list cache, the session
    /// chat store, the keep-as-friend rows and the envelope's sender name.
    ///
    /// The contract: under a sound namespace the result is never empty, carries no control,
    /// zero-width or bidirectional-override scalar and no leading, trailing or repeated whitespace,
    /// and keeps at most the namespace's `installation.peerNames.maxLength` characters (the soundness
    /// rule holds the floor to exactly what this sanitizer leaves of it). It throws nothing and traps
    /// on nothing, whatever the input or the namespace.
    ///
    /// - Parameters:
    ///   - raw: The name as the peer supplied it.
    ///   - namespace: The host's namespace, whose `installation.peerNames` gives the cap and the floor.
    /// - Returns: The sanitized name, or the floor, which a sound namespace never leaves empty.
    public static func peerDisplayName(_ raw: String, in namespace: ProximityNamespace) -> String {
        let policy = namespace.installation.peerNames
        let name = sanitized(raw, maxLength: policy.maxLength)
        return name.isEmpty ? policy.floor : name
    }

    /// Zero-width and bidirectional-override format characters that can hide or reorder text.
    private static let invisibleScalars: CharacterSet = CharacterSet(charactersIn:
        "\u{200B}\u{200C}\u{200D}\u{200E}\u{200F}\u{202A}\u{202B}\u{202C}\u{202D}\u{202E}"
            + "\u{2060}\u{2066}\u{2067}\u{2068}\u{2069}\u{FEFF}")
}
