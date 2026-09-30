//
//  PeerNameDisplay.swift
//  ProximityKit
//
//  The one rule for what a person READS as another person's name on the in-person surfaces:
//  the name they chose, or a plain placeholder. Never an identifier (owner decision 2026-09-29:
//  the hex fingerprint and the random Bonjour instance name were debugging aids, and they do not
//  belong on the connect, join, session, roster, keep-as-friend or recipe-share path).
//

import Foundation
import FernletDomainModel

/// What a person reads for a peer: the name that peer chose, or a plain placeholder, and never
/// an identifier.
///
/// **Display text only.** The result is resolved, localized copy. It must never reach a roster,
/// the trust vault, a removal proposal, `keepProximityFriends`, or any wire payload; those persist
/// ``ProximityCoordinator/PeerIdentity/displayNameOrFingerprint``, which is unchanged and is still
/// the value audits and the Lane C witness read.
///
/// **Why a filter and not just a check for an empty name.** An identifier reaches a name slot
/// through three doors, and a surface usually cannot tell which one it came through:
/// - the Option 1b withheld state, where the name is empty until the peer commits;
/// - a roster or trust-vault row that filed the fingerprint AS the name, because the link dropped
///   before the name arrived (`MeshNetworkManager.rosterDisplayName`, then `keepProximityFriends`);
/// - the QUIC transport's random Bonjour instance name (`fernlet-mesh-` plus 12 hex characters),
///   which a slot carries as its `displayHint` and the session's participant projection moderates
///   into a 24-character truncation.
///
/// Every one of them is turned into the placeholder here, in one place, so a new surface cannot
/// forget one.
///
/// **The accepted false positive.** Someone who literally names themselves sixteen hex characters,
/// or `fernlet-mesh-…`, reads as the placeholder. Shorter hex-looking names (`Ada`, `Dee Cafe`,
/// `deadbeef`) are names and pass. `PeerNameDisplayTests` pins both halves.
public nonisolated enum PeerNameDisplay {

    /// Which plain phrase stands in for a person whose name is not known.
    public enum Placeholder: Sendable {
        /// Someone on the connect path whose name has not been shared yet: the nearby rows, the
        /// session's participants, a join request, a recipe recipient.
        case nearby
        /// Someone met in an earlier session whose name never arrived: the keep-as-friend rows and
        /// the Friends & Blocks list.
        case met
    }

    /// The width of a canonical fingerprint (`IdentityService.fingerprint(of:)`: 16 hex characters).
    private static let fingerprintLength = 16

    /// The peer's own chosen name, sanitized for display, or nil when what is on hand is not a
    /// name a person should read.
    ///
    /// - Parameters:
    ///   - raw: The name as received or stored. Peer-supplied, so it is sanitized here
    ///     (`ItemNameModeration.sanitizedName`) before it is judged.
    ///   - fingerprint: The peer's fingerprint when the caller has it. A name equal to it (ignoring
    ///     case) is the fingerprint filed as a name. Nil still catches the canonical shape.
    /// - Returns: The sanitized name, or nil when it is empty, is the peer's fingerprint, has the
    ///   shape of a fingerprint, or is the QUIC instance name.
    public static func personName(_ raw: String, fingerprint: String?) -> String? {
        let name = ItemNameModeration.sanitizedName(raw)
        guard !name.isEmpty else { return nil }
        if let fingerprint, name.caseInsensitiveCompare(fingerprint) == .orderedSame { return nil }
        guard !hasFingerprintShape(name) else { return nil }
        guard !name.lowercased().hasPrefix(MeshLinkAdvertisement.instanceNamePrefix) else { return nil }
        return name
    }

    /// The text to render for a peer: ``personName(_:fingerprint:)``, or the placeholder.
    ///
    /// - Parameters:
    ///   - raw: The name as received or stored.
    ///   - fingerprint: The peer's fingerprint, when the caller has it.
    ///   - placeholder: Which phrase stands in when there is no name. Defaults to ``Placeholder/nearby``.
    /// - Returns: A string safe to show, already localized. Render it verbatim.
    public static func shown(_ raw: String, fingerprint: String?, placeholder: Placeholder = .nearby) -> String {
        personName(raw, fingerprint: fingerprint) ?? text(for: placeholder)
    }

    /// The localized phrase for a placeholder, resolved against this module's catalog.
    ///
    /// - Parameter placeholder: Which phrase.
    /// - Returns: "Someone nearby" or "Someone you met", in the current locale.
    public static func text(for placeholder: Placeholder) -> String {
        switch placeholder {
        case .nearby: ProximityUICopy.Peer.someoneNearby
        case .met: ProximityUICopy.Peer.someoneYouMet
        }
    }

    /// Whether `name` is exactly the canonical fingerprint shape: 16 hex characters.
    ///
    /// - Parameter name: A sanitized name, at most `ItemNameModeration.maxNameLength` characters,
    ///   so the character check is bounded.
    /// - Returns: True for a 16-character all-hex string.
    private static func hasFingerprintShape(_ name: String) -> Bool {
        name.count == fingerprintLength && name.allSatisfy(\.isHexDigit)
    }
}
