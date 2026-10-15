//
//  PeerNameDisplay.swift
//  ProximityKit
//
//  The one rule for what a person READS as another person's name on the in-person surfaces:
//  the name they chose, never an identifier (owner decision 2026-09-29: the hex fingerprint and
//  the random Bonjour instance name were debugging aids, and they do not belong on the connect,
//  join, session, roster, keep-as-friend or recipe-share path). This is the identifier filter, and
//  it is mechanism: this module knows its own identifiers, and the namespace's soundness rule exists
//  to keep the filter whole. The plain placeholder a person reads when it refuses a name is the
//  host's display policy, so this module ships none: Fernlet's is FernletConnections' extension of
//  this type (`PeerNameDisplay+Placeholders.swift`), over that module's own catalog.
//

import Foundation

/// What a person reads for a peer: the name that peer chose, and never an identifier.
///
/// **The filter is this module's; the placeholders are the host's.**
/// ``personName(_:fingerprint:in:)`` is the identifier filter, with the fingerprint width and shape
/// it checks, which the namespace's soundness rule protects
/// (`ProximityNamespace.peerNameFingerprintLength`, which `ProximityVocabularyGoldenTests` holds
/// equal to `fingerprintLength`). Which plain phrase stands in when it refuses a name is the host's
/// display policy: Fernlet's app reads it through FernletConnections' extension of this type
/// (`Placeholder`, `shown`, `firstName` and `text(for:)`, resolved against that module's catalog).
///
/// **Display text only.** The name it answers, and the placeholder a host shows in its place, is
/// display text. It must never reach a roster, the trust vault, a removal proposal,
/// `keepProximityFriends`, or any wire payload; those persist
/// ``ProximityCoordinator/PeerIdentity/displayNameOrFingerprint``, which is unchanged and is still
/// the value audits and the Lane C witness read.
///
/// **Why a filter and not just a check for an empty name.** An identifier reaches a name slot
/// through three doors, and a surface usually cannot tell which one it came through:
/// - the Option 1b withheld state, where the name is empty until the peer commits;
/// - a roster or trust-vault row that filed the fingerprint AS the name, because the link dropped
///   before the name arrived (`MeshNetworkManager.rosterDisplayName`, then `keepProximityFriends`);
/// - the QUIC transport's random Bonjour instance name (the host namespace's
///   `family.radios.meshInstanceNamePrefix` plus 12 hex characters; Fernlet's prefix is
///   `fernlet-mesh-`), which a slot carries as its `displayHint` and the session's participant
///   projection moderates into a truncation at the host's peer-name cap (24 characters for Fernlet).
///
/// Every one of them is refused here, in one place, so a new surface cannot forget one, and reads
/// as the host's placeholder. The instance name is recognized by the prefix of the namespace each
/// caller passes (`in namespace:`, last): a peer advertises the prefix of the family both devices
/// share, so the host's own namespace names it. The checks run on the name already cut to that
/// namespace's peer-name cap, which its soundness rules keep at least a fingerprint's 16 characters
/// and the mesh prefix's length, so a cut name still shows what they look for.
///
/// **The accepted false positive.** Someone who literally names themselves sixteen hex characters,
/// or the mesh prefix and more (`fernlet-mesh-…` for Fernlet), is refused and reads as the
/// placeholder. Shorter hex-looking names (`Ada`, `Dee Cafe`, `deadbeef`) are names and pass.
/// `PeerNameDisplayTests` pins both halves.
public nonisolated enum PeerNameDisplay {

    /// The width of a canonical fingerprint (`IdentityService.fingerprint(of:)`: 16 hex characters).
    /// Internal so `ProximityVocabularyGoldenTests` holds the namespace's soundness bound
    /// (`ProximityNamespace.peerNameFingerprintLength`) equal to it.
    static let fingerprintLength = 16

    /// The peer's own chosen name, sanitized for display, or nil when what is on hand is not a
    /// name a person should read.
    ///
    /// - Parameters:
    ///   - raw: The name as received or stored. Peer-supplied, so it is sanitized here
    ///     (`ProximityDisplayName.sanitized(_:maxLength:)`, under the namespace's peer-name cap) before
    ///     it is judged.
    ///   - fingerprint: The peer's fingerprint when the caller has it. A name equal to it (ignoring
    ///     case) is the fingerprint filed as a name. Nil still catches the canonical shape.
    ///   - namespace: The host's namespace. A name that begins with its
    ///     `family.radios.meshInstanceNamePrefix` (compared lowercased, as the soundness rule keeps
    ///     the prefix) is the QUIC instance name, and its `installation.peerNames.maxLength` caps the
    ///     name.
    /// - Returns: The sanitized name, or nil when it is empty, is the peer's fingerprint, has the
    ///   shape of a fingerprint, or is the QUIC instance name.
    public static func personName(_ raw: String, fingerprint: String?, in namespace: ProximityNamespace) -> String? {
        let name = ProximityDisplayName.sanitized(raw, maxLength: namespace.installation.peerNames.maxLength)
        guard !name.isEmpty else { return nil }
        if let fingerprint, name.caseInsensitiveCompare(fingerprint) == .orderedSame { return nil }
        guard !hasFingerprintShape(name) else { return nil }
        guard !name.lowercased().hasPrefix(namespace.family.radios.meshInstanceNamePrefix) else { return nil }
        return name
    }

    /// Whether `name` is exactly the canonical fingerprint shape: 16 hex characters.
    ///
    /// - Parameter name: A sanitized name, at most the namespace's peer-name cap in characters (63 at
    ///   most, by its soundness rules), so the character check is bounded.
    /// - Returns: True for a 16-character all-hex string.
    private static func hasFingerprintShape(_ name: String) -> Bool {
        name.count == fingerprintLength && name.allSatisfy(\.isHexDigit)
    }
}
