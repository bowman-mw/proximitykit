import Foundation

/// What the QUIC mesh radio publishes in its Bonjour TXT record, and what it will believe when it
/// reads one back.
///
/// Both directions are pure functions over `[String: String]` so the two decisions that actually
/// matter can be pinned at tier 1 with no radio in sight:
///
/// 1. **`sid` is carried.** The production dial tie-break — `MeshNetworkManager.shouldInitiateInvite`
///    — ranks the per-launch random session id both sides publish, and a peer whose `sid` never
///    arrives is treated as unrankable and always invited. The DEBUG probe's TXT carries no `sid`
///    (it ranks Bonjour service names instead), so copying the probe's advertisement verbatim would
///    silently degrade the mesh tie-break to *both sides dial* — one duplicate tunnel per pair,
///    every pair, with nothing failing.
/// 2. **`fp` is withheld, in both directions.** Publishing the identity fingerprint would activate
///    the coordinator's fingerprint-mismatch gate and the envelope recipient binding that are
///    vacuous today — probably desirable, but it moves signed bytes, so it is a wire decision with
///    a golden vector attached (plan §19.4) and not a port detail. Until that decision is taken the
///    radio neither publishes `fp` nor believes an inbound one: accepting a fingerprint claim we do
///    not make ourselves would turn an unverified peer-supplied string into a fatal-mismatch lever.
///
/// Every key and value here is a frozen wire token in English. `sid`, `v`, `meshID`, `meshName` and
/// `memberCount` are Fernlet's own vocabulary, minted by `MeshNetworkManager.currentDiscoveryInfo()`
/// and read by `PeerHandle.discoveryInfo`; they survive a transport swap precisely because neither
/// side of that pair is transport-shaped. They are never localized.
nonisolated enum MeshLinkAdvertisement {

    /// The advertisement key the dial tie-break ranks on. Never dropped by the field cap below.
    static let sessionIDKey = "sid"

    /// Keys that are deliberately not published, and not believed when a peer publishes them.
    /// See the type's discussion — this is the deferred `fp` decision, spelled once.
    static let withheldKeys: Set<String> = ["fp"]

    /// Maximum advertisement fields in either direction. `currentDiscoveryInfo()` produces at most
    /// five, so this never bites in practice; it exists because the *inbound* direction is
    /// untrusted wire data and a bound that only holds for well-behaved peers is not a bound.
    static let maxFields = 8

    /// Maximum bytes in one advertisement value. The longest honest value is a 36-character UUID
    /// (`sid`, `meshID`) or the 40-character mesh-name prefix, so 64 clears every real field.
    ///
    /// Over-long values are **dropped, never truncated**. A truncated `sid` still looks like a
    /// `sid`, ranks against the local one, and silently decides the wrong side dials; a dropped one
    /// reads as "unrankable", which the tie-break already handles by inviting — the safe direction.
    static let maxFieldValueLength = 64

    /// Bonjour instance-name prefix. A frozen token: it is matched by nothing, but it is what a
    /// developer sees in a `dns-sd` listing, so it stays stable and stays English.
    static let instanceNamePrefix = "fernlet-mesh-"

    /// Random hex characters after the prefix. Twelve is the same width the MC presence radio's
    /// ephemeral display name uses.
    static let instanceNameTokenLength = 12

    /// The TXT fields to publish for a given `discoveryInfo`.
    ///
    /// `sid` is hoisted before the cap is applied, so a manager that one day advertises more than
    /// ``maxFields`` keys loses a mesh label rather than the tie-break discriminator. Empty values
    /// are dropped: an empty `sid` reads as absent to the tie-break anyway, and publishing empty
    /// keys only widens what a passive scanner sees.
    static func publishedFields(from discoveryInfo: [String: String]) -> [String: String] {
        bounded(discoveryInfo)
    }

    /// A browsed peer's TXT record, read back into the `discoveryInfo` shape ``PeerHandle`` carries.
    ///
    /// Deliberately the *same* function as ``publishedFields(from:)`` rather than a mirror of it:
    /// the same withheld keys, the same field cap, the same value-length rule. Asymmetry between
    /// the two directions is precisely how a peer gets to put something into a handle that this
    /// build would never put into its own advertisement, so the two spellings are one body.
    static func advertisement(from txtFields: [String: String]) -> [String: String] {
        bounded(txtFields)
    }

    /// The shared rule both directions obey: hoist `sid`, drop the withheld keys and unpublishable
    /// values, then take the remaining keys in sorted order up to ``maxFields``.
    ///
    /// Hoisting `sid` before the cap is what guarantees it is never the field that gets dropped —
    /// a manager that one day advertises more than ``maxFields`` keys loses a mesh label rather
    /// than the tie-break discriminator.
    private static func bounded(_ fields: [String: String]) -> [String: String] {
        var result: [String: String] = [:]
        if let sessionID = fields[sessionIDKey], isPublishable(sessionID) {
            result[sessionIDKey] = sessionID
        }
        let remaining = max(0, maxFields - result.count)
        let others = fields
            .filter { $0.key != sessionIDKey && !withheldKeys.contains($0.key) && isPublishable($0.value) }
            .sorted { $0.key < $1.key }
        for field in others.prefix(remaining) {
            result[field.key] = field.value
        }
        return result
    }

    /// A fresh Bonjour instance name for one session.
    ///
    /// Random per session and derived from nothing stable (plan §7.2): the archived `MCPeerID` it
    /// replaces was a device-name-derived identifier that persisted across launches, so a passive
    /// Bonjour scanner could link sightings of one person across days and places. Identity here is
    /// proven cryptographically after connecting, never advertised — so the name can afford to
    /// carry no meaning at all, and does.
    static func randomInstanceName() -> String {
        let token = UUID().uuidString
            .replacingOccurrences(of: "-", with: "")
            .prefix(instanceNameTokenLength)
            .lowercased()
        return instanceNamePrefix + token
    }

    /// Whether a value may cross the wire in either direction: non-empty and within the length cap.
    private static func isPublishable(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= maxFieldValueLength
    }
}
