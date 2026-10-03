// ProximityNamespace.swift
// ProximityKit/Namespace
//
// The host's protocol identity (Docs/Plan-FernletCoach-ProximityKit-2026-10-01.md §4 A0.2 and A0.3,
// §13 item 1): its labels, radio values, QR scheme, payload vocabulary, keychain rows, storage names,
// log subsystem and peer-name policy as ONE `Sendable` value that the host builds once and hands
// down, and that ProximityKit reads every one of those from, byte-identical for Fernlet.

import Foundation

// MARK: - ProximityNamespace

/// The host's protocol identity: the labels, radio values and names by which ProximityKit's wire,
/// keychain and disk formats identify the app it runs in.
///
/// **Two halves.** ``family`` is what every interoperating app shares — the domain-separation labels,
/// the radios' service types, ALPNs, heartbeat and presentation strings, the QR scheme and the payload
/// vocabulary — so two apps that supply one family speak one wire. ``installation`` is what belongs to
/// this app on this device — its keychain rows, its storage names, its log subsystem and how it shows a
/// peer's name — so two apps of one family still never share a key, a file or a log stream.
///
/// **Built once by the host, never looked up.** ProximityKit holds no instance, offers no default and
/// keeps no global: no `static var`, no slot, no `@TaskLocal`. The host builds one value at its
/// composition root and hands it down through the seams ProximityKit already has, and every reader
/// keeps its own copy, so no read hops an actor and no reader can see a namespace its root did not
/// hand it. A host that supplies none gets a compile error, never another app's identity. The host
/// supplies it as ``ProximityHost/proximityNamespace``, the managers keep a copy, and ProximityKit
/// reads from it all 39 protocol labels, the radio values, the QR scheme, the identity's and the two
/// mesh seal keys' keychain rows, the storage names and the log subsystem. The radios, their
/// postures and `PeerNameDisplay` read the radios' three presentation strings off it too, and
/// wherever a peer's name enters, ProximityKit shows it under the installation's peer-name policy
/// (``PeerNames``: the cap and the floor). Its family also carries the payload vocabulary
/// (``Vocabulary``): the identity envelope seals and parks by its payload rules, the session
/// coordinator signs and dispatches by its session messages and reads its capability rules, the mesh
/// and presence managers advertise its wire2 token and the mesh frames by it, the inventory digest
/// hashes its membership record kinds, the routed type registry builds its rows from its routed
/// types, and the mesh manager signs and dispatches its engine's own frames by its mesh messages. The
/// mesh features' payload and capability tokens are still Fernlet's `PayloadType` and
/// `ProximityCapability` cases until plan steps A0.4 and A0.5 move them; for Fernlet the two
/// spellings are equal, which `ProximityVocabularyGoldenTests` holds. Some strings stay outside it
/// until plan step A0.4: the 13 feature labels ProximityKit reads from FernletCrypto's registry, the
/// heart-drop and moderation keychain services and ``ProximitySupportLayout``'s folder.
/// `ProximityNamespaceBoundaryTests` keeps four rules: no namespace, group or purpose is built outside
/// `Namespace/`; `FernletCryptoPurpose` stays on its 20 allowlisted lines; every literal that spells
/// `fernlet` is on an exact allowlist; and Fernlet's domain vocabulary and records (`PayloadType`,
/// `ProximityCapability`, `ProximityMode`, `ItemNameModeration` and the persisted proximity records)
/// are named only on the exact lines that leave with their features or the session profile. Each
/// list can only shrink.
///
/// **Total, judged once, and refused at run time.** ``init(family:installation:)`` never throws or
/// traps: it runs every soundness rule once and records the verdict in ``soundness``. A host that
/// prefers to fail at launch calls ``validated(family:installation:)``, which throws the same
/// violations. ProximityKit refuses an unsound namespace at run time on its own, reading that stored
/// verdict and failing closed: ``IdentityService/ensureProvisioned()`` and
/// ``IdentityService/encryptGroupKey(_:for:)`` throw ``ProximityNamespaceError`` before they touch a
/// key, and each radio's `start` throws it before it advertises, each with a named audit event
/// (`identity.namespace.unsound`, `mesh.quic.namespaceUnsound`, `presence.quic.namespaceUnsound`,
/// `recipe.quic.namespaceUnsound`) whose context names the door, the violation count and the first
/// violation's case, never a value. A manager handed an identity of another namespace refuses every
/// start of its radio, so nothing is signed for or advertised under two namespaces.
///
/// `nonisolated` against the module's `defaultIsolation(MainActor.self)`, like every type in
/// `Namespace/`: inert value data, read from nonisolated code.
public nonisolated struct ProximityNamespace: Hashable, Sendable {

    /// What every interoperating app shares: the labels, the radios, the QR scheme and the vocabulary.
    public let family: Family

    /// What belongs to this app on this device: keychain rows, storage names, the log subsystem and the
    /// peer-name policy.
    public let installation: Installation

    /// Every soundness rule's verdict, computed once by ``init(family:installation:)``.
    public let soundness: Soundness

    /// The path from the namespace root to the labels, which every ``LabelRow/field`` begins with.
    static let purposesPath = "family.purposes"

    /// Builds a namespace and judges it.
    ///
    /// Total: it never throws or traps. Every broken rule is recorded in ``soundness`` instead, in the
    /// order the rules run (labels, radios, QR scheme, keychain, storage, log subsystem, then the
    /// vocabulary, the radios' presentation strings and the peer-name policy).
    ///
    /// - Parameters:
    ///   - family: What every interoperating app shares.
    ///   - installation: What belongs to this app on this device.
    public init(family: Family, installation: Installation) {
        self.family = family
        self.installation = installation
        self.soundness = Self.judge(family: family, installation: installation)
    }

    /// A namespace, or every reason it is unsound: for a host that prefers to fail at launch.
    ///
    /// - Parameters:
    ///   - family: What every interoperating app shares.
    ///   - installation: What belongs to this app on this device.
    /// - Returns: The namespace, when its ``soundness`` is ``Soundness/sound``.
    /// - Throws: ``ProximityNamespaceError`` carrying every violation, exactly as ``soundness`` records
    ///   them.
    public static func validated(
        family: Family,
        installation: Installation
    ) throws(ProximityNamespaceError) -> ProximityNamespace {
        let namespace = ProximityNamespace(family: family, installation: installation)
        guard case .unsound(let violations) = namespace.soundness else { return namespace }
        throw ProximityNamespaceError(violations: violations)
    }

    /// Every label with its field path, in declaration order: the signature labels (the legacy pair
    /// after the QR labels, when accepted), then key derivation, AEAD and hash.
    ///
    /// Goldens and prefix checks iterate this; they never scan source.
    public var labelRows: [LabelRow] {
        family.purposes.labelRows(under: Self.purposesPath)
    }

    // MARK: - LabelRow

    /// One label and the field it fills, as ``ProximityNamespace/labelRows`` lists them.
    public nonisolated struct LabelRow: Hashable, Sendable {
        /// The field's path from the namespace root, e.g.
        /// `family.purposes.signature.meshRoutedChunkV1`.
        public let field: String
        /// The label, with the role its field fixes.
        public let purpose: ProximityCryptographicPurpose
    }

    // MARK: - Soundness

    /// Whether a namespace passes every soundness rule.
    public nonisolated enum Soundness: Hashable, Sendable {
        /// Every rule passes.
        case sound
        /// At least one rule fails: every failure, in the order the rules run.
        case unsound([Violation])
    }

    /// One broken soundness rule, naming by path from the namespace root the field or fields that break
    /// it. Where a case names two fields, `field` is the one declared first.
    public nonisolated enum Violation: Hashable, Sendable {
        /// A label is empty, longer than 255 bytes, or holds a byte outside `0x21`–`0x7E`. The range also
        /// keeps `0x00` out of every label, so a raw-prefix transcript can never begin with a
        /// length-prefixed label's count, nor the reverse.
        case malformedLabel(field: String)
        /// Two labels have the same bytes.
        case duplicateLabel(field: String, otherField: String)
        /// One label's bytes begin another's, so every transcript under the longer label also begins
        /// with the shorter one: the overlap a positional prefix check cannot tell apart.
        case labelIsPrefix(shorter: String, longer: String)
        /// A service type is not `_name._udp` with a name of 1–15 characters from `[a-z0-9-]` that holds
        /// a letter and no leading, trailing or double hyphen.
        case malformedServiceType(field: String)
        /// An ALPN is empty, longer than 255 bytes, or not printable ASCII (`0x20`–`0x7E`).
        case malformedALPN(field: String)
        /// Two radios share a service type, or two share an ALPN.
        case duplicateRadioValue(field: String, otherField: String)
        /// The mesh heartbeat is empty, longer than 64 bytes, or begins with `{`: every app frame is a
        /// JSON object, and the receive path tells the heartbeat apart from a frame by byte equality
        /// alone.
        case malformedHeartbeat
        /// The QR URL scheme is not a lowercase RFC 3986 scheme: a letter, then letters, digits, `+`,
        /// `-` or `.`. Lowercase because the QR parser lowercases a URL before comparing it.
        case malformedURLScheme
        /// A keychain service or account name is empty.
        case malformedKeychainName(field: String)
        /// Two keychain services are equal, or two identity accounts are.
        case duplicateKeychainName(field: String, otherField: String)
        /// A storage name is not a single path component: it is empty, `.` or `..`, or holds a `/`, a
        /// `:` or a NUL.
        case malformedPathComponent(field: String)
        /// Two of the names inside the storage directory are equal, ignoring case, as a Mac's file system
        /// does.
        case duplicateFileName(field: String, otherField: String)
        /// The log subsystem is empty.
        case emptyLogSubsystem
        /// A token is empty, longer than its group allows, or holds a byte outside `0x21`–`0x7E`: a
        /// payload token (a mesh message among them) or membership record kind at most 255 bytes, a
        /// capability token at most 32 (a receiver cuts a longer one, which then matches nothing), a
        /// routed-type token at most 64 (a routed manifest naming a longer one is refused). A set or
        /// list is named once, by its own path, however many of its members break the rule.
        case malformedToken(field: String)
        /// Two tokens of one group have the same bytes: two of the three session payload tokens, two
        /// capability tokens (each named by its index in `capabilities.known`), two membership record
        /// kinds, two routed types, two mesh messages, or a session payload token and a mesh message,
        /// which one dispatch path tells apart by token alone.
        case duplicateToken(field: String, otherField: String)
        /// A token a rule names is not one the vocabulary knows: a session payload token, a
        /// `sealingRequired` member or a mesh message outside `payloads.known`, or `wire2` or an
        /// `assumedForLegacyPeers` member outside `capabilities.known`. A set or list is named once,
        /// by its own path.
        case unknownToken(field: String)
        /// A summary title is empty or longer than 200 characters, the most a receiver's bounded
        /// summary decode accepts.
        case malformedSummaryTitle(field: String)
        /// An instance-name prefix is empty, holds a byte other than `a`–`z`, `0`–`9` or `-`, or
        /// leaves too little of a 63-byte DNS-SD instance name for the hex that follows it: the mesh
        /// prefix at most 51 bytes (12 hex characters follow), the presence prefix at most 47 (16
        /// follow). Lowercase, because a display layer lowercases a name before comparing it with the
        /// mesh prefix.
        case malformedInstanceNamePrefix(field: String)
        /// The TLS common name is empty, longer than 64 bytes (X.509's upper bound on a common name),
        /// or not printable ASCII (`0x20`–`0x7E`).
        case malformedCommonName
        /// The peer-name policy is out of bounds: its cap is not 1 to 63 characters, or its floor is
        /// empty, longer than the cap, or not exactly what ProximityKit's sanitizer makes of it under
        /// the cap, which would show a floored name differently each time it is moderated again.
        case malformedPeerNames(field: String)
    }

    // MARK: - Collision

    /// Where two namespaces overlap, as ``ProximityNamespace/familyCollisions(with:)`` and
    /// ``ProximityNamespace/installationCollisions(with:)`` report it.
    public nonisolated struct Collision: Hashable, Sendable {

        /// How two values overlap.
        public nonisolated enum Kind: Hashable, Sendable {
            /// The two values are equal.
            case equal
            /// One label's bytes begin the other's.
            case prefix
        }

        /// The field in the namespace that was asked, by path from its root.
        public let field: String
        /// The field in the namespace passed as `other`, by path from its root.
        public let otherField: String
        /// How the two overlap.
        public let kind: Kind
    }
}

// MARK: - ProximityNamespaceError

/// Why a namespace was refused, by ``ProximityNamespace/validated(family:installation:)`` at a host's
/// launch or by ProximityKit at run time (an identity's provisioning or group-key wrap, or a radio's
/// start): every violation its soundness recorded.
///
/// Deliberately not a `LocalizedError`: it names fields for the host's developer, never copy for a
/// person.
public nonisolated struct ProximityNamespaceError: Error, Hashable, Sendable {
    /// The broken rules, exactly as ``ProximityNamespace/soundness`` records them.
    public let violations: [ProximityNamespace.Violation]
}
