// ProximityNamespace.swift
// ProximityKit/Namespace
//
// ProximityKit plan step A0.2.1 (Docs/Plan-FernletCoach-ProximityKit-2026-10-01.md §4 A0.2, §13 item
// 1): the host's protocol identity — every byte string by which ProximityKit's wire, keychain and disk
// formats identify the app it runs in — as ONE `Sendable` value that the host builds once and hands
// down. Step A0.2.1 added the type alone; A0.2's later commits routed ProximityKit's reads through
// it, one consumer family at a time, each byte-identical for Fernlet.

import Foundation

// MARK: - ProximityNamespace

/// The host's protocol identity: every byte string by which ProximityKit's wire, keychain and disk
/// formats identify the app it runs in.
///
/// **Two halves.** ``family`` is what every interoperating app shares — the domain-separation labels,
/// the radios' service types, ALPNs and heartbeat, and the QR scheme — so two apps that supply one
/// family speak one wire. ``installation`` is what belongs to this app on this device — its keychain
/// rows, its storage names and its log subsystem — so two apps of one family still never share a key,
/// a file or a log stream.
///
/// **Built once by the host, never looked up.** ProximityKit holds no instance, offers no default and
/// keeps no global: no `static var`, no slot, no `@TaskLocal`. The host builds one value at its
/// composition root and hands it down through the seams ProximityKit already has, and every reader
/// keeps its own copy, so no read hops an actor and no reader can see a namespace its root did not
/// hand it. A host that supplies none gets a compile error, never another app's identity. Plan step
/// A0.2.1 added the type; since A0.2.3 the host supplies it as ``ProximityHost/proximityNamespace``
/// and the managers keep a copy, and by the end of A0.2 every protocol label, radio value, keychain
/// row and storage name ProximityKit reads comes from it (`ProximityNamespaceBoundaryTests` keeps it
/// that way).
///
/// **Total, and judged once.** ``init(family:installation:)`` never throws or traps: it runs every
/// soundness rule once and records the verdict in ``soundness``. A host that prefers to fail at launch
/// calls ``validated(family:installation:)``, which throws the same violations. ProximityKit's own
/// run-time refusal of an unsound namespace arrives with plan step A0.3.
///
/// `nonisolated` against the module's `defaultIsolation(MainActor.self)`, like every type in
/// `Namespace/`: inert value data, read from nonisolated code.
public nonisolated struct ProximityNamespace: Hashable, Sendable {

    /// What every interoperating app shares: the labels, the radios and the QR scheme.
    public let family: Family

    /// What belongs to this app on this device: keychain rows, storage names and the log subsystem.
    public let installation: Installation

    /// Every soundness rule's verdict, computed once by ``init(family:installation:)``.
    public let soundness: Soundness

    /// The path from the namespace root to the labels, which every ``LabelRow/field`` begins with.
    static let purposesPath = "family.purposes"

    /// Builds a namespace and judges it.
    ///
    /// Total: it never throws or traps. Every broken rule is recorded in ``soundness`` instead, in the
    /// order the rules run (labels, radios, QR scheme, keychain, storage, log subsystem).
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

/// Why ``ProximityNamespace/validated(family:installation:)`` refused a namespace: every violation its
/// soundness recorded.
///
/// Deliberately not a `LocalizedError`: it names fields for the host's developer, never copy for a
/// person.
public nonisolated struct ProximityNamespaceError: Error, Hashable, Sendable {
    /// The broken rules, exactly as ``ProximityNamespace/soundness`` records them.
    public let violations: [ProximityNamespace.Violation]
}
