import Foundation
import FernletDomainModel

/// The transport's own stable notion of *one remote endpoint*, opaque to everything above it.
///
/// This exists because ``PeerHandle/id`` is **not** an identity. `id` is a per-discovery cache
/// handle: `MeshMultipeerSession.peer(for:)` mints a fresh `UUID` whenever its peer cache misses,
/// which happens whenever a peer was lost while holding no channel, and on every inbound invitation
/// from a device the transport is not currently tracking. So `a.id == b.id` implies "same device",
/// but "same device" does **not** imply `a.id == b.id` — `id` is a false-negative-only test.
///
/// An endpoint key is the total test. Two handles minted in different discovery cycles for the same
/// remote carry the same key, which is what lets a slot, a heart connection, or a device cap
/// recognize a returning peer. Under MultipeerConnectivity it stands in for `MCPeerID` equality;
/// under a QUIC transport it will be minted per authenticated connection endpoint.
///
/// **Never leaves the process.** It is not persisted, not localized, not serialized, and never on
/// the wire — it carries no meaning outside the transport instance that minted it, which is why it
/// exposes no accessor for its underlying value. Prefer ``PeerHandle/isSameEndpoint(as:)`` over
/// comparing keys directly; that method is the sanctioned spelling of the "same device?" question.
public nonisolated struct PeerEndpointKey: Hashable, Sendable {
    private let raw: UUID

    /// Mints a fresh key. Only a transport should call this: every distinct remote endpoint gets
    /// exactly one, and two calls never produce equal keys.
    public init() {
        self.raw = UUID()
    }

    /// Rebuilds a key from a value a transport already minted. Tests use this to construct two
    /// handles that stand for the same device under different discovery `id`s — the case that has
    /// no other way to be expressed and that the production code's identity rules turn on.
    public init(_ raw: UUID) {
        self.raw = raw
    }
}

/// A discovered peer, wrapped with a per-discovery `UUID`, the parsed advertisement, and the
/// transport's stable ``PeerEndpointKey`` for the endpoint behind it.
///
/// The value every transport/coordinator/manager API passes instead of a framework peer type.
/// Equality and hashing are by `id` only, so a peer whose advertisement updates stays the same
/// peer — but see ``isSameEndpoint(as:)`` for the question `==` does *not* answer. Peer-supplied
/// fields (``displayHint``, ``discoveryInfo``) are untrusted wire data until the identity handshake
/// verifies; nothing here is an identity claim.
public nonisolated struct PeerHandle: Hashable, Identifiable, Sendable {
    /// Per-discovery handle. Stable while the transport keeps tracking this endpoint, and re-minted
    /// after a cache miss — see ``PeerEndpointKey``. `PeerSlot.id` is this value, which is why the
    /// QR ceremony and admission bookkeeping key on it.
    public let id: UUID

    /// The advertised instance name.
    ///
    /// A *hint*, not an identity: it is peer-supplied, unauthenticated, and not unique. Two current
    /// readers use it for more than display and are named here so the next transport does not
    /// silently drop them — `ProximityCoordinator.shouldInviteDiscoveredPeer` uses it as the
    /// last-resort inviter tie-break when neither side advertises a session id, and
    /// `PresenceManager` compares it against its own ephemeral names to filter its own ghost
    /// advertisements. Plan §7.2/§17.1 re-home both onto explicit fields when the QUIC transport
    /// lands; until then the value must keep arriving with the same shape it has today.
    public let displayHint: String

    /// The peer's advertisement record, verbatim. Five keys are read anywhere in the app —
    /// `sid`, `v`, `t`, `name`, `fp` — and all five are Fernlet's own vocabulary, not the
    /// transport's, so they survive a transport swap unchanged.
    public let discoveryInfo: [String: String]?

    /// `discoveryInfo["fp"]`, cached. Advertised, therefore unverified: the coordinator treats a
    /// mismatch against the handshake-proven fingerprint as fatal, and treats absence as "no claim
    /// was made" rather than as a pass.
    public let advertisedFingerprint: String?

    /// The transport's stable identity for the endpoint behind this handle. See
    /// ``PeerEndpointKey`` for why `id` cannot serve this role.
    public let endpoint: PeerEndpointKey

    public init(
        id: UUID,
        displayHint: String,
        discoveryInfo: [String: String]?,
        advertisedFingerprint: String?,
        endpoint: PeerEndpointKey = PeerEndpointKey()
    ) {
        self.id = id
        self.displayHint = displayHint
        self.discoveryInfo = discoveryInfo
        self.advertisedFingerprint = advertisedFingerprint
        self.endpoint = endpoint
    }

    public static func == (lhs: PeerHandle, rhs: PeerHandle) -> Bool { lhs.id == rhs.id }
    public func hash(into hasher: inout Hasher) { hasher.combine(id) }

    /// True when `other` names the same remote endpoint, even if the two values were minted in
    /// different discovery cycles.
    ///
    /// **Use this, not `==`, wherever a stored record is being matched to a transport event** — a
    /// slot, a heart connection, a recipe pairing, a device cap. `==` compares `id`, which answers
    /// "same discovery handle" and returns false for a device that was re-minted between the record
    /// being stored and the event arriving. The consequences of that false negative are concrete
    /// and were a real review finding: a slot that is never removed on disconnect keeps its seat,
    /// its coordinator is never cancelled (so ranging is never invalidated and the foreground Live
    /// Activity anchor is orphaned), and a returning partner is refused by the very cap it already
    /// occupies.
    ///
    /// The `id` disjunct is kept rather than dropped in favour of the endpoint alone: equal `id`
    /// implies equal endpoint, so it can only ever add a match that a transport-level cache miss
    /// would otherwise lose, never a wrong one.
    public func isSameEndpoint(as other: PeerHandle) -> Bool {
        id == other.id || endpoint == other.endpoint
    }
}
