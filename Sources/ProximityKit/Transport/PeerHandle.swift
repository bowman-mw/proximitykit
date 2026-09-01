import Foundation
import FernletDomainModel

/// The transport's own stable notion of *one remote endpoint*, opaque to everything above it.
///
/// This exists because ``PeerHandle/id`` alone cannot carry identity across transports. A key is
/// minted once per remote endpoint per session, paired with that endpoint's `id` at the single
/// mint point inside the transport, and handed to every handle built for it — so two handles from
/// different discovery cycles for the same remote carry the same key, which is what lets a slot, a
/// heart connection, or a device cap recognize a returning peer. Under MultipeerConnectivity it
/// stands in for `MCPeerID` equality; under a QUIC transport it will be minted per authenticated
/// connection endpoint.
///
/// **History worth keeping.** `id` used to be a per-discovery cache handle: it was minted inside
/// the same dictionary discovery pruned, so a peer lost while holding no channel came back under a
/// fresh `id`, and `a.id == b.id` implied "same device" while "same device" did not imply
/// `a.id == b.id`. Splitting the identity map out of that dictionary (plan §6.5) is what made `id`
/// session-stable; the endpoint key stays because the *cross-transport* question it answers is
/// not the same question, and because a handle built outside a transport (a test fixture, a mock)
/// still has an `id` no transport minted.
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

/// A discovered peer, wrapped with the transport's session-stable `UUID` for it, the parsed
/// advertisement, and the ``PeerEndpointKey`` for the endpoint behind it.
///
/// The value every transport/coordinator/manager API passes instead of a framework peer type.
/// Equality and hashing are by `id` only, so a peer whose advertisement updates stays the same
/// peer — and, since the split described in ``PeerEndpointKey``, so does a peer re-discovered after
/// the transport pruned its discovery record. Peer-supplied fields (``displayHint``,
/// ``discoveryInfo``) are untrusted wire data until the identity handshake verifies; nothing here
/// is an identity claim.
public nonisolated struct PeerHandle: Hashable, Identifiable, Sendable {
    /// The transport's identity for this endpoint, stable for the life of the transport session
    /// and re-minted only after a `stop()` or a bounded-map eviction — see ``PeerEndpointKey``.
    /// `PeerSlot.id` is this value, which is why the QR ceremony and admission bookkeeping can key
    /// on it.
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
    /// slot, a heart connection, a recipe pairing, a device cap. The consequences of getting the
    /// false negative were concrete and were a real review finding: a slot that is never removed on
    /// disconnect keeps its seat, its coordinator is never cancelled (so ranging is never
    /// invalidated and the foreground Live Activity anchor is orphaned), and a returning partner is
    /// refused by the very cap it already occupies.
    ///
    /// Since ``PeerHandle/id`` became session-stable the two arms agree for every handle a
    /// transport minted, so this reads as belt-and-braces there. It is kept, and kept as the house
    /// spelling, for three reasons: a handle built outside a transport (a fixture, a mock, a fake)
    /// has an `id` no transport minted and only the `id` arm can match it; the bounded identity map
    /// can still evict a very old endpoint, after which the endpoint arm is the one that survives;
    /// and a future transport is free to key identity differently. Neither arm can produce a wrong
    /// match — `id` and endpoint are minted as a pair — so the disjunction only ever adds matches
    /// that would otherwise be lost.
    public func isSameEndpoint(as other: PeerHandle) -> Bool {
        id == other.id || endpoint == other.endpoint
    }
}
