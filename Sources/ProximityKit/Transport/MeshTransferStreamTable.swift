import Foundation

// MARK: - MeshTransferRoute

/// Which pipe one reliable frame rides on a QUIC tunnel.
///
/// Plan §7.1 maps `.reliable` sends onto "one long-lived **control stream** per connection … +
/// independent per-transfer streams for photo chunks". This is that fork, said as a value so the
/// decision is settled at tier 1 and ``NetworkMeshSession`` only acts on the answer — the same
/// separation ``MeshHeartbeatChannel`` makes for the other pipe.
nonisolated enum MeshTransferRoute: Equatable, Sendable {

    /// The tunnel's single long-lived control stream. Every small frame, in order, as today.
    case controlStream

    /// A stream opened for this one frame and released when the peer has read it.
    case transferStream
}

// MARK: - MeshTransferID

/// A handle on one open transfer, minted per tunnel and per direction.
///
/// **Session-scoped and memory-only**: never persisted, never advertised, and never on the wire —
/// a transfer stream is self-describing (one length-framed payload, then the peer's ack), so the
/// two ends never need to agree on a name for it. The id exists so the local budget can be released
/// by the exact transfer that took it, rather than by a count a second failure path could
/// decrement twice.
nonisolated struct MeshTransferID: Hashable, Sendable {

    /// The minting counter's value. Opaque; ordering carries no meaning.
    let rawValue: UInt64
}

// MARK: - MeshTransferStreamTable

/// One tunnel's per-transfer stream budget: which frames earn a stream of their own, and how many
/// may be open at once in each direction.
///
/// ## Why a bulk frame wants its own stream
///
/// A QUIC stream is a byte pipe, and ``NetworkMeshSession`` writes every reliable frame onto one of
/// them. A friend photo is roughly three orders of magnitude larger than a chat message, so putting
/// it on the control stream parks every later frame — a heartbeat, a moderation signal, the next
/// message — behind it until the photo has finished crossing. That is head-of-line blocking, and it
/// is the whole reason plan §7.1 asks for independent per-transfer streams.
///
/// **The behaviour above the transport is unchanged.** A transfer stream carries exactly one
/// length-framed payload, delivered as exactly one `InboundPeerFrame`, with the same
/// ``NetworkMeshSession/maxInboundWireBytes`` ceiling both radios enforce. There is no chunking, no
/// resume, no ack for the *application* to see, and no new envelope: `MeshNetworkManager` sends a
/// photo the same way it sends a chat message, over MC and over QUIC alike, and cannot tell which
/// pipe carried it. The only thing that moved is which stream the bytes travelled on.
///
/// ## What ordering this gives up
///
/// Frames on separate streams are not ordered against each other. That is why the floor is set high
/// enough that only photo- and manifest-shaped payloads reach it: the coordinator's identity
/// handshake, the chat/heart/capability/moderation traffic and every membership record stay on the
/// control stream, in order, exactly as they are under MultipeerConnectivity. What crosses the floor
/// is idempotent and causally gated by a round trip already — a photo is only ever sent in answer to
/// a `FriendPhotoRequestPayload`, and a manifest is a diff that is re-sent at the next commit.
///
/// ## Why exhausting the budget cannot wedge anything
///
/// Both halves degrade to what happens today rather than to a failure:
///
/// - **Outbound.** No free slot means ``openOutbound(reliableByteCount:)`` answers nil and the frame
///   goes on the control stream. Delivering a bulk frame in order is always allowed; dropping one is
///   not — the same rule ``NetworkMeshSession/send(_:to:mode:)`` already applies when a best-effort
///   payload will not fit a datagram.
/// - **Inbound.** No free slot means the stream is not served, so it is released un-acked and the
///   sender's write fails loudly. That is the MC photo path's own failure semantics (no ack, no
///   retry, no partial state; recovery is the next manifest sync), reached by a different route.
///
/// And a budget can never outlive the tunnel that owns it: the table is stored **in** the tunnel
/// record, so `endTunnel` dropping that record drops the budget with it, and a transfer whose peer
/// vanished mid-flight releases a slot nobody is left to take.
///
/// Bounded in both directions (Power of 10 rule 3), pure, and driven by no clock — which is what
/// lets the whole policy be settled at tier 1.
nonisolated struct MeshTransferStreamTable: Sendable {

    /// Payload size at or above which a reliable frame earns a stream of its own.
    ///
    /// 64 KiB sits in a wide empty gap. Everything the mesh sends in the ordinary course — the
    /// signed identity introduction, capability lists, chat messages (500 characters), hearts, shop
    /// catalogues, moderation signals, membership records — is a few kilobytes at most, and stays
    /// ordered on the control stream. A friend photo (1400 px JPEG at q0.82, sealed, base64 inside
    /// JSON, sealed and base64'd again) is hundreds of kilobytes. Nothing real lands near the line,
    /// so moving it a factor of two either way changes which stream nothing travels on.
    static let bulkFloorBytes = 64 * 1024

    /// Transfers this side may have open to one peer at once.
    ///
    /// Four, against a photo path that answers one request per slot at a time and broadcasts to at
    /// most `maxActiveSlots` (3) peers: enough that a real session never reaches it, small enough
    /// that a peer stalling mid-transfer costs a bounded number of streams before bulk traffic
    /// simply goes back to riding the control stream.
    static let maxConcurrentOutbound = 4

    /// Transfers one peer may have open toward this side at once. Same size, same reasoning, and
    /// the reason a peer that opens streams and then says nothing cannot consume more than four.
    static let maxConcurrentInbound = 4

    /// The single byte a receiver writes back once it has read a transfer whole.
    ///
    /// A frozen wire token — never localized, never persisted. It exists for a mechanical reason
    /// rather than a protocol one: a `Network.QUIC.Stream`'s lifetime **is its Swift object's**, so
    /// a sender that released the stream the instant its last write returned would tear the stream
    /// down under a peer that had not read it yet. Waiting for one byte is how the sender knows the
    /// payload landed, and it turns "the peer vanished mid-transfer" into a thrown send rather than
    /// a silent truncation.
    static let ackByte: UInt8 = 0x06

    /// ``ackByte`` as the payload a receiver actually writes.
    static var ack: Data { Data([ackByte]) }

    /// One direction's open transfers: a capacity, the ids currently holding it, and the counter
    /// that mints them.
    ///
    /// A set rather than a count so a slot is released by the transfer that took it. Two failure
    /// paths racing to release the same transfer — the write throwing and the tunnel being torn
    /// down — would each decrement a counter, and the second decrement would hand out a slot that
    /// was never free.
    struct Ledger: Sendable {

        /// How many transfers may be open in this direction at once.
        let capacity: Int

        private var openIDs: Set<MeshTransferID> = []
        private var nextRawValue: UInt64 = 0

        /// A ledger with room for `capacity` transfers.
        init(capacity: Int) {
            self.capacity = capacity
        }

        /// How many transfers are open right now.
        var openCount: Int { openIDs.count }

        /// Whether this ledger still holds `id`.
        func isOpen(_ id: MeshTransferID) -> Bool { openIDs.contains(id) }

        /// Takes one slot, or answers nil when the direction is full.
        mutating func open() -> MeshTransferID? {
            guard openIDs.count < capacity else { return nil }
            let id = MeshTransferID(rawValue: nextRawValue)
            nextRawValue &+= 1
            openIDs.insert(id)
            return id
        }

        /// Gives one slot back. Idempotent: releasing a transfer twice is a no-op, which is what
        /// makes it safe to call from both a `defer` and a teardown path.
        mutating func close(_ id: MeshTransferID) {
            openIDs.remove(id)
        }
    }

    /// Transfers this side has open toward the peer.
    private(set) var outbound = Ledger(capacity: maxConcurrentOutbound)

    /// Transfers the peer has open toward this side.
    private(set) var inbound = Ledger(capacity: maxConcurrentInbound)

    /// An empty budget. One tunnel owns exactly one.
    init() {}

    /// Which pipe a reliable frame of this size belongs on, before any budget is consulted.
    ///
    /// Pure and static: the floor is a property of the payload, not of what happens to be in flight,
    /// so a test can pin the boundary without building a table at all.
    static func route(reliableByteCount: Int) -> MeshTransferRoute {
        guard reliableByteCount >= bulkFloorBytes else { return .controlStream }
        return .transferStream
    }

    /// Claims a transfer stream for one outbound reliable frame.
    ///
    /// - Returns: the id holding the slot, or nil when the frame belongs on the control stream —
    ///   either because it is under ``bulkFloorBytes`` or because this direction is already full.
    ///   Both answers mean the same thing to the caller, which is why they are one value: send it
    ///   on the control stream.
    mutating func openOutbound(reliableByteCount: Int) -> MeshTransferID? {
        guard Self.route(reliableByteCount: reliableByteCount) == .transferStream else { return nil }
        return outbound.open()
    }

    /// Releases one outbound transfer.
    mutating func closeOutbound(_ id: MeshTransferID) {
        outbound.close(id)
    }

    /// Claims a slot for one inbound transfer stream, or answers nil when the peer already has
    /// ``maxConcurrentInbound`` open and this one must go unserved.
    mutating func openInbound() -> MeshTransferID? {
        inbound.open()
    }

    /// Releases one inbound transfer.
    mutating func closeInbound(_ id: MeshTransferID) {
        inbound.close(id)
    }
}
