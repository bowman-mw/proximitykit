import Foundation
import FernletDomainModel

/// Failures of the mesh group-key photo/metadata AES-GCM crypto.
///
/// Thrown by ``MeshNetworkManager``'s static encrypt/decrypt helpers; callers treat every case
/// as "drop the payload".
enum MeshEncryptionError: Error, Equatable {
    case decryptionFailed
    case encryptionFailed
    /// The bytes carry no `FMGP2` / `FMGM2` format marker — the shape of the retired mesh wire
    /// format a peer on an older build sends.
    ///
    /// Named separately from ``decryptionFailed`` on purpose: the crypto standardization round's
    /// Phase 4 deleted the reader for that format, and a peer that still speaks it must be refused
    /// with a reason the receiving surface can explain rather than folded into the generic "this
    /// did not decrypt" that also covers a wrong key, a stale epoch and a tampered payload. The
    /// retired format had no marker of its own, so this case cannot separate an older build from
    /// malformed bytes — it separates both from a payload that reached the AEAD and was rejected
    /// there, which is the distinction the audit trail actually needs.
    case legacyWireFormat
}

/// A slot's traffic class in the capped mesh session.
///
/// ``MeshNetworkManager`` re-ranks slots by stable distance: the nearest peers get the three
/// `active` slots (full payload routing) and the rest fall to `lightweight` (heartbeats only).
public enum SlotKind {
    case active      // full payload routing, up to 3
    case lightweight // heartbeats only, up to 2
}

/// What the returning-member re-seat has concluded about one slot's gated peer (2026-09-22).
///
/// Two of the three answers are final for the life of the slot and one is not, which is why this
/// is not a flag: a peer that is simply not (yet) a member stays ``open`` and is judged again when
/// the roster or the session state moves — a member admitted by somebody else while this device
/// was away becomes re-seatable the moment its admission lands here.
enum MeshReturningMemberReseat: Equatable {

    /// Not re-seated: never judged, or judged and not (yet) a returning member.
    case open

    /// The coordinator was asked to commit the peer whose signing key is `signingPublicKey` — the
    /// key the re-seat judged, which was both the gated identity's and the one the tunnel proved.
    /// The commit lands a main-actor hop later; nothing more is asked of this slot.
    ///
    /// The key is kept because the coordinator commits whatever identity it holds when the ask
    /// lands, and a second identity introduction in between re-gates it: the slot is seated only as
    /// this key (`MeshNetworkManager.reseatRefusal(at:identity:)`), or evicted.
    case commitRequested(signingPublicKey: Data)

    /// The identity the coordinator verified is not the key the transport's channel introduction
    /// proved for this link — a replayed or borrowed identity introduction. Refused, and audited
    /// once, for the life of the slot. (A link with no proven key YET stays ``open``: that is
    /// "cannot tell", not "mismatched".)
    ///
    /// The re-seat's refusal only: the gated identity is left where only a gesture could commit
    /// it, and a gesture that does is refused one step later at the seat, whose transport check
    /// every commit answers to (`MeshNetworkManager.seatTransportRefusal(at:identity:)`,
    /// 2026-09-23) — the link is then evicted.
    case refusedMismatchedKey
}

/// One peer's seat in the live mesh session: the transport channel, its ``ProximityCoordinator``,
/// and the handshake-verified identity captured at commit.
///
/// Owned exclusively by ``MeshNetworkManager``, which appends a slot when a peer channel comes up
/// and fills `fingerprint` / the verified key fields only when the coordinator reaches
/// `.connected` — a nil `fingerprint` means an UNCOMMITTED candidate, which the feature-payload
/// registry gate must drop. `verifiedKeyAgreementPublicKey` is the sealing target for every
/// pairwise-sealed send (never descriptor gossip); `peerCapabilities` gates room broadcasts.
/// Memory-only session state, never persisted.
///
/// **Read that against ``MeshSessionContext`` (P3 item 2), which is the documented reversal of the
/// module's old blanket "ProximityKit persists nothing" rule (plan §17.3).** What is durable now is
/// *membership* — the signed records a mesh's roster is derived from — sealed by
/// ``MeshSessionStore``. A slot is not membership: it is one live channel plus the keys that
/// channel verified, and losing sockets never ends membership (plan §8.2). So this stays
/// memory-only, and after a process death the slots are rebuilt by reconnecting, not reloaded.
public struct PeerSlot: Identifiable {
    public let id: UUID  // == peer.id
    public let peer: PeerHandle
    /// The peer's channel on whichever radio the manager is running — `NetworkPeerChannel` on the
    /// QUIC radio that ships, a detached one in unit tests. (The retired MultipeerConnectivity
    /// radio's `PeerChannelTransport` left the tree with it.) Held as the neutral protocol so a
    /// slot never names a radio.
    let channel: any MeshPeerChannel
    public let coordinator: ProximityCoordinator
    public var kind: SlotKind
    public var fingerprint: String?
    // Handshake-verified Ed25519 key used for key-based block operations.
    var verifiedSigningPublicKey: Data? = nil
    // Handshake-verified X25519 key agreement public key used for group key wrapping.
    // Set from ProximityCoordinator.PeerIdentity after identity exchange, never descriptor gossip.
    var verifiedKeyAgreementPublicKey: Data?
    /// Raw capability tokens the peer advertised in its identity intro/ack (Phase 1), captured at slot
    /// commit from `ProximityCoordinator.PeerIdentity`. `nil` = a legacy peer whose intro predates
    /// capability advertisement (treated as photos-only). Lets a room broadcast (e.g. temp messages)
    /// skip slots whose peer can't use the payload, without re-plumbing the PeerIdentity to the sender.
    var peerCapabilities: [String]? = nil
    var joinedEpoch: Int = 0
    var distanceSamples: [MeshDistanceSample] = []
    var stableDistanceMeters: Double?
    var isOverflowCandidate = false
    /// Where `MeshNetworkManager.reseatReturningMembers()` has got to with this slot's gated peer
    /// (2026-09-22). Per slot, so it dies with the slot and a peer that re-dials is judged afresh.
    var returningMemberReseat: MeshReturningMemberReseat = .open

    /// Phase 1 capability gate for room broadcasts, mirroring `ProximityCoordinator.PeerIdentity.supports`:
    /// a legacy peer with no advertised capabilities is photos-only.
    func supports(_ capability: ProximityCapability) -> Bool {
        guard let peerCapabilities else { return capability == .photos }
        return peerCapabilities.contains(capability.rawValue)
    }
}

/// In-memory symmetric group key for the current mesh session, tagged with its rotation epoch.
///
/// Distributed pairwise-wrapped by the elected coordinator (`encryptGroupKey`) and rotated every
/// 15 minutes; used for closed-mode photo/metadata AES-GCM. Never written to disk or keychain;
/// lost on app termination or mesh leave.
///
/// ## "Never persisted" is now load-bearing, not incidental (plan §8.1, §17.3)
///
/// Until P3 nothing in this module was persisted, so this sentence cost nothing. P3 added
/// ``MeshSessionContext`` — a sealed, on-disk record of a session's membership — and this key is
/// **deliberately excluded from it**. The exclusion is safe because content does not depend on the
/// control key (design invariant 3): after a process death the session resumes by reconnecting and
/// performing a fresh membership-driven rotation, so persisting the key would buy nothing and
/// would put a live group secret in a file whose whole justification is that it holds only signed,
/// already-public membership records.
///
/// Concretely: do not add `Codable` here, do not add a field for it to ``MeshSessionContext``, and
/// do not cache it in the keychain "just for resume". `MeshSessionStoreTests` pins the absence.
///
/// The same guard extends to ``MeshEpochKeyring``, which holds this key and up to three
/// predecessors: the keyring is memory-only too, and what `MeshSessionContext.epochHeads` persists
/// is ``MeshEpochRef`` values — the *names* of epochs, which are already public — never their keys.
public struct MeshGroupKey {
    public let epoch: Int
    public let keyBytes: Data   // 32 bytes
    public let activeSince: Date

    public init(epoch: Int, keyBytes: Data, activeSince: Date) {
        self.epoch = epoch
        self.keyBytes = keyBytes
        self.activeSince = activeSince
    }
}

/// One timestamped UWB distance reading for a slot.
///
/// ``MeshNetworkManager`` keeps a 10-second rolling window of these per slot to compute the
/// stable distance that drives slot ranking and overflow eviction.
struct MeshDistanceSample: Equatable {
    let recordedAt: Date
    let meters: Double
}

/// A handshake-committed participant of the current proximity session, retained for the
/// post-session keep-as-friend prompt (Phase 2, Docs/Proximity-Mesh-Redesign-2026-07-10.md).
/// Deliberately NOT Codable: this is memory-only key material — never persisted, never synced,
/// never part of a snapshot. Entries survive slot teardown (the review UI fires after
/// `leaveSession` clears slots, and the non-initiating side of a 2-person session loses its slot
/// before its review fires) and reset only when the next session begins or the UI consumes them.
public nonisolated struct MeshSessionRosterEntry: Identifiable, Equatable, Sendable {
    /// Stable per-peer identity within the session; the roster dedupes on it.
    public var id: String { fingerprint }
    /// Last write wins across re-commits within a session.
    public internal(set) var displayName: String
    public let fingerprint: String
    public let signingPublicKey: Data
    public let keyAgreementPublicKey: Data

    public init(
        displayName: String,
        fingerprint: String,
        signingPublicKey: Data,
        keyAgreementPublicKey: Data
    ) {
        self.displayName = displayName
        self.fingerprint = fingerprint
        self.signingPublicKey = signingPublicKey
        self.keyAgreementPublicKey = keyAgreementPublicKey
    }
}

/// A promoted, unconsumed session-end review (Phase 2, "Session-end review is model-state, not
/// view-events" — Docs/Proximity-Mesh-Redesign-2026-07-10.md): the ended session's keep-as-friend
/// candidates **and the photos the user has not yet chosen between**.
///
/// The manager moves the live `sessionRoster` AND the live `sessionPhotos` into one of these at the
/// session-end moment (`MeshNetworkManager.isSessionLive` going false — every ending, including
/// this device being the last member left when the others end the mesh); views present off this
/// observable state instead of `isInSession` view-events (the Social-tab layout swap destroys the
/// presenting view in the same transaction as the `isInSession` flip).
///
/// **Nothing in `photos` is on the friend wall** (2026-09-30, the owner's rule: "None of the photos
/// should be saved ... until this selection has been made"). Every session photo, taken here or
/// received from a peer, is HELD in the sealed pending corpus (`PendingSessionPhotoStore`, its own
/// device-bound key, excluded from backup) from the moment it exists; `photos` and `sessionPhotos`
/// are two memory projections of that corpus's index, metadata only. A photo reaches the wall only
/// through the person's answer (`MeshNetworkManager.finishReviewedPhotos(_:keeping:in:)` here,
/// `finishSessionPhotos(keeping:of:)` in the camera), and an unkept one is deleted for good and
/// tombstoned by its origin and item id so the mesh cannot deliver it again.
///
/// Not Codable, and it needs no persistence of its own: the pending index IS the durable truth, and
/// a manager built after a process kill rebuilds a photos-only batch of this type from it (every
/// held photo is awaiting by definition at launch — no session is live until a commit). The
/// CANDIDATES are memory-only key material like the roster entries they are, so a kill loses the
/// keep-as-friend offer (Q5) and never the photo choice. It survives `startJoin` / `startNewMesh`
/// so an unreviewed batch from the previous session re-presents (merged) after the next teardown.
public nonisolated struct MeshFriendReviewBatch: Identifiable, Equatable, Sendable {
    public let id: UUID
    public internal(set) var entries: [MeshSessionRosterEntry]
    /// The ended session's photos still awaiting the user's keep/discard choice, newest first,
    /// metadata-only, each id the photo's LOCAL id in the pending corpus. None is on the friend wall:
    /// the review is the admission, never a prune.
    public internal(set) var photos: [FriendPhotoPayload]

    public init(id: UUID = UUID(), entries: [MeshSessionRosterEntry], photos: [FriendPhotoPayload] = []) {
        self.id = id
        self.entries = entries
        self.photos = photos
    }

    /// Whether nothing is left for the user to answer — no candidate and no photo.
    public var isEmpty: Bool { entries.isEmpty && photos.isEmpty }
}

/// Why a session-photo answer could not be applied in full (the 2026-09-30 held-photo review).
///
/// A frozen reason, never copy: the review surfaces fork it into their own localized lines.
///
/// Concurrency: an immutable `Sendable` value.
public nonisolated enum SessionPhotoAnswerFailure: Equatable, Sendable {
    /// Nothing could be applied: the device is locked or the app backgrounded, a duress session is
    /// in force (the answer reads plaintext, so it runs only where the routed gate is open), or the
    /// pending index cannot be read right now. Also a KEEP whose held bytes could not be read right
    /// now (no key, or a file read that failed): those photos stay held for a retry, while the rest
    /// of the answer applied.
    case unavailable
    /// The friend wall's index cannot be read, so no photo can be KEPT; the discards were applied,
    /// because they need only the pending index.
    case keepUnavailable
    /// The wall did not take some kept photos (a disk or key failure). They stay held, untouched,
    /// and nothing of theirs was swept.
    case wallWriteFailed
}

/// What one answer to a session-photo review actually did, photo by photo (local ids).
///
/// The hosts read it rather than assume: the camera-roll export runs over ``keptOnWall`` ONLY
/// (those are the photos whose sealed bytes landed on the wall and whose index names them), and a
/// non-empty ``notApplied`` keeps the review up with an inline failure instead of hiding it. Ids the
/// answer was given that are no longer held (already answered elsewhere) appear in no set: the first
/// answer wins.
///
/// Concurrency: an immutable `Sendable` value.
public nonisolated struct SessionPhotoAnswer: Equatable, Sendable {
    /// Kept and landed on the wall — the ONLY ids a Photos-library export may use.
    public let keptOnWall: Set<UUID>
    /// Not kept: deleted for good and tombstoned.
    public let discarded: Set<UUID>
    /// Kept, but their held bytes could not be opened: removed like a discard, and the review says so.
    public let unreadable: Set<UUID>
    /// Still held and still offered, untouched by this answer.
    public let notApplied: Set<UUID>
    /// Why ``notApplied`` is not empty (or why the keeps were refused), when it is.
    public let failure: SessionPhotoAnswerFailure?

    /// An answer that did nothing and owes nothing — nothing it named was still held.
    public static let nothing = SessionPhotoAnswer(
        keptOnWall: [], discarded: [], unreadable: [], notApplied: [], failure: nil
    )

    /// Creates an answer report; `MeshNetworkManager` is the only producer outside tests.
    public init(
        keptOnWall: Set<UUID>,
        discarded: Set<UUID>,
        unreadable: Set<UUID>,
        notApplied: Set<UUID>,
        failure: SessionPhotoAnswerFailure?
    ) {
        self.keptOnWall = keptOnWall
        self.discarded = discarded
        self.unreadable = unreadable
        self.notApplied = notApplied
        self.failure = failure
    }
}

/// Display row for one member of the current session (mesh members or committed pairwise slots),
/// including the local device.
///
/// Derived on demand by `MeshNetworkManager.sessionParticipants` for the session UI and photo
/// metadata; identity is the fingerprint. Not persisted.
public struct MeshSessionParticipant: Identifiable, Equatable {
    public var id: String { fingerprint }

    public let fingerprint: String
    public let displayName: String
    public let isLocal: Bool

    public init(fingerprint: String, displayName: String, isLocal: Bool) {
        self.fingerprint = fingerprint
        self.displayName = displayName
        self.isLocal = isLocal
    }
}
