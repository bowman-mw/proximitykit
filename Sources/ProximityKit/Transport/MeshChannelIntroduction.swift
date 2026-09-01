import Foundation
import FernletCrypto

// MARK: - MeshChannelRole

/// Which end of one QUIC tunnel this side is.
///
/// The transcript both peers sign lists the initiator's key and nonce before the responder's, so a
/// signature is only reproducible when both sides agree on who dialed whom. The role is decided by
/// the transport, never negotiated: the side that opened the connection is the initiator.
nonisolated enum MeshChannelRole: Equatable, Sendable {
    /// This side dialed and opened the control stream.
    case initiator
    /// This side accepted the connection and served the control stream.
    case responder
}

// MARK: - MeshChannelIntroductionFormat

/// The frozen shape of the signed channel introduction: version, field widths, and the nonce
/// source.
///
/// Every constant here is wire format, never display text, and every one is a *bound* on untrusted
/// input as much as a description of honest output — an inbound hello whose fields do not have
/// exactly these widths is refused before a signature is verified, so a peer cannot choose how much
/// this side parses.
nonisolated enum MeshChannelIntroductionFormat {

    /// The protocol version carried in the hello and bound into the transcript. Both sides must
    /// present the same one; there is no negotiation and no fallback.
    static let protocolVersion = 1

    /// Bytes of fresh randomness each side contributes. Sixteen matches the DEBUG probe and the QR
    /// ceremony's challenge nonce — well past what a birthday bound over one session needs.
    static let nonceByteCount = 16

    /// Ed25519 public-key length. A hello carrying any other length is malformed by definition.
    static let signingKeyByteCount = 32

    /// Ed25519 signature length.
    static let signatureByteCount = 64

    /// Length of the TLS-exporter channel binding, which is a SHA-256 digest.
    static let channelBindingByteCount = 32

    /// Cap on the epoch reference's UTF-8 length. Today's value is a short decimal counter and P3's
    /// is a counter plus a UUID plus a 16-character fingerprint, so 96 clears both with room.
    static let maxEpochRefLength = 96

    /// Cap on the session id's UTF-8 length. The same bound ``MeshLinkAdvertisement`` puts on the
    /// `sid` it publishes, deliberately: the value in the hello and the value in the TXT record are
    /// the same string, and a hello may not smuggle a longer one.
    static let maxSessionIDLength = MeshLinkAdvertisement.maxFieldValueLength

    /// Largest introduction frame this side will read off the control stream before the tunnel is
    /// authenticated. A hello is a few hundred bytes; the cap exists because an unauthenticated peer
    /// is the one choosing how many bytes to claim.
    static let maxFrameByteCount = 4_096

    /// A fresh nonce for one introduction.
    ///
    /// `UInt8.random` draws from `SystemRandomNumberGenerator`, the platform CSPRNG — the same
    /// source `MeshNetworkManager` uses for group keys, and without the pointer seam or the
    /// discarded `OSStatus` the `SecRandomCopyBytes` spelling would bring (Power of 10 rules 7, 9).
    static func randomNonce() -> Data {
        Data((0..<nonceByteCount).map { _ in UInt8.random(in: .min ... .max) })
    }
}

// MARK: - MeshChannelHello

/// The unsigned first frame of the introduction: who this side claims to be, and the randomness it
/// contributes to the transcript.
///
/// **Nothing here is believed on its own.** The hello exists so both ends can build the *same*
/// transcript; every claim in it is either checked against this side's own view (`protocolVersion`,
/// `meshID`, `epochRef`) or bound into the bytes the peer must produce a valid Ed25519 signature
/// over (`signingPublicKey`, `nonce`). The one exception is ``sessionID``, which is called out on
/// its own property.
///
/// Every field is a frozen wire token or a fixed-width value. None of them is ever localized.
nonisolated struct MeshChannelHello: Codable, Equatable, Sendable {

    /// The introduction protocol version this side speaks.
    let protocolVersion: Int
    /// The mesh this side believes the tunnel belongs to.
    let meshID: UUID
    /// This side's current membership-epoch reference, or the empty string when it has none yet —
    /// see ``MeshChannelIntroductionExchange`` for what "no epoch" means and why it is allowed.
    let epochRef: String
    /// This side's long-term Ed25519 signing public key: the identity the roster is checked against.
    let signingPublicKey: Data
    /// Fresh randomness for this introduction, bound into the transcript.
    let nonce: Data

    /// The per-launch random `sid` this side also publishes in its Bonjour TXT record.
    ///
    /// **Not covered by the introduction signature** (plan §7.2 fixes the transcript's fields and
    /// this is not one of them). It is a dial-preference hint only: it lets an inbound tunnel be
    /// matched to the browsed advertisement it came from, so duplicate-tunnel suppression can rank
    /// the pair instead of falling through to ``MeshDialPreference/unranked``. A verified roster
    /// member that lied about it could at worst cost itself a link — refusing on both sides is the
    /// unrecoverable direction, and admitting is what an unranked pair already does.
    let sessionID: String

    /// Whether every field has the exact width the format fixes. Checked before anything else, on
    /// untrusted bytes, so no later step has to reason about a short key or an unbounded string.
    var isWellFormed: Bool {
        signingPublicKey.count == MeshChannelIntroductionFormat.signingKeyByteCount
            && nonce.count == MeshChannelIntroductionFormat.nonceByteCount
            && epochRef.utf8.count <= MeshChannelIntroductionFormat.maxEpochRefLength
            && sessionID.utf8.count <= MeshChannelIntroductionFormat.maxSessionIDLength
    }
}

// MARK: - MeshChannelIntroduction

/// The signed second frame: this side's Ed25519 signature over the joint transcript, plus the
/// channel binding it signed under.
///
/// It deliberately carries **no copy of the transcript**. Every other field the transcript contains
/// already crossed in the hellos, and a second place to state them is a second place to lie —
/// receiving them again would only create the possibility that the two disagree. The channel
/// binding is the one value that cannot be exchanged (each side derives it from its own end of the
/// TLS connection), so it travels here to be compared, and a mismatch is named rather than reported
/// as an invalid signature.
nonisolated struct MeshChannelIntroduction: Codable, Equatable, Sendable {

    /// SHA-256 of this side's TLS exporter secret for this connection.
    let channelBindingHash: Data
    /// Ed25519 signature over ``MeshChannelIntroductionTranscript``'s canonical bytes.
    let signature: Data

    /// Whether both fields have the exact widths the format fixes.
    var isWellFormed: Bool {
        channelBindingHash.count == MeshChannelIntroductionFormat.channelBindingByteCount
            && signature.count == MeshChannelIntroductionFormat.signatureByteCount
    }
}

// MARK: - MeshChannelIntroductionTranscript

/// The bytes both peers sign, in plan §7.2's order: purpose ‖ version ‖ meshID ‖ epochRef ‖ both
/// signing public keys ‖ both nonces ‖ TLS-exporter hash.
///
/// **Derived on both sides, never received.** It is assembled from the two hellos and this side's
/// own channel binding, so there is no wire representation of it to tamper with; a peer that
/// disagrees about any field simply produces a signature that does not verify.
///
/// Serialized by `canonicalBytes(for:)` in `CanonicalSignatureSerializer.swift` — the same
/// length-prefixed `CanonicalByteWriter` format every other production signature uses, which is why
/// `FernletCryptoPurpose.Signature.meshChannelIntroductionV1` declares `.lengthPrefixed` framing.
/// That pairing is proven by `CryptographicPurposeBoundaryTests`; changing one without the other is
/// what broke in commit `91c3956`.
nonisolated struct MeshChannelIntroductionTranscript: Equatable, Sendable {
    /// The agreed protocol version.
    let protocolVersion: Int
    /// The mesh both sides agree the tunnel belongs to.
    let meshID: UUID
    /// The agreed membership-epoch reference.
    let epochRef: String
    /// The dialing side's signing public key.
    let initiatorSigningPublicKey: Data
    /// The accepting side's signing public key.
    let responderSigningPublicKey: Data
    /// The dialing side's nonce.
    let initiatorNonce: Data
    /// The accepting side's nonce.
    let responderNonce: Data
    /// SHA-256 of the TLS exporter secret — what binds this signature to this one live tunnel.
    let channelBindingHash: Data
}

// MARK: - MeshIntroductionRejection

/// Why one signed channel introduction was refused.
///
/// Every refusal names itself rather than collapsing into `false`, for the same reason
/// ``MeshLinkAdmission`` does: a roster-absent peer, a peer in another mesh and a tampered channel
/// are three completely different situations, and a single boolean is exactly how they become one
/// indistinguishable "it didn't connect" in a bug report.
///
/// **Every case is a rejection, not a degraded accept.** The transport tears the tunnel down on any
/// of them; nothing here means "continue with less".
///
/// Not an `Error` and not `LocalizedError`: ``diagnosticDescription`` is frozen English read by a
/// developer in a log, never user copy, so it stays out of the localization catalogs by
/// construction.
nonisolated enum MeshIntroductionRejection: Equatable, Sendable {
    /// A field in the peer's hello does not have the width the format fixes.
    case malformedHello
    /// The peer speaks a different introduction protocol version.
    case unsupportedProtocolVersion
    /// The peer named a different mesh, or one this side has ended.
    case foreignMesh
    /// Both sides have an epoch reference and they are not the same one.
    case divergentEpoch
    /// The peer presented this device's own signing key.
    case selfIntroduction
    /// The peer's nonce was already used in this session, or reflects this side's own.
    case replayedNonce
    /// The peer's signing key is in neither the roster nor the trust vault.
    case unknownIdentity
    /// The peer's signing key is departed, removed, revoked, or blocked.
    case barredMember
    /// A field in the peer's signed introduction does not have the width the format fixes.
    case malformedIntroduction
    /// The peer derived a different TLS exporter secret — the two ends are not on one tunnel.
    case channelBindingMismatch
    /// The signature does not verify over the transcript this side derived.
    case signatureInvalid
    /// The introduction was reviewed before the peer's hello was accepted — a caller-order fault,
    /// never something a peer can cause.
    case missingPeerHello

    /// Frozen English for the diagnostic surface. Never shown as user copy.
    var diagnosticDescription: String {
        switch self {
        case .malformedHello: return "The peer's channel hello was malformed."
        case .unsupportedProtocolVersion: return "The peer speaks another channel-introduction version."
        case .foreignMesh: return "The peer named a different mesh."
        case .divergentEpoch: return "The peer is on a different membership epoch."
        case .selfIntroduction: return "The peer presented this device's own signing key."
        case .replayedNonce: return "The peer replayed a channel-introduction nonce."
        case .unknownIdentity: return "The peer is not a member of this mesh."
        case .barredMember: return "The peer has departed, been removed, or been blocked."
        case .malformedIntroduction: return "The peer's signed channel introduction was malformed."
        case .channelBindingMismatch: return "The peer derived a different TLS channel binding."
        case .signatureInvalid: return "The peer's channel-introduction signature did not verify."
        case .missingPeerHello: return "A channel introduction was reviewed before any peer hello."
        }
    }
}

// MARK: - MeshRosterVerdict

/// What the current roster says about one signing key.
nonisolated enum MeshRosterVerdict: Equatable, Sendable {
    /// A current member: admitted, and neither departed nor removed.
    case member
    /// Nobody this mesh knows.
    case stranger
    /// Known and explicitly excluded — departed, removed, revoked, or blocked.
    case barred
}

// MARK: - MeshIntroductionRoster

/// The set of signing keys one introduction is judged against: who is in, and who is explicitly out.
///
/// A value type, so the transport's authentication decision can be enumerated at tier 1 with no
/// mesh manager, no trust vault and no store in sight — the same reason ``MeshLinkTable`` holds the
/// dial decisions. The layer above the transport rebuilds it whenever membership changes; plan §8.1
/// derives it as `admitted − departed − removed`.
///
/// **Barred wins over member** (fail closed). A key on both lists is barred: a removal that raced an
/// admission must not be resolved in the removed member's favour, and the group key rotation that
/// follows a removal (plan §8.3) assumes the transport already stopped letting them in.
///
/// **Bounded by construction** (Power of 10 rule 3): at most ``maxMembers`` members — the roster cap
/// — and ``maxBarred`` barred keys, matching the record caps plan §8.1 puts on the session context.
nonisolated struct MeshIntroductionRoster: Equatable, Sendable {

    /// Members retained. The roster cap (plan §9), so the transport can never be asked about a
    /// ninth member of an eight-member mesh.
    static let maxMembers = MeshLinkTable.maxConcurrentLinks

    /// Barred keys retained — the departure/removal record cap from plan §8.1.
    static let maxBarred = 16

    private let members: Set<Data>
    private let barred: Set<Data>

    /// A roster with nobody in it. Every introduction against it is ``MeshRosterVerdict/stranger``,
    /// which is the correct answer for a transport that has not been told who the members are.
    static let empty = MeshIntroductionRoster(members: [], barred: [])

    /// Builds a roster, dropping anything past the caps rather than growing without bound.
    init(members: [Data], barred: [Data] = []) {
        self.members = Set(members.prefix(Self.maxMembers))
        self.barred = Set(barred.prefix(Self.maxBarred))
    }

    /// What this roster says about one signing key.
    func verdict(for signingPublicKey: Data) -> MeshRosterVerdict {
        if barred.contains(signingPublicKey) { return .barred }
        return members.contains(signingPublicKey) ? .member : .stranger
    }

    /// How many members the roster holds — the read a test uses to prove the cap bit.
    var memberCount: Int { members.count }

    /// How many barred keys the roster holds.
    var barredCount: Int { barred.count }
}

// MARK: - MeshIntroductionNonceCache

/// The bounded per-session cache that makes a replayed introduction nonce a rejection.
///
/// Session-scoped and memory-only, like every other map the QUIC radio holds: it dies with
/// ``NetworkMeshSession/stop()``, so it owes no row on the wipe ledger.
///
/// **What the bound costs, stated plainly.** Oldest-first eviction means a nonce could be reused
/// after ``maxTrackedNonces`` distinct introductions in one session. That is acceptable because the
/// nonce is not what makes a replay useless — the TLS-exporter binding is. A transcript signed on
/// one tunnel cannot verify on another, because the exporter secret differs, so replay across
/// connections is already impossible; this cache closes the narrower case of the *same* peer
/// re-sending an introduction it already sent on a live channel.
nonisolated struct MeshIntroductionNonceCache {

    /// Nonces retained. Eight peers × eight reconnects — an order of magnitude past a real session
    /// while the map stays obviously bounded.
    static let maxTrackedNonces = 64

    private var seen: Set<Data> = []
    private var order: [Data] = []

    /// An empty cache. A session owns exactly one, shared by every peer it introduces itself to.
    init() {}

    /// Records a nonce, returning `false` when it has already been seen in this session.
    mutating func admit(_ nonce: Data) -> Bool {
        guard !seen.contains(nonce) else { return false }
        evictOldestIfFull()
        seen.insert(nonce)
        order.append(nonce)
        return true
    }

    /// How many nonces the cache holds.
    var trackedCount: Int { seen.count }

    /// Drops every nonce. Called from teardown with everything else the radio was holding.
    mutating func removeAll() {
        seen.removeAll()
        order.removeAll()
    }

    private mutating func evictOldestIfFull() {
        guard order.count >= Self.maxTrackedNonces, let oldest = order.first else { return }
        order.removeFirst()
        seen.remove(oldest)
    }
}

// MARK: - MeshVerifiedPeer

/// A peer that completed the signed channel introduction: the only thing the transport will let
/// past its accept gate.
///
/// It exists so the accept path is *unconstructable* without a verified identity. Nothing on the
/// rejection side of ``MeshChannelIntroductionOutcome`` carries one, so a failed introduction has
/// no value to hand onward — which is what stops an unauthenticated peer's `sid` from reaching
/// duplicate-tunnel suppression, and its handle from reaching an owner.
nonisolated struct MeshVerifiedPeer: Equatable, Sendable {
    /// The Ed25519 signing key whose signature verified over the transcript.
    let signingPublicKey: Data
    /// The canonical 16-character fingerprint of that key.
    let fingerprint: String
    /// The peer's advertised `sid`, now attributable to a verified identity. See
    /// ``MeshChannelHello/sessionID`` for exactly how far it is trusted.
    let sessionID: String
}

// MARK: - MeshChannelIntroductionOutcome

/// The result of reviewing a peer's signed channel introduction.
nonisolated enum MeshChannelIntroductionOutcome: Equatable, Sendable {
    /// The peer proved its identity over this tunnel.
    case accepted(MeshVerifiedPeer)
    /// The introduction failed, and the tunnel must be torn down.
    case rejected(MeshIntroductionRejection)

    /// The verified peer, or nil. Deliberately the only way to read one out of an outcome, so
    /// "did this succeed" and "who is it" are one question rather than two that can disagree.
    var verifiedPeer: MeshVerifiedPeer? {
        guard case .accepted(let peer) = self else { return nil }
        return peer
    }
}

// MARK: - MeshChannelIntroductionExchange

/// One tunnel's signed channel introduction, driven a step at a time by the transport (plan §7.2).
///
/// The whole authentication decision, with no framework, no clock and no I/O inside it — the same
/// factoring ``MeshLinkTable`` gets, and for the same reason: this is the code that decides whether
/// a stranger reaches the mesh, so it must be enumerable at tier 1 rather than only reachable with
/// two radios in a room.
///
/// ## The three steps
///
/// 1. ``receive(_:roster:nonces:)`` — review the peer's hello. Refusing here means the exchange
///    keeps **nothing**: no peer hello is recorded, so ``bind(channelBindingHash:)`` returns nil and
///    there is no transcript and no identity to leak onward.
/// 2. ``bind(channelBindingHash:)`` — derive the transcript once this side knows its TLS exporter
///    hash, and hand back the canonical bytes to sign.
/// 3. ``review(_:)`` — check the peer's signature over that exact transcript.
///
/// ## The two agreement rules
///
/// **meshID must be equal.** A peer naming another mesh is refused (plan §7.2's "foreign meshID").
///
/// **epochRef must converge**: equal, or one side has none (the empty string). "None" is what a
/// peer being admitted has — it holds no group key yet — so requiring equality outright would make
/// admission impossible. Two peers that each hold a *different* epoch are on diverged branches,
/// which P2 has no machinery to merge, so refusing is the honest answer until plan §8.4's merge
/// lands and relaxes this to "any epoch; the merge mints max + 1".
nonisolated struct MeshChannelIntroductionExchange {

    /// Which end of the tunnel this side is.
    let role: MeshChannelRole
    /// The hello this side sent.
    let localHello: MeshChannelHello

    private var peerHello: MeshChannelHello?
    private var transcript: MeshChannelIntroductionTranscript?

    /// Starts an exchange for one tunnel.
    init(role: MeshChannelRole, localHello: MeshChannelHello) {
        self.role = role
        self.localHello = localHello
    }

    /// Step 1: review the peer's hello, recording it only if every check passes.
    ///
    /// - Returns: nil when the hello is acceptable, otherwise the named rejection.
    mutating func receive(
        _ hello: MeshChannelHello,
        roster: MeshIntroductionRoster,
        nonces: inout MeshIntroductionNonceCache
    ) -> MeshIntroductionRejection? {
        guard hello.isWellFormed else { return .malformedHello }
        guard hello.protocolVersion == localHello.protocolVersion,
              hello.protocolVersion == MeshChannelIntroductionFormat.protocolVersion else {
            return .unsupportedProtocolVersion
        }
        guard hello.meshID == localHello.meshID else { return .foreignMesh }
        guard Self.epochsConverge(localHello.epochRef, hello.epochRef) else { return .divergentEpoch }
        guard hello.signingPublicKey != localHello.signingPublicKey else { return .selfIntroduction }
        guard hello.nonce != localHello.nonce, nonces.admit(hello.nonce) else { return .replayedNonce }
        switch roster.verdict(for: hello.signingPublicKey) {
        case .barred: return .barredMember
        case .stranger: return .unknownIdentity
        case .member: break
        }
        peerHello = hello
        return nil
    }

    /// Step 2: derive the transcript and return the canonical bytes this side must sign.
    ///
    /// - Returns: nil when no peer hello has been accepted, or when the binding is the wrong width —
    ///   both of which mean this side must not sign anything.
    mutating func bind(channelBindingHash: Data) -> Data? {
        guard let peerHello,
              channelBindingHash.count == MeshChannelIntroductionFormat.channelBindingByteCount else {
            return nil
        }
        let initiator = role == .initiator ? localHello : peerHello
        let responder = role == .initiator ? peerHello : localHello
        let built = MeshChannelIntroductionTranscript(
            protocolVersion: initiator.protocolVersion,
            meshID: initiator.meshID,
            epochRef: Self.agreedEpoch(initiator.epochRef, responder.epochRef),
            initiatorSigningPublicKey: initiator.signingPublicKey,
            responderSigningPublicKey: responder.signingPublicKey,
            initiatorNonce: initiator.nonce,
            responderNonce: responder.nonce,
            channelBindingHash: channelBindingHash
        )
        transcript = built
        return canonicalBytes(for: built)
    }

    /// Step 3: review the peer's signed introduction against the derived transcript.
    func review(_ introduction: MeshChannelIntroduction) -> MeshChannelIntroductionOutcome {
        guard let peerHello, let transcript else { return .rejected(.missingPeerHello) }
        guard introduction.isWellFormed else { return .rejected(.malformedIntroduction) }
        guard introduction.channelBindingHash == transcript.channelBindingHash else {
            return .rejected(.channelBindingMismatch)
        }
        guard IdentityService.verify(
            introduction.signature,
            of: canonicalBytes(for: transcript),
            by: peerHello.signingPublicKey,
            purpose: FernletCryptoPurpose.Signature.meshChannelIntroductionV1
        ) else {
            return .rejected(.signatureInvalid)
        }
        return .accepted(MeshVerifiedPeer(
            signingPublicKey: peerHello.signingPublicKey,
            fingerprint: IdentityService.fingerprint(of: peerHello.signingPublicKey),
            sessionID: peerHello.sessionID
        ))
    }

    /// The transcript this exchange derived, or nil before ``bind(channelBindingHash:)`` has been
    /// called with an accepted peer hello. The read that lets a test prove a refused hello left
    /// nothing behind.
    var derivedTranscript: MeshChannelIntroductionTranscript? { transcript }

    /// Whether two epoch references may share a tunnel: equal, or one side has none yet.
    static func epochsConverge(_ local: String, _ peer: String) -> Bool {
        local.isEmpty || peer.isEmpty || local == peer
    }

    /// The epoch reference the transcript carries: the initiator's, unless it has none.
    /// Deterministic from values both sides hold, so both derive the same bytes.
    static func agreedEpoch(_ initiator: String, _ responder: String) -> String {
        initiator.isEmpty ? responder : initiator
    }
}

// MARK: - MeshIntroductionAuthority

/// What the layer above the transport must answer before a QUIC tunnel can authenticate a peer.
///
/// The transport owns no identity and no membership: it does not know which mesh it is in, who is
/// on the roster, or how to reach the signing key. This is that seam, kept to five members so the
/// wiring in P2 item 8 is `MeshNetworkManager` itself, reading `IdentityService`, rather
/// than a second copy of either.
///
/// **Fail closed.** ``NetworkMeshSession`` with no authority refuses every tunnel: a transport that
/// cannot authenticate must not admit, and "admit unauthenticated until the manager is wired" is
/// exactly the degraded accept plan §7.2 forbids.
@MainActor
protocol MeshIntroductionAuthority: AnyObject {

    /// This device's long-term Ed25519 signing public key.
    var localSigningPublicKey: Data { get }

    /// The mesh the transport's tunnels belong to.
    var meshID: UUID { get }

    /// This device's current membership-epoch reference, or the empty string when it holds none —
    /// see ``MeshChannelIntroductionExchange`` for what the empty value means.
    var epochRef: String { get }

    /// Who may connect right now, derived fresh so a removal takes effect on the next introduction.
    var roster: MeshIntroductionRoster { get }

    /// Signs the introduction transcript with the device's identity key under
    /// `FernletCryptoPurpose.Signature.meshChannelIntroductionV1`.
    func signChannelIntroduction(_ transcript: Data) throws -> Data
}
