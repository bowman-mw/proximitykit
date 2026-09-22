import Combine
import Foundation

// MARK: - MeshPeerChannel

/// A per-peer channel a shared mesh radio hands to its owner.
///
/// A ``PeerTransport`` that also knows which peer it carries and can be told to publish
/// `.connected` / `.disconnected`. The protocol outlived the two-radio period it was introduced
/// for (P2): it named the shape the retired MultipeerConnectivity radio's per-peer adapter and
/// `NetworkPeerChannel` (QUIC) shared, so `MeshNetworkManager` could hold a slot's channel without
/// knowing which radio minted it. The MC adapter left the tree in the deletion round (2026-09-22);
/// the protocol still earns its place — `DetachedPeerChannel` is the second conformer, and the
/// manager's test seams are built on it.
///
/// `notifyConnected()` is the owner's call, never the radio's: the owner creates the slot's
/// coordinator and awaits its `begin()` first, because publishing `.connected` before that returns
/// is what put the handshake into the wrong branch. Both conformers document the same contract.
@MainActor
protocol MeshPeerChannel: PeerTransport {

    /// The peer this channel carries.
    var peer: PeerHandle { get }

    /// Publishes `.connected` for ``peer``.
    func notifyConnected()

    /// Publishes `.disconnected` with a diagnostic reason.
    func notifyDisconnected(reason: String)
}

extension NetworkPeerChannel: MeshPeerChannel {}

// MARK: - DetachedPeerChannel

/// A channel with no radio behind it: it publishes state locally and refuses every send.
///
/// The manager's `internal` test seams (`addSlotForTesting`, `makeRetainedSlotCoordinatorForTesting`)
/// need a slot channel, and a unit test has no live radio to put behind one. Before P1 they built a
/// channel over a never-started radio, whose `send` threw ``PeerTransportError/unexpectedState``
/// for want of a live session — this is that same behaviour, said out loud, and it costs the
/// manager one fewer reason to name a specific radio.
@MainActor
final class DetachedPeerChannel: MeshPeerChannel {

    let peer: PeerHandle

    private let stateSubject = CurrentValueSubject<PeerTransportState, Never>(.idle)
    private let inboundSubject = PassthroughSubject<InboundPeerFrame, Never>()

    var state: AnyPublisher<PeerTransportState, Never> { stateSubject.eraseToAnyPublisher() }
    var inbound: AnyPublisher<InboundPeerFrame, Never> { inboundSubject.eraseToAnyPublisher() }
    var connectedPeers: [PeerHandle] { [] }

    init(peer: PeerHandle) {
        self.peer = peer
    }

    // Discovery belongs to a shared session this channel does not have.
    func startAdvertising(serviceType: String, discoveryInfo: [String: String]) async throws {}
    func startBrowsing(serviceType: String) async throws {}
    func invite(_ peer: PeerHandle) async throws {}
    func accept(_ invite: PeerPendingInvite) async throws {}

    /// Always throws: there is no radio to carry the bytes, and a channel that silently swallowed
    /// them would let a test pass over a send that never happened.
    func send(_ data: Data, to peer: PeerHandle, mode: PeerDeliveryMode) async throws {
        throw PeerTransportError.unexpectedState
    }

    func disconnect() async {
        stateSubject.send(.idle)
    }

    func notifyConnected() {
        stateSubject.send(.connected(peer))
    }

    func notifyDisconnected(reason: String = "Peer disconnected") {
        stateSubject.send(.disconnected(reason: reason))
    }
}

// MARK: - MeshTransportHandlers

/// Everything a mesh radio calls back into its owner for, in one value.
///
/// One struct rather than five settable properties on ``MeshTransportSession``: a radio stores its
/// hooks under its own names and types (the QUIC session's channel hook is typed to
/// `NetworkPeerChannel`; the retired MC session's was typed to its own adapter), so a settable
/// protocol property would need a getter that could not honestly answer. ``MeshTransportSession/wire(_:)``
/// takes the whole set instead, and each conformer forwards it to whatever it actually keeps.
///
/// Every closure here is expected to capture its owner weakly; a radio holds this struct for its
/// lifetime.
struct MeshTransportHandlers {

    /// A peer appeared in discovery. The owner decides whether to dial it.
    var onPeerDiscovered: ((PeerHandle) -> Void)?

    /// A peer's channel is live and ready to be given a coordinator.
    var onChannelReady: ((any MeshPeerChannel) -> Void)?

    /// A peer's link dropped, with a diagnostic reason.
    var onPeerDisconnected: ((PeerHandle, String) -> Void)?

    /// Whether to admit an inbound connection attempt. **Fail closed**: a radio with no gate wired
    /// refuses (`?? false`), exactly as the retired MultipeerConnectivity advertiser did.
    var shouldAcceptInvitation: ((PeerHandle) -> Bool)?

    /// Discovery failed to start — a declined Local Network prompt, or a service type missing from
    /// `NSBonjourServices`. Surfaced to the user rather than searched-forever in silence.
    var onTransportError: ((String) -> Void)?
}

// MARK: - MeshSlotEvictionCause

/// Why the owner is freeing one peer's link — the one thing a radio cannot work out for itself.
///
/// Both arms look identical at the transport: the owner's slot goes away and
/// ``MeshTransportSession/disconnectPeer(_:cause:)`` ends the tunnel as a `localEviction`. They are
/// not identical to the bound that reads them. ``MeshLinkTable/maxReproposalsPerEndpoint`` is
/// deliberately never refilled because its loop is *connect → the owner refuses the seat →
/// disconnect → idle → re-offer*, and six of those is plenty. A pre-commit **timeout** produces the
/// same shape and is not that loop: it is two people who did not get their phones close enough
/// inside the pre-commit deadline, and spending a never-refilled budget on it strands a genuine
/// friend for the rest of the session on the sixth try (D-4.3 Option 1's "two bounds to name").
///
/// **That deadline is five minutes, not the 25 s / 60 s connection-phase timer.** `handleChannelReady`
/// arms `timeoutSeconds: isProximityJoin ? 25 : 60`, but `ProximityCoordinator.transitionToProximityGate`
/// cancels it the moment the identity introduction verifies and arms a five-minute proximity gate
/// in its place (`Engine/ProximityCoordinator.swift:1320`) — which is precisely the state a
/// provisionally admitted stranger sits in, so five minutes is the number this cause is about.
/// It is also why the refund is capped rather than unlimited: five minutes rate-limits an
/// all-timeout endpoint's re-offers, it does not bound them
/// (``MeshLinkTable/maxTimeoutRefundsPerEndpoint``).
///
/// Frozen automation tokens, never display text and never persisted.
nonisolated enum MeshSlotEvictionCause: Equatable, Sendable {

    /// This device decided the peer may not hold this slot — the seat gate refused it, the session
    /// was held or closed, the slot lost an overflow race, or the owner tore the session down. The
    /// re-propose budget is charged, because re-offering the same endpoint would re-run exactly
    /// this decision.
    case ownerDecision

    /// The pre-commit deadline — the five-minute proximity gate — expired with no dwell and no tap
    /// (`ProximityCoordinator.EndReason.timeout`). Nothing was refused and nothing is likely to be:
    /// the re-propose booking that produced this tunnel is given back, up to
    /// ``MeshLinkTable/maxTimeoutRefundsPerEndpoint`` times per endpoint per session.
    case preCommitTimeout
}

// MARK: - MeshTransportSession

/// The shared radio `MeshNetworkManager` drives, with no radio's name on it.
///
/// `NetworkMeshSession` is the one conformer a shipping or a test build constructs since the
/// deletion round (2026-09-22) took the MultipeerConnectivity one; the seam outlives the choice it
/// was built to make because the suite runs the manager over an in-memory fake through it.
///
/// `startRadios(discoveryInfo:)` rather than `start(discoveryInfo:)`: the retired MC session's own
/// `start(serviceType:discoveryInfo:)` defaulted its service type, so a same-named forwarder would
/// have read as direct recursion (Power of 10 rule 1) for no gain. The service type is the radio's
/// own affair — the owner never picks one.
@MainActor
protocol MeshTransportSession: AnyObject {

    /// Installs the owner's callbacks. Called once, at wiring time.
    func wire(_ handlers: MeshTransportHandlers)

    /// Hands the radio the mesh id, epoch reference, roster and signing key its peer authentication
    /// needs — on the QUIC radio the difference between admitting a verified roster member (or a
    /// provisional stranger while the join doors are open) and refusing every tunnel. (The retired
    /// MC radio ignored it by contract; it authenticated inside the coordinator's identity
    /// introduction instead.)
    func attachIntroductionAuthority(_ authority: any MeshIntroductionAuthority)

    /// Brings advertising and browsing up with the owner's discovery payload.
    func startRadios(discoveryInfo: [String: String])

    /// Tears the radio down and drops every peer-keyed record it held.
    func stop()

    /// Republishes the discovery payload.
    func updateDiscoveryInfo(_ info: [String: String])

    /// Opens a connection to a discovered peer. The inviter decision is the owner's
    /// (`MeshNetworkManager.shouldInitiateInvite`), never the radio's.
    func invite(_ peer: PeerHandle)

    /// Frees one peer's link. Best-effort on both radios — the owner's record eviction is what
    /// actually drives teardown.
    func disconnectPeer(_ peer: PeerHandle)

    /// Frees one peer's link, telling the radio **why** the owner is doing it.
    ///
    /// Default-implemented as ``disconnectPeer(_:)``, so a radio that keeps no per-endpoint budget
    /// need not know the cause exists (the retired MC radio re-invited on its own timer and had
    /// nothing to spend; a fake has nothing either). `NetworkMeshSession` overrides it, because its
    /// never-refilled re-propose budget is the one bound the distinction matters to (see
    /// ``MeshSlotEvictionCause``).
    func disconnectPeer(_ peer: PeerHandle, cause: MeshSlotEvictionCause)

    /// Stops browsing and advertising while KEEPING the session and every live connection — the
    /// radio half of ``MeshNetworkManager/holdCommittedLinks()``.
    ///
    /// Deliberately not ``stop()``: that one disconnects, drops every peer-keyed record and, on the
    /// QUIC radio, discards the TLS identity. This one only goes quiet to peers that are not
    /// already connected. Idempotent, and a no-op on a radio that never started.
    func pauseDiscovery()

    /// Reopens a paused radio, and nothing else. Idempotent, and a no-op unless
    /// ``pauseDiscovery()`` ran.
    ///
    /// It is also what ``startRadios(discoveryInfo:)`` does to a radio that is already running, so
    /// the owner's one re-arm funnel (`startSearching()`) undoes a hold without naming this verb.
    func resumeDiscovery()

    /// Waits — bounded — until every one of `peers`' links has ended, returning the moment the last
    /// one goes (2026-09-22).
    ///
    /// The nearest thing to an acknowledgement a final pair's signed termination can get without a
    /// new wire frame: a partner that verified it tears its own session down, and that ends the
    /// link here. It is not a read receipt — a local link failure ends the link too (see
    /// ``MeshRemoteCloseOutcome/closed``) — but it is what the leaver can wait on. The
    /// leaver waits for that — or for the bound — BEFORE ``stop()``, because `stop()` cancels the
    /// connection, and a frame the stack had accepted but not yet delivered went down with it: the
    /// partner never learned the mesh was over and was left holding a mesh of one.
    ///
    /// Default-implemented as an immediate ``MeshRemoteCloseOutcome/nothingToWaitFor``, so a radio
    /// with no far end — the tier-1 fake — keeps every leaving cell exactly as fast as it was.
    /// ``NetworkMeshSession`` is the one shipping override.
    ///
    /// - Parameters:
    ///   - peers: The links whose far-end close would acknowledge what was just sent.
    ///   - seconds: The most this may wait; the conformer clamps it to its own ceiling.
    /// - Returns: how the wait ended — the leaver audits it, and a cell asserts it without a clock.
    func awaitRemoteClose(of peers: [PeerHandle], within seconds: TimeInterval) async -> MeshRemoteCloseOutcome

    /// The Ed25519 signing key this radio's own **signed channel introduction** proved for `peer`'s
    /// live link, or nil when it proved none (2026-09-22).
    ///
    /// The transport's answer to "who is really on the other end of this link", and a different
    /// fact from the identity a slot's `ProximityCoordinator` claims to have verified. The
    /// coordinator's identity introduction is a signed envelope with no recipient on this radio (a
    /// QUIC handle carries no advertised fingerprint) and a five-minute lifetime, so a device that
    /// was sent one can replay it over its OWN tunnel. The channel introduction cannot be replayed:
    /// its transcript binds the TLS exporter of this very connection. A caller that is about to act
    /// on a claimed identity without a person's gesture — the returning-member re-seat — requires
    /// the two to agree.
    ///
    /// Default-implemented as nil: a radio that proved nothing vouches for nobody, which fails the
    /// caller closed. ``NetworkMeshSession`` is the one shipping override.
    func verifiedSigningPublicKey(for peer: PeerHandle) -> Data?
}

// MARK: - MeshRemoteCloseOutcome

/// How one ``MeshTransportSession/awaitRemoteClose(of:within:)`` ended (2026-09-22).
///
/// Frozen English tokens, logged verbatim by the leaver beside its development audit line — never
/// display copy. The value exists so the answer is a fact rather than an inference from how long
/// the wait took: a cell asserts the case, which no amount of main-actor starvation can move.
nonisolated enum MeshRemoteCloseOutcome: String, Equatable, Sendable, CaseIterable {

    /// Every watched link ended within the bound. Usually that is the partner closing its end
    /// after reading the frame, but the radio cannot tell that from any other end of the link — a
    /// local link failure, a duplicate-tunnel close, a concurrent `stop()` — so this records that
    /// the link went down, never a read receipt.
    case closed

    /// The bound passed with at least one watched link still open: a partner that could not answer
    /// (a suspended phone, a lost frame), or one that dropped the frame unread.
    case boundReached

    /// There was no live link to wait on, so nothing was waited for.
    case nothingToWaitFor

    /// The waiting task was cancelled. The teardown it guarded runs regardless.
    case cancelled
}

extension MeshTransportSession {

    /// The cause-blind default: a radio with no per-endpoint budget has nothing to spend it on, so
    /// it frees the link and forgets why. ``NetworkMeshSession`` is the one shipping override.
    func disconnectPeer(_ peer: PeerHandle, cause: MeshSlotEvictionCause) {
        disconnectPeer(peer)
    }

    /// The far-end-free default: there is nothing to wait for, so it answers at once.
    func awaitRemoteClose(
        of peers: [PeerHandle], within seconds: TimeInterval
    ) async -> MeshRemoteCloseOutcome {
        .nothingToWaitFor
    }

    /// The fail-closed default: a radio that proved no key vouches for nobody.
    func verifiedSigningPublicKey(for peer: PeerHandle) -> Data? {
        nil
    }
}

// MARK: - Conformances

extension NetworkMeshSession: MeshTransportSession {

    func wire(_ handlers: MeshTransportHandlers) {
        onPeerDiscovered = handlers.onPeerDiscovered
        onPeerChannelReady = { channel in handlers.onChannelReady?(channel) }
        onPeerDisconnected = handlers.onPeerDisconnected
        onTransportError = handlers.onTransportError
        invitationGate = handlers.shouldAcceptInvitation
    }

    func attachIntroductionAuthority(_ authority: any MeshIntroductionAuthority) {
        introductionAuthority = authority
    }

    /// "Invite" was the MC word for it; on this radio it is a dial. Same decision, same owner, and
    /// the same refusal rules — ``MeshLinkTable`` still gets the last word on whether it happens.
    func invite(_ peer: PeerHandle) {
        dial(peer)
    }

    /// A failed listener is reported through the owner's transport-error hook rather than thrown:
    /// that was the shape the retired MultipeerConnectivity radio forced (it could not throw), and
    /// it is kept because the symptom a user sees — the discovery-failure banner — is the owner's
    /// to render either way.
    func startRadios(discoveryInfo: [String: String]) {
        // A radio that is already running is, on this path, a PAUSED one: `start(discoveryInfo:)`
        // guards `!isRunning`, so without this arm the hold's inverse would be a silent no-op and
        // this radio would stay dark for the rest of the session. (The retired MC radio self-healed
        // inside its own start; this one needs the arm said out loud.)
        guard !isRunning else {
            // The caller's fields are not thrown away with the start (review finding F-5):
            // `resumeDiscovery()` re-mints the listener from the STORED advertisement, so a resume
            // that skipped this would republish whatever was advertised when the radio last
            // started — the member count and mesh label of another moment. `updateDiscoveryInfo`
            // only records them while the radio is paused, so the re-mint happens once, below.
            updateDiscoveryInfo(discoveryInfo)
            resumeDiscovery()
            return
        }
        do {
            try start(discoveryInfo: discoveryInfo)
        } catch {
            reportTransportError("The QUIC mesh radio could not start: \(error.localizedDescription)")
        }
    }
}
