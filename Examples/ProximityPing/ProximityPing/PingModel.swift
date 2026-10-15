// PingModel.swift
// ProximityPing
//
// The example's whole behaviour: one ProximityKit pair session, a ping that a nearby device answers
// with a pong, and the diagnostics the public API exposes along the way.

import Foundation
import Observation
import ProximityKit

/// One ping or pong on the wire: its sequence number, which the pong echoes.
nonisolated struct PingFrame: Codable, Sendable {
    /// Most bytes an encoded frame takes (`{"seq":` and the longest `Int`, with room to spare); a
    /// longer payload is refused unread.
    static let maxEncodedBytes = 64
    /// The ping's sequence number on the device that sent it.
    let seq: Int
}

/// One line of the diagnostics log.
struct PingLogLine: Identifiable {
    /// The line's identity, for the list.
    let id = UUID()
    /// When the line was written.
    let at: Date
    /// Where it came from: `event` (the pair session), `audit` (ProximityKit's audit sink),
    /// `session` (a trust-policy audit) or `app` (this model).
    let source: String
    /// What happened.
    let text: String
}

/// The example's state: the pair session it owns, the counters and timings of its pings, and a
/// bounded log of everything ProximityKit told it.
@MainActor
@Observable
final class PingModel: ProximityPayloadHandling {

    /// Most lines the log keeps; the oldest goes first.
    static let maxLogLines = 300
    /// Most pings awaiting a pong at once; an older one is forgotten.
    static let maxOutstanding = 32

    /// The host the session is built over, kept for the session's whole life (it is held `unowned`).
    @ObservationIgnored let host: PingHost
    /// The one pair session.
    @ObservationIgnored let session: ProximityPairSession
    /// This device's identity, read for its fingerprint (the session holds its own instance of it).
    @ObservationIgnored private let identity: IdentityService

    /// This device's signing-key fingerprint, or empty until the identity is provisioned.
    private(set) var localFingerprint = ""
    /// The last error the identity, the radio or a send reported.
    private(set) var lastError: String?
    /// Pings this device sent, pongs it got back, pings it answered.
    private(set) var pingsSent = 0
    private(set) var pongsReceived = 0
    private(set) var pingsAnswered = 0
    /// Round-trip times of the answered pings, in milliseconds: the last, the best, and the mean.
    private(set) var lastRoundTripMs: Double?
    private(set) var bestRoundTripMs: Double?
    private(set) var meanRoundTripMs: Double?
    /// Payload bytes this device's pings and pongs carried out and in (before sealing).
    private(set) var payloadBytesOut = 0
    private(set) var payloadBytesIn = 0
    /// The coordinator state of the pairing that last delivered a payload, and its peer's capabilities.
    private(set) var pairingState = "none"
    private(set) var peerCapabilities: [String]?
    /// The log, newest last.
    private(set) var log: [PingLogLine] = []

    /// The next ping's sequence number.
    @ObservationIgnored private var nextSeq = 1
    /// When each ping still awaiting its pong was sent, by sequence number; at most ``maxOutstanding``.
    @ObservationIgnored private var outstanding: [Int: Date] = [:]
    /// The task reading the audit sink's lines into the log, cancelled in `deinit`.
    @ObservationIgnored private var auditTask: Task<Void, Never>?

    /// A model whose session runs over a new host; the sink's lines join the log.
    ///
    /// - Parameters:
    ///   - displayWord: The generic word this device's advertised name starts with.
    ///   - auditSink: The sink installed as ProximityKit's audit sink before this model was built.
    init(displayWord: String, auditSink: PingAuditSink) {
        var forward: (ProximitySessionAudit) -> Void = { _ in }
        let host = PingHost(displayWord: displayWord) { forward($0) }
        self.host = host
        self.identity = host.makeProximityIdentity()
        self.session = ProximityPairSession(host: host, profile: .proximityPing)
        forward = { [weak self] audit in
            self?.append("session", "\(audit.kind.rawValue): \(audit.message)")
        }
        session.payloadHandler = self
        session.onEvent = { [weak self] event in self?.record(event) }
        auditTask = Task { [weak self] in
            // R2: bounded by the stream's life: it ends when this task is cancelled (the model's
            // deinit) or the model is gone, and each pass appends one line to a log capped at
            // `maxLogLines`.
            for await line in auditSink.lines {
                guard let self else { return }
                self.append("audit", PingAuditSink.text(of: line))
            }
        }
        provisionIdentity()
    }

    /// Ends the audit reader if the model is released.
    isolated deinit {
        auditTask?.cancel()
    }

    /// Reads (or mints) this device's identity, for its fingerprint; once it is read, does nothing.
    private func provisionIdentity() {
        guard localFingerprint.isEmpty else { return }
        do {
            try identity.ensureProvisioned()
            localFingerprint = identity.localFingerprint
            append("app", "identity ready: \(localFingerprint)")
        } catch {
            lastError = "identity: \(error)"
            append("app", "identity failed: \(error)")
        }
    }

    /// Brings the radio up: advertise, browse, accept a pairing. Refused while this device has no
    /// identity, which nothing could verify; the identity is read again first.
    func start() {
        provisionIdentity()
        guard !localFingerprint.isEmpty else {
            append("app", "radio not started: this device has no identity")
            return
        }
        session.start()
    }

    /// Stands the radio down, with every pairing it holds.
    func stop() {
        session.stop()
    }

    /// Sends one ping to `peer`, dialing and verifying it first when no pairing holds it yet.
    func ping(_ peer: ProximityPairPeer) {
        guard nextSeq < Int.max else {
            append("app", "ping not sent: sequence numbers exhausted")
            return
        }
        let seq = nextSeq
        nextSeq += 1
        if outstanding.count >= Self.maxOutstanding, let oldest = outstanding.keys.min() {
            outstanding.removeValue(forKey: oldest)
        }
        outstanding[seq] = Date()
        pingsSent += 1
        send(PingPayload.ping, seq: seq, to: peer)
    }

    /// Sends a ping or a pong carrying `seq`; the session seals it to the verified peer.
    private func send(_ token: String, seq: Int, to peer: ProximityPairPeer) {
        let title = token == PingPayload.ping ? "Ping" : "Pong"
        let outgoing = ProximityPairSession.Outgoing(
            payloadTypeToken: token,
            summary: PayloadSummary(title: title),
            subject: "\(title.lowercased()) #\(seq)",
            encode: { [weak self] in
                let data = try JSONEncoder().encode(PingFrame(seq: seq))
                self?.payloadBytesOut += data.count
                return data
            }
        )
        session.send(outgoing, to: peer)
    }

    /// A verified payload from the paired device: a ping is answered with a pong, a pong ends a
    /// round trip. A payload longer than a frame can be is refused unread.
    func proximityCoordinator(
        _ coordinator: ProximityCoordinator,
        didReceive envelope: ProximityIdentityEnvelope,
        plaintext: Data,
        from peer: ProximityCoordinator.PeerIdentity?
    ) {
        guard plaintext.count <= PingFrame.maxEncodedBytes else {
            lastError = "\(envelope.payloadTypeToken): \(plaintext.count) bytes refused"
            append("app", "refused \(envelope.payloadTypeToken): \(plaintext.count) bytes")
            return
        }
        payloadBytesIn += plaintext.count
        pairingState = coordinator.state.debugLabel
        peerCapabilities = peer?.capabilities
        let frame: PingFrame
        do {
            frame = try JSONDecoder().decode(PingFrame.self, from: plaintext)
        } catch {
            lastError = "decode: \(error)"
            append("app", "undecodable \(envelope.payloadTypeToken): \(error)")
            return
        }
        switch envelope.payloadTypeToken {
        case PingPayload.ping:
            answer(frame, from: peer)
        case PingPayload.pong:
            finishRoundTrip(frame)
        default:
            append("app", "ignored \(envelope.payloadTypeToken)")
        }
    }

    /// Answers a ping with a pong to the device that sent it.
    private func answer(_ frame: PingFrame, from peer: ProximityCoordinator.PeerIdentity?) {
        guard let peer else {
            append("app", "ping #\(frame.seq) from an unconfirmed peer: not answered")
            return
        }
        let row = session.nearbyPeers.first { $0.id == peer.id }
            ?? ProximityPairPeer(id: peer.id, displayName: peer.displayNameOrFingerprint, fingerprint: peer.fingerprint)
        pingsAnswered += 1
        append("app", "ping #\(frame.seq) from \(row.displayName): answering")
        send(PingPayload.pong, seq: frame.seq, to: row)
    }

    /// Records the round trip of the ping a pong answers.
    private func finishRoundTrip(_ frame: PingFrame) {
        guard let sentAt = outstanding.removeValue(forKey: frame.seq) else {
            append("app", "pong #\(frame.seq) for no outstanding ping")
            return
        }
        let ms = Date().timeIntervalSince(sentAt) * 1000
        pongsReceived += 1
        lastRoundTripMs = ms
        bestRoundTripMs = min(bestRoundTripMs ?? ms, ms)
        let count = Double(pongsReceived)
        meanRoundTripMs = ((meanRoundTripMs ?? 0) * (count - 1) + ms) / count
        append("app", String(format: "pong #%d: %.1f ms", frame.seq, ms))
    }

    /// Logs a pair-session event; one that reports a failure also becomes the last error.
    private func record(_ event: ProximityPairSession.Event) {
        if Self.isFailure(event) {
            lastError = "\(event)"
        }
        append("event", "\(event)")
    }

    /// Whether `event` reports that the radio, a connection or a send did not do what was asked.
    private static func isFailure(_ event: ProximityPairSession.Event) -> Bool {
        switch event {
        case .radioDidNotStart, .radioFailed, .recipientUnavailable, .sendRefusedWhilePaired, .noAnswer,
             .couldNotConnect, .duplicateSendRefused, .sendFailed:
            return true
        default:
            return false
        }
    }

    /// Appends a log line, dropping the oldest past ``maxLogLines``.
    private func append(_ source: String, _ text: String) {
        log.append(PingLogLine(at: Date(), source: source, text: text))
        if log.count > Self.maxLogLines {
            log.removeFirst(log.count - Self.maxLogLines)
        }
    }
}
