// PingHost.swift
// ProximityPing
//
// The example's one seam into ProximityKit: a `ProximityHost` built from the public API alone. It
// answers every requirement the pair session reads, and the mesh's requirements with the smallest
// honest answer, because the example runs no mesh.

import Foundation
import ProximityKit

/// The example app as ProximityKit sees it: its namespace, its name, its trust answers, its identity
/// and where its files would live.
///
/// The pair session holds the host `unowned`, so the app keeps this object for its whole life.
@MainActor
final class PingHost: ProximityHost {

    /// The example's namespace, ``ProximityNamespace/proximityPing``.
    let proximityNamespace = ProximityNamespace.proximityPing

    /// The name this device advertises and discloses: a generic word and four random hex digits,
    /// drawn once per launch. Never the device's own name, which an unauthenticated TXT record
    /// would broadcast.
    let proximityDisplayName: String

    /// The name a device goes by when its own name trims to nothing.
    let proximityFallbackDisplayName = "Ping device"

    /// The container's Application Support folder; ProximityKit puts the namespace's folder under it.
    /// The pair session writes nothing there.
    let proximitySupportDirectory = URL.applicationSupportDirectory

    /// No binding: only the mesh's sealed stores read it, and the example runs no mesh. A real app
    /// answers 16 random bytes kept in a this-device-only keychain row.
    let proximityInstallBinding: any ProximityInstallBinding = NoInstallBinding()

    /// The example runs no mesh, so it registers no routed types.
    let meshRoutedTypeEntries: [MeshRoutedTypeEntry] = []

    /// Where every trust policy this host hands out reports its session audits.
    private let audits: (ProximitySessionAudit) -> Void

    /// A host whose trust policies report to `audits`.
    ///
    /// - Parameters:
    ///   - displayWord: The generic word the display name starts with (`Mac`, `iPhone`).
    ///   - audits: Called once per session audit, on the main actor.
    init(displayWord: String, audits: @escaping (ProximitySessionAudit) -> Void) {
        let suffix = String(format: "%04X", UInt16.random(in: UInt16.min...UInt16.max))
        proximityDisplayName = "\(displayWord) \(suffix)"
        self.audits = audits
    }

    /// The example blocks nobody.
    func isBlockedFingerprint(_ fingerprint: String) -> Bool { false }

    /// The example keeps no block list, so a block request changes nothing.
    func blockProximityPeer(signingPublicKey: Data) {}

    /// A fresh policy per connection, trusting no one in particular and blocking no one.
    func makeProximityTrustPolicy() -> any ProximityTrustPolicy {
        PingTrustPolicy(audits: audits)
    }

    /// No UWB: every pairing commits without ranging.
    func makeProximityRangingProvider() -> any RangingProvider {
        NoopRangingProvider()
    }

    /// This device's identity under the example's namespace, on the namespace's own keychain rows.
    func makeProximityIdentity() -> IdentityService {
        IdentityService(namespace: proximityNamespace)
    }
}

/// The trust answers of one connection: nothing revoked, nothing blocked, nothing trusted ahead of
/// time; every audit forwarded to the diagnostics log.
@MainActor
final class PingTrustPolicy: ProximityTrustPolicy {

    /// Where the audits go.
    private let audits: (ProximitySessionAudit) -> Void

    /// A policy reporting to `audits`.
    init(audits: @escaping (ProximitySessionAudit) -> Void) {
        self.audits = audits
    }

    /// Nothing is revoked.
    func isRevokedProximitySigningKey(_ publicKey: Data) -> Bool { false }

    /// Nothing is blocked.
    func isBlockedProximitySigningKey(_ publicKey: Data) -> Bool { false }

    /// No one is trusted ahead of time.
    func isTrustedProximityPeer(signingPublicKey: Data) -> Bool { false }

    /// Forwards the audit.
    func recordSessionAudit(_ audit: ProximitySessionAudit) {
        audits(audit)
    }
}

/// The install binding of a host that seals nothing: every read answers no binding.
nonisolated struct NoInstallBinding: ProximityInstallBinding {

    /// No binding, whatever the access.
    func read(for access: ProximityInstallBindingAccess) throws(ProximityInstallBindingReadError) -> Data? {
        nil
    }
}

/// ProximityKit's audit lines, handed to the app as a stream: the sink yields each line where it is
/// logged, with no hop and no wait, and the diagnostics model reads the stream on the main actor.
nonisolated final class PingAuditSink: ProximityAuditSink {

    /// One audit line: its event token and its context.
    struct Line: Sendable {
        /// The event token, such as `recipe.quic.connected`.
        let event: String
        /// The line's context, by key.
        let context: [String: String]
    }

    /// The lines, in the order ProximityKit logged them.
    let lines: AsyncStream<Line>

    /// The stream's input side.
    private let continuation: AsyncStream<Line>.Continuation

    /// A sink with an empty stream that keeps the newest 200 unread lines.
    init() {
        let (stream, continuation) = AsyncStream<Line>.makeStream(bufferingPolicy: .bufferingNewest(200))
        lines = stream
        self.continuation = continuation
    }

    /// Yields the line to the stream.
    func record(_ event: String, context: [String: String]) {
        continuation.yield(Line(event: event, context: context))
    }

    /// A line as the log shows it: the event token, then each `key=value` of its context, keys sorted.
    static func text(of line: Line) -> String {
        let context = line.context.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }
        return ([line.event] + context).joined(separator: " ")
    }
}
