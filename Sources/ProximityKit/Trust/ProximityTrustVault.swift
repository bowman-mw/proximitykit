import Foundation
import Observation
import FernletDomainModel

@MainActor
@Observable
public final class ProximityTrustVault: ProximityTrustPolicy {
    public private(set) var trustedPeers: [ProximityTrustedPeerRecord] = []
    public private(set) var auditEvents: [TrainerAuditEvent] = []

    // Mutable so FernletStore can wire it after all stored properties are initialized.
    @ObservationIgnored public var onChange: () -> Void = {}

    public init(
        initialPeers: [ProximityTrustedPeerRecord] = [],
        initialAudit: [TrainerAuditEvent] = [],
        onChange: @escaping () -> Void = {}
    ) {
        self.trustedPeers = Self.normalized(initialPeers)
        self.auditEvents = initialAudit
        self.onChange = onChange
    }

    // MARK: - Reads

    public func peer(signingPublicKey: Data) -> ProximityTrustedPeerRecord? {
        trustedPeers.first { $0.signingPublicKey == signingPublicKey }
    }

    public func peer(displayName: String) -> ProximityTrustedPeerRecord? {
        trustedPeers
            .filter { $0.displayName == displayName }
            .sorted { $0.lastSeenAt > $1.lastSeenAt }
            .first
    }

    /// The most-recently-seen peer whose fingerprint matches — used to resolve a shop seller's signing
    /// key from a catalog that only carries the verified fingerprint.
    public func peer(fingerprint: String) -> ProximityTrustedPeerRecord? {
        trustedPeers
            .filter { IdentityService.fingerprintsMatch($0.fingerprint, fingerprint) }
            .sorted { $0.lastSeenAt > $1.lastSeenAt }
            .first
    }

    public func isTrustedProximityPeer(signingPublicKey: Data) -> Bool {
        return trustedPeers.contains {
            $0.signingPublicKey == signingPublicKey && $0.revokedAt == nil
        }
    }

    public func isRevokedProximitySigningKey(_ publicKey: Data) -> Bool {
        trustedPeers.contains { $0.signingPublicKey == publicKey && $0.revokedAt != nil }
    }

    public func isBlockedProximitySigningKey(_ publicKey: Data) -> Bool {
        trustedPeers.contains { $0.signingPublicKey == publicKey && $0.blockedAt != nil }
    }

    public func isBlockedFingerprint(_ fingerprint: String) -> Bool {
        trustedPeers.contains {
            $0.blockedAt != nil && Self.blockMatches(stored: $0.fingerprint, query: fingerprint)
        }
    }

    /// Block matching keeps ONE narrow legacy affordance that the strict 16-char
    /// `fingerprintsMatch` (tightened 2026-07-25) dropped: photo-cache payloads written before
    /// 2026-06-12 carry 8-char sender fingerprints and have no key bytes to re-derive from, so an
    /// 8-hex QUERY may prefix-match a (normalized, 16-char) blocked row. This direction is
    /// hide-only — a grindable 32-bit prefix can only hide MORE cached photos, never grant
    /// anything — which is why the affordance lives here and nowhere else.
    private static func blockMatches(stored: String, query: String) -> Bool {
        if IdentityService.fingerprintsMatch(stored, query) { return true }
        let short = query.lowercased()
        return short.count == 8 && short.allSatisfy(\.isHexDigit) && stored.lowercased().hasPrefix(short)
    }

    // MARK: - Writes

    public func trust(_ peer: ProximityCoordinator.PeerIdentity, mode: ProximityCoordinator.Mode) {
        let fingerprint = IdentityService.fingerprint(of: peer.signingPublicKey)
        if let index = trustedPeers.firstIndex(where: { $0.signingPublicKey == peer.signingPublicKey }) {
            trustedPeers[index].displayName = peer.displayName
            trustedPeers[index].fingerprint = fingerprint
            trustedPeers[index].keyAgreementPublicKey = peer.keyAgreementPublicKey
            trustedPeers[index].mode = mode
            trustedPeers[index].lastSeenAt = Date()
            trustedPeers[index].revokedAt = nil
            trustedPeers[index].blockedAt = nil
        } else {
            trustedPeers.append(ProximityTrustedPeerRecord(
                displayName: peer.displayName,
                fingerprint: fingerprint,
                signingPublicKey: peer.signingPublicKey,
                keyAgreementPublicKey: peer.keyAgreementPublicKey,
                mode: mode
            ))
        }
        onChange()
    }

    public func block(signingPublicKey: Data) {
        let now = Date()
        guard let index = trustedPeers.firstIndex(where: { $0.signingPublicKey == signingPublicKey }) else {
            let fingerprint = IdentityService.fingerprint(of: signingPublicKey)
            trustedPeers.append(ProximityTrustedPeerRecord(
                displayName: fingerprint,
                fingerprint: fingerprint,
                signingPublicKey: signingPublicKey,
                keyAgreementPublicKey: Data(),
                mode: .friend,
                firstAcceptedAt: now,
                lastSeenAt: now,
                revokedAt: now,
                blockedAt: now
            ))
            onChange()
            return
        }
        trustedPeers[index].blockedAt = now
        trustedPeers[index].revokedAt = now
        recordAuditWithoutSaving(TrainerAuditEvent(
            kind: .revokedPeerBlocked,
            peerFingerprint: trustedPeers[index].fingerprint,
            peerDisplayName: trustedPeers[index].displayName,
            message: "Blocked \(trustedPeers[index].displayName)"
        ))
        onChange()
    }

    public func unblock(signingPublicKey: Data) {
        guard let index = trustedPeers.firstIndex(where: { $0.signingPublicKey == signingPublicKey }) else { return }
        trustedPeers[index].blockedAt = nil
        // Do not touch revokedAt: block and revoke are independent states.
        onChange()
    }

    public func revoke(signingPublicKey: Data) {
        guard let index = trustedPeers.firstIndex(where: { $0.signingPublicKey == signingPublicKey }) else { return }
        trustedPeers[index].revokedAt = Date()
        recordAuditWithoutSaving(TrainerAuditEvent(
            kind: .trainerRevoked,
            peerFingerprint: trustedPeers[index].fingerprint,
            peerDisplayName: trustedPeers[index].displayName,
            message: "Revoked \(trustedPeers[index].displayName)"
        ))
        onChange()
    }

    /// Reports a peer for objectionable content. Stamps `reportedAt`/`reportReason`; when `blockAlso`
    /// (the safe default) also blocks + revokes exactly like `block()`. Creates a blocked+reported stub
    /// when the key isn't already in the vault (a reported item's seller may not be a kept friend).
    public func report(signingPublicKey: Data, reason: String, blockAlso: Bool = true) {
        let now = Date()
        guard let index = trustedPeers.firstIndex(where: { $0.signingPublicKey == signingPublicKey }) else {
            let fingerprint = IdentityService.fingerprint(of: signingPublicKey)
            trustedPeers.append(ProximityTrustedPeerRecord(
                displayName: fingerprint,
                fingerprint: fingerprint,
                signingPublicKey: signingPublicKey,
                keyAgreementPublicKey: Data(),
                mode: .friend,
                firstAcceptedAt: now,
                lastSeenAt: now,
                revokedAt: blockAlso ? now : nil,
                blockedAt: blockAlso ? now : nil,
                reportedAt: now,
                reportReason: reason
            ))
            recordAuditWithoutSaving(TrainerAuditEvent(
                kind: .peerReported, peerFingerprint: fingerprint, peerDisplayName: fingerprint,
                message: "Reported \(fingerprint)"))
            onChange()
            return
        }
        trustedPeers[index].reportedAt = now
        trustedPeers[index].reportReason = reason
        if blockAlso {
            trustedPeers[index].blockedAt = now
            trustedPeers[index].revokedAt = now
        }
        recordAuditWithoutSaving(TrainerAuditEvent(
            kind: .peerReported,
            peerFingerprint: trustedPeers[index].fingerprint,
            peerDisplayName: trustedPeers[index].displayName,
            message: "Reported \(trustedPeers[index].displayName)"))
        onChange()
    }

    public func recordTrainerAudit(_ event: TrainerAuditEvent) {
        recordAuditWithoutSaving(event)
        onChange()
    }

    // MARK: - Snapshot

    public func apply(peers: [ProximityTrustedPeerRecord], audit: [TrainerAuditEvent]) {
        trustedPeers = Self.normalized(peers)
        auditEvents = audit
    }

    private static func normalized(_ peers: [ProximityTrustedPeerRecord]) -> [ProximityTrustedPeerRecord] {
        peers.map { peer in
            guard !peer.signingPublicKey.isEmpty,
                  peer.fingerprint.count == 8,
                  peer.fingerprint.allSatisfy(\.isHexDigit) else { return peer }
            var normalizedPeer = peer
            normalizedPeer.fingerprint = IdentityService.fingerprint(of: peer.signingPublicKey)
            return normalizedPeer
        }
    }

    private func recordAuditWithoutSaving(_ event: TrainerAuditEvent) {
        auditEvents.insert(event, at: 0)
        auditEvents = Array(auditEvents.prefix(500))
    }
}
