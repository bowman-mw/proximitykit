// MeshFrameReplayWindow.swift
// ProximityKit/Mesh
//
// P3 item 4 (plan §8.4): replay protection, moved OFF epochs.
//
// The old arrangement made an epoch do two jobs. Its honest one is key selection — which key opens
// this frame. Its second, implicit one was replay protection: a frame naming a retired epoch could
// not be opened, so re-sending one was pointless. That coupling is exactly what plan §8.4 retires:
//
//   > Replay protection moves off epochs: routed content carries unique IDs + meshID + expiry and
//   > dedups by ID (P5); only live control-frame key selection uses epochs. (Today's epoch-gated
//   > photo manifests would wrongly reject cross-partition content; that gating is retired with the
//   > old path.)
//
// Once the keyring (`MeshEpochKeyring`) can open a frame from a predecessor epoch, and once a
// merge can bring two branches together, "the epoch no longer opens" stops being a replay answer.
// This is the replacement: per-sender dedup by frame id, bounded, with an explicit expiry, and
// with no knowledge of epochs at all.

import Foundation

// MARK: - MeshFrameReplayVerdict

/// What a replay window says about one presented frame.
///
/// Every refusal names itself. "Replayed" and "expired" look identical to a user and must not look
/// identical to whoever is reading a log: the first is an attack or a buggy re-gossip, the second
/// is a slow network or a clock that drifted.
nonisolated enum MeshFrameReplayVerdict: Equatable, Sendable {
    /// First time this sender has presented this id, inside its validity window. Recorded.
    case admitted
    /// This sender has presented this id before. Nothing is recorded a second time.
    case replayed
    /// The frame's own expiry has passed. Not recorded — an expired frame must not consume a slot
    /// that an honest one could use.
    case expired
    /// The frame names another mesh. Not recorded, for the same reason.
    case foreignMesh
    /// This sender already holds ``MeshFrameReplayWindow/maxFramesPerSender`` ids in the window.
    /// Refused rather than evicting, so one loud sender cannot flush another's history — and
    /// cannot flush its *own* history to replay a frame the window would otherwise remember.
    case senderWindowFull
}

// MARK: - MeshFrameReplayWindow

/// Per-sender dedup of routed frames by id, independent of any epoch (plan §8.4).
///
/// ## Why per sender, and why refusal rather than eviction
///
/// The window is keyed by the frame's **authenticated** sender fingerprint, so one member's
/// traffic can never displace another's history. Within a sender the window is a hard cap that
/// *refuses* rather than evicting: an LRU would let an attacker replay an old frame simply by
/// sending `maxFramesPerSender` fresh ones first, which is the whole protection undone by a
/// convenience.
///
/// ## Bounds (plan §9)
///
/// - ``maxSenders`` = the roster cap: a mesh cannot have more authenticated senders than members.
/// - ``maxFramesPerSender`` = 64 ids. Growth is bounded on both axes and on every input path,
///   which is what makes this safe to feed from an unauthenticated-at-parse-time frame body.
///
/// ## The clock is injected
///
/// ``admit(frameID:from:meshID:expiresAt:now:)`` takes `now` and never reads `Date()`, so expiry
/// is a value a test states. `expiresAt` is the frame's own claim: a sender cannot use it to make a
/// frame live *longer* than the window remembers it, only shorter, because the id stays recorded
/// until ``forget(senderFingerprint:)`` or a reset.
///
/// ## Concurrency
///
/// `nonisolated` and `Sendable`: a pure value the caller owns and mutates in place.
nonisolated struct MeshFrameReplayWindow: Equatable, Sendable {

    /// Distinct authenticated senders tracked. The roster cap — a mesh has no more.
    static let maxSenders = MeshMembershipBounds.maxRosterMembers

    /// Frame ids remembered per sender.
    static let maxFramesPerSender = 64

    /// The mesh every admitted frame must name. A frame from another mesh is refused before it can
    /// occupy a slot.
    let meshID: UUID

    /// Recorded ids, per authenticated sender fingerprint.
    private var seenBySender: [String: Set<UUID>] = [:]

    /// Starts an empty window for one mesh.
    init(meshID: UUID) {
        self.meshID = meshID
    }

    /// Offers one frame to the window.
    ///
    /// - Parameters:
    ///   - frameID: The frame's unique id — the dedup key.
    ///   - senderFingerprint: The **authenticated** sender. Callers must not pass a claimed one;
    ///     an unauthenticated string here would let a peer poison another member's window.
    ///   - meshID: The mesh the frame names.
    ///   - expiresAt: The instant the frame stops being valid, from the frame itself.
    ///   - now: The current instant, injected.
    /// - Returns: The verdict. Only ``MeshFrameReplayVerdict/admitted`` records anything.
    mutating func admit(
        frameID: UUID,
        from senderFingerprint: String,
        meshID frameMeshID: UUID,
        expiresAt: Date,
        now: Date
    ) -> MeshFrameReplayVerdict {
        guard frameMeshID == meshID else { return .foreignMesh }
        guard now <= expiresAt else { return .expired }
        var seen = seenBySender[senderFingerprint] ?? []
        if seen.contains(frameID) { return .replayed }
        guard seen.count < Self.maxFramesPerSender else { return .senderWindowFull }
        guard seenBySender[senderFingerprint] != nil || seenBySender.count < Self.maxSenders else {
            return .senderWindowFull
        }
        seen.insert(frameID)
        seenBySender[senderFingerprint] = seen
        return .admitted
    }

    /// Forgets one sender entirely — what a departure or a removal does, so a member that leaves
    /// and is re-admitted starts with a clean window instead of an inherited one.
    mutating func forget(senderFingerprint: String) {
        seenBySender.removeValue(forKey: senderFingerprint)
    }

    /// How many ids are recorded for a sender. Diagnostic and test surface.
    func recordedCount(for senderFingerprint: String) -> Int {
        seenBySender[senderFingerprint]?.count ?? 0
    }

    /// How many senders the window is tracking. Diagnostic and test surface.
    var trackedSenderCount: Int { seenBySender.count }
}
