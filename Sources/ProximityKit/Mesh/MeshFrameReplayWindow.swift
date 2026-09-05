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
/// ## Bounds (plan §9), per instance since P5 item 12
///
/// - ``maxSenders`` = the roster cap: a control-frame mesh cannot have more authenticated senders
///   than members. The static is the DEFAULT behind the instance property of the same name.
/// - ``maxFramesPerSender`` = 64 ids, likewise the default behind ``framesPerSender``.
/// - The routed instance (P5 item 12) overrides both, additively and per instance, because its two
///   axes have different populations from a control frame's: `framesPerSender` is
///   `MeshRoutedDrainBounds.sessionFramesPerPeer` (1056 ≥ one maximal 1024-chunk item plus its
///   manifest and both receipt kinds) and `maxSenders` is `MeshMembershipBounds.maxRecordsPerKind`
///   (16), because a routed frame's **author** is any admitted-and-not-removed signer, not a
///   current roster member — a departed origin's content stays valid and keeps moving under
///   custody transfer, so the roster cap of 8 would silently switch the defence off for exactly
///   that traffic. Growth is bounded on both axes and on every input path, which is what makes
///   this safe to feed from an unauthenticated-at-parse-time frame body.
///
/// ## Wired against routed content ids (P5 item 12)
///
/// The four routed content doors key it on the ids items 1–4 derived for this purpose —
/// `MeshRoutedManifest.itemID`, `MeshChunk.chunkID`, `MeshCustodyReceipt.receiptID`,
/// `MeshRecipientReceipt.receiptID` — attributed to the frame's **author** (origin, custodian,
/// recipient), never to the forwarding envelope's sender and never to an epoch. That kept plan
/// §8.4's promise the three `keyEpoch` gates were retired against, and P5 item 13 collected on it:
/// routed content carries unique ids + meshID + expiry and dedups by id, which is what let two of
/// the three be deleted with the paths they gated rather than loosened.
///
/// Two calls, not one, and the split is the whole reason both ``verdict(frameID:from:meshID:expiresAt:now:)``
/// and ``admit(frameID:from:meshID:expiresAt:now:)`` exist: the manager PROBES with `verdict` on the
/// unverified frame (safe on a claimed author precisely because it records nothing) and RECORDS with
/// `admit` on the verified one, after the store's door has answered. A `.senderWindowFull` at either
/// axis is a **named degradation, never a refusal** — the frame falls through to the unchanged
/// verify-and-store path — because no bounded window can cover a whole session's ids and a window
/// that dropped legitimate traffic at its cap would be a delivery denial wearing a defence's name.
///
/// ``forget(senderFingerprint:)`` is deliberately **never** called on the routed instance: under
/// increment 1 a departed origin's content is exactly what a custodian keeps forwarding after a
/// departure hand-off, so forgetting a departed author would hand an attacker a free replay of the
/// content custody transfer exists to keep moving. ``forget(frameID:from:)`` is a different verb
/// with a different justification — the store can give a chunk slot back (a repair), and an id whose
/// slot came back must be re-admittable.
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

    /// Distinct authenticated senders tracked by default. The roster cap — a control-frame mesh
    /// has no more.
    static let maxSenders = MeshMembershipBounds.maxRosterMembers

    /// Frame ids remembered per sender by default.
    static let maxFramesPerSender = 64

    /// The mesh every admitted frame must name. A frame from another mesh is refused before it can
    /// occupy a slot.
    let meshID: UUID

    /// This instance's per-author frame cap. Defaults to ``maxFramesPerSender``; the routed
    /// instance raises it to `MeshRoutedDrainBounds.sessionFramesPerPeer` so one maximal item's
    /// whole frame family fits on one author's axis.
    let framesPerSender: Int

    /// This instance's author cap. Defaults to the static ``maxSenders`` (the roster cap); the
    /// routed instance raises it to `MeshMembershipBounds.maxRecordsPerKind`, the admission set's
    /// own capacity, because a routed frame's author need not be a current roster member.
    let maxSenders: Int

    /// Recorded ids, per authenticated sender fingerprint.
    private var seenBySender: [String: Set<UUID>] = [:]

    /// Starts an empty window for one mesh, with both bounds defaulted to the control-frame values
    /// P3 shipped — so `MeshFrameReplayWindow(meshID:)` is exactly the pre-item-12 window.
    ///
    /// - Parameters:
    ///   - meshID: The mesh every admitted frame must name.
    ///   - framesPerSender: Ids remembered per author.
    ///   - maxSenders: Distinct authors tracked.
    init(
        meshID: UUID,
        framesPerSender: Int = Self.maxFramesPerSender,
        maxSenders: Int = Self.maxSenders
    ) {
        self.meshID = meshID
        self.framesPerSender = framesPerSender
        self.maxSenders = maxSenders
    }

    /// What the window WOULD say about one frame, recording nothing.
    ///
    /// The guard chain lives here and only here, so a probe and the admission that follows it can
    /// never disagree — the property P5 item 12's wiring leans on. Non-mutating, which is what makes
    /// it safe to run on a frame whose author is still only a **claim**: an attacker cannot place an
    /// id under another member's axis, cannot evict anything, and cannot make an honest frame be
    /// dropped, because an id is present under author A only if a frame that VERIFIED under A's
    /// ledger-resolved key put it there.
    ///
    /// Note the order: an expired replay answers ``MeshFrameReplayVerdict/expired``, never
    /// `.replayed`, so the window is not an expiry gate and cannot be used to suppress an expiry
    /// line.
    ///
    /// - Parameters:
    ///   - frameID: The frame's unique id — the dedup key.
    ///   - senderFingerprint: The author the frame names.
    ///   - meshID: The mesh the frame names.
    ///   - expiresAt: The instant the frame stops being valid, from the frame itself.
    ///   - now: The current instant, injected.
    /// - Returns: The verdict this frame would receive.
    func verdict(
        frameID: UUID,
        from senderFingerprint: String,
        meshID frameMeshID: UUID,
        expiresAt: Date,
        now: Date
    ) -> MeshFrameReplayVerdict {
        guard frameMeshID == meshID else { return .foreignMesh }
        guard now <= expiresAt else { return .expired }
        let seen = seenBySender[senderFingerprint] ?? []
        if seen.contains(frameID) { return .replayed }
        guard seen.count < framesPerSender else { return .senderWindowFull }
        guard seenBySender[senderFingerprint] != nil || seenBySender.count < maxSenders else {
            return .senderWindowFull
        }
        return .admitted
    }

    /// Offers one frame to the window.
    ///
    /// - Parameters:
    ///   - frameID: The frame's unique id — the dedup key.
    ///   - senderFingerprint: The **authenticated** sender. Callers must not pass a claimed one;
    ///     an unauthenticated string here would let a peer poison another member's window. Probe
    ///     with ``verdict(frameID:from:meshID:expiresAt:now:)`` when the author is not yet verified.
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
        let outcome = verdict(
            frameID: frameID, from: senderFingerprint, meshID: frameMeshID,
            expiresAt: expiresAt, now: now
        )
        guard outcome == .admitted else { return outcome }
        var seen = seenBySender[senderFingerprint] ?? []
        seen.insert(frameID)
        seenBySender[senderFingerprint] = seen
        return .admitted
    }

    /// Forgets one sender entirely — what a departure or a removal does, so a member that leaves
    /// and is re-admitted starts with a clean window instead of an inherited one.
    ///
    /// **Not** what P5 item 12's routed instance does: a departed origin's content is precisely what
    /// a custodian keeps forwarding after a departure hand-off, so forgetting that author would hand
    /// an attacker a free replay of the content custody transfer exists to keep moving.
    mutating func forget(senderFingerprint: String) {
        seenBySender.removeValue(forKey: senderFingerprint)
    }

    /// Forgets ONE id under one author — the counterpart of a slot the store gave back.
    ///
    /// P5 item 12's one caller is a chunk **repair**: `MeshRoutedCustody.repairing(_:dropping:in:)`
    /// removes a chunk descriptor and unlinks its file, the slot re-appears as a gap in the
    /// advertised inventory, and a peer re-offers that exact chunk. Its `chunkID` is derived from
    /// `(itemID, index)`, so the honest re-send carries the identical `(author, id)` the first
    /// admission recorded — without this verb the slot could never be refilled for the rest of the
    /// session, and no complete item means no witness, no receipt and no delivery.
    ///
    /// The author's axis is deliberately kept even when its last id goes: a released axis is an
    /// eviction primitive, which is exactly what this type refuses to offer.
    mutating func forget(frameID: UUID, from senderFingerprint: String) {
        seenBySender[senderFingerprint]?.remove(frameID)
    }

    /// How many ids are recorded for a sender. Diagnostic and test surface.
    func recordedCount(for senderFingerprint: String) -> Int {
        seenBySender[senderFingerprint]?.count ?? 0
    }

    /// How many senders the window is tracking. Diagnostic and test surface.
    var trackedSenderCount: Int { seenBySender.count }
}
