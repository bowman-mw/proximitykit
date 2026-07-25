import Foundation
import Observation
import FernletDomainModel

/// The live-session temporary-message store (Phase 5, Docs/Proximity-Mesh-Redesign-2026-07-10.md).
///
/// Owner decision (binding): messages are exchanged ONLY during a live friend session and VANISH at
/// session end — nothing retained on device, nothing synced, no dead-drop, no offline queue. This type
/// is the ONLY in-memory holder, and it is deliberately **NOT Codable**: it is structurally impossible
/// for a message to enter a `FernletSnapshot` (mirrors `MeshSessionRosterEntry`/`MeshFriendReviewBatch`,
/// which are equally non-Codable memory-only state). Owned by `MeshNetworkManager`, which drives the
/// whole lifecycle:
///  - **Outbound** — `sendTempMessage(_:)` sanitizes + caps the text, appends the local echo here, and
///    room-broadcasts it sealed to every active committed slot advertising the `messages` capability.
///  - **Inbound** — the manager's Phase-1 payload registry dispatches verified `.tempMessage` envelopes
///    (committed-slot gate + blocked-fingerprint drop already enforced by the manager, mirroring
///    `.friendPhoto`) to `receiveIncoming(...)`, which dedupes by id, rate-limits per sender, sanitizes,
///    and caps.
///  - **Clear** — the manager calls `clear()` at EVERY session-end path (the same last-committed-slot-gone
///    moment that promotes `pendingFriendReview` / opens the shop window: stopSearching's teardown funnel,
///    removeSlot, disconnectSlot) AND on the next session formation (the first slot commit). Unlike the
///    shop's post-session window, messages do NOT outlive the session — they vanish immediately.
@MainActor
@Observable
public final class SessionMessageStore {

    /// A single message in the current session's transcript. Value-typed + `Sendable` so views can key
    /// off it; never persisted (its holder is not Codable).
    public struct Message: Identifiable, Equatable, Sendable {
        public let id: UUID
        /// Transport-VERIFIED sender fingerprint (local fingerprint for outgoing). Never a wire claim.
        public let senderFingerprint: String
        public let senderDisplayName: String
        public let text: String
        public let sentAt: Date
        public let isOutgoing: Bool

        public init(
            id: UUID,
            senderFingerprint: String,
            senderDisplayName: String,
            text: String,
            sentAt: Date,
            isOutgoing: Bool
        ) {
            self.id = id
            self.senderFingerprint = senderFingerprint
            self.senderDisplayName = senderDisplayName
            self.text = text
            self.sentAt = sentAt
            self.isOutgoing = isOutgoing
        }
    }

    /// Max characters a message may carry. A hostile peer over-length is capped, not dropped.
    public static let maxTextLength = 500
    /// Receive flood guard as a token bucket: a sender may burst up to `burstAllowance` messages,
    /// then the bucket refills at `refillPerSecond`. This tolerates normal human double-/triple-
    /// texting (which a flat 1/sec window silently dropped) while still bounding a hostile flood
    /// (the transcript is additionally hard-capped at `maxMessages`).
    static let burstAllowance: Double = 5
    static let refillPerSecond: Double = 1
    /// Hard cap on the in-memory transcript (a session is short; this only bounds a hostile flood).
    static let maxMessages = 500

    /// The current session's messages, oldest-first (append order). Empty outside a session.
    public private(set) var messages: [Message] = []

    /// Count of inbound messages that arrived while the chat panel was NOT on screen (TF b19 item 6).
    /// Drives the unread dot on the in-session chat button + the receive haptic/notification. Memory-
    /// only like the transcript itself (the holder is not Codable), so it never enters a snapshot; it
    /// resets to zero when the panel is opened (`beginViewing` / `markAllRead`) and when the session
    /// clears. Only inbound messages count — a local echo of an outgoing message is never "unread".
    public private(set) var unreadCount = 0

    /// True while the chat panel is on screen. While viewing, an inbound message is shown live, so it
    /// is never counted as unread (and any standing unread is cleared the moment viewing begins).
    @ObservationIgnored private var isViewing = false

    public var hasUnread: Bool { unreadCount > 0 }

    /// Dedup set across incoming AND outgoing ids — a reflected/duplicate id is never appended twice.
    @ObservationIgnored private var seenIDs: Set<UUID> = []
    /// Per-verified-sender token-bucket state for the receive flood guard.
    @ObservationIgnored private var rateBucketBySender: [String: (tokens: Double, updated: Date)] = [:]

    public init() {}

    // MARK: - Outbound (local echo)

    /// Appends the local echo of a just-sent message. `text` is already sanitized + capped by the
    /// sender (`MeshNetworkManager.sendTempMessage`). Idempotent by id.
    func appendOutgoing(
        id: UUID,
        senderFingerprint: String,
        senderDisplayName: String,
        text: String,
        sentAt: Date
    ) {
        guard seenIDs.insert(id).inserted else { return }
        append(Message(
            id: id,
            senderFingerprint: senderFingerprint,
            senderDisplayName: senderDisplayName,
            text: text,
            sentAt: sentAt,
            isOutgoing: true
        ))
    }

    // MARK: - Inbound (called by MeshNetworkManager's registered handler)

    /// Accepts a verified `.tempMessage` from a committed, unblocked peer. The caller
    /// (`MeshNetworkManager`) has already enforced the committed-slot gate and the blocked-fingerprint
    /// drop; `senderFingerprint` is the transport-authenticated identity, never a wire claim.
    ///
    /// Applies, in order: dedup by id, per-sender rate limit, sanitize + length-cap (empty after
    /// sanitize is dropped). Returns true iff the message was appended (test seam).
    @discardableResult
    func receiveIncoming(
        id: UUID,
        senderFingerprint: String,
        senderDisplayName: String,
        text rawText: String,
        sentAt: Date,
        now: Date = Date()
    ) -> Bool {
        guard !seenIDs.contains(id) else { return false }

        // Token-bucket flood guard: refill by elapsed time (capped at the burst allowance), then
        // require one whole token to accept. A burst of ordinary double-texts passes; a sustained
        // flood is throttled to `refillPerSecond`.
        let prior = rateBucketBySender[senderFingerprint]
        let elapsed = prior.map { max(0, now.timeIntervalSince($0.updated)) } ?? 0
        let available = min(Self.burstAllowance, (prior?.tokens ?? Self.burstAllowance) + elapsed * Self.refillPerSecond)
        guard available >= 1 else {
            // Keep the refilled level so tokens keep accruing while the flood continues.
            rateBucketBySender[senderFingerprint] = (available, now)
            return false
        }

        let text = Self.sanitize(rawText)
        guard !text.isEmpty else { return false }

        // Only record dedup + bucket state once the message is actually accepted, so a dropped
        // (empty/rate-limited) message never poisons a later legitimate one from the same sender.
        seenIDs.insert(id)
        rateBucketBySender[senderFingerprint] = (available - 1, now)

        let name = ItemNameModeration.sanitizedName(senderDisplayName)
        append(Message(
            id: id,
            senderFingerprint: senderFingerprint,
            senderDisplayName: name.isEmpty ? "A friend" : name,
            text: text,
            sentAt: sentAt,
            isOutgoing: false
        ))
        // TF b19 item 6: a message that arrives while the panel is closed is unread. While the panel is
        // on screen the user is already reading, so it stays at zero.
        if !isViewing { unreadCount += 1 }
        return true
    }

    // MARK: - Unread state (TF b19 item 6)

    /// The chat panel appeared: mark the transcript read and suppress unread counting until it leaves.
    /// Called from `SessionChatPanel.onAppear`.
    public func beginViewing() {
        isViewing = true
        if unreadCount != 0 { unreadCount = 0 }
    }

    /// The chat panel left the screen: resume unread counting for later inbound messages. Called from
    /// `SessionChatPanel.onDisappear`.
    public func endViewing() {
        isViewing = false
    }

    /// Clears the unread badge without changing the viewing state. `beginViewing()` already does this;
    /// exposed separately so a caller can drop the badge without asserting the panel is open.
    public func markAllRead() {
        if unreadCount != 0 { unreadCount = 0 }
    }

    // MARK: - Session lifecycle

    /// Drops the whole transcript — the session ended (messages vanish) or a new one formed. Memory
    /// only; nothing to flush.
    public func clear() {
        messages.removeAll()
        seenIDs.removeAll()
        rateBucketBySender.removeAll()
        // Reset the badge, but leave `isViewing` to the panel's own onAppear/onDisappear — a session may
        // clear (formation / end) while the panel is still on screen, and forcing it false there would
        // make the next inbound message count as unread even though the user is looking at it.
        unreadCount = 0
    }

    // MARK: - Text sanitizer

    /// Coerce untrusted (wire-received or user-typed) message text into a safe shape WITHOUT throwing:
    /// drop control / zero-width / bidi-override scalars, collapse whitespace runs to single spaces,
    /// trim, and cap length. Mirrors `ItemNameModeration.sanitizedName`'s never-throw boundary coercion
    /// but at the message length cap. Does NOT screen profanity — chat is not a listed cosmetic label.
    public static func sanitize(_ raw: String) -> String {
        let kept = raw.unicodeScalars.filter { scalar in
            !CharacterSet.controlCharacters.contains(scalar)
                && !invisibleScalars.contains(scalar)
        }
        let collapsed = String(String.UnicodeScalarView(kept))
            .components(separatedBy: .whitespacesAndNewlines)
            .filter { !$0.isEmpty }
            .joined(separator: " ")
        return String(collapsed.prefix(maxTextLength))
    }

    /// Zero-width and bidirectional-override format characters that can hide or reorder text (same set
    /// as `ItemNameModeration`, kept local so the sanitizer is self-contained).
    private static let invisibleScalars: CharacterSet = CharacterSet(charactersIn:
        "\u{200B}\u{200C}\u{200D}\u{200E}\u{200F}\u{202A}\u{202B}\u{202C}\u{202D}\u{202E}"
            + "\u{2060}\u{2066}\u{2067}\u{2068}\u{2069}\u{FEFF}")

    // MARK: - Private

    private func append(_ message: Message) {
        messages.append(message)
        if messages.count > Self.maxMessages {
            // Drop oldest; keep dedup ids so a re-send of a dropped id doesn't resurrect it.
            messages.removeFirst(messages.count - Self.maxMessages)
        }
    }
}
