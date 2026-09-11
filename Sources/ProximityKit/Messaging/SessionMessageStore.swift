import Foundation
import Observation
import FernletDomainModel

/// The live-session temporary-message store (Phase 5, Docs/Proximity-Mesh-Redesign-2026-07-10.md).
///
/// Owner decision (binding): the visible transcript exists ONLY during a live friend session and
/// VANISHES at session end — nothing synced, no dead-drop, no offline queue. This type is the only
/// in-memory holder of that transcript, and it is deliberately **NOT Codable**: it is structurally
/// impossible for a message to enter a `FernletSnapshot` (mirrors
/// `MeshSessionRosterEntry`/`MeshFriendReviewBatch`, which are equally non-Codable memory-only
/// state). Owned by `MeshNetworkManager`, which drives the whole lifecycle:
///  - **Outbound** — `sendTempMessage(_:)` sanitizes, byte-bounds and frames the text, mints a
///    routed item for it, and appends the local echo here **only once the mint staged**.
///  - **Inbound** — the routed projection's `.sessionTranscript` arm calls
///    ``receiveIncoming(id:senderFingerprint:senderDisplayName:text:sentAt:seenAt:)``, which dedupes
///    by ``MeshContentKey`` (author **and** id), sanitizes, caps, and returns which of the three
///    things it did. The author's fingerprint
///    is the origin's signed one resolved against the admission ledger, with the block list and the
///    removal set applied **before** the content key is unwrapped; the display name is the body's
///    own claim, re-moderated here.
///  - **Clear** — the manager calls `clear()` at EVERY session-end path and on the next session
///    formation, through one funnel (`clearSessionTranscript()`) that also bumps
///    `transcriptGeneration`, which is what the projection keys on.
///
/// ## The transcript is a DERIVATION, not an append log (plan §10.3, §12)
///
/// The store holds a ``MeshContentSet`` of ``MeshMergedMessage`` and derives ``messages`` from
/// `MeshContentLedger.visibleTranscript(gates:)` on every change. That is §12's own word —
/// *re-derive* — and it is what the routed path needs rather than a nicety: a backlog drains in
/// index order, `(originFingerprint, itemID)`, so a device joining a chat in progress would
/// otherwise see the transcript grouped by sender and shuffled within it. The order is §10.3's
/// `(claimedSentAt clamped to ±10 min of first-seen, senderFingerprint, messageID)` plus a
/// content-derived last resort, already implemented and tested in `MeshContentMerge.swift`.
///
/// Two things follow from the shape rather than from an argument: the 500-row cap drops the oldest
/// **in that order** instead of in arrival order, and a member that turns its age gate or a block
/// off sees the affected rows again with no second delivery, because the gate is a view filter over
/// an unmutated union.
///
/// ## A row's identity is `(author, id)`, never the id alone (P6 item 4 fix review, P1-1)
///
/// Every dedup here — ``seenKeys``, the held ``MeshContentSet``, the attribution table and
/// ``Message/id`` itself — keys on ``MeshContentKey``. The id on the wire is the **origin's own
/// choice**, the routed index's key is `(originFingerprint, itemID)`, and the signed manifest
/// carrying that id reaches the whole roster-at-creation in the clear before the content does — so
/// an admitted member could otherwise read another member's message id, mint its own text under it,
/// win the race to a partitioned third device, and have the genuine message land `alreadyHeld` →
/// marked final → gone for the session, while its sender saw `.staged`. The key is local: nothing
/// about the manifest or the body changed.
///
/// The gate value arrives through ``refreshGates(chatAllowed:isRefused:)``, which the manager calls
/// at every ingest — **and only there**. A block or an age-gate flip therefore re-renders at the
/// NEXT ingest, not at the flip: the arm that folds the gates is the text projection itself, and it
/// is unreachable while `isChatAllowed` is false, so a mid-session flip changes nothing visible
/// until another message arrives. That is display only, and deliberately so — the *projection* is
/// fail-closed at both ends (`projectableRoutedTypeTokens` omits `.sessionTranscript` while the
/// gate is shut, and the live arm marks a gated item final), which is the load-bearing half and is
/// tested. Its `isRefused` half is `ProximityHost.isBlockedFingerprint` and **not** yet
/// `ModerationBanStore.isPeerBanned`: the ban store is not reachable from `ProximityHost`, so the
/// routed path consults the block half only — the same gap the photo arm has, inherited and named
/// rather than silently different.
///
/// ## What P3's sealed store did and did not change (plan §17.3)
///
/// P3 gave ProximityKit its first durable surface, ``MeshSessionContext``, sealed by
/// ``MeshSessionStore``. **This projection is untouched by that** — it is memory-only and not
/// `Codable`, so a message still cannot reach a snapshot.
///
/// What P6 item 4 changed is what lies BENEATH it. Chat now rides the routed store, so each message
/// is also held as **sealed ciphertext** — by its origin and by every destination, this device
/// included — until the item expires at `mesh hardDeadline + 20 min`. Said plainly: the *visible
/// transcript* still vanishes at session end, and the ciphertext does not. It is covered by the
/// routed store's existing `Docs/PrivacyWipeCoverage.md` row and its delete-all wiring — no new
/// persisted surface, no new row — and it is why §17.3's privacy sentence is now plural.
@MainActor
@Observable
public final class SessionMessageStore {

    /// A single message in the current session's transcript. Value-typed + `Sendable` so views can key
    /// off it; never persisted (its holder is not Codable).
    public struct Message: Identifiable, Equatable, Sendable {

        /// The row's identity: the **author and the id together** (P6 item 4 fix review, P1-1).
        ///
        /// `Identifiable`'s `id`, so the transcript's `ForEach` is keyed on something unique: two
        /// origins may legitimately mint one message id, and both rows land.
        public var id: MeshContentKey {
            MeshContentKey(senderFingerprint: senderFingerprint, contentID: messageID)
        }
        /// The author's own message id — equal to the routed item id the origin signed.
        public let messageID: UUID
        /// Transport-VERIFIED sender fingerprint (local fingerprint for outgoing). Never a wire claim.
        public let senderFingerprint: String
        public let senderDisplayName: String
        public let text: String
        /// The message's ordering instant: the sender's claim, **clamped** to ±10 minutes of when
        /// this device first saw the item (plan §10.3). The clamped value is what is stored and
        /// rendered, deliberately — the UI shows relative times, and a message claiming 1999 must
        /// not render as 1999. For an outgoing message the clamp is the identity.
        public let sentAt: Date
        public let isOutgoing: Bool

        public init(
            messageID: UUID,
            senderFingerprint: String,
            senderDisplayName: String,
            text: String,
            sentAt: Date,
            isOutgoing: Bool
        ) {
            self.messageID = messageID
            self.senderFingerprint = senderFingerprint
            self.senderDisplayName = senderDisplayName
            self.text = text
            self.sentAt = sentAt
            self.isOutgoing = isOutgoing
        }
    }

    /// Max characters a message may carry. A hostile peer over-length is capped, not dropped.
    ///
    /// `nonisolated` for the same reason ``maxMessages`` is: ``MeshRoutedTextBody`` is a
    /// `nonisolated` value type and its wire byte bound is stated as a multiple of this number
    /// rather than as a second literal (P6 item 4). **It is a `Character` cap, not a byte cap** —
    /// a grapheme cluster is unbounded in bytes — which is exactly why the routed row needs its
    /// own.
    public nonisolated static let maxTextLength = 500
    /// Hard cap on the in-memory transcript (a session is short; this only bounds a hostile flood).
    /// `nonisolated` so the merge layer can reuse it rather than restate it: `MeshMergedMessage`
    /// is a `nonisolated` value type and its `setCapacity` is this number (plan §10.3).
    nonisolated static let maxMessages = 500

    /// What the routed projection did with one offered message — three facts a single `Bool` used
    /// to conflate (P6 item 4).
    ///
    /// The caller needs the distinction because it decides whether the routed item still owes the
    /// projection anything, and **all three are final**: ``seenKeys`` deliberately never forgets a
    /// dropped key ("a re-send cannot resurrect them"), and "empty after sanitizing" is a
    /// deterministic verdict over origin-signed bytes. Frozen English tokens — audit vocabulary,
    /// never user copy.
    ///
    /// `alreadyHeld` is a statement about **this author's** id and no one else's (P1-1): the key is
    /// `(senderFingerprint, id)`, so another member cannot spend it.
    public enum Acceptance: String, Equatable, Sendable {
        /// The message entered the held set, and shows unless a gate filters it.
        case appended
        /// This author's copy of this id has already been seen — a duplicate delivery, or this
        /// device's own echo.
        case alreadyHeld
        /// Nothing survived the sanitizer.
        case emptyAfterSanitizing
    }

    /// The current session's visible messages, oldest-first in §10.3's total order. Empty outside a
    /// session.
    ///
    /// **Derived**, never appended to: it is `MeshContentLedger.visibleTranscript(gates:)` over
    /// ``held``, recomputed on every ingest and on every gate change. See the type's own note on
    /// why that is §12's word and what follows from it.
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

    /// Dedup set across incoming AND outgoing rows, keyed on ``MeshContentKey`` — the author and
    /// the id — so a reflected or duplicate delivery is never appended twice and **another
    /// member's message id is not this member's to spend** (P6 item 4 fix review, P1-1).
    @ObservationIgnored private var seenKeys: Set<MeshContentKey> = []
    /// Insertion order for ``seenKeys``, so the set can evict oldest-first at its cap.
    @ObservationIgnored private var seenOrder: [MeshContentKey] = []

    /// The messages this device HOLDS — the union half of plan §10.3, capped at
    /// `MeshMergedMessage.setCapacity` (which is ``maxMessages``) by the set itself.
    ///
    /// Unfiltered on purpose: a gate is a view filter over this, so turning one off does not
    /// destroy the rows it was hiding.
    @ObservationIgnored private var held: MeshContentSet<MeshMergedMessage> = .empty

    /// What ``held`` cannot carry, per ``MeshContentKey``: the display name the message arrived
    /// with and whether it was ours.
    ///
    /// ``MeshMergedMessage`` is the merge layer's value and holds no display name and no direction —
    /// correctly, because neither participates in the order or the union. Pruned to ``held``'s own
    /// keys on every insert, so it is bounded by the same 500 (R3). Keyed on the pair rather than
    /// the id so two authors' rows carrying one id cannot overwrite each other's name and
    /// direction (P1-1).
    @ObservationIgnored private var attributionByKey:
        [MeshContentKey: (displayName: String, isOutgoing: Bool)] = [:]

    /// This member's own view gates — the 13+ chat gate and the local block/ban set — folded from
    /// the live seams by ``refreshGates(chatAllowed:isRefused:)``.
    ///
    /// `.open` until the manager folds them, which it does at every ingest: a store nobody has told
    /// about a block shows what it holds, and the routed projection additionally refuses a blocked
    /// or removed origin **before** the unwrap, so this is the second of two ends.
    @ObservationIgnored private var gates: MeshContentGates = .open

    public init() {}

    // MARK: - Outbound (local echo)

    /// Appends the local echo of a just-STAGED message. `text` is already sanitized and
    /// byte-bounded by the sender (`MeshNetworkManager.sendTempMessage`). Idempotent by id.
    ///
    /// The sender calls this only on `.staged` (P6 item 4): a photo's echo is unconditional because
    /// the photo is on the user's own wall either way, but a row in a transcript is a claim that
    /// the message was *sent*, and the transcript has no failed-row state to correct it with.
    ///
    /// Own messages need no clamp — `claimedSentAt` and `firstSeenAt` are both this device's clock,
    /// so the clamp is the identity.
    func appendOutgoing(
        id: UUID,
        senderFingerprint: String,
        senderDisplayName: String,
        text: String,
        sentAt: Date
    ) {
        // Keyed on this device's OWN fingerprint, exactly as an inbound row is keyed on its
        // author's, so the echo and a hypothetical reflection of it are one row and another
        // member's same-id message is a different one (P1-1).
        let key = MeshContentKey(senderFingerprint: senderFingerprint, contentID: id)
        guard !seenKeys.contains(key) else { return }
        rememberSeen(key)
        hold(
            MeshMergedMessage(
                messageID: id, senderFingerprint: senderFingerprint, text: text,
                claimedSentAt: sentAt, firstSeenAt: sentAt
            ),
            displayName: senderDisplayName,
            isOutgoing: true
        )
    }

    // MARK: - Inbound (called by MeshNetworkManager's registered handler)

    /// Accepts one routed text item's plaintext from an author the projection has already resolved
    /// and authorized.
    ///
    /// What the caller has already done, and this must therefore not re-do: resolved
    /// `senderFingerprint` from the origin's **signed** manifest against `admissions − removals`,
    /// applied the block list and the removal set before the content key was unwrapped, re-applied
    /// the 13+ gate, judged the session live, and spent the per-origin routed quota.
    /// `senderDisplayName` is the body's own display claim and is re-moderated here.
    ///
    /// Applies, in order: dedup by `(senderFingerprint, id)`, sanitize + length-cap (empty after
    /// sanitize is refused). The dedup key is the PAIR and not the id, because the id is the
    /// origin's own choice and its manifest publishes it to the whole roster before the content
    /// arrives (P6 item 4 fix review, P1-1).
    ///
    /// **`seenAt` is required, not defaulted** (P6 item 4, D-13.36's direction). It is the
    /// RECEIVER's instant at which this item entered this device's view — the re-entry pass reads
    /// `MeshRoutedItemRef.firstSeenAt`, which the index already stores, and the live path passes the
    /// pass's own injected instant — and it is the anchor §10.3's clamp bounds a forged
    /// `sentAt` against. Replacing the old `now: Date = Date()` with it takes a defaulted clock out
    /// of a surface the projection touches.
    ///
    /// - Returns: which of the three things happened. All three are final for the routed item.
    func receiveIncoming(
        id: UUID,
        senderFingerprint: String,
        senderDisplayName: String,
        text rawText: String,
        sentAt: Date,
        seenAt: Date
    ) -> Acceptance {
        let key = MeshContentKey(senderFingerprint: senderFingerprint, contentID: id)
        guard !seenKeys.contains(key) else { return .alreadyHeld }
        let text = Self.sanitize(rawText)
        guard !text.isEmpty else { return .emptyAfterSanitizing }

        // Only record the dedup key once the message is actually accepted, so a dropped (empty)
        // message never poisons a later legitimate one carrying the same id.
        rememberSeen(key)
        hold(
            MeshMergedMessage(
                messageID: id, senderFingerprint: senderFingerprint, text: text,
                claimedSentAt: sentAt, firstSeenAt: seenAt
            ),
            displayName: ItemNameModeration.moderatedPeerDisplayName(senderDisplayName),
            isOutgoing: false
        )
        // TF b19 item 6: a message that arrives while the panel is closed is unread. While the panel is
        // on screen the user is already reading, so it stays at zero — and a row a gate is filtering
        // is not something the user can go and read, so it never counts either.
        if !isViewing, messages.contains(where: { $0.id == key }) { unreadCount += 1 }
        return .appended
    }

    /// Re-folds this member's view gates from the live seams and re-derives the transcript.
    ///
    /// Called by the manager at every ingest, so the gate value can never disagree with the seam it
    /// came from (`MeshContentGates.folding`'s own contract). Because the transcript is a
    /// derivation, a gate that closes hides rows without destroying them and a gate that re-opens
    /// shows them again with no second delivery.
    ///
    /// **The trigger is the next INGEST, not the flip** (P6 item 4 fix review, P3-3). The one
    /// shipping caller is the routed text arm, which is unreachable while `isChatAllowed` is false,
    /// so a block or an age-gate flip mid-session changes nothing *visible* until another message
    /// arrives. That is the display half only: the projection is fail-closed at both ends and is
    /// tested, so nothing new is shown — a row that should now be hidden stays on screen until the
    /// next ingest. Calling this from the gate's own setter would re-render on the flip; it is not
    /// wired that way because the setters are the app's (`ProximityHost`, `AgeAssurance`) and the
    /// store is not observable from them.
    ///
    /// - Parameters:
    ///   - chatAllowed: `MeshNetworkManager.isChatAllowed` at this member.
    ///   - isRefused: `ProximityHost.isBlockedFingerprint` ∪ `ModerationBanStore.isPeerBanned`.
    func refreshGates(chatAllowed: Bool, isRefused: (String) -> Bool) {
        gates = MeshContentGates.folding(
            chatAllowed: chatAllowed,
            senders: MeshContentLedger(messages: held).senders,
            isRefused: isRefused
        )
        rederiveTranscript()
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
        held = .empty
        attributionByKey.removeAll()
        gates = .open
        seenKeys.removeAll()
        seenOrder.removeAll()
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

    /// R3: the dedup set is fed by peer messages, so it needs its own explicit cap — the 500-row
    /// transcript cap does not bound it (dropped keys are deliberately kept so a re-send cannot
    /// resurrect them). A key older than `maxSeenIDs` messages is past any realistic re-send window.
    static let maxSeenIDs = maxMessages * 4

    private func rememberSeen(_ key: MeshContentKey) {
        guard seenKeys.insert(key).inserted else { return }
        seenOrder.append(key)
        guard seenOrder.count > Self.maxSeenIDs else { return }
        let evicted = seenOrder.prefix(seenOrder.count - Self.maxSeenIDs)
        // R2: bounded by the overflow this call created.
        for old in evicted { seenKeys.remove(old) }
        seenOrder.removeFirst(evicted.count)
    }

    /// Puts one message into the held union with its attribution, then re-derives.
    ///
    /// The 500-row cap is the SET's (`MeshMergedMessage.setCapacity`), which keeps the newest k
    /// under §10.3's order rather than the last k to arrive — the same statement the old
    /// `removeFirst` made, with the correct result on a backlog that drains out of send order.
    private func hold(_ message: MeshMergedMessage, displayName: String, isOutgoing: Bool) {
        held = held.inserting(message)
        attributionByKey[message.mergeKey] = (displayName, isOutgoing)
        let kept = held.mergeKeys
        // R3: the attribution table is pruned to the set's own keys, so it is bounded by the same
        // `setCapacity` and an evicted row cannot leak an entry for the session's lifetime.
        attributionByKey = attributionByKey.filter { kept.contains($0.key) }
        rederiveTranscript()
    }

    /// Re-derives ``messages`` from the held union and this member's gates — plan §12's
    /// "re-derive transcript (§10.3 ordering), re-apply age gate + moderation", as one expression.
    ///
    /// A held row whose attribution is somehow missing is dropped from the VIEW rather than shown
    /// with an invented name: `hold(_:displayName:isOutgoing:)` writes both together and prunes
    /// them together, so the case is unreachable, and answering it by omission keeps that true
    /// without a trap.
    private func rederiveTranscript() {
        messages = MeshContentLedger(messages: held)
            .visibleTranscript(gates: gates)
            .compactMap { merged in
                guard let who = attributionByKey[merged.mergeKey] else { return nil }
                return Message(
                    messageID: merged.messageID,
                    senderFingerprint: merged.senderFingerprint,
                    senderDisplayName: who.displayName,
                    text: merged.text,
                    sentAt: merged.orderingInstant,
                    isOutgoing: who.isOutgoing
                )
            }
    }
}
