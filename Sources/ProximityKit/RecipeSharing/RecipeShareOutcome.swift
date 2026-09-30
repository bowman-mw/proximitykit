import Foundation

// MARK: - RecipeShareFailure

/// Why one recipe share did not go out, or did not finish going out: the frozen cause the share
/// sheet turns into its own localized sentence.
///
/// ## Tokens, not copy
///
/// No display text lives here. ProximityKit has no business choosing the words the user reads, and
/// a `String` composed in this module would be English forever (the localization wall's failure
/// mode A). The app target maps each case to a catalog sentence in `RecipeShareConfirmation`, and
/// that switch is exhaustive, so a new case here is a build error there until it has honest copy.
///
/// ## Two different facts
///
/// Six of the seven cases mean **nothing left this device**: the share was refused, or it ended
/// before the sealed payload was handed to the transport. ``sendIncomplete`` is the odd one out. The
/// payload had started going out when the send failed or was cut off, so the other person **may**
/// have it. The copy must never merge the two, which is what ``mayHaveReachedRecipient`` is for.
///
/// There is deliberately no "delivered", "received", "accepted" or "queued" case. The recipe radio
/// has no application receipt (the receiver's Import/Decline sends nothing back) and no routed or
/// held path (recipe sharing is strictly one pairing at a time, in person), so this module can never
/// know any of those things.
public nonisolated enum RecipeShareFailure: CaseIterable, Equatable, Sendable {

    /// This device is already paired with a DIFFERENT Fernlet, and recipe sharing links two
    /// Fernlets at a time. Refused before anything was attempted.
    case pairedWithAnother

    /// A connection attempt to a different Fernlet was already in flight. Refused before anything
    /// was attempted.
    case connectingToAnother

    /// The picked Fernlet was no longer discoverable when the share began.
    case recipientUnavailable

    /// The pre-connect timer ran out: the other Fernlet never answered the dial (the usual reason is
    /// that it is busy with its own pairing, locked, or closed).
    case noAnswer

    /// The channel came up but the pairing ended before it was verified (a blocked or revoked key,
    /// the handshake budget, a dropped peer, or the stalled-connection sweep). Nothing was sent.
    case couldNotConnect

    /// The radio was stood down (the share sheet closed, the scene went inactive, the app lock
    /// engaged, or a search restarted) before the payload was handed over. Nothing was sent.
    case interrupted

    /// The send had begun and then threw, was refused as a duplicate, or was cut off by a stop. The
    /// other person may or may not have the recipe.
    case sendIncomplete

    /// Whether the other person might nonetheless hold the recipe: true only for
    /// ``sendIncomplete``. Every other case is "nothing left this device".
    public var mayHaveReachedRecipient: Bool {
        switch self {
        case .sendIncomplete:
            return true
        case .pairedWithAnother, .connectingToAnother, .recipientUnavailable, .noAnswer,
             .couldNotConnect, .interrupted:
            return false
        }
    }
}

// MARK: - RecipeShareOutcome

/// How one recipe share ended, published by ``ProximityRecipeShareManager/lastShareOutcome`` so the
/// share sheet can say so plainly instead of silently clearing.
///
/// ## Why this exists beside `SendState`
///
/// ``ProximityRecipeShareManager/SendState`` is display copy for a status line: its failure arm is
/// an English sentence composed in this module, and every terminal state is reset to `.idle` 2.5 s
/// later. Neither property is usable for a confirmation that has to stay on screen until the user
/// dismisses it and has to be translated. This value is the record: a frozen cause
/// (``RecipeShareFailure``), the names it happened to, and a fresh ``id`` per publication, so two
/// identical failures in a row are still two changes an observer can see.
///
/// ## What `sent` means, exactly
///
/// ``Result/sent`` means the coordinator's `sendPayload` returned: the sealed payload was handed to
/// the QUIC transport. For a text recipe that is the control stream's send completing; a recipe that
/// carries a picture rides a stream of its own and also reads the peer's one-byte transport ack. It
/// is **never** an application receipt. The other device can still drop the share (its per-sender
/// rate limit, a full review queue, a payload it refuses to decode), and the person can decline it.
/// Nothing is ever sent back. Copy built on this value must say "sent", never "delivered".
///
/// Identity-free by construction apart from the two names the user already saw on screen (the row
/// they tapped and the recipe they picked). No fingerprint, key or payload body rides it.
public nonisolated struct RecipeShareOutcome: Equatable, Identifiable, Sendable {

    /// The two ways a share can end.
    public nonisolated enum Result: Equatable, Sendable {

        /// The sealed payload was handed to the transport. See the type's discussion for why this
        /// is not "delivered".
        case sent

        /// The share did not go out, or did not finish going out, for the given reason.
        case notSent(RecipeShareFailure)
    }

    /// Fresh per publication, so an observer sees every outcome, including a repeat of the last one.
    public let id: UUID

    /// The picker row the user tapped (``ProximityRecipeShareRecipient/id``).
    public let recipientID: UUID

    /// The name that row showed when the user tapped it.
    public let recipientName: String

    /// The recipe's title as the payload carries it.
    public let recipeTitle: String

    /// The Fernlet this device is already paired with. Set only for
    /// ``RecipeShareFailure/pairedWithAnother``, so the sheet can name who is holding the link.
    public let otherPeerName: String?

    /// How the share ended.
    public let result: Result

    /// An outcome record.
    ///
    /// - Parameters:
    ///   - id: The publication's identity. Defaults to a fresh value; a caller that reused one would
    ///     make a second outcome invisible to an observer comparing by value.
    ///   - recipientID: The picker row the share was for.
    ///   - recipientName: The name that row showed.
    ///   - recipeTitle: The recipe's title.
    ///   - otherPeerName: The already-paired Fernlet, for ``RecipeShareFailure/pairedWithAnother``.
    ///   - result: How the share ended.
    public init(
        id: UUID = UUID(),
        recipientID: UUID,
        recipientName: String,
        recipeTitle: String,
        otherPeerName: String? = nil,
        result: Result
    ) {
        self.id = id
        self.recipientID = recipientID
        self.recipientName = recipientName
        self.recipeTitle = recipeTitle
        self.otherPeerName = otherPeerName
        self.result = result
    }
}
