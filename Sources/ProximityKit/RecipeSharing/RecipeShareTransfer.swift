import Foundation
import FernletDomainModel

// MARK: - RecipeShareDiscoveryGate

/// Whether the recipe-share radio should be quiet to new peers right now — the whole of the
/// pause/resume contract, said once, as a value.
///
/// ## Why this is a value and not two call sites
///
/// "The radio closes once two devices connect" is a **shipped, user-visible behaviour**: while a
/// pairing is held this device can neither be seen nor invited by a third Fernlet, and it reopens
/// when the pairing's manager-level record is evicted. Plan §17.1 asks P9 to preserve it across the
/// move to QUIC, and it is precisely the kind of behaviour a transport swap loses silently — the
/// bytes still flow, the share still lands, and the only symptom is a third device that can suddenly
/// see a paired one.
///
/// Under MultipeerConnectivity the two decisions lived as two bare calls
/// (`session.pauseDiscovery()` inside `registerConnection`, `session.resumeDiscovery()` inside
/// `finalizeConnectionRemovals`), each guarded by a different inline condition. Neither was reachable
/// without a manager, and the conditions could drift apart without anything noticing. Here they are
/// one total function over the radio's three facts, so a pass-2 session can be bound to the same
/// table rather than to a reading of two guard chains.
///
/// ## The two rules the table exists to freeze
///
/// * **Resume is keyed on manager-level RECORD eviction, never on a transport disconnect event.** A
///   failed handshake fires no disconnect at all, so keying on one leaves the radio paused forever
///   with no connection — the deadlock the 2-device redesign closed.
/// * **A stopped radio never resumes.** `isRunning` is part of the verdict because a resume over a
///   stopped radio would put a Bonjour registration (and, under QUIC, a listener) back up behind a
///   manager that believes it is dark.
///
/// Pure, bounded, clock-free and `nonisolated`, so the policy is settled at tier 1 and every radio
/// only acts on the answer.
nonisolated enum RecipeShareDiscoveryGate {

    /// What the radio is holding at the instant an event arrives.
    struct Radio: Equatable, Sendable {

        /// Whether the manager considers the radio up — `ProximityRecipeShareManager.isListening`.
        let isRunning: Bool

        /// Whether discovery is already standing down.
        let isPaused: Bool

        /// How many connection records the manager holds AFTER applying the event.
        let connectionCount: Int

        /// A radio reading. `connectionCount` is the count *after* the event, which is what makes
        /// ``RecipeShareDiscoveryGate/Event/connectionsEvicted`` answerable without a second field.
        init(isRunning: Bool, isPaused: Bool, connectionCount: Int) {
            self.isRunning = isRunning
            self.isPaused = isPaused
            self.connectionCount = connectionCount
        }
    }

    /// The five things that happen to the recipe radio's discovery.
    enum Event: Equatable, Sendable {

        /// A connection record was just added (`registerConnection`), for either role.
        case connectionRegistered

        /// One or more connection records were just dropped — every removal path funnels through
        /// `finalizeConnectionRemovals`: the peer-disconnect eviction, the stale `.ended`/`.failed`
        /// sweep, and the parked pre-verification sweep.
        case connectionsEvicted

        /// The user asked the share sheet to search again.
        case refreshRequested

        /// The advertiser or browser failed to (re)start while the radio believed it was listening.
        case transportErrorWhileListening

        /// The manager stood the whole radio down.
        case stopped
    }

    /// What to do to the radio's discovery.
    enum Verdict: Equatable, Sendable {

        /// Stop advertising and browsing, keeping every live connection.
        case pause

        /// Reopen a paused radio.
        case resume

        /// Leave discovery exactly as it is.
        case unchanged
    }

    /// The verdict for one event against one radio reading.
    ///
    /// Total, and deliberately `.unchanged` for three of the five events: the contract's whole
    /// content is that discovery moves at exactly two moments and at no others. `refreshRequested`,
    /// `transportErrorWhileListening` and `stopped` all resolve through the radio's own
    /// `stop()`/`start()`, which clears the paused flag in the transport rather than through this
    /// gate — routing them here too would give one state two owners.
    static func verdict(for event: Event, radio: Radio) -> Verdict {
        switch event {
        case .connectionRegistered:
            // A register with nothing held is unreachable from the manager (the record is appended
            // first). Refusing it is the fail-safe direction: never close a radio holding nothing.
            guard radio.connectionCount > 0, !radio.isPaused else { return .unchanged }
            return .pause
        case .connectionsEvicted:
            guard radio.connectionCount == 0, radio.isRunning, radio.isPaused else { return .unchanged }
            return .resume
        case .refreshRequested, .transportErrorWhileListening, .stopped:
            return .unchanged
        }
    }
}

// MARK: - RecipeShareTransfer

/// One recipe share, from the moment the user picks a recipient to the moment the payload has
/// landed — as a state machine with an exactly-once completion.
///
/// ## What this pins that the manager could not
///
/// The send pipeline's observable half (`ProximityRecipeShareManager.SendState`) is display copy: it
/// exists to render a status line and is cleared 2.5 s after a terminal state. It is not a record of
/// what happened, it carries no refusal, and a second completion would simply overwrite the first.
/// This value is the record: every legal move is a row in the table below, every illegal one is a
/// refusal the caller can see, and a completion is counted rather than assigned.
///
/// | from \ event | `peerVerified` | `sendBegan` | `sendCompleted` | `sendFailed` | `cancelled` |
/// | --- | --- | --- | --- | --- | --- |
/// | `connecting` | `verified` | refused | refused | `failed` | `cancelled` |
/// | `verified` | `verified` | `sending` | refused | `failed` | `cancelled` |
/// | `sending` | `sending` | refused | `sent` | `failed` | `cancelled` |
/// | terminal | refused | refused | refused | refused | refused |
///
/// `peerVerified` is idempotent because the manager re-evaluates every coordinator on every
/// observation tick; `sendBegan` is not, because two send starts for one share is the defect.
/// `sendCompleted` from anywhere but `sending` is refused, which is what makes
/// ``completionCount`` an oracle rather than a counter: it can only ever be 0 or 1, and it is 1
/// exactly when ``phase`` is ``Phase/sent``.
///
/// ## The pause/resume row, which is the point of pass 1
///
/// ``Event/discoveryPaused`` and ``Event/discoveryResumed`` are accepted in **every** phase,
/// terminal included, and move the phase **not at all** — they only set ``radioIsQuiet``. Closing
/// the radio to new peers is not pausing a transfer in flight, and the two must never be confused:
/// under MultipeerConnectivity `pauseDiscovery()` stopped the advertiser and browser while the
/// MCSession and every live connection kept flowing, so a share in progress was untouched by the very
/// event that closed the door behind it. A QUIC session that implemented "pause" as standing the
/// connection down would break a send the retired radio kept alive, and the regression would look
/// like a flaky share rather than a transport change. This row is the wall against that.
///
/// Pure, `nonisolated`, clock-free and driven by no radio.
nonisolated struct RecipeShareTransfer: Equatable, Sendable {

    /// Where one share has got to.
    enum Phase: Equatable, Sendable {

        /// A recipient was picked; the pairing is being formed.
        case connecting

        /// The coordinator's sealed identity introduction completed for this recipient.
        case verified

        /// The sealed payload is on its way.
        case sending

        /// The peer acknowledged the sealed payload. Terminal.
        case sent

        /// The send threw, or the pairing failed before it. Terminal.
        case failed

        /// The user, a timeout or a teardown ended the share. Terminal.
        case cancelled

        /// Whether no further event can move this phase.
        var isTerminal: Bool {
            switch self {
            case .sent, .failed, .cancelled: return true
            case .connecting, .verified, .sending: return false
            }
        }
    }

    /// Everything that happens to one share.
    enum Event: Equatable, Sendable {

        /// The coordinator reported `.connected` with a verified peer identity.
        case peerVerified

        /// The encoded payload is about to be handed to the coordinator, carrying its plaintext
        /// size so the route can be projected without the value ever holding the bytes.
        case sendBegan(wireByteCount: Int)

        /// `sendPayload` returned.
        case sendCompleted

        /// `sendPayload` threw.
        case sendFailed

        /// The recipient went away, the pre-connect timeout fired, or the manager stopped.
        case cancelled

        /// Discovery stood down. **Never moves the phase** — see the type's discussion.
        case discoveryPaused

        /// Discovery reopened. **Never moves the phase.**
        case discoveryResumed
    }

    /// The picker row this share is for — `ProximityRecipeShareRecipient.id`.
    let recipientID: UUID

    /// This record's own identity, minted per SEND.
    ///
    /// ``recipientID`` cannot do this job: a second share to the SAME already-paired peer mints a
    /// second record carrying the same recipient, and the first send is still in flight. Its
    /// completion then arrives against a record that is not the one it began, and — because
    /// `sendCompleted` is legal from `sending` — is counted there. The oracle still holds inside
    /// each record; what breaks is the attribution, which is the user-visible half: the status line
    /// says the second recipe landed when it is the first that did.
    ///
    /// So every send captures the token of the record it began and hands it back with its outcome,
    /// and `ProximityRecipeShareManager.applyTransfer(_:token:)` refuses an outcome whose token is
    /// not the live record's. Events that belong to whatever share is live — a verification, a
    /// teardown, a discovery pause — pass no token and are unaffected.
    let token: UUID

    /// Where the share has got to.
    private(set) var phase: Phase = .connecting

    /// How many times this share has completed. 0 or 1, and 1 exactly when ``phase`` is
    /// ``Phase/sent`` — the oracle a second completion path would break.
    private(set) var completionCount = 0

    /// Whether the radio is currently quiet to new peers. Independent of ``phase`` by construction.
    ///
    /// Seeded from the radio at the mint and moved afterwards only by ``Event/discoveryPaused`` /
    /// ``Event/discoveryResumed``, which are *transitions*. A second share to an already-paired peer
    /// is minted between transitions — the pairing, and its pause, already exist and no gate event
    /// follows — so a record that assumed an open radio would claim one for that whole share.
    private(set) var radioIsQuiet: Bool

    /// The encoded plaintext's size, once ``Event/sendBegan(wireByteCount:)`` has supplied it; 0
    /// before that.
    private(set) var wireByteCount = 0

    /// A share for `recipientID`, in ``Phase/connecting``, under a fresh ``token``.
    ///
    /// - Parameters:
    ///   - recipientID: The picker row the user chose.
    ///   - radioIsQuiet: The radio's stand-down state **at the mint** — the caller passes what the
    ///     radio actually holds (`isDiscoveryPaused`), never a guess. The default is the open radio
    ///     a share that has to form its pairing first will find.
    ///   - token: This record's identity. Defaulted to a fresh value, because a caller that could
    ///     reuse one would be handing two sends one attribution — the defect the token exists for.
    init(recipientID: UUID, radioIsQuiet: Bool = false, token: UUID = UUID()) {
        self.recipientID = recipientID
        self.radioIsQuiet = radioIsQuiet
        self.token = token
    }

    /// Which pipe this share's payload would ride over a QUIC tunnel, or nil before the size is
    /// known.
    ///
    /// A text-only recipe is a few kilobytes and stays on the control stream; a recipe carrying a
    /// picture (`ProximityRecipeSharePayload.maxImageBytes`, 512 KiB, base64'd into the JSON) clears
    /// ``MeshTransferStreamTable/bulkFloorBytes`` and earns a stream of its own.
    ///
    /// **It is an estimate in both directions, not a floor.** The size here is the *plaintext* the
    /// manager encodes, and the radio routes on the sealed frame's real size —
    /// `SealedPayloadFraming.frame` DEFLATES a body of 128 bytes or more whenever that shrinks it,
    /// so a verbose text recipe of 70 KiB can seal to well under the floor and ride the control
    /// stream after all. Nothing acts on this value; it is what said, at pass 1, that this radio
    /// would need a per-transfer-stream acceptor. The two real cases — a text recipe, and a picture
    /// recipe at ~693 KiB on the wire after base64 — sit on the same side of the floor either way.
    ///
    /// Projected rather than acted on. Pass 1 moves no bytes; the projection is what tells pass 2
    /// that a recipe radio needs a per-transfer-stream acceptor, which the presence radio
    /// deliberately has none of.
    var route: MeshTransferRoute? {
        guard wireByteCount > 0 else { return nil }
        return MeshTransferStreamTable.route(reliableByteCount: wireByteCount)
    }

    /// Applies one event.
    ///
    /// - Returns: true when the event was taken, false when the table refuses it. A refusal is
    ///   information, not an error: the caller's own guard chain is what turns a refused
    ///   `sendBegan` into "do not send".
    @discardableResult
    mutating func apply(_ event: Event) -> Bool {
        switch event {
        case .discoveryPaused:
            radioIsQuiet = true
            return true
        case .discoveryResumed:
            radioIsQuiet = false
            return true
        case .peerVerified, .sendBegan, .sendCompleted, .sendFailed, .cancelled:
            return applyPhaseEvent(event)
        }
    }

    /// The half of ``apply(_:)`` that can move ``phase``. Split out so neither body carries both the
    /// pause/resume rule and the phase table.
    private mutating func applyPhaseEvent(_ event: Event) -> Bool {
        guard !phase.isTerminal else { return false }
        guard let next = Self.phase(after: phase, on: event) else { return false }
        if case .sendBegan(let byteCount) = event {
            wireByteCount = max(0, byteCount)
        }
        if case .sendCompleted = event {
            completionCount += 1
        }
        phase = next
        return true
    }

    /// The transition table, as a function. Nil is a refusal.
    private static func phase(after phase: Phase, on event: Event) -> Phase? {
        switch event {
        case .cancelled:
            return .cancelled
        case .sendFailed:
            return .failed
        case .peerVerified:
            return phase == .connecting ? .verified : phase
        case .sendBegan:
            return phase == .verified ? .sending : nil
        case .sendCompleted:
            return phase == .sending ? .sent : nil
        case .discoveryPaused, .discoveryResumed:
            return nil
        }
    }
}

// MARK: - RecipeShareAdvertisedName

/// The local display name the recipe radio advertises, bounded so every transport can carry it.
///
/// ## Why a byte bound and not a character one
///
/// The MultipeerConnectivity advertiser took `String(displayName.prefix(32))` — 32 **Characters**,
/// which is an unbounded number of bytes: 24 CJK characters are 72 UTF-8 bytes and 24 emoji far
/// more. MC never minded. Bonjour does: a TXT entry is capped by DNS-SD, and
/// ``MeshLinkAdvertisement/maxFieldValueLength`` (64 bytes, the bound the mesh radio already
/// publishes under) **drops an over-long value rather than truncating it** — deliberately, because a
/// truncated `sid` still looks like a `sid`. A recipe `name` published through that path would
/// therefore vanish for exactly the users with long names, and the picker would show them by the
/// random Bonjour instance name instead. Nothing would fail; a friend would just stop having a name.
///
/// Fixing it here rather than in the pass-2 publisher makes the wire match what the receiver already
/// renders: ``ItemNameModeration/moderatedPeerDisplayName`` re-caps an inbound name at
/// ``ItemNameModeration/maxNameLength`` (24) Characters, so anything past that was never displayed
/// by anyone.
nonisolated enum RecipeShareAdvertisedName {

    /// Bytes one advertised name may occupy — the bound ``MeshLinkAdvertisement`` publishes under,
    /// so a name that passes here is publishable by every transport unchanged.
    static let maxByteCount = MeshLinkAdvertisement.maxFieldValueLength

    /// The advertisable form of a local display name: sanitized, capped at
    /// ``ItemNameModeration/maxNameLength`` Characters, then trimmed on **grapheme** boundaries
    /// until it fits ``maxByteCount`` bytes.
    ///
    /// Trimming by Character rather than by byte is what keeps a partial scalar off the wire — a
    /// byte-sliced UTF-8 string is not a string, and the receiver's decoder would drop the whole
    /// field. The loop is bounded by the character cap (Power of 10 rule 2) because that is the most
    /// characters `sanitizedName` can return.
    ///
    /// **It answers "" for one real input**: a SINGLE grapheme cluster wider than ``maxByteCount``
    /// — a base letter under ≥ 32 combining marks, which `sanitizedName` keeps (its invisible set is
    /// zero-width and bidi scalars, not combining ones). Removing that one Character leaves nothing.
    /// An empty answer is **not publishable**: the caller omits the field rather than advertising
    /// `""`, exactly as ``MeshLinkAdvertisement/publishedFields`` does, because an ABSENT name falls
    /// back to the peer's own hint while an EMPTY one would reach
    /// ``ItemNameModeration/moderatedPeerDisplayName`` and render as its placeholder. ``received(_:hint:)``
    /// is the matching receive-side rule.
    static func publishable(_ raw: String) -> String {
        var name = ItemNameModeration.sanitizedName(raw)
        for _ in 0..<ItemNameModeration.maxNameLength {
            guard name.utf8.count > maxByteCount, !name.isEmpty else { return name }
            name.removeLast()
        }
        return name.utf8.count <= maxByteCount ? name : ""
    }

    /// The advertised name to render for a peer, or `hint` when the peer published none.
    ///
    /// The fallback fires for an ABSENT field and an EMPTY one alike, which a bare `??` does not: a
    /// nil-coalesce passes `""` straight through to ``ItemNameModeration/moderatedPeerDisplayName``,
    /// which answers its placeholder for an empty string — so a peer this device could have named
    /// from its own transport hint would lose that name instead. ``publishable(_:)`` already omits
    /// an unpublishable name on this device, but the wire is not ours to assume: an older build, or
    /// a pass-2 publisher that writes the key unconditionally, can still put `""` on the air.
    static func received(_ advertised: String?, hint: String) -> String {
        guard let advertised, !advertised.isEmpty else { return hint }
        return advertised
    }
}
