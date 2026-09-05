// MeshRoutedAck.swift
// ProximityKit/Mesh
//
// Network migration P5 item 4 (plan §11's acknowledgement stages): what makes a routed item FINAL
// at a destination, as a VALUE — three frozen stages, the frozen type-token spellings, the
// token → stage table item 11 registers, and the evidence a caller offers for the one stage whose
// condition the store cannot read for itself.
//
// The rule §11 states in one line — "photos/text final on durable recipient storage; hearts final
// only after foreground decrypt + ledger commit; control immediate" — is expressed here as data
// rather than as a `switch` on a type token. Nothing in this file is named "registry": item 11 owns
// acceptance, item 4 owns the column, and `MeshRoutedStore.committingDelivery(...)` takes the table
// as a parameter so no door hard-codes policy.
//
// **The stage is never on the wire.** A `MeshRecipientReceipt` says only "delivered"; what that
// meant is resolved on both sides from the manifest's ORIGIN-signed `typeToken`. A recipient has no
// field in which to state a weaker rule. What keeps the resolution single is item 11's one registry
// plus the source-scan wall asserting shipping code names only
// ``MeshRoutedAckStageTable/increment1`` — said out loud here rather than claimed as a property of
// the types.
//
// What is deliberately NOT here: any store extension (so tier 1 can build a stage with no disk
// root), any decryption or unwrap, any dispatch, and any acceptance decision about an unknown token
// beyond "``MeshRoutedAckStageTable/stage(for:)`` answers nil, and nil is a refusal everywhere".

import Foundation

// MARK: - MeshRoutedAckStage

/// Which condition makes a routed item FINAL at a destination (plan §11's acknowledgement stages).
///
/// Frozen English, never localized, and **never on the wire**: a ``MeshRecipientReceipt`` says only
/// "delivered", and what that means is fixed by the manifest's origin-signed `typeToken` through a
/// ``MeshRoutedAckStageTable``. The recipient never *states* a stage — it has no field to state it
/// in — so the only way two members can disagree about what "delivered" meant is by resolving the
/// same token through two different tables. Item 4 does not close that by itself: the table is a
/// door parameter, and what makes it ONE table is item 11's registry plus the source-scan wall
/// asserting shipping code names only ``MeshRoutedAckStageTable/increment1``. That is said here
/// rather than claimed as a guarantee this type carries.
///
/// Deliberately **not** ordered and deliberately without a rank: a heart is not "further along"
/// than a photo, and a max-merge over stages would be meaningless. The monotone ladder is
/// `MeshDeliveryState`'s, unchanged.
nonisolated enum MeshRoutedAckStage: String, CaseIterable, Equatable, Sendable {
    /// Final on a verified, known item — no content retention, no decrypt, no foreground.
    ///
    /// The ACK RECORD is still what must be durable (plan §3.6): nothing is acknowledged before the
    /// index write recording it returned, so "immediate" is about the CONTENT condition being empty,
    /// never about skipping the write. Reserved in increment 1 — no control type is registered
    /// (see ``MeshRoutedTypeToken/control``).
    case immediate
    /// Final when this device durably holds the item's complete ciphertext — photos and text.
    ///
    /// **No decrypt is in the condition**: plan §11's locked-device clause is ciphertext-only
    /// custody, and §12 calls the sealed routed inbox beneath the feature "the durable truth". A
    /// destination that holds the bytes and cannot yet read them has received the item.
    case durableRecipientStorage
    /// Final only after a FOREGROUND decrypt and a `ProximityHeartLedger` commit — hearts, and the
    /// one type plan §11 makes explicit.
    ///
    /// A locked or backgrounded device holding the ciphertext is `custodied(by: self)`, not
    /// delivered, and stays so across restarts until a foreground pass supplies the ledger
    /// judgement — or until the item expires.
    case foregroundDecryptAndLedgerCommit
}

// MARK: - MeshRoutedTypeToken

/// The routed type-token spellings (`fernlet.mesh.routed-type.<kind>.v1`, each within
/// ``MeshRoutedManifestFormat/maxTypeTokenLength``).
///
/// Frozen English wire vocabulary, never localized. Item 11's registry is what ACCEPTS a token;
/// item 4 hard-codes no acceptance anywhere and only names the spellings its stage table keys on.
nonisolated enum MeshRoutedTypeToken {
    /// The friend photo (plan §12).
    static let photo = "fernlet.mesh.routed-type.photo.v1"
    /// A session-scoped temporary message (plan §12).
    static let tempMessage = "fernlet.mesh.routed-type.temp-message.v1"
    /// A heart. For this type the manifest's `itemID` **is** the gift id — one id, no second
    /// mapping table, and the replay window, the delivery target and the heart ledger all key on
    /// the same value.
    static let heart = "fernlet.mesh.routed-type.heart.v1"
    /// **Reserved, not registered.** Plan §11 names an `immediate` stage but neither §11 nor §12
    /// routes a control item, and registering a token nothing mints would open a door with no
    /// handler behind it. The precedent is `AEAD.meshRoutedItemV1`, which was registered by item 1
    /// and left unwritten until item 13 built its sealer, applied to a token instead of a domain:
    /// ``MeshRoutedAckStageTable/increment1`` deliberately answers nil for it.
    static let control = "fernlet.mesh.routed-type.control.v1"
}

// MARK: - MeshRoutedAckStageRow

/// One routed type's final-ack condition — the `finalAck` column of the five things plan §11 makes
/// every routed type declare at registration.
///
/// Item 11's type rule carries this row plus size cap, destination semantics, relay-retention and
/// expiry; item 4 owns this column alone.
nonisolated struct MeshRoutedAckStageRow: Equatable, Sendable {
    /// The frozen wire spelling the origin signs into its manifest.
    let typeToken: String
    /// What makes an item of that type final at a destination.
    let finalAck: MeshRoutedAckStage

    /// Builds one row.
    init(typeToken: String, finalAck: MeshRoutedAckStage) {
        self.typeToken = typeToken
        self.finalAck = finalAck
    }
}

// MARK: - MeshRoutedAckStageTable

/// Frozen type token → final-ack stage.
///
/// A **value**, keyed by `String`, because the token arrives on the wire and the record stores the
/// origin's manifest verbatim — the type is only ever a string at rest. `nil` from ``stage(for:)``
/// IS "unknown", and it is the one answer everywhere: the ack door refuses
/// ``MeshRoutedStoreRefusal/unknownTypeToken`` and acknowledges nothing, which is plan §11's
/// "unknown type tokens are rejected, not forwarded" answered at the ack seam as well as at the
/// manifest verifier.
///
/// Injected rather than global (`MeshRoutedStore.committingDelivery(item:recipient:stages:evidence:now:)`
/// takes it) so policy stays item 11's. Shipping code names exactly one value, ``increment1``, and a
/// source-scan wall in `MeshRoutedStoreIsolationTests` is what keeps that true — a fixture table is
/// a test-only affordance.
///
/// **Since P5 item 11 this type is a PROJECTION, not a source.** ``MeshRoutedTypeRegistry`` owns the
/// rows — one per routed type, carrying the other four columns plan §11 makes a type declare — and
/// ``increment1`` is `MeshRoutedTypeRegistry.increment1.ackStages`. The table survives so item 4's
/// door contract (D-4.7) and its pins keep asserting through the new source; a caller still hands a
/// table to a door, and the registry is what decided what is in it.
nonisolated struct MeshRoutedAckStageTable: Equatable, Sendable {
    /// Most rows a table holds. The routed type vocabulary is a compile-time literal; this cap is
    /// what makes the build loop bounded (Power of 10 R2/R4) rather than a policy number.
    static let maxRows = 16

    /// The resolved column, keyed by the frozen token.
    private let stages: [String: MeshRoutedAckStage]

    /// Builds a table from rows, first row winning for a repeated token — a duplicate is a
    /// build-time mistake, and `theTableHasNoDuplicateTokens` walls it rather than this initialiser
    /// pretending to arbitrate.
    ///
    /// - Parameter rows: The type rules, at most ``maxRows``.
    init(rows: [MeshRoutedAckStageRow]) {
        var resolved: [String: MeshRoutedAckStage] = [:]
        // R2: bounded by `maxRows`.
        for row in rows.prefix(Self.maxRows) where resolved[row.typeToken] == nil {
            resolved[row.typeToken] = row.finalAck
        }
        stages = resolved
    }

    /// Plan §11's three registered types, **projected from item 11's registry** — the rows live in
    /// ``MeshRoutedTypeRegistry/increment1``, and this value is the `finalAck` column of them.
    ///
    /// Derived rather than re-listed: the accepted-token set and the stage column come from one
    /// source, so they cannot drift. Control is deliberately absent (``MeshRoutedTypeToken/control``)
    /// because no row registers it.
    static let increment1 = MeshRoutedTypeRegistry.increment1.ackStages

    /// Every token this table knows. Item 11 folds these rows into its registry and derives its
    /// accepted-token set from the same source, so the two can never disagree.
    var tokens: Set<String> { Set(stages.keys) }

    /// The stage for `typeToken`, or nil for a token nobody registered.
    ///
    /// - Parameter typeToken: The manifest's origin-signed token, verbatim.
    /// - Returns: the stage, or nil — which is a refusal at every door that asks.
    func stage(for typeToken: String) -> MeshRoutedAckStage? {
        stages[typeToken]
    }
}

// MARK: - MeshRoutedHeartAck

/// A routed heart's ledger judgement, as EVIDENCE — derived from `MeshHeartCommitOutcome` plus the
/// ledger's own ``MeshHeartLedgerProof``, never a re-implementation of its dedup, cooldown or
/// retention rules.
///
/// Two facts to carry rather than re-derive. **Pruning is not a regression**: a delivered gift may
/// fall out of the ledger's 32-item / 48-hour window later, and only the FIRST mint consults the
/// ledger — `MeshRoutedItemRecord.deliveredAt`, not the ledger, is the durable gate that stops the
/// second ask. And `MeshHeartCommit.commit(_:into:)` bounds its loop at `MeshMergedHeart.setCapacity`,
/// so "not in the outcome" is **not** "refused": ``judgementsForGift`` is the field that tells the
/// two apart, and a gift beyond that bound yields no evidence and stays enumerable rather than being
/// acknowledged on a guess.
nonisolated struct MeshRoutedHeartAck: Equatable, Sendable {
    /// The gift id, which for ``MeshRoutedTypeToken/heart`` IS the manifest's `itemID`.
    let giftID: UUID
    /// How many times the ledger judged THIS gift in the outcome that produced this evidence —
    /// always 1 when the value exists.
    ///
    /// `MeshHeartCommitOutcome.judgements` is a **batch** counter (`received.count + refused.count`)
    /// and is deliberately not the field carried here: the reused idempotence assertion (P4 item 7)
    /// is "each distinct gift id offered is judged exactly once", and this is that statement for one
    /// gift.
    let judgementsForGift: Int

    /// The pure form, for tier 1 and for callers holding both values already.
    ///
    /// Answers nil — so no evidence, and therefore no receipt — unless BOTH legs hold:
    ///
    ///  1. this gift was judged exactly once **in this outcome**. Never `outcome.judgements == 1`:
    ///     `MeshHeartCommit.commit(_:into:)` is a BATCH door and every shipped call site hands it a
    ///     whole merged set, so a pass carrying two hearts has `judgements == 2` and a per-pass leg
    ///     would fail closed for BOTH — silently, until expiry.
    ///  2. `proof.giftID == giftID` — the ledger's own answer to "the write landed and the gift is
    ///     in the stored set". A caller cannot construct a ``MeshHeartLedgerProof``.
    ///
    /// - Parameters:
    ///   - outcome: What the ledger made of the batch this gift was offered in.
    ///   - giftID: The gift, which is the routed item's id.
    ///   - proof: The ledger's own durability answer.
    init?(outcome: MeshHeartCommitOutcome, giftID: UUID, proof: MeshHeartLedgerProof) {
        let judged = outcome.receivedGiftIDs.filter { $0 == giftID }.count
            + outcome.refusedGiftIDs.filter { $0 == giftID }.count
        guard judged == 1 else { return nil }
        guard proof.giftID == giftID else { return nil }
        self.giftID = giftID
        judgementsForGift = judged
    }

    /// The one-call form: asks the ledger for its proof SYNCHRONOUSLY, right after the commit and
    /// never after an `await`, so the conjunction cannot be got wrong at a call site. Reads only.
    ///
    /// - Important: the caller must be in `MeshSessionState.activeForeground` — never
    ///   `.continuingInBackground`. That predicate lives on the mesh manager and cannot be reached
    ///   from a pure value; item 10 wires it and P6 owns the call site. It is the **only** leg on
    ///   the heart path a caller can satisfy by assertion — the other two are proof-gated.
    ///
    /// - Parameters:
    ///   - outcome: What the ledger made of the batch this gift was offered in.
    ///   - giftID: The gift, which is the routed item's id.
    ///   - ledger: The heart ledger that judged it.
    @MainActor
    init?(outcome: MeshHeartCommitOutcome, giftID: UUID, ledger: ProximityHeartLedger) {
        guard let proof = ledger.commitProof(for: giftID) else { return nil }
        self.init(outcome: outcome, giftID: giftID, proof: proof)
    }
}

// MARK: - MeshRoutedAckEvidence

/// What a caller offers the ack commit as proof for the item's stage.
///
/// Two cases, because only one stage has a condition the store cannot read from its own durable
/// state. Nothing here is a stage: the stage is resolved from the origin's signed token, and this
/// value only says whether the caller has what that stage asks for.
nonisolated enum MeshRoutedAckEvidence: Equatable, Sendable {
    /// ``MeshRoutedAckStage/durableRecipientStorage`` and ``MeshRoutedAckStage/immediate`` need
    /// none — their evidence is durable state the store reads for itself.
    case none
    /// ``MeshRoutedAckStage/foregroundDecryptAndLedgerCommit``'s only accepted form.
    case heartLedgerCommit(MeshRoutedHeartAck)
}

// MARK: - MeshRoutedAckShortfall

/// Why an ack was not final — the stage's own condition is not met yet.
///
/// A shortfall is **not** a refusal: the request was well formed and the door would take it, the
/// item simply is not there yet. Nothing is written on any of these, no witness exists, and the
/// destination stays outstanding so the drain comes back. Frozen English tokens for the audit log,
/// never user copy; item 14 needs one named token per event.
nonisolated enum MeshRoutedAckShortfall: Equatable, Sendable {
    /// Chunks are missing. Carries what is held and what is expected.
    case itemIncomplete(received: Int, expected: Int)
    /// Complete, but no durable custody commit stands — including one a repair undid.
    case custodyNotCommitted
    /// A heart with no ledger judgement: no evidence was offered, or its legs did not hold.
    case ledgerJudgementMissing
    /// The heart evidence names a different gift than this item.
    case evidenceForAnotherItem

    /// Frozen English for the diagnostic surface. Never shown as user copy.
    var diagnosticDescription: String {
        switch self {
        case .itemIncomplete(let received, let expected):
            return "The item holds \(received) of \(expected) chunks."
        case .custodyNotCommitted:
            return "No durable custody commit stands for the item."
        case .ledgerJudgementMissing:
            return "The heart ledger has no durable judgement for this gift."
        case .evidenceForAnotherItem:
            return "The heart evidence names a different gift than this item."
        }
    }
}

// MARK: - MeshRoutedDeliveryCommitOutcome

/// What `MeshRoutedStore.committingDelivery(item:recipient:stages:evidence:now:)` found.
///
/// The delivery twin of `MeshRoutedCustodyOutcome`: either the durable ack record was written and a
/// witness exists, or the stage's condition is not met and nothing was written at all. There is no
/// third answer — a door-level refusal and a store-level unavailability travel in
/// `MeshRoutedOutcome`'s other two channels.
nonisolated enum MeshRoutedDeliveryCommitOutcome: Equatable, Sendable {
    /// The ack instant is durable. The witness is the **only** thing that can mint a
    /// ``MeshRecipientReceipt``.
    case acknowledged(MeshRecipientDeliveryWitness)
    /// The stage's condition is not met, by name. No witness, nothing written.
    case unsatisfied(MeshRoutedAckShortfall)
}
