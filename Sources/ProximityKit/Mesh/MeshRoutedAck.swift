// MeshRoutedAck.swift
// ProximityKit/Mesh
//
// Network migration P5 item 4 (plan §11's acknowledgement stages): what makes a routed item FINAL
// at a destination, as a VALUE — three frozen stages, the token → stage table item 11 registers,
// and the evidence a caller offers for the one stage whose condition the store cannot read for
// itself. The type tokens are the host's: the namespace's routed types, from which the registry
// builds the rows this table projects.
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
// plus the source-scan wall asserting shipping code names no `MeshRoutedAckStageTable` member at all
// and builds the table only as the registry's projection — said out loud here rather than claimed as
// a property of the types.
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
/// asserting shipping code names no `MeshRoutedAckStageTable` member and builds the table only as
/// the registry's projection. That is said here rather than claimed as a guarantee this type carries.
///
/// Deliberately **not** ordered and deliberately without a rank: a heart is not "further along"
/// than a photo, and a max-merge over stages would be meaningless. The monotone ladder is
/// `MeshDeliveryState`'s, unchanged.
///
/// Public as the final-ack column of a host's ``MeshRoutedTypeEntry`` (plan step A0.5.9, S16).
public nonisolated enum MeshRoutedAckStage: String, CaseIterable, Equatable, Sendable {
    /// Final on a verified, known item — no content retention, no decrypt, no foreground.
    ///
    /// The ACK RECORD is still what must be durable (plan §3.6): nothing is acknowledged before the
    /// index write recording it returned, so "immediate" is about the CONTENT condition being empty,
    /// never about skipping the write. Reserved in increment 1 — no control type is registered
    /// (see ``ProximityNamespace/RoutedTypes/control``).
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
/// takes it) so policy stays item 11's. Shipping code names no value of this type at all: the one
/// table a door is handed is the manager's registry's ``MeshRoutedTypeRegistry/ackStages``, and a
/// source-scan wall in `MeshRoutedStoreIsolationTests` is what keeps that true — a fixture table is a
/// test-only affordance.
///
/// **Since P5 item 11 this type is a PROJECTION, not a source.** ``MeshRoutedTypeRegistry`` owns the
/// rows — one per routed type, carrying the other four columns plan §11 makes a type declare — and
/// builds this table from them. The table survives so item 4's door contract (D-4.7) and its pins
/// keep asserting through the new source; a caller still hands a table to a door, and the registry
/// is what decided what is in it. Its `increment1(_:)` factory is the test target's (S16), which
/// reads the registry the suites build; no shipping code has one.
nonisolated struct MeshRoutedAckStageTable: Equatable, Sendable {
    /// Most rows a table holds. The routed type rows are a compile-time literal; this cap is
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

// MARK: - MeshRoutedLedgerCommit

/// The engine's record that a routed ledger judge committed ONE item — the payload of
/// ``MeshRoutedAckEvidence/ledgerCommit(_:)`` (plan step A0.5.3, S10).
///
/// Minted only by the mesh manager's ledger ceremony, from a judge's
/// ``MeshRoutedJudgement/committed`` answer, and bound to the item that judge was handed. It carries
/// the item id and nothing else: whether a durable proof stands behind the item is the judge's to
/// settle before it answers, and what the stage check needs is which item the answer was about.
/// Internal, with no public initializer, so no module but ProximityKit can build evidence — for this
/// item or for another.
nonisolated struct MeshRoutedLedgerCommit: Equatable, Sendable {
    /// The routed item the judge committed: the manifest's signed item id.
    let itemID: UUID
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
    /// ``MeshRoutedAckStage/foregroundDecryptAndLedgerCommit``'s only accepted form: the engine's
    /// record that the ledger judge registered for the item's row committed it, minted from the
    /// judge's answer and never by the judge (plan step A0.5.3). The stage check refuses one that
    /// names another item.
    case ledgerCommit(MeshRoutedLedgerCommit)
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
