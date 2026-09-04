// MeshRoutedDeliveryCommit.swift
// ProximityKit/Mesh
//
// Network migration P5 item 4 (plan §3.6, §11): the delivery durability gate, and nothing else.
//
// This file holds ONE type and ONE verb on purpose. `MeshRecipientDeliveryWitness`'s initialiser is
// `fileprivate`, and `fileprivate` is FILE scope — so the only way anywhere in the app to hold a
// witness is to have completed `MeshRoutedStore.committingDelivery(...)`, which lives here beside
// it. `MeshRecipientReceipt.signed(witness:manifest:identity:)` takes a witness as a parameter, so
// the forbidden order — receipt first, durable acknowledgement later — is not merely discouraged, it
// is unwritable. It is the same two-gates-in-two-files arrangement item 3 built for custody:
// `MeshRoutedStore.LoadToken`'s initialiser is `fileprivate` to `MeshRoutedStore.swift`, so this
// file cannot mint its own write token either.
//
// **This verb writes no per-destination rung.** It writes exactly one thing — the record-level
// `deliveredAt` — and mints the witness. The `delivered` rung is written only by
// `recordingRecipientReceipt`, from a signed receipt whose signer IS that destination, which is what
// makes every `delivered` in the store receipt-backed by construction. The reason is concrete: the
// `recipient:` parameter here is a caller-supplied string the store cannot check against a self
// identity it does not hold, `delivered` is terminal, outranks a later departure and drops a
// destination out of every outstanding enumerator — so one wrong call would permanently stop the
// drain for a peer that never acknowledged anything, with no repair and no merge to walk it back.
//
// **Idempotent means "does not refuse", never "skips the check"** — with one stated exception. Every
// call re-runs the whole stage verification, except for a record whose ack instant is already
// stamped, where the durable ack IS the satisfied precondition and fresh stage evidence is not
// demanded again. The exception is keyed on `deliveredAt` alone, never on a rung: the rung is
// written by a later, separate door and may legitimately not be there yet. Without it, a crash
// between "ack stamped" and "receipt stored" would be unrecoverable for a heart, because the ledger
// refuses to judge one gift twice.

import Foundation
import FernletFoundation

// MARK: - MeshRecipientDeliveryWitness

/// Proof that a durable delivery acknowledgement **returned** (plan §3.6).
///
/// Its initialiser is `fileprivate` and it is declared in `Mesh/MeshRoutedDeliveryCommit.swift`, the
/// file that holds ``MeshRoutedStore/committingDelivery(item:recipient:stages:evidence:now:)`` and
/// nothing else — so the only way to hold one is to have completed that verb. This is
/// durable-before-acknowledged in the type system: no witness ⇒ no ``MeshRecipientReceipt`` ⇒ the
/// forbidden order is unwritable, here and in items 6 and 10.
///
/// Deliberately **not** ``MeshCustodyDurabilityWitness``: that one attests "I hold the complete
/// ciphertext", which is the `custodied` rung's fact. Reusing it would let a pure custody path mint
/// a delivery claim. Where the underlying measurement is the same, the private helper is shared —
/// never the witness type.
///
/// A value, not a handle: it carries what a receipt needs and nothing that could go stale.
nonisolated struct MeshRecipientDeliveryWitness: Equatable, Sendable {
    /// The item's author — the receipt's subject.
    let originFingerprint: String
    /// The routed item.
    let itemID: UUID
    /// The whole item's content hash, as this device durably records it.
    let contentHash: Data
    /// This device — the receipt's signer, and the destination this closes.
    let recipientFingerprint: String
    /// The instant the index write that FIRST recorded this device's final ack returned, floored —
    /// read back from the stored record, not the instant of this pass.
    ///
    /// A re-commit re-uses this stored value, so two receipts for one durable fact are
    /// byte-identical up to the hedged signature. "The instant the write returned" is undetermined
    /// on a re-mint (no write happens), and leaving a **signed wire field** to depend on which
    /// reading an implementer picked is how a golden stops being reproducible.
    let deliveredAt: Date
    /// The rule this device actually satisfied.
    ///
    /// Audit and test surface only — **never on the wire**, and deliberately **not** re-checked at
    /// the mint: the door already refused an unknown token and an unsatisfied stage before a witness
    /// existed, and a mint-side re-check against a table the same caller passes would be circular.
    /// What keeps the token → stage binding single is item 11's registry plus the source-scan wall
    /// over ``MeshRoutedAckStageTable/increment1``, not this field.
    let ackStage: MeshRoutedAckStage

    /// The one construction site's initialiser. `fileprivate` on purpose — see the type's
    /// documentation.
    fileprivate init(
        originFingerprint: String,
        itemID: UUID,
        contentHash: Data,
        recipientFingerprint: String,
        deliveredAt: Date,
        ackStage: MeshRoutedAckStage
    ) {
        self.originFingerprint = originFingerprint
        self.itemID = itemID
        self.contentHash = contentHash
        self.recipientFingerprint = recipientFingerprint
        self.deliveredAt = deliveredAt
        self.ackStage = ackStage
    }
}

// MARK: - MeshRoutedDeliveryStampResult

/// What writing the durable ack instant produced.
///
/// Two cases, not an optional `Date`: the failure carries the store's OWN classification, so a
/// refused seal, a deferral and a write that failed stay three different answers here exactly as
/// they do at every other writer door (plan §19.5). A `Date?` collapsed all three into one, which is
/// the distinction the whole item exists to preserve. (`Result` does not fit: the unavailability is
/// an outcome value, not an `Error`.)
private nonisolated enum MeshRoutedDeliveryStampResult {
    /// The instant now stored on the record — this pass's write, or the one an earlier ack made.
    case stamped(Date)
    /// Nothing was stamped, for the named reason. No witness may exist.
    case unavailable(MeshRoutedUnavailability)
}

// MARK: - The commit

nonisolated extension MeshRoutedStore {

    /// Records this device's FINAL acknowledgement of `item` durably, and mints the one witness a
    /// ``MeshRecipientReceipt`` needs.
    ///
    /// The stage is resolved from the record's own origin-signed `typeToken` through `stages` — a
    /// token the table does not know refuses ``MeshRoutedStoreRefusal/unknownTypeToken`` and
    /// acknowledges nothing, which is plan §11's "unknown type tokens are rejected, not forwarded"
    /// answered at this seam too. A caller supplies the table, never the stage: a stage parameter
    /// would let a caller weaken a heart to `immediate`.
    ///
    /// Writes exactly one thing on success — the record-level ack instant — and advances **no**
    /// delivery rung, not this device's and certainly not a peer's (see the file header). On the
    /// first success it stamps `deliveredAt`; on a later call it re-uses the **stored** instant, so a
    /// re-mint's canonical bytes are byte-identical, and for a record whose instant is already
    /// stamped it does not demand fresh stage evidence again — the ledger cannot be asked twice.
    ///
    /// - Parameters:
    ///   - item: The signed pair.
    ///   - recipient: This device's fingerprint. Checked against the item's signed destination set
    ///     here, and against the signing identity at the mint. Nothing per-destination is written on
    ///     it.
    ///   - stages: The type → final-ack table. Item 11 passes the registry's; shipping code names
    ///     only ``MeshRoutedAckStageTable/increment1``.
    ///   - evidence: What the caller offers for the stage. `.none` for every stage whose condition
    ///     the store reads for itself.
    ///   - now: The injected instant — the value stamped on a first acknowledgement.
    /// - Returns: the witness, the named shortfall, a door refusal, or the store's unavailability.
    func committingDelivery(
        item: MeshRoutedItemKey,
        recipient: String,
        stages: MeshRoutedAckStageTable,
        evidence: MeshRoutedAckEvidence,
        now: Date
    ) -> MeshRoutedOutcome<MeshRoutedDeliveryCommitOutcome> {
        var index: MeshRoutedIndex
        let token: LoadToken
        switch indexForWriting() {
        case .unavailable(let cause): return .unavailable(cause)
        case .writable(let loaded, let vended): index = loaded; token = vended
        }
        guard let record = index.record(for: item) else { return .refused(.unknownItem) }
        guard let manifest = record.manifest else { return .refused(.manifestMismatch) }
        guard record.isLive(at: now) else { return .refused(.itemExpired) }
        guard manifest.destinations.contains(recipient) else { return .refused(.notADestination) }
        guard let stage = stages.stage(for: manifest.typeToken) else {
            return .refused(.unknownTypeToken)
        }
        guard record.deliveryTarget != nil else {
            return .unavailable(.corrupt(MeshRoutedCorruption(detail: .undecodableJSON("deliveryRestore"))))
        }
        if record.deliveredAt == nil,
           let shortfall = Self.stageShortfall(record, stage: stage, evidence: evidence, item: item) {
            return .completed(.unsatisfied(shortfall))
        }
        return acknowledged(record, recipient: recipient, stage: stage,
                            now: now, index: &index, token: token)
    }

    /// The write half: stamp the ack instant once, and only then mint the witness. The reverse order
    /// is unwritable — the witness is constructed after `save` returned, in this file alone.
    private func acknowledged(
        _ record: MeshRoutedItemRecord,
        recipient: String,
        stage: MeshRoutedAckStage,
        now: Date,
        index: inout MeshRoutedIndex,
        token: LoadToken
    ) -> MeshRoutedOutcome<MeshRoutedDeliveryCommitOutcome> {
        let deliveredAt: Date
        switch stampedDeliveryInstant(record, now: now, index: &index, token: token) {
        case .stamped(let stamped): deliveredAt = stamped
        case .unavailable(let cause): return .unavailable(cause)
        }
        return .completed(
            .acknowledged(
                MeshRecipientDeliveryWitness(
                    originFingerprint: record.key.originFingerprint,
                    itemID: record.key.itemID,
                    contentHash: record.contentHash,
                    recipientFingerprint: recipient,
                    deliveredAt: deliveredAt,
                    ackStage: stage
                )
            )
        )
    }

    /// The stage's precondition table (plan §11's three clauses), or nil when it is satisfied.
    ///
    /// `immediate` asks nothing of the CONTENT — a control item is final on a verified, known item —
    /// while the ack record's own durable write still happens, which is what keeps plan §3.6 true for
    /// all three stages. The held-ciphertext clause on the heart stage is a deliberate deviation from
    /// plan §11's words: gift ids also reach `ProximityHeartLedger` from the live and dead-drop heart
    /// paths, so custody is the only leg binding a ledger judgement to **this** signed item's
    /// hash-verified bytes.
    private static func stageShortfall(
        _ record: MeshRoutedItemRecord,
        stage: MeshRoutedAckStage,
        evidence: MeshRoutedAckEvidence,
        item: MeshRoutedItemKey
    ) -> MeshRoutedAckShortfall? {
        guard stage != .immediate else { return nil }
        guard record.isComplete else {
            return .itemIncomplete(received: record.receivedCount, expected: Int(record.chunkCount))
        }
        guard record.isCustodied else { return .custodyNotCommitted }
        guard stage == .foregroundDecryptAndLedgerCommit else { return nil }
        guard case .heartLedgerCommit(let ack) = evidence else { return .ledgerJudgementMissing }
        guard ack.giftID == item.itemID else { return .evidenceForAnotherItem }
        return nil
    }

    /// The stored ack instant, writing it on the FIRST acknowledgement and re-using it on every
    /// later one.
    ///
    /// A failed write answers with the store's OWN classification
    /// (``MeshRoutedStore/unavailability(from:)``), never a flattened "not written": a refused seal
    /// is not an absent file, and a deferral is not a silent retry (plan §19.5). No witness exists on
    /// any failure — that half is what plan §3.6 requires.
    private func stampedDeliveryInstant(
        _ record: MeshRoutedItemRecord,
        now: Date,
        index: inout MeshRoutedIndex,
        token: LoadToken
    ) -> MeshRoutedDeliveryStampResult {
        if let stored = record.deliveredAt { return .stamped(stored) }
        let stamped = MeshRoutedManifest.floored(now)
        var updated = record
        updated.deliveredAt = stamped
        index.upsert(updated)
        do {
            try save(index, token: token)
        } catch {
            let cause = unavailability(from: error)
            FernletAuditLog.log(
                "mesh.routedStore.deliveryNotWritten",
                context: ["cause": cause.logToken, "error": String(describing: error)]
            )
            return .unavailable(cause)
        }
        return .stamped(stamped)
    }
}
