// MeshRoutedDeliveryIngest.swift
// ProximityKit/Mesh
//
// Network migration P5 item 4 (plan §11): the observer-side delivery doors — where a verified
// ``MeshRecipientReceipt`` becomes a `delivered` rung and stored evidence, and where a courier hands
// the signer's own bytes on.
//
// **`recordingRecipientReceipt` is the only writer of a `delivered` rung in the whole store** — for
// peers and for this device alike. Every `.delivered` entry in a persisted `MeshRoutedDeliveryRecord`
// therefore has a verified, signed receipt behind it whose signer is that destination, and the
// invariant holds by construction rather than by call-site discipline. `committingDelivery` writes
// only the record-level ack instant; this door is where a rung moves, and it moves exactly one — the
// receipt's own signer's.
//
// There is deliberately **no `for destinations:` parameter**, unlike `recordingCustodyTransfer`.
// "Which destinations this custodian is now courier for" is the caller's statement; "this reached
// me" is the signer's, and a destination list here would let one member's receipt mark somebody else
// delivered.
//
// Kept out of `MeshRoutedDeliveryCommit.swift` on purpose: that file's one-type-one-verb property is
// what makes `fileprivate` a real gate on the witness, and this door mints no witness at all.

import Foundation

// MARK: - The ingest and forwarding doors

nonisolated extension MeshRoutedStore {

    /// Records that `receipt`'s signer has FINALLY received this item, advancing that one
    /// destination to `delivered` and storing the receipt as the evidence in the **same index
    /// write**.
    ///
    /// The destination is `receipt.recipientFingerprint` and nothing else — a recipient receipt
    /// speaks only for its own signer. This is also the door for **this device's own** receipt, called
    /// right after the mint: the local sequence is `committingCustody` → *(hearts: foreground unwrap
    /// and ledger commit)* → `committingDelivery` → `MeshRecipientReceipt.signed` → here, and the rung
    /// closes at the last step, never the third.
    ///
    /// A crash between the mint and this call leaves `deliveredAt` stamped with no rung and no stored
    /// receipt. That state is reachable, so it is enumerated rather than described:
    /// ``MeshRoutedIndex/itemsAwaitingLocalAck(at:for:)`` names exactly it, and the recovery is a
    /// re-commit — which re-uses the stored instant, does not re-ask the heart ledger, and re-mints
    /// byte-identical canonical bytes.
    ///
    /// - Important: `receipt` must be one ``MeshRecipientReceiptVerifier/verify(_:)`` has already
    ///   accepted (returned nil). The door re-checks identity anyway, because a store that trusts its
    ///   caller's word about whose receipt this is has no invariant left.
    ///
    /// There is no expiry gate, matching `recordingCustodyTransfer`: a receipt for an expired item is
    /// still evidence of what happened, and item 9 retires the item.
    ///
    /// - Parameters:
    ///   - item: The signed pair.
    ///   - receipt: The destination's signed statement.
    ///   - now: The injected instant.
    /// - Returns: the advanced delivery target, or a delivery-level refusal, or a store refusal.
    ///   **Nothing is written on any refusal.**
    func recordingRecipientReceipt(
        item: MeshRoutedItemKey,
        receipt: MeshRecipientReceipt,
        now: Date
    ) -> MeshRoutedOutcome<MeshDeliveryOutcome> {
        var index: MeshRoutedIndex
        let token: LoadToken
        switch indexForWriting() {
        case .unavailable(let cause): return .unavailable(cause)
        case .writable(let loaded, let vended): index = loaded; token = vended
        }
        guard var record = index.record(for: item) else { return .refused(.unknownItem) }
        guard let manifest = record.manifest else { return .refused(.manifestMismatch) }
        if let refusal = recipientReceiptRefusal(receipt, against: record, manifest: manifest) {
            return .refused(refusal)
        }
        guard let target = record.deliveryTarget else {
            return .unavailable(.corrupt(MeshRoutedCorruption(detail: .undecodableJSON("deliveryRestore"))))
        }
        let advanced = target.advancing(receipt.recipientFingerprint, to: .delivered)
        guard let updatedTarget = advanced.target else { return .completed(advanced) }
        record.delivery = MeshRoutedDeliveryRecord(encoding: updatedTarget)
        record.recipientReceipts = Self.storing(receipt, in: record.recipientReceipts)
        index.upsert(record)
        do {
            try save(index, token: token)
        } catch {
            return .unavailable(unavailability(from: error))
        }
        return .completed(advanced)
    }

    /// The four identity equalities plus the destination and evidence-capacity guards.
    ///
    /// The identity check is the triple the verifier makes plus the mesh, re-asked against **this
    /// device's own record**: the verifier answers about the manifest it was handed, and this door is
    /// what ties the receipt to the item it is being filed under.
    private func recipientReceiptRefusal(
        _ receipt: MeshRecipientReceipt,
        against record: MeshRoutedItemRecord,
        manifest: MeshRoutedManifest
    ) -> MeshRoutedStoreRefusal? {
        guard receipt.itemID == record.key.itemID,
              receipt.originFingerprint == record.key.originFingerprint,
              receipt.contentHash == record.contentHash,
              receipt.meshID == manifest.meshID else {
            return .manifestMismatch
        }
        guard manifest.destinations.contains(receipt.recipientFingerprint) else {
            return .notADestination
        }
        let alreadyStored = record.recipientReceipts.contains {
            $0.recipientFingerprint == receipt.recipientFingerprint
        }
        guard alreadyStored
                || record.recipientReceipts.count < capacity.maxReceiptsPerItem else {
            return .capacityRecipientReceipts
        }
        return nil
    }

    /// The evidence set with `receipt` inserted or REPLACED for its signer, in recipient order.
    ///
    /// Replace-by-signer rather than append-per-arrival is what makes a second arrival — including
    /// the same receipt over two different links — grow nothing.
    private static func storing(
        _ receipt: MeshRecipientReceipt,
        in receipts: [MeshRecipientReceipt]
    ) -> [MeshRecipientReceipt] {
        var stored = receipts.filter { $0.recipientFingerprint != receipt.recipientFingerprint }
        stored.append(receipt)
        return stored.sorted { $0.recipientFingerprint < $1.recipientFingerprint }
    }

    /// The stored recipient receipts for `item`, byte-identical, ordered by recipient fingerprint —
    /// including this device's own.
    ///
    /// A courier forwards signed bytes; it never re-signs and, for a recipient receipt, never
    /// re-derives. That is the deliberate difference from custody: a custody claim is re-measurable
    /// from the bytes on disk forever, while a heart's final-ack condition is a one-shot ledger
    /// judgement the ledger will refuse to repeat — so this device's own receipt is **stored** and
    /// re-sent rather than re-minted.
    ///
    /// - Parameter item: The signed pair.
    /// - Returns: the receipts (empty when the item is unknown or holds none), or the store's
    ///   unavailability.
    func forwardableRecipientReceipts(
        item: MeshRoutedItemKey
    ) -> MeshRoutedOutcome<[MeshRecipientReceipt]> {
        switch indexForWriting() {
        case .unavailable(let cause):
            return .unavailable(cause)
        case .writable(let index, _):
            return .completed(index.record(for: item)?.recipientReceipts ?? [])
        }
    }
}
