// MeshRoutedInventoryBuilder.swift
// ProximityKit/Mesh
//
// Network migration P5 item 5 (plan §11): deriving a `MeshRoutedInventory` from a LOADED routed
// index — read-only, clock-injected, and the only production door onto the record.
//
// Item 5 adds **no store verb and no index enumerator**. `MeshRoutedStore.load()` already vends the
// index; a second door would be a second place for the five-state load discipline to be got wrong.
// The drain (item 6) composes `load()` + this initializer, and — this is the fail-closed half —
// **sends no digest at all** when the load is not `.loaded`. An empty digest is a positive claim
// ("I hold nothing"), and before first unlock that claim would turn a deferred sidecar into a
// re-delivery storm.

import Foundation

// MARK: - Deriving an inventory from the store

extension MeshRoutedInventory {

    /// This device's advertisable holdings, derived from a **loaded** index.
    ///
    /// Read-only: nothing here opens a file, a keychain or a transport, and nothing mutates the
    /// store. Deterministic given `(index, selfFingerprint, now)` — two builds from the same inputs
    /// are `==`.
    ///
    /// **Which items are advertised: live ones, and otherwise everything.** The only filter is
    /// `record.isLive(at: now)`, because two peers sweeping expiries at different moments must not
    /// differ forever. Parked items, fully-delivered items and items whose delivery map will not
    /// restore are **all** advertised: every delivery-state enumerator drops one of those classes, so
    /// a digest built off `outstandingItems` would silently omit held bytes. "Nothing grows
    /// silently" has a mirror — nothing *vanishes* silently either.
    ///
    /// **The custody self-rule** (both halves are load-bearing). `MeshRoutedItemRecord.receipts`
    /// stores only OTHER members' custody receipts, so this device is added to `custodySigners` when
    /// it holds custody — without which a custody transfer is invisible and the origin never learns
    /// who is holding the item — and **only** when the item is not its own, because an origin can
    /// never mint a receipt for itself (`MeshCustodyReceipt.signed` throws `originIsSelf`) and a peer
    /// would ask for it forever. `recipientReceipts` needs no rule: this device's own is stored.
    ///
    /// - Parameters:
    ///   - meshID: The session the holdings belong to.
    ///   - index: The loaded index. Its own invariants bound the entry and signer counts.
    ///   - selfFingerprint: This device.
    ///   - now: The injected instant; expired items are excluded, as everywhere else.
    /// - Returns: nil **only** when the live records reference more distinct fingerprints than
    ///   ``MeshRoutedInventoryFormat/maxReferencedMembers``. Every other bound is an index invariant,
    ///   so a refusal there would be untestable. The mint turns this nil into the named
    ///   ``MeshRoutedInventoryMintError/tooManyReferencedMembers``.
    init?(meshID: UUID, index: MeshRoutedIndex, selfFingerprint: String, at now: Date) {
        let live = index.items.filter { $0.isLive(at: now) }
        guard let table = Self.memberTable(of: live, selfFingerprint: selfFingerprint) else {
            return nil
        }
        var positions: [String: UInt8] = [:]
        // R2: bounded by `maxReferencedMembers`.
        for (position, member) in table.enumerated() {
            positions[member] = UInt8(truncatingIfNeeded: position)
        }
        var built: [MeshRoutedInventoryEntry] = []
        // R2: bounded by `MeshRoutedStoreFormat.maxItems`.
        for record in live {
            guard let entry = Self.entry(for: record, positions: positions, selfFingerprint: selfFingerprint)
            else { return nil }
            built.append(entry)
        }
        self.init(meshID: meshID, members: table, entries: built)
    }

    /// The minimal fingerprint table: every origin and receipt signer the live records reference,
    /// sorted ascending and distinct, or nil past ``MeshRoutedInventoryFormat/maxReferencedMembers``.
    private static func memberTable(
        of records: [MeshRoutedItemRecord], selfFingerprint: String
    ) -> [String]? {
        var referenced: Set<String> = []
        // R2: bounded by `MeshRoutedStoreFormat.maxItems`.
        for record in records {
            referenced.insert(record.key.originFingerprint)
            for signer in custodySignerFingerprints(of: record, selfFingerprint: selfFingerprint) {
                referenced.insert(signer)
            }
            for receipt in record.recipientReceipts {
                referenced.insert(receipt.recipientFingerprint)
            }
        }
        guard referenced.count <= MeshRoutedInventoryFormat.maxReferencedMembers else { return nil }
        return referenced.sorted()
    }

    /// One record's entry against a finished member table, or nil when a referenced fingerprint is
    /// somehow absent from it (unreachable: the table is built from exactly these fingerprints).
    ///
    /// `chunkCount` is the record's own, verbatim. The store's writers derive it from a manifest's
    /// size or a chunk header, both of which are `1 … maxChunkCount` by their own shape checks; a
    /// planted zero — or a planted over-cap value, which ``heldChunkBitmap(of:)`` refuses to turn
    /// into an allocation — would make the built inventory refuse its own shape check, which is the
    /// honest answer for malformed durable state rather than a silently repaired digest.
    private static func entry(
        for record: MeshRoutedItemRecord, positions: [String: UInt8], selfFingerprint: String
    ) -> MeshRoutedInventoryEntry? {
        guard let originIndex = positions[record.key.originFingerprint] else { return nil }
        let custody = custodySignerFingerprints(of: record, selfFingerprint: selfFingerprint)
        guard let custodyIndices = indices(of: custody, in: positions),
              let recipientIndices = indices(
                  of: record.recipientReceipts.map(\.recipientFingerprint), in: positions
              )
        else { return nil }
        return MeshRoutedInventoryEntry(
            originIndex: originIndex,
            itemID: record.key.itemID,
            holdsManifest: !record.isParked,
            chunkCount: record.chunkCount,
            heldChunks: heldChunkBitmap(of: record),
            custodySigners: custodyIndices,
            recipientSigners: recipientIndices
        )
    }

    /// The custody signers one record advertises: the stored receipts' custodians, plus **this
    /// device** when it holds custody of somebody else's item.
    private static func custodySignerFingerprints(
        of record: MeshRoutedItemRecord, selfFingerprint: String
    ) -> [String] {
        var signers = record.receipts.map(\.custodianFingerprint)
        if record.isCustodied, record.key.originFingerprint != selfFingerprint {
            signers.append(selfFingerprint)
        }
        return signers
    }

    /// `fingerprints` resolved through `positions`, deduplicated and sorted ascending — the frozen
    /// signer-list shape — or nil when one is not in the table.
    private static func indices(
        of fingerprints: [String], in positions: [String: UInt8]
    ) -> [UInt8]? {
        var resolved: Set<UInt8> = []
        // R2: bounded by the two per-entry signer caps.
        for fingerprint in fingerprints {
            guard let position = positions[fingerprint] else { return nil }
            resolved.insert(position)
        }
        return resolved.sorted()
    }

    /// One record's held set as the canonical bitmap of ``MeshRoutedInventoryEntry``.
    ///
    /// A descriptor whose index is at or above the record's own `chunkCount` is **skipped**: it has
    /// no slot in the item the origin signed, so there is no canonical bit for it, and setting one
    /// would break the trailing-zero rule the whole comparison rests on.
    ///
    /// **`chunkCount` is bounded here before it becomes an allocation size.** This is the first
    /// consumer that turns that at-rest field into a byte count, and `MeshRoutedItemRecord`'s decode
    /// caps its three collections but not this scalar — a planted `UInt32` would otherwise size a
    /// half-gigabyte `Data`. An out-of-range count yields an **empty** map rather than a clamped one,
    /// which is the same answer a planted zero already gets: the built inventory then refuses its own
    /// shape check, the honest outcome for malformed durable state, instead of advertising a
    /// silently-repaired holding.
    private static func heldChunkBitmap(of record: MeshRoutedItemRecord) -> Data {
        guard record.chunkCount >= 1,
              Int(record.chunkCount) <= MeshRoutedInventoryFormat.maxChunkCount
        else { return Data() }
        let width = MeshRoutedInventoryEntry.bitmapByteCount(forChunkCount: record.chunkCount)
        guard width > 0 else { return Data() }
        var bytes = Data(repeating: 0, count: width)
        // R2: bounded by `MeshRoutedStoreFormat.maxChunksPerItem`.
        for chunk in record.chunks where chunk.descriptor.chunkIndex < record.chunkCount {
            let index = Int(chunk.descriptor.chunkIndex)
            bytes[index / 8] |= UInt8(1) << UInt8(index % 8)
        }
        return bytes
    }
}
