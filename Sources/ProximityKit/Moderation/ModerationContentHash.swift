// ModerationContentHash.swift
// ProximityKit/Moderation
//
// The stable content key a report binds to: SHA-256 over an item's *sanitized* artwork (texture grid
// + slot). Because it hashes the pixels — not the item id, name, or price — a designer cannot escape a
// report by relisting the same artwork under a new id/name (2026-07-11 ban memo). Lives here (not in
// FernletDomainModel) so DomainModel stays crypto-free; ProximityKit already links CryptoKit.

import Foundation
import CryptoKit
import FernletDomainModel

public nonisolated enum ModerationContentHash {
    /// Order-stable SHA-256 over the grid + slot. Callers should pass a sanitized texture/slot.
    public static func of(texture: ItemGridTexture, slot: ItemSlot) -> Data {
        var hasher = SHA256()
        hasher.update(data: Data("cols=\(texture.cols);rows=\(texture.rows);".utf8))
        hasher.update(data: Data(("palette=" + texture.palette.joined(separator: ",") + ";").utf8))
        hasher.update(data: Data(("pixels=" + texture.pixels.map(String.init).joined(separator: ",")).utf8))
        hasher.update(data: Data(";slot=\(slot.rawValue)".utf8))
        return Data(hasher.finalize())
    }

    /// Sanitizes the item first so the hash is stable across hostile encodings, then hashes.
    public static func of(_ item: CustomizationItem) -> Data {
        let sanitized = ClothingShopLimits.sanitizedForShop(item)
        return of(texture: sanitized.texture, slot: sanitized.slot)
    }
}
