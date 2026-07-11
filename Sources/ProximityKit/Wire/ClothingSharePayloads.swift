import Foundation
import FernletDomainModel

// Wire payloads for the in-person clothing shop (Increment 3). Mirrors RecipeSharePayloads.swift.
//
// WI-9: marked `nonisolated, Sendable` so ProximityKit's `.defaultIsolation(MainActor.self)` does not
// MainActor-isolate these value types and their synthesized `Codable`, which would block off-main decode
// of untrusted MCSession bytes under Swift 6.
//
// A `CustomizationItem` is already a `nonisolated`, `Codable`, `Sendable` domain value type carrying
// everything a shop entry needs — slot, texture, name, `price`, and its anonymous `designer.id` — so the
// catalog embeds it directly (no separate per-item wire mirror). The buyer sanitizes every received item
// via `ClothingShopLimits.sanitizedForShop` before rendering, storing, or buying.

/// A peer's current shop: the (capped, deterministically ordered) items they are offering, plus their
/// anonymous designer id and display name so the buyer can resolve "designed by <friend>" and learn the
/// id→name mapping in person. Ephemeral — held in memory only from receipt through the post-session
/// shop window (see `MeshClothingShop`); only items the buyer actually purchases persist.
public nonisolated struct ClothingCatalogPayload: Codable, Equatable, Identifiable, Sendable {
    public var format = "fernlet.proximity.clothing.catalog"
    public var version = 1
    public var id = UUID()
    public var sentAt = Date()
    /// The sender's anonymous designer id — matches `designer.id` on every item they made.
    public var designerID: UUID
    /// The sender's chosen display name, learned in person and stored locally as the id→name mapping.
    public var displayName: String
    /// Shareable items for sale. Deterministically ordered by the codec before send so the signed bytes
    /// are stable (sign-time order must equal verify-time order).
    public var items: [CustomizationItem]

    public init(
        format: String = "fernlet.proximity.clothing.catalog",
        version: Int = 1,
        id: UUID = UUID(),
        sentAt: Date = Date(),
        designerID: UUID,
        displayName: String,
        items: [CustomizationItem]
    ) {
        self.format = format
        self.version = version
        self.id = id
        self.sentAt = sentAt
        self.designerID = designerID
        self.displayName = displayName
        self.items = items
    }
}

/// A peer's catalog held in memory from receipt (during the friend-mesh session) through the 1-hour
/// post-session shop window (`MeshClothingShop`). The shop is the inverse of recipe-share: the BUYER
/// holds the SELLER's broadcast catalog. Keyed by the transport-VERIFIED sender fingerprint (the mesh
/// accepts catalogs from committed slots only, so the fingerprint is always present in production; the
/// display-name fallback in `id` is retained for the legacy initializer shape) so a re-broadcast
/// replaces the prior catalog rather than stacking.
public struct ProximityClothingCatalog: Identifiable, Equatable {
    public var id: String { senderFingerprint ?? senderDisplayName }
    public var senderDisplayName: String
    public var senderFingerprint: String?
    public var receivedAt: Date
    public var payload: ClothingCatalogPayload

    public init(
        senderDisplayName: String,
        senderFingerprint: String?,
        receivedAt: Date,
        payload: ClothingCatalogPayload
    ) {
        self.senderDisplayName = senderDisplayName
        self.senderFingerprint = senderFingerprint
        self.receivedAt = receivedAt
        self.payload = payload
    }
}
