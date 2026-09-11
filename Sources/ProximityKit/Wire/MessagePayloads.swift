import Foundation
import FernletDomainModel

// Wire payload for live-session temporary chat messages (mesh redesign Phase 5,
// Docs/Proximity-Mesh-Redesign-2026-07-10.md). Mirrors RecipeSharePayloads / ClothingSharePayloads.
//
// Owner decision (binding): messages are exchanged ONLY during a live friend session and VANISH at
// session end — nothing retained on device, nothing synced, no dead-drop, no offline queue. This is a
// pure wire value type; the only in-memory holder is `SessionMessageStore`, which is deliberately NOT
// Codable so a message can never enter a snapshot.
//
// WI-9: marked `nonisolated, Sendable` so ProximityKit's `.defaultIsolation(MainActor.self)` does not
// MainActor-isolate this value type and its synthesized `Codable`, which would block off-main decode of
// untrusted MCSession bytes under Swift 6. The receiver sanitizes + length-caps `text` (via
// `SessionMessageStore`) before it is stored or rendered — never trust the wire.

/// A single session-scoped chat message on the wire — **frozen and parked** (network migration P6
/// item 4).
///
/// Still `Codable`, still sealed-only (`.tempMessage` is in `sealingRequiredTypes`), and no longer
/// emitted or dispatched by anything: chat rides the routed store as a `MeshRoutedTextBody` inside
/// a signed manifest's per-recipient wrap. This value stays so an older peer's frame parks by name
/// rather than failing a session, and because it is the sealing-required CONTROL several wire suites
/// make their claims against. `id` drove receive-side dedup; `sentAt` was the sender's clock
/// (display only — never trusted for ordering security).
public nonisolated struct TempMessagePayload: Codable, Equatable, Identifiable, Sendable {
    public var id: UUID
    public var text: String
    public var sentAt: Date

    public init(id: UUID = UUID(), text: String, sentAt: Date = Date()) {
        self.id = id
        self.text = text
        self.sentAt = sentAt
    }
}
