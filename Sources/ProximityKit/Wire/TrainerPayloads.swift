// TrainerPayloads.swift
// ProximityKit/Wire
//
// The wire envelope for the Trainer / Nutritionist export (Phase 7). A user assembles a CURATED,
// allowlist-projected workout + nutrition bundle in the app (`TrainerExportBuilder`) and reviews exactly
// what it contains before sharing. The bundle bytes are opaque to ProximityKit: the app owns the
// `Codable` shape (which by construction excludes journal text, period/cycle, intimate, photos, friends,
// location, and recipe ingredients — see `TrainerExportBuilder`).
//
// TRANSPORT SEAM (deferred): a coach is NOT a friend. When the dedicated coaching feature ships, this
// bundle will travel over the separate `fernlet-coach` trainer channel (`ProximityMode.trainer` /
// `MultipeerServiceType.trainer`, `ProximityCoordinator.sendPayload(...)`) to a coach running the
// separate coaching app — never over the friend mesh. Until then the app shares the reviewed bundle as a
// file. This type + `PayloadType.workoutCompletion`'s membership in `sealingRequiredTypes` (so an
// unsealed send is fail-closed at `verify()`) are the wire seam that later feature will use.
//
// WI-9: `public nonisolated struct … : Codable, Equatable, Sendable` — ProximityKit's
// `.defaultIsolation(MainActor.self)` would otherwise MainActor-isolate the synthesized `Codable`, a hard
// error when the coordinator decodes these untrusted MCSession bytes off the main actor.

import Foundation

public nonisolated struct TrainerExportPayload: Codable, Equatable, Sendable {
    public var format = "fernlet.trainer.export"
    public var version = 1
    /// The app-encoded `TrainerExportBundle` JSON. Opaque here; bounded so a hostile peer can't ship a
    /// giant blob that the receiver would hold in memory.
    public let bundle: Data

    public init(bundle: Data) {
        self.bundle = bundle
    }

    /// Upper bound on the encoded bundle (a curated multi-month export is well under this).
    public static let maxBundleBytes = 2 * 1024 * 1024

    /// Hard cap on a coach-session inbound WIRE blob, enforced by `ProximityCoordinator`
    /// BEFORE the envelope is decoded, decrypted, or inflated (Increment 10 — the hearts
    /// ordering: `isWellFormed`'s check runs after decrypt+inflate, which is the wrong layer
    /// for a denial-of-service bound). Derived from `maxBundleBytes`, never hand-written:
    /// the sealed ciphertext is ≈ payload-sized, the envelope carries it base64 (×4/3) plus
    /// bounded JSON overhead — 2× covers both with margin while keeping a hostile blob far
    /// under `SealedPayloadFraming`'s 16 MiB inflate guard.
    public static let maxTrainerWireBytes = 2 * maxBundleBytes

    public var isWellFormed: Bool {
        format == "fernlet.trainer.export" && version == 1 && !bundle.isEmpty && bundle.count <= Self.maxBundleBytes
    }
}
