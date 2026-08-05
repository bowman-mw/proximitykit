// JSONSidecarFile.swift
// ProximityKit/Support
//
// The shared best-effort JSON sidecar idiom used by the device-local ProximityKit stores
// (FriendStateCache, ClosenessLedger, ModerationLedger, ProximityActivityManager, and the mesh
// photo-wall preferences). One home for the load/save/remove plumbing those stores previously
// repeated verbatim; each store keeps its own PersistedState shape and post-decode mapping.

import Foundation

/// Best-effort JSON file persistence for a device-local sidecar in Application Support
/// (`.completeFileProtection`, never synced) — the shared plumbing behind ``FriendStateCache``,
/// ``ClosenessLedger``, ``ModerationLedger``, ``ProximityActivityManager``, and the mesh
/// photo-wall preferences in `MeshNetworkManager`.
///
/// This is deliberately the *naive* idiom: every failure is swallowed. A `load()` that fails for
/// ANY reason — file absent, transient I/O error, or a `.completeFileProtection` file touched
/// while the device is locked — returns `nil`, which callers treat as "no data"; the next
/// `save(_:)` then overwrites the real file with that near-empty state (the documented clobber
/// hazard). That trade-off is acceptable only for reconstructible convenience state. Anything
/// that is data of record must load through ``ProtectedSidecar`` instead, which classifies read
/// failures so a locked-device read can never be mistaken for "empty".
///
/// `save(_:)` preserves the stores' exact operation order — encode (bail on failure), create the
/// parent directory, then an atomic `.completeFileProtection` write — and, unlike
/// ``ProtectedSidecar``'s writer, does NOT exclude the file from backup.
struct JSONSidecarFile<State: Codable> {
    /// The on-disk location of the sidecar (tests inject their own; production uses
    /// `defaultFileURL(name:)`).
    let fileURL: URL

    /// The production sidecar home: `Application Support/Fernlet/<name>`.
    nonisolated static func defaultFileURL(name: String) -> URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("Fernlet/\(name)")
    }

    /// Reads + decodes the sidecar. `nil` on ANY failure — absent, unreadable (including a
    /// locked-device read of a protected file), or undecodable.
    func load() -> State? {
        guard let data = try? Data(contentsOf: fileURL),
              let state = try? JSONDecoder().decode(State.self, from: data) else { return nil }
        return state
    }

    /// Encodes + writes the sidecar: encode (silently bail on failure), ensure the parent
    /// directory exists, then an atomic `.completeFileProtection` write. A failed write is
    /// silently dropped.
    func save(_ state: State) {
        guard let data = try? JSONEncoder().encode(state) else { return }
        try? FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: fileURL, options: [.atomic, .completeFileProtection])
    }

    /// Deletes the sidecar file (best-effort) — the `clearAll` / reset-everything path.
    func removeFile() {
        try? FileManager.default.removeItem(at: fileURL)
    }
}
