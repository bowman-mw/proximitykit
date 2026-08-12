// HeartDropStorageScope.swift
// ProximityKit/HeartSharing
//
// Where ONE device's heart-drop state lives — the sidecar directory and the keychain service that
// holds the key sealing it. Both halves in one value because `HeartDropService.wipeForDeleteAll()`
// destroys both, so isolating one without the other isolates nothing.

import Foundation

/// The storage identity of one device's heart-drop state: the directory holding the three sidecars
/// (outbox, peer bundles, dedup) and the keychain service holding both the prekey private halves
/// and the key those sidecars are sealed with.
///
/// **Why the two travel together.** The sidecars are sealed at rest (Increment 4), and
/// ``HeartDropSidecarSeal`` keeps its key under the same `com.fernlet.heartdrop` service as
/// ``HeartPrekeyStore``'s blob precisely so both share the delete-all fate —
/// `HeartDropService.wipeForDeleteAll()` removes the files AND, via
/// `HeartPrekeyStore.wipeForDeleteAll()`'s `KeychainItem.deleteAll(service:)`, the key. A scope that
/// isolated only the directory would therefore be cosmetic: a wipe elsewhere in the process still
/// deletes the shared key, and the isolated file then fails to open — the outbox quarantines it and
/// latches `dataLossOccurred`, which is strictly worse than losing the file outright.
///
/// **Why that matters outside production.** XCTest and Swift Testing suites run in parallel inside
/// ONE process, so on the production scope every live `FernletStore` shares one outbox, one dedup
/// store, one peer-bundle cache and one seal key — and any test that runs "delete everything"
/// destroys all of them for every concurrently-running suite. Same hazard, and the same fix, as
/// ``ProximityHost/proximitySupportDirectory`` for the friend photo wall and
/// `FernletStore.photoDocumentsDirectory` for the own-photo corpora; this one just has a keychain
/// half as well.
///
/// Scoping is deliberately NOT the same as unsealing. A test store on its own scope still seals
/// through the real ``HeartDropSidecarSeal`` key path — it just mints its key under a service
/// nobody else wipes — so what the tests exercise stays what production does.
/// `nonisolated` against the target's `defaultIsolation(MainActor.self)`: this is inert
/// configuration, read by `FernletStore`'s nonisolated stored properties and by the
/// nonisolated-static default paths on the sidecar stores.
public nonisolated struct HeartDropStorageScope: Sendable, Equatable {
    /// Directory holding `HeartDropOutbox.json`, `HeartDropPeerBundles.json` and
    /// `HeartDropDedup.json` (plus any `.corrupt` quarantine beside them).
    public let directory: URL
    /// Keychain service holding the prekey private halves and the sidecar seal key. One service for
    /// both, so a delete-all takes them together and never leaves ciphertext without its key.
    public let keychainService: String

    public init(directory: URL, keychainService: String) {
        self.directory = directory
        self.keychainService = keychainService
    }

    /// The shipped scope: `Application Support/Fernlet` + `com.fernlet.heartdrop`, i.e. exactly the
    /// paths and service the heart-drop stores have always used. Nothing installed is migrated by
    /// the seam that made this injectable.
    public static var production: HeartDropStorageScope {
        HeartDropStorageScope(
            directory: ProximitySupportLayout.defaultDirectory,
            keychainService: HeartPrekeyStore.keychainService
        )
    }
}
