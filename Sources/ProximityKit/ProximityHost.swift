import Foundation
import FernletDomainModel

/// The narrow seam the Proximity subsystem uses to reach app-level state, so the
/// mesh / recipe-share managers depend on this abstraction instead of the concrete
/// `FernletStore`. This removes the App→Proximity type coupling (the managers no
/// longer name `FernletStore`), which is the precondition for `Proximity/` to
/// become a standalone `ProximityKit` module (plan §5d). The app conforms
/// `FernletStore` to it in `ProximityHostAdapter.swift`.
///
/// Mirrors the existing `ProximityTrustPolicy` / `WorkoutSyncContext` host-protocol
/// pattern. Surface is exactly what `MeshNetworkManager` + `ProximityRecipeShareManager`
/// consume: display name, trusted peers + vault, and the block/fingerprint checks.
@MainActor
public protocol ProximityHost: AnyObject {
    var proximityDisplayName: String { get }
    var trustedProximityPeers: [ProximityTrustedPeerRecord] { get }
    var proximityTrustVault: ProximityTrustVault { get }
    func isBlockedFingerprint(_ fingerprint: String) -> Bool
    func blockProximityPeer(signingPublicKey: Data)
    /// The in-person hearts opt-in (mesh redesign Phase 4b). `PresenceManager` consults it on the
    /// send side (block an outbound heart) and the receive side (drop an inbound heart) — the two
    /// non-UI homes of the setting. Presence VISIBILITY is a separate setting, so hearts-off +
    /// presence-on means a friend still sees you nearby but a heart to you is silently dropped.
    var allowNearbyHearts: Bool { get }
    /// The away-delivery opt-in (bitchat adoptions Increment 3). `PresenceManager` consults it
    /// only for copy — `notNearbyHeartMessage(firstName:)`, so a failed send doesn't tell a user
    /// who turned away delivery ON that "hearts travel in person for now". The enforcement homes
    /// are `HeartDropService.queueHeart`/`syncNow`; the friend row's affordance decision takes it
    /// as an explicit parameter (`PresenceManager.heartAffordance`) rather than through this host.
    var heartsAwayDeliveryEnabled: Bool { get }
    /// Root directory for the proximity subsystem's on-disk sidecars — the friend photo-wall index
    /// (`MeshPhotoCache.sealed`, GCM-sealed under the friend-wall media key; a legacy plaintext
    /// `MeshPhotoCache.json` is read once, resealed, and deleted by `PrivateMediaStore.loadIndex()`)
    /// and its preferences (`MeshPhotoWallPreferences.json`), and the
    /// heart-drop set the app hangs off the same root (`HeartLedger.json` plus the three sealed
    /// sidecars named by ``HeartDropStorageScope``).
    ///
    /// Comes through the HOST rather than being a constant inside `MeshNetworkManager` because it is
    /// shared *mutable on-disk state*: `deletePhoto` / `deleteAllSessionPhotos` re-save the whole
    /// index, and every manager loads that file at init. With one process-wide path, a manager built
    /// in one test reads (and overwrites) the wall of every other live one — and under the test
    /// runner, where XCTest and Swift Testing suites run in parallel in ONE process, that is a live
    /// cross-suite race. Routing it through the host means the 49 `MeshNetworkManager(store:)` sites
    /// inherit their store's isolation for free. Same reasoning as
    /// `FernletStore.photoDocumentsDirectory`, for the corpus on the other side of the media-key split.
    ///
    /// The heart-drop sidecars share this root but need a second half the wall does not: they are
    /// sealed, and their key is wiped by service, so isolating them means isolating a
    /// ``HeartDropStorageScope`` (directory + keychain service), not just a directory.
    var proximitySupportDirectory: URL { get }

    /// This host's sealed mesh-session scope (network migration P3): the directory holding
    /// `MeshSessionContext.sealed` and the keychain service holding the key that seals it.
    ///
    /// Routed through the host for the same reason ``proximitySupportDirectory`` is, and with one
    /// axis more: the seal key is wiped **by service**, so a store isolated only by directory would
    /// still have its files un-openable the moment a concurrently-running suite ran delete-all.
    /// The app's `FernletStore` derives both halves from seams other walls already enforce
    /// (`MeshSessionStoreIsolationTests`); the default below keeps a test double's scope private to
    /// its own sidecar root rather than lodging it on the production keychain row.
    var meshSessionStorage: MeshSessionStorageScope { get }

    /// This host's sealed ROUTED-CONTENT scope (network migration P5 item 3): the directory holding
    /// `MeshRoutedIndex.sealed`, its `.corrupt` quarantine sibling and the `MeshRoutedChunks`
    /// payload files, plus the keychain service holding the key that seals them.
    ///
    /// A second scope rather than a lodger on ``meshSessionStorage``: the routed store has its own
    /// keychain service, because one fate per service is the only arrangement a service-wide delete
    /// can express honestly, and a session wipe must not silently orphan routed ciphertext this
    /// device is holding for other people. Routed through the host for the same isolation reason
    /// ``meshSessionStorage`` is; the default below keeps a test double's scope private to its own
    /// sidecar root.
    var meshRoutedStorage: MeshRoutedStorageScope { get }
}

public extension ProximityHost {

    /// Default for hosts that do not carry their own scope (test doubles). Production resolves to
    /// `Application Support/Fernlet` + `com.fernlet.mesh-session`, unchanged; a host on any other
    /// sidecar root gets a service named after that root, so it can never wipe — or be wiped by —
    /// the production row or another double's.
    var meshSessionStorage: MeshSessionStorageScope {
        let directory = proximitySupportDirectory
        guard directory != ProximitySupportLayout.defaultDirectory else {
            return MeshSessionStorageScope(
                directory: directory,
                keychainService: MeshSessionStorageScope.productionKeychainService
            )
        }
        return MeshSessionStorageScope(
            directory: directory,
            keychainService: MeshSessionStorageScope.productionKeychainService
                + ".host." + directory.lastPathComponent
        )
    }

    /// Default for hosts that do not carry their own routed scope (test doubles). Production
    /// resolves to `Application Support/Fernlet` + `com.fernlet.mesh-routed`, unchanged; a host on
    /// any other sidecar root gets a service named after that root, so it can never wipe — or be
    /// wiped by — the production row or another double's.
    var meshRoutedStorage: MeshRoutedStorageScope {
        let directory = proximitySupportDirectory
        guard directory != ProximitySupportLayout.defaultDirectory else {
            return MeshRoutedStorageScope(
                directory: directory,
                keychainService: MeshRoutedStorageScope.productionKeychainService
            )
        }
        return MeshRoutedStorageScope(
            directory: directory,
            keychainService: MeshRoutedStorageScope.productionKeychainService
                + ".host." + directory.lastPathComponent
        )
    }
    /// Default for hosts that predate the hearts opt-out (e.g. test doubles). The app's
    /// `FernletStore` overrides this with the live setting.
    var allowNearbyHearts: Bool { true }
    /// Default for hosts that predate away delivery (test doubles). The app overrides it.
    var heartsAwayDeliveryEnabled: Bool { false }
    /// The production sidecar home, and the default for hosts that don't redirect it (test doubles
    /// that never touch the wall). The app's `FernletStore` overrides it with a per-instance root.
    var proximitySupportDirectory: URL { ProximitySupportLayout.defaultDirectory }
}

/// Where the proximity subsystem's on-disk sidecars live. Split out of `MeshNetworkManager`'s
/// initializer so the production path has ONE definition that both the app and the default
/// ``ProximityHost/proximitySupportDirectory`` resolve to.
public enum ProximitySupportLayout {
    /// `Application Support/Fernlet` — unchanged from the path the mesh photo cache, the heart
    /// ledger and the heart-drop sidecars have always used, so no shipped install is migrated by the
    /// seams that made these injectable.
    /// `nonisolated` against the target's `defaultIsolation(MainActor.self)`: a pure path
    /// computation, read from the nonisolated stored properties and static defaults that resolve
    /// production paths (`HeartDropStorageScope.production`, `FernletStore.proximitySupportRoot`).
    public nonisolated static var defaultDirectory: URL {
        // `URL.applicationSupportDirectory` is the non-optional accessor for exactly the path the
        // optional `FileManager.urls(for:in:).first` resolved to (R5: no force unwrap).
        URL.applicationSupportDirectory.appendingPathComponent("Fernlet", isDirectory: true)
    }
}
