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
/// consume: display name, trusted peers + trust store, and the block/fingerprint checks — and, since
/// ProximityKit plan step A0.2.3, the host's protocol identity, ``proximityNamespace``, since
/// step A0.2.9 its install binding, ``proximityInstallBinding``, and the session trust policy every
/// connection's coordinator consults, ``makeProximityTrustPolicy()``: three requirements the
/// extension below will never give a default.
@MainActor
public protocol ProximityHost: AnyObject {
    var proximityDisplayName: String { get }
    /// Every trusted-peer record the host keeps (kept, removed, blocked and reported alike), in the
    /// host's persisted type: the managers read a friend's record from them where a feature needs one
    /// (presence tags, a heart connection's sealing key, a heart sender's filed name, the mesh's vouch
    /// list). The same records ``proximityTrustStore`` answers from: Fernlet's app and every test
    /// double answer their vault's.
    var trustedProximityPeers: [ProximityTrustedPeerRecord] { get }
    /// The host's durable trust records, asked the two questions this module puts to them outside a
    /// session: whether a signing key is a remembered, unrevoked peer, and whether it is blocked
    /// (``ProximityTrustStore`` says where each manager asks).
    ///
    /// **No default, like ``trustedProximityPeers``.** Which peers a device remembers is the host's
    /// record, not the mechanism's, so ProximityKit keeps none of its own: a host that supplies none
    /// fails to compile. Fernlet's app answers its `ProximityTrustVault` (the `FernletConnections`
    /// module) in `ProximityHostAdapter.swift`, and every test double answers its own vault. The
    /// managers read it at each question, so an answer always reflects the records as they are then.
    var proximityTrustStore: any ProximityTrustStore { get }
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
    /// shared *mutable on-disk state*: `deletePhoto` and an answer's keep re-save the whole wall
    /// index, every hold and answer rewrites the pending session-photo index beside it
    /// (`PendingSessionPhotos/`, 2026-09-30), and every manager loads both at init. With one process-wide path, a manager built
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

    /// The host's protocol identity (ProximityKit plan step A0.2.3): the labels, radio values, QR
    /// scheme, identity and mesh seal-key rows, storage names and log subsystem by which this module's
    /// wire, keychain and disk formats identify the app it runs in, as the one ``ProximityNamespace``
    /// the host builds at its composition root. The radios, their postures and ``PeerNameDisplay`` read
    /// the radios' presentation strings off it too. It also carries the payload vocabulary, which this
    /// module reads off it as well: the envelope, the coordinator, the managers, the inventory digest,
    /// the routed type registry and the mesh engine's own frames; the mesh features' payload and
    /// capability tokens are still Fernlet's cases until plan steps A0.4 and A0.5. Some such strings
    /// stay outside it until plan step A0.4:
    /// the feature labels, the heart-drop and moderation keychain services and
    /// ``ProximitySupportLayout``'s folder. `ProximityNamespaceBoundaryTests` allowlists each
    /// feature-label read and each literal that spells `fernlet`.
    ///
    /// **Deliberately no default.** The extension below hands a host that carries no value of its
    /// own the hearts settings, the sidecar root and the two storage scopes; it hands out no
    /// namespace, and never will. ProximityKit holds no namespace instance and keeps no global, so a
    /// host that supplies none gets a compile error, never another app's identity. Fernlet's app
    /// supplies `ProximityNamespace.fernlet` (the `FernletConnections` module) in
    /// `ProximityHostAdapter.swift`, as the test target's eleven Fernlet doubles do;
    /// `ProximityNamespaceGoldenTests`' three hosts take theirs from the cell that builds them, another
    /// app's in the cells that test one.
    ///
    /// Read once, at construction: ``MeshNetworkManager``, ``PresenceManager`` and
    /// ``ProximityRecipeShareManager`` each keep their own copy and build the identity and the radio
    /// they own by default from it, so no later read reaches back to the host. Since step A0.2.8 the
    /// extension below also builds this host's default sidecar root and both storage scopes from it,
    /// and every scope carries it to the store that reads its names.
    var proximityNamespace: ProximityNamespace { get }

    /// The host's install binding (ProximityKit plan step A0.2.9): the per-install bytes the two
    /// sealed mesh stores' column seal places after the column label in every blob's authenticated
    /// data, read at each seal and each open.
    ///
    /// **No default, like ``proximityNamespace``.** An install has one binding, shared with whatever
    /// else the host seals under it, so ProximityKit keeps no row of its own and never falls back to
    /// one: a host that supplies none fails to compile. Fernlet's app answers
    /// `FernletDeviceBindingAdapter()` (the `FernletConnections` module, delegating to FernletCrypto's
    /// `DeviceBindingID`) in `ProximityHostAdapter.swift`, as the test target's doubles do, but for
    /// the two `ProximityNamespaceGoldenTests` hosts that take theirs from the cell that builds them,
    /// a pinned binding in the cells that test one. The extension below builds both default storage
    /// scopes with it; a host with scopes of its own hands each the same binding.
    var proximityInstallBinding: any ProximityInstallBinding { get }

    /// A fresh trust policy for one connection: the ``ProximityTrustPolicy`` that the
    /// ``ProximityCoordinator`` a manager builds for a friend-mode link consults on every inbound
    /// envelope (the revoked-key hard fail, the blocked-key silent drop, remembered-trust
    /// auto-confirm) and records its audit events through.
    ///
    /// **A new value per call, kept alive by the caller.** The coordinator holds its policy `weak`,
    /// so ``MeshNetworkManager`` (per slot), ``PresenceManager`` (per heart connection) and
    /// ``ProximityRecipeShareManager`` (per pairing) each call this once per connection, test seams
    /// included, and keep the result beside that connection for its lifetime: a policy nothing
    /// retains lets the revoked and blocked drops silently stop firing.
    ///
    /// **No default, like ``proximityNamespace``.** Which peers a session trusts, treats as revoked
    /// and bans is the host's rule, not the mechanism's, so ProximityKit ships no session policy and
    /// never falls back to one: a host that supplies none fails to compile. Fernlet's app answers
    /// `FriendSessionTrustPolicy(vault: proximityTrustVault)` (the `FernletConnections` module, over
    /// the store's `ProximityTrustVault`) in `ProximityHostAdapter.swift`, and every test double
    /// answers the same over its own vault.
    func makeProximityTrustPolicy() -> any ProximityTrustPolicy
}

public extension ProximityHost {

    /// Default for hosts that do not carry their own scope (test doubles), built from the host's
    /// namespace (plan step A0.2.8) and install binding (plan step A0.2.9). On the namespace's
    /// default directory it is the namespace's production scope — for Fernlet
    /// `Application Support/Fernlet` + `com.fernlet.mesh-session`, unchanged; a host on any other
    /// sidecar root gets a service named after that root, so it can never wipe — or be wiped by —
    /// the production row or another double's.
    var meshSessionStorage: MeshSessionStorageScope {
        let namespace = proximityNamespace
        let directory = proximitySupportDirectory
        guard directory != namespace.installation.storage.defaultDirectory else {
            return MeshSessionStorageScope(
                namespace: namespace,
                directory: directory,
                keychainService: namespace.installation.keychain.meshSessionSealKey.service,
                installBinding: proximityInstallBinding
            )
        }
        return MeshSessionStorageScope(
            namespace: namespace,
            directory: directory,
            keychainService: namespace.installation.keychain.meshSessionSealKey.service
                + ".host." + directory.lastPathComponent,
            installBinding: proximityInstallBinding
        )
    }

    /// Default for hosts that do not carry their own routed scope (test doubles), built from the
    /// host's namespace (plan step A0.2.8) and install binding (plan step A0.2.9). On the
    /// namespace's default directory it is the namespace's production scope — for Fernlet
    /// `Application Support/Fernlet` + `com.fernlet.mesh-routed`, unchanged; a host on any other
    /// sidecar root gets a service named after that root, so it can never wipe — or be wiped by —
    /// the production row or another double's.
    var meshRoutedStorage: MeshRoutedStorageScope {
        let namespace = proximityNamespace
        let directory = proximitySupportDirectory
        guard directory != namespace.installation.storage.defaultDirectory else {
            return MeshRoutedStorageScope(
                namespace: namespace,
                directory: directory,
                keychainService: namespace.installation.keychain.meshRoutedSealKey.service,
                installBinding: proximityInstallBinding
            )
        }
        return MeshRoutedStorageScope(
            namespace: namespace,
            directory: directory,
            keychainService: namespace.installation.keychain.meshRoutedSealKey.service
                + ".host." + directory.lastPathComponent,
            installBinding: proximityInstallBinding
        )
    }
    /// Default for hosts that predate the hearts opt-out (e.g. test doubles). The app's
    /// `FernletStore` overrides this with the live setting.
    var allowNearbyHearts: Bool { true }
    /// Default for hosts that predate away delivery (test doubles). The app overrides it.
    var heartsAwayDeliveryEnabled: Bool { false }
    /// The production sidecar home, and the default for hosts that don't redirect it (test doubles
    /// that never touch the wall): the host namespace's `installation.storage.defaultDirectory` (plan
    /// step A0.2.8; for Fernlet `Application Support/Fernlet`, unchanged). The app's `FernletStore`
    /// overrides it with a per-instance root.
    var proximitySupportDirectory: URL { proximityNamespace.installation.storage.defaultDirectory }
}

/// Where the proximity subsystem's on-disk sidecars live. Split out of `MeshNetworkManager`'s
/// initializer so the production path had ONE definition that both the app and the default
/// ``ProximityHost/proximitySupportDirectory`` resolved to. Since plan step A0.2.8 those two, and the
/// mesh stores' production scopes, resolve the host namespace's
/// `installation.storage.defaultDirectory` instead, built the same way (Fernlet's spells the same
/// folder); this one stays for the heart-drop scope's and the feature ledgers' defaults until their
/// features leave in plan step A0.4.
public enum ProximitySupportLayout {
    /// `Application Support/Fernlet` — unchanged from the path the mesh photo cache, the heart
    /// ledger and the heart-drop sidecars have always used, so no shipped install is migrated by the
    /// seams that made these injectable.
    /// `nonisolated` against the target's `defaultIsolation(MainActor.self)`: a pure path
    /// computation, read by the nonisolated static default `HeartDropStorageScope.production`. The
    /// main-actor feature ledgers (`ProximityHeartLedger`, `FriendStateCache`, `ClosenessLedger`,
    /// `ModerationLedger`, `ProximityActivityManager`) read it too, for their initializers' default
    /// file URLs.
    public nonisolated static var defaultDirectory: URL {
        // `URL.applicationSupportDirectory` is the non-optional accessor for exactly the path the
        // optional `FileManager.urls(for:in:).first` resolved to (R5: no force unwrap).
        URL.applicationSupportDirectory.appendingPathComponent("Fernlet", isDirectory: true)
    }
}
