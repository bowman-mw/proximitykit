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
/// consume: display name and the block/fingerprint checks — and five requirements the extension
/// below will never give a default, because each is the host's identity, custody or rule, not the
/// mechanism's: the host's protocol identity, ``proximityNamespace``, its install binding,
/// ``proximityInstallBinding``, the session trust policy every connection's coordinator consults,
/// ``makeProximityTrustPolicy()``, the device identity a manager holds, ``makeProximityIdentity()``,
/// and the routed types its features carry, ``meshRoutedTypeEntries``. The requirements only a host's
/// social features read — its trusted-peer records, its durable trust store, the in-person hearts
/// opt-in and the heart-eligibility predicate over them — are FernletSocial's `FernletSocialHost`'s,
/// a refinement of this protocol: no code in this module reads them.
@MainActor
public protocol ProximityHost: AnyObject {
    var proximityDisplayName: String { get }
    func isBlockedFingerprint(_ fingerprint: String) -> Bool
    func blockProximityPeer(signingPublicKey: Data)
    /// Root directory for the proximity subsystem's on-disk files: this module's two sealed mesh
    /// stores, through the default ``meshSessionStorage`` and ``meshRoutedStorage`` built from it, and
    /// the files a host's mesh features keep on the same root — for Fernlet, FernletSocial's session
    /// photos' friend photo-wall index (`MeshPhotoCache.sealed`, GCM-sealed under the friend-wall media
    /// key; a legacy plaintext `MeshPhotoCache.json` is read once, resealed, and deleted by
    /// `PrivateMediaStore.loadIndex()`), its preferences (`MeshPhotoWallPreferences.json`) and the
    /// pending session-photo corpus (`PendingSessionPhotos/`), the activity ledger
    /// (`ActivityLedger.json`), and the heart set (`HeartLedger.json` plus the three sealed sidecars
    /// named by FernletSocial's `HeartDropStorageScope`).
    ///
    /// Comes through the HOST rather than being a constant because it is shared *mutable on-disk
    /// state*: a photo's delete and an answer's keep re-save the whole wall index, every hold and
    /// answer rewrites the pending session-photo index beside it (2026-09-30), and every session-photo
    /// object loads both at init. With one process-wide path, a store built in one test reads (and
    /// overwrites) the wall of every other live one — and under the test runner, where XCTest and
    /// Swift Testing suites run in parallel in ONE process, that is a live cross-suite race. Routing it
    /// through the host means every manager and composition built over a store inherits its isolation
    /// for free. Same reasoning as
    /// `FernletStore.photoDocumentsDirectory`, for the corpus on the other side of the media-key split.
    ///
    /// The heart-drop sidecars share this root but need a second half the wall does not: they are
    /// sealed, and their key is wiped by service, so isolating them means isolating FernletSocial's
    /// `HeartDropStorageScope` (directory + keychain service), not just a directory.
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

    /// The host's protocol identity: the labels, radio values, QR
    /// scheme, identity and mesh seal-key rows, storage names and log subsystem by which this module's
    /// wire, keychain and disk formats identify the app it runs in, as the one ``ProximityNamespace``
    /// the host builds at its composition root. The radios, their postures and ``PeerNameDisplay`` read
    /// the radios' presentation strings off it too. It also carries the payload vocabulary, which this
    /// module reads off it as well: the envelope, the coordinator, the managers, the inventory digest
    /// and the mesh engine's own frames; the routed-type rows a host supplies are keyed by its routed
    /// types. A host's features' payload and capability tokens are the host's own (Fernlet's
    /// FernletSocial features spell `PayloadType` and `ProximityCapability` raw values through this
    /// module's token doors), and so are its feature labels: this module reads none from
    /// FernletCrypto's registry. The heart dead-drop's keychain service and the moderation ban store's
    /// are FernletSocial's, which also names presence's epoch-tag prefix and the activities' and the
    /// moderation report's signature labels, and the sealed-backup escrow's labels are its app's.
    /// `ProximityNamespaceBoundaryTests` allowlists each literal that spells `fernlet` and each line
    /// that still names one of Fernlet's domain types, with the step that removes it.
    ///
    /// **Deliberately no default.** The extension below hands a host that carries no value of its
    /// own the sidecar root and the two storage scopes; it hands out no namespace, and never will.
    /// ProximityKit holds no namespace instance
    /// and keeps no global, so a host that supplies none gets a compile error, never another app's
    /// identity. Fernlet's app supplies `ProximityNamespace.fernlet` (the `FernletConnections` module)
    /// in `ProximityHostAdapter.swift`, as twelve of the test target's seventeen doubles do; the other
    /// five, `ProximityNamespaceGoldenTests`' three hosts and `ProximityVocabularyGoldenTests`' two,
    /// take theirs from the cell that builds them: another app's, or Fernlet's with some of its groups
    /// replaced, in the cells that test one.
    ///
    /// Read once, at construction: ``MeshNetworkManager`` and ``ProximityRecipeShareManager`` here,
    /// and FernletSocial's `PresenceManager`, each keep their own copy, build the radio they own by
    /// default from it and check against it the identity they own (``makeProximityIdentity()``'s when
    /// they are handed none), so no later read reaches back to the host; FernletSocial's mesh features
    /// read the copy their composition's host holder keeps the same way. The extension below also
    /// builds this host's default sidecar root and both storage scopes from it, and every scope
    /// carries it to the store that reads its names.
    var proximityNamespace: ProximityNamespace { get }

    /// The host's install binding: the per-install bytes the two
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
    /// so ``MeshNetworkManager`` (per slot), FernletSocial's `PresenceManager` (per heart connection)
    /// and ``ProximityRecipeShareManager`` (per pairing) each call this once per connection, test seams
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

    /// A fresh device identity for a manager that was handed none: the identity
    /// ``MeshNetworkManager``, ``ProximityRecipeShareManager`` and FernletSocial's `PresenceManager`
    /// build by default, once each, at construction.
    ///
    /// **No default, like ``proximityNamespace``, because an identity's custody is the host's.** A
    /// host that keeps keys of its own beside the device identity's rows answers an identity that
    /// carries its ``IdentityProvisioningParticipant``, so every identity a manager holds provisions
    /// under that host's rules, and ProximityKit never guesses one: an identity with another
    /// participant, or none, provisions without the host's keys, so a host that answers nothing fails
    /// to compile instead. Fernlet's app answers its factory's identity, whose participant is its
    /// sealed-backup escrow key, in `ProximityHostAdapter.swift` (`KeyCustodyBoundaryTests` holds its
    /// three managers to that participant). Sixteen of the test target's seventeen doubles answer
    /// `IdentityService(namespace: proximityNamespace)`, this device's identity under the host's
    /// namespace with no participant, through one test-only extension the app's conformance cannot
    /// see; the seventeenth, `ProximityNamespaceGateTests`' `ForeignIdentityHost`, answers an identity
    /// of another namespace, so each manager's check of its host's identity can be seen refusing.
    ///
    /// A new value per call, built from the host's values and reading and writing nothing until the
    /// manager provisions it. Each manager checks it against its namespace
    /// (``ProximityNamespaceGate/checkIdentity(_:isOf:event:)``) before anything else: an identity of
    /// another namespace makes it audit `<area>.identity.namespaceMismatch` and start no radio.
    func makeProximityIdentity() -> IdentityService

    /// The host's routed-type rows: every routed type its features mint, project or judge. The engine
    /// declares none of its own.
    ///
    /// **No default, like ``proximityNamespace``.** Which routed types a host's features carry, and
    /// each one's cap, destination semantics, retention, final acknowledgement, expiry and content
    /// scope, is the host's declaration, so ProximityKit never guesses a row: a host that supplies none
    /// fails to compile.
    ///
    /// **Reading each row's token off its own namespace's routed types is the host's obligation**, so
    /// that it never registers another app's spelling, and every token it registers is one its
    /// namespace's soundness rules already hold to 1 to 64 bytes of printable ASCII, the width a routed
    /// manifest's type token may have (`MeshRoutedManifestFormat.maxTypeTokenLength`). The engine checks
    /// no row's token. A row whose token is empty or wider than that is registered all the same, and
    /// every item minted or received under it is then refused at the manifest; a row whose token is
    /// well formed but none of the namespace's routed types is registered and carries items like any
    /// other, under a spelling the namespace does not declare.
    ///
    /// Read once, by ``MeshNetworkManager``'s initializer, which builds its one routed type registry
    /// from these rows alone. What the engine itself applies to a row is exactly this: at most sixteen
    /// rows are read, a token's first row wins, and a row is registered only when its relay retention is
    /// one the engine implements, its cap is at least 1 byte and its cap is at most the wire bound
    /// (`MeshRoutedManifestFormat.maxContentByteCount`); any other row is dropped, its token then
    /// refused at every door. The widest accepted row's cap is the one resident bound the engine's
    /// seal, open and projection guard share. Every door that admits, resolves, acknowledges or
    /// forwards an item reads that registry, and a projection handler or a ledger judge registers only
    /// under one of its rows. Fernlet's app answers FernletSocial's `FernletRoutedTypes.entries` over
    /// its namespace's routed types (the temporary-message, heart and photo rows) in
    /// `ProximityHostAdapter.swift`; the test target's doubles answer the same through one test-only
    /// extension the app's conformance cannot see.
    var meshRoutedTypeEntries: [MeshRoutedTypeEntry] { get }
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
    /// The production sidecar home, and the default for hosts that don't redirect it (test doubles
    /// that never touch the wall): the host namespace's `installation.storage.defaultDirectory` (plan
    /// step A0.2.8; for Fernlet `Application Support/Fernlet`, unchanged). The app's `FernletStore`
    /// overrides it with a per-instance root.
    var proximitySupportDirectory: URL { proximityNamespace.installation.storage.defaultDirectory }
}
