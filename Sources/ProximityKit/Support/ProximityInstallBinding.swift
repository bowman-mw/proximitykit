// ProximityInstallBinding.swift
// ProximityKit/Support
//
// ProximityKit plan step A0.2.9 (Docs/Plan-FernletCoach-ProximityKit-2026-10-01.md §4 A0.2, "Injected by
// the host: … the `DeviceBindingID`, so its keychain row stays shared with Fernlet's private stores"):
// the install binding that `ProximityColumnCrypto` mixes into the authenticated data of every blob the
// two sealed mesh stores write, as a capability the host hands in. ProximityKit keeps no binding row of
// its own. An install has one binding, shared with whatever else the host seals under it, so the host
// reads it and ProximityKit asks. It reaches the stores through their storage scopes, required at
// construction like the namespace beside it, and never through a global.

import Foundation

// MARK: - ProximityInstallBindingAccess

/// What a sealed store is about to do with the install binding, which decides what reading it may do.
///
/// The two answers differ on purpose, exactly as Fernlet's `DeviceBindingID.current()` and
/// `currentForOpen()` do: a seal may create the binding, an open never may, and only an open has to
/// tell an absent binding from a read that failed.
public nonisolated enum ProximityInstallBindingAccess: Hashable, Sendable {
    /// Sealing a new blob. The host may mint the binding, and durably store it, when the install has
    /// none yet, and it answers `nil` whenever it cannot produce a durable one: a row it could not
    /// mint, or a read whose outcome is unknown. A `nil` refuses the seal (owner decision D4): no blob
    /// is written without the binding, and none under one the next open might not reproduce.
    case seal
    /// Opening an existing blob. Never mints: a sealed blob exists only because a binding was durably
    /// stored on this install, so a fresh one could never open it. `nil` means the binding is
    /// authoritatively absent, and the open refuses, terminally. A read that failed throws
    /// ``ProximityInstallBindingReadError``, and the open defers, retryably.
    case open
}

// MARK: - ProximityInstallBindingReadError

/// The install binding could not be read, so its state is unknown: retry later.
///
/// Thrown by an ``ProximityInstallBindingAccess/open`` read, and only when the read itself failed — as
/// opposed to a binding that is authoritatively absent, which answers `nil`. Retryable by contract: the
/// two sealed mesh stores defer on it (their `installBindingReadError` deferral) and never refuse or
/// call the bytes corrupt, so a transient keychain outage, such as the window before a device's first
/// unlock, reads as "try again" and never as "this data is gone". A read failure while sealing refuses
/// the seal instead, as an absent binding does.
///
/// Mirrors Fernlet's `DeviceBindingID.ReadError`, field for field: Fernlet's adapter
/// (`FernletDeviceBindingAdapter`, in FernletConnections) throws this with the status that error carries.
public nonisolated struct ProximityInstallBindingReadError: Error, Hashable, Sendable {
    /// The status the read failed with; for a keychain-backed binding, the `SecItemCopyMatching` status.
    public let status: OSStatus

    /// A read failure.
    ///
    /// - Parameter status: The status the read failed with.
    public init(status: OSStatus) {
        self.status = status
    }
}

// MARK: - ProximityInstallBinding

/// The host's per-install binding: the bytes, unique to one install of the host app on one device, that
/// `ProximityColumnCrypto` places after the column label in the authenticated data of every blob the two
/// sealed mesh stores write. A blob therefore refuses to authenticate on any other install, even under
/// the right content key.
///
/// **One row per install, the host's.** Fernlet's binding is FernletCrypto's `DeviceBindingID`: 16
/// random bytes in one never-synchronized, `AfterFirstUnlockThisDeviceOnly` keychain row that its
/// sealed private stores mix into their own blobs too. ProximityKit reading a row of its own would
/// split that row in two, and every mesh file sealed before would stop opening. So the host supplies
/// the binding and ProximityKit only asks for it, through ``read(for:)``, once per seal and once per
/// open. Fernlet's adapter (`FernletDeviceBindingAdapter`, in FernletConnections) delegates to
/// `DeviceBindingID` at each call, so its cache, its durability gate and its task-local test seam stay
/// the only ones.
///
/// **How it arrives.** Through ``MeshSessionStorageScope/installBinding`` and
/// ``MeshRoutedStorageScope/installBinding``, which every scope initializer requires, and
/// ``ProximityHost/proximityInstallBinding``, from which the host seam's default scopes are built. It
/// has no default, and ProximityKit keeps no global: a host that supplies none gets a compile error,
/// never another app's binding.
///
/// `nonisolated` against the module's `defaultIsolation(MainActor.self)`, and `Sendable`: the column
/// seal reads it synchronously from inside the nonisolated stores, whatever task they run on.
public nonisolated protocol ProximityInstallBinding: Sendable {

    /// This install's binding, read for `access`.
    ///
    /// Synchronous, and called once per seal or open, at that moment: an answer that changes between
    /// two calls is seen by the second.
    ///
    /// - Parameter access: Whether the caller seals or opens, which decides what the read may do (see
    ///   ``ProximityInstallBindingAccess``).
    /// - Returns: The binding's bytes, taken whole into the authenticated data; `nil` for no binding.
    /// - Throws: ``ProximityInstallBindingReadError`` when an open's read failed and the binding's
    ///   state is unknown.
    func read(for access: ProximityInstallBindingAccess) throws(ProximityInstallBindingReadError) -> Data?
}
