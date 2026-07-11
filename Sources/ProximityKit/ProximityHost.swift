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
}

public extension ProximityHost {
    /// Default for hosts that predate the hearts opt-out (e.g. test doubles). The app's
    /// `FernletStore` overrides this with the live setting.
    var allowNearbyHearts: Bool { true }
}
