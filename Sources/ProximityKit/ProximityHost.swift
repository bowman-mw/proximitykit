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
}
