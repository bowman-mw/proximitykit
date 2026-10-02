//
//  ProximityUICopy.swift
//  ProximityKit
//
//  This module's copy vault (accessibility review 2026-08-22, §4.0). Sibling of `FernletUICopy`
//  and `FernletLockCopy`; same reason, same shape.
//
//  ProximityKit has no SwiftUI surface of its own any more. The three it shipped — the friend-photo
//  review sheet, the keep-friends prompt and the photo-save failure alert — moved to
//  `FernletProximityUI` in plan step A0.1 (Docs/Plan-FernletCoach-ProximityKit-2026-10-01.md §4),
//  and their 28 keys went with them, unchanged, into `FernletProximityUICopy` and that module's own
//  catalog. What stays here is the copy this module still hands out as resolved strings: the
//  camera's hold-failure line (`MeshNetworkManager` publishes it as `meshError`) and the two name
//  placeholders `PeerNameDisplay` resolves.
//
//  A `String(localized:)` inside an SPM module that omits `bundle: .module` resolves against
//  `Bundle.main` — the APP's bundle — which never consults this module's own catalog, so the
//  string renders as untranslatable English with a clean build and no warning anywhere. Routing
//  the copy through here with `bundle: .module` is what makes it translatable at all.
//
//  DO NOT put wire vocabulary in this file. Every `PayloadSummary` title, every mesh token and
//  every canonical-signature byte is FROZEN ENGLISH and must never reach `String(localized:)` —
//  see `ProximityKit.md` §"Wire vocabulary" and `CanonicalSignatureSerializer.swift:204`. This
//  vault is display copy only: what a person reads, never what a peer parses.
//

import Foundation

/// Display copy ProximityKit hands out already resolved: the camera's hold-failure line and the
/// name placeholders ``PeerNameDisplay`` hands the app's in-person surfaces. The review sheet's,
/// the keep-friends prompt's and the photo-save failure alert's copy is `FernletProximityUICopy`,
/// in `FernletProximityUI`.
///
/// Members are computed, not stored, so each lookup happens under the locale in force when the
/// surface renders. Resolved `String`s rather than `LocalizedStringKey`s, deliberately: a key
/// carries no bundle, so handing one to SwiftUI would put the lookup back in `Bundle.main` and
/// undo the fix.
enum ProximityUICopy {

    /// Copy the disposable camera's session surfaces read from the manager.
    enum Camera {
        /// The capture refusal when this phone could not seal its own copy (no film is spent and
        /// nothing is shared). Rendered by the camera's session alert through `meshError`.
        static var holdFailed: String {
            String(localized: "proximity.camera.holdFailed", defaultValue: "Couldn't keep that photo. Try again.",
                   bundle: .module,
                   comment: "Alert on the in-person camera when a photo just taken could not be saved securely on this phone. No film was used and nothing was shared.")
        }
    }

    /// The plain phrases that stand in for a person whose name is not known, read through
    /// ``PeerNameDisplay``. `nonisolated` because that helper is: a resolved display string has no
    /// actor to protect, and `Bundle.module` is itself nonisolated.
    nonisolated enum Peer {
        /// Someone on the connect path whose name has not been shared yet.
        static var someoneNearby: String {
            String(localized: "proximity.peer.someoneNearby", defaultValue: "Someone nearby", bundle: .module,
                   comment: "Stands in for a nearby person whose name has not been shared yet: the connect rows on the Friends tab, the session's participant list, a join request, a recipe recipient. A plain phrase, shown where a name would be.")
        }

        /// Someone met in an earlier session whose name never arrived.
        static var someoneYouMet: String {
            String(localized: "proximity.peer.someoneYouMet", defaultValue: "Someone you met", bundle: .module,
                   comment: "Stands in for a person met in person whose name never arrived before the connection ended: the keep-as-friend rows at the end of a session and the Friends & Blocks list.")
        }
    }
}
