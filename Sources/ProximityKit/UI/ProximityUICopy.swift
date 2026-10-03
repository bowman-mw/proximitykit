//
//  ProximityUICopy.swift
//  ProximityKit
//
//  This module's copy vault (accessibility review 2026-08-22, §4.0). Sibling of `FernletUICopy`
//  and `FernletLockCopy`; same reason, same shape.
//
//  ProximityKit has no SwiftUI surface of its own: the friend-photo review sheet, the keep-friends
//  prompt and the photo-save failure alert are `FernletProximityUI`'s, with their copy in
//  `FernletProximityUICopy` and that module's own catalog, and the plain placeholder a person reads
//  when `PeerNameDisplay` refuses a name is the host's (Fernlet's is `FernletConnectionsCopy`'s, in
//  FernletConnections' catalog). What is here is the one string this module still hands out
//  resolved: the camera's hold-failure line (`MeshNetworkManager` publishes it as `meshError`).
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

/// Display copy ProximityKit hands out already resolved: the camera's hold-failure line. The review
/// sheet's, the keep-friends prompt's and the photo-save failure alert's copy is
/// `FernletProximityUICopy`, in `FernletProximityUI`, and the name placeholders the app's in-person
/// surfaces show when ``PeerNameDisplay`` refuses a name are `FernletConnectionsCopy`'s, in
/// `FernletConnections`.
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
}
