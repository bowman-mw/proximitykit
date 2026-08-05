// PeerDisplayNames.swift
// ProximityKit
//
// The two shared display-name coercions of the proximity subsystem: the LOCAL name a radio
// advertises (host preference → device-name fallback), and the wire-boundary coercion every
// PEER-supplied name passes through before it is shown or persisted. Previously duplicated
// across the mesh / recipe-share / presence managers and their consumers.
//
// Deliberately NOT adopted by the app-side FernletStore.shopDisplayName or the HeartDropService
// name paths — those variants differ on purpose.

import UIKit
import FernletDomainModel

extension ProximityHost {
    /// The local display name a proximity radio advertises: `proximityDisplayName` trimmed of
    /// whitespace, falling back to the device name when the user hasn't set one. The single home
    /// of the three previously identical private `displayName` vars in `MeshNetworkManager`,
    /// `ProximityRecipeShareManager`, and `PresenceManager`.
    var resolvedProximityDisplayName: String {
        let name = proximityDisplayName.trimmingCharacters(in: .whitespaces)
        return name.isEmpty ? UIDevice.current.name : name
    }
}

extension ItemNameModeration {
    /// Wire-boundary coercion for a PEER-supplied display name about to be rendered or
    /// persisted: `sanitizedName` (control/zero-width/bidi scalars out, whitespace collapsed,
    /// length-capped), falling back to "A friend" when nothing displayable remains. The single
    /// home of the sanitize-or-"A friend" idiom used by the heart receive paths, the vouch-list
    /// cache, the session chat store, and the keep-as-friend rows.
    nonisolated static func moderatedPeerDisplayName(_ raw: String) -> String {
        let name = sanitizedName(raw)
        return name.isEmpty ? "A friend" : name
    }
}
