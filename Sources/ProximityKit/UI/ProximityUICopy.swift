//
//  ProximityUICopy.swift
//  ProximityKit
//
//  This module's copy vault for the three peer-to-peer UI surfaces (accessibility review
//  2026-08-22, §4.0). Sibling of `FernletUICopy` and `FernletLockCopy`; same reason, same shape.
//
//  ProximityKit's SwiftUI surfaces are the only place in this module where a string is *read by a
//  person*. A `LocalizedStringKey` literal written inside an SPM module resolves against
//  `Bundle.main` — the APP's bundle — which never consults this module's own catalog, so the
//  literal renders as untranslatable English with a clean build and no warning anywhere. Routing
//  the copy through here with `bundle: .module` is what makes it translatable at all.
//
//  DO NOT put wire vocabulary in this file. Every `PayloadSummary` title, every mesh token and
//  every canonical-signature byte is FROZEN ENGLISH and must never reach `String(localized:)` —
//  see `ProximityKit.md` §"Wire vocabulary" and `CanonicalSignatureSerializer.swift:204`. This
//  vault is display copy only: what a person reads, never what a peer parses.
//

import Foundation

/// Display copy owned by ProximityKit's own UI (the friend-photo review sheet, the keep-friends
/// prompt, and the photo-save failure alert).
///
/// Members are computed, not stored, so each lookup happens under the locale in force when the
/// surface renders. Resolved `String`s rather than `LocalizedStringKey`s, deliberately: a key
/// carries no bundle, so handing one to SwiftUI would put the lookup back in `Bundle.main` and
/// undo the fix.
enum ProximityUICopy {

    /// Copy on the post-session photo review sheet.
    enum Review {
        /// The sheet's own title.
        static var title: String {
            String(localized: "proximity.review.title", defaultValue: "Review pictures", bundle: .module,
                   comment: "Title of the sheet shown after a shared photo session, where the user picks which pictures taken of them to keep.")
        }

        /// The optional export button, above the decisive keep/discard pair.
        static var alsoSaveToPhotos: String {
            String(localized: "proximity.review.alsoSaveToPhotos", defaultValue: "Also save to Photos",
                   bundle: .module,
                   comment: "Secondary button copying the selected pictures out to the system Photos library, in addition to keeping them inside Fernlet.")
        }

        /// Affirmative button when the split bar is in use — the primary keeps to the in-app wall.
        static var keepSelected: String {
            String(localized: "proximity.review.keepSelected", defaultValue: "Keep selected", bundle: .module,
                   comment: "Affirmative button of the photo review sheet when a separate 'Also save to Photos' button exists: this one only keeps pictures inside Fernlet.")
        }

        /// Affirmative button on the legacy single-action bar, where the host owns the save flow.
        static var saveSelected: String {
            String(localized: "proximity.review.saveSelected", defaultValue: "Save selected", bundle: .module,
                   comment: "Affirmative button of the photo review sheet on the legacy single-action bar, where saving is the host's whole flow.")
        }

        /// Explainer under the title on the split bar (the primary only keeps).
        static var explainerKeep: String {
            String(localized: "proximity.review.explainer.keep",
                   defaultValue: "Choose which shared pictures to keep. Everything else is deleted from this device's temporary cache.",
                   bundle: .module,
                   comment: "Explainer under the review sheet's title when the primary action only keeps pictures inside Fernlet. The cache deletion is the important half — say it plainly.")
        }

        /// Explainer under the title on the legacy single-action bar.
        static var explainerSave: String {
            String(localized: "proximity.review.explainer.save",
                   defaultValue: "Choose which shared pictures to save. Everything else is deleted from this device's temporary cache.",
                   bundle: .module,
                   comment: "Explainer under the review sheet's title on the legacy single-action bar, where the primary action saves.")
        }

        /// The destructive button when exactly one picture is under review.
        static var deleteOne: String {
            String(localized: "proximity.review.deleteOne", defaultValue: "Delete it", bundle: .module,
                   comment: "Destructive button of the photo review sheet when there is exactly one picture.")
        }

        /// The destructive button, naming the count — a mis-tap should show its size.
        ///
        /// The count is an ARGUMENT and the key carries `one`/`other` plural variations in the
        /// catalog. English never renders the `one` form (``deleteOne`` handles a single picture),
        /// but a language with three or six plural categories needs the block to exist at all.
        ///
        /// - Parameter count: How many shared pictures are under review.
        /// - Returns: The button's label, e.g. "Delete all 12".
        static func deleteAll(_ count: Int) -> String {
            String(localized: "proximity.review.deleteAll", defaultValue: "Delete all \(count)", bundle: .module,
                   comment: "Destructive button of the photo review sheet. The count is deliberate: it turns a mis-tap into a visible amount of loss.")
        }
    }

    /// Copy on the keep-as-friends prompt (its own sheet, or the section inside the review sheet).
    enum KeepFriends {
        /// The standalone prompt's title, for a session that produced no photos.
        static var sessionTitle: String {
            String(localized: "proximity.keepFriends.sessionTitle", defaultValue: "Nice hangout!", bundle: .module,
                   comment: "Warm title of the sheet shown when an in-person session ends without photos, asking whether to keep the people met as friends.")
        }

        /// The section heading above the per-person rows.
        static var sectionTitle: String {
            String(localized: "proximity.keepFriends.sectionTitle", defaultValue: "Keep as friends?", bundle: .module,
                   comment: "Heading of the list of people met during the session, each with a keep-or-not choice.")
        }

        /// The reassurance under the heading: keeping is private and one-sided.
        static var explainer: String {
            String(localized: "proximity.keepFriends.explainer",
                   defaultValue: "Friends stay on your list for good vibes and future hangouts. This is just for you — they won't be notified either way.",
                   bundle: .module,
                   comment: "Body under the keep-as-friends heading. Must keep saying that the choice is private to this user and that the other person is never told either way.")
        }

        /// The per-person chip while that person is NOT being kept — tapping keeps them.
        static var keep: String {
            String(localized: "proximity.keepFriends.keep", defaultValue: "Keep", bundle: .module,
                   comment: "Chip beside one person met during the session, in its unselected state. Tapping it keeps them as a friend.")
        }

        /// The same chip once that person IS being kept.
        static var keeping: String {
            String(localized: "proximity.keepFriends.keeping", defaultValue: "Keeping", bundle: .module,
                   comment: "The keep-as-friend chip in its selected state. Present participle: it describes what will happen, not a completed action.")
        }

        /// Finishes the flow and mints the keeps.
        static var done: String {
            String(localized: "proximity.keepFriends.done", defaultValue: "Done", bundle: .module,
                   comment: "Button that closes the end-of-session sheet and saves the keep-as-friend choices.")
        }
    }

    /// Buttons on the photo-save failure alert.
    enum SaveFailure {
        /// Deep-links to the app's page in Settings, where the Photos permission lives.
        static var openSettings: String {
            String(localized: "proximity.saveFailure.openSettings", defaultValue: "Open Settings", bundle: .module,
                   comment: "Button on the photo-save failure alert that opens the app's own page in the system Settings, where the Photos permission can be granted.")
        }

        /// The catch-all body when a save to the system Photos library failed.
        static var generic: String {
            String(localized: "proximity.saveFailure.generic",
                   defaultValue: "Could not save to your photo library. Please try again.",
                   bundle: .module,
                   comment: "Body of the photo-save failure alert when the cause is unknown, and also when a picture's bytes could not be read back from the encrypted cache at all.")
        }

        /// The body when the system add-only Photos authorization was denied.
        static var permissionDenied: String {
            String(localized: "proximity.saveFailure.permissionDenied",
                   defaultValue: "Fernlet needs access to your Photo Library to save photos. Open Settings to grant access.",
                   bundle: .module,
                   comment: "Body of the photo-save failure alert when the user denied add-only Photos access. This is the only failure that offers the Open Settings button.")
        }

        /// The body when the single picture being saved could not be decoded.
        static var corruptedOne: String {
            String(localized: "proximity.saveFailure.corruptedOne",
                   defaultValue: "This picture couldn't be saved. It may be corrupted.",
                   bundle: .module,
                   comment: "Body of the photo-save failure alert when exactly one picture was being saved and it failed to decode.")
        }

        /// The body when none of several pictures could be decoded.
        static var corruptedMany: String {
            String(localized: "proximity.saveFailure.corruptedMany",
                   defaultValue: "None of the selected pictures could be saved. They may be corrupted — try choosing different ones.",
                   bundle: .module,
                   comment: "Body of the photo-save failure alert when several pictures were being saved and every one failed to decode.")
        }

        /// Dismisses the alert without doing anything.
        static var ok: String {
            String(localized: "proximity.saveFailure.ok", defaultValue: "OK", bundle: .module,
                   comment: "Cancel-role button dismissing the photo-save failure alert.")
        }
    }
}
