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
/// prompt, the photo-save failure alert, and the name placeholders ``PeerNameDisplay`` hands the
/// app's in-person surfaces).
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

        /// The affirmative button: copies the ticked pictures to the in-app wall. Photos-library
        /// export is never this button's job — it is the separate toggle, applied after the keep.
        static var keepSelected: String {
            String(localized: "proximity.review.keepSelected", defaultValue: "Keep selected", bundle: .module,
                   comment: "Affirmative button of the photo review sheet: keeps the ticked pictures inside Fernlet. Copying them to the Photos library is a separate toggle, applied only after the keep.")
        }

        /// Explainer under the title: nothing is saved before the choice, and what is not kept is
        /// deleted. A NEW key, not a reworded `explainer.keep`: the promise changed, and a
        /// translation of the old sentence must not be shown for the new one.
        static var explainerPending: String {
            String(localized: "proximity.review.explainer.pending",
                   defaultValue: "Nothing from this session is saved until you choose. Photos you don't keep are deleted from this phone.",
                   bundle: .module,
                   comment: "Explainer under the photo review sheet's title. Two promises, both load-bearing: nothing is saved (not to Fernlet, not to the camera roll) until the person chooses, and unkept photos are deleted from this phone.")
        }

        /// The opt-in toggle row: export the KEPT photos to the system Photos library, only after the
        /// keep has landed.
        static var alsoSaveToPhotosToggle: String {
            String(localized: "proximity.review.alsoSaveToPhotos.toggle", defaultValue: "Also save kept photos to Photos",
                   bundle: .module,
                   comment: "Toggle on the photo review sheet, off each time. When on, the photos the person keeps are also copied to the system Photos library after they are kept in Fernlet.")
        }

        /// The working line while the kept photos are being copied to the Photos library.
        static var savingToPhotos: String {
            String(localized: "proximity.review.savingToPhotos", defaultValue: "Saving to Photos...", bundle: .module,
                   comment: "Status line on the photo review sheet while kept photos are copied to the system Photos library; the buttons are disabled meanwhile.")
        }

        /// The inline failure when an answer could not be saved (nothing was lost; the photos are
        /// still offered).
        static var answerFailed: String {
            String(localized: "proximity.review.answerFailed",
                   defaultValue: "Couldn't save your choice. Nothing was lost. Try again.",
                   bundle: .module,
                   comment: "Inline message on the photo review sheet when the person's keep/delete answer could not be applied. The photos are still waiting, untouched.")
        }

        /// Why Keep is disabled: the saved wall cannot be read right now.
        static var keepUnavailable: String {
            String(localized: "proximity.review.keepUnavailable",
                   defaultValue: "Keeping isn't possible right now because your saved photos can't be read. You can delete these, or choose later.",
                   bundle: .module,
                   comment: "Line on the photo review sheet shown when the Keep button is disabled because the saved photo album cannot be read right now. Delete all still works.")
        }

        /// The notice for kept photos whose held bytes could not be opened (they were removed).
        ///
        /// - Parameter count: How many photos could not be opened.
        /// - Returns: The notice; the key carries `one`/`other` plural variations in the catalog.
        static func unreadable(_ count: Int) -> String {
            String(localized: "proximity.review.unreadable",
                   defaultValue: "\(count) photos couldn't be opened and were removed.",
                   bundle: .module,
                   comment: "Notice on the photo review sheet after an answer, when some photos the person chose to keep could not be opened and were removed instead. The count is how many.")
        }

        /// The accessibility label of the opaque cover drawn over the review while the app is not
        /// frontmost (the app-switcher snapshot must not hold a photo nobody chose yet).
        static var snapshotCover: String {
            String(localized: "proximity.review.snapshotCover", defaultValue: "Photos hidden", bundle: .module,
                   comment: "Label on the opaque cover over the photo review while the app is not frontmost, so the app switcher never shows photos that have not been chosen yet.")
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
