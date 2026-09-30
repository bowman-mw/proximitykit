import SwiftUI
import FernletUI
import Photos
import UIKit
import FernletDomainModel
import FernletFoundation
import os

/// One selectable photo thumbnail in the session-end review grid.
///
/// Renders the payload's inline bytes when present, otherwise loads them on demand through
/// `loadImageData` (session photos are held metadata-only, sealed in the pending corpus; the host
/// passes its gated seam); a checkmark overlay marks selection.
struct FriendPhotoTile: View {
    let photo: FriendPhotoPayload
    let selected: Bool
    var loadImageData: (() -> Data?)? = nil
    /// Part of the load's identity: a new value loads the bytes again (the review's decrypt seam
    /// may have been closed the first time).
    var reloadToken = 0

    @State private var loadedImageData: Data?

    /// Tile height, scaled with Dynamic Type (accessibility wall rule A5-GRID-SCALES).
    ///
    /// `.body` because the tile carries no caption at all — the only things in it that respond to
    /// Larger Text are two *unstyled* `Image(systemName:)` glyphs (the `photo` placeholder and the
    /// selection checkmark), and an unstyled SF Symbol tracks the default font, which is `.body`.
    /// Picking `.caption` here would grow the box more slowly than the checkmark growing inside it.
    /// Paired with ``FriendPhotoReviewSheet``'s grid minimum on the same role and the same base
    /// ratio, so the tile keeps its proportions instead of stretching into a letterbox at AX sizes.
    @ScaledMetric(relativeTo: .body) private var tileHeight: CGFloat = 112

    var body: some View {
        ZStack(alignment: .topTrailing) {
            if let data = photo.imageData ?? loadedImageData, let image = UIImage(data: data) {
                Image(uiImage: image)
                    .resizable()
                    .scaledToFill()
                    .frame(height: tileHeight)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                    // T2-10: the review grid is where the user decides which of a session's
                    // photographs to keep. Judging that from colour negatives is not a decision.
                    // The moss selection checkmark is a glyph and is left to invert with the chrome.
                    .accessibilityIgnoresInvertColors()
            } else {
                RoundedRectangle(cornerRadius: 8)
                    .fill(Color.cream)
                    .frame(height: tileHeight)
                    .overlay(Image(systemName: "photo").foregroundStyle(Color.slate))
            }

            if selected {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(Color.moss)
                    .background(Color.cream, in: Circle())
                    .padding(6)
            }
        }
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(selected ? Color.moss : Color.bark.opacity(0.08), lineWidth: selected ? 2 : 1)
        )
        // Selection was conveyed by a moss checkmark alone — say it out loud too.
        .accessibilityAddTraits(selected ? .isSelected : [])
        .task(id: "\(photo.id.uuidString)#\(reloadToken)") {
            guard photo.imageData == nil else { return }
            loadedImageData = loadImageData?()
        }
    }
}

/// What the review is busy doing while its buttons are disabled — a line the sheet renders from its
/// own catalog, so a host in another bundle never passes display text in.
///
/// Concurrency: an immutable `Sendable` value.
public enum FriendPhotoReviewWorkingMessage: Equatable, Sendable {
    /// The kept photos are being copied to the system Photos library (after the keep landed).
    case savingToPhotos
    /// The host is waiting for the ended session to be left before it hides the review.
    case endingSession
}

/// The session-end photo review sheet: pick which session pictures to keep — nothing is saved,
/// anywhere, until this answer — with the keep-as-friend section riding along when eligible
/// candidates exist.
///
/// Presented by the app's hosts (the Friends surface's session-end review, the camera's Develop
/// review) over photos HELD in the sealed pending corpus (2026-09-30): ``keepSelected`` copies the
/// ticked ones to the in-app wall, ``discardAll`` deletes every shown one, and the host reads the
/// manager's per-photo answer. Copying to the system Photos library is an opt-in toggle
/// (``alsoSaveToPhotos``) the HOST applies only after the keep has landed and only to the photos
/// that landed — there is no path from this sheet to the camera roll before the choice.
///
/// Two host-driven states: ``answerFailure`` keeps an unapplied answer on screen with an inline line
/// (the photos are still offered; nothing was lost), and ``canKeep`` false disables Keep with the
/// reason while Delete all still works. A host that passes ``notNow`` (the app's session-end overlay)
/// gets a "Not now" text button in the header, and VoiceOver's escape gesture performs it; the
/// camera's Develop sheet passes nil and keeps the sheet's own swipe-down and escape (cancel back to
/// the camera) — except while an answer runs, when the sheet cannot be swiped away
/// (`interactiveDismissDisabled`), so the working line and a failed export's alert stay in front of
/// the person until the answer ends. While the scene is not `.active` the sheet draws an opaque
/// cover INSTEAD of the grid, so the app-switcher snapshot never holds a photo nobody chose (the
/// switcher can be entered without a background transition, hence `!= .active`).
///
/// The actions are explicitly `@MainActor`-typed so their bodies stay on the main actor after an
/// `await` resumes.
public struct FriendPhotoReviewSheet: View {
    let photos: [FriendPhotoPayload]
    @Binding var selectedIDs: Set<UUID>
    /// Phase 2 friend minting: session participants eligible to be kept as friends
    /// (empty = hide the section). The host mints the kept set when the review completes.
    var friendCandidates: [MeshSessionRosterEntry] = []
    var keptFriendFingerprints: Binding<Set<String>> = .constant([])
    /// The opt-in "Also save kept photos to Photos" toggle, off each time the review presents. The
    /// host reads it after the keep; the sheet never exports anything itself.
    @Binding var alsoSaveToPhotos: Bool
    /// False while the wall cannot take a keep (its index cannot be read): Keep is disabled with the
    /// reason, and Delete all still works — a broken wall never deadlocks the review.
    let canKeep: Bool
    /// What the host is busy doing, shown as a status line while every button is disabled.
    let workingMessage: FriendPhotoReviewWorkingMessage?
    /// Why the last answer was not applied in full, shown inline (the review stays up).
    let answerFailure: SessionPhotoAnswerFailure?
    /// How many kept photos could not be opened and were removed by the last answer.
    let unreadableCount: Int
    /// Bumped by the host when the decrypt seam reopens, so a tile that loaded nothing while it was
    /// closed loads again.
    let tileReloadToken: Int
    let keepSelected: @MainActor () async -> Void
    let discardAll: @MainActor () async -> Void
    /// Hides the review WITHOUT answering anything (the overlay's "Not now"); nil where the host's
    /// own dismissal is the way out (the camera's Develop sheet).
    let notNow: (@MainActor () -> Void)?
    /// Loads a held photo's bytes for its tile (the host's gated seam); nil draws a placeholder.
    var loadImageData: ((FriendPhotoPayload) -> Data?)? = nil
    @State private var isSaving = false
    /// "Delete all" deletes every shown picture from this device — on a sheet that (in the
    /// disconnect flow) can't even be swiped away. It asks first.
    @State private var askingToDeleteAll = false
    /// Read for the snapshot cover. Both hosts are SwiftUI presentations inside the app scene, so
    /// the scene's phase reaches this sheet through the environment.
    @Environment(\.scenePhase) private var scenePhase
    /// Adaptive-grid cell minimum, scaled with Dynamic Type (accessibility wall rule
    /// A5-GRID-SCALES). A bare `110` pins the cell while ``FriendPhotoTile``'s contents grow
    /// inside it; this grows the column with them, so the grid reflows to fewer, larger tiles at
    /// accessibility text sizes instead of crowding the selection checkmark against the edge.
    ///
    /// `.body` for the same reason the tile's own height uses it — see `FriendPhotoTile.tileHeight`
    /// for the evidence. The two must stay on the same role: scaling one and not the other stretches
    /// the tile out of proportion. At the default text size `@ScaledMetric` returns the base value,
    /// so this is not a visual change for anyone who has not asked for one.
    @ScaledMetric(relativeTo: .body) private var photoTileMinimum: CGFloat = 110

    /// Creates the review.
    ///
    /// - Parameters:
    ///   - photos: The held photos to offer (metadata only; tiles load through `loadImageData`).
    ///   - selectedIDs: The ticked photos.
    ///   - friendCandidates: Eligible keep-as-friend candidates (empty hides the section).
    ///   - keptFriendFingerprints: The candidates the person chose to keep.
    ///   - alsoSaveToPhotos: The opt-in camera-roll toggle the host applies after the keep.
    ///   - canKeep: Whether the wall can take a keep right now.
    ///   - workingMessage: What the host is busy doing, if anything.
    ///   - answerFailure: Why the last answer was not applied in full, if it was not.
    ///   - unreadableCount: Kept photos the last answer removed because they could not be opened.
    ///   - tileReloadToken: Changes when tiles should load again.
    ///   - keepSelected: Keeps the ticked photos.
    ///   - discardAll: Deletes every shown photo (after the sheet's own confirmation).
    ///   - notNow: Hides the review answering nothing; nil hides the header button.
    ///   - loadImageData: The tile loader.
    public init(
        photos: [FriendPhotoPayload],
        selectedIDs: Binding<Set<UUID>>,
        friendCandidates: [MeshSessionRosterEntry] = [],
        keptFriendFingerprints: Binding<Set<String>> = .constant([]),
        alsoSaveToPhotos: Binding<Bool>,
        canKeep: Bool = true,
        workingMessage: FriendPhotoReviewWorkingMessage? = nil,
        answerFailure: SessionPhotoAnswerFailure? = nil,
        unreadableCount: Int = 0,
        tileReloadToken: Int = 0,
        keepSelected: @escaping @MainActor () async -> Void,
        discardAll: @escaping @MainActor () async -> Void,
        notNow: (@MainActor () -> Void)? = nil,
        loadImageData: ((FriendPhotoPayload) -> Data?)? = nil
    ) {
        self.photos = photos
        self._selectedIDs = selectedIDs
        self.friendCandidates = friendCandidates
        self.keptFriendFingerprints = keptFriendFingerprints
        self._alsoSaveToPhotos = alsoSaveToPhotos
        self.canKeep = canKeep
        self.workingMessage = workingMessage
        self.answerFailure = answerFailure
        self.unreadableCount = unreadableCount
        self.tileReloadToken = tileReloadToken
        self.keepSelected = keepSelected
        self.discardAll = discardAll
        self.notNow = notNow
        self.loadImageData = loadImageData
    }

    /// The explainer, the selectable photo grid, and the keep-friends section.
    private var reviewScrollContent: some View {
        VStack(alignment: .leading, spacing: 18) {
            header

            Text(verbatim: ProximityUICopy.Review.explainerPending)
                .font(.fernlet(.body))
                .foregroundStyle(Color.slate)
                .fernletWrappingText()

            LazyVGrid(columns: [GridItem(.adaptive(minimum: photoTileMinimum), spacing: 10)], spacing: 10) {
                ForEach(photos) { photo in
                    Button {
                        toggle(photo.id)
                    } label: {
                        FriendPhotoTile(
                            photo: photo,
                            selected: selectedIDs.contains(photo.id),
                            loadImageData: loadImageData.map { load in { load(photo) } },
                            reloadToken: tileReloadToken
                        )
                    }
                    .buttonStyle(.plain)
                    // Who took it (a withheld name reads as the placeholder, never a fingerprint)
                    // and what a double-tap does; the tile carries `.isSelected` itself.
                    .accessibilityLabel(Text(verbatim: ProximityUICopy.Review.tileLabel(
                        PeerNameDisplay.shown(photo.senderName, fingerprint: photo.senderFingerprint, placeholder: .met)
                    )))
                    .accessibilityHint(Text(verbatim: ProximityUICopy.Review.tileHint))
                }
            }

            if !friendCandidates.isEmpty {
                Divider().overlay(Color.bark.opacity(0.08))
                KeepFriendsSection(
                    candidates: friendCandidates,
                    keptFingerprints: keptFriendFingerprints
                )
            }
        }
        .padding(20)
        .padding(.bottom, 10)
    }

    /// The title — a VoiceOver heading — and, when the host offers it, the "Not now" text button.
    private var header: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(verbatim: ProximityUICopy.Review.title)
                .font(.fernlet(.displayMedium))
                .foregroundStyle(Color.bark)
                .accessibilityAddTraits(.isHeader)
            Spacer(minLength: 8)
            if let notNow {
                Button(ProximityUICopy.Review.notNow) { notNow() }
                    .font(.fernlet(.label))
                    .foregroundStyle(Color.mossInk)
                    .frame(minHeight: 44)
                    .disabled(isBusy)
                    .accessibilityIdentifier("friends.review.notNow")
            }
        }
    }

    /// The pinned action bar: the status line (when there is one), the opt-in camera-roll toggle,
    /// then the decisive pair — delete everything shown, or keep what was picked.
    private var actionBar: some View {
        VStack(spacing: 10) {
            if let line = statusLine {
                Text(verbatim: line.text)
                    .font(.fernlet(.bodySmall))
                    .foregroundStyle(line.isFailure ? Color.bark : Color.slate)
                    .multilineTextAlignment(.center)
                    .fernletWrappingText()
                    .accessibilityIdentifier(line.identifier)
            }
            Toggle(isOn: $alsoSaveToPhotos) {
                Text(verbatim: ProximityUICopy.Review.alsoSaveToPhotosToggle)
                    .font(.fernlet(.body))
                    .foregroundStyle(Color.bark)
            }
            .tint(Color.moss)
            .disabled(isBusy || !keepAvailable)
            .accessibilityIdentifier("friends.review.alsoSaveToPhotosToggle")
            AdaptiveStack(spacing: 10) {
                Button(deleteAllLabel) {
                    askingToDeleteAll = true
                }
                .buttonStyle(ActionPillButtonStyle(.destructive))
                .disabled(isBusy)
                .accessibilityIdentifier("friends.review.deleteAll")
                Button(ProximityUICopy.Review.keepSelected) {
                    runExclusively { await keepSelected() }
                }
                .buttonStyle(ActionPillButtonStyle(.primary))
                .disabled(selectedIDs.isEmpty || isBusy || !keepAvailable)
                .accessibilityIdentifier("friends.review.saveSelected")
            }
        }
        .padding(16)
        .background(Color.parchment)
    }

    /// Whether any action is running — this sheet's own, or the host's working state.
    private var isBusy: Bool { isSaving || workingMessage != nil }

    /// Whether Keep may be offered: the host says the wall can take it, and the last answer did not
    /// just find it unreadable.
    private var keepAvailable: Bool { canKeep && answerFailure != .keepUnavailable }

    /// The one status line under the grid, most urgent first: what the host is doing, why Keep is
    /// off, why the last answer did not land, and what the last answer could not open.
    private var statusLine: FriendPhotoReviewStatusLine? {
        switch workingMessage {
        case .savingToPhotos:
            return FriendPhotoReviewStatusLine(
                text: ProximityUICopy.Review.savingToPhotos, identifier: "friends.review.working", isFailure: false
            )
        case .endingSession:
            return FriendPhotoReviewStatusLine(
                text: ProximityUICopy.Review.endingSession, identifier: "friends.review.working", isFailure: false
            )
        case nil:
            break
        }
        if !keepAvailable {
            return FriendPhotoReviewStatusLine(
                text: ProximityUICopy.Review.keepUnavailable, identifier: "friends.review.keepUnavailable",
                isFailure: true
            )
        }
        if answerFailure != nil {
            return FriendPhotoReviewStatusLine(
                text: ProximityUICopy.Review.answerFailed, identifier: "friends.review.answerFailed", isFailure: true
            )
        }
        guard unreadableCount > 0 else { return nil }
        return FriendPhotoReviewStatusLine(
            text: ProximityUICopy.Review.unreadable(unreadableCount), identifier: "friends.review.unreadable",
            isFailure: true
        )
    }

    /// Runs one bar action at a time: `isSaving` disables every button until the closure resumes.
    private func runExclusively(_ action: @escaping @MainActor () async -> Void) {
        isSaving = true
        Task { @MainActor in
            await action()
            isSaving = false
        }
    }

    public var body: some View {
        ZStack {
            if scenePhase == .active {
                VStack(spacing: 0) {
                    ScrollView {
                        reviewScrollContent
                    }
                    actionBar
                }
            } else {
                snapshotCover
            }
        }
        .background(Color.parchment)
        // An answer that has started is finished in front of the person: no swipe-away mid-answer
        // (the Develop sheet's host would otherwise lose its working line and its failure alert).
        .interactiveDismissDisabled(isBusy)
        .modifier(EscapePerformsNotNow(notNow: isBusy ? nil : notNow))
        .onChange(of: statusLine?.text) { _, line in
            // The working line and the inline failure are announced, not only drawn.
            guard let line else { return }
            FernletAnnouncer.system.announce(.status, resolved: line)
        }
        .confirmDestructive(
            photos.count == 1 ? "Delete this shared picture?" : "Delete \(photos.count) shared pictures?",
            isPresented: $askingToDeleteAll,
            message: "They'll be removed from this phone. Friends keep their own copies.",
            confirmLabel: deleteAllLabel
        ) {
            // Wrapped rather than passed directly: `discardAll` is explicitly `@MainActor`-typed and
            // the modifier's parameter is a plain function type.
            runExclusively { await discardAll() }
        }
    }

    /// The opaque cover drawn INSTEAD of the review while the scene is not active: no tile image is
    /// in the view tree, so the snapshot iOS writes for the app switcher cannot hold a pending photo.
    /// One accessibility element carrying the explanation.
    private var snapshotCover: some View {
        ZStack {
            Color.parchment.ignoresSafeArea()
            VStack(spacing: 8) {
                Image(systemName: "lock.fill")
                    .font(.title2.weight(.semibold))
                    .foregroundStyle(Color.slate)
                Text(verbatim: ProximityUICopy.Review.snapshotCover)
                    .font(.fernlet(.labelSmall))
                    .foregroundStyle(Color.slate)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(verbatim: ProximityUICopy.Review.snapshotCover))
        .accessibilityIdentifier("friends.review.snapshotCover")
    }

    /// "Delete all 12" — the count is what turns a mis-tap into a visible amount of loss.
    private var deleteAllLabel: String {
        photos.count == 1 ? ProximityUICopy.Review.deleteOne : ProximityUICopy.Review.deleteAll(photos.count)
    }

    private func toggle(_ id: UUID) {
        if selectedIDs.contains(id) {
            selectedIDs.remove(id)
        } else {
            selectedIDs.insert(id)
        }
    }
}

/// VoiceOver's escape gesture (the two-finger scrub) as "Not now" on the host that offers it.
///
/// Attached only when there is a `notNow` to run: an `.accessibilityAction(.escape)` hung on the
/// camera's Develop sheet would replace the sheet's own escape, which is its cancel back to the
/// camera. Nil while the review is busy, so a scrub cannot run past a disabled button.
private struct EscapePerformsNotNow: ViewModifier {
    let notNow: (@MainActor () -> Void)?

    func body(content: Content) -> some View {
        if let notNow {
            content.accessibilityAction(.escape) { notNow() }
        } else {
            content
        }
    }
}

/// One status line under the review grid: resolved text, its frozen accessibility identifier, and
/// whether it reports a failure (drawn in the stronger colour).
///
/// Concurrency: an immutable value built during body evaluation.
private struct FriendPhotoReviewStatusLine: Equatable {
    let text: String
    let identifier: String
    let isFailure: Bool
}

/// Saves KEPT friend photos into the system photo library (add-only authorization).
///
/// Stateless namespace enum used by the review hosts' post-answer export — only ever over the
/// photos an answer reported landed on the wall, re-read from the wall, never pending bytes — and
/// by the album carousel's per-photo save of a photo already on the wall. Deliberately `nonisolated`
/// with a `@Sendable` change block: `PHPhotoLibrary.performChanges` runs on its own serial queue,
/// and inheriting the module's MainActor default there trips the Swift executor precondition (the
/// build-19 TestFlight crash). Counts actual creation requests so an all-decode-failure surfaces
/// as ``NothingSavedError`` instead of a false success.
public enum FriendPhotoLibrarySaver {
    /// Thrown when the payload list was non-empty but every image failed to decode, so no
    /// asset was actually created. Without this the flow reports success and leaves the
    /// session with zero pictures saved.
    public struct NothingSavedError: LocalizedError {
        public init() {}
        /// Package source, so the lookup passes `bundle: .module`: without it the resolution goes
        /// to `Bundle.main`, finds nothing, and silently renders the English `defaultValue` forever.
        public var errorDescription: String? {
            String(localized: "friendPhoto.error.nothingSaved",
                   defaultValue: "None of the selected pictures could be saved.",
                   bundle: .module,
                   comment: "Shown after saving shared friend photos when every image failed to decode, so no asset was created. Reports the real outcome rather than a false success.")
        }
    }

    // `nonisolated` + an explicit `@Sendable` change block so this work does NOT inherit the
    // target's default MainActor isolation (FernletKit/Package.swift sets
    // `.defaultIsolation(MainActor.self)` on ProximityKit). Photos runs `performChanges` on its
    // own private serial queue; a MainActor-inheriting block trips the Swift executor
    // precondition (`dispatch_assert_queue_fail`) — the build-19 TestFlight crash. Everything the
    // block touches is created locally; `photos` is Sendable.
    public nonisolated static func save(_ photos: [FriendPhotoPayload]) async throws {
        guard !photos.isEmpty else { return }
        let status = await PHPhotoLibrary.requestAuthorization(for: .addOnly)
        guard status == .authorized || status == .limited else {
            throw CocoaError(.userCancelled)
        }

        // Count creation requests inside the block: if every payload fails to decode we must
        // surface an error rather than report a false "saved".
        let savedCount = OSAllocatedUnfairLock(initialState: 0)
        let skippedCount = OSAllocatedUnfairLock(initialState: 0)
        try await PHPhotoLibrary.shared().performChanges { @Sendable in
            for photo in photos {
                guard let imgData = photo.imageData, let image = UIImage(data: imgData) else {
                    skippedCount.withLock { $0 += 1 }
                    continue
                }
                PHAssetChangeRequest.creationRequestForAsset(from: image)
                savedCount.withLock { $0 += 1 }
            }
        }
        // R7: a partial save ("3 of 5") used to report as full success with nothing recorded.
        let skipped = skippedCount.withLock { $0 }
        if skipped > 0 {
            FernletAuditLog.log("photoSave.partialDecodeFailure", context: ["skipped": "\(skipped)"])
        }
        guard savedCount.withLock({ $0 }) > 0 else { throw NothingSavedError() }
    }
}

/// A user-facing photo-library save failure: the alert body plus whether the alert should offer
/// the Open Settings shortcut (only the permission denial does).
///
/// UI-only presentation state — deliberately NOT `Codable` and never persisted or sent over the
/// wire. Produced by ``FriendPhotoLibrarySaver``'s `userFacingFailure(for:photoCount:)` mapping
/// and rendered by the shared `photoSaveFailureAlert(_:failure:)` modifier so every save surface
/// (session-end review, disconnect review, album carousel) shows identical wording.
public struct PhotoSaveFailure: Equatable {
    /// The alert body shown to the user.
    public var message: String
    /// Whether the alert offers an "Open Settings" button — true only for the
    /// photo-library-permission denial, whose fix lives in Settings.
    public var offersSettings: Bool

    /// The catch-all failure ("Could not save to your photo library. Please try again."), also
    /// assigned directly by hosts as the pre-save guard when a photo's bytes could not be
    /// rehydrated from the encrypted disk cache at all.
    /// A computed property, not a `static let`: the message resolves through this module's catalog
    /// (`bundle: .module`, review §4.0), and a stored constant would freeze whichever language the
    /// process launched in.
    public static var generic: PhotoSaveFailure {
        PhotoSaveFailure(message: ProximityUICopy.SaveFailure.generic, offersSettings: false)
    }
}

extension FriendPhotoLibrarySaver {
    /// Maps a `save(_:)` failure onto the shared user-facing alert content.
    ///
    /// `photoCount` is how many photos the caller was saving — it selects the singular or plural
    /// corruption wording when every image failed to decode (``NothingSavedError``). A permission
    /// denial (`CocoaError.userCancelled` from the add-only authorization gate) yields the only
    /// failure that offers the Open Settings shortcut; any other error maps to
    /// ``PhotoSaveFailure/generic``.
    public static func userFacingFailure(for error: Error, photoCount: Int) -> PhotoSaveFailure {
        if (error as? CocoaError)?.code == .userCancelled {
            return PhotoSaveFailure(
                message: ProximityUICopy.SaveFailure.permissionDenied,
                offersSettings: true
            )
        }
        if error is NothingSavedError {
            return PhotoSaveFailure(
                message: photoCount == 1
                    ? ProximityUICopy.SaveFailure.corruptedOne
                    : ProximityUICopy.SaveFailure.corruptedMany,
                offersSettings: false
            )
        }
        return .generic
    }
}

extension View {
    /// Presents the shared "couldn't save" alert whenever `failure` is non-nil.
    ///
    /// Renders identically at every photo-save surface: the failure's message as the body, an
    /// "Open Settings" button (deep-linking to the app's Settings page) only when the failure
    /// offers it, and an OK cancel button; every button clears the binding. The title stays a
    /// parameter because the carousel's single-photo alert is deliberately titled in the
    /// singular ("Couldn't Save Photo") while the review sheets use the plural.
    public func photoSaveFailureAlert(
        _ title: String,
        failure: Binding<PhotoSaveFailure?>
    ) -> some View {
        alert(title, isPresented: failure.isPresent()) {
            if failure.wrappedValue?.offersSettings == true {
                Button(ProximityUICopy.SaveFailure.openSettings) {
                    if let url = URL(string: UIApplication.openSettingsURLString) {
                        UIApplication.shared.open(url)
                    }
                    failure.wrappedValue = nil
                }
            }
            Button(ProximityUICopy.SaveFailure.ok, role: .cancel) { failure.wrappedValue = nil }
        } message: {
            // `verbatim:` because `PhotoSaveFailure.message` is a caller-supplied, already-final
            // sentence — the hosts assemble it. The label also states that plainly, which is what
            // keeps the display-literal wall from having to guess about the `?? ""` fallback.
            Text(verbatim: failure.wrappedValue?.message ?? "")
        }
    }
}
