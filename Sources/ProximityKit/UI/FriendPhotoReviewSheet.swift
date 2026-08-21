import SwiftUI
import FernletUI
import Photos
import UIKit
import FernletDomainModel
import FernletFoundation
import os

/// One selectable photo thumbnail in the session-end review grid.
///
/// Renders the payload's inline bytes when present, otherwise rehydrates them on demand through
/// `loadImageData` (session photos are held metadata-only to bound memory); a checkmark overlay
/// marks selection.
struct FriendPhotoTile: View {
    let photo: FriendPhotoPayload
    let selected: Bool
    var loadImageData: (() -> Data?)? = nil

    @State private var loadedImageData: Data?

    var body: some View {
        ZStack(alignment: .topTrailing) {
            if let data = photo.imageData ?? loadedImageData, let image = UIImage(data: data) {
                Image(uiImage: image)
                    .resizable()
                    .scaledToFill()
                    .frame(height: 112)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
            } else {
                RoundedRectangle(cornerRadius: 8)
                    .fill(Color.cream)
                    .frame(height: 112)
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
        .task(id: photo.id) {
            guard photo.imageData == nil else { return }
            loadedImageData = loadImageData?()
        }
    }
}

/// The session-end photo review sheet: pick which shared pictures to keep (everything else is
/// deleted from the temporary cache), with the keep-as-friend section riding along when eligible
/// candidates exist.
///
/// Presented by the app's session-end flow off the promoted review state; the host supplies the
/// save/discard actions (explicitly `@MainActor`-typed so their bodies stay on the main actor
/// after `await` resumes) and the optional disk-cache rehydrator for metadata-only photos.
/// A host that also passes `saveToPhotos` gets the split (FRND-12) action bar: keeping to the
/// in-app wall is the primary action and the system photo-library export is a separate,
/// strictly optional button — so a Photos permission denial can never cost the user the keep.
public struct FriendPhotoReviewSheet: View {
    let photos: [FriendPhotoPayload]
    @Binding var selectedIDs: Set<UUID>
    /// Phase 2 friend minting: session participants eligible to be kept as friends
    /// (empty = hide the section). The host mints the kept set when the review completes.
    var friendCandidates: [MeshSessionRosterEntry] = []
    var keptFriendFingerprints: Binding<Set<String>> = .constant([])
    // MainActor-typed so the supplied closure bodies (which touch @MainActor mesh state and
    // @State) run on the main actor even after an `await` resume, not the module's default
    // (which erases to a bare function value that can resume off-main).
    let saveSelected: @MainActor () async -> Void
    /// FRND-12: when non-nil the pinned bar splits in two — the primary action becomes
    /// "Keep selected" (`saveSelected`, in-app wall only, no Photos authorization involved) and
    /// this closure runs behind a secondary "Also save to Photos" button, so a photo-library
    /// permission denial can never cost the user the keep. When nil the bar keeps the single
    /// legacy "Save selected" primary and the host owns the whole save flow.
    var saveToPhotos: (@MainActor () async -> Void)? = nil
    let discardAll: @MainActor () -> Void
    /// Rehydrates a photo's bytes on demand (from the disk cache) for tiles whose in-memory
    /// payload carries no image data — session photos are stored metadata-only to bound memory.
    var loadImageData: ((FriendPhotoPayload) -> Data?)? = nil
    @State private var isSaving = false
    /// "Delete all" discards every shared picture from this device and leaves the session — on a
    /// sheet that (in the disconnect flow) can't even be swiped away. It asks first.
    @State private var askingToDeleteAll = false

    public init(
        photos: [FriendPhotoPayload],
        selectedIDs: Binding<Set<UUID>>,
        friendCandidates: [MeshSessionRosterEntry] = [],
        keptFriendFingerprints: Binding<Set<String>> = .constant([]),
        saveSelected: @escaping @MainActor () async -> Void,
        saveToPhotos: (@MainActor () async -> Void)? = nil,
        discardAll: @escaping @MainActor () -> Void,
        loadImageData: ((FriendPhotoPayload) -> Data?)? = nil
    ) {
        self.photos = photos
        self._selectedIDs = selectedIDs
        self.friendCandidates = friendCandidates
        self.keptFriendFingerprints = keptFriendFingerprints
        self.saveSelected = saveSelected
        self.saveToPhotos = saveToPhotos
        self.discardAll = discardAll
        self.loadImageData = loadImageData
    }

    /// The explainer, the selectable photo grid, and the keep-friends section.
    private var reviewScrollContent: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Review pictures")
                .font(.fernlet(.displayMedium))
                .foregroundStyle(Color.bark)

            Text(explainerText)
                .font(.fernlet(.body))
                .foregroundStyle(Color.slate)
                .fernletWrappingText()

            LazyVGrid(columns: [GridItem(.adaptive(minimum: 110), spacing: 10)], spacing: 10) {
                ForEach(photos) { photo in
                    Button {
                        toggle(photo.id)
                    } label: {
                        FriendPhotoTile(
                            photo: photo,
                            selected: selectedIDs.contains(photo.id),
                            loadImageData: loadImageData.map { load in { load(photo) } }
                        )
                    }
                    .buttonStyle(.plain)
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

    /// The pinned action bar. Legacy form: discard everything, or save what was picked. Split
    /// (FRND-12) form: the optional "Also save to Photos" export rides above the decisive pair,
    /// and the primary keeps to the in-app wall with no Photos-library involvement.
    private var actionBar: some View {
        VStack(spacing: 10) {
            if let saveToPhotos {
                Button("Also save to Photos") {
                    runExclusively { await saveToPhotos() }
                }
                .buttonStyle(ActionPillButtonStyle(.secondary))
                .disabled(selectedIDs.isEmpty || isSaving)
                .accessibilityIdentifier("friends.review.alsoSaveToPhotos")
            }
            AdaptiveStack(spacing: 10) {
                Button(deleteAllLabel) {
                    askingToDeleteAll = true
                }
                .buttonStyle(ActionPillButtonStyle(.destructive))
                .disabled(isSaving)
                .accessibilityIdentifier("friends.review.deleteAll")
                Button(primaryActionLabel) {
                    runExclusively { await saveSelected() }
                }
                .buttonStyle(ActionPillButtonStyle(.primary))
                .disabled(selectedIDs.isEmpty || isSaving)
                .accessibilityIdentifier("friends.review.saveSelected")
            }
        }
        .padding(16)
        .background(Color.parchment)
    }

    /// Runs one bar action at a time: `isSaving` disables every button until the closure resumes.
    private func runExclusively(_ action: @escaping @MainActor () async -> Void) {
        isSaving = true
        Task { @MainActor in
            await action()
            isSaving = false
        }
    }

    /// The affirmative button's label. The split (FRND-12) bar keeps to the in-app wall — "Keep
    /// selected", no Photos authorization involved; the legacy single-action bar keeps its
    /// original "Save selected".
    private var primaryActionLabel: LocalizedStringKey {
        saveToPhotos == nil ? "Save selected" : "Keep selected"
    }

    /// The explainer under the title — the split (FRND-12) bar talks about keeping, because its
    /// primary action no longer touches the system photo library.
    private var explainerText: LocalizedStringKey {
        saveToPhotos == nil
            ? "Choose which shared pictures to save. Everything else is deleted from this device's temporary cache."
            : "Choose which shared pictures to keep. Everything else is deleted from this device's temporary cache."
    }

    public var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                reviewScrollContent
            }

            actionBar
        }
        .background(Color.parchment)
        .confirmDestructive(
            photos.count == 1 ? "Delete this shared picture?" : "Delete \(photos.count) shared pictures?",
            isPresented: $askingToDeleteAll,
            message: "They'll be removed from this phone. Friends keep their own copies.",
            confirmLabel: deleteAllLabel
        ) {
            // Wrapped rather than passed directly: `discardAll` is explicitly `@MainActor`-typed and
            // the modifier's parameter is a plain function type.
            discardAll()
        }
    }

    /// "Delete all 12" — the count is what turns a mis-tap into a visible amount of loss.
    private var deleteAllLabel: String {
        photos.count == 1 ? "Delete it" : "Delete all \(photos.count)"
    }

    private func toggle(_ id: UUID) {
        if selectedIDs.contains(id) {
            selectedIDs.remove(id)
        } else {
            selectedIDs.insert(id)
        }
    }
}

/// Saves selected friend photos into the system photo library (add-only authorization).
///
/// Stateless namespace enum used by the review sheet's save action. Deliberately `nonisolated`
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
        public var errorDescription: String? {
            "None of the selected pictures could be saved."
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
    public static let generic = PhotoSaveFailure(
        message: "Could not save to your photo library. Please try again.",
        offersSettings: false
    )
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
                message: "Fernlet needs access to your Photo Library to save photos. Open Settings to grant access.",
                offersSettings: true
            )
        }
        if error is NothingSavedError {
            return PhotoSaveFailure(
                message: photoCount == 1
                    ? "This picture couldn't be saved. It may be corrupted."
                    : "None of the selected pictures could be saved. They may be corrupted — try choosing different ones.",
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
                Button("Open Settings") {
                    if let url = URL(string: UIApplication.openSettingsURLString) {
                        UIApplication.shared.open(url)
                    }
                    failure.wrappedValue = nil
                }
            }
            Button("OK", role: .cancel) { failure.wrappedValue = nil }
        } message: {
            Text(failure.wrappedValue?.message ?? "")
        }
    }
}
