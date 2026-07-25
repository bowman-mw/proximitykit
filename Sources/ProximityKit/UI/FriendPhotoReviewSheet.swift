import SwiftUI
import FernletUI
import Photos
import UIKit
import FernletDomainModel
import os

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
        .task(id: photo.id) {
            guard photo.imageData == nil else { return }
            loadedImageData = loadImageData?()
        }
    }
}

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
    let discardAll: @MainActor () -> Void
    /// Rehydrates a photo's bytes on demand (from the disk cache) for tiles whose in-memory
    /// payload carries no image data — session photos are stored metadata-only to bound memory.
    var loadImageData: ((FriendPhotoPayload) -> Data?)? = nil
    @State private var isSaving = false

    public init(
        photos: [FriendPhotoPayload],
        selectedIDs: Binding<Set<UUID>>,
        friendCandidates: [MeshSessionRosterEntry] = [],
        keptFriendFingerprints: Binding<Set<String>> = .constant([]),
        saveSelected: @escaping @MainActor () async -> Void,
        discardAll: @escaping @MainActor () -> Void,
        loadImageData: ((FriendPhotoPayload) -> Data?)? = nil
    ) {
        self.photos = photos
        self._selectedIDs = selectedIDs
        self.friendCandidates = friendCandidates
        self.keptFriendFingerprints = keptFriendFingerprints
        self.saveSelected = saveSelected
        self.discardAll = discardAll
        self.loadImageData = loadImageData
    }

    public var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    Text("Review pictures")
                        .font(.fernlet(.displayMedium))
                        .foregroundStyle(Color.bark)

                    Text("Choose which shared pictures to save. Everything else is deleted from this device's temporary cache.")
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

            HStack(spacing: 10) {
                Button("Delete all", role: .destructive) {
                    discardAll()
                }
                .buttonStyle(ChipButtonStyle(selected: false))
                .disabled(isSaving)
                Button("Save selected") {
                    isSaving = true
                    Task { @MainActor in
                        await saveSelected()
                        isSaving = false
                    }
                }
                .buttonStyle(ChipButtonStyle(selected: true))
                .disabled(selectedIDs.isEmpty || isSaving)
            }
            .padding(16)
            .background(Color.parchment)
        }
        .background(Color.parchment)
    }

    private func toggle(_ id: UUID) {
        if selectedIDs.contains(id) {
            selectedIDs.remove(id)
        } else {
            selectedIDs.insert(id)
        }
    }
}

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
        try await PHPhotoLibrary.shared().performChanges { @Sendable in
            for photo in photos {
                guard let imgData = photo.imageData, let image = UIImage(data: imgData) else { continue }
                PHAssetChangeRequest.creationRequestForAsset(from: image)
                savedCount.withLock { $0 += 1 }
            }
        }
        guard savedCount.withLock({ $0 }) > 0 else { throw NothingSavedError() }
    }
}
