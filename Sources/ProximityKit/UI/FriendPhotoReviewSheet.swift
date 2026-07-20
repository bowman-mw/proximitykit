import SwiftUI
import FernletUI
import Photos
import UIKit
import FernletDomainModel

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
    let saveSelected: () async -> Void
    let discardAll: () -> Void
    /// Rehydrates a photo's bytes on demand (from the disk cache) for tiles whose in-memory
    /// payload carries no image data — session photos are stored metadata-only to bound memory.
    var loadImageData: ((FriendPhotoPayload) -> Data?)? = nil
    @State private var isSaving = false

    public init(
        photos: [FriendPhotoPayload],
        selectedIDs: Binding<Set<UUID>>,
        friendCandidates: [MeshSessionRosterEntry] = [],
        keptFriendFingerprints: Binding<Set<String>> = .constant([]),
        saveSelected: @escaping () async -> Void,
        discardAll: @escaping () -> Void,
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
                Button("Delete all", role: .destructive, action: discardAll)
                    .buttonStyle(ChipButtonStyle(selected: false))
                    .disabled(isSaving)
                Button("Save selected") {
                    isSaving = true
                    Task {
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
    public static func save(_ photos: [FriendPhotoPayload]) async throws {
        guard !photos.isEmpty else { return }
        let status = await PHPhotoLibrary.requestAuthorization(for: .addOnly)
        guard status == .authorized || status == .limited else {
            throw CocoaError(.userCancelled)
        }

        try await PHPhotoLibrary.shared().performChanges {
            for photo in photos {
                guard let imgData = photo.imageData, let image = UIImage(data: imgData) else { continue }
                PHAssetChangeRequest.creationRequestForAsset(from: image)
            }
        }
    }
}
