// MeshLastMemberPhotoReviewTests.swift
// ProximityKitTests
//
// Owner report, 2026-09-29: "When the last person is knocked out of the mesh because they were the
// last person, it doesn't give them the option of going through the images and picking what they
// want to keep. It keeps everything."
//
// **The mechanism.** Every session photo is written to the persisted friend wall the moment it is
// taken or received (`cachePhoto`); `sessionPhotos` is only the list the review reads, and the ONLY
// thing that ever removes an unkept photo is the user's answer. The last device left in a mesh ends
// through a verified termination — the other side's Develop signs it — and
// `applyVerifiedTermination()` ran `leaveSession()`, whose first line was
// `sessionPhotos.removeAll()`, in the same main-actor turn as the promotion. So by the time
// `FriendsView.presentDisconnectReviewIfNeeded()` ran, it saw no photos: at most the keep-as-friend
// prompt, and every photo stayed on the wall unasked. A removal naming this device, the ceiling,
// epoch exhaustion, the pairwise "Ask to remove" and a hard stop all took the same shortcut.
//
// **The fix under test.** Photos leave the live list only through the user's choice or by being
// PROMOTED into `pendingFriendReview.photos` at the session-end moment — never dropped. The cells
// below drive the owner's case end to end on the fake fabric (both roads a termination reaches the
// last member by: the live record and the merge), the other involuntary endings, and the review
// API's scoping rules; the source walls pin the presenter to the batch.
//
// **And since the owner's 2026-09-30 answer, nothing is on the wall before the choice.** Every
// session photo is HELD in the sealed pending corpus from capture or receipt; the cells that used to
// assert "still on the wall, not yet pruned" now assert the inverse — held, and NOT on the wall, in
// memory or in the persisted index — and every cell that answers pushes an open routed gate first,
// because the answer (which reads plaintext to re-seal kept photos under the wall key) runs only
// where the gate is open.
//
// Nothing here runs a real radio or sleeps on a wall clock; the fabric's clock is advanced by the
// rigs' own bounded settles.
//
// A partial copy (ProximityKit plan step A1.3's batch D, which copies here every Fernlet test cell that
// reads this module's sources before Fernlet stops holding them): of the Fernlet repository's
// FernletTests file of the same name, this holds only `LastMemberPhotoReviewSourceWallTests`' one cell
// that reads ProximityKit's sources (`theLivePhotoListIsEmptiedOnlyByAnAnswerOrThePromotion`), with the
// suite's and the tests' names unchanged and only each cell's half that reads this module's code, now
// through `PackageRoot` and the package's walker. Each cell's half that reads the app's or Fernlet's
// other modules' code, the suite's other cells and the file's other suites stay there, so what this
// header says of them is not held here.

import Foundation
import Testing

// MARK: - Source walls

/// The defect lived in two places a behavioral cell cannot reach at once — the manager's teardown
/// and the SwiftUI presenter — so both are pinned by reading the shipping source. Since plan step
/// A0.5.11 the live list, its answers, the promotion and the purge are the session photos'
/// (`MeshSessionPhotos.swift`), told each moment by the mesh's session observer; the teardown and
/// the start stay the manager's. This copy holds the manager's half; the app-side half (the presenter
/// and the session photos) stays in the Fernlet repository.
@Suite
struct LastMemberPhotoReviewSourceWallTests {

    /// Only the user's answer, the promotion and delete-all may empty the live photo list.
    ///
    /// **This copy's half** (plan step A1.3): the manager's two moments, its leave telling the
    /// observer only after the teardown and its new search telling the observer a session begins.
    /// The live list's emptiers, the answers, the promotion, the purge and the observer's photo legs
    /// are `FernletSocial`'s (`MeshSessionPhotos.swift`, `FernletMeshFeatures.swift`) and stay in the
    /// original.
    @Test func theLivePhotoListIsEmptiedOnlyByAnAnswerOrThePromotion() throws {
        let manager = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift")
        )
        // The leave (plan step A0.5.13): the mesh's `leaveSession()` tears down, which runs the ending
        // and its promotion, and only then tells the observer, whose one photo leg forgets the photo
        // session's ids and decides nothing about the photos (the ending stamped them with those ids).
        let leave = try #require(MeshRoutedSourceScan.bracedBody(after: "public func leaveSession()", in: manager))
        let teardown = try #require(leave.range(of: "leaveMesh("), "leaveSession no longer tears the session down")
        let told = try #require(leave.range(of: "meshSessionDidLeave("), "leaveSession no longer tells the observer")
        #expect(teardown.upperBound <= told.lowerBound, "the observer hears the leave before the teardown's ending")
        let join = try #require(MeshRoutedSourceScan.bracedBody(after: "public func startJoin()", in: manager))
        #expect(join.contains("meshSessionWillBegin("), "a new search tells the session observer a session begins")
    }
}
