import Foundation

/// How the Friends tab must enter discovery, decided as a pure value over the two session
/// predicates the app reads (P6 item 2 fix, review finding P2-5).
///
/// The three-way arm this replaces lived inside `ContentView.startFriendsDiscovery()`, where both
/// halves — the arm and the five-minute timeout that rides it — were `private` in the app target
/// and reddened **nothing** when deleted, while being the whole user-facing claim of item 2's P1
/// (a founded pair whose link dropped can get its radios back at all). Pulled out here it is a
/// four-row truth table a cell can pin, exactly as ``FriendMintingReview/sessionEndReview(hasPhotos:eligibleCandidateCount:)``
/// is for the session-end sheet; the call site stays two lines and a `switch`.
///
/// Deliberately NOT a decision about the *mesh*: it answers only "which radio call", and every
/// reason each answer is right lives with the manager seams it names.
public nonisolated enum FriendsDiscoveryEntry: String, Equatable, Sendable, CaseIterable {

    /// No session at all ⇒ `MeshNetworkManager.startJoin()`, a fresh search cycle with every reset.
    case fresh

    /// A session whose mesh outlived its links and holds no committed peer (a blip, or a tab bounce
    /// after one) ⇒ `MeshNetworkManager.resumeSearchingForPartitionedMesh()`. `startJoin()` is the
    /// wrong answer here and the manager seam's own doc says why: it would nil the session ceiling
    /// on a mesh that can never re-found, and drop this session's photos, film quota and removal
    /// set.
    case resume

    /// A live session with a committed peer ⇒ nothing at all: the radios are already up and
    /// re-entering discovery would re-arm a timeout against a session that is not searching.
    case none

    /// Whether this entry arms the five-minute "found nobody" timeout. Both entries that touch the
    /// radios do; the no-op does not, which is what stops a re-entry while a session is live from
    /// arming a second timeout behind the first.
    public var armsDiscoveryTimeout: Bool { self != .none }

    /// The decision.
    ///
    /// - Parameters:
    ///   - isInSession: `MeshNetworkManager.isInSession` — a mesh is held, or some slot has
    ///     committed.
    ///   - hasCommittedPeer: `MeshNetworkManager.hasCommittedPeer` — a slot holds a committed
    ///     fingerprint right now. Deliberately this predicate and not `isSessionLive`: the question
    ///     is whether the radios have anybody, not whether the session has ended.
    /// - Returns: Which entry to take.
    ///
    /// The fourth row of the table — a committed peer with no session — is **unrepresentable** in
    /// the model (`hasCommittedPeer ⇒ isInSession`, since the same slots satisfy both), and is
    /// answered ``none`` rather than trapped: a committed peer means the radios have a peer, and
    /// re-entering discovery over one is never the safe move. The function is total, so a model
    /// change that makes the row reachable gets an answer instead of a crash.
    public static func entry(isInSession: Bool, hasCommittedPeer: Bool) -> FriendsDiscoveryEntry {
        if hasCommittedPeer { return .none }
        return isInSession ? .resume : .fresh
    }
}
