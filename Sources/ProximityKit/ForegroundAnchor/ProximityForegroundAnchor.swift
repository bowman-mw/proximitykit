import Foundation

#if canImport(ActivityKit)
import ActivityKit
import FernletDomainModel
import FernletFoundation
#endif

/// Seam for the "connection in progress" foreground anchor a ``ProximityCoordinator`` raises
/// while a session is live — a Live Activity in production, a no-op elsewhere.
///
/// The coordinator calls `start` when a peer identity is confirmed, `update` with running byte
/// counters on every transfer, and `stop` at session end/failure.
///
/// There is exactly one conformer in shipping code: ``NoopProximityForegroundAnchor``. The
/// ActivityKit conformer was RETIRED in the network migration's P9 item 5 — every
/// `Activity.request` it made was doomed, because `ProximityConnectionActivityAttributes` is
/// internal to this module and `App/FernletWidgets/FernletWidgetsBundle.swift` declares no
/// `ActivityConfiguration` for it, so each call either threw (audited) or spent one of the per-app
/// Live Activity slots a workout or cooking activity needs on something nothing draws. The seam
/// itself is kept: it is what a future proximity widget would conform, and tests inject through it.
@MainActor
public protocol ProximityForegroundAnchoring: AnyObject {
    var isActive: Bool { get }
    func start(peerName: String, startedAt: Date) async
    func update(bytesSent: Int, bytesReceived: Int) async
    func stop() async
}

/// ``ProximityForegroundAnchoring`` that tracks only the active flag and shows nothing.
///
/// Since P9 item 5 this is the ONLY anchor in shipping code and ``ProximityCoordinator``'s
/// unconditional default on every platform — not a fallback. Tests observe `isActive` through it
/// to assert that a dropped connection ended its anchor.
@MainActor
final class NoopProximityForegroundAnchor: ProximityForegroundAnchoring {
    private(set) var isActive = false

    func start(peerName: String, startedAt: Date) async {
        isActive = true
    }

    func update(bytesSent: Int, bytesReceived: Int) async {}

    func stop() async {
        isActive = false
    }
}

#if canImport(ActivityKit)
/// ActivityKit attributes for the proximity-connection Live Activity.
///
/// **Nothing requests one of these any more** (P9 item 5). The type is kept for exactly one
/// reader — ``ProximityLiveActivityReaper``, whose enumeration
/// `Activity<ProximityConnectionActivityAttributes>.activities` is spelled in terms of it, so
/// deleting the struct deletes the reaper. No widget declares an `ActivityConfiguration` for it,
/// which is why no request could ever render.
///
/// **Do not change its stored shape.** ActivityKit decodes an activity a previous process
/// stranded against this declaration; a renamed or re-typed property makes such an activity
/// unreapable rather than merely unrendered. Shipping a proximity widget later means ADDING a
/// configuration, not editing these fields.
struct ProximityConnectionActivityAttributes: ActivityAttributes {
    /// The mutable half of the Live Activity: running byte counters and a status word. Only the
    /// reaper writes one now, and only ever `"Ended"`.
    struct ContentState: Codable, Hashable {
        var bytesSent: Int
        var bytesReceived: Int
        var status: String
    }

    var peerName: String
    var startedAt: Date
}

/// Ends every proximity-connection Live Activity left system-side by a PREVIOUS process.
///
/// **Since P9 item 5 nothing in this app requests one**, so this reaper cannot find an activity
/// THIS build created. It is kept deliberately, for two reasons. (1) A build installed before the
/// retirement could in principle have stranded one: the requester held its `Activity` in a private
/// property, the only code that ended it was that same anchor's `stop()`, and a process kill while
/// a session was live left nothing holding a handle — so it lingered until ActivityKit's own
/// maximum-lifetime auto-end (hours), spending a per-app Live Activity slot a later
/// workout/cooking `Activity.request` needs. (2) It is the cheap, already-correct half of shipping
/// a proximity widget later: the reap side exists, so only the configuration and the request would
/// be new. It costs one enumeration of an empty list per launch.
///
/// Call `endOrphans()` ONCE per launch, from the composition root, BEFORE any proximity manager can
/// start a coordinator — never on scene activation, where it would end the activities of anchors
/// still live in this process. The workout/cooking kinds have their own relaunch reapers
/// (`LiveActivityStarter`); this one touches only the proximity kind.
@MainActor
public enum ProximityLiveActivityReaper {
    /// Ends every stranded proximity activity with `.immediate` dismissal. Bounded by the OS
    /// per-app Live Activity cap (R2); a no-op — no awaits — when there is nothing to reap.
    public static func endOrphans() async {
        let content = ActivityContent(
            state: ProximityConnectionActivityAttributes.ContentState(bytesSent: 0, bytesReceived: 0, status: "Ended"),
            staleDate: nil
        )
        for orphan in Activity<ProximityConnectionActivityAttributes>.activities {
            // `Activity` is a non-Sendable class and `end(_:dismissalPolicy:)` is nonisolated
            // async, so the MainActor-held reference is transferred across the call. One local per
            // stranded activity, used for exactly one call, never stored — see the allowlist entry.
            nonisolated(unsafe) let activity = orphan
            await activity.end(content, dismissalPolicy: .immediate)
        }
    }
}
#else
/// Platform twin of the ActivityKit reaper so the composition root compiles everywhere; there are
/// no Live Activities to reap without ActivityKit.
@MainActor
public enum ProximityLiveActivityReaper {
    /// No-op: nothing to reap on a platform without ActivityKit.
    public static func endOrphans() async {}
}
#endif
