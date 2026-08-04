import Foundation

#if canImport(ActivityKit)
import ActivityKit
import FernletDomainModel
#endif

/// Seam for the "connection in progress" foreground anchor a ``ProximityCoordinator`` raises
/// while a session is live — a Live Activity in production, a no-op elsewhere.
///
/// The coordinator calls `start` when a peer identity is confirmed, `update` with running byte
/// counters on every transfer, and `stop` at session end/failure. Conformers:
/// ``ActivityKitProximityForegroundAnchor`` (ActivityKit) and ``NoopProximityForegroundAnchor``
/// (tests, platforms without ActivityKit).
@MainActor
public protocol ProximityForegroundAnchoring: AnyObject {
    var isActive: Bool { get }
    func start(peerName: String, startedAt: Date) async
    func update(bytesSent: Int, bytesReceived: Int) async
    func stop() async
}

/// ``ProximityForegroundAnchoring`` that tracks only the active flag and shows nothing.
///
/// Injected in unit tests and used as the fallback when ActivityKit is unavailable.
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
/// ActivityKit attributes for the proximity-connection Live Activity: the fixed peer name and
/// start time, plus the mutable transfer counters.
///
/// The app target's Live Activity widget renders these; this module only requests and updates
/// the activity.
struct ProximityConnectionActivityAttributes: ActivityAttributes {
    /// The mutable half of the Live Activity: running byte counters and a status word
    /// ("Connected" / "Ended"). Updated by ``ActivityKitProximityForegroundAnchor``.
    struct ContentState: Codable, Hashable {
        var bytesSent: Int
        var bytesReceived: Int
        var status: String
    }

    var peerName: String
    var startedAt: Date
}

/// Production ``ProximityForegroundAnchoring``: runs a Live Activity for the duration of a
/// proximity connection so the transfer stays visible when the user leaves the app.
///
/// Holds at most one `Activity` at a time; `start` no-ops when activities are disabled or one is
/// already live, `update` deduplicates identical counter values, and `stop` claims ownership
/// (nils the stored activity) synchronously BEFORE its await so a racing `update` bails instead
/// of resurrecting an ended activity. Content auto-stales after 90 s as the backstop for the
/// narrow documented races. Non-Sendable `Activity` values are transferred across nonisolated
/// async calls via `nonisolated(unsafe)` locals — see the inline notes.
@MainActor
final class ActivityKitProximityForegroundAnchor: ProximityForegroundAnchoring {
    private var activity: Activity<ProximityConnectionActivityAttributes>?
    private(set) var isActive = false
    private var lastBytesSent = -1
    private var lastBytesReceived = -1

    func start(peerName: String, startedAt: Date) async {
        guard ActivityAuthorizationInfo().areActivitiesEnabled else { return }
        guard activity == nil else { return }
        do {
            let attributes = ProximityConnectionActivityAttributes(peerName: peerName, startedAt: startedAt)
            let content = ActivityContent(
                state: ProximityConnectionActivityAttributes.ContentState(
                    bytesSent: 0,
                    bytesReceived: 0,
                    status: "Connected"
                ),
                staleDate: Date().addingTimeInterval(90)
            )
            activity = try Activity.request(attributes: attributes, content: content, pushType: nil)
            lastBytesSent = 0
            lastBytesReceived = 0
            isActive = true
        } catch {
            isActive = false
        }
    }

    func update(bytesSent: Int, bytesReceived: Int) async {
        guard let activity else { return }
        guard bytesSent != lastBytesSent || bytesReceived != lastBytesReceived else { return }
        lastBytesSent = bytesSent
        lastBytesReceived = bytesReceived
        let content = ActivityContent(
            state: ProximityConnectionActivityAttributes.ContentState(
                bytesSent: bytesSent,
                bytesReceived: bytesReceived,
                status: "Connected"
            ),
            staleDate: Date().addingTimeInterval(90)
        )
        // Activity<…> is a non-Sendable class and update(_:) is nonisolated async; transfer the
        // MainActor-held reference across the call via nonisolated(unsafe). The `guard let activity`
        // above ensures we only update a live activity, and stop() clears `self.activity` BEFORE it
        // ends the activity, so an update() scheduled after a stop() bails at that guard rather than
        // resurrecting an ended activity. (A narrow residual race remains only if an update() is
        // already suspended at this await when stop() runs; that content auto-stales in 90s.)
        nonisolated(unsafe) let liveActivity = activity
        await liveActivity.update(content)
    }

    func stop() async {
        guard let activity else {
            isActive = false
            return
        }
        // Claim ownership synchronously BEFORE the await: a concurrently-scheduled update() that begins
        // during end()'s suspension then sees `self.activity == nil` at its guard and skips, instead of
        // pushing a "Connected" update onto the activity we are ending (resurrecting it). The local
        // `activity` binding keeps the object alive for the end() call below.
        //
        // A symmetric start() that interleaves at end()'s suspension also sees `self.activity == nil` and
        // may request a FRESH Live Activity while this one is still ending. That window is benign: both
        // methods are @MainActor (so they interleave only at awaits, never truly concurrently), start()'s
        // catch resets `isActive = false` on a rejected request, and the worst case is a brief duplicate
        // anchor that auto-stales — the same accepted trade-off the update() race above documents.
        self.activity = nil
        isActive = false
        let content = ActivityContent(
            state: ProximityConnectionActivityAttributes.ContentState(
                bytesSent: 0,
                bytesReceived: 0,
                status: "Ended"
            ),
            staleDate: nil
        )
        // non-Sendable Activity across nonisolated async end(_:); see update(_:) note above.
        nonisolated(unsafe) let liveActivity = activity
        await liveActivity.end(content, dismissalPolicy: .immediate)
    }
}
#endif
