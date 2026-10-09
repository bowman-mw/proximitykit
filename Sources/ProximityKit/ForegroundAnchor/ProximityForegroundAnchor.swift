import Foundation

/// Seam for the "connection in progress" foreground anchor a ``ProximityCoordinator`` raises
/// while a session is live — a no-op in shipping code since P9 item 5.
///
/// The coordinator calls `start` when a peer identity is confirmed, `update` with running byte
/// counters on every transfer, and `stop` at session end/failure.
///
/// There is exactly one conformer in shipping code: ``NoopProximityForegroundAnchor``. The
/// ActivityKit conformer was RETIRED in the network migration's P9 item 5 — every
/// `Activity.request` it made was doomed, because the proximity activity's attributes type was
/// internal to this module and `App/FernletWidgets/FernletWidgetsBundle.swift` declares no
/// `ActivityConfiguration` for it, so each call either threw (audited) or spent one of the per-app
/// Live Activity slots a workout or cooking activity needs on something nothing draws. The seam
/// itself is kept: it is what a future proximity widget would conform, and tests inject through it.
/// The once-per-launch reaper of the activities earlier builds stranded, and the attributes type it
/// enumerates, are the app's `ProximityLiveActivityReaper` since plan step A0.6, so this module
/// imports no ActivityKit.
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
