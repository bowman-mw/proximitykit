import Foundation

#if canImport(ActivityKit)
import ActivityKit
import FernletDomainModel
#endif

@MainActor
public protocol ProximityForegroundAnchoring: AnyObject {
    var isActive: Bool { get }
    func start(peerName: String, startedAt: Date) async
    func update(bytesSent: Int, bytesReceived: Int) async
    func stop() async
}

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
struct ProximityConnectionActivityAttributes: ActivityAttributes {
    struct ContentState: Codable, Hashable {
        var bytesSent: Int
        var bytesReceived: Int
        var status: String
    }

    var peerName: String
    var startedAt: Date
}

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
        // Activity<…> is a non-Sendable class and update(_:) is nonisolated async; transfer
        // the MainActor-held reference across the call via nonisolated(unsafe). Behaviour-
        // identical to the prior Swift 5 language mode — ActivityKit manages the object's own
        // thread safety, and the reference is not used elsewhere during the await.
        nonisolated(unsafe) let liveActivity = activity
        await liveActivity.update(content)
    }

    func stop() async {
        guard let activity else {
            isActive = false
            return
        }
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
        self.activity = nil
        isActive = false
    }
}
#endif
