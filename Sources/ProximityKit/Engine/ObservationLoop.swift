// ObservationLoop.swift
// ProximityKit
//
// The single home of the coordinator-state observation loop that MeshNetworkManager,
// ProximityRecipeShareManager, and PresenceManager previously each hand-rolled
// (byte-identical machinery whose leak-fix comment had drifted to only one copy —
// exactly the hand-propagation hazard this extraction removes).

import Observation

/// The shared `withObservationTracking` re-arm loop behind the proximity managers'
/// coordinator-state observers (`MeshNetworkManager.startObserving`,
/// `ProximityRecipeShareManager.startObserving`, `PresenceManager.startHeartObserving`).
///
/// Each iteration registers the caller's tracked reads, suspends until Observation reports a
/// change, then runs the caller's check on the main actor and re-arms. The owner is held
/// **weakly** by the loop task and strongly only for the duration of one iteration, so the
/// loop terminates on owner deallocation instead of suspending forever — do not replace the
/// owner parameter with weak-self caller closures, which would reintroduce the suspended-task
/// leak documented below.
@MainActor
enum ObservationLoop {

    /// Start the observation loop for `owner` and return the loop task (callers store it and
    /// `cancel()` it in their stop paths, exactly as they did with the hand-rolled loops).
    ///
    /// - Parameters:
    ///   - owner: The manager whose state is observed. Captured `weak`; each iteration begins
    ///     with `guard let owner else { return }` so dealloc ends the loop.
    ///   - tracking: Performs the tracked reads (`withObservationTracking`'s apply closure).
    ///     Runs on the main actor with a strong `owner`; must not retain it.
    ///   - onChange: The post-change check(s), run on the main actor after each observed
    ///     mutation (willSet → yield → next main-actor hop → check); must not retain `owner`.
    /// - Returns: The unstructured loop task, already running.
    static func start<Owner: AnyObject>(
        on owner: Owner,
        tracking: @escaping @MainActor (Owner) -> Void,
        onChange: @escaping @MainActor (Owner) -> Void
    ) -> Task<Void, Never> {
        Task { @MainActor [weak owner] in
            while !Task.isCancelled {
                guard let owner else { return }
                // AsyncStream does not finish automatically when its consumer task is
                // cancelled. Finish the continuation explicitly so repeated discovery
                // sessions do not leave suspended observer tasks behind.
                let (stream, continuation) = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
                withObservationTracking {
                    tracking(owner)
                } onChange: {
                    continuation.yield(())
                }
                await withTaskCancellationHandler {
                    for await _ in stream { break }
                } onCancel: {
                    continuation.finish()
                }
                continuation.finish()
                guard !Task.isCancelled else { return }
                onChange(owner)
            }
        }
    }
}
