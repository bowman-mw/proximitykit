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
/// **weakly** by the loop task and strongly only while arming the reads and while running the
/// check — never across the suspension — so the loop terminates on owner deallocation instead
/// of pinning the owner until a change that can no longer come. Do not replace the owner
/// parameter with weak-self caller closures, which would reintroduce the suspended-task leak
/// documented below; and do not hoist a `guard let owner` above the await, which reintroduces
/// the pin (``MemoryLifecycleTests`` covers both).
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
                // AsyncStream does not finish automatically when its consumer task is
                // cancelled. Finish the continuation explicitly so repeated discovery
                // sessions do not leave suspended observer tasks behind.
                let (stream, continuation) = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
                // The strong reference lives only inside `arm` — never across the await below.
                // A `guard let owner` at the top of the iteration pinned the owner (and every
                // slot, coordinator and transport it owns) for the whole suspension, and the
                // suspension ends only when a tracked property changes — which, once the owner's
                // last other reference is gone, is never. The header's "loop ends on owner
                // dealloc" guarantee was void; this makes it true.
                guard arm(owner, tracking: tracking, continuation: continuation) else { return }
                await withTaskCancellationHandler {
                    for await _ in stream { break }
                } onCancel: {
                    continuation.finish()
                }
                continuation.finish()
                guard !Task.isCancelled, let owner else { return }
                onChange(owner)
            }
        }
    }

    /// Registers one round of tracked reads for `owner`, holding it strongly only for the call.
    /// Returns `false` (and registers nothing) once the owner has been deallocated, which ends the loop.
    private static func arm<Owner: AnyObject>(
        _ owner: Owner?,
        tracking: @escaping @MainActor (Owner) -> Void,
        continuation: AsyncStream<Void>.Continuation
    ) -> Bool {
        guard let owner else { return false }
        withObservationTracking {
            tracking(owner)
        } onChange: {
            continuation.yield(())
        }
        return true
    }
}
