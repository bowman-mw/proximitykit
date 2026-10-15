// ProximityAudit.swift
// ProximityKit/Support
//
// ProximityKit plan step A0.2 (Docs/Plan-FernletCoach-ProximityKit-2026-10-01.md §4 A0.2, "Injected
// by the host"): every audit line this module writes goes to a sink the HOST installs, instead of
// naming a host's own audit log. Every call site (427 at this step) spells
// `ProximityAudit.log(_:context:)` with the arguments it always had. Fernlet installs
// `FernletAuditBridge` (FernletConnections) at launch, which hands each line to `FernletAuditLog`
// verbatim and synchronously, so the unified-log output and every audit-capture test see exactly the
// lines they saw before.

import Synchronization

/// Where ProximityKit's audit lines go: one synchronous call per event, from any executor.
///
/// The host implements it and installs one value at launch with ``ProximityAudit/install(_:)``.
/// ProximityKit calls ``record(_:context:)`` from main-actor managers and from its `nonisolated`
/// stores alike (the routed and session stores, the seal-key helpers), so the requirement is
/// `nonisolated`, synchronous and non-throwing, and the protocol refines `Sendable`. Declared
/// `nonisolated` against the module's `defaultIsolation(MainActor.self)`, which would otherwise make
/// the requirement main-actor-isolated and unusable from those stores; a conforming type in a
/// main-actor-default module is declared `nonisolated` for the same reason.
public nonisolated protocol ProximityAuditSink: Sendable {

    /// Records one audit event, before the emitting call site returns.
    ///
    /// Called on the caller's executor with no hop, so an implementation that forwards to a log with
    /// observers (Fernlet's capture tests read their results right after the emitting call, and one
    /// of them changes the outcome of the operation from inside its handler) must forward in line:
    /// no `Task`, queue, actor hop or buffer. It must not wait on the main actor either, because a
    /// `nonisolated` caller may be on it.
    ///
    /// - Parameters:
    ///   - event: A short, stable, identifier-shaped name such as `mesh.routedDrain.rejected`: a
    ///     token, never display copy. Forward it unchanged; tests pin the names byte for byte.
    ///   - context: Key/value detail: counts, reasons, salted per-session peer labels, digest
    ///     prefixes, and on a few lines a peer's name or fingerprint, so a sink treats it as private
    ///     (Fernlet's log redacts it outside a debugger). Forward every key and value unchanged
    ///     (tests scope their counts by `held` and `peer`).
    func record(_ event: String, context: [String: String])
}

/// ProximityKit's audit entry point, and the one process-wide slot that holds the host's sink.
///
/// **Installed once, by the host, at launch.** ``install(_:)`` is called by the host's composition
/// root before anything constructs a ProximityKit object; Fernlet calls it first thing in
/// `FernletApp.init`, which also runs before any unit test, because the test bundle is hosted in the
/// app. A later call replaces the sink for every line logged after it. With **no sink installed, an
/// event is dropped**: ProximityKit keeps no log of its own and no default, so a host that wants
/// audit installs a sink. A host whose tests assert that an event was NOT logged should also prove
/// its sink is installed (Fernlet's `ProximityAuditBridgeTests`), or every such negative assertion
/// passes vacuously.
///
/// **Why a slot, when the namespace is handed down instead.** ``ProximityNamespace`` reaches its
/// readers through seams they already have. Audit lines are written from nearly four hundred call
/// sites, including `nonisolated` value-type stores and static helpers that hold no host, and the
/// host's tests build ProximityKit objects directly and still have to see every line. A sink each
/// constructor took would have to reach all of those sites, and the objects the tests build would
/// log nowhere.
///
/// **Delivery is synchronous, on the caller's executor.** ``log(_:context:)`` reads the sink under
/// the lock, releases the lock, and calls ``ProximityAuditSink/record(_:context:)`` before it
/// returns. A sink may therefore re-enter the log or block without deadlocking this slot.
///
/// **Concurrency (Power of 10 R6/R9).** The slot is a `nonisolated static let` that OWNS its lock
/// (`Mutex`), the shape `FernletAuditLog`'s capture registry has: no stored `static var`, no
/// `nonisolated(unsafe)`. The sink is `Sendable`, so the checked `withLock` is enough; nothing else
/// reads or writes the slot, and no reference to it escapes the lock. Every member is `nonisolated`
/// and callable from any executor.
public nonisolated enum ProximityAudit {

    /// The installed sink, or nil before the host installs one.
    ///
    /// The one process-global in this file: an immutable `let` owning its lock (R6/R9), written only
    /// by ``install(_:)`` and read only by ``log(_:context:)``, each inside `withLock`.
    nonisolated private static let slot = Mutex<(any ProximityAuditSink)?>(nil)

    /// Installs the sink every later ProximityKit audit line goes to.
    ///
    /// Call it once, at launch, before anything constructs a ProximityKit object: a line logged
    /// before the first install is dropped. A later call replaces the sink.
    ///
    /// - Parameter sink: The host's sink. It is called synchronously, on the emitting executor.
    nonisolated public static func install(_ sink: any ProximityAuditSink) {
        slot.withLock { $0 = sink }
    }

    /// Hands one audit event to the installed sink before returning, or drops it when there is none.
    ///
    /// ProximityKit's only audit entry point. The `context` default keeps the call sites that log a
    /// bare event unchanged, since a protocol requirement cannot carry a default argument.
    ///
    /// - Parameters:
    ///   - event: A short, stable, identifier-shaped event name: a token, never display copy.
    ///   - context: Key/value detail, private to the sink (it may name a peer). Empty by default.
    nonisolated static func log(_ event: String, context: [String: String] = [:]) {
        guard let sink = slot.withLock({ $0 }) else { return }
        sink.record(event, context: context)
    }
}
