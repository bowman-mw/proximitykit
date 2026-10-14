// PackageAuditCapture.swift
// ProximityKitTests
//
// ProximityKit plan step A1.1: how ProximityKit's package tests read its audit lines. ProximityKit hands
// every line to the one sink its host installs and drops the line while none is installed, and this bundle
// is unhosted, so no app installs one. PackageTestEnvironment installs `PackageAuditSink` once, on first
// touch, and a cell reads the lines its own code caused through a `PackageAuditCapture`, which registers
// with that sink as it is built and keeps only the lines its scope admits.

import Foundation
import ProximityKit
import Synchronization

/// One ProximityKit audit line, as the bundle's sink received it.
struct PackageAuditLine: Equatable, Sendable {
    /// The event name, unchanged.
    let event: String
    /// The context, every key and value unchanged.
    let context: [String: String]
}

/// ProximityKit's audit sink in the package test bundle: it hands each line, in line and before
/// ProximityKit's call returns, to every capture registered at that moment.
///
/// **Installed once.** `PackageTestEnvironment.audit` builds the one instance and installs it with
/// `ProximityAudit.install(_:)` on its first read, and every ``PackageAuditCapture`` registers with that
/// instance as it is built, so no capture exists before the sink is installed and a read that finds no
/// line is never vacuous.
///
/// **A registry, not a slot.** Suites run in parallel in one process, so a single handler slot would let
/// one suite's capture replace another's, the lesson Fernlet's `FernletAuditLog` capture registry
/// records. Each capture registers its handler under a token of its own and removes only that one.
///
/// **Concurrency.** One immutable `let` owns the handlers behind a `Mutex`; a line is delivered after the
/// lock is released, so a handler may log again, register or unregister without deadlocking; every
/// handler is `@Sendable`. No stored `static var`, so one instance serves every suite in the process.
final class PackageAuditSink: ProximityAuditSink {

    /// What a capture registers: called once per line, on the emitting executor, before the emitting
    /// call returns.
    typealias Handler = @Sendable (PackageAuditLine) -> Void

    /// The registered handlers, by token, owned with their lock.
    private let handlers = Mutex<[UUID: Handler]>([:])

    /// Hands the line to every handler registered when it arrived, in line.
    ///
    /// - Parameters:
    ///   - event: The event name, forwarded unchanged.
    ///   - context: The context, forwarded unchanged.
    func record(_ event: String, context: [String: String]) {
        let line = PackageAuditLine(event: event, context: context)
        let current = handlers.withLock { Array($0.values) }
        // R2: bounded by the handlers registered when the line arrived.
        for handler in current {
            handler(line)
        }
    }

    /// Registers `handler` under `token` for every line from now on, replacing any handler that token
    /// already held.
    ///
    /// - Parameters:
    ///   - token: The registration's token, fresh for each capture.
    ///   - handler: Called with each line.
    func register(_ token: UUID, handler: @escaping Handler) {
        handlers.withLock { $0[token] = handler }
    }

    /// Removes the handler registered under `token`.
    ///
    /// - Parameter token: The registration's token.
    /// - Returns: Whether a handler was registered under it.
    @discardableResult
    func unregister(_ token: UUID) -> Bool {
        handlers.withLock { $0.removeValue(forKey: token) != nil }
    }
}

/// A scoped read of ProximityKit's audit lines: the lines the bundle's sink delivered while the capture
/// was registered, kept only when its scope admits them.
///
/// **Scoped two ways.** Suites run in parallel and the sink hands a capture every line the process logs,
/// so a capture keeps only what its own cell could have caused: a line whose context holds every key of
/// its `context` scope with that key's value (a rig's own label), and, for a capture built `markedOnly`,
/// a line logged inside its own ``marking(_:)``, which binds a task-local mark that only this capture
/// answers to. The mark scopes a line whose context names no rig, such as a manager's provisioning
/// failure; a line logged on another task, or from a detached one, carries no mark.
///
/// **Never vacuous.** Its initializer registers with `PackageTestEnvironment.audit`, whose first read
/// installs the sink, so the sink is ProximityKit's before the capture exists: a cell that reads no line
/// read a sink that would have delivered one.
///
/// **Ends.** ``stop()`` unregisters it, and its deinit does too; a line delivered after that is not kept.
/// The name is the package's own: Fernlet's tests read their lines through `FernletAuditLog`, which this
/// bundle cannot import, under other names.
final class PackageAuditCapture: Sendable {

    /// The lines a capture kept, owned with their lock: shared by the capture and the handler it
    /// registered, so the handler holds no reference to the capture and the capture's deinit runs.
    private final class Kept: Sendable {
        /// The kept lines, in the order the sink delivered them.
        let lines = Mutex<[PackageAuditLine]>([])
    }

    /// The task-local mark ``marking(_:)`` binds: the marking capture's token, or nil outside every
    /// marking. Held in a `static let`, not through the property wrapper's stored `static var`.
    private static let mark = TaskLocal<UUID?>(wrappedValue: nil)

    /// This capture's token: its registration's, and the mark its ``marking(_:)`` binds.
    private let token: UUID

    /// The lines it kept.
    private let kept: Kept

    /// The bundle's sink, which it registered with.
    private let sink: PackageAuditSink

    /// Starts capturing: from the moment it returns, every line the bundle's sink receives is kept when
    /// its context holds every key of `scope` with that key's value and, when `markedOnly`, it was logged
    /// inside this capture's ``marking(_:)``.
    ///
    /// - Parameters:
    ///   - scope: The context pairs a kept line must hold; empty keeps a line whatever its context.
    ///   - markedOnly: Whether to keep only the lines logged inside ``marking(_:)``.
    init(context scope: [String: String] = [:], markedOnly: Bool = false) {
        let token = UUID()
        let kept = Kept()
        let mark = Self.mark
        self.token = token
        self.kept = kept
        sink = PackageTestEnvironment.audit
        sink.register(token) { line in
            guard scope.allSatisfy({ line.context[$0.key] == $0.value }) else { return }
            guard !markedOnly || mark.get() == token else { return }
            kept.lines.withLock { $0.append(line) }
        }
    }

    /// Unregisters the capture, when ``stop()`` has not.
    deinit {
        sink.unregister(token)
    }

    /// Every line it kept, in the order the sink delivered them.
    var lines: [PackageAuditLine] {
        kept.lines.withLock { $0 }
    }

    /// The kept lines named `event`, in order.
    ///
    /// - Parameter event: The event name.
    /// - Returns: The kept lines with that name.
    func lines(named event: String) -> [PackageAuditLine] {
        lines.filter { $0.event == event }
    }

    /// Runs `body` with this capture's mark bound, so a capture built `markedOnly` keeps the lines `body`
    /// logs on this task and on any task it creates that inherits task-locals.
    ///
    /// - Parameter body: The emitting code, run once, synchronously.
    /// - Returns: What `body` returns.
    /// - Throws: What `body` throws.
    func marking<Result>(_ body: () throws -> Result) rethrows -> Result {
        try Self.mark.withValue(token, operation: body)
    }

    /// Unregisters the capture: no line delivered after this returns is kept.
    ///
    /// - Returns: Whether it was still registered.
    @discardableResult
    func stop() -> Bool {
        sink.unregister(token)
    }
}
