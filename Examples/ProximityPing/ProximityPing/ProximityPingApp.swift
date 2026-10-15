// ProximityPingApp.swift
// ProximityPing
//
// The composition root: install ProximityKit's audit sink before any ProximityKit object exists,
// build the model, bring the radio up once the window shows.

import ProximityKit
import SwiftUI

/// The example app: one window showing the diagnostics screen.
@main
struct ProximityPingApp: App {

    /// The app's one model, built once.
    @State private var model: PingModel

    /// Installs the audit sink, then builds the model over it.
    init() {
        let sink = PingAuditSink()
        ProximityAudit.install(sink)
        _model = State(initialValue: PingModel(displayWord: Self.displayWord, auditSink: sink))
    }

    var body: some Scene {
        WindowGroup {
            DiagnosticsView(model: model)
                .task { model.start() }
        }
    }

    /// The generic word this device's advertised name starts with.
    private static var displayWord: String {
        #if os(macOS)
        "Mac"
        #elseif targetEnvironment(simulator)
        "Simulator"
        #else
        "iPhone"
        #endif
    }
}
