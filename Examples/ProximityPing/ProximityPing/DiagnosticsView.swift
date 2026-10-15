// DiagnosticsView.swift
// ProximityPing
//
// The example's one screen: the namespace, this device, the devices nearby with a Ping button each,
// the round trips, and the log.

import ProximityKit
import SwiftUI

/// Everything the example knows, on one scrolling screen.
struct DiagnosticsView: View {

    /// The model the screen reads and drives.
    let model: PingModel

    var body: some View {
        NavigationStack {
            List {
                namespaceSection
                deviceSection
                nearbySection
                pingSection
                logSection
            }
            .navigationTitle("ProximityPing")
            .toolbar {
                ToolbarItemGroup {
                    Button("Start") { model.start() }
                        .disabled(model.session.isListening)
                    Button("Stop") { model.stop() }
                        .disabled(!model.session.isListening)
                    Button("Refresh") { model.session.refreshDiscovery() }
                }
            }
        }
    }

    /// The namespace's radio and verdict.
    private var namespaceSection: some View {
        let namespace = model.session.namespace
        return Section("Namespace") {
            row("Service type", namespace.family.radios.pair.serviceType)
            row("ALPN", namespace.family.radios.pair.alpn)
            row("Soundness", namespace.soundness == .sound ? "sound" : "\(namespace.soundness)")
            row("Labels", "\(namespace.labelRows.count)")
            row("Log subsystem", namespace.installation.logSubsystem)
        }
    }

    /// This device: its advertised name, its fingerprint, the radio and the send status.
    private var deviceSection: some View {
        Section("This device") {
            row("Name", model.host.proximityDisplayName)
            row("Fingerprint", model.localFingerprint.isEmpty ? "not provisioned" : model.localFingerprint)
            row("Radio", model.session.isListening ? "listening" : "stopped")
            row("Status", "\(model.session.status)")
            row("Last error", model.lastError ?? "none")
        }
    }

    /// The devices the radio found, each with its verified fingerprint once paired.
    private var nearbySection: some View {
        Section("Nearby (\(model.session.nearbyPeers.count))") {
            ForEach(model.session.nearbyPeers) { peer in
                HStack {
                    VStack(alignment: .leading) {
                        Text(peer.displayName)
                        Text(peer.fingerprint ?? "not verified")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    if model.session.engagedPeerID == peer.id {
                        Text("engaged").font(.caption)
                    }
                    Button("Ping") { model.ping(peer) }
                        .buttonStyle(.bordered)
                }
            }
        }
    }

    /// The round trips and what the last pairing reported.
    private var pingSection: some View {
        Section("Pings") {
            row("Sent / pongs / answered", "\(model.pingsSent) / \(model.pongsReceived) / \(model.pingsAnswered)")
            row("Round trip (last, best, mean)", roundTrips)
            row("Payload bytes out / in", "\(model.payloadBytesOut) / \(model.payloadBytesIn)")
            row("Pairing state", model.pairingState)
            row("Peer capabilities", capabilities)
            row("Last send", model.session.lastSendOutcome.map { "\($0.subject): \($0.result)" } ?? "none")
        }
    }

    /// The last, best and mean round trip, a dash for each not measured yet.
    private var roundTrips: String {
        [model.lastRoundTripMs, model.bestRoundTripMs, model.meanRoundTripMs]
            .map { $0.map { String(format: "%.1f ms", $0) } ?? "-" }
            .joined(separator: ", ")
    }

    /// The capabilities the last payload's peer advertised, once a payload has arrived.
    private var capabilities: String {
        guard let advertised = model.peerCapabilities else { return "no payload yet" }
        return advertised.isEmpty ? "none advertised" : advertised.joined(separator: ", ")
    }

    /// The newest log lines first.
    private var logSection: some View {
        Section("Log") {
            ForEach(model.log.reversed()) { line in
                VStack(alignment: .leading) {
                    Text("\(line.at.formatted(date: .omitted, time: .standard)) \(line.source)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    Text(line.text)
                        .font(.caption.monospaced())
                }
            }
        }
    }

    /// One label and its value.
    private func row(_ label: String, _ value: String) -> some View {
        LabeledContent(label) {
            Text(value)
                .font(.callout.monospaced())
                .textSelection(.enabled)
        }
    }
}
