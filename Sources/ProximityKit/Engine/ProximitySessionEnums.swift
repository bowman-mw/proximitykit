// ProximitySessionEnums.swift
// ProximityKit/Engine
//
// Two of the three enums a `ProximityCoordinator` session is described by, which name no app: the
// role this device played (`ProximityRole`) and how it measured its peer's distance
// (`ProximityRangingMode`). The coordinator keeps `typealias Role = ProximityRole` and
// `typealias RangingMode = ProximityRangingMode`, so every `ProximityCoordinator.Role` and bare
// `Role` reference reads as it did. Their raw values are tokens and frozen: the ranging mode's rides
// every identity introduction and acknowledgement body, and a host that persists a session keeps
// its own copies with the same raw values (Fernlet's session log: `ConnectionSessionLog.Role` and
// `ConnectionSessionLog.RangingMode`, which `ProximityVocabularyGoldenTests` holds to these
// spellings). The third enum, the session's mode, is Fernlet's `ProximityMode` (FernletDomainModel).
//
// `nonisolated` + `Sendable` against ProximityKit's `.defaultIsolation(MainActor.self)`, so the
// values and their synthesized `Codable` are usable off the main actor.

import Foundation

/// Which role this device played in a session (advertiser or browser).
///
/// The two spellings are MultipeerConnectivity's, from when it was the radio, and they are frozen:
/// a host persists the role by rawValue. Under QUIC the listening half is still the `advertiser`.
///
/// The coordinator keeps a `Role` typealias to it and reports it to its inspector
/// (``ProximityInspectorRecording/beginSession(role:mode:localFingerprint:)``).
public nonisolated enum ProximityRole: String, Codable, Equatable, Sendable {
    case advertiser
    case browser
}

/// How peer distance was measured during a session: UWB, RSSI fallback, or not at all.
///
/// Reported to the session's inspector (``ProximityInspectorRecording/updateRangingMode(_:)``), and
/// its raw value rides every identity introduction and acknowledgement body; the UWB dwell-commit
/// is the join ritual several trust flows key off. The coordinator keeps a `RangingMode` typealias
/// to it.
public nonisolated enum ProximityRangingMode: String, Codable, Equatable, Sendable {
    case uwb
    case rssi
    case none
}
