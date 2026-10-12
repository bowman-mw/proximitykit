// ProximitySessionEnums.swift
// ProximityKit/Engine
//
// The three enums a `ProximityCoordinator` session is described by, none of which names an app: the
// role this device played (`ProximityRole`), how it measured its peer's distance
// (`ProximityRangingMode`) and the trust posture the session runs under (`ProximitySessionMode`). The
// coordinator keeps `typealias Role = ProximityRole`, `typealias RangingMode = ProximityRangingMode`
// and `typealias Mode = ProximitySessionMode`, so every `ProximityCoordinator.Role` and bare `Role`
// reference reads as it did. Their raw values are tokens and frozen: the ranging mode's rides every
// identity introduction and acknowledgement body, the session mode's is written into the session's
// pairing-started audit, and a host that persists a session keeps its own copies with the same raw
// values (Fernlet's session log: `ConnectionSessionLog.Role` and `ConnectionSessionLog.RangingMode`;
// its trust vault and session log: FernletDomainModel's `ProximityMode`;
// `ProximityVocabularyGoldenTests` holds each to these spellings).
//
// `nonisolated` + `Sendable` against ProximityKit's `.defaultIsolation(MainActor.self)`, so the
// values (and the role's and ranging mode's synthesized `Codable`) are usable off the main actor.

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

/// The trust posture a pair or mesh session runs under: `trainer` or `friend`.
///
/// The coordinator keeps a `Mode` typealias to it, takes it in `begin(role:mode:)` and reports it to
/// its inspector (``ProximityInspectorRecording/beginSession(role:mode:localFingerprint:)``). It
/// selects the session's gates: a friend session, the mesh's and the pair session's, introduces
/// itself on connect, waits at the proximity commit gate and reconnects after transport loss; a
/// trainer session waits for its user to confirm a peer its host's trust store does not remember and
/// bounds every inbound frame by `maxTrainerModeInboundBytes` before decoding it. Plan step C5
/// generalizes it into the session policy a connection profile brings, the coach's being the first
/// other than friend.
///
/// The raw values are frozen: the coordinator writes `rawValue` into the session's pairing-started
/// ``ProximitySessionAudit``, whose message a host may persist, and a host that persists the mode
/// keeps its own copy with the same raw values (Fernlet's is FernletDomainModel's `ProximityMode`,
/// which it converts to case for case).
public nonisolated enum ProximitySessionMode: String, Equatable, Sendable {
    /// A one-to-one trainer session's trust posture: the user's confirmation of a peer the host's
    /// trust store does not remember, and the trainer inbound bound. Its raw value, `trainer`, is
    /// frozen; plan step C5 generalizes the posture into a session policy.
    case trainer
    /// The trust posture of a friend session, the mesh's and the pair session's: the identity
    /// introduction on connect, the proximity commit gate and reconnection after transport loss. Its
    /// raw value, `friend`, is frozen; plan step C5 generalizes the posture into a session policy.
    case friend
}
