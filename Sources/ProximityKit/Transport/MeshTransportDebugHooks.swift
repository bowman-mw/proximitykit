import Foundation

// MARK: - MeshTransportConsoleLog

/// A DEBUG-only stdout mirror of the QUIC radio's diagnostics, so a headless
/// `xcrun simctl launch --console-pty` run can read the same lines Console.app would show.
///
/// Same shape and same reason as the feasibility probe's `FERNLET_PROBE_CONSOLE_LOG`: the variable
/// is read once per process, absent means off, and off means the transport behaves exactly as it
/// does with this file deleted. It never changes a decision — it only echoes one that was already
/// made and already logged through `Logger`.
///
/// **Release cannot switch it on.** In a Release build ``echo(_:)`` is an empty function: there is
/// no environment read and no `print` compiled into it at all, so no launch environment a shipped
/// app could ever see can produce a line.
///
/// ``prefix`` and ``enabledKey`` are frozen automation tokens — grep targets in a transcript, never
/// display strings, never localized.
nonisolated enum MeshTransportConsoleLog {

    /// Frozen console tag, so a `--console-pty` transcript can be grepped down to the radio's lines.
    static let prefix = "[mesh-quic]"

    #if DEBUG
    /// Launch environment key enabling the mirror, e.g. `FERNLET_MESH_CONSOLE_LOG=1`.
    static let enabledKey = "FERNLET_MESH_CONSOLE_LOG"

    /// Whether this process mirrors. Read once, at first use, and never written.
    static let isEnabled = ProcessInfo.processInfo.environment[enabledKey] == "1"

    /// Mirrors one diagnostic line to stdout, and only when the mirror was asked for.
    static func echo(_ message: String) {
        guard isEnabled else { return }
        print("\(prefix) \(message)")
    }
    #else
    /// Release: the mirror does not exist.
    static let isEnabled = false

    /// Release no-op — nothing is read, nothing is printed.
    static func echo(_ message: String) {}
    #endif
}

// MARK: - MeshIntroductionChaosBehaviour

/// One misbehaviour a DEBUG build can be asked to perform during the signed channel introduction.
///
/// These exist to make the transport's *refusals* observable over a real radio: a rejection matrix
/// that only ever sees well-behaved peers proves nothing about selectivity. Each case names a lie a
/// hostile peer could tell, told deliberately by this side so the other side's named rejection can
/// be read out of a log.
///
/// The raw values are frozen automation tokens parsed from a DEBUG-only environment variable. They
/// are never persisted, never put on a wire, and never localized.
nonisolated enum MeshIntroductionChaosBehaviour: String, CaseIterable, Sendable {

    /// Reuse one nonce for every introduction this process sends, instead of drawing a fresh one.
    /// The peer's ``MeshIntroductionNonceCache`` refuses the second one.
    case frozenNonce

    /// Flip a bit of this side's introduction signature before it goes on the wire, so the peer's
    /// verification over the transcript fails.
    case tamperSignature
}

// MARK: - MeshIntroductionChaos

/// The DEBUG-only chaos seam the signed channel introduction consults, and the one place the
/// misbehaviours are switched on.
///
/// **Default-off, read once, never persisted.** With `FERNLET_MESH_CHAOS` absent every member here
/// returns exactly what the honest path returns: ``introductionNonce()`` is
/// ``MeshChannelIntroductionFormat/randomNonce()``, ``signature(_:)`` is the identity function, and
/// ``additionalBarredKeys`` is empty. There is no setting, no UI and no `UserDefaults` key, so this
/// owes no row on the persisted-surface wipe ledger.
///
/// **Release is not merely default-off, it is incapable.** The whole environment-reading half is
/// compiled out; the Release members are constants a compiler can fold.
///
/// **Nothing here can admit a peer that would otherwise be refused.** Two of the three seams damage
/// *this* side's own outbound introduction, which can only cause the peer to refuse us; the third,
/// ``additionalBarredKeys``, only ever adds keys to the roster's `barred` set, and barred wins over
/// member (``MeshIntroductionRoster``) — so it can only turn an accept into a refusal. The
/// direction is one-way by construction, which is why this is a diagnostic hook and not an escape
/// hatch.
///
/// **Scope narrowed at P3 item 7.** `barred` is no longer empty in production: the derived roster
/// fills it from signed removal and departure records, so ``additionalBarredKeys`` is now only what
/// makes the branch reachable where no quorum for a real removal exists — a two-node lane.
nonisolated enum MeshIntroductionChaos {

    #if DEBUG
    /// Launch environment key naming the misbehaviours, comma-separated, e.g.
    /// `FERNLET_MESH_CHAOS=frozenNonce,tamperSignature`. Unrecognized tokens are ignored.
    static let behaviourKey = "FERNLET_MESH_CHAOS"

    /// Launch environment key carrying base64 Ed25519 signing keys to bar, comma-separated.
    static let barredKeysKey = "FERNLET_MESH_CHAOS_BARRED"

    /// The misbehaviours this process performs. Read once, at first use.
    static let behaviours = parseBehaviours(ProcessInfo.processInfo.environment[behaviourKey])

    /// Extra signing keys to bar, **on top of** the ones the derived roster already bars.
    ///
    /// P3 item 7 changed what this is for. The shipping authority now fills `barred` itself, from
    /// verified departure and removal records that carry the member's signing key — so the
    /// ``MeshRosterVerdict/barred`` branch is the mesh's own answer, walled at tier 1 in
    /// `MeshIntroductionAuthorityTests`. What remains is the two-node lane: a real removal needs
    /// ⌊|roster|/2⌋ + 1 votes, so two Simulators cannot produce one, and Lane C's matrix row 3 uses
    /// this to reach the branch until item 9's 3-node lane can vote a member out for real.
    ///
    /// It still only ever ADDS a refusal — barred wins over member — so it cannot open a door the
    /// records closed.
    static let additionalBarredKeys = parseKeys(ProcessInfo.processInfo.environment[barredKeysKey])

    /// The one nonce a ``MeshIntroductionChaosBehaviour/frozenNonce`` process reuses. Still drawn
    /// from the platform CSPRNG, so two chaos processes do not collide with each other — a peer
    /// whose nonce equalled ours would be refused for the *reflection* reason rather than the cache
    /// reason, and those are two different observations.
    private static let reusedNonce = MeshChannelIntroductionFormat.randomNonce()

    /// The nonce for one outbound hello: fresh, unless this process was asked to reuse one.
    static func introductionNonce() -> Data {
        guard behaviours.contains(.frozenNonce) else {
            return MeshChannelIntroductionFormat.randomNonce()
        }
        return reusedNonce
    }

    /// This side's introduction signature, with one bit flipped when tampering was asked for.
    static func signature(_ signature: Data) -> Data {
        guard behaviours.contains(.tamperSignature) else { return signature }
        var bytes = Array(signature)
        guard let first = bytes.first else { return signature }
        bytes[0] = first ^ 0x01
        return Data(bytes)
    }

    /// Frozen diagnostic English naming what this process was asked to do, for the console mirror.
    static var summary: String {
        let names = MeshIntroductionChaosBehaviour.allCases
            .filter { behaviours.contains($0) }
            .map(\.rawValue)
        guard !names.isEmpty || !additionalBarredKeys.isEmpty else { return "off" }
        return "behaviours=[\(names.joined(separator: ","))] barredKeys=\(additionalBarredKeys.count)"
    }

    /// Parses the comma-separated behaviour list, bounded by the number of behaviours that exist.
    private static func parseBehaviours(_ raw: String?) -> Set<MeshIntroductionChaosBehaviour> {
        guard let raw, !raw.isEmpty else { return [] }
        var parsed: Set<MeshIntroductionChaosBehaviour> = []
        for token in raw.split(separator: ",").prefix(MeshIntroductionChaosBehaviour.allCases.count) {
            guard let behaviour = MeshIntroductionChaosBehaviour(rawValue: String(token)) else { continue }
            parsed.insert(behaviour)
        }
        return parsed
    }

    /// Parses comma-separated base64 signing keys, dropping anything that is not exactly one
    /// Ed25519 public key, and bounded by the roster's own barred cap.
    private static func parseKeys(_ raw: String?) -> [Data] {
        guard let raw, !raw.isEmpty else { return [] }
        var keys: [Data] = []
        for token in raw.split(separator: ",").prefix(MeshIntroductionRoster.maxBarred) {
            guard let key = Data(base64Encoded: String(token)),
                  key.count == MeshChannelIntroductionFormat.signingKeyByteCount else { continue }
            keys.append(key)
        }
        return keys
    }
    #else
    /// Release: no key is ever barred by this seam.
    static let additionalBarredKeys: [Data] = []

    /// Release: always a fresh nonce.
    static func introductionNonce() -> Data { MeshChannelIntroductionFormat.randomNonce() }

    /// Release: the signature goes out exactly as it was signed.
    static func signature(_ signature: Data) -> Data { signature }

    /// Release: there is nothing to report.
    static var summary: String { "off" }
    #endif
}
