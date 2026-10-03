// ProximityNamespaceGate.swift
// ProximityKit/Support
//
// ProximityKit plan step A0.3 (Docs/Plan-FernletCoach-ProximityKit-2026-10-01.md §4 A0.3; owner
// decision 5 on PR #1): ProximityKit refuses an unsound host namespace at run time, failing closed with
// a named audit event, and a manager acts under one namespace only. A namespace is judged once, when
// the host builds it (`ProximityNamespace.soundness`); this is where ProximityKit acts on that verdict.
// The identity checks it before it provisions and before it wraps a group key, each radio before it
// advertises, and each manager compares the namespace of an identity it is handed with its own.

// MARK: - ProximityNamespaceGate

/// ProximityKit's run-time refusal of an unsound host namespace, and its check that a manager acts
/// under one namespace only.
///
/// **Where an unsound namespace is refused.** At three doors, each before it does anything under the
/// namespace: ``IdentityService/ensureProvisioned()`` first thing (`identity.namespace.unsound`, at
/// `provision`), so no keychain row is read or written; ``IdentityService/encryptGroupKey(_:for:)``
/// first thing (the same event, at `groupKeyWrap`), the one identity operation that needs no
/// provisioned key; and each radio's `start` (`mesh.quic.namespaceUnsound`,
/// `presence.quic.namespaceUnsound`, `recipe.quic.namespaceUnsound`, at `start`), before it mints a name
/// or a certificate or brings a listener up. Everything else ProximityKit does under a namespace sits
/// behind one of them: nothing signs, seals or opens without a provisioned identity, and nothing reaches
/// a peer without a started radio. Each door throws ``ProximityNamespaceError`` carrying every violation,
/// exactly as ``ProximityNamespace/soundness`` records them, and writes nothing else.
///
/// **It reads the stored verdict, nothing else.** No rule runs again here: the namespace judged itself
/// once, when it was built, and the identity and the radios keep that verdict beside the values they
/// read off it.
///
/// **The audit line names the refusal, never a value.** Its context holds `at` (the door),
/// `violations` (how many rules broke) and `first` (the first violation's case name, such as
/// `malformedLabel`): no field path, label, token or name, so a host's log says why without repeating
/// what.
///
/// **One namespace per manager.** The mesh, presence and recipe-share managers compare the namespace of
/// an identity they are handed (their `identity:` seam, which no shipping caller uses) with their own.
/// On a mismatch a manager still constructs, as it does when provisioning fails, but audits
/// `<area>.identity.namespaceMismatch` (at `construction`) and refuses every start of its radio with
/// the same event (at `start`), so nothing is signed for or advertised under two namespaces.
///
/// `nonisolated` against the module's `defaultIsolation(MainActor.self)`: pure reads of `Sendable`
/// values and one synchronous audit line, called from the main-actor identity, radios and managers.
nonisolated enum ProximityNamespaceGate {

    /// Where a check stands, as its audit line's `at` value spells it: frozen tokens, never display copy.
    nonisolated enum Site: String, Sendable {
        /// `IdentityService.ensureProvisioned()`, before any keychain row is read or written.
        case provision
        /// `IdentityService.encryptGroupKey(_:for:)`, before a group key is wrapped.
        case groupKeyWrap
        /// A radio's `start`, or a manager's start of its radio, before anything is advertised.
        case start
        /// A manager's initializer, where it compares its identity's namespace with its own.
        case construction
    }

    /// Refuses an unsound namespace: when `soundness` is unsound, writes `event` and throws every
    /// violation; when it is sound, returns and writes nothing.
    ///
    /// - Parameters:
    ///   - soundness: The verdict the caller keeps for its namespace, ``ProximityNamespace/soundness``.
    ///   - event: The caller's audit event: a frozen token, never display copy.
    ///   - site: The door, written as the line's `at`.
    /// - Throws: ``ProximityNamespaceError`` carrying every violation, in the order the rules ran.
    static func refuseUnsound(
        _ soundness: ProximityNamespace.Soundness, event: String, at site: Site
    ) throws(ProximityNamespaceError) {
        guard case .unsound(let violations) = soundness else { return }
        ProximityAudit.log(event, context: [
            "at": site.rawValue,
            "violations": String(violations.count),
            "first": violations.first.map(Self.caseName(of:)) ?? "none"
        ])
        throw ProximityNamespaceError(violations: violations)
    }

    /// Whether a manager's `identity` is of the manager's `namespace`, the whole namespace compared:
    /// an identity of another family signs under other labels, and one of another installation keeps
    /// its rows under another keychain service.
    ///
    /// - Parameters:
    ///   - identity: The identity the manager was handed.
    ///   - namespace: The manager's namespace, read from its host.
    ///   - event: The manager's mismatch event, written at `construction` when the two differ.
    /// - Returns: `true` when the identity was built from `namespace`; otherwise `false`, which the
    ///   manager keeps and ``mayStart(identityIsOfNamespace:event:)`` reads at every start.
    static func checkIdentity(_ identity: IdentityService, isOf namespace: ProximityNamespace, event: String) -> Bool {
        guard identity.namespace == namespace else {
            ProximityAudit.log(event, context: ["at": Site.construction.rawValue])
            return false
        }
        return true
    }

    /// Whether a manager may start its radio: only when its identity is of its namespace.
    ///
    /// - Parameters:
    ///   - identityIsOfNamespace: What ``checkIdentity(_:isOf:event:)`` answered at construction.
    ///   - event: The manager's mismatch event, written at `start` on every refused start.
    /// - Returns: `true` to go ahead; `false`, after the audit line, to advertise nothing.
    static func mayStart(identityIsOfNamespace: Bool, event: String) -> Bool {
        guard identityIsOfNamespace else {
            ProximityAudit.log(event, context: ["at": Site.start.rawValue])
            return false
        }
        return true
    }

    /// A violation's case name, without the fields it names: what an audit line may carry. Exhaustive,
    /// so a rule added to ``ProximityNamespace/Violation`` is named here before it can be audited.
    ///
    /// - Parameter violation: A broken soundness rule.
    /// - Returns: Its case name, a frozen token.
    static func caseName(of violation: ProximityNamespace.Violation) -> String {
        switch violation {
        case .malformedLabel: return "malformedLabel"
        case .duplicateLabel: return "duplicateLabel"
        case .labelIsPrefix: return "labelIsPrefix"
        case .malformedServiceType: return "malformedServiceType"
        case .malformedALPN: return "malformedALPN"
        case .duplicateRadioValue: return "duplicateRadioValue"
        case .malformedHeartbeat: return "malformedHeartbeat"
        case .malformedURLScheme: return "malformedURLScheme"
        case .malformedKeychainName: return "malformedKeychainName"
        case .duplicateKeychainName: return "duplicateKeychainName"
        case .malformedPathComponent: return "malformedPathComponent"
        case .duplicateFileName: return "duplicateFileName"
        case .emptyLogSubsystem: return "emptyLogSubsystem"
        case .malformedToken: return "malformedToken"
        case .duplicateToken: return "duplicateToken"
        case .unknownToken: return "unknownToken"
        case .malformedSummaryTitle: return "malformedSummaryTitle"
        case .malformedInstanceNamePrefix: return "malformedInstanceNamePrefix"
        case .malformedCommonName: return "malformedCommonName"
        case .malformedPeerNames: return "malformedPeerNames"
        }
    }
}
