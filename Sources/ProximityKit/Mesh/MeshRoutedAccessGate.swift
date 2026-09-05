// MeshRoutedAccessGate.swift
// ProximityKit/Mesh
//
// Network migration P5 item 10 (plan §11 "locked device", §19.5, invariant 7): item 10's whole pure
// vocabulary — the three app-level facts that decide whether PLAINTEXT may exist on this device
// right now, which legs of them moved, what the re-entry did about it, and the two frozen token
// enums the routed store's suppression lines are named with.
//
// **Not a readability gate.** After the first post-boot unlock a locked device's routed store is
// `loaded` (the seal key is `AfterFirstUnlockThisDeviceOnly` and the files are
// `…UntilFirstUserAuthentication`), so ciphertext-only custody, custody receipts and photo/text
// recipient receipts already work with the screen off — by design, not by accident. The store
// answers readability itself, in five states; this value answers a different question.
//
// **No decrypt seam, no store, no clock, no UIKit.** Pure `Sendable` values, unit-testable without a
// manager, which is why the manager's own additions stay small. All tokens are frozen English and
// none of them is display text.

import Foundation

// MARK: - MeshRoutedCapability

/// The three questions the routed path asks about a lock, as one closed vocabulary.
///
/// Three cases rather than one Bool so each question has a **named, tested answer** instead of being
/// answered by silence, and so a future non-decrypt canonical mutation inherits nothing by accident.
/// Frozen English `rawValue`s: they are logged and matched on, never shown to anyone.
public nonisolated enum MeshRoutedCapability: String, CaseIterable, Equatable, Sendable {

    /// Taking durable ciphertext custody: admitting a manifest, staging a chunk, minting a custody
    /// receipt, claiming a handed-off leg, writing the index. **Never gated by the access gate** —
    /// its authority is the store's own five-state load (D-10.2), which is a type-level gate: three
    /// of the five states vend no `MeshRoutedStore.LoadToken`, so a caller structurally cannot write.
    case sealCustody

    /// Unwrapping a routed item's content key and reading its plaintext.
    case decryptContent

    /// Writing routed plaintext into a canonical store (`ProximityHeartLedger`, the friend-photo
    /// wall, `SessionMessageStore`). Answered at the **same strength** as ``decryptContent``,
    /// deliberately: a plaintext write is not a weaker act than a plaintext read.
    case mutateCanonicalStore
}

// MARK: - MeshRoutedAccessGate

/// The three app-level facts that decide whether PLAINTEXT may exist on this device right now.
///
/// Pushed in by the app (`MeshNetworkManager.applyRoutedAccessGate(_:now:)`), never pulled: a pull
/// has no edge, and item 10's re-entry is defined by an edge (D-10.1). The push is also P7's
/// `apply(_:)` shape, so `ProximityRunPolicy` later becomes its single writer without the seam
/// moving.
///
/// Which lock is which (D-10.3):
///
/// - ``protectedDataAvailable`` is **iOS data protection** — the OS device lock. It gates plaintext
///   and, at the store, readability.
/// - ``appIsForeground`` is the app scene. It is the *real* foreground enforcement; the mesh's own
///   `MeshSessionState.activeForeground` never leaves that value today, so it is not one.
/// - ``duressActive`` is the only clause of **Fernlet's own app lock** that reaches the mesh: no
///   `FernletLockScope` covers Friends and ProximityKit cannot import `FernletLock`, so claiming the
///   app lock gates the mesh would be false. Never commit a friend's content into a canonical store
///   during a duress session.
///
/// This is a **policy** gate, not a capability one: the identity key-agreement key is
/// `AfterFirstUnlockThisDeviceOnly` and cached in memory after `ensureProvisioned()`, so a locked,
/// backgrounded device *could* unwrap. It does not, because plaintext in a canonical store on a
/// locked device is what plan §11 forbids — and that is also why the answer to a future "background
/// decrypt would be convenient" is **no**, never a keychain accessibility change (D-10.8).
///
/// ## Concurrency
///
/// A `nonisolated`, `Sendable` value. Nothing here reads a clock, a store or `UIApplication`.
public nonisolated struct MeshRoutedAccessGate: Equatable, Sendable {

    /// iOS data protection: the device is unlocked **now**.
    public let protectedDataAvailable: Bool

    /// The app scene is active.
    public let appIsForeground: Bool

    /// Fernlet's app lock is in a duress session.
    public let duressActive: Bool

    /// The fail-closed initial value every manager starts on, and the value a rig pushes to close
    /// the gate. Nothing is decrypted and no canonical store is mutated under it.
    public static let closed = MeshRoutedAccessGate(
        protectedDataAvailable: false, appIsForeground: false, duressActive: false
    )

    /// Builds a gate from the three facts.
    ///
    /// - Parameters:
    ///   - protectedDataAvailable: Whether iOS data protection currently permits protected reads.
    ///   - appIsForeground: Whether the app scene is active.
    ///   - duressActive: Whether the app lock is in a duress session.
    public init(protectedDataAvailable: Bool, appIsForeground: Bool, duressActive: Bool) {
        self.protectedDataAvailable = protectedDataAvailable
        self.appIsForeground = appIsForeground
        self.duressActive = duressActive
    }

    /// Whether plaintext may exist right now: unlocked **and** foreground **and** not under duress.
    public var isOpen: Bool { protectedDataAvailable && appIsForeground && !duressActive }

    /// The gate's answer for one capability.
    ///
    /// - Parameter capability: The question being asked.
    /// - Returns: `true` for ``MeshRoutedCapability/sealCustody`` always — custody is ciphertext-only
    ///   and its authority is the store's five states — and ``isOpen`` for the two plaintext
    ///   capabilities.
    public func permits(_ capability: MeshRoutedCapability) -> Bool {
        switch capability {
        case .sealCustody:
            return true
        case .decryptContent, .mutateCanonicalStore:
            return isOpen
        }
    }
}

// MARK: - MeshRoutedAccessEdge

/// Which legs of the gate moved on one push, and which of them owe work.
///
/// The two ciphertext legs matter on their **rising** edge: an unlock or a foreground makes the
/// store readable again, and the work owed is ciphertext-only — which is why the re-entry runs on a
/// rise even while the app is backgrounded, rather than on ``MeshRoutedAccessGate/isOpen``'s edge.
///
/// Duress is the third leg and it owes work on its **falling** edge: while a duress session was
/// active the heart stage was refused, so its clearing is the moment to re-evaluate it. A duress
/// fall moves no ciphertext leg (`isDuressSessionActive` survives `lock(reason:)`, and a real-PIN
/// unlock clears it with the device already unlocked and the app already foreground), so without
/// ``duressCleared`` the deferred heart stage would wait for an unrelated lock/foreground cycle.
/// Do not "tidy" this into `wasClosed && isOpen`.
///
/// ## Concurrency
///
/// A `nonisolated`, `Sendable` value derived from two gates.
public nonisolated struct MeshRoutedAccessEdge: Equatable, Sendable {

    /// Data protection became available on this push.
    public let protectedDataRose: Bool

    /// The app scene became active on this push.
    public let foregroundRose: Bool

    /// A duress session ended on this push.
    public let duressCleared: Bool

    /// Builds an edge from its three legs.
    ///
    /// - Parameters:
    ///   - protectedDataRose: Whether data protection became available.
    ///   - foregroundRose: Whether the scene became active.
    ///   - duressCleared: Whether a duress session ended.
    public init(protectedDataRose: Bool, foregroundRose: Bool, duressCleared: Bool) {
        self.protectedDataRose = protectedDataRose
        self.foregroundRose = foregroundRose
        self.duressCleared = duressCleared
    }

    /// The edge between two pushed values.
    ///
    /// - Parameters:
    ///   - previous: The gate the manager held.
    ///   - current: The gate just pushed.
    public init(from previous: MeshRoutedAccessGate, to current: MeshRoutedAccessGate) {
        protectedDataRose = !previous.protectedDataAvailable && current.protectedDataAvailable
        foregroundRose = !previous.appIsForeground && current.appIsForeground
        duressCleared = previous.duressActive && !current.duressActive
    }

    /// Whether a **ciphertext** leg rose. Jobs that read or write the sealed routed store self-guard
    /// on this, because a duress fall makes no store readable that was not readable before.
    public var isRising: Bool { protectedDataRose || foregroundRose }

    /// Whether this edge runs the re-entry pass at all.
    public var runsPass: Bool { isRising || duressCleared }

    /// A frozen English token naming the legs that moved — `"protectedData+foreground"`,
    /// `"duressCleared"`, `"none"`. Logged verbatim, never localized, never user copy.
    public var logToken: String {
        var legs: [String] = []
        if protectedDataRose { legs.append("protectedData") }
        if foregroundRose { legs.append("foreground") }
        if duressCleared { legs.append("duressCleared") }
        return legs.isEmpty ? "none" : legs.joined(separator: "+")
    }
}

// MARK: - MeshRoutedReentryReport

/// What one re-entry pass actually did, as **counts and legs** — never item ids and never peer
/// fingerprints (D-9.5's vocabulary rule).
///
/// Returned from `MeshNetworkManager.applyRoutedAccessGate(_:now:)` so a caller — a test today, P7's
/// `ProximityRunPolicy` tomorrow — can assert that each action ran exactly once, rather than
/// inferring it from audit lines.
///
/// ## Concurrency
///
/// A `nonisolated`, `Sendable` value.
public nonisolated struct MeshRoutedReentryReport: Equatable, Sendable {

    /// Which legs moved to produce this pass.
    public let legs: MeshRoutedAccessEdge

    /// Whether a deferred session restore was retried on this pass.
    public let restoredSession: Bool

    /// How many items the custody recovery handed to the durable commit door.
    public let committedCustodyCount: Int

    /// How many peers' suppressed capacity sweeps were spent on this pass.
    public let sweptPeerCount: Int

    /// How many of this device's own recipient receipts the retry list filed.
    public let acksFiled: Int

    /// How many heart-stage items are still awaiting a foreground ledger judgement. A **counted**
    /// number, not an enforcement claim: P6 owns the unwrap and the ledger commit.
    public let heartsPending: Int

    /// Builds a report.
    ///
    /// - Parameters:
    ///   - legs: The edge that ran the pass.
    ///   - restoredSession: Whether the session-restore retry ran.
    ///   - committedCustodyCount: Items handed to the durable custody commit.
    ///   - sweptPeerCount: Peers whose suppressed sweep was spent.
    ///   - acksFiled: Own recipient receipts filed.
    ///   - heartsPending: Heart-stage items still awaiting a judgement.
    public init(
        legs: MeshRoutedAccessEdge,
        restoredSession: Bool,
        committedCustodyCount: Int,
        sweptPeerCount: Int,
        acksFiled: Int,
        heartsPending: Int
    ) {
        self.legs = legs
        self.restoredSession = restoredSession
        self.committedCustodyCount = committedCustodyCount
        self.sweptPeerCount = sweptPeerCount
        self.acksFiled = acksFiled
        self.heartsPending = heartsPending
    }
}

// MARK: - MeshRoutedIndexReadReason

/// Why the manager is reading the routed index — one case per real caller class of
/// `routedIndexForReading(reason:)`.
///
/// The reason exists so a non-`loaded` store's silent exit becomes a **named** suppression line: the
/// shared reader used to log `advertisementSuppressed` at seven call sites, only two of which were
/// advertising. Frozen English `rawValue`s, logged verbatim.
nonisolated enum MeshRoutedIndexReadReason: String, CaseIterable, Equatable, Sendable {

    /// A departure's hand-off push batch.
    case handoffPush

    /// The signed routed inventory advertisement.
    case advertise

    /// The per-item "are either of this device's rungs still outstanding" predicate.
    case rung

    /// The per-item "was some destination's leg handed to this device" predicate.
    case courier

    /// The custody claim's own read.
    case claim

    /// The durable custody commit's read.
    case commit

    /// The drain answer's plan.
    case drainPlan

    /// Whether a suppressed read on this reason writes an audit line.
    ///
    /// `false` for the two **per-item predicates**: they run inside the drain's per-item loops, so a
    /// line each would be one per item per pass — the very noise this vocabulary exists to remove,
    /// at a finer grain. Both stay fail-closed in their own directions regardless (D-10.15); do not
    /// flip one for "consistency".
    var logsSuppression: Bool {
        switch self {
        case .rung, .courier:
            return false
        case .handoffPush, .advertise, .claim, .commit, .drainPlan:
            return true
        }
    }
}

// MARK: - MeshRoutedSweepVerb

/// Which sweep asked the store for a loaded index — the token a suppressed sweep is named with.
///
/// The four sweeps all exit correctly on a non-`loaded` store (D-9.4) and all exited **silently**
/// before item 10. Frozen English `rawValue`s, logged verbatim.
nonisolated enum MeshRoutedSweepVerb: String, CaseIterable, Equatable, Sendable {

    /// The roster-free expiry sweep.
    case expiry

    /// The once-per-peer capacity reclaim.
    case capacity

    /// The single-item reclaim that follows a delivery completing.
    case reclaimDelivered

    /// The terminal-rejection parked-set drop.
    case parkedDrop
}
