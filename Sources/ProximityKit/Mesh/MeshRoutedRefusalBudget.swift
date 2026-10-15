// MeshRoutedRefusalBudget.swift
// ProximityKit/Mesh
//
// The P5 review's finding 3, closing D-12.14: the per-sender budget for routed content frames that
// are refused BEFORE any store verb. Item 12's replay window records a frame only once the store's
// door has answered `.completed` on an author the verifier just authenticated; every refusal that
// sits before that — a verifier rejection, `notADestinationOrHandoff`, `unknownItemNotFromOrigin`,
// `unregisteredTypeChunk`, an undecodable frame — is therefore never recorded, and each costs real
// work (an Ed25519 verify, or a sealed-index load) that a committed member could repeat without
// bound. Bounded frame size is not bounded aggregate work.
//
// The bound is on the SENDER — the committed slot the envelope signature authenticated — never on
// the frame's claimed author, which is precisely the value the window cannot trust at that point.
// Pure `Sendable` value, no clock, no I/O, unit-testable without a manager.

import Foundation

// MARK: - MeshRoutedRefusalBudget

/// A per-sender budget for routed content frames refused **before** any store verb.
///
/// **What is counted:** refusals, never frames. An honest peer's inbound frames are already bounded
/// by the drain — `MeshRoutedDrainBounds.sessionFramesPerPeer` is the most bulk frames one peer may
/// make this device serve in a session — and an honest frame is refused before the store only by a
/// race (a courier's chunk arriving ahead of its manifest, a stale manifest after a re-key), so an
/// honest peer's refusal count stays far below its frame count. The cap is therefore that same
/// number: a sender that has produced more pre-store refusals than the drain would ever let it send
/// frames is not honest by the drain's own rules, and its routed content is dropped unread for the
/// rest of the session.
///
/// **Bounded on both axes** (R3): at most ``maxSenders`` rows, each at most ``cap``. The sender
/// axis is the **admission set's** capacity (`MeshMembershipBounds.maxRecordsPerKind`, 16) rather
/// than the tighter roster cap, for the replay window's reason: a session's senders are every
/// admitted-and-committed member it ever had, departures and rejoins included, and a row is never
/// released mid-session. A sender with no row on a full axis is refused, fail closed and silently
/// — unreachable for a real member, since committed senders can never outnumber admissions, so it
/// is a bug's signature rather than a case.
///
/// **Cleared only at the session resets** the manager's other per-session sets clear at — never on
/// a slot's disconnect or a rejoin (that would be the attacker's reset lever) and never at a
/// partition flap. The honest worst case is one peer's routed delivery delayed to the receiver's
/// next session, which no honest peer reaches.
///
/// ## Concurrency
///
/// A `nonisolated`, `Sendable` value the `@MainActor` manager owns.
nonisolated struct MeshRoutedRefusalBudget: Equatable, Sendable {

    /// What one charge did.
    enum Charge: Equatable, Sendable {
        /// Counted; the sender is still under its cap.
        case charged
        /// This charge reached the cap — the ONE transition, and the caller's one audit line.
        case spent
        /// The cap had already been reached; nothing changed and nothing is owed.
        case alreadySpent
        /// The sender axis is full and this sender holds no row — refused, fail closed. Unreachable
        /// for a committed-slot sender; a bug's signature.
        case untracked
    }

    /// Pre-store refusals one sender may cause in a session before its routed content is dropped.
    let cap: Int

    /// Senders tracked at once.
    let maxSenders: Int

    /// Refusals so far, per authenticated envelope sender. Every value is at most ``cap``.
    private(set) var refusals: [String: Int] = [:]

    /// Builds a budget. Shipping code takes both defaults; a cell injects a tiny cap.
    ///
    /// - Parameters:
    ///   - cap: Refusals per sender per session, at least 1.
    ///   - maxSenders: Rows kept, at least 1.
    init(
        cap: Int = MeshRoutedDrainBounds.sessionFramesPerPeer,
        maxSenders: Int = MeshMembershipBounds.maxRecordsPerKind
    ) {
        self.cap = max(1, cap)
        self.maxSenders = max(1, maxSenders)
    }

    /// Whether `sender`'s routed content is dropped before any work: its budget is spent, or the
    /// sender axis is full and it holds no row (fail closed; the manager's gate asks this before
    /// any door runs, so ``charge(_:)`` never answers ``Charge/untracked`` through it).
    ///
    /// - Parameter sender: The authenticated envelope sender's fingerprint.
    func isSpent(_ sender: String) -> Bool {
        if let count = refusals[sender] { return count >= cap }
        return refusals.count >= maxSenders
    }

    /// Charges one pre-store refusal to `sender`.
    ///
    /// - Parameter sender: The authenticated envelope sender's fingerprint.
    /// - Returns: what the charge did; only ``Charge/spent`` and ``Charge/untracked`` owe a line.
    mutating func charge(_ sender: String) -> Charge {
        guard let before = refusals[sender] else {
            guard refusals.count < maxSenders else { return .untracked }
            refusals[sender] = 1                                          // R3: bounded map
            return cap <= 1 ? .spent : .charged
        }
        guard before < cap else { return .alreadySpent }
        let after = before + 1
        refusals[sender] = after                                          // R3: bounded by `cap`
        return after >= cap ? .spent : .charged
    }

    /// Forgets every sender — at the session resets only.
    mutating func reset() {
        refusals.removeAll()
    }
}
