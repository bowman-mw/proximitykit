// MeshRoutedDeliveryHold.swift
// ProximityKit/Mesh
//
// Network migration P5 item 9 (plan §11): the bounded observable behind the user-visible backpressure
// failure — "a queue that grows past its cap without telling anyone is the violation, not just the
// growth itself".
//
// **No display text lives here, and none ever will.** A `String` composed inside a package renders
// verbatim in every language (SwiftUI's `Text(String)` selects the `StringProtocol` overload), which
// is the live defect in every existing mesh failure surface. The app forks the copy from the frozen
// cause; this module ships counts and tokens.

import Foundation

// MARK: - MeshRoutedDeliveryHoldCause

/// Why routed content this device was offered is not being held.
///
/// Frozen English `rawValue`s — a wire-adjacent vocabulary that is logged verbatim, matched on and
/// never localized. The app forks its own copy per case, because the two causes are different facts:
/// a storage sentence states the opposite of what happened for ``notPlaced``.
///
/// Deliberately **silent about three other states**. `deferred`, seal-`refused` and `corrupt` are not
/// "full" (plan §19.5's fifth wrinkle) and set no hold at all.
///
/// **P5 item 10 declined the third case it was offered here (D-10.9).** The user-visible hold stays
/// the three store-level capacity refusals: a locked device that is holding ciphertext perfectly well
/// has nothing to tell the user, and the genuinely blocked window (pre-first-unlock) is already
/// fail-closed in five named states. Locked-device visibility therefore ships as **counts and frozen
/// tokens** instead — `MeshNetworkManager.routedAccessGate`, ``MeshRoutedReentryReport``,
/// `mesh.routedStore.readSuppressed` / `sweepSuppressed` and the `mesh.routedAccess.*` family. The
/// copy question (whether a device that could hold nothing all session should say so, and in what
/// words) is an **owner** question, parked with item 9's blocked display literals — not a silent
/// drop, and not a case added here on a guess.
public nonisolated enum MeshRoutedDeliveryHoldCause: String, CaseIterable, Equatable, Sendable {

    /// A capacity refusal at a writer door, or an item admitted that the byte budget can no longer
    /// complete. The live, actionable condition.
    case storeFull

    /// A departure hand-off could not place items with a custodian, so this device is still keeping
    /// them. A settled fact about a past departure, never a promise about a future one.
    case notPlaced
}

// MARK: - MeshRoutedDeliveryHold

/// What this device could not take or place, as **counts and a frozen token** — the whole of item
/// 9's user-visible surface at the module boundary.
///
/// One value, never a list of keys, peers or file names: content identifiers are not display material
/// and are kept out of the visible and audited vocabulary. The diagnostic half —
/// `lastRoutedDrainRefusal` and the per-peer refused-key map — stays internal and untouched beside
/// it.
///
/// ``itemCount`` **saturates** at the store's item cap: both key sets behind it are bounded by
/// ``MeshRoutedStoreFormat/maxItems`` and name that bound in an audit line when they reach it, so the
/// count under-reports rather than lying about a set that stopped growing.
///
/// ## Concurrency
///
/// A `nonisolated`, `Sendable` value. The manager publishes it; nothing here reads a clock or a
/// store.
public nonisolated struct MeshRoutedDeliveryHold: Equatable, Sendable {

    /// Which fact this hold states.
    public let cause: MeshRoutedDeliveryHoldCause

    /// How many distinct items are behind **this** cause — never a union of two facts.
    public let itemCount: Int

    /// When the hold was last derived.
    public let at: Date

    /// Builds a hold.
    ///
    /// - Parameters:
    ///   - cause: The frozen cause.
    ///   - itemCount: Distinct items behind that cause.
    ///   - at: The instant the hold was derived.
    public init(cause: MeshRoutedDeliveryHoldCause, itemCount: Int, at: Date) {
        self.cause = cause
        self.itemCount = itemCount
        self.at = at
    }
}
