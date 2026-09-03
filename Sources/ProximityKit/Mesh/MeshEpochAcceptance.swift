// MeshEpochAcceptance.swift
// ProximityKit/Mesh
//
// P3 item 4 (plan §8.4): the acceptance rule. Two questions, one vocabulary.
//
//   1. May this presented rotation move our head?  -> `rotationVerdict(...)`
//   2. May this tunnel be introduced at all?       -> `introductionVerdict(...)`
//
// Both are pure functions of values the caller already holds — no clock, no roster lookup, no
// crypto. Whether the presenter is *authentic* is settled before either is asked; this file only
// decides what an authenticated claim means.

import Foundation

// MARK: - MeshEpochRotationVerdict

/// What a presented rotation may do to this device's epoch (plan §8.4).
///
/// Three answers, not two. ``coexist`` is the one a boolean cannot express and the one plan §8.4
/// exists to name: two partitions that each rotated at the same counter are **both correct**, and
/// collapsing that into "reject" would make a returning branch look like an attacker while
/// collapsing it into "accept" would silently pick a winner no one elected.
nonisolated enum MeshEpochRotationVerdict: Equatable, Sendable {
    /// The presented epoch strictly supersedes the local one; adopt it.
    case accept
    /// A divergent branch at the same counter. Both heads are real, both belong in
    /// `MeshSessionContext.epochHeads`, and neither supersedes the other until a merge mints a
    /// strictly greater successor (P4, plan §10.3).
    case coexist
    /// Refused, with the reason named.
    case reject(MeshEpochRotationRefusal)
}

// MARK: - MeshEpochRotationRefusal

/// Why a presented rotation was refused outright.
///
/// Frozen English diagnostics only — read in a log by a developer, never shown to a person, so
/// they stay out of the localization catalogs by construction.
nonisolated enum MeshEpochRotationRefusal: Equatable, Sendable {
    /// The presenter is not in the roster it presented — it cannot coordinate a set it is not in.
    case presenterNotInPresentedRoster
    /// The presenter is not the deterministic coordinator (lowest fingerprint) of the roster it
    /// presented (plan §8.4's authority test).
    case presenterIsNotTheCoordinator
    /// The presented roster is empty or over ``MeshMembershipBounds/maxRosterMembers``.
    case presentedRosterOutOfBounds
    /// The presented epoch's counter is below the local head's: stale, or a replay.
    case staleCounter
    /// The presented epoch is exactly the local head. Idempotent, not an advance.
    case alreadyCurrent

    /// Frozen English for the diagnostic surface. Never user copy.
    var diagnosticDescription: String {
        switch self {
        case .presenterNotInPresentedRoster:
            return "The rotation's signer is not in the roster it presented."
        case .presenterIsNotTheCoordinator:
            return "The rotation's signer is not the deterministic coordinator of its roster."
        case .presentedRosterOutOfBounds:
            return "The rotation presented an empty or oversized roster."
        case .staleCounter:
            return "The rotation names an epoch older than this device's."
        case .alreadyCurrent:
            return "The rotation names the epoch this device is already on."
        }
    }
}

// MARK: - MeshEpochIntroductionVerdict

/// What the two epoch references exchanged in a channel hello mean for the tunnel.
///
/// This is the strict replacement for P2's soft "equal, or one side empty" rule. See
/// ``MeshEpochAcceptance/introductionVerdict(local:peer:)`` for exactly what got stricter — and
/// ``reconcile(local:peer:)`` for the one thing P4 item 3 deliberately made *less* strict, and why
/// refusing it was a deadlock rather than a defence.
nonisolated enum MeshEpochIntroductionVerdict: Equatable, Sendable {
    /// The two sides are on one epoch (or one of them is on none yet). The associated value is the
    /// epoch the pair converged on — nil when neither side holds one.
    case converge(MeshEpochRef?)
    /// A non-empty epoch reference that is not a canonical ``MeshEpochRef``. Structurally
    /// malformed input, refused before any epoch comparison happens.
    case malformed
    /// Both sides hold a well-formed epoch and they are not the same epoch — divergent branches of
    /// one mesh.
    ///
    /// They coexist in the model (``MeshEpochRotationVerdict/coexist``) and they do **not** share a
    /// group key. Until P4 item 3 that was a refusal, which was a deadlock: two branches that had
    /// each rotated while split could never open the tunnel the merge runs over, so the epoch they
    /// diverged on could never be reconciled. The verdict now says *reconcile* — admit the tunnel
    /// and let plan §10.3's merge mint the strictly greater successor that retires both heads.
    ///
    /// Admitting it is a decision about **epochs only**. Every identity decision downstream is
    /// unchanged: ``MeshChannelIntroductionExchange/receive(_:roster:nonces:mayReconcileDivergentEpochs:)``
    /// still asks the roster whether the peer is a member, still refuses a departed or removed one,
    /// still refuses a foreign mesh, and still refuses a malformed reference before this case can
    /// even be reached.
    case reconcile(local: MeshEpochRef, peer: MeshEpochRef)
}

// MARK: - MeshEpochAcceptance

/// Plan §8.4's acceptance rule, as two pure decisions.
///
/// ## The rotation rule, verbatim from the plan
///
/// > Acceptance of a rotation: signed by an authenticated roster member who is the deterministic
/// > coordinator (lowest fingerprint) of *the roster set they present*, and `counter >` local
/// > counter.
///
/// Authentication is the caller's (the signature was checked before this is asked). What is here is
/// the other two halves: the presenter must be the lowest fingerprint of the roster it presented,
/// and the counter must strictly advance — with ``MeshEpochRotationVerdict/coexist`` carved out for
/// the same-counter divergence the plan says never needs mutual acceptance.
///
/// **Epoch continuity is not required.** A member returning from a long partition at counter 5
/// accepts counter 9 without ever having seen 6, 7 or 8; identity and roster validation are the
/// authority, not an unbroken chain. Nothing here consults history.
///
/// ## Concurrency
///
/// Pure static functions over `Sendable` values; callable from any isolation.
nonisolated enum MeshEpochAcceptance {

    /// Decides what a presented rotation may do to the local head.
    ///
    /// - Parameters:
    ///   - local: This device's current epoch, or nil when it holds none (a joiner accepts the
    ///     first epoch it is offered — there is nothing for it to be stale against).
    ///   - presented: The epoch the rotation names.
    ///   - presentedRoster: The roster the rotation presented, as canonical fingerprints.
    ///   - presenterFingerprint: The authenticated signer of the rotation.
    static func rotationVerdict(
        local: MeshEpochRef?,
        presented: MeshEpochRef,
        presentedRoster: [String],
        presenterFingerprint: String
    ) -> MeshEpochRotationVerdict {
        guard !presentedRoster.isEmpty,
              presentedRoster.count <= MeshMembershipBounds.maxRosterMembers else {
            return .reject(.presentedRosterOutOfBounds)
        }
        guard presentedRoster.contains(presenterFingerprint) else {
            return .reject(.presenterNotInPresentedRoster)
        }
        guard presentedRoster.min() == presenterFingerprint else {
            return .reject(.presenterIsNotTheCoordinator)
        }
        guard presented.coordinatorFingerprint == presenterFingerprint else {
            return .reject(.presenterIsNotTheCoordinator)
        }
        guard let local else { return .accept }
        if presented == local { return .reject(.alreadyCurrent) }
        if presented.counter == local.counter { return .coexist }
        return presented.counter > local.counter ? .accept : .reject(.staleCounter)
    }

    /// Merges a presented epoch into a set of branch heads, keeping the set bounded and ordered.
    ///
    /// This is how ``MeshEpochRotationVerdict/coexist`` becomes a *representable* state rather than
    /// a comment: both divergent heads survive here, and P4's merge is what later replaces them
    /// with a single strictly greater successor. Duplicates collapse; the oldest heads fall off the
    /// end when the cap bites, by ``MeshEpochRefOrder`` so every device drops the same ones.
    ///
    /// - Parameters:
    ///   - heads: The heads known so far.
    ///   - ref: The head to add.
    ///   - limit: The cap; defaults to what ``MeshSessionContext`` persists.
    static func mergedHeads(
        _ heads: [MeshEpochRef],
        adding ref: MeshEpochRef,
        limit: Int = MeshSessionContextSchema.maxEpochHeads
    ) -> [MeshEpochRef] {
        var unique = heads
        if !unique.contains(ref) { unique.append(ref) }
        let ordered = unique.sorted { MeshEpochRefOrder.precedes($1, $0) }
        return Array(ordered.prefix(max(0, limit)))
    }

    /// Decides whether two channel hellos may introduce, from their `epochRef` strings.
    ///
    /// ## What "strict" means here, precisely (plan §20.1)
    ///
    /// P2's rule was `local.isEmpty || peer.isEmpty || local == peer`, evaluated on raw strings.
    /// Three things it let through are now refused:
    ///
    /// 1. **Junk.** The old rule short-circuited on emptiness *before* looking at the other side,
    ///    so any string at all was admitted opposite an empty one. Every non-empty reference must
    ///    now parse as a canonical ``MeshEpochRef`` — counter in bounds, 32-hex id, 16-hex
    ///    coordinator — or the hello is ``MeshEpochIntroductionVerdict/malformed``.
    /// 2. **Two divergent branches wearing one number.** Under the placeholder decimal form, two
    ///    partitions that each rotated to counter 7 both sent `"7"` and the gate agreed they
    ///    matched. Equality is now equality of the whole ``MeshEpochRef``, so a same-counter
    ///    divergence is **seen** instead of silently conflated. Since P4 item 3 seeing it means
    ///    ``MeshEpochIntroductionVerdict/reconcile(local:peer:)`` — named, carried to the caller,
    ///    and reconciled by the merge — rather than a refusal that no merge could get past.
    /// 3. **Emptiness as a wildcard.** "No epoch" is now one named case of this rule — the joiner
    ///    that holds no group key — decided here rather than by a short-circuit that skipped the
    ///    comparison entirely. A joiner still introduces (admission would otherwise be impossible),
    ///    but only against a peer whose reference is itself well formed.
    ///
    /// - Parameters:
    ///   - local: This side's `epochRef` string; empty means "this device holds no epoch".
    ///   - peer: The peer's `epochRef` string, straight off untrusted bytes.
    static func introductionVerdict(local: String, peer: String) -> MeshEpochIntroductionVerdict {
        let localRef: MeshEpochRef?
        let peerRef: MeshEpochRef?
        do {
            localRef = local.isEmpty ? nil : try MeshEpochRef(canonical: local)
            peerRef = peer.isEmpty ? nil : try MeshEpochRef(canonical: peer)
        } catch {
            return .malformed
        }
        switch (localRef, peerRef) {
        case (nil, nil): return .converge(nil)
        case (nil, .some(let remote)): return .converge(remote)
        case (.some(let mine), nil): return .converge(mine)
        case (.some(let mine), .some(let remote)):
            return mine == remote ? .converge(mine) : .reconcile(local: mine, peer: remote)
        }
    }

    /// Whether a set of heads holds two that **coexist**: the same counter, different mintings.
    ///
    /// This is the question a merge asks of the folded head set, and it is a pure function of the
    /// heads — no clock, no roster, no tie-break. Two branches that both rotated while split always
    /// show up here, because both counted up from the same base: the counter they diverged at holds
    /// one head per branch, whatever either branch did afterwards.
    ///
    /// A head set with no divergence is a lineage — this device's own rotation history — and needs
    /// no successor minted for it.
    ///
    /// - Parameter heads: The heads to inspect. Bounded by ``MeshMergeOffer/maxFoldedHeads``
    ///   (Power of 10 rule 2): a peer cannot grow the loop by offering more.
    static func isDivergent(_ heads: [MeshEpochRef]) -> Bool {
        var mintingByCounter: [UInt32: UUID] = [:]
        for head in heads.prefix(MeshMergeOffer.maxFoldedHeads) {
            if let seen = mintingByCounter[head.counter], seen != head.epochID { return true }
            mintingByCounter[head.counter] = head.epochID
        }
        return false
    }

    /// The head a merge counts **up from**: the highest in ``MeshEpochRefOrder``, whose counter is
    /// therefore the `max` of plan §10.3's "counter = max + 1".
    ///
    /// Deliberately not a *winner*. The returned head is only the number the successor is derived
    /// from; the successor's own identity comes from the minting coordinator, so neither coexisting
    /// head survives the merge and no property of a head — not its id, not its coordinator, and
    /// above all not any timestamp, of which a ``MeshEpochRef`` carries none — decides anything.
    ///
    /// - Parameter heads: The folded head set.
    /// - Returns: The highest head, or nil for an empty set (a device on no epoch at all).
    static func highestHead(_ heads: [MeshEpochRef]) -> MeshEpochRef? {
        heads.prefix(MeshMergeOffer.maxFoldedHeads).max(by: MeshEpochRefOrder.precedes)
    }
}
