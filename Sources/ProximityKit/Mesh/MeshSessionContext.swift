// MeshSessionContext.swift
// ProximityKit/Mesh
//
// P3 item 2 (plan §8.1): the ONE value a mesh session persists. Everything about who belongs is
// carried here as the pure ledger of item 1; everything derived from it (the roster, the connected
// set, the coordinator, quorum, "final pair") is recomputed on read and never stored.
//
// This file is the documented policy reversal of plan §17.3: until P3, ProximityKit persisted no
// session state at all. It now persists exactly this, sealed, and the things that stay memory-only
// say so by contrast — above all `MeshGroupKey`, which is still never written anywhere.

import Foundation

// MARK: - MeshSessionContextSchema

/// The at-rest schema constants for ``MeshSessionContext``.
///
/// ``token`` is a **frozen English wire/at-rest token** (localization wall): it is the same
/// spelling as the sealing purpose `FernletCryptoPurpose.KeyDerivation.meshSessionContextV1`, and
/// it names the shape of the JSON inside the sealed blob. ``current`` is the integer actually
/// written into every context, and the ONLY value the decoder accepts — a context stamped with any
/// other version is refused as corrupt rather than partially decoded, because a partially decoded
/// membership ledger is a roster that silently lost members.
///
/// **Bumping it is a deliberate act.** Adding a field with a default is compatible and needs no
/// bump; changing the MEANING of a field, or narrowing one, does.
///
/// ## Version 2 (P3 item 4) — and why a v1 file is corrupt, not migrated
///
/// v2 narrows ``MeshSessionContext/epochHeads`` from an opaque `[String]` placeholder to
/// `[MeshEpochRef]`: the same JSON shape (each head is still one string) with a strictly narrower
/// meaning (each string must now be a canonical ``MeshEpochRef``). There is **no migration**, and
/// a v1 file lands in the store's `corrupt` state like any other unreadable one. That is honest
/// rather than lazy: the store shipped in this same phase and no build that wrote a v1 file has
/// ever run on a device, so a v1 file on disk is not an old user's data — it is a file this build
/// cannot account for, and `corrupt` is exactly the state that refuses to overwrite such a thing.
/// If a v1 file could ever have held a real roster, this would have to be a migration instead.
nonisolated enum MeshSessionContextSchema {

    /// The schema version this build writes and the only one it reads. See the type's discussion
    /// for what v2 changed and why v1 is refused rather than migrated.
    static let current = 2

    /// The frozen token naming this at-rest shape. English forever — it is a persisted format
    /// name, never display copy.
    ///
    /// It stays `…v1` across the schema bump on purpose: this token is the **sealing domain**,
    /// spelled identically to `FernletCryptoPurpose.KeyDerivation.meshSessionContextV1`, and the
    /// key that opens the blob did not change. ``current`` is the value that carries the shape.
    static let token = "fernlet.mesh.session-context.v1"

    /// Epoch branch heads retained (plan §9 caps the keyring; 8 is the roster cap, and a mesh
    /// cannot have more live branches than it has members).
    static let maxEpochHeads = MeshMembershipBounds.maxRosterMembers
}

// MARK: - MeshSessionContextDecodingError

/// Why a decoded ``MeshSessionContext`` was refused before any of its fields were trusted.
///
/// Thrown from `init(from:)`, so it surfaces through `JSONDecoder` and lands in the store's
/// `corrupt` state — deliberately NOT in `absent`. A context this build cannot read is not a
/// green field: overwriting it would destroy membership records a newer build wrote.
nonisolated enum MeshSessionContextDecodingError: Error, Equatable, Sendable {
    /// The blob decoded, but its `schemaVersion` is not ``MeshSessionContextSchema/current``.
    /// Carries the version found so a refusal can name it.
    case unsupportedSchemaVersion(Int)
}

// MARK: - MeshSessionTerminationReason

/// Why this device's participation in a mesh ended, for good (plan §8.2).
///
/// Frozen English `rawValue`s: they are written into the sealed context and read back after a
/// relaunch, so they are at-rest tokens and never localize. The display copy that a UI would show
/// for "this session has ended" is forked separately and does not live here.
///
/// The distinction ``endsTheMeshForEveryone`` draws is plan §8.3's: a departure or a removal takes
/// **this device** out of a mesh that carries on without it, while a termination, a development or
/// the ceiling ends the mesh itself.
nonisolated enum MeshSessionTerminationReason: String, Codable, Equatable, Sendable, CaseIterable {

    /// This device sent its own signed departure record.
    case ownDeparture = "own-departure"

    /// A verified removal record named this device (plan §10.4's vote completed elsewhere).
    case removedFromRoster = "removed-from-roster"

    /// A peer's `terminated.v1` verified against the merged roster.
    case verifiedTerminationRecord = "verified-termination"

    /// This device signed the termination as a member of the final pair.
    case finalPairTermination = "final-pair"

    /// The signed absolute `hardDeadline` was reached.
    case hardDeadlineSigned = "hard-deadline-signed"

    /// The local monotonic guard reached the ceiling first — a wall clock that moved backwards
    /// cannot lengthen a session (plan §8.2).
    case hardDeadlineMonotonic = "hard-deadline-monotonic"

    /// The epoch counter cap was reached, so no further key can be minted (plan §8.4).
    case epochCounterExhausted = "epoch-counter-exhausted"

    /// The user developed the mesh: a permanent rejoin bar.
    case developed = "developed"

    /// Whether this reason ends the mesh for every member, as opposed to only for this device.
    var endsTheMeshForEveryone: Bool {
        switch self {
        case .ownDeparture, .removedFromRoster: return false
        case .verifiedTerminationRecord, .finalPairTermination, .hardDeadlineSigned,
             .hardDeadlineMonotonic, .epochCounterExhausted, .developed:
            return true
        }
    }
}

// MARK: - MeshSessionLocalTermination

/// The durable mark that this device's participation in a mesh ended (plan §8.2's rejoin bar).
///
/// Written into the sealed context **before** the frame that tells anybody about it is sent (plan
/// §3.6), which is what makes the bar survive a force-quit: a session that ended and then died
/// before it could say so still comes back ended.
nonisolated struct MeshSessionLocalTermination: Codable, Equatable, Sendable {

    /// Why it ended. A frozen token.
    let reason: MeshSessionTerminationReason

    /// When this device recorded the ending. Diagnostic and ordering only — the *authority* is the
    /// signed record or the ceiling, never this timestamp.
    let at: Date

    /// Builds a mark.
    ///
    /// - Parameters:
    ///   - reason: Why the session ended.
    ///   - at: When this device recorded it.
    init(reason: MeshSessionTerminationReason, at: Date) {
        self.reason = reason
        self.at = at
    }
}

// MARK: - MeshSessionContext

/// Everything one device durably knows about one mesh session (plan §8.1).
///
/// Sealed at rest by ``MeshSessionStore`` and by nothing else — there is no plaintext writer, and
/// no second copy in `UserDefaults`, the synced blob, or CloudKit.
///
/// ## What is here, and what is deliberately not
///
/// - **The membership ledger** (``ledger``) is the whole of "who belongs". The roster is
///   `admitted − departed − removed`, derived per read via ``MeshMembershipLedger/derivedRoster``
///   and never stored, so reload-after-process-death and merge-after-partition are literally the
///   same code path (plan §10.3).
/// - **The group control key is NOT here** and never will be. `MeshGroupKey` stays memory-only:
///   after a process death the session resumes by reconnecting and rotating (plan §8.3), and
///   content never depends on the control key (invariant 3). That doc guard is load-bearing
///   precisely because THIS type broke the "ProximityKit persists nothing" rule beside it.
/// - **No message content.** The live transcript (`SessionMessageStore`) stays memory-only; the
///   durable half of a session is membership, not conversation.
/// - **No display copy.** Every string here is a frozen token or a fingerprint.
///
/// ## Concurrency
///
/// `nonisolated` against the module's `defaultIsolation(MainActor.self)` and `Sendable`: a pure
/// immutable-ish value read and written by a nonisolated store, exactly like the membership
/// records it carries.
nonisolated struct MeshSessionContext: Codable, Equatable, Sendable {

    /// The at-rest schema stamp. Always ``MeshSessionContextSchema/current`` on write; any other
    /// value on read is refused (``MeshSessionContextDecodingError/unsupportedSchemaVersion(_:)``).
    let schemaVersion: Int

    /// The mesh this context describes. Every membership record in ``ledger`` carries the same id;
    /// mixing two meshes in one file is a bug the store cannot detect for you.
    let meshID: UUID

    /// The mesh protocol version agreed at creation, mirrored from the mesh descriptor.
    let protocolVersion: Int

    /// When the mesh was created — signed into the descriptor, identical on every member.
    let createdAt: Date

    /// `createdAt + 6 h`: the absolute membership ceiling (plan §8.2). Signed at creation and
    /// identical on every member, so it is enforceable across a process death; the local monotonic
    /// guard that pairs with it belongs to the state machine (item 6), not to this value.
    let hardDeadline: Date

    /// The four grow-only signed record sets membership is made of (item 1). The only mutable
    /// field that grows, and its growth is bounded by ``MeshMembershipBounds``.
    var ledger: MeshMembershipLedger

    /// Current epoch branch head(s) — plan §8.4's real model, as of schema 2.
    ///
    /// **Plural on purpose.** Two members that rotated independently while partitioned hold
    /// divergent epochs at the same counter, and §8.4 says neither is wrong: they *coexist* until
    /// a merge mints a strictly greater successor. Both belong here, which is what makes that
    /// state representable across a process death instead of only inside one run
    /// (``MeshEpochAcceptance/mergedHeads(_:adding:limit:)`` is how one is added).
    ///
    /// Each head is stored as its canonical string, so the at-rest JSON shape is unchanged from
    /// schema 1 while the meaning is strictly narrower — a head that is not a canonical
    /// ``MeshEpochRef`` now fails the decode instead of being carried as an opaque token. Capped at
    /// ``MeshSessionContextSchema/maxEpochHeads`` on both init and decode — a bound, never a trap.
    ///
    /// The **keys** those epochs name are not here and never will be: ``MeshEpochKeyring`` is
    /// memory-only, exactly like the ``MeshGroupKey`` values it holds.
    var epochHeads: [MeshEpochRef]

    /// Last authenticated external heartbeat, which resets the 30-minute idle timer (plan §8.2).
    /// Nil until one is seen.
    var lastExternalHeartbeat: Date?

    /// Set when this device develops the mesh. A **permanent rejoin bar**: a developed mesh can
    /// never be re-entered, which is why the flag is durable rather than derived from live state.
    var developedLocally: Bool

    /// P5's routing-inventory digest (plan §11), carried as an opaque token so the schema does not
    /// have to move when routing lands. Nil until P5 writes one; never a display string.
    var routingInventoryDigest: String?

    /// The durable ending mark (P3 item 6, plan §8.2). Nil while this device is still a member.
    ///
    /// **Additive, so the schema stays at 2.** The at-rest shape does not move: a context written
    /// before this field existed decodes with a nil mark (``init(from:)`` uses `decodeIfPresent`),
    /// and a context written with one is refused by no reader that ever shipped, because no build
    /// with the old shape has ever run on a device (see ``MeshSessionContextSchema``). A bump would
    /// be owed only if the field NARROWED an existing one, which is precisely what took epochHeads
    /// from 1 to 2.
    ///
    /// The ledger cannot carry this on its own: an ending recorded here is often one this device
    /// signed for itself (its own departure, the ceiling), and the verifier is fail-closed against
    /// a ledger that holds no admission for the signer — so the ending would be refused into the
    /// very record set that was supposed to remember it. This field is the honest home until item
    /// 7 gives joiners a real ledger.
    var localTermination: MeshSessionLocalTermination?

    /// Builds a context, stamping the current schema version and clamping ``epochHeads``.
    ///
    /// - Parameters:
    ///   - meshID: The mesh this context describes.
    ///   - protocolVersion: The mesh protocol version agreed at creation.
    ///   - createdAt: Mesh creation instant, from the signed descriptor.
    ///   - hardDeadline: `createdAt + 6 h`, from the signed descriptor.
    ///   - ledger: Membership records known so far; defaults to empty.
    ///   - epochHeads: Epoch branch heads; clamped to the cap.
    ///   - lastExternalHeartbeat: Last authenticated heartbeat, if any.
    ///   - developedLocally: Whether this device has developed the mesh.
    ///   - routingInventoryDigest: P5's inventory digest, if any.
    ///   - localTermination: The durable ending mark, if this device's participation has ended.
    init(
        meshID: UUID,
        protocolVersion: Int,
        createdAt: Date,
        hardDeadline: Date,
        ledger: MeshMembershipLedger = .empty,
        epochHeads: [MeshEpochRef] = [],
        lastExternalHeartbeat: Date? = nil,
        developedLocally: Bool = false,
        routingInventoryDigest: String? = nil,
        localTermination: MeshSessionLocalTermination? = nil
    ) {
        self.schemaVersion = MeshSessionContextSchema.current
        self.meshID = meshID
        self.protocolVersion = protocolVersion
        self.createdAt = createdAt
        self.hardDeadline = hardDeadline
        self.ledger = ledger
        self.epochHeads = Array(epochHeads.prefix(MeshSessionContextSchema.maxEpochHeads))
        self.lastExternalHeartbeat = lastExternalHeartbeat
        self.developedLocally = developedLocally
        self.routingInventoryDigest = routingInventoryDigest
        self.localTermination = localTermination
    }

    /// The ending this context already records, or nil while this device is still a member.
    ///
    /// Four independent authorities, checked in the order of how *specific* they are: the durable
    /// mark this device wrote, its own development flag, a verified termination record in the
    /// ledger, and its own departure record. Any one of them is a permanent bar — plan §8.2's
    /// "a developed or terminated mesh can never be rejoined" — and a relaunch re-derives it from
    /// exactly these bytes, which is what stops a restart resurrecting an ended session.
    ///
    /// - Parameter selfFingerprint: This device's fingerprint, for the own-departure check.
    /// - Returns: The reason, or nil.
    func recordedEndingReason(selfFingerprint: String) -> MeshSessionTerminationReason? {
        if let mark = localTermination { return mark.reason }
        if developedLocally { return .developed }
        if ledger.termination != nil { return .verifiedTerminationRecord }
        if ledger.departures.contains(fingerprint: selfFingerprint) { return .ownDeparture }
        return nil
    }

    /// Decodes a context, refusing any schema version this build does not own and clamping the
    /// one unbounded array.
    ///
    /// The version check runs FIRST, before any other key is touched: a future build's context must
    /// be refused as a whole, not silently reinterpreted field by field. The clamp mirrors the
    /// membership record sets, which do the same on their own decode — bounded growth is a property
    /// of the at-rest format, not only of the writer (Power of 10 R2/R3).
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let version = try container.decode(Int.self, forKey: .schemaVersion)
        guard version == MeshSessionContextSchema.current else {
            throw MeshSessionContextDecodingError.unsupportedSchemaVersion(version)
        }
        schemaVersion = version
        meshID = try container.decode(UUID.self, forKey: .meshID)
        protocolVersion = try container.decode(Int.self, forKey: .protocolVersion)
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        hardDeadline = try container.decode(Date.self, forKey: .hardDeadline)
        ledger = try container.decode(MeshMembershipLedger.self, forKey: .ledger)
        let heads = try container.decodeIfPresent([MeshEpochRef].self, forKey: .epochHeads) ?? []
        epochHeads = Array(heads.prefix(MeshSessionContextSchema.maxEpochHeads))
        lastExternalHeartbeat = try container.decodeIfPresent(Date.self, forKey: .lastExternalHeartbeat)
        developedLocally = try container.decodeIfPresent(Bool.self, forKey: .developedLocally) ?? false
        routingInventoryDigest = try container.decodeIfPresent(String.self, forKey: .routingInventoryDigest)
        localTermination = try container.decodeIfPresent(
            MeshSessionLocalTermination.self, forKey: .localTermination
        )
    }
}
