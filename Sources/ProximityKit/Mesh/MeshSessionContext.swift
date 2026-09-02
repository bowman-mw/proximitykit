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
/// bump; changing the MEANING of a field, or narrowing one, does. P3 item 4 is the next scheduled
/// bump: `epochHeads` is a `[String]` placeholder here and becomes `[MeshEpochRef]` there.
nonisolated enum MeshSessionContextSchema {

    /// The schema version this build writes and the only one it reads.
    static let current = 1

    /// The frozen token naming this at-rest shape. English forever — it is a persisted format
    /// name, never display copy.
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

    /// Current epoch branch head(s).
    ///
    /// **Placeholder, deliberately.** Plan §8.4 defines `MeshEpochRef` (a Lamport counter with a
    /// merge rule) in item 4; until it exists the head is the same opaque `epochRef` string the
    /// transport already carries on the wire, so this file can be written today without inventing
    /// half of item 4's model. Capped at ``MeshSessionContextSchema/maxEpochHeads`` on both init
    /// and decode — a bound, never a trap.
    var epochHeads: [String]

    /// Last authenticated external heartbeat, which resets the 30-minute idle timer (plan §8.2).
    /// Nil until one is seen.
    var lastExternalHeartbeat: Date?

    /// Set when this device develops the mesh. A **permanent rejoin bar**: a developed mesh can
    /// never be re-entered, which is why the flag is durable rather than derived from live state.
    var developedLocally: Bool

    /// P5's routing-inventory digest (plan §11), carried as an opaque token so the schema does not
    /// have to move when routing lands. Nil until P5 writes one; never a display string.
    var routingInventoryDigest: String?

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
    init(
        meshID: UUID,
        protocolVersion: Int,
        createdAt: Date,
        hardDeadline: Date,
        ledger: MeshMembershipLedger = .empty,
        epochHeads: [String] = [],
        lastExternalHeartbeat: Date? = nil,
        developedLocally: Bool = false,
        routingInventoryDigest: String? = nil
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
        let heads = try container.decodeIfPresent([String].self, forKey: .epochHeads) ?? []
        epochHeads = Array(heads.prefix(MeshSessionContextSchema.maxEpochHeads))
        lastExternalHeartbeat = try container.decodeIfPresent(Date.self, forKey: .lastExternalHeartbeat)
        developedLocally = try container.decodeIfPresent(Bool.self, forKey: .developedLocally) ?? false
        routingInventoryDigest = try container.decodeIfPresent(String.self, forKey: .routingInventoryDigest)
    }
}
