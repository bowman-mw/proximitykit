// MeshKeyAgreementAdvertisement.swift
// ProximityKit/Mesh
//
// P6 item 1 (plan §11.3 item 13(ii), §23.1): ADDRESSING, not membership.
//
// A mint has to wrap one content key for every destination the roster names, and until this file
// the only sources it would accept were present-tense: a live slot's handshake-verified
// key-agreement key, and the session-roster entry written from that same verified value. Both are
// memory-only, so a restart, an idle-lapse resume or a rejoin restored the ledger and NOT the keys,
// and the mint refused every destination it did not happen to be linked to at that instant
// (D-13.22). This file is the durable third source.
//
// A member signs its OWN key-agreement public key under its admitted Ed25519 key; the statement is
// verified against `ledger.admissions` — the ledger's own trust root — and folded into a bounded,
// grow-only, CONFLICT-REFUSING set that rides in the sealed ``MeshSessionContext``.
//
// It is deliberately NOT a fifth ``MeshMembershipRecordKind`` (launcher §5a): a key is not a
// membership fact — it is addressing for a member that is already admitted, and it can never
// create, end or revoke a membership. A fifth kind would also move two pinned goldens (the
// membership digest enumerates records by kind) and the re-gossip budget `maxProofs ==
// maxReGossipFrames == 49`, a number P4's 80 and P5's 40 cells were measured under. Because
// ``SignedKeyAgreementAdvertisement`` is not a ``MeshMembershipRecord`` at all, `MeshRecordIdentity`
// cannot be constructed from one: "the digest's golden cannot move" is a type-system fact here
// rather than a promise.
//
// Nothing in this file reads a clock, touches disk or speaks to a transport, and only the one
// `@MainActor` factory at the bottom mints a signature. The fold is a pure function, so the whole
// decision table — the duplicate-key refusal included — is provable at tier 1 with no rig.

import FernletCrypto
import Foundation

// MARK: - SignedKeyAgreementAdvertisement

/// One member's signed statement of its own durable key-agreement public key
/// (`fernlet.mesh.key-agreement.v1`).
///
/// **Self-signed by definition**, exactly like ``SignedDepartureRecord``: the subject IS the author,
/// held as one field rather than two, so there is no separate author check to get wrong and the
/// worst a bad signature can cost is the signer's own addressability.
///
/// **Why it is worth persisting.** `IdentityService`'s key-agreement private key is keychain-
/// resident, device-only and never rotated within a mesh; `ensureProvisioned()` mints the signing
/// and key-agreement pair together in every one of its four cases, and a device that loses one row
/// loses both and comes back with a NEW fingerprint. So "same fingerprint, a different advertised
/// key" is reachable by no legitimate provisioning path — which is the argument the duplicate-key
/// refusal in ``MeshKeyAdvertisementFold`` rests on.
///
/// **The fingerprint is an index, never the authority.** It is 16 hex characters derived from the
/// signing key, and `IdentityService.fingerprintsMatch` states the rule this type inherits:
/// fingerprints stay display and routing metadata, while authorization uses full key bytes. The
/// authority here is the `signingPublicKey` the ledger's own admission bound to that fingerprint
/// (``MeshMembershipRecordVerifier``), never anything carried in this value.
///
/// The `signature` is opaque bytes this type merely carries: nothing in this file verifies one, and
/// a value that has not been through the verifier must never reach the set.
nonisolated struct SignedKeyAgreementAdvertisement: Codable, Equatable, Sendable {

    /// The mesh the statement belongs to. An advertisement for another mesh is a refusal, not a
    /// difference — and `meshID` is bound into the signed bytes, so it cannot be rewritten in
    /// flight.
    let meshID: UUID

    /// The member the key belongs to — and the author. The dedup key of the set it lives in.
    let memberFingerprint: String

    /// The member's raw key-agreement public key, exactly
    /// ``MeshMembershipEventFormat/keyAgreementByteCount`` bytes. Bound into the signed bytes as
    /// OPAQUE length-prefixed bytes, never as a string, so a 32-byte blob can never be read as a
    /// count.
    let keyAgreementPublicKey: Data

    /// When the member signed it. Bound in, so a replayed advertisement cannot be re-dated, and it
    /// is the set's primary order key.
    let advertisedAt: Date

    /// The member's signature over ``canonicalBytes(for:)-(SignedKeyAgreementAdvertisement)``.
    /// Opaque here; checked by ``MeshMembershipRecordVerifier``.
    let signature: Data

    /// Who signed it — the subject itself. Present so the value reads like every other signed
    /// membership object even though it is not a membership record.
    var authorFingerprint: String { memberFingerprint }

    /// Builds an advertisement from already-signed parts.
    ///
    /// - Parameters:
    ///   - meshID: The mesh the statement belongs to.
    ///   - memberFingerprint: The subject, which is also the author.
    ///   - keyAgreementPublicKey: The subject's raw key-agreement public key.
    ///   - advertisedAt: The signing instant, bound into the signature.
    ///   - signature: The subject's signature over the canonical bytes.
    init(
        meshID: UUID,
        memberFingerprint: String,
        keyAgreementPublicKey: Data,
        advertisedAt: Date,
        signature: Data
    ) {
        self.meshID = meshID
        self.memberFingerprint = memberFingerprint
        self.keyAgreementPublicKey = keyAgreementPublicKey
        self.advertisedAt = advertisedAt
        self.signature = signature
    }

    /// Whether every field has the width the format fixes. Checked on untrusted bytes BEFORE any
    /// signature verification, the ``MeshEpochHeadsPayload/isWellFormed`` idiom.
    var isWellFormed: Bool {
        keyAgreementPublicKey.count == MeshMembershipEventFormat.keyAgreementByteCount
            && signature.count == MeshMembershipEventFormat.signatureByteCount
            && !memberFingerprint.isEmpty
            && memberFingerprint.utf8.count <= MeshMembershipEventFormat.maxFingerprintLength
    }
}

// MARK: - MeshKeyAgreementAdvertisementSet

/// The bounded, grow-only, **conflict-refusing** set of verified key advertisements one device
/// holds.
///
/// ## Why this is its own type rather than a ``MeshMembershipRecordSet``
///
/// The membership record set is the right algebra for records that "can differ only by records one
/// side is MISSING, never by records that conflict": its `merging`/`inserting` dedup by member
/// **earliest-wins and silently pick one** of two rows for the same member. For a *key* that is
/// precisely the wrong answer — two different keys under one fingerprint is a substitution attempt
/// or a bug, and picking either would mean wrapping a content key to a device that may not hold it.
/// Inheriting that fold would have been a fail-open every cell in this file would have passed
/// through, so the set is its own type with its own fold and **no `merging` at all**. The only
/// mutating doors, ``inserting(_:)`` and ``markingConflicted(_:)``, take a
/// ``MeshVerifiedKeyAgreementAdvertisement``, which only the verifier can mint.
///
/// ## What the bound is, and why reaching it is a defect signal
///
/// ``capacity`` is the admission set's own cap (16), derived rather than chosen. It cannot be
/// reached honestly: `MeshDerivedRoster.admittedMembers` applies `prefix(maxRosterMembers)` (8) to
/// the admission set, so at most **eight distinct fingerprints** can ever pass the verifier's
/// roster check over the life of one mesh, and a departure never promotes a ninth. The fold
/// therefore refuses at the bound **by name** (``MeshKeyAdvertisementFoldOutcome/refusedSetFull(_:)``)
/// instead of dropping a row the way a silent truncation would — the one thing that must not happen
/// is a full set quietly evicting an incumbent.
///
/// A `conflicted` fingerprint keeps its earliest row (the set only grows) and is simply
/// unaddressable: ``keyAgreementPublicKey(for:)`` answers nil for it, which is what makes a mint
/// refuse that destination rather than choose a key. Conflicts are permanent for the life of the
/// mesh, like every other row here; "rejoining means a new mesh" is the existing escape.
///
/// The set and its conflict marks are **one value** so a save that fails rolls both back together:
/// a refused seal that left a conflict mark in memory would be a divergence between "verified" and
/// "remembered" in the one direction that matters.
nonisolated struct MeshKeyAgreementAdvertisementSet: Codable, Equatable, Sendable {

    /// How many advertisements the set retains — the admission set's own cap (16).
    static let capacity = MeshMembershipBounds.maxRecordsPerKind

    /// Advertisements read off a decoder or handed to an initializer before deduplication, so a
    /// hostile input cannot make normalization do unbounded work. Four times the cap, as every
    /// record set uses.
    static var maxInputAdvertisements: Int { capacity * 4 }

    private let ordered: [SignedKeyAgreementAdvertisement]
    private let conflicted: [String]

    /// The empty set — the right starting point for a device that has folded nothing.
    static var empty: MeshKeyAgreementAdvertisementSet { MeshKeyAgreementAdvertisementSet() }

    /// An empty set.
    init() {
        ordered = []
        conflicted = []
    }

    /// Builds a set from advertisements in any order, deduplicating by member, sorting and capping.
    ///
    /// **The at-rest door.** Every row in a blob this build wrote came through
    /// ``MeshKeyAdvertisementFold``; this initializer exists so the sealed context can be decoded
    /// and so tests can state a starting position. It is not a verification seam and never was —
    /// like ``MeshMembershipRecordSet``, "a value in a set is not a verified value".
    ///
    /// Two rows for one member with **different** keys mark that member conflicted here too, so a
    /// hand-built or decoded set cannot be more trusting than the fold.
    ///
    /// - Parameters:
    ///   - advertisements: The advertisements, in any order.
    ///   - conflictedFingerprints: Members already known to be unaddressable.
    init(
        advertisements: [SignedKeyAgreementAdvertisement],
        conflictedFingerprints: [String] = []
    ) {
        let folded = Self.normalized(advertisements, conflictedFingerprints)
        ordered = folded.ordered
        conflicted = folded.conflicted
    }

    /// Decodes a set, applying exactly the normalization the initializer does — bounded growth is a
    /// property of the at-rest format, not only of the writer.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            advertisements: try container.decodeIfPresent(
                [SignedKeyAgreementAdvertisement].self, forKey: .ordered
            ) ?? [],
            conflictedFingerprints: try container.decodeIfPresent([String].self, forKey: .conflicted) ?? []
        )
    }

    /// The advertisements, in the set's deterministic order (earliest first).
    var all: [SignedKeyAgreementAdvertisement] { ordered }

    /// How many advertisements the set holds.
    var count: Int { ordered.count }

    /// Whether the set holds nothing.
    var isEmpty: Bool { ordered.isEmpty }

    /// Whether the set is full, so the fold can refuse by name instead of dropping a row.
    var isAtCapacity: Bool { ordered.count >= Self.capacity }

    /// The members whose keys are durably unaddressable, sorted and capped. Grow-only.
    var conflictedFingerprints: [String] { conflicted }

    /// The members the set holds an advertisement for — conflicted ones included, since the row
    /// stays.
    var memberFingerprints: Set<String> { Set(ordered.map(\.memberFingerprint)) }

    /// The advertisement held for `fingerprint`, whatever its conflict state.
    ///
    /// - Parameter fingerprint: The member to look up.
    /// - Returns: The row, or nil.
    func advertisement(for fingerprint: String) -> SignedKeyAgreementAdvertisement? {
        ordered.first { $0.memberFingerprint == fingerprint }
    }

    /// Whether `fingerprint` has been marked unaddressable by a second, different verified key.
    ///
    /// - Parameter fingerprint: The member to check.
    /// - Returns: `true` when the member is conflicted.
    func isConflicted(_ fingerprint: String) -> Bool {
        conflicted.contains(fingerprint)
    }

    /// The key this set will let a mint address `fingerprint` with — nil when there is no row **or**
    /// the member is conflicted.
    ///
    /// Fail closed: a conflicted member is not "resolve it from the earliest row", it is "this
    /// device cannot say which key that member holds".
    ///
    /// - Parameter fingerprint: The destination to resolve.
    /// - Returns: The raw key-agreement public key, or nil.
    func keyAgreementPublicKey(for fingerprint: String) -> Data? {
        guard !isConflicted(fingerprint) else { return nil }
        return advertisement(for: fingerprint)?.keyAgreementPublicKey
    }

    /// The set with a verified advertisement added. An existing, earlier row for the same member
    /// wins.
    ///
    /// Takes a verified value rather than a raw one: that is the compile half of "verification
    /// happens before any fold decision".
    ///
    /// - Parameter verified: The verified advertisement to fold in.
    /// - Returns: The new set.
    func inserting(_ verified: MeshVerifiedKeyAgreementAdvertisement) -> MeshKeyAgreementAdvertisementSet {
        MeshKeyAgreementAdvertisementSet(
            advertisements: ordered + [verified.advertisement],
            conflictedFingerprints: conflicted
        )
    }

    /// The set with the verified advertisement's member marked unaddressable, keeping every row it
    /// already held.
    ///
    /// Also takes a verified value: an UNVERIFIED advertisement must never be able to mark anything
    /// conflicted, or any peer in radio range could permanently un-address any member with a few
    /// forged bytes.
    ///
    /// - Parameter verified: The verified advertisement that disagreed with the held row.
    /// - Returns: The new set.
    func markingConflicted(
        _ verified: MeshVerifiedKeyAgreementAdvertisement
    ) -> MeshKeyAgreementAdvertisementSet {
        MeshKeyAgreementAdvertisementSet(
            advertisements: ordered,
            conflictedFingerprints: conflicted + [verified.advertisement.memberFingerprint]
        )
    }

    /// Deduplicates by member (earliest wins), marks any member that arrived with two different
    /// keys, sorts by the total order and keeps the first ``capacity``.
    private static func normalized(
        _ advertisements: [SignedKeyAgreementAdvertisement],
        _ conflictedFingerprints: [String]
    ) -> (ordered: [SignedKeyAgreementAdvertisement], conflicted: [String]) {
        var earliest: [String: SignedKeyAgreementAdvertisement] = [:]
        var conflicts = Set(conflictedFingerprints)
        // R2: bounded by `maxInputAdvertisements`.
        for advertisement in advertisements.prefix(maxInputAdvertisements) {
            guard let held = earliest[advertisement.memberFingerprint] else {
                earliest[advertisement.memberFingerprint] = advertisement
                continue
            }
            if held.keyAgreementPublicKey != advertisement.keyAgreementPublicKey {
                conflicts.insert(advertisement.memberFingerprint)
            }
            if precedes(advertisement, held) {
                earliest[advertisement.memberFingerprint] = advertisement
            }
        }
        let sorted = earliest.values.sorted(by: precedes)
        return (Array(sorted.prefix(capacity)), Array(conflicts.sorted().prefix(capacity)))
    }

    /// The total order the set sorts and truncates by: earliest instant, then member, then the key
    /// bytes, then the signature bytes.
    ///
    /// Total (never "equal but different") and derived only from the value's own fields, so two
    /// devices holding the same advertisements keep the same rows under the same cap.
    private static func precedes(
        _ lhs: SignedKeyAgreementAdvertisement,
        _ rhs: SignedKeyAgreementAdvertisement
    ) -> Bool {
        if lhs.advertisedAt != rhs.advertisedAt { return lhs.advertisedAt < rhs.advertisedAt }
        if lhs.memberFingerprint != rhs.memberFingerprint {
            return lhs.memberFingerprint < rhs.memberFingerprint
        }
        if lhs.keyAgreementPublicKey != rhs.keyAgreementPublicKey {
            return lhs.keyAgreementPublicKey.lexicographicallyPrecedes(rhs.keyAgreementPublicKey)
        }
        return lhs.signature.lexicographicallyPrecedes(rhs.signature)
    }
}

// MARK: - MeshKeyAdvertisementFoldOutcome

/// What folding one advertisement did, named rather than collapsed into a Bool.
///
/// Every case carries the member it is about, so a caller can audit the outcome without re-deriving
/// it, and ``auditToken`` is the frozen English vocabulary a log reads. "Nothing happened" and "that
/// member is now unaddressable" are completely different situations, and a bare boolean is exactly
/// how they become one indistinguishable "addressing didn't update".
nonisolated enum MeshKeyAdvertisementFoldOutcome: Equatable, Sendable {

    /// A verified advertisement this device did not hold, folded in.
    case folded(String)

    /// The set already holds this member's key — an honest re-advertisement after a reconnect, or a
    /// relayed copy of a row this device folded earlier. Nothing changed and nothing is audited.
    case alreadyHeld(String)

    /// A **second, different** verified key for a member the set already holds one for. Refused,
    /// and the member is marked unaddressable. Fail closed: never pick one.
    case conflicted(String)

    /// The set is full, so a new member's row is refused by name rather than dropped. Unreachable
    /// on an honest mesh (see ``MeshKeyAgreementAdvertisementSet``) and therefore a defect signal.
    case refusedSetFull(String)

    /// The advertisement did not verify. Carries the verifier's own named rejection.
    case refused(MeshMembershipRecordRejection)

    /// The frozen audit token for this outcome, or nil when there is deliberately nothing to log.
    ///
    /// English forever: these are log keys read by a developer and matched by tests, never display
    /// copy.
    var auditToken: String? {
        switch self {
        case .folded: return "mesh.keyAgreement.folded"
        case .alreadyHeld: return nil
        case .conflicted: return "mesh.keyAgreement.conflicted"
        case .refusedSetFull: return "mesh.keyAgreement.setFull"
        case .refused: return "mesh.keyAgreement.rejected"
        }
    }

    /// Whether the outcome refused the advertisement. A refusal never aborts a batch: a relayed set
    /// legitimately holds rows this device refuses.
    var isRefusal: Bool {
        switch self {
        case .folded, .alreadyHeld: return false
        case .conflicted, .refusedSetFull, .refused: return true
        }
    }
}

// MARK: - MeshKeyAdvertisementFoldResult

/// The new set, and what happened to every advertisement in the batch.
///
/// ``changed`` is the write gate: a batch that changed nothing must not spend a seal, which is what
/// keeps a replayed frame free.
nonisolated struct MeshKeyAdvertisementFoldResult: Equatable, Sendable {

    /// The set after the fold. The input set is untouched — this is a value, not a mutation.
    let set: MeshKeyAgreementAdvertisementSet

    /// One outcome per advertisement, in the order they were offered.
    let outcomes: [MeshKeyAdvertisementFoldOutcome]

    /// Whether the fold changed the set at all.
    let changed: Bool
}

// MARK: - MeshKeyAdvertisementFold

/// The one door a key advertisement may enter the set through — pure, clock-free and testable
/// without a rig.
///
/// **The ordering is the security property.** Verification happens BEFORE any conflict decision,
/// never after. An unverified advertisement that could mark a fingerprint conflicted would let any
/// peer on the link permanently un-address any member with a few forged bytes — a trivial denial of
/// service on every mint. A *verified* conflicting advertisement can only be produced by the holder
/// of that member's own signing key, i.e. by that member, and no legitimate provisioning path
/// produces one (see ``SignedKeyAgreementAdvertisement``). The cheap idempotence pre-filter that
/// runs before verification is safe for the same reason it is worth having: it only ever answers
/// "identical to a row this device already verified", which changes nothing.
///
/// **The residual worth naming:** a member can permanently un-address *itself* mesh-wide by signing
/// two different keys and handing one to each of two peers. Self-griefing only — it cannot touch
/// another fingerprint — permanent for the session, and the escape is the same one a departure has:
/// rejoining means a new mesh.
nonisolated enum MeshKeyAdvertisementFold {

    /// Folds a batch of advertisements into a set, verifying each one first.
    ///
    /// Bounded by the set's own input cap, so a hostile batch cannot make this loop do unbounded
    /// work, and a refused row never aborts the batch.
    ///
    /// - Parameters:
    ///   - advertisements: The advertisements offered, in any order.
    ///   - set: The set to fold into; returned untouched in the result when nothing changed.
    ///   - verifier: The ledger's verifier — the trust root every row is checked against.
    /// - Returns: The new set, the per-advertisement outcomes, and whether anything changed.
    static func folding(
        _ advertisements: [SignedKeyAgreementAdvertisement],
        into set: MeshKeyAgreementAdvertisementSet,
        verifiedBy verifier: MeshMembershipRecordVerifier
    ) -> MeshKeyAdvertisementFoldResult {
        var working = set
        var outcomes: [MeshKeyAdvertisementFoldOutcome] = []
        // R2: bounded by `MeshKeyAgreementAdvertisementSet.maxInputAdvertisements`.
        for advertisement in advertisements.prefix(MeshKeyAgreementAdvertisementSet.maxInputAdvertisements) {
            outcomes.append(folding(advertisement, into: &working, verifiedBy: verifier))
        }
        return MeshKeyAdvertisementFoldResult(
            set: working, outcomes: outcomes, changed: working != set
        )
    }

    /// Folds one advertisement: the pre-filter, then verification, then the decision.
    private static func folding(
        _ advertisement: SignedKeyAgreementAdvertisement,
        into set: inout MeshKeyAgreementAdvertisementSet,
        verifiedBy verifier: MeshMembershipRecordVerifier
    ) -> MeshKeyAdvertisementFoldOutcome {
        let fingerprint = advertisement.memberFingerprint
        if let held = set.advertisement(for: fingerprint),
           held.keyAgreementPublicKey == advertisement.keyAgreementPublicKey,
           held.advertisedAt == advertisement.advertisedAt {
            // Identical to a row this device already verified: skipped before spending a
            // verification, which is what bounds the cost of a replayed batch.
            return .alreadyHeld(fingerprint)
        }
        switch verifier.verify(advertisement) {
        case .refused(let rejection):
            return .refused(rejection)
        case .verified(let verified):
            return deciding(verified, into: &set)
        }
    }

    /// The three-way decision, reachable only with a verified advertisement.
    private static func deciding(
        _ verified: MeshVerifiedKeyAgreementAdvertisement,
        into set: inout MeshKeyAgreementAdvertisementSet
    ) -> MeshKeyAdvertisementFoldOutcome {
        let fingerprint = verified.advertisement.memberFingerprint
        guard let held = set.advertisement(for: fingerprint) else {
            guard !set.isAtCapacity else { return .refusedSetFull(fingerprint) }
            set = set.inserting(verified)
            return .folded(fingerprint)
        }
        guard held.keyAgreementPublicKey != verified.advertisement.keyAgreementPublicKey else {
            // Same key, a later instant: an honest re-advertisement. Earliest-wins keeps the held
            // row and nothing is audited.
            return .alreadyHeld(fingerprint)
        }
        set = set.markingConflicted(verified)
        return .conflicted(fingerprint)
    }
}

// MARK: - Signing factory

extension SignedKeyAgreementAdvertisement {

    /// Mints this device's own advertisement, signed by its own identity key.
    ///
    /// `@MainActor` because `IdentityService` is: signing reads the device's long-term key. The
    /// verification counterpart is `nonisolated`, so a received advertisement can be checked off
    /// the main actor exactly as every membership record can.
    ///
    /// The self row verifies through the same door as any other — there is no privileged insert.
    /// Once the local admission is in `ledger.admissions` and the local fingerprint is on the
    /// derived roster, it verifies; before that it is refused `signerNotAdmitted`, which is the
    /// honest answer for a device that cannot yet prove it belongs.
    ///
    /// - Parameters:
    ///   - meshID: The mesh the statement belongs to.
    ///   - identity: The signer, whose key-agreement public key is being advertised.
    ///   - advertisedAt: The signing instant, bound into the signature.
    /// - Returns: The signed advertisement.
    /// - Throws: The identity's signing error; never a trap.
    @MainActor
    static func signed(
        meshID: UUID,
        identity: IdentityService,
        advertisedAt: Date = Date()
    ) throws -> SignedKeyAgreementAdvertisement {
        let unsigned = SignedKeyAgreementAdvertisement(
            meshID: meshID,
            memberFingerprint: identity.localFingerprint,
            keyAgreementPublicKey: identity.localKeyAgreementPublicKey,
            advertisedAt: advertisedAt,
            signature: Data()
        )
        let signature = try identity.sign(
            canonicalBytes(for: unsigned),
            purpose: FernletCryptoPurpose.Signature.meshKeyAgreementV1
        )
        return SignedKeyAgreementAdvertisement(
            meshID: meshID,
            memberFingerprint: unsigned.memberFingerprint,
            keyAgreementPublicKey: unsigned.keyAgreementPublicKey,
            advertisedAt: advertisedAt,
            signature: signature
        )
    }
}
