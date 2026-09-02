// MeshEpochRef.swift
// ProximityKit/Mesh
//
// P3 item 4 (plan §8.4): the epoch model that survives divergence. A Lamport-style counter, a
// per-minted-epoch identifier, and the fingerprint of the coordinator that minted it — canonical,
// deterministic, and short enough to ride the `epochRef` string field the signed introduction
// already carries. The field's wire framing does not change; only the vocabulary written into it
// stops being a bare decimal counter.

import Foundation
import CryptoKit

// MARK: - MeshEpochBounds

/// Every bound plan §8.4 puts on the epoch model, in one place.
///
/// The numbers are the plan's own: "≤ 24 timer rotations per branch per ceiling × roster ≤ 8
/// branches → counter cap 4096 is generous; keyring 4". They are stated here rather than at their
/// three use sites so a reader can check the table against the code without opening three files.
nonisolated enum MeshEpochBounds {

    /// Highest counter a mesh may ever mint (plan §8.4).
    ///
    /// **A counter at the cap does not trap.** ``MeshEpochRef/minted(counter:coordinatorFingerprint:meshID:)``
    /// and ``MeshEpochRef/successor(coordinatorFingerprint:meshID:)`` return `nil`, which the
    /// caller reads as *rotation refused*: a mesh that has exhausted its counters cannot rotate,
    /// and a session that cannot rotate must terminate at its next membership change rather than
    /// keep serving a key it can no longer retire. Reaching it takes 4096 rotations inside one
    /// six-hour ceiling, i.e. more than 11 per minute across every branch — it is a bound on
    /// hostile input, not a schedule.
    static let counterCap: UInt32 = 4_096

    /// Predecessor epochs the keyring retains beside the current one (plan §8.4: "current + ≤ 3").
    static let keyringPredecessors = 3

    /// How long a superseded epoch's key stays usable for decryption (plan §8.4: "≤ 5 minutes
    /// after supersession"). Covers control frames already in flight when a rotation lands.
    static let predecessorGraceSeconds: TimeInterval = 300

    /// Hex characters in the canonical `epochID` half — 16 bytes, lowercase, no dashes.
    static let epochIDHexLength = 32

    /// Hex characters in a canonical fingerprint (`IdentityService.fingerprint(of:)`'s width).
    static let fingerprintHexLength = 16

    /// Longest canonical string form: four counter digits, two separators, the two hex halves.
    /// Must stay ≤ `MeshChannelIntroductionFormat.maxEpochRefLength`; a test pins that.
    static let canonicalStringMaxLength = 4 + 1 + epochIDHexLength + 1 + fingerprintHexLength

    /// The frozen English domain string mixed into a derived ``MeshEpochRef/epochID``. A persisted
    /// and on-wire derivation input, never display copy — it never localizes.
    static let derivationDomain = "fernlet.mesh.epoch.v1"

    /// The canonical separator between the three halves of the string form. Chosen because it
    /// appears in neither a decimal counter nor lowercase hex, so parsing is unambiguous.
    static let canonicalSeparator: Character = "."
}

// MARK: - MeshEpochRefParseError

/// Why a string was refused as a ``MeshEpochRef``.
///
/// Named rather than collapsed into `nil` for the reason every other refusal in this subsystem is:
/// "the peer sent an epoch reference from a newer build" and "the peer sent junk" are different
/// diagnoses, and a bare optional makes them the same line in a bug report.
nonisolated enum MeshEpochRefParseError: Error, Equatable, Sendable {
    /// The string is not exactly three separator-joined fields.
    case wrongFieldCount
    /// The counter half is not a canonical decimal (empty, non-digit, or leading zero).
    case malformedCounter
    /// The counter parses but exceeds ``MeshEpochBounds/counterCap``.
    case counterOverCap(UInt32)
    /// The epoch-id half is not 32 lowercase hex characters, or does not form a UUID.
    case malformedEpochID
    /// The coordinator half is not a canonical 16-character lowercase hex fingerprint.
    case malformedCoordinatorFingerprint
}

// MARK: - MeshEpochRef

/// One membership epoch: which rotation it is, which minting it was, and who minted it (plan §8.4).
///
/// ## Why three fields and not one counter
///
/// A bare counter cannot tell two *divergent* epochs apart. Two partitions that each rotate while
/// split both mint counter `n + 1`, and under the placeholder string form both rendered `"n+1"` —
/// so two devices holding different group keys agreed they were on the same epoch. ``epochID``
/// and ``coordinatorFingerprint`` are what make that state **representable**: the two refs are
/// distinct values, both may sit in `MeshSessionContext.epochHeads`, and neither is "wrong". They
/// coexist until a merge mints a strictly greater successor (P4, plan §10.3) — coexistence is a
/// state, not an error.
///
/// ## The identifier is derived, not drawn
///
/// Plan §8.4 sketches `epochID` as a fresh `UUID`. A drawn UUID would have to cross the wire before
/// two members could agree on it, which is a rotation-payload change (item 5). Deriving it instead
/// from `domain ‖ meshID ‖ counter ‖ coordinatorFingerprint` gives the same property with no wire
/// change: every member of one branch computes the *same* id, and two branches differ because their
/// deterministic coordinators — the lowest fingerprint of each partition's roster — cannot be the
/// same member. It is a 128-bit name-based identifier carried in `UUID`'s shape, deliberately NOT
/// an RFC 4122 version-tagged UUID; nothing reads its version bits.
///
/// ## Canonical string form
///
/// `"<counter>.<32 lowercase hex>.<16 lowercase hex>"` — at most
/// ``MeshEpochBounds/canonicalStringMaxLength`` characters, which is what lets a real epoch ref be
/// written into the introduction's existing `epochRef` field (cap 96) without moving a single byte
/// of wire framing. The form is canonical in both directions: no leading zeros, no uppercase, so
/// `MeshEpochRef(canonical:)` ∘ `canonicalString` is the identity and two devices that hold the
/// same epoch produce byte-identical strings to sign over.
///
/// ## Concurrency
///
/// `nonisolated` and `Sendable`: a pure value, computed and compared on whichever actor holds it.
nonisolated struct MeshEpochRef: Codable, Hashable, Sendable {

    /// The Lamport-style rotation counter. Minting is `max(seen) + 1`, capped at
    /// ``MeshEpochBounds/counterCap``.
    let counter: UInt32

    /// The identifier of this particular minting — the half that distinguishes two divergent
    /// epochs sharing a counter. See the type's discussion for why it is derived.
    let epochID: UUID

    /// The 16-character lowercase hex fingerprint of the member that minted this epoch: the
    /// deterministic coordinator (lowest fingerprint) of the roster it presented (plan §8.4).
    let coordinatorFingerprint: String

    /// Builds a ref from **already-validated** parts.
    ///
    /// The three doors that take untrusted input — ``minted(counter:coordinatorFingerprint:meshID:)``,
    /// ``init(canonical:)`` and `init(from:)` — each validate and then call this one, so a
    /// `MeshEpochRef` built through them is in bounds and round-trips through its canonical string.
    /// This initializer itself checks nothing: call it only with parts you have already checked
    /// (module-internal, so nothing outside ProximityKit can reach it at all).
    init(counter: UInt32, epochID: UUID, coordinatorFingerprint: String) {
        self.counter = counter
        self.epochID = epochID
        self.coordinatorFingerprint = coordinatorFingerprint
    }

    /// Mints the ref for one epoch of one mesh, deriving ``epochID`` deterministically.
    ///
    /// - Parameters:
    ///   - counter: The Lamport counter this epoch takes.
    ///   - coordinatorFingerprint: The minting coordinator's canonical 16-hex fingerprint.
    ///   - meshID: The mesh, so two meshes at the same counter never share an epoch id.
    /// - Returns: `nil` when the counter is over ``MeshEpochBounds/counterCap`` or the fingerprint
    ///   is not canonical — **rotation refused**, never a trap.
    static func minted(counter: UInt32, coordinatorFingerprint: String, meshID: UUID) -> MeshEpochRef? {
        guard counter <= MeshEpochBounds.counterCap,
              isCanonicalFingerprint(coordinatorFingerprint),
              let id = derivedEpochID(
                  counter: counter, coordinatorFingerprint: coordinatorFingerprint, meshID: meshID
              ) else { return nil }
        return MeshEpochRef(counter: counter, epochID: id, coordinatorFingerprint: coordinatorFingerprint)
    }

    /// Mints `counter + 1` for the same mesh under a (possibly different) coordinator.
    ///
    /// - Returns: `nil` at the cap — the documented "rotation refused" answer of
    ///   ``MeshEpochBounds/counterCap``.
    func successor(coordinatorFingerprint: String, meshID: UUID) -> MeshEpochRef? {
        guard counter < MeshEpochBounds.counterCap else { return nil }
        return Self.minted(
            counter: counter + 1, coordinatorFingerprint: coordinatorFingerprint, meshID: meshID
        )
    }

    /// The canonical string form — the exact bytes written into the introduction's `epochRef`
    /// field and into a persisted epoch head.
    var canonicalString: String {
        let id = epochID.uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        return "\(counter)\(MeshEpochBounds.canonicalSeparator)\(id)"
            + "\(MeshEpochBounds.canonicalSeparator)\(coordinatorFingerprint)"
    }

    /// Parses a canonical string, refusing anything that is not exactly the form
    /// ``canonicalString`` produces.
    ///
    /// Strict by design: this runs on untrusted bytes from an unauthenticated peer, and a lenient
    /// parser is how "the peer sent an epoch this build does not understand" becomes "the peer is
    /// on our epoch".
    init(canonical string: String) throws {
        let fields = string.split(
            separator: MeshEpochBounds.canonicalSeparator, omittingEmptySubsequences: false
        )
        guard fields.count == 3 else { throw MeshEpochRefParseError.wrongFieldCount }
        let parsedCounter = try Self.parseCounter(String(fields[0]))
        guard let id = Self.parseEpochID(String(fields[1])) else {
            throw MeshEpochRefParseError.malformedEpochID
        }
        let fingerprint = String(fields[2])
        guard Self.isCanonicalFingerprint(fingerprint) else {
            throw MeshEpochRefParseError.malformedCoordinatorFingerprint
        }
        self.init(counter: parsedCounter, epochID: id, coordinatorFingerprint: fingerprint)
    }

    /// Whether a string is a canonical ref. The one question the transport's width checks ask.
    static func isCanonical(_ string: String) -> Bool {
        (try? MeshEpochRef(canonical: string)) != nil
    }

    // MARK: Codable — one canonical string, so at rest and on the wire read the same

    /// Decodes from the canonical string form, validating every bound before the value exists.
    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        try self.init(canonical: container.decode(String.self))
    }

    /// Encodes as the canonical string form.
    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(canonicalString)
    }
}

// MARK: - MeshEpochRef parsing helpers

nonisolated extension MeshEpochRef {

    /// Parses the counter half: canonical decimal only — no sign, no padding, no leading zero
    /// (except `"0"` itself), so one counter has exactly one spelling.
    private static func parseCounter(_ field: String) throws -> UInt32 {
        guard !field.isEmpty, field.count <= 4, field.allSatisfy(\.isNumber),
              field == "0" || field.first != "0",
              let value = UInt32(field) else {
            throw MeshEpochRefParseError.malformedCounter
        }
        guard value <= MeshEpochBounds.counterCap else {
            throw MeshEpochRefParseError.counterOverCap(value)
        }
        return value
    }

    /// Rebuilds a `UUID` from 32 lowercase hex characters, or nil when the field is not that.
    private static func parseEpochID(_ field: String) -> UUID? {
        guard field.count == MeshEpochBounds.epochIDHexLength, isLowercaseHex(field) else {
            return nil
        }
        let characters = Array(field)
        var dashed = ""
        for (index, character) in characters.enumerated() {
            if index == 8 || index == 12 || index == 16 || index == 20 { dashed.append("-") }
            dashed.append(character)
        }
        return UUID(uuidString: dashed)
    }

    /// Whether a fingerprint has the canonical width and alphabet `IdentityService` produces.
    static func isCanonicalFingerprint(_ fingerprint: String) -> Bool {
        fingerprint.count == MeshEpochBounds.fingerprintHexLength && isLowercaseHex(fingerprint)
    }

    /// Whether every character is `0`–`9` or `a`–`f`. Bounded by the caller's length check.
    private static func isLowercaseHex(_ string: String) -> Bool {
        string.allSatisfy { $0.isNumber || ("a"..."f").contains($0) }
    }

    /// Derives the epoch id from the three values every member of a branch already agrees on.
    ///
    /// SHA-256 over `domain ‖ meshID ‖ counter (big-endian) ‖ coordinator fingerprint`, truncated
    /// to 16 bytes. Not a key and not a signature: it names an epoch, so it registers no crypto
    /// purpose. The domain string is what keeps it from colliding with any other digest this app
    /// computes over the same inputs.
    private static func derivedEpochID(
        counter: UInt32,
        coordinatorFingerprint: String,
        meshID: UUID
    ) -> UUID? {
        var input = Data(MeshEpochBounds.derivationDomain.utf8)
        input.append(Data(meshID.uuidString.lowercased().utf8))
        for shift in stride(from: 24, through: 0, by: -8) {
            input.append(UInt8(truncatingIfNeeded: counter >> UInt32(shift)))
        }
        input.append(Data(coordinatorFingerprint.utf8))
        let digest = SHA256.hash(data: input)
        let hex = digest.prefix(16).map { String(format: "%02x", $0) }.joined()
        return parseEpochID(hex)
    }
}

// MARK: - MeshEpochRefOrder

/// The total order epoch heads are sorted and truncated by.
///
/// Total by construction — counter, then coordinator, then the epoch id's string form — so two
/// devices holding the same set of heads keep the same ones when the cap bites. Note what it is
/// **not**: an ordering of "better" epochs. Two same-counter heads are ordered here only so the
/// list is deterministic; ``MeshEpochAcceptance`` is what decides whether one supersedes the other.
nonisolated enum MeshEpochRefOrder {

    /// Whether `lhs` sorts before `rhs`.
    static func precedes(_ lhs: MeshEpochRef, _ rhs: MeshEpochRef) -> Bool {
        if lhs.counter != rhs.counter { return lhs.counter < rhs.counter }
        if lhs.coordinatorFingerprint != rhs.coordinatorFingerprint {
            return lhs.coordinatorFingerprint < rhs.coordinatorFingerprint
        }
        return lhs.epochID.uuidString < rhs.epochID.uuidString
    }
}
