// MeshRoutedManifest.swift
// ProximityKit/Mesh
//
// Network migration P5 item 1 (plan §11): the origin-signed description of one routed item, and
// the per-recipient content-key wrap that rides inside it.
//
// The manifest is the first routed-content record. It says which mesh and item, what type, the
// ciphertext's hash and size, when it was made and when it stops mattering, WHO it is for, and one
// `MeshRecipientKeyWrap` per destination — and it is signed by the ORIGIN only. Relays and
// custodians forward the exact object inside their own envelope and never re-sign: there is no
// factory here that signs somebody else's manifest, which is what keeps origin authenticity a
// property of the bytes rather than of the path they took.
//
// Two rules from plan §3 are structural here. Invariant §3.3 — content encryption is independent
// of the group key — is why the manifest carries wraps and no key epoch. Plan §10.1 — the
// destination set is the full roster at creation — is why the only mint takes a `MeshDeliveryTarget`,
// whose only initializer takes a `MeshDerivedRoster`, so a connected set or a branch view cannot
// reach the wire by mistake.
//
// What is deliberately NOT here: persistence (item 3, with its wipe row), dispatch and emission
// (item 6), chunks (item 2) and the item seal (item 6 / P6 — item 2 chunks an OPAQUE blob and
// deliberately does not seal), the type-token registry (item 11), receipts (items
// 3/4). `MeshRoutedManifestVerifier` is the receive-side door and `MeshRoutedContentKeyWrapper`
// the crypto; this file is the record, its bounds and its mint.

import FernletCrypto
import Foundation

// MARK: - MeshRoutedManifestFormat

/// Fixed widths and caps of the routed-manifest wire family (network migration P5 item 1, plan §11).
///
/// Every constant is a **bound on untrusted input** as much as a description of honest output: a
/// manifest arrives from a peer, is forwarded verbatim by custodians that never saw it minted, and
/// is checked field by field BEFORE its origin signature is verified (``MeshRoutedManifest/isWellFormed``).
/// Nothing here is a tuning knob — a change to a width is a wire decision, and a change to a cap is
/// a bound decision recorded in the plan.
nonisolated enum MeshRoutedManifestFormat {
    /// Ed25519 signature length. Shared with the membership family.
    static let signatureByteCount = MeshMembershipEventFormat.signatureByteCount
    /// SHA-256 width of ``MeshRoutedManifest/contentHash``.
    static let contentHashByteCount = MeshMembershipEventFormat.digestByteCount
    /// Cap on a fingerprint's UTF-8 length, shared with the membership family.
    static let maxFingerprintLength = MeshMembershipEventFormat.maxFingerprintLength
    /// Cap on ``MeshRoutedManifest/typeToken``'s UTF-8 length. Item 11 gives tokens meaning; this
    /// only bounds them.
    static let maxTypeTokenLength = 64
    /// Most destinations one manifest can name: the roster cap minus the origin itself.
    static let maxDestinations = MeshMembershipBounds.maxRosterMembers - 1
    /// Largest ``MeshRoutedManifest/size`` a manifest may claim — the relay cache's whole budget
    /// (plan §11). Item 9 reuses this constant as its cache-total cap; nothing else defines 256 MiB.
    static let maxContentByteCount: UInt64 = 256 * 1024 * 1024
    /// X25519 public key width (``MeshRecipientKeyWrap/ephemeralPublicKey`` and recipient keys).
    static let keyAgreementPublicKeyByteCount = 32
    /// AES-GCM nonce width (``MeshRecipientKeyWrap/nonce``).
    static let nonceByteCount = 12
    /// ``MeshRecipientKeyWrap/sealedKey`` width: 32-byte content-key ciphertext ‖ 16-byte GCM tag.
    static let sealedKeyByteCount = 48
    /// The random content key's width — 32 bytes, carried as `Data` (AES-256 material; item 6 / P6
    /// builds the `SymmetricKey(data:)` at the seal).
    static let contentKeyByteCount = 32
    /// Plan §11's "20-minute development grace" past the mesh's signed `hardDeadline`. Frozen: it is
    /// bound into every origin signature via ``MeshRoutedManifest/expiresAt``.
    static let developmentGraceSeconds: TimeInterval = 20 * 60
}

// MARK: - MeshRecipientKeyWrap

/// One destination's copy of a routed item's content key: the random key, sealed to that member's
/// handshake-verified X25519 identity (plan §11, invariant §3.3 — "own content key, wrapped per
/// recipient, independent of the group key").
///
/// Lives INSIDE ``MeshRoutedManifest/keyWraps`` and is bound into the origin's signature, so the
/// signature also fixes who can open the item. The wrap is additionally self-binding: its AEAD
/// authenticates the mesh id, item id, origin and ``recipientFingerprint``
/// (``MeshRoutedContentKeyWrapper/additionalData(binding:recipientFingerprint:)``), so a wrap
/// lifted out of one manifest cannot be opened under another, and one relabelled to a different
/// recipient cannot be opened by anyone. Carries no epoch, no group-key reference, no format
/// marker — the `.v1` in the wrap purposes is the version. Never on the wire alone: it has no
/// `PayloadType`. Pure value; nothing reads a clock.
nonisolated struct MeshRecipientKeyWrap: Codable, Equatable, Sendable {
    /// The destination this wrap is for. Equals the same-index entry of ``MeshRoutedManifest/destinations``.
    let recipientFingerprint: String
    /// The origin's per-wrap ephemeral X25519 public key, 32 bytes. Fresh for every wrap.
    let ephemeralPublicKey: Data
    /// AES-GCM nonce, 12 bytes. Fresh for every wrap.
    let nonce: Data
    /// The 32-byte content key under AES-256-GCM, ciphertext ‖ 16-byte tag = 48 bytes.
    let sealedKey: Data

    /// Builds a wrap from already-minted parts. Nothing is clamped: every field is fixed-width and
    /// a wrong width is a refusal (``isWellFormed``), never a repair.
    init(recipientFingerprint: String, ephemeralPublicKey: Data, nonce: Data, sealedKey: Data) {
        self.recipientFingerprint = recipientFingerprint
        self.ephemeralPublicKey = ephemeralPublicKey
        self.nonce = nonce
        self.sealedKey = sealedKey
    }

    /// Whether every field has the width the format fixes. Checked on untrusted bytes before the
    /// manifest's signature is verified and again before any key agreement.
    var isWellFormed: Bool {
        !recipientFingerprint.isEmpty
            && recipientFingerprint.utf8.count <= MeshRoutedManifestFormat.maxFingerprintLength
            && ephemeralPublicKey.count == MeshRoutedManifestFormat.keyAgreementPublicKeyByteCount
            && nonce.count == MeshRoutedManifestFormat.nonceByteCount
            && sealedKey.count == MeshRoutedManifestFormat.sealedKeyByteCount
    }
}

// MARK: - MeshRoutedManifest

/// The origin-signed description of one routed item (network migration P5 item 1, plan §11):
/// which mesh and item, what type, the ciphertext's hash and size, when it was made and when it
/// stops mattering, **who it is for**, and one ``MeshRecipientKeyWrap`` per destination.
///
/// **Signed by the origin only.** Relays and custodians forward this exact object — the same
/// decoded fields, the same `signature` — inside their OWN `FernletIdentityEnvelope`; there is no
/// factory that re-signs someone else's manifest, and ``MeshRoutedManifestVerifier`` resolves the
/// signing key from ``originFingerprint`` via the admission ledger, never from the envelope's sender.
/// A since-departed origin's manifest still verifies: leaving is not a retraction (membership and
/// blocks are ingestion-time view filters, never a signature refusal). A quorum-REMOVED origin's
/// does not (``MeshRoutedManifestRejection/originRemoved``): removal is the mesh's moderation act,
/// and the per-recipient wraps below are untouched by the group-key rotation that enforces it on
/// live traffic, so the verifier consults the removal record set — and only that set.
///
/// **The destination set is immutable and is `MeshDeliveryTarget.destinations`** — the full derived
/// roster at creation minus the origin, in the roster's sorted order — captured once by
/// ``signed(meshID:target:typeToken:contentHash:size:createdAt:hardDeadline:contentKey:recipientKeys:identity:types:)``
/// and never re-derived from the connected set, a branch view, or a bare list. Every destination
/// has exactly one wrap at the same index. ``expiresAt`` is the mesh's signed `hardDeadline` plus
/// ``MeshRoutedManifestFormat/developmentGraceSeconds``, bound into the signature so a custodian can
/// enforce it and cross-checked by every receiver against its own context (D6).
///
/// Carries **no** key epoch, branch id, partition of origin, custody state, receipt or first-seen
/// instant (invariants §3.2/§3.3): anything receiver-local lives in `MeshDeliveryTarget` and the
/// routed store, or the origin's bytes would have to change to record custody. Pure value; every
/// instant is a parameter; `Codable` for the wire only — nothing persists this type in item 1.
nonisolated struct MeshRoutedManifest: Codable, Equatable, Sendable {
    /// The mesh the item belongs to. A manifest for another mesh is a refusal, not a difference.
    let meshID: UUID
    /// The item id: `MeshDeliveryTarget.contentID` and the replay window's per-sender frame id.
    /// The routed store's union key is the PAIR `(originFingerprint, itemID)` — both fields are
    /// inside the signed transcript, so no wire change is needed to key on both — because the
    /// frame is unsealed and any admitted member can mint a manifest under its OWN admitted key
    /// that reuses another origin's `itemID`. A manifest whose `itemID` is already held under a
    /// DIFFERENT origin is refused at ingestion (item 3/6's rule, a `duplicateItemID` refusal at
    /// the store door), never here: this verifier decides on one manifest at a time.
    let itemID: UUID
    /// The author. The verifier resolves its Ed25519 key from the admission ledger.
    let originFingerprint: String
    /// Frozen English routed-type token (item 11's registry gives it meaning; this file bounds it).
    let typeToken: String
    /// ``MeshRoutedContentDigest/contentHash(of:)`` over the **complete sealed blob**:
    /// `SHA-256(lp(Hash.meshRoutedContentV1) ‖ blob)`, 32 bytes. **Never a bare `SHA256.hash`** for
    /// routed bytes (P5 item 2, C12) — a manifest minted with an untagged digest is accepted by
    /// every verifier (this field is opaque here, D2) and then no chunk can ever be minted for it
    /// (`MeshChunkMintError.contentHashMismatch`). The 32 bytes are opaque to this type; the
    /// domain they must be computed under is not.
    let contentHash: Data
    /// Ciphertext byte count, 1 … ``MeshRoutedManifestFormat/maxContentByteCount``.
    let size: UInt64
    /// The origin's claimed creation instant, whole seconds — floored by BOTH doors (the memberwise
    /// initializer and `init(from:)`), so the stored `Date` is always the value the signature
    /// covers. The routed store clamps it against its own first-seen for ordering (plan §10.3,
    /// `Date` arithmetic); nothing in this type decides on it, and no reader ever converts it to
    /// an integer — see ``expiresAt``.
    let createdAt: Date
    /// `hardDeadline + 20 min`, whole seconds, floored by both doors exactly as ``createdAt``: a
    /// custodian re-encoding the wire with a sub-second fraction cannot extend liveness or make a
    /// manifest `!=` the origin's while still verifying. Live iff `now <= expiresAt`
    /// (``isLive(at:)``). Compared only as a `Date`, through ``floored(_:)``: a signed hostile
    /// value (`1e300` decodes into a `Date` under the wire's default strategy) is exactly what
    /// `appendDate` saturates for, and `Int64(_:)` on it would trap AFTER the signature had passed.
    let expiresAt: Date
    /// The immutable destination set, `MeshDeliveryTarget.destinations` verbatim. Clamped to
    /// ``MeshRoutedManifestFormat/maxDestinations`` by BOTH doors (the memberwise initializer and
    /// `init(from:)`, the `MeshEpochHeadsPayload` idiom), so a count above the cap is unrepresentable:
    /// a padded frame is either trimmed back to the origin's exact bytes (padding past a full roster —
    /// the signature then accepts it because nothing signed was touched) or fails the signature
    /// (anything the trim leaves that the origin did not sign). It is never trusted after a trim.
    let destinations: [String]
    /// One wrap per destination, same order. Clamped exactly as ``destinations``.
    let keyWraps: [MeshRecipientKeyWrap]
    /// The origin's Ed25519 signature over ``canonicalBytes(for:)-(MeshRoutedManifest)`` under
    /// `FernletCryptoPurpose.Signature.meshRoutedManifestV1`. Excluded from those bytes.
    let signature: Data

    /// Builds a manifest from already-signed parts, clamping both lists to the destination cap and
    /// flooring both instants to whole seconds through ``floored(_:)`` — so a decoded manifest's
    /// `Date`s are always the signed value, and ``isLive(at:)``, `MeshFrameReplayWindow` and `==`
    /// all read what the origin signed rather than what a relay re-encoded.
    init(
        meshID: UUID,
        itemID: UUID,
        originFingerprint: String,
        typeToken: String,
        contentHash: Data,
        size: UInt64,
        createdAt: Date,
        expiresAt: Date,
        destinations: [String],
        keyWraps: [MeshRecipientKeyWrap],
        signature: Data
    ) {
        self.meshID = meshID
        self.itemID = itemID
        self.originFingerprint = originFingerprint
        self.typeToken = typeToken
        self.contentHash = contentHash
        self.size = size
        self.createdAt = Self.floored(createdAt)
        self.expiresAt = Self.floored(expiresAt)
        self.destinations = Array(destinations.prefix(MeshRoutedManifestFormat.maxDestinations))
        self.keyWraps = Array(keyWraps.prefix(MeshRoutedManifestFormat.maxDestinations))
        self.signature = signature
    }

    /// Decodes with the same clamp and the same floor the memberwise initializer applies (the
    /// `MeshEpochHeadsPayload` idiom): it routes through that initializer, so the two doors cannot drift.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            meshID: try container.decode(UUID.self, forKey: .meshID),
            itemID: try container.decode(UUID.self, forKey: .itemID),
            originFingerprint: try container.decode(String.self, forKey: .originFingerprint),
            typeToken: try container.decode(String.self, forKey: .typeToken),
            contentHash: try container.decode(Data.self, forKey: .contentHash),
            size: try container.decode(UInt64.self, forKey: .size),
            createdAt: try container.decode(Date.self, forKey: .createdAt),
            expiresAt: try container.decode(Date.self, forKey: .expiresAt),
            destinations: try container.decode([String].self, forKey: .destinations),
            keyWraps: try container.decode([MeshRecipientKeyWrap].self, forKey: .keyWraps),
            signature: try container.decode(Data.self, forKey: .signature)
        )
    }

    /// Whether every field has the width or count the format fixes. Checked on untrusted bytes
    /// before the signature is verified. Cross-field consistency (wrap ↔ destination alignment,
    /// distinctness, origin ∉ destinations, expiry) is the verifier's, after the signature.
    var isWellFormed: Bool {
        hasWellFormedScalars && hasWellFormedLists
    }

    /// The fixed-width and bounded-scalar half of ``isWellFormed``.
    private var hasWellFormedScalars: Bool {
        signature.count == MeshRoutedManifestFormat.signatureByteCount
            && contentHash.count == MeshRoutedManifestFormat.contentHashByteCount
            && !typeToken.isEmpty
            && typeToken.utf8.count <= MeshRoutedManifestFormat.maxTypeTokenLength
            && !originFingerprint.isEmpty
            && originFingerprint.utf8.count <= MeshRoutedManifestFormat.maxFingerprintLength
            && size >= 1
            && size <= MeshRoutedManifestFormat.maxContentByteCount
    }

    /// The list half of ``isWellFormed``. `destinations.count <= maxDestinations` is unreachable
    /// after either door's clamp and is kept so the predicate states the whole bound in one place.
    private var hasWellFormedLists: Bool {
        !destinations.isEmpty
            && destinations.count <= MeshRoutedManifestFormat.maxDestinations
            && destinations.allSatisfy {
                !$0.isEmpty && $0.utf8.count <= MeshRoutedManifestFormat.maxFingerprintLength
            }
            && keyWraps.count == destinations.count
            && keyWraps.allSatisfy(\.isWellFormed)
    }

    /// Liveness under an injected clock: `now <= expiresAt`, the same predicate as
    /// `MeshFrameReplayWindow.admit`. Never reads `Date()`.
    func isLive(at now: Date) -> Bool {
        now <= expiresAt
    }

    /// The one formula for ``expiresAt``: `hardDeadline` floored to whole seconds plus the grace.
    /// Used by the mint and by the verifier's cross-check, so the two cannot drift.
    static func expiry(afterHardDeadline hardDeadline: Date) -> Date {
        Date(
            timeIntervalSince1970: floored(hardDeadline).timeIntervalSince1970
                + MeshRoutedManifestFormat.developmentGraceSeconds
        )
    }

    /// The one finite-guarded floor the two initializers, the mint and the verifier all use.
    /// Returns a `Date`, never an integer, so no input — finite, infinite or NaN — can trap it; a
    /// non-finite input maps to the epoch, mirroring `CanonicalByteWriter.appendDate`'s saturation.
    static func floored(_ date: Date) -> Date {
        let seconds = date.timeIntervalSince1970.rounded(.down)
        guard seconds.isFinite else { return Date(timeIntervalSince1970: 0) }
        return Date(timeIntervalSince1970: seconds)
    }
}

// MARK: - MeshRoutedManifestPayload

/// The wire frame for a ``MeshRoutedManifest`` — `PayloadType.meshRoutedManifest`, signed and
/// UNSEALED like every membership record so a custodian can re-broadcast it verbatim; the
/// per-recipient wraps are the confidentiality, not the envelope. Carries no second claim about
/// the origin: the record already says, under the origin's own signature. Registered in item 1,
/// dispatched from item 6 (P4's "built, unwired" shape).
nonisolated struct MeshRoutedManifestPayload: Codable, Equatable, Sendable {
    /// The origin's signed record.
    let manifest: MeshRoutedManifest

    /// Wraps a manifest for the wire.
    init(manifest: MeshRoutedManifest) {
        self.manifest = manifest
    }
}

// MARK: - MeshRoutedManifestMintError

/// Why ``MeshRoutedManifest/signed(meshID:target:typeToken:contentHash:size:createdAt:hardDeadline:contentKey:recipientKeys:identity:types:)``
/// refused to mint. Thrown, never returned as `nil`, and never silent: a manifest that could not
/// be built for the WHOLE destination set is not built at all (destination immutability, plan
/// §10.1). Not `LocalizedError` — ``diagnosticDescription`` is frozen English for the audit log and
/// is never shown as user copy.
nonisolated enum MeshRoutedManifestMintError: Error, Equatable, Sendable {
    /// The target names nobody (a roster of one). There is nothing to route.
    case noDestinations
    /// The target names more destinations than the roster cap allows. Unreachable through
    /// `MeshDeliveryTarget`'s only initializer — `MeshDerivedRoster` caps members at
    /// `MeshMembershipBounds.maxRosterMembers` (8), so a target names at most 7 — and kept so the
    /// mint states the whole bound in one place rather than inheriting it from a type it does not own.
    case tooManyDestinations(count: Int)
    /// The target names the signing identity itself; a target is always built with `self` removed.
    case originIsADestination
    /// `typeToken` is empty or longer than ``MeshRoutedManifestFormat/maxTypeTokenLength``.
    case invalidTypeToken
    /// `contentHash` is not 32 bytes.
    case invalidContentHash
    /// `size` is zero or above ``MeshRoutedManifestFormat/maxContentByteCount``.
    case invalidSize
    /// The content key is not 32 bytes.
    case invalidContentKey
    /// No handshake-verified X25519 key was supplied for this destination (D1).
    case missingRecipientKey(fingerprint: String)
    /// `size` is above the cap the type's own registry row declares (P5 item 11). Distinct from
    /// ``invalidSize``, which is the wire bound every type shares: this one names a POLICY the
    /// registry set for one type, and in increment 1 no row can raise it because every row's cap
    /// equals the wire bound.
    case sizeExceedsTypeCap(token: String)
    /// The type's registry row declares a destination semantics this build cannot mint — today only
    /// ``MeshRoutedDestinationSemantics/singleRecipient``, which needs a `MeshDeliveryTarget`
    /// initializer P4 deliberately withheld. Registerable, unmintable, refused by name.
    case unsupportedDestinationSemantics(token: String)

    /// Frozen English for the diagnostic surface. Never shown as user copy.
    var diagnosticDescription: String {
        switch self {
        case .noDestinations: return "The delivery target names no destinations."
        case .tooManyDestinations(let count):
            return "The delivery target names \(count) destinations, above the roster cap."
        case .originIsADestination: return "The delivery target names the origin itself."
        case .invalidTypeToken: return "The routed type token is empty or too long."
        case .invalidContentHash: return "The content hash is not 32 bytes."
        case .invalidSize: return "The content size is zero or above the relay cache cap."
        case .invalidContentKey: return "The content key is not 32 bytes."
        case .missingRecipientKey(let fingerprint):
            return "No handshake-verified key-agreement key for destination \(fingerprint)."
        case .sizeExceedsTypeCap(let token):
            return "The content size is above the declared cap for routed type \(token)."
        case .unsupportedDestinationSemantics(let token):
            return "Routed type \(token) declares a destination semantics this build cannot mint."
        }
    }
}

// MARK: - Signing factory

extension MeshRoutedManifest {

    /// Mints an origin-signed manifest for `target`'s destination set.
    ///
    /// The destination set is `target.destinations` verbatim — the full derived roster at the
    /// target's creation minus this device — and is never derived from who is connected. One
    /// ``MeshRecipientKeyWrap`` is minted per destination from `recipientKeys[fingerprint]`; a
    /// missing key refuses the whole mint (D1). `createdAt` and `expiresAt` are floored to whole
    /// seconds BEFORE signing so the signed bytes and the wire bytes agree.
    ///
    /// - Parameters:
    ///   - meshID: The session's mesh id.
    ///   - target: The delivery target built from the derived roster; `target.contentID` is the item id.
    ///   - typeToken: Frozen English routed-type token.
    ///   - contentHash: ``MeshRoutedContentDigest/contentHash(of:)`` over the complete sealed blob
    ///     — `SHA-256(lp(Hash.meshRoutedContentV1) ‖ blob)`, 32 bytes. Never a bare `SHA256.hash`
    ///     (P5 item 2, C12): unchecked here, and a mismatch surfaces only at the chunk mint.
    ///   - size: Ciphertext byte count.
    ///   - createdAt: The origin's creation instant, injected — nothing here reads a clock.
    ///   - hardDeadline: The session's signed ceiling (`MeshSessionContext.hardDeadline`).
    ///   - contentKey: The random 32-byte content key (``MeshRoutedContentKeyWrapper/makeContentKey()``),
    ///     as `Data` so no pointer API is needed to wrap it (Power of 10 R9); item 6 / P6 builds
    ///     the `SymmetricKey(data:)` at the seal — item 2 chunks an opaque blob and never sees a key.
    ///   - recipientKeys: Handshake-verified X25519 public keys by destination fingerprint.
    ///   - identity: The origin. Its fingerprint becomes ``originFingerprint``.
    ///   - types: The routed type registry this mint declares against (P5 item 11). A REGISTERED
    ///     token's row supplies the per-type size cap, the destination semantics the mint is allowed
    ///     to use, and the expiry rule. An UNREGISTERED token still mints, under the shared wire
    ///     bounds — a documented asymmetry: acceptance is a receiver-side statement (D13), so an
    ///     unregistered item is refused at every receiver door rather than at its author's. The
    ///     default is written as `MeshRoutedTypeRegistry.increment1` rather than `.increment1` on
    ///     purpose: the one-registry wall's member scanner reads the spelled-out form only, so a
    ///     leading dot here would let a second registry value reach a value position unseen.
    /// - Throws: ``MeshRoutedManifestMintError``, ``MeshRoutedKeyWrapError``, or the identity's
    ///   signing error. Never a trap.
    @MainActor
    static func signed(
        meshID: UUID,
        target: MeshDeliveryTarget,
        typeToken: String,
        contentHash: Data,
        size: UInt64,
        createdAt: Date,
        hardDeadline: Date,
        contentKey: Data,
        recipientKeys: [String: Data],
        identity: IdentityService,
        types: MeshRoutedTypeRegistry = MeshRoutedTypeRegistry.increment1
    ) throws -> MeshRoutedManifest {
        let origin = identity.localFingerprint
        try validated(
            target: target, typeToken: typeToken, contentHash: contentHash, size: size,
            contentKey: contentKey, originFingerprint: origin, types: types
        )
        let rule = types.entry(for: typeToken)?.expiry ?? .meshHardDeadlinePlusGrace
        let binding = MeshRoutedWrapBinding(meshID: meshID, itemID: target.contentID, originFingerprint: origin)
        let wraps = try mintWraps(
            for: target.destinations, binding: binding, contentKey: contentKey, recipientKeys: recipientKeys
        )
        let unsigned = MeshRoutedManifest(
            meshID: meshID, itemID: target.contentID, originFingerprint: origin, typeToken: typeToken,
            contentHash: contentHash, size: size, createdAt: floored(createdAt),
            expiresAt: rule.expiry(afterHardDeadline: hardDeadline), destinations: target.destinations,
            keyWraps: wraps, signature: Data()
        )
        let signature = try identity.sign(
            canonicalBytes(for: unsigned),
            purpose: FernletCryptoPurpose.Signature.meshRoutedManifestV1
        )
        return MeshRoutedManifest(
            meshID: unsigned.meshID, itemID: unsigned.itemID, originFingerprint: unsigned.originFingerprint,
            typeToken: unsigned.typeToken, contentHash: unsigned.contentHash, size: unsigned.size,
            createdAt: unsigned.createdAt, expiresAt: unsigned.expiresAt, destinations: unsigned.destinations,
            keyWraps: unsigned.keyWraps, signature: signature
        )
    }

    /// The mint's guard chain, in ``MeshRoutedManifestMintError``'s case order. Every refusal is
    /// named before a single wrap is minted.
    ///
    /// The two registry guards run **last**, after the shared wire bounds, so a per-type policy
    /// refusal is never confused with a shape refusal. They are skipped entirely for a token no row
    /// registers (D-11.5): the mint does not enforce acceptance, receivers do.
    private static func validated(
        target: MeshDeliveryTarget,
        typeToken: String,
        contentHash: Data,
        size: UInt64,
        contentKey: Data,
        originFingerprint: String,
        types: MeshRoutedTypeRegistry
    ) throws {
        guard target.destinationCount > 0 else { throw MeshRoutedManifestMintError.noDestinations }
        guard target.destinationCount <= MeshRoutedManifestFormat.maxDestinations else {
            throw MeshRoutedManifestMintError.tooManyDestinations(count: target.destinationCount)
        }
        guard !target.names(originFingerprint) else { throw MeshRoutedManifestMintError.originIsADestination }
        guard !typeToken.isEmpty, typeToken.utf8.count <= MeshRoutedManifestFormat.maxTypeTokenLength else {
            throw MeshRoutedManifestMintError.invalidTypeToken
        }
        guard contentHash.count == MeshRoutedManifestFormat.contentHashByteCount else {
            throw MeshRoutedManifestMintError.invalidContentHash
        }
        guard size >= 1, size <= MeshRoutedManifestFormat.maxContentByteCount else {
            throw MeshRoutedManifestMintError.invalidSize
        }
        guard contentKey.count == MeshRoutedManifestFormat.contentKeyByteCount else {
            throw MeshRoutedManifestMintError.invalidContentKey
        }
        if let entry = types.entry(for: typeToken) {
            guard size <= entry.maxItemByteCount else {
                throw MeshRoutedManifestMintError.sizeExceedsTypeCap(token: typeToken)
            }
            guard entry.destinations == .fullRosterAtCreation else {
                throw MeshRoutedManifestMintError.unsupportedDestinationSemantics(token: typeToken)
            }
        }
    }

    /// One wrap per destination, in destination order. Bounded by the destination cap; a
    /// destination with no handshake-verified key refuses the whole mint by name (D1).
    private static func mintWraps(
        for destinations: [String],
        binding: MeshRoutedWrapBinding,
        contentKey: Data,
        recipientKeys: [String: Data]
    ) throws -> [MeshRecipientKeyWrap] {
        var wraps: [MeshRecipientKeyWrap] = []
        wraps.reserveCapacity(destinations.count)
        for fingerprint in destinations {
            guard let key = recipientKeys[fingerprint] else {
                throw MeshRoutedManifestMintError.missingRecipientKey(fingerprint: fingerprint)
            }
            wraps.append(try MeshRoutedContentKeyWrapper.wrap(
                contentKey: contentKey,
                recipientFingerprint: fingerprint,
                recipientKeyAgreementPublicKey: key,
                binding: binding
            ))
        }
        return wraps
    }
}
