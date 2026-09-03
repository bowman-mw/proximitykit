// CanonicalSignatureSerializer.swift
// Fernlet/Proximity
//
// Deterministic, cross-platform-stable canonical byte serializer for Ed25519 signing (WI-6).
//
// WHY THIS EXISTS
// ---------------
// The original canonical encoder was a Foundation `JSONEncoder` configured with `.sortedKeys`.
// `.sortedKeys` sorts keys by UTF-16 code units, and Foundation makes NO guarantee that the byte
// encoding of numbers / strings is identical across Foundation versions or a non-Apple stack (the
// planned Android port — see Docs/cross-platform-direction). Any divergence in the canonical bytes
// produces a `signatureInvalid` for an envelope/token that was legitimately signed. That is a
// latent interoperability fault, not a confidentiality leak, but it must be closed before any
// cross-stack signing exists.
//
// This serializer is a positional, length-prefixed BINARY format with no key names, no
// number/locale formatting, and a fixed integer/date encoding. It is trivially reproducible
// byte-for-byte in Swift and Kotlin/Java. Ed25519 signs arbitrary bytes, so the signing input does
// not need to be (and is not) JSON.
//
// FORMAT (canonical v2) — all integers big-endian:
//   * A leading length-prefixed domain tag distinguishes the two signed types (identity envelope vs
//     mesh admission token), so a signature computed over one type can never validate over the other.
//   * Fixed-width fields: Int64 (8 B, two's complement), UUID (16 raw bytes, network order),
//     bool / enum-discriminant (1 B).
//   * Variable-width fields: every `Data` / `String` is a UInt64 (8 B) length prefix followed by the
//     raw bytes (UTF-8 for `String`).
//   * Optionals: a single presence byte (0 = absent, 1 = present); if present, the value follows.
//   * Dates: Int64 whole SECONDS since 1970-01-01T00:00:00Z, floored. Whole-second granularity is
//     deliberate — envelopes transit as JSON and `verify` re-derives canonical bytes from the
//     DECODED date, so the canonical granularity must be no finer than what survives the wire. It
//     matches the legacy `.iso8601` precision exactly, so sign-time and verify-time bytes always
//     agree. The seconds→Int64 conversion saturates (never traps) because `verify` runs over
//     untrusted, attacker-controlled bytes.
//   * Maps (`[String: String]`): a UInt64 entry count, then entries sorted by the RAW UTF-8 bytes of
//     the key (byte-lexicographic — unambiguous and identical on every stack, unlike `.sortedKeys`).
//
// This is signing INPUT only. It is never the wire format, never persisted, never transmitted.
// The wire format remains the types' synthesized `Codable` conformance (unchanged).

import Foundation
import FernletCrypto
import FernletDomainModel

// WI-9: every declaration in this file is `nonisolated`. ProximityKit sets
// `.defaultIsolation(MainActor.self)`, which would otherwise MainActor-isolate this pure signing-byte
// serializer. The canonical bytes are derived from value-type fields with no actor state, so signing
// and signature verification must be runnable from any isolation domain — `MeshAdmissionToken.verify`
// is `nonisolated` and calls straight into `canonicalBytes`/`legacyCanonicalBytes` below.

// MARK: - Canonical byte writer

/// Append-only binary writer for canonical signing bytes. The format is positional and
/// length-prefixed: the field order in the `canonicalBytes(for:)` functions below IS the schema.
nonisolated struct CanonicalByteWriter {
    private(set) var bytes = Data()

    mutating func appendByte(_ value: UInt8) {
        bytes.append(value)
    }

    /// 8-byte big-endian. Endianness is pinned by `bigEndian`, so the on-wire bytes are identical
    /// regardless of host byte order.
    mutating func appendUInt64(_ value: UInt64) {
        // Pure-Swift shift-out (R9: no pointer seam). Byte-identical to the previous
        // `withUnsafeBytes(of: value.bigEndian)`: most-significant byte first.
        for shift in stride(from: 56, through: 0, by: -8) {
            bytes.append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
        }
    }

    /// 8-byte big-endian two's-complement.
    mutating func appendInt64(_ value: Int64) {
        appendUInt64(UInt64(bitPattern: value))
    }

    /// UInt64 big-endian length prefix followed by the raw bytes.
    mutating func appendLengthPrefixed(_ data: Data) {
        appendUInt64(UInt64(data.count))
        bytes.append(data)
    }

    /// Length-prefixed UTF-8.
    mutating func appendString(_ string: String) {
        appendLengthPrefixed(Data(string.utf8))
    }

    /// 16 raw bytes in network order (no length prefix — a UUID is always 16 bytes).
    mutating func appendUUID(_ uuid: UUID) {
        // Same 16 network-order bytes as the previous `withUnsafeBytes(of: uuid.uuid)`, spelled
        // without a pointer seam (R9). `uuid.uuid` is a 16-tuple in network order by definition.
        let raw = uuid.uuid
        bytes.append(contentsOf: [
            raw.0, raw.1, raw.2, raw.3, raw.4, raw.5, raw.6, raw.7,
            raw.8, raw.9, raw.10, raw.11, raw.12, raw.13, raw.14, raw.15
        ])
    }

    /// Whole seconds since the Unix epoch, floored. Saturating: an out-of-range or non-finite value
    /// (only reachable from a hostile decoded envelope) clamps instead of trapping.
    mutating func appendDate(_ date: Date) {
        let seconds = date.timeIntervalSince1970.rounded(.down)
        let clamped: Int64
        if !seconds.isFinite {
            clamped = 0
        } else if seconds >= Double(Int64.max) {
            clamped = .max
        } else if seconds <= Double(Int64.min) {
            clamped = .min
        } else {
            clamped = Int64(seconds)
        }
        appendInt64(clamped)
    }

    mutating func appendOptional(_ date: Date?) {
        if let date {
            appendByte(1)
            appendDate(date)
        } else {
            appendByte(0)
        }
    }

    mutating func appendOptional(_ string: String?) {
        if let string {
            appendByte(1)
            appendString(string)
        } else {
            appendByte(0)
        }
    }
}

// MARK: - Byte-lexicographic key ordering

/// Orders two strings by their raw UTF-8 bytes. Deterministic and identical across stacks — unlike
/// Foundation's `.sortedKeys`, which orders by UTF-16 code units (different for non-BMP scalars).
nonisolated func canonicalUTF8Ordered(_ lhs: String, _ rhs: String) -> Bool {
    let a = Array(lhs.utf8)
    let b = Array(rhs.utf8)
    let shared = min(a.count, b.count)
    var index = 0
    while index < shared {
        if a[index] != b[index] { return a[index] < b[index] }
        index += 1
    }
    return a.count < b.count
}

// MARK: - Domain tags

// Distinct per signed type so a signature over one type cannot validate over the other.
private nonisolated let canonicalEnvelopeDomain = FernletCryptoPurpose.Signature.identityEnvelopeV2.data
private nonisolated let canonicalAdmissionTokenDomain = FernletCryptoPurpose.Signature.meshAdmissionTokenV2.data
// Group Activities (Phase 6). Distinct tags so an activity descriptor hash, a join token, and a roster
// snapshot can never cross-validate one another (or the mesh types above).
private nonisolated let canonicalActivityDescriptorDomain = FernletCryptoPurpose.Signature.activityDescriptorV2.data
private nonisolated let canonicalActivityJoinTokenDomain = FernletCryptoPurpose.Signature.activityJoinTokenV2.data
private nonisolated let canonicalActivityRosterSnapshotDomain = FernletCryptoPurpose.Signature.activityRosterSnapshotV2.data
// Moderation report row (Phase 3b). Distinct tag so a report signature can never cross-validate any
// other signed type.
private nonisolated let canonicalModerationReportDomain = FernletCryptoPurpose.Signature.moderationReportV2.data
// QUIC mesh channel introduction (network migration P2). Distinct from the DEBUG probe's spelling by
// registry construction, so a spike build can never mint bytes a shipping peer would accept.
private nonisolated let canonicalMeshChannelIntroductionDomain =
    FernletCryptoPurpose.Signature.meshChannelIntroductionV1.data
// Membership events (network migration P3, plan §8.3). One domain per record kind, so a departure
// signature can never validate as a termination — the difference between a member removing itself
// and a member ending the mesh for everyone.
private nonisolated let canonicalMeshMemberDepartureDomain =
    FernletCryptoPurpose.Signature.meshMemberDepartureV1.data
private nonisolated let canonicalMeshMemberRemovalDomain =
    FernletCryptoPurpose.Signature.meshMemberRemovalV1.data
private nonisolated let canonicalMeshTerminatedDomain =
    FernletCryptoPurpose.Signature.meshTerminatedV1.data
private nonisolated let canonicalMeshInventoryDigestDomain =
    FernletCryptoPurpose.Signature.meshInventoryDigestV1.data
private nonisolated let canonicalMeshInventoryDigestHashDomain =
    FernletCryptoPurpose.Hash.meshInventoryDigestV1.data
private nonisolated let canonicalMeshEpochHeadsDomain =
    FernletCryptoPurpose.Signature.meshEpochHeadsV1.data
// Quorum under partition (network migration P4 item 5, plan §10.4). Two more domains, distinct from
// each other and from the completed removal's: a proposal binds `proposalID → (mesh, target,
// proposer)` and a vote agrees with one, while `meshMemberRemovalV1` signs the permanent record. If
// any two of the three cross-validated, one signed object could be replayed as another.
private nonisolated let canonicalMeshRemovalProposalDomain =
    FernletCryptoPurpose.Signature.meshRemovalProposalV1.data
private nonisolated let canonicalMeshRemovalVoteDomain =
    FernletCryptoPurpose.Signature.meshRemovalVoteV1.data
// P5 item 1 (plan §11): the routed-content manifest is signed by the ORIGIN only and forwarded
// verbatim; its domain must be distinct from every membership frame's so "what I am sending"
// can never be replayed as "what I hold" (the inventory digest) or "what epoch I am on".
private nonisolated let canonicalMeshRoutedManifestDomain = FernletCryptoPurpose.Signature.meshRoutedManifestV1.data

// MARK: - Identity envelope

/// Canonical signing bytes for a `FernletIdentityEnvelope` (schema v2+). The `signature` field is
/// excluded entirely (it is the output of signing these bytes).
public nonisolated func canonicalBytes(for envelope: FernletIdentityEnvelope) -> Data {
    var writer = CanonicalByteWriter()
    writer.appendLengthPrefixed(canonicalEnvelopeDomain)
    writer.appendInt64(Int64(envelope.schemaVersion))
    writer.appendUUID(envelope.envelopeID)
    writer.appendLengthPrefixed(envelope.senderSigningPublicKey)
    writer.appendLengthPrefixed(envelope.senderKeyAgreementPublicKey)
    writer.appendString(envelope.senderDisplayName)
    writer.appendOptional(envelope.recipientFingerprint)
    // The RAW wire token, not the enum case: canonical bytes must be computable for payload types
    // this build doesn't know, so signatures on newer-build envelopes still verify (Phase 1
    // forward tolerance). For known types the token IS the rawValue — bytes unchanged.
    writer.appendString(envelope.payloadTypeToken)
    appendCanonical(&writer, envelope.payloadEncryption)
    appendCanonical(&writer, envelope.payloadSummary)
    writer.appendLengthPrefixed(envelope.payload)
    writer.appendDate(envelope.createdAt)
    writer.appendOptional(envelope.expiresAt)
    // signature: deliberately excluded.
    return writer.bytes
}

private nonisolated func appendCanonical(_ writer: inout CanonicalByteWriter, _ encryption: PayloadEncryption) {
    switch encryption {
    case .none:
        writer.appendByte(0)
    case .sealedTo(let recipientKeyAgreementPublicKey):
        writer.appendByte(1)
        writer.appendLengthPrefixed(recipientKeyAgreementPublicKey)
    }
}

/// Writes a `PayloadSummary` into the canonical signing bytes.
///
/// **DO NOT LOCALIZE ANY STRING THAT REACHES THIS FUNCTION.** `title`, `subtitle`, and every
/// `extraDetails` key and value are hashed into the Ed25519 signature below. They read like UI copy
/// ("Recipe share", "Session ended", "Good vibes") but they are wire bytes: a `String(localized:)`
/// anywhere upstream makes the canonical bytes locale-dependent, which is exactly the class of
/// cross-stack divergence this whole serializer exists to eliminate (see the WHY THIS EXISTS header).
/// The failure mode is a `signatureInvalid` on a legitimately signed envelope, reproducible only on
/// a device set to the other language — no crash, no log, just a peer that silently cannot connect.
/// The receiver-side localization plan is documented on `FernletIdentityEnvelope.payloadSummary`.
private nonisolated func appendCanonical(_ writer: inout CanonicalByteWriter, _ summary: PayloadSummary) {
    writer.appendString(summary.title)
    writer.appendOptional(summary.subtitle)
    writer.appendInt64(Int64(summary.itemCount))
    if let dateRange = summary.dateRange {
        writer.appendByte(1)
        writer.appendDate(dateRange.start)
        writer.appendDate(dateRange.end)
    } else {
        writer.appendByte(0)
    }
    let orderedDetails = summary.extraDetails.sorted { canonicalUTF8Ordered($0.key, $1.key) }
    writer.appendUInt64(UInt64(orderedDetails.count))
    for (key, value) in orderedDetails {
        writer.appendString(key)
        writer.appendString(value)
    }
}

// MARK: - Mesh admission token

/// Canonical signing bytes for a `MeshAdmissionToken` (canonical v2). The `admitterSignature` field
/// is excluded entirely (it is the output of signing these bytes).
public nonisolated func canonicalBytes(for token: MeshAdmissionToken) -> Data {
    var writer = CanonicalByteWriter()
    writer.appendLengthPrefixed(canonicalAdmissionTokenDomain)
    writer.appendUUID(token.meshID)
    writer.appendString(token.joinerFingerprint)
    writer.appendLengthPrefixed(token.joinerSigningPublicKey)
    writer.appendString(token.admitterFingerprint)
    writer.appendDate(token.grantedAt)
    writer.appendDate(token.expiresAt)
    writer.appendLengthPrefixed(token.admitterSigningPublicKey)
    // admitterSignature: deliberately excluded.
    return writer.bytes
}

// MARK: - Group Activities (Phase 6)

// All three include the SIGNED `schemaVersion` (where present), so `verify` uses a SINGLE encoder gated
// on the version — no permanent dual-verify (contrast the `MeshAdmissionToken` note above). Because
// these types are new (day one), there is no legacy encoder for them and never will be.

/// Canonical bytes an `ActivityDescriptor` is hashed over to form `activityParamsHash` (SHA-256). The
/// descriptor is not itself signed; this hash is what the signed token/snapshot bind, so its byte
/// layout must be as stable as any signing input.
public nonisolated func canonicalBytes(for descriptor: ActivityDescriptor) -> Data {
    var writer = CanonicalByteWriter()
    writer.appendLengthPrefixed(canonicalActivityDescriptorDomain)
    writer.appendUUID(descriptor.activityID)
    writer.appendString(descriptor.hostFingerprint)
    writer.appendLengthPrefixed(descriptor.hostSigningPublicKey)
    writer.appendString(descriptor.title)
    writer.appendString(descriptor.activityTypeToken)
    writer.appendOptional(descriptor.coarseLocation)
    writer.appendDate(descriptor.createdAt)
    writer.appendDate(descriptor.expiresAt)
    return writer.bytes
}

/// Canonical signing bytes for an `ActivityJoinToken`. The `hostSignature` field is excluded (it is the
/// output of signing these bytes).
public nonisolated func canonicalBytes(for token: ActivityJoinToken) -> Data {
    var writer = CanonicalByteWriter()
    writer.appendLengthPrefixed(canonicalActivityJoinTokenDomain)
    writer.appendInt64(Int64(token.schemaVersion))
    writer.appendUUID(token.activityID)
    writer.appendLengthPrefixed(token.activityParamsHash)
    writer.appendString(token.joinerFingerprint)
    writer.appendLengthPrefixed(token.joinerSigningPublicKey)
    writer.appendString(token.hostFingerprint)
    writer.appendLengthPrefixed(token.hostSigningPublicKey)
    writer.appendDate(token.grantedAt)
    writer.appendDate(token.expiresAt)
    writer.appendInt64(Int64(token.rosterVersionAtGrant))
    // hostSignature: deliberately excluded.
    return writer.bytes
}

/// Canonical signing bytes for an `ActivityRosterSnapshot`. The `hostSignature` field is excluded. The
/// participant array is length-prefixed and serialized in array order (the host's authored order IS the
/// canonical order), so the same roster always produces the same bytes.
public nonisolated func canonicalBytes(for snapshot: ActivityRosterSnapshot) -> Data {
    var writer = CanonicalByteWriter()
    writer.appendLengthPrefixed(canonicalActivityRosterSnapshotDomain)
    writer.appendInt64(Int64(snapshot.schemaVersion))
    writer.appendUUID(snapshot.activityID)
    writer.appendInt64(Int64(snapshot.version))
    writer.appendUInt64(UInt64(snapshot.participants.count))
    for participant in snapshot.participants {
        writer.appendString(participant.fingerprint)
        writer.appendString(participant.displayName)
        writer.appendLengthPrefixed(participant.signingPublicKey)
        writer.appendLengthPrefixed(participant.keyAgreementPublicKey)
        writer.appendDate(participant.joinedAt)
    }
    writer.appendDate(snapshot.issuedAt)
    writer.appendLengthPrefixed(snapshot.hostSigningPublicKey)
    // hostSignature: deliberately excluded.
    return writer.bytes
}

// MARK: - Moderation report (Phase 3b)

/// Canonical signing bytes for a `ModerationLedgerEntry` — the deterministic bytes a reporter signs and
/// a receiver re-derives to verify. Both ends produce identical bytes for the same row. `createdAt` is
/// bound at whole-second resolution (a hostile future date is part of the signature; the receiver may
/// then clamp the STORED createdAt for decay without touching verification). Length-prefixing makes the
/// encoding injective — no value can shift a field boundary — and `appendDate` saturates instead of
/// trapping on an out-of-range wire date. There is no legacy encoder: this row type never signed before.
public nonisolated func canonicalBytes(for entry: ModerationLedgerEntry) -> Data {
    var writer = CanonicalByteWriter()
    writer.appendLengthPrefixed(canonicalModerationReportDomain)
    writer.appendString(entry.kind.rawValue)
    writer.appendLengthPrefixed(entry.reporterSigningPublicKey)
    writer.appendLengthPrefixed(entry.subjectSigningPublicKey)
    writer.appendUUID(entry.itemID)
    writer.appendLengthPrefixed(entry.contentHash)
    writer.appendString(entry.reasonToken)
    writer.appendUInt64(entry.reporterSeq)
    writer.appendDate(entry.createdAt)
    // signature: lives on `SignedModerationReport`, not the entry — nothing to exclude here.
    return writer.bytes
}

// MARK: - QUIC mesh channel introduction (network migration P2)

/// Canonical signing bytes for a ``MeshChannelIntroductionTranscript`` — the mutually-signed QUIC
/// channel introduction of plan §7.2.
///
/// The field order **is** the plan's transcript definition, in the plan's order: purpose ‖ version ‖
/// meshID ‖ epochRef ‖ both signing public keys ‖ both nonces ‖ TLS-exporter hash. Roles fix the
/// order of the paired fields — initiator before responder — so both ends of one tunnel produce
/// byte-identical input without exchanging the transcript itself.
///
/// Length-prefixing every variable field makes the encoding injective: no nonce can borrow a byte
/// from a key, and no epoch reference can shift the fields after it. That is what lets the registry
/// declare `.lengthPrefixed` for this purpose and have the claim be true —
/// `CryptographicPurposeBoundaryTests` pins the pair, because a declared-vs-emitted framing
/// mismatch is what broke silently in `91c3956`.
///
/// There is no signature field to exclude: the signature lives on ``MeshChannelIntroduction``, which
/// is the frame, not the transcript.
nonisolated func canonicalBytes(for transcript: MeshChannelIntroductionTranscript) -> Data {
    var writer = CanonicalByteWriter()
    writer.appendLengthPrefixed(canonicalMeshChannelIntroductionDomain)
    writer.appendInt64(Int64(transcript.protocolVersion))
    writer.appendUUID(transcript.meshID)
    writer.appendString(transcript.epochRef)
    writer.appendLengthPrefixed(transcript.initiatorSigningPublicKey)
    writer.appendLengthPrefixed(transcript.responderSigningPublicKey)
    writer.appendLengthPrefixed(transcript.initiatorNonce)
    writer.appendLengthPrefixed(transcript.responderNonce)
    writer.appendLengthPrefixed(transcript.channelBindingHash)
    return writer.bytes
}

// MARK: - Membership events (network migration P3, plan §8.3)

// Three record encoders and one message encoder, all in the same length-prefixed writer as every
// other production signature — so all four purposes declare `.lengthPrefixed`, and
// `CryptographicPurposeBoundaryTests` holds each one to that declaration in the same change that
// introduced it (the `91c3956` lesson).
//
// A record's own `signature` is excluded from its bytes, exactly as `admitterSignature` is on a
// `MeshAdmissionToken`: the signature is the OUTPUT of signing these bytes. The admission record
// has no encoder here because it wraps a `MeshAdmissionToken` whole and is signed under the
// already-registered `meshAdmissionTokenV2` domain — one admission format, not two.

/// Canonical signing bytes for a ``SignedDepartureRecord`` — the leaver's own statement that it
/// left (plan §8.3). The custody summary is bound in: what a leaver claims to have handed to whom
/// is part of what it signed, so a relay cannot rewrite the hand-off while re-gossiping the record.
nonisolated func canonicalBytes(for record: SignedDepartureRecord) -> Data {
    var writer = CanonicalByteWriter()
    writer.appendLengthPrefixed(canonicalMeshMemberDepartureDomain)
    writer.appendUUID(record.meshID)
    writer.appendString(record.memberFingerprint)
    writer.appendDate(record.occurredAt)
    writer.appendUInt64(UInt64(record.custodyHandoff.custodianFingerprints.count))
    for custodian in record.custodyHandoff.custodianFingerprints {
        writer.appendString(custodian)
    }
    writer.appendInt64(Int64(record.custodyHandoff.handedOffItemCount))
    // signature: deliberately excluded.
    return writer.bytes
}

/// Canonical signing bytes for a ``SignedRemovalRecord`` — a completed quorum (plan §10.4).
///
/// The voter list is bound in array order, which is the order the record's initializer preserves,
/// so the tallier signs the exact evidence a receiver re-checks. A relay that reordered or trimmed
/// the voters would invalidate the signature rather than quietly weakening the quorum.
nonisolated func canonicalBytes(for record: SignedRemovalRecord) -> Data {
    var writer = CanonicalByteWriter()
    writer.appendLengthPrefixed(canonicalMeshMemberRemovalDomain)
    writer.appendUUID(record.meshID)
    writer.appendString(record.memberFingerprint)
    writer.appendUUID(record.proposalID)
    writer.appendUInt64(UInt64(record.voterFingerprints.count))
    for voter in record.voterFingerprints {
        writer.appendString(voter)
    }
    writer.appendDate(record.occurredAt)
    writer.appendString(record.authorFingerprint)
    // signature: deliberately excluded.
    return writer.bytes
}

/// Canonical signing bytes for a ``SignedTerminationRecord`` — a final-pair member ending the mesh
/// (plan §8.3). `rosterAtSigning` is bound in so the audit trail is signed, not merely carried;
/// the downgrade rule still judges against the RECEIVER's merged roster (``MeshDerivedRoster``).
nonisolated func canonicalBytes(for record: SignedTerminationRecord) -> Data {
    var writer = CanonicalByteWriter()
    writer.appendLengthPrefixed(canonicalMeshTerminatedDomain)
    writer.appendUUID(record.meshID)
    writer.appendString(record.memberFingerprint)
    writer.appendUInt64(UInt64(record.rosterAtSigning.count))
    for fingerprint in record.rosterAtSigning {
        writer.appendString(fingerprint)
    }
    writer.appendDate(record.occurredAt)
    // signature: deliberately excluded.
    return writer.bytes
}

/// Canonical signing bytes for a ``MeshInventoryDigestPayload`` (plan §10.5). The digest's own
/// hash is bound as opaque bytes — it was already domain-separated when it was computed, by
/// ``canonicalInventoryDigestBytes(for:)``.
nonisolated func canonicalBytes(for payload: MeshInventoryDigestPayload) -> Data {
    var writer = CanonicalByteWriter()
    writer.appendLengthPrefixed(canonicalMeshInventoryDigestDomain)
    writer.appendUUID(payload.digest.meshID)
    writer.appendString(payload.senderFingerprint)
    writer.appendDate(payload.sentAt)
    writer.appendInt64(Int64(payload.digest.admissionCount))
    writer.appendInt64(Int64(payload.digest.departureCount))
    writer.appendInt64(Int64(payload.digest.removalCount))
    writer.appendInt64(Int64(payload.digest.terminationCount))
    writer.appendLengthPrefixed(payload.digest.recordsHash)
    // signature: deliberately excluded.
    return writer.bytes
}

/// Canonical signing bytes for a ``MeshEpochHeadsPayload`` (plan §10.3, P4 item 3).
///
/// Each head contributes its own canonical string — the exact spelling
/// ``MeshEpochRef/canonicalString`` produces and the one a peer parses back — so two devices
/// holding the same head set sign over identical bytes, and the count is written first so a
/// re-partitioning of the same characters cannot produce the same transcript.
nonisolated func canonicalBytes(for payload: MeshEpochHeadsPayload) -> Data {
    var writer = CanonicalByteWriter()
    writer.appendLengthPrefixed(canonicalMeshEpochHeadsDomain)
    writer.appendUUID(payload.meshID)
    writer.appendString(payload.senderFingerprint)
    writer.appendDate(payload.sentAt)
    writer.appendUInt64(UInt64(payload.heads.count))
    for head in payload.heads {
        writer.appendString(head.canonicalString)
    }
    // signature: deliberately excluded.
    return writer.bytes
}

/// Canonical signing bytes for a ``SignedRemovalProposal`` (plan §10.4, P4 item 5).
///
/// The target is bound before the proposer so the two fingerprints can never be transposed into a
/// valid transcript for the mirror-image proposal, and `issuedAt` is bound because it is audited —
/// the five-minute window is measured at the receiver from first-seen, so binding the stamp costs
/// nothing and an unbound one could be rewritten by a relay.
nonisolated func canonicalBytes(for proposal: SignedRemovalProposal) -> Data {
    var writer = CanonicalByteWriter()
    writer.appendLengthPrefixed(canonicalMeshRemovalProposalDomain)
    writer.appendUUID(proposal.meshID)
    writer.appendUUID(proposal.proposalID)
    writer.appendString(proposal.targetFingerprint)
    writer.appendString(proposal.proposerFingerprint)
    writer.appendDate(proposal.issuedAt)
    // signature: deliberately excluded.
    return writer.bytes
}

/// Canonical signing bytes for a ``SignedRemovalVote`` (plan §10.4, P4 item 5).
///
/// The same field order as the proposal's, with the voter where the proposer sits — and a different
/// domain, so the two transcripts cannot be mistaken for one another even though they are the same
/// shape. Binding the target here is what makes a vote countable only against the proposal it
/// actually agrees with.
nonisolated func canonicalBytes(for vote: SignedRemovalVote) -> Data {
    var writer = CanonicalByteWriter()
    writer.appendLengthPrefixed(canonicalMeshRemovalVoteDomain)
    writer.appendUUID(vote.meshID)
    writer.appendUUID(vote.proposalID)
    writer.appendString(vote.targetFingerprint)
    writer.appendString(vote.voterFingerprint)
    writer.appendDate(vote.castAt)
    // signature: deliberately excluded.
    return writer.bytes
}

// MARK: - Routed content (network migration P5 item 1, plan §11)

/// Canonical signing bytes for a ``MeshRoutedManifest`` — the origin's description of one routed
/// item (plan §11). **Field order IS the schema**: identity first (mesh, item, origin), then the
/// descriptor (type token, hash, size), then the two instants, then the two count-prefixed lists.
///
/// The destinations and the wraps are bound in the ORIGIN's authored order, each wrap field by
/// field, so a relay that reordered, trimmed, relabelled or re-clamped either list would
/// invalidate the signature rather than quietly changing who the item is for or who can open it.
/// Signed by the origin only; a custodian forwards these exact fields and never re-derives them.
nonisolated func canonicalBytes(for manifest: MeshRoutedManifest) -> Data {
    var writer = CanonicalByteWriter()
    writer.appendLengthPrefixed(canonicalMeshRoutedManifestDomain)
    writer.appendUUID(manifest.meshID)
    writer.appendUUID(manifest.itemID)
    writer.appendString(manifest.originFingerprint)
    writer.appendString(manifest.typeToken)
    writer.appendLengthPrefixed(manifest.contentHash)
    writer.appendUInt64(manifest.size)
    writer.appendDate(manifest.createdAt)
    writer.appendDate(manifest.expiresAt)
    writer.appendUInt64(UInt64(manifest.destinations.count))
    for destination in manifest.destinations {
        writer.appendString(destination)
    }
    writer.appendUInt64(UInt64(manifest.keyWraps.count))
    for wrap in manifest.keyWraps {
        appendCanonical(&writer, wrap)
    }
    // signature: deliberately excluded.
    return writer.bytes
}

/// One ``MeshRecipientKeyWrap`` inside a manifest's transcript: recipient, then the three
/// fixed-width wrap fields, each length-prefixed so the layout is unambiguous even though the
/// widths are fixed.
private nonisolated func appendCanonical(_ writer: inout CanonicalByteWriter, _ wrap: MeshRecipientKeyWrap) {
    writer.appendString(wrap.recipientFingerprint)
    writer.appendLengthPrefixed(wrap.ephemeralPublicKey)
    writer.appendLengthPrefixed(wrap.nonce)
    writer.appendLengthPrefixed(wrap.sealedKey)
}

/// The bytes a ``MeshInventoryDigest`` hashes, under the Hash-family purpose that names them.
///
/// Every record contributes its kind token and the four fields that give the record set its total
/// order, in that set's own deterministic order — so two ledgers holding the same records produce
/// the same bytes on any device, and one extra or one missing record changes them.
nonisolated func canonicalInventoryDigestBytes(for identities: [MeshRecordIdentity]) -> Data {
    var writer = CanonicalByteWriter()
    writer.appendLengthPrefixed(canonicalMeshInventoryDigestHashDomain)
    writer.appendUInt64(UInt64(identities.count))
    for identity in identities {
        writer.appendString(identity.kind.rawValue)
        writer.appendString(identity.memberFingerprint)
        writer.appendDate(identity.occurredAt)
        writer.appendString(identity.authorFingerprint)
        writer.appendLengthPrefixed(identity.signature)
    }
    return writer.bytes
}

// MARK: - Legacy (pre-WI-6) canonical encoder

// Retained ONLY to verify signatures minted by in-field peers that predate WI-6 (envelope schema
// v1 / unversioned tokens). It is never used to SIGN. Removing it would silently reject every
// not-yet-updated Apple peer, so it stays until those builds age out.

/// The exact Foundation encoder configuration used before WI-6. Do not change — its byte output is a
/// compatibility contract with already-signed, in-field data.
private nonisolated func makeLegacyCanonicalSignatureEncoder() -> JSONEncoder {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    encoder.dateEncodingStrategy = .iso8601
    return encoder
}

/// Legacy (schema v1) canonical bytes for an envelope. `try?`/`?? Data()` keeps the untrusted
/// verify path non-throwing; an empty result simply fails the signature check.
public nonisolated func legacyCanonicalBytes(for envelope: FernletIdentityEnvelope) -> Data {
    var copy = envelope
    copy.signature = Data()
    return (try? makeLegacyCanonicalSignatureEncoder().encode(copy)) ?? Data()
}

/// Legacy (pre-WI-6) canonical bytes for an admission token.
public nonisolated func legacyCanonicalBytes(for token: MeshAdmissionToken) -> Data {
    var copy = token
    copy.admitterSignature = Data()
    return (try? makeLegacyCanonicalSignatureEncoder().encode(copy)) ?? Data()
}
