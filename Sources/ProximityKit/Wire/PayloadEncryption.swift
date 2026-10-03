// PayloadEncryption.swift
// ProximityKit/Wire
//
// Whether an envelope's payload rides plaintext or sealed: a generic wire type that names no payload
// type, capability or app, declared beside the envelope that carries it
// (`FernletIdentityEnvelope.payloadEncryption`). Its synthesized `Codable` form is wire, in every
// envelope frame and in a schema-v1 envelope's signed bytes, and `CanonicalSignatureSerializer` writes
// it into the schema-v2 signed bytes as one tag byte (0 plaintext, 1 sealed), then the sealed case's
// key. `ProximityVocabularyGoldenTests` pins both cases' JSON and one schema-v1 envelope;
// `FernletIdentityEnvelopeTests.goldenEnvelopeHex` pins the schema-v2 bytes.
//
// `nonisolated` + `Sendable` against ProximityKit's `.defaultIsolation(MainActor.self)`, like every
// wire type here, so it decodes with its envelope off the main actor.

import Foundation

/// Whether an envelope's payload rides plaintext or sealed to a recipient key.
///
/// `sealedTo` carries the recipient's X25519 key-agreement public key; the sealing itself is
/// performed by `IdentityService.seal(_:to:format:)` — this type only names the intent.
public nonisolated enum PayloadEncryption: Codable, Equatable, Sendable {
    case none
    case sealedTo(recipientKeyAgreementPublicKey: Data)
}
