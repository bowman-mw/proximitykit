// SealedIntroductionEnvelope.swift
// ProximityKit/Wire
//
// Mesh redesign Phase 4b — SEALED-INTRODUCTION rule (Docs/Proximity-Mesh-Redesign-2026-07-10.md).
//
// The transport container for a presence-originated heart handshake's identity intro / ack. A
// plain `FernletIdentityEnvelope` carries the sender's STABLE signing key, KA key, and display
// name in its cleartext header. On the presence radio a tag-replay forger can get a heart
// connection accepted (tags are broadcast in the clear with no nonce), and the old flow then
// emitted that identity intro before any friend-key proof — deanonymizing the very identity the
// ephemeral presence radio exists to hide.
//
// Fix: a presence-heart coordinator is created with the EXPECTED friend's vault KA public key
// (presence recognition is mutual-by-construction, so both sides hold it). The identity
// intro/ack envelope is JSON-encoded, SEALED to that KA key via `IdentityService.seal`, and put
// on the wire inside THIS wrapper — which carries ONLY the ciphertext, nothing identifying. A
// replay-forger holds no matching KA private key, so it cannot open the wrapper and learns
// neither keys nor name in either direction; the real friend decrypts and the handshake proceeds.
//
// This wrapper is NOT signed — the INNER `FernletIdentityEnvelope` is Ed25519-signed exactly as
// before, and its signature verifies after the recipient opens the wrapper. The single
// `sealedIntroduction` key is absent from every `FernletIdentityEnvelope`, so the two shapes are
// unambiguous on the wire (a plain envelope decodes as `.notWrapped`, this decodes as a wrapper).

import Foundation

/// A presence-heart identity intro/ack sealed to the intended friend's KA key. Carries only the
/// ciphertext of a JSON-encoded `FernletIdentityEnvelope` — no cleartext identity.
public nonisolated struct SealedIntroductionEnvelope: Codable, Equatable, Sendable {
    /// `IdentityService.seal` output over the JSON-encoded inner `FernletIdentityEnvelope`:
    /// ephemeralPubKey (32 B) || ChaChaPoly sealed box. Opaque without the recipient KA private key.
    public let sealedIntroduction: Data

    public init(sealedIntroduction: Data) {
        self.sealedIntroduction = sealedIntroduction
    }
}
