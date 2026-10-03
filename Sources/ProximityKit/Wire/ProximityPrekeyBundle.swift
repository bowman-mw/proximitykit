// ProximityPrekeyBundle.swift
// ProximityKit/Wire
//
// The prekey bundle a host gossips inside the coordinator's signed identity introduction: one-time
// X25519 public keys and an optional signed prekey, public halves only. ProximityKit carries it
// opaquely: the coordinator encodes the bundle its host's provider returns into every introduction
// and acknowledgement it sends, and hands the bundle a verified introduction carried, with the
// sender's signing key, to its host's receiver; nothing here reads a field, mints a key or keeps a
// private half. Fernlet's heart dead-drop is the host that does (`HeartPrekeyStore` mints the bundles
// and keeps their private halves, and names this type `Bundle`, `PrekeyEntry` and `SignedPrekey`).
//
// Its JSON is wire: the introduction's `heartDropPrekeyBundle` key, a host's keychain blob and its
// sealed caches all hold it, and no type name reaches the bytes, only the stored properties' keys in
// their declared order. `FernletFeatureGoldenTests` holds the JSON to frozen literals both ways and
// drives the introduction that gossips it.
//
// `nonisolated` + `Sendable` against ProximityKit's `.defaultIsolation(MainActor.self)`, like every
// wire type here, so the introduction that carries it decodes off the main actor.

import Foundation

/// A prekey bundle as the signed identity introduction gossips it: one-time X25519 public keys and an
/// optional signed prekey, public halves only.
///
/// **Carried, never read.** ``ProximityCoordinator`` encodes the bundle its host's
/// ``ProximityCoordinator/introductionPrekeyBundleProvider`` returns into every introduction and
/// acknowledgement it sends, and hands the bundle a verified introduction carried, with the sender's
/// full signing key, to ``ProximityCoordinator/onIntroductionPrekeyBundle``. It reads no field, mints
/// nothing and keeps no private half: what a bundle's keys are for, how long they live and who may
/// seal to them is the host's policy. Fernlet's heart dead-drop is the host that mints them, keeps their
/// private halves and caches its friends' bundles to seal drops to.
///
/// **Provenance is the introduction's signature.** A bundle travels only inside the signed
/// introduction, under the additive optional key `heartDropPrekeyBundle`, which an older decoder
/// ignores, so the envelope's Ed25519 signature is its provenance and no second standalone signature
/// can drift out of sync.
///
/// **The JSON is frozen.** The bytes are the stored properties' keys, in their declared order, under
/// `JSONEncoder`'s default date and data strategies: `bundleID`, `created`, `expires`, `keys` (each
/// `id`, `publicKey`) and, only when present, `signedPrekey` (`id`, `publicKey`, `created`,
/// `expires`), an additive optional key that an older peer's bundle leaves out and an older decoder
/// ignores. No type name reaches them, so every introduction, keychain blob and sealed cache already
/// written decodes unchanged. `FernletFeatureGoldenTests` holds them to frozen literals both ways.
///
/// `nonisolated` and `Sendable`: a pure value, decoded with the introduction off the main actor.
public nonisolated struct ProximityPrekeyBundle: Codable, Equatable, Sendable {

    /// One one-time X25519 prekey's public half, with the id a sender names it by when it seals to it.
    public nonisolated struct PrekeyEntry: Codable, Equatable, Sendable {
        /// The id a sealed message names this prekey by.
        public let id: UUID
        /// The X25519 public key's raw representation.
        public let publicKey: Data

        /// A prekey entry.
        ///
        /// - Parameters:
        ///   - id: The id a sealed message names the prekey by.
        ///   - publicKey: The X25519 public key's raw representation.
        public init(id: UUID, publicKey: Data) {
            self.id = id
            self.publicKey = publicKey
        }
    }

    /// The X3DH-style medium-term signed prekey: one X25519 public key its owner rotates on a schedule of
    /// its own, beside the one-time keys.
    ///
    /// "Signed" as in signed by the identity introduction it rides: like the one-time keys it travels
    /// only inside the signed introduction, so its provenance is the envelope's Ed25519 signature, with
    /// no second standalone signature to get out of sync.
    public nonisolated struct SignedPrekey: Codable, Equatable, Sendable {
        /// The id a sealed message names this prekey by.
        public let id: UUID
        /// The X25519 public key's raw representation.
        public let publicKey: Data
        /// When the owner minted it.
        public let created: Date
        /// Rotation deadline, NOT retention deadline: after this the owner gossips a fresh signed prekey,
        /// but keeps this one's private half longer, so what was sealed to it before the rotation still
        /// opens.
        public let expires: Date

        /// A signed prekey.
        ///
        /// - Parameters:
        ///   - id: The id a sealed message names the prekey by.
        ///   - publicKey: The X25519 public key's raw representation.
        ///   - created: When the owner minted it.
        ///   - expires: When the owner rotates it out of what it gossips.
        public init(id: UUID, publicKey: Data, created: Date, expires: Date) {
            self.id = id
            self.publicKey = publicKey
            self.created = created
            self.expires = expires
        }
    }

    /// The bundle's id.
    public let bundleID: UUID
    /// When the owner minted the bundle.
    public let created: Date
    /// When the bundle stops being gossiped.
    public let expires: Date
    /// The one-time prekeys.
    public let keys: [PrekeyEntry]
    /// The signed prekey, or nil: an additive optional key, absent from an older peer's bundle, which
    /// decodes with nil and keeps working.
    public let signedPrekey: SignedPrekey?

    /// A bundle.
    ///
    /// - Parameters:
    ///   - bundleID: The bundle's id.
    ///   - created: When the owner minted it.
    ///   - expires: When it stops being gossiped.
    ///   - keys: The one-time prekeys.
    ///   - signedPrekey: The signed prekey, or nil for none.
    public init(bundleID: UUID, created: Date, expires: Date, keys: [PrekeyEntry],
                signedPrekey: SignedPrekey? = nil) {
        self.bundleID = bundleID
        self.created = created
        self.expires = expires
        self.keys = keys
        self.signedPrekey = signedPrekey
    }
}
