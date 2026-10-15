// IdentityProvisioningParticipant.swift
// ProximityKit/Identity
//
// The seam through which a host keeps keys of its own beside the device identity, under the
// identity's keychain service, without ProximityKit knowing what they are: the identity's
// provisioning calls its participant at the points where those keys must be accounted for, in an
// order the identity fixes, and its wipe tells the participant when the rows are gone.

import CryptoKit

/// Keys a host keeps beside its device identity, under the identity's keychain service, that the
/// identity's provisioning must account for.
///
/// The identity tells its participant when it adopts the device keys already on this device, asks
/// it before it mints fresh ones over its rows (handing it a fail-closed reader of the
/// key-agreement row a previous build left there), tells it when that mint is on disk, and tells it
/// after a wipe. Without a participant an identity adopts or mints, and nothing else.
///
/// **The order is the identity's, and it is the safety property.**
/// ``IdentityService/ensureProvisioned()`` calls ``identityAdoptedDeviceKeys(_:)`` after it adopts
/// the two device keys and before it rewrites the key-agreement row device-only; it calls
/// ``identityWillMintDeviceKeys(_:previousKeyAgreementKey:)`` before it mints, so whatever the
/// participant must keep of the rows the mint overwrites (delete-then-add, every variant of each
/// row) is kept first, and anything it throws stops provisioning before the identity writes a row;
/// it calls ``identityMintedDeviceKeys(_:)`` only once the four fresh rows are on disk and adopted,
/// never after a failed mint. ``IdentityService/wipe()`` calls ``identityWiped(_:)`` after it has
/// swept the identity's service and cleared its keys, whether or not the sweep succeeded.
/// Provisioning's soundness refusal comes first: under an unsound namespace
/// ``IdentityService/ensureProvisioned()`` throws before it calls the participant, so none is told
/// of an adoption or asked or told of a mint. A wipe reads no verdict: it sweeps, clears and tells
/// the participant under any namespace, sound or not.
///
/// **What leaves the identity.** The device's signing and key-agreement private keys never reach a
/// participant. The one private key that does is the previous build's key-agreement key the reader
/// returns, which the mint is about to overwrite and which is no longer the device's key.
///
/// Main-actor, like the identity; every call is synchronous, on the identity's own provisioning or
/// wipe, so a participant sees its identity's calls in their order and nothing in between.
/// Fernlet's participant is the app's sealed-backup escrow key.
@MainActor public protocol IdentityProvisioningParticipant: AnyObject {

    /// The identity adopted the signing and key-agreement keys already on this device (provisioning's
    /// first case). Called before the identity rewrites the key-agreement row device-only.
    ///
    /// - Parameter identity: The identity that adopted them; its ``IdentityService/keychainService``
    ///   names the service the participant's own rows live under.
    func identityAdoptedDeviceKeys(_ identity: IdentityService)

    /// The identity is about to mint fresh device keys, which overwrite whatever its rows hold, the
    /// key-agreement row a previous build left included.
    ///
    /// - Parameters:
    ///   - identity: The identity about to mint.
    ///   - previousKeyAgreementKey: Reads that row: nil when it is absent or holds no parseable key;
    ///     throws ``IdentityError/keychainReadFailed(_:)`` when it could not be read, so the caller
    ///     cannot take an unreadable row for an empty one. Call it at most once, inside this call.
    /// - Throws: Whatever the participant throws stops provisioning before the identity writes a row;
    ///   the identity holds no device keys afterwards and the next
    ///   ``IdentityService/ensureProvisioned()`` asks again.
    func identityWillMintDeviceKeys(
        _ identity: IdentityService,
        previousKeyAgreementKey: () throws -> Curve25519.KeyAgreement.PrivateKey?
    ) throws

    /// The fresh device keys are on disk and adopted. Never called after a mint that failed.
    ///
    /// - Parameter identity: The identity that minted them.
    func identityMintedDeviceKeys(_ identity: IdentityService)

    /// The identity swept its rows and cleared its keys; called whether or not the sweep reported
    /// success, and under any namespace, sound or not (a wipe reads no soundness verdict), so a
    /// participant drops what it holds in memory either way.
    ///
    /// - Parameter identity: The identity that was wiped.
    func identityWiped(_ identity: IdentityService)
}
