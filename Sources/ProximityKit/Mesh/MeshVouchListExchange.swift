// MeshVouchListExchange.swift
// ProximityKit/Mesh
//
// ProximityKit plan step A0.5.5 (seam S14): the vouch-list exchange — the contract through which a
// host supplies the content of the friend vouch list a device sends a just-committed peer, and keeps
// what it chooses of the lists its committed peers send, while the engine keeps the frame.
//
// The split is the engine's on purpose. The vouch list is a mesh frame with its own role and token
// (`MeshPayloadRole.meshFriendVouchList`), and everything about the frame stays at the engine's call
// sites: the committed-slot gate on the receive side and its `mesh.vouchList.droppedUncommittedSlot`
// line, the decode of ``MeshFriendVouchListPayload`` and both commit-time sends (after a verified
// commit, and when a mesh is promoted at a first commit). The exchange is asked only for content: the
// list to send, or none, and what to do with a list the engine decoded from a committed slot. Whose
// friends are listed, how long a list lives, what a received list is trusted for and how its voucher
// is labelled are the host's.
//
// Not here: the payload, which stays a public engine wire type beside the mesh's other frames
// (`Wire/MeshPayloads.swift`), and the manager's one reference to the exchange
// (`MeshNetworkManager.vouchListExchange`).

import Foundation

// MARK: - MeshVouchListExchange

/// A host's vouch-list content: the list this device sends a just-committed peer, and what it keeps of
/// a list a committed peer sent (plan step A0.5.5, S14).
///
/// Installed on ``MeshNetworkManager/vouchListExchange``, which holds it strongly for the manager's
/// lifetime; a manager with none sends no vouch list and drops every list it decodes, after the
/// engine's own gate and decode.
///
/// **The engine's half, which an exchange cannot change.** On receive, the engine dispatches a vouch
/// list only from a committed slot (an uncommitted one is dropped with one
/// `mesh.vouchList.droppedUncommittedSlot` line and never reaches the exchange), decodes it, and hands
/// every list that decodes to ``receiveVouchList(_:senderFingerprint:)``; a list that does not decode is
/// dropped silently, as before. On send, after each verified commit and when a mesh is promoted at a
/// first commit, the engine asks ``vouchListForBroadcast()`` inside the send's own spawned task, signs
/// the answer under the vouch token to that one committed slot, and sends nothing for nil.
///
/// **The contract for a conformer.** ``vouchListForBroadcast()`` may be asked once per committed slot
/// per commit, from a task the engine spawned on the main actor; it builds a fresh list each time and
/// writes no state. ``receiveVouchList(_:senderFingerprint:)`` is handed a value a peer chose: the
/// fingerprint is that of the peer identity the engine credited the frame to (nil when it credited
/// none), and every field of the payload, its voucher fingerprint, display name and expiry included,
/// is attacker-chosen, so a conformer binds the voucher to the sender, bounds the expiry and sanitizes
/// the name before it keeps or shows anything.
///
/// Main-actor, like the frames that call it; `AnyObject`, because an exchange is an object the engine
/// retains.
@MainActor public protocol MeshVouchListExchange: AnyObject {

    /// The vouch list to send a just-committed peer, or nil to send nothing.
    ///
    /// - Returns: the list, built now, or nil.
    func vouchListForBroadcast() -> MeshFriendVouchListPayload?

    /// A vouch list a committed peer sent, decoded by the engine.
    ///
    /// - Parameters:
    ///   - payload: The decoded list, every field of it peer-chosen.
    ///   - senderFingerprint: The fingerprint of the peer identity the engine credited the frame to,
    ///     or nil when it credited none.
    func receiveVouchList(_ payload: MeshFriendVouchListPayload, senderFingerprint: String?)
}
