// MeshPayloadRole.swift
// ProximityKit/Mesh
//
// The mesh engine's own frames by role: what each frame is, never how it is spelled. The spelling is
// the host's, its namespace's `family.vocabulary.mesh` (`ProximityNamespace.MeshMessages`), and this
// file is the one place a role meets its token, both ways: `token(in:)` for every frame the mesh
// manager signs, `role(for:in:)` for every token its dispatch door receives. The features riding the
// mesh are not here: their payloads keep Fernlet's `PayloadType` tokens until they leave ProximityKit
// with the mesh manager's feature parts (plan step A0.5), and the manager hands those to its handler
// registry by token.

import Foundation

// MARK: - MeshPayloadRole

/// The mesh engine's own messages, by role: the frames its membership, admission, routed-delivery,
/// group-key and verify-ceremony doors sign and dispatch, and the legacy goodbye it parses and never
/// sends.
///
/// The spelling is the host's. ``token(in:)`` reads a role's token off the mesh messages of the
/// namespace the caller holds (``ProximityNamespace/MeshMessages``); ``role(for:in:)`` resolves a
/// received token back to its role. A token is frozen wire data, signed into every envelope twice
/// (as its payload type and as its summary title), so it never localizes; nothing encodes or decodes
/// a role, and nothing shows one to a person. No raw value, so a role cannot be written to the wire
/// or to an audit line except through its host's token.
///
/// Each case carries the name of the `PayloadType` case Fernlet sends that frame under, so the
/// manager's switches and sends read as Fernlet's wire vocabulary does; source walls pin some of that
/// text (`MeshRoutedPhotoDeliveryTests`' routing arms, `MeshRoutedCustodyHandoffTests`' count of
/// `sendMembershipEvent`'s refusals).
nonisolated enum MeshPayloadRole: CaseIterable, Sendable {
    /// The mesh's descriptor, which a committed member adopts.
    case meshDescriptor
    /// The admitter's grant.
    case meshAdmissionGrant
    /// A joiner's request to be admitted.
    case meshAdmissionRequest
    /// A mesh state change, opened only inside closed-mode group metadata.
    case meshStateChange
    /// A member's vouch list.
    case meshFriendVouchList
    /// The legacy unsigned two-party removal's proposal.
    case meshRemovalProposal
    /// The legacy unsigned two-party removal's second.
    case meshRemovalSecond
    /// A leaver's signed departure record.
    case meshMemberDeparture
    /// An admitter's signed admission record.
    case meshMemberAdmission
    /// A completed quorum's signed removal record.
    case meshMemberRemoval
    /// A final-pair member's signed termination record.
    case meshTerminated
    /// A member's signed membership inventory digest.
    case meshInventoryDigest
    /// A member's signed epoch heads.
    case meshEpochHeads
    /// A batch of members' signed key-agreement advertisements.
    case meshKeyAgreement
    /// A signed removal proposal.
    case meshRemovalProposalSigned
    /// A signed removal vote.
    case meshRemovalVote
    /// A routed item's signed manifest.
    case meshRoutedManifest
    /// A signed routed chunk.
    case meshRoutedChunk
    /// A signed custody receipt.
    case meshCustodyReceipt
    /// A signed recipient receipt.
    case meshRecipientReceipt
    /// A member's signed routed inventory digest.
    case meshRoutedInventoryDigest
    /// A signed routed drain answer.
    case meshRoutedDrainAnswer
    /// The elected coordinator's group-key rotation.
    case meshKeyRotation
    /// A member's acknowledgement of a rotation.
    case meshKeyAck
    /// The coordinator's rotation sync.
    case meshRotationSync
    /// Closed-mode group metadata, received only.
    case meshEncryptedMetadata
    /// The elected coordinator's liveness beacon.
    case meshCoordinatorBeacon
    /// The verify ceremony's challenge.
    case verifyChallenge
    /// The verify ceremony's response.
    case verifyResponse
    /// The legacy goodbye: parsed, never sent.
    case sessionGoodbye

    /// This role's token in the host's vocabulary: what a frame of this role is signed under, and
    /// titled with.
    ///
    /// - Parameter mesh: The mesh messages of the namespace the caller holds.
    /// - Returns: The token.
    func token(in mesh: ProximityNamespace.MeshMessages) -> String {
        switch self {
        case .meshDescriptor: return mesh.descriptor
        case .meshAdmissionGrant: return mesh.admissionGrant
        case .meshAdmissionRequest: return mesh.admissionRequest
        case .meshStateChange: return mesh.stateChange
        case .meshFriendVouchList: return mesh.friendVouchList
        case .meshRemovalProposal: return mesh.removalProposal
        case .meshRemovalSecond: return mesh.removalSecond
        case .meshMemberDeparture: return mesh.memberDeparture
        case .meshMemberAdmission: return mesh.memberAdmission
        case .meshMemberRemoval: return mesh.memberRemoval
        case .meshTerminated: return mesh.terminated
        case .meshInventoryDigest: return mesh.inventoryDigest
        case .meshEpochHeads: return mesh.epochHeads
        case .meshKeyAgreement: return mesh.keyAgreement
        case .meshRemovalProposalSigned: return mesh.removalProposalSigned
        case .meshRemovalVote: return mesh.removalVote
        case .meshRoutedManifest: return mesh.routedManifest
        case .meshRoutedChunk: return mesh.routedChunk
        case .meshCustodyReceipt: return mesh.custodyReceipt
        case .meshRecipientReceipt: return mesh.recipientReceipt
        case .meshRoutedInventoryDigest: return mesh.routedInventoryDigest
        case .meshRoutedDrainAnswer: return mesh.routedDrainAnswer
        case .meshKeyRotation: return mesh.keyRotation
        case .meshKeyAck: return mesh.keyAck
        case .meshRotationSync: return mesh.rotationSync
        case .meshEncryptedMetadata: return mesh.encryptedMetadata
        case .meshCoordinatorBeacon: return mesh.coordinatorBeacon
        case .verifyChallenge: return mesh.verifyChallenge
        case .verifyResponse: return mesh.verifyResponse
        case .sessionGoodbye: return mesh.sessionGoodbye
        }
    }

    /// The role a received token plays in the host's vocabulary, or nil for a token that names none
    /// of the mesh's own messages: a feature's payload, which goes to the handler registry, or a token
    /// the host does not know.
    ///
    /// The namespace's soundness holds the thirty tokens distinct, so at most one role matches; in an
    /// unsound namespace the earliest declared role wins.
    ///
    /// - Parameters:
    ///   - token: The token a received envelope carries.
    ///   - mesh: The mesh messages of the namespace the caller holds.
    /// - Returns: The role, or nil.
    static func role(for token: String, in mesh: ProximityNamespace.MeshMessages) -> MeshPayloadRole? {
        // R2: bounded by the thirty roles.
        allCases.first { $0.token(in: mesh) == token }
    }
}
