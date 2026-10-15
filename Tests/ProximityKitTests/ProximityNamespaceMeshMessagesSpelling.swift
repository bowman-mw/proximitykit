// ProximityNamespaceMeshMessagesSpelling.swift
//
// ProximityKit plan step A1.1: the mesh-message spelling helper, shared by the protocol namespace's
// tests that build a namespace's thirty mesh messages from one spelling rule (the soundness suite,
// the namespace and vocabulary goldens and the runtime gate). It names no app's values and needs
// nothing but ProximityKit, so it is a file of its own, apart from every suite that uses it: those
// suites need not share a test target, and a test target cannot import another.

import ProximityKit

// MARK: - Mesh messages from a spelling rule

/// Builds a namespace's thirty mesh messages from one spelling rule, so a fixture names thirty
/// distinct tokens in one line: the soundness suite's two apps (`ProximityNamespaceSoundnessTests`),
/// the goldens' foreign and renamed namespaces (`ProximityNamespaceGoldenTests`,
/// `ProximityVocabularyGoldenTests`) and the runtime gate's app (`ProximityNamespaceGateTests`). It
/// holds no app's values, and it lives in a file of its own so that the soundness suite, which needs
/// nothing but ProximityKit, can join ProximityKit's package tests while the three suites that stay
/// in `FernletTests` keep using it.
extension ProximityNamespace.MeshMessages {

    /// The thirty mesh messages' field names in declaration order, each the last component of its
    /// field's path from the namespace root (`family.vocabulary.mesh.<name>`).
    /// ``ProximityNamespaceSoundnessTests/theMeshGroupsFieldNamesAreItsFieldsInOrder()`` holds the
    /// list to the type's stored properties.
    static let fieldNames = [
        "descriptor", "admissionGrant", "admissionRequest", "stateChange", "friendVouchList",
        "removalProposal", "removalSecond", "memberDeparture", "memberAdmission", "memberRemoval", "terminated",
        "inventoryDigest", "epochHeads", "keyAgreement", "removalProposalSigned", "removalVote",
        "routedManifest", "routedChunk", "custodyReceipt", "recipientReceipt", "routedInventoryDigest",
        "routedDrainAnswer", "keyRotation", "keyAck", "rotationSync", "encryptedMetadata", "coordinatorBeacon",
        "verifyChallenge", "verifyResponse", "sessionGoodbye"
    ]

    /// Every token ``spelled(_:)`` gives the thirty fields under `spelling`, in declaration order.
    static func tokens(_ spelling: (String) -> String) -> [String] {
        // R2: bounded by the thirty names.
        fieldNames.map(spelling)
    }

    /// Mesh messages whose every token is `spelling` applied to its field's name.
    static func spelled(_ spelling: (String) -> String) -> ProximityNamespace.MeshMessages {
        ProximityNamespace.MeshMessages(
            descriptor: spelling("descriptor"), admissionGrant: spelling("admissionGrant"),
            admissionRequest: spelling("admissionRequest"), stateChange: spelling("stateChange"),
            friendVouchList: spelling("friendVouchList"), removalProposal: spelling("removalProposal"),
            removalSecond: spelling("removalSecond"), memberDeparture: spelling("memberDeparture"),
            memberAdmission: spelling("memberAdmission"), memberRemoval: spelling("memberRemoval"),
            terminated: spelling("terminated"), inventoryDigest: spelling("inventoryDigest"),
            epochHeads: spelling("epochHeads"), keyAgreement: spelling("keyAgreement"),
            removalProposalSigned: spelling("removalProposalSigned"), removalVote: spelling("removalVote"),
            routedManifest: spelling("routedManifest"), routedChunk: spelling("routedChunk"),
            custodyReceipt: spelling("custodyReceipt"), recipientReceipt: spelling("recipientReceipt"),
            routedInventoryDigest: spelling("routedInventoryDigest"),
            routedDrainAnswer: spelling("routedDrainAnswer"), keyRotation: spelling("keyRotation"),
            keyAck: spelling("keyAck"), rotationSync: spelling("rotationSync"),
            encryptedMetadata: spelling("encryptedMetadata"), coordinatorBeacon: spelling("coordinatorBeacon"),
            verifyChallenge: spelling("verifyChallenge"), verifyResponse: spelling("verifyResponse"),
            sessionGoodbye: spelling("sessionGoodbye")
        )
    }
}
