// MeshDialProofTests.swift
// ProximityKitTests
//
// 0.2.0's mesh dialer privacy (the owner's "Go A+B", 2026-11-15):
//
//   A. the dial proof (`MeshDialProof`) that runs before either hello. Its tag is mutual, per pair and
//      per tunnel; the frame always holds 24 tags whatever the candidate count; a responder matches a
//      friend's frame and refuses a stranger's or a malformed one; a dialer believes only the accept
//      of a key it proved; and the manager's candidates are the host's first, never its own key,
//      never twice;
//   B. the mesh `sid` is part of the posture: it rotates at a presence-epoch boundary and not inside
//      one.
//
// Pure values and the manager's own seams: nothing starts a radio.

import CryptoKit
import Foundation
@testable import ProximityKit
import Testing

/// The mesh dial proof and the rotating `sid`.
@Suite(.serialized) @MainActor struct MeshDialProofTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built.
    let keychain = PackageTestEnvironment.keychain

    /// **The pair key is mutual, and its tag is per tunnel.**
    @Test func theTagIsMutualPerPairAndPerTunnel() throws {
        let (alice, idA) = try provisioned()
        defer { ProximityKeychainItem.deleteAll(service: idA) }
        let (bob, idB) = try provisioned()
        defer { ProximityKeychainItem.deleteAll(service: idB) }
        let (carol, idC) = try provisioned()
        defer { ProximityKeychainItem.deleteAll(service: idC) }
        let ab = try alice.meshDialProofKey(with: bob.localKeyAgreementPublicKey)
        let ba = try bob.meshDialProofKey(with: alice.localKeyAgreementPublicKey)
        let ac = try alice.meshDialProofKey(with: carol.localKeyAgreementPublicKey)
        let one = Data(repeating: 0x5C, count: 32)
        let two = Data(repeating: 0x5D, count: 32)
        #expect(MeshDialProof.tag(key: ab, binding: one) == MeshDialProof.tag(key: ba, binding: one),
                "the two members of a pair derive different tags")
        #expect(MeshDialProof.tag(key: ab, binding: one) != MeshDialProof.tag(key: ac, binding: one),
                "two pairs share a tag")
        #expect(MeshDialProof.tag(key: ab, binding: one) != MeshDialProof.tag(key: ab, binding: two),
                "a tag replays into another tunnel")
        #expect(MeshDialProof.tag(key: ab, binding: one).count == MeshDialProof.tagByteCount)
        #expect(MeshDialProof.accept(key: ab, binding: one).prefix(MeshDialProof.tagByteCount)
                != MeshDialProof.tag(key: ab, binding: one), "an accept is a tag the dialer sent back")
        #expect(throws: IdentityError.invalidKeyData) { try alice.meshDialProofKey(with: Data([1, 2, 3])) }
    }

    /// **A frame is always 24 tags, whatever the candidate count.**
    @Test func theFrameIsAlwaysTwentyFourTags() throws {
        let binding = Data(repeating: 0x5C, count: 32)
        for count in [0, 1, 3, 24, 30] {
            let keys = (0..<count).map { _ in SymmetricKey(size: .bits256) }
            let frame = MeshDialProof.frame(keys: keys, binding: binding)
            #expect(frame.isWellFormed && frame.tags.count == MeshDialProof.slotCount,
                    "\(count) candidates sent \(frame.tags.count) tags")
            let encoded = try JSONEncoder().encode(frame)
            #expect(encoded.count <= MeshChannelIntroductionFormat.maxFrameByteCount)
        }
    }

    /// **A responder matches a friend, refuses a stranger, and refuses a malformed frame.**
    @Test func theResponderMatchesAFriendAndNoOneElse() {
        let binding = Data(repeating: 0x5C, count: 32)
        let friend = SymmetricKey(size: .bits256)
        let others = (0..<5).map { _ in SymmetricKey(size: .bits256) }
        let frame = MeshDialProof.frame(keys: others + [friend], binding: binding)
        #expect(MeshDialProof.match(frame, keys: [SymmetricKey(size: .bits256), friend], binding: binding) == 1,
                "a friend's frame was not matched")
        #expect(MeshDialProof.match(frame, keys: [SymmetricKey(size: .bits256)], binding: binding) == nil,
                "a stranger was matched")
        #expect(MeshDialProof.match(frame, keys: [friend], binding: Data(repeating: 0x5D, count: 32)) == nil,
                "a frame relayed from another tunnel was matched")
        let short = MeshDialProof.Frame(version: MeshDialProof.version, tags: Array(frame.tags.dropLast()))
        #expect(MeshDialProof.match(short, keys: [friend], binding: binding) == nil, "a 23-tag frame was read")
        let old = MeshDialProof.Frame(version: 1, tags: frame.tags)
        #expect(MeshDialProof.match(old, keys: [friend], binding: binding) == nil, "a wrongly versioned frame was read")
    }

    /// **A dialer believes only the accept of a key it proved, on this tunnel.**
    @Test func theDialerBelievesOnlyTheRightAccept() {
        let binding = Data(repeating: 0x5C, count: 32)
        let keys = (0..<3).map { _ in SymmetricKey(size: .bits256) }
        let right = MeshDialProof.Accept(version: MeshDialProof.version,
                                         proof: MeshDialProof.accept(key: keys[2], binding: binding))
        #expect(MeshDialProof.verify(right, keys: keys, binding: binding) == 2)
        let elsewhere = MeshDialProof.Accept(
            version: MeshDialProof.version,
            proof: MeshDialProof.accept(key: keys[2], binding: Data(repeating: 0x5D, count: 32)))
        #expect(MeshDialProof.verify(elsewhere, keys: keys, binding: binding) == nil, "another tunnel's accept was believed")
        let forged = MeshDialProof.Accept(version: MeshDialProof.version,
                                          proof: Data(repeating: 0, count: MeshDialProof.acceptByteCount))
        #expect(MeshDialProof.verify(forged, keys: keys, binding: binding) == nil, "a forged accept was believed")
    }

    /// **The manager's candidates: the host's first, never its own key, never twice.**
    @Test func theManagersCandidatesAreTheHostsFirstAndNeverItsOwn() throws {
        let host = PackageTestHost()
        let manager = MeshNetworkManager(store: host)
        let own = manager.identityKeyAgreementPublicKeyForTesting
        let friend = Data(repeating: 0x0A, count: 32)
        let tapped = Data(repeating: 0x0B, count: 32)
        manager.dialProofPeerKeyAgreementKeys = [friend, own, tapped, friend, Data()]
        #expect(manager.dialProofKeyAgreementKeys == [friend, tapped], "\(manager.dialProofKeyAgreementKeys)")
        try host.tearDown()
    }

    /// **The `sid` rotates at an epoch boundary, and not inside an epoch.**
    @Test func theSessionIDRotatesAtAnEpochBoundaryOnly() throws {
        let host = PackageTestHost()
        let manager = MeshNetworkManager(store: host)
        let first = manager.sessionIDForTesting
        #expect(!manager.rotateSessionIDIfNeeded(at: Date()), "the sid rotated inside its own epoch")
        #expect(manager.sessionIDForTesting == first)
        #expect(manager.rotateSessionIDIfNeeded(at: Date().addingTimeInterval(IdentityService.presenceEpochSeconds)),
                "the sid outlived its epoch")
        #expect(manager.sessionIDForTesting != first && manager.currentDiscoveryInfo()["sid"] == manager.sessionIDForTesting,
                "the advertised sid is not the rotated one")
        try host.tearDown()
    }

    // MARK: - Helpers

    private func provisioned() throws -> (IdentityService, String) {
        let service = "org.example.pktest.identity.dialproof.\(UUID().uuidString)"
        let identity = IdentityService(keychainService: service)
        try identity.ensureProvisioned()
        return (identity, service)
    }
}
