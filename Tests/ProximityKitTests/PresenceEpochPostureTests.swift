// PresenceEpochPostureTests.swift
// ProximityKitTests
//
// P9 item 2 pass 1 (Docs/Plan-ProximityKit-Network-Migration-2026-08-27.md §17.1): the presence
// radio's EPHEMERAL POSTURE as a tier-1 value — a fresh TLS identity and a randomized instance
// name per 900 s presence epoch, so two sightings 901 seconds apart are not linkable.
//
// The rotation table is the test. Over a table of instants (epoch start, mid, 899.999, 900,
// 900.001, 1800 and a wrap 100 000 epochs ahead) the name and the certificate are stable inside an
// epoch and BOTH change at every boundary; across two epochs nothing is derivable — no counter, no
// shared half, no length that encodes the epoch, and no byte that comes from the device. The two
// non-derivability claims that could otherwise only be argued probabilistically are made exactly,
// by holding the entropy fixed and showing the name does not move with the epoch, and by holding
// the epoch fixed and showing it does move with the entropy. A third exact claim covers the one
// field of the posture that is NOT random: the certificate's validity window is anchored to the
// epoch's START, so a device that switches presence on ten minutes in carries byte-identical
// `notBefore`/`notAfter` to one that rotated on the boundary, and cannot be picked out by them.
//
// Tier 1: no rig, no radio, no simulator, no clock — every instant is an injected `Date` and every
// random draw is an injected closure.

import Foundation
import Security
import Testing
@testable import ProximityKit

@Suite(.serialized)
struct PresenceEpochPostureTests {

    // MARK: - The rotation table

    /// Exactly on a 900 s multiple since 1970: `1_800_000_000 == 900 * 2_000_000`, so the anchor is
    /// an epoch START and the table's offsets are offsets into a known epoch.
    static let anchor = Date(timeIntervalSince1970: 1_800_000_000)
    static let anchorEpoch: UInt64 = 2_000_000

    /// One row of the rotation table: an offset from ``anchor`` and the epoch it must land in.
    struct Instant {
        let offset: TimeInterval
        let epoch: UInt64
        let what: String
    }

    static let table: [Instant] = [
        Instant(offset: 0, epoch: anchorEpoch, what: "epoch start"),
        Instant(offset: 450, epoch: anchorEpoch, what: "mid-epoch"),
        Instant(offset: 899.999, epoch: anchorEpoch, what: "the last instant of the epoch"),
        Instant(offset: 900, epoch: anchorEpoch + 1, what: "the boundary itself"),
        Instant(offset: 900.001, epoch: anchorEpoch + 1, what: "just past the boundary"),
        Instant(offset: 1800, epoch: anchorEpoch + 2, what: "two boundaries on"),
        Instant(offset: 900 * 100_000, epoch: anchorEpoch + 100_000, what: "a wrap far ahead")
    ]

    static func instant(_ row: Instant) -> Date { anchor.addingTimeInterval(row.offset) }

    /// A deterministic entropy source: the same bytes every draw, so a difference between two
    /// names can only have come from something OTHER than the entropy.
    static func fixedEntropy(_ seed: UInt8) -> (Int) -> [UInt8] {
        { count in Array(repeating: seed, count: count) }
    }

    /// The table is walked ONCE, carrying the posture through `rotated(at:)` exactly as the manager
    /// does. Inside an epoch neither the name nor the certificate may move; at a boundary BOTH must.
    @Test func theRotationTableRotatesNameAndIdentityExactlyAtTheBoundaries() throws {
        var posture = try PresenceEpochPosture.minted(at: Self.instant(Self.table[0]))
        var previous = Self.table[0]

        #expect(posture.epoch == Self.anchorEpoch, "the anchor is an epoch start by construction")

        for row in Self.table.dropFirst() {
            let before = posture
            posture = try posture.rotated(at: Self.instant(row))

            #expect(posture.epoch == row.epoch, "\(row.what): epoch \(posture.epoch) != \(row.epoch)")

            if row.epoch == previous.epoch {
                #expect(posture.instanceName == before.instanceName,
                        "\(row.what): the name must not move inside an epoch")
                #expect(posture.tlsIdentity.certificateDER == before.tlsIdentity.certificateDER,
                        "\(row.what): the identity must not move inside an epoch")
            } else {
                #expect(posture.instanceName != before.instanceName,
                        "\(row.what): the name must rotate at the boundary")
                #expect(posture.tlsIdentity.certificateDER != before.tlsIdentity.certificateDER,
                        "\(row.what): the identity must rotate at the boundary")
            }
            previous = row
        }
    }

    /// The rotation is total: over the table's four distinct epochs no name and no certificate is
    /// ever reused, and no name carries a half, a length or a digit of another.
    @Test func nothingSurvivesAnEpochBoundary() throws {
        var epochs: [UInt64] = []
        var names: [String] = []
        var certificates: [Data] = []
        var posture = try PresenceEpochPosture.minted(at: Self.instant(Self.table[0]))
        epochs.append(posture.epoch)
        names.append(posture.instanceName)
        certificates.append(posture.tlsIdentity.certificateDER)

        for row in Self.table.dropFirst() where row.epoch != posture.epoch {
            posture = try posture.rotated(at: Self.instant(row))
            epochs.append(posture.epoch)
            names.append(posture.instanceName)
            certificates.append(posture.tlsIdentity.certificateDER)
        }
        #expect(epochs == [Self.anchorEpoch, Self.anchorEpoch + 1, Self.anchorEpoch + 2,
                           Self.anchorEpoch + 100_000],
                "the table crosses four distinct epochs, in order")

        #expect(Set(names).count == names.count, "no instance name is reused across epochs")
        #expect(Set(certificates).count == certificates.count, "no certificate is reused across epochs")
        #expect(Set(names.map(\.count)).count == 1, "every name is the same length — length encodes nothing")

        let prefixLength = ProximityNamespace.packageTest.family.radios.presenceInstanceNamePrefix.count
        let randomHalves = names.map { String($0.dropFirst(prefixLength)) }
        #expect(Set(randomHalves).count == randomHalves.count, "the random halves are not reused either")

        // No name spells the epoch index it was minted at. (The prefix/suffix pair that used to
        // stand here could not fire: names asserted equal-length and distinct above can never be
        // one another's prefix or suffix. The exact non-derivability claim is the cell below.)
        for (index, name) in names.enumerated() {
            #expect(!name.contains(String(epochs[index])), "the name spells its epoch index in decimal")
            #expect(!name.contains(String(epochs[index], radix: 16)), "the name spells its epoch index in hex")
        }
    }

    // MARK: - Non-derivability, made exactly rather than probabilistically

    /// Hold the entropy fixed and move the clock a hundred thousand epochs: the name does not
    /// change. That is the exact form of "no counter, no epoch index, no timestamp byte" — anything
    /// derived from the epoch would have to move here, and nothing does.
    @Test func theNameIsAFunctionOfItsEntropyAloneAndNeverOfTheEpoch() throws {
        let entropy = Self.fixedEntropy(0xA5)
        let mint: (Date) throws -> EphemeralMeshTLSIdentity.Minted = { try EphemeralMeshTLSIdentity.mint(now: $0) }

        let first = try PresenceEpochPosture.minted(at: Self.anchor, entropy: entropy, mintIdentity: mint)
        let far = try PresenceEpochPosture.minted(
            at: Self.anchor.addingTimeInterval(900 * 100_000),
            entropy: entropy,
            mintIdentity: mint
        )
        #expect(first.epoch != far.epoch, "the two postures really are at different epochs")
        #expect(first.instanceName == far.instanceName,
                "the same entropy must produce the same name at any epoch — otherwise the epoch is in the name")

        // ...and the converse: the same clock with different entropy must differ.
        let sibling = try PresenceEpochPosture.minted(
            at: Self.anchor,
            entropy: Self.fixedEntropy(0x5A),
            mintIdentity: mint
        )
        #expect(sibling.epoch == first.epoch)
        #expect(sibling.instanceName != first.instanceName,
                "two devices at the same epoch must not share a name — the entropy is the whole name")

        // The certificate is NOT a function of the name's entropy: it has its own CSPRNG draw, so
        // even a caller who fixes the entropy cannot fix the identity.
        #expect(first.tlsIdentity.certificateDER != far.tlsIdentity.certificateDER)
        #expect(first.tlsIdentity.certificateDER != sibling.tlsIdentity.certificateDER)
    }

    /// The name's shape: the host's frozen service token, its separator included, which every device
    /// carries identically (`.packageTest`'s `pk-` here), and then entropy of a stated size and nothing
    /// else.
    @Test func theNameIsAFrozenServiceTokenPlusStatedEntropy() throws {
        let prefix = ProximityNamespace.packageTest.family.radios.presenceInstanceNamePrefix
        #expect(PresenceEpochPosture.instanceNameEntropyByteCount == 8, "the stated size: 64 bits")
        #expect(PresenceEpochPosture.instanceNameLength(prefix: prefix) == 2 + 1 + 16)

        var names: Set<String> = []
        // R2: bounded.
        for _ in 0..<32 {
            let name = try PresenceEpochPosture.instanceName(prefix: prefix, entropy: PresenceEpochPosture.systemEntropy)
            #expect(name.hasPrefix(prefix), "every instance carries the SAME frozen prefix")
            #expect(name.count == PresenceEpochPosture.instanceNameLength(prefix: prefix))
            let half = name.dropFirst(prefix.count)
            #expect(half.count == 2 * PresenceEpochPosture.instanceNameEntropyByteCount)
            #expect(half.allSatisfy { $0.isHexDigit && !$0.isUppercase },
                    "the random half is lowercase hexadecimal and nothing else")
            names.insert(name)
        }
        #expect(names.count == 32, "32 draws from the system CSPRNG must not collide")
    }

    /// The entropy is validated at entry rather than padded: a source that under-delivers is
    /// refused, because a short name is a weaker name for a whole epoch and nothing would say so.
    @Test func aShortEntropyDrawIsRefusedRatherThanAdvertised() {
        #expect(throws: PresencePostureError.entropyUnavailable(byteCount: 3)) {
            _ = try PresenceEpochPosture.instanceName(entropy: { _ in [0x01, 0x02, 0x03] })
        }
        #expect(throws: PresencePostureError.entropyUnavailable(byteCount: 0)) {
            _ = try PresenceEpochPosture.instanceName(entropy: { _ in [] })
        }
        #expect(PresenceEpochPosture.systemEntropy(PresenceEpochPosture.instanceNameEntropyByteCount).count
            == PresenceEpochPosture.instanceNameEntropyByteCount)
        #expect(PresenceEpochPosture.systemEntropy(0).isEmpty, "a zero draw is empty, not a trap")
        #expect(PresenceEpochPosture.systemEntropy(PresenceEpochPosture.maxEntropyByteCount + 1).isEmpty,
                "an unbounded draw is refused, not attempted (R2)")
        #expect(!PresencePostureError.entropyUnavailable(byteCount: 3).diagnosticDescription.isEmpty)
    }

    // MARK: - The TLS identity

    /// The identity comes through the module's ONE certificate path: its certificate parses, and
    /// its subject is the host's shared common name (`.packageTest`'s `pktest-mesh`) rather than anything
    /// about this device.
    @Test func theTLSIdentityIsTheOneCertificatePathAndNamesNoDevice() throws {
        let radios = ProximityNamespace.packageTest.family.radios
        let posture = try PresenceEpochPosture.minted(
            at: Self.anchor, instanceNamePrefix: radios.presenceInstanceNamePrefix, commonName: radios.tlsCommonName)
        guard let certificate = SecCertificateCreateWithData(nil, posture.tlsIdentity.certificateDER as CFData) else {
            Issue.record("the posture's certificate is not one Security will parse")
            return
        }
        guard let summary = SecCertificateCopySubjectSummary(certificate) else {
            Issue.record("the posture's certificate has no readable subject")
            return
        }
        #expect(summary as String == radios.tlsCommonName,
                "the subject is a shared protocol token — a device-derived subject would re-link")
        #expect(!(summary as String).contains(posture.instanceName),
                "and it does not carry the advertised name either")
    }

    /// The DER a certificate's validity window is encoded as, built with the module's OWN encoder
    /// rather than read back out of a certificate: the claim below is about the bytes on the wire,
    /// and a hand-rolled DER reader in a test would just be a second parser to get wrong.
    static func validityDER(anchoredAt instant: Date) -> [UInt8] {
        MeshCertificateDER.sequence(
            MeshCertificateDER.utcTime(instant.addingTimeInterval(-EphemeralMeshTLSIdentity.clockSkewSeconds))
                + MeshCertificateDER.utcTime(instant.addingTimeInterval(EphemeralMeshTLSIdentity.lifetimeSeconds))
        )
    }

    /// The certificate is minted at the EPOCH'S START, never at the instant the mint happens.
    ///
    /// `EphemeralMeshTLSIdentity.mint(commonName:now:)` writes its instant into the certificate as
    /// `notBefore = now − clockSkewSeconds` and `notAfter = now + lifetimeSeconds`, at one-second
    /// resolution — and the transport's validator accepts any certificate, so both fields are
    /// readable by every device in range. Anchored to the mint instant they would say which second
    /// this radio came up, and would single this device out for the rest of the epoch: exactly
    /// what the synchronised rotation in reason 3 of the type's doc exists to prevent. So the
    /// window must be a CONSTANT of the epoch, identical on a device that started at its first
    /// second and one that started ten minutes in.
    @Test func theCertificateIsMintedAtTheEpochStartAndNeverAtTheMintInstant() throws {
        var mintInstants: [Date] = []
        let recording: (Date) throws -> EphemeralMeshTLSIdentity.Minted = { instant in
            mintInstants.append(instant)
            return try EphemeralMeshTLSIdentity.mint(now: instant)
        }

        // Two devices that switch presence on 27 s and 613 s into the SAME epoch.
        let early = try PresenceEpochPosture.minted(
            at: Self.anchor.addingTimeInterval(27), entropy: Self.fixedEntropy(0x3C), mintIdentity: recording)
        let late = try PresenceEpochPosture.minted(
            at: Self.anchor.addingTimeInterval(613), entropy: Self.fixedEntropy(0xC3), mintIdentity: recording)

        #expect(early.epoch == late.epoch, "the two instants really are inside one epoch")
        #expect(early.instanceName != late.instanceName, "and the two devices are otherwise distinct")
        #expect(mintInstants == [Self.anchor, Self.anchor],
                "the mint instant handed to the certificate path is the epoch START — `now` never reaches it")

        let shared = Data(Self.validityDER(anchoredAt: Self.anchor))
        #expect(early.tlsIdentity.certificateDER.range(of: shared) != nil,
                "the early device's certificate carries the epoch's own validity window")
        #expect(late.tlsIdentity.certificateDER.range(of: shared) != nil,
                "and the late device's carries the identical bytes — neither is singled out by its window")

        // A rotation at an arbitrary instant inside the NEXT epoch anchors to that epoch's start,
        // which is also the only production caller shape `rotated(at:entropy:mintIdentity:)` has.
        let rotated = try early.rotated(
            at: Self.anchor.addingTimeInterval(IdentityService.presenceEpochSeconds + 431),
            entropy: Self.fixedEntropy(0x3C),
            mintIdentity: recording
        )
        #expect(rotated.epoch == early.epoch + 1)
        #expect(mintInstants.last == Self.anchor.addingTimeInterval(IdentityService.presenceEpochSeconds),
                "the boundary mint anchors to the new epoch's start, not to the 431st second of it")
        #expect(rotated.tlsIdentity.certificateDER.range(of: shared) == nil,
                "and the window rotated with it — the next epoch's certificate is not valid from this one's start")
    }

    // MARK: - Source walls

    /// The value's source, code lines only (`///` and `//` dropped), so a doc sentence about 900
    /// seconds or about the device cannot satisfy — or break — the greps below.
    static func postureCodeLines() throws -> [String] {
        let url = PackageRoot.url
            .appendingPathComponent("Sources/ProximityKit/Presence/PresenceEpochPosture.swift")
        let lines = try String(contentsOf: url, encoding: .utf8).components(separatedBy: .newlines)
        let code = lines.filter {
            let trimmed = $0.trimmingCharacters(in: .whitespaces)
            return !trimmed.hasPrefix("//") && !trimmed.isEmpty
        }
        #expect(code.count > 40, "the wall must be scanning the real file, not an empty one")
        return code
    }

    /// One epoch length, one clock. The posture declares no 900 of its own and derives its epoch
    /// from `IdentityService.presenceEpoch(at:)` — the same counter the tags use — so the posture
    /// and the payload can never rotate on two different phases.
    @Test func thePostureDeclaresNoSecondEpochLengthAndNoSecondClock() throws {
        let code = try Self.postureCodeLines()
        #expect(IdentityService.presenceEpochSeconds == 900, "the one named constant")
        #expect(!code.contains { $0.contains("900") },
                "the posture must not write 900 down again — IdentityService.presenceEpochSeconds is the one home")
        #expect(code.contains { $0.contains("IdentityService.presenceEpoch(at:") },
                "the epoch comes from the presence clock, not from arithmetic done here")
        #expect(!code.contains { $0.contains("Date()") },
                "every instant is injected — the value reads no clock of its own")
        #expect(!code.contains { $0.contains("Task") || $0.contains("Timer") || $0.contains("sleep") },
                "a value schedules nothing")
    }

    /// Nothing about the device reaches the posture, and nothing about the posture reaches disk.
    /// A grep rather than a sample of call paths: a future edit that reaches for the device name or
    /// the keychain must fail here rather than rely on a reviewer remembering the claim.
    @Test func noByteOfThePostureComesFromTheDeviceOrGoesToDisk() throws {
        let code = try Self.postureCodeLines()
        // The vendor-identifier symbol is deliberately NOT spelled here: `NoTrackingBoundaryTests`
        // bans it in every file of every kind repo-wide, INCLUDING comments, so naming it would
        // only indict this suite (it did, once). `UIDevice` below is the only door to it, and the
        // import assertion at the end of this cell closes even that.
        let forbidden = [
            "UIDevice", "ProcessInfo", "hostName", "Host.current",
            "fingerprint", "Keychain", "KeychainItem", "SecItem", "kSecAttrService",
            "UserDefaults", "FileManager", "write(to:", "JSONSidecarFile",
            "MCPeerID", "localPeerID", "bundleIdentifier", "meshID", "localMeshID",
            "signingPublicKey", "keyAgreementPublicKey", "presenceTag", "localizedString"
        ]
        for marker in forbidden {
            #expect(!code.contains { $0.contains(marker) },
                    "PresenceEpochPosture must not reach for '\(marker)' — the posture is entropy and a clock, nothing else")
        }
        let imports = code.filter { $0.hasPrefix("import ") }
        #expect(imports == ["import Foundation"],
                "the value imports Foundation only — no UIKit, no MultipeerConnectivity, no Security of its own")
    }
}
