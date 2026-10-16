// CrossVersionFixtureTests.swift
// ProximityKitTests
//
// ProximityKit plan step A2: the bytes a released tag wrote, read back by the code of today. Each wire
// and on-disk format ProximityKit owns has fixtures under `Fixtures/<tag>/`, generated ONCE from that
// tag's own code and committed with their SHA-256 pinned here, and each cell decodes its fixtures with
// the current code and asserts what they hold: the fields, the signatures under the namespace's
// labels, the seals opening with the keys the tag stored, the re-encodings of the deterministic
// encodings byte for byte, and the refusals of the retired formats. A wire or on-disk break therefore
// fails here, in this repository, before a tag exists, instead of first in a host's re-pin of the tag
// (tags never move). Not here: the session coordinator's own introduction and heartbeat payloads,
// private types only a running session reads, and the `FMGM2` metadata seal, which 0.1.0 opens but
// never writes.
//
// `Fixtures/0.1.0/` is tag 0.1.0 (6648094f): generated once under `.packageTest`
// (TestSupport/PackageTestNamespace.swift) on a tree whose `Sources/` was `git archive 0.1.0`, by a
// throwaway generator that is not part of this repository, on 2026-10-15. Its cast is four identities
// 0.1.0 minted into the in-memory keychain (Alice, Bob, Carol and Dave) and two seal keys Bob's
// stores minted, and `keychain-rows.json` holds those rows exactly as 0.1.0 wrote them (service,
// account, accessibility class, sync flag, bytes), so every signature, seal and sealed file below is
// checked against the keys that made it. Every byte is 0.1.0's own output but two signatures:
// 0.1.0 verifies a schema-1 envelope and a legacy-signed admission token but cannot mint either (its
// identity refuses to sign under the verify-only legacy label), so the generator signed those two
// with the private key from the rows, over 0.1.0's own `legacyCanonicalBytes`, as a pre-WI-6 peer did.
// The retired column formats are 0.1.0's sealed session file with its marker replaced (v2) or dropped
// (unprefixed), the shapes those retired writers left on disk.
//
// THE RULE (README "Versioning", CHANGELOG.md): a fixture folder is never regenerated or edited. A
// digest that stops matching is a fixture someone changed, and the change is reviewed as a change to
// this file's pin. A later tag adds `Fixtures/<tag>/` and its own cells beside these; every older
// folder keeps decoding, because a new format is added beside the old one and only retiring a reader
// is a break (a `y` bump while the version is 0.y). The test bundle carries the folder as a resource
// (`Package.swift`, `resources: [.copy("Fixtures")]`, which `Scripts/manifest-scan.py` holds), so the
// cells read it through `Bundle.module` on every test lane, the iOS simulator's included.

import CryptoKit
import Foundation
@testable import ProximityKit
import Security
import Testing

/// Tag 0.1.0's wire and on-disk bytes decode, verify and open with today's code: the folder is exactly
/// its pinned bytes, and one cell per format family reads it.
///
/// **Isolation.** A cell that needs a key seeds the fixture's keychain rows under services of its own
/// (the fixture's service plus this instance's ``cell``), so cells running in parallel never share or
/// delete one another's rows, and a cell that opens an on-disk fixture copies it into a scratch folder
/// of its own first. The keys, accounts, accessibility classes and bytes are the fixture's, unchanged.
@MainActor
@Suite struct CrossVersionFixtureTests {

    /// The bundle's in-memory keychain, read as each cell's suite instance is built, so the installer has
    /// run before a cell seeds a row or provisions an identity.
    let keychain = PackageTestEnvironment.keychain

    /// This instance's suffix, appended to every keychain service a cell seeds and to its scratch folder.
    let cell = UUID().uuidString

    /// Every fixture file under the bundle's `Fixtures` folder, by its path there, with its SHA-256, as
    /// generated. A file added, removed, regenerated or edited fails ``everyFixtureIsExactlyItsPinnedBytes()``.
    let digests: [String: String] = [
        "0.1.0/channel-hello-initiator.bin": "35f45fb931ba84171f15ee9bda8496fad6e4ad1e61a0e210d61d3da6a8db438e",
        "0.1.0/channel-hello-responder.bin": "9f2b982381b07bf210093257ffa51c12b709bb3523219af2d4a46c515595c34e",
        "0.1.0/channel-introduction.bin": "1b50c5d411b4a4112cfe7a38e29d281f1e14a89dcb0347a2c6bada5274c89ab2",
        "0.1.0/column-unprefixed.sealed": "87820dfe97fd7b1c52758c1459b2dd519402d7bcead09ccb52222a6075bcb466",
        "0.1.0/column-v2-marked.sealed": "235d88cc61b0830f631b71f68733ae1705b06d580a4abb45d06122159c7ae080",
        "0.1.0/framed-labels.json": "13c7e0bd802dc7f412569f4f527d85b7040b03f62cddb7941370aab08ec533fd",
        "0.1.0/identity-envelope-sealed-legacy.json": "b257a7d74476593c4518ca87d8e2710212582a928f2597d9aefdd0ab597324a8",
        "0.1.0/identity-envelope-sealed-wire2.json": "998ef14503f2d46fcadc4c3cb74e1f320c0dd09fca00d653ff6c8f4c85c84dfb",
        "0.1.0/identity-envelope-v1.json": "81c8190a4b41523c1dcbdb475fa1879c54a7f668351b7328de9354ce3bca0039",
        "0.1.0/identity-envelope-v2.json": "53be4a9e06344fffb830b9811dcba928798f3fd2ea87005557fe37612b5b323d",
        "0.1.0/keychain-rows.json": "747e8c9a7014d27fd4c178061f54500dd89f2ee2b6a3b632d9a023671e1ffde7",
        "0.1.0/membership-admission-alice.json": "0f6a2097bdf30fb8178e64d1832d219f0abd7f23019ef6e3d6e96214efb3f30a",
        "0.1.0/membership-admission-bob.json": "8d4b37c212fc84a88782560ae6f3f9b13b6d868a5bcdc3db3ac7dc5da52d757c",
        "0.1.0/membership-admission-carol.json": "3524cdc757965e4681906160145076b68e798e12b431819ee8432bd841a30e96",
        "0.1.0/membership-admission-dave.json": "22a5ec227e37474bb373b5992625be17aed0f9c5fca42d6cde72bb33d8ac3ddb",
        "0.1.0/membership-departure.json": "db24642bbe93ce93d2188f7b8770fde6f3b63b75d7a8b2d2c15b39726dd85431",
        "0.1.0/membership-epoch-heads.json": "f422995f80807db4d22bca780665a3a3efde04e8d868755bda6c7660f1e5b548",
        "0.1.0/membership-inventory-digest.json": "d525db01a471c5e6bafa5cb32a3d9c11defbdef9c04857e1f19c879f17e497d1",
        "0.1.0/membership-key-agreement.json": "6b6d4e900bc3008f2da2450e61ad473814654264537be7ee9ac37ea9e3d10491",
        "0.1.0/membership-removal-proposal.json": "327eef6ea0e092c109148907f9a7de3b5d568ef7ec218dbccab02905ddd02a30",
        "0.1.0/membership-removal-vote-bob.json": "f7453c43762e8d4d6cf5a095844ced9a5fe25df2fd66a2e4f05e86f6f59b474a",
        "0.1.0/membership-removal-vote-carol.json": "01f0b5889d771792dbb5756da6e70f1a616e47595866af1b8200842e5d12efb3",
        "0.1.0/membership-removal.json": "c54527e7380e5a8715bf104ac0106ac78362d062ad3b9636024bde2af32f4048",
        "0.1.0/membership-termination.json": "c0038494b907f52644a527c94d80feb17649b7c407a8121d66315e406b66eab9",
        "0.1.0/mesh-admission-grant.json": "34d0053995d2f8ac6c303d9b424c8bc8d324c9bf183fac180a931d3ca08209b6",
        "0.1.0/mesh-admission-request.json": "fe77a6b43e007d69baa1640df200c67e503019fb3b0dbe566fa5f73e592da0ff",
        "0.1.0/mesh-admission-token-v1.json": "59039ca4c8030a4c064d548779da2d9b8eea424ebcc636ec593a91a546d8fb49",
        "0.1.0/mesh-coordinator-beacon.json": "6f12f50340bd4d2470e6a52660a49f1b39274533d4bd538e01d9f54083697dbc",
        "0.1.0/mesh-key-ack.json": "f5a7834916a9f55ca2bdb3a094eb5da722ed9c0a2b41006ea3c796030cf6537b",
        "0.1.0/mesh-key-rotation.json": "9c11f2a75dc0c24d1b63c746535fc516383fe59a47e95ed9a676dc63f9be2556",
        "0.1.0/mesh-removal-proposal.json": "960a312a0220db360da4233a4dd0d2cd29590de480a1408591e903afaa892581",
        "0.1.0/mesh-removal-second.json": "05f8ca82aa89c7fe9edc69858727c6b3869ab627f743fb508f2fcf5630e8f4a1",
        "0.1.0/mesh-rotation-sync.json": "a6aad5e145ba9ed1858bdd22dd42d656fa748743a33cac24149bea3048d40dc2",
        "0.1.0/mesh-state-change.json": "b38174a6ce38acb2723f5fa74dd2594990ea8007b6161370bef88df3c9fec216",
        "0.1.0/mesh-vouch-list.json": "add99a04fcbf32acc373c8be4cdd20e526319c649f1e36c8496dd1667432e604",
        "0.1.0/mesh-wire-frame.bin": "005b8ad3ca6d33c69d8b9630fe2fe6b34d28f1f5b6b335e8a8bf9bd80730471b",
        "0.1.0/pair-dial-hello.json": "96350f34e812904d9b97816e8eb18796e384eae18a1001d22e6ea038183f7ea6",
        "0.1.0/prekey-bundle.json": "7cbca2cd0a6e5723b78b6d170374e25f9d2e02960ff08c7339965958489fbf26",
        "0.1.0/presence-dial-hello.json": "1a0e6a4da3f018c230db0b97db5db0a7f4fe230bb2e2c6523c2d13eb9e8cf5d3",
        "0.1.0/protected-sidecar.json": "63eeef8bf01eba9bbb14f440d6cddb361a861edd10e3f3beaf7c9bd09e0e1876",
        "0.1.0/routed-chunk.json": "6b4d16a1b2cef42374efcbfb86fb2cbf5ba31660cb9ef15ac1593e9f4f054523",
        "0.1.0/routed-custody-receipt.json": "fed0535d7226302d6f8dd86c76fb39dfebe52af50fa742113cda4893c4a40751",
        "0.1.0/routed-drain-answer.json": "3cf229b2632138c3c4ac2a06803c434267274499b58b2333e87be3a7084e0530",
        "0.1.0/routed-inventory.json": "574503ad8c979f337563e2f0be1f690e22a41093dc3184e60b853122d31d1d42",
        "0.1.0/routed-manifest.json": "3ba02e2f318b37ed4713cc872bdb4c9fe141435044a0a6d97f2329d9c6a87f28",
        "0.1.0/routed-recipient-receipt.json": "d3891d2e062833d860785152373db8ac0df500d396355029907e4ad50cc77963",
        "0.1.0/routed-store/Routed.sealed": "c6f3edc2419783619033f13aac280ec33bd1d973baa37c6c13bcb855eaa5445d",
        "0.1.0/routed-store/RoutedChunks/D6779744-61C6-4A81-8250-7D8ED6A02B13.chunk": "d192f1342577acf1a81b8e306657c4adc4f5836644a240f0ca265dc9360507a6",
        "0.1.0/sealed-frame-deflate.bin": "94e9f2d983e07676eb96163977a482e0e38ac51281a0120b92d1e8ad6410af31",
        "0.1.0/sealed-frame-raw.bin": "5b6871ea3931221684994272436e5919ce85de85b9025f0a9f9af483489d55f4",
        "0.1.0/sealed-introduction.json": "4493c4713d7f6d896f76d6af99edc26394e2e71a536e1786382818e89178aa4a",
        "0.1.0/session-store/Session.sealed": "f7ae276c628bbe7cdcfbc9a6af6cf2ce901fcbd06ac7cc05d5d2b8dbfe681c75",
        "0.1.0/txt-records.json": "c49c626f99ddd93de562da1fc5ec2f3ef296a721087709520c55402108cb92ae"
    ]

    /// The fewest fixture files the folder walk may read: the 53 of 0.1.0. A walk that reads fewer is a
    /// bundle that lost its resources, not a smaller format list.
    let fixtureFloor = 53

    // MARK: - 0.1.0's world

    /// The fingerprints 0.1.0 derived for the cast's signing keys, which
    /// ``theKeychainRowsAdoptAsTheIdentitiesTheyWere()`` re-derives from the rows: Alice founded the mesh
    /// and originated the routed item, Bob is the custodian and recipient whose stores are on disk, Carol
    /// departed, and Dave was removed.
    let alice = "bed3ec5f2fbe494b", bob = "d9c3377b65a9c11b", carol = "56d314f3caa1a152", dave = "831da20f0430755b"

    /// The generation's instants: 2026-10-15T12:00:00Z, and the far expiry of the envelopes that carry one.
    let base = Date(timeIntervalSince1970: 1_792_065_600)
    let farFuture = Date(timeIntervalSince1970: 4_102_444_800)

    /// The mesh's id and the routed item's id.
    var meshID: UUID { Self.id(1) }
    var itemID: UUID { Self.id(2) }

    /// Bob's stores' install binding, 0.1.0's seal key services, and the routed type the item carries.
    let binding = Data(repeating: 0xA5, count: 16)
    let sessionSealService = "org.example.pktest.mesh-session.fixture.bob"
    let routedSealService = "org.example.pktest.mesh-routed.fixture.bob"
    let tempMessage = "pktest.routed.note.v1"

    /// The plaintexts 0.1.0 sealed: a wire2 note (long enough to deflate), a legacy-framed note, and the
    /// routed note.
    let wirePlaintext = Data(String(repeating: "A wire2 note sealed to Bob, framed and deflated by 0.1.0. ", count: 4).utf8)
    let legacyPlaintext = Data("A note sealed to Bob with no wire2 framing.".utf8)
    let routedPlaintext = Data(String(repeating: "A routed note from Alice to Bob and Carol. ", count: 5).utf8)

    /// The ids the generation named: `C0FFEE00-0000-4000-8000-` and `n` as twelve hex digits.
    static func id(_ number: Int) -> UUID {
        UUID(uuidString: String(format: "C0FFEE00-0000-4000-8000-%012X", number)) ?? UUID()
    }

    // MARK: - The folder

    /// **The folder is exactly its pinned bytes.** Every file under the bundle's `Fixtures` folder (a
    /// name starting with `.` is no fixture) is on ``digests`` and every pinned path is there, at least
    /// ``fixtureFloor`` of them, and each file's SHA-256 is its pin. Regenerating or editing a fixture
    /// fails here, so it happens only as a reviewed change to the pin.
    @Test func everyFixtureIsExactlyItsPinnedBytes() throws {
        let root = try fixturesFolder()
        let found = try fixtureFiles(under: root)
        #expect(found.count >= fixtureFloor, """
            read \(found.count) fixture files, below the floor of \(fixtureFloor): the bundle lost its resources
            """)
        #expect(Set(found) == Set(digests.keys), """
            the fixture folder and the pins disagree: unpinned \(Set(found).subtracting(digests.keys).sorted()), \
            missing \(Set(digests.keys).subtracting(found).sorted())
            """)
        // R2: bounded by the pin table.
        for (path, pin) in digests.sorted(by: { $0.key < $1.key }) {
            let bytes = try Data(contentsOf: root.appendingPathComponent(path))
            let actual = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
            #expect(actual == pin, """
                \(path) hashes to \(actual), pinned \(pin): a fixture is never regenerated or edited; a \
                change to one is a reviewed change to this pin
                """)
        }
    }

    // MARK: - Identity, labels and envelopes

    /// **The keychain rows adopt as the identities they were.** Every row 0.1.0 wrote is an
    /// after-first-unlock, this-device-only row that never syncs, 32 bytes, under the namespace's
    /// accounts; seeded as written, each identity provisions by adopting its rows (it mints nothing), to
    /// the signing and key-agreement keys its public-key rows cache and the fingerprint 0.1.0 derived.
    @Test func theKeychainRowsAdoptAsTheIdentitiesTheyWere() throws {
        let rows = try seededRows()
        let accounts = ProximityNamespace.packageTest.installation.keychain
        let identityAccounts = [accounts.identity.signingPrivateKey, accounts.identity.keyAgreementPrivateKey,
                                accounts.identity.signingPublicKeyCache, accounts.identity.keyAgreementPublicKeyCache]
        #expect(rows.count == 18)
        #expect(rows.allSatisfy {
            $0.accessibility == kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String && !$0.synchronizable && $0.data.count == 32
        }, "a row 0.1.0 wrote is not a 32-byte, non-syncing, after-first-unlock this-device-only row")
        #expect(rows.filter { $0.service == sessionSealService }.map(\.account) == [accounts.meshSessionSealKey.account])
        #expect(rows.filter { $0.service == routedSealService }.map(\.account) == [accounts.meshRoutedSealKey.account])
        let cast = try provisionedCast()
        let expected = [("alice", alice, cast.alice), ("bob", bob, cast.bob), ("carol", carol, cast.carol), ("dave", dave, cast.dave)]
        // R2: four identities.
        for (name, fingerprint, identity) in expected {
            let own = rows.filter { $0.service == Self.identityService(name) }
            #expect(own.map(\.account).sorted() == identityAccounts.sorted(), "\(name)'s rows: \(own.map(\.account))")
            #expect(identity.localFingerprint == fingerprint, "\(name) adopted \(identity.localFingerprint)")
            #expect(own.first { $0.account == accounts.identity.signingPublicKeyCache }?.data == identity.localSigningPublicKey)
            #expect(own.first { $0.account == accounts.identity.keyAgreementPublicKeyCache }?.data == identity.localKeyAgreementPublicKey)
        }
    }

    /// **The labels frame as they did.** Every label of `.packageTest` (each group's, the verify-only
    /// legacy pair, the feature salts) and one host feature signature label of each framing has the
    /// prefix bytes 0.1.0 framed it with: raw bytes, an eight-byte big-endian length then the bytes, or
    /// none for a verify-only label. Every signature, hash domain, salt and associated datum below starts
    /// with one of these.
    @Test func theFramedLabelsFrameAsTheyDid() throws {
        let fixture = try decode([String: [String: String]].self, "0.1.0/framed-labels.json")
        let current = Self.framedLabels()
        #expect(fixture.count == 43, "0.1.0 framed \(fixture.count) labels")
        #expect(current == fixture, """
            labels framed differently from 0.1.0: \
            \(current.filter { fixture[$0.key] != $0.value }.keys.sorted()) differ, \
            \(Set(fixture.keys).subtracting(current.keys).sorted()) are gone
            """)
    }

    /// **A schema-2 envelope verifies and carries its fields.** Alice's plain envelope to Bob decodes to
    /// every field she signed, its summary included, verifies for Bob under the identity envelope's v2
    /// label over today's canonical bytes, and hands over its payload; and it is no sealed introduction,
    /// which a coordinator tells apart by decoding.
    @Test func aSchemaTwoEnvelopeVerifiesAndCarriesItsFields() throws {
        let cast = try provisionedCast()
        let bytes = try fixture("0.1.0/identity-envelope-v2.json")
        let envelope = try JSONDecoder().decode(ProximityIdentityEnvelope.self, from: bytes)
        #expect(envelope.schemaVersion == 2 && envelope.envelopeID == Self.id(3) && envelope.senderDisplayName == "Alice")
        #expect(envelope.senderSigningPublicKey == cast.alice.localSigningPublicKey
                && envelope.senderKeyAgreementPublicKey == cast.alice.localKeyAgreementPublicKey)
        #expect(envelope.recipientFingerprint == bob && envelope.payloadTypeToken == "pktest.wave.v1")
        #expect(envelope.payloadEncryption == .none && envelope.createdAt == base && envelope.expiresAt == farFuture)
        #expect(envelope.payloadSummary == PayloadSummary(
            title: "Fixture wave", subtitle: "schema 2", itemCount: 1,
            dateRange: DateRange(start: base, end: base.addingTimeInterval(60)), extraDetails: ["kind": "wave"]))
        #expect(try envelope.verify(identityService: cast.bob, replayCache: nil)
                == Data("A schema-2 envelope's plaintext payload.".utf8))
        #expect((try? JSONDecoder().decode(SealedIntroductionEnvelope.self, from: bytes)) == nil,
                "a plain envelope decodes as a sealed introduction, so a coordinator could not tell them apart")
    }

    /// **A schema-1 envelope still verifies.** The pre-WI-6 shape, signed over the legacy sorted-key JSON
    /// under the verify-only legacy label, is accepted for anyone (it names no recipient) and hands over
    /// its payload; its signature does not verify over the schema-2 bytes, so the legacy reader is what
    /// accepted it.
    @Test func aSchemaOneEnvelopeStillVerifiesUnderTheLegacyReader() throws {
        let cast = try provisionedCast()
        let envelope = try decode(ProximityIdentityEnvelope.self, "0.1.0/identity-envelope-v1.json")
        let purposes = ProximityNamespace.Purposes.packageTest
        #expect(envelope.schemaVersion == 1 && envelope.envelopeID == Self.id(4) && envelope.recipientFingerprint == nil)
        #expect(envelope.createdAt == base.addingTimeInterval(1) && envelope.expiresAt == nil)
        #expect(envelope.payloadSummary == PayloadSummary(title: "Fixture wave", subtitle: "schema 1"))
        #expect(try envelope.verify(identityService: cast.carol, replayCache: nil)
                == Data("A schema-1 envelope's plaintext payload.".utf8))
        #expect(!IdentityService.verify(envelope.signature, of: canonicalBytes(for: envelope, in: purposes),
                                        by: envelope.senderSigningPublicKey, purpose: purposes.signature.identityEnvelopeV2))
    }

    /// **A sealed envelope opens in both framings.** Alice's notes sealed to Bob (`FPT2`, ephemeral X25519,
    /// ChaCha20-Poly1305 under the transport's salt and associated data) verify for Bob and open: the wire2
    /// one through its deflated frame, the other with no frame at all.
    @Test func aSealedEnvelopeOpensInBothFramings() throws {
        let cast = try provisionedCast()
        let wire2 = try decode(ProximityIdentityEnvelope.self, "0.1.0/identity-envelope-sealed-wire2.json")
        let legacy = try decode(ProximityIdentityEnvelope.self, "0.1.0/identity-envelope-sealed-legacy.json")
        let sealedToBob = PayloadEncryption.sealedTo(recipientKeyAgreementPublicKey: cast.bob.localKeyAgreementPublicKey)
        // R2: two envelopes.
        for (envelope, id) in [(wire2, 5), (legacy, 6)] {
            #expect(envelope.envelopeID == Self.id(id) && envelope.payloadTypeToken == "pktest.note.v1")
            #expect(envelope.payloadEncryption == sealedToBob && envelope.payload.starts(with: Data("FPT2".utf8)))
        }
        #expect(try wire2.verify(identityService: cast.bob, replayCache: nil, sealedPayloadFormat: .wire2) == wirePlaintext)
        #expect(try legacy.verify(identityService: cast.bob, replayCache: nil, sealedPayloadFormat: .legacy) == legacyPlaintext)
    }

    /// **The sealed payload frames unframe, and the raw one re-frames byte for byte.** A short plaintext
    /// rides raw (`0x02`) and a long one deflated (`0x01`), each padded to the 256-byte bucket with its
    /// pad count in the last two bytes.
    @Test func theSealedPayloadFramesUnframe() throws {
        let raw = try fixture("0.1.0/sealed-frame-raw.bin")
        let deflated = try fixture("0.1.0/sealed-frame-deflate.bin")
        #expect(raw.first == 0x02 && deflated.first == 0x01 && raw.count == 256 && deflated.count == 256)
        #expect(try SealedPayloadFraming.unframe(raw) == legacyPlaintext)
        #expect(try SealedPayloadFraming.unframe(deflated) == wirePlaintext)
        #expect(SealedPayloadFraming.frame(legacyPlaintext) == raw, "the raw frame no longer re-frames to 0.1.0's bytes")
    }

    /// **A sealed introduction opens to its signed envelope.** The wrapper carries only ciphertext; Bob
    /// opens it from Alice's key-agreement key, and the envelope inside is Alice's signed hello, which
    /// verifies for Bob.
    @Test func aSealedIntroductionOpensToItsSignedEnvelope() throws {
        let cast = try provisionedCast()
        let wrapper = try decode(SealedIntroductionEnvelope.self, "0.1.0/sealed-introduction.json")
        let inner = try cast.bob.open(wrapper.sealedIntroduction, from: cast.alice.localKeyAgreementPublicKey)
        let envelope = try JSONDecoder().decode(ProximityIdentityEnvelope.self, from: inner)
        #expect(envelope.envelopeID == Self.id(7) && envelope.payloadTypeToken == "pktest.session.hello.v1")
        #expect(envelope.senderDisplayName.isEmpty && envelope.payloadSummary == PayloadSummary(title: "Test hello"))
        #expect(try envelope.verify(identityService: cast.bob, replayCache: nil)
                == Data("An introduction sealed to the friend it was meant for.".utf8))
    }

    /// **The prekey bundle decodes its keys and values.** Ids, instants, the two one-time keys and the
    /// signed prekey, each the public half of the private key the generation derived from a fill byte.
    @Test func thePrekeyBundleDecodesItsKeysAndValues() throws {
        let bundle = try decode(ProximityPrekeyBundle.self, "0.1.0/prekey-bundle.json")
        let expected = ProximityPrekeyBundle(
            bundleID: Self.id(8), created: base, expires: base.addingTimeInterval(7 * 86_400),
            keys: [ProximityPrekeyBundle.PrekeyEntry(id: Self.id(9), publicKey: try Self.prekey(0x41)),
                   ProximityPrekeyBundle.PrekeyEntry(id: Self.id(10), publicKey: try Self.prekey(0x42))],
            signedPrekey: ProximityPrekeyBundle.SignedPrekey(
                id: Self.id(11), publicKey: try Self.prekey(0x43), created: base,
                expires: base.addingTimeInterval(30 * 86_400)))
        #expect(bundle == expected)
    }

    // MARK: - The radios

    /// **A mesh wire frame names its length.** Four big-endian bytes of length, under the transport's
    /// ceiling, then exactly that many bytes, which are the schema-2 envelope; the header re-encodes byte
    /// for byte.
    @Test func aMeshWireFrameNamesItsLength() throws {
        let frame = try fixture("0.1.0/mesh-wire-frame.bin")
        let length = try NetworkMeshWire.payloadLength(
            from: frame.prefix(NetworkMeshWire.headerByteCount), ceiling: NetworkMeshSession.maxInboundWireBytes)
        #expect(length == frame.count - NetworkMeshWire.headerByteCount)
        #expect(NetworkMeshWire.header(for: length) == frame.prefix(NetworkMeshWire.headerByteCount))
        #expect(frame.dropFirst(NetworkMeshWire.headerByteCount) == (try fixture("0.1.0/identity-envelope-v2.json")))
    }

    /// **The channel introduction reviews as accepted.** Bob, the responder, reads Alice's and his own
    /// hello frames and her signed introduction under the handshake's ceiling, admits her hello, binds the
    /// transcript to the channel binding both ends derived, and accepts her: today's transcript bytes are
    /// the ones she signed.
    @Test func theChannelIntroductionReviewsAsAccepted() throws {
        let cast = try provisionedCast()
        let aliceHello = try framedJSON(MeshChannelHello.self, "0.1.0/channel-hello-initiator.bin")
        let bobHello = try framedJSON(MeshChannelHello.self, "0.1.0/channel-hello-responder.bin")
        let introduction = try framedJSON(MeshChannelIntroduction.self, "0.1.0/channel-introduction.bin")
        let epoch = try #require(MeshEpochRef.minted(counter: 1, coordinatorFingerprint: alice, meshID: meshID, in: .packageTest))
        #expect(aliceHello == MeshChannelHello(
            protocolVersion: 1, meshID: meshID, epochRef: epoch.canonicalString, signingPublicKey: cast.alice.localSigningPublicKey,
            nonce: Data(repeating: 0x11, count: 16), sessionID: "alice-sid"))
        #expect(bobHello.signingPublicKey == cast.bob.localSigningPublicKey && bobHello.sessionID == "bob-sid")
        var exchange = MeshChannelIntroductionExchange(role: .responder, localHello: bobHello, purposes: .packageTest)
        var nonces = MeshIntroductionNonceCache()
        let refusal = exchange.receive(aliceHello, roster: MeshIntroductionRoster(members: [cast.alice.localSigningPublicKey]),
                                       nonces: &nonces)
        #expect(refusal == nil, "Bob refused Alice's hello: \(String(describing: refusal))")
        let transcript = exchange.bind(channelBindingHash: Data(repeating: 0x5C, count: 32))
        #expect(transcript != nil && introduction.channelBindingHash == Data(repeating: 0x5C, count: 32))
        #expect(exchange.review(introduction) == .accepted(MeshVerifiedPeer(
            signingPublicKey: cast.alice.localSigningPublicKey, fingerprint: alice, sessionID: "alice-sid")))
    }

    /// **The dial hellos decode.** The pair radio's hello reads its session id and re-encodes byte for
    /// byte (sorted keys); the presence radio's reads its tag.
    @Test func theDialHellosDecode() throws {
        let pair = try fixture("0.1.0/pair-dial-hello.json")
        #expect(ProximityPairDialHello.decoded(pair)?.sessionID == "alice-sid")
        #expect(try ProximityPairDialHello.encoded(sessionID: "alice-sid") == pair)
        #expect(PresenceDialHello.decoded(try fixture("0.1.0/presence-dial-hello.json"))?.tag == "pkfixturetag01")
    }

    /// **The TXT records read as they were published.** The fields 0.1.0 published for the pair, presence
    /// and mesh radios (the TXT record's key-value pairs, which Network.framework encodes) read back to
    /// the session id, the tags and the bounded mesh advertisement, the withheld fingerprint left out, and
    /// today's publishers write the same fields from the same input.
    @Test func theTXTRecordsReadAsTheyWerePublished() throws {
        let records = try decode([String: [String: String]].self, "0.1.0/txt-records.json")
        let pair = try #require(records["pair"])
        let presence = try #require(records["presence"])
        let mesh = try #require(records["meshLink"])
        #expect(ProximityPairAdvertisement.sessionID(from: pair, mode: "pair") == "alice-sid" && pair["name"] == "Alice")
        #expect(ProximityPairAdvertisement.publishedFields(
            from: [ProximityPairAdvertisement.versionKey: ProximityPairAdvertisement.version,
                   ProximityPairAdvertisement.modeKey: "pair", ProximityPairAdvertisement.nameKey: "Alice"],
            sessionID: "alice-sid") == pair)
        #expect(PresenceAdvertisement.tags(from: presence) == ["tag0001", "tag0002", "tag0003"])
        #expect(PresenceAdvertisement.publishedFields(tags: ["tag0003", "tag0001", "tag0002"]) == presence)
        #expect(MeshLinkAdvertisement.advertisement(from: mesh) == mesh && mesh["fp"] == nil && mesh["sid"] == "alice-sid")
        #expect(MeshLinkAdvertisement.publishedFields(
            from: ["sid": "alice-sid", "fp": "withheld-fingerprint", "name": "Alice", "mode": "mesh"]) == mesh)
    }

    // MARK: - The mesh payloads

    /// **The admission grant verifies and its group key opens.** Alice's token admitting Bob verifies
    /// for Bob's key under the token's v2 label at an instant inside its two hours, and the group key
    /// she wrapped to him (`FGK2`, 96 bytes) opens to the key she wrapped; the legacy-signed token
    /// admitting Carol verifies through the legacy reader alone.
    @Test func theAdmissionGrantVerifiesAndItsGroupKeyOpens() throws {
        let cast = try provisionedCast()
        let grant = try decode(MeshAdmissionGrantPayload.self, "0.1.0/mesh-admission-grant.json")
        let purposes = ProximityNamespace.Purposes.packageTest
        #expect(grant.meshID == meshID && grant.requesterFingerprint == bob && grant.currentKeyEpoch == 3)
        #expect(grant.token.grantedAt == base.addingTimeInterval(11) && grant.token.expiresAt == base.addingTimeInterval(7_211))
        try grant.token.verify(joinerSigningPublicKey: cast.bob.localSigningPublicKey, expectedMeshID: meshID,
                               expectedAdmitterSigningPublicKey: cast.alice.localSigningPublicKey,
                               now: base.addingTimeInterval(60), in: purposes)
        let wrapped = try #require(grant.encryptedCurrentKey)
        #expect(wrapped.count == 96 && wrapped.starts(with: Data("FGK2".utf8)))
        #expect(try cast.bob.decryptGroupKey(wrapped) == Data(repeating: 0x6B, count: 32))
        let legacy = try decode(MeshAdmissionToken.self, "0.1.0/mesh-admission-token-v1.json")
        #expect(legacy.joinerFingerprint == carol && legacy.admitterFingerprint == alice)
        try legacy.verify(joinerSigningPublicKey: cast.carol.localSigningPublicKey, expectedMeshID: meshID,
                          expectedAdmitterSigningPublicKey: cast.alice.localSigningPublicKey,
                          now: base.addingTimeInterval(60), in: purposes)
        #expect(!IdentityService.verify(legacy.admitterSignature, of: canonicalBytes(for: legacy, in: purposes),
                                        by: cast.alice.localSigningPublicKey, purpose: purposes.signature.meshAdmissionTokenV2))
    }

    /// **The key rotation's wraps open for each member.** The rotation names its epoch, coordinator,
    /// instant and cause, and wraps one key to Bob and Carol, each opening with their own key.
    @Test func theKeyRotationWrapsOpenForEachMember() throws {
        let cast = try provisionedCast()
        let rotation = try decode(MeshKeyRotationPayload.self, "0.1.0/mesh-key-rotation.json")
        #expect(rotation.newEpoch == 4 && rotation.coordinatorFingerprint == alice && rotation.cause == .membership)
        #expect(rotation.rotationInitiatedAt == base.addingTimeInterval(120) && Set(rotation.perMember.keys) == [bob, carol])
        #expect(try cast.bob.decryptGroupKey(try #require(rotation.perMember[bob])) == Data(repeating: 0x7C, count: 32))
        #expect(try cast.carol.decryptGroupKey(try #require(rotation.perMember[carol])) == Data(repeating: 0x7C, count: 32))
    }

    /// **The plain mesh payloads decode to their values.** The state change's descriptor, the admission
    /// request, the unsigned removal proposal and its second, the vouch list, the key acknowledgement,
    /// the rotation sync and the coordinator beacon each decode equal to the value 0.1.0 encoded.
    @Test func thePlainMeshPayloadsDecodeToTheirValues() throws {
        let cast = try provisionedCast()
        #expect(try decode(MeshStateChangePayload.self, "0.1.0/mesh-state-change.json")
                == MeshStateChangePayload(descriptor: descriptor(cast)))
        #expect(try decode(MeshAdmissionRequestPayload.self, "0.1.0/mesh-admission-request.json") == MeshAdmissionRequestPayload(
            meshID: meshID, requesterFingerprint: carol, requesterDisplayName: "Carol",
            requesterSigningPublicKey: cast.carol.localSigningPublicKey,
            requesterKeyAgreementPublicKey: cast.carol.localKeyAgreementPublicKey))
        let proposal = MeshRemovalProposalPayload(
            id: Self.id(13), targetFingerprint: dave, targetDisplayName: "Dave", proposerFingerprint: alice,
            proposerDisplayName: "Alice", createdAt: base.addingTimeInterval(200), expiresAt: base.addingTimeInterval(500))
        #expect(try decode(MeshRemovalProposalPayload.self, "0.1.0/mesh-removal-proposal.json") == proposal)
        #expect(try decode(MeshRemovalSecondPayload.self, "0.1.0/mesh-removal-second.json")
                == MeshRemovalSecondPayload(proposal: proposal, seconderFingerprint: bob))
        #expect(try decode(MeshFriendVouchListPayload.self, "0.1.0/mesh-vouch-list.json") == MeshFriendVouchListPayload(
            voucherFingerprint: alice, voucherDisplayName: "Alice", trustedFingerprints: [bob, carol],
            expiresAt: base.addingTimeInterval(3_600)))
        #expect(try decode(MeshKeyAckPayload.self, "0.1.0/mesh-key-ack.json") == MeshKeyAckPayload(epoch: 4, memberFingerprint: bob))
        #expect(try decode(MeshRotationSyncPayload.self, "0.1.0/mesh-rotation-sync.json") == MeshRotationSyncPayload(closingEpoch: 3))
        #expect(try decode(MeshCoordinatorBeaconPayload.self, "0.1.0/mesh-coordinator-beacon.json") == MeshCoordinatorBeaconPayload(
            coordinatorFingerprint: alice, currentEpoch: 4, nextRotationAt: base.addingTimeInterval(1_800),
            sentAt: base.addingTimeInterval(130)))
    }

    // MARK: - Membership

    /// **The membership records verify into one ledger.** A verifier that knows only the founder's key
    /// admits Alice's four admissions in order, verifies the three members' key advertisements, the
    /// signed removal proposal against Dave and both votes, then inserts the quorum removal, Carol's
    /// departure (with her custody hand-off) and Alice's termination, each under its own label: the
    /// roster is Alice and Bob until the termination ends the mesh, and the ledger the verifier holds is
    /// the one Bob's session file holds.
    @Test func theMembershipRecordsVerifyIntoOneLedger() throws {
        let cast = try provisionedCast()
        var verifier = MeshMembershipRecordVerifier(
            meshID: meshID, founderSigningPublicKey: cast.alice.localSigningPublicKey, family: ProximityNamespace.packageTest.family)
        // R2: four admissions.
        for name in ["alice", "bob", "carol", "dave"] {
            let record = try decode(MeshMemberAdmissionPayload.self, "0.1.0/membership-admission-\(name).json").record
            #expect(verifier.insert(record) == nil, "\(name)'s admission was refused")
        }
        let advertisements = try decode(MeshKeyAgreementPayload.self, "0.1.0/membership-key-agreement.json")
        #expect(advertisements.senderFingerprint == alice && advertisements.advertisements.map(\.memberFingerprint) == [alice, bob, carol])
        #expect(advertisements.advertisements.allSatisfy { verifier.verify($0).rejection == nil })
        #expect(advertisements.advertisements.map(\.keyAgreementPublicKey)
                == [cast.alice, cast.bob, cast.carol].map(\.localKeyAgreementPublicKey))
        let proposal = try decode(SignedRemovalProposal.self, "0.1.0/membership-removal-proposal.json")
        #expect(proposal.proposalID == Self.id(12) && proposal.targetFingerprint == dave && verifier.verify(proposal) == nil)
        // R2: two votes.
        for voter in ["bob", "carol"] {
            #expect(verifier.verify(try decode(SignedRemovalVote.self, "0.1.0/membership-removal-vote-\(voter).json")) == nil)
        }
        let removal = try decode(MeshMemberRemovalPayload.self, "0.1.0/membership-removal.json").record
        #expect(removal.voterFingerprints == [alice, bob, carol] && verifier.insert(removal) == nil)
        let departure = try decode(MeshMemberDeparturePayload.self, "0.1.0/membership-departure.json").record
        #expect(departure.custodyHandoff == MeshCustodyHandoffSummary(custodianFingerprints: [bob], handedOffItemCount: 1))
        #expect(verifier.insert(departure) == nil)
        #expect(verifier.roster.memberFingerprints.sorted() == [alice, bob].sorted() && verifier.roster.status == .active)
        let termination = try decode(MeshTerminationPayload.self, "0.1.0/membership-termination.json").record
        #expect(termination.rosterAtSigning == [alice, bob].sorted() && verifier.insert(termination) == nil)
        #expect(verifier.roster.memberFingerprints.isEmpty && verifier.roster.status == .terminated)
        #expect(verifier.ledger == (try fullLedger()))
    }

    /// **The digest and the epoch heads verify against that ledger.** At a member that has not yet
    /// folded the termination (Alice is still on its roster), Alice's inventory digest and epoch heads
    /// verify under their labels; the digest is the one today's code derives from the whole ledger, and
    /// the heads name the epoch today's code mints for her first rotation of this mesh.
    @Test func theDigestAndTheEpochHeadsVerifyAgainstThatLedger() throws {
        let cast = try provisionedCast()
        var verifier = MeshMembershipRecordVerifier(
            meshID: meshID, founderSigningPublicKey: cast.alice.localSigningPublicKey, family: ProximityNamespace.packageTest.family)
        var live = try routedLedger()
        live.departures = live.departures.inserting(try decode(MeshMemberDeparturePayload.self, "0.1.0/membership-departure.json").record)
        let refused = verifier.merge(try routedLedger()) + [verifier.insert(try decode(
            MeshMemberDeparturePayload.self, "0.1.0/membership-departure.json").record)].compactMap { $0 }
        #expect(refused.isEmpty && verifier.ledger == live, "the live ledger did not verify whole: \(refused)")
        let digest = try decode(MeshInventoryDigestPayload.self, "0.1.0/membership-inventory-digest.json")
        #expect(digest.senderFingerprint == alice && digest.sentAt == base.addingTimeInterval(510))
        #expect(verifier.verify(digest) == nil)
        #expect(digest.digest
                == MeshInventoryDigest(meshID: meshID, ledger: try fullLedger(), family: ProximityNamespace.packageTest.family))
        #expect(digest.digest.admissionCount == 4 && digest.digest.removalCount == 1
                && digest.digest.departureCount == 1 && digest.digest.terminationCount == 1)
        let heads = try decode(MeshEpochHeadsPayload.self, "0.1.0/membership-epoch-heads.json")
        let epoch = try #require(MeshEpochRef.minted(counter: 1, coordinatorFingerprint: alice, meshID: meshID, in: .packageTest))
        #expect(heads.heads == [epoch] && heads.sentAt == base.addingTimeInterval(520) && verifier.verify(heads) == nil)
    }

    // MARK: - Routed

    /// **The routed item verifies from its manifest to its receipts.** Alice's manifest passes the
    /// manifest verifier over the roster it was minted on (the admissions and Dave's removal), its one
    /// chunk passes the chunk verifier and assembles into the sealed blob its content hash names, each
    /// destination unwraps the content key from its own wrap and opens the blob to Alice's note, and
    /// Bob's custody and recipient receipts pass their verifiers; the chunk's hash and id and both
    /// receipts' ids are the ones 0.1.0 derived.
    @Test func theRoutedItemVerifiesFromItsManifestToItsReceipts() throws {
        let cast = try provisionedCast()
        let ledger = try routedLedger()
        let manifest = try routedManifest()
        let hardDeadline = base.addingTimeInterval(21_600)
        #expect(manifest.itemID == itemID && manifest.originFingerprint == alice && manifest.typeToken == tempMessage)
        #expect(manifest.destinations.sorted() == [bob, carol].sorted() && manifest.createdAt == base.addingTimeInterval(600))
        #expect(manifest.expiresAt == hardDeadline.addingTimeInterval(1_200))
        #expect(MeshRoutedManifestVerifier(meshID: meshID, hardDeadline: hardDeadline, ledger: ledger,
                                           acceptedTypeTokens: [tempMessage], purposes: .packageTest).verify(manifest) == nil)
        let chunk = try decode(MeshChunkPayload.self, "0.1.0/routed-chunk.json").chunk
        #expect(MeshChunkVerifier(meshID: meshID, hardDeadline: hardDeadline, ledger: ledger, manifest: manifest,
                                  purposes: .packageTest).verify(chunk) == nil)
        #expect(chunk.chunkHash == MeshRoutedContentDigest.chunkHash(of: chunk.payload, in: .packageTest))
        #expect(chunk.chunkID(in: .packageTest) == UUID(uuidString: "E0020174-A950-BE0B-FF8F-9C82DE83E756"))
        let blob = try assembled(manifest, from: chunk)
        #expect(MeshRoutedContentDigest.contentHash(of: blob, in: .packageTest) == manifest.contentHash)
        // R2: two destinations.
        for destination in [cast.bob, cast.carol] {
            #expect(try opened(blob, of: manifest, by: destination) == routedPlaintext)
        }
        let custody = try decode(MeshCustodyReceiptPayload.self, "0.1.0/routed-custody-receipt.json").receipt
        let receipt = try decode(MeshRecipientReceiptPayload.self, "0.1.0/routed-recipient-receipt.json").receipt
        #expect(custody.custodianFingerprint == bob && custody.custodiedAt == base.addingTimeInterval(910))
        #expect(receipt.recipientFingerprint == bob && receipt.receivedAt == base.addingTimeInterval(920))
        #expect(MeshCustodyReceiptVerifier(meshID: meshID, hardDeadline: hardDeadline, ledger: ledger, manifest: manifest,
                                           purposes: .packageTest).verify(custody) == nil)
        #expect(MeshRecipientReceiptVerifier(meshID: meshID, hardDeadline: hardDeadline, ledger: ledger, manifest: manifest,
                                             purposes: .packageTest).verify(receipt) == nil)
        #expect(custody.receiptID(in: .packageTest) == UUID(uuidString: "36B6DA87-959E-5A17-F42B-0367252D4BFB"))
        #expect(receipt.receiptID(in: .packageTest) == UUID(uuidString: "4CC5EBB9-1F28-2873-F523-ED73E26E7EF9"))
    }

    /// **The routed inventory and the drain answer verify.** Bob's signed advertisement of what he holds
    /// passes the inventory verifier, and Carol's answer to it, bound to his instant, passes the drain
    /// answer verifier.
    @Test func theRoutedInventoryAndTheDrainAnswerVerify() throws {
        let ledger = try routedLedger()
        let inventory = try decode(MeshRoutedInventoryPayload.self, "0.1.0/routed-inventory.json")
        #expect(inventory.senderFingerprint == bob && inventory.sentAt == base.addingTimeInterval(930))
        #expect(inventory.inventory.meshID == meshID && inventory.inventory.entries.count == 1)
        #expect(MeshRoutedInventoryVerifier(meshID: meshID, ledger: ledger, purposes: .packageTest).verify(inventory) == nil)
        let answer = try decode(MeshRoutedDrainAnswerPayload.self, "0.1.0/routed-drain-answer.json")
        #expect(answer.answer == MeshRoutedDrainAnswer(meshID: meshID, advertiserFingerprint: bob,
                                                       advertisedAt: inventory.sentAt, quiescent: false))
        #expect(answer.senderFingerprint == carol && answer.sentAt == base.addingTimeInterval(940))
        #expect(MeshRoutedDrainAnswerVerifier(meshID: meshID, ledger: ledger, purposes: .packageTest).verify(answer) == nil)
    }

    // MARK: - On disk

    /// **Bob's routed store opens and reassembles its item.** Under the seal key and install binding
    /// 0.1.0 sealed it with, the V3 index loads, at schema 2, to the one item Bob held (its manifest, its one chunk
    /// file, its custody and delivery instants and both receipts), the inventory today's code derives
    /// from it is the one Bob signed, and the store reassembles the sealed blob from its chunk file,
    /// which Bob's content key opens to Alice's note.
    @Test func theRoutedStoreOpensAndReassemblesItsItem() throws {
        let cast = try provisionedCast()
        let manifest = try routedManifest()
        let scope = MeshRoutedStorageScope(
            namespace: .packageTest, directory: try copiedFolder("0.1.0/routed-store"),
            keychainService: service(routedSealService), installBinding: PinnedInstallBinding(bytes: binding))
        defer { removeScratch() }
        let store = MeshRoutedStore(scope: scope)
        guard case .loaded(let index, _) = store.load() else {
            Issue.record("Bob's routed index did not load: \(store.load())")
            return
        }
        let record = try #require(index.record(for: MeshRoutedItemKey(manifest)))
        #expect(index.schemaVersion == 2 && index.itemCount == 1 && record.manifest == manifest && record.isComplete
                && record.chunks.count == 1)
        #expect(record.firstSeenAt == base.addingTimeInterval(900) && record.custodiedAt == base.addingTimeInterval(910)
                && record.deliveredAt == base.addingTimeInterval(920))
        #expect(record.receipts == [try decode(MeshCustodyReceiptPayload.self, "0.1.0/routed-custody-receipt.json").receipt])
        #expect(record.recipientReceipts
                == [try decode(MeshRecipientReceiptPayload.self, "0.1.0/routed-recipient-receipt.json").receipt])
        let signed = try decode(MeshRoutedInventoryPayload.self, "0.1.0/routed-inventory.json")
        #expect(MeshRoutedInventory(meshID: meshID, index: index, selfFingerprint: bob, at: signed.sentAt) == signed.inventory)
        guard case .completed(let reassembled?) = store.assembledBlob(item: MeshRoutedItemKey(manifest), expecting: manifest) else {
            Issue.record("Bob's store did not reassemble the item from its chunk file")
            return
        }
        #expect(try opened(reassembled, of: manifest, by: cast.bob) == routedPlaintext)
    }

    /// **Bob's session context opens from its sealed file.** Under the seal key and install binding 0.1.0
    /// sealed it with, the V3 file loads to schema 3 and every field Bob saved: the mesh, its instants,
    /// the whole ledger the membership frames verify into, the epoch heads, the three key advertisements,
    /// the local termination mark and its presentation.
    @Test func theSessionContextOpensFromItsSealedFile() throws {
        defer { removeScratch() }
        let session = try loadedSession(replacingFileWith: nil)
        guard case .loaded(let context, _) = session else {
            Issue.record("Bob's session context did not load: \(session)")
            return
        }
        let epoch = try #require(MeshEpochRef.minted(counter: 1, coordinatorFingerprint: alice, meshID: meshID, in: .packageTest))
        #expect(context.schemaVersion == 3 && context.meshID == meshID && context.protocolVersion == 1)
        #expect(context.createdAt == base && context.hardDeadline == base.addingTimeInterval(21_600))
        #expect(context.ledger == (try fullLedger()) && context.epochHeads == [epoch])
        #expect(context.lastExternalHeartbeat == base.addingTimeInterval(700) && !context.developedLocally && context.endingPresented)
        #expect(context.localTermination
                == MeshSessionLocalTermination(reason: .verifiedTerminationRecord, at: base.addingTimeInterval(500)))
        let advertised = try decode(MeshKeyAgreementPayload.self, "0.1.0/membership-key-agreement.json").advertisements
        let stored = context.keyAdvertisements.all
        let keyed = { (rows: [SignedKeyAgreementAdvertisement]) in
            rows.map { $0.memberFingerprint + ":" + $0.keyAgreementPublicKey.base64EncodedString() }.sorted()
        }
        #expect(stored.count == 3 && keyed(stored) == keyed(advertised))
        let purposes = ProximityNamespace.Purposes.packageTest
        let admitted = { (fingerprint: String) in
            context.ledger.admissions.all.first { $0.memberFingerprint == fingerprint }?.signingPublicKey ?? Data()
        }
        #expect(stored.allSatisfy { advertisement in
            advertisement.meshID == meshID && advertisement.advertisedAt == base.addingTimeInterval(30) && IdentityService.verify(
                advertisement.signature, of: canonicalBytes(for: advertisement, in: purposes),
                by: admitted(advertisement.memberFingerprint), purpose: purposes.signature.meshKeyAgreementV1)
        }, "a stored key advertisement does not verify under its member's admitted key")
        #expect(context.recordedEndingReason(selfFingerprint: bob) == .verifiedTerminationRecord)
    }

    /// **A retired column marker is refused by name.** Bob's session file with its V3 marker replaced by
    /// the retired V2 marker, or dropped (the unprefixed format's shape), is refused as a retired at-rest
    /// format, never opened and never read as corrupt or absent.
    @Test func aRetiredColumnMarkerIsRefusedByName() throws {
        defer { removeScratch() }
        let retired = MeshSessionLoad.refused(MeshSessionSealRefusal(operation: .open, cause: .retiredAtRestFormat))
        let expected: [(String, ProximityColumnCrypto.StoredFormat)] = [
            ("0.1.0/column-v2-marked.sealed", .v2Marked), ("0.1.0/column-unprefixed.sealed", .unprefixed)
        ]
        // R2: two retired formats.
        for (path, format) in expected {
            let bytes = try fixture(path)
            #expect(ProximityColumnCrypto.StoredFormat.classify(bytes) == format, "\(path) does not read as \(format)")
            #expect(try loadedSession(replacingFileWith: bytes) == retired, "\(path) was not refused as a retired format")
        }
    }

    /// **The protected sidecar reads its value.** An unsealed sidecar file 0.1.0 wrote (its value's JSON)
    /// loads ready, with no data loss, to the value written.
    @Test func theProtectedSidecarReadsItsValue() throws {
        defer { removeScratch() }
        let url = try copiedFolder(nil).appendingPathComponent("protected-sidecar.json")
        try fixture("0.1.0/protected-sidecar.json").write(to: url)
        let sidecar = ProtectedSidecar<[String: Int]>(
            fileURL: url, empty: [:], auditPrefix: "pktest.fixture.sidecar", observeProtectedData: false)
        #expect(sidecar.state == .ready && !sidecar.dataLossOccurred)
        #expect(sidecar.read() == ["alpha": 1, "beta": 2, "gamma": 3])
    }

    // MARK: - Reading the folder

    /// The bundle's `Fixtures` folder, which the manifest copies whole into the test bundle.
    func fixturesFolder() throws -> URL {
        try #require(Bundle.module.url(forResource: "Fixtures", withExtension: nil), "the test bundle holds no Fixtures folder")
    }

    /// Every regular file under `root`, by its path there, sorted; a name starting with `.` is left out.
    func fixtureFiles(under root: URL) throws -> [String] {
        let walker = FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey])
        let prefix = root.standardizedFileURL.path + "/"
        var found: [String] = []
        // R2: bounded by the folder's files.
        for case let url as URL in walker?.allObjects ?? [] where !url.lastPathComponent.hasPrefix(".") {
            guard try url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true else { continue }
            found.append(String(url.standardizedFileURL.path.dropFirst(prefix.count)))
        }
        return found.sorted()
    }

    /// A fixture's bytes, by its path under the folder.
    func fixture(_ path: String) throws -> Data {
        try Data(contentsOf: fixturesFolder().appendingPathComponent(path))
    }

    /// A JSON fixture decoded with a plain `JSONDecoder`, as every reader in ProximityKit decodes it.
    func decode<Value: Decodable>(_ type: Value.Type, _ path: String) throws -> Value {
        try JSONDecoder().decode(type, from: fixture(path))
    }

    /// A handshake frame's JSON, read under the handshake's ceiling, its header re-encoded byte for byte.
    func framedJSON<Value: Decodable>(_ type: Value.Type, _ path: String) throws -> Value {
        let frame = try fixture(path)
        let header = frame.prefix(NetworkMeshWire.headerByteCount)
        let length = try NetworkMeshWire.payloadLength(from: header, ceiling: MeshChannelIntroductionFormat.maxFrameByteCount)
        #expect(length == frame.count - header.count && NetworkMeshWire.header(for: length) == header, "\(path)'s header")
        return try JSONDecoder().decode(type, from: frame.dropFirst(header.count))
    }

    // MARK: - The keychain and the cast

    /// One keychain row as 0.1.0 wrote it.
    struct Row: Decodable {
        /// The fixture's service: the identity's, or a seal key's.
        let service: String
        /// The namespace's account.
        let account: String
        /// The accessibility class's raw value.
        let accessibility: String
        /// Whether the row syncs.
        let synchronizable: Bool
        /// The key bytes.
        let data: Data
    }

    /// The four identities, provisioned from their rows.
    struct Cast {
        /// The founder and the routed item's origin.
        let alice: IdentityService
        /// The custodian and recipient whose stores are on disk.
        let bob: IdentityService
        /// The member who departed.
        let carol: IdentityService
        /// The member who was removed.
        let dave: IdentityService
    }

    /// The fixture's service for a cast member's identity.
    static func identityService(_ name: String) -> String { "org.example.pktest.identity.fixture." + name }

    /// The service this instance seeds a fixture service's rows under.
    func service(_ fixtureService: String) -> String { fixtureService + ".cell." + cell }

    /// Every row of `keychain-rows.json`, stored exactly as written (account, accessibility class, sync
    /// flag, bytes) under this instance's services.
    func seededRows() throws -> [Row] {
        let rows = try decode([Row].self, "0.1.0/keychain-rows.json")
        // R2: bounded by the fixture's rows.
        for row in rows {
            let status = ProximityKeychainItem.store(
                row.data, account: row.account, service: service(row.service),
                accessibility: row.accessibility as CFString, synchronizable: row.synchronizable)
            #expect(status == errSecSuccess, "seeding \(row.service)/\(row.account) answered \(status)")
        }
        return rows
    }

    /// The cast, each identity provisioned by adopting its seeded rows.
    func provisionedCast() throws -> Cast {
        _ = try seededRows()
        return Cast(alice: try identity("alice"), bob: try identity("bob"), carol: try identity("carol"), dave: try identity("dave"))
    }

    /// One cast member's identity over this instance's copy of its rows.
    func identity(_ name: String) throws -> IdentityService {
        let identity = IdentityService(namespace: .packageTest, keychainService: service(Self.identityService(name)))
        try identity.ensureProvisioned()
        return identity
    }

    // MARK: - Ledgers, labels and values

    /// The ledger the membership frames hold: the four admissions, Dave's removal, Carol's departure and
    /// Alice's termination.
    func fullLedger() throws -> MeshMembershipLedger {
        var ledger = try routedLedger()
        let departure = try decode(MeshMemberDeparturePayload.self, "0.1.0/membership-departure.json").record
        let termination = try decode(MeshTerminationPayload.self, "0.1.0/membership-termination.json").record
        ledger.departures = ledger.departures.inserting(departure)
        ledger.terminations = ledger.terminations.inserting(termination)
        return ledger
    }

    /// The ledger the routed item was minted on: the four admissions and Dave's removal.
    func routedLedger() throws -> MeshMembershipLedger {
        var ledger = MeshMembershipLedger.empty
        // R2: four admissions.
        for name in ["alice", "bob", "carol", "dave"] {
            ledger.admissions = ledger.admissions.inserting(
                try decode(MeshMemberAdmissionPayload.self, "0.1.0/membership-admission-\(name).json").record)
        }
        ledger.removals = ledger.removals.inserting(try decode(MeshMemberRemovalPayload.self, "0.1.0/membership-removal.json").record)
        return ledger
    }

    /// The routed manifest frame's manifest.
    func routedManifest() throws -> MeshRoutedManifest {
        try decode(MeshRoutedManifestPayload.self, "0.1.0/routed-manifest.json").manifest
    }

    /// `chunk` assembled against `manifest`: the sealed blob, or a recorded issue.
    func assembled(_ manifest: MeshRoutedManifest, from chunk: MeshChunk) throws -> Data {
        var assembly = try #require(MeshChunkAssembly.forManifest(manifest))
        _ = assembly.admit(chunk, in: .packageTest)
        guard case .complete(let blob) = assembly.completion(against: manifest, in: .packageTest) else {
            Issue.record("the routed chunk did not complete its item")
            return Data()
        }
        return blob
    }

    /// `blob` opened by `destination`: its key wrap unwrapped through its static key agreement, then the
    /// item seal opened under the manifest's binding and type.
    func opened(_ blob: Data, of manifest: MeshRoutedManifest, by destination: IdentityService) throws -> Data {
        let wrap = try #require(manifest.keyWraps.first { $0.recipientFingerprint == destination.localFingerprint })
        let binding = MeshRoutedWrapBinding(meshID: manifest.meshID, itemID: manifest.itemID, originFingerprint: manifest.originFingerprint)
        let contentKey = try MeshRoutedContentKeyWrapper.unwrap(
            wrap, binding: binding, localFingerprint: destination.localFingerprint,
            localKeyAgreementPublicKey: destination.localKeyAgreementPublicKey,
            staticAgreement: { try destination.staticKeyAgreement(withEphemeralPublicKey: $0) }, in: .packageTest)
        return try MeshRoutedItemSealer.open(
            blob, contentKey: contentKey, binding: binding, typeToken: manifest.typeToken, maxBlobByteCount: 9_065,
            in: .packageTest)
    }

    /// The state change's descriptor: a closed mesh of Alice and Bob, named and moded by Alice.
    func descriptor(_ cast: Cast) -> MeshDescriptor {
        let members = [(cast.alice, "Alice", 10.0), (cast.bob, "Bob", 11.0)].map { identity, name, joined in
            MeshMember(fingerprint: identity.localFingerprint, displayName: name, signingPublicKey: identity.localSigningPublicKey,
                       keyAgreementPublicKey: identity.localKeyAgreementPublicKey, joinedAt: base.addingTimeInterval(joined))
        }
        return MeshDescriptor(
            meshID: meshID, name: "Fixture mesh", mode: .closed, members: members, nameSetAt: base.addingTimeInterval(20),
            nameSetBy: alice, modeSetAt: base.addingTimeInterval(21), modeSetBy: alice, createdAt: base.addingTimeInterval(10))
    }

    /// The public half of the X25519 private key whose 32 bytes are all `fill`.
    static func prekey(_ fill: UInt8) throws -> Data {
        try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: fill, count: 32)).publicKey.rawRepresentation
    }

    /// Every label of `.packageTest`, and one feature signature label of each framing, by its group and
    /// name, with its text and its prefix bytes in hex, read through `Mirror` as the generation read them.
    static func framedLabels() -> [String: [String: String]] {
        let purposes = ProximityNamespace.Purposes.packageTest
        let groups: [(String, Any)] = [("signature", purposes.signature), ("keyDerivation", purposes.keyDerivation),
                                       ("aead", purposes.aead), ("hash", purposes.hash),
                                       ("signature.legacyV1", purposes.signature.legacyV1)]
        var table: [String: [String: String]] = [:]
        // R2: five groups × each group's stored labels.
        for (group, value) in groups {
            for child in Mirror(reflecting: value).children {
                let purpose = (child.value as? ProximityCryptographicPurpose) ?? ((child.value as? ProximityCryptographicPurpose?) ?? nil)
                guard let label = child.label, let purpose else { continue }
                table[group + "." + label] = framed(purpose)
            }
        }
        // R2: bounded by the family's feature salts.
        for entry in purposes.feature.entries {
            table["feature." + entry.name] = framed(entry.purpose)
        }
        table["featureSignature.rawPrefix"] = framed(.featureSignature("pktest.fixture.raw-signature.v1", framing: .rawPrefix))
        table["featureSignature.lengthPrefixed"] = framed(
            .featureSignature("pktest.fixture.prefixed-signature.v1", framing: .lengthPrefixed))
        return table
    }

    /// One label's text and prefix bytes in lowercase hex.
    static func framed(_ purpose: ProximityCryptographicPurpose) -> [String: String] {
        ["label": purpose.rawValue, "prefix": purpose.prefixBytes.map { String(format: "%02x", $0) }.joined()]
    }

    // MARK: - Scratch folders and stores

    /// This instance's scratch folder, under the temporary directory and named for ``cell``.
    var scratch: URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("CrossVersionFixtures-" + cell, isDirectory: true)
    }

    /// A copy of the fixture folder at `path` in a fresh folder under ``scratch``, or that folder empty when
    /// `path` is nil, so a store may read and write it without touching the bundle.
    func copiedFolder(_ path: String?) throws -> URL {
        let target = scratch.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
        guard let path else {
            try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
            return target
        }
        try FileManager.default.copyItem(at: fixturesFolder().appendingPathComponent(path), to: target)
        return target
    }

    /// Removes ``scratch`` and everything under it, when a cell made it.
    func removeScratch() {
        guard FileManager.default.fileExists(atPath: scratch.path) else { return }
        do {
            try FileManager.default.removeItem(at: scratch)
        } catch {
            Issue.record("the scratch folder \(scratch.path) was not removed: \(error)")
        }
    }

    /// Bob's session store over a copy of `session-store`, its file replaced by `bytes` when given, loaded
    /// under the seal key and install binding 0.1.0 sealed it with.
    func loadedSession(replacingFileWith bytes: Data?) throws -> MeshSessionLoad {
        _ = try seededRows()
        let scope = MeshSessionStorageScope(
            namespace: .packageTest, directory: try copiedFolder("0.1.0/session-store"),
            keychainService: service(sessionSealService), installBinding: PinnedInstallBinding(bytes: binding))
        let fileURL = scope.directory.appendingPathComponent(ProximityNamespace.packageTest.installation.storage.meshSessionContextFileName)
        if let bytes {
            try bytes.write(to: fileURL)
        }
        return MeshSessionStore(scope: scope).load()
    }
}
