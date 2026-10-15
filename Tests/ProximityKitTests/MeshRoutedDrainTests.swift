// MeshRoutedDrainTests.swift
// ProximityKitTests
//
// Network migration P5 item 6 (plan §11, §10.3, §22.1): the drain, wired onto the ONE merge path.
//
// Tier 1 only — `FakePeerNetwork` + `FakeMeshTransportSession` + an injected clock, no radio and no
// wall-clock sleeps. The rig is a thin facade over `MeshDepartureRig`, not a second rig: nodes,
// links, pumps, settles and rotation samples are item 4's, and only the routed half is new.
//
// Three fixture facts, each of which has cost an iteration somewhere in P5:
//
// - **One pinned install binding.** `MeshP3Acceptance.install` (0x83), never
//   `MeshRoutedStoreFixtures.installA` (0xA7): the routed writes happen inside the manager's receive
//   path, which every rig pump wraps in the former. Mixing them yields a seal refusal, not an empty
//   store.
// - **One time anchor.** `MeshRoutedFixtureClock.createdAt` — exactly `MeshP3Acceptance.base`
//   (1.8e9) until 2026-12-16, a month before that instant falls due, and the wall clock plus that
//   month from the crossover on (item 6a) — with `hardDeadline` derived
//   from `MeshSessionCeiling.ceilingSeconds`, never `MeshRoutedManifestFixtures.hardDeadline`
//   (1.7e9). The same anchor is handed to `MeshDepartureRig.start` so the MESH rolls with it: the
//   manifest verifier demands `expiresAt == floor(hardDeadline) + grace` exactly, and the deadline
//   is the mesh's own `createdAt + ceiling`, so moving one route without the other looks like a
//   signing bug.
// - **The rig's nodes are JOINER-shaped**: `MeshMergeWire.start` applies `.founded`/`.peerCommitted`
//   and never calls `startNewMesh`, so no node has a `sessionCeiling`. That is deliberate — a drain
//   that guarded its ingest on `sessionCeiling?.hardDeadline` would drop every routed frame here,
//   which is exactly what happens to a real joiner for its whole first session.
//
// A partial copy (ProximityKit plan step A1.3's batch D, the routed track): of the Fernlet
// repository's FernletTests file of the same name, this holds only its source walls,
// `MeshRoutedDrainWallTests`, under their suite's name and their own: every one of its cells reads
// ProximityKit's manager, and the five that also read a FernletSocial feature file (the three
// retired transports, the retired epoch gates and the parked text payload) hold the manager's half
// here, the Fernlet repository keeping the feature file's. The rig, the drain's behavioural suite
// and its audit capture stay there, so what this header says of them is not held here.

import Foundation
import Testing
@testable import ProximityKit

// MARK: - The walls

/// The mechanical halves of "no second reconnect path", "no epoch on the routed path" and "item 12
/// inherits a clean seam" — grep-walls over the manager's own source, and for the parked text payload
/// over every file of the module. Here they read only this module: the original also reads, for the
/// retired transports, the FernletSocial feature file that holds each routed family's send, budget and
/// projection handler or ledger judge, and that half stays in the Fernlet repository.
@MainActor
@Suite(.serialized)
struct MeshRoutedDrainWallTests {

    private func managerSource() throws -> String {
        try PackageRoot.source("Sources/ProximityKit/Mesh/MeshNetworkManager.swift")
    }

    /// **The mechanical form of "do NOT add a second reconnect path".** The routed ask rides exactly
    /// the three **ask** doors; the membership digest has two additional, non-ask doors — the
    /// post-merge **proof** and the joiner's post-**adoption** digest — each of which opens no
    /// window, asks nothing and carries no routed bulk.
    ///
    /// **This claim was amended by P5 item 7, deliberately, and strengthened in the same commit.**
    /// Before item 7 both counts were four and equal. The window redesign added
    /// `readvertiseMergeProof(to:)` — a fourth `sendInventoryDigest(` call that is the *occasion*
    /// the strict closing rule needs, since nothing else ever sends a second digest inside one
    /// session — and then `attemptLedgerAdoption(ownAdmission:meshID:)`, a fifth, which is the same
    /// missing occasion for a **joiner**: its grant-reply digest is a one-record bootstrap ledger,
    /// so the admitter answers it and carries the obligation, and adoption rebases without going
    /// through `mergeMembershipLedger(_:)`, so the proof door never fires there. Routing either
    /// through a private helper to keep the textual count at four was rejected on purpose: that
    /// would have left the wall green while the property it protects had changed. So the counts
    /// moved and the wall became **per function** instead — it now names WHICH functions may send
    /// each ask, which a count never could.
    ///
    /// **P5 item 13 moved the BULK count, not the ask count.** All three ask doors fire as a link
    /// OPENS, so an item minted mid-session with the links already open would wait for the next
    /// reconnect — in a stable session, forever. The fix is a fourth `sendRoutedBulk(` site,
    /// `pushOriginatedItem(_:to:now:)`, and deliberately **not** a fourth `sendRoutedInventory(`
    /// one: an advertisement asks the PEER to push to this device, which is the opposite of what an
    /// origination needs, and recording one would overwrite the `advertisedAt` an inbound quiescence
    /// answer has to quote. So `sendRoutedInventory(` stands at four, `sendRoutedBulk(` at four, and
    /// the new door gets its own class below beside item 8's hand-off.
    ///
    /// Counted on the SYMBOL, not on a spelling: a call written `await sendRoutedInventory(…)` —
    /// the natural form for any same-actor caller, and the one the signature invites — would leave a
    /// `self?.`-prefixed count at three and the wall green.
    ///
    /// **P6 item 1 moved the MEMBERSHIP half, not the routed half.** The key-advertisement frame
    /// (`fernlet.mesh.key-agreement.v1`) is addressing, not bulk: it opens no exchange, carries no
    /// content and is never an occasion to push any, so the three routed counts (4 / 6 / 4) do not
    /// move and the hand-off and origination doors must never name it. It rides every door that is
    /// a LINK-OPEN — the three asks, the two non-ask membership doors, and the admitter's grant,
    /// which is the one link-open no other door covers (`openBlipMergeIfReconnected(_:from:peer:)`
    /// opens no exchange for a peer that was not already on the roster, so on a fresh pair the
    /// admitter would otherwise tell the joiner nothing). This wall is the only thing that knows
    /// that: a new send is invisible to a count of three other symbols, which is exactly how
    /// `sendEpochHeads(` drifted uncounted for two phases — **closed here in the same amendment**,
    /// with its own shape stated (ask + *answer*, never a hand-off or an origination).
    ///
    /// **`writeKeyAdvertisementFrame(` is counted too** (third review P3 7). It is not a door — it
    /// is the private writer the one door calls, and it is where the latch is claimed and released
    /// — but that is precisely why it needs a count: a future door that called the writer directly
    /// would skip the roster filter, the bounded self-mint repair and the `owed` computation, with
    /// every count above still green. Two is one declaration plus the one call inside
    /// `sendKeyAdvertisements(to:)`; a second call site is a claim about the wall's own subject and
    /// has to be argued for here.
    @Test func theDrainFiresOnlyFromTheMergeDoor() throws {
        let source = MeshRoutedSourceScan.codeOnly(try managerSource())
        let routed = source.components(separatedBy: "sendRoutedInventory(").count - 1
        let membership = source.components(separatedBy: "sendInventoryDigest(").count - 1
        let heads = source.components(separatedBy: "sendEpochHeads(").count - 1
        let addressing = source.components(separatedBy: "sendKeyAdvertisements(").count - 1
        let writer = source.components(separatedBy: "writeKeyAdvertisementFrame(").count - 1
        #expect(routed == 4, "one declaration plus three ask sites, found \(routed)")
        #expect(membership == 6,
                "those three plus the proof and adoption doors, found \(membership)")
        #expect(heads == 4,
                "one declaration, two ask sites and the digest ANSWER, found \(heads)")
        #expect(addressing == 7,
                "one declaration, three asks, two non-asks and the grant, found \(addressing)")
        #expect(writer == 2,
                "one declaration and the one call inside the send, found \(writer)")
        for door in Self.askDoors {
            let body = try #require(Self.body(startingWith: door, in: source),
                                    "\(door) is gone from MeshNetworkManager.swift")
            #expect(body.components(separatedBy: "sendInventoryDigest(").count - 1 == 1,
                    "\(door) asks with exactly one membership digest")
            #expect(body.components(separatedBy: "sendRoutedInventory(").count - 1 == 1,
                    "\(door) carries exactly one routed twin")
            #expect(body.components(separatedBy: "sendKeyAdvertisements(").count - 1 == 1,
                    "\(door) carries exactly one addressing half")
        }
        for door in Self.nonAskDoors {
            let body = try #require(Self.body(startingWith: door, in: source),
                                    "\(door) is gone from MeshNetworkManager.swift")
            #expect(body.components(separatedBy: "sendInventoryDigest(").count - 1 == 1,
                    "\(door) sends exactly one membership digest")
            #expect(!body.contains("sendRoutedInventory("),
                    "\(door) is not an ask: it must never carry routed bulk")
            #expect(body.components(separatedBy: "sendKeyAdvertisements(").count - 1 == 1,
                    "\(door) carries exactly one addressing half")
        }
        for door in Self.grantDoors {
            let body = try #require(Self.body(startingWith: door, in: source),
                                    "\(door) is gone from MeshNetworkManager.swift")
            #expect(body.components(separatedBy: "sendKeyAdvertisements(").count - 1 == 1,
                    "\(door) tells the member it just admitted this device's own addressing")
            #expect(!body.contains("sendInventoryDigest("),
                    "\(door) asks nothing: an admission is not a merge exchange")
            #expect(!body.contains("sendRoutedInventory("),
                    "\(door) asks nothing: an admission is not a merge exchange")
            #expect(!body.contains("sendRoutedBulk("),
                    "\(door) moves no bytes: the drain is push-only and this is not a push")
        }
        #expect(source.components(separatedBy: "sendRoutedBulk(").count - 1 == 4,
                "one declaration plus three sites: drain answer, hand-off push, origination push")
        for door in Self.handoffDoors {
            let body = try #require(Self.body(startingWith: door, in: source),
                                    "\(door) is gone from MeshNetworkManager.swift")
            #expect(!body.contains("sendInventoryDigest("),
                    "\(door) asks nothing: a departure is not a merge exchange")
            #expect(!body.contains("sendRoutedInventory("),
                    "\(door) asks nothing: a departure is not a merge exchange")
            #expect(!body.contains("sendKeyAdvertisements("),
                    "\(door) is not a link-open: a departure states no addressing")
            #expect(!body.contains("sendEpochHeads("),
                    "\(door) is not a link-open: a departure answers no head set")
            #expect(body.components(separatedBy: "sendRoutedBulk(").count - 1 == 1,
                    "\(door) moves bytes through the one extracted sender")
        }
        for door in Self.originationDoors {
            let body = try #require(Self.body(startingWith: door, in: source),
                                    "\(door) is gone from MeshNetworkManager.swift")
            #expect(!body.contains("sendInventoryDigest("),
                    "\(door) asks nothing: an origination is not a merge exchange")
            #expect(!body.contains("sendRoutedInventory("),
                    "\(door) asks nothing: an advertisement would ask the PEER to push to us")
            #expect(!body.contains("recordRoutedAdvertisement("),
                    "\(door) records nothing: recording would unbind an open exchange's answer")
            #expect(!body.contains("sendKeyAdvertisements("),
                    "\(door) is not a link-open: an origination states no addressing")
            #expect(!body.contains("sendEpochHeads("),
                    "\(door) is not a link-open: an origination answers no head set")
            #expect(body.components(separatedBy: "sendRoutedBulk(").count - 1 == 1,
                    "\(door) moves bytes through the one extracted sender")
        }
    }

    /// The **fourth** door class, added by P5 item 13: the origination push. Like item 8's hand-off
    /// it is neither an ask door nor a non-ask membership door — it opens no exchange, sends no
    /// digest of either kind and records no advertisement — and it is the only routed send that
    /// fires on a USER ACTION rather than on a link opening, which is exactly why it must not touch
    /// the advertisement binding an open merge exchange is waiting on.
    private static let originationDoors = ["private func pushOriginatedItem("]

    /// The **third** door class, added by P5 item 8: the one-moment hand-off. It is neither an ask
    /// door (it opens no exchange and sends no digest of either kind) nor a non-ask membership door
    /// (it carries routed bulk, which those may never do), so it needs its own row rather than a
    /// count that would stay green by accident. Increment 1 has exactly one of them.
    private static let handoffDoors = ["private func pushCustodyToCustodians("]

    /// The **fifth** door class, added by P6 item 1: the admitter's grant. It is a link-open no
    /// other door on this list covers — a brand-new member is not a reconnect, so
    /// `openBlipMergeIfReconnected(_:from:peer:)` opens no exchange for it — and it is the only
    /// door that carries addressing WITHOUT any digest, because the joiner has nothing to
    /// reconcile: it is being told, not asked.
    private static let grantDoors = ["private func grantAdmission(to request:"]

    /// The two doors that send a membership digest WITHOUT opening an exchange: the post-merge proof
    /// (P5 item 7, D-7.8) and the joiner's post-adoption digest (D-7.33).
    private static let nonAskDoors = [
        "private func readvertiseMergeProof(to peers:",
        "private func attemptLedgerAdoption(ownAdmission:"
    ]

    /// The three doors that open an exchange, and therefore carry both halves of it.
    private static let askDoors = [
        "private func beginMergeExchange(entry:",
        "private func askOneReconnectedPeer(_ peer:",
        "private func handleAdmissionGrant("
    ]

    /// **P5 item 7's own asymmetries, asserted from both sides.** The merge window is cleared at its
    /// three sites and nowhere else; the drain's per-peer budget is still refunded by the three
    /// session resets and still **not** by `abandonMergeExchange`; the membership re-gossip
    /// budget is not refunded by a flap either (D-7.30) — a flapping link must not let a peer
    /// re-spend this device's bytes; and **`pendingMergeEntry` is not folded into the window's
    /// clear** (D-7.23/D-7.29), which is the asymmetry `clearMergeWindow()`'s own doc comment
    /// claims and this is the wall that makes the claim true. Folding `pendingMergeEntry = nil`
    /// into either `clearMergeWindow()` or `resetSessionStateMachine` would silently destroy the
    /// launch restore's `.processRestart` arming, which is set with no window at all.
    @Test func theMergeWindowIsClearedAtExactlyItsOwnSites() throws {
        let source = MeshRoutedSourceScan.codeOnly(try managerSource())
        let cleared = "clearMergeWindow()"
        #expect(source.components(separatedBy: cleared).count - 1 == 4,
                "one declaration plus three call sites")
        for declaration in [
            "private func concludeMergeIfConverged() {",
            "private func abandonMergeExchange() {",
            "private func resetSessionStateMachine(keepingTerminalState: Bool) {"
        ] {
            let body = try #require(Self.functionBody(declaration, in: source),
                                    "\(declaration) is gone from MeshNetworkManager.swift")
            #expect(body.components(separatedBy: cleared).count - 1 == 1,
                    "\(declaration) must clear the merge window exactly once")
        }
        let abandon = try #require(
            Self.functionBody("private func abandonMergeExchange() {", in: source)
        )
        #expect(!abandon.contains("clearRoutedDrainState()"),
                "a partition is not a new session: the drain's budget is not refunded")
        #expect(!abandon.contains("reGossipedToFingerprints"),
                "and neither is the membership re-gossip budget (D-7.30)")
        for declaration in [
            "private func clearMergeWindow() {",
            "private func resetSessionStateMachine(keepingTerminalState: Bool) {"
        ] {
            let body = try #require(Self.functionBody(declaration, in: source),
                                    "\(declaration) is gone from MeshNetworkManager.swift")
            #expect(!body.contains("pendingMergeEntry"),
                    "\(declaration) must not fold in the pre-window arming slot (D-7.23/D-7.29)")
        }
    }

    /// **The reach set is a transport fact, not a traffic class.** `reachableMergePeers()` reads
    /// every committed slot, never `activeSlots` and never the `activeSlots`-based
    /// `reachableRosterFingerprints()`, which is the obvious wrong reuse.
    ///
    /// Only a source wall can catch this: `rerankSlots()` re-assigns a slot's `kind` from ranging
    /// samples that `FakePeerNetwork` never produces, so the demotion half of the bug is invisible
    /// to tier 1 — a demoted-but-linked peer would silently leave the pending set and 2d would
    /// return, triggered by a distance sample with no membership meaning.
    @Test func theMergeWindowsReachSetIsEveryCommittedSlot() throws {
        let source = MeshRoutedSourceScan.codeOnly(try managerSource())
        let reach = try #require(
            Self.functionBody("private func reachableMergePeers() -> Set<String> {", in: source)
        )
        #expect(reach.contains("slots.compactMap"), "every committed slot is the reach set")
        #expect(!reach.contains("activeSlots"), "`.active` is a distance rank, not a reach")
        #expect(!reach.contains("reachableRosterFingerprints"), "and neither is the partition helper")
        for declaration in [
            "private func concludeMergeIfConverged() {",
            "private func clearMergeWindow() {",
            "private func recordMergeMatch(_ peer: String) {",
            "private func recordMergeAnswer(_ peer: String) {",
            "private func advanceMergeWindowAfterFold(previousDigest: MeshInventoryDigest?) {",
            "private func readvertiseMergeProof(to peers: Set<String>) {"
        ] {
            let body = try #require(Self.functionBody(declaration, in: source),
                                    "\(declaration) is gone from MeshNetworkManager.swift")
            #expect(!body.contains(".active"), "\(declaration) must not read a slot rank")
            #expect(!body.contains("kind"), "\(declaration) must not read a slot kind")
        }
    }

    /// One function's body found from a declaration **prefix**, brace-matched from the first `{`
    /// after it — so a declaration whose parameters wrap onto several lines can still be named.
    ///
    /// - Parameters:
    ///   - prefix: The declaration's opening text, unique in the file.
    ///   - source: The source to search.
    /// - Returns: The body, or nil when the declaration is gone.
    private static func body(startingWith prefix: String, in source: String) -> String? {
        guard let start = source.range(of: prefix),
              let open = source.range(of: "{", range: start.upperBound..<source.endIndex)
        else { return nil }
        return functionBody(String(source[start.lowerBound..<open.upperBound]), in: source)
    }

    /// The drain state is refunded by the three session resets and by nothing else — not by
    /// `abandonMergeExchange`, where a flapping link would re-spend this device's bytes on every flap.
    ///
    /// Asserted per SITE rather than by counting: a count of four is satisfied by three calls in the
    /// wrong three functions, and `abandonMergeExchange` is exactly the function the count cannot
    /// speak about.
    @Test func theDrainStateIsClearedAtExactlyThreeSites() throws {
        let source = MeshRoutedSourceScan.codeOnly(try managerSource())
        let cleared = "clearRoutedDrainState()"
        #expect(source.components(separatedBy: cleared).count - 1 == 4,
                "one declaration plus three call sites")
        for declaration in [
            "public func leaveMesh() {",
            "func prepareMembershipLedger(meshID: UUID, founderSigningPublicKey: Data?, now: Date = Date()) {",
            "func armJoinerLedger(_ grant: MeshAdmissionGrantPayload, now: Date = Date()) -> Bool {"
        ] {
            guard let body = Self.functionBody(declaration, in: source) else {
                Issue.record("\(declaration) is gone from MeshNetworkManager.swift")
                continue
            }
            #expect(body.components(separatedBy: cleared).count - 1 == 1,
                    "\(declaration) must clear the drain state exactly once")
        }
        let abandon = try #require(
            Self.functionBody("private func abandonMergeExchange() {", in: source)
        )
        #expect(abandon.contains(cleared) == false,
                "a partition is not a new session: abandonMergeExchange must refund nothing")
    }

    /// One function's body, by brace matching from its declaration — so a wall can say WHICH
    /// function holds a call rather than only how many the file holds.
    private static func functionBody(_ declaration: String, in source: String) -> String? {
        guard let start = source.range(of: declaration) else { return nil }
        var depth = 1
        var index = start.upperBound
        var scanned = 0
        // R2: bounded by the file's own length.
        while index < source.endIndex, scanned < source.count {
            scanned += 1
            if source[index] == "{" { depth += 1 }
            if source[index] == "}" {
                depth -= 1
                if depth == 0 { return String(source[start.upperBound..<index]) }
            }
            index = source.index(after: index)
        }
        return nil
    }

    /// **W1 — the retired gates are gone and the survivors are pinned by count** (P5 item 13).
    ///
    /// A pin table, not a zero list, and the difference is the whole design. Two of the three
    /// `keyEpoch` gates retired WITH the path that made them necessary and are pinned at zero. The
    /// third — `handleEncryptedMetadata`'s compare — is deliberately RETAINED: its two content arms
    /// retired, but its door survives with two control arms that have no routed successor, and
    /// deleting the compare over those would be loosening a gate in place, which is the one move the
    /// wall forbids. `decryptPayload` authenticates the metadata purpose alone, so a wrapper sealed
    /// under the current key but stamped with a foreign epoch would otherwise open and dispatch;
    /// `MeshEncryptionTests.aCurrentKeyWrapperStampedWithAForeignEpochIsRefused` is that case.
    ///
    /// The surviving `keyEpoch` occurrences are named line by line so a new one has to move a
    /// number rather than hide in a total: `sanitizedIncomingPhoto`'s legacy-shape check
    /// (`payload.keyEpoch > 0`) and its re-mint (the `keyEpoch:` label plus `payload.keyEpoch`, two
    /// occurrences on one line), and the retained compare. `currentKeyEpoch` spells `KeyEpoch` and
    /// does not match. `localJoinedEpoch` stands at seven: its declaration, two resets, the grant's
    /// monotonicity compare, two assignments and the rotation fallback — the control plane, which
    /// item 13 never touched.
    ///
    /// A zero list was tried first and could not pass: `.keyEpoch >` is literally contained in
    /// `payload.keyEpoch > 0`, so the wall would have gone red on its own commit and the obvious
    /// green-making move — widening the exemption — would quietly re-admit
    /// `if x.keyEpoch > localJoinedEpoch` anywhere in the manager.
    ///
    /// Read over the manager AND the session photos' file, which holds `sanitizedIncomingPhoto` (and
    /// with it three of the four `keyEpoch` survivors): the pins count over the two, and a retired
    /// gate coming back belongs to whichever of them holds the photo path.
    ///
    /// **The package half** (ProximityKit plan step A1.3's batch D): the manager's file alone, which is
    /// ProximityKit's, each pin at the manager's share of the two files' total, MEASURED 2026-10-15 over
    /// the Fernlet repository's 7c9162bb and over this package's tree alike: `keyEpoch` 1 of the 4 (the
    /// retained compare; the session photos' file holds the legacy-shape check and the re-mint's two),
    /// every other pin unchanged, none of them in that file. The Fernlet repository keeps the session
    /// photos' file at its share: `keyEpoch` 3, every other pin 0.
    @Test func theRetiredEpochGatesAreGoneAndTheSurvivorsArePinned() throws {
        let source = MeshRoutedSourceScan.codeOnly(try managerSource())
        let pins: [(needle: String, pinned: Int)] = [
            ("key.epoch == photo.keyEpoch", 0),
            ("keyEpoch >= localJoinedEpoch", 0),
            ("manifestAnnouncedPhotoAuthors", 0),
            ("wrapper.keyEpoch == currentGroupKey?.epoch", 1),
            ("keyEpoch", 1),
            ("localJoinedEpoch", 7)
        ]
        // R2: six needles over one file.
        for pin in pins {
            let found = source.components(separatedBy: pin.needle).count - 1
            #expect(found == pin.pinned,
                    "\(pin.needle) stands at \(found), pinned at \(pin.pinned)")
        }
    }

    /// **W2 — the retired photo transport is gone**, symbol by symbol (P5 item 13).
    ///
    /// Eleven names, one flow: the group-key photo decrypt and its author claim, the manifest pull
    /// and its request answer, the closed-mode metadata SEAL half whose only two call sites were
    /// that pull, and the two public statics that sealed and opened a photo under the group key.
    /// A count is not enough here — a re-introduction under any of these names is the regression —
    /// so each is pinned at zero by name.
    ///
    /// Read over the manager AND the session photos' file, which holds the photo sender, its quota and
    /// its projection arm: a retired name coming back belongs to whichever of the two holds the photo
    /// path.
    ///
    /// **The package half** (ProximityKit plan step A1.3's batch D): the zero-list over the manager's
    /// file, which is ProximityKit's, read by its path, so a file that is gone throws rather than reading
    /// as clean. The Fernlet repository keeps it over the session photos' file.
    @Test func theRetiredPhotoTransportIsGone() throws {
        let source = MeshRoutedSourceScan.codeOnly(try managerSource())
        let retired = [
            "handleFriendPhotoEnvelope", "decryptedIncomingPhoto", "dispatchPhotoPayload",
            "photoAuthorIsAcceptable", "handlePhotoManifest", "syncPhotoManifest",
            "sendRequestedPhotos", "sendEncryptedMetadata", "encryptPhoto", "decryptPhoto",
            "encryptPayload",
            // The legacy per-sender RECEIVE quota and the two fields that served it. Its routed
            // twin `allowIncomingRoutedPhoto` keys on the ITEM's mesh (D-13.23) where this one
            // keyed on the live one, so a re-introduction would put two per-sender quotas with
            // opposite mesh-keying in one file with nothing saying which is live.
            "allowIncomingPhoto", "receivedPhotoIDsByFingerprint", "receiveQuotaMeshID"
        ]
        var scanned = 0
        // R2: fourteen names over one file.
        for symbol in retired {
            scanned += 1
            #expect(!source.contains(symbol),
                    "\(symbol) came back to MeshNetworkManager.swift")
        }
        #expect(scanned == retired.count, "the retired-transport scan lost a symbol")
    }

    /// **W2 — the retired TEXT transport is gone**, symbol by symbol (P6 item 4).
    ///
    /// The same shape as the photo wall's zero-list, and owed for the same reason: keeping both
    /// paths alive is what makes a retirement a fiction. Seven names, one flow — the registered
    /// `.tempMessage` handler, the payload the fan-out minted, the per-slot capability read that
    /// chose who got one, the per-slot send seam, the retired per-sender token bucket, and the
    /// audit-token family the whole thing logged under.
    ///
    /// The needles are deliberately NARROW. `MeshRoutedTypeToken.tempMessage` is a **live**
    /// registered routed type with the same last component, so a bare `.tempMessage` needle would
    /// be unsatisfiable: the token the routed path mints under is exactly the one whose legacy
    /// wire twin is retired here.
    ///
    /// Read over the manager AND the chat's file, which holds the text sender, its budget and its
    /// projection arm: a retired name coming back belongs to whichever of the two holds the text path.
    ///
    /// **The package half** (ProximityKit plan step A1.3's batch D): the zero-list over the manager's
    /// file, read by its path; the Fernlet repository keeps it over the chat's file.
    @Test func theRetiredTextTransportIsGone() throws {
        let source = MeshRoutedSourceScan.codeOnly(try managerSource())
        let retired = [
            "registerSessionMessageHandler", "TempMessagePayload", "for: .tempMessage",
            "mesh.tempMessage.", "onTempMessageSendForTesting",
            // The capability column decided who received a legacy fan-out. A routed manifest binds
            // wraps ≡ destinations, so a destination cannot be skipped; re-introducing this read
            // would put a second, weaker destination rule beside the roster's.
            "supports(.messages)",
            // The live-arrival token bucket, retired WITH its transport (a policy act): a drain
            // answer carries up to 16 items, so burst 5 would flood-drop 11 legitimate messages,
            // and a fixed per-item `firstSeenAt` never refills it. Its replacement is
            // `allowIncomingRoutedText`, the photo quota's twin, keyed on the ITEM's mesh.
            "rateBucketBySender"
        ]
        var scanned = 0
        // R2: seven names over one file.
        for symbol in retired {
            scanned += 1
            #expect(!source.contains(symbol),
                    "\(symbol) came back to MeshNetworkManager.swift")
        }
        #expect(scanned == retired.count, "the retired-text-transport scan lost a symbol")
    }

    /// **W2 — the retired MESH heart transport is gone**, symbol by symbol (P6 item 6).
    ///
    /// The same zero-list shape the photo and text walls use, and owed for the same reason: keeping
    /// both paths alive is what makes a retirement a fiction. **Three functions, one seam, one
    /// payload spelling.** The registered `.friendHeart` handler and the receiver-side gate chain it
    /// applied (`registerSessionHeartHandler`, `receiveSessionHeart`), the sealed per-slot send that
    /// was this module's only `.friendHeart` call site (`deliverSessionHeart`), the slot-id test seam
    /// that could not be re-aimed in place because the routed path has no slot
    /// (`onSessionHeartSendForTesting`), and the payload spelling itself over comment-stripped
    /// source, so neither file names the legacy payload type in code (the capability composer's
    /// mention of it, in FernletSocial's `FernletMeshCapabilities`, is a comment, and that file is not
    /// read here).
    ///
    /// **`PayloadType.friendHeart` is NOT parked, and that is the one place this row differs from
    /// the text row's.** Parking is what the `.tempMessage` and `.friendPhoto` retirements did
    /// because nothing else used those cases. `.friendHeart` is still LIVE: `PresenceManager` sends
    /// and receives it, it is in `.fernlet`'s sealing set, and `HeartPayload` is still used by the
    /// presence path and by `HeartDropService`. There is nothing to park —
    /// `sealedPayloadTypeCoverageIsComplete` and the sealed-framing pins are untouched — and the
    /// presence heart path is deliberately left alone (P9's).
    ///
    /// Read over the manager AND the session hearts' file, which holds the heart sender, its seams and
    /// the heart row's ledger judge: a retired name coming back belongs to whichever of the two holds
    /// the heart path.
    ///
    /// **The package half** (ProximityKit plan step A1.3's batch D): the zero-list over the manager's
    /// file, read by its path. The Fernlet repository keeps it over the session hearts' file, with
    /// `PayloadType.friendHeart`'s frozen rawValue and its live use in FernletSocial's `PresenceManager`,
    /// which are its own type and file.
    @Test func theRetiredMeshHeartTransportIsGone() throws {
        let source = MeshRoutedSourceScan.codeOnly(try managerSource())
        let retired = [
            "registerSessionHeartHandler", "receiveSessionHeart", "deliverSessionHeart",
            "onSessionHeartSendForTesting", ".friendHeart"
        ]
        var scanned = 0
        // R2: five names over one file.
        for symbol in retired {
            scanned += 1
            #expect(!source.contains(symbol),
                    "\(symbol) came back to MeshNetworkManager.swift")
        }
        #expect(scanned == retired.count, "the retired-mesh-heart scan lost a symbol")
    }

    /// The other half of the retirement: `PayloadType.tempMessage` is **parked, not deleted**.
    ///
    /// The `.friendPhoto` precedent (D-13.5, itself `.sessionGoodbye`'s): the case, its frozen
    /// `rawValue` and its membership in `.fernlet`'s sealing set all stay, and `TempMessagePayload`
    /// stays decodable, so an older peer's frame parks by name rather than being mis-dispatched or
    /// failing a session. Six unrelated suites also use the token as their sealing-required
    /// CONTROL, so deleting it would drag them into this item.
    ///
    /// Nothing registers a handler for it, in either module a registration can come from: the mesh
    /// registers a feature's handler only through its token door (ProximityKit has no typed
    /// registration), and every feature in FernletSocial spells `forToken: PayloadType.<case>.rawValue`,
    /// so that spelling and the typed one are both refused across ProximityKit and FernletSocial.
    ///
    /// **The package half** (ProximityKit plan step A1.3's batch D): the registration scan over
    /// ProximityKit's module, at the original's floor for it, 120 files. `PayloadType` and `.fernlet`'s
    /// sealing set are FernletDomainModel's and FernletConnections', so the Fernlet repository keeps the
    /// rawValue and sealing checks, with the scan over FernletSocial at its floor of 15 files.
    @Test func theLegacyTextPayloadTypeIsParkedNotDeleted() throws {
        let kit = try MeshP7Acceptance.sources()
        #expect(kit.count >= 120,
                "the registration scan read only \(kit.count) ProximityKit files")
        let registrations = [
            "registerPayloadHandler(forToken: PayloadType.tempMessage.rawValue",
            "registerPayloadHandler(for: .tempMessage)"
        ]
        // R2: bounded by the two spellings.
        for needle in registrations {
            let homes = Set(MeshP7Acceptance.homes(of: needle, in: kit)).sorted()
            #expect(homes.isEmpty, "while NOTHING registers a handler for it: `\(needle)` is in \(homes)")
        }
    }

    /// **Item 13's precondition, still green after item 13.** The routed section names no epoch,
    /// group key, branch or partition symbol — and it now carries the sender door, the projection
    /// and the re-entry projection pass, so the claim is about real content code rather than about
    /// plumbing with nothing to gate: the routed path's authorisation is the origin's signature plus the per-recipient key
    /// wrap, which is what lets item 13 delete the three `keyEpoch` gates rather than loosen them.
    @Test func theRoutedPathNamesNoEpochSymbol() throws {
        let source = try managerSource()
        guard let start = source.range(of: "// MARK: - Routed drain (network migration P5 item 6") else {
            Issue.record("the routed drain section is gone from MeshNetworkManager.swift")
            return
        }
        let rest = String(source[start.upperBound...])
        let body = rest.range(of: "// MARK: -").map { String(rest[..<$0.lowerBound]) } ?? rest
        let section = MeshRoutedSourceScan.codeOnly(body)
        #expect(section.count > 5_000, "the routed drain section is suspiciously short")
        for forbidden in ["keyEpoch", "currentGroupKey", "branchView", "partition"] {
            #expect(section.contains(forbidden) == false, "the routed drain names a forbidden symbol")
        }
    }

    // MARK: - P5 item 12: the replay window, wired

    /// The four routed CONTENT doors, by declaration prefix — the only four the window is wired at.
    private static let contentDoors = [
        "private func ingestRoutedManifest(",
        "private func ingestRoutedChunk(",
        "private func ingestCustodyReceipt(",
        "private func ingestRecipientReceipt("
    ]

    /// The two DIGEST doors, which are deliberately outside the window (D-5.12, D-6.10).
    private static let digestDoors = [
        "func receiveRoutedInventory(",
        "private func receiveRoutedDrainAnswer("
    ]

    /// **W1 — the window is wired at every routed content door, and nowhere else.**
    ///
    /// Per door, so a count of four satisfied by four calls in the wrong four functions fails; and
    /// manager-wide, so a fifth call site anywhere in the ~10 400-line file — including inside a
    /// helper a digest door reaches, which the per-door half cannot see — fails here rather than in
    /// the field. Five of each: four call sites plus one declaration.
    @Test func theReplayWindowIsWiredAtEveryRoutedContentDoor() throws {
        let source = MeshRoutedSourceScan.codeOnly(try managerSource())
        for door in Self.contentDoors {
            let body = try #require(Self.body(startingWith: door, in: source),
                                    "\(door) is gone from MeshNetworkManager.swift")
            #expect(body.components(separatedBy: "routedFrameIsReplayed(").count - 1 == 1,
                    "\(door) probes the replay window exactly once")
            #expect(body.components(separatedBy: "noteRoutedFrame(").count - 1 == 1,
                    "\(door) records into the replay window exactly once")
        }
        #expect(source.components(separatedBy: "routedFrameIsReplayed").count - 1 == 5,
                "one declaration plus exactly the four content doors")
        #expect(source.components(separatedBy: "noteRoutedFrame").count - 1 == 5,
                "one declaration plus exactly the four content doors")
    }

    /// **W2 — the probe precedes the verifier AND the first store read**, which is the whole point:
    /// a replayed frame must be refused before the signature work and before any sealed-index load.
    @Test func theReplayProbePrecedesTheVerifierAndTheStore() throws {
        let source = MeshRoutedSourceScan.codeOnly(try managerSource())
        for door in Self.contentDoors {
            let body = try #require(Self.body(startingWith: door, in: source))
            let probe = try #require(body.range(of: "routedFrameIsReplayed("),
                                     "\(door) does not probe the window at all")
            let expensive = ["Verifier(", "routedStore(", "store."]
                .compactMap { body.range(of: $0)?.lowerBound }
            #expect(expensive.isEmpty == false, "\(door) reads neither a verifier nor the store?")
            for offset in expensive {
                #expect(probe.lowerBound < offset,
                        "\(door) pays for a verify or a store read before the replay probe")
            }
        }
    }

    /// **W3 — the digest family is not admitted** (D-5.12: an inventory digest's replay defence is
    /// its slot binding and the per-peer frame budget, never a freshness check; D-6.10: a drain
    /// answer is already bound to advertiser + `advertisedAt`). W1's manager-wide count is what
    /// closes the helper-shaped escape from this one.
    @Test func theDigestFamilyIsNotAdmittedToTheWindow() throws {
        let source = MeshRoutedSourceScan.codeOnly(try managerSource())
        for door in Self.digestDoors {
            let body = try #require(Self.body(startingWith: door, in: source),
                                    "\(door) is gone from MeshNetworkManager.swift")
            #expect(!body.contains("routedFrameIsReplayed("), "\(door) must not probe the window")
            #expect(!body.contains("noteRoutedFrame("), "\(door) must not record into the window")
        }
    }

    /// **W4 — cleared at the session resets and nowhere else.** Clearing on a partition flap would
    /// hand an attacker the eviction primitive the window refuses to offer (D-6.6's argument, only
    /// stronger here).
    @Test func theReplayWindowIsClearedOnlyAtTheSessionResets() throws {
        let source = MeshRoutedSourceScan.codeOnly(try managerSource())
        let cleared = "routedReplayWindow = nil"
        #expect(source.components(separatedBy: cleared).count - 1 == 1,
                "the window is cleared at exactly one place in the manager")
        let clear = try #require(
            Self.functionBody("private func clearRoutedDrainState() {", in: source)
        )
        #expect(clear.contains(cleared), "and that place is the three session resets' one helper")
        let abandon = try #require(
            Self.functionBody("private func abandonMergeExchange() {", in: source)
        )
        #expect(!abandon.contains(cleared), "a partition is not a new session")
        #expect(!abandon.contains("forget("), "and a flap is not an eviction primitive either")
    }

    /// **W5 — the frame axis is DERIVED, and carries a maximal item.** Aimed at the property rather
    /// than the call, because the call can only name the property: the testing override lives there.
    @Test func theRoutedReplayFrameBoundIsDerived() throws {
        #expect(MeshRoutedDrainBounds.sessionFramesPerPeer >= MeshChunkFormat.maxChunkCount + 1,
                "the routed replay window must hold a maximal item's chunks plus its manifest")
        let source = MeshRoutedSourceScan.codeOnly(try managerSource())
        let capacity = try #require(
            Self.body(startingWith: "private var routedReplayCapacity: Int", in: source),
            "routedReplayCapacity is gone from MeshNetworkManager.swift"
        )
        #expect(capacity.contains("MeshRoutedDrainBounds.sessionFramesPerPeer"),
                "the frame cap must be derived from the session budget it mirrors")
        #expect(capacity.rangeOfCharacter(from: CharacterSet(charactersIn: "0123456789")) == nil,
                "a literal here is a second, undocumented bound")
        let arguments = PackageTestTreeWallTests.constructionArguments(
            of: "MeshFrameReplayWindow(", in: source
        )
        #expect(arguments.count == 1, "the manager builds exactly one replay window")
        #expect(arguments.first?.contains("framesPerSender: routedReplayCapacity") == true,
                "the construction must take the derived capacity, not a literal")
    }

    /// **W6 — the routed window never forgets an AUTHOR.** A departed origin's content is exactly
    /// what a custodian keeps forwarding after a departure hand-off, so releasing that axis would
    /// hand an attacker a free replay of the content custody transfer exists to keep moving.
    /// `forget(frameID:from:)` — the repaired-slot un-record — is a different verb and is permitted.
    @Test func theRoutedWindowNeverForgetsASender() throws {
        let section = try #require(Self.routedSection(in: try managerSource()))
        #expect(section.contains("forget(senderFingerprint:") == false,
                "the routed path must never release an author's axis")
        #expect(section.contains("forget("), "and it must still un-record a repaired slot")
    }

    /// **W7 — the author axis is the ADMISSION cap, not the roster cap.** Every routed verifier
    /// resolves its author's key from the admission set, whose capacity is `maxRecordsPerKind`; a
    /// departed origin is not a roster member at all, so at the roster cap the ninth author's every
    /// frame would answer `senderWindowFull` and never be caught on repeat.
    @Test func theRoutedReplayAuthorBoundIsTheAdmissionCap() throws {
        #expect(MeshMembershipBounds.maxRecordsPerKind >= MeshMembershipBounds.maxRosterMembers,
                "the admission set is the wider population, and the window is sized on it")
        let source = MeshRoutedSourceScan.codeOnly(try managerSource())
        let arguments = PackageTestTreeWallTests.constructionArguments(
            of: "MeshFrameReplayWindow(", in: source
        )
        #expect(arguments.first?.contains("maxSenders: MeshMembershipBounds.maxRecordsPerKind") == true,
                "the author cap must name the admission-set bound, never a literal or the roster cap")
    }

    /// **W8 — item 8's hop bound survives a replayed manifest.** The probe is sender-blind, so the
    /// `originServedItems` write runs on the replayed path too; without it a courier's copy followed
    /// by the origin's own would strand that leg at the origin's next departure.
    @Test func theHopBoundSurvivesAReplayedManifest() throws {
        let source = MeshRoutedSourceScan.codeOnly(try managerSource())
        let door = try #require(
            Self.body(startingWith: "private func ingestRoutedManifest(", in: source)
        )
        #expect(door.components(separatedBy: "noteOriginServed(").count - 1 == 2,
                "the replayed path and the admitted path each write the hop bound")
        let first = try #require(door.range(of: "noteOriginServed("))
        let admitting = try #require(door.range(of: "admittingManifest("))
        #expect(first.lowerBound < admitting.lowerBound,
                "the replayed path's write must come first — it is the early return's own line")
    }

    /// The routed drain section's own source, sliced exactly as `theRoutedPathNamesNoEpochSymbol`
    /// slices it, with whole-line comments removed.
    private static func routedSection(in source: String) -> String? {
        guard let start = source.range(of: "// MARK: - Routed drain (network migration P5 item 6")
        else { return nil }
        let rest = String(source[start.upperBound...])
        let body = rest.range(of: "// MARK: -").map { String(rest[..<$0.lowerBound]) } ?? rest
        return MeshRoutedSourceScan.codeOnly(body)
    }

    /// Every routed store site in the manager names an explicit scope — the host's, never the
    /// production one.
    ///
    /// The forbidden spelling is assembled at run time on purpose: `MeshRoutedStoreIsolationTests`
    /// greps every test source for it, so writing it as a literal here would fail that wall from
    /// inside the test that exists to enforce the same rule. In this package the same sweep is
    /// `PackageTestTreeWallTests`' routed store wall, which reads every file of this target's tests.
    @Test func theDrainNamesItsStoreScopeExplicitly() throws {
        let source = try managerSource()
        let production = "MeshRoutedStorageScope" + "." + "production"
        #expect(source.contains("MeshRoutedStore(scope: store.meshRoutedStorage)"))
        #expect(source.contains(production) == false)
    }
}
