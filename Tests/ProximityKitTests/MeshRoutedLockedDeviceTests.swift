// MeshRoutedLockedDeviceTests.swift
// ProximityKitTests
//
// Network migration P5 item 10 (plan §11 "locked device", §19.5, invariant 7): ciphertext-only
// custody under a lock, the one pushed gate that decides whether PLAINTEXT may exist, and the
// re-entry an unlock, a foreground or a cleared duress session owes.
//
// The finding this suite is written against: after the first post-boot unlock a locked device's
// routed store is **`loaded`** — the seal key is `AfterFirstUnlockThisDeviceOnly` and the files are
// `…UntilFirstUserAuthentication` — so custody, custody receipts and photo/text recipient receipts
// already work with the screen off. `MeshRoutedAccessGate` is therefore NOT a proxy for store
// readability: the store answers readability itself, in five states, and the gate answers a
// different question. Both halves are asserted here, and their orthogonality is itself a cell (T2
// drives the gate with the store sealable; T3/T4 drive the store's states with the gate untouched).
//
// Tier 1 throughout: `MeshRoutedDrainRig` on `FakePeerNetwork`, an injected clock, no radio and no
// wall-clock sleeps. `DeviceBindingID.$testOverride` drives the STORE's states (`.readError` ⇒
// deferred, `.unavailable` ⇒ seal-refused, `.identifier(install)` ⇒ loaded) and
// `applyRoutedAccessGate(_:now:)` drives the GATE — deliberately two independent knobs.
//
// The audit log is process-global and suites run in parallel (D-8.31), so every claim about a
// logged line is a **containment** claim, and every claim about a state is made against this rig's
// own store as well.
//
// A partial copy (ProximityKit plan step A1.3's batch D, the routed track): of the Fernlet
// repository's FernletTests file of the same name, this holds only the source walls of
// `MeshRoutedLockedDeviceTests` that read ProximityKit's sources, under their suite's name and their
// own: W1's ProximityKit half (`theAccessPredicatesEachHaveExactlyOneDefinition`), W2
// (`everyRoutedPlaintextSeamNamesItsPredicate`), W3 (`theCustodyDoorsNameNoAccessGate`), W3(c)
// (`theDecryptingFileGuardsOnItsPredicate`), W4 (`noRoutedDoorCollapsesAnOutcomeToADefault`) and
// W5's ProximityKit half (`theKeychainClassesTheLockStoryRestsOnAreNamedInSource`), with the data and
// helpers they read. The suite's behavioural cells, W2's FernletSocial half, the app's walls (W6 to
// W8 and the launch restore) and the two other halves stay there, so what this header and the docs
// say of them is not held here. The `Mesh/` sweeps of W3 and W4 are floored here, which the
// original's are not (W4 is a zero-list).

import Foundation
import Testing

// MARK: - The locked device

/// Locked-device handling end to end: the gate's truth table, the five store states at the routed
/// doors, and the re-entry.
@MainActor
@Suite(.serialized)
struct MeshRoutedLockedDeviceTests {
}

// MARK: - The source walls

/// The tripwires. Item 10 adds a predicate and a re-entry, not a decrypt: the enforcement that
/// matters is a wall that fails the moment P6 or item 13 adds a plaintext seam which does not name
/// the gate. Said plainly rather than dressed up — a tripwire plus a predicate, never a claim that
/// something is being blocked today.
@MainActor
extension MeshRoutedLockedDeviceTests {

    /// The ten files whose authority is the STORE's five states, never the access gate.
    private static let custodyDoorFiles = [
        "MeshRoutedStore.swift", "MeshRoutedCustody.swift", "MeshRoutedCustodyCommit.swift",
        "MeshRoutedIndex.swift", "MeshRoutedStoreKey.swift", "MeshRoutedContentHasher.swift",
        "MeshChunkAdmissionRule.swift", "MeshRoutedCustodyHandoff.swift",
        "MeshRoutedCapacity.swift", "MeshRoutedDeliveryHold.swift"
    ]

    /// Every `.swift` file under one folder of ProximityKit's source folder, comments stripped, in path
    /// order: `folder` is a path under ``PackageSwiftFiles/sourceFolder`` (`"Mesh"`), and the empty
    /// folder is the whole module.
    ///
    /// Whole-line comments are removed so a wall states something about CODE rather than about the
    /// prose explaining why the code does not do a thing — this file's own subjects document
    /// themselves at length in exactly those terms.
    ///
    /// Read through the package's walker (``PackageSwiftFiles/sources()``) in place of the Fernlet
    /// repository's directory enumerator over a repository-relative path; each caller holds its read to
    /// a floor.
    private static func codeSources(under folder: String) throws -> [(name: String, code: String)] {
        let prefix = folder.isEmpty ? "" : folder + "/"
        var sources: [(name: String, code: String)] = []
        // R2: bounded by the module's own file list.
        for file in try PackageSwiftFiles.sources() where file.path.hasPrefix(prefix) {
            sources.append((
                URL(fileURLWithPath: file.path).lastPathComponent,
                MeshRoutedSourceScan.codeOnly(file.text)
            ))
        }
        return sources
    }

    /// How many times `needle` occurs in `haystack`.
    private static func occurrences(of needle: String, in haystack: String) -> Int {
        haystack.components(separatedBy: needle).count - 1
    }

    /// The fewest Swift files a `Mesh/` sweep may read: about four fifths of the 75 the folder holds at
    /// the package's 0.1.0, MEASURED 2026-10-15 (as many as at the Fernlet repository's 7c9162bb), so a
    /// folder that stops resolving fails the wall that reads it rather than passing over nothing.
    private static let meshSourceFloor = 60

    /// **W1.** Each of the three predicates is defined exactly once in the whole package: one
    /// question, one answer, and no second definition to answer it more weakly.
    ///
    /// **The package half** (ProximityKit plan step A1.3's batch D): ProximityKit's module, which
    /// declares all three (`MeshNetworkManager.swift`), at the module walk's floor. The Fernlet
    /// repository's sweep read every module of its `FernletKit/Sources`, and it keeps that half: no
    /// module of its own defines one.
    @Test func theAccessPredicatesEachHaveExactlyOneDefinition() throws {
        let sources = try Self.codeSources(under: "")
        #expect(sources.count >= PackageSwiftFiles.sourceFloor, "the package source sweep found too few files")
        for predicate in ["var mayDecryptRoutedContent",
                          "var mayMutateCanonicalStoreWithRoutedContent",
                          "var mayCommitRoutedHeartLedgerJudgement"] {
            let defined = sources.reduce(0) { $0 + Self.occurrences(of: predicate, in: $1.code) }
            #expect(defined == 1, "a routed access predicate is defined other than exactly once")
        }
    }

    /// The qualified spellings a real routed decrypt, canonical mutation or heart judgement has to
    /// write, each with the one file it may legitimately appear in and the count pinned **there**.
    /// Everywhere else in `ProximityKit` the count is zero.
    ///
    /// Pinned counts rather than per-file containment alone, because containment cannot fire where
    /// such a seam would actually land: `MeshNetworkManager.swift` **defines** all three predicates,
    /// so a decrypt written there would name one by construction and pass a containment check
    /// automatically. A pin says the honest thing instead and fails the build on the first
    /// unaccounted-for seam, wherever it is written.
    ///
    /// **The counts are raw substring counts over comment-stripped source**, so a needle a target's
    /// own DECLARATION also spells counts twice. The first two dodge that by construction (the
    /// declarations read `static func unwrap(` and `static func open(` in other files); the third
    /// does not, and its arithmetic is written out below rather than left to be re-derived.
    ///
    /// Row by row:
    ///
    /// * `MeshRoutedContentKeyWrapper.unwrap(` — **1**, in the delivery door. P5 item 13's one
    ///   content-key unwrap. Not "≥ 1", and not a home of `""` with a raised count: `elsewhere == 0`
    ///   is what makes the home load-bearing, so a second call site or the same call moved to
    ///   another file still fails.
    /// * `MeshRoutedItemSealer.open(` — **1**, beside it: the plaintext seam's other half.
    /// * `routedCanonicalDispatch(` — **0** in ProximityKit, a zero-pin, so an arm cannot come back to
    ///   the engine unseen: every projection arm is its host's, behind the projection handler the host
    ///   registers for its routed type's token (Fernlet's chat and session photos, in FernletSocial,
    ///   whose arms ``fernletSocialNamesNoEngineSeamAndCallsItsArmsOnlyFromItsHandlersWrite()`` holds to
    ///   their handlers' writes). This is W2(b), the canonical-mutation half item 10 handed forward; a
    ///   second, ungated mutation is a build failure rather than a review catch.
    /// * `dispatchRoutedPlaintext(` — **2** in the manager: the declaration plus its single call
    ///   site in `routedProjectionVerdict`. It is the row the P6 item 4 fix review added (finding
    ///   P2-2), and the reason is that item 4 HOISTED the mutation guard one level up: every arm
    ///   reaches its canonical store (FernletSocial's session photos' `holdSessionPhoto` and chat's
    ///   `receiveIncoming`, each through its handler) through this one verb, which sits *above* the
    ///   pinned needle, so a second caller of it — a live-door shortcut, say — would reach every
    ///   canonical store with no mutation guard, leave `routedCanonicalDispatch(` where it stands,
    ///   and satisfy the containment half (a whole-file `contains`, vacuous in the defining file) for
    ///   free. Pinning the outer verb is what closes
    ///   that; it names the same predicate in the containment half below. **Pinned by shape**: the
    ///   verb is non-generic, over the type-erased box each token's handler is stored in, so its
    ///   declaration is matched by the needle and the count is 2. A generic declaration
    ///   (`dispatchRoutedPlaintext<`) would drop the count to 1 and owe a separate pin of
    ///   `func dispatchRoutedPlaintext<` at 1, or a second declaration would hide.
    /// * `.projectRoutedItem(` — **1** in the manager: the ONE call of a registered projection
    ///   handler's canonical write, inside the open-then-project step that
    ///   `registerRoutedProjectionHandler(_:forToken:)` builds for the handler's token. The needle's
    ///   leading dot matches a call and never a handler's own `func projectRoutedItem(` declaration, so
    ///   a second call of a handler's write, reached any other way, moves it.
    /// * `.openThenProject(` — **1** in the manager: the ONE invocation of that step, in
    ///   `dispatchRoutedPlaintext`. The box's closure is a verb of its own: a second invocation would
    ///   reach every registered handler's canonical write ungated while `.projectRoutedItem(` (the
    ///   closure's body) and `dispatchRoutedPlaintext(` both stood still, so it is pinned for the
    ///   reason the outer verb is. The box is how the engine calls a handler without opening an
    ///   existential; a generic dispatch would retire this row.
    /// * `.judgeRoutedItem(` — **1** in the manager: the ONE call of a registered ledger judge's
    ///   commit, inside the open-then-judge step that `registerRoutedLedgerJudge(_:forToken:)` builds
    ///   for the judge's token. The leading dot matches a call and never a judge's own
    ///   `func judgeRoutedItem(` declaration (the protocol's, in `MeshRoutedLedgerJudge.swift`, or a
    ///   host's judge's, FernletSocial's session hearts'), so a second call of a judge's commit, reached
    ///   any other way, moves it.
    /// * `.openThenJudge(` — **1** in the manager: the ONE invocation of that step, in
    ///   `ledgerJudgement`, behind the ceremony's readiness, author, admission and blob legs. Pinned
    ///   for the reason `.openThenProject(` is: a second invocation would reach every registered
    ///   judge's commit with those legs skipped while `.judgeRoutedItem(` (the closure's body) stood
    ///   still. The box is how the engine calls a judge inside the ack door's `@autoclosure` without
    ///   opening an existential; a generic ceremony would retire this row.
    /// * `MeshRoutedHeartAck(` — no row: the ack is the heart judge's proof gate, FernletSocial's, and
    ///   W2's FernletSocial half (``fernletSocialNamesNoEngineSeamAndCallsItsArmsOnlyFromItsHandlersWrite()``)
    ///   pins its ONE construction there, inside the session hearts' judge's `judgeRoutedItem` (at 1
    ///   since P6 item 6). The ack proves the ledger stands behind the gift; it is not the evidence.
    /// * `.ledgerCommit(` — **2** (`.heartLedgerCommit(` at 2 since P6 item 6), and in **two** files:
    ///   the stage precondition's own `guard case` in `MeshRoutedDeliveryCommit.stageShortfall` (the
    ///   *reader* of the evidence, which judges nothing) and the engine's one mint in the manager's
    ///   `ledgerJudgement`, from a registered judge's `.committed` answer: the evidence is the
    ///   engine's, minted for the judged item and never by a judge or a host. That second home is why
    ///   ``routedPlaintextSeams`` had to grow a `homes`
    ///   SET: with one home per needle, `elsewhere == 0` fails for this row no matter what number is
    ///   pinned. **The widening is forced, not chosen**, and both escapes are blocked — a factory on
    ///   the enum or on `MeshRoutedLedgerCommit` would put the spelling in `MeshRoutedAck.swift`,
    ///   which is in ``heartEvidenceHomes`` and therefore EXEMPT from the containment half, so the
    ///   mint would sit in a file the wall does not require to name
    ///   `mayCommitRoutedHeartLedgerJudgement`, and it would move this pin; and a mint inside
    ///   `MeshRoutedDeliveryCommit.swift` — a `nonisolated extension MeshRoutedStore` that could
    ///   build the bare value but ask no judge — moves this pin too.
    private static let routedPlaintextSeams: [(needle: String, homes: Set<String>, pinned: Int)] = [
        ("MeshRoutedContentKeyWrapper.unwrap(", ["MeshRoutedItemDelivery.swift"], 1),
        ("MeshRoutedItemSealer.open(", ["MeshRoutedItemDelivery.swift"], 1),
        // A zero-pin: every projection arm is a host's, behind the handler it registers for its token
        // (FernletSocial's chat and session photos, held by the FernletSocial half below), so an arm
        // spelled anywhere in ProximityKit is a failure.
        ("routedCanonicalDispatch(", ["MeshNetworkManager.swift"], 0),
        // Added at the P6 item 4 fix review: the hoisted mutation guard lives one level ABOVE
        // `routedCanonicalDispatch`, so the pin has to reach the outer verb too (finding P2-2).
        // Pinned by shape: non-generic over the handler box, so 2.
        ("dispatchRoutedPlaintext(", ["MeshNetworkManager.swift"], 2),
        // A registered handler's canonical write is called once, inside the box's open-then-project
        // step, and that step is invoked once, in `dispatchRoutedPlaintext`.
        (".projectRoutedItem(", ["MeshNetworkManager.swift"], 1),
        (".openThenProject(", ["MeshNetworkManager.swift"], 1),
        // A registered judge's commit is called once, inside the box's open-then-judge step, and that
        // step is invoked once, in `ledgerJudgement`.
        (".judgeRoutedItem(", ["MeshNetworkManager.swift"], 1),
        (".openThenJudge(", ["MeshNetworkManager.swift"], 1),
        (".ledgerCommit(", ["MeshRoutedDeliveryCommit.swift", "MeshNetworkManager.swift"], 2)
    ]

    /// The two files that name the heart evidence without judging anything: the enum's own
    /// declaration and the stage precondition that reads it.
    private static let heartEvidenceHomes: Set<String> =
        ["MeshRoutedAck.swift", "MeshRoutedDeliveryCommit.swift"]

    /// **W2.** No routed plaintext seam exists that does not name its predicate — and today none
    /// exists at all.
    ///
    /// Two halves. **The pin** (``routedPlaintextSeams``) counts every occurrence of the nine
    /// qualified spellings across `FernletKit/Sources/ProximityKit` — the whole module, not just
    /// `Mesh/`, because `MeshRoutedContentKeyWrapper` and its `unwrap` are internal to all of it, so
    /// a decrypt under `HeartSharing/` or `Messaging/` would otherwise be invisible — and requires
    /// each to stand at its recorded number. **The containment half**
    /// (``expectPlaintextSeamsNameTheirPredicate(_:)``) is the rule P6 and item 13 inherit the day a
    /// pin legitimately rises. The scan keys on the qualified call because a bare `.unwrap(` also
    /// matches the app lock's own Secure Enclave wrap.
    @Test func everyRoutedPlaintextSeamNamesItsPredicate() throws {
        let sources = try Self.codeSources(under: "")
        #expect(sources.count >= PackageSwiftFiles.sourceFloor, "the ProximityKit source sweep found too few files")
        // R2: the table's own needles over the module's own bounded file list.
        for seam in Self.routedPlaintextSeams {
            var atHome = 0
            var elsewhere = 0
            for source in sources {
                let found = Self.occurrences(of: seam.needle, in: source.code)
                if seam.homes.contains(source.name) { atHome += found } else { elsewhere += found }
            }
            #expect(elsewhere == 0, "a routed plaintext seam appeared outside its pinned homes")
            #expect(atHome == seam.pinned, "a routed plaintext seam's pinned count moved")
        }
        // **The guard on the shape change itself** (P6 item 6). For a single-element `homes` set the
        // summed form is semantically identical to the one-home form it replaced, so the widening
        // costs nothing — but only while it stays confined to the one row that forced it. Without
        // this, a later edit could relax `unwrap(`, `open(` or `routedCanonicalDispatch(` to two homes
        // with no deliberate decision anywhere.
        let widened = Self.routedPlaintextSeams.filter { $0.homes.count > 1 }
        #expect(widened.map(\.needle) == [".ledgerCommit("],
                "exactly ONE seam may stand in two files, and it is the heart evidence's")
        Self.expectPlaintextSeamsNameTheirPredicate(sources)
    }

    /// W2's containment half: whoever moves a pin in ``routedPlaintextSeams`` must name the gating
    /// predicate in the same file — ``MeshNetworkManager/mayDecryptRoutedContent`` for a decrypt,
    /// ``MeshNetworkManager/mayMutateCanonicalStoreWithRoutedContent`` for a canonical mutation,
    /// ``MeshNetworkManager/mayCommitRoutedHeartLedgerJudgement`` for a heart judgement.
    ///
    /// **The decrypt arm asks for a `guard`, not a mention** (P5 item 13, D-13.3 amended). A
    /// decorative occurrence of the identifier would satisfy a `contains` while the file that
    /// produces the plaintext never consulted the answer — the vacuity item 10 argued against — and
    /// P6 adds two more callers to this same seam. `MeshRoutedItemDelivery` therefore takes the
    /// predicate as a parameter under that exact spelling and guards on it as its first line.
    ///
    /// **And this half cannot see a SECOND entry point in an already-guarding file** (P6 item 4).
    /// The scan is a whole-FILE `contains`, so a second door could skip the guard entirely while the
    /// first door's occurrence kept the file green. That is closed by structure rather than by a
    /// wall: the one door left — the generic `openBody`, which every family's body opens through, a
    /// projection handler's and a ledger judge's alike — reaches the ciphertext through one private
    /// `openPlaintext(…)` whose first line is the guard, which is also what keeps the `unwrap(` /
    /// `open(` pins at 1 as callers are added. A new body family conforms to `MeshRoutedBody` and
    /// opens through `openBody`, or writes a second guard.
    ///
    /// The manager arm is the mention, because containment there is vacuous by construction (it
    /// DEFINES the predicates); the pinned counts of `routedCanonicalDispatch(` and the three verbs
    /// above it are the enforcement on that side, exactly as D-10.17 argued. The canonical-mutation
    /// list carries all four — the inner arm, the outer verb, a registered handler's write and the
    /// box step that calls it — so a file outside the manager that spells any of them must name the
    /// mutation predicate. The heart-judgement list carries four the same way — the ack's
    /// construction, the evidence's mint, a registered judge's commit and the box step that calls it
    /// — so a file outside the evidence's two homes that spells any of them must name the heart
    /// stage's predicate. (The ack's construction is FernletSocial's, where the FernletSocial half
    /// pins it; its spelling stays on this list, so it cannot come back to a ProximityKit file that
    /// names no predicate.)
    ///
    /// Note the deliberate pairing with W3(b), which exempts exactly the files this half matches — a
    /// new decrypting file MUST name the decrypt predicate here, so W3(b) may not forbid the token
    /// there.
    private static func expectPlaintextSeamsNameTheirPredicate(
        _ sources: [(name: String, code: String)]
    ) {
        // R2: bounded by the module's own file list.
        for source in sources where source.name != "MeshRoutedContentKeyWrapper.swift" {
            guard source.code.contains("MeshRoutedContentKeyWrapper.unwrap(") else { continue }
            #expect(source.code.contains("guard mayDecryptRoutedContent"),
                    "a routed decrypt appeared in a file that does not GUARD on the decrypt predicate")
        }
        // R2: the module's file list times the four canonical-mutation spellings — the inner verb,
        // the hoisted outer one that reaches every arm (P6 item 4 fix review, finding P2-2), a
        // registered handler's write and the box step that invokes it.
        for needle in ["routedCanonicalDispatch(", "dispatchRoutedPlaintext(", ".projectRoutedItem(", ".openThenProject("] {
            for source in sources where source.code.contains(needle) {
                #expect(source.code.contains("mayMutateCanonicalStoreWithRoutedContent"),
                        "a routed canonical mutation appeared in a file that never names its predicate")
            }
        }
        // R2: the same bound — over the four heart-judgement spellings: the ack's construction,
        // the evidence's mint, a registered judge's commit and the box step that invokes it.
        for source in sources where !Self.heartEvidenceHomes.contains(source.name) {
            let mutates = source.code.contains("MeshRoutedHeartAck(")
                || source.code.contains(".ledgerCommit(")
                || source.code.contains(".judgeRoutedItem(")
                || source.code.contains(".openThenJudge(")
            guard mutates else { continue }
            #expect(source.code.contains("mayCommitRoutedHeartLedgerJudgement"),
                    "a routed heart judgement appeared in a file that never names its predicate")
        }
    }

    /// **W3.** Custody's authority stays the store's five states.
    ///
    /// (a) no custody door names the gate, its predicates or the `sealCustody` case — a lock fact at
    /// a ciphertext door would delete the locked-device feature; (b) the vocabulary cannot spread:
    /// under the mesh directory the two tokens appear only in the manager and in the gate's own file
    /// (which is not a custody door, and necessarily contains `case .sealCustody` inside
    /// `permits(_:)`).
    ///
    /// **(b) exempts a file that performs a routed decrypt**, because W2's containment half
    /// *requires* such a file to name ``MeshNetworkManager/mayDecryptRoutedContent``. Without the
    /// exemption the two walls would be mutually unsatisfiable for the first real decrypt outside
    /// the manager — every new `Mesh/` file would fail one or the other, silently forcing every
    /// routed decrypt into `MeshNetworkManager.swift`. `routedAccessGate` itself stays confined: a
    /// decrypting file consults the manager's **predicate**, never the gate value.
    ///
    /// **(b)'s sweep is floored here** (ProximityKit plan step A1.3's batch D): at least
    /// ``meshSourceFloor`` files of `Mesh/`, the vocabulary's two homes among them, so a sweep that read
    /// nothing cannot pass (b) over nothing.
    @Test func theCustodyDoorsNameNoAccessGate() throws {
        var scanned = 0
        for name in Self.custodyDoorFiles {
            let code = MeshRoutedSourceScan.codeOnly(
                try PackageRoot.source("Sources/ProximityKit/Mesh/\(name)")
            )
            scanned += 1
            for token in ["routedAccessGate", "mayDecryptRoutedContent",
                          "mayMutateCanonicalStoreWithRoutedContent", ".sealCustody"] {
                #expect(code.contains(token) == false, "a custody door consulted the access gate")
            }
        }
        #expect(scanned == Self.custodyDoorFiles.count, "the custody-door scan lost a file")

        let allowed: Set<String> = ["MeshRoutedAccessGate.swift", "MeshNetworkManager.swift"]
        let mesh = try Self.codeSources(under: "Mesh")
        #expect(mesh.count >= Self.meshSourceFloor, "the Mesh/ sweep read only \(mesh.count) files")
        #expect(allowed.isSubset(of: Set(mesh.map(\.name))), "the gate's two homes are gone from the Mesh/ sweep")
        for source in mesh
        where !allowed.contains(source.name) {
            #expect(source.code.contains("routedAccessGate") == false,
                    "the gate's vocabulary spread beyond the manager and its own file")
            // The W2 exemption: a file W2's containment half already obliges to name the predicate
            // cannot also be forbidden from naming it.
            guard source.code.contains("MeshRoutedContentKeyWrapper.unwrap(") == false else { continue }
            #expect(source.code.contains("mayDecryptRoutedContent") == false,
                    "the decrypt predicate spread beyond the manager and the gate's own file")
        }
    }

    /// **W3(c) — the decrypting file guards on its predicate, and W3(b)'s exemption is live.**
    ///
    /// Three claims in one place, because the interesting thing about them is that they hold
    /// TOGETHER. `MeshRoutedItemDelivery.swift` performs the one routed unwrap and the one item
    /// open; it names the decrypt predicate as a `guard`, not decoratively; and it therefore takes
    /// W3(b)'s exemption, which until P5 item 13 no file did. An exemption nothing exercises is a
    /// hole nobody would notice closing — so this asserts it is exercised by exactly the file W2's
    /// containment half obliges to name the predicate.
    @Test func theDecryptingFileGuardsOnItsPredicate() throws {
        let code = MeshRoutedSourceScan.codeOnly(
            try PackageRoot.source("Sources/ProximityKit/Mesh/MeshRoutedItemDelivery.swift")
        )
        #expect(code.contains("MeshRoutedContentKeyWrapper.unwrap("),
                "the delivery door no longer performs the unwrap W3(b) exempts it for")
        #expect(code.contains("MeshRoutedItemSealer.open("),
                "the delivery door no longer opens the item blob")
        #expect(code.contains("guard mayDecryptRoutedContent"),
                "the decrypting file must GUARD on the predicate, not merely mention it")

        var exempted: [String] = []
        for source in try Self.codeSources(under: "Mesh")
        where !["MeshRoutedAccessGate.swift", "MeshNetworkManager.swift"].contains(source.name) {
            guard source.code.contains("MeshRoutedContentKeyWrapper.unwrap("),
                  source.code.contains("mayDecryptRoutedContent") else { continue }
            exempted.append(source.name)
        }
        #expect(exempted == ["MeshRoutedItemDelivery.swift"],
                "W3(b)'s exemption must be exercised by exactly the routed delivery door: \(exempted)")
    }

    /// **W4.** No routed door collapses an outcome to a default.
    ///
    /// `.value ?? []` made a deferred store, a seal refusal and a genuinely receipt-less item
    /// produce one identical answer — invariant 7's failure mode expressed as a diagnostic.
    ///
    /// **A zero-list, so floored here** (ProximityKit plan step A1.3's batch D): the sweep reads at least
    /// ``meshSourceFloor`` files of `Mesh/`, the routed doors' own among them (the store's custody doors,
    /// ``custodyDoorFiles``, and the manager's), so a sweep that stopped reading `Mesh/` fails instead of
    /// counting zero over nothing.
    @Test func noRoutedDoorCollapsesAnOutcomeToADefault() throws {
        let mesh = try Self.codeSources(under: "Mesh")
        #expect(mesh.count >= Self.meshSourceFloor, "the Mesh/ sweep read only \(mesh.count) files")
        let doors = Set(Self.custodyDoorFiles + ["MeshNetworkManager.swift"])
        #expect(doors.isSubset(of: Set(mesh.map(\.name))),
                "the routed doors' files are gone from the Mesh/ sweep: \(doors.subtracting(mesh.map(\.name)).sorted())")
        var found = 0
        for source in mesh {
            found += Self.occurrences(of: ".value ??", in: source.code)
        }
        #expect(found == 0, "a routed door collapsed a five-state outcome into a default")
    }

    /// **W5.** The four keychain rows the whole lock story rests on still spell their class in
    /// source, so a "background decrypt would be convenient" patch cannot move one quietly. The
    /// answer to that request is **no**, never an accessibility change.
    ///
    /// **The package half** (ProximityKit plan step A1.3's batch D): the three rows that are
    /// ProximityKit's; the install binding's row, FernletCrypto's `DeviceBindingID.swift`, is the Fernlet
    /// repository's, and it keeps that half.
    @Test func theKeychainClassesTheLockStoryRestsOnAreNamedInSource() throws {
        let files = [
            "Sources/ProximityKit/Mesh/MeshRoutedStoreKey.swift",
            "Sources/ProximityKit/Mesh/MeshSessionKeyStore.swift",
            "Sources/ProximityKit/Identity/IdentityService.swift"
        ]
        var scanned = 0
        for path in files {
            let code = MeshRoutedSourceScan.codeOnly(try PackageRoot.source(path))
            scanned += 1
            #expect(code.contains("kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"),
                    "a row the locked-device story rests on no longer names its class")
        }
        #expect(scanned == files.count, "the keychain-class scan lost a file")
    }
}
