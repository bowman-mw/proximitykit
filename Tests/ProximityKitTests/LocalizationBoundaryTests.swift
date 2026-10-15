// LocalizationBoundaryTests.swift
// ProximityKitTests
//
// The "localization wall" of the Fernlet repository, sibling there of its privacy, no-tracking and
// Power-of-10 walls. THE RULE: every string is exactly ONE of two things, and never both: a TOKEN (a
// persisted `rawValue`, a wire byte, a dictionary key, an accessibility identifier), English FOREVER,
// or DISPLAY, text a person reads, which alone localizes. Every failure mode it guards is SILENT:
// inside an SPM module, `String(localized:)` and SwiftUI's `LocalizedStringKey` resolve against
// `Bundle.main`, the host app's bundle, unless `bundle: .module` is passed, so the build is clean and
// the string is simply never translated.
//
// A partial copy (ProximityKit plan step A1.3, which copies into the package every cell of the Fernlet
// repository's tests that reads this module's sources before that repository stops holding them): that
// repository's suite of this name walks its package's sources, this module's among them, in six cells,
// each a zero-list over this module today. This copy holds those six over this module's sources alone,
// with the suite's name and theirs unchanged, every file read through the package's walker
// (`TestSupport/PackageSwiftFiles.swift`) at its floor, the matchers copied unchanged, and the planted
// fixtures that prove each matcher fires, since a zero-list whose matcher nobody has proven is
// indistinguishable from one that never fires:
//
//   A   `String(localized:)` / `AttributedString(localized:)` passes `bundle: .module` (this module
//       declares no resources, so no call can resolve against its own bundle and none stands);
//   A2  no source names a retired key of the app-lock and period-sheet copy;
//   E   no SwiftUI display literal and no `LocalizedStringKey` holding a literal of its own;
//   F   no accessibility label, value or hint typed `String`;
//   G   no bare literal in a `LocalizedError` member a person reads;
//   H1  no bare literal assigned to a UIKit display or accessibility property.
//
// Every allowlist of the original names a file outside this module, so each is empty here. The cells
// over the app, its extensions, its catalogs and its frozen tokens, and A2's half that requires the
// rewritten keys, stay in that repository's original, so what this header says of them is not held
// here.

import Foundation
import Testing

/// The localization wall's rules over ProximityKit's own sources: every `String(localized:)` resolves
/// against the module's bundle, no retired key is named, no SwiftUI display literal or held
/// `LocalizedStringKey` resolves against the host's bundle, no accessibility copy is typed `String`, and
/// no `LocalizedError` member or UIKit display property holds a bare literal; each matcher held to its
/// planted fixtures.
///
/// Concurrency: the scans are pure functions over `String`s read off disk, nonisolated.
struct LocalizationBoundaryTests {

    // MARK: - A. The `bundle: .module` wall

    /// The one root every rule here reads: this module's sources, by their path under the package root,
    /// through the package's walker (``moduleSources()``). The Fernlet repository's original reads its
    /// whole package's sources for parts A and E, and its app's too for parts F, G and H1.
    static let packageSourceRoot = PackageSwiftFiles.sourceFolder

    /// Floor for every scan here: the package walker's own floor, about four fifths of the module's
    /// files, so a root that stops resolving fails rather than reading as clean. (The Fernlet
    /// repository's original floors its wider roots at 170 and 320 files.)
    static let minimumPackageFilesScanned = PackageSwiftFiles.sourceFloor

    /// A package call site where `bundle:` is not merely unnecessary but IMPOSSIBLE.
    ///
    /// `String(localized:)` has an overload taking a `LocalizedStringResource` — a value the CALLER
    /// built, carrying the bundle the caller attached to it. That overload has no `bundle:`
    /// parameter, and the file doing the resolving holds no key of its own, so failure mode (A) —
    /// a literal in package source silently falling back to English — cannot occur: there is no
    /// literal to fall back to.
    ///
    /// Matched on path AND exact call text so an entry can never drift onto a different call, and
    /// an entry that stops matching is reported rather than left to rot (the
    /// `Scripts/power-of-10-allowlist.json` house rule: every entry states the invariant that makes
    /// it safe).
    struct BundleFreeResolution: Sendable {
        /// Repo-relative path of the file.
        let path: String
        /// The call's exact flattened text, as ``LocalizedCallSite/report`` renders it.
        let call: String
        /// Why `bundle:` cannot apply here.
        let reason: String
    }

    /// Every allowlisted bundle-free resolution in this module: none. The Fernlet repository's
    /// original allows one call, in a module of its own (its VoiceOver announcer), and holds that
    /// entry to its exact call; a call here resolving a caller's resource would need its own entry,
    /// argued as that one is.
    static let bundleFreeResolutions: [BundleFreeResolution] = []

    /// One `String(localized:…)` call site found in package source.
    ///
    /// `text` is the WHOLE call — from `String` through its matching close paren, newlines included —
    /// because the argument that matters is routinely written on a later line than the head. Testing
    /// the span rather than the line is what makes multi-line formatting a non-issue.
    struct LocalizedCallSite: Hashable, Sendable {
        /// Repo-relative path of the file the call lives in.
        let path: String
        /// 1-based line of the `String(` head.
        let line: Int
        /// The full call text, from `String` to its matching `)`.
        let text: String
        /// Whether the call resolves against `.module`.
        ///
        /// Not "passes a `bundle:` argument at all", which is what this asked at first and what an
        /// adversarial review walked through by planting `bundle: .main` in package source. Inside
        /// a package `.main` is the APP's bundle — precisely the wrong one, and precisely the typo
        /// an app→package migration produces — so accepting it made the rule agree with the bug.
        let passesBundle: Bool

        /// `path:line: <call text, single-lined>` — pasteable straight into a search.
        var report: String {
            let flattened = text
                .components(separatedBy: .newlines)
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .joined(separator: " ")
            return "\(path):\(line): \(flattened)"
        }
    }

    /// Inside an SPM module, `String(localized:)` resolves its key against `Bundle.main` — the APP's
    /// bundle — unless `bundle: .module` is passed. The package's `Localizable.xcstrings` lives in the
    /// module bundle, so the lookup misses, falls back to the English literal baked into the code, and
    /// returns it. Nothing throws, nothing warns, no test fails: the string is simply never translated
    /// for the life of the product.
    ///
    /// That is why this is a wall and not a lint note. The mistake is invisible in every English build
    /// — which is every build anyone on this project runs — and only shows up as a half-translated
    /// screen in a language the team cannot proofread.
    ///
    /// The FLOOR is on FILES SCANNED, not on call sites found. Call-site count is not a health signal:
    /// it was zero when localization Phase 1 started, 96 a few hours later, and it will keep moving —
    /// while a green run here always means "no violations", which is indistinguishable from "the scan
    /// read nothing" unless the file count is pinned separately. The planted fixtures below carry the
    /// other half of the proof: that the matcher fires at all.
    @Test func everyPackageLocalizedStringPassesModuleBundle() throws {
        let (sites, filesScanned) = try Self.scanPackageForLocalizedCalls()

        #expect(
            filesScanned >= Self.minimumPackageFilesScanned,
            """
            Scanned only \(filesScanned) Swift files under \(Self.packageSourceRoot) (floor \
            \(Self.minimumPackageFilesScanned)) — the root moved or the enumerator broke, and this \
            wall is now passing without looking at anything.
            """
        )

        let bundleless = sites.filter { !$0.passesBundle }
        let offenders = bundleless.filter { !Self.isAllowlistedBundleFree($0) }
        #expect(
            offenders.isEmpty,
            """
            \(offenders.count) `String(localized:)` call(s) inside ProximityKit omit `bundle: .module`. \
            Inside a package that resolves against Bundle.main, finds no catalog entry, and silently \
            returns the English literal FOREVER — no error, no warning, no failing test but this one. \
            Add `bundle: .module` to each:
            \(offenders.map(\.report).sorted().joined(separator: "\n"))
            """
        )

        // Allowlist hygiene: an entry that no longer matches anything is an entry nobody is
        // reading, and it would silently cover the next call that happens to land on that text.
        let unused = Self.bundleFreeResolutions.filter { entry in
            !bundleless.contains { Self.matches(entry, $0) }
        }
        #expect(
            unused.isEmpty,
            """
            \(unused.count) allowlisted bundle-free resolution(s) match no call any more. Delete \
            them — a stale entry is a hole nobody is watching:
            \(unused.map { "\($0.path): \($0.call)" }.sorted().joined(separator: "\n"))
            """
        )
    }

    /// Whether a bundle-less call is one of the ``bundleFreeResolutions``.
    static func isAllowlistedBundleFree(_ site: LocalizedCallSite) -> Bool {
        bundleFreeResolutions.contains { matches($0, site) }
    }

    /// Exact path AND exact flattened-call match — never a prefix or a path-only match, so an entry
    /// cannot widen to cover a neighbouring call added later in the same file.
    static func matches(_ entry: BundleFreeResolution, _ site: LocalizedCallSite) -> Bool {
        guard site.path == entry.path else { return false }
        return site.report.hasSuffix(": \(entry.call)")
    }

    /// Fixture: the call scanner flags a bundle-less call, accepts a bundled one, and — the case that
    /// actually matters — reads the `bundle:` argument when it sits on a LATER line than the head, or
    /// when the head itself is split across lines.
    ///
    /// Without this the wall is unfalsifiable. Part A is expected to report zero violations forever —
    /// that is what success looks like — so only a planted token can distinguish "nothing is wrong"
    /// from "the matcher never fires".
    @Test func localizedCallScannerSeesBundleAcrossLineBreaks() {
        let bad = #"let greeting = String(localized: "Hello", comment: "greeting")"#
        let badSites = Self.localizedCalls(in: bad)
        #expect(badSites.count == 1)
        #expect(badSites.first?.passesBundle == false)

        let good = #"let greeting = String(localized: "Hello", bundle: .module, comment: "greeting")"#
        #expect(Self.localizedCalls(in: good).first?.passesBundle == true)

        // The argument on a later line — the formatting the wall exists to survive.
        let multiline = """
        let greeting = String(
            localized: "Hello",
            bundle: .module,
            comment: "greeting"
        )
        """
        let multilineSites = Self.localizedCalls(in: multiline)
        #expect(multilineSites.count == 1, "a `String(` head split from `localized:` must still match")
        #expect(multilineSites.first?.passesBundle == true)

        // A nested call and a paren inside the literal must not end the span early.
        let nested = #"String(localized: "Meals (today)", bundle: .module, comment: String(describing: 1))"#
        #expect(Self.localizedCalls(in: nested).first?.passesBundle == true)

        // AttributedString(localized:) has the same Bundle.main default and the same silent failure.
        let attributed = #"AttributedString(localized: "Hello", comment: "x")"#
        #expect(Self.localizedCalls(in: attributed).first?.passesBundle == false)

        // Near-misses that must NOT be treated as call sites.
        #expect(Self.localizedCalls(in: "let s = LocalizedStringResource(\"Hello\")").isEmpty)
        #expect(Self.localizedCalls(in: "func localizedTitle() -> String { \"x\" }").isEmpty)
        #expect(Self.localizedCalls(in: #"let sample = "String(localized: \"x\")""#).isEmpty,
                "a call named inside a string literal is data, not a call site")

        // The real false positives this scan hit on its first run over the tree: doc comments that
        // WARN against localizing at a wire seam. Six of them, all correct, all would have hard-failed
        // CI. A wall that fires on careful documentation is a wall someone deletes.
        let warningComment = """
        /// **DO NOT LOCALIZE ANY STRING THAT REACHES THIS FUNCTION.** A `String(localized:)` anywhere
        /// upstream makes the canonical bytes locale-dependent.
        // nothing here should ever call String(localized:)
        func appendCanonical() {}
        """
        #expect(Self.localizedCalls(in: warningComment).isEmpty,
                "a comment naming String(localized:) is documentation, not a call")
        #expect(Self.localizedCalls(in: "/* String(localized: \"x\") */\nlet y = 1").isEmpty,
                "block comments are skipped too")

        // A comment INSIDE a call must not be able to fake the bundle argument.
        let fakedBundle = """
        String(localized: "Hello",
               // bundle: .module would go here, but nobody added it
               comment: "greeting")
        """
        #expect(Self.localizedCalls(in: fakedBundle).first?.passesBundle == false)
    }

    // MARK: - A2. Retired meanings get new keys (period-data design 2026-09-30, §10.5)

    /// The app-lock loss copy changed MEANING when cycle history started living in Fernlet whether or
    /// not it was copied to Apple Health, so each string moved to a NEW key and its old key is retired:
    /// a new meaning under an old key keeps every translation of the old promise. The same for the
    /// period sheet's refusals and buffer sentences, and "Delete everything"'s scope.
    ///
    /// The ProximityKit half: no source of this module names a retired key. The Fernlet repository's
    /// original also requires every rewritten key to be named, which only its app's sources do; that
    /// half stays there.
    @Test func theRetiredLossCopyKeysAreGoneFromSourceAndTheirV2KeysArePresent() throws {
        let retired = [
            "\"lock.disclosure.forgottenPasscode\"", "\"lock.reset.required.body\"",
            "\"lock.reset.confirm.message\"", "\"lock.hardBinding.message\"",
            "\"logPeriod.refusal.sharingOff.noLock\"", "\"logPeriod.refusal.notesNeedLock\"",
            "\"logPeriod.refusal.sharingOff\"", "\"logPeriod.refusal.sharingOff.edit\"",
            "\"logPeriod.refusal.healthDenied\"", "\"logPeriod.refusal.healthDenied.edit\"",
            "\"logPeriod.error.bufferUnopenable\"", "\"logPeriod.error.bufferFull\"",
            "\"deleteAll.scope.base\""
        ]
        let files = try Self.moduleSources()
        let sources = files.map(\.text).joined()
        #expect(files.count >= Self.minimumPackageFilesScanned,
                "scanned only \(files.count) files — the walk broke and this wall reads nothing")
        #expect(retired.count == 13, "the retired list holds \(retired.count) keys")
        // R2: bounded by the thirteen keys.
        for key in retired {
            #expect(!sources.contains(key), "\(key) is retired (its meaning changed); use its .v2 key")
        }
    }

    // MARK: - E. The SwiftUI display-literal wall

    /// SwiftUI initializers whose first parameter is a `LocalizedStringKey`.
    ///
    /// A bare literal handed to one of these inside a package module is looked up in `Bundle.main`
    /// — the APP's bundle — which never consults the module's own catalog. Same silent failure as
    /// part A, different door: part A watches `String(localized:)`, this watches the SwiftUI half,
    /// and until this test existed the SwiftUI half was completely unguarded. Eighteen live
    /// violations were sitting in `FernletUI` and `ProximityKit` on the day it was written.
    ///
    /// Matched only when the literal is the FIRST argument, so `Text(verbatim:)`,
    /// `Image(systemName:)` and every already-resolved `FernletUICopy.…` call are non-matches by
    /// construction rather than by exclusion list.
    static let displayInitializers = [
        "Text", "Button", "Label", "Toggle", "TextField", "SecureField", "Picker", "Section",
        "Stepper", "Link", "NavigationLink", "ProgressView", "Menu", "DatePicker",
        "ContentUnavailableView", "LocalizedStringKey", "LocalizedStringResource",
    ]

    /// View modifiers whose first parameter is a `LocalizedStringKey`, with the same `Bundle.main`
    /// default and the same silent failure.
    ///
    /// `accessibilityIdentifier` is deliberately ABSENT: an identifier is a token, frozen English
    /// forever, and a wall that demanded a bundle there would be asking for the wrong thing.
    /// `accessibilityLabel`/`Value`/`Hint` have no `bundle:` parameter of their own, so the fix at
    /// those sites is to pass `Text("…", bundle: .module)` — which this scan then sees as a
    /// correct `Text(` call and the modifier as a non-literal first argument.
    static let displayModifiers = [
        "navigationTitle", "navigationBarTitle", "alert", "confirmationDialog",
        "accessibilityLabel", "accessibilityValue", "accessibilityHint",
        "accessibilityAction", "accessibilityInputLabels", "help",
    ]

    /// One SwiftUI display call in package source whose first argument is a string literal.
    struct DisplayLiteralSite: Hashable, Sendable {
        /// Repo-relative path of the file.
        let path: String
        /// 1-based line of the call head.
        let line: Int
        /// The initializer or modifier name, e.g. `Text` or `.alert`.
        let head: String
        /// The literal's text, interpolations collapsed to `{}`.
        let literal: String
        /// Whether a `bundle:` argument appears anywhere in the call span.
        let passesBundle: Bool

        /// `path:line: Head("literal")` — pasteable straight into a search.
        var report: String { "\(path):\(line): \(head)(\"\(literal)\")" }
    }

    /// Inside an SPM module, SwiftUI resolves a `LocalizedStringKey` against `Bundle.main` unless a
    /// `bundle:` argument is passed — and most of these APIs have no `bundle:` parameter at all, so
    /// the only correct form is to resolve first (a copy vault: `FernletUICopy`, `FernletLockCopy`,
    /// `FernletProximityUICopy`, `FernletConnectionsCopy`) or to wrap in `Text(_:bundle:)`.
    ///
    /// This is the exact sibling of ``everyPackageLocalizedStringPassesModuleBundle()`` and exists
    /// because that test could not see SwiftUI. `CLAUDE.md`'s localization-wall paragraph has always
    /// named BOTH doors — "`String(localized:)` **and** SwiftUI's `LocalizedStringKey`" — but only
    /// the first was enforced, which is why `SheetSaveBar`'s `"Save"` default could carry a written
    /// note admitting it was broken and still ship.
    ///
    /// The FLOOR is on files scanned, for the same reason as part A: zero violations is the
    /// intended steady state, and is indistinguishable from a scan that read nothing.
    @Test func packageDisplayLiteralsPassModuleBundle() throws {
        let (sites, filesScanned) = try Self.scanPackageForDisplayLiterals()

        #expect(
            filesScanned >= Self.minimumPackageFilesScanned,
            """
            Scanned only \(filesScanned) Swift files under \(Self.packageSourceRoot) (floor \
            \(Self.minimumPackageFilesScanned)) — the root moved or the enumerator broke, and this \
            wall is now passing without looking at anything.
            """
        )

        let offenders = sites.filter { !$0.passesBundle }
        #expect(
            offenders.isEmpty,
            """
            \(offenders.count) SwiftUI display literal(s) inside ProximityKit resolve against \
            Bundle.main and will render untranslated English FOREVER — clean build, no warning, no \
            other failing test. Resolve through the module's copy vault (FernletUICopy, \
            FernletLockCopy, FernletProximityUICopy, FernletConnectionsCopy) with \
            `String(localized:…, bundle: .module)`, or pass `Text("…", bundle: .module)`:
            \(offenders.map(\.report).sorted().joined(separator: "\n"))
            """
        )

        let held = try Self.scanPackageForHeldKeys()
        #expect(
            held.isEmpty,
            """
            \(held.count) `LocalizedStringKey` member(s) inside ProximityKit hold a literal of their \
            own. A key carries no bundle, so it resolves against Bundle.main and never sees the \
            module's catalog — moving the literal from a call site into a property hides it from \
            every call-site scan without fixing anything. Resolve through the module's copy vault \
            and type the member `String`. (A LocalizedStringKey PARAMETER is correct — that is a \
            caller's key, and it is FernletUI's whole architecture.)
            \(held.map(\.report).sorted().joined(separator: "\n"))
            """
        )
    }

    /// Scans this module's sources for `LocalizedStringKey` members holding their own literals.
    static func scanPackageForHeldKeys() throws -> [DisplayLiteralSite] {
        var sites: [DisplayLiteralSite] = []
        // R2: bounded by the module's file list.
        for file in try moduleSources() {
            for found in localizedStringKeyLiteralDeclarations(in: file.text) {
                sites.append(DisplayLiteralSite(
                    path: file.path, line: found.line, head: "LocalizedStringKey",
                    literal: found.text, passesBundle: false
                ))
            }
        }
        return sites
    }

    /// Fixture: the display-literal scanner fires on each shape it must catch and stays silent on
    /// each shape it must not.
    ///
    /// Without this the wall is unfalsifiable — it is expected to report zero forever, which looks
    /// exactly like a matcher that never runs.
    @Test func displayLiteralScannerSeparatesKeysFromResolvedText() {
        // The two shapes that were actually shipping in the tree.
        #expect(Self.displayLiterals(in: #"Button("Cancel", action: onCancel)"#).count == 1)
        #expect(Self.displayLiterals(in: #"Text("Keep as friends?")"#).first?.literal == "Keep as friends?")

        // A modifier head needs its leading dot; the same word as a declaration must not match.
        #expect(Self.displayLiterals(in: #".accessibilityLabel("12 coins")"#).count == 1)
        #expect(Self.displayLiterals(in: #"func accessibilityLabel("x")"#).isEmpty)

        // The correct forms.
        #expect(Self.displayLiterals(in: #"Text(verbatim: FernletUICopy.save)"#).isEmpty)
        #expect(Self.displayLiterals(in: #"Button(FernletUICopy.cancel, action: action)"#).isEmpty)
        #expect(Self.displayLiterals(in: #"Text("Hello", bundle: .module)"#).first?.passesBundle == true)

        // A literal that is not the FIRST argument is somebody else's parameter, not a key.
        #expect(Self.displayLiterals(in: #"Label(FernletUICopy.done, systemImage: "checkmark")"#).isEmpty)

        // Substring safety: an identifier ENDING in a head word is not that head.
        #expect(Self.displayLiterals(in: #"SheetText("caption")"#).isEmpty)
        #expect(Self.displayLiterals(in: #"myButton("x")"#).isEmpty)

        // Comments naming a call are documentation, not a call — the lesson part A learned the
        // hard way when six doc comments warning against localizing failed CI.
        #expect(Self.displayLiterals(in: #"// never write Text("Hello") here"#).isEmpty)
        #expect(Self.displayLiterals(in: "/* Text(\"Hello\") */\nlet y = 1").isEmpty)
        #expect(Self.displayLiterals(in: #"let sample = "Text(\"Hello\")""#).isEmpty,
                "a call named inside a string literal is data, not a call site")

        // A `bundle:` written inside a COMMENT in the span must not fake the argument.
        let faked = """
        Text("Hello",
             // bundle: .module was never added
             tableName: nil)
        """
        #expect(Self.displayLiterals(in: faked).first?.passesBundle == false)

        // Multi-line: the literal on a later line than the head still matches, and a paren inside
        // the literal does not end the span early.
        let multiline = """
        Text(
            "Meals (today)",
            bundle: .module
        )
        """
        #expect(Self.displayLiterals(in: multiline).first?.passesBundle == true)

        // THE TERNARY. Six of these were live in ProximityKit and the first draft of this rule —
        // which required the literal to be the first token — saw none of them.
        #expect(Self.displayLiterals(in: #"Button(isKept ? "Keeping" : "Keep") { toggle() }"#).count == 1)
        #expect(Self.displayLiterals(in: #"Button(isKept ? copy.keeping : copy.keep) { toggle() }"#).isEmpty)

        // The held-key form: the literal moved out of the call and into a property.
        let heldKey = """
        private var explainerText: LocalizedStringKey {
            saveToPhotos == nil ? "Choose which to save." : "Choose which to keep."
        }
        """
        #expect(Self.localizedStringKeyLiteralDeclarations(in: heldKey).count == 1)

        let resolvedProperty = """
        private var explainerText: String {
            saveToPhotos == nil ? FernletProximityUICopy.Review.explainerSave : FernletProximityUICopy.Review.explainerKeep
        }
        """
        #expect(Self.localizedStringKeyLiteralDeclarations(in: resolvedProperty).isEmpty)

        // A `LocalizedStringKey` PARAMETER is the correct architecture, not a violation — it is the
        // caller's key, harvested into the caller's catalog.
        let parameter = """
        public init(_ label: LocalizedStringKey, @ViewBuilder content: () -> Content) {
            self.label = Text(label)
        }
        """
        #expect(Self.localizedStringKeyLiteralDeclarations(in: parameter).isEmpty)

        // A stored property fed from such a parameter holds no literal of its own.
        #expect(Self.localizedStringKeyLiteralDeclarations(in: "    var placeholder: LocalizedStringKey").isEmpty)

        // The one-line forms. The first draft of the span reader missed BOTH — it required the
        // literal to be on a later line than the `{` — which the plant-it-and-watch-it-fail run
        // caught and no fixture would have.
        #expect(Self.localizedStringKeyLiteralDeclarations(
            in: #"    private var planted: LocalizedStringKey { "Planted" }"#).count == 1)
        #expect(Self.localizedStringKeyLiteralDeclarations(
            in: #"    let planted: LocalizedStringKey = "Planted""#).count == 1)
    }

    /// Fixture: the eight shapes an adversarial review used to walk straight through the first
    /// draft of these rules. One `#expect` per measured evasion; each was green before the
    /// hardening and is red now.
    @Test func hardenedRulesCatchTheMeasuredEvasions() {
        // (a) A parameter DEFAULT — the shape review §4.0 is literally about, and it carries no
        //     `var`/`let` for the property rule to key off.
        #expect(Self.localizedStringKeyLiteralDeclarations(
            in: #"    public init(label: LocalizedStringKey = "Save", disabled: Bool = false) {"#).count == 1)
        // …while a bare key parameter stays correct: that is the CALLER's key.
        #expect(Self.localizedStringKeyLiteralDeclarations(
            in: "    public init(_ label: LocalizedStringKey, disabled: Bool = false) {").isEmpty)
        // …and a literal default on a DIFFERENT parameter is not blamed on this one.
        #expect(Self.localizedStringKeyLiteralDeclarations(
            in: #"    init(_ label: LocalizedStringKey, identifier: String = "row") {"#).isEmpty)

        // (b) A function RETURNING a key — the property shape one keyword away.
        let returningFunction = """
        private func primaryActionLabel() -> LocalizedStringKey {
            saveToPhotos == nil ? "Save selected" : "Keep selected"
        }
        """
        #expect(Self.localizedStringKeyLiteralDeclarations(in: returningFunction).count == 1)

        // (c) The array spelling, which `": LocalizedStringKey"` could never match.
        #expect(Self.localizedStringKeyLiteralDeclarations(
            in: #"    static let names: [LocalizedStringKey] = ["Hat", "Face"]"#).count == 1)
        #expect(Self.localizedStringKeyLiteralDeclarations(
            in: #"    var title: LocalizedStringKey? = "Untitled""#).count == 1)

        // (d) + (e) Two heads that were simply missing from the lists.
        #expect(Self.displayLiterals(in: #".accessibilityAction(named: "Retry") { retry() }"#).count == 1)
        #expect(Self.displayLiterals(in: #"ContentUnavailableView("No meals yet", systemImage: "fork.knife")"#).count == 1)
        // A label-less action is a closure, not copy.
        #expect(Self.displayLiterals(in: ".accessibilityAction { retry() }").isEmpty)

        // (f) A MULTI-LINE signature. Rule F was line-based, so wrapping the parameter list hid the
        //     name from the return type. Nothing more exotic than a line break was needed.
        let wrappedSignature = """
        private func shutterAccessibilityLabel(
            canShoot: Bool
        ) -> String {
        """
        #expect(Self.stringTypedAccessibilityCopy(in: wrappedSignature).count == 1)
        // The same signature, correctly typed, still passes.
        let wrappedCorrect = """
        private func shutterAccessibilityLabel(
            canShoot: Bool
        ) -> Text {
        """
        #expect(Self.stringTypedAccessibilityCopy(in: wrappedCorrect).isEmpty)

        // (h) The verbatim exemption is now ARGUMENT-LEVEL. A literal that merely contains the
        //     word, or an interpolation of a variable named for it, no longer exempts the call.
        #expect(Self.displayLiterals(in: #"Text("Read this verbatim, please")"#).count == 1)
        #expect(Self.displayLiterals(in: #"Text("Signed \(verbatimFingerprint) today")"#).count == 1)
        // The real label still exempts, and so does a `verbatim`-prefixed one.
        #expect(Self.displayLiterals(in: #"Text(verbatim: "already final")"#).isEmpty)
        #expect(Self.displayLiterals(in: #"SheetTextEditor(verbatimPlaceholder: "already final")"#).isEmpty)

        // (g) is NOT here, and cannot be: a member renamed to `spokenName: String` matches no name
        //     fragment any rule can know in advance. That evasion is answered by the pinned list in
        //     `forkedMembers`, and its residue is stated in this file's header.
    }

    /// Fixture: the MULTI-LINE collection forms of evasion (c).
    ///
    /// The first fix for (c) was verified against a one-line array and declared closed; a second
    /// review pointed out that the fixture had flattened the very thing that made it an evasion.
    /// Wrapped across lines the array escaped twice over: ``logicalLines(in:)`` joined only round
    /// brackets, so the literals were never in the declaration's text, and
    /// ``declarationSpanHoldsLiteral(_:startingAt:)`` bails on a declaration with no `{`.
    @Test func multiLineCollectionsOfKeysAreCaught() {
        let wrappedArray = """
        private static let paletteNames: [LocalizedStringKey] = [
            "Near-black",
            "Bark",
        ]
        """
        #expect(Self.localizedStringKeyLiteralDeclarations(in: wrappedArray).count == 1)

        let wrappedDictionary = """
        static let bySlot: [String: LocalizedStringKey] = [
            "hat": "Hat",
            "face": "Face",
        ]
        """
        #expect(Self.localizedStringKeyLiteralDeclarations(in: wrappedDictionary).count == 1)

        // A wrapped collection of ALREADY-RESOLVED strings is the correct shape and stays clean.
        let wrappedResolved = """
        private static var paletteNames: [String] = [
            FernletUICopy.nearBlack,
            FernletUICopy.bark,
        ]
        """
        #expect(Self.localizedStringKeyLiteralDeclarations(in: wrappedResolved).isEmpty)

        // The joiner itself: square brackets now carry a unit across lines, and braces still do not
        // (a joined function body would make every rule read one enormous string).
        #expect(Self.logicalLines(in: "let a = [\n  1,\n  2\n]").first?.text == "let a = [ 1, 2 ]")
        #expect(Self.logicalLines(in: "func f() {\n  let x = 1\n}").first?.text == "func f() {")
        #expect(Self.delimiterBalance("let a = [") == 1)
        #expect(Self.delimiterBalance("]") == -1)
        #expect(Self.delimiterBalance(#"let s = "a [ b""#) == 0)
    }

    /// Fixture: `bundle: .main` inside a package is a violation, not a pass.
    ///
    /// The rule asked only whether a `bundle:` argument existed, so the one wrong value it will
    /// ever realistically be given — `.main`, the app's bundle, which is what an app→package move
    /// leaves behind — read as compliant. It is the same silent English as passing no bundle at all.
    @Test func onlyTheModuleBundleCountsInsidePackageSource() {
        let main = #"String(localized: "Saved", bundle: .main)"#
        #expect(Self.localizedCalls(in: main).first?.passesBundle == false)
        #expect(Self.localizedCalls(in: #"String(localized: "Saved", bundle: Bundle.main)"#).first?.passesBundle == false)

        // The correct spellings, both of them.
        #expect(Self.localizedCalls(in: #"String(localized: "Saved", bundle: .module)"#).first?.passesBundle == true)
        #expect(Self.localizedCalls(in: #"String(localized: "Saved", bundle: Bundle.module)"#).first?.passesBundle == true)

        // A trailing argument must not swallow the bundle value.
        #expect(Self.localizedCalls(in: #"String(localized: "Saved", bundle: .module, comment: "x")"#)
                .first?.passesBundle == true)
        #expect(Self.localizedCalls(in: #"String(localized: "Saved", bundle: .main, comment: "x")"#)
                .first?.passesBundle == false)

        // The SwiftUI half keys off the same helper.
        #expect(Self.displayLiterals(in: #"Text("Saved", bundle: .main)"#).first?.passesBundle == false)
        #expect(Self.displayLiterals(in: #"Text("Saved", bundle: .module)"#).first?.passesBundle == true)
    }

    /// Fixture: ``logicalLines(in:)`` joins a wrapped signature and leaves everything else alone.
    @Test func logicalLinesJoinWrappedSignaturesOnly() {
        let wrapped = """
        func f(
            a: Int,
            b: Int
        ) -> String {
            return "x"
        }
        """
        let units = Self.logicalLines(in: wrapped)
        #expect(units.first?.text == "func f( a: Int, b: Int ) -> String {")
        #expect(units.first?.line == 1)
        // The body lines are their own units — joining must not swallow the whole declaration.
        #expect(units.contains { $0.text == "return \"x\"" })

        // A balanced line is returned untouched, at its own 1-based number.
        let flat = "let a = 1\nlet b = f(2)"
        #expect(Self.logicalLines(in: flat).map(\.text) == ["let a = 1", "let b = f(2)"])
        #expect(Self.logicalLines(in: flat).map(\.line) == [1, 2])

        // A paren inside a string literal or a trailing comment must not unbalance the count.
        #expect(Self.delimiterBalance(#"let s = "a ( b""#) == 0)
        #expect(Self.delimiterBalance("let a = 1  // note (see above)") == 0)
    }

    /// Every display-literal call in `source`. Pure + testable; comments and nested string literals
    /// are skipped through the same ``skipNonCode(_:from:)`` every other scan in this file uses.
    static func displayLiterals(in source: String) -> [DisplayLiteralSite] {
        let chars = Array(source)
        var sites: [DisplayLiteralSite] = []
        var index = 0
        var line = 1
        while index < chars.count {
            if let skip = skipNonCode(chars, from: index) {
                line += countNewlines(chars, from: index, to: skip)
                index = max(skip, index + 1)
                continue
            }
            if chars[index] == "\n" { line += 1 }
            guard let head = displayCallHead(chars, at: index) else {
                index += 1
                continue
            }
            let end = endOfCall(chars, openParen: head.openParen)
            let literal = readStringLiteral(chars, from: head.quote)
            sites.append(DisplayLiteralSite(
                path: "", line: line, head: head.name, literal: literal.text,
                passesBundle: resolvesAgainstModuleBundle(code(chars, from: index, to: end))
            ))
            line += countNewlines(chars, from: index, to: end)
            index = max(end, index + 1)
        }
        return sites
    }

    /// When a display initializer or modifier head starts at `index` AND its FIRST ARGUMENT contains
    /// a string literal, that head's name plus the offsets of its `(` and of the literal's opening
    /// quote; otherwise nil.
    ///
    /// "The first argument contains a literal" — rather than "begins with one" — is what catches the
    /// shape that got past the first draft of this rule and shipped:
    /// `Button(isKept ? "Keeping" : "Keep")`. Six live literals in `ProximityKit` were hiding inside
    /// ternaries and were only found because adding that module's catalog made the harvester write
    /// them out as valueless keys.
    ///
    /// A first argument mentioning `verbatim` is exempt by construction: that label is this repo's
    /// marker for text that is already final, and it is chosen by typing it.
    static func displayCallHead(
        _ chars: [Character], at index: Int
    ) -> (name: String, openParen: Int, quote: Int)? {
        for name in displayModifiers where matches(chars, at: index, ".\(name)") {
            if let found = literalArgument(chars, after: index + name.count + 1) {
                return (".\(name)", found.openParen, found.quote)
            }
        }
        guard index == 0 || !isIdentifierCharacter(chars[index - 1]) else { return nil }
        for name in displayInitializers where matches(chars, at: index, name) {
            if let found = literalArgument(chars, after: index + name.count) {
                return (name, found.openParen, found.quote)
            }
        }
        return nil
    }

    /// The `(` at or after `index` and the opening quote of the first string literal inside its
    /// FIRST argument, when there is one; otherwise nil.
    static func literalArgument(_ chars: [Character], after index: Int) -> (openParen: Int, quote: Int)? {
        let cursor = skipWhitespace(chars, from: index)
        guard cursor < chars.count, chars[cursor] == "(" else { return nil }
        let openParen = cursor
        let argumentEnd = endOfFirstArgument(chars, openParen: openParen)
        // ARGUMENT-LEVEL exemption, not span-level. The first draft asked whether the word
        // "verbatim" appeared anywhere in the first argument, which any literal could satisfy on
        // its own: `Text("read this verbatim")` exempted itself, and so did an interpolation of a
        // variable that merely happened to be named `verbatimSomething`. Only the argument LABEL
        // counts now, because the label is the thing an author has to type on purpose.
        if let label = firstArgumentLabel(chars, openParen: openParen),
           label.lowercased().hasPrefix("verbatim") {
            return nil
        }
        guard let quote = firstQuote(chars, from: openParen + 1, to: argumentEnd) else { return nil }
        return (openParen, quote)
    }

    /// The first argument's LABEL (the identifier before its `:`), or nil when the first argument is
    /// unlabelled — which a string literal always is.
    static func firstArgumentLabel(_ chars: [Character], openParen: Int) -> String? {
        var cursor = skipWhitespace(chars, from: openParen + 1)
        var label = ""
        while cursor < chars.count, isIdentifierCharacter(chars[cursor]), chars[cursor] != "." {
            label.append(chars[cursor])
            cursor += 1
        }
        guard !label.isEmpty else { return nil }
        cursor = skipWhitespace(chars, from: cursor)
        guard cursor < chars.count, chars[cursor] == ":" else { return nil }
        return label
    }

    /// Index just past the first top-level argument of the call opening at `openParen` — the first
    /// `,` at nesting depth 1, or the closing `)`.
    static func endOfFirstArgument(_ chars: [Character], openParen: Int) -> Int {
        var depth = 0
        var index = openParen
        while index < chars.count {
            if let skip = skipNonCode(chars, from: index) {
                index = max(skip, index + 1)
                continue
            }
            let character = chars[index]
            if character == "(" || character == "[" || character == "{" { depth += 1 }
            if character == ")" || character == "]" || character == "}" {
                depth -= 1
                if depth <= 0 { return index }
            }
            if character == ",", depth == 1 { return index }
            index += 1
        }
        return chars.count
    }

    /// The index of the first string-literal quote in `from..<to`, skipping comments.
    static func firstQuote(_ chars: [Character], from: Int, to: Int) -> Int? {
        var index = from
        let end = min(to, chars.count)
        while index < end {
            if chars[index] == "\"" { return index }
            if chars[index] == "/", let skip = skipNonCode(chars, from: index) {
                index = max(skip, index + 1)
                continue
            }
            index += 1
        }
        return nil
    }

    /// Declarations in package source that HOLD a `LocalizedStringKey` literal of their own, in any
    /// of the three shapes a key can hide in.
    ///
    /// The second half of the ternary lesson, hardened after an adversarial review landed 3 of its
    /// 8 evasions here. `private var explainerText: LocalizedStringKey { … }` moves the literal out
    /// of the call and into a property, where no call-site scan can see it — and a key held in
    /// package source carries no bundle, so it still resolves against `Bundle.main`. The first
    /// draft caught only that one shape. All three are caught now:
    ///
    /// - **S — stored or computed property.** `var x: LocalizedStringKey { "…" }`, and the array,
    ///   optional and dictionary spellings (`[LocalizedStringKey]`, `LocalizedStringKey?`), which
    ///   the old `": LocalizedStringKey"` substring silently missed.
    /// - **P — parameter with a literal DEFAULT.** `init(label: LocalizedStringKey = "Save")` — the
    ///   exact shape review §4.0 exists to fix, and it has no `var`/`let` to key off. Only the
    ///   default is a violation; a bare `LocalizedStringKey` parameter is the opposite of one, and
    ///   is `FernletUI`'s whole architecture (it is the CALLER's key).
    /// - **R — function RETURNING a key.** `func label() -> LocalizedStringKey { cond ? "a" : "b" }`
    ///   is the property shape one keyword away, and evaded the property rule completely.
    ///
    /// Every span scan is bounded (Power of 10 rule 2): a declaration is read for at most
    /// ``maximumDeclarationLines`` lines, so a missing closing brace cannot run to end of file.
    static func localizedStringKeyLiteralDeclarations(in source: String) -> [(line: Int, text: String)] {
        let rawLines = source.components(separatedBy: "\n")
        var found: [(line: Int, text: String)] = []
        for unit in logicalLines(in: source) {
            let trimmed = unit.text
            guard !trimmed.hasPrefix("//"), !trimmed.hasPrefix("*") else { continue }
            guard declaresType(trimmed, named: "LocalizedStringKey") else { continue }
            if parameterHoldsLiteralDefault(trimmed, type: "LocalizedStringKey") {
                found.append((unit.line, trimmed))
                continue
            }
            guard isPropertyOrKeyReturningFunction(trimmed, type: "LocalizedStringKey") else { continue }
            // BOTH halves, because a value can live in either place. The joined logical line holds
            // an `= "…"` or an `= [ … ]` collection (square brackets are joined); the raw brace span
            // holds a multi-line computed body, which is NOT joined. Checking only the span missed
            // every multi-line array and dictionary — the span reader bails when a declaration has
            // no `{` at all.
            if valueHoldsLiteral(trimmed) || declarationSpanHoldsLiteral(rawLines, startingAt: unit.line - 1) {
                found.append((unit.line, trimmed))
            }
        }
        return found
    }

    /// True when `text` mentions `name` in TYPE position — after a `:` or a `->`, through any number
    /// of brackets, optionals and generic braces.
    ///
    /// Written as a token test rather than the old `": \(name)"` substring because `[Type]`,
    /// `Type?` and `[String: Type]` are all the same declaration wearing different punctuation, and
    /// the array spelling was a measured evasion.
    static func declaresType(_ text: String, named name: String) -> Bool {
        let chars = Array(text)
        var index = 0
        while index < chars.count {
            guard matches(chars, at: index, name) else {
                index += 1
                continue
            }
            let after = index + name.count
            let boundedAfter = after >= chars.count || !isIdentifierCharacter(chars[after]) || chars[after] == "."
            if boundedAfter, typePositionPrecedes(chars, before: index) { return true }
            index = after
        }
        return false
    }

    /// True when a `:` or `->` introduces the type starting at `index`, ignoring the brackets and
    /// whitespace a container type puts in between.
    static func typePositionPrecedes(_ chars: [Character], before index: Int) -> Bool {
        var cursor = index - 1
        var steps = 0
        while cursor >= 0, steps < 64 {
            let character = chars[cursor]
            if character == ":" { return true }
            if character == ">", cursor > 0, chars[cursor - 1] == "-" { return true }
            guard character == " " || character == "[" || character == "<" || character == "(" else { return false }
            cursor -= 1
            steps += 1
        }
        return false
    }

    /// True when `text` is a `var`/`let` declaration of `type`, or a function RETURNING it.
    static func isPropertyOrKeyReturningFunction(_ text: String, type: String) -> Bool {
        if text.hasPrefix("var ") || text.hasPrefix("let ")
            || text.contains(" var ") || text.contains(" let ") { return true }
        guard let arrow = text.range(of: "->") else { return false }
        return declaresType(String(text[arrow.lowerBound...]), named: type)
    }

    /// True when a parameter of `type` carries a string-literal DEFAULT.
    ///
    /// Scans forward from the type to the end of that ONE parameter (its top-level `,` or the
    /// closing `)`), so a literal default on a *different* parameter — `Bool = false, name: String
    /// = "x"` beside a clean `LocalizedStringKey` — cannot be blamed on this one.
    static func parameterHoldsLiteralDefault(_ text: String, type: String) -> Bool {
        let chars = Array(text)
        var index = 0
        while index < chars.count {
            guard matches(chars, at: index, type), typePositionPrecedes(chars, before: index) else {
                index += 1
                continue
            }
            let end = endOfParameter(chars, from: index + type.count)
            let slice = String(chars[min(index, end)..<end])
            if slice.contains("="), firstQuote(chars, from: index, to: end) != nil { return true }
            index = max(end, index + 1)
        }
        return false
    }

    /// Index of the `,` or `)` ending the parameter that starts at `index`.
    static func endOfParameter(_ chars: [Character], from index: Int) -> Int {
        var depth = 0
        var cursor = index
        while cursor < chars.count {
            if let skip = skipNonCode(chars, from: cursor) {
                cursor = max(skip, cursor + 1)
                continue
            }
            let character = chars[cursor]
            if character == "(" || character == "[" || character == "<" { depth += 1 }
            if character == ")" || character == "]" || character == ">" {
                if depth <= 0 { return cursor }
                depth -= 1
            }
            if character == ",", depth <= 0 { return cursor }
            cursor += 1
        }
        return chars.count
    }

    /// Source lines with their continuations joined, so a declaration split across lines is ONE unit.
    ///
    /// A line whose round OR SQUARE brackets are unbalanced absorbs the lines after it until they
    /// balance. Round brackets alone were the first version, and they made the multi-line signature
    /// evasion visible — but left the collection literal wide open:
    ///
    /// ```swift
    /// static let names: [LocalizedStringKey] = [
    ///     "Hat",                                  // ← invisible while only `(` counted
    ///     "Face",
    /// ]
    /// ```
    ///
    /// which is the same evasion as the wrapped signature, one bracket shape over. Bounded by
    /// ``maximumDeclarationLines`` per unit.
    ///
    /// Returns 1-based start lines and whitespace-collapsed text.
    static func logicalLines(in source: String) -> [(line: Int, text: String)] {
        let rawLines = source.components(separatedBy: "\n")
        var units: [(line: Int, text: String)] = []
        var index = 0
        while index < rawLines.count {
            var joined = rawLines[index].trimmingCharacters(in: .whitespaces)
            var depth = delimiterBalance(joined)
            var consumed = 0
            while depth > 0, index + consumed + 1 < rawLines.count, consumed < maximumDeclarationLines {
                consumed += 1
                let next = rawLines[index + consumed].trimmingCharacters(in: .whitespaces)
                joined += " " + next
                depth += delimiterBalance(next)
            }
            units.append((index + 1, joined))
            index += consumed + 1
        }
        return units
    }

    /// Round and square brackets opened minus closed on one line, ignoring comments and string
    /// literals.
    ///
    /// Braces are deliberately NOT counted: a `{` opens a body, and joining a whole function body
    /// into its signature would make every rule in this file read one enormous string. Bodies are
    /// reached instead through ``declarationSpanHoldsLiteral(_:startingAt:)``, which brace-balances
    /// on purpose.
    static func delimiterBalance(_ line: String) -> Int {
        let chars = Array(line)
        var depth = 0
        var index = 0
        while index < chars.count {
            if let skip = skipNonCode(chars, from: index) {
                if skip > index, chars[index] == "/" { return depth }
                index = max(skip, index + 1)
                continue
            }
            if chars[index] == "(" || chars[index] == "[" { depth += 1 }
            if chars[index] == ")" || chars[index] == "]" { depth -= 1 }
            index += 1
        }
        return depth
    }

    /// How many lines of a declaration the span scan will read before giving up.
    static let maximumDeclarationLines = 40

    /// True when the declaration starting at `index` holds a string literal in its VALUE — after the
    /// `{` of a computed property or the `=` of a stored one.
    ///
    /// Reading the value rather than the whole line is what keeps a `LocalizedStringKey` parameter
    /// (`_ label: LocalizedStringKey`) and a stored property fed from one (`var placeholder:
    /// LocalizedStringKey`) out of the results: neither has a value of its own here.
    static func declarationSpanHoldsLiteral(_ lines: [String], startingAt index: Int) -> Bool {
        var span = ""
        var depth = 0
        var seenBrace = false
        var cursor = index
        let limit = min(index + maximumDeclarationLines, lines.count)
        while cursor < limit {
            if cursor > index, !seenBrace { break }
            let line = lines[cursor]
            span += line + "\n"
            for character in line where character == "{" || character == "}" {
                seenBrace = true
                depth += character == "{" ? 1 : -1
            }
            if seenBrace, depth <= 0 { break }
            cursor += 1
        }
        return valueHoldsLiteral(span)
    }

    /// True when `text` holds a string literal in its VALUE — after the `{` of a computed property
    /// or the `=` of a stored one (or of a parameter default).
    ///
    /// Reading only the value is what keeps a bare `LocalizedStringKey` parameter — a CALLER's key,
    /// and `FernletUI`'s whole architecture — out of the results.
    static func valueHoldsLiteral(_ text: String) -> Bool {
        let chars = Array(text)
        guard let bodyStart = chars.firstIndex(where: { $0 == "{" || $0 == "=" }) else { return false }
        return firstQuote(chars, from: bodyStart, to: chars.count) != nil
    }

    /// True when `character` can appear inside a Swift identifier — the guard that stops `Text(`
    /// from matching inside `SheetText(`.
    static func isIdentifierCharacter(_ character: Character) -> Bool {
        character.isLetter || character.isNumber || character == "_" || character == "."
    }

    /// Scans every `.swift` file of this module for SwiftUI display literals.
    static func scanPackageForDisplayLiterals() throws -> (sites: [DisplayLiteralSite], filesScanned: Int) {
        var sites: [DisplayLiteralSite] = []
        var filesScanned = 0
        // R2: bounded by the module's file list.
        for file in try moduleSources() {
            filesScanned += 1
            for site in displayLiterals(in: file.text) {
                sites.append(DisplayLiteralSite(
                    path: file.path, line: site.line, head: site.head,
                    literal: site.literal, passesBundle: site.passesBundle
                ))
            }
        }
        return (sites, filesScanned)
    }

    // MARK: - F. Accessibility copy may not be typed `String`

    /// Roots scanned by part F: this module's sources. The Fernlet repository's original reads its
    /// app's shipping source too, because the failure it guards is not about bundles at all — it is
    /// about which SwiftUI overload the argument's static type selects.
    static let accessibilityScanRoots = [packageSourceRoot]

    /// Floor for the part-F scan: the package walker's own floor.
    static let minimumAccessibilityFilesScanned = minimumPackageFilesScanned

    /// Identifier fragments that mark a declaration as *accessibility copy* — text whose only job is
    /// to be spoken.
    static let accessibilityCopyNames = [
        "accessibilitylabel", "accessibilityvalue", "accessibilityhint", "accessibilitytext",
    ]

    /// A declaration of accessibility copy that is typed `String`.
    struct AccessibilityCopyDeclaration: Hashable, Sendable {
        /// Repo-relative path.
        let path: String
        /// 1-based line.
        let line: Int
        /// The declaration's trimmed source line.
        let text: String

        /// `path:line: <declaration>` — pasteable straight into a search.
        var report: String { "\(path):\(line): \(text)" }
    }

    /// A `String`-typed accessibility member that is nonetheless correct, and why.
    struct AccessibilityCopyException: Sendable {
        /// Repo-relative path of the file.
        let path: String
        /// The declaration's exact trimmed text.
        let declaration: String
        /// Why `String` is right here.
        let reason: String
    }

    /// Every allowlisted `String`-typed accessibility member in this module: none. The Fernlet
    /// repository's original allows two, in its domain model and its app, each by exact text.
    static let accessibilityCopyExceptions: [AccessibilityCopyException] = []

    /// An accessibility label, value or hint whose static type is `String` does not localize —
    /// SwiftUI's `StringProtocol` overload renders it verbatim — and, worse, the compiler never
    /// harvests it, so the string is not even *present* in the catalog for a translator to find.
    ///
    /// This is the rule the review's §4.5 calls "the highest-value single rule available", and it
    /// deliberately lives HERE rather than in an accessibility wall: it is a localization failure
    /// that happens to surface through accessibility APIs, and one home beats two half-rules.
    ///
    /// It is a TYPE check, not a call-site grep, for the reason §4.5 gives: a grep over
    /// `.accessibilityLabel(x)` cannot tell `x: String` (a defect) from `x: Text` (correct), because
    /// the argument's type is exactly what is invisible at the call site. Checking the declaration
    /// is the one place the type is written down.
    ///
    /// A declaration carrying `verbatim` is exempt by construction: that label is this repo's
    /// documented marker for text that is *already final* (`SectionLabel.init(verbatim:)`,
    /// `EmptyState.init(verbatim:)`, `FernletAnnouncer.announce(_:resolved:)`), and it is chosen by
    /// typing it, which is the whole point of the convention.
    @Test func accessibilityCopyIsNeverTypedString() throws {
        let (declarations, filesScanned) = try Self.scanForStringTypedAccessibilityCopy()

        #expect(
            filesScanned >= Self.minimumAccessibilityFilesScanned,
            """
            Scanned only \(filesScanned) Swift files under \(Self.accessibilityScanRoots.joined(separator: ", ")) \
            (floor \(Self.minimumAccessibilityFilesScanned)) — a root moved or the enumerator broke, \
            and this wall is now passing without looking at anything.
            """
        )

        let offenders = declarations.filter { declaration in
            !Self.accessibilityCopyExceptions.contains { Self.matches($0, declaration) }
        }
        #expect(
            offenders.isEmpty,
            """
            \(offenders.count) accessibility label/value/hint member(s) are typed `String`. SwiftUI \
            renders a `String` VERBATIM — it never localizes — and the compiler never harvests it, \
            so the sentence is not in any catalog for a translator to even see. Declare it as \
            `Text` (or `LocalizedStringKey` for a parameter), or, if it really is already-resolved \
            text, give it a `verbatim` label so the choice is one somebody typed:
            \(offenders.map(\.report).sorted().joined(separator: "\n"))
            """
        )

        let unused = Self.accessibilityCopyExceptions.filter { entry in
            !declarations.contains { Self.matches(entry, $0) }
        }
        #expect(
            unused.isEmpty,
            """
            \(unused.count) allowlisted `String`-typed accessibility member(s) match nothing any \
            more. Delete them — a stale entry is a hole nobody is watching:
            \(unused.map { "\($0.path): \($0.declaration)" }.sorted().joined(separator: "\n"))
            """
        )
    }

    /// Exact path AND exact declaration text — never a path-only match, so an entry cannot turn its
    /// file into an exempt file.
    static func matches(_ entry: AccessibilityCopyException, _ declaration: AccessibilityCopyDeclaration) -> Bool {
        declaration.path == entry.path && declaration.text == entry.declaration
    }

    /// Fixture: the type check fires on each shape that must fail and stays silent on each shape
    /// that must pass.
    ///
    /// Part F is expected to report zero forever, so — as everywhere else in this file — only a
    /// planted token distinguishes "nothing is wrong" from "the matcher never runs".
    @Test func accessibilityCopyTypeCheckSeesTheStringForms() {
        // The four shapes that were live in the tree the day this rule was written.
        #expect(Self.stringTypedAccessibilityCopy(in: "    var accessibilityLabel: String {").count == 1)
        #expect(Self.stringTypedAccessibilityCopy(in: "    private var accessibilityText: String {").count == 1)
        #expect(Self.stringTypedAccessibilityCopy(in: "    private func shutterAccessibilityLabel(canShoot: Bool) -> String {").count == 1)
        #expect(Self.stringTypedAccessibilityCopy(in: "        accessibilityLabel: String,").count == 1)
        #expect(Self.stringTypedAccessibilityCopy(in: "    var accessibilityHint: String?").count == 1,
                "an optional is the same defect")

        // The corrected forms.
        #expect(Self.stringTypedAccessibilityCopy(in: "    var accessibilityLabel: Text {").isEmpty)
        #expect(Self.stringTypedAccessibilityCopy(in: "        accessibilityLabel: LocalizedStringKey,").isEmpty)
        #expect(Self.stringTypedAccessibilityCopy(in: "    private func albumCellLabel(_ post: Post) -> Text {").isEmpty)

        // `verbatim` is the documented "already final" marker and is exempt by construction.
        #expect(Self.stringTypedAccessibilityCopy(in: "        verbatim accessibilityLabel: String,").isEmpty)

        // A CALL SITE is not a declaration — the leading dot is the discriminator, and without it
        // this rule would fire on all ~150 correct `.accessibilityLabel(…)` uses in the app.
        #expect(Self.stringTypedAccessibilityCopy(in: "        .accessibilityLabel(name as String)").isEmpty)
        #expect(Self.stringTypedAccessibilityCopy(in: "            .accessibilityValue(String(describing: x))").isEmpty)

        // Documentation naming the pattern is documentation.
        #expect(Self.stringTypedAccessibilityCopy(in: "    /// var accessibilityLabel: String is the defect").isEmpty)
        #expect(Self.stringTypedAccessibilityCopy(in: "    // accessibilityLabel: String").isEmpty)

        // An unrelated `String` member is not accessibility copy.
        #expect(Self.stringTypedAccessibilityCopy(in: "    var summaryText: String {").isEmpty)
    }

    /// The `String`-typed accessibility-copy declarations in `source`, by line. Pure + testable.
    ///
    /// Runs over ``logicalLines(in:)``, not raw lines. The first draft was line-based, and an
    /// adversarial review broke it by doing nothing more exotic than wrapping a signature:
    ///
    /// ```swift
    /// private func shutterAccessibilityLabel(
    ///     canShoot: Bool
    /// ) -> String {          // ← the name and the type are now on different lines
    /// ```
    ///
    /// Joining continuation lines until the round brackets balance puts the name and the return
    /// type back in one string, which is the only form this rule can reason about.
    static func stringTypedAccessibilityCopy(in source: String) -> [(line: Int, text: String)] {
        var found: [(line: Int, text: String)] = []
        for unit in logicalLines(in: source) {
            let trimmed = unit.text
            guard !trimmed.hasPrefix("//"), !trimmed.hasPrefix("*"), !trimmed.contains("verbatim") else { continue }
            if accessibilityCopyTypes(in: trimmed).contains(where: isStringType) {
                found.append((unit.line, trimmed))
            }
        }
        return found
    }

    /// The declared type of every accessibility-copy member named in `text`.
    ///
    /// Reading each member's OWN type — rather than asking whether the string `": String"` occurs
    /// anywhere in it — is what makes the rule survive line-joining. A wrapped signature legitimately
    /// mixes types (`systemName: String` beside `accessibilityLabel: LocalizedStringKey`), and the
    /// first joined version of this rule reported all three such helpers in the tree as violations.
    /// Returns one entry per named member, so a signature carrying two is fully checked.
    static func accessibilityCopyTypes(in text: String) -> [String] {
        let chars = Array(text)
        var types: [String] = []
        var index = 0
        while index < chars.count {
            guard let nameEnd = accessibilityCopyNameEnd(chars, at: index) else {
                index += 1
                continue
            }
            if let type = declaredType(chars, after: nameEnd) { types.append(type) }
            index = nameEnd
        }
        return types
    }

    /// The index just past an accessibility-copy identifier starting at `index`, or nil.
    ///
    /// Whole-identifier matching: the scan finds identifier STARTS (a letter or `_` whose
    /// predecessor is neither an identifier character nor a `.`), reads the identifier out, and asks
    /// whether it contains one of ``accessibilityCopyNames``. That covers both `accessibilityLabel`
    /// and `shutterAccessibilityLabel` without a second code path, and the leading-dot exclusion is
    /// what separates a DECLARATION from the ~150 correct `.accessibilityLabel(…)` call sites.
    static func accessibilityCopyNameEnd(_ chars: [Character], at index: Int) -> Int? {
        guard chars[index].isLetter || chars[index] == "_" else { return nil }
        if index > 0, isIdentifierCharacter(chars[index - 1]) { return nil }
        var cursor = index
        while cursor < chars.count, chars[cursor].isLetter || chars[cursor].isNumber || chars[cursor] == "_" {
            cursor += 1
        }
        let identifier = String(chars[index..<cursor]).lowercased()
        guard accessibilityCopyNames.contains(where: identifier.contains) else { return nil }
        return cursor
    }

    /// The type a declaration gives the member whose identifier ends at `nameEnd`.
    ///
    /// Two shapes, and only two: `name: Type` (property or parameter) and
    /// `name(<params>) -> Type` (function). Anything else — a call, a `case`, prose — yields nil.
    static func declaredType(_ chars: [Character], after nameEnd: Int) -> String? {
        var cursor = skipWhitespace(chars, from: nameEnd)
        guard cursor < chars.count else { return nil }
        if chars[cursor] == ":" {
            let end = endOfParameter(chars, from: cursor + 1)
            return String(chars[(cursor + 1)..<min(end, chars.count)]).trimmingCharacters(in: .whitespaces)
        }
        guard chars[cursor] == "(" else { return nil }
        cursor = endOfCall(chars, openParen: cursor)
        cursor = skipWhitespace(chars, from: cursor)
        guard matches(chars, at: cursor, "->") else { return nil }
        cursor = skipWhitespace(chars, from: cursor + 2)
        var end = cursor
        while end < chars.count, chars[end] != "{" { end += 1 }
        return String(chars[cursor..<end]).trimmingCharacters(in: .whitespaces)
    }

    /// True when a declared type IS `String` (optionals included) rather than merely mentioning it.
    ///
    /// `StringProtocol`, `StringLiteralType` and `[String]` are other types; a bare `String`,
    /// `String?` and `String!` are the defect, and `= "default"` after it is still the same type.
    static func isStringType(_ type: String) -> Bool {
        var head = type
        // A property carries its body brace and a parameter its default; neither is part of the
        // type. Trimming both is what lets `var accessibilityLabel: String {` and
        // `accessibilityHint: String? = nil` resolve to the same answer as a bare `String`.
        if let brace = head.firstIndex(of: "{") { head = String(head[..<brace]) }
        if let equals = head.firstIndex(of: "=") { head = String(head[..<equals]) }
        head = head.trimmingCharacters(in: .whitespaces)
        return head == "String" || head == "String?" || head == "String!"
    }

    /// Scans this module's sources for `String`-typed accessibility copy.
    static func scanForStringTypedAccessibilityCopy() throws -> (
        declarations: [AccessibilityCopyDeclaration], filesScanned: Int
    ) {
        var declarations: [AccessibilityCopyDeclaration] = []
        var filesScanned = 0
        // R2: bounded by the module's file list.
        for file in try moduleSources() {
            filesScanned += 1
            for found in stringTypedAccessibilityCopy(in: file.text) {
                declarations.append(AccessibilityCopyDeclaration(
                    path: file.path, line: found.line, text: found.text
                ))
            }
        }
        return (declarations, filesScanned)
    }

    // MARK: - G. `LocalizedError` copy may not be a bare literal

    /// Roots scanned by part G: this module's sources. The Fernlet repository's original reads its
    /// app's shipping source too, for part F's reason — the defect is not about bundles.
    static let localizedErrorScanRoots = [packageSourceRoot]

    /// Floor for the part-G scan: the package walker's own floor.
    static let minimumLocalizedErrorFilesScanned = minimumPackageFilesScanned

    /// The `LocalizedError` members whose value a person actually reads.
    ///
    /// `helpAnchor` is deliberately absent: it names a macOS help-book anchor, which is a token.
    static let localizedErrorCopyMembers = ["errorDescription", "failureReason", "recoverySuggestion"]

    /// A user-facing sentence sitting in a `LocalizedError` member as a plain literal.
    struct LocalizedErrorLiteral: Hashable, Sendable {
        /// Repo-relative path.
        let path: String
        /// 1-based line of the literal itself, not of the member that holds it.
        let line: Int
        /// The literal's text, with any interpolation collapsed to `{}`.
        let literal: String

        /// `path:line: "<literal>"` — pasteable straight into a search.
        var report: String { "\(path):\(line): \"\(literal)\"" }
    }

    /// A bare literal in a `LocalizedError` member that is nonetheless correct, and why.
    struct LocalizedErrorException: Sendable {
        /// Repo-relative path of the file.
        let path: String
        /// The literal's exact text.
        let literal: String
        /// Why no key belongs here.
        let reason: String
    }

    /// Every allowlisted bare literal. Keep this list short: entries are copy a person could in
    /// principle read, exempted only because no build that reaches a person contains them.
    ///
    /// `#if DEBUG` copy needs no entry — ``debugOnlyLineFlags(in:)`` skips it structurally, because
    /// a sentence that is not in the shipping binary cannot be read in any language.
    /// Empty, and that is the finished state. It held three `MessageTransportProbe` sentences whose
    /// argument was "its target owns no catalog, so cataloguing them buys a translator nothing".
    /// Rule H2 gave the Messages extension a catalog and a `TARGETS` line, which retired the
    /// argument rather than answering it — the three sentences are now keyed like every other one,
    /// at a cost of nine lines. The probe itself is still dead code with zero call sites; deleting
    /// it remains the right cleanup, and now costs three catalog keys rather than a rule change.
    static let localizedErrorExceptions: [LocalizedErrorException] = []

    /// A sentence returned from `errorDescription` / `failureReason` / `recoverySuggestion` as a
    /// plain literal never reaches a catalog, so it renders English in every language forever.
    ///
    /// This is a BODY rule, and it has to be: parts A and E read only package source, and part
    /// F — the one rule that reads `App/` — asserts that display copy is not typed `String`.
    /// `LocalizedError` mandates `String?`, so F's type signal cannot fire here and its remedy
    /// (declare it `Text`) is not available. `String(localized:)` inside the body is the only form
    /// that reaches a catalog, so the only thing left to check is whether it is there.
    ///
    /// The check is deliberately blunt: after every `String(localized:)` / `AttributedString(localized:)`
    /// call in the body is blanked out — which takes its `defaultValue:` and `comment:` literals with
    /// it — ANY string literal left standing is a violation. Measured over the tree the day it was
    /// written, that produced exactly the two known-and-argued skips and no false positive at all,
    /// so a narrower "is this literal in return position" rule would have bought precision nobody
    /// needed and cost the ability to see a literal spliced in through a `let` or a ternary.
    ///
    /// Empty and whitespace-only literals are ignored: `""` is a sentinel, not a sentence.
    @Test func localizedErrorCopyIsNeverABareLiteral() throws {
        let (literals, filesScanned) = try Self.scanForBareLocalizedErrorLiterals()

        #expect(
            filesScanned >= Self.minimumLocalizedErrorFilesScanned,
            """
            Scanned only \(filesScanned) Swift files under \(Self.localizedErrorScanRoots.joined(separator: ", ")) \
            (floor \(Self.minimumLocalizedErrorFilesScanned)) — a root moved or the enumerator broke, \
            and this wall is now passing without looking at anything.
            """
        )

        let offenders = literals.filter { literal in
            !Self.localizedErrorExceptions.contains { Self.matches($0, literal) }
        }
        #expect(
            offenders.isEmpty,
            """
            \(offenders.count) `LocalizedError` sentence(s) are plain string literals. Nothing \
            harvests them, so they are not in any catalog for a translator to see and they render \
            English in every language — through Shortcuts, the share sheet and system alerts, where \
            nobody on the team will ever notice. Wrap each in `String(localized:defaultValue:comment:)` \
            with a dotted-namespace key (`<domain>.error.<case>`), adding `bundle: .module` if and \
            only if the file is package source:
            \(offenders.map(\.report).sorted().joined(separator: "\n"))
            """
        )

        let unused = Self.localizedErrorExceptions.filter { entry in
            !literals.contains { Self.matches(entry, $0) }
        }
        #expect(
            unused.isEmpty,
            """
            \(unused.count) allowlisted bare `LocalizedError` literal(s) match nothing any more. \
            Delete them — a stale entry is a hole nobody is watching:
            \(unused.map { "\($0.path): \($0.literal)" }.sorted().joined(separator: "\n"))
            """
        )
    }

    /// Exact path AND exact literal — never a path-only match, so an entry cannot turn its file into
    /// an exempt file.
    static func matches(_ entry: LocalizedErrorException, _ literal: LocalizedErrorLiteral) -> Bool {
        literal.path == entry.path && literal.literal == entry.literal
    }

    /// Fixture: the body rule fires on each shape that must fail and stays silent on each shape that
    /// must pass.
    ///
    /// Part G is expected to report zero forever once the sweep lands, so — as everywhere else in
    /// this file — only a planted violation distinguishes "nothing is wrong" from "the matcher never
    /// runs". Both directions are planted, because a matcher that fires on everything is as useless
    /// as one that fires on nothing.
    @Test func localizedErrorBodyScannerSeesTheLiteralForms() {
        // MUST TRIP — the shapes the sweep found in the tree.
        #expect(Self.bareLocalizedErrorLiterals(in: """
            var errorDescription: String? {
                "Could not read that label."
            }
            """).count == 1, "a single implicit return is the commonest shape")
        #expect(Self.bareLocalizedErrorLiterals(in: """
            public var errorDescription: String? {
                switch self {
                case .a: "First."
                case .b: return "Second."
                }
            }
            """).count == 2, "implicit and explicit returns are the same defect")
        #expect(Self.bareLocalizedErrorLiterals(in: """
            var failureReason: String? { "Why it failed." }
            """).count == 1, "failureReason is display copy too")
        #expect(Self.bareLocalizedErrorLiterals(in: """
            var recoverySuggestion: String? { "Try again." }
            """).count == 1, "so is recoverySuggestion")
        #expect(Self.bareLocalizedErrorLiterals(in: """
            var errorDescription: String? {
                let prefix = "Keychain "
                return prefix + operation
            }
            """).count == 1, "a literal laundered through a `let` is still uncatalogued copy")
        #expect(Self.bareLocalizedErrorLiterals(in: """
            var errorDescription: String? = "Stored, not computed."
            """).count == 1, "a stored property satisfies the protocol just as well")
        #expect(Self.bareLocalizedErrorLiterals(in: """
            var errorDescription: String? {
                String(localized: "k", defaultValue: "Fine.", comment: "c") + " and \\("x")"
            }
            """).count == 1, "one localized call does not launder a second bare literal beside it")

        // MUST NOT TRIP — the corrected forms and the near misses.
        #expect(Self.bareLocalizedErrorLiterals(in: """
            var errorDescription: String? {
                String(localized: "camera.error.unavailable",
                       defaultValue: "Camera access is unavailable.",
                       comment: "Shown when the camera cannot be opened.")
            }
            """).isEmpty, "the whole point: defaultValue and comment are INSIDE the call")
        #expect(Self.bareLocalizedErrorLiterals(in: """
            public var errorDescription: String? {
                String(localized: "lock.error.locked",
                       defaultValue: "App lock is locked.",
                       bundle: .module,
                       comment: "Shown when the lock is closed.")
            }
            """).isEmpty, "package form, with the module bundle")
        #expect(Self.bareLocalizedErrorLiterals(in: """
            var errorDescription: String? {
                switch self {
                case .invalidCredential(let message): message
                }
            }
            """).isEmpty, "a pass-through of an already-finished sentence holds no literal")
        #expect(Self.bareLocalizedErrorLiterals(in: """
            var errorDescription: String? { nil }
            """).isEmpty, "no literal, no finding")
        #expect(Self.bareLocalizedErrorLiterals(in: """
            var errorDescription: String? {
                // A note mentioning "a quoted phrase" is documentation.
                String(localized: "k", defaultValue: "Fine.", comment: "c")
            }
            """).isEmpty, "comments are not code — the lesson part A learned the hard way")
        #expect(Self.bareLocalizedErrorLiterals(in: """
            var errorDescription: String? { "" }
            """).isEmpty, "an empty literal is a sentinel, not a sentence")

        // A READ or an ARGUMENT LABEL is not a declaration — without this discriminator the rule
        // fires on every `catch` block in the app that unwraps someone else's errorDescription.
        #expect(Self.bareLocalizedErrorLiterals(in: """
            notice = (error as? LocalizedError)?.errorDescription ?? "Could not import that."
            """).isEmpty, "a leading dot means a read, not a declaration")
        #expect(Self.bareLocalizedErrorLiterals(in: """
            queue.noteFailure(record, errorDescription: "Could not import that.")
            """).isEmpty, "an argument label is not a member declaration")
        #expect(Self.bareLocalizedErrorLiterals(in: """
            init(errorDescription: String? = "Default.") { }
            """).isEmpty, "nor is an initializer parameter")
        #expect(Self.bareLocalizedErrorLiterals(in: """
            /// var errorDescription: String? { "the defect" }
            """).isEmpty, "documentation naming the pattern is documentation")

        // A neighbouring member's body must not be swallowed into this one.
        #expect(Self.bareLocalizedErrorLiterals(in: """
            var errorDescription: String? {
                String(localized: "k", defaultValue: "Fine.", comment: "c")
            }
            var debugSummary: String {
                "Not display copy."
            }
            """).isEmpty, "the scan resumes AFTER the body, and debugSummary is not one of the three")
    }

    /// Fixture: `#if DEBUG` copy is skipped, and only the branch that actually is debug-only.
    ///
    /// The carve-out is structural rather than an allowlist entry because it is mechanically true —
    /// a sentence excluded from the shipping binary cannot be read in the wrong language — and
    /// because the evasion it appears to open is self-defeating: wrapping real copy in `#if DEBUG`
    /// removes it from the app along with the finding.
    @Test func debugOnlyErrorCopyIsSkippedButItsReleaseBranchIsNot() {
        #expect(Self.bareLocalizedErrorLiterals(in: """
            #if DEBUG
            var errorDescription: String? { "A probe diagnostic." }
            #endif
            """).isEmpty, "DEBUG-only copy never reaches a person")
        #expect(Self.bareLocalizedErrorLiterals(in: """
            #if DEBUG
            var errorDescription: String? { "A probe diagnostic." }
            #else
            var errorDescription: String? { "Shipping copy." }
            #endif
            """).count == 1, "the #else of an #if DEBUG is the RELEASE branch and must still be checked")
        #expect(Self.bareLocalizedErrorLiterals(in: """
            #if !DEBUG
            var errorDescription: String? { "Shipping copy." }
            #else
            var errorDescription: String? { "A probe diagnostic." }
            #endif
            """).count == 1, "and the sense inverts with the condition")
        #expect(Self.bareLocalizedErrorLiterals(in: """
            #if canImport(UIKit)
            var errorDescription: String? { "Shipping copy." }
            #else
            var errorDescription: String? { "Also shipping copy." }
            #endif
            """).count == 2, "an unrelated condition exempts neither branch")
        #expect(Self.bareLocalizedErrorLiterals(in: """
            #if DEBUG
            let probe = 1
            #endif
            var errorDescription: String? { "Shipping copy." }
            """).count == 1, "#endif closes the region — code after it is shipping code again")
    }

    /// Every bare display literal inside a `LocalizedError` copy member in `source`, by line.
    ///
    /// Pure + testable, and line-oriented at the top so a member's body can be found without a
    /// parser: a declaration line, then a brace-balanced (or `=`-terminated) span, then a character
    /// walk over that span that blanks comments and whole `String(localized:)` calls.
    static func bareLocalizedErrorLiterals(in source: String) -> [(line: Int, literal: String)] {
        let chars = Array(source)
        let lines = source.components(separatedBy: "\n")
        let debugOnly = debugOnlyLineFlags(in: source)
        let starts = lineStartOffsets(in: chars, lineCount: lines.count)
        var found: [(line: Int, literal: String)] = []
        var index = 0
        while index < lines.count {
            guard !debugOnly[index], declaresLocalizedErrorCopy(lines[index]),
                  let span = localizedErrorValueSpan(chars, lineStart: starts[index]) else {
                index += 1
                continue
            }
            found += bareLiterals(chars, from: span.start, to: span.end, startLine: index + 1)
            // Resume AFTER the body, so a member declared inside it is not scanned twice and the
            // next member's own declaration line is still reached.
            while index + 1 < starts.count, starts[index + 1] < span.end { index += 1 }
            index += 1
        }
        return found
    }

    /// Character offset where each 0-based line begins.
    static func lineStartOffsets(in chars: [Character], lineCount: Int) -> [Int] {
        var starts = [0]
        starts.reserveCapacity(lineCount)
        for (offset, character) in chars.enumerated() where character == "\n" { starts.append(offset + 1) }
        while starts.count < lineCount { starts.append(chars.count) }
        return starts
    }

    /// True when a line DECLARES one of ``localizedErrorCopyMembers``.
    ///
    /// The discriminator is the preceding keyword, and it is what separates the ~14 declarations in
    /// the tree from the far more numerous reads (`(error as? LocalizedError)?.errorDescription`),
    /// argument labels (`noteFailure(record, errorDescription:)`) and initializer parameters. A
    /// leading `.` is excluded by ``isIdentifierCharacter(_:)`` counting it as part of an identifier.
    static func declaresLocalizedErrorCopy(_ line: String) -> Bool {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard !trimmed.hasPrefix("//"), !trimmed.hasPrefix("*") else { return false }
        let chars = Array(trimmed)
        var index = 0
        while index < chars.count {
            guard chars[index].isLetter || chars[index] == "_" else { index += 1; continue }
            if index > 0, isIdentifierCharacter(chars[index - 1]) { index += 1; continue }
            var cursor = index
            while cursor < chars.count, chars[cursor].isLetter || chars[cursor].isNumber || chars[cursor] == "_" {
                cursor += 1
            }
            if localizedErrorCopyMembers.contains(String(chars[index..<cursor])),
               declarationKeywordPrecedes(chars, before: index) {
                return true
            }
            index = max(cursor, index + 1)
        }
        return false
    }

    /// True when the identifier starting at `index` is introduced by `var` or `func`.
    static func declarationKeywordPrecedes(_ chars: [Character], before index: Int) -> Bool {
        var cursor = index - 1
        while cursor >= 0, chars[cursor] == " " { cursor -= 1 }
        let end = cursor + 1
        while cursor >= 0, chars[cursor].isLetter { cursor -= 1 }
        let word = String(chars[(cursor + 1)..<max(end, cursor + 1)])
        return word == "var" || word == "func"
    }

    /// The span of a copy member's VALUE: a brace-balanced body, or the rest of the statement after
    /// an `=`.
    ///
    /// Both shapes conform to `LocalizedError`, so both are checked. `nil` when the declaration line
    /// carries neither — a protocol requirement written `{ get }` has a body and simply holds no
    /// literal, which the walk below reports as the zero findings it is.
    static func localizedErrorValueSpan(_ chars: [Character], lineStart: Int) -> (start: Int, end: Int)? {
        var index = lineStart
        while index < chars.count, chars[index] != "\n" {
            if let skip = skipNonCode(chars, from: index), skip > index {
                index = max(skip, index + 1)
                continue
            }
            if chars[index] == "{" { return (index, endOfBody(chars, openBrace: index)) }
            if chars[index] == "=" { return (index, endOfStatement(chars, from: index)) }
            index += 1
        }
        return nil
    }

    /// Index just past the `}` matching `openBrace`, skipping comments and string literals so a brace
    /// inside a sentence cannot end the body early.
    static func endOfBody(_ chars: [Character], openBrace: Int) -> Int {
        var depth = 0
        var index = openBrace
        while index < chars.count {
            if let skip = skipNonCode(chars, from: index), skip > index {
                index = max(skip, index + 1)
                continue
            }
            if chars[index] == "{" { depth += 1 }
            if chars[index] == "}" {
                depth -= 1
                if depth <= 0 { return index + 1 }
            }
            index += 1
        }
        return chars.count
    }

    /// Index of the end of the statement starting at `index` — the next newline outside any literal,
    /// comment or bracket. The stored-property (`= "…"`) counterpart of ``endOfBody(_:openBrace:)``.
    static func endOfStatement(_ chars: [Character], from index: Int) -> Int {
        var depth = 0
        var cursor = index
        while cursor < chars.count {
            if let skip = skipNonCode(chars, from: cursor), skip > cursor {
                cursor = max(skip, cursor + 1)
                continue
            }
            if chars[cursor] == "(" || chars[cursor] == "[" { depth += 1 }
            if chars[cursor] == ")" || chars[cursor] == "]" { depth -= 1 }
            if chars[cursor] == "\n", depth <= 0 { return cursor }
            cursor += 1
        }
        return chars.count
    }

    /// The string literals in `from..<to` that are neither inside a comment nor inside a
    /// `String(localized:)` call — which is exactly the set that reaches no catalog.
    static func bareLiterals(
        _ chars: [Character], from: Int, to: Int, startLine: Int
    ) -> [(line: Int, literal: String)] {
        var found: [(line: Int, literal: String)] = []
        var index = from
        var line = startLine
        let end = min(to, chars.count)
        while index < end {
            if chars[index] == "\n" { line += 1; index += 1; continue }
            if chars[index] == "/", let skip = skipNonCode(chars, from: index), skip > index {
                line += countNewlines(chars, from: index, to: skip)
                index = max(skip, index + 1)
                continue
            }
            // A localized call swallows its own `defaultValue:` and `comment:` literals, which is
            // the whole discriminator: those two ARE the catalogued form.
            if chars[index] == "S", let openParen = localizedCallHead(chars, at: index) {
                let callEnd = endOfCall(chars, openParen: openParen)
                line += countNewlines(chars, from: index, to: callEnd)
                index = max(callEnd, index + 1)
                continue
            }
            guard chars[index] == "\"" else { index += 1; continue }
            let literal = readStringLiteral(chars, from: index)
            if !literal.text.trimmingCharacters(in: .whitespaces).isEmpty {
                found.append((line, literal.text))
            }
            line += countNewlines(chars, from: index, to: literal.end)
            index = max(literal.end, index + 1)
        }
        return found
    }

    /// Whether each 0-based line sits inside a branch that only compiles in DEBUG.
    ///
    /// Tracks `#if` / `#elseif` / `#else` / `#endif` as a stack of frames, so a nested directive
    /// cannot clear an enclosing DEBUG region. `#else` inverts only when the frame's own condition
    /// was about DEBUG: the `#else` of `#if DEBUG` is the release branch, the `#else` of
    /// `#if !DEBUG` is the debug branch, and the `#else` of `#if canImport(UIKit)` is neither.
    static func debugOnlyLineFlags(in source: String) -> [Bool] {
        var flags: [Bool] = []
        var stack: [(isDebugBranch: Bool, isAboutDebug: Bool)] = []
        for raw in source.components(separatedBy: "\n") {
            let trimmed = raw.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("#if") {
                let condition = String(trimmed.dropFirst(3)).trimmingCharacters(in: .whitespaces)
                stack.append((condition == "DEBUG", condition == "DEBUG" || condition == "!DEBUG"))
            } else if trimmed.hasPrefix("#elseif"), !stack.isEmpty {
                let condition = String(trimmed.dropFirst(7)).trimmingCharacters(in: .whitespaces)
                stack[stack.count - 1] = (condition == "DEBUG", condition == "DEBUG" || condition == "!DEBUG")
            } else if trimmed == "#else", !stack.isEmpty {
                let frame = stack[stack.count - 1]
                stack[stack.count - 1] = (frame.isAboutDebug && !frame.isDebugBranch, frame.isAboutDebug)
            } else if trimmed.hasPrefix("#endif"), !stack.isEmpty {
                stack.removeLast()
            }
            flags.append(stack.contains { $0.isDebugBranch })
        }
        return flags
    }

    /// Scans this module's sources for bare literals in `LocalizedError` copy members.
    static func scanForBareLocalizedErrorLiterals() throws -> (
        literals: [LocalizedErrorLiteral], filesScanned: Int
    ) {
        var literals: [LocalizedErrorLiteral] = []
        var filesScanned = 0
        // R2: bounded by the module's file list.
        for file in try moduleSources() {
            filesScanned += 1
            for found in bareLocalizedErrorLiterals(in: file.text) {
                literals.append(LocalizedErrorLiteral(
                    path: file.path, line: found.line, literal: found.literal
                ))
            }
        }
        return (literals, filesScanned)
    }

    // MARK: - H. UIKit display copy: the assignment shape

    /// Roots scanned by part H1: this module's sources. The Fernlet repository's original reads its
    /// app's shipping source too, as F and G do. This module names UIKit in one seam file only (the
    /// platform wall's row), so that file is where an assignment could stand.
    static let uikitAssignmentScanRoots = [packageSourceRoot]

    /// Floor for the part-H1 scan: the package walker's own floor.
    static let minimumUIKitAssignmentFilesScanned = minimumPackageFilesScanned

    /// UIKit properties whose value a person reads or hears.
    ///
    /// Deliberately NOT `title`: `UIButton.Configuration.title`, `UINavigationItem.title` and
    /// `MSMessage`'s own layout all use it, but so does every value type in the tree with a `title`
    /// field — a recipe, a workout card, a catalog entry — and those are data, not display copy set
    /// on a view. Including it made the rule report the model layer. The button titles this round
    /// fixed reach their `Configuration` through a function argument, which H1 could not see either
    /// way; H2 is what actually caught them.
    static let uikitDisplayProperties = [
        "text", "attributedText", "placeholder", "summaryText",
        "caption", "subcaption", "trailingCaption",
        "accessibilityLabel", "accessibilityValue", "accessibilityHint",
    ]

    /// A UIKit display or accessibility property assigned a bare literal.
    struct UIKitDisplayAssignment: Hashable, Sendable {
        /// Repo-relative path.
        let path: String
        /// 1-based line of the assignment.
        let line: Int
        /// The property assigned, e.g. `accessibilityHint`.
        let property: String
        /// The literal's text, with any interpolation collapsed to `{}`.
        let literal: String

        /// `path:line: <property> = "<literal>"` — pasteable straight into a search.
        var report: String { "\(path):\(line): \(property) = \"\(literal)\"" }
    }

    /// A UIKit display property set to a bare literal never reaches a catalog.
    ///
    /// This is the shape rule F cannot see. F is a TYPE check over `var` / `func` DECLARATIONS —
    /// `var accessibilityHint: String` — and it is the right rule for SwiftUI, where copy is
    /// declared before it is handed to a modifier. UIKit declares nothing: it ASSIGNS, on an object
    /// it does not own, to a property whose type is fixed by the framework at `String?`. There is no
    /// declaration to check and no `Text` to declare instead, so F's signal cannot fire and F's
    /// remedy is not available. `String(localized:)` is the only form that reaches a catalog here,
    /// exactly as in rule G, so — exactly as in rule G — the check is whether it is there.
    ///
    /// Measured over both roots the day it was written, this found 12 assignments, all in
    /// `FernletMessagesViewController`, and no false positive.
    ///
    /// LIMIT, and it is the load-bearing one: 12 was a small fraction of that file's real surface of
    /// 57. The rest reached the screen as function arguments, `UIButton.Configuration` titles,
    /// initializer arguments and helper returns — the "INDIRECTION THROUGH A TYPE" ceiling this file
    /// documents, which no assignment-shaped rule can close. H1 generalizes to any UIKit file added
    /// later; ``everyMessagesExtensionLiteralIsCataloguedOrAnArguedToken()`` is what actually holds
    /// today's one UIKit target shut. Neither substitutes for the other.
    ///
    /// Literals with no letters are ignored: `""` is a sentinel and `" · "` is punctuation. That is
    /// what lets the fixed code join plural-ruled counts with a separator instead of keying it.
    @Test func uikitDisplayCopyIsNeverABareLiteral() throws {
        let (assignments, filesScanned) = try Self.scanForBareUIKitDisplayAssignments()

        #expect(
            filesScanned >= Self.minimumUIKitAssignmentFilesScanned,
            """
            Scanned only \(filesScanned) Swift files under \(Self.uikitAssignmentScanRoots.joined(separator: ", ")) \
            (floor \(Self.minimumUIKitAssignmentFilesScanned)) — a root moved or the enumerator broke, \
            and this wall is now passing without looking at anything.
            """
        )

        #expect(
            assignments.isEmpty,
            """
            \(assignments.count) UIKit display/accessibility propert(ies) are assigned a bare string \
            literal. Nothing harvests them, so they are in no catalog for a translator to see and \
            they render English in every language. Wrap each in \
            `String(localized:defaultValue:comment:)` with a dotted-namespace key, or — if the \
            target already has a copy vault, as `FernletMessagesExtension` does — add a member there \
            and assign that. App-target source takes NO `bundle:` argument; package source takes \
            `bundle: .module`:
            \(assignments.map(\.report).sorted().joined(separator: "\n"))
            """
        )
    }

    /// Fixture: the assignment rule fires on each shape that must fail and stays silent on each
    /// shape that must pass.
    ///
    /// Both directions are planted, because H1 is expected to report zero forever from the day it
    /// lands — and a matcher nobody has proven is indistinguishable from one that never fires.
    @Test func uikitAssignmentScannerSeesTheDisplayShapes() {
        // MUST TRIP — the shapes measured in FernletMessagesViewController before the fix.
        #expect(Self.bareUIKitDisplayAssignments(in: #"        statusLabel.text = "Fernlet couldn't prepare this item.""#).count == 1,
                "the plain label assignment is the commonest shape")
        #expect(Self.bareUIKitDisplayAssignments(in: #"        browseButton.accessibilityHint = "Shows the catalog.""#).count == 1,
                "an accessibility hint is display copy too")
        #expect(Self.bareUIKitDisplayAssignments(in: #"        message.summaryText = "Fernlet: \(title)""#).count == 1,
                "interpolation does not make a literal catalogued")
        #expect(Self.bareUIKitDisplayAssignments(in: #"        layout.trailingCaption = "Fernlet recipe""#).count == 1,
                "the Messages card captions are display copy")
        #expect(Self.bareUIKitDisplayAssignments(in: #"        label.text = value ?? "Open Fernlet.""#).count == 1,
                "a literal reached through `??` is still the fallback a person reads")
        #expect(Self.bareUIKitDisplayAssignments(in: """
                    searchBar.placeholder = isRecipes
                        ? "Search recipes"
                        : "Search plans"
            """).count == 2, "a ternary wrapped onto its own lines hides two literals, not zero")
        #expect(Self.bareUIKitDisplayAssignments(in: #"        label.accessibilityValue = on ? "Selected" : """#).count == 1,
                "the empty arm is a sentinel; only the spoken arm counts")

        // MUST NOT TRIP.
        #expect(Self.bareUIKitDisplayAssignments(in: """
                label.text = String(localized: "messages.brand", defaultValue: "⌁  FERNLET",
                                    comment: "Wordmark above the composer title.")
            """).isEmpty, "a localized call is the catalogued form — its own literals must not count")
        #expect(Self.bareUIKitDisplayAssignments(in: #"        label.text = FernletMessagesCopy.brand"#).isEmpty,
                "a copy-vault member is already keyed")
        #expect(Self.bareUIKitDisplayAssignments(in: #"        searchBar.text = """#).isEmpty,
                "clearing a field is not copy")
        #expect(Self.bareUIKitDisplayAssignments(in: #"        label.text = [a, b].joined(separator: " · ")"#).isEmpty,
                "a separator carries no letters, so it is punctuation, not a sentence")
        #expect(Self.bareUIKitDisplayAssignments(in: #"        if entry.text == "done" { return }"#).isEmpty,
                "a comparison is not an assignment")
        #expect(Self.bareUIKitDisplayAssignments(in: #"        card.title = "Weeknight pasta""#).isEmpty,
                "`title` is excluded on purpose — it is a model field far more often than a view's")
        #expect(Self.bareUIKitDisplayAssignments(in: #"        // label.text = "an old note about the label""#).isEmpty,
                "a commented-out assignment ships nothing")
        #expect(Self.bareUIKitDisplayAssignments(in: #"        label.text = url ?? "see https://fernlet.com for help""#).count == 1,
                "the `//` inside a URL literal is not a comment — truncating there would hide the sentence")
        #expect(Self.bareUIKitDisplayAssignments(in: """
            #if DEBUG
                    label.text = "seeded"
            #endif
            """).isEmpty, "copy that is not in the shipping binary cannot be read in the wrong language")
    }

    /// Scans this module's sources for UIKit display properties assigned a bare literal.
    static func scanForBareUIKitDisplayAssignments() throws -> (
        assignments: [UIKitDisplayAssignment], filesScanned: Int
    ) {
        var assignments: [UIKitDisplayAssignment] = []
        var filesScanned = 0
        // R2: bounded by the module's file list.
        for file in try moduleSources() {
            filesScanned += 1
            for found in bareUIKitDisplayAssignments(in: file.text) {
                assignments.append(UIKitDisplayAssignment(
                    path: file.path, line: found.line, property: found.property, literal: found.literal
                ))
            }
        }
        return (assignments, filesScanned)
    }

    /// Every UIKit display/accessibility property in `source` assigned a bare literal.
    ///
    /// Line-oriented at the top, then a character walk over the assignment's VALUE span — the same
    /// two-stage shape as ``bareLocalizedErrorLiterals(in:)``, and for the same reason: the value is
    /// where the literal is, and reading only the value keeps a comparison (`==`) and a
    /// same-named model field out of the results.
    static func bareUIKitDisplayAssignments(in source: String) -> [(line: Int, property: String, literal: String)] {
        let chars = Array(source)
        let lines = source.components(separatedBy: "\n")
        let debugOnly = debugOnlyLineFlags(in: source)
        let starts = lineStartOffsets(in: chars, lineCount: lines.count)
        var found: [(line: Int, property: String, literal: String)] = []
        for index in lines.indices {
            guard !debugOnly[index],
                  let hit = uikitDisplayAssignment(in: codeOnlyPrefix(of: lines[index])) else { continue }
            let span = uikitAssignmentValueSpan(
                chars: chars, lines: lines, starts: starts, from: index, equalsColumn: hit.equalsColumn
            )
            for literal in bareLiterals(chars, from: span.start, to: span.end, startLine: index + 1)
            where literal.literal.contains(where: { $0.isLetter }) {
                found.append((literal.line, hit.property, literal.literal))
            }
        }
        return found
    }

    /// `line` up to its first comment, so a commented-out assignment is not read as live code.
    ///
    /// Not cosmetic: the value span starts just past the `=`, which for a `// label.text = "…"`
    /// line is already INSIDE the comment — so the span scan's own comment skipping has nothing
    /// left to skip and reports the literal. The planted near-miss fixture caught exactly this.
    /// `skipNonCode` does the walking, so a `//` inside a string literal (`"https://…"`) is not
    /// mistaken for a comment and a block comment is skipped whole.
    static func codeOnlyPrefix(of line: String) -> String {
        let chars = Array(line)
        var index = 0
        while index < chars.count {
            if chars[index] == "/", index + 1 < chars.count, chars[index + 1] == "/" {
                return String(chars[0..<index])
            }
            guard let skip = skipNonCode(chars, from: index) else { index += 1; continue }
            index = max(skip, index + 1)
        }
        return line
    }

    /// The display property assigned on `line`, and the column just past its `=`.
    ///
    /// Requires a `.` before the name (it is a property on something) and rejects `==`, `!=`, `>=`,
    /// `<=` and the compound assignments, so a comparison never reads as an assignment.
    static func uikitDisplayAssignment(in line: String) -> (property: String, equalsColumn: Int)? {
        let chars = Array(line)
        for property in uikitDisplayProperties {
            var index = 0
            while index < chars.count {
                guard matches(chars, at: index, property), index > 0, chars[index - 1] == "." else {
                    index += 1
                    continue
                }
                let after = skipWhitespace(chars, from: index + property.count)
                guard after < chars.count, chars[after] == "=",
                      after + 1 >= chars.count || chars[after + 1] != "=",
                      after == 0 || !"=!<>+-*/?".contains(chars[after - 1]) else {
                    index += 1
                    continue
                }
                return (property, after + 1)
            }
        }
        return nil
    }

    /// Character range of the value assigned on line `index`, absorbing continuation lines.
    ///
    /// A line is absorbed when brackets are still unbalanced (a wrapped call) OR when the next line
    /// opens with a ternary or coalescing operator (a wrapped ternary, whose brackets balance on
    /// every line and which `logicalLines` therefore cannot join). That second case is not
    /// hypothetical: it is how this round's own fixed code formats `searchBar.placeholder`, so a
    /// rule blind to it would certify the exact shape it was written to guard.
    static func uikitAssignmentValueSpan(
        chars: [Character], lines: [String], starts: [Int], from index: Int, equalsColumn: Int
    ) -> (start: Int, end: Int) {
        let start = min(starts[index] + equalsColumn, chars.count)
        var last = index
        var depth = delimiterBalance(String(Array(lines[index]).dropFirst(equalsColumn)))
        while last + 1 < lines.count, last - index < maximumDeclarationLines {
            let next = lines[last + 1].trimmingCharacters(in: .whitespaces)
            let continues = depth > 0 || next.hasPrefix("?") || next.hasPrefix(":") || next.hasPrefix("??")
            guard continues else { break }
            last += 1
            depth += delimiterBalance(lines[last])
        }
        let end = last + 1 < starts.count ? starts[last + 1] : chars.count
        return (start, end)
    }

    // MARK: - Pure matchers

    /// Every `String(localized:…)` / `AttributedString(localized:…)` call in `source`, with whether it
    /// passes a `bundle:` argument.
    ///
    /// Spans the WHOLE call — head through matching close paren — so an argument written on a later
    /// line is still seen, and skips string literals while balancing parens so a `)` inside a message
    /// cannot end the span early.
    ///
    /// COMMENTS ARE SKIPPED, and that is not a nicety. The first run of this scan over the tree
    /// reported six "violations", every one of them a doc comment WARNING future authors never to
    /// call `String(localized:)` at that seam (the canonical signature serializer, the mesh payload
    /// summary, the connection inspector). Hard-failing CI on correct, careful documentation is how a
    /// wall gets switched off — the same false-positive lesson S3BoundaryTests learned at identifier
    /// boundaries (F12). Pure + testable.
    static func localizedCalls(in source: String) -> [LocalizedCallSite] {
        let chars = Array(source)
        var sites: [LocalizedCallSite] = []
        var index = 0
        var line = 1
        while index < chars.count {
            if let skip = skipNonCode(chars, from: index) {
                line += countNewlines(chars, from: index, to: skip)
                index = max(skip, index + 1)
                continue
            }
            if chars[index] == "\n" { line += 1 }
            guard chars[index] == "S", let openParen = localizedCallHead(chars, at: index) else {
                index += 1
                continue
            }
            let end = endOfCall(chars, openParen: openParen)
            let text = String(chars[index..<min(end, chars.count)])
            sites.append(LocalizedCallSite(
                path: "", line: line, text: text,
                passesBundle: resolvesAgainstModuleBundle(code(chars, from: index, to: end))
            ))
            line += countNewlines(chars, from: index, to: end)
            index = max(end, index + 1)
        }
        return sites
    }

    /// When `index` opens a string literal, a `//` comment, or a `/* */` comment, the index just past
    /// it; otherwise nil. One place decides what "not code" means, so every scan agrees.
    static func skipNonCode(_ chars: [Character], from index: Int) -> Int? {
        guard index < chars.count else { return nil }
        if chars[index] == "\"" { return readStringLiteral(chars, from: index).end }
        guard chars[index] == "/", index + 1 < chars.count else { return nil }
        if chars[index + 1] == "/" {
            var cursor = index + 2
            while cursor < chars.count, chars[cursor] != "\n" { cursor += 1 }
            return cursor
        }
        guard chars[index + 1] == "*" else { return nil }
        var depth = 0
        var cursor = index
        while cursor + 1 < chars.count {
            if chars[cursor] == "/", chars[cursor + 1] == "*" { depth += 1; cursor += 2; continue }
            if chars[cursor] == "*", chars[cursor + 1] == "/" {
                depth -= 1
                cursor += 2
                if depth <= 0 { return cursor }
                continue
            }
            cursor += 1
        }
        return chars.count
    }

    /// The `from..<to` span with comments removed (string literals kept — `bundle:` never hides in
    /// one). Used to decide `passesBundle`, so a `// no bundle: here` note inside a multi-line call
    /// cannot fake the argument's presence.
    static func code(_ chars: [Character], from: Int, to: Int) -> String {
        var text = ""
        var index = from
        let end = min(to, chars.count)
        while index < end {
            guard chars[index] == "/" || chars[index] == "\"" else {
                text.append(chars[index])
                index += 1
                continue
            }
            guard let skip = skipNonCode(chars, from: index) else {
                text.append(chars[index])
                index += 1
                continue
            }
            if chars[index] == "\"" { text += String(chars[index..<min(skip, end)]) }
            index = max(skip, index + 1)
        }
        return text
    }

    /// Newlines in `from..<to` — the incremental line counter for the scan above.
    static func countNewlines(_ chars: [Character], from: Int, to: Int) -> Int {
        var count = 0
        var index = max(from, 0)
        let end = min(to, chars.count)
        while index < end {
            if chars[index] == "\n" { count += 1 }
            index += 1
        }
        return count
    }

    /// The index of the `(` when a `String(localized:` head starts at `index`, else nil.
    ///
    /// Whitespace and newlines are tolerated between `String`, `(`, and `localized:` so a call split
    /// across lines at the head still matches. Matching on the bare suffix `String` is deliberate: it
    /// also catches `AttributedString(localized:)`, which carries the identical `Bundle.main` default
    /// and the identical silent failure.
    static func localizedCallHead(_ chars: [Character], at index: Int) -> Int? {
        guard matches(chars, at: index, "String") else { return nil }
        var cursor = skipWhitespace(chars, from: index + 6)
        guard cursor < chars.count, chars[cursor] == "(" else { return nil }
        let openParen = cursor
        cursor = skipWhitespace(chars, from: cursor + 1)
        guard matches(chars, at: cursor, "localized:") else { return nil }
        return openParen
    }

    /// Index just past the `)` matching `openParen`, skipping string literals and comments so a paren
    /// inside a message argument — or inside a `// note` between arguments — cannot unbalance the count.
    static func endOfCall(_ chars: [Character], openParen: Int) -> Int {
        var depth = 0
        var index = openParen
        while index < chars.count {
            let character = chars[index]
            if let skip = skipNonCode(chars, from: index) {
                index = max(skip, index + 1)
                continue
            }
            if character == "(" { depth += 1 }
            if character == ")" {
                depth -= 1
                if depth <= 0 { return index + 1 }
            }
            index += 1
        }
        return chars.count
    }

    /// Reads the Swift string literal whose opening quote is at `openQuote`.
    ///
    /// Returns the literal's text with every `\(…)` interpolation collapsed to `{}`, and the index just
    /// past the closing quote. Escapes are consumed as a pair so an escaped quote never ends the
    /// literal, and interpolations are skipped wholesale so the quotes INSIDE one (`\(n == 1 ? "" : "s")`)
    /// do not either.
    ///
    /// LIMIT: an interpolation containing a nested literal that itself interpolates is not modelled.
    /// No such literal exists in the scanned files, and if one appeared the scan would over-read and
    /// the frozen-set comparison would fail LOUDLY — never silently pass.
    static func readStringLiteral(_ chars: [Character], from openQuote: Int) -> (text: String, end: Int) {
        var text = ""
        var index = openQuote + 1
        while index < chars.count {
            let character = chars[index]
            if character == "\\", index + 1 < chars.count {
                if chars[index + 1] == "(" {
                    text += "{}"
                    index = skipInterpolation(chars, from: index + 1)
                    continue
                }
                text.append(chars[index + 1])
                index += 2
                continue
            }
            if character == "\"" { return (text, index + 1) }
            text.append(character)
            index += 1
        }
        return (text, chars.count)
    }

    /// Index just past the `)` closing the interpolation whose `(` is at `openParen`.
    ///
    /// Tracks nested parens and skips nested string literals inline rather than recursing (Power of 10
    /// rule 1), which is why the nested-interpolation limit above exists.
    static func skipInterpolation(_ chars: [Character], from openParen: Int) -> Int {
        var depth = 0
        var insideString = false
        var index = openParen
        while index < chars.count {
            let character = chars[index]
            if insideString {
                if character == "\\" { index += 2; continue }
                if character == "\"" { insideString = false }
                index += 1
                continue
            }
            if character == "\"" { insideString = true; index += 1; continue }
            if character == "(" { depth += 1 }
            if character == ")" {
                depth -= 1
                if depth <= 0 { return index + 1 }
            }
            index += 1
        }
        return chars.count
    }

    /// True when a call's code text passes `bundle:` AND the value it passes is the MODULE bundle.
    ///
    /// `.module` and `Bundle.module` both count; `.main`, `Bundle.main` and anything else do not.
    /// The distinction is the entire point inside a package: `.main` resolves against the app's
    /// bundle, which never contains the module's catalog, so the string falls back to its English
    /// literal exactly as if no bundle had been passed. A wall that accepted any `bundle:` argument
    /// was checking that a keyword had been typed, not that the lookup was correct.
    static func resolvesAgainstModuleBundle(_ callText: String) -> Bool {
        guard let marker = callText.range(of: "bundle:") else { return false }
        let chars = Array(callText[marker.upperBound...])
        let end = endOfParameter(chars, from: 0)
        // `.whitespacesAndNewlines`, not `.whitespaces`: this runs over the RAW call text, and the
        // formatting these calls are actually written in puts the bundle argument on its own line.
        // `.whitespaces` leaves the trailing newline attached and every correct multi-line call
        // reads as a violation.
        let value = String(chars[0..<min(end, chars.count)]).trimmingCharacters(in: .whitespacesAndNewlines)
        return value == ".module" || value == "Bundle.module"
    }

    /// True when `token` appears verbatim at `index`.
    static func matches(_ chars: [Character], at index: Int, _ token: String) -> Bool {
        let expected = Array(token)
        guard index >= 0, index + expected.count <= chars.count else { return false }
        for offset in 0..<expected.count where chars[index + offset] != expected[offset] { return false }
        return true
    }

    /// Index of the first non-whitespace character at or after `index`.
    static func skipWhitespace(_ chars: [Character], from index: Int) -> Int {
        var cursor = index
        while cursor < chars.count, chars[cursor].isWhitespace { cursor += 1 }
        return cursor
    }

    // MARK: - Discovery

    /// Scans every `.swift` file of this module for `String(localized:)` call sites.
    ///
    /// Returns the sites (paths under the package root, for the failure report) and the number of files
    /// actually read, so the caller can enforce the floor rather than trusting a walk that may have
    /// silently returned nothing.
    static func scanPackageForLocalizedCalls() throws -> (sites: [LocalizedCallSite], filesScanned: Int) {
        var sites: [LocalizedCallSite] = []
        var filesScanned = 0
        // R2: bounded by the module's file list.
        for file in try moduleSources() {
            filesScanned += 1
            for site in localizedCalls(in: file.text) {
                sites.append(LocalizedCallSite(
                    path: file.path, line: site.line, text: site.text, passesBundle: site.passesBundle
                ))
            }
        }
        return (sites, filesScanned)
    }

    /// Every Swift file of this module, by its path under the package root (`Sources/ProximityKit/…`)
    /// and its text, read through the package's walker: the one root every rule here reads. The walker
    /// holds no floor; each cell holds its read to ``minimumPackageFilesScanned``.
    static func moduleSources() throws -> [(path: String, text: String)] {
        try PackageSwiftFiles.sources().map { (path: packageSourceRoot + "/" + $0.path, text: $0.text) }
    }
}
