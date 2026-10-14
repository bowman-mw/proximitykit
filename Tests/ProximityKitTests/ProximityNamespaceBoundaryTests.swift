// ProximityNamespaceBoundaryTests.swift
// ProximityKitTests
//
// The wall that keeps ProximityKit's split from eroding (Fernlet's plan for ProximityKit,
// Docs/Plan-FernletCoach-ProximityKit-2026-10-01.md in the Fernlet repository, §4 A0.2 to A0.5). It is
// one of ProximityKit's own package tests (since plan step A1.1.7) and travels with the package: it
// reads ProximityKit's sources and its manifest through `PackageRoot`, by paths relative to the package
// root (`Sources/ProximityKit`, `Package.swift`), so it reads the same files inside the Fernlet
// repository, where the package is the `FernletKit` folder, and at the root of ProximityKit's own
// repository, and it reads code through the package's own copy of the source walls' lexer
// (`TestSupport/SwiftSourceLexer.swift`). What it refuses is Fernlet's: the names, strings, labels and
// types of the app ProximityKit was carved out of, so that none comes back into the module wherever
// the module lives. ProximityKit reads every protocol label and radio value, the QR scheme, the
// identity's and the two mesh seal keys' keychain rows, the storage names, the log subsystem, the
// radios' presentation strings and the payload vocabulary off the namespace its host hands down
// (`ProximityNamespace`; Fernlet's is `.fernlet`, in FernletConnections), and shows a peer's name
// under the namespace's peer-name policy; it asks its host's trust store and per-connection session
// policy its trust questions, records its own audit type and reports its own inspector values; it
// takes the routed types its mesh carries, and the features that carry them, from its host; and
// Fernlet's social features, its mesh features among them, and its sealed-backup escrow live in
// Fernlet's own modules, FernletSocial and the app. The compiler does not keep it that way: a
// ProximityKit file that builds a namespace of its own, reaches for one of FernletCrypto's purposes
// again, spells a new Fernlet string, names one of Fernlet's domain types again, opens a `package`
// door or declares a feature type that left it compiles clean and passes every other test. So this
// suite reads ProximityKit's source and holds six lines, and its target's dependencies in the package
// manifest:
//
//   1. no namespace, namespace group or purpose is built in ProximityKit outside `Namespace/`;
//   2. `FernletCryptoPurpose` is named nowhere in ProximityKit code: every label it reads is its host
//      namespace's, and every feature label is its feature's module's;
//   3. a string literal in ProximityKit code that contains `fernlet` (any case) is only on an exact
//      per-file allowlist that names why it is still there and the plan step that removes it, which
//      is empty: no literal spells it (the DEBUG launch-environment keys ProximityKit reads are its
//      own, `PROXIMITYKIT_*`, since plan step A1.0, so their old `FERNLET_` spellings fail here);
//   4. Fernlet's domain vocabulary and records, FernletDomainModel's `PayloadType`,
//      `ProximityCapability`, `ProximityMode`, `ItemNameModeration`, `ProximityTrustedPeerRecord`,
//      `TrainerAuditEvent` and `ConnectionSessionLog`, are named in ProximityKit code only on an exact
//      per-file, per-type allowlist of the lines a named later step removes, which is empty: no line
//      names one (the coordinator's session mode is ProximityKit's own `ProximitySessionMode`);
//   5. `package` is declared in ProximityKit code only on an exact per-file list of the doors a named
//      later step reshapes or closes, each row with that step, which is empty: no line declares it
//      (the presence radio's doors closed at plan step A1.1, behind its public presence engine);
//   6. no type that left ProximityKit for FernletSocial or the app, or was renamed in it (96 names:
//      the heart dead-drop's, presence's, moderation's (the report relay's among them), closeness's
//      and friend state's types, the parked chat payload, the clothing shop's, the activity manager's
//      with its payloads and the two domain types its signing extends, the live-session chat's with
//      the content layer's first half, the session hearts' with the heart ledger, its proof, the ack,
//      the merged heart, the commit and the body, the session photos' with the wall's post and
//      preferences, the review batch and its answer, the routed photo body and the JSON sidecar, the
//      deleted support layout and camera's copy vault, the sealed-backup escrow's, the Live Activity
//      reaper and its attributes, the app's since plan step A0.6, the recipe-share manager, its
//      diagnostics ring and its wire types, FernletSocial's since plan step A0.7, the three public
//      values plan step A0.7 renamed, and the nine recipe-named types of the pair session's mechanism
//      plan step A1.0 renamed with pair names, so no compatibility alias brings a recipe name back) is
//      declared, extended or aliased in ProximityKit code again, and no renamed public member's old
//      name (`recipeShare`, the namespace's pair-session radio, `Radios.pair` since plan step A1.0) is
//      named in its code at all.
//
// And ProximityKit's target in its package's manifest (the package root's `Package.swift`:
// `FernletKit/Package.swift` in the Fernlet repository, the root's own in ProximityKit's) depends on
// nothing (plan step A1.0), so an edge it dropped cannot come back unseen: FernletCrypto's (its
// identity signs and verifies only under its own purposes, FernletSocial's feature labels and the
// app's duress and probe labels among them, each minted with its feature-signature mint),
// FernletDomainModel's (the session mode, its own), or FernletFoundation's or PrivateMediaStore's,
// which only Fernlet's features needed.
//
// Rules 3 to 5 are ratchets. A new use fails; a use that goes away fails too, until its row is
// lowered or deleted. So rule 3's, rule 4's and rule 5's lists are already empty, and a row added
// for a later step's debt lives exactly as long as that debt. Rule 2 lists nothing: any use fails.
// Rule 6 only grows: a feature that came back under its old name with no Fernlet string, no registry
// label and no domain type of its own would pass rules 2 to 4, so each step that moves features out
// adds the types it took, and a step that renames a type or a public member for its generic use
// adds the old name. Between them they hold nothing ProximityKit still takes from Fernlet rather
// than from its host: no row names a DEBUG launch-environment key, a domain type, a presentation
// string, a membership record kind, a routed-type token or a coach-channel format, and no rule lists
// a line of a feature that left (the heart dead-drop, presence, moderation's ban store and report relay,
// closeness, friend state, the parked chat payload, the mesh's capability list and vouch-list
// content, the clothing shop, activities, the live-session chat, the session hearts and heart
// ledger, the session photos and their review, the sealed-backup escrow, the Live Activity reaper
// and the recipe share), which rule 6 keeps out. Rule 5 holds the
// other direction, the doors ProximityKit would open to Fernlet's own modules, and it opens none:
// FernletSocial's presence manager drives the presence radio through the public presence engine,
// `ProximityPresenceSession` (plan step A1.1), whose radio, epoch posture and TXT vocabulary are
// internal, and the coordinator's per-connection send and manual commit, which the pair session's
// pairings and presence's heart connections go through, are public.

import Foundation
import Testing

// MARK: - The wall

/// ProximityKit builds no namespace of its own, names none of FernletCrypto's purposes, spells
/// `fernlet` only in the literals its allowlist names, names Fernlet's domain vocabulary and records
/// only on the lines its list names (none), declares `package` only on the doors its list names,
/// declares, extends or aliases none of the types that left it, and depends on exactly the targets
/// its list names (none).
@Suite struct ProximityNamespaceBoundaryTests {

    /// The module, from the package root (``PackageRoot``), in either repository.
    private static let moduleRoot = "Sources/ProximityKit"

    /// The one folder that may build a namespace, its groups and its purposes.
    private static let namespaceFolder = "Namespace/"

    // MARK: Rule 1: no namespace is built outside Namespace/

    /// No namespace, namespace group or purpose is built in ProximityKit code outside `Namespace/`.
    ///
    /// ProximityKit reads the namespace its host hands down and never makes one: a namespace built
    /// anywhere else would be a default nobody supplied, and a purpose minted anywhere else a label no
    /// namespace carries. Every way to build one is a pattern in ``constructionPatterns`` (the host's
    /// two mints, `featureKeyDerivationSalt(_:)` and `featureSignature(_:framing:)`, among them: a
    /// feature salt ProximityKit minted for itself would be a label no host declared, and a feature
    /// signature label one no host wrote), and so is the place the patterns cannot see: an
    /// extension of, or alias for, a namespace type outside the folder, where an unqualified
    /// initializer or `Self(` would build one by a name too short to search for. The scan reads code
    /// only (comments and literal text removed), so prose about these spellings is never a violation.
    /// Its floors fail an empty scan: it must read the module, find the folder, and find there the
    /// constructions the patterns exist to catch (`Namespace/` mints each of the 39 labels with
    /// `ProximityCryptographicPurpose(_:role:)`).
    @Test func noNamespaceGroupOrPurposeIsBuiltOutsideTheNamespaceFolder() throws {
        let patterns = try Self.constructionPatterns.map {
            (name: $0.name, regex: try NSRegularExpression(pattern: $0.pattern))
        }
        let sources = try Self.proximitySources()
        var violations: [String] = []
        var insideMatches: [String: Int] = [:]
        // R2: bounded by the module's file list and the pattern list.
        for source in sources {
            let inside = source.path.hasPrefix(Self.namespaceFolder)
            for pattern in patterns {
                let lines = Self.matchLines(of: pattern.regex, in: source.lexed.code)
                if inside {
                    insideMatches[pattern.name, default: 0] += lines.count
                } else {
                    violations += lines.map { "\(source.path):\($0): \(pattern.name)" }
                }
            }
        }
        #expect(sources.count >= 50, "the ProximityKit sweep read only \(sources.count) Swift files")
        #expect(sources.filter { $0.path.hasPrefix(Self.namespaceFolder) }.count >= 5,
                "the sweep did not find the five files of \(Self.moduleRoot)/\(Self.namespaceFolder)")
        #expect(insideMatches["ProximityCryptographicPurpose(", default: 0] >= 39 &&
                insideMatches["ProximityNamespace(", default: 0] >= 1, """
            the patterns no longer see Namespace/ mint its 39 labels and build its namespace \
            (\(insideMatches)): a blind pattern would pass every file outside it vacuously
            """)
        #expect(violations.isEmpty, """
            ProximityKit builds a namespace, a namespace group or a purpose outside \
            \(Self.namespaceFolder): \(violations). ProximityKit reads the namespace its host supplies \
            (a manager's stored copy, an identity's purposes, a scope's namespace, a verifier's own \
            copy) and never makes one; a new label belongs in Namespace/'s groups, with its value in \
            the host's namespace (Fernlet's: FernletConnections' `.fernlet`).
            """)
    }

    /// Rule 1's patterns, by name. A name matches ``matchLines(of:in:)``'s use of `pattern` against
    /// lexed code, where literals are empty and comments gone.
    ///
    /// - The type's own name called, with `.init` too: a group name counts unqualified or under
    ///   `ProximityNamespace.`, so another type's nested `Radio(` is not a match.
    /// - The group factories `accepted(identityEnvelopeV1:meshAdmissionTokenV1:)` (also as `.accepted(`)
    ///   and `validated(family:installation:)`.
    /// - An initializer's shorthand `.init(…)`, known by its first argument label.
    /// - The purpose initializer's shape however it is called: a literal then `role:`, or a shorthand
    ///   `.init(` with an unlabeled argument then `role:`. (Not any unlabeled argument then `role:`:
    ///   the transport's `refusalDetail(rejection, role: role, …)` is that shape too.)
    /// - The host's feature-salt mint, `featureKeyDerivationSalt(_:)`, and its feature-signature mint,
    ///   `featureSignature(_:framing:)`, however each is reached.
    /// - An extension of, or a typealias for, a namespace type.
    ///
    /// ``everyConstructionPatternSeesItsFormAndNoNeighbour()`` holds each pattern to a sample it must
    /// match and to the near neighbours in today's code it must not.
    private static let constructionPatterns: [(name: String, pattern: String)] = [
        ("ProximityNamespace(", #"(?<![A-Za-z0-9_.])ProximityNamespace\s*(?:\.\s*init\s*)?\("#),
        ("ProximityCryptographicPurpose(",
         #"(?<![A-Za-z0-9_.])ProximityCryptographicPurpose\s*(?:\.\s*init\s*)?\("#),
        ("a namespace group's initializer",
         #"(?<![A-Za-z0-9_.])(?:ProximityNamespace\s*\.\s*)?(?:Signature|KeyDerivation|AEAD|Hash|Radios|Radio|VerifyQR|Family|Purposes|FeaturePurposes|Installation|Keychain|Storage|PeerNames|Vocabulary|SessionMessages|SessionMessage|Heartbeat|PayloadRules|Capabilities|MembershipRecordKinds|RoutedTypes|MeshMessages)\s*(?:\.\s*init\s*)?\("#),
        ("a keychain row's initializer",
         #"(?<![A-Za-z0-9_.])(?:(?:ProximityNamespace\s*\.\s*)?Keychain\s*\.\s*Row|(?:(?:ProximityNamespace\s*\.\s*)?Keychain\s*\.\s*)?IdentityRows)\s*(?:\.\s*init\s*)?\("#),
        ("LegacyV1.accepted(", #"(?<![A-Za-z0-9_])accepted\s*\(\s*identityEnvelopeV1\s*:"#),
        ("ProximityNamespace.validated(", #"(?<![A-Za-z0-9_])validated\s*\(\s*family\s*:"#),
        ("a namespace initializer's shorthand .init(",
         #"\.\s*init\s*\(\s*(?:family|purposes|signature|identityEnvelopeV2|proximityTransportV1|proximityTransportV2|meshInventoryDigestV1|mesh|serviceType|urlScheme|keychain|identity|service|directoryName|maxLength|session|identityIntroduction|payloadType|known|admission|photo|descriptor)\s*:"#),
        ("the purpose initializer's shape",
         #"(?:\(\s*""|\.\s*init\s*\(\s*[^\s,():]+)\s*,\s*role\s*:"#),
        ("a feature purpose's mint", #"(?<![A-Za-z0-9_])featureKeyDerivationSalt\s*\("#),
        ("a feature signature's mint", #"(?<![A-Za-z0-9_])featureSignature\s*\("#),
        ("an extension of a namespace type",
         #"(?<![A-Za-z0-9_])extension\s+(?:ProximityNamespace|ProximityCryptographicPurpose)(?![A-Za-z0-9_])"#),
        ("a typealias for a namespace type",
         #"(?<![A-Za-z0-9_])typealias\s+\w+\s*=\s*(?:ProximityNamespace|ProximityCryptographicPurpose)(?![A-Za-z0-9_])"#)
    ]

    /// Rule 1's patterns, fixtured both ways, because the matcher is the wall: each sees its own
    /// construction forms (named, `.init`, shorthand, wrapped), and none sees the nearest code in
    /// today's tree that is not a construction — another type's nested `Radio(`, the transport's calls
    /// that pass a `role:`, a shorthand `.init(` of another type, a namespace field read, a hash, the
    /// session-message store, heartbeat payload and schedule and capability list whose names hold a
    /// vocabulary group's, the descriptor payload and a role's token lookup beside the mesh
    /// messages' first label and type, the peer-name coercion, the sanitizer and the name display
    /// beside the peer-name policy's type and first label, and the salt role's switch arm and
    /// argument, a comment naming the feature-salt mint, the pair-secret door's call and the feature
    /// group's read beside the feature group and its mint, and a comment naming the feature-signature
    /// mint, its framing type and a sign call beside that mint. Every sample is lexed first, as the
    /// module's files are.
    @Test func everyConstructionPatternSeesItsFormAndNoNeighbour() throws {
        let patterns = try Dictionary(uniqueKeysWithValues: Self.constructionPatterns.map {
            ($0.name, try NSRegularExpression(pattern: $0.pattern))
        })
        let samples: [(pattern: String, source: String)] = [
            ("ProximityNamespace(", "let n = ProximityNamespace(family: family, installation: installation)"),
            ("ProximityNamespace(", "let n = ProximityNamespace\n    .init(family: family, installation: installation)"),
            ("ProximityCryptographicPurpose(", #"let p = ProximityCryptographicPurpose("x.v1", role: .columnSeal)"#),
            ("a namespace group's initializer", "let r = ProximityNamespace.Radio(serviceType: s, alpn: a)"),
            ("a namespace group's initializer", #"Hash.init(meshInventoryDigestV1: "a", meshRoutedContentV1: "b")"#),
            ("a namespace group's initializer", "let beat = ProximityNamespace.Heartbeat(payloadType: t, pingTitle: p, replyTitle: r)"),
            ("a namespace group's initializer", "let kinds = MembershipRecordKinds.init(admission: a, departure: d)"),
            ("a namespace group's initializer", "let mesh = ProximityNamespace.MeshMessages(descriptor: d, admissionGrant: g)"),
            ("a namespace group's initializer", "let names = ProximityNamespace.PeerNames(maxLength: 24, floor: f)"),
            ("a keychain row's initializer", "let row = ProximityNamespace.Keychain.Row(service: s, account: a)"),
            ("a keychain row's initializer", "let rows = IdentityRows(service: s, signingPrivateKey: k)"),
            ("LegacyV1.accepted(", #"legacyV1: .accepted(identityEnvelopeV1: "a", meshAdmissionTokenV1: "b")"#),
            ("ProximityNamespace.validated(", "let n = try ProximityNamespace.validated(family: f, installation: i)"),
            ("a namespace initializer's shorthand .init(", "let r: ProximityNamespace.Radio = .init(serviceType: s, alpn: a)"),
            ("a namespace initializer's shorthand .init(",
             "let rules: ProximityNamespace.PayloadRules = .init(known: k, sealingRequired: s)"),
            ("a namespace initializer's shorthand .init(",
             "let mesh: ProximityNamespace.MeshMessages = .init(descriptor: d, admissionGrant: g)"),
            ("a namespace initializer's shorthand .init(",
             "let names: ProximityNamespace.PeerNames = .init(maxLength: 24, floor: f)"),
            ("the purpose initializer's shape", #"Self("x.v1", role: .aeadAssociatedData)"#),
            ("the purpose initializer's shape", "let p: ProximityCryptographicPurpose = .init(spelling, role: .columnSeal)"),
            ("a namespace group's initializer", #"let f = ProximityNamespace.FeaturePurposes(["pairV1": salt])"#),
            ("a feature purpose's mint", #"let p = ProximityCryptographicPurpose.featureKeyDerivationSalt("x.v1")"#),
            ("a feature purpose's mint", #"let p: ProximityCryptographicPurpose = .featureKeyDerivationSalt("x.v1")"#),
            ("a feature signature's mint",
             #"let p = ProximityCryptographicPurpose.featureSignature("x.v1", framing: .lengthPrefixed)"#),
            ("a feature signature's mint",
             #"let p: ProximityCryptographicPurpose = .featureSignature("x.v1", framing: .rawPrefix)"#),
            ("an extension of a namespace type", "nonisolated extension ProximityNamespace.Storage {"),
            ("a typealias for a namespace type", "typealias Labels = ProximityNamespace.Purposes")
        ]
        // R2: bounded by the sample list.
        for sample in samples {
            let regex = try #require(patterns[sample.pattern], "no pattern is named \(sample.pattern)")
            #expect(!Self.matchLines(of: regex, in: SwiftSourceLexer.lex(sample.source).code).isEmpty,
                    "\(sample.pattern) misses: \(sample.source)")
        }
        let neighbours = Self.constructionNeighbours
        // R2: bounded by the neighbour and pattern lists.
        for source in neighbours {
            let code = SwiftSourceLexer.lex(source).code
            let matched = patterns.filter { !Self.matchLines(of: $0.value, in: code).isEmpty }.map(\.key)
            #expect(matched.isEmpty, "\(matched) read a construction in: \(source)")
        }
    }

    /// Rule 1's neighbours: the nearest code in today's tree that is not a construction, which
    /// ``everyConstructionPatternSeesItsFormAndNoNeighbour()`` holds every pattern to missing (its
    /// doc names each). Each is lexed first, as the module's files are.
    private static let constructionNeighbours = [
        "let gate = ProximityPairDiscoveryGate.Radio(isRunning: true, isPaused: false)",
        "MeshTransportConsoleLog.echo(Self.refusalDetail(rejection, role: role, authority: authority))",
        "return try await settle(exchange, role: role, signed: signed, over: stream)",
        "tunnels[key] = Tunnel(peer: channel.peer, channel: channel, role: .initiator)",
        "entries.append(.init(activityID: id, versionHeld: version))",
        "let label = identity.purposes.signature.meshRoutedChunkV1",
        "let digest = SHA256.hash(data: bytes)",
        "case .signature(let framing), .hashDomain(let framing):",
        "public let sessionMessages = SessionMessageStore()",
        "private var heartbeats = MeshHeartbeatSchedule()",
        "let payload = SessionHeartbeatPayload(kind: .ack, heartbeatID: UUID(), sentAt: now, responseTo: heartbeatID)",
        "capabilities: localCapabilities(),",
        "await sendMeshDescriptor(to: slot); let payload = MeshStateChangePayload(descriptor: mesh)",
        "func token(in mesh: ProximityNamespace.MeshMessages) -> String { mesh.descriptor }",
        "let name = ProximityDisplayName.peerDisplayName(raw, in: namespace)",
        "let shown = ProximityDisplayName.sanitized(raw, maxLength: namespace.installation.peerNames.maxLength)",
        "let name = PeerNameDisplay.personName(raw, fingerprint: nil, in: namespace)",
        "case .keyDerivationSalt, .columnSeal, .aeadAssociatedData, .tlsExporterLabel:",
        "let salt = ProximityCryptographicPurpose.Role.keyDerivationSalt",
        "role: .keyDerivationSalt",
        "/// Mint a salt with featureKeyDerivationSalt(_:) and declare it in the feature group.",
        "let secret = try identity.pairSecret(with: peerKey, purpose: purpose)",
        "guard purpose.role == .keyDerivationSalt, let purpose = purposes.feature.declaredLabel(matching: purpose) else {",
        "/// Mint a host signature label with featureSignature(_:framing:) for a transcript of its own.",
        "let framing = ProximityCryptographicPurpose.FeatureSignatureFraming.lengthPrefixed",
        "let signature = try identity.sign(transcript, purpose: purpose)"
    ]

    // MARK: Rule 2: FernletCryptoPurpose nowhere

    /// `FernletCryptoPurpose` is named nowhere in ProximityKit code.
    ///
    /// Every protocol label ProximityKit reads is its host namespace's (`purposes.<group>.<label>`),
    /// and it reads no feature label: the moderation report's and the activities' three are FernletSocial's,
    /// signed and verified there beside the canonical bytes they cover, under host labels minted with
    /// `ProximityCryptographicPurpose.featureSignature(_:framing:)`. The module has had no door into
    /// FernletCrypto since plan step A1.0 (it depends on no FernletKit module, which
    /// ``proximityKitDependsOnExactlyItsListedTargets()`` holds), and this rule keeps the registry's
    /// name out of its code as well as its manifest.
    /// So any code line that names the registry fails, whatever it reads, and the message names its
    /// file, its lines and the purposes they read. Comments may name the registry; only code lines
    /// count.
    @Test func fernletCryptoPurposeIsNamedNowhereInProximityKit() throws {
        let mention = try NSRegularExpression(pattern: #"(?<![A-Za-z0-9_])FernletCryptoPurpose(?![A-Za-z0-9_])"#)
        let member = try NSRegularExpression(
            pattern: #"FernletCryptoPurpose\s*\.\s*([A-Za-z]+)\s*\.\s*([A-Za-z0-9]+)"#
        )
        let sources = try Self.proximitySources()
        var violations: [String] = []
        var linesRead = 0
        // R2: bounded by the module's file list.
        for source in sources {
            linesRead += source.lexed.code.count(where: { $0 == "\n" }) + 1
            let lines = Set(Self.matchLines(of: mention, in: source.lexed.code)).sorted()
            guard !lines.isEmpty else { continue }
            let purposes = Self.captures(of: member, in: source.lexed.code).sorted()
            violations.append("\(source.path) on code lines \(lines) reading \(purposes)")
        }
        #expect(sources.count >= 50, "the ProximityKit sweep read only \(sources.count) Swift files")
        #expect(linesRead >= 20_000, "the ProximityKit sweep read only \(linesRead) lines")
        #expect(violations.isEmpty, """
            ProximityKit names FernletCryptoPurpose: \(violations). A label ProximityKit reads is its \
            host's namespace's (`purposes.<group>.<label>`), and a feature's label is signed and \
            verified in the feature's own module, never read off FernletCrypto's registry here.
            """)
    }

    // MARK: Rule 3: every fernlet literal is allowlisted

    /// Every string literal in ProximityKit code that contains `fernlet` (any case) is in
    /// ``fernletLiterals``, file by file and count by count, and every row there is still in the code.
    ///
    /// Every Fernlet value ProximityKit's protocol reads is the host namespace's, and so are the
    /// presentation strings the radios and the name display read and the membership record kinds the
    /// inventory digest hashes; the routed types the mesh registers are the host's rows, and the
    /// formats of the features' payloads are their own modules', while the coach channel's
    /// trainer-export body is FernletConnections'; the recipe share's copy and format are
    /// FernletSocial's; and the DEBUG launch-environment keys the module reads are its own,
    /// `PROXIMITYKIT_*` (plan step A1.0). Nothing is left, so the list is empty and a new Fernlet
    /// string fails here on its first literal, with its file and lines: it belongs in the host's
    /// namespace, or in the feature's own module. The six keys' old `FERNLET_` spellings need no list
    /// of retired literals of their own: each spells `fernlet`, so this rule refuses it in any
    /// literal. The list stays exact both ways for a literal a later step must carry: a row whose
    /// literal is gone fails until it is deleted. The scan reads literals only: comments may say
    /// Fernlet freely.
    @Test func everyFernletLiteralIsAllowlistedWithItsReasonAndExitStep() throws {
        let sources = try Self.proximitySources()
        var found: [String: [String: [Int]]] = [:]
        var literalsLexed = 0
        // R2: bounded by the module's file list and each file's literal count.
        for source in sources {
            literalsLexed += source.lexed.literals.count
            for literal in source.lexed.literals where literal.text.lowercased().contains("fernlet") {
                found[source.path, default: [:]][literal.text, default: []].append(literal.line)
            }
        }
        #expect(sources.count >= 50, "the ProximityKit sweep read only \(sources.count) Swift files")
        #expect(literalsLexed >= 500, "the lexer found only \(literalsLexed) literals in ProximityKit")
        var allowed: [String: [String: Int]] = [:]
        // R2: bounded by the allowlist.
        for row in Self.fernletLiterals {
            #expect(allowed[row.file]?[row.text] == nil, "\(row.file) lists \"\(row.text)\" twice")
            allowed[row.file, default: [:]][row.text] = row.count
        }
        let files = Set(found.keys).union(allowed.keys).sorted()
        // R2: bounded by the union of two finite key sets.
        for file in files {
            let actual = (found[file] ?? [:]).mapValues(\.count)
            let expected = allowed[file] ?? [:]
            #expect(actual == expected, """
                \(file): the fernlet literals in code are \(Self.describe(found[file] ?? [:])), but the \
                allowlist says \(Self.describeRows(of: file)). A new Fernlet string belongs in the \
                host's namespace (ProximityNamespace, Fernlet's in FernletConnections) or in its \
                feature's own module, not spelled in ProximityKit; a literal that left needs its row \
                lowered or deleted here, so the list stays exact.
                """)
        }
    }

    /// One allowlisted literal.
    struct FernletLiteral: Sendable {
        /// The file, by path under the module root.
        let file: String
        /// The literal's text between its delimiters, exactly as written.
        let text: String
        /// How many times the file's code spells it.
        let count: Int
        /// Why it is still here, and the step that removes it.
        let reason: Reason

        init(_ file: String, _ text: String, _ count: Int, _ reason: Reason) {
            self.file = file
            self.text = text
            self.count = count
            self.reason = reason
        }
    }

    /// Every `fernlet` literal still in ProximityKit code, by file: none.
    static let fernletLiterals: [FernletLiteral] = []

    /// `found`'s literals with the lines each is on, sorted, for a failure message.
    private static func describe(_ found: [String: [Int]]) -> String {
        let listed = found.sorted { $0.key < $1.key }.map { "\"\($0.key)\" at \($0.value)" }
        return listed.isEmpty ? "none" : listed.joined(separator: ", ")
    }

    /// `file`'s allowlist rows with their counts and exit steps, for a failure message.
    private static func describeRows(of file: String) -> String {
        let rows = fernletLiterals.filter { $0.file == file }
            .map { "\"\($0.text)\" ×\($0.count) (until \(Self.exitText($0.reason.exit)))" }
        return rows.isEmpty ? "none" : rows.joined(separator: ", ")
    }

    // MARK: Rule 4: Fernlet's domain types only on the lines that leave

    /// Fernlet's domain vocabulary and records (``domainTypeNames``) are named in ProximityKit code
    /// only on the lines ``domainTypeLines`` lists, file by file and type by type, each row with the
    /// plan step it leaves at.
    ///
    /// ProximityKit's core takes none of them from Fernlet: it reads every payload and capability
    /// token off the namespace its host hands down, asks the host's trust store and per-connection
    /// session policy its trust questions, records its own session audit, reports its own inspector
    /// values and sanitizes a peer's name with its own copy of the sanitizer, under the namespace's
    /// peer-name policy; Fernlet's mesh features, which send its payload types, gate on its
    /// capabilities, cap names by its item-name rules and read its trusted-peer records, are
    /// FernletSocial's, over the engine's token doors, and the envelope's typed view of its token,
    /// which they read and sign through, is FernletConnections'; and the coordinator's session mode
    /// is this module's own `ProximitySessionMode`, which Fernlet converts to the `ProximityMode` it
    /// persists (plan step A1.0). Nothing is left, so the list is empty and a type no row names fails
    /// on its first line, with its file and lines. The list stays exact both ways for a line a later
    /// step must carry: a new line fails, and so does a type named in a file whose rows name only
    /// others; a line that goes away fails until its row is lowered or deleted, so the list only
    /// shrinks. Only code lines count: comments and literals may name the types, and an implicit
    /// member (`.friend`) names none; the parameter it is passed to is spelled through the
    /// coordinator's `Mode`, this module's own enum.
    @Test func fernletDomainTypesAreNamedOnlyOnTheLinesThatLeave() throws {
        let needles = try Self.domainTypeNeedles()
        let sources = try Self.proximitySources()
        var found: [String: [String: [Int]]] = [:]
        // R2: bounded by the module's file list.
        for source in sources {
            let mentions = Self.domainTypeMentions(in: source.lexed.code, matching: needles)
            if !mentions.isEmpty { found[source.path] = mentions }
        }
        #expect(sources.count >= 50, "the ProximityKit sweep read only \(sources.count) Swift files")
        var allowed: [String: [String: Int]] = [:]
        // R2: bounded by the allowlist.
        for row in Self.domainTypeLines {
            #expect(Self.domainTypeNames.contains(row.type), "\(row.file) lists \(row.type), no domain type")
            #expect(allowed[row.file]?[row.type] == nil, "\(row.file) lists \(row.type) twice")
            allowed[row.file, default: [:]][row.type] = row.lines
        }
        let files = Set(found.keys).union(allowed.keys).sorted()
        // R2: bounded by the union of two finite key sets.
        for file in files {
            let actual = (found[file] ?? [:]).mapValues(\.count)
            #expect(actual == (allowed[file] ?? [:]), """
                \(file): Fernlet's domain types are named on the code lines \(Self.describe(found[file] ?? [:])), \
                but the allowlist says \(Self.describeDomainRows(of: file)). ProximityKit's core takes \
                Fernlet's vocabulary from its host's namespace and asks its host's protocols for trust and \
                records, so a new line naming one of these types belongs in the host (FernletConnections) \
                or in its feature's own module; a line that left needs its row lowered or deleted here, so \
                the list stays exact.
                """)
        }
    }

    /// Rule 4's matcher, fixtured both ways, because the matcher is the wall: it sees each type in
    /// every form ProximityKit writes one (a parameter, an optional, a collection, a closure type, a
    /// member access, a module-qualified name, a nested type, an alias, an extension, a name on a
    /// line of its own), counts a line once per type however often it names it and once for each
    /// type it names, and sees none of today's nearest code that names no domain type: the
    /// envelope's raw token and a typed view's parked flag, the soundness rule's token fields, the
    /// mesh's roles, the namespace's payload rules and capabilities, the coordinator's own role,
    /// ranging mode and session mode with their aliases, the host's trust store and trusted-peer list,
    /// the session audit, the name coercion, the generic summary and encryption types, and a comment
    /// and a literal that spell the types. Every sample is lexed first, as the module's files are.
    @Test func theDomainTypeMatcherSeesEveryFormAndNoNeighbour() throws {
        let needles = try Self.domainTypeNeedles()
        let samples: [(source: String, expected: [String: [Int]])] = [
            ("public var payloadType: PayloadType? { PayloadType(rawValue: payloadTypeToken) }", ["PayloadType": [1]]),
            ("public func registerPayloadHandler(for type: PayloadType, handler: @escaping MeshPayloadHandler) {",
             ["PayloadType": [1]]),
            ("await sendFeatureEnvelope(FernletDomainModel.PayloadType.itemReport.rawValue, encodable: p, via: s)",
             ["PayloadType": [1]]),
            ("extension PayloadType: CustomStringConvertible {}", ["PayloadType": [1]]),
            ("capabilities.append(ProximityCapability.hearts.rawValue)", ["ProximityCapability": [1]]),
            ("public typealias Mode = ProximityMode", ["ProximityMode": [1]]),
            ("let cleanTitle = ItemNameModeration.sanitizedName(title)", ["ItemNameModeration": [1]]),
            ("@ObservationIgnored private let activeFriends: () -> [ProximityTrustedPeerRecord]",
             ["ProximityTrustedPeerRecord": [1]]),
            ("public var queueAwayHeart: ((ProximityTrustedPeerRecord) -> Bool)?", ["ProximityTrustedPeerRecord": [1]]),
            ("func recordTrainerAudit(_ event: TrainerAuditEvent) {", ["TrainerAuditEvent": [1]]),
            ("let record = ConnectionSessionLog.EnvelopeRecord(direction: .sent)", ["ConnectionSessionLog": [1]]),
            ("func gate(_ type: PayloadType, _ capability: ProximityCapability) -> ProximityMode",
             ["PayloadType": [1], "ProximityCapability": [1], "ProximityMode": [1]]),
            ("func send(\n    _ type:\n        PayloadType,\n    to friend: ProximityTrustedPeerRecord\n)",
             ["PayloadType": [3], "ProximityTrustedPeerRecord": [4]])
        ]
        // R2: bounded by the sample list.
        for sample in samples {
            let mentions = Self.domainTypeMentions(in: SwiftSourceLexer.lex(sample.source).code, matching: needles)
            #expect(mentions == sample.expected, "the matcher read \(mentions) in: \(sample.source)")
        }
        #expect(Set(samples.flatMap { $0.expected.keys }) == Set(Self.domainTypeNames),
                "a domain type has no sample the matcher must see")
        let neighbours = [
            "let token = envelope.payloadTypeToken",
            "public var isUnknownPayloadType: Bool { payloadType == nil }",
            "var violations = duplicatePairs(vocabulary.session.payloadTypeFields, duplicate)",
            "let role = MeshPayloadRole.role(for: token, in: namespace.family.vocabulary.mesh)",
            "let rules: ProximityNamespace.PayloadRules = vocabulary.payloads",
            "func supports(_ token: String, in host: ProximityNamespace.Capabilities) -> Bool {",
            "public typealias Role = ProximityRole",
            "public typealias RangingMode = ProximityRangingMode",
            "public typealias Mode = ProximitySessionMode",
            "func beginSession(role: ProximityCoordinator.Role, mode: ProximityCoordinator.Mode, localFingerprint: String)",
            "var proximityTrustStore: any ProximityTrustStore { get }",
            "let eligible = Self.eligibleFriends(in: store.trustedProximityPeers)",
            "func recordSessionAudit(_ audit: ProximitySessionAudit)",
            "let name = ProximityDisplayName.peerDisplayName(raw, in: namespace)",
            "payloadEncryption: PayloadEncryption = .none, payloadSummary: PayloadSummary,",
            "/// Fernlet's typed view: the `PayloadType` case it spells, as `ProximityMode` does.",
            #"#expect(name == "ConnectionSessionLog", "a TrainerAuditEvent row")"#
        ]
        // R2: bounded by the neighbour list.
        for source in neighbours {
            let mentions = Self.domainTypeMentions(in: SwiftSourceLexer.lex(source).code, matching: needles)
            #expect(mentions.isEmpty, "\(mentions.keys.sorted()) read a domain type in: \(source)")
        }
    }

    /// FernletDomainModel's types for Fernlet's payload vocabulary, session mode, item-name rules and
    /// persisted proximity records: what ProximityKit's core takes from its host, or does without.
    static let domainTypeNames = [
        "PayloadType", "ProximityCapability", "ProximityMode", "ItemNameModeration",
        "ProximityTrustedPeerRecord", "TrainerAuditEvent", "ConnectionSessionLog"
    ]

    /// Each of ``domainTypeNames`` as a whole identifier: no letter, digit or underscore on either
    /// side, so `payloadTypeToken` and `isUnknownPayloadType` are not it, and a module-qualified or
    /// nested use is.
    private static func domainTypeNeedles() throws -> [(name: String, regex: NSRegularExpression)] {
        try domainTypeNames.map { name in
            (name: name, regex: try NSRegularExpression(pattern: #"(?<![A-Za-z0-9_])"# + name + #"(?![A-Za-z0-9_])"#))
        }
    }

    /// The 1-based lines of lexed `code` that name each needle's type, by name, each list sorted and
    /// without repeats; a type `code` never names has no entry.
    private static func domainTypeMentions(
        in code: String, matching needles: [(name: String, regex: NSRegularExpression)]
    ) -> [String: [Int]] {
        var mentions: [String: [Int]] = [:]
        // R2: bounded by the needle list.
        for needle in needles {
            let lines = Set(matchLines(of: needle.regex, in: code)).sorted()
            if !lines.isEmpty { mentions[needle.name] = lines }
        }
        return mentions
    }

    /// One file's code lines naming one of Fernlet's domain types.
    struct DomainTypeLines: Sendable {
        /// The file, by path under the module root.
        let file: String
        /// The type, one of ``domainTypeNames``.
        let type: String
        /// How many of the file's code lines name it.
        let lines: Int
        /// Why the lines are still here, and the step that removes them.
        let reason: Reason

        init(_ file: String, _ type: String, _ lines: Int, _ reason: Reason) {
            self.file = file
            self.type = type
            self.lines = lines
            self.reason = reason
        }
    }

    /// Every file and type whose code lines still name one of Fernlet's domain types: none, since the
    /// coordinator's session mode became this module's own (plan step A1.0).
    static let domainTypeLines: [DomainTypeLines] = []

    /// `file`'s rule-4 rows with their counts and exit steps, for a failure message.
    private static func describeDomainRows(of file: String) -> String {
        let rows = domainTypeLines.filter { $0.file == file }
            .map { "\($0.type) on \($0.lines) (until \(Self.exitText($0.reason.exit)))" }
        return rows.isEmpty ? "none" : rows.joined(separator: ", ")
    }

    // MARK: Rule 5: package only on the listed lines

    /// `package` is declared in ProximityKit code only on the lines ``packageDeclarationLines``
    /// lists, file by file and count by count, each row with the plan step that closes its doors.
    ///
    /// `package` access reaches every target of FernletKit, and the test target through
    /// `@testable import`, but never the app, and never a module of another package: it is the access
    /// a Fernlet module inside the package would use a ProximityKit declaration through while a named
    /// later step reshapes or replaces it, so it is debt with an exit, never a settled seam (a settled
    /// seam is `public`, with its contract). Nothing else counts that debt: a widened declaration
    /// compiles clean wherever it is used. So the list is exact both ways, like rules 3 and 4: a new
    /// `package` line fails until a row names why it is there and its exit, and a line that goes away
    /// fails until its row is lowered or deleted, so no door outlives its step unnoticed. ProximityKit
    /// declares `package` on no code line: the presence radio's doors, its last, closed at plan step
    /// A1.1, when FernletSocial's presence manager began driving the radio through the public presence
    /// engine (`ProximityPresenceSession`). Every code line on which `package` is an access modifier
    /// counts, once, however its declaration goes on (``packageDeclarationPattern``), a setter's
    /// `package(set)` included; comments and literals may say `package` freely, and code may use it
    /// as a name.
    @Test func packageIsDeclaredOnlyOnTheListedLines() throws {
        let matcher = try NSRegularExpression(pattern: Self.packageDeclarationPattern)
        let sources = try Self.proximitySources()
        var found: [String: Int] = [:]
        var linesRead = 0
        // R2: bounded by the module's file list.
        for source in sources {
            linesRead += source.lexed.code.count(where: { $0 == "\n" }) + 1
            let lines = Set(Self.matchLines(of: matcher, in: source.lexed.code))
            if !lines.isEmpty { found[source.path] = lines.count }
        }
        #expect(sources.count >= 50, "the ProximityKit sweep read only \(sources.count) Swift files")
        #expect(linesRead >= 20_000, "the ProximityKit sweep read only \(linesRead) lines")
        let paths = Set(found.keys).union(Self.packageDeclarationLines.keys).sorted()
        // R2: bounded by the union of two finite key sets.
        for path in paths {
            let allowed = Self.packageDeclarationLines[path]
            let actual = found[path] ?? 0
            #expect(actual == (allowed?.lines ?? 0), """
                \(path) declares `package` on \(actual) code lines; the list says \(allowed?.lines ?? 0)\
                \(allowed.map { ", closing at \(Self.exitText($0.reason.exit))" } ?? ""). A new `package` door \
                needs a row naming why a Fernlet module needs it and the plan step that closes it (a \
                settled seam is `public`, with its contract); a door that closed needs its row lowered \
                or deleted here, so the list stays exact.
                """)
        }
    }

    /// Rule 5's matcher, fixtured both ways, because the matcher is the wall: it sees `package`
    /// wherever it is an access modifier, before a type, a protocol, a function, a property and an
    /// initializer, behind an attribute, as a setter's access (`public package(set) var`), before
    /// whatever modifier its declaration goes on with (`nonisolated`, `nonisolated(nonsending)`,
    /// `static`, an operator's `prefix` and `postfix` and an infix operator, which takes none,
    /// `consuming`, `borrowing`, `distributed`, `unowned(unsafe)`, `nonmutating`, a setter's
    /// `private(set)`), and ending its line before its declaration, alone or behind an attribute or a
    /// modifier; and it sees none of the nearest code where `package` is a name or no code at all: a
    /// manifest's `let package = Package(`, a comment and a literal that spell the word, an identifier
    /// that begins with it, an enum case named for it (alone, and before the next member), a
    /// setter-access declaration with no `package` before it, a loop variable, a parameter's argument
    /// label, a `guard` binding, a type test, a member read and write, a value ending a line before a
    /// declaration, a closure parameter, a call with a `set:` label, a return, a type named for it, a
    /// ternary's operand and an awaited value. Every sample is lexed first, as the module's files are.
    @Test func thePackageMatcherSeesEveryDeclarationAndNoNeighbour() throws {
        let matcher = try NSRegularExpression(pattern: Self.packageDeclarationPattern)
        let samples = [
            "package struct JSONSidecarFile<State: Codable> {",
            "package nonisolated static func fileURL(in directory: URL, name: String) -> URL {",
            "package init(fileURL: URL) {",
            "@MainActor package protocol PresenceRadioSession: AnyObject {",
            "package var onPeerDiscovered: ((PeerHandle) -> Void)?",
            "package private(set) var isRunning = false",
            "public package(set) var sessionHeartState = SessionHeartState()",
            "package nonisolated(nonsending) func settle() async {",
            "package consuming func take() {",
            "package borrowing func peek() {",
            "package static prefix func - (value: Level) -> Level { value }",
            "package static postfix func ++ (value: Level) -> Level { value }",
            "package static func + (lhs: Level, rhs: Level) -> Level { lhs }",
            "package distributed func ping() {",
            "package unowned(unsafe) var owner: Radio?",
            "package nonmutating func touch() {",
            "package\nfunc settle() {",
            "@MainActor package\nfinal class Radio {",
            "nonisolated(unsafe) package\nvar count = 0"
        ]
        // R2: bounded by the sample list.
        for sample in samples {
            let lines = Self.matchLines(of: matcher, in: SwiftSourceLexer.lex(sample).code)
            #expect(lines == [1], "the package matcher read \(lines) in: \(sample)")
        }
        let neighbours = [
            "let package = Package(",
            "/// a package door",
            #""package""#,
            "packageName",
            "case package",
            "private(set) var isRunning = false",
            "case package\n    var label: String { \"\" }",
            "for package in packages {",
            "func make(package level: Int) -> Int { level }",
            "guard let package else { return }",
            "if package is Bundle {",
            "let size = package.count",
            "manifest.package = nil",
            "let kind = package\nvar other = 1",
            "_ = packages.map { package in package }",
            "let level = package(set: x)",
            "    return package\n}",
            "class package\n{",
            "let pair = isOn ? package : other",
            "try await package\nlet next = 1"
        ]
        // R2: bounded by the neighbour list.
        for source in neighbours {
            let lines = Self.matchLines(of: matcher, in: SwiftSourceLexer.lex(source).code)
            #expect(lines.isEmpty, "the package matcher read a declaration on \(lines) in: \(source)")
        }
    }

    /// Rule 5's matcher over lexed code: every line on which `package` is an access modifier, in
    /// either of the two places a declaration can put it (multiline, so `^` and `$` are a line's).
    ///
    /// - **Before its declaration, on its line** (``packageBeforeItsDeclaration``): `package` as a
    ///   whole word (no identifier character and no `.` before it), then its setter's `(set)`, or then
    ///   the next word of its declaration, whatever that word is, so a modifier is counted however the
    ///   declaration goes on, one Swift adds later included. A name is never followed by a word but
    ///   for the five a value or a pattern can take after it (`in`, `as`, `is`, `where`, `else`), and
    ///   a parameter's name after its argument label, which a colon follows; those are not read.
    /// - **Ending its line, its declaration on a later one** (``packageEndingItsLine``): `package` last
    ///   on a line that holds nothing before it but attributes and modifiers. A word that introduces a
    ///   name or a value there (`case`, `let`, `return`, `try` and the like) makes it a name, as in an
    ///   enum case or a value named `package` at the end of a line, which is not read.
    static let packageDeclarationPattern = "(?m)" + packageBeforeItsDeclaration + "|" + packageEndingItsLine

    /// `package` followed on its line by `(set)` or by a word other than `in`, `as`, `is`, `where` and
    /// `else` that no colon follows.
    static let packageBeforeItsDeclaration =
        #"(?<![A-Za-z0-9_.])package(?:\(\s*set\s*\)|(?=[ \t]+(?!(?:in|as|is|where|else)\b)[A-Za-z_]\w*\b(?![ \t]*:)))"#

    /// `package` ending a line whose code before it is only attributes and modifiers: words (each with
    /// an optional parenthesized argument) none of which introduces a name or a value.
    static let packageEndingItsLine =
        #"^[ \t]*(?:(?:@\w+(?:\([^()\n]*\))?|(?!(?:case|let|var|func|class|struct|enum|actor|protocol|extension|typealias|associatedtype|import|return|throw|try|await|in|is|as|if|guard|while|switch|for|repeat|some|any|inout|else|where)\b)[A-Za-z_]\w*(?:\([^()\n]*\))?)[ \t]+)*package[ \t]*$"#

    /// One file's `package` declaration lines.
    struct PackageLines: Sendable {
        /// How many of the file's code lines declare `package`.
        let lines: Int
        /// Why the doors are open, and the step that closes them.
        let reason: Reason
    }

    /// Every file whose code declares `package`, by path under the module root, each row with the
    /// step that closes its doors: none, since the presence radio's doors closed behind the public
    /// presence engine (plan step A1.1).
    static let packageDeclarationLines: [String: PackageLines] = [:]

    // MARK: Rule 6: the moved types stay gone

    /// No type that left ProximityKit for Fernlet's own modules is declared, extended or aliased in
    /// ProximityKit code again: none of ``movedTypeNames``, read by ``movedTypeMatcherPattern(for:)``.
    ///
    /// Fernlet's social features left ProximityKit with their bytes unchanged: the heart dead-drop,
    /// presence, moderation's ban store, ledger and content hash, closeness, friend state, the parked
    /// chat payload, the clothing shop with its catalog payloads, the moderation report relay with its
    /// payload, the activity manager with its payloads and the signing its two domain types carry, the
    /// live-session chat with the first half of the content layer, the session hearts with the heart
    /// ledger and everything its routed judgement builds, and the session photos with the session review,
    /// the routed photo body and the JSON sidecar, for FernletSocial, and the sealed-backup escrow and
    /// (plan step A0.6) the Live Activity reaper with its attributes type for the app; the support
    /// layout that named their folder and the camera's copy vault, whose one line FernletSocial's own
    /// copy holds, were deleted; and (plan step A0.7) the recipe share, its manager, its diagnostics
    /// ring and its wire types, left for FernletSocial over the pair session that stayed, and its three
    /// public values were renamed in place for the one-to-one send, so their old names are refused here
    /// too, against a compatibility alias, as are (plan step A1.0) the old names of the nine
    /// recipe-named types of the pair session's mechanism, renamed with pair names before the package
    /// left Fernlet's tree. Rules 2 to 4 cannot see one come back: a feature
    /// re-declared here under its old name, with no Fernlet string, no registry label and no domain
    /// type of its own, compiles clean and passes them and every other test, and two declarations of
    /// one name in two modules the app imports compile until a caller names it. So each name is
    /// refused as a type declared here (a class, struct, enum, actor or protocol, nested or not), an
    /// extension, or an alias's name or target, module-qualified or not. The list has no exit step: it
    /// only grows, as each step adds the types it moves out.
    /// Only code counts: comments and literals may name a moved type freely, as the docs that say where
    /// it went do. The same matcher over types that stay (``declarationFloorNames``) must find each of
    /// them, so a matcher gone blind cannot pass the module vacuously.
    /// A public member renamed in place has no declaration keyword the type matcher reads, so its old
    /// name (``renamedMemberNames``) is refused as any whole identifier in code, read by
    /// ``renamedMemberMatcherPattern(for:)``: a stored property, an initializer label and a read bring
    /// it back alike.
    @Test func noMovedTypeIsDeclaredExtendedOrAliasedInProximityKit() throws {
        let moved = try NSRegularExpression(pattern: Self.movedTypeMatcherPattern(for: Self.movedTypeNames))
        let floor = try NSRegularExpression(pattern: Self.movedTypeMatcherPattern(for: Self.declarationFloorNames))
        let renamed = try NSRegularExpression(pattern: Self.renamedMemberMatcherPattern(for: Self.renamedMemberNames))
        let sources = try Self.proximitySources()
        var violations: [String] = []
        var floorSeen: Set<String> = []
        // R2: bounded by the module's file list.
        for source in sources {
            violations += Self.lineCaptures(of: moved, in: source.lexed.code).map {
                "\(source.path):\($0.line): \($0.name)"
            }
            violations += Self.lineCaptures(of: renamed, in: source.lexed.code).map {
                "\(source.path):\($0.line): \($0.name) (a renamed member's old name)"
            }
            floorSeen.formUnion(Self.lineCaptures(of: floor, in: source.lexed.code).map { $0.name })
        }
        #expect(sources.count >= 50, "the ProximityKit sweep read only \(sources.count) Swift files")
        #expect(Set(Self.movedTypeNames).count == Self.movedTypeNames.count, "a moved type is listed twice")
        #expect(floorSeen == Set(Self.declarationFloorNames), """
            the matcher read only \(floorSeen.sorted()) of the types that stay in ProximityKit \
            (\(Self.declarationFloorNames.sorted())): a matcher that no longer sees a declaration would \
            pass every file vacuously
            """)
        #expect(violations.isEmpty, """
            ProximityKit declares, extends or aliases a type that left it, or names a renamed member's \
            old name: \(violations). Fernlet's features live in FernletSocial and its sealed-backup \
            escrow in the app, which depend on ProximityKit, never the reverse. Mechanism a feature \
            needs belongs here under a name of its own, as public API with its contract or, while a \
            named later step reshapes it, as a `package` door on rule 5's list; the feature itself goes \
            back to its module, and a renamed type or member keeps its new name, with no alias.
            """)
    }

    /// Rule 6's matcher, fixtured both ways, because the matcher is the wall: it sees a moved name
    /// declared as every kind of type (a class behind its attribute and modifiers, a struct, an enum,
    /// an actor, a protocol, a generic type, a nested type, a type whose name is on the line after its
    /// keyword), extended (plainly, `nonisolated`, module-qualified) and aliased (as the alias's name,
    /// or as its target, plain, behind a generic alias or module-qualified), each match on its
    /// keyword's line and under its own name; it sees every listed name declared, extended and aliased,
    /// and never inside a longer name or a use; and it sees none of the nearest code that declares no
    /// moved type: the types that stay beside them (the prekey bundle, the coordinator, the presence
    /// radio's TXT vocabulary, the prekey store's alias for the bundle), a name that begins or ends
    /// with a moved name, a use of one as a type or a value, a class method that returns one, a host
    /// extension, and a comment and a literal that name one. Every sample is lexed first, as the
    /// module's files are. The renamed-member matcher is fixtured beside it
    /// (``expectTheRenamedMemberMatcherSeesEveryFormAndNoNeighbour()``).
    @Test func theMovedTypeMatcherSeesEveryFormAndNoNeighbour() throws {
        let matcher = try NSRegularExpression(pattern: Self.movedTypeMatcherPattern(for: Self.movedTypeNames))
        let read = { (source: String) in Self.lineCaptures(of: matcher, in: SwiftSourceLexer.lex(source).code) }
        let samples: [(source: String, name: String)] = [
            ("public final class PresenceManager: ProximityPayloadHandling {", "PresenceManager"),
            ("extension HeartPrekeyStore {", "HeartPrekeyStore"),
            ("typealias ClosenessLedger = Foo", "ClosenessLedger"),
            ("@MainActor final class ModerationBanStore {", "ModerationBanStore"),
            ("public nonisolated struct CachedFriendState: Codable, Equatable, Identifiable {", "CachedFriendState"),
            ("public nonisolated enum ModerationContentHash {", "ModerationContentHash"),
            ("actor HeartDropOutbox {", "HeartDropOutbox"),
            ("protocol HeartDropSidecarFormatCensus: Sendable {", "HeartDropSidecarFormatCensus"),
            ("final class HeartDropService<Transport> {", "HeartDropService"),
            ("struct Escrow { enum BackupEscrowReconcileOutcome: Equatable { case noEscrow } }",
             "BackupEscrowReconcileOutcome"),
            ("public final class\n    ProximitySupportLayout {", "ProximitySupportLayout"),
            ("nonisolated extension HeartDropSealer {", "HeartDropSealer"),
            ("extension FernletSocial.TempMessagePayload: CustomStringConvertible {}", "TempMessagePayload"),
            ("public typealias Escrow = SealedBackupEscrowKey", "SealedBackupEscrowKey"),
            ("typealias Cache<Key> = HeartDropPeerBundleCache", "HeartDropPeerBundleCache"),
            ("typealias Scope = FernletSocial.HeartDropStorageScope", "HeartDropStorageScope")
        ]
        // R2: bounded by the sample list.
        for sample in samples {
            let found = read(sample.source)
            #expect(found.map { $0.line } == [1] && found.map { $0.name } == [sample.name],
                    "the moved-type matcher read \(found) in: \(sample.source)")
        }
        // R2: bounded by the name list and three forms each way.
        for name in Self.movedTypeNames {
            for form in ["struct \(name) {", "extension \(name) {", "typealias Alias = \(name)"] {
                #expect(read(form).map { $0.name } == [name], "the moved-type matcher misses \(name) in: \(form)")
            }
            for form in ["struct \(name)Row {", "struct Legacy\(name) {", "let value: \(name)? = nil"] {
                #expect(read(form).isEmpty, "the moved-type matcher read \(read(form)) in: \(form)")
            }
        }
        let neighbours = [
            "public nonisolated struct ProximityPrekeyBundle: Codable, Equatable, Sendable {",
            "public final class ProximityCoordinator {",
            "package nonisolated enum PresenceAdvertisement {",
            "public typealias Bundle = ProximityPrekeyBundle",
            "final class PresenceManagerTests {",
            "let scope = HeartDropStorageScope.production",
            "class func makeHeartDropService() -> HeartDropService {",
            "extension ProximityHost {",
            "/// PresenceManager in FernletSocial",
            #"let token = "HeartDropService""#
        ]
        // R2: bounded by the neighbour list.
        for source in neighbours {
            #expect(read(source).isEmpty, "the moved-type matcher read \(read(source)) in: \(source)")
        }
        try Self.expectTheRenamedMemberMatcherSeesEveryFormAndNoNeighbour()
    }

    /// The renamed-member matcher, fixtured both ways: it sees every listed old name as a stored
    /// property, an initializer label, an assignment through `self` and a read off the namespace, each
    /// on its line under its own name, and none of a longer name that begins or ends with it, a comment
    /// or a literal that spells it (the field paths a diagnostic names).
    /// Every sample is lexed first, as the module's files are.
    static func expectTheRenamedMemberMatcherSeesEveryFormAndNoNeighbour() throws {
        let matcher = try NSRegularExpression(pattern: Self.renamedMemberMatcherPattern(for: Self.renamedMemberNames))
        let read = { (source: String) in Self.lineCaptures(of: matcher, in: SwiftSourceLexer.lex(source).code) }
        // R2: bounded by the member list and four forms each way.
        for name in Self.renamedMemberNames {
            for form in ["public let \(name): Radio", "init(mesh: Radio, \(name): Radio) {",
                         "self.\(name) = radio", "let radio = namespace.family.radios.\(name)"] {
                #expect(read(form).map { $0.line } == [1] && read(form).map { $0.name } == [name],
                        "the renamed-member matcher read \(read(form)) in: \(form)")
            }
            for form in ["let \(name)Listening = true", "let legacy\(name) = radio", "/// radios.\(name)",
                         #"let field = "family.radios.\#(name).alpn""#] {
                #expect(read(form).isEmpty, "the renamed-member matcher read \(read(form)) in: \(form)")
            }
        }
    }

    /// Every type that left ProximityKit for Fernlet's own modules, by its name. FernletSocial's: the
    /// heart dead-drop's (the service, its outbox and dedup store, its peer-bundle cache, the sealer,
    /// the sidecar seal, the storage scope, the format census and the prekey store), presence's (the
    /// manager and its heart connection), the closeness ledger, the friend-state cache and its rows,
    /// moderation's (the ban store and its record, the ledger and the content hash), the parked chat
    /// payload, the clothing shop's (the shop, a held catalog and the catalog payload), the moderation
    /// report relay's (the relay, its payload and a signed row), the activity manager's (the manager and
    /// its four nested shapes, the params hash, the five wire payloads, and FernletDomainModel's join
    /// token and roster snapshot, which its signing and verification extend), the live-session chat's
    /// (the transcript store, the send outcome, the routed text header and body, and the content
    /// layer's first half: the merged photo and message kinds, the content ledger, the ingestion gates,
    /// the photo reassembly and the heart receipt), the session hearts' (the heart ledger, its
    /// received-heart record and its durability proof, the routed heart's ack, the merged heart, the
    /// heart commit and its outcome, the routed heart header and body, and the hearts' failure and state
    /// vocabulary, nested in `MeshSessionHearts`) and the session photos' (the wall's post and its
    /// preferences, the keep's outcome nested in `MeshSessionPhotos`, the session-end review batch, its
    /// answer and the answer's failure, the routed photo header and body, and the JSON sidecar). The
    /// app's: the sealed-backup escrow's (the escrow key, its reconcile outcome, its candidate and its
    /// legacy-account name), and, since plan step A0.6, the Live Activity reaper and the attributes
    /// type it enumerates. Deleted: the support layout that named their folder, and the camera's copy
    /// vault, `ProximityUICopy`, whose one line FernletSocial's copy holds. FernletSocial's since plan
    /// step A0.7: the recipe share's (its manager, the diagnostics ring presence shares with it, and
    /// its five wire types: the payload, the shared recipe and its kind, the saved recipe's payload and
    /// a pending inbound share). Renamed in place, since plan step A0.7: the three public values of the
    /// one-to-one send, the recipe share's outcome, its failure and its picker row, named
    /// `ProximityPairSendOutcome`, `ProximityPairSendFailure` and `ProximityPairPeer`, and, since plan
    /// step A1.0, the nine recipe-named types of the pair session's mechanism, named
    /// `ProximityPairTransfer`, `ProximityPairDiscoveryGate`, `ProximityPairAdvertisedName`,
    /// `ProximityPairAdvertisement`, `ProximityPairDialHello`, `ProximityPairPosture`,
    /// `ProximityPairRadioSession`, `NetworkPairSession` and the radio's private `PairTransferClaim`, so
    /// no compatibility alias brings a recipe name back.
    static let movedTypeNames = [
        "HeartDropService", "HeartDropOutbox", "HeartDropDedupStore", "HeartDropPeerBundleCache",
        "HeartDropSealer", "HeartDropSidecarSeal", "HeartDropStorageScope", "HeartDropSidecarFormatCensus",
        "HeartPrekeyStore", "PresenceManager", "PresenceHeartConnection", "ClosenessLedger",
        "FriendStateCache", "CachedFriendState", "ModerationBanStore", "BanRecord", "ModerationLedger",
        "ModerationContentHash", "TempMessagePayload", "ProximitySupportLayout", "SealedBackupEscrowKey",
        "BackupEscrowReconcileOutcome", "EscrowCandidate", "IdentityKeychainKey",
        "MeshClothingShop", "ProximityClothingCatalog", "ClothingCatalogPayload",
        "ModerationReportRelay", "ModerationReportPayload", "SignedModerationReport",
        "ProximityActivityManager", "HostedActivity", "JoinedActivity", "OfferedActivity", "PendingActivityJoin",
        "ActivityParamsHash", "ActivityOfferPayload", "ActivityJoinRequestPayload", "ActivityJoinGrantPayload",
        "ActivityRosterSnapshotPayload", "ActivitySyncPayload", "ActivityJoinToken", "ActivityRosterSnapshot",
        "SessionMessageStore", "MeshTextSendOutcome", "MeshRoutedTextHeader", "MeshRoutedTextBody",
        "MeshMergedPhoto", "MeshMergedMessage", "MeshContentLedger", "MeshContentGates", "MeshPhotoReassembly",
        "MeshHeartReceipt",
        "ProximityHeartLedger", "ReceivedHeartRecord", "MeshHeartLedgerProof", "MeshMergedHeart", "MeshHeartCommit",
        "MeshHeartCommitOutcome", "MeshRoutedHeartAck", "MeshRoutedHeartHeader", "MeshRoutedHeartBody",
        "SessionHeartFailure", "SessionHeartState",
        "FriendPhotoWallPost", "FriendPhotoWallPreferences", "MeshFriendReviewBatch", "SessionPhotoAnswer",
        "SessionPhotoAnswerFailure", "MeshRoutedPhotoHeader", "MeshRoutedPhotoBody", "HeldKeepOutcome",
        "JSONSidecarFile", "ProximityUICopy",
        "ProximityConnectionActivityAttributes", "ProximityLiveActivityReaper",
        "RecipeShareOutcome", "RecipeShareFailure", "ProximityRecipeShareRecipient",
        "ProximityRecipeShareManager", "ProximityRecipeShareDiagnosticEvent", "ProximityRecipeShareDiagnostics",
        "ProximityRecipeSharePayload", "ProximitySharedRecipeKind", "ProximitySharedRecipe",
        "SharedSavedRecipePayload", "PendingProximityRecipeShare",
        "RecipeShareTransfer", "RecipeShareDiscoveryGate", "RecipeShareAdvertisedName", "RecipeShareAdvertisement",
        "RecipeShareDialHello", "RecipeSharePosture", "RecipeShareRadioSession", "NetworkRecipeShareSession",
        "RecipeShareTransferClaim"
    ]

    /// Every public member renamed in place, by its old name, which ProximityKit code names nowhere:
    /// `recipeShare`, the namespace's pair-session radio (`ProximityNamespace.Radios.recipeShare` and its
    /// `Radios.init` label), named `pair` since plan step A1.0. A host builds its namespace through that
    /// label, so the old name back as a field, a label or a read would be a compatibility door.
    static let renamedMemberNames = ["recipeShare"]

    /// Types that stay in ProximityKit, each declared or extended there, which rule 6's matcher must
    /// find: its floor against a blind matcher.
    static let declarationFloorNames = [
        "IdentityService", "ProximityHost", "ProximityPrekeyBundle", "PresenceAdvertisement", "ProtectedSidecar"
    ]

    /// Rule 6's matcher over lexed code, for `names`: a type keyword (`class`, `struct`, `enum`, `actor`,
    /// `protocol`), `extension` or `typealias`, then one of the names, module-qualified or not, or a
    /// `typealias` of any name, generic or not, whose target is one of them, module-qualified or not.
    /// The keyword is a whole word (no identifier character and no `.` before it) and the name a whole
    /// identifier (none after it), so a longer name that begins or ends with one is not it; the name is
    /// capture group 1.
    static func movedTypeMatcherPattern(for names: [String]) -> String {
        let qualifier = #"(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)*"#
        let declared = #"(?:class|struct|enum|actor|protocol|extension|typealias)\s+"# + qualifier
        let aliased = #"typealias\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:<[^>\n]*>\s*)?=\s*"# + qualifier
        let alternatives = names.map(NSRegularExpression.escapedPattern(for:)).joined(separator: "|")
        return #"(?<![A-Za-z0-9_.])(?:"# + declared + "|" + aliased + ")(" + alternatives + #")(?![A-Za-z0-9_])"#
    }

    /// Rule 6's renamed-member matcher over lexed code, for `names`: any whole identifier that is one
    /// of them (no identifier character on either side), so a declaration, a label and a read are
    /// seen alike and a longer name is not; the name is capture group 1.
    static func renamedMemberMatcherPattern(for names: [String]) -> String {
        let alternatives = names.map(NSRegularExpression.escapedPattern(for:)).joined(separator: "|")
        return #"(?<![A-Za-z0-9_])("# + alternatives + #")(?![A-Za-z0-9_])"#
    }

    // MARK: ProximityKit's package dependencies

    /// ProximityKit's target in its package's manifest, the package root's `Package.swift` (``PackageRoot``:
    /// `FernletKit/Package.swift` in the Fernlet repository, the root's own in ProximityKit's), depends on
    /// exactly ``proximityKitDependencies``, compared as a sorted list, so a dependency added, dropped or
    /// listed twice fails.
    ///
    /// An edge leaves with the last code that reads its module, and none may come back unseen: an edge
    /// restored in the manifest compiles clean, and so does every file that then imports the module
    /// again. `FernletFoundation` (the session heart's day key) and `PrivateMediaStore` (the session
    /// photos' wall and pending corpus) are FernletSocial's edges, with the features that read them,
    /// and not this module's; `FernletDomainModel` is not either, since the session mode became this
    /// module's own, nor `FernletCrypto`, since its identity signs and verifies only under its own
    /// purposes, a host's feature labels minted with its feature-signature mint (plan step A1.0). The
    /// manifest is read as text: the `dependencies:` array of the one target declared
    /// `name: "ProximityKit"`, each quoted name in it, so the target keeps a literal `dependencies: []`.
    /// The reader needs nothing else of the manifest, so it reads either repository's alike: the target
    /// declared `name: "ProximityKit", dependencies: [...]`, once (a product or a test target of a longer
    /// name is not it). A manifest whose ProximityKit target the reader cannot find, or whose list is not
    /// a literal, fails rather than passing on an empty list.
    @Test func proximityKitDependsOnExactlyItsListedTargets() throws {
        let manifest = try PackageRoot.source("Package.swift")
        let target = try NSRegularExpression(pattern: #"name:\s*"ProximityKit"\s*,\s*dependencies:\s*\[([^\]]*)\]"#)
        let text = manifest as NSString
        let matches = target.matches(in: manifest, range: NSRange(location: 0, length: text.length))
        try #require(matches.count == 1,
                     "the manifest declares \(matches.count) ProximityKit targets with a dependency list")
        let list = text.substring(with: matches[0].range(at: 1))
        let quoted = try NSRegularExpression(pattern: #""([^"]+)""#)
        let listText = list as NSString
        let dependencies = quoted.matches(in: list, range: NSRange(location: 0, length: listText.length)).map {
            listText.substring(with: $0.range(at: 1))
        }
        #expect(dependencies.sorted() == Self.proximityKitDependencies.sorted(), """
            ProximityKit depends on \(dependencies), not exactly \(Self.proximityKitDependencies): an edge A0.5 \
            or A1.0 dropped came back, or one left without this list moving with it
            """)
    }

    /// ProximityKit's target dependencies, exactly: none. It depends on nothing in FernletKit (plan
    /// step A1.0), the state the package left the Fernlet repository in.
    static let proximityKitDependencies: [String] = []

    // MARK: The lexer, fixtured

    /// The lexer reads code, comments and literals as Swift does: the rules above are only as sharp as
    /// it is. This is the package's own copy (`TestSupport/SwiftSourceLexer.swift`, a twin of the one
    /// Fernlet's source walls read through, which Fernlet's `SwiftSourceLexerTests` holds to the same
    /// fixtures).
    ///
    /// Each fixture is a form the module or the test tree writes, chosen where a looser reading goes
    /// wrong: a quote in a comment, a comment inside a comment, an escaped quote, a literal inside an
    /// interpolation, a raw literal holding quotes and a `\(` that is text, and a multi-line literal,
    /// whose line breaks the code must keep so every later line number stays true.
    @Test func theLexerTellsCodeCommentsAndLiteralsApartAsSwiftDoes() {
        let commented = SwiftSourceLexer.lex(#"let a = "x" // "not a literal""#)
        #expect(commented.literals == [SwiftSourceLexer.Literal(line: 1, text: "x")])
        #expect(commented.code == #"let a = "" "#)
        let nested = SwiftSourceLexer.lex("/* outer /* \"inner\" */ still */ let b = 1\nlet c = \"y\"")
        #expect(nested.literals == [SwiftSourceLexer.Literal(line: 2, text: "y")])
        #expect(nested.code == " let b = 1\nlet c = \"\"")
        let escaped = SwiftSourceLexer.lex(#"let d = "say \"fernlet\"" + "z""#)
        #expect(escaped.literals.map(\.text) == [#"say \"fernlet\""#, "z"])
        let interpolated = SwiftSourceLexer.lex(#"let e = "a \(f("fernlet")) b""#)
        #expect(interpolated.literals.map(\.text) == [#"a \(f("fernlet")) b"#])
        #expect(interpolated.code == #"let e = "(f(""))""#)
        let raw = SwiftSourceLexer.lex(##"let f = #"raw "quoted" \(text)"# + "w""##)
        #expect(raw.literals.map(\.text) == [#"raw "quoted" \(text)"#, "w"])
        let multiline = SwiftSourceLexer.lex("let g = \"\"\"\n    one \"two\"\n    \"\"\"\nlet h = \"v\"")
        #expect(multiline.literals.map(\.line) == [1, 4])
        #expect(multiline.literals.first?.text == "\n    one \"two\"\n    ")
        #expect(multiline.code == "let g = \"\n\n\"\nlet h = \"\"")
    }

    // MARK: The sweep

    /// ProximityKit's Swift files, each by its path under the module root and lexed, sorted by path.
    ///
    /// Read through ``PackageRoot``, so the walk is the module's own folder in either repository; each
    /// rule that walks it floors the files it read, so a walk that found nothing fails.
    static func proximitySources() throws -> [(path: String, lexed: SwiftSourceLexer.Lexed)] {
        let root = PackageRoot.url(moduleRoot)
        let walker = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil)
        let files = (walker?.allObjects as? [URL] ?? []).filter { $0.pathExtension == "swift" }
        var sources: [(path: String, lexed: SwiftSourceLexer.Lexed)] = []
        // R2: bounded by the module's file list.
        for file in files.sorted(by: { $0.path < $1.path }) {
            let source = try String(contentsOf: file, encoding: .utf8)
            sources.append((path: relativePath(of: file), lexed: SwiftSourceLexer.lex(source)))
        }
        return sources
    }

    /// `file`'s path under the module root, read off the path's own `Sources/ProximityKit/` component
    /// (its last) so a symlinked checkout (`/tmp` and `/private/tmp`) resolves alike, inside the Fernlet
    /// repository and at ProximityKit's own root; the full path if the file is somehow outside it, which
    /// then matches no allowlist row and fails loudly. Every row above names its file by this path.
    static func relativePath(of file: URL) -> String {
        let path = file.path
        guard let range = path.range(of: "/" + moduleRoot + "/", options: .backwards) else { return path }
        return String(path[range.upperBound...])
    }

    /// The 1-based lines of `code` on which `regex` matches.
    private static func matchLines(of regex: NSRegularExpression, in code: String) -> [Int] {
        let text = code as NSString
        return regex.matches(in: code, range: NSRange(location: 0, length: text.length)).map {
            text.substring(to: $0.range.location).count(where: { $0 == "\n" }) + 1
        }
    }

    /// Every match of `regex`'s two capture groups in `code`, joined as `first.second`.
    private static func captures(of regex: NSRegularExpression, in code: String) -> Set<String> {
        let text = code as NSString
        let matches = regex.matches(in: code, range: NSRange(location: 0, length: text.length))
        return Set(matches.map { text.substring(with: $0.range(at: 1)) + "." + text.substring(with: $0.range(at: 2)) })
    }

    /// Every match of `regex` in `code`, in order, as the 1-based line it starts on and its first
    /// capture group.
    private static func lineCaptures(of regex: NSRegularExpression, in code: String) -> [(line: Int, name: String)] {
        let text = code as NSString
        return regex.matches(in: code, range: NSRange(location: 0, length: text.length)).map {
            (line: text.substring(to: $0.range.location).count(where: { $0 == "\n" }) + 1,
             name: text.substring(with: $0.range(at: 1)))
        }
    }

    // MARK: Reasons

    /// The plan step that takes a value out of ProximityKit. A step's case is deleted with its last
    /// row, as A1's (the presence radio's `package` doors, closed at plan step A1.1 behind the public
    /// presence engine) was.
    ///
    /// No case is left, so rules 3 to 5 list nothing and the enum is uninhabited, as
    /// `ProximityPlatformNeutralityTests.ExitStep` is: a ``Reason``'s `exit` is optional so the type
    /// still compiles, and nil would name no step. A later step that adds a row adds its case with its
    /// step's name as a `String` raw value, the raw type with it, and ``exitText(_:)``'s arm naming it,
    /// which the compiler then requires.
    enum ExitStep: Sendable {}

    /// A row's exit step, as a failure message says it: every row of rules 3 to 5 names one, and no
    /// case is left, so the one arm is the nil a row must never carry. A step that adds a case adds
    /// the arm that names it.
    static func exitText(_ exit: ExitStep?) -> String {
        switch exit {
        case .none:
            return "no plan step"
        }
    }

    /// Why a value is still in ProximityKit, and the step that takes it out.
    struct Reason: Sendable {
        /// The step that removes it; nil only while no step is left to name.
        let exit: ExitStep?
        /// Why it is still here until then.
        let why: String
    }
}
