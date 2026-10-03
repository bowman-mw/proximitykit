// ProximityNamespace+Soundness.swift
// ProximityKit/Namespace
//
// The rules a namespace is judged by: alone, once, when it is built (`soundness`), and against
// another app's namespace (`familyCollisions(with:)`, `installationCollisions(with:)`). Every loop runs
// over the namespace's fixed shape — at most 39 labels, three radios, three keychain services, four
// storage names, forty-six vocabulary fields — or over one value whose length a guard has already
// bounded, or a string or token list the host wrote.

import Foundation

// MARK: - Soundness rules

nonisolated extension ProximityNamespace {

    /// The most bytes a label may hold.
    static let maximumLabelBytes = 255

    /// The most characters a Bonjour service name may hold (RFC 6335 §5.1).
    static let maximumServiceNameLength = 15

    /// The most bytes an ALPN may hold: TLS writes its length in one byte.
    static let maximumALPNBytes = 255

    /// The most bytes the mesh heartbeat may hold.
    static let maximumHeartbeatBytes = 64

    /// The most bytes a payload token or a membership record kind may hold. A mesh message is held to
    /// ``maximumSummaryTitleCharacters`` too: the mesh signs it as its frame's summary title.
    static let maximumPayloadTokenBytes = 255

    /// The most bytes a capability token may hold: the coordinator cuts every token a peer advertises
    /// to `ProximityCoordinator.maxCapabilityTokenLength` characters, so a longer one would never match.
    static let maximumCapabilityTokenBytes = 32

    /// The most bytes a routed-type token may hold: `MeshRoutedManifestFormat.maxTypeTokenLength`, past
    /// which a routed manifest is refused.
    static let maximumRoutedTypeTokenBytes = 64

    /// The most characters a summary title may hold: a receiver's bounded `PayloadSummary` decode refuses
    /// a longer one (`PayloadSummary.maxDetailCharacters`, in `Wire/`, out of this folder's reach,
    /// which `ProximityVocabularyGoldenTests` holds equal). It bounds the session messages' titles, and
    /// every mesh message, which the mesh signs as its frame's title.
    static let maximumSummaryTitleCharacters = 200

    /// The most bytes a DNS-SD instance name may hold: it is one DNS label.
    static let maximumInstanceNameBytes = 63

    /// The lowercase hex characters a mesh or recipe-share instance name holds after its prefix
    /// (`MeshLinkAdvertisement.instanceNameTokenLength`).
    static let meshInstanceNameTokenLength = 12

    /// The lowercase hex characters a presence instance name holds after its prefix: eight bytes of
    /// entropy (`PresenceEpochPosture.instanceNameEntropyByteCount`), two characters each.
    static let presenceInstanceNameTokenLength = 16

    /// The most bytes the certificates' common name may hold: X.509's upper bound on a common name.
    static let maximumCommonNameBytes = 64

    /// The most characters a peer-name cap may allow: a name is a short label, and the loops that walk
    /// one a character at a time (the recipe radio's advertised-name trim) are bounded by the cap.
    static let maximumPeerNameLength = 63

    /// The characters of a key fingerprint, the shape `PeerNameDisplay` hides when a fingerprint was
    /// filed as a name (`PeerNameDisplay.fingerprintLength`, in `UI/`, out of this folder's reach, which
    /// `ProximityVocabularyGoldenTests` holds equal). The display cuts a name to the peer-name cap
    /// before it looks, so a shorter cap would cut a fingerprint to a name it shows as a person's.
    static let peerNameFingerprintLength = 16

    /// Every soundness rule's verdict for one family and installation.
    ///
    /// Runs once, from ``init(family:installation:)``, in a fixed order — labels, radios and heartbeat,
    /// QR scheme, keychain, storage, log subsystem, then the vocabulary, the radios' presentation
    /// strings and the peer-name policy — so equal inputs always record equal verdicts.
    ///
    /// - Parameters:
    ///   - family: The family to judge.
    ///   - installation: The installation to judge.
    /// - Returns: ``Soundness/sound``, or every violation in rule order.
    static func judge(family: Family, installation: Installation) -> Soundness {
        var violations = labelViolations(family.purposes.labelRows(under: purposesPath))
        violations += radioViolations(family.radios)
        if !isWellFormedURLScheme(family.verifyQR.urlScheme) {
            violations.append(.malformedURLScheme)
        }
        violations += keychainViolations(installation.keychain)
        violations += storageViolations(installation.storage)
        if installation.logSubsystem.isEmpty {
            violations.append(.emptyLogSubsystem)
        }
        violations += vocabularyViolations(family.vocabulary)
        violations += presentationViolations(family.radios)
        violations += peerNameViolations(
            installation.peerNames, meshInstanceNamePrefix: family.radios.meshInstanceNamePrefix)
        return violations.isEmpty ? .sound : .unsound(violations)
    }

    // MARK: Labels

    /// Labels: each well-formed, and every unordered pair distinct and prefix-free.
    ///
    /// - Parameter rows: Every label row, in declaration order.
    /// - Returns: The malformed labels in row order, then each pair's violation in pair order.
    private static func labelViolations(_ rows: [LabelRow]) -> [Violation] {
        var violations = rows
            .filter { !isWellFormedLabel($0.purpose.data) }
            .map { Violation.malformedLabel(field: $0.field) }
        // R2: every unordered pair once, over at most 39 rows — 741 comparisons.
        for (index, row) in rows.enumerated() {
            for other in rows.dropFirst(index + 1) {
                guard let violation = labelPairViolation(row, other) else { continue }
                violations.append(violation)
            }
        }
        return violations
    }

    /// The violation two labels make together, if any. `Data.starts(with:)` is the same positional
    /// test ``ProximityCryptographicPurpose/signingBytes(_:)`` applies.
    ///
    /// - Parameters:
    ///   - first: The row declared first.
    ///   - second: The row declared later.
    /// - Returns: `duplicateLabel` for equal bytes, `labelIsPrefix` when one begins the other, else nil.
    private static func labelPairViolation(_ first: LabelRow, _ second: LabelRow) -> Violation? {
        let firstBytes = first.purpose.data
        let secondBytes = second.purpose.data
        guard firstBytes != secondBytes else {
            return .duplicateLabel(field: first.field, otherField: second.field)
        }
        if secondBytes.starts(with: firstBytes) {
            return .labelIsPrefix(shorter: first.field, longer: second.field)
        }
        if firstBytes.starts(with: secondBytes) {
            return .labelIsPrefix(shorter: second.field, longer: first.field)
        }
        return nil
    }

    /// 1 to ``maximumLabelBytes`` bytes, each from `0x21` (`!`) to `0x7E` (`~`): printable ASCII with no
    /// space and never a `0x00`.
    private static func isWellFormedLabel(_ bytes: Data) -> Bool {
        guard (1...maximumLabelBytes).contains(bytes.count) else { return false }
        // R2: bounded by the guard above, at most 255 bytes.
        return bytes.allSatisfy { (0x21...0x7E).contains($0) }
    }

    // MARK: Radios and heartbeat

    /// Radios: every service type and ALPN well-formed, the service types distinct, the ALPNs distinct,
    /// and the heartbeat well-formed.
    ///
    /// - Parameter radios: The family's radios.
    /// - Returns: Each radio's malformed values in radio order, then duplicate service types, duplicate
    ///   ALPNs, and the heartbeat.
    private static func radioViolations(_ radios: Radios) -> [Violation] {
        var violations: [Violation] = []
        // R2: three radios.
        for (serviceType, alpn) in zip(radios.serviceTypeFields, radios.alpnFields) {
            if !isWellFormedServiceType(serviceType.value) {
                violations.append(.malformedServiceType(field: serviceType.field))
            }
            if !isWellFormedALPN(alpn.value) {
                violations.append(.malformedALPN(field: alpn.field))
            }
        }
        violations += duplicatePairs(radios.serviceTypeFields, Violation.duplicateRadioValue(field:otherField:))
        violations += duplicatePairs(radios.alpnFields, Violation.duplicateRadioValue(field:otherField:))
        if !isWellFormedHeartbeat(radios.meshHeartbeat) {
            violations.append(.malformedHeartbeat)
        }
        return violations
    }

    /// `_name._udp`, the name passing ``isWellFormedServiceName(_:)``.
    private static func isWellFormedServiceType(_ serviceType: String) -> Bool {
        let prefix = "_"
        let suffix = "._udp"
        let longest = prefix.utf8.count + maximumServiceNameLength + suffix.utf8.count
        guard serviceType.utf8.count <= longest, serviceType.hasPrefix(prefix), serviceType.hasSuffix(suffix) else {
            return false
        }
        let name = serviceType.utf8.dropFirst(prefix.utf8.count).dropLast(suffix.utf8.count)
        return isWellFormedServiceName(Array(name))
    }

    /// 1 to ``maximumServiceNameLength`` characters of `[a-z0-9-]`, at least one of them a letter, with
    /// no hyphen first, last or twice in a row: RFC 6335's service-name rule, lowercase.
    private static func isWellFormedServiceName(_ name: [UInt8]) -> Bool {
        let hyphen = UInt8(ascii: "-")
        guard (1...maximumServiceNameLength).contains(name.count),
              let first = name.first, let last = name.last,
              first != hyphen, last != hyphen else { return false }
        // R2: bounded by the guard above, at most 15 characters.
        guard name.allSatisfy({ isLowercaseLetter($0) || isDigit($0) || $0 == hyphen }),
              name.contains(where: { isLowercaseLetter($0) }) else { return false }
        return !zip(name, name.dropFirst()).contains { $0 == hyphen && $1 == hyphen }
    }

    /// 1 to ``maximumALPNBytes`` bytes of printable ASCII, `0x20` (space) to `0x7E` (`~`).
    private static func isWellFormedALPN(_ alpn: String) -> Bool {
        guard (1...maximumALPNBytes).contains(alpn.utf8.count) else { return false }
        // R2: bounded by the guard above, at most 255 bytes.
        return alpn.utf8.allSatisfy { (0x20...0x7E).contains($0) }
    }

    /// 1 to ``maximumHeartbeatBytes`` bytes, the first of them not `{`.
    private static func isWellFormedHeartbeat(_ heartbeat: Data) -> Bool {
        guard (1...maximumHeartbeatBytes).contains(heartbeat.count), let first = heartbeat.first else {
            return false
        }
        return first != UInt8(ascii: "{")
    }

    // MARK: QR scheme

    /// A lowercase RFC 3986 scheme: a letter, then letters, digits, `+`, `-` or `.`.
    private static func isWellFormedURLScheme(_ scheme: String) -> Bool {
        guard let first = scheme.utf8.first, isLowercaseLetter(first) else { return false }
        let punctuation: Set<UInt8> = [UInt8(ascii: "+"), UInt8(ascii: "-"), UInt8(ascii: ".")]
        // R2: bounded by the scheme the host wrote.
        return scheme.utf8.allSatisfy { isLowercaseLetter($0) || isDigit($0) || punctuation.contains($0) }
    }

    // MARK: Keychain

    /// Keychain: every name non-empty, the three services distinct, and the four identity accounts
    /// distinct. The two seal-key accounts may match: they live under distinct services.
    ///
    /// - Parameter keychain: The installation's keychain rows.
    /// - Returns: Empty names (services, then identity accounts, then seal-key accounts), then
    ///   duplicate services, then duplicate identity accounts.
    private static func keychainViolations(_ keychain: Keychain) -> [Violation] {
        let names = keychain.serviceFields + keychain.identityAccountFields + keychain.sealKeyAccountFields
        var violations = names
            .filter { $0.value.isEmpty }
            .map { Violation.malformedKeychainName(field: $0.field) }
        violations += duplicatePairs(keychain.serviceFields, Violation.duplicateKeychainName(field:otherField:))
        violations += duplicatePairs(keychain.identityAccountFields, Violation.duplicateKeychainName(field:otherField:))
        return violations
    }

    // MARK: Storage

    /// Storage: every name a single path component, and the three names inside the directory distinct
    /// ignoring case — a Mac's default file system ignores it, so names that differ only in case are
    /// one file there.
    ///
    /// - Parameter storage: The installation's storage names.
    /// - Returns: Malformed names in declaration order, then duplicate names.
    private static func storageViolations(_ storage: Storage) -> [Violation] {
        var violations = ([storage.directoryField] + storage.entryFields)
            .filter { !isSinglePathComponent($0.value) }
            .map { Violation.malformedPathComponent(field: $0.field) }
        let caseFolded = storage.entryFields.map { (field: $0.field, value: $0.value.lowercased()) }
        violations += duplicatePairs(caseFolded, Violation.duplicateFileName(field:otherField:))
        return violations
    }

    /// One path component: not empty, not `.` or `..`, and holding no `/`, `:` or NUL. A NUL would end
    /// the path early in every file-system call, which turns two names into one.
    private static func isSinglePathComponent(_ name: String) -> Bool {
        guard !name.isEmpty, name != ".", name != ".." else { return false }
        let separators: Set<UInt8> = [UInt8(ascii: "/"), UInt8(ascii: ":"), 0]
        // R2: bounded by the name the host wrote.
        return !name.utf8.contains { separators.contains($0) }
    }

    // MARK: Vocabulary

    /// The vocabulary: every token well-formed, the tokens of each group distinct, every token a rule
    /// names known, and every summary title well-formed.
    ///
    /// - Parameter vocabulary: The family's vocabulary.
    /// - Returns: Malformed tokens, then duplicate tokens, then unknown tokens, then malformed summary
    ///   titles, each in declaration order.
    private static func vocabularyViolations(_ vocabulary: Vocabulary) -> [Violation] {
        // R2: forty-six token fields, a set's or list's members bounded by the tokens the host listed.
        var violations = vocabulary.tokenFields
            .filter { field in
                !field.tokens.allSatisfy { isWellFormedToken($0, maximumBytes: field.maximumBytes) }
            }
            .map { Violation.malformedToken(field: $0.field) }
        violations += duplicateTokenViolations(vocabulary)
        violations += unknownTokenViolations(vocabulary)
        // R2: four titles.
        violations += vocabulary.session.titleFields
            .filter { !isWellFormedSummaryTitle($0.value) }
            .map { Violation.malformedSummaryTitle(field: $0.field) }
        return violations
    }

    /// Tokens repeated within a group: the three session payload tokens, the capability tokens, the
    /// four record kinds, the four routed types, the thirty mesh messages, and the session and mesh
    /// messages together, which the coordinator and the mesh manager dispatch on one after the other.
    /// Other groups may share a token, as a record kind may spell the payload token of the message
    /// that carries its record.
    ///
    /// - Parameter vocabulary: The family's vocabulary.
    /// - Returns: Each group's duplicate pairs, in that order; a session token a mesh message repeats
    ///   is named first.
    private static func duplicateTokenViolations(_ vocabulary: Vocabulary) -> [Violation] {
        let duplicate = Violation.duplicateToken(field:otherField:)
        var violations = duplicatePairs(vocabulary.session.payloadTypeFields, duplicate)
        violations += duplicatePairs(vocabulary.capabilities.knownFields, duplicate)
        violations += duplicatePairs(vocabulary.membershipRecordKinds.fields, duplicate)
        violations += duplicatePairs(vocabulary.routedTypes.fields, duplicate)
        violations += duplicatePairs(vocabulary.mesh.fields, duplicate)
        // R2: three session tokens by thirty mesh messages.
        for session in vocabulary.session.payloadTypeFields {
            for mesh in vocabulary.mesh.fields where mesh.value == session.value {
                violations.append(duplicate(session.field, mesh.field))
            }
        }
        return violations
    }

    /// Tokens a rule names that the vocabulary does not know: each session payload token, the sealing
    /// set and each mesh message against `payloads.known`, `wire2` and the legacy assumption against
    /// `capabilities.known`.
    ///
    /// - Parameter vocabulary: The family's vocabulary.
    /// - Returns: The unknown session tokens in declaration order, then the sealing set, `wire2` and
    ///   the legacy assumption, each named once, then the unknown mesh messages in declaration order.
    private static func unknownTokenViolations(_ vocabulary: Vocabulary) -> [Violation] {
        let payloads = vocabulary.payloads
        let capabilities = vocabulary.capabilities
        let knownCapabilities = Set(capabilities.known)
        // R2: three session tokens; the set operations below are bounded by the tokens the host listed.
        var violations = vocabulary.session.payloadTypeFields
            .filter { !payloads.known.contains($0.value) }
            .map { Violation.unknownToken(field: $0.field) }
        if !payloads.sealingRequired.isSubset(of: payloads.known) {
            violations.append(.unknownToken(field: PayloadRules.sealingRequiredField))
        }
        if !knownCapabilities.contains(capabilities.wire2) {
            violations.append(.unknownToken(field: Capabilities.wire2Field))
        }
        if !knownCapabilities.isSuperset(of: capabilities.assumedForLegacyPeers) {
            violations.append(.unknownToken(field: Capabilities.assumedForLegacyPeersField))
        }
        // R2: thirty mesh messages.
        violations += vocabulary.mesh.fields
            .filter { !payloads.known.contains($0.value) }
            .map { Violation.unknownToken(field: $0.field) }
        return violations
    }

    /// 1 to `maximumBytes` bytes, each from `0x21` (`!`) to `0x7E` (`~`): printable ASCII with no space,
    /// the byte rule labels follow.
    private static func isWellFormedToken(_ token: String, maximumBytes: Int) -> Bool {
        guard (1...maximumBytes).contains(token.utf8.count) else { return false }
        // R2: bounded by the guard above, at most `maximumBytes` bytes.
        return token.utf8.allSatisfy { (0x21...0x7E).contains($0) }
    }

    /// 1 to ``maximumSummaryTitleCharacters`` characters, counted as the receiver's decode counts them:
    /// by `Character`, so a letter and its combining mark are one.
    private static func isWellFormedSummaryTitle(_ title: String) -> Bool {
        (1...maximumSummaryTitleCharacters).contains(title.count)
    }

    // MARK: Presentation strings

    /// The radios' presentation strings: both instance-name prefixes and the certificates' common name
    /// well-formed.
    ///
    /// - Parameter radios: The family's radios.
    /// - Returns: The malformed prefixes, mesh then presence, then the common name.
    private static func presentationViolations(_ radios: Radios) -> [Violation] {
        // R2: two prefixes.
        var violations = radios.instanceNamePrefixFields
            .filter { !isWellFormedInstanceNamePrefix($0.value, room: $0.room) }
            .map { Violation.malformedInstanceNamePrefix(field: $0.field) }
        if !isWellFormedCommonName(radios.tlsCommonName) {
            violations.append(.malformedCommonName)
        }
        return violations
    }

    /// 1 to `room` bytes of `[a-z0-9-]`: lowercase, because a display layer lowercases a name before it
    /// compares it with the mesh prefix, and within the room a 63-byte DNS-SD instance name leaves
    /// before the hex that follows.
    private static func isWellFormedInstanceNamePrefix(_ prefix: String, room: Int) -> Bool {
        guard (1...room).contains(prefix.utf8.count) else { return false }
        let hyphen = UInt8(ascii: "-")
        // R2: bounded by the guard above, at most `room` bytes.
        return prefix.utf8.allSatisfy { isLowercaseLetter($0) || isDigit($0) || $0 == hyphen }
    }

    /// 1 to ``maximumCommonNameBytes`` bytes of printable ASCII, `0x20` (space) to `0x7E` (`~`).
    private static func isWellFormedCommonName(_ name: String) -> Bool {
        guard (1...maximumCommonNameBytes).contains(name.utf8.count) else { return false }
        // R2: bounded by the guard above, at most 64 bytes.
        return name.utf8.allSatisfy { (0x20...0x7E).contains($0) }
    }

    // MARK: Peer names

    /// The peer-name policy: the cap at most ``maximumPeerNameLength`` characters and at least the
    /// longer of a key fingerprint's ``peerNameFingerprintLength`` and the family's mesh instance-name
    /// prefix, and the floor not empty and byte for byte what ProximityKit's sanitizer makes of it
    /// under the cap, which also keeps it no longer than the cap.
    ///
    /// The cap's lower bound is the one rule judged across the family and the installation:
    /// `PeerNameDisplay` cuts a name to the cap before it looks for a fingerprint filed as a name or a
    /// mesh instance name, so a cap shorter than either would cut one to a name it shows as a person's.
    /// The floor's rule is the one here that runs code outside this folder: the floor is judged by the
    /// sanitizer every peer's name passes through (`ProximityDisplayName.sanitized(_:maxLength:)`),
    /// because judging it by any copy of that sanitizer would judge it by a rule that can drift from
    /// the one applied.
    ///
    /// - Parameters:
    ///   - peerNames: The installation's peer-name policy.
    ///   - meshInstanceNamePrefix: The family's mesh instance-name prefix, which a name cut to the cap
    ///     must still hold whole.
    /// - Returns: The malformed cap, then the malformed floor.
    private static func peerNameViolations(_ peerNames: PeerNames, meshInstanceNamePrefix: String) -> [Violation] {
        var violations: [Violation] = []
        // R2: the prefix's count is bounded by the prefix the host wrote. Two comparisons, not a
        // range: a prefix longer than the upper bound would make a range's bounds cross and trap.
        let shortest = max(peerNameFingerprintLength, meshInstanceNamePrefix.count)
        if peerNames.maxLength < shortest || peerNames.maxLength > maximumPeerNameLength {
            violations.append(.malformedPeerNames(field: PeerNames.maxLengthField))
        }
        // R2: the sanitizer and the comparison are bounded by the floor the host wrote; under a cap
        // below one the sanitizer keeps nothing, so no floor passes.
        let sanitized = ProximityDisplayName.sanitized(peerNames.floor, maxLength: peerNames.maxLength)
        if peerNames.floor.isEmpty || !sanitized.utf8.elementsEqual(peerNames.floor.utf8) {
            violations.append(.malformedPeerNames(field: PeerNames.floorField))
        }
        return violations
    }

    // MARK: Shared

    /// One violation per unordered pair of equal values, the earlier field first.
    ///
    /// - Parameters:
    ///   - named: Fields and their values, in declaration order (at most thirty, or the capability
    ///     tokens the host listed).
    ///   - violation: Builds the violation from the earlier and the later field.
    /// - Returns: The violations, in pair order.
    private static func duplicatePairs(
        _ named: [(field: String, value: String)],
        _ violation: (String, String) -> Violation
    ) -> [Violation] {
        var violations: [Violation] = []
        // R2: every unordered pair once, over at most thirty values (435 comparisons) or the
        // capability tokens the host listed.
        for (index, first) in named.enumerated() {
            for second in named.dropFirst(index + 1) where first.value == second.value {
                violations.append(violation(first.field, second.field))
            }
        }
        return violations
    }

    /// Whether a byte is an ASCII lowercase letter.
    private static func isLowercaseLetter(_ byte: UInt8) -> Bool {
        (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte)
    }

    /// Whether a byte is an ASCII digit.
    private static func isDigit(_ byte: UInt8) -> Bool {
        (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
    }
}

// MARK: - Collisions

nonisolated extension ProximityNamespace {

    /// Where this namespace's family overlaps another's: labels that are equal or byte-prefix related,
    /// and equal service types, ALPNs, heartbeat or QR scheme.
    ///
    /// A host proves in its own tests that it overlaps no other app by asserting this is empty against a
    /// literal copy of that app's values. Two apps that share a family on purpose compare only
    /// ``installationCollisions(with:)``. Service types and ALPNs are compared across radios, because a
    /// browser sees every type that is advertised; the QR scheme is compared ignoring case, as the QR
    /// parser compares it.
    ///
    /// - Parameter other: The namespace to compare against.
    /// - Returns: Every overlap, `field` in this namespace and `otherField` in `other`: labels in
    ///   ``labelRows`` order, then service types, ALPNs, the heartbeat and the scheme.
    public func familyCollisions(with other: ProximityNamespace) -> [Collision] {
        let radios = family.radios
        let otherRadios = other.family.radios
        let scheme = (field: "family.verifyQR.urlScheme", value: family.verifyQR.urlScheme.lowercased())
        let otherScheme = (field: scheme.field, value: other.family.verifyQR.urlScheme.lowercased())
        var collisions = Self.labelCollisions(labelRows, other.labelRows)
        collisions += Self.equalPairs(radios.serviceTypeFields, otherRadios.serviceTypeFields)
        collisions += Self.equalPairs(radios.alpnFields, otherRadios.alpnFields)
        collisions += Self.equalPairs([radios.heartbeatField], [otherRadios.heartbeatField])
        collisions += Self.equalPairs([scheme], [otherScheme])
        return collisions
    }

    /// Where this namespace's installation overlaps another's: equal keychain services, an equal
    /// storage directory name ignoring case, or an equal log subsystem.
    ///
    /// Two apps that share a family on purpose, such as an app and its companion, assert this is empty:
    /// it is what keeps them from sharing a key, a folder or a log stream on one device.
    ///
    /// - Parameter other: The namespace to compare against.
    /// - Returns: Every overlap, `field` in this namespace and `otherField` in `other`: keychain services,
    ///   then the directory, then the log subsystem.
    public func installationCollisions(with other: ProximityNamespace) -> [Collision] {
        let directory = installation.storage.directoryField
        let otherDirectory = other.installation.storage.directoryField
        let subsystem = (field: "installation.logSubsystem", value: installation.logSubsystem)
        let otherSubsystem = (field: subsystem.field, value: other.installation.logSubsystem)
        var collisions = Self.equalPairs(
            installation.keychain.serviceFields, other.installation.keychain.serviceFields
        )
        collisions += Self.equalPairs(
            [(field: directory.field, value: directory.value.lowercased())],
            [(field: otherDirectory.field, value: otherDirectory.value.lowercased())]
        )
        collisions += Self.equalPairs([subsystem], [otherSubsystem])
        return collisions
    }

    /// Every pair of labels, one from each list, that are equal or byte-prefix related.
    ///
    /// - Parameters:
    ///   - mine: This namespace's label rows.
    ///   - theirs: The other namespace's label rows.
    /// - Returns: The overlaps, in `mine`-then-`theirs` order.
    private static func labelCollisions(_ mine: [LabelRow], _ theirs: [LabelRow]) -> [Collision] {
        var collisions: [Collision] = []
        // R2: bounded by the two label lists, at most 39 × 39 comparisons.
        for own in mine {
            for other in theirs {
                guard let kind = overlap(own.purpose.data, other.purpose.data) else { continue }
                collisions.append(Collision(field: own.field, otherField: other.field, kind: kind))
            }
        }
        return collisions
    }

    /// How two labels overlap: equal, one a byte prefix of the other, or not at all.
    private static func overlap(_ first: Data, _ second: Data) -> Collision.Kind? {
        guard first != second else { return .equal }
        guard first.starts(with: second) || second.starts(with: first) else { return nil }
        return .prefix
    }

    /// Every pair of equal values, one from each list.
    ///
    /// - Parameters:
    ///   - mine: This namespace's fields and values.
    ///   - theirs: The other namespace's fields and values.
    /// - Returns: An `.equal` collision per equal pair, in `mine`-then-`theirs` order.
    private static func equalPairs<Value: Equatable>(
        _ mine: [(field: String, value: Value)],
        _ theirs: [(field: String, value: Value)]
    ) -> [Collision] {
        var collisions: [Collision] = []
        // R2: bounded by the two fixed lists, at most three values each.
        for own in mine {
            for other in theirs where own.value == other.value {
                collisions.append(Collision(field: own.field, otherField: other.field, kind: .equal))
            }
        }
        return collisions
    }
}

// MARK: - Field lists

nonisolated extension ProximityNamespace.Radios {

    /// The three service types with their paths from the namespace root, in declaration order.
    var serviceTypeFields: [(field: String, value: String)] {
        [
            (field: "family.radios.mesh.serviceType", value: mesh.serviceType),
            (field: "family.radios.presence.serviceType", value: presence.serviceType),
            (field: "family.radios.recipeShare.serviceType", value: recipeShare.serviceType)
        ]
    }

    /// The three ALPNs with their paths from the namespace root, in declaration order.
    var alpnFields: [(field: String, value: String)] {
        [
            (field: "family.radios.mesh.alpn", value: mesh.alpn),
            (field: "family.radios.presence.alpn", value: presence.alpn),
            (field: "family.radios.recipeShare.alpn", value: recipeShare.alpn)
        ]
    }

    /// The mesh heartbeat with its path from the namespace root.
    var heartbeatField: (field: String, value: Data) {
        (field: "family.radios.meshHeartbeat", value: meshHeartbeat)
    }

    /// The two instance-name prefixes with their paths from the namespace root, in declaration order,
    /// each with the room a 63-byte DNS-SD instance name leaves it before the hex that follows.
    var instanceNamePrefixFields: [(field: String, value: String, room: Int)] {
        let longest = ProximityNamespace.maximumInstanceNameBytes
        return [
            (field: "family.radios.meshInstanceNamePrefix", value: meshInstanceNamePrefix,
             room: longest - ProximityNamespace.meshInstanceNameTokenLength),
            (field: "family.radios.presenceInstanceNamePrefix", value: presenceInstanceNamePrefix,
             room: longest - ProximityNamespace.presenceInstanceNameTokenLength)
        ]
    }
}

nonisolated extension ProximityNamespace.Vocabulary {

    /// The forty-six token fields with their paths from the namespace root, in declaration order:
    /// each with its token or, for a set or list, every member, and the most bytes its group's
    /// receivers accept. A mesh message is a payload token that the mesh also signs as its frame's
    /// summary title, so it takes the shorter of the two bounds; a well-formed token is printable
    /// ASCII, one byte a character, so the title's character bound applies to it in bytes.
    var tokenFields: [(field: String, tokens: [String], maximumBytes: Int)] {
        let payloadBytes = ProximityNamespace.maximumPayloadTokenBytes
        let capabilityBytes = ProximityNamespace.maximumCapabilityTokenBytes
        let routedBytes = ProximityNamespace.maximumRoutedTypeTokenBytes
        let meshBytes = min(payloadBytes, ProximityNamespace.maximumSummaryTitleCharacters)
        var fields = Self.singleTokenFields(session.payloadTypeFields, maximumBytes: payloadBytes)
        fields.append((field: ProximityNamespace.PayloadRules.knownField,
                       tokens: Array(payloads.known), maximumBytes: payloadBytes))
        fields.append((field: ProximityNamespace.PayloadRules.sealingRequiredField,
                       tokens: Array(payloads.sealingRequired), maximumBytes: payloadBytes))
        fields.append((field: ProximityNamespace.Capabilities.knownField,
                       tokens: capabilities.known, maximumBytes: capabilityBytes))
        fields.append((field: ProximityNamespace.Capabilities.wire2Field,
                       tokens: [capabilities.wire2], maximumBytes: capabilityBytes))
        fields.append((field: ProximityNamespace.Capabilities.assumedForLegacyPeersField,
                       tokens: capabilities.assumedForLegacyPeers, maximumBytes: capabilityBytes))
        fields += Self.singleTokenFields(membershipRecordKinds.fields, maximumBytes: payloadBytes)
        fields += Self.singleTokenFields(routedTypes.fields, maximumBytes: routedBytes)
        fields += Self.singleTokenFields(mesh.fields, maximumBytes: meshBytes)
        return fields
    }

    /// One token field per single token in `named`, each accepting at most `maximumBytes`.
    private static func singleTokenFields(
        _ named: [(field: String, value: String)],
        maximumBytes: Int
    ) -> [(field: String, tokens: [String], maximumBytes: Int)] {
        // R2: at most thirty fields.
        named.map { (field: $0.field, tokens: [$0.value], maximumBytes: maximumBytes) }
    }
}

nonisolated extension ProximityNamespace.SessionMessages {

    /// The three session payload tokens with their paths from the namespace root, in declaration order.
    var payloadTypeFields: [(field: String, value: String)] {
        [
            (field: "family.vocabulary.session.identityIntroduction.payloadType",
             value: identityIntroduction.payloadType),
            (field: "family.vocabulary.session.identityAcknowledge.payloadType",
             value: identityAcknowledge.payloadType),
            (field: "family.vocabulary.session.heartbeat.payloadType", value: heartbeat.payloadType)
        ]
    }

    /// The four summary titles with their paths from the namespace root, in declaration order.
    var titleFields: [(field: String, value: String)] {
        [
            (field: "family.vocabulary.session.identityIntroduction.summaryTitle",
             value: identityIntroduction.summaryTitle),
            (field: "family.vocabulary.session.identityAcknowledge.summaryTitle",
             value: identityAcknowledge.summaryTitle),
            (field: "family.vocabulary.session.heartbeat.pingTitle", value: heartbeat.pingTitle),
            (field: "family.vocabulary.session.heartbeat.replyTitle", value: heartbeat.replyTitle)
        ]
    }
}

nonisolated extension ProximityNamespace.PayloadRules {

    /// The known set's path from the namespace root.
    static let knownField = "family.vocabulary.payloads.known"

    /// The sealing set's path from the namespace root.
    static let sealingRequiredField = "family.vocabulary.payloads.sealingRequired"
}

nonisolated extension ProximityNamespace.Capabilities {

    /// The known list's path from the namespace root. A member's path adds its index in brackets.
    static let knownField = "family.vocabulary.capabilities.known"

    /// The wire2 token's path from the namespace root.
    static let wire2Field = "family.vocabulary.capabilities.wire2"

    /// The legacy assumption's path from the namespace root.
    static let assumedForLegacyPeersField = "family.vocabulary.capabilities.assumedForLegacyPeers"

    /// Each known token with its path from the namespace root, `known[0]` first.
    var knownFields: [(field: String, value: String)] {
        // R2: bounded by the tokens the host listed.
        known.enumerated().map { (field: Self.knownField + "[\($0.offset)]", value: $0.element) }
    }
}

nonisolated extension ProximityNamespace.MembershipRecordKinds {

    /// The four record kinds with their paths from the namespace root, in declaration order.
    var fields: [(field: String, value: String)] {
        [
            (field: "family.vocabulary.membershipRecordKinds.admission", value: admission),
            (field: "family.vocabulary.membershipRecordKinds.departure", value: departure),
            (field: "family.vocabulary.membershipRecordKinds.removal", value: removal),
            (field: "family.vocabulary.membershipRecordKinds.termination", value: termination)
        ]
    }
}

nonisolated extension ProximityNamespace.RoutedTypes {

    /// The four routed-type tokens with their paths from the namespace root, in declaration order.
    var fields: [(field: String, value: String)] {
        [
            (field: "family.vocabulary.routedTypes.photo", value: photo),
            (field: "family.vocabulary.routedTypes.tempMessage", value: tempMessage),
            (field: "family.vocabulary.routedTypes.heart", value: heart),
            (field: "family.vocabulary.routedTypes.control", value: control)
        ]
    }
}

nonisolated extension ProximityNamespace.MeshMessages {

    /// The thirty mesh messages with their paths from the namespace root, in declaration order.
    var fields: [(field: String, value: String)] {
        let path = "family.vocabulary.mesh."
        return [
            (field: path + "descriptor", value: descriptor),
            (field: path + "admissionGrant", value: admissionGrant),
            (field: path + "admissionRequest", value: admissionRequest),
            (field: path + "stateChange", value: stateChange),
            (field: path + "friendVouchList", value: friendVouchList),
            (field: path + "removalProposal", value: removalProposal),
            (field: path + "removalSecond", value: removalSecond),
            (field: path + "memberDeparture", value: memberDeparture),
            (field: path + "memberAdmission", value: memberAdmission),
            (field: path + "memberRemoval", value: memberRemoval),
            (field: path + "terminated", value: terminated),
            (field: path + "inventoryDigest", value: inventoryDigest),
            (field: path + "epochHeads", value: epochHeads),
            (field: path + "keyAgreement", value: keyAgreement),
            (field: path + "removalProposalSigned", value: removalProposalSigned),
            (field: path + "removalVote", value: removalVote),
            (field: path + "routedManifest", value: routedManifest),
            (field: path + "routedChunk", value: routedChunk),
            (field: path + "custodyReceipt", value: custodyReceipt),
            (field: path + "recipientReceipt", value: recipientReceipt),
            (field: path + "routedInventoryDigest", value: routedInventoryDigest),
            (field: path + "routedDrainAnswer", value: routedDrainAnswer),
            (field: path + "keyRotation", value: keyRotation),
            (field: path + "keyAck", value: keyAck),
            (field: path + "rotationSync", value: rotationSync),
            (field: path + "encryptedMetadata", value: encryptedMetadata),
            (field: path + "coordinatorBeacon", value: coordinatorBeacon),
            (field: path + "verifyChallenge", value: verifyChallenge),
            (field: path + "verifyResponse", value: verifyResponse),
            (field: path + "sessionGoodbye", value: sessionGoodbye)
        ]
    }
}

nonisolated extension ProximityNamespace.Keychain {

    /// The three services with their paths from the namespace root, in declaration order.
    var serviceFields: [(field: String, value: String)] {
        [
            (field: "installation.keychain.identity.service", value: identity.service),
            (field: "installation.keychain.meshSessionSealKey.service", value: meshSessionSealKey.service),
            (field: "installation.keychain.meshRoutedSealKey.service", value: meshRoutedSealKey.service)
        ]
    }

    /// The four identity accounts with their paths from the namespace root, in declaration order.
    var identityAccountFields: [(field: String, value: String)] {
        [
            (field: "installation.keychain.identity.signingPrivateKey", value: identity.signingPrivateKey),
            (field: "installation.keychain.identity.keyAgreementPrivateKey", value: identity.keyAgreementPrivateKey),
            (field: "installation.keychain.identity.signingPublicKeyCache", value: identity.signingPublicKeyCache),
            (field: "installation.keychain.identity.keyAgreementPublicKeyCache",
             value: identity.keyAgreementPublicKeyCache)
        ]
    }

    /// The two seal-key accounts with their paths from the namespace root, in declaration order.
    var sealKeyAccountFields: [(field: String, value: String)] {
        [
            (field: "installation.keychain.meshSessionSealKey.account", value: meshSessionSealKey.account),
            (field: "installation.keychain.meshRoutedSealKey.account", value: meshRoutedSealKey.account)
        ]
    }
}

nonisolated extension ProximityNamespace.Storage {

    /// The directory name with its path from the namespace root.
    var directoryField: (field: String, value: String) {
        (field: "installation.storage.directoryName", value: directoryName)
    }

    /// The three names inside the directory with their paths from the namespace root, in declaration
    /// order.
    var entryFields: [(field: String, value: String)] {
        [
            (field: "installation.storage.meshSessionContextFileName", value: meshSessionContextFileName),
            (field: "installation.storage.meshRoutedIndexFileName", value: meshRoutedIndexFileName),
            (field: "installation.storage.meshRoutedChunkDirectoryName", value: meshRoutedChunkDirectoryName)
        ]
    }
}

nonisolated extension ProximityNamespace.PeerNames {

    /// The cap's path from the namespace root.
    static let maxLengthField = "installation.peerNames.maxLength"

    /// The floor's path from the namespace root.
    static let floorField = "installation.peerNames.floor"
}
