// ProximityNamespace+Soundness.swift
// ProximityKit/Namespace
//
// The rules a namespace is judged by: alone, once, when it is built (`soundness`), and against
// another app's namespace (`familyCollisions(with:)`, `installationCollisions(with:)`). Every loop runs
// over the namespace's fixed shape — at most 39 labels, three radios, three keychain services, four
// storage names — or over one value whose length a guard has already bounded, or a string the host
// wrote.

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

    /// Every soundness rule's verdict for one family and installation.
    ///
    /// Runs once, from ``init(family:installation:)``, in a fixed order — labels, radios and heartbeat,
    /// QR scheme, keychain, storage, log subsystem — so equal inputs always record equal verdicts.
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

    // MARK: Shared

    /// One violation per unordered pair of equal values, the earlier field first.
    ///
    /// - Parameters:
    ///   - named: Fields and their values, in declaration order (at most four).
    ///   - violation: Builds the violation from the earlier and the later field.
    /// - Returns: The violations, in pair order.
    private static func duplicatePairs(
        _ named: [(field: String, value: String)],
        _ violation: (String, String) -> Violation
    ) -> [Violation] {
        var violations: [Violation] = []
        // R2: every unordered pair once, over at most four values.
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
