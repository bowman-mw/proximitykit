// SwiftSourceLexer.swift
//
// The source walls' small Swift lexer, which reads a file's code apart from its comments and string
// literals as the compiler does. A twin (ProximityKit plan step A1.1): the same file at Tests/FernletTests
// and FernletKit/Tests/ProximityKitTests/TestSupport, held identical but for its imports by
// CIGateSelectorBoundaryTests.everyTwinMatchesItsOriginal(), because ProximityKit's namespace, platform
// and keychain-door walls, its tests' hygiene, its tree walls and its source walls' identity rule
// (ProximityNamespaceBoundaryTests, ProximityPlatformNeutralityTests, ProximityKeychainDoorTests and,
// since ProximityKit plan step A1.1.13, PackageTestHygieneTests, since A1.1.14, PackageTestTreeWallTests
// and, since A1.1.17, ProximitySourceWallTests, in ProximityKit's package tests) read ProximityKit's
// sources and tests through it and Fernlet's own source walls read theirs (the key-custody,
// store-isolation, photo-directory, audit-bridge and continuation task-host walls, the platform wall's
// presence door and the feature golden's recipe-copy scan), and a test target cannot import another.
// Each target holds its copy to the same fixtures: the namespace wall's lexer cell in the package,
// `SwiftSourceLexerTests` in FernletTests.

/// A small Swift lexer for the source walls. It tells code from comments and string literals the way
/// the compiler does, so a wall can read code without the prose about it, and literals without the
/// code around them.
///
/// It knows line comments, nested block comments, every string-literal form ProximityKit and the test
/// tree write (single-line and multi-line, raw (`#"…"#`, any number of `#`), escapes, and
/// interpolations, which may hold literals of their own), and regex literals, whose bodies would
/// otherwise read as code: a `//`, a `/*` or a quote inside one would open a comment or a literal and
/// blank or misread the code after it. An extended regex literal (`#/…/#`, any number of `#`, line
/// breaks allowed) is read wherever it stands. A bare one (`/…/`) is read where Swift reads one: a `/`
/// after no operand that does not start the operator `/` or `/=` with nothing bound after it (`a / b`,
/// `x /= y`, the only operators valid Swift starts with a `/`), its body closing at the first unescaped
/// `/` on its line, neither ending in a space or a tab nor followed by a comment's opening. The one bare
/// form Swift reads that it reads as operators is a body opening with `=` and a blank where an
/// expression starts (`/= x/`), which neither tree writes. It reads UTF-8 bytes, because every delimiter
/// it looks for is ASCII and no byte of a multi-byte UTF-8 sequence is.
enum SwiftSourceLexer {

    /// One outermost string literal.
    struct Literal: Equatable, Sendable {
        /// The 1-based line its opening delimiter is on.
        let line: Int
        /// Its text between the delimiters, exactly as written, escapes and interpolations included.
        let text: String
    }

    /// A file, lexed.
    struct Lexed: Sendable {
        /// The source with every comment removed and every literal emptied, line breaks kept so line
        /// numbers still match the file. A literal reads `""`, with its interpolations' code, each in
        /// its parentheses, between the two quotes; a regex literal reads `""` too, its body in no
        /// literal.
        let code: String
        /// Every outermost literal, in source order. A literal inside an interpolation is part of the
        /// text of the literal that holds it.
        let literals: [Literal]
    }

    /// Lexes Swift source.
    ///
    /// - Parameter source: A Swift file's text.
    /// - Returns: Its code and its literals.
    static func lex(_ source: String) -> Lexed {
        var lexer = SwiftByteLexer(bytes: Array(source.utf8))
        lexer.run()
        return Lexed(code: String(decoding: lexer.code, as: UTF8.self), literals: lexer.literals)
    }
}

/// `SwiftSourceLexer`'s state, one byte at a time.
private struct SwiftByteLexer {

    /// A string literal still open; the innermost is last.
    struct Open {
        /// The `#` count of its delimiters (0 for an ordinary literal).
        let hashes: Int
        /// Whether its delimiters are `"""`.
        let multiline: Bool
        /// The index of its first byte of text.
        let textStart: Int
        /// The line its opening delimiter is on.
        let line: Int
        /// The parenthesis depth of the interpolation open inside it, or nil while reading its text.
        var interpolation: Int?
    }

    /// The bytes after which a `/` follows no operand (Swift's left-unbound test): white space, `(`,
    /// `[`, `{`, `,`, `;` and `:`.
    private static let operandOpeners = Array(" \t\r\n([{,;:".utf8)

    /// The bytes before which an operator binds to nothing (Swift's right-unbound test): white space,
    /// `)`, `]`, `}`, `,`, `;` and `:`.
    private static let operandClosers = Array(" \t\r\n)]},;:".utf8)

    /// The ASCII operator characters, which run on from a `/` into one operator.
    private static let operatorCharacters = Array("/=-+!*%<>&|^~?".utf8)

    let bytes: [UInt8]
    var index = 0
    var line = 1
    var code: [UInt8] = []
    var literals: [SwiftSourceLexer.Literal] = []
    var open: [Open] = []

    init(bytes: [UInt8]) {
        self.bytes = bytes
    }

    /// Lexes every byte.
    mutating func run() {
        // R2: every step consumes at least one byte of a finite array.
        while index < bytes.count {
            if let innermost = open.last, innermost.interpolation == nil {
                stepInLiteral(innermost)
            } else {
                stepInCode()
            }
        }
    }

    /// One step through code: top-level code, or an interpolation's.
    private mutating func stepInCode() {
        let byte = bytes[index]
        if byte == .slash, at(index + 1) == .slash { return skipLineComment() }
        if byte == .slash, at(index + 1) == .star { return skipBlockComment() }
        if byte == .hash || byte == .quote, let hashes = literalOpening() { return openLiteral(hashes: hashes) }
        if byte == .hash, let end = extendedRegexEnd() { return skipRegex(to: end) }
        if byte == .slash, let end = bareRegexEnd() { return skipRegex(to: end) }
        if byte == .newline { line += 1 }
        if byte == .leftParenthesis || byte == .rightParenthesis { trackInterpolation(byte) }
        code.append(byte)
        index += 1
    }

    /// One step through the text of the innermost open literal.
    private mutating func stepInLiteral(_ innermost: Open) {
        let byte = bytes[index]
        if byte == .backslash, hashesFollow(index + 1, count: innermost.hashes) {
            return escape(at: index + 1 + innermost.hashes)
        }
        if byte == .quote, let length = closingLength(of: innermost) { return close(innermost, length: length) }
        if byte == .newline {
            line += 1
            code.append(.newline)
        }
        index += 1
    }

    /// The byte at `position`, or nil past the end.
    private func at(_ position: Int) -> UInt8? {
        position < bytes.count ? bytes[position] : nil
    }

    /// Whether `count` `#` bytes start at `position`.
    private func hashesFollow(_ position: Int, count: Int) -> Bool {
        guard position + count <= bytes.count else { return false }
        return bytes[position..<position + count].allSatisfy { $0 == .hash }
    }

    /// The `#` count of a literal opening at `index`, or nil when no literal opens there.
    private func literalOpening() -> Int? {
        var position = index
        // R2: bounded by the remaining bytes.
        while at(position) == .hash { position += 1 }
        return at(position) == .quote ? position - index : nil
    }

    /// Opens a literal whose delimiter starts at `index` with `hashes` `#` bytes.
    private mutating func openLiteral(hashes: Int) {
        let quote = index + hashes
        let multiline = at(quote + 1) == .quote && at(quote + 2) == .quote
        let textStart = quote + (multiline ? 3 : 1)
        open.append(Open(hashes: hashes, multiline: multiline, textStart: textStart, line: line))
        code.append(.quote)
        index = textStart
    }

    /// The length of the closing delimiter of `literal` at `index`, or nil when it does not close here.
    private func closingLength(of literal: Open) -> Int? {
        let quotes = literal.multiline ? 3 : 1
        guard (0..<quotes).allSatisfy({ at(index + $0) == .quote }) else { return nil }
        return hashesFollow(index + quotes, count: literal.hashes) ? quotes + literal.hashes : nil
    }

    /// Closes the innermost literal, recording it when it is outermost.
    private mutating func close(_ literal: Open, length: Int) {
        open.removeLast()
        if open.isEmpty {
            let text = String(decoding: bytes[literal.textStart..<index], as: UTF8.self)
            literals.append(SwiftSourceLexer.Literal(line: literal.line, text: text))
        }
        code.append(.quote)
        index += length
    }

    /// The index just past an extended regex literal opening at `index` (`#/…/#`, any number of `#`), or
    /// nil when none opens there or it never closes. Its body runs, line breaks included, to the first
    /// `/` followed by as many `#`; a backslash escapes the byte after it.
    private func extendedRegexEnd() -> Int? {
        var position = index
        // R2: bounded by the remaining bytes.
        while at(position) == .hash { position += 1 }
        guard at(position) == .slash else { return nil }
        let hashes = position - index
        position += 1
        // R2: bounded by the remaining bytes; each pass consumes at least one.
        while position < bytes.count {
            if bytes[position] == .backslash {
                position += 2
            } else if bytes[position] == .slash, hashesFollow(position + 1, count: hashes) {
                return position + 1 + hashes
            } else {
                position += 1
            }
        }
        return nil
    }

    /// The index just past a bare regex literal opening at `index` (`/…/`), or nil when the `/` is an
    /// operator. A `/` after no operand (``opensOperand()``) opens one unless it starts an operator bound
    /// to nothing after it (``startsAnUnboundOperator()``). Its body runs to the first unescaped `/` on
    /// its line, which neither ends the body in a space or a tab nor is followed by a comment's opening:
    /// Swift reads an operator or the comment then.
    private func bareRegexEnd() -> Int? {
        guard opensOperand(), !startsAnUnboundOperator() else { return nil }
        var position = index + 1
        var escaped = false
        // R2: bounded by the line's remaining bytes; each pass consumes at least one.
        while let byte = at(position), byte != .newline {
            if byte == .slash {
                let blank = !escaped && (bytes[position - 1] == .space || bytes[position - 1] == .tab)
                return blank || opensComment(at: position + 1) ? nil : position + 1
            }
            escaped = byte == .backslash
            if escaped, at(position + 1) == .newline { return nil }
            position += escaped ? 2 : 1
        }
        return nil
    }

    /// Whether the `/` at `index` follows no operand, as Swift reads it: it starts the source, or white
    /// space, `(`, `[`, `{`, `,`, `;`, `:` or a block comment's end precedes it.
    private func opensOperand() -> Bool {
        guard index > 0 else { return true }
        if Self.operandOpeners.contains(bytes[index - 1]) { return true }
        return bytes[index - 1] == .slash && index > 1 && bytes[index - 2] == .star
    }

    /// Whether the `/` at `index` starts the operator `/` or `/=` bound to nothing after it (white space,
    /// a closing bracket, `,`, `;`, `:`, a comment or the end), as in `a / b`, `x /= y` and
    /// `reduce(0, /)`: the only operators valid Swift starts with a `/`, which a regex literal never is
    /// there, while any other run of operator characters after no operand opens one.
    private func startsAnUnboundOperator() -> Bool {
        let end = operatorEnd()
        let named = end == index + 1 || (end == index + 2 && bytes[index + 1] == .equals)
        guard named, let next = at(end) else { return named }
        return Self.operandClosers.contains(next) || opensComment(at: end)
    }

    /// The index just past the operator characters that start at the `/` at `index`, stopping before a
    /// comment's opening: Swift binds an operator to what follows by the byte after them.
    private func operatorEnd() -> Int {
        var position = index + 1
        // R2: bounded by the remaining bytes.
        while let byte = at(position), Self.operatorCharacters.contains(byte), !opensComment(at: position) {
            position += 1
        }
        return position
    }

    /// Whether a comment opens at `position` (`//` or `/*`).
    private func opensComment(at position: Int) -> Bool {
        at(position) == .slash && (at(position + 1) == .slash || at(position + 1) == .star)
    }

    /// Skips a regex literal ending just before `end`, which reads `""` in the code, keeping its line
    /// breaks; its body is in no literal.
    private mutating func skipRegex(to end: Int) {
        code.append(.quote)
        // R2: bounded by `end`, within the bytes.
        while index < end {
            if bytes[index] == .newline {
                line += 1
                code.append(.newline)
            }
            index += 1
        }
        code.append(.quote)
    }

    /// Reads the escape whose escaped byte is at `position`: an interpolation opens on `(`.
    private mutating func escape(at position: Int) {
        if at(position) == .leftParenthesis {
            open[open.count - 1].interpolation = 1
            code.append(.leftParenthesis)
        } else if at(position) == .newline {
            line += 1
            code.append(.newline)
        }
        index = position + 1
    }

    /// Follows an interpolation's parentheses; the one that balances its `\(` returns to the text.
    private mutating func trackInterpolation(_ byte: UInt8) {
        guard let depth = open.last?.interpolation else { return }
        let next = byte == .leftParenthesis ? depth + 1 : depth - 1
        open[open.count - 1].interpolation = next == 0 ? nil : next
    }

    /// Skips a line comment, leaving its line break to the code.
    private mutating func skipLineComment() {
        // R2: bounded by the remaining bytes.
        while index < bytes.count, bytes[index] != .newline { index += 1 }
    }

    /// Skips a block comment and every block comment nested in it, keeping its line breaks.
    private mutating func skipBlockComment() {
        var depth = 0
        // R2: bounded by the remaining bytes; each pass consumes at least one.
        while index < bytes.count {
            if bytes[index] == .slash, at(index + 1) == .star {
                depth += 1
                index += 2
            } else if bytes[index] == .star, at(index + 1) == .slash {
                depth -= 1
                index += 2
                if depth == 0 { return }
            } else {
                if bytes[index] == .newline {
                    line += 1
                    code.append(.newline)
                }
                index += 1
            }
        }
    }
}

private extension UInt8 {
    static let tab: UInt8 = 0x09
    static let newline: UInt8 = 0x0A
    static let space: UInt8 = 0x20
    static let quote: UInt8 = 0x22
    static let hash: UInt8 = 0x23
    static let leftParenthesis: UInt8 = 0x28
    static let rightParenthesis: UInt8 = 0x29
    static let star: UInt8 = 0x2A
    static let slash: UInt8 = 0x2F
    static let equals: UInt8 = 0x3D
    static let backslash: UInt8 = 0x5C
}
