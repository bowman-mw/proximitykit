// SwiftSourceLexer.swift
//
// The source walls' small Swift lexer, which reads a file's code apart from its comments and string
// literals as the compiler does. A twin (ProximityKit plan step A1.1): the same file at Tests/FernletTests
// and FernletKit/Tests/ProximityKitTests/TestSupport, held identical but for its imports by
// CIGateSelectorBoundaryTests.everyTwinMatchesItsOriginal() (this package's copy differs from those two
// in this header only, which since plan step A1.3 also names the readers copied here), because
// ProximityKit's namespace, platform and keychain-door walls, its tests' hygiene, its tree walls, its
// source walls' identity rule, and the continuation task-host wall and the feature golden's recipe-copy
// scan copied from Fernlet's tests
// (ProximityNamespaceBoundaryTests, ProximityPlatformNeutralityTests, ProximityKeychainDoorTests and,
// since ProximityKit plan step A1.1.13, PackageTestHygieneTests, since A1.1.14, PackageTestTreeWallTests,
// since A1.1.17, ProximitySourceWallTests and, since plan step A1.3, MeshContinuationTaskHostWallTests
// and FernletFeatureGoldenTests, in ProximityKit's package tests) read ProximityKit's sources and tests
// through it and Fernlet's own source walls read theirs (the key-custody, store-isolation,
// photo-directory, audit-bridge and continuation task-host walls, the platform wall's presence door and
// the feature golden's recipe-copy scan), and a test target cannot import another.
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
/// after no operand (white space, an opening bracket, `,`, `;`, `:`, a block comment's end, or, with no
/// blank, a keyword Swift reads an expression or a pattern after, as in `return/a/`), unless it starts
/// the operator `/` or `/=` with nothing bound after it (`a / b`, `x /= y`, `reduce(0, /)`) or names an
/// operator after `func` or `operator` on its line (`static func /(`, `infix operator /+/`), its body
/// closing at the first unescaped `/` on its line, which neither ends the body in a space or a tab nor
/// opens a comment with the byte after it. The valid Swift it is known to read otherwise, none of which
/// either tree writes: a bare body opening, where an expression starts, with `,`, `;`, `:`, `]` or `}`,
/// or with `=` and then a space or one of those (`/,x/`, `/= x/`), which it reads as the operator `/` or
/// `/=` and code; a bare regex right after a prefix operator (`~/a/`), or after `yield` in a `_read` or
/// `_modify` accessor, which it reads as code; and a use of a custom operator whose name starts with a
/// `/`, which Swift allows, spaced as an infix one (`a /^ b`) or, as a prefix `/`, before an unbalanced
/// `)` (`(/x)/2`), or the declaration of one whose name starts the line after its `func` or `operator`,
/// which it reads as a regex up to the next `/` on that line. It reads UTF-8 bytes, because every
/// delimiter it looks for is ASCII and no byte of a multi-byte UTF-8 sequence is.
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

    /// The keywords Swift reads an expression or a pattern after, so a `/` right after one, with no
    /// blank, follows no operand (`return/a/` is a regex literal, as `return /a/` is): each a reserved
    /// word, or `await`, which Swift 6 reads as the keyword there too. `try` counts with its `?` or `!`.
    private static let expressionKeywords: Set<String> = [
        "return", "throw", "try", "await", "in", "case", "where", "if", "guard", "while", "switch", "repeat",
        "catch"
    ]

    /// The keywords whose declaration a `/` after them names (`func /(`, `operator /+/`): an operator's
    /// name, never a regex literal.
    private static let declarationKeywords: Set<String> = ["func", "operator"]

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
    /// to nothing after it (``startsAnUnboundOperator()``) or names one being declared
    /// (``namesADeclaredOperator()``). Its body runs to the first unescaped `/` on its line, and Swift
    /// reads no regex literal when that `/` ends the body in a space or a tab or opens a comment with the
    /// byte after it (`/a//`, `/a/*`): an operator then, or the comment.
    private func bareRegexEnd() -> Int? {
        guard opensOperand(), !startsAnUnboundOperator(), !namesADeclaredOperator() else { return nil }
        var position = index + 1
        var escaped = false
        // R2: bounded by the line's remaining bytes; each pass consumes at least one.
        while let byte = at(position), byte != .newline {
            if byte == .slash {
                let blank = !escaped && (bytes[position - 1] == .space || bytes[position - 1] == .tab)
                return blank || opensComment(at: position) ? nil : position + 1
            }
            escaped = byte == .backslash
            if escaped, at(position + 1) == .newline { return nil }
            position += escaped ? 2 : 1
        }
        return nil
    }

    /// Whether the `/` at `index` follows no operand, as Swift reads it: it starts the source, or white
    /// space, `(`, `[`, `{`, `,`, `;`, `:` or a block comment's end precedes it (Swift's left-unbound
    /// test), or one of ``expressionKeywords`` ends right before it, `try` with its `?` or `!` too.
    private func opensOperand() -> Bool {
        guard index > 0 else { return true }
        if Self.operandOpeners.contains(bytes[index - 1]) { return true }
        if bytes[index - 1] == .slash && index > 1 && bytes[index - 2] == .star { return true }
        let marked = bytes[index - 1] == .question || bytes[index - 1] == .exclamation
        let word = Self.keyword(endingAt: marked ? index - 1 : index, in: bytes)
        return marked ? word == "try" : Self.expressionKeywords.contains(word)
    }

    /// Whether the `/` at `index` names an operator being declared: one of ``declarationKeywords`` ends
    /// the code before it on its line, spaces, tabs and comments between (`static func /(`,
    /// `infix operator /+/ :`), where Swift reads the operator's name.
    private func namesADeclaredOperator() -> Bool {
        var end = code.count
        // R2: bounded by the code read so far.
        while end > 0, code[end - 1] == .space || code[end - 1] == .tab { end -= 1 }
        return Self.declarationKeywords.contains(Self.keyword(endingAt: end, in: code))
    }

    /// The word that ends just before `end` in `text` (letters, digits, `_`, `$` and any non-ASCII
    /// byte), or "" when none does or a `.` makes it a member's name (`k.in`), which no keyword is.
    private static func keyword(endingAt end: Int, in text: [UInt8]) -> String {
        var start = end
        // R2: bounded by `end`.
        while start > 0, isIdentifierByte(text[start - 1]) { start -= 1 }
        guard start < end, start == 0 || text[start - 1] != .period else { return "" }
        return String(decoding: text[start..<end], as: UTF8.self)
    }

    /// Whether `byte` can belong to a Swift name: an ASCII letter or digit, `_`, `$`, or any byte of a
    /// multi-byte UTF-8 sequence.
    private static func isIdentifierByte(_ byte: UInt8) -> Bool {
        switch byte {
        case 0x30...0x39, 0x41...0x5A, 0x61...0x7A, .underscore, .dollar, 0x80...: return true
        default: return false
        }
    }

    /// Whether the `/` at `index` starts the operator `/` or `/=` bound to nothing after it (white space,
    /// a closing bracket, `,`, `;`, `:`, a comment or the end), as in `a / b`, `x /= y` and
    /// `reduce(0, /)`: an operator there in all but the body openings the type's doc lists, while any
    /// other run of operator characters after no operand opens a regex literal where one closes.
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
    static let exclamation: UInt8 = 0x21
    static let quote: UInt8 = 0x22
    static let hash: UInt8 = 0x23
    static let dollar: UInt8 = 0x24
    static let leftParenthesis: UInt8 = 0x28
    static let rightParenthesis: UInt8 = 0x29
    static let star: UInt8 = 0x2A
    static let period: UInt8 = 0x2E
    static let slash: UInt8 = 0x2F
    static let equals: UInt8 = 0x3D
    static let question: UInt8 = 0x3F
    static let backslash: UInt8 = 0x5C
    static let underscore: UInt8 = 0x5F
}
