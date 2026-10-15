// FernletFeatureGoldenTests.swift
// ProximityKitTests
//
// Fernlet's features over the proximity stack put bytes on the wire, in the keychain and on disk that
// no other suite pins, and the Fernlet repository's plan steps A0.4 to A0.7 moved every one of those
// features or re-derived its bytes. That repository's suite of this name holds each such byte to the
// value Fernlet ships. THE RULE there holds here too: every literal is FROZEN, and a red cell is a
// wire, keychain or at-rest decision, never re-pinned from Swift's output.
//
// A partial copy (ProximityKit plan step A1.3, which copies into the package every cell of the Fernlet
// repository's tests that reads this module's sources before that repository stops holding them): of
// the Fernlet repository's FernletTests file of the same name, this holds only the ProximityKit halves
// of the two cells of `FernletFeatureGoldenTests` that read this module's sources, with the suite's
// name and theirs unchanged, each source read through `PackageRoot` and the module walk through the
// package's walker (`TestSupport/PackageSwiftFiles.swift`) at its floor:
//
//   - 31e, the recipe copy: no ProximityKit file holds one of the forty frozen templates as a
//     literal, so none comes back to the pair session. The templates' home, FernletSocial's
//     recipe-share manager, and the render row read files and types only that repository holds and
//     stay in its original;
//   - 31f, the recipe send's constants: the pair session's ten source rows, each needle counted
//     exactly in its file or its brace-matched body, and the recipe radio's tunnel and pending-inbound
//     caps. The connect timeout read off a pairing rig, Fernlet's recipe profile and the seven rows
//     over FernletSocial's recipe-share and presence managers stay there.
//
// Every other group of that suite names Fernlet's features, namespace or stores and stays there.

import Foundation
import Testing
@testable import ProximityKit

/// The ProximityKit halves of the feature golden's recipe groups: the recipe copy kept out of this
/// module's code, and the pair session's recipe constants and spellings held in its source.
///
/// **The rule for every commit: re-point a row's file or body, never a literal or a count.** A frozen
/// template, needle or count was written by hand or read off the code the Fernlet repository's suite
/// froze; a failing one is a decision, so it is never re-pinned from Swift's output to go green.
@MainActor
@Suite(.serialized)
struct FernletFeatureGoldenTests {

    // MARK: - Group 31: the recipe share

    /// **31e.** The recipe copy is its frozen templates in its home, and no ProximityKit file holds
    /// one of the forty as a literal (lexed as Swift reads it, each interpolation read as `\(…)`), so
    /// none comes back to the pair session. The list's own size is held first, so a template dropped
    /// from it cannot shrink what the scan looks for. The Fernlet repository's original also reads the
    /// templates off their home, FernletSocial's recipe-share manager, as a set equal to this list,
    /// and holds every event and status to the sentence it renders; that half stays there.
    @Test func theRecipeCopyIsItsFrozenTemplatesInItsHome() throws {
        let frozen = Set(Self.frozenRecipeCopyTemplates)
        #expect(Self.frozenRecipeCopyTemplates.count == 40 && frozen.count == 40, "the frozen list holds \(frozen.count) templates")
        var strays: [String] = []
        let sources = try PackageSwiftFiles.sources()
        // R2: bounded by ProximityKit's file list.
        for source in sources {
            let literals = SwiftSourceLexer.lex(source.text).literals
            let held = Set(literals.map { Self.normalizingInterpolations($0.text) }).intersection(frozen)
            strays += held.sorted().map { "\(source.path): \($0)" }
        }
        #expect(sources.count >= PackageSwiftFiles.sourceFloor, """
            the ProximityKit walk read only \(sources.count) Swift files (floor \(PackageSwiftFiles.sourceFloor))
            """)
        #expect(strays.isEmpty, "the recipe copy is back in ProximityKit: \(strays)")
    }

    /// **31f.** The recipe send keeps its constants and spellings in the pair session: the radio's one
    /// tunnel and two pending inbound connections, and ``recipeConstantsPaths``' rows, each needle
    /// counted exactly in its file or its brace-matched body (comments dropped): the door's 25 s
    /// handshake, its friend-mode browser start, its retained trust policy and its default
    /// capabilities and plain introduction; the parked timeout and sweep, the status clear and the
    /// identity checks' audit events, spelled in full under the profile's area. The Fernlet
    /// repository's original also holds the 12 s connect timeout off a pairing rig, Fernlet's recipe
    /// profile, and its rows over FernletSocial's recipe-share manager (the inbound cap and rate limit,
    /// the summary's title and the payload's encoder) and presence manager (the heart delivery's
    /// token, title and seal); that half stays there.
    @Test func theRecipeAndHeartSendsKeepTheirConstantsAndSpellings() throws {
        #expect(NetworkPairSession.maxTunnels == 1, "the recipe radio holds \(NetworkPairSession.maxTunnels) tunnels")
        #expect(NetworkPairSession.maxPendingInbound == 2,
                "the recipe radio holds \(NetworkPairSession.maxPendingInbound) pending inbound connections")
        #expect(Self.recipeConstantsPaths.count == 10, "the pair session's rows are \(Self.recipeConstantsPaths.count), not ten")
        // R2: bounded by the rows.
        for row in Self.recipeConstantsPaths {
            let code = MeshRoutedSourceScan.codeOnly(try PackageRoot.source(row.path))
            let scope = try row.body.map { signature in
                try #require(MeshRoutedSourceScan.bracedBody(after: signature, in: code), "\(row.path) no longer declares `\(signature)`")
            } ?? code
            let count = Self.occurrences(of: row.needle, in: scope)
            #expect(count == row.count, "\(row.path) holds `\(row.needle)` \(count) times, not \(row.count)")
        }
    }

    // MARK: - The frozen values

    /// 31e's frozen templates: every code literal in the recipe share's copy holding a space, each
    /// interpolation read as `\(…)`, the forty the copy census finds there.
    static let frozenRecipeCopyTemplates = [
        #"A send completed against a newer share record — completion not counted."#,
        #"A share outcome arrived for a superseded share — not shown."#,
        #"Connect timeout: \(…) did not answer."#,
        #"Connected to \(…) — recipe sharing links two Fernlets at a time."#,
        #"Connecting to \(…)."#,
        #"Could not connect securely to \(…)."#,
        #"Could not send that recipe."#,
        #"Discovered \(…)."#,
        #"Dropped an oversized recipe share from \(…)."#,
        #"Dropped recipe share from \(…): queue full."#,
        #"Dropped stalled connection to \(…)."#,
        #"No answer from \(…) — that Fernlet may be busy sharing with someone else."#,
        #"Rate-limited recipe share from \(…)."#,
        #"Received recipe share from \(…)."#,
        #"Recipe share"#,
        #"Recipe share discovery refreshed."#,
        #"Recipe share discovery started."#,
        #"Recipe share discovery stopped."#,
        #"Recipe share failed while sending to \(…)."#,
        #"Recipe share failed: \(…) is no longer available."#,
        #"Recipe share radio failed to start — listening will retry on the next app event."#,
        #"Recipe share recipient verified; confirming selected recipient."#,
        #"Recipe share to \(…) ended before sending: the connection closed during setup."#,
        #"Recipe sharing closed to others while paired with \(…)."#,
        #"Recipe sharing reopened to nearby Fernlets."#,
        #"Refused a second send of \(…)."#,
        #"Refused share to \(…): already paired with \(…)."#,
        #"Refused share to \(…): another connection attempt is in flight."#,
        #"Search skipped — already paired with \(…)."#,
        #"Secure recipe-share channel opened with \(…)."#,
        #"Sending \(…) to \(…)."#,
        #"Sent \(…) to \(…)."#,
        #"Still connecting to another Fernlet — recipe sharing links two Fernlets at a time."#,
        #"Still sharing with \(…) — recipe sharing links two Fernlets at a time."#,
        #"That nearby Fernlet is no longer available."#,
        #"The recipe share radio could not start: \(…)"#,
        #"Turned away \(…) — recipe sharing links two Fernlets at a time."#,
        #"Verified \(…)."#,
        #"\(…) disconnected."#,
        #"\(…) is no longer nearby."#
    ]

    /// The file that holds the recipe pairing's channel-ready door and the pair session's constants:
    /// since plan step A0.7.3 ProximityKit's pair session, by its path under the package root.
    static let recipeDoorPath = "Sources/ProximityKit/PairSession/ProximityPairSession.swift"

    /// 31f's source rows over the pair session: a file, the declaration whose brace-matched body is read
    /// (nil for the whole file), a needle, and how many times the needle occurs there, comments dropped.
    /// A commit that moves a row's text re-points its file or its body, never its needle's count. The
    /// Fernlet repository's original holds these ten rows among its seventeen, in this order.
    static let recipeConstantsPaths: [(path: String, body: String?, needle: String, count: Int)] = [
        (recipeDoorPath, "private func handleChannelReady(", "timeoutSeconds: 25", 1),
        (recipeDoorPath, "private func handleChannelReady(", "begin(role: .browser, mode: .friend)", 1),
        (recipeDoorPath, "private func handleChannelReady(", "capabilities:", 0),
        (recipeDoorPath, "private func handleChannelReady(", "sealedIntroductionPeerKeyAgreementKey:", 0),
        (recipeDoorPath, "private func handleChannelReady(", "let trustPolicy = store.makeProximityTrustPolicy()", 1),
        (recipeDoorPath, nil, "parkedConnectionTimeoutSeconds: TimeInterval = 30", 1),
        (recipeDoorPath, nil, "parkedSweepIntervalSeconds: TimeInterval = 5", 1),
        (recipeDoorPath, nil, ".seconds(2.5)", 1),
        (recipeDoorPath, nil, #""\(profile.auditArea).identity.namespaceMismatch""#, 2),
        (recipeDoorPath, nil, #""\(profile.auditArea).identity.provisionFailed""#, 1)
    ]

    // MARK: - Helpers

    /// `text` with each interpolation's contents read as an ellipsis, `\(…)`: a balanced-parenthesis
    /// pass from each unescaped `\(` to its matching `)`. A literal's text is read as written, so an
    /// escaped backslash opens nothing.
    static func normalizingInterpolations(_ text: String) -> String {
        var result = ""
        var depth = 0
        var escaping = false
        // R2: bounded by the literal's characters.
        for character in text {
            if depth > 0 {
                if character == "(" { depth += 1 }
                if character == ")" { depth -= 1 }
                if depth == 0 { result += "\u{2026})" }
                continue
            }
            if escaping, character == "(" { depth = 1 }
            escaping = !escaping && character == "\\"
            result.append(character)
        }
        return result
    }

    /// How many times `needle` occurs in `haystack`, without overlap.
    static func occurrences(of needle: String, in haystack: String) -> Int {
        haystack.components(separatedBy: needle).count - 1
    }
}
