// PayloadSummary.swift
// ProximityKit/Wire
//
// The sender's disclosure summary every envelope carries (`FernletIdentityEnvelope.payloadSummary`),
// and the date interval it may name: generic wire types that name no payload type, capability or
// app, declared beside the envelope. Their JSON is wire, in every envelope frame and in a schema-v1
// envelope's signed bytes, and `CanonicalSignatureSerializer` writes every field into the schema-v2
// signed bytes, so the strings a sender puts in a summary are wire tokens (the banner on
// `PayloadSummary` says why they never localize). `ProximityVocabularyGoldenTests` pins the JSON, one
// schema-v1 envelope and the decode bounds; `FernletIdentityEnvelopeTests.goldenEnvelopeHex` pins the
// schema-v2 bytes.
//
// `nonisolated` + `Sendable` against ProximityKit's `.defaultIsolation(MainActor.self)`, like every
// wire type here, so both decode with their envelope off the main actor.

import Foundation

/// A contiguous date interval used in PayloadSummary.
/// Using a plain struct rather than ClosedRange<Date> to sidestep retroactive Codable conformance.
public nonisolated struct DateRange: Codable, Equatable, Sendable {
    public let start: Date
    public let end: Date

    public init(start: Date, end: Date) {
        self.start = start
        self.end = end
    }
}

/// The human-readable disclosure summary shown before a payload is accepted.
///
/// Built by the sender to describe what a payload contains (title, item count, date range) so the
/// receiving user can consent to it without the app decoding the body first.
///
/// **DO NOT LOCALIZE `title`, `subtitle`, or any `extraDetails` key or value.** They are wire
/// tokens despite reading exactly like UI copy — which is why this banner is here, on a type whose
/// first sentence says "human-readable", sitting in a module a bulk localization pass would
/// reasonably assume is display-bearing. Two things break at once if they are translated:
/// `CanonicalSignatureSerializer` folds all of them into the Ed25519 canonical signing bytes, and
/// they render on the **receiving** device, not the sender's — so a Spanish sender's payload would
/// arrive as Spanish consent copy on a German peer's phone. Signature verification still passes
/// either way, so no test would catch it. A localized Connection Inspector belongs on the receiving
/// side, mapping the frozen title to a local label keyed on the payload type token.
public nonisolated struct PayloadSummary: Codable, Equatable, Sendable {
    public let title: String
    public let subtitle: String?
    public let itemCount: Int
    public let dateRange: DateRange?
    public let extraDetails: [String: String]

    /// Most `extraDetails` entries a decoded summary may carry, and the longest any single summary
    /// string may be.
    ///
    /// R3: the summary is built by the SENDER and rendered to the receiving user before consent, so
    /// its strings and dictionary are untrusted peer input with nothing else bounding them. A
    /// legitimate disclosure is a handful of short lines; anything past these caps is rejected.
    public static let maxExtraDetails = 16
    public static let maxDetailCharacters = 200

    public init(
        title: String,
        subtitle: String? = nil,
        itemCount: Int = 0,
        dateRange: DateRange? = nil,
        extraDetails: [String: String] = [:]
    ) {
        self.title = title
        self.subtitle = subtitle
        self.itemCount = itemCount
        self.dateRange = dateRange
        self.extraDetails = extraDetails
    }

    /// Bounded decode (R3/R5): rejects an oversize summary rather than holding and rendering it.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        title = try Self.boundedText(c.decode(String.self, forKey: .title), in: c, key: .title)
        subtitle = try c.decodeIfPresent(String.self, forKey: .subtitle)
            .map { try Self.boundedText($0, in: c, key: .subtitle) }
        itemCount = try c.decode(Int.self, forKey: .itemCount)
        dateRange = try c.decodeIfPresent(DateRange.self, forKey: .dateRange)
        let details = try c.decode([String: String].self, forKey: .extraDetails)
        guard details.count <= Self.maxExtraDetails else {
            throw DecodingError.dataCorruptedError(
                forKey: .extraDetails, in: c,
                debugDescription: "\(details.count) detail rows exceeds the \(Self.maxExtraDetails) allowed")
        }
        for (key, value) in details {
            _ = try Self.boundedText(key, in: c, key: .extraDetails)
            _ = try Self.boundedText(value, in: c, key: .extraDetails)
        }
        extraDetails = details
    }

    /// Rejects a summary string longer than ``maxDetailCharacters``.
    private static func boundedText(_ value: String, in container: KeyedDecodingContainer<CodingKeys>,
                                    key: CodingKeys) throws -> String {
        guard value.count <= maxDetailCharacters else {
            throw DecodingError.dataCorruptedError(
                forKey: key, in: container,
                debugDescription: "summary text of \(value.count) characters exceeds the \(maxDetailCharacters) allowed")
        }
        return value
    }

    /// Wire JSON keys for a disclosure summary.
    private enum CodingKeys: String, CodingKey {
        case title, subtitle, itemCount, dateRange, extraDetails
    }
}
