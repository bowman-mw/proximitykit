import Foundation

// MARK: - PresenceAdvertisement

/// What the presence radio publishes in its Bonjour TXT record, and what it believes reading one
/// back — as pure functions over `[String: String]`, so the whole vocabulary settles at tier 1.
///
/// The counterpart of ``MeshLinkAdvertisement`` for the presence radio, and deliberately a separate
/// type rather than a parameter on it: the two radios publish disjoint vocabularies with
/// incompatible bounds. The mesh hoists `sid` and caps every value at 64 bytes; presence carries no
/// `sid` at all and its one value is a tag list that is an order of magnitude longer. Sharing one
/// type would mean the mesh's 64-byte cap silently dropping the presence tag list — the whole
/// payload — on a clean build.
///
/// ## The payload
///
/// `v` is the frozen version token `"1"`. The tags are the truncated pairwise HMACs
/// `IdentityService.presenceTag` derives for the current epoch, base64, comma-separated — the only
/// thing this radio ever broadcasts. There is no display name, no session id and no fingerprint,
/// and there is deliberately no room in the vocabulary for one.
///
/// ## Why the tags are chunked
///
/// DNS-SD (RFC 6763 §6.1) gives each TXT entry a single length byte, so one `key=value` string may
/// not exceed 255 bytes. `PresenceManager.maxAdvertisedTags` is 24, and 24 base64 tags with their
/// separators are 311 bytes — over the limit before the key is even counted. Under
/// MultipeerConnectivity that ceiling was the framework's problem and its behaviour there was never
/// established; under `NWTXTRecord` it is this type's problem, and an over-long entry would either
/// be refused or silently truncated, which reads on the air as "presence stopped working once you
/// had twenty friends".
///
/// So the list is split across at most ``maxChunks`` keys — `t`, then `t1` — each at or under
/// ``maxChunkValueBytes``, and the reader joins them back in key order. A roster small enough to fit
/// (eighteen tags, which is every realistic roster) publishes exactly `v` and `t` and looks
/// identical to what MC advertised. Tags past the last chunk are dropped rather than truncated: a
/// truncated tag matches nothing and would be indistinguishable from a stranger's, while a dropped
/// one simply means that friend is not advertised this epoch, which is what the advertise cap
/// already means.
///
/// Every key and value here is a frozen wire token in English, never localized.
nonisolated enum PresenceAdvertisement {

    /// The advertisement version key. A reader that does not see ``version`` under it believes
    /// nothing else in the record.
    static let versionKey = "v"

    /// The only version this build publishes or believes.
    static let version = "1"

    /// The first (and, for any realistic roster, only) tag-list key.
    static let tagsKey = "t"

    /// Separator between tags inside one chunk.
    static let tagSeparator = ","

    /// Chunks the tag list may occupy: `t` and `t1`. Two chunks hold 36 tags, comfortably above
    /// `PresenceManager.maxAdvertisedTags`, so the cap that bites is the roster cap and not this one.
    static let maxChunks = 2

    /// Bytes one chunk's VALUE may occupy. Held under the DNS-SD 255-byte ceiling for the whole
    /// `key=value` string with room for the key and the `=`, so a legal advertisement cannot be
    /// built by accident.
    static let maxChunkValueBytes = 240

    /// Tags believed from ONE inbound advertisement. The inbound direction is untrusted wire data,
    /// and a bound that only holds for well-behaved peers is not a bound (Power of 10 rule 2).
    static let maxInboundTags = 64

    /// The TXT key for one chunk index: `t`, then `t1`, `t2`, … A pure function of the index, so
    /// the writer and the reader cannot spell the continuation keys differently.
    static func tagsKey(chunk index: Int) -> String {
        index == 0 ? tagsKey : tagsKey + String(index)
    }

    /// The TXT fields to publish for a set of own tag tokens.
    ///
    /// `v` is always present — an advertisement with no tags is still a presence advertisement, and
    /// a device with no eligible friends must look exactly like one that has them but is out of
    /// range. The tags are sorted so the record is a function of the set alone: an unstable
    /// ordering would re-publish (and therefore re-register) an unchanged advertisement.
    static func publishedFields(tags: [String]) -> [String: String] {
        var fields = [versionKey: version]
        var chunk = ""
        var index = 0
        for tag in tags.sorted() where index < maxChunks {
            let candidate = chunk.isEmpty ? tag : chunk + tagSeparator + tag
            if candidate.utf8.count <= maxChunkValueBytes {
                chunk = candidate
                continue
            }
            fields[tagsKey(chunk: index)] = chunk
            index += 1
            chunk = tag.utf8.count <= maxChunkValueBytes ? tag : ""
        }
        if !chunk.isEmpty, index < maxChunks {
            fields[tagsKey(chunk: index)] = chunk
        }
        return fields
    }

    /// Whether a browsed record is a presence advertisement this build understands.
    static func isPresenceAdvertisement(_ fields: [String: String]?) -> Bool {
        fields?[versionKey] == version
    }

    /// The tag tokens carried by a browsed record, joined back across the chunks.
    ///
    /// Empty for anything that is not a version-1 presence advertisement, and bounded at
    /// ``maxInboundTags`` however many a peer crams in. Empty tokens are dropped rather than
    /// matched: an empty string would be a token every malformed record shares.
    static func tags(from fields: [String: String]?) -> Set<String> {
        guard let fields, isPresenceAdvertisement(fields) else { return [] }
        var tags: Set<String> = []
        for index in 0..<maxChunks {
            guard let chunk = fields[tagsKey(chunk: index)] else { continue }
            for token in chunk.split(separator: Character(tagSeparator)).map(String.init)
            where !token.isEmpty && tags.count < maxInboundTags {
                tags.insert(token)
            }
        }
        return tags
    }
}

// MARK: - PresenceDialHello

/// The one frame a presence dialer writes before anything else on its control stream: the pairwise
/// tag it is claiming to advertise.
///
/// **Why it exists.** Under MultipeerConnectivity the inbound side got peer resolution for free —
/// an invitation arrives bearing the `MCPeerID` the browser already discovered, so
/// `PresenceManager` could look the peer up in its tag-match map, find the one friend it matched,
/// and hand that friend's key-agreement key to the coordinator as the SEALED-INTRODUCTION
/// recipient. QUIC has no invitation: a peer dials, and an inbound `NetworkConnection` carries a
/// connection id that belongs to no browse result. Without a resolution the responder cannot name
/// the friend it must seal its ack to, and the sealed-introduction rule has no recipient — so the
/// receive half of in-person hearts would simply stop working.
///
/// **Why a tag, and why that is not a new disclosure.** The dialer sends the very token it is
/// already broadcasting to the whole room in its own TXT record, to a peer that is almost certainly
/// already browsing it. Nothing here is knowable from this frame that was not knowable from the
/// air a second earlier, and the responder believes it exactly as far as it believes the
/// advertisement: it looks the token up in its own `candidateTokens` — tokens it derived itself
/// from pairwise secrets only the two members of a pair hold — and refuses the connection outright
/// if it names no friend, or names a friend it has not actually browsed. A tag replayed inside its
/// epoch buys an attacker one accepted connection and nothing else, which is the residual the
/// presence radio already documents and which the sealed introduction then closes: the forger
/// cannot open the intro, cannot produce a valid ack, and learns nothing.
///
/// **What it is not.** Not an identity claim, not signed, and never trusted for anything but
/// routing the connection to a browsed peer. The identity decision stays exactly where it was — in
/// ``ProximityCoordinator``'s sealed introduction.
nonisolated struct PresenceDialHello: Codable, Equatable, Sendable {

    /// Hard ceiling on the encoded frame, enforced before a byte of it is read. Two short frozen
    /// keys and one 12-character base64 tag encode to well under a hundred bytes; 256 is generous
    /// and still refuses anything shaped like a payload.
    static let maxEncodedBytes = 256

    /// The frozen version token — ``PresenceAdvertisement/version``, the same vocabulary the TXT
    /// record uses, so there is one version to move if the presence wire ever changes.
    let version: String

    /// The pairwise tag the dialer claims to be advertising: one token from its own TXT record.
    let tag: String

    /// Frozen wire spellings, identical to the TXT record's keys.
    enum CodingKeys: String, CodingKey {
        case version = "v"
        case tag = "t"
    }

    /// A hello claiming `tag`, at the current wire version.
    init(tag: String) {
        self.version = PresenceAdvertisement.version
        self.tag = tag
    }

    /// The encoded frame for a hello claiming `tag`.
    ///
    /// - Throws: whatever `JSONEncoder` throws, plus
    ///   ``MeshTransportError/oversizedFrame(byteCount:)`` for a tag long enough to push the frame
    ///   past ``maxEncodedBytes`` — refused here rather than written and refused by the peer.
    static func encoded(tag: String) throws -> Data {
        let data = try JSONEncoder().encode(PresenceDialHello(tag: tag))
        guard data.count <= maxEncodedBytes else {
            throw MeshTransportError.oversizedFrame(byteCount: data.count)
        }
        return data
    }

    /// The hello in `data`, or nil for anything oversized, malformed, wrongly versioned or carrying
    /// an empty tag.
    ///
    /// Total, never throwing: every failure here is untrusted wire input and has exactly one
    /// answer — refuse the connection — so a caller that had to distinguish them would only be
    /// tempted to treat some of them as recoverable.
    static func decoded(_ data: Data) -> PresenceDialHello? {
        guard data.count <= maxEncodedBytes,
              let hello = try? JSONDecoder().decode(PresenceDialHello.self, from: data),
              hello.version == PresenceAdvertisement.version,
              !hello.tag.isEmpty else { return nil }
        return hello
    }
}
