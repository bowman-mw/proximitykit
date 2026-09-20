import Foundation

// MARK: - RecipeShareAdvertisement

/// What the recipe-share radio publishes in its Bonjour TXT record, and what it believes reading
/// one back — as pure functions over `[String: String]`, so the whole vocabulary settles at tier 1.
///
/// The counterpart of ``MeshLinkAdvertisement`` and ``PresenceAdvertisement`` for the third radio,
/// and a separate type for the same reason they are separate from each other: the three publish
/// disjoint vocabularies. This one carries `v`, `sid`, `mode` and an optional `name`, and there is
/// deliberately no room in it for anything else.
///
/// ## The split of ownership, which is the point of this type
///
/// The **owner** (`ProximityRecipeShareManager`) contributes `v`, `mode` and the byte-bounded
/// `name` — the fields a picker row is rendered from. The **radio**
/// (``NetworkRecipeShareSession``) contributes `sid`, because under QUIC the session id is minted
/// with the instance name and the TLS identity and is replaced with them at every `start()` and
/// every resume. Neither half can publish alone, and ``publishedFields(from:sessionID:)`` is the
/// one place they are joined.
///
/// ## Why the entries cannot overflow
///
/// DNS-SD (RFC 6763 §6.1) gives each TXT entry a single length byte, so one `key=value` string may
/// not exceed ``maxEntryByteCount``. Every value here is bounded well under that before it
/// arrives: `sid` is a 36-character UUID, `name` is capped at
/// ``MeshLinkAdvertisement/maxFieldValueLength`` bytes by ``RecipeShareAdvertisedName``, and `v`
/// and `mode` are frozen tokens. The fields are published through
/// ``MeshLinkAdvertisement/publishedFields(from:)``, which drops an empty or over-long value
/// rather than truncating it, so the bound holds by construction — and
/// ``entriesFitTheTXTLimit(_:)`` is the assertion that says so out loud. Presence needed chunking
/// here (24 tags were 311 bytes); this record's worst case is ~150.
///
/// Every key and value is a frozen wire token in English, never localized.
nonisolated enum RecipeShareAdvertisement {

    /// The advertisement version key. A reader that does not see ``version`` under it believes
    /// nothing else in the record.
    static let versionKey = "v"

    /// The only version this build publishes or believes.
    static let version = "1"

    /// The key carrying the radio's per-start session id — the token an inbound dialer claims in
    /// its ``RecipeShareDialHello`` and the one this device excludes its own echo by.
    static let sessionIDKey = "sid"

    /// The key carrying the sender's chosen display name, absent when it cannot be published.
    static let nameKey = "name"

    /// The key naming which Fernlet radio this registration belongs to.
    static let modeKey = "mode"

    /// The only mode this radio publishes or believes.
    static let mode = "recipe"

    /// Bytes one whole `key=value` TXT entry may occupy — DNS-SD's single length byte.
    static let maxEntryByteCount = 255

    /// The TXT fields to publish: the owner's half joined to the radio's session id, bounded by
    /// ``MeshLinkAdvertisement/publishedFields(from:)``.
    ///
    /// The `sid` is written last and unconditionally: it is the radio's, not the owner's, and an
    /// owner that one day advertised its own would be silently overruled here rather than putting
    /// a stale token on the air.
    static func publishedFields(from ownerFields: [String: String], sessionID: String) -> [String: String] {
        var fields = ownerFields
        fields[sessionIDKey] = sessionID
        return MeshLinkAdvertisement.publishedFields(from: fields)
    }

    /// Whether a browsed record is a recipe-share advertisement this build understands.
    static func isRecipeAdvertisement(_ fields: [String: String]?) -> Bool {
        fields?[versionKey] == version && fields?[modeKey] == mode
    }

    /// The session id a browsed record carries, or nil when the record is not a recipe-share
    /// advertisement of this version or carries no usable id.
    static func sessionID(from fields: [String: String]?) -> String? {
        guard isRecipeAdvertisement(fields), let sessionID = fields?[sessionIDKey],
              !sessionID.isEmpty else { return nil }
        return sessionID
    }

    /// Whether every entry in `fields` fits one DNS-SD TXT entry, `key`, `=` and value together.
    ///
    /// Total over the record and bounded by ``MeshLinkAdvertisement/maxFields``, so a cell can
    /// assert the published record is legal rather than asserting that each value happens to be
    /// short.
    static func entriesFitTheTXTLimit(_ fields: [String: String]) -> Bool {
        for (key, value) in fields.sorted(by: { $0.key < $1.key })
        where key.utf8.count + 1 + value.utf8.count > maxEntryByteCount {
            return false
        }
        return true
    }
}

// MARK: - RecipeShareDialHello

/// The one frame a recipe-share dialer writes before anything else on its control stream: the
/// session id it is advertising.
///
/// **Why it exists.** Under MultipeerConnectivity the inbound side got peer resolution for free —
/// an invitation arrives bearing the peer the browser already discovered, so the owner's
/// invitation gate could answer "do I already hold a pairing with *this device*?". QUIC has no
/// invitation: a peer dials, and an inbound connection carries a connection id that belongs to no
/// browse result. Without a resolution the hard 2-device cap's inbound layer has nothing to rule
/// on and the radio would admit by arrival order instead.
///
/// **Why a `sid`, and why that is not a new disclosure.** The dialer sends the very token it is
/// already broadcasting to the whole room in its own TXT record, to a peer that is almost
/// certainly already browsing it. Nothing is knowable from this frame that was not knowable from
/// the air a second earlier, and the responder believes it exactly as far as it believes the
/// advertisement: it looks the token up among the peers it has actually browsed and refuses the
/// connection outright if it names none, or names this device itself. The identity decision is
/// untouched — it is `ProximityCoordinator`'s sealed introduction, after the channel exists.
///
/// **What it is not.** Not an identity claim, not signed, and never trusted for anything but
/// routing the connection to a browsed peer.
nonisolated struct RecipeShareDialHello: Codable, Equatable, Sendable {

    /// Hard ceiling on the encoded frame, enforced before a byte of it is read. Two short frozen
    /// keys and one 36-character UUID encode to 54 bytes; 96 is generous for that and still
    /// refuses anything shaped like a payload.
    static let maxEncodedBytes = 96

    /// The frozen version token — ``RecipeShareAdvertisement/version``, the same vocabulary the TXT
    /// record uses, so there is one version to move if the recipe wire ever changes.
    let version: String

    /// The session id the dialer claims to be advertising: the `sid` from its own TXT record.
    let sessionID: String

    /// Frozen wire spellings, identical to the TXT record's keys.
    enum CodingKeys: String, CodingKey {
        case version = "v"
        case sessionID = "sid"
    }

    /// A hello claiming `sessionID`, at the current wire version.
    init(sessionID: String) {
        self.version = RecipeShareAdvertisement.version
        self.sessionID = sessionID
    }

    /// The encoded frame for a hello claiming `sessionID`.
    ///
    /// - Throws: whatever `JSONEncoder` throws, plus
    ///   ``MeshTransportError/oversizedFrame(byteCount:)`` for an id long enough to push the frame
    ///   past ``maxEncodedBytes`` — refused here rather than written and refused by the peer.
    /// The key order is pinned with `.sortedKeys` so the frame is **canonical**: the same hello
    /// encodes to the same bytes on every build and every device, which is what makes a golden
    /// vector for it a golden vector rather than a snapshot of one encoder's field ordering.
    static func encoded(sessionID: String) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(RecipeShareDialHello(sessionID: sessionID))
        guard data.count <= maxEncodedBytes else {
            throw MeshTransportError.oversizedFrame(byteCount: data.count)
        }
        return data
    }

    /// The hello in `data`, or nil for anything oversized, malformed, wrongly versioned, or
    /// carrying an empty or over-long session id.
    ///
    /// Total, never throwing: every failure here is untrusted wire input and has exactly one
    /// answer — refuse the connection — so a caller that had to distinguish them would only be
    /// tempted to treat some of them as recoverable. The id's own length bound is
    /// ``MeshLinkAdvertisement/maxFieldValueLength``, the same bound that decides whether a `sid`
    /// could have been advertised at all: an id too long to publish can never name a browsed peer,
    /// so believing one would only widen what reaches the resolver.
    static func decoded(_ data: Data) -> RecipeShareDialHello? {
        guard data.count <= maxEncodedBytes,
              let hello = try? JSONDecoder().decode(RecipeShareDialHello.self, from: data),
              hello.version == RecipeShareAdvertisement.version,
              !hello.sessionID.isEmpty,
              hello.sessionID.utf8.count <= MeshLinkAdvertisement.maxFieldValueLength else { return nil }
        return hello
    }
}
