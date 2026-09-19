import Foundation

// MARK: - PresencePostureError

/// Why a presence posture could not be minted.
///
/// Diagnostic only — never user-facing copy, so deliberately **not** a `LocalizedError` (the
/// localization wall's rule G governs error types a person actually reads). It sits beside
/// ``MeshTransportError`` in spirit: a failure raised before anything reaches the air.
nonisolated enum PresencePostureError: Error, Equatable {

    /// The injected entropy source answered with the wrong number of bytes.
    ///
    /// Refused rather than padded, truncated or shrugged off: the instance name's unlinkability
    /// *is* the entropy behind it, so a short draw would advertise a name that is weaker than the
    /// one this type promises, silently and for a whole epoch.
    case entropyUnavailable(byteCount: Int)

    /// Frozen English for the diagnostic surface. Never shown as user copy.
    var diagnosticDescription: String {
        switch self {
        case .entropyUnavailable(let byteCount):
            return "The presence posture's entropy source returned \(byteCount) bytes."
        }
    }
}

// MARK: - PresenceEpochPosture

/// The ephemeral posture the presence radio wears for exactly one presence epoch: the service
/// instance name it advertises, and the TLS identity it presents.
///
/// **The privacy claim of the whole presence feature** (plan §17.1). The advertisement's *payload*
/// already rotates — it carries nothing but pairwise-DH tags keyed to the epoch — but a radio that
/// keeps one name and one certificate across epochs re-links every sighting anyway: an observer
/// simply follows the name. This value is the other half of the posture, so two sightings 901
/// seconds apart share no byte at all. Nothing here is derived from the device, nothing is
/// persisted, and nothing survives a boundary.
///
/// ## What a posture is made of
///
/// - ``epoch`` — `IdentityService.presenceEpoch(at:)`, the same counter the presence tags use.
/// - ``instanceName`` — ``instanceNamePrefix``, a separator, then ``instanceNameEntropyByteCount``
///   freshly drawn bytes as lowercase hexadecimal. The prefix is a frozen *service* token every
///   Fernlet device carries identically; the rest is entropy and nothing else. The name has the
///   same length at every epoch on every device, so not even its length encodes anything.
/// - ``tlsIdentity`` — one ``EphemeralMeshTLSIdentity/Minted``, minted through the module's single
///   certificate path. There is no second crypto path here and no new cryptographic purpose: the
///   key pair is generated, used to self-sign, and thrown away by machinery that already exists
///   (its one escape-hatch marker, `x509-self-signature`, is already censused). It is anchored to
///   `IdentityService.presenceEpochStart(at:)` and **never to the instant the mint happens** — see
///   below.
///
/// ## Why the certificate is minted at the epoch's START
///
/// `EphemeralMeshTLSIdentity.mint(now:)` writes its argument into the certificate as
/// `notBefore`/`notAfter` at one-second resolution, and the transport's validator accepts any
/// certificate — so those two fields are readable by every device in range. Handing it the *mint
/// instant* would therefore stamp each posture with the second its radio came up: a phone that
/// enables presence at 14:03:27 would advertise `notBefore 13:58:27` while every phone that
/// rotated on the boundary advertises `13:55:00`, and that one field alone would single it out for
/// the rest of the epoch. Anchoring the mint to the epoch start instead makes the validity window
/// a constant every device in the room shares, which is reason 3 below made good rather than
/// merely claimed.
///
/// ## Why the epoch is anchored to the wall clock
///
/// The epoch is `floor(unixTime / IdentityService.presenceEpochSeconds)` — absolute multiples of
/// 900 s since 1970, identical on every device — and **not** a per-launch random phase. Three
/// reasons, in order of weight:
///
/// 1. The presence *tag* epoch must be wall-clock anchored: two phones derive the same pairwise
///    HMAC without exchanging a byte, so the epoch index is a shared absolute quantity, not a
///    local one. A differently-phased clock for the name and the certificate would be a **second
///    clock** — and worse, it would leave the tags rotating on one phase and the name on another,
///    so the pair (tags changed, name unchanged) re-links straight across the boundary. Alignment
///    is what makes the rotation total.
/// 2. A per-launch random phase is itself a stable, device-identifying value. An observer who
///    watches one device rotate twice learns its phase offset — a fingerprint at 900 s resolution
///    that *survives every rotation* and re-links precisely the sightings the rotation exists to
///    break. Wall-clock anchoring has no such residue.
/// 3. The cost — an observer can predict *when* every device rotates — buys them nothing. What
///    they must not learn is *which* new name replaced *which* old one, and a globally
///    synchronised rotation is exactly what denies them that: every Fernlet device in range
///    changes name, certificate and tags at the same instant, so the anonymity set at the boundary
///    is every device present, which is the largest one available.
///
/// ## What this value is not
///
/// A pure value: no radio, no task, no timer, no manager. It holds no reference to anything that
/// can start a radio, and it never rotates itself — `PresenceManager` rotates it on the epoch tick
/// it already runs, and `stop()` drops it. Nothing writes it to the keychain, a file or
/// `UserDefaults`; a posture that is dropped is gone.
nonisolated struct PresenceEpochPosture {

    // MARK: Shape

    /// The frozen service token every presence instance name begins with.
    ///
    /// Constant across every device and every epoch, so it names the protocol and never the
    /// device — a device-derived prefix here would re-introduce exactly the linkability the rest
    /// of the name removes. A wire token: frozen English, never localized.
    static let instanceNamePrefix = "fn"

    /// Separates the frozen token from the random half, so a reader can see where entropy starts.
    /// A fixed string, which is what keeps ``instanceNameLength`` a constant.
    static let instanceNameSeparator = "-"

    /// Bytes of entropy behind one instance name: 64 bits, drawn fresh at every epoch.
    ///
    /// Enough that two devices in one room collide with negligible probability, and far more than
    /// enough that a name is unguessable; the same 8-byte unit the presence tag
    /// (`IdentityService.presenceTagByteCount`) and the certificate serial
    /// (``EphemeralMeshTLSIdentity/serialByteCount``) already use.
    static let instanceNameEntropyByteCount = 8

    /// Bound on one entropy draw (Power of 10 rule 2: the loop that fills it is bounded by a
    /// constant, not by a caller's number). Far above ``instanceNameEntropyByteCount``, which is
    /// the only draw this type makes.
    static let maxEntropyByteCount = 64

    /// The length every instance name has, on every device, at every epoch. A constant by
    /// construction — a variable-length name would leak through its length alone.
    static var instanceNameLength: Int {
        instanceNamePrefix.count + instanceNameSeparator.count + 2 * instanceNameEntropyByteCount
    }

    // MARK: The posture

    /// The presence epoch this posture belongs to — `IdentityService.presenceEpoch(at:)`, the
    /// single presence clock. Not a second counter, and never advertised on its own.
    let epoch: UInt64

    /// The service instance name advertised for this epoch.
    let instanceName: String

    /// The TLS identity presented for this epoch: a fresh self-signed P-256 key pair whose
    /// certificate's subject is ``EphemeralMeshTLSIdentity/commonName``, a token shared by every
    /// device, and whose validity window is anchored to the epoch's start so it is shared too.
    /// Memory-only, and replaced wholesale at the next boundary.
    ///
    /// Minted EAGERLY, with the rest of the posture, rather than lazily on the first QUIC accept:
    /// a lazily-minted identity would make "stable within an epoch" depend on the order calls
    /// happen to arrive in, and would move a P-256 keygen onto the accept path. The cost of
    /// eagerness is one keygen per 900 s while the radio is up.
    let tlsIdentity: EphemeralMeshTLSIdentity.Minted

    private init(epoch: UInt64, instanceName: String, tlsIdentity: EphemeralMeshTLSIdentity.Minted) {
        self.epoch = epoch
        self.instanceName = instanceName
        self.tlsIdentity = tlsIdentity
    }

    // MARK: Minting

    /// Mints the posture for the epoch containing `now`, from injected sources.
    ///
    /// - Parameters:
    ///   - now: the clock reading, and the only input the epoch comes from. The certificate is
    ///     minted at the epoch's START, never at `now` — a certificate anchored to the asking
    ///     instant would carry the second this device's radio came up (see the type's doc).
    ///   - entropy: the instance name's randomness, as a count-to-bytes function.
    ///   - mintIdentity: the certificate path — production passes
    ///     ``EphemeralMeshTLSIdentity/mint(now:)`` and nothing else ever should. It is handed
    ///     `IdentityService.presenceEpochStart(at: now)`, which is the same instant on every
    ///     device in the epoch.
    /// - Throws: ``PresencePostureError/entropyUnavailable(byteCount:)``, or whatever the identity
    ///   mint throws.
    static func minted(
        at now: Date,
        entropy: (Int) -> [UInt8],
        mintIdentity: (Date) throws -> EphemeralMeshTLSIdentity.Minted
    ) throws -> PresenceEpochPosture {
        let name = try instanceName(entropy: entropy)
        let identity = try mintIdentity(IdentityService.presenceEpochStart(at: now))
        return PresenceEpochPosture(
            epoch: IdentityService.presenceEpoch(at: now),
            instanceName: name,
            tlsIdentity: identity
        )
    }

    /// The production mint: the system CSPRNG and the module's one certificate path.
    static func minted(at now: Date) throws -> PresenceEpochPosture {
        try minted(
            at: now,
            entropy: systemEntropy,
            mintIdentity: { try EphemeralMeshTLSIdentity.mint(now: $0) }
        )
    }

    /// The posture to wear at `now`: `self` while `now` is still inside ``epoch``, and an entirely
    /// fresh posture — new name, new key pair, new certificate — the moment it is not.
    ///
    /// Non-mutating, and the whole of the rotation rule: there is no partial rotation, no carried
    /// field and no counter, so a boundary crossing shares nothing with what preceded it.
    func rotated(
        at now: Date,
        entropy: (Int) -> [UInt8],
        mintIdentity: (Date) throws -> EphemeralMeshTLSIdentity.Minted
    ) throws -> PresenceEpochPosture {
        guard IdentityService.presenceEpoch(at: now) != epoch else { return self }
        return try Self.minted(at: now, entropy: entropy, mintIdentity: mintIdentity)
    }

    /// The production rotation, on the same terms as ``rotated(at:entropy:mintIdentity:)``.
    func rotated(at now: Date) throws -> PresenceEpochPosture {
        guard IdentityService.presenceEpoch(at: now) != epoch else { return self }
        return try Self.minted(at: now)
    }

    // MARK: Name construction

    /// One instance name: the frozen token, the separator, then exactly
    /// ``instanceNameEntropyByteCount`` drawn bytes as lowercase hexadecimal.
    ///
    /// Nothing else goes in — no counter, no epoch index, no timestamp, no device byte — which is
    /// why a name minted from fixed entropy is the same string at every epoch, and why two names
    /// from the same epoch differ whenever the entropy does.
    ///
    /// - Throws: ``PresencePostureError/entropyUnavailable(byteCount:)`` when the source answers
    ///   with the wrong number of bytes (validated at entry; never padded or truncated).
    static func instanceName(entropy: (Int) -> [UInt8]) throws -> String {
        let bytes = entropy(instanceNameEntropyByteCount)
        guard bytes.count == instanceNameEntropyByteCount else {
            throw PresencePostureError.entropyUnavailable(byteCount: bytes.count)
        }
        return instanceNamePrefix + instanceNameSeparator + hexadecimal(bytes)
    }

    /// The production entropy source: `byteCount` bytes from the system CSPRNG — the same draw
    /// ``EphemeralMeshTLSIdentity/randomSerial()`` makes next door.
    ///
    /// A request outside 1 ... ``maxEntropyByteCount`` answers empty, which
    /// ``instanceName(entropy:)`` then refuses by length rather than advertising a short name.
    static func systemEntropy(_ byteCount: Int) -> [UInt8] {
        guard byteCount > 0, byteCount <= maxEntropyByteCount else { return [] }
        return (0..<byteCount).map { _ in UInt8.random(in: UInt8.min...UInt8.max) }
    }

    /// Lowercase hexadecimal, two characters per byte, fixed width — the encoding that makes a
    /// name's length a function of the byte count alone.
    static func hexadecimal(_ bytes: [UInt8]) -> String {
        var encoded = ""
        encoded.reserveCapacity(bytes.count * 2)
        for byte in bytes {
            encoded.append(hexadecimalDigits[Int(byte >> 4)])
            encoded.append(hexadecimalDigits[Int(byte & 0x0F)])
        }
        return encoded
    }

    /// The 16 hexadecimal digits. Indexed only by a nibble, which is provably in range.
    private static let hexadecimalDigits: [Character] = Array("0123456789abcdef")
}
