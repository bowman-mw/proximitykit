import Foundation
import CryptoKit
import Security
import FernletFoundation

/// One-time X25519 prekeys for forward-secret heart drops (bitchat adoptions Increment 3 — the
/// pattern bitchat landed after shipping no-FS sealed mail: gossip signed one-time prekey
/// bundles, seal offline mail to a prekey, fall back to the static key only when none is left).
///
/// Local side: mints bundles of 16, private halves in ONE keychain blob under
/// `com.fernlet.heartdrop` (AfterFirstUnlockThisDeviceOnly, never synchronizable — FS keys must
/// never leave the device; proximity identity is per-device already). Retention policy is
/// deliberately simpler than bitchat's delete-on-use + 48 h grace: private halves are retained
/// until bundle expiry (30 d) + grace, because the bundle is broadcast identically to every
/// friend and two senders can race the same prekey. The FS window is therefore the bundle
/// lifetime — bounded, monthly-rotating — instead of static-forever (documented deviation, plan
/// Increment 3).
///
/// Bundle authenticity: a bundle only ever travels INSIDE the signed identity intro envelope
/// (`IdentityRangingPayload.heartDropPrekeyBundle`), so provenance is the envelope's Ed25519
/// signature at receipt — there is no second standalone signature to get out of sync (documented
/// deviation from the plan's first draft).
@MainActor
public final class HeartPrekeyStore {

    /// One one-time X25519 prekey's public half plus the id senders use to name it in the
    /// drop header. Sixteen of these make up a gossiped ``Bundle``.
    public struct PrekeyEntry: Codable, Equatable, Sendable {
        public let id: UUID
        public let publicKey: Data
        public init(id: UUID, publicKey: Data) {
            self.id = id
            self.publicKey = publicKey
        }
    }

    /// The X3DH-style medium-term signed prekey (Track B of
    /// Docs/Plan-Prekeys-ProtectedLoad-CoachMesh-2026-07-26.md). What it buys: any friend not
    /// met in person within `HeartDropPeerBundleCache.maxSealBundleAge` used to get
    /// static-sealed drops forever — one device compromise then retroactively opened every one
    /// of them. The SPK gives those drops a medium-term key instead. This is a COVERAGE win,
    /// not a window win: the private half lives `spkRetention` (~4 weeks), slightly longer than
    /// a one-time key's. "Signed" as in signed-by-the-identity-envelope: like the one-time
    /// bundle it only ever travels inside the signed identity intro, so provenance is the
    /// envelope's Ed25519 signature — no second standalone signature to get out of sync.
    public struct SignedPrekey: Codable, Equatable, Sendable {
        public let id: UUID
        public let publicKey: Data
        public let created: Date
        /// Rotation deadline, NOT retention deadline: after this the owner gossips a fresh SPK,
        /// but keeps this one's private half until `created + spkRetention` so in-flight drops
        /// still open.
        public let expires: Date
        public init(id: UUID, publicKey: Data, created: Date, expires: Date) {
            self.id = id
            self.publicKey = publicKey
            self.created = created
            self.expires = expires
        }
    }

    /// The gossiped shape — public halves only. Codable so it rides `IdentityRangingPayload`
    /// as an optional field old decoders ignore. `signedPrekey` is additive-OPTIONAL: old
    /// peers' bundles decode with nil and keep working; old decoders ignore the extra key.
    public struct Bundle: Codable, Equatable, Sendable {
        public let bundleID: UUID
        public let created: Date
        public let expires: Date
        public let keys: [PrekeyEntry]
        public let signedPrekey: SignedPrekey?
        public init(bundleID: UUID, created: Date, expires: Date, keys: [PrekeyEntry],
                    signedPrekey: SignedPrekey? = nil) {
            self.bundleID = bundleID
            self.created = created
            self.expires = expires
            self.keys = keys
            self.signedPrekey = signedPrekey
        }
    }

    static let batchSize = 16
    public static let bundleLifetime: TimeInterval = 30 * 24 * 3600
    /// Mint a fresh bundle when the current one has less life than this left.
    static let renewalHorizon: TimeInterval = 7 * 24 * 3600
    /// Keep expired bundles' private halves this much longer — an in-flight drop sealed just
    /// before expiry must still open (mirrors bitchat's consumed-prekey grace window).
    public static let expiryGrace: TimeInterval = 48 * 3600

    /// Signed-prekey constants (O2: 14 d seal window → 29 d retention; the invariants matter
    /// more than the numbers and are pinned by tests):
    ///  - `spkRetention ≥ maxSealSignedPrekeyAge + HeartDropOutbox.entryLifetime +
    ///    createdAtSkewTolerance` — a drop sealed at the end of the seal window can sit the full
    ///    outbox lifetime (plus skew) and must still open; violating this silently loses hearts.
    ///  - `spkRetention < bundleLifetime + expiryGrace` — nothing this change introduces is ever
    ///    the longest-lived key on the device.
    static let spkRotation: TimeInterval = 7 * 24 * 3600
    public static let spkRetention: TimeInterval = 29 * 24 * 3600

    public static let keychainService = "com.fernlet.heartdrop"
    static let keychainAccount = "prekeyPrivateHalves"

    /// A minted bundle plus its private halves, as persisted in the keychain blob.
    private struct StoredBundle: Codable {
        var bundle: Bundle
        /// Raw representations, index-aligned with `bundle.keys`.
        var privateKeys: [Data]
    }
    /// A minted signed prekey plus its private half, as persisted in the keychain blob.
    private struct StoredSignedPrekey: Codable {
        var prekey: SignedPrekey
        var privateKey: Data
    }
    /// The whole keychain blob: every retained bundle and signed prekey with private halves.
    private struct StoredState: Codable {
        var bundles: [StoredBundle]
        /// OPTIONAL and must stay so: a non-optional field would make synthesized `Codable`
        /// throw on every pre-change keychain blob, and `loadState()` classifies an undecodable
        /// blob as corrupt → empty → mint fresh — stranding the private halves of prekeys
        /// already gossiped, so every in-flight drop would silently fail to open. Pinned by a
        /// regression test that decodes a captured pre-change blob.
        var signedPrekeys: [StoredSignedPrekey]?
    }

    private let keychainService: String
    private let now: () -> Date
    private var cachedState: StoredState?

    public init(keychainService: String = HeartPrekeyStore.keychainService,
                now: @escaping () -> Date = { Date() }) {
        self.keychainService = keychainService
        self.now = now
    }

    // MARK: - Local bundle (mint / top-up)

    /// The bundle to gossip right now — mints on first use, rotates when inside the renewal
    /// horizon, and prunes bundles past expiry + grace. The signed prekey is maintained
    /// alongside (minted on first use, rotated past `spkRotation`, retained `spkRetention`)
    /// and attached to whichever bundle is returned.
    ///
    /// Fail-closed on keychain trouble: an unreadable keychain returns nil rather than an empty
    /// state, because minting over a state we could not read would strand the private halves of
    /// prekeys we already gossiped — every drop sealed to them would then fail to open. A bundle
    /// (or SPK) whose private halves did not persist is likewise never gossiped.
    public func currentBundle() -> Bundle? {
        guard var state = loadState() else { return nil }
        let currentTime = now()
        state.bundles.removeAll { $0.bundle.expires.addingTimeInterval(Self.expiryGrace) < currentTime }

        var signedPrekeys = state.signedPrekeys ?? []
        signedPrekeys.removeAll { $0.prekey.created.addingTimeInterval(Self.spkRetention) < currentTime }
        var currentSPK = signedPrekeys.max(by: { $0.prekey.created < $1.prekey.created })
        // The previous still-gossipable SPK, for the fail-closed path: if a freshly minted SPK's
        // persist fails, this one (already durable) is what may be gossiped instead.
        let persistedSPK = currentSPK.flatMap { $0.prekey.expires > currentTime ? $0 : nil }
        var spkMinted = false
        if currentSPK == nil || currentSPK!.prekey.expires <= currentTime {
            let fresh = mintSignedPrekey(at: currentTime)
            signedPrekeys.append(fresh)
            currentSPK = fresh
            spkMinted = true
        }
        state.signedPrekeys = signedPrekeys

        if let newest = state.bundles.max(by: { $0.bundle.expires < $1.bundle.expires }),
           newest.bundle.expires.timeIntervalSince(currentTime) > Self.renewalHorizon {
            if persist(state) {
                return attaching(currentSPK?.prekey, to: newest.bundle)
            }
            // The prune (and possibly a fresh SPK) didn't land. The bundle itself is already
            // durable, so keep gossiping it — but only ever with a PERSISTED signed prekey.
            return attaching(spkMinted ? persistedSPK?.prekey : currentSPK?.prekey, to: newest.bundle)
        }
        let minted = mint(at: currentTime)
        state.bundles.append(minted)
        guard persist(state) else { return nil }
        return attaching(currentSPK?.prekey, to: minted.bundle)
    }

    private func attaching(_ signedPrekey: SignedPrekey?, to bundle: Bundle) -> Bundle {
        Bundle(
            bundleID: bundle.bundleID,
            created: bundle.created,
            expires: bundle.expires,
            keys: bundle.keys,
            signedPrekey: signedPrekey
        )
    }

    /// The private half for an incoming drop's prekey id — searches every retained bundle
    /// (expired-but-in-grace included) and every retained signed prekey (rotated-out-but-within-
    /// retention included).
    public func privateKey(forPrekeyID id: UUID) -> Curve25519.KeyAgreement.PrivateKey? {
        guard let state = loadState() else { return nil }
        for stored in state.bundles {
            if let index = stored.bundle.keys.firstIndex(where: { $0.id == id }),
               index < stored.privateKeys.count {
                return try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: stored.privateKeys[index])
            }
        }
        for stored in state.signedPrekeys ?? [] where stored.prekey.id == id {
            return try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: stored.privateKey)
        }
        return nil
    }

    /// Drops every retained private half that is past its window, WITHOUT minting anything.
    ///
    /// `currentBundle()` is the only other place retention is enforced, and its caller
    /// (`HeartDropService.currentLocalBundle()`) is consent-gated — so turning away hearts off
    /// froze the `expires + expiryGrace` and `spkRetention` filters forever, and every X25519
    /// private half ever minted stayed in the keychain until a full delete-all. That defeats the
    /// documented "the FS window is the bundle lifetime — bounded, monthly-rotating" property for
    /// exactly the user who opted out (review finding, 2026-07-27). Call this on the consent-off
    /// path and on every sync tick; it is a no-op once nothing is stale.
    ///
    /// Fail-closed like `currentBundle()`: an unreadable keychain prunes nothing rather than
    /// persisting an empty state over halves we simply couldn't read.
    public func pruneRetainedKeys() {
        guard var state = loadState() else { return }
        let currentTime = now()
        let bundlesBefore = state.bundles.count
        let signedBefore = (state.signedPrekeys ?? []).count
        state.bundles.removeAll { $0.bundle.expires.addingTimeInterval(Self.expiryGrace) < currentTime }
        state.signedPrekeys = (state.signedPrekeys ?? []).filter {
            $0.prekey.created.addingTimeInterval(Self.spkRetention) >= currentTime
        }
        guard state.bundles.count != bundlesBefore
                || (state.signedPrekeys ?? []).count != signedBefore else { return }
        if persist(state) {
            FernletAuditLog.log("heartdrop.prekeys.pruned", context: [
                "bundles": "\(bundlesBefore - state.bundles.count)",
                "signed": "\(signedBefore - (state.signedPrekeys ?? []).count)"
            ])
        }
    }

    /// Delete-all seam (Docs/PrivacyWipeCoverage.md).
    public func wipeForDeleteAll() {
        KeychainItem.deleteAll(service: keychainService)
        cachedState = nil
    }

    // MARK: - Storage

    private func mint(at date: Date) -> StoredBundle {
        var entries: [PrekeyEntry] = []
        var privates: [Data] = []
        for _ in 0..<Self.batchSize {
            let key = Curve25519.KeyAgreement.PrivateKey()
            entries.append(PrekeyEntry(id: UUID(), publicKey: key.publicKey.rawRepresentation))
            privates.append(key.rawRepresentation)
        }
        let bundle = Bundle(
            bundleID: UUID(),
            created: date,
            expires: date.addingTimeInterval(Self.bundleLifetime),
            keys: entries
        )
        return StoredBundle(bundle: bundle, privateKeys: privates)
    }

    private func mintSignedPrekey(at date: Date) -> StoredSignedPrekey {
        let key = Curve25519.KeyAgreement.PrivateKey()
        return StoredSignedPrekey(
            prekey: SignedPrekey(
                id: UUID(),
                publicKey: key.publicKey.rawRepresentation,
                created: date,
                expires: date.addingTimeInterval(Self.spkRotation)
            ),
            privateKey: key.rawRepresentation
        )
    }

    /// Nil means "the keychain could not be read", which is NOT the same as "no bundles yet" —
    /// the difference is the whole point (see `currentBundle()`). `errSecItemNotFound` and an
    /// undecodable blob both read as an empty state; any other status fails closed.
    private func loadState() -> StoredState? {
        if let cachedState { return cachedState }
        switch readRow() {
        case .absent:
            return StoredState(bundles: [])
        case .unreadable(let status):
            FernletAuditLog.log("heartdrop.prekeys.readFailed", context: ["status": "\(status)"])
            return nil
        case .found(let data):
            guard let state = try? JSONDecoder().decode(StoredState.self, from: data) else {
                // A corrupt blob is unrecoverable either way: the private halves in it can't be
                // parsed, so treating it as empty (and minting fresh) is the only forward path.
                FernletAuditLog.log("heartdrop.prekeys.corrupt")
                return StoredState(bundles: [])
            }
            cachedState = state
            return state
        }
    }

    /// False when the write did not land — the caller must not treat the state as durable.
    @discardableResult
    private func persist(_ state: StoredState) -> Bool {
        guard let data = try? JSONEncoder().encode(state) else { return false }
        let status = KeychainItem.store(
            data,
            account: Self.keychainAccount,
            service: keychainService,
            accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            synchronizable: false
        )
        guard status == errSecSuccess else {
            // Never cache a state that isn't on disk: the next read must see the keychain's truth
            // rather than an in-memory bundle whose private halves were lost.
            cachedState = nil
            FernletAuditLog.log("heartdrop.prekeys.writeFailed", context: ["status": "\(status)"])
            return false
        }
        cachedState = state
        return true
    }

    // MARK: - Keychain read that distinguishes "absent" from "failed"

    /// Three-way keychain read result — absent (mint fresh) vs unreadable (fail closed) is the
    /// distinction that keeps gossiped private halves from being stranded by a transient error.
    private enum RowRead {
        case found(Data)
        case absent
        case unreadable(OSStatus)
    }

    /// `KeychainItem.load` collapses every failure into nil; this store needs the distinction, so
    /// it issues the query itself (same attributes as `KeychainItem.load`).
    private func readRow() -> RowRead {
        var result: AnyObject?
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: Self.keychainAccount,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true,
            kSecUseDataProtectionKeychain as String: true
        ]
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else { return .unreadable(status) }
            return .found(data)
        case errSecItemNotFound:
            return .absent
        default:
            return .unreadable(status)
        }
    }
}
