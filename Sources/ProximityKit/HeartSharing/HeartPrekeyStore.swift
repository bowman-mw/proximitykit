import Foundation
import CryptoKit
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

    public struct PrekeyEntry: Codable, Equatable, Sendable {
        public let id: UUID
        public let publicKey: Data
        public init(id: UUID, publicKey: Data) {
            self.id = id
            self.publicKey = publicKey
        }
    }

    /// The gossiped shape — public halves only. Codable so it rides `IdentityRangingPayload`
    /// as an optional field old decoders ignore.
    public struct Bundle: Codable, Equatable, Sendable {
        public let bundleID: UUID
        public let created: Date
        public let expires: Date
        public let keys: [PrekeyEntry]
        public init(bundleID: UUID, created: Date, expires: Date, keys: [PrekeyEntry]) {
            self.bundleID = bundleID
            self.created = created
            self.expires = expires
            self.keys = keys
        }
    }

    static let batchSize = 16
    static let bundleLifetime: TimeInterval = 30 * 24 * 3600
    /// Mint a fresh bundle when the current one has less life than this left.
    static let renewalHorizon: TimeInterval = 7 * 24 * 3600
    /// Keep expired bundles' private halves this much longer — an in-flight drop sealed just
    /// before expiry must still open (mirrors bitchat's consumed-prekey grace window).
    static let expiryGrace: TimeInterval = 48 * 3600

    public static let keychainService = "com.fernlet.heartdrop"
    static let keychainAccount = "prekeyPrivateHalves"

    private struct StoredBundle: Codable {
        var bundle: Bundle
        /// Raw representations, index-aligned with `bundle.keys`.
        var privateKeys: [Data]
    }
    private struct StoredState: Codable {
        var bundles: [StoredBundle]
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
    /// horizon, and prunes bundles past expiry + grace.
    public func currentBundle() -> Bundle? {
        var state = loadState()
        let currentTime = now()
        state.bundles.removeAll { $0.bundle.expires.addingTimeInterval(Self.expiryGrace) < currentTime }
        if let newest = state.bundles.max(by: { $0.bundle.expires < $1.bundle.expires }),
           newest.bundle.expires.timeIntervalSince(currentTime) > Self.renewalHorizon {
            persist(state)
            return newest.bundle
        }
        guard let minted = mint(at: currentTime) else {
            persist(state)
            return state.bundles.last?.bundle
        }
        state.bundles.append(minted)
        persist(state)
        return minted.bundle
    }

    /// The private half for an incoming drop's prekey id — searches every retained bundle
    /// (expired-but-in-grace included).
    public func privateKey(forPrekeyID id: UUID) -> Curve25519.KeyAgreement.PrivateKey? {
        let state = loadState()
        for stored in state.bundles {
            if let index = stored.bundle.keys.firstIndex(where: { $0.id == id }),
               index < stored.privateKeys.count {
                return try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: stored.privateKeys[index])
            }
        }
        return nil
    }

    /// Delete-all seam (Docs/PrivacyWipeCoverage.md).
    public func wipeForDeleteAll() {
        KeychainItem.deleteAll(service: keychainService)
        cachedState = nil
    }

    // MARK: - Storage

    private func mint(at date: Date) -> StoredBundle? {
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

    private func loadState() -> StoredState {
        if let cachedState { return cachedState }
        guard let data = KeychainItem.load(account: Self.keychainAccount, service: keychainService),
              let state = try? JSONDecoder().decode(StoredState.self, from: data) else {
            return StoredState(bundles: [])
        }
        cachedState = state
        return state
    }

    private func persist(_ state: StoredState) {
        cachedState = state
        guard let data = try? JSONEncoder().encode(state) else { return }
        KeychainItem.store(
            data,
            account: Self.keychainAccount,
            service: keychainService,
            accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            synchronizable: false
        )
    }
}
