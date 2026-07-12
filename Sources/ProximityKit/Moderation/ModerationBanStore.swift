// ModerationBanStore.swift
// ProximityKit/Moderation
//
// The tamper-resistant store-ban clock (2026-07-11 ban memo). A designer whose items are repeatedly
// reported loses their shop for 30 days — and that ban must survive app delete+reinstall AND device
// clock changes.
//
//  * Reinstall-proof: the ban record lives in the Keychain under a DEDICATED service
//    (`com.fernlet.moderation`, ThisDeviceOnly, non-synchronizable). Data-protection keychain items
//    survive app uninstall, and this service is never wiped by the app lock reset or identity wipe.
//    The self-ban is keyed to a CONSTANT device account (not the identity pubkey), so minting a fresh
//    identity does not clear it.
//  * Clock-tamper-proof: a credited-time countdown reusing FernletLockService's monotonic-anchor
//    pattern, with two deliberate upgrades — (1) `mach_continuous_time` (counts sleep) so a month-long
//    ban accrues in real time, and (2) a persisted wall-clock high-water ratchet: rolling the clock
//    back trips the trap (voids any wall-credited time and keeps the ban active); jumping forward
//    credits nothing (monotonic time barely moves) and is caught on the return by the ratchet.
//
// Enforcement is at LIST + BROADCAST time in FernletStore. This self-enforcement is honest-client
// compliance; the load-bearing enforcement is receiver-side (peers hide/peer-ban) — see the memo.

import Foundation
import Observation
import Security
import FernletFoundation
import FernletDomainModel

nonisolated struct BanRecord: Codable {
    var banID: UUID
    var subject: String
    var durationSeconds: Double
    var startedAtWall: Double
    var creditedMonotonic: Double
    var creditedWall: Double
    var lastCheckMonotonic: Double
    var lastCheckWall: Double
    var maxObservedWall: Double
    var tamperCount: Int
}

@MainActor
@Observable
public final class ModerationBanStore {
    @ObservationIgnored private let service: String
    @ObservationIgnored private let clock: MonotonicClock
    @ObservationIgnored private let date: () -> Date

    /// Generous slack (26h) absorbs any legitimate timezone / NTP jitter before a backward move reads
    /// as tampering. All ban math is on absolute `timeIntervalSinceReferenceDate`, so timezone changes
    /// move nothing.
    @ObservationIgnored private static let clockSlack: Double = 26 * 3600
    /// Constant device account: identity-independent so wiping/minting a new identity can't clear it.
    @ObservationIgnored private static let selfAccount = "selfBan.device"
    /// A single reboot may credit at most this much wall time. Caps the "jump the clock far forward,
    /// then reboot" attack (the monotonic clock resets on reboot, so the shutdown-gap branch runs and
    /// would otherwise credit the whole forward jump). A device is rarely off longer than this; a
    /// genuinely long shutdown just serves the ban slightly slower (safe direction). Repeated
    /// forward-ONLY reboots remain the accepted residual — they need a permanently-ahead clock, which
    /// breaks every day-keyed feature of the app.
    @ObservationIgnored private static let maxRebootGapCreditSeconds: Double = 2 * 86_400

    public init(
        service: String = "com.fernlet.moderation",
        clock: MonotonicClock = SystemMonotonicClock(),
        date: @escaping () -> Date = Date.init
    ) {
        self.service = service
        self.clock = clock
        self.date = date
    }

    // MARK: - Apply

    /// Bans this device's store for `durationDays`. No-op if a self-ban is already active (never resets
    /// or extends an in-flight ban).
    public func applySelfBan(durationDays: Int = ClothingModerationLimits.banDurationDays) {
        writeBanIfNotActive(account: Self.selfAccount, subject: "self", durationDays: durationDays)
    }

    /// Bans a peer designer (by fingerprint) locally — this device drops their catalogs for the duration.
    public func applyPeerBan(fingerprint: String, durationDays: Int = ClothingModerationLimits.banDurationDays) {
        writeBanIfNotActive(account: Self.peerAccount(fingerprint), subject: "peer:\(fingerprint)", durationDays: durationDays)
    }

    // MARK: - Query (refresh-on-read)

    public var isSelfBanned: Bool { remainingSeconds(account: Self.selfAccount) > 0 }
    public func selfBanRemainingSeconds() -> Double { remainingSeconds(account: Self.selfAccount) }
    public func isPeerBanned(fingerprint: String) -> Bool { remainingSeconds(account: Self.peerAccount(fingerprint)) > 0 }

    /// TEST/diagnostic: the recorded clock-tamper count for the self-ban.
    public func selfBanTamperCount() -> Int { (load(account: Self.selfAccount)?.tamperCount) ?? 0 }

    // MARK: - Escalation reconcile (fed by the moderation ledger; Phase 3b adds peers' reports)

    /// Applies self/peer bans that the verified report set now warrants. Idempotent.
    public func reconcile(rows: [ModerationLedgerEntry], localSigningKey: Data) {
        let now = date()
        if !isSelfBanned,
           ModerationEconomy.shouldBanDesigner(subjectKey: localSigningKey, in: rows, now: now) {
            applySelfBan()
        }
        let subjects = Set(rows.map { $0.subjectSigningPublicKey }).subtracting([localSigningKey, Data()])
        for subject in subjects
        where ModerationEconomy.shouldBanDesigner(subjectKey: subject, in: rows, now: now) {
            let fingerprint = IdentityService.fingerprint(of: subject)
            if !isPeerBanned(fingerprint: fingerprint) { applyPeerBan(fingerprint: fingerprint) }
        }
    }

    /// Deliberately NOT called from "Reset everything": a self-ban must survive a data reset (that is
    /// the whole point). Exposed only for tests to clean up the shared keychain service.
    public func clearAllForTesting() {
        KeychainItem.deleteAll(service: service)
    }

    // MARK: - Internals

    private static func peerAccount(_ fingerprint: String) -> String { "peerBan:\(fingerprint)" }

    private func writeBanIfNotActive(account: String, subject: String, durationDays: Int) {
        guard remainingSeconds(account: account) <= 0 else { return }
        let nowWall = date().timeIntervalSinceReferenceDate
        let record = BanRecord(
            banID: UUID(), subject: subject, durationSeconds: Double(durationDays) * 86_400,
            startedAtWall: nowWall, creditedMonotonic: 0, creditedWall: 0,
            lastCheckMonotonic: clock.seconds, lastCheckWall: nowWall,
            maxObservedWall: nowWall, tamperCount: 0)
        save(record, account: account)
        FernletAuditLog.log("storeBan.applied", context: ["subject": subject, "days": "\(durationDays)"])
    }

    /// The credited-time countdown. Returns remaining ban seconds (0 = not banned / served).
    private func remainingSeconds(account: String) -> Double {
        guard var record = load(account: account) else { return 0 }
        let nowWall = date().timeIntervalSinceReferenceDate
        let nowMono = clock.seconds

        if nowMono + 1.0 >= record.lastCheckMonotonic {
            // Same boot: monotonic time (which counts sleep) is the real elapsed credit.
            record.creditedMonotonic += max(0, nowMono - record.lastCheckMonotonic)
        } else {
            // Reboot: the monotonic clock reset. Credit the (unobservable) shutdown gap from the wall
            // clock — but CAP it, so "jump the clock far forward, then reboot" can't instant-serve the
            // ban in a single reboot. The high-water ratchet below still voids all wall credit if the
            // clock is later rolled back.
            let gap = max(0, nowWall - record.lastCheckWall)
            record.creditedWall += min(gap, Self.maxRebootGapCreditSeconds)
            FernletAuditLog.log("storeBan.rebootFallback", context: ["account": account])
        }

        record.maxObservedWall = max(record.maxObservedWall, nowWall)
        let inRegression = nowWall + Self.clockSlack < record.maxObservedWall
        if inRegression {
            // Clock rolled back below its high-water mark: void any wall-credited time and flag the
            // tampering. Monotonic credit is physically real and is never revoked. `inRegression` also
            // keeps the ban unexpired below until the wall clock climbs back to the high-water mark.
            record.creditedWall = 0
            record.tamperCount += 1
            FernletAuditLog.log("storeBan.clockRegressionDetected",
                                context: ["account": account, "tamperCount": "\(record.tamperCount)"])
        }

        record.lastCheckMonotonic = nowMono
        record.lastCheckWall = nowWall
        save(record, account: account)

        let credited = record.creditedMonotonic + record.creditedWall
        if credited >= record.durationSeconds && !inRegression {
            return 0
        }
        return max(0, record.durationSeconds - credited)
    }

    private func load(account: String) -> BanRecord? {
        guard let data = KeychainItem.load(account: account, service: service) else { return nil }
        return try? JSONDecoder().decode(BanRecord.self, from: data)
    }

    private func save(_ record: BanRecord, account: String) {
        guard let data = try? JSONEncoder().encode(record) else { return }
        _ = KeychainItem.store(
            data, account: account, service: service,
            accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, synchronizable: false)
    }
}
