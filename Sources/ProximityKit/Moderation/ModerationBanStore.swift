// ModerationBanStore.swift
// ProximityKit/Moderation
//
// The tamper-resistant store-ban clock (2026-07-11 ban memo). A designer whose items are repeatedly
// reported loses their shop for 30 days — and that ban must survive app delete+reinstall AND device
// clock changes.
//
//  * Reinstall-proof: the ban record lives in the Keychain under a DEDICATED service
//    (`com.fernlet.moderation`, ThisDeviceOnly, non-synchronizable). Data-protection keychain items
//    survive app uninstall, and the SELF-ban row is never wiped by the app lock reset, identity wipe,
//    or "Delete everything" (2026-07-17 decision: a ban a wipe could clear is a ban-evasion tool).
//    It is keyed to a CONSTANT device account (not the identity pubkey), so minting a fresh identity
//    does not clear it. PEER-ban rows are the opposite case — 30-day records about OTHER people,
//    keyed to their identity fingerprints — and the delete-everything funnel clears them
//    (`clearPeerBansForDeleteAll`): a wiped device must not keep data about others.
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

/// The keychain-persisted state of one store ban: duration, credited monotonic/wall time, the
/// clock high-water ratchet, tamper count, and the artworks the ban already answered for.
///
/// Written and refreshed on every read by ``ModerationBanStore``'s credited-time countdown;
/// stored per account (self vs per-peer) under the dedicated moderation keychain service.
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
    /// Hex content hashes of the artworks whose reports have already triggered a ban of this subject
    /// (cumulative across successive bans). A served ban keeps its record, so this high-water mark lets
    /// `reconcile` re-arm only on a NEW qualifying artwork — the same still-non-decayed reports can't
    /// silently re-mint the 30-day ban. Optional so records written before this field decode cleanly.
    var handledContentHashes: [String]? = nil
}

/// The tamper-resistant 30-day store-ban clock for repeatedly-reported clothing designers —
/// self-bans (this device's shop) and local peer bans (their catalogs are dropped).
///
/// Survives app delete+reinstall (records live in the Keychain under the dedicated
/// `com.fernlet.moderation` service, ThisDeviceOnly, never wiped by identity resets — the
/// self-ban is keyed to a constant device account, not the identity key) and survives device
/// clock changes (a credited-time countdown over `mach_continuous_time` plus a wall-clock
/// high-water ratchet: rollback voids wall credit and flags tampering; a forward jump credits
/// almost nothing, and the reboot-gap credit is capped). `reconcile` applies bans the verified
/// report set warrants, re-arming a served ban only on a NEW qualifying artwork. Enforcement
/// here is honest-client compliance at list/broadcast time; the load-bearing enforcement is
/// receiver-side.
///
/// "Delete everything" splits the two record kinds: the SELF-ban is deliberately NOT cleared
/// (2026-07-17 decision — a device ban must survive a wipe or the wipe is a ban-evasion tool),
/// while PEER-ban rows — records about other people, keyed to identity fingerprints the wipe's
/// identity rotation just disowned — are cleared via ``clearPeerBansForDeleteAll()``.
/// `@MainActor @Observable`.
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
    /// or extends an in-flight ban). `handledContentHashes` records the artworks this ban answers for.
    public func applySelfBan(durationDays: Int = ClothingModerationLimits.banDurationDays,
                             handledContentHashes: Set<String> = []) {
        writeBanIfNotActive(account: Self.selfAccount, subject: "self", durationDays: durationDays,
                            handledContentHashes: handledContentHashes)
    }

    /// Bans a peer designer (by fingerprint) locally — this device drops their catalogs for the duration.
    public func applyPeerBan(fingerprint: String, durationDays: Int = ClothingModerationLimits.banDurationDays,
                             handledContentHashes: Set<String> = []) {
        writeBanIfNotActive(account: Self.peerAccount(fingerprint), subject: "peer:\(fingerprint)",
                            durationDays: durationDays, handledContentHashes: handledContentHashes)
    }

    // MARK: - Query (refresh-on-read)

    public var isSelfBanned: Bool { remainingSeconds(account: Self.selfAccount) > 0 }
    public func selfBanRemainingSeconds() -> Double { remainingSeconds(account: Self.selfAccount) }
    public func isPeerBanned(fingerprint: String) -> Bool { remainingSeconds(account: Self.peerAccount(fingerprint)) > 0 }

    /// TEST/diagnostic: the recorded clock-tamper count for the self-ban.
    public func selfBanTamperCount() -> Int { (load(account: Self.selfAccount)?.tamperCount) ?? 0 }

    // MARK: - Escalation reconcile (fed by the moderation ledger; Phase 3b adds peers' reports)

    /// Applies self/peer bans that the verified report set now warrants. Idempotent — and a served ban is
    /// re-armed only by a NEW qualifying artwork, never by the same still-non-decayed reports (so a 30-day
    /// ban stays 30 days instead of re-minting every reconcile for the reports' full 180-day lifetime).
    public func reconcile(rows: [ModerationLedgerEntry], localSigningKey: Data) {
        let now = date()
        if let hashes = evidenceWarrantingBan(account: Self.selfAccount, subjectKey: localSigningKey, rows: rows, now: now) {
            applySelfBan(handledContentHashes: hashes)
        }
        let subjects = Set(rows.map { $0.subjectSigningPublicKey }).subtracting([localSigningKey, Data()])
        for subject in subjects {
            let fingerprint = IdentityService.fingerprint(of: subject)
            if let hashes = evidenceWarrantingBan(account: Self.peerAccount(fingerprint), subjectKey: subject, rows: rows, now: now) {
                applyPeerBan(fingerprint: fingerprint, handledContentHashes: hashes)
            }
        }
    }

    /// The currently-qualifying artwork hashes to record IF a (re)ban should fire now, else nil. Returns
    /// nil when a ban is already active, when the designer is below the ban threshold, or when a prior
    /// (served) ban already covered every currently-qualifying artwork — the last case is what stops a
    /// served ban from re-minting off unchanged evidence.
    private func evidenceWarrantingBan(account: String, subjectKey: Data, rows: [ModerationLedgerEntry], now: Date) -> Set<String>? {
        guard remainingSeconds(account: account) <= 0 else { return nil }
        guard ModerationEconomy.shouldBanDesigner(subjectKey: subjectKey, in: rows, now: now) else { return nil }
        let currentHex = Set(ModerationEconomy.unlistableContentHashes(ofDesigner: subjectKey, in: rows, now: now)
            .map { ModerationLedgerEntry.hex($0) })
        if let prior = load(account: account)?.handledContentHashes,
           currentHex.subtracting(Set(prior)).isEmpty {
            return nil   // a prior ban already answered for all of this; no new offense
        }
        return currentHex
    }

    // MARK: - Delete-everything clear (peer records ONLY)

    /// Removes every peer-ban record — the keychain rows keyed to OTHER designers' identity
    /// fingerprints (`peerBan:` accounts) — for the "Delete everything" funnel. The SELF-ban row
    /// in the same service deliberately survives (2026-07-17 decision: a device ban must outlive
    /// a wipe or the wipe is a ban-evasion tool); peer rows are the opposite case — data about
    /// other people, addressed to fingerprints the wipe's identity rotation just disowned — so
    /// the wipe must take them.
    ///
    /// - Returns: false when the peer rows could not be enumerated at all, or when any enumerated
    ///   row survived its delete (R7: the funnel reports it as an incomplete store instead of
    ///   promising a clean wipe over a record still in the keychain). The enumeration leg matters
    ///   as much as the delete leg: `KeychainItem.loadAll` collapses a failed enumeration into
    ///   `[]`, which here would mean zero accounts to delete, zero failures, and a CLEAN result
    ///   reported over surviving peer bans — so this goes through
    ///   `KeychainItem.loadAllDistinguishingFailure` instead. `errSecItemNotFound` is not a
    ///   failure: a service holding no rows is genuinely clear. In practice the wipe runs
    ///   post-unlock in the foreground, where the data-protection keychain is available, so a real
    ///   enumeration failure is rare — but "rare" is not "reported honestly".
    public func clearPeerBansForDeleteAll() -> Bool {
        let peerAccounts: [String]
        switch KeychainItem.loadAllDistinguishingFailure(service: service) {
        case .rows(let rows):
            // Bounded: one pass over the finite row set the keychain returned. Labeled-tuple member
            // access, not destructuring — only the account names matter here, and taking them now
            // drops every row's sealed record payload rather than carrying it through the deletes.
            peerAccounts = rows.map { $0.account }.filter { $0.hasPrefix(Self.peerAccountPrefix) }
        case .unreadable(let status):
            // No account names were read, so nothing identifying can reach the audit trail here even
            // by accident — only the status that stopped the enumeration.
            FernletAuditLog.log("storeBan.peerClearEnumerationFailed", context: ["status": "\(status)"])
            return false
        }
        var failures = 0
        for account in peerAccounts
        where KeychainItem.deleteReportingStatus(account: account, service: service) != errSecSuccess {
            // `deleteReportingStatus` normalizes not-found to success, so this is a genuine survivor.
            failures += 1
        }
        guard failures == 0 else {
            // Counts only — the fingerprint inside the account name is exactly the data being erased,
            // so it must not ride into the audit trail.
            FernletAuditLog.log("storeBan.peerClearFailed",
                                context: ["failures": "\(failures)", "total": "\(peerAccounts.count)"])
            return false
        }
        FernletAuditLog.log("storeBan.peerBansCleared", context: ["count": "\(peerAccounts.count)"])
        return true
    }

    /// Deliberately NOT called from "Reset everything": a self-ban must survive a data reset (that is
    /// the whole point). Exposed only for tests to clean up the shared keychain service.
    public func clearAllForTesting() {
        KeychainItem.deleteAll(service: service)
    }

    // MARK: - Internals

    /// Frozen persisted keychain-account prefix for peer-ban rows — the selector
    /// ``clearPeerBansForDeleteAll()`` keys the peer/self split on. Never localized, never renamed:
    /// existing records are filed under it.
    @ObservationIgnored private static let peerAccountPrefix = "peerBan:"

    private static func peerAccount(_ fingerprint: String) -> String { peerAccountPrefix + fingerprint }

    private func writeBanIfNotActive(account: String, subject: String, durationDays: Int,
                                     handledContentHashes: Set<String>) {
        guard remainingSeconds(account: account) <= 0 else { return }
        // Carry forward the artworks any prior (served) ban already covered, so the high-water mark only grows.
        let merged = Set(load(account: account)?.handledContentHashes ?? []).union(handledContentHashes)
        let nowWall = date().timeIntervalSinceReferenceDate
        let record = BanRecord(
            banID: UUID(), subject: subject, durationSeconds: Double(durationDays) * 86_400,
            startedAtWall: nowWall, creditedMonotonic: 0, creditedWall: 0,
            lastCheckMonotonic: clock.seconds, lastCheckWall: nowWall,
            maxObservedWall: nowWall, tamperCount: 0,
            handledContentHashes: merged.isEmpty ? nil : Array(merged))
        guard save(record, account: account) else { return }   // R7: never report an unwritten ban as applied
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
        // The countdown bookkeeping is re-derived from the record on every read, so a failed write
        // costs at most this tick's credit; `save` has already logged it (R7).
        _ = save(record, account: account)

        let credited = record.creditedMonotonic + record.creditedWall
        if credited >= record.durationSeconds && !inRegression {
            return 0
        }
        return max(0, record.durationSeconds - credited)
    }

    private func load(account: String) -> BanRecord? {
        guard let data = KeychainItem.load(account: account, service: service) else { return nil }
        do {
            return try JSONDecoder().decode(BanRecord.self, from: data)
        } catch {
            // Every caller reads nil as "not banned", so a corrupt row silently LIFTS a ban.
            // It still lifts (there is nothing left to enforce against), but not silently.
            FernletAuditLog.log("storeBan.corruptRecord", context: ["account": account])
            return nil
        }
    }

    /// False when the record did not reach the keychain — a ban that never persisted takes no
    /// effect at all, so the caller must not report it as applied (R7).
    private func save(_ record: BanRecord, account: String) -> Bool {
        guard let data = try? JSONEncoder().encode(record) else {
            FernletAuditLog.log("storeBan.encodeFailed", context: ["account": account])
            return false
        }
        let status = KeychainItem.store(
            data, account: account, service: service,
            accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, synchronizable: false)
        guard status == errSecSuccess else {
            FernletAuditLog.log("storeBan.saveFailed",
                                context: ["account": account, "status": "\(status)"])
            return false
        }
        return true
    }
}
