// PackageSwitchableInstallBinding.swift
// ProximityKitTests
//
// ProximityKit plan step A1, the split's second batch of copied suites: the install binding a cell can
// switch, for the store suites the third batch copies from the Fernlet repository's tests. Those suites
// seal and open the two mesh stores under Fernlet's `FernletDeviceBindingAdapter`, which reads
// FernletCrypto's `DeviceBindingID` at each call, and switch what it answers for the work a closure
// wraps with `DeviceBindingID.$testOverride.withValue(...)`: another install's bytes, an absent binding,
// or a read that fails. This package can name neither type, and `PackageTestHost`'s
// `PinnedInstallBinding` answers the same bytes whatever a cell does. So this double answers as that
// adapter does, case for case, from a task-local override a cell binds the same way, and a copied call
// site reads `PackageSwitchableInstallBinding.testOverride.withValue(...)` where Fernlet's reads
// `DeviceBindingID.$testOverride.withValue(...)`.

import Foundation
import ProximityKit
import Security

/// An install binding whose answer a cell switches for the work it wraps: this package's stand-in for
/// Fernlet's `FernletDeviceBindingAdapter` over `DeviceBindingID`, read at each seal and open.
///
/// **With no override** it answers ``installBytes`` for a seal and an open alike, as the adapter answers
/// the one row an install holds: every instance answers the same bytes, so a store sealed through one
/// opens through another, as two adapters over one install's row agree.
///
/// **With an override**, bound with `PackageSwitchableInstallBinding.testOverride.withValue(_:operation:)`
/// for the work it wraps and no longer, it answers as `DeviceBindingID.current()` (a seal) and
/// `DeviceBindingID.currentForOpen()` (an open) answer under the same override of theirs, through the
/// adapter: ``TestOverride/identifier(_:)`` answers those bytes for both; ``TestOverride/unavailable``
/// answers `nil` for both, an authoritatively absent binding; ``TestOverride/readError`` answers `nil`
/// for a seal, which refuses it, and throws ``ProximityInstallBindingReadError`` with `errSecIO`, the
/// status `DeviceBindingID` throws, for an open, which defers it. `DeviceBindingID`'s fourth case,
/// `scripted`, which flips an answer partway through an operation, has no caller in Fernlet's tests and
/// none here.
///
/// **Task-local, so parallel suites never see one another's override.** It is held in a `static let`
/// over `TaskLocal`, not through the property wrapper's stored `static var`, as
/// `PackageAuditCapture`'s mark is; a store reads it synchronously on the task that seals or opens, so
/// an override bound around a call reaches the stores that call reaches.
nonisolated struct PackageSwitchableInstallBinding: ProximityInstallBinding {

    /// What the binding answers instead of ``installBytes`` while a cell holds it: `DeviceBindingID`'s
    /// three fixed test overrides, case for case.
    enum TestOverride: Equatable, Sendable {
        /// Answer exactly these bytes, as another install would.
        case identifier(Data)
        /// Answer `nil`, as an install whose binding is authoritatively absent does: a seal refuses and an
        /// open refuses, terminally.
        case unavailable
        /// Answer as a read whose outcome is unknown: `nil` for a seal, which refuses it, and a thrown
        /// ``ProximityInstallBindingReadError`` for an open, which defers it, retryably.
        case readError
    }

    /// The override in force on the task that reads it, or `nil` outside every one.
    static let testOverride = TaskLocal<TestOverride?>(wrappedValue: nil)

    /// The bytes every instance answers with no override: this test install's binding, sixteen fixed
    /// bytes, as `DeviceBindingID`'s row holds sixteen.
    static let installBytes = Data(repeating: 0x5B, count: 16)

    /// This install's binding for `access`, or the override's answer while one is bound.
    ///
    /// - Parameter access: Whether the caller seals or opens.
    /// - Returns: ``installBytes``, the override's bytes, or `nil` for an absent binding or, for a seal,
    ///   a read that failed.
    /// - Throws: ``ProximityInstallBindingReadError`` with `errSecIO` when an open's read fails under
    ///   ``TestOverride/readError``.
    func read(for access: ProximityInstallBindingAccess) throws(ProximityInstallBindingReadError) -> Data? {
        guard let override = Self.testOverride.get() else { return Self.installBytes }
        switch override {
        case .identifier(let bytes):
            return bytes
        case .unavailable:
            return nil
        case .readError:
            guard access == .open else { return nil }
            throw ProximityInstallBindingReadError(status: errSecIO)
        }
    }
}
