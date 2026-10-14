// PackageTestEnvironment.swift
// ProximityKitTests
//
// ProximityKit plan step A1.1: the package test bundle's one-time setup. Swift Testing has no bundle-level
// set-up, and an unhosted bundle has no app whose launch could run one, so what the bundle must install
// before its first ProximityKit call is installed lazily, by `static let`s whose initializers the runtime
// runs exactly once, on the first read, whichever suite reads them first. Whatever reaches the keychain
// from a package test reads `keychain` first, and whatever reads ProximityKit's audit lines reads `audit`
// first: a `PackageAuditCapture` does as it is built, and a `PackageTestHost` reads both.

@testable import ProximityKit

/// The package test bundle's environment, set up once, on first touch.
///
/// **The keychain.** ``keychain`` is the bundle's in-memory keychain, a ``PackageKeychainStore``,
/// installed as ProximityKit's keychain backend before the first read returns it. This bundle is
/// unhosted, so the system keychain answers it `errSecMissingEntitlement` (-34018) on the simulator and is
/// the developer's own on a Mac; a suite or helper that reaches the keychain (an identity's provisioning,
/// a seal key, a call of the keychain funnel itself) reads ``keychain`` first, so every such call reaches
/// the store. This is the one caller of the funnel's install door in either test target: Fernlet's
/// hosted tests install nothing and run against the system keychain.
///
/// **The audit sink.** ``audit`` is the bundle's ``PackageAuditSink``, installed with ProximityKit's
/// `ProximityAudit.install(_:)` before the first read returns it. No app installs a sink in this bundle,
/// and ProximityKit drops every line while none is installed, so a check that a line was not logged
/// would pass whatever the code did; every ``PackageAuditCapture`` registers with ``audit`` as it is
/// built, so the sink is installed before any capture exists. This is the one install of a sink in
/// either test target: Fernlet's hosted tests inherit the bridge `FernletApp.init` installs, and
/// Fernlet's `ProximityAuditBridgeTests` holds both.
///
/// **Once, from any thread.** A `static let`'s initializer runs once under the runtime's guard, so
/// parallel suites racing to read one all get the one value, installed before any of them gets it.
enum PackageTestEnvironment {

    /// The bundle's in-memory keychain, ProximityKit's keychain backend from the first read on.
    static let keychain: PackageKeychainStore = {
        let store = PackageKeychainStore()
        ProximityKeychainItem.installBackend(store)
        return store
    }()

    /// The bundle's audit sink, the one every ProximityKit audit line goes to from the first read on.
    static let audit: PackageAuditSink = {
        let sink = PackageAuditSink()
        ProximityAudit.install(sink)
        return sink
    }()
}
