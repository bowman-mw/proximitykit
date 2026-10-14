// PackageTestEnvironment.swift
// ProximityKitTests
//
// ProximityKit plan step A1.1: the package test bundle's one-time setup. Swift Testing has no bundle-level
// set-up, and an unhosted bundle has no app whose launch could run one, so what the bundle must install
// before its first ProximityKit call is installed lazily, by a `static let` whose initializer the runtime
// runs exactly once, on the first read, whichever suite reads it first. Whatever reaches the keychain
// from a package test reads it first.

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
/// **Once, from any thread.** A `static let`'s initializer runs once under the runtime's guard, so
/// parallel suites racing to read it all get the one store, installed before any of them gets it.
enum PackageTestEnvironment {

    /// The bundle's in-memory keychain, ProximityKit's keychain backend from the first read on.
    static let keychain: PackageKeychainStore = {
        let store = PackageKeychainStore()
        ProximityKeychainItem.installBackend(store)
        return store
    }()
}
