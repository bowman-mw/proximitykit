// ProximityNamespace+Installation.swift
// ProximityKit/Namespace
//
// The installation half of `ProximityNamespace`: what belongs to one app on one device. Names only:
// each keychain row's accessibility and synchronizable class stay ProximityKit code, where the
// key-custody walls read them, and the directory the names resolve under stays the host's to pass.

import Foundation

nonisolated extension ProximityNamespace {

    // MARK: - Installation

    /// What belongs to this app on this device: its keychain rows, its storage names and its log
    /// subsystem.
    ///
    /// Two apps of one family keep separate installations, so they share a wire and never a key, a file
    /// or a log stream. That matters most on an unsandboxed Mac, where two apps can otherwise reach
    /// the same Application Support folder.
    public nonisolated struct Installation: Hashable, Sendable {
        /// The keychain rows ProximityKit writes for the device identity and the two mesh seal keys.
        public let keychain: Keychain
        /// The default directory's name and the two mesh stores' on-disk names.
        public let storage: Storage
        /// The `os.Logger` subsystem the three radios log under. Never on the wire.
        public let logSubsystem: String

        /// Assembles an installation.
        ///
        /// - Parameters:
        ///   - keychain: The identity's and the two mesh seal keys' keychain rows.
        ///   - storage: The default directory's name and the two mesh stores' on-disk names.
        ///   - logSubsystem: The radios' log subsystem.
        public init(keychain: Keychain, storage: Storage, logSubsystem: String) {
            self.keychain = keychain
            self.storage = storage
            self.logSubsystem = logSubsystem
        }
    }

    // MARK: - Keychain

    /// The names of the keychain rows ProximityKit writes for the device identity and the two mesh seal
    /// keys. The heart-drop and moderation keychain services are still ProximityKit literals until
    /// plan step A0.4 takes their features out.
    ///
    /// Row names only. Each row's accessibility and synchronizable class stay ProximityKit code, where
    /// the key-custody walls read them: a host names its rows and never weakens how they are kept.
    public nonisolated struct Keychain: Hashable, Sendable {

        /// One keychain row: a service and an account.
        public nonisolated struct Row: Hashable, Sendable {
            /// The row's keychain service.
            public let service: String
            /// The row's account within that service.
            public let account: String

            /// Names one row.
            ///
            /// - Parameters:
            ///   - service: The row's keychain service.
            ///   - account: The row's account within that service.
            public init(service: String, account: String) {
                self.service = service
                self.account = account
            }
        }

        /// The device identity's rows: one service, four accounts.
        public nonisolated struct IdentityRows: Hashable, Sendable {
            /// The keychain service holding all four rows.
            public let service: String
            /// The Ed25519 signing private key's account.
            public let signingPrivateKey: String
            /// The X25519 key-agreement private key's account.
            public let keyAgreementPrivateKey: String
            /// The cached signing public key's account.
            public let signingPublicKeyCache: String
            /// The cached key-agreement public key's account.
            public let keyAgreementPublicKeyCache: String

            /// Names the identity's rows.
            ///
            /// - Parameters:
            ///   - service: The keychain service holding all four rows.
            ///   - signingPrivateKey: The signing private key's account.
            ///   - keyAgreementPrivateKey: The key-agreement private key's account.
            ///   - signingPublicKeyCache: The cached signing public key's account.
            ///   - keyAgreementPublicKeyCache: The cached key-agreement public key's account.
            public init(
                service: String, signingPrivateKey: String, keyAgreementPrivateKey: String,
                signingPublicKeyCache: String, keyAgreementPublicKeyCache: String
            ) {
                self.service = service
                self.signingPrivateKey = signingPrivateKey
                self.keyAgreementPrivateKey = keyAgreementPrivateKey
                self.signingPublicKeyCache = signingPublicKeyCache
                self.keyAgreementPublicKeyCache = keyAgreementPublicKeyCache
            }
        }

        /// The device identity's rows.
        public let identity: IdentityRows
        /// The row of the key that seals the mesh-session context file.
        public let meshSessionSealKey: Row
        /// The row of the key that seals the routed store.
        public let meshRoutedSealKey: Row

        /// Names the identity's and the two mesh seal keys' keychain rows.
        ///
        /// - Parameters:
        ///   - identity: The device identity's rows.
        ///   - meshSessionSealKey: The mesh-session seal key's row.
        ///   - meshRoutedSealKey: The routed store's seal key's row.
        public init(identity: IdentityRows, meshSessionSealKey: Row, meshRoutedSealKey: Row) {
            self.identity = identity
            self.meshSessionSealKey = meshSessionSealKey
            self.meshRoutedSealKey = meshRoutedSealKey
        }
    }

    // MARK: - Storage

    /// The on-disk names ProximityKit writes for its default directory and the two mesh stores. Until
    /// plan step A0.4 the heart-drop scope and the feature ledgers default instead to
    /// ``ProximitySupportLayout/defaultDirectory``, which spells Fernlet's folder.
    public nonisolated struct Storage: Hashable, Sendable {
        /// The folder under Application Support that a host passing no root of its own gets.
        public let directoryName: String
        /// The sealed mesh-session context file.
        public let meshSessionContextFileName: String
        /// The routed store's sealed index file.
        public let meshRoutedIndexFileName: String
        /// The directory holding the routed store's chunk files.
        public let meshRoutedChunkDirectoryName: String

        /// Names the default directory and the two mesh stores' on-disk entries.
        ///
        /// - Parameters:
        ///   - directoryName: The folder under Application Support.
        ///   - meshSessionContextFileName: The sealed mesh-session context file.
        ///   - meshRoutedIndexFileName: The routed store's sealed index file.
        ///   - meshRoutedChunkDirectoryName: The routed store's chunk directory.
        public init(
            directoryName: String, meshSessionContextFileName: String,
            meshRoutedIndexFileName: String, meshRoutedChunkDirectoryName: String
        ) {
            self.directoryName = directoryName
            self.meshSessionContextFileName = meshSessionContextFileName
            self.meshRoutedIndexFileName = meshRoutedIndexFileName
            self.meshRoutedChunkDirectoryName = meshRoutedChunkDirectoryName
        }

        /// `URL.applicationSupportDirectory/<directoryName>`: the root a host gets when it passes none.
        ///
        /// Built the way `ProximitySupportLayout.defaultDirectory` builds today's root, so a host whose
        /// ``directoryName`` matches that folder resolves the same path.
        public var defaultDirectory: URL {
            URL.applicationSupportDirectory.appendingPathComponent(directoryName, isDirectory: true)
        }
    }
}
