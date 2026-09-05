// MeshRoutedOrigination.swift
// ProximityKit/Mesh
//
// Network migration P5 item 13 (plan §11, §22.1): what the SENDER door answers.
//
// The vocabulary is split three ways on purpose. "There was nobody to send to" is a **skip** and is
// silent — a solo member capturing a photo has always cached it locally and sent it to nobody, and
// turning that into an error would put a failure on the user's screen for the ordinary first
// minute of every session. "The mint was attempted and failed" is a **refusal**, and it is visible:
// item 9's rule is refuse VISIBLY, never silently. And a staged item carries its key and chunk
// count so the caller can say what it staged without re-reading the store.
//
// Not here: any user copy. Every case below is a frozen English token for an audit line and a
// switch; the sentence the user reads is composed at the manager's `meshError` seam, which is the
// surface `addPhoto` already used for `mesh.photo.encryptFailed` (D-13.15).

import Foundation

// MARK: - MeshRoutedShareSkip

/// Why an origination did nothing, with nothing to tell the user (P5 item 13, D-13.8).
///
/// A skip is **silent**: the local echo is already on this device's own wall, and "send to nobody"
/// is the shipped behaviour for a session that has no other members yet.
nonisolated enum MeshRoutedShareSkip: String, Equatable, Sendable {
    /// No mesh, no membership ledger, or a derived roster of just this device — there is no
    /// destination set to mint against. Frozen English token.
    case noDestinations
}

// MARK: - MeshRoutedShareRefusal

/// Why an origination was attempted and failed (P5 item 13, D-13.15).
///
/// Every case is **visible**: the manager raises `meshError` and writes one
/// `mesh.routedShare.refused` audit line carrying the token. Frozen English `rawValue`s — they are
/// audit vocabulary, never user copy.
nonisolated enum MeshRoutedShareRefusal: String, Equatable, Sendable {
    /// The body could not be framed, or ``MeshRoutedItemSealer`` refused the plaintext — empty,
    /// above the resident bound (D-13.19), or an invalid content key. One token for both halves of
    /// "these bytes never became a sealed blob": the framing is a pure encode of the origin's own
    /// values, so a caller can act on neither differently.
    case sealFailed
    /// A destination has no handshake-verified X25519 key on this device, so the whole mint is
    /// refused rather than minted to a subset (D-13.1, D-13.22). The stated outage: a star
    /// topology, a roster above the slot cap, and any resumption that restored the ledger but not
    /// the memory-only session roster.
    case destinationNotAddressable
    /// The manifest or chunk mint threw — a signing failure, or a shape the mint's own guard chain
    /// refused by name.
    case mintFailed
    /// The routed store refused the manifest or a chunk, by name. At the three store-level capacity
    /// caps this also raises item 9's existing `.storeFull` hold.
    case storeRefused
    /// The routed store could not say what it holds: deferred protected data, a refused seal, or a
    /// corrupt index. Nothing was written and nothing is known.
    case storeUnavailable
}

// MARK: - MeshRoutedOriginationOutcome

/// What the routed sender door did with one item (P5 item 13, plan §11).
///
/// Three answers rather than a `Bool` or an optional: "staged", "there was nobody to stage for" and
/// "it failed" reach three different surfaces, and collapsing the middle one into either of the
/// others is how a solo capture becomes either a silent loss or a false error.
nonisolated enum MeshRoutedOriginationOutcome: Equatable, Sendable {
    /// The item is in this device's own routed store, complete, and pushed once to every committed
    /// slot. The drain carries it to everyone else at the next exchange.
    case staged(MeshRoutedItemKey, chunkCount: Int)
    /// Nothing was minted and nothing is wrong. Silent.
    case skipped(MeshRoutedShareSkip)
    /// A mint was attempted and failed. Visible.
    case refused(MeshRoutedShareRefusal)
}
