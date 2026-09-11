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
// switch; the manager publishes the refusal on `routedShareRefusal` and the APP forks the sentence
// per case (`RoutedShareRefusalCopy`), so it localizes — the `meshError` `String` seam this first
// rode rendered English in every language (D-13.15; the P5 review's finding 5).

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
/// Every case is **visible**: the manager publishes it on `routedShareRefusal` — which the app forks
/// into localized copy, one sentence per case — and writes one `mesh.routedShare.refused` audit line
/// carrying the token. Frozen English `rawValue`s — they are audit vocabulary, never user copy.
/// `public` and `CaseIterable` so the app's copy switch is exhaustive and its test covers every case.
public nonisolated enum MeshRoutedShareRefusal: String, CaseIterable, Equatable, Sendable {
    /// The body could not be framed, or ``MeshRoutedItemSealer`` refused the plaintext — empty,
    /// above the resident bound (D-13.19), or an invalid content key. One token for both halves of
    /// "these bytes never became a sealed blob": the framing is a pure encode of the origin's own
    /// values, so a caller can act on neither differently.
    case sealFailed
    /// A destination has no verified X25519 key on this device — neither a handshake-verified one
    /// (a live slot, or the session-roster entry written from that same value) nor a verified,
    /// durable `fernlet.mesh.key-agreement.v1` advertisement — so the whole mint is refused rather
    /// than minted to a subset (D-13.1, D-13.22).
    ///
    /// **Amended by P6 item 1.** The stated outage used to be three cases; the advertisement closed
    /// the third and converted the other two. A **resumption** (a restart, an idle-lapse resume or a
    /// rejoin) restores the ledger and, now, the addressing with it, so it mints and delivers. A
    /// **star topology** and a **roster above the slot cap** now mint too: the unlinked
    /// destinations' copies are sealed, wrapped and custodied by the origin until a link forms or
    /// the origin departs and hands custody over — `relayInFlight` is increment 2's, so a
    /// destination that holds an item never forwards it. What still lands here is a member no
    /// device has ever advertised a key for to this one: a brand-new joiner before its admitter has
    /// relayed the set on, and a member whose advertisement this device could not prove.
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
    /// A destination's two verified sources of its X25519 key disagree (P6 item 1): a live
    /// handshake-verified key against a signed, durable advertisement, two handshake-verified
    /// values against each other, or a member the advertisement set has marked **conflicted**
    /// because two different keys arrived under one fingerprint, both verified.
    ///
    /// Refused rather than resolved, and never "pick the present-tense one": both are verified
    /// sources, and choosing would mean either wrapping a content key to a key the peer no longer
    /// holds or accepting a substitution. `IdentityService.ensureProvisioned()` mints the signing
    /// and key-agreement pair together in every one of its four cases, so a member cannot
    /// legitimately hold two — which makes this a signal, not a race. Fail closed.
    case keyMismatch
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
