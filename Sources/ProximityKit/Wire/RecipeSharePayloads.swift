import Foundation
import FernletDomainModel

// WI-9: wire recipe-share payloads marked `nonisolated, Sendable` — see the note in MeshPayloads.swift.
// ProximityKit's `.defaultIsolation(MainActor.self)` would otherwise MainActor-isolate these value
// types and their synthesized `Codable` conformances, blocking off-main decode under Swift 6.
/// The `.recipeShare` wire body: format/version markers plus one ``ProximitySharedRecipe``.
///
/// Built by the app's share sheet, sent sealed by ``ProximityRecipeShareManager``, and received
/// into ``PendingProximityRecipeShare``. The share-notes members implement the "Include notes"
/// privacy toggle — sender-authored free text can be withheld before the payload leaves.
public nonisolated struct ProximityRecipeSharePayload: Codable, Equatable, Identifiable, Sendable {
    /// Wire cap for ``imageJPEGData``: the sender downscales/re-encodes until the JPEG fits (or
    /// omits it), and the receiver drops any image above it before decoding a single pixel. Well
    /// under the friend channel's 10 MB envelope bound, so a recipe-with-picture always fits.
    public static let maxImageBytes = 512 * 1024

    /// Ceiling on a decoded recipe-share plaintext, enforced BEFORE `JSONDecoder`. Derived, never
    /// hand-picked: ``maxImageBytes`` (512 KB) inflates to ~683 KB as base64 inside the JSON, plus
    /// a generous ~340 KB for the recipe text itself — an honest share is far under 1 MiB. The
    /// image cap alone is not enough: it only applies AFTER a multi-megabyte body has been decoded.
    public static let maxWireBytes = 1024 * 1024

    public var format = "fernlet.proximity.recipe"
    public var version = 1
    public var id = UUID()
    public var sentAt = Date()
    public var recipe: ProximitySharedRecipe
    /// A downscaled JPEG of the recipe's picture (the sender's stored recipe photo — their own pick
    /// or a web-derived default), at most ``maxImageBytes``, so the receiving device gets the
    /// picture without ever fetching the web. Optional key, `version` STAYS 1 — the same wire-compat
    /// rule as `SharedSavedRecipePayload.steps`: an older peer's synthesized `Codable` ignores the
    /// extra key and decodes minus the image; a newer peer decoding an older payload sees `nil`.
    /// The app-side receiver seals accepted bytes into its own private recipe-photo store and marks
    /// the recipe's web-image fetch as already attempted, so a received recipe never web-fetches.
    public var imageJPEGData: Data?

    public init(
        format: String = "fernlet.proximity.recipe",
        version: Int = 1,
        id: UUID = UUID(),
        sentAt: Date = Date(),
        recipe: ProximitySharedRecipe,
        imageJPEGData: Data? = nil
    ) {
        self.format = format
        self.version = version
        self.id = id
        self.sentAt = sentAt
        self.recipe = recipe
        self.imageJPEGData = imageJPEGData
    }

    /// True when this payload carries sender-authored free text the "Include notes" toggle can withhold.
    /// For a LOCAL (manually authored) recipe that is the notes OR the cooking steps — both are the
    /// sender's own prose and can carry personal remarks. For a SAVED (web-imported) recipe it is only
    /// the summary: that recipe's steps are parsed from a public URL, not personal, so they are never
    /// gated (withholding them would strip the recipe's value with no privacy benefit).
    public var hasShareNotes: Bool {
        switch recipe.kind {
        case .local:
            let hasNotes = !(recipe.local?.notes.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true)
            let hasSteps = !(recipe.local?.steps?.isEmpty ?? true)
            return hasNotes || hasSteps
        case .saved:
            return !(recipe.saved?.summary.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true)
        }
    }

    /// Returns a copy with the attached picture removed — the sender-side "Include picture"
    /// toggle. The recipe's stored photo can be the user's own kitchen/home shot, which can carry
    /// more identifying content than the notes the notes-toggle withholds, so the sender gets the
    /// same per-share control over it (default ON, preserving the image-rides-the-share decision).
    /// Independent of ``omittingShareNotes()``: picture and notes are separate decisions.
    public func omittingImage() -> ProximityRecipeSharePayload {
        var copy = self
        copy.imageJPEGData = nil
        return copy
    }

    /// Returns a copy safe to RETAIN on the receive side: an image above ``maxImageBytes`` —
    /// bytes an honest sender can never produce, since senders downscale to fit or omit — is
    /// dropped at the door, before the payload enters the pending queue, so a hostile-but-verified
    /// peer cannot park multi-megabyte blobs in a receiver's memory while the share awaits review.
    /// The recipe itself is kept (a bad image never fails an import; the app-side importer applies
    /// the same cap again as defense in depth).
    public func droppingOversizeImage() -> ProximityRecipeSharePayload {
        guard let imageJPEGData, imageJPEGData.count > Self.maxImageBytes else { return self }
        var copy = self
        copy.imageJPEGData = nil
        return copy
    }

    /// Returns a copy whose rendered strings and lists are bounded for the review sheet.
    ///
    /// ``maxWireBytes`` bounds the TOTAL bytes; this bounds what the sheet has to LAY OUT, so a
    /// share carrying a hundred ten-kilobyte ingredient names cannot stall the review UI while
    /// still fitting comfortably under the wire cap. The local variant is already bounded by
    /// `SharedRecipePayload.init(from:)`; the saved variant has no custom decode, so it is clamped
    /// here — at the door — to the same ``SharedRecipeLimits`` the import path already enforces.
    public func clampedForReview() -> ProximityRecipeSharePayload {
        guard case .saved = recipe.kind, var saved = recipe.saved else { return self }
        saved.name = String(saved.name.prefix(SharedRecipeLimits.maxNameCharacters))
        saved.summary = String(saved.summary.prefix(SharedRecipeLimits.maxNotesCharacters))
        saved.sourceURLString = String(saved.sourceURLString.prefix(SharedRecipeLimits.maxNotesCharacters))
        saved.servings = min(max(saved.servings, 1), SharedRecipeLimits.maxServings)
        saved.ingredients = saved.ingredients
            .prefix(SharedRecipeLimits.maxIngredients)
            .map { String($0.prefix(SharedRecipeLimits.maxNameCharacters)) }
        if let steps = saved.steps {
            saved.steps = steps.prefix(SharedRecipeLimits.maxSteps).map {
                RecipeStep(id: $0.id,
                           text: String($0.text.prefix(SharedRecipeLimits.maxNotesCharacters)),
                           durationSeconds: $0.durationSeconds)
            }
        }
        var copy = self
        copy.recipe.saved = saved
        return copy
    }

    /// Returns a copy with the sender's free text removed. For a LOCAL recipe this clears BOTH `notes`
    /// and the user-authored `steps` (F5: step text is free-form and can carry the same personal remarks
    /// the notes toggle exists to withhold). For a SAVED recipe it clears only the `summary` — its steps
    /// come from a public source, so they ride along even when notes are omitted.
    public func omittingShareNotes() -> ProximityRecipeSharePayload {
        var copy = self
        switch copy.recipe.kind {
        case .local:
            if var local = copy.recipe.local {
                local.notes = ""
                local.steps = nil
                copy.recipe.local = local
            }
        case .saved:
            if var saved = copy.recipe.saved {
                saved.summary = ""
                copy.recipe.saved = saved
            }
        }
        return copy
    }
}

/// Which variant a ``ProximitySharedRecipe`` carries: a user-authored local recipe or a
/// web-imported saved recipe.
///
/// The distinction drives the notes-privacy rules — local steps are personal prose, saved steps
/// come from a public URL.
public nonisolated enum ProximitySharedRecipeKind: String, Codable, Equatable, Sendable {
    case local
    case saved
}

/// Tagged union of the two shareable recipe shapes, with convenience accessors that read whichever
/// side `kind` selects.
///
/// Exactly one of `local` / `saved` is populated; the accessors fall back to safe defaults so a
/// malformed payload still renders rather than crashing.
public nonisolated struct ProximitySharedRecipe: Codable, Equatable, Sendable {
    public var kind: ProximitySharedRecipeKind
    public var local: SharedRecipePayload?
    public var saved: SharedSavedRecipePayload?

    public init(
        kind: ProximitySharedRecipeKind,
        local: SharedRecipePayload? = nil,
        saved: SharedSavedRecipePayload? = nil
    ) {
        self.kind = kind
        self.local = local
        self.saved = saved
    }

    public var title: String {
        switch kind {
        case .local:
            local?.name ?? "Recipe"
        case .saved:
            saved?.name ?? "Saved recipe"
        }
    }

    public var servings: Int {
        switch kind {
        case .local:
            local?.servings ?? 1
        case .saved:
            saved?.servings ?? 1
        }
    }

    public var ingredientCount: Int {
        switch kind {
        case .local:
            local?.ingredients.count ?? 0
        case .saved:
            saved?.ingredients.count ?? 0
        }
    }
}

/// Wire projection of a web-imported saved recipe: name, source URL, ingredients, macro totals,
/// micronutrients, and (optionally) parsed cooking steps.
///
/// The `summary` is the only sender-authored free text here, which is why `omittingShareNotes()`
/// clears it alone. The companion local-recipe shape (`SharedRecipePayload`) lives in
/// `FernletDomainModel`.
public nonisolated struct SharedSavedRecipePayload: Codable, Equatable, Sendable {
    public var name: String
    public var sourceURLString: String
    public var ingredients: [String]
    public var summary: String
    public var servings: Int
    public var protein: Int
    public var carbs: Int
    public var fat: Int
    public var micronutrients: Micronutrients
    /// Ordered cooking steps (F5) for a web/saved recipe shared over proximity. Optional key, no format
    /// version bump: an older peer's `SharedSavedRecipePayload` lacks this property and its synthesized
    /// `Codable` ignores the extra key, so a steps-carrying saved recipe still decodes minus steps on old
    /// builds (`ProximityRecipeSharePayload.version` stays 1). See the note on `SharedRecipePayload.steps`.
    public var steps: [RecipeStep]?

    public init(
        name: String,
        sourceURLString: String,
        ingredients: [String],
        summary: String,
        servings: Int,
        protein: Int,
        carbs: Int,
        fat: Int,
        micronutrients: Micronutrients,
        steps: [RecipeStep]? = nil
    ) {
        self.name = name
        self.sourceURLString = sourceURLString
        self.ingredients = ingredients
        self.summary = summary
        self.servings = servings
        self.protein = protein
        self.carbs = carbs
        self.fat = fat
        self.micronutrients = micronutrients
        self.steps = steps
    }

    /// Bounded decode (R3/R5), mirroring `SharedRecipePayload.init(from:)` on the local arm. This
    /// type is built from UNTRUSTED bytes — a mesh recipe envelope — and import writes its name,
    /// ingredient lines, summary and steps straight into the synced snapshot, so every string and
    /// collection is capped where the bytes enter. The macro `Int`s are bounded here too because
    /// the review sheet sums and renders them BEFORE the store's own clamps ever run, and the
    /// micronutrients are sanitized because a non-finite amount would reach a trapping `Int(_:)`
    /// in a day-detail row.
    ///
    /// WIRE CONTRACT UNCHANGED: every key except `steps` stays REQUIRED and `steps` stays optional,
    /// exactly as the synthesized decode had it — an older peer that sends no `steps` key must
    /// still round-trip (see the note on ``steps``).
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try Self.bounded(c.decode(String.self, forKey: .name),
                                limit: SharedRecipeLimits.maxNameCharacters)
        sourceURLString = try Self.bounded(c.decode(String.self, forKey: .sourceURLString),
                                           limit: SharedRecipeLimits.maxSourceURLCharacters)
        summary = try Self.bounded(c.decode(String.self, forKey: .summary),
                                   limit: SharedRecipeLimits.maxSummaryCharacters)
        let decodedIngredients = try c.decode([String].self, forKey: .ingredients)
        guard decodedIngredients.count <= SharedRecipeLimits.maxIngredients,
              decodedIngredients.allSatisfy({ $0.count <= SharedRecipeLimits.maxIngredientLineCharacters }) else {
            throw RecipeImportError.invalidPayload
        }
        ingredients = decodedIngredients
        servings = min(max(try c.decode(Int.self, forKey: .servings), 1), SharedRecipeLimits.maxServings)
        protein = try Self.boundedMacro(c.decode(Int.self, forKey: .protein))
        carbs = try Self.boundedMacro(c.decode(Int.self, forKey: .carbs))
        fat = try Self.boundedMacro(c.decode(Int.self, forKey: .fat))
        micronutrients = try c.decode(Micronutrients.self, forKey: .micronutrients).sanitizedForImport()
        let decodedSteps = try c.decodeIfPresent([RecipeStep].self, forKey: .steps)
        guard (decodedSteps?.count ?? 0) <= SharedRecipeLimits.maxSavedSteps,
              (decodedSteps ?? []).allSatisfy({ $0.text.count <= SharedRecipeLimits.maxStepTextCharacters }) else {
            throw RecipeImportError.invalidPayload
        }
        steps = decodedSteps
    }

    /// Rejects an over-long free-text field rather than silently truncating it — a truncated recipe
    /// name, summary or source link is a quiet corruption of the sender's content.
    private static func bounded(_ value: String, limit: Int) throws -> String {
        guard value.count <= limit else { throw RecipeImportError.invalidPayload }
        return value
    }

    /// Rejects a macro gram value outside `[0, SharedRecipeLimits.maxMacroGrams]`, so no peer-chosen
    /// `Int` can reach the trapping arithmetic in `Macros.calories` or the review sheet.
    private static func boundedMacro(_ value: Int) throws -> Int {
        guard value >= 0, value <= SharedRecipeLimits.maxMacroGrams else {
            throw RecipeImportError.invalidPayload
        }
        return value
    }

    /// Wire JSON keys for a shared saved (web-imported) recipe payload.
    private enum CodingKeys: String, CodingKey {
        case name, sourceURLString, ingredients, summary, servings, protein, carbs, fat
        case micronutrients, steps
    }
}

/// A received recipe share awaiting the user's accept/dismiss decision.
///
/// Held in memory by ``ProximityRecipeShareManager/pendingRecipeShares`` (capped, rate-limited);
/// `senderFingerprint` is the transport-verified identity when available. Identity is the
/// payload's id so a re-send replaces rather than stacks.
public struct PendingProximityRecipeShare: Identifiable, Equatable {
    public var id: UUID { payload.id }
    public var senderDisplayName: String
    public var senderFingerprint: String?
    public var receivedAt: Date
    public var payload: ProximityRecipeSharePayload

    public init(
        senderDisplayName: String,
        senderFingerprint: String?,
        receivedAt: Date,
        payload: ProximityRecipeSharePayload
    ) {
        self.senderDisplayName = senderDisplayName
        self.senderFingerprint = senderFingerprint
        self.receivedAt = receivedAt
        self.payload = payload
    }
}

/// A nearby Fernlet the user can send a recipe to, as shown in the share sheet's recipient list.
///
/// `id` is the discovered peer's UUID; `fingerprint` stays nil until the identity introduction
/// verifies, after which the row upgrades to the verified display name.
public struct ProximityRecipeShareRecipient: Identifiable, Equatable {
    public var id: UUID
    public var displayName: String
    public var fingerprint: String?  // nil until identity introduction completes

    public init(id: UUID, displayName: String, fingerprint: String?) {
        self.id = id
        self.displayName = displayName
        self.fingerprint = fingerprint
    }
}
