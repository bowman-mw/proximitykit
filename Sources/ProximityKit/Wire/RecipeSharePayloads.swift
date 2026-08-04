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
    public var format = "fernlet.proximity.recipe"
    public var version = 1
    public var id = UUID()
    public var sentAt = Date()
    public var recipe: ProximitySharedRecipe

    public init(
        format: String = "fernlet.proximity.recipe",
        version: Int = 1,
        id: UUID = UUID(),
        sentAt: Date = Date(),
        recipe: ProximitySharedRecipe
    ) {
        self.format = format
        self.version = version
        self.id = id
        self.sentAt = sentAt
        self.recipe = recipe
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
