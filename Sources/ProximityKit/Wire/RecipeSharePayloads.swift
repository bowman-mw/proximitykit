import Foundation
import FernletDomainModel

// WI-9: wire recipe-share payloads marked `nonisolated, Sendable` — see the note in MeshPayloads.swift.
// ProximityKit's `.defaultIsolation(MainActor.self)` would otherwise MainActor-isolate these value
// types and their synthesized `Codable` conformances, blocking off-main decode under Swift 6.
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

    public var hasShareNotes: Bool {
        switch recipe.kind {
        case .local:
            !(recipe.local?.notes.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true)
        case .saved:
            !(recipe.saved?.summary.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true)
        }
    }

    public func omittingShareNotes() -> ProximityRecipeSharePayload {
        var copy = self
        switch copy.recipe.kind {
        case .local:
            if var local = copy.recipe.local {
                local.notes = ""
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

public nonisolated enum ProximitySharedRecipeKind: String, Codable, Equatable, Sendable {
    case local
    case saved
}

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

    public init(
        name: String,
        sourceURLString: String,
        ingredients: [String],
        summary: String,
        servings: Int,
        protein: Int,
        carbs: Int,
        fat: Int,
        micronutrients: Micronutrients
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
    }
}

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
