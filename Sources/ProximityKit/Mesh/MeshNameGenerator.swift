import Foundation
import FernletDomainModel

enum MeshNameGenerator {
    static func generate() -> String {
        "\(adjectives.randomElement() ?? "sunny")-\(nouns.randomElement() ?? "meadow")"
    }

    private static let adjectives: [String] = [
        "amber", "azure", "breezy", "bright", "calm", "cedar", "cheerful", "clear",
        "cloudy", "cozy", "crisp", "dawn", "dewy", "drifting", "earthy", "even",
        "fern", "field", "fleet", "flowing", "foggy", "gentle", "golden", "grassy",
        "green", "happy", "hazy", "hidden", "honey", "jade", "kind", "leafy",
        "light", "lively", "long", "lush", "meadow", "mild", "misty", "mossy",
        "open", "pale", "peaceful", "peach", "pebbled", "pine", "pink", "plain",
        "quiet", "radiant", "rainy", "rich", "rosy", "sandy", "serene", "shady",
        "silver", "sleepy", "slow", "smooth", "soft", "solar", "still", "stone",
        "sunny", "swift", "tall", "tender", "tidy", "tiny", "tranquil", "velvet",
        "warm", "wandering", "wavy", "wide", "wild", "windy", "winter", "wispy",
        "wooden", "yellow"
    ]

    private static let nouns: [String] = [
        "acorn", "antler", "arch", "basin", "bay", "birch", "bloom", "boulder",
        "brook", "canopy", "cedar", "clover", "cloud", "coast", "coral", "creek",
        "dew", "drift", "dune", "fern", "field", "finch", "fjord", "flower",
        "fog", "glade", "glen", "grove", "harbor", "haven", "heath", "hill",
        "hollow", "horizon", "inlet", "island", "ivy", "lagoon", "lake", "leaf",
        "ledge", "lily", "loch", "log", "marsh", "meadow", "mesa", "moss",
        "mountain", "oak", "orchard", "otter", "path", "peak", "petal", "pine",
        "pond", "pool", "rain", "reef", "ridge", "ripple", "river", "robin",
        "root", "shore", "sky", "slope", "snow", "sparrow", "spring", "stone",
        "stream", "summit", "tide", "timber", "trail", "vale", "valley", "vine",
        "wave", "wildflower", "willow", "wind"
    ]
}
