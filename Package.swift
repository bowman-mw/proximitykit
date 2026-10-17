// swift-tools-version: 6.2
import PackageDescription

// ProximityKit: one library and its tests, and no package dependencies. Both targets keep the
// settings they built with in the Fernlet repository's FernletKit package, where the code lived
// before it moved here with its history: the library defaults to the main actor, and the tests build
// in Swift 6 mode with no default isolation and three upcoming features, so every suite keeps the
// isolation, executor semantics and name lookup it was written against.
//
// The walls read this file. The namespace wall pins the library's dependency list to a literal,
// empty list; the no-tracking scan refuses any package dependency; and Scripts/manifest-scan.py
// refuses unsafe flags and any warnings setting here, because CI sets warnings as errors on its build
// command lines instead. It also holds the one resource declaration: the test target's fixture
// folder, the bytes each released tag wrote (Tests/ProximityKitTests/Fixtures/<tag>/, which
// CrossVersionFixtureTests reads through Bundle.module on every test lane), copied whole so each
// tag's files keep their paths; the library declares none, so nothing of it reaches a host's app.
let package = Package(
    name: "ProximityKit",
    platforms: [
        .iOS(.v26),
        .macOS(.v26),
    ],
    products: [
        .library(name: "ProximityKit", targets: ["ProximityKit"]),
    ],
    targets: [
        .target(
            name: "ProximityKit",
            dependencies: [],
            swiftSettings: [
                .defaultIsolation(MainActor.self),
            ]
        ),
        .testTarget(
            name: "ProximityKitTests",
            dependencies: ["ProximityKit"],
            resources: [
                .copy("Fixtures"),
            ],
            swiftSettings: [
                .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
                .enableUpcomingFeature("InferIsolatedConformances"),
                .enableUpcomingFeature("MemberImportVisibility"),
            ]
        ),
    ]
)
