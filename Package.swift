// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Cryptography",
    platforms: [
        .macOS(.v12)
    ],
    products: [
        .library(
            name: "Cryptography",
            targets: ["Cryptography"]
        ),
    ],
    dependencies: [
        // .package(url: "https://github.com/leviouwendijk/Variables.git", branch: "master"),
        .package(url: "https://github.com/leviouwendijk/Milieu.git", branch: "master"),
        // .package(url: "https://github.com/leviouwendijk/Loggers.git", branch: "master"),
        // .package(url: "https://github.com/leviouwendijk/Primitives.git", branch: "master"),
        // .package(url: "https://github.com/leviouwendijk/Parsers.git", branch: "master"),
    ],
    targets: [
        .target(
            name: "Cryptography",
            dependencies: [
                // .product(name: "Variables", package: "Variables"),
                .product(name: "Milieu", package: "Milieu"),
                // .product(name: "Loggers", package: "Loggers"),
                // .product(name: "Primitives", package: "Primitives"),
                // .product(name: "Parsers", package: "Parsers"),
            ]
        ),
        .testTarget(
            name: "CryptographyTests",
            dependencies: ["Cryptography"]
        ),
    ]
)
