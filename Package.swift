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
        .package(url: "https://github.com/leviouwendijk/Milieu.git", branch: "master"),
    ],
    targets: [
        .target(
            name: "Cryptography",
            dependencies: [
                .product(name: "Milieu", package: "Milieu"),
            ]
        ),
        .testTarget(
            name: "CryptographyTests",
            dependencies: ["Cryptography"]
        ),
    ]
)
