// swift-tools-version:5.9
// SPDX-License-Identifier: AGPL-3.0-only

// CBBKit is the protocol core of the phone app: pairing (CPace, the
// frames, the welcome), the join QR code and the member protocol. It has no
// UI and runs on Linux too, so its tests run against the Go implementation's
// test vectors anywhere. The group's rules come from the Rust core
// (CCbbCore), whose static library ffi/bind.sh builds: the kit's tests
// run as swift test -Xlinker -L<its folder>.
import PackageDescription

let package = Package(
    name: "CBBKit",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [.library(name: "CBBKit", targets: ["CBBKit"])],
    dependencies: [
        // CryptoKit's API, on Linux too; on Apple platforms it uses CryptoKit.
        .package(url: "https://github.com/apple/swift-crypto.git", "4.0.0"..<"5.0.0"),
    ],
    targets: [
        // The Rust core's C functions (ffi/include/cbb_core.h).
        .systemLibrary(name: "CCbbCore"),
        .target(name: "CBBKit", dependencies: [
            "CCbbCore",
            .product(name: "Crypto", package: "swift-crypto"),
            // RSA, for Google's attestation root (AndroidAttestation).
            .product(name: "_CryptoExtras", package: "swift-crypto"),
        ], linkerSettings: [
            .linkedLibrary("cbb_ffi"),
            // What Rust's standard library needs from the system on Linux;
            // Apple's platforms have it in libSystem.
            .linkedLibrary("m", .when(platforms: [.linux])),
            .linkedLibrary("dl", .when(platforms: [.linux])),
            .linkedLibrary("pthread", .when(platforms: [.linux])),
            .linkedLibrary("rt", .when(platforms: [.linux])),
            .linkedLibrary("util", .when(platforms: [.linux])),
            .linkedLibrary("gcc_s", .when(platforms: [.linux])),
        ]),
        .testTarget(name: "CBBKitTests", dependencies: ["CBBKit"]),
        // Plays the phone against the Go code in the Go tests; not shipped.
        .executableTarget(name: "cbb-interop", dependencies: ["CBBKit"]),
    ]
)
