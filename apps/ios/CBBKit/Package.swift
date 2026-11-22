// swift-tools-version:5.9
// SPDX-License-Identifier: AGPL-3.0-only

// CBBKit is the phone app's way to the Rust core (CCbbCore): the member,
// pairing, the recovery key and the group's state, with no UI. It runs on
// Linux too. The core's static library comes from ffi/bind.sh: the kit's
// tests run as swift test -Xlinker -L<its folder>.
import PackageDescription

let package = Package(
    name: "CBBKit",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [.library(name: "CBBKit", targets: ["CBBKit"])],
    dependencies: [
        // CryptoKit's API, on Linux too; on Apple platforms it uses CryptoKit.
        .package(url: "https://github.com/apple/swift-crypto.git", "4.0.0"..<"6.0.0"),
    ],
    targets: [
        // The Rust core's C functions (ffi/include/cbb_core.h).
        .systemLibrary(name: "CCbbCore"),
        .target(name: "CBBKit", dependencies: [
            "CCbbCore",
            .product(name: "Crypto", package: "swift-crypto"),
        ], linkerSettings: [
            .linkedLibrary("cbb_ffi"),
            // The Rust cbb's smart card signer (member/src/piv.rs) on a
            // Mac, in the host's library that swift test links; a static
            // library does not carry its frameworks, so the link names it.
            .linkedFramework("PCSC", .when(platforms: [.macOS])),
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
    ]
)
