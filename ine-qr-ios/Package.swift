// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "IneQr",
    platforms: [
        .iOS(.v15),
        .macCatalyst(.v15),
        .macOS(.v12),
    ],
    products: [
        .library(name: "IneQr", targets: ["IneQr"]),
    ],
    targets: [
        // Platform-agnostic C: pipeline + output decoder + Apple crypto backend.
        // INE_BACKEND_VENDORED_BN routes ine_crypto_backend.h to the vendored
        // bignum.h instead of <openssl/bn.h>.
        .target(
            name: "IneQrCore",
            path: "IneQr/ce",
            sources: [
                "no_so_crypto.c",
                "output_decode.c",
                "crypto_backend_apple.c",
                "vendor/aes256.c",
                "vendor/base64.c",
                "vendor/bignum.c",
            ],
            publicHeadersPath: "include",
            cSettings: [
                .define("INE_BACKEND_VENDORED_BN"),
                .headerSearchPath("include"),
                .headerSearchPath("vendor"),
                .unsafeFlags(["-Wno-unused-parameter"], .when(configuration: .release)),
            ]
        ),

        .target(
            name: "IneQr",
            dependencies: ["IneQrCore"],
            path: "IneQr",
            exclude: ["ce"],
            sources: [
                "IneQr.swift",
                "IneResult.swift",
                "IneQrError.swift",
                "Internal/VisionScanner.swift",
            ]
        ),

        .testTarget(
            name: "IneQrTests",
            dependencies: ["IneQr"],
            path: "Tests/IneQrTests",
            resources: [.copy("Resources")]
        ),
    ]
)
