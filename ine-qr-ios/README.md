# IneQr (iOS / SwiftPM)

iOS library port of the INE voter-credential QR decoder.

The crypto pipeline (AES-256-CBC + RSA-8192 + 6-bit text unpack + WebP
header interleave) is the same C source the desktop and Go-API paths use
— `ine-qr-c/src/no_so_crypto.c` and `output_decode.c` are symlinked into
the package via `IneQr/ce/`. The Apple crypto backend
(`crypto_backend_apple.c`) uses the vendored bignum + AES + base64 from
`ine-qr-wasm/vendor/` (also symlinked) instead of OpenSSL — same bytes
the WASM build proves bit-exact, no external system dependencies.

QR detection uses `Vision` (`VNDetectBarcodesRequest`) with a `CIDetector`
fallback for iOS 15 cases where the descriptor cast occasionally returns
`nil`.

## Public API

```swift
import IneQr

let result = try await IneQr.decodeImage(photoData)
print(result.json)            // 18 biographical fields
result.webp                   // raw WebP image bytes (Data)

// Or skip Vision and pass extracted payloads:
try IneQr.decodePayloads(left: leftData, right: rightData)

// Or pass the 1712-byte concatenated buffer directly:
try IneQr.decodeCombined(combinedData)
```

## Build

SwiftPM:

```bash
swift build
swift test
```

XCFramework (for binary distribution):

```bash
./scripts/build-xcframework.sh
# → dist/IneQr.xcframework  (iOS + iOS Simulator + Mac Catalyst slices)
```

Distribute the xcframework via SwiftPM `.binaryTarget(url:, checksum:)` —
zip the framework directory, host the zip, paste its SHA-256.

Toolchain: Xcode 15.4+, Swift 5.9, iOS 15 / Mac Catalyst 15 minimum.

## Verification

`OutputDecodeParityTests` calls the Swift bridge's decode-only entry point
against a synthetic, already-"decrypted" fixture (`synthetic_decoded.bin`)
and asserts the JSON/WebP output matches `expected.json`/`expected.webp`
byte-for-byte. This validates Swift/C marshalling and the bit-unpacking/WebP-
passthrough logic, not the AES/RSA crypto layers — no real credential data is
distributed in this repo, so full crypto-pipeline parity against a real
captured QR remains a manual, local process for maintainers. Drop a new
`(synthetic_decoded.bin, expected.json, expected.webp)` triplet into
`Tests/IneQrTests/Resources/` to extend coverage.

```bash
xcodebuild test -scheme IneQr -destination 'platform=iOS Simulator,OS=17.4,name=iPhone 15'
xcodebuild test -scheme IneQr -destination 'platform=iOS Simulator,OS=15.5,name=iPhone 13'
```

The iOS 15 leg specifically catches Vision descriptor regressions; the
iOS 17 leg covers the current Apple SDKs.

## RSA backend choice

Default backend is the vendored bignum (~256 LOC, public domain, identical
to the WASM build). Speed: ~160 ms per decode on iPhone 15. That's the
crypto-only number; total decode including Vision is in the same ballpark.

If you want full platform-native crypto (CommonCrypto AES + Security.framework
RSA), run `Spikes/RsaVerifyRecoverSpike.swift` against the fixtures. Apple's
SecKey API has no `verify-recover` operation; the workaround uses
`SecKeyCreateEncryptedData(.rsaEncryptionRaw)` to compute `m^e mod n`. If
the spike returns the same bytes the C reference does for both QR halves
on iOS 15.5 *and* iOS 17.4 simulators, swap `crypto_backend_apple.c`'s RSA
path for SecKey. Until then, stick with the vendored bignum — it's cheap
and zero-risk.

## Notes

* **Symlinks into `ine-qr-c/` and `ine-qr-wasm/vendor/`**. The C sources
  are not duplicated. After cloning the repo make sure symlinks are
  preserved (`git config --global core.symlinks true` if you're on
  Windows). Run `ls -la IneQr/ce/` to verify.
* **No camera, no permissions, no UI.** The library is bytes-in,
  bytes-out. Wire AVCaptureSession yourself.
* **Privacy manifest**: ship a `PrivacyInfo.xcprivacy` declaring no
  tracking APIs once you embed this in an App Store build.
* **Bitcode is off** in the build script. Apple deprecated bitcode in
  Xcode 14 and rejects it from App Store submissions on iOS 17+.
