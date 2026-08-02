# ine-qr-android

Android library port of the INE voter-credential QR decoder.

The cryptographic pipeline (AES-256-CBC + RSA-8192 + 6-bit text unpacking +
WebP header interleave) is the same C source the desktop and Go-API paths
use — `ine-qr-c/src/no_so_crypto.c` and `output_decode.c` are pulled in
verbatim by CMake. BoringSSL satisfies the OpenSSL-shaped crypto backend
(`crypto_backend_boringssl.c`); QR detection uses ML Kit's bundled SKU.

## Public API

```kotlin
import mx.ine.qr.IneQr

// From a credential photo (ML Kit handles QR detection):
val result = IneQr.decodeImage(photoBytes)
println(result.json)          // 18 biographical fields
result.webp                   // raw WebP image bytes

// From already-extracted QR payloads:
IneQr.decodePayloads(left = qrLeftBytes, right = qrRightBytes)

// From the 1712-byte concatenated buffer:
IneQr.decodeCombined(combinedBytes)
```

## Build

```bash
cd ine-qr-android
gradle :ine-qr:assembleRelease         # or `./gradlew …` if you've committed a wrapper
# → ine-qr/build/outputs/aar/ine-qr-release.aar
```

The repo doesn't ship a Gradle wrapper jar — install Gradle 8.7+ locally
(`brew install gradle` on macOS, `sdk install gradle 8.7` via SDKMAN on
Linux) or run `gradle wrapper --gradle-version 8.7` once to bootstrap a
wrapper into the project. CI uses `gradle/actions/setup-gradle@v3` which
installs Gradle on the runner.

First configure pulls BoringSSL via CMake `FetchContent` from a pinned tag,
so it needs network access on first build. Subsequent builds are offline.

Toolchain: Android Gradle Plugin 8.5.2, NDK r26, CMake 3.22.1, Kotlin 2.0.20,
`compileSdk = 34`, `minSdk = 24`. ABIs shipped: `arm64-v8a`, `armeabi-v7a`,
`x86_64`.

## Verification

`OutputDecodeParityTest` calls the JNI bridge's decode-only entry point
(`decodeDecryptedNative`) against a synthetic, already-"decrypted" fixture
(`synthetic_decoded.bin`) and asserts the JSON/WebP output matches
`expected.json`/`expected.webp` byte-for-byte. This validates JNI marshalling
and the bit-unpacking/WebP-passthrough logic, not the AES/RSA crypto layers —
no real credential data is distributed in this repo, so full crypto-pipeline
parity against a real captured QR remains a manual, local process for
maintainers. Drop a new `(synthetic_decoded.bin, expected.json, expected.webp)`
triplet into `src/androidTest/assets/fixtures/` to extend coverage.

```bash
gradle :ine-qr:connectedAndroidTest
```

## Notes

* **No camera, no permissions, no UI.** The library is byte-in, byte-out.
  Caller wires CameraX or whatever else.
* **No on-device tracking APIs.** No privacy-manifest / data-safety entries
  beyond the ML Kit barcode model, which runs offline.
* **16 KB page size on Android 15+** is handled by
  `-Wl,-z,max-page-size=16384` in CMakeLists.
* **Sync `crypto_backend_boringssl.c` with
  `ine-qr-c/src/crypto_backend_openssl.c`** — they are intentionally the
  same file under two names so the two builds never drift.
