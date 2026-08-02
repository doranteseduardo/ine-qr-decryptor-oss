<div align="center">

# INE QR Code Decryptor

**Reverse-engineered decryption of Mexican INE credential QR codes, in six independent implementations**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/doranteseduardo/ine-qr-decryptor-oss/ci.yml?branch=master&style=flat-square&label=CI)](https://github.com/doranteseduardo/ine-qr-decryptor-oss/actions/workflows/ci.yml)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)

Reverse engineering of the INE (Instituto Nacional Electoral) credential QR
codes used in the official Mexican voter ID card reader app
`mx.ine.rfe.lectorqr` (PersonalCode-INE v5.0.11). The two QR codes on a
Mexican voter credential encode 18 biographical fields plus the credential
photo, protected by a 7-layer cryptographic pipeline inside the native
library `libPersonalCode.so` (ARM64, 4.6 MB, Chilkat 9.5 statically linked).

**Open source, Apache-2.0 licensed.** No vendor code, binaries, or real
personal data are included — see the Disclaimer below. Issues and pull
requests are welcome; see [`CONTRIBUTING.md`](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md).

</div>

---

## About This Release

This repository is a **pruned, public release of a broader internal
reverse-engineering research effort**, not the original research tree in
full.

- **No proprietary binary or decompiled source.** This repository does not
  include the `libPersonalCode.so` binary, any decompiled application
  source, or any material describing how to bypass a third-party library's
  license or tamper checks. Only this project's own clean-room
  reimplementation of the pipeline is included, along with the emulator
  architecture documentation (memory layout, stub dispatch, buffer
  injection) that doesn't depend on any of that.
- **No real personal data.** Test fixtures that once referenced a real
  credential have been replaced with fabricated, obviously-fake equivalents
  (see the Disclaimer below and `scripts/gen_synthetic_fixture.py`). No real
  person's data appears anywhere in this repository or its history.

What's left is the six working implementations of the decryption pipeline
and the technical documentation of the algorithm itself.

---

## What Is Inside

This project ships **six end-to-end implementations**, all of which produce
bit-identical output:

1. **An ARM64 emulator path** (Unicorn-based, in C and Python) that runs the
   real `pc()` JNI function inside a sandbox. This is the original research
   tool — it loaded the `.so`, hooked every Chilkat call, captured the AES
   keys / RSA keys / intermediate buffers, and produced the ground truth
   used to verify everything else. The emulator path is what made the
   pipeline understood in the first place.
2. **A pure-crypto path** (in C and Python) that reimplements the entire
   pipeline — including the NEON/SIMD key derivation and the post-RSA
   bit-unpacker — using only OpenSSL (or `cryptography` / `numpy`) and a
   handful of constants extracted from the `.so` once. Faster, smaller,
   and runs natively on x86-64 hosts without ARM emulation.
3. **A WebAssembly path** (`ine-qr-wasm/`, ~85 KB total) that compiles the
   pure-crypto pipeline to WASM with Emscripten, vendoring tiny AES-256-CBC,
   base64, and a small bignum modexp in place of OpenSSL. Runs entirely in
   the browser — no server round-trip, no .so, no native dependencies.
4. **An Android library** (`ine-qr-android/`) that pulls the same C
   sources into an NDK build linked against BoringSSL (vendored at
   configure time via CMake `FetchContent`). ML Kit's bundled barcode
   model handles QR detection. Output: an AAR exposing a
   three-method Kotlin API (`decodeImage`, `decodePayloads`,
   `decodeCombined`).
5. **An iOS / Swift package** (`ine-qr-ios/`) that symlinks the same
   pipeline source and uses CommonCrypto-style vendored AES + bignum
   (zero external deps, identical to the WASM build). Vision +
   `CIDetector` handle QR detection. Output: an `IneQr.xcframework` for
   binary distribution, plus the equivalent Swift API.
6. **An Eskiu path** (`ine-qr-eskiu/`) that reimplements the crypto + output
   pipeline in [Eskiu](https://eskiu-lang.org) — a systems language that
   compiles to native via LLVM — and wraps it in an HTTP API (`POST /decode`,
   multipart or JSON base64 → the 18 fields + `foto_base64`; plus `/healthz`,
   `/stats`, `X-API-Key` auth, and rate limiting), mirroring the Go
   `ine-qr-api/`. QR extraction reuses `ine-qr-c`'s portable `stb_image` +
   `zxing-cpp` reader, so it builds on Linux too. The HTTP server, multipart
   parsing, rate-limit map and JSON are all built on Eskiu's standard library.

---

## Disclaimer

This is an independent security-research and technical-transparency project.

- **No affiliation.** It is not affiliated with, authorized by, or endorsed by
  the Instituto Nacional Electoral (INE) or any Mexican government agency, nor
  by Chilkat Software or any other vendor mentioned. Vendor and product names
  are used only to factually describe what was analyzed.
- **No vendor code or binaries.** No proprietary source, decompiled code, or
  vendor binary is included or distributed here. The proprietary
  `libPersonalCode.so` is **not** shipped; the emulator path requires you to
  supply your own extracted copy, and every other path runs without it.
- **No real personal data.** No real credential data, CURP, name, photo, or
  captured QR bytes appears anywhere in this repository or its history. All test
  fixtures use synthetic, clearly-fake values (see
  `scripts/gen_synthetic_fixture.py`).
- **Responsible use.** Only decode credentials that you own or are explicitly
  authorized to read. You are responsible for complying with all applicable
  laws and privacy regulations.
- **No warranty / no liability.** Provided "as is" under the Apache License 2.0,
  without warranty of any kind. The authors accept no liability for any misuse.

---

## Decoded Output

| File                            | Description                        |
| ------------------------------- | ---------------------------------- |
| `output/datos_biograficos.json` | All 18 biographical fields as JSON |
| `output/foto_ine.webp`          | 96×129 px credential photo (WebP)  |
| `output/texto_biografico.txt`   | Raw pipe-delimited text            |

### Biographical Fields

| #   | Field             | Description                      |
| --- | ----------------- | -------------------------------- |
| 0   | tipo              | Credential type (`N` = Nacional) |
| 1   | cic               | CIC number (9 digits)            |
| 2   | ocr               | OCR number (13 digits)           |
| 3   | curp              | CURP (18 chars)                  |
| 4   | nombre            | First name                       |
| 5   | apellido1         | Paternal surname                 |
| 6   | apellido2         | Maternal surname                 |
| 7   | entidad           | State code (2 digits)            |
| 8   | municipio         | Municipality code                |
| 9   | seccion           | Electoral section                |
| 10  | etnia             | Ethnicity (optional)             |
| 11  | vigencia          | Validity period (`YYYY/YYYY`)    |
| 12  | sexo              | Sex (`H`/`M`)                    |
| 13  | indiceHuella1     | Fingerprint index 1              |
| 14  | indiceHuella2     | Fingerprint index 2 (optional)   |
| 15  | version           | Credential version               |
| 16  | fechaGeneracion   | Generation date (`YYYYMMDD`)     |
| 17  | firmaVerificadora | Verification signature (hex)     |

---

## Quick Start

### Pure-C path — recommended for production (0.19 s)

```bash
brew install openssl zxing-cpp                  # macOS
# Linux: see Dockerfile for the package recipe (libssl-dev, build zxing-cpp from source)

cd ine-qr-c
make                                            # → ine_decode (~175 KB)
./ine_decode /path/to/credential_photo.heic
```

No `libPersonalCode.so` required at runtime; all `.rodata` constants and AES
ciphertexts are embedded in the binary.

### Pure-Python path — recommended for hacking / inspection (0.32 s)

```bash
pip install cryptography numpy Pillow zxing-cpp
pip install pillow-heif        # optional, for HEIC/HEIF photos

python3 ine-qr-py/no_so_pipeline.py /path/to/credential_photo.heic
```

The Python script walks each step of the pipeline with stage-by-stage
timings, making it useful as the canonical reference for the algorithm.

### WebAssembly path — runs in the browser (~85 KB, ~160 ms)

```bash
cd ine-qr-wasm
./build.sh                              # needs emsdk in $EMCC or PATH
                                        # → dist/ine_qr.{js,wasm}

# Smoke test in Node:
node test_node.mjs

# Browser demo:
python3 -m http.server 8000             # then open http://localhost:8000/
```

Self-contained: no OpenSSL, no .so, no server. AES-256-CBC, base64, and
RSA-8192 modexp are vendored in `vendor/` (~600 lines of public-domain C).
Plug a JS QR reader (e.g. `jsQR`, `@zxing/browser`) in front of `_decode_qr`
to go from a photo to JSON+WebP entirely client-side.

### Android library (AAR)

```bash
cd ine-qr-android
gradle :ine-qr:assembleRelease   # → ine-qr/build/outputs/aar/ine-qr-release.aar
gradle :ine-qr:connectedAndroidTest    # JNI marshalling + decode parity (synthetic fixture)
```

```kotlin
import mx.ine.qr.IneQr
val result = IneQr.decodeImage(photoBytes)        // ML Kit handles QR detection
println(result.json)                              // 18 biographical fields
result.webp                                       // ByteArray (WebP image)
```

Pulls `no_so_crypto.c` and `output_decode.c` from `ine-qr-c/src/` via CMake;
links BoringSSL fetched at configure time. minSdk 24, ABIs arm64-v8a,
armeabi-v7a, x86_64. ML Kit's bundled barcode SKU keeps detection offline
(no Play Services download). Full details in
[`ine-qr-android/README.md`](ine-qr-android/README.md).

### iOS / SwiftPM

```bash
cd ine-qr-ios
swift test                              # Swift marshalling + decode parity (synthetic fixture)
./scripts/build-xcframework.sh          # → dist/IneQr.xcframework
```

```swift
import IneQr
let result = try await IneQr.decodeImage(photoData)   // Vision handles QR detection
print(result.json)                                    // 18 biographical fields
result.webp                                           // Data (WebP image)
```

Symlinks the same C pipeline from `ine-qr-c/src/` and the vendored bignum
+ AES + base64 from `ine-qr-wasm/vendor/`, so the iOS package has zero
external dependencies (no OpenSSL, no Security.framework RSA round-trip).
iOS 15+, Swift 5.9, ships iOS device + iOS simulator + Mac Catalyst slices.
A `Spikes/RsaVerifyRecoverSpike.swift` is included for the user to validate
a future Security.framework-based RSA backend on real device matrices.
Full details in [`ine-qr-ios/README.md`](ine-qr-ios/README.md).

Both emulator paths below run the real `pc()` function from
`libPersonalCode.so` inside a Unicorn sandbox. Useful for re-deriving the
pipeline if a future `.so` version changes any of the hardcoded constants,
or for capturing fresh ground truth into `output/captured_*.{txt,bin}`.

> **Note:** `libPersonalCode.so` is a proprietary INE binary and is **not
> distributed with this repository**. Only the two emulator paths need it —
> extract your own copy from the official app and place it in the repo root
> (or `ine-qr-c/`). Every other implementation (pure-C, Python, WASM,
> Android, iOS, Go/Eskiu APIs) runs without the `.so`.

### C emulator path — alternative C build (0.42 s)

```bash
brew install unicorn openssl zxing-cpp
cd ine-qr-c
make emulator                  # → ine_decode_emulator (~200 KB)
./ine_decode_emulator /path/to/credential_photo.heic
                               # needs libPersonalCode.so in ./ or ../
```

`make all-paths` builds both `ine_decode` and `ine_decode_emulator`.

### Python emulator path — alternative Python pipeline (~3 s)

```bash
pip install Pillow zxing-cpp unicorn capstone lief cryptography rich
pip install pillow-heif        # optional, for HEIC/HEIF photos

python3 ine-qr-py/ine_decode.py /path/to/credential_photo.heic
python3 ine-qr-py/ine_decode.py /path/to/credential_photo.heic --verbose
```

This is the most-readable, most-hackable form of the pipeline. It loads
`libPersonalCode.so` with `lief`, disassembles with `capstone`, drives a
Unicorn ARM64 emulator from `emulate_pc.py`, and is the easiest place to
inspect or modify the cryptographic flow — for example, to dump fresh
captured buffers if you ever need to re-derive the static constants
embedded in the pure paths.

### HTTP API (Go)

A stateless HTTP wrapper around the C decoder lives in `ine-qr-api/`. The
decoder is embedded **in-process** via cgo against `libine_decode.a`, so each
request runs the full pipeline in the API process — no `fork+exec`, no temp
files on the hot path.

```bash
docker compose up --build       # serves on :8080
curl -F "photo=@credential.jpg" http://localhost:8080/decode
```

Built-in safety: `X-API-Key` auth (`API_KEY`), per-key/IP rate limiting,
queue-saturation `503` with `Retry-After`, body size cap, slowloris-safe
HTTP timeouts, and a `/stats` endpoint with p50/p95/p99 latencies. Observed
throughput on Apple Silicon at `WORKERS=8`: ~66 req/s, p95 ≈ 100 ms. Full
configuration and error semantics in [`ine-qr-api/README.md`](ine-qr-api/README.md).

---

## Performance

| Implementation                     | Total      | Crypto only | Binary / deps                   |
| ---------------------------------- | ---------- | ----------- | ------------------------------- |
| C (pure, `ine-qr-c/`, default)     | **0.19 s** | **2 ms**    | 175 KB, OpenSSL + zxing-cpp     |
| Python (pure, `no_so_pipeline.py`) | 0.32 s     | 12 ms       | `cryptography` + `numpy`        |
| WASM (`ine-qr-wasm/`, browser)     | —          | ~160 ms     | 85 KB total, zero deps          |
| Android AAR (`ine-qr-android/`)    | —          | ~2 ms       | + ML Kit barcode (bundled)      |
| iOS xcframework (`ine-qr-ios/`)    | —          | ~160 ms     | zero external deps              |
| C (emulator, `make emulator`)      | 0.42 s     | ~0.40 s     | 200 KB + libunicorn + .so       |
| Python (emulator, `ine_decode.py`) | ~3 s       | ~3 s        | + `unicorn`, `lief`, `capstone` |

Measured on Apple Silicon. The pure paths are **architecture-agnostic** —
the emulator translates ARM64 instructions and is 2-4× slower on x86 hosts;
the pure paths run native everywhere.

---

## Project Structure

```
ine-qr-analysis/
│                              # libPersonalCode.so is NOT distributed with this
│                              # repo (proprietary INE binary). Supply your own
│                              # extracted copy in the repo root to use the
│                              # emulator path; every other path runs without it.
├── README.md
├── Dockerfile, docker-compose.yml
│
├── ine-qr-c/                  # C/C++ implementations
│   ├── Makefile               # `make` → pure path; `make emulator` → emu path
│   ├── include/
│   │   ├── ine_crypto_backend.h   # 4-primitive shim (the mobile boundary)
│   │   ├── no_so_crypto.h, output_decode.h, ine_lib.h
│   │   └── …                  # emulator-only headers (ine_types.h, etc.)
│   └── src/
│       │  ── pure-C path ──
│       ├── main.c                  # Orchestration: QR → no_so_crypto → decode
│       ├── no_so_crypto.c          # Round 1+2 + Stage A/B/C, embedded constants
│       ├── crypto_backend_openssl.c  # AES/RSA/base64 on OpenSSL — also reused
│       │                              # verbatim by the Android NDK build
│       │                              # under the name crypto_backend_boringssl.c
│       │
│       │  ── emulator path ──
│       ├── main_emulator.c    # Orchestration with .so loading + emulation
│       ├── elf_loader.c       # Manual ELF64 loader + GOT/PLT relocation
│       ├── emulator.c         # Unicorn engine setup, hooks, BRK dispatch
│       ├── stub_dispatch.c    # BRK slot allocator + O(1) hash-map dispatch
│       ├── stubs_libc.c       # ~60 libc stubs (malloc, memcpy, strlen, …)
│       ├── stubs_chilkat.c    # Chilkat AES/RSA/ECC overrides
│       ├── stubs_jni.c        # JNI helpers + app-specific stubs
│       ├── bump_heap.c        # 64 MB bump allocator for emulated malloc
│       ├── static_crypto.c    # Emulator-only: pre-compute buf2 from .so .rodata
│       │
│       │  ── shared ──
│       ├── output_decode.c    # Binary → JSON + WebP + text
│       └── qr_extract.cpp     # zxing-cpp QR reader (C++ → C interface)
│
├── ine-qr-py/                 # Python implementations
│   ├── no_so_pipeline.py      # Pure-Python (recommended)
│   ├── ine_decode.py          # Emulator path entry point
│   ├── emulate_pc.py          # ARM64 emulator with Chilkat overrides
│   ├── decrypt_qr.py          # Static layers 1–2 (reference)
│   ├── decode_result.py       # pc() base64 output decoder (reference)
│   └── decode_ine_qr.py       # QR extraction from photos (reference)
│
├── ine-qr-wasm/               # WebAssembly build of the pure-crypto path
│   ├── build.sh               # emcc command (needs emsdk)
│   ├── index.html             # Browser demo
│   ├── test_node.mjs          # Node smoke test
│   ├── vendor/                # Vendored crypto (no OpenSSL needed)
│   │   ├── aes256.{c,h}       # AES-256-CBC + PKCS7
│   │   ├── base64.{c,h}       # base64 decoder
│   │   └── bignum.{c,h}       # Minimal BN_* + modexp
│   └── src/
│       ├── pipeline.c         # Adapted from no_so_crypto.c
│       ├── output_decode.c    # Adapted from C output_decode.c
│       ├── glue.c             # OpenSSL-shaped helpers over vendor/
│       └── wasm_main.c        # decode_qr / get_json_ptr / get_webp_ptr
│
├── ine-qr-android/            # Android library (AAR)
│   ├── settings.gradle.kts, build.gradle.kts
│   └── ine-qr/
│       ├── build.gradle.kts        # AGP 8.5, NDK r26, minSdk 24
│       └── src/main/
│           ├── cpp/
│           │   ├── CMakeLists.txt              # pulls ine-qr-c/src/, fetches BoringSSL
│           │   ├── crypto_backend_boringssl.c  # synced verbatim with crypto_backend_openssl.c
│           │   └── ine_jni.cpp                 # JNI bridge → IneResult
│           └── kotlin/mx/ine/qr/
│               ├── IneQr.kt        # decodeImage / decodePayloads / decodeCombined
│               ├── IneResult.kt
│               └── internal/       # NativeBridge + MlKitScanner
│
├── ine-qr-ios/                # iOS / SwiftPM package + XCFramework
│   ├── Package.swift               # IneQrCore (C) + IneQr (Swift)
│   ├── scripts/build-xcframework.sh
│   ├── Spikes/                     # RsaVerifyRecoverSpike.swift (Security.framework probe)
│   ├── IneQr/
│   │   ├── IneQr.swift, IneResult.swift, IneQrError.swift
│   │   ├── Internal/VisionScanner.swift   # Vision + CIDetector fallback
│   │   └── ce/                     # Symlinks into ine-qr-c/src and ine-qr-wasm/vendor
│   │       ├── no_so_crypto.c → ../../../ine-qr-c/src/no_so_crypto.c
│   │       ├── output_decode.c → …
│   │       ├── crypto_backend_apple.c     # Vendored bignum + AES backend
│   │       └── vendor/             # Symlinks to ine-qr-wasm/vendor/{aes256,bignum,base64}
│   └── Tests/IneQrTests/OutputDecodeParityTests.swift  # decode parity (synthetic fixture)
│
├── ine-qr-api/                # Go HTTP server wrapping the C binary
└── output/                    # Generated artifacts (git-ignored)
    ├── datos_biograficos.json, foto_ine.webp, texto_biografico.txt
    ├── qr_izquierdo.bin, qr_derecho.bin       (raw QR payloads)
    ├── pc_return_raw.bin, pc_return_decoded.bin   (emulator captures)
    └── captured_*.{txt,bin}                    (per-call emulator captures)
```

---

## Documentation

Deep technical content lives under `docs/`:

* **[docs/PIPELINE.md](docs/PIPELINE.md)** — QR structure, the 7-layer
  cryptographic pipeline, Stage A/B/C buffer layouts, 6-bit text
  encoding, hardcoded constants, and the Java JNI surface
  (`pc / gTxt / gImg`). The reference for *what* is computed.
* **[docs/EMULATOR.md](docs/EMULATOR.md)** — Memory layout, BRK stub
  dispatch, AppendBinary2 buffer injection, and the engineering
  challenges (ELF string-table guard, Chilkat dispose crashes, NEON SIMD
  verification). The reference for *how* the Unicorn sandbox runs the
  real `pc()`.
* **[docs/REVERSE_ENGINEERING.md](docs/REVERSE_ENGINEERING.md)** — The
  six-step RE narrative, verification status, and a guide to the
  ground-truth captures under `output/captured_*`.

Per-implementation READMEs:

* [`ine-qr-android/README.md`](ine-qr-android/README.md) — AAR build,
  ML Kit detail, BoringSSL pinning.
* [`ine-qr-ios/README.md`](ine-qr-ios/README.md) — SwiftPM /
  XCFramework build, Vision + CIDetector, Security.framework spike.
* [`ine-qr-api/README.md`](ine-qr-api/README.md) — Go HTTP server
  endpoints, configuration, error semantics.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE). Copyright 2026
Eduardo Dorantes. Contributions follow [`CONTRIBUTING.md`](CONTRIBUTING.md)
and the [Code of Conduct](CODE_OF_CONDUCT.md) — see the Disclaimer above for
scope, affiliation, and responsible-use terms.

---

<div align="center">
  <sub>Independent research on Mexican INE credential QR codes — no vendor code, no real personal data</sub>
</div>
