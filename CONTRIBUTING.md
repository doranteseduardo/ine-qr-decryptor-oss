# Contributing

Thanks for your interest in improving this project. It reverse-engineers and
reimplements the INE credential QR decode pipeline in several parallel forms.
Please read the ground rules below before opening an issue or PR.

## Ground rules (read this first)

- **Never add real credential data.** Do not include real CURPs, names, photos,
  or captured/encrypted QR bytes in any commit, PR, issue, comment, or test
  fixture. All fixtures must be synthetic. Regenerate the synthetic fixtures
  with `scripts/gen_synthetic_fixture.py` (it injects obviously-fake values at
  the one crypto-free seam, `decode_to_buffers()`).
- **No vendor code or binaries.** Do not add proprietary source, decompiled
  code, or the `libPersonalCode.so` binary. Factual descriptions of recovered
  constants and pipeline structure are fine; copied vendor source is not.
- **Be respectful.** See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

By contributing, you agree your contributions are licensed under the project's
[Apache License 2.0](LICENSE).

## Why fixtures are synthetic

A genuine encrypted QR payload cannot be fabricated: the pipeline's RSA layers
use recovered **public** keys (INE holds the private key), so there is no
"encode" direction. Tests therefore inject synthetic data at `decode_to_buffers()`
— a pure, crypto-free function that parses an already-decrypted buffer into the
18 fields + WebP photo — via test-only entry points (`decodeDecryptedNative` on
Android, `IneQr.decodeDecrypted` on iOS, `_decode_decrypted` in WASM). Full
AES/RSA crypto-layer regression against a real credential remains a manual,
non-public process for the maintainer and never lands in this repo.

## Building and testing each sub-project

Each directory has its own README with full detail; quick reference:

### `ine-qr-c/` — C/C++ reference (pure + emulator)
```bash
cd ine-qr-c
make            # pure-C CLI (ine_decode)
make lib        # libine_decode.a (consumed by the Go API via cgo)
make emulator   # Unicorn path (needs libunicorn + your own libPersonalCode.so)
```
Deps: OpenSSL, zxing-cpp. The pure-C output is the byte-exact reference the other
paths are checked against.

### `ine-qr-py/` — Python (pure + emulator)
```bash
python3 ine-qr-py/no_so_pipeline.py <photo>   # pure path
python3 ine-qr-py/ine_decode.py     <photo>   # emulator path
```
Deps: `cryptography numpy Pillow zxing-cpp` (+ `unicorn capstone lief` for the
emulator path).

### `ine-qr-wasm/` — WebAssembly
```bash
cd ine-qr-wasm
./build.sh              # needs emsdk (emcc on PATH, or $EMCC)
node test_node.mjs      # smoke test against fixtures/synthetic_decoded.bin
```

### `ine-qr-android/` — Android AAR
```bash
cd ine-qr-android
gradle :ine-qr:assembleRelease        # build the AAR
gradle :ine-qr:connectedAndroidTest   # OutputDecodeParityTest (needs a device/emulator)
```

### `ine-qr-ios/` — Swift package / XCFramework
```bash
cd ine-qr-ios
swift test                       # OutputDecodeParityTests
./scripts/build-xcframework.sh   # build IneQr.xcframework
```

### `ine-qr-api/` — Go HTTP API
```bash
docker compose up --build        # serves on :8080
# or, without Docker (needs ine-qr-c built):
cd ine-qr-api && go build -o ine_api .
```

### `ine-qr-eskiu/` — Eskiu implementation + HTTP API
```bash
cd ine-qr-eskiu
make            # needs eskiuc on PATH (see ine-qr-eskiu/README.md)
make test       # crypto+output parity
```

## Continuous integration

`.github/workflows/ci.yml` builds the C reference, the Linux static archive, the
Android AAR, and runs the iOS parity tests. One check to be aware of:

- **`backend-sync`** diffs `ine-qr-c/src/crypto_backend_openssl.c` against
  `ine-qr-android/ine-qr/src/main/cpp/crypto_backend_boringssl.c` from the first
  `#include "ine_crypto_backend.h"` onward. The two backend bodies must stay
  **byte-identical** — if you edit one, edit the other the same way, or CI fails.

## Pull requests

- Keep changes focused; describe what and why.
- Update the relevant sub-project README when you change its build/test flow.
- Make sure the sub-projects you touched still build and their tests pass.
