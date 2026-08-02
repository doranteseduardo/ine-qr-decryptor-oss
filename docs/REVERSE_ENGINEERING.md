# How the Pipeline Was Reverse-Engineered

A case study. From an Android APK, one credential photo, and a description
of the expected output — to a fully self-contained decoder in three
languages.

For the technical specification of what was discovered see
[PIPELINE.md](PIPELINE.md); for the Unicorn-sandbox details see
[EMULATOR.md](EMULATOR.md).

The starting position:

* `PersonalCode-INE v5.0.11` APK.
* One credential photo (`IMG_8372.HEIC`).
* The in-app screen as the **oracle** — 18 biographical fields plus the
  embedded photo, displayed by the official app for that exact image.
* No source, no test vectors, no vendor cooperation.

What made the project converge: every layer was treated as an independent
black box, and we only moved past a layer once it had a deterministic
test vector. The APK gave us the input. The credential image gave us a
real test case. The official app's display gave us the oracle. With those
three anchors fixed, every step had a binary success criterion.

---

## Phase 1 — Static APK analysis

### Locating the JNI bridge

`apktool` + `jadx` surfaced a Kotlin class `com.personalcode.Azf` with all
field names obfuscated by DexGuard (meaningless names like
`t685175933260u`). The Java surface was tractable anyway — five native
methods on top of a single `System.loadLibrary("PersonalCode")`:

```java
private final native Bitmap gImg(String data);
private final native String  gTxt(String data);
private final native String  pc(Activity act, byte[] data);   // ← the heart
public  final native int     getRemaining(Activity activity);
public  final native boolean isUpToDate(Activity activity);
```

### What the Java side does

* Two byte buffers `t685175933260u` and `t685175933261u` hold the raw
  scans of the two QR codes (858 bytes each).
* `System.arraycopy(bArr, 2, bArr3, …)` strips the 2-byte header from
  each QR and concatenates them into a 1,712-byte buffer.
* That buffer is passed to `pc(activity, data)` — the only function that
  matters.
* The returned `String` is fed to `gTxt()` / `gImg()` to produce text
  + photo.

The Java side also exposed a helper, `Azf.acc(rawQR, type=-1, ext=false)`,
which unpacks each QR by re-aligning nibbles — verified by the size
constraint `((b1<<4)|(b2>>4)) >= 800`. And the character set used by the
final decoder is referenced in Java via constants like `JSON_TAG_TIPO`,
`JSON_TAG_CIC`, `JSON_TAG_CURP`, confirming the field set we expected to
recover. The decoded text is stuffed into a `JSONObject` by
`Azf.t452356517317u`.

By the end of Phase 1 we had the function name, signature, and the exact
pre-processing. Everything we needed to reverse-engineer lived inside one
native binary: `libPersonalCode.so`.

---

## Phase 2 — Cracking open `libPersonalCode.so`

### Inventory

| Property                  | Value                                                                |
| ------------------------- | -------------------------------------------------------------------- |
| Architecture              | AArch64 (ARM64) Android NDK                                          |
| Total size                | ~4.6 MB                                                              |
| Imported symbols          | 183 external (libc, pthread, dlopen, …)                              |
| Internal PLT/GOT entries  | 1,071 internal stubs                                                 |
| Visible C++ symbols       | Heavy `Chilkat` namespace (`CkCrypt2`, `CkRsa`, `CkEcc`, `CkGlobal`) |
| Anti-tampering            | `isSafeEnvironment`, `hR` (license), `updateCtr`                     |

### The crypto stack

The Chilkat surface was decisive — a well-known set of symbol names we
could instrument:

* `CkCrypt2_SetEncodedKey` / `CkCrypt2_decryptStringENC` — symmetric AES.
* `CkRsa_ImportPublicKey` / `CkRsa_DecryptBd` — public-key RSA.
* `CkEcc` — ECDSA (later confirmed P-256 / P-384 / P-521).
* `CkGlobal_UnlockBundle` — Chilkat licensing call (the one that breaks
  under emulation).

### Hardcoded ciphertexts in `.rodata`

| Offset      | Length            | Purpose                                       |
| ----------- | ----------------- | --------------------------------------------- |
| `0x1182CD`  | ~7,168 hex chars  | AES-CBC ciphertext for RSA Public Key #1 XML  |
| `0xD05AE`   | ~16,384 hex chars | AES-CBC ciphertext for RSA-encrypted data blob |

Two more pairs (`CT_R2_KEY/BLOB`, `CT_R3_KEY/BLOB`) sat at later offsets.
Three (key, blob) pairs feeding three rounds of AES → RSA — a classic
onion-of-keys.

Cross-referencing the Java side against `.rodata` also surfaced a
DexGuard fingerprint (the `"WhiteBoxCipher"` blob with the key
`F5B97F8F4B`) — but the actual crypto path we cared about ran through
Chilkat. DexGuard was used elsewhere for asset protection, not for the
QR pipeline itself.

### The 60-constant catalogue

Cross-referenced 16-byte vectors at `0x1249E7..0x124AFC` and
`0xBA5C0..0xBABD0`. Every one of these constants now lives inside
`no_so_pipeline.py`'s `_RODATA` dict.

---

## Phase 3 — Building the ARM64 emulator

### Why Unicorn

Static analysis alone could not confirm what the SIMD blocks computed or
what data flowed through `pc()` at runtime. Unicorn lets us hook every
memory access and every external call without ever invoking the JVM.

### The harness (`emulate_pc.py`)

1. Loads `libPersonalCode.so` with `lief`, walks program headers, maps
   every `PT_LOAD` at base `0x10000000`.
2. Allocates dedicated regions: stack 4 MB, heap 64 MB, TLS, function
   stubs, return-address trap.
3. Walks PLT/GOT + dynamic relocations and rewrites every external GOT
   entry to a `BRK` trap whose handler is in Python.
4. Dispatches BRK exceptions to per-symbol Python handlers — every
   libc / pthread / Chilkat / JNI call becomes a normal function.

The C port (`ine-qr-c/src/emulator.c` + `stub_dispatch.c`) implements the
same architecture — see [EMULATOR.md](EMULATOR.md) for the memory layout
and dispatcher details.

---

## Phase 4 — Capturing the crypto pipeline

### The AES layer (captured live)

```
AES_KEY = 0001029836537892876377726A4E78E77F987CC321180281AABB019654321000
AES_IV  = 0192C58D36E47A589AF01928376428AA
Mode    = AES-256-CBC, PKCS7 padding
```

### The RSA chain — peel back the onion

| Round | Input ciphertext         | Decryption                            | Output                       |
| ----- | ------------------------ | ------------------------------------- | ---------------------------- |
| 1a    | `0x1182CD`               | AES-CBC                               | RSA Public Key #1 (XML)      |
| 1b    | `0xD05AE`                | AES-CBC                               | Base64 of RSA-encrypted blob |
| 2     | output of 1b             | RSA decrypt with key #1               | RSA Public Key #2 (XML)      |
| 3a    | hardcoded `CT_R2_KEY`    | AES-CBC                               | RSA Public Key #3 (XML)      |
| 3b    | hardcoded `CT_R2_BLOB`   | AES-CBC + RSA decrypt with key #3     | RSA Public Key #4 (XML)      |
| 4     | buf2 from QR (1024 B)    | RSA decrypt with key #2               | 970-byte intermediate        |
| 5     | `buf1 ‖ decrypted_buf2`  | RSA verify with key #4 (PKCS#1 type 1)| Inner signed blob (1647 B)   |

Every key recovered is an RSA *public* key — the `.so` is verifying
signatures and unwrapping nested keys produced by INE offline. Consistent
with INE controlling the signing keys.

### Tactical shortcut: pre-compute RSA

Chilkat's RSA code is slow under emulation. Once key #2 is recovered we
pre-decrypt buf2 in Python (`cryptography` handles modular exponentiation
natively) and inject the plaintext back into the emulator's heap, skipping
the native RSA call entirely.

---

## Phase 5 — Decoding the NEON key derivation

### The unsolved question

Where do the AES key + IV come from? Static analysis showed they were
computed at runtime by **six tight ARM64 NEON SIMD blocks** at virtual
addresses `0x1DCE60..0x1DD1E0` and siblings. They read 16-byte vectors
from `.rodata`, applied chains of vector ADD/SUB/ROT/XOR, and emitted
ASCII hex bytes.

### Why we re-implemented the NEON code

Translating the SIMD blocks mattered for two reasons:

1. The `.so` contains **anti-debug guards** that refuse to run if any of
   the constants are swapped at load time — meaning the constants are
   not swapped, but they are also not patched out. Capturing the SIMD
   output by tracing wasn't enough; we needed to be able to *derive*
   the keys without ever running the binary.
2. With the SIMD blocks in pure Python, we could derive the AES key
   without ever touching the `.so` file or Unicorn — the critical
   insight that makes `no_so_pipeline.py` possible at all.

### One-to-one translation

We disassembled each block with Capstone and translated every instruction
into NumPy uint8 ops:

| ARM64 NEON                         | NumPy uint8                          |
| ---------------------------------- | ------------------------------------ |
| `ADD V0.16B, V1.16B, V2.16B`       | `(a + b).astype(uint8)`              |
| `EOR V0.16B, V1.16B, V2.16B`       | `a ^ b`                              |
| `USHR / SHL / SLI`                 | `rot(v, n)` with 8-bit wrap          |
| `LDR Q0, [.rodata + N]`            | `_RODATA[key]`                       |

### Verification

We already had the AES key/IV from the live emulator — so when
`_block0_aes_iv()` returned `0192C58D36E47A589AF01928376428AA` and
`_block1_aes_key()` returned the 32-byte AES key byte-for-byte, the
translation was certified correct. Same exercise for the four sibling
blocks that produce keys 2 and 3. All six now run in **well under 1 ms**
in NumPy.

### Sample of the recovered constants

```
R_1249E7   22a021ed daee6e5b 71f3d4f7 756223fb
R_BA6B0    0100fffe fdfcfbfa f9f8f7f6 f5f4f3f2
R_BABC0    00010203 04050607 08090a0b 0c0d0e0f
R_BAB00    00fffefd fcfbfaf9 f8f7f6f5 f4f3f2f1
```

60 constants total — full catalogue lives in `no_so_pipeline.py`'s
`_RODATA` dict.

---

## Phase 6 — QR wire format + final blob

(See [PIPELINE.md](PIPELINE.md) for the full specification including the
6-bit alphabet table and WebP header reconstruction details.)

The result is a valid 96 × 129 px WebP — byte-for-byte identical to what
the official app shows.

---

## Phase 7 — Pure Python, then C + Go API

### `no_so_pipeline.py` — proof of complete RE

One ~1,000-line Python file with **no Unicorn, no LIEF, no Capstone, no
.so dependency**. Hardcodes every recovered constant and re-runs the full
pipeline in NumPy + `cryptography`:

* `_RODATA` — 60 hardcoded 16-byte constants.
* `_CT` — three (AES key, AES blob) pairs as hex strings.
* Six SIMD blocks `_block0…_block5` in NumPy.
* Three rounds of `_aes_rsa_round()`.
* `_decode_buf2()`, `_decode_final_blob()` for the bit-packed decoder
  + WebP reconstruction.

### Production port

Once Python validated the algorithm, `ine-qr-c` reimplements it against
OpenSSL + zxing-cpp. The Makefile produces three targets:

* `ine_decode` — CLI: image → JSON + WebP.
* `libine_decode.a` — static library for cgo embedding.
* `ine_decode_emulator` — Unicorn-backed reference, used as a regression
  oracle.

`ine-qr-api` wraps that library in a Go HTTP server (`POST /decode`) with
per-API-key rate limiting, a worker semaphore, request-size caps, and
timing telemetry.

---

## Performance

Stage-by-stage, on Apple Silicon:

| Stage                | Pure Python  | Pure C       | Emulator     |
| -------------------- | ------------ | ------------ | ------------ |
| QR extraction (zxing)| ~80 ms       | ~80 ms       | ~80 ms       |
| Crypto pipeline      | ~25 ms       | ~2 ms        | ~8 s         |
| Output decode        | ~5 ms        | ~1 ms        | ~5 ms        |
| **Total per image**  | **~110 ms**  | **~90 ms**   | **~8 s**     |

The emulator is intentionally slow — it executes the `.so` byte-by-byte.
We keep it as a regression check, not as a production path.

Go API throughput on Apple M-series, `MAX_LONG_EDGE=3000`:

| Concurrency     | Throughput   |
| --------------- | ------------ |
| Sequential      | ~10 req/s    |
| 4 in parallel   | ~37 req/s    |
| 8 in parallel   | ~66 req/s    |

---

## Verification status

The pure-C and pure-Python implementations match the emulator's outputs
byte-for-byte (`pc_return_decoded.bin`, `foto_ine.webp`,
`texto_biografico.txt`).

Both pure paths skip the optional ECDSA signature verification (key #5 +
signature in the working buffer); add it back if you need authenticity
guarantees — the emulator path performs it natively as part of running
the real `pc()`.

---

## 14-step reproducible recipe

What any future engineer can follow to repeat the work:

1. Decompile the APK with `apktool` + `jadx`; locate the JNI bridge class
   (`Azf`, `com.personalcode`).
2. Identify the native function (`pc`) and confirm input is
   `left[2:] || right[2:]`.
3. Pull `libPersonalCode.so` and inventory it (architecture, imports,
   Chilkat surface).
4. Build a Unicorn ARM64 harness: load segments, fix relocations, stub
   libc / pthread / JNI.
5. Override Chilkat AES + RSA primitives so the emulator runs without a
   Chilkat license.
6. Capture AES key + IV by logging Chilkat calls; decrypt the `.rodata`
   ciphertexts in Python.
7. Trace the three-round AES + RSA chain; recover RSA keys #1, #2, #3, #4
   in XML form.
8. Disassemble the six NEON SIMD key-derivation blocks and translate them
   to NumPy uint8 ops.
9. Verify the SIMD translation by comparing its output to the captured
   AES key/IV.
10. Document the QR layout (header bytes, buf1/buf2 split) and the
    1,658-byte final blob format.
11. Decode the 6-bit text alphabet and the WebP-with-header-table
    reconstruction.
12. Reimplement everything as `no_so_pipeline.py` with no .so / Unicorn
    dependency.
13. Validate Python vs Emulator byte-for-byte on real images.
14. Port to C against OpenSSL + zxing-cpp; expose via a Go HTTP API for
    production.

---

## Useful artifacts under `output/`

| File                                  | Purpose                                              |
| ------------------------------------- | ---------------------------------------------------- |
| `captured_CkCrypt2_*.txt`             | Per-AES-call inputs (key, IV, ciphertext, plaintext) |
| `captured_CkRsa_*.txt`                | RSA key XML + decrypt inputs/outputs                 |
| `captured_data_CkBinData_*.bin`       | The two AppendBinary2 buffers (688 + 1024 + 1024 B)  |
| `pc_return_raw.bin`                   | Final base64 token that `pc()` returns to Java       |
| `pc_return_decoded.bin`               | Same after base64 decode (Stage C output format)     |
| `qr_izquierdo.bin` / `qr_derecho.bin` | Raw 858-byte QR payloads (left / right)              |

The `captured_*` files are the verification corpus for any future change
to the pure paths — re-run the emulator on a fresh credential photo and
diff against the new pure-path output to catch regressions.
