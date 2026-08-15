# How the Pipeline Was Reverse-Engineered

A case study. From an Android APK, one credential photo, and a description
of the expected output — to a fully self-contained decoder in several
languages.

For the technical specification of what was discovered see
[PIPELINE.md](PIPELINE.md).

> **On the research harness.** The pipeline was originally understood with
> a dynamic-analysis harness (an ARM64 emulator that ran the native `pc()`
> and captured its intermediate values). That harness was an investigation
> instrument only and is **not part of this public release**: no emulator,
> ELF loader, or environment/license stubs — nor the proprietary `.so` they
> would run — are included here. What ships is the clean-room
> reimplementation the harness made possible, which needs none of it. The
> account below refers to that original research to explain *how the
> algorithm was recovered*, not to provide a way to re-run the binary.

The starting position:

* `PersonalCode-INE v5.0.11` APK.
* One credential photo, supplied by its own holder.
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

### The crypto stack

The Chilkat surface was decisive — a well-known set of symbol names we
could instrument:

* `CkCrypt2_SetEncodedKey` / `CkCrypt2_decryptStringENC` — symmetric AES.
* `CkRsa_ImportPublicKey` / `CkRsa_DecryptBd` — public-key RSA.
* `CkEcc` — ECDSA (later confirmed P-256 / P-384 / P-521).

### Hardcoded ciphertexts in `.rodata`

| Constant     | Length            | Purpose                                        |
| ------------ | ----------------- | ---------------------------------------------- |
| `CT_R1_KEY`  | ~7,168 hex chars  | AES-CBC ciphertext for RSA Public Key #1 XML   |
| `CT_R1_BLOB` | ~16,384 hex chars | AES-CBC ciphertext for RSA-encrypted data blob |

Two more pairs (`CT_R2_KEY/BLOB`, `CT_R3_KEY/BLOB`) sat further along in
the same section. Three (key, blob) pairs feeding three rounds of
AES → RSA — a classic onion-of-keys.

### The 60-constant catalogue

Two runs of 16-byte vectors in `.rodata` feed the key derivation. Every
one of those constants now lives inside `no_so_pipeline.py`'s `_RODATA`
dict — which is all any implementation needs; the addresses they were
read from inside the proprietary binary are not published here.

---

## Phase 3 — Observing the pipeline at runtime

Static analysis alone could not confirm what the SIMD blocks computed or
what data flowed through `pc()` at runtime. The research harness ran the
native function under emulation and logged every external call — every
libc / pthread / Chilkat / JNI entry point became an observable event —
so the intermediate keys and buffers could be captured without ever
invoking the JVM. Those captures are the ground truth the pure paths were
later checked against.

The harness itself is not published (see the note at the top of this
document); what follows is what it revealed.

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
| 1a    | `CT_R1_KEY`              | AES-CBC                               | RSA Public Key #1 (XML)      |
| 1b    | `CT_R1_BLOB`             | AES-CBC                               | Base64 of RSA-encrypted blob |
| 2     | output of 1b             | RSA decrypt with key #1               | RSA Public Key #2 (XML)      |
| 3a    | hardcoded `CT_R2_KEY`    | AES-CBC                               | RSA Public Key #3 (XML)      |
| 3b    | hardcoded `CT_R2_BLOB`   | AES-CBC + RSA decrypt with key #3     | RSA Public Key #4 (XML)      |
| 4     | buf2 from QR (1024 B)    | RSA decrypt with key #2               | 970-byte intermediate        |
| 5     | `buf1 ‖ decrypted_buf2`  | RSA verify with key #4 (PKCS#1 type 1)| Inner signed blob (1647 B)   |

Every key recovered is an RSA *public* key — the `.so` is verifying
signatures and unwrapping nested keys produced by INE offline. Consistent
with INE controlling the signing keys.

### Tactical shortcut: pre-compute RSA

RSA under emulation is slow. Once key #2 was recovered, buf2 could be
pre-decrypted host-side (`cryptography` handles modular exponentiation
natively) and the plaintext observed directly — which is exactly the shape
the pure paths take, doing all the RSA natively and never touching the
`.so` at all.

---

## Phase 5 — Decoding the NEON key derivation

### The unsolved question

Where do the AES key + IV come from? Static analysis showed they were
computed at runtime by **six tight ARM64 NEON SIMD blocks**. They read
16-byte vectors from `.rodata`, applied chains of vector ADD/SUB/ROT/XOR,
and emitted ASCII hex bytes.

### Why we re-implemented the NEON code

Translating the SIMD blocks mattered for two reasons:

1. The `.so` refuses to run if any of the constants are swapped at load
   time. Capturing the SIMD output by tracing wasn't enough; we needed to
   be able to *derive* the keys without ever running the binary.
2. With the SIMD blocks in pure Python, we could derive the AES key
   without ever touching the `.so` file — the critical insight that makes
   `no_so_pipeline.py` possible at all.

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

We already had the AES key/IV captured from the running binary — so when
`_block0_aes_iv()` returned `0192C58D36E47A589AF01928376428AA` and
`_block1_aes_key()` returned the 32-byte AES key byte-for-byte, the
translation was certified correct. Same exercise for the four sibling
blocks that produce keys 2 and 3. All six now run in **well under 1 ms**
in NumPy.

### Sample of the recovered constants

```
22a021ed daee6e5b 71f3d4f7 756223fb
0100fffe fdfcfbfa f9f8f7f6 f5f4f3f2
00010203 04050607 08090a0b 0c0d0e0f
00fffefd fcfbfaf9 f8f7f6f5 f4f3f2f1
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

## Phase 7 — Pure Python, then C and the mobile ports

### `no_so_pipeline.py` — proof of complete RE

One ~1,000-line Python file with **no emulator and no .so dependency**.
Hardcodes every recovered constant and re-runs the full pipeline in
NumPy + `cryptography`:

* `_RODATA` — 60 hardcoded 16-byte constants.
* `_CT` — three (AES key, AES blob) pairs as hex strings.
* Six SIMD blocks `_block0…_block5` in NumPy.
* Three rounds of `_aes_rsa_round()`.
* `_decode_buf2()`, `_decode_final_blob()` for the bit-packed decoder
  + WebP reconstruction.

### Production port

Once Python validated the algorithm, `ine-qr-c` reimplements it against
OpenSSL + zxing-cpp. The Makefile produces:

* `ine_decode` — CLI: image → JSON + WebP.
* `libine_decode.a` — static archive for embedding the decoder in another
  process via FFI.

From there the same C sources were reused unchanged by the Android (NDK +
BoringSSL), iOS (SwiftPM + vendored crypto) and WebAssembly builds, and
ported a second time to Eskiu — a set of independent implementations that
must all agree byte-for-byte.

---

## Performance

Stage-by-stage, on Apple Silicon:

| Stage                | Pure Python  | Pure C       |
| -------------------- | ------------ | ------------ |
| QR extraction (zxing)| ~80 ms       | ~80 ms       |
| Crypto pipeline      | ~25 ms       | ~2 ms        |
| Output decode        | ~5 ms        | ~1 ms        |
| **Total per image**  | **~110 ms**  | **~90 ms**   |

---

## Verification status

The independent implementations (pure-C, pure-Python, WASM, Android, iOS,
Eskiu) all produce byte-for-byte identical output — the same JSON fields
and the same WebP photo — which is the regression signal the project runs
on: a transcription error in any one path would break parity with the
others.

Both pure paths skip the optional ECDSA signature verification (key #5 +
signature in the working buffer); add it back if you need authenticity
guarantees.

---

## Reproducible recipe

The high-level path any future engineer can follow to repeat the work,
without redistributing any vendor material:

1. Decompile the APK with `apktool` + `jadx`; locate the JNI bridge class
   (`Azf`, `com.personalcode`).
2. Identify the native function (`pc`) and confirm input is
   `left[2:] || right[2:]`.
3. Inventory the native library (architecture, imports, Chilkat surface).
4. Observe the pipeline at runtime and capture the AES key + IV; decrypt
   the `.rodata` ciphertexts with any AES implementation.
5. Trace the three-round AES + RSA chain; recover RSA keys #1, #2, #3, #4
   in XML form.
6. Disassemble the six NEON SIMD key-derivation blocks and translate them
   to plain integer ops.
7. Verify the SIMD translation by comparing its output to the captured
   AES key/IV.
8. Document the QR layout (header bytes, buf1/buf2 split) and the
   1,658-byte final blob format.
9. Decode the 6-bit text alphabet and the WebP-with-header-table
   reconstruction.
10. Reimplement everything as `no_so_pipeline.py` with no .so dependency.
11. Port to C against OpenSSL + zxing-cpp, then reuse those same sources
    for the WASM, Android and iOS builds.

---

## Ground-truth captures

During the original research the harness wrote a corpus of captured
intermediate values (per-AES-call inputs, RSA key XML, the raw and decoded
`pc()` return, and the two 858-byte QR payloads) that the pure paths were
validated against. Those captures derive from a real credential and are
**not included in this repository**; the shipped parity tests instead use
the synthetic, PII-free fixture produced by
`scripts/gen_synthetic_fixture.py`.
