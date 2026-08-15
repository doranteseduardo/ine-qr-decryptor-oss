# Cryptographic Pipeline

Specification of the seven-layer pipeline `pc()` runs against an INE
credential's two QR codes. Reimplemented bit-exact in `ine-qr-c/src/no_so_crypto.c`,
`ine-qr-py/no_so_pipeline.py`, and `ine-qr-wasm/src/pipeline.c`, all of which
produce byte-identical output.

For the historical account of how this was recovered see
[REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md).

---

## QR Code Structure

Each INE credential carries **two QR codes** of 858 bytes each:

```
Left QR  (858 B):  [2-byte header] [856 bytes payload]
Right QR (858 B):  [2-byte header] [856 bytes payload]

Combined payload (1712 bytes):
  buf1 = bytes[   0 :  688]   (688 B)
  buf2 = bytes[ 688 : 1712]   (1024 B — RSA ciphertext)
```

Header byte 0 is `0x00` on both QRs. Header byte 1 is `0x00` on the left
QR and `0x01` on the right — that's how the scanner distinguishes them.

### What buf1 and buf2 do

* `buf2` is RSA-encrypted with key #2 (1024 bytes / 256 bytes per block
  = 4 PKCS#1 blocks).
* `buf1` is the first 688 bytes of an outer envelope. It is concatenated
  with the RSA-decrypted `buf2` to form a 1658-byte intermediate.
* The first 1024 bytes of that intermediate is then RSA-verified with
  key #4 (PKCS#1 type 01). The plaintext is the inner signed blob.
* The remaining bytes of decrypted_buf2 are appended to the inner signed
  blob to produce the working buffer the final decoder operates on.

---

## Pipeline Overview

The native `pc(Activity, byte[])` function in `libPersonalCode.so` runs a
chain of AES-CBC and RSA-8192 operations using the Chilkat library
(statically linked, ~1071 internal functions). The whole chain has been
reverse-engineered and reimplemented in pure C/Python:

```
                                   ┌──── HARDCODED CONSTANTS ───┐
                                   │  AES key/IV #1, #2         │
                                   │  4 AES ciphertexts         │
                                   │  WebP header table (23 B)  │
                                   └────────────────────────────┘

Round 1:                                   Round 2:
   AES(CT_R1_KEY, key1/iv1)   → XML#1         AES(CT_R2_KEY, key2/iv2)   → XML#3
   AES(CT_R1_BLOB, key1/iv1)  → b64 blob      AES(CT_R2_BLOB, key2/iv2)  → b64 blob
   RSA-decrypt(blob, key#1)   → XML#2         RSA-decrypt(blob, key#3)   → XML#4

Stage A — RSA-decrypt(buf2, key#2)  → 970-byte intermediate (PKCS#1 type 02)

Stage B — stack_buf = (buf1 + 970-byte intermediate)[:1024]
          RSA-verify(stack_buf, key#4)  → 1013-byte inner blob (PKCS#1 type 01)

Stage C — work_buf = inner_blob + intermediate[336:]   (1647 B)
          decode the structured layout below → text + WebP
```

All RSA keys are 8192-bit (1024-byte modulus, exponent 65537).

---

## Working buffer layout (Stage C input)

| Offset                             | Size       | Field                                                                  |
| ---------------------------------- | ---------- | ---------------------------------------------------------------------- |
| `[0]`                              | 1 B        | Control byte `b0` (always 0)                                           |
| `[b0+2 … b0+0x42]`                 | 64 B       | Raw ECDSA signature (r ‖ s, 32 B each on secp256r1)                    |
| `[b0+0x42 … b0+0x44]`              | 2 B BE     | Number of input bytes used by the text decoder                         |
| `[b0+0x44 …]`                      | variable   | Packed 6-bit text data (custom alphabet)                               |
| *next*                             | 2 B BE     | Length of an interstitial field (skipped by the decoder)               |
| `w25+6`                            | 2 B BE     | Image-data length                                                      |
| `w25+8 …`                          | variable   | WebP image bytes (interleaved with the `.rodata` header table)         |

The text section is unpacked one bit at a time (8 input bits MSB-first per
byte → 6-bit output values, one per output byte). The image is reconstructed
by interleaving payload bytes with a hardcoded 23-byte WebP header table at
specific positions (`{4,5,16,17,20,21,28}` and `>29` come from input;
positions in `{0..27}` minus those come from the table).

```
_WEBP_HDR_TABLE = 52 49 46 46  __ __ __ __  57 45 42 50  56 50 38 20
                  __ __ __ __  9D 01 2A 60  00 00 00 __
(__ = byte from QR payload, rest from the table)
```

Result: a valid 96 × 129 px WebP — byte-for-byte identical to what the
official app shows.

### Final output format

```
[text_len:u16 BE] [encoded_text:N bytes] [img_len:u16 BE] [WebP image]
```

### Text encoding

The text uses a custom 6-bit-per-character alphabet (Spanish with Ñ):

| Code      | Character | Code      | Character        |
| --------- | --------- | --------- | ---------------- |
| 0x01–0x0E | A–N       | 0x1C–0x25 | 0–9              |
| 0x0F      | Ñ         | 0x28      | `/`              |
| 0x10–0x1B | O–Z       | 0x39      | `\|` (separator) |

Fields are pipe-delimited: `tipo|cic|ocr|curp|nombre|apellido1|…`

---

## Hardcoded Constants

All constants below are extracted once from `libPersonalCode.so .rodata`
and embedded directly into the source. They are stable across `.so`
versions of the official app, since the underlying NEON/SIMD blocks (in
the original binary) derive them from constant inputs only — no QR data
participates in key derivation.

```
AES KEY #1: 0001029836537892876377726A4E78E77F987CC321180281AABB019654321000
AES IV  #1: 0192C58D36E47A589AF01928376428AA
AES KEY #2: 00010298310293A573C93A745AD38298F36E0928777726A4E78E77F1AABB0197
AES IV  #2: 10293A573C93A745AD38298F36E09287

CT_R1_KEY   (1456 bytes, AES-encrypted RSA-XML #1)
CT_R1_BLOB  (2736 bytes, AES-encrypted base64 RSA blob)
CT_R2_KEY   (1456 bytes, AES-encrypted RSA-XML #3)
CT_R2_BLOB  (2736 bytes, AES-encrypted base64 RSA blob)

WebP header table  (23 bytes: RIFF / WEBP / VP8 / 9D 01 2A …)
```

The four ciphertexts and the header table are reproduced verbatim in
`ine-qr-c/src/no_so_crypto.c`, `ine-qr-py/no_so_pipeline.py` and
`ine-qr-wasm/src/pipeline.c`, which is all any implementation needs. The
`.rodata` addresses they were originally read from inside the proprietary
binary are deliberately not published here.

---

## Java Integration

The Java class `com.personalcode.Azf` declares:

```java
private final native String pc(Activity act, byte[] data);
private final native String gTxt(String data);
private final native Bitmap gImg(String data);
```

The app:

1. Scans both QR codes (858 bytes each).
2. Concatenates into a 1712-byte buffer (skipping the 2-byte header on each).
3. Calls `pc(activity, buffer)` → opaque base64 token.
4. `gTxt(token)` → pipe-delimited biographical text.
5. `gImg(token)` → WebP bitmap.

The base64 token is the binary `[text_len][text][img_len][img]` blob
produced by Stage C above; `gTxt` and `gImg` are thin parsers over that
format. (The `pc / gTxt / gImg` JNI surface was recovered by analysing the
official app's `com.personalcode.Azf` class; no decompiled app sources are
redistributed in this repository.)
