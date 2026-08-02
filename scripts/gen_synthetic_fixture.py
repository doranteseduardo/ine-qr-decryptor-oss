#!/usr/bin/env python3
"""
gen_synthetic_fixture.py — build a synthetic, PII-free test fixture for the
INE QR output decoder.

WHY THIS EXISTS
---------------
The full decode pipeline ends in `decode_to_buffers()` (ine-qr-c/src/output_decode.c),
a pure, crypto-free function that parses an *already-decrypted* buffer into the
18 biographical fields (JSON) plus the credential photo (WebP). Its input layout:

    [2 bytes BE]  text_len
    [text_len  ]  text_data  — '|'-separated fields, one byte per char via CHAR_TABLE
    [2 bytes BE]  img_len
    [img_len   ]  img_data   — WebP photo, copied through verbatim (no validation)

It is cryptographically impossible to forge a *valid encrypted* QR payload with
fabricated data (the RSA layers use recovered PUBLIC keys; INE holds the private
key), so tests can never round-trip fake data through the crypto stages. Instead
we inject synthetic data at this one crypto-free seam: this script emits
`synthetic_decoded.bin`, the exact buffer `decode_to_buffers()` expects, carrying
obviously-fake values and a placeholder photo. No real credential data is used.

The matching `expected.json` / `expected.webp` are NOT hand-written — they are
produced by running the real C `decode_to_buffers()` over this buffer (see
scripts/roundtrip_decode.c), guaranteeing the fixtures match the shipping code.

USAGE
-----
    python3 scripts/gen_synthetic_fixture.py <out_dir>

Writes <out_dir>/synthetic_decoded.bin and <out_dir>/synthetic_photo.webp.
"""
import struct
import sys
from PIL import Image

# ── Reverse of output_decode.c's CHAR_TABLE (char -> byte code) ──────────────
# 1..27  -> A-Z with Ñ at 15 ; 28..37 -> 0-9 ; 40 -> '/' ; 57 -> '|'
LETTERS = "ABCDEFGHIJKLMNÑOPQRSTUVWXYZ"
ENCODE = {}
for i, ch in enumerate(LETTERS):
    ENCODE[ch] = i + 1
for d in range(10):
    ENCODE[str(d)] = 28 + d
ENCODE["/"] = 40
PIPE = 57  # field separator


def encode_text(fields):
    """Encode a list of field strings to CHAR_TABLE bytes, '|'-separated."""
    out = bytearray()
    for idx, field in enumerate(fields):
        if idx:
            out.append(PIPE)
        for ch in field:
            if ch not in ENCODE:
                raise ValueError(
                    f"char {ch!r} in field {idx} ({field!r}) is not encodable "
                    f"by CHAR_TABLE (only A-Z, Ñ, 0-9, '/')"
                )
            out.append(ENCODE[ch])
    return bytes(out)


# ── Synthetic, unmistakably-fake credential fields (FIELD_LABELS order) ───────
# CURP XEXX010101HNEXXXA4 is the well-known placeholder pattern. Names are the
# canonical JUAN PEREZ EXAMPLE. Everything else is structurally plausible but
# all-zeros / obvious dummy values. No spaces (CHAR_TABLE has none).
FIELDS = [
    "N",                    # tipo
    "000000000",            # cic  (9 digits)
    "0000000000000",        # ocr  (13 digits)
    "XEXX010101HNEXXXA4",   # curp (placeholder pattern, 18 chars)
    "JUAN",                 # nombre
    "PEREZ",                # apellido1
    "EXAMPLE",              # apellido2
    "09",                   # entidad
    "001",                  # municipio
    "0001",                 # seccion
    "",                     # etnia (empty)
    "2020/2030",            # vigencia
    "H",                    # sexo
    "1",                    # indiceHuella1
    "",                     # indiceHuella2 (empty)
    "X",                    # version
    "20200101",             # fechaGeneracion
    # firmaVerificadora — obviously-fake repeating hex, not a real signature
    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
]


def make_placeholder_webp(width=96, height=129):
    """A synthetic 96x129 test-pattern WebP standing in for the photo."""
    img = Image.new("RGB", (width, height))
    px = img.load()
    for y in range(height):
        for x in range(width):
            # simple diagonal gradient — clearly not a real face
            px[x, y] = ((x * 255) // width, (y * 255) // height, 128)
    import io
    buf = io.BytesIO()
    img.save(buf, format="WEBP", lossless=True)
    return buf.getvalue()


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    out_dir = sys.argv[1]

    text = encode_text(FIELDS)
    webp = make_placeholder_webp()

    blob = bytearray()
    blob += struct.pack(">H", len(text))
    blob += text
    blob += struct.pack(">H", len(webp))
    blob += webp

    bin_path = f"{out_dir}/synthetic_decoded.bin"
    webp_path = f"{out_dir}/synthetic_photo.webp"
    with open(bin_path, "wb") as f:
        f.write(blob)
    with open(webp_path, "wb") as f:
        f.write(webp)

    print(f"fields      : {len(FIELDS)}")
    print(f"text_len    : {len(text)} bytes")
    print(f"img_len     : {len(webp)} bytes (WebP 96x129)")
    print(f"total       : {len(blob)} bytes")
    print(f"wrote       : {bin_path}")
    print(f"wrote       : {webp_path}")


if __name__ == "__main__":
    main()
