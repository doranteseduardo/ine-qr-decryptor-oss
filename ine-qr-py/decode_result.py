#!/usr/bin/env python3
"""
INE QR Final Decoder — Decodifica el resultado de pc()
=======================================================
Toma pc_return_decoded.bin (salida base64-decodificada de pc())
y extrae los datos biográficos y la foto.

Formato del resultado:
  [text_len:2 BE] [encoded_text:N] [img_len:2 BE] [WebP image]

Codificación de texto (alfabeto español con Ñ):
  1-14  = A-N
  15    = Ñ
  16-27 = O-Z
  28-37 = 0-9
  40    = /
  57    = | (separador de campos)
"""

import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR   = os.path.join(SCRIPT_DIR, "..")
OUTPUT_DIR = os.path.join(ROOT_DIR, "output")

# Character table: Spanish alphabet (A-Z with Ñ after N) + digits + specials
CHAR_TABLE = {}
letters = 'ABCDEFGHIJKLMNÑOPQRSTUVWXYZ'
for i, ch in enumerate(letters):
    CHAR_TABLE[i + 1] = ch
for d in range(10):
    CHAR_TABLE[28 + d] = str(d)
CHAR_TABLE[57] = '|'   # pipe separator
CHAR_TABLE[40] = '/'   # slash


def decode_text(encoded_bytes):
    """Decode encoded bytes using the INE character table."""
    result = []
    for b in encoded_bytes:
        if b in CHAR_TABLE:
            result.append(CHAR_TABLE[b])
        elif b == 0:
            pass  # skip nulls
        else:
            result.append(f'[0x{b:02x}]')
    return ''.join(result)


def main():
    input_path = os.path.join(OUTPUT_DIR, "pc_return_decoded.bin")
    if not os.path.exists(input_path):
        print("[!] pc_return_decoded.bin no encontrado. Ejecuta emulate_pc.py primero.")
        sys.exit(1)

    with open(input_path, "rb") as f:
        data = f.read()

    print(f"Total: {len(data)} bytes")

    # Parse structure
    text_len = (data[0] << 8) | data[1]
    text_data = data[2:2 + text_len]
    img_offset = 2 + text_len
    img_len = (data[img_offset] << 8) | data[img_offset + 1]
    img_data = data[img_offset + 2:img_offset + 2 + img_len]

    print(f"Texto: {text_len} bytes codificados")
    print(f"Imagen: {img_len} bytes (WebP)")

    # Decode text
    text = decode_text(text_data)
    fields = text.split('|')

    # Field labels (for tipo "N" = Nacional)
    labels = [
        "tipo", "cic", "ocr", "curp", "nombre", "apellido1", "apellido2",
        "entidad", "municipio", "seccion", "etnia", "vigencia", "sexo",
        "indiceHuella1", "indiceHuella2", "version", "fechaGeneracion",
        "firmaVerificadora"
    ]

    print(f"\n{'=' * 60}")
    print(f"  DATOS BIOGRÁFICOS ({len(fields)} campos)")
    print(f"{'=' * 60}")

    result = {}
    for i, val in enumerate(fields):
        label = labels[i] if i < len(labels) else f"campo_{i}"
        result[label] = val
        if len(val) > 60:
            print(f"  {label}: {val[:60]}...")
        else:
            print(f"  {label}: {val}")

    # Save JSON
    json_path = os.path.join(OUTPUT_DIR, "datos_biograficos.json")
    with open(json_path, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n  Guardado: {json_path}")

    # Save WebP
    webp_path = os.path.join(OUTPUT_DIR, "foto_ine.webp")
    with open(webp_path, "wb") as f:
        f.write(img_data)
    print(f"  Guardado: {webp_path}")

    # Save decoded text
    txt_path = os.path.join(OUTPUT_DIR, "texto_biografico.txt")
    with open(txt_path, "w") as f:
        f.write(text)
    print(f"  Guardado: {txt_path}")


if __name__ == "__main__":
    main()
