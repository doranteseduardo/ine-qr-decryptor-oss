#!/usr/bin/env python3
"""
INE QR Decryptor — Static Crypto Pipeline (Layers 1-3)
=======================================================
Standalone Python implementation of the first 3 layers of the INE QR
crypto pipeline. Does NOT require Unicorn Engine.

1. AES-CBC-256 decrypt of .rodata constants → RSA key #1 XML
2. RSA public-key decrypt with key #1 → RSA key #2 XML
3. RSA DecryptBd of buf2 (1024 bytes from QR) → 970 bytes intermediate

Note: This only covers layers 1-3. The remaining layers (4-7) require
SIMD/NEON key derivation that only runs in the full emulator (emulate_pc.py).

Requirements: pip install cryptography
"""

import os
import base64
import json
from binascii import unhexlify
import xml.etree.ElementTree as ET
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR   = os.path.join(SCRIPT_DIR, "..")
OUTPUT_DIR = os.path.join(ROOT_DIR, "output")
SO_PATH = os.path.join(ROOT_DIR, "libPersonalCode.so")
QR_LEFT = os.path.join(OUTPUT_DIR, "qr_izquierdo.bin")
QR_RIGHT = os.path.join(OUTPUT_DIR, "qr_derecho.bin")

# AES parameters from emulation trace
AES_KEY_HEX = "0001029836537892876377726A4E78E77F987CC321180281AABB019654321000"
AES_IV_HEX = "0192C58D36E47A589AF01928376428AA"

# .rodata offsets for AES hex ciphertext
AES_INPUT1_OFFSET = 0x1182cd  # RSA key #1 XML (encrypted)
AES_INPUT2_OFFSET = 0xd05ae   # Data for RSA decrypt (encrypted)


def read_cstr(data, offset):
    """Read null-terminated C string from binary data."""
    end = data.index(b'\x00', offset)
    return data[offset:end]


def aes_cbc_decrypt(ciphertext_hex, key_hex, iv_hex):
    """AES-CBC-256 decrypt. Input: hex-encoded ciphertext."""
    key = unhexlify(key_hex)
    iv = unhexlify(iv_hex)
    ciphertext = unhexlify(ciphertext_hex)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


def parse_rsa_xml_key(xml_str):
    """Parse RSA public key from Chilkat XML format."""
    root = ET.fromstring(xml_str)
    mod_b64 = root.find("Modulus").text
    exp_b64 = root.find("Exponent").text

    n_bytes = base64.b64decode(mod_b64)
    n = int.from_bytes(n_bytes, 'big')
    e = int.from_bytes(base64.b64decode(exp_b64), 'big')

    print(f"  Modulus: {n.bit_length()} bits ({len(n_bytes)} bytes)")
    print(f"  Exponent: {e}")
    return n, e, len(n_bytes)


def rsa_raw(data_bytes, n, e, key_size):
    """Raw RSA: m = c^e mod n"""
    c = int.from_bytes(data_bytes, 'big')
    m = pow(c, e, n)
    return m.to_bytes(key_size, 'big')


def strip_pkcs1(data):
    """Strip PKCS#1 v1.5 padding. Returns None if invalid."""
    if len(data) < 11 or data[0] != 0x00 or data[1] not in (0x01, 0x02):
        return None
    for i in range(2, len(data)):
        if data[i] == 0x00:
            if i < 10:
                return None  # Too short
            return data[i + 1:]
    return None


def rsa_decrypt_multiblock(ciphertext, n, e, key_size):
    """RSA decrypt multiple blocks (each key_size bytes)."""
    if len(ciphertext) % key_size != 0:
        print(f"  [!] {len(ciphertext)} bytes no es multiplo de {key_size}")
        return None

    nblocks = len(ciphertext) // key_size
    print(f"  {nblocks} bloque(s) de {key_size} bytes")

    result = b""
    for i in range(nblocks):
        block = ciphertext[i * key_size:(i + 1) * key_size]
        raw = rsa_raw(block, n, e, key_size)
        plain = strip_pkcs1(raw)
        if plain:
            print(f"  Bloque {i+1}: PKCS#1 tipo {raw[1]}, {len(plain)} bytes de datos")
            result += plain
        else:
            print(f"  Bloque {i+1}: sin padding PKCS#1. Raw[0:8]: {raw[:8].hex()}")
            return None

    return result


def main():
    print("=" * 70)
    print("  INE QR Decoder — Pipeline completo desde .rodata + QR")
    print("=" * 70)

    # Load .so binary
    so_data = open(SO_PATH, "rb").read()

    # Load QR data
    with open(QR_LEFT, "rb") as f:
        qr_left = f.read()
    with open(QR_RIGHT, "rb") as f:
        qr_right = f.read()

    combined = qr_left[2:] + qr_right[2:]
    buf1_raw = combined[:688]
    buf2_raw = combined[688:]
    print(f"[*] QR raw: buf1={len(buf1_raw)}B, buf2={len(buf2_raw)}B")

    buf2 = buf2_raw

    # ===== STEP 1: Read AES inputs from .rodata =====
    print(f"\n[*] Paso 1: Leer AES ciphertext de .rodata...")
    aes_hex1 = read_cstr(so_data, AES_INPUT1_OFFSET).decode('ascii')
    aes_hex2 = read_cstr(so_data, AES_INPUT2_OFFSET).decode('ascii')
    print(f"  Input #1: {len(aes_hex1)} hex chars = {len(aes_hex1)//2} bytes")
    print(f"  Input #2: {len(aes_hex2)} hex chars = {len(aes_hex2)//2} bytes")

    # ===== STEP 2: AES-CBC-256 decrypt =====
    print(f"\n[*] Paso 2: AES-CBC-256 decrypt...")

    plain1 = aes_cbc_decrypt(aes_hex1, AES_KEY_HEX, AES_IV_HEX)
    print(f"  Output #1: {len(plain1)} bytes")
    # Find the end of the XML (</RSAPublicKey>)
    xml_end_marker = b'</RSAPublicKey>'
    xml_end = plain1.find(xml_end_marker)
    if xml_end >= 0:
        plain1_str = plain1[:xml_end + len(xml_end_marker)].decode('utf-8')
    else:
        plain1_str = plain1.rstrip(b'\x00').decode('utf-8', errors='replace')
    print(f"  Texto #1: {len(plain1_str)} chars")
    print(f"    Inicio: {plain1_str[:100]}")

    plain2 = aes_cbc_decrypt(aes_hex2, AES_KEY_HEX, AES_IV_HEX)
    print(f"\n  Output #2: {len(plain2)} bytes")
    # The base64 string ends with '=' padding — find the end
    # Look for the last valid base64 character
    # Base64 chars: A-Za-z0-9+/=
    b64_chars = set(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    end_pos = 0
    for i in range(len(plain2)):
        if plain2[i] in b64_chars:
            end_pos = i + 1
        else:
            break
    plain2_str = plain2[:end_pos].decode('ascii')
    print(f"  Base64 texto: {len(plain2_str)} chars")
    print(f"    Inicio: {plain2_str[:80]}")
    print(f"    Final:  ...{plain2_str[-40:]}")

    # ===== STEP 3: Parse RSA key #1 =====
    print(f"\n[*] Paso 3: RSA key #1 desde AES output #1...")
    if '<RSAPublicKey>' in plain1_str:
        n1, e1, ks1 = parse_rsa_xml_key(plain1_str)
    else:
        print(f"  [!] No es RSA XML!")
        return

    # ===== STEP 4: RSA public-key decrypt =====
    print(f"\n[*] Paso 4: RSA decrypt con public key #1...")

    # Decode the base64 data
    ct_b64 = base64.b64decode(plain2_str)
    print(f"  Base64 decode: {len(ct_b64)} bytes")
    print(f"  Key size: {ks1} bytes")
    print(f"  Bloques: {len(ct_b64) / ks1:.2f}")

    result = rsa_decrypt_multiblock(ct_b64, n1, e1, ks1)

    if result is None:
        print(f"\n  Multi-bloque fallo. Intentando bloque unico con primeros {ks1} bytes...")
        raw = rsa_raw(ct_b64[:ks1], n1, e1, ks1)
        p = strip_pkcs1(raw)
        if p:
            print(f"  Primer bloque: PKCS#1 tipo {raw[1]}, {len(p)} bytes")
            result_partial = p
            try:
                txt = result_partial.decode('utf-8')
                print(f"  Texto: {txt[:200]}")

                # Check if there's a second block
                if len(ct_b64) > ks1:
                    remaining = ct_b64[ks1:]
                    print(f"\n  Bytes restantes: {len(remaining)}")
                    # Try as a separate RSA block (padded to key_size)
                    if len(remaining) < ks1:
                        # Zero-pad
                        padded = b'\x00' * (ks1 - len(remaining)) + remaining
                        raw2 = rsa_raw(padded, n1, e1, ks1)
                        p2 = strip_pkcs1(raw2)
                        if p2:
                            print(f"  Segundo bloque (padded): {len(p2)} bytes")
                            print(f"  Texto: {p2.decode('utf-8', errors='replace')[:200]}")
                            result = result_partial + p2
                        else:
                            print(f"  Segundo bloque sin padding valido: {raw2[:8].hex()}")
            except:
                pass

    if result:
        result_str = result.decode('utf-8', errors='replace').strip('\x00')
        print(f"\n  RSA result total: {len(result_str)} chars")

        with open(os.path.join(OUTPUT_DIR, "rsa_step1_full.txt"), "w") as f:
            f.write(result_str)
        print(f"  Guardado: rsa_step1_full.txt")

        if '</RSAPublicKey>' in result_str:
            print(f"\n*** RSA key #2 COMPLETA! ***")

            # Parse RSA key #2
            print(f"\n[*] Paso 5: RSA key #2...")
            n2, e2, ks2 = parse_rsa_xml_key(result_str)

            # Decrypt buf2
            print(f"\n[*] Paso 6: RSA decrypt buf2 ({len(buf2)} bytes) con key #2...")
            buf2_result = rsa_decrypt_multiblock(buf2, n2, e2, ks2)

            if buf2_result:
                buf2_text = buf2_result.decode('utf-8', errors='replace').strip('\x00')
                print(f"\n  Resultado: {len(buf2_text)} chars")
                print(f"  Texto: {buf2_text[:300]}")

                if '|' in buf2_text:
                    parse_biographical(buf2_text)
                else:
                    with open(os.path.join(OUTPUT_DIR, "buf2_decrypted.bin"), "wb") as f:
                        f.write(buf2_result)
                    print(f"  Guardado: buf2_decrypted.bin")
        else:
            print(f"\n  XML incompleto. Contenido:")
            print(f"  {result_str[:500]}")
            print(f"  ...{result_str[-200:]}")
    else:
        print(f"\n  [!] RSA decrypt fallo completamente")


def parse_biographical(text):
    text = text.strip().strip('\x00')
    fields = text.split('|')
    names = [
        "tipo", "cic", "ocr", "curp", "nombre", "apellido1", "apellido2",
        "entidad", "municipio", "seccion", "etnia", "vigencia", "sexo",
        "indiceHuella1", "indiceHuella2", "version", "fechaGeneracion",
        "firmaVerificadora"
    ]

    print(f"\n{'='*70}")
    print(f"  DATOS BIOGRAFICOS ({len(fields)} campos)")
    print(f"{'='*70}")

    result = {}
    for i, val in enumerate(fields):
        name = names[i] if i < len(names) else f"campo_{i}"
        result[name] = val
        if name == "firmaVerificadora":
            print(f"  {name}: {val[:60]}...")
        else:
            print(f"  {name}: {val}")

    with open(os.path.join(OUTPUT_DIR, "datos_biograficos.json"), "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n  Guardado: datos_biograficos.json")


if __name__ == "__main__":
    main()
