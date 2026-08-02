#!/usr/bin/env python3
"""
INE QR Decoder — End-to-End Pipeline
=====================================
Takes a credential photo, extracts QR codes, runs the full 7-layer
crypto pipeline via ARM64 emulation, and outputs biographical data + photo.

Usage:
    python3 ine_decode.py <imagen_credencial>

Output (in output/ directory):
    datos_biograficos.json  — All 18 biographical fields
    foto_ine.webp           — 96x129 credential photo
    texto_biografico.txt    — Raw pipe-delimited text

Requirements:
    pip install Pillow zxing-cpp unicorn capstone lief cryptography rich
    (optional) pip install pillow-heif   # for HEIC/HEIF photos

Options:
    --verbose, -v   Show internal details for each step
"""

import sys
import os
import subprocess
import base64
import json
import io
import contextlib
import time as time_module
from binascii import unhexlify
import xml.etree.ElementTree as ET

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR   = os.path.join(SCRIPT_DIR, "..")          # project root
SO_PATH    = os.path.join(ROOT_DIR, "libPersonalCode.so")

# ── Character table for decoding pc() output ──
# Spanish alphabet: A-Z with Ñ inserted after N (position 15)
CHAR_TABLE = {}
_letters = 'ABCDEFGHIJKLMNÑOPQRSTUVWXYZ'
for _i, _ch in enumerate(_letters):
    CHAR_TABLE[_i + 1] = _ch
for _d in range(10):
    CHAR_TABLE[28 + _d] = str(_d)
CHAR_TABLE[57] = '|'
CHAR_TABLE[40] = '/'

FIELD_LABELS = [
    "tipo", "cic", "ocr", "curp", "nombre", "apellido1", "apellido2",
    "entidad", "municipio", "seccion", "etnia", "vigencia", "sexo",
    "indiceHuella1", "indiceHuella2", "version", "fechaGeneracion",
    "firmaVerificadora"
]


def extract_qr_codes(image_path):
    """Extract QR codes from a credential image. Returns (left_bytes, right_bytes)."""
    try:
        from PIL import Image
    except ImportError:
        print("[!] pip install Pillow")
        sys.exit(1)

    try:
        import pillow_heif
        pillow_heif.register_heif_opener()
    except ImportError:
        pass  # HEIC support optional

    try:
        import zxingcpp
    except ImportError:
        print("[!] pip install zxing-cpp")
        sys.exit(1)

    img = Image.open(image_path)
    print(f"[*] Imagen: {img.size[0]}x{img.size[1]} ({img.mode})")

    results = zxingcpp.read_barcodes(img)
    print(f"[*] Códigos encontrados: {len(results)}")

    left = None
    right = None

    for r in results:
        raw = bytes(r.bytes)
        fmt = str(r.format)

        if len(raw) != 858:
            print(f"    {fmt}: {len(raw)} bytes (ignorado, no es QR INE)")
            continue

        if raw[0] != 0:
            print(f"    {fmt}: header=0x{raw[0]:02X} (ignorado, header inválido)")
            continue

        if raw[1] == 0:
            left = raw
            print(f"    QR izquierdo: {len(raw)} bytes")
        elif raw[1] == 1:
            right = raw
            print(f"    QR derecho: {len(raw)} bytes")
        else:
            print(f"    {fmt}: index={raw[1]} (ignorado, índice desconocido)")

    if not left or not right:
        missing = []
        if not left:
            missing.append("izquierdo")
        if not right:
            missing.append("derecho")
        print(f"[!] Faltan QR: {', '.join(missing)}")
        print("[!] Asegúrate de que la foto incluya ambos QR con buena resolución")
        sys.exit(1)

    return left, right


def run_static_pipeline(so_path, qr_left, qr_right):
    """Run layers 1-3 of the crypto pipeline (AES + RSA key derivation).
    Returns the RSA key #2 XML string needed by the emulator."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    AES_KEY_HEX = "0001029836537892876377726A4E78E77F987CC321180281AABB019654321000"
    AES_IV_HEX = "0192C58D36E47A589AF01928376428AA"
    AES_INPUT1_OFFSET = 0x1182cd
    AES_INPUT2_OFFSET = 0xd05ae

    so_data = open(so_path, "rb").read()

    # Read hex ciphertext from .rodata
    def read_cstr(data, offset):
        end = data.index(b'\x00', offset)
        return data[offset:end]

    aes_hex1 = read_cstr(so_data, AES_INPUT1_OFFSET).decode('ascii')
    aes_hex2 = read_cstr(so_data, AES_INPUT2_OFFSET).decode('ascii')

    # AES-CBC-256 decrypt
    def aes_decrypt(hex_input, key_hex, iv_hex):
        key = unhexlify(key_hex)
        iv = unhexlify(iv_hex)
        ct = unhexlify(hex_input)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        dec = cipher.decryptor()
        pt = dec.update(ct) + dec.finalize()
        pad = pt[-1]
        if 1 <= pad <= 16 and all(b == pad for b in pt[-pad:]):
            pt = pt[:-pad]
        return pt

    # Layer 1: AES → RSA key #1
    plain1 = aes_decrypt(aes_hex1, AES_KEY_HEX, AES_IV_HEX)
    xml_end = plain1.find(b'</RSAPublicKey>')
    rsa_key1_xml = plain1[:xml_end + len(b'</RSAPublicKey>')].decode('utf-8')

    # Layer 1: AES → base64 blob
    plain2 = aes_decrypt(aes_hex2, AES_KEY_HEX, AES_IV_HEX)
    b64_chars = set(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    end_pos = 0
    for i in range(len(plain2)):
        if plain2[i] in b64_chars:
            end_pos = i + 1
        else:
            break
    b64_blob = plain2[:end_pos].decode('ascii')

    # Parse RSA key #1
    root = ET.fromstring(rsa_key1_xml)
    n1 = int.from_bytes(base64.b64decode(root.find("Modulus").text), 'big')
    e1 = int.from_bytes(base64.b64decode(root.find("Exponent").text), 'big')
    ks1 = len(base64.b64decode(root.find("Modulus").text))

    print(f"[*] RSA key #1: {ks1 * 8}-bit")

    # Layer 2: RSA decrypt blob → RSA key #2
    ct = base64.b64decode(b64_blob)
    nblocks = len(ct) // ks1
    result = b""
    for i in range(nblocks):
        block = ct[i * ks1:(i + 1) * ks1]
        c_int = int.from_bytes(block, 'big')
        m_int = pow(c_int, e1, n1)
        raw = m_int.to_bytes(ks1, 'big')
        if raw[0] == 0x00 and raw[1] in (0x01, 0x02):
            for j in range(2, len(raw)):
                if raw[j] == 0x00:
                    result += raw[j + 1:]
                    break

    rsa_key2_xml = result.decode('utf-8', errors='replace').strip('\x00')
    if '</RSAPublicKey>' not in rsa_key2_xml:
        print("[!] Failed to derive RSA key #2")
        sys.exit(1)

    print(f"[*] RSA key #2: derived ({len(rsa_key2_xml)} chars)")
    return rsa_key2_xml


def decode_pc_result(decoded_bin):
    """Decode the binary output of pc() into fields and image."""
    text_len = (decoded_bin[0] << 8) | decoded_bin[1]
    text_data = decoded_bin[2:2 + text_len]
    img_offset = 2 + text_len
    img_len = (decoded_bin[img_offset] << 8) | decoded_bin[img_offset + 1]
    img_data = decoded_bin[img_offset + 2:img_offset + 2 + img_len]

    # Decode text using character table
    chars = []
    for b in text_data:
        if b in CHAR_TABLE:
            chars.append(CHAR_TABLE[b])
        elif b == 0:
            pass
        else:
            chars.append(f'[0x{b:02x}]')
    text = ''.join(chars)

    # Parse fields
    fields = text.split('|')
    result = {}
    for i, val in enumerate(fields):
        label = FIELD_LABELS[i] if i < len(FIELD_LABELS) else f"campo_{i}"
        result[label] = val

    return result, img_data, text


# ── Visual helpers ──

def _fmt_size(size_bytes):
    """Format file size for display."""
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes} B"


def _run_quiet(func):
    """Run a function with stdout suppressed. Returns (result, captured_output).
    Re-raises SystemExit after restoring stdout."""
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            result = func()
        return result, buf.getvalue()
    except SystemExit:
        # Print captured output so error messages are visible, then re-raise
        captured = buf.getvalue()
        if captured:
            sys.stderr.write(captured)
        raise


def main():
    if len(sys.argv) < 2:
        print("Uso: python3 ine_decode.py <imagen_credencial>")
        print("")
        print("Formatos: JPG, PNG, HEIC")
        print("La imagen debe incluir ambos códigos QR de la credencial INE.")
        sys.exit(1)

    image_path = sys.argv[1]
    if not os.path.exists(image_path):
        print(f"[!] Archivo no encontrado: {image_path}")
        sys.exit(1)

    output_dir = os.path.join(ROOT_DIR, "output")
    os.makedirs(output_dir, exist_ok=True)

    verbose = "--verbose" in sys.argv or "-v" in sys.argv

    if not HAS_RICH:
        _main_plain(image_path, output_dir, verbose)
        return

    console = Console()
    image_name = os.path.basename(image_path)
    step_times = []

    # ── Header ──
    console.print()
    console.print(Panel.fit(
        "[bold white]INE QR Decoder[/bold white]  [dim]Pipeline completo[/dim]",
        border_style="cyan",
    ))
    console.print(f"  [dim]Imagen[/dim]  {image_name}")
    console.print()

    # ── Step 1: Extract QR codes ──
    with console.status("  [cyan]\\[1/4][/] Extrayendo QR codes...", spinner="dots"):
        t0 = time_module.time()
        (qr_left, qr_right), log = _run_quiet(lambda: extract_qr_codes(image_path))
        step_times.append(time_module.time() - t0)

    console.print(f"  [green]\u2713[/] [bold]\\[1/4][/] Extrayendo QR codes [dim]{step_times[-1]:.1f}s[/]")
    if verbose and log.strip():
        for line in log.strip().splitlines():
            console.print(f"         [dim]{line}[/]")

    # Save QR data
    with open(os.path.join(output_dir, "qr_izquierdo.bin"), "wb") as f:
        f.write(qr_left)
    with open(os.path.join(output_dir, "qr_derecho.bin"), "wb") as f:
        f.write(qr_right)

    # ── Step 2: Static crypto pipeline ──
    with console.status("  [cyan]\\[2/4][/] AES + RSA keys 1-2...", spinner="dots"):
        t0 = time_module.time()
        rsa_key2_xml, log = _run_quiet(lambda: run_static_pipeline(SO_PATH, qr_left, qr_right))
        step_times.append(time_module.time() - t0)

    console.print(f"  [green]\u2713[/] [bold]\\[2/4][/] AES + RSA keys 1-2 [dim]{step_times[-1]:.1f}s[/]")
    if verbose and log.strip():
        for line in log.strip().splitlines():
            console.print(f"         [dim]{line}[/]")

    # Save RSA key #2
    with open(os.path.join(output_dir, "rsa_step1_full.txt"), "w") as f:
        f.write(rsa_key2_xml)

    # ── Step 3: ARM64 emulation ──
    with console.status("  [cyan]\\[3/4][/] Emulación ARM64 (capas 4-7)...", spinner="dots"):
        t0 = time_module.time()
        emu_script = os.path.join(SCRIPT_DIR, "emulate_pc.py")
        emu_result = subprocess.run(
            [sys.executable, emu_script],
            capture_output=True, text=True, cwd=ROOT_DIR,
            timeout=180
        )
        step_times.append(time_module.time() - t0)

    if emu_result.returncode != 0:
        console.print(f"  [red]\u2717[/] [bold]\\[3/4][/] Emulación ARM64 [red]ERROR[/]")
        console.print(f"\n[red]{emu_result.stderr[-500:] if emu_result.stderr else 'sin stderr'}[/]")
        sys.exit(1)

    decoded_path = os.path.join(output_dir, "pc_return_decoded.bin")
    if not os.path.exists(decoded_path):
        console.print(f"  [red]\u2717[/] [bold]\\[3/4][/] Emulación ARM64 [red]sin resultado[/]")
        for line in emu_result.stdout.split('\n'):
            if 'ERROR' in line or 'RETURN' in line:
                console.print(f"         [dim]{line.strip()}[/]")
        sys.exit(1)

    console.print(f"  [green]\u2713[/] [bold]\\[3/4][/] Emulación ARM64 (capas 4-7) [dim]{step_times[-1]:.1f}s[/]")
    if verbose:
        for line in emu_result.stdout.split('\n'):
            if any(k in line for k in ['[CRYPTO]', '[REDIRECT]', '[RETURN]', 'completada en']):
                console.print(f"         [dim]{line.strip()}[/]")

    # ── Step 4: Decode result ──
    t0 = time_module.time()
    with open(decoded_path, "rb") as f:
        decoded_bin = f.read()

    fields, img_data, raw_text = decode_pc_result(decoded_bin)

    # Save outputs
    json_path = os.path.join(output_dir, "datos_biograficos.json")
    with open(json_path, "w") as f:
        json.dump(fields, f, indent=2, ensure_ascii=False)

    webp_path = os.path.join(output_dir, "foto_ine.webp")
    with open(webp_path, "wb") as f:
        f.write(img_data)

    txt_path = os.path.join(output_dir, "texto_biografico.txt")
    with open(txt_path, "w") as f:
        f.write(raw_text)

    step_times.append(time_module.time() - t0)
    console.print(f"  [green]\u2713[/] [bold]\\[4/4][/] Decodificando resultado [dim]{step_times[-1]:.1f}s[/]")

    total = sum(step_times)
    console.print(f"\n  [dim]Completado en {total:.1f}s[/]")

    # ── Results table ──
    console.print()
    table = Table(
        title=f"Datos Biográficos ({len(fields)} campos)",
        border_style="cyan",
        title_style="bold",
        show_lines=False,
    )
    table.add_column("Campo", style="cyan", min_width=18)
    table.add_column("Valor")

    for label, val in fields.items():
        display = val if len(val) <= 55 else val[:52] + "..."
        table.add_row(label, Text(display))

    console.print(table)

    # ── Photo info ──
    console.print(f"\n  [dim]Foto:[/] {_fmt_size(len(img_data))} (WebP)")

    # ── Generated files table ──
    console.print()
    ftable = Table(
        title="Archivos generados",
        border_style="green",
        title_style="bold",
        show_lines=False,
    )
    ftable.add_column("Archivo", style="green")
    ftable.add_column("Tamaño", justify="right", style="dim")

    for path in [json_path, webp_path, txt_path]:
        rel = os.path.relpath(path, SCRIPT_DIR)
        ftable.add_row(rel, _fmt_size(os.path.getsize(path)))

    console.print(ftable)
    console.print()


def _main_plain(image_path, output_dir, verbose=False):
    """Fallback plain-text output when rich is not installed."""
    print("=" * 60)
    print("  INE QR Decoder — Pipeline completo")
    print("=" * 60)

    # Step 1
    print(f"\n[Paso 1] Extrayendo QR codes de la imagen...")
    qr_left, qr_right = extract_qr_codes(image_path)

    with open(os.path.join(output_dir, "qr_izquierdo.bin"), "wb") as f:
        f.write(qr_left)
    with open(os.path.join(output_dir, "qr_derecho.bin"), "wb") as f:
        f.write(qr_right)

    # Step 2
    print(f"\n[Paso 2] Pipeline estático (AES + RSA keys 1-2)...")
    rsa_key2_xml = run_static_pipeline(SO_PATH, qr_left, qr_right)

    with open(os.path.join(output_dir, "rsa_step1_full.txt"), "w") as f:
        f.write(rsa_key2_xml)

    # Step 3
    print(f"\n[Paso 3] Emulación ARM64 (capas 4-7)...")
    emu_script = os.path.join(SCRIPT_DIR, "emulate_pc.py")
    result = subprocess.run(
        [sys.executable, emu_script],
        capture_output=True, text=True, cwd=ROOT_DIR,
        timeout=180
    )

    if result.returncode != 0:
        print(f"[!] Error en emulador:")
        print(result.stderr[-500:] if result.stderr else "sin stderr")
        sys.exit(1)

    decoded_path = os.path.join(output_dir, "pc_return_decoded.bin")
    if not os.path.exists(decoded_path):
        print("[!] El emulador no produjo pc_return_decoded.bin")
        for line in result.stdout.split('\n'):
            if '[CRYPTO]' in line or 'ERROR' in line or 'RETURN' in line:
                print(f"    {line}")
        sys.exit(1)

    if verbose:
        for line in result.stdout.split('\n'):
            if any(k in line for k in ['[CRYPTO]', '[REDIRECT]', '[RETURN]', 'completada en']):
                print(f"    {line.strip()}")

    # Step 4
    print(f"\n[Paso 4] Decodificando resultado...")
    with open(decoded_path, "rb") as f:
        decoded_bin = f.read()

    fields, img_data, raw_text = decode_pc_result(decoded_bin)

    json_path = os.path.join(output_dir, "datos_biograficos.json")
    with open(json_path, "w") as f:
        json.dump(fields, f, indent=2, ensure_ascii=False)

    webp_path = os.path.join(output_dir, "foto_ine.webp")
    with open(webp_path, "wb") as f:
        f.write(img_data)

    txt_path = os.path.join(output_dir, "texto_biografico.txt")
    with open(txt_path, "w") as f:
        f.write(raw_text)

    print(f"\n{'=' * 60}")
    print(f"  DATOS BIOGRÁFICOS ({len(fields)} campos)")
    print(f"{'=' * 60}")
    for label, val in fields.items():
        if len(val) > 60:
            print(f"  {label}: {val[:60]}...")
        else:
            print(f"  {label}: {val}")

    print(f"\n  Foto: {len(img_data)} bytes (WebP)")
    print(f"\n{'=' * 60}")
    print(f"  ARCHIVOS GENERADOS")
    print(f"{'=' * 60}")
    for path in [json_path, webp_path, txt_path]:
        rel = os.path.relpath(path, SCRIPT_DIR)
        print(f"  {rel}  ({_fmt_size(os.path.getsize(path))})")


if __name__ == "__main__":
    main()
