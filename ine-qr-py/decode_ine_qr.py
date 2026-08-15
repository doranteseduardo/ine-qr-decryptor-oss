#!/usr/bin/env python3
"""
INE QR Code Decoder & Analyzer
===============================
Decodifica los códigos QR de una credencial INE (Instituto Nacional Electoral de México)
y analiza su estructura interna basándose en la ingeniería inversa de la app mx.ine.rfe.lectorqr.

Hallazgos clave del análisis:
- La app usa PersonalCode-INE-v5.0.11 SDK
- Cada credencial tiene 2 QR codes (izquierdo=index 0, derecho=index 1)
- Cada QR tiene exactamente 858 bytes raw
- Byte[0] = 0x00 (header), Byte[1] = index del QR (0 o 1)
- La verificación usa ECDSA con curvas P-256, P-384 y P-521
- Las claves públicas están embebidas en libPersonalCode.so (Chilkat crypto)

Uso:
    python3 decode_ine_qr.py <imagen_ine>
"""

import sys
import os
import json
import struct
import hashlib
import base64
from datetime import datetime

# --- Dependencias ---
try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    print("[!] Pillow no instalado: pip3 install Pillow")

try:
    import pillow_heif
    pillow_heif.register_heif_opener()
    HAS_HEIF = True
except ImportError:
    HAS_HEIF = False

try:
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509 import load_der_x509_certificate
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("[!] cryptography no instalado: pip3 install cryptography")


# ============================================================================
# Claves públicas ECC extraídas de libPersonalCode.so
# ============================================================================

INE_PUBLIC_KEYS = {
    "P-256 (secp256r1)": (
        "MIIBSzCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAA"
        "AAAAAAAAAAAA////////////////MFsEIP////8AAAABAAAAAAAAAAAAAAAA//////"
        "/////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVAMSdNgiG"
        "5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwp"
        "ZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA//////"
        "////+85vqtpxeehPO5ysL8YyVRAgEBA0IABO4pC2SpHu+l9Iw6jvOyZKv10Fxb72Hy"
        "VAKy4JBpR7nLRHQUEBFnKHdSY20ZnYfY8u4UU815AtAHc+a4vsa8Ch0="
    ),
    "P-384 (secp384r1)": (
        "MIIBzDCCAWQGByqGSM49AgEwggFXAgEBMDwGByqGSM49AQECMQD/////////////////"
        "////////////////////////v////8AAAAAAAAAAP////8wewQw//////////////////"
        "//////////////////////7/////AAAAAAAAAAD////8BDCzMS+n4j7n5JiOBWvj+C0ZGB"
        "2cbv6BQRIDFAiPUBOHWsZWOY2KLtGdKoXI7dPsKu8DFQCjNZJqoxmieh0AiWpnc6SCe"
        "s2scwRhBKqHyiK+iwU3jrHHHvMgrXRuHTtii6ebmFn3QeCCVCo4VQLyXb9VKWw6VF44c"
        "nYKtzYX3kqWJixvXZ6Yv5KS3Cn49B29KJoUfOnaMRO18LjACmCxzh1+gZ16Qx18kOoOX"
        "wIxAP///////////////////////////////8djTYH0Ny3fWBoNskiwp3rs7BlqzMUpcwIB"
        "AQNiAASIyX8AwFlZUSbu+10LsCq23LS6bT0+6yZv2BJ+iDPAD+Fxt7PN9+0JiWRZWFaP"
        "uP/SO7IColKtmxsh2JVLFpqo4nwS364XnuX3YkDfLEjY9VVorcQHfcHZ+3aV086g3F4="
    ),
    "P-521 (secp521r1)": (
        "MIICXDCCAc8GByqGSM49AgEwggHCAgEBME0GByqGSM49AQECQgH/////////////////"
        "////////////////////////////////////////////////////////////////////////"
        "/zCBngRCAf///////////////////////////////////////////////////////////////////"
        "//////////////8EQVGVPrlhjhyaH5KaIaC2hUDuotpyW5mzFfO4tImRjvEJ4VYZOVHsfpN7"
        "FlLAvTuxvwc1c9+IPSw08e9FH9RrUD8AAxUA0J6IACkcuFOWzGcXOTKEqqDaZLoEgYUEAM"
        "aFjga3BATpzZ4+y2YjlbRCnGSBOQU/tSH4KK9ga009uqFLXnfv51ko/h3BJ6L/qN4zSLP"
        "BhWpCm/l+fjHC5b1mARg5KWp4mjvABFyKX7QsfRvZmPVESVebRGgXr70XJz5mLJfucple"
        "9CZAxVC5AT+tB2E1PHCGonLCQIi+lHaf0WZQAkIB//////////////////////////////////"
        "/////////+lGGh4O/L5Zrf8wBSPcJpdA7tcm4iZxHrrtvtx6ROGQJAgEBA4GGAAQBlihTKdw5"
        "5JJvaHd22xM8yBIFlxqkWTYxPlIP5j7kxV4FEPYJiVqCbiui4XqFJV5eKdH6JXEIyl/1gG"
        "s+wt2ArpEBo+4PAGsv2ykwy0lxp/e2x0iTeMgIuryM9cgMqntJnZC/g79B7DzpahC8HVYm"
        "qmlm+mTT9XTjFWkd6eCGIRgdJo8="
    ),
}


# ============================================================================
# Estructura del QR del INE (basado en ingeniería inversa de Dqf.kt y Azf.kt)
# ============================================================================

def analyze_qr_structure(raw_bytes, qr_label="QR"):
    """Analiza la estructura interna de un QR del INE."""
    info = {
        "label": qr_label,
        "raw_size": len(raw_bytes),
        "expected_size": 858,
        "size_match": len(raw_bytes) == 858,
    }

    if len(raw_bytes) < 3:
        info["error"] = "QR demasiado pequeño"
        return info

    # Basado en Dqf.decode$lambda$5:
    #   rawBytes.length == 858 && rawBytes[0] == 0 && (rawBytes[1] == 0 || rawBytes[1] == 1)
    info["header_byte"] = raw_bytes[0]
    info["qr_index"] = raw_bytes[1]  # 0=izquierdo, 1=derecho
    info["is_valid_header"] = raw_bytes[0] == 0
    info["is_valid_index"] = raw_bytes[1] in (0, 1)
    info["qr_side"] = "IZQUIERDO" if raw_bytes[1] == 0 else "DERECHO" if raw_bytes[1] == 1 else f"DESCONOCIDO ({raw_bytes[1]})"

    # Basado en Azf.acc() con type=-1:
    #   length = ((data[1] & 0xFF) << 4) | ((data[2] & 0xFF) >> 4)
    #   Luego desempaqueta nibbles a partir del byte 3
    extracted_length = ((raw_bytes[1] & 0xFF) << 4) | ((raw_bytes[2] & 0xFF) >> 4)
    info["extracted_payload_length"] = extracted_length

    # Extraer payload usando el algoritmo de Azf.acc() type=-1
    if len(raw_bytes) > 3:
        payload = bytearray(len(raw_bytes) - 3)
        for i in range(3, len(raw_bytes)):
            payload[i - 3] = ((raw_bytes[i - 1] & 0x0F) << 4) | ((raw_bytes[i] & 0xF0) >> 4)
        info["payload_size"] = len(payload)
        info["payload_trimmed_size"] = min(extracted_length, len(payload))

        # Mostrar primeros bytes del payload
        trimmed = bytes(payload[:min(extracted_length, len(payload))])
        info["payload_hex_preview"] = trimmed[:64].hex()
        info["payload_sha256"] = hashlib.sha256(trimmed).hexdigest()

    # Análisis de entropía por secciones
    info["raw_hex_first_16"] = raw_bytes[:16].hex()
    info["raw_hex_last_16"] = raw_bytes[-16:].hex()
    info["raw_sha256"] = hashlib.sha256(raw_bytes).hexdigest()

    # Buscar posible firma ECDSA al final
    # Las firmas ECDSA típicamente están en formato DER: 0x30 <len> 0x02 <len> <r> 0x02 <len> <s>
    for offset in range(len(raw_bytes) - 80, len(raw_bytes) - 40):
        if offset >= 0 and raw_bytes[offset] == 0x30:
            try:
                sig_len = raw_bytes[offset + 1]
                if 60 <= sig_len <= 140 and raw_bytes[offset + 2] == 0x02:
                    info["possible_ecdsa_signature_offset"] = offset
                    info["possible_signature_hex"] = raw_bytes[offset:offset + sig_len + 2].hex()
                    break
            except IndexError:
                pass

    return info


def print_qr_analysis(info):
    """Imprime el análisis de un QR de forma legible."""
    print(f"\n{'='*70}")
    print(f"  {info['label']}")
    print(f"{'='*70}")
    print(f"  Tamaño raw:              {info['raw_size']} bytes (esperado: {info['expected_size']})")
    print(f"  Tamaño correcto:         {'SI' if info['size_match'] else 'NO'}")
    print(f"  Header byte [0]:         0x{info['header_byte']:02X} ({'valido' if info['is_valid_header'] else 'INVALIDO'})")
    print(f"  Index byte [1]:          0x{info['qr_index']:02X} -> {info['qr_side']}")
    print(f"  Payload length (calc):   {info.get('extracted_payload_length', 'N/A')} bytes")
    print(f"  Payload size (actual):   {info.get('payload_trimmed_size', 'N/A')} bytes")
    print(f"  SHA-256 (raw):           {info.get('raw_sha256', 'N/A')}")
    print(f"  SHA-256 (payload):       {info.get('payload_sha256', 'N/A')}")
    print(f"  Raw hex [0:16]:          {info.get('raw_hex_first_16', 'N/A')}")
    print(f"  Raw hex [-16:]:          {info.get('raw_hex_last_16', 'N/A')}")
    print(f"  Payload hex [0:64]:      {info.get('payload_hex_preview', 'N/A')}")

    if "possible_ecdsa_signature_offset" in info:
        print(f"  Posible firma ECDSA en:  offset {info['possible_ecdsa_signature_offset']}")
        sig_hex = info.get("possible_signature_hex", "")
        print(f"  Firma hex:               {sig_hex[:80]}...")


def decode_qr_from_image(image_path):
    """Decodifica QR codes de una imagen de credencial INE usando zxing-cpp."""
    print(f"\n[*] Cargando imagen: {image_path}")

    if not HAS_PIL:
        print("[ERROR] Se requiere Pillow: pip3 install Pillow")
        return []

    try:
        import zxingcpp
    except ImportError:
        print("[ERROR] Se requiere zxing-cpp: pip3 install zxing-cpp")
        return []

    img = Image.open(image_path)
    print(f"[*] Tamaño: {img.size}, Modo: {img.mode}")

    print("[*] Decodificando con zxing-cpp...")
    results = zxingcpp.read_barcodes(img)

    decoded_qrs = []
    for i, r in enumerate(results):
        raw = bytes(r.bytes)
        content = str(r.content_type)
        fmt = str(r.format)
        print(f"[+] #{i}: formato={fmt}, tipo={content}, {len(raw)} bytes")

        decoded_qrs.append({
            "index": i,
            "type": fmt,
            "content_type": content,
            "raw_bytes": raw,
            "text": r.text if len(raw) < 200 else None,
            "method": "zxing-cpp",
        })

    print(f"[*] Total códigos encontrados: {len(decoded_qrs)}")
    return decoded_qrs


def print_keys_info():
    """Imprime información sobre las claves públicas embebidas."""
    print(f"\n{'='*70}")
    print("  CLAVES PUBLICAS ECC DEL INE (extraidas de libPersonalCode.so)")
    print(f"{'='*70}")

    for name, b64_key in INE_PUBLIC_KEYS.items():
        der_bytes = base64.b64decode(b64_key)
        print(f"\n  Curva: {name}")
        print(f"  Tamaño DER: {len(der_bytes)} bytes")
        print(f"  SHA-256: {hashlib.sha256(der_bytes).hexdigest()}")
        print(f"  Base64 (primeros 80 chars): {b64_key[:80]}...")

        if HAS_CRYPTO:
            try:
                pubkey = serialization.load_der_public_key(der_bytes)
                if hasattr(pubkey, 'key_size'):
                    print(f"  Key size: {pubkey.key_size} bits")
                if hasattr(pubkey, 'curve'):
                    print(f"  Curva: {pubkey.curve.name}")
            except Exception as e:
                print(f"  [!] No se pudo parsear como SubjectPublicKeyInfo: {e}")
                print(f"      (La clave usa formato EC explicit parameters, no named curve)")


def export_results(qr_analyses, output_dir):
    """Exporta los resultados a archivos."""
    os.makedirs(output_dir, exist_ok=True)

    # Exportar datos raw de cada QR
    for analysis in qr_analyses:
        if "raw_bytes" in analysis:
            raw_path = os.path.join(output_dir, f"qr_{analysis.get('qr_side', 'unknown').lower()}_raw.bin")
            with open(raw_path, "wb") as f:
                f.write(analysis["raw_bytes"])
            print(f"[*] Raw bytes guardados en: {raw_path}")

    # Exportar JSON con análisis completo
    json_path = os.path.join(output_dir, "analysis.json")
    serializable = []
    for a in qr_analyses:
        sa = {k: v for k, v in a.items() if k != "raw_bytes"}
        if "raw_bytes" in a:
            sa["raw_bytes_b64"] = base64.b64encode(a["raw_bytes"]).decode()
        serializable.append(sa)

    with open(json_path, "w") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "tool": "INE QR Decoder v1.0",
            "source": "Ingenieria inversa de mx.ine.rfe.lectorqr (PersonalCode-INE-v5.0.11)",
            "qr_analyses": serializable,
            "public_keys": {name: key for name, key in INE_PUBLIC_KEYS.items()},
        }, f, indent=2, ensure_ascii=False)
    print(f"[*] Análisis JSON guardado en: {json_path}")


# ============================================================================
# Main
# ============================================================================

def main():
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║          INE QR Code Decoder & Analyzer v1.0                       ║
║  Basado en ingeniería inversa de mx.ine.rfe.lectorqr               ║
║  PersonalCode-INE-v5.0.11 SDK + Chilkat + DexGuard                ║
╚══════════════════════════════════════════════════════════════════════╝
    """)

    image_path = sys.argv[1] if len(sys.argv) > 1 else None

    # Siempre mostrar info de claves
    print_keys_info()

    if not image_path:
        print("\n[!] Uso: python3 decode_ine_qr.py <imagen_credencial_ine>")
        print("[!] Formatos soportados: PNG, JPG, HEIC")
        print("\n[*] Ejecutando solo análisis de claves (sin imagen).")
        return

    if not os.path.exists(image_path):
        print(f"\n[ERROR] Archivo no encontrado: {image_path}")
        return

    # Decodificar QR codes
    qr_results = decode_qr_from_image(image_path)

    if not qr_results:
        print("\n[!] No se pudieron decodificar los QR codes de la imagen.")
        print("[!] Posibles causas:")
        print("    - La imagen no tiene suficiente resolución")
        print("    - Los QR están parcialmente tapados/borrosos")
        print("    - Los QR del INE usan modo binario que pyzbar puede no soportar completamente")
        print("    - Intentar con una foto de mejor calidad/resolución")
        return

    # Analizar cada QR
    analyses = []
    for qr in qr_results:
        raw = qr["raw_bytes"]
        analysis = analyze_qr_structure(raw, f"QR #{qr['index']} ({qr['type']})")
        analysis["raw_bytes"] = raw
        analyses.append(analysis)
        print_qr_analysis(analysis)

    # Exportar resultados
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(script_dir, "output")
    export_results(analyses, out_dir)

    # Resumen
    print(f"\n{'='*70}")
    print("  RESUMEN")
    print(f"{'='*70}")
    print(f"  QR codes encontrados: {len(analyses)}")
    for a in analyses:
        side = a.get("qr_side", "?")
        valid = "VALIDO" if a.get("is_valid_header") and a.get("is_valid_index") else "INVALIDO"
        print(f"    - {side}: {a['raw_size']} bytes [{valid}]")

    print(f"\n  La verificación completa ECDSA requiere la librería nativa libPersonalCode.so")
    print(f"  Las claves públicas ECC están arriba. La firma está dentro del payload.")
    print(f"  El algoritmo exacto de verificación está en código nativo (Chilkat CkEcc).")


if __name__ == "__main__":
    main()
