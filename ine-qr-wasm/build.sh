#!/bin/bash
# Build the INE QR pipeline as a WebAssembly module.
set -euo pipefail
cd "$(dirname "$0")"

EMCC="${EMCC:-emcc}"

SOURCES=(
  src/pipeline.c
  src/output_decode.c
  src/glue.c
  src/wasm_main.c
  vendor/aes256.c
  vendor/base64.c
  vendor/bignum.c
)

EXPORTS='["_decode_qr","_decode_decrypted","_get_json_ptr","_get_json_len","_get_webp_ptr","_get_webp_len","_alloc_buf","_free_buf","_malloc","_free"]'
RUNTIME_METHODS='["ccall","cwrap","HEAPU8","UTF8ToString"]'

"$EMCC" "${SOURCES[@]}" \
  -O3 \
  -s WASM=1 \
  -s MODULARIZE=1 \
  -s EXPORT_NAME=createIneQrModule \
  -s ENVIRONMENT=web,worker,node \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s INITIAL_MEMORY=8MB \
  -s STACK_SIZE=1MB \
  -s EXPORTED_FUNCTIONS="$EXPORTS" \
  -s EXPORTED_RUNTIME_METHODS="$RUNTIME_METHODS" \
  -o dist/ine_qr.js

echo
echo "── Build artifacts ────────────────────────"
ls -lh dist/ine_qr.js dist/ine_qr.wasm 2>/dev/null
