/* WASM entry: takes 1712 bytes of combined QR payload, runs the pipeline,
 * and exposes JSON + WebP buffers via simple getter functions. */
#include "../include/wasm_pipeline.h"
#include <emscripten.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static char    *g_json     = NULL;
static size_t   g_json_len = 0;
static uint8_t *g_webp     = NULL;
static size_t   g_webp_len = 0;

EMSCRIPTEN_KEEPALIVE
int decode_qr(const uint8_t *combined, int combined_len) {
    if (g_json) { free(g_json); g_json = NULL; g_json_len = 0; }
    if (g_webp) { free(g_webp); g_webp = NULL; g_webp_len = 0; }

    uint8_t *raw = NULL;
    size_t   raw_len = 0;
    if (run_no_so_pipeline(combined, (size_t)combined_len, &raw, &raw_len) != 0) {
        return -1;
    }
    int rc = decode_to_buffers(raw, raw_len, &g_json, &g_json_len, &g_webp, &g_webp_len);
    free(raw);
    return rc;
}

/* Test-only: decode an ALREADY-decrypted buffer directly, skipping the
 * AES/RSA crypto pipeline. Input layout is the decode_to_buffers() format
 * (2-byte BE text_len + CHAR_TABLE text + 2-byte BE img_len + WebP). Lets the
 * Node smoke test exercise the WASM marshalling + output decode against a
 * synthetic, PII-free fixture, since a real encrypted QR payload cannot be
 * fabricated (the RSA layers use recovered public keys). Results are exposed
 * through the same get_json_ptr/get_webp_ptr getters as decode_qr. */
EMSCRIPTEN_KEEPALIVE
int decode_decrypted(const uint8_t *decoded_bin, int decoded_len) {
    if (g_json) { free(g_json); g_json = NULL; g_json_len = 0; }
    if (g_webp) { free(g_webp); g_webp = NULL; g_webp_len = 0; }
    return decode_to_buffers(decoded_bin, (size_t)decoded_len,
                             &g_json, &g_json_len, &g_webp, &g_webp_len);
}

EMSCRIPTEN_KEEPALIVE const char *get_json_ptr(void) { return g_json; }
EMSCRIPTEN_KEEPALIVE int         get_json_len(void) { return (int)g_json_len; }
EMSCRIPTEN_KEEPALIVE const uint8_t *get_webp_ptr(void) { return g_webp; }
EMSCRIPTEN_KEEPALIVE int             get_webp_len(void) { return (int)g_webp_len; }

EMSCRIPTEN_KEEPALIVE
uint8_t *alloc_buf(int n) { return (uint8_t *)malloc((size_t)n); }

EMSCRIPTEN_KEEPALIVE
void free_buf(void *p) { free(p); }
