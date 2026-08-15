/* ══ FILE: no_so_crypto.h ══
 *
 * Public API for the fully self-contained INE QR crypto pipeline.
 * No libPersonalCode.so required; all .rodata constants and AES ciphertexts
 * are hardcoded inline in no_so_crypto.c.
 *
 * This is the C equivalent of ine-qr-py/no_so_pipeline.py.
 */

#pragma once
#include <stdint.h>
#include <stddef.h>

/* Key derivation results from the six NEON SIMD blocks.
 * Each string is a null-terminated uppercase ASCII hex value
 * (as they appear in the .so .rodata — the NEON ops emit ASCII bytes). */
typedef struct {
    char aes_iv1 [33];  /* 32 hex chars = 16 bytes */
    char aes_key1[65];  /* 64 hex chars = 32 bytes */
    char aes_iv2 [33];
    char aes_key2[65];
    char aes_iv3 [33];
    char aes_key3[65];
} NoSoKeys;

/* Derive all six AES keys / IVs from hardcoded .rodata constants.
 * Fills *keys and returns 0 on success (always succeeds). */
int no_so_derive_keys(NoSoKeys *keys);

/* Run the full 3-round AES+RSA pipeline + buf2 decrypt without any .so.
 *
 *   combined     : qr_left[2:] + qr_right[2:]  (1712 bytes)
 *   combined_len : must be >= 1712
 *   out_data     : receives a malloc'd buffer with the decrypted payload
 *   out_len      : receives its length
 *
 * Returns 0 on success, -1 on any crypto failure.
 * Caller must free(*out_data). */
int run_no_so_pipeline(const uint8_t *combined, size_t combined_len,
                       uint8_t **out_data, size_t *out_len);

/* Decode the plaintext from run_no_so_pipeline and write output files.
 *
 *   plain      : decrypted payload bytes (pipe-separated biographic text
 *                or raw image data)
 *   len        : byte count
 *   output_dir : directory to write datos_biograficos.json and/or foto_ine.*
 *
 * Prints a field summary to stderr.
 * Returns 0 on success, -1 on I/O or parse failure. */
int no_so_decode_and_write(const uint8_t *plain, size_t len,
                           const char *output_dir);
