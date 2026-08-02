/* ══ FILE: crypto_state.h ══
 *
 * Emulator-only helpers (`run_static_pipeline`, `precompute_buf2`) that
 * decrypt the `.so`'s embedded layer-1/2 ciphertexts so the Unicorn path
 * can pre-inject the resulting RSA key #2 + buf2 plaintext.
 *
 * The four crypto primitives (aes_cbc_decrypt, rsa_pkcs1_decrypt_multiblock,
 * base64_decode, BN_*) live in ine_crypto_backend.h — include that header
 * directly when you need them.
 */

#pragma once
#include "ine_types.h"
#include "ine_crypto_backend.h"
#include <stdint.h>

/* Run static crypto layers 1a, 1b, and 2 (AES → RSA#1 → RSA#2) against
 * the ciphertext embedded in the .so binary.
 *
 * so_data / so_size : full .so contents (read-only)
 * rsa_key2_xml      : caller buffer; receives the RSA key #2 XML on success
 * max_len           : size of rsa_key2_xml (recommend >= 65536)
 *
 * Returns 0 on success, -1 on decryption or parse failure. */
int run_static_pipeline(const uint8_t *so_data, size_t so_size,
                        char *rsa_key2_xml, size_t max_len);

/* Decrypt the 1024-byte buf2 region (combined[688:1712]) with RSA key #2.
 * Strips PKCS#1 v1.5 padding.
 * Returns malloc'd plaintext and writes *out_len; caller must free.
 * Returns NULL if combined is too short, key parse fails, or padding is invalid. */
uint8_t *precompute_buf2(const char *rsa_key2_xml,
                         const uint8_t *combined, size_t combined_len,
                         size_t *out_len);
