/* Public WASM API. Single entry point that runs the full pipeline. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "../vendor/bignum.h"

/* High-level pipeline: takes 1712 bytes (qr_left[2:] + qr_right[2:])
 * and produces a malloc'd JSON + WebP. Caller frees both. */
int run_no_so_pipeline(const uint8_t *combined, size_t combined_len,
                       uint8_t **out_data, size_t *out_len);

int decode_to_buffers(const uint8_t *decoded_bin, size_t len,
                      char    **json_out, size_t *json_len,
                      uint8_t **webp_out, size_t *webp_len);

/* Glue functions provided by glue.c. */
uint8_t *aes_cbc_decrypt(const uint8_t *key, const uint8_t *iv,
                         const uint8_t *ct, size_t ct_len, size_t *out_len);
int      base64_decode(const char *b64, uint8_t *buf, int buf_size);
uint8_t *rsa_pkcs1_decrypt_multiblock(BIGNUM *n, BIGNUM *e, int key_bytes,
                                      const uint8_t *ct, size_t ct_len,
                                      BN_CTX *bn_ctx, size_t *out_len);
