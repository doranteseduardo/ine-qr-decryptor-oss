/* Pure-C AES-256-CBC decrypt with PKCS7 unpadding. Public domain. */
#pragma once
#include <stdint.h>
#include <stddef.h>

/* Decrypts ct[0..ct_len) with AES-256-CBC and strips PKCS7 padding.
 * key = 32 bytes, iv = 16 bytes, ct_len must be a multiple of 16.
 * Returns malloc'd plaintext (caller frees) and sets *out_len.
 * Returns NULL on bad padding or OOM. */
uint8_t *aes256_cbc_decrypt_pkcs7(const uint8_t key[32], const uint8_t iv[16],
                                  const uint8_t *ct, size_t ct_len,
                                  size_t *out_len);
