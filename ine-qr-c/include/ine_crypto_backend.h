/* ══ FILE: ine_crypto_backend.h ══
 *
 * Backend-agnostic shim for the four crypto primitives no_so_crypto.c needs.
 *
 * The desktop / Android builds satisfy this header with OpenSSL or BoringSSL
 * (crypto_backend_openssl.c, crypto_backend_boringssl.c — same source modulo
 * include paths). The iOS build can swap in a vendored bignum + CommonCrypto
 * implementation by defining INE_BACKEND_VENDORED_BN before including this
 * header in its translation units. The wasm build already proves the vendored
 * path works bit-exact (see ine-qr-wasm/vendor/{aes256,bignum,base64}.c).
 *
 * Surface (the entire crypto dependency of no_so_crypto.c):
 *   - aes_cbc_decrypt              AES-256-CBC + PKCS7 unpad
 *   - rsa_pkcs1_decrypt_multiblock multi-block raw RSA + PKCS#1 v1.5 strip
 *   - base64_decode                from the vendored base64.{c,h}
 *   - BN_* / BN_CTX_*              modexp + binary <-> bignum conversions
 *
 * Why base64 lives outside this header: BoringSSL has been deprecating
 * BIO-based primitives, and an OpenSSL/BoringSSL-shaped base64 is dead-
 * weight when a 30-line public-domain decoder works on every platform.
 *
 * The BN_* declarations come from whichever bignum implementation is in use,
 * not from this header — so callers see the right BIGNUM type.
 */

#pragma once
#include <stdint.h>
#include <stddef.h>

#if defined(INE_BACKEND_VENDORED_BN)
#  include "bignum.h"
#else
#  include <openssl/bn.h>
#endif

/* base64_decode lives in vendor/base64.{c,h} — same signature on every backend. */
#include "base64.h"

#ifdef __cplusplus
extern "C" {
#endif

/* AES-256-CBC decrypt with PKCS7 unpadding.
 * key = 32 bytes, iv = 16 bytes. Output malloc'd; caller frees.
 * Returns NULL on cipher error or padding failure. */
uint8_t *aes_cbc_decrypt(const uint8_t *key, const uint8_t *iv,
                         const uint8_t *ct, size_t ct_len,
                         size_t *out_len);

/* RSA raw public-key decrypt across consecutive key_bytes-sized blocks with
 * PKCS#1 v1.5 stripping. Output malloc'd; caller frees.
 * Returns NULL if ct_len is not a multiple of key_bytes or on padding error. */
uint8_t *rsa_pkcs1_decrypt_multiblock(BIGNUM *n, BIGNUM *e, int key_bytes,
                                      const uint8_t *ct, size_t ct_len,
                                      BN_CTX *bn_ctx, size_t *out_len);

#ifdef __cplusplus
}
#endif
