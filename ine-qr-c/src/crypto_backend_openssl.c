/* ══ FILE: crypto_backend_openssl.c ══
 *
 * OpenSSL implementation of ine_crypto_backend.h.
 *
 * Shared by the desktop ine_decode CLI, libine_decode.a (FFI consumers), and
 * the Android NDK build (which links the same source against BoringSSL's
 * libcrypto — every OpenSSL API used here exists in BoringSSL with identical
 * signatures).
 *
 * The four primitives are exactly what no_so_crypto.c calls.
 */

#include "ine_crypto_backend.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

/* base64_decode is supplied by vendor/base64.c (compiled separately). */

/* ── AES-256-CBC + PKCS7 ────────────────────────────────────────────── */

uint8_t *aes_cbc_decrypt(const uint8_t *key, const uint8_t *iv,
                         const uint8_t *ct, size_t ct_len,
                         size_t *out_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;

    uint8_t *out = malloc(ct_len + 16);
    if (!out) { EVP_CIPHER_CTX_free(ctx); return NULL; }

    int len1 = 0, len2 = 0;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) ||
        !EVP_DecryptUpdate(ctx, out, &len1, ct, (int)ct_len) ||
        !EVP_DecryptFinal_ex(ctx, out + len1, &len2)) {
        free(out);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    EVP_CIPHER_CTX_free(ctx);
    *out_len = (size_t)(len1 + len2);
    return out;
}

/* ── Multi-block raw RSA + PKCS#1 v1.5 strip ────────────────────────── */

uint8_t *rsa_pkcs1_decrypt_multiblock(BIGNUM *n, BIGNUM *e, int key_bytes,
                                      const uint8_t *ct, size_t ct_len,
                                      BN_CTX *bn_ctx, size_t *out_len) {
    int nblocks = (int)(ct_len / (size_t)key_bytes);
    if (nblocks == 0) return NULL;

    uint8_t *result = malloc((size_t)nblocks * (size_t)key_bytes);
    if (!result) return NULL;
    size_t total = 0;

    uint8_t *raw = malloc((size_t)key_bytes);
    if (!raw) { free(result); return NULL; }

    BIGNUM *c_bn = BN_new();
    BIGNUM *m_bn = BN_new();

    for (int i = 0; i < nblocks; i++) {
        BN_bin2bn(ct + i * key_bytes, key_bytes, c_bn);
        BN_mod_exp(m_bn, c_bn, e, n, bn_ctx);
        int mlen = BN_num_bytes(m_bn);
        memset(raw, 0, (size_t)key_bytes);
        BN_bn2bin(m_bn, raw + key_bytes - mlen);

        if (raw[0] != 0x00 || (raw[1] != 0x01 && raw[1] != 0x02)) {
            free(raw); free(result); BN_free(c_bn); BN_free(m_bn);
            return NULL;
        }
        int sep = -1;
        for (int j = 2; j < key_bytes; j++) {
            if (raw[j] == 0x00) { sep = j; break; }
        }
        if (sep < 0) {
            free(raw); free(result); BN_free(c_bn); BN_free(m_bn);
            return NULL;
        }
        size_t msize = (size_t)(key_bytes - sep - 1);
        memcpy(result + total, raw + sep + 1, msize);
        total += msize;
    }

    free(raw);
    BN_free(c_bn);
    BN_free(m_bn);
    *out_len = total;
    return result;
}
