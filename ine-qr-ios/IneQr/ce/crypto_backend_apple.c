/* ══ FILE: crypto_backend_apple.c ══
 *
 * Apple implementation of ine_crypto_backend.h. Default backend: vendored
 * AES-256-CBC + vendored bignum (both lifted from ine-qr-wasm/vendor/),
 * which the wasm build has already proven bit-exact against the desktop
 * reference.
 *
 * Why vendored over Security.framework: Apple's RSA APIs do not expose a
 * verify-recover operation that returns the recovered message — they only
 * expose verify-as-bool. The pipeline's Stage B is mathematically the same
 * as RSA verify-recover; doing it via SecKeyCreateEncryptedData with
 * kSecKeyAlgorithmRSAEncryptionRaw is possible but unverified for
 * RSA-8192 keys across the iOS 15-18 matrix. The vendored bignum is 256
 * lines of public-domain C and removes the risk entirely.
 *
 * If/when the spike in Spikes/RsaVerifyRecoverSpike.swift confirms the
 * Security.framework path works on every iOS version we support, swap
 * this file's RSA path for SecKeyCreateEncryptedData and keep AES on
 * CommonCrypto. The header surface won't change.
 */

#include "include/ine_crypto_backend.h"
#include "vendor/aes256.h"
#include "vendor/base64.h"
#include "vendor/bignum.h"

#include <stdlib.h>
#include <string.h>

uint8_t *aes_cbc_decrypt(const uint8_t *key, const uint8_t *iv,
                         const uint8_t *ct, size_t ct_len,
                         size_t *out_len) {
    return aes256_cbc_decrypt_pkcs7(key, iv, ct, ct_len, out_len);
}

/* base64_decode is provided directly by vendor/base64.c with the matching
 * signature; no wrapper required. base64_encode is not exercised by the
 * shipped decode path on iOS. Stub it so the symbol resolves if any future
 * caller links against it. */
char *base64_encode(const uint8_t *in, size_t in_len, char *out_buf) {
    (void)in; (void)in_len;
    if (out_buf) out_buf[0] = '\0';
    return out_buf;
}

uint8_t *rsa_pkcs1_decrypt_multiblock(BIGNUM *n, BIGNUM *e, int key_bytes,
                                      const uint8_t *ct, size_t ct_len,
                                      BN_CTX *bn_ctx, size_t *out_len) {
    int nblocks = (int)(ct_len / (size_t)key_bytes);
    if (nblocks == 0) return NULL;

    uint8_t *result = (uint8_t *)malloc((size_t)nblocks * (size_t)key_bytes);
    if (!result) return NULL;
    size_t total = 0;

    uint8_t *raw = (uint8_t *)malloc((size_t)key_bytes);
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
