/* Glue: provides the OpenSSL-shaped helpers that pipeline.c expects, but
 * implemented on top of our vendored AES / bignum / base64. */
#include "../include/wasm_pipeline.h"
#include "../vendor/aes256.h"
#include "../vendor/base64.h"
#include "../vendor/bignum.h"
#include <stdlib.h>
#include <string.h>

uint8_t *aes_cbc_decrypt(const uint8_t *key, const uint8_t *iv,
                         const uint8_t *ct, size_t ct_len,
                         size_t *out_len) {
    return aes256_cbc_decrypt_pkcs7(key, iv, ct, ct_len, out_len);
}

/* base64_decode is already provided directly by vendor/base64.c with the
 * matching signature, so no wrapper needed. */

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
