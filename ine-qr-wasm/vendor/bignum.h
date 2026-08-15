/* Minimal bignum supporting just what no_so_crypto.c needs:
 * - BN_new / BN_free
 * - BN_bin2bn / BN_bn2bin / BN_num_bytes
 * - BN_mod_exp(r, base, exp, mod, ctx)
 * - BN_CTX_new / BN_CTX_free  (CTX is a no-op)
 *
 * API names match OpenSSL so existing pipeline code compiles unchanged. */
#pragma once
#include <stdint.h>
#include <stddef.h>

typedef struct BIGNUM BIGNUM;
typedef struct BN_CTX BN_CTX;

BIGNUM *BN_new(void);
void    BN_free(BIGNUM *bn);

/* OpenSSL BN_bin2bn allocates a fresh BIGNUM if ret == NULL,
 * otherwise reuses it. */
BIGNUM *BN_bin2bn(const uint8_t *s, int len, BIGNUM *ret);
int     BN_bn2bin(const BIGNUM *a, uint8_t *to);
int     BN_num_bytes(const BIGNUM *a);

int     BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                   const BIGNUM *m, BN_CTX *ctx);

BN_CTX *BN_CTX_new(void);
void    BN_CTX_free(BN_CTX *ctx);
