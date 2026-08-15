/* Minimal bignum modexp on 32-bit limbs. Square-and-multiply with plain
 * schoolbook multiplication and Knuth's Algorithm D for division.
 * Not constant-time, not Montgomery. Adequate for one-shot 2048-bit
 * RSA decrypts (a few ms in WASM).
 *
 * Internal limb order: little-endian (limbs[0] = least significant).
 * Sign is unsigned only — no negative numbers needed. */
#include "bignum.h"
#include <stdlib.h>
#include <string.h>

#define LIMB_BITS 32
typedef uint32_t limb_t;
typedef uint64_t dlimb_t;

struct BIGNUM {
    limb_t  *d;     /* limbs, little-endian */
    int      n;     /* significant limb count */
    int      cap;   /* allocated limb count */
};

struct BN_CTX { int dummy; };

BN_CTX *BN_CTX_new(void)        { return (BN_CTX *)calloc(1, sizeof(BN_CTX)); }
void    BN_CTX_free(BN_CTX *c)  { free(c); }

static int bn_grow(BIGNUM *a, int cap) {
    if (a->cap >= cap) return 0;
    limb_t *nd = (limb_t *)realloc(a->d, (size_t)cap * sizeof(limb_t));
    if (!nd) return -1;
    if (cap > a->cap) memset(nd + a->cap, 0, (size_t)(cap - a->cap) * sizeof(limb_t));
    a->d = nd;
    a->cap = cap;
    return 0;
}

static void bn_trim(BIGNUM *a) {
    while (a->n > 0 && a->d[a->n - 1] == 0) a->n--;
}

BIGNUM *BN_new(void) {
    BIGNUM *r = (BIGNUM *)calloc(1, sizeof(BIGNUM));
    return r;
}

void BN_free(BIGNUM *bn) {
    if (!bn) return;
    free(bn->d);
    free(bn);
}

BIGNUM *BN_bin2bn(const uint8_t *s, int len, BIGNUM *ret) {
    BIGNUM *r = ret ? ret : BN_new();
    if (!r) return NULL;
    int nlimbs = (len + 3) / 4;
    if (nlimbs == 0) nlimbs = 1;
    if (bn_grow(r, nlimbs) < 0) { if (!ret) BN_free(r); return NULL; }
    memset(r->d, 0, (size_t)r->cap * sizeof(limb_t));
    /* big-endian bytes → little-endian limbs */
    for (int i = 0; i < len; i++) {
        int byte_from_lsb = len - 1 - i;
        int li = byte_from_lsb / 4;
        int sh = (byte_from_lsb % 4) * 8;
        r->d[li] |= ((limb_t)s[i]) << sh;
    }
    r->n = nlimbs;
    bn_trim(r);
    return r;
}

int BN_num_bytes(const BIGNUM *a) {
    if (a->n == 0) return 0;
    limb_t top = a->d[a->n - 1];
    int top_bytes = 0;
    while (top) { top_bytes++; top >>= 8; }
    return (a->n - 1) * 4 + top_bytes;
}

int BN_bn2bin(const BIGNUM *a, uint8_t *to) {
    int total = BN_num_bytes(a);
    for (int i = 0; i < total; i++) {
        int byte_from_lsb = total - 1 - i;
        int li = byte_from_lsb / 4;
        int sh = (byte_from_lsb % 4) * 8;
        to[i] = (uint8_t)((a->d[li] >> sh) & 0xFF);
    }
    return total;
}

/* ── arithmetic helpers ── */

static int bn_cmp(const BIGNUM *a, const BIGNUM *b) {
    if (a->n != b->n) return a->n < b->n ? -1 : 1;
    for (int i = a->n - 1; i >= 0; i--) {
        if (a->d[i] != b->d[i]) return a->d[i] < b->d[i] ? -1 : 1;
    }
    return 0;
}

static int bn_set_zero(BIGNUM *a) {
    if (bn_grow(a, 1) < 0) return -1;
    a->d[0] = 0;
    a->n = 0;
    return 0;
}

static int bn_copy(BIGNUM *dst, const BIGNUM *src) {
    if (bn_grow(dst, src->n > 0 ? src->n : 1) < 0) return -1;
    memset(dst->d, 0, (size_t)dst->cap * sizeof(limb_t));
    if (src->n) memcpy(dst->d, src->d, (size_t)src->n * sizeof(limb_t));
    dst->n = src->n;
    return 0;
}

/* r = a * b. r must not alias a or b. */
static int bn_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b) {
    int rn = a->n + b->n;
    if (rn == 0) return bn_set_zero(r);
    if (bn_grow(r, rn + 1) < 0) return -1;
    memset(r->d, 0, (size_t)r->cap * sizeof(limb_t));
    for (int i = 0; i < a->n; i++) {
        dlimb_t carry = 0;
        dlimb_t ai = a->d[i];
        for (int j = 0; j < b->n; j++) {
            dlimb_t cur = (dlimb_t)r->d[i + j] + ai * (dlimb_t)b->d[j] + carry;
            r->d[i + j] = (limb_t)cur;
            carry = cur >> LIMB_BITS;
        }
        r->d[i + b->n] = (limb_t)carry;
    }
    r->n = rn + 1;
    bn_trim(r);
    return 0;
}

/* a >>= 1 in-place */
static void bn_shr1(BIGNUM *a) {
    if (a->n == 0) return;
    limb_t carry = 0;
    for (int i = a->n - 1; i >= 0; i--) {
        limb_t cur = a->d[i];
        a->d[i] = (cur >> 1) | (carry << (LIMB_BITS - 1));
        carry = cur & 1u;
    }
    bn_trim(a);
}

/* a -= b ; assumes a >= b */
static void bn_sub_assign(BIGNUM *a, const BIGNUM *b) {
    int64_t borrow = 0;
    for (int i = 0; i < a->n; i++) {
        int64_t bv = (i < b->n) ? (int64_t)b->d[i] : 0;
        int64_t diff = (int64_t)a->d[i] - bv - borrow;
        if (diff < 0) { diff += ((int64_t)1 << LIMB_BITS); borrow = 1; }
        else borrow = 0;
        a->d[i] = (limb_t)diff;
    }
    bn_trim(a);
}

/* a <<= 1 in-place */
static int bn_shl1(BIGNUM *a) {
    if (bn_grow(a, a->n + 1) < 0) return -1;
    limb_t carry = 0;
    for (int i = 0; i < a->n; i++) {
        limb_t cur = a->d[i];
        a->d[i] = (cur << 1) | carry;
        carry = cur >> (LIMB_BITS - 1);
    }
    if (carry) {
        a->d[a->n] = carry;
        a->n++;
    }
    return 0;
}

/* r = a mod m, where a may be much larger than m. Schoolbook restoring
 * binary long division — slow but simple and correct.
 *
 * We iterate from the high bit of a downward, building rem = (rem<<1) | bit
 * and subtracting m whenever rem >= m. Result lands in r. */
static int bn_mod(BIGNUM *r, const BIGNUM *a, const BIGNUM *m) {
    if (m->n == 0) return -1;
    BIGNUM *rem = BN_new();
    if (!rem) return -1;
    if (bn_set_zero(rem) < 0) { BN_free(rem); return -1; }

    int total_bits = a->n * LIMB_BITS;
    /* Find highest set bit */
    int top = total_bits - 1;
    while (top >= 0 && ((a->d[top / LIMB_BITS] >> (top % LIMB_BITS)) & 1u) == 0) top--;

    for (int bit = top; bit >= 0; bit--) {
        if (bn_shl1(rem) < 0) { BN_free(rem); return -1; }
        int b = (a->d[bit / LIMB_BITS] >> (bit % LIMB_BITS)) & 1u;
        if (b) {
            if (rem->n == 0) {
                if (bn_grow(rem, 1) < 0) { BN_free(rem); return -1; }
                rem->n = 1;
            }
            rem->d[0] |= 1u;
        }
        if (bn_cmp(rem, m) >= 0) bn_sub_assign(rem, m);
    }
    if (bn_copy(r, rem) < 0) { BN_free(rem); return -1; }
    BN_free(rem);
    return 0;
}

/* r = (a * b) mod m */
static int bn_mulmod(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m) {
    BIGNUM *t = BN_new();
    if (!t) return -1;
    if (bn_mul(t, a, b) < 0) { BN_free(t); return -1; }
    if (bn_mod(r, t, m) < 0) { BN_free(t); return -1; }
    BN_free(t);
    return 0;
}

int BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
               const BIGNUM *m, BN_CTX *ctx) {
    (void)ctx;
    /* result = 1 */
    if (bn_grow(r, 1) < 0) return -1;
    memset(r->d, 0, (size_t)r->cap * sizeof(limb_t));
    r->d[0] = 1;
    r->n = 1;

    BIGNUM *base = BN_new();
    if (!base) return -1;
    if (bn_mod(base, a, m) < 0) { BN_free(base); return -1; }

    BIGNUM *exp = BN_new();
    if (!exp) { BN_free(base); return -1; }
    if (bn_copy(exp, p) < 0) { BN_free(base); BN_free(exp); return -1; }

    BIGNUM *t = BN_new();
    if (!t) { BN_free(base); BN_free(exp); return -1; }

    while (exp->n > 0) {
        if (exp->d[0] & 1u) {
            if (bn_mulmod(t, r, base, m) < 0) goto err;
            if (bn_copy(r, t) < 0) goto err;
        }
        bn_shr1(exp);
        if (exp->n == 0) break;
        if (bn_mulmod(t, base, base, m) < 0) goto err;
        if (bn_copy(base, t) < 0) goto err;
    }

    BN_free(base); BN_free(exp); BN_free(t);
    return 0;
err:
    BN_free(base); BN_free(exp); BN_free(t);
    return -1;
}
