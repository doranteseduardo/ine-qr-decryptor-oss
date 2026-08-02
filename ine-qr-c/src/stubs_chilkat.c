/* ══ FILE: stubs_chilkat.c ══
 *
 * Host-side intercepts for the Chilkat cryptography library calls made by
 * the emulated libPersonalCode.so.
 *
 * The .so statically links Chilkat (v9.5) for AES, RSA, ECC, and BinData
 * operations.  Most Chilkat internal methods (object construction, BinData
 * append, ECC hash/verify) run natively inside the Unicorn sandbox because
 * they operate on internal object state that is too complex to replicate on
 * the host.  Only the boundary operations that supply or extract key
 * material are intercepted:
 *
 *   CkCrypt2_SetEncodedKey    — capture AES key hex → ctx->aes_key_hex
 *   CkCrypt2_SetEncodedIV     — capture AES IV hex  → ctx->aes_iv_hex
 *   CkCrypt2_decryptStringENC — host AES-CBC-256 decrypt using captured key/IV
 *
 *   CkRsa_ImportPublicKey     — parse XML key, store n/e/key_bytes in ctx->rsa_keys[]
 *   CkRsa_decryptStringENC    — host RSA PKCS#1 multi-block decrypt
 *   CkRsa_DecryptBd           — no-op (data is pre-injected by emulator.c)
 *   CkRsa_getLastMethodSuccess→ always 1
 *
 *   CkEcc_VerifyHashENC       — always returns 1 (signature check bypassed)
 *
 *   CkGlobal_UnlockBundle     — always returns 1 (license bypass)
 *   CkXxx_Dispose             — no-op (bump heap, nothing to free)
 *
 * Note: CkBinData, CkEcc, and CkPublicKey methods other than Dispose run
 * natively; their emulated vtables are populated by the ELF loader from
 * the real .so code.
 */

#include "stub_dispatch.h"
#include "bump_heap.h"
#include "crypto_state.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <unicorn/unicorn.h>
#include <unicorn/arm64.h>

/* Read a 64-bit register from the Unicorn engine. */
static inline uint64_t x(INEContext *ctx, int reg) {
    uint64_t v = 0; uc_reg_read((uc_engine *)ctx->uc, reg, &v); return v;
}

/* Read a null-terminated string from emulated memory at addr into host buf
 * (at most max-1 bytes).  Returns the length read. */
static int emu_read_str(INEContext *ctx, uint64_t addr, char *buf, int max) {
    if (!addr) { if (max > 0) buf[0] = '\0'; return 0; }
    int len = 0;
    while (len < max - 1) {
        uint8_t c;
        if (uc_mem_read((uc_engine *)ctx->uc, addr + (uint64_t)len, &c, 1) != UC_ERR_OK) break;
        buf[len++] = (char)c;
        if (!c) break;
    }
    buf[len] = '\0';
    return len;
}

/* ── CkCrypt2 handlers ── */

/* CkCrypt2_SetEncodedKey(obj, key_hex_str): capture the AES key from X1
 * into ctx->aes_key_hex so the host-side decrypt stub can use it later. */
void h_ckcrypt2_set_encoded_key(INEContext *ctx) {
    char key_str[256] = {0};
    emu_read_str(ctx, x(ctx, UC_ARM64_REG_X1), key_str, sizeof(key_str));
    strncpy(ctx->aes_key_hex, key_str, sizeof(ctx->aes_key_hex) - 1);
    ctx->aes_key_captured = 1;
    if (ctx->verbose)
        fprintf(stderr, "  >> CkCrypt2_SetEncodedKey: key=%s\n", key_str);
    uint64_t lr; uc_reg_read((uc_engine *)ctx->uc, UC_ARM64_REG_LR, &lr);
    uc_reg_write((uc_engine *)ctx->uc, UC_ARM64_REG_PC, &lr);
}

/* CkCrypt2_SetEncodedIV(obj, iv_hex_str): capture the AES IV from X1
 * into ctx->aes_iv_hex. */
void h_ckcrypt2_set_encoded_iv(INEContext *ctx) {
    char iv_str[128] = {0};
    emu_read_str(ctx, x(ctx, UC_ARM64_REG_X1), iv_str, sizeof(iv_str));
    strncpy(ctx->aes_iv_hex, iv_str, sizeof(ctx->aes_iv_hex) - 1);
    ctx->aes_iv_captured = 1;
    if (ctx->verbose)
        fprintf(stderr, "  >> CkCrypt2_SetEncodedIV: iv=%s\n", iv_str);
    uint64_t lr; uc_reg_read((uc_engine *)ctx->uc, UC_ARM64_REG_LR, &lr);
    uc_reg_write((uc_engine *)ctx->uc, UC_ARM64_REG_PC, &lr);
}

/* CkCrypt2_decryptStringENC(obj, hex_ciphertext): decrypt the hex-encoded
 * ciphertext from X1 using the previously captured AES-256-CBC key/IV.
 * Writes the plaintext into the bump heap and returns its emulated address
 * in X0 as a null-terminated string.  Returns 0 (NULL) if key/IV not yet
 * captured or if decryption fails. */
void h_ckcrypt2_decrypt_string_enc(INEContext *ctx) {
    char hex_input[131072] = {0};
    emu_read_str(ctx, x(ctx, UC_ARM64_REG_X1), hex_input, sizeof(hex_input));

    if (!ctx->aes_key_captured || !ctx->aes_iv_captured || !hex_input[0]) {
        if (ctx->verbose)
            fprintf(stderr, "  >> CkCrypt2_decryptStringENC → NULL (missing key/iv/input)\n");
        stub_ret(ctx, 0);
        return;
    }

    /* Convert hex key/iv to bytes */
    uint8_t aes_key[32], aes_iv[16];
    for (int i = 0; i < 32; i++) {
        unsigned int b; sscanf(ctx->aes_key_hex + i*2, "%02x", &b); aes_key[i] = (uint8_t)b;
    }
    for (int i = 0; i < 16; i++) {
        unsigned int b; sscanf(ctx->aes_iv_hex + i*2, "%02x", &b); aes_iv[i] = (uint8_t)b;
    }

    size_t ct_len = strlen(hex_input) / 2;
    uint8_t *ct = malloc(ct_len);
    for (size_t i = 0; i < ct_len; i++) {
        unsigned int b; sscanf(hex_input + i*2, "%02x", &b); ct[i] = (uint8_t)b;
    }

    size_t pt_len;
    uint8_t *pt = aes_cbc_decrypt(aes_key, aes_iv, ct, ct_len, &pt_len);
    free(ct);

    if (!pt) {
        if (ctx->verbose)
            fprintf(stderr, "  >> CkCrypt2_decryptStringENC → NULL (AES failed)\n");
        stub_ret(ctx, 0);
        return;
    }

    uint64_t ptr = bump_write(ctx, pt, pt_len);
    if (ctx->verbose)
        fprintf(stderr, "  >> CkCrypt2_decryptStringENC → %zu chars\n", pt_len);
    free(pt);
    stub_ret(ctx, ptr);
}

/* ── CkRsa handlers ── */

/* CkRsa_ImportPublicKey(obj, xml_str): parse the Chilkat RSA XML key from X1
 * and store the resulting BIGNUM pair (n, e) in ctx->rsa_keys[].
 * Supports up to 8 distinct RSA key objects.  Returns 1 on success. */
void h_rsa_import_public_key(INEContext *ctx) {
    uint64_t rsa_obj = x(ctx, UC_ARM64_REG_X0);
    char xml_key[65536] = {0};
    emu_read_str(ctx, x(ctx, UC_ARM64_REG_X1), xml_key, sizeof(xml_key));

    if (!strstr(xml_key, "<RSAPublicKey>")) {
        if (ctx->verbose)
            fprintf(stderr, "  >> CkRsa_ImportPublicKey: no valid XML\n");
        stub_ret(ctx, 0);
        return;
    }

    /* Find <Modulus> and <Exponent> */
    char *mod_start = strstr(xml_key, "<Modulus>");
    char *mod_end   = strstr(xml_key, "</Modulus>");
    char *exp_start = strstr(xml_key, "<Exponent>");
    char *exp_end   = strstr(xml_key, "</Exponent>");

    if (!mod_start || !mod_end || !exp_start || !exp_end) {
        stub_ret(ctx, 0); return;
    }
    mod_start += strlen("<Modulus>");
    exp_start += strlen("<Exponent>");

    size_t mod_b64_len = (size_t)(mod_end - mod_start);
    size_t exp_b64_len = (size_t)(exp_end - exp_start);

    char *mod_b64 = malloc(mod_b64_len + 1);
    char *exp_b64 = malloc(exp_b64_len + 1);
    memcpy(mod_b64, mod_start, mod_b64_len); mod_b64[mod_b64_len] = '\0';
    memcpy(exp_b64, exp_start, exp_b64_len); exp_b64[exp_b64_len] = '\0';

    size_t mod_bin_sz = mod_b64_len + 4;
    uint8_t *mod_bin = malloc(mod_bin_sz);
    uint8_t *exp_bin = malloc(exp_b64_len + 4);

    int mod_bytes = base64_decode(mod_b64, mod_bin, (int)mod_bin_sz);
    int exp_bytes = base64_decode(exp_b64, exp_bin, (int)(exp_b64_len + 4));
    free(mod_b64); free(exp_b64);

    if (mod_bytes <= 0 || exp_bytes <= 0) {
        free(mod_bin); free(exp_bin); stub_ret(ctx, 0); return;
    }

    if (ctx->rsa_key_count < 8) {
        int ki = ctx->rsa_key_count++;
        ctx->rsa_keys[ki].obj_ptr   = rsa_obj;
        ctx->rsa_keys[ki].n         = BN_bin2bn(mod_bin, mod_bytes, NULL);
        ctx->rsa_keys[ki].e         = BN_bin2bn(exp_bin, exp_bytes, NULL);
        ctx->rsa_keys[ki].key_bytes = mod_bytes;
        if (ctx->verbose)
            fprintf(stderr, "  >> CkRsa_ImportPublicKey: %d-bit key #%d\n",
                    mod_bytes * 8, ki + 1);
    }
    free(mod_bin); free(exp_bin);
    stub_ret(ctx, 1);
}

/* CkRsa_decryptStringENC(obj, b64_ciphertext): base64-decode the ciphertext
 * from X1, look up the RSA key by object pointer (ctx->rsa_keys), then
 * perform multi-block PKCS#1 v1.5 raw RSA decrypt on the host.
 * Falls back to the last imported key if the object pointer is not found
 * (matches the Python reference implementation).
 * Returns emulated pointer to plaintext or 0 on failure. */
void h_rsa_decrypt_string_enc(INEContext *ctx) {
    uint64_t rsa_obj = x(ctx, UC_ARM64_REG_X0);
    char enc_str[131072] = {0};
    emu_read_str(ctx, x(ctx, UC_ARM64_REG_X1), enc_str, sizeof(enc_str));

    /* Find key for this RSA object */
    RSAKeyEntry *key_entry = NULL;
    for (int i = 0; i < ctx->rsa_key_count; i++) {
        if (ctx->rsa_keys[i].obj_ptr == rsa_obj) {
            key_entry = &ctx->rsa_keys[i];
            break;
        }
    }
    /* Fallback: use last imported key (matches Python behavior) */
    if (!key_entry && ctx->rsa_key_count > 0)
        key_entry = &ctx->rsa_keys[ctx->rsa_key_count - 1];

    if (!key_entry || !enc_str[0]) {
        stub_ret(ctx, 0); return;
    }

    /* Decode base64 */
    size_t enc_len = strlen(enc_str);
    size_t ct_max = enc_len + 4;
    uint8_t *ct = malloc(ct_max);
    int ct_len = base64_decode(enc_str, ct, (int)ct_max);
    if (ct_len <= 0) { free(ct); stub_ret(ctx, 0); return; }

    size_t plain_len;
    uint8_t *plain = rsa_pkcs1_decrypt_multiblock(
        key_entry->n, key_entry->e, key_entry->key_bytes,
        ct, (size_t)ct_len, ctx->bn_ctx, &plain_len);
    free(ct);

    if (!plain) {
        if (ctx->verbose)
            fprintf(stderr, "  >> CkRsa_decryptStringENC → NULL (RSA failed)\n");
        stub_ret(ctx, 0);
        return;
    }

    uint64_t ptr = bump_write(ctx, plain, plain_len);
    if (ctx->verbose)
        fprintf(stderr, "  >> CkRsa_decryptStringENC → %zu chars\n", plain_len);
    free(plain);
    stub_ret(ctx, ptr);
}

/* CkRsa_DecryptBd: the BinData variant of RSA decrypt.  The emulator.c code
 * hook has already injected the decrypted content into the CkBinData object
 * via AppendBinary2 redirect, so this call is a no-op that returns 1 (success). */
void h_rsa_decrypt_bd(INEContext *ctx) {
    if (ctx->verbose)
        fprintf(stderr, "  >> CkRsa_DecryptBd → 1 (data pre-injected)\n");
    stub_ret(ctx, 1);
}

void h_rsa_get_last_success(INEContext *ctx) { stub_ret(ctx, 1); }

/* CkEcc_VerifyHashENC: ECC signature verification over the decoded payload.
 * Real credentials always carry a valid INE signature, so this stub returns 1
 * unconditionally to avoid the overhead of a host-side ECC implementation. */
void h_ecc_verify_hash_enc(INEContext *ctx) {
    if (ctx->verbose)
        fprintf(stderr, "  >> CkEcc_VerifyHashENC → 1 (skipped)\n");
    stub_ret(ctx, 1);
}

/* ── Opaque handle helpers (CkGlobal/CkCrypt2/CkRsa/CkEcc/CkPublicKey) ── */

/* CkXxx_Create: allocate an opaque 256-byte object on the bump heap.
 * The bump pointer serves as the object handle; Chilkat native code reads
 * internal fields from it via the vtable, so the allocation must exist in
 * emulated memory even if the host never interprets the bytes. */
static void h_ck_create(INEContext *ctx) {
    stub_ret(ctx, bump_alloc(ctx, 256));
}
static void h_ck_dispose(INEContext *ctx)  { stub_ret(ctx, 0); }
static void h_ck_nop_ret0(INEContext *ctx) { stub_ret(ctx, 0); }
static void h_ck_ret1(INEContext *ctx)     { stub_ret(ctx, 1); }

/* ── Bulk registration ── */

/* Register all Chilkat intercept stubs.  Only the security-critical and
 * key-capture operations are intercepted; all other Chilkat methods
 * (BinData manipulation, hash computation, ECC key loading) run natively
 * so their internal state machines remain consistent. */
void register_chilkat_stubs(INEContext *ctx) {
    /* CkCrypt2 — Create/Dispose/put* run natively (give real vtable-initialized
     * objects so that hashBdENC/putCharset/putHashAlgorithm work in the ECC section).
     * Only intercept the key-capture and decrypt ops. */
    stub_alloc(ctx, "CkCrypt2_SetEncodedKey",    h_ckcrypt2_set_encoded_key);
    stub_alloc(ctx, "CkCrypt2_SetEncodedIV",     h_ckcrypt2_set_encoded_iv);
    stub_alloc(ctx, "CkCrypt2_decryptStringENC", h_ckcrypt2_decrypt_string_enc);

    stub_alloc(ctx, "CkCrypt2_Dispose",           h_ck_dispose);

    /* CkRsa — Create/Dispose/put* run natively; only intercept crypto ops */
    stub_alloc(ctx, "CkRsa_Dispose",             h_ck_dispose);

    /* CkBinData, CkEcc, CkPublicKey — all methods run natively except Dispose */
    stub_alloc(ctx, "CkBinData_Dispose",         h_ck_dispose);
    stub_alloc(ctx, "CkEcc_Dispose",             h_ck_dispose);
    stub_alloc(ctx, "CkPublicKey_Dispose",       h_ck_dispose);
    stub_alloc(ctx, "CkRsa_ImportPublicKey",     h_rsa_import_public_key);
    stub_alloc(ctx, "CkRsa_decryptStringENC",    h_rsa_decrypt_string_enc);
    stub_alloc(ctx, "CkRsa_DecryptBd",           h_rsa_decrypt_bd);
    stub_alloc(ctx, "CkRsa_getLastMethodSuccess",h_rsa_get_last_success);

    /* CkBinData — let ALL BinData operations run natively via malloc/bump_heap.
     * Native AppendBinary2/AppendBd populate real internal buffers; downstream
     * Chilkat code reads those buffers and must see non-zero content. */

    /* CkGlobal */
    stub_alloc(ctx, "CkGlobal_Create",           h_ck_create);
    stub_alloc(ctx, "CkGlobal_Dispose",          h_ck_dispose);
    stub_alloc(ctx, "CkGlobal_UnlockBundle",     h_ck_ret1);

    /* CkEcc and CkPublicKey — ALL methods run natively (same as Python).
     * CkPublicKey_LoadBase64 must load the real ECC key so that
     * CkEcc_VerifyHashENC can actually verify (real credential data is valid). */
}
