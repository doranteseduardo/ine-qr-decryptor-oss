/* ══ FILE: emulator.c ══
 *
 * ARM64 Unicorn Engine harness for running the pc() JNI function.
 *
 * This module owns the full emulation lifecycle:
 *   - Virtual address space layout (stack, heap, TLS, stub area, data, return trap)
 *   - ELF loading via elf_loader.c
 *   - Stub registration (libc, Chilkat, JNI)
 *   - Chilkat license bypass (NOP patch + BSS flag)
 *   - Pre-injection of the buf2 plaintext derived by the static pipeline
 *   - AppendBinary2 code hook that redirects operand registers at two key
 *     offsets so the emulated code sees the already-decrypted buffers
 *   - Return-trap handler that decodes the base64 result string from X0
 *   - Full emulation start/stop and result capture
 *
 * The native pc() function at offset 0x1dcd40 implements crypto layers 3-7
 * (SIMD key derivation, AES, RSA#3-#4, SIMD, AES, RSA#5, ECC) using the
 * Chilkat library statically linked into libPersonalCode.so.
 */

#include "emulator.h"
#include "elf_loader.h"
#include "stub_dispatch.h"
#include "bump_heap.h"
#include "crypto_state.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unicorn/unicorn.h>
#include <unicorn/arm64.h>
#include <openssl/bn.h>

/* Forward declarations for stub registration */
void register_libc_stubs(INEContext *ctx);
void register_chilkat_stubs(INEContext *ctx);
void register_jni_stubs(INEContext *ctx);

/* ── Return trap ──
 * Called when emulated code branches to RETURN_ADDR (BRK #0).
 * Reads the base64 result string from X0, base64-decodes it into
 * ctx->result_data, then stops the emulator. */
static void h_return_trap(INEContext *ctx) {
    uint64_t x0;
    uc_reg_read((uc_engine *)ctx->uc, UC_ARM64_REG_X0, &x0);

    if (x0) {
        /* Read result — look for base64 null-terminated string */
        uint8_t tmp[131072];
        memset(tmp, 0, sizeof(tmp));
        if (uc_mem_read((uc_engine *)ctx->uc, x0, tmp, sizeof(tmp) - 1) == UC_ERR_OK) {
            /* Find null terminator */
            size_t null_pos = 0;
            for (null_pos = 0; null_pos < sizeof(tmp) - 1; null_pos++) {
                if (tmp[null_pos] == '\0') break;
            }
            if (null_pos > 0) {
                fprintf(stderr, "  [RETURN] pc() → %zu bytes\n", null_pos);

                /* Check if base64 */
                int is_b64 = 1;
                for (size_t i = 0; i < null_pos; i++) {
                    uint8_t c = tmp[i];
                    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                          (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=')) {
                        is_b64 = 0; break;
                    }
                }

                if (is_b64) {
                    /* Decode base64 */
                    size_t decoded_max = null_pos * 3 / 4 + 4;
                    uint8_t *decoded = malloc(decoded_max);
                    if (decoded) {
                        int dlen = base64_decode((const char *)tmp, decoded, (int)decoded_max);
                        if (dlen > 0) {
                            free(ctx->result_data);
                            ctx->result_data = decoded;
                            ctx->result_len  = (size_t)dlen;
                            fprintf(stderr, "  [RETURN] base64 decoded: %d bytes\n", dlen);
                        } else {
                            free(decoded);
                        }
                    }
                } else if (null_pos > 0 && !ctx->result_data) {
                    /* Not base64 — use raw */
                    ctx->result_data = malloc(null_pos + 1);
                    if (ctx->result_data) {
                        memcpy(ctx->result_data, tmp, null_pos + 1);
                        ctx->result_len = null_pos;
                    }
                }
            }
        }
    }
    ctx->emulation_done = 1;
    uc_emu_stop((uc_engine *)ctx->uc);
}

/* ── UC_HOOK_CODE for AppendBinary2 buffer redirects ── */

/* User data passed to the per-instruction code hook.
 * Carries the pre-computed buf2 plaintext so the hook can overwrite
 * the X1/X2 register pair before AppendBinary2 consumes them. */
typedef struct {
    INEContext *ctx;
    uint8_t    *decrypted_buf2;      /* heap-allocated plaintext of buf2    */
    size_t      decrypted_buf2_len;  /* byte length of decrypted_buf2       */
} CodeHookData;

/* Per-instruction hook scoped to [HOOK_RANGE_START, HOOK_RANGE_END].
 *
 * Intercepts two specific AppendBinary2 call sites inside pc() and
 * rewrites the (X1=data_ptr, X2=len) argument pair so the emulated
 * Chilkat CkBinData object receives already-decrypted content:
 *
 *   Offset 0x1dd250 (AppendBinary2[1]) — injects the statically
 *       pre-computed buf2 plaintext (RSA key #2 decrypt of QR bytes).
 *   Offset 0x1dd6e0 (AppendBinary2[3]) — performs RSA decrypt with
 *       key #4 on the stack buffer pointed to by X1/X2 and injects
 *       the result, bypassing the emulated RSA entirely.
 */
static void on_code(uc_engine *uc, uint64_t addr, uint32_t size, void *user_data) {
    (void)size;
    CodeHookData *d = (CodeHookData *)user_data;
    INEContext *ctx = d->ctx;

    uint64_t so_off = addr - BASE_ADDR;

    /* ── AppendBinary2[1] at offset 0x1dd250: inject decrypted buf2 ── */
    if (so_off == APPEND_BIN2_1_OFF && d->decrypted_buf2 && d->decrypted_buf2_len) {
        uint64_t inject_addr = DATA_ADDR + 0x2000;
        uint32_t inject_len  = (uint32_t)d->decrypted_buf2_len;
        uint64_t inject_len64 = (uint64_t)inject_len;
        uc_reg_write(uc, UC_ARM64_REG_X1, &inject_addr);
        uc_reg_write(uc, UC_ARM64_REG_X2, &inject_len64);
        if (ctx->verbose)
            fprintf(stderr, "     [REDIRECT] AppendBinary2[1] → decrypted buf2 (%zu bytes)\n",
                    d->decrypted_buf2_len);
        return;
    }

    /* ── AppendBinary2[3] at offset 0x1dd6e0: RSA decrypt stack buf with key #4 ── */
    if (so_off == APPEND_BIN2_3_OFF) {
        uint64_t x1; uint64_t w2_val;
        uc_reg_read(uc, UC_ARM64_REG_X1, &x1);
        uc_reg_read(uc, UC_ARM64_REG_X2, &w2_val);
        uint32_t w2 = (uint32_t)w2_val;

        if (!x1 || !w2 || ctx->rsa_key_count == 0) return;

        uint8_t *stack_buf = malloc(w2);
        if (!stack_buf) return;
        if (uc_mem_read(uc, x1, stack_buf, w2) != UC_ERR_OK) { free(stack_buf); return; }

        /* Use last imported RSA key (key #4) */
        RSAKeyEntry *ke = &ctx->rsa_keys[ctx->rsa_key_count - 1];

        BIGNUM *c_bn = BN_bin2bn(stack_buf, (int)w2, NULL);
        BIGNUM *m_bn = BN_new();
        free(stack_buf);

        BN_mod_exp(m_bn, c_bn, ke->e, ke->n, ctx->bn_ctx);
        BN_free(c_bn);

        uint8_t *raw = malloc((size_t)ke->key_bytes);
        memset(raw, 0, (size_t)ke->key_bytes);
        int mlen = BN_num_bytes(m_bn);
        BN_bn2bin(m_bn, raw + ke->key_bytes - mlen);
        BN_free(m_bn);

        /* Strip PKCS#1 v1.5 */
        if (raw[0] != 0x00 || (raw[1] != 0x01 && raw[1] != 0x02)) {
            fprintf(stderr, "     [!] AppendBinary2[3] PKCS#1 invalid [%02x %02x]\n",
                    raw[0], raw[1]);
            free(raw); return;
        }
        int sep = -1;
        for (int i = 2; i < ke->key_bytes; i++) {
            if (raw[i] == 0x00) { sep = i; break; }
        }
        if (sep < 0) { fprintf(stderr, "     [!] AppendBinary2[3] no null sep\n"); free(raw); return; }

        uint8_t *decrypted = raw + sep + 1;
        size_t dec_len = (size_t)(ke->key_bytes - sep - 1);

        uint64_t dec_addr = DATA_ADDR + 0x3000;
        uc_mem_write(uc, dec_addr, decrypted, dec_len);
        free(raw);

        uint64_t da = dec_addr;
        uint64_t dl = (uint64_t)dec_len;
        uc_reg_write(uc, UC_ARM64_REG_X1, &da);
        uc_reg_write(uc, UC_ARM64_REG_X2, &dl);

        if (ctx->verbose)
            fprintf(stderr, "     [REDIRECT] AppendBinary2[3] → RSA key4 decrypted (%zu bytes)\n",
                    dec_len);
    }
}

/* ── Context initialisation ── */

/* Zero-initialise an INEContext and set mandatory fields.
 * Must be called before emu_run().  so_data must remain valid for the
 * lifetime of the context since the ELF loader reads directly from it. */
void emu_context_init(INEContext *ctx, uint8_t *so_data, size_t so_size, int verbose) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->so_data = so_data;
    ctx->so_size = so_size;
    ctx->verbose = verbose;
    ctx->bn_ctx  = BN_CTX_new();
    ctx->heap.base = HEAP_ADDR;
    ctx->heap.size = HEAP_SIZE;
    ctx->heap.pos  = 0;
    ctx->tls_key_counter = 1;
}

/* ── Full emulation run ── */

/* Set up Unicorn, load the ELF, apply patches, install hooks, write the QR
 * payload, pre-inject decrypted buf2, then start pc() execution.
 *
 * combined     : concatenated QR payload (left[2:] + right[2:]), 1712 bytes
 * combined_len : byte count of combined
 * rsa_key2_xml : RSA public key #2 XML produced by the static pipeline;
 *                used to pre-compute the buf2 plaintext before emulation
 *
 * Returns 0 on success; ctx->result_data / ctx->result_len hold the output.
 * On failure ctx->result_data is NULL and -1 is returned. */
int emu_run(INEContext *ctx,
            const uint8_t *combined, size_t combined_len,
            const char *rsa_key2_xml) {
    uc_engine *uc = NULL;
    uc_err err;

    err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "[!] uc_open failed: %s\n", uc_strerror(err));
        return -1;
    }
    ctx->uc = uc;

    /* ── Map regions ── */
    uc_mem_map(uc, STACK_ADDR - STACK_SIZE, STACK_SIZE, UC_PROT_ALL);
    uc_mem_map(uc, HEAP_ADDR,  HEAP_SIZE,   UC_PROT_ALL);
    uc_mem_map(uc, TLS_ADDR,   TLS_SIZE,    UC_PROT_ALL);
    uc_mem_map(uc, STUB_AREA,  STUB_SIZE,   UC_PROT_ALL);
    uc_mem_map(uc, DATA_ADDR,  0x10000,     UC_PROT_ALL);
    uc_mem_map(uc, RETURN_ADDR, 0x1000,     UC_PROT_ALL);

    /* TLS: stack canary at offset 0x28 */
    uint64_t canary = 0xDEADBEEFCAFEBABEULL;
    uc_mem_write(uc, TLS_ADDR + 0x28, &canary, 8);
    uint64_t tls_base = TLS_ADDR;
    uc_reg_write(uc, UC_ARM64_REG_TPIDR_EL0, &tls_base);

    /* Return trap: BRK #0 */
    uint32_t brk0 = 0xD4200000u;
    uc_mem_write(uc, RETURN_ADDR, &brk0, 4);

    /* ── Register all stubs ── */
    /* Return trap slot must be first (slot 0) */
    stub_alloc(ctx, "__return_trap__", h_return_trap);
    /* Fix slot 0's address to RETURN_ADDR */
    ctx->stubs[0].addr = RETURN_ADDR;
    /* Update hash table for slot 0 */
    memset(ctx->stub_hash, 0, sizeof(ctx->stub_hash));
    uint32_t h0 = (uint32_t)((RETURN_ADDR >> 3) % STUB_HASH_SIZE);
    while (ctx->stub_hash[h0].key != 0) h0 = (h0 + 1) % STUB_HASH_SIZE;
    ctx->stub_hash[h0].key = RETURN_ADDR;
    ctx->stub_hash[h0].idx = 0;

    register_libc_stubs(ctx);
    register_chilkat_stubs(ctx);
    register_jni_stubs(ctx);

    /* ── Load ELF ── */
    if (elf_load(ctx) != 0) {
        uc_close(uc); return -1;
    }


    /* ── NOP patches ── */
    uint32_t nop_insn = 0xD503201Fu;
    uc_mem_write(uc, BASE_ADDR + NOP_PATCH_1, &nop_insn, 4);
    uc_mem_write(uc, BASE_ADDR + NOP_PATCH_2, &nop_insn, 4);
    fprintf(stderr, "[*] Patched: Chilkat license check bypassed\n");

    /* ── Set Chilkat global licensed flag (BSS at 0x472901) ──
     * Without this, all Chilkat class constructors take the "unlicensed" code
     * path which calls pthread_mutex_init on an uninitialized mutex, leading
     * to null function pointer crashes in the emulator.  Matches the effect of
     * CkGlobal_UnlockBundle("ANEMNA.CB4032026_ciuicL5Fndll") running natively. */
    uint8_t ck_licensed = 1;
    uc_mem_write(uc, BASE_ADDR + 0x472901, &ck_licensed, 1);

    /* ── Write QR payload ── */
    uc_mem_write(uc, DATA_ADDR, combined, combined_len);
    fprintf(stderr, "[*] Payload: %zu bytes at 0x%llx\n",
            combined_len, (unsigned long long)DATA_ADDR);

    /* ── Pre-compute decrypted buf2 and inject ── */
    CodeHookData code_hook_data;
    code_hook_data.ctx = ctx;
    code_hook_data.decrypted_buf2 = NULL;
    code_hook_data.decrypted_buf2_len = 0;

    if (rsa_key2_xml && rsa_key2_xml[0]) {
        size_t buf2_len;
        uint8_t *buf2 = precompute_buf2(rsa_key2_xml, combined, combined_len, &buf2_len);
        if (buf2) {
            uint64_t inject_addr = DATA_ADDR + 0x2000;
            uc_mem_write(uc, inject_addr, buf2, buf2_len);
            code_hook_data.decrypted_buf2     = buf2;
            code_hook_data.decrypted_buf2_len = buf2_len;
            fprintf(stderr, "[*] Decrypted buf2 at 0x%llx (%zu bytes)\n",
                    (unsigned long long)inject_addr, buf2_len);
        }
    }

    /* ── Hooks ── */
    uc_hook h_intr = 0, h_mem = 0, h_code = 0;
    uc_hook_add(uc, &h_intr, UC_HOOK_INTR, stub_on_interrupt, ctx, 1, 0);
    uc_hook_add(uc, &h_mem, UC_HOOK_MEM_UNMAPPED,
                stub_on_unmapped, ctx, 1, 0);
    /* Code hook scoped to pc() range for AppendBinary2 redirects */
    uc_hook_add(uc, &h_code, UC_HOOK_CODE, on_code, &code_hook_data,
                BASE_ADDR + HOOK_RANGE_START,
                BASE_ADDR + HOOK_RANGE_END);

    /* ── Set up pc() call ── */
    uint64_t pc_func = BASE_ADDR + PC_FUNC_OFFSET;
    uint64_t sp      = STACK_ADDR - 0x1000;
    uint64_t zero    = 0;
    uint64_t data_a  = DATA_ADDR;
    uint64_t len_w   = (uint64_t)combined_len;
    uint64_t magic   = 0x309ULL;
    uint64_t ret_a   = RETURN_ADDR;

    uc_reg_write(uc, UC_ARM64_REG_SP, &sp);
    uc_reg_write(uc, UC_ARM64_REG_X0, &zero);    /* env */
    uc_reg_write(uc, UC_ARM64_REG_X1, &zero);    /* thiz */
    uc_reg_write(uc, UC_ARM64_REG_X2, &zero);    /* activity */
    uc_reg_write(uc, UC_ARM64_REG_X3, &data_a);  /* data */
    uc_reg_write(uc, UC_ARM64_REG_X4, &len_w);   /* length */
    uc_reg_write(uc, UC_ARM64_REG_X5, &magic);   /* magic = 0x309 */
    uc_reg_write(uc, UC_ARM64_REG_LR, &ret_a);

    fprintf(stderr, "\n[*] Starting pc() at 0x%llx...\n",
            (unsigned long long)pc_func);

    err = uc_emu_start(uc, pc_func, RETURN_ADDR + 4, 120000000 /* 2 min */, 0);
    if (err != UC_ERR_OK && !ctx->emulation_done) {
        uint64_t pc_val;
        uc_reg_read(uc, UC_ARM64_REG_PC, &pc_val);
        fprintf(stderr, "[!] uc_emu_start error: %s at PC=0x%llx\n",
                uc_strerror(err), (unsigned long long)pc_val);
    }

    if (code_hook_data.decrypted_buf2)
        free(code_hook_data.decrypted_buf2);

    uc_close(uc);
    ctx->uc = NULL;

    if (!ctx->result_data) {
        fprintf(stderr, "[!] No result captured\n");
        return -1;
    }
    fprintf(stderr, "[*] Emulation done, result: %zu bytes\n", ctx->result_len);
    return 0;
}
