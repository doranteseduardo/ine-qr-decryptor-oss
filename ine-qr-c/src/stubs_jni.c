/* ══ FILE: stubs_jni.c ══
 *
 * Host-side stubs for Android JNI helper functions and internal utility
 * functions used by libPersonalCode.so.
 *
 * The native library uses a thin JNI helper layer (_JNIEnv::Call*Method,
 * showToast, jstr2str, strConcat, …) that bridges between C++ and the
 * Android Java runtime.  In the emulator sandbox there is no JVM, so:
 *
 *   - Most JNI call wrappers (_ZN7_JNIEnv…) are no-ops returning 0.
 *   - isSafeEnvironment() and hR() always return 1 (emulation is "safe").
 *   - updateCtr() is a no-op (network call counter, not needed offline).
 *   - strConcat is re-implemented on the host to support path construction
 *     inside the native code.
 *   - newJStringFromBytes is the critical intercept: it captures the final
 *     decrypted biographical text into ctx->result_data so the return trap
 *     can pick it up.
 *
 * register_jni_stubs() must be called before elf_load().
 */

#include "stub_dispatch.h"
#include "bump_heap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unicorn/unicorn.h>
#include <unicorn/arm64.h>

/* Read a 64-bit register from the Unicorn engine. */
static inline uint64_t x(INEContext *ctx, int reg) {
    uint64_t v = 0; uc_reg_read((uc_engine *)ctx->uc, reg, &v); return v;
}
/* Read a 32-bit register (lower word). */
static inline uint32_t w(INEContext *ctx, int reg) {
    uint64_t v = 0; uc_reg_read((uc_engine *)ctx->uc, reg, &v); return (uint32_t)v;
}

static void h_nop_ret0(INEContext *ctx) { stub_ret(ctx, 0); }
static void h_nop(INEContext *ctx) {
    uint64_t lr; uc_reg_read((uc_engine *)ctx->uc, UC_ARM64_REG_LR, &lr);
    uc_reg_write((uc_engine *)ctx->uc, UC_ARM64_REG_PC, &lr);
}

/* ── Internal overrides ── */

/* isSafeEnvironment(): the .so checks for root/frida/debugger at startup.
 * Always return 1 so the crypto pipeline proceeds without abort. */
static void h_is_safe_env(INEContext *ctx) {
    if (ctx->verbose)
        fprintf(stderr, "  >> isSafeEnvironment → 1\n");
    stub_ret(ctx, 1);
}

/* hR(): secondary environment / integrity check.  Always return 1. */
static void h_hr(INEContext *ctx) {
    if (ctx->verbose)
        fprintf(stderr, "  >> hR → 1\n");
    stub_ret(ctx, 1);
}

/* updateCtr(): sends a network usage counter to the INE backend.
 * Silently skipped — all network stubs return errors. */
static void h_update_ctr(INEContext *ctx) {
    if (ctx->verbose)
        fprintf(stderr, "  >> updateCtr → (nop)\n");
    uint64_t lr; uc_reg_read((uc_engine *)ctx->uc, UC_ARM64_REG_LR, &lr);
    uc_reg_write((uc_engine *)ctx->uc, UC_ARM64_REG_PC, &lr);
}

/* _Z9strConcatPKcS0_ — strConcat(s1, s2): read two emulated strings from
 * X0/X1, concatenate them on the host, write the result to the bump heap,
 * and return its emulated address.  Used internally by the .so to build
 * composite string values during the decryption output phase. */
static void h_str_concat(INEContext *ctx) {
    char s1[4096] = {0}, s2[4096] = {0};
    int len1 = 0, len2 = 0;
    uint64_t p1 = x(ctx, UC_ARM64_REG_X0);
    uint64_t p2 = x(ctx, UC_ARM64_REG_X1);
    if (p1) {
        for (int i = 0; i < 4095; i++) {
            uint8_t c;
            if (uc_mem_read((uc_engine *)ctx->uc, p1 + (uint64_t)i, &c, 1) != UC_ERR_OK) break;
            s1[i] = (char)c; len1 = i + 1;
            if (!c) { len1 = i; break; }
        }
    }
    if (p2) {
        for (int i = 0; i < 4095; i++) {
            uint8_t c;
            if (uc_mem_read((uc_engine *)ctx->uc, p2 + (uint64_t)i, &c, 1) != UC_ERR_OK) break;
            s2[i] = (char)c; len2 = i + 1;
            if (!c) { len2 = i; break; }
        }
    }
    size_t total = (size_t)(len1 + len2);
    char *concat = malloc(total + 1);
    if (!concat) { stub_ret(ctx, 0); return; }
    memcpy(concat, s1, (size_t)len1);
    memcpy(concat + len1, s2, (size_t)len2);
    concat[total] = '\0';
    uint64_t ptr = bump_write(ctx, concat, total);
    free(concat);
    stub_ret(ctx, ptr);
}

/* _Z19newJStringFromBytesP7_JNIEnvPai — newJStringFromBytes(env, data, len).
 *
 * This is the key extraction point: the native pc() function calls this
 * helper to wrap the fully-decrypted biographical byte array into a Java
 * String just before it would return to the JVM.  We intercept it here,
 * copy the data into ctx->result_data, and return the original pointer so
 * any downstream code sees a valid (emulated) string address.
 *
 * X1 = pointer to byte array in emulated memory
 * W2 = byte count */
static void h_new_jstring_from_bytes(INEContext *ctx) {
    uint64_t data_ptr = x(ctx, UC_ARM64_REG_X1);
    uint32_t length   = w(ctx, UC_ARM64_REG_W2);

    if (data_ptr && length > 0 && length < 0x100000) {
        uint8_t *data = malloc((size_t)length + 1);
        if (data) {
            uc_mem_read((uc_engine *)ctx->uc, data_ptr, data, length);
            data[length] = '\0';
            if (ctx->verbose) {
                fprintf(stderr, "  >> newJStringFromBytes: %u bytes\n", length);
                if (length < 500) fprintf(stderr, "     %s\n", (char *)data);
                else fprintf(stderr, "     %.300s...\n", (char *)data);
            }
            free(ctx->result_data);
            ctx->result_data = data;
            ctx->result_len  = (size_t)length;
        }
        stub_ret(ctx, data_ptr);
    } else {
        if (ctx->verbose)
            fprintf(stderr, "  >> newJStringFromBytes: empty (ptr=0x%llx, len=%u)\n",
                    (unsigned long long)data_ptr, length);
        stub_ret(ctx, 0);
    }
}

/* ── Bulk registration ── */

/* Register all JNI and internal-override stubs.
 * isSafeEnvironment and hR must come first so that the security checks at
 * the start of pc() short-circuit before reaching any crypto logic. */
void register_jni_stubs(INEContext *ctx) {
    /* Internal overrides */
    stub_alloc(ctx, "isSafeEnvironment", h_is_safe_env);
    stub_alloc(ctx, "hR",                h_hr);
    stub_alloc(ctx, "updateCtr",         h_update_ctr);

    /* JNI helpers */
    stub_alloc(ctx, "_ZN7_JNIEnv22CallStaticObjectMethodEP7_jclassP10_jmethodIDz",  h_nop_ret0);
    stub_alloc(ctx, "_Z9showToastP7_JNIEnvP8_jobjectNSt6__ndk112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE", h_nop);
    stub_alloc(ctx, "_ZN7_JNIEnv20CallStaticVoidMethodEP7_jclassP10_jmethodIDz",    h_nop);
    stub_alloc(ctx, "_ZN7_JNIEnv14CallVoidMethodEP8_jobjectP10_jmethodIDz",         h_nop);
    stub_alloc(ctx, "_Z9strConcatPKcS0_",                                           h_str_concat);
    stub_alloc(ctx, "_Z8jstr2strP7_JNIEnvP8_jstring",                              h_nop_ret0);
    stub_alloc(ctx, "_Z9jstrSplitP7_JNIEnvP8_jstringS2_",                          h_nop_ret0);
    stub_alloc(ctx, "_ZN7_JNIEnv16CallObjectMethodEP8_jobjectP10_jmethodIDz",       h_nop_ret0);
    stub_alloc(ctx, "_ZN7_JNIEnv19CallStaticIntMethodEP7_jclassP10_jmethodIDz",     h_nop_ret0);
    stub_alloc(ctx, "_Z13str2LowerCaseP7_JNIEnvRKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE", h_nop_ret0);
    stub_alloc(ctx, "_Z13str2UpperCaseP7_JNIEnvRKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE", h_nop_ret0);
    stub_alloc(ctx, "_Z8strSplitP7_JNIEnvRKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES9_",    h_nop_ret0);
    stub_alloc(ctx, "_Z19newJStringFromBytesP7_JNIEnvPai",                          h_new_jstring_from_bytes);
    stub_alloc(ctx, "_ZN7_JNIEnv9NewObjectEP7_jclassP10_jmethodIDz",               h_nop_ret0);
    stub_alloc(ctx, "_Z10strReplaceP7_JNIEnvRKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES9_S9_", h_nop_ret0);
    stub_alloc(ctx, "_Z7str2IntP7_JNIEnvNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE", h_nop_ret0);
}
