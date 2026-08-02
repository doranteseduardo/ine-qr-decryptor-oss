/* ══ FILE: stubs_libc.c ══
 *
 * Host-side implementations of C/C++ standard library functions called by
 * the emulated ARM64 libPersonalCode.so.
 *
 * The .so is compiled for Android (Bionic libc) and dynamically links
 * malloc, free, string ops, pthreads, time functions, sockets, locale
 * functions, and C++ operators.  None of these are present in the Unicorn
 * sandbox, so every external reference is replaced by a stub that:
 *   - Reads arguments from ARM64 registers X0-X7 / W0-W7.
 *   - Performs equivalent logic on the host side (using the real glibc/libSystem).
 *   - Returns results via stub_ret() (sets X0, jumps to LR).
 *
 * Memory stubs forward to the bump_heap allocator.
 * pthread stubs are no-ops (single-threaded emulation).
 * Network and file-I/O stubs return errors (-1 or 0) — the crypto pipeline
 * does not actually open files or sockets at runtime.
 *
 * register_libc_stubs() must be called before elf_load() so that the
 * relocation pass can find these symbols when filling the PLT.
 */

#include "stub_dispatch.h"
#include "bump_heap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unicorn/unicorn.h>
#include <unicorn/arm64.h>

/* ── Register read helpers ── */

/* Read a 64-bit ARM64 register from the Unicorn engine. */
static inline uint64_t x(INEContext *ctx, int reg) {
    uint64_t v = 0; uc_reg_read((uc_engine *)ctx->uc, reg, &v); return v;
}
/* Read a 32-bit ARM64 register (lower word of a 64-bit reg). */
static inline uint32_t w(INEContext *ctx, int reg) {
    uint64_t v = 0; uc_reg_read((uc_engine *)ctx->uc, reg, &v); return (uint32_t)v;
}

/* ── String helpers ── */

/* Read a null-terminated string from emulated memory at addr into host buf.
 * Reads at most max-1 characters and always null-terminates buf.
 * Returns the number of characters read (excluding the null terminator). */
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

/* ── Memory handlers ── */

/* malloc(size) → bump_alloc(X0). */
void h_malloc(INEContext *ctx) {
    uint64_t sz = x(ctx, UC_ARM64_REG_X0);
    stub_ret(ctx, bump_alloc(ctx, sz));
}
void h_free(INEContext *ctx)    { stub_ret(ctx, 0); }
void h_new(INEContext *ctx)     { h_malloc(ctx); }
void h_delete(INEContext *ctx)  { stub_ret(ctx, 0); }

void h_realloc(INEContext *ctx) {
    uint64_t old_ptr  = x(ctx, UC_ARM64_REG_X0);
    uint64_t new_size = x(ctx, UC_ARM64_REG_X1);
    stub_ret(ctx, bump_realloc(ctx, old_ptr, new_size));
}

/* calloc(nmemb, size): allocate nmemb*size bytes and zero-fill the region.
 * Zeroing is done in 256-byte chunks via uc_mem_write to handle large blocks. */
void h_calloc(INEContext *ctx) {
    uint64_t n    = x(ctx, UC_ARM64_REG_X0);
    uint64_t size = x(ctx, UC_ARM64_REG_X1);
    uint64_t total = n * size;
    uint64_t ptr = bump_alloc(ctx, total);
    if (ptr) {
        /* Zero the region */
        uint8_t zero[256];
        memset(zero, 0, sizeof(zero));
        uint64_t remaining = total;
        uint64_t off = 0;
        while (remaining > 0) {
            uint64_t chunk = remaining < 256 ? remaining : 256;
            uc_mem_write((uc_engine *)ctx->uc, ptr + off, zero, (size_t)chunk);
            off += chunk; remaining -= chunk;
        }
    }
    stub_ret(ctx, ptr);
}

/* posix_memalign(memptr, align, size): allocate size bytes with given
 * alignment and store the result pointer at *memptr.  Returns 0 on success. */
void h_posix_memalign(INEContext *ctx) {
    uint64_t memptr   = x(ctx, UC_ARM64_REG_X0);
    uint64_t align    = x(ctx, UC_ARM64_REG_X1);
    uint64_t size     = x(ctx, UC_ARM64_REG_X2);
    if (align == 0) align = 16;
    uint64_t ptr = bump_alloc(ctx, size + align);
    ptr = (ptr + align - 1) & ~(align - 1);
    uc_mem_write((uc_engine *)ctx->uc, memptr, &ptr, 8);
    stub_ret(ctx, 0);
}

/* memcpy(dst, src, n): copy n bytes between emulated memory regions.
 * Uses a host-side temporary buffer to bridge the uc_mem_read/write gap. */
void h_memcpy(INEContext *ctx) {
    uint64_t dst = x(ctx, UC_ARM64_REG_X0);
    uint64_t src = x(ctx, UC_ARM64_REG_X1);
    uint32_t n   = w(ctx, UC_ARM64_REG_X2);
    if (n > 0 && n < (uint32_t)HEAP_SIZE) {
        uint8_t *tmp = malloc(n);
        if (tmp) {
            uc_mem_read((uc_engine *)ctx->uc, src, tmp, n);
            uc_mem_write((uc_engine *)ctx->uc, dst, tmp, n);
            free(tmp);
        }
    }
    stub_ret(ctx, dst);
}

void h_memmove(INEContext *ctx) { h_memcpy(ctx); }

/* memset(dst, val, n): fill n bytes at emulated dst with val. */
void h_memset(INEContext *ctx) {
    uint64_t dst = x(ctx, UC_ARM64_REG_X0);
    uint8_t  val = (uint8_t)w(ctx, UC_ARM64_REG_W1);
    uint32_t n   = w(ctx, UC_ARM64_REG_X2);
    if (n > 0 && n < (uint32_t)HEAP_SIZE) {
        uint8_t *tmp = malloc(n);
        if (tmp) {
            memset(tmp, val, n);
            uc_mem_write((uc_engine *)ctx->uc, dst, tmp, n);
            free(tmp);
        }
    }
    stub_ret(ctx, dst);
}

/* memcmp(a, b, n): compare n bytes between two emulated memory regions.
 * Capped at 64 KB to avoid runaway allocations on bad inputs. */
void h_memcmp(INEContext *ctx) {
    uint64_t a = x(ctx, UC_ARM64_REG_X0);
    uint64_t b = x(ctx, UC_ARM64_REG_X1);
    uint32_t n = w(ctx, UC_ARM64_REG_X2);
    if (n == 0) { stub_ret(ctx, 0); return; }
    if (n > 65536) n = 65536;
    uint8_t *ba = malloc(n), *bb = malloc(n);
    uc_mem_read((uc_engine *)ctx->uc, a, ba, n);
    uc_mem_read((uc_engine *)ctx->uc, b, bb, n);
    int r = memcmp(ba, bb, n);
    free(ba); free(bb);
    stub_ret(ctx, (uint64_t)(int64_t)r);
}

/* memchr(s, c, n): search n bytes at emulated address s for byte c.
 * Returns emulated pointer to first match or 0 (NULL). */
void h_memchr(INEContext *ctx) {
    uint64_t s = x(ctx, UC_ARM64_REG_X0);
    uint8_t  c = (uint8_t)w(ctx, UC_ARM64_REG_W1);
    uint32_t n = w(ctx, UC_ARM64_REG_X2);
    if (n > 65536) n = 65536;
    uint8_t *buf = malloc(n);
    uc_mem_read((uc_engine *)ctx->uc, s, buf, n);
    uint8_t *found = (uint8_t *)memchr(buf, c, n);
    uint64_t result = found ? s + (uint64_t)(found - buf) : 0;
    free(buf);
    stub_ret(ctx, result);
}

/* ── String handlers ── */

void h_strlen(INEContext *ctx) {
    char buf[65536]; buf[0]='\0';
    emu_read_str(ctx, x(ctx, UC_ARM64_REG_X0), buf, sizeof(buf));
    stub_ret(ctx, strlen(buf));
}

void h_strchr(INEContext *ctx) {
    uint64_t saddr = x(ctx, UC_ARM64_REG_X0);
    uint8_t  c     = (uint8_t)w(ctx, UC_ARM64_REG_W1);
    char buf[8192]; emu_read_str(ctx, saddr, buf, sizeof(buf));
    char *p = (char *)memchr(buf, c, strlen(buf) + 1);
    stub_ret(ctx, p ? saddr + (uint64_t)(p - buf) : 0);
}

void h_strcmp(INEContext *ctx) {
    char a[4096], b[4096];
    emu_read_str(ctx, x(ctx, UC_ARM64_REG_X0), a, sizeof(a));
    emu_read_str(ctx, x(ctx, UC_ARM64_REG_X1), b, sizeof(b));
    stub_ret(ctx, (uint64_t)(int64_t)strcmp(a, b));
}

void h_strncmp(INEContext *ctx) {
    char a[4096], b[4096];
    uint32_t n = w(ctx, UC_ARM64_REG_X2);
    if (n > 4095) n = 4095;
    emu_read_str(ctx, x(ctx, UC_ARM64_REG_X0), a, (int)n + 1);
    emu_read_str(ctx, x(ctx, UC_ARM64_REG_X1), b, (int)n + 1);
    stub_ret(ctx, (uint64_t)(int64_t)strncmp(a, b, n));
}

void h_strcasecmp(INEContext *ctx) {
    char a[4096], b[4096];
    emu_read_str(ctx, x(ctx, UC_ARM64_REG_X0), a, sizeof(a));
    emu_read_str(ctx, x(ctx, UC_ARM64_REG_X1), b, sizeof(b));
    stub_ret(ctx, (uint64_t)(int64_t)strcasecmp(a, b));
}

void h_strncasecmp(INEContext *ctx) {
    char a[4096], b[4096];
    uint32_t n = w(ctx, UC_ARM64_REG_X2);
    if (n > 4095) n = 4095;
    emu_read_str(ctx, x(ctx, UC_ARM64_REG_X0), a, (int)n + 1);
    emu_read_str(ctx, x(ctx, UC_ARM64_REG_X1), b, (int)n + 1);
    stub_ret(ctx, (uint64_t)(int64_t)strncasecmp(a, b, n));
}

void h_strstr(INEContext *ctx) {
    uint64_t haddr = x(ctx, UC_ARM64_REG_X0);
    char h[8192], n[4096];
    emu_read_str(ctx, haddr, h, sizeof(h));
    emu_read_str(ctx, x(ctx, UC_ARM64_REG_X1), n, sizeof(n));
    char *p = strstr(h, n);
    stub_ret(ctx, p ? haddr + (uint64_t)(p - h) : 0);
}

void h_strtol(INEContext *ctx) {
    char buf[64]; emu_read_str(ctx, x(ctx, UC_ARM64_REG_X0), buf, sizeof(buf));
    stub_ret(ctx, (uint64_t)(int64_t)strtol(buf, NULL, 0));
}

void h_strtoul(INEContext *ctx) {
    char buf[64]; emu_read_str(ctx, x(ctx, UC_ARM64_REG_X0), buf, sizeof(buf));
    stub_ret(ctx, (uint64_t)strtoul(buf, NULL, 0));
}

void h_atoi(INEContext *ctx) {
    char buf[64]; emu_read_str(ctx, x(ctx, UC_ARM64_REG_X0), buf, sizeof(buf));
    stub_ret(ctx, (uint64_t)(int64_t)atoi(buf));
}

void h_atof(INEContext *ctx) { stub_ret(ctx, 0); }

void h_tolower(INEContext *ctx) {
    uint32_t c = w(ctx, UC_ARM64_REG_W0) & 0xFF;
    stub_ret(ctx, (c >= 'A' && c <= 'Z') ? c + 32 : c);
}

void h_toupper(INEContext *ctx) {
    uint32_t c = w(ctx, UC_ARM64_REG_W0) & 0xFF;
    stub_ret(ctx, (c >= 'a' && c <= 'z') ? c - 32 : c);
}

void h_isalnum(INEContext *ctx) {
    uint32_t c = w(ctx, UC_ARM64_REG_W0) & 0xFF;
    stub_ret(ctx, (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
                  (c >= 'a' && c <= 'z') ? 1 : 0);
}

/* ── I/O (no-op stubs) ── */

void h_snprintf(INEContext *ctx)  { stub_ret(ctx, 0); }
void h_sscanf(INEContext *ctx)    { stub_ret(ctx, 0); }
void h_fprintf(INEContext *ctx)   { stub_ret(ctx, 0); }
void h_fwrite(INEContext *ctx)    { stub_ret(ctx, 0); }

/* ── Time ── */

void h_time(INEContext *ctx) {
    time_t t = time(NULL);
    uint64_t ptr = x(ctx, UC_ARM64_REG_X0);
    if (ptr) {
        int64_t tv = (int64_t)t;
        uc_mem_write((uc_engine *)ctx->uc, ptr, &tv, 8);
    }
    stub_ret(ctx, (uint64_t)(int64_t)t);
}

void h_gettimeofday(INEContext *ctx) {
    uint64_t tv_ptr = x(ctx, UC_ARM64_REG_X0);
    if (tv_ptr) {
        struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
        int64_t sec  = (int64_t)ts.tv_sec;
        int64_t usec = (int64_t)(ts.tv_nsec / 1000);
        uc_mem_write((uc_engine *)ctx->uc, tv_ptr,     &sec,  8);
        uc_mem_write((uc_engine *)ctx->uc, tv_ptr + 8, &usec, 8);
    }
    stub_ret(ctx, 0);
}

void h_gmtime_r(INEContext *ctx) {
    uint64_t tm_ptr = x(ctx, UC_ARM64_REG_X1);
    if (tm_ptr) {
        time_t now = time(NULL);
        struct tm tm_val;
        gmtime_r(&now, &tm_val);
        int32_t tm_fields[9] = {
            tm_val.tm_sec, tm_val.tm_min,  tm_val.tm_hour,
            tm_val.tm_mday, tm_val.tm_mon, tm_val.tm_year,
            tm_val.tm_wday, tm_val.tm_yday, tm_val.tm_isdst
        };
        uc_mem_write((uc_engine *)ctx->uc, tm_ptr, tm_fields, sizeof(tm_fields));
    }
    stub_ret(ctx, tm_ptr);
}

void h_localtime_r(INEContext *ctx) { h_gmtime_r(ctx); }

void h_mktime(INEContext *ctx) {
    stub_ret(ctx, (uint64_t)(int64_t)time(NULL));
}

/* ── Threads (fake single-threaded) ── */

/* Generic no-op: jump directly to LR without touching X0.
 * Used for void functions that the pipeline does not need to observe. */
void h_nop(INEContext *ctx) {
    uint64_t lr; uc_reg_read((uc_engine *)ctx->uc, UC_ARM64_REG_LR, &lr);
    uc_reg_write((uc_engine *)ctx->uc, UC_ARM64_REG_PC, &lr);
}
void h_nop_ret0(INEContext *ctx)  { stub_ret(ctx, 0); }
void h_ret1(INEContext *ctx)      { stub_ret(ctx, 1); }
void h_ret_neg1(INEContext *ctx)  { stub_ret(ctx, (uint64_t)-1LL); }

/* pthread_once: execute the init function only if the once_control flag is 0.
 * In single-threaded emulation the init function is not actually called here;
 * only the flag is set.  This prevents repeated Chilkat global init paths. */
void h_pthread_once(INEContext *ctx) {
    uint64_t once_ptr = x(ctx, UC_ARM64_REG_X0);
    if (once_ptr) {
        uint32_t val = 0;
        uc_mem_read((uc_engine *)ctx->uc, once_ptr, &val, 4);
        if (val == 0) {
            val = 1;
            uc_mem_write((uc_engine *)ctx->uc, once_ptr, &val, 4);
        }
    }
    stub_ret(ctx, 0);
}

/* pthread_key_create: allocate a fake TLS key ID from the context counter
 * and write it to the key pointer.  The key is used by Chilkat thread-local
 * storage for per-thread object caches. */
void h_pthread_key_create(INEContext *ctx) {
    uint64_t key_ptr = x(ctx, UC_ARM64_REG_X0);
    uint32_t key_id  = (uint32_t)ctx->tls_key_counter++;
    if (key_ptr)
        uc_mem_write((uc_engine *)ctx->uc, key_ptr, &key_id, 4);
    stub_ret(ctx, 0);
}

/* pthread_getspecific: return the TLS value stored for key in ctx->tls_vals[]. */
void h_pthread_getspecific(INEContext *ctx) {
    uint32_t key = w(ctx, UC_ARM64_REG_W0);
    uint64_t val = (key < 64) ? ctx->tls_vals[key] : 0;
    stub_ret(ctx, val);
}

/* pthread_setspecific: store val into ctx->tls_vals[key] (up to 64 keys). */
void h_pthread_setspecific(INEContext *ctx) {
    uint32_t key = w(ctx, UC_ARM64_REG_W0);
    uint64_t val = x(ctx, UC_ARM64_REG_X1);
    if (key < 64) ctx->tls_vals[key] = val;
    stub_ret(ctx, 0);
}

/* ── System ── */

/* __stack_chk_fail: the emulated stack canary was overwritten.
 * Print a diagnostic and halt emulation immediately. */
void h_stack_chk_fail(INEContext *ctx) {
    fprintf(stderr, "[!] __stack_chk_fail: stack canary corrupt!\n");
    uc_emu_stop((uc_engine *)ctx->uc);
}

/* __errno: return a pointer into the TLS area used as the emulated errno cell. */
void h_errno_fn(INEContext *ctx) {
    stub_ret(ctx, TLS_ADDR + 0x100);
}

/* __assert2(file, line, func, expr): print the assertion details and stop
 * emulation.  Mirrors Android Bionic's __assert2 signature. */
void h_assert2(INEContext *ctx) {
    char file[256], func[256], expr[256];
    emu_read_str(ctx, x(ctx, UC_ARM64_REG_X0), file, sizeof(file));
    uint32_t line = w(ctx, UC_ARM64_REG_W1);
    emu_read_str(ctx, x(ctx, UC_ARM64_REG_X2), func, sizeof(func));
    emu_read_str(ctx, x(ctx, UC_ARM64_REG_X3), expr, sizeof(expr));
    fprintf(stderr, "[!] ASSERT FAILED: %s at %s:%u (%s)\n", expr, file, line, func);
    uc_emu_stop((uc_engine *)ctx->uc);
}

void h_abort(INEContext *ctx) {
    fprintf(stderr, "[!] abort() called\n");
    uc_emu_stop((uc_engine *)ctx->uc);
}

void h_strerror(INEContext *ctx) {
    static const char *msg = "Unknown error";
    uint64_t ptr = bump_strdup(ctx, msg);
    stub_ret(ctx, ptr);
}

/* ── Bulk registration of all libc stubs ── */

/* Register every C/C++ standard library stub into the dispatch table.
 * Must be called once, before elf_load(), so that relocation resolution
 * can find these symbols.  Symbols are grouped by category: memory,
 * string, I/O, time, pthreads, file I/O, network, system, locale,
 * wide-char, FD/semaphore, and miscellaneous numeric conversions. */
void register_libc_stubs(INEContext *ctx) {
    /* Memory */
    stub_alloc(ctx, "malloc",          h_malloc);
    stub_alloc(ctx, "free",            h_free);
    stub_alloc(ctx, "realloc",         h_realloc);
    stub_alloc(ctx, "calloc",          h_calloc);
    stub_alloc(ctx, "posix_memalign",  h_posix_memalign);
    stub_alloc(ctx, "memcpy",          h_memcpy);
    stub_alloc(ctx, "memmove",         h_memmove);
    stub_alloc(ctx, "memset",          h_memset);
    stub_alloc(ctx, "memcmp",          h_memcmp);
    stub_alloc(ctx, "memchr",          h_memchr);
    stub_alloc(ctx, "_Znwm",           h_malloc);  /* operator new */
    stub_alloc(ctx, "_Znam",           h_malloc);  /* operator new[] */
    stub_alloc(ctx, "_ZdlPv",          h_free);    /* operator delete */
    stub_alloc(ctx, "_ZdaPv",          h_free);    /* operator delete[] */
    stub_alloc(ctx, "_ZdlPvm",         h_free);
    stub_alloc(ctx, "_ZdaPvm",         h_free);

    /* String */
    stub_alloc(ctx, "strlen",          h_strlen);
    stub_alloc(ctx, "strchr",          h_strchr);
    stub_alloc(ctx, "strcmp",          h_strcmp);
    stub_alloc(ctx, "strncmp",         h_strncmp);
    stub_alloc(ctx, "strcasecmp",      h_strcasecmp);
    stub_alloc(ctx, "strncasecmp",     h_strncasecmp);
    stub_alloc(ctx, "strstr",          h_strstr);
    stub_alloc(ctx, "strtol",          h_strtol);
    stub_alloc(ctx, "strtoul",         h_strtoul);
    stub_alloc(ctx, "atoi",            h_atoi);
    stub_alloc(ctx, "atof",            h_atof);
    stub_alloc(ctx, "tolower",         h_tolower);
    stub_alloc(ctx, "toupper",         h_toupper);
    stub_alloc(ctx, "isalnum",         h_isalnum);

    /* I/O */
    stub_alloc(ctx, "snprintf",        h_snprintf);
    stub_alloc(ctx, "sscanf",          h_sscanf);
    stub_alloc(ctx, "fprintf",         h_fprintf);
    stub_alloc(ctx, "fwrite",          h_fwrite);

    /* Time */
    stub_alloc(ctx, "time",            h_time);
    stub_alloc(ctx, "gettimeofday",    h_gettimeofday);
    stub_alloc(ctx, "gmtime_r",        h_gmtime_r);
    stub_alloc(ctx, "localtime_r",     h_localtime_r);
    stub_alloc(ctx, "mktime",          h_mktime);
    stub_alloc(ctx, "tzset",           h_nop);
    stub_alloc(ctx, "srand",           h_nop);

    /* Threads */
    stub_alloc(ctx, "pthread_mutex_init",          h_nop_ret0);
    stub_alloc(ctx, "pthread_mutex_destroy",       h_nop_ret0);
    stub_alloc(ctx, "pthread_mutex_lock",          h_nop_ret0);
    stub_alloc(ctx, "pthread_mutex_unlock",        h_nop_ret0);
    stub_alloc(ctx, "pthread_mutexattr_init",      h_nop_ret0);
    stub_alloc(ctx, "pthread_mutexattr_destroy",   h_nop_ret0);
    stub_alloc(ctx, "pthread_mutexattr_settype",   h_nop_ret0);
    stub_alloc(ctx, "pthread_once",                h_pthread_once);
    stub_alloc(ctx, "pthread_key_create",          h_pthread_key_create);
    stub_alloc(ctx, "pthread_getspecific",         h_pthread_getspecific);
    stub_alloc(ctx, "pthread_setspecific",         h_pthread_setspecific);
    stub_alloc(ctx, "pthread_key_delete",          h_nop_ret0);
    stub_alloc(ctx, "pthread_cond_broadcast",      h_nop_ret0);
    stub_alloc(ctx, "pthread_cond_wait",           h_nop_ret0);
    stub_alloc(ctx, "pthread_create",              h_nop_ret0);
    stub_alloc(ctx, "pthread_exit",                h_nop);
    stub_alloc(ctx, "pthread_rwlock_rdlock",       h_nop_ret0);
    stub_alloc(ctx, "pthread_rwlock_unlock",       h_nop_ret0);
    stub_alloc(ctx, "pthread_rwlock_wrlock",       h_nop_ret0);
    stub_alloc(ctx, "pthread_attr_init",           h_nop_ret0);
    stub_alloc(ctx, "pthread_attr_destroy",        h_nop_ret0);
    stub_alloc(ctx, "pthread_attr_setdetachstate", h_nop_ret0);

    /* File I/O */
    stub_alloc(ctx, "fopen",    h_nop_ret0);
    stub_alloc(ctx, "fclose",   h_nop_ret0);
    stub_alloc(ctx, "fread",    h_nop_ret0);
    stub_alloc(ctx, "fseek",    h_nop_ret0);
    stub_alloc(ctx, "fseeko",   h_nop_ret0);
    stub_alloc(ctx, "ftello",   h_nop_ret0);
    stub_alloc(ctx, "ferror",   h_nop_ret0);
    stub_alloc(ctx, "fflush",   h_nop_ret0);
    stub_alloc(ctx, "fileno",   h_nop_ret0);
    stub_alloc(ctx, "fdopen",   h_nop_ret0);
    stub_alloc(ctx, "remove",   h_nop_ret0);
    stub_alloc(ctx, "rename",   h_nop_ret0);
    stub_alloc(ctx, "fputc",    h_nop_ret0);
    stub_alloc(ctx, "fstat",    h_nop_ret0);

    /* Network */
    stub_alloc(ctx, "socket",         h_ret_neg1);
    stub_alloc(ctx, "connect",        h_ret_neg1);
    stub_alloc(ctx, "bind",           h_ret_neg1);
    stub_alloc(ctx, "send",           h_ret_neg1);
    stub_alloc(ctx, "recv",           h_ret_neg1);
    stub_alloc(ctx, "sendmsg",        h_ret_neg1);
    stub_alloc(ctx, "close",          h_nop_ret0);
    stub_alloc(ctx, "select",         h_nop_ret0);
    stub_alloc(ctx, "poll",           h_nop_ret0);
    stub_alloc(ctx, "shutdown",       h_nop_ret0);
    stub_alloc(ctx, "setsockopt",     h_nop_ret0);
    stub_alloc(ctx, "getsockopt",     h_nop_ret0);
    stub_alloc(ctx, "getsockname",    h_nop_ret0);
    stub_alloc(ctx, "getaddrinfo",    h_ret_neg1);
    stub_alloc(ctx, "freeaddrinfo",   h_nop);
    stub_alloc(ctx, "gethostbyname",  h_nop_ret0);
    stub_alloc(ctx, "gethostname",    h_nop_ret0);
    stub_alloc(ctx, "inet_addr",      h_nop_ret0);
    stub_alloc(ctx, "inet_ntoa",      h_nop_ret0);
    stub_alloc(ctx, "fcntl",          h_nop_ret0);

    /* System */
    stub_alloc(ctx, "__stack_chk_fail",          h_stack_chk_fail);
    stub_alloc(ctx, "__errno",                   h_errno_fn);
    stub_alloc(ctx, "__assert2",                 h_assert2);
    stub_alloc(ctx, "abort",                     h_abort);
    stub_alloc(ctx, "android_set_abort_message", h_nop);
    stub_alloc(ctx, "getenv",                    h_nop_ret0);
    stub_alloc(ctx, "getcwd",                    h_nop_ret0);
    stub_alloc(ctx, "stat",                      h_ret_neg1);
    stub_alloc(ctx, "open",                      h_ret_neg1);
    stub_alloc(ctx, "mkdir",                     h_ret_neg1);
    stub_alloc(ctx, "usleep",                    h_nop);
    stub_alloc(ctx, "__system_property_get",     h_nop_ret0);
    stub_alloc(ctx, "getpid",                    h_ret1);
    stub_alloc(ctx, "getauxval",                 h_nop_ret0);
    stub_alloc(ctx, "strerror",                  h_strerror);
    stub_alloc(ctx, "strerror_r",                h_nop_ret0);
    stub_alloc(ctx, "dl_iterate_phdr",           h_nop_ret0);
    stub_alloc(ctx, "dlopen",                    h_nop_ret0);
    stub_alloc(ctx, "dlclose",                   h_nop_ret0);
    stub_alloc(ctx, "dlerror",                   h_nop_ret0);
    stub_alloc(ctx, "dlsym",                     h_nop_ret0);
    stub_alloc(ctx, "syscall",                   h_nop_ret0);
    stub_alloc(ctx, "syslog",                    h_nop);
    stub_alloc(ctx, "openlog",                   h_nop);
    stub_alloc(ctx, "closelog",                  h_nop);
    stub_alloc(ctx, "__cxa_atexit",              h_nop_ret0);
    stub_alloc(ctx, "__cxa_finalize",            h_nop);
    stub_alloc(ctx, "__register_atfork",         h_nop_ret0);

    /* Locale */
    stub_alloc(ctx, "setlocale",             h_nop_ret0);
    stub_alloc(ctx, "newlocale",             h_nop_ret0);
    stub_alloc(ctx, "uselocale",             h_nop_ret0);
    stub_alloc(ctx, "freelocale",            h_nop);
    stub_alloc(ctx, "localeconv",            h_nop_ret0);
    stub_alloc(ctx, "__ctype_get_mb_cur_max", h_ret1);
    stub_alloc(ctx, "strcoll_l",             h_strcmp);
    stub_alloc(ctx, "strxfrm_l",             h_nop_ret0);
    stub_alloc(ctx, "wcscoll_l",             h_nop_ret0);
    stub_alloc(ctx, "wcsxfrm_l",             h_nop_ret0);
    stub_alloc(ctx, "strftime_l",            h_nop_ret0);
    stub_alloc(ctx, "strtold_l",             h_nop_ret0);
    stub_alloc(ctx, "strtoll_l",             h_nop_ret0);
    stub_alloc(ctx, "strtoull_l",            h_nop_ret0);

    /* Wide char */
    stub_alloc(ctx, "wcscmp",          h_nop_ret0);
    stub_alloc(ctx, "wcsstr",          h_nop_ret0);
    stub_alloc(ctx, "wcslen",          h_nop_ret0);
    stub_alloc(ctx, "btowc",           h_ret_neg1);
    stub_alloc(ctx, "wctob",           h_ret_neg1);
    stub_alloc(ctx, "mbrtowc",         h_nop_ret0);
    stub_alloc(ctx, "wcrtomb",         h_nop_ret0);
    stub_alloc(ctx, "mbrlen",          h_nop_ret0);
    stub_alloc(ctx, "mbsrtowcs",       h_nop_ret0);
    stub_alloc(ctx, "mbsnrtowcs",      h_nop_ret0);
    stub_alloc(ctx, "wcsnrtombs",      h_nop_ret0);
    stub_alloc(ctx, "mbtowc",          h_nop_ret0);
    stub_alloc(ctx, "wmemchr",         h_nop_ret0);
    stub_alloc(ctx, "wmemcmp",         h_nop_ret0);
    stub_alloc(ctx, "swprintf",        h_nop_ret0);
    stub_alloc(ctx, "iswalpha_l",      h_nop_ret0);
    stub_alloc(ctx, "iswblank_l",      h_nop_ret0);
    stub_alloc(ctx, "iswcntrl_l",      h_nop_ret0);
    stub_alloc(ctx, "iswdigit_l",      h_nop_ret0);
    stub_alloc(ctx, "iswlower_l",      h_nop_ret0);
    stub_alloc(ctx, "iswprint_l",      h_nop_ret0);
    stub_alloc(ctx, "iswpunct_l",      h_nop_ret0);
    stub_alloc(ctx, "iswspace_l",      h_nop_ret0);
    stub_alloc(ctx, "iswupper_l",      h_nop_ret0);
    stub_alloc(ctx, "iswxdigit_l",     h_nop_ret0);
    stub_alloc(ctx, "towlower",        h_nop_ret0);
    stub_alloc(ctx, "towupper",        h_nop_ret0);
    stub_alloc(ctx, "towlower_l",      h_nop_ret0);
    stub_alloc(ctx, "towupper_l",      h_nop_ret0);

    /* FD / semaphore */
    stub_alloc(ctx, "__FD_ISSET_chk",  h_nop_ret0);
    stub_alloc(ctx, "__FD_SET_chk",    h_nop);
    stub_alloc(ctx, "sem_init",        h_nop_ret0);
    stub_alloc(ctx, "sem_destroy",     h_nop_ret0);
    stub_alloc(ctx, "sem_post",        h_nop_ret0);
    stub_alloc(ctx, "sem_timedwait",   h_nop_ret0);

    /* Misc */
    stub_alloc(ctx, "vasprintf",   h_nop_ret0);
    stub_alloc(ctx, "vfprintf",    h_nop_ret0);
    stub_alloc(ctx, "vsnprintf",   h_nop_ret0);
    stub_alloc(ctx, "vsscanf",     h_nop_ret0);
    stub_alloc(ctx, "strtod",      h_nop_ret0);
    stub_alloc(ctx, "strtof",      h_nop_ret0);
    stub_alloc(ctx, "strtold",     h_nop_ret0);
    stub_alloc(ctx, "strtoll",     h_nop_ret0);
    stub_alloc(ctx, "strtoull",    h_nop_ret0);
    stub_alloc(ctx, "wcstod",      h_nop_ret0);
    stub_alloc(ctx, "wcstof",      h_nop_ret0);
    stub_alloc(ctx, "wcstold",     h_nop_ret0);
    stub_alloc(ctx, "wcstol",      h_nop_ret0);
    stub_alloc(ctx, "wcstoll",     h_nop_ret0);
    stub_alloc(ctx, "wcstoul",     h_nop_ret0);
    stub_alloc(ctx, "wcstoull",    h_nop_ret0);
}

/* Registration forward decl */
void register_libc_stubs(INEContext *ctx);
