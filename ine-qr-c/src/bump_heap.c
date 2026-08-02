/* ══ FILE: bump_heap.c ══
 *
 * Bump-pointer allocator for the emulated ARM64 heap (HEAP_ADDR..HEAP_ADDR+HEAP_SIZE).
 *
 * The Unicorn sandbox does not host a libc malloc, so all emulated allocations
 * (malloc, calloc, realloc, new, posix_memalign…) are backed by this simple
 * bump allocator that advances a cursor through the pre-mapped HEAP region.
 * Allocations are 16-byte aligned.  There is intentionally no free/coalesce:
 * the emulation is short-lived and heap pressure is low enough that a monotone
 * bump is sufficient.
 *
 * bump_write / bump_strdup are convenience helpers used by stub handlers that
 * need to return a host string to emulated code without knowing about Unicorn
 * memory management.
 */

#include "ine_types.h"
#include <string.h>
#include <unicorn/unicorn.h>

/* Allocate size bytes from the emulated heap, 16-byte aligned.
 * Returns the emulated address or 0 if the heap is exhausted (OOM). */
uint64_t bump_alloc(INEContext *ctx, uint64_t size) {
    if (size == 0) size = 1;
    /* 16-byte align */
    size = (size + 15) & ~(uint64_t)15;
    if (ctx->heap.pos + size > ctx->heap.size) {
        return 0; /* OOM */
    }
    uint64_t ptr = ctx->heap.base + ctx->heap.pos;
    ctx->heap.pos += size;
    return ptr;
}

/* Emulated realloc: allocate a new block and copy the old contents.
 * Because the bump allocator does not track block sizes, new_size bytes are
 * copied from old_ptr (conservatively safe provided the old block was at
 * least new_size bytes — which holds for the grow-only usage patterns in
 * the Chilkat library).  old_ptr is not freed (bump heap). */
uint64_t bump_realloc(INEContext *ctx, uint64_t old_ptr, uint64_t new_size) {
    uint64_t new_ptr = bump_alloc(ctx, new_size);
    if (old_ptr && new_ptr) {
        /* Find old size: we don't track it exactly, so copy conservatively.
           Use new_size as copy limit (safe since old region was >= its request). */
        uint64_t copy_size = new_size;
        uint8_t tmp[4096];
        uint64_t remaining = copy_size;
        uint64_t src = old_ptr, dst = new_ptr;
        while (remaining > 0) {
            uint64_t chunk = remaining < sizeof(tmp) ? remaining : sizeof(tmp);
            if (uc_mem_read((uc_engine *)ctx->uc, src, tmp, (size_t)chunk) != UC_ERR_OK) break;
            if (uc_mem_write((uc_engine *)ctx->uc, dst, tmp, (size_t)chunk) != UC_ERR_OK) break;
            src += chunk; dst += chunk; remaining -= chunk;
        }
    }
    return new_ptr;
}

/* Write a buffer into emulated heap and return the pointer. */
uint64_t bump_write(INEContext *ctx, const void *data, size_t len) {
    uint64_t ptr = bump_alloc(ctx, (uint64_t)len + 1);
    if (!ptr) return 0;
    uc_mem_write((uc_engine *)ctx->uc, ptr, data, len);
    uint8_t zero = 0;
    uc_mem_write((uc_engine *)ctx->uc, ptr + len, &zero, 1);
    return ptr;
}

/* Write a C string into emulated heap, return pointer. */
uint64_t bump_strdup(INEContext *ctx, const char *s) {
    if (!s) return 0;
    size_t len = strlen(s);
    return bump_write(ctx, s, len);
}
