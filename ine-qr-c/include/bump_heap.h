/* ══ FILE: bump_heap.h ══
 *
 * Public interface for the bump-pointer allocator (bump_heap.c).
 *
 * All emulated ARM64 memory allocations (malloc, calloc, realloc, new…)
 * are backed by this allocator.  Pointers are 16-byte aligned emulated
 * addresses in the range [HEAP_ADDR, HEAP_ADDR + HEAP_SIZE).
 * There is no free/coalesce — the bump pointer only advances.
 */

#pragma once
#include "ine_types.h"

/* Allocate size bytes from the emulated heap (16-byte aligned).
 * Returns emulated address, or 0 on out-of-memory. */
uint64_t bump_alloc(INEContext *ctx, uint64_t size);

/* Grow an existing allocation by allocating new_size bytes and copying the
 * old contents (up to new_size bytes).  The old block is not freed. */
uint64_t bump_realloc(INEContext *ctx, uint64_t old_ptr, uint64_t new_size);

/* Write len bytes of data to a fresh heap allocation (null-terminated).
 * Returns emulated pointer or 0 on OOM. */
uint64_t bump_write(INEContext *ctx, const void *data, size_t len);

/* Duplicate a host C string into the emulated heap (null-terminated).
 * Returns emulated pointer or 0 if s is NULL or OOM. */
uint64_t bump_strdup(INEContext *ctx, const char *s);
