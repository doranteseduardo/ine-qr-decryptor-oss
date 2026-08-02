/* ══ FILE: stub_dispatch.h ══
 *
 * Public interface for the BRK-based host stub dispatch system (stub_dispatch.c).
 *
 * Every function that the emulated ARM64 code needs to call on the host is
 * registered as a "stub": an 8-byte (BRK #slot / RET) trampoline written
 * into STUB_AREA, with a corresponding handler function stored in the context.
 *
 * When the emulated CPU hits a BRK the Unicorn interrupt hook fires
 * stub_on_interrupt(), which looks up the handler by PC and calls it.
 *
 * Handlers read their arguments from ARM64 registers with uc_reg_read and
 * return results via stub_ret().
 */

#pragma once
#include "ine_types.h"
#include <unicorn/unicorn.h>

/* Allocate a stub slot, write the BRK+RET trampoline into emulated memory,
 * and register the name→handler mapping in the context.
 * Returns the emulated address of the stub (inside STUB_AREA), or 0 if
 * the stub table is full (limit: 512 stubs). */
uint64_t stub_alloc(INEContext *ctx, const char *name,
                    void (*handler)(INEContext *));

/* Allocate a stub backed by a generic handler that logs the name (in verbose
 * mode) and returns 0.  Used by elf_loader for unknown external symbols. */
uint64_t stub_alloc_unimpl(INEContext *ctx, const char *name);

/* Linear search: return stub address for the given symbol name, or 0. */
uint64_t stub_lookup_by_name(INEContext *ctx, const char *name);

/* Hash-map lookup: return index into ctx->stubs[] for the given PC, or -1. */
int stub_lookup_by_pc(const INEContext *ctx, uint64_t pc);

/* Unicorn UC_HOOK_INTR callback.  user_data must be the INEContext pointer.
 * Dispatches to the registered handler for the stub at the current PC. */
void stub_on_interrupt(uc_engine *uc, uint32_t intno, void *user_data);

/* Unicorn UC_HOOK_MEM_UNMAPPED callback.  Maps a 64 KB page at the faulting
 * address and returns true so Unicorn retries the faulting access. */
bool stub_on_unmapped(uc_engine *uc, uc_mem_type type,
                      uint64_t addr, int size, int64_t value, void *user_data);

/* Inline return helper used by every stub handler.
 * Writes val to X0 and sets PC = LR to simulate a normal function return. */
static inline void stub_ret(INEContext *ctx, uint64_t val) {
    uint64_t lr;
    uc_reg_read((uc_engine *)ctx->uc, UC_ARM64_REG_LR, &lr);
    uc_reg_write((uc_engine *)ctx->uc, UC_ARM64_REG_X0, &val);
    uc_reg_write((uc_engine *)ctx->uc, UC_ARM64_REG_PC, &lr);
}
