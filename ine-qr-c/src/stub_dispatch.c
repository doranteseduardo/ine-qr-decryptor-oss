/* ══ FILE: stub_dispatch.c ══
 *
 * BRK-based host-stub dispatch table for the ARM64 emulator.
 *
 * How it works:
 *   Each external (or overridden internal) symbol is assigned an 8-byte
 *   "stub" in the STUB_AREA region of emulated memory:
 *
 *       BRK #<slot>   (4 bytes)  — raises Unicorn HOOK_INTR
 *       RET           (4 bytes)  — return after the handler resumes
 *
 *   When the emulated code calls a stubbed symbol the CPU executes BRK,
 *   Unicorn fires HOOK_INTR, and stub_on_interrupt() dispatches to the
 *   registered handler by decoding the slot number from the BRK encoding
 *   via the open-addressing hash map (stub_hash[]).
 *
 *   Each handler receives the full INEContext, reads arguments from ARM64
 *   registers (X0-X7, W0-W7) via uc_reg_read, performs host-side logic,
 *   and writes return values with stub_ret() which sets X0 and jumps to LR.
 *
 * Stub layout:
 *   BRK #n  =  0xD4200000 | (n << 5)
 *   RET     =  0xD65F03C0
 *   Slot 0  is always the return trap at RETURN_ADDR (special-cased in
 *   emu_run after the initial stub_alloc call).
 */

#include "stub_dispatch.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unicorn/unicorn.h>
#include <unicorn/arm64.h>

/* Each stub is 8 bytes: BRK #slot_id + RET */
/* BRK #n = 0xD4200000 | (n << 5),  RET = 0xD65F03C0 */

/* Compute the emulated address of a stub slot from its sequential index. */
static uint64_t _slot_addr(int slot) {
    return STUB_AREA + (uint64_t)slot * 8;
}

/* Register a named host stub handler and write its BRK+RET trampoline into
 * emulated STUB_AREA memory.  Returns the stub's emulated address or 0 if the
 * table is full (max 512 stubs). */
uint64_t stub_alloc(INEContext *ctx, const char *name,
                    void (*handler)(INEContext *)) {
    if (ctx->stub_count >= 512) {
        fprintf(stderr, "[!] stub table full\n");
        return 0;
    }
    int slot = ctx->stub_next_slot++;
    uint64_t addr = _slot_addr(slot);

    /* Write BRK #slot + RET into emulated memory */
    uint32_t brk = 0xD4200000u | ((uint32_t)slot << 5);
    uint32_t ret = 0xD65F03C0u;
    uc_mem_write((uc_engine *)ctx->uc, addr,     &brk, 4);
    uc_mem_write((uc_engine *)ctx->uc, addr + 4, &ret, 4);

    /* Store in stubs array */
    int idx = ctx->stub_count++;
    ctx->stubs[idx].addr    = addr;
    ctx->stubs[idx].name    = name;
    ctx->stubs[idx].handler = handler;
    ctx->call_counts[idx]   = 0;

    /* Insert into hash map */
    uint32_t h = (uint32_t)((addr >> 3) % STUB_HASH_SIZE);
    while (ctx->stub_hash[h].key != 0) {
        h = (h + 1) % STUB_HASH_SIZE;
    }
    ctx->stub_hash[h].key = addr;
    ctx->stub_hash[h].idx = idx;

    return addr;
}

/* Default handler for symbols that appear in the .so but have no explicit
 * implementation.  Logs the call in verbose mode and returns 0 via X0. */
static void _h_unimpl(INEContext *ctx) {
    /* Find which stub fired by looking at PC */
    uint64_t pc, lr;
    uc_reg_read((uc_engine *)ctx->uc, UC_ARM64_REG_PC, &pc);
    uc_reg_read((uc_engine *)ctx->uc, UC_ARM64_REG_LR, &lr);
    int idx = stub_lookup_by_pc(ctx, pc);
    if (idx >= 0 && ctx->verbose) {
        fprintf(stderr, "    [STUB] %s() not implemented → 0 (LR=0x%llx)\n",
                ctx->stubs[idx].name, (unsigned long long)lr);
    }
    stub_ret(ctx, 0);
}

/* Allocate a stub backed by the generic "unimplemented" handler.
 * Used by elf_loader for external symbols with no registered implementation. */
uint64_t stub_alloc_unimpl(INEContext *ctx, const char *name) {
    return stub_alloc(ctx, name, _h_unimpl);
}

/* Linear scan for a stub by symbol name.  Returns its emulated address
 * or 0 if not found.  Called at relocation time, not on the hot path. */
uint64_t stub_lookup_by_name(INEContext *ctx, const char *name) {
    for (int i = 0; i < ctx->stub_count; i++) {
        if (strcmp(ctx->stubs[i].name, name) == 0)
            return ctx->stubs[i].addr;
    }
    return 0;
}

/* O(1) stub lookup by emulated PC using the open-addressing hash map.
 * Returns the index into ctx->stubs[] or -1 if pc is not a known stub. */
int stub_lookup_by_pc(const INEContext *ctx, uint64_t pc) {
    uint32_t h = (uint32_t)((pc >> 3) % STUB_HASH_SIZE);
    for (int probe = 0; probe < STUB_HASH_SIZE; probe++) {
        uint32_t slot = (h + (uint32_t)probe) % STUB_HASH_SIZE;
        if (ctx->stub_hash[slot].key == 0) return -1;
        if (ctx->stub_hash[slot].key == pc) return ctx->stub_hash[slot].idx;
    }
    return -1;
}

/* Unicorn UC_HOOK_INTR callback.  Decodes which stub fired from the current
 * PC, increments its call counter, and invokes the registered handler.
 * If PC does not map to any stub the emulation is stopped with an error. */
void stub_on_interrupt(uc_engine *uc, uint32_t intno, void *user_data) {
    (void)intno;
    INEContext *ctx = (INEContext *)user_data;
    uint64_t pc;
    uc_reg_read(uc, UC_ARM64_REG_PC, &pc);

    int idx = stub_lookup_by_pc(ctx, pc);
    if (idx >= 0) {
        ctx->call_counts[idx]++;
        ctx->stubs[idx].handler(ctx);
    } else {
        fprintf(stderr, "[!] Unhandled interrupt at PC=0x%llx\n",
                (unsigned long long)pc);
        uc_emu_stop(uc);
    }
}

/* Unicorn UC_HOOK_MEM_UNMAPPED callback.  On any unmapped read/write/fetch,
 * maps a 64 KB page at the faulting address so execution can continue.
 * This handles lazy BSS regions and Chilkat internal allocations that land
 * outside the pre-mapped heap.  Returns true to retry the faulting access. */
bool stub_on_unmapped(uc_engine *uc, uc_mem_type type,
                      uint64_t addr, int size, int64_t value, void *user_data) {
    (void)size; (void)value; (void)user_data;
    const char *atype = (type == UC_MEM_READ_UNMAPPED)  ? "READ"  :
                        (type == UC_MEM_WRITE_UNMAPPED) ? "WRITE" :
                        (type == UC_MEM_FETCH_UNMAPPED) ? "FETCH" : "?";
    uint64_t pc;
    uc_reg_read(uc, UC_ARM64_REG_PC, &pc);
    fprintf(stderr, "[!] Unmapped %s: 0x%llx at PC=0x%llx\n",
            atype, (unsigned long long)addr, (unsigned long long)pc);
    /* Map the page so execution can continue */
    uint64_t page = addr & ~0xFFFULL;
    uc_err err = uc_mem_map(uc, page, 0x10000, UC_PROT_ALL);
    return (err == UC_ERR_OK || err == UC_ERR_MAP);
}
