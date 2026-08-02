/* ══ FILE: elf_loader.h ══
 *
 * Public interface for the ELF64/AArch64 shared library loader (elf_loader.c).
 *
 * elf_load() is called once per emulation run, after the Unicorn address
 * space is set up but before the code hook and emulation start.
 */

#pragma once
#include "ine_types.h"

/* Load libPersonalCode.so (ctx->so_data / ctx->so_size) into the Unicorn
 * sandbox (ctx->uc) and resolve all ELF relocations.
 *
 * Prerequisites: Unicorn engine must be open; STUB_AREA must be mapped and
 * all stubs registered so that apply_rela can look them up by name.
 *
 * Returns 0 on success, -1 if the ELF is invalid or a mapping error occurs. */
int elf_load(INEContext *ctx);
