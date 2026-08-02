/* ══ FILE: elf_loader.c ══
 *
 * Minimal ELF64 / AArch64 shared-library loader for the Unicorn sandbox.
 *
 * Responsibilities:
 *   1. Validate the ELF magic and machine type (EM_AARCH64).
 *   2. Map every PT_LOAD segment into Unicorn memory at BASE_ADDR + p_vaddr,
 *      page-aligning the mapping and zero-filling BSS (Unicorn does this
 *      automatically for pages beyond p_filesz).
 *   3. Parse PT_DYNAMIC to locate DT_RELA, DT_JMPREL, DT_SYMTAB, DT_STRTAB.
 *   4. Apply all Rela relocations (R_AARCH64_RELATIVE, R_AARCH64_GLOB_DAT,
 *      R_AARCH64_JUMP_SLOT):
 *        - Relative relocations resolve to BASE_ADDR + addend.
 *        - External symbols are resolved to host stubs registered in the
 *          INEContext stub table; unregistered symbols get a "nop → ret 0"
 *          auto-stub so the emulator never encounters an unmapped PLT entry.
 *        - Internal symbols are written directly; if a stub override exists
 *          (e.g., isSafeEnvironment) it takes priority.
 *
 * This loader intentionally skips .init_array / .ctors execution: the
 * Chilkat library's C++ constructors depend on pthreads and a licensed
 * global flag that is set manually in emulator.c instead.
 */

#include "elf_loader.h"
#include "elf64_types.h"
#include "stub_dispatch.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unicorn/unicorn.h>

/* Translate a virtual address to the corresponding file offset by scanning
 * the PT_LOAD program headers.  Returns (uint64_t)-1 if vaddr is not covered
 * by any LOAD segment (e.g., BSS-only range or out-of-bounds address). */
static uint64_t vaddr_to_foff(const Elf64_Phdr *phdrs, int phnum, uint64_t vaddr) {
    for (int i = 0; i < phnum; i++) {
        if (phdrs[i].p_type != PT_LOAD) continue;
        if (vaddr >= phdrs[i].p_vaddr &&
            vaddr <  phdrs[i].p_vaddr + phdrs[i].p_filesz) {
            return phdrs[i].p_offset + (vaddr - phdrs[i].p_vaddr);
        }
    }
    return (uint64_t)-1;
}

/* Apply a single RELA relocation entry to the emulated GOT/PLT.
 *
 * Handled relocation types:
 *   R_AARCH64_RELATIVE  : GOT entry = BASE_ADDR + r_addend (no symbol lookup)
 *   R_AARCH64_GLOB_DAT  : data symbol — resolved via stub table or .so address
 *   R_AARCH64_JUMP_SLOT : PLT entry  — resolved via stub table or .so address
 *
 * internal_count / external_count are incremented for logging only. */
static void apply_rela(INEContext *ctx, uc_engine *uc,
                       const Elf64_Rela *rela,
                       const Elf64_Sym  *symtab,
                       const char       *strtab,
                       int              *internal_count,
                       int              *external_count) {
    uint64_t got_vaddr = BASE_ADDR + rela->r_offset;
    uint32_t type = ELF64_R_TYPE(rela->r_info);
    uint32_t sym_idx = ELF64_R_SYM(rela->r_info);

    if (type == R_AARCH64_RELATIVE) {
        uint64_t val = BASE_ADDR + (uint64_t)rela->r_addend;
        uc_mem_write(uc, got_vaddr, &val, 8);
        (*internal_count)++;
        return;
    }

    if (type != R_AARCH64_GLOB_DAT && type != R_AARCH64_JUMP_SLOT) return;

    if (sym_idx == 0) return;

    const Elf64_Sym *sym = &symtab[sym_idx];
    const char *name = strtab + sym->st_name;

    if (sym->st_value != 0) {
        /* Internal symbol — check if we need to override it */
        uint64_t stub_addr = stub_lookup_by_name(ctx, name);
        if (stub_addr) {
            uc_mem_write(uc, got_vaddr, &stub_addr, 8);
        } else {
            uint64_t func_addr = BASE_ADDR + sym->st_value;
            uc_mem_write(uc, got_vaddr, &func_addr, 8);
        }
        (*internal_count)++;
    } else {
        /* External symbol — must have a stub */
        uint64_t stub_addr = stub_lookup_by_name(ctx, name);
        if (!stub_addr) {
            /* Unimplemented — allocate a "nop→ret0" stub */
            stub_addr = stub_alloc_unimpl(ctx, name);
        }
        uc_mem_write(uc, got_vaddr, &stub_addr, 8);
        (*external_count)++;
    }
}

/* Map libPersonalCode.so into Unicorn memory and resolve all relocations.
 *
 * ctx->so_data / ctx->so_size must be set before calling.
 * ctx->uc must point to an open uc_engine with the STUB_AREA already mapped.
 *
 * Returns 0 on success, -1 on any ELF parse or Unicorn mapping error. */
int elf_load(INEContext *ctx) {
    uc_engine *uc = (uc_engine *)ctx->uc;
    const uint8_t *data = ctx->so_data;
    size_t size = ctx->so_size;

    if (size < sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "[!] .so too small\n"); return -1;
    }

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)data;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "[!] Not an ELF file\n"); return -1;
    }
    if (ehdr->e_machine != EM_AARCH64) {
        fprintf(stderr, "[!] Not ARM64 ELF\n"); return -1;
    }

    const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(data + ehdr->e_phoff);
    int phnum = ehdr->e_phnum;

    /* ── Map LOAD segments ── */
    for (int i = 0; i < phnum; i++) {
        if (phdrs[i].p_type != PT_LOAD) continue;
        uint64_t vaddr    = BASE_ADDR + phdrs[i].p_vaddr;
        uint64_t memsz    = phdrs[i].p_memsz;
        uint64_t aligned_start = vaddr & ~0xFFFULL;
        uint64_t aligned_end   = (vaddr + memsz + 0xFFF) & ~0xFFFULL;
        uint64_t mapsz = aligned_end - aligned_start;

        uc_err err = uc_mem_map(uc, aligned_start, mapsz, UC_PROT_ALL);
        if (err != UC_ERR_OK && err != UC_ERR_MAP) {
            fprintf(stderr, "[!] uc_mem_map 0x%llx failed: %s\n",
                    (unsigned long long)aligned_start, uc_strerror(err));
            return -1;
        }

        /* Write file data */
        if (phdrs[i].p_filesz > 0) {
            uint64_t foff = phdrs[i].p_offset;
            uint64_t fsz  = phdrs[i].p_filesz;
            if (foff + fsz > size) fsz = size - foff;
            uc_mem_write(uc, vaddr, data + foff, (size_t)fsz);
        }
        /* BSS portion is already zeroed (Unicorn maps zero-filled memory) */
    }

    /* ── Find PT_DYNAMIC ── */
    uint64_t dyn_vaddr = 0;
    uint64_t dyn_size  = 0;
    for (int i = 0; i < phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            dyn_vaddr = phdrs[i].p_vaddr;
            dyn_size  = phdrs[i].p_filesz;
            break;
        }
    }
    if (!dyn_vaddr) {
        fprintf(stderr, "[!] No PT_DYNAMIC\n"); return -1;
    }

    uint64_t dyn_foff = vaddr_to_foff(phdrs, phnum, dyn_vaddr);
    if (dyn_foff == (uint64_t)-1) {
        fprintf(stderr, "[!] PT_DYNAMIC vaddr not in any LOAD\n"); return -1;
    }
    const Elf64_Dyn *dyn = (const Elf64_Dyn *)(data + dyn_foff);
    int ndyn = (int)(dyn_size / sizeof(Elf64_Dyn));

    uint64_t dt_rela = 0, dt_relasz = 0;
    uint64_t dt_jmprel = 0, dt_pltrelsz = 0;
    uint64_t dt_symtab = 0, dt_strtab = 0;

    for (int i = 0; i < ndyn; i++) {
        switch (dyn[i].d_tag) {
            case DT_RELA:     dt_rela     = dyn[i].d_un.d_ptr; break;
            case DT_RELASZ:   dt_relasz   = dyn[i].d_un.d_val; break;
            case DT_JMPREL:   dt_jmprel   = dyn[i].d_un.d_ptr; break;
            case DT_PLTRELSZ: dt_pltrelsz = dyn[i].d_un.d_val; break;
            case DT_SYMTAB:   dt_symtab   = dyn[i].d_un.d_ptr; break;
            case DT_STRTAB:   dt_strtab   = dyn[i].d_un.d_ptr; break;
            default: break;
        }
    }

    if (!dt_symtab || !dt_strtab) {
        fprintf(stderr, "[!] Missing DT_SYMTAB or DT_STRTAB\n"); return -1;
    }

    /* Convert vaddrs to file offsets */
    uint64_t symtab_foff = vaddr_to_foff(phdrs, phnum, dt_symtab);
    uint64_t strtab_foff = vaddr_to_foff(phdrs, phnum, dt_strtab);
    if (symtab_foff == (uint64_t)-1 || strtab_foff == (uint64_t)-1) {
        fprintf(stderr, "[!] symtab/strtab not in LOAD segments\n"); return -1;
    }

    const Elf64_Sym *symtab = (const Elf64_Sym *)(data + symtab_foff);
    const char      *strtab = (const char *)(data + strtab_foff);

    int internal_count = 0, external_count = 0;

    /* ── Apply DT_RELA relocations (R_AARCH64_RELATIVE mainly) ── */
    if (dt_rela && dt_relasz) {
        uint64_t rela_foff = vaddr_to_foff(phdrs, phnum, dt_rela);
        if (rela_foff != (uint64_t)-1) {
            const Elf64_Rela *relas = (const Elf64_Rela *)(data + rela_foff);
            int nrela = (int)(dt_relasz / sizeof(Elf64_Rela));
            for (int i = 0; i < nrela; i++) {
                apply_rela(ctx, uc, &relas[i], symtab, strtab,
                           &internal_count, &external_count);
            }
        }
    }

    /* ── Apply DT_JMPREL relocations (PLT GOT entries) ── */
    if (dt_jmprel && dt_pltrelsz) {
        uint64_t jmprel_foff = vaddr_to_foff(phdrs, phnum, dt_jmprel);
        if (jmprel_foff != (uint64_t)-1) {
            const Elf64_Rela *relas = (const Elf64_Rela *)(data + jmprel_foff);
            int nrela = (int)(dt_pltrelsz / sizeof(Elf64_Rela));
            for (int i = 0; i < nrela; i++) {
                apply_rela(ctx, uc, &relas[i], symtab, strtab,
                           &internal_count, &external_count);
            }
        }
    }

    fprintf(stderr, "[*] Relocations: %d internal, %d external\n",
            internal_count, external_count);
    return 0;
}
