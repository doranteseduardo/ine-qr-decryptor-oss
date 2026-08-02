/* ══ FILE: ine_types.h ══
 *
 * Central type definitions and address-space constants for the INE QR
 * decoder.  Shared by all translation units.
 *
 * Address layout
 * ──────────────
 * The Unicorn sandbox uses a fixed virtual address layout.  Each region is
 * mapped before ELF loading:
 *
 *   BASE_ADDR    .so text+data segments are mapped here.
 *   STACK_ADDR   ARM64 stack grows down from STACK_ADDR; SP starts just below.
 *   HEAP_ADDR    Bump-pointer heap for all emulated malloc/free calls.
 *   TLS_ADDR     Thread-local storage area; TPIDR_EL0 = TLS_ADDR.
 *                Offset 0x28 holds the stack canary (0xDEADBEEFCAFEBABE).
 *   STUB_AREA    BRK+RET stubs for intercepted symbols (8 bytes each).
 *   DATA_ADDR    Input QR payload and pre-computed decrypted buffers.
 *   RETURN_ADDR  Single BRK #0 instruction acting as the return trap for pc().
 *
 * Key offsets are reverse-engineered from libPersonalCode.so (ARM64, 4.6 MB,
 * Chilkat 9.5 statically linked).  They must not change between .so versions.
 */

#pragma once
#include <stdint.h>
#include <stddef.h>
#include <openssl/bn.h>

/* ── Memory layout (must match Python emulate_pc.py exactly) ── */
#define BASE_ADDR    0x10000000ULL
#define STACK_ADDR   0x80000000ULL
#define STACK_SIZE   0x400000ULL
#define HEAP_ADDR    0x90000000ULL
#define HEAP_SIZE    0x4000000ULL
#define TLS_ADDR     0xA0000000ULL
#define TLS_SIZE     0x10000ULL
#define STUB_AREA    0xC0000000ULL
#define STUB_SIZE    0x200000ULL
#define DATA_ADDR    0xD0000000ULL
#define RETURN_ADDR  0xE0000000ULL

/* ── Key offsets in libPersonalCode.so ── */
#define PC_FUNC_OFFSET        0x1dcd40ULL
#define HOOK_RANGE_START      0x1dcdc0ULL
#define HOOK_RANGE_END        0x1de000ULL
#define NOP_PATCH_1           0x1dcde0ULL
#define NOP_PATCH_2           0x1dcde4ULL
#define AES_CIPHERTEXT1_OFF   0x1182cdULL
#define AES_CIPHERTEXT2_OFF   0xd05aeULL

/* AppendBinary2 redirect offsets */
#define APPEND_BIN2_1_OFF     0x1dd250ULL
#define APPEND_BIN2_3_OFF     0x1dd6e0ULL

/* ── Static AES key/IV (hard-coded in the app) ── */
#define STATIC_AES_KEY_HEX "0001029836537892876377726A4E78E77F987CC321180281AABB019654321000"
#define STATIC_AES_IV_HEX  "0192C58D36E47A589AF01928376428AA"

/* ── Structures ── */

/* State of the bump-pointer heap inside Unicorn emulated memory. */
typedef struct {
    uint64_t base; /* emulated base address of the heap region        */
    uint64_t size; /* total size of the heap region in bytes           */
    uint64_t pos;  /* current allocation cursor (offset from base)     */
} BumpHeap;

/* One RSA public key captured from CkRsa_ImportPublicKey.
 * obj_ptr identifies which Chilkat RSA object this key belongs to so that
 * CkRsa_decryptStringENC can dispatch to the correct key when multiple RSA
 * objects are active simultaneously. */
typedef struct {
    uint64_t obj_ptr;  /* emulated address of the CkRsa object   */
    BIGNUM  *n;        /* modulus (OpenSSL BIGNUM, must BN_free)  */
    BIGNUM  *e;        /* public exponent (usually 65537)         */
    int      key_bytes;/* modulus length in bytes (8192/8 = 1024) */
} RSAKeyEntry;

struct INEContext;  /* forward decl for StubEntry */

/* One entry in the stub dispatch table.
 * Each stub occupies one 8-byte BRK+RET slot in STUB_AREA. */
typedef struct {
    uint64_t    addr;    /* emulated address of the BRK instruction      */
    const char *name;    /* symbol name (static string, not owned)        */
    void      (*handler)(struct INEContext *); /* host implementation     */
} StubEntry;

/* Open-addressing hash map for O(1) stub lookup by PC.
 * Key = emulated stub address; value = index into INEContext.stubs[].
 * A key of 0 means the slot is empty (zero is never a valid stub address). */
#define STUB_HASH_SIZE 512
typedef struct {
    uint64_t key;   /* emulated PC of the BRK (0 = empty slot) */
    int      idx;   /* index into stubs[]                      */
} StubHashEntry;

/* Master context for one INE QR decode session.
 *
 * Created by emu_context_init() and passed to every subsystem.
 * Holds all mutable state for the emulator, stub table, crypto captures,
 * and final result. */
typedef struct INEContext {
    void        *uc;            /* uc_engine* (opaque; avoids unicorn.h here) */
    uint8_t     *so_data;       /* raw bytes of libPersonalCode.so             */
    size_t       so_size;       /* byte count of so_data                        */

    BumpHeap     heap;          /* emulated bump-pointer heap state             */

    /* Stub dispatch table (populated before elf_load) */
    StubEntry     stubs[512];
    int           stub_count;       /* number of registered stubs               */
    int           stub_next_slot;   /* next BRK slot index to assign            */
    StubHashEntry stub_hash[STUB_HASH_SIZE];

    /* AES state captured from CkCrypt2_SetEncodedKey / SetEncodedIV */
    char         aes_key_hex[128]; /* 64 hex digits = 32-byte key              */
    char         aes_iv_hex[64];   /* 32 hex digits = 16-byte IV               */
    int          aes_key_captured;
    int          aes_iv_captured;

    /* RSA keys captured from CkRsa_ImportPublicKey (up to 8) */
    RSAKeyEntry  rsa_keys[8];
    int          rsa_key_count;
    BN_CTX      *bn_ctx;           /* shared OpenSSL BN scratch context        */

    /* Fake pthread TLS storage (key → value map, up to 64 keys) */
    uint64_t     tls_vals[64];
    int          tls_key_counter;  /* next key ID to assign                    */

    /* Pre-computed buf2 (filled before emulation, injected via code hook) */
    uint8_t     *decrypted_buf2;
    size_t       decrypted_buf2_len;

    /* Emulation result (captured by h_new_jstring_from_bytes or h_return_trap) */
    uint8_t     *result_data;  /* malloc'd; caller must free                   */
    size_t       result_len;
    int          emulation_done;   /* set to 1 when the return trap fires      */

    int          verbose;
    int          call_counts[512]; /* call frequency per stub (mirrors stubs[]) */
} INEContext;
