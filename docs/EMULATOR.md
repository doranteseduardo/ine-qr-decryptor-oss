# Emulator Architecture

The Unicorn-based path (`ine-qr-c/src/main_emulator.c` +
`ine-qr-py/emulate_pc.py`) runs the original ARM64 `pc()` function
unmodified. It is preserved as the foundational research tool that
discovered the pipeline structure (see [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md))
and continues to produce ground-truth captures used to verify the
pure-crypto implementations described in [PIPELINE.md](PIPELINE.md).

---

## Memory Layout

| Region              | Address      | Size  | Purpose                         |
| ------------------- | ------------ | ----- | ------------------------------- |
| `.so` LOAD segments | `0x10000000` | ~8 MB | ELF mapped here                 |
| Stack               | `0x80000000` | 4 MB  | ARM64 stack                     |
| Heap                | `0x90000000` | 64 MB | Bump allocator (malloc)         |
| TLS                 | `0xA0000000` | 64 KB | pthread TLS slots               |
| Stub area           | `0xC0000000` | 2 MB  | BRK+RET trampolines             |
| Data                | `0xD0000000` | —     | QR payload + pre-computed bufs  |
| Return trap         | `0xE0000000` | —     | Sentinel PC that ends emulation |

Defined as constants in `ine-qr-c/include/ine_types.h`. The Python and C
emulator paths use identical addresses so traces can be diffed directly.

---

## BRK Stub Dispatch

External symbols (libc, Chilkat, JNI) are replaced with 8-byte stubs:

```
BRK #slot_id    ; 0xD4200000 | (slot << 5) — triggers UC_HOOK_INTR
RET             ; 0xD65F03C0
```

When the emulated code calls a stub, Unicorn fires `UC_HOOK_INTR`. The
handler looks up the stub by PC in an O(1) open-addressing hash map,
increments a call counter, and invokes the registered C handler which
reads ARM64 registers (X0–X7), performs host-side logic (OpenSSL AES/RSA),
and writes the return value to X0 before jumping to LR.

Total stubs: ~245 (60 libc + 15 Chilkat + ~170 unimplemented auto-stubs).

The dispatcher, allocator and counter machinery lives in
`ine-qr-c/src/stub_dispatch.c`. The actual handlers split by family:

* `stubs_libc.c` — malloc / memcpy / strlen / strchr / etc.
* `stubs_chilkat.c` — `CkCrypt2_*`, `CkRsa_*`, `CkBinData_*`, `CkEcc_*`.
* `stubs_jni.c` — `GetStringUTFChars`, `NewByteArray`, friends.

### Replacement strategy by family

| Group                              | Strategy                                                       |
| ---------------------------------- | -------------------------------------------------------------- |
| Memory (`malloc`, `realloc`, …)    | Bump allocator that never frees                                |
| Strings / format I/O               | Read format + register args, run host-side equivalent          |
| Threading (`pthread_*`)            | Single-threaded no-ops; `pthread_once` just calls the init fn  |
| File / network                     | Stub to fail safely (`-1` / `0`)                               |
| JNI (`_JNIEnv*`)                   | Returns 0 — we never expose a real JVM                         |

---

## AppendBinary2 Buffer Injection

The `.so` calls `CkBinData_AppendBinary2` to pass encrypted data into its
internal pipeline. Two `UC_HOOK_CODE` hooks intercept these calls and
redirect the data pointer to pre-computed (host-side decrypted) buffers,
short-circuiting the native BinData machinery while keeping the rest of
the pipeline intact.

Pre-computed buffer #1 is the Round-1 RSA-decrypt output (XML #2);
pre-computed buffer #2 is the Stage A RSA-decrypt of buf2. Both are
produced by `static_crypto.c`'s `precompute_buf2()` from the same
`.rodata` constants documented in [PIPELINE.md](PIPELINE.md).

---

## Engineering Challenges Solved by the Emulator Path

### ELF String Table Offset Bug

The `.so`'s `.dynstr` section is 180,137 bytes. During ELF relocation, an
early version of the loader had a guard `(sym->st_name < 65536)` that
caused symbols with large string-table offsets (`strchr` = 66546,
`strstr` = 66615, `strncmp` = 66967, `tolower` = 67000) to be treated as
anonymous. All four were patched to the same "unimplemented" stub,
silently breaking all string operations after the crypto layers
completed.

**Fix:** remove the 65536 guard — `st_name` is a byte offset into
`.dynstr`, not a count, and can legitimately exceed 65535 for large
libraries.

### Chilkat Dispose Crashes

The native Chilkat destructors (`CkCrypt2_Dispose`, `CkRsa_Dispose`, …)
crash inside the emulator because they call into pthreads and C++ runtime
infrastructure that is not fully modelled. Each Dispose function is
replaced with a no-op stub.

### NEON/SIMD Key Derivation

Custom ARM64 NEON instructions derive AES keys/IVs from `.rodata`
constants. These run **natively** inside the Unicorn emulator — the
emulator path does not need to reimplement them. Once the emulator
captured their outputs, those outputs were used to verify the pure-C /
Python translations of the SIMD blocks.

The verified SIMD-block → key mapping:

| Block | VA range            | Output                                                                     |
| ----- | ------------------- | -------------------------------------------------------------------------- |
| 0     | 0x1dce60..0x1dcf78  | AES IV1  = `0192C58D36E47A589AF01928376428AA` ✓                            |
| 1     | 0x1dcf80..0x1dd1e0  | AES KEY1 = `0001029836537892876377726A4E78E77F987CC321180281AABB019654321000` ✓ |
| 2     | 0x1dd328..0x1dd48c  | AES IV2  (16 bytes)                                                        |
| 3     | 0x1dd498..0x1dd66c  | AES KEY2 (32 bytes)                                                        |
| 4     | 0x1dd864..0x1dd9a4  | AES IV3  (16 bytes)                                                        |
| 5     | 0x1dd9b0..0x1ddbf4  | AES KEY3 (32 bytes)                                                        |
