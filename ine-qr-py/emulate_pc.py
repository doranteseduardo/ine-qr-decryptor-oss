#!/usr/bin/env python3
"""
INE QR Emulator — ARM64 Emulation of libPersonalCode.so
========================================================
Emulates the native pc() function from the INE QR reader app using
Unicorn Engine v2. Executes all 7 layers of the crypto pipeline to
fully decrypt the QR code data.

Strategy:
- Load .so with correct GOT/PLT relocations (1071 internal + 183 external)
- Python implementations of libc functions (malloc, memcpy, strlen, etc.)
- Python overrides for Chilkat crypto (AES, RSA, ECDSA) to bypass licensing
- SIMD/NEON key derivation runs natively in the emulator

Requirements: pip install unicorn capstone lief cryptography
"""

import struct
import sys
import os
import time as time_module

# Force UTF-8 output on Windows (avoids cp1252 errors with arrow/unicode chars)
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if sys.stderr.encoding and sys.stderr.encoding.lower() != 'utf-8':
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

from unicorn import *
from unicorn.arm64_const import *
from capstone import *

import base64
import xml.etree.ElementTree as ET
from binascii import unhexlify

import lief

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# === Memory Layout ===
BASE_ADDR      = 0x10000000
STACK_ADDR     = 0x80000000
STACK_SIZE     = 0x400000     # 4MB stack
HEAP_ADDR      = 0x90000000
HEAP_SIZE      = 0x4000000    # 64MB heap
TLS_ADDR       = 0xA0000000
TLS_SIZE       = 0x10000
STUB_AREA      = 0xC0000000   # Area for function stubs
STUB_SIZE      = 0x200000
DATA_ADDR      = 0xD0000000
RETURN_ADDR    = 0xE0000000   # Return address trap

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR   = os.path.join(SCRIPT_DIR, "..")
OUTPUT_DIR = os.path.join(ROOT_DIR, "output")
SO_PATH = os.path.join(ROOT_DIR, "libPersonalCode.so")
QR_LEFT = os.path.join(OUTPUT_DIR, "qr_izquierdo.bin")
QR_RIGHT = os.path.join(OUTPUT_DIR, "qr_derecho.bin")


class BumpHeap:
    def __init__(self, base, size):
        self.base = base
        self.size = size
        self.pos = 0
        self.allocs = {}

    def malloc(self, size):
        size = max(size, 1)
        size = (size + 15) & ~15
        if self.pos + size > self.size:
            return 0
        ptr = self.base + self.pos
        self.pos += size
        self.allocs[ptr] = size
        return ptr

    def realloc(self, ptr, new_size):
        new_ptr = self.malloc(new_size)
        if ptr and ptr in self.allocs:
            old_size = self.allocs[ptr]
            return new_ptr, min(old_size, new_size)
        return new_ptr, 0

    def free(self, ptr):
        pass  # bump allocator never frees


class INEEmulator:
    def __init__(self):
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.heap = BumpHeap(HEAP_ADDR, HEAP_SIZE)
        self.binary = lief.parse(SO_PATH)
        self.so_data = open(SO_PATH, "rb").read()

        self.stub_hooks = {}      # stub_addr -> (name, handler)
        self.stub_next = 0        # Next stub slot
        self.got_entries = {}      # GOT addr -> (name, is_external)
        self.call_count = {}       # name -> count
        self.instruction_count = 0
        self.result_string = None
        self.verbose = "--verbose" in sys.argv

        # Mutex state (fake)
        self.mutexes = {}
        # TLS keys
        self.tls_keys = {}
        self.tls_key_counter = 1

        # Crypto state for Python overrides
        self._aes_key_hex = None
        self._aes_iv_hex = None
        self._rsa_keys = {}  # rsa_obj_ptr -> (n, e, key_size)

    def _precompute_rsa_results(self):
        """Pre-compute RSA results that Chilkat can't handle in emulation."""
        # Load RSA key #2 XML
        rsa_key2_path = os.path.join(OUTPUT_DIR, "rsa_step1_full.txt")
        if not os.path.exists(rsa_key2_path):
            print("[!] rsa_step1_full.txt not found — RSA overrides disabled")
            self._rsa_key2_xml = None
            self._decrypted_buf2 = None
            return

        with open(rsa_key2_path) as f:
            self._rsa_key2_xml = f.read().strip()
        print(f"[*] RSA key #2 loaded: {len(self._rsa_key2_xml)} chars")

        # Parse RSA key #2 to decrypt buf2
        root = ET.fromstring(self._rsa_key2_xml)
        mod_b64 = root.find("Modulus").text
        exp_b64 = root.find("Exponent").text
        n = int.from_bytes(base64.b64decode(mod_b64), 'big')
        e = int.from_bytes(base64.b64decode(exp_b64), 'big')
        key_size = len(base64.b64decode(mod_b64))

        # Load QR data and extract buf2
        with open(QR_LEFT, "rb") as f:
            left = f.read()
        with open(QR_RIGHT, "rb") as f:
            right = f.read()
        combined = left[2:] + right[2:]
        buf2 = combined[688:688 + 1024]

        # RSA raw decrypt: m = c^e mod n
        c_int = int.from_bytes(buf2, 'big')
        m_int = pow(c_int, e, n)
        raw = m_int.to_bytes(key_size, 'big')

        # Strip PKCS#1 v1.5 padding
        self._decrypted_buf2 = None
        if raw[0] == 0x00 and raw[1] in (0x01, 0x02):
            for i in range(2, len(raw)):
                if raw[i] == 0x00:
                    self._decrypted_buf2 = raw[i + 1:]
                    break

        if self._decrypted_buf2:
            print(f"[*] Decrypted buf2: {len(self._decrypted_buf2)} bytes (PKCS#1 type {raw[1]})")
        else:
            print("[!] Failed to RSA-decrypt buf2 — PKCS#1 padding invalid")

    def _alloc_stub(self, name, handler):
        """Allocate a stub function that triggers a BRK hook."""
        addr = STUB_AREA + self.stub_next * 8
        self.stub_next += 1
        # Write BRK #stub_id instruction
        brk_insn = struct.pack("<I", 0xD4200000 | (self.stub_next << 5))
        self.uc.mem_write(addr, brk_insn + struct.pack("<I", 0xD65F03C0))  # BRK + RET
        self.stub_hooks[addr] = (name, handler)
        return addr

    def setup_memory(self):
        uc = self.uc

        # Map ELF segments
        for seg in self.binary.segments:
            if seg.type == lief.ELF.Segment.TYPE.LOAD:
                vaddr = BASE_ADDR + seg.virtual_address
                memsz = seg.virtual_size
                aligned_start = vaddr & ~0xFFF
                aligned_end = (vaddr + memsz + 0xFFF) & ~0xFFF
                try:
                    uc.mem_map(aligned_start, aligned_end - aligned_start, UC_PROT_ALL)
                except UcError:
                    pass
                uc.mem_write(vaddr, bytes(seg.content))

        # Stack, Heap, TLS, Stubs, Data, Return trap
        for addr, size in [(STACK_ADDR - STACK_SIZE, STACK_SIZE),
                           (HEAP_ADDR, HEAP_SIZE),
                           (TLS_ADDR, TLS_SIZE),
                           (STUB_AREA, STUB_SIZE),
                           (DATA_ADDR, 0x10000),
                           (RETURN_ADDR, 0x1000)]:
            uc.mem_map(addr, size, UC_PROT_ALL)

        # TLS: stack canary
        uc.mem_write(TLS_ADDR + 0x28, struct.pack("<Q", 0xDEADBEEFCAFEBABE))
        uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS_ADDR)

        # Return trap
        uc.mem_write(RETURN_ADDR, struct.pack("<I", 0xD4200000))  # BRK #0
        self.stub_hooks[RETURN_ADDR] = ("__return_trap__", self._hook_return)

    def apply_relocations(self):
        """Apply GOT relocations: internal → real address, external → stub."""
        uc = self.uc

        # Handlers for external functions
        ext_handlers = {
            # Memory
            "malloc": self._h_malloc, "free": self._h_free, "realloc": self._h_realloc,
            "calloc": self._h_calloc, "posix_memalign": self._h_posix_memalign,
            "memcpy": self._h_memcpy, "memmove": self._h_memmove, "memset": self._h_memset,
            "memcmp": self._h_memcmp, "memchr": self._h_memchr,
            "_Znwm": self._h_malloc, "_Znam": self._h_malloc,  # C++ new
            "_ZdlPv": self._h_free, "_ZdaPv": self._h_free,    # C++ delete

            # String
            "strlen": self._h_strlen, "strchr": self._h_strchr, "strcmp": self._h_strcmp,
            "strncmp": self._h_strncmp, "strcasecmp": self._h_strcasecmp,
            "strncasecmp": self._h_strncasecmp, "strstr": self._h_strstr,
            "strtol": self._h_strtol, "strtoul": self._h_strtoul,
            "atoi": self._h_atoi, "atof": self._h_atof,
            "tolower": self._h_tolower, "toupper": self._h_toupper,
            "isalnum": self._h_isalnum,

            # Formatted I/O
            "snprintf": self._h_snprintf, "sscanf": self._h_sscanf,
            "fprintf": self._h_nop_ret0, "fwrite": self._h_nop_ret0,

            # Time
            "time": self._h_time, "gettimeofday": self._h_gettimeofday,
            "gmtime_r": self._h_gmtime_r, "localtime_r": self._h_localtime_r,
            "mktime": self._h_mktime, "tzset": self._h_nop,
            "srand": self._h_nop,

            # Threads (fake single-threaded)
            "pthread_mutex_init": self._h_nop_ret0, "pthread_mutex_destroy": self._h_nop_ret0,
            "pthread_mutex_lock": self._h_nop_ret0, "pthread_mutex_unlock": self._h_nop_ret0,
            "pthread_mutexattr_init": self._h_nop_ret0, "pthread_mutexattr_destroy": self._h_nop_ret0,
            "pthread_mutexattr_settype": self._h_nop_ret0,
            "pthread_once": self._h_pthread_once,
            "pthread_key_create": self._h_pthread_key_create,
            "pthread_getspecific": self._h_pthread_getspecific,
            "pthread_setspecific": self._h_pthread_setspecific,
            "pthread_key_delete": self._h_nop_ret0,
            "pthread_cond_broadcast": self._h_nop_ret0, "pthread_cond_wait": self._h_nop_ret0,
            "pthread_create": self._h_nop_ret0, "pthread_exit": self._h_nop,
            "pthread_rwlock_rdlock": self._h_nop_ret0, "pthread_rwlock_unlock": self._h_nop_ret0,
            "pthread_rwlock_wrlock": self._h_nop_ret0,
            "pthread_attr_init": self._h_nop_ret0, "pthread_attr_destroy": self._h_nop_ret0,
            "pthread_attr_setdetachstate": self._h_nop_ret0,

            # File I/O (stub)
            "fopen": self._h_nop_ret0, "fclose": self._h_nop_ret0,
            "fread": self._h_nop_ret0, "fseek": self._h_nop_ret0,
            "fseeko": self._h_nop_ret0, "ftello": self._h_nop_ret0,
            "ferror": self._h_nop_ret0, "fflush": self._h_nop_ret0,
            "fileno": self._h_nop_ret0, "fdopen": self._h_nop_ret0,
            "remove": self._h_nop_ret0, "rename": self._h_nop_ret0,
            "fputc": self._h_nop_ret0, "fstat": self._h_nop_ret0,

            # Network (stub)
            "socket": self._h_ret_neg1, "connect": self._h_ret_neg1,
            "bind": self._h_ret_neg1, "send": self._h_ret_neg1,
            "recv": self._h_ret_neg1, "sendmsg": self._h_ret_neg1,
            "close": self._h_nop_ret0, "select": self._h_nop_ret0,
            "poll": self._h_nop_ret0, "shutdown": self._h_nop_ret0,
            "setsockopt": self._h_nop_ret0, "getsockopt": self._h_nop_ret0,
            "getsockname": self._h_nop_ret0, "getaddrinfo": self._h_ret_neg1,
            "freeaddrinfo": self._h_nop, "gethostbyname": self._h_nop_ret0,
            "gethostname": self._h_nop_ret0, "inet_addr": self._h_nop_ret0,
            "inet_ntoa": self._h_nop_ret0, "fcntl": self._h_nop_ret0,

            # System
            "__stack_chk_fail": self._h_stack_chk_fail,
            "__errno": self._h_errno, "__assert2": self._h_assert,
            "abort": self._h_abort, "android_set_abort_message": self._h_nop,
            "getenv": self._h_nop_ret0, "getcwd": self._h_nop_ret0,
            "stat": self._h_ret_neg1, "open": self._h_ret_neg1,
            "mkdir": self._h_ret_neg1, "usleep": self._h_nop,
            "__system_property_get": self._h_nop_ret0,
            "getpid": self._h_ret1, "getauxval": self._h_nop_ret0,
            "strerror": self._h_strerror, "strerror_r": self._h_nop_ret0,
            "dl_iterate_phdr": self._h_nop_ret0,
            "dlopen": self._h_nop_ret0, "dlclose": self._h_nop_ret0,
            "dlerror": self._h_nop_ret0, "dlsym": self._h_nop_ret0,
            "syscall": self._h_nop_ret0,
            "syslog": self._h_nop, "openlog": self._h_nop, "closelog": self._h_nop,
            "__cxa_atexit": self._h_nop_ret0, "__cxa_finalize": self._h_nop,
            "__register_atfork": self._h_nop_ret0,

            # Locale (stub)
            "setlocale": self._h_nop_ret0, "newlocale": self._h_nop_ret0,
            "uselocale": self._h_nop_ret0, "freelocale": self._h_nop,
            "localeconv": self._h_nop_ret0, "__ctype_get_mb_cur_max": self._h_ret1,
            "strcoll_l": self._h_strcmp, "strxfrm_l": self._h_nop_ret0,
            "wcscoll_l": self._h_nop_ret0, "wcsxfrm_l": self._h_nop_ret0,
            "strftime_l": self._h_nop_ret0, "strtold_l": self._h_nop_ret0,
            "strtoll_l": self._h_nop_ret0, "strtoull_l": self._h_nop_ret0,

            # Wide char (stub)
            "wcscmp": self._h_nop_ret0, "wcsstr": self._h_nop_ret0,
            "wcslen": self._h_nop_ret0, "btowc": self._h_ret_neg1,
            "wctob": self._h_ret_neg1, "mbrtowc": self._h_nop_ret0,
            "wcrtomb": self._h_nop_ret0, "mbrlen": self._h_nop_ret0,
            "mbsrtowcs": self._h_nop_ret0, "mbsnrtowcs": self._h_nop_ret0,
            "wcsnrtombs": self._h_nop_ret0, "mbtowc": self._h_nop_ret0,
            "wmemchr": self._h_nop_ret0, "wmemcmp": self._h_nop_ret0,
            "swprintf": self._h_nop_ret0,
            "iswalpha_l": self._h_nop_ret0, "iswblank_l": self._h_nop_ret0,
            "iswcntrl_l": self._h_nop_ret0, "iswdigit_l": self._h_nop_ret0,
            "iswlower_l": self._h_nop_ret0, "iswprint_l": self._h_nop_ret0,
            "iswpunct_l": self._h_nop_ret0, "iswspace_l": self._h_nop_ret0,
            "iswupper_l": self._h_nop_ret0, "iswxdigit_l": self._h_nop_ret0,
            "towlower": self._h_nop_ret0, "towupper": self._h_nop_ret0,
            "towlower_l": self._h_nop_ret0, "towupper_l": self._h_nop_ret0,

            # FD
            "__FD_ISSET_chk": self._h_nop_ret0, "__FD_SET_chk": self._h_nop,
            "sem_init": self._h_nop_ret0, "sem_destroy": self._h_nop_ret0,
            "sem_post": self._h_nop_ret0, "sem_timedwait": self._h_nop_ret0,

            # Misc
            "vasprintf": self._h_nop_ret0, "vfprintf": self._h_nop_ret0,
            "vsnprintf": self._h_nop_ret0, "vsscanf": self._h_nop_ret0,
            "strtod": self._h_nop_ret0, "strtof": self._h_nop_ret0,
            "strtold": self._h_nop_ret0, "strtoll": self._h_nop_ret0,
            "strtoull": self._h_nop_ret0,
            "wcstod": self._h_nop_ret0, "wcstof": self._h_nop_ret0,
            "wcstold": self._h_nop_ret0, "wcstol": self._h_nop_ret0,
            "wcstoll": self._h_nop_ret0, "wcstoul": self._h_nop_ret0,
            "wcstoull": self._h_nop_ret0,
        }

        # Internal functions that need to be stubbed (they use JNI env which we don't have)
        internal_overrides = {
            "isSafeEnvironment": self._h_ret1,     # Anti-tampering check → always safe
            "hR": self._h_ret1,                    # License/remaining check → always OK
            "updateCtr": self._h_nop,              # Counter update → skip
            # Full Chilkat crypto override (Python AES + RSA)
            "CkCrypt2_SetEncodedKey": self._h_ckcrypt2_set_encoded_key,
            "CkCrypt2_SetEncodedIV": self._h_ckcrypt2_set_encoded_iv,
            "CkCrypt2_decryptStringENC": self._h_ckcrypt2_decrypt_string_enc,
            "CkRsa_ImportPublicKey": self._h_rsa_import_public_key,
            "CkRsa_decryptStringENC": self._h_rsa_decrypt_string_enc,
            "CkRsa_DecryptBd": self._h_rsa_decrypt_bd,
            "CkRsa_getLastMethodSuccess": self._h_ret1,
            # CkGlobal_UnlockBundle runs natively but we patch the check after it
            # JNI helper functions that need env
            "_ZN7_JNIEnv22CallStaticObjectMethodEP7_jclassP10_jmethodIDz": self._h_nop_ret0,
            "_Z9showToastP7_JNIEnvP8_jobjectNSt6__ndk112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE": self._h_nop,
            "_ZN7_JNIEnv20CallStaticVoidMethodEP7_jclassP10_jmethodIDz": self._h_nop,
            "_ZN7_JNIEnv14CallVoidMethodEP8_jobjectP10_jmethodIDz": self._h_nop,
            "_Z9strConcatPKcS0_": self._h_str_concat,
            "_Z8jstr2strP7_JNIEnvP8_jstring": self._h_nop_ret0,
            "_Z9jstrSplitP7_JNIEnvP8_jstringS2_": self._h_nop_ret0,
            "_ZN7_JNIEnv16CallObjectMethodEP8_jobjectP10_jmethodIDz": self._h_nop_ret0,
            "_ZN7_JNIEnv19CallStaticIntMethodEP7_jclassP10_jmethodIDz": self._h_nop_ret0,
            "_Z13str2LowerCaseP7_JNIEnvRKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE": self._h_nop_ret0,
            "_Z13str2UpperCaseP7_JNIEnvRKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE": self._h_nop_ret0,
            "_Z8strSplitP7_JNIEnvRKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES9_": self._h_nop_ret0,
            "_Z19newJStringFromBytesP7_JNIEnvPai": self._h_new_jstring_from_bytes,
            "_ZN7_JNIEnv9NewObjectEP7_jclassP10_jmethodIDz": self._h_nop_ret0,
            "_Z10strReplaceP7_JNIEnvRKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES9_S9_": self._h_nop_ret0,
            "_Z7str2IntP7_JNIEnvNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE": self._h_nop_ret0,
        }

        # Apply relocations
        internal_count = 0
        external_count = 0

        for reloc in self.binary.pltgot_relocations:
            sym = reloc.symbol
            if not sym:
                continue

            got_addr = BASE_ADDR + reloc.address

            if sym.value > 0:
                # Check if this internal function needs to be overridden
                if sym.name in internal_overrides:
                    handler = internal_overrides[sym.name]
                    stub_addr = self._alloc_stub(sym.name, handler)
                    uc.mem_write(got_addr, struct.pack("<Q", stub_addr))
                    internal_count += 1
                    continue
                # Internal: point GOT to actual function
                func_addr = BASE_ADDR + sym.value
                uc.mem_write(got_addr, struct.pack("<Q", func_addr))
                internal_count += 1
            else:
                # External: point GOT to our stub
                handler = ext_handlers.get(sym.name, self._h_unimpl)
                stub_addr = self._alloc_stub(sym.name, handler)
                uc.mem_write(got_addr, struct.pack("<Q", stub_addr))
                external_count += 1

        # Also handle non-PLT GOT relocations (R_AARCH64_GLOB_DAT, R_AARCH64_RELATIVE)
        for reloc in self.binary.dynamic_relocations:
            got_addr = BASE_ADDR + reloc.address
            if reloc.type == lief.ELF.Relocation.TYPE.AARCH64_RELATIVE:
                # R_AARCH64_RELATIVE: *got = base + addend
                value = BASE_ADDR + reloc.addend
                try:
                    uc.mem_write(got_addr, struct.pack("<Q", value))
                except:
                    pass
            elif reloc.symbol and reloc.symbol.value > 0:
                func_addr = BASE_ADDR + reloc.symbol.value
                try:
                    uc.mem_write(got_addr, struct.pack("<Q", func_addr))
                except:
                    pass

        print(f"[*] Relocaciones: {internal_count} internas, {external_count} externas")

    # =================== libc implementations ===================

    def _read_string(self, addr, max_len=4096):
        if addr == 0:
            return ""
        try:
            data = bytes(self.uc.mem_read(addr, max_len))
            null = data.find(b'\x00')
            return data[:null].decode('utf-8', errors='replace') if null >= 0 else data.decode('utf-8', errors='replace')
        except:
            return ""

    def _write_string(self, addr, s):
        self.uc.mem_write(addr, s.encode('utf-8') + b'\x00')

    def _ret(self, val=0):
        self.uc.reg_write(UC_ARM64_REG_X0, val & 0xFFFFFFFFFFFFFFFF)
        lr = self.uc.reg_read(UC_ARM64_REG_LR)
        self.uc.reg_write(UC_ARM64_REG_PC, lr)

    # Memory
    def _h_malloc(self, name):
        size = self.uc.reg_read(UC_ARM64_REG_X0)
        ptr = self.heap.malloc(size)
        self._ret(ptr)

    def _h_free(self, name):
        self._ret(0)

    def _h_realloc(self, name):
        old_ptr = self.uc.reg_read(UC_ARM64_REG_X0)
        new_size = self.uc.reg_read(UC_ARM64_REG_X1)
        new_ptr, copy_size = self.heap.realloc(old_ptr, new_size)
        if old_ptr and copy_size > 0 and new_ptr:
            data = self.uc.mem_read(old_ptr, copy_size)
            self.uc.mem_write(new_ptr, bytes(data))
        self._ret(new_ptr)

    def _h_calloc(self, name):
        n = self.uc.reg_read(UC_ARM64_REG_X0)
        size = self.uc.reg_read(UC_ARM64_REG_X1)
        ptr = self.heap.malloc(n * size)
        self._ret(ptr)

    def _h_posix_memalign(self, name):
        memptr = self.uc.reg_read(UC_ARM64_REG_X0)
        alignment = self.uc.reg_read(UC_ARM64_REG_X1)
        size = self.uc.reg_read(UC_ARM64_REG_X2)
        ptr = self.heap.malloc(size + alignment)
        ptr = (ptr + alignment - 1) & ~(alignment - 1)
        self.uc.mem_write(memptr, struct.pack("<Q", ptr))
        self._ret(0)

    def _h_memcpy(self, name):
        dst = self.uc.reg_read(UC_ARM64_REG_X0)
        src = self.uc.reg_read(UC_ARM64_REG_X1)
        n = self.uc.reg_read(UC_ARM64_REG_X2) & 0xFFFFFFFF
        if n > 0 and n < HEAP_SIZE:
            data = self.uc.mem_read(src, n)
            self.uc.mem_write(dst, bytes(data))
        self._ret(dst)

    def _h_memmove(self, name):
        self._h_memcpy(name)  # Our mem_read/mem_write is safe for overlapping

    def _h_memset(self, name):
        dst = self.uc.reg_read(UC_ARM64_REG_X0)
        val = self.uc.reg_read(UC_ARM64_REG_W1) & 0xFF
        n = self.uc.reg_read(UC_ARM64_REG_X2) & 0xFFFFFFFF
        if n > 0 and n < HEAP_SIZE:
            self.uc.mem_write(dst, bytes([val]) * n)
        self._ret(dst)

    def _h_memcmp(self, name):
        a = self.uc.reg_read(UC_ARM64_REG_X0)
        b = self.uc.reg_read(UC_ARM64_REG_X1)
        n = self.uc.reg_read(UC_ARM64_REG_X2) & 0xFFFFFFFF
        if n > 0:
            da = bytes(self.uc.mem_read(a, n))
            db = bytes(self.uc.mem_read(b, n))
            result = (da > db) - (da < db)
        else:
            result = 0
        self._ret(result)

    def _h_memchr(self, name):
        s = self.uc.reg_read(UC_ARM64_REG_X0)
        c = self.uc.reg_read(UC_ARM64_REG_W1) & 0xFF
        n = self.uc.reg_read(UC_ARM64_REG_X2) & 0xFFFFFFFF
        data = bytes(self.uc.mem_read(s, min(n, 0x10000)))
        idx = data.find(bytes([c]))
        self._ret(s + idx if idx >= 0 else 0)

    # String
    def _h_strlen(self, name):
        s = self.uc.reg_read(UC_ARM64_REG_X0)
        text = self._read_string(s)
        self._ret(len(text.encode('utf-8')))

    def _h_strchr(self, name):
        s = self.uc.reg_read(UC_ARM64_REG_X0)
        c = self.uc.reg_read(UC_ARM64_REG_W1) & 0xFF
        text = self._read_string(s, 8192)
        raw = text.encode('utf-8')
        idx = raw.find(bytes([c]))
        self._ret(s + idx if idx >= 0 else 0)

    def _h_strcmp(self, name):
        a = self._read_string(self.uc.reg_read(UC_ARM64_REG_X0))
        b = self._read_string(self.uc.reg_read(UC_ARM64_REG_X1))
        result = (a > b) - (a < b)
        self._ret(result)

    def _h_strncmp(self, name):
        a_addr = self.uc.reg_read(UC_ARM64_REG_X0)
        b_addr = self.uc.reg_read(UC_ARM64_REG_X1)
        n = self.uc.reg_read(UC_ARM64_REG_X2) & 0xFFFFFFFF
        a = self._read_string(a_addr, n)[:n]
        b = self._read_string(b_addr, n)[:n]
        result = (a > b) - (a < b)
        self._ret(result)

    def _h_strcasecmp(self, name):
        a = self._read_string(self.uc.reg_read(UC_ARM64_REG_X0)).lower()
        b = self._read_string(self.uc.reg_read(UC_ARM64_REG_X1)).lower()
        result = (a > b) - (a < b)
        self._ret(result)

    def _h_strncasecmp(self, name):
        n = self.uc.reg_read(UC_ARM64_REG_X2) & 0xFFFFFFFF
        a = self._read_string(self.uc.reg_read(UC_ARM64_REG_X0), n)[:n].lower()
        b = self._read_string(self.uc.reg_read(UC_ARM64_REG_X1), n)[:n].lower()
        result = (a > b) - (a < b)
        self._ret(result)

    def _h_strstr(self, name):
        haystack_addr = self.uc.reg_read(UC_ARM64_REG_X0)
        needle = self._read_string(self.uc.reg_read(UC_ARM64_REG_X1))
        haystack = self._read_string(haystack_addr, 8192)
        idx = haystack.find(needle)
        self._ret(haystack_addr + idx if idx >= 0 else 0)

    def _h_strtol(self, name):
        s = self._read_string(self.uc.reg_read(UC_ARM64_REG_X0))
        try:
            val = int(s.strip(), 0)
        except:
            val = 0
        self._ret(val)

    def _h_strtoul(self, name):
        self._h_strtol(name)

    def _h_atoi(self, name):
        s = self._read_string(self.uc.reg_read(UC_ARM64_REG_X0))
        try:
            val = int(s.strip())
        except:
            val = 0
        self._ret(val)

    def _h_atof(self, name):
        # Returns double in D0 register, but we'll just return 0
        self._ret(0)

    def _h_tolower(self, name):
        c = self.uc.reg_read(UC_ARM64_REG_W0) & 0xFF
        self._ret(c + 32 if 65 <= c <= 90 else c)

    def _h_toupper(self, name):
        c = self.uc.reg_read(UC_ARM64_REG_W0) & 0xFF
        self._ret(c - 32 if 97 <= c <= 122 else c)

    def _h_isalnum(self, name):
        c = self.uc.reg_read(UC_ARM64_REG_W0) & 0xFF
        result = 1 if (48 <= c <= 57 or 65 <= c <= 90 or 97 <= c <= 122) else 0
        self._ret(result)

    # I/O
    def _h_snprintf(self, name):
        # Just return 0 (wrote 0 chars)
        self._ret(0)

    def _h_sscanf(self, name):
        self._ret(0)

    # Time
    def _h_time(self, name):
        t = int(time_module.time())
        ptr = self.uc.reg_read(UC_ARM64_REG_X0)
        if ptr:
            self.uc.mem_write(ptr, struct.pack("<q", t))
        self._ret(t)

    def _h_gettimeofday(self, name):
        t = time_module.time()
        tv_ptr = self.uc.reg_read(UC_ARM64_REG_X0)
        if tv_ptr:
            sec = int(t)
            usec = int((t - sec) * 1000000)
            self.uc.mem_write(tv_ptr, struct.pack("<qq", sec, usec))
        self._ret(0)

    def _h_gmtime_r(self, name):
        # Return a fake tm struct
        tm_ptr = self.uc.reg_read(UC_ARM64_REG_X1)
        if tm_ptr:
            # Fill with current UTC time (simplified)
            import datetime
            now = datetime.datetime.utcnow()
            tm = struct.pack("<9i",
                now.second, now.minute, now.hour,
                now.day, now.month - 1, now.year - 1900,
                now.weekday(), 0, 0)
            self.uc.mem_write(tm_ptr, tm)
        self._ret(tm_ptr)

    def _h_localtime_r(self, name):
        self._h_gmtime_r(name)

    def _h_mktime(self, name):
        self._ret(int(time_module.time()))

    # Threads
    def _h_pthread_once(self, name):
        once_ctrl = self.uc.reg_read(UC_ARM64_REG_X0)
        init_fn = self.uc.reg_read(UC_ARM64_REG_X1)
        # Check if already initialized
        val = struct.unpack("<I", bytes(self.uc.mem_read(once_ctrl, 4)))[0]
        if val == 0:
            self.uc.mem_write(once_ctrl, struct.pack("<I", 1))
            # We need to call init_fn - save LR, set it, and let it run
            # For simplicity, just skip the init function
            pass
        self._ret(0)

    def _h_pthread_key_create(self, name):
        key_ptr = self.uc.reg_read(UC_ARM64_REG_X0)
        key_id = self.tls_key_counter
        self.tls_key_counter += 1
        self.tls_keys[key_id] = 0
        self.uc.mem_write(key_ptr, struct.pack("<I", key_id))
        self._ret(0)

    def _h_pthread_getspecific(self, name):
        key = self.uc.reg_read(UC_ARM64_REG_W0)
        val = self.tls_keys.get(key, 0)
        self._ret(val)

    def _h_pthread_setspecific(self, name):
        key = self.uc.reg_read(UC_ARM64_REG_W0)
        val = self.uc.reg_read(UC_ARM64_REG_X1)
        self.tls_keys[key] = val
        self._ret(0)

    # System
    def _h_stack_chk_fail(self, name):
        print("[!] __stack_chk_fail llamado - stack canary corrupto!")
        self.uc.emu_stop()

    def _h_errno(self, name):
        # Return pointer to a fake errno variable
        errno_addr = TLS_ADDR + 0x100
        self._ret(errno_addr)

    def _h_assert(self, name):
        file = self._read_string(self.uc.reg_read(UC_ARM64_REG_X0))
        line = self.uc.reg_read(UC_ARM64_REG_W1)
        func = self._read_string(self.uc.reg_read(UC_ARM64_REG_X2))
        expr = self._read_string(self.uc.reg_read(UC_ARM64_REG_X3))
        print(f"[!] ASSERT FAILED: {expr} at {file}:{line} ({func})")
        self.uc.emu_stop()

    def _h_abort(self, name):
        print("[!] abort() llamado!")
        self.uc.emu_stop()

    def _h_strerror(self, name):
        err_str = self.heap.malloc(32)
        self._write_string(err_str, "Unknown error")
        self._ret(err_str)

    # Generic
    def _h_nop(self, name):
        lr = self.uc.reg_read(UC_ARM64_REG_LR)
        self.uc.reg_write(UC_ARM64_REG_PC, lr)

    def _h_nop_ret0(self, name):
        self._ret(0)

    def _h_ret1(self, name):
        self._ret(1)

    def _h_ret_neg1(self, name):
        self._ret(0xFFFFFFFFFFFFFFFF)

    def _h_chilkat_unlock(self, name):
        """CkGlobal_UnlockBundle → return 1 (success)."""
        self._ret(1)

    def _h_unimpl(self, name):
        if self.verbose:
            print(f"    [STUB] {name}() not implemented → 0")
        self._ret(0)

    # =================== Crypto overrides (Python AES + RSA) ===================

    def _h_ckcrypt2_set_encoded_key(self, name):
        """Capture AES key from CkCrypt2_SetEncodedKey(crypt, keyStr, encoding)."""
        x1 = self.uc.reg_read(UC_ARM64_REG_X1)
        key_str = self._read_string(x1, 256)
        self._aes_key_hex = key_str
        call_num = self.call_count.get(name, 0)
        print(f"  >> [CRYPTO] {name}[{call_num}]: key={key_str}")
        lr = self.uc.reg_read(UC_ARM64_REG_LR)
        self.uc.reg_write(UC_ARM64_REG_PC, lr)

    def _h_ckcrypt2_set_encoded_iv(self, name):
        """Capture AES IV from CkCrypt2_SetEncodedIV(crypt, ivStr, encoding)."""
        x1 = self.uc.reg_read(UC_ARM64_REG_X1)
        iv_str = self._read_string(x1, 256)
        self._aes_iv_hex = iv_str
        call_num = self.call_count.get(name, 0)
        print(f"  >> [CRYPTO] {name}[{call_num}]: iv={iv_str}")
        lr = self.uc.reg_read(UC_ARM64_REG_LR)
        self.uc.reg_write(UC_ARM64_REG_PC, lr)

    def _h_ckcrypt2_decrypt_string_enc(self, name):
        """Python AES-CBC-256 decrypt for CkCrypt2_decryptStringENC(crypt, hexInput)."""
        x1 = self.uc.reg_read(UC_ARM64_REG_X1)
        hex_input = self._read_string(x1, 65536)
        call_num = self.call_count.get(name, 0)

        if not self._aes_key_hex or not self._aes_iv_hex or not hex_input:
            print(f"  >> [CRYPTO] {name}[{call_num}] → NULL (missing key/iv/input)")
            self._ret(0)
            return

        try:
            key = unhexlify(self._aes_key_hex)
            iv = unhexlify(self._aes_iv_hex)
            ct = unhexlify(hex_input)

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ct) + decryptor.finalize()

            # PKCS7 unpadding
            pad = plaintext[-1]
            if 1 <= pad <= 16 and all(b == pad for b in plaintext[-pad:]):
                plaintext = plaintext[:-pad]

            result_bytes = plaintext + b'\x00'
            ptr = self.heap.malloc(len(result_bytes))
            self.uc.mem_write(ptr, result_bytes)

            result_str = plaintext.decode('utf-8', errors='replace')
            print(f"  >> [CRYPTO] {name}[{call_num}] → {len(result_str)} chars ({len(hex_input)//2}B cipher → {len(plaintext)}B plain)")
            if '<RSA' in result_str:
                print(f"     (RSA key XML)")
            elif len(result_str) < 100:
                print(f"     \"{result_str}\"")
            else:
                print(f"     \"{result_str[:60]}...\"")
            self._ret(ptr)
        except Exception as e:
            print(f"  >> [CRYPTO] {name}[{call_num}] → ERROR: {e}")
            self._ret(0)

    def _h_rsa_import_public_key(self, name):
        """Capture RSA public key from CkRsa_ImportPublicKey(rsa, xmlKey)."""
        rsa_obj = self.uc.reg_read(UC_ARM64_REG_X0)
        x1 = self.uc.reg_read(UC_ARM64_REG_X1)
        key_xml = self._read_string(x1, 16384)
        call_num = self.call_count.get(name, 0)

        if key_xml and '<RSAPublicKey>' in key_xml:
            try:
                root = ET.fromstring(key_xml)
                mod_b64 = root.find("Modulus").text
                exp_b64 = root.find("Exponent").text
                n = int.from_bytes(base64.b64decode(mod_b64), 'big')
                e = int.from_bytes(base64.b64decode(exp_b64), 'big')
                key_size = len(base64.b64decode(mod_b64))
                self._rsa_keys[rsa_obj] = (n, e, key_size)
                print(f"  >> [CRYPTO] {name}[{call_num}]: {key_size*8}-bit key for rsa=0x{rsa_obj:x}")
                self._ret(1)
            except Exception as ex:
                print(f"  >> [CRYPTO] {name}[{call_num}] parse error: {ex}")
                self._ret(0)
        else:
            print(f"  >> [CRYPTO] {name}[{call_num}]: no valid XML (x1=0x{x1:x})")
            self._ret(0)

    def _h_rsa_decrypt_string_enc(self, name):
        """Python RSA decrypt for CkRsa_decryptStringENC(rsa, b64Input, usePrivate)."""
        rsa_obj = self.uc.reg_read(UC_ARM64_REG_X0)
        x1 = self.uc.reg_read(UC_ARM64_REG_X1)
        enc_str = self._read_string(x1, 65536)
        call_num = self.call_count.get(name, 0)

        key_info = self._rsa_keys.get(rsa_obj)
        if not key_info:
            print(f"  >> [CRYPTO] {name}[{call_num}] → NULL (no key for rsa=0x{rsa_obj:x})")
            self._ret(0)
            return
        if not enc_str:
            print(f"  >> [CRYPTO] {name}[{call_num}] → NULL (no input)")
            self._ret(0)
            return

        n, e, key_size = key_info
        try:
            ct = base64.b64decode(enc_str)
        except Exception as ex:
            print(f"  >> [CRYPTO] {name}[{call_num}] → NULL (base64 error: {ex})")
            self._ret(0)
            return

        # Multi-block RSA decrypt
        nblocks = len(ct) // key_size
        if len(ct) % key_size != 0:
            print(f"  >> [CRYPTO] {name}[{call_num}] → NULL ({len(ct)}B not multiple of {key_size}B key)")
            self._ret(0)
            return

        result = b""
        for i in range(nblocks):
            block = ct[i * key_size:(i + 1) * key_size]
            c_int = int.from_bytes(block, 'big')
            m_int = pow(c_int, e, n)
            raw = m_int.to_bytes(key_size, 'big')

            # Strip PKCS#1 v1.5 padding
            if raw[0] == 0x00 and raw[1] in (0x01, 0x02):
                found = False
                for j in range(2, len(raw)):
                    if raw[j] == 0x00:
                        result += raw[j + 1:]
                        found = True
                        break
                if not found:
                    print(f"  >> [CRYPTO] {name}[{call_num}] block {i}: no PKCS#1 null separator")
                    self._ret(0)
                    return
            else:
                print(f"  >> [CRYPTO] {name}[{call_num}] block {i}: invalid PKCS#1 header [{raw[0]:02x} {raw[1]:02x}]")
                self._ret(0)
                return

        result_bytes = result + b'\x00'
        ptr = self.heap.malloc(len(result_bytes))
        self.uc.mem_write(ptr, result_bytes)
        result_str = result.decode('utf-8', errors='replace')

        print(f"  >> [CRYPTO] {name}[{call_num}] → {len(result_str)} chars ({nblocks} blocks)")
        if '<RSA' in result_str:
            print(f"     (RSA key XML)")
        elif len(result_str) < 100:
            print(f"     \"{result_str}\"")
        else:
            print(f"     \"{result_str[:60]}...\"")
        self._ret(ptr)

    def _h_rsa_decrypt_bd(self, name):
        """Override CkRsa_DecryptBd → return 1 (success, data was pre-injected)."""
        call_num = self.call_count.get(name, 0)
        print(f"  >> [CRYPTO] {name}[{call_num}] → 1 (success, data pre-injected)")
        self._ret(1)

    def _h_new_jstring_from_bytes(self, name):
        """Capture biographical text from newJStringFromBytes."""
        data_ptr = self.uc.reg_read(UC_ARM64_REG_X1)
        length = self.uc.reg_read(UC_ARM64_REG_W2) & 0xFFFFFFFF
        if data_ptr and length > 0 and length < 0x100000:
            data = bytes(self.uc.mem_read(data_ptr, length))
            text = data.decode('utf-8', errors='replace')
            print(f"  >> [CAPTURE] newJStringFromBytes: {length} bytes")
            if len(text) < 500:
                print(f"     {text}")
            else:
                print(f"     {text[:300]}...")
            self.result_string = text
            self._ret(data_ptr)
        else:
            print(f"  >> [CAPTURE] newJStringFromBytes: empty (ptr=0x{data_ptr:x}, len={length})")
            self._ret(0)

    def _h_str_concat(self, name):
        """strConcat(s1, s2) → allocate and return concatenated string."""
        s1 = self._read_string(self.uc.reg_read(UC_ARM64_REG_X0))
        s2 = self._read_string(self.uc.reg_read(UC_ARM64_REG_X1))
        result = s1 + s2
        if result:
            raw = result.encode('utf-8') + b'\x00'
            ptr = self.heap.malloc(len(raw))
            self.uc.mem_write(ptr, raw)
            self._ret(ptr)
        else:
            self._ret(0)

    def _hook_return(self, name):
        """Trap for when pc() returns."""
        x0 = self.uc.reg_read(UC_ARM64_REG_X0)
        if x0:
            try:
                data = bytes(self.uc.mem_read(x0, 65536))
                null = data.find(b'\x00')
                if null > 0:
                    raw = data[:null]
                    self.result_string = raw.decode('utf-8', errors='replace')
                    self.result_raw = raw
                    # Save raw bytes
                    out_path = os.path.join(OUTPUT_DIR, "pc_return_raw.bin")
                    with open(out_path, "wb") as f:
                        f.write(raw)
                    print(f"  [RETURN] pc() → {len(raw)} bytes saved to pc_return_raw.bin")
            except:
                pass
        self.uc.emu_stop()

    def _on_interrupt(self, uc, intno, user_data):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        if pc in self.stub_hooks:
            name, handler = self.stub_hooks[pc]
            self.call_count[name] = self.call_count.get(name, 0) + 1
            handler(name)
        else:
            print(f"[!] Unhandled interrupt at PC=0x{pc:x}")
            uc.emu_stop()

    def _on_unmapped(self, uc, access, addr, size, value, user_data):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        atype = {1: "READ", 2: "WRITE", 3: "FETCH"}.get(access, f"ACCESS({access})")
        print(f"[!] Unmapped {atype}: 0x{addr:x} (size={size}) at PC=0x{pc:x}")
        # Try to map
        page = addr & ~0xFFF
        try:
            uc.mem_map(page, 0x10000, UC_PROT_ALL)
            return True
        except:
            return False

    def run(self):
        print("=" * 70)
        print("  INE QR Decoder — ARM64 Emulation via Unicorn Engine")
        print("=" * 70)

        self.setup_memory()
        self._precompute_rsa_results()
        self.apply_relocations()

        # Load QR data
        with open(QR_LEFT, "rb") as f:
            left = f.read()
        with open(QR_RIGHT, "rb") as f:
            right = f.read()

        combined = left[2:] + right[2:]
        print(f"[*] Payload: {len(combined)} bytes (izq={len(left)}, der={len(right)})")
        self.uc.mem_write(DATA_ADDR, combined)

        # Write decrypted buf2 to known address for injection
        self._decrypted_buf2_addr = 0
        if self._decrypted_buf2:
            self._decrypted_buf2_addr = DATA_ADDR + 0x2000
            self.uc.mem_write(self._decrypted_buf2_addr, self._decrypted_buf2)
            print(f"[*] Decrypted buf2 at 0x{self._decrypted_buf2_addr:x} ({len(self._decrypted_buf2)} bytes)")

        uc = self.uc

        # Set up call to internal pc() at 0x1dcd40
        pc_func = BASE_ADDR + 0x1dcd40

        uc.reg_write(UC_ARM64_REG_SP, STACK_ADDR - 0x1000)
        uc.reg_write(UC_ARM64_REG_X0, 0)           # env (not used after license patches)
        uc.reg_write(UC_ARM64_REG_X1, 0)           # thiz
        uc.reg_write(UC_ARM64_REG_X2, 0)           # activity
        uc.reg_write(UC_ARM64_REG_X3, DATA_ADDR)   # data
        uc.reg_write(UC_ARM64_REG_W4, len(combined))  # length
        uc.reg_write(UC_ARM64_REG_W5, 0x309)       # magic
        uc.reg_write(UC_ARM64_REG_LR, RETURN_ADDR)

        # Hooks
        uc.hook_add(UC_HOOK_INTR, self._on_interrupt)
        uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._on_unmapped)

        # No per-instruction counter — the trace_calls hook below covers what we need

        # Patch: NOP the Chilkat license check branch
        # At 0x1dcde4: b.ne -> NOP (skip error if CkGlobal_UnlockBundle fails)
        nop = struct.pack("<I", 0xD503201F)  # NOP instruction
        uc.mem_write(BASE_ADDR + 0x1dcde4, nop)
        print("[*] Patched: Chilkat license check bypassed (NOP at 0x1dcde4)")

        # Also patch the CkGlobal_Dispose call and the CMP before it
        # to avoid issues with the CkGlobal object
        # Actually let's also NOP the cmp w23, #1 to be safe
        # 0x1dcde0: cmp w23, #1 → NOP it too
        uc.mem_write(BASE_ADDR + 0x1dcde0, nop)

        # Trace specific known call sites in pc() and their return points
        # Format: offset_in_so -> (before_call_name, after_call_name_for_return)
        call_sites = {
            # Chilkat Global
            0x1dcdc0: "CkGlobal_Create",
            0x1dcdd0: "CkGlobal_UnlockBundle",
            0x1dcddc: "CkGlobal_Dispose",
            # memcpy splits
            0x1dcdf8: "memcpy(buf1, data, 688)",
            0x1dce08: "memcpy(buf2, data+688, 1024)",
            # CkCrypt2 AES setup
            0x1dce0c: "CkCrypt2_Create",
            0x1dce1c: "CkCrypt2_putCryptAlgorithm",
            0x1dce2c: "CkCrypt2_putCipherMode",
            0x1dce38: "CkCrypt2_putKeyLength",
            0x1dce44: "CkCrypt2_putPaddingScheme",
            0x1dce58: "CkCrypt2_putEncodingMode",
            # SetEncodedIV
            0x1dcf78: "CkCrypt2_SetEncodedIV",
            # SetEncodedKey (multiple locations)
            0x1dd1e4: "CkCrypt2_SetEncodedKey[1]",
            0x1dd674: "CkCrypt2_SetEncodedKey[2]",
            0x1ddbf8: "CkCrypt2_SetEncodedKey[3]",
            # CkRsa_Create
            0x1dd1e8: "CkRsa_Create[1]",
            0x1dd20c: "CkRsa_Create[2]",
            0x1dd678: "CkRsa_Create[3]",
            0x1dd69c: "CkRsa_Create[4]",
            0x1ddbfc: "CkRsa_Create[5]",
            # AES decrypt
            0x1dd1fc: "CkCrypt2_decryptStringENC[1]",
            0x1dd220: "CkCrypt2_decryptStringENC[2]",
            0x1dd68c: "CkCrypt2_decryptStringENC[3]",
            0x1dd6b0: "CkCrypt2_decryptStringENC[4]",
            0x1ddc10: "CkCrypt2_decryptStringENC[5]",
            # RSA ImportPublicKey
            0x1dd208: "CkRsa_ImportPublicKey[1]",
            0x1dd23c: "CkRsa_ImportPublicKey[2]",
            0x1dd698: "CkRsa_ImportPublicKey[3]",
            0x1dd6cc: "CkRsa_ImportPublicKey[4]",
            0x1ddc1c: "CkRsa_ImportPublicKey[5]",
            # RSA decrypt (ACTUAL addresses from disassembly)
            0x1dd230: "CkRsa_decryptStringENC[1]",  # RSA decrypt with key1 → get key2
            # BinData operations — first pipeline
            0x1dd240: "CkBinData_Create[1]",
            0x1dd250: "CkBinData_AppendBinary2[1](buf2,1024)",
            0x1dd260: "CkRsa_DecryptBd[1]",
            0x1dd26c: "CkRsa_getLastMethodSuccess[1]",
            0x1dd27c: "CkBinData_Create[2]",
            0x1dd28c: "CkBinData_AppendBinary2[2](buf1,688)",
            # BinData operations — second pipeline (after SIMD key derivation)
            0x1dd6d0: "CkBinData_Create[3]",
            0x1dd6e0: "CkBinData_AppendBinary2[3](stack,1024)",
            0x1dd6f4: "CkRsa_DecryptBd[2]",
            0x1dd704: "CkRsa_getLastMethodSuccess[2]",
            # Hash
            0x1dd854: "CkEcc_Create",
            0x1dd85c: "CkPublicKey_Create",
            # ECDSA verify
            0x1dd340: "CkEcc_VerifyHashENC",
        }

        return_captures = {}
        captured_strings = {}  # name -> full string

        def trace_calls(uc, addr, size, _):
            so_offset = addr - BASE_ADDR
            if so_offset in call_sites:
                name = call_sites[so_offset]
                x0 = uc.reg_read(UC_ARM64_REG_X0)
                x1 = uc.reg_read(UC_ARM64_REG_X1)
                w2 = uc.reg_read(UC_ARM64_REG_W2)
                # Try to read string args
                x1_str = ""
                if x1 and "put" in name.lower() or "Import" in name or "LoadXml" in name or "Bundle" in name or "ENC" in name or "Key" in name or "IV" in name:
                    try:
                        s = self._read_string(x1, 200)
                        if s and len(s) < 150:
                            x1_str = f'  x1="{s}"'
                        elif s:
                            x1_str = f'  x1="{s[:60]}..."'
                    except:
                        pass
                w2_str = f"  w2={w2}" if "KeyLength" in name or "Padding" in name else ""
                print(f"  >> {name}  x0=0x{x0:x}{x1_str}{w2_str}")

                # Redirect AppendBinary2[1](buf2,1024) → use decrypted buf2 instead
                if "AppendBinary2[1]" in name and self._decrypted_buf2_addr:
                    uc.reg_write(UC_ARM64_REG_X1, self._decrypted_buf2_addr)
                    uc.reg_write(UC_ARM64_REG_W2, len(self._decrypted_buf2))
                    print(f"     [REDIRECT] buf2 → decrypted ({len(self._decrypted_buf2)} bytes) at 0x{self._decrypted_buf2_addr:x}")

                # Redirect AppendBinary2[3](stack,1024) → RSA decrypt with key #4
                if "AppendBinary2[3]" in name and x1 and w2 > 0:
                    # Read the 1024 bytes from the stack buffer
                    try:
                        stack_buf = bytes(uc.mem_read(x1, w2))
                        # Find the last imported RSA key (key #4)
                        if self._rsa_keys:
                            last_key = list(self._rsa_keys.values())[-1]
                            n4, e4, ks4 = last_key
                            c_int = int.from_bytes(stack_buf, 'big')
                            m_int = pow(c_int, e4, n4)
                            raw = m_int.to_bytes(ks4, 'big')
                            # Strip PKCS#1 v1.5 padding
                            decrypted = None
                            if raw[0] == 0x00 and raw[1] in (0x01, 0x02):
                                for j in range(2, len(raw)):
                                    if raw[j] == 0x00:
                                        decrypted = raw[j + 1:]
                                        break
                            if decrypted:
                                dec_addr = DATA_ADDR + 0x3000
                                uc.mem_write(dec_addr, decrypted)
                                uc.reg_write(UC_ARM64_REG_X1, dec_addr)
                                uc.reg_write(UC_ARM64_REG_W2, len(decrypted))
                                print(f"     [REDIRECT] stack buf → RSA key4 decrypted ({len(decrypted)} bytes) at 0x{dec_addr:x}")
                                print(f"     PKCS#1 type {raw[1]}, plaintext[:32]={decrypted[:32].hex()}")
                            else:
                                print(f"     [!] RSA key4 decrypt: invalid PKCS#1 header [{raw[0]:02x} {raw[1]:02x}]")
                        else:
                            print(f"     [!] No RSA keys available for AppendBinary2[3] decrypt")
                    except Exception as ex:
                        print(f"     [!] AppendBinary2[3] RSA decrypt error: {ex}")

                # Capture data for CkBinData_AppendBinary2 calls
                if "AppendBinary2" in name and x1 and w2 > 0:
                    try:
                        actual_x1 = uc.reg_read(UC_ARM64_REG_X1)
                        actual_w2 = uc.reg_read(UC_ARM64_REG_W2)
                        captured_data = bytes(uc.mem_read(actual_x1, actual_w2))
                        fname = f"captured_data_{name.replace('[','_').replace(']','').replace('(','_').replace(')','').replace(',','_')}.bin"
                        fpath = os.path.join(OUTPUT_DIR, fname)
                        with open(fpath, "wb") as ff:
                            ff.write(captured_data)
                        print(f"     DATOS: {actual_w2} bytes guardados en {fname}")
                    except Exception as ex:
                        print(f"     DATOS: error capturando: {ex}")

                # Register return capture at the next instruction (addr+4)
                return_captures[addr + 4] = name

            if addr - BASE_ADDR == 0x1ddf04:
                print(f"  !! ERROR: x0 set to NULL at so+0x1ddf04")

            if (addr - BASE_ADDR) in return_captures:
                orig_addr = (addr - BASE_ADDR)
            if addr in return_captures:
                name = return_captures.pop(addr)
                x0 = uc.reg_read(UC_ARM64_REG_X0)
                ret_str = ""
                if x0:
                    try:
                        s = self._read_string(x0, 16384)  # Read up to 16KB
                        if s:
                            captured_strings[name] = s
                            if len(s) < 150:
                                ret_str = f'  → "{s}"'
                            else:
                                ret_str = f'  → "{s[:60]}..."'
                        else:
                            ret_str = f"  → 0x{x0:x}"
                    except:
                        ret_str = f"  → 0x{x0:x}"
                else:
                    ret_str = "  → NULL"
                print(f"     RET{ret_str}")

        # Scope hook to just the pc() function range (0x1dcdc0..0x1de000) for performance
        pc_range_start = BASE_ADDR + 0x1dcdc0
        pc_range_end = BASE_ADDR + 0x1de000
        uc.hook_add(UC_HOOK_CODE, trace_calls, begin=pc_range_start, end=pc_range_end)

        print(f"\n[*] Ejecutando pc() en 0x{pc_func:x}...")
        start = time_module.time()

        try:
            uc.emu_start(pc_func, RETURN_ADDR + 4, timeout=120_000_000)  # 2 min
        except UcError as e:
            pc = uc.reg_read(UC_ARM64_REG_PC)
            print(f"\n[!] Error: {e} en PC=0x{pc:x}")

            # Disassemble at error location
            try:
                code = bytes(uc.mem_read(pc, 16))
                for insn in self.cs.disasm(code, pc):
                    print(f"    → {insn.mnemonic}\t{insn.op_str}")
                    break
            except:
                pass

        elapsed = time_module.time() - start
        print(f"\n[*] Emulación completada en {elapsed:.1f}s")

        # Top called functions
        top = sorted(self.call_count.items(), key=lambda x: -x[1])[:20]
        if top:
            print(f"\n[*] Top funciones llamadas:")
            for name, count in top:
                print(f"    {count:6d}x  {name}")

        # Dump captured data
        print(f"\n{'='*70}")
        print("  DATOS CAPTURADOS DE LA EMULACION")
        print(f"{'='*70}")

        output_dir = OUTPUT_DIR
        os.makedirs(output_dir, exist_ok=True)
        import json

        if captured_strings:
            print(f"\n  {len(captured_strings)} strings capturadas:")
            for name, s in captured_strings.items():
                print(f"    {name}: {len(s)} chars")
                # Save each to file
                fname = name.replace("[", "_").replace("]", "").replace(" ", "_")
                path = os.path.join(output_dir, f"captured_{fname}.txt")
                with open(path, "w", encoding="utf-8") as f:
                    f.write(s)
                print(f"      → {path}")
        else:
            print("  No se capturaron strings.")

        # Result
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        print(f"\n[*] Retorno X0 = 0x{x0:x}")

        if hasattr(self, 'result_raw') and self.result_raw:
            raw = self.result_raw
            print(f"\n{'='*70}")
            print("  DATOS DESCIFRADOS DEL QR")
            print(f"{'='*70}")
            print(f"  Total: {len(raw)} bytes")
            print(f"  Hex[0:64]: {raw[:64].hex()}")
            print(f"  Hex[-32:]: {raw[-32:].hex()}")

            # Check if it's base64
            b64_chars = set(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
            is_b64 = all(b in b64_chars for b in raw)
            if is_b64:
                print(f"\n  Formato: BASE64 ({len(raw)} chars)")
                try:
                    decoded = base64.b64decode(raw)
                    print(f"  Decodificado: {len(decoded)} bytes")
                    print(f"  Hex[0:64]: {decoded[:64].hex()}")
                    # Save decoded
                    dec_path = os.path.join(output_dir, "pc_return_decoded.bin")
                    with open(dec_path, "wb") as f:
                        f.write(decoded)
                    print(f"  Guardado: pc_return_decoded.bin")

                    # Check for pipe separators
                    if b'|' in decoded:
                        text_end = decoded.find(b'\x00')
                        if text_end < 0:
                            text_end = len(decoded)
                        text = decoded[:text_end].decode('utf-8', errors='replace')
                        print(f"\n  Texto con pipes encontrado:")
                        fields = text.split('|')
                        labels = ["tipo", "cic", "ocr", "curp", "nombre", "apellido1", "apellido2",
                                  "entidad", "municipio", "seccion", "etnia", "vigencia", "sexo",
                                  "indiceHuella1", "indiceHuella2", "version", "fechaGeneracion",
                                  "firmaVerificadora"]
                        for i, val in enumerate(fields):
                            label = labels[i] if i < len(labels) else f"campo_{i}"
                            if len(val) > 80:
                                print(f"    {label}: {val[:60]}... ({len(val)} chars)")
                            else:
                                print(f"    {label}: {val}")

                    # Check for RIFF/WEBP
                    riff_pos = decoded.find(b'RIFF')
                    if riff_pos >= 0:
                        print(f"\n  WebP encontrado en offset {riff_pos}")
                        webp_size = int.from_bytes(decoded[riff_pos+4:riff_pos+8], 'little') + 8
                        print(f"  WebP tamaño: {webp_size} bytes")
                        webp_path = os.path.join(output_dir, "foto_ine.webp")
                        with open(webp_path, "wb") as f:
                            f.write(decoded[riff_pos:riff_pos+webp_size])
                        print(f"  Guardado: foto_ine.webp")
                except Exception as e:
                    print(f"  Error decodificando base64: {e}")
            else:
                # Not base64 — check for pipe separators directly
                if b'|' in raw:
                    text = raw.decode('utf-8', errors='replace')
                    print(f"\n  Texto con pipes:")
                    fields = text.split('|')
                    labels = ["tipo", "cic", "ocr", "curp", "nombre", "apellido1", "apellido2",
                              "entidad", "municipio", "seccion", "etnia", "vigencia", "sexo"]
                    for i, val in enumerate(fields):
                        label = labels[i] if i < len(labels) else f"campo_{i}"
                        if len(val) > 80:
                            print(f"    {label}: {val[:60]}... ({len(val)} chars)")
                        else:
                            print(f"    {label}: {val}")
                else:
                    # Show printable chars
                    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw[:200])
                    print(f"  Printable[0:200]: {printable}")
                    # Check for RIFF in raw
                    riff_pos = raw.find(b'RIFF')
                    if riff_pos >= 0:
                        print(f"\n  RIFF/WebP header en offset {riff_pos}")
        elif x0:
            try:
                data = bytes(uc.mem_read(x0, 4096))
                null = data.find(b'\x00')
                if null > 0:
                    s = data[:null].decode('utf-8', errors='replace')
                    print(f"  String: {s}")
            except:
                pass


if __name__ == "__main__":
    emu = INEEmulator()
    emu.run()
