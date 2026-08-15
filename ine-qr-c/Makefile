# ──────────────────────────────────────────────────────────────────────
# Build targets:
#
#   make             — `ine_decode` CLI (pure-C path).
#                      ~175 KB binary, ~2 ms crypto, runs on x86 + ARM.
#
#   make lib         — `libine_decode.a` static archive for embedding via
#                      FFI in another process. Bundles the crypto +
#                      QR extraction + output decoding without main.o.
# ──────────────────────────────────────────────────────────────────────

CC      = gcc
CXX     = g++
AR      = ar
BREW    = $(shell brew --prefix 2>/dev/null)

OPENSSL_CFLAGS  = $(shell pkg-config --cflags openssl 2>/dev/null || echo "-I$(BREW)/opt/openssl@3/include")
OPENSSL_LDFLAGS = $(shell pkg-config --libs openssl 2>/dev/null || echo "-L$(BREW)/opt/openssl@3/lib -lssl -lcrypto")

ZXING_CXXFLAGS  = $(shell pkg-config --cflags zxing 2>/dev/null)
ZXING_LDFLAGS   = $(shell pkg-config --libs   zxing 2>/dev/null || echo "-lZXing")

POSIX_DEFS = -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -D_DARWIN_C_SOURCE

# -fPIC keeps every translation unit position-independent so the same .o
# files can populate libine_decode.a for FFI callers and the CLI binary.
CFLAGS   = -O2 -g -Wall -Wextra -std=c17 -fPIC \
           $(POSIX_DEFS) \
           -I./include -I./vendor \
           $(OPENSSL_CFLAGS)

CXXFLAGS = -O2 -g -Wall -std=c++17 -fPIC \
           $(POSIX_DEFS) \
           -I./include -I./vendor \
           $(OPENSSL_CFLAGS) \
           $(ZXING_CXXFLAGS)

LDFLAGS  = $(OPENSSL_LDFLAGS) \
           $(ZXING_LDFLAGS) \
           -lstdc++ -lm -lpthread

# ── Pure-C path objects (shared between CLI binary and library) ───────
# crypto_backend_openssl.o satisfies ine_crypto_backend.h with OpenSSL.
# vendor/base64.o is the public-domain base64 decoder used on every
# platform — replaces an OpenSSL BIO path that BoringSSL has deprecated.
LIB_OBJS = src/ine_lib.o \
           src/no_so_crypto.o \
           src/crypto_backend_openssl.o \
           src/output_decode.o \
           src/qr_extract.o \
           vendor/base64.o

CLI_OBJS = src/main.o $(LIB_OBJS)

.PHONY: all clean lib

all: ine_decode

ine_decode: $(CLI_OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS)

# Static archive for FFI consumers — does NOT include main.o, so the host
# binary supplies its own entry point. Link order (zxing, openssl, stdc++)
# is the consumer's responsibility.
lib: libine_decode.a

libine_decode.a: $(LIB_OBJS)
	$(AR) rcs $@ $^

src/qr_extract.o: src/qr_extract.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(CLI_OBJS) ine_decode libine_decode.a
