# Makefile — INE QR Decoder HTTP API in Eskiu.
#
# Builds the Eskiu server (.esk → object via eskiuc) and links it with the
# *portable* QR extractor reused from ine-qr-c (stb_image + zxing-cpp), so the
# binary builds on Linux (Docker) as well as macOS — no CoreGraphics.
#
#   make            # build ./ine_qr_eskiu
#   make test       # crypto+output parity against output/qr_*.bin (needs only -lcrypto)
#   make clean
#
# Override eskiuc if it lives elsewhere:
#   make ESKIUC=/path/to/eskiuc

ESKIUC ?= eskiuc
CC     ?= cc
CXX    ?= c++

# Extra eskiuc flags. `make safe` sets --safe to bounds-check every array/slice
# index (traps on an out-of-range access from a malformed/adversarial QR).
ESKIU_FLAGS ?=

# reuse ine-qr-c's portable qr_extract.cpp + vendored stb headers
INE_C  := ../ine-qr-c

UNAME  := $(shell uname -s)
ifeq ($(UNAME),Darwin)
  OPENSSL := $(shell brew --prefix openssl@3 2>/dev/null || brew --prefix openssl)
  ZXING   := $(shell brew --prefix zxing-cpp)
  CXXINC  := -I$(INE_C)/include -I$(ZXING)/include
  LIBS    := -L$(OPENSSL)/lib -lcrypto -L$(ZXING)/lib -lZXing -lpthread
else
  CXXINC  := -I$(INE_C)/include -I/usr/local/include
  LIBS    := -L/usr/local/lib -lcrypto -lZXing -lpthread -lm
endif

OBJS := main.o qr_extract.o qr_extract_impl.o

all: ine_qr_eskiu

# Eskiu server → object. main.esk pulls in src/*.esk + decoder/*.esk + stdlib.
main.o: src/main.esk src/ratelimit.esk src/decode_api.esk \
        decoder/pipeline.esk decoder/crypto.esk decoder/output.esk decoder/types.esk decoder/extern.esk
	$(ESKIUC) $(ESKIU_FLAGS) src/main.esk -o main.o

# Eskiu→C adapter: ine_qr_extract → ine-qr-c's qr_extract.
qr_extract.o: decoder/qr_extract.c
	$(CC) -O2 -I$(INE_C)/include -c decoder/qr_extract.c -o qr_extract.o

# ine-qr-c's portable extractor (stb_image + zxing). Its "../vendor/stb_image.h"
# include resolves against ine-qr-c/src, so the vendored headers are picked up.
qr_extract_impl.o: $(INE_C)/src/qr_extract.cpp
	$(CXX) -std=c++17 -O2 $(CXXINC) -c $(INE_C)/src/qr_extract.cpp -o qr_extract_impl.o

ine_qr_eskiu: $(OBJS)
	$(CXX) $(OBJS) $(LIBS) -o ine_qr_eskiu

# Parity check for the pure-Eskiu crypto+output stages (no QR shim needed).
test: tests/pipeline_test.esk
	$(ESKIUC) tests/pipeline_test.esk -o /tmp/ine_pt $(LIBS)
	cd .. && /tmp/ine_pt

# Hardened build: bounds-check every index. Off by default (zero cost in the
# normal build); recommended when decoding untrusted / attacker-supplied images.
safe:
	$(MAKE) clean
	$(MAKE) ESKIU_FLAGS=--safe ine_qr_eskiu

clean:
	rm -f $(OBJS) ine_qr_eskiu /tmp/ine_pt

.PHONY: all test safe clean

.PHONY: all test clean
