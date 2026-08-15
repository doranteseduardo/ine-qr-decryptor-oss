# Makefile — INE QR decoder pipeline in Eskiu.
#
# Builds the parity test (.esk → binary via eskiuc), which runs the pure-Eskiu
# crypto + output stages against the pre-extracted QR payloads in output/ and
# must agree byte-for-byte with the C reference.
#
#   make            # build + run the parity test
#   make objects    # compile the C adapter to ine-qr-c's portable QR extractor
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

all: test

# Parity check for the pure-Eskiu crypto+output stages (no QR shim needed).
test: tests/pipeline_test.esk decoder/pipeline.esk decoder/crypto.esk \
      decoder/output.esk decoder/types.esk decoder/extern.esk
	$(ESKIUC) $(ESKIU_FLAGS) tests/pipeline_test.esk -o /tmp/ine_pt $(LIBS)
	cd .. && /tmp/ine_pt

# The image path: Eskiu→C adapter plus ine-qr-c's portable extractor
# (stb_image + zxing). Built separately since the parity test feeds the
# pipeline pre-extracted payloads and needs neither.
objects: qr_extract.o qr_extract_impl.o

qr_extract.o: decoder/qr_extract.c
	$(CC) -O2 -I$(INE_C)/include -c decoder/qr_extract.c -o qr_extract.o

# ine-qr-c's portable extractor (stb_image + zxing). Its "../vendor/stb_image.h"
# include resolves against ine-qr-c/src, so the vendored headers are picked up.
qr_extract_impl.o: $(INE_C)/src/qr_extract.cpp
	$(CXX) -std=c++17 -O2 $(CXXINC) -c $(INE_C)/src/qr_extract.cpp -o qr_extract_impl.o

# Hardened build: bounds-check every index. Off by default (zero cost in the
# normal build); recommended when decoding untrusted / attacker-supplied images.
safe:
	$(MAKE) clean
	$(MAKE) ESKIU_FLAGS=--safe test

clean:
	rm -f *.o /tmp/ine_pt

.PHONY: all test objects safe clean
