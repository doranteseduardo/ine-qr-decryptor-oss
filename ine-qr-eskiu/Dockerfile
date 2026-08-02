# INE QR Decoder — Eskiu HTTP API.
#
# Build from the PROJECT ROOT (the build needs both ine-qr-eskiu/ and ine-qr-c/):
#   docker build -f ine-qr-eskiu/Dockerfile -t ine-qr-eskiu:local .
#
# The image is x86-64: the vendored eskiuc compiler is a Linux x86-64 build
# (the Eskiu repo is private, so it's vendored rather than fetched). On an
# Apple-Silicon host this builds under emulation; on an x86-64 host it is native.

# ── Stage 1 — build zxing-cpp + the Eskiu binary ──────────────────────────────
# Build for linux/amd64 (the vendored eskiuc is x86-64): pass --platform
# linux/amd64 to `docker build`, or `platform: linux/amd64` in compose.
FROM ubuntu:24.04 AS builder

ARG ZXING_VERSION=3.0.2
ENV DEBIAN_FRONTEND=noninteractive

# libz3-4 is an LLVM runtime dependency of the eskiuc binary.
# curl is used to fetch the eskiuc release tarball (see fetch-eskiuc.sh).
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ make cmake git pkg-config ca-certificates libssl-dev libz3-4 curl \
    && rm -rf /var/lib/apt/lists/*

# zxing-cpp as a static library — the exact build the C/Go image uses. v3.x
# bundles libzint as a submodule, so --recurse-submodules is required.
RUN git clone --depth 1 --branch v${ZXING_VERSION} --recurse-submodules --shallow-submodules \
        https://github.com/zxing-cpp/zxing-cpp.git /tmp/zxing \
    && cmake -S /tmp/zxing -B /tmp/zxing/build \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DBUILD_SHARED_LIBS=OFF \
        -DZXING_EXAMPLES=OFF \
        -DZXING_C_API=OFF \
    && cmake --build /tmp/zxing/build -j"$(nproc)" \
    && cmake --install /tmp/zxing/build \
    && rm -rf /tmp/zxing

# Fetch the Eskiu compiler from its public GitHub releases (not vendored in
# git). The tarball lays out bin/eskiuc + lib/eskiu/stdlib; eskiuc resolves the
# stdlib via ../lib/eskiu relative to its own path, so extracting to /opt gives
# /opt/bin/eskiuc → /opt/lib/eskiu/stdlib. Override the release with
# --build-arg ESKIUC_VERSION=vX.Y.Z.
ARG ESKIUC_VERSION=v0.6.1
COPY ine-qr-eskiu/vendor/fetch-eskiuc.sh /tmp/fetch-eskiuc.sh
RUN ESKIUC_VERSION="${ESKIUC_VERSION}" /tmp/fetch-eskiuc.sh \
    && tar -xz -C /opt < /tmp/eskiuc-linux-x86_64.tar.gz \
    && rm -f /tmp/eskiuc-linux-x86_64.tar.gz \
    && /opt/bin/eskiuc --version

# Sources — ine-qr-eskiu reuses ine-qr-c's portable QR extractor.
WORKDIR /src
COPY ine-qr-c/   ./ine-qr-c/
COPY ine-qr-eskiu/ ./ine-qr-eskiu/

WORKDIR /src/ine-qr-eskiu
# `make clean` first: the build context may carry host-built artifacts (a macOS
# ine_qr_eskiu / *.o), and make would otherwise consider them up-to-date and
# ship the wrong-arch binary. Clean forces a fresh x86-64 build.
RUN make clean && make ESKIUC=/opt/bin/eskiuc

# ── Stage 2 — minimal runtime image ───────────────────────────────────────────
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 libstdc++6 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /src/ine-qr-eskiu/ine_qr_eskiu ./ine_qr_eskiu

ENV PORT=8080
# Rate limiting off by default; override with -e RATE_PER_SEC=5 -e RATE_BURST=10.
ENV RATE_PER_SEC=0
EXPOSE 8080

# The decode path writes the uploaded image to a temp file, so /tmp must be
# writable (a tmpfs mount works under read_only — see docker-compose.yml).
RUN useradd -r -u 1001 ineqr && chown ineqr /app
USER ineqr

CMD ["./ine_qr_eskiu"]
