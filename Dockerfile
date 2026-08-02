# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — Build zxing-cpp + libine_decode.a + ine_api Go binary in one go.
#
# The Go binary embeds the C decoder via cgo (libine_decode.a), so the
# entire decode pipeline runs in-process: no fork+exec per request, no
# temp files, no file-system I/O on the hot path.
# ─────────────────────────────────────────────────────────────────────────────
FROM ubuntu:24.04 AS builder

ARG ZXING_VERSION=3.0.2
ARG GO_VERSION=1.22.6

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ make cmake git pkg-config ca-certificates \
        libssl-dev curl xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Install Go matching the version pinned in go.mod.
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-$(dpkg --print-architecture).tar.gz" \
        | tar -C /usr/local -xz
ENV PATH=/usr/local/go/bin:$PATH

# Build zxing-cpp as a static library. v3.x bundles libzint as a git
# submodule, so --recurse-submodules is required.
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

# Build the C decoder static archive consumed by cgo.
WORKDIR /src/ine-qr-c
COPY ine-qr-c/ .
RUN make lib \
        BREW="" \
        OPENSSL_CFLAGS="$(pkg-config --cflags openssl)" \
        OPENSSL_LDFLAGS="$(pkg-config --libs openssl)"

# Build the Go API. cgo links against libine_decode.a + libZXing.a + ssl/crypto.
WORKDIR /src/api
COPY ine-qr-api/go.mod ine-qr-api/go.sum* ./
RUN go mod download
COPY ine-qr-api/main.go ./

ENV CGO_ENABLED=1
ENV CGO_CFLAGS="-I/src/ine-qr-c/include"
ENV CGO_LDFLAGS="-L/src/ine-qr-c -line_decode -lZXing -lssl -lcrypto -lstdc++ -lm -lpthread"

RUN go build -ldflags="-s -w" -o ine_api .

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — Minimal runtime image
# ─────────────────────────────────────────────────────────────────────────────
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 \
        libstdc++6 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /src/api/ine_api ./ine_api

ENV PORT=8080
# Rate limiting is disabled by default in this image. Override at runtime
# with `-e RATE_PER_SEC=5 -e RATE_BURST=10` to turn it back on.
ENV RATE_PER_SEC=0
EXPOSE 8080

# Drop to non-root user
RUN useradd -r -u 1001 ineapi && chown ineapi /app
USER ineapi

CMD ["./ine_api"]
