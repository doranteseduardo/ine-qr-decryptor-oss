# ine-qr-eskiu — INE QR decoder + HTTP API in Eskiu

A sixth implementation of the decoder, written in [Eskiu](https://eskiu-lang.org)
(a systems language that compiles to native code via LLVM), wrapped in an HTTP
API that mirrors the Go service in [`../ine-qr-api`](../ine-qr-api).

The crypto + output pipeline (AES-256-CBC + RSA-8192 → 18 biographical fields +
WebP photo) is pure Eskiu — a direct port of the reference pipeline, producing
bit-identical output. QR extraction reuses **ine-qr-c's** portable reader
(`stb_image` + `zxing-cpp`), so the image path is the same one that ships in the
Linux Docker image. The HTTP layer, multipart parsing, rate limiting and JSON
are all built on Eskiu's standard library — no framework.

```
src/
  main.esk         # config, routing, middleware (auth / rate-limit / CORS / stats)
  decode_api.esk   # image bytes → JSON + foto_base64 (wraps the pipeline)
  ratelimit.esk    # per-identity token bucket over Map<V>
decoder/           # the crypto + output pipeline (Eskiu) + a thin C adapter to
                   # ine-qr-c's qr_extract (stb_image + zxing)
tests/             # parity check against output/qr_*.bin
```

## Build

Requires:
- **eskiuc** — the Eskiu compiler. Install it from the public
  [Eskiu releases](https://github.com/doranteseduardo/eskiu/releases)
  (grab the prebuilt asset for your platform and put `eskiuc` on your `PATH`),
  or build it from source: `git clone https://github.com/doranteseduardo/eskiu
  && cd eskiu && cmake -S . -B build && cmake --build build` (then use
  `make ESKIUC=/path/to/eskiu/build/eskiuc`).
- **OpenSSL** and **zxing-cpp** (macOS: `brew install openssl@3 zxing-cpp`; Linux: build zxing-cpp from source as in the project `Dockerfile`).
- A C/C++ toolchain.

```bash
make                              # → ./ine_qr_eskiu (uses `eskiuc` on PATH)
make ESKIUC=/path/to/eskiuc       # if eskiuc isn't on PATH
make test                         # crypto+output parity vs output/qr_*.bin (only -lcrypto)
```

The QR extractor is reused from `../ine-qr-c` (compiled by the Makefile), so the
binary builds on both macOS and Linux. **HEIC** input is converted via `sips`
on macOS only; on Linux, send **JPEG or PNG** (same as the C/Go paths).

## Run

```bash
PORT=8080 ./ine_qr_eskiu
```

Environment (same names as the Go API):

| Var | Default | |
|-----|---------|--|
| `PORT` | `8080` | listen port |
| `API_KEY` | _(unset)_ | if set, requests must carry `X-API-Key` |
| `WORKERS` | `4` | worker threads (concurrency cap) |
| `MAX_BODY_MB` | `25` | max request body |
| `RATE_PER_SEC` | `0` | per-identity token-bucket rate (0 = off) |
| `RATE_BURST` | `10` | bucket capacity |
| `CORS_ORIGIN` | `*` | `Access-Control-Allow-Origin` |

## API

### `POST /decode`

Accepts either:
- `multipart/form-data` with a `photo` file field, or
- `application/json` — `{"photo_base64": "<base64>", "filename": "cred.jpg"}`

Responds with the 18 biographical fields plus `foto_base64` (the WebP photo,
base64-encoded):

```bash
curl -F photo=@cred.jpg http://localhost:8080/decode
# or
curl -H 'Content-Type: application/json' \
     -d "{\"photo_base64\":\"$(base64 -i cred.jpg)\"}" \
     http://localhost:8080/decode
```

```json
{ "tipo":"N", "cic":"…", "ocr":"…", "curp":"…", "nombre":"…", …,
  "firmaVerificadora":"…", "foto_base64":"UklGR…" }
```

Errors are JSON: `{"error":"…"}` with `400` (bad input), `401` (bad/missing
`X-API-Key`), `413` (body too large), `422` (decode failed), `429` (rate
limited).

### `GET /healthz` → `{"status":"ok"}`
### `GET /stats` → request counters

## Docker

An x86-64 image (`ine-qr-eskiu/Dockerfile`) builds zxing-cpp, then **fetches the
Linux `eskiuc` compiler** from the public Eskiu GitHub releases at build time
(`vendor/fetch-eskiuc.sh`, rather than vendoring the ~22 MB binary in git),
compiles the service, and ships a minimal runtime. Pick the release with
`--build-arg ESKIUC_VERSION=vX.Y.Z`. Build from the **project root** (it needs
both `ine-qr-eskiu/` and `ine-qr-c/`):

```bash
docker build --platform linux/amd64 -f ine-qr-eskiu/Dockerfile -t ine-qr-eskiu:local .
docker run --rm --platform linux/amd64 -p 8081:8080 --tmpfs /tmp ine-qr-eskiu:local
```

Or via compose — it runs on `:8081`, beside the Go API on `:8080`:

```bash
docker compose up eskiu        # or `docker compose up` for both
```

To pin a different Eskiu compiler release, pass its tag through the build:

```bash
docker build --platform linux/amd64 --build-arg ESKIUC_VERSION=v0.6.1 \
   -f ine-qr-eskiu/Dockerfile -t ine-qr-eskiu:local .
```

`vendor/fetch-eskiuc.sh` performs the download (via `gh` if present, else
`curl`) and can also be run standalone to fetch the tarball locally.

## Identity for rate limiting

`X-API-Key`, else `X-Forwarded-For`, else the peer IP (via the stdlib's
`net_accept_addr`).

## Standard-library features it exercises

`<http>` (binary-safe `HttpReq` / `http_recv` — full Content-Length body),
`<multipart>`, `<map>` (`Map<V>` for the rate-limit buckets), `<json>`,
`<base64>`, `<net>` (`net_accept_addr`), `<threading>`. Most of these landed in
Eskiu 0.2.0 to make services like this clean to write.
