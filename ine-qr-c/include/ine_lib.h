/* ══ FILE: ine_lib.h ══
 *
 * Public library API for the INE QR decoder. Designed to be embedded
 * in-process (e.g. via FFI) so callers can avoid fork+exec and disk I/O.
 *
 * Usage:
 *
 *   IneResult res;
 *   if (ine_decode_bytes(image_bytes, image_len, 3000, &res) == 0) {
 *       // res.json (UTF-8, null-terminated) and res.webp (binary) are
 *       // owned by the library; copy what you need then call
 *       // ine_result_free(&res).
 *   } else {
 *       fprintf(stderr, "decode failed: %s\n", res.err);
 *       ine_result_free(&res);
 *   }
 *
 * Thread safety: ine_decode_bytes() is fully reentrant; multiple threads
 * may call it concurrently with independent IneResult instances.
 */

#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int     ok;             /* 1 on success, 0 on failure */
    char    err[256];       /* human-readable error when ok == 0 */
    char   *json;           /* malloc'd, null-terminated JSON string */
    size_t  json_len;       /* bytes in json (excluding NUL) */
    uint8_t *webp;          /* malloc'd raw WebP image */
    size_t  webp_len;       /* bytes in webp */
    double  qr_ms;
    double  crypto_ms;
    double  decode_ms;
} IneResult;

/* Decode INE QR codes from an in-memory image (JPEG, PNG, or HEIC*).
 *
 *   img            : image bytes
 *   img_len        : byte count
 *   max_long_edge  : if > 0 and the image exceeds this on its longer edge,
 *                    downsample to it before scanning. Use 0 to disable.
 *   res            : output struct (caller-allocated, library-populated)
 *
 * (*) HEIC requires libheif at build time. Without libheif a HEIC input
 * produces an "unsupported format" error.
 *
 * Returns 0 on success, -1 on failure. In both cases res->err is filled.
 * On success the caller MUST eventually call ine_result_free(res). */
int ine_decode_bytes(const uint8_t *img, size_t img_len,
                     int max_long_edge,
                     IneResult *res);

/* Release all heap memory owned by res. Safe to call after a failed decode. */
void ine_result_free(IneResult *res);

#ifdef __cplusplus
}
#endif
