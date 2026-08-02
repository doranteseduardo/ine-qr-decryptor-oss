/* ══ FILE: ine_lib.c ══
 *
 * Library entry point that wires the three pipeline stages
 * (qr_extract_from_memory → run_no_so_pipeline → decode_to_buffers) into a
 * single in-memory call. No disk I/O, no subprocess spawning, fully
 * reentrant — designed for cgo / FFI consumers running multiple decodes
 * in parallel.
 */

#include "ine_lib.h"
#include "qr_extract.h"
#include "no_so_crypto.h"
#include "output_decode.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double elapsed_ms(struct timespec a, struct timespec b) {
    return (b.tv_sec - a.tv_sec) * 1000.0 +
           (b.tv_nsec - a.tv_nsec) / 1e6;
}

void ine_result_free(IneResult *res) {
    if (!res) return;
    free(res->json);  res->json = NULL;  res->json_len = 0;
    free(res->webp);  res->webp = NULL;  res->webp_len = 0;
}

int ine_decode_bytes(const uint8_t *img, size_t img_len,
                     int max_long_edge,
                     IneResult *res) {
    if (!res) return -1;
    memset(res, 0, sizeof(*res));

    if (!img || img_len == 0) {
        snprintf(res->err, sizeof(res->err), "empty image buffer");
        return -1;
    }

    struct timespec t0, t1, t2, t3;

    /* Stage 1: QR extraction (memory in → 2× 858B QR payloads). */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    QRPair qrp = qr_extract_from_memory(img, img_len, max_long_edge);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    res->qr_ms = elapsed_ms(t0, t1);

    if (!qrp.ok) {
        snprintf(res->err, sizeof(res->err), "%s", qrp.err);
        return -1;
    }

    /* Stage 2: crypto pipeline. combined = left[2:] + right[2:]. */
    uint8_t combined[856 * 2];
    memcpy(combined,       qrp.left  + 2, 856);
    memcpy(combined + 856, qrp.right + 2, 856);

    uint8_t *plain = NULL;
    size_t   plain_len = 0;
    if (run_no_so_pipeline(combined, sizeof(combined), &plain, &plain_len) != 0) {
        snprintf(res->err, sizeof(res->err), "crypto pipeline failed");
        return -1;
    }
    clock_gettime(CLOCK_MONOTONIC, &t2);
    res->crypto_ms = elapsed_ms(t1, t2);

    /* Stage 3: parse the binary payload into JSON + WebP buffers. */
    char    *json = NULL;  size_t json_len = 0;
    uint8_t *webp = NULL;  size_t webp_len = 0;
    int rc = decode_to_buffers(plain, plain_len,
                               &json, &json_len,
                               &webp, &webp_len);
    free(plain);
    if (rc != 0) {
        snprintf(res->err, sizeof(res->err), "output decode failed");
        return -1;
    }
    clock_gettime(CLOCK_MONOTONIC, &t3);
    res->decode_ms = elapsed_ms(t2, t3);

    res->ok       = 1;
    res->json     = json;
    res->json_len = json_len;
    res->webp     = webp;
    res->webp_len = webp_len;
    return 0;
}
