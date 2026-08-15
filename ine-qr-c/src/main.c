/* ══ FILE: main.c ══
 *
 * Thin CLI wrapper around libine_decode.
 *
 * Reads the input image into memory, calls ine_decode_bytes(), then writes
 * the resulting JSON / WebP / texto_biografico.txt under output/ to keep
 * the original CLI behaviour stable for downstream scripts.
 *
 * Usage: ine_decode <credential_image> [-v|--verbose]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include "ine_lib.h"

static int g_verbose = 0;

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <credential_image> [-v|--verbose]\n", prog);
    fprintf(stderr, "Formats: JPG, PNG (and HEIC on macOS via sips fallback in qr_extract).\n");
}

/* Slurp a file into a malloc'd buffer. Returns NULL on failure. */
static uint8_t *slurp(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    rewind(f);
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) { free(buf); return NULL; }
    *out_len = (size_t)sz;
    return buf;
}

int main(int argc, char *argv[]) {
    if (argc < 2) { usage(argv[0]); return 1; }

    const char *image_path = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
            g_verbose = 1;
        else if (!image_path)
            image_path = argv[i];
    }
    if (!image_path) { usage(argv[0]); return 1; }
    (void)g_verbose;

    struct stat st;
    if (stat(image_path, &st) != 0) {
        fprintf(stderr, "[!] File not found: %s\n", image_path);
        return 1;
    }

    /* HEIC needs the file-path code path (sips fallback). For HEIC we
     * still prefer the legacy two-step extract → write so behaviour is
     * unchanged on macOS. For JPEG/PNG we go through ine_decode_bytes()
     * to exercise the same path the API uses. */
    const char *dot = strrchr(image_path, '.');
    int is_heic = dot && (strcasecmp(dot, ".heic") == 0 || strcasecmp(dot, ".heif") == 0);

    char output_dir[1024] = "./output";
    mkdir(output_dir, 0755);

    if (is_heic) {
        /* Defer to the legacy path-based pipeline: it still handles the sips
         * conversion and writes the three files via decode_and_write(). */
        extern int legacy_decode_path(const char *image_path, const char *output_dir);
        return legacy_decode_path(image_path, output_dir);
    }

    size_t img_len = 0;
    uint8_t *img = slurp(image_path, &img_len);
    if (!img) {
        fprintf(stderr, "[!] Cannot read %s\n", image_path);
        return 1;
    }

    struct timespec t_start, t_end;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    IneResult res;
    int rc = ine_decode_bytes(img, img_len, /*max_long_edge=*/0, &res);
    free(img);

    if (rc != 0) {
        fprintf(stderr, "[!] %s\n", res.err);
        ine_result_free(&res);
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &t_end);
    double total_ms = (t_end.tv_sec - t_start.tv_sec) * 1000.0 +
                      (t_end.tv_nsec - t_start.tv_nsec) / 1e6;

    /* Persist the JSON / WebP for parity with the previous CLI. */
    char path[1024];
    snprintf(path, sizeof(path), "%s/datos_biograficos.json", output_dir);
    FILE *jf = fopen(path, "w");
    if (jf) { fwrite(res.json, 1, res.json_len, jf); fclose(jf); }

    if (res.webp && res.webp_len > 0) {
        snprintf(path, sizeof(path), "%s/foto_ine.webp", output_dir);
        FILE *wf = fopen(path, "wb");
        if (wf) { fwrite(res.webp, 1, res.webp_len, wf); fclose(wf); }
    }

    fprintf(stderr, "\n[*] Timing:\n");
    fprintf(stderr, "    QR extraction:   %7.1f ms\n", res.qr_ms);
    fprintf(stderr, "    Crypto pipeline: %7.1f ms\n", res.crypto_ms);
    fprintf(stderr, "    Output decode:   %7.1f ms\n", res.decode_ms);
    fprintf(stderr, "    Total:           %7.1f ms\n", total_ms);

    /* Emit JSON to stdout (used by the API when running via subprocess). */
    fwrite(res.json, 1, res.json_len, stdout);

    ine_result_free(&res);
    return 0;
}

/* Legacy file-path pipeline kept for HEIC inputs on macOS. Lives here to
 * avoid pulling the file-based qr_extract path into the library build. */
#include "qr_extract.h"
#include "no_so_crypto.h"
#include "output_decode.h"

int legacy_decode_path(const char *image_path, const char *output_dir) {
    struct timespec t0, t1, t2, t3;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    QRPair qrp = qr_extract(image_path);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    if (!qrp.ok) {
        fprintf(stderr, "[!] QR extraction failed: %s\n", qrp.err);
        return 1;
    }

    uint8_t combined[856 * 2];
    memcpy(combined,       qrp.left  + 2, 856);
    memcpy(combined + 856, qrp.right + 2, 856);

    uint8_t *plain = NULL;
    size_t   plain_len = 0;
    if (run_no_so_pipeline(combined, sizeof(combined), &plain, &plain_len) != 0) {
        fprintf(stderr, "[!] Crypto pipeline failed\n");
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &t2);

    int rc = decode_and_write(plain, plain_len, output_dir);
    free(plain);
    clock_gettime(CLOCK_MONOTONIC, &t3);

    double qr_ms     = (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
    double crypto_ms = (t2.tv_sec - t1.tv_sec) * 1000.0 + (t2.tv_nsec - t1.tv_nsec) / 1e6;
    double decode_ms = (t3.tv_sec - t2.tv_sec) * 1000.0 + (t3.tv_nsec - t2.tv_nsec) / 1e6;
    double total_ms  = (t3.tv_sec - t0.tv_sec) * 1000.0 + (t3.tv_nsec - t0.tv_nsec) / 1e6;

    fprintf(stderr, "\n[*] Timing (Legacy HEIC path):\n");
    fprintf(stderr, "    QR extraction:   %7.1f ms\n", qr_ms);
    fprintf(stderr, "    Crypto pipeline: %7.1f ms\n", crypto_ms);
    fprintf(stderr, "    Output decode:   %7.1f ms\n", decode_ms);
    fprintf(stderr, "    Total:           %7.1f ms\n", total_ms);

    /* Mirror previous behaviour: print JSON to stdout. */
    char json_path[1024];
    snprintf(json_path, sizeof(json_path), "%s/datos_biograficos.json", output_dir);
    FILE *jf = fopen(json_path, "r");
    if (jf) {
        char buf[8192]; size_t n;
        while ((n = fread(buf, 1, sizeof(buf), jf)) > 0)
            fwrite(buf, 1, n, stdout);
        fclose(jf);
    }
    return rc == 0 ? 0 : 1;
}
