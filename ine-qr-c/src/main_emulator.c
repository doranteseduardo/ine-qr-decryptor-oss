/* ══ FILE: main.c ══
 *
 * Entry point for the INE QR decoder.
 *
 * Orchestrates the four-stage pipeline that extracts and decrypts the
 * biographical data embedded in a Mexican voter ID (INE) credential photo:
 *
 *   Stage 1 — QR extraction   : locate the two QR codes in the credential
 *                               image and read their raw 858-byte payloads.
 *   Stage 2 — .so loading     : read libPersonalCode.so into host memory so
 *                               the ELF loader and emulator can work with it.
 *   Stage 3 — Static crypto   : run the pure-C AES→RSA#1→RSA#2 layers that
 *                               do not require ARM64 emulation.
 *   Stage 4 — ARM64 emulation : run the pc() JNI function inside a Unicorn
 *                               Engine sandbox to execute the remaining SIMD,
 *                               AES, RSA#3-#4, and ECC layers natively.
 *
 * On success the decoded result is written to output/:
 *   datos_biograficos.json   — structured biographical fields (CURP, nombre…)
 *   foto_ine.webp            — credential photo extracted from the QR payload
 *   texto_biografico.txt     — raw pipe-separated text before JSON encoding
 *
 * Usage: ine_decode <credential_image> [-v|--verbose]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#include "ine_types.h"
#include "emulator.h"
#include "crypto_state.h"
#include "output_decode.h"
#include "qr_extract.h"

static int g_verbose = 0;

/* Print usage information and accepted image formats to stderr. */
static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <credential_image> [-v|--verbose]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Formats: JPG, PNG, HEIC\n");
    fprintf(stderr, "The image must include both INE QR codes.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Output (in output/ relative to image or cwd):\n");
    fprintf(stderr, "  datos_biograficos.json\n");
    fprintf(stderr, "  foto_ine.webp\n");
    fprintf(stderr, "  texto_biografico.txt\n");
}

/* Program entry point.  Parses arguments, drives the four pipeline stages,
 * writes output files, and streams the JSON result to stdout. */
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

    /* Check image exists */
    struct stat st;
    if (stat(image_path, &st) != 0) {
        fprintf(stderr, "[!] File not found: %s\n", image_path);
        return 1;
    }

    /* Determine output directory (sibling 'output/' of the binary or image) */
    char output_dir[1024] = "./output";
    mkdir(output_dir, 0755);

    /* Determine .so path — same directory as this binary or hardcoded sibling */
    char so_path[1024];
    /* Try ../libPersonalCode.so relative to this binary's directory */
    /* For simplicity use the path expected by the plan */
    snprintf(so_path, sizeof(so_path), "%s/../libPersonalCode.so",
             /* dirname of argv[0] */ ".");
    /* Check if file exists at hardcoded sibling path */
    const char *candidates[] = {
        "../libPersonalCode.so",
        "./libPersonalCode.so",
        NULL
    };
    const char *found_so = NULL;
    for (int i = 0; candidates[i]; i++) {
        if (stat(candidates[i], &st) == 0) { found_so = candidates[i]; break; }
    }
    if (!found_so) {
        fprintf(stderr, "[!] libPersonalCode.so not found in ./ or ../\n");
        return 1;
    }

    struct timespec t_start, t_step;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    /* ── Step 1: Extract QR codes ── */
    fprintf(stderr, "\n[1/4] Extracting QR codes from image...\n");
    clock_gettime(CLOCK_MONOTONIC, &t_step);
    QRPair qrp = qr_extract(image_path);
    if (!qrp.ok) {
        fprintf(stderr, "[!] QR extraction failed: %s\n", qrp.err);
        return 1;
    }
    {
        struct timespec t_now; clock_gettime(CLOCK_MONOTONIC, &t_now);
        double dt = (t_now.tv_sec - t_step.tv_sec) + (t_now.tv_nsec - t_step.tv_nsec) * 1e-9;
        fprintf(stderr, "    [1/4] done (%.2fs)\n", dt);
    }

    /* ── Step 2: Load .so ── */
    fprintf(stderr, "\n[2/4] Loading libPersonalCode.so...\n");
    FILE *f = fopen(found_so, "rb");
    if (!f) { fprintf(stderr, "[!] Cannot open %s\n", found_so); return 1; }
    fseek(f, 0, SEEK_END);
    long so_size = ftell(f);
    rewind(f);
    uint8_t *so_data = malloc((size_t)so_size);
    if (!so_data) { fclose(f); fprintf(stderr, "[!] OOM\n"); return 1; }
    fread(so_data, 1, (size_t)so_size, f);
    fclose(f);
    fprintf(stderr, "    Loaded %ld bytes\n", so_size);

    /* ── Step 3: Static crypto pipeline ── */
    fprintf(stderr, "\n[3/4] Static crypto pipeline (AES + RSA layers 1-2)...\n");
    clock_gettime(CLOCK_MONOTONIC, &t_step);
    char rsa_key2_xml[65536];
    if (run_static_pipeline(so_data, (size_t)so_size, rsa_key2_xml, sizeof(rsa_key2_xml)) != 0) {
        fprintf(stderr, "[!] Static pipeline failed\n");
        free(so_data); return 1;
    }
    {
        /* Save RSA key #2 to output/ */
        char rsa_path[1024];
        snprintf(rsa_path, sizeof(rsa_path), "%s/rsa_step1_full.txt", output_dir);
        FILE *rf = fopen(rsa_path, "w");
        if (rf) { fputs(rsa_key2_xml, rf); fclose(rf); }
    }
    {
        struct timespec t_now; clock_gettime(CLOCK_MONOTONIC, &t_now);
        double dt = (t_now.tv_sec - t_step.tv_sec) + (t_now.tv_nsec - t_step.tv_nsec) * 1e-9;
        fprintf(stderr, "    [3/4] done (%.2fs)\n", dt);
    }

    /* ── Step 4: ARM64 emulation ── */
    fprintf(stderr, "\n[4/4] ARM64 emulation (layers 3-7)...\n");
    clock_gettime(CLOCK_MONOTONIC, &t_step);

    /* Combined payload = left[2:] + right[2:]
     * Each QR carries 858 bytes; the first 2 bytes are a header (type tag +
     * side index) that the native pc() function does not expect, so they are
     * stripped here before concatenation. */
    uint8_t combined[856 * 2];
    memcpy(combined,       qrp.left  + 2, 856);
    memcpy(combined + 856, qrp.right + 2, 856);
    size_t combined_len = sizeof(combined);

    INEContext ctx;
    emu_context_init(&ctx, so_data, (size_t)so_size, g_verbose);

    int emu_ret = emu_run(&ctx, combined, combined_len, rsa_key2_xml);
    {
        struct timespec t_now; clock_gettime(CLOCK_MONOTONIC, &t_now);
        double dt = (t_now.tv_sec - t_step.tv_sec) + (t_now.tv_nsec - t_step.tv_nsec) * 1e-9;
        fprintf(stderr, "    [4/4] done (%.2fs)\n", dt);
    }

    if (emu_ret != 0 || !ctx.result_data) {
        fprintf(stderr, "[!] Emulation failed\n");
        free(so_data); return 1;
    }

    /* ── Save pc_return_decoded.bin ── */
    {
        char bin_path[1024];
        snprintf(bin_path, sizeof(bin_path), "%s/pc_return_decoded.bin", output_dir);
        FILE *bf = fopen(bin_path, "wb");
        if (bf) {
            fwrite(ctx.result_data, 1, ctx.result_len, bf);
            fclose(bf);
        }
    }

    /* ── Decode result ── */
    if (decode_and_write(ctx.result_data, ctx.result_len, output_dir) != 0) {
        fprintf(stderr, "[!] Output decode failed\n");
        free(ctx.result_data); free(so_data); return 1;
    }

    /* ── Summary ── */
    struct timespec t_end; clock_gettime(CLOCK_MONOTONIC, &t_end);
    double total = (t_end.tv_sec - t_start.tv_sec) + (t_end.tv_nsec - t_start.tv_nsec) * 1e-9;
    fprintf(stderr, "\n[*] Completed in %.2fs\n", total);

    /* Print JSON to stdout */
    {
        char json_path[1024];
        snprintf(json_path, sizeof(json_path), "%s/datos_biograficos.json", output_dir);
        FILE *jf = fopen(json_path, "r");
        if (jf) {
            char buf[8192]; size_t n;
            while ((n = fread(buf, 1, sizeof(buf), jf)) > 0)
                fwrite(buf, 1, n, stdout);
            fclose(jf);
        }
    }

    free(ctx.result_data);
    /* Free RSA keys */
    for (int i = 0; i < ctx.rsa_key_count; i++) {
        if (ctx.rsa_keys[i].n) BN_free(ctx.rsa_keys[i].n);
        if (ctx.rsa_keys[i].e) BN_free(ctx.rsa_keys[i].e);
    }
    if (ctx.bn_ctx) BN_CTX_free(ctx.bn_ctx);
    free(so_data);
    return 0;
}
