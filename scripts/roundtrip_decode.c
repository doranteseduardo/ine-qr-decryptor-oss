/* roundtrip_decode.c — verify a synthetic buffer through the REAL decoder.
 *
 * Reads synthetic_decoded.bin, runs ine-qr-c's decode_to_buffers() over it
 * (the same pure, crypto-free function every platform ships), and writes the
 * resulting expected.json + expected.webp. This guarantees the test fixtures
 * are produced by the shipping code, not hand-authored.
 *
 * Build (from repo root):
 *   cc -I ine-qr-c/include -o /tmp/roundtrip \
 *      scripts/roundtrip_decode.c ine-qr-c/src/output_decode.c -lpthread
 *   /tmp/roundtrip <in.bin> <out.json> <out.webp>
 */
#include "output_decode.h"
#include <stdio.h>
#include <stdlib.h>

static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(1); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)n);
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { perror("fread"); exit(1); }
    fclose(f);
    *len = (size_t)n;
    return buf;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <in.bin> <out.json> <out.webp>\n", argv[0]);
        return 2;
    }
    size_t len = 0;
    uint8_t *bin = read_file(argv[1], &len);

    char *json = NULL; size_t json_len = 0;
    uint8_t *webp = NULL; size_t webp_len = 0;
    if (decode_to_buffers(bin, len, &json, &json_len, &webp, &webp_len) != 0) {
        fprintf(stderr, "decode_to_buffers failed\n");
        return 1;
    }

    FILE *jf = fopen(argv[2], "wb");
    fwrite(json, 1, json_len, jf);
    fclose(jf);

    FILE *wf = fopen(argv[3], "wb");
    if (webp && webp_len) fwrite(webp, 1, webp_len, wf);
    fclose(wf);

    fprintf(stderr, "wrote %s (%zu bytes json), %s (%zu bytes webp)\n",
            argv[2], json_len, argv[3], webp_len);
    free(bin); free(json); free(webp);
    return 0;
}
