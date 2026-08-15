/* ══ FILE: output_decode.c ══
 *
 * Decoder for the binary result produced by the emulated pc() function.
 *
 * Layout of the input buffer:
 *   [2 bytes, big-endian]  text_len
 *   [text_len bytes]       text_data  — biographical fields, '|'-separated,
 *                                       encoded with CHAR_TABLE
 *   [2 bytes, big-endian]  img_len
 *   [img_len  bytes]       img_data   — credential photo (WebP)
 *
 * Two consumers:
 *   decode_to_buffers  — produces JSON + WebP as in-memory buffers (used by
 *                        libine_decode for cgo callers; zero disk I/O).
 *   decode_and_write   — wraps decode_to_buffers and writes the legacy
 *                        three-file output expected by the CLI binary.
 */

#include "output_decode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* ── Character table (1-indexed, matches Python CHAR_TABLE) ── */
/* Spanish alphabet A-Z with Ñ at position 15 */
static const char *CHAR_TABLE[256];
static pthread_once_t CHAR_TABLE_ONCE = PTHREAD_ONCE_INIT;

/* Populate CHAR_TABLE exactly once across all threads.
 *   1-14  → A-N  | 15 → Ñ (UTF-8 two bytes) | 16-27 → O-Z
 *   28-37 → 0-9  | 40 → /  | 57 → | (field separator)
 * Unused indices stay NULL and produce a "[xx]" hex placeholder. */
static void init_char_table_once(void) {
    static const char *letters[] = {
        "A","B","C","D","E","F","G","H","I","J","K","L","M","N",
        "\xC3\x91", /* Ñ */
        "O","P","Q","R","S","T","U","V","W","X","Y","Z"
    };
    for (int i = 0; i < 27; i++) {
        if (i + 1 < 256) CHAR_TABLE[i + 1] = letters[i];
    }
    static const char *digit_strs[10] = {"0","1","2","3","4","5","6","7","8","9"};
    for (int i = 0; i < 10; i++) CHAR_TABLE[28 + i] = digit_strs[i];
    CHAR_TABLE[40] = "/";
    CHAR_TABLE[57] = "|";
}

static const char *FIELD_LABELS[] = {
    "tipo", "cic", "ocr", "curp", "nombre", "apellido1", "apellido2",
    "entidad", "municipio", "seccion", "etnia", "vigencia", "sexo",
    "indiceHuella1", "indiceHuella2", "version", "fechaGeneracion",
    "firmaVerificadora"
};
#define N_FIELDS 18

/* ── Tiny growable byte buffer for in-memory JSON assembly ── */
typedef struct {
    char  *data;
    size_t len;
    size_t cap;
    int    oom;
} Buf;

static void buf_init(Buf *b) {
    b->data = malloc(512);
    b->len  = 0;
    b->cap  = b->data ? 512 : 0;
    b->oom  = b->data ? 0 : 1;
}

static int buf_reserve(Buf *b, size_t extra) {
    if (b->oom) return 0;
    if (b->len + extra + 1 <= b->cap) return 1;
    size_t cap = b->cap ? b->cap : 64;
    while (cap < b->len + extra + 1) cap *= 2;
    char *p = realloc(b->data, cap);
    if (!p) { b->oom = 1; return 0; }
    b->data = p;
    b->cap  = cap;
    return 1;
}

static void buf_append(Buf *b, const char *s, size_t n) {
    if (!buf_reserve(b, n)) return;
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
}

static void buf_append_str(Buf *b, const char *s) { buf_append(b, s, strlen(s)); }
static void buf_append_ch (Buf *b, char c)        { buf_append(b, &c, 1); }

/* JSON-escape a UTF-8 string into the buffer. Only " and \ require
 * escaping for ASCII/UTF-8 fields produced by the INE decoder. */
static void buf_append_jsonstr(Buf *b, const char *s) {
    buf_append_ch(b, '"');
    for (const char *c = s; *c; c++) {
        if      (*c == '"')  buf_append(b, "\\\"", 2);
        else if (*c == '\\') buf_append(b, "\\\\", 2);
        else                 buf_append_ch(b, *c);
    }
    buf_append_ch(b, '"');
}

/* Core decode: parses the binary buffer and produces JSON + WebP buffers. */
int decode_to_buffers(const uint8_t *decoded_bin, size_t len,
                      char    **json_out, size_t *json_len,
                      uint8_t **webp_out, size_t *webp_len) {
    if (json_out) *json_out = NULL;
    if (json_len) *json_len = 0;
    if (webp_out) *webp_out = NULL;
    if (webp_len) *webp_len = 0;

    pthread_once(&CHAR_TABLE_ONCE, init_char_table_once);

    if (len < 4) {
        fprintf(stderr, "[!] decoded_bin too short (%zu)\n", len);
        return -1;
    }

    size_t text_len = ((size_t)decoded_bin[0] << 8) | decoded_bin[1];
    if (2 + text_len + 2 > len) {
        fprintf(stderr, "[!] text_len %zu exceeds buffer\n", text_len);
        return -1;
    }
    const uint8_t *text_data = decoded_bin + 2;

    size_t img_off = 2 + text_len;
    size_t img_len = ((size_t)decoded_bin[img_off] << 8) | decoded_bin[img_off + 1];
    const uint8_t *img_data = decoded_bin + img_off + 2;

    if (img_off + 2 + img_len > len) {
        fprintf(stderr, "[W] img_len %zu truncated\n", img_len);
        img_len = len - img_off - 2;
    }

    /* Decode text bytes via char table. Worst case Ñ = 2 UTF-8 bytes/byte. */
    char *text_buf = malloc(text_len * 3 + 1);
    if (!text_buf) return -1;
    size_t tbpos = 0;
    for (size_t i = 0; i < text_len; i++) {
        uint8_t bv = text_data[i];
        if (bv == 0) continue;
        const char *ch = CHAR_TABLE[bv];
        if (ch) {
            size_t chlen = strlen(ch);
            memcpy(text_buf + tbpos, ch, chlen);
            tbpos += chlen;
        } else {
            tbpos += (size_t)snprintf(text_buf + tbpos, 8, "[%02x]", bv);
        }
    }
    text_buf[tbpos] = '\0';

    /* Split text on '|' to get fields */
    char *fields[N_FIELDS + 4];
    int nfields = 0;
    char *p = text_buf;
    while (nfields < N_FIELDS + 3) {
        char *pipe = strchr(p, '|');
        fields[nfields++] = p;
        if (!pipe) break;
        *pipe = '\0';
        p = pipe + 1;
    }

    /* ── Build JSON in memory ── */
    Buf jb;
    buf_init(&jb);
    buf_append_str(&jb, "{\n");
    for (int i = 0; i < nfields; i++) {
        const char *label = (i < N_FIELDS) ? FIELD_LABELS[i] : "campo_xx";
        buf_append_str(&jb, "  ");
        buf_append_jsonstr(&jb, label);
        buf_append_str(&jb, ": ");
        buf_append_jsonstr(&jb, fields[i]);
        buf_append_str(&jb, (i < nfields - 1) ? ",\n" : "\n");
    }
    buf_append_str(&jb, "}\n");

    free(text_buf);

    if (jb.oom) {
        free(jb.data);
        return -1;
    }

    /* ── Produce WebP buffer ── */
    uint8_t *webp = NULL;
    if (img_len > 0) {
        webp = malloc(img_len);
        if (!webp) {
            free(jb.data);
            return -1;
        }
        memcpy(webp, img_data, img_len);
    }

    fprintf(stderr, "[*] datos_biograficos.json (%d campos)\n", nfields);
    fprintf(stderr, "[*] foto_ine.webp (%zu bytes)\n", img_len);

    if (json_out) *json_out = jb.data;        else free(jb.data);
    if (json_len) *json_len = jb.len;
    if (webp_out) *webp_out = webp;           else free(webp);
    if (webp_len) *webp_len = img_len;
    return 0;
}

/* Legacy file-based wrapper used by the CLI binary. */
int decode_and_write(const uint8_t *decoded_bin, size_t len,
                     const char *output_dir) {
    char    *json = NULL;  size_t json_len = 0;
    uint8_t *webp = NULL;  size_t webp_len = 0;

    if (decode_to_buffers(decoded_bin, len, &json, &json_len, &webp, &webp_len) != 0)
        return -1;

    char path[1024];
    int rc = 0;

    snprintf(path, sizeof(path), "%s/datos_biograficos.json", output_dir);
    FILE *jf = fopen(path, "w");
    if (!jf) { fprintf(stderr, "[!] Cannot open %s\n", path); rc = -1; }
    else { fwrite(json, 1, json_len, jf); fclose(jf); }

    if (webp && webp_len > 0) {
        snprintf(path, sizeof(path), "%s/foto_ine.webp", output_dir);
        FILE *wf = fopen(path, "wb");
        if (wf) { fwrite(webp, 1, webp_len, wf); fclose(wf); }
        else fprintf(stderr, "[!] Cannot open %s\n", path);
    }

    /* texto_biografico.txt is no longer reconstructed in-buffer; keep a
     * stub so external scripts that look for the file still find an empty
     * one, signalling that the CLI ran successfully. */
    snprintf(path, sizeof(path), "%s/texto_biografico.txt", output_dir);
    FILE *tf = fopen(path, "w");
    if (tf) fclose(tf);

    free(json);
    free(webp);
    return rc;
}
