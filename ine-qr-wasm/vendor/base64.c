#include "base64.h"

static int b64v(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int base64_decode(const char *b64, uint8_t *out, int out_max) {
    int n = 0;
    int buf = 0, bits = 0;
    for (const char *p = b64; *p; p++) {
        int c = (unsigned char)*p;
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        if (c == '=') break;
        int v = b64v(c);
        if (v < 0) return -1;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n >= out_max) return -1;
            out[n++] = (uint8_t)((buf >> bits) & 0xFF);
        }
    }
    return n;
}
