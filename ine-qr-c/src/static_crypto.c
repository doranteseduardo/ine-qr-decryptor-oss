/* ══ FILE: static_crypto.c ══
 *
 * Emulator-only helpers: decrypt the .so's embedded layer-1/2 ciphertexts so
 * the Unicorn path can pre-inject the resulting RSA key #2 + buf2 plaintext.
 *
 * The four primitives this file used to host (aes_cbc_decrypt,
 * rsa_pkcs1_decrypt_multiblock, base64_decode, base64_encode) were lifted
 * into crypto_backend_openssl.c so the same source can be linked against
 * BoringSSL on Android and against a vendored bignum on iOS.
 *
 * What still lives here:
 *   run_static_pipeline()  AES → RSA#1 → RSA#2 against .so .rodata
 *   precompute_buf2()      single-block RSA decrypt of combined[688:1712]
 *
 * Both depend on the four primitives via ine_crypto_backend.h.
 */

#include "crypto_state.h"
#include "ine_crypto_backend.h"
#include "ine_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Minimal XML text extractor: returns the content between <tag>…</tag>.
 * Only the first occurrence is returned.  Result is malloc'd; caller frees.
 * Returns NULL if the tag is not found or on OOM. */
static char *xml_find_text(const char *xml, const char *tag) {
    char open[64], close[64];
    snprintf(open,  sizeof(open),  "<%s>",  tag);
    snprintf(close, sizeof(close), "</%s>", tag);

    const char *start = strstr(xml, open);
    if (!start) return NULL;
    start += strlen(open);
    const char *end = strstr(start, close);
    if (!end) return NULL;

    size_t len = (size_t)(end - start);
    char *out = malloc(len + 1);
    if (!out) return NULL;
    memcpy(out, start, len);
    out[len] = '\0';
    return out;
}

/* Parse a Chilkat-format RSA public key XML string into OpenSSL BIGNUMs.
 * Expected XML tags: <Modulus> (base64) and <Exponent> (base64).
 * On success *n_out, *e_out are populated and *key_bytes_out = len(modulus).
 * Returns 0 on success, -1 if the XML is malformed or decoding fails.
 * Caller must BN_free() *n_out and *e_out. */
static int parse_rsa_xml(const char *xml, BIGNUM **n_out, BIGNUM **e_out,
                          int *key_bytes_out) {
    char *mod_b64 = xml_find_text(xml, "Modulus");
    char *exp_b64 = xml_find_text(xml, "Exponent");
    if (!mod_b64 || !exp_b64) { free(mod_b64); free(exp_b64); return -1; }

    int mod_len = (int)strlen(mod_b64) + 4;
    uint8_t *mod_bin = malloc((size_t)mod_len);
    uint8_t *exp_bin = malloc((size_t)(strlen(exp_b64) + 4));
    if (!mod_bin || !exp_bin) {
        free(mod_b64); free(exp_b64); free(mod_bin); free(exp_bin); return -1;
    }

    int mod_bytes = base64_decode(mod_b64, mod_bin, mod_len);
    int exp_bytes = base64_decode(exp_b64, exp_bin, (int)strlen(exp_b64) + 4);
    free(mod_b64); free(exp_b64);

    if (mod_bytes <= 0 || exp_bytes <= 0) {
        free(mod_bin); free(exp_bin); return -1;
    }

    *n_out = BN_bin2bn(mod_bin, mod_bytes, NULL);
    *e_out = BN_bin2bn(exp_bin, exp_bytes, NULL);
    *key_bytes_out = mod_bytes;
    free(mod_bin); free(exp_bin);
    return 0;
}

/* ── Static crypto pipeline (layers 1-3) ── */

/* Run crypto layers 1a, 1b, and 2 against the embedded ciphertext in the .so.
 *
 * so_data / so_size : full contents of libPersonalCode.so
 * rsa_key2_xml      : caller-allocated buffer, receives the RSA key #2 XML
 * max_len           : size of rsa_key2_xml buffer (must be >= ~65536)
 *
 * Returns 0 on success, -1 on any decryption or parse failure. */
int run_static_pipeline(const uint8_t *so_data, size_t so_size,
                        char *rsa_key2_xml, size_t max_len) {
    /* Read null-terminated hex strings from .rodata */
    if (AES_CIPHERTEXT1_OFF >= so_size || AES_CIPHERTEXT2_OFF >= so_size) {
        fprintf(stderr, "[!] .so too small for rodata offsets\n");
        return -1;
    }

    const char *hex1 = (const char *)(so_data + AES_CIPHERTEXT1_OFF);
    const char *hex2 = (const char *)(so_data + AES_CIPHERTEXT2_OFF);

    /* Convert static key/iv hex strings to bytes */
    static const char key_hex[] = STATIC_AES_KEY_HEX;
    static const char iv_hex[]  = STATIC_AES_IV_HEX;
    uint8_t aes_key[32], aes_iv[16];
    for (int i = 0; i < 32; i++) {
        unsigned int b;
        sscanf(&key_hex[i*2], "%02x", &b);
        aes_key[i] = (uint8_t)b;
    }
    for (int i = 0; i < 16; i++) {
        unsigned int b;
        sscanf(&iv_hex[i*2], "%02x", &b);
        aes_iv[i] = (uint8_t)b;
    }

    /* Layer 1a: AES → RSA key #1 XML */
    size_t ct1_len = strlen(hex1) / 2;
    uint8_t *ct1 = malloc(ct1_len);
    for (size_t i = 0; i < ct1_len; i++) {
        unsigned int b; sscanf(hex1 + i*2, "%02x", &b); ct1[i] = (uint8_t)b;
    }
    size_t plain1_len;
    uint8_t *plain1 = aes_cbc_decrypt(aes_key, aes_iv, ct1, ct1_len, &plain1_len);
    free(ct1);
    if (!plain1) { fprintf(stderr, "[!] AES layer 1a failed\n"); return -1; }

    /* Find RSA key #1 XML end */
    const char *xml1_end_tag = "</RSAPublicKey>";
    const char *xml1_end = memmem(plain1, plain1_len,
                                   xml1_end_tag, strlen(xml1_end_tag));
    if (!xml1_end) {
        free(plain1);
        fprintf(stderr, "[!] RSA key #1 XML end not found\n");
        return -1;
    }
    size_t xml1_len = (size_t)(xml1_end - (char *)plain1) + strlen(xml1_end_tag);
    char *rsa_key1_xml = malloc(xml1_len + 1);
    memcpy(rsa_key1_xml, plain1, xml1_len);
    rsa_key1_xml[xml1_len] = '\0';
    free(plain1);

    /* Layer 1b: AES → base64 blob */
    size_t ct2_len = strlen(hex2) / 2;
    uint8_t *ct2 = malloc(ct2_len);
    for (size_t i = 0; i < ct2_len; i++) {
        unsigned int b; sscanf(hex2 + i*2, "%02x", &b); ct2[i] = (uint8_t)b;
    }
    size_t plain2_len;
    uint8_t *plain2 = aes_cbc_decrypt(aes_key, aes_iv, ct2, ct2_len, &plain2_len);
    free(ct2);
    if (!plain2) { free(rsa_key1_xml); fprintf(stderr, "[!] AES layer 1b failed\n"); return -1; }

    /* Extract base64 blob (trim non-base64 bytes) */
    size_t b64_end = 0;
    for (size_t i = 0; i < plain2_len; i++) {
        uint8_t c = plain2[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
            b64_end = i + 1;
        } else {
            break;
        }
    }
    char *b64_blob = malloc(b64_end + 1);
    memcpy(b64_blob, plain2, b64_end);
    b64_blob[b64_end] = '\0';
    free(plain2);

    /* Parse RSA key #1 */
    BIGNUM *n1 = NULL, *e1 = NULL;
    int ks1;
    BN_CTX *bnc = BN_CTX_new();
    if (parse_rsa_xml(rsa_key1_xml, &n1, &e1, &ks1) != 0) {
        free(rsa_key1_xml); free(b64_blob); BN_CTX_free(bnc);
        fprintf(stderr, "[!] Failed to parse RSA key #1\n");
        return -1;
    }
    free(rsa_key1_xml);
    fprintf(stderr, "[*] RSA key #1: %d-bit\n", ks1 * 8);

    /* Layer 2: RSA decrypt blob → RSA key #2 */
    /* Decode base64 blob */
    size_t blob_bin_len = (b64_end * 3 / 4) + 4;
    uint8_t *blob_bin = malloc(blob_bin_len);
    int decoded = base64_decode(b64_blob, blob_bin, (int)blob_bin_len);
    free(b64_blob);
    if (decoded <= 0) {
        free(blob_bin); BN_free(n1); BN_free(e1); BN_CTX_free(bnc);
        fprintf(stderr, "[!] Failed to decode base64 blob\n");
        return -1;
    }

    size_t rsa2_len;
    uint8_t *rsa2_plain = rsa_pkcs1_decrypt_multiblock(n1, e1, ks1,
                                                        blob_bin, (size_t)decoded,
                                                        bnc, &rsa2_len);
    free(blob_bin);
    BN_free(n1); BN_free(e1); BN_CTX_free(bnc);

    if (!rsa2_plain) {
        fprintf(stderr, "[!] RSA layer 2 failed\n");
        return -1;
    }

    /* Validate and copy RSA key #2 XML */
    const char *end_tag = "</RSAPublicKey>";
    const char *xml2_end = memmem(rsa2_plain, rsa2_len, end_tag, strlen(end_tag));
    if (!xml2_end) {
        free(rsa2_plain);
        fprintf(stderr, "[!] RSA key #2 XML end not found\n");
        return -1;
    }
    size_t xml2_len = (size_t)(xml2_end - (char *)rsa2_plain) + strlen(end_tag);
    if (xml2_len + 1 > max_len) xml2_len = max_len - 1;
    memcpy(rsa_key2_xml, rsa2_plain, xml2_len);
    rsa_key2_xml[xml2_len] = '\0';
    free(rsa2_plain);

    fprintf(stderr, "[*] RSA key #2: derived (%zu chars)\n", xml2_len);
    return 0;
}

/* ── Pre-compute decrypted buf2 ── */

/* Pre-compute the plaintext of the buf2 region so emulator.c can inject it.
 *
 * The INE payload layout places a 1024-byte RSA ciphertext block at byte
 * offset 688 of the combined QR buffer.  This function decrypts it with
 * RSA public key #2 (PKCS#1 v1.5 raw) so that emulator.c can write the
 * plaintext to DATA_ADDR+0x2000 before emulation starts and redirect the
 * AppendBinary2[1] call to use it instead of the emulated RSA result.
 *
 * Returns a malloc'd plaintext buffer and writes its length to *out_len.
 * Returns NULL if the combined buffer is too short, key parse fails, or
 * the PKCS#1 structure is invalid. */
uint8_t *precompute_buf2(const char *rsa_key2_xml,
                         const uint8_t *combined, size_t combined_len,
                         size_t *out_len) {
    if (combined_len < 688 + 1024) {
        fprintf(stderr, "[!] Combined payload too short (%zu < %d)\n",
                combined_len, 688 + 1024);
        return NULL;
    }

    BIGNUM *n2 = NULL, *e2 = NULL;
    int ks2;
    BN_CTX *bnc = BN_CTX_new();
    if (parse_rsa_xml(rsa_key2_xml, &n2, &e2, &ks2) != 0) {
        BN_CTX_free(bnc);
        fprintf(stderr, "[!] Failed to parse RSA key #2 for buf2 decrypt\n");
        return NULL;
    }

    const uint8_t *buf2 = combined + 688;
    /* RSA raw decrypt of 1024 bytes */
    BIGNUM *c_bn = BN_bin2bn(buf2, 1024, NULL);
    BIGNUM *m_bn = BN_new();
    BN_mod_exp(m_bn, c_bn, e2, n2, bnc);
    uint8_t raw[1024];
    memset(raw, 0, sizeof(raw));
    int mlen = BN_num_bytes(m_bn);
    BN_bn2bin(m_bn, raw + ks2 - mlen);
    BN_free(c_bn); BN_free(m_bn); BN_free(n2); BN_free(e2); BN_CTX_free(bnc);

    /* Strip PKCS#1 v1.5 */
    if (raw[0] != 0x00 || (raw[1] != 0x01 && raw[1] != 0x02)) {
        fprintf(stderr, "[!] buf2 PKCS#1 header invalid: %02x %02x\n",
                raw[0], raw[1]);
        return NULL;
    }
    int sep = -1;
    for (int i = 2; i < ks2; i++) {
        if (raw[i] == 0x00) { sep = i; break; }
    }
    if (sep < 0) {
        fprintf(stderr, "[!] buf2 PKCS#1 no null separator\n");
        return NULL;
    }
    size_t plain_len = (size_t)(ks2 - sep - 1);
    uint8_t *plain = malloc(plain_len);
    if (!plain) return NULL;
    memcpy(plain, raw + sep + 1, plain_len);
    *out_len = plain_len;
    fprintf(stderr, "[*] Decrypted buf2: %zu bytes (PKCS#1 type %d)\n",
            plain_len, raw[1]);
    return plain;
}
