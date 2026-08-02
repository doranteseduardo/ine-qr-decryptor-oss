/* ══ FILE: qr_extract.cpp ══
 *
 * QR code extraction from INE (Mexican voter ID) credential photos.
 *
 * An INE credential carries two QR codes side by side (izquierdo / derecho).
 * Each QR encodes exactly 858 bytes with a two-byte header:
 *   byte 0 : 0x00   (type tag — always zero for INE QR)
 *   byte 1 : 0 or 1 (side index: 0 = left / izquierdo, 1 = right / derecho)
 *   bytes 2-857 : 856-byte encrypted payload slice
 *
 * Two entry points:
 *   qr_extract(path)              — file-path API used by the CLI binary.
 *   qr_extract_from_memory(...)   — in-memory API used by the embedding
 *                                   library (no temp files, optional
 *                                   downsampling cap before zxing).
 *
 * Both share the same scan-and-classify core (scan_image_rgba).
 */

#include "qr_extract.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <strings.h>

/* stb_image is the single-header JPEG/PNG decoder. HEIC is handled
 * out-of-band (sips on macOS, currently unsupported on Linux). */
#define STB_IMAGE_IMPLEMENTATION
#define STBI_NO_BMP
#define STBI_NO_PSD
#define STBI_NO_TGA
#define STBI_NO_GIF
#define STBI_NO_PIC
#include "../vendor/stb_image.h"

#define STB_IMAGE_RESIZE_IMPLEMENTATION
#include "../vendor/stb_image_resize2.h"

#include <ZXing/ReadBarcode.h>
#include <ZXing/ReaderOptions.h>
#include <ZXing/BarcodeFormat.h>

namespace {

/* Run zxing on an RGBA buffer and select the two INE QR payloads. */
QRPair scan_image_rgba(const unsigned char *img, int width, int height,
                       const char *origin) {
    QRPair result{};
    result.ok = 0;

    fprintf(stderr, "[*] Image: %dx%d (%s)\n", width, height, origin);

    ZXing::ImageView iv(img, width, height, ZXing::ImageFormat::RGBA);
    ZXing::ReaderOptions opts;
    opts.setFormats(ZXing::BarcodeFormat::QRCode);
    opts.setTryHarder(true);
    opts.setTryRotate(true);

    auto barcodes = ZXing::ReadBarcodes(iv, opts);
    fprintf(stderr, "[*] Barcodes found: %zu\n", barcodes.size());

    const ZXing::Barcode *left_bc  = nullptr;
    const ZXing::Barcode *right_bc = nullptr;

    for (const auto &bc : barcodes) {
        const auto &bytes = bc.bytes();
        if (bytes.size() != 858) {
            fprintf(stderr, "    %s: %zu bytes (skipped, not INE QR)\n",
                    ZXing::ToString(bc.format()).c_str(), bytes.size());
            continue;
        }
        if (bytes[0] != 0x00) {
            fprintf(stderr, "    %s: header=0x%02x (skipped, invalid header)\n",
                    ZXing::ToString(bc.format()).c_str(), bytes[0]);
            continue;
        }
        if (bytes[1] == 0) {
            left_bc = &bc;
            fprintf(stderr, "    QR izquierdo: %zu bytes\n", bytes.size());
        } else if (bytes[1] == 1) {
            right_bc = &bc;
            fprintf(stderr, "    QR derecho: %zu bytes\n", bytes.size());
        } else {
            fprintf(stderr, "    %s: index=%d (skipped)\n",
                    ZXing::ToString(bc.format()).c_str(), bytes[1]);
        }
    }

    if (!left_bc || !right_bc) {
        const char *missing = (!left_bc && !right_bc) ? "both" :
                              (!left_bc)              ? "izquierdo" : "derecho";
        snprintf(result.err, sizeof(result.err),
                 "Missing QR: %s. Ensure photo has both QRs with good resolution.",
                 missing);
        return result;
    }

    memcpy(result.left,  left_bc->bytes().data(),  858);
    memcpy(result.right, right_bc->bytes().data(), 858);
    result.ok = 1;
    return result;
}

/* Optionally downsample an RGBA image to cap zxing's per-frame cost.
 * Caller passes ownership of *img in (allocated by stb_image, freed with
 * stbi_image_free); on resize this function frees the original and
 * substitutes a malloc'd buffer that the caller must release with free().
 *
 * Returns false if resize was needed but allocation failed; in that case
 * the original image is preserved and the caller can still scan it. */
struct RGBAImage {
    unsigned char *data;
    int width;
    int height;
    bool from_stbi;          /* true → free with stbi_image_free, false → free() */
};

bool maybe_downsample(RGBAImage *img, int max_long_edge) {
    if (max_long_edge <= 0) return true;
    int longest = (img->width >= img->height) ? img->width : img->height;
    if (longest <= max_long_edge) return true;

    double scale = (double)max_long_edge / (double)longest;
    int new_w = (int)(img->width  * scale + 0.5);
    int new_h = (int)(img->height * scale + 0.5);

    unsigned char *resized = (unsigned char *)malloc((size_t)new_w * new_h * 4);
    if (!resized) return false;

    /* stbir_resize_uint8_linear is the simplest API in stb_image_resize2.
     * Linear sampling is plenty for QR detection — the codes are large
     * relative to the image and zxing tolerates softness. */
    if (!stbir_resize_uint8_linear(img->data, img->width, img->height, 0,
                                   resized, new_w, new_h, 0,
                                   STBIR_RGBA)) {
        free(resized);
        return false;
    }

    fprintf(stderr, "[*] Downsampled %dx%d → %dx%d (max_long_edge=%d)\n",
            img->width, img->height, new_w, new_h, max_long_edge);

    if (img->from_stbi) stbi_image_free(img->data);
    else                free(img->data);

    img->data      = resized;
    img->width     = new_w;
    img->height    = new_h;
    img->from_stbi = false;
    return true;
}

void free_rgba(RGBAImage *img) {
    if (!img->data) return;
    if (img->from_stbi) stbi_image_free(img->data);
    else                free(img->data);
    img->data = nullptr;
}

} /* anonymous namespace */

/* File-path API (preserved for the CLI binary). */
extern "C" QRPair qr_extract(const char *path) {
    QRPair result{};
    result.ok = 0;

    /* HEIC fallback via sips on macOS (no-op on Linux — sips absent). */
    const char *load_path = path;
    char tmp_path[512] = {};
    bool used_tmp = false;
    {
        const char *dot = strrchr(path, '.');
        if (dot && (strcasecmp(dot, ".heic") == 0 || strcasecmp(dot, ".heif") == 0)) {
            snprintf(tmp_path, sizeof(tmp_path), "/tmp/ine_heic_%d.jpg", (int)getpid());
            char cmd[1024];
            snprintf(cmd, sizeof(cmd),
                     "sips -s format jpeg \"%s\" --out \"%s\" >/dev/null 2>&1",
                     path, tmp_path);
            if (system(cmd) == 0) {
                load_path = tmp_path;
                used_tmp  = true;
            } else {
                snprintf(result.err, sizeof(result.err),
                         "sips conversion failed for %s", path);
                return result;
            }
        }
    }

    int width, height, channels;
    unsigned char *img_data = stbi_load(load_path, &width, &height, &channels, 4);
    if (used_tmp) remove(tmp_path);

    if (!img_data) {
        snprintf(result.err, sizeof(result.err),
                 "stbi_load failed: %s", stbi_failure_reason());
        return result;
    }

    result = scan_image_rgba(img_data, width, height, "from file");
    stbi_image_free(img_data);
    return result;
}

/* In-memory API used by libine_decode for cgo callers. */
extern "C" QRPair qr_extract_from_memory(const uint8_t *data, size_t len,
                                         int max_long_edge) {
    QRPair result{};
    result.ok = 0;

    if (!data || len < 12) {
        snprintf(result.err, sizeof(result.err), "image buffer too small");
        return result;
    }

    /* HEIC/HEIF magic: bytes 4-11 contain "ftyp" then a brand. We don't try
     * to decode it in pure C — return a clear error instead. */
    if (len >= 12 && memcmp(data + 4, "ftyp", 4) == 0) {
        const char *brand = (const char *)(data + 8);
        if (memcmp(brand, "heic", 4) == 0 || memcmp(brand, "heix", 4) == 0 ||
            memcmp(brand, "mif1", 4) == 0 || memcmp(brand, "msf1", 4) == 0 ||
            memcmp(brand, "heim", 4) == 0 || memcmp(brand, "heis", 4) == 0) {
            snprintf(result.err, sizeof(result.err),
                     "HEIC not supported in-memory: re-encode to JPEG or PNG client-side");
            return result;
        }
    }

    int width, height, channels;
    unsigned char *raw = stbi_load_from_memory(data, (int)len,
                                               &width, &height, &channels, 4);
    if (!raw) {
        snprintf(result.err, sizeof(result.err),
                 "stbi_load_from_memory failed: %s", stbi_failure_reason());
        return result;
    }

    RGBAImage img{raw, width, height, /*from_stbi=*/true};
    if (!maybe_downsample(&img, max_long_edge)) {
        fprintf(stderr, "[!] Downsample alloc failed; scanning original\n");
    }

    result = scan_image_rgba(img.data, img.width, img.height, "from memory");
    free_rgba(&img);
    return result;
}
