/* qr_extract.c — Eskiu adapter over ine-qr-c's portable QR extractor.
 *
 * Eskiu declares:  extern int ine_qr_extract(string path, *QRPair out)
 * This forwards to ine-qr-c's qr_extract(path), which loads JPEG/PNG with
 * stb_image and scans with zxing-cpp (HEIC via `sips` on macOS). That path is
 * cross-platform — exactly what the C CLI uses — so the Eskiu port builds and
 * runs on Linux as well as macOS.
 *
 * QRPair here is ine-qr-c's struct (from ../../ine-qr-c/include/qr_extract.h);
 * its layout is byte-identical to decoder/types.esk's QRPair, so the memcpy
 * into the Eskiu-allocated struct is safe.
 */
#include "qr_extract.h"   /* resolved via -I../ine-qr-c/include */
#include <string.h>

int ine_qr_extract(const char *path, QRPair *out) {
    QRPair r = qr_extract(path);
    memcpy(out, &r, sizeof(QRPair));
    return r.ok;
}
