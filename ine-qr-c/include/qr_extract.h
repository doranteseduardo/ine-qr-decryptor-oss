#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t left[858];
    uint8_t right[858];
    int     ok;
    char    err[256];
} QRPair;

/* Extract the two INE QR codes from an image file (JPEG, PNG, HEIC).
   HEIC is handled via sips on macOS.
   Returns QRPair with ok=1 on success, ok=0 with err message on failure. */
QRPair qr_extract(const char *path);

/* Same as qr_extract but reads the image from memory (JPEG/PNG/HEIC).
 * If max_long_edge > 0 and the decoded image exceeds it on the longer edge,
 * the image is downsampled before QR scanning to cap zxing-cpp's workload.
 * HEIC support requires the host to provide a converter; on macOS this
 * spills the bytes to a temp file and shells out to sips. On Linux without
 * libheif this returns an "unsupported format" error. */
QRPair qr_extract_from_memory(const uint8_t *data, size_t len,
                              int max_long_edge);

#ifdef __cplusplus
}
#endif
