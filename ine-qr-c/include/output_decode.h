/* ══ FILE: output_decode.h ══
 *
 * Public interface for the pc() result decoder (output_decode.c).
 *
 * After the crypto pipeline runs, the resulting buffer carries the
 * biographical text + WebP photo packed back-to-back. Two consumers:
 *
 *   decode_and_write   — file-based output (used by the CLI binary).
 *   decode_to_buffers  — in-memory output (used by the embedding library
 *                        and any cgo caller that wants zero disk I/O).
 */

#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Parse the binary pc() return buffer and write output files to output_dir.
 * Writes datos_biograficos.json, foto_ine.webp, texto_biografico.txt.
 * Returns 0 on success, -1 on parse error or file I/O failure. */
int decode_and_write(const uint8_t *decoded_bin, size_t len,
                     const char *output_dir);

/* Same as decode_and_write but returns the JSON and WebP as malloc'd
 * buffers instead of writing to disk.
 *
 *   *json_out  : null-terminated UTF-8 JSON. Caller must free().
 *   *json_len  : strlen(*json_out).
 *   *webp_out  : raw WebP bytes (may be NULL if no photo present).
 *                Caller must free().
 *   *webp_len  : byte count of *webp_out (0 if NULL).
 *
 * On failure all out-pointers are set to NULL/0 and -1 is returned. */
int decode_to_buffers(const uint8_t *decoded_bin, size_t len,
                      char    **json_out, size_t *json_len,
                      uint8_t **webp_out, size_t *webp_len);

#ifdef __cplusplus
}
#endif
