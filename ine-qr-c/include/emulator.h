/* ══ FILE: emulator.h ══
 *
 * Public interface for the ARM64 Unicorn emulator harness (emulator.c).
 *
 * Typical call sequence:
 *   INEContext ctx;
 *   emu_context_init(&ctx, so_data, so_size, verbose);
 *   int rc = emu_run(&ctx, combined, combined_len, rsa_key2_xml);
 *   // use ctx.result_data / ctx.result_len
 *   free(ctx.result_data);
 */

#pragma once
#include "ine_types.h"

/* Zero-initialise ctx and allocate the OpenSSL BN_CTX scratch space.
 * so_data/so_size must remain valid until after emu_run() returns. */
void emu_context_init(INEContext *ctx, uint8_t *so_data, size_t so_size, int verbose);

/* Run the full ARM64 emulation of the pc() JNI function.
 *
 * combined      : concatenated QR payload left[2:] + right[2:], 1712 bytes
 * combined_len  : byte count (must be 1712)
 * rsa_key2_xml  : RSA public key #2 XML produced by run_static_pipeline()
 *
 * On success: returns 0; ctx->result_data holds a malloc'd byte array of
 * length ctx->result_len containing the decoded binary output.
 * On failure: returns -1; ctx->result_data is NULL. */
int emu_run(INEContext *ctx,
            const uint8_t *combined, size_t combined_len,
            const char *rsa_key2_xml);
