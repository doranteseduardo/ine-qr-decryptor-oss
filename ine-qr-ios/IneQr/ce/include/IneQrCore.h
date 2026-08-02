/* ══ FILE: IneQrCore.h ══
 *
 * Umbrella header for the IneQrCore SwiftPM C target.
 *
 * Swift imports this module and gets the two public C functions:
 *   run_no_so_pipeline  — full crypto pipeline; combined → decoded buffer.
 *   decode_to_buffers   — decoded buffer → (json, webp).
 *
 * Internal headers (vendored bignum, AES, base64, ine_crypto_backend) are
 * not exposed; they live alongside as non-public sources.
 */

#pragma once

#include "no_so_crypto.h"
#include "output_decode.h"
