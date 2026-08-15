/* Tiny base64 decoder. Skips whitespace, accepts trailing '='.
 * Returns number of decoded bytes written to out, or -1 on bad input. */
#pragma once
#include <stdint.h>

int base64_decode(const char *b64, uint8_t *out, int out_max);
