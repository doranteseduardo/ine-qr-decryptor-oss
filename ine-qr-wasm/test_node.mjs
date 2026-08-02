// Node smoke test for the WASM build.
//
// Exercises the output-decode stage through the test-only `_decode_decrypted`
// export against a SYNTHETIC, PII-free fixture (fixtures/synthetic_decoded.bin,
// an already-"decrypted" buffer with obviously-fake fields + a placeholder
// photo). It validates WASM marshalling + the CHAR_TABLE bit-unpacking + WebP
// passthrough, and asserts the JSON matches fixtures/expected.json.
//
// It does NOT test the AES/RSA crypto layers: a genuine encrypted QR payload
// cannot be fabricated (the pipeline's RSA layers use recovered PUBLIC keys),
// and no real credential data ships in this repository. Run `./build.sh` first
// to produce dist/ine_qr.{js,wasm}.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const createIneQrModule = (await import(resolve(here, "dist/ine_qr.js"))).default;

const decodedBin = readFileSync(resolve(here, "fixtures/synthetic_decoded.bin"));
const expectedJson = readFileSync(resolve(here, "fixtures/expected.json"), "utf8");
console.log(`synthetic_decoded.bin: ${decodedBin.length} bytes`);

const Module = await createIneQrModule();

const t0 = performance.now();
const ptr = Module._alloc_buf(decodedBin.length);
Module.HEAPU8.set(decodedBin, ptr);
const rc = Module._decode_decrypted(ptr, decodedBin.length);
const t1 = performance.now();
Module._free_buf(ptr);

if (rc !== 0) {
  console.error(`decode_decrypted failed: rc=${rc}`);
  process.exit(1);
}

const json_ptr = Module._get_json_ptr();
const json_len = Module._get_json_len();
const webp_ptr = Module._get_webp_ptr();
const webp_len = Module._get_webp_len();

const json = Module.UTF8ToString(json_ptr, json_len);

console.log(`decode: ${(t1 - t0).toFixed(1)} ms`);
console.log(`json: ${json_len} bytes, webp: ${webp_len} bytes`);
console.log("─── JSON ───");
console.log(json);

if (json !== expectedJson) {
  console.error("MISMATCH: decoded JSON does not match fixtures/expected.json");
  process.exit(1);
}
if (webp_len === 0) {
  console.error("MISMATCH: expected a non-empty WebP photo");
  process.exit(1);
}
console.log("\nOK: JSON matches the synthetic reference; WebP is non-empty.");
