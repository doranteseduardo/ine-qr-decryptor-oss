package mx.ine.qr

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import mx.ine.qr.internal.NativeBridge
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Parity check for the output-decode stage using SYNTHETIC data.
 *
 * This validates the JNI marshalling + the CHAR_TABLE bit-unpacking + the
 * WebP passthrough performed by `decode_to_buffers()`, driven through the
 * test-only `NativeBridge.decodeDecryptedNative` entry point. The input is a
 * synthetic, PII-free `synthetic_decoded.bin` (an already-"decrypted" buffer
 * carrying obviously-fake fields — CURP `XEXX010101HNEXXXA4`, name
 * `JUAN PEREZ EXAMPLE` — and a placeholder photo), and the expected
 * `expected.json` / `expected.webp` were produced by running the real C
 * decoder over that same buffer (see `scripts/gen_synthetic_fixture.py`).
 *
 * It deliberately does NOT test the AES/RSA crypto layers. A genuine encrypted
 * QR payload cannot be fabricated (the pipeline's RSA layers use recovered
 * PUBLIC keys; INE holds the private key), and no real credential data ships
 * in this repository. Full crypto-layer regression against a real credential
 * remains a manual, non-public step for the maintainer.
 */
@RunWith(AndroidJUnit4::class)
class OutputDecodeParityTest {

    private val ctx by lazy { InstrumentationRegistry.getInstrumentation().context }

    private fun asset(name: String): ByteArray =
        ctx.assets.open("fixtures/$name").use { it.readBytes() }

    @Test
    fun decodeDecrypted_matches_synthetic_reference() {
        val decodedBin = asset("synthetic_decoded.bin")
        val expectedJson = String(asset("expected.json"), Charsets.UTF_8)
        val expectedWebp = asset("expected.webp")

        val result = NativeBridge.decodeDecryptedNative(decodedBin)

        assertEquals("JSON must match the synthetic reference byte-for-byte",
            expectedJson, result.json)
        assertArrayEquals("WebP must match the synthetic reference byte-for-byte",
            expectedWebp, result.webp)
    }
}
