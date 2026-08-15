package mx.ine.qr

import androidx.annotation.WorkerThread
import mx.ine.qr.internal.MlKitScanner
import mx.ine.qr.internal.NativeBridge

/**
 * INE voter-credential QR decoder.
 *
 * The cryptographic pipeline (AES-256-CBC + RSA-8192 + bit-packing) runs
 * natively against BoringSSL via JNI. QR extraction uses ML Kit's bundled
 * barcode model (offline, no Play Services download).
 *
 * Three entry points:
 *   * [decodeImage]    — full pipeline including QR detection.
 *   * [decodePayloads] — caller already has the two 858-byte QR payloads.
 *   * [decodeCombined] — caller already concatenated the 1712-byte combined
 *                       buffer. Useful for tests and for any custom scanner.
 */
object IneQr {

    /**
     * Decode a credential photo. Convenience wrapper that runs ML Kit in
     * the calling coroutine context, then jumps to native code for the
     * crypto pipeline.
     *
     * @param bytes        JPEG/PNG/HEIF/WebP image bytes.
     * @param maxLongEdge  Downsample to this max long edge before scanning.
     *                     Defaults to 3000 px to match the Go API. Pass 0
     *                     to disable downsampling.
     */
    suspend fun decodeImage(bytes: ByteArray, maxLongEdge: Int = 3000): IneResult {
        val (left, right) = MlKitScanner.extractPayloads(bytes, maxLongEdge)
        return decodePayloads(left, right)
    }

    /**
     * Decode from already-extracted QR payloads.
     * Each payload is the raw 858-byte QR content (2-byte header + 856-byte body).
     */
    @WorkerThread
    fun decodePayloads(left: ByteArray, right: ByteArray): IneResult {
        if (left.size != 858) throw Error.InvalidPayload("left QR is ${left.size} bytes, expected 858")
        if (right.size != 858) throw Error.InvalidPayload("right QR is ${right.size} bytes, expected 858")

        val combined = ByteArray(1712)
        System.arraycopy(left, 2, combined, 0, 856)
        System.arraycopy(right, 2, combined, 856, 856)
        return decodeCombined(combined)
    }

    /**
     * Decode from the 1712-byte concatenated payload (left[2..] + right[2..]).
     * Equivalent to what the Go API receives over its raw-payload endpoint.
     */
    @WorkerThread
    fun decodeCombined(combined: ByteArray): IneResult {
        if (combined.size != 1712) {
            throw Error.InvalidPayload("combined is ${combined.size} bytes, expected 1712")
        }
        return NativeBridge.decodeCombinedNative(combined)
    }

    /** Errors thrown by the decoder. JNI side throws by FQCN. */
    sealed class Error(message: String) : RuntimeException(message) {
        class InvalidPayload(message: String) : Error(message)
        class CryptoFailure(message: String) : Error(message)
        class OutputDecode(message: String) : Error(message)
    }
}
