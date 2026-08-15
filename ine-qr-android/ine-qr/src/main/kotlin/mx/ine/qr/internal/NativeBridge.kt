package mx.ine.qr.internal

import mx.ine.qr.IneResult

internal object NativeBridge {
    init {
        System.loadLibrary("ine_qr_jni")
    }

    @JvmStatic
    external fun decodeCombinedNative(combined: ByteArray): IneResult

    /**
     * Test-only: decode an already-decrypted buffer directly via
     * decode_to_buffers(), skipping the AES/RSA crypto pipeline. Exercised by
     * OutputDecodeParityTest with a synthetic, PII-free fixture. Not used by
     * any production entry point in [mx.ine.qr.IneQr].
     */
    @JvmStatic
    external fun decodeDecryptedNative(decodedBin: ByteArray): IneResult
}
