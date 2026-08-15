package mx.ine.qr.internal

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import com.google.mlkit.vision.barcode.BarcodeScanner
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

internal object MlKitScanner {

    private val client: BarcodeScanner by lazy {
        BarcodeScanning.getClient(
            BarcodeScannerOptions.Builder()
                .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
                .build()
        )
    }

    /**
     * Decode a JPEG/PNG/HEIF/WebP image and return the two 858-byte INE QR
     * payloads in left/right order. Throws [IllegalStateException] if exactly
     * two valid QRs cannot be located.
     *
     * The library does no orientation correction beyond what BitmapFactory
     * provides — callers feeding raw camera frames should rotate to portrait
     * before calling.
     */
    suspend fun extractPayloads(imageBytes: ByteArray, maxLongEdge: Int): Pair<ByteArray, ByteArray> {
        val bitmap = decodeAndDownsample(imageBytes, maxLongEdge)
            ?: error("BitmapFactory could not decode image bytes")
        val image = InputImage.fromBitmap(bitmap, /*rotationDegrees=*/ 0)
        val barcodes = await(image)
        bitmap.recycle()

        // INE credentials carry binary QR payloads, not text. Read raw bytes.
        val payloads = barcodes.mapNotNull { it.rawBytes }
            .filter { it.size == 858 && it[0] == 0x00.toByte() }
        if (payloads.size < 2) {
            error("Found ${payloads.size} valid INE QR(s), expected 2")
        }

        // Header byte 1 is the side index: 0 = left, 1 = right.
        val left  = payloads.firstOrNull { it[1] == 0x00.toByte() }
            ?: error("Left QR (index 0) not found")
        val right = payloads.firstOrNull { it[1] == 0x01.toByte() }
            ?: error("Right QR (index 1) not found")
        return left to right
    }

    private fun decodeAndDownsample(bytes: ByteArray, maxLongEdge: Int): Bitmap? {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
        if (bounds.outWidth <= 0) return null

        var sample = 1
        if (maxLongEdge > 0) {
            val long = maxOf(bounds.outWidth, bounds.outHeight)
            while (long / sample > maxLongEdge) sample *= 2
        }
        val opts = BitmapFactory.Options().apply { inSampleSize = sample }
        return BitmapFactory.decodeByteArray(bytes, 0, bytes.size, opts)
    }

    private suspend fun await(image: InputImage): List<Barcode> =
        suspendCancellableCoroutine { cont ->
            client.process(image)
                .addOnSuccessListener { cont.resume(it) }
                .addOnFailureListener { cont.resumeWithException(it) }
        }
}
