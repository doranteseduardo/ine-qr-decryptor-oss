package mx.ine.qr

/**
 * Decoded INE credential.
 *
 * @property json   18 biographical fields as a UTF-8 JSON string. Always
 *                  populated on success.
 * @property webp   Photo as raw WebP bytes (96×129 px). Empty if the
 *                  credential carried no photo (rare but possible).
 */
class IneResult(
    val json: String,
    val webp: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is IneResult) return false
        return json == other.json && webp.contentEquals(other.webp)
    }

    override fun hashCode(): Int = 31 * json.hashCode() + webp.contentHashCode()
}
