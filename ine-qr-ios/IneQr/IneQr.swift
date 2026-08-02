import Foundation
import IneQrCore

/// INE voter-credential QR decoder.
///
/// The cryptographic pipeline (AES-256-CBC + RSA-8192 + bit-packing) runs in
/// C against a vendored bignum + AES + base64 (same code the WASM build
/// uses). QR detection uses Apple Vision (with a CIDetector fallback for
/// iOS 15 compatibility).
///
/// Three entry points:
///   * `decodeImage` — full pipeline including QR detection.
///   * `decodePayloads` — caller already has the two 858-byte QR payloads.
///   * `decodeCombined` — caller already concatenated the 1712-byte buffer.
public enum IneQr {

    /// Decode a credential photograph.
    public static func decodeImage(_ imageData: Data) async throws -> IneResult {
        let (left, right) = try await VisionScanner.extractPayloads(from: imageData)
        return try decodePayloads(left: left, right: right)
    }

    /// Decode from already-extracted QR payloads.
    /// Each payload is the raw 858-byte QR content (2-byte header + 856-byte body).
    public static func decodePayloads(left: Data, right: Data) throws -> IneResult {
        if left.count  != 858 { throw IneQrError.invalidPayload(reason: "left is \(left.count) bytes, expected 858") }
        if right.count != 858 { throw IneQrError.invalidPayload(reason: "right is \(right.count) bytes, expected 858") }

        var combined = Data(count: 1712)
        combined.replaceSubrange(0..<856,    with: left.suffix(856))
        combined.replaceSubrange(856..<1712, with: right.suffix(856))
        return try decodeCombined(combined)
    }

    /// Decode from the 1712-byte concatenated payload (`left[2...] + right[2...]`).
    public static func decodeCombined(_ combined: Data) throws -> IneResult {
        if combined.count != 1712 {
            throw IneQrError.invalidPayload(reason: "combined is \(combined.count) bytes, expected 1712")
        }
        return try combined.withUnsafeBytes { (buf: UnsafeRawBufferPointer) -> IneResult in
            guard let base = buf.bindMemory(to: UInt8.self).baseAddress else {
                throw IneQrError.invalidPayload(reason: "combined buffer is empty")
            }

            var decoded: UnsafeMutablePointer<UInt8>? = nil
            var decodedLen: Int = 0
            let rc = run_no_so_pipeline(base, buf.count, &decoded, &decodedLen)
            guard rc == 0, let decoded else {
                if decoded != nil { free(decoded) }
                throw IneQrError.cryptoFailure(stage: "pipeline")
            }
            defer { free(decoded) }

            var jsonPtr: UnsafeMutablePointer<CChar>? = nil
            var jsonLen: Int = 0
            var webpPtr: UnsafeMutablePointer<UInt8>? = nil
            var webpLen: Int = 0
            let rc2 = decode_to_buffers(decoded, decodedLen,
                                        &jsonPtr, &jsonLen,
                                        &webpPtr, &webpLen)
            guard rc2 == 0, let jsonPtr else {
                if jsonPtr != nil { free(jsonPtr) }
                if webpPtr != nil { free(webpPtr) }
                throw IneQrError.outputDecode(reason: "decode_to_buffers failed")
            }
            defer {
                free(jsonPtr)
                if webpPtr != nil { free(webpPtr) }
            }

            let json = String(cString: jsonPtr)
            let webp: Data
            if let webpPtr, webpLen > 0 {
                webp = Data(bytes: webpPtr, count: webpLen)
            } else {
                webp = Data()
            }
            return IneResult(json: json, webp: webp)
        }
    }

    /// Test-only: decode an ALREADY-decrypted buffer directly via
    /// `decode_to_buffers()`, skipping the AES/RSA crypto pipeline.
    ///
    /// The buffer layout is `2-byte BE text_len + CHAR_TABLE text + 2-byte BE
    /// img_len + WebP`. Used by `OutputDecodeParityTests` to exercise the
    /// Swift/C marshalling + bit-unpacking + WebP passthrough against a
    /// synthetic, PII-free fixture, without a real encrypted QR payload
    /// (which cannot be forged — the RSA layers use recovered public keys).
    /// Not used by any production entry point.
    static func decodeDecrypted(_ decodedBin: Data) throws -> IneResult {
        return try decodedBin.withUnsafeBytes { (buf: UnsafeRawBufferPointer) -> IneResult in
            let base = buf.bindMemory(to: UInt8.self).baseAddress

            var jsonPtr: UnsafeMutablePointer<CChar>? = nil
            var jsonLen: Int = 0
            var webpPtr: UnsafeMutablePointer<UInt8>? = nil
            var webpLen: Int = 0
            let rc = decode_to_buffers(base, buf.count,
                                       &jsonPtr, &jsonLen,
                                       &webpPtr, &webpLen)
            guard rc == 0, let jsonPtr else {
                if jsonPtr != nil { free(jsonPtr) }
                if webpPtr != nil { free(webpPtr) }
                throw IneQrError.outputDecode(reason: "decode_to_buffers failed")
            }
            defer {
                free(jsonPtr)
                if webpPtr != nil { free(webpPtr) }
            }

            let json = String(cString: jsonPtr)
            let webp: Data
            if let webpPtr, webpLen > 0 {
                webp = Data(bytes: webpPtr, count: webpLen)
            } else {
                webp = Data()
            }
            return IneResult(json: json, webp: webp)
        }
    }
}
