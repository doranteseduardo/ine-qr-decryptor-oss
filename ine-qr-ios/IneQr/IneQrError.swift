import Foundation

/// Errors thrown by the `IneQr` decoder.
public enum IneQrError: Error, Equatable, Sendable {
    /// The image could not be decoded into a bitmap, or no QR was found.
    case noQrFound
    /// Exactly one of the two INE QRs was missing or malformed.
    case missingQrSide(expected: Int, found: Int)
    /// A QR payload had an unexpected size or header byte.
    case invalidPayload(reason: String)
    /// The crypto pipeline rejected the input. `stage` is one of
    /// `"round1"`, `"round2"`, `"stageA"`, `"stageB"`, `"stageC"`.
    case cryptoFailure(stage: String)
    /// Output decoding (text bit-unpack or WebP interleave) failed.
    case outputDecode(reason: String)
}
