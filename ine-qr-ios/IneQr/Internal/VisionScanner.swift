import Foundation
import Vision
import CoreImage

/// Extracts the two INE QR payloads (each 858 bytes, binary) from a credential
/// photograph using Apple's Vision framework.
///
/// Vision's `VNBarcodeObservation.descriptor` exposes the raw QR payload via
/// `CIQRCodeDescriptor.errorCorrectedPayload`. INE QRs are binary (not text),
/// so we go through the descriptor — `payloadStringValue` would return `nil`.
///
/// If the descriptor cast fails on a given iOS version, we fall back to
/// `CIDetector` which has exposed `symbolDescriptor` since iOS 11.
enum VisionScanner {

    static func extractPayloads(from imageData: Data) async throws -> (left: Data, right: Data) {
        let payloads = try await detectAllQrPayloads(in: imageData)
        let valid = payloads.filter { $0.count == 858 && $0.first == 0x00 }
        if valid.count < 2 {
            throw IneQrError.missingQrSide(expected: 2, found: valid.count)
        }

        guard let left = valid.first(where: { $0[1] == 0x00 }) else {
            throw IneQrError.invalidPayload(reason: "left QR (header[1] == 0) missing")
        }
        guard let right = valid.first(where: { $0[1] == 0x01 }) else {
            throw IneQrError.invalidPayload(reason: "right QR (header[1] == 1) missing")
        }
        return (left, right)
    }

    private static func detectAllQrPayloads(in imageData: Data) async throws -> [Data] {
        // Try Vision first (preferred — newer, faster).
        let visionPayloads = (try? await visionDetect(imageData)) ?? []
        if !visionPayloads.isEmpty { return visionPayloads }

        // Fall back to CIDetector for the iOS 15 case where Vision's descriptor
        // cast occasionally returns nil for INE QRs.
        return ciDetect(imageData)
    }

    private static func visionDetect(_ imageData: Data) async throws -> [Data] {
        try await withCheckedThrowingContinuation { cont in
            let handler = VNImageRequestHandler(data: imageData, options: [:])
            let request = VNDetectBarcodesRequest { req, err in
                if let err { cont.resume(throwing: err); return }
                let observations = (req.results as? [VNBarcodeObservation]) ?? []
                let payloads: [Data] = observations.compactMap { obs in
                    if let qr = obs.barcodeDescriptor as? CIQRCodeDescriptor {
                        return qr.errorCorrectedPayload
                    }
                    return nil
                }
                cont.resume(returning: payloads)
            }
            request.symbologies = [.qr]
            do { try handler.perform([request]) }
            catch { cont.resume(throwing: error) }
        }
    }

    private static func ciDetect(_ imageData: Data) -> [Data] {
        guard let image = CIImage(data: imageData) else { return [] }
        let opts: [String: Any] = [CIDetectorAccuracy: CIDetectorAccuracyHigh]
        guard let detector = CIDetector(ofType: CIDetectorTypeQRCode,
                                        context: nil, options: opts) else { return [] }
        let features = detector.features(in: image)
        return features.compactMap { feature in
            (feature as? CIQRCodeFeature)?.symbolDescriptor?.errorCorrectedPayload
        }
    }
}
