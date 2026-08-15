import XCTest
@testable import IneQr

/// Parity check for the output-decode stage using SYNTHETIC data.
///
/// Validates the Swift/C marshalling + the CHAR_TABLE bit-unpacking + the
/// WebP passthrough of `decode_to_buffers()`, driven through the test-only
/// `IneQr.decodeDecrypted` entry point. The input is a synthetic, PII-free
/// `synthetic_decoded.bin` (an already-"decrypted" buffer with obviously-fake
/// fields — CURP `XEXX010101HNEXXXA4`, name `JUAN PEREZ EXAMPLE` — and a
/// placeholder photo); the expected `expected.json` / `expected.webp` were
/// produced by running the real C decoder over that same buffer
/// (see `scripts/gen_synthetic_fixture.py`).
///
/// It deliberately does NOT test the AES/RSA crypto layers. A genuine
/// encrypted QR payload cannot be fabricated (the pipeline's RSA layers use
/// recovered PUBLIC keys; INE holds the private key), and no real credential
/// data ships in this repository. Full crypto-layer regression against a real
/// credential remains a manual, non-public step for the maintainer.
final class OutputDecodeParityTests: XCTestCase {

    private func resource(_ name: String) throws -> Data {
        let url = Bundle.module.url(forResource: name, withExtension: nil)
        try XCTUnwrap(url, "missing resource: \(name)")
        return try Data(contentsOf: url!)
    }

    func test_decodeDecrypted_matches_synthetic_reference() throws {
        let decodedBin = try resource("synthetic_decoded.bin")
        let expectedJson = String(decoding: try resource("expected.json"), as: UTF8.self)
        let expectedWebp = try resource("expected.webp")

        let result = try IneQr.decodeDecrypted(decodedBin)

        XCTAssertEqual(result.json, expectedJson,
            "JSON must match the synthetic reference byte-for-byte")
        XCTAssertEqual(result.webp, expectedWebp,
            "WebP must match the synthetic reference byte-for-byte")
    }
}
