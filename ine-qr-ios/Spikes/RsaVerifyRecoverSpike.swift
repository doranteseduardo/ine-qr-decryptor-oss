// ── Spike: can iOS Security.framework do RSA-8192 verify-recover? ──
//
// The pipeline's Stage B is mathematically `m = c^e mod n` against a public
// key (PKCS#1 type 01 padding strip on the result). Apple's SecKey API
// exposes only `SecKeyVerifySignature` (returns Bool), not OpenSSL's
// RSA_public_decrypt-style "give me the recovered message" call.
//
// Workaround: use SecKeyCreateEncryptedData with kSecKeyAlgorithmRSAEncryptionRaw
// against the public key, treating raw RSA encryption (m^e mod n) as the
// way to recover the signed message from a signature. This spike validates
// it works for our 8192-bit pipeline modulus on iOS 15-18.
//
// HOW TO RUN:
//   This spike needs a real encrypted QR capture, which this repo does not
//   ship (no real credential data is distributed here or in its history —
//   see the README Disclaimer). To run it locally:
//   1. Build the existing ine-qr-c reference: `(cd ine-qr-c && make)`
//   2. Capture your own credential's QR bytes (e.g. via `ine-qr-c`'s pure
//      path against a photo you own) into a gitignored local directory —
//      NOT into Tests/IneQrTests/Resources/, which only holds the public,
//      synthetic decode-only fixtures.
//   3. Point this spike at that local capture and run it on a real iOS sim
//      or device.
//   4. Use the no_so_pipeline source-of-truth captures the desktop tool
//      writes under output/ (gitignored) as the expected `recovered_b` value.
//
// If this spike returns `recovered_b` byte-exact for both qr_left/qr_right
// fixtures across iOS 15.5 and 17.4 simulators, swap crypto_backend_apple.c
// to use SecKey for RSA. Until then the vendored bignum is the safe path.

#if canImport(Security)
import Foundation
import Security

enum RsaVerifyRecoverSpike {

    /// Returns the recovered message (PKCS#1 type 01 padding included) or
    /// throws the underlying SecKey error. Caller strips padding manually.
    static func recover(modulus: Data, publicExponent: Data, signature: Data) throws -> Data {
        // Build a PKCS#1-format DER public key body: SEQUENCE { INTEGER n, INTEGER e }.
        let derBody = derSequence([derInteger(modulus), derInteger(publicExponent)])

        let attrs: [String: Any] = [
            kSecAttrKeyType   as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass  as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: modulus.count * 8,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(derBody as CFData, attrs as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }

        // Treat verify-recover as raw m^e mod n.
        guard let recovered = SecKeyCreateEncryptedData(
            key,
            .rsaEncryptionRaw,
            signature as CFData,
            &error
        ) else {
            throw error!.takeRetainedValue() as Error
        }
        return recovered as Data
    }

    // ── Minimal DER helpers (just enough for SEQUENCE{INTEGER,INTEGER}) ──

    private static func derLen(_ n: Int) -> Data {
        if n < 0x80 { return Data([UInt8(n)]) }
        var bytes: [UInt8] = []
        var v = n
        while v > 0 { bytes.insert(UInt8(v & 0xff), at: 0); v >>= 8 }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }

    private static func derInteger(_ raw: Data) -> Data {
        var body = raw.drop { $0 == 0 } // strip leading zeros
        if body.first.map({ $0 & 0x80 != 0 }) == true {
            body = Data([0]) + body // re-prefix to keep sign positive
        }
        if body.isEmpty { body = Data([0]) }
        return Data([0x02]) + derLen(body.count) + body
    }

    private static func derSequence(_ items: [Data]) -> Data {
        let body = items.reduce(Data()) { $0 + $1 }
        return Data([0x30]) + derLen(body.count) + body
    }
}
#endif
