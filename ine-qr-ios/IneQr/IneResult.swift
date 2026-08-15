import Foundation

/// Decoded INE credential.
///
/// - `json`: 18 biographical fields as a UTF-8 JSON string. Always populated.
/// - `webp`: photo as raw WebP bytes (96×129 px). Empty if no photo present.
public struct IneResult: Equatable, Sendable {
    public let json: String
    public let webp: Data

    public init(json: String, webp: Data) {
        self.json = json
        self.webp = webp
    }
}
