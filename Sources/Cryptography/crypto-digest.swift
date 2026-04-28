import CryptoKit
import Foundation

public enum CryptographicDigest {
    public static func sha256(
        _ data: Data
    ) -> Data {
        Data(
            SHA256.hash(
                data: data
            )
        )
    }

    public static func sha256Hex(
        _ data: Data
    ) -> String {
        HexEncoding.lower.encode(
            sha256(
                data
            )
        )
    }
}
