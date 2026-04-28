import CryptoKit
import Foundation

public enum CryptographicHMAC {
    public static func sha256(
        key: Data,
        data: Data
    ) -> Data {
        let key = SymmetricKey(
            data: key
        )

        let mac = HMAC<SHA256>.authenticationCode(
            for: data,
            using: key
        )

        return Data(
            mac
        )
    }

    public static func sha256Hex(
        key: Data,
        data: Data
    ) -> String {
        HexEncoding.lower.encode(
            sha256(
                key: key,
                data: data
            )
        )
    }
}
