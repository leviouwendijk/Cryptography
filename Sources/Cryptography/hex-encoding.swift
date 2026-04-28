import Foundation

public struct HexEncoding: Sendable, Hashable {
    public static let lower = Self(
        alphabet: "0123456789abcdef"
    )

    public static let upper = Self(
        alphabet: "0123456789ABCDEF"
    )

    public var alphabet: [UInt8]

    public init(
        alphabet: String
    ) {
        self.alphabet = Array(
            alphabet.utf8
        )
    }

    public func encode(
        _ data: Data
    ) -> String {
        var result = String()
        result.reserveCapacity(
            data.count * 2
        )

        for byte in data {
            result.append(
                Character(
                    UnicodeScalar(
                        alphabet[Int(byte >> 4)]
                    )
                )
            )
            result.append(
                Character(
                    UnicodeScalar(
                        alphabet[Int(byte & 0x0F)]
                    )
                )
            )
        }

        return result
    }
}
