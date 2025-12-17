import Foundation

public final class CryptographicKeyPair: @unchecked Sendable {
    public let publicKey: SecKey
    public let privateKey: SecKey

    public init(publicKey: SecKey, privateKey: SecKey) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }
}
