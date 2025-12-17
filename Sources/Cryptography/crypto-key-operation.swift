import Foundation
import CryptoKit
import Security
import Milieu

public enum CryptographicKeyOperation {
    public enum ProbeError: Error, CustomStringConvertible {
        case usage(String)
        case invalidPacket(String)
        case keyLoadFailed(String)

        public var description: String {
            switch self {
            case .usage(let s):          return s
            case .invalidPacket(let s):  return s
            case .keyLoadFailed(let s):  return s
            }
        }
    }

    // -----------------------
    // Key loading / DER helpers
    // -----------------------
    public enum KeyFlavor {
        case spkiPublicPEM
        case pkcs1PublicPEM
        case pkcs8PrivatePEM
        case pkcs1PrivatePEM
        case encryptedPrivatePEM
        case derUnknown
        case pemUnknown
    }

    public static func detectFlavor(_ data: Data) -> KeyFlavor {
        if let s = String(data: data, encoding: .utf8) {
            if s.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") { return .encryptedPrivatePEM }
            if s.contains("-----BEGIN PRIVATE KEY-----")          { return .pkcs8PrivatePEM }
            if s.contains("-----BEGIN RSA PRIVATE KEY-----")      { return .pkcs1PrivatePEM }
            if s.contains("-----BEGIN PUBLIC KEY-----")           { return .spkiPublicPEM }
            if s.contains("-----BEGIN RSA PUBLIC KEY-----")       { return .pkcs1PublicPEM }
            if s.contains("-----BEGIN")                           { return .pemUnknown }
            return .derUnknown
        }
        return .derUnknown
    }

    public static func pemBody(_ pem: String, begin: String, end: String) -> Data? {
        guard pem.contains(begin), pem.contains(end) else { return nil }
        let stripped = pem
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.hasPrefix("-----BEGIN") && !$0.hasPrefix("-----END") && !$0.isEmpty }
            .joined()
        return Data(base64Encoded: stripped)
    }

    public static func derLen(_ n: Int) -> [UInt8] {
        if n < 0x80 { return [UInt8(n)] }
        if n <= 0xFF { return [0x81, UInt8(n)] }
        if n <= 0xFFFF { return [0x82, UInt8(n >> 8), UInt8(n & 0xFF)] }
        let b3 = UInt8((n >> 16) & 0xFF), b2 = UInt8((n >> 8) & 0xFF), b1 = UInt8(n & 0xFF)
        return [0x83, b3, b2, b1]
    }

    public static func wrapRSAPrivateKeyToPKCS8(_ pkcs1: Data) -> Data {
        let rsaOID: [UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
        let nullBytes: [UInt8] = [0x05, 0x00]

        let privateKeyOctet: [UInt8] = [0x04] + derLen(pkcs1.count) + pkcs1
        let algSeqContent: [UInt8] = rsaOID + nullBytes
        let algSeq: [UInt8] = [0x30] + derLen(algSeqContent.count) + algSeqContent
        let version: [UInt8] = [0x02, 0x01, 0x00]

        let totalLen = version.count + algSeq.count + privateKeyOctet.count
        let pki: [UInt8] = [0x30] + derLen(totalLen) + version + algSeq + privateKeyOctet
        return Data(pki)
    }

    public static func wrapRSAPublicKeyToSPKI(_ pkcs1: Data) -> Data {
        let rsaOID: [UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
        let nullBytes: [UInt8] = [0x05, 0x00]
        let bitStringContent: [UInt8] = [0x00] + pkcs1
        let bitString: [UInt8] = [0x03] + derLen(bitStringContent.count) + bitStringContent
        let algSeqContent: [UInt8] = rsaOID + nullBytes
        let algSeq: [UInt8] = [0x30] + derLen(algSeqContent.count) + algSeqContent
        let spkiContent: [UInt8] = algSeq + bitString
        let spki: [UInt8] = [0x30] + derLen(spkiContent.count) + spkiContent
        return Data(spki)
    }

    public static func makeSecKeyFromDER(_ der: Data, isPublic: Bool, sizeBits: Int? = nil) throws -> SecKey {
        var attrs: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: isPublic ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate,
            kSecAttrIsPermanent: false
        ]
        if let bits = sizeBits {
            attrs[kSecAttrKeySizeInBits] = NSNumber(value: bits)
        }

        var err: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(der as CFData, attrs as CFDictionary, &err) else {
            if let e = err?.takeRetainedValue() {
                throw ProbeError.keyLoadFailed("SecKeyCreateWithData failed: \(e)")
            }
            throw ProbeError.keyLoadFailed("SecKeyCreateWithData failed with unknown error")
        }
        return key
    }

    // Minimal DER reader for definite lengths; returns (tag, length, valueStartIndex, nextIndex)
    public static func derReadTLV(_ bytes: [UInt8], _ i0: Int) -> (UInt8, Int, Int, Int)? {
        var i = i0
        guard i < bytes.count else { return nil }
        let tag = bytes[i]; i += 1
        guard i < bytes.count else { return nil }
        var length = 0
        if bytes[i] < 0x80 {
            length = Int(bytes[i]); i += 1
        } else {
            let lenLen = Int(bytes[i] & 0x7F); i += 1
            guard i + lenLen <= bytes.count else { return nil }
            for _ in 0..<lenLen { length = (length << 8) | Int(bytes[i]); i += 1 }
        }
        let start = i
        let next = i + length
        guard next <= bytes.count else { return nil }
        return (tag, length, start, next)
    }

    // RSAPrivateKey ::= SEQUENCE { version INTEGER, modulus INTEGER, ... } → modulus bit length
    public static func rsaPrivateKeyModulusBits(_ pkcs1: Data) -> Int? {
        let b = [UInt8](pkcs1)
        guard let (t0, _, s0, n0) = derReadTLV(b, 0), t0 == 0x30 else { return nil }
        guard let (t1, _, _, n1) = derReadTLV(b, s0), t1 == 0x02 else { return nil }
        guard let (t2, _, s2, _) = derReadTLV(b, n1), t2 == 0x02 else { return nil }
        var j = s2
        while j < b.count && b[j] == 0x00 { j += 1 }
        let modulusByteCount = max(0, (n0 - j))
        guard modulusByteCount > 0 else { return nil }
        let firstByte = b[j]
        let leadingZeros = firstByte.leadingZeroBitCount
        return modulusByteCount * 8 - leadingZeros
    }

    // Extract inner RSAPrivateKey from PKCS#8 PrivateKeyInfo (OCTET STRING)
    public static func unwrapPKCS8ToPKCS1(_ pkcs8: Data) -> Data? {
        let b = [UInt8](pkcs8)
        guard let (t0, _, s0, _) = derReadTLV(b, 0), t0 == 0x30 else { return nil }
        guard let (t1, _, _, n1) = derReadTLV(b, s0), t1 == 0x02 else { return nil }
        guard let (t2, _, _, n2) = derReadTLV(b, n1), t2 == 0x30 else { return nil }
        guard let (t3, L3, s3, _) = derReadTLV(b, n2), t3 == 0x04 else { return nil }
        let inner = Data(b[s3..<(s3+L3)])
        if let (ti, _, _, _) = derReadTLV([UInt8](inner), 0), ti == 0x30 { return inner }
        return nil
    }

    public static func loadPublicKey(at path: String) throws -> SecKey {
        let raw = try Data(contentsOf: URL(fileURLWithPath: path))
        switch detectFlavor(raw) {
        case .spkiPublicPEM:
            let s = String(decoding: raw, as: UTF8.self)
            guard let spki = pemBody(s, begin: "-----BEGIN PUBLIC KEY-----", end: "-----END PUBLIC KEY-----")
            else { throw ProbeError.keyLoadFailed("Failed to parse SPKI public PEM.") }
            print("[crypter] detected public key: SPKI (PEM)")
            return try makeSecKeyFromDER(spki, isPublic: true)

        case .pkcs1PublicPEM:
            let s = String(decoding: raw, as: UTF8.self)
            guard let pkcs1 = pemBody(s, begin: "-----BEGIN RSA PUBLIC KEY-----", end: "-----END RSA PUBLIC KEY-----")
            else { throw ProbeError.keyLoadFailed("Failed to parse PKCS#1 public PEM.") }
            print("[crypter] detected public key: PKCS#1 (PEM) → wrapping to SPKI")
            let spki = wrapRSAPublicKeyToSPKI(pkcs1)
            return try makeSecKeyFromDER(spki, isPublic: true)

        case .pemUnknown:
            throw ProbeError.keyLoadFailed("Unknown PUBLIC PEM header; expected BEGIN PUBLIC KEY or BEGIN RSA PUBLIC KEY.")

        case .derUnknown:
            print("[crypter] detected public key: DER (assuming SPKI)")
            return try makeSecKeyFromDER(raw, isPublic: true)

        default:
            throw ProbeError.keyLoadFailed("Not a public key file.")
        }
    }

    // Keychain import fallback (unchanged logic)
    public static func importPrivateKeyWithSecItemImport(_ data: Data) throws -> SecKey {
        var items: CFArray?
        let status = SecItemImport(
            data as CFData,
            nil, nil, nil,
            SecItemImportExportFlags(),
            nil,
            nil,
            &items
        )
        guard status == errSecSuccess, let arr = items as? [NSDictionary] else {
            throw ProbeError.keyLoadFailed("SecItemImport failed (\(status))")
        }
        for dict in arr {
            for (_, v) in dict {
                let cf = v as CFTypeRef
                if CFGetTypeID(cf) == SecKeyGetTypeID() { return (cf as! SecKey) }
            }
        }
        throw ProbeError.keyLoadFailed("SecItemImport succeeded but no SecKey present")
    }

    public static func loadPrivateKey(at path: String) throws -> SecKey {
        let raw = try Data(contentsOf: URL(fileURLWithPath: path))
        switch detectFlavor(raw) {
        case .encryptedPrivatePEM:
            throw ProbeError.keyLoadFailed("Encrypted private key detected (BEGIN ENCRYPTED PRIVATE KEY). Convert to unencrypted PKCS#8 first.")

        case .pkcs8PrivatePEM:
            let s = String(decoding: raw, as: UTF8.self)
            guard let pkcs8 = pemBody(s, begin: "-----BEGIN PRIVATE KEY-----", end: "-----END PRIVATE KEY-----")
            else { throw ProbeError.keyLoadFailed("Failed to parse PKCS#8 private PEM.") }
            print("[crypter] detected private key: PKCS#8 (PEM)")
            if let pkcs1 = unwrapPKCS8ToPKCS1(pkcs8) {
                let bits = rsaPrivateKeyModulusBits(pkcs1)
                return try makeSecKeyFromDER(pkcs1, isPublic: false, sizeBits: bits)
            }
            return try makeSecKeyFromDER(pkcs8, isPublic: false)

        case .pkcs1PrivatePEM:
            let s = String(decoding: raw, as: UTF8.self)
            guard let pkcs1 = pemBody(s, begin: "-----BEGIN RSA PRIVATE KEY-----", end: "-----END RSA PRIVATE KEY-----")
            else { throw ProbeError.keyLoadFailed("Failed to parse PKCS#1 private PEM.") }
            print("[crypter] detected private key: PKCS#1 (PEM) → wrapping to PKCS#8")
            let wrapped = wrapRSAPrivateKeyToPKCS8(pkcs1)
            if let k = try? makeSecKeyFromDER(wrapped, isPublic: false) { return k }
            return try importPrivateKeyWithSecItemImport(wrapped)

        case .derUnknown:
            print("[crypter] detected private key: DER (PKCS#8 or PKCS#1)")
            if let pkcs1 = unwrapPKCS8ToPKCS1(raw) {
                let bits = rsaPrivateKeyModulusBits(pkcs1)
                return try makeSecKeyFromDER(pkcs1, isPublic: false, sizeBits: bits)
            }
            if let bits = rsaPrivateKeyModulusBits(raw) {
                return try makeSecKeyFromDER(raw, isPublic: false, sizeBits: bits)
            }
            return try makeSecKeyFromDER(raw, isPublic: false)

        default:
            throw ProbeError.keyLoadFailed("Not a private key file.")
        }
    }

    // -----------------------
    // Crypto primitives
    // -----------------------
    public static func rsaEncryptOAEP_SHA256(publicKey: SecKey, data: Data) throws -> Data {
        var err: Unmanaged<CFError>?
        guard let out = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionOAEPSHA256, data as CFData, &err) else {
            if let e = err?.takeRetainedValue() {
                throw ProbeError.keyLoadFailed("RSA-OAEP encrypt failed: \(e)")
            }
            throw ProbeError.keyLoadFailed("RSA-OAEP encrypt failed (unknown)")
        }
        return out as Data
    }

    public static func rsaDecryptOAEP_SHA256(privateKey: SecKey, data: Data) throws -> Data {
        var err: Unmanaged<CFError>?
        guard let out = SecKeyCreateDecryptedData(privateKey, .rsaEncryptionOAEPSHA256, data as CFData, &err) else {
            if let e = err?.takeRetainedValue() {
                throw ProbeError.keyLoadFailed("RSA-OAEP decrypt failed: \(e)")
            }
            throw ProbeError.keyLoadFailed("RSA-OAEP decrypt failed (unknown)")
        }
        return out as Data
    }

    public static func randomBytes(_ count: Int) throws -> Data {
        var data = Data(count: count)
        let rc = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        guard rc == errSecSuccess else { throw ProbeError.invalidPacket("SecRandomCopyBytes failed") }
        return data
    }

    // -----------------------
    // base64 encoding
    // -----------------------

    public static func b64urlEncode(_ data: Data) -> String {
        let s = data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return s
    }

    public static func b64urlDecode(_ s: String) -> Data? {
        var t = s.replacingOccurrences(of: "-", with: "+")
                 .replacingOccurrences(of: "_", with: "/")
        let pad = (4 - (t.count % 4)) % 4
        if pad > 0 { t.append(String(repeating: "=", count: pad)) }
        return Data(base64Encoded: t)
    }
}

extension CryptographicKeyOperation {
    public static func loadKey(_ type: CryptographicKeyType, at path: String) throws -> SecKey {
        switch type {
        case .public:
            return try loadPublicKey(at: path)
        case .private:
            return try loadPrivateKey(at: path)
        }
    }

    public static func load(_ type: CryptographicKeyType, at path: String) throws -> SecKey {
        return try loadKey(type, at: path)
    }

    /// convenience overload that uses a plain app name 'MY_APP'
    /// to resolve into 'MY_APP_PUBLIC_KEY_PATH' automatically
    /// then resolve its path from EnvironmentExtractor
    /// then load it
    public static func loadKey(
        name: String,
        _ type: CryptographicKeyType,
        replacer: EnvironmentReplacer = .init(
            replacements: [
                .variable(key: "$HOME", replacement: .home)
            ]
        )
    ) throws -> SecKey {
        switch type {
        case .public:
            let path = try EnvironmentExtractor.value(
                name: name,
                suffix: .public_key_path,
                replacer: replacer
            )
            return try loadPublicKey(at: path)
        case .private:
            let path = try EnvironmentExtractor.value(
                name: name,
                suffix: .private_key_path,
                replacer: replacer
            )
            return try loadPrivateKey(at: path)
        }
    }

    public static func load(
        name: String,
        _ type: CryptographicKeyType,
        replacer: EnvironmentReplacer = .init(
            replacements: [
                .variable(key: "$HOME", replacement: .home)
            ]
        )
    ) throws -> SecKey {
        return try loadKey(
            name: name,
            type,
            replacer: replacer
        )
    }
}

extension CryptographicKeyOperation {
    internal static func keys(
        prefix: String,
        replacer: EnvironmentReplacer = .init(
            replacements: [
                .variable(key: "$HOME", replacement: .home)
            ]
        )
    ) throws -> CryptographicKeyPair {
        let pubPath = try EnvironmentExtractor.value(
            name: prefix,
            suffix: .public_key_path,
            replacer: replacer
        )
        let privPath = try EnvironmentExtractor.value(
            name: prefix,
            suffix: .private_key_path,
            replacer: replacer
        )

        let publicKey  = try CryptographicKeyOperation.loadPublicKey(at: pubPath)
        let privateKey = try CryptographicKeyOperation.loadPrivateKey(at: privPath)

        return CryptographicKeyPair(publicKey: publicKey, privateKey: privateKey)
    }
}
