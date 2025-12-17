import Foundation
import Security
import Milieu

public enum CryptographicCATrustError: Error, LocalizedError {
    case trustEvaluationFailed(String)

    public var errorDescription: String? {
        switch self {
        case .trustEvaluationFailed(let msg):
            return "TLS trust evaluation failed: \(msg)"
        }
    }
}

public actor CryptographicCATrustState {
    private var lastError: CryptographicCATrustError?

    public init() {}

    public func set(_ error: CryptographicCATrustError?) {
        lastError = error
    }

    public func take() -> CryptographicCATrustError? {
        let e = lastError
        lastError = nil
        return e
    }
}

public final class CryptographicCASessionDelegate: NSObject, URLSessionDelegate {
    public enum PolicyMode: Sendable {
        case strictServerAuth   // enforce normal TLS server usage
        case basicX509          // ignore EKU, just validate chain against CA
    }

    private let caCertificate: SecCertificate
    private let allowedHost: String?
    private let anchorOnly: Bool
    private let trustState: CryptographicCATrustState
    private let policyMode: PolicyMode

    public init(
        caCertificate: SecCertificate,
        allowedHost: String? = nil,
        anchorOnly: Bool = true,
        trustState: CryptographicCATrustState,
        policyMode: PolicyMode = .strictServerAuth
    ) {
        self.caCertificate = caCertificate
        self.allowedHost = allowedHost
        self.anchorOnly = anchorOnly
        self.trustState = trustState
        self.policyMode = policyMode
    }

    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust
        else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        if let allowedHost {
            let host = challenge.protectionSpace.host
            guard host == allowedHost else {
                let err = CryptographicCATrustError.trustEvaluationFailed(
                    "Host mismatch. Expected \(allowedHost), got \(host)"
                )
                Task { await trustState.set(err) }
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
        }

        switch policyMode {
        case .strictServerAuth:
            // keep system's SSL policy (this enforces EKU serverAuth etc.)
            break

        case .basicX509:
            // behave more like OpenSSL/Node: validate chain against CA only
            let policy = SecPolicyCreateBasicX509()
            SecTrustSetPolicies(trust, policy)
        }

        // Pin our CA as anchor
        SecTrustSetAnchorCertificates(trust, [caCertificate] as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, anchorOnly)

        var cfError: CFError?
        let ok = SecTrustEvaluateWithError(trust, &cfError)

        if ok {
            Task { await trustState.set(nil) }
            let credential = URLCredential(trust: trust)
            completionHandler(.useCredential, credential)
        } else {
            let description: String
            if let cfError {
                description = CFErrorCopyDescription(cfError) as String
            } else {
                description = "Unknown trust error"
            }

            let err = CryptographicCATrustError.trustEvaluationFailed(description)
            Task { await trustState.set(err) }
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

public enum CryptographicCATrustedURLSession {
    public static func create(
        caCertificate: SecCertificate,
        allowedHost: String? = nil,
        anchorOnly: Bool = true,
        policyMode: CryptographicCASessionDelegate.PolicyMode = .strictServerAuth,
        configuration: URLSessionConfiguration = .ephemeral
    ) -> (URLSession, CryptographicCATrustState) {
        let state = CryptographicCATrustState()
        let delegate = CryptographicCASessionDelegate(
            caCertificate: caCertificate,
            allowedHost: allowedHost,
            anchorOnly: anchorOnly,
            trustState: state,
            policyMode: policyMode
        )
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
        return (session, state)
    }

    public static func create(
        caCertificatePathSymbol: String,
        allowedHost: String? = nil,
        anchorOnly: Bool = true,
        policyMode: CryptographicCASessionDelegate.PolicyMode = .strictServerAuth,
        configuration: URLSessionConfiguration = .ephemeral
    ) throws -> (URLSession, CryptographicCATrustState) {
        let caPath = try EnvironmentExtractor.value(.symbol(caCertificatePathSymbol))
        let caCert = try CryptographicTLSCertificateLoader.loadCertificate(at: caPath)
        return create(
            caCertificate: caCert,
            allowedHost: allowedHost,
            anchorOnly: anchorOnly,
            policyMode: policyMode,
            configuration: configuration
        )
    }

    /// Convenience: run a request and surface TLS trust errors instead of bare `.cancelled`.
    public static func data(
        for request: URLRequest,
        caCertificatePathSymbol: String,
        allowedHost: String? = nil,
        anchorOnly: Bool = true,
        policyMode: CryptographicCASessionDelegate.PolicyMode = .strictServerAuth,
        configuration: URLSessionConfiguration = .ephemeral
    ) async throws -> (Data, URLResponse) {
        let (session, state) = try create(
            caCertificatePathSymbol: caCertificatePathSymbol,
            allowedHost: allowedHost,
            anchorOnly: anchorOnly,
            policyMode: policyMode,
            configuration: configuration
        )

        do {
            return try await session.data(for: request)
        } catch let urlError as URLError where urlError.code == .cancelled {
            if let trustError = await state.take() {
                throw trustError
            }
            throw urlError
        }
    }
}
