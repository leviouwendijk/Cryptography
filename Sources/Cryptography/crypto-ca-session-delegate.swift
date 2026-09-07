import Errors
import Foundation
import Security
import Milieu

public enum CryptographicCATrustError:
    Error,
    LocalizedError,
    Sendable,
    Codable,
    Hashable
{
    case trustEvaluationFailed(String)

    public var errorDescription: String? {
        switch self {
        case .trustEvaluationFailed(let msg):
            return "TLS trust evaluation failed: \(msg)"
        }
    }
}

public struct CryptographicCATrustSnapshot:
    Sendable,
    Codable,
    Hashable
{
    public let challengeCount: Int
    public let evaluationCount: Int
    public let lastHost: String?
    public let lastAuthenticationMethod: String?
    public let lastEvaluationSucceeded: Bool?
    public let lastError: CryptographicCATrustError?

    public init(
        challengeCount: Int,
        evaluationCount: Int,
        lastHost: String?,
        lastAuthenticationMethod: String?,
        lastEvaluationSucceeded: Bool?,
        lastError: CryptographicCATrustError?
    ) {
        self.challengeCount = challengeCount
        self.evaluationCount = evaluationCount
        self.lastHost = lastHost
        self.lastAuthenticationMethod = lastAuthenticationMethod
        self.lastEvaluationSucceeded = lastEvaluationSucceeded
        self.lastError = lastError
    }
}

public final class CryptographicCATrustState: @unchecked Sendable {
    private let lock = NSLock()
    private var challengeCount = 0
    private var evaluationCount = 0
    private var lastHost: String?
    private var lastAuthenticationMethod: String?
    private var lastEvaluationSucceeded: Bool?
    private var lastError: CryptographicCATrustError?

    public init() {}

    public func recordChallenge(
        host: String,
        authenticationMethod: String
    ) {
        lock.lock()
        defer { lock.unlock() }

        challengeCount += 1
        lastHost = host
        lastAuthenticationMethod = authenticationMethod
    }

    public func recordEvaluation(
        succeeded: Bool,
        error: CryptographicCATrustError?
    ) {
        lock.lock()
        defer { lock.unlock() }

        evaluationCount += 1
        lastEvaluationSucceeded = succeeded
        lastError = error
    }

    public func set(_ error: CryptographicCATrustError?) {
        lock.lock()
        defer { lock.unlock() }

        lastError = error
    }

    public func snapshot() -> CryptographicCATrustSnapshot {
        lock.lock()
        defer { lock.unlock() }

        return CryptographicCATrustSnapshot(
            challengeCount: challengeCount,
            evaluationCount: evaluationCount,
            lastHost: lastHost,
            lastAuthenticationMethod: lastAuthenticationMethod,
            lastEvaluationSucceeded: lastEvaluationSucceeded,
            lastError: lastError
        )
    }

    public func take() -> CryptographicCATrustError? {
        lock.lock()
        defer { lock.unlock() }

        let error = lastError
        lastError = nil
        return error
    }
}

public struct CryptographicCATrustedURLSessionFailure:
    Error,
    PresentableError,
    ErrorIdentityProviding,
    ErrorDiagnosticFieldsProviding,
    ErrorRelationsProviding
{
    public let underlying: any Error
    public let trust: CryptographicCATrustSnapshot
    public let caCertificatePathSymbol: String
    public let allowedHost: String?
    public let anchorOnly: Bool
    public let policyMode: CryptographicCASessionDelegate.PolicyMode

    public init(
        underlying: any Error,
        trust: CryptographicCATrustSnapshot,
        caCertificatePathSymbol: String,
        allowedHost: String?,
        anchorOnly: Bool,
        policyMode: CryptographicCASessionDelegate.PolicyMode
    ) {
        self.underlying = underlying
        self.trust = trust
        self.caCertificatePathSymbol = caCertificatePathSymbol
        self.allowedHost = allowedHost
        self.anchorOnly = anchorOnly
        self.policyMode = policyMode
    }

    public var errorIdentity: ErrorIdentity {
        .init(
            namespace: "cryptography.privateca",
            code: "requestfailed"
        )
    }

    public var errorPresentation: ErrorPresentation {
        .init(
            title: "Private-CA request failed",
            message:
                trust.lastError?.localizedDescription
                ?? underlying.localizedDescription,
            reason:
                trust.lastError == nil
                ? "The request failed without a recorded private-CA trust rejection."
                : "The private-CA trust delegate recorded a trust rejection.",
            recoverySuggestion:
                "Inspect the trust diagnostics and underlying error chain."
        )
    }

    public var errorDiagnosticFields: [ErrorDiagnosticField] {
        [
            .init(
                key: "tls.cacertificatepathsymbol",
                value: caCertificatePathSymbol
            ),
            .init(
                key: "tls.allowedhost",
                value: allowedHost ?? "<none>"
            ),
            .init(
                key: "tls.anchoronly",
                value: String(anchorOnly)
            ),
            .init(
                key: "tls.policymode",
                value: policyModeName
            ),
            .init(
                key: "tls.challengereceived",
                value: String(trust.challengeCount > 0)
            ),
            .init(
                key: "tls.challengecount",
                value: String(trust.challengeCount)
            ),
            .init(
                key: "tls.lasthost",
                value: trust.lastHost ?? "<none>"
            ),
            .init(
                key: "tls.lastauthenticationmethod",
                value: trust.lastAuthenticationMethod ?? "<none>"
            ),
            .init(
                key: "tls.evaluationattempted",
                value: String(trust.evaluationCount > 0)
            ),
            .init(
                key: "tls.evaluationcount",
                value: String(trust.evaluationCount)
            ),
            .init(
                key: "tls.lastevaluationsucceeded",
                value:
                    trust.lastEvaluationSucceeded.map(String.init)
                    ?? "<not-evaluated>"
            ),
            .init(
                key: "tls.trusterrorpresent",
                value: String(trust.lastError != nil)
            ),
        ]
    }

    public var errorRelations: [ErrorRelation] {
        var relations: [ErrorRelation] = [
            .underlying(
                underlying
            ),
        ]

        if let trustError = trust.lastError {
            relations.append(
                .related(
                    trustError
                )
            )
        }

        return relations
    }

    private var policyModeName: String {
        switch policyMode {
        case .strictServerAuth:
            return "strictServerAuth"

        case .basicX509:
            return "basicX509"
        }
    }
}

public final class CryptographicCASessionDelegate: NSObject, URLSessionTaskDelegate {
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
        handleAuthenticationChallenge(
            challenge,
            completionHandler: completionHandler
        )
    }

    public func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        handleAuthenticationChallenge(
            challenge,
            completionHandler: completionHandler
        )
    }

    private func handleAuthenticationChallenge(
        _ challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        trustState.recordChallenge(
            host: challenge.protectionSpace.host,
            authenticationMethod:
                challenge.protectionSpace.authenticationMethod
        )

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
                trustState.set(err)
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
        }

        switch policyMode {
        case .strictServerAuth:
            // Keep the system SSL policy, including server-auth usage checks.
            break

        case .basicX509:
            // Validate the chain against the configured CA without EKU policy.
            let policy = SecPolicyCreateBasicX509()
            SecTrustSetPolicies(trust, policy)
        }

        SecTrustSetAnchorCertificates(
            trust,
            [caCertificate] as CFArray
        )
        SecTrustSetAnchorCertificatesOnly(
            trust,
            anchorOnly
        )

        var cfError: CFError?
        let ok = SecTrustEvaluateWithError(
            trust,
            &cfError
        )

        if ok {
            trustState.recordEvaluation(
                succeeded: true,
                error: nil
            )
            completionHandler(
                .useCredential,
                URLCredential(trust: trust)
            )
            return
        }

        let description: String
        if let cfError {
            description =
                CFErrorCopyDescription(cfError) as String
        } else {
            description = "Unknown trust error"
        }

        let err =
            CryptographicCATrustError
                .trustEvaluationFailed(description)

        trustState.recordEvaluation(
            succeeded: false,
            error: err
        )
        completionHandler(
            .cancelAuthenticationChallenge,
            nil
        )
    }
}

public enum CryptographicCATrustedURLSession {
    private static func requestFailure(
        _ error: any Error,
        state: CryptographicCATrustState,
        caCertificatePathSymbol: String,
        allowedHost: String?,
        anchorOnly: Bool,
        policyMode: CryptographicCASessionDelegate.PolicyMode
    ) -> CryptographicCATrustedURLSessionFailure {
        CryptographicCATrustedURLSessionFailure(
            underlying: error,
            trust: state.snapshot(),
            caCertificatePathSymbol: caCertificatePathSymbol,
            allowedHost: allowedHost,
            anchorOnly: anchorOnly,
            policyMode: policyMode
        )
    }

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

    /// Run work with a CA-trusted URLSession and its exact task delegate.
    ///
    /// Use this overload for async Foundation APIs such as
    /// `bytes(for:delegate:)` which accept a task-specific delegate.
    /// The synchronized trust state remains authoritative for diagnostic state.
    public static func withSession<Result>(
        caCertificatePathSymbol: String,
        allowedHost: String? = nil,
        anchorOnly: Bool = true,
        policyMode: CryptographicCASessionDelegate.PolicyMode = .strictServerAuth,
        configuration: URLSessionConfiguration = .ephemeral,
        operation: (
            URLSession,
            CryptographicCASessionDelegate
        ) async throws -> Result
    ) async throws -> Result {
        let caPath = try EnvironmentExtractor.value(
            .symbol(caCertificatePathSymbol)
        )
        let caCertificate =
            try CryptographicTLSCertificateLoader
                .loadCertificate(at: caPath)

        let state = CryptographicCATrustState()
        let delegate = CryptographicCASessionDelegate(
            caCertificate: caCertificate,
            allowedHost: allowedHost,
            anchorOnly: anchorOnly,
            trustState: state,
            policyMode: policyMode
        )
        let session = URLSession(
            configuration: configuration,
            delegate: delegate,
            delegateQueue: nil
        )

        defer {
            session.finishTasksAndInvalidate()
        }

        do {
            return try await operation(
                session,
                delegate
            )
        } catch {
            throw requestFailure(
                error,
                state: state,
                caCertificatePathSymbol:
                    caCertificatePathSymbol,
                allowedHost: allowedHost,
                anchorOnly: anchorOnly,
                policyMode: policyMode
            )
        }
    }

    /// Run work with a CA-trusted URLSession while keeping creation,
    /// trust-error propagation, and session invalidation inside Cryptography.
    ///
    /// The operation may remain suspended while consuming a streaming response;
    /// the session is invalidated only after the operation completes or throws.
    public static func withSession<Result>(
        caCertificatePathSymbol: String,
        allowedHost: String? = nil,
        anchorOnly: Bool = true,
        policyMode: CryptographicCASessionDelegate.PolicyMode = .strictServerAuth,
        configuration: URLSessionConfiguration = .ephemeral,
        operation: (URLSession) async throws -> Result
    ) async throws -> Result {
        let (session, state) = try create(
            caCertificatePathSymbol: caCertificatePathSymbol,
            allowedHost: allowedHost,
            anchorOnly: anchorOnly,
            policyMode: policyMode,
            configuration: configuration
        )

        defer {
            session.finishTasksAndInvalidate()
        }

        do {
            return try await operation(session)
        } catch {
            throw requestFailure(
                error,
                state: state,
                caCertificatePathSymbol:
                    caCertificatePathSymbol,
                allowedHost: allowedHost,
                anchorOnly: anchorOnly,
                policyMode: policyMode
            )
        }
    }

    /// Convenience: run a request and preserve private-CA trust diagnostics alongside the underlying transport failure.
    public static func data(
        for request: URLRequest,
        caCertificatePathSymbol: String,
        allowedHost: String? = nil,
        anchorOnly: Bool = true,
        policyMode: CryptographicCASessionDelegate.PolicyMode = .strictServerAuth,
        configuration: URLSessionConfiguration = .ephemeral
    ) async throws -> (Data, URLResponse) {
        try await withSession(
            caCertificatePathSymbol: caCertificatePathSymbol,
            allowedHost: allowedHost,
            anchorOnly: anchorOnly,
            policyMode: policyMode,
            configuration: configuration
        ) { session in
            try await session.data(for: request)
        }
    }
}
