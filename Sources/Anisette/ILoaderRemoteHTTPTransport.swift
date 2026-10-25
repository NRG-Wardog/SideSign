// Bounded HTTP collection for the existing Mac RemoteV3 provider only.
// Request payloads, endpoints, auth policy, WebSocket flow and identity storage stay unchanged.
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Owns every HTTP request so client invalidation also reaches an in-flight body.
final class ILoaderRemoteHTTPTransport: @unchecked Sendable {
    private let lock = NSLock()
    private var invalidated = false
    private var tasks: [UUID: ILoaderRemoteHTTPTask] = [:]
    private let startTask: @Sendable (URLSessionDataTask) -> Void
    private let didRegister: @Sendable (ILoaderRemoteHTTPTask) -> Void

    // Internal synthetic/parked-task seams only, never selectable by an app setting.
    init(startTask: @escaping @Sendable (URLSessionDataTask) -> Void = { $0.resume() },
         didRegister: @escaping @Sendable (ILoaderRemoteHTTPTask) -> Void = { _ in }) {
        self.startTask = startTask
        self.didRegister = didRegister
    }

    func data(for request: URLRequest, maximumBytes: Int = 1_048_576) async throws -> Data {
        try Task.checkCancellation()
        let id = UUID()
        let task = ILoaderRemoteHTTPTask(request: request, maximumBytes: maximumBytes, startTask: startTask)
        try lock.withLock {
            guard !invalidated else { throw CancellationError() }
            tasks[id] = task
        }
        defer { _ = lock.withLock { tasks.removeValue(forKey: id) } }
        didRegister(task)
        return try await task.run()
    }

    func invalidate() {
        let pending = lock.withLock {
            invalidated = true
            let pending = Array(tasks.values)
            tasks.removeAll()
            return pending
        }
        for task in pending { task.cancel() }
    }

    deinit { invalidate() }
}

/// Rejects oversized advertised and streamed bodies before their bytes are appended.
/// A separate session per request makes cancellation ownership explicit. No shared
/// credential, cookie or cache store is consulted. TLS uses normal platform trust.
final class ILoaderRemoteHTTPTask: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let request: URLRequest
    private let maximumBytes: Int
    private let startTask: @Sendable (URLSessionDataTask) -> Void
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, Error>?
    private var session: URLSession?
    private var response: HTTPURLResponse?
    private var body = Data()
    private var completed = false

    // Synthetic tests park actual tasks without resuming them. Production always resumes.
    init(request: URLRequest, maximumBytes: Int,
         startTask: @escaping @Sendable (URLSessionDataTask) -> Void = { $0.resume() }) {
        var bounded = request
        bounded.timeoutInterval = 30
        bounded.cachePolicy = .reloadIgnoringLocalCacheData
        bounded.httpShouldHandleCookies = false
        self.request = bounded
        self.maximumBytes = maximumBytes
        self.startTask = startTask
    }

    static func configuration() -> URLSessionConfiguration {
        let config = URLSessionConfiguration.ephemeral
        config.urlCache = nil
        config.urlCredentialStorage = nil
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60
        return config
    }

    func run() async throws -> Data {
        try Task.checkCancellation()
        guard maximumBytes >= 0 else { throw ILoaderRemoteError.invalidResponse }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                lock.lock()
                guard !completed else {
                    lock.unlock()
                    continuation.resume(throwing: CancellationError())
                    return
                }
                self.continuation = continuation
                let session = URLSession(configuration: Self.configuration(), delegate: self, delegateQueue: nil)
                self.session = session
                let task = session.dataTask(with: request)
                lock.unlock()
                startTask(task)
            }
        } onCancel: { self.cancel() }
    }

    func cancel() { finish(.failure(CancellationError())) }

    private func finish(_ result: Result<Data, Error>) {
        lock.lock()
        guard !completed else { lock.unlock(); return }
        completed = true
        let continuation = self.continuation
        let session = self.session
        self.continuation = nil
        self.session = nil
        self.response = nil
        self.body = Data()
        lock.unlock()
        session?.invalidateAndCancel()
        continuation?.resume(with: result)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                    completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil)
        // Preserve the previous provider's finite HTTP-status error category.
        finish(.failure(ILoaderRemoteError.httpStatus(response.statusCode)))
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        #if canImport(Security)
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        #endif
        completionHandler(.cancelAuthenticationChallenge, nil)
        finish(.failure(URLError(.userAuthenticationRequired)))
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping @Sendable (URLSession.ResponseDisposition) -> Void) {
        guard let http = response as? HTTPURLResponse else {
            completionHandler(.cancel)
            finish(.failure(ILoaderRemoteError.httpStatus(-1)))
            return
        }
        guard (200..<300).contains(http.statusCode) else {
            completionHandler(.cancel)
            finish(.failure(ILoaderRemoteError.httpStatus(http.statusCode)))
            return
        }
        guard http.url == request.url, http.expectedContentLength <= Int64(maximumBytes) else {
            completionHandler(.cancel)
            finish(.failure(ILoaderRemoteError.invalidResponse))
            return
        }
        let accepted = lock.withLock {
            guard !completed else { return false }
            self.response = http
            return true
        }
        completionHandler(accepted ? .allow : .cancel)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        let overflow = lock.withLock {
            guard !completed else { return false }
            guard data.count <= maximumBytes - body.count else { return true }
            body.append(data)
            return false
        }
        if overflow { finish(.failure(ILoaderRemoteError.invalidResponse)) }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error { finish(.failure(error)); return }
        let data = lock.withLock { response == nil ? nil : body }
        if let data { finish(.success(data)) }
        else { finish(.failure(ILoaderRemoteError.invalidResponse)) }
    }
}
