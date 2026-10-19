// Only the reserve path uses these isolated, redirect-refusing transports.
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

struct RemoteReserveHTTPResponse: Sendable {
    let data: Data
    let response: HTTPURLResponse
}
protocol RemoteReserveTransport: Sendable {
    func data(for request: URLRequest, maximumBytes: Int) async throws -> RemoteReserveHTTPResponse
    func openWebSocket(at url: URL) throws -> any RemoteReserveWebSocket
}
protocol RemoteReserveWebSocket: Sendable {
    func send(_ bytes: Data) async throws
    func receive() async throws -> Data
    func cancel()
}

struct RemoteReserveNetworkTransport: RemoteReserveTransport {
    func data(for request: URLRequest, maximumBytes: Int) async throws -> RemoteReserveHTTPResponse {
        try await RemoteReserveHTTPTask(request: request, maximumBytes: maximumBytes).run()
    }
    func openWebSocket(at url: URL) throws -> any RemoteReserveWebSocket {
        try RemoteReserveNetworkWebSocket(url: url)
    }
    static func configuration() -> URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 60
        return configuration
    }
}

/// Streaming collection enforces a cap BEFORE appending each chunk, unlike a
/// post-hoc check on URLSession.data(for:), which has already allocated the body.
final class RemoteReserveHTTPTask: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let request: URLRequest
    private let maximumBytes: Int
    private let startTask: @Sendable (URLSessionDataTask) -> Void
    private let lock = NSLock()
    private var continuation: CheckedContinuation<RemoteReserveHTTPResponse, Error>?
    private var session: URLSession?
    private var task: URLSessionDataTask?
    private var response: HTTPURLResponse?
    private var body = Data()
    private var completed = false

    // Internal starter seam lets the synthetic delegate harness park a task
    // without resuming it. Public reserve calls always use the real resume.
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
    func run() async throws -> RemoteReserveHTTPResponse {
        try Task.checkCancellation()
        return try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { continuation in
                lock.lock()
                if completed {
                    lock.unlock()
                    continuation.resume(throwing: CancellationError())
                    return
                }
                self.continuation = continuation
                let session = URLSession(configuration: RemoteReserveNetworkTransport.configuration(), delegate: self, delegateQueue: nil)
                self.session = session
                let task = session.dataTask(with: request)
                self.task = task
                lock.unlock()
                startTask(task)
            }
        }, onCancel: { self.finish(.failure(CancellationError())) })
    }
    private func finish(_ result: Result<RemoteReserveHTTPResponse, Error>) {
        lock.lock()
        guard !completed else { lock.unlock(); return }
        completed = true
        let continuation = self.continuation
        let session = self.session
        self.continuation = nil
        self.session = nil
        self.task = nil
        lock.unlock()
        session?.invalidateAndCancel()
        continuation?.resume(with: result)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        // Reject even same-origin redirects; never replay identity-bearing bodies.
        completionHandler(nil)
        finish(.failure(RemoteReserveError.redirectRefused))
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // Standard TLS validation only. Never pull credentials from shared stores.
        #if canImport(Security)
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            completionHandler(.performDefaultHandling, nil)
        } else { completionHandler(.cancelAuthenticationChallenge, nil) }
        #else
        completionHandler(.cancelAuthenticationChallenge, nil)
        #endif
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping @Sendable (URLSession.ResponseDisposition) -> Void) {
        guard let http = response as? HTTPURLResponse, http.url == request.url else {
            completionHandler(.cancel); finish(.failure(RemoteReserveError.invalidResponse)); return
        }
        guard http.statusCode == 200 else {
            completionHandler(.cancel); finish(.failure(RemoteReserveError.httpStatus(http.statusCode))); return
        }
        guard http.expectedContentLength <= Int64(maximumBytes) else {
            completionHandler(.cancel); finish(.failure(RemoteReserveError.responseTooLarge)); return
        }
        lock.withLock { self.response = http }
        completionHandler(.allow)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        let overflow = lock.withLock { () -> Bool in
            guard !completed else { return false }
            guard data.count <= maximumBytes - body.count else { return true }
            body.append(data)
            return false
        }
        if overflow { finish(.failure(RemoteReserveError.responseTooLarge)) }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error {
            finish(.failure(error))
            return
        }
        let result = lock.withLock { () -> RemoteReserveHTTPResponse? in
            guard let response else { return nil }
            return RemoteReserveHTTPResponse(data: body, response: response)
        }
        if let result { finish(.success(result)) }
        else { finish(.failure(RemoteReserveError.invalidResponse)) }
    }
}

final class RemoteReserveSocketDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil)
        task.cancel()
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        #if canImport(Security)
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            completionHandler(.performDefaultHandling, nil)
        } else { completionHandler(.cancelAuthenticationChallenge, nil) }
        #else
        completionHandler(.cancelAuthenticationChallenge, nil)
        #endif
    }
}

final class RemoteReserveNetworkWebSocket: RemoteReserveWebSocket, @unchecked Sendable {
    private let session: URLSession
    private let task: URLSessionWebSocketTask
    private let url: URL
    private let operationTimeoutNanoseconds: UInt64
    init(url: URL, operationTimeoutNanoseconds: UInt64 = 30_000_000_000,
         startTask: @Sendable (URLSessionWebSocketTask) -> Void = { $0.resume() }) throws {
        guard url.scheme == "wss" else { throw RemoteReserveError.invalidOrigin }
        self.url = url
        self.operationTimeoutNanoseconds = operationTimeoutNanoseconds
        session = URLSession(configuration: RemoteReserveNetworkTransport.configuration(),
            delegate: RemoteReserveSocketDelegate(), delegateQueue: nil)
        var request = RemoteReserveValidation.request(url)
        request.httpShouldHandleCookies = false
        task = session.webSocketTask(with: request)
        task.maximumMessageSize = RemoteReserveValidation.maximumResponseBytes
        startTask(task)
    }
    deinit { cancel() }
    func cancel() {
        task.cancel(with: .goingAway, reason: nil)
        session.invalidateAndCancel()
    }
    func bounded<T: Sendable>(_ operation: @escaping @Sendable () async throws -> T) async throws -> T {
        try Task.checkCancellation()
        return try await withTaskCancellationHandler(operation: {
            try await withThrowingTaskGroup(of: T.self) { group in
                group.addTask { try await operation() }
                group.addTask {
                    try await Task.sleep(nanoseconds: self.operationTimeoutNanoseconds)
                    self.cancel() // Wake an otherwise blocked receive/send before joining.
                    throw RemoteReserveError.timedOut
                }
                defer { group.cancelAll() }
                guard let result = try await group.next() else { throw RemoteReserveError.invalidResponse }
                try Task.checkCancellation()
                guard self.task.currentRequest?.url == self.url else { throw RemoteReserveError.redirectRefused }
                return result
            }
        }, onCancel: { self.cancel() })
    }
    func send(_ bytes: Data) async throws {
        guard bytes.count <= RemoteReserveValidation.maximumResponseBytes,
              let string = String(data: bytes, encoding: .utf8) else { throw RemoteReserveError.invalidInput }
        try await bounded { try await self.task.send(.string(string)) }
    }
    func receive() async throws -> Data {
        try await bounded {
            let bytes: Data
            switch try await self.task.receive() {
            case .data(let value): bytes = value
            case .string(let value): bytes = Data(value.utf8)
            @unknown default: throw RemoteReserveError.invalidResponse
            }
            guard bytes.count <= RemoteReserveValidation.maximumResponseBytes else { throw RemoteReserveError.responseTooLarge }
            return bytes
        }
    }
}
