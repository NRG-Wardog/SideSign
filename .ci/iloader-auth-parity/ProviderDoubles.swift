// Additional boundaries used only by the dedicated fake-only opt-in fixture.
// Implementations never invoke Foundation networking or native crypto.

final class FakeSessionConfiguration: @unchecked Sendable {
    static var ephemeral: FakeSessionConfiguration { FakeSessionConfiguration() }
    var urlCache: Any?
    var httpCookieStorage: Any?
    var httpShouldSetCookies = true
    var requestCachePolicy: URLRequest.CachePolicy = .useProtocolCachePolicy
    var timeoutIntervalForRequest: TimeInterval = 0
    var timeoutIntervalForResource: TimeInterval = 0
}
protocol FakeSessionTaskDelegate {}
final class FakeSessionTask {}

final class FakeWebSocketTask: @unchecked Sendable {
    enum Message: Sendable { case string(String), data(Data) }
    enum CloseCode { case normalClosure, goingAway }
    private let lock = NSLock()
    private var incoming: [Message]
    private var outgoing: [Message] = []
    private var cancellationCount = 0
    private var cancelled = false
    private let hangOnEmpty: Bool
    private var waiter: CheckedContinuation<Message, Error>?
    var maximumMessageSize = 0
    init(_ messages: [[String: String]], hangOnEmpty: Bool = false) {
        self.hangOnEmpty = hangOnEmpty
        incoming = messages.map { .string(String(decoding: try! JSONSerialization.data(withJSONObject: $0), as: UTF8.self)) }
    }
    var sent: [Message] { lock.withLock { outgoing } }
    var cancels: Int { lock.withLock { cancellationCount } }
    func resume() {}
    func cancel(with code: CloseCode, reason: Data?) {
        let pending = lock.withLock { () -> CheckedContinuation<Message, Error>? in
            cancellationCount += 1; cancelled = true
            let result = waiter; waiter = nil; return result
        }
        pending?.resume(throwing: URLError(.cancelled))
    }
    func send(_ message: Message) async throws { lock.withLock { outgoing.append(message) } }
    func receive() async throws -> Message {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                lock.withLock {
                    if cancelled || Task.isCancelled { continuation.resume(throwing: URLError(.cancelled)) }
                    else if !incoming.isEmpty { continuation.resume(returning: incoming.removeFirst()) }
                    else if hangOnEmpty { waiter = continuation }
                    else { continuation.resume(throwing: FixtureFailure.unscripted) }
                }
            }
        } onCancel: { self.cancel(with: .goingAway, reason: nil) }
    }
}
final class TransportScript: @unchecked Sendable {
    let http: FakeSession
    private let lock = NSLock()
    private var sockets: [FakeWebSocketTask]
    private var socketURLs: [URL] = []
    private var activeSockets: [FakeWebSocketTask] = []
    private var configurations: [FakeSessionConfiguration] = []
    private var cancellations = 0
    init(_ steps: [Step], sockets: [FakeWebSocketTask] = []) { http = FakeSession(steps); self.sockets = sockets }
    var requests: [URLRequest] { http.requests }
    var websocketURLs: [URL] { lock.withLock { socketURLs } }
    var sessionConfigurations: [FakeSessionConfiguration] { lock.withLock { configurations } }
    var cancelCount: Int { lock.withLock { cancellations } }
    func configured(_ config: FakeSessionConfiguration) { lock.withLock { configurations.append(config) } }
    func cancelled() {
        let sockets = lock.withLock { () -> [FakeWebSocketTask] in cancellations += 1; return activeSockets }
        for socket in sockets { socket.cancel(with: .goingAway, reason: nil) }
    }
    func socket(_ url: URL) -> FakeWebSocketTask {
        lock.withLock {
            socketURLs.append(url)
            let selected = sockets.isEmpty ? FakeWebSocketTask([]) : sockets.removeFirst()
            activeSockets.append(selected)
            return selected
        }
    }
}
enum SyntheticTransport { @TaskLocal static var current: TransportScript? }
extension FakeSession {
    convenience init(configuration: FakeSessionConfiguration, delegate: FakeSessionTaskDelegate?, delegateQueue: OperationQueue?) {
        self.init([])
        let script = SyntheticTransport.current
        script?.configured(configuration)
        syntheticForward = { request in
            guard let script else { throw FixtureFailure.unscripted }
            return try await script.http.data(for: request)
        }
        syntheticInvalidation = { script?.cancelled() }
    }
    func invalidateAndCancel() { syntheticInvalidation?() }
    func webSocketTask(with url: URL) -> FakeWebSocketTask {
        SyntheticTransport.current?.socket(url) ?? FakeWebSocketTask([])
    }
}
// Synthetic hash boundary: output has the correct size, but is not a crypto parity assertion.
enum SHA256 {
    static func hash(data: Data) -> [UInt8] { (0..<32).map { UInt8($0) } }
}
typealias ALTAnisetteData = AnisetteData
enum AnisetteError: Error { case providerNotReady(String), invalidAnisetteData }
func withLoginDiagnosticStage<T>(_ stage: LoginDiagnosticStage, _ operation: () async throws -> T) async rethrows -> T { try await operation() }
func v3LoginStage<T>(_ stage: LoginDiagnosticStage, _ operation: () async throws -> T) async rethrows -> T { try await operation() }
