// Synthetic fixtures only. Never select the live transport from these tests.
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Testing
import AnisetteKit
@testable import SideSign

private let reserveID = UUID(uuidString: "00010203-0405-0607-0809-0A0B0C0D0E0F")!
private let reserveServer = URL(string: "https://reserve.example")!
private let clientInfo = "<Synthetic> <Test;1;1> <Example/1>"
private let userAgent = "Synthetic/1"
private func json(_ object: [String: String]) throws -> Data { try JSONSerialization.data(withJSONObject: object) }
private func descriptorBytes(_ info: String = clientInfo) throws -> Data {
    try json(["client_info": info, "user_agent": userAgent])
}
private func headerBytes() throws -> Data {
    try json(["result": "Headers", "X-Apple-I-MD": "SYNTHETIC-OTP", "X-Apple-I-MD-M": "SYNTHETIC-MID", "X-Apple-I-MD-RINFO": "12345"])
}
private func descriptor() -> RemoteReserveDescriptor {
    RemoteReserveDescriptor(origin: reserveServer.absoluteString, protocolVersion: 3, clientInfo: clientInfo, userAgent: userAgent)
}
private func plist(_ object: [String: Any]) throws -> Data {
    try PropertyListSerialization.data(fromPropertyList: object, format: .xml, options: 0)
}
private func fixtureHTTP(_ request: URLRequest) throws -> Data {
    switch request.url!.path {
    case "/v3/client_info": return try descriptorBytes()
    case "/v3/get_headers": return try headerBytes()
    case "/grandslam/GsService2/lookup":
        return try plist(["urls": ["midStartProvisioning": "https://gsa.apple.com/grandslam/start", "midFinishProvisioning": "https://gsa.apple.com/grandslam/finish"]])
    case "/grandslam/start": return try plist(["Response": ["spim": "AQID"]])
    case "/grandslam/finish": return try plist(["Response": ["ptm": "BAU=", "tk": "Bg=="]])
    default: throw RemoteReserveError.unexpectedStep
    }
}
private final class FakeSocket: RemoteReserveWebSocket, @unchecked Sendable {
    private let lock = NSLock()
    private var messages: [Data]
    private var sent: [Data] = []
    private var cancellations = 0
    let suspendReceive: Bool
    init(_ values: [[String: String]] = [], suspendReceive: Bool = false) throws {
        messages = try values.map(json)
        self.suspendReceive = suspendReceive
    }
    var outgoing: [Data] { lock.withLock { sent } }
    var cancelled: Bool { lock.withLock { cancellations > 0 } }
    func send(_ bytes: Data) async throws { try Task.checkCancellation(); lock.withLock { sent.append(bytes) } }
    func receive() async throws -> Data {
        if suspendReceive { try await Task.sleep(nanoseconds: 60_000_000_000) }
        try Task.checkCancellation()
        return try lock.withLock {
            guard !messages.isEmpty else { throw RemoteReserveError.unexpectedStep }
            return messages.removeFirst()
        }
    }
    func cancel() { lock.withLock { cancellations += 1 } }
}
private final class FakeTransport: RemoteReserveTransport, @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [URLRequest] = []
    private var connections: [URL] = []
    let socket: FakeSocket
    let handler: @Sendable (URLRequest) async throws -> Data
    init(socket: FakeSocket, handler: @escaping @Sendable (URLRequest) async throws -> Data = { try fixtureHTTP($0) }) {
        self.socket = socket; self.handler = handler
    }
    var requests: [URLRequest] { lock.withLock { recorded } }
    var webSockets: [URL] { lock.withLock { connections } }
    func data(for request: URLRequest, maximumBytes: Int) async throws -> RemoteReserveHTTPResponse {
        try Task.checkCancellation()
        lock.withLock { recorded.append(request) }
        let bytes = try await handler(request)
        guard bytes.count <= maximumBytes else { throw RemoteReserveError.responseTooLarge }
        return RemoteReserveHTTPResponse(data: bytes, response: HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
            headerFields: ["X-Apple-I-MD-RINFO": "999"])!)
    }
    func openWebSocket(at url: URL) throws -> any RemoteReserveWebSocket {
        lock.withLock { connections.append(url) }
        return socket
    }
}
private func fetch(_ transport: FakeTransport, blob: Data? = Data([8, 9]),
                   expected: RemoteReserveDescriptor? = descriptor()) async throws -> (data: AnisetteData, newAdiBlob: Data?, descriptor: RemoteReserveDescriptor) {
    let manager = AnisetteDataManager(mode: .localODA(libsDir: URL(fileURLWithPath: "/does-not-exist")))
    return try await manager.fetchRemoteReserveAnisetteData(server: reserveServer, identifier: reserveID,
        existingAdiBlob: blob, profileGeneration: UUID(), expectedDescriptor: expected, transport: transport)
}
private func expectReserveError(_ expected: RemoteReserveError, _ operation: () async throws -> Void) async {
    do { try await operation(); Issue.record("Expected finite reserve error") }
    catch { #expect((error as? RemoteReserveError) == expected) }
}

private func waitUntil(_ condition: @Sendable () -> Bool) async -> Bool {
    // A failed upstream step must fail the test, never spin or hang CI.
    for _ in 0..<400 {
        if condition() { return true }
        do { try await Task.sleep(nanoseconds: 5_000_000) } catch { return false }
    }
    return condition()
}

@Suite("RemoteReserveTests: synthetic transport, no identity or network")
struct RemoteReserveTests {
    @Test func normalizesOnlyHTTPSOrigins() throws {
        #expect(try AnisetteDataManager.normalizedRemoteReserveOrigin(URL(string: "https://EXAMPLE.com:443/")!).absoluteString == "https://example.com")
        for value in ["http://example.com", "https://u:p@example.com", "https://example.com/path", "https://example.com/?x=1", "https://example.com/#x", "https://example.com."] {
            #expect(throws: RemoteReserveError.invalidOrigin) { try AnisetteDataManager.normalizedRemoteReserveOrigin(URL(string: value)!) }
        }
    }
    @Test func existingBlobUsesDescriptorAndCorrectUUIDEncoding() async throws {
        let transport = FakeTransport(socket: try FakeSocket())
        let result = try await fetch(transport)
        #expect(result.newAdiBlob == nil)
        #expect(result.descriptor == descriptor())
        #expect(result.data.clientInfo == clientInfo)
        #expect(result.data.userAgent == userAgent)
        #expect(result.data.routingInfo == "12345")
        #expect(result.data.localUserID == "be45cb2605bf36bebde684841a28f0fd43c69850a3dce5fedba69928ee3a8991")
        #expect(transport.webSockets.isEmpty)
        #expect(transport.requests.map { $0.url!.path } == ["/v3/client_info", "/v3/get_headers"])
        let body = try RemoteReserveValidation.json(transport.requests[1].httpBody!, maximumBytes: 1000)
        // Exact reference-format regression: 16 binary bytes, NEVER UUID hex text.
        #expect(body["identifier"] == "AAECAwQFBgcICQoLDA0ODw==")
        #expect(body["adi_pb"] == "CAk=")
        #expect(transport.requests[1].value(forHTTPHeaderField: "X-Mme-Device-Id") == nil)
    }
    @Test func mismatchedDescriptorStopsBeforeIdentityTransmission() async throws {
        let transport = FakeTransport(socket: try FakeSocket(), handler: { _ in try descriptorBytes("<Changed>") })
        await expectReserveError(.descriptorChanged) { _ = try await fetch(transport) }
        #expect(transport.requests.count == 1)
        #expect(transport.requests[0].httpBody == nil)
        #expect(transport.webSockets.isEmpty)
    }
    @Test func invalidDescriptorStopsBeforeIdentityTransmission() async throws {
        for info in ["", "<Injected>\r\nAuthorization: secret", String(repeating: "x", count: 1025)] {
            let transport = FakeTransport(socket: try FakeSocket(), handler: { _ in try descriptorBytes(info) })
            await expectReserveError(.invalidDescriptor) { _ = try await fetch(transport) }
            #expect(transport.requests.count == 1)
        }
    }
    @Test func rejectsUnboundExistingOrEmptyBlobBeforeNetwork() async throws {
        let transport = FakeTransport(socket: try FakeSocket())
        await expectReserveError(.invalidInput) { _ = try await fetch(transport, expected: nil) }
        await expectReserveError(.invalidInput) { _ = try await fetch(transport, blob: Data()) }
        await expectReserveError(.invalidInput) { _ = try await fetch(transport, blob: Data(repeating: 0, count: 1_048_577)) }
        #expect(transport.requests.isEmpty)
    }
    @Test func v3FailureNeverDowngradesReprovisionsOrRotates() async throws {
        let transport = FakeTransport(socket: try FakeSocket(), handler: { request in
            if request.url!.path == "/v3/client_info" { return try descriptorBytes() }
            return try json(["result": "GetHeadersError", "message": "synthetic"])
        })
        await expectReserveError(.invalidResponse) { _ = try await fetch(transport) }
        #expect(transport.requests.count == 2)
        #expect(transport.requests.allSatisfy { $0.url!.host == "reserve.example" && $0.url!.path.hasPrefix("/v3/") })
        #expect(transport.webSockets.isEmpty)
    }
    @Test func freshProvisioningBindsDescriptorAndClosesSession() async throws {
        let socket = try FakeSocket([["result": "GiveIdentifier"], ["result": "GiveStartProvisioningData"],
            ["result": "GiveEndProvisioningData", "cpim": "Bw=="], ["result": "ProvisioningSuccess", "adi_pb": "CAk="]])
        let transport = FakeTransport(socket: socket)
        let result = try await fetch(transport, blob: nil, expected: nil)
        #expect(result.newAdiBlob == Data([8, 9]))
        #expect(transport.requests.count == 5)
        #expect(transport.webSockets == [URL(string: "wss://reserve.example/v3/provisioning_session")!])
        #expect(socket.cancelled)
        let identifier = try RemoteReserveValidation.json(socket.outgoing[0], maximumBytes: 1000)
        #expect(identifier["identifier"] == "AAECAwQFBgcICQoLDA0ODw==")
        for request in transport.requests where request.url!.host == "gsa.apple.com" {
            #expect(request.value(forHTTPHeaderField: "X-Mme-Client-Info") == clientInfo)
            #expect(request.value(forHTTPHeaderField: "User-Agent") == userAgent)
            #expect(request.value(forHTTPHeaderField: "X-Mme-Device-Id") == reserveID.uuidString.uppercased())
        }
        #expect(transport.requests.first { $0.url!.path == "/grandslam/finish" }?.value(forHTTPHeaderField: "X-Apple-I-MD-RINFO") == "999")
    }
    @Test func duplicateOrReorderedProtocolStepsFailClosed() async throws {
        for steps in [["GiveStartProvisioningData"], ["GiveIdentifier", "GiveIdentifier"]] {
            let socket = try FakeSocket(steps.map { ["result": $0] })
            let transport = FakeTransport(socket: socket)
            await expectReserveError(.unexpectedStep) { _ = try await fetch(transport, blob: nil, expected: nil) }
            #expect(socket.cancelled)
            #expect(!transport.requests.contains { $0.url!.path == "/v3/get_headers" })
        }
    }
    @Test func maliciousAppleLookupURLIsNeverRequested() async throws {
        let transport = FakeTransport(socket: try FakeSocket(), handler: { request in
            if request.url!.path == "/grandslam/GsService2/lookup" {
                return try plist(["urls": ["midStartProvisioning": "https://attacker.example/collect", "midFinishProvisioning": "https://gsa.apple.com/grandslam/finish"]])
            }
            return try fixtureHTTP(request)
        })
        await expectReserveError(.invalidOrigin) { _ = try await fetch(transport, blob: nil, expected: nil) }
        #expect(transport.requests.count == 2)
        #expect(transport.webSockets.isEmpty)
    }
    @Test func cancellationDuringSocketReceiveClosesWithoutFallback() async throws {
        let socket = try FakeSocket(suspendReceive: true)
        let transport = FakeTransport(socket: socket)
        let task = Task { try await fetch(transport, blob: nil, expected: nil) }
        guard await waitUntil({ !transport.webSockets.isEmpty }) else {
            task.cancel()
            _ = try? await task.value
            Issue.record("Synthetic socket never became ready")
            return
        }
        task.cancel()
        do { _ = try await task.value; Issue.record("Expected cancellation") }
        catch { #expect(error is CancellationError) }
        #expect(socket.cancelled)
        #expect(!transport.requests.contains { $0.url!.path == "/v3/get_headers" })
    }
    @Test func alreadyCancelledTaskSendsNothing() async throws {
        let transport = FakeTransport(socket: try FakeSocket())
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await fetch(transport)
        }
        do { _ = try await task.value; Issue.record("Expected cancellation") }
        catch { #expect(error is CancellationError) }
        #expect(transport.requests.isEmpty)
    }
    @Test func binaryAndJSONBoundsAreEnforced() throws {
        #expect(throws: RemoteReserveError.invalidResponse) { try RemoteReserveValidation.blob("!!!") }
        #expect(throws: RemoteReserveError.invalidResponse) { try RemoteReserveValidation.blob("") }
        #expect(throws: RemoteReserveError.responseTooLarge) { try RemoteReserveValidation.json(Data(repeating: 0, count: 17), maximumBytes: 16) }
        #expect(throws: RemoteReserveError.invalidResponse) { try RemoteReserveValidation.json(Data("[]".utf8), maximumBytes: 16) }
    }
    @Test func repeatedCallsDoNotCacheOTPOrDescriptor() async throws {
        let transport = FakeTransport(socket: try FakeSocket())
        _ = try await fetch(transport)
        _ = try await fetch(transport)
        #expect(transport.requests.count == 4)
    }
    @Test func tracesUseRemoteStages() async throws {
        let transport = FakeTransport(socket: try FakeSocket())
        let trace = LoginDiagnosticTrace()
        _ = try await LoginDiagnosticTrace.$current.withValue(trace) { try await fetch(transport) }
        let rows = trace.snapshot(maximumBytes: 8192).split(separator: ";").dropFirst(4)
        let stages = rows.compactMap { Int($0.split(separator: ",")[0]) }
        #expect(stages.contains(LoginDiagnosticStage.remoteDescriptor.rawValue))
        #expect(stages.contains(LoginDiagnosticStage.remoteHeaders.rawValue))
        #expect(!stages.contains(LoginDiagnosticStage.nativeOTP.rawValue))
        #expect(!stages.contains(LoginDiagnosticStage.nativeVM.rawValue))
    }
}

private final class ParkedHTTPTask: @unchecked Sendable {
    private let lock = NSLock()
    private var value: URLSessionDataTask?
    func store(_ task: URLSessionDataTask) { lock.withLock { value = task } }
    var task: URLSessionDataTask? { lock.withLock { value } }
}
private final class RedirectObservation: @unchecked Sendable {
    private let lock = NSLock()
    private var refused = false
    func record(_ request: URLRequest?) { lock.withLock { refused = request == nil } }
    var wasRefused: Bool { lock.withLock { refused } }
}

@Suite("RemoteReserveHTTPDelegateTests: parked tasks, never resumed")
struct RemoteReserveHTTPDelegateTests {
    // This exercises the REAL delegate/state/continuation implementation, not
    // FakeTransport. Created URLSession tasks are parked and NEVER resumed.
    private func harness(_ perform: (RemoteReserveHTTPTask, URLSession, URLSessionDataTask) -> Void,
                         expected: RemoteReserveError) async throws {
        let request = RemoteReserveValidation.request(reserveServer.appendingPathComponent("v3/get_headers"))
        let parked = ParkedHTTPTask()
        let operation = RemoteReserveHTTPTask(request: request, maximumBytes: 8, startTask: { parked.store($0) })
        let runner = Task { try await operation.run() }
        guard await waitUntil({ parked.task != nil }), let task = parked.task else {
            runner.cancel(); _ = try? await runner.value
            Issue.record("Synthetic HTTP task never became ready")
            return
        }
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel(); runner.cancel() }
        perform(operation, session, task)
        do { _ = try await runner.value; Issue.record("Expected delegate failure") }
        catch { #expect((error as? RemoteReserveError) == expected) }
    }
    @Test func redirectIsRefusedBeforeReplayingBody() async throws {
        let observed = RedirectObservation()
        try await harness({ operation, session, task in
            let redirect = HTTPURLResponse(url: task.originalRequest!.url!, statusCode: 307, httpVersion: nil,
                headerFields: ["Location": "https://attacker.example/collect"])!
            operation.urlSession(session, task: task, willPerformHTTPRedirection: redirect,
                newRequest: URLRequest(url: URL(string: "https://attacker.example/collect")!),
                completionHandler: { observed.record($0) })
        }, expected: .redirectRefused)
        #expect(observed.wasRefused)
    }
    @Test func streamedChunksStopBeforeExceedingCap() async throws {
        try await harness({ operation, session, task in
            let response = HTTPURLResponse(url: task.originalRequest!.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            operation.urlSession(session, dataTask: task, didReceive: response, completionHandler: { _ in })
            operation.urlSession(session, dataTask: task, didReceive: Data(repeating: 1, count: 8))
            operation.urlSession(session, dataTask: task, didReceive: Data([2]))
            // A late success callback must not replace the size failure.
            operation.urlSession(session, task: task, didCompleteWithError: nil)
        }, expected: .responseTooLarge)
    }
    @Test func declaredOversizeAndChangedResponseURLAreRejected() async throws {
        try await harness({ operation, session, task in
            let response = HTTPURLResponse(url: task.originalRequest!.url!, statusCode: 200, httpVersion: nil,
                headerFields: ["Content-Length": "9"])!
            operation.urlSession(session, dataTask: task, didReceive: response, completionHandler: { _ in })
        }, expected: .responseTooLarge)
        try await harness({ operation, session, task in
            let response = HTTPURLResponse(url: URL(string: "https://attacker.example/collect")!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            operation.urlSession(session, dataTask: task, didReceive: response, completionHandler: { _ in })
        }, expected: .invalidResponse)
    }
    @Test func cancellationWinsAgainstLateCompletion() async throws {
        let request = RemoteReserveValidation.request(reserveServer)
        let parked = ParkedHTTPTask()
        let operation = RemoteReserveHTTPTask(request: request, maximumBytes: 8, startTask: { parked.store($0) })
        let runner = Task { try await operation.run() }
        guard await waitUntil({ parked.task != nil }), let task = parked.task else {
            runner.cancel(); _ = try? await runner.value
            Issue.record("Synthetic HTTP task never became ready")
            return
        }
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        runner.cancel()
        let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
        operation.urlSession(session, dataTask: task, didReceive: response, completionHandler: { _ in })
        operation.urlSession(session, dataTask: task, didReceive: Data([1]))
        operation.urlSession(session, task: task, didCompleteWithError: nil)
        do { _ = try await runner.value; Issue.record("Expected cancellation") }
        catch { #expect(error is CancellationError) }
    }
}

private final class ParkedWebSocket: @unchecked Sendable {
    private let lock = NSLock()
    private var value: URLSessionWebSocketTask?
    func store(_ task: URLSessionWebSocketTask) { lock.withLock { value = task } }
    var task: URLSessionWebSocketTask? { lock.withLock { value } }
    var isCancelled: Bool {
        lock.withLock { value?.state == .canceling || value?.state == .completed }
    }
}

private final class OperationReadiness: @unchecked Sendable {
    private let lock = NSLock()
    private var ready = false
    func markReady() { lock.withLock { ready = true } }
    var isReady: Bool { lock.withLock { ready } }
}

@Suite("RemoteReserveWebSocketDelegateTests: parked tasks, never resumed")
struct RemoteReserveWebSocketDelegateTests {
    @Test func redirectCallbackRefusesTargetAndCancelsHandshake() {
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        let url = URL(string: "wss://reserve.example/v3/provisioning_session")!
        let task = session.webSocketTask(with: url) // NEVER resumed
        let delegate = RemoteReserveSocketDelegate()
        let observed = RedirectObservation()
        let response = HTTPURLResponse(url: url, statusCode: 307, httpVersion: nil, headerFields: nil)!
        delegate.urlSession(session, task: task, willPerformHTTPRedirection: response,
            newRequest: URLRequest(url: URL(string: "wss://attacker.example/collect")!),
            completionHandler: { observed.record($0) })
        #expect(observed.wasRefused)
        #expect(task.state == .canceling || task.state == .completed)
    }
    @Test func deadlineCancelsOwnedSocketAndStopsBlockedOperation() async throws {
        let parked = ParkedWebSocket()
        let socket = try RemoteReserveNetworkWebSocket(url: URL(string: "wss://reserve.example/v3/provisioning_session")!,
            operationTimeoutNanoseconds: 1_000_000, startTask: { parked.store($0) })
        defer { socket.cancel() }
        do {
            _ = try await socket.bounded {
                try await Task.sleep(nanoseconds: 60_000_000_000)
                return 42
            }
            Issue.record("Expected bounded deadline")
        } catch { #expect((error as? RemoteReserveError) == .timedOut) }
        #expect(parked.isCancelled)
    }
    @Test func parentCancellationClosesSocketAndPropagates() async throws {
        let parked = ParkedWebSocket()
        let socket = try RemoteReserveNetworkWebSocket(url: URL(string: "wss://reserve.example/v3/provisioning_session")!,
            startTask: { parked.store($0) })
        defer { socket.cancel() }
        let readiness = OperationReadiness()
        let task = Task {
            try await socket.bounded {
                readiness.markReady()
                try await Task.sleep(nanoseconds: 60_000_000_000)
                return 42
            }
        }
        guard await waitUntil({ readiness.isReady }) else {
            task.cancel(); _ = try? await task.value
            Issue.record("Synthetic bounded operation never became ready")
            return
        }
        task.cancel()
        do { _ = try await task.value; Issue.record("Expected cancellation") }
        catch { #expect(error is CancellationError) }
        #expect(parked.isCancelled) // Handler, not explicit test cleanup, closed it.
    }
}
