// Run only: swift test --filter ILoaderRemoteHTTPTransportTests
// Uses real Foundation tasks and actual production delegate code. No task resumes,
// no real provider/Apple request occurs, and all bodies are synthetic.
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import XCTest
@testable import SideSign

private final class HTTPDelegateTestBox<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Value
    init(_ value: Value) { stored = value }
    var value: Value { lock.withLock { stored } }
    func set(_ value: Value) { lock.withLock { stored = value } }
    func update(_ change: (inout Value) -> Void) { lock.withLock { change(&stored) } }
}
private enum HTTPDelegateTestError: Error { case notReady }

@MainActor
final class ILoaderRemoteHTTPTransportTests: XCTestCase {
    private func request(_ name: String = "body") -> URLRequest {
        URLRequest(url: URL(string:"https://synthetic.invalid/" + name)!)
    }
    private func waitFor(_ condition: () -> Bool) async throws {
        for _ in 0..<1000 {
            if condition() { return }
            try await Task.sleep(nanoseconds:1_000_000)
        }
        XCTFail("A parked task did not reach its expected boundary")
        throw HTTPDelegateTestError.notReady
    }
    private func expectCancellation(_ operation: Task<Data, Error>) async {
        do { _ = try await operation.value; XCTFail("Cancellation must not return a response") }
        catch is CancellationError { }
        catch { XCTFail("Expected CancellationError, got \(type(of:error))") }
    }
    private func reply(_ collector: ILoaderRemoteHTTPTask, task: URLSessionDataTask,
                       session: URLSession, bytes: Data = Data([1,2,3,4])) {
        let response = HTTPURLResponse(url:task.originalRequest!.url!,statusCode:200,
            httpVersion:"HTTP/1.1",headerFields:["Content-Length":String(bytes.count)])!
        collector.urlSession(session,dataTask:task,didReceive:response) { _ in }
        collector.urlSession(session,dataTask:task,didReceive:bytes)
        collector.urlSession(session,task:task,didCompleteWithError:nil)
    }

    func testCancelBeforeContinuationStartsNoFoundationTask() async throws {
        let starts = HTTPDelegateTestBox(0)
        let collector = ILoaderRemoteHTTPTask(request:request(),maximumBytes:4,startTask:{ _ in starts.update { $0 += 1 } })
        collector.cancel()
        let operation = Task { try await collector.run() }
        await expectCancellation(operation)
        XCTAssertEqual(starts.value,0)
    }

    func testInvalidateBetweenRegistryInsertionAndRunStartsNoTask() async throws {
        let starts = HTTPDelegateTestBox(0)
        let ownerBox = HTTPDelegateTestBox<ILoaderRemoteHTTPTransport?>(nil)
        let owner = ILoaderRemoteHTTPTransport(startTask:{ _ in starts.update { $0 += 1 } },
            didRegister:{ _ in ownerBox.value?.invalidate() })
        ownerBox.set(owner)
        defer { ownerBox.set(nil) }
        let first = Task { try await owner.data(for:request()) }
        await expectCancellation(first)
        let second = Task { try await owner.data(for:request("later")) }
        await expectCancellation(second)
        XCTAssertEqual(starts.value,0)
    }

    func testCancelAfterSessionCreationBeforeResumeClosesRealTask() async throws {
        let taskBox = HTTPDelegateTestBox<URLSessionDataTask?>(nil)
        let collectorBox = HTTPDelegateTestBox<ILoaderRemoteHTTPTask?>(nil)
        let collector = ILoaderRemoteHTTPTask(request:request(),maximumBytes:4,startTask:{ task in
            taskBox.set(task)
            collectorBox.value?.cancel()
            // Intentionally never resume this actual Foundation task.
        })
        collectorBox.set(collector)
        defer { collectorBox.set(nil) }
        let operation = Task { try await collector.run() }
        await expectCancellation(operation)
        guard let task = taskBox.value else { return XCTFail("Expected an actual parked Foundation task") }
        try await waitFor { task.state == .canceling || task.state == .completed }
    }

    func testDuplicateCompletionAndLateDataCannotResumeTwice() async throws {
        let parked = HTTPDelegateTestBox<URLSessionDataTask?>(nil)
        let collector = ILoaderRemoteHTTPTask(request:request(),maximumBytes:4,startTask:{ parked.set($0) })
        let operation = Task { try await collector.run() }
        defer { operation.cancel() }
        try await waitFor { parked.value != nil }
        let task = parked.value!
        let callbacks = URLSession(configuration:.ephemeral)
        defer { callbacks.invalidateAndCancel() }
        reply(collector,task:task,session:callbacks)
        collector.urlSession(callbacks,task:task,didCompleteWithError:nil)
        collector.urlSession(callbacks,task:task,didCompleteWithError:URLError(.cancelled))
        collector.urlSession(callbacks,dataTask:task,didReceive:Data([9,9,9]))
        let data = try await operation.value
        XCTAssertEqual(data,Data([1,2,3,4]))
    }

    func testOneConcurrentCancellationDoesNotCancelAnotherRequest() async throws {
        let tasks = HTTPDelegateTestBox<[URLSessionDataTask]>([])
        let collectors = HTTPDelegateTestBox<[ILoaderRemoteHTTPTask]>([])
        let owner = ILoaderRemoteHTTPTransport(startTask:{ task in tasks.update { $0.append(task) } },
            didRegister:{ collector in collectors.update { $0.append(collector) } })
        defer { owner.invalidate() }
        let firstRequest = request("first")
        let first = Task { try await owner.data(for:firstRequest,maximumBytes:4) }
        defer { first.cancel() }
        try await waitFor { tasks.value.count == 1 }
        let secondRequest = request("second")
        let second = Task { try await owner.data(for:secondRequest,maximumBytes:4) }
        defer { second.cancel() }
        try await waitFor { tasks.value.count == 2 }
        first.cancel()
        await expectCancellation(first)
        let secondTask = tasks.value[1]
        XCTAssertEqual(secondTask.state,.suspended)
        let callbacks = URLSession(configuration:.ephemeral)
        defer { callbacks.invalidateAndCancel() }
        reply(collectors.value[1],task:secondTask,session:callbacks)
        let value = try await second.value
        XCTAssertEqual(value,Data([1,2,3,4]))
        XCTAssertEqual(tasks.value.count,2)
    }

    func testOwnerInvalidationCancelsEveryConcurrentTask() async throws {
        let tasks = HTTPDelegateTestBox<[URLSessionDataTask]>([])
        let owner = ILoaderRemoteHTTPTransport(startTask:{ task in tasks.update { $0.append(task) } })
        let firstRequest = request("first")
        let secondRequest = request("second")
        let first = Task { try await owner.data(for:firstRequest) }
        let second = Task { try await owner.data(for:secondRequest) }
        defer { first.cancel(); second.cancel(); owner.invalidate() }
        try await waitFor { tasks.value.count == 2 }
        owner.invalidate()
        await expectCancellation(first)
        await expectCancellation(second)
        try await waitFor { tasks.value.allSatisfy { $0.state == .canceling || $0.state == .completed } }
    }

    func testRealDelegateRejectsStreamOverflowBeforeLateCompletion() async throws {
        let parked = HTTPDelegateTestBox<URLSessionDataTask?>(nil)
        let collector = ILoaderRemoteHTTPTask(request:request(),maximumBytes:4,startTask:{ parked.set($0) })
        let operation = Task { try await collector.run() }
        defer { operation.cancel() }
        try await waitFor { parked.value != nil }
        let task = parked.value!
        let callbacks = URLSession(configuration:.ephemeral)
        defer { callbacks.invalidateAndCancel() }
        let response = HTTPURLResponse(url:task.originalRequest!.url!,statusCode:200,httpVersion:"HTTP/1.1",headerFields:nil)!
        collector.urlSession(callbacks,dataTask:task,didReceive:response) { _ in }
        collector.urlSession(callbacks,dataTask:task,didReceive:Data([1,2,3]))
        collector.urlSession(callbacks,dataTask:task,didReceive:Data([4,5]))
        collector.urlSession(callbacks,task:task,didCompleteWithError:nil)
        do { _ = try await operation.value; XCTFail("Overflow must fail") }
        catch ILoaderRemoteError.invalidResponse { }
        catch { XCTFail("Expected finite invalidResponse, got \(type(of:error))") }
    }
}
