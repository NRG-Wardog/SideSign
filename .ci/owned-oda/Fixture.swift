import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public struct AnisetteData: Sendable, Equatable { let value: Int }

final class Authorization: @unchecked Sendable {
    private let lock = NSLock()
    private var valid = true
    func allowed() -> Bool { lock.withLock { valid } }
    func revoke() { lock.withLock { valid = false } }
}
actor Barrier {
    private var entered = false
    private var arrival: CheckedContinuation<Void, Never>?
    private var exit: CheckedContinuation<Void, Never>?
    private(set) var calls = 0
    func blocked() async {
        entered = true; calls += 1; arrival?.resume(); arrival = nil
        await withCheckedContinuation { exit = $0 }
    }
    func waitUntilEntered() async {
        if entered { return }
        await withCheckedContinuation { arrival = $0 }
    }
    func release() { exit?.resume(); exit = nil }
}
final class CompletionState: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    func mark() { lock.withLock { value = true } }
    func read() -> Bool { lock.withLock { value } }
}
actor BlobInputs {
    private(set) var values: [Data?] = []
    func record(_ value: Data?) { values.append(value) }
}
@main struct OwnedODAContextTests {
    static func main() async throws {
        let fresh = Data([1, 2, 3])
        let calls = BlobInputs()
        let context = OwnedODAAuthenticationContext(existingBlob: nil, isAuthorized: { true }, canceller: {}) { blob in
            await calls.record(blob)
            return (AnisetteData(value: 7), blob == nil ? fresh : nil)
        }
        let value1 = try await context.fetch(); precondition(value1 == AnisetteData(value: 7))
        let staged1 = try context.stagedBlobForCommit(); precondition(staged1 == fresh)
        let value2 = try await context.fetch(); precondition(value2 == AnisetteData(value: 7))
        let inputs = await calls.values
        precondition(inputs == [nil, fresh])
        var committed = false
        try context.commitStagedBlob(fresh) { blob in precondition(blob == fresh); committed = true }
        precondition(committed)
        let staged2 = try context.stagedBlobForCommit(); precondition(staged2 == nil)
        await context.finish()
        var cancelledWrite = false
        do { try context.commitStagedBlob(nil) { _ in cancelledWrite = true }; fatalError("revoked commit admitted") } catch {}
        precondition(!cancelledWrite)
        do { _ = try await context.fetch(); fatalError("revoked context admitted") } catch {}

        let preCalls = BlobInputs()
        let revoked = OwnedODAAuthenticationContext(existingBlob: nil, isAuthorized: { true }, canceller: {}) { blob in
            await preCalls.record(blob); return (AnisetteData(value: 1), nil)
        }
        revoked.invalidate()
        do { _ = try await revoked.fetch(); fatalError("pre-cancel admitted") } catch {}
        let before = await preCalls.values; precondition(before.isEmpty)

        let authorization = Authorization(); let staleBarrier = Barrier()
        let stale = OwnedODAAuthenticationContext(existingBlob: nil, isAuthorized: { authorization.allowed() }, canceller: {}) { _ in
            await staleBarrier.blocked(); return (AnisetteData(value: 9), fresh)
        }
        let staleTask = Task { try await stale.fetch() }
        await staleBarrier.waitUntilEntered(); authorization.revoke(); await staleBarrier.release()
        do { _ = try await staleTask.value; fatalError("stale identity returned") } catch {}
        do { _ = try stale.stagedBlobForCommit(); fatalError("stale blob exposed") } catch {}
        await stale.finish()

        let barrier = Barrier()
        let workerExited = CompletionState(); let cleanupCompleted = CompletionState()
        let blocked = OwnedODAAuthenticationContext(existingBlob: nil, isAuthorized: { true }, canceller: {}) { _ in
            await barrier.blocked(); workerExited.mark(); return (AnisetteData(value: 3), fresh)
        }
        let first = Task { try await blocked.fetch() }
        await barrier.waitUntilEntered()
        do { _ = try await blocked.fetch(); fatalError("overlap admitted") } catch {}
        first.cancel()
        let cleanup = Task {
            await blocked.finish()
            precondition(workerExited.read(), "finish returned before native worker drained")
            cleanupCompleted.mark()
        }
        do { _ = try await blocked.fetch(); fatalError("cancelled worker readmitted") } catch {}
        let blockedCalls = await barrier.calls; precondition(blockedCalls == 1)
        precondition(!cleanupCompleted.read(), "cleanup completed with worker still blocked")
        await barrier.release()
        do { _ = try await first.value; fatalError("cancelled response returned") } catch {}
        await cleanup.value
        precondition(cleanupCompleted.read())

        let gate = OwnedODAAuthenticationContext(existingBlob: nil, isAuthorized: { true }, canceller: {}) { _ in
            (AnisetteData(value: 1), nil)
        }
        let enteredCommit = DispatchSemaphore(value: 0)
        let releaseCommit = DispatchSemaphore(value: 0)
        let cancelStarted = DispatchSemaphore(value: 0)
        let cancelCompleted = CompletionState(); let committedGate = CompletionState()
        let committedTask = Task.detached {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                DispatchQueue.global().async {
                    do {
                        try gate.commitStagedBlob(nil) { _ in
                            enteredCommit.signal(); releaseCommit.wait()
                            precondition(!cancelCompleted.read())
                            committedGate.mark()
                        }
                    } catch { fatalError("commit winner unexpectedly rejected") }
                    continuation.resume()
                }
            }
        }
        let cancelledTask = Task.detached {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                DispatchQueue.global().async {
                    enteredCommit.wait(); cancelStarted.signal(); gate.invalidate()
                    precondition(committedGate.read(), "invalidation crossed commit lock")
                    cancelCompleted.mark(); continuation.resume()
                }
            }
        }
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            DispatchQueue.global().async {
                cancelStarted.wait(); releaseCommit.signal(); continuation.resume()
            }
        }
        await committedTask.value; await cancelledTask.value
        precondition(cancelCompleted.read() && committedGate.read())
        var lateWrite = false
        do { try gate.commitStagedBlob(nil) { _ in lateWrite = true }; fatalError("cancel winner admitted commit") } catch {}
        precondition(!lateWrite)

        let mismatch = OwnedODAAuthenticationContext(existingBlob: Data([8]), isAuthorized: { true }, canceller: {}) { _ in
            (AnisetteData(value: 1), fresh)
        }
        do { _ = try await mismatch.fetch(); fatalError("existing identity overwritten") } catch {}
        await mismatch.finish()

        let scoped = OwnedODAAuthenticationContext(existingBlob: nil, isAuthorized: { true }, canceller: {}) { _ in
            (AnisetteData(value: 1), nil)
        }
        try await OwnedODAAuthentication.$current.withValue(scoped) {
            precondition(OwnedODAAuthentication.current === scoped)
            await OwnedODAAuthentication.$current.withValue(nil) { precondition(OwnedODAAuthentication.current == nil) }
            do {
                _ = try await OwnedODAAuthentication.data(for: URLRequest(url: URL(string: "https://example.invalid")!),
                                                          legacySession: .shared, remoteSelected: true)
                fatalError("conflicting wire routes admitted")
            } catch {}
        }
        await scoped.finish()
        print("PASS owned ODA context: staging, repeated fetch, pre-cancel, stale identity, joined cancellation, overlap, immutable blob, task-local shadow, conflicting routes")
    }
}
