import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Separate from RemoteMac: selecting this context changes ownership, not SRP/2FA wire policy.
public enum OwnedODAAuthentication {
    @TaskLocal public static var current: OwnedODAAuthenticationContext?

    public static func data(for request: URLRequest, legacySession: URLSession,
                            remoteSelected: Bool, validateAfterResponse: Bool = true) async throws -> (Data, URLResponse) {
        guard let context = current else { return try await legacySession.data(for: request) }
        guard !remoteSelected else { throw OwnedODAAuthenticationError.conflictingRoutes }
        try context.checkActive()
        let result = try await withTaskCancellationHandler {
            try await context.session.data(for: request)
        } onCancel: { context.invalidate() }
        if validateAfterResponse { try context.checkActive() }
        return result
    }
}

public enum OwnedODAAuthenticationError: Error, Sendable {
    case revoked, overlappingFetch, conflictingRoutes, staleBlob
}

/// Each authentication operation owns one context. Each native fetch must drain
/// before its task completes. Invalidation never substitutes a legacy provider.
public final class OwnedODAAuthenticationContext: @unchecked Sendable {
    public let session: URLSession
    private let lock = NSLock()
    private let isAuthorized: @Sendable () -> Bool
    private let fetcher: @Sendable (Data?) async throws -> (data: AnisetteData, newBlob: Data?)
    private let canceller: @Sendable () -> Void
    private var invalidated = false
    private var currentBlob: Data?
    private var pendingBlob: Data?
    private var active: Task<AnisetteData, Error>?
    private var fetching = false

    public init(existingBlob: Data?, isAuthorized: @escaping @Sendable () -> Bool,
                canceller: @escaping @Sendable () -> Void,
                fetcher: @escaping @Sendable (Data?) async throws -> (data: AnisetteData, newBlob: Data?)) {
        currentBlob = existingBlob
        self.isAuthorized = isAuthorized; self.canceller = canceller; self.fetcher = fetcher
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil; configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 30; configuration.timeoutIntervalForResource = 60
        session = URLSession(configuration: configuration)
    }

    deinit { session.invalidateAndCancel() }

    public func checkActive() throws {
        try Task.checkCancellation()
        guard isAuthorized(), lock.withLock({ !invalidated }) else {
            throw OwnedODAAuthenticationError.revoked
        }
    }

    public func invalidate() {
        let task = lock.withLock { () -> Task<AnisetteData, Error>? in
            invalidated = true; pendingBlob = nil
            return active
        }
        session.invalidateAndCancel()
        task?.cancel()
        canceller()
    }

    /// Awaiting this method joins even a cancelled native worker. It is not a timeout shortcut.
    public func finish() async {
        invalidate()
        let task = lock.withLock { active }
        _ = await task?.result
    }

    public func fetch() async throws -> AnisetteData {
        try checkActive()
        let task: Task<AnisetteData, Error> = try lock.withLock {
            guard !invalidated else { throw OwnedODAAuthenticationError.revoked }
            guard !fetching else { throw OwnedODAAuthenticationError.overlappingFetch }
            fetching = true
            let blob = currentBlob
            // Publish the child under the same lock that invalidation/finish reads.
            // No cancellation can observe an admitted worker without its drain handle.
            let child = Task<AnisetteData, Error> { [self] in
                try checkActive()
                let result = try await fetcher(blob)
                try checkActive()
                try lock.withLock {
                    guard !invalidated else { throw OwnedODAAuthenticationError.revoked }
                    if let fresh = result.newBlob {
                        guard !fresh.isEmpty, blob == nil || blob == fresh else {
                            throw OwnedODAAuthenticationError.staleBlob
                        }
                        currentBlob = fresh; pendingBlob = fresh
                    }
                }
                return result.data
            }
            active = child
            return child
        }
        defer { lock.withLock { active = nil; fetching = false } }
        return try await withTaskCancellationHandler {
            let value = try await task.value
            try checkActive()
            return value
        } onCancel: { self.invalidate() }
    }

    /// The caller captures this while authorized, then commits under its own
    /// compare-and-reserve identity transition and Keychain snapshot CAS.
    public func stagedBlobForCommit() throws -> Data? {
        try checkActive()
        return try lock.withLock {
            guard !invalidated, !fetching else { throw OwnedODAAuthenticationError.revoked }
            return pendingBlob
        }
    }

    /// Commit and invalidation have one linearization lock. The supplied closure
    /// must synchronously verify the caller's reserved identity and perform its
    /// snapshot-CAS write; it must not suspend or call this context recursively.
    public func commitStagedBlob(_ expected: Data?, commit: (Data?) throws -> Void) throws {
        try lock.withLock {
            try Task.checkCancellation()
            guard !invalidated, !fetching, pendingBlob == expected else {
                throw OwnedODAAuthenticationError.revoked
            }
            try commit(expected)
            pendingBlob = nil
        }
    }
}
