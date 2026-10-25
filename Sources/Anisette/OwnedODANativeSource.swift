import Foundation
import AnisetteKit
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

private final class OwnedODANativeSource: @unchecked Sendable {
    let source: OwnedODALibrarySource
    let scratchParent: URL
    let identifier: UUID
    let headers: AnisetteRequestHeaders
    private let lock = NSLock()
    private var active: OwnedOnDeviceAnisetteAttempt?
    private var cancelled = false

    init(source: OwnedODALibrarySource, scratchParent: URL, identifier: UUID, headers: AnisetteRequestHeaders) {
        self.source = source; self.scratchParent = scratchParent
        self.identifier = identifier; self.headers = headers
    }
    func cancel() {
        let attempt = lock.withLock { cancelled = true; return active }
        attempt?.cancel()
    }
    func fetch(blob: Data?) async throws -> (data: AnisetteData, newBlob: Data?) {
        try Task.checkCancellation()
        guard !lock.withLock({ cancelled }) else { throw CancellationError() }
        let storage = try OwnedODAPrivateDirectory(parent: scratchParent)
        let privateParent = storage.url
        let outcome: Result<(data: AnisetteData, newBlob: Data?), Error>
        do {

        // Asset preparation may populate the verified vendor cache, but neither
        // ADI state nor native execution uses shared writable staging.
        let libraries = try await OwnedODALibraryPreparation.prepare(source, scratchParent: privateParent)
        try Task.checkCancellation()
        guard !lock.withLock({ cancelled }) else { throw CancellationError() }
        let attempt = try await OwnedOnDeviceAnisetteAttempt(libraryDirectory: privateParent,
            verifiedLibraries: libraries, scratchParent: privateParent, identifier: identifier)
        let revoke = lock.withLock { active = attempt; return cancelled }
        if revoke || Task.isCancelled { attempt.cancel() }
        defer { lock.withLock { active = nil } }
        let raw = try await withTaskCancellationHandler {
            try await attempt.fetch(existingBlob: blob, headers: headers)
        } onCancel: { attempt.cancel() }
        try Task.checkCancellation()
        guard !lock.withLock({ cancelled }) else { throw CancellationError() }
        outcome = .success((try AnisetteDataManager.validateAndCreateAnisetteData(from: raw.headers), raw.newBlob))
        } catch { outcome = .failure(error) }
        // Never erase retained native evidence after failed teardown. Only remove
        // this exact inode's empty directory after the child has fully drained.
        try storage.removeEmpty()
        return try outcome.get()
    }
}

extension OwnedODAAuthenticationContext {
    public static func onDevice(source: OwnedODALibrarySource, scratchParent: URL,
        identifier: UUID, existingBlob: Data?, headers: AnisetteRequestHeaders,
        isAuthorized: @escaping @Sendable () -> Bool) -> OwnedODAAuthenticationContext {
        let source = OwnedODANativeSource(source: source, scratchParent: scratchParent,
                                          identifier: identifier, headers: headers)
        return OwnedODAAuthenticationContext(existingBlob: existingBlob, isAuthorized: isAuthorized,
            canceller: { source.cancel() }, fetcher: { blob in try await source.fetch(blob: blob) })
    }
}


private final class OwnedODAPrivateDirectory {
    let url: URL
    private let parentFD: Int32
    private let directoryFD: Int32
    private let name: String
    init(parent: URL) throws {
        let canonical = parent.resolvingSymlinksInPath().standardizedFileURL
        let parentFD = open(canonical.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parentFD >= 0 else { throw AnisetteError.providerNotReady("Owned ODA parent unavailable.") }
        var pattern = Array(canonical.appendingPathComponent("OwnedODAContext-XXXXXX").path.utf8CString)
        let created = pattern.withUnsafeMutableBufferPointer { buffer -> String? in
            guard let pointer = buffer.baseAddress, let path = mkdtemp(pointer) else { return nil }
            return String(cString: path)
        }
        guard let created else { close(parentFD); throw AnisetteError.providerNotReady("Cannot create private ODA storage.") }
        let url = URL(fileURLWithPath: created, isDirectory: true)
        let name = url.lastPathComponent
        let directoryFD = openat(parentFD, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        var identity = stat()
        guard directoryFD >= 0, fstat(directoryFD, &identity) == 0,
              identity.st_uid == geteuid(), identity.st_mode & mode_t(0o777) == mode_t(0o700) else {
            if directoryFD >= 0 { close(directoryFD) }; close(parentFD)
            throw AnisetteError.providerNotReady("Owned ODA storage identity rejected.")
        }
        self.url = url; self.name = name; self.parentFD = parentFD; self.directoryFD = directoryFD
    }
    deinit { close(directoryFD); close(parentFD) }
    func removeEmpty() throws {
        var held = stat(); var named = stat()
        guard fstat(directoryFD, &held) == 0,
              fstatat(parentFD, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
              held.st_dev == named.st_dev, held.st_ino == named.st_ino,
              named.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              unlinkat(parentFD, name, AT_REMOVEDIR) == 0 else {
            throw AnisetteError.providerNotReady("Owned ODA cleanup incomplete; retained storage was not recursively removed.")
        }
    }
}
