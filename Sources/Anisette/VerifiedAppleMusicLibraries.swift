import Foundation
import Crypto
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// Vendor source is separate from custom ODA metadata: never reinterpret or
// ignore the latter's declared archive checksum. No APK code is executed here.
enum VerifiedAppleMusicLibraries {
    static let source = URL(string: "https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk")!
    static let archiveBytes: Int64 = 142_139_820
    private static let commitLock = NSLock()
    static let cacheName = "AppleMusic-4.9.6.1447-arm64-v1"
    struct Library: Sendable {
        let name: String
        let size: Int
        let sha256: String
        var entry: String { "lib/arm64-v8a/" + name }
    }
    // Independently published source: parawanderer/OpenTagViewer commit
    // 29846fa06bea19029c9605802d9284ded6bcf146, app/src/main/assets/adi-libraries.json.
    // Checked against Apple's HTTPS APK; not derived from the rejected zzz ZIP.
    static let libraries = [
        Library(name: "libCoreADI.so", size: 1_792_592,
            sha256: "9d5b557cf3faf88c34c394ab2cd7fc1a3b4acf3aed51f28cd0bc093858107c22"),
        Library(name: "libstoreservicescore.so", size: 2_388_480,
            sha256: "bd335e6963ba5ae2f5babca613435ad56d2660a9aee37df35f876c458d105ce4")
    ]
    static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
    static func validate(_ data: Data, library: Library) throws {
        guard data.count == library.size, digest(data) == library.sha256 else {
            throw AnisetteError.sha256Mismatch(expected: library.sha256, actual: digest(data))
        }
    }
    static func validateCache(_ directory: URL) throws {
        let fm = FileManager.default
        guard try fm.attributesOfItem(atPath: directory.path)[.type] as? FileAttributeType == .typeDirectory,
              directory.standardizedFileURL == directory.resolvingSymlinksInPath().standardizedFileURL else {
            throw AnisetteError.providerNotReady("Vendor cache is not a regular directory.")
        }
        for library in libraries {
            let file = directory.appendingPathComponent(library.name)
            let attributes = try fm.attributesOfItem(atPath: file.path)
            guard attributes[.type] as? FileAttributeType == .typeRegular,
                  (attributes[.size] as? NSNumber)?.intValue == library.size else {
                throw AnisetteError.missingRequiredLibs([library.name])
            }
            let data = try Data(contentsOf: file)
            try validate(data, library: library)
        }
    }
    static func prepare(in base: URL) async throws -> URL {
        let fm = FileManager.default
        try Task.checkCancellation()
        try fm.createDirectory(at: base, withIntermediateDirectories: true)
        // FileManager's trusted app-container root may use the OS /var alias.
        // Resolve that root once; cache/staging children themselves must not be links.
        let base = base.resolvingSymlinksInPath().standardizedFileURL
        let destination = base.appendingPathComponent(cacheName, isDirectory: true)
        if (try? fm.attributesOfItem(atPath: destination.path)) != nil {
            if (try? validateCache(destination)) != nil { return destination }
            // Keep a damaged revision intact until a replacement is fully checked.
            guard try fm.attributesOfItem(atPath: destination.path)[.type] as? FileAttributeType == .typeDirectory else {
                throw AnisetteError.providerNotReady("Vendor cache leaf is not a directory.")
            }
        }
        var pattern = Array(base.appendingPathComponent(".vendor-stage-XXXXXX").path.utf8CString)
        let staging: URL = try pattern.withUnsafeMutableBufferPointer { buffer in
            guard let pointer = buffer.baseAddress, let created = mkdtemp(pointer) else {
                throw AnisetteError.downloadFailed("Cannot create vendor staging directory.")
            }
            return URL(fileURLWithPath: String(cString: created), isDirectory: true)
        }
        defer { try? fm.removeItem(at: staging) }
        let archive = staging.appendingPathComponent("download.apk")
        let downloader = VendorAPKDownload(destination: archive)
        try await withTaskCancellationHandler {
            try await downloader.download()
        } onCancel: { downloader.cancel() }
        try Task.checkCancellation()
        let output = staging.appendingPathComponent("libraries", isDirectory: true)
        try fm.createDirectory(at: output, withIntermediateDirectories: false,
                               attributes: [.posixPermissions: 0o700])
        try extract(archive: archive, into: output)
        try validateCache(output)
        try Task.checkCancellation()
        return try publish(output: output, destination: destination, base: base)
    }
    // No suspension while held. Revalidate the winner under this process-wide
    // commit lock before moving any owned revision out of the active path.
    static func publish(output: URL, destination: URL, base: URL,
                        validateDirectory: (URL) throws -> Void = validateCache) throws -> URL {
        commitLock.lock(); defer { commitLock.unlock() }
        let fm = FileManager.default
        try Task.checkCancellation()
        let lockURL = base.appendingPathComponent(".vendor-install.lock")
        let descriptor = open(lockURL.path, O_CREAT | O_RDWR | O_NOFOLLOW, mode_t(0o600))
        guard descriptor >= 0 else { throw AnisetteError.providerNotReady("Cannot open vendor cache lock.") }
        defer { close(descriptor) }
        var attributes = stat()
        guard fstat(descriptor, &attributes) == 0,
              (attributes.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG) else {
            throw AnisetteError.providerNotReady("Invalid vendor cache lock.")
        }
        let lockDeadline = Date().addingTimeInterval(5)
        while lockf(descriptor, F_TLOCK, 0) != 0 {
            try Task.checkCancellation()
            guard (errno == EAGAIN || errno == EACCES), Date() < lockDeadline else {
                throw AnisetteError.providerNotReady("Vendor cache is busy.")
            }
            usleep(10_000)
        }
        defer { _ = lockf(descriptor, F_ULOCK, 0) }
        try validateDirectory(output)
        if (try? validateDirectory(destination)) != nil { return destination }
        if (try? fm.attributesOfItem(atPath: destination.path)) == nil {
            do { try fm.moveItem(at: output, to: destination) }
            catch { try validateDirectory(destination) } // Concurrent verified winner.
        } else {
            guard try fm.attributesOfItem(atPath: destination.path)[.type] as? FileAttributeType == .typeDirectory else {
                throw AnisetteError.providerNotReady("Vendor cache leaf changed type.")
            }
            // Quarantine only this mode's owned cache revision, never legacy libs
            // or provisioning. A failed rollback retains the backup for recovery.
            let quarantine = base.appendingPathComponent(".vendor-quarantine-" + UUID().uuidString)
            try fm.moveItem(at: destination, to: quarantine)
            do {
                try fm.moveItem(at: output, to: destination)
                try validateDirectory(destination)
                try fm.removeItem(at: quarantine)
            } catch {
                if (try? fm.attributesOfItem(atPath: destination.path)) == nil {
                    try fm.moveItem(at: quarantine, to: destination)
                } else if (try? validateDirectory(destination)) != nil {
                    try? fm.removeItem(at: quarantine)
                    return destination
                }
                throw error
            }
        }
        try validateDirectory(destination)
        return destination
    }
    static func extract(archive: URL, into output: URL) throws {
        // Bound the existing reader's central-directory allocation before opening.
        let handle = try FileHandle(forReadingFrom: archive)
        defer { try? handle.close() }
        let size = try handle.seekToEnd()
        guard size == UInt64(archiveBytes) else { throw AnisetteError.decompressionFailed("Invalid vendor archive size.") }
        let tailSize = min(size, 65_558)
        try handle.seek(toOffset: size - tailSize)
        let tail = try handle.read(upToCount: Int(tailSize)) ?? Data()
        func u16(_ index: Int) -> UInt64 { UInt64(tail[index]) | UInt64(tail[index + 1]) << 8 }
        func u32(_ index: Int) -> UInt64 { u16(index) | u16(index + 2) << 16 }
        var end: Int?
        if tail.count >= 22 {
            for index in stride(from: tail.count - 22, through: 0, by: -1) {
                if u32(index) == 0x06054b50 { end = index; break }
            }
        }
        guard let end, u16(end + 4) == 0, u16(end + 6) == 0,
              u16(end + 8) == u16(end + 10), u16(end + 10) <= 10_000,
              u32(end + 12) <= 4_194_304,
              u32(end + 16) + u32(end + 12) == size - tailSize + UInt64(end),
              end + 22 + Int(u16(end + 20)) == tail.count else {
            throw AnisetteError.decompressionFailed("Invalid vendor ZIP directory.")
        }
        // The generic reader does not expose ZIP flags or compare local names.
        // This fixed vendor format requires unencrypted, descriptor-free entries.
        try handle.seek(toOffset: u32(end + 16))
        let central = try handle.read(upToCount: Int(u32(end + 12))) ?? Data()
        func read16(_ data: Data, _ i: Int) -> UInt64 { UInt64(data[i]) | UInt64(data[i + 1]) << 8 }
        func read32(_ data: Data, _ i: Int) -> UInt64 { read16(data, i) | read16(data, i + 2) << 16 }
        var cursor = 0
        for _ in 0..<Int(u16(end + 10)) {
            guard cursor + 46 <= central.count, read32(central, cursor) == 0x02014b50 else {
                throw AnisetteError.decompressionFailed("Malformed vendor central directory.")
            }
            let nameLength = Int(read16(central, cursor + 28))
            let next = cursor + 46 + nameLength + Int(read16(central, cursor + 30)) + Int(read16(central, cursor + 32))
            guard next <= central.count else { throw AnisetteError.decompressionFailed("Truncated vendor entry.") }
            let name = central.subdata(in: cursor + 46..<cursor + 46 + nameLength)
            if libraries.contains(where: { Data($0.entry.utf8) == name }) {
                let localOffset = read32(central, cursor + 42)
                guard read16(central, cursor + 8) == 0,
                      localOffset + 30 <= u32(end + 16) else {
                    throw AnisetteError.decompressionFailed("Unsupported vendor ZIP flags.")
                }
                try handle.seek(toOffset: localOffset)
                let local = try handle.read(upToCount: 30) ?? Data()
                guard local.count == 30, read32(local, 0) == 0x04034b50,
                      read16(local, 6) == 0, read16(local, 8) == read16(central, cursor + 10),
                      read32(local, 14) == read32(central, cursor + 16),
                      read32(local, 18) == read32(central, cursor + 20),
                      read32(local, 22) == read32(central, cursor + 24),
                      Int(read16(local, 26)) == nameLength,
                      localOffset + 30 + UInt64(nameLength) + read16(local, 28) + read32(local, 18) <= u32(end + 16),
                      try handle.read(upToCount: nameLength) == name else {
                    throw AnisetteError.decompressionFailed("Vendor local header differs from directory.")
                }
            }
            cursor = next
        }
        guard cursor == central.count else { throw AnisetteError.decompressionFailed("Trailing vendor directory data.") }
        let reader = try Archive.Reader.open(at: archive)
        let entries = try reader.entries()
        guard entries.count == Int(u16(end + 10)) else { throw AnisetteError.decompressionFailed("Vendor entry count exceeds limit.") }
        for library in libraries {
            let matches = entries.filter { $0.filename == library.entry }
            guard matches.count == 1, let entry = matches.first,
                  !entry.isDirectory,
                  (entry.externalAttributes >> 16) & 0o170000 == 0o100000,
                  entry.uncompressedSize == Int64(library.size),
                  entry.compressedSize > 0, entry.compressedSize <= Int64(library.size),
                  entry.compressionMethod == 0 || entry.compressionMethod == 8 else {
                throw AnisetteError.decompressionFailed("Invalid vendor library entry.")
            }
        }
        try reader.goToFirstFile()
        repeat {
            try Task.checkCancellation()
            let entry = try reader.currentEntry()
            guard let library = libraries.first(where: { $0.entry == entry.filename }) else { continue }
            let data = try reader.readCurrentFile()
            try validate(data, library: library)
            try data.write(to: output.appendingPathComponent(library.name), options: .withoutOverwriting)
        } while reader.goToNextFile()
    }
}

// A dedicated ephemeral session streams to disk, rejects all redirects and
// credentials, and enforces a byte cap independently of Content-Length.
final class VendorAPKDownload: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let destination: URL
    private let configuration: URLSessionConfiguration
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Error>?
    private var session: URLSession?
    private var task: URLSessionDataTask?
    private var handle: FileHandle?
    private var count: Int64 = 0
    private var failure: Error?
    private var cancelled = false
    init(destination: URL, configuration: URLSessionConfiguration = .ephemeral) {
        self.destination = destination
        self.configuration = configuration
    }
    func download() async throws {
        try await withCheckedThrowingContinuation { continuation in
            lock.lock(); defer { lock.unlock() }
            guard !cancelled else { continuation.resume(throwing: CancellationError()); return }
            guard FileManager.default.createFile(atPath: destination.path, contents: nil,
                attributes: [.posixPermissions: 0o600]) else {
                continuation.resume(throwing: AnisetteError.downloadFailed("Cannot stage vendor download.")); return
            }
            do { handle = try FileHandle(forWritingTo: destination) }
            catch { continuation.resume(throwing: error); return }
            self.continuation = continuation
            let config = configuration
            config.httpCookieStorage = nil; config.urlCredentialStorage = nil; config.urlCache = nil
            config.httpShouldSetCookies = false
            config.timeoutIntervalForRequest = 60
            config.timeoutIntervalForResource = 300
            let queue = OperationQueue(); queue.maxConcurrentOperationCount = 1
            let session = URLSession(configuration: config, delegate: self, delegateQueue: queue)
            self.session = session
            var request = URLRequest(url: VerifiedAppleMusicLibraries.source)
            request.cachePolicy = .reloadIgnoringLocalCacheData
            request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
            let task = session.dataTask(with: request); self.task = task; task.resume()
        }
    }
    func cancel() {
        lock.lock(); cancelled = true; let current = task; lock.unlock()
        current?.cancel()
    }
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == "NSURLAuthenticationMethodServerTrust" {
            completionHandler(.performDefaultHandling, nil)
        } else { completionHandler(.cancelAuthenticationChallenge, nil) }
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask,
                    didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        lock.lock(); defer { lock.unlock() }
        guard let response = response as? HTTPURLResponse, response.statusCode == 200 else {
            failure = AnisetteError.archiveHTTPFailure(statusCode: (response as? HTTPURLResponse)?.statusCode ?? -1)
            completionHandler(.cancel); return
        }
        guard response.url == VerifiedAppleMusicLibraries.source,
              response.expectedContentLength == VerifiedAppleMusicLibraries.archiveBytes,
              response.value(forHTTPHeaderField: "Content-Encoding").map({ $0.lowercased() == "identity" }) ?? true else {
            failure = AnisetteError.downloadFailed("Unexpected vendor response metadata.")
            completionHandler(.cancel); return
        }
        completionHandler(.allow)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock(); defer { lock.unlock() }
        guard failure == nil, !cancelled else { dataTask.cancel(); return }
        guard Int64(data.count) <= VerifiedAppleMusicLibraries.archiveBytes - count else {
            failure = AnisetteError.downloadFailed("Vendor archive exceeds byte limit."); dataTask.cancel(); return
        }
        do { try handle?.write(contentsOf: data); count += Int64(data.count) }
        catch { failure = error; dataTask.cancel() }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        lock.lock()
        do { try handle?.close() } catch { if failure == nil { failure = error } }
        handle = nil
        let result: Error? = cancelled ? CancellationError() : (failure ?? error ??
            (count == VerifiedAppleMusicLibraries.archiveBytes ? nil : AnisetteError.downloadFailed("Incomplete vendor archive.")))
        let done = continuation; continuation = nil; self.task = nil; self.session = nil
        lock.unlock()
        session.finishTasksAndInvalidate()
        if let result { done?.resume(throwing: result) } else { done?.resume() }
    }
}
