import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public enum OwnedODALibrarySource: Sendable {
    case verifiedAppleMusic(baseDirectory: URL)
    case customMetadata(sourceURL: URL, fallbackURL: URL?)
}

/// The owned path never initializes the legacy shared VM or shares mutable ADI state.
/// Built-in preparation may populate its hash-verified vendor cache; execution gets immutable bytes.
enum OwnedODALibraryPreparation {
    static func prepare(_ source: OwnedODALibrarySource, scratchParent: URL) async throws -> [String: Data] {
        switch source {
        case .verifiedAppleMusic(let base):
            let directory = try await VerifiedAppleMusicLibraries.prepare(in: base)
            var result: [String: Data] = [:]
            for library in VerifiedAppleMusicLibraries.libraries {
                try Task.checkCancellation()
                let bytes = try Data(contentsOf: directory.appendingPathComponent(library.name))
                try VerifiedAppleMusicLibraries.validate(bytes, library: library)
                result[library.name] = bytes
            }
            return result
        case .customMetadata(let sourceURL, let fallbackURL):
            let info = try await metadata(sourceURL, fallbackURL: fallbackURL)
            guard let expected = info.sha256?.lowercased(), expected.count == 64,
                  expected.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
                throw AnisetteError.providerNotReady("Owned custom ODA requires an explicit archive SHA-256.")
            }
            let archive: Data
            if let inline = info.base64Payload,
               let decoded = Data(base64Encoded: inline.trimmingCharacters(in: .whitespacesAndNewlines), options: .ignoreUnknownCharacters) {
                archive = decoded
            } else if let value = info.url, let url = URL(string: value) {
                let downloaded = try await download(url, maximum: 64 * 1024 * 1024)
                if let text = String(data: downloaded, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
                   let decoded = Data(base64Encoded: text, options: .ignoreUnknownCharacters) { archive = decoded }
                else { archive = downloaded }
            } else { throw AnisetteError.invalidBase64Payload }
            guard !archive.isEmpty, archive.count <= 64 * 1024 * 1024 else {
                throw AnisetteError.downloadFailed("Owned custom ODA archive exceeds its bound.")
            }
            let observed = VerifiedAppleMusicLibraries.digest(archive)
            guard observed == expected else { throw AnisetteError.sha256Mismatch(expected: expected, actual: observed) }
            try Task.checkCancellation()
            let file = scratchParent.appendingPathComponent("OwnedODAArchive-" + UUID().uuidString + ".zip")
            try archive.write(to: file, options: .withoutOverwriting)
            defer { try? FileManager.default.removeItem(at: file) }
            let reader = try Archive.Reader.open(at: file)
            let entries = try reader.entries()
            let names = Set(VerifiedAppleMusicLibraries.libraries.map(\.name))
            guard entries.count <= 1024,
                  Set(entries.map(\.filename)).count == entries.count else {
                throw AnisetteError.decompressionFailed("Duplicate or excessive custom ODA entries.")
            }
            for name in names {
                let matches = entries.filter { $0.filename == name }
                guard matches.count == 1, let entry = matches.first,
                      !entry.isDirectory, entry.uncompressedSize > 0, entry.uncompressedSize <= 16 * 1024 * 1024,
                      entry.compressedSize > 0, entry.compressedSize <= 64 * 1024 * 1024,
                      entry.compressionMethod == 0 || entry.compressionMethod == 8,
                      (entry.externalAttributes >> 16) & 0o170000 != 0o120000 else {
                    throw AnisetteError.missingRequiredLibs([name])
                }
            }
            var result: [String: Data] = [:]
            try reader.goToFirstFile()
            repeat {
                try Task.checkCancellation()
                let entry = try reader.currentEntry()
                if names.contains(entry.filename) {
                    let bytes = try reader.readCurrentFile()
                    guard Int64(bytes.count) == entry.uncompressedSize else { throw AnisetteError.invalidBase64Payload }
                    result[entry.filename] = bytes
                }
            } while reader.goToNextFile()
            guard Set(result.keys) == names else { throw AnisetteError.missingRequiredLibs(Array(names)) }
            return result
        }
    }
    private static func metadata(_ source: URL, fallbackURL: URL?) async throws -> ODAInfo {
        let bytes = try await download(source, maximum: 8 * 1024 * 1024)
        let decoder = JSONDecoder()
        if let direct = try? decoder.decode(ODAInfo.self, from: bytes), direct.url != nil || direct.base64Payload != nil {
            return direct
        }
        let servers = try? decoder.decode(AnisetteServerData.self, from: bytes)
        switch servers?.oda {
        case .direct(let info): return info
        case .path(let value):
            guard let url = URL(string: value, relativeTo: source)?.absoluteURL else { throw AnisetteError.missingODAEntry }
            return try decoder.decode(ODAInfo.self, from: await download(url, maximum: 8 * 1024 * 1024))
        case .none:
            guard let url = fallbackURL else { throw AnisetteError.missingODAEntry }
            return try decoder.decode(ODAInfo.self, from: await download(url, maximum: 8 * 1024 * 1024))
        }
    }
    private static func download(_ url: URL, maximum: Int) async throws -> Data {
        guard url.scheme?.lowercased() == "https", url.user == nil, url.password == nil, url.host != nil else {
            throw AnisetteError.invalidURL
        }
        let download = OwnedODABoundedDownload(url: url, maximum: maximum)
        return try await withTaskCancellationHandler { try await download.fetch() }
            onCancel: { download.cancel() }
    }
}

private final class OwnedODABoundedDownload: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    let url: URL
    let maximum: Int
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, Error>?
    private var task: URLSessionDataTask?
    private var session: URLSession?
    private var cancelled = false
    private var bytes = Data()
    private var failure: Error?
    init(url: URL, maximum: Int) { self.url = url; self.maximum = maximum }
    func fetch() async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            lock.lock(); defer { lock.unlock() }
            guard !cancelled else { continuation.resume(throwing: CancellationError()); return }
            self.continuation = continuation
            let config = URLSessionConfiguration.ephemeral
            config.httpCookieStorage = nil; config.urlCredentialStorage = nil; config.urlCache = nil
            config.httpShouldSetCookies = false; config.timeoutIntervalForRequest = 30; config.timeoutIntervalForResource = 60
            let queue = OperationQueue(); queue.maxConcurrentOperationCount = 1
            let session = URLSession(configuration: config, delegate: self, delegateQueue: queue)
            self.session = session
            var request = URLRequest(url: url); request.cachePolicy = .reloadIgnoringLocalCacheData
            request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
            let task = session.dataTask(with: request); self.task = task; task.resume()
        }
    }
    func cancel() { let current = lock.withLock { cancelled = true; return task }; current?.cancel() }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        completionHandler(challenge.protectionSpace.authenticationMethod == "NSURLAuthenticationMethodServerTrust" ? .performDefaultHandling : .cancelAuthenticationChallenge, nil)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        lock.lock(); defer { lock.unlock() }
        guard let response = response as? HTTPURLResponse, response.url == url, (200..<300).contains(response.statusCode),
              response.expectedContentLength <= Int64(maximum) else {
            failure = AnisetteError.downloadFailed("Owned custom ODA response rejected."); completionHandler(.cancel); return
        }
        completionHandler(.allow)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock(); defer { lock.unlock() }
        guard !cancelled, failure == nil, data.count <= maximum - bytes.count else {
            failure = AnisetteError.downloadFailed("Owned custom ODA download exceeds its bound."); dataTask.cancel(); return
        }
        bytes.append(data)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        lock.lock(); let result: Error? = cancelled ? CancellationError() : (failure ?? error)
        let done = continuation; continuation = nil; self.task = nil; self.session = nil; let value = bytes; bytes = Data(); lock.unlock()
        session.finishTasksAndInvalidate()
        if let result { done?.resume(throwing: result) } else { done?.resume(returning: value) }
    }
}
