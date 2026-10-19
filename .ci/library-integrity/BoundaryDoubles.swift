// Test-only boundaries. No native provider, credentials, or network implementation.
import Foundation

public enum Constants {
    public enum Anisette {
        public static let defaultClientInfo = "synthetic-fixture"
        public static let defaultUserAgent = "synthetic-fixture"
        public static let cachingPollingDelayNanoseconds: UInt64 = 1_000_000
        public enum URLs {
            public static let grandSlamLookup = URL(string: "https://invalid.invalid/")!
        }
        public enum Libraries {
            public static let requiredNames = ["libstoreservicescore.so", "libCoreADI.so"]
        }
    }
}

final class Observations: @unchecked Sendable {
    static let shared = Observations()
    var temporaryDirectoryReads = 0
    var directoryCreates = 0
    var extractionCalls = 0
    var providerCalls = 0
    var validationCalls = 0
    var networkCalls = 0
    var temporaryRoot: URL!
    func reset() {
        temporaryDirectoryReads = 0
        directoryCreates = 0
        extractionCalls = 0
        providerCalls = 0
        validationCalls = 0
        networkCalls = 0
    }
}

// The exact production methods bind to this forwarding facade. Directory/file
// operations use Foundation; only the temporary root and observations differ.
public final class FileManager: @unchecked Sendable {
    public static let `default` = FileManager()
    public var temporaryDirectory: URL {
        Observations.shared.temporaryDirectoryReads += 1
        return Observations.shared.temporaryRoot
    }
    public func createDirectory(at url: URL, withIntermediateDirectories: Bool,
                                attributes: [FileAttributeKey: Any]? = nil) throws {
        Observations.shared.directoryCreates += 1
        try Foundation.FileManager.default.createDirectory(
            at: url, withIntermediateDirectories: withIntermediateDirectories, attributes: attributes)
    }
    public func fileExists(atPath path: String) -> Bool {
        Foundation.FileManager.default.fileExists(atPath: path)
    }
    public func setAttributes(_ attributes: [FileAttributeKey: Any], ofItemAtPath path: String) throws {
        try Foundation.FileManager.default.setAttributes(attributes, ofItemAtPath: path)
    }
    public func attributesOfItem(atPath path: String) throws -> [FileAttributeKey: Any] {
        try Foundation.FileManager.default.attributesOfItem(atPath: path)
    }
    public func removeItem(at url: URL) throws {
        try Foundation.FileManager.default.removeItem(at: url)
    }
    public func createFile(atPath path: String, contents: Data?) -> Bool {
        Foundation.FileManager.default.createFile(atPath: path, contents: contents)
    }
}

public final class AnisetteClient {
    public let libraryDirectory: URL
    public static func validateLibrariesExist(at directory: URL, requiredLibraries: [String]) -> Bool {
        Observations.shared.validationCalls += 1
        return requiredLibraries.allSatisfy {
            Foundation.FileManager.default.fileExists(atPath: directory.appendingPathComponent($0).path)
        }
    }
    public init(provisioningDir: URL, clientInfo: String, userAgent: String, lookupURL: URL,
                requiredLibraries: [String], libraryDirectoryResolver: () throws -> URL) throws {
        Observations.shared.providerCalls += 1
        libraryDirectory = try libraryDirectoryResolver()
    }
}

// The complete production resolveZipData method is copied unchanged. Even an
// accidental fall-through cannot reach Foundation.URLSession in this fixture.
enum URLSession {
    static let shared = NetworkDenied()
}
struct NetworkDenied: Sendable {
    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        Observations.shared.networkCalls += 1
        throw URLError(.notConnectedToInternet)
    }
}

func debugLog(_ message: String) {}
func verboseLog(_ message: String) {
    if message.hasPrefix("[SideSign] FileManager.unzipArchive started for archive:") {
        Observations.shared.extractionCalls += 1
    }
}
