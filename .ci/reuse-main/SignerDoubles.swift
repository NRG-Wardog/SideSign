import Foundation

public struct Team: Sendable { var identifier = "TEAM" }
public struct Certificate: Sendable { var organizationalUnit = "TEAM"; var data: Data? = Data("synthetic-certificate".utf8) }
public struct KeyStore: Sendable { var certificate = Certificate(); func exportP12() throws -> Data { Data() } }
public struct ProvisioningProfile: Sendable {
    let name: String
    let bundleIdentifier: String
    var teamIdentifier = "TEAM"
    let entitlements: [String: any Sendable]
    let data: Data
    let expirationDate: Date
    var certificates: [Certificate] = [Certificate()]
}
public enum SignerError: Error {
    case invalidApp(cause: String)
    case missingProvisioningProfile(bundleIdentifier: String)
    case unknown(cause: String)
}
func debugLog(_ value: String) {}
func verboseLog(_ value: String) {}

final class FixtureState: @unchecked Sendable {
    static let shared = FixtureState()
    var bundles: [URL: AppBundle] = [:]
    var signedEntitlements: [String: String] = [:]
}
struct AppBundle: Sendable, Hashable {
    let fileURL: URL
    let bundleIdentifier: String
    let entitlements: [String: any Sendable]
    let extensionURLs: [URL]
    var appExtensions: Set<AppBundle> {
        Set(extensionURLs.compactMap { FixtureState.shared.bundles[$0] })
    }
    init?(fileURL: URL) {
        guard let app = FixtureState.shared.bundles[fileURL] else { return nil }
        self = app
    }
    init(url: URL, id: String, entitlements: [String: any Sendable], extensions: [URL] = []) {
        self.fileURL = url
        self.bundleIdentifier = id
        self.entitlements = entitlements
        self.extensionURLs = extensions
    }
    static func == (lhs: Self, rhs: Self) -> Bool { lhs.fileURL == rhs.fileURL }
    func hash(into hasher: inout Hasher) { hasher.combine(fileURL) }
}
enum CodeSigner {
    static func sign(appPath: String, keyData: Data,
                     entitlementProvider: (String) -> String, progress: () -> Void) throws {
        for app in FixtureState.shared.bundles.values {
            FixtureState.shared.signedEntitlements[app.bundleIdentifier] = entitlementProvider(app.fileURL.path)
            progress()
        }
    }
}
