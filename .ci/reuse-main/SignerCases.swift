import Foundation

@main struct SignerCases {
    static func main() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let appURL = root.appendingPathComponent("App.app")
        let extensionURL = appURL.appendingPathComponent("PlugIns/Widget.appex")
        try FileManager.default.createDirectory(at: extensionURL, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let mainEntitlements: [String: any Sendable] = [
            "application-identifier": "TEAM.example.app",
            "com.apple.developer.team-identifier": "TEAM", "get-task-allow": true
        ]
        let mainProfile = ProvisioningProfile(name: "synthetic-main", bundleIdentifier: "example.app",
            entitlements: mainEntitlements, data: Data("synthetic-main".utf8), expirationDate: .distantFuture)
        func setup(_ extensionEntitlements: [String: any Sendable] = [:]) {
            FixtureState.shared.bundles = [
                appURL: AppBundle(url: appURL, id: "example.app", entitlements: [:], extensions: [extensionURL]),
                extensionURL: AppBundle(url: extensionURL, id: "example.app.widget", entitlements: extensionEntitlements)
            ]
            FixtureState.shared.signedEntitlements = [:]
        }
        let signer = AppBundleSigner(team: Team(), keyStore: KeyStore())
        setup()
        let decisions = try await signer.signApp(at: appURL, provisioningProfiles: [mainProfile],
            extensionStrategy: .reuseMainWhenCompatible)
        precondition(decisions.count == 1 && decisions[0].reuseMain)
        precondition(FixtureState.shared.signedEntitlements["example.app"] == FixtureState.shared.signedEntitlements["example.app.widget"])
        let reusedProfileData = try Data(contentsOf: extensionURL.appendingPathComponent("embedded.mobileprovision"))
        precondition(reusedProfileData == mainProfile.data)
        setup(["aps-environment": "production"])
        do {
            _ = try await signer.signApp(at: appURL, provisioningProfiles: [mainProfile], extensionStrategy: .reuseMainWhenCompatible)
            preconditionFailure("Incompatible extension without fallback profile must fail")
        } catch SignerError.missingProvisioningProfile { }
        var extensionProfileEntitlements = mainEntitlements
        extensionProfileEntitlements["application-identifier"] = "TEAM.example.app.widget"
        extensionProfileEntitlements["aps-environment"] = "production"
        let extensionProfile = ProvisioningProfile(name: "synthetic-extension", bundleIdentifier: "example.app.widget",
            entitlements: extensionProfileEntitlements, data: Data("synthetic-extension".utf8), expirationDate: .distantFuture)
        let fallback = try await signer.signApp(at: appURL, provisioningProfiles: [mainProfile, extensionProfile], extensionStrategy: .reuseMainWhenCompatible)
        precondition(!fallback[0].reuseMain)
        let fallbackProfileData = try Data(contentsOf: extensionURL.appendingPathComponent("embedded.mobileprovision"))
        precondition(fallbackProfileData == extensionProfile.data)
        setup()
        try await signer.signApp(at: appURL, provisioningProfiles: [mainProfile, extensionProfile])
        precondition(FixtureState.shared.signedEntitlements["example.app"] != FixtureState.shared.signedEntitlements["example.app.widget"])
        setup(mainEntitlements)
        let refreshed = try await signer.signApp(at: appURL, provisioningProfiles: [mainProfile],
            extensionStrategy: .reuseMainWhenCompatible,
            previouslyReusedExtensionIdentifiers: ["example.app.widget"])
        precondition(refreshed[0].reuseMain)
        setup(mainEntitlements)
        do {
            _ = try await signer.signApp(at: appURL, provisioningProfiles: [mainProfile], extensionStrategy: .reuseMainWhenCompatible)
            preconditionFailure("An imported copied main identity is not trusted")
        } catch SignerError.missingProvisioningProfile { }
        setup(["aps-environment": "production"])
        var insufficientEntitlements = mainEntitlements
        insufficientEntitlements["application-identifier"] = "TEAM.example.app.widget"
        let insufficient = ProvisioningProfile(name: "missing-push", bundleIdentifier: "example.app.widget",
            entitlements: insufficientEntitlements, data: Data(), expirationDate: .distantFuture)
        do {
            _ = try await signer.signApp(at: appURL, provisioningProfiles: [mainProfile, insufficient],
                extensionStrategy: .perExtensionPreservingCapabilities)
            preconditionFailure("Fallback must not silently remove required push")
        } catch SignerError.invalidApp { }
        setup()
        var foreign = mainProfile
        foreign.teamIdentifier = "OTHER"
        do {
            _ = try await signer.signApp(at: appURL, provisioningProfiles: [foreign], extensionStrategy: .reuseMainWhenCompatible)
            preconditionFailure("Foreign team profile must fail")
        } catch SignerError.invalidApp { }
        let foreignSigner = AppBundleSigner(team: Team(), keyStore: KeyStore(certificate: Certificate(organizationalUnit: "OTHER")))
        do {
            _ = try await foreignSigner.signApp(at: appURL, provisioningProfiles: [mainProfile], extensionStrategy: .reuseMainWhenCompatible)
            preconditionFailure("Foreign certificate must fail")
        } catch SignerError.invalidApp { }
        let differentLeafSigner = AppBundleSigner(team: Team(), keyStore: KeyStore(certificate: Certificate(data: Data("other-leaf".utf8))))
        do {
            _ = try await differentLeafSigner.signApp(at: appURL, provisioningProfiles: [mainProfile], extensionStrategy: .reuseMainWhenCompatible)
            preconditionFailure("Same-team leaf not listed in profile must fail")
        } catch SignerError.invalidApp { }
        print("ReuseMain signer fixture: candidate, exact entitlements/profile, explicit fallback and default checks passed; no cryptographic or device proof")
    }
}
