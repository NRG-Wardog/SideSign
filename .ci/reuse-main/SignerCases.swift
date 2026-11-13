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
        let groupKey = "com.apple.security.application-groups"
        setup([groupKey: ["group.source"]])
        var mappedProfile = insufficient
        mappedProfile.entitlements[groupKey] = ["group.source.TEAM"]
        let assignedMap = ["example.app.widget": ["group.source": "group.source.TEAM"]]
        do {
            _ = try await signer.signApp(at: appURL, provisioningProfiles: [mainProfile, mappedProfile], extensionStrategy: .perExtensionPreservingCapabilities)
            preconditionFailure("Real strict signer must reject an unrecorded remap")
        } catch SignerError.invalidApp { }
        _ = try await signer.signApp(at: appURL, provisioningProfiles: [mainProfile, mappedProfile], extensionStrategy: .perExtensionPreservingCapabilities, provisionedAppGroupMappings: assignedMap)
        for strategy in [ExtensionSigningStrategy.reuseMainWhenCompatible, .perExtensionPreservingCapabilities] {
            let wrongMap = strategy == .reuseMainWhenCompatible ? assignedMap : ["wrong.bundle": ["group.source": "group.source.TEAM"]]
            do {
                _ = try await signer.signApp(at: appURL, provisioningProfiles: [mainProfile, mappedProfile], extensionStrategy: strategy, provisionedAppGroupMappings: wrongMap)
                preconditionFailure("Mappings are scoped to separate strategy and exact bundle")
            } catch SignerError.invalidApp { }
        }
        // A valid remap must never waive the rest of strict signing admission.
        var expiredMapped = mappedProfile
        expiredMapped.expirationDate = .distantPast
        var foreignMapped = mappedProfile
        foreignMapped.teamIdentifier = "OTHER"
        let wrongLeaf = AppBundleSigner(team: Team(), keyStore: KeyStore(certificate: Certificate(data: Data("different-leaf".utf8))))
        for (candidateSigner, candidateProfile) in [(signer, expiredMapped), (signer, foreignMapped), (wrongLeaf, mappedProfile)] {
            do {
                _ = try await candidateSigner.signApp(at: appURL, provisioningProfiles: [mainProfile, candidateProfile], extensionStrategy: .perExtensionPreservingCapabilities, provisionedAppGroupMappings: assignedMap)
                preconditionFailure("Recorded mapping cannot bypass profile/certificate admission")
            } catch SignerError.invalidApp { }
        }
        setup([groupKey: ["group.source"], "aps-environment": "production"])
        do {
            _ = try await signer.signApp(at: appURL, provisioningProfiles: [mainProfile, mappedProfile], extensionStrategy: .perExtensionPreservingCapabilities, provisionedAppGroupMappings: assignedMap)
            preconditionFailure("Recorded group mapping cannot drop another capability")
        } catch SignerError.invalidApp { }
        setup([groupKey: ["group.source"]])
        FixtureState.shared.bundles[appURL] = AppBundle(url: appURL, id: "example.app", entitlements: [groupKey: ["group.source"]], extensions: [extensionURL])
        var mappedMain = mainProfile
        mappedMain.entitlements[groupKey] = ["group.source.TEAM"]
        _ = try await signer.signApp(at: appURL, provisioningProfiles: [mappedMain, mappedProfile], extensionStrategy: .perExtensionPreservingCapabilities, provisionedAppGroupMappings: ["example.app": ["group.source": "group.source.TEAM"], "example.app.widget": ["group.source": "group.source.TEAM"]])
        setup([groupKey: ["group.source"]])
        mappedProfile.entitlements[groupKey] = ["group.tampered"]
        do {
            _ = try await signer.signApp(at: appURL, provisioningProfiles: [mainProfile, mappedProfile], extensionStrategy: .perExtensionPreservingCapabilities, provisionedAppGroupMappings: assignedMap)
            preconditionFailure("A changed profile cannot satisfy recorded mapping")
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
