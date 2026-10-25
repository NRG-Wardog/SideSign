import Foundation

@main struct Cases {
    static func main() throws {
        let main: [String: any Sendable] = [
            "application-identifier": "TEAM.example.app",
            "com.apple.developer.team-identifier": "TEAM",
            "get-task-allow": true
        ]
        var checks = 0
        func check(_ condition: Bool, _ message: String) {
            precondition(condition, message)
            checks += 1
        }
        func decide(_ extensionValues: [String: any Sendable] = [:],
                    mainValues: [String: any Sendable]? = nil,
                    identifier: String = "example.app.widget",
                    strategy: ExtensionSigningStrategy = .reuseMainWhenCompatible) -> ExtensionSigningDecision {
            ExtensionSigningPolicy.evaluate(strategy: strategy, mainBundleIdentifier: "example.app",
                extensionBundleIdentifier: identifier, mainEntitlements: mainValues ?? main,
                extensionEntitlements: extensionValues)
        }
        check(decide().reuseMain, "minimal extension is an experimental candidate")
        check(!decide(strategy: .perExtension).reuseMain, "default does not reuse")
        check(!decide(identifier: "example.application.widget").reuseMain, "prefix boundary")
        check(!decide(identifier: "example.app").reuseMain, "distinct extension identity")
        check(!decide(identifier: "example.app.").reuseMain, "empty suffix")
        check(!decide(mainValues: [:]).reuseMain, "missing main identity")
        var invalidMain = main
        invalidMain["application-identifier"] = "TEAM.other.app"
        check(!decide(mainValues: invalidMain).reuseMain, "main app identity binding")
        check(!decide(["application-identifier": "OLD.other.app.widget"]).reuseMain, "extension identity binding")
        check(decide(["application-identifier": "OLD.example.app.widget"]).reuseMain, "source team can be resigned")
        check(!decide(["aps-environment": "production"]).reuseMain, "required capability never dropped")
        var extraMain = main
        extraMain["aps-environment"] = "production"
        check(!decide(mainValues: extraMain).reuseMain, "extra capability never granted")
        check(decide(["aps-environment": "production"], mainValues: extraMain).reuseMain, "same capability")
        check(!decide(["aps-environment": "development"], mainValues: extraMain).reuseMain, "different capability")
        check(!decide(["keychain-access-groups": ["OLD.example.app.widget"]]).reuseMain, "keychain fallback")
        check(!decide(["com.apple.security.application-groups": ["group.widget"]]).reuseMain, "app group fallback")
        check(!decide(["get-task-allow": false]).reuseMain, "debug requirement mismatch")
        var typedMain = main
        typedMain["custom-capability"] = true
        check(!decide(["custom-capability": 1], mainValues: typedMain).reuseMain, "boolean and integer differ")
        let mismatch = decide(["keychain-access-groups": ["PRIVATE-GROUP"]])
        check(!mismatch.reasons.joined().contains("PRIVATE-GROUP"), "reason codes do not disclose values")
        let trustedRefresh = ExtensionSigningPolicy.evaluate(strategy: .reuseMainWhenCompatible,
            mainBundleIdentifier: "example.app", extensionBundleIdentifier: "example.app.widget",
            mainEntitlements: main, extensionEntitlements: main, allowPreviouslyReusedMainIdentity: true)
        check(trustedRefresh.reuseMain, "trusted previous reuse survives refresh")
        check(!decide(main).reuseMain, "untrusted copied main identity is not accepted")
        var changedRefresh = main
        changedRefresh["aps-environment"] = "production"
        check(!ExtensionSigningPolicy.evaluate(strategy: .reuseMainWhenCompatible,
            mainBundleIdentifier: "example.app", extensionBundleIdentifier: "example.app.widget",
            mainEntitlements: main, extensionEntitlements: changedRefresh,
            allowPreviouslyReusedMainIdentity: true).reuseMain, "changed capabilities invalidate prior reuse")
        check(ExtensionSigningPolicy.evaluate(strategy: .reuseMainWhenCompatible,
            mainBundleIdentifier: "example.app", extensionBundleIdentifier: "example.app.widget",
            mainEntitlements: main, extensionEntitlements: ["application-identifier": "OLD.original.app.widget"],
            originalExtensionBundleIdentifier: "original.app.widget").reuseMain, "explicit original to signed identity mapping")
        check(!ExtensionSigningPolicy.requiredCapabilitiesPreserved(required: ["aps-environment": "production"],
            signed: main, teamIdentifier: "TEAM"), "fallback cannot drop push capability")
        check(!ExtensionSigningPolicy.requiredCapabilitiesPreserved(required: ["com.apple.security.application-groups": ["group.required"]],
            signed: main, teamIdentifier: "TEAM"), "fallback cannot drop app groups")
        print("ReuseMain policy: \(checks) checks passed; device validation is not covered")
    }
}
