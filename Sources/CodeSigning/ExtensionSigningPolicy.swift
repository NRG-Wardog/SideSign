import Foundation

/// ReuseMain is experimental and opt-in. Eligibility is a preflight check, not
/// evidence that iOS will install the app or that an extension works on a device.
public enum ExtensionSigningStrategy: String, Sendable, Codable {
    case perExtension
    case perExtensionPreservingCapabilities
    case reuseMainWhenCompatible
}

public struct ExtensionSigningDecision: Sendable, Equatable {
    public let bundleIdentifier: String
    public let reuseMain: Bool
    /// Stable, non-sensitive reason codes. Never include entitlement values.
    public let reasons: [String]
}

/// A small boundary shared by provisioning preflight and the final signer.
/// Callers must provision a separate profile for every fallback decision.
public enum ExtensionSigningPolicy {
    private static let identityKeys: Set<String> = [
        "application-identifier", "com.apple.application-identifier",
        "com.apple.developer.team-identifier", "get-task-allow"
    ]

    public static func evaluate(
        strategy: ExtensionSigningStrategy,
        mainBundleIdentifier: String,
        extensionBundleIdentifier: String,
        mainEntitlements: [String: any Sendable],
        extensionEntitlements: [String: any Sendable],
        originalExtensionBundleIdentifier: String? = nil,
        allowPreviouslyReusedMainIdentity: Bool = false
    ) -> ExtensionSigningDecision {
        func fallback(_ reasons: [String]) -> ExtensionSigningDecision {
            .init(bundleIdentifier: extensionBundleIdentifier, reuseMain: false, reasons: reasons)
        }
        guard strategy == .reuseMainWhenCompatible else { return fallback(["separateProfileRequested"]) }
        guard !mainBundleIdentifier.isEmpty,
              extensionBundleIdentifier.hasPrefix(mainBundleIdentifier + "."),
              extensionBundleIdentifier.count > mainBundleIdentifier.count + 1 else {
            return fallback(["extensionIdentifierOutsideContainer"])
        }
        guard let mainID = mainEntitlements["application-identifier"] as? String,
              let team = mainEntitlements["com.apple.developer.team-identifier"] as? String,
              !team.isEmpty,
              mainID == team + "." + mainBundleIdentifier else {
            return fallback(["mainSigningIdentityUnavailable"])
        }

        let sourceIdentifier = originalExtensionBundleIdentifier ?? extensionBundleIdentifier
        let previousReuseMatches = allowPreviouslyReusedMainIdentity &&
            equal(mainEntitlements, extensionEntitlements)
        var reasons = [String]()
        // The strategy deliberately signs a distinct extension bundle using the
        // main application's identity. Do not rewrite CFBundleIdentifier here.
        // Any declared extension identity must still describe this extension.
        for key in ["application-identifier", "com.apple.application-identifier"] {
            if let value = extensionEntitlements[key] {
                guard let identifier = value as? String,
                      (identifier.hasSuffix("." + sourceIdentifier) && identifier.count > sourceIdentifier.count + 1) ||
                        (previousReuseMatches && identifier == mainID) else {
                    reasons.append("invalidExtensionApplicationIdentifier")
                    continue
                }
            }
        }
        if let value = extensionEntitlements["get-task-allow"],
           !equal(value, mainEntitlements["get-task-allow"]) {
            reasons.append("debugEntitlementMismatch")
        }
        // Require identical capability sets rather than silently removing a
        // required capability or granting the extension an extra main-app one.
        let keys = Set(mainEntitlements.keys).union(extensionEntitlements.keys).subtracting(identityKeys)
        for key in keys.sorted() {
            guard equal(mainEntitlements[key], extensionEntitlements[key]) else {
                switch key {
                case "keychain-access-groups": reasons.append("keychainGroupsMismatch")
                case "com.apple.security.application-groups": reasons.append("appGroupsMismatch")
                default: reasons.append("capabilitiesMismatch")
                }
                continue
            }
        }
        let uniqueReasons = Array(Set(reasons)).sorted()
        return .init(bundleIdentifier: extensionBundleIdentifier,
                     reuseMain: uniqueReasons.isEmpty,
                     reasons: uniqueReasons.isEmpty ? ["compatibleCandidateRequiresDeviceValidation"] : uniqueReasons)
    }

    public static func requiredCapabilitiesPreserved(
        required: [String: any Sendable], signed: [String: any Sendable], teamIdentifier: String
    ) -> Bool {
        for (key, value) in required where !identityKeys.contains(key) {
            if key == "keychain-access-groups", let groups = value as? [String] {
                let normalized = groups.compactMap { group -> String? in
                    guard let dot = group.firstIndex(of: ".") else { return nil }
                    return teamIdentifier + group[dot...]
                }
                guard normalized.count == groups.count, equal(normalized, signed[key]) else { return false }
            } else if !equal(value, signed[key]) { return false }
        }
        return true
    }

    private static func equal(_ lhs: (any Sendable)?, _ rhs: (any Sendable)?) -> Bool {
        guard let lhs, let rhs else { return lhs == nil && rhs == nil }
        // Only valid property-list values are admitted. Avoid String(describing:)
        // comparisons, which can collapse distinct entitlement value types.
        guard PropertyListSerialization.propertyList([lhs], isValidFor: .binary),
              PropertyListSerialization.propertyList([rhs], isValidFor: .binary) else { return false }
        guard let left = try? PropertyListSerialization.data(fromPropertyList: ["value": lhs], format: .xml, options: 0),
              let right = try? PropertyListSerialization.data(fromPropertyList: ["value": rhs], format: .xml, options: 0) else { return false }
        return left == right
    }
}
