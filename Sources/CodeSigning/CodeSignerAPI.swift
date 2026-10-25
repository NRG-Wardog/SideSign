//
//  CodeSignerAPI.swift
//  SideSign
//
//  Created by Magesh K on 30/08/26.
//  Copyright © 2026 SideSign. All rights reserved.
//

import Foundation
import CodeSignKit

public protocol CodeSignerAPI: Sendable {
    var team: Team { get }
    var keyStore: KeyStore { get }

    func signApp(at appURL: URL, provisioningProfiles profiles: [ProvisioningProfile], progress: Progress?) async throws
}

public extension CodeSignerAPI {
    func signApp(at appURL: URL, provisioningProfiles profiles: [ProvisioningProfile]) async throws {
        try await signApp(at: appURL, provisioningProfiles: profiles, progress: nil)
    }
}

public struct AppBundleSigner: CodeSignerAPI, Sendable {
    public let team: Team
    public let keyStore: KeyStore

    private enum SigningTargetType: CustomStringConvertible {
        case mainAppBundleDirectory
        case mainAppExecutable
        case appExtensionBundle(identifier: String)
        case appExtensionExecutable(identifier: String)
        case framework
        case dylib
        case unmatched

        var description: String {
            switch self {
            case .mainAppBundleDirectory:
                return ".mainAppBundleDirectory"
            case .mainAppExecutable:
                return ".mainAppExecutable"
            case .appExtensionBundle(let id):
                return ".appExtensionBundle('\(id)')"
            case .appExtensionExecutable(let id):
                return ".appExtensionExecutable('\(id)')"
            case .framework:
                return ".framework"
            case .dylib:
                return ".dylib"
            case .unmatched:
                return ".unmatched"
            }
        }
    }

    public init(team: Team, keyStore: KeyStore) {
        self.team = team
        self.keyStore = keyStore
    }

    /// Build the exact entitlement map used for signing the main application.
    /// Provisioning preflight must call this same boundary, not compare against
    /// the unfiltered profile and then make a different decision at signing.
    public static func signingEntitlements(profile: ProvisioningProfile,
                                           applicationEntitlements: [String: any Sendable]) throws -> [String: any Sendable] {
        var filteredEntitlements = profile.entitlements
        for (key, _) in filteredEntitlements {
            if let applicationValue = applicationEntitlements[key] {
                if key == "keychain-access-groups" {
                    guard let groups = applicationValue as? [String] else { continue }
                    filteredEntitlements[key] = try groups.map { group in
                        guard let separator = group.firstIndex(of: ".") else {
                            throw SignerError.invalidApp(cause: "A keychain access group is missing its team prefix.")
                        }
                        return profile.teamIdentifier + group[separator...]
                    }
                }
            } else if key != "application-identifier" && key != "com.apple.developer.team-identifier" && key != "get-task-allow" {
                filteredEntitlements.removeValue(forKey: key)
            }
        }
        return filteredEntitlements
    }

    public func signApp(at appURL: URL, provisioningProfiles profiles: [ProvisioningProfile], progress: Progress? = nil) async throws
    {
        _ = try await signApp(at: appURL, provisioningProfiles: profiles,
                              extensionStrategy: .perExtension, progress: progress)
    }

    /// Opt-in experiment. Fallback extensions require their own matching profile;
    /// they never silently inherit the main profile or lose capabilities.
    @discardableResult
    public func signApp(at appURL: URL, provisioningProfiles profiles: [ProvisioningProfile],
                        extensionStrategy: ExtensionSigningStrategy,
                        originalExtensionBundleIdentifiers: [String: String] = [:],
                        previouslyReusedExtensionIdentifiers: Set<String> = [],
                        progress: Progress? = nil) async throws -> [ExtensionSigningDecision]
    {
        debugLog("[SideSign] AppBundleSigner.signApp called")
        verboseLog("[SideSign] URL: \(appURL.path), Profiles: \(profiles.map { "\($0.name) (\($0.bundleIdentifier))" })")

        guard let appBundle = AppBundle(fileURL: appURL) else {
            debugLog("[SideSign] AppBundleSigner.signApp error: Failed to parse AppBundle")
            verboseLog("[SideSign] Path: \(appURL.path)")
            throw SignerError.invalidApp(cause: "Failed to parse AppBundle at \(appURL.path)")
        }

        debugLog("[SideSign] AppBundleSigner.signApp started")
        verboseLog("[SideSign] BundleID: \(appBundle.bundleIdentifier)")

        func profile(for app: AppBundle) -> ProvisioningProfile? {
            for p in profiles where p.bundleIdentifier == app.bundleIdentifier {
                return p
            }
            return profiles.first
        }

        var entitlementsByURL: [URL: String] = [:]

        var decisions = [ExtensionSigningDecision]()
        var mainSigningEntitlements: [String: any Sendable] = [:]
        let mainProfile = profiles.first { $0.bundleIdentifier == appBundle.bundleIdentifier }

        func prepare(_ app: AppBundle, reuseMain: Bool = false) throws {
            verboseLog("[SideSign] AppBundleSigner.prepare started for: \(app.bundleIdentifier)")

            let selectedProfile: ProvisioningProfile?
            if extensionStrategy != .perExtension {
                selectedProfile = reuseMain ? mainProfile : profiles.first { $0.bundleIdentifier == app.bundleIdentifier }
            } else {
                selectedProfile = profile(for: app)
            }
            guard let matchedProfile = selectedProfile else {
                debugLog("[SideSign] AppBundleSigner.prepare error: Missing provisioning profile")
                verboseLog("[SideSign] BundleID: \(app.bundleIdentifier)")
                throw SignerError.missingProvisioningProfile(bundleIdentifier: app.bundleIdentifier)
            }

            if extensionStrategy != .perExtension {
                guard !team.identifier.isEmpty,
                      matchedProfile.teamIdentifier == team.identifier,
                      matchedProfile.entitlements["com.apple.developer.team-identifier"] as? String == team.identifier,
                      matchedProfile.entitlements["application-identifier"] as? String == team.identifier + "." + matchedProfile.bundleIdentifier,
                      keyStore.certificate.organizationalUnit == team.identifier,
                      let signingDER = keyStore.certificate.data, !signingDER.isEmpty,
                      matchedProfile.certificates.contains(where: { $0.data == signingDER }),
                      matchedProfile.expirationDate > Date() else {
                    throw SignerError.invalidApp(cause: "The selected signing profile and certificate do not match the active team, or the profile has expired.")
                }
            }

            var filteredEntitlements = try Self.signingEntitlements(
                profile: matchedProfile, applicationEntitlements: app.entitlements)

            if reuseMain {
                // Reuse the exact main signing entitlement map, not a second
                // extension-specific filtering of the same profile.
                filteredEntitlements = mainSigningEntitlements
            } else if app.fileURL == appBundle.fileURL {
                mainSigningEntitlements = filteredEntitlements
            }

            if extensionStrategy != .perExtension,
               !ExtensionSigningPolicy.requiredCapabilitiesPreserved(required: app.entitlements,
                    signed: filteredEntitlements, teamIdentifier: matchedProfile.teamIdentifier) {
                throw SignerError.invalidApp(cause: "The selected profile cannot preserve all required app or extension capabilities.")
            }

            verboseLog("[SideSign] Filtered entitlements for signing: \(filteredEntitlements)")

            let plist = try PropertyListSerialization.data(
                fromPropertyList: filteredEntitlements,
                format: .xml,
                options: 0
            )

            guard let string = String(data: plist, encoding: .utf8) else {
                debugLog("[SideSign] AppBundleSigner.prepare error: Failed to convert plist data to XML string")
                throw SignerError.unknown(cause: "Failed to convert plist data to XML string")
            }

            verboseLog("[SideSign] Prepared Entitlements XML for \(app.bundleIdentifier):\n\(string)")
            entitlementsByURL[app.fileURL.resolvingSymlinksInPath()] = string

            let profileURL = app.fileURL.appendingPathComponent("embedded.mobileprovision")
            verboseLog("[SideSign] Writing mobileprovision to: \(profileURL.path)")
            try matchedProfile.data.write(to: profileURL)
        }

        do {
            try prepare(appBundle)

            for ext in appBundle.appExtensions {
                verboseLog("[SideSign] Found app extension: \(ext.bundleIdentifier) at \(ext.fileURL.path)")
                var decision = ExtensionSigningPolicy.evaluate(
                    strategy: extensionStrategy,
                    mainBundleIdentifier: appBundle.bundleIdentifier,
                    extensionBundleIdentifier: ext.bundleIdentifier,
                    mainEntitlements: mainSigningEntitlements,
                    extensionEntitlements: ext.entitlements,
                    originalExtensionBundleIdentifier: originalExtensionBundleIdentifiers[ext.bundleIdentifier],
                    allowPreviouslyReusedMainIdentity: previouslyReusedExtensionIdentifiers.contains(ext.bundleIdentifier))
                if decision.reuseMain, (mainProfile?.expirationDate ?? .distantPast) <= Date() {
                    decision = .init(bundleIdentifier: ext.bundleIdentifier, reuseMain: false,
                                     reasons: ["mainProfileExpired"])
                }
                decisions.append(decision)
                try prepare(ext, reuseMain: decision.reuseMain)
            }

            let keyData = try keyStore.exportP12()

            verboseLog("[SideSign] Invoking CodeSigner.sign for appPath: \(appBundle.fileURL.path)")
            try CodeSigner.sign(
                appPath: appBundle.fileURL.path,
                keyData: keyData,
                entitlementProvider: { path in
                    let normPath = path.trimmingCharacters(in: .whitespacesAndNewlines)
                    let appResolved = appBundle.fileURL.resolvingSymlinksInPath()

                    let targetType: SigningTargetType
                    let xml: String

                    if normPath.isEmpty {
                        targetType = .mainAppBundleDirectory
                        xml = entitlementsByURL[appResolved] ?? ""
                    } else {
                        let url: URL = normPath.hasPrefix("/") ? URL(fileURLWithPath: normPath) : appBundle.fileURL.appendingPathComponent(normPath)
                        let resolved = url.resolvingSymlinksInPath()

                        if resolved == appResolved {
                            targetType = .mainAppBundleDirectory
                            xml = entitlementsByURL[appResolved] ?? ""
                        } else if let matchedExt = appBundle.appExtensions.first(where: { ext in
                            let extResolved = ext.fileURL.resolvingSymlinksInPath()
                            return resolved == extResolved ||
                                   resolved.path.hasPrefix(extResolved.path + "/") ||
                                   resolved.lastPathComponent == extResolved.lastPathComponent ||
                                   resolved.deletingPathExtension().lastPathComponent == extResolved.deletingPathExtension().lastPathComponent
                        }) {
                            let extResolved = matchedExt.fileURL.resolvingSymlinksInPath()
                            if resolved == extResolved {
                                targetType = .appExtensionBundle(identifier: matchedExt.bundleIdentifier)
                            } else {
                                targetType = .appExtensionExecutable(identifier: matchedExt.bundleIdentifier)
                            }
                            xml = entitlementsByURL[extResolved] ?? ""
                        } else if resolved.pathExtension.lowercased() == "framework" || resolved.path.contains(".framework") {
                            targetType = .framework
                            xml = ""
                        } else if resolved.pathExtension.lowercased() == "dylib" || resolved.lastPathComponent.hasSuffix(".dylib") {
                            targetType = .dylib
                            xml = ""
                        } else if resolved.deletingLastPathComponent() == appResolved ||
                                  resolved.path.hasPrefix(appResolved.path + "/") {
                            targetType = .mainAppExecutable
                            xml = entitlementsByURL[appResolved] ?? ""
                        } else {
                            targetType = .unmatched
                            xml = ""
                        }
                    }

                    let xmlStatus = xml.isEmpty ? "none" : "present (\(xml.count) bytes)"
                    verboseLog("[SideSign] AppBundleSigner entitlementProvider queried path: '\(path)' [Type: \(targetType)], xml: \(xmlStatus)")
                    return xml
                },
                progress: {
                    progress?.completedUnitCount += 1
                }
            )

            debugLog("[SideSign] AppBundleSigner.signApp completed successfully")
            verboseLog("[SideSign] App URL: \(appURL.path)")
            return decisions
        } catch {
            debugLog("[SideSign] AppBundleSigner.signApp failed with error: \(error)")
            throw error
        }
    }
}
