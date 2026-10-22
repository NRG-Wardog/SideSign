// Diagnostic-only classifications. No raw headers or account state are retained.
import Foundation

public enum AuthenticationHeaderSource: String, Sendable {
    case defaultValue = "default"
    case userDefaults = "UserDefaults"
    case file, caller, provider, unknown
}

public enum AuthenticationHeaderFamily: String, Sendable {
    case macAkd = "Mac-akd"
    case androidAkd = "Android-akd"
    case windows = "Windows"
    case other, unknown

    static func classify(_ value: String) -> Self {
        guard !value.isEmpty, value.utf8.count <= 512 else { return .unknown }
        let lower = value.lowercased()
        if lower.contains("windows") { return .windows }
        if lower.contains("com.apple.akd/") {
            if lower.contains("android") { return .androidAkd }
            if lower.contains("<mac") && (lower.contains("macos") || lower.contains("mac os x")) { return .macAkd }
        }
        // AuthKit's Macintosh User-Agent alone does not establish an akd profile.
        return .other
    }
}

public enum AuthenticationUserAgentFamily: String, Sendable {
    case upstreamDefaultAuthKit, macAuthKit, windowsAuthKit, other, unknown

    static func classify(_ value: String) -> Self {
        guard !value.isEmpty, value.utf8.count <= 512 else { return .unknown }
        if value == Constants.GrandSlam.userAgent { return .upstreamDefaultAuthKit }
        if value.hasPrefix("AuthKit/"), value.contains("(Macintosh;") { return .macAuthKit }
        if value.hasPrefix("AuthKit/"), value.contains("(Windows;") { return .windowsAuthKit }
        return .other
    }
}

public enum AuthenticationProviderMode: String, Sendable {
    case localAndroidADI, remote, unknown
}

public enum AuthenticationProfileRelation: String, Sendable {
    case knownFamilyAgreement, mixedKnownFamilies, unknown

    static func compare(_ client: AuthenticationHeaderFamily, _ agent: AuthenticationUserAgentFamily) -> Self {
        guard client != .unknown, client != .other, agent != .unknown, agent != .other else { return .unknown }
        switch (client, agent) {
        case (.macAkd, .upstreamDefaultAuthKit), (.macAkd, .macAuthKit), (.windows, .windowsAuthKit):
            return .knownFamilyAgreement
        default: return .mixedKnownFamilies
        }
    }
}

public struct AuthenticationAnisetteContext: Sendable {
    public enum Cache: String, Sendable { case generated, cacheHit, unknown }
    public enum CacheAge: String, Sendable {
        case under1s, oneTo5s = "1to5s", fiveTo30s = "5to30s", atLeast30s, unknown
        static func classify(_ age: TimeInterval) -> Self {
            guard age.isFinite, age >= 0 else { return .unknown }
            if age < 1 { return .under1s }
            if age < 5 { return .oneTo5s }
            if age < 30 { return .fiveTo30s }
            return .atLeast30s
        }
    }
    public enum FamilyRelation: String, Sendable {
        case sameFamily, differentFamily, unknown
        static func compare(_ requested: AuthenticationHeaderFamily, _ used: AuthenticationHeaderFamily) -> Self {
            guard requested != .unknown, requested != .other, used != .unknown, used != .other else { return .unknown }
            return requested == used ? .sameFamily : .differentFamily
        }
    }
    public enum ExactEquality: String, Sendable {
        case same, different, unknown
        static func compare(_ requested: String, _ used: String) -> Self {
            requested.utf8.elementsEqual(used.utf8) ? .same : .different
        }
    }
    public enum BlobInput: String, Sendable { case present, absent, unknown }
    public enum BlobOutput: String, Sendable { case generated, notGenerated, unknown }
    public enum Adapter: String, Sendable { case unicorn, native, remote, unknown }
    public enum LibrarySelection: String, Sendable { case appleMusic4961447Arm64, customOrLocal, remote, unknown }
    public enum LibraryValidation: String, Sendable { case observedVerified, notObserved, unknown }
    public enum LoadedMapping: String, Sendable { case unobserved }
    public enum Preservation: String, Sendable { case matched, different, unknown }
    public enum HistoricalAssociation: String, Sendable { case notRecorded, unknown }

    public let cache: Cache
    public let cacheAge: CacheAge
    public let requestedClientInfoFamily: AuthenticationHeaderFamily
    // Observed only at cache return, not recomputed after caller mutation.
    public let cacheRequestedVersusUsedExact: ExactEquality
    // Generation facts remain attached to the used data, including cache hits.
    public let generationBlobInput: BlobInput
    public let generationBlobOutput: BlobOutput
    public let adapter: Adapter
    public let librarySelection: LibrarySelection
    public let libraryValidation: LibraryValidation
    public let loadedMapping: LoadedMapping
    public let clientInfoPreservation: Preservation
    public let historicalBlobAssociation: HistoricalAssociation

    // Trusted public selected-file identities, never arbitrary file hashes and
    // never evidence of the bytes actually mapped by a native loader.
    static let coreADIHash = "9d5b557cf3faf88c34c394ab2cd7fc1a3b4acf3aed51f28cd0bc093858107c22"
    static let storeServicesHash = "bd335e6963ba5ae2f5babca613435ad56d2660a9aee37df35f876c458d105ce4"
    public var selectedVerifiedCoreADIHash: String {
        librarySelection == .appleMusic4961447Arm64 && libraryValidation == .observedVerified ? Self.coreADIHash : "unknown"
    }
    public var selectedVerifiedStoreServicesHash: String {
        librarySelection == .appleMusic4961447Arm64 && libraryValidation == .observedVerified ? Self.storeServicesHash : "unknown"
    }

    init(cache: Cache = .unknown, cacheAge: CacheAge = .unknown,
         requestedClientInfoFamily: AuthenticationHeaderFamily = .unknown,
         cacheRequestedVersusUsedExact: ExactEquality = .unknown,
         generationBlobInput: BlobInput = .unknown, generationBlobOutput: BlobOutput = .unknown,
         adapter: Adapter = .unknown, librarySelection: LibrarySelection = .unknown,
         libraryValidation: LibraryValidation = .unknown, loadedMapping: LoadedMapping = .unobserved,
         clientInfoPreservation: Preservation = .unknown,
         historicalBlobAssociation: HistoricalAssociation = .unknown) {
        self.cache = cache
        self.cacheAge = cacheAge
        self.requestedClientInfoFamily = requestedClientInfoFamily
        self.cacheRequestedVersusUsedExact = cacheRequestedVersusUsedExact
        self.generationBlobInput = generationBlobInput
        self.generationBlobOutput = generationBlobOutput
        self.adapter = adapter
        self.librarySelection = librarySelection
        self.libraryValidation = libraryValidation
        self.loadedMapping = loadedMapping
        self.clientInfoPreservation = clientInfoPreservation
        self.historicalBlobAssociation = historicalBlobAssociation
    }

    func observingCacheHit(age: TimeInterval, requestedClientInfo: String, usedClientInfo: String) -> Self {
        Self(cache: .cacheHit, cacheAge: .classify(age),
             requestedClientInfoFamily: .classify(requestedClientInfo),
             cacheRequestedVersusUsedExact: .compare(requestedClientInfo, usedClientInfo),
             generationBlobInput: generationBlobInput, generationBlobOutput: generationBlobOutput,
             adapter: adapter, librarySelection: librarySelection, libraryValidation: libraryValidation,
             loadedMapping: loadedMapping, clientInfoPreservation: clientInfoPreservation,
             historicalBlobAssociation: historicalBlobAssociation)
    }
}

struct AnisetteHeaderProvenance: Sendable {
    let source: AuthenticationHeaderSource
    let provider: AuthenticationProviderMode
    let context: AuthenticationAnisetteContext
    init(source: AuthenticationHeaderSource = .unknown, provider: AuthenticationProviderMode = .unknown,
         context: AuthenticationAnisetteContext = .init()) {
        self.source = source
        self.provider = provider
        self.context = context
    }
}

struct DiagnosticCustomHeadersSnapshot: Sendable {
    let headers: SideSignHeaders
    let source: AuthenticationHeaderSource
}

public struct AuthenticationHeaderProvenance: Sendable {
    public let provider: AuthenticationProviderMode
    public let clientInfoSource: AuthenticationHeaderSource
    public let clientInfoFamily: AuthenticationHeaderFamily
    public let userAgentSource: AuthenticationHeaderSource
    public let userAgentFamily: AuthenticationUserAgentFamily
    public let anisette: AuthenticationAnisetteContext
    public var profileRelation: AuthenticationProfileRelation { .compare(clientInfoFamily, userAgentFamily) }
    public var selectedVersusUsedFamily: AuthenticationAnisetteContext.FamilyRelation {
        .compare(anisette.requestedClientInfoFamily, clientInfoFamily)
    }

    init(anisetteData: AnisetteData, grandSlamHeaders: DiagnosticCustomHeadersSnapshot) {
        provider = anisetteData.diagnosticHeaderProvenance.provider
        anisette = anisetteData.diagnosticHeaderProvenance.context
        clientInfoSource = anisetteData.diagnosticHeaderProvenance.source
        clientInfoFamily = .classify(anisetteData.clientInfo)
        userAgentSource = grandSlamHeaders.source
        userAgentFamily = .classify(grandSlamHeaders.headers.grandSlam.userAgent)
    }

    public init?(encoded: String) {
        guard encoded.utf8.count <= 512 else { return nil }
        let p = encoded.split(separator: ";", omittingEmptySubsequences: false).map(String.init)
        guard p.count == 22, p[0] == "hp2",
              let provider = AuthenticationProviderMode(rawValue: p[1]),
              let clientSource = AuthenticationHeaderSource(rawValue: p[2]),
              let clientFamily = AuthenticationHeaderFamily(rawValue: p[3]),
              let agentSource = AuthenticationHeaderSource(rawValue: p[4]),
              let agentFamily = AuthenticationUserAgentFamily(rawValue: p[5]),
              let relation = AuthenticationProfileRelation(rawValue: p[6]),
              let cache = AuthenticationAnisetteContext.Cache(rawValue: p[7]),
              let age = AuthenticationAnisetteContext.CacheAge(rawValue: p[8]),
              let requestedFamily = AuthenticationHeaderFamily(rawValue: p[9]),
              let selectedRelation = AuthenticationAnisetteContext.FamilyRelation(rawValue: p[10]),
              let blobInput = AuthenticationAnisetteContext.BlobInput(rawValue: p[11]),
              let blobOutput = AuthenticationAnisetteContext.BlobOutput(rawValue: p[12]),
              let adapter = AuthenticationAnisetteContext.Adapter(rawValue: p[13]),
              let library = AuthenticationAnisetteContext.LibrarySelection(rawValue: p[14]),
              let validation = AuthenticationAnisetteContext.LibraryValidation(rawValue: p[15]),
              let mapping = AuthenticationAnisetteContext.LoadedMapping(rawValue: p[16]),
              let preservation = AuthenticationAnisetteContext.Preservation(rawValue: p[17]),
              let association = AuthenticationAnisetteContext.HistoricalAssociation(rawValue: p[18]),
              let cacheExact = AuthenticationAnisetteContext.ExactEquality(rawValue: p[21]),
              relation == .compare(clientFamily, agentFamily),
              selectedRelation == .compare(requestedFamily, clientFamily),
              cache == .cacheHit || (age == .unknown && cacheExact == .unknown) else { return nil }
        let context = AuthenticationAnisetteContext(cache: cache, cacheAge: age,
            requestedClientInfoFamily: requestedFamily, cacheRequestedVersusUsedExact: cacheExact,
            generationBlobInput: blobInput, generationBlobOutput: blobOutput, adapter: adapter,
            librarySelection: library, libraryValidation: validation, loadedMapping: mapping,
            clientInfoPreservation: preservation, historicalBlobAssociation: association)
        guard (library == .appleMusic4961447Arm64) == (validation == .observedVerified),
              p[19] == context.selectedVerifiedCoreADIHash,
              p[20] == context.selectedVerifiedStoreServicesHash else { return nil }
        self.provider = provider
        self.clientInfoSource = clientSource
        self.clientInfoFamily = clientFamily
        self.userAgentSource = agentSource
        self.userAgentFamily = agentFamily
        self.anisette = context
    }

    // Separate diagnostic wire, never an HTTP header or account field.
    public var encoded: String {
        ["hp2", provider.rawValue, clientInfoSource.rawValue, clientInfoFamily.rawValue,
         userAgentSource.rawValue, userAgentFamily.rawValue, profileRelation.rawValue,
         anisette.cache.rawValue, anisette.cacheAge.rawValue, anisette.requestedClientInfoFamily.rawValue,
         selectedVersusUsedFamily.rawValue, anisette.generationBlobInput.rawValue,
         anisette.generationBlobOutput.rawValue, anisette.adapter.rawValue,
         anisette.librarySelection.rawValue, anisette.libraryValidation.rawValue,
         anisette.loadedMapping.rawValue, anisette.clientInfoPreservation.rawValue,
         anisette.historicalBlobAssociation.rawValue, anisette.selectedVerifiedCoreADIHash,
         anisette.selectedVerifiedStoreServicesHash, anisette.cacheRequestedVersusUsedExact.rawValue].joined(separator: ";")
    }
}

// Latest acquisition event, not an inferred relationship to a retained request.
public struct AuthenticationProviderObservation: Sendable {
    public enum Mode: String, Sendable { case onDevice, remote, verifiedAppleMusic, localODA, remoteODA, unknown }
    public enum Stage: String, Sendable { case selected, clientReady, dataReady, cacheHit }
    public enum RequestAssociation: String, Sendable { case unobserved }
    public let requestAssociation: RequestAssociation = .unobserved
    public let mode: Mode
    public let stage: Stage
    public let requestedClientInfoSource: AuthenticationHeaderSource
    public let requestedClientInfoFamily: AuthenticationHeaderFamily
    public let adapter: AuthenticationAnisetteContext.Adapter
    public let librarySelection: AuthenticationAnisetteContext.LibrarySelection
    public let libraryValidation: AuthenticationAnisetteContext.LibraryValidation
    public let requestedBlobInput: AuthenticationAnisetteContext.BlobInput
    public let historicalBlobAssociation: AuthenticationAnisetteContext.HistoricalAssociation
    public let loadedMapping: AuthenticationAnisetteContext.LoadedMapping

    init(mode: Mode, stage: Stage = .selected,
         requestedClientInfoSource: AuthenticationHeaderSource,
         requestedClientInfoFamily: AuthenticationHeaderFamily,
         adapter: AuthenticationAnisetteContext.Adapter = .unknown,
         librarySelection: AuthenticationAnisetteContext.LibrarySelection = .unknown,
         libraryValidation: AuthenticationAnisetteContext.LibraryValidation = .unknown,
         requestedBlobInput: AuthenticationAnisetteContext.BlobInput,
         historicalBlobAssociation: AuthenticationAnisetteContext.HistoricalAssociation = .notRecorded,
         loadedMapping: AuthenticationAnisetteContext.LoadedMapping = .unobserved) {
        self.mode = mode
        self.stage = stage
        self.requestedClientInfoSource = requestedClientInfoSource
        self.requestedClientInfoFamily = requestedClientInfoFamily
        self.adapter = adapter
        self.librarySelection = librarySelection
        self.libraryValidation = libraryValidation
        self.requestedBlobInput = requestedBlobInput
        self.historicalBlobAssociation = historicalBlobAssociation
        self.loadedMapping = loadedMapping
    }

    func observing(_ stage: Stage, adapter: AuthenticationAnisetteContext.Adapter,
                   library: AuthenticationAnisetteContext.LibrarySelection,
                   validation: AuthenticationAnisetteContext.LibraryValidation) -> Self {
        Self(mode: mode, stage: stage, requestedClientInfoSource: requestedClientInfoSource,
             requestedClientInfoFamily: requestedClientInfoFamily, adapter: adapter,
             librarySelection: library, libraryValidation: validation,
             requestedBlobInput: requestedBlobInput, historicalBlobAssociation: historicalBlobAssociation,
             loadedMapping: loadedMapping)
    }

    public static func selectedBranch(onDevice: Bool) -> Self {
        Self(mode: onDevice ? .onDevice : .remote, requestedClientInfoSource: .unknown,
             requestedClientInfoFamily: .unknown, requestedBlobInput: .unknown,
             historicalBlobAssociation: .unknown)
    }

    public init?(encoded: String) {
        guard encoded.utf8.count <= 256 else { return nil }
        let p = encoded.split(separator: ";", omittingEmptySubsequences: false).map(String.init)
        guard p.count == 12, p[0] == "ap1",
              let mode = Mode(rawValue: p[1]), let stage = Stage(rawValue: p[2]),
              let source = AuthenticationHeaderSource(rawValue: p[3]),
              let family = AuthenticationHeaderFamily(rawValue: p[4]),
              let adapter = AuthenticationAnisetteContext.Adapter(rawValue: p[5]),
              let library = AuthenticationAnisetteContext.LibrarySelection(rawValue: p[6]),
              let validation = AuthenticationAnisetteContext.LibraryValidation(rawValue: p[7]),
              let blobInput = AuthenticationAnisetteContext.BlobInput(rawValue: p[8]),
              let association = AuthenticationAnisetteContext.HistoricalAssociation(rawValue: p[9]),
              let mapping = AuthenticationAnisetteContext.LoadedMapping(rawValue: p[10]),
              p[11] == RequestAssociation.unobserved.rawValue,
              (library == .appleMusic4961447Arm64) == (validation == .observedVerified),
              stage != .selected || (adapter == .unknown && library == .unknown && validation == .unknown)
        else { return nil }
        self.init(mode: mode, stage: stage, requestedClientInfoSource: source,
            requestedClientInfoFamily: family, adapter: adapter, librarySelection: library,
            libraryValidation: validation, requestedBlobInput: blobInput,
            historicalBlobAssociation: association, loadedMapping: mapping)
    }

    public static func validatedEncoded(_ value: String) -> String? { Self(encoded: value)?.encoded }
    public var encoded: String {
        ["ap1", mode.rawValue, stage.rawValue, requestedClientInfoSource.rawValue,
         requestedClientInfoFamily.rawValue, adapter.rawValue, librarySelection.rawValue,
         libraryValidation.rawValue, requestedBlobInput.rawValue,
         historicalBlobAssociation.rawValue, loadedMapping.rawValue, requestAssociation.rawValue].joined(separator: ";")
    }
}
