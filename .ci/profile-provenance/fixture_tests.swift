struct ProfileExportCase: Encodable {
    let name: String
    let auth_header_provenance: String?
    let auth_provider_observation: String?
}
struct ProfileExportBundle: Encodable {
    let schema = "profile-provenance-cases-v1"
    let producer = "actual_hp2_ap1_models_stub_provider_collector"
    let cases: [ProfileExportCase]
}
@main enum Fixture {
    static let fake = "SYNTHETIC_NOT_A_CREDENTIAL"
    static let mac = AnisetteConstants.defaultClientInfo
    static let windows = "<Windows> <com.apple.akd/1>"
    static let android = "<Android> <com.apple.akd/1>"
    static func data() -> AnisetteData {
        AnisetteData(machineID: fake, oneTimePassword: fake, localUserID: fake, routingInfo: fake,
            deviceID: fake, serialNumber: fake, clientInfo: mac, userAgent: fake,
            clientTime: fake, locale: fake, timeZone: fake)
    }
    static func bytes<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = .sortedKeys
        return try encoder.encode(value)
    }
    static func equalBytes<A: Encodable, B: Encodable>(_ a: A, _ b: B) throws {
        let lhs = try bytes(a), rhs = try bytes(b); precondition(lhs == rhs)
    }
    static func snapshot(_ data: AnisetteData, _ portal: DeveloperPortal) -> AuthenticationHeaderProvenance {
        AuthenticationHeaderProvenance(anisetteData: data, grandSlamHeaders: portal.diagnosticCustomHeadersSnapshot())
    }
    static func main() async throws {
        let trace = AuthenticationDiagnosticTrace()
        let cases = try await AuthenticationDiagnosticTrace.$current.withValue(trace) { try await run(trace) }
        if CommandLine.arguments.count > 1 {
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
            try encoder.encode(ProfileExportBundle(cases: cases)).write(
                to: URL(fileURLWithPath: CommandLine.arguments[1]), options: .atomic)
            print("EXPORTED profile_provenance_cases=\(cases.count) actual_hp2_ap1_models_stub_provider_collector")
        }
    }
    static func run(_ trace: AuthenticationDiagnosticTrace) async throws -> [ProfileExportCase] {
        var cases: [ProfileExportCase] = []
        let portal = DeveloperPortal(diagnosticHeaderSource: .defaultValue)
        func append(_ name: String, _ data: AnisetteData?) {
            cases.append(ProfileExportCase(name: name,
                auth_header_provenance: data.map { snapshot($0, portal).encoded },
                auth_provider_observation: trace.providerObservation?.encoded))
        }
        let original = data(), originalBytes = try bytes(data())
        let baseline = try JSONDecoder().decode(BaselineAnisetteData.self, from: originalBytes)
        try equalBytes(original, baseline)
        precondition(original.hashValue == baseline.hashValue)
        let verified = AuthenticationAnisetteContext(cache: .generated, requestedClientInfoFamily: .macAkd,
            generationBlobInput: .present, generationBlobOutput: .notGenerated, adapter: .unicorn,
            librarySelection: .appleMusic4961447Arm64, libraryValidation: .observedVerified,
            clientInfoPreservation: .matched, historicalBlobAssociation: .notRecorded)
        var tagged = original
        for source in [AuthenticationHeaderSource.defaultValue, .userDefaults, .file, .caller, .provider, .unknown] {
            tagged.recordDiagnosticHeaderProvenance(source: source, provider: .localAndroidADI, context: verified)
            precondition(tagged == original && tagged.hashValue == original.hashValue)
            precondition(tagged.toRequestHeaders() == baseline.toRequestHeaders())
            try equalBytes(tagged, baseline)
            let restored = try JSONDecoder().decode(AnisetteData.self, from: bytes(tagged))
            precondition(restored == original && restored.diagnosticHeaderProvenance.source == .unknown)
            precondition(restored.diagnosticHeaderProvenance.provider == .unknown)
            precondition(restored.diagnosticHeaderProvenance.context.cache == .unknown)
            precondition(snapshot(restored, portal).anisette.librarySelection == .unknown)
        }
        tagged.recordDiagnosticHeaderProvenance(source: .file, provider: .localAndroidADI, context: verified)
        let frozen = snapshot(tagged, portal)
        precondition(frozen.clientInfoFamily == .macAkd && frozen.userAgentFamily == .upstreamDefaultAuthKit)
        precondition(frozen.profileRelation == .knownFamilyAgreement)
        precondition(frozen.encoded.utf8.count <= 512)
        precondition(AuthenticationHeaderProvenance(encoded: frozen.encoded)?.encoded == frozen.encoded)
        precondition(frozen.anisette.selectedVerifiedCoreADIHash == AuthenticationAnisetteContext.coreADIHash)
        precondition(frozen.anisette.loadedMapping == .unobserved)
        tagged.clientInfo = windows
        precondition(tagged.diagnosticHeaderProvenance.source == .caller)
        precondition(snapshot(tagged, portal).profileRelation == .mixedKnownFamilies)
        precondition(snapshot(tagged, portal).selectedVersusUsedFamily == .differentFamily)
        precondition(frozen.clientInfoSource == .file && frozen.clientInfoFamily == .macAkd)
        tagged.deviceDescription = android; tagged.userAgent = "MUST_NOT_BE_AUTH_USER_AGENT"
        precondition(snapshot(tagged, portal).clientInfoFamily == .androidAkd)
        precondition(snapshot(tagged, portal).userAgentFamily == .upstreamDefaultAuthKit)
        var alternate = SideSignHeaders(); alternate.grandSlam.userAgent = "AuthKit/1 (Windows; fixture)"
        let alternateHeaders = alternate
        portal.setCustomHeaders(alternateHeaders, diagnosticSource: .file)
        let capturedHeaders = portal.diagnosticCustomHeadersSnapshot()
        portal.customHeaders = SideSignHeaders()
        precondition(capturedHeaders.source == .file && capturedHeaders.headers == alternateHeaders)
        precondition(portal.diagnosticCustomHeadersSnapshot().source == .caller)
        DispatchQueue.concurrentPerform(iterations: 1200) { i in
            switch i % 3 {
            case 0: portal.setCustomHeaders(alternateHeaders, diagnosticSource: .file)
            case 1: portal.setCustomHeaders(SideSignHeaders(), diagnosticSource: .defaultValue)
            default:
                let current = portal.diagnosticCustomHeadersSnapshot()
                if current.source == .file { precondition(current.headers == alternateHeaders) }
                if current.source == .defaultValue { precondition(current.headers == SideSignHeaders()) }
            }
        }
        portal.setCustomHeaders(SideSignHeaders(), diagnosticSource: .defaultValue)
        for ud in [nil, "", "UD"] as [String?] {
            for fileValue in [nil, "", "FILE"] as [String?] {
                let file = fileValue.map { AnisetteConfig(clientInfo: $0, userAgent: "FILE_UA") }
                let chosen = FakeConfigManager.resolve(udClientInfo: ud, fileConfig: file)
                let old = BaselineConfigManager.resolve(udClientInfo: ud, fileConfig: file)
                precondition(chosen.config == old)
                let actual = FakeConfigManager.headers(chosen)
                precondition(actual.headers == BaselineConfigManager.headers(old))
                let expected = (ud?.isEmpty == false ? ud : fileValue) ?? mac
                let source: AuthenticationHeaderSource = expected.isEmpty ? .defaultValue :
                    (ud?.isEmpty == false ? .userDefaults : (file != nil ? .file : .defaultValue))
                precondition(actual.clientInfoSource == source)
            }
        }
        for (age, expected) in [(-1.0, AuthenticationAnisetteContext.CacheAge.unknown),
            (0, .under1s), (0.99, .under1s), (1, .oneTo5s), (4.99, .oneTo5s),
            (5, .fiveTo30s), (29.99, .fiveTo30s), (30, .atLeast30s), (.infinity, .unknown), (.nan, .unknown)] {
            precondition(AuthenticationAnisetteContext.CacheAge.classify(age) == expected)
        }
        let server = URL(string: "https://synthetic.invalid")!
        let identifier = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
        let existing = Data([1, 2, 3])
        let manager = AnisetteDataManager(), oldManager = BaselineManager()
        let input = AnisetteRequestHeaders().with { $0.clientInfo = mac }
        let first = try await manager.fetchAnisetteData(mode: .remote(server: server), identifier: identifier,
            existingAdiBlob: existing, headers: input, diagnosticClientInfoSource: .file)
        let oldFirst = try await oldManager.fetchAnisetteData(mode: .remote(server: server), identifier: identifier,
            existingAdiBlob: existing, headers: input)
        try equalBytes(first.data, oldFirst.data)
        precondition(first.newAdiBlob == oldFirst.newAdiBlob && manager.state.captured == oldManager.state.captured)
        append("remote-fresh", first.data)
        let secondInput = AnisetteRequestHeaders().with { $0.clientInfo = windows }
        let changedMac = "<MacBookPro18,3> <macOS;26.7;25G1> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
        let changedInput = AnisetteRequestHeaders().with { $0.clientInfo = changedMac }
        let second = try await manager.fetchAnisetteData(mode: .remote(server: server), identifier: identifier,
            existingAdiBlob: nil, headers: changedInput, diagnosticClientInfoSource: .userDefaults)
        let oldSecond = try await oldManager.fetchAnisetteData(mode: .remote(server: server), identifier: identifier,
            existingAdiBlob: nil, headers: changedInput)
        try equalBytes(second.data, oldSecond.data)
        precondition(manager.state.calls == 1 && oldManager.state.calls == 1)
        let cached = snapshot(second.data, portal)
        precondition(cached.clientInfoSource == .file && cached.clientInfoFamily == .macAkd)
        precondition(cached.anisette.cache == .cacheHit && cached.anisette.requestedClientInfoFamily == .macAkd)
        precondition(cached.selectedVersusUsedFamily == .sameFamily && cached.anisette.cacheRequestedVersusUsedExact == .different)
        precondition(cached.anisette.generationBlobInput == .present && cached.anisette.adapter == .remote)
        precondition(cached.anisette.historicalBlobAssociation == .notRecorded)
        append("changed-config-cache", second.data)
        precondition(snapshot(first.data, portal).anisette.cache == .generated)
        precondition(snapshot(first.data, portal).anisette.cacheRequestedVersusUsedExact == .unknown)
        let same = try await manager.fetchAnisetteData(mode: .remote(server: server), identifier: identifier, headers: input)
        let oldSame = try await oldManager.fetchAnisetteData(mode: .remote(server: server), identifier: identifier, headers: input)
        try equalBytes(same.data, oldSame.data)
        precondition(snapshot(same.data, portal).anisette.cacheRequestedVersusUsedExact == .same)
        var mutated = same.data; mutated.clientInfo = windows
        let mutation = snapshot(mutated, portal)
        precondition(mutation.selectedVersusUsedFamily == .differentFamily && mutation.anisette.cacheRequestedVersusUsedExact == .same)
        precondition(AuthenticationHeaderProvenance(encoded: mutation.encoded)?.encoded == mutation.encoded)
        precondition(AuthenticationAnisetteContext.ExactEquality.compare("\u{00E9}", "e\u{0301}") == .different)
        let legacyBytes = try bytes(first.data)
        let legacy = try JSONDecoder().decode(AnisetteData.self, from: legacyBytes)
        let oldLegacy = try JSONDecoder().decode(BaselineAnisetteData.self, from: legacyBytes)
        let future = Date().addingTimeInterval(100)
        manager.fixtureReplaceCache(data: legacy, timestamp: future, server: server, identifier: identifier)
        oldManager.fixtureReplaceCache(data: oldLegacy, timestamp: future, server: server, identifier: identifier)
        let legacyHit = try await manager.fetchAnisetteData(mode: .remote(server: server), identifier: identifier, headers: secondInput)
        let oldLegacyHit = try await oldManager.fetchAnisetteData(mode: .remote(server: server), identifier: identifier, headers: secondInput)
        try equalBytes(legacyHit.data, oldLegacyHit.data)
        precondition(manager.state.calls == 1 && oldManager.state.calls == 1)
        let legacySnapshot = snapshot(legacyHit.data, portal)
        precondition(legacySnapshot.clientInfoSource == .unknown && legacySnapshot.provider == .unknown)
        precondition(legacySnapshot.anisette.cache == .cacheHit && legacySnapshot.anisette.cacheAge == .unknown)
        precondition(legacySnapshot.anisette.generationBlobInput == .unknown && legacySnapshot.anisette.adapter == .unknown)
        precondition(legacySnapshot.anisette.librarySelection == .unknown && legacySnapshot.anisette.historicalBlobAssociation == .unknown)
        precondition(legacySnapshot.selectedVersusUsedFamily == .differentFamily && legacySnapshot.anisette.cacheRequestedVersusUsedExact == .different)
        append("legacy-negative-cache", legacyHit.data)
        let oldDate = Date().addingTimeInterval(-31)
        manager.fixtureReplaceCache(data: legacy, timestamp: oldDate, server: server, identifier: identifier)
        oldManager.fixtureReplaceCache(data: oldLegacy, timestamp: oldDate, server: server, identifier: identifier)
        let regenerated = try await manager.fetchAnisetteData(mode: .remote(server: server), identifier: identifier, headers: secondInput)
        let oldRegenerated = try await oldManager.fetchAnisetteData(mode: .remote(server: server), identifier: identifier, headers: secondInput)
        try equalBytes(regenerated.data, oldRegenerated.data)
        precondition(manager.state.calls == 2 && oldManager.state.calls == 2)
        precondition(snapshot(regenerated.data, portal).anisette.cache == .generated)
        for mode in [AnisetteMode.verifiedAppleMusic, .localODA(libsDir: server), .remoteODA(sourceURL: server)] {
            let local = AnisetteDataManager(), oldLocal = BaselineManager()
            local.state.blobOutput = existing; oldLocal.state.blobOutput = existing
            let value = try await local.fetchAnisetteData(mode: mode, identifier: identifier, existingAdiBlob: Data(), headers: input)
            let oldValue = try await oldLocal.fetchAnisetteData(mode: mode, identifier: identifier, existingAdiBlob: Data(), headers: input)
            try equalBytes(value.data, oldValue.data); precondition(value.newAdiBlob == oldValue.newAdiBlob)
            let metadata = snapshot(value.data, portal)
            precondition(metadata.provider == .localAndroidADI && metadata.anisette.adapter == .unicorn)
            precondition(metadata.anisette.generationBlobInput == .absent && metadata.anisette.generationBlobOutput == .generated)
            let caseName: String
            switch mode {
            case .verifiedAppleMusic:
                caseName = "verified-public-library"
                precondition(metadata.anisette.libraryValidation == .observedVerified)
                precondition(metadata.anisette.selectedVerifiedCoreADIHash == AuthenticationAnisetteContext.coreADIHash)
            case .localODA: caseName = "local-custom-library"
            default: caseName = "remote-custom-library"
            }
            if case .verifiedAppleMusic = mode {} else {
                precondition(metadata.anisette.librarySelection == .customOrLocal)
                precondition(metadata.anisette.selectedVerifiedCoreADIHash == "unknown")
            }
            precondition(metadata.anisette.loadedMapping == .unobserved); append(caseName, value.data)
        }
        for adapter in ["unknown", "native"] {
            let local = AnisetteDataManager(); local.state.adapterOverride = adapter
            let value = try await local.fetchAnisetteData(mode: .verifiedAppleMusic, identifier: identifier, headers: input)
            let meta = snapshot(value.data, portal)
            #if os(macOS)
            precondition(meta.anisette.adapter == (adapter == "native" ? .native : .unknown))
            #else
            precondition(meta.anisette.adapter == .unknown)
            #endif
        }
        let altered = AnisetteDataManager(); altered.state.outputOverride = windows
        let alteredResult = try await altered.fetchAnisetteData(mode: .verifiedAppleMusic, identifier: identifier, headers: input)
        precondition(snapshot(alteredResult.data, portal).clientInfoSource == .unknown)
        precondition(snapshot(alteredResult.data, portal).anisette.clientInfoPreservation == .different)
        append("output-mismatch", alteredResult.data)
        let failover = AnisetteDataManager(), oldFailover = BaselineManager()
        failover.state.failCalls = [1]; oldFailover.state.failCalls = [1]
        let servers = [server, URL(string: "https://second.synthetic.invalid")!]
        let result = try await failover.fetchAnisetteDataWithFailover(servers: servers, identifier: identifier, headers: input)
        let oldResult = try await oldFailover.fetchAnisetteDataWithFailover(servers: servers, identifier: identifier, headers: input)
        try equalBytes(result.data, oldResult.data)
        precondition(failover.state.calls == 2 && oldFailover.state.calls == 2); append("failover-return", result.data)
        for boundary in ["setup", "provider", "validation", "cancel"] {
            let failing = AnisetteDataManager()
            switch boundary {
            case "setup": failing.state.setupFails = true
            case "provider": failing.state.failCalls = [1]
            case "validation": failing.state.outputOverride = ""
            default: failing.state.cancelCalls = [1]
            }
            do {
                _ = try await failing.fetchAnisetteData(mode: .verifiedAppleMusic, identifier: identifier, headers: input, diagnosticClientInfoSource: .file)
                preconditionFailure("Expected fake failure")
            } catch {
                if boundary == "cancel" { precondition(error is CancellationError) }
                let observed = trace.providerObservation!
                precondition(observed.mode == .verifiedAppleMusic && observed.requestedClientInfoSource == .file)
                precondition(observed.stage == (boundary == "setup" ? .selected : .clientReady))
                precondition(observed.librarySelection == (boundary == "setup" ? .unknown : .appleMusic4961447Arm64))
                precondition(observed.loadedMapping == .unobserved && observed.requestAssociation == .unobserved)
                precondition(AuthenticationProviderObservation.validatedEncoded(observed.encoded) == observed.encoded)
                append("acquisition-"+boundary, nil)
            }
        }
        for branch in [false, true] {
            let event = AuthenticationProviderObservation.selectedBranch(onDevice: branch)
            precondition(event.mode == (branch ? .onDevice : .remote))
            precondition(event.requestedClientInfoSource == .unknown && event.adapter == .unknown)
            precondition(event.requestedBlobInput == .unknown && event.historicalBlobAssociation == .unknown)
            precondition(event.encoded.utf8.count <= 256)
            precondition(AuthenticationProviderObservation.validatedEncoded(event.encoded) == event.encoded)
            for index in 0..<12 {
                var tokens = event.encoded.split(separator: ";").map(String.init); tokens[index] = "UNTRUSTED_FREEFORM"
                precondition(AuthenticationProviderObservation.validatedEncoded(tokens.joined(separator: ";")) == nil)
            }
        }
        let independentA = AuthenticationDiagnosticTrace(), independentB = AuthenticationDiagnosticTrace()
        async let a: Void = AuthenticationDiagnosticTrace.$current.withValue(independentA) {
            let m = AnisetteDataManager(); _ = try await m.fetchAnisetteData(mode: .remote(server: server), identifier: identifier, headers: input)
        }
        async let b: Void = AuthenticationDiagnosticTrace.$current.withValue(independentB) {
            let m = AnisetteDataManager(); _ = try await m.fetchAnisetteData(mode: .verifiedAppleMusic, identifier: identifier, headers: secondInput)
        }
        _ = try await (a, b)
        precondition(independentA.providerObservation?.mode == .remote && independentA.providerObservation?.requestedClientInfoFamily == .macAkd)
        precondition(independentB.providerObservation?.mode == .verifiedAppleMusic && independentB.providerObservation?.requestedClientInfoFamily == .windows)
        for source in [AuthenticationHeaderSource.defaultValue, .userDefaults, .file, .caller, .provider, .unknown] {
            for family in [mac, windows, android, "OTHER", ""] {
                for ua in [Constants.GrandSlam.userAgent, "AuthKit/1 (Macintosh; fixture)", "AuthKit/1 (Windows; fixture)", "OTHER", ""] {
                    var value = data(); value.clientInfo = family
                    value.recordDiagnosticHeaderProvenance(source: source, provider: .unknown)
                    var selected = SideSignHeaders(); selected.grandSlam.userAgent = ua
                    portal.setCustomHeaders(selected, diagnosticSource: source)
                    let encoded = snapshot(value, portal).encoded
                    precondition(AuthenticationHeaderProvenance(encoded: encoded)?.encoded == encoded)
                    precondition(!encoded.contains(fake) && !encoded.contains("synthetic.invalid"))
                }
            }
        }
        let valid = frozen.encoded
        for i in 0..<22 {
            var tokens = valid.split(separator: ";", omittingEmptySubsequences: false).map(String.init)
            tokens[i] = "UNTRUSTED_TOKEN_ACCOUNT_URL_SECRET"
            precondition(AuthenticationHeaderProvenance(encoded: tokens.joined(separator: ";")) == nil)
        }
        for bad in ["", valid+";extra", valid+"\n", String(repeating: "x", count: 513), valid.replacingOccurrences(of: "hp2;", with: "hp1;")] {
            precondition(AuthenticationHeaderProvenance(encoded: bad) == nil)
        }
        for (index, replacement) in [(6, "mixedKnownFamilies"), (8, "under1s"), (10, "differentFamily"), (15, "notObserved"), (16, "verified"), (19, String(repeating: "a", count: 64)), (21, "same")] {
            var tokens = valid.split(separator: ";").map(String.init); tokens[index] = replacement
            precondition(AuthenticationHeaderProvenance(encoded: tokens.joined(separator: ";")) == nil)
        }
        precondition(AuthenticationHeaderFamily.classify(String(repeating: "x", count: 513)) == .unknown)
        precondition(cases.count == 12)
        print("PASS hp2_profile_provenance: source-owned selection; immutable snapshots; 1200 concurrent snapshot operations; 9 config cases; 150 schema round trips; baseline Codable/hash/request-header equality; actual fetch/cache/failover behavior; legacy/negative-age provenance; finite public library identities; ap1 acquisition failures/TaskLocal isolation; malformed input rejection; fake-only")
        return cases
    }
}
