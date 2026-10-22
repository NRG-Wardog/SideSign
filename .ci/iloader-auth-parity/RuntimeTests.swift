import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

let syntheticProfile = "<Mac14,5> <macOS;15.5;24F74> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
let syntheticAgent = "akd/1.0 synthetic-fixture"
func fixedAnisette(_ suffix: String = "original") -> AnisetteData {
    AnisetteData(machineID: "synthetic-machine-\(suffix)", oneTimePassword: "synthetic-otp-\(suffix)",
        localUserID: "synthetic-local-user", routingInfo: "17106176", deviceID: "synthetic-device",
        serialNumber: "synthetic-serial", clientInfo: syntheticProfile, userAgent: syntheticAgent,
        clientTime: "2026-01-01T00:00:00Z", locale: "fr_FR", timeZone: "Europe/Paris")
}
func json(_ dictionary: [String: Any]) throws -> Data { try JSONSerialization.data(withJSONObject: dictionary) }
func wrapped(_ fields: [String: any Sendable]) throws -> Data { try plist(["Response": fields]) }
func accepted(_ extra: [String: any Sendable] = [:]) throws -> Data {
    var result = extra
    if result["Status"] == nil { result["Status"] = ["ec": 0] as [String: any Sendable] }
    return try wrapped(result)
}
func initOK() throws -> Data { try accepted(["c": "synthetic-challenge", "s": Data([1]), "i": 2, "B": Data([2]), "sp": "s2k"]) }
func completeOK() throws -> Data { try accepted(["spd": Data([3]), "M2": Data([4])]) }
func tokensOK() throws -> Data { try accepted(["et": Data(repeating: 5, count: 40)]) }
func profileBody(_ profile: String = syntheticProfile, agent: String = syntheticAgent) throws -> Data { try json(["client_info": profile, "user_agent": agent]) }
func headersBody(_ suffix: String = "original") throws -> Data {
    try json(["result": "Headers", "X-Apple-I-MD-M": "synthetic-machine-\(suffix)", "X-Apple-I-MD": "synthetic-otp-\(suffix)", "X-Apple-I-MD-RINFO": "17106176"])
}
func lookupBody() throws -> Data {
    try plist(["urls": ["midStartProvisioning": "https://gsa.apple.com/grandslam/MidService/startMachineProvisioning", "midFinishProvisioning": "https://gsa.apple.com/grandslam/MidService/finishMachineProvisioning", "gsService": Constants.URLs.grandSlamAuth.absoluteString, "trustedDeviceSecondaryAuth": Constants.URLs.trustedDevice.absoluteString, "validateCode": Constants.URLs.grandSlamValidate.absoluteString]])
}
func expectedBaseHeaders(client: String = syntheticProfile, sms: Bool = false) -> [String: String] {
    ["Content-Type": sms ? "application/json" : "text/x-xml-plist", "Accept": sms ? "application/json" : "text/x-xml-plist",
     "X-Mme-Client-Info": client, "User-Agent": syntheticAgent, "X-Xcode-Version": "27.0 (27A5218g)",
     "X-Apple-App-Info": "com.apple.gs.xcode.auth", "Connection": "close"]
}
func expectedCPD(_ data: AnisetteData) -> [String: any Sendable] {
    ["bootstrap": "true", "icscrec": "true", "loc": "en_US", "pbe": "false", "prkgen": "true", "svct": "iCloud",
     "X-Mme-Device-Id": data.deviceID, "X-Apple-I-MD": data.oneTimePassword, "X-Apple-I-MD-M": data.machineID]
}
func canonicalHeaders(_ headers: [String: String]) -> [String: String] {
    Dictionary(uniqueKeysWithValues: headers.map { ($0.key.lowercased(), $0.value) })
}
func expectHeaders(_ request: URLRequest, _ expected: [String: String], _ label: String) throws {
    let actual = canonicalHeaders(request.allHTTPHeaderFields ?? [:])
    let wanted = canonicalHeaders(expected)
    let unexpected = Set(actual.keys).subtracting(wanted.keys).sorted()
    let missing = Set(wanted.keys).subtracting(actual.keys).sorted()
    // Keep the complete comparison, but reveal only differing header names.
    let changed = Set(actual.keys).intersection(wanted.keys).filter { actual[$0] != wanted[$0] }.sorted()
    try expect(actual == wanted, "exact complete header dictionary: \(label); unexpected=\(unexpected); missing=\(missing); changed=\(changed)")
}
func decodedBody(_ request: URLRequest) throws -> [String: Any] {
    guard let body = request.httpBody, let dictionary = try PropertyListSerialization.propertyList(from: body, format: nil) as? [String: Any] else { throw FixtureFailure.assertion("expected plist request body") }
    return dictionary
}
func expectBody(_ request: URLRequest, _ expected: [String: any Sendable], _ label: String) throws {
    let roundtrip = try PropertyListSerialization.propertyList(from: plist(expected), format: nil)
    try expect(exactValue(try decodedBody(request)) == exactValue(roundtrip), "full dictionary and primitive types: \(label)")
}
func expectJSONBody(_ request: URLRequest, _ expected: [String: Any], _ label: String) throws {
    guard let body = request.httpBody else { throw FixtureFailure.assertion("missing JSON body") }
    let actual = try JSONSerialization.jsonObject(with: body)
    let normalized = try JSONSerialization.jsonObject(with: json(expected))
    try expect(exactValue(actual) == exactValue(normalized), "full JSON body and primitive types: \(label)")
}
func expectThrows(_ label: String, _ work: () throws -> Void) throws {
    var rejected = false
    do { try work() } catch let error as FixtureFailure {
        if case .assertion = error { throw error }; rejected = true
    } catch { rejected = true }
    try expect(rejected, label)
}
func expectAsyncThrows(_ label: String, _ work: () async throws -> Void) async throws {
    var rejected = false
    do { try await work() } catch let error as FixtureFailure {
        if case .assertion = error { throw error }; rejected = true
    } catch { rejected = true }
    try expect(rejected, label)
}
final class FixtureClock: @unchecked Sendable {
    private let lock = NSLock()
    private var seconds: TimeInterval = 0
    func set(_ value: TimeInterval) { lock.withLock { seconds = value } }
    func now() -> Date { lock.withLock { Date(timeIntervalSince1970: seconds) } }
}
actor FetchScript {
    private var values: [AnisetteData]
    private var observed: [String?] = []
    init(_ values: [AnisetteData]) { self.values = values }
    func fetch(_ sim: String?) throws -> AnisetteData {
        observed.append(sim)
        guard !values.isEmpty else { throw FixtureFailure.unscripted }
        return values.removeFirst()
    }
    func calls() -> [String?] { observed }
}
func profile() -> ILoaderRemoteProfile { .init(endpoint: .macJkcoxson, clientInfo: syntheticProfile, userAgent: syntheticAgent) }
func state(blob: String? = Data([31,32,33]).base64EncodedString()) -> ILoaderRemoteState {
    .init(profile: profile(), identity: Data((0..<16).map(UInt8.init)), adiPB: blob)
}
func socket() -> FakeWebSocketTask {
    FakeWebSocketTask([["result":"GiveIdentifier"], ["result":"GiveStartProvisioningData"], ["result":"GiveEndProvisioningData", "cpim":"synthetic-cpim"], ["result":"ProvisioningSuccess", "adi_pb":Data([31,32,33]).base64EncodedString()]])
}
func provisionSteps(includeFactoryProfile: Bool = false, suffix: String = "original") throws -> [Step] {
    var steps = [Step(body: try profileBody())]
    if includeFactoryProfile { steps.append(Step(body: try profileBody())) }
    steps += [Step(body: try lookupBody()), Step(body: try wrapped(["spim":"synthetic-spim"])), Step(body: try wrapped(["ptm":"synthetic-ptm", "tk":"synthetic-tk"])), Step(body: try headersBody(suffix))]
    return steps
}
func requireSessionSecurity(_ script: TransportScript) throws {
    try expect(!script.sessionConfigurations.isEmpty, "source transport configured")
    for config in script.sessionConfigurations {
        try expect(config.urlCache == nil && config.httpCookieStorage == nil && !config.httpShouldSetCookies, "ephemeral no cache/cookies")
        try expect(config.requestCachePolicy == .reloadIgnoringLocalCacheData && config.timeoutIntervalForRequest == 30 && config.timeoutIntervalForResource == 60, "bounded transport policy")
    }
}

func testPolicy(_ rows: inout [String]) throws {
    let data = fixedAnisette()
    try expect(exactValue(ILoaderAuthenticationPolicy.clientDictionary(data)) == exactValue(expectedCPD(data)), "exact minimal string CPD")
    try expect(ILoaderAuthenticationPolicy.clientDictionary(data).count == 9, "exact nine CPD keys")
    try expect(ILoaderAuthenticationPolicy.baseHeaders(clientInfo: syntheticProfile, userAgent: syntheticAgent) == expectedBaseHeaders(), "exact auth base headers")
    for sms in [false, true] {
        var headers = expectedBaseHeaders(sms: sms)
        headers["X-Mme-Device-Id"] = data.deviceID; headers["X-Apple-I-MD"] = data.oneTimePassword
        headers["X-Apple-I-MD-M"] = data.machineID; headers["X-Apple-I-MD-RINFO"] = data.routingInfo
        headers["X-Apple-Identity-Token"] = Data("synthetic-dsid:synthetic-idms".utf8).base64EncodedString()
        try expect(ILoaderAuthenticationPolicy.twoFactorHeaders(data, dsid: "synthetic-dsid", token: "synthetic-idms", sms: sms) == headers, "exact 2FA headers")
    }
    let simValues: [any Sendable] = ["synthetic-sim", Data([1,2,3])]
    for value in simValues {
        let status: [String: any Sendable] = ["hsc":434,"X-Apple-I-MD-DATA":value]
        try expect(ILoaderAuthenticationPolicy.resyncSIM(["Status":status]) == (value as? String ?? Data([1,2,3]).base64EncodedString()), "434 SIM String/Data")
    }
    let invalidStatuses: [any Sendable] = [true, "434", 434.0, 433, 435]
    for invalid in invalidStatuses {
        let status: [String: any Sendable] = ["hsc":invalid,"X-Apple-I-MD-DATA":"synthetic-sim"]
        try expect(ILoaderAuthenticationPolicy.resyncSIM(["Status":status]) == nil, "reject non434 status")
    }
    rows.append("exact-policy-primitives-headers-sim")
}

func testBuilders(_ rows: inout [String]) throws {
    let state = state()
    try expect(state.identifier == "AAECAwQFBgcICQoLDA0ODw==" && state.deviceID == "00010203-0405-0607-0809-0a0b0c0d0e0f", "identity bytes map to base64 and UUID without bit rewriting")
    try expect(state.localUserID == (0..<32).map { String(format:"%02x",$0) }.joined(), "owned SHA boundary result consumed as lowercase hex")
    try expect(try state.headerRequestBody(sim: nil) == ["identifier":state.identifier,"adi_pb":"HyAh"], "exact regular header acquisition body")
    try expect(try state.headerRequestBody(sim: "synthetic-sim") == ["identifier":state.identifier,"adi_pb":"HyAh","sim":"synthetic-sim","device_id":state.deviceID,"md_lu":state.localUserID], "exact resync acquisition body")
    let lookup = try ILoaderRemoteAnisetteClient.makeAppleRequest(role:"lookup",profile:profile(),state:nil)
    try expect(lookup.url?.absoluteString == "https://gsa.apple.com/grandslam/GsService2/lookup" && lookup.httpMethod == "GET" && lookup.httpBody == nil, "lookup URL method body")
    try expectHeaders(lookup, expectedBaseHeaders(client:"<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"), "lookup distinct Mac profile")
    for role in ["start", "finish"] {
        let request = try ILoaderRemoteAnisetteClient.makeAppleRequest(role:role,profile:profile(),state:state,cpim:"synthetic-cpim")
        var headers = expectedBaseHeaders(); headers["X-Apple-I-MD-LU"] = state.localUserID; headers["X-Mme-Device-Id"] = state.deviceID
        try expectHeaders(request,headers,"\(role) provider profile")
        let payload: [String:any Sendable] = role == "finish" ? ["cpim":"synthetic-cpim"] : [:]
        try expectBody(request,["Header":[:] as [String:any Sendable],"Request":payload],role)
        try expect(request.httpMethod == "POST" && request.url?.absoluteString == "https://gsa.apple.com/grandslam/MidService/\(role == "start" ? "start" : "finish")MachineProvisioning", "exact provisioning endpoint")
    }
    rows.append("production-builders-full-wire-shape")
}

func testStrictParsers(_ rows: inout [String]) throws {
    let decoded = try ILoaderRemoteAnisetteClient.decodeProfile(profileBody(),endpoint:.macJkcoxson)
    try expect(decoded == profile(), "metadata preserved, not replaced with fallback")
    for invalid in ["<Pixel 7> <Android;14;x> <com.apple.AuthKit/1 (com.apple.akd/1.0)>", "<PC> <Windows;10;x> <com.apple.akd/1.0>", "", syntheticProfile+"\r\nunsafe"] {
        try expectThrows("nonMac/malformed metadata rejected") { _ = try ILoaderRemoteAnisetteClient.decodeProfile(profileBody(invalid),endpoint:.macJkcoxson) }
    }
    try expectThrows("missing metadata rejected") { _ = try ILoaderRemoteAnisetteClient.decodeProfile(json(["client_info":syntheticProfile]),endpoint:.macJkcoxson) }
    try expectThrows("empty user agent rejected") { _ = try ILoaderRemoteAnisetteClient.decodeProfile(profileBody(agent:""),endpoint:.macJkcoxson) }
    let headers = try ILoaderRemoteAnisetteClient.decodeHeaders(headersBody())
    try expect(headers.mid == fixedAnisette().machineID && headers.otp == fixedAnisette().oneTimePassword && headers.routing == "17106176", "header values preserved")
    let invalidHeaderPayloads: [[String:Any]] = [["result":"GetHeadersError","message":"-45061"],["result":"Headers","X-Apple-I-MD-M":"x","X-Apple-I-MD":"y","X-Apple-I-MD-RINFO":17106176],["result":"Headers","X-Apple-I-MD-M":"x","X-Apple-I-MD":"y","X-Apple-I-MD-RINFO":"bad"]]
    for payload in invalidHeaderPayloads {
        try expectThrows("invalid provider response no reinterpretation") { _ = try ILoaderRemoteAnisetteClient.decodeHeaders(json(payload)) }
    }
    try ILoaderRemoteAnisetteClient.validateLookup(lookupBody())
    try expectThrows("unapproved URL-bag destination rejected") { try ILoaderRemoteAnisetteClient.validateLookup(plist(["urls":["midStartProvisioning":"https://not-approved.invalid/start","midFinishProvisioning":"https://gsa.apple.com/grandslam/MidService/finishMachineProvisioning"]])) }
    try expectThrows("missing Response rejected") { _ = try ILoaderRemoteAnisetteClient.plistResponse(plist(["spim":"synthetic-spim"])) }
    rows.append("strict-provider-parsers-no-profile-fallback")
}

func testCache(_ rows: inout [String]) async throws {
    let clock = FixtureClock(); let fetcher = FetchScript([fixedAnisette("first"),fixedAnisette("expired"),fixedAnisette("reversed"),fixedAnisette("resynced")])
    let context = ILoaderRemoteAuthenticationContext(now:{clock.now()},fetcher:{try await fetcher.fetch($0)})
    let first = try await context.fetch()
    for time in [0.0,59,60,60.999] { clock.set(time); let cached = try await context.fetch(); try expect(cached == first,"whole-second TTL stays valid through 60.x") }
    clock.set(61); let expired = try await context.fetch(); try expect(expired == fixedAnisette("expired"),"61-second TTL expires")
    clock.set(60); let reversed = try await context.fetch(); try expect(reversed == fixedAnisette("reversed"),"clock reversal expires")
    let resynced = try await context.resynchronize(sim:"synthetic-sim"); try expect(resynced == fixedAnisette("resynced"),"resync refreshes cache")
    let resyncCached = try await context.fetch(); try expect(resyncCached == fixedAnisette("resynced"),"resync result cached")
    try await expectAsyncThrows("one resync only") { _ = try await context.resynchronize(sim:"again") }
    let calls = await fetcher.calls(); try expect(calls.count == 4 && calls[3] == "synthetic-sim","no hidden acquisitions")
    context.invalidate()
    try await expectAsyncThrows("invalidated context cannot reacquire") { _ = try await context.fetch() }
    rows.append("context-ttl60-whole-seconds-clock-reversal-one-resync-invalidation")
}

func testProviderLifecycle(_ rows: inout [String]) async throws {
    let ws = socket(); let script = TransportScript(try provisionSteps(),sockets:[ws])
    try await SyntheticTransport.$current.withValue(script) {
        let client = ILoaderRemoteAnisetteClient()
        let (result, updated) = try await client.fetch(state:state(blob:nil))
        try expect(result.machineID == fixedAnisette().machineID && updated.adiPB == "HyAh","actual provider acquisition")
        let requests = script.requests
        try expect(requests.count == 5 && requests[0].url?.absoluteString == "https://mac-ani.jkcoxson.com/v3/client_info","metadata stage first")
        try expect(requests[0].httpMethod == "GET" && requests[0].httpBody == nil,"metadata request body/method")
        try expectJSONBody(requests[4],["identifier":"AAECAwQFBgcICQoLDA0ODw==","adi_pb":"HyAh"],"get_headers")
        try expect(requests[4].httpMethod == "POST" && requests[4].url?.absoluteString == "https://mac-ani.jkcoxson.com/v3/get_headers","get_headers destination")
        try expectHeaders(requests[4],["Content-Type":"application/json"],"get_headers minimal HTTP headers")
        try expect(script.websocketURLs.map(\.absoluteString) == ["wss://mac-ani.jkcoxson.com/v3/provisioning_session"],"only approved websocket destination")
        let expected = [["identifier":"AAECAwQFBgcICQoLDA0ODw=="],["spim":"synthetic-spim"],["ptm":"synthetic-ptm","tk":"synthetic-tk"]]
        try expect(ws.sent.count == expected.count && ws.cancels == 1,"exact socket count and completion close")
        for (message, body) in zip(ws.sent,expected) {
            guard case .string(let text) = message else { throw FixtureFailure.assertion("text websocket frame") }
            try expect(exactValue(try JSONSerialization.jsonObject(with:Data(text.utf8))) == exactValue(body),"exact websocket stage body")
        }
        try requireSessionSecurity(script)
    }
    let currentProfile = syntheticProfile.replacingOccurrences(of:"15.5",with:"15.6")
    let changed = TransportScript([Step(body:try profileBody(currentProfile)),Step(body:try headersBody())])
    try await SyntheticTransport.$current.withValue(changed) {
        let client = ILoaderRemoteAnisetteClient()
        let retained = state()
        let (result, updated) = try await client.fetch(state:retained)
        try expect(result.clientInfo == currentProfile && updated.profile.clientInfo == currentProfile,"compatible current Mac profile is adopted")
        try expect(updated.identity == retained.identity && updated.adiPB == retained.adiPB,"compatible profile retains installation identity and registration")
        try expect(changed.requests.count == 2 && changed.websocketURLs.isEmpty,"no profile fallback or reprovision")
        try expectJSONBody(changed.requests[1],["identifier":"AAECAwQFBgcICQoLDA0ODw==","adi_pb":"HyAh"],"profile update reuses get_headers identity")
    }
    let error = TransportScript([Step(body:try profileBody()),Step(body:try json(["result":"GetHeadersError","message":"-45061"]))])
    try await SyntheticTransport.$current.withValue(error) {
        let client = ILoaderRemoteAnisetteClient()
        try await expectAsyncThrows("provider -45061 rejected without silent reprovision") { _ = try await client.fetch(state:state()) }
        try expect(error.requests.count == 2 && error.websocketURLs.isEmpty,"no provider fallback or retry")
    }
    rows.append("actual-provider-metadata-provisioning-headers-no-fallback")
}

func testFactoryLifecycle(_ rows: inout [String]) async throws {
    let script = TransportScript(try provisionSteps(includeFactoryProfile:true) + [Step(body:try profileBody()),Step(body:try headersBody("resync"))] + provisionSteps(includeFactoryProfile:true),sockets:[socket(),socket()])
    try await SyntheticTransport.$current.withValue(script) {
        let first = try makeILoaderRemoteAuthenticationContext()
        let original = try await first.fetch()
        let cached = try await first.fetch()
        try expect(original == cached && script.requests.count == 6,"same actual factory context caches identity/blob")
        let resynced = try await first.resynchronize(sim:"synthetic-sim")
        let firstBody = try JSONSerialization.jsonObject(with:script.requests[5].httpBody!) as! [String:String]
        let nextBody = try JSONSerialization.jsonObject(with:script.requests[7].httpBody!) as! [String:String]
        try expect(firstBody["identifier"] == nextBody["identifier"] && firstBody["adi_pb"] == nextBody["adi_pb"],"same factory resync reuses identity and blob")
        try expect(nextBody["sim"] == "synthetic-sim" && nextBody["device_id"] == original.deviceID && nextBody["md_lu"] == original.localUserID,"factory resync fields")
        try expect(resynced.oneTimePassword == "synthetic-otp-resync","factory commits valid current data")
        let second = try makeILoaderRemoteAuthenticationContext()
        let fresh = try await second.fetch()
        try expect(fresh.deviceID != original.deviceID,"new factory attempt has fresh identity")
        let count = script.requests.count; let cancels = script.cancelCount
        first.invalidate(); first.invalidate()
        try await expectAsyncThrows("factory invalidation blocks all further acquisition") { _ = try await first.fetch() }
        try expect(script.requests.count == count && script.cancelCount >= cancels+2,"factory cancel closes provider and auth transports without fallback")
    }
    rows.append("actual-factory-identity-cache-resync-revocation")

    var failedSteps = try provisionSteps(includeFactoryProfile:true)
    failedSteps[failedSteps.count-1] = Step(body:try json(["result":"GetHeadersError","message":"synthetic failure"]))
    let failed = TransportScript(failedSteps + (try provisionSteps()),sockets:[socket(),socket()])
    try await SyntheticTransport.$current.withValue(failed) {
        let context = try makeILoaderRemoteAuthenticationContext()
        try await expectAsyncThrows("failed fetch not cached") { _ = try await context.fetch() }
        _ = try await context.fetch()
        try expect(failed.websocketURLs.count == 2,"failed acquisition did not commit provisioning blob")
        let firstBody = try JSONSerialization.jsonObject(with:failed.requests[5].httpBody!) as! [String:String]
        let retriedBody = try JSONSerialization.jsonObject(with:failed.requests[10].httpBody!) as! [String:String]
        try expect(firstBody["identifier"] == retriedBody["identifier"],"retry retains only attempt identity")
    }
    rows.append("actual-factory-failed-fetch-does-not-commit-blob")

    let entered = SyntheticLatch(), release = SyntheticLatch()
    var steps = try provisionSteps(includeFactoryProfile:true)
    steps[0].entered = entered; steps[0].release = release
    let interleaved = TransportScript(steps,sockets:[socket()])
    try await SyntheticTransport.$current.withValue(interleaved) {
        let context = try makeILoaderRemoteAuthenticationContext()
        let task = Task { try await context.fetch() }
        await entered.wait()
        try await expectAsyncThrows("reentrant factory acquisition rejected") { _ = try await context.fetch() }
        task.cancel(); context.invalidate(); await release.signal()
        try await expectAsyncThrows("cancelled acquisition never commits state") { _ = try await task.value }
        try expect(interleaved.requests.count == 1 && interleaved.websocketURLs.isEmpty,"cancellation produces no fallback/provisioning")
    }
    rows.append("actual-factory-reentrant-and-cancellation-boundaries")
}

func runAuthentication(_ script: TransportScript, context: ILoaderRemoteAuthenticationContext,
                       handler: DeveloperPortal.VerificationHandler? = nil) async throws -> AuthSession {
    try await SyntheticTransport.$current.withValue(script) {
        try await observed {
            try await ILoaderRemoteAuthentication.$current.withValue(context) {
                try await DeveloperPortal(session:FakeSession([])).authenticate(appleID:" Synthetic@Example.invalid ",password:"synthetic-password",anisetteData:fixedAnisette("ignored"),xcodeVersion:"synthetic-xcode",verificationHandler:handler)
            }
        }
    }
}
func testAuthResync(_ rows: inout [String]) async throws {
    let status: [String:any Sendable] = ["ec":-80045,"hsc":434,"X-Apple-I-MD-DATA":Data([1,2,3])]
    let script = TransportScript([Step(body:try accepted(["Status":status])),Step(body:try initOK()),Step(body:try completeOK()),Step(body:try tokensOK())])
    let fetcher = FetchScript([fixedAnisette(),fixedAnisette("resync")])
    try await SyntheticTransport.$current.withValue(script) {
        let context = ILoaderRemoteAuthenticationContext(fetcher:{try await fetcher.fetch($0)})
        let result = try await runAuthentication(script,context:context)
        try expect(result.session.authToken == "synthetic-auth-token","resync reaches token")
        let calls = await fetcher.calls()
        try expect(calls.count == 2 && calls[0] == nil && calls[1] == "AQID","434 resync before EC rejection, only one acquisition")
        let requests = script.requests
        try expect(requests.count == 4,"exact init,resync,complete,apptokens count")
        for request in requests { try expectHeaders(request,expectedBaseHeaders(),"auth phase"); try expect(request.url == Constants.URLs.grandSlamAuth && request.httpMethod == "POST","auth fixed endpoint") }
        let header: [String:any Sendable] = ["Version":"1.0.1"]
        for (index,data) in [(0,fixedAnisette()),(1,fixedAnisette("resync"))] {
            try expectBody(requests[index],["Header":header,"Request":["A2k":Data([1,2,3,4]),"cpd":expectedCPD(data),"ps":["s2k","s2k_fo"],"o":"init","u":"synthetic@example.invalid"] as [String:any Sendable]],"init \(index) same A2k")
        }
        try expectBody(requests[2],["Header":header,"Request":["c":"synthetic-challenge","cpd":expectedCPD(fixedAnisette()),"M1":Data([5,6]),"o":"complete","u":"synthetic@example.invalid"] as [String:any Sendable]],"complete ORIGINAL CPD")
        try expectBody(requests[3],["Header":header,"Request":["app":["com.apple.gs.xcode.auth"],"c":Data([3,4]),"checksum":Data([13,14]),"cpd":expectedCPD(fixedAnisette("resync")),"o":"apptokens","t":"synthetic-idms","u":"synthetic-dsid"] as [String:any Sendable]],"apptokens current CPD")
    }
    rows.append("auth-434-once-same-a2k-original-complete-cpd-full-bodies")
    for (name,responses,expectedRequests,expectedFetches) in [
        ("repeated434",[try accepted(["Status":status]),try accepted(["Status":status])],2,2),
        ("error80045",[try accepted(["Status":["ec":-80045,"hsc":409] as [String:any Sendable]])],1,1),
        ("missingSIM",[try accepted(["Status":["ec":0,"hsc":434] as [String:any Sendable]])],1,1),
        ("jsonFallback",[Data("{\"Response\":{\"Status\":{\"ec\":0}}}".utf8)],1,1),
        ("topLevelFallback",[try plist(["Status":["ec":0] as [String:any Sendable]])],1,1)
    ] {
        let transport = TransportScript(responses.map{Step(body:$0)}); let provider = FetchScript([fixedAnisette(),fixedAnisette("resync")])
        try await SyntheticTransport.$current.withValue(transport) {
            let context = ILoaderRemoteAuthenticationContext(fetcher:{try await provider.fetch($0)})
            try await expectAsyncThrows(name) { _ = try await runAuthentication(transport,context:context) }
            let calls = await provider.calls()
            try expect(transport.requests.count == expectedRequests && calls.count == expectedFetches,"\(name) no retry or fallback")
        }
        rows.append("auth-negative-"+name)
    }
}

func expectedTwoFactorHeaders(_ data: AnisetteData, sms: Bool) -> [String:String] {
    var headers = expectedBaseHeaders(sms:sms)
    headers["X-Mme-Device-Id"] = data.deviceID; headers["X-Apple-I-MD"] = data.oneTimePassword
    headers["X-Apple-I-MD-M"] = data.machineID; headers["X-Apple-I-MD-RINFO"] = data.routingInfo
    headers["X-Apple-Identity-Token"] = Data("synthetic-dsid:synthetic-idms".utf8).base64EncodedString()
    return headers
}
func testStageFreshness(_ rows: inout [String]) async throws {
    let clock = FixtureClock()
    let script = TransportScript([Step(body:try initOK()),Step(body:try completeOK(),onResponse:{clock.set(61)}),Step(body:try tokensOK())])
    let provider = FetchScript([fixedAnisette(),fixedAnisette("token-fresh")])
    try await SyntheticTransport.$current.withValue(script) {
        let context = ILoaderRemoteAuthenticationContext(now:{clock.now()},fetcher:{try await provider.fetch($0)})
        let result = try await runAuthentication(script,context:context)
        let body = try decodedBody(script.requests[2])["Request"] as! [String:Any]
        try expect(exactValue(body["cpd"]!) == exactValue(expectedCPD(fixedAnisette("token-fresh"))),"actual apptokens reacquires expired data")
        try expect(result.session.anisetteData == fixedAnisette("token-fresh"),"returned session uses token-stage acquisition")
        let calls = await provider.calls(); try expect(calls.count == 2,"only token-stage needed fresh fetch")
    }
    rows.append("actual-apptokens-stage-refresh-after61s")
    for operation in 0..<4 {
        let transport = TransportScript([Step(body:try plist(["Status":["ec":0] as [String:any Sendable]]))])
        let clock = FixtureClock(); let provider = FetchScript([fixedAnisette(),fixedAnisette("2fa-fresh")])
        try await SyntheticTransport.$current.withValue(transport) {
            let context = ILoaderRemoteAuthenticationContext(now:{clock.now()},fetcher:{try await provider.fetch($0)})
            _ = try await context.fetch(); clock.set(61)
            _ = try await runProbe(context,operation)
            let requests = transport.requests; try expect(requests.count == 1,"2FA request count")
            var headers = expectedTwoFactorHeaders(fixedAnisette("2fa-fresh"),sms:operation == 1 || operation == 3)
            if operation == 2 { headers["security-code"] = "123456" }
            try expectHeaders(requests[0],headers,"fresh 2FA operation \(operation)")
            let expectedURLs = [Constants.URLs.trustedDevice.absoluteString,"https://gsa.apple.com/auth/verify/phone",Constants.URLs.grandSlamValidate.absoluteString,"https://gsa.apple.com/auth/verify/phone/securitycode"]
            let methods = ["GET","PUT","GET","POST"]
            try expect(requests[0].url?.absoluteString == expectedURLs[operation] && requests[0].httpMethod == methods[operation],"exact 2FA URL/method")
            if operation == 1 { try expectJSONBody(requests[0],["phoneNumber":["id":1],"mode":"sms"],"SMS request integer id") }
            if operation == 3 { try expectJSONBody(requests[0],["phoneNumber":["id":1],"mode":"sms","securityCode":["code":"123456"]],"SMS verify integer id/string code") }
            if operation == 0 || operation == 2 { try expect(requests[0].httpBody == nil,"trusted requests body absent") }
            let calls = await provider.calls(); try expect(calls.count == 2,"2FA acquisition refreshed once")
        }
        rows.append("actual-2fa-stage-refresh-\(operation)")
    }
}
func testTrustedVerification(_ rows: inout [String]) async throws {
    let vectors: [(String,Data,String?)] = [
        ("nestedWins",try plist(["Status":["ec":-21669] as [String:any Sendable],"ec":0]),"retry:incorrectCode"),
        ("nestedMissingECWins",try plist(["Status":[:] as [String:any Sendable],"ec":-21669]),"success"),
        ("topLevel",try plist(["ec":-21669]),"retry:incorrectCode"),
        ("JSON200",Data("{\"ec\":0}".utf8),nil),
        ("malformed200",Data("not-a-plist".utf8),nil)
    ]
    for (name,body,wanted) in vectors {
        let script = TransportScript([Step(body:body)])
        try await SyntheticTransport.$current.withValue(script) {
            let context = ILoaderRemoteAuthenticationContext(fetcher:{_ in fixedAnisette()})
            if let wanted {
                let actual = try await runProbe(context,2)
                try expect(actual == wanted,"nested Status precedence: \(name)")
            } else {
                try await expectAsyncThrows(name) { _ = try await runProbe(context,2) }
            }
            try expect(script.requests.count == 1,"trusted validation no unrequested retry")
        }
        rows.append("trusted-validation-"+name)
    }
}
func testSMSClassifier(_ rows: inout [String]) throws {
    let active: [String:Any] = ["mode":"sms","type":"verification","authenticationType":"hsa2","trustedPhoneNumber":["id":1,"numberWithDialCode":"synthetic-number","lastTwoDigits":"00","pushMode":"sms"],"trustedPhoneNumbers":[["id":1,"numberWithDialCode":"synthetic-number","lastTwoDigits":"00","pushMode":"sms"]],"securityCode":["length":6,"tooManyCodesSent":false,"tooManyCodesValidated":false,"securityCodeLocked":false,"securityCodeCooldown":false]]
    try expect(ILoaderAuthenticationPolicy.classifySMS(status:412,data:try json(active),phoneID:1,verifying:false) == .accepted,"exact valid 412 active challenge")
    for key in ["tooManyCodesSent","tooManyCodesValidated","securityCodeLocked","securityCodeCooldown","length"] {
        var invalid = active; var security = active["securityCode"] as! [String:Any]; security[key] = key == "length" ? 7 : true; invalid["securityCode"] = security
        try expect(ILoaderAuthenticationPolicy.classifySMS(status:412,data:try json(invalid),phoneID:1,verifying:false) == .rejected(nil),"412 security gate \(key)")
    }
    let wrongIDs: [Any] = [true,"1",1.5,2]
    for wrongID in wrongIDs {
        var invalid = active; invalid["trustedPhoneNumber"] = ["id":wrongID]
        try expect(ILoaderAuthenticationPolicy.classifySMS(status:412,data:try json(invalid),phoneID:1,verifying:false) == .rejected(nil),"412 exact id primitive")
    }
    let wrongCode = try json(["serviceErrors":[["code":"-21669","title":"synthetic","message":"synthetic"]]])
    try expect(ILoaderAuthenticationPolicy.classifySMS(status:400,data:wrongCode,phoneID:1,verifying:true) == .incorrectCode,"typed incorrect SMS code")
    try expect(ILoaderAuthenticationPolicy.classifySMS(status:200,data:Data(),phoneID:1,verifying:false) == .accepted,"SMS HTTP success")
    rows.append("sms-exact-412-and-typed-error-classification")
}
final class CancellationFlag: @unchecked Sendable {
    private let lock = NSLock(); private var value = false
    func enable() { lock.withLock { value = true } }
    var enabled: Bool { lock.withLock { value } }
}
func testTimeoutAndLateCancellation(_ rows: inout [String]) async throws {
    let script = TransportScript([Step(body:try profileBody(),delayNanoseconds:30_000_000_000)])
    try await SyntheticTransport.$current.withValue(script) {
        let client = ILoaderRemoteAnisetteClient(acquisitionTimeoutNanoseconds:1_000_000)
        var timedOut = false
        do { _ = try await client.fetch(state:state()) }
        catch let error as URLError { timedOut = error.code == .timedOut }
        try expect(timedOut && script.cancelCount >= 1 && script.requests.count <= 1 && script.websocketURLs.isEmpty,"bounded acquisition timeout closes transport without fallback")
    }
    let hanging = FakeWebSocketTask([["result":"GiveIdentifier"]],hangOnEmpty:true)
    let wsScript = TransportScript([Step(body:try profileBody()),Step(body:try lookupBody())],sockets:[hanging])
    try await SyntheticTransport.$current.withValue(wsScript) {
        let client = ILoaderRemoteAnisetteClient(acquisitionTimeoutNanoseconds:100_000_000)
        var timedOut = false
        do { _ = try await client.fetch(state:state(blob:nil)) }
        catch let error as URLError { timedOut = error.code == .timedOut }
        try expect(timedOut && wsScript.websocketURLs.count == 1 && hanging.cancels >= 1,"bounded timeout cancels upgraded hanging websocket")
        try expect(wsScript.requests.count == 2 && hanging.sent.count == 1,"websocket timeout no provisioning retry/fallback")
    }
    let flag = CancellationFlag()
    let context = ILoaderRemoteAuthenticationContext(now:{
        if flag.enabled { withUnsafeCurrentTask { $0?.cancel() } }
        return Date(timeIntervalSince1970:0)
    },fetcher:{_ in fixedAnisette()})
    _ = try await context.fetch(); flag.enable()
    let task = Task { try await context.fetch() }
    try await expectAsyncThrows("late cache-hit cancellation rechecked") { _ = try await task.value }
    rows.append("bounded-provider-timeout-and-late-cache-cancellation")
}

struct Export: Encodable {
    let schema = "iloader-auth-parity-cases-v1"
    let fake_only = true
    let cases: [String]
}
@main struct ILoaderAuthParityFixture {
    static func main() async throws {
        var rows: [String] = []
        try testPolicy(&rows); try testBuilders(&rows); try testStrictParsers(&rows)
        try await testCache(&rows); try await testProviderLifecycle(&rows); try await testFactoryLifecycle(&rows)
        try await testAuthResync(&rows); try await testStageFreshness(&rows)
        try await testTrustedVerification(&rows); try testSMSClassifier(&rows)
        try await testDiagnosticBoundaries(&rows)
        try await testTimeoutAndLateCancellation(&rows)
        try expect(Set(rows).count == rows.count && !rows.isEmpty,"unique executed case labels")
        if CommandLine.arguments.count > 1 {
            try JSONEncoder().encode(Export(cases:rows)).write(to:URL(fileURLWithPath:CommandLine.arguments[1]))
        }
        print("ILOADER_AUTH_PARITY_FIXTURE_PASS")
        print("{\"case_count\":\(rows.count)}")
    }
}

func assertActualSnapshot(_ trace: AuthenticationDiagnosticTrace, requireRequest: Bool) throws {
    let snapshot = trace.snapshot()
    if requireRequest { try expect(snapshot.requestTrace != nil, "actual collector produced ar1") }
    if let encoded = snapshot.requestTrace {
        try expect(AuthenticationDiagnosticTrace.validatedEncodedSnapshot(encoded) == encoded, "actual opt-in collector ar1 passes real validator")
    }
    if let encoded = snapshot.headerProvenance {
        try expect(AuthenticationHeaderProvenance(encoded:encoded)?.encoded == encoded, "actual opt-in hp2 passes real validator")
    }
    if let encoded = snapshot.providerObservation {
        try expect(AuthenticationProviderObservation.validatedEncoded(encoded) == encoded, "actual opt-in ap1 passes real validator")
    }
    for encoded in [snapshot.requestTrace,snapshot.headerProvenance,snapshot.providerObservation].compactMap({$0}) {
        for secret in ["synthetic-password","synthetic-machine","synthetic-otp","synthetic-dsid","synthetic-idms","https://"] {
            try expect(!encoded.contains(secret), "actual collector redacts raw data")
        }
    }
}
func observed<T>(requireRequest: Bool = true, _ work: () async throws -> T) async throws -> T {
    let trace = AuthenticationDiagnosticTrace()
    do {
        let value = try await AuthenticationDiagnosticTrace.$current.withValue(trace) { try await work() }
        try assertActualSnapshot(trace,requireRequest:requireRequest)
        return value
    } catch {
        try assertActualSnapshot(trace,requireRequest:requireRequest)
        throw error
    }
}
func runProbe(_ context: ILoaderRemoteAuthenticationContext, _ operation: Int) async throws -> String {
    try await observed {
        try await ILoaderRemoteAuthentication.$current.withValue(context) { try await DeveloperPortal(session:FakeSession([])).fixtureRemoteTwoFactor(operation) }
    }
}
func testDiagnosticBoundaries(_ rows: inout [String]) async throws {
    let transport = TransportScript([Step(body:Data(),error:URLError(.timedOut))])
    try await SyntheticTransport.$current.withValue(transport) {
        let context = ILoaderRemoteAuthenticationContext(fetcher:{_ in fixedAnisette()})
        try await expectAsyncThrows("pre-response auth transport") { _ = try await runAuthentication(transport,context:context) }
        try expect(transport.requests.count == 1,"pre-response transport no retry")
    }
    rows.append("actual-collector-pre-response-transport")
    for (label,step) in [("parse",Step(body:Data("not-json".utf8))),("transport",Step(body:Data(),error:URLError(.timedOut)))] {
        let complete = try accepted(["spd":Data([3]),"M2":Data([4]),"Status":["ec":0,"au":"trustedDeviceSecondaryAuth"] as [String:any Sendable]])
        let script = TransportScript([Step(body:try initOK()),Step(body:complete),step])
        try await SyntheticTransport.$current.withValue(script) {
            let context = ILoaderRemoteAuthenticationContext(fetcher:{_ in fixedAnisette()})
            try await expectAsyncThrows("discovery \(label) then explicit cancellation") { _ = try await runAuthentication(script,context:context,handler:{_ in .cancel}) }
            try expect(script.requests.count == 3 && script.requests[2].url?.absoluteString == "https://gsa.apple.com/auth","actual discovery production route")
            try expectHeaders(script.requests[2],expectedTwoFactorHeaders(fixedAnisette(),sms:true),"discovery exact headers")
        }
        rows.append("actual-collector-discovery-"+label)
    }
    let clock = FixtureClock(); let fetcher = FetchScript([fixedAnisette()])
    let context = ILoaderRemoteAuthenticationContext(now:{clock.now()},fetcher:{try await fetcher.fetch($0)})
    _ = try await context.fetch(); clock.set(61)
    let trace = AuthenticationDiagnosticTrace()
    try await expectAsyncThrows("provider failure during 2FA refresh") {
        _ = try await AuthenticationDiagnosticTrace.$current.withValue(trace) {
            try await ILoaderRemoteAuthentication.$current.withValue(context) { try await DeveloperPortal(session:FakeSession([])).fixtureTwoFactor(2) }
        }
    }
    try assertActualSnapshot(trace,requireRequest:false)
    try expect(trace.snapshot().requestTrace == nil,"pre-request provider failure has no fabricated request")
    rows.append("actual-collector-provider-failure-before-2fa-request")
}
