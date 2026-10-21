import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

func fixedAnisette() -> AnisetteData {
    AnisetteData(machineID: "synthetic-machine", oneTimePassword: "synthetic-otp", localUserID: "synthetic-local-user",
        routingInfo: "17106176", deviceID: "synthetic-device", serialNumber: "synthetic-serial",
        clientInfo: "<MacBookPro;MacOS;com.apple.akd/1>", userAgent: "synthetic-provider-agent",
        clientTime: "2026-01-01T00:00:00Z", locale: "en_US", timeZone: "UTC")
}
let cpdKeys = ["bootstrap", "icscrec", "pbe", "prkgen", "svct", "loc", "X-Apple-Locale", "X-Apple-I-MD", "X-Apple-I-MD-M", "X-Mme-Device-Id", "X-Apple-I-MD-LU", "X-Apple-I-MD-RINFO", "X-Apple-I-SRL-NO", "X-Apple-I-Client-Time", "X-Apple-I-TimeZone"]
func fixedCPD() -> [String: any Sendable] {
    var p: [String: any Sendable] = [:]
    for key in cpdKeys { p[key] = "synthetic-secret" }
    for key in cpdKeys.prefix(4) { p[key] = true }
    p["svct"] = Constants.GrandSlam.service
    return p
}
func parameters(_ cpd: [String: any Sendable] = fixedCPD()) -> [String: any Sendable] {
    ["o": "init", "u": "synthetic-account", "A2k": Data([1,2,3,4]), "cpd": cpd, "ps": ["s2k", "s2k_fo"]]
}
func accepted(_ extra: [String: any Sendable] = [:]) throws -> Data {
    var d = extra; let status: [String: any Sendable] = ["ec": 0]; d["Status"] = status
    return try plist(d)
}
func initOK() throws -> Data { try accepted(["c": "synthetic-challenge", "s": Data([1]), "i": 2, "B": Data([2])]) }
func completeOK() throws -> Data { try accepted(["spd": Data([3]), "M2": Data([4])]) }
func tokensOK() throws -> Data { try accepted(["et": Data(repeating: 5, count: 40)]) }
struct RunResult: @unchecked Sendable { let value: String; let requests: [URLRequest] }
struct ExportCase: Encodable {
    let name: String
    let auth_request_trace: String?
    let auth_header_provenance: String?
    let auth_provider_observation: String?
}
struct ExportFile: Encodable { let schema = "auth-request-cases-v1"; let cases: [ExportCase] }
func record(_ name: String, _ trace: AuthenticationDiagnosticTrace, _ rows: inout [ExportCase]) throws {
    let s = trace.snapshot()
    if let ar = s.requestTrace { try expect(AuthenticationDiagnosticTrace.validatedEncodedSnapshot(ar) == ar, "actual ar1 validates: \(name)"); try expect(ar.utf8.count <= 1024, "ar1 budget") }
    if let hp = s.headerProvenance { try expect(AuthenticationHeaderProvenance(encoded: hp)?.encoded == hp, "actual hp2 validates"); try expect(hp.split(separator: ";").count == 22, "hp2 final22") }
    if let ap = s.providerObservation { try expect(AuthenticationProviderObservation.validatedEncoded(ap) == ap, "actual ap1 validates") }
    for text in [s.requestTrace, s.headerProvenance, s.providerObservation].compactMap({ $0 }) {
        for secret in ["synthetic-secret", "synthetic-account", "synthetic-machine", "synthetic-otp", "em-secret", "raw-secret", "https://"] { try expect(!text.contains(secret), "redaction: \(secret)") }
    }
    rows.append(.init(name: name, auth_request_trace: s.requestTrace, auth_header_provenance: s.headerProvenance, auth_provider_observation: s.providerObservation))
}
func detail(_ trace: AuthenticationDiagnosticTrace) throws -> [String] {
    guard let ar = trace.encodedSnapshot() else { throw FixtureFailure.assertion("missing ar1") }
    let p = ar.split(separator: ";", omittingEmptySubsequences: false)
    try expect(p.count == 9 && p[7] != "-", "detail exists")
    return p[7].split(separator: ",", omittingEmptySubsequences: false).map(String.init)
}
func compareRequests(_ a: [URLRequest], _ b: [URLRequest], _ name: String) throws {
    try expect(a.count == b.count, "request count \(name)")
    for (x, y) in zip(a,b) {
        try expect(x.url == y.url && x.httpMethod == y.httpMethod, "URL/method \(name)")
        try expect(x.allHTTPHeaderFields == y.allHTTPHeaderFields, "headers \(name)")
        try expect(x.httpBody == y.httpBody, "EXACT serialized body \(name)")
        try expect(x.cachePolicy == y.cachePolicy && x.timeoutInterval == y.timeoutInterval, "request policy \(name)")
    }
}
func runSend(_ step: Step, _ p: [String: any Sendable], baseline: Bool, trace: AuthenticationDiagnosticTrace?) async -> RunResult {
    let session = FakeSession([step]); let value: String
    do {
        value = try await AuthenticationDiagnosticTrace.$current.withValue(trace) {
            let dictionary: [String: any Sendable]
            if baseline { dictionary = try await BaselineDeveloperPortal(session: session).sendAuthenticationRequest(parameters: p, anisetteData: fixedAnisette()) }
            else { dictionary = try await DeveloperPortal(session: session).sendAuthenticationRequest(parameters: p, anisetteData: fixedAnisette()) }
            return "returned:" + exactValue(dictionary)
        }
    } catch { value = "thrown:" + typedError(error) }
    return RunResult(value: value, requests: session.requests)
}
func parity(_ name: String, _ step: Step, p: [String: any Sendable] = parameters(), rows: inout [ExportCase]) async throws -> AuthenticationDiagnosticTrace {
    let trace = AuthenticationDiagnosticTrace()
    let base = await runSend(step, p, baseline: true, trace: nil)
    let off = await runSend(step, p, baseline: false, trace: nil)
    let on = await runSend(step, p, baseline: false, trace: trace)
    try expect(base.value == off.value && off.value == on.value, "recursive exact typed return/error parity \(name)")
    try compareRequests(base.requests, off.requests, name); try compareRequests(off.requests, on.requests, name)
    try record(name, trace, &rows); return trace
}
func authValue(_ auth: AuthSession) -> String {
    let s = auth.session
    // The original wall-clock creationDate is intentionally not compared across separate executions.
    return [auth.account.id, s.dsid, s.authToken, s.xcodeVersion, s.machinePassword ?? "nil",
            String(describing: s.expirationDate), String(describing: s.timeToLive), String(s.creationDate != nil),
            exactValue([s.anisetteData.machineID, s.anisetteData.oneTimePassword, s.anisetteData.localUserID, s.anisetteData.routingInfo, s.anisetteData.deviceID, s.anisetteData.serialNumber, s.anisetteData.clientInfo, s.anisetteData.userAgent, s.anisetteData.clientTime, s.anisetteData.locale, s.anisetteData.timeZone])].joined(separator: "|")
}
actor VerificationScript {
    private var entries: [TwoFactorResponse] = [.requestTrustedDevice, .verificationCode("123456")]
    func next() throws -> TwoFactorResponse { guard !entries.isEmpty else { throw FixtureFailure.unscripted }; return entries.removeFirst() }
}
func runAuth(_ steps: [Step], scenario: CryptoScenario, baseline: Bool, trace: AuthenticationDiagnosticTrace?, accountFailure: Bool = false, twoFactor: Bool = false) async -> RunResult {
    let session = FakeSession(steps); let value: String
    let script = VerificationScript()
    let handler: DeveloperPortal.VerificationHandler?
    if twoFactor { handler = { _ in try await script.next() } } else { handler = nil }
    do {
        value = try await AuthenticationDiagnosticTrace.$current.withValue(trace) {
            try await CryptoState.$current.withValue(scenario) {
                let auth: AuthSession
                if baseline {
                    let p = BaselineDeveloperPortal(session: session); p.failAccount = accountFailure
                    auth = try await p.authenticate(appleID: " Synthetic@Example.invalid ", password: "synthetic-password", anisetteData: fixedAnisette(), xcodeVersion: "synthetic-xcode", verificationHandler: handler)
                } else {
                    let p = DeveloperPortal(session: session); p.failAccount = accountFailure
                    auth = try await p.authenticate(appleID: " Synthetic@Example.invalid ", password: "synthetic-password", anisetteData: fixedAnisette(), xcodeVersion: "synthetic-xcode", verificationHandler: handler)
                }
                return "returned:" + authValue(auth)
            }
        }
    } catch { value = "thrown:" + typedError(error) }
    return .init(value: value, requests: session.requests)
}
func authParity(_ name: String, steps: [Step], scenario: CryptoScenario = .init(), accountFailure: Bool = false, twoFactor: Bool = false, rows: inout [ExportCase]) async throws -> AuthenticationDiagnosticTrace {
    let trace = AuthenticationDiagnosticTrace()
    let b = await runAuth(steps, scenario: scenario, baseline: true, trace: nil, accountFailure: accountFailure, twoFactor: twoFactor)
    let o = await runAuth(steps, scenario: scenario, baseline: false, trace: nil, accountFailure: accountFailure, twoFactor: twoFactor)
    let n = await runAuth(steps, scenario: scenario, baseline: false, trace: trace, accountFailure: accountFailure, twoFactor: twoFactor)
    try expect(b.value == o.value && o.value == n.value, "auth dsid/token/value/error parity: \(name)")
    try compareRequests(b.requests,o.requests,name); try compareRequests(o.requests,n.requests,name)
    try record(name,trace,&rows); return trace
}
func runTwoFactor(_ operation: Int, step: Step, baseline: Bool, trace: AuthenticationDiagnosticTrace?) async -> RunResult {
    let session = FakeSession([step]); let value: String
    do { value = try await AuthenticationDiagnosticTrace.$current.withValue(trace) {
        if baseline { return try await BaselineDeveloperPortal(session: session).fixtureTwoFactor(operation) }
        return try await DeveloperPortal(session: session).fixtureTwoFactor(operation)
    } } catch { value = "thrown:" + typedError(error) }
    return .init(value: value, requests: session.requests)
}

@main struct AuthenticationRequestFixture {
    static func main() async throws {
        var rows: [ExportCase] = []
        let success = Step(body: try accepted(["value": "retained", "nested": ["a", "b"]]))
        let acceptedTrace = try await parity("plist accepted",success,rows:&rows)
        try expect(try detail(acceptedTrace)[8] == "accepted", "accepted outcome")
        let mappedStatus: [String: any Sendable] = ["ec": -80045, "hsc": 409, "em": "em-secret"]
        let rejected = Step(body: try plist(["Status": mappedStatus]), status: 503)
        let rejectedTrace = try await parity("mappedEC-80045",rejected,rows:&rows)
        let rd = try detail(rejectedTrace)
        try expect(rd[10] == "503" && rd[24] == "-80045" && rd[25] == "409", "HTTP/ec/hsc independent")
        for code in [-22406,-20101,-20209,-21669] {
            let status: [String: any Sendable] = ["ec": code, "hsc": 409, "em": "em-secret"]
            _ = try await parity("mappedEC\(code)",Step(body:try plist(["Status":status])),rows:&rows)
        }
        let invalid: [(String,Data)] = [("empty",Data()),("html503",Data("<html>raw-secret</html>".utf8)),("array",try PropertyListSerialization.data(fromPropertyList:[1,2],format:.xml,options:0)),("scalar",Data("true".utf8)),("malformed",Data([0,255,0,253]))]
        for (name,body) in invalid {
            let trace = try await parity(name,Step(body:body,status:503,mime:"text/html"),rows:&rows)
            let observation = try detail(trace)
            try expect(observation[8] == (name == "empty" ? "empty" : "parse") && observation[10] == "503", "empty/parse status observation")
        }
        let status0: [String: any Sendable] = ["ec":0]
        let inner: [String: any Sendable] = ["Status":status0,"ok":"inner"]
        let emptyDict: [String: any Sendable] = [:]
        let envelopes: [(String,[String:any Sendable])] = [("missingStatus",[:]),("wrongStatus",["Status":"raw-secret"]),("nested",["Response":inner]),("wrongEnvelopeFallback",["Response":"raw-secret","Status":status0]),("emptyNestedWins",["Response":emptyDict,"Status":status0])]
        for (name,dict) in envelopes { _ = try await parity(name,Step(body:try plist(dict)),rows:&rows) }
        _ = try await parity("json",Step(body:Data("{\"Status\":{\"ec\":0},\"value\":\"raw-secret\"}".utf8),mime:"application/json"),rows:&rows)
        _ = try await parity("nonHTTP",Step(body:success.body,nonHTTP:true),rows:&rows)
        _ = try await parity("sameOrigin",Step(body:success.body,finalURL:URL(string:"https://gsa.apple.com/other?secret=raw-secret")!),rows:&rows)
        _ = try await parity("otherOrigin",Step(body:success.body,finalURL:URL(string:"https://other.invalid/raw-secret")!),rows:&rows)
        let numeric: [(String,any Sendable,String)] = [("int0",0,"0"),("int1",1,"1"),("boolFalse",false,"ib"),("boolTrue",true,"ib"),("float1",1.0,"if"),("string0","0","is"),("arrayEC",[0],"io"),("outside",100_000_000,"ir")]
        for (name,code,expected) in numeric {
            let status: [String:any Sendable] = ["ec":code,"hsc":true,"em":"em-secret"]
            let trace = try await parity(name,Step(body:try plist(["Status":status])),rows:&rows)
            let d = try detail(trace); try expect(d[24] == expected && d[25] == "ib", "strict primitive vs baseline Int cast \(name)")
        }
        _ = try await parity("missingEC",Step(body:try plist(["Status":emptyDict])),rows:&rows)
        for (name,e) in [("cancelled",URLError(.cancelled)),("timeout",URLError(.timedOut)),("dns",URLError(.cannotFindHost)),("connectivity",URLError(.notConnectedToInternet)),("lost",URLError(.networkConnectionLost)),("tls",URLError(.secureConnectionFailed)),("url",URLError(.badURL))] {
            let t = try await parity("transport:\(name)",Step(body:Data(),error:e),rows:&rows); try expect(try detail(t)[9] == name,"transport category")
        }
        _ = try await parity("CancellationError",Step(body:Data(),error:CancellationError()),rows:&rows)
        _ = try await parity("unknownError",Step(body:Data(),error:FixtureFailure.unscripted),rows:&rows)
        for (index,value) in ["0","42","999999999999999999999999999999","01","raw-secret","Wed, 01 Jan 2020 00:00:00 GMT"].enumerated() {
            let trace = try await parity("retryAfter:\(index)",Step(body:success.body,headers:["Retry-After":value]),rows:&rows)
            let observation = try detail(trace)
            let forms = ["delta", "delta", "delta", "invalid", "invalid", "date"]
            try expect(observation[30] == forms[index], "Retry-After finite form")
            if index == 2 { try expect(observation[31] == "86400" && observation[32] == "1", "Retry-After cap") }
        }
        var absent = parameters(); absent.removeValue(forKey:"cpd")
        var wrong = parameters(); wrong["cpd"] = "raw-secret"
        var extra = fixedCPD(); extra["raw-secret-key"] = "raw-secret"
        let absentTrace = try await parity("absentCPD",success,p:absent,rows:&rows)
        let wrongTrace = try await parity("wrongCPD",success,p:wrong,rows:&rows)
        let extraTrace = try await parity("extraCPD",success,p:parameters(extra),rows:&rows)
        let absentDetail = try detail(absentTrace), wrongDetail = try detail(wrongTrace), extraDetail = try detail(extraTrace)
        try expect(absentDetail[29] == "a" && wrongDetail[29] == "w" && extraDetail[37] == "1", "CPD container and unexpected count")
        try expect(extraDetail[38] == "headerRequest:builtIn:builtIn" && extraDetail[39] == "plist", "actual envelope selection and serialization")
        let cpdCases: [(String,(any Sendable)?,Character)] = [("missing",nil,"a"),("bool",false,"b"),("string","raw-secret","s"),("emptyString","","e"),("data",Data([1]),"d"),("emptyData",Data(),"z"),("integer",42,"n"),("real",2.5,"r"),("array",[1],"c"),("emptyArray",[Int](),"c"),("dictionary",["a":"raw-secret"],"c"),("date",Date(timeIntervalSince1970:0),"o")]
        for (index,key) in cpdKeys.enumerated() {
            for (name,value,expected) in cpdCases {
                var cpd=fixedCPD(); cpd[key]=value
                let t=try await parity("cpd:\(index):\(name)",success,p:parameters(cpd),rows:&rows)
                try expect(Array(try detail(t)[29])[index] == expected,"CPD primitive \(index):\(name)")
            }
        }
        let normal=[Step(body:try initOK()),Step(body:try completeOK()),Step(body:try tokensOK())]
        let auth=try await authParity("authSuccess",steps:normal,rows:&rows)
        try expect(try detail(auth)[1] == "3","three auth requests")
        let account=try await authParity("accountLookup",steps:normal,accountFailure:true,rows:&rows)
        let ad=try detail(account); try expect(ad[8] == "accepted" && ad[33] == "tokenPath" && ad[34] == "passed","accepted prior request not relabeled cause")
        _ = try await authParity("initFields",steps:[success],rows:&rows)
        let initValues: [String:any Sendable] = ["c":"synthetic-challenge","s":Data([1]),"i":2,"B":Data([2])]
        for key in ["c","s","i","B"] {
            var missing=initValues; missing.removeValue(forKey:key)
            var wrong=initValues; wrong[key]=["wrong"]
            _ = try await authParity("initMissing:\(key)",steps:[Step(body:try accepted(missing))],rows:&rows)
            _ = try await authParity("initWrong:\(key)",steps:[Step(body:try accepted(wrong))],rows:&rows)
        }
        for fail in ["srpInit","publicKey","hash","pbkdf2","challenge","proof","sharedSecret","hmac","spdDecrypt","checksum","tokenDecrypt"] {
            var scenario=CryptoScenario(); scenario.fail=fail
            _ = try await authParity(fail,steps:normal,scenario:scenario,rows:&rows)
        }
        _ = try await authParity("completeSPD",steps:[normal[0],Step(body:try accepted(["M2":Data([4])]))],rows:&rows)
        _ = try await authParity("proofField",steps:[normal[0],Step(body:try accepted(["spd":Data([3])]))],rows:&rows)
        for (name,data) in [("spdParse",Data("raw-secret".utf8)),("dsid",try plist(["GsIdmsToken":"synthetic-idms"])),("idms",try plist(["adsid":"synthetic-dsid"])),("sessionKey",try plist(["adsid":"synthetic-dsid","GsIdmsToken":"synthetic-idms"])),("sessionChallenge",try plist(["adsid":"synthetic-dsid","GsIdmsToken":"synthetic-idms","sk":Data([1])]))] {
            var scenario=CryptoScenario(); scenario.spd=data
            _ = try await authParity(name,steps:normal,scenario:scenario,rows:&rows)
        }
        for (name,body) in [("tokenField",try accepted()),("tokenLength",try accepted(["et":Data([1])]))] {
            _ = try await authParity(name,steps:[normal[0],normal[1],Step(body:body)],rows:&rows)
        }
        for (name,data) in [("tokenParse",Data("raw-secret".utf8)),("tokenPath",try plist(["wrong":"raw-secret"]))] {
            var scenario=CryptoScenario(); scenario.token=data
            _ = try await authParity(name,steps:normal,scenario:scenario,rows:&rows)
        }
        var tfaStatus=status0; tfaStatus["au"]="trustedDevice"
        let tfaComplete: [String:any Sendable] = ["Status":tfaStatus,"spd":Data([3]),"M2":Data([4])]
        _ = try await authParity("recursive2FA",steps:[normal[0],Step(body:try plist(tfaComplete)),success,success]+normal,twoFactor:true,rows:&rows)
        let tfaSteps=[success,Step(body:Data(),status:503),Step(body:Data("<alert title=\"raw-secret\" message=\"raw-secret\"/>".utf8)),Step(body:try plist(["ec":-21669])),Step(body:try plist(["ec":-21668])),Step(body:try plist(["ec":-80045])),Step(body:success.body,headers:["X-Apple-PE-Token":"raw-secret"]),Step(body:Data(),error:CancellationError()),Step(body:Data("<pinView/>".utf8))]
        for operation in 0..<4 { for (index,step) in tfaSteps.enumerated() {
            let t=AuthenticationDiagnosticTrace(); let name="twoFactor:\(operation):\(index)"
            let b=await runTwoFactor(operation,step:step,baseline:true,trace:nil)
            let o=await runTwoFactor(operation,step:step,baseline:false,trace:nil)
            let n=await runTwoFactor(operation,step:step,baseline:false,trace:t)
            try expect(b.value==o.value && o.value==n.value,"typed2FA \(name)")
            try compareRequests(b.requests,o.requests,name); try compareRequests(o.requests,n.requests,name)
            try expect(t.snapshot().headerProvenance==nil,"no stale GrandSlam provenance on 2FA")
            try record(name,t,&rows)
        } }
        try await collectorTests(success, rows:&rows)
        try await legacyTests(rows:&rows)
        if CommandLine.arguments.count > 1 {
            let data=try JSONEncoder().encode(ExportFile(cases:rows)); try data.write(to:URL(fileURLWithPath:CommandLine.arguments[1]))
        }
        print("AUTH_REQUEST_DIAGNOSTICS_FIXTURE_PASS")
        print("{\"schema\":\"auth-request-runtime-v1\",\"cases\":\(rows.count),\"requestParity\":true,\"liveNetwork\":false,\"nativeProvider\":false}")
    }
    static func collectorTests(_ success: Step, rows: inout [ExportCase]) async throws {
        let trace=AuthenticationDiagnosticTrace()
        var request=URLRequest(url:Constants.URLs.grandSlamAuth); request.httpMethod="POST"; request.httpBody=Data([1])
        let invocation=trace.beginAuthentication()
        AuthenticationDiagnosticTrace.$invocation.withValue(invocation) {
            for _ in 0..<40 { let item=trace.beginRequest(request,phase:"init",parameters:parameters(),headerVersion:Constants.GrandSlam.headerVersion); item.response(request:request,data:success.body,response:HTTPURLResponse(url:Constants.URLs.grandSlamAuth,statusCode:200,httpVersion:nil,headerFields:nil)!); item.finish(.accepted) }
        }
        let encoded=trace.encodedSnapshot()!; let p=encoded.split(separator:";",omittingEmptySubsequences:false).map(String.init)
        let boundedDetail = try detail(trace)
        try expect(p[4]=="1" && boundedDetail[1]=="40","bounded chronology retains decisive")
        try expect(AuthenticationDiagnosticTrace.validatedEncodedSnapshot(encoded)==encoded,"valid bounded trace")
        for malformed in [encoded+";extra", "future"+encoded.dropFirst(3), encoded+"\n",String(repeating:"x",count:1025)] { try expect(AuthenticationDiagnosticTrace.validatedEncodedSnapshot(malformed)==nil,"reject malformed wire") }
        var modified=p; modified[1]="01"; try expect(AuthenticationDiagnosticTrace.validatedEncodedSnapshot(modified.joined(separator:";"))==nil,"canonical ordinal")
        var fields=p[7].split(separator:",",omittingEmptySubsequences:false).map(String.init)
        fields[25]="99"; modified=p; modified[7]=fields.joined(separator:","); try expect(AuthenticationDiagnosticTrace.validatedEncodedSnapshot(modified.joined(separator:";"))==nil,"HSC strict100...599")
        modified=p; if let first=p[8].split(separator:"~").first { modified[8]="\(first)~\(first)"; try expect(AuthenticationDiagnosticTrace.validatedEncodedSnapshot(modified.joined(separator:";"))==nil,"duplicate record rejected") }
        let four=AuthenticationDiagnosticTrace()
        for _ in 0..<4 { _=four.beginRequest(request,phase:"init") }
        _=four.beginAuthentication(); four.authentication(.srpInit,.failed)
        let noCurrent=four.encodedSnapshot()!.split(separator:";",omittingEmptySubsequences:false)
        try expect(noCurrent[7]=="-" && noCurrent[4]=="1" && noCurrent[8].split(separator:"~").count==3,"four old requests trimmed explicitly without current")
        try record("currentScopeUnavailable",four,&rows)
        var invalid=parameters(); invalid["notPlist"]=URL(string:"https://fixture.invalid/raw-secret")!
        let serialization = try await parity("serializationBeforeRequest", success, p: invalid, rows: &rows)
        let serialized=serialization.encodedSnapshot()!.split(separator:";",omittingEmptySubsequences:false)
        try expect(serialized[5]=="serialization" && serialized[6]=="failed" && serialized[7]=="-","serialization before request observed")
        let provider=AuthenticationDiagnosticTrace(); let selected=AuthenticationProviderObservation.selectedBranch(onDevice:false)
        let token=provider.beginProviderObservation(selected)
        try expect(provider.snapshot().requestTrace==nil && provider.snapshot().providerObservation != nil,"preauth provider available")
        try record("providerPreAuth",provider,&rows)
        let old=provider.beginRequest(request,phase:"init",parameters:parameters(),headerVersion:Constants.GrandSlam.headerVersion)
        _=provider.beginProviderObservation(.selectedBranch(onDevice:true))
        let newEvent=provider.snapshot().providerObservation
        provider.setProviderObservation(selected,token:token)
        let foreign=AuthenticationDiagnosticTrace().beginProviderObservation(selected)
        provider.setProviderObservation(selected,token:foreign)
        old.response(request:request,data:success.body,response:HTTPURLResponse(url:Constants.URLs.grandSlamAuth,statusCode:200,httpVersion:nil,headerFields:nil)!)
        old.finish(.accepted); old.consumer(.initFields,.failed)
        try expect(provider.snapshot().providerObservation==newEvent,"stale/foreign provider token ignored")
        try expect(provider.snapshot().headerProvenance==nil,"provider new acquisition clears request provenance")
        try expect(provider.encodedSnapshot()!.split(separator:";",omittingEmptySubsequences:false)[7]=="-","late old callback cannot restore decisive")
        try record("providerNewAcquisition",provider,&rows)
        // Real task interleaving with deterministic actor latches, no timing/sleeps.
        let first=AuthenticationDiagnosticTrace(), second=AuthenticationDiagnosticTrace()
        let entered=SyntheticLatch(), release=SyntheticLatch()
        var delayed=success; delayed.entered=entered; delayed.release=release
        let task=Task { await runSend(delayed,parameters(),baseline:false,trace:first) }
        await entered.wait()
        _ = await runSend(Step(body:Data(),error:URLError(.timedOut)),parameters(),baseline:false,trace:second)
        await release.signal(); _ = await task.value
        let firstDetail = try detail(first), secondDetail = try detail(second)
        try expect(firstDetail[8]=="accepted" && secondDetail[9]=="timeout","interleaved collectors isolated")
        try record("concurrentCollectors:old",first,&rows); try record("concurrentCollectors:new",second,&rows)
        let shared=AuthenticationDiagnosticTrace(); let oldInvocation=shared.beginAuthentication()
        let entered2=SyntheticLatch(), release2=SyntheticLatch()
        var delayed2=success; delayed2.entered=entered2; delayed2.release=release2
        let oldTask=Task { await AuthenticationDiagnosticTrace.$invocation.withValue(oldInvocation) { await runSend(delayed2,parameters(),baseline:false,trace:shared) } }
        await entered2.wait()
        let newInvocation=shared.beginAuthentication()
        _ = await AuthenticationDiagnosticTrace.$invocation.withValue(newInvocation) { await runSend(Step(body:Data(),error:URLError(.timedOut)),parameters(),baseline:false,trace:shared) }
        await release2.signal(); _ = await oldTask.value
        let latest=try detail(shared); try expect(latest[0]=="2" && latest[1]=="2" && latest[9]=="timeout","older invocation cannot overwrite current request")
        try record("concurrentInvocations",shared,&rows)
    }
    static func legacyTests(rows: inout [ExportCase]) async throws {
        let dict:[String:any Sendable] = ["Status":["ec":0] as [String:any Sendable]]
        for (label,body) in [("binary",try plist(dict,format:.binary)),("xml",try plist(dict)),("json",Data("{\"Status\":{\"ec\":0}}".utf8))] {
            for status in [200,503] { _=try await parity("legacyAccepted:\(label):\(status)",Step(body:body,status:status),rows:&rows) }
        }
        let bad:[(String,Data)] = [
            ("plistArray",try PropertyListSerialization.data(fromPropertyList:["raw-secret"],format:.xml,options:0)),
            ("plistScalar",Data("<?xml version=\"1.0\"?><plist version=\"1.0\"><string>raw-secret</string></plist>".utf8)),
            ("jsonArray",Data("[\"raw-secret\"]".utf8)),("jsonNull",Data("null".utf8)),("jsonTrue",Data("true".utf8)),
            ("htmlSecret",Data("<html>raw-secret</html>".utf8)),("nonPlistXML",Data("<raw-secret/>".utf8)),("binaryInvalid",Data([255,254,0,1]))]
        for (name,body) in bad {
            _=try await parity("legacyInvalid:\(name)",Step(body:body,status:503,mime:"text/html"),rows:&rows)
            do {
                _=try await DeveloperPortal(session:FakeSession([Step(body:body,status:503,mime:"text/html")])).sendAuthenticationRequest(parameters:parameters(),anisetteData:fixedAnisette())
                throw FixtureFailure.assertion("invalid accepted")
            } catch let error as ServerError {
                guard case .invalidResponseFormat(let raw,let context)=error else { throw FixtureFailure.assertion("legacy wrong error") }
                try expect(raw=="[redacted]" && context?.httpStatus==503,"legacy bounded context")
                try expect((error as NSError).code==1,"legacy enum ordinal1")
                for text in [error.description,error.errorDescription ?? "",error.localizedDescription,(error as NSError).localizedDescription] { try expect(!text.contains("raw-secret"),"legacy redaction all forms") }
            }
        }
        for mime in [nil,"application/xhtml+xml","TEXT/HTML","application/json","application/plist","application/octet-stream","text/html; charset=utf-8","raw-secret"] as [String?] {
            let context=AuthenticationResponseContext(data:Data("raw-secret".utf8),httpStatus:503,mimeType:mime)
            try expect(!context.mime.rawValue.contains("raw-secret"),"finite legacy MIME")
        }
        for status in [99,100,418,599,600] {
            let context=AuthenticationResponseContext(data:Data(),httpStatus:status,mimeType:nil)
            try expect(context.httpStatus==((100...599).contains(status) ? status:nil),"legacy HTTP bounds")
        }
        let old=ServerError.invalidResponseFormat(rawPayload:"legacy")
        guard case .invalidResponseFormat(_,nil)=old else { throw FixtureFailure.assertion("legacy nil context") }
    }
}
